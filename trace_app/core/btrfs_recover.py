"""Deleted files on Btrfs, from the tree nodes copy-on-write leaves behind
(no Qt).

Btrfs never changes a tree node in place: a change writes a new copy and
frees the old one, which stays on disk until the space is used again. A
deleted file therefore survives in older leaves of its subvolume's tree --
its inode, its names, its extents -- after the live tree has dropped it.
This reads every block of the metadata chunks, keeps the leaves that are
intact (the node's own checksum must match: a half-overwritten block is
never trusted), and collects the inodes they describe that the live tree
no longer has.

How much of a file is left is proven, not guessed: Btrfs checksums every
data sector (CRC32C, xxHash64, SHA-256 or BLAKE2b), and older copies of
the checksum tree keep the sums of extents since freed. A sector is
intact when its bytes still match the sum recorded when it was written:

* recoverable          every sector checked matches (or, for files Btrfs
                       keeps no sums for, no sector is in use again)
* partly overwritten   some sectors no longer match
* overwritten          none matches
* resident             the data sits inside the leaf itself (inline)
* no data recorded     the leaves found say nothing of where it was

A deleted subvolume or snapshot is found the same way: its leaves name a
tree the root tree no longer has, and its files are listed under
'[deleted subvolume N]'.

`DeletedScan(volume)` scans once; `records(offset)` yields rows in
core/deleted.py's shape; `entry(identifier)` gives a recovered file to
read like a live one (BtrfsEntry over the recovered inode and extents).

Measured on a Fedora root (1 GB of metadata, 7.5 GB of data chunks), it
never finished: every checksum was Python (CRC-32C now comes from the
crc32c wheel), every deleted file's sectors were read 4 KB at a time (now
an extent at a time), and every data sector's sums were kept -- millions
of entries. The checksum leaves are now read in a second pass, keeping
only the sums of the deleted files' own extents. Each stage reports
progress and stops when asked.
"""

import bisect
import hashlib
import logging
import struct

from trace_app.core import btrfs

logger = logging.getLogger('TRACE.Btrfs.Recover')

CHUNK_SYSTEM, CHUNK_METADATA = 1 << 1, 1 << 2
CSUM_TREE = 7
EXTENT_CSUM_OBJECTID = (1 << 64) - 10
EXTENT_CSUM = 128
CSUM_SIZES = {0: 4, 1: 8, 2: 32, 3: 32}
#: Bytes of a deleted file read at once when checking its sectors.
READ_PIECE = 1024 * 1024
_HEADER = 101
_FIRST_FREE = 256
_LAST_FREE = (1 << 64) - 256


# --- checksums -------------------------------------------------------------------

def _crc32c_table():
    table = []
    for i in range(256):
        value = i
        for _ in range(8):
            value = (value >> 1) ^ 0x82F63B78 if value & 1 else value >> 1
        table.append(value)
    return table


_CRC = _crc32c_table()


def crc32c(data, crc=0xFFFFFFFF):
    """CRC-32C in Python: the reference the C one (`_fast_crc32c`) is
    tested against. ~10 MB/s -- a Fedora root's deleted-file scan never
    finished on it."""
    table = _CRC
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _fast_crc32c(data):
    import crc32c as library        # wheels everywhere (requirements.txt)
    return library.crc32c(data)


def checksum(kind, data):
    """The bytes Btrfs stores for `data` under checksum type `kind`."""
    if kind == 0:
        return struct.pack('<I', _fast_crc32c(data))
    if kind == 1:
        from trace_app.core.zstd_decode import xxh64
        return struct.pack('<Q', xxh64(bytes(data)))
    if kind == 2:
        return hashlib.sha256(data).digest()
    if kind == 3:
        return hashlib.blake2b(data, digest_size=32).digest()
    raise btrfs.BtrfsError(f"Unknown checksum type {kind}")


# --- what the old leaves say -----------------------------------------------------

class Recovered:
    """One deleted inode, as the newest intact leaves recorded it."""
    __slots__ = ('tree', 'inode', 'meta', 'generation', 'names', 'extents',
                 '_extent_gen', '_rank', 'deleted_in')

    def __init__(self, tree, inode):
        self.tree = tree
        self.inode = inode
        self.meta = None
        self.generation = -1
        self.names = {}            # (parent inode, name) -> generation
        self.extents = {}          # file offset -> extent tuple
        self._extent_gen = {}
        self._rank = (False, -1, -1)
        #: The newest transaction any record of it was written in -- when it
        #: was deleted, or after: its data's space is free only from then.
        self.deleted_in = -1

    def name(self):
        """(parent inode, name) most recently recorded, or (0, b'')."""
        if not self.names:
            return 0, b''
        return max(self.names, key=self.names.get)


def _leaf_items(data):
    """[(key, item bytes)] of a leaf node."""
    count = struct.unpack_from('<I', data, 0x60)[0]
    out = []
    for i in range(min(count, (len(data) - _HEADER) // 25)):
        objectid, kind, offset, where, size = struct.unpack_from(
            '<QBQII', data, _HEADER + 25 * i)
        out.append(((objectid, kind, offset),
                    data[_HEADER + where:_HEADER + where + size]))
    return out


def _is_fs_tree(owner):
    return owner == btrfs.FS_TREE or _FIRST_FREE <= owner < _LAST_FREE


def _extent(start, data):
    """The tuple BtrfsVolume.extents gives, from an EXTENT_DATA item."""
    if len(data) < 21:
        return None
    _gen, ram, compression, encryption, _other, kind = struct.unpack_from(
        '<QQBBHB', data, 0)
    if encryption:
        return None
    if kind == btrfs.EXTENT_INLINE:
        return (start, ram, kind, compression, 0, 0, 0, ram, data[21:])
    if len(data) < 53:
        return None
    bytenr, disk_bytes, offset, length = struct.unpack_from('<QQQQ', data, 21)
    return (start, length, kind, compression, bytenr, disk_bytes, offset,
            ram, None)


class DeletedScan:
    """Every deleted inode the metadata of one Btrfs device still holds."""

    def __init__(self, volume, should_stop=None, progress=None):
        self.volume = volume
        self.csum_size = CSUM_SIZES.get(volume.csum_type, 4)
        self.found = {}            # (tree, inode) -> Recovered
        #: data sector (logical) -> {generation: sum}: every version kept,
        #: of the deleted files' sectors only. Once a deleted file's space
        #: is used again, the newest sum is the new data's, and of course
        #: it matches -- the file's own is the newest written no later than
        #: its deletion (`_sum_for`).
        self.sums = {}
        self.leaves = self.rejected = 0
        #: (logical, generation) of each intact checksum-tree leaf, read
        #: again once it is known which sums are wanted.
        self._csum_leaves = []
        self._should_stop = should_stop
        self._progress = progress
        self._scan()
        self._drop_live()
        self._keep_sums()

    def _check(self):
        if self._should_stop is not None and self._should_stop():
            from trace_app.core.deleted import DeletedCancelled
            raise DeletedCancelled()

    def _report(self, done, total, text):
        if self._progress is not None:
            self._progress(done, total, text)

    # --- reading every metadata block -------------------------------------

    def _blocks(self):
        node = self.volume.node_size
        for chunk in self.volume._chunks:
            if not chunk.flags & (CHUNK_SYSTEM | CHUNK_METADATA):
                continue
            for logical in range(chunk.start, chunk.start + chunk.length,
                                 node):
                yield logical

    def _scan(self):
        volume = self.volume
        total = sum(chunk.length // volume.node_size
                    for chunk in volume._chunks
                    if chunk.flags & (CHUNK_SYSTEM | CHUNK_METADATA))
        for count, logical in enumerate(self._blocks()):
            if count % 256 == 0:
                self._check()
                self._report(count, total, "Reading Btrfs metadata")
            try:
                data = volume.read(logical, volume.node_size)
            except btrfs.BtrfsError:
                continue
            if data[0x20:0x30] != volume.fsid or \
                    struct.unpack_from('<Q', data, 0x30)[0] != logical or \
                    data[0x64] != 0:
                continue                     # not a leaf written here
            generation, owner = struct.unpack_from('<QQ', data, 0x50)
            if not (_is_fs_tree(owner) or owner == CSUM_TREE):
                continue
            if checksum(volume.csum_type, data[0x20:])[:self.csum_size] != \
                    data[:self.csum_size]:
                self.rejected += 1           # half overwritten: not trusted
                continue
            self.leaves += 1
            if owner == CSUM_TREE:
                self._csum_leaves.append((logical, generation))
            else:
                self._fs_leaf(owner, data, generation)

    def _wanted(self):
        """The deleted files' data extents, merged and sorted: the only
        sectors whose sums are worth keeping."""
        spans = sorted((e[4], e[4] + e[5])
                       for found in self.found.values()
                       for e in found.extents.values()
                       if e[2] != btrfs.EXTENT_INLINE and e[4])
        merged = []
        for begin, end in spans:
            if merged and begin <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([begin, end])
        return merged

    def _keep_sums(self):
        """The second pass: the checksum leaves again, keeping the sums
        of the deleted files' sectors."""
        wanted = self._wanted()
        if not wanted:
            return
        starts = [begin for begin, _end in wanted]
        leaves = self._csum_leaves
        for count, (logical, generation) in enumerate(leaves):
            if count % 64 == 0:
                self._check()
                self._report(count, len(leaves), "Reading Btrfs checksums")
            try:
                data = self.volume.read(logical, self.volume.node_size)
            except btrfs.BtrfsError:
                continue
            self._sums(data, generation, wanted, starts)

    def _sums(self, data, generation, wanted=None, starts=None):
        size = self.csum_size
        sector = self.volume.sector_size
        for (objectid, kind, start), item in _leaf_items(data):
            if objectid != EXTENT_CSUM_OBJECTID or kind != EXTENT_CSUM:
                continue
            count = len(item) // size
            end = start + count * sector
            if wanted is None:
                ranges = [(start, end)]
            else:
                # Only where the item meets a deleted file's extents.
                index = max(0, bisect.bisect_right(starts, start) - 1)
                ranges = []
                while index < len(wanted) and wanted[index][0] < end:
                    low = max(start, wanted[index][0])
                    high = min(end, wanted[index][1])
                    if high > low:
                        ranges.append((low, high))
                    index += 1
            for low, high in ranges:
                first = (low - start) // sector
                last = -(-(high - start) // sector)
                for index in range(first, last):
                    where = start + index * sector
                    self.sums.setdefault(where, {})[generation] = \
                        item[index * size:(index + 1) * size]

    def _fs_leaf(self, tree, data, generation):
        for (objectid, kind, offset), item in _leaf_items(data):
            if objectid < _FIRST_FREE or objectid >= _LAST_FREE:
                continue
            if kind == btrfs.INODE_ITEM and len(item) >= 160:
                # Deleting drops the link count to 0 and, a transaction
                # later, truncates the inode to nothing: the file as it was
                # is the newest record that still had a link. Two copies of
                # one transaction's leaf can both survive (the file just
                # created, and after its data was written): the larger.
                found = self._get(tree, objectid)
                found.deleted_in = max(found.deleted_in, generation)
                meta = btrfs._Inode(item)
                rank = (meta.nlink > 0, generation, meta.size)
                if rank > found._rank:
                    found.meta = meta
                    found.generation = generation
                    found._rank = rank
            elif kind == btrfs.INODE_REF:
                found = self._get(tree, objectid)
                position = 0
                while position + 10 <= len(item):
                    _index, length = struct.unpack_from('<QH', item,
                                                        position)
                    name = item[position + 10:position + 10 + length]
                    key = (offset, bytes(name))
                    found.names[key] = max(found.names.get(key, -1),
                                           generation)
                    position += 10 + length
            elif kind == btrfs.DIR_INDEX and len(item) >= 30:
                child, child_kind = struct.unpack_from('<QB', item, 0)
                if child_kind != btrfs.INODE_ITEM:
                    continue
                length = struct.unpack_from('<H', item, 27)[0]
                name = bytes(item[30:30 + length])
                found = self._get(tree, child)
                key = (objectid, name)
                found.names[key] = max(found.names.get(key, -1), generation)
            elif kind == btrfs.EXTENT_DATA:
                extent = _extent(offset, item)
                if extent is None:
                    continue
                found = self._get(tree, objectid)
                if generation > found._extent_gen.get(offset, -1):
                    found.extents[offset] = extent
                    found._extent_gen[offset] = generation

    def _get(self, tree, inode):
        key = (tree, inode)
        found = self.found.get(key)
        if found is None:
            found = self.found[key] = Recovered(tree, inode)
        return found

    def _drop_live(self):
        """Keep what the live trees no longer have (an inode of a tree
        that is gone: a deleted subvolume or snapshot)."""
        volume = self.volume
        deleted = {}
        for key, found in self.found.items():
            tree, inode = key
            if found.meta is None:
                continue                     # only names or extents seen
            if tree in volume._trees and \
                    volume.inode(tree, inode) is not None:
                continue
            deleted[key] = found
        self.found = deleted

    # --- what is left of each file -----------------------------------------

    def path_of(self, tree, inode, depth=0):
        volume = self.volume
        if depth > 64:
            return '/$Orphan'
        if tree in volume._trees and volume.inode(tree, inode) is not None:
            prefix = volume.subvolume_path(tree)
            inside = volume.directory_path(tree, inode)
            if prefix is not None and inside is not None:
                return (prefix + inside) or '/'
        if inode == btrfs.ROOT_DIR:
            if tree in volume._trees:
                return volume.subvolume_path(tree) or '/'
            return f'/[deleted subvolume {tree}]'
        found = self.found.get((tree, inode))
        if found is None or not found.names:
            prefix = '' if tree in volume._trees else \
                f'/[deleted subvolume {tree}]'
            return f'{prefix}/$Orphan/{inode}'
        parent, name = found.name()
        above = self.path_of(tree, parent, depth + 1)
        return f"{above.rstrip('/')}/{name.decode('utf-8', 'surrogateescape')}"

    def assess(self, found):
        """(state, overwritten bytes, [(logical, length)] of its data,
        how the state was decided)."""
        from trace_app.core import deleted
        extents = sorted(found.extents.values())
        size = found.meta.size
        stored = [e for e in extents if e[2] != btrfs.EXTENT_INLINE
                  and e[4] and e[0] < size]
        inline = [e for e in extents if e[2] == btrfs.EXTENT_INLINE]
        if not stored:
            if inline:
                return deleted.RESIDENT, 0, [], 'inline in the leaf'
            return (deleted.NO_DATA if size else deleted.RECOVERABLE, 0, [],
                    'no extents recorded' if size else 'empty')
        volume = self.volume
        sector = volume.sector_size
        checked = matched = 0
        unsummed = 0               # sectors with no sum surviving
        spans = []
        for extent in stored:
            bytenr, disk_bytes = extent[4], extent[5]
            spans.append((bytenr, disk_bytes))
            # Read a piece at a time and check its sectors from memory:
            # a read per 4 KB sector was most of a scan's time.
            for piece in range(bytenr, bytenr + disk_bytes, READ_PIECE):
                length = min(READ_PIECE, bytenr + disk_bytes - piece)
                known = [self._sum_for(where, found.deleted_in)
                         for where in range(piece, piece + length, sector)]
                if not any(k is not None for k in known):
                    unsummed += len(known)
                    continue
                try:
                    data = volume.read(piece, length)
                except btrfs.BtrfsError:
                    data = None
                for index, expected in enumerate(known):
                    if expected is None:
                        unsummed += 1
                        continue
                    checked += 1
                    if data is None:
                        continue
                    block = data[index * sector:(index + 1) * sector]
                    if checksum(volume.csum_type, block)[:self.csum_size] \
                            == expected:
                        matched += 1
        total = sum(length for _b, length in spans)
        if checked:
            lost = (checked - matched) * sector
            if matched == checked and not unsummed:
                return deleted.RECOVERABLE, 0, spans, \
                    f'all {checked:,} sectors match their checksums'
            if matched == 0:
                return deleted.OVERWRITTEN, total, spans, \
                    f'none of {checked:,} sectors matches its checksum'
            return deleted.PARTLY, lost, spans, \
                f'{matched:,} of {checked:,} sectors match their checksums'
        # No sums (nodatasum files): judged by whether the space is in use.
        used = self._in_use(spans)
        state = (deleted.RECOVERABLE if not used else
                 deleted.OVERWRITTEN if used >= total else deleted.PARTLY)
        return state, used, spans, ('no checksums kept; judged by whether '
                                    'its space is in use again')

    def _sum_for(self, sector, deleted_in):
        """The sum a sector had while the deleted file owned it: the newest
        written no later than the file's deletion. None if none survives."""
        versions = self.sums.get(sector)
        if not versions:
            return None
        before = [g for g in versions if g <= deleted_in]
        return versions[max(before)] if before else None

    def _in_use(self, spans):
        if not hasattr(self, '_live_extents'):
            ranges = []
            volume = self.volume
            extent_root = None
            for _key, data in volume.items(
                    volume.root_tree, (btrfs.EXTENT_TREE, btrfs.ROOT_ITEM, 0),
                    (btrfs.EXTENT_TREE, btrfs.ROOT_ITEM, btrfs._MAX)):
                extent_root = struct.unpack_from('<Q', data, 176)[0]
            if extent_root is not None:
                for (bytenr, kind, offset), _d in volume.items(
                        extent_root, 0, btrfs._MAX):
                    if kind == btrfs.EXTENT_ITEM:
                        ranges.append((bytenr, bytenr + offset))
            ranges.sort()
            self._live_extents = ranges
            self._live_starts = [b for b, _e in ranges]
        used = 0
        for begin, length in spans:
            end = begin + length
            index = max(0, bisect.bisect_right(self._live_starts, begin) - 1)
            while index < len(self._live_extents) and \
                    self._live_extents[index][0] < end:
                low = max(begin, self._live_extents[index][0])
                high = min(end, self._live_extents[index][1])
                if high > low:
                    used += high - low
                index += 1
        return used

    # --- rows and entries ---------------------------------------------------------

    def records(self, offset, base, should_stop=None, progress=None,
                assess=None):
        """Rows in core/deleted.py's shape for the volume at `offset`
        (`base`: its byte offset in the image). `assess(path)`, when given,
        says whether a file's data is checked (False: listed by name, its
        state 'not assessed' -- outside the run's scope)."""
        import stat
        from trace_app.core.activity import times
        from trace_app.core.case import make_artifact_ref
        found_all = sorted(self.found.items())
        for count, ((tree, inode), found) in enumerate(found_all):
            if should_stop is not None and should_stop():
                from trace_app.core.deleted import DeletedCancelled
                raise DeletedCancelled()
            meta = found.meta
            is_dir = stat.S_ISDIR(meta.mode)
            ident = btrfs.identifier(tree, inode)
            path = self.path_of(tree, inode)
            if progress is not None and count % 32 == 0:
                progress(count, len(found_all), path)
            record = {'volume': offset, 'path': path,
                      'name': path.rsplit('/', 1)[-1], 'inode': ident,
                      'is_dir': is_dir, 'sequence': None,
                      'size': 0 if is_dir else meta.size, 'runs': [],
                      'overwritten': 0,
                      'ref': make_artifact_ref(offset, ident, None)}
            for key, index in (('accessed', 0), ('changed', 1),
                               ('modified', 2), ('created', 3)):
                seconds, _nano = meta.times[index]
                record[key] = times.iso(times.unix(seconds)) \
                    if seconds else None
            if is_dir:
                from trace_app.core import deleted
                record['state'] = deleted.RECOVERABLE
            elif assess is not None and not assess(path):
                from trace_app.core import deleted
                record['state'] = deleted.NOT_ASSESSED
            else:
                state, lost, spans, why = self.assess(found)
                record['state'] = state
                record['overwritten'] = lost
                runs = []
                for logical, length in spans:
                    for physical, part in self.volume._physical_copies(
                            logical, length)[:1]:
                        runs.append((base + physical, part))
                record['runs'] = runs
                record['detail'] = {'checked': why,
                                    'generation': found.generation}
            yield record

    def entry(self, value):
        """A recovered file to read like a live one, or None."""
        tree, inode = btrfs.split_identifier(value)
        found = self.found.get((tree, inode))
        if found is None:
            return None
        parent, name = found.name()
        return btrfs.BtrfsEntry(
            self.volume, tree, inode,
            name.decode('utf-8', 'surrogateescape'),
            btrfs.identifier(tree, parent) if parent else 0,
            recovered=found)

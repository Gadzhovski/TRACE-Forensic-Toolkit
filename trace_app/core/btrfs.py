"""Btrfs, read in Python and shaped like pytsk3's file system objects.

Btrfs is Fedora's and openSUSE's default file system (Arch and others
offer it), and The Sleuth Kit in the pytsk3 wheels does not read it. No
libyal binding with wheels does either, and the one pure-Python reader
(dissect.btrfs) is AGPL -- so TRACE reads it itself, as it reads AFF4 and
UDIF. Entries look like libyal's (see core/libyal_fs.py), so browsing,
previews, exports, analysis, indexing and activity need no Btrfs code.

What is read: the superblock (primary copy at 64 KiB), the chunk tree
(logical -> physical; SINGLE, DUP and the RAID1 family from any one disk,
RAID0 / RAID10 where this disk holds the stripe asked for), the root tree,
and every subvolume's file tree. Subvolumes and snapshots appear where
they are linked, as the top-level subvolume (id 5) shows them when mounted
with subvolid=5 -- Fedora's root/home and Snapper's .snapshots included,
whatever the default subvolume is. File data: inline, regular and
preallocated extents, holes (NO_HOLES too), and zlib, LZO and zstd
compression.

Identifiers: the top-level subvolume's entries keep their inode numbers
(what `ls -i` shows there); another subvolume's are `tree << 48 | inode`,
since every subvolume numbers its own inodes from 256.

Not read: RAID5/6 spread over several disks, encryption (not in mainline
Linux), and deleted entries -- Btrfs is copy-on-write, and older tree
nodes do survive, but nothing here reports them, so nothing is ever
reported deleted (as for APFS and XFS).
"""

import bisect
import logging
import stat
import struct
import zlib
from collections import OrderedDict

from trace_app.core import zstd_decode
from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.Btrfs')

MAGIC = b'_BHRfS_M'
SUPERBLOCK_OFFSET = 0x10000
MAGIC_OFFSET = SUPERBLOCK_OFFSET + 0x40

# Item types (ctree.h).
INODE_ITEM = 1
INODE_REF = 12
DIR_ITEM = 84
DIR_INDEX = 96
EXTENT_DATA = 108
ROOT_ITEM = 132
ROOT_BACKREF = 144
ROOT_REF = 156
EXTENT_ITEM = 168
METADATA_ITEM = 169
DEV_ITEM = 216
CHUNK_ITEM = 228

EXTENT_TREE = 2
FS_TREE = 5
ROOT_TREE_DIR = 6
FIRST_FREE = 256
ROOT_DIR = 256              # every subvolume's root directory
CHUNK_TREE_DEVICES = 1      # DEV_ITEMs live under objectid 1

# Chunk profile bits (block group flags).
RAID0 = 1 << 3
RAID1 = 1 << 4
DUP = 1 << 5
RAID10 = 1 << 6
RAID5 = 1 << 7
RAID6 = 1 << 8

COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_LZO, COMPRESS_ZSTD = 0, 1, 2, 3
EXTENT_INLINE, EXTENT_REG, EXTENT_PREALLOC = 0, 1, 2

#: Another subvolume's entries: tree id above the inode number.
TREE_SHIFT = 48
_MAX = (1 << 64) - 1
_HEADER = 101               # node header bytes
_NODES_KEPT = 512
#: A compressed extent decompresses to at most 128 KiB; a damaged one is
#: not allowed to claim more than this.
_MAX_EXTENT = 1 << 20


class BtrfsError(Exception):
    """Not Btrfs, or Btrfs this reader cannot follow."""


def superblock_geometry(head):
    """(sector size, size in bytes, label) from the bytes of a volume's
    first 68 KiB, or None when they hold no Btrfs superblock."""
    if len(head) < SUPERBLOCK_OFFSET + 0x32b or \
            head[MAGIC_OFFSET:MAGIC_OFFSET + 8] != MAGIC:
        return None
    sb = head[SUPERBLOCK_OFFSET:]
    total = struct.unpack_from('<Q', sb, 0x70)[0]
    sector = struct.unpack_from('<I', sb, 0x90)[0]
    if not 512 <= sector <= 65536:
        return None
    label = sb[0x12b:0x22b].split(b'\0', 1)[0].decode('utf-8', 'replace')
    return sector, total, label


def identifier(tree, inode):
    return inode if tree == FS_TREE else (tree << TREE_SHIFT) | inode


def identifier_label(value):
    """How an identifier reads to an examiner: the inode as `ls -i` shows
    it, and the subvolume it is in when that is not the top level --
    '4122 (subvolume 256)' rather than 72057594037928218."""
    tree, inode = split_identifier(value)
    return str(inode) if tree == FS_TREE else f"{inode} (subvolume {tree})"


def split_identifier(value):
    value = int(value)
    if value >> TREE_SHIFT:
        return value >> TREE_SHIFT, value & ((1 << TREE_SHIFT) - 1)
    return FS_TREE, value


# --- decompression ---------------------------------------------------------------

def lzo1x_decompress(src, limit=_MAX_EXTENT):
    """LZO1X (Linux lib/lzo), what Btrfs's 'lzo' compresses each page
    with. Raises BtrfsError on damage rather than reading past either
    buffer."""
    src = bytes(src)
    out = bytearray()
    ip = 0

    def run(base):
        # A zero length is extended by 255 per zero byte, then one byte.
        nonlocal ip
        length = 0
        while src[ip] == 0:
            length += 255
            ip += 1
        length += base + src[ip]
        ip += 1
        return length

    try:
        state = 0        # literals just copied: 0, 1-3, or 4 (a long run)
        if src[0] > 17:
            count = src[0] - 17
            ip = 1
            out += src[ip:ip + count]
            ip += count
            state = 4 if count >= 4 else count
        while True:
            t = src[ip]
            ip += 1
            if t < 16:
                if state == 0:
                    count = (run(15) if t == 0 else t) + 3
                    if ip + count > len(src):
                        raise BtrfsError("LZO literal run past the input")
                    out += src[ip:ip + count]
                    ip += count
                    state = 4
                    continue
                if state == 4:
                    distance = 1 + 0x800 + (t >> 2) + (src[ip] << 2)
                    length = 3
                else:
                    distance = 1 + (t >> 2) + (src[ip] << 2)
                    length = 2
                ip += 1
            elif t >= 64:
                distance = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                ip += 1
                length = (t >> 5) + 1
            elif t >= 32:
                length = (run(31) if t & 31 == 0 else t & 31) + 2
                distance = 1 + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
            else:
                high = (t & 8) << 11
                length = (run(7) if t & 7 == 0 else t & 7) + 2
                distance = high + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                if distance == 0:
                    return bytes(out)                   # end of stream
                distance += 0x4000
            start = len(out) - distance
            if start < 0:
                raise BtrfsError("LZO match before the start of output")
            if distance >= length:
                out += out[start:start + length]
            else:
                pattern = bytes(out[start:])
                out += (pattern * (length // distance + 1))[:length]
            if len(out) > limit:
                raise BtrfsError("LZO output larger than an extent")
            state = src[ip - 2] & 3
            if state:
                out += src[ip:ip + state]
                ip += state
    except IndexError:
        raise BtrfsError("LZO data ends early") from None


def _lzo_extent(data, sector_size, limit):
    """Btrfs's LZO layout: a u32 total length, then per page a u32 segment
    length and LZO1X bytes; a segment header never straddles a sector."""
    if len(data) < 4:
        raise BtrfsError("LZO extent too short")
    total = min(struct.unpack_from('<I', data, 0)[0], len(data))
    out = bytearray()
    position = 4
    while position + 4 <= total and len(out) < limit:
        left = sector_size - position % sector_size
        if left < 4:
            position += left
            if position + 4 > total:
                break
        length = struct.unpack_from('<I', data, position)[0]
        position += 4
        if not length or position + length > total:
            break
        out += lzo1x_decompress(data[position:position + length], limit)
        position += length
    return bytes(out)


def decompress(kind, data, size, sector_size=4096):
    """`size` bytes of an extent compressed with `kind`."""
    limit = min(max(size, 1), _MAX_EXTENT)
    try:
        if kind == COMPRESS_ZLIB:
            out = zlib.decompressobj().decompress(bytes(data), limit)
        elif kind == COMPRESS_LZO:
            out = _lzo_extent(data, sector_size, limit)
        elif kind == COMPRESS_ZSTD:
            # One frame, then zeros to the end of the sector.
            out = zstd_decode.decompress_frame(data, limit)
        else:
            raise BtrfsError(f"Unknown compression {kind}")
    except (zlib.error, zstd_decode.ZstdError) as exc:
        raise BtrfsError(f"Compressed extent unreadable: {exc}") from exc
    return out[:size]


# --- the volume --------------------------------------------------------------------

class _Chunk:
    __slots__ = ('start', 'length', 'stripe_len', 'flags', 'sub_stripes',
                 'stripes')

    def __init__(self, start, data, position=0):
        (self.length, _owner, self.stripe_len, self.flags, _align, _width,
         _sector, count, self.sub_stripes) = struct.unpack_from(
            '<QQQQIIIHH', data, position)
        self.start = start
        self.stripes = [struct.unpack_from('<QQ', data, position + 48 + 32 * i)
                        for i in range(count)]          # (devid, offset)

    @property
    def size(self):
        return 48 + 32 * len(self.stripes)


class _Node:
    __slots__ = ('level', 'keys', 'values')


class _Inode:
    __slots__ = ('size', 'nlink', 'uid', 'gid', 'mode', 'flags', 'times')

    def __init__(self, data):
        (_gen, _transid, self.size, _nbytes, _group, self.nlink, self.uid,
         self.gid, self.mode, _rdev, self.flags) = struct.unpack_from(
            '<QQQQQIIIIQQ', data, 0)
        # atime, ctime, mtime, otime: (seconds, nanoseconds)
        self.times = [struct.unpack_from('<qI', data, 112 + 12 * i)
                      for i in range(4)]


class BtrfsVolume:
    """One Btrfs device, read through `source` (a file object over the
    partition): logical addresses, trees, inodes, extents."""

    def __init__(self, source):
        self.source = source
        source.seek(0)
        head = source.read(SUPERBLOCK_OFFSET + 4096)
        if superblock_geometry(head) is None:
            raise BtrfsError("No Btrfs superblock")
        sb = head[SUPERBLOCK_OFFSET:SUPERBLOCK_OFFSET + 4096]
        self.fsid = sb[0x20:0x30]
        (self.generation, root, chunk_root, _log, _log_transid,
         self.total_bytes, self.bytes_used, _root_dir,
         self.num_devices) = struct.unpack_from('<QQQQQQQQQ', sb, 0x48)
        (self.sector_size, self.node_size, _leaf, _stripe,
         array_size) = struct.unpack_from('<IIIII', sb, 0x90)
        self.incompat = struct.unpack_from('<Q', sb, 0xbc)[0]
        self.devid = struct.unpack_from('<Q', sb, 0xc9)[0]
        self.label = sb[0x12b:0x22b].split(b'\0', 1)[0].decode(
            'utf-8', 'replace')
        if self.incompat & (1 << 10):                   # METADATA_UUID
            self.fsid = sb[0x23b:0x24b]
        if not 4096 <= self.node_size <= 65536:
            raise BtrfsError(f"Implausible node size {self.node_size}")
        self._chunks = []
        self._starts = []
        array = sb[0x32b:0x32b + min(array_size, 2048)]
        position = 0
        while position + 17 + 48 <= len(array):
            _objectid, kind, offset = struct.unpack_from('<QBQ', array,
                                                         position)
            position += 17
            if kind != CHUNK_ITEM:
                raise BtrfsError("Unexpected item in the system chunk array")
            chunk = _Chunk(offset, array, position)
            self._add_chunk(chunk)
            position += chunk.size
        self._nodes = OrderedDict()
        for (_o, kind, offset), data in self.items(chunk_root, 0, _MAX):
            if kind == CHUNK_ITEM:
                self._add_chunk(_Chunk(offset, data))
        self.root_tree = root
        self._trees = {}
        self._links = set()      # (parent tree, dir inode, name, child tree)
        self._parents = {}       # child tree -> (parent tree, dir, name)
        for (objectid, kind, offset), data in self.items(root, 0, _MAX):
            if kind == ROOT_ITEM and (objectid == FS_TREE or
                                      FIRST_FREE <= objectid < _MAX - 255):
                bytenr = struct.unpack_from('<Q', data, 176)[0]
                self._trees[objectid] = bytenr
            elif kind == ROOT_REF:
                dirid, _seq, length = struct.unpack_from('<QQH', data, 0)
                name = data[18:18 + length]
                self._links.add((objectid, dirid, name, offset))
                self._parents[offset] = (objectid, dirid, name)
        if FS_TREE not in self._trees:
            raise BtrfsError("No top-level subvolume")
        # The default subvolume: the root tree's directory 6, 'default'.
        self.default_subvolume = FS_TREE
        for _key, data in self.items(root, (ROOT_TREE_DIR, DIR_ITEM, 0),
                                     (ROOT_TREE_DIR, DIR_ITEM, _MAX)):
            if len(data) >= 30 and data[30:30 + 7] == b'default' and \
                    struct.unpack_from('<Q', data, 0)[0] in self._trees:
                self.default_subvolume = struct.unpack_from('<Q', data, 0)[0]

    # --- addresses ---------------------------------------------------------

    def _add_chunk(self, chunk):
        index = bisect.bisect_left(self._starts, chunk.start)
        if index < len(self._starts) and self._starts[index] == chunk.start:
            return
        self._starts.insert(index, chunk.start)
        self._chunks.insert(index, chunk)

    def _map(self, logical):
        """(physical offset on this device, bytes readable from there)."""
        index = bisect.bisect_right(self._starts, logical) - 1
        if index < 0:
            raise BtrfsError(f"No chunk maps logical {logical:#x}")
        chunk = self._chunks[index]
        within = logical - chunk.start
        if within >= chunk.length:
            raise BtrfsError(f"No chunk maps logical {logical:#x}")
        stripes = chunk.stripes
        if chunk.flags & (RAID5 | RAID6):
            raise BtrfsError("RAID5/6 across several disks is not read")
        if chunk.flags & (RAID0 | RAID10):
            group = chunk.sub_stripes if chunk.flags & RAID10 else 1
            group = max(1, group)
            width = len(stripes) // group
            number, inside = divmod(within, chunk.stripe_len)
            first = (number % width) * group
            candidates = stripes[first:first + group]
            base = (number // width) * chunk.stripe_len + inside
            left = chunk.stripe_len - inside
        else:                           # SINGLE, DUP, RAID1, RAID1C3/C4
            candidates = stripes
            base = within
            left = chunk.length - within
        for devid, offset in candidates:
            if devid == self.devid:
                return offset + base, left
        raise BtrfsError(f"Logical {logical:#x} is on another disk")

    def read(self, logical, length):
        out = bytearray()
        while length > 0:
            physical, left = self._map(logical)
            part = min(length, left)
            self.source.seek(physical)
            data = self.source.read(part)
            if len(data) < part:
                data += b'\0' * (part - len(data))
            out += data
            logical += part
            length -= part
        return bytes(out)

    # --- trees ---------------------------------------------------------------

    def _node(self, bytenr):
        node = self._nodes.get(bytenr)
        if node is not None:
            self._nodes.move_to_end(bytenr)
            return node
        data = self.read(bytenr, self.node_size)
        if data[0x20:0x30] != self.fsid or \
                struct.unpack_from('<Q', data, 0x30)[0] != bytenr:
            raise BtrfsError(f"Tree node at {bytenr:#x} is not where its "
                             f"header says")
        count = struct.unpack_from('<I', data, 0x60)[0]
        node = _Node()
        node.level = data[0x64]
        node.keys = []
        node.values = []
        if node.level:
            for i in range(min(count, (len(data) - _HEADER) // 33)):
                objectid, kind, offset, child = struct.unpack_from(
                    '<QBQQ', data, _HEADER + 33 * i)
                node.keys.append((objectid, kind, offset))
                node.values.append(child)
        else:
            for i in range(min(count, (len(data) - _HEADER) // 25)):
                objectid, kind, offset, where, size = struct.unpack_from(
                    '<QBQII', data, _HEADER + 25 * i)
                node.keys.append((objectid, kind, offset))
                node.values.append(data[_HEADER + where:
                                        _HEADER + where + size])
        self._nodes[bytenr] = node
        if len(self._nodes) > _NODES_KEPT:
            self._nodes.popitem(last=False)
        return node

    def items(self, bytenr, low, high, depth=0):
        """(key, data) of every item in the tree at `bytenr` whose key is
        in [low, high], in key order. A key is (objectid, type, offset);
        an int bound means that objectid with any type and offset."""
        if isinstance(low, int):
            low = (low, 0, 0)
        if isinstance(high, int):
            high = (high, 255, _MAX)
        if depth > 8:
            raise BtrfsError("Tree deeper than Btrfs allows")
        node = self._node(bytenr)
        keys = node.keys
        if not node.level:
            for index in range(bisect.bisect_left(keys, low), len(keys)):
                if keys[index] > high:
                    return
                yield keys[index], node.values[index]
            return
        # Child i holds keys from keys[i] up to keys[i + 1].
        first = max(0, bisect.bisect_right(keys, low) - 1)
        for index in range(first, len(keys)):
            if keys[index] > high:
                return
            yield from self.items(node.values[index], low, high, depth + 1)

    def tree(self, tree_id):
        try:
            return self._trees[tree_id]
        except KeyError:
            raise BtrfsError(f"No subvolume {tree_id}") from None

    def subvolumes(self):
        """{tree id: (parent tree, directory inode, name)} of every
        subvolume and snapshot linked somewhere."""
        return {tree: (parent, dirid, name.decode('utf-8', 'replace'))
                for tree, (parent, dirid, name) in self._parents.items()}

    def _physical_copies(self, logical, length):
        """[(physical offset, length)] of every copy of a logical range on
        this device -- both under DUP, each RAID1 copy that is here."""
        out = []
        while length > 0:
            index = bisect.bisect_right(self._starts, logical) - 1
            if index < 0:
                break
            chunk = self._chunks[index]
            within = logical - chunk.start
            if within >= chunk.length:
                break
            if chunk.flags & (RAID0 | RAID10 | RAID5 | RAID6):
                try:
                    physical, left = self._map(logical)
                except BtrfsError:
                    break
                part = min(length, left)
                out.append((physical, part))
            else:
                part = min(length, chunk.length - within)
                out += [(offset + within, part)
                        for devid, offset in chunk.stripes
                        if devid == self.devid]
            logical += part
            length -= part
        return out

    def allocated_ranges(self):
        """Byte ranges of this device that hold something: every data and
        metadata extent the extent tree records, on every copy here, and
        the superblock copies. What carving must not call free space."""
        out = [(offset, offset + 4096) for offset in
               (SUPERBLOCK_OFFSET, 64 << 20, 256 << 30)]
        extent_root = None
        for (_o, _k, _off), data in self.items(
                self.root_tree, (EXTENT_TREE, ROOT_ITEM, 0),
                (EXTENT_TREE, ROOT_ITEM, _MAX)):
            extent_root = struct.unpack_from('<Q', data, 176)[0]
        if extent_root is None:
            raise BtrfsError("No extent tree")
        for (bytenr, kind, offset), _data in self.items(extent_root, 0,
                                                        _MAX):
            if kind == EXTENT_ITEM:
                length = offset
            elif kind == METADATA_ITEM:
                length = self.node_size
            else:
                continue
            out += [(physical, physical + size) for physical, size in
                    self._physical_copies(bytenr, length)]
        return out

    def subvolume_path(self, tree_id, depth=0):
        """Where a subvolume appears from the top level: '' for the top
        level itself, '/home', '/@/.snapshots/1/snapshot'; None when it is
        linked nowhere."""
        if tree_id == FS_TREE:
            return ''
        if tree_id not in self._parents or depth > 64:
            return None
        parent, dirid, name = self._parents[tree_id]
        above = self.subvolume_path(parent, depth + 1)
        inside = self.directory_path(parent, dirid)
        if above is None or inside is None:
            return None
        return f"{above}{inside}/{name.decode('utf-8', 'surrogateescape')}"

    def directory_path(self, tree_id, inode):
        """A directory's path inside its own subvolume ('' for its root)."""
        names = []
        while inode != ROOT_DIR:
            links = self.links(tree_id, inode)
            if not links or len(names) > 256:
                return None
            inode, name = links[0]
            names.append(name.decode('utf-8', 'surrogateescape'))
        return ''.join('/' + n for n in reversed(names))

    def inode(self, tree_id, inode):
        for _key, data in self.items(self.tree(tree_id),
                                     (inode, INODE_ITEM, 0),
                                     (inode, INODE_ITEM, _MAX)):
            return _Inode(data)
        return None

    def links(self, tree_id, inode):
        """(parent directory inode, name) for each name the inode has."""
        out = []
        for (_o, _t, parent), data in self.items(self.tree(tree_id),
                                                 (inode, INODE_REF, 0),
                                                 (inode, INODE_REF, _MAX)):
            position = 0
            while position + 10 <= len(data):
                _index, length = struct.unpack_from('<QH', data, position)
                out.append((parent, data[position + 10:
                                         position + 10 + length]))
                position += 10 + length
        return out

    def directory(self, tree_id, inode):
        """(name, child tree, child inode) in the directory's index order.
        A subvolume linked here is (name, its tree, ROOT_DIR); a
        subvolume entry with no link here (a snapshot's copy of a nested
        subvolume) is an empty directory, as Linux shows it."""
        out = []
        for _key, data in self.items(self.tree(tree_id),
                                     (inode, DIR_INDEX, 0),
                                     (inode, DIR_INDEX, _MAX)):
            if len(data) < 30:
                continue
            child, kind = struct.unpack_from('<QB', data, 0)
            _transid, _data_len, length = struct.unpack_from('<QHH', data, 17)
            name = data[30:30 + length]
            if kind == ROOT_ITEM:
                if (tree_id, inode, name, child) in self._links and \
                        child in self._trees:
                    out.append((name, child, ROOT_DIR))
                else:
                    out.append((name, None, None))
            elif kind == INODE_ITEM:
                out.append((name, tree_id, child))
        return out

    def extents(self, tree_id, inode):
        """(file offset, length, kind, compression, disk_bytenr,
        disk_num_bytes, offset in extent, ram_bytes, inline data)."""
        out = []
        for (_o, _t, start), data in self.items(self.tree(tree_id),
                                                (inode, EXTENT_DATA, 0),
                                                (inode, EXTENT_DATA, _MAX)):
            if len(data) < 21:
                continue
            _gen, ram, compression, encryption, _other, kind = \
                struct.unpack_from('<QQBBHB', data, 0)
            if encryption:
                raise BtrfsError("Encrypted extent")
            if kind == EXTENT_INLINE:
                inline = data[21:]
                length = ram
                out.append((start, length, kind, compression, 0, 0, 0, ram,
                            inline))
            elif len(data) >= 53:
                bytenr, disk_bytes, offset, length = struct.unpack_from(
                    '<QQQQ', data, 21)
                out.append((start, length, kind, compression, bytenr,
                            disk_bytes, offset, ram, None))
        return out


# --- libyal's vocabulary, so core/libyal_fs.py presents it ------------------------

class BtrfsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, tree, inode, name='', parent=0, empty=False):
        self._volume = volume
        self.tree = tree
        self.inode_number = inode
        self.identifier = identifier(tree, inode) if tree else 0
        self.name = name
        self.parent_identifier = parent
        self._children = None
        self._extents = None
        self._cached = (None, None, b'')
        meta = None if empty else volume.inode(tree, inode)
        if meta is None:
            # A snapshot's placeholder for a nested subvolume.
            self._meta = None
            self.file_mode = stat.S_IFDIR | 0o755
            self.size = 0
            self._children = []
        else:
            self._meta = meta
            self.file_mode = meta.mode
            self.size = meta.size if not stat.S_ISDIR(meta.mode) else 0
        self.owner_identifier = meta.uid if meta else 0
        self.group_identifier = meta.gid if meta else 0

    def get_number_of_links(self):
        return self._meta.nlink if self._meta else 1

    def _time(self, index):
        if self._meta is None:
            return 0
        seconds, nanoseconds = self._meta.times[index]
        if not seconds and not nanoseconds:
            return 0
        return seconds * 1_000_000_000 + nanoseconds

    def get_access_time_as_integer(self):
        return self._time(0)

    def get_inode_change_time_as_integer(self):
        return self._time(1)

    def get_modification_time_as_integer(self):
        return self._time(2)

    def get_creation_time_as_integer(self):
        return self._time(3)

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self.read_buffer_at_offset(min(self.size, 4096), 0).decode(
            'utf-8', 'surrogateescape')

    # --- directories ---------------------------------------------------------

    def _list(self):
        if self._children is None:
            self._children = []
            if stat.S_ISDIR(self.file_mode):
                for name, tree, inode in self._volume.directory(
                        self.tree, self.inode_number):
                    self._children.append((name, tree, inode))
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, tree, inode = self._list()[index]
        return BtrfsEntry(self._volume, tree, inode,
                          name.decode('utf-8', 'surrogateescape'),
                          self.identifier, empty=tree is None)

    # --- data --------------------------------------------------------------------

    def read_buffer_at_offset(self, length, offset):
        size = self.size
        if offset >= size or length <= 0:
            return b''
        length = min(length, size - offset)
        if self._extents is None:
            self._extents = self._volume.extents(self.tree, self.inode_number)
        out = bytearray(length)          # holes read as zeros
        end = offset + length
        for extent in self._extents:
            start, span = extent[0], extent[1]
            if start >= end or start + span <= offset:
                continue
            first = max(offset, start)
            last = min(end, start + span)
            piece = self._extent_bytes(extent, first - start, last - first)
            out[first - offset:first - offset + len(piece)] = piece
        return bytes(out)

    def _extent_bytes(self, extent, within, length):
        (_start, _span, kind, compression, bytenr, disk_bytes, offset, ram,
         inline) = extent
        volume = self._volume
        if kind == EXTENT_INLINE:
            data = inline if not compression else self._decompressed(
                extent, lambda: inline)
            return data[within:within + length]
        if kind == EXTENT_PREALLOC or bytenr == 0:
            return b''
        if not compression:
            return volume.read(bytenr + offset + within, length)
        data = self._decompressed(
            extent, lambda: volume.read(bytenr, disk_bytes))
        return data[offset + within:offset + within + length]

    def _decompressed(self, extent, raw):
        key = (extent[4], extent[0])
        if self._cached[0] != key:
            data = decompress(extent[3], raw(), extent[7],
                              self._volume.sector_size)
            self._cached = (key, None, data)
        return self._cached[2]


class _Volume:
    """libyal's volume vocabulary over a BtrfsVolume."""

    def __init__(self, volume):
        self.btrfs = volume
        self.label = volume.label

    def get_root_directory(self):
        return BtrfsEntry(self.btrfs, FS_TREE, ROOT_DIR, '', 0)

    def entry(self, value):
        tree, inode = split_identifier(value)
        volume = self.btrfs
        if tree not in volume._trees:
            return None
        if inode == ROOT_DIR:
            if tree == FS_TREE:
                return self.get_root_directory()
            parent_tree, dirid, name = volume._parents.get(
                tree, (FS_TREE, ROOT_DIR, b''))
            return BtrfsEntry(volume, tree, inode,
                              name.decode('utf-8', 'surrogateescape'),
                              identifier(parent_tree, dirid))
        links = volume.links(tree, inode)
        if not links and volume.inode(tree, inode) is None:
            return None
        parent, name = links[0] if links else (0, b'')
        return BtrfsEntry(volume, tree, inode,
                          name.decode('utf-8', 'surrogateescape'),
                          identifier(tree, parent) if parent else 0)

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            want = part.encode('utf-8', 'surrogateescape')
            for index, (name, _tree, _inode) in enumerate(entry._list()):
                if name == want:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.btrfs._nodes.clear()


class BtrfsFileSystem(LibyalFileSystem):
    """A Btrfs volume, read like a pytsk3.FS_Info."""

    KIND = 'Btrfs'

    def __init__(self, volume):
        self.BLOCK_SIZE = volume.sector_size
        self.btrfs = volume
        super().__init__(_Volume(volume), volume.total_bytes,
                         volume.label or 'Btrfs volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return identifier(FS_TREE, ROOT_DIR)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        """Every extent the extent tree records, on this device (not the
        file walk: Btrfs addresses are logical, and metadata counts)."""
        return self.btrfs.allocated_ranges()

    def close(self):
        self.volume.close()


def open_btrfs(source):
    """A BtrfsFileSystem over `source` (a file object over the
    partition), or None when it is not a Btrfs volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(SUPERBLOCK_OFFSET + 4096)
    except (OSError, IOError):
        return None
    if superblock_geometry(head) is None:
        return None
    try:
        return BtrfsFileSystem(BtrfsVolume(source))
    except (BtrfsError, struct.error, OSError, IOError) as exc:
        logger.warning("Btrfs volume not opened: %s", exc)
        return None


def is_btrfs(fs):
    return isinstance(fs, BtrfsFileSystem)


def _fstab_mounts(text, volume):
    """{mount point: subvolume path} for the lines of an fstab that mount
    this file system (by UUID or LABEL when they name one)."""
    uuid = volume.fsid.hex()
    uuid = '-'.join((uuid[:8], uuid[8:12], uuid[12:16], uuid[16:20],
                     uuid[20:]))
    mounts = {}
    for line in text.splitlines():
        fields = line.split('#', 1)[0].split()
        if len(fields) < 4 or fields[2] != 'btrfs':
            continue
        spec, point = fields[0], fields[1]
        if spec.upper().startswith('UUID=') and \
                spec[5:].strip('"').lower() != uuid:
            continue
        if spec.upper().startswith('LABEL=') and \
                spec[6:].strip('"') != volume.label:
            continue
        options = dict(o.split('=', 1) if '=' in o else (o, '')
                       for o in fields[3].split(','))
        if 'subvolid' in options:
            try:
                path = volume.subvolume_path(int(options['subvolid']))
            except ValueError:
                path = None
        elif 'subvol' in options:
            path = '/' + options['subvol'].strip('/') \
                if options['subvol'].strip('/') else ''
        else:
            path = volume.subvolume_path(volume.default_subvolume)
        if path is not None:
            mounts[point.rstrip('/') or '/'] = path
    return mounts


def system_layouts(fs):
    """[(root path, {mount point: path})] for each installed system on the
    volume, from its own /etc/fstab: Fedora's '/root' with /home and /var
    in sibling subvolumes, Ubuntu's '/@' and '/@home', openSUSE's default
    subvolume. A snapshot (whose fstab mounts another subvolume as /) is
    not a system of its own. [] when no fstab says."""
    volume = fs.btrfs
    candidates = [''] + sorted(
        p for p in (volume.subvolume_path(t) for t in volume._parents)
        if p is not None)
    found = []
    for root in candidates:
        entry = fs.volume.get_file_entry_by_path(root + '/etc/fstab')
        if entry is None or not entry.size or entry.size > 1 << 20:
            continue
        try:
            text = entry.read_buffer_at_offset(entry.size, 0).decode(
                'utf-8', 'replace')
        except (BtrfsError, OSError):
            continue
        mounts = _fstab_mounts(text, volume)
        if mounts.get('/', root) != root:
            continue
        mounts.pop('/', None)
        found.append((root or '/', {point.strip('/'): path or '/'
                                    for point, path in mounts.items()}))
    return found

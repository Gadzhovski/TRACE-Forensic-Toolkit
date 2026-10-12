"""Classic HFS volumes (the Mac OS Standard format), read in Python (no Qt).

HFS was the Macintosh file system from 1985 until HFS+ (Mac OS 8.1, 1998)
and stayed on floppies, CDs and older drives long after. The Sleuth Kit
reads HFS+ but not HFS. The layout (Inside Macintosh: Files, ch. 2):

* the Master Directory Block at 1 KiB ('BD'): the allocation block size,
  where allocation blocks start (in 512-byte sectors), and the first three
  extents of the extents overflow file and of the catalog file;
* both are B-trees of 512-byte nodes: a node descriptor, records, and the
  records' offsets at the end of the node; the header node says which leaf
  comes first, and leaves are chained;
* catalog keys are (parent folder id, name of up to 31 MacRoman
  characters); the leaf records are folders (id, dates), files (id, data
  and resource fork lengths, their first three extents, dates) and
  threads;
* a fork's fourth and later extents are in the extents overflow file,
  keyed by (fork, file id, first allocation block).

Dates are seconds since 1904 in the Mac's local time, with no zone: they
are given as the digits recorded ("local, no zone", as FAT's are). The data
fork is the file's content; resource forks are not shown. An HFS wrapper
around an HFS+ volume is left to The Sleuth Kit. Nothing deleted is listed.
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.HFS')

MDB_OFFSET = 1024
SIGNATURE = b'BD'
EMBEDDED_HFS_PLUS = 0x482B
NODE_SIZE = 512
#: Seconds from 1904-01-01 to 1970-01-01.
MAC_EPOCH = 2_082_844_800

ROOT_PARENT, ROOT_FOLDER = 1, 2
EXTENTS_FILE, CATALOG_FILE = 3, 4
LEAF = 0xFF
DIRECTORY, FILE, DIRECTORY_THREAD, FILE_THREAD = 1, 2, 3, 4


class HfsError(Exception):
    pass


def is_hfs(head):
    """A classic HFS Master Directory Block (not an HFS+ wrapper)."""
    if len(head) < MDB_OFFSET + 162 or \
            head[MDB_OFFSET:MDB_OFFSET + 2] != SIGNATURE:
        return False
    block_size = struct.unpack_from('>I', head, MDB_OFFSET + 20)[0]
    embedded = struct.unpack_from('>H', head, MDB_OFFSET + 124)[0]
    return block_size and block_size % 512 == 0 and \
        embedded != EMBEDDED_HFS_PLUS


def _extents(data, offset):
    """[(first allocation block, count)] of an ExtDataRec, empty ones
    left out."""
    out = []
    for number in range(3):
        start, count = struct.unpack_from('>HH', data, offset + 4 * number)
        if count:
            out.append((start, count))
    return out


def _name(data):
    return data.decode('mac_roman')


class HfsVolume:
    """The structures of one HFS volume, read from `source` (a file object
    over the partition)."""

    def __init__(self, source):
        self.source = source
        mdb = self.read(MDB_OFFSET, 162)
        if len(mdb) < 162 or mdb[:2] != SIGNATURE:
            raise HfsError("no Master Directory Block")
        (self.created, self.modified, _attributes, _files,
         _bitmap, _alloc_ptr, self.block_count, self.block_size, _clump,
         self.first_sector, _next_id, _free) = struct.unpack_from(
             '>IIHHHHHIIHIH', mdb, 2)
        self.label = _name(mdb[37:37 + mdb[36]])
        if not self.block_size or self.block_size % 512:
            raise HfsError(f"allocation block size {self.block_size}")
        if struct.unpack_from('>H', mdb, 124)[0] == EMBEDDED_HFS_PLUS:
            raise HfsError("an HFS wrapper around HFS+")
        extents_size = struct.unpack_from('>I', mdb, 130)[0]
        catalog_size = struct.unpack_from('>I', mdb, 146)[0]
        self.extents_fork = Fork(self, EXTENTS_FILE, extents_size,
                                 _extents(mdb, 134), overflow=False)
        self.catalog_fork = Fork(self, CATALOG_FILE, catalog_size,
                                 _extents(mdb, 150))
        self._overflow = None
        self._catalog = None

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def block_position(self, block):
        return self.first_sector * 512 + block * self.block_size

    # -- B-trees ------------------------------------------------------------

    def _leaf_records(self, fork):
        """Every leaf record of a B-tree: (key bytes, data bytes)."""
        header = fork.read(0, NODE_SIZE)
        if len(header) < NODE_SIZE or header[8] != 1:
            raise HfsError("no B-tree header node")
        _depth, _root, _records, first, _last, node_size = \
            struct.unpack_from('>HIIIIH', header, 14)
        if node_size != NODE_SIZE:
            raise HfsError(f"B-tree node size {node_size}")
        node = first
        seen = set()
        while node and node not in seen:
            seen.add(node)
            data = fork.read(node * NODE_SIZE, NODE_SIZE)
            if len(data) < NODE_SIZE:
                raise HfsError(f"B-tree node {node} past its fork")
            forward, _back, kind, _height, count = struct.unpack_from(
                '>IIBBH', data, 0)
            if kind != LEAF:
                raise HfsError(f"node {node} is not a leaf")
            offsets = [struct.unpack_from('>H', data, NODE_SIZE - 2 *
                                          (number + 1))[0]
                       for number in range(count + 1)]
            for number in range(count):
                start, end = offsets[number], offsets[number + 1]
                record = data[start:end]
                key_length = record[0]
                key = record[1:1 + key_length]
                body = (1 + key_length + 1) // 2 * 2
                yield key, record[body:]
            node = forward

    def overflow(self, fork_type, file_id):
        """The extents in the overflow file for one fork, in order:
        [(first file block, [(start, count)...])]."""
        if self._overflow is None:
            self._overflow = {}
            for key, data in self._leaf_records(self.extents_fork):
                kind, number, first = struct.unpack_from('>BIH', key, 0)
                self._overflow.setdefault((kind, number), []).append(
                    (first, _extents(data, 0)))
        return sorted(self._overflow.get((fork_type, file_id), []))

    def catalog(self):
        """{id: record} for every folder and file, each with its parent
        and name."""
        if self._catalog is None:
            catalog = {}
            for key, data in self._leaf_records(self.catalog_fork):
                parent = struct.unpack_from('>I', key, 1)[0]
                name = _name(key[6:6 + key[5]])
                kind = data[0]
                if kind == DIRECTORY:
                    (_flags, valence, number, created, modified,
                     backup) = struct.unpack_from('>HHIIII', data, 2)
                    catalog[number] = {
                        'kind': DIRECTORY, 'id': number, 'parent': parent,
                        'name': name, 'created': created,
                        'modified': modified, 'backup': backup,
                        'children': []}
                elif kind == FILE:
                    number = struct.unpack_from('>I', data, 20)[0]
                    size = struct.unpack_from('>I', data, 26)[0]
                    resource = struct.unpack_from('>I', data, 36)[0]
                    created, modified, backup = struct.unpack_from(
                        '>III', data, 44)
                    catalog[number] = {
                        'kind': FILE, 'id': number, 'parent': parent,
                        'name': name, 'size': size,
                        'resource_size': resource,
                        'type': data[4:8].decode('mac_roman'),
                        'creator': data[8:12].decode('mac_roman'),
                        'created': created, 'modified': modified,
                        'backup': backup,
                        'extents': _extents(data, 74),
                        'resource_extents': _extents(data, 86)}
            for record in catalog.values():
                parent = catalog.get(record['parent'])
                if parent is not None and parent['kind'] == DIRECTORY \
                        and record['id'] != ROOT_FOLDER:
                    parent['children'].append(record['id'])
            for record in catalog.values():
                if record['kind'] == DIRECTORY:
                    record['children'].sort(
                        key=lambda number: catalog[number]['name'].lower())
            self._catalog = catalog
        return self._catalog

    def allocated_ranges(self):
        """Everything before the allocation blocks, and the blocks the
        volume bitmap marks used."""
        mdb = self.read(MDB_OFFSET, 64)
        bitmap_sector = struct.unpack_from('>H', mdb, 14)[0]
        raw = self.read(bitmap_sector * 512, -(-self.block_count // 8))
        out = [(0, self.first_sector * 512)]
        run = None
        for number in range(self.block_count):
            used = bool(raw[number >> 3] >> (7 - (number & 7)) & 1) \
                if (number >> 3) < len(raw) else True
            if used and run is None:
                run = number
            elif not used and run is not None:
                out.append((self.block_position(run),
                            self.block_position(number)))
                run = None
        if run is not None:
            out.append((self.block_position(run),
                        self.block_position(self.block_count)))
        return out


class Fork:
    """One fork's bytes, through its extents (the first three, then the
    overflow file's)."""

    def __init__(self, volume, file_id, size, first, overflow=True,
                 fork_type=0):
        self.volume = volume
        self.file_id = file_id
        self.size = size
        self._first = first
        self._overflow = overflow
        self._fork_type = fork_type
        self._runs = None

    def runs(self):
        """[(file offset, length, byte position)]."""
        if self._runs is None:
            extents = list(self._first)
            if self._overflow and \
                    sum(count for _start, count in extents) * \
                    self.volume.block_size < self.size:
                for _block, more in self.volume.overflow(self._fork_type,
                                                         self.file_id):
                    extents += more
            runs = []
            offset = 0
            for start, count in extents:
                length = count * self.volume.block_size
                runs.append((offset, length,
                             self.volume.block_position(start)))
                offset += length
            self._runs = runs
        return self._runs

    def read(self, offset, length):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        out = bytearray()
        end = offset + length
        for logical, size, position in self.runs():
            if logical + size <= offset or logical >= end:
                continue
            begin = max(offset, logical)
            stop = min(end, logical + size)
            out += self.volume.read(position + begin - logical,
                                    stop - begin)
        return bytes(out)


# --- libyal's vocabulary -----------------------------------------------------

class HfsEntry:
    """A file or folder, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, record):
        self._volume = volume
        self._record = record
        self.identifier = record['id']
        self.parent_identifier = record['parent']
        self.name = record['name']
        directory = record['kind'] == DIRECTORY
        self.file_mode = (stat.S_IFDIR | 0o755) if directory else \
            (stat.S_IFREG | 0o644)
        self.size = 0 if directory else record['size']
        self.owner_identifier = self.group_identifier = 0
        self.type_creator = None if directory else \
            (record['type'], record['creator'])
        self._fork = None if directory else Fork(
            volume, record['id'], record['size'], record['extents'])

    def get_number_of_links(self):
        return 1

    @staticmethod
    def _time(value):
        # The digits the Mac recorded, as if UTC: they have no zone.
        return (value - MAC_EPOCH) * 1_000_000_000 if value else 0

    def get_modification_time_as_integer(self):
        return self._time(self._record['modified'])

    def get_creation_time_as_integer(self):
        return self._time(self._record['created'])

    def get_backup_time_as_integer(self):
        return self._time(self._record['backup'])

    symbolic_link_target = ''

    def _children(self):
        return self._record.get('children', [])

    @property
    def number_of_sub_file_entries(self):
        return len(self._children())

    def get_sub_file_entry(self, index):
        catalog = self._volume.catalog()
        return HfsEntry(self._volume, catalog[self._children()[index]])

    def read_buffer_at_offset(self, length, offset):
        if self._fork is None:
            return b''
        return self._fork.read(offset, length)


class _Volume:
    """libyal's volume vocabulary over an HfsVolume."""

    def __init__(self, volume):
        self.hfs = volume
        self.label = volume.label

    def get_root_directory(self):
        root = self.hfs.catalog().get(ROOT_FOLDER)
        if root is None:
            raise HfsError("no root folder in the catalog")
        return HfsEntry(self.hfs, root)

    def entry(self, identifier):
        record = self.hfs.catalog().get(identifier)
        return HfsEntry(self.hfs, record) if record else None

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index in range(entry.number_of_sub_file_entries):
                child = entry.get_sub_file_entry(index)
                if child.name == part:
                    entry = child
                    break
            else:
                return None
        return entry

    def close(self):
        self.hfs._catalog = None
        self.hfs._overflow = None


class HfsFileSystem(LibyalFileSystem):
    """A classic HFS volume, read like a pytsk3.FS_Info."""

    KIND = 'HFS (classic)'

    def __init__(self, volume):
        self.hfs = volume
        self.BLOCK_SIZE = volume.block_size
        super().__init__(_Volume(volume),
                         volume.block_position(volume.block_count),
                         volume.label or 'HFS volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT_FOLDER

    def _last_identifier(self):
        return max(self.hfs.catalog(), default=ROOT_FOLDER)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.hfs.allocated_ranges()

    def close(self):
        self.volume.close()


def open_hfs(source):
    """An HfsFileSystem over `source` (a file object over the partition),
    or None when it is not a classic HFS volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(MDB_OFFSET + 162)
    except (OSError, IOError):
        return None
    if not is_hfs(head):
        return None
    try:
        fs = HfsFileSystem(HfsVolume(source))
        fs.volume.get_root_directory()
        return fs
    except (HfsError, struct.error, KeyError, OSError, IOError,
            UnicodeDecodeError) as exc:
        logger.warning("HFS volume not opened: %s", exc)
        return None


def is_hfs_fs(fs):
    return isinstance(fs, HfsFileSystem)

"""ReFS 3.x (Windows 10 1703 and later, Server 2016 on, Dev Drives), read
in Python (no Qt).

The Sleuth Kit and libyal read no current ReFS, and neither has wheels; this
follows the published analyses -- Prade, Groß and Dewald, "Forensic
Analysis of the Resilient File System (ReFS) Version 3.4" (DFRWS EU 2020)
and the ReFS extension they wrote for The Sleuth Kit, Nordvik et al.,
"Reverse engineering of ReFS" (2019), and libyal's documentation -- checked
against volumes Windows itself wrote (tests/test_refs.py).

A volume is:

* a boot sector: 'ReFS' at 3, 'FSRS' at 16; sectors, bytes per sector,
  sectors per cluster, version, and (3.4 on) the container size;
* superblocks ('SUPB') at cluster 0x1E and the third- and second-last
  clusters -- the newest valid one names two checkpoints ('CHKP'); the
  newer checkpoint (by its clock) holds references to the root tables:
  0 object table, 7 container table, ...;
* tables are B+ trees of pages ('MSB+'): a page is 16 KiB (or one cluster
  when clusters are larger), its clusters each addressed -- with 4 KiB
  clusters a reference names four, not necessarily together. After the
  80-byte page header, a node: an index root (whose first word is its own
  size, and whose tail is the table's fixed data), an index header, a key
  index of entry offsets; entries have a key and a value; in an inner node
  (height > 0) each value references a child page. A node can sit inside
  another table's value (a file's table inside its directory's row).
  Stream rows (flag 0x40) are a 24-byte extent as their key;
* addresses are virtual, except the superblocks', checkpoints' and the
  container table's: the container table maps each container (band) of
  virtual clusters to where it lies -- container = lcn // (2 * clusters
  per container), at its start cluster + lcn % clusters per container.
  ReFS before 3.4 records no container size in its boot sector: the
  container rows give it;
* the object table: object id -> its table (0x600 is the root directory,
  0x701 on other directories);
* a directory's table: 0x10 its own information, 0x00020030 + name a
  subdirectory (its object id, times, attributes), 0x00010030 + name a
  file -- whose value is the file's own table: fixed data (times,
  attributes, size, file id) and attribute rows, $DATA (0x80) an inner
  table of extents (virtual start cluster, cluster offset in the file,
  cluster count; gaps are sparse), 0x80000020 a file id's name (ID2).
  Rows flagged deleted (0x04) are ignored.

Identifiers TRACE gives entries: a directory its object id << 32, a file
(directory object id << 32) | file id. Times are FILETIME, UTC.
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.ReFS')

SUPERBLOCK_CLUSTER = 0x1E
PAGE_HEADER = 0x50
MIN_PAGE = 16 * 1024
ROOT_DIRECTORY = 0x600
#: The root tables' places in a checkpoint's list.
OBJECT_TABLE, CONTAINER_TABLE = 0, 7

ROW_DELETED, ROW_STREAM = 0x04, 0x40
DIRECTORY_INFO, ID2 = 0x00000010, 0x80000020
FILE_ROW, DIRECTORY_ROW = 0x00010030, 0x00020030
ATTRIBUTE_DATA = 0x80

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILETIME_EPOCH = 116444736000000000         # 1601 -> 1970, in 100 ns


class RefsError(Exception):
    pass


def is_refs(head):
    """Whether `head` (a partition's first 512 bytes) is a ReFS boot
    sector."""
    return len(head) >= 24 and head[3:7] == b'ReFS' and head[16:20] == b'FSRS'


def _ns(filetime):
    """FILETIME as nanoseconds since 1970 (0 for none)."""
    if not filetime or filetime < _FILETIME_EPOCH:
        return 0
    return (filetime - _FILETIME_EPOCH) * 100


# --- nodes -----------------------------------------------------------------------

def _rows(data):
    """(height, [(key, value, flags)]) of the node `data` begins with (its
    index root first)."""
    if len(data) < 4:
        raise RefsError("node cut short")
    root_size = struct.unpack_from('<I', data, 0)[0]
    header = root_size
    if header + 40 > len(data):
        raise RefsError("index header outside the node")
    (_first, _end, _free, height, _f, _flags, key_start,
     count) = struct.unpack_from('<IIIBBHII', data, header)
    out = []
    for index in range(count):
        at = header + key_start + 4 * index
        if at + 4 > len(data):
            break
        entry = header + (struct.unpack_from('<I', data, at)[0] & 0xFFFF)
        if entry + 16 > len(data):
            continue
        flags = struct.unpack_from('<H', data, entry + 8)[0]
        if flags & ROW_STREAM:
            # The extent is the key; checksums follow, to data_length.
            length = struct.unpack_from('<H', data, entry + 10)[0]
            key = data[entry:entry + 24]
            value = data[entry + 24:entry + max(24, length)]
        else:
            (_size, key_offset, key_length, flags, value_offset,
             value_length) = struct.unpack_from('<IHHHHH', data, entry)
            key = data[entry + key_offset:entry + key_offset + key_length]
            value = data[entry + value_offset:
                         entry + value_offset + value_length]
        out.append((key, value, flags))
    return height, out


class RefsVolume:
    """The tables of a ReFS 3.x volume read through `source` (a file object
    over the partition)."""

    def __init__(self, source):
        self._source = source
        boot = self.read(0, 512)
        if not is_refs(boot):
            raise RefsError("no ReFS boot sector")
        (sectors, sector_size, per_cluster, self.major,
         self.minor) = struct.unpack_from('<QIIBB', boot, 24)
        if self.major < 3:
            raise RefsError(f"ReFS {self.major}.{self.minor}: only ReFS 3 "
                            f"(Windows 10 1703 on) is read")
        self.cluster = sector_size * per_cluster
        if self.cluster not in (4096, 65536):
            raise RefsError(f"cluster size {self.cluster}")
        self.size = sectors * sector_size
        self.clusters = self.size // self.cluster
        self.serial = struct.unpack_from('<Q', boot, 56)[0]
        self.container_bytes = struct.unpack_from('<Q', boot, 64)[0]
        self.page = max(self.cluster, MIN_PAGE)
        self.per_page = self.page // self.cluster
        self._containers = None
        self._objects = None
        #: Real clusters of every table page read: metadata, which carving
        #: must not take for free space.
        self.metadata = set()
        self.label = ''
        self.roots = self._checkpoint_roots()
        self._load_containers()
        self._objects = self._object_table()
        self.label = self._volume_name()

    # --- reading -----------------------------------------------------------

    def read(self, offset, length):
        self._source.seek(offset)
        return self._source.read(length)

    def translate(self, lcn):
        """The real cluster of virtual cluster `lcn`."""
        if self._containers is None:
            return lcn
        size = self._container_clusters
        start = self._containers.get(lcn // (2 * size))
        if start is None:
            raise RefsError(f"cluster {lcn:#x} is in no container")
        return start + lcn % size

    def read_page(self, lcns, virtual=True):
        """The page whose clusters `lcns` names (up to four)."""
        out = bytearray()
        for lcn in lcns[:self.per_page]:
            real = self.translate(lcn) if virtual else lcn
            self.metadata.add(real)
            out += self.read(real * self.cluster, self.cluster)
        if out[:4] != b'MSB+':
            raise RefsError(f"no table page at cluster {lcns[0]:#x}")
        return bytes(out)

    @staticmethod
    def reference(data, offset=0):
        """The four cluster numbers of a page reference."""
        return struct.unpack_from('<4Q', data, offset)

    def table(self, lcns, virtual=True):
        """Every row of the table whose root page `lcns` names."""
        return self.rows_of(self.read_page(lcns, virtual)[PAGE_HEADER:],
                            virtual)

    def rows_of(self, node, virtual=True):
        """Every row under `node` (a node's bytes, index root first),
        child pages followed."""
        height, rows = _rows(node)
        if height == 0:
            return [(k, v, f) for k, v, f in rows if not f & ROW_DELETED]
        out = []
        for _key, value, flags in rows:
            if flags & ROW_DELETED or len(value) < 32:
                continue
            child = self.read_page(self.reference(value), virtual)
            out += self.rows_of(child[PAGE_HEADER:], virtual)
        return out

    # --- bootstrapping -----------------------------------------------------

    def _checkpoint_roots(self):
        best = None
        for lcn in (SUPERBLOCK_CLUSTER, self.clusters - 3, self.clusters - 2):
            block = self.read(lcn * self.cluster, self.cluster)
            if block[:4] != b'SUPB':
                continue
            version = struct.unpack_from('<Q', block, 104)[0]
            offset, count = struct.unpack_from('<II', block, 112)
            if not 0 < count <= 4 or offset + 8 * count > len(block):
                continue
            if best is None or version > best[0]:
                best = (version, struct.unpack_from(f'<{count}Q', block,
                                                    offset))
        if best is None:
            raise RefsError("no valid superblock")
        self.metadata.update((0, SUPERBLOCK_CLUSTER, self.clusters - 3,
                              self.clusters - 2))
        newest = None
        for lcn in best[1]:
            self.metadata.update(range(lcn, lcn + self.per_page))
            block = self.read(lcn * self.cluster, self.page)
            if block[:4] != b'CHKP':
                continue
            clock = struct.unpack_from('<Q', block, 96)[0]
            count = struct.unpack_from('<I', block, 144)[0]
            if not 0 < count < 64:
                continue
            offsets = struct.unpack_from(f'<{count}I', block, 148)
            roots = [self.reference(block, o) for o in offsets
                     if o + 32 <= len(block)]
            if newest is None or clock > newest[0]:
                newest = (clock, roots)
        if newest is None:
            raise RefsError("no valid checkpoint")
        return newest[1]

    def _load_containers(self):
        """Container index -> start cluster, from the container table
        (real addresses)."""
        rows = self.table(self.roots[CONTAINER_TABLE], virtual=False)
        containers, sizes = {}, set()
        for key, value, _flags in rows:
            if len(key) < 8 or len(value) < 160:
                continue
            index = struct.unpack_from('<Q', key, 0)[0]
            start, count = struct.unpack_from('<QQ', value, 144)
            containers[index] = start
            if count:
                sizes.add(count)
        if not containers:
            raise RefsError("empty container table")
        if self.container_bytes:
            self._container_clusters = self.container_bytes // self.cluster
        elif len(sizes) == 1:
            self._container_clusters = sizes.pop()
        else:
            raise RefsError("container size not recorded")
        self._containers = containers

    def _object_table(self):
        out = {}
        for key, value, _flags in self.table(self.roots[OBJECT_TABLE]):
            if len(key) < 16 or len(value) < 64:
                continue
            out[struct.unpack_from('<Q', key, 8)[0]] = \
                self.reference(value, 32)
        return out

    def object_rows(self, oid):
        """The rows of object `oid`'s table, or None."""
        lcns = self._objects.get(oid)
        if lcns is None:
            return None
        return self.table(lcns)

    def _volume_name(self):
        """The volume label (object 0x500, row 0x510)."""
        try:
            for key, value, _flags in self.object_rows(0x500) or ():
                if len(key) >= 8 and struct.unpack_from('<Q', key)[0] == \
                        0x510:
                    return value.decode('utf-16-le', 'replace') \
                        .rstrip('\0')
        except (RefsError, struct.error) as exc:
            logger.debug("ReFS volume name: %s", exc)
        return ''

    # --- directories and files ----------------------------------------------

    def directory(self, oid):
        """{name: record} of directory `oid`: subdirectories and files."""
        rows = self.object_rows(oid)
        if rows is None:
            raise RefsError(f"directory {oid:#x} is not in the object table")
        out = {}
        for key, value, _flags in rows:
            if len(key) < 4:
                continue
            kind = struct.unpack_from('<I', key, 0)[0]
            name = key[4:].decode('utf-16-le', 'surrogatepass')
            try:
                if kind == DIRECTORY_ROW and len(value) >= 72:
                    child = struct.unpack_from('<Q', value, 8)[0]
                    (created, modified, changed,
                     accessed) = struct.unpack_from('<4Q', value, 16)
                    attributes = struct.unpack_from('<I', value, 64)[0]
                    out[name] = {
                        'directory': True, 'oid': child, 'file_id': 0,
                        'times': (created, modified, changed, accessed),
                        'attributes': attributes, 'size': 0}
                elif kind == FILE_ROW:
                    out[name] = dict(self._file(value), directory=False,
                                     oid=oid)
            except (RefsError, struct.error) as exc:
                logger.debug("ReFS %s in %#x: %s", name, oid, exc)
        return out

    def directory_times(self, oid):
        """A directory's own times (its 0x10 row), or zeros."""
        for key, value, _flags in self.object_rows(oid) or ():
            if len(key) >= 4 and struct.unpack_from('<I', key)[0] == \
                    DIRECTORY_INFO and len(value) >= 4:
                fixed = value[40:struct.unpack_from('<I', value)[0]]
                if len(fixed) >= 36:
                    return struct.unpack_from('<4Q', fixed, 0), \
                        struct.unpack_from('<I', fixed, 32)[0]
        return (0, 0, 0, 0), FILE_ATTRIBUTE_DIRECTORY

    def _file(self, value):
        """A file row's own table: its fixed data and $DATA extents."""
        root = struct.unpack_from('<I', value, 0)[0]
        fixed = value[40:root]
        if len(fixed) < 96:
            raise RefsError("file record cut short")
        created, modified, changed, accessed, attributes = \
            struct.unpack_from('<4QI', fixed, 0)
        size = struct.unpack_from('<Q', fixed, 48)[0]
        file_id = struct.unpack_from('<Q', fixed, 88)[0]
        extents, data_size = [], None
        for key, attribute, _flags in self.rows_of(value):
            if len(key) < 12:
                continue
            kind = struct.unpack_from('<I', key, 8)[0]
            name = key[12:].decode('utf-16-le', 'replace').rstrip('\0')
            if kind == ATTRIBUTE_DATA and not name:
                data_size, extents = self._data(attribute)
        return {'times': (created, modified, changed, accessed),
                'attributes': attributes, 'file_id': file_id,
                'size': data_size if data_size is not None else size,
                'extents': extents}

    def _data(self, attribute):
        """(size, [(file offset, length, byte position)]) of a $DATA
        attribute's table."""
        root = struct.unpack_from('<I', attribute, 0)[0]
        fixed = attribute[40:root]
        size = struct.unpack_from('<Q', fixed, 28)[0] \
            if len(fixed) >= 36 else 0
        extents = []
        for key, _value, _flags in self.rows_of(attribute):
            if len(key) < 24:
                continue
            lcn, _f, _length, offset, count = struct.unpack_from(
                '<QHHQI', key, 0)
            extents += self._real_runs(lcn, offset, count)
        extents.sort()
        return size, extents

    def _real_runs(self, lcn, offset, count):
        """A run of `count` virtual clusters as real byte runs -- split
        where it crosses a container."""
        out = []
        size = self._container_clusters
        while count > 0:
            room = size - lcn % size
            take = min(count, room)
            out.append((offset * self.cluster, take * self.cluster,
                        self.translate(lcn) * self.cluster))
            lcn += take
            offset += take
            count -= take
        return out


# --- libyal's vocabulary -------------------------------------------------------

def file_identifier(oid, file_id=0):
    return oid << 32 | file_id


class RefsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, name, record, parent):
        self._volume = volume
        self._record = record
        self.name = name
        self.parent_identifier = parent
        self.identifier = file_identifier(record['oid'], record['file_id'])
        directory = record['directory']
        self.file_mode = (stat.S_IFDIR | 0o755) if directory else \
            (stat.S_IFREG | 0o644)
        self.size = 0 if directory else record['size']
        self.attributes = record['attributes']
        self.owner_identifier = self.group_identifier = 0
        self.symbolic_link_target = ''
        self._children = None

    def get_number_of_links(self):
        return 1

    def get_creation_time_as_integer(self):
        return _ns(self._record['times'][0])

    def get_modification_time_as_integer(self):
        return _ns(self._record['times'][1])

    def get_inode_change_time_as_integer(self):
        return _ns(self._record['times'][2])

    def get_access_time_as_integer(self):
        return _ns(self._record['times'][3])

    def _listing(self):
        if self._children is None:
            if not self._record['directory']:
                self._children = []
            else:
                listing = self._volume.directory(self._record['oid'])
                self._children = sorted(listing.items(),
                                        key=lambda kv: kv[0].lower())
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._listing())

    def get_sub_file_entry(self, index):
        name, record = self._listing()[index]
        return RefsEntry(self._volume, name, record, self.identifier)

    @property
    def number_of_extents(self):
        return len(self._record.get('extents') or ())

    def get_extent(self, index):
        _offset, length, position = self._record['extents'][index]
        return position, length, 0

    def read_buffer_at_offset(self, length, offset):
        if self._record['directory'] or offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        out = bytearray(length)           # sparse gaps stay zeros
        end = offset + length
        for logical, size, position in self._record['extents']:
            if logical + size <= offset or logical >= end:
                continue
            begin = max(offset, logical)
            stop = min(end, logical + size)
            out[begin - offset:stop - offset] = self._volume.read(
                position + begin - logical, stop - begin)
        return bytes(out)


class _Volume:
    """libyal's volume vocabulary over a RefsVolume."""

    def __init__(self, volume):
        self.refs = volume
        self.label = volume.label
        self._by_id = {}

    def get_root_directory(self):
        times, attributes = self.refs.directory_times(ROOT_DIRECTORY)
        return RefsEntry(self.refs, '', {
            'directory': True, 'oid': ROOT_DIRECTORY, 'file_id': 0,
            'times': times, 'attributes': attributes, 'size': 0},
            file_identifier(ROOT_DIRECTORY))

    def entry(self, identifier):
        """An entry by its identifier: found by walking from the root (ReFS
        keeps no table of every file), remembered."""
        if identifier == file_identifier(ROOT_DIRECTORY):
            return self.get_root_directory()
        if identifier in self._by_id:
            return self._by_id[identifier]
        pending = [self.get_root_directory()]
        while pending:
            directory = pending.pop()
            for index in range(directory.number_of_sub_file_entries):
                child = directory.get_sub_file_entry(index)
                self._by_id.setdefault(child.identifier, child)
                if child.identifier == identifier:
                    return child
                if child.file_mode & stat.S_IFDIR:
                    pending.append(child)
        return None

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            lowered = part.lower()
            for index in range(entry.number_of_sub_file_entries):
                child = entry.get_sub_file_entry(index)
                if child.name.lower() == lowered:     # Windows: no case
                    entry = child
                    break
            else:
                return None
        return entry

    def close(self):
        self._by_id.clear()


class RefsFileSystem(LibyalFileSystem):
    """A ReFS 3.x volume, read like a pytsk3.FS_Info."""

    KIND = 'ReFS'

    def __init__(self, volume):
        self.refs = volume
        self.BLOCK_SIZE = volume.cluster
        super().__init__(_Volume(volume), volume.size,
                         volume.label or 'ReFS volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return file_identifier(ROOT_DIRECTORY)

    def _last_identifier(self):
        return file_identifier(max(self.refs._objects, default=0), 0xFFFFFFFF)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        """Live files' data, plus every table page: the root tables
        whole (allocators, schema, reference counts...) and each object's
        table, as far as they can be read."""
        out = super().allocated_ranges()
        refs = self.refs
        for index, lcns in enumerate(refs.roots):
            for virtual in ((False,) if index == CONTAINER_TABLE
                            else (True, False)):
                try:
                    refs.table(lcns, virtual)
                    break
                except (RefsError, struct.error) as exc:
                    logger.debug("ReFS root table %d: %s", index, exc)
        for oid in list(refs._objects):
            try:
                refs.object_rows(oid)
            except (RefsError, struct.error) as exc:
                logger.debug("ReFS object %#x: %s", oid, exc)
        size = refs.cluster
        out += [(lcn * size, (lcn + 1) * size)
                for lcn in sorted(refs.metadata)]
        return out

    def close(self):
        self.volume.close()


def open_refs(source):
    """A RefsFileSystem over `source` (a file object over the partition),
    or None when it is not a ReFS 3 volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(512)
    except (OSError, IOError):
        return None
    if not is_refs(head):
        return None
    try:
        fs = RefsFileSystem(RefsVolume(source))
        fs.volume.get_root_directory().number_of_sub_file_entries
        return fs
    except (RefsError, struct.error, KeyError, OSError, IOError,
            UnicodeDecodeError) as exc:
        logger.warning("ReFS volume not opened: %s", exc)
        return None


def is_refs_fs(fs):
    return isinstance(fs, RefsFileSystem)

"""QNX ETFS (the embedded transaction file system, on NAND flash) read in
pure Python (no Qt).

A head unit keeps configuration and manufacturing data on ETFS, imaged
bare as the whole flash. There is no superblock: each page of data is
followed by a 16-byte transaction record (in the spare area), and the
file system is what replaying them gives. The layout, as QNX's
fs/etfs.h has it (transcribed in NetherlandsForensicInstitute/qnxmount's
Kaitai spec, Apache-2.0):

* page = page-size data + transaction: file id (u32), cluster -- the
  page's place in its file -- (u32), cluster count (u16), transaction and
  data status codes (u8 each: low nibble 0 ok, 1 corrected, 2 erased,
  3 all ones, 5..7 errors), sequence (u32), little-endian;
* a file's current content is, per cluster, the page whose sequence is
  highest -- older copies are what it was before;
* file id 0 is the root folder, 1 the file table, 2..5 the file system's
  own (bad blocks, counts, lost+found, reserved);
* the file table: 64-byte entries, entry N for file id N: extension id
  (0 alone, 0x8000 an extension, 0xFFFF unused), parent id (0xFFFF
  deleted or never used), then mode, uid, gid, atime, mtime, ctime, size
  (u32 each) and 32 bytes of name -- a longer name goes on in the
  extension entry the first names (59 more bytes).

The page size is recorded nowhere: it is the one (512 to 16 KiB) the image
size divides into with its 16-byte records, and whose file table reads.
Live files only. Checked against qnxmount's test images (made by QNX's
mketfs, current and old layout) and the tar of their files
(tests/test_qnx.py).
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.ETFS')

KIND = 'QNX ETFS'
TRANSACTION = struct.Struct('<IIHBBI')
SPARE = 16
ENTRY_SIZE = 64
FILE_ENTRY = struct.Struct('<HHIIIIIII32s')
EXTENSION_NAME = 59
ROOT, FILE_TABLE = 0, 1
#: The file system's own files (bad blocks, counts, lost+found,
#: reserved): not listed.
SYSTEM_FIDS = (2, 3, 4, 5)
FIRST_FILE = 6
UNUSED = 0xFFFF
EXTENSION = 0x8000
PAGE_SIZES = (2048, 1024, 512, 4096, 8192, 16384)
#: Pages whose records are read at once.
READ_PAGES = 1024


class EtfsError(Exception):
    pass


def _usable(code):
    """A status code saying the page holds data (ok or corrected)."""
    return code & 0x0F in (0, 1)


def page_sizes(size):
    """The page sizes an image of `size` bytes can have, likeliest first."""
    return [page for page in PAGE_SIZES if size and
            size % (page + SPARE) == 0]


class EtfsImage:
    """The file system on `source` (a file object over the flash image of
    `size` bytes), replayed from its transaction records."""

    def __init__(self, source, size, page_size):
        self.source = source
        self.size = size
        self.page_size = page_size
        self.stride = page_size + SPARE
        self.page_count = size // self.stride
        #: {(fid, cluster): (sequence, page index)} -- the current pages.
        self.current = {}
        self._replay()
        self.entries = self._file_table()
        if ROOT not in self.entries and not any(
                entry['parent'] == ROOT for entry in self.entries.values()):
            raise EtfsError("no root folder in the file table")

    def _replay(self):
        stride, page = self.stride, self.page_size
        current = self.current
        for first in range(0, self.page_count, READ_PAGES):
            count = min(READ_PAGES, self.page_count - first)
            self.source.seek(first * stride)
            chunk = self.source.read(count * stride)
            for index in range(count):
                at = index * stride + page
                if at + SPARE > len(chunk):
                    break
                fid, cluster, _n, tacode, _dacode, sequence = \
                    TRANSACTION.unpack_from(chunk, at)
                if fid >= UNUSED or not _usable(tacode):
                    continue
                key = (fid, cluster)
                found = current.get(key)
                # Equal sequences: the later page, as qnxmount takes it.
                if found is None or sequence >= found[0]:
                    current[key] = (sequence, first + index)
        if not any(fid == FILE_TABLE for fid, _cluster in current):
            raise EtfsError("no file table pages")

    def page(self, index):
        self.source.seek(index * self.stride)
        return self.source.read(self.page_size)

    def file_bytes(self, fid, offset, length, size):
        """`length` bytes of file `fid` from `offset` (its size `size`);
        a cluster no page holds reads as erased flash (0xFF)."""
        end = min(size, offset + length)
        if offset >= end:
            return b''
        page_size = self.page_size
        out = bytearray()
        cluster = offset // page_size
        while cluster * page_size < end:
            found = self.current.get((fid, cluster))
            data = self.page(found[1]) if found is not None else \
                b'\xff' * page_size
            begin = max(offset - cluster * page_size, 0)
            stop = min(end - cluster * page_size, page_size)
            out += data[begin:stop]
            cluster += 1
        return bytes(out)

    def _file_table(self):
        clusters = [cluster for fid, cluster in self.current
                    if fid == FILE_TABLE]
        size = (max(clusters) + 1) * self.page_size
        table = self.file_bytes(FILE_TABLE, 0, size, size)
        raw = {}
        for fid in range(len(table) // ENTRY_SIZE):
            raw[fid] = table[fid * ENTRY_SIZE:(fid + 1) * ENTRY_SIZE]
        entries = {}
        for fid, data in raw.items():
            (extension, parent, mode, uid, gid, atime, mtime, ctime, size_,
             name) = FILE_ENTRY.unpack(data)
            if extension == UNUSED or extension == EXTENSION or \
                    parent == UNUSED:
                continue
            name = name.split(b'\0', 1)[0]
            if extension and extension in raw:
                more = raw[extension]
                extension_parent = struct.unpack_from('<H', more, 2)[0]
                if struct.unpack_from('<H', more, 0)[0] == EXTENSION and \
                        extension_parent == fid:
                    name += more[4:4 + EXTENSION_NAME].split(b'\0', 1)[0]
            entries[fid] = {'parent': parent, 'mode': mode, 'uid': uid,
                            'gid': gid, 'atime': atime, 'mtime': mtime,
                            'ctime': ctime, 'size': size_, 'name': name}
        return entries

    def children(self, fid):
        """[(name, fid)] of a folder: the entries whose parent it is."""
        return sorted(((entry['name'], child)
                       for child, entry in self.entries.items()
                       if entry['parent'] == fid and child != fid and
                       child >= FIRST_FILE),
                      key=lambda item: item[1])

    def allocated_ranges(self):
        """(begin, end) byte ranges of the pages live files' current
        content is in, and the file system's own (its file table, ...)."""
        live = set(self.entries) | {FILE_TABLE, *SYSTEM_FIDS}
        pages = sorted(index for (fid, _cluster), (_seq, index)
                       in self.current.items() if fid in live)
        out = []
        for index in pages:
            begin = index * self.stride
            if out and out[-1][1] == begin:
                out[-1] = (out[-1][0], begin + self.stride)
            else:
                out.append((begin, begin + self.stride))
        return out


class EtfsEntry:
    """A file or folder, answering what libyal_fs asks a file entry."""

    def __init__(self, image, fid, parent=0):
        self._image = image
        self.identifier = fid
        self.parent_identifier = parent
        entry = image.entries.get(fid) or {
            'mode': stat.S_IFDIR | 0o755, 'uid': 0, 'gid': 0, 'atime': 0,
            'mtime': 0, 'ctime': 0, 'size': 0, 'name': b''}
        if fid == ROOT and not stat.S_ISDIR(entry['mode']):
            entry = dict(entry, mode=stat.S_IFDIR | 0o755)
        self._entry = entry
        self.name = entry['name'].decode('utf-8', 'surrogateescape')
        self.file_mode = entry['mode']
        self.size = 0 if stat.S_ISDIR(entry['mode']) else entry['size']
        self.owner_identifier = entry['uid']
        self.group_identifier = entry['gid']

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._entry['mtime'] * 1_000_000_000

    def get_access_time_as_integer(self):
        return self._entry['atime'] * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._entry['ctime'] * 1_000_000_000

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        target = self.read_buffer_at_offset(self._entry['size'], 0)
        return target.rstrip(b'\0').decode('utf-8', 'surrogateescape')

    def _list(self):
        if not stat.S_ISDIR(self.file_mode):
            return []
        return self._image.children(self.identifier)

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        _name, fid = self._list()[index]
        return EtfsEntry(self._image, fid, self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._image.file_bytes(self.identifier, offset, length,
                                      self._entry['size'])


class _Volume:
    def __init__(self, image):
        self.image = image

    def get_root_directory(self):
        return EtfsEntry(self.image, ROOT)

    def entry(self, fid):
        if fid == ROOT:
            return self.get_root_directory()
        entry = self.image.entries.get(fid)
        if entry is None:
            return None
        return EtfsEntry(self.image, fid, entry['parent'])

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for name, fid in self.image.children(entry.identifier):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = EtfsEntry(self.image, fid, entry.identifier)
                    break
            else:
                return None
        return entry


class EtfsFileSystem(LibyalFileSystem):
    """An ETFS flash image, read like a pytsk3.FS_Info."""

    KIND = KIND

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.page_size
        super().__init__(_Volume(image), image.size,
                         f"QNX ETFS ({image.page_size}-byte pages)")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _last_identifier(self):
        return max(self.image.entries, default=0)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()


def open_etfs(source, size=None):
    """An EtfsFileSystem over `source` (a file object over a flash image),
    or None. Tried after every file system with a signature: there is
    none, so each page size the image's size allows is replayed until one
    gives a file table with a root."""
    try:
        if size is None:
            source.seek(0, 2)
            size = source.tell()
    except (OSError, IOError):
        return None
    for page_size in page_sizes(size):
        try:
            # A cheap look first: the first pages' records must be file
            # system records (a known status, a small file id).
            source.seek(0)
            head = source.read(min(64, size // (page_size + SPARE)) *
                               (page_size + SPARE))
            records = [TRANSACTION.unpack_from(head, at + page_size)
                       for at in range(0, len(head) - SPARE + 1,
                                       page_size + SPARE)]
            plausible = [r for r in records if r[0] < 0x100000 and
                         r[3] & 0x0F in (0, 1, 2, 3)]
            if not records or len(plausible) < len(records) * 0.9 or \
                    not any(r[0] == FILE_TABLE and _usable(r[3])
                            for r in records):
                continue
            return EtfsFileSystem(EtfsImage(source, size, page_size))
        except (EtfsError, struct.error, OSError, IOError,
                ValueError) as exc:
            logger.debug("Not ETFS with %d-byte pages: %s", page_size, exc)
    return None

"""A libyal file system volume, shaped like pytsk3's file system objects.

The Sleuth Kit in the pytsk3 wheels reads neither APFS nor XFS, and libyal
reads both (libfsapfs, libfsxfs) with the same vocabulary: a volume with a
root directory, file entries with sub-entries, `read_buffer_at_offset`,
times as nanoseconds. This presents such a volume the way the rest of TRACE
already reads every file system: `open_dir(path=|inode=)`,
`open_meta(inode=)`, entries with `info.name` / `info.meta`, `read_random`,
`as_directory`. Browsing, previews, exports, analysis, indexing and activity
then need no per-file-system code.

What these libraries do not report, these objects do not invent: no deleted
entries are listed (libyal gives the live directory tree), so nothing here
is ever reported deleted. Times are kept to the nanosecond.

A subclass says how its entries are identified (`identifier`), which
identifier is the root, and how big a block is.
"""

import logging
import stat

import pytsk3

from trace_app.core.containers import LIBYAL_LOCK, holding_libyal

logger = logging.getLogger('TRACE.LibyalFS')


def _kind(mode):
    if stat.S_ISDIR(mode or 0):
        return pytsk3.TSK_FS_META_TYPE_DIR
    if stat.S_ISLNK(mode or 0):
        return pytsk3.TSK_FS_META_TYPE_LNK
    return pytsk3.TSK_FS_META_TYPE_REG


def _split_ns(entry, which):
    try:
        value = getattr(entry, f'get_{which}_time_as_integer')()
    except (AttributeError, OSError, IOError):
        return 0, 0
    if not value:
        return 0, 0
    return int(value) // 1_000_000_000, int(value) % 1_000_000_000


class _Name:
    __slots__ = ('name', 'meta_seq', 'flags', 'par_addr', 'meta_addr',
                 'type')

    def __init__(self, fs, entry, kind, identifier):
        name = entry.name if entry.name is not None else ''
        if identifier == fs.info.root_inum:
            name = '/'
        self.name = name.encode('utf-8', 'surrogateescape')
        self.meta_seq = 0
        self.flags = pytsk3.TSK_FS_NAME_FLAG_ALLOC
        self.par_addr = getattr(entry, 'parent_identifier', 0) or 0
        self.meta_addr = identifier
        self.type = kind


class _Meta:
    def __init__(self, entry, identifier):
        mode = getattr(entry, 'file_mode', 0) or 0
        self.addr = identifier
        self.type = _kind(mode)
        self.size = int(entry.size or 0)
        self.flags = pytsk3.TSK_FS_META_FLAG_ALLOC
        self.mode = mode
        self.uid = getattr(entry, 'owner_identifier', 0) or 0
        self.gid = getattr(entry, 'group_identifier', 0) or 0
        try:
            self.nlink = entry.get_number_of_links()
        except (AttributeError, OSError, IOError):
            self.nlink = 1
        self.seq = 0
        self.mtime, self.mtime_nano = _split_ns(entry, 'modification')
        self.atime, self.atime_nano = _split_ns(entry, 'access')
        self.ctime, self.ctime_nano = _split_ns(entry, 'inode_change')
        self.crtime, self.crtime_nano = _split_ns(entry, 'creation')
        try:
            self.link = entry.symbolic_link_target or ''
        except (OSError, IOError):
            self.link = ''


class _Info:
    __slots__ = ('name', 'meta', 'fs_info')

    def __init__(self, fs, entry):
        identifier = fs.identifier(entry)
        meta = _Meta(entry, identifier)
        self.meta = meta
        self.name = _Name(fs, entry, meta.type, identifier)
        self.fs_info = fs.info


class LibyalFile:
    """One file or directory -- pytsk3.File's shape."""

    @holding_libyal
    def __init__(self, fs, entry):
        self._fs = fs
        self._entry = entry
        self.info = _Info(fs, entry)

    @holding_libyal
    def read_random(self, offset, length, *_attribute):
        size = self.info.meta.size
        if offset >= size or length <= 0:
            return b''
        return self._entry.read_buffer_at_offset(min(length, size - offset),
                                                 offset)

    def as_directory(self):
        if self.info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
            raise IOError(f"{self.info.name.name!r} is not a directory")
        return LibyalDirectory(self._fs, self._entry)

    def __iter__(self):
        # No NTFS-style attributes. Extended attributes exist, but are not
        # data streams TRACE lists.
        return iter(())


class LibyalDirectory:
    def __init__(self, fs, entry):
        self._fs = fs
        self._entry = entry

    def __iter__(self):
        try:
            with LIBYAL_LOCK:
                count = self._entry.number_of_sub_file_entries
        except (OSError, IOError) as exc:
            logger.warning("%s directory unreadable: %s", self._fs.KIND, exc)
            return
        for index in range(count):
            try:
                with LIBYAL_LOCK:   # not held across the yield
                    item = LibyalFile(self._fs,
                                      self._entry.get_sub_file_entry(index))
                yield item
            except (OSError, IOError) as exc:
                logger.debug("%s entry %d unreadable: %s", self._fs.KIND,
                             index, exc)


class _FsInfo:
    """pytsk3's FS_Info.info, as far as TRACE asks it."""

    def __init__(self, size, block_size, root, last_inum):
        self.ftype = 0                      # no TSK type: see is_libyal()
        self.block_size = block_size
        self.root_inum = root
        self.first_block = 0
        self.block_count = size // block_size if block_size else 0
        self.last_block = max(0, self.block_count - 1)
        self.last_inum = last_inum
        self.inum_count = last_inum
        self.endian = 0


class LibyalFileSystem:
    """A libyal volume, read like a pytsk3.FS_Info. Subclasses set KIND and
    implement `identifier`, `_root_identifier`, `_by_identifier`."""

    KIND = 'libyal'
    BLOCK_SIZE = 4096

    @holding_libyal
    def __init__(self, volume, size=0, name=''):
        self.volume = volume
        self.name = name
        self.info = _FsInfo(size, self.BLOCK_SIZE, self._root_identifier(),
                            self._last_identifier())

    # --- what a subclass says ----------------------------------------------

    def identifier(self, entry):
        raise NotImplementedError

    def _root_identifier(self):
        raise NotImplementedError

    def _last_identifier(self):
        return 0

    def _by_identifier(self, identifier):
        raise NotImplementedError

    # --- pytsk3's FS_Info -------------------------------------------------

    @holding_libyal
    def _entry(self, path=None, inode=None):
        if inode is not None:
            return self._by_identifier(int(inode))
        if not path or path == '/':
            return self.volume.get_root_directory()
        return self.volume.get_file_entry_by_path(path)

    def open_dir(self, path=None, inode=None):
        entry = self._entry(path, inode)
        if entry is None:
            raise IOError(f"No such directory: {path or inode}")
        return LibyalFile(self, entry).as_directory()

    def open_meta(self, inode):
        entry = self._entry(inode=inode)
        if entry is None:
            raise IOError(f"No file entry {inode}")
        return LibyalFile(self, entry)

    def open(self, path):
        entry = self._entry(path=path)
        if entry is None:
            raise IOError(f"No such file: {path}")
        return LibyalFile(self, entry)


def is_libyal(fs):
    return isinstance(fs, LibyalFileSystem)

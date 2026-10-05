"""APFS through libfsapfs, shaped like pytsk3's file system objects.

The Sleuth Kit in the pytsk3 wheels does not read APFS (it needs pool
support pytsk3 does not expose), so an APFS volume is read with libfsapfs,
and this module presents it the way the rest of TRACE already reads every
other file system: `open_dir(path=|inode=)`, `open_meta(inode=)`, entries
with `info.name` / `info.meta`, `read_random`, `as_directory`. Browsing,
previews, exports, analysis, indexing and activity then need no APFS code.

What APFS does not have, these objects do not invent: there is no deleted
entry in an APFS directory listing (a deleted file's name is gone; its data
may live on in snapshots, which libfsapfs does not expose), so nothing here
is ever reported deleted. Times are kept to the nanosecond APFS stores.

An encrypted volume is unlocked with its password or recovery key before it
is shaped; the key stays in memory, as BitLocker's does.
"""

import logging
import stat

import pytsk3

from trace_app.core.containers import LIBYAL_LOCK, holding_libyal

logger = logging.getLogger('TRACE.APFS')

ROOT_IDENTIFIER = 2
BLOCK_SIZE = 4096


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

    def __init__(self, entry, kind):
        name = entry.name if entry.name is not None else ''
        if entry.identifier == ROOT_IDENTIFIER:
            name = '/'
        self.name = name.encode('utf-8', 'surrogateescape')
        self.meta_seq = 0
        self.flags = pytsk3.TSK_FS_NAME_FLAG_ALLOC
        self.par_addr = getattr(entry, 'parent_identifier', 0) or 0
        self.meta_addr = entry.identifier
        self.type = kind


class _Meta:
    def __init__(self, entry):
        mode = getattr(entry, 'file_mode', 0) or 0
        self.addr = entry.identifier
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
        meta = _Meta(entry)
        self.meta = meta
        self.name = _Name(entry, meta.type)
        self.fs_info = fs.info


class ApfsFile:
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
        return ApfsDirectory(self._fs, self._entry)

    def __iter__(self):
        # No NTFS-style attributes. Extended attributes exist in APFS but
        # are not data streams TRACE lists.
        return iter(())


class ApfsDirectory:
    def __init__(self, fs, entry):
        self._fs = fs
        self._entry = entry

    def __iter__(self):
        try:
            with LIBYAL_LOCK:
                count = self._entry.number_of_sub_file_entries
        except (OSError, IOError) as exc:
            logger.warning("APFS directory unreadable: %s", exc)
            return
        for index in range(count):
            try:
                with LIBYAL_LOCK:   # not held across the yield
                    item = ApfsFile(self._fs,
                                    self._entry.get_sub_file_entry(index))
                yield item
            except (OSError, IOError) as exc:
                logger.debug("APFS entry %d unreadable: %s", index, exc)


class _FsInfo:
    """pytsk3's FS_Info.info, as far as TRACE asks it."""

    def __init__(self, volume):
        try:
            size = int(volume.size or 0)
        except (IOError, OSError):
            size = 0
        self.ftype = 0                      # no TSK type; see is_apfs()
        self.block_size = BLOCK_SIZE
        self.root_inum = ROOT_IDENTIFIER
        self.first_block = 0
        self.block_count = size // BLOCK_SIZE
        self.last_block = max(0, self.block_count - 1)
        try:
            self.last_inum = int(volume.next_file_entry_identifier) - 1
        except (AttributeError, OSError, IOError, TypeError):
            self.last_inum = 0
        self.inum_count = self.last_inum
        self.endian = 0


class ApfsFileSystem:
    """An unlocked APFS volume, read like a pytsk3.FS_Info."""

    @holding_libyal
    def __init__(self, volume, container=None, name=''):
        self.volume = volume
        self.container = container
        self.name = name or getattr(volume, 'name', '') or 'APFS volume'
        self.info = _FsInfo(volume)

    @holding_libyal
    def _entry(self, path=None, inode=None):
        if inode is not None:
            return self.volume.get_file_entry_by_identifier(int(inode))
        if not path or path == '/':
            return self.volume.get_root_directory()
        return self.volume.get_file_entry_by_path(path)

    def open_dir(self, path=None, inode=None):
        entry = self._entry(path, inode)
        if entry is None:
            raise IOError(f"No such directory: {path or inode}")
        return ApfsFile(self, entry).as_directory()

    def open_meta(self, inode):
        entry = self._entry(inode=inode)
        if entry is None:
            raise IOError(f"No file entry {inode}")
        return ApfsFile(self, entry)

    def open(self, path):
        entry = self._entry(path=path)
        if entry is None:
            raise IOError(f"No such file: {path}")
        return ApfsFile(self, entry)


def is_apfs(fs):
    return isinstance(fs, ApfsFileSystem)

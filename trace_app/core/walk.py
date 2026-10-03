"""Every file on an image, once, with the reference the rest of TRACE uses.

The analysis pass walks for itself; modules that read files on their own
(YARA, persistence) walk with this, so their artifact refs are the
analysis's: partition start, inode, and the sequence recorded in the name
entry. Hard links and directory cycles are visited once.
"""

import logging

import pytsk3

from trace_app.core.case import make_artifact_ref

logger = logging.getLogger('TRACE.Walk')

MAX_DEPTH = 64


class WalkCancelled(Exception):
    """The examiner stopped the walk."""


class FileEntry:
    __slots__ = ('offset', 'inode', 'sequence', 'name', 'path', 'size',
                 'deleted', 'fs')

    def __init__(self, offset, inode, sequence, name, path, size, deleted,
                 fs):
        self.offset, self.inode, self.sequence = offset, inode, sequence
        self.name, self.path, self.size = name, path, size
        self.deleted, self.fs = deleted, fs

    @property
    def ref(self):
        return make_artifact_ref(self.offset, self.inode, self.sequence)

    def read(self, length=None, start=0):
        """Up to `length` bytes from `start` (the whole file by default)."""
        handle = self.fs.open_meta(inode=self.inode)
        size = int(handle.info.meta.size)
        length = size - start if length is None else min(length,
                                                         size - start)
        if length <= 0:
            return b''
        return handle.read_random(start, length)


def volume_offsets(image_handler):
    """Every file system to read: partitions, and the logical and APFS
    volumes inside LVM and APFS partitions (ImageHandler.volume_offsets)."""
    if hasattr(image_handler, 'volume_offsets'):
        return image_handler.volume_offsets()
    partitions = image_handler.get_partitions()
    return [p[2] for p in partitions] if partitions else [0]


def iter_files(image_handler, should_stop=None, offsets=None):
    """FileEntry for every regular file with content, on every volume."""
    for offset in dict.fromkeys(offsets or volume_offsets(image_handler)):
        fs = image_handler.get_fs_info(offset)
        if fs is None:
            continue
        visited = set()
        yield from _walk(fs, fs.open_dir(path='/'), '', 0, offset, visited,
                         should_stop)


def count_files(image_handler, should_stop=None):
    return sum(1 for _ in iter_files(image_handler, should_stop))


def _walk(fs, directory, path, depth, offset, visited, should_stop):
    if depth > MAX_DEPTH:
        return
    for entry in directory:
        if should_stop and should_stop():
            raise WalkCancelled()
        info = entry.info
        if info.name is None or info.meta is None:
            continue
        name = info.name.name.decode('utf-8', 'replace')
        if name in ('.', '..'):
            continue
        meta = info.meta
        if meta.addr in visited:
            continue
        visited.add(meta.addr)
        child = f"{path}/{name}"
        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                yield from _walk(fs, entry.as_directory(), child, depth + 1,
                                 offset, visited, should_stop)
            except WalkCancelled:
                raise
            except Exception as exc:
                logger.debug("Could not list %s: %s", child, exc)
            continue
        if not meta.size or meta.type != pytsk3.TSK_FS_META_TYPE_REG:
            continue
        yield FileEntry(offset, meta.addr, getattr(info.name, 'meta_seq',
                                                   None), name, child,
                        int(meta.size),
                        not (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC),
                        fs)

"""Logical evidence -- a tree of files with no disk underneath -- shaped
like pytsk3's file system objects.

An AD1 or L01 image, a folder of collected files (a KAPE, Velociraptor or
UAC triage collection, a phone's extraction), a ZIP or TAR of one, an
iTunes backup: none of these is a disk. Each source builds a
`LogicalFileSystem` -- nodes with names, sizes, times and a function that
reads their bytes -- and the rest of TRACE reads it exactly as it reads a
volume through The Sleuth Kit: `open_dir(path=|inode=)`, `open_meta`,
entries with `info.name` / `info.meta`, `read_random`, `as_directory`.
Browsing, previews, exports, analysis, indexing, activity, YARA and the
timeline need no code of their own. It is what core/apfs.py does for APFS.

Nothing is extracted: every read goes to the source (the AD1 chunk, the
ZIP member, the file in the folder) when it is asked for. There are no
sectors and no unallocated space, so nothing is carved from logical
evidence; a deleted file is listed only when the source says it was one.

Inode 1 is the root; files are numbered in the order the source lists
them, which the source keeps stable, so artifact refs survive reopening.
"""

import logging
import posixpath

import pytsk3

logger = logging.getLogger('TRACE.Logical')

ROOT = 1
BLOCK_SIZE = 512

#: The time slots TRACE reads, as TSK names them.
TIMES = ('mtime', 'atime', 'ctime', 'crtime')


class Node:
    __slots__ = ('inode', 'parent', 'name', 'is_dir', 'size', 'times',
                 'children', 'reader', 'deleted', 'facts')

    def __init__(self, inode, parent, name, is_dir, size=0, times=None,
                 reader=None, deleted=False, facts=None):
        self.inode, self.parent, self.name = inode, parent, name
        self.is_dir, self.size = is_dir, int(size or 0)
        #: {'mtime': (seconds, nanoseconds), ...} -- UTC.
        self.times = times or {}
        self.children = {} if is_dir else None
        #: reader(offset, length) -> bytes
        self.reader = reader
        self.deleted = deleted
        #: What the source records about the file beyond TSK's fields
        #: (stored hashes, attributes, the original path...).
        self.facts = facts or {}


class _Name:
    __slots__ = ('name', 'meta_seq', 'flags', 'par_addr', 'meta_addr',
                 'type')

    def __init__(self, node, kind):
        self.name = ('/' if node.inode == ROOT else node.name).encode(
            'utf-8', 'surrogateescape')
        self.meta_seq = 0
        self.flags = (pytsk3.TSK_FS_NAME_FLAG_UNALLOC if node.deleted else
                      pytsk3.TSK_FS_NAME_FLAG_ALLOC)
        self.par_addr = node.parent
        self.meta_addr = node.inode
        self.type = kind


class _Meta:
    def __init__(self, node):
        self.addr = node.inode
        self.type = (pytsk3.TSK_FS_META_TYPE_DIR if node.is_dir else
                     pytsk3.TSK_FS_META_TYPE_REG)
        self.size = 0 if node.is_dir else node.size
        self.flags = (pytsk3.TSK_FS_META_FLAG_UNALLOC if node.deleted else
                      pytsk3.TSK_FS_META_FLAG_ALLOC)
        self.mode = self.uid = self.gid = 0
        self.nlink = 1
        self.seq = 0
        self.link = ''
        for slot in TIMES:
            seconds, nanos = node.times.get(slot) or (0, 0)
            setattr(self, slot, int(seconds))
            setattr(self, f'{slot}_nano', int(nanos))


class _Info:
    __slots__ = ('name', 'meta', 'fs_info')

    def __init__(self, fs, node):
        self.meta = _Meta(node)
        self.name = _Name(node, self.meta.type)
        self.fs_info = fs.info


class LogicalFile:
    """One file or folder -- pytsk3.File's shape."""

    def __init__(self, fs, node):
        self._fs = fs
        self.node = node
        self.info = _Info(fs, node)

    def read_random(self, offset, length, *_attribute):
        size = self.node.size
        if self.node.is_dir or offset >= size or length <= 0 or \
                self.node.reader is None:
            return b''
        return self.node.reader(offset, min(length, size - offset))

    def as_directory(self):
        if not self.node.is_dir:
            raise IOError(f"{self.node.name!r} is not a folder")
        return LogicalDirectory(self._fs, self.node)

    def __iter__(self):
        return iter(())             # no NTFS-style attributes


class LogicalDirectory:
    def __init__(self, fs, node):
        self._fs = fs
        self._node = node

    def __iter__(self):
        for inode in self._node.children.values():
            yield LogicalFile(self._fs, self._fs.nodes[inode])


class _FsInfo:
    """pytsk3's FS_Info.info, as far as TRACE asks it."""

    def __init__(self, fs):
        self.ftype = 0                      # no TSK type; see is_logical()
        self.block_size = BLOCK_SIZE
        self.root_inum = ROOT
        self.first_block = 0
        self.block_count = 0
        self.last_block = 0
        self._fs = fs
        self.endian = 0

    @property
    def last_inum(self):
        return max(self._fs.nodes)

    @property
    def inum_count(self):
        return len(self._fs.nodes)


class LogicalFileSystem:
    """A tree of files from a logical source, read like a pytsk3.FS_Info.

    `label` is what the examiner is shown as the file system ("AD1",
    "Folder", "ZIP"...); `source` says where it came from."""

    def __init__(self, label, source=''):
        self.label = label
        self.source = source
        self.nodes = {ROOT: Node(ROOT, ROOT, '', True)}
        self.info = _FsInfo(self)
        #: Things the source records about itself (stored image hashes,
        #: the acquiring tool, the device...), for Image Information.
        self.facts = {}
        #: What could not be read, and why.
        self.problems = []

    # --- building --------------------------------------------------------------

    def add(self, parent, name, is_dir, **fields):
        """A new node under `parent`; returns its inode. A name already in
        that folder gets ' (2)', ' (3)'... -- sources can hold duplicates."""
        folder = self.nodes[parent]
        unique, n = name, 1
        while unique in folder.children:
            n += 1
            unique = f"{name} ({n})"
        inode = len(self.nodes) + 1
        self.nodes[inode] = Node(inode, parent, unique, is_dir, **fields)
        folder.children[unique] = inode
        return inode

    def folder(self, path):
        """The inode of the folder at `path`, made (with its parents) if it
        does not exist yet."""
        inode = ROOT
        for part in _parts(path):
            node = self.nodes[inode]
            child = node.children.get(part)
            if child is None or not self.nodes[child].is_dir:
                child = self.add(inode, part, True)
            inode = child
        return inode

    def add_file(self, path, **fields):
        """A file at `path` ('a/b/c.txt'), its folders made as needed."""
        parent, name = posixpath.split(path.strip('/'))
        return self.add(self.folder(parent), name, False, **fields)

    # --- reading --------------------------------------------------------------

    def lookup(self, path):
        """The node at `path`: exact names first, then ignoring case (TSK
        does on NTFS and FAT, and Windows paths are written either way)."""
        node = self.nodes[ROOT]
        for part in _parts(path):
            if not node.is_dir:
                return None
            inode = node.children.get(part)
            if inode is None:
                lowered = part.lower()
                inode = next((i for n, i in node.children.items()
                              if n.lower() == lowered), None)
            if inode is None:
                return None
            node = self.nodes[inode]
        return node

    def path_of(self, inode):
        parts = []
        node = self.nodes.get(inode)
        while node is not None and node.inode != ROOT:
            parts.append(node.name)
            node = self.nodes.get(node.parent)
        return '/' + '/'.join(reversed(parts))

    def open_dir(self, path=None, inode=None):
        return self._file(path, inode).as_directory()

    def open_meta(self, inode):
        return self._file(None, inode)

    def open(self, path):
        return self._file(path, None)

    def _file(self, path, inode):
        node = self.nodes.get(int(inode)) if inode is not None else \
            self.lookup(path or '/')
        if node is None:
            raise IOError(f"No such file: {path or inode}")
        return LogicalFile(self, node)

    def total_size(self):
        return sum(n.size for n in self.nodes.values() if not n.is_dir)

    def close(self):
        closer = self.facts.pop('_close', None)
        if closer is not None:
            try:
                closer()
            except Exception as exc:
                logger.debug("Closing %s: %s", self.source, exc)


def _parts(path):
    return [p for p in (path or '').replace('\\', '/').split('/')
            if p and p != '.']


def is_logical(fs):
    return isinstance(fs, LogicalFileSystem)


#: Names whose presence makes a folder the top of an operating system's
#: file system: one of the first set (Windows), or two of another.
_WINDOWS_MARKERS = {'windows', 'users', 'documents and settings',
                    'programdata', '$recycle.bin'}
_UNIX_MARKERS = ({'etc', 'home', 'var', 'usr', 'root', 'opt'},
                 {'users', 'library', 'private', 'system', 'applications'})


def system_roots(fs, depth=4):
    """Folders of a collection that are the top of a system's file system
    -- 'C' in a KAPE output, 'uploads/auto/C%3A' in a Velociraptor one,
    the root itself for a copied drive -- shallowest first. The root if
    none is."""
    found = []
    level = [ROOT]
    for _ in range(depth + 1):
        following = []
        for inode in level:
            node = fs.nodes[inode]
            names = {n.lower() for n in node.children}
            if names & _WINDOWS_MARKERS or any(len(names & markers) >= 2
                                               for markers in _UNIX_MARKERS):
                found.append(fs.path_of(inode))
                continue                    # not inside a system's own tree
            following += [i for i in node.children.values()
                          if fs.nodes[i].is_dir]
        level = following
    return found or ['/']

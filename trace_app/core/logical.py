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
from collections.abc import Mapping
from functools import partial

import pytsk3

logger = logging.getLogger('TRACE.Logical')

ROOT = 1
BLOCK_SIZE = 512

#: The time slots TRACE reads, as TSK names them.
TIMES = ('mtime', 'atime', 'ctime', 'crtime')
#: A listing's time columns (core/folder_listing.TIME_SLOTS) and its "no
#: such time".
TIMES_KEPT = TIMES
MISSING_TIME = -(2 ** 63)


def birth_ns(info):
    """A stat result's creation time in ns, or None. st_birthtime_ns is
    Windows' only (3.12+); macOS and BSD give st_birthtime as a float --
    without it a folder opened on a Mac had no creation times at all."""
    birth = getattr(info, 'st_birthtime_ns', None)
    if birth is None:
        seconds = getattr(info, 'st_birthtime', None)
        if seconds is not None:
            birth = round(seconds * 1_000_000_000)
    return birth


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


class ListedNodes(Mapping):
    """`LogicalFileSystem.nodes` over a folder's listing in columns
    (core/folder_listing.Listing): a Node is made the first time it is
    asked for and kept. 1.3 million Nodes made at once took 5.5 s; most
    openings ask for a few thousand."""

    def __init__(self, listing, reader):
        self._listing = listing
        self._reader = reader               # reader(inode, offset, length)
        self._made = {}
        self._size = len(listing)

    def __len__(self):
        return self._size + sum(1 for inode in self._made
                                if inode > self._size)

    def __iter__(self):
        yield from range(1, self._size + 1)
        yield from sorted(i for i in self._made if i > self._size)

    def __contains__(self, inode):
        return (isinstance(inode, int) and 1 <= inode <= self._size) or \
            inode in self._made

    def __getitem__(self, inode):
        node = self._made.get(inode)
        if node is None:
            if not isinstance(inode, int) or not 1 <= inode <= self._size:
                raise KeyError(inode)
            node = self._made[inode] = self._make(inode)
        return node

    def __setitem__(self, inode, node):
        self._made[inode] = node

    def values(self):
        made, make = self._made, self._make
        for inode in self:
            node = made.get(inode)
            if node is None:
                node = made[inode] = make(inode)
            yield node

    def items(self):
        for node in self.values():
            yield node.inode, node

    def file_names(self):
        """Every file's name, from the columns: no node is made."""
        names = self._listing.names
        return (names[index] for index, kind in
                enumerate(self._listing.kinds) if not kind)

    def _make(self, inode):
        listing, index = self._listing, inode - 1
        mtimes, atimes, ctimes, crtimes = listing.times
        times = {}
        value = mtimes[index]
        if value != MISSING_TIME:
            times['mtime'] = divmod(value, 1_000_000_000)
        value = atimes[index]
        if value != MISSING_TIME:
            times['atime'] = divmod(value, 1_000_000_000)
        value = ctimes[index]
        if value != MISSING_TIME:
            times['ctime'] = divmod(value, 1_000_000_000)
        value = crtimes[index]
        if value != MISSING_TIME:
            times['crtime'] = divmod(value, 1_000_000_000)
        if listing.kinds[index] != 1:
            return Node(inode, listing.parents[index], listing.names[index],
                        False, listing.sizes[index], times,
                        partial(self._reader, inode))
        node = Node(inode, listing.parents[index], listing.names[index],
                    True, 0, times)
        first, names = listing.first[index], listing.names
        node.children = {names[child - 1]: child for child in
                         range(first, first + listing.count[index])}
        return node


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
        #: the acquiring tool, the device...), for Evidence Information.
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
        listing = getattr(self, 'listing', None)
        if listing is not None:
            return sum(size for size, kind in zip(listing.sizes,
                                                  listing.kinds) if not kind)
        return sum(n.size for n in self.nodes.values() if not n.is_dir)

    def file_names(self):
        """Every file's name (folders' not), without making nodes where
        the source keeps them as columns (a folder's listing)."""
        if isinstance(self.nodes, ListedNodes):
            return self.nodes.file_names()
        return (n.name for n in self.nodes.values() if not n.is_dir)

    def file_rows(self):
        """(folder path, name, size) of every live file -- folder '' at the
        root, else '/a/b' -- in source order. Over a folder's listing no
        node is made and each folder's path is built once: a node and a
        path_of per file took 20 s on a Mac folder's 1.3 million."""
        nodes = self.nodes
        if isinstance(nodes, ListedNodes):
            listing = nodes._listing
            names, parents, kinds, sizes = (listing.names, listing.parents,
                                            listing.kinds, listing.sizes)
            # A folder is numbered when its parent is listed, so its
            # parent's path is always known first.
            folders = {ROOT: ''}
            for index, kind in enumerate(kinds):
                if index + 1 == ROOT:
                    continue
                parent = folders.get(parents[index])
                if parent is None:
                    continue
                if kind == 1:
                    folders[index + 1] = f"{parent}/{names[index]}"
                else:
                    yield parent, names[index], sizes[index]
            # Nodes added past the listing (none for a plain folder).
            extra = [node for inode, node in nodes._made.items()
                     if inode > len(listing)]
        else:
            extra = nodes.values()
        paths = {}
        for node in extra:
            if node.is_dir or node.deleted:
                continue
            folder = paths.get(node.parent)
            if folder is None:
                folder = self.path_of(node.parent)
                folder = paths[node.parent] = '' if folder == '/' else folder
            yield folder, node.name, node.size

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
                 {'users', 'library', 'private', 'system', 'applications'},
                 # Android: a whole file system, or its data partition.
                 {'data', 'system', 'vendor', 'apex', 'product'},
                 {'data', 'system_ce', 'system_de', 'user_de', 'misc'})


def _child(fs, node, name):
    """The folder `name` in `node`, ignoring case, or None."""
    for child, inode in node.children.items():
        if child.lower() == name and fs.nodes[inode].is_dir:
            return fs.nodes[inode]
    return None


def _phone_root(fs, node):
    """A folder that is the top of a phone's file system as extraction
    tools lay it out: iOS's private/var/mobile, or Android's data/data or
    data/user (often alone, under the tool's own 'filesystem1', 'Dump'
    or 'fs' folder)."""
    path = node
    for name in ('private', 'var', 'mobile'):
        path = _child(fs, path, name) if path is not None else None
    if path is not None:
        return True
    data = _child(fs, node, 'data')
    return data is not None and any(
        _child(fs, data, name) is not None
        for name in ('data', 'user', 'user_de', 'system_ce'))


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
                                               for markers in _UNIX_MARKERS) \
                    or _phone_root(fs, node):
                found.append(fs.path_of(inode))
                continue                    # not inside a system's own tree
            following += [i for i in node.children.values()
                          if fs.nodes[i].is_dir]
        level = following
    return found or ['/']

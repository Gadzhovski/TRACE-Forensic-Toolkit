"""The names inside deleted folders on ext2/3/4.

Deleting a folder loses the way to its files' names, a different way on
each ext (NIST's DFR-11): ext2 clears the parent's entry for the folder
(its inode number reads 0), so nothing reaches the folder; ext3 empties
the folder's inode (no blocks, size 0) and its journal logs it already
empty; ext4 zeroes the extents. The files then show as nameless orphans,
or (ext2) not at all.

The folder's directory block itself is seldom wiped. It is found:
* ext2 -- from the deleted folder's inode, which keeps its block
  pointers: every unallocated directory inode is looked at (ext2 volumes
  are small);
* ext3 / ext4 -- by searching the folder's block group (a directory's
  blocks are placed in its inode's group) for a block that starts with
  the folder's own "." entry followed by "..".
Its entries -- live and the deleted ones left in record slack -- give
each file's name and inode (ext_journal._directory_entries).
"""

import logging
import struct

from trace_app.core.ext_journal import _directory_entries

logger = logging.getLogger('TRACE.ExtFolders')

S_IFMT, S_IFDIR = 0o170000, 0o040000
#: Read this much of a block group at a time while searching it.
CHUNK = 4 * 1024 * 1024


def _dot(inode, filetype=True):
    """The bytes a directory block starts with: its "." entry."""
    kind = b'\x01\x02' if filetype else b'\x01\x00'
    return struct.pack('<IH', inode, 12) + kind + b'.\x00\x00\x00'


def _starts_directory(block, inode):
    """Whether `block` is the first block of directory `inode`: "." with
    its number, then ".." (any parent)."""
    if len(block) < 24 or not (block.startswith(_dot(inode)) or
                               block.startswith(_dot(inode, False))):
        return False
    return block[12 + 6:12 + 8] in (b'\x02\x02', b'\x02\x00') and \
        block[12 + 8:12 + 10] == b'..'


def _entries(block, folder):
    """[(inode, name)] of a folder's block, "." and ".." left out; and its
    parent's inode."""
    found = _directory_entries(block)
    parent = next((inode for inode, name in found if name == '..'), None)
    return [(inode, name) for inode, name in found
            if name not in ('.', '..') and inode and inode != folder], parent


def deleted_folders(geometry, known=(), every_inode=False):
    """{folder inode: {'parent': inode, 'entries': [(inode, name)],
    'found': 'inode' | 'search'}} for deleted folders: those in `known`
    (deleted folders the listing reached) and, with `every_inode`, every
    unallocated directory inode in the used part of the inode tables --
    a folder whose entry was overwritten is reached no other way. Never
    raises."""
    folders = {}
    try:
        candidates = set(int(i) for i in known if i)
        if every_inode:
            candidates |= set(_unallocated_folders(geometry))
        searched = []
        for folder in sorted(candidates):
            entry = _from_inode(geometry, folder)
            if entry is not None:
                folders[folder] = entry
            else:
                searched.append(folder)
        folders.update(_by_search(geometry, searched))
    except Exception as exc:
        logger.debug("Deleted folders not read: %s", exc)
    return folders


def _unallocated_folders(geometry):
    """Inode numbers of unallocated directory inodes, group by group."""
    for group in range(geometry.groups()):
        for number, raw, allocated in geometry.group_inodes(group):
            if not allocated and len(raw) >= 2 and \
                    struct.unpack_from('<H', raw, 0)[0] & S_IFMT == S_IFDIR:
                yield number


def _from_inode(geometry, folder):
    """The folder's entries through the block pointers its inode still
    holds (ext2), or None."""
    raw, _allocated = geometry.inode(folder)
    if struct.unpack_from('<H', raw, 0)[0] & S_IFMT != S_IFDIR:
        return None
    size = struct.unpack_from('<I', raw, 4)[0]
    runs = geometry.blocks_of(raw, size) if size else None
    if not runs:
        return None
    entries, parent, first = [], None, True
    for _logical, block, count in runs:
        for index in range(count):
            if not block:
                continue
            data = geometry.read((block + index) * geometry.block,
                                 geometry.block)
            if first and not _starts_directory(data, folder):
                return None                # the block is another's now
            first = False
            more, up = _entries(data, folder)
            entries += more
            parent = parent or up
    return {'parent': parent, 'entries': entries, 'found': 'inode'}


def _by_search(geometry, folders):
    """{folder: entry} for folders whose first block is found by searching
    the pool of block groups their inode's group belongs to (one group, or
    a flex_bg pool -- ext4 places a directory's blocks anywhere in its
    pool). Each pool is read once for all its folders. Several copies of
    a block (an older one in the journal area): their entries merged."""
    pools = {}
    for folder in folders:
        group = (folder - 1) // geometry.inodes_per_group
        pools.setdefault(group // geometry.groups_per_flex, []).append(folder)
    found = {}
    span = max(CHUNK // geometry.block, 1)
    for pool, members in sorted(pools.items()):
        first = geometry.first_data_block + \
            pool * geometry.groups_per_flex * geometry.blocks_per_group
        last = min(first + geometry.groups_per_flex *
                   geometry.blocks_per_group, geometry.blocks_count)
        signatures = {}
        for folder in members:
            for signature in (_dot(folder), _dot(folder, False)):
                signatures[signature] = folder
        state = {folder: ([], None, set()) for folder in members}
        for chunk_start in range(first, last, span):
            count = min(span, last - chunk_start)
            data = geometry.read(chunk_start * geometry.block,
                                 count * geometry.block)
            for signature, folder in signatures.items():
                at = data.find(signature)
                while at != -1:
                    if at % geometry.block == 0:
                        block = data[at:at + geometry.block]
                        if _starts_directory(block, folder):
                            entries, parent, seen = state[folder]
                            more, up = _entries(block, folder)
                            state[folder] = (entries, parent or up, seen)
                            for item in more:
                                if item not in seen:
                                    seen.add(item)
                                    entries.append(item)
                    at = data.find(signature, at + 1)
        for folder, (entries, parent, _seen) in state.items():
            if entries:
                found[folder] = {'parent': parent, 'entries': entries,
                                 'found': 'search'}
    return found

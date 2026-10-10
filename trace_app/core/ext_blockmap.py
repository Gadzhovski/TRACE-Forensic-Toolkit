"""ext2/3/4 files with many fragments, read without The Sleuth Kit's run list.

The Sleuth Kit builds a block-mapped (ext2/ext3, or ext4 without extents)
file's run list by appending each run to the end of a linked list, so
opening a file of n fragments costs n^2: NIST's 300 MB FILL.TXT, 132,000
runs, takes 40 seconds to *open* -- on every open, since nothing is
cached -- and every module that touches it waits (the same file under
ext4's extents opens at once). TRACE reads such an inode's block map
itself: the inode from its table, the direct pointers and the single,
double and triple indirect blocks, merged into runs.

`ExtFileSystem` wraps TSK's FS_Info for an ext volume and answers
`open_meta` / `open` / `open_dir` with a `MappedFile` -- shaped like
pytsk3's File (info.meta, read_random, its attribute and runs) -- only
for a block-mapped regular file of more than `MANY_BLOCKS` blocks. Every
other file goes to TSK unchanged. tests/test_ext_blockmap.py holds the
two to the same values on every file of the test images, TSK being the
reference.
"""

import logging
import struct

import pytsk3

logger = logging.getLogger('TRACE.ExtBlockMap')

#: Past this many blocks TSK's quadratic run list makes opening the file
#: slow, and the block map is read here instead. TSK's run count tracks
#: the blocks, not the fragments (FILL.TXT: 131,900 TSK runs, 1,274 once
#: contiguous blocks are merged), so the size decides.
MANY_BLOCKS = 8192

INCOMPAT_FLEX_BG = 0x200
#: Group descriptors' bg_itable_unused is kept (checksummed groups).
RO_COMPAT_GDT_CSUM, RO_COMPAT_METADATA_CSUM = 0x10, 0x400
EXTENTS_FL = 0x80000
INLINE_DATA_FL = 0x10000000
INCOMPAT_64BIT = 0x80
S_IFMT, S_IFREG = 0o170000, 0o100000


class Geometry:
    """An ext volume's superblock and group descriptors."""

    def __init__(self, read):
        self.read = read                       # (offset, length) -> bytes
        sb = read(1024, 1024)
        if len(sb) < 1024 or struct.unpack_from('<H', sb, 56)[0] != 0xEF53:
            raise ValueError("not an ext superblock")
        self.block = 1024 << struct.unpack_from('<I', sb, 24)[0]
        self.first_data_block = struct.unpack_from('<I', sb, 20)[0]
        self.inodes_per_group = struct.unpack_from('<I', sb, 40)[0]
        self.inodes_count = struct.unpack_from('<I', sb, 0)[0]
        self.blocks_per_group = struct.unpack_from('<I', sb, 32)[0]
        self.blocks_count = struct.unpack_from('<I', sb, 4)[0] | (
            struct.unpack_from('<I', sb, 0x150)[0] << 32
            if struct.unpack_from('<I', sb, 96)[0] & INCOMPAT_64BIT else 0)
        revision = struct.unpack_from('<I', sb, 76)[0]
        self.inode_size = struct.unpack_from('<H', sb, 88)[0] \
            if revision >= 1 else 128
        incompat = struct.unpack_from('<I', sb, 96)[0]
        ro_compat = struct.unpack_from('<I', sb, 100)[0]
        #: Block groups pooled by flex_bg: a file's blocks can lie anywhere
        #: in its inode's pool.
        self.groups_per_flex = (1 << sb[0x174]) \
            if incompat & INCOMPAT_FLEX_BG and sb[0x174] < 31 else 1
        #: Whether bg_itable_unused can be trusted.
        self.itable_unused_kept = bool(
            ro_compat & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM))
        self.desc_size = (struct.unpack_from('<H', sb, 254)[0] or 64) \
            if incompat & INCOMPAT_64BIT else 32
        self._tables = {}

    def _descriptor(self, group):
        """(inode table block, inode bitmap block, inodes in use at the
        table's start) of a block group."""
        if group not in self._tables:
            table = (self.first_data_block + 1) * self.block
            raw = self.read(table + group * self.desc_size, self.desc_size)
            inode_table = struct.unpack_from('<I', raw, 8)[0]
            inode_bitmap = struct.unpack_from('<I', raw, 4)[0]
            unused = struct.unpack_from('<H', raw, 0x1C)[0]
            if self.desc_size >= 64:
                inode_table |= struct.unpack_from('<I', raw, 0x28)[0] << 32
                inode_bitmap |= struct.unpack_from('<I', raw, 0x24)[0] << 32
                unused |= struct.unpack_from('<H', raw, 0x32)[0] << 16
            used = self.inodes_per_group - unused \
                if self.itable_unused_kept and unused <= \
                self.inodes_per_group else self.inodes_per_group
            self._tables[group] = (inode_table, inode_bitmap, used)
        return self._tables[group]

    def groups(self):
        return -(-self.inodes_count // self.inodes_per_group)

    def group_inodes(self, group):
        """[(inode number, raw inode, allocated)] of the part of a group's
        inode table ever used, read in one go."""
        table, bitmap, used = self._descriptor(group)
        if not used:
            return []
        raw = self.read(table * self.block, used * self.inode_size)
        bits = self.read(bitmap * self.block, -(-used // 8))
        first = group * self.inodes_per_group + 1
        out = []
        for index in range(min(used, len(raw) // self.inode_size)):
            allocated = index // 8 < len(bits) and \
                bool(bits[index // 8] >> (index % 8) & 1)
            out.append((first + index,
                        raw[index * self.inode_size:
                            (index + 1) * self.inode_size], allocated))
        return out

    def inode(self, number):
        """(raw inode bytes, allocated in the inode bitmap)."""
        group, index = divmod(number - 1, self.inodes_per_group)
        table, bitmap, _used = self._descriptor(group)
        raw = self.read(table * self.block + index * self.inode_size,
                        self.inode_size)
        bits = self.read(bitmap * self.block + index // 8, 1)
        allocated = bool(bits and bits[0] >> (index % 8) & 1)
        return raw, allocated

    def blocks_of(self, raw, size):
        """[(logical block, physical block or 0 for a hole, count)] of a
        block-mapped inode's data, merged; None for extents or inline
        data. Followed as far as the size reaches *and* as far as the
        blocks the inode holds (i_blocks, its indirect blocks included):
        a file can hold blocks past its size, and TSK lists them too."""
        flags = struct.unpack_from('<I', raw, 32)[0]
        if flags & (EXTENTS_FL | INLINE_DATA_FL):
            return None
        per_block = self.block // 4
        wanted = -(-size // self.block)
        held = struct.unpack_from('<I', raw, 28)[0] * 512 // self.block
        state = {'logical': 0, 'used': 0}
        physical = []

        def done():
            return state['logical'] >= wanted and state['used'] >= held

        def data(block):
            if block:
                state['used'] += 1
                physical.append((state['logical'], block))
            state['logical'] += 1

        def walk(block, depth):
            """The data blocks under an indirect block."""
            if done():
                return
            if block == 0:
                # A hole as wide as everything this pointer maps.
                state['logical'] += per_block ** depth
                return
            if block >= self.blocks_count:
                raise ValueError(f"indirect block {block} past the volume")
            state['used'] += 1                    # the indirect block
            entries = struct.unpack(f'<{per_block}I',
                                    self.read(block * self.block,
                                              self.block))
            for entry in entries:
                if done():
                    return
                if depth == 1:
                    data(entry)
                else:
                    walk(entry, depth - 1)

        for pointer in struct.unpack_from('<12I', raw, 40):
            if done():
                break
            data(pointer)
        for depth, at in ((1, 88), (2, 92), (3, 96)):
            walk(struct.unpack_from('<I', raw, at)[0], depth)
        if any(block >= self.blocks_count for _logical, block in physical):
            # A pointer past the volume: a block map overwritten with
            # something else (a deleted inode reused). Not ours to read --
            # TSK opens it and says what it can.
            return None
        # Holes inside the size read as zeros: runs of block 0.
        runs = []
        expected = 0
        for logical, block in physical:
            if logical > expected and expected < wanted:
                runs.append((expected, 0, min(logical, wanted) - expected))
            if runs and runs[-1][1] and logical == runs[-1][0] + \
                    runs[-1][2] and block == runs[-1][1] + runs[-1][2]:
                runs[-1] = (runs[-1][0], runs[-1][1], runs[-1][2] + 1)
            else:
                runs.append((logical, block, 1))
            expected = logical + 1
        if expected < wanted:
            runs.append((expected, 0, wanted - expected))
        return runs


class _Run:
    __slots__ = ('offset', 'addr', 'len', 'flags')

    def __init__(self, offset, addr, length, flags):
        self.offset, self.addr, self.len, self.flags = (offset, addr,
                                                        length, flags)


class _AttributeInfo:
    __slots__ = ('type', 'flags', 'name', 'size', 'id')


class _Attribute:
    """pytsk3's default data attribute: its info, and its runs."""

    def __init__(self, size, runs):
        self.info = _AttributeInfo()
        self.info.type = pytsk3.TSK_FS_ATTR_TYPE_DEFAULT
        self.info.flags = pytsk3.TSK_FS_ATTR_NONRES | \
            pytsk3.TSK_FS_ATTR_INUSE
        self.info.name = None
        self.info.size = size
        self.info.id = 0
        self._runs = runs

    def __iter__(self):
        for logical, block, count in self._runs:
            yield _Run(logical, block, count,
                       pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE if block == 0
                       else 0)


class _Meta:
    """The fields of pytsk3's TSK_FS_META that TRACE reads."""


class _Info:
    __slots__ = ('meta', 'name', 'fs_info')


class MappedFile:
    """A block-mapped ext file read through its own block map, shaped like
    pytsk3's File."""

    def __init__(self, geometry, number, raw, allocated, runs):
        self._geometry = geometry
        self._runs = runs
        size = struct.unpack_from('<I', raw, 4)[0] | \
            struct.unpack_from('<I', raw, 108)[0] << 32
        self._size = size
        meta = _Meta()
        mode = struct.unpack_from('<H', raw, 0)[0]
        meta.addr = number
        meta.size = size
        meta.type = pytsk3.TSK_FS_META_TYPE_REG
        meta.mode = mode & 0o7777
        meta.nlink = struct.unpack_from('<H', raw, 26)[0]
        meta.uid = struct.unpack_from('<H', raw, 2)[0] | \
            struct.unpack_from('<H', raw, 120)[0] << 16
        meta.gid = struct.unpack_from('<H', raw, 24)[0] | \
            struct.unpack_from('<H', raw, 122)[0] << 16
        meta.seq = 0
        meta.link = ''
        meta.flags = (pytsk3.TSK_FS_META_FLAG_ALLOC if allocated
                      else pytsk3.TSK_FS_META_FLAG_UNALLOC) | \
            pytsk3.TSK_FS_META_FLAG_USED
        meta.atime, meta.ctime, meta.mtime = struct.unpack_from(
            '<III', raw, 8)
        meta.dtime = struct.unpack_from('<I', raw, 20)[0]
        meta.crtime = 0
        meta.atime_nano = meta.ctime_nano = meta.mtime_nano = \
            meta.crtime_nano = 0
        if len(raw) > 128:
            extra = struct.unpack_from('<H', raw, 128)[0]
            fields = (('ctime', 132), ('mtime', 136), ('atime', 140))
            for name, at in fields:
                if 128 + extra >= at + 4:
                    setattr(meta, name + '_nano',
                            struct.unpack_from('<I', raw, at)[0] >> 2)
            if 128 + extra >= 152:
                meta.crtime = struct.unpack_from('<I', raw, 144)[0]
                meta.crtime_nano = struct.unpack_from('<I', raw, 148)[0] >> 2
        self.info = _Info()
        self.info.meta = meta
        self.info.name = None
        self.info.fs_info = None

    def __iter__(self):
        yield _Attribute(self._size, self._runs)

    def read_random(self, offset, length, *_args):
        """`length` bytes from `offset` (holes read as zeros), clipped to
        the file's size."""
        length = min(length, self._size - offset)
        if length <= 0:
            return b''
        block = self._geometry.block
        out = bytearray()
        for logical, physical, count in self._runs:
            begin, end = logical * block, (logical + count) * block
            if end <= offset or begin >= offset + length:
                continue
            start = max(offset, begin)
            stop = min(offset + length, end)
            if physical == 0:
                out += bytes(stop - start)
            else:
                out += self._geometry.read(
                    physical * block + (start - begin), stop - start)
        return bytes(out[:length])


class _Entry:
    """A directory entry whose file is read through its block map: the
    entry's own info (TSK listed it cheaply), the mapped file's data."""

    def __init__(self, entry, mapped):
        self._entry = entry
        self._mapped = mapped
        self.info = entry.info

    def __iter__(self):
        return iter(self._mapped)

    def read_random(self, offset, length, *args):
        return self._mapped.read_random(offset, length)

    def __getattr__(self, name):
        return getattr(self._entry, name)


class _Directory:
    def __init__(self, directory, wrapper):
        self._directory = directory
        self._wrapper = wrapper

    def __iter__(self):
        for entry in self._directory:
            yield self._wrapper.entry(entry)

    def __getattr__(self, name):
        return getattr(self._directory, name)


class ExtFileSystem:
    """TSK's FS_Info for an ext volume, opening heavily fragmented
    block-mapped files itself (module docstring)."""

    def __init__(self, fs, geometry):
        self._fs = fs
        self.geometry = geometry
        self.info = fs.info

    @classmethod
    def wrap(cls, fs, read):
        """`fs` wrapped when it is ext; otherwise `fs` itself. `read` reads
        the volume: (offset from its start, length) -> bytes."""
        try:
            if not int(fs.info.ftype) & pytsk3.TSK_FS_TYPE_EXT_DETECT:
                return fs
            return cls(fs, Geometry(read))
        except Exception as exc:
            logger.debug("ext block maps not read: %s", exc)
            return fs

    def mapped(self, number, size=None):
        """A MappedFile for inode `number` if it is a block-mapped regular
        file of more than MANY_BLOCKS blocks; None otherwise."""
        try:
            raw, allocated = self.geometry.inode(number)
            mode = struct.unpack_from('<H', raw, 0)[0]
            if mode & S_IFMT != S_IFREG:
                return None
            length = struct.unpack_from('<I', raw, 4)[0] | \
                struct.unpack_from('<I', raw, 108)[0] << 32
            if size is not None and size != length:
                return None                   # not what TSK listed
            if -(-length // self.geometry.block) <= MANY_BLOCKS:
                return None
            runs = self.geometry.blocks_of(raw, length)
            if runs is None:
                return None
            return MappedFile(self.geometry, number, raw, allocated, runs)
        except Exception as exc:
            logger.debug("Block map of inode %s not read: %s", number, exc)
            return None

    def open_meta(self, inode, *args, **kwargs):
        found = self.mapped(int(inode))
        if found is not None:
            return found
        return self._fs.open_meta(inode=inode, *args, **kwargs)

    def open(self, path, *args, **kwargs):
        parent, _sep, name = path.rstrip('/').rpartition('/')
        try:
            for entry in self._fs.open_dir(path=parent or '/'):
                info = entry.info
                if info.name is not None and info.meta is not None and \
                        info.name.name.decode('utf-8', 'replace') == name:
                    found = self.mapped(int(info.meta.addr),
                                        int(info.meta.size))
                    if found is not None:
                        return found
                    break
        except (IOError, OSError):
            pass
        return self._fs.open(path, *args, **kwargs)

    def open_dir(self, *args, **kwargs):
        return _Directory(self._fs.open_dir(*args, **kwargs), self)

    def entry(self, entry):
        """A directory entry, read through its block map when TSK would
        take long to open it."""
        info = entry.info
        meta = info.meta
        if meta is None or meta.type != pytsk3.TSK_FS_META_TYPE_REG or \
                int(meta.size or 0) <= MANY_BLOCKS * self.geometry.block:
            return entry
        found = self.mapped(int(meta.addr), int(meta.size))
        return entry if found is None else _Entry(entry, found)

    def __getattr__(self, name):
        return getattr(self._fs, name)

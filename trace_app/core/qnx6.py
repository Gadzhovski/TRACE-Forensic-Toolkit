"""QNX6 (the Power-Safe file system) read in pure Python (no Qt).

QNX6 is what most QNX head units run -- Ford SYNC 3 and 4, Harman and
Panasonic units -- and The Sleuth Kit, libyal and the pytsk3 wheels read
none of it: a head unit's image showed only "a file system TRACE cannot
read". Its layout, as the Linux kernel's read-only fs/qnx6 reads it:

* a boot area of 0x2000 bytes, then a superblock (512 bytes in a 0x1000
  area): magic 0x68191122 -- either byte order --, a CRC-32 (the
  big-endian one, polynomial 0x04C11DB7, no reflection) over bytes
  8..512, a serial number, the block size, counts, and four root nodes:
  the inode file, the block bitmap, the long file names and one unused;
* a second superblock right after the last block. The file system is
  copy-on-write and writes the two in turn: the valid one with the higher
  serial is the current state, the other the one before it;
* blocks numbered from the end of the superblock area (`blocks_offset`);
* a root node or an inode maps a file with 16 pointers and a level
  count: at level 0 they are data blocks, each level more a block of
  pointers in between. 0xFFFFFFFF is no block (a hole);
* inode N is the 128-byte record at (N - 1) * 128 of the inode file; the
  root directory is inode 1;
* a directory is 32-byte entries: inode, name length, 27 bytes of name.
  A longer name's entry holds instead the block of the long-names file
  where it is kept (length + up to 510 bytes).

Live files only: an older state (the other superblock's tree) is not
offered as deleted files. Checked against NetherlandsForensicInstitute/
qnxmount's test image, made by QNX's own mkqnx6fs, and the tar of the
files that were put on it (tests/test_qnx.py).
"""

import logging
import stat
import struct
from collections import OrderedDict

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.QNX6')

KIND = 'QNX6'
MAGIC = 0x68191122
#: The boot area before the superblock, and the superblock's own area.
BOOT_AREA = 0x2000
SUPERBLOCK_AREA = 0x1000
SUPERBLOCK_SIZE = 512
INODE_SIZE = 128
DIRENT_SIZE = 32
SHORT_NAME = 27
NO_BLOCK = 0xFFFFFFFF
ROOT_INODE = 1
#: Indirect blocks kept (each one a block of pointers).
CACHED_BLOCKS = 256


class Qnx6Error(Exception):
    pass


def _crc32_table():
    table = []
    for byte in range(256):
        crc = byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
        table.append(crc & 0xFFFFFFFF)
    return table


_CRC_TABLE = _crc32_table()


def crc32_be(data, crc=0):
    """The kernel's crc32_be: MSB first, no reflection, no final XOR."""
    table = _CRC_TABLE
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[((crc >> 24) ^ byte) & 0xFF]
    return crc


def byte_order(head):
    """'<' or '>' when `head` (from the partition start) holds a QNX6
    superblock after its boot area, else None."""
    if len(head) < BOOT_AREA + 4:
        return None
    magic = head[BOOT_AREA:BOOT_AREA + 4]
    if magic == struct.pack('<I', MAGIC):
        return '<'
    if magic == struct.pack('>I', MAGIC):
        return '>'
    return None


class _RootNode:
    __slots__ = ('size', 'pointers', 'levels')

    def __init__(self, order, data):
        self.size = struct.unpack_from(order + 'Q', data, 0)[0]
        self.pointers = struct.unpack_from(order + '16I', data, 8)
        self.levels = data[72]


class Superblock:
    def __init__(self, order, data, where):
        (self.magic, self.checksum, self.serial, self.ctime, self.atime,
         self.flags, self.version1, self.version2) = struct.unpack_from(
            order + 'IIQIIIHH', data, 0)
        self.volume_id = data[32:48]
        (self.block_size, self.inode_count, self.free_inodes,
         self.block_count, self.free_blocks, self.allocation_group) = \
            struct.unpack_from(order + 'IIIIII', data, 48)
        self.inodes = _RootNode(order, data[72:152])
        self.bitmap = _RootNode(order, data[152:232])
        self.long_names = _RootNode(order, data[232:312])
        self.where = where
        self.valid = self.magic == MAGIC and \
            crc32_be(data[8:SUPERBLOCK_SIZE]) == self.checksum and \
            self.block_size in (512, 1024, 2048, 4096)


class Qnx6Image:
    """The file system on `source` (a file object over the partition)."""

    def __init__(self, source, state=0):
        """`state` 0 is the current state (the valid superblock with the
        higher serial), 1 the one before it -- what the other superblock
        still describes."""
        self.source = source
        source.seek(0)
        head = source.read(BOOT_AREA + SUPERBLOCK_SIZE)
        self.order = byte_order(head)
        if self.order is None:
            raise Qnx6Error("no QNX6 superblock")
        first = Superblock(self.order, head[BOOT_AREA:], BOOT_AREA)
        candidates = [first] if first.valid else []
        block_size = first.block_size if first.valid else 0
        if block_size:
            # The other superblock follows the last block.
            where = BOOT_AREA + SUPERBLOCK_AREA + \
                first.block_count * block_size
            second = Superblock(self.order, self._read(where,
                                                       SUPERBLOCK_SIZE),
                                where)
            if second.valid and second.block_size == block_size:
                candidates.append(second)
        if not candidates:
            raise Qnx6Error("no valid QNX6 superblock (checksums fail)")
        candidates.sort(key=lambda sb: sb.serial, reverse=True)
        if state >= len(candidates):
            raise Qnx6Error(f"no state {state}: {len(candidates)} valid "
                            f"superblock(s)")
        self.superblock = candidates[state]
        self.superblocks = candidates
        self.block_size = self.superblock.block_size
        self.blocks_offset = (BOOT_AREA + SUPERBLOCK_AREA) // self.block_size
        self._pointers_per_block = self.block_size // 4
        self._pointer_bits = self._pointers_per_block.bit_length() - 1
        self._blocks = OrderedDict()
        self._inode_cache = {}
        self.inode_file = Qnx6File(self, self.superblock.inodes)
        self.long_name_file = Qnx6File(self, self.superblock.long_names)

    @property
    def size(self):
        return BOOT_AREA + SUPERBLOCK_AREA + \
            self.superblock.block_count * self.block_size + SUPERBLOCK_AREA

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def block_offset(self, number):
        return (number + self.blocks_offset) * self.block_size

    def block(self, number):
        return self._read(self.block_offset(number), self.block_size)

    def pointer_block(self, number):
        """An indirect block's pointers (cached)."""
        found = self._blocks.get(number)
        if found is not None:
            self._blocks.move_to_end(number)
            return found
        found = struct.unpack(f"{self.order}{self._pointers_per_block}I",
                              self.block(number))
        self._blocks[number] = found
        while len(self._blocks) > CACHED_BLOCKS:
            self._blocks.popitem(last=False)
        return found

    def map(self, pointers, levels, index):
        """The block holding block `index` of a file, or None (a hole)."""
        shift = self._pointer_bits * levels
        top = index >> shift
        if top >= 16:
            return None
        pointer = pointers[top]
        for _ in range(levels):
            if pointer == NO_BLOCK:
                return None
            shift -= self._pointer_bits
            pointer = self.pointer_block(pointer)[
                (index >> shift) & (self._pointers_per_block - 1)]
        return None if pointer == NO_BLOCK else pointer

    def inode(self, number):
        found = self._inode_cache.get(number)
        if found is None:
            if number < 1:
                raise Qnx6Error(f"no inode {number}")
            raw = self.inode_file.read((number - 1) * INODE_SIZE,
                                       INODE_SIZE)
            if len(raw) < INODE_SIZE:
                raise Qnx6Error(f"inode {number} is past the inode file")
            found = Inode(self, number, raw)
            if len(self._inode_cache) > 65536:
                self._inode_cache.clear()
            self._inode_cache[number] = found
        return found

    def long_name(self, block_index):
        data = self.long_name_file.read(block_index * self.block_size,
                                        2 + 510)
        if len(data) < 2:
            return b''
        length = struct.unpack_from(self.order + 'H', data, 0)[0]
        return data[2:2 + min(length, 510)]

    def allocated_ranges(self):
        """(begin, end) byte ranges in use: both superblock areas and the
        boot area, and every block the bitmap marks used (bit n of byte n
        // 8, least significant first, is block n)."""
        out = [(0, BOOT_AREA + SUPERBLOCK_AREA),
               (self.size - SUPERBLOCK_AREA, self.size)]
        bitmap = Qnx6File(self, self.superblock.bitmap).read(
            0, self.superblock.bitmap.size)
        start = None
        count = self.superblock.block_count
        for block in range(count + 1):
            used = block < count and \
                bitmap[block >> 3] >> (block & 7) & 1 if \
                (block >> 3) < len(bitmap) else False
            if used and start is None:
                start = block
            elif not used and start is not None:
                out.append((self.block_offset(start),
                            self.block_offset(block)))
                start = None
        return out


class Qnx6File:
    """A file's bytes through its pointers (an inode's or a root node's)."""

    def __init__(self, image, node, size=None):
        self.image = image
        self.pointers = node.pointers
        self.levels = node.levels
        self.size = node.size if size is None else size

    def read(self, offset, length):
        image = self.image
        size = self.size
        if offset >= size or length <= 0:
            return b''
        end = min(size, offset + length)
        bs = image.block_size
        out = bytearray()
        index = offset // bs
        while index * bs < end:
            block = image.map(self.pointers, self.levels, index)
            data = image.block(block) if block is not None else bytes(bs)
            begin = max(offset - index * bs, 0)
            stop = min(end - index * bs, bs)
            out += data[begin:stop]
            index += 1
        return bytes(out)


class Inode:
    def __init__(self, image, number, raw):
        order = image.order
        self.number = number
        (self.size, self.uid, self.gid, self.ftime, self.mtime, self.atime,
         self.ctime, self.mode, self.ext_mode) = struct.unpack_from(
            order + 'QIIIIIIHH', raw, 0)
        self.pointers = struct.unpack_from(order + '16I', raw, 36)
        self.levels = raw[100]
        self.status = raw[101]
        self._image = image

    @property
    def is_dir(self):
        return stat.S_ISDIR(self.mode)

    def data(self):
        return Qnx6File(self._image, self)

    def entries(self):
        """[(name bytes, inode number)] of a directory, '.' and '..' left
        out."""
        image = self._image
        data = self.data().read(0, self.size)
        out = []
        for at in range(0, len(data) - DIRENT_SIZE + 1, DIRENT_SIZE):
            number, length = struct.unpack_from(image.order + 'IB', data, at)
            if not number or not length:
                continue
            if length <= SHORT_NAME:
                name = data[at + 5:at + 5 + length]
            else:
                long_block = struct.unpack_from(image.order + 'I', data,
                                                at + 8)[0]
                name = image.long_name(long_block)
            if name in (b'.', b'..'):
                continue
            out.append((name, number))
        return out


class Qnx6Entry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, image, number, name='', parent=0):
        self._image = image
        self._inode = image.inode(number)
        self.identifier = number
        self.parent_identifier = parent
        self.name = name
        self.file_mode = self._inode.mode
        self.size = 0 if self._inode.is_dir else self._inode.size
        self.owner_identifier = self._inode.uid
        self.group_identifier = self._inode.gid
        self._children = None

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._inode.mtime * 1_000_000_000

    def get_access_time_as_integer(self):
        return self._inode.atime * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._inode.ctime * 1_000_000_000

    def get_creation_time_as_integer(self):
        return self._inode.ftime * 1_000_000_000

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self._inode.mode):
            return ''
        target = self._inode.data().read(0, self._inode.size)
        return target.rstrip(b'\0').decode('utf-8', 'surrogateescape')

    def _list(self):
        if self._children is None:
            try:
                self._children = self._inode.entries() \
                    if self._inode.is_dir else []
            except (Qnx6Error, struct.error, OSError) as exc:
                logger.warning("QNX6 directory %d unreadable: %s",
                               self.identifier, exc)
                self._children = []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, number = self._list()[index]
        return Qnx6Entry(self._image, number,
                         name.decode('utf-8', 'surrogateescape'),
                         self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._inode.data().read(offset, length)


class _Volume:
    """libyal's volume vocabulary over a Qnx6Image."""

    def __init__(self, image):
        self.image = image
        self._parents = None

    def get_root_directory(self):
        return Qnx6Entry(self.image, ROOT_INODE)

    def entry(self, number):
        try:
            if number == ROOT_INODE:
                return self.get_root_directory()
            names = self._names()
            if number not in names:
                return None
            name, parent = names[number]
            return Qnx6Entry(self.image, number, name, parent)
        except (Qnx6Error, struct.error, OSError):
            return None

    def _names(self):
        """{inode: (name, parent inode)}, by walking the tree once -- an
        inode records no name or parent of its own."""
        if self._parents is None:
            self._parents = {}
            pending = [ROOT_INODE]
            seen = {ROOT_INODE}
            while pending:
                number = pending.pop()
                try:
                    inode = self.image.inode(number)
                    children = inode.entries()
                except (Qnx6Error, struct.error, OSError):
                    continue
                for name, child in children:
                    if child in seen:
                        continue
                    seen.add(child)
                    self._parents[child] = (
                        name.decode('utf-8', 'surrogateescape'), number)
                    try:
                        if self.image.inode(child).is_dir:
                            pending.append(child)
                    except (Qnx6Error, struct.error, OSError):
                        continue
        return self._parents

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _number) in enumerate(entry._list()):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.image._blocks.clear()
        self.image._inode_cache.clear()


class Qnx6FileSystem(LibyalFileSystem):
    """A QNX6 volume, read like a pytsk3.FS_Info."""

    KIND = KIND

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.block_size
        super().__init__(_Volume(image), image.size, "QNX6 (Power-Safe)")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT_INODE

    def _last_identifier(self):
        return self.image.superblock.inode_count

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()

    def close(self):
        self.volume.close()


def open_qnx6(source, state=0):
    """A Qnx6FileSystem over `source` (a file object over the partition),
    or None when it holds no QNX6 file system TRACE can read. `state` 1
    reads the state before the last commit (Qnx6Image)."""
    try:
        source.seek(0)
        head = source.read(BOOT_AREA + 4)
    except (OSError, IOError):
        return None
    if byte_order(head) is None:
        return None
    try:
        return Qnx6FileSystem(Qnx6Image(source, state))
    except (Qnx6Error, struct.error, OSError, IOError) as exc:
        logger.warning("QNX6 volume not opened: %s", exc)
        return None

"""cramfs read in pure Python (no Qt).

The compressed read-only file system of older embedded Linux -- routers,
cameras, set-top boxes, bootloaders' root file systems. Its layout, as
the Linux kernel's include/uapi/linux/cramfs_fs.h has it:

* superblock (76 bytes, at 0): magic 0x28CD3D45 -- whose byte order is
  the image's --, size, flags, a reserved word, "Compressed ROMFS", the
  file system's crc / edition / block and file counts, a 16-byte name,
  and the root's inode;
* an inode is three 32-bit words of bit fields: mode:16 uid:16, size:24
  gid:8, namelen:6 offset:26 (offset in 4-byte units; the name length
  too). On a big-endian image the first field of each word is its high
  bits, on a little-endian one its low bits;
* a folder's data (at offset * 4) is its entries: an inode, then its
  name, NUL-padded to the 4 bytes namelen counts;
* a file's or a symlink's data is a table of one 32-bit pointer per 4 KiB
  block -- each where its compressed block ends --, then the blocks,
  zlib-compressed; the first starts right after the table. With the
  extended-pointers flag a pointer's top bits say a block is stored
  uncompressed (bit 30) or found directly (bit 31), and a zero pointer is
  a hole.

No times are kept (the kernel shows 0), nor are deleted files. Checked
against unblob's test images -- both byte orders and the old layout -- and
the files unblob extracted from them (tests/test_flash_filesystems.py).
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup

logger = logging.getLogger('TRACE.cramfs')

KIND = 'cramfs'
MAGIC = 0x28CD3D45
SIGNATURE = b'Compressed ROMFS'
SUPERBLOCK = 76
BLOCK = 4096
FLAG_EXT_BLOCK_POINTERS = 0x00000800
BLOCK_UNCOMPRESSED = 1 << 30
BLOCK_DIRECT = 1 << 31
BLOCK_MASK = (1 << 30) - 1


class CramfsError(Exception):
    pass


def byte_order(head):
    if len(head) < 4:
        return None
    if head[:4] == struct.pack('<I', MAGIC):
        return '<'
    if head[:4] == struct.pack('>I', MAGIC):
        return '>'
    return None


def _inode(words, order):
    first, second, third = words
    if order == '<':
        mode, uid = first & 0xFFFF, first >> 16
        size, gid = second & 0xFFFFFF, second >> 24
        namelen, offset = third & 0x3F, third >> 6
    else:
        mode, uid = first >> 16, first & 0xFFFF
        size, gid = second >> 8, second & 0xFF
        namelen, offset = third >> 26, third & 0x3FFFFFF
    return {'mode': mode, 'uid': uid, 'size': size, 'gid': gid,
            'namelen': namelen * 4, 'offset': offset * 4}


class CramfsImage:
    def __init__(self, source):
        self.source = source
        head = self._read(0, SUPERBLOCK)
        self.order = byte_order(head)
        if self.order is None or len(head) < SUPERBLOCK:
            raise CramfsError("no cramfs superblock")
        if head[16:32] != SIGNATURE:
            raise CramfsError("no 'Compressed ROMFS' signature")
        (_magic, self.size, self.flags, _future) = struct.unpack_from(
            self.order + 'IIII', head, 0)
        self.name = head[48:64].split(b'\0', 1)[0]
        self.root = _inode(struct.unpack_from(self.order + 'III', head, 64),
                           self.order)
        if not stat.S_ISDIR(self.root['mode']):
            raise CramfsError("the root is not a folder")
        self._blocks = {}

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def entries(self, inode):
        """[(name, inode, where)] of a folder; `where` (the entry's
        offset) identifies it."""
        data = self._read(inode['offset'], inode['size'])
        out, at = [], 0
        while at + 12 <= len(data):
            child = _inode(struct.unpack_from(self.order + 'III', data, at),
                           self.order)
            name = data[at + 12:at + 12 + child['namelen']].rstrip(b'\0')
            out.append((name, child, inode['offset'] + at))
            at += 12 + child['namelen']
            if not child['namelen']:
                break
        return out

    def _block(self, inode, number):
        key = (inode['offset'], number)
        found = self._blocks.get(key)
        if found is not None:
            return found
        count = (inode['size'] + BLOCK - 1) // BLOCK
        pointers = struct.unpack(self.order + f'{count}I',
                                 self._read(inode['offset'], count * 4))
        pointer = pointers[number]
        if self.flags & FLAG_EXT_BLOCK_POINTERS:
            if pointer & BLOCK_MASK == 0:
                data = bytes(BLOCK)
            elif pointer & BLOCK_DIRECT:
                start = (pointer & BLOCK_MASK) << 2
                if pointer & BLOCK_UNCOMPRESSED:
                    data = self._read(start, BLOCK)
                else:
                    length = struct.unpack(self.order + 'H',
                                           self._read(start, 2))[0]
                    data = zlib.decompress(self._read(start + 2, length))
            else:
                end = pointer & BLOCK_MASK
                start = inode['offset'] + count * 4 if number == 0 else \
                    pointers[number - 1] & BLOCK_MASK
                raw = self._read(start, end - start)
                data = raw if pointer & BLOCK_UNCOMPRESSED else \
                    zlib.decompress(raw)
        else:
            start = inode['offset'] + count * 4 if number == 0 else \
                pointers[number - 1]
            raw = self._read(start, pointer - start)
            data = zlib.decompress(raw) if raw else bytes(BLOCK)
        if len(self._blocks) > 64:
            self._blocks.clear()
        self._blocks[key] = data
        return data

    def read(self, inode, offset, length):
        end = min(inode['size'], offset + length)
        out = bytearray()
        number = offset // BLOCK
        while number * BLOCK < end:
            data = self._block(inode, number)
            out += data[max(offset - number * BLOCK, 0):
                        min(end - number * BLOCK, BLOCK)]
            number += 1
        return bytes(out)


class CramfsEntry:
    def __init__(self, image, inode, name, identifier, parent):
        self._image = image
        self._inode = inode
        self.identifier = identifier
        self.parent_identifier = parent
        self.name = name.decode('utf-8', 'surrogateescape')
        self.file_mode = inode['mode']
        self.size = 0 if stat.S_ISDIR(inode['mode']) else inode['size']
        self.owner_identifier = inode['uid']
        self.group_identifier = inode['gid']

    def get_number_of_links(self):
        return 1

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._image.read(self._inode, 0, self._inode['size']).decode(
            'utf-8', 'surrogateescape')

    def _list(self):
        if not stat.S_ISDIR(self.file_mode) or not self._inode['offset']:
            return []
        try:
            return self._image.entries(self._inode)
        except (CramfsError, struct.error) as exc:
            logger.warning("cramfs folder %s unreadable: %s", self.name, exc)
            return []

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, inode, where = self._list()[index]
        return CramfsEntry(self._image, inode, name, where, self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if not (stat.S_ISREG(self.file_mode) or stat.S_ISLNK(self.file_mode)):
            return b''
        try:
            return self._image.read(self._inode, offset, length)
        except (zlib.error, struct.error, IndexError) as exc:
            logger.warning("cramfs file %s unreadable: %s", self.name, exc)
            return b''


#: The root's identifier: where its inode sits in the superblock.
ROOT = 64


class _Volume(PathLookup):
    def __init__(self, image):
        self.image = image
        self._index = None

    def get_root_directory(self):
        return CramfsEntry(self.image, self.image.root, b'', ROOT, ROOT)

    def entry(self, identifier):
        if identifier == ROOT:
            return self.get_root_directory()
        if self._index is None:
            self._index = {}
            pending = [self.get_root_directory()]
            while pending:
                folder = pending.pop()
                for index in range(folder.number_of_sub_file_entries):
                    child = folder.get_sub_file_entry(index)
                    self._index[child.identifier] = child
                    if stat.S_ISDIR(child.file_mode):
                        pending.append(child)
        return self._index.get(identifier)


class CramfsFileSystem(LibyalFileSystem):
    KIND = KIND
    BLOCK_SIZE = BLOCK

    def __init__(self, image):
        self.image = image
        order = 'big-endian' if image.order == '>' else 'little-endian'
        super().__init__(_Volume(image), image.size, f"cramfs ({order})")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return [(0, self.image.size)]


def open_cramfs(source):
    try:
        source.seek(0)
        if byte_order(source.read(4)) is None:
            return None
        return CramfsFileSystem(CramfsImage(source))
    except (CramfsError, struct.error, OSError, IOError) as exc:
        logger.debug("Not cramfs: %s", exc)
        return None

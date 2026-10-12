"""SquashFS 4.0 images, read in Python (no Qt).

SquashFS is the read-only compressed file system of Linux live and install
media, snaps, AppImages, router and camera firmware and older Android
system partitions. The Sleuth Kit does not read it. The layout
(fs/squashfs/squashfs_fs.h, squashfs-tools' format notes):

* a 96-byte superblock at 0 ('hsqs'): block size, compressor, flags, and
  where each table starts -- inodes, directories, fragments, ids, the
  export table that maps an inode number to its inode;
* metadata (inodes, directories, the tables) in blocks of up to 8 KiB,
  each behind a 16-bit header whose top bit says "stored, not
  compressed". An inode or directory is found by a reference: the block's
  offset from its table's start << 16 | the offset inside that block once
  decompressed -- and may run on into the next block;
* a file is a run of data blocks from `start_block`, each with its stored
  size in the inode's block list (bit 24: stored uncompressed; 0: a block
  of zeros, nothing stored), and its tail, when smaller than a block, in a
  fragment block it shares with other tails;
* a directory is a list of headers (a run of entries whose inodes share a
  metadata block) and entries (offset, inode number delta, type, name).

Compression is gzip (zlib), LZMA (the legacy .lzma format), LZO, XZ, LZ4
or zstd; every one is read here with the standard library or the
decompressors TRACE already has. Entries speak libyal's vocabulary, so
core/libyal_fs presents them like every other file system. SquashFS keeps
one time per inode (modification) and has nothing deleted to find.
SquashFS 3 and earlier (big-endian, older firmware) is refused by name.
"""

import logging
import lzma
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.SquashFS')

MAGIC = b'hsqs'
SUPERBLOCK = struct.Struct('<4sIIIIHHHHHHQQQQQQQQ')
METADATA_SIZE = 8192
STORED = 1 << 15                 # a metadata block's header: not compressed
DATA_STORED = 1 << 24            # a data block's size: not compressed
NO_FRAGMENT = 0xFFFFFFFF
INVALID_TABLE = 0xFFFFFFFFFFFFFFFF

# Superblock flags.
NO_FRAGMENTS = 0x0010
EXPORTABLE = 0x0080
COMPRESSOR_OPTIONS = 0x0400

GZIP, LZMA, LZO, XZ, LZ4, ZSTD = 1, 2, 3, 4, 5, 6
COMPRESSION_NAMES = {GZIP: 'gzip', LZMA: 'LZMA', LZO: 'LZO', XZ: 'XZ',
                     LZ4: 'LZ4', ZSTD: 'zstd'}

# Inode types.
BASIC_DIR, BASIC_FILE, BASIC_SYMLINK, BASIC_BLOCK, BASIC_CHAR, \
    BASIC_FIFO, BASIC_SOCKET = range(1, 8)
EXT_DIR, EXT_FILE, EXT_SYMLINK, EXT_BLOCK, EXT_CHAR, EXT_FIFO, \
    EXT_SOCKET = range(8, 15)
_MODE_KIND = {BASIC_DIR: stat.S_IFDIR, EXT_DIR: stat.S_IFDIR,
              BASIC_FILE: stat.S_IFREG, EXT_FILE: stat.S_IFREG,
              BASIC_SYMLINK: stat.S_IFLNK, EXT_SYMLINK: stat.S_IFLNK,
              BASIC_BLOCK: stat.S_IFBLK, EXT_BLOCK: stat.S_IFBLK,
              BASIC_CHAR: stat.S_IFCHR, EXT_CHAR: stat.S_IFCHR,
              BASIC_FIFO: stat.S_IFIFO, EXT_FIFO: stat.S_IFIFO,
              BASIC_SOCKET: stat.S_IFSOCK, EXT_SOCKET: stat.S_IFSOCK}

#: Larger than any data block SquashFS allows (1 MiB).
MAX_BLOCK = 1 << 20


class SquashfsError(Exception):
    pass


def is_squashfs(head):
    return len(head) >= 4 and head[:4] == MAGIC


def lzma_alone(data, limit):
    """The legacy .lzma format: properties, dictionary size and the
    uncompressed size in a 13-byte header, then raw LZMA1. Decoded raw
    from the header's values: liblzma's own .lzma reader calls
    mksquashfs's blocks corrupt (their size is known and they end with an
    end marker too)."""
    if len(data) < 13:
        raise SquashfsError("LZMA block shorter than its header")
    properties = data[0]
    dictionary = struct.unpack_from('<I', data, 1)[0]
    size = struct.unpack_from('<Q', data, 5)[0]
    literal, rest = properties % 9, properties // 9
    position, state = rest % 5, rest // 5
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
        'id': lzma.FILTER_LZMA1, 'lc': literal, 'lp': position,
        'pb': state, 'dict_size': max(dictionary, 4096)}])
    wanted = size if size != 0xFFFFFFFFFFFFFFFF else limit
    return decoder.decompress(data[13:], min(wanted, limit))


def decompress(compression, data, limit):
    """One block of `compression`, at most `limit` bytes once
    decompressed."""
    try:
        if compression == GZIP:
            return zlib.decompress(data)
        if compression == XZ:
            return lzma.decompress(data, format=lzma.FORMAT_XZ)
        if compression == LZMA:
            return lzma_alone(data, limit)
        if compression == LZO:
            from trace_app.core.btrfs import lzo1x_decompress
            return bytes(lzo1x_decompress(data, limit))
        if compression == LZ4:
            from trace_app.core.activity.journal import lz4_block
            return bytes(lz4_block(data, limit))
        if compression == ZSTD:
            from trace_app.core.zstd_decode import decompress_frame
            return bytes(decompress_frame(data, limit))
    except Exception as exc:          # every decompressor's own errors
        raise SquashfsError(f"{COMPRESSION_NAMES.get(compression)} block "
                            f"does not decompress: {exc}") from exc
    raise SquashfsError(f"compression {compression} is not known")


class SquashfsImage:
    """The structures of one image, read from `source` (a file object
    over the partition)."""

    def __init__(self, source):
        self.source = source
        head = self.read(0, SUPERBLOCK.size)
        if len(head) < SUPERBLOCK.size or not is_squashfs(head):
            raise SquashfsError("no SquashFS superblock")
        (_magic, self.inode_count, self.mkfs_time, self.block_size,
         self.fragment_count, self.compression, self.block_log, self.flags,
         self.id_count, major, minor, self.root_ref, self.bytes_used,
         self.id_table, self.xattr_table, self.inode_table,
         self.directory_table, self.fragment_table,
         self.export_table) = SUPERBLOCK.unpack(head)
        if major != 4:
            raise SquashfsError(f"SquashFS {major}.{minor} is not read "
                                f"(only 4.x)")
        if self.compression not in COMPRESSION_NAMES:
            raise SquashfsError(f"unknown compression {self.compression}")
        if not 4096 <= self.block_size <= MAX_BLOCK or \
                1 << self.block_log != self.block_size:
            raise SquashfsError(f"block size {self.block_size}")
        self._metadata = {}
        self._fragments = None
        self._ids = None
        self._exports = None
        self._inodes = {}

    # -- reading ------------------------------------------------------------

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def metadata_block(self, position):
        """(the block at `position` decompressed, where the next starts)."""
        cached = self._metadata.get(position)
        if cached is not None:
            return cached
        header = self.read(position, 2)
        if len(header) < 2:
            raise SquashfsError(f"metadata block at {position} past the end")
        size = struct.unpack('<H', header)[0]
        length = size & ~STORED & 0xFFFF
        if not length or length > METADATA_SIZE:
            raise SquashfsError(f"metadata block at {position}: {length}")
        data = self.read(position + 2, length)
        if not size & STORED:
            data = decompress(self.compression, data, METADATA_SIZE)
        result = (data, position + 2 + length)
        if len(self._metadata) > 4096:
            self._metadata.clear()
        self._metadata[position] = result
        return result

    def metadata(self, table, block, offset, length):
        """`length` bytes of metadata from a reference: `block` is relative
        to `table`, `offset` inside the decompressed block; runs on into
        the following blocks."""
        out = bytearray()
        position = table + block
        while len(out) < length:
            data, following = self.metadata_block(position)
            if offset > len(data):
                raise SquashfsError("metadata reference past its block")
            out += data[offset:offset + length - len(out)]
            offset = 0
            position = following
        return bytes(out)

    def _table(self, start, count, entry_size):
        """A table of `count` entries in metadata blocks, listed by the
        64-bit block positions at `start`."""
        if not count or start == INVALID_TABLE:
            return b''
        total = count * entry_size
        blocks = -(-total // METADATA_SIZE)
        pointers = struct.unpack(f'<{blocks}Q', self.read(start, 8 * blocks))
        out = bytearray()
        for pointer in pointers:
            data, _following = self.metadata_block(pointer)
            out += data
        return bytes(out[:total])

    def uid_gid(self, index):
        if self._ids is None:
            raw = self._table(self.id_table, self.id_count, 4)
            self._ids = struct.unpack(f'<{len(raw) // 4}I', raw)
        return self._ids[index] if index < len(self._ids) else 0

    def fragment(self, index):
        """(position, stored size) of fragment block `index`."""
        if self._fragments is None:
            raw = self._table(self.fragment_table, self.fragment_count, 16)
            self._fragments = [struct.unpack_from('<QI', raw, at)
                               for at in range(0, len(raw), 16)]
        if index >= len(self._fragments):
            raise SquashfsError(f"fragment {index} is not in the table")
        return self._fragments[index]

    def export_ref(self, number):
        """The inode reference of inode `number` (1-based), from the export
        table; None without one."""
        if not self.flags & EXPORTABLE or self.export_table == INVALID_TABLE:
            return None
        if self._exports is None:
            raw = self._table(self.export_table, self.inode_count, 8)
            self._exports = struct.unpack(f'<{len(raw) // 8}Q', raw)
        if 1 <= number <= len(self._exports):
            return self._exports[number - 1]
        return None

    def data_block(self, position, stored, expected):
        """One data block: `stored` is its size entry; `expected` how many
        bytes it holds once read."""
        size = stored & ~DATA_STORED
        if not size:
            return bytes(expected)          # sparse: nothing stored
        data = self.read(position, size)
        if not stored & DATA_STORED:
            data = decompress(self.compression, data, self.block_size)
        return data

    def inode(self, ref):
        cached = self._inodes.get(ref)
        if cached is None:
            cached = Inode(self, ref)
            if len(self._inodes) > 65536:
                self._inodes.clear()
            self._inodes[ref] = cached
        return cached

    def allocated_ranges(self):
        # Everything up to bytes_used is the image's; past it is padding.
        return [(0, self.bytes_used)]


class Inode:
    """One inode, from its reference."""

    def __init__(self, image, ref):
        self.image = image
        self.ref = ref
        block, offset = ref >> 16, ref & 0xFFFF
        head = image.metadata(image.inode_table, block, offset, 16)
        (self.type, permissions, uid, gid, self.mtime,
         self.number) = struct.unpack('<HHHHII', head)
        if self.type not in _MODE_KIND:
            raise SquashfsError(f"inode {ref:#x}: type {self.type}")
        self.mode = _MODE_KIND[self.type] | (permissions & 0o7777)
        self.uid = image.uid_gid(uid)
        self.gid = image.uid_gid(gid)
        self.nlink = 1
        self.size = 0
        self.target = b''
        self.blocks = ()
        self.start = 0
        self.fragment = NO_FRAGMENT
        self.fragment_offset = 0
        self.parent = 0
        self.listing = None          # (block, offset, size) of a directory
        # The fixed part of every type fits in 56 bytes after the header;
        # a file's block list and a link's target follow it.
        body = image.metadata(image.inode_table, block, offset, 16 + 56)[16:]
        kind = self.type
        if kind == BASIC_DIR:
            start, self.nlink, size, at, self.parent =                 struct.unpack_from('<IIHHI', body)
            self.listing = (start, at, size)
        elif kind == EXT_DIR:
            self.nlink, size, start, self.parent, _count, at,                 _xattr = struct.unpack_from('<IIIIHHI', body)
            self.listing = (start, at, size)
        elif kind in (BASIC_FILE, EXT_FILE):
            if kind == BASIC_FILE:
                self.start, self.fragment, self.fragment_offset,                     self.size = struct.unpack_from('<IIII', body)
                fixed = 16
            else:
                self.start, self.size, _sparse, self.nlink, self.fragment,                     self.fragment_offset, _xattr = struct.unpack_from(
                        '<QQQIIII', body)
                fixed = 40
            whole, tail = divmod(self.size, image.block_size)
            count = whole if self.fragment != NO_FRAGMENT else                 whole + (1 if tail else 0)
            if count:
                raw = image.metadata(image.inode_table, block, offset,
                                     16 + fixed + 4 * count)[16 + fixed:]
                self.blocks = struct.unpack(f'<{count}I', raw)
        elif kind in (BASIC_SYMLINK, EXT_SYMLINK):
            self.nlink, length = struct.unpack_from('<II', body)
            self.target = image.metadata(image.inode_table, block, offset,
                                         24 + length)[24:]
            self.size = length
        else:
            self.nlink, = struct.unpack_from('<I', body)
        self._offsets = None

    @property
    def is_dir(self):
        return self.listing is not None

    def entries(self):
        """[(name bytes, inode reference, inode number)] of a directory."""
        if self.listing is None:
            return []
        start, offset, size = self.listing
        # The recorded size counts 3 bytes for '.' and '..'.
        if size <= 3:
            return []
        data = self.image.metadata(self.image.directory_table, start, offset,
                                   size - 3)
        out = []
        position = 0
        while position + 12 <= len(data):
            count, block, base = struct.unpack_from('<III', data, position)
            position += 12
            for _ in range(count + 1):
                entry_offset, delta, _type, length = struct.unpack_from(
                    '<HhHH', data, position)
                position += 8
                name = data[position:position + length + 1]
                position += length + 1
                out.append((name, block << 16 | entry_offset, base + delta))
        return out

    def _block_offsets(self):
        """Where each data block starts: stored blocks lie end to end."""
        if self._offsets is None:
            offsets = []
            position = self.start
            for stored in self.blocks:
                offsets.append(position)
                position += stored & ~DATA_STORED
            self._offsets = offsets
        return self._offsets

    def read(self, offset, length):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        if self.type in (BASIC_SYMLINK, EXT_SYMLINK):
            return self.target[offset:offset + length]
        size = self.image.block_size
        offsets = self._block_offsets()
        out = bytearray()
        index = offset // size
        skip = offset - index * size
        while len(out) < length:
            if index < len(self.blocks):
                expected = min(size, self.size - index * size)
                data = self.image.data_block(offsets[index],
                                             self.blocks[index], expected)
            else:
                data = self._tail()
            if not data:
                break
            out += data[skip:skip + length - len(out)]
            skip = 0
            index += 1
        return bytes(out)

    def _tail(self):
        """The file's last part, from its fragment block."""
        if self.fragment == NO_FRAGMENT:
            return b''
        position, stored = self.image.fragment(self.fragment)
        block = self.image.data_block(position, stored,
                                      self.image.block_size)
        tail = self.size % self.image.block_size
        return block[self.fragment_offset:self.fragment_offset + tail]


# --- libyal's vocabulary -----------------------------------------------------

class SquashfsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, image, ref, name='', parent=0):
        self._image = image
        self._inode = image.inode(ref)
        self.identifier = self._inode.number
        self.parent_identifier = parent or self._inode.parent
        self.name = name
        self.file_mode = self._inode.mode
        self.size = 0 if self._inode.is_dir else self._inode.size
        self.owner_identifier = self._inode.uid
        self.group_identifier = self._inode.gid
        self._children = None

    def get_number_of_links(self):
        return self._inode.nlink

    def get_modification_time_as_integer(self):
        return self._inode.mtime * 1_000_000_000

    @property
    def symbolic_link_target(self):
        return self._inode.target.decode('utf-8', 'surrogateescape')

    def _list(self):
        if self._children is None:
            try:
                self._children = self._inode.entries()
            except (SquashfsError, struct.error) as exc:
                logger.warning("SquashFS directory %d unreadable: %s",
                               self.identifier, exc)
                self._children = []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, ref, _number = self._list()[index]
        return SquashfsEntry(self._image, ref,
                             name.decode('utf-8', 'surrogateescape'),
                             self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._inode.read(offset, length)


class _Volume:
    """libyal's volume vocabulary over a SquashfsImage."""

    def __init__(self, image):
        self.image = image
        self._refs = None

    def get_root_directory(self):
        return SquashfsEntry(self.image, self.image.root_ref)

    def entry(self, number):
        ref = self.image.export_ref(number)
        if ref is None:
            ref = self._walked().get(number)
        if ref is None:
            return None
        if ref == self.image.root_ref:
            return self.get_root_directory()
        entry = SquashfsEntry(self.image, ref)
        entry.name = self._names().get(number, '')
        return entry

    def _walked(self):
        """{inode number: reference}, by walking the tree -- for an image
        made without an export table."""
        if self._refs is None:
            self._refs, self._name_of = {}, {}
            root = self.image.inode(self.image.root_ref)
            self._refs[root.number] = self.image.root_ref
            pending = [root]
            while pending:
                inode = pending.pop()
                for name, ref, number in inode.entries():
                    if number in self._refs:
                        continue
                    self._refs[number] = ref
                    self._name_of[number] = name.decode(
                        'utf-8', 'surrogateescape')
                    child = self.image.inode(ref)
                    if child.is_dir:
                        pending.append(child)
        return self._refs

    def _names(self):
        self._walked()
        return self._name_of

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _ref, _number) in enumerate(entry._list()):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.image._metadata.clear()
        self.image._inodes.clear()


class SquashfsFileSystem(LibyalFileSystem):
    """A SquashFS image, read like a pytsk3.FS_Info."""

    KIND = 'SquashFS'

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.block_size
        super().__init__(_Volume(image), image.bytes_used,
                         f"SquashFS ({COMPRESSION_NAMES[image.compression]})")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return self.image.inode(self.image.root_ref).number

    def _last_identifier(self):
        return self.image.inode_count

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()

    def close(self):
        self.volume.close()


def open_squashfs(source):
    """A SquashfsFileSystem over `source` (a file object over the
    partition), or None when it is not a SquashFS image TRACE can read."""
    try:
        source.seek(0)
        head = source.read(4)
    except (OSError, IOError):
        return None
    if not is_squashfs(head):
        return None
    try:
        return SquashfsFileSystem(SquashfsImage(source))
    except (SquashfsError, struct.error, OSError, IOError) as exc:
        logger.warning("SquashFS image not opened: %s", exc)
        return None


def is_squashfs_fs(fs):
    return isinstance(fs, SquashfsFileSystem)

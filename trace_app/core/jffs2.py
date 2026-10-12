"""JFFS2 images, read in Python (no Qt).

JFFS2 is the log-structured file system of raw NOR/NAND flash: routers,
IP cameras, set-top boxes and other embedded devices, whose firmware dumps
come as JFFS2 images. The Sleuth Kit does not read it. There is no tree on
the flash, only nodes (fs/jffs2/, include/uapi/linux/jffs2.h):

* every node starts with a 12-byte header -- magic 0x1985, node type,
  total length, header CRC -- in the device's byte order, at a 4-byte
  boundary; erased flash (0xFF) and padding lie between them;
* a directory entry node names an inode in a parent directory, with a
  version; the newest version of a (parent, name) wins, and inode 0 there
  means the name was removed;
* an inode node carries the inode's attributes (mode, owner, size, times)
  and one piece of its data -- offset, compressed and decompressed size,
  compressor (none, zero, rtime, zlib, LZO) -- with a version; a file is
  its nodes laid down in version order, the newest attributes standing;
* a node that was superseded on the flash has its "accurate" bit cleared.

So the whole image is scanned once for valid nodes (header and node CRCs
checked) and the files are built from them. JFFS2's CRC is the kernel's
crc32 seeded with 0, not zlib's: crc32(data, ~0) ^ ~0. Entries speak
libyal's vocabulary, so core/libyal_fs presents them like every other file
system. Removed names are not listed; rubin compression (never on by
default) is not read.
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.JFFS2')

MAGIC = 0x1985
NODE_ACCURATE = 0x2000
DIRENT = 0xE001
INODE = 0xE002
HEADER = 12
DIRENT_SIZE = 40
INODE_SIZE = 68

COMPR_NONE, COMPR_ZERO, COMPR_RTIME, COMPR_RUBINMIPS, COMPR_COPY, \
    COMPR_DYNRUBIN, COMPR_ZLIB, COMPR_LZO, COMPR_LZMA = range(9)
COMPRESSION_NAMES = {COMPR_NONE: 'none', COMPR_ZERO: 'zero',
                     COMPR_RTIME: 'rtime', COMPR_RUBINMIPS: 'rubinmips',
                     COMPR_COPY: 'copy', COMPR_DYNRUBIN: 'dynrubin',
                     COMPR_ZLIB: 'zlib', COMPR_LZO: 'LZO',
                     COMPR_LZMA: 'LZMA'}

ROOT = 1
#: Scanned this much at a time.
CHUNK = 16 << 20
#: Larger than a JFFS2 node can be (data nodes hold at most a page).
MAX_NODE = 1 << 20


class Jffs2Error(Exception):
    pass


def crc32(data):
    """The kernel's crc32(0, data): zlib's, without its inversions."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def byte_order(head):
    """'<' or '>' when `head` holds a JFFS2 node header at a 4-byte
    boundary, else None."""
    for order, magic in (('<', b'\x85\x19'), ('>', b'\x19\x85')):
        position = head.find(magic)
        while position != -1:
            if position % 4 == 0 and position + HEADER <= len(head):
                _magic, kind, length, header_crc = struct.unpack_from(
                    order + 'HHII', head, position)
                if crc32(head[position:position + 8]) == header_crc and \
                        kind & 0x00FF and length >= HEADER:
                    return order
            position = head.find(magic, position + 1)
    return None


def rtime(data, size):
    """JFFS2's rtime: a literal byte, then a repeat count copied from where
    that byte value was last seen (compr_rtime.c)."""
    positions = [0] * 256
    out = bytearray()
    position = 0
    while len(out) < size and position + 1 < len(data):
        value = data[position]
        repeat = data[position + 1]
        position += 2
        out.append(value)
        back = positions[value]
        positions[value] = len(out)
        for _ in range(repeat):
            out.append(out[back])
            back += 1
    return bytes(out[:size])


def decompress(method, data, size):
    try:
        if method in (COMPR_NONE, COMPR_COPY):
            return data[:size]
        if method == COMPR_ZERO:
            return bytes(size)
        if method == COMPR_ZLIB:
            return zlib.decompress(data)[:size]
        if method == COMPR_RTIME:
            return rtime(data, size)
        if method == COMPR_LZO:
            from trace_app.core.btrfs import lzo1x_decompress
            return bytes(lzo1x_decompress(data, size))[:size]
    except Exception as exc:          # every decompressor's own errors
        raise Jffs2Error(f"{COMPRESSION_NAMES.get(method)} data does not "
                         f"decompress: {exc}") from exc
    raise Jffs2Error(f"{COMPRESSION_NAMES.get(method, method)} compression "
                     f"is not read")


class Jffs2Image:
    """Every valid node of one image, read from `source` (a file object
    over the partition or flash dump)."""

    def __init__(self, source, size=None):
        self.source = source
        if size is None:
            source.seek(0, 2)
            size = source.tell()
        self.size = size
        head = self.read(0, min(size, 1 << 20))
        self.order = byte_order(head)
        if self.order is None:
            raise Jffs2Error("no JFFS2 node")
        #: ino -> [(version, offset, node fields)]
        self.inodes = {}
        #: (parent ino, name) -> (version, ino, type, mctime)
        self.names = {}
        self.ranges = []
        self._scan()
        self._files = {}

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def _scan(self):
        order = self.order
        magic = b'\x85\x19' if order == '<' else b'\x19\x85'
        dirent = struct.Struct(order + 'IIIIBB2xII')
        inode = struct.Struct(order + 'IIIHHIIIIIIIBBHII')
        offset = 0
        while offset < self.size:
            data = self.read(offset, CHUNK + MAX_NODE)
            if not data:
                break
            limit = min(len(data), CHUNK)
            position = data.find(magic)
            while position != -1 and position < limit:
                if position % 4 or position + HEADER > len(data):
                    position = data.find(magic, position + 1)
                    continue
                _magic, kind, length, header_crc = struct.unpack_from(
                    order + 'HHII', data, position)
                if crc32(data[position:position + 8]) != header_crc or \
                        not HEADER <= length <= MAX_NODE or \
                        position + length > len(data):
                    position = data.find(magic, position + 1)
                    continue
                node = data[position:position + length]
                if kind & NODE_ACCURATE:
                    self._node(kind, node, offset + position, dirent, inode)
                self.ranges.append((offset + position,
                                    offset + position + length))
                step = (length + 3) // 4 * 4
                position = data.find(magic, position + step)
            offset += CHUNK

    def _node(self, kind, node, offset, dirent, inode):
        if kind == DIRENT and len(node) >= DIRENT_SIZE:
            (parent, version, ino, mctime, name_size, file_type, node_crc,
             name_crc) = dirent.unpack_from(node, HEADER)
            if crc32(node[:DIRENT_SIZE - 8]) != node_crc:
                return
            name = node[DIRENT_SIZE:DIRENT_SIZE + name_size]
            if crc32(name) != name_crc:
                return
            key = (parent, name)
            known = self.names.get(key)
            if known is None or version > known[0]:
                self.names[key] = (version, ino, file_type, mctime)
        elif kind == INODE and len(node) >= INODE_SIZE:
            (ino, version, mode, uid, gid, isize, atime, mtime, ctime,
             data_offset, csize, dsize, compression, _user, _flags,
             data_crc, node_crc) = inode.unpack_from(node, HEADER)
            if crc32(node[:INODE_SIZE - 8]) != node_crc:
                return
            self.inodes.setdefault(ino, []).append(
                (version, offset, {
                    'mode': mode, 'uid': uid, 'gid': gid, 'size': isize,
                    'atime': atime, 'mtime': mtime, 'ctime': ctime,
                    'offset': data_offset, 'csize': csize, 'dsize': dsize,
                    'compression': compression, 'data_crc': data_crc}))

    def children(self, parent):
        """[(name, ino, type)] in `parent`: each name's newest entry, names
        removed (inode 0) left out."""
        out = []
        for (owner, name), (_version, ino, kind, _time) in \
                self.names.items():
            if owner == parent and ino:
                out.append((name, ino, kind))
        out.sort(key=lambda item: item[0])
        return out

    def parents(self):
        """{ino: (parent, name)} from the live directory entries."""
        out = {}
        for (owner, name), (_version, ino, _kind, _time) in \
                self.names.items():
            if ino:
                out.setdefault(ino, (owner, name))
        return out

    def attributes(self, ino):
        """The newest inode node's fields, or None."""
        nodes = self.inodes.get(ino)
        if not nodes:
            return None
        return max(nodes, key=lambda node: node[0])[2]

    def content(self, ino):
        """A file's bytes: its data nodes laid down in version order."""
        cached = self._files.get(ino)
        if cached is not None:
            return cached
        attributes = self.attributes(ino)
        if attributes is None:
            return b''
        size = attributes['size']
        out = bytearray(size)
        for version, offset, fields in sorted(self.inodes[ino],
                                              key=lambda node: node[0]):
            if not fields['dsize']:
                continue
            raw = self.read(offset + INODE_SIZE, fields['csize'])
            if crc32(raw) != fields['data_crc']:
                logger.debug("JFFS2 inode %d version %d: data CRC fails",
                             ino, version)
                continue
            piece = decompress(fields['compression'], raw, fields['dsize'])
            start = fields['offset']
            end = min(size, start + len(piece))
            if start < end:
                out[start:end] = piece[:end - start]
        result = bytes(out)
        if len(self._files) > 256:
            self._files.clear()
        self._files[ino] = result
        return result

    def allocated_ranges(self):
        return sorted(self.ranges)


# --- libyal's vocabulary -----------------------------------------------------

class Jffs2Entry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, image, ino, name='', parent=0):
        self._image = image
        self.identifier = ino
        self.parent_identifier = parent
        self.name = name
        attributes = image.attributes(ino) or {}
        self._attributes = attributes
        self.file_mode = attributes.get('mode', stat.S_IFDIR | 0o755
                                        if ino == ROOT else 0)
        self.size = 0 if stat.S_ISDIR(self.file_mode) else \
            attributes.get('size', 0)
        self.owner_identifier = attributes.get('uid', 0)
        self.group_identifier = attributes.get('gid', 0)
        self._children = None

    def get_number_of_links(self):
        return 1

    def _time(self, which):
        value = self._attributes.get(which, 0)
        return value * 1_000_000_000 if value else 0

    def get_access_time_as_integer(self):
        return self._time('atime')

    def get_modification_time_as_integer(self):
        return self._time('mtime')

    def get_inode_change_time_as_integer(self):
        return self._time('ctime')

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._image.content(self.identifier).decode(
            'utf-8', 'surrogateescape')

    @property
    def compression(self):
        methods = {fields['compression']
                   for _version, _offset, fields in
                   self._image.inodes.get(self.identifier, ())
                   if fields['dsize']}
        methods.discard(COMPR_NONE)
        return ', '.join(sorted(COMPRESSION_NAMES.get(m, str(m))
                                for m in methods)) or None

    def _list(self):
        if self._children is None:
            self._children = self._image.children(self.identifier) \
                if stat.S_ISDIR(self.file_mode) else []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, ino, _kind = self._list()[index]
        return Jffs2Entry(self._image, ino,
                          name.decode('utf-8', 'surrogateescape'),
                          self.identifier)

    def read_buffer_at_offset(self, length, offset):
        data = self._image.content(self.identifier)
        return data[offset:offset + length]


class _Volume:
    """libyal's volume vocabulary over a Jffs2Image."""

    def __init__(self, image):
        self.image = image
        self.label = ''
        self._parents = None

    def get_root_directory(self):
        return Jffs2Entry(self.image, ROOT)

    def entry(self, ino):
        if ino == ROOT:
            return self.get_root_directory()
        if ino not in self.image.inodes:
            return None
        if self._parents is None:
            self._parents = self.image.parents()
        parent, name = self._parents.get(ino, (0, b''))
        return Jffs2Entry(self.image, ino,
                          name.decode('utf-8', 'surrogateescape'), parent)

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _ino, _kind) in enumerate(entry._list()):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.image._files.clear()


class Jffs2FileSystem(LibyalFileSystem):
    """A JFFS2 image, read like a pytsk3.FS_Info."""

    KIND = 'JFFS2'

    def __init__(self, image):
        self.image = image
        super().__init__(_Volume(image), image.size,
                         f"JFFS2 ({'little' if image.order == '<' else 'big'}"
                         f"-endian)")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _last_identifier(self):
        return max(self.image.inodes, default=ROOT)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()

    def close(self):
        self.volume.close()


def open_jffs2(source):
    """A Jffs2FileSystem over `source`, or None when it holds no JFFS2
    nodes TRACE can read."""
    try:
        source.seek(0)
        head = source.read(64 * 1024)
    except (OSError, IOError):
        return None
    if byte_order(head) is None:
        return None
    try:
        image = Jffs2Image(source)
        if not image.inodes and not image.names:
            return None
        return Jffs2FileSystem(image)
    except (Jffs2Error, struct.error, OSError, IOError) as exc:
        logger.warning("JFFS2 image not opened: %s", exc)
        return None


def is_jffs2_fs(fs):
    return isinstance(fs, Jffs2FileSystem)

"""EROFS images, read in Python (no Qt).

EROFS (Enhanced Read-Only File System) holds the system, vendor and product
partitions of current Android phones (and some Linux images and
containers). The Sleuth Kit does not read it. The layout (the kernel's
fs/erofs/erofs_fs.h, zmap.c, decompressor*.c):

* a 128-byte superblock at 1 KiB (magic 0xE0F5E1E2): block size, the
  metadata area's first block, the root's nid, features, the packed inode
  (fragments);
* an inode lives at metadata area + nid * 32: compact (32 bytes; its time
  is the image's build time) or extended (64 bytes), then its inline
  xattrs, then whatever its data layout keeps inline;
* data layouts: flat (blocks from raw_blkaddr), flat with the tail inline
  after the inode, chunk-based (a table of block addresses per chunk), and
  compressed -- full (legacy) or compact indexes, one per logical cluster,
  saying where each extent starts and which physical cluster holds it;
* compressed extents: LZ4, MicroLZMA, DEFLATE or zstd, right-aligned in
  their physical cluster behind zero padding; an uncompressed (plain)
  physical cluster may be stored rotated ("interlaced"); the last extent
  may be inline after the indexes (tail packing) or a fragment of the
  packed inode, which can also hold a whole file;
* directories: blocks of 12-byte entries (nid, name offset, type) and the
  names after them.

The index decoding follows the kernel (zmap.c) step for step. Entries
speak libyal's vocabulary, so core/libyal_fs presents them like every other
file system. Read-only: nothing is ever deleted, so nothing deleted is
listed. Devices outside the image (multi-device images) are not read.
"""

import logging
import lzma
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.EROFS')

MAGIC = 0xE0F5E1E2
SUPER_OFFSET = 1024
SUPERBLOCK = struct.Struct('<IIIBBHQQIIII16s16sIHHHBBIQ')
ISLOT = 32
NULL_ADDR = 0xFFFFFFFF

# Features.
INCOMPAT_ZERO_PADDING = 0x00000001
INCOMPAT_COMPR_CFGS = 0x00000002
INCOMPAT_FRAGMENTS = 0x00000020

# Data layouts.
FLAT_PLAIN, COMPRESSED_FULL, FLAT_INLINE, COMPRESSED_COMPACT, \
    CHUNK_BASED = range(5)
LAYOUT_NAMES = {FLAT_PLAIN: 'flat', COMPRESSED_FULL: 'compressed (full)',
                FLAT_INLINE: 'flat, tail inline',
                COMPRESSED_COMPACT: 'compressed (compact)',
                CHUNK_BASED: 'chunks'}

# Chunk-based files.
CHUNK_FORMAT_BLKBITS_MASK = 0x001F
CHUNK_FORMAT_INDEXES = 0x0020

# Compressed files: the map header's advice, lcluster types, algorithms.
ADVISE_COMPACTED_2B = 0x0001
ADVISE_BIG_PCLUSTER_1 = 0x0002
ADVISE_BIG_PCLUSTER_2 = 0x0004
ADVISE_INLINE_PCLUSTER = 0x0008
ADVISE_INTERLACED_PCLUSTER = 0x0010
ADVISE_FRAGMENT_PCLUSTER = 0x0020
FRAGMENT_INODE_BIT = 7
TYPE_PLAIN, TYPE_HEAD1, TYPE_NONHEAD, TYPE_HEAD2 = range(4)
LI_D0_CBLKCNT = 1 << 11
LI_PARTIAL_REF = 1 << 15
LZ4, LZMA, DEFLATE, ZSTD = range(4)
ALGORITHM_NAMES = {LZ4: 'LZ4', LZMA: 'MicroLZMA', DEFLATE: 'DEFLATE',
                   ZSTD: 'zstd'}

_FILE_TYPES = {1: stat.S_IFREG, 2: stat.S_IFDIR, 3: stat.S_IFCHR,
               4: stat.S_IFBLK, 5: stat.S_IFIFO, 6: stat.S_IFSOCK,
               7: stat.S_IFLNK}


class ErofsError(Exception):
    pass


def is_erofs(head):
    return len(head) >= SUPER_OFFSET + 4 and struct.unpack_from(
        '<I', head, SUPER_OFFSET)[0] == MAGIC


def _align(value, unit):
    return (value + unit - 1) // unit * unit


def decompress(algorithm, data, length, padded=True):
    """`length` bytes from one physical cluster of `algorithm`. With zero
    padding (every image since Linux 5.3) the stream is right-aligned
    behind zeros; without, it starts the cluster and stops where the
    extent ends."""
    start = 0
    while padded and start < len(data) and data[start] == 0:
        start += 1
    data = bytes(data[start:])
    try:
        if algorithm == LZ4:
            from trace_app.core.activity.journal import lz4_block
            return bytes(lz4_block(data, length, stop_at=None if padded
                                   else length))[:length]
        if algorithm == LZMA:
            # MicroLZMA: LZMA1 whose range coder's first byte (always 0) is
            # replaced by the properties byte, inverted.
            properties = ~data[0] & 0xFF
            literal, rest = properties % 9, properties // 9
            position, state = rest % 5, rest // 5
            decoder = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW, filters=[{
                    'id': lzma.FILTER_LZMA1, 'lc': literal, 'lp': position,
                    'pb': state, 'dict_size': 8 << 20}])
            return decoder.decompress(b'\x00' + data[1:], length)
        if algorithm == DEFLATE:
            decoder = zlib.decompressobj(-15)
            return decoder.decompress(data, length)
        if algorithm == ZSTD:
            from trace_app.core.zstd_decode import decompress_frame
            return bytes(decompress_frame(data, max(length, 1 << 20)))[
                :length]
    except Exception as exc:          # every decompressor's own errors
        raise ErofsError(f"{ALGORITHM_NAMES.get(algorithm)} cluster does "
                         f"not decompress: {exc}") from exc
    raise ErofsError(f"compression algorithm {algorithm} is not supported")


class ErofsImage:
    """The structures of one image, read from `source` (a file object
    over the partition)."""

    def __init__(self, source):
        self.source = source
        head = self.read(SUPER_OFFSET, SUPERBLOCK.size)
        if len(head) < SUPERBLOCK.size:
            raise ErofsError("no EROFS superblock")
        (magic, _checksum, _compat, self.block_bits, _extslots,
         self.root_nid, self.inode_count, self.build_time,
         self.build_time_nsec, self.block_count, self.meta_blkaddr,
         _xattr_blkaddr, _uuid, label, self.incompat, _algorithms,
         _devices, _devt, self.dir_block_bits, _prefixes, _prefix_start,
         self.packed_nid) = SUPERBLOCK.unpack(head)
        if magic != MAGIC:
            raise ErofsError("no EROFS superblock")
        if not 9 <= self.block_bits <= 16:
            raise ErofsError(f"block size 2^{self.block_bits}")
        self.block = 1 << self.block_bits
        self.label = label.split(b'\0', 1)[0].decode('utf-8', 'replace')
        self._inodes = {}
        self._packed = None

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def inode(self, nid):
        cached = self._inodes.get(nid)
        if cached is None:
            cached = Inode(self, nid)
            if len(self._inodes) > 65536:
                self._inodes.clear()
            self._inodes[nid] = cached
        return cached

    def packed(self):
        """The packed inode, whose data holds files' fragments."""
        if self._packed is None:
            if not self.incompat & INCOMPAT_FRAGMENTS or not self.packed_nid:
                raise ErofsError("a fragment, but no packed inode")
            self._packed = Inode(self, self.packed_nid)
        return self._packed

    def allocated_ranges(self):
        return [(0, self.block_count * self.block)]


class Inode:
    """One inode, from its nid."""

    def __init__(self, image, nid):
        self.image = image
        self.nid = nid
        self.position = image.meta_blkaddr * image.block + nid * ISLOT
        head = image.read(self.position, 64)
        if len(head) < 32:
            raise ErofsError(f"inode {nid} past the end of the image")
        form = struct.unpack_from('<H', head, 0)[0]
        self.extended = bool(form & 1)
        self.layout = (form >> 1) & 7
        if self.extended:
            (_format, xattr_count, mode, _reserved, self.size, self.raw,
             self.ino, self.uid, self.gid, mtime, mtime_nsec,
             self.nlink) = struct.unpack_from('<HHHHQIIIIQII', head)
            self.inode_size = 64
            self.mtime = (mtime, mtime_nsec)
        else:
            (_format, xattr_count, mode, self.nlink, self.size, _reserved,
             self.raw, self.ino, self.uid, self.gid) = struct.unpack_from(
                 '<HHHHIIIIHH', head)
            self.inode_size = 32
            # A compact inode's time is the image's build time.
            self.mtime = (image.build_time, image.build_time_nsec)
        self.mode = mode
        self.xattr_size = 12 + (xattr_count - 1) * 4 if xattr_count else 0
        #: Where what the layout keeps inline begins.
        self.inline = self.position + self.inode_size + self.xattr_size
        self._extents = None

    @property
    def is_dir(self):
        return stat.S_ISDIR(self.mode)

    @property
    def compressed(self):
        return self.layout in (COMPRESSED_FULL, COMPRESSED_COMPACT)

    # -- reading ------------------------------------------------------------

    def read(self, offset, length):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        if self.layout in (FLAT_PLAIN, FLAT_INLINE):
            return self._read_flat(offset, length)
        if self.layout == CHUNK_BASED:
            return self._read_chunks(offset, length)
        if self.compressed:
            return self._read_compressed(offset, length)
        raise ErofsError(f"inode {self.nid}: data layout {self.layout}")

    def _read_flat(self, offset, length):
        block = self.image.block
        blocks = -(-self.size // block)
        # With the tail inline, the last block lives after the inode.
        stored = blocks - 1 if self.layout == FLAT_INLINE else blocks
        out = bytearray()
        while len(out) < length:
            position = offset + len(out)
            number = position // block
            within = position % block
            want = min(length - len(out), block - within)
            if number < stored:
                # Contiguous blocks: read on to the end of them at once.
                want = min(length - len(out), stored * block - position)
                data = self.image.read(self.raw * block + position, want)
            else:
                data = self.image.read(self.inline + within, want)
            if not data:
                break
            out += data
        return bytes(out)

    def _read_chunks(self, offset, length):
        block = self.image.block
        form = self.raw & 0xFFFF
        chunk = block << (form & CHUNK_FORMAT_BLKBITS_MASK)
        unit = 8 if form & CHUNK_FORMAT_INDEXES else 4
        table = _align(self.inline, unit)
        out = bytearray()
        while len(out) < length:
            position = offset + len(out)
            number, within = divmod(position, chunk)
            entry = self.image.read(table + number * unit, unit)
            address = struct.unpack_from('<I', entry, unit - 4)[0]
            want = min(length - len(out), chunk - within)
            if address == NULL_ADDR:
                out += bytes(want)                    # a hole
            else:
                out += self.image.read(address * block + within, want)
        return bytes(out)

    # -- compressed files ---------------------------------------------------

    def _map_header(self):
        position = _align(self.inline, 8)
        raw = self.image.read(position, 8)
        (fragment_off, advise, algorithms,
         cluster_bits) = struct.unpack('<IHBB', raw)
        self._header64 = struct.unpack('<Q', raw)[0]
        return position, fragment_off, advise, algorithms, cluster_bits

    def extents(self):
        """[(logical start, length, kind, where, stored length, algorithm)]
        in file order. kind: 'plain', 'compressed', 'fragment'; `where` is
        a byte position in the image (the packed inode's for a fragment)."""
        if self._extents is None:
            self._extents = self._map()
        return self._extents

    def _map(self):
        image = self.image
        header, fragment_off, advise, algorithms, cluster_bits = \
            self._map_header()
        idata_size = fragment_off >> 16
        if cluster_bits >> FRAGMENT_INODE_BIT & 1:
            # The whole file is a fragment of the packed inode; the rest of
            # the 8-byte header is where it starts there.
            where = self._header64 ^ (1 << 63)
            return [(0, self.size, 'fragment', where, self.size, None)]
        lcluster_bits = image.block_bits + (cluster_bits & 7)
        lcluster = 1 << lcluster_bits
        # One index per block of the file (the kernel's BLK_ROUND_UP).
        total = -(-self.size // image.block)
        records = self._indexes(header, advise, lcluster_bits, total)
        heads = [(lcn, record) for lcn, record in enumerate(records)
                 if record['type'] != TYPE_NONHEAD]
        big = bool(advise & ADVISE_BIG_PCLUSTER_1)
        extents = []
        for number, (lcn, record) in enumerate(heads):
            start = lcn * lcluster + record['clusterofs']
            if number + 1 < len(heads):
                following = heads[number + 1]
                end = following[0] * lcluster + following[1]['clusterofs']
            else:
                end = self.size
            end = min(end, self.size)
            if end <= start:
                continue
            # How much is stored (z_erofs_get_extent_compressedlen): one
            # logical cluster, unless a big physical cluster says more in
            # the first non-head index after its head.
            stored = lcluster
            if big and record['type'] != TYPE_PLAIN and \
                    lcn + 1 < len(records):
                after = records[lcn + 1]
                if after['type'] == TYPE_NONHEAD:
                    if after.get('compressedblks') is None:
                        raise ErofsError(f"inode {self.nid}: no block count "
                                         f"after lcluster {lcn}")
                    stored = after['compressedblks'] * image.block
            algorithm = (algorithms & 0xF) if record['type'] == TYPE_HEAD1 \
                else (algorithms >> 4) & 0xF
            kind = 'plain' if record['type'] == TYPE_PLAIN else 'compressed'
            extents.append([start, end - start, kind,
                            record.get('pblk', 0) * image.block, stored,
                            algorithm, record.get('pblk', 0)])
        if not extents:
            return []
        last = extents[-1]
        if advise & ADVISE_FRAGMENT_PCLUSTER:
            # The last extent is a fragment of the packed inode. With full
            # indexes the offset is 64-bit: its high half is the block
            # address of the tail extent's head.
            where = fragment_off
            if self.layout == COMPRESSED_FULL:
                where |= last[6] << 32
            last[2], last[3], last[4] = 'fragment', where, last[1]
        elif advise & ADVISE_INLINE_PCLUSTER:
            # Tail packing: the last physical cluster is inline, after the
            # indexes.
            last[3] = self._index_end
            last[4] = idata_size
        return [tuple(extent[:6]) for extent in extents]

    def _indexes(self, header, advise, lcluster_bits, total):
        if self.layout == COMPRESSED_FULL:
            return self._full_indexes(header, advise, lcluster_bits, total)
        return self._compact_indexes(header, advise, lcluster_bits, total)

    def _full_indexes(self, header, advise, lcluster_bits, total):
        base = header + 8 + 8
        raw = self.image.read(base, total * 8)
        records = []
        for lcn in range(total):
            di_advise, clusterofs, union = struct.unpack_from(
                '<HHI', raw, lcn * 8)
            kind = di_advise & 3
            if kind == TYPE_NONHEAD:
                delta0 = union & 0xFFFF
                record = {'type': kind}
                if delta0 & LI_D0_CBLKCNT:
                    record['compressedblks'] = delta0 & ~LI_D0_CBLKCNT
                records.append(record)
            else:
                if clusterofs >= 1 << lcluster_bits:
                    raise ErofsError(f"inode {self.nid}: cluster offset")
                records.append({'type': kind, 'clusterofs': clusterofs,
                                'pblk': union})
        self._index_end = base + total * 8
        return records

    def _compact_indexes(self, header, advise, lcluster_bits, total):
        """The kernel's compacted_load_cluster_from_disk and
        unpack_compacted_index, for every logical cluster."""
        ebase = header + 8
        initial = (32 - ebase % 32) // 4
        if initial == 8:
            initial = 0
        if advise & ADVISE_COMPACTED_2B and initial < total:
            two_byte = (total - initial) // 16 * 16
        else:
            two_byte = 0
        big = bool(advise & ADVISE_BIG_PCLUSTER_1)
        end = ebase + initial * 4 + two_byte * 2 + \
            (total - initial - two_byte) * 4
        # Packs are aligned to the image (8 or 32 bytes), not to where the
        # indexes begin: read from a 32-byte boundary and keep positions
        # relative to it.
        origin = ebase - ebase % 32
        raw = self.image.read(origin, end - origin + 32)
        records = []
        next_pack = ebase
        for lcn in range(total):
            if lcn < initial:
                shift, at = 2, ebase + lcn * 4
            elif lcn < initial + two_byte:
                shift, at = 1, ebase + initial * 4 + (lcn - initial) * 2
            else:
                shift, at = 2, ebase + initial * 4 + two_byte * 2 + \
                    (lcn - initial - two_byte) * 4
            record, pack_end = _unpack_compacted(raw, at - origin, shift,
                                                 lcluster_bits, big)
            next_pack = origin + pack_end
            records.append(record)
        # Tail packing keeps the inline cluster after the last index's
        # pack (the kernel's nextpackoff).
        self._index_end = next_pack
        return records

    def _read_compressed(self, offset, length):
        out = bytearray()
        end = offset + length
        for start, size, kind, where, stored, algorithm in self.extents():
            if start + size <= offset or start >= end:
                continue
            data = self._extent(start, size, kind, where, stored, algorithm)
            out += data[max(offset, start) - start:min(start + size, end)
                        - start]
        return bytes(out)

    def _extent(self, start, size, kind, where, stored, algorithm):
        if kind == 'fragment':
            return self.image.packed().read(where, size)
        raw = self.image.read(where, stored)
        if kind == 'plain':
            _header, _frag, advise, _alg, _bits = self._map_header()
            if advise & ADVISE_INTERLACED_PCLUSTER:
                # Stored rotated: the extent's first byte sits at its
                # offset within a block.
                turn = start % self.image.block
                raw = raw[turn:] + raw[:turn]
            return raw[:size]
        return decompress(algorithm, raw, size, padded=bool(
            self.image.incompat & INCOMPAT_ZERO_PADDING))

    # -- directories --------------------------------------------------------

    def entries(self):
        """[(name bytes, nid, file type)] of a directory, without '.' and
        '..'; '..' is kept apart as `parent`."""
        if not self.is_dir:
            return []
        data = self.read(0, self.size)
        block = self.image.block
        out = []
        self.parent = 0
        for base in range(0, len(data), block):
            chunk = data[base:base + block]
            if len(chunk) < 12:
                break
            first = struct.unpack_from('<H', chunk, 8)[0]
            count = first // 12
            if not count or first > len(chunk):
                break
            rows = [struct.unpack_from('<QHBB', chunk, number * 12)
                    for number in range(count)]
            for number, (nid, name_off, kind, _reserved) in enumerate(rows):
                name_end = rows[number + 1][1] if number + 1 < count \
                    else len(chunk)
                name = chunk[name_off:name_end]
                if number + 1 == count:
                    name = name.split(b'\0', 1)[0]
                if name == b'.':
                    continue
                if name == b'..':
                    self.parent = nid
                    continue
                out.append((name, nid, kind))
        return out


def _bits(raw, base, position, lo_bits):
    """The kernel's decode_compactedbits: (lo, type) at a bit position."""
    value = struct.unpack_from('<I', raw + bytes(4), base + position // 8)[0]
    value >>= position & 7
    return value & ((1 << lo_bits) - 1), (value >> lo_bits) & 3


def _unpack_compacted(raw, at, shift, lcluster_bits, big):
    """One logical cluster's index from its pack (kernel:
    unpack_compacted_index). Returns (record, where its pack ends)."""
    unit = 1 << shift
    if unit == 4 and lcluster_bits <= 14:
        count = 2
    elif unit == 2 and lcluster_bits == 12:
        count = 16
    else:
        raise ErofsError("compact indexes of this cluster size")
    pack = count << shift
    lo_bits = max(lcluster_bits, LI_D0_CBLKCNT.bit_length())
    encode_bits = (pack - 4) * 8 // count
    base = at - at % pack
    index = (at % pack) >> shift
    lo, kind = _bits(raw, base, encode_bits * index, lo_bits)
    if kind == TYPE_NONHEAD:
        record = {'type': kind}
        if lo & LI_D0_CBLKCNT:
            if not big:
                raise ErofsError("a block count without big clusters")
            record['compressedblks'] = lo & ~LI_D0_CBLKCNT
        return record, base + pack
    record = {'type': kind, 'clusterofs': lo}
    # The physical block: the pack's base address, plus the clusters of
    # the heads before this one in the pack.
    i = index
    if not big:
        blocks = 1
        while i > 0:
            i -= 1
            lo, kind = _bits(raw, base, encode_bits * i, lo_bits)
            if kind == TYPE_NONHEAD:
                i -= lo
            if i >= 0:
                blocks += 1
    else:
        blocks = 0
        while i > 0:
            i -= 1
            lo, kind = _bits(raw, base, encode_bits * i, lo_bits)
            if kind == TYPE_NONHEAD:
                if lo & LI_D0_CBLKCNT:
                    i -= 1
                    blocks += lo & ~LI_D0_CBLKCNT
                    continue
                if lo <= 1:
                    raise ErofsError("a big cluster's distance of 1")
                i -= lo - 2
                continue
            blocks += 1
    address = struct.unpack_from('<I', raw, base + pack - 4)[0]
    record['pblk'] = address + blocks
    return record, base + pack


# --- libyal's vocabulary -----------------------------------------------------

class ErofsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, image, nid, name='', parent=0):
        self._image = image
        self._inode = image.inode(nid)
        self.identifier = nid
        self.parent_identifier = parent
        self.name = name
        self.file_mode = self._inode.mode
        self.size = 0 if self._inode.is_dir else self._inode.size
        self.owner_identifier = self._inode.uid
        self.group_identifier = self._inode.gid
        self._children = None

    def get_number_of_links(self):
        return self._inode.nlink

    def get_modification_time_as_integer(self):
        seconds, nanoseconds = self._inode.mtime
        return seconds * 1_000_000_000 + nanoseconds

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._inode.read(0, self._inode.size).decode(
            'utf-8', 'surrogateescape')

    @property
    def compression(self):
        if not self._inode.compressed:
            return None
        return LAYOUT_NAMES[self._inode.layout]

    def _list(self):
        if self._children is None:
            try:
                self._children = self._inode.entries()
            except (ErofsError, struct.error) as exc:
                logger.warning("EROFS directory %d unreadable: %s",
                               self.identifier, exc)
                self._children = []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, nid, _kind = self._list()[index]
        return ErofsEntry(self._image, nid,
                          name.decode('utf-8', 'surrogateescape'),
                          self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._inode.read(offset, length)


class _Volume:
    """libyal's volume vocabulary over an ErofsImage."""

    def __init__(self, image):
        self.image = image
        self._names = None

    def get_root_directory(self):
        return ErofsEntry(self.image, self.image.root_nid)

    def entry(self, nid):
        if nid == self.image.root_nid:
            return self.get_root_directory()
        try:
            self.image.inode(nid)
        except (ErofsError, struct.error):
            return None
        name, parent = self._walked().get(nid, ('', 0))
        return ErofsEntry(self.image, nid, name, parent)

    def _walked(self):
        """{nid: (name, parent nid)}: an inode knows neither."""
        if self._names is None:
            self._names = {}
            pending = [self.image.root_nid]
            seen = set(pending)
            while pending:
                nid = pending.pop()
                inode = self.image.inode(nid)
                for name, child, _kind in inode.entries():
                    self._names.setdefault(child, (name.decode(
                        'utf-8', 'surrogateescape'), nid))
                    if child not in seen and self.image.inode(child).is_dir:
                        seen.add(child)
                        pending.append(child)
        return self._names

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _nid, _kind) in enumerate(entry._list()):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.image._inodes.clear()


class ErofsFileSystem(LibyalFileSystem):
    """An EROFS image, read like a pytsk3.FS_Info."""

    KIND = 'EROFS'

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.block
        super().__init__(_Volume(image), image.block_count * image.block,
                         image.label or 'EROFS image')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return self.image.root_nid

    def _last_identifier(self):
        return self.image.inode_count

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()

    def close(self):
        self.volume.close()


def open_erofs(source):
    """An ErofsFileSystem over `source` (a file object over the
    partition), or None when it is not an EROFS image TRACE can read."""
    try:
        source.seek(0)
        head = source.read(SUPER_OFFSET + 4)
    except (OSError, IOError):
        return None
    if not is_erofs(head):
        return None
    try:
        return ErofsFileSystem(ErofsImage(source))
    except (ErofsError, struct.error, OSError, IOError) as exc:
        logger.warning("EROFS image not opened: %s", exc)
        return None


def is_erofs_fs(fs):
    return isinstance(fs, ErofsFileSystem)

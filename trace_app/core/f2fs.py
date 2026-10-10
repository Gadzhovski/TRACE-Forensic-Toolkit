"""F2FS volumes, read in Python (no Qt).

The Flash-Friendly File System is Android's /data (and some Linux
installs'); The Sleuth Kit does not read it and no library with wheels
does. The layout (include/linux/f2fs_fs.h, fs/f2fs/):

* the superblock at 1 KiB: magic 0xF2F52010, block and segment sizes, and
  where each area starts -- checkpoint, SIT, NAT, SSA, main;
* two checkpoint packs; the valid one with the newer version is current
  (CRC-32 seeded with the magic, the pack's last block repeating its
  version). It holds the version bitmaps that say which of each NAT and SIT
  block's two copies is live, and the summary blocks whose journals carry
  NAT and SIT entries not yet written back -- read after a clean unmount
  too, or recent files are missed;
* the NAT maps a node id to the block holding that node: an inode, or a
  direct / indirect node of block addresses. An inode keeps 923 addresses
  (fewer with extra attributes and inline xattrs), then two direct, two
  indirect and one double-indirect node;
* directories are dentry blocks (214 slots: bitmap, entries, 8-byte name
  slots, a long name over several), or inline in the inode; small files
  are inline data;
* a compressed file (F2FS_COMPR_FL) is clusters of 2^n blocks: a cluster
  whose first address is COMPRESS_ADDR holds the compressed bytes in the
  blocks after it (a 24-byte header, then LZO, LZ4 or zstd); any other is
  stored as is.

Entries speak libyal's vocabulary, so core/libyal_fs presents them like
every other file system. File-based encryption (Android's FBE) is not
decrypted: such names and contents are reported as encrypted. Deleted
files are not listed.
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.F2FS')

MAGIC = 0xF2F52010
SUPER_OFFSET = 1024
BLOCK = 4096

# Checkpoint flags.
CP_COMPACT_SUM = 0x4
CP_LARGE_NAT_BITMAP = 0x400

# Inode.
DEF_ADDRS_PER_INODE = 923
DEF_ADDRS_PER_BLOCK = 1018
NIDS_PER_BLOCK = 1018
DEFAULT_INLINE_XATTR_ADDRS = 50
I_ADDR = 360
I_NID = I_ADDR + DEF_ADDRS_PER_INODE * 4           # 4052
INLINE_XATTR = 0x01
INLINE_DATA = 0x02
INLINE_DENTRY = 0x04
EXTRA_ATTR = 0x20
COMPR_FL = 0x00000004
ENCRYPT_FL = 0x00000800
FEATURE_FLEXIBLE_INLINE_XATTR = 0x40
FEATURE_INODE_CRTIME = 0x100

NULL_ADDR = 0
NEW_ADDR = 0xFFFFFFFF
COMPRESS_ADDR = 0xFFFFFFFE

# Directories.
NR_DENTRY_IN_BLOCK = 214
SLOT_LEN = 8
DIR_ENTRY_SIZE = 11
DENTRY_BITMAP = (NR_DENTRY_IN_BLOCK + 7) // 8      # 27
DENTRY_RESERVED = BLOCK - ((DIR_ENTRY_SIZE + SLOT_LEN) * NR_DENTRY_IN_BLOCK
                           + DENTRY_BITMAP)

# Summaries and journals.
ENTRIES_IN_SUM = 512
SUM_ENTRY_SIZE = 7
SUM_JOURNAL_SIZE = BLOCK - 5 - SUM_ENTRY_SIZE * ENTRIES_IN_SUM   # 507
NAT_ENTRY_SIZE = 9
NAT_ENTRIES_PER_BLOCK = BLOCK // NAT_ENTRY_SIZE                  # 455
NAT_JOURNAL_ENTRY = 4 + NAT_ENTRY_SIZE
SIT_ENTRY_SIZE = 74
SIT_ENTRIES_PER_BLOCK = BLOCK // SIT_ENTRY_SIZE                  # 55
SIT_JOURNAL_ENTRY = 4 + SIT_ENTRY_SIZE

COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_ZSTD, COMPRESS_LZORLE = 0, 1, 2, 3
COMPRESSION_NAMES = {0: 'LZO', 1: 'LZ4', 2: 'zstd', 3: 'LZO-RLE'}
COMPRESS_HEADER = 24

#: Inode modes by dentry file type (for an entry whose inode is gone).
_FILE_TYPES = {1: stat.S_IFREG, 2: stat.S_IFDIR, 3: stat.S_IFCHR,
               4: stat.S_IFBLK, 5: stat.S_IFIFO, 6: stat.S_IFSOCK,
               7: stat.S_IFLNK}


class F2fsError(Exception):
    """The volume cannot be read, and why."""


def crc32(data, seed=MAGIC):
    """F2FS's CRC-32: the kernel's crc32_le seeded with the magic (no
    inversion before or after)."""
    return zlib.crc32(data, seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def _test_bit(bitmap, number):
    """f2fs_test_bit: big-endian bit order within each byte."""
    return bool(bitmap[number >> 3] & (0x80 >> (number & 7)))


def _test_bit_le(bitmap, number):
    return bool(bitmap[number >> 3] & (1 << (number & 7)))


def is_f2fs(head):
    """Whether `head` (the first 2 KiB of a volume) holds an F2FS
    superblock."""
    return len(head) >= SUPER_OFFSET + 4 and struct.unpack_from(
        '<I', head, SUPER_OFFSET)[0] == MAGIC


class F2fsVolume:
    """The superblock, current checkpoint, NAT and SIT of one volume."""

    def __init__(self, source):
        self.source = source
        self._nat_blocks = {}
        self._nodes = {}
        sb = self.read(SUPER_OFFSET, BLOCK - SUPER_OFFSET)
        if len(sb) < 2200 or struct.unpack_from('<I', sb, 0)[0] != MAGIC:
            raise F2fsError("No F2FS superblock")
        (self.major, self.minor, _log_sector, _log_sectors_per_block,
         log_block, self.log_blocks_per_seg) = struct.unpack_from(
            '<HHIIII', sb, 4)
        if log_block != 12:
            raise F2fsError(f"Block size 2^{log_block} is not supported")
        self.blocks_per_seg = 1 << self.log_blocks_per_seg
        self.block_count = struct.unpack_from('<Q', sb, 36)[0]
        (_sections, self.segment_count, segment_count_ckpt,
         self.segment_count_sit, self.segment_count_nat, _ssa,
         self.segment_count_main, _seg0, self.cp_blkaddr,
         self.sit_blkaddr, self.nat_blkaddr, self.ssa_blkaddr,
         self.main_blkaddr, self.root_ino, _node_ino,
         _meta_ino) = struct.unpack_from('<16I', sb, 44)
        self.label = sb[124:124 + 1024].decode('utf-16-le', 'replace') \
            .split('\0', 1)[0].strip()
        self.cp_payload = struct.unpack_from('<I', sb, 1664)[0]
        self.feature = struct.unpack_from('<I', sb, 2180)[0]
        self._checkpoint()

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def block(self, address):
        return self.read(address * BLOCK, BLOCK)

    # --- checkpoint ---------------------------------------------------------

    def _pack(self, start):
        """The checkpoint pack at block `start`, or None when invalid."""
        head = self.block(start)
        if len(head) < BLOCK:
            return None
        offset = struct.unpack_from('<I', head, 164)[0]
        if offset < 192 or offset > BLOCK - 4 or \
                crc32(head[:offset]) != struct.unpack_from('<I', head,
                                                           offset)[0]:
            return None
        version = struct.unpack_from('<Q', head, 0)[0]
        total = struct.unpack_from('<I', head, 136)[0]
        if not 1 <= total <= self.blocks_per_seg:
            return None
        tail = self.block(start + total - 1)
        tail_offset = struct.unpack_from('<I', tail, 164)[0]
        if tail_offset != offset or crc32(tail[:offset]) != \
                struct.unpack_from('<I', tail, offset)[0] or \
                struct.unpack_from('<Q', tail, 0)[0] != version:
            return None
        return version, start, head

    def _checkpoint(self):
        packs = [p for p in (self._pack(self.cp_blkaddr),
                             self._pack(self.cp_blkaddr +
                                        self.blocks_per_seg)) if p]
        if not packs:
            raise F2fsError("No valid checkpoint")
        # The newer version (wrapping compare, as ver_after does); the
        # first pack when equal.
        current = packs[0]
        for pack in packs[1:]:
            if ((pack[0] - current[0]) & (1 << 63)) == 0 and \
                    pack[0] != current[0]:
                current = pack
        self.cp_version, self.cp_start, cp = current
        self.cp_flags = struct.unpack_from('<I', cp, 132)[0]
        start_sum = struct.unpack_from('<I', cp, 140)[0]
        sit_bytes, nat_bytes = struct.unpack_from('<II', cp, 156)
        # __bitmap_ptr
        if self.cp_flags & CP_LARGE_NAT_BITMAP:
            base = 192 + 4
            self.nat_bitmap = cp[base:base + nat_bytes]
            self.sit_bitmap = cp[base + nat_bytes:base + nat_bytes +
                                 sit_bytes]
        elif self.cp_payload:
            self.nat_bitmap = cp[192:192 + nat_bytes]
            payload = b''.join(self.block(self.cp_start + 1 + index)
                               for index in range(self.cp_payload))
            self.sit_bitmap = payload[:sit_bytes]
        else:
            self.sit_bitmap = cp[192:192 + sit_bytes]
            self.nat_bitmap = cp[192 + sit_bytes:192 + sit_bytes +
                                 nat_bytes]
        self.valid_inodes = struct.unpack_from('<I', cp, 148)[0]
        self._journals(self.cp_start + start_sum)

    def _journals(self, address):
        """The NAT and SIT entries the current checkpoint's summaries
        carry (newer than the NAT and SIT blocks)."""
        self.nat_journal = {}
        self.sit_journal = {}
        if self.cp_flags & CP_COMPACT_SUM:
            data = self.block(address)
            nat = data[:SUM_JOURNAL_SIZE]
            sit = data[SUM_JOURNAL_SIZE:2 * SUM_JOURNAL_SIZE]
        else:
            journal = SUM_ENTRY_SIZE * ENTRIES_IN_SUM
            # Hot data's summary carries the NAT journal, cold data's the
            # SIT journal.
            nat = self.block(address)[journal:journal + SUM_JOURNAL_SIZE]
            sit = self.block(address + 2)[journal:journal + SUM_JOURNAL_SIZE]
        count = struct.unpack_from('<H', nat, 0)[0]
        for index in range(min(count, (SUM_JOURNAL_SIZE - 2) //
                               NAT_JOURNAL_ENTRY)):
            nid, _version, ino, address_ = struct.unpack_from(
                '<IBII', nat, 2 + index * NAT_JOURNAL_ENTRY)
            self.nat_journal[nid] = (ino, address_)
        count = struct.unpack_from('<H', sit, 0)[0]
        for index in range(min(count, (SUM_JOURNAL_SIZE - 2) //
                               SIT_JOURNAL_ENTRY)):
            offset = 2 + index * SIT_JOURNAL_ENTRY
            segno = struct.unpack_from('<I', sit, offset)[0]
            self.sit_journal[segno] = sit[offset + 4:offset + 4 +
                                          SIT_ENTRY_SIZE]

    # --- NAT and nodes -------------------------------------------------------

    def _nat_block(self, number):
        if number not in self._nat_blocks:
            segment = number >> self.log_blocks_per_seg
            address = self.nat_blkaddr + \
                (segment << self.log_blocks_per_seg << 1) + \
                (number & (self.blocks_per_seg - 1))
            if _test_bit(self.nat_bitmap, number):
                address += self.blocks_per_seg
            self._nat_blocks[number] = self.block(address)
        return self._nat_blocks[number]

    def node_address(self, nid):
        """The block a node id lives in (0: none)."""
        if nid in self.nat_journal:
            return self.nat_journal[nid][1]
        data = self._nat_block(nid // NAT_ENTRIES_PER_BLOCK)
        offset = (nid % NAT_ENTRIES_PER_BLOCK) * NAT_ENTRY_SIZE
        _version, _ino, address = struct.unpack_from('<BII', data, offset)
        return address

    def node(self, nid):
        """The node block of `nid`, or None. Its footer must name it."""
        if nid in self._nodes:
            return self._nodes[nid]
        address = self.node_address(nid)
        data = None
        if address not in (NULL_ADDR, NEW_ADDR) and \
                self.main_blkaddr <= address < self.block_count:
            block = self.block(address)
            if len(block) == BLOCK and \
                    struct.unpack_from('<I', block, BLOCK - 24)[0] == nid:
                data = block
        if len(self._nodes) > 4096:
            self._nodes.clear()
        self._nodes[nid] = data
        return data

    def inode(self, nid):
        block = self.node(nid)
        if block is None or struct.unpack_from('<I', block,
                                               BLOCK - 20)[0] != nid:
            return None                       # not an inode block
        return Inode(self, nid, block)

    # --- SIT: which blocks are in use ---------------------------------------

    def _sit_entry(self, segno):
        if segno in self.sit_journal:
            return self.sit_journal[segno]
        number = segno // SIT_ENTRIES_PER_BLOCK
        address = self.sit_blkaddr + number
        if _test_bit(self.sit_bitmap, number):
            address += (self.segment_count_sit >> 1) << \
                self.log_blocks_per_seg
        data = self.block(address)
        offset = (segno % SIT_ENTRIES_PER_BLOCK) * SIT_ENTRY_SIZE
        return data[offset:offset + SIT_ENTRY_SIZE]

    def allocated_ranges(self):
        """(begin, end) byte ranges in use: the metadata areas, and every
        main-area block the SIT marks valid."""
        out = [(0, self.main_blkaddr * BLOCK)]
        for segno in range(self.segment_count_main):
            entry = self._sit_entry(segno)
            if len(entry) < SIT_ENTRY_SIZE or \
                    not struct.unpack_from('<H', entry, 0)[0] & 0x3FF:
                continue
            valid = entry[2:66]
            first = self.main_blkaddr + segno * self.blocks_per_seg
            run = None
            for index in range(self.blocks_per_seg):
                if _test_bit(valid, index):
                    if run is None:
                        run = index
                elif run is not None:
                    out.append(((first + run) * BLOCK,
                                (first + index) * BLOCK))
                    run = None
            if run is not None:
                out.append(((first + run) * BLOCK,
                            (first + self.blocks_per_seg) * BLOCK))
        return out


class Inode:
    """One inode: its fields, and its data by block."""

    def __init__(self, volume, nid, block):
        self.volume = volume
        self.nid = nid
        self.block = block
        (self.mode, _advise, self.inline, self.uid, self.gid, self.links,
         self.size, _blocks, atime, ctime, mtime, atime_ns, ctime_ns,
         mtime_ns, _generation, self.depth, _xattr_nid, self.flags,
         self.pino, namelen) = struct.unpack_from(
            '<HBBIIIQQQQQIIIIIIIII', block, 0)
        self.name = block[92:92 + min(namelen, 255)]
        self.times = {'access': (atime, atime_ns),
                      'inode_change': (ctime, ctime_ns),
                      'modification': (mtime, mtime_ns), 'creation': (0, 0)}
        self.extra = 0                        # in 32-bit words
        self.compress_algorithm = None
        self.cluster_log = 0
        if self.inline & EXTRA_ATTR:
            extra_isize, inline_xattr = struct.unpack_from('<HH', block,
                                                           I_ADDR)
            self.extra = extra_isize // 4
            if volume.feature & FEATURE_INODE_CRTIME and extra_isize >= 20:
                crtime, crtime_ns = struct.unpack_from('<QI', block, 372)
                self.times['creation'] = (crtime, crtime_ns)
            if self.flags & COMPR_FL and extra_isize >= 36:
                self.compress_algorithm = block[392]
                self.cluster_log = block[393]
        else:
            inline_xattr = 0
        if self.inline & INLINE_XATTR:
            self.xattr_addrs = inline_xattr if volume.feature & \
                FEATURE_FLEXIBLE_INLINE_XATTR else DEFAULT_INLINE_XATTR_ADDRS
        else:
            self.xattr_addrs = 0
        cluster = 1 << self.cluster_log if self.compressed else 1
        addrs = DEF_ADDRS_PER_INODE - self.extra - self.xattr_addrs
        self.addrs_in_inode = addrs - addrs % cluster
        self.addrs_per_block = DEF_ADDRS_PER_BLOCK - \
            DEF_ADDRS_PER_BLOCK % cluster
        self.nids = struct.unpack_from('<5I', block, I_NID)

    @property
    def compressed(self):
        return bool(self.flags & COMPR_FL)

    @property
    def encrypted(self):
        return bool(self.flags & ENCRYPT_FL)

    @property
    def max_inline(self):
        return 4 * (DEF_ADDRS_PER_INODE - self.extra - self.xattr_addrs - 1)

    def inline_area(self):
        start = I_ADDR + 4 * (self.extra + 1)
        return self.block[start:start + self.max_inline]

    # --- block addresses -----------------------------------------------------

    def _addr(self, block, index):
        return struct.unpack_from('<I', block, index * 4)[0]

    def address(self, index):
        """The block address of the file's block `index` (NULL_ADDR for a
        hole)."""
        if index < self.addrs_in_inode:
            return struct.unpack_from(
                '<I', self.block, I_ADDR + 4 * (self.extra + index))[0]
        index -= self.addrs_in_inode
        per = self.addrs_per_block
        volume = self.volume
        for slot in (0, 1):                       # direct nodes
            if index < per:
                node = volume.node(self.nids[slot])
                return self._addr(node, index) if node else NULL_ADDR
            index -= per
        for slot in (2, 3):                       # indirect nodes
            if index < per * NIDS_PER_BLOCK:
                outer = volume.node(self.nids[slot])
                if outer is None:
                    return NULL_ADDR
                node = volume.node(self._addr(outer, index // per))
                return self._addr(node, index % per) if node else NULL_ADDR
            index -= per * NIDS_PER_BLOCK
        span = per * NIDS_PER_BLOCK               # double indirect
        if index < span * NIDS_PER_BLOCK:
            top = volume.node(self.nids[4])
            if top is None:
                return NULL_ADDR
            middle = volume.node(self._addr(top, index // span))
            if middle is None:
                return NULL_ADDR
            node = volume.node(self._addr(middle, index % span // per))
            return self._addr(node, index % per) if node else NULL_ADDR
        return NULL_ADDR

    # --- data -----------------------------------------------------------------

    def read(self, offset, length):
        size = self.size
        if offset >= size or length <= 0:
            return b''
        length = min(length, size - offset)
        if self.inline & INLINE_DATA:
            return bytes(self.inline_area()[offset:offset + length]).ljust(
                length, b'\0')
        if self.compressed:
            return self._read_compressed(offset, length)
        out = bytearray()
        first = offset // BLOCK
        last = (offset + length - 1) // BLOCK
        for index in range(first, last + 1):
            out += self._plain_block(index)
        skip = offset - first * BLOCK
        return bytes(out[skip:skip + length])

    def _plain_block(self, index):
        address = self.address(index)
        if address in (NULL_ADDR, NEW_ADDR, COMPRESS_ADDR) or \
                not self.volume.main_blkaddr <= address < \
                self.volume.block_count:
            return bytes(BLOCK)
        return self.volume.block(address).ljust(BLOCK, b'\0')

    def _read_compressed(self, offset, length):
        cluster = 1 << self.cluster_log
        span = cluster * BLOCK
        out = bytearray()
        first = offset // span
        last = (offset + length - 1) // span
        for number in range(first, last + 1):
            out += self._cluster(number, cluster)
        skip = offset - first * span
        return bytes(out[skip:skip + length])

    def _cluster(self, number, cluster):
        base = number * cluster
        if self.address(base) != COMPRESS_ADDR:
            return b''.join(self._plain_block(base + index)
                            for index in range(cluster))
        stored = []
        for index in range(1, cluster):
            address = self.address(base + index)
            if address in (NULL_ADDR, NEW_ADDR, COMPRESS_ADDR):
                break
            stored.append(self.volume.block(address))
        data = b''.join(stored)
        if len(data) < COMPRESS_HEADER:
            raise F2fsError(f"inode {self.nid}: cluster {number} damaged")
        clen = struct.unpack_from('<I', data, 0)[0]
        payload = data[COMPRESS_HEADER:COMPRESS_HEADER + clen]
        plain = decompress(self.compress_algorithm, payload, cluster * BLOCK)
        return plain.ljust(cluster * BLOCK, b'\0')[:cluster * BLOCK]

    # --- directories ----------------------------------------------------------

    def entries(self):
        """[(name bytes, nid, file type)] of a directory, '.' and '..'
        left out."""
        out = []
        if self.inline & INLINE_DENTRY:
            area = self.inline_area()
            count = len(area) * 8 // ((DIR_ENTRY_SIZE + SLOT_LEN) * 8 + 1)
            bitmap_size = (count + 7) // 8
            reserved = len(area) - ((DIR_ENTRY_SIZE + SLOT_LEN) * count +
                                    bitmap_size)
            entries = bitmap_size + reserved
            names = entries + DIR_ENTRY_SIZE * count
            _dentries(area, count, 0, entries, names, out)
        else:
            blocks = (self.size + BLOCK - 1) // BLOCK
            for index in range(blocks):
                address = self.address(index)
                if address in (NULL_ADDR, NEW_ADDR):
                    continue
                block = self.volume.block(address)
                entries = DENTRY_BITMAP + DENTRY_RESERVED
                names = entries + DIR_ENTRY_SIZE * NR_DENTRY_IN_BLOCK
                _dentries(block, NR_DENTRY_IN_BLOCK, 0, entries, names, out)
        return [entry for entry in out if entry[0] not in (b'.', b'..')]


def _dentries(data, count, bitmap, entries, names, out):
    position = 0
    while position < count:
        if not _test_bit_le(data[bitmap:], position):
            position += 1
            continue
        _hash, nid, name_len, file_type = struct.unpack_from(
            '<IIHB', data, entries + position * DIR_ENTRY_SIZE)
        slots = max(1, (name_len + SLOT_LEN - 1) // SLOT_LEN)
        if name_len and nid:
            start = names + position * SLOT_LEN
            out.append((bytes(data[start:start + name_len]), nid,
                        file_type))
        position += slots


def decompress(algorithm, data, size):
    """One cluster's bytes."""
    if algorithm == COMPRESS_LZ4:
        from trace_app.core.activity.journal import lz4_block
        return bytes(lz4_block(data, size))
    if algorithm == COMPRESS_LZO:
        from trace_app.core.btrfs import lzo1x_decompress
        return bytes(lzo1x_decompress(data, size))
    if algorithm == COMPRESS_ZSTD:
        from trace_app.core.zstd_decode import decompress_frame
        return bytes(decompress_frame(data))
    raise F2fsError(f"{COMPRESSION_NAMES.get(algorithm, algorithm)} "
                    f"compression is not supported")


# --- libyal's vocabulary -----------------------------------------------------

def _display_name(name, encrypted):
    if encrypted:
        # FBE: the stored name is ciphertext, shown as such.
        return f"[encrypted] {name.hex()[:32]}"
    return name.decode('utf-8', 'surrogateescape')


class F2fsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, nid, name='', parent=0, file_type=0,
                 encrypted_name=False):
        self._volume = volume
        self.identifier = nid
        self.parent_identifier = parent
        self._inode = volume.inode(nid)
        self.name = name
        self._children = None
        inode = self._inode
        if inode is None:
            self.file_mode = _FILE_TYPES.get(file_type, stat.S_IFREG)
            self.size = 0
            self.owner_identifier = self.group_identifier = 0
            self.encrypted = False
        else:
            self.file_mode = inode.mode
            self.size = inode.size if not stat.S_ISDIR(inode.mode) else 0
            self.owner_identifier = inode.uid
            self.group_identifier = inode.gid
            self.encrypted = inode.encrypted
        self.name_encrypted = encrypted_name

    def get_number_of_links(self):
        return self._inode.links if self._inode else 1

    def _time(self, which):
        if self._inode is None:
            return 0
        seconds, nanoseconds = self._inode.times[which]
        if not seconds and not nanoseconds:
            return 0
        return seconds * 1_000_000_000 + nanoseconds

    def get_access_time_as_integer(self):
        return self._time('access')

    def get_inode_change_time_as_integer(self):
        return self._time('inode_change')

    def get_modification_time_as_integer(self):
        return self._time('modification')

    def get_creation_time_as_integer(self):
        return self._time('creation')

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode) or self._inode is None:
            return ''
        data = self._inode.read(0, min(self._inode.size, BLOCK))
        if self.encrypted:
            return f"[encrypted] {data.hex()[:32]}"
        return data.decode('utf-8', 'surrogateescape')

    @property
    def compression(self):
        inode = self._inode
        if inode is None or not inode.compressed:
            return None
        return COMPRESSION_NAMES.get(inode.compress_algorithm,
                                     inode.compress_algorithm)

    def _list(self):
        if self._children is None:
            self._children = []
            if self._inode is not None and stat.S_ISDIR(self.file_mode):
                try:
                    self._children = self._inode.entries()
                except (F2fsError, struct.error) as exc:
                    logger.warning("F2FS directory %d unreadable: %s",
                                   self.identifier, exc)
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, nid, file_type = self._list()[index]
        return F2fsEntry(self._volume, nid,
                         _display_name(name, self.encrypted), self.identifier,
                         file_type, self.encrypted)

    def read_buffer_at_offset(self, length, offset):
        if self._inode is None:
            return b''
        return self._inode.read(offset, length)


class _Volume:
    """libyal's volume vocabulary over an F2fsVolume."""

    def __init__(self, volume):
        self.f2fs = volume
        self.label = volume.label

    def get_root_directory(self):
        return F2fsEntry(self.f2fs, self.f2fs.root_ino, '', 0)

    def entry(self, nid):
        inode = self.f2fs.inode(nid)
        if inode is None:
            return None
        if nid == self.f2fs.root_ino:
            return self.get_root_directory()
        parent = self.f2fs.inode(inode.pino)
        return F2fsEntry(self.f2fs, nid,
                         _display_name(inode.name, bool(
                             parent and parent.encrypted)),
                         inode.pino)

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _nid, _type) in enumerate(entry._list()):
                if _display_name(name, entry.encrypted) == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.f2fs._nodes.clear()
        self.f2fs._nat_blocks.clear()


class F2fsFileSystem(LibyalFileSystem):
    """An F2FS volume, read like a pytsk3.FS_Info."""

    KIND = 'F2FS'

    def __init__(self, volume):
        self.f2fs = volume
        super().__init__(_Volume(volume), volume.block_count * BLOCK,
                         volume.label or 'F2FS volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return self.f2fs.root_ino

    def _last_identifier(self):
        return self.f2fs.valid_inodes

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.f2fs.allocated_ranges()

    def close(self):
        self.volume.close()


def open_f2fs(source):
    """An F2fsFileSystem over `source` (a file object over the partition),
    or None when it is not an F2FS volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(SUPER_OFFSET + 8)
    except (OSError, IOError):
        return None
    if not is_f2fs(head):
        return None
    try:
        return F2fsFileSystem(F2fsVolume(source))
    except (F2fsError, struct.error, OSError, IOError) as exc:
        logger.warning("F2FS volume not opened: %s", exc)
        return None


def is_f2fs_fs(fs):
    return isinstance(fs, F2fsFileSystem)

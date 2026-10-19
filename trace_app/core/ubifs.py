"""UBIFS (the file system of UBI volumes on raw flash), read in Python (no
Qt).

The Sleuth Kit and libyal do not read UBIFS. A UBIFS volume is a run of
logical erase blocks (LEBs) -- a UBI volume (core/ubi.py), or a bare image
mkfs.ubifs wrote -- of nodes (fs/ubifs/ubifs-media.h, little-endian):

* every node starts with a 24-byte common header: magic 0x06101831, CRC of
  the rest of the node (UBI's: zlib's crc32 ^ ~0), sequence number,
  length, node type; nodes are 8-byte aligned, padding nodes and 0xCE fill
  between them;
* LEB 0 holds the superblock (LEB size, count, log and LPT sizes, key
  format, default compressor, flags); LEBs 1 and 2 the master node, written
  again at every commit -- the last valid one of LEB 1 (else 2) is current;
  it gives the index root and where the log starts;
* the index is a B+ tree of index nodes (child count, level; branches of
  LEB, offset, length and an 8-byte key), whose level-0 branches point at
  the leaf nodes: inodes (attributes, inline symlink target), directory
  entries (parent's key, name, the child's inode number, its type) and data
  nodes (one 4 KiB block of a file, compressed by none / LZO / zlib (raw
  deflate) / zstd);
* nodes written since the last commit are not in the index: the log (LEBs
  from 3) holds a commit-start node and reference nodes naming the buds --
  LEBs the journal heads wrote -- and those are replayed in sequence-number
  order over the index: a newer node replaces the indexed one with its key,
  a directory entry whose inode number is 0 removes the name, an inode with
  no links removes the inode, a truncation node drops the blocks past the
  new size.

A key is (inode number: 32 bits; type: 3 bits; block number or the name's
hash: 29 bits). Entries speak libyal's vocabulary, so core/libyal_fs
presents them like every other file system. Identifiers are inode numbers.
Encrypted (fscrypt) names and data are shown as stored and said to be
encrypted; authenticated volumes (HMAC) are read without checking the HMAC.
Deleted files are not listed.
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup
from trace_app.core.ubi import crc32

logger = logging.getLogger('TRACE.UBIFS')

MAGIC = b'\x31\x18\x10\x06'
CH = 24
ALIGN = 8
BLOCK = 4096
ROOT = 1

(INO_NODE, DATA_NODE, DENT_NODE, XENT_NODE, TRUN_NODE, PAD_NODE, SB_NODE,
 MST_NODE, REF_NODE, IDX_NODE, CS_NODE, ORPH_NODE, AUTH_NODE,
 SIG_NODE) = range(14)
INO_KEY, DATA_KEY, DENT_KEY, XENT_KEY = range(4)
LOG_LNUM = 3

COMPR_NONE, COMPR_LZO, COMPR_ZLIB, COMPR_ZSTD = range(4)
COMPRESSION_NAMES = {COMPR_NONE: 'none', COMPR_LZO: 'LZO',
                     COMPR_ZLIB: 'zlib', COMPR_ZSTD: 'zstd'}

FLG_ENCRYPTION = 0x10
FLG_AUTHENTICATION = 0x20
CRYPT_FL = 0x40

#: Directory entry types -> stat file type bits.
_ITYPE = {0: stat.S_IFREG, 1: stat.S_IFDIR, 2: stat.S_IFLNK, 3: stat.S_IFBLK,
          4: stat.S_IFCHR, 5: stat.S_IFIFO, 6: stat.S_IFSOCK}

#: Hash lengths of the authentication algorithms (by the kernel's
#: hash_algo, HASH_ALGO_*): each index branch carries one.
_HASH_LENGTHS = {0: 16, 1: 20, 2: 20, 3: 32, 4: 48, 5: 64, 6: 28, 7: 32,
                 8: 64, 9: 20, 10: 28, 11: 32, 12: 48, 13: 64}


class UbifsError(Exception):
    pass


def is_ubifs(head):
    """Whether `head` (the volume's start) is a UBIFS superblock node."""
    return len(head) >= CH and head[:4] == MAGIC and head[20] == SB_NODE


def _key(data, offset):
    """(inode, type, block or hash) of an 8-byte simple key."""
    inum, second = struct.unpack_from('<II', data, offset)
    return inum, second >> 29, second & 0x1FFFFFFF


def decompress(method, data, size):
    try:
        if method == COMPR_NONE:
            return bytes(data[:size])
        if method == COMPR_ZLIB:
            return zlib.decompress(bytes(data), -15)[:size]
        if method == COMPR_LZO:
            from trace_app.core.btrfs import lzo1x_decompress
            return bytes(lzo1x_decompress(bytes(data), size))[:size]
        if method == COMPR_ZSTD:
            from trace_app.core import zstd_decode
            return bytes(zstd_decode.decompress_frame(bytes(data),
                                                      size))[:size]
    except Exception as exc:      # every decompressor's own errors
        raise UbifsError(f"{COMPRESSION_NAMES.get(method)} block does not "
                         f"decompress: {exc}") from exc
    raise UbifsError(f"compression {method} is not read")


class UbifsVolume:
    """The live nodes of a UBIFS volume read through `source` (a file
    object over its LEBs end to end)."""

    def __init__(self, source):
        self._source = source
        sb = self._node_at(0, 0)
        if sb is None or sb[20] != SB_NODE:
            raise UbifsError("no UBIFS superblock")
        (self.key_hash, self.key_fmt, self.flags, self.min_io,
         self.leb_size, self.leb_count, self.max_leb_count) = \
            struct.unpack_from('<BBIIIII', sb, 26)
        (self.log_lebs, self.lpt_lebs, self.orph_lebs, _jheads,
         self.fanout, _lsave, self.fmt_version, self.default_compr) = \
            struct.unpack_from('<IIIIIIIH', sb, 56)
        self.uuid = sb[108:124]
        self.hash_len = 0
        if self.flags & FLG_AUTHENTICATION:
            algo, = struct.unpack_from('<H', sb, 256)
            self.hash_len = _HASH_LENGTHS.get(algo, 32)
        if self.key_fmt != 0:
            raise UbifsError(f"key format {self.key_fmt} is not read")
        self.encrypted = bool(self.flags & FLG_ENCRYPTION)
        self.size = self.leb_size * self.leb_count
        self.master = self._master()
        # (inode) -> (sqnum, fields); (parent, name) -> (sqnum, inum, type);
        # (inode, block) -> (sqnum, lnum, offs, len)
        self.inodes = {}
        self.dents = {}
        self.blocks = {}
        self.used = set()            # LEBs holding live nodes or the index
        self._walk_index()
        self._replay()

    # --- reading -----------------------------------------------------------

    def read(self, offset, length):
        self._source.seek(offset)
        return self._source.read(length)

    def leb(self, lnum):
        return self.read(lnum * self.leb_size, self.leb_size)

    def _node_at(self, lnum, offs, length=None):
        """The node at (lnum, offs), its CRC checked, or None. LEB 0 is
        read before the LEB size is known (the superblock tells it)."""
        base = (lnum * self.leb_size if lnum else 0) + offs
        head = self.read(base, CH)
        if len(head) < CH or head[:4] != MAGIC:
            return None
        node_len, = struct.unpack_from('<I', head, 16)
        if node_len < CH or (length is not None and node_len != length):
            return None
        node = self.read(base, node_len)
        if len(node) < node_len or                 crc32(node[8:]) != struct.unpack_from('<I', node, 4)[0]:
            return None
        return node

    def _scan_leb(self, lnum, start=0):
        """[(offs, node)] of the valid nodes of LEB `lnum` from `start`, up
        to the first gap that is not padding."""
        data = self.leb(lnum)
        out = []
        offs = start
        while offs + CH <= len(data):
            if data[offs:offs + 4] != MAGIC:
                if data[offs] == 0xCE:          # padding bytes
                    offs = (offs + ALIGN) & ~(ALIGN - 1)
                    continue
                break
            node_len, = struct.unpack_from('<I', data, offs + 16)
            if node_len < CH or offs + node_len > len(data):
                break
            node = data[offs:offs + node_len]
            if crc32(node[8:]) != struct.unpack_from('<I', node, 4)[0]:
                break
            if node[20] == PAD_NODE:
                pad, = struct.unpack_from('<I', node, CH)
                offs += node_len + pad
            else:
                out.append((offs, node))
                offs += node_len
            offs = (offs + ALIGN - 1) & ~(ALIGN - 1)
        return out

    def _master(self):
        for lnum in (1, 2):
            nodes = [node for _offs, node in self._scan_leb(lnum)
                     if node[20] == MST_NODE]
            if nodes:
                node = max(nodes, key=lambda n: struct.unpack_from(
                    '<Q', n, 8)[0])
                (highest_inum, cmt_no, flags, log_lnum, root_lnum,
                 root_offs, root_len) = struct.unpack_from('<QQIIIII',
                                                           node, 24)
                return {'highest_inum': highest_inum, 'cmt_no': cmt_no,
                        'flags': flags, 'log_lnum': log_lnum,
                        'root': (root_lnum, root_offs, root_len)}
        raise UbifsError("no valid master node")

    # --- the index ---------------------------------------------------------

    def _walk_index(self):
        branch = 12 + 8 + self.hash_len
        pending = [self.master['root']]
        seen = set()
        while pending:
            lnum, offs, length = pending.pop()
            if (lnum, offs) in seen:
                continue
            seen.add((lnum, offs))
            node = self._node_at(lnum, offs, length)
            if node is None:
                logger.warning("UBIFS node at LEB %d:%d unreadable", lnum,
                               offs)
                continue
            self.used.add(lnum)
            if node[20] != IDX_NODE:
                self._leaf(node, lnum, offs, replay=False)
                continue
            count, level = struct.unpack_from('<HH', node, CH)
            for index in range(count):
                at = CH + 4 + index * branch
                child = struct.unpack_from('<III', node, at)
                if level > 0:
                    pending.append(child)
                else:
                    leaf = self._node_at(*child)
                    if leaf is None:
                        logger.warning("UBIFS leaf at LEB %d:%d unreadable",
                                       child[0], child[1])
                        continue
                    self.used.add(child[0])
                    self._leaf(leaf, child[0], child[1], replay=False)

    def _leaf(self, node, lnum, offs, replay):
        kind = node[20]
        sqnum, = struct.unpack_from('<Q', node, 8)
        if kind == INO_NODE:
            inum, _t, _x = _key(node, CH)
            fields = self._inode_fields(node)
            old = self.inodes.get(inum)
            if old is not None and old[0] > sqnum:
                return
            if replay and fields['nlink'] == 0:
                self._forget(inum)
                return
            self.inodes[inum] = (sqnum, fields)
        elif kind in (DENT_NODE, XENT_NODE):
            parent, _t, _hash = _key(node, CH)
            inum, = struct.unpack_from('<Q', node, 40)
            dtype = node[49]
            nlen, = struct.unpack_from('<H', node, 50)
            name = bytes(node[56:56 + nlen])
            if kind == XENT_NODE:
                return                              # extended attributes
            entry = (parent, name)
            old = self.dents.get(entry)
            if old is not None and old[0] > sqnum:
                return
            if inum == 0:
                self.dents.pop(entry, None)
            else:
                self.dents[entry] = (sqnum, inum, dtype)
        elif kind == DATA_NODE:
            inum, _t, block = _key(node, CH)
            old = self.blocks.get((inum, block))
            if old is not None and old[0] > sqnum:
                return
            self.blocks[(inum, block)] = (sqnum, lnum, offs, len(node))
        elif kind == TRUN_NODE and replay:
            inum, = struct.unpack_from('<I', node, CH)
            new_size, = struct.unpack_from('<Q', node, CH + 24)
            first = (new_size + BLOCK - 1) // BLOCK
            for key in [k for k in self.blocks
                        if k[0] == inum and k[1] >= first]:
                if self.blocks[key][0] < sqnum:
                    del self.blocks[key]

    def _forget(self, inum):
        self.inodes.pop(inum, None)
        for key in [k for k in self.blocks if k[0] == inum]:
            del self.blocks[key]

    @staticmethod
    def _inode_fields(node):
        (creat_sqnum, size, atime, ctime, mtime, atime_ns, ctime_ns,
         mtime_ns, nlink, uid, gid, mode, flags, data_len) = \
            struct.unpack_from('<QQQQQIIIIIIIII', node, 40)
        compr, = struct.unpack_from('<H', node, 132)
        return {'size': size, 'atime': atime * 10**9 + atime_ns,
                'ctime': ctime * 10**9 + ctime_ns,
                'mtime': mtime * 10**9 + mtime_ns, 'nlink': nlink,
                'uid': uid, 'gid': gid, 'mode': mode, 'flags': flags,
                'compr': compr, 'data': bytes(node[160:160 + data_len]),
                'creat_sqnum': creat_sqnum}

    # --- the journal --------------------------------------------------------

    def _replay(self):
        """Nodes written since the last commit, from the buds the log names,
        in sequence-number order."""
        refs = []
        commit = None
        for lnum in range(LOG_LNUM, LOG_LNUM + self.log_lebs):
            for _offs, node in self._scan_leb(lnum):
                sqnum, = struct.unpack_from('<Q', node, 8)
                if node[20] == CS_NODE:
                    cmt_no, = struct.unpack_from('<Q', node, CH)
                    if cmt_no == self.master['cmt_no']:
                        commit = sqnum
                elif node[20] == REF_NODE:
                    bud_lnum, bud_offs = struct.unpack_from('<II', node, CH)
                    refs.append((sqnum, bud_lnum, bud_offs))
        if commit is None:
            return
        nodes = []
        for sqnum, lnum, offs in refs:
            if sqnum < commit or not 0 <= lnum < self.leb_count:
                continue
            for at, node in self._scan_leb(lnum, offs):
                self.used.add(lnum)
                nodes.append((struct.unpack_from('<Q', node, 8)[0], lnum, at,
                              node))
        nodes.sort(key=lambda n: n[0])
        for _sqnum, lnum, at, node in nodes:
            if node[20] in (INO_NODE, DENT_NODE, XENT_NODE, DATA_NODE,
                            TRUN_NODE):
                self._leaf(node, lnum, at, replay=True)
        if nodes:
            logger.info("UBIFS: %d journal nodes replayed", len(nodes))

    # --- files ----------------------------------------------------------------

    def children(self, parent):
        """[(name, inum, dtype)] of directory `parent`, by name."""
        if getattr(self, '_by_parent', None) is None:
            self._by_parent = {}
            for (owner, name), (_sq, inum, dtype) in self.dents.items():
                self._by_parent.setdefault(owner, []).append(
                    (name, inum, dtype))
            for listing in self._by_parent.values():
                listing.sort()
        return self._by_parent.get(parent, [])

    def parents(self):
        out = {}
        for (owner, name), (_sq, inum, _dtype) in self.dents.items():
            out.setdefault(inum, (owner, name))
        return out

    def attributes(self, inum):
        found = self.inodes.get(inum)
        return found[1] if found else None

    def block(self, inum, number):
        """Block `number` of inode `inum`, decompressed (zeros for a
        hole)."""
        found = self.blocks.get((inum, number))
        if found is None:
            return bytes(BLOCK)
        _sq, lnum, offs, length = found
        node = self._node_at(lnum, offs, length)
        if node is None:
            raise UbifsError(f"data node at LEB {lnum}:{offs} unreadable")
        size, compr = struct.unpack_from('<IH', node, CH + 16)
        return decompress(compr, node[48:], size).ljust(BLOCK, b'\0')

    def content(self, inum, offset, length):
        attributes = self.attributes(inum) or {}
        size = attributes.get('size', 0)
        end = min(offset + length, size)
        out = bytearray()
        while offset < end:
            number, inside = divmod(offset, BLOCK)
            piece = self.block(inum, number)[inside:inside + end - offset]
            out += piece
            offset += len(piece)
        return bytes(out)

    def compressions(self, inum):
        out = set()
        for (owner, _number), (_sq, lnum, offs, length) in \
                self.blocks.items():
            if owner != inum:
                continue
            head = self.read(lnum * self.leb_size + offs + CH + 16, 6)
            if len(head) == 6:
                out.add(struct.unpack_from('<H', head, 4)[0])
        out.discard(COMPR_NONE)
        return out

    def allocated_ranges(self):
        """Every LEB holding the index or a live node, plus the fixed areas
        (superblock, master, log, LPT, orphans): UBIFS works in whole LEBs,
        and a LEB in use is not free space."""
        fixed = 1 + 2 + self.log_lebs + self.lpt_lebs + self.orph_lebs
        lebs = sorted(set(range(fixed)) | self.used)
        return [(lnum * self.leb_size, (lnum + 1) * self.leb_size)
                for lnum in lebs]


# --- libyal's vocabulary -----------------------------------------------------

class UbifsEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, inum, name='', parent=0):
        self._volume = volume
        self.identifier = inum
        self.parent_identifier = parent
        self.name = name
        attributes = volume.attributes(inum) or {}
        self._attributes = attributes
        self.file_mode = attributes.get('mode', stat.S_IFDIR | 0o755
                                        if inum == ROOT else 0)
        self.size = 0 if stat.S_ISDIR(self.file_mode) else \
            attributes.get('size', 0)
        self.owner_identifier = attributes.get('uid', 0)
        self.group_identifier = attributes.get('gid', 0)
        self._children = None

    def get_number_of_links(self):
        return self._attributes.get('nlink', 1)

    def get_access_time_as_integer(self):
        return self._attributes.get('atime', 0)

    def get_modification_time_as_integer(self):
        return self._attributes.get('mtime', 0)

    def get_inode_change_time_as_integer(self):
        return self._attributes.get('ctime', 0)

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._attributes.get('data', b'').decode('utf-8',
                                                        'surrogateescape')

    @property
    def compression(self):
        methods = self._volume.compressions(self.identifier) \
            if stat.S_ISREG(self.file_mode) else ()
        return ', '.join(sorted(COMPRESSION_NAMES.get(m, str(m))
                                for m in methods)) or None

    @property
    def encrypted(self):
        return bool(self._attributes.get('flags', 0) & CRYPT_FL)

    def _list(self):
        if self._children is None:
            self._children = self._volume.children(self.identifier) \
                if stat.S_ISDIR(self.file_mode) else []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, inum, _dtype = self._list()[index]
        return UbifsEntry(self._volume, inum,
                          name.decode('utf-8', 'surrogateescape'),
                          self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if not stat.S_ISREG(self.file_mode):
            return b''
        return self._volume.content(self.identifier, offset, length)


class _Volume(PathLookup):
    """libyal's volume vocabulary over a UbifsVolume."""

    def __init__(self, volume):
        self.volume = volume
        self.label = ''
        self._parents = None

    def get_root_directory(self):
        return UbifsEntry(self.volume, ROOT)

    def entry(self, inum):
        if inum == ROOT:
            return self.get_root_directory()
        if inum not in self.volume.inodes:
            return None
        if self._parents is None:
            self._parents = self.volume.parents()
        parent, name = self._parents.get(inum, (0, b''))
        return UbifsEntry(self.volume, inum,
                          name.decode('utf-8', 'surrogateescape'), parent)

    def _names_in(self, entry):
        return [name.decode('utf-8', 'surrogateescape')
                for name, *_ in entry._list()]

    def close(self):
        pass


class UbifsFileSystem(LibyalFileSystem):
    """A UBIFS volume, read like a pytsk3.FS_Info."""

    KIND = 'UBIFS'

    def __init__(self, volume):
        self.ubifs = volume
        self.BLOCK_SIZE = BLOCK
        super().__init__(_Volume(volume), volume.size, 'UBIFS')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _last_identifier(self):
        return max(self.ubifs.inodes, default=ROOT)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.ubifs.allocated_ranges()

    def close(self):
        self.volume.close()


def open_ubifs(source):
    """A UbifsFileSystem over `source`, or None when it is not a UBIFS
    volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(CH)
    except (OSError, IOError):
        return None
    if not is_ubifs(head):
        return None
    try:
        return UbifsFileSystem(UbifsVolume(source))
    except (UbifsError, struct.error, OSError, IOError) as exc:
        logger.warning("UBIFS volume not opened: %s", exc)
        return None



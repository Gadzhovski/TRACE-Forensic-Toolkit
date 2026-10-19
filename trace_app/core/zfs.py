"""ZFS pools, read in Python (no Qt).

The Sleuth Kit and libyal read no ZFS, and no library with wheels does.
This follows OpenZFS's own headers (include/sys/spa.h, vdev_impl.h,
dnode.h, zap_impl.h, zap_leaf.h, sa_impl.h, dsl_*.h, vdev_raidz.c) and is
checked against pools OpenZFS itself wrote (tools/testdata/build/
make_zfs.py, tests/test_zfs.py). A pool is:

* on every disk (vdev), four 256 KiB labels -- two at the start, two at the
  end -- each an XDR nvlist (pool name and GUID, this disk's GUID, its
  top-level vdev's tree: disk / mirror / raidz with its children, ashift,
  parity) and a ring of uberblocks; the uberblock with the highest txg
  (of a valid magic) is current, and its root block pointer names the
  meta object set (MOS). Data starts 4 MiB into the disk;
* block pointers: up to three DVAs (top-level vdev, offset, allocated
  size; a gang bit), logical and physical size, compression (lz4 with a
  4-byte length; gzip; zstd magicless behind an 8-byte header; lzjb; zle),
  level, type, birth; an embedded pointer carries its (small, compressed)
  data in its own words; a hole has no DVA;
* raidz: a block's sectors spread over the children by
  vdev_raidz_map_alloc's arithmetic (parity columns first, the first
  column rotating with the offset, raidz1's parity and first data column
  swapped in every other MiB); one missing disk of raidz1 is rebuilt by
  XOR. A mirror reads from any child;
* object sets: a meta dnode whose data is an array of 512-byte dnode
  slots; a dnode has its block size, indirect block shift, levels, block
  pointers and bonus buffer (large dnodes span several slots; a spill
  block pointer at the end);
* the MOS object directory (a ZAP) -> the root DSL directory; each DSL
  directory's head dataset and child directories (named in a ZAP); each
  dataset's block pointer is its object set, its snapshots named in
  another ZAP;
* ZAPs: micro (one block of 64-byte name/value entries) or fat (leaf
  blocks of 24-byte chunks: entries, names and big-endian values in
  chained arrays; the pointer table says which blocks are leaves);
* the ZPL: object 1 the master node (ROOT, SA_ATTRS), directories are ZAPs
  whose values are (type << 60 | object), file attributes are system
  attributes in the bonus (laid out by the SA registry and layouts) or a
  legacy znode.

Datasets and snapshots are the volumes of a pool (`ZfsPool.datasets`);
each is read like a pytsk3 FS_Info through core/libyal_fs. Identifiers
are object numbers. Encrypted datasets are listed and said to be locked
(native encryption is not read). Deleted files are not listed.
"""

import hashlib
import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.ZFS')

LABEL = 256 * 1024
LABEL_START = 4 * 1024 * 1024           # two labels + the boot region
NVLIST_OFFSET, NVLIST_SIZE = 16 * 1024, 112 * 1024
UBERBLOCK_OFFSET, UBERBLOCK_RING = 128 * 1024, 128 * 1024
UB_MAGIC = 0x00BAB10C
SECTOR = 512
DNODE_SLOT = 512
BP = 128

# compression (zio.h)
(ZIO_INHERIT, ZIO_ON, ZIO_OFF, ZIO_LZJB, ZIO_EMPTY) = range(5)
ZIO_GZIP = range(5, 14)
ZIO_ZLE, ZIO_LZ4, ZIO_ZSTD = 14, 15, 16
COMPRESSION_NAMES = {ZIO_OFF: 'off', ZIO_LZJB: 'lzjb', ZIO_EMPTY: 'empty',
                     ZIO_ZLE: 'zle', ZIO_LZ4: 'lz4', ZIO_ZSTD: 'zstd',
                     **{n: f'gzip-{n - 4}' for n in ZIO_GZIP}}

# DMU object types (dmu.h)
DMU_OT_DSL_DIR, DMU_OT_DSL_DATASET, DMU_OT_ZNODE, DMU_OT_SA = 12, 16, 17, 44

# ZAP
ZBT_LEAF, ZBT_HEADER, ZBT_MICRO = (1 << 63), (1 << 63) + 1, (1 << 63) + 3
ZAP_MAGIC = 0x2F52AB2AB
LEAF_MAGIC = 0x2AB1EAF
CHUNK = 24
CHUNK_ENTRY, CHUNK_ARRAY = 252, 251
MZAP_ENT = 64

SA_MAGIC = 0x2F505A
DNODE_FLAG_SPILL_BLKPTR = 4

#: Directory entry types (the top 4 bits of a ZPL directory value).
_DT_MODE = {1: stat.S_IFIFO, 2: stat.S_IFCHR, 4: stat.S_IFDIR,
            6: stat.S_IFBLK, 8: stat.S_IFREG, 10: stat.S_IFLNK,
            12: stat.S_IFSOCK}

#: The ZPL's legacy attribute numbering (zfs_sa.h), for a dataset whose
#: registry is not read.
_ZPL_ATTRS = ('ZPL_ATIME', 'ZPL_MTIME', 'ZPL_CTIME', 'ZPL_CRTIME',
              'ZPL_GEN', 'ZPL_MODE', 'ZPL_SIZE', 'ZPL_PARENT', 'ZPL_LINKS',
              'ZPL_XATTR', 'ZPL_RDEV', 'ZPL_FLAGS', 'ZPL_UID', 'ZPL_GID',
              'ZPL_PAD', 'ZPL_ZNODE_ACL', 'ZPL_DACL_COUNT', 'ZPL_SYMLINK',
              'ZPL_SCANSTAMP', 'ZPL_DACL_ACES', 'ZPL_DXATTR', 'ZPL_PROJID')


class ZfsError(Exception):
    pass


# --- XDR nvlists ------------------------------------------------------------

def _xdr_string(data, at):
    length, = struct.unpack_from('>I', data, at)
    at += 4
    value = data[at:at + length].decode('utf-8', 'replace')
    return value, at + ((length + 3) & ~3)


def _nvlist(data, at):
    """(dict, position) of an XDR-encoded nvlist at `at` (version, flags,
    pairs, terminated by a zero-size pair)."""
    at += 8                                         # version, nvflag
    out = {}
    while True:
        encoded, decoded = struct.unpack_from('>II', data, at)
        if encoded == 0 and decoded == 0:
            return out, at + 8
        start = at
        at += 8
        name, at = _xdr_string(data, at)
        kind, count = struct.unpack_from('>II', data, at)
        at += 8
        if kind == 19:                              # NVLIST
            out[name], at = _nvlist(data, at)
        elif kind == 20:                            # NVLIST_ARRAY
            items = []
            for _ in range(count):
                item, at = _nvlist(data, at)
                items.append(item)
            out[name] = items
        elif kind in (8, 7, 6, 5, 3, 4):            # (u)int64/32/16
            values = []
            for _ in range(count):
                if kind in (8, 7):
                    values.append(struct.unpack_from('>Q', data, at)[0])
                    at += 8
                else:
                    values.append(struct.unpack_from('>I', data, at)[0])
                    at += 4
            out[name] = values[0] if count == 1 else values
        elif kind == 9:                             # STRING
            out[name], at = _xdr_string(data, at)
        elif kind in (16, 15):                      # UINT64/INT64_ARRAY
            out[name] = list(struct.unpack_from(f'>{count}Q', data, at))
            at += 8 * count
        elif kind == 1:                             # BOOLEAN (no value)
            out[name] = True
        else:                                       # anything else: skip
            out[name] = None
            at = start + encoded
            continue
        at = max(at, start + encoded) if encoded else at


def unpack_nvlist(data):
    if len(data) < 4 or data[0] != 1:               # NV_ENCODE_XDR
        raise ZfsError("label nvlist is not XDR")
    return _nvlist(data, 4)[0]


# --- block pointers ---------------------------------------------------------

class BlockPointer:
    __slots__ = ('raw', 'dvas', 'lsize', 'psize', 'compression', 'embedded',
                 'checksum', 'type', 'level', 'encrypted', 'dedup',
                 'little', 'birth', 'fill', 'etype')

    def __init__(self, raw):
        self.raw = raw
        words = struct.unpack_from('<16Q', raw)
        prop = words[6]
        self.embedded = bool(prop >> 39 & 1)
        self.compression = prop >> 32 & 0x7F
        self.type = prop >> 48 & 0xFF
        self.level = prop >> 56 & 0x1F
        self.encrypted = bool(prop >> 61 & 1)
        self.dedup = bool(prop >> 62 & 1)
        self.little = bool(prop >> 63 & 1)
        self.birth = words[10]
        self.fill = words[11]
        if self.embedded:
            self.etype = prop >> 40 & 0xFF
            self.lsize = (prop & 0x1FFFFFF) + 1
            self.psize = (prop >> 25 & 0x7F) + 1
            self.dvas = []
            self.checksum = None
            return
        self.etype = None
        self.lsize = ((prop & 0xFFFF) + 1) << 9
        self.psize = ((prop >> 16 & 0xFFFF) + 1) << 9
        self.checksum = prop >> 40 & 0xFF
        self.dvas = []
        for index in range(3):
            first, second = words[2 * index], words[2 * index + 1]
            asize = (first & 0xFFFFFF) << 9
            if not asize:
                continue
            self.dvas.append((first >> 32, (second & ~(1 << 63)) << 9,
                              asize, bool(second >> 63)))

    @property
    def hole(self):
        return not self.embedded and not self.dvas

    def embedded_payload(self):
        """The data an embedded pointer carries: every word but the
        properties (6) and the birth (10)."""
        words = [self.raw[i * 8:i * 8 + 8] for i in range(16)
                 if i not in (6, 10)]
        return b''.join(words)[:self.psize]


def lzjb_decompress(source, size):
    out = bytearray()
    position = 0
    copymask = 1 << 7
    copymap = 0
    while len(out) < size and position < len(source):
        copymask <<= 1
        if copymask == 1 << 8:
            copymask = 1
            copymap = source[position]
            position += 1
        if copymap & copymask:
            if position + 1 >= len(source):
                break
            length = (source[position] >> 2) + 3
            offset = ((source[position] << 8) | source[position + 1]) & 0x3FF
            position += 2
            start = len(out) - offset
            if start < 0:
                raise ZfsError("lzjb reference before the start")
            for index in range(min(length, size - len(out))):
                out.append(out[start + index])
        else:
            out.append(source[position])
            position += 1
    return bytes(out)


def zle_decompress(source, size, n=64):
    out = bytearray()
    position = 0
    while position < len(source) and len(out) < size:
        length = 1 + source[position]
        position += 1
        if length <= n:
            out += source[position:position + length]
            position += length
        else:
            out += bytes(length - n)
    return bytes(out)


def decompress(method, data, size):
    try:
        if method in (ZIO_OFF, ZIO_INHERIT, ZIO_ON) and len(data) >= size:
            # 'on' never reaches the disk; a block stored as is says off.
            return bytes(data[:size])
        if method == ZIO_LZ4:
            from trace_app.core.activity.journal import lz4_block
            length, = struct.unpack_from('>I', data)
            return bytes(lz4_block(bytes(data[4:4 + length]),
                                   stop_at=size))[:size]
        if method in ZIO_GZIP:
            return zlib.decompress(bytes(data))[:size]
        if method == ZIO_ZSTD:
            from trace_app.core import zstd_decode
            length, = struct.unpack_from('>I', data)
            frame = b'\x28\xb5\x2f\xfd' + bytes(data[8:8 + length])
            return bytes(zstd_decode.decompress_frame(frame, size))[:size]
        if method == ZIO_LZJB:
            return lzjb_decompress(data, size)
        if method == ZIO_ZLE:
            return zle_decompress(data, size)
        if method == ZIO_EMPTY:
            return bytes(size)
    except ZfsError:
        raise
    except Exception as exc:          # every decompressor's own errors
        raise ZfsError(f"{COMPRESSION_NAMES.get(method, method)} block does "
                       f"not decompress: {exc}") from exc
    raise ZfsError(f"compression {method} is not read")


# --- vdevs --------------------------------------------------------------------

class _Disk:
    """A leaf vdev: reads at a vdev offset (past the labels)."""

    def __init__(self, source):
        self.source = source

    def read(self, offset, length):
        self.source.seek(LABEL_START + offset)
        data = self.source.read(length)
        if len(data) < length:
            raise ZfsError(f"short read at {offset:#x}")
        return data


class _Missing:
    def read(self, offset, length):
        raise ZfsError("a disk of this pool is not here")


class _Mirror:
    def __init__(self, children):
        self.children = children

    def read(self, offset, length):
        last = None
        for child in self.children:
            try:
                return child.read(offset, length)
            except ZfsError as exc:
                last = exc
        raise last or ZfsError("mirror with no children")


class _Raidz:
    """vdev_raidz_map_alloc's layout, read back (OpenZFS before raidz
    expansion: no reflow)."""

    def __init__(self, children, nparity, ashift):
        self.children = children
        self.nparity = nparity
        self.ashift = ashift

    def columns(self, offset, size):
        """[(child index, child offset, length)] of every column, parity
        first."""
        shift = self.ashift
        dcols = len(self.children)
        p = self.nparity
        b = offset >> shift
        s = size >> shift
        f = b % dcols
        o = (b // dcols) << shift
        q = s // (dcols - p)
        r = s - q * (dcols - p)
        bc = 0 if r == 0 else r + p
        if q == 0:
            acols = bc
            scols = min(dcols, -(-bc // (p + 1)) * (p + 1))
        else:
            acols = dcols
            scols = dcols
        out = []
        for c in range(scols):
            col = f + c
            coff = o
            if col >= dcols:
                col -= dcols
                coff += 1 << shift
            if c >= acols:
                length = 0
            elif c < bc:
                length = (q + 1) << shift
            else:
                length = q << shift
            out.append([col, coff, length])
        if p == 1 and offset & (1 << 20) and len(out) > 1:
            out[0][0], out[1][0] = out[1][0], out[0][0]
            out[0][1], out[1][1] = out[1][1], out[0][1]
        return out

    def read(self, offset, length):
        unit = 1 << self.ashift
        size = -(-length // unit) * unit
        columns = self.columns(offset, size)
        data = []
        missing = None
        for index, (child, coff, clen) in enumerate(columns):
            if index < self.nparity:
                continue
            try:
                data.append(self.children[child].read(coff, clen)
                            if clen else b'')
            except ZfsError:
                if missing is not None or self.nparity < 1:
                    raise
                missing = len(data)
                data.append(None)
        if missing is not None:
            # raidz's P column is the XOR of the data columns, each padded
            # to the parity column's length.
            child, coff, plen = columns[0]
            parity = bytearray(self.children[child].read(coff, plen))
            for column in data:
                if column is None:
                    continue
                for index, byte in enumerate(column):
                    parity[index] ^= byte
            data[missing] = bytes(parity[:columns[self.nparity + missing][2]])
        return b''.join(data)[:length]


def _build_vdev(tree, leaves):
    kind = tree.get('type')
    if kind in ('disk', 'file'):
        return leaves.get(tree.get('guid'), _Missing())
    children = [_build_vdev(child, leaves)
                for child in tree.get('children', [])]
    if kind == 'mirror' or kind == 'replacing' or kind == 'spare':
        return _Mirror(children)
    if kind == 'raidz':
        if tree.get('raidz_expanding') or tree.get('raidz_expand_txg'):
            raise ZfsError("an expanded raidz is not read")
        return _Raidz(children, tree.get('nparity', 1), tree['ashift'])
    raise ZfsError(f"vdev type {kind!r} is not read")


# --- labels -----------------------------------------------------------------

def _labels(source, size):
    return [0, LABEL, size - 2 * LABEL, size - LABEL]


def read_label(source, size=None):
    """(config nvlist, [uberblock dicts]) of the first readable label of a
    vdev, or None."""
    if size is None:
        source.seek(0, 2)
        size = source.tell()
    for start in _labels(source, size):
        if start < 0:
            continue
        source.seek(start)
        label = source.read(LABEL)
        if len(label) < LABEL:
            continue
        try:
            config = unpack_nvlist(label[NVLIST_OFFSET:NVLIST_OFFSET +
                                         NVLIST_SIZE])
        except (ZfsError, struct.error, UnicodeDecodeError):
            continue
        if 'pool_guid' not in config or 'vdev_tree' not in config:
            continue
        ashift = config['vdev_tree'].get('ashift', 9)
        slot = 1 << max(ashift, 10)
        if slot > UBERBLOCK_RING // 4:
            slot = 1 << 13
        uberblocks = []
        for at in range(UBERBLOCK_OFFSET, UBERBLOCK_OFFSET + UBERBLOCK_RING,
                        slot):
            block = label[at:at + slot]
            magic, version, txg, guid_sum, timestamp = \
                struct.unpack_from('<QQQQQ', block)
            if magic != UB_MAGIC or not txg:
                continue
            if not _label_checksum_ok(block, start + at):
                continue
            uberblocks.append({'txg': txg, 'timestamp': timestamp,
                               'version': version, 'guid_sum': guid_sum,
                               'rootbp': BlockPointer(block[40:40 + BP])})
        return config, uberblocks
    return None


def _label_checksum_ok(block, offset):
    """A label block's embedded SHA-256 (zio_eck_t in its last 40 bytes,
    computed with the checksum words set to the block's offset)."""
    if struct.unpack_from('<Q', block, len(block) - 40)[0] != \
            0x0210DA7AB10C7A11:
        return False
    stored = block[-32:]
    copy = bytearray(block)
    copy[-32:] = struct.pack('<4Q', offset, 0, 0, 0)
    digest = hashlib.sha256(copy).digest()
    return struct.pack('<4Q', *struct.unpack('>4Q', digest)) == stored


# --- dnodes and object sets ------------------------------------------------------

class Dnode:
    __slots__ = ('raw', 'type', 'indblkshift', 'nlevels', 'nblkptr',
                 'bonustype', 'flags', 'datablksz', 'bonuslen', 'slots',
                 'maxblkid', 'blkptrs', 'bonus', 'spill')

    def __init__(self, raw):
        self.raw = raw
        (self.type, self.indblkshift, self.nlevels, self.nblkptr,
         self.bonustype, _checksum, _compress, self.flags, datablkszsec,
         self.bonuslen, extra) = struct.unpack_from('<8BHHB', raw)
        self.datablksz = datablkszsec * SECTOR
        self.slots = extra + 1
        self.maxblkid, = struct.unpack_from('<Q', raw, 16)
        self.blkptrs = [BlockPointer(raw[64 + i * BP:64 + (i + 1) * BP])
                        for i in range(self.nblkptr)]
        start = 64 + self.nblkptr * BP
        self.bonus = raw[start:start + self.bonuslen]
        self.spill = BlockPointer(raw[len(raw) - BP:]) \
            if self.flags & DNODE_FLAG_SPILL_BLKPTR else None


class ZfsPool:
    """A pool read through its disks' readers (file objects over each
    vdev's partition)."""

    def __init__(self, sources):
        configs = []
        for source in sources:
            found = read_label(source)
            if found is None:
                raise ZfsError("no ZFS label")
            configs.append((found, source))
        (config, _ub), _source = configs[0]
        self.name = config.get('name', '')
        self.guid = config['pool_guid']
        self.config = config
        leaves = {}
        trees = {}
        uberblocks = []
        for (found_config, found_ubs), source in configs:
            if found_config['pool_guid'] != self.guid:
                raise ZfsError("disks of different pools")
            leaves[found_config['guid']] = _Disk(source)
            tree = found_config['vdev_tree']
            trees[tree['id']] = tree
            uberblocks += found_ubs
        children = config.get('vdev_children', len(trees))
        self.top = {index: _build_vdev(tree, leaves)
                    for index, tree in trees.items()}
        self.missing_top = [index for index in range(children)
                            if index not in self.top]
        if self.missing_top:
            raise ZfsError(f"{len(self.missing_top)} of {children} top-level "
                           f"vdevs are on other disks: those disks are "
                           f"needed")
        self.degraded = []
        for tree in trees.values():
            self._check_redundancy(tree, leaves)
        if not uberblocks:
            raise ZfsError("no valid uberblock")
        self.uberblock = max(uberblocks,
                             key=lambda u: (u['txg'], u['timestamp']))
        self._cache = {}
        self.mos = ObjectSet(self, self.read_bp(self.uberblock['rootbp']))
        self.datasets = self._datasets()

    def _check_redundancy(self, tree, leaves):
        """Refuse a pool missing more disks than a vdev can do without --
        some blocks would read (small ones whose sectors are all here) and
        others not, file by file. Missing disks within the parity are
        noted (`degraded`)."""
        children = tree.get('children', [])
        if not children:
            return
        missing = [child for child in children
                   if not self._present(child, leaves)]
        kind = tree.get('type')
        # raidz: one missing disk is rebuilt from P (XOR); raidz2/3's Q and
        # R (Reed-Solomon) are not read, so two missing are not rebuilt.
        allowed = 1 if kind == 'raidz' else len(children) - 1
        if len(missing) > allowed:
            raise ZfsError(f"{len(children) - len(missing)} of "
                           f"{len(children)} disks of a {kind}"
                           f"{tree.get('nparity', '') if kind == 'raidz' else ''}"
                           f" are here: the other disks are needed")
        if missing:
            self.degraded.append(f"{kind} without {len(missing)} of "
                                 f"{len(children)} disks")
        for child in children:
            self._check_redundancy(child, leaves)

    @classmethod
    def _present(cls, tree, leaves):
        if tree.get('type') in ('disk', 'file'):
            return tree.get('guid') in leaves
        children = tree.get('children', [])
        return any(cls._present(child, leaves) for child in children)

    # --- reading blocks -------------------------------------------------------

    def read_bp(self, bp):
        """The logical bytes of a block pointer."""
        if bp.embedded:
            return decompress(bp.compression, bp.embedded_payload(),
                              bp.lsize)
        if bp.hole:
            return bytes(bp.lsize)
        if bp.encrypted and bp.level == 0 and bp.type not in (10, 11):
            raise ZfsError("encrypted block (native encryption is not read)")
        last = None
        for vdev, offset, asize, gang in bp.dvas:
            try:
                if gang:
                    data = self._read_gang(vdev, offset, bp.psize)
                else:
                    data = self._read_dva(vdev, offset, bp.psize)
                return decompress(bp.compression, data, bp.lsize)
            except ZfsError as exc:
                last = exc
        raise last or ZfsError("block pointer with no DVA")

    def _read_dva(self, vdev, offset, length):
        top = self.top.get(vdev)
        if top is None:
            raise ZfsError(f"top-level vdev {vdev} is not here")
        return top.read(offset, length)

    def _read_gang(self, vdev, offset, psize):
        header = self._read_dva(vdev, offset, SECTOR)
        out = bytearray()
        for index in range(3):
            child = BlockPointer(header[index * BP:(index + 1) * BP])
            if child.hole:
                continue
            for cvdev, coff, _asize, cgang in child.dvas[:1]:
                piece = self._read_gang(cvdev, coff, child.psize) if cgang \
                    else self._read_dva(cvdev, coff, child.psize)
                out += piece
        return bytes(out[:psize])

    # --- the DSL ----------------------------------------------------------------

    def _datasets(self):
        """[{'name', 'kind' (filesystem | snapshot), 'objset': bp,
        'creation', 'encrypted'}] of every dataset and snapshot."""
        directory = self.mos.zap(1)
        root = directory.get('root_dataset')
        out = []
        if root is None:
            return out
        pending = [(root, self.name)]
        while pending:
            dir_obj, name = pending.pop(0)
            dnode = self.mos.dnode(dir_obj)
            if dnode is None or len(dnode.bonus) < 40:
                continue
            head, = struct.unpack_from('<Q', dnode.bonus, 8)
            child_zap, = struct.unpack_from('<Q', dnode.bonus, 32)
            if head:
                dataset = self._dataset(head, name, 'filesystem')
                if dataset is not None:
                    out.append(dataset)
                    snapnames = dataset.pop('_snapnames')
                    if snapnames:
                        for snap, obj in sorted(
                                self.mos.zap(snapnames).items()):
                            snapshot = self._dataset(obj, f"{name}@{snap}",
                                                     'snapshot')
                            if snapshot is not None:
                                snapshot.pop('_snapnames')
                                out.append(snapshot)
            if child_zap:
                for child, obj in sorted(self.mos.zap(child_zap).items()):
                    if child.startswith('$'):          # $MOS, $FREE, $ORIGIN
                        continue
                    pending.append((obj, f"{name}/{child}"))
        return out

    def _dataset(self, obj, name, kind):
        dnode = self.mos.dnode(obj)
        if dnode is None or len(dnode.bonus) < 256:
            return None
        bonus = dnode.bonus
        snapnames, = struct.unpack_from('<Q', bonus, 32)
        creation, = struct.unpack_from('<Q', bonus, 48)
        bp = BlockPointer(bonus[128:128 + BP])
        return {'name': name, 'kind': kind, 'objset': bp,
                'creation': creation, 'object': obj,
                'encrypted': bp.encrypted, '_snapnames': snapnames}

    def open_dataset(self, dataset):
        if dataset['encrypted']:
            raise ZfsError(f"{dataset['name']} is encrypted (native "
                           f"encryption is not read)")
        return ObjectSet(self, self.read_bp(dataset['objset']))

    def describe(self):
        tops = ', '.join(sorted({type(top).__name__.strip('_').lower()
                                 for top in self.top.values()}))
        degraded = f"; degraded: {', '.join(self.degraded)}"             if self.degraded else ''
        return (f"ZFS pool {self.name} (txg {self.uberblock['txg']}, "
                f"{tops}): {len(self.datasets)} datasets and snapshots"
                f"{degraded}")


class ObjectSet:
    """An object set: its meta dnode, and its objects' dnodes and data."""

    def __init__(self, pool, raw):
        self.pool = pool
        self.meta = Dnode(raw[:DNODE_SLOT])
        self.type, = struct.unpack_from('<Q', raw, DNODE_SLOT + 192) \
            if len(raw) >= DNODE_SLOT + 200 else (0,)
        self._blocks = {}
        self._dnodes = {}

    def block(self, dnode, blkid):
        """Data block `blkid` of `dnode` (zeros past its last, and for
        holes)."""
        if blkid > dnode.maxblkid or not dnode.nlevels:
            return bytes(dnode.datablksz)
        epbs = dnode.indblkshift - 7
        index = blkid >> (epbs * (dnode.nlevels - 1))
        if index >= len(dnode.blkptrs):
            return bytes(dnode.datablksz)
        bp = dnode.blkptrs[index]
        for level in range(dnode.nlevels - 1, 0, -1):
            if bp.hole:
                return bytes(dnode.datablksz)
            indirect = self._indirect(bp)
            slot = (blkid >> (epbs * (level - 1))) & ((1 << epbs) - 1)
            bp = BlockPointer(indirect[slot * BP:(slot + 1) * BP])
        if bp.hole:
            return bytes(dnode.datablksz)
        return self.pool.read_bp(bp)

    def _indirect(self, bp):
        key = bp.raw[:16] + bp.raw[80:88]
        found = self._blocks.get(key)
        if found is None:
            found = self.pool.read_bp(bp)
            if len(self._blocks) > 256:
                self._blocks.clear()
            self._blocks[key] = found
        return found

    def read(self, dnode, offset, length):
        size = dnode.datablksz
        out = bytearray()
        while length > 0:
            blkid, inside = divmod(offset, size)
            piece = self.block(dnode, blkid)[inside:inside + length]
            if not piece:
                break
            out += piece
            offset += len(piece)
            length -= len(piece)
        return bytes(out)

    def dnode(self, obj):
        found = self._dnodes.get(obj)
        if found is not None:
            return found
        raw = self.read(self.meta, obj * DNODE_SLOT, DNODE_SLOT)
        if len(raw) < DNODE_SLOT or raw[0] == 0:
            return None
        extra = raw[12]
        if extra:
            raw = self.read(self.meta, obj * DNODE_SLOT,
                            (extra + 1) * DNODE_SLOT)
        found = Dnode(raw)
        if len(self._dnodes) > 4096:
            self._dnodes.clear()
        self._dnodes[obj] = found
        return found

    # --- ZAPs -----------------------------------------------------------------

    def zap(self, obj, integers=False):
        """{name: value} of ZAP object `obj`: a value is one integer, or
        with `integers` the list of them."""
        dnode = self.dnode(obj)
        if dnode is None:
            return {}
        first = self.block(dnode, 0)
        kind, = struct.unpack_from('<Q', first)
        if kind == ZBT_MICRO:
            out = {}
            for at in range(MZAP_ENT, len(first) - MZAP_ENT + 1, MZAP_ENT):
                value, = struct.unpack_from('<Q', first, at)
                name = first[at + 14:at + 64].split(b'\0')[0]
                if name:
                    out[name.decode('utf-8', 'surrogateescape')] = \
                        [value] if integers else value
            return out
        if kind != ZBT_HEADER:
            raise ZfsError(f"object {obj} is not a ZAP")
        return self._fat_zap(dnode, first, integers)

    def _fat_zap(self, dnode, header, integers):
        magic, = struct.unpack_from('<Q', header, 8)
        if magic != ZAP_MAGIC:
            raise ZfsError("bad ZAP magic")
        zt_blk, zt_numblks, zt_shift = struct.unpack_from('<QQQ', header, 16)
        size = dnode.datablksz
        if zt_numblks == 0:
            count = 1 << zt_shift
            table = struct.unpack_from(f'<{count}Q', header, size // 2)
        else:
            table = []
            for blkid in range(zt_blk, zt_blk + zt_numblks):
                block = self.block(dnode, blkid)
                table += struct.unpack(f'<{size // 8}Q', block)
        out = {}
        for leaf in sorted(set(table)):
            self._leaf(self.block(dnode, leaf), out, integers)
        return out

    @staticmethod
    def _leaf(block, out, integers):
        if len(block) < 48:
            return
        kind, = struct.unpack_from('<Q', block)
        magic, = struct.unpack_from('<I', block, 24)
        if kind != ZBT_LEAF or magic != LEAF_MAGIC:
            return
        shift = (len(block).bit_length() - 1) - 5
        hash_entries = 1 << shift
        base = 48 + 2 * hash_entries
        chunks = (len(block) - 2 * hash_entries) // CHUNK - 2

        def array(first, length):
            data = bytearray()
            chunk = first
            while chunk != 0xFFFF and len(data) < length and chunk < chunks:
                at = base + chunk * CHUNK
                if block[at] != CHUNK_ARRAY:
                    break
                data += block[at + 1:at + 22]
                chunk, = struct.unpack_from('<H', block, at + 22)
            return bytes(data[:length])

        for chunk in range(chunks):
            at = base + chunk * CHUNK
            if block[at] != CHUNK_ENTRY:
                continue
            (intlen, _next, name_chunk, name_len, value_chunk,
             value_count) = struct.unpack_from('<BHHHHH', block, at + 1)
            name = array(name_chunk, name_len).rstrip(b'\0')
            raw = array(value_chunk, value_count * intlen)
            values = [int.from_bytes(raw[i:i + intlen], 'big')
                      for i in range(0, len(raw), intlen)] if intlen else []
            if integers:
                value = values
            else:
                value = values[0] if len(values) == 1 else values
            out[name.decode('utf-8', 'surrogateescape')] = value


# --- the ZPL --------------------------------------------------------------------

class ZplVolume:
    """One dataset's files."""

    def __init__(self, objset, name):
        self.objset = objset
        self.name = name
        master = objset.zap(1)
        self.root = master.get('ROOT')
        if self.root is None:
            raise ZfsError(f"{name}: no ROOT (not a file system)")
        self.version = master.get('VERSION', 0)
        self._registry = {}
        self._layouts = {}
        sa = master.get('SA_ATTRS')
        if sa:
            tables = objset.zap(sa)
            if 'REGISTRY' in tables:
                for attr, value in objset.zap(tables['REGISTRY']).items():
                    self._registry[value & 0xFFFF] = (attr,
                                                      value >> 24 & 0xFFFF)
            if 'LAYOUTS' in tables:
                for number, attrs in objset.zap(tables['LAYOUTS'],
                                                integers=True).items():
                    self._layouts[int(number)] = attrs
        self._attrs = {}

    def attributes(self, obj):
        """{attribute name: bytes} of object `obj`'s znode, or None."""
        found = self._attrs.get(obj)
        if found is not None:
            return found
        dnode = self.objset.dnode(obj)
        if dnode is None:
            return None
        if dnode.bonustype == DMU_OT_SA:
            out = self._sa(dnode.bonus)
            if dnode.spill is not None and not dnode.spill.hole:
                try:
                    out.update(self._sa(self.objset.pool.read_bp(
                        dnode.spill)))
                except ZfsError as exc:
                    logger.debug("ZFS spill block of %d: %s", obj, exc)
        elif dnode.bonustype == DMU_OT_ZNODE:
            out = self._znode(dnode.bonus)
        else:
            return None
        out['_dnode'] = dnode
        if len(self._attrs) > 4096:
            self._attrs.clear()
        self._attrs[obj] = out
        return out

    def _sa(self, data):
        if len(data) < 8:
            return {}
        magic, info = struct.unpack_from('<IH', data)
        if magic != SA_MAGIC:
            return {}
        layout = self._layouts.get(info & 0x3FF)
        if layout is None:
            return {}
        names = [self._registry.get(a, (_ZPL_ATTRS[a] if a < len(_ZPL_ATTRS)
                                        else str(a), 0)) for a in layout]
        variable = sum(1 for _name, length in names if not length)
        lengths = struct.unpack_from(f'<{variable}H', data, 6)
        at = (6 + 2 * variable + 7) & ~7
        out = {}
        index = 0
        for name, length in names:
            if not length:
                length = lengths[index]
                index += 1
            out[name] = data[at:at + length]
            at = (at + length + 7) & ~7
        return out

    @staticmethod
    def _znode(data):
        if len(data) < 264:
            return {}
        fields = {'ZPL_ATIME': data[0:16], 'ZPL_MTIME': data[16:32],
                  'ZPL_CTIME': data[32:48], 'ZPL_CRTIME': data[48:64],
                  'ZPL_GEN': data[64:72], 'ZPL_MODE': data[72:80],
                  'ZPL_SIZE': data[80:88], 'ZPL_PARENT': data[88:96],
                  'ZPL_LINKS': data[96:104], 'ZPL_XATTR': data[104:112],
                  'ZPL_RDEV': data[112:120], 'ZPL_FLAGS': data[120:128],
                  'ZPL_UID': data[128:136], 'ZPL_GID': data[136:144]}
        # A short symlink target sits after the znode.
        fields['_inline'] = data[264:]
        return fields

    def children(self, obj):
        """[(name, object, dirent type)] of directory `obj`, by name."""
        listing = self.objset.zap(obj)
        return sorted((name, value & 0xFFFFFFFFFFFF, value >> 60)
                      for name, value in listing.items())

    def content(self, obj, offset, length):
        attributes = self.attributes(obj) or {}
        dnode = attributes.get('_dnode')
        size = _u64(attributes.get('ZPL_SIZE'))
        if dnode is None:
            return b''
        end = min(offset + length, size)
        if offset >= end:
            return b''
        return self.objset.read(dnode, offset, end - offset)

    def symlink(self, obj):
        attributes = self.attributes(obj) or {}
        if 'ZPL_SYMLINK' in attributes:
            return attributes['ZPL_SYMLINK']
        size = _u64(attributes.get('ZPL_SIZE'))
        inline = attributes.get('_inline', b'')
        if size and len(inline) >= size:
            return inline[:size]
        return self.content(obj, 0, size)


def _u64(raw):
    return struct.unpack_from('<Q', raw)[0] if raw and len(raw) >= 8 else 0


def _time(raw):
    if not raw or len(raw) < 16:
        return 0
    seconds, nanoseconds = struct.unpack_from('<QQ', raw)
    return seconds * 1_000_000_000 + nanoseconds


# --- libyal's vocabulary -----------------------------------------------------

class ZfsEntry:
    def __init__(self, zpl, obj, name='', parent=0, dtype=None):
        self._zpl = zpl
        self.identifier = obj
        self.parent_identifier = parent
        self.name = name
        attributes = zpl.attributes(obj) or {}
        self._attributes = attributes
        mode = _u64(attributes.get('ZPL_MODE'))
        if not mode and dtype in _DT_MODE:
            mode = _DT_MODE[dtype]
        self.file_mode = mode
        self.size = 0 if stat.S_ISDIR(mode) else \
            _u64(attributes.get('ZPL_SIZE'))
        self.owner_identifier = _u64(attributes.get('ZPL_UID'))
        self.group_identifier = _u64(attributes.get('ZPL_GID'))
        self._children = None

    def get_number_of_links(self):
        return _u64(self._attributes.get('ZPL_LINKS')) or 1

    def get_access_time_as_integer(self):
        return _time(self._attributes.get('ZPL_ATIME'))

    def get_modification_time_as_integer(self):
        return _time(self._attributes.get('ZPL_MTIME'))

    def get_inode_change_time_as_integer(self):
        return _time(self._attributes.get('ZPL_CTIME'))

    def get_creation_time_as_integer(self):
        return _time(self._attributes.get('ZPL_CRTIME'))

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._zpl.symlink(self.identifier).decode('utf-8',
                                                         'surrogateescape')

    @property
    def compression(self):
        return None

    def _list(self):
        if self._children is None:
            self._children = self._zpl.children(self.identifier) \
                if stat.S_ISDIR(self.file_mode) else []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, obj, dtype = self._list()[index]
        return ZfsEntry(self._zpl, obj, name, self.identifier, dtype)

    def read_buffer_at_offset(self, length, offset):
        if not stat.S_ISREG(self.file_mode):
            return b''
        return self._zpl.content(self.identifier, offset, length)


class _Volume:
    def __init__(self, zpl):
        self.zpl = zpl
        self.label = zpl.name

    def get_root_directory(self):
        return ZfsEntry(self.zpl, self.zpl.root)

    def entry(self, obj):
        if obj == self.zpl.root:
            return self.get_root_directory()
        attributes = self.zpl.attributes(obj)
        if attributes is None:
            return None
        parent = _u64(attributes.get('ZPL_PARENT'))
        name = ''
        try:
            for child, number, _dtype in self.zpl.children(parent):
                if number == obj:
                    name = child
                    break
        except ZfsError:
            pass
        return ZfsEntry(self.zpl, obj, name, parent)

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _obj, _dtype) in enumerate(entry._list()):
                if name == part:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        pass


class ZfsFileSystem(LibyalFileSystem):
    """One ZFS dataset (or snapshot), read like a pytsk3.FS_Info."""

    KIND = 'ZFS'

    def __init__(self, zpl, size=0):
        self.zpl = zpl
        self.BLOCK_SIZE = 1 << 12
        super().__init__(_Volume(zpl), size, f"ZFS {zpl.name}")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return self.zpl.root

    def _last_identifier(self):
        meta = self.zpl.objset.meta
        return (meta.maxblkid + 1) * meta.datablksz // DNODE_SLOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return []

    def close(self):
        self.volume.close()


def open_dataset(pool, dataset, size=0):
    """A ZfsFileSystem over one of `pool.datasets`."""
    return ZfsFileSystem(ZplVolume(pool.open_dataset(dataset),
                                   dataset['name']), size)


def looks_like_label(head):
    """A quick look at the first 256 KiB of a partition: an XDR nvlist at
    16 KiB and an uberblock magic in the ring at 128 KiB. read_label then
    checks the label for real."""
    if len(head) < LABEL or head[NVLIST_OFFSET] != 1:
        return False
    magic = struct.pack('<Q', UB_MAGIC)
    ring = head[UBERBLOCK_OFFSET:UBERBLOCK_OFFSET + UBERBLOCK_RING]
    return any(ring[at:at + 8] == magic
               for at in range(0, len(ring), 1024))

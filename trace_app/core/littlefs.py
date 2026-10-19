"""LittleFS (v2) read in pure Python (no Qt).

The file system of microcontrollers: telematics units, IoT devices,
wearables, Zephyr/Mbed/ESP-IDF firmware's flash partitions. The Sleuth Kit
and libyal read none of it. Its layout, as littlefs's SPEC.md gives it and
lfs.c reads it:

* every block is a metadata block (directories, the superblock) or a data
  block; metadata blocks come in pairs, each a log of commits -- a 32-bit
  revision, then tags (big-endian, each XORed with the one before,
  starting from 0xFFFFFFFF) with their data, a CRC tag (CRC-32 over the
  commit, littlefs's: zlib's without the final inversion) closing each
  commit. Of a pair, the block with the newer revision is read, up to its
  last commit whose CRC holds;
* a tag: valid bit, an 11-bit type (NAME 0x0xx -- REG 0x001, DIR 0x002,
  SUPERBLOCK 0x0FF --, STRUCT 0x2xx -- DIRSTRUCT, INLINESTRUCT,
  CTZSTRUCT --, USERATTR 0x3xx, CREATE 0x401 / DELETE 0x4FF, TAIL
  0x6xx, MOVESTATE 0x7FF, CRC 0x5xx), a 10-bit id, a 10-bit length (0x3FF
  a deleted tag). Creates and deletes shift the ids after them; a lookup
  walks the log backwards following them (lfs_dir_getslice);
* blocks 0/1 hold the superblock ('littlefs', version, block size and
  count); the last pair holding it is the root directory. A directory is
  a chain of pairs joined by hard tails;
* a file is inline (its data in the tag) or a CTZ skip list: data blocks
  from the last back, block n holding ctz(n)+1 pointers before its data
  (lfs_ctz_index / lfs_ctz_find);
* global state: the XOR of every pair's move-state deltas; a move cut
  short by power loss names an entry that is to be read as gone.

No times or permissions (littlefs keeps none unless an application adds
user attributes). Live files only. Checked against littlefs itself
(littlefs-python, its C code) reading images it wrote with every
structure above (tools/testdata/build/make_littlefs.py;
tests/test_littlefs.py).
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup

logger = logging.getLogger('TRACE.LittleFS')

KIND = 'LittleFS'
MAGIC = b'littlefs'
NULL = 0xFFFFFFFF
TYPE_NAME, TYPE_STRUCT, TYPE_USERATTR, TYPE_SPLICE, TYPE_CRC, \
    TYPE_TAIL, TYPE_GLOBALS = 0x000, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700
REG, DIR, SUPERBLOCK = 0x001, 0x002, 0x0FF
DIRSTRUCT, INLINESTRUCT, CTZSTRUCT = 0x200, 0x201, 0x202
CREATE, DELETE = 0x401, 0x4FF
HARDTAIL = 0x601
MOVESTATE = 0x7FF
CCRC = 0x500
#: Block sizes tried when block 0 cannot say (its log is damaged).
BLOCK_SIZES = tuple(1 << n for n in range(7, 21))
#: Pairs followed, at most (a damaged tail chain must end).
MAX_PAIRS = 1 << 16
ROOT = 1


class LittleFsError(Exception):
    pass


def crc(value, data):
    """lfs_crc: CRC-32 (reflected 0xEDB88320), no final inversion."""
    return zlib.crc32(data, value ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def mktag(kind, ident, size):
    return (kind << 20) | (ident << 10) | size


def type1(tag):
    return (tag & 0x70000000) >> 20


def type2(tag):
    return (tag & 0x78000000) >> 20


def type3(tag):
    return (tag & 0x7FF00000) >> 20


def chunk(tag):
    return (tag & 0x0FF00000) >> 20


def splice(tag):
    value = chunk(tag)
    return value - 256 if value & 0x80 else value


def tag_id(tag):
    return (tag & 0x000FFC00) >> 10


def size_of(tag):
    return tag & 0x3FF


def is_delete(tag):
    return size_of(tag) == 0x3FF


def dsize(tag):
    return 4 + (0 if is_delete(tag) else size_of(tag))


def _popc(value):
    return bin(value).count('1')


def _ctz(value):
    return (value & -value).bit_length() - 1


def _npw2(value):
    return (value - 1).bit_length()


def _scmp(a, b):
    """lfs_scmp: sequence comparison of 32-bit revisions."""
    difference = (a - b) & 0xFFFFFFFF
    return difference - (1 << 32) if difference & 0x80000000 else difference


class _Dir:
    """One fetched metadata block: its valid tags (tag, data offset) in
    log order, the id count, tail and split."""

    __slots__ = ('pair', 'block', 'tags', 'count', 'tail', 'split',
                 'moves')

    def __init__(self, pair, block, tags, count, tail, split, moves):
        self.pair = pair
        self.block = block
        self.tags = tags
        self.count = count
        self.tail = tail
        self.split = split
        self.moves = moves


class LittleFsImage:
    def __init__(self, source):
        self.source = source
        source.seek(0, 2)
        self.size = source.tell()
        self.block_size = self._find_block_size()
        self.block_count = self.size // self.block_size
        self.gstate = None
        superblock = self._superblock_pair()
        self.root = superblock
        self.gstate = self._global_state()

    def _read(self, block, offset, length):
        if block >= getattr(self, 'block_count', block + 1):
            raise LittleFsError(f"block {block} is past the image")
        self.source.seek(block * self.block_size + offset)
        return self.source.read(length)

    def _find_block_size(self):
        """From block 0's superblock entry, or the first size at which
        block 1 opens with 'littlefs' after its revision."""
        self.source.seek(0)
        head = self.source.read(4096)
        if head[8:16] == MAGIC:
            for size in BLOCK_SIZES:
                if size > self.size:
                    break
                found = self._superblock_config(0, size)
                if found:
                    return found
        for size in BLOCK_SIZES:
            if 2 * size > self.size:
                break
            self.source.seek(size + 8)
            if self.source.read(8) == MAGIC:
                found = self._superblock_config(1, size)
                if found:
                    return found
        raise LittleFsError("no littlefs superblock")

    def _superblock_config(self, block, size):
        """The block size the superblock entry in `block` (read at block
        size `size`) records, when its first commit holds."""
        self.block_count = self.size // size
        self.block_size = size
        try:
            tags, _count, _tail, _split, _moves = self._log(block)
        except (LittleFsError, struct.error):
            return None
        for tag, at in tags:
            if type3(tag) == INLINESTRUCT and tag_id(tag) == 0 and \
                    size_of(tag) >= 12:
                version, block_size, count = struct.unpack(
                    '<III', self._read(block, at, 12))
                if version >> 16 == 2 and block_size == size:
                    return block_size
        return None

    def _log(self, block):
        """(valid tags, count, tail, split, move deltas) of one metadata
        block, as lfs_dir_fetchmatch reads it: every commit up to the last
        whose CRC holds."""
        size = self.block_size
        data = self._read(block, 0, size)
        if len(data) < 8:
            raise LittleFsError("short metadata block")
        value = crc(0xFFFFFFFF, data[:4])
        offset, previous = 0, 0xFFFFFFFF
        pending, count, tail, split, moves = [], 0, (NULL, NULL), False, []
        accepted = None
        while True:
            offset += dsize(previous)
            if offset + 4 > size:
                break
            raw = data[offset:offset + 4]
            value = crc(value, raw)
            tag = struct.unpack('>I', raw)[0] ^ previous
            if tag & 0x80000000:
                break                       # not yet programmed
            if offset + dsize(tag) > size:
                break
            previous = tag
            if type2(tag) == CCRC:
                stored = struct.unpack_from('<I', data, offset + 4)[0]
                if value != stored:
                    break
                previous ^= (chunk(tag) & 1) << 31
                accepted = (list(pending), count, tail, split, list(moves))
                value = 0xFFFFFFFF
                continue
            body = data[offset + 4:offset + dsize(tag)]
            value = crc(value, body)
            pending.append((tag, offset + 4))
            kind = type1(tag)
            if kind == TYPE_NAME:
                if tag_id(tag) >= count:
                    count = tag_id(tag) + 1
            elif kind == TYPE_SPLICE:
                count += splice(tag)
            elif kind == TYPE_TAIL:
                split = bool(chunk(tag) & 1)
                tail = struct.unpack_from('<II', body)
            elif type3(tag) == MOVESTATE and size_of(tag) >= 12:
                moves.append(body[:12])
        if accepted is None:
            raise LittleFsError(f"no valid commit in block {block}")
        return accepted

    def fetch(self, pair):
        """The newer of a pair's blocks (by revision, as lfs_dir_fetch),
        falling back to the other when its log holds no valid commit."""
        a, b = pair
        if a >= self.block_count or b >= self.block_count:
            raise LittleFsError(f"pair {pair} is past the image")
        revs = [struct.unpack('<I', self._read(n, 0, 4))[0] for n in pair]
        order = (0, 1) if _scmp(revs[0], revs[1]) >= 0 else (1, 0)
        last = None
        for which in order:
            try:
                tags, count, tail, split, moves = self._log(pair[which])
            except LittleFsError as exc:
                last = exc
                continue
            return _Dir((pair[which], pair[1 - which]), pair[which], tags,
                        count, tail, split, moves)
        raise last or LittleFsError(f"pair {pair} unreadable")

    def _superblock_pair(self):
        """The last pair of the threaded list from {0, 1} that holds the
        superblock: the root directory (lfs_mount)."""
        root, pair, seen = None, (0, 1), set()
        while pair != (NULL, NULL) and pair not in seen and \
                len(seen) < MAX_PAIRS:
            seen.add(pair)
            directory = self.fetch(pair)
            found = self.get(directory, 0x7FF, 0x3FF, SUPERBLOCK, 0)
            if found is not None and \
                    self._read(directory.block, found[1], 8) == MAGIC:
                root = pair
            pair = tuple(directory.tail)
        if root is None:
            raise LittleFsError("no superblock entry")
        return root

    def _global_state(self):
        """The move state, XOR of every pair's deltas (lfs_mount)."""
        state = bytearray(12)
        pair, seen = (0, 1), set()
        while pair != (NULL, NULL) and pair not in seen and \
                len(seen) < MAX_PAIRS:
            seen.add(pair)
            try:
                directory = self.fetch(pair)
            except LittleFsError:
                break
            for delta in directory.moves:
                for index in range(12):
                    state[index] ^= delta[index]
            pair = tuple(directory.tail)
        tag, block0, block1 = struct.unpack('<III', bytes(state))
        moving = tag & 0x7FFFFFFF
        if type3(moving) == DELETE:
            return (tag_id(moving), (block0, block1))
        return None

    def get(self, directory, type_mask, id_mask, kind, ident):
        """lfs_dir_getslice: the newest tag of `kind` for `ident` (matched
        on `type_mask` bits of the type), following creates and deletes
        backwards; (tag, data offset) or None."""
        gmask = mktag(type_mask, id_mask, 0)
        gtag = mktag(kind, ident, 0)
        gdiff = 0
        if self.gstate is not None and id_mask:
            move_id, move_pair = self.gstate
            if set(move_pair) == set(directory.pair):
                if move_id == ident:
                    return None
                if move_id < ident:
                    gdiff -= mktag(0, 1, 0)
        for tag, at in reversed(directory.tags):
            if id_mask and type1(tag) == TYPE_SPLICE and \
                    tag_id(tag) <= tag_id(gtag - gdiff):
                if tag == (mktag(CREATE, 0, 0) |
                           (mktag(0, 0x3FF, 0) & (gtag - gdiff))):
                    return None                 # created here: no older
                gdiff += splice(tag) << 10      # LFS_MKTAG(0, splice, 0)
            if (gmask & tag) == (gmask & (gtag - gdiff)):
                if is_delete(tag):
                    return None
                return tag + gdiff, at
        return None

    def entries(self, pair):
        """[(name, type, struct tag, data offset, block)] of a directory,
        across its chain of pairs."""
        out, seen = [], set()
        while pair != (NULL, NULL) and pair not in seen and \
                len(seen) < MAX_PAIRS:
            seen.add(pair)
            directory = self.fetch(pair)
            for ident in range(directory.count):
                name = self.get(directory, 0x780, 0x3FF, TYPE_NAME, ident)
                if name is None:
                    continue
                kind = type3(name[0])
                if kind not in (REG, DIR):
                    continue                    # the superblock entry
                raw = self._read(directory.block, name[1], size_of(name[0]))
                found = self.get(directory, 0x700, 0x3FF, TYPE_STRUCT, ident)
                out.append((raw, kind, found, directory.block,
                            (directory.pair, ident)))
            if not directory.split:
                break
            pair = tuple(directory.tail)
        return out

    def read_struct(self, block, struct_tag, offset, length):
        """Bytes of a file: inline in its metadata block, or by its CTZ
        skip list."""
        if struct_tag is None:
            return b''
        tag, at = struct_tag
        kind = type3(tag)
        if kind == INLINESTRUCT:
            size = size_of(tag)
            end = min(size, offset + length)
            return self._read(block, at + offset, max(0, end - offset))
        if kind == CTZSTRUCT:
            head, size = struct.unpack('<II', self._read(block, at, 8))
            return self._ctz_read(head, size, offset, length)
        return b''

    def _ctz_index(self, offset):
        size = offset
        b = self.block_size - 8
        index = size // b
        if index == 0:
            return 0, offset
        index = (size - 4 * (_popc(index - 1) + 2)) // b
        return index, size - b * index - 4 * _popc(index)

    def _ctz_find(self, head, size, position):
        current, _ = self._ctz_index(size - 1)
        target, inside = self._ctz_index(position)
        steps = 0
        while current > target:
            skip = min(_npw2(current - target + 1) - 1, _ctz(current))
            head = struct.unpack('<I', self._read(head, 4 * skip, 4))[0]
            current -= 1 << skip
            steps += 1
            if head >= self.block_count or steps > 64:
                raise LittleFsError("CTZ skip list points past the image")
        return head, inside

    def _ctz_read(self, head, size, offset, length):
        end = min(size, offset + length)
        out = bytearray()
        position = offset
        while position < end:
            block, inside = self._ctz_find(head, size, position)
            take = min(end - position, self.block_size - inside)
            out += self._read(block, inside, take)
            position += take
        return bytes(out)

    def allocated_ranges(self):
        """Every block reachable: metadata pairs (both blocks) and each
        file's CTZ blocks -- what lfs_fs_traverse visits."""
        blocks = set()
        pair, seen = (0, 1), set()
        while pair != (NULL, NULL) and pair not in seen and \
                len(seen) < MAX_PAIRS:
            seen.add(pair)
            blocks.update(pair)
            try:
                directory = self.fetch(pair)
            except LittleFsError:
                break
            for ident in range(directory.count):
                found = self.get(directory, 0x700, 0x3FF, TYPE_STRUCT,
                                 ident)
                if found is None or type3(found[0]) != CTZSTRUCT:
                    continue
                head, size = struct.unpack('<II', self._read(
                    directory.block, found[1], 8))
                blocks.update(self._ctz_blocks(head, size))
            pair = tuple(directory.tail)
        out = []
        for block in sorted(b for b in blocks if b < self.block_count):
            begin = block * self.block_size
            if out and out[-1][1] == begin:
                out[-1] = (out[-1][0], begin + self.block_size)
            else:
                out.append((begin, begin + self.block_size))
        return [(begin, end - begin) for begin, end in out]

    def _ctz_blocks(self, head, size):
        if not size:
            return []
        index, _ = self._ctz_index(size - 1)
        out = []
        while True:
            out.append(head)
            if index == 0 or head >= self.block_count:
                break
            head = struct.unpack('<I', self._read(head, 0, 4))[0]
            index -= 1
            if len(out) > self.block_count:
                break
        return out


class LittleFsEntry:
    def __init__(self, image, record, identifier, parent):
        self._image = image
        raw, kind, struct_tag, block, _where = record
        self._kind = kind
        self._struct = struct_tag
        self._block = block
        self.identifier = identifier
        self.parent_identifier = parent
        self.name = raw.decode('utf-8', 'surrogateescape')
        self.file_mode = (stat.S_IFDIR | 0o755) if kind == DIR else \
            (stat.S_IFREG | 0o644)
        self.size = 0
        if kind == REG and struct_tag is not None:
            tag, at = struct_tag
            if type3(tag) == INLINESTRUCT:
                self.size = size_of(tag)
            elif type3(tag) == CTZSTRUCT:
                self.size = struct.unpack('<II',
                                          image._read(block, at, 8))[1]
        self.owner_identifier = self.group_identifier = 0
        self._children = None

    def get_number_of_links(self):
        return 1

    symbolic_link_target = ''

    def _list(self):
        if self._kind != DIR:
            return []
        if self._children is None:
            if self._struct is None or type3(self._struct[0]) != DIRSTRUCT:
                self._children = []
            else:
                pair = struct.unpack('<II', self._image._read(
                    self._block, self._struct[1], 8))
                try:
                    self._children = self._image.entries(tuple(pair))
                except (LittleFsError, struct.error) as exc:
                    logger.warning("LittleFS folder %s unreadable: %s",
                                   self.name, exc)
                    self._children = []
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        return self._image.volume_entry(self._list()[index], self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if self._kind != REG:
            return b''
        return self._image.read_struct(self._block, self._struct, offset,
                                       length)


class _Volume(PathLookup):
    def __init__(self, image):
        self.image = image
        self.ids = {}                       # (pair, id) -> identifier
        self.entries = {}
        image.volume_entry = self._entry

    def _entry(self, record, parent):
        key = (frozenset(record[4][0]), record[4][1])
        identifier = self.ids.get(key)
        if identifier is None:
            identifier = len(self.ids) + 2
            self.ids[key] = identifier
        entry = LittleFsEntry(self.image, record, identifier, parent)
        self.entries[identifier] = entry
        return entry

    def get_root_directory(self):
        root = LittleFsEntry(self.image, (b'', DIR, None, 0, (None, 0)),
                             ROOT, ROOT)
        root._children = self.image.entries(self.image.root)
        root.name = ''
        return root

    def entry(self, identifier):
        if identifier == ROOT:
            return self.get_root_directory()
        if identifier not in self.entries:
            pending = [self.get_root_directory()]
            while pending and identifier not in self.entries:
                folder = pending.pop()
                for index in range(folder.number_of_sub_file_entries):
                    child = folder.get_sub_file_entry(index)
                    if stat.S_ISDIR(child.file_mode):
                        pending.append(child)
        return self.entries.get(identifier)


class LittleFsFileSystem(LibyalFileSystem):
    KIND = KIND

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.block_size
        super().__init__(_Volume(image), image.block_count * image.block_size,
                         f"LittleFS ({image.block_size}-byte blocks)")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()


def open_littlefs(source):
    try:
        source.seek(0, 2)
        if source.tell() < 256:
            return None
        # 'littlefs' at 8 in block 0 -- or in block 1, at whichever block
        # size it is (block 0 can be the pair's damaged half).
        image = LittleFsImage(source)
        fs = LittleFsFileSystem(image)
        fs.volume.get_root_directory()
        return fs
    except (LittleFsError, struct.error, OSError, IOError) as exc:
        logger.debug("Not LittleFS: %s", exc)
        return None

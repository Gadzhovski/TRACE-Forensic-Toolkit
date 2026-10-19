"""QNX4 read in pure Python (no Qt).

The file system of QNX 4 and of QNX Neutrino up to 6.3 (before QNX6
replaced it): older head units, industrial controllers, medical devices.
The Sleuth Kit and libyal read none of it. Its layout, as the Linux
kernel's read-only fs/qnx4 (include/uapi/linux/qnx4_fs.h) reads it,
little-endian, 512-byte blocks:

* block 0 the loader; block 1 the superblock: four 64-byte inode entries
  -- the root folder (named '/'), the inode file, boot and alternate boot;
* an inode entry: a 16-byte name, size, first extent (block, count --
  block numbers count from 1), the extent block chain ('IamXblk', 60
  extents each), creation/modification/access/change times (Unix
  seconds), extent count, mode, uid, gid, links, type and status;
* a folder's data is those entries, 8 to a block. Status bit 0 used, bit
  3 link: a link entry holds a 48-byte name and where the inode is kept
  in /.inodes (block counted from 1, index) -- long names and hard
  links. Other entries are inode number = block * 8 + index;
* /.bitmap: one bit per block, set = used.

QNX writes a new file's entry twice in its folder (the kernel's comment);
a name is listed once, the first entry, as the kernel's lookup finds it.
Deleted entries (name kept, status cleared) are listed as deleted when
every block of theirs is still free in the bitmap -- otherwise their
blocks hold other data now, and they are left out. Checked against the
Linux kernel's own reading of a real QNX4 floppy image (openqnx's
qnxfs.img; tests/test_qnx.py, key tools/testdata/build/make_kernel_keys.py).
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup

logger = logging.getLogger('TRACE.QNX4')

KIND = 'QNX4'
BLOCK = 512
ENTRY = 64
PER_BLOCK = BLOCK // ENTRY
ROOT = 1 * PER_BLOCK          # QNX4_ROOT_INO * QNX4_INODES_PER_BLOCK
USED, BUSY, LINK, INODE = 0x01, 0x04, 0x08, 0x10
XBLK_SIGNATURE = b'IamXblk'
#: Extent blocks followed for one file, at most (a damaged chain ends).
MAX_XBLKS = 1 << 16
_ENTRY = struct.Struct('<16sII I IIIIIHHHHH4sBB')


class Qnx4Error(Exception):
    pass


def _name(raw):
    return raw.split(b'\0', 1)[0]


class Qnx4Image:
    def __init__(self, source):
        self.source = source
        source.seek(0, 2)
        self.size = source.tell()
        superblock = self._read(BLOCK, BLOCK)
        if len(superblock) < BLOCK or superblock[:2] != b'/\0':
            raise Qnx4Error("no QNX4 root folder in block 1")
        self.root = self.inode(ROOT)
        if not stat.S_ISDIR(self.root['mode']):
            raise Qnx4Error("the root entry is not a folder")
        self.bitmap = None
        for _index, entry in self._raw_entries(self.root):
            if entry['name'] == b'.bitmap':
                self.bitmap = entry
                break
        if self.bitmap is None:
            raise Qnx4Error("no /.bitmap")
        self._bits = None

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    @staticmethod
    def parse(raw):
        (name, size, first_block, first_count, xblk, ftime, mtime, atime,
         ctime, extents, mode, uid, gid, nlink, _zero, ftype,
         status) = _ENTRY.unpack_from(raw)
        return {'name': _name(name), 'size': size,
                'first': (first_block, first_count), 'xblk': xblk,
                'created': ftime, 'mtime': mtime, 'atime': atime,
                'ctime': ctime, 'extents': extents, 'mode': mode,
                'uid': uid, 'gid': gid, 'nlink': nlink, 'type': ftype,
                'status': status}

    def inode(self, number):
        raw = self._read((number // PER_BLOCK) * BLOCK +
                         (number % PER_BLOCK) * ENTRY, ENTRY)
        if len(raw) < ENTRY:
            raise Qnx4Error(f"inode {number} is past the image")
        entry = self.parse(raw)
        entry['number'] = number
        return entry

    def extents(self, entry):
        """[(first physical block, count)] of a file, as qnx4_block_map
        walks them."""
        block, count = entry['first']
        out = [(block - 1, count)] if block and count else []
        remaining = entry['extents'] - 1
        xblk, seen = entry['xblk'], set()
        while remaining > 0 and xblk and xblk not in seen and \
                len(seen) < MAX_XBLKS:
            seen.add(xblk)
            raw = self._read((xblk - 1) * BLOCK, BLOCK)
            if len(raw) < BLOCK or raw[496:503] != XBLK_SIGNATURE:
                logger.warning("QNX4: extent block %d is not one", xblk)
                break
            following, _previous, number = struct.unpack_from('<IIB', raw)
            for index in range(min(number, 60, remaining)):
                block, count = struct.unpack_from('<II', raw, 16 + index * 8)
                if block and count:
                    out.append((block - 1, count))
                remaining -= 1
            xblk = following
        return out

    def read(self, entry, offset, length):
        end = min(entry['size'], offset + length)
        out = bytearray()
        position = 0
        for block, count in self.extents(entry):
            span = count * BLOCK
            if position + span > offset and position < end:
                start = max(offset, position)
                stop = min(end, position + span)
                out += self._read(block * BLOCK + start - position,
                                  stop - start)
            position += span
            if position >= end:
                break
        return bytes(out)

    def _raw_entries(self, folder):
        """(inode number, entry) of every slot of a folder that has a name,
        used or not, in order."""
        data_blocks = []
        for block, count in self.extents(folder):
            data_blocks.extend(range(block, block + count))
        blocks = (folder['size'] + BLOCK - 1) // BLOCK
        for block in data_blocks[:blocks]:
            raw = self._read(block * BLOCK, BLOCK)
            for index in range(PER_BLOCK):
                slot = raw[index * ENTRY:(index + 1) * ENTRY]
                if len(slot) < ENTRY or not slot[0]:
                    continue
                status = slot[63]
                if status & LINK:
                    name = _name(slot[:48])
                    inode_block, inode_index = struct.unpack_from('<IB',
                                                                  slot, 48)
                    number = (inode_block - 1) * PER_BLOCK + inode_index
                    try:
                        entry = self.inode(number)
                    except Qnx4Error:
                        continue
                    entry['name'] = name
                else:
                    number = block * PER_BLOCK + index
                    entry = self.parse(slot)
                    entry['number'] = number
                entry['live'] = bool(status & (USED | LINK))
                # A deleted entry has its used bit cleared and nothing else
                # set: busy (lost+found's placeholder), link and inode
                # entries are not files that were deleted.
                entry['gone'] = not status & (USED | BUSY | LINK | INODE)
                yield number, entry

    def _is_free(self, block):
        self._bitmap_bits()
        byte = block >> 3
        return byte < len(self._bits) and \
            not self._bits[byte] & (1 << (block & 7))

    def entries(self, folder):
        """The folder's entries: live ones once per name (the first), then
        deleted ones whose blocks are all free still."""
        out, names = [], set()
        deleted = []
        for number, entry in self._raw_entries(folder):
            if entry['name'] in (b'.', b'..'):
                continue
            if entry['live']:
                if entry['name'] not in names:
                    names.add(entry['name'])
                    out.append(entry)
            elif entry['gone']:
                deleted.append(entry)
        for entry in deleted:
            if entry['name'] in names or not stat.S_IFMT(entry['mode']):
                continue
            extents = self.extents(entry)
            if not extents and entry['size']:
                continue
            if all(self._is_free(block) for first, count in extents
                   for block in range(first, first + count)):
                entry['deleted'] = True
                names.add(entry['name'])
                out.append(entry)
        return out

    def volume_blocks(self):
        """The volume's length in blocks: what the bitmap counts, or the
        end of the superblock's own files if further -- openqnx's floppy
        has a bitmap of 2,048 blocks and a .boot running to block 2,688."""
        blocks = len(self._bitmap_bits()) * 8
        superblock = self._read(BLOCK, BLOCK)
        for index in range(4):
            entry = self.parse(superblock[index * ENTRY:(index + 1) * ENTRY])
            for first, count in self.extents(entry):
                blocks = max(blocks, first + count)
        for first, count in self.extents(self.bitmap):
            blocks = max(blocks, first + count)
        return min(blocks, self.size // BLOCK)

    def _bitmap_bits(self):
        if self._bits is None:
            self._bits = self.read(self.bitmap, 0, self.bitmap['size'])
        return self._bits

    def allocated_ranges(self):
        """Blocks the bitmap marks used, and every block past what it
        covers (nothing says those are free)."""
        bits = self._bitmap_bits()
        total = self.volume_blocks()
        covered = min(len(bits) * 8, total)
        out, start = [], None
        for block in range(covered):
            used = bits[block >> 3] & (1 << (block & 7))
            if used and start is None:
                start = block
            elif not used and start is not None:
                out.append((start * BLOCK, (block - start) * BLOCK))
                start = None
        if start is None and covered < total:
            start = covered
        if start is not None:
            out.append((start * BLOCK, (total - start) * BLOCK))
        return out


class Qnx4Entry:
    def __init__(self, image, entry, parent):
        self._image = image
        self._entry = entry
        self.identifier = entry['number']
        self.parent_identifier = parent
        self.name = entry['name'].decode('utf-8', 'surrogateescape')
        self.file_mode = entry['mode']
        self.size = 0 if stat.S_ISDIR(entry['mode']) else entry['size']
        self.owner_identifier = entry['uid']
        self.group_identifier = entry['gid']
        self.deleted = entry.get('deleted', False)

    def get_number_of_links(self):
        return self._entry['nlink'] or 1

    def get_modification_time_as_integer(self):
        return self._entry['mtime'] * 1_000_000_000

    def get_access_time_as_integer(self):
        return self._entry['atime'] * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._entry['ctime'] * 1_000_000_000

    def get_creation_time_as_integer(self):
        return self._entry['created'] * 1_000_000_000

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._image.read(self._entry, 0, self._entry['size']).rstrip(
            b'\0').decode('utf-8', 'surrogateescape')

    def _list(self):
        if not stat.S_ISDIR(self.file_mode):
            return []
        try:
            return self._image.entries(self._entry)
        except (Qnx4Error, struct.error) as exc:
            logger.warning("QNX4 folder %s unreadable: %s", self.name, exc)
            return []

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        return Qnx4Entry(self._image, self._list()[index], self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if stat.S_ISDIR(self.file_mode):
            return b''
        return self._image.read(self._entry, offset, length)


class _Volume(PathLookup):
    def __init__(self, image):
        self.image = image
        self._index = None

    def get_root_directory(self):
        root = Qnx4Entry(self.image, self.image.root, ROOT)
        root.name = ''
        return root

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
                    if child.identifier in self._index:
                        continue
                    self._index[child.identifier] = child
                    if stat.S_ISDIR(child.file_mode) and not child.deleted:
                        pending.append(child)
        return self._index.get(identifier)


class Qnx4FileSystem(LibyalFileSystem):
    KIND = KIND
    BLOCK_SIZE = BLOCK

    def __init__(self, image):
        self.image = image
        # Not the window's length: over a lost partition it runs to the
        # end of the disk.
        size = image.volume_blocks() * BLOCK
        super().__init__(_Volume(image), size, "QNX4")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()


def looks_like_qnx4(head):
    """Block 1 opens with the root folder's entry, named '/'."""
    return len(head) >= BLOCK + ENTRY and head[BLOCK:BLOCK + 2] == b'/\0' \
        and stat.S_ISDIR(struct.unpack_from('<H', head, BLOCK + 50)[0])


def open_qnx4(source):
    try:
        source.seek(0)
        if not looks_like_qnx4(source.read(BLOCK + ENTRY)):
            return None
        return Qnx4FileSystem(Qnx4Image(source))
    except (Qnx4Error, struct.error, OSError, IOError) as exc:
        logger.debug("Not QNX4: %s", exc)
        return None

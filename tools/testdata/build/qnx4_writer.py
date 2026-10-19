"""Write QNX4 file systems from a folder, for TRACE's reader (core/qnx4.py).

Nothing outside QNX writes QNX4, and QNX's own tools (dinit, mkqnx4fs) run
only on QNX. So the images are laid out here by the on-disk structures of
include/uapi/linux/qnx4_fs.h, as openqnx's real floppy (qnxfs.img) lays
them out, and **the answer key is the Linux kernel's reading of them**
(fs/qnx4, in a QEMU guest -- make_kernel_keys.py), never this writer's
idea of what it wrote. What the images hold, so every path the reader
takes is used:

* block 0 a loader, block 1 the superblock (root, /.inodes, .boot,
  .altboot), /.bitmap after it, /.inodes (64 slots);
* '.' and '..' as link entries, as QNX writes them;
* names over 16 bytes as link entries to an inode in /.inodes (up to the
  kernel's 48), a hard link as two link entries to one such inode; names
  longer than 48 bytes are not written (QNX4 has none);
* one file in 70 extents, so its extent blocks ('IamXblk', 60 a block)
  chain; a folder of 300 files in three extents;
* symbolic links (the target as the data), empty files, a sparse file
  (QNX4 has no holes: written out);
* `deleted`: files whose entry has its status cleared and whose blocks
  are free again -- the kernel lists none of them -- and one whose blocks
  another file took since (`reused`).

    write(folder, image, size, deleted=..., reused=...) -> what was left out
"""

import os
import stat
import struct

BLOCK = 512
ENTRY = 64
PER_BLOCK = 8
USED, LINK, INODE = 0x01, 0x08, 0x10
INODE_SLOTS = 64


def _entry(name, size=0, first=(0, 0), xblk=0, when=0, extents=0, mode=0,
           uid=0, gid=0, nlink=1, status=USED):
    return struct.pack('<16sIIIIIIIIHHHHH4sBB', name[:16], size, first[0],
                       first[1], xblk, when, when, when, when, extents, mode,
                       uid, gid, nlink, b'', 0, status)


def _link(name, inode_block, index, status=LINK):
    return struct.pack('<48sIB10sB', name, inode_block, index, b'', status)


class _Image:
    def __init__(self, size):
        self.blocks = size // BLOCK
        self.data = bytearray(self.blocks * BLOCK)
        self.used = bytearray((self.blocks + 7) // 8)
        self.next = 2

    def mark(self, block, used=True):
        if used:
            self.used[block >> 3] |= 1 << (block & 7)
        else:
            self.used[block >> 3] &= ~(1 << (block & 7)) & 0xFF

    def alloc(self, count):
        start = self.next
        if start + count > self.blocks:
            raise ValueError("the image is too small for the tree")
        for block in range(start, start + count):
            self.mark(block)
        self.next += count
        return start

    def put(self, block, data, offset=0):
        at = block * BLOCK + offset
        self.data[at:at + len(data)] = data


class _Writer:
    def __init__(self, image, when):
        self.image = image
        self.when = when
        self.inode_slot = 4                 # after the system files' slots
        self.inodes_start = None
        self.skipped = []
        self.long_inodes = {}               # source inode -> (block, index)

    def data(self, payload, pieces=1):
        """(extents [(block 1-based, count)], xblk) for `payload`, in
        `pieces` extents with a free block between each."""
        count = (len(payload) + BLOCK - 1) // BLOCK
        if not count:
            return [], 0
        extents = []
        sizes = [count // pieces + (1 if i < count % pieces else 0)
                 for i in range(pieces)]
        written = 0
        for size in sizes:
            if not size:
                continue
            start = self.image.alloc(size)
            self.image.put(start, payload[written * BLOCK:
                                          (written + size) * BLOCK])
            extents.append((start + 1, size))
            written += size
            if len(extents) < pieces:
                gap = self.image.alloc(1)
                self.image.mark(gap, False)
        return extents, self._xblks(extents[1:])

    def _xblks(self, rest):
        if not rest:
            return 0
        chunks = [rest[i:i + 60] for i in range(0, len(rest), 60)]
        blocks = [self.image.alloc(1) for _ in chunks]
        for number, chunk in enumerate(chunks):
            following = blocks[number + 1] + 1 if number + 1 < len(blocks) \
                else 0
            previous = blocks[number - 1] + 1 if number else 0
            raw = bytearray(BLOCK)
            struct.pack_into('<IIB3sI', raw, 0, following, previous,
                             len(chunk), b'', sum(c for _b, c in chunk))
            for index, (block, count) in enumerate(chunk):
                struct.pack_into('<II', raw, 16 + index * 8, block, count)
            raw[496:504] = b'IamXblk\0'
            struct.pack_into('<II', raw, 504, *chunk[0])
            self.image.put(blocks[number], bytes(raw))
        return blocks[0] + 1

    def inode_entry(self, name, payload, mode, nlink=1, pieces=1,
                    status=USED):
        extents, xblk = self.data(payload, pieces)
        return _entry(name, len(payload), extents[0] if extents else (0, 0),
                      xblk, self.when, len(extents), mode, 0, 0, nlink,
                      status)

    def folder(self, path, own, parent, pieces=1, extra=()):
        """Write folder `path`; `own` / `parent`: (inode block 1-based,
        index) of this folder's and its parent's entries."""
        names = sorted(os.listdir(path))
        slots = 2 + len(names) + len(extra)
        count = (slots + PER_BLOCK - 1) // PER_BLOCK
        extents, xblk = self.data(bytes(count * BLOCK), pieces)
        positions = [b - 1 + i for b, c in extents for i in range(c)]
        entries = [_link(b'.', *own), _link(b'..', *parent)]
        entries += list(extra)
        children = []
        for name in names:
            full = os.path.join(path, name)
            raw = os.fsencode(name)
            if len(raw) > 48:
                self.skipped.append(full)
                continue
            slot = len(entries)
            where = (positions[slot // PER_BLOCK] + 1, slot % PER_BLOCK)
            info = os.lstat(full)
            if stat.S_ISDIR(info.st_mode):
                entries.append(None)
                children.append((slot, full, where, raw))
                continue
            if stat.S_ISLNK(info.st_mode):
                payload, mode = os.fsencode(os.readlink(full)), 0o120777
            else:
                with open(full, 'rb') as handle:
                    payload = handle.read()
                mode = stat.S_IFREG | (info.st_mode & 0o777)
            many = 70 if name == 'video.bin' else 1
            if len(raw) > 16 or info.st_nlink > 1:
                key = (info.st_dev, info.st_ino)
                if key not in self.long_inodes:
                    block = self.inodes_start + self.inode_slot // PER_BLOCK
                    index = self.inode_slot % PER_BLOCK
                    self.inode_slot += 1
                    self.image.put(block, self.inode_entry(
                        raw, payload, mode, info.st_nlink, many,
                        USED | INODE), index * ENTRY)
                    self.long_inodes[key] = (block + 1, index)
                entries.append(_link(raw, *self.long_inodes[key]))
            else:
                entries.append(self.inode_entry(raw, payload, mode, 1, many))
        for slot, full, where, raw in children:
            name = os.path.basename(full)
            sub = 3 if name == 'many' else 1
            if len(raw) > 16:
                self.skipped.append(full)
                entries[slot] = bytes(ENTRY)
                continue
            extents_sub = self.folder(full, where, own, sub)
            extent_list, sub_xblk, sub_size = extents_sub
            entries[slot] = _entry(raw, sub_size, extent_list[0], sub_xblk,
                                   self.when, len(extent_list),
                                   stat.S_IFDIR | 0o755, 0, 0, 2)
        for slot, raw in enumerate(entries):
            if raw:
                block = positions[slot // PER_BLOCK]
                self.image.put(block, raw, (slot % PER_BLOCK) * ENTRY)
        return extents, xblk, count * BLOCK


def write(folder, target, size, deleted=None, reused=None, when=None):
    """A QNX4 image of `folder` at `target`. `deleted` {name: bytes} are
    written into the root and then deleted (status cleared, blocks freed);
    `reused` {name: bytes} the same, its blocks then taken by a file named
    'reused-by.bin'. Returns the paths not written (names over 48 bytes)."""
    image = _Image(size)
    when = int(when if when is not None else os.stat(folder).st_mtime)
    writer = _Writer(image, when)
    bitmap_blocks = (len(image.used) + BLOCK - 1) // BLOCK
    bitmap = image.alloc(bitmap_blocks)
    writer.inodes_start = image.alloc(INODE_SLOTS // PER_BLOCK)
    image.mark(0)
    image.mark(1)
    root_where = (2, 0)                      # the superblock's first slot
    extra = [_entry(b'.bitmap', len(image.used), (bitmap + 1, bitmap_blocks),
                    0, when, 1, stat.S_IFREG | 0o444),
             _link(b'.inodes', 2, 1), _link(b'.boot', 2, 2),
             _link(b'.altboot', 2, 3)]
    gone = []
    for name, payload in sorted((deleted or {}).items()):
        entry = writer.inode_entry(os.fsencode(name), payload,
                                   stat.S_IFREG | 0o644, status=0)
        gone.append(entry)
    reused_blocks = []
    for name, payload in sorted((reused or {}).items()):
        entry = writer.inode_entry(os.fsencode(name), payload,
                                   stat.S_IFREG | 0o644, status=0)
        gone.append(entry)
        first, count = struct.unpack_from('<II', entry, 20)
        reused_blocks.append((first - 1, count))
    root = writer.folder(folder, root_where, root_where,
                         extra=extra + gone)
    for entry in gone:
        first, count = struct.unpack_from('<II', entry, 20)
        for block in range(first - 1, first - 1 + count):
            image.mark(block, False)
    for first, count in reused_blocks:
        for block in range(first, first + count):
            image.mark(block)
    if reused_blocks:
        # The blocks belong to a live file now: its entry, in /.inodes.
        payload = b'the reused blocks now hold this file\n' * 40
        first, count = reused_blocks[0]
        payload = payload[:count * BLOCK]
        image.put(first, payload)
        slot = writer.inode_slot
        writer.inode_slot += 1
        block = writer.inodes_start + slot // PER_BLOCK
        image.put(block, _entry(b'reused-by.bin', len(payload),
                                (first + 1, count), 0, when, 1,
                                stat.S_IFREG | 0o644, 0, 0, 1,
                                USED | INODE), (slot % PER_BLOCK) * ENTRY)
        # ... and a name in the root's last free slot is not needed: the
        # kernel lists names, so the file gets one in a new root block.
        # Simplest: append a link entry to the root's last block.
        extents, xblk, root_size = root
        last = extents[-1][0] - 1 + extents[-1][1] - 1
        raw = image.data[last * BLOCK:(last + 1) * BLOCK]
        free = next((i for i in range(PER_BLOCK) if not raw[i * ENTRY]), None)
        if free is None:
            raise ValueError("no free slot in the root folder's last block")
        image.put(last, _link(b'reused-by.bin', block + 1,
                              slot % PER_BLOCK), free * ENTRY)
    extents, xblk, root_size = root
    superblock = _entry(b'/', root_size, extents[0], xblk, when,
                        len(extents), stat.S_IFDIR | 0o775, 0, 0, 3)
    superblock += _entry(b'', INODE_SLOTS * ENTRY,
                         (writer.inodes_start + 1, INODE_SLOTS // PER_BLOCK),
                         0, when, 1, stat.S_IFREG | 0o444, 0, 0, 1,
                         USED | INODE)
    superblock += _entry(b'', 0, (0, 0), 0, when, 0, stat.S_IFREG | 0o600,
                         0, 0, 1, USED | INODE)
    superblock += _entry(b'', 0, (0, 0), 0, when, 0, stat.S_IFREG | 0o600,
                         0, 0, 1, USED | INODE)
    image.put(1, superblock)
    image.put(bitmap, bytes(image.used))
    with open(target, 'wb') as handle:
        handle.write(image.data)
    return writer.skipped

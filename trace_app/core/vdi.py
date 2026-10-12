"""VirtualBox VDI disks, read in Python (no Qt).

No library with wheels reads VDI (libyal has none). The format
(VirtualBox's VDICore.h):

* a 64-byte text banner ("<<< Oracle VM VirtualBox Disk Image >>>"),
  then the signature 0xBEDA107F and version 1.1 at 0x40;
* header 1: image type (1 dynamic, 2 fixed, 4 differencing), where the
  block map and the data start, the disk's size, the block size (1 MiB)
  and extra bytes per block, the block count, and four UUIDs -- this
  image's, and for a differencing image its parent's (uuidLinkage);
* the block map: one 32-bit entry per block -- the index of the stored
  block, or 0xFFFFFFFF (never written: zeros, or the parent's for a
  differencing image) or 0xFFFFFFFE (written as zeros);
* stored block n at offData + n * (block + extra) + extra.

A differencing image (a VirtualBox snapshot) is read through its parent,
found beside it (or in the folder above, where VirtualBox keeps the base
disk) by the UUID it names.
"""

import os
import struct
import uuid

SIGNATURE = 0xBEDA107F
BLOCK_FREE = 0xFFFFFFFF
BLOCK_ZERO = 0xFFFFFFFE
TYPE_DYNAMIC, TYPE_FIXED, TYPE_UNDO, TYPE_DIFF = 1, 2, 3, 4
TYPE_NAMES = {TYPE_DYNAMIC: 'dynamic', TYPE_FIXED: 'fixed',
              TYPE_UNDO: 'undo', TYPE_DIFF: 'differencing'}
MAX_PARENTS = 64


class VdiError(Exception):
    pass


def is_vdi(head):
    return len(head) >= 0x48 and \
        struct.unpack_from('<I', head, 0x40)[0] == SIGNATURE


class VdiDisk:
    """One VDI file: libyal's shape (read_buffer_at_offset, get_size)."""

    def __init__(self, path, depth=0):
        self.path = path
        self._handle = open(path, 'rb')
        head = self._handle.read(0x200)
        if not is_vdi(head):
            self._handle.close()
            raise VdiError(f"{os.path.basename(path)} is not a VDI disk")
        version = struct.unpack_from('<I', head, 0x44)[0]
        if version >> 16 != 1:
            self._handle.close()
            raise VdiError(f"VDI version {version >> 16}.{version & 0xFFFF}"
                           f" is not read")
        (_header_size, self.type, _flags) = struct.unpack_from('<III',
                                                               head, 0x48)
        self.blocks_at, self.data_at = struct.unpack_from('<II', head,
                                                          0x154)
        (self.size, self.block_size, self.block_extra, self.block_count,
         self.allocated) = struct.unpack_from('<QIIII', head, 0x170)
        self.uuid = uuid.UUID(bytes_le=head[0x188:0x198])
        self.parent_uuid = uuid.UUID(bytes_le=head[0x1A8:0x1B8])
        if not self.block_size or self.block_count * self.block_size < \
                self.size:
            self._handle.close()
            raise VdiError("VDI block map does not cover the disk")
        self._handle.seek(self.blocks_at)
        raw = self._handle.read(4 * self.block_count)
        if len(raw) < 4 * self.block_count:
            self._handle.close()
            raise VdiError("VDI block map cut short")
        self.map = struct.unpack(f'<{self.block_count}I', raw)
        self.parent = None
        if self.type == TYPE_DIFF and self.parent_uuid.int:
            if depth >= MAX_PARENTS:
                raise VdiError("too many differencing levels")
            self.parent = _find_parent(path, self.parent_uuid, depth)

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        out = bytearray()
        end = min(offset + length, self.size)
        while offset < end:
            number, within = divmod(offset, self.block_size)
            take = min(end - offset, self.block_size - within)
            entry = self.map[number]
            if entry == BLOCK_FREE:
                if self.parent is not None:
                    out += self.parent.read_buffer_at_offset(take, offset)
                else:
                    out += bytes(take)
            elif entry == BLOCK_ZERO:
                out += bytes(take)
            else:
                self._handle.seek(self.data_at + entry * (
                    self.block_size + self.block_extra) + self.block_extra +
                    within)
                data = self._handle.read(take)
                if len(data) < take:
                    raise VdiError(f"block {number} past the end of the "
                                   f"file")
                out += data
            offset += take
        return bytes(out)

    def chain(self):
        disk, out = self, []
        while disk is not None:
            out.append(disk)
            disk = disk.parent
        return out

    def describe(self):
        chain = self.chain()
        text = (f"VirtualBox VDI ({TYPE_NAMES.get(self.type, self.type)}), "
                f"{self.size:,} bytes, {self.allocated:,} of "
                f"{self.block_count:,} blocks stored")
        if len(chain) > 1:
            text += ", on " + " <- ".join(os.path.basename(d.path)
                                          for d in chain[1:])
        return text

    def close(self):
        for disk in self.chain():
            try:
                disk._handle.close()
            except Exception:
                pass


def _find_parent(path, wanted, depth):
    """The VDI whose own UUID is `wanted`: beside `path`, or in the folder
    above (a VirtualBox VM keeps snapshots in Snapshots/)."""
    folder = os.path.dirname(os.path.abspath(path))
    for place in (folder, os.path.dirname(folder)):
        try:
            names = sorted(os.listdir(place))
        except OSError:
            continue
        for name in names:
            candidate = os.path.join(place, name)
            if not name.lower().endswith('.vdi') or \
                    os.path.abspath(candidate) == os.path.abspath(path):
                continue
            try:
                with open(candidate, 'rb') as handle:
                    head = handle.read(0x200)
            except OSError:
                continue
            if is_vdi(head) and \
                    uuid.UUID(bytes_le=head[0x188:0x198]) == wanted:
                return VdiDisk(candidate, depth + 1)
    raise VdiError(f"{os.path.basename(path)} is a differencing disk; its "
                   f"parent (UUID {wanted}) must be beside it or in the "
                   f"folder above")

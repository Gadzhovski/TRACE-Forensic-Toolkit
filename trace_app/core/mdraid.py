"""Linux software RAID (md) arrays, read from their members (no Qt).

A Linux server's disks are commonly mirrored or striped by md: each member
disk (or partition, type "Linux RAID") carries a superblock saying which
array it belongs to, its level, layout and chunk size, where its data
starts and which slot it fills. The Sleuth Kit sees a member as nothing it
can read -- or, for a mirror, sees its data a few sectors off.

* Superblocks: 0.90 (at the end of the device, aligned to 64 KiB), 1.0 (at
  the end), 1.1 (at the start) and 1.2 (4 KiB in, mdadm's default).
* Levels: 1 (any one member is the whole array), 0, 4, 5 and 6 with every
  layout mdadm writes by default and the classic alternatives
  (left/right, symmetric/asymmetric, parity first/last), and 10 in its
  "near" layout. One missing member of a 4, 5 or 6 array is rebuilt from
  parity (XOR); two missing in a 6 are refused rather than guessed.

`superblock(read, size)` describes one member; `Array(members)` reads the
array from members given as (Member, read function). `MdImgInfo` is
pytsk3's view of it, for ImageHandler.
"""

import logging
import struct

logger = logging.getLogger('TRACE.MdRaid')

MAGIC = 0xA92B4EFC
SECTOR = 512

# RAID 4/5/6 layouts (drivers/md/raid5.h).
LEFT_ASYMMETRIC, RIGHT_ASYMMETRIC, LEFT_SYMMETRIC, RIGHT_SYMMETRIC = 0, 1, 2, 3
PARITY_0, PARITY_N = 4, 5
LAYOUT_NAMES = {LEFT_ASYMMETRIC: 'left-asymmetric',
                RIGHT_ASYMMETRIC: 'right-asymmetric',
                LEFT_SYMMETRIC: 'left-symmetric',
                RIGHT_SYMMETRIC: 'right-symmetric',
                PARITY_0: 'parity-first', PARITY_N: 'parity-last'}

ROLE_SPARE, ROLE_FAULTY = 0xFFFF, 0xFFFE


class MdError(Exception):
    """Not an md member, or an array this module cannot read."""


class Member:
    """What one member's superblock says."""

    def __init__(self, **facts):
        self.__dict__.update(facts)

    @property
    def array_bytes(self):
        """The array's size, from this member's view of it."""
        data = self.raid_disks - {0: 0, 1: self.raid_disks - 1, 4: 1, 5: 1,
                                  6: 2, 10: 0}.get(self.level, 0)
        if self.level == 10:
            copies = (self.layout & 0xFF) * ((self.layout >> 8) & 0xFF) or 2
            return self.device_bytes * self.raid_disks // copies
        return self.device_bytes * max(1, data)

    def describe(self):
        layout = LAYOUT_NAMES.get(self.layout, str(self.layout)) \
            if self.level in (4, 5, 6) else (
                f"near={self.layout & 0xFF}" if self.level == 10 else '')
        name = f"RAID{self.level}" + (f", {layout}" if layout else '')
        return (f"Linux RAID member ({name}, slot {self.role + 1} of "
                f"{self.raid_disks}, superblock {self.version}"
                f"{', ' + self.name if self.name else ''})")


def _v1(block, offset_bytes, size):
    magic, major, _feature = struct.unpack_from('<III', block, 0)
    if magic != MAGIC or major != 1:
        return None
    uuid = block[16:32]
    name = block[32:64].split(b'\0', 1)[0].decode('utf-8', 'replace')
    level, layout, used = struct.unpack_from('<iIQ', block, 72)
    chunk, raid_disks = struct.unpack_from('<II', block, 88)
    data_offset, data_size, super_offset = struct.unpack_from('<QQQ', block,
                                                              128)
    dev_number = struct.unpack_from('<I', block, 160)[0]
    events = struct.unpack_from('<Q', block, 200)[0]
    max_dev = struct.unpack_from('<I', block, 220)[0]
    role = ROLE_SPARE
    if dev_number < max_dev and 256 + 2 * dev_number + 2 <= len(block):
        role = struct.unpack_from('<H', block, 256 + 2 * dev_number)[0]
    version = {0: '1.1', 8: '1.2'}.get(super_offset, '1.0')
    # RAID0 leaves the used size 0: its members' data size is the stripe.
    usable = used or data_size
    if level == 0 and chunk:
        usable -= usable % chunk
    return Member(uuid=bytes(uuid), name=name.split(':')[-1], level=level,
                  layout=layout, chunk=chunk * SECTOR,
                  raid_disks=raid_disks, data_offset=data_offset * SECTOR,
                  device_bytes=usable * SECTOR, role=role, events=events,
                  version=version)


def _v090(block):
    magic, major = struct.unpack_from('<II', block, 0)
    if magic != MAGIC or major != 0:
        return None
    uuid0 = struct.unpack_from('<I', block, 20)[0]
    level, size_kib, _nr, raid_disks = struct.unpack_from('<iIII', block, 28)
    uuid1, uuid2, uuid3 = struct.unpack_from('<III', block, 52)
    events_hi, events_lo = struct.unpack_from('<II', block, 32 * 4 + 7 * 4)
    layout, chunk = struct.unpack_from('<II', block, 64 * 4)
    # this_disk: word 992 -- number, major, minor, raid_disk, state.
    raid_disk = struct.unpack_from('<I', block, 992 * 4 + 12)[0]
    uuid = struct.pack('<IIII', uuid0, uuid1, uuid2, uuid3)
    return Member(uuid=uuid, name='', level=level, layout=layout,
                  chunk=chunk, raid_disks=raid_disks, data_offset=0,
                  device_bytes=size_kib * 1024, role=raid_disk,
                  events=(events_hi << 32) | events_lo, version='0.90')


def superblock(read, size):
    """The Member a device of `size` bytes is, read through
    `read(offset, length)`; None when it carries no md superblock."""
    candidates = [(4096, 'v1'), (0, 'v1')]
    if size >= 16 * SECTOR:
        candidates.append((((size // SECTOR - 16) & ~7) * SECTOR, 'v1'))
    if size >= 128 * 1024:
        candidates.append(((size & ~(65536 - 1)) - 65536, 'v090'))
    for offset, kind in candidates:
        try:
            block = read(offset, 4096)
        except Exception:
            continue
        if len(block) < 1024:
            continue
        member = _v1(block, offset, size) if kind == 'v1' else _v090(block)
        if member is not None and member.level in (0, 1, 4, 5, 6, 10):
            return member
    return None


class Array:
    """An md array read from its members: [(Member, read)]."""

    def __init__(self, members):
        if not members:
            raise MdError("No members")
        first = members[0][0]
        for member, _read in members:
            if member.uuid != first.uuid:
                raise MdError("Members of different arrays")
        self.level = first.level
        self.layout = first.layout
        self.chunk = first.chunk
        self.raid_disks = first.raid_disks
        self.name = first.name
        self.uuid = first.uuid
        # The newest superblock says how big the array is now.
        newest = max(members, key=lambda m: m[0].events)[0]
        self.size = newest.array_bytes
        self.slots = {}
        for member, read in sorted(members, key=lambda m: -m[0].events):
            if member.role < self.raid_disks and member.role not in \
                    self.slots:
                self.slots[member.role] = (member.data_offset, read)
        self.parity = {0: 0, 1: 0, 4: 1, 5: 1, 6: 2, 10: 0}[self.level]
        missing = self.raid_disks - len(self.slots)
        if self.level == 1:
            if not self.slots:
                raise MdError("No member of the mirror is here")
        elif self.level in (0, 10):
            if self.level == 10 and (self.layout >> 8) & 0xFF not in (0, 1):
                raise MdError("RAID10 far/offset layouts are not read")
            if self.level == 10:
                near = self.layout & 0xFF or 2
                for chunk_number in range(self.raid_disks):
                    copies = {(chunk_number * near + k) % self.raid_disks
                              for k in range(near)}
                    if not copies & set(self.slots):
                        raise MdError(
                            f"RAID10 needs a member of every mirrored "
                            f"pair; {missing} of {self.raid_disks} missing")
            if self.level == 0 and missing:
                raise MdError(f"RAID0 needs all {self.raid_disks} members; "
                              f"{missing} missing")
        elif missing > 1 or (missing and self.level == 6 and
                              self.raid_disks - missing < self.raid_disks - 1):
            raise MdError(f"{missing} members of a RAID{self.level} missing:"
                          f" it cannot be rebuilt")
        if self.level in (4, 5, 6) and self.level != 4 and \
                self.layout not in LAYOUT_NAMES:
            raise MdError(f"RAID{self.level} layout {self.layout} not read")
        self.missing = missing

    def describe(self):
        return (f"RAID{self.level} '{self.name or self.uuid.hex()[:8]}', "
                f"{len(self.slots)} of {self.raid_disks} members"
                + (f" ({self.missing} rebuilt from parity)"
                   if self.missing and self.level in (4, 5, 6) else ''))

    # --- where an array byte lives ------------------------------------------

    def _member_read(self, slot, offset, length):
        data_offset, read = self.slots[slot]
        data = read(data_offset + offset, length)
        return data + b'\0' * (length - len(data))

    def _locate(self, chunk_number):
        """(slot, member chunk index, parity slots) of a data chunk."""
        n = self.raid_disks
        if self.level == 0:
            return chunk_number % n, chunk_number // n, ()
        if self.level == 10:
            near = self.layout & 0xFF or 2
            position = chunk_number * near
            return position % n, position // n, ()
        data = n - self.parity
        stripe, index = divmod(chunk_number, data)
        if self.level == 4:
            return index, stripe, (n - 1,)
        layout = self.layout
        if self.level == 5:
            if layout == LEFT_ASYMMETRIC:
                pd = data - stripe % n
                slot = index + 1 if index >= pd else index
            elif layout == RIGHT_ASYMMETRIC:
                pd = stripe % n
                slot = index + 1 if index >= pd else index
            elif layout == LEFT_SYMMETRIC:
                pd = data - stripe % n
                slot = (pd + 1 + index) % n
            elif layout == RIGHT_SYMMETRIC:
                pd = stripe % n
                slot = (pd + 1 + index) % n
            elif layout == PARITY_0:
                pd, slot = 0, index + 1
            else:                                   # PARITY_N
                pd, slot = data, index
            return slot, stripe, (pd,)
        # RAID6
        if layout == LEFT_SYMMETRIC:
            pd = n - 1 - stripe % n
            qd = (pd + 1) % n
            slot = (pd + 2 + index) % n
        elif layout == RIGHT_SYMMETRIC:
            pd = stripe % n
            qd = (pd + 1) % n
            slot = (pd + 2 + index) % n
        elif layout in (LEFT_ASYMMETRIC, RIGHT_ASYMMETRIC):
            pd = n - 1 - stripe % n if layout == LEFT_ASYMMETRIC \
                else stripe % n
            qd = pd + 1
            if pd == n - 1:
                slot, qd = index + 1, 0
            else:
                slot = index + 2 if index >= pd else index
        elif layout == PARITY_0:
            pd, qd, slot = 0, 1, index + 2
        else:                                       # PARITY_N
            pd, qd, slot = data, data + 1, index
        return slot, stripe, (pd, qd)

    def _chunk_piece(self, chunk_number, within, length):
        if self.level == 1:
            slot = next(iter(self.slots))
            return self._member_read(slot, chunk_number * self.chunk +
                                     within, length)
        slot, member_chunk, parity = self._locate(chunk_number)
        offset = member_chunk * self.chunk + within
        if self.level == 10:
            near = self.layout & 0xFF or 2
            for copy in range(near):
                where = (chunk_number * near + copy)
                candidate = where % self.raid_disks
                if candidate in self.slots:
                    return self._member_read(candidate,
                                             (where // self.raid_disks) *
                                             self.chunk + within, length)
            raise MdError("Every copy of a RAID10 chunk is missing")
        if slot in self.slots:
            return self._member_read(slot, offset, length)
        # Rebuild a missing member's chunk: XOR of the stripe's others and
        # its P parity (RAID6's Q is not needed for one missing member).
        result = 0
        others = [s for s in range(self.raid_disks)
                  if s != slot and (len(parity) < 2 or s != parity[1])]
        for other in others:
            if other not in self.slots:
                raise MdError("Cannot rebuild: another member is missing")
            # Whole chunks XORed as integers: one C operation, not a
            # Python loop per byte.
            result ^= int.from_bytes(
                self._member_read(other, offset, length), 'little')
        return result.to_bytes(length, 'little')

    def read(self, offset, length):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        if self.level == 1:
            return self._chunk_piece(0, offset, length)
        out = bytearray()
        while length > 0:
            chunk_number, within = divmod(offset, self.chunk)
            part = min(length, self.chunk - within)
            out += self._chunk_piece(chunk_number, within, part)
            offset += part
            length -= part
        return bytes(out)


try:
    import pytsk3

    class MdImgInfo(pytsk3.Img_Info):
        """pytsk3's view of an array, for ImageHandler."""

        def __init__(self, array, keep=()):
            self._array = array
            self._keep = list(keep)
            super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):
            return self._array.read(offset, length)

        def get_size(self):
            return self._array.size

        def close(self):
            for thing in self._keep:
                try:
                    thing.close()
                except Exception:
                    pass
except ImportError:                                   # pragma: no cover
    MdImgInfo = None


def member_read(read, size):
    """(Member, read) for one device, or None."""
    member = superblock(read, size)
    return (member, read) if member is not None else None

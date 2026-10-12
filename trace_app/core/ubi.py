"""UBI images (raw NAND flash dumps of embedded Linux), read in Python (no
Qt).

UBI is the volume layer under UBIFS on raw flash -- routers, cameras,
set-top boxes, IoT boards -- and a firmware image or a chip-off dump is a UBI
image. It is a sequence of physical erase blocks (PEBs) of one size, each
holding (drivers/mtd/ubi/ubi-media.h, all big-endian):

* an erase-counter header 'UBI#' (64 bytes): the offsets of the volume
  header and of the data, and the image sequence number;
* a volume-identifier header 'UBI!' (64 bytes) if the block is in use: the
  volume, the logical erase block (LEB) it holds, a sequence number, and for
  static volumes the data size, used blocks and data CRC;
* the data: one LEB of the volume.

The volume table (two copies of the layout volume, 0x7FFFEFFF) names each
volume (128 at most), its type (dynamic: a file system, UBIFS; static: a
blob such as a kernel, with its exact size), its reserved blocks and data
padding. A LEB can be in two PEBs at once (wear levelling copies it before
erasing the old one): the higher sequence number wins, unless it is a copy
whose data CRC fails (the copy was interrupted). A LEB in no PEB is
unmapped and reads as erased flash (0xFF), as UBIFS expects.

The PEB size is recorded nowhere: it is the distance between erase-counter
headers. CRCs are the kernel's crc32 seeded with ~0 and not inverted after
-- zlib's crc32 ^ 0xFFFFFFFF. Fastmap (a cache of this scan) is not needed
and not read: every block is scanned.
"""

import logging
import struct
import zlib

logger = logging.getLogger('TRACE.UBI')

EC_MAGIC = b'UBI#'
VID_MAGIC = b'UBI!'
HEADER = 64
LAYOUT_VOLUME = 0x7FFFEFFF
VTBL_RECORD = 172
DYNAMIC, STATIC = 1, 2
#: PEB sizes tried, smallest first (NOR: 64 KiB; NAND: 128 KiB - 2 MiB;
#: some NOR parts 4-32 KiB).
PEB_SIZES = [1 << shift for shift in range(12, 22)]


class UbiError(Exception):
    pass


def crc32(data):
    """UBI's (and UBIFS's) CRC: seeded with ~0, not inverted."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


def ec_header(block):
    """The fields of an erase-counter header, or None."""
    if len(block) < HEADER or block[:4] != EC_MAGIC:
        return None
    if crc32(block[:60]) != struct.unpack_from('>I', block, 60)[0]:
        return None
    version, = struct.unpack_from('>B', block, 4)
    ec, vid_offset, data_offset, image_seq = \
        struct.unpack_from('>QIII', block, 8)
    return {'version': version, 'ec': ec, 'vid_offset': vid_offset,
            'data_offset': data_offset, 'image_seq': image_seq}


def vid_header(block):
    if len(block) < HEADER or block[:4] != VID_MAGIC:
        return None
    if crc32(block[:60]) != struct.unpack_from('>I', block, 60)[0]:
        return None
    (vol_type, copy_flag, compat, vol_id, lnum) = \
        struct.unpack_from('>BBBII', block, 5)
    data_size, used_ebs, data_pad, data_crc = \
        struct.unpack_from('>IIII', block, 20)
    sqnum, = struct.unpack_from('>Q', block, 40)
    return {'vol_type': vol_type, 'copy_flag': copy_flag, 'compat': compat,
            'vol_id': vol_id, 'lnum': lnum, 'data_size': data_size,
            'used_ebs': used_ebs, 'data_pad': data_pad, 'data_crc': data_crc,
            'sqnum': sqnum}


def is_ubi(head):
    return ec_header(head[:HEADER]) is not None


class UbiVolume:
    """One volume: libyal's shape (read_buffer_at_offset, get_size) over its
    LEBs end to end."""

    def __init__(self, image, vol_id, record):
        self._image = image
        self.vol_id = vol_id
        self.name = record['name']
        self.vol_type = record['vol_type']
        self.leb_size = image.leb_size - record['data_pad']
        self._lebs = image.lebs.get(vol_id, {})
        self.data_pad = record['data_pad']
        if self.vol_type == STATIC:
            self.size = self._static_size()
        else:
            self.size = record['reserved_pebs'] * self.leb_size
        self.readable = True

    def _static_size(self):
        """A static volume's bytes: its used blocks, the last one's data
        size."""
        if not self._lebs:
            return 0
        header = next(iter(self._lebs.values()))[1]
        used = header['used_ebs']
        last = self._lebs.get(used - 1)
        if last is None:
            return used * self.leb_size
        return (used - 1) * self.leb_size + last[1]['data_size']

    @property
    def kind(self):
        return 'static' if self.vol_type == STATIC else 'dynamic'

    def get_size(self):
        return self.size

    def leb(self, lnum):
        """LEB `lnum`'s bytes; erased flash when it is unmapped."""
        found = self._lebs.get(lnum)
        if found is None:
            return b'\xff' * self.leb_size
        peb, _header = found
        return self._image.read_data(peb, self.leb_size)

    def read_buffer_at_offset(self, length, offset):
        out = bytearray()
        end = min(offset + length, self.size)
        while offset < end:
            lnum, inside = divmod(offset, self.leb_size)
            piece = self.leb(lnum)[inside:inside + end - offset]
            if not piece:
                break
            out += piece
            offset += len(piece)
        return bytes(out)

    def read(self, offset, length):
        return self.read_buffer_at_offset(length, offset)

    def close(self):
        pass


class UbiImage:
    """A UBI image read through `source` (a file object)."""

    def __init__(self, source, size=None):
        self._source = source
        if size is None:
            source.seek(0, 2)
            size = source.tell()
        self.size = size
        first = ec_header(self._read(0, HEADER))
        if first is None:
            raise UbiError("no UBI erase-counter header at the start")
        self.vid_offset = first['vid_offset']
        self.data_offset = first['data_offset']
        self.image_seq = first['image_seq']
        self.peb_size = self._peb_size()
        self.leb_size = self.peb_size - self.data_offset
        self.peb_count = size // self.peb_size
        self.bad = []
        self.lebs = {}
        self._scan()
        self.volumes = self._volume_table()

    def _read(self, offset, length):
        self._source.seek(offset)
        return self._source.read(length)

    def _peb_size(self):
        for size in PEB_SIZES:
            if size <= self.data_offset or size * 2 > self.size:
                continue
            if ec_header(self._read(size, HEADER)) is not None:
                return size
        if self.size > self.data_offset:
            # A one-block image: the block is the image.
            for size in PEB_SIZES:
                if size == self.size:
                    return size
        raise UbiError("erase block size not found")

    def read_data(self, peb, length):
        return self._read(peb * self.peb_size + self.data_offset, length)

    def _scan(self):
        """Every PEB's headers; for each (volume, LEB) the PEB that holds
        its current copy."""
        candidates = {}
        for peb in range(self.peb_count):
            base = peb * self.peb_size
            head = self._read(base, max(self.vid_offset + HEADER, HEADER))
            ec = ec_header(head[:HEADER])
            if ec is None:
                if head[:4] == EC_MAGIC:
                    self.bad.append(peb)
                continue
            vid = vid_header(head[self.vid_offset:self.vid_offset + HEADER])
            if vid is None:
                continue                     # erased, free
            candidates.setdefault((vid['vol_id'], vid['lnum']), []).append(
                (vid['sqnum'], peb, vid))
        for (vol_id, lnum), copies in candidates.items():
            copies.sort(key=lambda c: c[0], reverse=True)
            chosen = copies[0]
            if len(copies) > 1 and chosen[2]['copy_flag'] and \
                    not self._data_ok(chosen[1], chosen[2]):
                chosen = copies[1]
            self.lebs.setdefault(vol_id, {})[lnum] = (chosen[1], chosen[2])

    def _data_ok(self, peb, vid):
        data = self.read_data(peb, vid['data_size'])
        return crc32(data) == vid['data_crc']

    def _volume_table(self):
        layout = self.lebs.get(LAYOUT_VOLUME, {})
        for lnum in sorted(layout):
            peb, _vid = layout[lnum]
            table = self.read_data(peb, self.leb_size)
            records = self._records(table)
            if records is not None:
                return records
        raise UbiError("no readable volume table")

    def _records(self, table):
        out = []
        for vol_id in range(min(128, len(table) // VTBL_RECORD)):
            record = table[vol_id * VTBL_RECORD:(vol_id + 1) * VTBL_RECORD]
            if crc32(record[:-4]) != struct.unpack_from('>I', record,
                                                       VTBL_RECORD - 4)[0]:
                return None
            reserved, alignment, data_pad, vol_type, upd_marker, name_len = \
                struct.unpack_from('>IIIBBH', record)
            if not reserved:
                continue
            name = record[16:16 + min(name_len, 127)].decode(
                'utf-8', 'replace')
            out.append(UbiVolume(self, vol_id, {
                'name': name, 'vol_type': vol_type, 'data_pad': data_pad,
                'reserved_pebs': reserved, 'alignment': alignment,
                'updating': bool(upd_marker),
                'flags': record[144]}))
        return out

    def describe(self):
        parts = [f"UBI image: {self.peb_count:,} erase blocks of "
                 f"{self.peb_size // 1024} KiB"]
        for volume in self.volumes:
            parts.append(f"volume {volume.vol_id} '{volume.name}' "
                         f"({volume.kind}, {volume.size:,} bytes)")
        if self.bad:
            parts.append(f"{len(self.bad)} unreadable erase-counter "
                         f"headers")
        return '; '.join(parts)

    @property
    def groups(self):
        return [('ubi', 0)]

    @property
    def partitions(self):
        return self.volumes


def open_ubi(source):
    try:
        return UbiImage(source)
    except (UbiError, struct.error) as exc:
        raise UbiError(f"UBI image unreadable: {exc}") from exc

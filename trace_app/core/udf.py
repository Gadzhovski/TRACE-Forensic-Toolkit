"""UDF volumes, read in Python (no Qt).

UDF (ECMA-167 with OSTA's UDF 1.02-2.60) is the file system of DVDs and
Blu-ray discs, of Windows install media (where the ISO 9660 side holds only
a note saying so, and files over 4 GB live only in UDF), of packet-written
CD-RW/DVD-RW and of some USB drives and cameras. The Sleuth Kit does not
read it. The layout:

* a volume recognition sequence at 32 KiB (BEA01, NSR02/NSR03, TEA01);
* an Anchor Volume Descriptor Pointer at block 256 (and at the end),
  whose block size is the volume's: it points to the Volume Descriptor
  Sequence -- Partition Descriptors (where each partition starts), and the
  Logical Volume Descriptor (logical block size, the partition maps, and
  where the File Set Descriptor is);
* partition maps: type 1 (a partition as it is), sparable (rewritable
  media: packets remapped by a sparing table), virtual (write-once media:
  blocks looked up in the Virtual Allocation Table, a file near the end of
  what was written) and metadata (UDF 2.50+: directories and file entries
  inside a metadata file, with a mirror);
* the File Set Descriptor names the root directory's ICB: a File Entry or
  Extended File Entry (times with a time zone, size, owner) whose
  allocation descriptors (short, long or extended; or the data itself,
  inline) say where the data is. A directory's data is a run of File
  Identifier Descriptors: name (OSTA compressed Unicode), the ICB it names,
  and flags -- one of them "deleted";
* the partition's space bitmap says which blocks are free.

Every reference is a (partition, logical block) pair, translated through
its partition map. Entries speak libyal's vocabulary, so core/libyal_fs
presents them like every other file system. A deleted directory entry
whose File Entry still reads is listed, marked deleted -- its data may
have been reused since, as with any deleted file.
"""

import calendar
import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.UDF')

VRS_START = 32768
ANCHOR_BLOCK = 256
BLOCK_SIZES = (2048, 512, 4096, 1024)

# Descriptor tags.
TAG_PVD, TAG_AVDP, TAG_VDP, TAG_IUVD, TAG_PD, TAG_LVD, TAG_USD, TAG_TD, \
    TAG_LVID = 1, 2, 3, 4, 5, 6, 7, 8, 9
TAG_FSD, TAG_FID, TAG_AED, TAG_IE, TAG_TE, TAG_FE, TAG_EAHD, TAG_USE, \
    TAG_SBD, TAG_PIE, TAG_EFE = 256, 257, 258, 259, 260, 261, 262, 263, \
    264, 265, 266

# ICB file types.
FT_DIRECTORY, FT_FILE, FT_BLOCK, FT_CHAR, FT_FIFO, FT_SOCKET, \
    FT_SYMLINK, FT_STREAMDIR = 4, 5, 6, 7, 9, 10, 12, 13
FT_VAT20 = 248
_MODES = {FT_DIRECTORY: stat.S_IFDIR, FT_FILE: stat.S_IFREG,
          FT_BLOCK: stat.S_IFBLK, FT_CHAR: stat.S_IFCHR,
          FT_FIFO: stat.S_IFIFO, FT_SOCKET: stat.S_IFSOCK,
          FT_SYMLINK: stat.S_IFLNK, FT_STREAMDIR: stat.S_IFDIR}

# Allocation descriptor kinds (ICB tag flags, bits 0-2).
AD_SHORT, AD_LONG, AD_EXTENDED, AD_INLINE = 0, 1, 2, 3
# Extent types (the length's top two bits).
EXT_RECORDED, EXT_ALLOCATED, EXT_SPARSE, EXT_NEXT = 0, 1, 2, 3

# File Identifier characteristics.
FID_HIDDEN, FID_DIRECTORY, FID_DELETED, FID_PARENT = 1, 2, 4, 8

#: Largest file entry, directory or symlink read whole.
MAX_METADATA = 64 << 20


class UdfError(Exception):
    pass


def _tag(data, offset=0):
    """(identifier, location) of a descriptor tag whose checksum holds,
    else None."""
    if len(data) < offset + 16:
        return None
    head = data[offset:offset + 16]
    checksum = (sum(head[:4]) + sum(head[5:16])) & 0xFF
    if checksum != head[4]:
        return None
    identifier, _version, _checksum, _reserved, _serial, _crc, _crc_len, \
        location = struct.unpack('<HHBBHHHI', head)
    return identifier, location


def cs0(data):
    """OSTA compressed Unicode: an 8-bit or a 16-bit (big-endian) form,
    said by the first byte."""
    if not data:
        return ''
    form, body = data[0], data[1:]
    if form in (8, 254):
        return body.decode('latin-1')
    if form in (16, 255):
        return body[:len(body) // 2 * 2].decode('utf-16-be', 'replace')
    return body.decode('latin-1', 'replace')


def dstring(data):
    """A fixed-length field: CS0, its used length in the last byte."""
    if not data:
        return ''
    used = data[-1]
    return cs0(data[:used]) if used else ''


def timestamp(data):
    """(seconds since 1970 UTC, nanoseconds), or (0, 0). A time with no
    time zone recorded is taken as it stands."""
    (zone_type, year, month, day, hour, minute, second, centi, hundreds,
     micro) = struct.unpack('<HhBBBBBBBB', data)
    if not year or not 1 <= month <= 12 or not 1 <= day <= 31:
        return 0, 0
    try:
        seconds = calendar.timegm((year, month, day, hour, minute, second))
    except (ValueError, OverflowError):
        return 0, 0
    zone = zone_type & 0x0FFF
    if zone & 0x0800:
        zone -= 0x1000
    if zone_type >> 12 == 1 and zone != -2047:
        seconds -= zone * 60
    nanoseconds = (centi * 10_000 + hundreds * 100 + micro) * 1000
    return seconds, nanoseconds


def is_udf(head):
    """Whether the volume recognition sequence names NSR02 or NSR03:
    `head` is the volume's first 96 KiB."""
    for offset in range(VRS_START, min(len(head), VRS_START + 64 * 1024),
                        512):
        if head[offset + 1:offset + 6] in (b'NSR02', b'NSR03'):
            return True
    return False


class _Map:
    """One partition map: logical block -> byte position in the volume."""

    def __init__(self, volume, kind, partition, **extra):
        self.volume = volume
        self.kind = kind
        self.partition = partition
        self.extra = extra
        self._vat = None
        self._metadata = None

    def position(self, block):
        volume = self.volume
        start = volume.partition_start(self.partition)
        if self.kind == 'type1':
            return (start + block) * volume.block
        if self.kind == 'sparable':
            packet = self.extra['packet']
            base = block - block % packet
            mapped = volume.sparing.get(base)
            if mapped is not None:
                return (mapped + block % packet) * volume.block
            return (start + block) * volume.block
        if self.kind == 'virtual':
            vat = volume.vat()
            if block >= len(vat) or vat[block] == 0xFFFFFFFF:
                raise UdfError(f"virtual block {block} is not in the VAT")
            return (start + vat[block]) * volume.block
        if self.kind == 'metadata':
            return volume.metadata_position(block)
        raise UdfError(f"partition map {self.kind}")


class UdfVolume:
    """The structures of one UDF volume, read from `source` (a file object
    over the partition or disc)."""

    def __init__(self, source, size=None):
        self.source = source
        if size is None:
            source.seek(0, 2)
            size = source.tell()
        self.size = size
        self.block = self._find_anchor()
        self.partitions = {}         # partition number -> (start, length,
        #                              unallocated bitmap short_ad)
        self.maps = []
        self.sparing = {}
        self._vat = None
        self._metadata_extents = None
        self._read_descriptors()
        self._entries = {}

    # -- finding the volume -------------------------------------------------

    def read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def _find_anchor(self):
        for block in BLOCK_SIZES:
            for number in (ANCHOR_BLOCK, self.size // block - 1,
                           self.size // block - 1 - ANCHOR_BLOCK):
                if number <= 0:
                    continue
                tag = _tag(self.read(number * block, 16))
                if tag == (TAG_AVDP, number):
                    self.anchor = number
                    return block
        raise UdfError("no Anchor Volume Descriptor Pointer")

    def _read_descriptors(self):
        anchor = self.read(self.anchor * self.block, 32)
        main_length, main_start, reserve_length, reserve_start = \
            struct.unpack_from('<IIII', anchor, 16)
        for length, start in ((main_length, main_start),
                              (reserve_length, reserve_start)):
            try:
                self._sequence(start, length)
            except UdfError as exc:
                logger.debug("UDF descriptor sequence at %d: %s", start, exc)
                continue
            if self.maps and self.partitions:
                break
        if not self.maps or not self.partitions:
            raise UdfError("no partition or logical volume descriptor")
        for map_ in self.maps:
            if map_.kind == 'sparable':
                self._read_sparing(map_)

    def _sequence(self, start, length):
        blocks = max(1, length // self.block)
        number = start
        seen = 0
        while seen < blocks and seen < 256:
            data = self.read(number * self.block, self.block)
            tag = _tag(data)
            if tag is None:
                break
            identifier, _location = tag
            if identifier == TAG_TD:
                break
            if identifier == TAG_VDP:
                # Continues elsewhere.
                _sequence_number, length, start = struct.unpack_from(
                    '<III', data, 16)
                number, blocks, seen = start, max(1, length // self.block), 0
                continue
            if identifier == TAG_PD:
                self._partition(data)
            elif identifier == TAG_LVD:
                self._logical_volume(data)
            number += 1
            seen += 1

    def _partition(self, data):
        number = struct.unpack_from('<H', data, 22)[0]
        contents = data[25:32]
        start, length = struct.unpack_from('<II', data, 188)
        # Partition Header Descriptor (in contents use): the unallocated
        # space bitmap's short_ad.
        bitmap_length, bitmap_position = struct.unpack_from('<II', data,
                                                            56 + 8)
        if contents.startswith(b'+NSR0') or number not in self.partitions:
            self.partitions[number] = (start, length,
                                       (bitmap_length & 0x3FFFFFFF,
                                        bitmap_position))

    def _logical_volume(self, data):
        block_size = struct.unpack_from('<I', data, 212)[0]
        if block_size and block_size != self.block:
            raise UdfError(f"logical block size {block_size} differs from "
                           f"{self.block}")
        self.label = dstring(data[84:212])
        self.fsd = _long_ad(data, 248)
        _table_length, count = struct.unpack_from('<II', data, 264)
        offset = 440
        maps = []
        for _ in range(count):
            kind, length = data[offset], data[offset + 1]
            if kind == 1:
                _sequence, partition = struct.unpack_from('<HH', data,
                                                          offset + 2)
                maps.append(_Map(self, 'type1', partition))
            elif kind == 2:
                ident = data[offset + 5:offset + 28].rstrip(b'\0')
                _sequence, partition = struct.unpack_from('<HH', data,
                                                          offset + 36)
                if ident.startswith(b'*UDF Sparable Partition'):
                    packet, tables, _reserved, table_size = \
                        struct.unpack_from('<HBBI', data, offset + 40)
                    locations = struct.unpack_from(f'<{tables}I', data,
                                                   offset + 48)
                    maps.append(_Map(self, 'sparable', partition,
                                     packet=packet, tables=locations,
                                     table_size=table_size))
                elif ident.startswith(b'*UDF Virtual Partition'):
                    maps.append(_Map(self, 'virtual', partition))
                elif ident.startswith(b'*UDF Metadata Partition'):
                    main, mirror, _bitmap = struct.unpack_from(
                        '<III', data, offset + 40)
                    maps.append(_Map(self, 'metadata', partition,
                                     main=main, mirror=mirror))
                else:
                    maps.append(_Map(self, 'unknown', partition,
                                     name=ident.decode('ascii', 'replace')))
            offset += length or 6
        self.maps = maps

    def _read_sparing(self, map_):
        for location in map_.extra['tables']:
            data = self.read(location * self.block,
                             max(self.block, map_.extra['table_size']))
            tag = _tag(data)
            if tag is None or tag[0] != 0:
                continue
            count = struct.unpack_from('<H', data, 48)[0]
            for number in range(count):
                original, mapped = struct.unpack_from('<II', data,
                                                      56 + 8 * number)
                if original < 0xFFFFFFF0:
                    self.sparing[original] = mapped
            return

    # -- addressing ---------------------------------------------------------

    def partition_start(self, number):
        if number not in self.partitions:
            raise UdfError(f"partition {number} is not described")
        return self.partitions[number][0]

    def position(self, reference, block):
        """Byte position of logical `block` in partition reference
        `reference` (an index into the partition maps)."""
        if reference >= len(self.maps):
            raise UdfError(f"partition reference {reference}")
        return self.maps[reference].position(block)

    def underlying(self, map_):
        """The type-1 (or sparable) map a virtual or metadata partition
        lives in: the one naming the same partition."""
        for index, other in enumerate(self.maps):
            if other.partition == map_.partition and \
                    other.kind in ('type1', 'sparable'):
                return index
        raise UdfError("no partition under a virtual or metadata one")

    def vat(self):
        """The Virtual Allocation Table (UDF 2.00+), from the VAT file's
        entry near the end of what was written."""
        if self._vat is not None:
            return self._vat
        virtual = next(m for m in self.maps if m.kind == 'virtual')
        base = self.underlying(virtual)
        start = self.partition_start(virtual.partition)
        # The VAT closes what was written: an image of a disc (or one
        # made to a disc's size) runs on in zeros past it.
        last = self._last_written()
        for number in range(last, max(start, last - 512), -1):
            data = self.read(number * self.block, self.block)
            tag = _tag(data)
            if tag is None or tag[0] not in (TAG_FE, TAG_EFE):
                continue
            if data[27] != FT_VAT20:
                continue
            entry = FileEntry(self, base, number - start, data)
            content = entry.read(0, entry.size)
            header = struct.unpack_from('<H', content, 0)[0]
            body = content[header:]
            self._vat = struct.unpack(f'<{len(body) // 4}I',
                                      body[:len(body) // 4 * 4])
            return self._vat
        raise UdfError("no Virtual Allocation Table found")

    #: How far back from the end zeros are skipped looking for the VAT.
    MAX_ZERO_TAIL = 4 << 30

    def _last_written(self):
        """The last block holding anything but zeros."""
        step = 1 << 20
        end = self.size
        floor = max(0, self.size - self.MAX_ZERO_TAIL)
        while end > floor:
            begin = max(floor, end - step)
            data = self.read(begin, end - begin).rstrip(b'\0')
            if data:
                return (begin + len(data) - 1) // self.block
            end = begin
        return self.size // self.block - 1

    def metadata_position(self, block):
        """A metadata partition's block, through the metadata file (or its
        mirror) whose extents lie in the partition beneath."""
        if self._metadata_extents is None:
            meta = next(m for m in self.maps if m.kind == 'metadata')
            base = self.underlying(meta)
            extents = None
            for location in (meta.extra['main'], meta.extra['mirror']):
                try:
                    data = self.read(self.position(base, location),
                                     self.block)
                    entry = FileEntry(self, base, location, data)
                    extents = entry.extents()
                    break
                except UdfError as exc:
                    logger.debug("UDF metadata file at %d: %s", location,
                                 exc)
            if extents is None:
                raise UdfError("neither metadata file reads")
            self._metadata_extents = extents
        offset = block * self.block
        for logical, length, kind, position in self._metadata_extents:
            if logical <= offset < logical + length:
                if kind != EXT_RECORDED:
                    raise UdfError("metadata block not recorded")
                return position + offset - logical
        raise UdfError(f"metadata block {block} outside the metadata file")

    # -- entries ------------------------------------------------------------

    def entry(self, reference, block):
        key = (reference, block)
        cached = self._entries.get(key)
        if cached is None:
            data = self.read(self.position(reference, block), self.block)
            cached = FileEntry(self, reference, block, data)
            if len(self._entries) > 65536:
                self._entries.clear()
            self._entries[key] = cached
        return cached

    def root(self):
        """The root directory's (reference, block), from the File Set
        Descriptor."""
        _length, block, reference = self.fsd
        data = self.read(self.position(reference, block), self.block)
        tag = _tag(data)
        if tag is None or tag[0] != TAG_FSD:
            raise UdfError("no File Set Descriptor")
        _length, root_block, root_reference = _long_ad(data, 400)
        return root_reference, root_block

    def allocated_ranges(self):
        """(begin, end) byte ranges in use: everything outside the
        partitions, and the blocks each partition's space bitmap does not
        call free."""
        out = []
        block = self.block
        position = 0
        for start, length, bitmap in sorted(self.partitions.values()):
            out.append((position, start * block))
            position = (start + length) * block
            free = self._free_blocks(start, length, bitmap)
            if free is None:
                out.append((start * block, (start + length) * block))
                continue
            run = None
            for number in range(length):
                used = number not in free
                if used and run is None:
                    run = number
                elif not used and run is not None:
                    out.append(((start + run) * block,
                                (start + number) * block))
                    run = None
            if run is not None:
                out.append(((start + run) * block,
                            (start + length) * block))
        out.append((position, self.size))
        return [(begin, end) for begin, end in out if end > begin]

    def _free_blocks(self, start, length, bitmap):
        bitmap_length, bitmap_position = bitmap
        if not bitmap_length:
            return None
        data = self.read((start + bitmap_position) * self.block,
                         min(bitmap_length, 64 << 20))
        tag = _tag(data)
        if tag is None or tag[0] != TAG_SBD:
            return None
        bits, count = struct.unpack_from('<II', data, 16)
        raw = data[24:24 + count]
        free = set()
        for number in range(min(bits, length, len(raw) * 8)):
            if raw[number >> 3] >> (number & 7) & 1:
                free.add(number)
        return free


def _long_ad(data, offset):
    """(length, logical block, partition reference) of a long_ad."""
    length, block, reference = struct.unpack_from('<IIH', data, offset)
    return length, block, reference


class FileEntry:
    """A File Entry or Extended File Entry."""

    def __init__(self, volume, reference, block, data, depth=0):
        self.volume = volume
        self.reference = reference
        self.block = block
        tag = _tag(data)
        if tag is None:
            raise UdfError(f"no descriptor at block {block}")
        if tag[0] == TAG_IE and depth < 16:
            # An indirect entry (strategy 4096): the entry is elsewhere.
            _length, block, reference = _long_ad(data, 36)
            other = volume.read(volume.position(reference, block),
                                volume.block)
            self.__init__(volume, reference, block, other, depth + 1)
            return
        if tag[0] not in (TAG_FE, TAG_EFE):
            raise UdfError(f"block {block}: descriptor {tag[0]}, not a "
                           f"file entry")
        self.extended = tag[0] == TAG_EFE
        self.file_type = data[27]
        self.ad_kind = struct.unpack_from('<H', data, 34)[0] & 7
        (self.uid, self.gid, permissions, self.links, _format,
         _attributes, _record, self.size) = struct.unpack_from(
             '<IIIHBBIQ', data, 36)
        if self.extended:
            self.access = timestamp(data[80:92])
            self.modification = timestamp(data[92:104])
            self.creation = timestamp(data[104:116])
            self.change = timestamp(data[116:128])
            ea_length, ad_length = struct.unpack_from('<II', data, 208)
            area = 216
        else:
            self.access = timestamp(data[72:84])
            self.modification = timestamp(data[84:96])
            self.creation = (0, 0)
            self.change = timestamp(data[96:108])
            ea_length, ad_length = struct.unpack_from('<II', data, 168)
            area = 176
        if area + ea_length + ad_length > len(data):
            # A long descriptor area (inline data over a block is not
            # allowed; allocation descriptors can run long): read on.
            data = volume.read(volume.position(reference, block),
                               area + ea_length + ad_length)
        self.descriptors = data[area + ea_length:area + ea_length +
                                ad_length]
        self.mode = _MODES.get(self.file_type, stat.S_IFREG) | \
            _permissions(permissions)
        self._extents = None

    @property
    def is_dir(self):
        return self.file_type in (FT_DIRECTORY, FT_STREAMDIR)

    def extents(self):
        """[(logical offset, length, extent type, byte position)]."""
        if self._extents is not None:
            return self._extents
        out = []
        logical = 0
        if self.ad_kind == AD_INLINE:
            self._extents = []
            return self._extents
        pending = self.descriptors
        rounds = 0
        while pending and rounds < 4096:
            rounds += 1
            following = None
            for length, kind, block, reference in self._descriptors(pending):
                if kind == EXT_NEXT:
                    following = (reference, block, length)
                    break
                if not length:
                    break
                position = None
                if kind == EXT_RECORDED:
                    position = self.volume.position(reference, block)
                out.append((logical, length, kind, position))
                logical += length
            pending = None
            if following is not None:
                reference, block, length = following
                data = self.volume.read(
                    self.volume.position(reference, block),
                    max(length, self.volume.block))
                tag = _tag(data)
                if tag is None or tag[0] != TAG_AED:
                    break
                count = struct.unpack_from('<I', data, 20)[0]
                pending = data[24:24 + count]
        self._extents = out
        return out

    def _descriptors(self, data):
        """(length, extent type, logical block, partition reference) of
        each allocation descriptor in `data`."""
        if self.ad_kind == AD_SHORT:
            size = 8
        elif self.ad_kind == AD_LONG:
            size = 16
        elif self.ad_kind == AD_EXTENDED:
            size = 20
        else:
            raise UdfError(f"allocation descriptor kind {self.ad_kind}")
        for offset in range(0, len(data) - size + 1, size):
            raw = struct.unpack_from('<I', data, offset)[0]
            length, kind = raw & 0x3FFFFFFF, raw >> 30
            if self.ad_kind == AD_SHORT:
                block = struct.unpack_from('<I', data, offset + 4)[0]
                reference = self.reference
            elif self.ad_kind == AD_LONG:
                block, reference = struct.unpack_from('<IH', data,
                                                      offset + 4)
            else:
                block, reference = struct.unpack_from('<IH', data,
                                                      offset + 12)
            yield length, kind, block, reference

    def read(self, offset, length):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        if self.ad_kind == AD_INLINE:
            return self.descriptors[offset:offset + length]
        out = bytearray()
        end = offset + length
        for logical, size, kind, position in self.extents():
            if logical + size <= offset or logical >= end:
                continue
            begin = max(offset, logical)
            stop = min(end, logical + size)
            if kind == EXT_RECORDED:
                data = self.volume.read(position + begin - logical,
                                        stop - begin)
                out += data
                if len(data) < stop - begin:
                    break
            else:
                out += bytes(stop - begin)
            if logical + size >= end:
                break
        if len(out) < length:
            # Past the last extent: nothing recorded.
            out += bytes(length - len(out))
        return bytes(out)

    def identifiers(self):
        """[(name, (reference, block), characteristics)] of a directory,
        without the parent entry."""
        if not self.is_dir:
            return []
        data = self.read(0, min(self.size, MAX_METADATA))
        out = []
        offset = 0
        while offset + 38 <= len(data):
            tag = _tag(data, offset)
            if tag is None or tag[0] != TAG_FID:
                break
            characteristics, name_length = data[offset + 18], \
                data[offset + 19]
            _length, block, reference = _long_ad(data, offset + 20)
            use_length = struct.unpack_from('<H', data, offset + 36)[0]
            name_start = offset + 38 + use_length
            name = cs0(data[name_start:name_start + name_length])
            total = (38 + use_length + name_length + 3) // 4 * 4
            offset += total
            if characteristics & FID_PARENT:
                continue
            out.append((name, (reference, block), characteristics))
        return out

    def link_target(self):
        """A symlink's target, from its path components."""
        data = self.read(0, min(self.size, MAX_METADATA))
        parts = []
        absolute = False
        offset = 0
        while offset + 4 <= len(data):
            kind, length = data[offset], data[offset + 1]
            ident = data[offset + 4:offset + 4 + length]
            offset += 4 + length
            if kind in (1, 2):
                absolute = True
                parts = []
            elif kind == 3:
                parts.append('..')
            elif kind == 4:
                parts.append('.')
            elif kind == 5:
                parts.append(cs0(ident))
        return ('/' if absolute else '') + '/'.join(parts)


def _permissions(value):
    """UDF's permission bits (other, group, owner: 5 bits each, execute
    write read change-attribute delete) as a Unix mode."""
    mode = 0
    for shift, (read, write, execute) in ((10, (0o400, 0o200, 0o100)),
                                          (5, (0o040, 0o020, 0o010)),
                                          (0, (0o004, 0o002, 0o001))):
        bits = value >> shift
        if bits & 4:
            mode |= read
        if bits & 2:
            mode |= write
        if bits & 1:
            mode |= execute
    return mode


# --- libyal's vocabulary -----------------------------------------------------

def _identifier(location):
    reference, block = location
    return reference << 32 | block


#: Identifiers of deleted names whose file entry is gone: above any
#: (partition reference << 32 | block), from the folder and the slot.
NAME_ONLY = 1 << 62


def _name_only(parent, index):
    return NAME_ONLY | (parent & ((1 << 46) - 1)) << 16 | index


class _NoEntry:
    """What a deleted name with no file entry left has: nothing but the
    name. Linux clears a deleted identifier's ICB address."""
    mode = stat.S_IFREG
    is_dir = False
    size = uid = gid = 0
    links = 0
    access = modification = creation = change = (0, 0)

    def read(self, _offset, _length):
        return b''

    def identifiers(self):
        return []

    def link_target(self):
        return ''


class UdfEntry:
    """A file or directory, answering what libyal_fs asks a file entry."""

    def __init__(self, volume, location, name='', parent=0, deleted=False,
                 identifier=None):
        self._volume = volume
        self._location = location
        self._entry = volume.entry(*location) if location else _NoEntry()
        self.identifier = identifier if identifier is not None else \
            _identifier(location)
        self.parent_identifier = parent
        self.name = name
        self.deleted = deleted
        self.file_mode = self._entry.mode
        self.size = 0 if self._entry.is_dir else self._entry.size
        self.owner_identifier = self._entry.uid
        self.group_identifier = self._entry.gid
        self._children = None
        if stat.S_ISLNK(self.file_mode):
            self.size = len(self.symbolic_link_target.encode(
                'utf-8', 'surrogateescape'))

    def get_number_of_links(self):
        return self._entry.links

    def _time(self, value):
        seconds, nanoseconds = value
        return seconds * 1_000_000_000 + nanoseconds if seconds else 0

    def get_access_time_as_integer(self):
        return self._time(self._entry.access)

    def get_modification_time_as_integer(self):
        return self._time(self._entry.modification)

    def get_creation_time_as_integer(self):
        return self._time(self._entry.creation)

    def get_inode_change_time_as_integer(self):
        return self._time(self._entry.change)

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._entry.link_target()

    def _list(self):
        if self._children is None:
            children = []
            try:
                for name, location, flags in self._entry.identifiers():
                    deleted = bool(flags & FID_DELETED)
                    if deleted:
                        # The file entry, while it still reads; else the
                        # name alone (Linux clears the address).
                        try:
                            self._volume.entry(*location)
                        except (UdfError, struct.error):
                            location = None
                    children.append((name, location, deleted))
            except (UdfError, struct.error) as exc:
                logger.warning("UDF directory %x unreadable: %s",
                               self.identifier, exc)
            self._children = children
        return self._children

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, location, deleted = self._list()[index]
        identifier = None if location else _name_only(self.identifier,
                                                      index)
        return UdfEntry(self._volume, location, name, self.identifier,
                        deleted, identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._entry.read(offset, length)


class _Volume:
    """libyal's volume vocabulary over a UdfVolume."""

    def __init__(self, volume):
        self.udf = volume
        self.label = getattr(volume, 'label', '')
        self.root_location = volume.root()
        self._names = None

    def get_root_directory(self):
        return UdfEntry(self.udf, self.root_location)

    def entry(self, identifier):
        if identifier & NAME_ONLY:
            # A deleted name with no file entry: found again in its folder.
            parent = (identifier >> 16) & ((1 << 46) - 1)
            folder = self.entry(parent)
            index = identifier & 0xFFFF
            if folder is None or index >= folder.number_of_sub_file_entries:
                return None
            return folder.get_sub_file_entry(index)
        location = (identifier >> 32, identifier & 0xFFFFFFFF)
        if location == self.root_location:
            return self.get_root_directory()
        try:
            self.udf.entry(*location)
        except (UdfError, struct.error):
            return None
        name, parent, deleted = self._walked().get(identifier,
                                                   ('', 0, False))
        return UdfEntry(self.udf, location, name, parent, deleted)

    def _walked(self):
        """{identifier: (name, parent, deleted)}: a file entry knows
        neither its name nor its folder."""
        if self._names is None:
            self._names = {}
            root = self.get_root_directory()
            pending = [root]
            seen = {root.identifier}
            while pending:
                directory = pending.pop()
                for index, (name, location, deleted) in enumerate(
                        directory._list()):
                    if location is None:
                        continue
                    identifier = _identifier(location)
                    self._names.setdefault(
                        identifier, (name, directory.identifier, deleted))
                    if identifier in seen or deleted:
                        continue
                    child = directory.get_sub_file_entry(index)
                    if stat.S_ISDIR(child.file_mode):
                        seen.add(identifier)
                        pending.append(child)
        return self._names

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for index, (name, _location, deleted) in enumerate(
                    entry._list()):
                if name == part and not deleted:
                    entry = entry.get_sub_file_entry(index)
                    break
            else:
                return None
        return entry

    def close(self):
        self.udf._entries.clear()


class UdfFileSystem(LibyalFileSystem):
    """A UDF volume, read like a pytsk3.FS_Info."""

    KIND = 'UDF'

    def __init__(self, volume):
        self.udf = volume
        self.BLOCK_SIZE = volume.block
        super().__init__(_Volume(volume), volume.size,
                         getattr(volume, 'label', '') or 'UDF volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return _identifier(self.volume.root_location)

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.udf.allocated_ranges()

    def close(self):
        self.volume.close()


def open_udf(source):
    """A UdfFileSystem over `source` (a file object over the partition or
    disc), or None when it is not a UDF volume TRACE can read."""
    try:
        source.seek(0)
        head = source.read(VRS_START + 64 * 1024)
    except (OSError, IOError):
        return None
    if not is_udf(head):
        return None
    try:
        return UdfFileSystem(UdfVolume(source))
    except (UdfError, struct.error, OSError, IOError,
            StopIteration) as exc:
        logger.warning("UDF volume not opened: %s", exc)
        return None



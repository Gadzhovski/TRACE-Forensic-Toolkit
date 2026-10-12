"""Android dynamic partitions: the "super" partition, read in Python.

Since Android 10, system, vendor, product (and their _a/_b copies) are not
partitions of the phone's disk but logical partitions inside one physical
partition, "super" -- AOSP's liblp (fs_mgr/liblp/include/liblp/
metadata_format.h). A super image (super.img, or a super partition in a
full-disk extraction) holds:

* 4 KiB reserved, then the geometry (magic 'gDla') and its backup: the
  metadata's maximum size, how many slots, the logical block size, and a
  SHA-256 of itself;
* metadata slots (one per A/B slot), each a primary and a backup copy: a
  header (magic '0PLA', version, SHA-256s of itself and of its tables) and
  four tables -- partitions (name, attributes, which extents, group),
  extents (sectors, LINEAR to a place on a block device or ZERO), groups,
  block devices;
* extents in 512-byte sectors.

Each logical partition reads as its extents laid end to end. Slot 0 is
read (its backup when the primary's checksums fail); a partition on
another block device (a "retrofit" device's system_b) is listed but not
readable from this image.
"""

import hashlib
import struct

RESERVED = 4096
GEOMETRY_SIZE = 4096
GEOMETRY_MAGIC = 0x616C4467
HEADER_MAGIC = 0x414C5030
SECTOR = 512
LINEAR, ZERO = 0, 1
ATTRIBUTE_NAMES = {0x1: 'read-only', 0x2: 'slot-suffixed', 0x4: 'updated',
                   0x8: 'disabled'}

GEOMETRY = struct.Struct('<II32sIII')
HEADER_V1_0 = struct.Struct('<IHHI32sI32sIIIIIIIIIIII')
PARTITION = struct.Struct('<36sIIII')
EXTENT = struct.Struct('<QIQI')
GROUP = struct.Struct('<36sIQ')
BLOCK_DEVICE = struct.Struct('<QIIQ36sI')


class SuperError(Exception):
    pass


def is_super(head):
    """Whether `head` (a partition's first 8 KiB) holds liblp geometry."""
    return len(head) >= RESERVED + 4 and struct.unpack_from(
        '<I', head, RESERVED)[0] == GEOMETRY_MAGIC


def _name(raw):
    return raw.split(b'\0', 1)[0].decode('ascii', 'replace')


class LogicalPartition:
    """One logical partition: libyal's shape (read_buffer_at_offset,
    get_size), with a name."""

    def __init__(self, read, name, extents, attributes, group, readable):
        self._read = read
        self.name = name
        self.attributes = attributes
        self.group = group
        self.readable = readable
        #: [(logical offset, length, kind, byte position)]
        self.extents = []
        offset = 0
        for sectors, kind, data, _source in extents:
            length = sectors * SECTOR
            self.extents.append((offset, length, kind, data * SECTOR))
            offset += length
        self.size = offset

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        out = bytearray()
        end = min(offset + length, self.size)
        for start, size, kind, position in self.extents:
            if start + size <= offset or start >= end:
                continue
            begin = max(offset, start)
            stop = min(end, start + size)
            if kind == LINEAR:
                out += self._read(position + begin - start, stop - begin)
            else:
                out += bytes(stop - begin)
        return bytes(out)

    def flags(self):
        return [label for bit, label in ATTRIBUTE_NAMES.items()
                if self.attributes & bit]

    def close(self):
        pass


class SuperImage:
    """The metadata of a super partition read through `read(offset,
    length)`."""

    def __init__(self, read, slot=0):
        self._read = read
        geometry = None
        for offset in (RESERVED, RESERVED + GEOMETRY_SIZE):
            raw = read(offset, GEOMETRY_SIZE)
            try:
                geometry = self._geometry(raw)
                break
            except SuperError:
                continue
        if geometry is None:
            raise SuperError("no valid liblp geometry")
        self.metadata_max, self.slot_count, self.block_size = geometry
        if not 0 <= slot < self.slot_count:
            raise SuperError(f"metadata slot {slot} of {self.slot_count}")
        base = RESERVED + 2 * GEOMETRY_SIZE
        metadata = None
        errors = []
        for offset in (base + slot * self.metadata_max,
                       base + (self.slot_count + slot) * self.metadata_max):
            try:
                metadata = self._metadata(read(offset, self.metadata_max))
                break
            except (SuperError, struct.error) as exc:
                errors.append(str(exc))
        if metadata is None:
            raise SuperError("no valid liblp metadata: " + '; '.join(errors))
        self.version, partitions, extents, groups, devices = metadata
        self.groups = [(_name(name), maximum) for name, _flags, maximum
                       in groups]
        self.devices = [(_name(name), first, size)
                        for first, _alignment, _offset, size, name, _flags
                        in devices]
        self.partitions = []
        for name, attributes, first, count, group in partitions:
            own = extents[first:first + count]
            readable = all(source == 0 for _s, kind, _d, source in own
                           if kind == LINEAR)
            self.partitions.append(LogicalPartition(
                read, _name(name), own, attributes,
                self.groups[group][0] if group < len(self.groups) else '',
                readable))

    @staticmethod
    def _geometry(raw):
        if len(raw) < GEOMETRY.size:
            raise SuperError("geometry cut short")
        magic, size, checksum, metadata_max, slots, block = \
            GEOMETRY.unpack_from(raw)
        if magic != GEOMETRY_MAGIC or size > len(raw) or size < \
                GEOMETRY.size:
            raise SuperError("not liblp geometry")
        blank = bytearray(raw[:size])
        blank[8:40] = bytes(32)
        if hashlib.sha256(blank).digest() != checksum:
            raise SuperError("geometry checksum")
        if not metadata_max or metadata_max % SECTOR or not slots:
            raise SuperError("geometry values")
        return metadata_max, slots, block

    @staticmethod
    def _metadata(raw):
        (magic, major, minor, header_size, header_checksum, tables_size,
         tables_checksum, *descriptors) = HEADER_V1_0.unpack_from(raw)
        if magic != HEADER_MAGIC:
            raise SuperError("not a liblp metadata header")
        if major != 10:
            raise SuperError(f"liblp metadata version {major}.{minor}")
        blank = bytearray(raw[:header_size])
        blank[12:44] = bytes(32)
        if hashlib.sha256(blank).digest() != header_checksum:
            raise SuperError("metadata header checksum")
        tables = raw[header_size:header_size + tables_size]
        if hashlib.sha256(tables).digest() != tables_checksum:
            raise SuperError("metadata tables checksum")
        out = []
        for index, layout in enumerate((PARTITION, EXTENT, GROUP,
                                        BLOCK_DEVICE)):
            offset, count, entry_size = descriptors[index * 3:index * 3 + 3]
            if entry_size < layout.size:
                raise SuperError("metadata table entry size")
            out.append([layout.unpack_from(tables, offset + n * entry_size)
                        for n in range(count)])
        return (f"{major}.{minor}", *out)

    def describe(self):
        return (f"Android dynamic partitions (liblp {self.version}): "
                + ', '.join(f"{p.name} {p.size:,} bytes"
                            for p in self.partitions))


def open_super(window):
    """SuperImage over a file object over the super partition."""
    def read(offset, length):
        window.seek(offset)
        return window.read(length)
    return SuperImage(read)

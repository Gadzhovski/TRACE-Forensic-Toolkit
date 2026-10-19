"""QNX EFS (the flash file system, F3S version 3, on NOR flash) read in
pure Python (no Qt).

A head unit keeps its configuration on EFS, imaged with the rest of the
flash and no partition table. The layout, as QNX's fs/f3s_spec.h has it
(transcribed in NetherlandsForensicInstitute/qnxmount's Kaitai spec,
Apache-2.0):

* a partition is `unit_total` units of 2**unit_pow2 bytes. A unit lists
  its extents from its own end backwards: 32-byte headers -- a status
  word (bit 0 no write, 1 no next, 2 no super(seding extent), 3 no split,
  4-6 condition, 7 last extent, 8-9 type), two more status words, ECC,
  where the extent's text is (an offset in units of 2**align_pow2 from
  the unit's start) and its size, a next and a "superseded by" pointer
  (logical unit, extent index);
* extent 0 of a unit describes it (its size, byte order, the boot
  record's place), extent 1 gives its logical number (spare units have
  none);
* a boot record ('QSSL_F3S', version 3.0) says where the partition's
  first unit is, how many units it has, the alignment and the root;
* a folder is a chain of extents (next pointers), each extent one entry:
  name, first extent of what it names, mode, uid, gid, mtime, ctime. A
  file is the chain of its extents' texts; an extent with a newer copy
  (no-super bit clear) is read through its super pointer.

Either byte order. The boot record is found by its signature anywhere in
the image (a decoy that does not parse is passed over), so a raw flash
dump with EFS partitions in it opens at its first partition; the others
are listed by `partitions`. Live files only. Checked against qnxmount's
image (QNX's mkefs) and its tar, and qnxprobe's little- and big-endian
images with their recorded contents (tests/test_qnx.py).
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup

logger = logging.getLogger('TRACE.EFS')

KIND = 'QNX EFS'
SIGNATURE = b'QSSL_F3S'
HEADER_SIZE = 32
NO_NEXT, NO_SUPER, LAST = 1 << 1, 1 << 2, 1 << 7
#: The longest chain followed (a damaged image must not loop).
MAX_CHAIN = 1 << 20
#: Images larger than this are not scanned for boot records: EFS lives
#: on NOR flash (megabytes), and the scan runs whenever nothing else
#: recognised a partition -- a 100 GB disk would be read whole. (Once:
#: ImageHandler.get_fs_info keeps a miss.)
MAX_SCAN = 1 << 29
#: The scan's read size.
CHUNK = 16 << 20


class EfsError(Exception):
    pass


class _Extent:
    __slots__ = ('status', 'status1', 'text', 'next', 'super')

    def __init__(self, status, status1, text, nxt, sup):
        self.status, self.status1, self.text = status, status1, text
        self.next, self.super = nxt, sup


class Partition:
    """One EFS partition: its units by logical number."""

    def __init__(self, source, order, base, unit_size, boot):
        self.source = source
        self.order = order
        self.base = base
        self.unit_size = unit_size
        (_size, _major, _minor, _sig, self.unit_index, self.unit_total,
         self.unit_spare, self.align_pow2, root_unit, root_index) = boot
        self.root = (root_unit, root_index)
        self.size = self.unit_total * unit_size
        self.units = {}            # logical number -> [extents]
        for physical in range(self.unit_total):
            extents = self._unit(physical)
            if len(extents) < 2 or extents[1].status1 == 0xFFFFFFFF:
                continue           # a spare unit
            logical = struct.unpack_from(order + 'H', extents[1].text, 2)[0]
            self.units[logical] = extents
        if self.root[0] not in self.units:
            raise EfsError("the root's unit is missing")

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def _unit(self, physical):
        start = self.base + physical * self.unit_size
        data = self._read(start, self.unit_size)
        if len(data) < self.unit_size:
            return []
        out = []
        for index in range(self.unit_size // HEADER_SIZE):
            at = self.unit_size - HEADER_SIZE * (index + 1)
            (status, status1, _status2, _ecc, _reserve, hi, lo, size,
             next_unit, next_index, super_unit, super_index) = \
                struct.unpack_from(self.order + 'III6sBBHHHHHH', data, at)
            offset = ((hi << 16) + lo) << self.align_pow2
            text = data[offset:offset + size] \
                if size and offset + size <= self.unit_size else b''
            out.append(_Extent(status, status1, text,
                               (next_unit, next_index),
                               (super_unit, super_index)))
            if status & LAST:
                break
        return out

    def extent(self, pointer):
        """The extent `pointer` names, through any newer copies."""
        for _ in range(64):
            unit, index = pointer
            extents = self.units.get(unit)
            if extents is None or index >= len(extents):
                raise EfsError(f"no extent {unit}:{index}")
            found = extents[index]
            if found.status & NO_SUPER:
                return found
            pointer = found.super
        raise EfsError("superseded extents loop")

    def chain(self, pointer):
        """The extents from `pointer` along their next pointers."""
        seen = set()
        while len(seen) < MAX_CHAIN:
            if pointer in seen:
                break
            seen.add(pointer)
            found = self.extent(pointer)
            yield pointer, found
            if found.status & NO_NEXT:
                break
            pointer = found.next

    def entry(self, text):
        """A folder entry: {name, first, mode, uid, gid, mtime, ctime}."""
        order = self.order
        _size, _moves, length, first_unit, first_index = struct.unpack_from(
            order + 'HBBHH', text, 0)
        name = text[8:8 + length].split(b'\0', 1)[0]
        at = 8 + ((length + 3) & ~3)
        _stat_size, mode, uid, gid, mtime, ctime = struct.unpack_from(
            order + 'HHIIII', text, at)
        return {'name': name, 'first': (first_unit, first_index),
                'mode': mode, 'uid': uid, 'gid': gid, 'mtime': mtime,
                'ctime': ctime}

    def root_entry(self):
        return self.entry(self.extent(self.root).text)

    def children(self, entry):
        """[(pointer, entry)] of a folder."""
        out = []
        for pointer, found in self.chain(entry['first']):
            if not found.text:
                break
            try:
                out.append((pointer, self.entry(found.text)))
            except struct.error:
                continue
        return out

    def content(self, entry):
        return b''.join(found.text for _pointer, found
                        in self.chain(entry['first']))


def _boot_record(order, data, at):
    if at < 4 or at + 20 > len(data):
        return None
    try:
        boot = struct.unpack_from(order + 'HBB8sHHHHHH', data, at - 4)
    except struct.error:
        return None
    if boot[0] != 0x18 or boot[1] != 3 or boot[2] != 0 or \
            boot[3] != SIGNATURE:
        return None
    return boot


def _read(source, offset, length):
    source.seek(offset)
    return source.read(length)


def _hits(source, size):
    """Where the signature is, read a chunk at a time."""
    position, tail = 0, b''
    while position < size:
        chunk = _read(source, position, min(CHUNK, size - position))
        if not chunk:
            break
        data = tail + chunk
        base = position - len(tail)
        at = data.find(SIGNATURE)
        while at >= 0:
            yield base + at
            at = data.find(SIGNATURE, at + 1)
        tail = data[-(len(SIGNATURE) - 1):]
        position += len(chunk)


def partitions(source, size=None):
    """Every EFS partition in `source`: [Partition], by base. Nothing for
    an image over MAX_SCAN."""
    if size is None:
        source.seek(0, 2)
        size = source.tell()
    if size > MAX_SCAN:
        return []
    found, seen = [], set()
    for at in _hits(source, size):
        record = _read(source, max(at - 4, 0), 28)
        for order in ('<', '>'):
            boot = _boot_record(order, record, 4) if at >= 4 else None
            if boot is None:
                continue
            partition = _locate(source, size, order, at, boot)
            if partition is not None and partition.base not in seen:
                seen.add(partition.base)
                found.append(partition)
                break
    return sorted(found, key=lambda p: p.base)


def _locate(source, size, order, at, boot):
    """The partition a boot record at `at` belongs to: its unit's size is
    the one whose own description (extent 0) says so."""
    unit_index = boot[4]
    for power in range(9, 21):
        unit_size = 1 << power
        start = at & ~(unit_size - 1)
        header = start + unit_size - HEADER_SIZE
        if header + HEADER_SIZE > size:
            continue
        hi, lo, length = struct.unpack_from(
            order + 'BHH', _read(source, header + 19, 5), 0)
        offset = start + (((hi << 16) + lo) << boot[7])
        if not 8 <= length <= unit_size or offset + 8 > size:
            continue
        unit_pow2 = struct.unpack_from(order + 'H',
                                       _read(source, offset + 4, 2), 0)[0]
        if unit_pow2 != power:
            continue
        base = start - unit_index * unit_size
        if base < 0:
            continue
        try:
            return Partition(source, order, base, unit_size, boot)
        except (EfsError, struct.error) as exc:
            logger.debug("EFS boot record at %d: %s", at, exc)
    return None


class EfsEntry:
    """A file or folder, answering what libyal_fs asks a file entry."""

    def __init__(self, partition, pointer, entry, parent=0):
        self._partition = partition
        self._entry = entry
        self.identifier = (pointer[0] << 16) | pointer[1]
        self.parent_identifier = parent
        self.name = entry['name'].decode('utf-8', 'surrogateescape')
        self.file_mode = entry['mode']
        self.owner_identifier = entry['uid']
        self.group_identifier = entry['gid']
        self._data = None
        self.size = 0 if stat.S_ISDIR(entry['mode']) else len(self._bytes())

    def _bytes(self):
        if self._data is None:
            try:
                self._data = self._partition.content(self._entry)
            except (EfsError, struct.error) as exc:
                logger.warning("EFS file %s unreadable: %s", self.name, exc)
                self._data = b''
        return self._data

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._entry['mtime'] * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._entry['ctime'] * 1_000_000_000

    @property
    def symbolic_link_target(self):
        if not stat.S_ISLNK(self.file_mode):
            return ''
        return self._bytes().rstrip(b'\0').decode('utf-8', 'surrogateescape')

    def _list(self):
        if not stat.S_ISDIR(self.file_mode):
            return []
        try:
            return self._partition.children(self._entry)
        except (EfsError, struct.error) as exc:
            logger.warning("EFS folder %s unreadable: %s", self.name, exc)
            return []

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        pointer, entry = self._list()[index]
        return EfsEntry(self._partition, pointer, entry, self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._bytes()[offset:offset + length]


class _Volume(PathLookup):
    def __init__(self, partition):
        self.partition = partition
        self._index = None

    def get_root_directory(self):
        root = self.partition.root_entry()
        root = dict(root, mode=root['mode'] or stat.S_IFDIR | 0o755)
        return EfsEntry(self.partition, self.partition.root, root)

    def _walk(self):
        if self._index is None:
            self._index = {}
            pending = [self.get_root_directory()]
            while pending:
                entry = pending.pop()
                for index in range(entry.number_of_sub_file_entries):
                    child = entry.get_sub_file_entry(index)
                    if child.identifier in self._index:
                        continue
                    self._index[child.identifier] = child
                    if stat.S_ISDIR(child.file_mode):
                        pending.append(child)
        return self._index

    def entry(self, identifier):
        root = self.get_root_directory()
        if identifier == root.identifier:
            return root
        return self._walk().get(identifier)


class EfsFileSystem(LibyalFileSystem):
    """An EFS partition, read like a pytsk3.FS_Info."""

    KIND = KIND

    def __init__(self, partition, others=()):
        self.partition = partition
        #: Further EFS partitions in the same image (bases).
        self.other_partitions = [p.base for p in others]
        self.BLOCK_SIZE = partition.unit_size
        order = 'big-endian' if partition.order == '>' else 'little-endian'
        super().__init__(_Volume(partition), partition.size,
                         f"QNX EFS ({order}, {partition.unit_size}-byte "
                         f"units)")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        unit, index = self.partition.root
        return (unit << 16) | index

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        # The partition's units, whole: what is free inside one is not
        # told apart yet.
        return [(self.partition.base, self.partition.base +
                 self.partition.size)]


def open_efs(source, size=None):
    """An EfsFileSystem over the first EFS partition in `source`, or None."""
    try:
        found = partitions(source, size)
    except (OSError, IOError, struct.error) as exc:
        logger.debug("No EFS: %s", exc)
        return None
    if not found:
        return None
    if len(found) > 1:
        logger.info("EFS partitions at %s: the first is opened",
                    ', '.join(str(p.base) for p in found))
    return EfsFileSystem(found[0], found[1:])

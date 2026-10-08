"""Hardware and other metadata-less RAID, rebuilt from parameters (no Qt).

A Linux md array or a Btrfs pool describes itself on every disk
(core/mdraid.py, core/btrfs.py). An HP Smart Array, an Adaptec or a
motherboard RAID keeps its layout in the controller: the disks hold only
data and parity. Imaged one by one, they are rebuilt the way X-Ways and
other tools do it -- from parameters:

* level: 0 (striped), 1 (mirrored), 5 (one parity), 6 (two), or JBOD
  (disks end to end, "spanned");
* the disks' order, with a placeholder where one is missing (RAID5 and
  RAID6 rebuild one missing disk from parity, as core/mdraid.py does);
* stripe (chunk) size, and RAID5/6's parity rotation (left/right,
  symmetric/asymmetric -- md's names) and *delay*: HP / Compaq Smart
  Array controllers keep parity on one disk for a run of rows before it
  moves on (X-Ways calls it parity delay); 1 for everyone else;
* an offset where each member's data starts (a controller's own
  metadata at the front), 0 for most.

`build` gives a reader over the striping below (md's layouts, plus the
delay; one missing disk rebuilt by XOR with the row's others). `detect`
tries combinations and *scores* each by what it
reads: a candidate counts only as far as the files it finds parse as
the format they claim (carving's validators), because a wrong stripe size
still mounts a file system whose first chunk of every file happens to be
right. The best candidates come back ranked with their evidence.
"""

import itertools
import logging
import re

logger = logging.getLogger('TRACE.HwRaid')

LEVELS = ('0', '1', '5', '6', 'jbod')
LAYOUTS = ('left-asymmetric', 'right-asymmetric', 'left-symmetric',
           'right-symmetric')
#: Parity delays tried: rows before parity moves to the next disk.
DELAYS = (1, 2, 4, 8, 16)
#: Stripe sizes controllers use, smallest first.
CHUNKS = (4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
          1048576)
#: Up to this many disks every order is tried; above, only the order the
#: images' names give (and its reverse) -- 8 disks are 40,320 orders.
MAX_PERMUTED = 5


class RaidError(Exception):
    pass


class Params:
    """A reconstruction: level, chunk bytes, layout name, member offset
    in bytes. `order` is the members' slots: an index into the members
    given, or None for a missing disk."""

    def __init__(self, level, chunk=65536, layout='left-asymmetric',
                 offset=0, order=None, delay=1):
        self.level = str(level).lower()
        if self.level not in LEVELS:
            raise RaidError(f"RAID level {level} is not rebuilt")
        if layout not in LAYOUTS:
            raise RaidError(f"Parity layout {layout} is not known")
        self.chunk = int(chunk)
        if self.chunk < 512 or self.chunk % 512:
            raise RaidError("The stripe size must be whole sectors")
        self.layout = layout
        self.offset = int(offset)
        self.order = list(order) if order is not None else None
        self.delay = max(1, int(delay))

    def as_dict(self):
        return {'level': self.level, 'chunk': self.chunk,
                'layout': self.layout, 'offset': self.offset,
                'order': self.order, 'delay': self.delay}

    @classmethod
    def from_dict(cls, data):
        return cls(data['level'], data.get('chunk', 65536),
                   data.get('layout', 'left-asymmetric'),
                   data.get('offset', 0), data.get('order'),
                   data.get('delay', 1))

    def describe(self):
        if self.level == 'jbod':
            return 'JBOD (spanned)'
        text = f"RAID{self.level}, {self.chunk // 1024} KiB stripes"
        if self.level in ('5', '6'):
            text += f", {self.layout}"
            if self.delay > 1:
                text += f", parity delay {self.delay}"
        missing = sum(1 for slot in self.order or () if slot is None)
        if missing:
            text += f", {missing} disk{'s' if missing > 1 else ''} rebuilt"
        return text


class _Span:
    """JBOD: the members end to end."""

    def __init__(self, parts):
        self.parts = parts                     # [(read, start, length)]
        self.size = sum(length for _r, _s, length in parts)

    def read(self, offset, length):
        out = bytearray()
        position = 0
        for read, start, size in self.parts:
            if length <= 0:
                break
            if offset < position + size:
                within = max(0, offset - position)
                part = min(length, size - within)
                out += read(start + within, part)
                offset += part
                length -= part
            position += size
        return bytes(out)


def build(members, params):
    """A reader (`read(offset, length)`, `size`) of the volume the
    members make. `members` are [(read, size)]; params.order indexes them
    (None = missing). Raises RaidError when they cannot make it."""
    order = params.order if params.order is not None else \
        list(range(len(members)))
    if not order:
        raise RaidError("No disks")
    present = [members[i] for i in order if i is not None]
    if not present:
        raise RaidError("Every disk is missing")
    usable = min(size for _read, size in present) - params.offset
    if usable <= 0:
        raise RaidError("The offset is past the end of a disk")
    if params.level == 'jbod':
        if None in order:
            raise RaidError("A spanned volume cannot do without a disk")
        return _Span([(members[i][0], params.offset,
                       members[i][1] - params.offset) for i in order])
    reads = [members[i][0] if i is not None else None for i in order]
    return Striped(reads, int(params.level), params.chunk, params.layout,
                   params.delay, params.offset,
                   usable - usable % params.chunk)


class Striped:
    """RAID 0, 1, 5 and 6 over member readers in slot order (None for a
    missing disk). Rows are `chunk` bytes on every disk; a RAID5/6 row
    holds one (two) parity chunks, rotating every `delay` rows:

    * left-asymmetric: parity on the last disk first, moving left; data
      fills the other disks from the first;
    * right-asymmetric: parity on the first disk first, moving right;
    * left-/right-symmetric: parity as above; data starts on the disk
      after the parity and wraps round (md's default, left-symmetric).

    RAID6's Q follows P. A missing disk is rebuilt by XOR with the row's
    other data and P; two missing are not."""

    def __init__(self, reads, level, chunk, layout, delay, offset, usable):
        self.reads, self.level, self.chunk = reads, level, chunk
        self.layout, self.delay, self.offset = layout, delay, offset
        self.disks = len(reads)
        self.parity = {0: 0, 1: 0, 5: 1, 6: 2}.get(level)
        if self.parity is None:
            raise RaidError(f"RAID{level} is not rebuilt")
        missing = reads.count(None)
        if level == 0 and missing:
            raise RaidError("RAID0 needs every disk")
        if level == 1 and missing == self.disks:
            raise RaidError("No disk of the mirror is here")
        if level in (5, 6) and missing > 1:
            raise RaidError(f"{missing} disks of a RAID{level} are missing:"
                            f" one can be rebuilt")
        if level in (5, 6) and self.disks < self.parity + 2:
            raise RaidError(f"RAID{level} needs at least "
                            f"{self.parity + 2} disks")
        self.rows = usable // chunk
        data = 1 if level == 1 else self.disks - self.parity
        self.size = self.rows * chunk * data

    def _row_slots(self, row):
        """(data slots in order, parity slots) of a row."""
        n = self.disks
        if self.level == 0:
            return list(range(n)), []
        group = row // self.delay
        if self.layout.startswith('left'):
            first = n - 1 - (group % n)
        else:
            first = group % n
        parity = [(first + k) % n for k in range(self.parity)]
        if self.layout.endswith('asymmetric'):
            data = [s for s in range(n) if s not in parity]
        else:
            start = parity[-1] + 1
            data = [(start + k) % n for k in range(n - self.parity)]
        return data, parity

    def _piece(self, slot, row, within, length, parity):
        position = self.offset + row * self.chunk + within
        read = self.reads[slot]
        if read is not None:
            data = read(position, length)
            return data + bytes(length - len(data))
        # Rebuilt: XOR of the row's other data chunks and P.
        p_slot = parity[0]
        value = 0
        data, _parity = self._row_slots(row)
        for other in data + [p_slot]:
            if other == slot:
                continue
            piece = self.reads[other](position, length)
            piece += bytes(length - len(piece))
            value ^= int.from_bytes(piece, 'little')
        return value.to_bytes(length, 'little')

    def read(self, offset, length):
        out = bytearray()
        length = max(0, min(length, self.size - offset))
        while length > 0:
            if self.level == 1:
                slot = next(i for i, r in enumerate(self.reads)
                            if r is not None)
                data = self.reads[slot](self.offset + offset, length)
                out += data
                break
            number, within = divmod(offset, self.chunk)
            per_row = self.disks - self.parity
            row, index = divmod(number, per_row)
            data, parity = self._row_slots(row)
            part = min(length, self.chunk - within)
            out += self._piece(data[index], row, within, part, parity)
            offset += part
            length -= part
        return bytes(out)


def name_order(names):
    """The members' order their names suggest, with a None where a number
    is skipped ('1', '2', '4' ... '8': disk 3 missing): [index or None]."""
    numbers = []
    for name in names:
        found = re.findall(r'(\d+)', str(name).rsplit('/', 1)[-1]
                           .rsplit('\\', 1)[-1].split('.')[0])
        numbers.append(int(found[-1]) if found else None)
    if None in numbers or len(set(numbers)) != len(numbers):
        return list(range(len(names)))
    by_number = {n: i for i, n in enumerate(numbers)}
    low, high = min(numbers), max(numbers)
    if high - low + 1 > 2 * len(numbers):
        return [by_number[n] for n in sorted(numbers)]
    return [by_number.get(n) for n in range(low, high + 1)]


# --- telling a right reconstruction from a wrong one ---------------------------

class _Image:
    """pytsk3's view of a reader."""

    def __new__(cls, reader):
        import pytsk3

        class Img(pytsk3.Img_Info):
            def __init__(self):
                super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def read(self, offset, length):
                return reader.read(offset, length)

            def get_size(self):
                return reader.size
        return Img()


def _quick(reader):
    """Cheap first test: a partition table or a boot sector at the
    start. Most wrong orders and offsets fail here."""
    head = reader.read(0, 4096)
    if len(head) < 1024:
        return False
    if head[510:512] == b'\x55\xaa':
        return True
    return head[1080:1082] == b'\x53\xef' or head[:4] == b'XFSB' or \
        head[1024:1026] in (b'H+', b'HX')


def _volumes(image):
    import pytsk3
    try:
        volume = pytsk3.Volume_Info(image)
        starts = [p.start for p in volume
                  if p.len and int(p.flags) & pytsk3.TSK_VS_PART_FLAG_ALLOC]
        return starts or [0]
    except IOError:
        return [0]


def score(reader, should_stop=None, limit=400):
    """(score, evidence) for one candidate: files whose bytes parse as
    their extension's format count most, then files read at all."""
    import pytsk3
    from trace_app.core.carving import EXTENSION_CARVER
    from trace_app.core.carving_signatures import is_valid_file
    image = _Image(reader)
    evidence = {'file_systems': [], 'files': 0, 'valid': 0, 'checked': 0,
                'errors': 0}
    total = 0.0
    for start in _volumes(image):
        try:
            fs = pytsk3.FS_Info(image, offset=start * 512)
        except IOError:
            continue
        evidence['file_systems'].append(start)
        stack, seen = [fs.open_dir('/')], 0
        while stack and seen < limit:
            if should_stop and should_stop():
                break
            try:
                directory = stack.pop()
                entries = list(directory)
            except IOError:
                evidence['errors'] += 1
                continue
            for entry in entries:
                name = entry.info.name.name.decode('utf-8', 'replace')
                meta = entry.info.meta
                if name in ('.', '..') or meta is None or \
                        name.startswith('$'):
                    continue
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        stack.append(entry.as_directory())
                    except IOError:
                        evidence['errors'] += 1
                    continue
                seen += 1
                evidence['files'] += 1
                kind = name.rsplit('.', 1)[-1].lower() if '.' in name \
                    else ''
                size = meta.size or 0
                # Only formats a validator parses say anything: a text
                # file reads the same however its stripes are ordered.
                if not size or size > 8 << 20 or \
                        kind not in EXTENSION_CARVER:
                    continue
                try:
                    data = entry.read_random(0, size)
                except IOError:
                    evidence['errors'] += 1
                    continue
                try:
                    valid = is_valid_file(data, kind)
                except Exception:
                    valid = None
                if valid is None:
                    continue
                evidence['checked'] += 1
                if valid:
                    evidence['valid'] += 1
        total += 10 * evidence['valid'] + evidence['files'] - \
            5 * (evidence['checked'] - evidence['valid']) - \
            2 * evidence['errors']
    if evidence['file_systems']:
        total += 5
    return total, evidence


def candidates(count, names=None, levels=None, chunks=CHUNKS,
               layouts=LAYOUTS, delays=DELAYS, missing=0):
    """Every Params `detect` tries for `count` images (plus `missing`
    disks rebuilt from parity)."""
    base = name_order(names) if names else list(range(count))
    disks = len(base) if names else count + missing
    if names is None or len(base) == count:
        base = base + [None] * (disks - len(base))
    if count <= MAX_PERMUTED:
        orders = {tuple(p) for p in itertools.permutations(base)}
    else:
        orders = {tuple(base), tuple(reversed(base))}
    present = len(base) - base.count(None)
    levels = levels or (['5'] if base.count(None) else
                        ['0', '5'] + (['6'] if present >= 4 else []))
    for level in levels:
        for order in sorted(orders, key=lambda o: [(-1 if x is None else x)
                                                   for x in o]):
            if level in ('0', 'jbod') and None in order:
                continue
            if level == 'jbod':
                yield Params('jbod', order=list(order))
                continue
            for chunk in chunks:
                for layout in (layouts if level in ('5', '6')
                               else ('left-asymmetric',)):
                    for delay in (delays if level in ('5', '6')
                                  else (1,)):
                        yield Params(level, chunk, layout, 0, list(order),
                                     delay)


def detect(members, names=None, should_stop=None, progress=None,
           keep=5, **options):
    """Try reconstructions of `members` ([(read, size)]); the `keep` best
    as [(score, Params, evidence)], best first. Options as `candidates`.
    """
    tried = list(candidates(len(members), names, **options))
    ranked = []
    for number, params in enumerate(tried):
        if should_stop and should_stop():
            break
        if progress and number % 8 == 0:
            progress(number, len(tried))
        try:
            reader = build(members, params)
        except RaidError:
            continue
        if not _quick(reader):
            continue
        value, evidence = score(reader, should_stop)
        if evidence['file_systems']:
            ranked.append((value, params, evidence))
    ranked.sort(key=lambda item: -item[0])
    if progress:
        progress(len(tried), len(tried))
    return ranked[:keep]

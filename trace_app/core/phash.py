"""Perceptual hashes of pictures, and grouping by them (no Qt, no numpy).

An exact hash (MD5, SHA-256) says two files are the same bytes. A picture
resized, re-saved at another JPEG quality, lightly cropped or brightened is
the same picture to an examiner and a different file to every exact hash.
A perceptual hash summarises what the picture *looks like*: pictures that
look alike have hashes that differ in few bits.

This is pHash: the picture reduced to 32x32 grey, its 2-D DCT taken, and
the 8x8 lowest frequencies (the DC term set aside) compared with their
median -- 64 bits. Robust to scaling, compression and small edits; not to
rotation, mirroring or heavy cropping. Pillow decodes; the DCT is a few
thousand multiplications in Python, so numpy (and scipy, which `imagehash`
needs) stay out of the build.

`groups` puts pictures within `threshold` bits of each other together. A
BK-tree, used first, saves nothing at the radius pHash needs (10 of 64 bits
reaches most of the tree): 13,336 pictures on a Fedora image took minutes
of Python, with the window starved of the interpreter lock while it ran.
Now every distinct hash is a 64-bit lane of one large integer, and one
picture is compared with all the others at once -- XOR, then a lane-wise
bit count (`_Lanes`) -- in the integer arithmetic's C loops: seconds.
"""

import io
import logging
import math
import os

logger = logging.getLogger('TRACE.PHash')

#: Bits two pictures may differ by and still be "the same picture". Ten of
#: 64 is the usual pHash bound for resized and recompressed copies.
DEFAULT_THRESHOLD = 10
#: Pictures smaller than this (pixels each way) are icons and bullets:
#: thousands of them look alike and none says anything.
MIN_SIDE = 32

#: Reference pictures are read from these extensions.
REFERENCE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.tif', '.tiff',
                        '.heic', '.heif', '.bmp', '.gif'}

_N = 32
_LOW = 8
# Cosine table: _COS[u][x] = cos((2x + 1) u pi / 2N), for the 8 frequencies
# kept.
_COS = [[math.cos((2 * x + 1) * u * math.pi / (2 * _N)) for x in range(_N)]
        for u in range(_LOW)]


def phash(data):
    """The 64-bit perceptual hash of a picture's bytes, as 16 hex digits,
    or None when it does not decode (or is too small to mean anything)."""
    if not data:
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(bytes(data))) as image:
            if min(image.size) < MIN_SIDE:
                return None
            try:
                # A JPEG decoded at 1/8 scale is just as good for 32x32 and
                # many times faster.
                image.draft('L', (_N * 2, _N * 2))
            except Exception:
                pass
            grey = image.convert('L').resize((_N, _N), Image.LANCZOS)
            pixels = list(grey.getdata())
    except Exception as exc:
        logger.debug("No perceptual hash: %s", exc)
        return None
    return _hash_pixels(pixels)


def _hash_pixels(pixels):
    rows = [pixels[y * _N:(y + 1) * _N] for y in range(_N)]
    # Separable 2-D DCT, keeping the 8 lowest frequencies each way: along
    # each row, then down each of those 8 columns.
    along = [[sum(c * p for c, p in zip(_COS[u], row)) for u in range(_LOW)]
             for row in rows]
    coefficients = []
    for v in range(_LOW):
        cos_v = _COS[v]
        for u in range(_LOW):
            coefficients.append(sum(cos_v[y] * along[y][u]
                                    for y in range(_N)))
    # The DC term is the picture's mean brightness: left out of the median
    # so a lighter copy compares like the original.
    ranked = sorted(coefficients[1:])
    middle = len(ranked) // 2
    median = (ranked[middle - 1] + ranked[middle]) / 2
    bits = 0
    for value in coefficients:
        bits = (bits << 1) | (1 if value > median else 0)
    return f"{bits:016x}"


def hash_folder(folder, should_stop=None):
    """[{'name', 'path', 'phash', 'size'}] for the pictures under `folder`
    (subfolders too) that decode."""
    out = []
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            if should_stop and should_stop():
                return out
            if os.path.splitext(name)[1].lower() not in REFERENCE_EXTENSIONS:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, 'rb') as handle:
                    data = handle.read()
            except OSError:
                continue
            value = phash(data)
            if value:
                out.append({'name': name, 'path': path, 'phash': value,
                            'size': len(data)})
    return out


def distance(a, b):
    """Bits in which two hashes differ (0 = look the same)."""
    return bin(int(a, 16) ^ int(b, 16)).count('1')


#: A hash with every bit clear is a picture of one flat colour (every DCT
#: coefficient equal): it "looks like" every other blank picture -- on a
#: Fedora image, 623 of them -- and says nothing.
BLANK = '0' * 16


def _lane_constant(byte, lanes):
    """`byte` repeated through `lanes` 64-bit lanes."""
    return int.from_bytes(bytes([byte]) * (8 * lanes), 'little')


class _Lanes:
    """Hashes packed as 64-bit lanes of one integer (lane i = values[i]),
    so `near` compares one value with all of them in a few big-integer
    operations instead of a Python loop per pair."""

    def __init__(self, values):
        self.values = list(values)
        count = len(self.values)
        self.count = count
        self.packed = int.from_bytes(
            b''.join(v.to_bytes(8, 'little') for v in self.values), 'little')
        # One 1 in each lane's lowest bit: value * ones repeats a value in
        # every lane.
        self.ones = _lane_flags(0x01, count)
        self.m1 = _lane_constant(0x55, count)
        self.m2 = _lane_constant(0x33, count)
        self.m4 = _lane_constant(0x0F, count)
        self.low = _lane_flags(0x7F, count)
        #: Every lane's flag bit: bit 7 of its first byte.
        self.flags = _lane_flags(0x80, count)

    def near(self, value, threshold):
        """The lanes within `threshold` bits of `value`, as flag bits (an
        integer; `indexes` lists them)."""
        x = self.packed ^ (value * self.ones)
        # Bits set per lane (SWAR). No step carries or borrows across a
        # lane: the masks leave each lane's top bits clear where a shift
        # brings the next lane's bits in.
        x -= (x >> 1) & self.m1
        x = (x & self.m2) + ((x >> 2) & self.m2)
        x = (x + (x >> 4)) & self.m4
        x += x >> 8
        x += x >> 16
        x += x >> 32
        # The lane's count is in its low byte (at most 64); adding
        # 127 - threshold sets bit 7 exactly when the count is larger.
        over = ((x & self.low) + (127 - threshold) * self.ones) & self.flags
        return self.flags ^ over

    def indexes(self, flags):
        """The lanes whose flag bit is set in `flags`."""
        if not flags:
            return []
        # Read as bytes, not bit by bit: clearing bits of an integer this
        # size one at a time is quadratic when most lanes are set.
        marks = flags.to_bytes(8 * self.count, 'little')[::8]
        found, at = [], marks.find(0x80)
        while at >= 0:
            found.append(at)
            at = marks.find(0x80, at + 1)
        return found


def _lane_flags(byte, lanes):
    """`byte` as the first byte of each of `lanes` 64-bit lanes."""
    return int.from_bytes((bytes([byte]) + b'\x00' * 7) * lanes, 'little')


def _distinct(items):
    """(the distinct hashes as integers, the item indexes holding each)."""
    holders = {}
    for index, item in enumerate(items):
        holders.setdefault(int(item['phash'], 16), []).append(index)
    return list(holders), list(holders.values())


def _comparable(items):
    return [i for i in items if i.get('phash') and i['phash'] != BLANK]


def groups(items, threshold=DEFAULT_THRESHOLD, should_stop=None):
    """Pictures that look alike: `items` are dicts with 'phash'; returns
    lists of them (two or more each), largest group first. Each member gets
    'distance' -- bits from the group's largest picture, which comes first
    (ties: by size, larger first). Grouping is
    transitive (A~B and B~C put A, B and C together), as an examiner
    following a picture's copies would. Blank pictures (`BLANK`) are left
    out."""
    items = _comparable(items)
    values, holders = _distinct(items)
    lanes = _Lanes(values)
    # Each component found by a walk from one picture: what is near a
    # member, and not yet placed, joins. Every picture is placed, and
    # asked about, once -- however many pairs are near (at 24 bits nearly
    # all of them are, and visiting each pair took minutes).
    unplaced = lanes.flags
    placed = [False] * len(values)
    clusters = []
    for first in range(len(values)):
        if placed[first]:
            continue
        placed[first] = True
        unplaced ^= 0x80 << (64 * first)
        component, waiting = [first], [first]
        while waiting:
            if should_stop and should_stop():
                return []
            joining = lanes.near(values[waiting.pop()], threshold) & unplaced
            if not joining:
                continue
            unplaced ^= joining
            for lane in lanes.indexes(joining):
                placed[lane] = True
                component.append(lane)
                waiting.append(lane)
        clusters.append([i for lane in component for i in holders[lane]])
    out = []
    for members in clusters:
        if len(members) < 2:
            continue
        # Measured from the largest: most likely the original, the others
        # its resized and re-saved copies.
        first = items[max(members, key=lambda i: int(
            items[i].get('size') or 0))]['phash']
        group = [dict(items[i], distance=distance(first, items[i]['phash']))
                 for i in members]
        group.sort(key=lambda g: (g['distance'], -int(g.get('size') or 0)))
        out.append(group)
    out.sort(key=len, reverse=True)
    return out


def match(references, items, threshold=DEFAULT_THRESHOLD, should_stop=None):
    """Each reference picture ({'name', 'phash', ...}) with the evidence
    pictures that look like it: [(reference, [item + 'distance'])], only
    references with a match, closest first."""
    items = _comparable(items)
    values, holders = _distinct(items)
    lanes = _Lanes(values)
    out = []
    for reference in references:
        if should_stop and should_stop():
            return []
        if not reference.get('phash') or reference['phash'] == BLANK:
            continue
        value = int(reference['phash'], 16)
        hits = []
        for lane in lanes.indexes(lanes.near(value, threshold)):
            d = bin(value ^ values[lane]).count('1')
            hits.extend((d, i) for i in holders[lane])
        hits.sort()
        if hits:
            out.append((reference, [dict(items[i], distance=d)
                                    for d, i in hits]))
    return out

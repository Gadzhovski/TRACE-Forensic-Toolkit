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

`groups` puts pictures within `threshold` bits of each other together with a
BK-tree, so a case of tens of thousands of pictures is not compared pair by
pair.
"""

import io
import logging
import math

logger = logging.getLogger('TRACE.PHash')

#: Bits two pictures may differ by and still be "the same picture". Ten of
#: 64 is the usual pHash bound for resized and recompressed copies.
DEFAULT_THRESHOLD = 10
#: Pictures smaller than this (pixels each way) are icons and bullets:
#: thousands of them look alike and none says anything.
MIN_SIDE = 32

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


def distance(a, b):
    """Bits in which two hashes differ (0 = look the same)."""
    return bin(int(a, 16) ^ int(b, 16)).count('1')


class _BKTree:
    """A metric tree over Hamming distance: finds every hash within a
    radius without comparing against all of them."""

    def __init__(self):
        self.root = None

    def add(self, value, item):
        if self.root is None:
            self.root = [value, [item], {}]
            return
        node = self.root
        while True:
            d = distance(value, node[0])
            if d == 0:
                node[1].append(item)
                return
            child = node[2].get(d)
            if child is None:
                node[2][d] = [value, [item], {}]
                return
            node = child

    def search(self, value, radius):
        found, stack = [], [self.root] if self.root else []
        while stack:
            node = stack.pop()
            d = distance(value, node[0])
            if d <= radius:
                found.extend((d, item) for item in node[1])
            for edge, child in node[2].items():
                if d - radius <= edge <= d + radius:
                    stack.append(child)
        return found


def groups(items, threshold=DEFAULT_THRESHOLD):
    """Pictures that look alike: `items` are dicts with 'phash'; returns
    lists of them (two or more each), largest group first. Each member gets
    'distance' -- bits from the group's largest picture, which comes first
    (ties: by size, larger first). Grouping is
    transitive (A~B and B~C put A, B and C together), as an examiner
    following a picture's copies would."""
    items = [i for i in items if i.get('phash')]
    tree = _BKTree()
    for index, item in enumerate(items):
        tree.add(item['phash'], index)
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for index, item in enumerate(items):
        for _d, other in tree.search(item['phash'], threshold):
            a, b = find(index), find(other)
            if a != b:
                parent[b] = a
    clusters = {}
    for index in range(len(items)):
        clusters.setdefault(find(index), []).append(index)
    out = []
    for members in clusters.values():
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


def match(references, items, threshold=DEFAULT_THRESHOLD):
    """Each reference picture ({'name', 'phash', ...}) with the evidence
    pictures that look like it: [(reference, [item + 'distance'])], only
    references with a match, closest first."""
    tree = _BKTree()
    items = [i for i in items if i.get('phash')]
    for index, item in enumerate(items):
        tree.add(item['phash'], index)
    out = []
    for reference in references:
        if not reference.get('phash'):
            continue
        hits = sorted(tree.search(reference['phash'], threshold))
        if hits:
            out.append((reference, [dict(items[i], distance=d)
                                    for d, i in hits]))
    return out

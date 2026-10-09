"""Add NIST CFReDS's file carving images to tools/carve_ground_truth.json.

https://cfreds-archive.nist.gov/FileCarving/index.html publishes 30 images
(L0-L5 x Graphic/Documents/Archive/Audio/Video), each made of fragments of
the original files (TestFiles/) between 5,120,000-byte fills, and their
layout (ImageLayouts.htm: label, size, start and end sector per piece).

    python tools/nist_carving_truth.py test_images/nist/carving

The layout's extents are used, its labels are not: they have errors (an
"arc3.gz" of arc2.bz2's size, "D2.pdf (2)" that is D1's second half,
"acr7.zip", "L0_Document.dd" for L0_Documents.dd). Each piece is
identified by its bytes instead -- the original file and position whose
bytes equal the piece's sectors in the image -- so the truth rests on
NIST's originals and nothing typed in. Pieces of one original between two
fills are one planted file (an L5 image braids the same original twice,
split differently, in two places).

Levels, as NIST describes them: L0 contiguous; L1 fragments in order; L2
fragments out of order; L3 a fragment missing; L4 files nested inside
others; L5 two files' fragments braided. An entry's offset is where the
original's first byte lies; its MD5 the original's, when every byte of it
is in the image. A file whose first fragment is missing has no header to
find; one of a type TRACE has no carver for is listed with recoverable
false, and the note says why.
"""

import hashlib
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TRUTH = os.path.join(HERE, 'carve_ground_truth.json')
SOURCE = 'https://cfreds-archive.nist.gov/FileCarving/index.html'
SECTOR = 512

LEVELS = {
    'L0': 'contiguous files between fills',
    'L1': 'files in fragments, in order',
    'L2': 'files in fragments, out of order',
    'L3': 'files with a fragment missing',
    'L4': 'files nested inside other files',
    'L5': 'fragments of two files braided together',
}


def carver_type(extension):
    """The type TRACE's carver reports for an extension, or None."""
    sys.path.insert(0, os.path.dirname(HERE))
    from trace_app.core.carving import EXTENSION_CARVER
    extension = {'tif': 'tiff'}.get(extension, extension)
    return extension if extension in EXTENSION_CARVER else None


def riff_size(data):
    """The length a RIFF file's header declares, or None."""
    if data[:4] == b'RIFF' and len(data) >= 8:
        return int.from_bytes(data[4:8], 'little') + 8
    return None


def layouts(text):
    """{layout name: [(label, size, first sector, last sector)]}, fills
    included (they separate planted files)."""
    found = {}
    parts = re.split(r'(L\d_\w+\.dd) drive layout', text)
    for name, body in zip(parts[1::2], parts[2::2]):
        cells = [html.unescape(re.sub(r'<[^>]+>', '', cell))
                 .replace('\xa0', ' ').strip()
                 for cell in re.findall(r'<td[^>]*>(.*?)</td>', body,
                                        re.S | re.I)]
        rows = []
        index = 0
        while index + 3 < len(cells):
            label, size, first, last = cells[index:index + 4]
            if label and not re.fullmatch(r'[\d,]+', label) and all(
                    re.fullmatch(r'[\d,]+', c) for c in (size, first, last)):
                rows.append((label, int(size.replace(',', '')),
                             int(first.replace(',', '')),
                             int(last.replace(',', ''))))
                index += 4
            else:
                index += 1
        found[name] = rows
    return found


def image_file(folder, layout_name):
    """'L0_Document.dd' -> the image NIST published (L0_Documents.dd)."""
    for candidate in (layout_name, layout_name.replace('_Document.',
                                                       '_Documents.')):
        if os.path.exists(os.path.join(folder, candidate)):
            return candidate
    raise FileNotFoundError(layout_name)


def block_index(originals):
    """{512 bytes: [(original, position)]} at every sector-aligned
    position (NIST cut the originals on sector boundaries), and each
    original's last part-sector: [(bytes, original, position)]."""
    index, tails = {}, []
    for name, data in originals.items():
        for position in range(0, len(data), SECTOR):
            block = data[position:position + SECTOR]
            if len(block) == SECTOR:
                index.setdefault(block, []).append((name, position))
            else:
                tails.append((block, name, position))
    return index, tails


def _run_length(disk, at, end, data, position):
    """Bytes from `at` on that continue `data` from `position`, whole
    sectors, ending early only where the original does."""
    length = 0
    while at + length < end and position + length < len(data):
        want = data[position + length:position + length + SECTOR]
        if disk[at + length:at + length + len(want)] != want:
            break
        length += len(want)
    return length


def scan(disk, begin, end, originals, index):
    """[(original, position in it, image offset, length)]: the stretch
    begin..end of the image read sector by sector, each sector placed in
    the original it continues, or where a new piece of one starts. Where
    several originals hold a sector, the one that matches furthest wins."""
    blocks, tails = index
    pieces = []
    at = begin
    while at < end:
        sector = disk[at:at + SECTOR]
        candidates = list(blocks.get(sector, []))
        candidates += [(name, position) for tail, name, position in tails
                       if sector.startswith(tail)]
        best = None
        for name, position in candidates:
            length = _run_length(disk, at, end, originals[name], position)
            if length and (best is None or length > best[2]):
                best = (name, position, length)
        if best is None:
            at += SECTOR
            continue
        name, position, length = best
        pieces.append((name, position, at, length))
        at += -(-length // SECTOR) * SECTOR
    return pieces


def build(folder):
    with open(os.path.join(folder, 'ImageLayouts.htm'), encoding='latin-1') \
            as handle:
        text = handle.read()
    tests = os.path.join(folder, 'TestFiles')
    originals = {}
    for name in os.listdir(tests):
        if not name.endswith('.json'):
            with open(os.path.join(tests, name), 'rb') as handle:
                originals[name] = handle.read()
    entries, problems = {}, []
    index = block_index(originals)
    for layout_name, rows in layouts(text).items():
        image = image_file(folder, layout_name)
        with open(os.path.join(folder, image), 'rb') as handle:
            disk = handle.read()
        # The layout's planted stretches: rows between two fills.
        regions, current = [], []
        for row in rows + [('Fill', 0, 0, 0)]:
            if row[0].lower() == 'fill':
                if current:
                    regions.append(current)
                current = []
            else:
                current.append(row)
        planted = {}
        for number, region in enumerate(regions):
            begin = min(r[2] for r in region) * SECTOR
            end = (max(r[3] for r in region) + 1) * SECTOR
            labels = {re.sub(r'\s*\([\d,]+\)$', '', r[0]).strip()
                      for r in region}
            found = scan(disk, begin, end, originals, index)
            if not found:
                problems.append(f"{image}: nothing at sectors "
                                f"{begin // SECTOR}-{end // SECTOR - 1}")
            for name, position, at, length in found:
                planted.setdefault((number, name), []).append(
                    (position, at, length, labels))
        items = []
        for (_region, original), pieces in planted.items():
            pieces.sort()
            data = originals[original]
            covered = sum(p[2] for p in pieces)
            extension = original.rsplit('.', 1)[-1].lower()
            kind = carver_type(extension)
            header = pieces[0][0] == 0
            item = {'name': original, 'type': kind or extension,
                    'offset': hex(pieces[0][1]) if header else None,
                    'size': len(data)}
            if len(pieces) > 1:
                item['fragments'] = [[hex(p[1]), p[2]] for p in pieces]
            notes = []
            if covered == len(data):
                item['md5'] = hashlib.md5(data).hexdigest()
                declared = riff_size(data)
                if declared and declared != len(data):
                    # The original is not what its own header says: a carve
                    # that follows the header holds the bytes after it too.
                    item['header_size'] = declared
                    notes.append(f"its RIFF header declares {declared:,} "
                                 f"bytes; the original is {len(data):,}")
            else:
                notes.append(f"{len(data) - covered:,} of its "
                             f"{len(data):,} bytes are not in the image")
            if len(pieces) > 1:
                ordered = [p[1] for p in pieces] == \
                    sorted(p[1] for p in pieces)
                notes.append(f"{len(pieces)} fragments"
                             + ('' if ordered else ', out of order'))
            if not header:
                notes.append("its first fragment is missing")
            if kind is None:
                notes.append(f"TRACE has no carver for .{extension}")
            if original not in pieces[0][3]:
                notes.append(f"the layout names it "
                             f"{' / '.join(sorted(pieces[0][3]))}")
            item['recoverable'] = kind is not None and header
            item['note'] = '; '.join(notes) or 'contiguous'
            items.append(item)
        items.sort(key=lambda i: int(i['offset'] or '0', 16))
        entries[image] = {
            'source': SOURCE,
            'title': f"NIST CFReDS file carving {image[:-3]} -- "
                     f"{LEVELS.get(image[:2], '')}",
            'path': f"nist/carving/{image}",
            'files': items,
        }
    return entries, problems


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    entries, problems = build(argv[1])
    for problem in problems:
        print('  !!', problem)
    with open(TRUTH, encoding='utf-8') as handle:
        truth = json.load(handle)
    for name in [n for n, v in truth.items()
                 if isinstance(v, dict) and v.get('source') == SOURCE]:
        del truth[name]
    truth.update(entries)
    with open(TRUTH, 'w', encoding='utf-8') as handle:
        json.dump(truth, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    print(f"{len(entries)} images, "
          f"{sum(len(e['files']) for e in entries.values())} files -> {TRUTH}")
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

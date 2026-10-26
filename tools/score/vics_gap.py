"""Why TRACE's carving misses pictures another tool carved.

AXIOM names each picture it carved from unallocated space by where it
starts ('Physical Sector 13043775'), and a Griffeye listing of its VICS
export gives that name with the MD5, size and type. This reads the image
at each such sector, finds the picture there, and asks TRACE's own carving
why it did not keep it:

    python tools/score/vics_gap.py IMAGE LISTING.csv [--json OUT]
                                   [--unaligned]

LISTING.csv: the other tool's rows (columns File Name, MD5, File Size,
Mime Type) -- a 'missing from TRACE' list, or the whole listing. TRACE's
carve of the image (unallocated space, every picture and video type) is
kept beside the image as <image>.trace-carves.json, so a second run only
diagnoses.

Reasons, first that applies:
    carved by TRACE      TRACE has a carve at that offset (the bytes differ:
                         the other tool sized it differently)
    allocated            the picture starts inside a live file's clusters
    not at a sector      it starts inside a sector; TRACE looks at sector
                         starts only
    rejected             TRACE's validator refuses the bytes the other tool
                         kept (cut short, damaged)
    sized differently    TRACE carves it standalone, to another length
    not found            no signature where the other tool says it starts
"""

import argparse
import collections
import csv
import hashlib
import json
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

logging.disable(logging.ERROR)

SIGNATURES = {
    'image/jpeg': (b'\xff\xd8\xff', 'jpg'),
    'image/gif': (b'GIF8', 'gif'),
    'image/png': (b'\x89PNG\r\n\x1a\n', 'png'),
    'image/bmp': (b'BM', 'bmp'),
    'video/x-msvideo': (b'RIFF', 'avi'),
    'video/x-ms-asf': (b'\x30\x26\xb2\x75\x8e\x66\xcf\x11', 'wmv'),
}
SECTOR = 512
_SECTOR_NAME = re.compile(r'Physical Sector (\d+)')


def listing(path):
    """[(sector, md5, size, mime)] of the rows named by a sector."""
    out = []
    with open(path, encoding='utf-8-sig', newline='') as handle:
        for row in csv.DictReader(handle):
            found = _SECTOR_NAME.match(row.get('File Name') or '')
            mime = (row.get('Mime Type') or '').lower()
            if found and mime in SIGNATURES:
                out.append((int(found.group(1)), row['MD5'].upper(),
                            int(row['File Size'] or 0), mime))
    return out


def trace_carves(handler, cache, unaligned=False):
    """{offset: [type, length, md5]} of TRACE's carve of the image
    (`unaligned`: as with the case setting carve_unaligned_pictures)."""
    if os.path.exists(cache):
        with open(cache, encoding='utf-8') as handle:
            return {int(k): v for k, v in json.load(handle).items()}
    from trace_app.core import carving, export_readiness
    found = {}

    def sink(content, file_type, offset, fragments=None):
        found[offset] = [file_type, len(content),
                         hashlib.md5(content).hexdigest().upper()]

    def progress(position, size, count):
        print(f"\r  carving {position * 100 // max(size, 1):3d}%  "
              f"{count:,} found", end='', file=sys.stderr, flush=True)
    carving.carve_image(handler, sorted(export_readiness.media_carve_types()),
                        sink, unallocated_only=True, progress=progress,
                        unaligned=carving.UNALIGNED_FAMILIES if unaligned
                        else ())
    print(file=sys.stderr)
    with open(cache, 'w', encoding='utf-8') as handle:
        json.dump(found, handle)
    return found


def standalone(handler, offset, file_type, length):
    """What TRACE's carver keeps when it starts at `offset`: (length, md5)
    or None."""
    from trace_app.core import carving
    from trace_app.infra.constants import CARVE_OVERLAP
    kept = []

    def sink(content, kind, at, fragments=None):
        if at == offset:
            kept.append((len(content), hashlib.md5(content).hexdigest()
                         .upper()))
    carver = carving.Carver(sink, wanted=[file_type], reader=handler.read,
                            image_size=handler.get_size())
    carver.alignment = 1
    chunk = handler.read(offset, max(length, 4096) + CARVE_OVERLAP)
    family = carving.EXTENSION_CARVER.get(file_type, file_type)
    try:
        carving.Carver.CARVERS[family](carver, chunk, offset)
    except Exception:
        return None
    return kept[0] if kept else None


def diagnose(handler, item, carves, allocated):
    from trace_app.core import carving
    sector, md5, size, mime = item
    signature, file_type = SIGNATURES[mime]
    start = sector * SECTOR
    head = handler.read(start, SECTOR + len(signature))
    at = head.find(signature)
    if at < 0 or at >= SECTOR:
        return 'not found', {}
    offset = start + at
    content = handler.read(offset, size)
    facts = {'offset': offset, 'within_sector': at,
             'same_bytes': hashlib.md5(content).hexdigest().upper() == md5}
    if offset in carves:
        facts['trace'] = carves[offset]
        return 'carved by TRACE', facts
    if carving.Carver.is_offset_allocated(offset, 1, allocated):
        return 'allocated', facts
    if offset % SECTOR:
        return 'not at a sector', facts
    if not carving.is_valid_file(content, file_type):
        return 'rejected', facts
    kept = standalone(handler, offset, file_type, size)
    facts['standalone'] = kept
    if kept is None:
        return 'rejected', facts
    return 'sized differently', facts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('image')
    parser.add_argument('listing')
    parser.add_argument('--json', help="write each item's diagnosis here")
    parser.add_argument('--unaligned', action='store_true',
                        help="carve pictures at any byte, as the case "
                             "setting carve_unaligned_pictures does")
    args = parser.parse_args(argv)
    from trace_app.core import carving
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(args.image)
    if not handler.load_image():
        sys.exit(f"Could not open {args.image}")
    items = listing(args.listing)
    print(f"{len(items):,} carved pictures and videos named by sector")
    carves = trace_carves(
        handler, args.image + ('.trace-carves-unaligned.json'
                               if args.unaligned else '.trace-carves.json'),
        args.unaligned)
    traced = {md5 for _type, _length, md5 in carves.values()}
    print(f"TRACE carved {len(carves):,}")
    allocated = carving.allocation_map(handler)
    counts = collections.Counter()
    by_type = collections.defaultdict(collections.Counter)
    out = []
    for item in items:
        if item[1] in traced:
            reason, facts = 'same MD5 carved by TRACE', {}
        else:
            reason, facts = diagnose(handler, item, carves, allocated)
        counts[reason] += 1
        by_type[reason][item[3]] += 1
        out.append({'sector': item[0], 'md5': item[1], 'size': item[2],
                    'mime': item[3], 'reason': reason, **facts})
    print(f"\n{'reason':28} {'count':>7}  types")
    for reason, count in counts.most_common():
        kinds = ', '.join(f"{mime.split('/')[1]} {n}" for mime, n in
                          by_type[reason].most_common())
        print(f"{reason:28} {count:7,}  {kinds}")
    contiguous = sum(1 for row in out if row.get('same_bytes'))
    print(f"\nBytes at the sector equal the other tool's MD5 (contiguous): "
          f"{contiguous:,} of {len(out):,}")
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(out, handle, indent=1)
    handler.close_resources()


if __name__ == '__main__':
    main()

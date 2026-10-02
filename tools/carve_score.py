"""Score the carvers against the published DFTT/DFRWS answer keys.

Carving quality is otherwise unmeasurable: a scan that "finds files" tells you
nothing about the files it silently lost, or the fragments it invented. This
runs the real carvers over a test image the way carve_files does, then compares
what came back against ground truth transcribed from the test author's own key.

    python tools/carve_score.py                     # every known image
    python tools/carve_score.py 11-carve-fat.dd     # just one

Exit status is non-zero if any image scores below its recorded baseline, so
this can gate a change that would lose a file.
"""

import hashlib
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Rejected candidates are logged per-attempt and are the normal case; they are
# noise here, not findings.
logging.disable(logging.ERROR)

from trace_app.core.carving import Carver
from trace_app.infra.constants import CARVE_OVERLAP, CHUNK_SIZE

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMAGE_DIR = os.path.join(ROOT, 'test_images')
TRUTH = os.path.join(HERE, 'carve_ground_truth.json')

#: What the carvers scored when this harness was written, before any of the
#: accuracy work. A run may exceed these; it must never fall below one.
BASELINE = {
    '11-carve-fat.dd': 15,      # every planted file of a supported type
    '12-carve-ext2.dd': 10,     # likewise
    'dfrws-2006-challenge.raw': 25,  # 27 planted; the 2 misses are frag'd ZIPs
    'dfrws-2007-challenge.img': 30,  # 54 planted, only 5 contiguous
}

#: How close a recovered offset must be to the documented one to count as the
#: same file. Zero: the offset IS the identity, and a carve that starts even a
#: byte early is a different span of evidence.
OFFSET_TOLERANCE = 0


def carve_image(path):
    """Run every carver over `path`, returning [(type, offset, bytes)].

    The whole image, every type, no allocation map: the answer keys list
    files wherever they lie, and the score is of the carvers themselves --
    the same Carver class (trace_app/core/carving.py) an examiner runs.
    """
    found = []
    carver = Carver(lambda content, file_type, offset:
                    found.append((file_type, offset, content)))

    with open(path, 'rb') as handle:
        data = handle.read()

    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + CHUNK_SIZE + CARVE_OVERLAP]
        if not chunk:
            break
        for name, function in Carver.CARVERS.items():
            try:
                function(carver, chunk, offset)
            except Exception as exc:
                print(f"    !! {name} raised {type(exc).__name__}: {exc}")
        offset += CHUNK_SIZE
    return found


def _is_fragmented(item):
    """Does the key say this file's blocks are not contiguous?"""
    return 'fragment' in (item.get('note') or '').lower()

def score(image_name, truth, found):
    """Compare one image's results against its key. Returns (hits, total)."""
    expected = [f for f in truth['files']
                if f.get('recoverable') and f.get('offset')]
    by_offset = {off: (kind, blob) for kind, off, blob in found}

    print(f"\n=== {image_name}")
    print(f"    {truth['title']}")
    print(f"    {truth['source']}\n")

    hits = 0
    exact = 0
    exact_possible = 0
    for item in expected:
        want = int(item['offset'], 16)
        got = by_offset.get(want)
        if got and got[0] == item['type']:
            blob = got[1]
            hits += 1
            mark = 'FOUND'
            detail = f"{len(blob):,} bytes"
            if item.get('md5'):
                digest = hashlib.md5(blob).hexdigest()
                if digest == item['md5']:
                    exact += 1
                    exact_possible += 1
                    detail += ", MD5 matches key"
                elif _is_fragmented(item):
                    # Expected: the file's blocks are not adjacent on disk, so
                    # a contiguous carve cannot reproduce it. Locating it is
                    # still the win; reassembly is a separate capability.
                    detail += ", fragmented (no byte-exact carve possible)"
                else:
                    exact_possible += 1
                    detail += (f", MD5 MISMATCH ({digest[:8]}... vs "
                               f"{item['md5'][:8]}...)")
                    mark = 'PARTIAL'
        else:
            mark = 'MISS '
            detail = item.get('note', '')
        print(f"    [{mark}] {item['type']:4} @{item['offset']:>10}  "
              f"{item['name']:<18} {detail}")

    # Files the key says exist but no offset was documented for.
    undocumented = [f for f in truth['files']
                    if f.get('recoverable') and not f.get('offset')]
    if undocumented:
        print(f"\n    not scored (no offset in the published key): "
              f"{', '.join(f['name'] for f in undocumented)}")

    # Anything carved that the key does not account for.
    known = {int(f['offset'], 16) for f in truth['files'] if f.get('offset')}
    extras = [(k, o, len(b)) for k, o, b in found if o not in known]
    if extras:
        print(f"\n    {len(extras)} unaccounted carve(s):")
        flagged = {int(f['offset'], 16): f['note']
                   for f in truth.get('false_positives_to_avoid', [])}
        for kind, off, size in sorted(extras, key=lambda x: x[1]):
            note = flagged.get(off, '')
            tag = '  <-- KNOWN FALSE POSITIVE' if note else ''
            print(f"      {kind:4} @0x{off:<10x} {size:>12,} bytes{tag}")

    if exact_possible:
        print(f"\n    byte-exact: {exact}/{exact_possible} of the files a "
              f"contiguous carver can reproduce")

    total = len(expected)
    base = BASELINE.get(image_name)
    verdict = ''
    if base is not None:
        if hits < base:
            verdict = f"  REGRESSION (baseline {base})"
        elif hits > base:
            verdict = f"  improved on baseline {base}"
        else:
            verdict = f"  at baseline {base}"
    print(f"\n    SCORE: {hits}/{total}{verdict}")
    return hits, total, base


def main():
    with open(TRUTH, encoding='utf-8') as handle:
        truth = json.load(handle)

    wanted = sys.argv[1:]
    names = [n for n in truth if not n.startswith('_')]
    if wanted:
        names = [n for n in names if n in wanted]
        if not names:
            print(f"No ground truth for: {', '.join(wanted)}")
            return 2

    regressed = False
    for name in names:
        path = os.path.join(IMAGE_DIR, name)
        if not os.path.exists(path):
            print(f"\n=== {name}\n    not present in test_images/ -- skipped")
            continue
        hits, total, base = score(name, truth[name], carve_image(path))
        if base is not None and hits < base:
            regressed = True

    print()
    return 1 if regressed else 0


if __name__ == '__main__':
    sys.exit(main())

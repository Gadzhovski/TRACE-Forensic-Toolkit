"""Score the carvers against the published DFTT/DFRWS answer keys.

Carving quality is otherwise unmeasurable: a scan that "finds files" tells you
nothing about the files it silently lost, or the fragments it invented. This
runs the real carvers over a test image the way carve_files does, then compares
what came back against ground truth transcribed from the test author's own key.

    python tools/score/carve_score.py                     # every known image
    python tools/score/carve_score.py 11-carve-fat.dd     # just one

Exit status is non-zero if any image scores below its recorded baseline, so
this can gate a change that would lose a file.
"""

import hashlib
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

# Rejected candidates are logged per-attempt and are the normal case; they are
# noise here, not findings.
logging.disable(logging.ERROR)

from trace_app.core.carving import Carver
from trace_app.infra.constants import CARVE_OVERLAP, CHUNK_SIZE
from tools import testdata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
IMAGE_DIR = os.path.join(ROOT, 'test_images')
TRUTH = os.path.join(ROOT, 'tests', 'expected', 'carve_ground_truth.json')

#: What the carvers scored when this harness was written, before any of the
#: accuracy work. A run may exceed these; it must never fall below one.
BASELINE = {
    '11-carve-fat.dd': 15,      # every planted file of a supported type
    '12-carve-ext2.dd': 10,     # likewise
    # 27 planted. The 2 that were missed are ZIPs in two fragments, now
    # rebuilt by reassembly (core/reassembly.py) -- byte-exact.
    'dfrws-2006-challenge.raw': 27,
    # 114 planted of carvable types once MP3/MPG/AVI/FLV/EXE/ELF/mbox were
    # added (30 of the original 54); every miss is fragmented or incomplete.
    # Mail recovered as .eml -- the challenge's ".mbox" files are saved
    # RFC 5322 messages -- raised this from 63. Reassembly of the PDFs in
    # two fragments, in order, raised it to 78.
    'dfrws-2007-challenge.img': 78,
    # Real published files of 40+ formats (tools/testdata/build/carve_corpus.py): every one,
    # byte-exact, and none of its signature decoys. 63 since the camera raws
    # (CR2, CR3, NEF x2, ARW, DNG, RAF, RW2, ORF, PEF) and two PSBs.
    'carve-corpus.dd': 63,
    # NIST CFReDS file carving (tools/score/nist_carving_truth.py: every planted
    # piece identified by its bytes against NIST's originals). L0/L1 are
    # whole files -- "L1" pieces lie end to end -- all byte-exact once the
    # BMP (5,000,000-byte cap), GIF (first 00 3B) and MP3 (cut last frame)
    # carvers were fixed. L2 (out of order) and L3 (a piece missing) are
    # located at most: no structure proves an out-of-order join. L4/L5
    # (nested, braided): ZIPs and PDFs rebuilt around what lies inside
    # them once a nested archive's end record stopped being taken as the
    # outer one's.
    'L0_Graphic.dd': 5, 'L1_Graphic.dd': 5, 'L2_Graphic.dd': 3,
    'L3_Graphic.dd': 1, 'L4_Graphic.dd': 6, 'L5_Graphic.dd': 3,
    'L0_Archive.dd': 6, 'L1_Archive.dd': 6, 'L2_Archive.dd': 0,
    'L3_Archive.dd': 0, 'L4_Archive.dd': 4, 'L5_Archive.dd': 1,
    'L0_Video.dd': 6, 'L1_Video.dd': 6, 'L2_Video.dd': 5,
    'L3_Video.dd': 3, 'L4_Video.dd': 7, 'L5_Video.dd': 7,
    'L0_Documents.dd': 7, 'L1_Documents.dd': 7, 'L2_Documents.dd': 0,
    'L3_Documents.dd': 1, 'L4_Documents.dd': 8, 'L5_Documents.dd': 7,
    'L0_Audio.dd': 2, 'L1_Audio.dd': 2, 'L2_Audio.dd': 2,
    'L3_Audio.dd': 2, 'L4_Audio.dd': 2, 'L5_Audio.dd': 2,
}

#: Files rebuilt from fragments, byte-exact against the key. Gated like
#: the score: a change that loses one is a regression even if a contiguous
#: carve still "locates" the file.
REBUILT_BASELINE = {
    # lin_test.pdf (2 fragments: ext2's indirect block) and n_lin_ss.pdf
    # (4: the indirect blocks of a 700 KB file).
    '12-carve-ext2.dd': 2,
    'dfrws-2006-challenge.raw': 2,      # 4b.zip, 4c.zip
    'dfrws-2007-challenge.img': 4,      # 2.pdf, 3.pdf, 13.pdf, 14.pdf
    # NIST: an .xlsx and a .pptx rebuilt around the files nested in their
    # gaps, the braided .docx/.xlsx/.pdf pairs, one archive in each.
    'L4_Archive.dd': 1, 'L5_Archive.dd': 1,
    'L4_Documents.dd': 3, 'L5_Documents.dd': 6,
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
    with open(path, 'rb') as handle:
        data = handle.read()
    carver = Carver(lambda content, file_type, offset, fragments=None:
                    found.append((file_type, offset, content, fragments)),
                    reader=lambda offset, length: data[offset:offset + length],
                    image_size=len(data))

    # As the engine runs them (carving._carve_image): containers first, in
    # its order, and each read owning only its own chunk -- the read-ahead
    # belongs to the next read. The scorer used to run the carvers in
    # dictionary order, which is not what an examiner's carve does.
    from trace_app.core.carving import _CARVE_ORDER
    order = [name for name in _CARVE_ORDER if name in Carver.CARVERS] + \
        [name for name in Carver.CARVERS if name not in _CARVE_ORDER]
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + CHUNK_SIZE + CARVE_OVERLAP]
        if not chunk:
            break
        carver.own_end = offset + CHUNK_SIZE
        for name in order:
            try:
                Carver.CARVERS[name](carver, chunk, offset)
            except Exception as exc:
                print(f"    !! {name} raised {type(exc).__name__}: {exc}")
        carver.own_end = None
        carver.note_unfinished(chunk, offset, Carver.REASSEMBLERS,
                               limit=CHUNK_SIZE)
        offset += CHUNK_SIZE
    carver.reassemble_fragmented()
    return found


def _is_fragmented(item):
    """Does the key say this file's blocks are not contiguous?"""
    return 'fragment' in (item.get('note') or '').lower()

def score(image_name, truth, found):
    """Compare one image's results against its key. Returns (hits, total)."""
    expected = [f for f in truth['files']
                if f.get('recoverable') and f.get('offset')]
    by_offset = {off: (kind, blob, pieces)
                 for kind, off, blob, pieces in found}

    print(f"\n=== {image_name}")
    print(f"    {truth['title']}")
    print(f"    {truth['source']}\n")

    hits = 0
    rebuilt = 0
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
                if item.get('header_size') == len(blob) and \
                        hashlib.md5(blob[:item['size']]).hexdigest() == \
                        item['md5']:
                    # The original is shorter than its own header says
                    # (NIST's audio2.wav, by 8 bytes): the carve is the
                    # original, then the bytes the header claims too.
                    digest = item['md5']
                    detail += " (to the length its header declares)"
                if digest == item['md5']:
                    exact += 1
                    exact_possible += 1
                    detail += ", MD5 matches key"
                    if got[2]:
                        rebuilt += 1
                        detail += (f" -- reassembled from {len(got[2])} "
                                   f"fragments")
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
    extras = [(k, o, len(b)) for k, o, b, _ in found if o not in known]
    if extras:
        print(f"\n    {len(extras)} unaccounted carve(s):")
        flagged = {int(f['offset'], 16): f['note']
                   for f in truth.get('false_positives_to_avoid', [])}
        for kind, off, size in sorted(extras, key=lambda x: x[1]):
            note = flagged.get(off, '')
            tag = '  <-- KNOWN FALSE POSITIVE' if note else ''
            print(f"      {kind:4} @0x{off:<10x} {size:>12,} bytes{tag}")

    if exact_possible:
        print(f"\n    byte-exact: {exact}/{exact_possible} of the files "
              f"TRACE can reproduce ({rebuilt} reassembled from fragments)")
    least = REBUILT_BASELINE.get(image_name)
    if least is not None and rebuilt < least:
        print(f"    REASSEMBLY REGRESSION: {rebuilt} rebuilt "
              f"(baseline {least})")
        hits = -1               # fails the run below, whatever the count

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
        # An entry may name its image's place under test_images/ (NIST's
        # carving set lives in nist/carving/); others are found by name.
        path = os.path.join(IMAGE_DIR, truth[name]['path']) \
            if 'path' in truth[name] else testdata.locate(name)
        if not path or not os.path.exists(path):
            print(f"\n=== {name}\n    not present in test_images/ -- skipped")
            continue
        hits, total, base = score(name, truth[name], carve_image(path))
        if hits < 0 or (base is not None and hits < base):
            regressed = True

    print()
    return 1 if regressed else 0


if __name__ == '__main__':
    sys.exit(main())

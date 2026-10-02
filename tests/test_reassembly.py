"""Rebuilding files the file system split in two (core/reassembly.py).

Every input is generated here: a real ZIP and a real PDF, cut at a sector
boundary inside the member or stream whose checksum must then prove the
split, with foreign bytes laid in the gap. The DFRWS images, where the same
thing happens to real files, are scored by tools/carve_score.py.
"""

import io
import os
import random
import re
import sqlite3
import zipfile

import pytest

SECTOR = 512


class _Image:
    """Just enough of ImageHandler for carve_image over bytes."""

    def __init__(self, data):
        self.data = bytes(data)

    def get_size(self):
        return len(self.data)

    def read(self, offset, length):
        return self.data[offset:offset + length]

    def get_partitions(self):
        return []

    def has_filesystem(self, _offset):
        return False


def _carve(data, types):
    from trace_app.core.carving import carve_image
    found = []
    carve_image(_Image(data), types,
                lambda content, kind, offset, fragments=None:
                found.append((kind, offset, content, fragments)),
                unallocated_only=False)
    return found


def _text(seed, words=40000):
    rng = random.Random(seed)
    vocabulary = [''.join(rng.choice('abcdefghijklmnopqrstuvwxyz')
                          for _ in range(rng.randint(2, 9)))
                  for _ in range(3000)]
    return ' '.join(rng.choice(vocabulary) for _ in range(words)).encode()


def _split_on_disk(content, split, gap, lead=8 * SECTOR, seed=7):
    """`content` at `lead`, its first `split` bytes, then `gap` bytes of
    something else, then the rest -- the way a file system lays a file
    around a block already in use."""
    rng = random.Random(seed)
    noise = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    tail = (-(lead + len(content) + gap)) % SECTOR + 16 * SECTOR
    return (noise(lead) + content[:split] + noise(gap) + content[split:]
            + noise(tail))


def _zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('notes/first.txt', _text(1, 3000))
        archive.writestr('report.txt', _text(2))
        archive.writestr('zz-last.txt', _text(3, 2000))
    return buffer.getvalue()


def _member_data(content, name):
    """(start, end) of a member's compressed data in the archive."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        info = archive.getinfo(name)
    header = info.header_offset
    name_len = int.from_bytes(content[header + 26:header + 28], 'little')
    extra = int.from_bytes(content[header + 28:header + 30], 'little')
    start = header + 30 + name_len + extra
    return start, start + info.compress_size


def test_a_zip_in_two_fragments_is_rebuilt_exactly():
    content = _zip()
    begin, end = _member_data(content, 'report.txt')
    split = ((begin + end) // 2) // SECTOR * SECTOR      # inside report.txt
    gap = 37 * SECTOR
    lead = 8 * SECTOR
    image = _split_on_disk(content, split, gap, lead)

    found = [f for f in _carve(image, ['zip']) if f[1] == lead]
    assert len(found) == 1
    kind, offset, rebuilt, fragments = found[0]
    assert kind == 'zip' and rebuilt == content
    assert fragments == [(lead, split), (lead + split + gap,
                                         len(content) - split)]


def _pdf():
    import pymupdf
    document = pymupdf.open()
    for page_number in range(6):
        page = document.new_page()
        words = _text(10 + page_number, 900).decode()
        page.insert_textbox(page.rect + (36, 36, -36, -36), words,
                            fontsize=6)
    content = document.tobytes(deflate=True, garbage=0)
    document.close()
    return content


def _stream_spans(content):
    """(data start, data end) of every Flate stream in the file."""
    spans = []
    for match in re.finditer(rb'/Filter\s*/FlateDecode', content):
        start = re.compile(rb'stream\r?\n').search(content, match.end())
        stop = content.find(b'endstream', start.end())
        spans.append((start.end(), stop))
    return spans


def test_a_pdf_in_two_fragments_is_rebuilt_exactly():
    content = _pdf()
    # The longest Flate stream in the first half: its Adler-32 must decide.
    candidates = [s for s in _stream_spans(content)
                  if s[1] < len(content) * 0.75 and s[1] - s[0] > 3 * SECTOR]
    begin, end = max(candidates, key=lambda s: s[1] - s[0])
    split = ((begin + end) // 2) // SECTOR * SECTOR
    assert begin < split < end
    gap = 23 * SECTOR
    lead = 8 * SECTOR
    image = _split_on_disk(content, split, gap, lead)

    found = [f for f in _carve(image, ['pdf']) if f[1] == lead]
    assert len(found) == 1
    kind, offset, rebuilt, fragments = found[0]
    assert kind == 'pdf' and rebuilt == content
    assert fragments == [(lead, split), (lead + split + gap,
                                         len(content) - split)]


def test_a_whole_pdf_is_not_flagged_and_stays_contiguous():
    from trace_app.core.reassembly import pdf_contradicts_itself
    content = _pdf()
    assert not pdf_contradicts_itself(content)
    lead = 8 * SECTOR
    image = _split_on_disk(content, len(content), 0, lead)
    found = [f for f in _carve(image, ['pdf']) if f[1] == lead]
    # The contiguous carver ends at %%EOF itself, without the line end.
    assert found and found[0][2] == content.rstrip(b'\r\n')
    assert found[0][3] is None


def test_without_its_second_fragment_nothing_is_invented():
    """The first fragment alone, followed by unrelated data: no split can be
    proved, so no ZIP is rebuilt from whatever lies after it."""
    content = _zip()
    begin, end = _member_data(content, 'report.txt')
    split = ((begin + end) // 2) // SECTOR * SECTOR
    lead = 8 * SECTOR
    rng = random.Random(3)
    image = bytes(rng.getrandbits(8) for _ in range(lead)) + \
        content[:split] + bytes(rng.getrandbits(8) for _ in range(64 * SECTOR))
    assert not [f for f in _carve(image, ['zip']) if f[1] == lead]


def test_a_pdf_carved_across_a_gap_contradicts_itself():
    from trace_app.core.reassembly import pdf_contradicts_itself
    content = _pdf()
    begin, end = max(_stream_spans(content), key=lambda s: s[1] - s[0])
    split = ((begin + end) // 2) // SECTOR * SECTOR
    spliced = content[:split] + b'\0' * (5 * SECTOR) + content[split:]
    assert pdf_contradicts_itself(spliced)


def test_a_rebuilt_file_keeps_its_fragments_in_the_case(tmp_path):
    from trace_app.core.carving import carve_evidence, read_carved
    from trace_app.core.case import Case

    content = _zip()
    begin, end = _member_data(content, 'report.txt')
    split = ((begin + end) // 2) // SECTOR * SECTOR
    image = _split_on_disk(content, split, 11 * SECTOR)
    path = tmp_path / 'split.dd'
    path.write_bytes(image)

    case = Case.create(str(tmp_path / 'case'), 'Reassembly')
    evidence = case.add_evidence(str(path))
    try:
        carve_evidence(_Image(image), case, evidence, ['zip'],
                       unallocated_only=False)
        rows = [r for r in case.carved_files(evidence) if r['offset'] == 8 * SECTOR]
        assert len(rows) == 1
        row = rows[0]
        assert row['fragments'] == [[8 * SECTOR, split],
                                    [8 * SECTOR + split + 11 * SECTOR,
                                     len(content) - split]]
        assert case.carved_fragments(evidence, row['offset']) == row['fragments']
        # Read back from the evidence through its fragments, not the span.
        assert read_carved(_Image(image).read, row['offset'], row['size'],
                           row['fragments']) == content
        with open(row['path'], 'rb') as handle:
            assert handle.read() == content
    finally:
        case.close()


def test_a_version_7_case_gains_the_fragments_column(tmp_path):
    from trace_app.core.case import SCHEMA_VERSION, Case
    folder = str(tmp_path / 'case')
    Case.create(folder, 'Old case').close()
    db = sqlite3.connect(os.path.join(folder, 'case.db'))
    # carved_files as version 7 wrote it (DROP COLUMN is SQLite 3.35+).
    db.execute("DROP TABLE carved_files")
    db.execute("CREATE TABLE carved_files (id INTEGER PRIMARY KEY, "
               "evidence_id INTEGER NOT NULL, artifact_ref TEXT NOT NULL, "
               "name TEXT NOT NULL, path TEXT NOT NULL, offset INTEGER NOT "
               "NULL, size INTEGER NOT NULL, type TEXT NOT NULL, sha256 TEXT, "
               "embedded_date TEXT, date_source TEXT, carved_utc TEXT NOT "
               "NULL)")
    db.execute("UPDATE case_info SET value='7' WHERE key='schema_version'")
    db.commit()
    db.close()
    case = Case.open(folder)
    try:
        assert str(case._get('schema_version')) == str(SCHEMA_VERSION)
        columns = [r[1] for r in case._db.execute(
            "PRAGMA table_info(carved_files)")]
        assert 'fragments' in columns
    finally:
        case.close()


def _rebuilt_against_key(path, name, reassemble, rebuilt):
    import hashlib
    import json
    from tests.conftest import ROOT
    from trace_app.core import carving_formats as formats

    with open(os.path.join(ROOT, 'tools', 'carve_ground_truth.json'),
              encoding='utf-8') as handle:
        key = json.load(handle)[name]['files']
    with open(path, 'rb') as handle:
        source = formats.Source(handle.read(), 0)
    checked = set()
    for item in key:
        if item['name'] in rebuilt:
            result = reassemble(source, int(item['offset'], 16),
                                32 * 1024 * 1024)
            assert result, item['name']
            assert hashlib.md5(result[0]).hexdigest() == item['md5']
            assert len(result[1]) == 2
            checked.add(item['name'])
    assert checked == rebuilt


def test_a_pdf_split_by_an_ext2_indirect_block_is_rebuilt():
    """DFTT #12's lin_test.pdf: twelve 1 KB blocks, ext2's indirect block,
    then the rest -- rebuilt to the MD5 in the test's published key."""
    from tests.conftest import image_path
    from trace_app.core.reassembly import reassemble_pdf
    name = '12-carve-ext2.dd'
    _rebuilt_against_key(image_path(name), name, reassemble_pdf,
                         {'lin_test.pdf'})


def test_dfrws_2006_fragmented_zips_are_rebuilt():
    """The two ZIPs DFRWS 2006 stores in two fragments, byte-exact. The
    DFRWS images are scored locally by tools/carve_score.py and are not
    fetched in CI, so this one skips without them even there."""
    from tests.conftest import IMAGE_DIR
    from trace_app.core.reassembly import reassemble_zip
    name = 'dfrws-2006-challenge.raw'
    path = os.path.join(IMAGE_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"{name} is not in test_images/ (not used by CI)")
    _rebuilt_against_key(path, name, reassemble_zip, {'4b.zip', '4c.zip'})

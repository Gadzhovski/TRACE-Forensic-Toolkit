"""What carving proves about what it recovers (core/carve_verify.py,
carve_origin.py, and the run records in carving.py).

The DFRWS 2006 challenge's answer key says which of its files are stored in
fragments. Every file carved there is checked against it: no fragmented
file may be called complete (each carve of one holds another file's bytes),
no unfragmented one partial, and the ZIPs reassembly rebuilt must be
reconstructed. The 51 published files of the carving corpus must be
complete or valid, and complete wherever the format carries a proof. On
DFTT's JPEG search image, unallocated carving recovers exactly the two
deleted JPEGs -- one disguised as .hmm -- and names them from their
deleted directory entries.
"""

import json
import os

import pytest

from tests.conftest import ROOT, image_path

GROUND_TRUTH = os.path.join(ROOT, 'tools', 'carve_ground_truth.json')


def carve_all(name, unallocated_only=False):
    from trace_app.core import carve_verify, carving
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.load_image()
    found = {}

    def sink(content, file_type, offset, fragments=None):
        found[offset] = (file_type, carve_verify.assess(content, file_type,
                                                        fragments))
    stats = {}
    try:
        carving.carve_image(handler, [t.lower() for t in
                                      carving.CARVABLE_TYPES], sink,
                            unallocated_only, stats=stats)
    finally:
        handler.close_resources()
    return found, stats


def test_statuses_agree_with_the_dfrws_2006_answer_key():
    with open(GROUND_TRUTH, encoding='utf-8') as handle:
        key = json.load(handle)['dfrws-2006-challenge.raw']['files']
    found, stats = carve_all('dfrws-2006-challenge.raw')
    checked = partial = 0
    for planted in key:
        offset = int(planted['offset'], 16)
        if offset not in found:
            continue
        file_type, verdict = found[offset]
        fragmented = 'fragmented' in planted.get('note', '')
        checked += 1
        status = verdict['status']
        if file_type == 'zip' and fragmented:
            assert status == 'reconstructed', planted['name']
        elif fragmented:
            # Never "complete": partial where a check caught the foreign
            # data, valid where the format has nothing that could.
            assert status in ('partial', 'valid'), planted['name']
            partial += status == 'partial'
        else:
            assert status in ('complete', 'valid'), \
                (planted['name'], verdict['checks'])
    assert checked >= 20
    # 10 of the 13 fragmented carves are caught: four OLE files by their
    # sector chains, five JPEGs by bytes a JPEG never writes, one by its
    # restart markers, one HTML page by a second <html>.
    assert partial >= 10
    # The run's own record of what it saw.
    candidates = sum(stats['candidates'].values())
    rejected = sum(stats['rejected'].values())
    assert candidates - rejected >= len(found)
    assert stats['bytes_scanned'] > 0


def test_every_corpus_file_is_complete():
    found, _stats = carve_all('carve-corpus.dd')
    assert len(found) == 51
    statuses = {file_type: verdict['status']
                for file_type, verdict in found.values()}
    assert set(statuses.values()) <= {'complete', 'valid'}
    # Where the format carries a proof, it is used.
    for proved in ('docx', 'xlsx', 'pptx', 'odt', 'epub', 'apk', 'jar',
                   'gz', 'sqlite'):
        assert statuses[proved] == 'complete', proved


def test_checks_name_what_failed():
    from trace_app.core import carve_verify
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('a.txt', 'evidence ' * 2000)
        archive.writestr('b.txt', 'more ' * 2000)
    good = buffer.getvalue()
    verdict = carve_verify.assess(good, 'zip')
    assert verdict['status'] == 'complete'
    assert any('CRC-32 of all 2 member(s) matches' in text
               for ok, text in verdict['checks'] if ok)
    # Flip a byte inside the first member's compressed data.
    damaged = bytearray(good)
    damaged[60] ^= 0xFF
    verdict = carve_verify.assess(bytes(damaged), 'zip')
    assert verdict['status'] == 'partial'
    assert any('fail' in text for ok, text in verdict['checks']
               if ok is False)
    rebuilt = carve_verify.assess(good, 'zip', fragments=[[0, 10],
                                                          [99, 20]])
    assert rebuilt['status'] == 'reconstructed'


def test_pe_checksum_matches_the_reference_algorithm():
    """A Windows system DLL carries a checksum; recompute it."""
    import struct
    from trace_app.core import carve_verify
    candidates = [os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                               'System32', name)
                  for name in ('kernel32.dll', 'ntdll.dll')]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        pytest.skip("No signed Windows system DLL on this machine")
    with open(path, 'rb') as handle:
        data = handle.read()
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    stored = struct.unpack_from('<I', data, pe + 88)[0]
    assert carve_verify.pe_checksum(data, pe + 88) == stored
    verdict = carve_verify.assess(data, 'dll')
    assert any(text.startswith('PE checksum matches')
               for ok, text in verdict['checks'] if ok)


def test_unallocated_carving_recovers_and_names_the_deleted_jpegs():
    """DFTT #8: two JPEGs deleted, one renamed .hmm; the rest are live.
    Carving unallocated space must find exactly the two -- it once skipped
    any 4 MB chunk holding a live cluster, which on this image was all of
    them -- and name each from its deleted entry."""
    from trace_app.core import carve_origin, carving
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('8-jpeg-search.dd'))
    assert handler.load_image()
    found = {}
    try:
        starts = carve_origin.deleted_file_starts(handler)

        def sink(content, file_type, offset, fragments=None):
            found[offset] = carve_origin.match(starts, offset, len(content))
        stats = {}
        carving.carve_image(handler, ['jpg'], sink, True, stats=stats)
    finally:
        handler.close_resources()
    assert {origin['path'] for origin in found.values()} == \
        {'/del1/file6.jpg', '/del2/file7.hmm'}
    for origin in found.values():
        assert origin['size'] and 'its size matches' in origin['basis']
    assert stats['bytes_skipped'] > 0       # the live files were not read


@pytest.mark.parametrize('name, expected', [
    ('7-ntfs-undel.dd', {'/frag1.dat': ('recoverable', 2),
                         '/sing1.dat': ('recoverable', 1)}),
    ('6-fat-undel.dd', {'/_ing.dat': ('recoverable', 1)}),
    ('dfr-01-ext.dd', {'/Bunda.txt': ('no data recorded', 0)}),
])
def test_deleted_files_and_what_is_left_of_them(name, expected):
    """DFTT #6/#7 (FAT, NTFS; a file in two fragments) and NIST's ext
    image, where ext3 cleared the deleted file's block list."""
    from trace_app.core import carving, deleted
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.load_image()
    try:
        rows = {r['path']: r for r in deleted.deleted_files(
            handler, carving.allocation_map(handler))}
    finally:
        handler.close_resources()
    for path, (state, runs) in expected.items():
        assert rows[path]['state'] == state, path
        assert len(rows[path]['runs']) == runs, path


def test_carve_evidence_records_the_run(tmp_path):
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('dfrws-2006-challenge.raw')
    case = Case.create(str(tmp_path / 'case'), 'Carving')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    try:
        count = carve_evidence(handler, case, evidence_id,
                               [t.lower() for t in CARVABLE_TYPES])
        rows = case.carved_files(evidence_id)
        assert len(rows) == count
        assert all(r['md5'] and r['sha1'] and r['sha256'] for r in rows)
        assert {r['status'] for r in rows} == {'complete', 'valid',
                                               'partial', 'reconstructed'}
        assert all(r['checks'] for r in rows)
        (run,) = case.carving_runs(evidence_id)
        assert run['status'] == 'done' and run['found'] == count
        assert run['engine'].startswith('TRACE ')
        assert run['stats']['kept'] and run['stats']['candidates']
        assert run['stats']['status']['partial'] == sum(
            1 for r in rows if r['status'] == 'partial')
        trail = [row for row in case.activity()
                 if row['action'] == 'carving statistics']
        assert trail and 'candidates=' in trail[0]['detail']
    finally:
        handler.close_resources()
        case.close()


def test_an_interrupted_carve_resumes_to_the_same_result(tmp_path):
    """Stopped half way and resumed, a carve ends with exactly what one
    uninterrupted run finds -- the two ZIPs rebuilt from fragments that lie
    in the half already done included."""
    from trace_app.core import carving
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('dfrws-2006-challenge.raw')
    case = Case.create(str(tmp_path / 'case'), 'Resume')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    types = [t.lower() for t in CARVABLE_TYPES]
    size, seen = handler.get_size(), {}
    old = carving.CHECKPOINT_SECONDS
    carving.CHECKPOINT_SECONDS = 0
    try:
        carve_evidence(handler, case, evidence_id, types, False,
                       progress=lambda p, t, f: seen.__setitem__('at', p),
                       should_stop=lambda: seen.get('at', 0) > size // 2)
        state = case.carving_state(evidence_id)
        assert state['status'] == 'cancelled'
        assert 0 < state['bytes_done'] < size
        first = {r['offset'] for r in case.carved_files(evidence_id)}
        carve_evidence(handler, case, evidence_id, types, False,
                       resume=True)
        rows = case.carved_files(evidence_id)
        assert len(rows) == 29 and len({r['offset'] for r in rows}) == 29
        assert first < {r['offset'] for r in rows}
        assert {r['status'] for r in rows
                if r['offset'] in (0xE07200, 0x15FAE00)} == {'reconstructed'}
        latest = case.carving_runs(evidence_id)[0]
        assert latest['settings']['resumed_from'] == state['bytes_done']
        assert case.carving_state(evidence_id)['status'] == 'done'
    finally:
        carving.CHECKPOINT_SECONDS = old
        handler.close_resources()
        case.close()


def test_slack_is_found_and_read():
    """DFTT #2 hid 3slack3 wholly in file4.dat's slack."""
    from trace_app.core import slack
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('fat-img-kw.dd'))
    assert handler.load_image()
    try:
        regions = {path: (offset, length) for offset, length, path, _ref in
                   slack.slack_ranges(handler)}
        offset, length = regions['/file4.dat']
        text = slack.text_of(handler.read(offset, length))
    finally:
        handler.close_resources()
    assert '3slack3' in text
    assert all(length < 4096 for _o, length in regions.values())


def test_slack_carving_reads_nothing_past_the_slack(tmp_path):
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('8-jpeg-search.dd')
    case = Case.create(str(tmp_path / 'case'), 'Slack')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    try:
        carve_evidence(handler, case, evidence_id,
                       [t.lower() for t in CARVABLE_TYPES], source='slack')
        (run,) = case.carving_runs(evidence_id)
        assert run['settings']['source'] == 'slack'
        # The whole slack of 11 files, a few KB: not the image.
        assert 0 < run['stats']['bytes_scanned'] < 64 * 1024
        assert all(r['source'] == 'slack'
                   for r in case.carved_files(evidence_id))
    finally:
        handler.close_resources()
        case.close()

"""The case timeline (trace_app/core/timeline.py).

A real NTFS volume -- plaso's usnjrnl.qcow2, its $MFT times and change
journal read by core/ntfs -- plus one record of every other source written
the way their modules write them: an activity record, a photo's EXIF, a
document's dates (UTC, offset and zone-less), a carved file's own date, and
the examination's audit trail. Each assertion is about which rows a
question selects and in what order.
"""

import csv
import datetime
import json
import os
import sqlite3

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


@pytest.fixture(scope='module')
def built(tmp_path_factory):
    path = os.path.join(SAMPLES, 'usnjrnl.qcow2')
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail("usnjrnl.qcow2 missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    from trace_app.core import ntfs
    from trace_app.core.activity import record
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    folder = str(tmp_path_factory.mktemp('timeline') / 'case')
    case = Case.create(folder, 'Timeline')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    ntfs.analyse_evidence(handler, case, evidence_id)
    handler.close_resources()

    when = datetime.datetime(2015, 11, 30, 21, 15, 40,
                             tzinfo=datetime.timezone.utc)
    case.add_user_activity(evidence_id, [record(
        'files', 'Shortcut (Recent)', when, 'File opened (last)',
        r'C:\Users\ann\second.txt', user='ann', path='/Users/ann/x.lnk',
        ref='p63:i31:s1')])
    case.add_ntfs_findings(evidence_id, [])
    case._db.executemany(
        "INSERT INTO file_findings (evidence_id, artifact_ref, name, path, "
        "size, module, kind, grade, summary, detail, analysed_utc) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?)", [
            (evidence_id, 'p63:i40:s1', 'IMG_1.jpg', '/IMG_1.jpg', 10,
             'photo', 'camera', 'benign', 'Canon',
             json.dumps({'taken': '2015:11:30 20:00:00', 'make': 'Canon'}),
             '2026-01-01'),
            (evidence_id, 'p63:i41:s1', 'a.docx', '/a.docx', 10, 'authors',
             'document', 'benign', 'ann',
             json.dumps({'created': '2015-11-30 19:00:00 UTC',
                         'modified': '2015-11-30 22:30:00 +01:00',
                         'author': 'ann', 'last_saved_by': 'bob'}),
             '2026-01-01'),
            (evidence_id, 'p63:i42:s1', 'b.odt', '/b.odt', 10, 'authors',
             'document', 'benign', 'carol',
             json.dumps({'created': '2015-11-30 18:00:00',
                         'author': 'carol'}), '2026-01-01'),
            (evidence_id, 'p63:i31:s1', 'second.txt', '/second.txt', 1,
             'ntfs', 'timestomp', 'suspicious', 'set by hand', '{}',
             '2026-01-01')])
    case._db.execute(
        "INSERT INTO carved_files (evidence_id, artifact_ref, name, path, "
        "offset, size, type, sha256, embedded_date, date_source, carved_utc) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, 'p0:x1000-2000', '00001000.jpg', 'carved/x.jpg', 4096,
         4096, 'jpg', 'ab' * 32, '2015-11-29 08:00:00', 'EXIF', '2026'))
    case._db.commit()
    yield case, evidence_id
    case.close()


def _connection(case):
    return sqlite3.connect(os.path.join(case.folder, 'case.db'))


def _filters(**changes):
    from trace_app.core import timeline
    filters = timeline.default_filters()
    filters.update(changes)
    return filters


def test_every_source_is_in_one_time_order(built):
    from trace_app.core import timeline
    case, _evidence = built
    with _connection(case) as connection:
        rows = timeline.events(connection, _filters(
            sources=[k for k, _l, _c in timeline.SOURCES]))
        counts = timeline.source_counts(connection, _filters())
    times = [row['time'] for row in rows]
    assert times == sorted(times)
    assert {row['source'] for row in rows} == {
        'fs', 'usn', 'activity', 'photo', 'document', 'carved', 'case'}
    assert counts['usn'] == 19
    assert counts['fs'] == case.ntfs_state(built[1])['events']
    # The journal's first record, as plaso reads it.
    first = next(r for r in rows if r['source'] == 'usn')
    assert first['time'] == '2015-11-30 21:15:27.2031250'
    assert first['title'] == 'Nieuw - Tekstdocument.txt'
    assert first['kind'] == 'Created'


def test_times_keep_their_zone(built):
    """EXIF and a zone-less document date are local; UTC and an offset are
    converted and marked UTC."""
    from trace_app.core import timeline
    case, _evidence = built
    with _connection(case) as connection:
        rows = timeline.events(connection, _filters(
            sources=['photo', 'document', 'carved']))
    by = {(r['source'], r['kind'], r['title']): r for r in rows}
    photo = by[('photo', 'Photo taken', 'IMG_1.jpg')]
    assert (photo['time'], photo['local']) == ('2015-11-30 20:00:00', 1)
    created = by[('document', 'Document created', 'a.docx')]
    assert (created['time'], created['local']) == ('2015-11-30 19:00:00', 0)
    saved = by[('document', 'Document last saved', 'a.docx')]
    assert (saved['time'], saved['local'], saved['user']) == \
        ('2015-11-30 21:30:00', 0, 'bob')
    zoneless = by[('document', 'Document created', 'b.odt')]
    assert zoneless['local'] == 1
    carved = next(r for r in rows if r['source'] == 'carved')
    assert carved['local'] == 1 and carved['kind'].endswith('(EXIF)')


def test_range_text_and_pivots(built):
    from trace_app.core import timeline
    case, evidence_id = built
    with _connection(case) as connection:
        start, end = timeline.around('2015-11-30 21:15:27', 1)
        window = timeline.events(connection, _filters(start=start, end=end))
        assert window and all(start <= r['time'] < end for r in window)
        renamed = timeline.events(connection, _filters(
            sources=['usn'], text='Renamed'))
        assert renamed and all('Renamed' in r['kind'] for r in renamed)
        # One file: its $MFT times, its journal records, the activity
        # record read from it -- nothing else.
        focus = timeline.events(connection, _filters(
            focus_ref=(evidence_id, 'p63:i31:s1')))
        assert {r['source'] for r in focus} >= {'fs', 'usn'}
        assert {r['artifact_ref'] for r in focus} == {'p63:i31:s1'}
        users = timeline.events(connection, _filters(user='ann'))
        assert {r['source'] for r in users} == {'activity', 'document'}
        stomped = timeline.events(connection, _filters(
            timestomped_only=True))
        assert stomped and {r['artifact_ref'] for r in stomped} == \
            {'p63:i31:s1'}
        deleted = timeline.events(connection, _filters(
            sources=['usn'], deleted_only=True))
        assert all(r['deleted'] for r in deleted)
        si_only = timeline.events(connection, _filters(
            sources=['fs'], fs_attributes='SI'))
        assert si_only and all(r['kind'].endswith(' SI') for r in si_only)


def test_known_good_files_can_be_left_out(built):
    from trace_app.core import timeline
    case, evidence_id = built
    case.replace_hash_matches(evidence_id, [(
        'p63:i31:s1', 'second.txt', '/second.txt', 1, 'file', 'x', 'NSRL',
        'known-good', 'sha256', 'aa' * 32)])
    try:
        with _connection(case) as connection:
            shown = timeline.count(connection, _filters())
            hidden = timeline.count(connection, _filters(
                hide_known_good=True))
            gone = timeline.count(connection, _filters(
                focus_ref=(evidence_id, 'p63:i31:s1')))
        assert gone and hidden == shown - gone + timeline.count(
            _connection(case), _filters(
                focus_ref=(evidence_id, 'p63:i31:s1'),
                sources=['activity']))
    finally:
        case.clear_hash_matches(evidence_id)


def test_histogram_counts_every_row(built):
    from trace_app.core import timeline
    case, _evidence = built
    with _connection(case) as connection:
        first, last, outside = timeline.bounds(connection, _filters())
        assert first.startswith('2015') and outside >= 0
        unit = timeline.unit_for(first, last)
        filters = _filters(start=first, end=timeline.text(
            timeline.parse(last) + datetime.timedelta(seconds=1)))
        buckets = timeline.histogram(connection, filters, unit)
        assert sum(sum(c.values()) for c in buckets.values()) == \
            timeline.count(connection, filters)
    assert timeline.unit_for('2015-11-30 00:00:00',
                             '2015-11-30 00:02:00') == 'second'
    assert timeline.unit_for('2015-11-30', '2015-12-02') == 'hour'
    assert timeline.unit_for('2000-01-01', '2020-01-01') == 'month'
    assert timeline.step(timeline.parse('2015-12-01'), 'month') == \
        datetime.datetime(2016, 1, 1)


def test_csv_holds_every_selected_row(built, tmp_path):
    from trace_app.core import timeline
    case, evidence_id = built
    out = str(tmp_path / 'timeline.csv')
    with _connection(case) as connection:
        expected = timeline.count(connection, _filters())
        written = timeline.write_csv(connection, _filters(), out,
                                     {evidence_id: 'usnjrnl.qcow2'})
    assert written == expected
    with open(out, encoding='utf-8-sig', newline='') as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == list(timeline.CSV_HEADER)
    assert len(rows) == expected + 1
    created = next(r for r in rows if r[4] == 'Nieuw - Tekstdocument.txt')
    assert created[1] == 'UTC' and created[7] == 'usnjrnl.qcow2'


def test_report_items_are_kept_once(built):
    case, evidence_id = built
    item = {'evidence_id': evidence_id, 'artifact_ref': 'p63:i30:s1',
            'time': '2015-11-30 21:15:27.2031250', 'title': 'Created: x',
            'detail': {'source': 'usn'}}
    assert case.add_report_items('timeline', [item, item]) == 1
    assert case.add_report_items('timeline', [item]) == 0
    (stored,) = case.report_items('timeline')
    assert stored['detail'] == {'source': 'usn'}
    case.remove_report_items([stored['id']])
    assert case.report_items('timeline') == []


def test_zoom_never_overflows_and_stays_in_the_case():
    """Zooming out again and again once ran the range past year 9999
    (OverflowError). It stops at the case's own span, with a margin."""
    from trace_app.core import timeline
    bounds = ('2008-10-01 00:00:00', '2008-10-31 00:00:00')
    start, end = '2008-10-21 00:00:00', '2008-10-22 00:00:00'
    for _ in range(200):
        start, end = timeline.zoom_range(start, end, 0.9, 2.0, bounds)
    first, last = timeline.parse(start), timeline.parse(end)
    assert first >= timeline.parse(bounds[0]) - (
        timeline.parse(bounds[1]) - timeline.parse(bounds[0])) / 40
    assert last <= timeline.parse(bounds[1]) + (
        timeline.parse(bounds[1]) - timeline.parse(bounds[0])) / 40
    # No bounds known yet, and a 1601 timestomp: still no overflow.
    start, end = '1601-01-02 00:00:00', '1601-01-03 00:00:00'
    for _ in range(200):
        assert timeline.zoom_range(start, end, 0.0, 3.0) is not None
        start, end = timeline.zoom_range(start, end, 0.0, 3.0)


def test_zoom_in_keeps_the_pointer_and_a_minimum_span():
    from trace_app.core import timeline
    start, end = '2008-10-21 00:00:00', '2008-10-22 00:00:00'
    # The point under the pointer (a quarter of the way) stays put.
    zoomed = timeline.zoom_range(start, end, 0.25, 0.5)
    assert zoomed == ('2008-10-21 03:00:00', '2008-10-21 15:00:00')
    for _ in range(100):
        zoomed = timeline.zoom_range(*zoomed, 0.5, 0.1)
    span = timeline.parse(zoomed[1]) - timeline.parse(zoomed[0])
    assert span.total_seconds() == timeline.MIN_SPAN_SECONDS
    # A typed range backwards or of no width is made usable, not refused.
    assert timeline.clamp_range('2008-10-22 00:00:00',
                                '2008-10-21 00:00:00') == \
        ('2008-10-21 00:00:00', '2008-10-22 00:00:00')
    assert timeline.clamp_range('2008-10-21 00:00:00',
                                '2008-10-21 00:00:00') == \
        ('2008-10-20 23:59:55', '2008-10-21 00:00:05')

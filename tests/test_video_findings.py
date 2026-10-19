"""A video's recorded time and place, where the rest of TRACE shows a
photo's: the Timeline, the Map (geo.located and MapPanel.show_place) and
the report's contact sheets.

The findings are written as content_checks.video_finding writes them
(module 'photo', kind 'video', detail 'recorded' = the movie header's UTC
time, 'taken' = the creation-date tag's own digits when it has a zone).
"""

import hashlib
import json
import os
import sqlite3

import pytest


@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case, make_artifact_ref
    case = Case.create(str(tmp_path / 'case'), 'Videos')
    evidence = case.add_evidence(str(tmp_path / 'phone.dd'))
    case.add_module_findings(evidence, 'photo', [
        # An iPhone movie: header time (UTC) and the tag's local digits.
        (make_artifact_ref(0, 50, 1), 'IMG_0001.MOV', '/DCIM/IMG_0001.MOV',
         5000, 'video', 'notable', 'Recorded at 48.85840, 2.29450',
         json.dumps({'recorded': '2023-05-06 12:34:56',
                     'taken': '2023:05:06 14:34:56',
                     'latitude': 48.8584, 'longitude': 2.2945,
                     'make': 'Apple', 'model': 'iPhone 14 Pro'})),
        # A dashcam AVI: only the header's UTC time, no place.
        (make_artifact_ref(0, 51, 1), 'clip.avi', '/clip.avi', 5000,
         'video', 'benign', 'Recorded 2022-01-02',
         json.dumps({'recorded': '2022-01-02 08:00:00'})),
        (make_artifact_ref(0, 52, 1), 'memo.m4a', '/memo.m4a', 500,
         'audio', 'benign', 'Recorded 2021-03-04',
         json.dumps({'recorded': '2021-03-04 09:10:11'}))])
    case.commit()
    yield case, evidence
    case.close()


def test_videos_are_on_the_timeline(case):
    from trace_app.core import timeline
    case, _evidence = case
    filters = timeline.default_filters()
    filters['sources'] = ['photo']
    with sqlite3.connect(os.path.join(case.folder, 'case.db')) as connection:
        rows = timeline.events(connection, filters)
    by = {(r['kind'], r['title']): r for r in rows}
    # The tag's local digits, local; the header-only ones in UTC.
    movie = by[('Video recorded', 'IMG_0001.MOV')]
    assert (movie['time'], movie['local']) == ('2023-05-06 14:34:56', 1)
    clip = by[('Video recorded', 'clip.avi')]
    assert (clip['time'], clip['local']) == ('2022-01-02 08:00:00', 0)
    memo = by[('Audio recorded', 'memo.m4a')]
    assert (memo['time'], memo['local']) == ('2021-03-04 09:10:11', 0)


def test_a_located_video_is_on_the_map(case):
    from trace_app.core import geo
    case, _evidence = case
    points = geo.located(case)
    assert [p['name'] for p in points] == ['IMG_0001.MOV']
    assert points[0]['what'] == 'Video recorded with Apple iPhone 14 Pro'
    assert points[0]['source'] == 'Video metadata'


def test_show_place_selects_or_adds_a_point(qapp, case):
    from trace_app.ui.viewers.map_panel import MapPanel
    case, _evidence = case
    panel = MapPanel()
    try:
        panel.ask = lambda style: False
        panel.set_case(case)
        panel.refresh()
        assert [p['name'] for p in panel.points] == ['IMG_0001.MOV']
        # The case's own point is selected, not a second one added.
        assert panel.show_place(48.8584, 2.2945, 'IMG_0001.MOV') == 0
        assert len(panel.points) == 1
        added = panel.show_place(-33.8688, 151.2093, 'clip.avi',
                                 'Recorded here')
        assert added == len(panel.points) - 1
        assert panel.points[added]['what'] == 'Recorded here'
        assert panel.table.currentRow() == added
    finally:
        panel.deleteLater()


def test_a_contact_sheet_is_in_the_report_only_while_it_is_unchanged(
        case, tmp_path):
    from trace_app.core import contact_sheet, report
    case, evidence = case
    png = contact_sheet.compose([(None, '00:00.5 · frame 12')], 'clip.avi',
                                ['File SHA-256 x'])
    path = tmp_path / 'sheet.png'
    path.write_bytes(png)
    case.add_report_items('contact_sheet', [{
        'evidence_id': evidence, 'artifact_ref': 'p0:i51:s1', 'time': None,
        'title': 'Contact sheet: clip.avi',
        'detail': {'path': str(path), 'file': 'clip.avi',
                   'sha256': hashlib.sha256(png).hexdigest(),
                   'how': '1 frames spread evenly', 'frames': 1,
                   'missing': 1, 'file_sha256': None}}])
    def bookmarks_section():
        return report._Builder(case, report.default_options(case), None,
                               None, None).section_bookmarks()
    body = bookmarks_section()
    assert 'Video contact sheets (1)' in body
    assert 'data:image/png;base64,' in body
    path.write_bytes(png + b'changed')
    body = bookmarks_section()
    assert 'data:image/png;base64,' not in body
    assert 'no longer the sheet that was recorded' in body


def test_contact_sheet_layout():
    from PIL import Image
    import io
    from trace_app.core import contact_sheet
    frame = Image.new('RGB', (640, 360), (10, 200, 10))
    buffer = io.BytesIO()
    frame.save(buffer, 'PNG')
    png = contact_sheet.compose([(buffer.getvalue(), 'a')] * 5 + [(None, 'b')],
                                'title', ['one', 'two'], columns=3)
    sheet = Image.open(io.BytesIO(png))
    # Three columns of 320 px frames, two rows.
    assert sheet.width == 16 * 2 + 3 * 320 + 2 * 10
    assert sheet.convert('RGB').getpixel((16 + 160, 16 + 34 + 90)) == \
        (10, 200, 10)
    assert contact_sheet.evenly(10000, 4) == [1250, 3750, 6250, 8750]

"""The examiner's marks on timeline events -- star, colour, comment --
highlight rules, and the timeline in the report (chart and starred
narrative). A small generated case."""

import io
import os
import sqlite3

import pytest

from tests.conftest import pump


@pytest.fixture
def marked(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Marks')
    image = tmp_path / 'pc.dd'
    image.write_bytes(b'\0' * 512)
    evidence = case.add_evidence(str(image))
    case._db.executemany(
        "INSERT INTO fs_events (evidence_id, artifact_ref, path, time_utc, "
        "macb, source) VALUES (?,?,?,?,'MACB','SI')",
        [(evidence, f'p0:i{i}:s1', path, f'2024-05-0{1 + i % 5} 1{i % 10}:00:00')
         for i, path in enumerate(['/Users/ann/a.docx', '/tools/evil.exe',
                                   '/Users/ann/b.txt', '/tmp/x.ps1',
                                   '/Users/ann/c.pdf', '/Users/ann/d.jpg'])])
    case._db.execute(
        "INSERT INTO user_activity (evidence_id, category, what, time_utc, "
        "subject, detail, source) VALUES (?, 'usb', 'USB device connected', "
        "'2024-05-02 09:30:00', 'Kingston', '{}', 'SYSTEM')", (evidence,))
    case._db.commit()
    yield case, evidence
    case.close()


def _rows(case, **changes):
    from trace_app.core import timeline
    filters = timeline.default_filters()
    filters.update(changes)
    connection = sqlite3.connect(
        f"file:{os.path.join(case.folder, 'case.db')}?mode=ro", uri=True)
    try:
        return list(timeline.iter_events(connection, filters))
    finally:
        connection.close()


def test_marks_are_kept_audited_and_cleared(marked):
    from trace_app.core import timeline
    from trace_app.core.case import SCHEMA_VERSION
    case, _evidence = marked
    assert SCHEMA_VERSION >= 21
    rows = _rows(case)
    evil = next(r for r in rows if r['subject'] == '/tools/evil.exe')
    usb = next(r for r in rows if r['source'] == 'activity')
    # The key ignores where the row came from: a module run again gives
    # a new rowid, the same event.
    again = dict(evil, row_key='fs:000000999999', extra=None)
    assert timeline.event_key(again) == timeline.event_key(evil)
    assert timeline.event_key(usb) != timeline.event_key(evil)

    assert case.mark_events([evil], starred=True, colour='#E5534B',
                            comment='Dropped by the phishing mail') == 1
    assert case.mark_events([evil], starred=True) == 0      # no change
    case.mark_events([usb], starred=True)
    marks = case.timeline_marks()
    assert marks[timeline.event_key(evil)]['comment'] == \
        'Dropped by the phishing mail'
    entry = case.activity()[0]
    assert entry['action'] == 'timeline events marked'
    case.mark_events([evil], comment='Run at 10:00')
    entry = case.activity()[0]
    assert "'Dropped by the phishing mail' -> 'Run at 10:00'" in \
        entry['detail']

    starred = _rows(case, starred_only=True)
    assert {r['subject'] for r in starred} == {'/tools/evil.exe',
                                               'Kingston'}
    assert all(timeline.event_key(r) in marks for r in starred)
    assert 'Run at 10:00' in next(r['extra'] for r in starred
                                  if r['source'] == 'fs')

    # Nothing left: the mark goes.
    case.mark_events([usb], starred=False)
    case.mark_events([evil], starred=False, colour='', comment='')
    assert case.timeline_marks() == {}


def test_highlight_rules_tint_the_first_match():
    from trace_app.core import timeline
    rules = timeline.compile_highlights(timeline.DEFAULT_HIGHLIGHTS)
    exe = {'source': 'fs', 'kind': 'M SI', 'subject': '/a/run.EXE',
           'title': None, 'deleted': 0}
    usb = {'source': 'activity', 'kind': 'usb', 'title': 'USB device',
           'subject': 'Kingston', 'deleted': 0}
    clock = {'source': 'activity', 'kind': 'system',
             'title': 'System time changed', 'subject': 'ann', 'deleted': 0}
    plain = {'source': 'fs', 'kind': 'M SI', 'subject': '/a/b.txt',
             'title': None, 'deleted': 1}
    assert timeline.highlight_of(exe, rules) == '#E5534B'
    assert timeline.highlight_of(usb, rules) == '#E8743B'
    assert timeline.highlight_of(clock, rules) == '#9B6CF0'
    assert timeline.highlight_of(plain, rules) is None     # Deleted is off
    on = [dict(r, enabled=True) for r in timeline.DEFAULT_HIGHLIGHTS]
    assert timeline.highlight_of(plain, timeline.compile_highlights(on)) \
        == '#8A939E'
    broken = [{'name': 'x', 'colour': '#000000', 'text': '([', 'regex': True}]
    assert timeline.compile_highlights(broken) == []


def test_the_chart_is_a_picture_of_the_events():
    from PIL import Image
    from trace_app.core import timeline_chart
    buckets = {'2024-05-01': {'fs': 120, 'activity': 3},
               '2024-05-03': {'fs': 4}}
    png = timeline_chart.chart_png(buckets, 'day', '2024-04-30 00:00:00',
                                   '2024-05-05 00:00:00',
                                   ['2024-05-01 10:00:00'], title='Test')
    image = Image.open(io.BytesIO(png))
    assert image.size == (timeline_chart.WIDTH, timeline_chart.HEIGHT)
    # The file-system colour is in it.
    assert (76, 139, 245) in {c for _n, c in image.convert('RGB')
                              .getcolors(1 << 16)}
    assert timeline_chart.chart_png({}, 'day', '2024-01-01',
                                    '2024-01-02') == b''


def test_the_report_tells_the_starred_story(marked, tmp_path):
    from trace_app.core import report
    case, _evidence = marked
    rows = _rows(case)
    evil = next(r for r in rows if r['subject'] == '/tools/evil.exe')
    case.mark_events([evil], starred=True,
                     comment='Dropped by the phishing mail')
    options = report.default_options(case)
    for section in options['sections']:
        section['enabled'] = section['key'] == 'timeline'
    options['formats'] = ['html', 'docx']
    written = {w['format']: w for w in report.write_report(
        case, options, folder=str(tmp_path / 'out'))}
    with open(written['html']['path'], encoding='utf-8') as handle:
        page = handle.read()
    assert 'Starred events (1)' in page
    assert 'Dropped by the phishing mail' in page
    assert "data:image/png;base64," in page
    import zipfile
    with zipfile.ZipFile(written['docx']['path']) as docx:
        body = docx.read('word/document.xml').decode('utf-8')
        assert 'Dropped by the phishing mail' in body
        assert any(name.startswith('word/media/') for name in docx.namelist())


def test_the_panel_stars_tints_and_filters(qapp, marked):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from trace_app.infra.window_state import save_value
    from trace_app.ui.viewers import timeline_panel as module
    case, _evidence = marked
    save_value('Timeline', 'collapse', '0')
    panel = module.TimelinePanel()
    try:
        panel.resize(1400, 800)
        panel.set_case(case)
        panel.show()
        panel.whole_case()
        assert pump(qapp, 30, lambda: not panel.loading)
        rows = panel.model.rows
        position = next(i for i, r in enumerate(rows)
                        if r['subject'] == '/Users/ann/b.txt')
        # Highlights: the default rules tint the .exe, not the .txt.
        exe = next(i for i, r in enumerate(rows)
                   if r['subject'] == '/tools/evil.exe')
        assert panel.model.data(panel.model.index(exe, 0),
                                Qt.BackgroundRole) is not None
        assert panel.model.data(panel.model.index(position, 0),
                                Qt.BackgroundRole) is None
        # S stars the selected row. The keys are QShortcuts, which fire only
        # in an active window: a loaded runner had not activated it yet.
        panel.activateWindow()
        assert pump(qapp, 10, panel.isActiveWindow)
        panel.table.setFocus()
        panel.table.selectRow(position)
        QTest.keyClick(panel.table, Qt.Key_S)
        assert panel.model.mark_of(rows[position])[0]
        assert panel.model.data(panel.model.index(position, 0),
                                Qt.DecorationRole) is not None
        assert 'Your mark' in panel.detail.toPlainText()
        # N goes to the next starred one.
        panel.mark([rows[exe]], starred=True)
        panel.table.selectRow(0)
        QTest.keyClick(panel.table, Qt.Key_N)
        assert panel.model.mark_of(panel.current_row())[0]
        # Starred only.
        panel.starred_box.setChecked(True)
        assert pump(qapp, 30, lambda: not panel.loading)
        assert {r['subject'] for r in panel.model.rows} == {
            '/Users/ann/b.txt', '/tools/evil.exe'}
        panel._drop_flag('starred_only')
        assert pump(qapp, 30, lambda: not panel.loading)
        assert len(panel.model.rows) == len(rows)
    finally:
        panel.shutdown()
        panel.deleteLater()

"""The Timeline's paging, column filters, opening range and controls
(core/timeline.py, ui/viewers/timeline_panel.py).

A generated case: file-system times on two images -- a burst of thousands
sharing one second, ties broken by the row key -- plus activity records,
a few 1990s software dates and one in the future. Every expectation is
computed here from the rows written, independently of the query.
"""

import datetime
import os
import sqlite3

import pytest
from PySide6.QtCore import Qt

from tests.conftest import pump

EVENTS = 12_000


def _fs_rows(evidence_id, count, start):
    rows = []
    for i in range(count):
        moment = start + datetime.timedelta(seconds=(i // 40) * 7)
        macb = ('M', 'MACB', 'B', 'MA')[i % 4]
        rows.append((evidence_id, f'p0:i{1000 + i}:s1',
                     f'/home/ann/{"docs" if i % 3 else "bin"}/f{i}.txt',
                     moment.strftime('%Y-%m-%d %H:%M:%S'), macb,
                     ('SI', 'FN', 'FS')[i % 3], int(i % 11 == 0)))
    return rows


@pytest.fixture(scope='module')
def case(tmp_path_factory):
    from trace_app.core.case import Case
    root = tmp_path_factory.mktemp('timeline_features')
    made = Case.create(str(root / 'case'), 'Timeline features')
    images = []
    for name in ('laptop.dd', 'phone.dd'):
        image = root / name
        image.write_bytes(b'\0' * 512)
        images.append(made.add_evidence(str(image)))
    start = datetime.datetime(2023, 3, 1, 9, 0, 0)
    rows = _fs_rows(images[0], EVENTS - 400, start) + \
        _fs_rows(images[1], 400, start + datetime.timedelta(days=30))
    # Software's own dates from the 1990s, and one from the future.
    rows += [(images[0], f'p0:i{9_000_000 + i}:s1', f'/usr/doc/old{i}',
              f'1996-0{1 + i % 9}-01 00:00:00', 'M', 'FS', 0)
             for i in range(30)]
    rows.append((images[0], 'p0:i99:s1', '/future', '2099-01-01 00:00:00',
                 'M', 'FS', 0))
    made._db.executemany(
        "INSERT INTO fs_events (evidence_id, artifact_ref, path, time_utc, "
        "macb, source, deleted) VALUES (?,?,?,?,?,?,?)", rows)
    made._db.executemany(
        "INSERT INTO user_activity (evidence_id, category, what, time_utc, "
        "time_local, subject, user, detail, source, source_path, "
        "source_ref) VALUES (?,?,?,?,0,?,?,'{}','Prefetch','/x.pf',?)",
        [(images[0], 'programs', 'Program run', (start + datetime.timedelta(
            minutes=i)).strftime('%Y-%m-%d %H:%M:%S'), f'TOOL{i}.EXE',
          'ann' if i % 2 else 'bob', f'p0:i{50 + i}:s1') for i in range(60)])
    made._db.commit()
    yield made, images
    made.close()


def _connection(case):
    return sqlite3.connect(
        f"file:{os.path.join(case[0].folder, 'case.db')}?mode=ro", uri=True)


def _filters(**changes):
    from trace_app.core import timeline
    filters = timeline.default_filters()
    filters.update(changes)
    return filters


# --- core: paging, column filters, where the events are ---------------------------------

def test_pages_hold_every_row_once_in_order(case):
    """Read page after page from where the last stopped: the same rows,
    in the same order, as one read of them all -- ties at one second
    included (40 events share each)."""
    from trace_app.core import timeline
    filters = _filters(start='2023-01-01 00:00:00', end='2024-01-01 00:00:00')
    with _connection(case) as connection:
        whole = [r['row_key'] for r in timeline.iter_events(connection,
                                                            filters)]
        paged, after = [], None
        while True:
            page = timeline.events_after(connection, filters, after, 997)
            if not page:
                break
            paged += [r['row_key'] for r in page]
            after = (page[-1]['time'], page[-1]['row_key'])
        assert paged == whole and len(set(paged)) == len(whole)
        assert len(whole) == timeline.count(connection, filters)
        # Backwards from the middle: the rows just before it, in order.
        middle = len(whole) // 2
        rows = list(timeline.iter_events(connection, filters))
        key = (rows[middle]['time'], rows[middle]['row_key'])
        before = timeline.events_before(connection, filters, key, 500)
        assert [r['row_key'] for r in before] == whole[middle - 500:middle]
        assert timeline.count_before(connection, filters, key) == middle
        # A jump to a time: its first row is the first at or after it.
        moment = rows[middle]['time']
        jumped = timeline.events_after(connection, filters, (moment, ''), 5)
        assert jumped[0]['time'] == moment
        assert all(r['time'] < moment for r in rows[:whole.index(
            jumped[0]['row_key'])])


@pytest.mark.parametrize('columns, keep', [
    ({'subject': '/bin/'}, lambda r: '/bin/' in (r['subject'] or '')),
    ({'kind': 'created'},
     lambda r: r['source'] == 'fs' and 'B' in r['kind'].split(' ')[0]),
    ({'kind': '$FN'}, lambda r: r['source'] == 'fs'
     and r['kind'].endswith(' FN')),
    ({'macb': 'MB'}, lambda r: r['source'] == 'fs'
     and {'M', 'B'} <= set(r['kind'].split(' ')[0])),
    ({'user': 'ann'}, lambda r: r['user'] == 'ann'),
    ({'title': 'tool1'}, lambda r: 'tool1' in (r['title'] or r['subject']
                                               or '').lower()),
    ({'sources': ['activity']}, lambda r: r['source'] == 'activity'),
    ({'sources': []}, lambda r: False),
    ({'time': '2023-03-01 09:0'}, lambda r: r['time'].startswith(
        '2023-03-01 09:0')),
    ({'subject': '100%_'}, lambda r: False),       # LIKE's own characters
])
def test_column_filters_select_what_the_column_shows(case, columns, keep):
    from trace_app.core import timeline
    plain = _filters(start='2023-01-01 00:00:00', end='2024-01-01 00:00:00',
                     sources=['fs', 'activity'])
    with _connection(case) as connection:
        expected = [r['row_key'] for r in timeline.iter_events(connection,
                                                               plain)
                    if keep(r)]
        filtered = dict(plain, columns=columns)
        got = [r['row_key'] for r in timeline.iter_events(connection,
                                                          filtered)]
        assert got == expected
        assert timeline.count(connection, filtered) == len(expected)
        paged = timeline.events_after(connection, filtered, None, 10 ** 6)
        assert [r['row_key'] for r in paged] == expected


def test_the_view_opens_where_the_events_are(case):
    """Thirty 1996 software dates would stretch the view over 27 years and
    flatten the year that matters; the 2099 date is no date at all."""
    from trace_app.core import timeline
    with _connection(case) as connection:
        spread = timeline.spread(connection, _filters())
    assert spread['first'].startswith('1996')
    assert spread['outside'] == 1                   # 2099
    assert spread['dense_first'] == '2023-03-01 00:00:00'
    assert spread['dense_last'] >= '2023-03-31'
    assert spread['dense_outside'] >= 30


def test_macb_letters_and_calendar_ticks():
    from trace_app.core import timeline
    from trace_app.ui.viewers.timeline_panel import calendar_ticks
    assert timeline.macb({'source': 'fs', 'kind': 'MB SI'}) == 'M..B'
    assert timeline.macb({'source': 'activity', 'kind': 'programs'}) == ''
    ticks = calendar_ticks(datetime.datetime(2014, 5, 3),
                           datetime.datetime(2024, 2, 1), 12)
    assert [label for _m, label in ticks][:2] == ['2015', '2016']
    assert all(m.month == 1 and m.day == 1 for m, _l in ticks)
    months = calendar_ticks(datetime.datetime(2023, 1, 10),
                            datetime.datetime(2023, 7, 2), 12)
    assert [label for _m, label in months] == ['2023-02', '2023-03',
                                               '2023-04', '2023-05',
                                               '2023-06', '2023-07']
    hours = calendar_ticks(datetime.datetime(2023, 1, 1, 9, 13),
                           datetime.datetime(2023, 1, 1, 15, 2), 8)
    assert all(m.minute == 0 and m.second == 0 for m, _l in hours)
    assert 2 <= len(hours) <= 8


def test_a_time_shows_in_the_chosen_zone(monkeypatch):
    from trace_app.core import settings
    from trace_app.ui.viewers.timeline_panel import shown_time
    monkeypatch.setattr(settings, 'current',
                        lambda key: 'Europe/Sofia' if key == 'display_zone'
                        else None)
    assert shown_time('2024-07-01 10:00:00', 'utc') == '2024-07-01 10:00:00'
    assert shown_time('2024-07-01 10:00:00', 'zone') == \
        '2024-07-01 13:00:00 EEST'
    assert shown_time('2024-01-01 10:00:00', 'zone') == \
        '2024-01-01 12:00:00 EET'                  # winter: +2
    assert 'UTC' in shown_time('2024-07-01 10:00:00', 'both')


# --- the panel -------------------------------------------------------------------

@pytest.fixture
def panel(qapp, case):
    """The panel listing events one by one (bursts not collapsed)."""
    from trace_app.infra.window_state import save_value
    from trace_app.ui.viewers.timeline_panel import TimelinePanel
    save_value('Timeline', 'collapse', '0')
    shown = TimelinePanel()
    shown.resize(1400, 800)
    shown.set_case(case[0])
    shown.show()
    shown.refresh(find_bounds=True)
    assert pump(qapp, 30, lambda: not shown.loading)
    yield shown
    shown.shutdown()
    shown.hide()
    shown.deleteLater()


def test_every_event_is_reached_by_scrolling(qapp, panel):
    """No cap: the table holds a page, and the next is read as the view
    reaches its end -- until every event of the range is listed."""
    from trace_app.ui.viewers import timeline_panel as module
    total = panel.total
    assert total > module.PAGE_ROWS
    assert panel.model.rowCount() == module.PAGE_ROWS
    assert panel.filters['start'].startswith('2023-03')    # where they are
    for _ in range(10):
        if not panel.model.canFetchMore():
            break
        panel.table.scrollToBottom()
        panel.model.fetchMore()
        assert pump(qapp, 20, lambda: not panel.model.fetching)
    assert panel.model.rowCount() == total
    keys = [r['row_key'] for r in panel.model.rows]
    assert len(set(keys)) == total
    times = [r['time'] for r in panel.model.rows]
    assert times == sorted(times)


def test_a_jump_lists_from_there_and_reads_back_up(qapp, panel):
    from trace_app.ui.viewers import timeline_panel as module
    late = '2023-03-31 00:00:00'
    panel.go_to_time(late, '2023-04-01 00:00:00')
    assert pump(qapp, 20, lambda: not panel.model.fetching)
    first = panel.model.rows[0]
    assert first['time'] >= late and panel.model.more_before
    assert panel.current_row()['row_key'] == first['row_key']
    # At the top, the page before is read in above.
    panel.table.verticalScrollBar().setValue(1)
    panel.table.verticalScrollBar().setValue(0)
    assert pump(qapp, 20, lambda: not panel.model.fetching)
    assert panel.model.rows[0]['time'] < late
    assert len(panel.model.rows) > module.PAGE_ROWS // 2


def test_column_filters_from_the_boxes(qapp, panel):
    from trace_app.ui.viewers import timeline_panel as module
    panel.column_filters_action.setChecked(True)
    assert panel.column_filters.isVisibleTo(panel)
    box = panel.column_filters.edits[module.SUBJECT]
    header = panel.table.horizontalHeader()
    assert abs(box.geometry().width() - header.sectionSize(
        module.SUBJECT)) <= 4
    box.setText('/bin/')
    panel.column_filters.edits[module.SOURCE].setText('activ')
    assert pump(qapp, 5, lambda: panel.filters['columns'].get('subject'))
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.filters['columns']['sources'] == ['activity']
    assert panel.model.rowCount() == 0          # activity has no /bin/
    assert panel.pivot_holder.isVisibleTo(panel)
    panel.column_filters.edits[module.SOURCE].clear()
    assert pump(qapp, 5, lambda: 'sources' not in panel.filters['columns'])
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.model.rows and all('/bin/' in r['subject']
                                    for r in panel.model.rows)
    # A saved view keeps the boxes' text, and gives it back.
    panel.save_view('bin only')
    panel._clear_filters()
    assert pump(qapp, 30, lambda: not panel.loading)
    assert box.text() == ''
    panel.load_view('bin only')
    assert box.text() == '/bin/'
    panel.column_filters_action.setChecked(False)


def test_the_column_chooser_is_remembered(qapp, panel, case):
    from trace_app.ui.viewers import timeline_panel as module
    panel._set_column_shown(module.USER, False)
    panel._save_columns()
    again = module.TimelinePanel()
    try:
        assert again.table.horizontalHeader().isSectionHidden(module.USER)
        assert not again.table.horizontalHeader().isSectionHidden(
            module.TIME)
    finally:
        again._set_column_shown(module.USER, True)
        again.deleteLater()


def test_switches_show_as_chips_and_clear_together(qapp, panel):
    panel.deleted_box.setChecked(True)
    assert pump(qapp, 30, lambda: not panel.loading)
    assert all(r['deleted'] for r in panel.model.rows)
    chips = [w.text() for w in panel.pivot_holder.findChildren(
        type(panel.back_button)) if w.isVisibleTo(panel)]
    assert any(text.startswith('Deleted only') for text in chips)
    panel._clear_filters()
    assert pump(qapp, 30, lambda: not panel.loading)
    assert not panel.deleted_box.isChecked()
    assert not panel.pivot_holder.isVisibleTo(panel)


# --- bursts --------------------------------------------------------------------------

def test_bursts_collapse_what_shares_a_window(case):
    """Events of one source, type and image in one minute are one row when
    there are 20 or more; fewer stay as they are, in time order; a burst's
    filters select exactly its events."""
    from trace_app.core import timeline, timeline_clusters as tc
    filters = _filters(start='2023-01-01 00:00:00', end='2024-01-01 00:00:00')
    with _connection(case) as connection:
        rows = list(timeline.iter_events(connection, filters))
        groups = {}
        for row in rows:
            key = (row['time'][:16], row['source'], row['kind'],
                   row['evidence_id'])
            groups.setdefault(key, []).append(row)
        items, complete = tc.collapse(connection, filters, 'minute', 20)
        assert complete
        bursts = [i for i in items if i.get('burst')]
        singles = [i for i in items if not i.get('burst')]
        assert len(bursts) == sum(1 for g in groups.values() if len(g) >= 20)
        assert len(singles) == sum(len(g) for g in groups.values()
                                   if len(g) < 20)
        assert sum(b['count'] for b in bursts) + len(singles) == len(rows)
        assert [i['time'] for i in items] == sorted(i['time'] for i in items)
        burst = max(bursts, key=lambda b: b['count'])
        members = groups[(burst['window'], burst['source'], burst['kind'],
                          burst['evidence_id'])]
        assert burst['count'] == len(members)
        assert burst['time'] == members[0]['time']
        assert burst['last'] == members[-1]['time']
        assert sum(n for _f, n in burst['folders']) == len(members)
        assert burst['deleted'] == sum(1 for m in members if m['deleted'])
        listed = list(timeline.iter_events(
            connection, tc.burst_filters(filters, burst)))
        assert [r['row_key'] for r in listed] == \
            [m['row_key'] for m in members]
        # Wider windows, fewer rows; a cap gives up rather than holding
        # everything.
        hourly, _ = tc.collapse(connection, filters, 'hour', 20)
        assert len(hourly) <= len(items)
        assert tc.collapse(connection, filters, 'minute', 10 ** 6,
                           most=100) == (None, False)


def test_a_burst_lists_its_events_and_folds_them_away(qapp, case):
    from trace_app.infra.window_state import save_value
    from trace_app.ui.viewers.timeline_panel import TimelinePanel
    save_value('Timeline', 'collapse', '1')
    panel = TimelinePanel()
    try:
        panel.resize(1400, 800)
        panel.set_case(case[0])
        panel.show()
        panel.refresh(find_bounds=True)
        assert pump(qapp, 30, lambda: not panel.loading)
        assert panel.collapse_button.isChecked()
        rows = panel.model.rows
        assert len(rows) < panel.total and not panel.model.canFetchMore()
        position = next(i for i, r in enumerate(rows) if r.get('burst'))
        burst = rows[position]
        assert '×' in panel.model.cell(burst, 4)
        panel.table.selectRow(position)
        assert 'Folders' in panel.detail.toPlainText()
        before = len(rows)
        panel._activated(panel.model.index(position, 0))     # double-click
        assert pump(qapp, 20, lambda: burst.get('expanded'))
        assert len(panel.model.rows) == before + burst['count']
        children = panel.model.rows[position + 1:position + 1 +
                                    burst['count']]
        assert all(c['in_burst'] == burst['row_key'] for c in children)
        assert panel.selected_rows() == []        # a burst is not an event
        panel.toggle_burst(position)
        assert len(panel.model.rows) == before
        # Off: one row per event again.
        panel.collapse_button.setChecked(False)
        assert pump(qapp, 30, lambda: not panel.loading)
        assert not any(r.get('burst') for r in panel.model.rows)
    finally:
        save_value('Timeline', 'collapse', '0')
        panel.shutdown()
        panel.deleteLater()


def test_the_summary_counts_and_narrows(qapp, panel, case):
    from trace_app.core import timeline
    panel.set_view('summary')
    summary = panel.summary
    summary.by_combo.setCurrentIndex(summary.by_combo.findData('folder'))
    assert pump(qapp, 20, lambda: summary.model.rowCount() and
                not summary._jobs)
    shown = {summary.model.item(r, 0).text():
             int(summary.model.item(r, 1).data(Qt.UserRole + 2))
             for r in range(summary.model.rowCount())}
    with _connection(case) as connection:
        expected = {}
        for row in timeline.iter_events(connection, panel.filters):
            folder = (row['subject'] or '').rsplit('/', 1)[0] \
                if '/' in (row['subject'] or '') else ''
            expected[folder or '(none)'] = expected.get(
                folder or '(none)', 0) + 1
    assert shown == expected
    # Double-click a group: its events, a chip saying so.
    position = next(r for r in range(summary.model.rowCount())
                    if summary.model.item(r, 0).text() == '/home/ann/bin')
    summary.table.doubleClicked.emit(summary.model.index(position, 0))
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.views.currentWidget() is panel.table
    assert panel.model.rows and all(
        r['subject'].startswith('/home/ann/bin/') for r in panel.model.rows)
    chips = [w.text() for w in panel.pivot_holder.findChildren(
        type(panel.back_button)) if w.isVisibleTo(panel)]
    assert any(text.startswith('Folder is: /home/ann/bin') for text in chips)
    panel._drop_column('folder_is')
    assert pump(qapp, 30, lambda: not panel.loading)
    assert 'folder_is' not in panel.filters['columns']


def test_extensions_read_alike_in_sql_and_python():
    import sqlite3 as sqlite
    from trace_app.core import timeline
    connection = sqlite.connect(':memory:')
    for subject in ('/a/b.TXT', '/a/.bashrc', '/x.y/z', '/t.tar.gz', '',
                    None, 'name.pdf'):
        sql = connection.execute(
            f"SELECT {timeline.EXTENSION_SQL} FROM (SELECT ? AS subject)",
            (subject,)).fetchone()[0]
        assert sql == timeline.extension_of(subject), subject


# --- lanes ---------------------------------------------------------------------------

def test_lane_counts_add_up_per_lane(case):
    from trace_app.core import timeline
    filters = _filters(start='2023-03-01 00:00:00', end='2023-04-01 00:00:00')
    with _connection(case) as connection:
        rows = list(timeline.iter_events(connection, filters))
        for by, column in (('source', 'source'), ('evidence', 'evidence_id'),
                           ('user', 'user'), ('kind', 'kind')):
            counts = timeline.lane_counts(connection, filters, by, 300)
            expected = {}
            for row in rows:
                value = row[column]
                if column in ('user', 'kind'):
                    value = value or ''
                expected[value] = expected.get(value, 0) + 1
            assert {k: sum(v.values()) for k, v in counts.items()} == \
                expected, by
            assert all(0 <= b < 300 for v in counts.values() for b in v)
        # A row lands in the slice of the range its time falls in.
        one = timeline.lane_counts(connection, dict(
            filters, sources=['activity']), 'source', 31)
        days = {}
        for row in rows:
            if row['source'] == 'activity':
                day = int(row['time'][8:10]) - 1
                days[day] = days.get(day, 0) + 1
        assert one['activity'] == days


def test_lanes_draw_density_or_each_event(qapp, panel):
    from trace_app.ui.viewers import timeline_lanes
    panel.set_view('lanes')
    lanes = panel.lanes
    assert pump(qapp, 20, lambda: not lanes.loading)
    canvas = lanes.canvas
    assert [key for key, _l, _c in canvas.lanes][:1] == ['fs']
    assert canvas.events is None                  # 12,000: a density
    assert 'density' in lanes.status.text()
    # Zoomed to a few minutes: each event a marker, and a click selects it.
    panel.set_range('2023-03-01 09:00:00', '2023-03-01 09:05:00')
    assert pump(qapp, 30, lambda: not panel.loading and not lanes.loading)
    assert canvas.events is not None and \
        len(canvas.events) <= timeline_lanes.SPARSE_MOST
    canvas.resize(1200, 300)
    canvas.grab()                                 # lays the markers out
    assert canvas._markers
    rect, _row = canvas._markers[len(canvas._markers) // 2]
    row = canvas._marker_at(rect.center())        # the one drawn on top
    from PySide6.QtCore import QEvent, QPointF
    from PySide6.QtGui import QMouseEvent
    for kind in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease):
        qapp.sendEvent(canvas, QMouseEvent(
            kind, rect.center(), canvas.mapToGlobal(rect.center()),
            Qt.LeftButton, Qt.LeftButton, Qt.NoModifier))
    assert panel.current_row()['row_key'] == row['row_key']
    # A drag zooms, as on the histogram.
    before = (panel.filters['start'], panel.filters['end'])
    plot = canvas.plot()
    for kind, x in ((QEvent.MouseButtonPress, plot.left() + 50),
                    (QEvent.MouseMove, plot.left() + 300),
                    (QEvent.MouseButtonRelease, plot.left() + 300)):
        spot = QPointF(x, plot.top() + 10)
        qapp.sendEvent(canvas, QMouseEvent(
            kind, spot, canvas.mapToGlobal(spot), Qt.LeftButton,
            Qt.LeftButton, Qt.NoModifier))
    assert pump(qapp, 30, lambda: not panel.loading)
    assert (panel.filters['start'], panel.filters['end']) != before
    panel.set_view('events')

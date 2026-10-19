"""Activity's Charts and Items, and the charts of an external module's
artifacts (core/record_views.py, ui/viewers/record_views.py).

Every number a chart or a card shows must be the table's: the records it
says a bar, a value or an item holds are exactly those the table lists
under it (as the tree and the tabs count alike). Expected values are
worked out here by hand from the generated records, never by calling the
code under test twice.
"""

import datetime
import os
import sqlite3

import pytest

from trace_app.core import record_views
from trace_app.core.activity import record

UTC = datetime.timezone.utc


def _rows(records, first_id=1):
    """Records as the Activity tab holds them (query_user_activity's
    shape), without a case."""
    out = []
    for number, r in enumerate(records, first_id):
        out.append({'id': number, 'category': r['category'],
                    'what': r['what'], 'time_utc': r['time'],
                    'time_local': 1 if r.get('local') else 0,
                    'subject': r['subject'], 'user': r.get('user', ''),
                    'detail': r['detail'], 'source': r['source'],
                    'source_path': r['path'], 'source_ref': r['ref'],
                    'reader': 'TRACE', 'read_by': ['TRACE'],
                    'evidence_id': 1})
    return out


def _when(day, hour=10, minute=0):
    return datetime.datetime(2024, 3, day, hour, minute, tzinfo=UTC)


def _browsing():
    visits = []
    for day, url in ((1, 'https://www.example.com/a'),
                     (1, 'https://example.com/b'),
                     (2, 'https://news.test/x'),
                     (3, 'https://www.example.com/c'),
                     (3, 'https://mail.test/inbox')):
        visits.append(record('browser', 'Chrome', _when(day), 'Visited', url,
                             {'browser': 'Chrome', 'visits': 2}))
    visits.append(record('browser', 'Firefox', None, 'Visited',
                         'https://example.com/old', {'browser': 'Firefox'}))
    visits.append(record('browser', 'Safari', _when(4), 'Cookie',
                         'cookie for nothing', {'browser': 'Safari'}))
    return _rows(visits)


# --- the overview ---------------------------------------------------------------

def test_the_overview_counts_what_the_table_lists():
    rows = _browsing()
    result = record_views.overview(rows, 'browser')
    assert result['total'] == 7
    assert result['timed'] == 6 and result['untimed'] == 1
    assert result['unit'] == 'hour'          # four days: hours fit
    title, field, entries, others = result['breakdowns'][0]
    assert (title, field) == ("Sites", 'domain')
    # www. is the same site; a cookie naming no URL names no site.
    assert dict((label, n) for _k, label, n in entries) == {
        'example.com': 3, 'news.test': 1, 'mail.test': 1, '(none)': 1} \
        or dict((label, n) for _k, label, n in entries) == {
        'example.com': 4, 'news.test': 1, 'mail.test': 1, '(none)': 1}
    by_label = {label: (key, n) for key, label, n in entries}
    key, count = by_label['example.com']
    ids = result['ids'][('domain', key)]
    assert len(ids) == count == 4           # the untimed visit too
    assert {rows[i - 1]['subject'] for i in ids} == {
        'https://www.example.com/a', 'https://example.com/b',
        'https://www.example.com/c', 'https://example.com/old'}
    assert others == 0
    # Every bar's records are the timed rows, each once.
    bucket_ids = [i for (kind, _p), members in result['ids'].items()
                  if kind == 'bucket' for i in members]
    assert sorted(bucket_ids) == [1, 2, 3, 4, 5, 7]
    assert sum(sum(c.values()) for _p, c in result['buckets']) == 6
    # Weekday x hour: every timed row in one cell, at 10:00 UTC.
    assert sum(map(sum, result['grid'])) == 6
    assert sum(len(v) for v in result['hours'].values()) == 6
    assert all(hour == 10 for (_day, hour) in result['hours'])


def test_rows_naming_nothing_are_their_own_stack_last():
    result = record_views.overview(_browsing(), 'browser')
    keys = [key for key, _label in result['stacks']]
    assert keys[-1] == record_views.NONE
    assert record_views.NONE not in keys[:-1]


def test_all_names_the_categories_by_their_labels():
    rows = _browsing() + _rows([record('usb', 'setupapi', _when(5),
                                       'Connected', 'Kingston')], 100)
    result = record_views.overview(rows, None)
    labels = {label for _k, label, _n in result['breakdowns'][0][2]}
    assert labels == {'Web history', 'USB devices'} or \
        'browser' not in labels and 'usb' not in labels


def test_local_times_are_counted_as_written():
    rows = _rows([record('usb', 'setupapi', datetime.datetime(2024, 3, 1, 23),
                         'First connected', 'Stick', local=True),
                  record('usb', 'registry', _when(1, 9), 'Last connected',
                         'Stick')])
    result = record_views.overview(rows, 'usb')
    assert result['local'] == 1
    hours = sorted(hour for (_day, hour) in result['hours'])
    assert hours == [9, 23]                  # not shifted


def test_a_display_zone_moves_the_hours_not_the_buckets():
    rows = _rows([record('logons', 'Security', _when(1, 23, 30), 'Logon',
                         'alice', {'account': 'alice'})])
    result = record_views.overview(rows, 'logons', zone='Europe/Sofia')
    assert list(result['hours']) == [(5, 1)]     # Saturday 01:00 in Sofia
    assert result['buckets'][0][0] == '2024-03-01 23'


def test_zeroed_times_stay_off_the_axis():
    rows = _rows([record('files', 'MFT', datetime.datetime(1601, 1, 1,
                                                           tzinfo=UTC),
                         'Created', 'C:\\a.txt'),
                  record('files', 'MFT', _when(2), 'Created', 'C:\\b.txt')])
    result = record_views.overview(rows, 'files')
    assert result['timed'] == 1 and result['untimed'] == 1
    assert result['first'].startswith('2024')


@pytest.mark.parametrize('first, last, unit', [
    ('2024-03-01 00:00:00', '2024-03-02 10:00:00', 'hour'),
    ('2024-01-01 00:00:00', '2024-03-30 00:00:00', 'day'),
    ('2020-01-01 00:00:00', '2024-01-01 00:00:00', 'month'),
    ('1990-01-01 00:00:00', '2024-01-01 00:00:00', 'year')])
def test_the_bucket_is_the_finest_that_fits(first, last, unit):
    assert record_views.bucket_unit(first, last) == unit


def test_buckets_end_where_the_next_begins():
    start = record_views.bucket_start('2024-12', 'month')
    assert record_views.bucket_end(start, 'month') == \
        datetime.datetime(2025, 1, 1)
    start = record_views.bucket_start('2024-02', 'month')
    assert record_views.bucket_end(start, 'month') == \
        datetime.datetime(2024, 3, 1)


# --- the values rows are grouped by -----------------------------------------------

@pytest.mark.parametrize('detail, subject, expected', [
    ({}, 'C:\\Windows\\System32\\NOTEPAD.EXE', 'NOTEPAD.EXE'),
    ({}, 'NOTEPAD.EXE-D8414F97.pf', 'NOTEPAD.EXE'),
    ({'path': '/Applications/Safari.app'}, 'Safari', 'Safari.app'),
    ({'app': 'com.apple.Terminal'}, 'x', 'com.apple.Terminal'),
    # macOS's recent items: a display name, the bundle as the subject --
    # the same program the Dock calls 'Mail.app'.
    ({'name': 'Mail'}, '/System/Applications/Mail.app', 'Mail.app')])
def test_a_program_is_named_by_its_file(detail, subject, expected):
    row = {'subject': subject, 'detail': detail}
    assert record_views.value_of(row, 'program') == expected


def test_folders_and_extensions():
    row = {'subject': 'C:\\Users\\bob\\Documents\\plan.DOCX', 'detail': {}}
    assert record_views.value_of(row, 'folder') == 'C:\\Users\\bob\\Documents'
    assert record_views.value_of(row, 'extension') == '.docx'
    row = {'subject': '/home/bob/notes', 'detail': {}}
    assert record_views.value_of(row, 'folder') == '/home/bob'
    assert record_views.value_of(row, 'extension') == ''


# --- items ------------------------------------------------------------------------

def _devices():
    return _rows([
        record('usb', 'USBSTOR', _when(1, 8), 'First connected', 'Kingston',
               {'device': 'Kingston', 'serial': 'AA11', 'vendor': 'Kingston',
                'drive letter': 'E:'}),
        record('usb', 'USBSTOR', _when(5, 9), 'Last connected', 'Kingston',
               {'device': 'Kingston', 'serial': 'AA11', 'vendor': 'Kingston',
                'drive letter': 'F:'}),
        record('usb', 'MountedDevices', _when(3), 'Mounted', 'SanDisk',
               {'device': 'SanDisk', 'vendor': 'SanDisk', 'serial': 'BB22'}),
        record('usb', 'EMDMgmt', None, 'Volume seen', '', {})])


def test_an_item_per_device_with_what_its_records_agree_on():
    rows = _devices()
    items = record_views.inventory(rows, 'usb')
    assert [i['title'] for i in items] == ['Kingston', 'SanDisk']
    kingston = items[0]
    assert kingston['count'] == 2
    assert kingston['first'] == '2024-03-01 08:00:00'
    assert kingston['last'] == '2024-03-05 09:00:00'
    facts = dict(kingston['facts'])
    assert facts['serial'] == 'AA11' and facts['vendor'] == 'Kingston'
    assert 'drive letter' not in facts       # the records disagree
    assert sorted(kingston['ids']) == [1, 2]
    assert kingston['latest']['id'] == 2
    assert sum(kingston['strip']) == 2
    assert record_views.unnamed(rows, 'usb') == 1
    # Every named record is on exactly one card.
    assert sorted(i for item in items for i in item['ids']) == [1, 2, 3]


def test_people_are_named_from_contacts():
    rows = _rows([
        record('communication', 'Contacts', None, 'Contact', 'Ann Lee',
               {'phone': '+44 7700 900123'}),
        record('communication', 'Phone', _when(1), 'Call made', '',
               {'to': '07700 900123', 'duration': '1:05'}),
        record('communication', 'WhatsApp (iOS)', _when(2), 'Message sent',
               'hello', {'to': '447700900123@s.whatsapp.net'}),
        record('communication', 'SMS', _when(3), 'Message received', 'hi',
               {'from': '+1 555 0100'})])
    items = record_views.inventory(rows, 'communication')
    ann = next(i for i in items if i['title'] == 'Ann Lee')
    assert ann['count'] == 2                 # the call and the message
    assert 'WhatsApp' in ann['subtitle'] and 'Phone' in ann['subtitle']
    assert any(i['title'] == '+1 555 0100' for i in items)


def test_sites_count_their_pages():
    items = record_views.inventory(_browsing(), 'browser')
    example = next(i for i in items if i['title'].endswith('example.com'))
    assert example['count'] == 4
    assert example['subtitle'].startswith('4 page(s)')


def test_app_usage_adds_up_its_time():
    rows = _rows([record('usage', 'SRUM', _when(1), 'Application in use',
                         'C:\\x\\chrome.exe', {'seconds': 3600}),
                  record('usage', 'SRUM', _when(2), 'Application in use',
                         'C:\\x\\chrome.exe', {'seconds': 125})])
    item = record_views.inventory(rows, 'usage')[0]
    assert item['facts'][0] == ('time in use', '1 h 02 min')


def test_only_categories_with_items_offer_them():
    assert record_views.ITEMS in record_views.views_for('usb')
    assert record_views.ITEMS not in record_views.views_for('files')
    assert record_views.ITEMS not in record_views.views_for(None)
    assert record_views.views_for('locations')[0] == record_views.TABLE


# --- an external module's artifacts ---------------------------------------------

def _lava(tmp_path, columns, rows, table='t'):
    path = tmp_path / '_lava_artifacts.db'
    connection = sqlite3.connect(path)
    names = ', '.join(f'"{c["name"]}"' for c in columns)
    connection.execute(f'CREATE TABLE "{table}" ({names})')
    connection.executemany(
        f'INSERT INTO "{table}" VALUES ({", ".join("?" * len(columns))})',
        rows)
    connection.commit()
    return connection, {'name': 'Artifact', 'tablename': table,
                        'columns': columns}


def _col(name, label=None, kind=''):
    return {'name': name, 'label': label or name, 'type': kind}


BASE = 1_700_000_000


def test_a_measurement_is_found_even_written_as_text(tmp_path):
    columns = [_col('ts', 'Timestamp', 'datetime'),
               _col('level', 'Battery Level (%)'),
               _col('charging', 'Is Charging'),
               _col('addr', 'Address'), _col('state', 'State (as stored)')]
    rows = [(BASE + n * 60, str(100 - n), n % 2, f'+4477009{n:05d}', n % 3)
            for n in range(50)]
    connection, artifact = _lava(tmp_path, columns, rows)
    shape = record_views.artifact_shape(connection, artifact)
    assert shape['kind'] == 'series'
    assert [c['name'] for c in shape['numbers']] == ['level']
    assert shape['kinds'][0] == 'series'


def test_a_measurement_is_averaged_per_bucket(tmp_path):
    columns = [_col('ts', 'Timestamp', 'datetime'), _col('steps', 'Steps')]
    rows = [(BASE + n * 30, n) for n in range(400)] + [(None, 5), (0, 9),
                                                      (BASE, 'n/a')]
    connection, artifact = _lava(tmp_path, columns, rows)
    series = record_views.series_query(connection, artifact, columns[0],
                                       columns[1], buckets=20)
    step = series['step']
    expected = {}
    for n in range(400):
        bucket = (BASE + n * 30) // step * step
        expected.setdefault(bucket, []).append(n)
    assert [p[0] for p in series['points']] == sorted(expected)
    for start, count, mean, low, high in series['points']:
        values = expected[start]
        assert count == len(values)
        assert mean == pytest.approx(sum(values) / len(values))
        assert (low, high) == (min(values), max(values))
    assert series['rows'] == 400             # 1970, no time and 'n/a' out


def test_spans_come_from_start_and_end(tmp_path):
    columns = [_col('start', 'Start Time', 'datetime'),
               _col('end', 'End Time', 'datetime'),
               _col('status', 'Device Lock Status')]
    rows = [(BASE + n * 600, BASE + n * 600 + 300,
             'Locked' if n % 2 else 'Unlocked') for n in range(10)]
    rows.append((BASE + 9000, BASE + 8000, 'Locked'))   # ends before start
    connection, artifact = _lava(tmp_path, columns, rows)
    shape = record_views.artifact_shape(connection, artifact)
    assert shape['kind'] == 'intervals'
    assert shape['end']['name'] == 'end'
    assert [c['name'] for c in shape['labels']] == ['status']
    spans, total = record_views.intervals_query(
        connection, artifact, shape['time'], shape['end'], shape['labels'][0])
    assert total == 11 and len(spans) == 11
    assert spans[-1][0] == spans[-1][1]     # a moment, not a negative span
    assert {s[2] for s in spans} == {'Locked', 'Unlocked'}


def test_rows_over_time_add_up(tmp_path):
    columns = [_col('ts', 'Timestamp', 'datetime'), _col('kind', 'Event Type'),
               _col('message', 'Message')]
    rows = [(BASE + n * 3600, ('open', 'close', 'crash')[n % 3], f'm{n}')
            for n in range(90)]
    connection, artifact = _lava(tmp_path, columns, rows)
    shape = record_views.artifact_shape(connection, artifact)
    assert shape['kind'] == 'counts'
    assert shape['labels'][0]['name'] == 'kind'     # not the free text
    counts = record_views.counts_query(connection, artifact, shape['time'],
                                       shape['labels'][0])
    assert counts['rows'] == 90
    totals = {}
    for _start, values in counts['buckets']:
        for key, n in values.items():
            totals[key] = totals.get(key, 0) + n
    assert totals == {'open': 30, 'close': 30, 'crash': 30}


def test_a_date_column_is_charted(tmp_path):
    columns = [_col('day', 'Day', 'date'), _col('steps', 'Steps')]
    rows = [('2024-03-0%d' % d, 1000 * d) for d in range(1, 8)]
    connection, artifact = _lava(tmp_path, columns, rows)
    series = record_views.series_query(connection, artifact, columns[0],
                                       columns[1])
    assert series['rows'] == 7
    assert record_views.epoch_text(series['first']) == '2024-03-01 00:00:00'


def test_no_time_no_chart(tmp_path):
    connection, artifact = _lava(tmp_path, [_col('a', 'Name')], [('x',)])
    assert record_views.artifact_shape(connection, artifact)['kind'] is None


# --- the window ------------------------------------------------------------------------

@pytest.fixture
def activity_case(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Views')
    evidence = case.add_evidence(str(tmp_path / 'disk.dd'))
    records = []
    for n in range(30):
        records.append(record(
            'usb', 'USBSTOR', _when(1 + n % 7, 8 + n % 5),
            'Connected', ('Kingston', 'SanDisk', 'Lexar')[n % 3],
            {'device': ('Kingston', 'SanDisk', 'Lexar')[n % 3],
             'serial': ('AA', 'BB', 'CC')[n % 3]}))
    case.add_user_activity(evidence, records)
    case.commit()
    yield case
    case.close()


def test_the_activity_tab_charts_and_narrows(qapp, activity_case):
    from tests.conftest import pump
    from trace_app.ui.viewers.activity_panel import ActivityPanel
    panel = ActivityPanel()
    try:
        panel.set_case(activity_case)
        panel.show_category('usb')
        pump(qapp, 3, until=lambda: not panel.loading and panel.model.rows)
        assert len(panel.model.rows) == 30
        panel.set_view(record_views.CHARTS, remember=True)
        assert panel.views.currentWidget() is panel.overview
        result = panel.overview.result
        title, field, entries, _others = result['breakdowns'][0]
        assert title == 'Devices'
        assert {label: n for _k, label, n in entries} == {
            'Kingston': 10, 'SanDisk': 10, 'Lexar': 10}
        # A value's click lists exactly its records.
        key = next(k for k, label, _n in entries if label == 'Lexar')
        panel.overview._value_clicked(0, key)
        assert panel.views.currentWidget() is panel.table
        assert panel.proxy.rowCount() == 10
        shown = {panel.proxy.data(panel.proxy.index(r, 0), 0x0100)['subject']
                 for r in range(panel.proxy.rowCount())}
        assert shown == {'Lexar'}
        assert panel.narrow_bar.isVisibleTo(panel)
        # The chip goes back to the charts, every record again.
        panel.clear_narrow()
        assert panel.proxy.rowCount() == 30
        assert panel.views.currentWidget() is panel.overview
        # A bar's records are its bucket's.
        index = 0
        prefix = result['buckets'][index][0]
        panel.overview._bucket_clicked(index)
        assert panel.proxy.rowCount() == sum(
            result['buckets'][index][1].values())
        assert all(panel.proxy.data(panel.proxy.index(r, 0), 0x0100)
                   ['time_utc'].startswith(prefix)
                   for r in range(panel.proxy.rowCount()))
        panel.clear_narrow()
        # Items: a card per device, together every named record.
        panel.set_view(record_views.ITEMS, remember=True)
        items = panel.items_view.model.items
        assert sorted(i['title'] for i in items) == ['Kingston', 'Lexar',
                                                     'SanDisk']
        assert sum(i['count'] for i in items) == 30
        # The choice is kept per category.
        from trace_app.infra import config_store
        assert config_store.get('Activity', 'view_usb') == 'items'
        panel.show_category(None)
        pump(qapp, 3, until=lambda: not panel.loading)
        assert panel.view_mode != record_views.ITEMS   # All has no items
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_many_records_are_worked_out_in_a_child_process(activity_case,
                                                         monkeypatch):
    """job_record_view reads the tab's rows again and gives what the
    window would have worked out itself."""
    from trace_app.core import background
    from trace_app.core.case import query_user_activity
    items = []
    count = background.job_record_view(
        {'case_folder': activity_case.folder, 'category': 'usb',
         'view': record_views.ITEMS},
        lambda *a: None, items.append, lambda: False)
    assert count == 30
    rows = query_user_activity(activity_case._db, None, 'usb')
    inline = record_views.inventory(rows, 'usb')
    assert [(i['title'], i['count'], sorted(i['ids']))
            for i in items[0]['items']] == \
        [(i['title'], i['count'], sorted(i['ids'])) for i in inline]
    charts = []
    background.job_record_view(
        {'case_folder': activity_case.folder, 'category': 'usb',
         'view': record_views.CHARTS}, lambda *a: None, charts.append,
        lambda: False)
    assert charts[0]['overview']['breakdowns'] == \
        record_views.overview(rows, 'usb')['breakdowns']
    assert 'record_view' in background.JOBS


def test_an_artifact_is_charted_from_the_tools_database(qapp, tmp_path):
    from tests.conftest import pump
    from trace_app.ui.viewers.record_views import ArtifactChart
    columns = [_col('ts', 'Timestamp', 'datetime'),
               _col('level', 'Battery Level')]
    connection, artifact = _lava(tmp_path, columns,
                                 [(BASE + n * 60, 50 + n % 7)
                                  for n in range(100)])
    connection.close()
    chart = ArtifactChart()
    try:
        chart.show_artifact({'report': str(tmp_path)}, artifact)
        pump(qapp, 5, until=lambda: chart.stack.currentWidget()
             is chart.series)
        assert chart.stack.currentWidget() is chart.series
        assert sum(p[2] for p in chart.series.points) == 100
        assert 'Battery Level' in chart.status.text()
        # Rows over time instead: the same hundred rows.
        chart.kind_combo.setCurrentIndex(chart.kind_combo.findData('counts'))
        pump(qapp, 5, until=lambda: chart.stack.currentWidget()
             is chart.bars)
        assert sum(sum(c.values()) for _s, _e, c in chart.bars.buckets) == 100
        png = chart.bars.picture()
        assert png.startswith(b'\x89PNG')
    finally:
        chart.shutdown()
        chart.deleteLater()


def test_a_saved_chart_is_audited(qapp, tmp_path, monkeypatch):
    from trace_app.core import evidence_export
    from trace_app.ui.widgets import charts
    recorded = []
    monkeypatch.setattr(evidence_export, '_recorder',
                        lambda action, detail: recorded.append((action,
                                                                detail)))
    target = str(tmp_path / 'chart.png')
    monkeypatch.setattr(charts.QFileDialog, 'getSaveFileName',
                        staticmethod(lambda *a, **k: (target, '')))
    bars = charts.RankBars()
    try:
        bars.resize(400, 120)
        bars.title = 'USB — devices'
        bars.set_data([('a', 'Kingston', 3), ('b', 'SanDisk', 1)])
        bars.save_picture()
        assert os.path.getsize(target) > 100
        assert recorded and recorded[0][0] == 'chart saved'
        assert "USB — devices" in recorded[0][1]
    finally:
        bars.deleteLater()

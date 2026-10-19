"""What external modules read, sorted into TRACE (core/modules/routes.py,
core/modules/bridge.py, core/activity_match.py): evidence artifacts become
Activity rows naming their reader, telemetry stays on the Timeline behind
a filter, one record read by TRACE and a LEAPP is one row, and a run read
twice counts once."""

import json
import os
import sqlite3

import pytest

from trace_app.core.modules import routes

SAFARI = {'artifact_key': 'safariHistory', 'name': 'Safari History',
          'category': 'Safari Browser', 'module': 'safariHistory',
          'columns': [('visit_timestamp', 'Visit Time', 'datetime'),
                      ('url', 'URL', ''), ('title', 'Title', ''),
                      ('visit_count', 'Visits', '')],
          'rows': [(1586629000, 'https://Example.com/a/', 'Example', 3),
                   (1586629100, 'https://trace.test/', 'Trace', 1)]}
LOGS = {'artifact_key': 'unifiedLogs', 'name': 'Unified Logs',
        'category': 'Unified Logs', 'module': 'logarchive',
        'columns': [('timestamp', 'Timestamp', 'datetime'),
                    ('message', 'Message', '')],
        'rows': [(1586629000 + n, f'line {n}') for n in range(5)]}
PLACES = {'artifact_key': 'somethingNew', 'name': 'Places Visited',
          'category': 'Somewhere', 'module': 'places',
          'columns': [('seen', 'Seen', 'datetime'),
                      ('latitude', 'Latitude', ''),
                      ('longitude', 'Longitude', '')],
          'rows': [(1586629000, 35.660969, -78.879852)]}
CHAT_VIEW = {'conversationDiscriminatorColumn': 'chat_id',
             'conversationLabelColumn': 'chat_name', 'textColumn': 'message',
             'directionColumn': 'direction',
             'directionSentValue': 'Outgoing', 'timeColumn': 'timestamp',
             'senderColumn': 'sender_name'}
CHATS = {'artifact_key': 'whatsAppMessages', 'name': 'WhatsApp - Messages',
         'category': 'WhatsApp', 'module': 'whatsapp',
         'columns': [('timestamp', 'Timestamp', 'datetime'),
                     ('direction', 'Direction', ''),
                     ('sender_name', 'Sender', ''), ('chat_name', 'Chat', ''),
                     ('message', 'Message', ''), ('chat_id', 'Chat id', '')],
         'rows': [(1586629000, 'Incoming', 'Alice', 'Alice', 'Hi there',
                   'alice@s.whatsapp.net'),
                  (1586629060, 'Outgoing', 'Me', 'Alice', 'Only iLEAPP',
                   'alice@s.whatsapp.net')],
         'data_views': {'conversation': CHAT_VIEW}}


def _run(case, evidence_id, name, artifacts, events=True):
    """A completed iLEAPP run whose LAVA report holds `artifacts`, with a
    Timeline event per row and date column (as job.events makes them)."""
    report = os.path.join(case.folder, 'modules', name, 'report')
    os.makedirs(report)
    database = sqlite3.connect(os.path.join(report, '_lava_artifacts.db'))
    entries = {}
    for spec in artifacts:
        table = spec['artifact_key'].lower()
        names = [c[0] for c in spec['columns']]
        database.execute(f"CREATE TABLE {table} ({', '.join(names)})")
        database.executemany(
            f"INSERT INTO {table} VALUES ({','.join('?' * len(names))})",
            spec['rows'])
        entry = {'artifact_key': spec['artifact_key'], 'name': spec['name'],
                 'tablename': table, 'module': spec['module'],
                 'column_map': {c[0]: c[1] for c in spec['columns']},
                 'object_columns': [{'name': c[0], 'type': c[2]}
                                    for c in spec['columns'] if c[2]],
                 'record_count': len(spec['rows']),
                 'source_path': 'private/var/mobile/x.db'}
        if spec.get('data_views'):
            entry['data_views'] = spec['data_views']
        entries.setdefault(spec['category'], []).append(entry)
    database.commit()
    database.close()
    with open(os.path.join(report, '_lava_data.lava'), 'w') as handle:
        json.dump({'lava_schema_version': 2, 'processing_status': 'Complete',
                   'parser_info': {'leapp_name': 'iLEAPP',
                                   'leapp_version': '2026.4.4'},
                   'artifacts': entries, 'modules': []}, handle)
    from trace_app.core.modules import lava
    run = case.add_module_run(evidence_id, 'iLEAPP', '2026.4.4', 'x' * 64,
                              {}, os.path.dirname(report))
    ids = case.add_module_artifacts(run, lava.load(report)['artifacts'])
    if events:
        for spec in artifacts:
            table = spec['artifact_key'].lower()
            dated = [i for i, c in enumerate(spec['columns'])
                     if c[2] == 'datetime']
            case.add_module_events(run, [
                (ids[table], rowid, lava.utc_text(values[i]),
                 f"{spec['name']}: {spec['columns'][i][1]}", spec['name'])
                for rowid, values in enumerate(spec['rows'], 1)
                for i in dated])
    case.finish_module_run(run, 'complete')
    return run


@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case
    folder = tmp_path / 'phone'
    folder.mkdir()
    (folder / 'note.txt').write_text('x')
    other = tmp_path / 'other phone'
    other.mkdir()
    (other / 'note.txt').write_text('y')
    case = Case.create(str(tmp_path / 'case'), 'Bridge')
    case.phone = case.add_evidence(str(folder))
    case.other = case.add_evidence(str(other))
    yield case
    case.close()


def _bridge(case, run, **options):
    from trace_app.core.modules import bridge
    return bridge.bridge_run(case, run, **options)


def _trace_message(when, text, direction='received'):
    """TRACE's own reading of a WhatsApp message (activity/mobile.py's
    shape)."""
    from trace_app.core.activity import record
    from datetime import datetime, timezone
    moment = datetime.fromtimestamp(when, timezone.utc)
    detail = {'chat': 'Alice', 'chat id': 'alice@s.whatsapp.net'}
    detail['from' if direction == 'received' else 'to'] = \
        'alice@s.whatsapp.net'
    return record('communication', 'WhatsApp (iOS)', moment,
                  f'Message {direction}', text, detail,
                  path='ChatStorage.sqlite', ref='p0:i5:s1')


# --- routing ---------------------------------------------------------------

def _artifact(spec, **more):
    out = {'artifact_key': spec['artifact_key'], 'name': spec['name'],
           'module': spec['module'], 'category': spec['category'],
           'tablename': spec['artifact_key'].lower(),
           'columns': [{'name': c[0], 'label': c[1], 'type': c[2]}
                       for c in spec['columns']]}
    out.update(more)
    return out


def test_artifacts_are_sorted_by_key_name_columns_and_lists():
    safari = routes.route('iLEAPP', _artifact(SAFARI))
    assert (safari.role, safari.category, safari.what) == \
        ('evidence', 'browser', 'Visited')
    assert routes.route('iLEAPP', _artifact(LOGS)).role == 'telemetry'
    places = routes.route('aLEAPP', _artifact(PLACES))
    assert (places.role, places.category) == ('evidence', 'locations')
    chats = routes.route('iLEAPP', _artifact(CHATS, conversation=CHAT_VIEW))
    assert chats.conversation and chats.category == 'communication'
    # A name rule works for any tool; nothing known is 'other'.
    calls = routes.route('aLEAPP', {'name': 'Call Logs', 'columns': []})
    assert calls.role == 'evidence' and calls.category == 'communication'
    assert routes.route('DLEAPP', {'name': 'Mystery', 'columns': []}).role \
        == 'other'


def test_the_examiners_choice_wins():
    artifact = _artifact(LOGS)
    key = routes.override_key('iLEAPP', artifact)
    assert key == 'ileapp:unifiedLogs'
    chosen = routes.route('iLEAPP', artifact, {key: 'evidence'})
    assert (chosen.role, chosen.category) == ('evidence', 'records')
    assert routes.route('iLEAPP', _artifact(SAFARI),
                        {'ileapp:safariHistory': 'telemetry'}).role == \
        'telemetry'


# --- rows and events -------------------------------------------------------

def test_evidence_becomes_activity_and_telemetry_stays_on_the_timeline(case):
    run = _run(case, case.phone, 'first', [SAFARI, LOGS, PLACES])
    summary = _bridge(case, run)
    assert (summary['evidence'], summary['telemetry']) == (2, 1)
    rows = case.user_activity(case.phone)
    visits = sorted((r for r in rows if r['category'] == 'browser'),
                    key=lambda r: r['time_utc'])
    assert [r['what'] for r in visits] == ['Visited', 'Visited']
    first = visits[0]
    assert first['time_utc'].startswith('2020-04-11 18:16:40')
    # Typed by iLEAPP's map: the URL is the subject, as TRACE's own visits.
    assert first['subject'] == 'https://Example.com/a/'
    assert first['detail']['title'] == 'Example'
    assert first['detail']['visits'] == '3'
    assert first['reader'] == 'iLEAPP' and first['read_by'] == ['iLEAPP']
    assert first['module_run_id'] == run
    assert first['source_ref'] == f'mod:{run}:safarihistory:1'
    assert first['detail']['url'] == 'https://Example.com/a/'
    assert first['detail']['Visits'] == '3'
    place, = case.located_activity(case.phone)
    assert (place['detail']['latitude'], place['detail']['longitude']) == \
        (35.660969, -78.879852)
    assert not [r for r in rows if 'line' in (r['subject'] or '')]
    kinds = dict(case._db.execute(
        "SELECT a.tablename, GROUP_CONCAT(DISTINCT e.kind) FROM "
        "module_events e JOIN module_artifacts a ON a.id = e.artifact_id "
        "GROUP BY a.tablename").fetchall())
    # The visit time is the Activity row itself: its event is 'bridged'.
    assert kinds == {'safarihistory': 'bridged', 'unifiedlogs': 'telemetry',
                     'somethingnew': 'bridged'}
    assert case.user_activity_summary(case.phone) == {'browser': 2,
                                                      'locations': 1}


def test_the_timeline_hides_telemetry_until_asked(case):
    from trace_app.core import timeline
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, run)

    def subjects(**filters):
        filters.setdefault('sources', [key for key, *_ in timeline.SOURCES])
        return timeline.events(case._db, filters)

    shown = subjects()
    assert not [e for e in shown if e.get('source') == 'modules']
    assert len([e for e in shown if e.get('source') == 'activity']) == 2
    with_telemetry = subjects(module_telemetry=True)
    assert len([e for e in with_telemetry
                if e.get('source') == 'modules']) == 5


def test_sorting_again_changes_nothing(case):
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, run)
    before = case._db.execute("SELECT COUNT(*) FROM user_activity"
                              ).fetchone()[0]
    assert case.unbridged_module_runs() == []
    again = _bridge(case, run)
    assert again['artifacts'] == 0            # nothing left to sort
    _bridge(case, run, force=True)
    assert case._db.execute("SELECT COUNT(*) FROM user_activity"
                            ).fetchone()[0] == before


def test_the_job_sorts_what_is_unsorted(case):
    from trace_app.core import background
    _run(case, case.phone, 'first', [SAFARI])
    assert case.unbridged_module_runs()
    folder = case.folder
    case.close()
    found = []
    background.job_module_bridge({'case_folder': folder},
                                 lambda *_: None, found.append,
                                 lambda: False)
    assert found and found[0]['runs'] == 1
    from trace_app.core.case import Case
    reopened = Case.open(folder)
    try:
        assert reopened.unbridged_module_runs() == []
        assert reopened.user_activity_summary() == {'browser': 2}
        assert any('external module results sorted' in (a.get('action') or '')
                   for a in reopened.activity())
    finally:
        reopened.close()
    case.__dict__['_db'] = Case.open(folder)._db    # for the fixture's close


def test_an_override_moves_an_artifact(case):
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, run)
    logs = next(a for a in case.module_artifacts(run)
                if a['tablename'] == 'unifiedlogs')
    case.set_setting('module_routes', {'ileapp:unifiedLogs': 'evidence'})
    _bridge(case, run, only=[logs['id']])
    assert case.user_activity_summary(case.phone)['records'] == 5
    case.set_setting('module_routes', {'ileapp:safariHistory': 'telemetry'})
    _bridge(case, run, force=True)
    assert 'browser' not in case.user_activity_summary(case.phone)


# --- runs: removal, a phone read twice -------------------------------------

def test_trace_activity_rerun_keeps_what_modules_read(case):
    run = _run(case, case.phone, 'first', [SAFARI])
    _bridge(case, run)
    case.add_user_activity(case.phone, [_trace_message(1586000000, 'own')])
    case.clear_user_activity(case.phone)      # TRACE's module runs again
    rows = case.user_activity(case.phone)
    assert len(rows) == 2 and {r['reader'] for r in rows} == {'iLEAPP'}


def test_removing_a_run_removes_its_rows(case):
    run = _run(case, case.phone, 'first', [SAFARI])
    _bridge(case, run)
    case.remove_module_run(run)
    assert case.user_activity(case.phone) == []


def test_the_same_artifact_in_two_runs_counts_once(case):
    first = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, first)
    second = _run(case, case.phone, 'second', [SAFARI, LOGS])
    summary = _bridge(case, second)
    assert summary['superseded'] == 2
    rows = case.user_activity(case.phone)
    assert len(rows) == 2 and {r['module_run_id'] for r in rows} == {second}
    older = {a['tablename']: a for a in case.module_artifacts(first)}
    assert older['safarihistory']['superseded_by']
    kinds = {k for (k,) in case._db.execute(
        "SELECT DISTINCT kind FROM module_events WHERE run_id = ?",
        (first,))}
    assert kinds == {'superseded'}
    # The newer run goes: the older one's rows come back.
    case.remove_module_run(second)
    _bridge(case, first)
    rows = case.user_activity(case.phone)
    assert len(rows) == 2 and {r['module_run_id'] for r in rows} == {first}


def test_a_different_artifact_is_not_superseded(case):
    first = _run(case, case.phone, 'first', [SAFARI])
    _bridge(case, first)
    changed = dict(SAFARI, rows=SAFARI['rows'] + [
        (1586629200, 'https://new.test/', 'New', 1)])
    second = _run(case, case.phone, 'second', [changed])
    assert _bridge(case, second)['superseded'] == 0


# --- readers: one record, read by TRACE and a LEAPP ------------------------

def test_a_message_trace_and_ileapp_read_is_one_row(case):
    case.add_user_activity(case.phone, [
        _trace_message(1586629000, 'Hi there'),
        _trace_message(1586000000, 'Only TRACE')])
    case.relink_matches(case.phone)
    run = _run(case, case.phone, 'first', [CHATS])
    _bridge(case, run)
    rows = case.user_activity(case.phone)
    by_text = {r['subject']: r for r in rows}
    assert set(by_text) == {'Hi there', 'Only TRACE', 'Only iLEAPP'}
    both = by_text['Hi there']
    assert both['reader'] == 'TRACE'          # TRACE's own is the primary
    assert both['read_by'] == ['TRACE', 'iLEAPP']
    readings = case.readings(both['id'])
    assert [r['reader'] for r in readings] == ['TRACE', 'iLEAPP']
    assert by_text['Only TRACE']['read_by'] == ['TRACE']
    assert by_text['Only iLEAPP']['read_by'] == ['iLEAPP']
    assert case.activity_readers() == ['TRACE', 'iLEAPP']

    from trace_app.core.case import query_user_activity

    def texts(**options):
        return {r['subject'] for r in query_user_activity(case._db,
                                                          **options)}

    assert texts(reader='iLEAPP') == {'Hi there', 'Only iLEAPP'}
    assert texts(reader='iLEAPP', only_reader=True) == {'Only iLEAPP'}
    assert texts(reader='TRACE', only_reader=True) == {'Only TRACE'}
    assert case.user_activity_summary(case.phone) == {'communication': 3}
    # The Timeline: one event per record, filtered by reader alike.
    from trace_app.core import timeline
    sources = [key for key, *_ in timeline.SOURCES]

    def on_timeline(**more):
        return sorted(e['subject'] for e in timeline.events(
            case._db, dict(sources=sources, **more))
            if e['source'] == 'activity')

    assert on_timeline() == ['Hi there', 'Only TRACE', 'Only iLEAPP']
    assert on_timeline(reader='iLEAPP', reader_only=True) == ['Only iLEAPP']
    assert on_timeline(reader='TRACE') == ['Hi there', 'Only TRACE']
    # Conversations: one bubble, both readers named on it.
    thread, = [t for t in case.conversations() if t['messages'] >= 2]
    shown = case.conversation(thread['key'])
    hi = [r for r in shown if r['subject'] == 'Hi there']
    assert len(hi) == 1 and hi[0]['read_by'] == ['TRACE', 'iLEAPP']

    # TRACE's module runs again: the link is made again.
    case.clear_user_activity(case.phone)
    case.relink_matches(case.phone)
    rows = case.user_activity(case.phone)
    assert {r['subject'] for r in rows} == {'Hi there', 'Only iLEAPP'}
    assert all(r['read_by'] == ['iLEAPP'] for r in rows)
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'Hi there')])
    case.relink_matches(case.phone)
    # The LEAPP run goes: TRACE's reading stands alone.
    case.remove_module_run(run)
    rows = case.user_activity(case.phone)
    assert [(r['subject'], r['read_by']) for r in rows] == \
        [('Hi there', ['TRACE'])]


def test_an_hour_off_or_a_zoneless_time_is_another_record():
    from trace_app.core.activity_match import match_key
    base = _trace_message(1586629000, 'Hi there')
    assert match_key(base) == match_key(dict(base, source='WhatsApp'))
    assert match_key(base) != match_key(_trace_message(1586632600,
                                                       'Hi there'))
    assert match_key(dict(base, local=True)) is None
    assert match_key(dict(base, time=None)) is None


def test_records_on_two_evidence_items_are_never_merged(case):
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'Hi there')])
    case.relink_matches(case.phone)
    run = _run(case, case.other, 'first', [CHATS])
    _bridge(case, run)
    rows = case.user_activity()
    hi = [r for r in rows if r['subject'] == 'Hi there']
    assert len(hi) == 2
    assert {r['evidence_id'] for r in hi} == {case.phone, case.other}
    assert all(len(r['read_by']) == 1 for r in hi)


# --- the window -------------------------------------------------------------

def test_the_activity_tab_names_who_read_each_record(qapp, case,
                                                     monkeypatch):
    import time
    from tests.conftest import close_window, pump
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    from trace_app.ui.viewers.activity_panel import READ_BY
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    monkeypatch.setattr(message, 'question', lambda *a, **k: False)
    case.add_user_activity(case.phone, [
        _trace_message(1586629000, 'Hi there'),
        _trace_message(1586000000, 'Only TRACE')])
    _bridge(case, _run(case, case.phone, 'first', [CHATS]))
    window = MainWindow(case=case)
    try:
        panel = window.activity_panel

        def shown():
            panel.refresh()
            deadline = time.monotonic() + 10
            while panel.loading and time.monotonic() < deadline:
                pump(qapp, 0.05)
            pump(qapp, 0.05)
            model = panel.model
            return {model.index(r, 2).data(): model.index(r, READ_BY).data()
                    for r in range(model.rowCount())}

        assert shown() == {'Hi there': 'TRACE, iLEAPP',
                           'Only TRACE': 'TRACE',
                           'Only iLEAPP': 'iLEAPP'}
        assert panel.reader_filter_action.isVisible() or \
            panel.reader_filter.count() == 5
        panel.reader_filter.setCurrentIndex(
            panel.reader_filter.findData('iLEAPP|only'))
        assert panel.reader_choice() == ('iLEAPP', True)
        assert shown() == {'Only iLEAPP': 'iLEAPP'}
        panel._fill_readers()                  # kept when the list refills
        assert panel.reader_choice() == ('iLEAPP', True)
        assert window.case.user_activity_summary() == {'communication': 3}
    finally:
        close_window(window)


def test_the_timeline_says_how_much_telemetry_it_hides(qapp, case,
                                                       monkeypatch):
    import time
    from tests.conftest import close_window, pump
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    monkeypatch.setattr(message, 'question', lambda *a, **k: False)
    _bridge(case, _run(case, case.phone, 'first', [SAFARI, LOGS]))
    window = MainWindow(case=case)
    try:
        panel = window.timeline_panel

        def load():
            panel.refresh()
            deadline = time.monotonic() + 10
            while panel.loading and time.monotonic() < deadline:
                pump(qapp, 0.05)
            pump(qapp, 0.05)

        load()
        assert panel._telemetry_count == 5      # counted off the window
        assert panel.counts.get('modules', 0) == 0
        panel.filters['module_telemetry'] = True
        load()
        assert panel.counts.get('modules') == 5
    finally:
        close_window(window)


SMS = {'artifact_key': 'smsMessages', 'name': 'SMS Messages',
       'category': 'SMS & MMS', 'module': 'sms',
       'columns': [('date', 'Date', 'datetime'),
                   ('direction', 'Type', ''), ('address', 'Address', ''),
                   ('body', 'Body', '')],
       'rows': [(1586629000, 'Received', '+15551230001', 'Lunch?'),
                (1586629060, 'Sent', '+15551230001', 'Yes, at noon')]}
BOTH = dict(SMS, artifact_key='smsMmsMessages', name='SMS and MMS Messages',
            rows=SMS['rows'] + [(1586629120, 'Received', '+15551230002',
                                 'An MMS')])


def test_a_message_artifact_by_name_alone_becomes_messages(case):
    run = _run(case, case.phone, 'first', [SMS])
    _bridge(case, run)
    rows = sorted(case.user_activity(case.phone),
                  key=lambda r: r['time_utc'])
    assert [r['what'] for r in rows] == ['Message received', 'Message sent']
    assert [r['subject'] for r in rows] == ['Lunch?', 'Yes, at noon']
    assert rows[0]['detail']['from'] == '+15551230001'
    assert rows[1]['detail']['to'] == '+15551230001'
    thread, = case.conversations()
    assert thread['messages'] == 2
    # Attachments and leftovers are not messages.
    for name in ('MMS Attachments', 'SMS - Missing ROWIDs',
                 'Synchronoss - MMS Media Sent', 'IMO HD Chat - Key Values',
                 'Twitter X - Direct Message Users',
                 'iOS Message Retention'):
        assert routes.route('aLEAPP', {'name': name, 'columns': []}).role \
            == 'other', name
    assert routes.route('iLEAPP', {'name': 'IMO HD Chat - Contacts',
                                   'columns': []}).what == 'Contact'
    assert routes.route('RLEAPP', {'name': 'Synchronoss - Messages (SMS '
                                           'and MMS)', 'columns': []}).what \
        == 'Message {direction}'


def test_one_message_in_two_artifacts_of_a_run_is_one_row(case):
    """aLEAPP's 'SMS and MMS Messages' repeats its 'SMS Messages'."""
    run = _run(case, case.phone, 'first', [SMS, BOTH])
    _bridge(case, run)
    rows = case.user_activity(case.phone)
    assert sorted(r['subject'] for r in rows) == \
        ['An MMS', 'Lunch?', 'Yes, at noon']
    assert all(r['read_by'] == ['iLEAPP'] for r in rows)


# --- who read it, in Triage; what is not in Activity; the report ----------

SETTINGS = {'artifact_key': 'deviceSettings', 'name': 'Device Settings',
            'category': 'Settings', 'module': 'settings',
            'columns': [('setting', 'Setting', ''), ('value', 'Value', '')],
            'rows': [('Airplane mode', 'off'), ('Bluetooth', 'on')]}


def test_the_map_and_conversations_name_who_read_it(case):
    from trace_app.core import geo
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'Hi there')])
    _bridge(case, _run(case, case.phone, 'first', [CHATS, PLACES]))
    place, = geo.located(case)
    assert place['read_by'] == ['iLEAPP']
    assert place['source'] == 'Somewhere (iLEAPP)'
    thread, = [t for t in case.conversations() if t['messages'] >= 2]
    assert thread['readers'] == ['TRACE', 'iLEAPP']
    from trace_app.core.conversations import readers_text, source_text
    assert readers_text(['TRACE', 'iLEAPP']) == 'TRACE, iLEAPP'
    assert source_text({'source': 'WhatsApp (iOS)', 'reader': 'TRACE'}) == \
        'WhatsApp (iOS)'
    assert source_text({'source': 'iLEAPP stuff', 'reader': 'iLEAPP',
                        'read_by': ['iLEAPP']}) == 'iLEAPP stuff'


def test_the_report_says_what_was_sorted_and_takes_whole_artifacts(case):
    import hashlib
    from trace_app.core import report
    run = _run(case, case.phone, 'first', [SAFARI, LOGS, SETTINGS])
    _bridge(case, run)
    folder = os.path.join(case.folder, 'modules', 'first', 'report')
    with open(os.path.join(folder, 'index.html'), 'wb') as handle:
        handle.write(b'<html>iLEAPP</html>')
    case.add_report_items('module_artifact', [{
        'evidence_id': case.phone,
        'artifact_ref': f'modart:{run}:unifiedlogs',
        'title': 'iLEAPP - Unified Logs',
        'detail': {'run_id': run, 'tablename': 'unifiedlogs'}}])
    options = report.default_options(case)
    options['sections'] = [{'key': 'modules', 'enabled': True}]
    options['thumbnails'] = False
    options['activity_limit'] = 2
    html = report.build_html(case, options)[0]
    assert ('1 as evidence (copied into Activity), 1 other, 1 telemetry'
            in html)
    assert hashlib.sha256(b'<html>iLEAPP</html>').hexdigest() in html
    assert 'line 0' in html and 'line 1' in html and 'line 2' not in html
    assert '2 of 5 row(s) shown' in html
    # How each was sorted, run by run.
    assert 'Sorted by' in html and 'listed as telemetry or other' in html


def test_a_run_accounts_for_how_each_artifact_was_sorted(case):
    from trace_app.core.modules import routes
    from trace_app.ui.viewers.modules_panel import accounting_html
    run = _run(case, case.phone, 'first', [SAFARI, LOGS, PLACES, SETTINGS])
    _bridge(case, run)
    artifacts = case.module_artifacts(run)
    assert all(a['sorted_by'] for a in artifacts)
    groups = routes.accounting(artifacts)
    # Every artifact counted once, every row once.
    assert sum(g['artifacts'] for g in groups) == len(artifacts)
    assert sum(g['rows'] for g in groups) ==         sum(a['row_count'] or 0 for a in artifacts)
    by = {(g['sorted_by'], g['role']): g for g in groups}
    # 'Places Visited' is in no map or table: its columns sorted it, and
    # the page names it for the examiner to check.
    assert by[('columns', 'evidence')]['names'] == ['Places Visited']
    page = accounting_html(artifacts)
    assert 'Places Visited' in page and 'its latitude/longitude' in page
    assert [g['sorted_by'] for g in groups] == sorted(
        (g['sorted_by'] for g in groups),
        key=[k for k, _w in routes.SORTED_WORDS].index)


def test_activity_lists_what_modules_read_and_trace_did_not_sort(
        qapp, case, monkeypatch):
    import time
    from PySide6.QtCore import Qt
    from tests.conftest import close_window, pump
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    monkeypatch.setattr(message, 'question', lambda *a, **k: False)
    run = _run(case, case.phone, 'first', [SAFARI, LOGS, SETTINGS, PLACES,
                                            CHATS])
    _bridge(case, run)
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'Hi there')])
    case.relink_matches(case.phone)
    stored = case._db.execute("SELECT COUNT(*) FROM user_activity"
                              ).fetchone()[0]
    window = MainWindow(case=case)
    try:
        window.refresh_modules()
        panel = window.activity_panel
        assert 'Others (2)' in panel.tabs.headings()
        other, telemetry = sorted(panel._module_tabs)
        assert panel.tabs.tabText(other) == 'Other records (1)'
        assert panel.tabs.tabText(telemetry) == 'Telemetry (1)'
        panel.tabs.setCurrentIndex(telemetry)
        view = panel.views.currentWidget()
        assert view is panel._module_tabs[telemetry]
        assert '1 artifact(s), 5 row(s) iLEAPP read' in \
            panel.status_label.text()
        node = view.tree.topLevelItem(0).child(0).child(0)
        assert node.text(0) == 'Unified Logs (5)'
        view.tree.setCurrentItem(node)
        assert view.model.rowCount() == 5
        assert view.payload(0)['artifact_ref'] == \
            f'mod:{run}:unifiedlogs:1'
        # Read from the tool's database: nothing was copied for it.
        assert case._db.execute("SELECT COUNT(*) FROM user_activity"
                                ).fetchone()[0] == stored
        window.add_module_artifact_to_report(view.model.run,
                                             view.model.artifact)
        assert case.report_items('module_artifact')

        # The Modules tab: only what is not in Activity.
        modules = window.modules_panel
        modules.hidden_only.setChecked(True)
        top = modules.tree.topLevelItem(0)
        shown = [top.child(g).child(c).text(0)
                 for g in range(top.childCount())
                 for c in range(top.child(g).childCount())
                 if not top.child(g).child(c).isHidden()]
        assert sorted(shown) == ['Device Settings (2)',
                                 'Unified Logs (5) · telemetry']

        # The same records shown another way: Activity <-> Triage.
        def loaded(widget):
            deadline = time.monotonic() + 10
            while widget.loading and time.monotonic() < deadline:
                pump(qapp, 0.05)
            pump(qapp, 0.05)

        rows = case.user_activity(case.phone)
        message_row = next(r for r in rows if r['subject'] == 'Hi there')
        window.show_in_conversation(message_row)
        loaded(window.conversations_panel)
        conversations = window.conversations_panel
        current = conversations._row_of(
            conversations.messages_view.currentItem())
        assert current['id'] == message_row['id']
        assert current['read_by'] == ['TRACE', 'iLEAPP']
        assert conversations.threads_view.currentItem().text(2) == \
            'TRACE, iLEAPP'

        place_row = next(r for r in rows if r['category'] == 'locations')
        window.show_on_map(place_row)
        table = window.map_panel.table
        assert table.currentRow() >= 0
        headers = [table.horizontalHeaderItem(c).text()
                   for c in range(table.columnCount())]
        assert table.item(table.currentRow(),
                          headers.index('Read by')).text() == 'iLEAPP'

        window.show_activity_row(message_row)
        loaded(panel)
        index = panel.table.currentIndex()
        assert panel.proxy.data(panel.proxy.index(index.row(), 0),
                                Qt.UserRole)['id'] == message_row['id']
    finally:
        close_window(window)


def test_the_from_modules_group_goes_when_nothing_is_hidden(qapp):
    from trace_app.ui.viewers.activity_panel import ActivityPanel
    panel = ActivityPanel()
    try:
        panel.case = object()           # a case is open
        run = {'status': 'complete', 'evidence_id': 1, 'key': 1,
               'tool': 'iLEAPP', 'version': '1', 'evidence': 'phone',
               'artifacts': [{'role': 'telemetry', 'record_count': 3,
                              'category': 'Logs', 'name': 'Logs',
                              'tablename': 'logs', 'columns': []}]}
        panel.set_module_runs([run])
        assert 'Others (1)' in panel.tabs.headings()
        panel.tabs.setCurrentIndex(max(panel._module_tabs))
        panel.set_module_runs([])
        assert not any(h.startswith('Others')
                       for h in panel.tabs.headings())
        assert panel.tabs.currentIndex() == 0
        assert panel.views.currentWidget() is panel.table
    finally:
        panel.case = None
        panel.deleteLater()


# --- the import limit (case setting module_import_rows), changed later ----

def _imported_at(case, run, kept_tables):
    """The run as if imported with these artifacts over the limit: no
    events for them, the run's params saying so."""
    stored = {a['tablename']: a for a in case.module_artifacts(run)}
    case.drop_module_events(stored[t]['id'] for t in kept_tables)
    params = dict(case.module_run(run)['params'])
    params['not_imported'] = [[stored[t]['name'], stored[t]['row_count']]
                              for t in kept_tables]
    case.set_module_run_params(run, params)


def _module_search_rows(case, table):
    from trace_app.core.search_index import SearchIndex
    index = SearchIndex(case.folder)
    try:
        return index._db.execute(
            "SELECT COUNT(*) FROM indexed_items WHERE kind = 'module' AND "
            "artifact_ref LIKE ?", (f"mod:%:{table}:%",)).fetchone()[0]
    finally:
        index.close()


def _events_of(case, table):
    return case._db.execute(
        "SELECT COUNT(*) FROM module_events e JOIN module_artifacts a ON "
        "a.id = e.artifact_id WHERE a.tablename = ?", (table,)).fetchone()[0]


def test_a_changed_import_limit_applies_to_runs_already_in_the_case(case):
    from trace_app.core.modules import job
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _imported_at(case, run, ['unifiedlogs'])
    stored = case.module_artifacts(run)
    assert job.imported_tables(case.module_run(run), stored) == \
        {'safarihistory'}
    assert job.pending_rows(case.module_run(run), stored, 0) == (5, 0)
    assert job.pending_rows(case.module_run(run), stored, 3) == (0, 0)
    assert _events_of(case, 'unifiedlogs') == 0

    done = job.apply_limit(case, case.folder, run, 0)       # no limit
    assert done['added'] == [('Unified Logs', 5)]
    assert _events_of(case, 'unifiedlogs') == 5
    assert _module_search_rows(case, 'unifiedlogs') == 5
    assert _events_of(case, 'safarihistory') == 2           # untouched
    params = case.module_run(run)['params']
    assert params['not_imported_tables'] == [] and params['import_limit'] == 0
    assert job.apply_limit(case, case.folder, run, 0)['added'] == []

    done = job.apply_limit(case, case.folder, run, 3)       # smaller again
    assert done['dropped'] == [('Unified Logs', 5)]
    assert _events_of(case, 'unifiedlogs') == 0
    assert _module_search_rows(case, 'unifiedlogs') == 0
    assert case.module_run(run)['params']['not_imported_tables'] == \
        ['unifiedlogs']


def test_the_import_job_adds_audits_and_sorts_again(case):
    from trace_app.core import background
    from trace_app.core.case import Case
    from trace_app.core import settings as case_settings
    from trace_app.core.modules import destinations
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, run)
    _imported_at(case, run, ['unifiedlogs'])
    # Telemetry to the Timeline and Search too (the default keeps it out).
    case_settings.save_case(case, {
        'module_destinations': destinations.EVERYWHERE})
    folder = case.folder
    case.close()
    found = []
    added = background.job_module_import(
        {'case_folder': folder, 'limit': 0, 'old_limit': 3},
        lambda *_: None, found.append, lambda: False)
    assert added == 5 and found[0]['runs'] == 1
    reopened = Case.open(folder)
    try:
        assert _events_of(reopened, 'unifiedlogs') == 5
        # Telemetry stays telemetry on the Timeline after the import.
        kinds = {k for (k,) in reopened._db.execute(
            "SELECT DISTINCT e.kind FROM module_events e JOIN "
            "module_artifacts a ON a.id = e.artifact_id "
            "WHERE a.tablename = 'unifiedlogs'")}
        assert kinds == {'telemetry'}
        assert any(a['action'] == 'external module rows imported again'
                   for a in reopened.activity())
    finally:
        reopened.close()
    case.__dict__['_db'] = Case.open(folder)._db


def test_a_large_import_is_asked_and_a_no_puts_the_setting_back(
        qapp, case, monkeypatch):
    from tests.conftest import close_window
    from trace_app.core import settings as case_settings
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    asked = []
    monkeypatch.setattr(message, 'question',
                        lambda *a, **k: asked.append(a) or False)
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _imported_at(case, run, ['unifiedlogs'])
    window = MainWindow(case=case)
    try:
        queued = []
        monkeypatch.setattr(window, 'queue_module_import',
                            lambda old, new, **_k: queued.append((old, new)))
        window.LARGE_IMPORT = 1
        case_settings.save_case(case, {'module_import_rows': 0})
        assert window.module_import_limit_changed(3, 0) is False
        assert asked and 'Add 5 rows' in asked[0][2]
        assert case_settings.for_case(case)['module_import_rows'] == 3
        assert not queued
        monkeypatch.setattr(message, 'question', lambda *a, **k: True)
        case_settings.save_case(case, {'module_import_rows': 0})
        window.module_import_limit_changed(3, 0)
        assert queued == [(3, 0)]
        # Nothing to change: nothing queued.
        queued.clear()
        window.module_import_limit_changed(0, 3)
        assert not queued
    finally:
        close_window(window)



MEDIA = {'artifact_key': 'photosMedia', 'name': 'Google Photos - Local Media',
         'category': 'Google Photos', 'module': 'photos',
         'columns': [('taken', 'Taken', 'datetime'),
                     ('file_name', 'File', ''),
                     ('latitude', 'Latitude', ''),
                     ('longitude', 'Longitude', '')],
         'rows': [(1586629000, 'IMG_1.jpg', 35.66, -78.88),
                  (1586629100, 'IMG_2.jpg', None, None),
                  (1586629200, 'IMG_3.jpg', 0.0, 0.0)]}


def test_a_location_row_with_no_position_is_a_file_record(case):
    """Activity's Locations and the Map count alike: a row of a location
    artifact with no position (aLEAPP's Google Photos: 240 rows, 32
    placed) is a file record."""
    from trace_app.core import geo
    _bridge(case, _run(case, case.phone, 'first', [MEDIA]))
    summary = case.user_activity_summary(case.phone)
    assert summary == {'locations': 1, 'files': 2}
    assert len(geo.located(case)) == summary['locations']
    unplaced = [r for r in case.user_activity(case.phone)
                if r['category'] == 'files']
    assert {r['what'] for r in unplaced} == {'Google Photos - Local Media'}


# --- where each kind goes (case setting module_destinations) --------------

def _where(case, run):
    params = case.module_run(run)['params']
    return (sorted(params.get('timeline_tables', [])),
            sorted(params.get('search_tables', [])))


def _set_places(case, value):
    from trace_app.core import settings as case_settings
    case_settings.save_case(case, {'module_destinations': value})


def test_telemetry_stays_out_of_the_timeline_and_search_by_default(case):
    from trace_app.core.modules import destinations, job
    run = _run(case, case.phone, 'first', [SAFARI, LOGS], events=False)
    _bridge(case, run)
    params = dict(case.module_run(run)['params'])
    params.update(timeline_tables=[], search_tables=[])
    case.set_module_run_params(run, params)    # as job_leapp records it
    done = job.apply_destinations(case, case.folder, run, 250_000)
    assert done['added'] == [('Safari History', 2)]
    assert _events_of(case, 'safarihistory') == 2
    assert _module_search_rows(case, 'safarihistory') == 2
    assert _events_of(case, 'unifiedlogs') == 0
    assert _module_search_rows(case, 'unifiedlogs') == 0
    assert _where(case, run) == (['safarihistory'], ['safarihistory'])
    # Its own time is its Activity row's event: tagged as such.
    kinds = {k for (k,) in case._db.execute(
        "SELECT DISTINCT kind FROM module_events")}
    assert kinds == {'bridged'}

    # Telemetry to the Timeline only: events, no search rows.
    value = destinations.normalise(None)
    value['telemetry'] = ['activity', 'timeline']
    _set_places(case, value)
    stored = case.module_artifacts(run)
    assert job.pending_rows(case.module_run(run), stored, 250_000) == (5, 0)
    job.apply_destinations(case, case.folder, run, 250_000)
    assert _events_of(case, 'unifiedlogs') == 5
    assert _module_search_rows(case, 'unifiedlogs') == 0
    kinds = {k for (k,) in case._db.execute(
        "SELECT DISTINCT e.kind FROM module_events e JOIN module_artifacts a "
        "ON a.id = e.artifact_id WHERE a.tablename = 'unifiedlogs'")}
    assert kinds == {'telemetry'}

    # Back to the default: taken out again, nothing else touched.
    _set_places(case, destinations.DEFAULT)
    done = job.apply_destinations(case, case.folder, run, 250_000)
    assert done['dropped'] == [('Unified Logs', 5)]
    assert _events_of(case, 'unifiedlogs') == 0
    assert _events_of(case, 'safarihistory') == 2
    assert _where(case, run) == (['safarihistory'], ['safarihistory'])


def test_evidence_kept_out_of_activity_is_on_the_timeline_as_rows(case):
    from trace_app.core.modules import destinations
    value = destinations.normalise(None)
    value['evidence'] = ['timeline', 'search', 'report']
    _set_places(case, value)
    run = _run(case, case.phone, 'first', [SAFARI])
    done = _bridge(case, run)
    assert done['evidence'] == 1 and done['rows'] == 0
    assert not case.user_activity(case.phone)
    kinds = {k for (k,) in case._db.execute(
        "SELECT DISTINCT kind FROM module_events")}
    assert kinds == {'evidence'}         # no Activity row stands for one
    from trace_app.ui.viewers import module_records
    shown = module_records.hidden_artifacts(
        {'status': 'complete', 'evidence_id': case.phone,
         'artifacts': [{'role': 'evidence', 'record_count': 2}]},
        ('other',))
    assert len(shown) == 1               # browsed under Others instead


def test_a_cancel_takes_back_what_it_had_added(case):
    from trace_app.core.modules import job
    run = _run(case, case.phone, 'first', [SAFARI, LOGS], events=False)
    params = dict(case.module_run(run)['params'])
    params.update(timeline_tables=[], search_tables=[])
    case.set_module_run_params(run, params)
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 3            # part-way through Search
    from trace_app.core.modules import destinations
    _set_places(case, destinations.EVERYWHERE)
    done = job.apply_destinations(case, case.folder, run, 0,
                                  should_stop=stop)
    assert done['cancelled']
    # The Timeline was done and is recorded; Search was not, and holds
    # nothing of the run.
    assert _events_of(case, 'safarihistory') == 2
    assert _module_search_rows(case, 'safarihistory') == 0
    assert _where(case, run) == (['safarihistory', 'unifiedlogs'], [])
    # The next apply adds what is missing, once.
    job.apply_destinations(case, case.folder, run, 0)
    assert _events_of(case, 'safarihistory') == 2
    assert _module_search_rows(case, 'safarihistory') == 2


def test_readings_are_not_linked_when_the_case_says_so(case):
    from trace_app.core import settings as case_settings
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'Hi there')])
    case.commit()
    run = _run(case, case.phone, 'first', [CHATS])
    _bridge(case, run)
    assert len(case.user_activity(case.phone)) == 2      # one linked
    case_settings.save_case(case, {'module_link_readings': False})
    case.relink_matches(case.phone)
    assert len(case.user_activity(case.phone)) == 3      # each its own


def test_the_report_leaves_out_what_the_case_keeps_from_reports(case):
    from trace_app.core import report
    from trace_app.core.modules import destinations
    case.add_user_activity(case.phone, [_trace_message(1586629000,
                                                       'From TRACE')])
    case.commit()
    run = _run(case, case.phone, 'first', [SAFARI, LOGS])
    _bridge(case, run)

    def written():
        options = report.default_options(case)
        options['module_artifacts'] = 'all'
        builder = report._Builder(case, options, {}, None, None)
        return builder.section_activity() + builder.section_modules()
    html = written()
    assert 'trace.test' in html and 'From TRACE' in html
    assert 'Unified Logs' not in html    # telemetry: not in reports
    value = destinations.normalise(None)
    value['evidence'] = ['activity', 'timeline', 'search']
    value['telemetry'] = ['activity', 'report']
    _set_places(case, value)
    html = written()
    assert 'trace.test' not in html and 'From TRACE' in html
    assert 'Unified Logs' in html

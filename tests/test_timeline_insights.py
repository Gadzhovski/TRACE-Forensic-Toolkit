"""The Timeline's Insights (ui/viewers/timeline_insights.py): the weekday ×
hour heatmap, gaps, and the checks of core/timeline_anomalies -- plus the
clock changes event logs and the Linux journal now record.

A small generated case planted with one of each thing to find: events
after the image was taken, zero and future dates, a clock change, a
cleared log, a change journal going back in time, a timestomped file.
"""

import datetime
import os
import sqlite3

import pytest

from tests.conftest import pump


# --- clock changes become records -----------------------------------------------------

def _event(eid, data, provider='Microsoft-Windows-Security-Auditing',
           channel='Security'):
    return {'event_id': eid, 'data': data, 'provider': provider,
            'channel': channel, 'computer': 'PC'}


def test_a_clock_set_by_a_minute_or_more_is_recorded():
    from trace_app.core.activity.eventlogs import describe
    what, user, detail = describe(_event(4616, {
        'PreviousTime': '2024-05-01T10:00:00.0000000Z',
        'NewTime': '2024-04-28T09:30:00.0000000Z',
        'SubjectUserName': 'ann', 'SubjectDomainName': 'PC',
        'ProcessName': 'C:\\Windows\\System32\\SystemSettingsAdminFlows.exe'}))
    assert what == 'System time changed'
    assert detail['shift'] == '-3d 00:30:00'
    assert detail['from'].startswith('2024-05-01 10:00:00')
    # The time service's routine correction is not a change.
    assert describe(_event(4616, {
        'PreviousTime': '2024-05-01T10:00:00.0000000Z',
        'NewTime': '2024-05-01T10:00:02.5000000Z'})) is None
    what, _user, detail = describe(_event(
        1, {'OldTime': '2024-05-01T10:00:00Z',
            'NewTime': '2024-05-01T12:00:00Z'},
        provider='Microsoft-Windows-Kernel-General', channel='System'))
    assert what == 'System time changed' and detail['shift'] == '+02:00:00'


def test_the_linux_journal_records_the_clock_set():
    from trace_app.core.activity.linux import Describer
    describer = Describer('journal', '/var/log/journal/x', 'p0:i1:s1')
    when = datetime.datetime(2024, 5, 1, 10, 0, tzinfo=datetime.timezone.utc)
    describer.message(when, 'systemd', 'Time has been changed')
    describer.message(when, 'systemd-timedated',
                      'Changed local time to Wed 2024-05-01 08:00:00 UTC')
    describer.message(when, 'systemd', 'Started Session 2 of user ann.')
    assert [r['what'] for r in describer.out] == ['System time changed'] * 2


# --- when: the heatmap, and gaps ---------------------------------------------------------

def test_the_heatmap_counts_in_the_display_zone_across_summer_time():
    """2024-03-31, Sofia goes from +2 to +3 at 01:00 UTC: 00 UTC is 02:00
    local, 01 UTC is 04:00 local -- there is no 03:00 that day."""
    from trace_app.core import timeline
    hours = [('2024-03-31 00', 0, 5), ('2024-03-31 01', 0, 7),
             ('2024-03-30 22', 1, 3)]                # a zone-less row
    grid, cells = timeline.weekday_hours(hours, 'Europe/Sofia')
    assert grid[6][2] == 5 and grid[6][4] == 7 and grid[6][3] == 0
    assert grid[5][22] == 3                          # as written: Saturday
    assert cells[(6, 4)] == ['2024-03-31 01']
    utc, _cells = timeline.weekday_hours(hours)
    assert utc[6][0] == 5 and utc[6][1] == 7


def test_gaps_are_holes_inside_the_range():
    from trace_app.core import timeline
    hours = [(f'2024-05-{day:02d} 10', 0, 1) for day in (1, 2, 3, 8, 9)]
    found = timeline.gaps(hours, '2024-04-01 00:00:00', '2024-06-01 00:00:00')
    assert found == [('2024-05-03 11:00:00', '2024-05-08 10:00:00')]
    assert timeline.gap_threshold('2024-01-01', '2024-01-03') == \
        datetime.timedelta(hours=2)


# --- the checks ---------------------------------------------------------------------

@pytest.fixture(scope='module')
def planted(tmp_path_factory):
    from trace_app.core.case import Case
    root = tmp_path_factory.mktemp('insights')
    case = Case.create(str(root / 'case'), 'Insights')
    image = root / 'pc.dd'
    image.write_bytes(b'\0' * 512)
    evidence = case.add_evidence(str(image), details={
        'acquired_on': '2024-06-01 12:00:00'})
    fs = [('2024-05-20 10:00:00', 'p0:i10:s1', '/a'),
          ('2024-06-05 08:00:00', 'p0:i11:s1', '/after1'),   # after taken
          ('2024-06-06 08:00:00', 'p0:i12:s1', '/after2'),
          ('1970-01-01 00:00:00', 'p0:i13:s1', '/zero'),
          ('1975-03-03 03:03:03', 'p0:i14:s1', '/old'),
          ('2099-01-01 00:00:00', 'p0:i15:s1', '/future')]
    case._db.executemany(
        "INSERT INTO fs_events (evidence_id, artifact_ref, path, time_utc, "
        "macb, source) VALUES (?,?,?,?,'M','SI')",
        [(evidence, ref, path, when) for when, ref, path in fs])
    case._db.executemany(
        "INSERT INTO user_activity (evidence_id, category, what, time_utc, "
        "subject, detail, source) VALUES (?,?,?,?,?,'{}','Security.evtx')",
        [(evidence, 'system', 'System time changed', '2024-05-10 09:00:00',
          'ann'),
         (evidence, 'system', 'Security log cleared', '2024-05-11 09:00:00',
          'ann'),
         (evidence, 'system', 'Windows installed', '2024-01-01 00:00:00',
          'Windows 11'),
         (evidence, 'programs', 'Program run', '2023-12-01 00:00:00',
          'EVIL.EXE')])
    # The change journal: USN order, one record dated an hour back.
    case._db.executemany(
        "INSERT INTO usn_journal (evidence_id, usn, time_utc, artifact_ref, "
        "file_entry, file_sequence, parent_entry, parent_sequence, name, "
        "path, reasons, reason_flags) VALUES (?,?,?,'p0:i1:s1',1,1,5,5,"
        "'x','/x','DATA_EXTEND',2)",
        [(evidence, 100, '2024-05-20 10:00:00'),
         (evidence, 200, '2024-05-20 10:05:00'),
         (evidence, 300, '2024-05-20 09:00:00'),
         (evidence, 400, '2024-05-20 10:06:00')])
    case._db.execute(
        "INSERT INTO file_findings (evidence_id, artifact_ref, name, path, "
        "module, kind, grade, summary, detail, analysed_utc) VALUES "
        "(?, 'p0:i10:s1', 'a', '/a', 'ntfs', 'timestomp', 'suspicious', "
        "'set by hand', '{}', '2024')", (evidence,))
    case._db.commit()
    yield case, evidence
    case.close()


def test_every_planted_thing_is_found(planted):
    from trace_app.core import timeline, timeline_anomalies as ta
    case, evidence = planted
    connection = sqlite3.connect(
        f"file:{os.path.join(case.folder, 'case.db')}?mode=ro", uri=True)
    try:
        found = {f['key']: f for f in ta.analyse(
            connection, timeline.default_filters(),
            [dict(r) for r in case.evidence()])}
    finally:
        connection.close()
    assert found[f'after-acquisition:{evidence}']['count'] == 2
    assert found['epoch']['count'] == 1
    assert found['early']['count'] == 1
    assert found['future']['count'] == 1
    assert found['clock']['count'] == 1
    assert found['log-cleared']['count'] == 1
    assert found[f'before-install:{evidence}']['count'] == 1
    assert found['usn-rollback']['count'] == 1
    assert found['timestomp']['count'] == 1
    assert found['future']['grade'] == 'suspicious'
    assert ta.parse_acquired('Thu Jun  6 12:00:00 2024') == \
        datetime.datetime(2024, 6, 6, 12, 0)


def test_an_iso_acquisition_time_keeps_its_digits():
    # The 'T' is replaced by a space and the digits either side kept: the
    # replacement once held control bytes, and no ISO time ever parsed.
    from trace_app.core import timeline_anomalies as ta
    assert ta.parse_acquired('2026-10-17T12:30:05') == \
        datetime.datetime(2026, 10, 17, 12, 30, 5)
    assert ta.parse_acquired('2026-10-17T12:30:05Z') == \
        datetime.datetime(2026, 10, 17, 12, 30, 5)


def test_insights_in_the_panel_lead_to_the_events(qapp, planted):
    from trace_app.infra.window_state import save_value
    from trace_app.ui.viewers.timeline_panel import TimelinePanel
    case, evidence = planted
    save_value('Timeline', 'collapse', '0')
    panel = TimelinePanel()
    try:
        panel.resize(1400, 800)
        panel.set_case(case)
        panel.show()
        panel.whole_case()
        assert pump(qapp, 30, lambda: not panel.loading)
        panel.side.setCurrentWidget(panel.insights)
        insights = panel.insights
        assert pump(qapp, 30, lambda: not insights.loading and
                    insights.findings)
        assert 'Checks (' in insights.text.toPlainText()
        # A check: its events.
        finding = next(f for f in insights.findings
                       if f['key'].startswith('after-acquisition'))
        panel.apply_finding(finding)
        assert pump(qapp, 30, lambda: not panel.loading)
        assert {r['subject'] for r in panel.model.rows} == {'/after1',
                                                            '/after2'}
        # A heatmap cell: only that weekday's hour.
        panel.whole_case()
        assert pump(qapp, 30, lambda: not panel.loading)
        panel.side.setCurrentWidget(panel.insights)
        assert pump(qapp, 30, lambda: not insights.loading)
        moment = datetime.datetime(2024, 5, 20, 10)       # a Monday
        insights.heatmap.cell_clicked.emit(moment.weekday(), moment.hour)
        assert pump(qapp, 30, lambda: not panel.loading)
        assert panel.model.rows and all(
            r['time'].startswith('2024-05-20 10') for r in panel.model.rows)
        chips = [w.text() for w in panel.pivot_holder.findChildren(
            type(panel.back_button)) if w.isVisibleTo(panel)]
        assert any(t.startswith('Hours: Mon 10:00') for t in chips)
        panel._drop_hours()
        assert pump(qapp, 30, lambda: not panel.loading)
        assert 'hours' not in panel.filters['columns']
    finally:
        panel.shutdown()
        panel.deleteLater()

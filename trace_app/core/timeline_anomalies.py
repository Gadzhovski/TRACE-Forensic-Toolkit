"""What in a case's timeline cannot be right, or says the clock or the
records were tampered with.

Each finding is a dict: 'key', 'title', 'count', 'detail' (why it
matters), 'grade' ('suspicious' | 'notable' | 'info') and 'action' -- what
the Timeline does when the examiner clicks it: {'range': (from, to)},
{'filters': {...}} (merged into the tab's), {'columns': {...}} (column
filters), or {'jump': time}. None of them is proof by itself: a camera's
wrong clock and an antivirus's backdated files look the same as forgery;
the finding says what to look at.

Read-only, on the reader thread's own connection. No Qt.
"""

import datetime
import logging
import re

from trace_app.core import timeline

logger = logging.getLogger('TRACE.Timeline')

#: A change-journal time this much earlier than the latest before it (in
#: USN order) is the clock going back, not ordinary disorder.
ROLLBACK_SECONDS = 600
#: Events up to this long after acquisition are left alone: the acquired
#: date is often a day (local, rounded) rather than a moment.
AFTER_ACQUISITION_GRACE = datetime.timedelta(days=1)

_DATE_FORMATS = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%a %b %d %H:%M:%S %Y',
                 '%d/%m/%Y %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%Y:%m:%d %H:%M:%S',
                 '%d.%m.%Y %H:%M:%S', '%d.%m.%Y')


def parse_acquired(value):
    """An acquisition date as recorded (E01 header, imaging log, typed in),
    or None when it does not read as one."""
    # ISO's 'T' between date and time only: 'Thu Jun  6 ...' (an E01
    # header's form) keeps its T.
    text = ' '.join(re.sub(r'(\d)T(\d)', r'\1 \2',
                           str(value or '')).split())
    for size in (len(text), 19, 10):
        for fmt in _DATE_FORMATS:
            try:
                return datetime.datetime.strptime(text[:size], fmt)
            except ValueError:
                continue
    return None


def analyse(connection, filters, evidence):
    """Findings for the case under the tab's filters (its range ignored:
    an anomaly outside the view is still one). `evidence` is the case's
    evidence rows (id, display name / path, acquired_on)."""
    unbounded = dict(filters, start=None, end=None)
    found = []
    for check in (_implausible, _log_cleared, _clock_changes,
                  _after_acquisition, _before_install, _usn_rollback,
                  _timestomped):
        try:
            found.extend(check(connection, unbounded, evidence) or [])
        except Exception as exc:        # one check failing hides no other
            logger.warning("Timeline check %s failed: %s", check.__name__,
                           exc)
    order = {'suspicious': 0, 'notable': 1, 'info': 2}
    found.sort(key=lambda f: (order.get(f['grade'], 3), -f['count']))
    return found


def _count(connection, filters, where='1', params=()):
    sql, values = timeline._union(filters)
    if sql is None:
        return 0, None, None
    return connection.execute(
        f"SELECT COUNT(*), MIN(time), MAX(time) FROM ({sql}) WHERE {where}",
        list(values) + list(params)).fetchone()


def _name(row):
    return row.get('display_name') or (row.get('path') or '').replace(
        '\\', '/').rsplit('/', 1)[-1]


def _implausible(connection, filters, _evidence):
    found = []
    until = timeline.plausible_until()
    epoch, _first, _last = _count(
        connection, filters,
        "time LIKE '1601-01-01%' OR time LIKE '1970-01-01%' OR "
        "time LIKE '1980-01-01 00:00%'")
    if epoch:
        found.append({
            'key': 'epoch', 'grade': 'notable', 'count': epoch,
            'title': f"{epoch:,} event(s) at a zero date (1601, 1970, 1980)",
            'detail': "A time of zero in the format it was stored in: the "
                      "field was never set, was wiped, or a tool wrote "
                      "nothing. Not a moment anything happened.",
            'action': {'range': ('1601-01-01 00:00:00',
                                 '1980-01-02 00:00:00')}})
    early, first, _last = _count(
        connection, filters,
        "time < ? AND time NOT LIKE '1601-01-01%' AND "
        "time NOT LIKE '1970-01-01%' AND time NOT LIKE '1980-01-01 00:00%'",
        [timeline.PLAUSIBLE_FROM])
    if early:
        found.append({
            'key': 'early', 'grade': 'notable', 'count': early,
            'title': f"{early:,} event(s) before 1980",
            'detail': "Earlier than any of these systems: a clock set "
                      "wrong, or times set by hand.",
            'action': {'range': (first[:19], timeline.PLAUSIBLE_FROM)}})
    future, _first, last = _count(connection, filters, "time >= ?", [until])
    if future:
        found.append({
            'key': 'future', 'grade': 'suspicious', 'count': future,
            'title': f"{future:,} event(s) more than a year in the future",
            'detail': "Dated after today and next year: a clock set ahead, "
                      "or times forged.",
            'action': {'range': (until, timeline.text(
                timeline.parse(last) + datetime.timedelta(seconds=1)))}})
    return found


def _after_acquisition(connection, filters, evidence):
    """Events dated after their image was taken cannot have happened."""
    found = []
    verified = {row[0]: row[1] for row in connection.execute(
        "SELECT evidence_id, MIN(utc) FROM verifications GROUP BY "
        "evidence_id")}
    for row in evidence:
        taken = parse_acquired(row.get('acquired_on'))
        basis = "acquired"
        if taken is None and verified.get(row['id']):
            taken = parse_acquired(verified[row['id']])
            basis = "first verified"
        if taken is None:
            continue
        limit = taken + AFTER_ACQUISITION_GRACE
        scoped = dict(filters, evidence_id=row['id'],
                      sources=[s for s in (filters.get('sources') or ())
                               if s != 'case'])
        number, first, _last = _count(connection, scoped, "time >= ? AND "
                                      "time < ?", [timeline.text(limit),
                                                   timeline.plausible_until()])
        if number:
            found.append({
                'key': f"after-acquisition:{row['id']}", 'grade': 'suspicious',
                'count': number,
                'title': f"{number:,} event(s) on {_name(row)} after it was "
                         f"{basis} ({taken:%Y-%m-%d})",
                'detail': f"The image was {basis} on {taken:%Y-%m-%d %H:%M}"
                          f"; nothing on it can have happened later. The "
                          f"machine's clock was ahead, or the times were "
                          f"set by hand.",
                'action': {'filters': {'evidence_id': row['id']},
                           'range': (timeline.text(limit), timeline.text(
                               timeline.parse(_last or first) +
                               datetime.timedelta(seconds=1)))}})
    return found


def _activity(connection, filters, what):
    scoped = dict(filters, sources=['activity'])
    marks = ','.join('?' * len(what))
    return _count(connection, scoped, f"title IN ({marks})", what)


def _log_cleared(connection, filters, _evidence):
    names = ['Security log cleared', 'Event log cleared']
    number, first, _last = _activity(connection, filters, names)
    if not number:
        return []
    return [{'key': 'log-cleared', 'grade': 'suspicious', 'count': number,
             'title': f"Event log cleared {number:,} time(s)",
             'detail': "Someone emptied a Windows event log: what it held "
                       "before is gone, and clearing it is often what an "
                       "intruder does last.",
             'action': {'filters': {'sources': ['activity']},
                        'columns': {'title': 'log cleared'},
                        'jump': first}}]


def _clock_changes(connection, filters, _evidence):
    number, first, _last = _activity(connection, filters,
                                     ['System time changed'])
    if not number:
        return []
    return [{'key': 'clock', 'grade': 'suspicious', 'count': number,
             'title': f"System clock changed {number:,} time(s)",
             'detail': "The clock was set by a minute or more (Windows "
                       "event 4616 / Kernel-General 1, or the Linux "
                       "journal). Times recorded after it may be off by "
                       "the shift, and setting the clock back is how "
                       "times get forged.",
             'action': {'filters': {'sources': ['activity']},
                        'columns': {'title': 'System time changed'},
                        'jump': first}}]


def _before_install(connection, filters, evidence):
    """User activity before Windows was installed: the clock, or records
    carried over from another machine."""
    found = []
    for evidence_id, installed in connection.execute(
            "SELECT evidence_id, MIN(time_utc) FROM user_activity WHERE "
            "what = 'Windows installed' AND time_utc IS NOT NULL "
            "GROUP BY evidence_id"):
        if filters.get('evidence_id') not in (None, evidence_id):
            continue
        scoped = dict(filters, evidence_id=evidence_id, sources=['activity'])
        number, first, _last = _count(
            connection, scoped, "time < ? AND title != 'Windows installed' "
            "AND kind IN ('programs', 'logons', 'files', 'usb', 'web')",
            [installed[:19]])
        if number:
            names = {row['id']: _name(row) for row in evidence}
            found.append({
                'key': f"before-install:{evidence_id}", 'grade': 'notable',
                'count': number,
                'title': f"{number:,} user action(s) on "
                         f"{names.get(evidence_id, 'an image')} before "
                         f"Windows was installed ({installed[:10]})",
                'detail': "Programs run, logons or files opened before the "
                          "system existed: its clock was wrong then, or "
                          "the records came from an earlier installation "
                          "(Windows.old, an upgrade).",
                'action': {'filters': {'evidence_id': evidence_id,
                                       'sources': ['activity']},
                           'range': (first[:19], installed[:19])}})
    return found


def _usn_rollback(connection, filters, _evidence):
    """The change journal numbers its records in order: a later record
    dated well before an earlier one is the clock going back."""
    if 'usn' not in (filters.get('sources') or ()):
        return []
    query = "SELECT evidence_id, usn, time_utc FROM usn_journal"
    params = []
    if filters.get('evidence_id') is not None:
        query += " WHERE evidence_id = ?"
        params.append(filters['evidence_id'])
    query += " ORDER BY evidence_id, usn"
    count, example = 0, None
    current, latest = None, None
    for evidence_id, _usn, stamp in connection.execute(query, params):
        moment = timeline.parse(stamp)
        if moment is None:
            continue
        if evidence_id != current:
            current, latest = evidence_id, moment
            continue
        if moment < latest - datetime.timedelta(seconds=ROLLBACK_SECONDS):
            count += 1
            if example is None:
                example = (stamp, latest)
        elif moment > latest:
            latest = moment
    if not count:
        return []
    stamp, before = example
    return [{'key': 'usn-rollback', 'grade': 'suspicious', 'count': count,
             'title': f"Change journal goes back in time {count:,} time(s)",
             'detail': f"Records written later (higher USN) are dated more "
                       f"than {ROLLBACK_SECONDS // 60} minutes before ones "
                       f"written earlier -- first at {stamp[:19]}, after "
                       f"{before:%Y-%m-%d %H:%M:%S}. The clock was set "
                       f"back while the volume was in use.",
             'action': {'filters': {'sources': ['usn']}, 'jump': stamp}}]


def _timestomped(connection, filters, _evidence):
    query = ("SELECT COUNT(*) FROM file_findings WHERE module = 'ntfs' AND "
             "kind = 'timestomp' AND grade != 'benign'")
    params = []
    if filters.get('evidence_id') is not None:
        query += " AND evidence_id = ?"
        params.append(filters['evidence_id'])
    number = connection.execute(query, params).fetchone()[0]
    if not number:
        return []
    return [{'key': 'timestomp', 'grade': 'notable', 'count': number,
             'title': f"{number:,} file(s) with times that look set by hand",
             'detail': "$STANDARD_INFORMATION earlier than $FILE_NAME, or "
                       "whole seconds where the file system keeps "
                       "fractions (Triage ▸ NTFS says why for each).",
             'action': {'filters': {'timestomped_only': True}}}]

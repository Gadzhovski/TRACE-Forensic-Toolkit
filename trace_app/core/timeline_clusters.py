"""Bursts in a timeline, collapsed: thousands of events of one kind in one
moment read as one row.

A package install writes the times of thousands of files in a minute; an
antivirus scan reads every file; a copy stamps a folder tree. Listed one by
one they bury the dozen events that matter. Here, events of the same source,
type and image inside the same time window (a whole minute, say) are one
*burst* when there are at least `minimum` of them -- "2,140 × Modified
($SI) in /usr/share/doc and 37 more folders, 10:04:12–10:04:58". Fewer stay
as they are, in time order. The examiner expands a burst to see its events
(`burst_filters` selects exactly them).

One pass over the rows in time order, a window at a time: on the examiner's
Fedora case 521,087 events became 5,177 rows (345 bursts) in 2.3 s. No Qt.
"""

import logging

from trace_app.core import timeline

logger = logging.getLogger('TRACE.Timeline')

#: Window choices: (key, label, time-text prefix length). The window is a
#: prefix of the time text, so it is a whole calendar unit, not a gap.
WINDOWS = (('10s', '10 seconds', 18), ('minute', '1 minute', 16),
           ('10min', '10 minutes', 15), ('hour', '1 hour', 13))
WINDOW_PREFIX = {key: length for key, _label, length in WINDOWS}
DEFAULT_WINDOW = 'minute'
#: Fewer events than this in a window stay as single rows.
MINIMUM = 20
#: Folders named on a burst's row.
FOLDERS_NAMED = 3
#: More rows than this after collapsing (a range with no bursts at all)
#: and the result is not kept: the table pages through the events instead.
MOST_ITEMS = 200_000


class Cancelled(Exception):
    pass


def folder_of(subject):
    """A path's folder ('/usr/share/doc' for '/usr/share/doc/x'), or ''."""
    subject = subject or ''
    cut = max(subject.rfind('/'), subject.rfind('\\'))
    return subject[:cut] if cut > 0 else ''


def collapse(connection, filters, window=DEFAULT_WINDOW, minimum=MINIMUM,
             most=MOST_ITEMS, should_stop=None):
    """(items, complete): rows and bursts in time order, or (None, False)
    when there would be more than `most` of them.

    A burst is a dict with the timeline's row keys (time = its first
    event's, row_key 'burst:' + its first's) plus 'burst': True, 'count',
    'last', 'window' (the time prefix), 'folders' [(folder, events)] most
    first, 'deleted' (how many), 'macb' letters seen and 'users'."""
    width = WINDOW_PREFIX.get(window, WINDOW_PREFIX[DEFAULT_WINDOW])
    items = []
    bucket, rows, counts = None, [], {}
    seen = 0

    def flush():
        bursts = {}
        for row in rows:
            key = (row['source'], row['kind'], row['evidence_id'])
            if counts[key] < minimum:
                items.append(row)
                continue
            burst = bursts.get(key)
            if burst is None:
                burst = bursts[key] = _new_burst(row, counts[key], bucket)
                items.append(burst)
            _add(burst, row)

    for row in timeline.iter_events(connection, filters):
        seen += 1
        if should_stop is not None and seen % 20000 == 0 and should_stop():
            raise Cancelled()
        prefix = (row['time'] or '')[:width]
        if prefix != bucket:
            if rows:
                flush()
                if len(items) > most:
                    return None, False
            bucket, rows, counts = prefix, [], {}
        rows.append(row)
        key = (row['source'], row['kind'], row['evidence_id'])
        counts[key] = counts.get(key, 0) + 1
    if rows:
        flush()
    for item in items:
        if item.get('burst'):
            _finish(item)
    return items, len(items) <= most


def _new_burst(row, count, bucket):
    burst = {key: row.get(key) for key in timeline.COLUMNS}
    burst.update({'burst': True, 'count': count, 'last': row['time'],
                  'window': bucket, 'row_key': 'burst:' + row['row_key'],
                  'artifact_ref': None, 'extra': None, 'title': None,
                  'subject': None, 'user': None, 'deleted': 0,
                  '_folders': {}, '_users': set(), '_names': []})
    return burst


def _add(burst, row):
    burst['last'] = row['time']
    if row['deleted']:
        burst['deleted'] += 1
    folder = folder_of(row['subject'])
    burst['_folders'][folder] = burst['_folders'].get(folder, 0) + 1
    if row['user']:
        burst['_users'].add(row['user'])
    if len(burst['_names']) < 5:
        name = row['title'] or (row['subject'] or '').replace(
            '\\', '/').rsplit('/', 1)[-1]
        if name and name not in burst['_names']:
            burst['_names'].append(name)


def _finish(burst):
    folders = sorted(burst.pop('_folders').items(),
                     key=lambda pair: (-pair[1], pair[0]))
    burst['folders'] = folders
    burst['folder_count'] = len(folders)
    users = sorted(burst.pop('_users'))
    burst['users'] = users
    burst['user'] = users[0] if len(users) == 1 else None
    burst['names'] = burst.pop('_names')
    named = [f for f, _n in folders[:FOLDERS_NAMED] if f]
    more = len(folders) - len(named)
    if named:
        burst['subject'] = ', '.join(named) + (
            f" and {more:,} more folder{'s' if more != 1 else ''}"
            if more > 0 else '')
    burst['title'] = describe(burst)


def describe(burst):
    """'2,140 × Modified ($SI)' -- the Description of a burst's row."""
    kind = timeline.describe_kind(burst)
    return f"{burst['count']:,} × {kind}"


def burst_filters(filters, burst):
    """The filters selecting exactly a burst's events."""
    columns = dict(filters.get('columns') or {})
    columns['burst'] = {'source': burst['source'], 'kind': burst['kind'],
                        'evidence_id': burst['evidence_id'],
                        'window': burst['window']}
    return dict(filters, columns=columns)

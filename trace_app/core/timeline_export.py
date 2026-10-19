"""The timeline written for other tools: Timesketch JSONL, plaso's l2t CSV
and The Sleuth Kit's mactime bodyfile -- beside TRACE's own CSV
(timeline.write_csv).

Every format reads the same rows as the Timeline tab and its CSV,
`timeline.iter_events` with the tab's filters, so what is exported is what
the examiner selected. Times are never shifted: a row whose time has no
zone (FAT, EXIF, a local-time document) is written as the digits it holds
and labelled local wherever the format has room for it -- Timesketch's
`datetime` without an offset and a `time_zone` field, l2t CSV's timezone
column, and in a bodyfile (which has only epoch seconds) a "(local time,
no zone)" after the name. No Qt.
"""

import calendar
import csv
import datetime
import json
import logging
import re

from trace_app.core import timeline

logger = logging.getLogger('TRACE.TimelineExport')

#: key -> (label, file extension, dialog filter).
FORMATS = {
    'csv': ("TRACE CSV", '.csv', "CSV (*.csv)"),
    'jsonl': ("Timesketch JSONL", '.jsonl', "Timesketch JSONL (*.jsonl)"),
    'l2tcsv': ("plaso l2t CSV", '.csv', "l2t CSV (*.csv)"),
    'bodyfile': ("mactime bodyfile (file-system times)", '.body',
                 "Bodyfile (*.body *.txt)"),
}

#: What each TRACE source is called in l2t CSV's 'source' column (plaso's
#: short source names where one fits).
L2T_SOURCES = {'fs': 'FILE', 'usn': 'FILE', 'activity': 'LOG',
               'photo': 'EXIF', 'document': 'META', 'carved': 'FILE',
               'sigma': 'EVT', 'modules': 'LEAPP', 'case': 'TRACE'}

L2T_HEADER = ('date', 'time', 'timezone', 'MACB', 'source', 'sourcetype',
              'type', 'user', 'host', 'short', 'desc', 'version', 'filename',
              'inode', 'notes', 'format', 'extra')

_REF_INODE = re.compile(r'(?:^|:)i(\d+)(?::s(\d+))?')


def write(fmt, connection, filters, path, evidence_names, should_stop=None):
    """Write the selected rows in `fmt` (a FORMATS key). Returns the
    number of rows (bodyfile: files) written."""
    if fmt == 'csv':
        return timeline.write_csv(connection, filters, path, evidence_names,
                                  should_stop)
    writer = {'jsonl': write_jsonl, 'l2tcsv': write_l2tcsv,
              'bodyfile': write_bodyfile}.get(fmt)
    if writer is None:
        raise ValueError(f"unknown timeline format {fmt!r}")
    return writer(connection, filters, path, evidence_names, should_stop)


# --- shared ----------------------------------------------------------------------

def _moment(text):
    """'YYYY-MM-DD HH:MM:SS[.fffffff]' -> (datetime to the microsecond,
    the seven-digit fraction text) or (None, '')."""
    if not text:
        return None, ''
    base, _, fraction = str(text).partition('.')
    try:
        moment = datetime.datetime.strptime(base[:19], '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None, ''
    digits = ''.join(c for c in fraction if c.isdigit())
    if digits:
        moment = moment.replace(microsecond=int(digits[:6].ljust(6, '0')))
    return moment, digits


def _epoch_seconds(moment):
    return calendar.timegm(moment.timetuple())


def _inode(ref):
    match = _REF_INODE.search(ref or '')
    if not match:
        return ''
    inode, sequence = match.groups()
    return f"{inode}-{sequence}" if sequence else inode


def _detail(extra):
    if not extra:
        return {}
    try:
        value = json.loads(extra)
    except (TypeError, ValueError):
        return {'detail': str(extra)}
    return value if isinstance(value, dict) else {'detail': value}


def _message(row):
    parts = [row['title'] or '', row['subject'] or '']
    text = ' -- '.join(p for p in parts if p)
    return text or timeline.describe_kind(row) or row['source']


def _rows(connection, filters, should_stop):
    for number, row in enumerate(timeline.iter_events(connection, filters)):
        if should_stop and number % 5000 == 0 and should_stop():
            return
        yield row


# --- Timesketch JSONL ----------------------------------------------------------------

def jsonl_event(row, evidence_names):
    """One Timesketch event: `message`, `datetime`, `timestamp` (µs) and
    `timestamp_desc` are what Timesketch requires; the rest are fields."""
    moment, _digits = _moment(row['time'])
    local = bool(row['local'])
    event = {
        'message': timeline._cell(_message(row)),
        'datetime': (moment.isoformat() if local else
                     moment.replace(tzinfo=datetime.timezone.utc).isoformat())
        if moment else row['time'],
        'timestamp': (_epoch_seconds(moment) * 1_000_000 + moment.microsecond)
        if moment else None,
        'timestamp_desc': timeline.describe_kind(row) or row['source'],
        'time_zone': 'local, no zone' if local else 'UTC',
        'data_type': f"trace:{row['source']}",
        'source_label': timeline.SOURCE_LABELS.get(row['source'],
                                                   row['source']),
        'evidence': evidence_names.get(row['evidence_id'], '')
        if row['evidence_id'] is not None else '',
        'path': row['subject'] or '',
        'user': row['user'] or '',
        'artifact_ref': row['artifact_ref'] or '',
        'deleted': bool(row['deleted']),
    }
    if row['time'] and '.' in str(row['time']):
        event['time_text'] = row['time']          # the 100 ns digits
    for key, value in _detail(row['extra']).items():
        event.setdefault(f"detail_{key}", value)
    return event


def write_jsonl(connection, filters, path, evidence_names, should_stop=None):
    written = 0
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        for row in _rows(connection, filters, should_stop):
            handle.write(json.dumps(jsonl_event(row, evidence_names),
                                    ensure_ascii=False, default=str) + '\n')
            written += 1
    return written


# --- plaso l2t CSV ---------------------------------------------------------------------

def _macb(row):
    """l2t CSV's four-character MACB ('M..B') for a file-system time."""
    if row['source'] != 'fs':
        return '....'
    letters = (row['kind'] or '').split(' ', 1)[0]
    return ''.join(c if c in letters else '.' for c in 'MACB')


def l2t_row(row, evidence_names):
    moment, _digits = _moment(row['time'])
    detail = _detail(row['extra'])
    description = _message(row)
    evidence = evidence_names.get(row['evidence_id'], '') \
        if row['evidence_id'] is not None else ''
    extra = '; '.join(f"{k}: {v}" for k, v in detail.items()
                      if v not in (None, '', {}, []))
    extra = '; '.join(p for p in (
        f"evidence: {evidence}" if evidence else '',
        f"artifact_ref: {row['artifact_ref']}" if row['artifact_ref'] else '',
        'deleted: yes' if row['deleted'] else '', extra) if p)
    return tuple(timeline._cell(value) for value in (
        moment.strftime('%m/%d/%Y') if moment else '',
        moment.strftime('%H:%M:%S') if moment else '',
        'local' if row['local'] else 'UTC',
        _macb(row),
        L2T_SOURCES.get(row['source'], row['source'].upper()),
        timeline.SOURCE_LABELS.get(row['source'], row['source']),
        timeline.describe_kind(row) or '-',
        row['user'] or '-',
        evidence or '-',
        description[:80],
        description,
        '2',
        row['subject'] or '-',
        _inode(row['artifact_ref']) or '-',
        '-',
        'trace',
        extra or '-'))


def write_l2tcsv(connection, filters, path, evidence_names,
                 should_stop=None):
    written = 0
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(L2T_HEADER)
        for row in _rows(connection, filters, should_stop):
            writer.writerow(l2t_row(row, evidence_names))
            written += 1
    return written


# --- mactime bodyfile ----------------------------------------------------------------------

#: MACB letter -> the bodyfile's time column (atime|mtime|ctime|crtime).
_BODY_COLUMNS = {'A': 0, 'M': 1, 'C': 2, 'B': 3}


def write_bodyfile(connection, filters, path, evidence_names,
                   should_stop=None):
    """TSK 3.x bodyfile, one line per file and time set:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime.
    Only file-system times have a place in it; NTFS's $SI and $FN (and
    index slack) become lines of their own, the name saying which, as
    analyzeMFT and plaso write them. Size and MD5 come from the analysis
    where it ran (else 0). Returns the number of lines."""
    wanted = dict(filters)
    wanted['sources'] = ['fs']
    files = {}            # (evidence, ref, path, attribute) -> [a, m, c, b]
    order = []
    local_keys = set()
    deleted_keys = set()
    for row in _rows(connection, wanted, should_stop):
        moment, _digits = _moment(row['time'])
        if moment is None:
            continue
        letters, _, attribute = (row['kind'] or '').partition(' ')
        key = (row['evidence_id'], row['artifact_ref'], row['subject'] or '',
               attribute)
        times = files.get(key)
        if times is None:
            times = files[key] = [0, 0, 0, 0]
            order.append(key)
        for letter in letters:
            column = _BODY_COLUMNS.get(letter)
            if column is not None:
                times[column] = _epoch_seconds(moment)
        if row['local']:
            local_keys.add(key)
        if row['deleted']:
            deleted_keys.add(key)
    sizes = _file_facts(connection, {(k[0], k[1]) for k in order})
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        for key in order:
            evidence_id, ref, name, attribute = key
            size, md5 = sizes.get((evidence_id, ref), (0, None))
            label = name
            if attribute and attribute not in ('FS', 'FS-local'):
                label += f" (${attribute})" if attribute in ('SI', 'FN') \
                    else f" ({attribute})"
            if key in deleted_keys:
                label += ' (deleted)'
            if key in local_keys:
                label += ' (local time, no zone)'
            if len(evidence_names) > 1 and evidence_id is not None:
                label = f"{evidence_names.get(evidence_id, '')}:{label}"
            atime, mtime, ctime, crtime = files[key]
            fields = (md5 or '0', label.replace('|', '\\|'),
                      _inode(ref) or '0', '', '0', '0', str(size or 0),
                      str(atime), str(mtime), str(ctime), str(crtime))
            handle.write(timeline._cell('|'.join(fields)) + '\n')
    return len(order)


def _file_facts(connection, keys):
    """{(evidence id, ref): (size, md5)} from the file analysis."""
    facts = {}
    evidence_ids = {evidence for evidence, _ref in keys}
    for evidence_id in evidence_ids:
        try:
            cursor = connection.execute(
                "SELECT artifact_ref, size, md5 FROM file_analysis "
                "WHERE evidence_id = ?", (evidence_id,))
        except Exception:
            return facts            # no analysis table (an old case)
        for ref, size, md5 in cursor:
            if (evidence_id, ref) in keys:
                facts[(evidence_id, ref)] = (size, md5)
    return facts

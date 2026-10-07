"""One timeline of everything the case knows happened, and when.

Sources, each a table some module filled:

* ``fs``       -- $MFT times: $STANDARD_INFORMATION and $FILE_NAME, MACB
                  (core/ntfs, ``fs_events``)
* ``usn``      -- the change journal (``usn_journal``)
* ``activity`` -- programs run, files opened, USB, logons, web history...
                  (core/activity, ``user_activity``)
* ``photo``    -- when a photo was taken, from its EXIF (``file_findings``)
* ``document`` -- when a document was created and last saved, from its own
                  metadata (``file_findings``)
* ``carved``   -- dates found inside carved files (``carved_files``)
* ``case``     -- the examination itself: audit trail, verification,
                  bookmarks and notes

Nothing is copied: each query is one UNION ALL over the source tables, every
filter pushed into each branch so their time indexes serve it. Times are
text that sorts -- 'YYYY-MM-DD HH:MM:SS[.fffffff]' -- and a source whose
time has no zone (EXIF, a local-time document, a carved file's own date)
says so in ``local`` rather than pretending to be UTC.

A query is described by a plain dict of filters (``Filters``) so the tab, the
CSV export and the report all ask the same question the same way. No Qt.
"""

import csv
import datetime
import json
import logging

logger = logging.getLogger('TRACE.Timeline')

#: (key, label, colour) in the order the tab shows them. The colours read on
#: both themes and are used for the histogram, the table and the report.
SOURCES = (
    ('fs', 'File system', '#4C8BF5'),
    ('usn', 'Change journal', '#17A2B8'),
    ('activity', 'User activity', '#9B6CF0'),
    ('photo', 'Photos', '#E3A008'),
    ('document', 'Documents', '#E8743B'),
    ('carved', 'Carved files', '#3FB950'),
    ('sigma', 'Sigma detections', '#E5534B'),
    ('case', 'Case events', '#8A939E'),
)
SOURCE_LABELS = {key: label for key, label, _colour in SOURCES}
SOURCE_COLOURS = {key: colour for key, _label, colour in SOURCES}

#: What the columns of a row are.
COLUMNS = ('time', 'local', 'source', 'kind', 'evidence_id', 'title',
           'subject', 'user', 'artifact_ref', 'deleted', 'extra')

#: Dates outside this are kept, but not where the view opens: one
#: timestomped 1601 would otherwise squash a whole case into one bar.
PLAUSIBLE_FROM = '1980-01-01 00:00:00'

#: Histogram units, finest first: (name, text prefix length).
UNITS = (('second', 19), ('minute', 16), ('hour', 13), ('day', 10),
         ('month', 7), ('year', 4))

MACB_WORDS = {'M': 'Modified', 'A': 'Accessed', 'C': 'Changed',
              'B': 'Created'}


def plausible_until():
    """A year past today: later than that is a misread or a forgery."""
    later = datetime.datetime.now(datetime.timezone.utc) + \
        datetime.timedelta(days=366)
    return later.strftime('%Y-%m-%d %H:%M:%S')


def default_filters():
    return {
        'start': None, 'end': None,             # text, end exclusive
        'sources': [key for key, _l, _c in SOURCES if key != 'case'],
        'evidence_id': None,
        'text': '',
        'deleted_only': False,
        'hide_known_good': False,
        'timestomped_only': False,
        'focus_ref': None,                       # (evidence_id, ref)
        'user': None,
        'folder': None,
        'fs_attributes': 'both',                 # both | SI | FN
    }


def describe_kind(row):
    """What the Type column says for a row."""
    source, kind = row['source'], row['kind'] or ''
    if source == 'fs':
        letters, _, attribute = kind.partition(' ')
        words = [MACB_WORDS[c] for c in letters if c in MACB_WORDS]
        return f"{', '.join(words)} ({'$SI' if attribute == 'SI' else '$FN'})"
    return kind


# --- the query -------------------------------------------------------------------

def _branches(filters):
    """[(sql, params)] -- one SELECT per wanted source, filters applied."""
    wanted = set(filters.get('sources') or ())
    start, end = filters.get('start'), filters.get('end')
    evidence_id = filters.get('evidence_id')
    text = (filters.get('text') or '').strip()
    deleted_only = filters.get('deleted_only')
    stomped_only = filters.get('timestomped_only')
    focus = filters.get('focus_ref')
    user = filters.get('user')
    folder = filters.get('folder')
    hide_good = filters.get('hide_known_good')
    out = []

    def common(alias, time_sql, evidence_sql, ref_sql=None, path_sql=None,
               text_sql=(), user_sql=None, hideable=True):
        """WHERE clauses and params shared by every branch. `hideable` is
        False where the reference is not the file the event is about (an
        activity record's is the artifact it was read from)."""
        clauses, params = [f"{time_sql} IS NOT NULL", f"{time_sql} != ''"], []
        if start:
            clauses.append(f"{time_sql} >= ?")
            params.append(start)
        if end:
            clauses.append(f"{time_sql} < ?")
            params.append(end)
        if evidence_id is not None:
            clauses.append(f"{evidence_sql} = ?")
            params.append(evidence_id)
        if focus:
            if ref_sql is None:
                return None
            clauses.append(f"{evidence_sql} = ? AND {ref_sql} = ?")
            params.extend(focus)
        if user:
            if user_sql is None:
                return None
            clauses.append(f"{user_sql} = ?")
            params.append(user)
        if folder:
            if path_sql is None:
                return None
            clauses.append(f"({path_sql} LIKE ? OR {path_sql} = ?)")
            params.extend([folder.rstrip('/') + '/%', folder])
        if text:
            if text_sql:
                clauses.append('(' + ' OR '.join(
                    f"{column} LIKE ?" for column in text_sql) + ')')
                params.extend([f'%{text}%'] * len(text_sql))
        if hide_good and ref_sql is not None and hideable:
            clauses.append(
                "NOT EXISTS (SELECT 1 FROM hash_matches h WHERE "
                f"h.evidence_id = {evidence_sql} AND h.artifact_ref = "
                f"{ref_sql} AND h.category = 'known-good')")
        if stomped_only:
            if ref_sql is None:
                return None
            clauses.append(
                f"{ref_sql} IN (SELECT artifact_ref FROM file_findings f "
                f"WHERE f.evidence_id = {evidence_sql} AND f.module = 'ntfs' "
                f"AND f.kind = 'timestomp' AND f.grade != 'benign')")
        return ' AND '.join(clauses), params

    if 'fs' in wanted:
        where = common('e', 'e.time_utc', 'e.evidence_id', 'e.artifact_ref',
                       'e.path', ('e.path',))
        if where is not None:
            sql, params = where
            attribute = filters.get('fs_attributes') or 'both'
            if attribute in ('SI', 'FN'):
                sql += " AND e.source = ?"
                params.append(attribute)
            if deleted_only:
                sql += " AND e.deleted = 1"
            out.append((
                "SELECT e.time_utc, 0, 'fs', e.macb || ' ' || e.source, "
                "e.evidence_id, NULL, e.path, NULL, e.artifact_ref, "
                f"e.deleted, NULL FROM fs_events e WHERE {sql}", params))

    if 'usn' in wanted:
        where = common('u', 'u.time_utc', 'u.evidence_id', 'u.artifact_ref',
                       'u.path', ('u.path', 'u.reasons'))
        if where is not None:
            sql, params = where
            if deleted_only:
                sql += " AND (u.reason_flags & 512) != 0"
            out.append((
                "SELECT u.time_utc, 0, 'usn', u.reasons, u.evidence_id, "
                "u.name, u.path, NULL, u.artifact_ref, "
                "(u.reason_flags & 512) != 0, "
                "json_object('usn', u.usn, 'entry', u.file_entry, "
                "'sequence', u.file_sequence, 'parent', u.parent_entry, "
                "'flags', u.reason_flags) "
                f"FROM usn_journal u WHERE {sql}", params))

    if 'activity' in wanted and not deleted_only:
        where = common('a', 'a.time_utc', 'a.evidence_id', 'a.source_ref',
                       None, ('a.what', 'a.subject', 'a.user', 'a.detail',
                              'a.source'), 'a.user', hideable=False)
        if where is not None and not stomped_only:
            sql, params = where
            out.append((
                "SELECT a.time_utc, a.time_local, 'activity', a.category, "
                "a.evidence_id, a.what, a.subject, a.user, a.source_ref, 0, "
                "json_object('detail', json(a.detail), 'source', a.source, "
                "'source_path', a.source_path) "
                f"FROM user_activity a WHERE {sql}", params))

    if 'photo' in wanted and not deleted_only and not stomped_only:
        taken = ("replace(substr(json_extract(p.detail, '$.taken'), 1, 10), "
                 "':', '-') || substr(json_extract(p.detail, '$.taken'), 11, "
                 "9)")
        where = common('p', taken, 'p.evidence_id', 'p.artifact_ref',
                       'p.path', ('p.path', 'p.summary'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {taken}, 1, 'photo', 'Photo taken', p.evidence_id, "
                "p.name, p.path, NULL, p.artifact_ref, 0, p.detail "
                "FROM file_findings p WHERE p.module = 'photo' AND "
                f"json_extract(p.detail, '$.taken') IS NOT NULL AND {sql}",
                params))

    if 'document' in wanted and not deleted_only and not stomped_only:
        for field, label, person in (('created', 'Document created',
                                      'author'),
                                     ('modified', 'Document last saved',
                                      'last_saved_by')):
            raw = f"json_extract(d.detail, '$.{field}')"
            moment = _normalised(raw)
            local = (f"CASE WHEN {raw} LIKE '% UTC' OR {raw} GLOB "
                     f"'* [+-][0-9][0-9]:[0-9][0-9]' THEN 0 ELSE 1 END")
            who = f"json_extract(d.detail, '$.{person}')"
            where = common('d', moment, 'd.evidence_id', 'd.artifact_ref',
                           'd.path', ('d.path', 'd.summary', who), who)
            if where is not None:
                sql, params = where
                out.append((
                    f"SELECT {moment}, {local}, 'document', '{label}', "
                    f"d.evidence_id, d.name, d.path, {who}, d.artifact_ref, "
                    "0, d.detail FROM file_findings d WHERE "
                    f"d.module = 'authors' AND {raw} IS NOT NULL AND {sql}",
                    params))

    if 'sigma' in wanted and not deleted_only and not stomped_only:
        moment = "substr(json_extract(g.detail, '$.time'), 1, 26)"
        rule = "json_extract(g.detail, '$.rule')"
        where = common('g', moment, 'g.evidence_id', 'g.artifact_ref',
                       'g.path', ('g.path', 'g.summary', rule))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {moment}, 0, 'sigma', "
                "'Sigma: ' || json_extract(g.detail, '$.level'), "
                f"g.evidence_id, {rule}, g.path, NULL, g.artifact_ref, 0, "
                "g.detail FROM file_findings g WHERE g.module = 'sigma' AND "
                f"json_extract(g.detail, '$.time') != '' AND {sql}", params))

    if 'carved' in wanted and not deleted_only and not stomped_only:
        where = common('c', 'c.embedded_date', 'c.evidence_id',
                       'c.artifact_ref', None, ('c.name', 'c.type'))
        if where is not None:
            sql, params = where
            out.append((
                "SELECT c.embedded_date, 1, 'carved', "
                "'Date inside carved file' || CASE WHEN c.date_source != '' "
                "THEN ' (' || c.date_source || ')' ELSE '' END, "
                "c.evidence_id, c.name, 'carved at byte ' || c.offset, NULL, "
                "c.artifact_ref, 0, json_object('offset', c.offset, 'size', "
                "c.size, 'type', c.type) FROM carved_files c "
                f"WHERE c.embedded_date != 'Unknown' AND {sql}", params))

    if 'case' in wanted and not deleted_only and not stomped_only \
            and not focus and not user and not folder:
        audit_time = "replace(substr(x.utc, 1, 19), 'T', ' ')"
        where = common('x', audit_time, 'NULL', None, None,
                       ('x.action', 'x.detail'))
        if where is not None and evidence_id is None:
            sql, params = where
            out.append((
                f"SELECT {audit_time}, 0, 'case', 'Audit', NULL, x.action, "
                f"x.detail, NULL, NULL, 0, NULL FROM activity x WHERE {sql}",
                params))
        verified = "replace(substr(v.utc, 1, 19), 'T', ' ')"
        where = common('v', verified, 'v.evidence_id', None, None,
                       ('v.status', 'v.algorithm'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {verified}, 0, 'case', 'Verification', "
                "v.evidence_id, 'Verified: ' || v.status, v.algorithm, NULL, "
                "NULL, 0, NULL FROM verifications v WHERE " + sql, params))
        marked = "replace(substr(b.created_utc, 1, 19), 'T', ' ')"
        where = common('b', marked, 'b.evidence_id', 'b.artifact_ref',
                       None, ('b.artifact_name', 'b.label'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {marked}, 0, 'case', 'Bookmarked', b.evidence_id, "
                "b.artifact_name, b.artifact_path, NULL, b.artifact_ref, 0, "
                "NULL FROM bookmarks b WHERE " + sql, params))
        noted = "replace(substr(n.created_utc, 1, 19), 'T', ' ')"
        where = common('n', noted, 'n.evidence_id', 'n.artifact_ref', None,
                       ('n.body', 'n.artifact_name'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {noted}, 0, 'case', 'Note', n.evidence_id, "
                "n.artifact_name, substr(n.body, 1, 200), NULL, "
                "n.artifact_ref, 0, NULL FROM notes n WHERE " + sql, params))
    return out


def _normalised(raw):
    """SQL turning '2023-02-19 10:29:00 UTC' / '... +01:00' / '...' into
    'YYYY-MM-DD HH:MM:SS' (UTC where a zone was stated)."""
    return (f"CASE WHEN {raw} LIKE '% UTC' THEN substr({raw}, 1, 19) "
            f"WHEN {raw} GLOB '* [+-][0-9][0-9]:[0-9][0-9]' THEN "
            f"datetime(substr({raw}, 1, 19) || substr({raw}, 21)) "
            f"ELSE substr({raw}, 1, 19) END")


#: A compound SELECT takes its column names from its first SELECT: this
#: one names them and returns nothing.
_NAMES = ("SELECT NULL AS time, NULL AS local, NULL AS source, NULL AS kind, "
          "NULL AS evidence_id, NULL AS title, NULL AS subject, NULL AS user, "
          "NULL AS artifact_ref, NULL AS deleted, NULL AS extra WHERE 0")


def _union(filters):
    branches = _branches(filters)
    if not branches:
        return None, []
    sql = _NAMES + ''.join(f" UNION ALL SELECT * FROM ({part})"
                           for part, _params in branches)
    params = [value for _part, values in branches for value in values]
    return sql, params


def events(connection, filters, limit=None, offset=0, descending=False):
    """Rows as dicts, in time order."""
    sql, params = _union(filters)
    if sql is None:
        return []
    query = (f"SELECT * FROM ({sql}) ORDER BY time "
             f"{'DESC' if descending else 'ASC'}")
    if limit:
        query += f" LIMIT {int(limit)} OFFSET {int(offset)}"
    return [dict(zip(COLUMNS, row)) for row in connection.execute(query,
                                                                  params)]


def iter_events(connection, filters):
    """Every matching row, in time order, without holding them all."""
    sql, params = _union(filters)
    if sql is None:
        return
    for row in connection.execute(f"SELECT * FROM ({sql}) ORDER BY time",
                                  params):
        yield dict(zip(COLUMNS, row))


def count(connection, filters):
    sql, params = _union(filters)
    if sql is None:
        return 0
    return connection.execute(f"SELECT COUNT(*) FROM ({sql})",
                              params).fetchone()[0]


def source_counts(connection, filters):
    """{source: rows} for the filters, every source asked about."""
    asked = dict(filters, sources=[key for key, _l, _c in SOURCES])
    sql, params = _union(asked)
    if sql is None:
        return {}
    return {row[0]: row[1] for row in connection.execute(
        f"SELECT source, COUNT(*) FROM ({sql}) GROUP BY source", params)}


def bounds(connection, filters):
    """(first, last) time among the plausible dates, and how many rows fall
    outside them -- for opening the view where the events are."""
    unbounded = dict(filters, start=None, end=None)
    sql, params = _union(unbounded)
    if sql is None:
        return None, None, 0
    until = plausible_until()
    first, last, outside = connection.execute(
        f"SELECT MIN(CASE WHEN t >= ? AND t < ? THEN t END), "
        f"MAX(CASE WHEN t >= ? AND t < ? THEN t END), "
        f"SUM(CASE WHEN t < ? OR t >= ? THEN 1 ELSE 0 END) "
        f"FROM (SELECT time AS t FROM ({sql}))",
        [PLAUSIBLE_FROM, until, PLAUSIBLE_FROM, until, PLAUSIBLE_FROM,
         until] + params).fetchone()
    return first, last, outside or 0


def unit_for(start, end, most=400):
    """The finest histogram unit giving at most `most` bars over
    [start, end)."""
    first, last = parse(start), parse(end)
    if first is None or last is None or last <= first:
        return 'day'
    span = (last - first).total_seconds()
    for name, _length in UNITS:
        seconds = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400,
                   'month': 86400 * 30.4, 'year': 86400 * 365.25}[name]
        if span / seconds <= most:
            return name
    return 'year'


def histogram(connection, filters, unit):
    """{bucket text: {source: count}} -- buckets are time prefixes."""
    length = dict(UNITS)[unit]
    sql, params = _union(filters)
    if sql is None:
        return {}
    out = {}
    for bucket, source, number in connection.execute(
            f"SELECT substr(time, 1, {length}) AS b, source, COUNT(*) FROM "
            f"({sql}) GROUP BY b, source", params):
        if bucket:
            out.setdefault(bucket, {})[source] = number
    return out


def bucket_start(bucket):
    """The datetime a histogram bucket text begins at."""
    text = bucket
    if len(text) == 4:
        text += '-01'
    if len(text) == 7:
        text += '-01'
    if len(text) == 10:
        text += ' 00'
    if len(text) == 13:
        text += ':00'
    if len(text) == 16:
        text += ':00'
    return parse(text)


def step(moment, unit):
    """The start of the bucket after the one `moment` starts."""
    if unit == 'year':
        return moment.replace(year=moment.year + 1)
    if unit == 'month':
        return (moment.replace(day=28) + datetime.timedelta(days=4)) \
            .replace(day=1)
    seconds = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400}[unit]
    return moment + datetime.timedelta(seconds=seconds)


def floor(moment, unit):
    if unit == 'year':
        return moment.replace(month=1, day=1, hour=0, minute=0, second=0,
                              microsecond=0)
    if unit == 'month':
        return moment.replace(day=1, hour=0, minute=0, second=0,
                              microsecond=0)
    if unit == 'day':
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == 'hour':
        return moment.replace(minute=0, second=0, microsecond=0)
    if unit == 'minute':
        return moment.replace(second=0, microsecond=0)
    return moment.replace(microsecond=0)


def parse(text):
    """A naive datetime from a timeline time text, or None."""
    if not text:
        return None
    if isinstance(text, datetime.datetime):
        return text
    text = str(text)[:19]
    for pattern in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d %H',
                    '%Y-%m-%d', '%Y-%m', '%Y'):
        try:
            return datetime.datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def text(moment):
    return moment.strftime('%Y-%m-%d %H:%M:%S') if moment else None


#: The narrowest span a zoom goes to.
MIN_SPAN_SECONDS = 10


def zoom_range(start, end, fraction, factor, bounds=None,
               minimum=MIN_SPAN_SECONDS):
    """(start, end) texts after zooming [start, end) by `factor` (<1 in,
    >1 out) around the point `fraction` of the way across, which stays
    where it is. Never wider than `bounds` (the case's own first and last
    event) and never narrower than `minimum` seconds; never outside what a
    datetime holds. None if the range cannot be read."""
    first, last = parse(start), parse(end)
    if first is None or last is None or last <= first:
        return None
    fraction = min(1.0, max(0.0, fraction))
    span = (last - first).total_seconds()
    wanted = max(float(minimum), span * factor)
    low, high = _limits(bounds)
    if wanted >= (high - low).total_seconds():
        return text(low), text(high)
    pivot = first + datetime.timedelta(seconds=span * fraction)
    new_first = pivot - datetime.timedelta(seconds=wanted * fraction)
    new_first = max(low, min(new_first, high - datetime.timedelta(
        seconds=wanted)))
    return text(new_first), text(new_first + datetime.timedelta(
        seconds=wanted))


def clamp_range(start, end, bounds=None, minimum=MIN_SPAN_SECONDS):
    """A typed or dragged range made safe: inside what a datetime holds,
    at least `minimum` seconds. (Typed ranges may go outside the case's
    bounds on purpose -- that is how a 1601 time is looked at.)"""
    first, last = parse(start), parse(end)
    if first is None or last is None:
        return None
    if last < first:
        first, last = last, first
    if (last - first).total_seconds() < minimum:
        middle = first + (last - first) / 2
        first = middle - datetime.timedelta(seconds=minimum / 2)
        last = first + datetime.timedelta(seconds=minimum)
    return text(first), text(last)


def _limits(bounds):
    """The widest a zoom may go: the case's span with a margin, or the
    plausible years."""
    floor_ = datetime.datetime(1601, 1, 2)
    ceiling = datetime.datetime(9999, 12, 30)
    first = parse(bounds[0]) if bounds and bounds[0] else None
    last = parse(bounds[1]) if bounds and bounds[1] else None
    if first is None or last is None:
        first, last = parse(PLAUSIBLE_FROM), parse(plausible_until())
    margin = max(datetime.timedelta(seconds=60), (last - first) / 50)
    try:
        low = max(floor_, first - margin)
    except OverflowError:
        low = floor_
    try:
        high = min(ceiling, last + margin)
    except OverflowError:
        high = ceiling
    return low, high


def around(time_text, seconds):
    """(start, end) of a window of +/- `seconds` around a time."""
    moment = parse(time_text)
    if moment is None:
        return None, None
    delta = datetime.timedelta(seconds=seconds)
    return text(moment - delta), text(moment + delta + datetime.timedelta(
        seconds=1))


# --- export -------------------------------------------------------------------

CSV_HEADER = ('Time', 'Time zone', 'Source', 'Type', 'Description',
              'Path or subject', 'User', 'Evidence', 'Artifact reference',
              'Deleted', 'Detail')


def write_csv(connection, filters, path, evidence_names, should_stop=None):
    """Every row the filters select, as CSV (UTF-8 with BOM, which Excel
    needs to read it as UTF-8). Returns the number of rows."""
    written = 0
    with open(path, 'w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADER)
        for row in iter_events(connection, filters):
            if should_stop and written % 5000 == 0 and should_stop():
                break
            writer.writerow(csv_row(row, evidence_names))
            written += 1
    return written


def csv_row(row, evidence_names):
    return tuple(_cell(value) for value in _csv_values(row, evidence_names))


def _cell(value):
    """A NUL in a name (raw MFT names can hold one) is written visibly;
    the csv module cannot write it at all."""
    return value.replace('\x00', '\\0') if isinstance(value, str) else value


def _csv_values(row, evidence_names):
    return (row['time'],
            'local, no zone' if row['local'] else 'UTC',
            SOURCE_LABELS.get(row['source'], row['source']),
            describe_kind(row),
            row['title'] or '',
            row['subject'] or '',
            row['user'] or '',
            evidence_names.get(row['evidence_id'], '')
            if row['evidence_id'] is not None else '',
            row['artifact_ref'] or '',
            'yes' if row['deleted'] else '',
            _flat(row['extra']))


def _flat(extra):
    if not extra:
        return ''
    try:
        value = json.loads(extra)
    except (TypeError, ValueError):
        return str(extra)
    if isinstance(value, dict):
        return '; '.join(f"{k}: {v}" for k, v in value.items()
                         if v not in (None, '', {}, []))
    return str(value)

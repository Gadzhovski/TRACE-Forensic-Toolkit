"""One timeline of everything the case knows happened, and when.

Sources, each a table some module filled:

* ``fs``       -- file-system times, MACB (``fs_events``): NTFS's $MFT
                  $STANDARD_INFORMATION and $FILE_NAME (core/ntfs), every
                  other file system's entries (core/fs_times; FAT and
                  exFAT as local time)
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
    ('modules', 'External modules', '#D16BA5'),
    ('case', 'Case events', '#8A939E'),
)
SOURCE_LABELS = {key: label for key, label, _colour in SOURCES}
SOURCE_COLOURS = {key: colour for key, _label, colour in SOURCES}

#: What the columns of a row are.
COLUMNS = ('time', 'local', 'source', 'kind', 'evidence_id', 'title',
           'subject', 'user', 'artifact_ref', 'deleted', 'extra', 'row_key')
#: `row_key` is '<branch>:<rowid of its table row>': with the time, it
#: orders rows that share a second the same way every time, so pages can
#: be read on from a (time, row_key) pair (`events_after`) instead of an
#: OFFSET, which re-sorts every row before it for each page.

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


def default_sources():
    """The sources the Timeline opens with: the case's choice (setting
    timeline_sources), else everything but the audit trail."""
    from trace_app.core import settings
    chosen = [key for key in settings.current('timeline_sources') or ()
              if key in SOURCE_LABELS]
    return chosen or [key for key, _l, _c in SOURCES if key != 'case']


def default_filters():
    from trace_app.core import settings
    from trace_app.core.modules import destinations
    return {
        'start': None, 'end': None,             # text, end exclusive
        'sources': default_sources(),
        # Activity kinds shown (setting timeline_activity_categories);
        # None: every kind.
        'activity_categories': list(
            settings.current('timeline_activity_categories') or ()) or None,
        # External tools' evidence rows in Activity shown here too
        # (core/modules/destinations: evidence -> timeline).
        'tool_activity': destinations.goes_to({'role': 'evidence'},
                                              'timeline'),
        'evidence_id': None,
        'text': '',
        'deleted_only': False,
        'hide_known_good': False,
        'timestomped_only': False,
        'focus_ref': None,                       # (evidence_id, ref)
        # [(evidence_id, volume key)]: events on the volumes holding these
        # operating systems (Case.systems); None = every volume.
        'systems': None,
        'user': None,
        'folder': None,
        'fs_attributes': 'both',                 # both | SI | FN
        'columns': {},                           # COLUMN_FILTERS
        'starred_only': False,                   # timeline_marks
    }


def event_key(row):
    """A stable name for an event: the same when the module that wrote it
    runs again (its table rowid would not be), for the examiner's marks
    (Case.mark_events)."""
    import hashlib
    parts = [str(row.get(name) if row.get(name) is not None else '')
             for name in ('source', 'evidence_id', 'time', 'kind',
                          'artifact_ref', 'title', 'subject')]
    return hashlib.sha1('\x1f'.join(parts).encode('utf-8',
                                                   'replace')).hexdigest()


def describe_kind(row):
    """What the Type column says for a row."""
    source, kind = row['source'], row['kind'] or ''
    if source == 'fs':
        letters, _, attribute = kind.partition(' ')
        words = [MACB_WORDS[c] for c in letters if c in MACB_WORDS]
        return f"{', '.join(words)} " \
               f"({FS_ATTRIBUTES.get(attribute, attribute)})"
    return kind


#: What each file-system time source is, in the Type column.
FS_ATTRIBUTES = {'SI': '$SI', 'FN': '$FN', 'I30': '$I30 slack',
                 'FS': 'file system', 'FS-local': 'file system, local time',
                 'SI (carved)': '$SI, carved', 'FN (carved)': '$FN, carved',
                 'I30 (carved)': '$I30, carved'}

#: The kinds of file-system time the File system source can be narrowed
#: to: (key, label, fs_events sources). NTFS keeps two sets of times per
#: file and index-slack copies; every other file system (ext, Btrfs, XFS,
#: F2FS, APFS, FAT, exFAT, HFS+) its own one set. Only the kinds a case
#: holds are offered (fs_kinds).
FS_KINDS = (
    ('SI', '$STANDARD_INFORMATION (NTFS)', ('SI', 'SI (carved)')),
    ('FN', '$FILE_NAME (NTFS)', ('FN', 'FN (carved)')),
    ('I30', '$I30 index slack (NTFS)', ('I30', 'I30 (carved)')),
    ('FS', 'File system times (non-NTFS)', ('FS', 'FS-local')),
)
_FS_KIND_SOURCES = {key: sources for key, _label, sources in FS_KINDS}


def fs_kinds(connection, evidence_id=None):
    """The FS_KINDS keys the case's file-system events hold (for one
    image, or all)."""
    query = "SELECT DISTINCT source FROM fs_events"
    params = []
    if evidence_id is not None:
        query += " WHERE evidence_id = ?"
        params.append(evidence_id)
    present = {row[0] for row in connection.execute(query, params)}
    return [key for key, _label, sources in FS_KINDS
            if present & set(sources)]


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
    systems = [tuple(pair) for pair in filters.get('systems') or ()]
    # Who read it: 'TRACE' or a tool ('iLEAPP'); with reader_only, what no
    # other reader read. A tool reads only activity and its own events.
    reader = filters.get('reader') or None
    reader_only = bool(filters.get('reader_only'))
    if reader and reader != 'TRACE':
        wanted &= {'activity', 'modules'}
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
        if systems:
            # A volume's events by their reference's volume (p<key>:...);
            # what refers to no file on one -- the audit trail, a carve --
            # belongs to no system.
            if ref_sql is None:
                return None
            clauses.append('(' + ' OR '.join(
                f"({evidence_sql} = ? AND {ref_sql} LIKE ?)"
                for _pair in systems) + ')')
            for evidence, key in systems:
                params.extend([evidence, f"p{int(key)}:%"])
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

    if filters.get('starred_only'):
        # The examiner's starred events, copied when marked: one branch,
        # whatever the sources asked.
        where = common('m', 'm.time', 'm.evidence_id', 'm.artifact_ref',
                       'm.subject', ('m.title', 'm.subject', 'm.comment',
                                     'm.kind'), 'm.user', hideable=False)
        if where is None:
            return []
        sql, params = where
        marked = [key for key in wanted]
        if marked:
            sql += f" AND m.source IN ({','.join('?' * len(marked))})"
            params.extend(marked)
        return [(
            "SELECT m.time, m.local, m.source, m.kind, m.evidence_id, "
            "m.title, m.subject, m.user, m.artifact_ref, m.deleted, "
            "json_object('comment', m.comment, 'colour', m.colour), "
            "printf('mark:%012d', m.rowid) FROM timeline_marks m WHERE "
            f"m.starred = 1 AND {sql}", params)]

    if 'fs' in wanted:
        where = common('e', 'e.time_utc', 'e.evidence_id', 'e.artifact_ref',
                       'e.path', ('e.path',))
        if where is not None:
            sql, params = where
            attribute = filters.get('fs_attributes') or 'both'
            if attribute in _FS_KIND_SOURCES:
                sources = _FS_KIND_SOURCES[attribute]
                sql += f" AND e.source IN ({','.join('?' * len(sources))})"
                params.extend(sources)
            if deleted_only:
                sql += " AND e.deleted = 1"
            out.append((
                "SELECT e.time_utc, e.source = 'FS-local', 'fs', "
                "e.macb || ' ' || e.source, "
                "e.evidence_id, NULL, e.path, NULL, e.artifact_ref, "
                "e.deleted, NULL, printf('fs:%012d', e.rowid) "
                f"FROM fs_events e WHERE {sql}", params))

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
                "'flags', u.reason_flags), printf('usn:%012d', u.rowid) "
                f"FROM usn_journal u WHERE {sql}", params))

    if 'activity' in wanted and not deleted_only:
        where = common('a', 'a.time_utc', 'a.evidence_id', 'a.source_ref',
                       None, ('a.what', 'a.subject', 'a.user', 'a.detail',
                              'a.source'), 'a.user', hideable=False)
        if where is not None and not stomped_only:
            sql, params = where
            # One record read by two readers (TRACE and a LEAPP) is one
            # event: the primary, naming the others (core/activity_match).
            sql += " AND a.duplicate_of IS NULL"
            kinds = filters.get('activity_categories')
            if kinds:
                # What is not chosen is left out -- never a kind outside
                # the choosable list ('web': Chromium storage).
                from trace_app.core.activity import CATEGORIES
                hidden = sorted({key for key, _label in CATEGORIES}
                                - set(kinds))
                if hidden:
                    sql += (" AND a.category NOT IN (" +
                            ','.join('?' * len(hidden)) + ")")
                    params = list(params) + hidden
            if filters.get('tool_activity') is False:
                sql += " AND a.module_run_id IS NULL"
            if reader:
                if reader_only:
                    sql += (" AND a.reader = ? AND NOT EXISTS (SELECT 1 FROM "
                            "user_activity d WHERE d.duplicate_of = a.id "
                            "AND d.reader != ?)")
                else:
                    sql += (" AND (a.reader = ? OR EXISTS (SELECT 1 FROM "
                            "user_activity d WHERE d.duplicate_of = a.id "
                            "AND d.reader = ?))")
                params = list(params) + [reader, reader]
            out.append((
                "SELECT a.time_utc, a.time_local, 'activity', a.category, "
                "a.evidence_id, a.what, a.subject, a.user, a.source_ref, 0, "
                "json_object('detail', json(a.detail), 'source', a.source, "
                "'source_path', a.source_path, 'reader', a.reader, 'also', "
                "(SELECT group_concat(DISTINCT d.reader) FROM user_activity d "
                "WHERE d.duplicate_of = a.id)), "
                "printf('activity:%012d', a.rowid) "
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
                f"SELECT {taken}, 1, 'photo', CASE p.kind WHEN 'video' THEN "
                "'Video recorded' WHEN 'audio' THEN 'Audio recorded' ELSE "
                "'Photo taken' END, p.evidence_id, "
                "p.name, p.path, NULL, p.artifact_ref, 0, p.detail, "
                "printf('photo:%012d', p.rowid) FROM file_findings p WHERE p.module = 'photo' AND "
                f"json_extract(p.detail, '$.taken') IS NOT NULL AND {sql}",
                params))
        # A video with no camera-clock tag: its container's recording
        # time, UTC (core/media_metadata.py).
        recorded = "json_extract(p.detail, '$.recorded')"
        where = common('p', recorded, 'p.evidence_id', 'p.artifact_ref',
                       'p.path', ('p.path', 'p.summary'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {recorded}, 0, 'photo', CASE p.kind WHEN 'audio' "
                "THEN 'Audio recorded' ELSE 'Video recorded' END, "
                "p.evidence_id, p.name, p.path, NULL, p.artifact_ref, 0, "
                "p.detail, printf('photo:%012d', p.rowid) FROM file_findings "
                "p WHERE p.module = 'photo' AND p.kind IN ('video', 'audio') "
                "AND json_extract(p.detail, '$.taken') IS NULL AND "
                f"{recorded} IS NOT NULL AND {sql}", params))

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
                    f"0, d.detail, printf('document-{field}:%012d', d.rowid) "
                    "FROM file_findings d WHERE "
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
                "g.detail, printf('sigma:%012d', g.rowid) FROM file_findings g "
                "WHERE g.module = 'sigma' AND "
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
                "c.size, 'type', c.type), printf('carved:%012d', c.rowid) "
                "FROM carved_files c "
                f"WHERE c.embedded_date != 'Unknown' AND {sql}", params))

    if 'modules' in wanted and not deleted_only and not stomped_only:
        # What external modules (iLEAPP, aLEAPP...) extracted: one event per
        # timestamp in a row (core/modules/job.events). The ref names the
        # row (case.make_module_ref), not a file: a click shows the row and
        # previews the file it came from.
        module_ref = ("'mod:' || k.run_id || ':' || t.tablename || ':' || "
                      "k.row_id")
        where = common('k', 'k.time_utc', 'r.evidence_id', module_ref, None,
                       ('k.label', 'k.summary', 't.name', 'r.tool'),
                       hideable=False)
        if where is not None and reader != 'TRACE':
            sql, params = where
            # Every timestamp is kept, sorted by core/modules/routes:
            # telemetry (log lines, power and health samples) only when
            # asked for; an evidence row's own time is its activity event
            # ('bridged'); an older run's copy of the same rows is not
            # shown ('superseded').
            kinds = ('evidence', 'other') + \
                (('telemetry',) if filters.get('module_telemetry') else ())
            sql += " AND k.kind IN (" + ','.join('?' * len(kinds)) + ")"
            params = list(params) + list(kinds)
            if reader:
                sql += " AND r.tool = ?"
                params.append(reader)
            out.append((
                "SELECT k.time_utc, 0, 'modules', k.label, r.evidence_id, "
                "r.tool || ': ' || t.name, k.summary, NULL, "
                f"{module_ref}, 0, json_object('tool', r.tool, 'version', "
                "r.version, 'category', t.category, 'run', r.id), "
                "printf('module:%012d', k.rowid) FROM module_events k "
                "JOIN module_runs r ON r.id = k.run_id "
                "JOIN module_artifacts t ON t.id = k.artifact_id "
                f"WHERE {sql}", params))

    if 'case' in wanted and not deleted_only and not stomped_only \
            and not focus and not user and not folder and not systems:
        audit_time = "replace(substr(x.utc, 1, 19), 'T', ' ')"
        where = common('x', audit_time, 'NULL', None, None,
                       ('x.action', 'x.detail'))
        if where is not None and evidence_id is None:
            sql, params = where
            out.append((
                f"SELECT {audit_time}, 0, 'case', 'Audit', NULL, x.action, "
                "x.detail, NULL, NULL, 0, NULL, printf('audit:%012d', x.rowid) "
                f"FROM activity x WHERE {sql}",
                params))
        verified = "replace(substr(v.utc, 1, 19), 'T', ' ')"
        where = common('v', verified, 'v.evidence_id', None, None,
                       ('v.status', 'v.algorithm'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {verified}, 0, 'case', 'Verification', "
                "v.evidence_id, 'Verified: ' || v.status, v.algorithm, NULL, "
                "NULL, 0, NULL, printf('verification:%012d', v.rowid) "
                "FROM verifications v WHERE " + sql, params))
        marked = "replace(substr(b.created_utc, 1, 19), 'T', ' ')"
        where = common('b', marked, 'b.evidence_id', 'b.artifact_ref',
                       None, ('b.artifact_name', 'b.label'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {marked}, 0, 'case', 'Bookmarked', b.evidence_id, "
                "b.artifact_name, b.artifact_path, NULL, b.artifact_ref, 0, "
                "NULL, printf('bookmark:%012d', b.rowid) "
                "FROM bookmarks b WHERE " + sql, params))
        noted = "replace(substr(n.created_utc, 1, 19), 'T', ' ')"
        where = common('n', noted, 'n.evidence_id', 'n.artifact_ref', None,
                       ('n.body', 'n.artifact_name'))
        if where is not None:
            sql, params = where
            out.append((
                f"SELECT {noted}, 0, 'case', 'Note', n.evidence_id, "
                "n.artifact_name, substr(n.body, 1, 200), NULL, "
                "n.artifact_ref, 0, NULL, printf('note:%012d', n.rowid) "
                "FROM notes n WHERE " + sql, params))
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
          "NULL AS artifact_ref, NULL AS deleted, NULL AS extra, "
          "NULL AS row_key WHERE 0")


def _union(filters):
    branches = _branches(filters)
    if not branches:
        return None, []
    sql = _NAMES + ''.join(f" UNION ALL SELECT * FROM ({part})"
                           for part, _params in branches)
    params = [value for _part, values in branches for value in values]
    where, values = _column_clauses(filters.get('columns') or {})
    if where:
        sql = f"SELECT * FROM ({sql}) WHERE {where}"
        params += values
    return sql, params


#: Column filters (`filters['columns']`), keyed as the table's columns:
#: text matched anywhere in the column, case ignored ('time', 'kind',
#: 'title', 'subject', 'user'); 'sources' and 'evidence_ids' lists of
#: keys; 'macb' letters every file-system row shown must have.
COLUMN_FILTERS = ('time', 'sources', 'kind', 'title', 'subject', 'user',
                  'evidence_ids', 'macb', 'extension', 'kind_is', 'folder_is',
                  'hours', 'burst')

#: SQL for a row's folder (the subject up to its last '/'), its file name
#: and that name's extension (lower case, '' for none) -- SQLite has no
#: last-index-of, but rtrim by the string's non-separator characters
#: leaves everything up to the last separator.
FOLDER_SQL = ("rtrim(rtrim(COALESCE(subject, ''), replace(COALESCE("
              "subject, ''), '/', '')), '/')")
_NAME_SQL = ("substr(COALESCE(subject, ''), length(rtrim(COALESCE("
             "subject, ''), replace(COALESCE(subject, ''), '/', ''))) + 1)")
EXTENSION_SQL = (f"CASE WHEN instr({_NAME_SQL}, '.') > 1 THEN lower(substr("
                 f"{_NAME_SQL}, length(rtrim({_NAME_SQL}, replace("
                 f"{_NAME_SQL}, '.', ''))) + 1)) ELSE '' END")


def _like(text):
    escaped = text.replace('\\', '\\\\').replace('%', '\\%') \
        .replace('_', '\\_')
    return f"%{escaped}%"


def _column_clauses(columns):
    """(sql, params) for the column filters: every one must hold."""
    clauses, params = [], []
    for key in ('time', 'user', 'subject'):
        text = (columns.get(key) or '').strip()
        if text:
            clauses.append(f"COALESCE({key}, '') LIKE ? ESCAPE '\\'")
            params.append(_like(text))
    text = (columns.get('title') or '').strip()
    if text:
        # The Description column: the title, or a file's own name.
        clauses.append("COALESCE(title, subject, '') LIKE ? ESCAPE '\\'")
        params.append(_like(text))
    text = (columns.get('kind') or '').strip()
    if text:
        clauses.append(_kind_clause(text, params))
    for key, column in (('sources', 'source'), ('evidence_ids',
                                                 'evidence_id')):
        values = columns.get(key)
        if values is not None:
            values = list(values)
            if not values:
                clauses.append('0')
            else:
                clauses.append(f"{column} IN "
                               f"({','.join('?' * len(values))})")
                params.extend(values)
    letters = ''.join(c for c in (columns.get('macb') or '').upper()
                      if c in MACB_WORDS)
    if letters:
        clauses.append("source = 'fs'")
        for letter in letters:
            clauses.append("instr(substr(kind, 1, instr(kind || ' ', ' ')),"
                           " ?) > 0")
            params.append(letter)
    # Exact values, from the Summary view's groups.
    if columns.get('extension') is not None:
        clauses.append(f"{EXTENSION_SQL} = ?")
        params.append(columns['extension'].lower().lstrip('.'))
    if columns.get('kind_is') is not None:
        clauses.append("COALESCE(kind, '') = ?")
        params.append(columns['kind_is'])
    if columns.get('folder_is') is not None:
        clauses.append(f"{FOLDER_SQL} = ?")
        params.append(columns['folder_is'])
    hours = columns.get('hours')
    if hours is not None:
        # A heatmap cell: the stored hours that fall in it (weekday_hours).
        hours = list(hours)
        if not hours:
            clauses.append('0')
        else:
            clauses.append(f"substr(time, 1, 13) IN "
                           f"({','.join('?' * len(hours))})")
            params.extend(hours)
    burst = columns.get('burst')
    if burst:
        # One burst's events (core/timeline_clusters).
        clauses.append("source = ? AND COALESCE(kind, '') = ? AND "
                       "evidence_id IS ? AND substr(time, 1, ?) = ?")
        params.extend([burst['source'], burst['kind'] or '',
                       burst['evidence_id'], len(burst['window']),
                       burst['window']])
    return ' AND '.join(clauses), params


#: The Summary view's groupings: key -> (label, SQL of the value).
SUMMARY_BY = {
    'source': ("Source", "source"),
    'kind': ("Type", "COALESCE(kind, '')"),
    'folder': ("Folder", FOLDER_SQL),
    'extension': ("Extension", EXTENSION_SQL),
    'user': ("User", "COALESCE(user, '')"),
    'evidence': ("Evidence", "evidence_id"),
}


def extension_of(subject):
    """A path's extension as EXTENSION_SQL reads it: lower case, '' for
    none (a leading dot, '.bashrc', is a name, not an extension)."""
    name = (subject or '').rsplit('/', 1)[-1]
    stem, dot, extension = name.rpartition('.')
    return extension.lower() if dot and stem else ''


def summary(connection, filters, by, limit=5000):
    """[(value, events, first, last)] for the events the filters select,
    grouped by `by` (a SUMMARY_BY key), most events first."""
    sql, params = _union(filters)
    if sql is None or by not in SUMMARY_BY:
        return []
    value = SUMMARY_BY[by][1]
    if by == 'extension':
        # Once per row in Python, not the SQL above four times over (6 s
        # on 520,000 events, this 1 s).
        connection.create_function('trace_extension', 1, extension_of,
                                   deterministic=True)
        value = 'trace_extension(subject)'
    return [tuple(row) for row in connection.execute(
        f"SELECT {value} AS v, COUNT(*), MIN(time), MAX(time) FROM ({sql}) "
        f"GROUP BY v ORDER BY 2 DESC, 1 LIMIT {int(limit)}", params)]


def _kind_clause(text, params):
    """The Type column as it reads: a file-system row's 'M SI' reads
    'Modified ($SI)', so the words match their letters and attributes."""
    options = ["COALESCE(kind, '') LIKE ? ESCAPE '\\'"]
    params.append(_like(text))
    lowered = text.lower()
    for letter, word in MACB_WORDS.items():
        if lowered in word.lower():
            options.append("(source = 'fs' AND instr(substr(kind, 1, "
                           "instr(kind || ' ', ' ')), ?) > 0)")
            params.append(letter)
    for attribute, label in FS_ATTRIBUTES.items():
        if lowered in label.lower():
            options.append("(source = 'fs' AND substr(kind, "
                           "instr(kind, ' ') + 1) = ?)")
            params.append(attribute)
    return '(' + ' OR '.join(options) + ')'


def events(connection, filters, limit=None, offset=0, descending=False):
    """Rows as dicts, in time order."""
    sql, params = _union(filters)
    if sql is None:
        return []
    order = 'DESC' if descending else 'ASC'
    query = f"SELECT * FROM ({sql}) ORDER BY time {order}, row_key {order}"
    if limit:
        query += f" LIMIT {int(limit)} OFFSET {int(offset)}"
    return [dict(zip(COLUMNS, row)) for row in connection.execute(query,
                                                                  params)]


def iter_events(connection, filters):
    """Every matching row, in time order, without holding them all."""
    sql, params = _union(filters)
    if sql is None:
        return
    for row in connection.execute(
            f"SELECT * FROM ({sql}) ORDER BY time, row_key", params):
        yield dict(zip(COLUMNS, row))


def _paged(filters, key, limit, backwards):
    """(sql, params) for one page: each source's rows past `key` in its
    own order, at most `limit` of them, then merged. Paged per branch, so
    a big table is read along its time index and stops at the page's end
    -- ordering the whole union for every page took 0.9 s on 520,000
    file-system times, this 15 ms."""
    branches = _branches(filters)
    if not branches:
        return None, []
    names = ', '.join(COLUMNS)
    compare, order = ('<', 'DESC') if backwards else ('>', 'ASC')
    where, column_params = _column_clauses(filters.get('columns') or {})
    ctes, parts, params = [], [], []
    for number, (part, values) in enumerate(branches):
        ctes.append(f"b{number}({names}) AS ({part})")
        params.extend(values)
    for number in range(len(branches)):
        clauses = []
        if key is not None:
            clauses.append(f"(time, row_key) {compare} (?, ?)")
        if where:
            clauses.append(where)
        condition = f" WHERE {' AND '.join(clauses)}" if clauses else ''
        parts.append(f"SELECT * FROM (SELECT * FROM b{number}{condition} "
                     f"ORDER BY time {order}, row_key {order} "
                     f"LIMIT {int(limit)})")
        if key is not None:
            params.extend([key[0], key[1] or ''])
        params.extend(column_params)
    sql = (f"WITH {', '.join(ctes)} SELECT * FROM ("
           + ' UNION ALL '.join(parts) +
           f") ORDER BY time {order}, row_key {order} LIMIT {int(limit)}")
    return sql, params


def events_after(connection, filters, after=None, limit=5000):
    """Up to `limit` rows after the (time, row_key) pair `after`, in
    order -- the next page. (time, '') starts at that time; None at the
    first row."""
    sql, params = _paged(filters, after, limit, False)
    if sql is None:
        return []
    return [dict(zip(COLUMNS, row)) for row in connection.execute(sql,
                                                                  params)]


def events_before(connection, filters, before, limit=5000):
    """Up to `limit` rows before the pair `before`, in order -- the page
    above one already shown."""
    sql, params = _paged(filters, before, limit, True)
    if sql is None:
        return []
    rows = [dict(zip(COLUMNS, row)) for row in connection.execute(sql,
                                                                  params)]
    rows.reverse()
    return rows


def count_before(connection, filters, before):
    """How many rows come before the pair `before`."""
    sql, params = _union(filters)
    if sql is None:
        return 0
    return connection.execute(
        f"SELECT COUNT(*) FROM ({sql}) WHERE (time, row_key) < (?, ?)",
        params + [before[0], before[1] or '']).fetchone()[0]


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


#: The share of events left out at each end of the range the tab opens
#: on: a few hundred files from 1994 (software's own dates) or a stray
#: 2099 would otherwise flatten the years that matter into a few pixels.
DENSE_TAIL = 0.005


def spread(connection, filters, tail=DENSE_TAIL):
    """Where the events are, from one count per day:

    {'first', 'last'}: the plausible times' ends (as `bounds`);
    'outside': events outside the plausible dates;
    {'dense_first', 'dense_last'}: the days holding all but the `tail`
    share at each end (dense_last is the day after the last, exclusive);
    'dense_outside': plausible events outside those days.
    None when no event has a plausible time."""
    unbounded = dict(filters, start=None, end=None)
    sql, params = _union(unbounded)
    if sql is None:
        return None
    until = plausible_until()
    days, outside = [], 0
    for day, number, first, last in connection.execute(
            f"SELECT substr(time, 1, 10) AS d, COUNT(*), MIN(time), "
            f"MAX(time) FROM ({sql}) GROUP BY d ORDER BY d", params):
        if first < PLAUSIBLE_FROM or last >= until:
            outside += number
        else:
            days.append((day, number, first, last))
    if not days:
        return None
    total = sum(number for _d, number, _f, _l in days)
    skip = int(total * tail)
    low = high = 0
    seen = 0
    for position, (_day, number, _f, _l) in enumerate(days):
        if seen + number > skip:
            low = position
            break
        seen += number
    seen = 0
    for position in range(len(days) - 1, -1, -1):
        number = days[position][1]
        if seen + number > skip:
            high = position
            break
        seen += number
    dense_outside = sum(n for _d, n, _f, _l in days[:low]) + \
        sum(n for _d, n, _f, _l in days[high + 1:])
    last_day = parse(days[high][0] + ' 00:00:00')
    return {'first': days[0][2], 'last': days[-1][3], 'outside': outside,
            'dense_first': days[low][0] + ' 00:00:00',
            'dense_last': text(last_day + datetime.timedelta(days=1)),
            'dense_outside': dense_outside}


def macb(row):
    """A file-system row's MACB letters ('MACB', 'M...'), else ''."""
    if row.get('source') != 'fs':
        return ''
    letters = (row.get('kind') or '').partition(' ')[0]
    return ''.join(c if c in letters else '.' for c in 'MACB')


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


#: The Lanes view's lanes: key -> (label, SQL of the lane value).
LANES_BY = {
    'source': ("Source", "source"),
    'evidence': ("Evidence", "evidence_id"),
    'user': ("User", "COALESCE(user, '')"),
    'kind': ("Type", "COALESCE(kind, '')"),
}


def lane_counts(connection, filters, by, buckets):
    """{lane value: {bucket index: events}} over the filters' range cut into
    `buckets` equal slices (the Lanes view's pixels' worth of time)."""
    sql, params = _union(filters)
    first, last = parse(filters.get('start')), parse(filters.get('end'))
    if sql is None or by not in LANES_BY or first is None or last is None \
            or last <= first:
        return {}
    width = (last - first).total_seconds() / max(1, int(buckets))
    value = LANES_BY[by][1]
    out = {}
    for lane, bucket, number in connection.execute(
            f"SELECT {value} AS lane, CAST((julianday(time) - julianday(?)) "
            f"* 86400.0 / ? AS INTEGER) AS b, COUNT(*) FROM ({sql}) "
            f"GROUP BY lane, b", [text(first), width] + params):
        if bucket is not None and 0 <= bucket < buckets:
            out.setdefault(lane, {})[bucket] = number
    return out


# --- patterns: when, and when not --------------------------------------------------

WEEKDAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


def hour_counts(connection, filters):
    """[(hour 'YYYY-MM-DD HH', local, events)] -- every hour with events,
    zone-less (local) rows apart from UTC ones."""
    sql, params = _union(filters)
    if sql is None:
        return []
    return [tuple(row) for row in connection.execute(
        f"SELECT substr(time, 1, 13) AS h, COALESCE(local, 0), COUNT(*) "
        f"FROM ({sql}) GROUP BY h, local ORDER BY h", params)
        if row[0] and len(row[0]) == 13]


def weekday_hours(hours, zone=None):
    """(grid, cells): grid[weekday][hour] = events, weekdays Monday first,
    in `zone` (a display zone name; None = UTC), and cells[(weekday,
    hour)] = the stored hour prefixes that fall in it -- what a click on
    it filters by. Zone-less rows are taken as they are: their digits are
    the machine's own local time already."""
    import zoneinfo
    tz = None
    if zone:
        try:
            tz = zoneinfo.ZoneInfo(zone)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            tz = None
    grid = [[0] * 24 for _day in range(7)]
    cells = {}
    for prefix, local, number in hours:
        try:
            moment = datetime.datetime.strptime(prefix, '%Y-%m-%d %H')
        except ValueError:
            continue
        if tz is not None and not local:
            moment = moment.replace(tzinfo=datetime.timezone.utc) \
                .astimezone(tz)
        cell = (moment.weekday(), moment.hour)
        grid[cell[0]][cell[1]] += number
        cells.setdefault(cell, set()).add(prefix)
    return grid, {cell: sorted(prefixes) for cell, prefixes in cells.items()}


def gap_threshold(start, end):
    """The shortest stretch with no events worth calling a gap, for a range
    from `start` to `end`: a week over half a year, a day over a fortnight,
    else two hours."""
    first, last = parse(start), parse(end)
    if first is None or last is None:
        return datetime.timedelta(days=7)
    span = last - first
    if span >= datetime.timedelta(days=180):
        return datetime.timedelta(days=7)
    if span >= datetime.timedelta(days=14):
        return datetime.timedelta(days=1)
    return datetime.timedelta(hours=2)


def gaps(hours, start, end, threshold=None):
    """[(from, to)] stretches inside [start, end) with no events at all, of
    at least `threshold` -- the machine off, a clock wrong, or records
    wiped. Before the first event and after the last are not gaps."""
    threshold = threshold or gap_threshold(start, end)
    present = sorted({prefix for prefix, _local, number in hours if number})
    found = []
    previous = None
    for prefix in present:
        moment = datetime.datetime.strptime(prefix, '%Y-%m-%d %H')
        if previous is not None:
            empty_from = previous + datetime.timedelta(hours=1)
            if moment - empty_from >= threshold:
                found.append((text(empty_from), text(moment)))
        previous = moment
    return found


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


# --- highlight rules ---------------------------------------------------------------

#: The rules a case starts with (case setting 'timeline_highlights' holds the
#: examiner's own): name, colour, on, and conditions -- any of 'sources'
#: (keys), 'kinds' (text in the Type), 'text' (in what the row says;
#: 'regex': True makes it a regular expression), 'extensions', 'deleted'.
#: A row takes the colour of the first rule it matches.
DEFAULT_HIGHLIGHTS = [
    {'name': 'Programs and scripts', 'colour': '#E5534B', 'enabled': True,
     'extensions': ['exe', 'dll', 'sys', 'scr', 'com', 'msi', 'ps1', 'bat',
                    'cmd', 'vbs', 'js', 'hta', 'jar', 'sh', 'elf']},
    {'name': 'Clock changed, logs cleared', 'colour': '#9B6CF0',
     'enabled': True, 'sources': ['activity'],
     'text': r'System time changed|log cleared', 'regex': True},
    {'name': 'USB devices', 'colour': '#E8743B', 'enabled': True,
     'sources': ['activity'], 'kinds': 'usb'},
    {'name': 'Logons', 'colour': '#4C8BF5', 'enabled': False,
     'sources': ['activity'], 'kinds': 'logons'},
    {'name': 'Deleted', 'colour': '#8A939E', 'enabled': False,
     'deleted': True},
]


def compile_highlights(rules):
    """The enabled rules, ready for `highlight_of`; a broken regular
    expression leaves its rule out."""
    import re
    ready = []
    for rule in rules or ():
        if not rule.get('enabled', True) or not rule.get('colour'):
            continue
        text = rule.get('text') or ''
        pattern = None
        if text:
            try:
                pattern = re.compile(text if rule.get('regex')
                                     else re.escape(text), re.IGNORECASE)
            except re.error:
                continue
        ready.append((rule, pattern,
                      {e.lower().lstrip('.') for e in
                       rule.get('extensions') or ()},
                      (rule.get('kinds') or '').lower()))
    return ready


def highlight_of(row, compiled):
    """The colour of the first rule `row` matches, or None."""
    for rule, pattern, extensions, kinds in compiled:
        sources = rule.get('sources')
        if sources and row.get('source') not in sources:
            continue
        if rule.get('deleted') and not row.get('deleted'):
            continue
        if kinds and kinds not in (row.get('kind') or '').lower():
            continue
        if extensions and extension_of(row.get('subject')) not in \
                extensions and extension_of(row.get('title')) not in \
                extensions:
            continue
        if pattern is not None and not pattern.search(
                f"{row.get('title') or ''} {row.get('subject') or ''} "
                f"{describe_kind(row)}"):
            continue
        return rule['colour']
    return None

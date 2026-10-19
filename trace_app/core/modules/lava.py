"""Reading a LEAPP's LAVA output (no Qt).

A LEAPP report folder holds, beside its HTML:

* `_lava_data.lava` -- JSON: `lava_schema_version` (2), `parser_info`
  (tool, version, start/end), `processing_status` ('Complete' when the
  run finished), `modules` (each artifact's status and file count), and
  `artifacts`: {category: [{'name', 'tablename', 'module',
  'column_map' {column: label}, 'record_count', 'source_path',
  'object_columns' [{'name', 'type': 'datetime' | 'date' | 'media'}],
  'data_views' {'conversation': {...}}}]};
* `_lava_artifacts.db` -- SQLite: one table per artifact, columns in
  column_map's order. A datetime is a UTC epoch number (INTEGER, a REAL
  for fractions), a date 'YYYY-MM-DD', '' when the source had none; a
  media column holds a media reference id, resolved by the view
  `_lava_media_info` (source_path: where the file was in the input;
  extraction_path: its copy, relative to the report folder).

Read-only throughout: the database is the tool's record of its run.
"""

import datetime
import json
import os
import sqlite3

from trace_app.infra.sqlite_uri import connect_read_only

DATA = '_lava_data.lava'
DATABASE = '_lava_artifacts.db'
SUPPORTED_SCHEMAS = (2,)


class LavaError(Exception):
    pass


def connect(report_dir):
    """A read-only connection to the run's database."""
    path = os.path.join(report_dir, DATABASE)
    if not os.path.isfile(path):
        raise LavaError(f"No {DATABASE} in {report_dir}.")
    connection = connect_read_only(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def load(report_dir):
    """The run's description: {'status', 'tool', 'version', 'started',
    'finished', 'artifacts': [...], 'modules': [...]}. Raises LavaError
    when there is none, or it is a schema this TRACE does not read."""
    path = os.path.join(report_dir, DATA)
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise LavaError(f"The tool's {DATA} could not be read: {exc}") \
            from exc
    schema = data.get('lava_schema_version')
    if schema not in SUPPORTED_SCHEMAS:
        raise LavaError(f"LAVA schema {schema!r} is not one this TRACE "
                        f"reads ({', '.join(map(str, SUPPORTED_SCHEMAS))}).")
    info = data.get('parser_info') or {}
    artifacts = []
    for category, entries in (data.get('artifacts') or {}).items():
        for entry in entries or ():
            types = {item.get('name'): item.get('type')
                     for item in entry.get('object_columns') or ()}
            columns = [{'name': column, 'label': label,
                        'type': types.get(column, '')}
                       for column, label in
                       (entry.get('column_map') or {}).items()]
            conversation = (entry.get('data_views') or {}).get(
                'conversation')
            artifacts.append({
                'category': category, 'name': entry.get('name') or '',
                'artifact_key': entry.get('artifact_key') or '',
                'tablename': entry.get('tablename') or '',
                'module': entry.get('module') or '',
                'columns': columns,
                'record_count': int(entry.get('record_count') or 0),
                'source_path': (entry.get('source_path') or '').replace(
                    '\\', '/'),
                'conversation': conversation or None,
                'icon': entry.get('artifact_icon') or ''})
    return {'status': data.get('processing_status') or '',
            'tool': info.get('leapp_name') or '',
            'version': info.get('leapp_version') or '',
            'started': _stamp(info.get('start_timestamp')),
            'finished': _stamp(info.get('end_timestamp')),
            'schema': schema,
            'artifacts': artifacts,
            'modules': data.get('modules') or []}


def _stamp(value):
    try:
        return datetime.datetime.fromtimestamp(
            float(value), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OverflowError, OSError):
        return ''


def utc_text(value):
    """A LAVA datetime (UTC epoch seconds) as TRACE writes UTC times,
    '' for none; fractions kept to the microsecond."""
    if value in (None, ''):
        return ''
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return str(value)
    try:
        moment = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) \
            + datetime.timedelta(seconds=seconds)
    except OverflowError:
        return str(value)
    text = moment.strftime('%Y-%m-%d %H:%M:%S')
    if moment.microsecond:
        text += f'.{moment.microsecond:06d}'.rstrip('0')
    return text


def rows(connection, artifact, offset=0, limit=500, order=None,
         after=None):
    """[(rowid, {column: value})] of one artifact, `limit` from `offset`
    -- or, in rowid order, the `limit` after rowid `after`: what to page a
    big table by. OFFSET steps over every row before it, so paging a
    21-million-row table by offset is quadratic (hours)."""
    names = [column['name'] for column in artifact['columns']]
    table = artifact['tablename'].replace('"', '""')
    quoted = ', '.join('"' + name.replace('"', '""') + '"' for name in names)
    query = f'SELECT rowid, {quoted} FROM "{table}"'
    if after is not None and not order:
        query += ' WHERE rowid > ? ORDER BY rowid LIMIT ?'
        args = (after, limit)
    else:
        if order:
            query += ' ORDER BY "' + order.replace('"', '""') + '"'
        else:
            query += ' ORDER BY rowid'
        query += ' LIMIT ? OFFSET ?'
        args = (limit, offset)
    out = []
    for row in connection.execute(query, args):
        out.append((row[0], {name: row[index + 1]
                             for index, name in enumerate(names)}))
    return out


def iter_rows(connection, artifact, batch=2000):
    """Every (rowid, {column: value}) of an artifact, in rowid order, a
    batch at a time."""
    after = -2 ** 63
    while True:
        page = rows(connection, artifact, limit=batch, after=after)
        if not page:
            return
        yield from page
        after = page[-1][0]


def row(connection, artifact, rowid):
    """{column: value} of one row, or None."""
    names = [column['name'] for column in artifact['columns']]
    table = artifact['tablename'].replace('"', '""')
    quoted = ', '.join('"' + name.replace('"', '""') + '"' for name in names)
    found = connection.execute(
        f'SELECT {quoted} FROM "{table}" WHERE rowid = ?',
        (rowid,)).fetchone()
    return None if found is None else {name: found[index]
                                       for index, name in enumerate(names)}


def source_path(artifact, values, media_items):
    """Where a row came from in the tool's input: its media file when it
    has one, else the file its artifact read."""
    for column in artifact['columns']:
        if column.get('type') == 'media' and values.get(column['name']):
            item = media_items.get(values[column['name']])
            if item and item.get('source_path'):
                return item['source_path']
    return artifact.get('source_path') or ''


def count(connection, artifact):
    table = artifact['tablename'].replace('"', '""')
    return connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]


def media(connection):
    """{media ref id: {'source_path', 'extraction_path', 'type', 'name'}}."""
    try:
        found = connection.execute(
            "SELECT media_ref_id, source_path, extraction_path, type, name "
            "FROM _lava_media_info")
    except sqlite3.Error:
        return {}
    return {row['media_ref_id']: {
        'source_path': (row['source_path'] or '').replace('\\', '/'),
        'extraction_path': (row['extraction_path'] or '').replace('\\', '/'),
        'type': row['type'] or '', 'name': row['name'] or ''}
        for row in found}


def display(column, value, media_items=None):
    """A cell as text: times in UTC, media by name."""
    kind = column.get('type')
    if kind == 'datetime':
        return utc_text(value)
    if kind == 'media' and value not in (None, ''):
        item = (media_items or {}).get(value)
        if item:
            return item['name'] or os.path.basename(item['source_path'])
    return '' if value is None else str(value)

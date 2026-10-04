"""The Windows Search index: what Windows indexed, and the thumbnail cache
id of each file it holds a picture of.

* Windows.edb (Vista to Windows 10, and 11 before 22H2): an ESE database,
  read through libesedb from a file object -- an index is often gigabytes,
  so it is never read into memory whole. Properties are columns, named
  'System_ItemPathDisplay' (Windows 7) or with a number before it,
  '4447-System_ItemPathDisplay' (8 and later), in SystemIndex_0A or
  SystemIndex_PropertyStore.
* Windows.db (Windows 11 22H2 and later): SQLite, one row per property
  (WorkId, ColumnId, Value), the column names in
  SystemIndex_1_PropertyStore_Metadata.

Times are FILETIMEs and sizes integers, both stored as little-endian bytes.
System_ThumbnailCacheId is the 64-bit id a thumbcache_*.db entry carries --
little-endian, the value TRACE shows for a thumbcache entry (checked on a
Windows 11 machine whose thumbnail cache and index were both published).

Locations: ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\
(and Documents and Settings\\All Users\\Application Data\\... on XP),
and per user under AppData\\Roaming\\Microsoft\\Search\\Data\\Applications\\
<SID>\\ on servers.

No Qt here.
"""

import logging
import posixpath

from trace_app.core.activity import times

logger = logging.getLogger('TRACE.WindowsSearch')

#: The properties read, by their name without the numeric prefix.
PROPERTIES = ('System_ThumbnailCacheId', 'System_ItemPathDisplay',
              'System_DateModified', 'System_DateCreated',
              'System_DateAccessed', 'System_Search_GatherTime',
              'System_Size', 'System_MIMEType', 'System_ItemTypeText',
              'System_Search_AutoSummary', 'System_ItemType',
              'System_Search_Store')
_TIMES = ('System_DateModified', 'System_DateCreated', 'System_DateAccessed',
          'System_Search_GatherTime')
_TEXT_TYPES = (10, 12)            # ESE text and long text


class WindowsSearchError(Exception):
    pass


def is_index_path(path):
    lower = path.lower().replace('\\', '/')
    return '/microsoft/search/data/applications/' in lower and \
        lower.rsplit('/', 1)[-1] in ('windows.edb', 'windows.db')


def _int(value):
    return int.from_bytes(value, 'little') if isinstance(value, bytes) \
        else value


def _item(values):
    """One indexed item as plain values."""
    item = {'path': values.get('System_ItemPathDisplay') or '',
            'size': _int(values.get('System_Size')),
            'type': (values.get('System_MIMEType')
                     or values.get('System_ItemTypeText') or ''),
            'summary': values.get('System_Search_AutoSummary') or '',
            'store': values.get('System_Search_Store') or '',
            'item_type': values.get('System_ItemType') or ''}
    for key in _TIMES:
        value = _int(values.get(key))
        item[key[7:].lower()] = times.filetime(value) if value else None
    cache_id = values.get('System_ThumbnailCacheId')
    item['cache_id'] = f'{_int(cache_id):016x}' \
        if isinstance(cache_id, bytes) and len(cache_id) == 8 else None
    if isinstance(item['summary'], bytes):
        item['summary'] = item['summary'].decode('utf-16-le', 'replace') \
            .rstrip('\x00')
    if isinstance(item['size'], bytes) or (item['size'] or 0) > 1 << 50:
        item['size'] = None          # folders carry no real size
    return item


def _ese_items(stream):
    import pyesedb
    database = pyesedb.file()
    try:
        database.open_file_object(stream)
    except (IOError, OSError) as exc:
        raise WindowsSearchError(f"Not a readable Windows.edb: {exc}") from exc
    try:
        names = [database.get_table(i).name
                 for i in range(database.number_of_tables)]
        table_name = next((n for n in ('SystemIndex_PropertyStore',
                                       'SystemIndex_0A') if n in names), None)
        if table_name is None:
            raise WindowsSearchError("No property store in this Windows.edb")
        table = database.get_table_by_name(table_name)
        columns = {}
        for index in range(table.number_of_columns):
            column = table.get_column(index)
            name = column.name.split('-', 1)[-1]
            if name in PROPERTIES:
                columns[name] = (index, column.type)
        for number in range(table.number_of_records):
            try:
                record = table.get_record(number)
            except (IOError, OSError) as exc:
                logger.debug("Record %s unreadable: %s", number, exc)
                continue
            values = {}
            for name, (index, kind) in columns.items():
                try:
                    if kind in _TEXT_TYPES:
                        value = record.get_value_data_as_string(index)
                    else:
                        value = record.get_value_data(index)
                except (IOError, OSError, UnicodeError):
                    value = None
                if value:
                    values[name] = value
            if values:
                yield _item(values)
    finally:
        database.close()


def _sqlite_items(data, wal=None):
    from trace_app.core.activity import sqlite_bytes
    with sqlite_bytes.open_database(data, wal) as db:
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not {'SystemIndex_1_PropertyStore',
                'SystemIndex_1_PropertyStore_Metadata'} <= tables:
            raise WindowsSearchError("No property store in this Windows.db")
        wanted = {}
        for column_id, key in db.execute(
                "SELECT Id, UniqueKey FROM "
                "SystemIndex_1_PropertyStore_Metadata"):
            name = (key or '').split('-', 1)[-1]
            if name in PROPERTIES:
                wanted[column_id] = name
        if not wanted:
            return
        marks = ','.join('?' * len(wanted))
        current, values = None, {}
        for work_id, column_id, value in db.execute(
                "SELECT WorkId, ColumnId, Value FROM "
                f"SystemIndex_1_PropertyStore WHERE ColumnId IN ({marks}) "
                "ORDER BY WorkId", list(wanted)):
            if work_id != current:
                if values:
                    yield _item(values)
                current, values = work_id, {}
            if value is not None and value != b'':
                values[wanted[column_id]] = value
        if values:
            yield _item(values)


def items(source, kind=None, wal=None):
    """Every indexed item. `source` is a file object (a Windows.edb read
    from the image) or bytes; `kind` 'edb' or 'db', else from the header."""
    if kind is None:
        header = source[:16] if isinstance(source, (bytes, bytearray)) \
            else _peek(source)
        kind = 'db' if header.startswith(b'SQLite format 3') else 'edb'
    if kind == 'db':
        data = source if isinstance(source, (bytes, bytearray)) \
            else _read_all(source)
        return _sqlite_items(data, wal)
    if isinstance(source, (bytes, bytearray)):
        import io
        source = io.BytesIO(source)
    return _ese_items(source)


def _peek(stream):
    stream.seek(0)
    header = stream.read(16)
    stream.seek(0)
    return header


def _read_all(stream):
    stream.seek(0)
    return stream.read()


def cache_index(source, kind=None, wal=None):
    """{thumbnail cache id: indexed item} for the items holding one."""
    out = {}
    for item in items(source, kind, wal):
        if item['cache_id']:
            out[item['cache_id']] = item
    return out


def volume_path(windows_path):
    """'C:\\Users\\a\\x.jpg' -> ('c', '/Users/a/x.jpg'); (None, None) for
    what is not a drive path."""
    if len(windows_path) > 2 and windows_path[1] == ':':
        rest = windows_path[2:].replace('\\', '/')
        # normpath keeps a leading '//' (POSIX allows it): strip first.
        return windows_path[0].lower(), posixpath.normpath(
            '/' + rest.lstrip('/'))
    return None, None

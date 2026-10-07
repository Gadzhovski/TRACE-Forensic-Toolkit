"""Windows' ESE (Extensible Storage Engine) databases: SRUM and WebCache.

* SRUM (Windows\\System32\\sru\\SRUDB.dat, Windows 8+): about 30 days, an
  hour at a time, of what each application did -- CPU cycles in the
  foreground and background, bytes read and written -- how many bytes it
  sent and received on which network, when the machine was connected to
  which network, and battery use. Per user.
* WebCache (each profile's AppData\\Local\\Microsoft\\Windows\\WebCache\\
  WebCacheV01.dat, IE 10+ and legacy Edge): history, downloads and the
  cache, in containers named by what they hold.

Read with libesedb from bytes, never from a file on disk. The database is
read as last flushed: an unclean one (the machine was running) can lack its
newest pages, which live in the .jrs/.log files beside it and are not
replayed.
"""

import datetime
import io
import logging
import struct

from trace_app.core.activity import times

logger = logging.getLogger('TRACE.Activity.ESE')

# ESE column types (libesedb's numbering).
_BOOLEAN, _UINT8, _INT16, _INT32, _CURRENCY, _FLOAT32, _DOUBLE, _DATETIME, \
    _BINARY, _TEXT, _LONG_BINARY, _LONG_TEXT, _SUPER_LONG, _UINT32, _INT64, \
    _GUID, _UINT16 = range(1, 18)

_OLE_EPOCH = datetime.datetime(1899, 12, 30, tzinfo=datetime.timezone.utc)


def open_database(data):
    import pyesedb
    database = pyesedb.file()
    database.open_file_object(io.BytesIO(data))
    return database


def _value(record, index, column_type):
    """A record's value as Python, by its column type."""
    try:
        if record.is_long_value(index):
            long_value = record.get_value_data_as_long_value(index)
            raw = long_value.get_data() if long_value is not None else None
            if raw is None:
                return None
            return raw.decode('utf-16-le', 'replace').rstrip('\x00') \
                if column_type in (_LONG_TEXT, _TEXT) else raw
        raw = record.get_value_data(index)
    except (OSError, IOError):
        return None
    if raw is None:
        return None
    if column_type in (_TEXT, _LONG_TEXT):
        try:
            return record.get_value_data_as_string(index)
        except (OSError, IOError, UnicodeDecodeError):
            return raw.decode('utf-16-le', 'replace').rstrip('\x00')
    if column_type == _DATETIME and len(raw) == 8:
        return ole_date(struct.unpack('<d', raw)[0])
    if column_type == _DOUBLE and len(raw) == 8:
        return struct.unpack('<d', raw)[0]
    if column_type == _FLOAT32 and len(raw) == 4:
        return struct.unpack('<f', raw)[0]
    if column_type in (_BOOLEAN, _UINT8, _INT16, _INT32, _UINT32, _INT64,
                       _UINT16, _CURRENCY):
        signed = column_type in (_INT16, _INT32, _INT64, _CURRENCY)
        return int.from_bytes(raw, 'little', signed=signed)
    return raw


def rows(table):
    """Every record of a table as a dict, column name -> value."""
    columns = [(column.name, column.type) for column in table.columns]
    for record in table.records:
        yield {name: _value(record, index, kind)
               for index, (name, kind) in enumerate(columns)}


def ole_date(days):
    """An OLE Automation date (days since 1899-12-30) as UTC."""
    if not days or days <= 0:
        return None
    try:
        return _OLE_EPOCH + datetime.timedelta(days=days)
    except OverflowError:
        return None


def sid_text(blob):
    """'S-1-5-21-...' from a binary SID."""
    if not blob or len(blob) < 8:
        return ''
    revision, count = blob[0], blob[1]
    authority = int.from_bytes(blob[2:8], 'big')
    parts = [str(struct.unpack_from('<I', blob, 8 + 4 * i)[0])
             for i in range(count) if 8 + 4 * i + 4 <= len(blob)]
    return '-'.join(['S', str(revision), str(authority)] + parts)


# --- SRUM ---------------------------------------------------------------------

SRUM_APPLICATIONS = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'
SRUM_NETWORK_USAGE = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'
SRUM_CONNECTIVITY = '{DD6636C4-8929-4683-974E-22C046A43763}'
SRUM_ENERGY = '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT'


def srum_ids(database):
    """{IdIndex: name or SID} from SruDbIdMapTable."""
    table = database.get_table_by_name('SruDbIdMapTable')
    out = {}
    if table is None:
        return out
    for row in rows(table):
        blob = row.get('IdBlob')
        if not isinstance(blob, (bytes, bytearray)):
            continue
        if row.get('IdType') == 3:
            out[row['IdIndex']] = sid_text(blob)
        else:
            out[row['IdIndex']] = blob.decode('utf-16-le', 'replace') \
                .rstrip('\x00')
    return out


def srum(data):
    """[{'table', 'id', 'recorded', 'application', 'user', ...}] from an
    SRUDB.dat: application resource use, network use, connectivity and
    energy use. `recorded` is the end of the hour SRUM summarised."""
    database = open_database(data)
    names = srum_ids(database)

    def name(value):
        return names.get(value, value)

    out = []
    for table_name, kind in ((SRUM_NETWORK_USAGE, 'network'),
                             (SRUM_APPLICATIONS, 'application'),
                             (SRUM_CONNECTIVITY, 'connectivity'),
                             (SRUM_ENERGY, 'energy')):
        table = database.get_table_by_name(table_name)
        if table is None:
            continue
        for row in rows(table):
            entry = {'table': kind, 'id': row.get('AutoIncId'),
                     'recorded': row.get('TimeStamp'),
                     'application': name(row.get('AppId')),
                     'user': name(row.get('UserId'))}
            if kind == 'network':
                entry.update(bytes_sent=row.get('BytesSent'),
                             bytes_received=row.get('BytesRecvd'),
                             interface=row.get('InterfaceLuid'),
                             profile=row.get('L2ProfileId'))
            elif kind == 'application':
                entry.update(
                    foreground_cycles=row.get('ForegroundCycleTime'),
                    background_cycles=row.get('BackgroundCycleTime'),
                    foreground_read=row.get('ForegroundBytesRead'),
                    foreground_written=row.get('ForegroundBytesWritten'),
                    background_read=row.get('BackgroundBytesRead'),
                    background_written=row.get('BackgroundBytesWritten'),
                    face_time=row.get('FaceTime'))
            elif kind == 'connectivity':
                entry.update(connected_seconds=row.get('ConnectedTime'),
                             connected_since=times.filetime(
                                 row.get('ConnectStartTime') or 0),
                             interface=row.get('InterfaceLuid'),
                             profile=row.get('L2ProfileId'))
            else:
                entry.update(active_ac=row.get('ActiveAcTime'),
                             active_dc=row.get('ActiveDcTime'),
                             energy=row.get('ActiveEnergy'))
            out.append(entry)
    return out


# --- WebCache -------------------------------------------------------------------

_HISTORY = ('history', 'mshist')


def webcache(data):
    """[{'kind', 'container', 'url', 'user', 'accessed', 'modified',
    'created', 'expires', 'hits', 'filename', 'size', 'directory'}] from a
    WebCacheV01.dat. kind is 'visit', 'download' or 'cache'."""
    database = open_database(data)
    table = database.get_table_by_name('Containers')
    if table is None:
        return []
    out = []
    for container in rows(table):
        label = (container.get('Name') or '').strip('\x00')
        lowered = label.lower()
        if lowered.startswith(_HISTORY):
            kind = 'visit'
        elif lowered == 'iedownload' or lowered.endswith('downloadhistory'):
            kind = 'download'
        elif lowered == 'content':
            kind = 'cache'
        else:
            continue                     # cookies, DOM storage, compat lists
        entries = database.get_table_by_name(
            f"Container_{container.get('ContainerId')}")
        if entries is None:
            continue
        directory = (container.get('Directory') or '').strip('\x00')
        for row in rows(entries):
            url = (row.get('Url') or '').strip('\x00')
            if not url:
                continue
            user = ''
            if kind == 'visit' and ':' in url and '@' in url.split('://')[0]:
                # 'Visited: user@https://...' -- who, then where.
                prefix, _, rest = url.partition(': ')
                user, _, url = rest.partition('@') if '@' in rest \
                    else ('', '', rest)
            out.append({
                'kind': kind, 'container': container.get('ContainerId'),
                'entry': row.get('EntryId'), 'url': url, 'user': user,
                'accessed': times.filetime(row.get('AccessedTime') or 0),
                'modified': times.filetime(row.get('ModifiedTime') or 0),
                'created': times.filetime(row.get('CreationTime') or 0),
                'expires': times.filetime(row.get('ExpiryTime') or 0),
                'hits': row.get('AccessCount'),
                'filename': (row.get('Filename') or '').strip('\x00'),
                'size': row.get('FileSize'), 'directory': directory})
    return out

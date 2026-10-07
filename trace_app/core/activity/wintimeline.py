"""Windows Timeline (Windows 10 1803+): ActivitiesCache.db.

Each user's AppData\\Local\\ConnectedDevicesPlatform\\<account>\\
ActivitiesCache.db records the applications and documents used --
ActivityType 5 is "opened" (with what was opened, when the app reports
it), 6 is "in use" with how long the user was active in it. Times are Unix
seconds, UTC; the payload says the user's time zone.

Also: Internet Explorer's index.dat caches (Windows XP to 8), through
libmsiecf -- History.IE5 (visits), its daily/weekly MSHist folders, and
Content.IE5 (the cache).
"""

import io
import json
import logging

from trace_app.core.activity import sqlite_bytes, times

logger = logging.getLogger('TRACE.Activity.Timeline')

_TYPES = {5: 'opened', 6: 'in use', 10: 'clipboard', 16: 'copied/pasted'}


def _application(app_id):
    """The program from the AppId JSON list: a Win32 path or package name."""
    try:
        entries = json.loads(app_id or '[]')
    except ValueError:
        return app_id or ''
    preferred = ('windows_win32', 'x_exe_path', 'windows_universal',
                 'packageId')
    by_platform = {e.get('platform'): e.get('application') for e in entries
                   if isinstance(e, dict) and e.get('application')}
    for platform in preferred:
        if by_platform.get(platform):
            return by_platform[platform]
    return next(iter(by_platform.values()), '')


def activities(data, wal=None):
    """[{'type', 'kind', 'application', 'started', 'ended', 'modified',
    'display', 'description', 'content', 'active_seconds', 'time_zone',
    'device', 'status'}] from an ActivitiesCache.db."""
    with sqlite_bytes.open_database(data, wal) as connection:
        columns = {row[1] for row in connection.execute(
            "PRAGMA table_info(Activity)")}
        clipboard = 'ClipboardPayload' if 'ClipboardPayload' in columns \
            else 'NULL'
        rows = connection.execute(
            "SELECT ActivityType, AppId, StartTime, EndTime, "
            "LastModifiedTime, Payload, PlatformDeviceId, ActivityStatus, "
            f"{clipboard} FROM Activity").fetchall()
    out = []
    for (kind, app_id, start, end, modified, payload, device, status,
         copied) in rows:
        try:
            facts = json.loads(payload) if payload else {}
        except (ValueError, TypeError):
            facts = {}
        if not isinstance(facts, dict):
            facts = {}
        out.append({
            'type': kind, 'kind': _TYPES.get(kind, f'type {kind}'),
            'application': _application(app_id),
            'started': times.unix(start), 'ended': times.unix(end),
            'modified': times.unix(modified),
            'display': facts.get('appDisplayName') or '',
            'description': facts.get('displayText') or facts.get(
                'description') or '',
            'content': facts.get('contentUri') or facts.get(
                'activationUri') or '',
            'active_seconds': facts.get('activeDurationSeconds'),
            'time_zone': facts.get('userTimezone') or '',
            'device': device or '', 'status': status,
            'clipboard': bool(copied)})
    return out


# --- Internet Explorer index.dat ----------------------------------------------

def index_dat(data, kind):
    """[{'url', 'user', 'when', 'second', 'hits', 'filename', 'size',
    'record'}] from an index.dat. `kind` is 'history' (History.IE5 itself:
    both times UTC, the primary is the last visit), 'daily' (MSHist
    folders: the primary is local time, the secondary UTC) or 'cache'
    (Content.IE5: last access, then the file's modification)."""
    import pymsiecf
    cache = pymsiecf.file()
    cache.open_file_object(io.BytesIO(data))
    out = []
    try:
        for index in range(cache.number_of_items):
            try:
                item = cache.get_item(index)
            except (OSError, IOError):
                continue
            location = getattr(item, 'location', None)
            if not location:
                continue
            record = type(item).__name__
            user, url = '', location
            if location.startswith(('Visited: ', ':')) or (
                    ': ' in location and '@' in location.split('://')[0]):
                _prefix, _, rest = location.partition(': ')
                if '@' in rest:
                    user, _, url = rest.partition('@')
            primary = _filetime(item, 'primary')
            secondary = _filetime(item, 'secondary')
            when = secondary if kind == 'daily' else primary
            out.append({'url': url, 'user': user, 'when': when,
                        'second': secondary if kind == 'cache' else None,
                        'hits': getattr(item, 'number_of_hits', None),
                        'filename': getattr(item, 'filename', '') or '',
                        'size': getattr(item, 'cached_file_size', None),
                        'record': record})
    finally:
        cache.close()
    return out


def _filetime(item, which):
    try:
        value = getattr(item, f'get_{which}_time_as_integer')()
    except (AttributeError, OSError, IOError):
        return None
    return times.filetime(value)

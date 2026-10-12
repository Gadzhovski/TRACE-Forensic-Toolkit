"""What web pages and desktop apps kept in a Chromium profile's storage.

Local Storage and Session Storage are LevelDB databases (core/leveldb.py)
in every Chromium browser profile and in every Electron app -- Teams,
Slack, Discord, Signal, WhatsApp Desktop -- which is where such an app
keeps its signed-in account, settings and, often, its recent state.
IndexedDB (core/indexeddb.py) holds the larger stores -- an app's
messages, a site's offline data -- and each of its records is listed too,
its value as the page's JavaScript held it (core/v8_values.py).

Each value is a record of category 'web': its origin, key and value, and
whether it is current, was overwritten, or was deleted -- LevelDB keeps an
old value until it compacts its files, so a deleted key's value (a closed
tab's Session Storage, a signed-out app's token) is often still there.
LevelDB records no times; the records say so.

Local Storage keys are '_' + origin + NUL + the script's key, and keys
and values start with an encoding byte: 0 for UTF-16LE, 1 for Latin-1.
Session Storage maps 'namespace-<id>-<origin>' to a map id and keeps
'map-<id>-<key>' = the value in UTF-16LE.
"""

import logging

from trace_app.core import leveldb

logger = logging.getLogger('TRACE.ChromiumStorage')

#: Largest database file read (a busy app's IndexedDB can be gigabytes).
MAX_FILE_BYTES = 256 * 1024 * 1024
#: Characters of a value kept in a record.
VALUE_CHARACTERS = 2000
#: IndexedDB records listed per database (a chat app's can hold millions).
MAX_RECORDS_PER_DATABASE = 20000
BASIS = "LevelDB records no time: when a value was written is not known"

#: Electron apps' Chromium profile folders, per system, below the home.
ELECTRON_APPS = {
    'Teams': (
        ('AppData', 'Local', 'Packages', 'MSTeams_8wekyb3d8bbwe', 'LocalCache',
         'Microsoft', 'MSTeams', 'EBWebView', 'Default'),
        ('AppData', 'Roaming', 'Microsoft', 'Teams'),
        ('Library', 'Containers', 'com.microsoft.teams2', 'Data', 'Library',
         'Application Support', 'Microsoft', 'MSTeams', 'EBWebView',
         'Default'),
        ('Library', 'Application Support', 'Microsoft', 'Teams'),
        ('.config', 'Microsoft', 'Microsoft Teams')),
    'Slack': (
        ('AppData', 'Roaming', 'Slack'),
        ('Library', 'Application Support', 'Slack'),
        ('Library', 'Containers', 'com.tinyspeck.slackmacgap', 'Data',
         'Library', 'Application Support', 'Slack'),
        ('.config', 'Slack')),
    'Discord': (
        ('AppData', 'Roaming', 'discord'),
        ('Library', 'Application Support', 'discord'),
        ('.config', 'discord')),
    'Signal': (
        ('AppData', 'Roaming', 'Signal'),
        ('Library', 'Application Support', 'Signal'),
        ('.config', 'Signal')),
    'WhatsApp Desktop': (
        ('AppData', 'Roaming', 'WhatsApp'),
        ('Library', 'Application Support', 'WhatsApp')),
    'Skype': (
        ('AppData', 'Roaming', 'Microsoft', 'Skype for Desktop'),
        ('Library', 'Application Support', 'Microsoft', 'Skype for Desktop'),
        ('.config', 'skypeforlinux')),
    'Element': (
        ('AppData', 'Roaming', 'Element'),
        ('Library', 'Application Support', 'Element'),
        ('.config', 'Element')),
}


def script_text(raw):
    """A Local Storage key or value: its encoding byte, then the text."""
    if raw[:1] == b'\x00':
        return raw[1:].decode('utf-16-le', 'replace')
    if raw[:1] == b'\x01':
        return raw[1:].decode('latin-1')
    return raw.decode('utf-8', 'replace')


def _state(record, versions):
    newest = versions[-1]
    if record is newest:
        return 'current'
    if newest.deleted:
        return 'deleted (still in the database)'
    return 'overwritten (still in the database)'


def _by_key(records):
    out = {}
    for record in records:
        out.setdefault(record.key, []).append(record)
    for versions in out.values():
        versions.sort(key=lambda r: r.sequence)
    return out


def local_storage(records):
    """[{'origin', 'key', 'value', 'state', 'sequence'}] -- every value
    the database holds, the current one and those before it."""
    out = []
    for key, versions in _by_key(records).items():
        if not key.startswith(b'_') or b'\x00' not in key:
            continue
        origin, script_key = key[1:].split(b'\x00', 1)
        for record in versions:
            if record.deleted:
                continue
            out.append({'origin': origin.decode('utf-8', 'replace'),
                        'key': script_text(script_key),
                        'value': script_text(record.value),
                        'state': _state(record, versions),
                        'sequence': record.sequence})
        if versions[-1].deleted and all(r.deleted for r in versions):
            out.append({'origin': origin.decode('utf-8', 'replace'),
                        'key': script_text(script_key), 'value': None,
                        'state': 'deleted (its value is gone)',
                        'sequence': versions[-1].sequence})
    return out


def session_storage(records):
    """The same for Session Storage: map entries named by their origin."""
    origins = {}
    for record in records:
        key = record.key
        if key.startswith(b'namespace-') and record.value and \
                not record.deleted:
            rest = key[len(b'namespace-'):]
            if b'-' in rest:
                origin = rest.split(b'-', 1)[1]
                origins[record.value] = origin.decode('utf-8', 'replace')
    out = []
    for key, versions in _by_key(records).items():
        if not key.startswith(b'map-'):
            continue
        parts = key.split(b'-', 2)
        if len(parts) < 3:
            continue
        map_id, script_key = parts[1], parts[2]
        for record in versions:
            if record.deleted:
                continue
            out.append({'origin': origins.get(map_id, f"map {map_id.decode()}"),
                        'key': script_key.decode('utf-8', 'replace'),
                        'value': record.value.decode('utf-16-le', 'replace'),
                        'state': _state(record, versions),
                        'sequence': record.sequence})
    return out


def has_storage(volume, profile_parts):
    return any(volume.find(*profile_parts, *sub) is not None for sub in (
        ('Local Storage', 'leveldb'), ('Session Storage',), ('IndexedDB',)))


# --- from a volume -------------------------------------------------------------------

def database_files(volume, folder):
    """[(name, bytes)] of a LevelDB folder's .log and table files, and the
    ref of the first (where a record points)."""
    files, ref = [], ''
    for entry in volume.children(folder):
        if entry.is_dir or not entry.name.lower().endswith(
                ('.log', '.ldb', '.sst')):
            continue
        if entry.size and entry.size > MAX_FILE_BYTES:
            logger.info("%s skipped: %d bytes", entry.path, entry.size)
            continue
        try:
            files.append((entry.name, volume.read(entry)))
        except Exception as exc:
            logger.debug("%s unreadable: %s", entry.path, exc)
            continue
        ref = ref or volume.ref(entry)
    return files, ref


def indexeddb_records(volume, profile_parts, app, user, step):
    """Every IndexedDB record of one Chromium profile folder."""
    from trace_app.core import indexeddb, v8_values
    from trace_app.core.activity import record
    out = []
    folder = volume.find(*profile_parts, 'IndexedDB')
    for database in volume.children(folder, dirs=True):
        if not database.name.lower().endswith('.indexeddb.leveldb'):
            continue
        step(database.path)
        files, ref = database_files(volume, database)
        if not files:
            continue
        items = indexeddb.object_records(
            leveldb.records_from_files(files))
        if len(items) > MAX_RECORDS_PER_DATABASE:
            logger.info("%s: %d records, the first %d listed",
                        database.path, len(items), MAX_RECORDS_PER_DATABASE)
            items = items[:MAX_RECORDS_PER_DATABASE]
        site = database.name[:-len('.indexeddb.leveldb')]
        for item in items:
            key = v8_values.to_text(item['key'], 200)
            detail = {'origin': site, 'database': item['database'],
                      'store': item['store'],
                      'value': v8_values.to_text(item['value'],
                                                 VALUE_CHARACTERS)
                      if 'error' not in item else None,
                      'unreadable': item.get('error'),
                      'state': item['state'], 'sequence': item['sequence'],
                      'basis': BASIS}
            what = 'Stored record' if item['state'] == 'current' else \
                f"Stored record ({item['state']}, still in the database)"
            out.append(record('web', f"IndexedDB ({app})", None, what,
                              f"{item['database']} / {item['store']} / {key}",
                              detail, user=user, path=database.path,
                              ref=ref))
    return out


def profile_records(volume, profile_parts, app, user, step):
    """Local Storage, Session Storage and IndexedDB of one Chromium
    profile folder."""
    from trace_app.core.activity import record
    out = indexeddb_records(volume, profile_parts, app, user, step)
    for sub, reader, label in (
            (('Local Storage', 'leveldb'), local_storage, 'Local Storage'),
            (('Session Storage',), session_storage, 'Session Storage')):
        folder = volume.find(*profile_parts, *sub)
        if folder is None:
            continue
        step(folder.path)
        files, ref = database_files(volume, folder)
        if not files:
            continue
        for item in reader(leveldb.records_from_files(files)):
            value = item['value']
            if value is None:
                value_text = None
            else:
                value_text = value[:VALUE_CHARACTERS] + \
                    ('…' if len(value) > VALUE_CHARACTERS else '')
            detail = {'origin': item['origin'], 'value': value_text,
                      'state': item['state'], 'sequence': item['sequence'],
                      'basis': BASIS}
            what = 'Stored value' if item['state'] == 'current' else \
                'Stored value (' + item['state'].split(' (')[0] + ')'
            out.append(record('web', f"{label} ({app})", None, what,
                              item['key'], detail, user=user,
                              path=folder.path, ref=ref))
    return out

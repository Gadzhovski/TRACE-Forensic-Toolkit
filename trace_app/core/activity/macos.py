"""What the users of a Mac did, from the databases and plists macOS keeps.

* KnowledgeC.db (CoreDuet, 10.13+; /private/var/db/CoreDuet/Knowledge and
  each user's Library/Application Support/Knowledge): which application was
  in use, from when to when; Safari pages seen.
* QuarantineEventsV2 (each user's Library/Preferences): every download
  marked with the quarantine flag -- what fetched it, from where.
* Shared file lists (.sfl2 / .sfl3, Library/Application Support/
  com.apple.sharedfilelist): recent documents, applications, servers and
  volumes, most recent first, as bookmarks (activity/macbookmark.py);
  com.apple.recentitems.plist on older systems.
* InstallHistory.plist (/Library/Receipts): every system update and
  package installed.
* utmpx (/private/var/run/utmpx): logons, logoffs and boots.
* Each user's TCC, Notification Center, Internet accounts, Notes, Dock,
  Launchpad, CFURL caches, saved application state and Terminal window
  text, Screen Sharing hosts and Trash (activity/macos_sqlite, macos_plists,
  macos_state); the system's netusage, XProtect behaviour database, Screen
  Time, file sharing, sharing services, Remote Management and sudo.
  Notification Center, Screen Time and Launchpad keep their databases in
  /private/var/folders/xx/<random>/0 (`_var_folders`).

Times are Cocoa (seconds since 2001) and UTC. Expected values in the tests
are plaso's for the same files.
"""

import datetime
import logging
import plistlib
import struct

from trace_app.core.activity import macbookmark, record, sqlite_bytes, times

logger = logging.getLogger('TRACE.Activity.macOS')


# --- KnowledgeC ------------------------------------------------------------------------

def knowledgec(data, wal=None):
    """[{'stream', 'value', 'title', 'start', 'end', 'created', 'seconds'}]
    for app use (/app/inFocus) and Safari history (/safari/history)."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        columns = {row[1] for row in db.execute(
            "PRAGMA table_info(ZSTRUCTUREDMETADATA)")}
        title = ("ZSTRUCTUREDMETADATA.Z_DKSAFARIHISTORYMETADATAKEY__TITLE"
                 if 'Z_DKSAFARIHISTORYMETADATAKEY__TITLE' in columns
                 else 'NULL')
        rows = db.execute(
            "SELECT ZOBJECT.ZCREATIONDATE, ZOBJECT.ZSTARTDATE, "
            "ZOBJECT.ZENDDATE, ZOBJECT.ZSTREAMNAME, ZOBJECT.ZVALUESTRING, "
            f"{title} FROM ZOBJECT LEFT JOIN ZSTRUCTUREDMETADATA ON "
            "ZOBJECT.ZSTRUCTUREDMETADATA = ZSTRUCTUREDMETADATA.Z_PK "
            "ORDER BY ZOBJECT.Z_PK")
        for created, start, end, stream, value, page_title in rows:
            stream = stream or ''
            if not stream.startswith(('/app/', '/safari/')):
                continue
            out.append({'stream': stream, 'value': value or '',
                        'title': page_title or '',
                        'created': times.mac_absolute(created),
                        'start': times.mac_absolute(start),
                        'end': times.mac_absolute(end),
                        'seconds': int(end - start) if start and end
                        else None})
    return out


def knowledgec_activity(data, wal, user, path, ref):
    out = []
    for item in knowledgec(data, wal):
        if item['stream'].startswith('/safari/'):
            out.append(record('browser', 'KnowledgeC', item['start'],
                              'Page seen in Safari', item['value'],
                              {'title': item['title'],
                               'recorded': item['created']},
                              user=user, path=path, ref=ref))
        else:
            out.append(record('usage', 'KnowledgeC', item['start'],
                              'Application in use', item['value'],
                              {'stream': item['stream'],
                               'until': item['end'],
                               'seconds': item['seconds'],
                               'recorded': item['created']},
                              user=user, path=path, ref=ref))
    return out


# --- quarantine events ------------------------------------------------------------------

def quarantine(data, wal=None):
    with sqlite_bytes.open_database(data, wal) as db:
        columns = {row[1] for row in db.execute(
            "PRAGMA table_info(LSQuarantineEvent)")}
        if 'LSQuarantineTimeStamp' not in columns:
            return []
        wanted = [c for c in ('LSQuarantineTimeStamp', 'LSQuarantineAgentName',
                              'LSQuarantineAgentBundleIdentifier',
                              'LSQuarantineDataURLString',
                              'LSQuarantineOriginURLString',
                              'LSQuarantineSenderName',
                              'LSQuarantineSenderAddress',
                              'LSQuarantineTypeNumber',
                              'LSQuarantineEventIdentifier')
                  if c in columns]
        rows = db.execute(f"SELECT {', '.join(wanted)} FROM "
                          "LSQuarantineEvent ORDER BY rowid")
        return [dict(zip(wanted, row)) for row in rows]


def quarantine_activity(data, wal, user, path, ref):
    out = []
    for row in quarantine(data, wal):
        url = row.get('LSQuarantineDataURLString') or ''
        out.append(record(
            'downloads', 'Quarantine events',
            times.mac_absolute(row.get('LSQuarantineTimeStamp')),
            'Downloaded', url or row.get('LSQuarantineOriginURLString') or '',
            {'application': row.get('LSQuarantineAgentName'),
             'bundle': row.get('LSQuarantineAgentBundleIdentifier'),
             'from page': row.get('LSQuarantineOriginURLString'),
             'sender': row.get('LSQuarantineSenderName'),
             'sender address': row.get('LSQuarantineSenderAddress'),
             'event id': row.get('LSQuarantineEventIdentifier')},
            user=user, path=path, ref=ref))
    return out


# --- shared file lists and recent items ------------------------------------------------

def _resolve(objects, value):
    if isinstance(value, plistlib.UID):
        return objects[value.data]
    return value


def _archived(objects, value):
    """An NSKeyedArchiver object as plain Python: dicts and lists followed
    through their UIDs (cycles stopped)."""
    def walk(item, depth):
        item = _resolve(objects, item)
        if depth > 12:
            return None
        if isinstance(item, dict) and 'NS.keys' in item:
            return {walk(k, depth + 1): walk(v, depth + 1)
                    for k, v in zip(item['NS.keys'], item['NS.objects'])}
        if isinstance(item, dict) and 'NS.objects' in item:
            return [walk(v, depth + 1) for v in item['NS.objects']]
        if isinstance(item, dict) and 'NS.string' in item:
            return item['NS.string']
        if isinstance(item, dict) and 'NS.time' in item:
            return times.mac_absolute(item['NS.time'])
        if item == '$null':
            return None
        return item
    return walk(value, 0)


def shared_file_list(data):
    """[{'name', 'path', 'volume', 'created', 'order'}] from an .sfl2/.sfl3
    (an NSKeyedArchiver plist), most recent first."""
    try:
        archive = plistlib.loads(data)
    except Exception as exc:
        raise ValueError(f"Not a shared file list: {exc}") from exc
    objects = archive.get('$objects') or []
    top = archive.get('$top', {}).get('root')
    root = _archived(objects, top) if top is not None else None
    items = root.get('items') if isinstance(root, dict) else None
    out = []
    for order, item in enumerate(items or [], 1):
        if not isinstance(item, dict):
            continue
        bookmark = item.get('Bookmark')
        facts = {}
        if isinstance(bookmark, bytes):
            try:
                facts = macbookmark.parse(bookmark)
            except (macbookmark.BookmarkError, struct.error) as exc:
                logger.debug("Bookmark unreadable: %s", exc)
        out.append({'order': order,
                    'name': item.get('Name') or facts.get('name') or '',
                    'path': facts.get('path') or '',
                    'volume': facts.get('volume') or '',
                    'created': facts.get('created')})
    return out


_LIST_KINDS = {
    'recentdocuments': ('files', 'Recent document'),
    'recentapplications': ('programs', 'Recent application'),
    'recentservers': ('network', 'Recent server'),
    'recenthosts': ('network', 'Recent host'),
    'favoritevolumes': ('usb', 'Volume in the sidebar'),
    'favoriteitems': ('files', 'Sidebar favourite'),
    'projectsitems': ('files', 'Finder tag'),
    'icloudItems'.lower(): ('files', 'iCloud item'),
}


def shared_file_list_activity(data, name, user, path, ref):
    lowered = name.lower()
    category, what = next(
        ((c, w) for key, (c, w) in _LIST_KINDS.items() if key in lowered),
        ('files', 'Recent item'))
    if '.applicationrecentdocuments' in path.lower():
        what = f"Recent document ({name.rsplit('.sfl', 1)[0]})"
    out = []
    for item in shared_file_list(data):
        out.append(record(
            category, 'Shared file list', None, what,
            item['path'] or item['name'],
            {'order': item['order'], 'name': item['name'],
             'volume': item['volume'], 'file created': item['created'],
             'basis': 'the list keeps no time; order 1 is the most recent'},
            user=user, path=path, ref=ref))
    return out


def recent_items_plist(data, user, path, ref):
    """com.apple.recentitems.plist (10.5-10.10)."""
    try:
        plist = plistlib.loads(data)
    except Exception:
        return []
    out = []
    for key, (category, what) in (('RecentDocuments', ('files',
                                                       'Recent document')),
                                  ('RecentApplications',
                                   ('programs', 'Recent application')),
                                  ('RecentServers', ('network',
                                                     'Recent server'))):
        section = plist.get(key) or {}
        for order, item in enumerate(section.get('CustomListItems') or [], 1):
            facts = {}
            bookmark = item.get('Bookmark')
            if isinstance(bookmark, bytes) and bookmark[:4] == b'book':
                try:
                    facts = macbookmark.parse(bookmark)
                except (macbookmark.BookmarkError, struct.error):
                    facts = {}
            out.append(record(category, 'Recent items', None, what,
                              facts.get('path') or item.get('Name') or '',
                              {'order': order, 'name': item.get('Name'),
                               'basis': 'order 1 is the most recent'},
                              user=user, path=path, ref=ref))
    return out


# --- install history, utmpx -----------------------------------------------------------

def install_history(data):
    plist = plistlib.loads(data)
    if not isinstance(plist, list):
        return []
    out = []
    for item in plist:
        if not isinstance(item, dict) or 'displayName' not in item:
            continue
        when = item.get('date')
        if isinstance(when, datetime.datetime) and when.tzinfo is None:
            when = when.replace(tzinfo=times.UTC)
        out.append({'name': item.get('displayName') or '',
                    'version': item.get('displayVersion') or '',
                    'process': item.get('processName') or '',
                    'packages': list(item.get('packageIdentifiers') or []),
                    'time': when})
    return out


def install_history_activity(data, path, ref):
    out = []
    for item in install_history(data):
        out.append(record('system', 'InstallHistory', item['time'],
                          'Installed', f"{item['name']} {item['version']}"
                          .strip(),
                          {'installer': item['process'],
                           'packages': ', '.join(item['packages'][:20])
                           + (f" (+{len(item['packages']) - 20})"
                              if len(item['packages']) > 20 else '')},
                          path=path, ref=ref))
    return out


UTMPX_SIZE = 628


def utmpx_records(data):
    out = []
    start = UTMPX_SIZE if data[:5] == b'utmpx' else 0
    for offset in range(start, len(data) - UTMPX_SIZE + 1, UTMPX_SIZE):
        raw = data[offset:offset + UTMPX_SIZE]
        pid, kind = struct.unpack_from('<iH', raw, 292)
        seconds, micro = struct.unpack_from('<iI', raw, 300)
        if not kind:
            continue                       # an empty record
        when = times.unix(seconds)
        if when is not None and micro < 1_000_000:
            when = when.replace(microsecond=micro)
        out.append({'offset': offset, 'type': kind, 'pid': pid,
                    'user': raw[:256].split(b'\0')[0].decode('utf-8',
                                                             'replace'),
                    'terminal_id': struct.unpack_from('<I', raw, 256)[0],
                    'terminal': raw[260:292].split(b'\0')[0].decode(
                        'utf-8', 'replace'),
                    'host': raw[308:564].split(b'\0')[0].decode(
                        'utf-8', 'replace'),
                    'time': when})
    return out


def utmpx_activity(data, path, ref):
    out = []
    for item in utmpx_records(data):
        kind, user = item['type'], item['user']
        if kind == 7:
            what, category = 'Logon', 'logons'
        elif kind == 8:
            what, category = 'Logoff', 'logons'
        elif kind == 2:
            what, category, user = 'System boot', 'system', ''
        elif kind == 9 or (kind == 1 and user == 'shutdown'):
            what, category, user = 'System shutdown', 'system', ''
        else:
            continue
        subject = f"{user} on {item['terminal']}" if user else \
            item['terminal']
        if item['host']:
            subject += f" from {item['host']}"
        out.append(record(category, 'utmpx', item['time'], what, subject,
                          {'terminal': item['terminal'], 'pid': item['pid'],
                           'host': item['host']},
                          user=user, path=path, ref=ref))
    return out


# --- the volume ---------------------------------------------------------------------------

def is_macos(volume):
    # A triage collection (UAC's [root], a targeted zip) may hold only
    # some of the system's folders: Users and private/var are enough.
    if volume.find('Library') is not None and (
            volume.find('System', 'Library') is not None or
            volume.find('private', 'var') is not None or
            volume.find('Users') is not None):
        return True
    return (volume.find('Users') is not None and
            volume.find('private', 'var', 'db') is not None)


def _read_with_wal(volume, entry):
    from trace_app.core.activity import _split
    parts = _split(entry.path)
    wal = volume.find(*parts[:-1], parts[-1] + '-wal')
    return volume.read(entry), (volume.read(wal) if wal else None)


def collect(volume, step, homes):
    from trace_app.core.activity import _split
    out = []

    def sqlite_source(entry, reader, user):
        step(entry.path)
        data, wal = _read_with_wal(volume, entry)
        try:
            return reader(data, wal, user, entry.path, volume.ref(entry))
        except Exception as exc:
            logger.info("%s unreadable: %s", entry.path, exc)
            return []

    def plist_source(entry, reader, *args):
        step(entry.path)
        try:
            return reader(volume.read(entry), *args, entry.path,
                          volume.ref(entry))
        except Exception as exc:
            logger.info("%s unreadable: %s", entry.path, exc)
            return []

    system_db = volume.find('private', 'var', 'db', 'CoreDuet', 'Knowledge',
                            'knowledgeC.db')
    if system_db is not None:
        out += sqlite_source(system_db, knowledgec_activity, '')
    out += _system_plists_and_dbs(volume, plist_source, sqlite_source)
    receipts = volume.find('Library', 'Receipts', 'InstallHistory.plist')
    if receipts is not None:
        step(receipts.path)
        try:
            out += install_history_activity(volume.read(receipts),
                                            receipts.path,
                                            volume.ref(receipts))
        except Exception as exc:
            logger.info("%s unreadable: %s", receipts.path, exc)
    utmpx = volume.find('private', 'var', 'run', 'utmpx')
    if utmpx is not None and not utmpx.is_dir:
        step(utmpx.path)
        out += utmpx_activity(volume.read(utmpx), utmpx.path,
                              volume.ref(utmpx))

    for user, home in homes:
        base = _split(home.path)
        knowledge = volume.find(*base, 'Library', 'Application Support',
                                'Knowledge', 'knowledgeC.db')
        if knowledge is not None:
            out += sqlite_source(knowledge, knowledgec_activity, user)
        for name in ('com.apple.LaunchServices.QuarantineEventsV2',
                     'com.apple.LaunchServices.QuarantineEvents'):
            entry = volume.find(*base, 'Library', 'Preferences', name)
            if entry is not None and not entry.is_dir:
                out += sqlite_source(entry, quarantine_activity, user)
        lists = volume.find(*base, 'Library', 'Application Support',
                            'com.apple.sharedfilelist')
        folders = [lists] + volume.children(lists, dirs=True) \
            if lists is not None else []
        for folder in folders:
            for entry in volume.children(folder):
                if not entry.name.endswith(('.sfl2', '.sfl3', '.sfl')):
                    continue
                step(entry.path)
                try:
                    out += shared_file_list_activity(
                        volume.read(entry), entry.name, user, entry.path,
                        volume.ref(entry))
                except ValueError as exc:
                    logger.info("%s: %s", entry.path, exc)
        recent = volume.find(*base, 'Library', 'Preferences',
                             'com.apple.recentitems.plist')
        if recent is not None:
            step(recent.path)
            out += recent_items_plist(volume.read(recent), user, recent.path,
                                      volume.ref(recent))
        out += _user_plists_and_dbs(volume, base, user, plist_source,
                                    sqlite_source)
        out += _user_state(volume, base, user, step, plist_source,
                           sqlite_source)
    out += _system_state(volume, step, plist_source, sqlite_source)
    return out


#: Each user's preference plists (macos_plists) and SQLite databases
#: (macos_sqlite), by the path under the home folder.
_USER_PLISTS = (
    (('Library', 'Preferences', 'com.apple.airport.preferences.plist'),
     'airport'),
    (('Library', 'Preferences', 'com.apple.spotlight.plist'),
     'spotlight_shortcuts'),
    (('Library', 'Preferences', 'com.apple.dock.plist'), 'dock'),
)
_USER_DATABASES = (
    (('Library', 'Application Support', 'com.apple.TCC', 'TCC.db'), 'tcc'),
    # Before 10.10 the database sat in Preferences; macOS 15 keeps it in
    # usernoted's group container (10.10-14: /private/var/folders).
    (('Library', 'Preferences', 'com.apple.notificationcenterui.db'),
     'notification_center'),
    (('Library', 'Group Containers', 'group.com.apple.usernoted', 'db2',
      'db'), 'notification_center'),
    (('Library', 'Accounts', 'Accounts4.sqlite'), 'internet_accounts'),
    (('Library', 'Accounts', 'Accounts3.sqlite'), 'internet_accounts'),
)


def _keychain_entries(data, path, ref, user=''):
    """Keychain items as metadata records (name, account, where, times);
    never a secret. core/keychain can decrypt on an examiner's request."""
    from trace_app.core import keychain
    from trace_app.core.activity import record
    try:
        store = keychain.Keychain(data)
    except keychain.KeychainError:
        return []
    out = []
    for entry in store.entries():
        detail = {'account': entry.account, 'where': entry.where,
                  'protocol': entry.protocol,
                  'modified': entry.modified.strftime('%Y-%m-%d %H:%M:%S')
                  if entry.modified else None,
                  'basis': 'when the keychain item was created'}
        out.append(record('accounts', 'Keychain', entry.created,
                          f'Keychain {entry.kind}',
                          entry.name or entry.account or entry.where or '',
                          detail, user=user, path=path, ref=ref))
    return out


def _user_plists_and_dbs(volume, base, user, plist_source, sqlite_source):
    from trace_app.core.activity import macos_plists, macos_sqlite
    out = []
    keychains = volume.find(*base, 'Library', 'Keychains')
    for folder in ((keychains,) if keychains is not None and keychains.is_dir
                   else ()):
        for entry in volume.children(folder):
            if entry.name.endswith(('.keychain', '.keychain-db')):
                out += plist_source(entry, _keychain_entries, user)
    for parts, reader in _USER_PLISTS:
        entry = volume.find(*base, *parts)
        if entry is not None and not entry.is_dir:
            out += plist_source(entry, getattr(macos_plists, reader), user)
    for notes in _note_stores(volume, base):
        out += sqlite_source(notes, macos_sqlite.macos_notes, user)
    from trace_app.core.activity import safari_cookies
    for parts in (('Library', 'Cookies', 'Cookies.binarycookies'),
                  ('Library', 'Containers', 'com.apple.Safari', 'Data',
                   'Library', 'Cookies', 'Cookies.binarycookies')):
        entry = volume.find(*base, *parts)
        if entry is not None and not entry.is_dir:
            out += plist_source(entry, safari_cookies.records)
    for parts, reader in _USER_DATABASES:
        entry = volume.find(*base, *parts)
        if entry is not None and not entry.is_dir:
            out += sqlite_source(entry, getattr(macos_sqlite, reader), user)
    # The Apple ID plist's name holds a UUID: match it by its prefix.
    prefs = volume.find(*base, 'Library', 'Application Support',
                        'com.apple.coreservices')
    for folder in ((prefs,) if prefs is not None else ()):
        for entry in volume.children(folder):
            if entry.name.startswith(
                    'com.apple.coreservices.appleidauthenticationinfo') and \
                    entry.name.endswith('.plist'):
                out += plist_source(entry, macos_plists.apple_account)
    return out


#: System-wide plists and databases, by the path from the volume root.
_SYSTEM_PLISTS = (
    (('Library', 'Preferences', 'com.apple.bluetooth.plist'), 'bluetooth'),
    (('Library', 'Preferences', 'com.apple.loginwindow.plist'),
     'login_window'),
    (('Library', 'Preferences', 'SystemConfiguration',
      'com.apple.spotlight.plist'), 'spotlight_shortcuts'),
    (('Library', 'Preferences', 'com.apple.iPod.plist'), 'ipod_devices'),
    (('Library', 'Preferences', 'com.apple.TimeMachine.plist'),
     'time_machine'),
    (('Library', 'Preferences', 'com.apple.SoftwareUpdate.plist'),
     'software_update'),
    (('private', 'var', 'db', 'Spotlight-V100', 'VolumeConfiguration.plist'),
     'spotlight_volumes'),
    (('.Spotlight-V100', 'VolumeConfiguration.plist'), 'spotlight_volumes'),
)
_SYSTEM_DATABASES = (
    (('Library', 'Application Support', 'com.apple.TCC', 'TCC.db'), 'tcc'),
    (('private', 'var', 'db', 'DocumentRevisions-V100',
      'db-V1', 'db.sqlite'), 'document_versions'),
    (('.DocumentRevisions-V100', 'db-V1', 'db.sqlite'), 'document_versions'),
)
#: One-argument plist readers take only (data, path, ref), not a user.
_NO_USER_PLISTS = {'bluetooth', 'login_window', 'ipod_devices',
                   'time_machine', 'software_update', 'spotlight_volumes'}


def _system_plists_and_dbs(volume, plist_source, sqlite_source):
    from trace_app.core.activity import macos_plists, macos_sqlite
    out = []
    for parts, reader in _SYSTEM_PLISTS:
        entry = volume.find(*parts)
        if entry is None or entry.is_dir:
            continue
        function = getattr(macos_plists, reader)
        if reader in _NO_USER_PLISTS:
            out += plist_source(entry, function)
        else:
            out += plist_source(entry, function, '')
    # The user's airport plist is per-system too (SystemConfiguration).
    airport = volume.find('Library', 'Preferences', 'SystemConfiguration',
                          'com.apple.airport.preferences.plist')
    if airport is not None and not airport.is_dir:
        out += plist_source(airport, macos_plists.airport, '')
    for parts, reader in _SYSTEM_DATABASES:
        entry = volume.find(*parts)
        if entry is not None and not entry.is_dir:
            out += sqlite_source(entry, getattr(macos_sqlite, reader), '')
    # Keychains: the item names, accounts and times only -- never a
    # stored secret (core/keychain decrypts only on an examiner's explicit
    # request, and TRACE never writes the result to the case).
    for parts in (('Library', 'Keychains'),):
        folder = volume.find(*parts)
        if folder is None or not folder.is_dir:
            continue
        for entry in volume.children(folder):
            if entry.name.endswith(('.keychain', '.keychain-db')):
                out += plist_source(entry, _keychain_entries)
    # Apple System Log: /private/var/log/asl/*.asl.
    from trace_app.core.activity import asl
    asl_dir = volume.find('private', 'var', 'log', 'asl')
    if asl_dir is not None and asl_dir.is_dir:
        for entry in volume.children(asl_dir):
            if entry.name.endswith('.asl'):
                out += plist_source(entry, asl.records)
    # CUPS print jobs: /private/var/spool/cups/c#####.
    from trace_app.core.activity import cups_ipp
    spool = volume.find('private', 'var', 'spool', 'cups')
    if spool is not None and spool.is_dir:
        for entry in volume.children(spool):
            if entry.name.startswith('c') and entry.name[1:].isdigit():
                out += plist_source(entry, cups_ipp.records)
    # dslocal user accounts (no hash): /var/db/dslocal/nodes/Default/users.
    users = volume.find('private', 'var', 'db', 'dslocal', 'nodes',
                        'Default', 'users')
    if users is not None and users.is_dir:
        for entry in volume.children(users):
            if entry.name.endswith('.plist') and not entry.name.startswith(
                    '_'):
                out += plist_source(entry, macos_plists.dslocal_user)
    return out


# --- notes, app state, Trash, sharing, per-boot folders ----------------------------

def _note_stores(volume, base):
    """Each Notes database of a user: NoteStore.sqlite (10.11+) and any
    NotesV*.storedata (earlier, in the app's container)."""
    found = []
    entry = volume.find(*base, 'Library', 'Group Containers',
                        'group.com.apple.notes', 'NoteStore.sqlite')
    if entry is not None and not entry.is_dir:
        found.append(entry)
    for parts in (('Library', 'Containers', 'com.apple.Notes', 'Data',
                   'Library', 'Notes'),
                  ('Library', 'Group Containers', 'group.com.apple.notes')):
        folder = volume.find(*base, *parts)
        for child in volume.children(folder, suffix='.storedata') \
                if folder is not None and folder.is_dir else ():
            if child.name.lower().startswith('notesv'):
                found.append(child)
    return found


def _var_folders(volume, *tail):
    """Entries at `tail` under every per-user temporary folder
    (/private/var/folders/xx/<random>/...): Notification Center (10.10-
    14), Screen Time and Launchpad keep their databases there."""
    root = volume.find('private', 'var', 'folders')
    if root is None or not root.is_dir:
        return []
    out = []
    for first in volume.children(root, dirs=True):
        for second in volume.children(first, dirs=True):
            entry = volume.find(*_parts(second.path), *tail)
            if entry is not None and not entry.is_dir:
                out.append(entry)
    return out


def _parts(path):
    from trace_app.core.activity import _split
    return _split(path)


def _saved_states(volume, base):
    """(bundle id, the .savedState folder) for every app of a user --
    in Saved Application State and in each sandboxed app's container."""
    folders = [volume.find(*base, 'Library', 'Saved Application State')]
    containers = volume.find(*base, 'Library', 'Containers')
    for container in volume.children(containers, dirs=True) \
            if containers is not None and containers.is_dir else ():
        folders.append(volume.find(*_parts(container.path), 'Data',
                                   'Library', 'Saved Application State'))
    for folder in folders:
        if folder is None or not folder.is_dir:
            continue
        for state in volume.children(folder, suffix='.savedState',
                                     dirs=True):
            yield state.name[:-len('.savedState')], state


def _user_state(volume, base, user, step, plist_source, sqlite_source):
    from trace_app.core.activity import macos_plists, macos_sqlite, \
        macos_state
    out = []
    # Saved application state and Terminal's window text.
    for bundle, state in _saved_states(volume, base):
        windows_plist = volume.find(*_parts(state.path), 'windows.plist')
        if windows_plist is None or windows_plist.is_dir:
            continue
        data_file = volume.find(*_parts(state.path), 'data.data')
        step(state.path)
        try:
            windows_data = volume.read(windows_plist)
            state_data = volume.read(data_file) if data_file else b''
            modified = windows_plist.modified
            ref = volume.ref(windows_plist)
            if bundle == 'com.apple.Terminal':
                out += macos_state.terminal_state(
                    windows_data, state_data, user, modified,
                    windows_plist.path, ref)
            out += macos_state.saved_state(
                windows_data, state_data, bundle, user, modified,
                windows_plist.path, ref)
        except Exception as exc:
            logger.info("%s unreadable: %s", state.path, exc)
    # Launchpad (before 10.10: the Dock's folder in Application Support).
    dock_folder = volume.find(*base, 'Library', 'Application Support',
                              'Dock')
    for entry in volume.children(dock_folder, suffix='.db') \
            if dock_folder is not None and dock_folder.is_dir else ():
        out += sqlite_source(entry, macos_sqlite.launchpad, user)
    # CFURL caches: each app's Cache.db, sandboxed apps' too.
    caches = [volume.find(*base, 'Library', 'Caches')]
    containers = volume.find(*base, 'Library', 'Containers')
    for container in volume.children(containers, dirs=True) \
            if containers is not None and containers.is_dir else ():
        caches.append(volume.find(*_parts(container.path), 'Data',
                                  'Library', 'Caches'))
    for folder in caches:
        if folder is None or not folder.is_dir:
            continue
        for app in volume.children(folder, dirs=True):
            cache = volume.find(*_parts(app.path), 'Cache.db')
            if cache is not None and not cache.is_dir:
                out += sqlite_source(
                    cache, lambda d, w, u, p, r, a=app.name:
                    macos_sqlite.cfurl_cache(d, w, u, p, r, app=a), user)
    # Screen Sharing: the computers this user connected to.
    for parts in (('Library', 'Preferences', 'com.apple.ScreenSharing.plist'),
                  ('Library', 'Containers', 'com.apple.ScreenSharing',
                   'Data', 'Library', 'Preferences',
                   'com.apple.ScreenSharing.plist')):
        entry = volume.find(*base, *parts)
        if entry is not None and not entry.is_dir:
            out += plist_source(entry, macos_plists.screen_sharing_client,
                                user, entry.modified)
    # The user's Trash: where each trashed item came from.
    out += _trash(volume, (*base, '.Trash'), user, step)
    return out


def _trash(volume, parts, user, step):
    from trace_app.core.activity import macos_state
    folder = volume.find(*parts)
    if folder is None or not folder.is_dir:
        return []
    store = volume.find(*parts, '.DS_Store')
    if store is None or store.is_dir:
        return []
    step(store.path)
    present = {e.name: e for e in volume.listdir(folder.path)
               if e.name != '.DS_Store' and not e.deleted}
    try:
        return macos_state.trash(volume.read(store), present,
                                 lambda entry: entry.changed, user,
                                 store.path, volume.ref(store))
    except Exception as exc:
        logger.info("%s unreadable: %s", store.path, exc)
        return []


def _system_state(volume, step, plist_source, sqlite_source):
    """What the Mac shares, per-boot databases, sudo, XProtect, network
    usage, and the Trashes of other volumes' users."""
    from trace_app.core.activity import macos_plists, macos_sqlite, \
        macos_state
    out = []
    for parts in (('private', 'var', 'networkd', 'netusage.sqlite'),
                  ('private', 'var', 'networkd', 'db', 'netusage.sqlite')):
        entry = volume.find(*parts)
        if entry is not None and not entry.is_dir:
            out += sqlite_source(entry, macos_sqlite.netusage, '')
    xprotect = volume.find('private', 'var', 'protected', 'xprotect', 'XPdb')
    if xprotect is not None and not xprotect.is_dir:
        out += sqlite_source(xprotect, macos_sqlite.xprotect_behavior, '')
    for tail, reader in (
            (('0', 'com.apple.notificationcenter', 'db2', 'db'),
             macos_sqlite.notification_center),
            (('0', 'com.apple.notificationcenter', 'db', 'db'),
             macos_sqlite.notification_center),
            (('0', 'com.apple.ScreenTimeAgent', 'Store',
              'RMAdminStore-Local.sqlite'), macos_sqlite.screen_time),
            (('0', 'com.apple.ScreenTimeAgent', 'Store',
              'RMAdminStore-Cloud.sqlite'), macos_sqlite.screen_time),
            (('0', 'com.apple.dock.launchpad', 'db', 'db'),
             macos_sqlite.launchpad)):
        for entry in _var_folders(volume, *tail):
            out += sqlite_source(entry, reader, '')
    # File sharing: share points, the SMB server's name, and which
    # sharing services are on.
    shares = volume.find('private', 'var', 'db', 'dslocal', 'nodes',
                         'Default', 'sharepoints')
    for entry in volume.children(shares, suffix='.plist') \
            if shares is not None and shares.is_dir else ():
        out += plist_source(entry, macos_plists.sharepoint, entry.modified)
    for parts, reader in (
            (('Library', 'Preferences', 'SystemConfiguration',
              'com.apple.smb.server.plist'), macos_plists.smb_server),
            (('private', 'var', 'db', 'launchd.db', 'com.apple.launchd',
              'overrides.plist'), macos_plists.launchd_overrides),
            (('private', 'var', 'db', 'com.apple.xpc.launchd',
              'disabled.plist'), macos_plists.launchd_overrides),
            (('Library', 'Preferences', 'com.apple.RemoteManagement.plist'),
             macos_plists.remote_management)):
        entry = volume.find(*parts)
        if entry is not None and not entry.is_dir:
            out += plist_source(entry, reader, entry.modified)
    # sudo: one timestamp file per user (10.12+), else a folder per user
    # of empty per-terminal files whose times are the record.
    sudo = volume.find('private', 'var', 'db', 'sudo')
    if sudo is not None and sudo.is_dir:
        ts = volume.find('private', 'var', 'db', 'sudo', 'ts')
        for entry in volume.listdir(ts.path) if ts is not None and \
                ts.is_dir else ():
            if entry.is_dir or entry.deleted:
                continue
            step(entry.path)
            out += macos_state.sudo_timestamps(
                volume.read(entry), entry.name, entry.modified, entry.path,
                volume.ref(entry))
        for folder in volume.children(sudo, dirs=True):
            if folder.name in ('ts', 'lectured'):
                continue
            for entry in volume.listdir(folder.path):
                if not entry.is_dir and not entry.deleted:
                    out += macos_state.sudo_timestamps(
                        b'', folder.name, entry.modified, entry.path,
                        volume.ref(entry))
    # Trashes of a volume's other users (/.Trashes/<uid>).
    trashes = volume.find('.Trashes')
    for folder in volume.children(trashes, dirs=True) \
            if trashes is not None and trashes.is_dir else ():
        out += _trash(volume, _parts(folder.path), f'uid {folder.name}',
                      step)
    return out

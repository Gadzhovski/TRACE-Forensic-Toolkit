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
    return volume.find('Library') is not None and (
        volume.find('System', 'Library') is not None or
        volume.find('private', 'var') is not None or
        volume.find('Users') is not None)


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

    system_db = volume.find('private', 'var', 'db', 'CoreDuet', 'Knowledge',
                            'knowledgeC.db')
    if system_db is not None:
        out += sqlite_source(system_db, knowledgec_activity, '')
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
    return out

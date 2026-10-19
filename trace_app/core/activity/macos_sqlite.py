"""macOS and iOS SQLite databases (no Qt).

The system databases a Mac or an iPhone keeps about privacy decisions,
notifications shown, applications used, document versions, screen time,
notes and data/network usage. Each reader takes the file's bytes (and a
`-wal` if there is one) through `sqlite_bytes.open_database`, so a
database on evidence is read without writing anything, and returns
`activity.record` dicts. Core Data times are seconds since 2001-01-01 UTC
(`times.mac_absolute`).

Checked against plaso's test databases and its expected values
(tests/test_macos_sqlite.py):

* macOS TCC.db -- the privacy permissions an app was granted or refused
* macOS NotificationCenter db -- the notifications the system showed
* macOS application_usage.sqlite -- how many times each app was launched
* macOS DocumentRevisions db -- the stored versions of a document
* NoteStore.sqlite (macOS 10.11+, iOS 9+) -- every note with its folder
  and body text (gzip + protobuf, core/protobuf); NotesV*.storedata and
  iOS notes.sqlite (HTML) before that
* RMAdminStore (Screen Time, iOS and macOS) -- time spent per app/device
* netusage.sqlite (iOS, macOS) / DataUsage.sqlite -- bytes per app/network
* Accounts4/Accounts3.sqlite -- the Internet accounts set up
* Cache.db (CFURL cache) -- each web request an app cached
* XPdb -- XProtect Behavior Service detections (macOS 13+)
* Launchpad's database -- the applications it lists
"""

import logging
import plistlib

from trace_app.core.activity import record, sqlite_bytes, times

logger = logging.getLogger('TRACE.Activity.macOSSQLite')


def _rows(data, wal, query):
    with sqlite_bytes.open_database(data, wal) as db:
        cursor = db.execute(query)
        names = [c[0] for c in cursor.description]
        for row in cursor.fetchall():
            yield dict(zip(names, row))


def _has(data, wal, table):
    with sqlite_bytes.open_database(data, wal) as db:
        return bool(db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone())


#: TCC's auth_value (macOS 11+), and why it was set (auth_reason).
TCC_DECISIONS = {0: 'Refused', 1: 'Unknown', 2: 'Allowed', 3: 'Limited'}
TCC_REASONS = {1: 'error', 2: 'user consent', 3: 'user set',
               4: 'system set', 5: 'service policy', 6: 'MDM policy',
               7: 'override policy', 8: 'missing usage string',
               9: 'prompt timeout', 10: 'preflight unknown',
               11: 'entitled', 12: 'app type policy'}


def tcc(data, wal, user, path, ref):
    """TCC.db: every privacy permission (camera, microphone, full disk...)
    an app was granted or refused, and when it was last changed. Before
    macOS 11 a row says `allowed` (0/1) and `prompt_count`; from 11 on
    `auth_value` (0 refused, 2 allowed, 3 limited) and `auth_reason`."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        if 'access' not in _tables(db):
            return out
        fields = _select(db, 'access', {
            name: (name,) for name in (
                'service', 'client', 'allowed', 'prompt_count',
                'auth_value', 'auth_reason', 'last_modified')})
        cursor = db.execute(f"SELECT {', '.join(fields)} FROM access")
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, values)) for values in cursor.fetchall()]
    for row in rows:
        if row.get('auth_value') is not None:
            decision = TCC_DECISIONS.get(row['auth_value'],
                                         f"auth_value {row['auth_value']}")
        else:
            decision = 'Allowed' if row.get('allowed') else 'Refused'
        reason = row.get('auth_reason')
        out.append(record(
            'system', 'TCC (privacy)', times.unix(row.get('last_modified')),
            decision,
            f"{row.get('client')} — {row.get('service')}",
            {'client': row.get('client'), 'service': row.get('service'),
             'decision': decision,
             'reason': TCC_REASONS.get(reason, reason) if reason else None,
             'prompt count': row.get('prompt_count'),
             'basis': 'when the permission was last set'},
            user=user, path=path, ref=ref))
    return out


def notification_center(data, wal, user, path, ref):
    """The NotificationCenter database: each notification shown, with the
    app, title, subtitle and body from its 'req' plist."""
    out = []
    if _has(data, wal, 'presented_notifications'):
        return _old_notifications(data, wal, user, path, ref)
    query = ("SELECT a.identifier AS bundle, r.delivered_date AS delivered, "
             "r.request_date AS requested, r.presented AS presented, "
             "r.data AS blob FROM record r JOIN app a ON r.app_id = a.app_id")
    for row in _rows(data, wal, query):
        title = subtitle = body = None
        try:
            request = (plistlib.loads(row['blob']) or {}).get('req') or {}
            title, subtitle, body = (request.get('titl'),
                                     request.get('subt'), request.get('body'))
        except Exception:
            pass
        out.append(record(
            'usage', 'Notification Center',
            times.mac_absolute(row.get('delivered')
                               or row.get('requested')),
            'Notification shown', title or row.get('bundle') or '',
            {'app': row.get('bundle'), 'subtitle': subtitle, 'body': body,
             'presented': row.get('presented'),
             'basis': 'when the notification was delivered'},
            user=user, path=path, ref=ref))
    return out


def _old_notifications(data, wal, user, path, ref):
    """Notification Center before macOS 10.13 (db/db): presented_notifications,
    the app from app_info, the text in an NSKeyedArchiver plist
    (NSTitle / NSSubtitle / NSInformativeText point into $objects)."""
    out = []
    query = ("SELECT p.date_presented AS presented_at, "
             "p.actually_presented AS shown, a.bundleid AS bundle, "
             "n.encoded_data AS blob FROM presented_notifications p "
             "LEFT JOIN app_info a ON a.app_id = p.app_id "
             "LEFT JOIN notifications n ON n.note_id = p.note_id")
    for row in _rows(data, wal, query):
        texts = {}
        try:
            archive = plistlib.loads(bytes(row['blob'] or b''))
            objects = archive.get('$objects') or []
            top = objects[1] if len(objects) > 1 and isinstance(
                objects[1], dict) else {}
            for key in ('NSTitle', 'NSSubtitle', 'NSInformativeText'):
                index = top.get(key)
                index = getattr(index, 'data', index)
                if isinstance(index, int) and 0 <= index < len(objects) \
                        and isinstance(objects[index], str):
                    texts[key] = objects[index]
        except Exception:
            pass
        out.append(record(
            'usage', 'Notification Center',
            times.mac_absolute(row.get('presented_at')),
            'Notification shown',
            texts.get('NSTitle') or row.get('bundle') or '',
            {'app': row.get('bundle'), 'subtitle': texts.get('NSSubtitle'),
             'body': texts.get('NSInformativeText'),
             'presented': row.get('shown'),
             'basis': 'when the notification was presented'},
            user=user, path=path, ref=ref))
    return out


def application_usage(data, wal, user, path, ref):
    """application_usage.sqlite: each application, how it was used (launch)
    and how many times."""
    out = []
    query = ("SELECT last_time, event, bundle_id, app_version, app_path, "
             "number_times FROM application_usage")
    for row in _rows(data, wal, query):
        out.append(record(
            'usage', 'Application usage', times.unix(row.get('last_time')),
            f"App {row.get('event') or 'used'}", row.get('app_path') or '',
            {'bundle id': row.get('bundle_id'),
             'version': row.get('app_version'),
             'count': row.get('number_times'),
             'basis': 'the last time the application was used'},
            user=user, path=path, ref=ref))
    return out


def document_versions(data, wal, user, path, ref):
    """The DocumentRevisions database: each stored version of a document,
    where the version is kept, and when it was made."""
    out = []
    query = ("SELECT f.file_name AS name, f.file_path AS path, "
             "f.file_last_seen AS last_time, "
             "g.generation_path AS version_path, "
             "g.generation_add_time AS version_time FROM files f, "
             "generations g WHERE f.file_storage_id = g.generation_storage_id")
    for row in _rows(data, wal, query):
        out.append(record(
            'files', 'Document versions', times.unix(row.get('version_time')),
            'Document version stored', row.get('name') or '',
            {'path': row.get('path'),
             'version path': row.get('version_path'),
             'last seen': times.iso(times.unix(row.get('last_time'))),
             'basis': 'when this version of the document was stored'},
            user=user, path=path, ref=ref))
    return out


def macos_notes(data, wal, user, path, ref):
    """A Mac's notes: NoteStore.sqlite (10.11+) or NotesV*.storedata."""
    return note_store(data, wal, user, path, ref, 'Notes')


def ios_notes(data, wal, user, path, ref):
    """An iPhone's notes: NoteStore.sqlite, or notes.sqlite before iOS 9."""
    return note_store(data, wal, user, path, ref, 'Notes (iOS)')


def _tables(db):
    return {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(db, table):
    return {row[1].upper() for row in db.execute(
        f'PRAGMA table_info("{table}")')}


def _pick(columns, *names):
    """The first of `names` the table has, or None."""
    return next((n for n in names if n.upper() in columns), None)


def note_store(data, wal, user, path, ref, source='Notes'):
    """Every note with its title, folder, times and **body text**.

    NoteStore.sqlite keeps a note's body in ZICNOTEDATA.ZDATA, gzip of a
    protobuf: field 2 (the document), its field 3 (the note), its field 2
    (the text) -- decoded with core/protobuf, no schema needed. Embedded
    attachments are U+FFFC in the text. A password-protected note's body
    is encrypted and is said to be so; its title and snippet are plain.
    Older stores (NotesV*.storedata, iOS notes.sqlite) keep HTML in
    ZNOTEBODY, which is stripped to text."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        tables = _tables(db)
        if {'ZICCLOUDSYNCINGOBJECT', 'ZICNOTEDATA'} <= tables:
            rows = _modern_notes(db)
        elif {'ZNOTE', 'ZNOTEBODY'} <= tables:
            rows = _legacy_notes(db)
        else:
            return out
    for row in rows:
        if not (row.get('title') or row.get('text') or row.get('snippet')):
            continue                    # an emptied, deleted note: nothing
        out.append(record(
            'notes', source, times.mac_absolute(row.get('created')),
            'Note' + (' (deleted)' if row.get('deleted') else ''),
            row.get('title') or (row.get('text') or '')[:80],
            {'text': (row.get('text') or '')[:4000] or None,
             'snippet': row.get('snippet'),
             'folder': row.get('folder'),
             'modified': times.iso(times.mac_absolute(row.get('modified'))),
             'password protected': 'yes, body encrypted'
             if row.get('locked') else None,
             'attachments': row.get('attachments') or None,
             'basis': 'when the note was created'},
            user=user, path=path, ref=ref))
    return out


def _modern_notes(db):
    objects = _columns(db, 'ZICCLOUDSYNCINGOBJECT')
    data_columns = _columns(db, 'ZICNOTEDATA')
    pick = {
        'title': _pick(objects, 'ZTITLE1', 'ZTITLE'),
        'snippet': _pick(objects, 'ZSNIPPET'),
        'created': _pick(objects, 'ZCREATIONDATE3', 'ZCREATIONDATE1',
                         'ZCREATIONDATE'),
        'modified': _pick(objects, 'ZMODIFICATIONDATE1',
                          'ZMODIFICATIONDATE'),
        'locked': _pick(objects, 'ZISPASSWORDPROTECTED'),
        'deleted': _pick(objects, 'ZMARKEDFORDELETION'),
    }
    fields = [f'o.{column} AS {name}' for name, column in pick.items()
              if column]
    if 'ZFOLDER' in objects and 'ZTITLE2' in objects:
        fields.append('(SELECT f.ZTITLE2 FROM ZICCLOUDSYNCINGOBJECT f '
                      'WHERE f.Z_PK = o.ZFOLDER) AS folder')
    note_column = 'ZNOTE' if 'ZNOTE' in data_columns else None
    if note_column is None or 'ZDATA' not in data_columns:
        return []
    query = (f"SELECT {', '.join(fields + ['d.ZDATA AS body'])} "
             f"FROM ZICNOTEDATA d JOIN ZICCLOUDSYNCINGOBJECT o "
             f"ON d.ZNOTE = o.Z_PK")
    rows = []
    for values in db.execute(query).fetchall():
        names = [f.rsplit(' AS ', 1)[1] for f in fields] + ['body']
        row = dict(zip(names, values))
        if row.get('locked'):
            row['text'] = None
        else:
            text = note_body_text(row.get('body'))
            if text:
                row['attachments'] = text.count('\ufffc')
                row['text'] = text.replace('\ufffc', '[attachment]')
        row.pop('body', None)
        rows.append(row)
    return rows


def note_body_text(blob):
    """The text of a NoteStore ZDATA blob (gzip + protobuf), or None."""
    import gzip
    import zlib
    from trace_app.core import protobuf
    if not blob:
        return None
    blob = bytes(blob)
    try:
        raw = gzip.decompress(blob) if blob[:2] == b'\x1f\x8b' else \
            zlib.decompress(blob)
    except (OSError, zlib.error, EOFError):
        raw = blob
    try:
        message = protobuf.parse(raw)
    except protobuf.ProtobufError:
        return None
    text = protobuf.first(message, 2, 3, 2)
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    if isinstance(text, str):
        return text
    found = protobuf.strings(raw, limit=50)
    return max(found, key=len) if found else None


def _legacy_notes(db):
    note = _columns(db, 'ZNOTE')
    body = _columns(db, 'ZNOTEBODY')
    content = _pick(body, 'ZHTMLSTRING', 'ZCONTENT')
    if content is None:
        return []
    join = 'b.Z_PK = n.ZBODY' if 'ZBODY' in note else 'b.Z_PK = n.Z_PK'
    pick = {'title': _pick(note, 'ZTITLE'),
            'created': _pick(note, 'ZDATECREATED', 'ZCREATIONDATE'),
            'modified': _pick(note, 'ZDATEEDITED', 'ZMODIFICATIONDATE'),
            'snippet': _pick(note, 'ZSUMMARY')}
    fields = [f'n.{column} AS {name}' for name, column in pick.items()
              if column] + [f'b.{content} AS html']
    rows = []
    cursor = db.execute(f"SELECT {', '.join(fields)} FROM ZNOTE n "
                        f"JOIN ZNOTEBODY b ON {join}")
    names = [c[0] for c in cursor.description]
    for values in cursor.fetchall():
        row = dict(zip(names, values))
        html = row.pop('html') or ''
        if isinstance(html, bytes):
            html = html.decode('utf-8', 'replace')
        row['text'] = _strip_html(html)
        rows.append(row)
    return rows


def screen_time(data, wal, user, path, ref):
    """iOS RMAdminStore (Screen Time): time spent per app, per device, in
    a usage block starting at ZSTARTDATE."""
    out = []
    query = """
      SELECT ZUSAGETIMEDITEM.ZTOTALTIMEINSECONDS AS seconds,
        ZUSAGETIMEDITEM.ZBUNDLEIDENTIFIER AS bundle,
        ZUSAGETIMEDITEM.ZDOMAIN AS domain,
        ZUSAGEBLOCK.ZSTARTDATE AS start,
        ZCOREDEVICE.ZIDENTIFIER AS device_id,
        ZCOREDEVICE.ZNAME AS device_name,
        ZCOREUSER.ZFAMILYNAME AS family_name,
        ZCOREUSER.ZGIVENNAME AS given_name
      FROM ZUSAGETIMEDITEM
      LEFT JOIN ZUSAGECATEGORY
        ON ZUSAGETIMEDITEM.ZCATEGORY = ZUSAGECATEGORY.Z_PK
      LEFT JOIN ZUSAGEBLOCK ON ZUSAGECATEGORY.ZBLOCK = ZUSAGEBLOCK.Z_PK
      LEFT JOIN ZUSAGE ON ZUSAGEBLOCK.ZUSAGE = ZUSAGE.Z_PK
      LEFT JOIN ZCOREDEVICE ON ZUSAGE.ZDEVICE = ZCOREDEVICE.Z_PK
      LEFT JOIN ZCOREUSER ON ZUSAGE.ZUSER = ZCOREUSER.Z_PK
      """
    for row in _rows(data, wal, query):
        out.append(record(
            'usage', 'Screen Time', times.mac_absolute(row.get('start')),
            'App used (Screen Time)',
            row.get('bundle') or row.get('domain') or '',
            {'seconds': row.get('seconds'),
             'device': row.get('device_name'),
             'device id': row.get('device_id'),
             'family name': row.get('family_name'),
             'given name': row.get('given_name'),
             'basis': 'the start of the usage block'},
            user=user, path=path, ref=ref))
    return out


def netusage(data, wal, user, path, ref):
    """netusage.sqlite: bytes in/out per route and per process."""
    out = []
    route = """
       SELECT ZLIVEROUTEPERF.ZTIMESTAMP AS start, ZLIVEROUTEPERF.ZKIND AS
         kind, ZLIVEROUTEPERF.ZBYTESIN AS bytes_in, ZLIVEROUTEPERF.ZBYTESOUT
         AS bytes_out, ZNETWORKATTACHMENT.ZIDENTIFIER AS network
       FROM ZLIVEROUTEPERF LEFT JOIN ZNETWORKATTACHMENT
       ON ZLIVEROUTEPERF.ZHASNETWORKATTACHMENT = ZNETWORKATTACHMENT.Z_PK"""
    for row in _rows(data, wal, route):
        out.append(record(
            'network', 'Network usage', times.mac_absolute(row.get('start')),
            'Network route used', row.get('network') or '',
            {'bytes in': row.get('bytes_in'),
             'bytes out': row.get('bytes_out'), 'kind': row.get('kind'),
             'basis': 'the start of the usage period'},
            user=user, path=path, ref=ref))
    process = """
       SELECT ZLIVEUSAGE.ZTIMESTAMP AS start, ZPROCESS.ZPROCNAME AS process,
         ZLIVEUSAGE.ZWIFIIN AS wifi_in, ZLIVEUSAGE.ZWIFIOUT AS wifi_out,
         ZLIVEUSAGE.ZWWANIN AS wwan_in, ZLIVEUSAGE.ZWWANOUT AS wwan_out,
         ZLIVEUSAGE.ZWIREDIN AS wired_in, ZLIVEUSAGE.ZWIREDOUT AS wired_out
       FROM ZLIVEUSAGE LEFT JOIN ZPROCESS
       ON ZPROCESS.Z_PK = ZLIVEUSAGE.ZHASPROCESS"""
    for row in _rows(data, wal, process):
        out.append(record(
            'network', 'Network usage', times.mac_absolute(row.get('start')),
            'App network usage', row.get('process') or '',
            {'wifi in': row.get('wifi_in'), 'wifi out': row.get('wifi_out'),
             'wwan in': row.get('wwan_in'), 'wwan out': row.get('wwan_out'),
             'wired in': row.get('wired_in'),
             'wired out': row.get('wired_out'),
             'basis': 'the start of the usage period'},
            user=user, path=path, ref=ref))
    return out


def datausage(data, wal, user, path, ref):
    """DataUsage.sqlite: cellular/Wi-Fi bytes per process."""
    out = []
    query = ("SELECT ZLIVEUSAGE.ZTIMESTAMP AS start, ZLIVEUSAGE.ZWIFIIN AS "
             "wifi_in, ZLIVEUSAGE.ZWIFIOUT AS wifi_out, ZLIVEUSAGE.ZWWANIN "
             "AS wwan_in, ZLIVEUSAGE.ZWWANOUT AS wwan_out, "
             "ZPROCESS.ZBUNDLENAME AS bundle, ZPROCESS.ZPROCNAME AS process "
             "FROM ZLIVEUSAGE LEFT JOIN ZPROCESS "
             "ON ZPROCESS.Z_PK = ZLIVEUSAGE.ZHASPROCESS")
    for row in _rows(data, wal, query):
        out.append(record(
            'network', 'Data usage', times.mac_absolute(row.get('start')),
            'App data usage', row.get('process') or '',
            {'bundle id': row.get('bundle'),
             'wifi in': row.get('wifi_in'), 'wifi out': row.get('wifi_out'),
             'cellular in': row.get('wwan_in'),
             'cellular out': row.get('wwan_out'),
             'basis': 'the start of the usage period'},
            user=user, path=path, ref=ref))
    return out


def _select(db, table, wanted):
    """SELECT the columns of `wanted` ({alias: (column, ...)}) that the
    table has -- schemas drift between macOS versions."""
    columns = _columns(db, table)
    fields = []
    for alias, names in wanted.items():
        column = _pick(columns, *names)
        if column:
            fields.append(f'{column} AS {alias}')
    return fields


def internet_accounts(data, wal, user, path, ref):
    """Accounts4.sqlite (Accounts3 before 10.14): every Internet account
    set up for the user -- iCloud, mail, Google, Exchange... -- with its
    type, user name, the app that owns it and when it was added. No
    credential is stored here (they are in the keychain)."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        if not {'ZACCOUNT', 'ZACCOUNTTYPE'} <= _tables(db):
            return out
        account = _columns(db, 'ZACCOUNT')
        fields = [f'a.{c} AS {alias}' for alias, c in (
            ('description', _pick(account, 'ZACCOUNTDESCRIPTION')),
            ('username', _pick(account, 'ZUSERNAME')),
            ('added', _pick(account, 'ZDATE')),
            ('identifier', _pick(account, 'ZIDENTIFIER')),
            ('owner', _pick(account, 'ZOWNINGBUNDLEID')),
            ('active', _pick(account, 'ZACTIVE')),
            ('authenticated', _pick(account, 'ZAUTHENTICATED')),
            ('visible', _pick(account, 'ZVISIBLE'))) if c]
        fields += ['t.ZACCOUNTTYPEDESCRIPTION AS type',
                   't.ZIDENTIFIER AS type_id']
        parent = ''
        if 'ZPARENTACCOUNT' in account:
            fields.append('p.ZACCOUNTDESCRIPTION AS parent')
            parent = ' LEFT JOIN ZACCOUNT p ON a.ZPARENTACCOUNT = p.Z_PK'
        cursor = db.execute(
            f"SELECT {', '.join(fields)} FROM ZACCOUNT a LEFT JOIN "
            f"ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK{parent}")
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, values)) for values in cursor.fetchall()]
    for row in rows:
        out.append(record(
            'accounts', 'Internet accounts',
            times.mac_absolute(row.get('added')), 'Account set up',
            row.get('username') or row.get('description') or
            row.get('type') or '',
            {'type': row.get('type'), 'type id': row.get('type_id'),
             'description': row.get('description'),
             'owning app': row.get('owner'),
             'parent account': row.get('parent'),
             'active': row.get('active'),
             'authenticated': row.get('authenticated'),
             'identifier': row.get('identifier'),
             'basis': 'when the account was added'},
            user=user, path=path, ref=ref))
    return out


def cfurl_cache(data, wal, user, path, ref, app=''):
    """An app's CFURL cache (Cache.db): each web request it cached -- the
    URL, when, and how large the response was. Response bodies stay in
    the file (or its fsCachedData folder); none is copied."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        if 'cfurl_cache_response' not in _tables(db):
            return out
        tables = _tables(db)
        receiver = 'cfurl_cache_receiver_data' in tables
        blob = 'cfurl_cache_blob_data' in tables
        query = ("SELECT r.entry_ID AS id, r.request_key AS url, "
                 "r.time_stamp AS stamp, r.storage_policy AS policy"
                 + (", length(d.receiver_data) AS size, d.isDataOnFS AS "
                    "on_fs" if receiver else "")
                 + (", b.response_object AS response" if blob else "")
                 + " FROM cfurl_cache_response r"
                 + (" LEFT JOIN cfurl_cache_receiver_data d ON d.entry_ID ="
                    " r.entry_ID" if receiver else "")
                 + (" LEFT JOIN cfurl_cache_blob_data b ON b.entry_ID = "
                    "r.entry_ID" if blob else ""))
        cursor = db.execute(query)
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, values)) for values in cursor.fetchall()]
    for row in rows:
        status, mime = _cfurl_response(row.get('response'))
        out.append(record(
            'browser', f'URL cache ({app})' if app else 'URL cache',
            _sqlite_time(row.get('stamp')), 'Web request cached',
            row.get('url') or '',
            {'app': app or None, 'status': status, 'content type': mime,
             'cached bytes': row.get('size'),
             'stored as a file': 'yes' if row.get('on_fs') else None,
             'basis': 'when the response was cached (UTC)'},
            user=user, path=path, ref=ref))
    return out


def _sqlite_time(value):
    """A 'YYYY-MM-DD HH:MM:SS' text time as SQLite writes it (UTC)."""
    import datetime
    if not value:
        return None
    if isinstance(value, (int, float)):
        return times.unix(value)
    try:
        when = datetime.datetime.fromisoformat(str(value).strip()[:19])
    except ValueError:
        return None
    return when.replace(tzinfo=times.UTC)


def _cfurl_response(blob):
    """(HTTP status, MIME type) from a cached NSHTTPURLResponse plist."""
    if not blob:
        return None, None
    try:
        archived = plistlib.loads(bytes(blob))
    except Exception:
        return None, None
    status = mime = None
    items = archived.get('Array') if isinstance(archived, dict) else None
    for value in items or ():
        if isinstance(value, int) and 100 <= value < 600 and status is None:
            status = value
        if isinstance(value, dict):
            for key, header in value.items():
                if str(key).lower() == 'content-type':
                    mime = str(header)
    return status, mime


#: XProtect Behavior Service columns (macOS 13+), whichever exist.
_XPROTECT_COLUMNS = {
    'rule': ('violated_rule',), 'path': ('exec_path',),
    'signing_id': ('exec_signing_id',), 'team_id': ('exec_team_id',),
    'cdhash': ('exec_cdhash',), 'sha256': ('exec_sha256',),
    'notarized': ('exec_is_notarized',),
    'responsible': ('responsible_path',),
    'responsible_id': ('responsible_signing_id',),
    'responsible_team': ('responsible_team_id',),
    'reported': ('reported',), 'profile': ('profile_hash',),
    'stamp': ('dt', 'date', 'timestamp'),
}


def xprotect_behavior(data, wal, user, path, ref):
    """XPdb, the XProtect Behavior Service's database (macOS 13+): each
    time a program did something one of Apple's behaviour rules watches
    (reading browser data, touching another app's files...), the rule, the
    program and what made it run."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        if 'events' not in _tables(db):
            return out
        fields = _select(db, 'events', _XPROTECT_COLUMNS)
        if not fields:
            return out
        cursor = db.execute(f"SELECT {', '.join(fields)} FROM events")
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, values)) for values in cursor.fetchall()]
    for row in rows:
        out.append(record(
            'antivirus', 'XProtect behaviour', _sqlite_time(row.get('stamp')),
            'Behaviour rule triggered',
            f"{row.get('rule') or ''} — {row.get('path') or ''}".strip(' —'),
            {'rule': row.get('rule'), 'program': row.get('path'),
             'signing id': row.get('signing_id'),
             'team id': row.get('team_id'), 'cdhash': row.get('cdhash'),
             'sha256': row.get('sha256'),
             'notarized': row.get('notarized'),
             'responsible program': row.get('responsible'),
             'responsible signing id': row.get('responsible_id'),
             'responsible team id': row.get('responsible_team'),
             'reported to Apple': row.get('reported'),
             'rule profile': row.get('profile'),
             'basis': 'when the behaviour was recorded'},
            user=user, path=path, ref=ref))
    return out


def launchpad(data, wal, user, path, ref):
    """Launchpad's database: every application it lists (so installed
    for that user at the time), with its bundle id and when the entry was
    last changed; the folder it was put in when there is one."""
    out = []
    with sqlite_bytes.open_database(data, wal) as db:
        tables = _tables(db)
        if 'apps' not in tables:
            return out
        apps = _columns(db, 'apps')
        fields = [f'a.{c} AS {alias}' for alias, c in (
            ('title', _pick(apps, 'title')),
            ('bundle', _pick(apps, 'bundleid')),
            ('store_id', _pick(apps, 'storeid')),
            ('changed', _pick(apps, 'moddate'))) if c]
        join = ''
        if {'items', 'groups'} <= tables and 'ITEM_ID' in apps:
            fields.append('g.title AS folder')
            join = (' LEFT JOIN items i ON i.rowid = a.item_id'
                    ' LEFT JOIN "groups" g ON g.item_id = i.parent_id')
        cursor = db.execute(f"SELECT {', '.join(fields)} FROM apps a{join}")
        names = [c[0] for c in cursor.description]
        rows = [dict(zip(names, values)) for values in cursor.fetchall()]
    for row in rows:
        out.append(record(
            'system', 'Launchpad', times.mac_absolute(row.get('changed')),
            'Application in Launchpad', row.get('title') or
            row.get('bundle') or '',
            {'bundle id': row.get('bundle'),
             'App Store id': row.get('store_id'),
             'folder': row.get('folder'),
             'basis': "when Launchpad's entry was last changed"},
            user=user, path=path, ref=ref))
    return out


def _strip_html(text):
    import re
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', text)).strip()

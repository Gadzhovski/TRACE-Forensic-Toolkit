"""Messages, calls and cloud sync: who the users talked to, and what their
files were synchronised with.

Read, from SQLite (recognised by its tables, so a carved database is read
the same way):

* Skype (classic) main.db -- messages, calls, file transfers, SMS
* iMessage chat.db (macOS) -- messages, with the other party
* Android mmssms.db -- text messages (an Android image, or a phone backup)
* Dropbox sync_history.db -- files uploaded and downloaded, with paths

Read from their logs: Google Drive (Backup and Sync) sync_log.log -- the
account, and files added, changed, moved and deleted; OneDrive's (SkyDrive)
text logs -- when the client ran, and which version.

Listed only, because their stores are encrypted (and no key is used):
Telegram Desktop (tdata), WhatsApp Desktop, Signal Desktop (SQLCipher) and
Microsoft Teams (LevelDB): that they were installed, for whom, and when
their data last changed.

Expected values in the tests are plaso's for the same files.
"""

import datetime
import html
import logging
import re
import sqlite3

from trace_app.core.activity import record, sqlite_bytes, times

logger = logging.getLogger('TRACE.Activity.Chat')

_TAGS = re.compile(r'<[^>]+>')


def _plain(text):
    return html.unescape(_TAGS.sub('', text or '')).strip()


def _tables(db):
    return {row[0].lower() for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(db, table):
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


# --- Skype ----------------------------------------------------------------------

def skype(db, user, path, ref, source='Skype'):
    out = []
    owners = {row[0] for row in db.execute("SELECT skypename FROM Accounts")
              if row[0]}
    chats = {}
    for name, topic, friendly, participants in db.execute(
            "SELECT name, topic, friendlyname, participants FROM Chats"):
        chats[name] = (topic or friendly or '', (participants or '').split())
    for (stamp, author, display, body, chatname, partner) in db.execute(
            "SELECT timestamp, author, from_dispname, body_xml, chatname, "
            "dialog_partner FROM Messages ORDER BY timestamp, id"):
        if (body or '').lstrip().startswith('<sms'):
            continue                    # an SMS: read from SMSes below
        text = _plain(body)
        if not text:
            continue
        topic, members = chats.get(chatname, ('', []))
        to = [m for m in members if m != author] or \
            ([partner] if partner and partner != author else [])
        sender = f"{display} <{author}>" if display and author else \
            (author or display or '')
        out.append(record('communication', source, times.unix(stamp),
                          'Skype message', text,
                          {'from': sender, 'to': ', '.join(to),
                           'chat': topic},
                          user=user, path=path, ref=ref))
    for (call_id, stamp, partner, partner_name, incoming, duration, host,
         conference) in db.execute(
            "SELECT id, begin_timestamp, partner_handle, partner_dispname, "
            "is_incoming, duration, host_identity, is_conference "
            "FROM Calls ORDER BY begin_timestamp"):
        rows = db.execute("SELECT identity, dispname, call_duration "
                          "FROM CallMembers WHERE call_db_id = ?",
                          (call_id,)).fetchall()
        members = [f"{name} <{identity}>" if name else identity
                   for identity, name, _seconds in rows if identity]
        duration = duration or max((r[2] or 0 for r in rows), default=0)
        who = ', '.join(members) or partner_name or partner
        out.append(record(
            'communication', source, times.unix(stamp),
            'Skype call received' if incoming else 'Skype call made',
            who or host or '',
            {'host': host, 'partner': partner,
             'seconds': duration or None,
             'conference': 'yes' if conference else ''},
            user=user, path=path, ref=ref))
    for (kind, partner, partner_name, status, start, finish, file_path,
         file_name, size, accepted) in db.execute(
            "SELECT type, partner_handle, partner_dispname, status, "
            "starttime, finishtime, filepath, filename, filesize, "
            "accepttime FROM Transfers ORDER BY starttime"):
        if partner in owners:
            continue                    # the offer itself, not a recipient
        sent = kind == 2
        out.append(record(
            'communication', source, times.unix(start),
            'File sent over Skype' if sent else 'File received over Skype',
            file_name or file_path or '',
            {'to' if sent else 'from':
             f"{partner_name} <{partner}>" if partner_name else partner,
             'path': file_path, 'size': size,
             'accepted': times.unix(accepted), 'finished': times.unix(finish),
             'status': status},
            user=user, path=path, ref=ref))
    if 'smses' in _tables(db):
        for stamp, numbers, body in db.execute(
                "SELECT timestamp, target_numbers, body FROM SMSes "
                "ORDER BY timestamp"):
            out.append(record('communication', source, times.unix(stamp),
                              'SMS sent from Skype', _plain(body),
                              {'to': numbers}, user=user, path=path,
                              ref=ref))
    for name, full, email, country, changed in db.execute(
            "SELECT skypename, fullname, emails, country, profile_timestamp "
            "FROM Accounts"):
        out.append(record('communication', source, times.unix(changed),
                          'Skype account', f"{full} <{name}>" if full
                          else (name or ''),
                          {'email': email, 'country': country,
                           'basis': 'when the profile last changed'},
                          user=user, path=path, ref=ref))
    return out


# --- iMessage ------------------------------------------------------------------------

def _apple_date(value):
    """Seconds since 2001, or nanoseconds since 10.13."""
    if not value:
        return None
    if value > 10 ** 12:
        value = value / 1e9
    return times.mac_absolute(value)


def imessage(db, user, path, ref, source='iMessage'):
    out = []
    for (text, date, read_date, from_me, service, handle, is_read,
         account) in db.execute(
            "SELECT m.text, m.date, m.date_read, m.is_from_me, m.service, "
            "h.id, m.is_read, m.account FROM message m LEFT JOIN handle h "
            "ON h.ROWID = m.handle_id ORDER BY m.date, m.ROWID"):
        out.append(record(
            'communication', source, _apple_date(date),
            f"{service or 'Message'} sent" if from_me
            else f"{service or 'Message'} received", text or '',
            {'to' if from_me else 'from': handle, 'account': account,
             'read': _apple_date(read_date) or ('yes' if is_read else '')},
            user=user, path=path, ref=ref))
    return out


# --- Android SMS ----------------------------------------------------------------------

_SMS_TYPES = {1: 'received', 2: 'sent', 3: 'draft', 4: 'outbox', 5: 'failed',
              6: 'queued'}


def android_sms(db, user, path, ref, source='Android SMS'):
    out = []
    for address, date, body, kind, read in db.execute(
            "SELECT address, date, body, type, read FROM sms ORDER BY date"):
        state = _SMS_TYPES.get(kind, str(kind))
        out.append(record(
            'communication', source,
            times.unix_micro(date * 1000) if date else None,
            f"SMS {state}", body or '',
            {'to' if kind in (2, 4, 5, 6) else 'from': address,
             'read': 'yes' if read else 'no'},
            user=user, path=path, ref=ref))
    return out


# --- Dropbox ---------------------------------------------------------------------------

def dropbox(db, user, path, ref, source='Dropbox'):
    out = []
    for (event, file_event, direction, file_id, local, other,
         stamp) in db.execute(
            "SELECT event_type, file_event_type, direction, file_id, "
            "local_path, other_user, timestamp FROM sync_history "
            "ORDER BY timestamp"):
        verb = {'upload': 'uploaded', 'download': 'downloaded'}.get(
            direction, direction or 'synced')
        out.append(record(
            'cloud', source, times.unix(stamp),
            f"Dropbox: {file_event or event or 'file'} {verb}", local or '',
            {'event': event, 'file id': file_id, 'other user': other},
            user=user, path=path, ref=ref))
    return out


#: (required tables, reader): the first whose tables are all present.
DATABASES = (
    ({'messages', 'chats', 'calls', 'transfers', 'accounts'}, skype),
    ({'message', 'handle', 'chat'}, imessage),
    ({'sms', 'threads'}, android_sms),
    ({'sms'}, android_sms),
    ({'sync_history'}, dropbox),
)


def read_database(data, wal, user, path, ref, carved=False):
    """Records from a chat or sync database, recognised by its tables;
    [] when it is none of them."""
    if not data or data[:16] != b'SQLite format 3\x00':
        return []
    try:
        with sqlite_bytes.open_database(data, wal) as db:
            tables = _tables(db)
            for required, reader in DATABASES:
                if required <= tables:
                    if reader is android_sms and \
                            'body' not in _columns(db, 'sms'):
                        continue
                    records = reader(db, user, path, ref)
                    if carved:
                        for item in records:
                            item['source'] += ' (carved)'
                    break
            else:
                return []
    except (sqlite3.DatabaseError, ValueError) as exc:
        logger.debug("%s unreadable: %s", path, exc)
        return []
    # Messages deleted, still in the database's free space.
    from trace_app.core.activity import recovered
    return records + recovered.deleted_records(data, wal, user, path, ref,
                                               carved)


# --- Google Drive and OneDrive logs ------------------------------------------------------

_GDRIVE = re.compile(
    r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) ([+-]\d{4}) (\w+) '
    r'pid=(\d+) (\S+)\s+(\S+) (.*)$')
_GDRIVE_ACCOUNT = re.compile(r'(?:Drive - |for )([\w.+-]+@[\w.-]+)')
_GDRIVE_FILE = re.compile(
    r'^(Deleting file|Deleting folder|Moving|Renaming|Uploading|Downloading|'
    r'Creating local (?:file|folder)|Updating local entry|'
    r'Creating cloud (?:file|folder)|Updating cloud entry|'
    r'Deleting cloud entry|Deleting local entry)\b[: ]*(.*)$')
_FILENAME = re.compile(r'filename=([^,]+)')


def gdrive_log(text):
    """[(datetime, level, message)] of a sync_log.log, its zone applied."""
    out = []
    for line in text.splitlines():
        match = _GDRIVE.match(line)
        if not match:
            if out:
                out[-1][2] += '\n' + line
            continue
        stamp, millis, zone, level, _pid, _thread, _code, message = \
            match.groups()
        try:
            when = datetime.datetime.strptime(
                f"{stamp}.{millis}000 {zone}", '%Y-%m-%d %H:%M:%S.%f %z')
        except ValueError:
            continue
        out.append([when, level, message])
    return [tuple(item) for item in out]


def gdrive_activity(text, user, path, ref):
    out, accounts = [], set()
    for when, _level, message in gdrive_log(text):
        account = _GDRIVE_ACCOUNT.search(message)
        if account and account.group(1) not in accounts:
            accounts.add(account.group(1))
            out.append(record('cloud', 'Google Drive', when,
                              'Google Drive account in use',
                              account.group(1),
                              {'basis': 'the first log line naming it'},
                              user=user, path=path, ref=ref))
        match = _GDRIVE_FILE.match(message)
        if match:
            action, rest = match.groups()
            name = _FILENAME.search(rest)
            subject = name.group(1) if name else rest.split(',')[0]
            out.append(record('cloud', 'Google Drive', when,
                              f"Google Drive: {action.lower()}",
                              subject.strip(), {'message': message[:400]},
                              user=user, path=path, ref=ref))
    return out


_SKYDRIVE_V1 = re.compile(
    r'^(\d\d)-(\d\d)-(\d{4}) (\d\d):(\d\d):(\d\d)\.(\d{3}) '
    r'\S+!logVersionInfo \(\w+\): (.*)$')
_SKYDRIVE_START = re.compile(
    r'^######Logging started\. Version=(\S+) StartSystemTime:'
    r'(\d{4})-(\d\d)-(\d\d)-(\d\d)(\d\d)(\d\d)\.(\d{3})')


def onedrive_log_activity(text, user, path, ref):
    out = []
    for line in text.splitlines():
        old = _SKYDRIVE_V1.match(line)
        if old:
            month, day, year, hour, minute, second, millis, version = \
                old.groups()
            when = datetime.datetime(int(year), int(month), int(day),
                                     int(hour), int(minute), int(second),
                                     int(millis) * 1000, tzinfo=times.UTC)
            out.append(record('cloud', 'OneDrive', when,
                              'OneDrive (SkyDrive) client started',
                              f"version {version}", {}, user=user,
                              path=path, ref=ref))
            continue
        match = _SKYDRIVE_START.match(line)
        if not match:
            continue
        version = match.group(1)
        parts = [int(p) for p in match.groups()[1:]]
        when = datetime.datetime(*parts[:6], parts[6] * 1000,
                                 tzinfo=times.UTC)
        out.append(record('cloud', 'OneDrive', when,
                          'OneDrive (SkyDrive) client started',
                          f"version {version}", {}, user=user, path=path,
                          ref=ref))
    return out


# --- the volume --------------------------------------------------------------------------

#: (path under a home, reader name) for databases at fixed places; a '*'
#: part is every folder there (Skype names one per account).
_DATABASE_HOMES = (
    ('AppData', 'Roaming', 'Skype', '*', 'main.db'),
    ('Application Data', 'Skype', '*', 'main.db'),
    ('Library', 'Application Support', 'Skype', '*', 'main.db'),
    ('.Skype', '*', 'main.db'),
    ('Library', 'Messages', 'chat.db'),
    ('AppData', 'Local', 'Dropbox', '*', 'sync_history.db'),
    ('.dropbox', '*', 'sync_history.db'),
)
_GDRIVE_HOMES = (
    ('AppData', 'Local', 'Google', 'Drive', '*', 'sync_log.log'),
    ('Library', 'Application Support', 'Google', 'Drive', '*',
     'sync_log.log'),
)
_ONEDRIVE_LOGS = (
    ('AppData', 'Local', 'Microsoft', 'SkyDrive', 'logs'),
    ('AppData', 'Local', 'Microsoft', 'OneDrive', 'logs'),
)
#: Encrypted stores: listed, never read.
ENCRYPTED_APPS = (
    ('Telegram Desktop', ('AppData', 'Roaming', 'Telegram Desktop',
                          'tdata')),
    ('Telegram Desktop', ('Library', 'Application Support',
                          'Telegram Desktop', 'tdata')),
    ('Telegram Desktop', ('.local', 'share', 'TelegramDesktop', 'tdata')),
    ('WhatsApp Desktop', ('AppData', 'Local', 'Packages',
                          '5319275A.WhatsAppDesktop_cv1g1gvanyjgm')),
    ('WhatsApp Desktop', ('AppData', 'Roaming', 'WhatsApp')),
    ('WhatsApp', ('Library', 'Group Containers',
                  'group.net.whatsapp.WhatsApp.shared')),
    ('Signal Desktop', ('AppData', 'Roaming', 'Signal', 'sql')),
    ('Signal Desktop', ('Library', 'Application Support', 'Signal', 'sql')),
    ('Signal Desktop', ('.config', 'Signal', 'sql')),
    ('Microsoft Teams', ('AppData', 'Roaming', 'Microsoft', 'Teams',
                         'IndexedDB')),
    ('Microsoft Teams', ('AppData', 'Local', 'Packages',
                         'MSTeams_8wekyb3d8bbwe')),
)


def _matches(volume, base, parts):
    """Entries at `base`/`parts`, '*' standing for every folder."""
    from trace_app.core.activity import _split
    found = [volume.find(*base)] if base else []
    if not found or found[0] is None:
        return []
    for part in parts:
        following = []
        for entry in found:
            if part == '*':
                following += volume.children(entry, dirs=True)
            else:
                hit = volume.find(*_split(entry.path), part)
                if hit is not None:
                    following.append(hit)
        found = following
    return found


def collect(volume, step, homes):
    from trace_app.core.activity import _split
    out = []
    for user, home in homes:
        base = _split(home.path)
        for parts in _DATABASE_HOMES:
            for entry in _matches(volume, base, parts):
                if entry.is_dir:
                    continue
                step(entry.path)
                parts_of = _split(entry.path)
                wal = volume.find(*parts_of[:-1], parts_of[-1] + '-wal')
                out += read_database(volume.read(entry),
                                     volume.read(wal) if wal else None,
                                     user, entry.path, volume.ref(entry))
        for parts in _GDRIVE_HOMES:
            for entry in _matches(volume, base, parts):
                step(entry.path)
                out += gdrive_activity(
                    volume.read(entry).decode('utf-8', 'replace'), user,
                    entry.path, volume.ref(entry))
        for parts in _ONEDRIVE_LOGS:
            for folder in _matches(volume, base, parts):
                for entry in volume.children(folder, '.log'):
                    step(entry.path)
                    data = volume.read(entry)
                    text = data.decode('utf-16' if data[:2] in (
                        b'\xff\xfe', b'\xfe\xff') else 'utf-8', 'replace')
                    out += onedrive_log_activity(text, user, entry.path,
                                                 volume.ref(entry))
        for app, parts in ENCRYPTED_APPS:
            for entry in _matches(volume, base, parts):
                accounts = [c.name for c in volume.children(entry, dirs=True)
                            if re.fullmatch(r'[0-9A-F]{16}', c.name)] \
                    if app == 'Telegram Desktop' else []
                out.append(record(
                    'communication', app, entry.modified,
                    f"{app} data present (encrypted)", entry.path,
                    {'accounts': len(accounts) or None,
                     'basis': "when the folder last changed; its messages "
                              "are encrypted and are not read"},
                    user=user, path=entry.path, ref=volume.ref(entry)))
    # An Android image: the telephony provider's database.
    for parts in (('data', 'data', 'com.android.providers.telephony',
                   'databases', 'mmssms.db'),
                  ('data', 'user_de', '0', 'com.android.providers.telephony',
                   'databases', 'mmssms.db')):
        entry = volume.find(*parts)
        if entry is not None and not entry.is_dir:
            step(entry.path)
            wal = volume.find(*parts[:-1], 'mmssms.db-wal')
            out += read_database(volume.read(entry),
                                 volume.read(wal) if wal else None, '',
                                 entry.path, volume.ref(entry))
    return out

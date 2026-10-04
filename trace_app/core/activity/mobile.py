"""Phones: what an iPhone backup or file system, or an Android extraction,
records about calls, contacts, messages, accounts, Wi-Fi and the device.

**iOS** (a backup through core/ios_backup.py, or a full file system
extraction -- the same paths):

* the backup itself (Info.plist): the device, its numbers, when backed up;
* CallHistory.storedata -- calls, FaceTime included;
* AddressBook.sqlitedb -- contacts, when each was added;
* WhatsApp's ChatStorage.sqlite -- messages, with the chat they are in;
* Accounts3.sqlite -- accounts set up on the phone;
* com.apple.wifi.known-networks.plist (iOS 16+) and com.apple.wifi.plist
  -- networks joined, with when and the access points.

Messages (sms.db) and Safari history are read by the readers that read
them on a Mac (activity/chat.py, the browsers), /private/var/mobile being
the phone's one home.

**Android** (a file system extraction: a folder, TAR or ZIP of / or of the
data partition):

* contacts2.db / calllog.db -- calls; contacts2.db -- contacts;
* WhatsApp's msgstore.db (unencrypted, as on the phone; the .crypt14/15
  backups need the key file and are not read) and wa.db for names;
* Chrome's History (activity's browser reader);
* accounts_ce.db / accounts_de.db / accounts.db -- accounts;
* WifiConfigStore.xml / wpa_supplicant.conf -- saved networks (whether a
  password is saved is said; the password is not copied into the case);
* build.prop -- the device and Android version.

mmssms.db is read by activity/chat.py. Expected values in the tests are
plaso's (contacts2.db calls, Accounts3.sqlite, known networks) and MVT's
(its backup's WhatsApp and SMS) for the same files; WhatsApp's msgstore.db,
accounts, WifiConfigStore and build.prop have no published sample and are
written by the tests in the apps' schemas.
"""

import datetime
import logging
import plistlib
import re
import sqlite3
import xml.etree.ElementTree as ElementTree

from trace_app.core.activity import record, sqlite_bytes, times

logger = logging.getLogger('TRACE.Activity.Mobile')

MOBILE = ('private', 'var', 'mobile')


def _tables(db):
    return {row[0].lower() for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(db, table):
    return {row[1].lower() for row in db.execute(
        f"PRAGMA table_info({table})")}


def _database(volume, entry):
    """(bytes, wal bytes or None) of a database entry."""
    from trace_app.core.activity import _split
    parts = _split(entry.path)
    wal = volume.find(*parts[:-1], parts[-1] + '-wal')
    return volume.read(entry), (volume.read(wal) if wal else None)


def _read(volume, entry, reader, step, *args):
    """Records from one database through `reader(db, path, ref, *args)`;
    [] when it is not readable as that."""
    if entry is None or entry.is_dir:
        return []
    step(entry.path)
    data, wal = _database(volume, entry)
    if data[:16] != b'SQLite format 3\x00':
        return []
    try:
        with sqlite_bytes.open_database(data, wal) as db:
            return reader(db, entry.path, volume.ref(entry), *args)
    except (sqlite3.DatabaseError, ValueError, KeyError) as exc:
        logger.debug("%s unreadable: %s", entry.path, exc)
        return []


def _apple(value):
    """A Mac absolute time (seconds since 2001), as Core Data stores it."""
    if value in (None, ''):
        return None
    try:
        return times.mac_absolute(float(value))
    except (TypeError, ValueError, OverflowError):
        return None


def _ms(value):
    """Milliseconds since 1970, as Android stores times."""
    if not value:
        return None
    try:
        return times.unix_micro(int(value) * 1000)
    except (TypeError, ValueError, OverflowError):
        return None


def _seconds(value):
    if value in (None, ''):
        return None
    minutes, seconds = divmod(int(value), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else \
        f"{minutes}:{seconds:02d}"


# --- iOS -------------------------------------------------------------------------------

def is_ios(volume):
    return volume.find(*MOBILE, 'Library') is not None


def backup_record(volume):
    """The backup's own record: the device, and when it was backed up."""
    entry = volume.find('Backup', 'Info.plist')
    if entry is None:
        return []
    try:
        info = plistlib.loads(volume.read(entry))
    except Exception:
        return []
    when = info.get('Last Backup Date')
    if isinstance(when, datetime.datetime) and when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    device = ' '.join(str(info[k]) for k in ('Device Name', 'Product Type')
                      if info.get(k))
    detail = {key: info.get(key) for key in (
        'Product Version', 'Build Version', 'Serial Number', 'IMEI',
        'IMEI 2', 'MEID', 'Phone Number', 'ICCID', 'Unique Identifier',
        'iTunes Version') if info.get(key)}
    apps = info.get('Installed Applications') or []
    if apps:
        detail['installed apps'] = ', '.join(apps[:50]) + \
            (f" and {len(apps) - 50} more" if len(apps) > 50 else '')
    return [record('system', 'iOS backup', when,
                   'Backed up (iTunes / Finder)', device or 'iPhone',
                   detail, path=entry.path, ref=volume.ref(entry))]


_CALL_KINDS = {1: 'Phone', 8: 'FaceTime video', 16: 'FaceTime audio'}


def ios_calls(db, path, ref):
    columns = _columns(db, 'zcallrecord')
    wanted = [c for c in ('zaddress', 'zdate', 'zduration', 'zoriginated',
                          'zanswered', 'zcalltype', 'zname',
                          'ziso_country_code', 'zservice_provider',
                          'zlocation') if c in columns]
    out = []
    for row in db.execute(f"SELECT {', '.join(wanted)} FROM ZCALLRECORD "
                          f"ORDER BY ZDATE"):
        item = dict(zip(wanted, row))
        address = item.get('zaddress')
        if isinstance(address, bytes):
            address = address.decode('utf-8', 'replace')
        outgoing = bool(item.get('zoriginated'))
        answered = bool(item.get('zanswered'))
        kind = _CALL_KINDS.get(item.get('zcalltype'), 'Call')
        what = (f"{kind} call made" if outgoing else
                f"{kind} call received" if answered else
                f"{kind} call missed")
        out.append(record(
            'communication', 'iOS call history', _apple(item.get('zdate')),
            what, address or '',
            {'to' if outgoing else 'from': address,
             'name': item.get('zname'),
             'duration': _seconds(item.get('zduration')),
             'app': item.get('zservice_provider'),
             'country': item.get('ziso_country_code'),
             'location': item.get('zlocation')},
            path=path, ref=ref))
    return out


#: ABMultiValue property numbers.
_PHONE, _EMAIL = 3, 4


def ios_contacts(db, path, ref):
    values = {}
    for owner, prop, value in db.execute(
            "SELECT record_id, property, value FROM ABMultiValue "
            "WHERE property IN (3, 4)"):
        values.setdefault(owner, {}).setdefault(prop, []).append(value)
    out = []
    for rowid, first, last, organisation, created, modified in db.execute(
            "SELECT ROWID, First, Last, Organization, CreationDate, "
            "ModificationDate FROM ABPerson ORDER BY CreationDate"):
        name = ' '.join(p for p in (first, last) if p) or organisation or ''
        found = values.get(rowid, {})
        out.append(record(
            'communication', 'iOS contacts', _apple(created), 'Contact added',
            name, {'phone': ', '.join(map(str, found.get(_PHONE, []))) or None,
                   'email': ', '.join(map(str, found.get(_EMAIL, []))) or None,
                   'organisation': organisation,
                   'modified': times.iso(_apple(modified))},
            path=path, ref=ref))
    return out


def ios_whatsapp(db, path, ref):
    sessions = {}
    for pk, jid, partner in db.execute(
            "SELECT Z_PK, ZCONTACTJID, ZPARTNERNAME FROM ZWACHATSESSION"):
        sessions[pk] = (jid, partner)
    columns = _columns(db, 'zwamessage')
    member = 'ZGROUPMEMBER' if 'zgroupmember' in columns else 'NULL'
    members = {}
    if member != 'NULL' and 'zwagroupmember' in _tables(db):
        members = {pk: (jid, name) for pk, jid, name in db.execute(
            "SELECT Z_PK, ZMEMBERJID, ZCONTACTNAME FROM ZWAGROUPMEMBER")}
    out = []
    for (text, when, mine, sender, recipient, session,
         group_member) in db.execute(
            f"SELECT ZTEXT, ZMESSAGEDATE, ZISFROMME, ZFROMJID, ZTOJID, "
            f"ZCHATSESSION, {member} FROM ZWAMESSAGE ORDER BY ZMESSAGEDATE"):
        jid, partner = sessions.get(session, (None, None))
        group = (jid or '').endswith('@g.us')
        detail = {'chat': partner or jid, 'chat id': jid}
        if mine:
            detail['to'] = recipient or jid
        else:
            who = members.get(group_member)
            detail['from'] = (who[1] or who[0]) if who else (sender or jid)
        out.append(record(
            'communication', 'WhatsApp (iOS)', _apple(when),
            ('Group message sent' if group else 'Message sent') if mine else
            ('Group message received' if group else 'Message received'),
            text or '', detail, path=path, ref=ref))
    return out


def ios_accounts(db, path, ref):
    out = []
    for when, kind, user, identifier, bundle in db.execute(
            "SELECT a.ZDATE, t.ZACCOUNTTYPEDESCRIPTION, a.ZUSERNAME, "
            "a.ZIDENTIFIER, a.ZOWNINGBUNDLEID FROM ZACCOUNT a LEFT JOIN "
            "ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK ORDER BY a.ZDATE"):
        out.append(record(
            'system', 'iOS accounts', _apple(when),
            f"Account added: {kind or 'account'}", user or '',
            {'type': kind, 'identifier': identifier, 'set up by': bundle},
            path=path, ref=ref))
    return out


def _utc(value):
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else \
            value.replace(tzinfo=datetime.timezone.utc)
    return None


def ios_known_networks(data, path, ref):
    """com.apple.wifi.known-networks.plist: a record per access point the
    phone joined (when last), and one for when the network was added."""
    networks = plistlib.loads(data)
    out = []
    for key, network in networks.items():
        if not isinstance(network, dict):
            continue
        ssid = network.get('SSID')
        ssid = ssid.decode('utf-8', 'replace') if isinstance(ssid, bytes) \
            else (ssid or key.split(':', 1)[-1])
        common = {'security': network.get('SupportedSecurityTypes'),
                  'hidden': network.get('Hidden'),
                  'joined by user': times.iso(_utc(
                      network.get('JoinedByUserAt'))),
                  'joined by the system': times.iso(_utc(
                      network.get('JoinedBySystemAt')))}
        out.append(record('network', 'iOS Wi-Fi', _utc(
            network.get('AddedAt')), 'Wi-Fi network added', ssid, common,
            path=path, ref=ref))
        for bss in network.get('BSSList') or []:
            out.append(record(
                'network', 'iOS Wi-Fi', _utc(bss.get('LastAssociatedAt')),
                'Wi-Fi joined', ssid,
                dict(common, BSSID=bss.get('BSSID'),
                     channel=bss.get('Channel'),
                     basis="the last time the phone joined this access "
                           "point"), path=path, ref=ref))
    return out


def ios_wifi_plist(data, path, ref):
    """com.apple.wifi.plist (before iOS 16): 'List of known networks'."""
    out = []
    for network in plistlib.loads(data).get('List of known networks') or []:
        ssid = network.get('SSID_STR') or ''
        for field, what in (('lastJoined', 'Wi-Fi joined'),
                            ('lastAutoJoined', 'Wi-Fi joined automatically'),
                            ('addedAt', 'Wi-Fi network added')):
            when = _utc(network.get(field))
            if when is None:
                continue
            out.append(record('network', 'iOS Wi-Fi', when, what, ssid,
                              {'BSSID': network.get('BSSID'),
                               'security': network.get('SecurityMode')},
                              path=path, ref=ref))
    return out


def ios(volume, step):
    out = backup_record(volume)
    library = (*MOBILE, 'Library')
    out += _read(volume, volume.find(*library, 'CallHistoryDB',
                                     'CallHistory.storedata'),
                 ios_calls, step)
    out += _read(volume, volume.find(*library, 'AddressBook',
                                     'AddressBook.sqlitedb'),
                 ios_contacts, step)
    out += _read(volume, volume.find(*library, 'Accounts',
                                     'Accounts3.sqlite'), ios_accounts, step)
    groups = volume.find(*MOBILE, 'Containers', 'Shared', 'AppGroup')
    for group in volume.children(groups, dirs=True):
        out += _read(volume, volume.find(*_split(group.path),
                                         'ChatStorage.sqlite'),
                     ios_whatsapp, step)
    for parts, reader in (
            (('private', 'var', 'preferences',
              'com.apple.wifi.known-networks.plist'), ios_known_networks),
            (('private', 'var', 'preferences', 'SystemConfiguration',
              'com.apple.wifi.plist'), ios_wifi_plist)):
        entry = volume.find(*parts)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        try:
            out += reader(volume.read(entry), entry.path, volume.ref(entry))
        except Exception as exc:
            logger.debug("%s unreadable: %s", entry.path, exc)
    return out


def _split(path):
    from trace_app.core.activity import _split as split
    return split(path)


# --- Android ---------------------------------------------------------------------------

def android_base(volume):
    """The path parts the data partition starts at -- ('data',) for a
    whole file system, () for the partition itself -- or None."""
    if volume.find('data', 'data') is not None or \
            volume.find('data', 'system') is not None:
        return ('data',)
    if volume.find('system', 'packages.xml') is not None or \
            volume.find('data', 'com.android.providers.telephony') is not None:
        return ()
    return None


def _app(volume, base, package, *parts):
    """An app's file, from its credential- or device-encrypted storage."""
    for where in (('data',), ('user', '0'), ('user_de', '0')):
        entry = volume.find(*base, *where, package, *parts)
        if entry is not None:
            return entry
    return None


_CALL_TYPES = {1: 'received', 2: 'made', 3: 'missed', 4: 'voicemail',
               5: 'rejected', 6: 'blocked', 7: 'answered elsewhere'}


def android_calls(db, path, ref):
    columns = _columns(db, 'calls')
    extra = [c for c in ('geocoded_location', 'countryiso',
                         'subscription_component_name', 'is_read')
             if c in columns]
    out = []
    for row in db.execute(
            "SELECT date, duration, name, number, type"
            + ''.join(f", {c}" for c in extra) + " FROM calls ORDER BY date"):
        when, duration, name, number, kind = row[:5]
        more = dict(zip(extra, row[5:]))
        state = _CALL_TYPES.get(kind, f'type {kind}')
        out.append(record(
            'communication', 'Android call log', _ms(when), f"Call {state}",
            number or '',
            {'to' if kind == 2 else 'from': number, 'name': name,
             'duration': _seconds(duration),
             'location': more.get('geocoded_location'),
             'country': more.get('countryiso'),
             'app': more.get('subscription_component_name')},
            path=path, ref=ref))
    return out


def android_contacts(db, path, ref):
    """contacts2.db's people: a name and their numbers and addresses."""
    tables = _tables(db)
    if not {'data', 'mimetypes', 'raw_contacts'} <= tables:
        return []
    found = {}
    for contact, kind, value in db.execute(
            "SELECT d.raw_contact_id, m.mimetype, d.data1 FROM data d "
            "JOIN mimetypes m ON m._id = d.mimetype_id"):
        found.setdefault(contact, {}).setdefault(kind, []).append(value)
    columns = _columns(db, 'raw_contacts')
    when = 'last_time_contacted' if 'last_time_contacted' in columns \
        else 'NULL'
    deleted = 'deleted' if 'deleted' in columns else '0'
    out = []
    for rowid, name, contacted, removed in db.execute(
            f"SELECT _id, display_name, {when}, {deleted} FROM raw_contacts"):
        values = found.get(rowid, {})
        phones = values.get('vnd.android.cursor.item/phone_v2', [])
        mails = values.get('vnd.android.cursor.item/email_v2', [])
        out.append(record(
            'communication', 'Android contacts', _ms(contacted),
            'Contact (deleted)' if removed else 'Contact', name or '',
            {'phone': ', '.join(p for p in phones if p) or None,
             'email': ', '.join(m for m in mails if m) or None,
             'basis': "the last time the contact was called or messaged"
                      if contacted else "no time is recorded for a contact"},
            path=path, ref=ref))
    return out


def android_whatsapp(db, path, ref, names=None):
    """msgstore.db: the 'message' table (2022 on) or 'messages' (before)."""
    names = names or {}
    tables = _tables(db)
    out = []

    def name_of(jid):
        return names.get(jid) or jid

    if {'message', 'chat', 'jid'} <= tables:
        jids = {row[0]: row[1] for row in db.execute(
            "SELECT _id, raw_string FROM jid")}
        chats = {row[0]: (jids.get(row[1]), row[2]) for row in db.execute(
            "SELECT _id, jid_row_id, subject FROM chat")}
        columns = _columns(db, 'message')
        sender = 'sender_jid_row_id' if 'sender_jid_row_id' in columns \
            else 'NULL'
        for chat, mine, text, when, who in db.execute(
                f"SELECT chat_row_id, from_me, text_data, timestamp, {sender} "
                f"FROM message ORDER BY timestamp"):
            jid, subject = chats.get(chat, (None, None))
            group = (jid or '').endswith('@g.us')
            detail = {'chat': subject or name_of(jid), 'chat id': jid}
            if mine:
                detail['to'] = name_of(jid)
            else:
                detail['from'] = name_of(jids.get(who) or jid)
            out.append(record(
                'communication', 'WhatsApp (Android)', _ms(when),
                ('Group message sent' if group else 'Message sent') if mine
                else ('Group message received' if group
                      else 'Message received'),
                text or '', detail, path=path, ref=ref))
        return out
    if 'messages' in tables:
        for jid, mine, text, when, author in db.execute(
                "SELECT key_remote_jid, key_from_me, data, timestamp, "
                "remote_resource FROM messages ORDER BY timestamp"):
            if jid == '-1':
                continue                    # WhatsApp's own status row
            group = (jid or '').endswith('@g.us')
            detail = {'chat': name_of(jid), 'chat id': jid}
            if mine:
                detail['to'] = name_of(jid)
            else:
                detail['from'] = name_of(author or jid)
            out.append(record(
                'communication', 'WhatsApp (Android)', _ms(when),
                ('Group message sent' if group else 'Message sent') if mine
                else ('Group message received' if group
                      else 'Message received'),
                text or '', detail, path=path, ref=ref))
    return out


def whatsapp_names(db, _path, _ref):
    """wa.db: {jid: display name}."""
    if 'wa_contacts' not in _tables(db):
        return {}
    return {jid: name for jid, name in db.execute(
        "SELECT jid, display_name FROM wa_contacts") if jid and name}


def android_accounts(db, path, ref):
    columns = _columns(db, 'accounts')
    when = 'last_password_entry_time_millis_epoch' \
        if 'last_password_entry_time_millis_epoch' in columns else 'NULL'
    out = []
    for name, kind, entered in db.execute(
            f"SELECT name, type, {when} FROM accounts"):
        out.append(record(
            'system', 'Android accounts', _ms(entered),
            f"Account on the phone: {kind}", name or '',
            {'type': kind,
             'basis': "when its password was last entered" if entered
             else "no time is recorded for this account"},
            path=path, ref=ref))
    return out


def _xml_values(element):
    """{name: value} of an Android settings XML element's children."""
    out = {}
    for child in element:
        name = child.get('name')
        if name is None:
            continue
        out[name] = child.get('value') if child.get('value') is not None \
            else (child.text or '')
    return out


def wifi_config_store(data, path, ref):
    """WifiConfigStore.xml (Android 8+): saved networks."""
    if data[:4] == b'ABX\x00':
        from trace_app.core.activity import abx
        data = abx.to_xml(data)
    root = ElementTree.fromstring(data)
    out = []
    for network in root.iter('Network'):
        config = network.find('WifiConfiguration')
        if config is None:
            continue
        values = _xml_values(config)
        status = _xml_values(network.find('NetworkStatus')) \
            if network.find('NetworkStatus') is not None else {}
        ssid = (values.get('SSID') or '').strip('"')
        key = values.get('ConfigKey') or ''
        security = key[len(values.get('SSID') or ''):] if key else ''
        created = values.get('CreationTime') or ''
        out.append(record(
            'network', 'Android Wi-Fi', None, 'Wi-Fi network saved', ssid,
            {'security': security or None,
             'password saved': 'yes' if values.get('PreSharedKey')
             else None,
             'hidden': values.get('HiddenSSID'),
             'added by': values.get('CreatorName'),
             'last changed by': values.get('LastUpdateName'),
             'created': created.replace('time=', '') or None,
             'status': status.get('SelectionStatus'),
             'basis': "Android records no reliable time for a saved "
                      "network ('created' has no year)"},
            path=path, ref=ref))
    return out


_NETWORK_BLOCK = re.compile(r'network=\{(.*?)\}', re.S)


def wpa_supplicant(text, path, ref):
    out = []
    for block in _NETWORK_BLOCK.findall(text):
        values = {key: value.strip() for key, value in
                  re.findall(r'^\s*(\w+)=(.*)$', block, re.M)}
        out.append(record(
            'network', 'Android Wi-Fi', None, 'Wi-Fi network saved',
            values.get('ssid', '').strip('"'),
            {'security': values.get('key_mgmt'),
             'password saved': 'yes' if values.get('psk') else None,
             'basis': "wpa_supplicant.conf records no time"},
            path=path, ref=ref))
    return out


_PROPS = ('ro.product.manufacturer', 'ro.product.model', 'ro.product.name',
          'ro.product.device', 'ro.build.version.release',
          'ro.build.version.sdk', 'ro.build.version.security_patch',
          'ro.build.fingerprint', 'ro.build.display.id', 'ro.serialno')


def build_prop(text, path, ref):
    props = {key: value.strip() for key, value in
             re.findall(r'^([\w.]+)=(.*)$', text, re.M)}
    if not any(p in props for p in _PROPS):
        return []
    try:
        built = times.unix(int(props.get('ro.build.date.utc') or 0)) or None
    except ValueError:
        built = None
    device = ' '.join(props[p] for p in ('ro.product.manufacturer',
                                         'ro.product.model') if props.get(p))
    return [record(
        'system', 'Android build', built,
        f"Android {props.get('ro.build.version.release', '')}".strip(),
        device or props.get('ro.product.device', ''),
        dict({p.split('.', 1)[1]: props[p] for p in _PROPS if props.get(p)},
             basis="when this Android build was made, not when the phone "
                   "was used"),
        path=path, ref=ref)]


def android(volume, step, base):
    from trace_app.core.activity import _history
    out = []
    contacts = _app(volume, base, 'com.android.providers.contacts',
                    'databases', 'contacts2.db')
    calllog = _app(volume, base, 'com.android.providers.contacts',
                   'databases', 'calllog.db')
    for entry in (calllog, contacts):
        out += _read(volume, entry, lambda db, p, r:
                     android_calls(db, p, r)
                     if 'calls' in _tables(db) else [], step)
    out += _read(volume, contacts, android_contacts, step)
    wa_db = _app(volume, base, 'com.whatsapp', 'databases', 'wa.db')
    names = _read(volume, wa_db, whatsapp_names, step) if wa_db else {}
    out += _read(volume, _app(volume, base, 'com.whatsapp', 'databases',
                              'msgstore.db'),
                 android_whatsapp, step, names or {})
    chrome = _app(volume, base, 'com.android.chrome', 'app_chrome',
                  'Default', 'History')
    if chrome is not None and not chrome.is_dir:
        step(chrome.path)
        data, wal = _database(volume, chrome)
        out += _history(data, wal, '', chrome.path, volume.ref(chrome),
                        'Chrome (Android)', profile='Default')
    for parts in (('system_de', '0', 'accounts_de.db'),
                  ('system_ce', '0', 'accounts_ce.db'),
                  ('system', 'users', '0', 'accounts.db')):
        found = _read(volume, volume.find(*base, *parts), android_accounts,
                      step)
        if found:
            out += found
            break
    for parts in (('misc', 'apexdata', 'com.android.wifi',
                   'WifiConfigStore.xml'),
                  ('misc', 'wifi', 'WifiConfigStore.xml')):
        entry = volume.find(*base, *parts)
        if entry is not None and not entry.is_dir:
            step(entry.path)
            try:
                out += wifi_config_store(volume.read(entry), entry.path,
                                         volume.ref(entry))
            except Exception as exc:
                logger.debug("%s unreadable: %s", entry.path, exc)
            break
    else:
        entry = volume.find(*base, 'misc', 'wifi', 'wpa_supplicant.conf')
        if entry is not None and not entry.is_dir:
            step(entry.path)
            out += wpa_supplicant(volume.read(entry).decode('utf-8',
                                                            'replace'),
                                  entry.path, volume.ref(entry))
    for parts in (('system', 'build.prop'), ('system', 'system',
                                             'build.prop')):
        entry = volume.find(*parts)
        if entry is not None and not entry.is_dir:
            step(entry.path)
            out += build_prop(volume.read(entry).decode('utf-8', 'replace'),
                              entry.path, volume.ref(entry))
            break
    return out


def collect(volume, step):
    out = []
    if is_ios(volume) or volume.find('Backup', 'Info.plist') is not None:
        out += ios(volume, step)
    base = android_base(volume)
    if base is not None:
        out += android(volume, step, base)
    return out

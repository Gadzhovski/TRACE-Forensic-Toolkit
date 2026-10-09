"""Phones: iPhone backups (core/ios_backup.py) and what activity reads from
an iPhone or an Android extraction (core/activity/mobile.py, abx.py).

* MVT's test backup -- a real Manifest.db of 3,721 files and the eleven
  files it keeps -- opens as evidence, its files where they were on the
  phone, byte for byte as stored; its WhatsApp and SMS messages are read.
* No encrypted backup is published, so an encrypted twin of MVT's is made
  here the way iTunes makes one (keybag, PBKDF2, RFC 3394 key wrap,
  AES-CBC per file) and every file must decrypt to its plain twin.
* plaso's contacts2.db, Accounts3.sqlite and known-networks plist, with
  the values plaso's own tests expect.
* CCL's Android binary XML files must read as the XML they were written
  from.
* An Android extraction as a folder and as a TAR: calls, contacts,
  WhatsApp, accounts, Wi-Fi (text and binary XML) and the build. Those
  databases are written here with Python's sqlite3, in the apps' schemas.
"""

import hashlib
import os
import plistlib
import shutil
import sqlite3
import struct
import tarfile
import xml.etree.ElementTree as ElementTree

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
MVT = 'mvt-ios-backup'


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def _stored(backup):
    """{phone path: bytes} of every file the backup keeps, from Manifest.db
    read directly -- independent of TRACE's reader."""
    from trace_app.core.ios_backup import phone_path
    db = sqlite3.connect(os.path.join(backup, 'Manifest.db'))
    out = {}
    for file_id, domain, relative in db.execute(
            "SELECT fileID, domain, relativePath FROM Files WHERE flags = 1"):
        stored = os.path.join(backup, file_id[:2], file_id)
        if os.path.isfile(stored):
            with open(stored, 'rb') as handle:
                out['/' + phone_path(domain, relative)] = handle.read()
    db.close()
    return out


def _read(handler, path):
    fs = handler.get_fs_info(0)
    node = fs.lookup(path)
    return node.reader(0, node.size) if node.size else b''


# --- an unencrypted backup: MVT's ---------------------------------------------

def test_mvt_backup_opens_as_a_phone():
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.logical_sources import kind_of
    path = sample(MVT)
    sample(f'{MVT}/Manifest.db')
    assert kind_of(path) == 'ios_backup'
    handler = ImageHandler(path)
    assert handler.loaded and handler.get_fs_type(0) == 'iOS backup'
    assert handler.encryption(0) is None
    facts = handler.logical_fs.facts
    assert facts['Product Type'] == 'iPhone9,3'
    assert facts['Product Version'] == '14.3'
    assert facts['IMEI'] == '42'
    assert facts['Serial Number'] == 'F1234567890'
    assert facts['Last Backup Date'] == '2021-12-03 19:33:13 UTC'
    # Every file Manifest.db lists is in the tree; the ten it keeps a copy
    # of read back as stored (the eleventh copy is not in Manifest.db).
    db = sqlite3.connect(os.path.join(path, 'Manifest.db'))
    files = db.execute("SELECT COUNT(*) FROM Files WHERE flags = 1"
                       ).fetchone()[0]
    db.close()
    assert facts['Files'] == f"{files:,}"
    stored = _stored(path)
    assert len(stored) == 10
    for phone, data in stored.items():
        assert _read(handler, phone) == data, phone
    assert _read(handler, '/private/var/mobile/Library/SMS/sms.db')[:16] \
        == b'SQLite format 3\x00'
    # The backup's own files, as they are on disk.
    with open(os.path.join(path, 'Info.plist'), 'rb') as handle:
        assert _read(handler, '/Backup/Info.plist') == handle.read()


def test_mvt_backup_messages():
    """MVT's WhatsApp and SMS checks read the same rows: an SMS carrying a
    link, and WhatsApp messages in a one-to-one chat and a group."""
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    path = sample(MVT)
    sample(f'{MVT}/Manifest.db')
    records = collect(ImageHandler(path))
    backup = [r for r in records if r['source'] == 'iOS backup']
    assert len(backup) == 1
    assert backup[0]['time'] == '2021-12-03 19:33:13'
    assert backup[0]['subject'] == 'iPhone iPhone9,3'
    sms = [r for r in records if r['source'] == 'iMessage']
    assert [(r['subject'], r['detail']['from']) for r in sms] == [
        ('Please click here https://badbadbad.example.org/', 'apple')]
    # date is nanoseconds since 2001 (iOS 11+).
    assert sms[0]['time'] == '2019-08-29 23:13:30'
    whatsapp = [r for r in records if r['source'] == 'WhatsApp (iOS)']
    stored = sqlite3.connect(os.path.join(
        path, '7c', '7c7fba66680ef796b916b067077cc246adacf01d'))
    assert len(whatsapp) == stored.execute(
        "SELECT COUNT(*) FROM ZWAMESSAGE").fetchone()[0] == 3
    stored.close()
    assert {r['what'] for r in whatsapp} == {
        'Message received', 'Message sent', 'Group message received'}
    assert any('https://example.org/news' in r['subject'] for r in whatsapp)
    assert all(r['path'].startswith('/private/var/mobile/Containers/Shared/'
                                    'AppGroup/group.net.whatsapp.WhatsApp.'
                                    'shared/') for r in whatsapp)


# --- an encrypted backup ------------------------------------------------------------

PASSWORD = 'trace-TEST'


def _tlv(tag, value):
    if isinstance(value, int):
        value = struct.pack('>I', value)
    return tag.encode('ascii') + struct.pack('>I', len(value)) + value


def _cbc(key, data):
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes)
    pad = 16 - len(data) % 16
    encryptor = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16)).encryptor()
    return encryptor.update(data + bytes([pad]) * pad) + encryptor.finalize()


def _with_key(blob, wrapped):
    """The Files row's NSKeyedArchiver record with an EncryptionKey, as an
    encrypted backup stores it (NSMutableData: class + wrapped key)."""
    archive = plistlib.loads(blob)
    objects = archive['$objects']
    objects.append({'$classname': 'NSMutableData',
                    '$classes': ['NSMutableData', 'NSData', 'NSObject']})
    objects.append({'NS.data': wrapped,
                    '$class': plistlib.UID(len(objects) - 1)})
    objects[archive['$top']['root'].data]['EncryptionKey'] = \
        plistlib.UID(len(objects) - 1)
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


def encrypt_backup(source, target, password=PASSWORD):
    """An encrypted twin of an unencrypted backup, as iTunes writes one.
    Rounds are cut from millions to a few: the derivation is the same."""
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    salt, dpsl = os.urandom(20), os.urandom(20)
    iterations, dpic = 10, 10
    passcode = hashlib.pbkdf2_hmac(
        'sha1', hashlib.pbkdf2_hmac('sha256', password.encode(), dpsl, dpic,
                                    32), salt, iterations, 32)
    keys = {cls: os.urandom(32) for cls in (1, 2, 3, 4)}
    bag = (_tlv('VERS', 4) + _tlv('TYPE', 1) + _tlv('UUID', os.urandom(16))
           + _tlv('HMCK', os.urandom(40)) + _tlv('WRAP', 0)
           + _tlv('SALT', salt) + _tlv('ITER', iterations)
           + _tlv('DPWT', 1) + _tlv('DPIC', dpic) + _tlv('DPSL', dpsl))
    for cls, key in keys.items():
        bag += (_tlv('UUID', os.urandom(16)) + _tlv('CLAS', cls)
                + _tlv('WRAP', 2) + _tlv('KTYP', 0)
                + _tlv('WPKY', aes_key_wrap(passcode, key)))
    os.makedirs(target)
    shutil.copy(os.path.join(source, 'Info.plist'), target)
    db_path = os.path.join(target, 'plain.db')
    shutil.copy(os.path.join(source, 'Manifest.db'), db_path)
    db = sqlite3.connect(db_path)
    for file_id, blob in db.execute(
            "SELECT fileID, file FROM Files WHERE flags = 1").fetchall():
        stored = os.path.join(source, file_id[:2], file_id)
        if not os.path.isfile(stored):
            continue
        key = os.urandom(32)
        with open(stored, 'rb') as handle:
            data = handle.read()
        os.makedirs(os.path.join(target, file_id[:2]), exist_ok=True)
        with open(os.path.join(target, file_id[:2], file_id), 'wb') as out:
            out.write(_cbc(key, data))
        db.execute("UPDATE Files SET file = ? WHERE fileID = ?", (
            _with_key(blob, struct.pack('<I', 3)
                      + aes_key_wrap(keys[3], key)), file_id))
    db.commit()
    db.close()
    manifest_key = os.urandom(32)
    with open(db_path, 'rb') as handle:
        plain = handle.read()
    os.remove(db_path)
    # Beside the backup, not in it: what Manifest.db must decrypt to.
    with open(target + '-Manifest.db', 'wb') as handle:
        handle.write(plain)
    with open(os.path.join(target, 'Manifest.db'), 'wb') as handle:
        handle.write(_cbc(manifest_key, plain))
    with open(os.path.join(target, 'Manifest.plist'), 'wb') as handle:
        plistlib.dump({'IsEncrypted': True, 'BackupKeyBag': bag,
                       'ManifestKey': struct.pack('<I', 4)
                       + aes_key_wrap(keys[4], manifest_key),
                       'WasPasscodeSet': True, 'Version': '10.0'}, handle,
                      fmt=plistlib.FMT_BINARY)
    return target


def test_encrypted_backup_needs_its_password(tmp_path):
    from trace_app.core import containers
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.logical_sources import kind_of
    pytest.importorskip('cryptography')
    source = sample(MVT)
    sample(f'{MVT}/Manifest.db')
    path = encrypt_backup(source, str(tmp_path / 'encrypted'))
    assert kind_of(path) == 'ios_backup'
    handler = ImageHandler(path)
    assert handler.loaded and handler.encryption(0) == 'ios_backup'
    fs = handler.get_fs_info(0)
    # Locked: only the backup's own files.
    assert {fs.path_of(n.inode) for n in fs.nodes.values()
            if not n.is_dir} == {'/Backup/Info.plist', '/Backup/Manifest.db',
                                 '/Backup/Manifest.plist'}
    with pytest.raises(containers.ContainerError, match='Wrong password'):
        handler.unlock_volume(0, 'ios_backup', password='not-it')
    assert handler.encryption(0) == 'ios_backup'
    assert handler.unlock_volume(0, 'ios_backup', password=PASSWORD)
    assert handler.encryption(0) is None and handler.is_unlocked(0)
    assert handler.logical_fs.facts['Encryption'] == \
        'encrypted -- unlocked with its password'
    plain = _stored(source)
    for phone, data in plain.items():
        node = handler.get_fs_info(0).lookup(phone)
        assert node.size == len(data), phone
        assert node.reader(0, node.size) == data, phone
        # A read from the middle decrypts only the blocks it covers.
        for offset, length in ((17, 100), (4096, 33), (len(data) - 5, 5)):
            assert node.reader(offset, length) == \
                data[offset:offset + length], (phone, offset)
    # Manifest.db decrypted, shown beside the encrypted one.
    with open(path + '-Manifest.db', 'rb') as handle:
        assert _read(handler, '/Backup/Manifest.db (decrypted)') == \
            handle.read()


def test_a_background_job_unlocks_with_the_examiners_password(tmp_path):
    """Jobs are handed the keys as {start: {'_kind', secret}}."""
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    pytest.importorskip('cryptography')
    source = sample(MVT)
    sample(f'{MVT}/Manifest.db')
    path = encrypt_backup(source, str(tmp_path / 'encrypted'))
    handler = ImageHandler(path)
    handler.apply_unlocks({0: {'_kind': 'ios_backup', 'password': PASSWORD}})
    records = collect(handler)
    plain = collect(ImageHandler(source))
    assert sorted((r['source'], r['time'], r['subject']) for r in records) \
        == sorted((r['source'], r['time'], r['subject']) for r in plain)
    assert any(r['source'] == 'iMessage' for r in records)


# --- plaso's iOS and Android databases -------------------------------------------------

def test_android_calls_as_plaso_reads_them():
    from trace_app.core.activity import mobile
    db = sqlite3.connect(sample('android-contacts2.db'))
    calls = mobile.android_calls(db, '/x', 'r')
    db.close()
    assert len(calls) == 3
    first = calls[0]
    assert first['time'] == '2013-11-06 21:17:16'
    assert first['what'] == 'Call missed' and first['subject'] == '5404561685'
    assert first['detail']['duration'] == '0:00'
    assert [c['what'] for c in calls] == ['Call missed', 'Call made',
                                          'Call received']


def test_ios_accounts_as_plaso_reads_them():
    from trace_app.core.activity import mobile
    db = sqlite3.connect(sample('ios-Accounts3.sqlite'))
    accounts = mobile.ios_accounts(db, '/x', 'r')
    db.close()
    assert len(accounts) == 18
    icloud = next(a for a in accounts if a['detail']['identifier']
                  == '1589F4EC-8F6C-4F37-929F-C6F121B36A59')
    assert icloud['time'] == '2020-03-21 21:47:57'
    assert icloud['subject'] == 'thisisdfir@gmail.com'
    assert icloud['detail']['type'] == 'iCloud'
    assert icloud['detail']['set up by'] == 'com.apple.purplebuddy'


def test_ios_known_networks_as_plaso_reads_them():
    from trace_app.core.activity import mobile
    with open(sample('ios-com.apple.wifi.known-networks.plist'), 'rb') as f:
        records = mobile.ios_known_networks(f.read(), '/x', 'r')
    joined = [r for r in records if r['what'] == 'Wi-Fi joined']
    assert len(joined) == 9                  # plaso: one per access point
    first = joined[0]
    assert (first['subject'], first['detail']['BSSID'],
            first['detail']['channel'], first['time']) == (
        'Matt_Foley', '76:a7:41:e7:7c:9d', 1, '2023-05-14 01:15:45')
    added = [r for r in records if r['what'] == 'Wi-Fi network added']
    assert added[0]['time'] == '2023-04-15 13:53:47'


# --- Android binary XML -----------------------------------------------------------------

def _tree(element):
    return (element.tag, dict(element.attrib), (element.text or '').strip(),
            [_tree(child) for child in element])


@pytest.mark.parametrize('name', ['test-basic', 'test-typed-attribute',
                                  'test_interned_strings'])
def test_abx_reads_as_the_xml_it_was_written_from(name):
    from trace_app.core.activity import abx
    with open(sample(f'abx-{name}.xml.abx'), 'rb') as handle:
        binary = handle.read()
    expected = ElementTree.parse(sample(f'abx-{name}.xml')).getroot()
    assert _tree(abx.parse(binary)) == _tree(expected)
    assert _tree(ElementTree.fromstring(abx.to_xml(binary))) == \
        _tree(expected)


def test_abx_refuses_what_is_not_abx():
    from trace_app.core.activity import abx
    with pytest.raises(abx.AbxError):
        abx.parse(b'<?xml version="1.0"?><a/>')
    with open(sample('abx-test-basic.xml.abx'), 'rb') as handle:
        data = handle.read()
    with pytest.raises(abx.AbxError):
        abx.parse(data[:len(data) // 2])


# --- an Android extraction ----------------------------------------------------------------

def _abx(root):
    """Android binary XML of an Element, written per AOSP's
    BinaryXmlSerializer (strings interned, attributes as strings)."""
    out = bytearray(b'ABX\x00\x00')            # magic, START_DOCUMENT
    interned = []

    def name(text):
        if text in interned:
            out.extend(struct.pack('>H', interned.index(text)))
        else:
            interned.append(text)
            raw = text.encode()
            out.extend(b'\xff\xff' + struct.pack('>H', len(raw)) + raw)

    def string(text):
        raw = text.encode()
        out.extend(struct.pack('>H', len(raw)) + raw)

    def element(node):
        out.append(0x32)                       # START_TAG, interned
        name(node.tag)
        for key, value in node.attrib.items():
            out.append(0x2F)                   # ATTRIBUTE, string
            name(key)
            string(value)
        if node.text and node.text.strip():
            out.append(0x24)                   # TEXT, string
            string(node.text)
        for child in node:
            element(child)
        out.append(0x33)                       # END_TAG, interned
        name(node.tag)

    element(root)
    out.append(0x01)                           # END_DOCUMENT
    return bytes(out)


WIFI_XML = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
<int name="Version" value="3" />
<NetworkList>
<Network>
<WifiConfiguration>
<string name="ConfigKey">&quot;CoffeeShop&quot;NONE</string>
<string name="SSID">&quot;CoffeeShop&quot;</string>
<null name="PreSharedKey" />
<boolean name="HiddenSSID" value="false" />
<string name="CreatorName">android.uid.system</string>
<string name="CreationTime">time=09-14 18:02:11.123</string>
</WifiConfiguration>
<NetworkStatus>
<string name="SelectionStatus">NETWORK_SELECTION_ENABLED</string>
</NetworkStatus>
</Network>
<Network>
<WifiConfiguration>
<string name="ConfigKey">&quot;Home-5G&quot;WPA_PSK</string>
<string name="SSID">&quot;Home-5G&quot;</string>
<string name="PreSharedKey">&quot;not-copied&quot;</string>
<boolean name="HiddenSSID" value="true" />
<string name="CreatorName">com.android.settings</string>
</WifiConfiguration>
</Network>
</NetworkList>
</WifiConfigStoreData>
"""

BUILD_PROP = """# begin build properties
ro.build.date.utc=1662076800
ro.build.version.release=13
ro.build.version.sdk=33
ro.build.version.security_patch=2022-09-05
ro.product.manufacturer=Google
ro.product.model=Pixel 6
ro.product.device=oriole
ro.build.fingerprint=google/oriole/oriole:13/TP1A.220905.004/8927612:user/release-keys
"""


def _database(path, script):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(script)
    db.commit()
    db.close()


def make_android(root, binary_wifi=False):
    """The data partition of an Android 13 phone, as a file system
    extraction lays it out under /data, with /system/build.prop."""
    data = os.path.join(root, 'data')
    _database(os.path.join(data, 'data', 'com.android.providers.contacts',
                           'databases', 'calllog.db'), """
        CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT,
            date INTEGER, duration INTEGER, type INTEGER, name TEXT,
            geocoded_location TEXT, countryiso TEXT,
            subscription_component_name TEXT, is_read INTEGER);
        INSERT INTO calls VALUES (1, '+447700900123', 1663171200000, 95, 1,
            'Sam', 'United Kingdom', 'GB', 'com.android.phone', 1);
        INSERT INTO calls VALUES (2, '+447700900456', 1663174800000, 0, 3,
            NULL, NULL, 'GB', NULL, 0);
        INSERT INTO calls VALUES (3, '+447700900123', 1663178400000, 3725, 2,
            'Sam', 'United Kingdom', 'GB', NULL, 1);
        """)
    _database(os.path.join(data, 'data', 'com.android.providers.contacts',
                           'databases', 'contacts2.db'), """
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, display_name TEXT,
            last_time_contacted INTEGER, deleted INTEGER);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER,
            mimetype_id INTEGER, data1 TEXT);
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2'),
            (2, 'vnd.android.cursor.item/email_v2'),
            (3, 'vnd.android.cursor.item/name');
        INSERT INTO raw_contacts VALUES (1, 'Sam Taylor', 1663178400000, 0),
            (2, 'Old Number', NULL, 1);
        INSERT INTO data VALUES (1, 1, 1, '+447700900123'),
            (2, 1, 2, 'sam@example.com'), (3, 1, 3, 'Sam Taylor'),
            (4, 2, 1, '+447700900999');
        """)
    _database(os.path.join(data, 'data', 'com.whatsapp', 'databases',
                           'msgstore.db'), """
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT,
            raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER,
            subject TEXT);
        CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER,
            from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER,
            timestamp INTEGER, text_data TEXT);
        INSERT INTO jid VALUES (1, '447700900123', 's.whatsapp.net',
            '447700900123@s.whatsapp.net'),
            (2, '120363000000000000', 'g.us', '120363000000000000@g.us'),
            (3, '447700900456', 's.whatsapp.net',
            '447700900456@s.whatsapp.net');
        INSERT INTO chat VALUES (1, 1, NULL), (2, 2, 'Weekend plans');
        INSERT INTO message VALUES
            (1, 1, 0, 'A1', 0, 1663171300000, 'Are you there?'),
            (2, 1, 1, 'A2', 0, 1663171360000, 'Yes, on my way'),
            (3, 2, 0, 'A3', 3, 1663171420000, 'Who is driving?');
        """)
    _database(os.path.join(data, 'data', 'com.whatsapp', 'databases',
                           'wa.db'), """
        CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY, jid TEXT,
            display_name TEXT);
        INSERT INTO wa_contacts VALUES (1, '447700900123@s.whatsapp.net',
            'Sam Taylor'), (2, '447700900456@s.whatsapp.net', 'Alex');
        """)
    _database(os.path.join(data, 'system_ce', '0', 'accounts_ce.db'), """
        CREATE TABLE accounts (_id INTEGER PRIMARY KEY, name TEXT, type TEXT,
            password TEXT, last_password_entry_time_millis_epoch INTEGER);
        INSERT INTO accounts VALUES (1, 'sam.taylor@gmail.com', 'com.google',
            NULL, 1663000000000);
        INSERT INTO accounts VALUES (2, 'Sam', 'com.whatsapp', NULL, 0);
        """)
    wifi = os.path.join(data, 'misc', 'apexdata', 'com.android.wifi')
    os.makedirs(wifi)
    with open(os.path.join(wifi, 'WifiConfigStore.xml'), 'wb') as handle:
        handle.write(_abx(ElementTree.fromstring(WIFI_XML)) if binary_wifi
                     else WIFI_XML)
    os.makedirs(os.path.join(root, 'system'))
    with open(os.path.join(root, 'system', 'build.prop'), 'w') as handle:
        handle.write(BUILD_PROP)
    for folder in ('vendor', 'apex', 'product'):
        os.makedirs(os.path.join(root, folder))
    return root


def _android_records(path):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded
    return collect(handler)


def _check_android(records):
    by = {}
    for item in records:
        by.setdefault(item['source'], []).append(item)
    calls = by['Android call log']
    assert [(c['time'], c['what'], c['subject']) for c in calls] == [
        ('2022-09-14 16:00:00', 'Call received', '+447700900123'),
        ('2022-09-14 17:00:00', 'Call missed', '+447700900456'),
        ('2022-09-14 18:00:00', 'Call made', '+447700900123')]
    assert calls[0]['detail']['duration'] == '1:35'
    assert calls[2]['detail']['duration'] == '1:02:05'
    assert calls[2]['detail']['to'] == '+447700900123'
    contacts = by['Android contacts']
    assert sorted((c['what'], c['subject'], c['detail']['phone'])
                  for c in contacts) == [
        ('Contact', 'Sam Taylor', '+447700900123'),
        ('Contact (deleted)', 'Old Number', '+447700900999')]
    whatsapp = by['WhatsApp (Android)']
    assert [(w['what'], w['subject'], w['detail'].get('from'),
             w['detail'].get('to')) for w in whatsapp] == [
        ('Message received', 'Are you there?', 'Sam Taylor', None),
        ('Message sent', 'Yes, on my way', None, 'Sam Taylor'),
        ('Group message received', 'Who is driving?', 'Alex', None)]
    assert whatsapp[2]['detail']['chat'] == 'Weekend plans'
    accounts = by['Android accounts']
    assert sorted((a['subject'], a['detail']['type']) for a in accounts) == [
        ('Sam', 'com.whatsapp'), ('sam.taylor@gmail.com', 'com.google')]
    google = next(a for a in accounts if a['detail']['type'] == 'com.google')
    assert google['time'] == '2022-09-12 16:26:40'
    wifi = by['Android Wi-Fi']
    assert [(w['subject'], w['detail']['security'],
             w['detail'].get('password saved')) for w in wifi] == [
        ('CoffeeShop', 'NONE', None), ('Home-5G', 'WPA_PSK', 'yes')]
    # The password itself is never copied into a record.
    assert 'not-copied' not in repr(wifi)
    build = by['Android build']
    assert len(build) == 1 and build[0]['what'] == 'Android 13'
    assert build[0]['subject'] == 'Google Pixel 6'
    assert build[0]['time'] == '2022-09-02 00:00:00'


@pytest.mark.parametrize('binary_wifi', [False, True])
def test_android_extraction_as_a_folder(tmp_path, binary_wifi):
    root = make_android(str(tmp_path / 'android'), binary_wifi)
    _check_android(_android_records(root))


def test_android_extraction_as_a_tar(tmp_path):
    root = make_android(str(tmp_path / 'android'), binary_wifi=True)
    archive = str(tmp_path / 'android.tar')
    with tarfile.open(archive, 'w') as tar:
        for name in sorted(os.listdir(root)):
            tar.add(os.path.join(root, name), arcname=name)
    _check_android(_android_records(archive))


def test_wpa_supplicant_before_android_8(tmp_path):
    from trace_app.core.activity import mobile
    text = ('ctrl_interface=wlan0\nnetwork={\n\tssid="Office"\n'
            '\tpsk="secret-psk"\n\tkey_mgmt=WPA-PSK\n\tpriority=3\n}\n'
            'network={\n\tssid="Guest"\n\tkey_mgmt=NONE\n}\n')
    records = mobile.wpa_supplicant(text, '/x', 'r')
    assert [(r['subject'], r['detail']['security'],
             r['detail'].get('password saved')) for r in records] == [
        ('Office', 'WPA-PSK', 'yes'), ('Guest', 'NONE', None)]
    assert 'secret-psk' not in repr(records)

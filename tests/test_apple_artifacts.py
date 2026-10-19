"""macOS and iOS artifacts read the way mac_apt reads them.

Quick (no evidence): LZFSE/LZVN against blobs Apple's reference encoder
made (tests/expected/apple/lzfse), protobuf, a Trash .DS_Store written by
the ds_store package, Notes bodies, saved application state and Terminal
text, the plist and SQLite readers, QuickLook bitmaps, SEGB v2 records.

Samples (CI): keychainbreaker's keychain unlocked through the dialog,
iLEAPP's NoteStore.sqlite.

Local: Magnet's 2022 CTF iPhone (iOS 15 full file system) -- every
CoreSpotlight store against ydkhatri's spotlight_parser and every SEGB
file against ccl-segb (tests/expected/apple/ios15_reference.json, made
with those tools), and the whole activity run.
"""

import datetime
import gzip
import hashlib
import io
import json
import os
import plistlib
import random
import sqlite3
import struct
import zipfile
import zlib

import pytest

from tests.conftest import data_path, image_path

EXPECTED = os.path.join(os.path.dirname(__file__), 'expected', 'apple')
IOS15 = 'fb028ddefa8af7df5b12d3e729f075d150637a31_files_full.zip'


# --- LZFSE / LZVN ---------------------------------------------------------------

def _original(case):
    """The text make_expectations wrote: words drawn from a seeded RNG."""
    if case['seed'] is None:
        return random.Random(5).randbytes(case['size'])
    rng = random.Random(case['seed'])
    words = [''.join(rng.choice(case['alphabet'])
                     for _ in range(rng.randint(2, 9))) for _ in range(300)]
    out, total = [], 0
    while total < case['size']:
        word = rng.choice(words)
        out.append(word)
        total += len(word) + 1
    return ' '.join(out).encode()[:case['size']]


@pytest.mark.parametrize('name', ['lzvn-small', 'lzvn-tiny', 'lzfse-text',
                                  'lzfse-multiblock', 'raw-random'])
def test_lzfse_decodes_what_apples_encoder_wrote(name):
    from trace_app.core import lzfse
    cases = json.load(open(os.path.join(EXPECTED, 'lzfse.json')))
    case = cases[name]
    packed = open(os.path.join(EXPECTED, 'lzfse', name + '.bin'), 'rb').read()
    assert packed[:4].decode('latin-1') == case['magic']
    out = lzfse.decompress(packed)
    assert hashlib.sha256(out).hexdigest() == case['sha256']
    assert out == _original(case)


def test_lzfse_refuses_damage():
    from trace_app.core import lzfse
    packed = open(os.path.join(EXPECTED, 'lzfse', 'lzfse-text.bin'),
                  'rb').read()
    with pytest.raises(lzfse.LzfseError):
        lzfse.decompress(packed[:len(packed) // 2])
    with pytest.raises(lzfse.LzfseError):
        lzfse.decompress(b'bvx2' + bytes(40))
    with pytest.raises(lzfse.LzfseError):
        lzfse.decompress(packed, max_length=1000)


# --- protobuf ----------------------------------------------------------------------

def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number, payload):
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def test_protobuf_reads_nested_messages_without_a_schema():
    from trace_app.core import protobuf
    inner = _field(2, 'Grocery list'.encode()) + _varint(3 << 3) + _varint(7)
    data = _field(1, b'com.apple.Notes') + _field(4, inner) + \
        _varint(5 << 3 | 1) + struct.pack('<d', 1.5)
    message = protobuf.parse(data)
    assert protobuf.first(message, 1) == 'com.apple.Notes'
    assert protobuf.first(message, 4, 2) == 'Grocery list'
    assert protobuf.first(message, 4, 3) == 7
    assert protobuf.fixed64_double(protobuf.first(message, 5)) == 1.5
    assert protobuf.strings(data) == ['com.apple.Notes', 'Grocery list']
    assert protobuf.strings(b'\xff\xff\xff') == []
    assert not protobuf.is_message(b'\x0a\x05ab')      # length past the end


# --- .DS_Store ---------------------------------------------------------------------

def test_ds_store_written_by_ds_store_package():
    from trace_app.core import dsstore
    data = open(os.path.join(EXPECTED, 'trash-ds_store.bin'), 'rb').read()
    assert dsstore.is_ds_store(data)
    back = dsstore.put_back(data)
    assert len(back) == 13
    assert back['report 7.docx'] == ('Users/jess/Desk7/', 'Report 7.docx')
    assert back['photo.jpg'] == ('Users/jess/Pictures/', 'IMG_0001.jpg')
    kinds = {(name, code): value for name, code, value in
             dsstore.records(data)}
    assert kinds[('.', 'ICVO')] is True
    assert kinds[('.', 'fwsw')] == 200
    assert isinstance(kinds[('photo.jpg', 'Iloc')], bytes)
    with pytest.raises(dsstore.DsStoreError):
        dsstore.records(b'not a DS_Store')


def test_trash_rows_say_where_items_came_from():
    from trace_app.core.activity import macos_state
    data = open(os.path.join(EXPECTED, 'trash-ds_store.bin'), 'rb').read()
    moved = datetime.datetime(2024, 3, 1, 10, 0, tzinfo=datetime.timezone.utc)

    class Entry:
        changed = moved

    rows = macos_state.trash(data, {'photo.jpg': Entry()},
                             lambda entry: entry.changed, 'jess',
                             '/Users/jess/.Trash/.DS_Store', 'ref')
    photo = next(r for r in rows if r['detail']['name in Trash'] ==
                 'photo.jpg')
    assert photo['subject'] == '/Users/jess/Pictures/IMG_0001.jpg'
    assert photo['time'] == '2024-03-01 10:00:00'
    assert photo['detail']['still in Trash'] == 'yes'
    gone = next(r for r in rows if r['detail']['name in Trash'] ==
                'report 3.docx')
    assert gone['time'] is None and gone['detail']['still in Trash'] == 'no'


# --- Notes ------------------------------------------------------------------------------

def _database(tmp_path, script, params=()):
    path = tmp_path / f'db{random.random()}.sqlite'
    connection = sqlite3.connect(path)
    connection.executescript(script)
    for statement, values in params:
        connection.execute(statement, values)
    connection.commit()
    connection.close()
    return path.read_bytes()


def test_note_bodies_from_gzip_protobuf(tmp_path):
    from trace_app.core.activity import macos_sqlite
    text = 'Meet at the dock at 9\nbring the drive ' + chr(0xFFFC)
    note = _field(2, text.encode()) + _varint(5 << 3) + _varint(7)
    document = _varint(2 << 3) + _varint(0) + _field(3, note)
    body = gzip.compress(_field(2, document))
    assert macos_sqlite.note_body_text(body) == text
    data = _database(tmp_path, """
        CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY,
          ZTITLE1 TEXT, ZTITLE2 TEXT, ZSNIPPET TEXT, ZCREATIONDATE3 REAL,
          ZMODIFICATIONDATE1 REAL, ZFOLDER INTEGER,
          ZISPASSWORDPROTECTED INTEGER, ZMARKEDFORDELETION INTEGER);
        CREATE TABLE ZICNOTEDATA (Z_PK INTEGER PRIMARY KEY, ZNOTE INTEGER,
          ZDATA BLOB);
        INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES
          (1, NULL, 'Notes', NULL, NULL, NULL, NULL, 0, 0),
          (2, 'Plan', NULL, 'Meet', 700000000, 700000100, 1, 0, 0),
          (3, 'Locked', NULL, 'x', 700000000, 700000100, 1, 1, 0),
          (4, NULL, NULL, NULL, NULL, NULL, 1, 0, 1);""",
        [("INSERT INTO ZICNOTEDATA VALUES (1, 2, ?)", (body,)),
         ("INSERT INTO ZICNOTEDATA VALUES (2, 3, ?)", (b'encrypted',)),
         ("INSERT INTO ZICNOTEDATA VALUES (3, 4, ?)", (b'',))])
    rows = macos_sqlite.macos_notes(data, None, 'jess', 'p', 'r')
    assert len(rows) == 2                    # the emptied deleted note: none
    plan = next(r for r in rows if r['subject'] == 'Plan')
    assert plan['time'] == '2023-03-08 20:26:40'
    assert plan['detail']['folder'] == 'Notes'
    assert plan['detail']['text'].endswith('[attachment]')
    assert plan['detail']['attachments'] == 1
    locked = next(r for r in rows if r['subject'] == 'Locked')
    assert 'text' not in locked['detail']
    assert locked['detail']['password protected'] == 'yes, body encrypted'


def test_ileapp_notestore_bodies():
    from trace_app.core.activity import macos_sqlite
    path = data_path('samples', 'NoteStore.sqlite')
    wal = path + '-wal'
    rows = macos_sqlite.ios_notes(
        open(path, 'rb').read(),
        open(wal, 'rb').read() if os.path.exists(wal) else None,
        'mobile', 'p', 'r')
    by_title = {r['subject']: r for r in rows}
    assert by_title['My First Note']['detail']['text'].startswith(
        'My First Note\n\nThis is my first note.')
    for title in ('iOS 14 Locked Note', 'My Super Secret Note'):
        assert by_title[title]['detail']['password protected']


# --- saved state, Terminal -------------------------------------------------------

def _saved_state(archive, key, name=b'_NSWindow', window=42):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    plist = plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)
    plain = bytes(4) + struct.pack('>I', len(name)) + name + b'rchv' + \
        struct.pack('>I', len(plist)) + plist
    plain += bytes(16 - len(plain) % 16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    sealed = encryptor.update(plain) + encryptor.finalize()
    return b'NSCR1000' + struct.pack('>II', window, 16 + len(sealed)) + sealed


def _keyed(top, objects):
    return {'$archiver': 'NSKeyedArchiver', '$version': 100000,
            '$top': top, '$objects': ['$null'] + objects}


def _style_run(text):
    """A 'Tab Contents v2' style run as Big Sur's Terminal writes it:
    three little-endian 64-bit words, the middle the text's length."""
    return {'NS.data': struct.pack('<QQQ', 0, len(text), 0)}


def test_terminal_tab_text_is_decrypted():
    from trace_app.core.activity import macos_state
    key = bytes(range(16))
    uid = plistlib.UID
    # As macOS 11 writes it: 'Tab Contents v2' alternates text and its
    # style runs, a dictionary elsewhere in the window is keyed by
    # dictionaries, and data.data holds the window's record twice.
    archive = _keyed(
        {'NSTitle': uid(1), 'TTWindowState': uid(2), 'Restorer': uid(14)},
        ['bash — 80x24',
         {'NS.keys': [uid(3)], 'NS.objects': [uid(4)]},
         'Window Settings',
         {'NS.objects': [uid(5)]},
         {'NS.keys': [uid(6), uid(7)], 'NS.objects': [uid(8), uid(11)]},
         'Tab Contents v2', 'Tab Working Directory URL String',
         {'NS.objects': [uid(9), uid(12), uid(10), uid(13)]},
         {'NS.data': b'$ ls -la\n'}, {'NS.data': b'total 8\n'},
         'file:///Users/jess/',
         _style_run(b'$ ls -la\n'), _style_run(b'total 8\n'),
         {'NS.keys': [uid(15)], 'NS.objects': [uid(3)]},
         {'NS.keys': [uid(3)], 'NS.objects': [uid(6)]}])
    data = _saved_state(archive, key) * 2
    windows = plistlib.dumps([{'NSWindowID': 42, 'NSTitle': 'bash',
                               'NSDataKey': key}], fmt=plistlib.FMT_BINARY)
    rows = macos_state.terminal_state(windows, data, 'jess', None, 'p', 'r')
    assert len(rows) == 1
    assert rows[0]['subject'] == 'bash — 80x24'
    assert rows[0]['detail']['text'] == '$ ls -la\ntotal 8'
    assert rows[0]['detail']['working folder'] == 'file:///Users/jess/'
    state = macos_state.saved_state(windows, data, 'com.apple.Terminal',
                                    'jess', None, 'p', 'r')
    assert state[0]['detail']['state decrypted'] == 'yes'
    assert state[0]['detail']['titles in state'] == 'bash — 80x24'
    wrong = plistlib.dumps([{'NSWindowID': 42, 'NSTitle': 'bash',
                             'NSDataKey': bytes(16)}],
                           fmt=plistlib.FMT_BINARY)
    assert macos_state.saved_state(wrong, data, 'x', '', None, 'p', 'r')[0][
        'detail']['state decrypted'] == 'no'


def test_tcc_before_and_after_big_sur(tmp_path):
    from trace_app.core.activity import macos_sqlite
    old = _database(tmp_path, """
        CREATE TABLE access (service TEXT, client TEXT, client_type INT,
            allowed INT, prompt_count INT, csreq BLOB,
            last_modified INT);
        INSERT INTO access VALUES ('kTCCServiceCamera', 'us.zoom.xos', 0,
            1, 1, NULL, 1600000000);""")
    rows = macos_sqlite.tcc(old, None, 'jess', 'p', 'r')
    assert [(r['what'], r['detail']['prompt count']) for r in rows] == [
        ('Allowed', 1)]
    # macOS 11: auth_value (0 refused, 2 allowed, 3 limited), auth_reason.
    new = _database(tmp_path, """
        CREATE TABLE access (service TEXT, client TEXT, client_type INT,
            auth_value INT, auth_reason INT, auth_version INT, csreq BLOB,
            policy_id INT, indirect_object_identifier_type INT,
            indirect_object_identifier TEXT, indirect_object_code_identity
            BLOB, flags INT, last_modified INT);
        INSERT INTO access VALUES ('kTCCServiceSystemPolicyAllFiles',
            '/usr/libexec/sshd-keygen-wrapper', 1, 2, 4, 1, NULL, NULL, 0,
            'UNUSED', NULL, 0, 1616189531);
        INSERT INTO access VALUES ('kTCCServiceScreenCapture',
            'com.apple.screensharing.agent', 0, 0, 2, 1, NULL, NULL, 0,
            'UNUSED', NULL, 0, 1613095034);""")
    rows = macos_sqlite.tcc(new, None, '', 'p', 'r')
    assert [(r['what'], r['detail']['reason'], r['time']) for r in rows] == [
        ('Allowed', 'system set', '2021-03-19 21:32:11'),
        ('Refused', 'user consent', '2021-02-12 01:57:14')]


def test_finder_saved_state_names_the_folder_shown():
    from trace_app.core.activity import macos_state
    key = bytes(16)
    uid = plistlib.UID
    archive = _keyed({'NSTitle': uid(1), 'WindowState': uid(2)},
                     ['Desktop', {'NS.keys': [uid(3)],
                                  'NS.objects': [uid(4)]},
                      'TargetURL', 'file:///Users/jess/Desktop/'])
    data = _saved_state(archive, key, window=7)
    windows = plistlib.dumps([{'NSWindowID': 7, 'NSTitle': 'Desktop',
                               'NSDataKey': b'k' * 16}])
    # The key in windows.plist is not the one used: nothing decrypts.
    rows = macos_state.saved_state(windows, data, 'com.apple.finder', '',
                                   None, 'p', 'r')
    assert rows[0]['detail']['state decrypted'] == 'no'
    windows = plistlib.dumps([{'NSWindowID': 7, 'NSTitle': 'Desktop',
                               'NSDataKey': key}])
    rows = macos_state.saved_state(windows, data, 'com.apple.finder', '',
                                   None, 'p', 'r')
    assert rows[0]['detail']['showing'] == 'file:///Users/jess/Desktop/'


def test_sudo_timestamp_file():
    from trace_app.core.activity import macos_state
    when = datetime.datetime(2024, 1, 2, tzinfo=datetime.timezone.utc)
    entry = struct.pack('<HHHHIi', 2, 56, 2, 0, 501, 100) + bytes(40)
    rows = macos_state.sudo_timestamps(entry + entry, 'jess', when, 'p', 'r')
    assert rows[0]['time'] == '2024-01-02 00:00:00'
    assert rows[0]['detail']['grants recorded'] == 'terminal, terminal'


# --- plists ----------------------------------------------------------------------------

def test_dock_sharing_and_remote_management_plists():
    from trace_app.core.activity import macos_plists
    dock = plistlib.dumps({'persistent-apps': [{'tile-data': {
        'file-label': 'Safari', 'bundle-identifier': 'com.apple.Safari',
        'file-mod-date': 3700000000,
        'file-data': {'_CFURLString': 'file:///Applications/Safari.app/'}}}]})
    row = macos_plists.dock(dock, 'jess', 'p', 'r')[0]
    assert row['detail']['path'] == '/Applications/Safari.app'
    assert row['time'] == '2021-03-31 01:46:40'      # seconds since 1904
    overrides = plistlib.dumps({'com.apple.screensharing': {'Disabled': False},
                                'com.openssh.sshd': {'Disabled': True}})
    assert {r['what'] for r in macos_plists.launchd_overrides(
        overrides, None, 'p', 'r')} == {'Screen Sharing on',
                                        'Remote Login (SSH) off'}
    disabled = plistlib.dumps({'com.apple.smbd': True})
    assert macos_plists.launchd_overrides(disabled, None, 'p', 'r')[0][
        'what'] == 'File Sharing (SMB) off'
    share = plistlib.dumps({'directory_path': ['/Users/jess/Public'],
                            'name': ['Public'], 'smb_shared': ['1'],
                            'afp_shared': ['0']})
    row = macos_plists.sharepoint(share, None, 'p', 'r')[0]
    assert row['subject'] == '/Users/jess/Public'
    assert row['detail']['shared over'] == 'SMB'
    ard = plistlib.dumps({'ARD_AllLocalUsers': True,
                          'VNCLegacyConnectionsEnabled': True})
    assert macos_plists.remote_management(ard, None, 'p', 'r')[0][
        'subject'] == 'all local users'
    client = plistlib.dumps({'NSNavRecentPlaces': ['x'],
                             'RecentHosts': ['vnc://10.0.0.5', 'mini.local']})
    hosts = {r['subject'] for r in macos_plists.screen_sharing_client(
        client, 'jess', None, 'p', 'r')}
    assert {'vnc://10.0.0.5', 'mini.local'} <= hosts


# --- SQLite readers ---------------------------------------------------------------

def test_accounts_url_cache_xprotect_launchpad(tmp_path):
    from trace_app.core.activity import macos_sqlite
    accounts = _database(tmp_path, """
        CREATE TABLE ZACCOUNTTYPE (Z_PK INTEGER PRIMARY KEY,
          ZACCOUNTTYPEDESCRIPTION TEXT, ZIDENTIFIER TEXT);
        CREATE TABLE ZACCOUNT (Z_PK INTEGER PRIMARY KEY, ZACCOUNTTYPE INTEGER,
          ZACCOUNTDESCRIPTION TEXT, ZUSERNAME TEXT, ZDATE REAL,
          ZPARENTACCOUNT INTEGER, ZOWNINGBUNDLEID TEXT);
        INSERT INTO ZACCOUNTTYPE VALUES (1, 'Gmail',
          'com.apple.account.Google');
        INSERT INTO ZACCOUNT VALUES (1, 1, 'Google', 'jess@gmail.com',
          600000000, NULL, 'com.apple.Preferences');""")
    row = macos_sqlite.internet_accounts(accounts, None, 'jess', 'p', 'r')[0]
    assert row['subject'] == 'jess@gmail.com'
    assert row['time'] == '2020-01-06 10:40:00'
    assert row['detail']['type'] == 'Gmail'
    cache = _database(tmp_path, """
        CREATE TABLE cfurl_cache_response (entry_ID INTEGER PRIMARY KEY,
          version INTEGER, hash_value INTEGER, storage_policy INTEGER,
          request_key TEXT, time_stamp TEXT, partition TEXT);
        CREATE TABLE cfurl_cache_receiver_data (entry_ID INTEGER,
          isDataOnFS INTEGER, receiver_data BLOB);
        INSERT INTO cfurl_cache_response VALUES (1, 0, 0, 0,
          'https://example.com/a', '2024-05-01 10:00:00', NULL);
        INSERT INTO cfurl_cache_receiver_data VALUES (1, 0, x'00112233');""")
    row = macos_sqlite.cfurl_cache(cache, None, 'jess', 'p', 'r',
                                   app='com.x')[0]
    assert (row['subject'], row['time']) == ('https://example.com/a',
                                             '2024-05-01 10:00:00')
    assert row['detail']['cached bytes'] == 4
    xprotect = _database(tmp_path, """
        CREATE TABLE events (id INTEGER, violated_rule TEXT,
          exec_path TEXT, responsible_path TEXT, dt TEXT);
        INSERT INTO events VALUES (1, 'XP_BROWSER_DATA', '/tmp/x',
          '/bin/zsh', '2024-01-02 03:04:05');""")
    row = macos_sqlite.xprotect_behavior(xprotect, None, '', 'p', 'r')[0]
    assert row['detail']['rule'] == 'XP_BROWSER_DATA'
    assert row['time'] == '2024-01-02 03:04:05'
    launchpad = _database(tmp_path, """
        CREATE TABLE apps (item_id INTEGER, title TEXT, bundleid TEXT,
          storeid TEXT, moddate REAL);
        CREATE TABLE items (rowid INTEGER PRIMARY KEY, parent_id INTEGER);
        CREATE TABLE "groups" (item_id INTEGER, title TEXT);
        INSERT INTO items VALUES (5, 9);
        INSERT INTO "groups" VALUES (9, 'Utilities');
        INSERT INTO apps VALUES (5, 'Terminal', 'com.apple.Terminal', NULL,
          600000000);""")
    row = macos_sqlite.launchpad(launchpad, None, 'jess', 'p', 'r')[0]
    assert (row['subject'], row['detail']['folder']) == ('Terminal',
                                                         'Utilities')


# --- QuickLook ----------------------------------------------------------------------

def test_quicklook_bitmaps_old_and_new_layouts(tmp_path):
    from PIL import Image
    from trace_app.core import thumbnails
    # Two pixels of four stored per row: red, then green (RGBA).
    rgba = (bytes([255, 0, 0, 255, 0, 255, 0, 255]) + bytes(8)) * 2
    picture = Image.open(io.BytesIO(thumbnails.quicklook_png(
        rgba, f'0:{len(rgba)}:2:2:16:rgba')))
    assert picture.size == (2, 2)
    assert picture.convert('RGBA').getpixel((0, 0)) == (255, 0, 0, 255)
    bgra = (bytes([0, 0, 255, 255, 0, 255, 0, 255]) + bytes(8)) * 2
    picture = Image.open(io.BytesIO(thumbnails.quicklook_png(
        bgra, f'0:{len(bgra)}:2:2:16:bgra')))
    assert picture.convert('RGBA').getpixel((0, 0)) == (255, 0, 0, 255)

    old = _database(tmp_path, f"""
        CREATE TABLE files (folder TEXT, file_name TEXT, version BLOB);
        CREATE TABLE thumbnails (file_id INTEGER, size INTEGER,
          width INTEGER, height INTEGER, bitspercomponent INTEGER,
          bitsperpixel INTEGER, bytesperrow INTEGER,
          bitmapdata_location INTEGER, bitmapdata_length INTEGER,
          last_hit_date REAL, hit_count INTEGER);
        INSERT INTO files VALUES ('/Users/jess/Pictures', 'gone.jpg', NULL);
        INSERT INTO files VALUES ('/Users/jess/Pictures', 'here.jpg', NULL);
        INSERT INTO thumbnails VALUES (1, 1, 2, 2, 8, 32, 16, 0,
          {len(rgba)}, 700000000, 3);
        INSERT INTO thumbnails VALUES (2, 1, 2, 2, 8, 32, 16, 0,
          {len(rgba)}, 700000000, 1);""")

    class Cache:
        ref = 'p0:i5:s1'
        path = '/private/var/folders/x/y/C/com.apple.QuickLook.' \
               'thumbnailcache/thumbnails.data'
        offset = 0

    names = {(0, '/users/jess/pictures'): {'here.jpg': (False, 'p0:i9')}}
    rows, findings = thumbnails._quicklook_rows(
        rgba, old, {'cache_ref': Cache.ref, 'cache_path': Cache.path},
        Cache, names)
    states = {r['name']: r['original_state'] for r in rows}
    assert states == {'gone.jpg': 'absent', 'here.jpg': 'present'}
    assert len(findings) == 1 and 'gone.jpg' in findings[0][6]
    assert rows[0]['detail']['last shown'] == '2023-03-08 20:26:40'

    new = _database(tmp_path, f"""
        CREATE TABLE basic_files (fileId INTEGER, version BLOB);
        CREATE TABLE preferences (key TEXT, value TEXT);
        INSERT INTO preferences VALUES ('version', '10');
        CREATE TABLE thumbnails (file_id INTEGER, size INTEGER,
          width INTEGER, height INTEGER, bitspercomponent INTEGER,
          bitsperpixel INTEGER, bytesperrow INTEGER,
          bitmapdata_location INTEGER, bitmapdata_length INTEGER,
          last_hit_date REAL, hit_count INTEGER);
        INSERT INTO basic_files VALUES (1234, NULL);
        INSERT INTO thumbnails VALUES (1234 | -9223372036854775808, 1, 2, 2,
          8, 32, 16, 0, {len(bgra)}, 700000000, 2);""")
    rows, findings = thumbnails._quicklook_rows(
        bgra, new, {'cache_ref': Cache.ref, 'cache_path': Cache.path},
        Cache, {})
    assert rows[0]['detail']['inode'] == 1234
    assert rows[0]['location'].endswith(':bgra') and not findings


# --- Biome / SEGB ------------------------------------------------------------------

def test_segb_v2_record_written_then_deleted():
    from trace_app.core.activity import biome
    payload = _field(1, b'com.apple.Maps')
    entry = struct.pack('<Ii', zlib.crc32(payload), 0) + payload
    padded = entry + bytes(-len(entry) % 4)
    trailer = struct.pack('<iid', len(entry), 1, 600000000.0) + \
        struct.pack('<iid', len(entry), 3, 600000100.0) + \
        struct.pack('<iid', 0, 0, 0.0)
    data = b'SEGB' + struct.pack('<i', 3) + bytes(24) + padded + trailer
    records = biome.read_records(data)
    assert [r['state'] for r in records] == [1, 3]
    assert all(r['payload'] == payload and r['crc_ok'] for r in records)
    rows = biome.records(data, 'AppLaunch', 'p', 'r')
    assert rows[0]['subject'] == 'com.apple.Maps'


# --- keychain dialog ------------------------------------------------------------------

def test_keychain_dialog_unlocks_and_audits_without_values(qapp):
    from trace_app.ui.dialogs.keychain import KeychainDialog
    path = data_path('samples', 'keychainbreaker-test.keychain-db')
    audit = []
    dialog = KeychainDialog(open(path, 'rb').read(), 'test.keychain-db',
                            record=lambda a, d='': audit.append((a, d)))
    assert dialog.table.rowCount() == len(dialog.entries) > 0
    assert not dialog.reveal_button.isEnabled()
    dialog.password.setText('wrong')
    dialog._unlock()
    assert audit[-1][0] == 'keychain unlock refused'
    dialog.password.setText('keychainbreaker-test')
    dialog._unlock()
    assert audit[-1] == ('keychain unlocked',
                         'test.keychain-db with the login password')
    revealed = []
    for row, entry in enumerate(dialog.entries):
        if entry.kind.endswith('password'):
            dialog.table.selectRow(row)
            dialog._reveal()
            revealed.append(dialog.table.item(row, 6).text())
    assert revealed and all(value == 'password#123' for value in revealed)
    assert not any('password#123' in detail for _action, detail in audit)
    assert sum(1 for a, _d in audit if a == 'keychain secret viewed') == \
        len(revealed)
    dialog.deleteLater()


# --- the Magnet 2022 iPhone (local) --------------------------------------------------

@pytest.fixture(scope='module')
def ios15():
    path = image_path(IOS15)
    reference = json.load(open(os.path.join(EXPECTED, 'ios15_reference.json'),
                               encoding='utf-8'))
    with zipfile.ZipFile(path) as package:
        yield package, reference


def _plain(value, date=False):
    """TRACE's value in the shape the reference file stores."""
    if isinstance(value, list):
        return [_plain(v, date) for v in value]
    if date and isinstance(value, float):
        return {'date': (datetime.datetime(2001, 1, 1) + datetime.timedelta(
            seconds=value)).isoformat()}
    if isinstance(value, bytes):
        return {'text': value.decode('utf-8', 'ignore')}
    if isinstance(value, float):
        return {'float': value}
    return value


def _close(a, b):
    if isinstance(a, dict) and 'date' in a and isinstance(b, dict):
        first = datetime.datetime.fromisoformat(a['date'])
        second = datetime.datetime.fromisoformat(b['date'])
        return abs((first - second).total_seconds()) < 1e-3
    if isinstance(a, dict) and 'float' in a and isinstance(b, dict):
        return abs(a['float'] - b.get('float', 0)) < 1e-6
    if isinstance(a, dict) and 'text' in a:
        return b == a or b == a['text']
    if isinstance(b, dict) and 'text' in b:
        return a == b['text']
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_close(x, y) for x, y in zip(a, b))
    return a == b


def _spotlight_equals_reference(package, name, expected, external=True):
    """A store read by TRACE against spotlight_parser's item count and
    sampled values. External stores keep their definitions in the
    dbStr-N.map files beside them; a volume's store holds its own."""
    from trace_app.core import spotlight
    folder = name.rsplit('/', 1)[0]
    maps = None
    if external:
        maps = {number: tuple(package.read(
            f'{folder}/dbStr-{number}.map.{kind}')
            for kind in ('data', 'offsets', 'header'))
            for number in spotlight.MAP_FILES}
    store = spotlight.Store(package.read(name), maps=maps)
    assert store.external == external, name
    items = {item.id: item for item in store.items()}
    assert len(items) == expected['items'], name
    dates = {prop for prop, _flags, value_type in
             store.properties.values() if value_type == 0x0C}
    for item_id, values in expected['sample'].items():
        mine = items[int(item_id)].attributes
        for prop, value in values.items():
            if value in ('', [], None):
                continue
            got = _plain(mine.get(prop), date=prop in dates)
            assert _close(value, got), (name, item_id, prop, value, got)


def test_ios15_corespotlight_equals_spotlight_parser(ios15):
    package, reference = ios15
    for name, expected in reference['spotlight'].items():
        _spotlight_equals_reference(package, name, expected)


def test_ios15_segb_equals_ccl_segb(ios15):
    from trace_app.core.activity import biome
    package, reference = ios15
    assert len(reference['segb']) == 32
    for name, expected in reference['segb'].items():
        records = biome.read_records(package.read(name))
        assert len(records) == expected['records'], name
        assert [r['state'] for r in records] == expected['states'], name
        assert sum(1 for r in records if r['crc_ok']) == expected['crc_ok']


def test_ios15_activity_end_to_end(ios15):
    from collections import Counter
    from trace_app.core import activity
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(IOS15))
    rows = activity.collect(handler)
    sources = Counter(r['source'].split(' · ')[0].split(' (')[0]
                      for r in rows)
    notes = {r['subject']: r['detail'].get('text') for r in rows
             if r['source'] == 'Notes (iOS)'}
    assert notes['Grocery list'].startswith('Grocery list \nEnergy drinks')
    assert '44.44545, -73.19659' in notes['East Woods Hike']
    # CoreSpotlight: every donated item with a name or text.
    assert sources['CoreSpotlight'] > 1000
    assert sources['Biome'] > 2400               # written records and more
    assert sources['Screen Time'] > 0 and sources['Network usage'] > 0
    assert sources['URL cache'] > 1000
    maps_poi = [r for r in rows if r['source'] == 'Biome · POICategory']
    assert any(r['subject'] == 'restaurant' for r in maps_poi)


# --- the Magnet 2021 Mac (local) ---------------------------------------------------------

MACOS11 = 'magnet-2021-ctf-macos.zip'


@pytest.fixture(scope='module')
def macos11():
    path = image_path(MACOS11)
    reference = json.load(open(os.path.join(EXPECTED,
                                            'macos11_reference.json'),
                               encoding='utf-8'))
    with zipfile.ZipFile(path) as package:
        yield package, reference


def test_macos11_spotlight_equals_spotlight_parser(macos11):
    # The volume's own store (14,930 items, its definitions inside it),
    # an external drive's, and the user's CoreSpotlight and help stores.
    package, reference = macos11
    for name, expected in reference['spotlight'].items():
        _spotlight_equals_reference(package, name, expected,
                                    external=expected['external'])


def test_macos11_activity_end_to_end(macos11):
    from collections import Counter
    from trace_app.core import activity
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(MACOS11))
    rows = activity.collect(handler)
    kinds = Counter((r['source'].split(' · ')[0], r['what']) for r in rows)
    # TCC as macOS 11 writes it (auth_value): 11 rows for the user, 4 for
    # the system -- sshd-keygen-wrapper given Full Disk Access is what
    # turning Remote Login on does.
    assert kinds['TCC (privacy)', 'Allowed'] == 12
    assert kinds['TCC (privacy)', 'Refused'] == 3
    full_disk = [r for r in rows if r['source'] == 'TCC (privacy)' and
                 r['detail']['service'] == 'kTCCServiceSystemPolicyAllFiles']
    assert [(r['time'], r['detail']['client']) for r in full_disk] == [
        ('2021-03-19 21:32:11', '/usr/libexec/sshd-keygen-wrapper')]
    # Terminal's window: the text on screen, once, without style runs.
    terminal = [r for r in rows if r['source'] == 'Terminal']
    assert len(terminal) == 1
    assert terminal[0]['detail']['text'] == (
        'Last login: Mon Apr  5 16:07:24 on ttys000\n'
        'eliflatt@stu-21-155-171-184 ~ %')
    assert terminal[0]['detail']['working folder'] == \
        'file://stu-21-155-171-184.champlain.edu/Users/eliflatt'
    # Every window of every saved state (Installer 2, Finder 2, Terminal
    # 3), each decrypted.
    states = [r for r in rows if r['source'] == 'Saved application state']
    assert len(states) == 7
    assert all(r['detail']['state decrypted'] == 'yes' for r in states)
    trash = {r['detail']['name in Trash'] for r in rows
             if r['source'] == 'Trash'}
    assert trash == {'checkra1n beta 0.12.2.dmg', 'untitled folder'}
    # The volume's Spotlight store: only four items carry a last-used
    # date, none a download origin.
    assert kinds['Spotlight', 'Opened (Spotlight)'] == 4
    assert kinds['Spotlight', 'Downloaded'] == 0
    assert kinds['CoreSpotlight', 'App content indexed'] == 26
    assert sum(c for (s, _w), c in kinds.items() if s == 'Dock') == 21
    assert sum(c for (s, _w), c in kinds.items() if s == 'KnowledgeC') == 13
    assert sum(c for (s, _w), c in kinds.items() if s == 'Keychain') == 25

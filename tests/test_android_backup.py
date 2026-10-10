"""Android extractions: `adb backup` files (core/android_backup.py) and the
ZIP/TAR layouts phone extraction tools write (logical.system_roots).

The backups are written here by a writer of their own that follows AOSP's
BackupManagerService (PerformAdbBackupTask: header lines, PBKDF2-HMAC-SHA1
user key, master key blob, the checksum over the master key as a Java
char[] in UTF-8 from version 2, AES-256-CBC, then Deflater) -- not by the
reader's module -- so a mistake in one is caught by the other. Every file
must come back byte for byte, read whole and in pieces across the
decompression checkpoints; the mobile parsers must find what is inside."""

import hashlib
import io
import os
import sqlite3
import tarfile
import zipfile
import zlib

import pytest

from trace_app.core import android_backup

PASSWORD = 'pässwörd-ß'
MSGSTORE = """
    CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT,
        raw_string TEXT);
    CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER,
        subject TEXT);
    CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER,
        from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER,
        timestamp INTEGER, text_data TEXT);
    INSERT INTO jid VALUES (1, '447700900123', 's.whatsapp.net',
        '447700900123@s.whatsapp.net');
    INSERT INTO chat VALUES (1, 1, NULL);
    INSERT INTO message VALUES
        (1, 1, 0, 'A1', 0, 1663171300000, 'Meet at the station'),
        (2, 1, 1, 'A2', 0, 1663171360000, 'OK, 8pm');
"""


def sqlite_file(script):
    path = os.path.join(os.environ.get('TMP', '.'), f'{os.getpid()}-x.db')
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.executescript(script)
    db.commit()
    db.close()
    with open(path, 'rb') as handle:
        data = handle.read()
    os.remove(path)
    return data


def backup_files():
    big = hashlib.sha256(b'seed').digest() * (20 * 1024 * 1024 // 32 + 7)
    return {
        'apps/com.whatsapp/_manifest': b'1\ncom.whatsapp\n',
        'apps/com.whatsapp/db/msgstore.db': sqlite_file(MSGSTORE),
        'apps/com.whatsapp/f/key': os.urandom(158),
        'apps/com.whatsapp/sp/prefs.xml': b'<map><string name="a">b</string>'
                                          b'</map>',
        'apps/com.example/d_f/state.bin': os.urandom(3000),
        'shared/0/DCIM/Camera/IMG_0001.jpg': big[:20 * 1024 * 1024 + 5],
        'apps/com.example/r/app_webview/Default/Cookies': b'',
    }


def tar_of(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT
                      ) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1663171200
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def aosp_backup(tar, version, compressed, password):
    """The bytes PerformAdbBackupTask writes (written independently of
    core/android_backup)."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)

    def encrypt(key, iv, data):
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        worker = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return worker.update(data) + worker.finalize()

    body = zlib.compress(tar) if compressed else tar
    header = f"ANDROID BACKUP\n{version}\n{1 if compressed else 0}\n"
    if password is None:
        return (header + "none\n").encode() + body
    rounds = 2000
    user_salt, checksum_salt = os.urandom(64), os.urandom(64)
    master, master_iv, user_iv = os.urandom(32), os.urandom(16), \
        os.urandom(16)
    # Java: new String(char[]) of signed bytes, then PBKDF2 over UTF-8.
    as_chars = ''.join(chr(b if b < 128 else b + 0xFF00) for b in master)
    material = as_chars.encode('utf-8') if version >= 2 else master
    checksum = hashlib.pbkdf2_hmac('sha1', material, checksum_salt, rounds,
                                   32)
    secret = password.encode('utf-8') if version >= 2 else \
        password.encode('latin-1', 'replace')
    user_key = hashlib.pbkdf2_hmac('sha1', secret, user_salt, rounds, 32)
    blob = bytes([16]) + master_iv + bytes([32]) + master + \
        bytes([len(checksum)]) + checksum
    lines = [header.rstrip('\n'), 'AES-256', user_salt.hex().upper(),
             checksum_salt.hex().upper(), str(rounds), user_iv.hex().upper(),
             encrypt(user_key, user_iv, blob).hex().upper()]
    return ('\n'.join(lines) + '\n').encode() + encrypt(master, master_iv,
                                                         body)


CASES = [(5, True, None), (5, False, None), (5, True, PASSWORD),
         (3, False, PASSWORD), (1, True, 'secret')]


@pytest.mark.parametrize('version,compressed,password', CASES)
def test_every_file_reads_as_backed_up(tmp_path, version, compressed,
                                       password):
    files = backup_files()
    path = tmp_path / 'phone.ab'
    path.write_bytes(aosp_backup(tar_of(files), version, compressed,
                                 password))
    backup = android_backup.AndroidBackup(str(path))
    try:
        if password:
            assert backup.fs.facts['_locked'] == 'android_backup'
            with pytest.raises(android_backup.BackupError,
                               match='does not unlock'):
                backup.unlock('wrong')
            backup.unlock(password)
        for name, data in files.items():
            node = backup.fs.lookup(android_backup.phone_path(name))
            assert node is not None, name
            assert node.size == len(data)
            assert node.reader(0, node.size) == data, name
            assert node.times['mtime'][0] == 1663171200
        # Read out of order across checkpoints (16 MiB apart), then on.
        picture = files['shared/0/DCIM/Camera/IMG_0001.jpg']
        node = backup.fs.lookup('storage/emulated/0/DCIM/Camera/IMG_0001.jpg')
        for offset, length in ((19 * 1024 * 1024, 4096), (100, 50),
                               (16 * 1024 * 1024 - 10, 20),
                               (len(picture) - 3, 10), (5, 1 << 20)):
            assert node.reader(offset, length) == \
                picture[offset:offset + length], offset
    finally:
        backup.close()


def test_members_are_where_the_phone_keeps_them():
    assert android_backup.phone_path('apps/com.whatsapp/db/msgstore.db') == \
        'data/data/com.whatsapp/databases/msgstore.db'
    assert android_backup.phone_path('apps/a.b/sp/x.xml') == \
        'data/data/a.b/shared_prefs/x.xml'
    assert android_backup.phone_path('apps/a.b/d_db/y.db') == \
        'data/user_de/0/a.b/databases/y.db'
    assert android_backup.phone_path('apps/a.b/ef/z') == \
        'storage/emulated/0/Android/data/a.b/files/z'
    assert android_backup.phone_path('shared/0/DCIM/x.jpg') == \
        'storage/emulated/0/DCIM/x.jpg'


def test_the_reader_and_writer_agree_on_the_checksum_quirk():
    """The module's own writer (used by other tests) against this file's."""
    key = bytes(range(250, 256)) + b'\x00\x7f\x80'
    assert android_backup.java_utf8(key) == ''.join(
        chr(b if b < 128 else b + 0xFF00) for b in key).encode('utf-8')


def _open_evidence(path, password=None):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(str(path))
    assert handler.load_image()
    if password:
        assert handler.volume_kind(0) == 'android_backup'
        assert handler.encryption(0) == 'android_backup'
        handler.unlock_volume(0, 'android_backup', password=password)
        assert handler.is_unlocked(0)
    return handler


def test_an_encrypted_backup_opens_as_evidence_and_its_chats_are_read(
        tmp_path):
    from trace_app.core.activity import run_evidence
    from trace_app.core.case import Case
    path = tmp_path / 'phone.ab'
    path.write_bytes(aosp_backup(tar_of(backup_files()), 5, True, PASSWORD))
    handler = _open_evidence(path, PASSWORD)
    case = Case.create(str(tmp_path / 'case'), 'Backup')
    try:
        assert handler.get_fs_type(0) == 'Android backup'
        evidence = case.add_evidence(str(path))
        run_evidence(handler, case, evidence)
        texts = {r['subject'] for r in case.user_activity(
            evidence, 'communication')}
        assert {'Meet at the station', 'OK, 8pm'} <= texts
        # Hashed as the file it is, like a ZIP.
        hashes = handler.calculate_hashes()
        assert hashes['computed_sha256'] == hashlib.sha256(
            path.read_bytes()).hexdigest()
    finally:
        handler.close_resources()
        case.close()


@pytest.mark.parametrize('prefix,archive', [
    ('filesystem1/', 'zip'), ('Dump/', 'tar'), ('', 'zip'),
    ('extraction/fs/', 'tar')])
def test_extraction_tool_layouts_are_found(tmp_path, prefix, archive):
    """A phone's file system as the tools write it: the system roots are
    found under the tool's folder and the parsers read both phones."""
    from trace_app.core.activity import run_evidence
    from trace_app.core.case import Case
    from trace_app.core.logical import system_roots
    sms = sqlite_file("""
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT,
            date INTEGER, date_read INTEGER, is_from_me INTEGER,
            service TEXT, handle_id INTEGER, is_read INTEGER, account TEXT);
        INSERT INTO handle VALUES (1, '+447700900123');
        INSERT INTO message VALUES (1, 'iPhone hello', 700000000000000000,
            0, 0, 'iMessage', 1, 1, '');
    """)
    members = {
        'ios/' + prefix + 'private/var/mobile/Library/SMS/sms.db': sms,
        'android/' + prefix + 'data/data/com.whatsapp/databases/msgstore.db':
            sqlite_file(MSGSTORE)}
    path = tmp_path / f'extraction.{archive}'
    if archive == 'zip':
        with zipfile.ZipFile(path, 'w') as handle:
            for name, data in members.items():
                handle.writestr(name, data)
    else:
        path.write_bytes(tar_of(members))
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(str(path))
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), 'FFS')
    try:
        roots = system_roots(handler.get_fs_info(0))
        assert sorted(roots) == [f"/android/{prefix}".rstrip('/'),
                                 f"/ios/{prefix}".rstrip('/')]
        evidence = case.add_evidence(str(path))
        run_evidence(handler, case, evidence)
        texts = {r['subject'] for r in case.user_activity(
            evidence, 'communication')}
        assert {'iPhone hello', 'Meet at the station'} <= texts
    finally:
        handler.close_resources()
        case.close()


def test_the_tree_unlocks_a_backup_through_the_dialog(qapp, tmp_path,
                                                      monkeypatch):
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs import bitlocker, message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)

    def fake_exec(dialog):
        dialog.password.setText(PASSWORD)
        dialog._try()
        return dialog.result()
    monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)
    path = tmp_path / 'phone.ab'
    path.write_bytes(aosp_backup(tar_of(backup_files()), 5, True, PASSWORD))
    window = MainWindow()
    try:
        assert window.open_evidence_image(str(path))
        tree = window.tree_viewer
        root = next(tree.topLevelItem(i) for i in range(
            tree.topLevelItemCount()) if (tree.topLevelItem(i).data(
                0, Qt.UserRole) or {}).get('image_path', '').endswith(
                    'phone.ab'))
        locked = next(root.child(i) for i in range(root.childCount())
                      if (root.child(i).data(0, Qt.UserRole) or {})
                      .get('encryption') == 'android_backup')
        assert 'locked' in locked.text(0)
        window.unlock_bitlocker_item(locked)
        node = next(root.child(i) for i in range(root.childCount())
                    if (root.child(i).data(0, Qt.UserRole) or {})
                    .get('encryption') == 'android_backup')
        assert 'unlocked' in node.text(0)
        assert window._unlocks_for(str(path))[0]['_kind'] == \
            'android_backup'
    finally:
        window.cleanup_resources()

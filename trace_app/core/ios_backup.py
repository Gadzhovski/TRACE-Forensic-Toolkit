"""iPhone and iPad backups (iTunes, Finder, libimobiledevice) as evidence.

A backup is a folder named by the device's UDID:

* Info.plist -- the device: name, model, iOS version, serial number, IMEI,
  phone number, ICCID, installed apps, when the backup was made;
* Manifest.plist -- whether the backup is encrypted, its keybag, the key
  of Manifest.db, the apps and their versions;
* Status.plist -- full or incremental, when, in what state;
* Manifest.db -- a SQLite table (Files) of every file backed up: its
  domain ("HomeDomain", "AppDomain-net.whatsapp.WhatsApp"...), its path
  in that domain, and an NSKeyedArchiver plist of its size, times, mode
  and, when encrypted, its key;
* the files themselves, each stored as <fileID[:2]>/<fileID>, the fileID
  being SHA-1(domain + '-' + relativePath).

TRACE presents the files where they were on the phone (HomeDomain is
/private/var/mobile, WirelessDomain /private/var/wireless...), so every
reader that looks up /private/var/mobile/Library/SMS/sms.db on a full
file system extraction finds it in a backup too. An app's container is
named by its bundle id: the backup does not record the UUID the phone
used. The backup's own files are under /Backup.

**Encrypted backups** (the "Encrypt local backup" option -- the kind that
also holds saved passwords, Wi-Fi, Health and call history) need their
password. The keybag in Manifest.plist holds a class key per protection
class, wrapped (RFC 3394 AES key wrap) with a key derived from the
password -- PBKDF2-HMAC-SHA256 with DPSL / DPIC rounds (iOS 10.2+), then
PBKDF2-HMAC-SHA1 with SALT / ITER. Manifest.db is AES-256-CBC with its own
key (ManifestKey, wrapped with a class key); every file is AES-256-CBC
with a zero IV and a key of its own (EncryptionKey in its record, wrapped
the same way). CBC decrypts any block from the one before it, so a file
is read from the middle without decrypting what comes before: nothing is
decrypted to disk, and only what is read is decrypted. The password is
kept in memory for the session, never in the case.

AES comes from `cryptography` (wheels everywhere but Windows ARM64 on
Python 3.10); PBKDF2 from hashlib. Checked against MVT's test backup
(a real Manifest.db of 3,721 files). No encrypted backup is published, so
tests/test_mobile.py encrypts that one the way iTunes does and every file
must decrypt to its plain twin.
"""

import datetime
import hashlib
import logging
import os
import plistlib
import sqlite3
import struct

from trace_app.core.logical import LogicalFileSystem

logger = logging.getLogger('TRACE.iOSBackup')

#: The folder TRACE shows the backup's own files in.
BACKUP_FOLDER = 'Backup'

#: Where each domain's files were on the phone.
DOMAINS = {
    'HomeDomain': 'private/var/mobile',
    'CameraRollDomain': 'private/var/mobile',
    'MediaDomain': 'private/var/mobile',
    'KeyboardDomain': 'private/var/mobile',
    'HealthDomain': 'private/var/mobile',
    'TonesDomain': 'private/var/mobile',
    'HomeKitDomain': 'private/var/mobile',
    'BooksDomain': 'private/var/mobile/Media/Books',
    'RootDomain': 'private/var/root',
    'SystemPreferencesDomain': 'private/var/preferences',
    'WirelessDomain': 'private/var/wireless',
    'KeychainDomain': 'private/var/Keychains',
    'ManagedPreferencesDomain': 'private/var/Managed Preferences',
    'DatabaseDomain': 'private/var/db',
    'MobileDeviceDomain': 'private/var/MobileDevice',
    'InstallDomain': 'private/var/installd',
    'NetworkDomain': 'private/var/networkd',
    'ProtectedDomain': 'private/var/protected',
}
DOMAIN_PREFIXES = (
    ('AppDomainGroup-', 'private/var/mobile/Containers/Shared/AppGroup'),
    ('AppDomainPlugin-', 'private/var/mobile/Containers/Data/PluginKitPlugin'),
    ('AppDomain-', 'private/var/mobile/Containers/Data/Application'),
    ('SysContainerDomain-', 'private/var/containers/Data/System'),
    ('SysSharedContainerDomain-',
     'private/var/containers/Shared/SystemGroup'),
)
#: Files table flags.
FILE, DIRECTORY, SYMLINK = 1, 2, 4

#: Info.plist keys shown as the evidence's facts, in this order.
DEVICE_FACTS = ('Device Name', 'Display Name', 'Product Name',
                'Product Type', 'Product Version', 'Build Version',
                'Serial Number', 'IMEI', 'IMEI 2', 'MEID', 'Phone Number',
                'ICCID', 'Unique Identifier', 'Target Identifier',
                'Last Backup Date', 'iTunes Version')

PROTECTION_CLASSES = {
    1: 'Complete', 2: 'Complete unless open',
    3: 'Until first user authentication', 4: 'None',
    5: 'Keybag (legacy)', 6: 'Complete (no backup)',
    7: 'Until first user authentication (no backup)',
    8: 'Always', 9: 'Always (no backup)', 10: 'Complete unless open',
    11: 'Until first user authentication'}

_ZERO_IV = b'\x00' * 16


class BackupError(Exception):
    """The backup could not be read or unlocked."""


def is_backup(path):
    """Is `path` a backup folder?"""
    try:
        names = {name.lower() for name in os.listdir(path)}
    except OSError:
        return False
    # Manifest.plist is in every backup the phone writes, but a copy that
    # lost it (MVT's test backup has none) is still one: Manifest.db and
    # Info.plist together are not found anywhere else.
    return ('manifest.db' in names or 'manifest.mbdb' in names) and \
        ('manifest.plist' in names or 'info.plist' in names)


def _plist(path):
    try:
        with open(path, 'rb') as handle:
            return plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        logger.debug("%s unreadable: %s", path, exc)
        return {}


def phone_path(domain, relative):
    """Where a backed-up file was on the phone."""
    base = DOMAINS.get(domain)
    if base is None:
        for prefix, folder in DOMAIN_PREFIXES:
            if domain.startswith(prefix):
                base = f"{folder}/{domain[len(prefix):]}"
                break
        else:
            base = f"private/var/mobile/{domain}"
    return f"{base}/{relative}".rstrip('/') if relative else base


# --- the keybag ---------------------------------------------------------------------

_CLASS_TAGS = ('CLAS', 'WRAP', 'WPKY', 'KTYP', 'PBKY')
WRAP_PASSCODE = 2


def _tlv(blob):
    at = 0
    while at + 8 <= len(blob):
        tag = blob[at:at + 4].decode('ascii', 'replace')
        length = struct.unpack_from('>I', blob, at + 4)[0]
        value = blob[at + 8:at + 8 + length]
        at += 8 + length
        yield tag, (struct.unpack('>I', value)[0] if length == 4 else value)


class Keybag:
    """A backup keybag: its attributes and class keys."""

    def __init__(self, blob):
        self.attributes, self.classes = {}, {}
        self.uuid = self.wrap = None
        current = None
        for tag, value in _tlv(blob):
            if tag == 'UUID' and self.uuid is None:
                self.uuid = value
            elif tag == 'WRAP' and self.wrap is None:
                self.wrap = value
            elif tag == 'UUID':
                if current and 'CLAS' in current:
                    self.classes[current['CLAS']] = current
                current = {'UUID': value}
            elif tag in _CLASS_TAGS and current is not None:
                current[tag] = value
            else:
                self.attributes[tag] = value
        if current and 'CLAS' in current:
            self.classes[current['CLAS']] = current
        if not self.classes:
            raise BackupError("The backup's keybag holds no class keys")

    def passcode_key(self, password):
        secret = password.encode('utf-8') if isinstance(password, str) \
            else bytes(password)
        rounds = self.attributes.get('DPIC')
        salt = self.attributes.get('DPSL')
        if rounds and salt:
            # iOS 10.2 and later: a slow SHA-256 round first.
            secret = hashlib.pbkdf2_hmac('sha256', secret, salt, rounds, 32)
        return hashlib.pbkdf2_hmac('sha1', secret, self.attributes['SALT'],
                                   self.attributes['ITER'], 32)

    def unlock(self, password):
        """Unwrap every class key; BackupError if the password is wrong."""
        from cryptography.hazmat.primitives.keywrap import (
            InvalidUnwrap, aes_key_unwrap)
        key = self.passcode_key(password)
        unlocked = 0
        for item in self.classes.values():
            wrapped = item.get('WPKY')
            if not isinstance(wrapped, bytes) or \
                    not item.get('WRAP', 0) & WRAP_PASSCODE:
                continue
            try:
                item['KEY'] = aes_key_unwrap(key, wrapped)
            except InvalidUnwrap:
                raise BackupError("Wrong password for this backup") from None
            unlocked += 1
        if not unlocked:
            raise BackupError("No class key in the keybag is protected by "
                              "the backup password")

    def unwrap(self, protection_class, wrapped):
        from cryptography.hazmat.primitives.keywrap import (
            InvalidUnwrap, aes_key_unwrap)
        item = self.classes.get(protection_class)
        if item is None or 'KEY' not in item:
            raise BackupError(f"No key for protection class "
                              f"{protection_class}")
        try:
            return aes_key_unwrap(item['KEY'], wrapped)
        except InvalidUnwrap:
            raise BackupError("A file key does not unwrap") from None


def _cbc_decrypt(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _unpad(data):
    """PKCS#7 padding off, when it is padding."""
    if data and 1 <= data[-1] <= 16 and \
            data[-data[-1]:] == bytes([data[-1]]) * data[-1]:
        return data[:-data[-1]]
    return data


class _EncryptedFile:
    """reader(offset, length) over one AES-CBC file: each read decrypts only
    the blocks it covers, from the ciphertext block before them."""

    def __init__(self, path, key):
        self.path, self.key = path, key

    def plain_size(self):
        """The size the padding leaves, for a record that has none."""
        size = os.path.getsize(self.path)
        if size < 16 or size % 16:
            return size
        with open(self.path, 'rb') as handle:
            handle.seek(size - 32 if size >= 32 else 0)
            tail = handle.read()
        iv = tail[:16] if len(tail) == 32 else _ZERO_IV
        last = _cbc_decrypt(self.key, iv, tail[-16:])
        return size - (len(last) - len(_unpad(last)))

    def __call__(self, offset, length):
        first = offset // 16 * 16
        end = -(-(offset + length) // 16) * 16
        with open(self.path, 'rb') as handle:
            if first:
                handle.seek(first - 16)
                iv = handle.read(16)
            else:
                iv = _ZERO_IV
            data = handle.read(end - first)
        data = data[:len(data) // 16 * 16]
        if not data:
            return b''
        plain = _cbc_decrypt(self.key, iv, data)
        return plain[offset - first:offset - first + length]


def _plain_reader(path):
    def read(offset, length):
        with open(path, 'rb') as handle:
            handle.seek(offset)
            return handle.read(length)
    return read


def _bytes_reader(data):
    return lambda offset, length: data[offset:offset + length]


# --- the file records ----------------------------------------------------------------

def file_record(blob):
    """The NSKeyedArchiver MBFile of a Files row: {'size', 'mtime',
    'ctime', 'birth', 'mode', 'inode', 'uid', 'gid', 'protection',
    'key' (wrapped, with its class) or None, 'target'}."""
    if not blob:
        return {}
    try:
        archive = plistlib.loads(blob)
        objects = archive['$objects']
        root = objects[archive['$top']['root'].data]
    except Exception:
        return {}

    def resolve(value):
        if isinstance(value, plistlib.UID):
            value = objects[value.data]
        if isinstance(value, dict) and 'NS.data' in value:
            value = value['NS.data']
        if isinstance(value, dict) and 'NS.string' in value:
            value = value['NS.string']
        return value

    key = resolve(root.get('EncryptionKey'))
    target = resolve(root.get('Target'))
    return {'size': root.get('Size'), 'mtime': root.get('LastModified'),
            'ctime': root.get('LastStatusChange'),
            'birth': root.get('Birth'), 'mode': root.get('Mode'),
            'inode': root.get('InodeNumber'), 'uid': root.get('UserID'),
            'gid': root.get('GroupID'),
            'protection': root.get('ProtectionClass'),
            'key': key if isinstance(key, bytes) else None,
            'target': target if isinstance(target, str) else None}


def _times(record):
    times = {}
    for slot, field in (('mtime', 'mtime'), ('ctime', 'ctime'),
                        ('crtime', 'birth')):
        value = record.get(field)
        if isinstance(value, int) and value > 0:
            times[slot] = (value, 0)
    return times


def _when(value):
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S UTC')
    return value


# --- the backup ----------------------------------------------------------------------

class Backup:
    """One backup folder, built into a LogicalFileSystem -- locked, with
    only its own files, until `unlock` is given the password when it is
    encrypted."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.manifest = _plist(self._file('Manifest.plist'))
        self.info = _plist(self._file('Info.plist'))
        self.status = _plist(self._file('Status.plist'))
        self.encrypted = bool(self.manifest.get('IsEncrypted'))
        self.keybag = None
        self.fs = LogicalFileSystem('iOS backup', self.path)
        self.fs.facts.update(self._facts())
        # What the backup takes on disk, as stored (encrypted or not): the
        # size the evidence tree shows, since a folder has no media size.
        stored = sum(os.path.getsize(os.path.join(folder, name))
                     for folder, _dirs, names in os.walk(self.path)
                     for name in names)
        self.fs.facts['_stored_size'] = stored
        self.fs.facts['Size on disk'] = f"{stored:,} bytes"
        self.manifest_db = None
        if self.encrypted:
            self.fs.facts['_locked'] = 'ios_backup'
            self.fs.facts['_unlock'] = self.unlock
            self.fs.facts['Encryption'] = ("encrypted -- locked until its "
                                           "password is given")
        else:
            self.fs.facts['Encryption'] = 'not encrypted'
        self._add_own_files()
        if not self.encrypted:
            with open(self._file('Manifest.db'), 'rb') as handle:
                self.manifest_db = handle.read()
            self._add_files()

    def _file(self, name):
        for entry in os.listdir(self.path):
            if entry.lower() == name.lower():
                return os.path.join(self.path, entry)
        return os.path.join(self.path, name)

    def _facts(self):
        facts = {'Format': 'iOS backup (iTunes / Finder)',
                 'Path': self.path}
        for key in DEVICE_FACTS:
            value = self.info.get(key)
            if value not in (None, ''):
                facts[key] = _when(value)
        lockdown = self.manifest.get('Lockdown') or {}
        for key, label in (('ProductVersion', 'Product Version'),
                           ('ProductType', 'Product Type'),
                           ('SerialNumber', 'Serial Number'),
                           ('DeviceName', 'Device Name'),
                           ('UniqueDeviceID', 'Unique Identifier')):
            if lockdown.get(key) and label not in facts:
                facts[label] = lockdown[key]
        for key, label in (('Date', 'Backup date'),
                           ('IsFullBackup', 'Full backup'),
                           ('SnapshotState', 'Backup state')):
            value = self.status.get(key)
            if value not in (None, ''):
                facts[label] = _when(value) if not isinstance(value, bool) \
                    else ('yes' if value else 'no')
        if 'WasPasscodeSet' in self.manifest:
            facts['Passcode set'] = 'yes' if \
                self.manifest['WasPasscodeSet'] else 'no'
        apps = self.manifest.get('Applications') or \
            self.info.get('Installed Applications')
        if apps:
            facts['Applications'] = f"{len(apps):,}"
        facts['Times'] = ("UTC, as Manifest.db records them; the folder's own "
                          "files have their times on this disk")
        return facts

    def _add_own_files(self):
        for entry in sorted(os.listdir(self.path), key=str.lower):
            full = os.path.join(self.path, entry)
            if os.path.isfile(full) and '.' in entry:
                info = os.stat(full)
                self.fs.add_file(
                    f"{BACKUP_FOLDER}/{entry}", size=info.st_size,
                    times={'mtime': (int(info.st_mtime), 0)},
                    reader=_plain_reader(full))

    def unlock(self, password):
        """Unlock an encrypted backup with its password and list its
        files. Raises BackupError when the password is wrong."""
        if not self.encrypted or self.manifest_db is not None:
            return True
        blob = self.manifest.get('BackupKeyBag')
        if not blob:
            raise BackupError("Manifest.plist holds no keybag")
        keybag = Keybag(blob)
        keybag.unlock(password)
        self.keybag = keybag
        manifest_key = self.manifest.get('ManifestKey')
        with open(self._file('Manifest.db'), 'rb') as handle:
            data = handle.read()
        if manifest_key:
            protection = struct.unpack('<I', manifest_key[:4])[0]
            key = keybag.unwrap(protection, manifest_key[4:])
            data = _unpad(_cbc_decrypt(key, _ZERO_IV,
                                       data[:len(data) // 16 * 16]))
        self.manifest_db = data
        self.fs.facts.pop('_locked', None)
        self.fs.facts['Encryption'] = 'encrypted -- unlocked with its password'
        self.fs.add_file(f"{BACKUP_FOLDER}/Manifest.db (decrypted)",
                         size=len(data), reader=_bytes_reader(data))
        self._add_files()
        return True

    def _rows(self):
        from trace_app.core.activity import sqlite_bytes
        if self.manifest_db[:16] != b'SQLite format 3\x00':
            raise BackupError("Manifest.db is not a SQLite database "
                              "(an iOS 9 or older Manifest.mbdb backup?)")
        with sqlite_bytes.open_database(self.manifest_db, None) as db:
            return db.execute(
                "SELECT fileID, domain, relativePath, flags, file FROM Files "
                "ORDER BY domain, relativePath").fetchall()

    def _add_files(self):
        try:
            rows = self._rows()
        except (sqlite3.DatabaseError, BackupError) as exc:
            self.fs.problems.append(f"Manifest.db: {exc}")
            return
        missing = 0
        for file_id, domain, relative, flags, blob in rows:
            path = phone_path(domain or '', relative or '')
            record = file_record(blob)
            facts = {'Domain': domain, 'Path in domain': relative,
                     'Backup file': f"{file_id[:2]}/{file_id}"}
            if record.get('protection') is not None:
                facts['Protection class'] = PROTECTION_CLASSES.get(
                    record['protection'], str(record['protection']))
            if record.get('mode') is not None:
                facts['Mode'] = oct(record['mode'])
            if flags == DIRECTORY:
                folder = self.fs.lookup(path)
                inode = self.fs.folder(path)
                if folder is None:
                    self.fs.nodes[inode].times = _times(record)
                    self.fs.nodes[inode].facts = facts
                continue
            if flags == SYMLINK:
                facts['Link to'] = record.get('target') or ''
                self.fs.add_file(path, size=0, times=_times(record),
                                 facts=facts)
                continue
            stored = os.path.join(self.path, file_id[:2], file_id)
            if not _safe_id(file_id) or not os.path.isfile(stored):
                missing += 1
                facts['Not in the backup'] = ("listed in Manifest.db, but "
                                              "the backup holds no copy")
                self.fs.add_file(path, size=0, times=_times(record),
                                 facts=facts)
                continue
            # The copy decides the size, not the record: Manifest.db can
            # say less than the backup holds (MVT's observations.db: 4,096
            # recorded, 110,592 stored -- a database that grew while it
            # was backed up), and trusting it would drop evidence.
            recorded = record.get('size')
            if record.get('key') and self.encrypted:
                try:
                    protection = struct.unpack('<I', record['key'][:4])[0]
                    key = self.keybag.unwrap(protection, record['key'][4:])
                except (BackupError, struct.error) as exc:
                    self.fs.problems.append(f"{path}: {exc}")
                    continue
                reader = _EncryptedFile(stored, key)
                size = reader.plain_size()
                facts['Encrypted'] = 'AES-256-CBC, decrypted as read'
            else:
                reader = _plain_reader(stored)
                size = os.path.getsize(stored)
            if isinstance(recorded, int) and recorded != size:
                facts['Recorded size'] = (f"{recorded:,} bytes in "
                                          f"Manifest.db; the copy holds "
                                          f"{size:,}")
            self.fs.add_file(path, size=size, times=_times(record),
                             reader=reader, facts=facts)
        self.fs.facts['Files'] = f"{sum(1 for r in rows if r[3] == FILE):,}"
        if missing:
            self.fs.facts['Not in the backup'] = (
                f"{missing:,} file(s) listed in Manifest.db without a copy")


def _safe_id(file_id):
    """A fileID is 40 hex digits; anything else is not followed to disk."""
    return len(file_id or '') == 40 and \
        all(c in '0123456789abcdefABCDEF' for c in file_id)


def open_backup(path):
    return Backup(path).fs


def hash_folder(path, hashers, progress=None, chunk=1024 * 1024):
    """Feed every file under `path`, in sorted path order, to `hashers` as
    '/relative/path' + NUL + content -- the backup as it is stored, not as
    decrypted -- and return the bytes read."""
    files = []
    for folder, names, entries in os.walk(path):
        names.sort()
        for name in entries:
            full = os.path.join(folder, name)
            relative = '/' + os.path.relpath(full, path).replace(os.sep, '/')
            files.append((relative, full, os.path.getsize(full)))
    files.sort()
    total = sum(size for _r, _f, size in files) or 1
    done = 0
    for relative, full, size in files:
        for hasher in hashers:
            hasher.update(relative.encode('utf-8', 'surrogateescape') + b'\0')
        read = 0
        with open(full, 'rb') as handle:
            while True:
                block = handle.read(chunk)
                if not block:
                    break
                for hasher in hashers:
                    hasher.update(block)
                read += len(block)
                done += len(block)
                if progress:
                    progress(done, total)
        # A file that changed while the backup was hashed: the hash
        # would describe neither the backup before nor after.
        if read != size:
            raise OSError(f"{relative} changed while it was hashed "
                          f"({size:,} -> {read:,} bytes)")
    return done

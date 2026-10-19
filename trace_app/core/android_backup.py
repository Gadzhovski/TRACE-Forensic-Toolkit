"""Android backups (`adb backup` .ab files), read in place (no Qt).

What `adb backup` writes (AOSP, BackupManagerService / PerformAdbBackupTask
and their restore side):

    ANDROID BACKUP\\n
    <version 1-5>\\n
    <compressed: 0 | 1>\\n
    <encryption: none | AES-256>\\n
    -- when AES-256:
    <user password salt, hex>\\n
    <master key checksum salt, hex>\\n
    <PBKDF2 rounds>\\n
    <user key IV, hex>\\n
    <master key blob, hex>\\n

then the data: AES-256-CBC under the master key (when encrypted), zlib
(when compressed), and a TAR whose members are each app's files:
`apps/<package>/{_manifest, a, f, db, sp, r, c, ef, d_f, d_db, d_sp, d_r}`
and the shared storage under `shared/0/`.

The password gives the user key (PBKDF2-HMAC-SHA1, 256 bits), which
decrypts the master key blob -- IV, master key, checksum, each a length
byte then bytes. The checksum is PBKDF2 of the master key with its own
salt; from version 2 the key is first turned into a Java char[] one signed
byte per char and encoded as UTF-8 (bytes >= 0x80 become U+FF80..U+FFFF,
three bytes each), version 1 used the raw bytes -- both are tried, as
Android's own restore does.

Members are listed in one pass. Reading one later decrypts and
decompresses from the nearest checkpoint (a `zlib.decompressobj().copy()`
every CHECKPOINT bytes; CBC needs only the previous ciphertext block), so a
backup of several GB is never decompressed whole, never held in memory and
never written to disk. They are shown where the phone keeps them --
/data/data/<package>/files, databases, shared_prefs; device-protected
storage under /data/user_de/0; shared storage under /storage/emulated/0 --
so the mobile parsers (activity/mobile.py) read them as from a phone.
"""

import bisect
import hashlib
import logging
import posixpath
import tarfile
import threading
import zlib

from trace_app.core.logical import LogicalFileSystem

logger = logging.getLogger('TRACE.AndroidBackup')

MAGIC = b'ANDROID BACKUP\n'
CHECKPOINT = 16 * 1024 * 1024
_FEED = 256 * 1024
_HEADER_LINES = 4
_ENCRYPTED_LINES = 5

#: Backup folder of an app -> where the phone keeps it (relative to the
#: app's data folder, or a whole other root).
_DOMAINS = {
    'f': ('data/data/{pkg}', 'files'),
    'db': ('data/data/{pkg}', 'databases'),
    'sp': ('data/data/{pkg}', 'shared_prefs'),
    'r': ('data/data/{pkg}', ''),
    'c': ('data/data/{pkg}', 'cache'),
    'nb': ('data/data/{pkg}', 'no_backup'),
    'd_f': ('data/user_de/0/{pkg}', 'files'),
    'd_db': ('data/user_de/0/{pkg}', 'databases'),
    'd_sp': ('data/user_de/0/{pkg}', 'shared_prefs'),
    'd_r': ('data/user_de/0/{pkg}', ''),
    'd_c': ('data/user_de/0/{pkg}', 'cache'),
    'ef': ('storage/emulated/0/Android/data/{pkg}', 'files'),
    'a': ('data/app/{pkg}', ''),
    'obb': ('storage/emulated/0/Android/obb/{pkg}', ''),
    'k': ('backup/key-value/{pkg}', ''),
}


class BackupError(Exception):
    """The backup cannot be read, and why."""


def is_android_backup(head):
    return head.startswith(MAGIC)


def phone_path(member):
    """Where the phone keeps a backup member ('' for one TRACE keeps only
    under its backup path)."""
    parts = member.strip('/').split('/')
    if len(parts) >= 3 and parts[0] == 'apps':
        package, domain, rest = parts[1], parts[2], parts[3:]
        if domain == '_manifest':
            return f"data/app/{package}/_manifest"
        if domain in _DOMAINS:
            root, sub = _DOMAINS[domain]
            return posixpath.join(root.format(pkg=package), sub, *rest)
        return posixpath.join('backup', *parts)
    if len(parts) >= 2 and parts[0] == 'shared':
        user = parts[1] if parts[1].isdigit() else '0'
        rest = parts[2:] if parts[1].isdigit() else parts[1:]
        return posixpath.join('storage/emulated', user, *rest)
    return posixpath.join('backup', *parts)


# --- keys ---------------------------------------------------------------------

def _pbkdf2(secret, salt, rounds):
    return hashlib.pbkdf2_hmac('sha1', secret, salt, rounds, 32)


def java_utf8(data):
    """A byte string as Java turns it into char[] (one signed byte per
    char) and PBKDF2WithHmacSHA1 back into bytes (UTF-8)."""
    return ''.join(chr(b) if b < 0x80 else chr(0xFF00 | b)
                   for b in data).encode('utf-8', 'surrogatepass')


def _aes_cbc(key, iv, data, decrypt=True):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    worker = cipher.decryptor() if decrypt else cipher.encryptor()
    return worker.update(data) + worker.finalize()


def _unpad(data):
    pad = data[-1] if data else 0
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise BackupError("That password does not unlock this backup.")
    return data[:-pad]


def master_key(header, password):
    """(master key, IV) from the header's fields and the password; raises
    BackupError when the password is wrong."""
    secret = password.encode('utf-8') if header['version'] >= 2 else \
        password.encode('latin-1', 'replace')
    user_key = _pbkdf2(secret, header['user_salt'], header['rounds'])
    blob = _unpad(_aes_cbc(user_key, header['user_iv'], header['blob']))
    fields, position = [], 0
    for _ in range(3):
        if position >= len(blob):
            raise BackupError("That password does not unlock this backup.")
        length = blob[position]
        fields.append(blob[position + 1:position + 1 + length])
        position += 1 + length
    iv, key, checksum = fields
    for material in (java_utf8(key), key):
        if _pbkdf2(material, header['checksum_salt'],
                   header['rounds']) == checksum:
            return key, iv
    raise BackupError("That password does not unlock this backup.")


# --- the data stream ------------------------------------------------------------

class _Plain:
    """The data after the header, decrypted on demand (CBC: a block needs
    only the one before it)."""

    def __init__(self, source, start, size, key=None, iv=None):
        self._source, self.start, self.size = source, start, size
        self.key, self.iv = key, iv
        self._lock = threading.Lock()

    def read(self, offset, length):
        length = min(length, self.size - offset)
        if length <= 0:
            return b''
        if self.key is None:
            with self._lock:
                self._source.seek(self.start + offset)
                return self._source.read(length)
        first = offset // 16 * 16
        end = -(-(offset + length) // 16) * 16
        back = 16 if first else 0
        with self._lock:
            self._source.seek(self.start + first - back)
            data = self._source.read(end - first + back)
        previous = data[:16] if first else self.iv
        cipher = data[back:]
        cipher = cipher[:len(cipher) // 16 * 16]
        plain = _aes_cbc(self.key, previous, cipher) if cipher else b''
        if end >= self.size:
            try:
                plain = _unpad(plain)
            except BackupError:
                pass
        return plain[offset - first:offset - first + length]


class _Inflated:
    """The TAR stream: `plain` inflated. Checkpoints (made while the TAR is
    first listed) let any range be read from the nearest one; a cursor
    keeps reading on in order cheap."""

    def __init__(self, plain):
        self.plain = plain
        #: [(output offset, input offset, decompressobj)]
        self.checkpoints = [(0, 0, zlib.decompressobj())]
        self._starts = [0]
        #: (output offset, input offset, decompressobj, bytes beyond)
        self._cursor = None
        self._lock = threading.Lock()

    def steps(self):
        """Inflate from the start, one fed chunk at a time, recording a
        checkpoint every CHECKPOINT bytes of output."""
        out_pos, in_pos = 0, 0
        inflater = zlib.decompressobj()
        while not inflater.eof:
            chunk = self.plain.read(in_pos, _FEED)
            if not chunk:
                break
            in_pos += len(chunk)
            data = inflater.decompress(chunk)
            out_pos += len(data)
            if out_pos >= self._starts[-1] + CHECKPOINT:
                self.checkpoints.append((out_pos, in_pos, inflater.copy()))
                self._starts.append(out_pos)
            if data:
                yield data

    def read(self, offset, length):
        with self._lock:
            cursor = self._cursor
            if cursor is None or offset < cursor[0] or                     offset - cursor[0] > CHECKPOINT:
                index = bisect.bisect_right(self._starts, offset) - 1
                out_pos, in_pos, inflater = self.checkpoints[index]
                cursor = (out_pos, in_pos, inflater.copy(), b'')
            out_pos, in_pos, inflater, held = cursor
            buffer = bytearray(held)
            while out_pos + len(buffer) < offset + length and                     not inflater.eof:
                chunk = self.plain.read(in_pos, _FEED)
                if not chunk:
                    break
                in_pos += len(chunk)
                buffer += inflater.decompress(chunk)
            skip = offset - out_pos
            piece = bytes(buffer[skip:skip + length])
            used = skip + len(piece)
            self._cursor = (out_pos + used, in_pos, inflater,
                            bytes(buffer[used:]))
            return piece


class _Pipe:
    """A file object over a stream read in order, for tarfile's 'r|'."""

    def __init__(self, read):
        self._read, self.position = read, 0

    def read(self, size=-1):
        data = self._read(self.position, size if size >= 0 else 1 << 30)
        self.position += len(data)
        return data


# --- the backup -------------------------------------------------------------------

class AndroidBackup:
    def __init__(self, path):
        self.path = path
        self._source = open(path, 'rb')
        head = self._source.read(64 * 1024)
        if not is_android_backup(head):
            self._source.close()
            raise BackupError("Not an Android backup (adb backup) file")
        lines = head.split(b'\n')
        try:
            self.version = int(lines[1])
            self.compressed = lines[2].strip() == b'1'
            self.encryption = lines[3].strip().decode('ascii')
        except (IndexError, ValueError) as exc:
            self._source.close()
            raise BackupError(f"Damaged backup header: {exc}") from exc
        used = _HEADER_LINES
        self.header = {'version': self.version}
        if self.encryption == 'AES-256':
            try:
                (user_salt, checksum_salt, rounds, user_iv,
                 blob) = lines[4:4 + _ENCRYPTED_LINES]
                self.header.update(
                    user_salt=bytes.fromhex(user_salt.decode()),
                    checksum_salt=bytes.fromhex(checksum_salt.decode()),
                    rounds=int(rounds), user_iv=bytes.fromhex(
                        user_iv.decode()), blob=bytes.fromhex(blob.decode()))
            except (ValueError, UnicodeDecodeError) as exc:
                self._source.close()
                raise BackupError(f"Damaged encryption header: {exc}") \
                    from exc
            used += _ENCRYPTED_LINES
        elif self.encryption != 'none':
            self._source.close()
            raise BackupError(f"Unknown backup encryption "
                              f"{self.encryption!r}")
        # The data starts after the header's last newline.
        self.data_start = sum(len(line) + 1 for line in lines[:used])
        self._source.seek(0, 2)
        self.data_size = self._source.tell() - self.data_start
        self.fs = LogicalFileSystem('Android backup', path)
        self.fs.facts.update({
            'Format': f"Android backup (adb backup), version {self.version}",
            'Compressed': 'yes' if self.compressed else 'no'})
        self._stream = None
        if self.encryption == 'AES-256':
            self.fs.facts['Encryption'] = ("AES-256 -- locked until its "
                                           "password is given")
            self.fs.facts['_locked'] = 'android_backup'
            self.fs.facts['_unlock'] = self.unlock
        else:
            self.fs.facts['Encryption'] = 'none'
            self._open(None, None)
        self.fs.facts['_close'] = self.close

    def unlock(self, password):
        key, iv = master_key(self.header, password or '')
        self._open(key, iv)
        self.fs.facts.pop('_locked', None)
        self.fs.facts['Encryption'] = 'AES-256 -- unlocked with its password'
        return True

    def _open(self, key, iv):
        plain = _Plain(self._source, self.data_start, self.data_size, key,
                       iv)
        if self.compressed:
            inflated = _Inflated(plain)
            stream = inflated
            members = self._members_compressed(inflated)
        else:
            stream = plain
            members = self._members(lambda o, n: plain.read(o, n))
        self._stream = stream
        for name, info in members:
            path = phone_path(name)
            facts = {'Stored in the backup as': name}
            times = {'mtime': (int(info.mtime), 0)} if info.mtime else {}
            if info.isdir():
                self.fs.folder(path)
                continue
            if not info.isreg():
                continue
            self.fs.add_file(path, size=info.size, times=times, facts=facts,
                             reader=self._reader(info.offset_data,
                                                 info.size))
        self.fs.facts['Files'] = f"{sum(1 for _n, i in members if i.isreg()):,}"

    def _members(self, read):
        with tarfile.open(fileobj=_Pipe(read), mode='r|') as archive:
            return [(info.name, info) for info in archive]

    def _members_compressed(self, inflated):
        """One pass: the TAR is walked as the stream inflates, so listing
        a backup also lays its checkpoints."""
        steps = inflated.steps()
        pending = bytearray()
        base = [0]

        def read(offset, length):
            start = offset - base[0]
            while len(pending) - start < length:
                try:
                    pending.extend(next(steps))
                except StopIteration:
                    break
            data = bytes(pending[start:start + length])
            used = start + len(data)
            if used > 1 << 20:              # drop what tarfile has passed
                del pending[:used]
                base[0] += used
            return data
        return self._members(read)

    def _reader(self, offset, size):
        def read(position, length):
            if position >= size or length <= 0:
                return b''
            return self._stream.read(offset + position,
                                     min(length, size - position))
        return read

    def close(self):
        try:
            self._source.close()
        except OSError:
            pass


def open_android_backup(path):
    return AndroidBackup(path).fs

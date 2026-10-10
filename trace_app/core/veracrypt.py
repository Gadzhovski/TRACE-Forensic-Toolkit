"""VeraCrypt and TrueCrypt volumes, unlocked and decrypted in Python (no Qt).

A VeraCrypt volume -- a container file, or a partition -- has no
signature: every byte is indistinguishable from random until a password
makes one header decrypt. So it is never detected; the examiner says
"this is VeraCrypt" and gives the password (and the PIM, if one was set).

What a volume holds (VeraCrypt's own source, Common/Volumes.c):

* headers of 512 bytes: the standard volume's at 0, a hidden volume's at
  65,536, and their backups at the end (size - 131,072, size - 65,536).
  The first 64 bytes are the salt; bytes 64-511 are encrypted.
* the header key is PBKDF2 of the password and salt, with a hash and a
  number of iterations the volume does not record -- so each is tried:
  SHA-512, SHA-256 and BLAKE2s at 500,000 (VeraCrypt's default for
  non-system volumes; system volumes use 200,000 for SHA-256 and BLAKE2s),
  15,000 + PIM x 1,000 when a PIM is given (system: PIM x 2,048), and
  TrueCrypt's SHA-512 at 1,000.
* the header decrypts with AES-XTS, data unit 0: 'VERA' (or 'TRUE'), a
  CRC-32 of the master keys and one of the header fields themselves -- both
  must hold, so a wrong password is never taken for a right one.
* the data: each 512-byte unit is AES-XTS with the master keys, its tweak
  the unit's number counted from the start of the container (so a
  standard volume's first unit is 256), over the encrypted area the header
  names.

Only AES is in `cryptography` with XTS. A volume made with Serpent,
Twofish, Camellia, Kuznyechik or a cascade, or with Whirlpool or Streebog
(or keyfiles), cannot be told from a wrong password: the error says both.

`unlock(read, size, password, pim=None)` returns a libyal-shaped volume
(read_buffer_at_offset, get_size, close), as core/luks2.py does.
"""

import struct
import threading
import zlib

HEADER_SIZE = 512
SALT_SIZE = 64
UNIT = 512
#: Where headers are: (name, offset; negative = from the end, hidden?).
HEADERS = (('standard', 0, False), ('hidden', 65536, True))
BACKUPS = (('standard backup', -131072, False),
           ('hidden backup', -65536, True))

#: VeraCrypt's PRFs TRACE can compute: name -> (hash, iterations at PIM 0
#: for a volume, for a system volume).
PRFS = (('SHA-512', 'sha512', 500000, 500000),
        ('SHA-256', 'sha256', 500000, 200000),
        ('BLAKE2s-256', 'blake2s', 500000, 200000))
#: TrueCrypt's one TRACE can compute.
TRUECRYPT = ('SHA-512', 'sha512', 1000)

UNSUPPORTED = ("Wrong password or PIM -- or the volume uses what TRACE "
               "cannot read yet: a cipher other than AES (Serpent, Twofish, "
               "Camellia, Kuznyechik, cascades), the Whirlpool or Streebog "
               "hash, or keyfiles.")


class VeraCryptError(Exception):
    """Why a volume did not unlock."""


def _hash(name):
    from cryptography.hazmat.primitives import hashes
    return {'sha512': hashes.SHA512, 'sha256': hashes.SHA256,
            'blake2s': lambda: hashes.BLAKE2s(32)}[name]()


def derive(password, salt, prf, iterations, length=64):
    """The header key: PBKDF2(password, salt) with `prf` ('sha512'...)."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    return PBKDF2HMAC(_hash(prf), length, salt, iterations).derive(password)


def _xts(key, unit, data, decrypt=True):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    cipher = Cipher(algorithms.AES(key),
                    modes.XTS(unit.to_bytes(16, 'little')))
    worker = cipher.decryptor() if decrypt else cipher.encryptor()
    return worker.update(data) + worker.finalize()


def attempts(pim=None, system=False):
    """(label, prf, iterations) in the order tried."""
    out = []
    for label, prf, normal, system_iterations in PRFS:
        if pim:
            iterations = pim * 2048 if system else 15000 + pim * 1000
        else:
            iterations = system_iterations if system else normal
        out.append((f"VeraCrypt {label}", prf, iterations))
    if not pim:
        label, prf, iterations = TRUECRYPT
        out.append((f"TrueCrypt {label}", prf, iterations))
    return out


def parse_header(plain):
    """The fields of a decrypted header (`plain` = its 512 bytes, salt
    first), or None when the magic or either CRC does not hold."""
    magic = plain[64:68]
    if magic not in (b'VERA', b'TRUE'):
        return None
    keys_crc, = struct.unpack('>I', plain[72:76])
    header_crc, = struct.unpack('>I', plain[252:256])
    if zlib.crc32(plain[256:512]) != keys_crc or \
            zlib.crc32(plain[64:252]) != header_crc:
        return None
    version, required = struct.unpack('>HH', plain[68:72])
    hidden_size, volume_size, area_start, area_length, flags = \
        struct.unpack('>QQQQI', plain[92:128])
    sector_size = struct.unpack('>I', plain[128:132])[0] if version >= 5 \
        else 512
    return {'format': 'VeraCrypt' if magic == b'VERA' else 'TrueCrypt',
            'version': version, 'required_program': required,
            'hidden_size': hidden_size, 'volume_size': volume_size,
            'area_start': area_start, 'area_length': area_length,
            'flags': flags, 'sector_size': sector_size or 512,
            'master_keys': plain[256:256 + 64]}


def _try_header(raw, password, plan):
    salt = raw[:SALT_SIZE]
    for label, prf, iterations in plan:
        key = derive(password, salt, prf, iterations)
        plain = salt + _xts(key, 0, raw[SALT_SIZE:HEADER_SIZE])
        fields = parse_header(plain)
        if fields is not None:
            fields['kdf'] = f"{label}, {iterations:,} iterations"
            return fields
    return None


class VeraCryptVolume:
    """The decrypted encrypted area, libyal-shaped."""

    def __init__(self, read, fields, where):
        self._read = read
        self.fields = fields
        self.where = where
        self.start = fields['area_start']
        self.size = fields['area_length']
        keys = fields['master_keys']
        # AES-XTS: the first 32 bytes are the data key, the next the tweak
        # key; cryptography takes them together.
        self._key = keys[:64]
        self._lock = threading.Lock()

    @property
    def hidden(self):
        return self.where.startswith('hidden')

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        first = offset // UNIT
        last = (offset + length + UNIT - 1) // UNIT
        with self._lock:
            raw = self._read(self.start + first * UNIT,
                             (last - first) * UNIT)
        raw = raw[:len(raw) // UNIT * UNIT]
        base = (self.start // UNIT) + first
        plain = b''.join(
            _xts(self._key, base + index, raw[index * UNIT:
                                              (index + 1) * UNIT])
            for index in range(len(raw) // UNIT))
        skip = offset - first * UNIT
        return plain[skip:skip + length]

    def close(self):
        pass


def unlock(read, size, password, pim=None, system=False, hidden=None,
           backups=True):
    """A VeraCryptVolume for the volume read by `read(offset, length)`
    (`size` bytes). `hidden`: True tries only the hidden volume's header,
    False only the standard one, None both (the password decides which
    opens, as in VeraCrypt). Backup headers are tried when the primary
    ones fail (a damaged start). Raises VeraCryptError."""
    if not password:
        raise VeraCryptError("A password is needed.")
    secret = password.encode('utf-8') if isinstance(password, str) \
        else password
    if pim is not None:
        try:
            pim = int(pim)
        except (TypeError, ValueError):
            raise VeraCryptError("The PIM is a whole number.") from None
        if pim < 0:
            raise VeraCryptError("The PIM is a whole number.")
    plan = attempts(pim, system)
    places = list(HEADERS) + (list(BACKUPS) if backups else [])
    for where, offset, is_hidden in places:
        if hidden is not None and is_hidden != hidden:
            continue
        start = offset if offset >= 0 else size + offset
        if start < 0 or start + HEADER_SIZE > size:
            continue
        raw = read(start, HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            continue
        fields = _try_header(raw, secret, plan)
        if fields is None:
            continue
        if fields['area_start'] + fields['area_length'] > size or \
                fields['area_length'] <= 0:
            raise VeraCryptError(
                f"The {where} header opens, but names an encrypted area "
                f"past the end of the volume ({fields['area_start']:,} + "
                f"{fields['area_length']:,} > {size:,}): the image is cut "
                f"short.")
        return VeraCryptVolume(read, fields, where)
    raise VeraCryptError(UNSUPPORTED)


# --- writing (tests; and what makes the reader's rules checkable) ----------

def make_header(password, salt, master_keys, area_start, area_length,
                prf='sha512', iterations=500000, magic=b'VERA',
                hidden_size=0, volume_size=None, version=5):
    """A header as VeraCrypt writes one: what the tests' independent volumes
    are built from."""
    body = bytearray(HEADER_SIZE - SALT_SIZE)
    body[0:4] = magic
    struct.pack_into('>HH', body, 4, version, 0x010b)
    struct.pack_into('>QQQQI', body, 28, hidden_size,
                     area_length if volume_size is None else volume_size,
                     area_start, area_length, 0)
    struct.pack_into('>I', body, 64, 512)
    master_keys = master_keys.ljust(256, b'\0')
    body[192:448] = master_keys
    struct.pack_into('>I', body, 8, zlib.crc32(bytes(body[192:448])))
    struct.pack_into('>I', body, 188, zlib.crc32(bytes(body[0:188])))
    key = derive(password, salt, prf, iterations)
    return salt + _xts(key, 0, bytes(body), decrypt=False)


def encrypt_area(master_keys, area_start, plain):
    """`plain` encrypted as the area starting at `area_start` (tests)."""
    return b''.join(
        _xts(master_keys[:64], area_start // UNIT + index,
             plain[index * UNIT:(index + 1) * UNIT], decrypt=False)
        for index in range(len(plain) // UNIT))

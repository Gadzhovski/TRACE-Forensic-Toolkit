"""LUKS2 volumes, unlocked and decrypted in Python (no Qt).

libluksde (pyluksde), which TRACE uses for LUKS1, does not read LUKS2 --
cryptsetup's default since 2.1, so what a current Ubuntu, Fedora or Debian
install writes. LUKS2 is a JSON description over the same building blocks
as LUKS1, and every one of them is in `cryptography` (already required):

* the header: binary (magic, version 2, header size) then JSON -- keyslots,
  segments, digests;
* a keyslot: the passphrase through its KDF (PBKDF2, or Argon2i/Argon2id
  with time/memory/lanes) gives the key that decrypts the slot's area; the
  area is the master key spread over `stripes` copies by the anti-forensic
  splitter (AF merge: XOR and a diffusing hash in turn);
* a digest: PBKDF2 of the master key, which proves a candidate right;
* the data segment: AES-XTS (or CBC-ESSIV) per sector, IV = `iv_tweak`
  plus the sector's position in 512-byte units -- also with 4 KiB
  sectors, since cryptsetup does not ask dm-crypt for large-sector IVs
  (checked on a cryptsetup volume: counting 4 KiB units garbles every
  sector after the first).

`unlock(window, password=None, key=None)` returns a volume shaped like a
libyal one (read_buffer_at_offset, get_size, close), so ImageHandler and
LibyalImgInfo treat it as they treat pyluksde's. Values are checked
against cryptsetup's own volumes (tools/testdata/build/make_luks_lvm.py).
"""

import base64
import hashlib
import json
import struct
import threading

MAGIC = b'LUKS\xba\xbe'
_KEYSLOT_SECTOR = 512


class Luks2Error(Exception):
    """Not LUKS2, or it would not unlock (the message says why)."""


def is_luks2(head):
    return head[:6] == MAGIC and struct.unpack_from('>H', head, 6)[0] == 2


def _number(value):
    return int(value) if value is not None else None


def read_header(read):
    """The JSON metadata, from the primary header or, if that is damaged,
    the secondary one right after it."""
    head = read(0, 4096)
    if not is_luks2(head):
        raise Luks2Error("Not a LUKS2 header")
    size = struct.unpack_from('>Q', head, 8)[0]
    for offset in (0, size):
        block = read(offset, size) if offset else read(0, size)
        if len(block) < size or not is_luks2(block):
            continue
        text = block[4096:size].split(b'\0', 1)[0]
        try:
            return json.loads(text.decode('utf-8'))
        except ValueError:
            continue
    raise Luks2Error("The LUKS2 metadata is unreadable")


# --- keys -------------------------------------------------------------------------

def _hash(name):
    name = (name or 'sha256').lower().replace('-', '')
    try:
        return hashlib.new(name)
    except ValueError as exc:
        raise Luks2Error(f"Unsupported hash {name}") from exc


def _derive(kdf, password, length):
    salt = base64.b64decode(kdf['salt'])
    kind = kdf['type']
    if kind == 'pbkdf2':
        return hashlib.pbkdf2_hmac(kdf['hash'].replace('-', ''), password,
                                   salt, int(kdf['iterations']), length)
    if kind in ('argon2i', 'argon2id'):
        from cryptography.hazmat.primitives.kdf import argon2
        algorithm = argon2.Argon2id if kind == 'argon2id' else argon2.Argon2i
        return algorithm(salt=salt, length=length,
                         iterations=int(kdf['time']),
                         lanes=int(kdf['cpus']),
                         memory_cost=int(kdf['memory'])).derive(password)
    raise Luks2Error(f"Unsupported key derivation {kind}")


def _diffuse(block, name):
    size = _hash(name).digest_size
    out = bytearray()
    for index in range(0, (len(block) + size - 1) // size):
        piece = block[index * size:(index + 1) * size]
        digest = _hash(name)
        digest.update(struct.pack('>I', index) + piece)
        out += digest.digest()[:len(piece)]
    return bytes(out)


def af_merge(material, key_size, stripes, name):
    """The anti-forensic splitter undone: the master key."""
    buffer = bytes(key_size)
    for stripe in range(stripes - 1):
        piece = material[stripe * key_size:(stripe + 1) * key_size]
        buffer = _diffuse(bytes(a ^ b for a, b in zip(buffer, piece)), name)
    last = material[(stripes - 1) * key_size:stripes * key_size]
    return bytes(a ^ b for a, b in zip(buffer, last))


def _check(digests, keyslot, key):
    for digest in digests.values():
        if keyslot is not None and keyslot not in digest.get('keyslots', ()):
            continue
        if digest.get('type') != 'pbkdf2':
            continue
        expected = base64.b64decode(digest['digest'])
        found = hashlib.pbkdf2_hmac(
            digest['hash'].replace('-', ''), key,
            base64.b64decode(digest['salt']), int(digest['iterations']),
            len(expected))
        if found == expected:
            return True
    return False


# --- sectors ------------------------------------------------------------------

class _Sectors:
    """Decrypt whole sectors of one cipher spec ('aes-xts-plain64',
    'aes-xts-plain', 'aes-cbc-essiv:sha256', 'aes-cbc-plain64')."""

    def __init__(self, spec, key, sector_size):
        from cryptography.hazmat.primitives.ciphers import (Cipher,
                                                            algorithms,
                                                            modes)
        self._cipher, self._algorithms, self._modes = \
            Cipher, algorithms, modes
        parts = spec.lower().split('-')
        if len(parts) < 3 or parts[0] != 'aes':
            raise Luks2Error(f"Unsupported encryption {spec}")
        self.mode, self.iv = parts[1], '-'.join(parts[2:])
        self.key = key
        self.sector_size = sector_size
        if self.mode not in ('xts', 'cbc'):
            raise Luks2Error(f"Unsupported encryption {spec}")
        if self.iv.startswith('essiv:'):
            digest = _hash(self.iv.split(':', 1)[1])
            digest.update(key)
            self._essiv = Cipher(algorithms.AES(digest.digest()),
                                 modes.ECB()).encryptor()
        elif self.iv not in ('plain64', 'plain', 'plain64be'):
            raise Luks2Error(f"Unsupported IV {self.iv}")

    def _iv(self, number):
        if self.iv == 'plain':
            return struct.pack('<I', number & 0xffffffff) + bytes(12)
        if self.iv == 'plain64be':
            return bytes(8) + struct.pack('>Q', number)
        if self.iv == 'plain64':
            return struct.pack('<Q', number) + bytes(8)
        return self._essiv.update(struct.pack('<Q', number) + bytes(8))

    def decrypt(self, data, first):
        """`data` (whole sectors); `first` is the first sector's IV number,
        in 512-byte units, as are the steps between sectors."""
        out = bytearray()
        size = self.sector_size
        step = size // 512
        mode = self._modes.XTS if self.mode == 'xts' else self._modes.CBC
        for index in range(0, len(data) // size):
            decryptor = self._cipher(self._algorithms.AES(self.key),
                                     mode(self._iv(first + index * step))
                                     ).decryptor()
            out += decryptor.update(data[index * size:(index + 1) * size])
        return bytes(out)


class Luks2Volume:
    """The decrypted data segment, libyal-shaped."""

    def __init__(self, read, size, segment, key):
        self._read = read
        self.offset = int(segment['offset'])
        self.sector_size = int(segment.get('sector_size') or 512)
        length = segment.get('size', 'dynamic')
        self.size = (size - self.offset if length == 'dynamic'
                     else int(length))
        self.tweak = int(segment.get('iv_tweak') or 0)
        self._sectors = _Sectors(segment['encryption'], key, self.sector_size)
        self._lock = threading.Lock()

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        size = self.sector_size
        first = offset // size
        last = (offset + length + size - 1) // size
        with self._lock:
            raw = self._read(self.offset + first * size,
                             (last - first) * size)
        raw = raw[:len(raw) // size * size]
        plain = self._sectors.decrypt(raw, self.tweak + first * size // 512)
        skip = offset - first * size
        return plain[skip:skip + length]

    def close(self):
        pass


def unlock(read, size, password=None, key=None):
    """A Luks2Volume for the LUKS2 volume read by `read(offset, length)`
    (`size` bytes). Raises Luks2Error saying why it did not unlock."""
    meta = read_header(read)
    segments = sorted(
        (s for s in meta.get('segments', {}).values()
         if s.get('type') == 'crypt'), key=lambda s: int(s['offset']))
    if not segments:
        raise Luks2Error("The LUKS2 volume has no encrypted segment")
    digests = meta.get('digests', {})
    if key is not None:
        if not _check(digests, None, key):
            raise Luks2Error("That key is not this volume's master key.")
        return Luks2Volume(read, size, segments[0], key)
    if not password:
        raise Luks2Error("A passphrase is needed.")
    secret = password.encode('utf-8') if isinstance(password, str) \
        else password
    tried = 0
    for slot_id, slot in sorted(meta.get('keyslots', {}).items(),
                                key=lambda item: int(item[0])):
        if slot.get('type') != 'luks2':
            continue
        area = slot['area']
        if area.get('type') != 'raw':
            continue
        tried += 1
        key_size = int(slot['key_size'])
        stripes = int(slot['af']['stripes'])
        slot_key = _derive(slot['kdf'], secret, int(area['key_size']))
        length = key_size * stripes
        length += -length % _KEYSLOT_SECTOR
        material = _Sectors(area['encryption'], slot_key,
                            _KEYSLOT_SECTOR).decrypt(
            read(int(area['offset']), length), 0)
        candidate = af_merge(material, key_size, stripes,
                             slot['af'].get('hash', 'sha256'))
        if _check(digests, slot_id, candidate):
            return Luks2Volume(read, size, segments[0], candidate)
    if not tried:
        raise Luks2Error("The LUKS2 volume has no keyslot TRACE can open")
    raise Luks2Error("That passphrase does not unlock this volume.")

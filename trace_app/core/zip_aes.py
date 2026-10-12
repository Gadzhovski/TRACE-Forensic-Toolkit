"""WinZip AES-encrypted ZIP members (AE-1 / AE-2), decrypted in memory.

Python's zipfile reads ZipCrypto ("traditional") encryption but not
compression method 99, which WinZip, 7-Zip and most tools write when
asked for AES. The format (WinZip's "AES Encryption Information"):

* extra field 0x9901: vendor version (1 = AE-1, which keeps the CRC; 2 =
  AE-2, whose CRC is 0), 'AE', strength (1/2/3 = AES-128/192/256) and the
  real compression method;
* the member's data: a salt (8/12/16 bytes), a 2-byte password verifier,
  the encrypted data, then a 10-byte authentication code;
* PBKDF2-HMAC-SHA1, 1,000 rounds, gives the AES key, the HMAC key and the
  verifier; AES in counter mode with a little-endian counter from 1 (not
  the usual big-endian CTR); HMAC-SHA1 over the encrypted data, first 10
  bytes, is the code.

A wrong password is told by the verifier (1 in 65,536 slips through) and
then by the authentication code, which also proves the data undamaged --
so every member decrypted here is checked, AE-2 included. Decompression
after decryption: stored, deflate, bzip2, LZMA, xz and zstd; PPMd is
refused by name. Nothing is written to disk.
"""

import bz2
import hashlib
import hmac
import lzma
import struct
import zlib

AES_METHOD = 99
_EXTRA_ID = 0x9901
_SALT = {1: 8, 2: 12, 3: 16}
_KEY = {1: 16, 2: 24, 3: 32}
_METHODS = {0: 'stored', 8: 'deflate', 12: 'bzip2', 14: 'LZMA', 93: 'zstd',
            95: 'xz', 98: 'PPMd'}


class ZipAesError(Exception):
    pass


class WrongPassword(ZipAesError):
    pass


def aes_fields(info):
    """(vendor version, strength, real method) for an AES member, else
    None."""
    if info.compress_type != AES_METHOD:
        return None
    extra = info.extra or b''
    at = 0
    while at + 4 <= len(extra):
        header, size = struct.unpack_from('<HH', extra, at)
        if header == _EXTRA_ID and size >= 7:
            version, vendor, strength, method = struct.unpack_from(
                '<H2sBH', extra, at + 4)
            if vendor != b'AE' or strength not in _SALT:
                raise ZipAesError("unreadable AES extra field")
            return version, strength, method
        at += 4 + size
    raise ZipAesError("an AES member without its AES extra field")


def stored_bytes(data, info):
    """The member's bytes as stored (still encrypted), from its local
    header."""
    at = info.header_offset
    if data[at:at + 4] != b'PK\x03\x04':
        raise ZipAesError("the local file header is not where the "
                          "directory says")
    name_length, extra_length = struct.unpack_from('<HH', data, at + 26)
    start = at + 30 + name_length + extra_length
    return bytes(data[start:start + info.compress_size])


def decrypt(stored, password, strength):
    """The decrypted data. WrongPassword, or ZipAesError when the
    authentication code fails (damaged or altered)."""
    salt_length, key_length = _SALT[strength], _KEY[strength]
    if len(stored) < salt_length + 2 + 10:
        raise ZipAesError("the encrypted member is cut short")
    salt = stored[:salt_length]
    verifier = stored[salt_length:salt_length + 2]
    body = stored[salt_length + 2:-10]
    code = stored[-10:]
    secret = password.encode('utf-8') if isinstance(password, str) \
        else password
    keys = hashlib.pbkdf2_hmac('sha1', secret, salt, 1000,
                               2 * key_length + 2)
    if not hmac.compare_digest(keys[-2:], verifier):
        raise WrongPassword("wrong password")
    mac = hmac.new(keys[key_length:2 * key_length], body,
                   hashlib.sha1).digest()[:10]
    if not hmac.compare_digest(mac, code):
        # The verifier is two bytes: a wrong password passes it once in
        # 65,536 tries, and the code then tells. A right password with a
        # failing code is damage.
        raise WrongPassword("wrong password (the authentication code "
                            "fails)")
    return _ctr(keys[:key_length], body)


def _ctr(key, body):
    """AES-CTR with WinZip's little-endian counter, starting at 1."""
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    blocks = (len(body) + 15) // 16
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    stream = bytearray()
    step = 65536                      # counters per call
    for first in range(1, blocks + 1, step):
        last = min(first + step, blocks + 1)
        counters = b''.join(n.to_bytes(16, 'little')
                            for n in range(first, last))
        stream += encryptor.update(counters)
    stream = bytes(stream[:len(body)])
    return (int.from_bytes(body, 'little') ^
            int.from_bytes(stream, 'little')).to_bytes(len(body), 'little')


def decompress(method, data, size, limit):
    """The member's content from its decrypted data."""
    wanted = min(size, limit) if size else limit
    if method == 0:
        return data[:wanted]
    if method == 8:
        return zlib.decompressobj(-15).decompress(data, wanted)
    if method == 12:
        return bz2.BZ2Decompressor().decompress(data, wanted)
    if method == 14:
        # ZIP's LZMA: version (2 bytes), properties size (2), properties,
        # then a raw LZMA1 stream.
        props_size = struct.unpack_from('<H', data, 2)[0]
        props = data[4:4 + props_size]
        filters = [lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)]
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters) \
            .decompress(data[4 + props_size:], wanted)
    if method == 95:
        return lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(data,
                                                                wanted)
    if method == 93:
        from trace_app.core.zstd_decode import standard_library
        library = standard_library()
        if library is not None:
            return library.ZstdDecompressor().decompress(data, wanted)
        from trace_app.core.zstd_decode import decompress_frame
        return bytes(decompress_frame(data, wanted))[:wanted]
    raise ZipAesError(f"{_METHODS.get(method, f'method {method}')} "
                      f"compression inside AES is not read")


def read(data, info, password, limit):
    """Decrypt and decompress one AES member, checked: the authentication
    code always, the CRC-32 for AE-1, the size for both."""
    version, strength, method = aes_fields(info)
    content = decompress(method, decrypt(stored_bytes(data, info), password,
                                         strength), info.file_size, limit)
    if info.file_size <= limit and len(content) != info.file_size:
        raise ZipAesError(f"decompressed to {len(content):,} bytes, not "
                          f"{info.file_size:,}")
    if version == 1 and info.file_size <= limit and \
            zlib.crc32(content) != info.CRC:
        raise ZipAesError("the CRC-32 does not match")
    return content

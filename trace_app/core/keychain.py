"""macOS Keychain files (.keychain / .keychain-db), no Qt.

A faithful Python port of moonD4rk's keychainbreaker (Apache-2.0), which
reads Apple's CSSM keychain format and, given the login password, a 24-byte
master key or a SystemKey file, decrypts the stored secrets. The format
(three-layer 3DES-CBC key hierarchy, RFC 3217 key wrap, PBKDF2-HMAC-SHA1)
has been stable from OS X 10.6 to macOS 26.

* `Keychain(data)` parses the file: tables, schema, records.
* `.entries()` lists every password/certificate/key as metadata only --
  the item's name, account, service/host, kind and times -- **never the
  secret**.
* `.unlock(password=/master_key=/system_key=)` derives the keys.
* `.secret(entry)` returns one item's decrypted bytes, for a caller that
  has unlocked the keychain and explicitly asks. TRACE never writes these
  into the case, the activity log, the timeline, the index or trace.log --
  as it never copies a Wi-Fi or web password.

3DES comes from `cryptography`'s `decrepit` module (as TRACE's Camellia
does); PBKDF2 and the rest are pure `cryptography`. No compiler, no
Homebrew, every platform. Checked against plaso's login.keychain (metadata)
and keychainbreaker's own test.keychain-db (decryption);
tests/test_keychain.py.
"""

import datetime
import logging
import struct

logger = logging.getLogger('TRACE.Keychain')

_SIGNATURE = b'kych'
_SSGP = b'ssgp'
_KEYBLOB_MAGIC = 0xFADE0711
_CMS_IV = bytes([0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05])
_ITERATIONS = 1000
_KEY_LENGTH = 24
_BLOCK = 8

_HEADER_SIZE = 20
_SCHEMA_SIZE = 8
_TABLE_HEADER = 28
_ATOM = 4
_DBBLOB_SIZE = 92
_KEYBLOB_LEN = 24
_SSGP_HEADER = 28
_RECORD_FIXED = 6               # RecSize, RecNumber, unk1, unk2, BlobSize, 0
_NAME_LEN = 12                  # private-key name prefix

TABLE_SCHEMA_INFO = 0x00000000
TABLE_SCHEMA_ATTRIBUTES = 0x00000002
TABLE_PUBLIC_KEY = 0x0000000F
TABLE_PRIVATE_KEY = 0x00000010
TABLE_SYMMETRIC_KEY = 0x00000011
TABLE_GENERIC = 0x80000000
TABLE_INTERNET = 0x80000001
TABLE_CERTIFICATE = 0x80001000
TABLE_METADATA = 0x80008000

_BLOB_V1 = 0x00000100

#: Bootstrap schemas: the two tables that describe every other table.
_SCHEMA_INFO_ATTRS = ('RelationID', 'AttributeNameFormat', 'AttributeID',
                      'AttributeNameID')
_SCHEMA_ATTR_ATTRS = ('RelationID', 'AttributeID', 'AttributeNameFormat',
                      'AttributeNameID', 'AttributeFormat')


class KeychainError(Exception):
    pass


class WrongKey(KeychainError):
    pass


def _triple_des():
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:                 # older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import \
            TripleDES
    return TripleDES


def _decrypt(key, iv, data):
    """3DES-CBC decrypt with PKCS#7 removed; WrongKey on bad padding."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    if not data or len(data) % _BLOCK:
        raise WrongKey("ciphertext not block-aligned")
    cipher = Cipher(_triple_des()(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain = decryptor.update(data) + decryptor.finalize()
    pad = plain[-1]
    if pad == 0 or pad > _BLOCK or plain[-pad:] != bytes([pad]) * pad:
        raise WrongKey("padding verification failed")
    return plain[:-pad]


def _pbkdf2(password, salt):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=_KEY_LENGTH, salt=salt,
                     iterations=_ITERATIONS)
    return kdf.derive(password.encode('utf-8'))


def _u32(data, offset):
    return struct.unpack_from('>I', data, offset)[0]


class _Record:
    def __init__(self, buf, attr_offsets, blob, payload):
        self.buf = buf
        self.attr_offsets = attr_offsets
        self.blob = blob
        self.payload = payload
        self.schema = None

    def _offset(self, name):
        index = self.schema.index(name) if name in self.schema else -1
        if index < 0 or index >= len(self.attr_offsets):
            return -1
        stored = self.attr_offsets[index]
        return stored - 1 if stored else -1     # 1-based

    def string(self, name):
        pos = self._offset(name)
        if pos < 0 or pos + 4 > len(self.buf):
            return ''
        length = _u32(self.buf, pos)
        start = pos + 4
        if start + length > len(self.buf):
            return ''
        return self.buf[start:start + length].rstrip(b'\x00').decode(
            'utf-8', 'replace')

    def uint32(self, name):
        pos = self._offset(name)
        return _u32(self.buf, pos) if 0 <= pos and pos + 4 <= len(self.buf) \
            else 0

    def time(self, name):
        pos = self._offset(name)
        if pos < 0 or pos + 16 > len(self.buf):
            return None
        raw = self.buf[pos:pos + 16].rstrip(b'\x00')
        try:
            return datetime.datetime.strptime(
                raw.decode('ascii'), '%Y%m%d%H%M%SZ').replace(
                tzinfo=datetime.timezone.utc)
        except (ValueError, UnicodeDecodeError):
            return None


class Entry:
    """One keychain item, as metadata (never the secret)."""

    __slots__ = ('kind', 'name', 'account', 'where', 'protocol', 'created',
                 'modified', '_record', '_table')

    def __init__(self, kind, record, table):
        self.kind = kind
        self._record = record
        self._table = table
        self.name = record.string('PrintName') or record.string('labl')
        self.account = record.string('acct')
        self.where = record.string('svce') or record.string('srvr')
        self.protocol = record.string('ptcl')
        self.created = record.time('cdat')
        self.modified = record.time('mdat')


class Keychain:
    def __init__(self, data):
        self.buf = data
        self.tables = {}            # table id -> (base, [record offsets])
        self.schemas = {}           # table id -> [attr name]
        self.db_key = None
        self._key_list = {}
        self._parse()

    # --- parsing ------------------------------------------------------

    def _parse(self):
        if self.buf[:4] != _SIGNATURE:
            raise KeychainError("not a keychain (no 'kych' signature)")
        schema_off = _u32(self.buf, 12)
        table_count = _u32(self.buf, schema_off + 4)
        base = _HEADER_SIZE + _SCHEMA_SIZE
        for i in range(table_count):
            off = _u32(self.buf, base + i * _ATOM)
            if not off:
                continue
            self._parse_table(_HEADER_SIZE + off)
        self._build_schemas()

    def _parse_table(self, offset):
        if offset + _TABLE_HEADER > len(self.buf):
            return
        table_id = _u32(self.buf, offset + 4)
        record_count = _u32(self.buf, offset + 8)
        offsets = []
        rec_base = offset + _TABLE_HEADER
        for i in range(record_count):
            pos = rec_base + i * _ATOM
            if pos + _ATOM > len(self.buf):
                break
            value = _u32(self.buf, pos)
            if value and value % 4 == 0:
                offsets.append(value)
        self.tables.setdefault(table_id, (offset, offsets))

    def _record(self, table_id, record_offset, schema):
        base, _ = self.tables[table_id]
        offset = base + record_offset
        if offset + _ATOM > len(self.buf):
            return None
        size = _u32(self.buf, offset)
        if not size or offset + size > len(self.buf):
            return None
        buf = self.buf[offset:offset + size]
        header_len = (_RECORD_FIXED + len(schema)) * _ATOM
        if len(buf) < header_len:
            return None
        blob_size = _u32(buf, 16)
        attr_offsets = [_u32(buf, (_RECORD_FIXED + i) * _ATOM)
                        for i in range(len(schema))]
        blob = buf[header_len:header_len + blob_size] \
            if 0 < blob_size and header_len + blob_size <= len(buf) else b''
        record = _Record(buf, attr_offsets, blob, buf[header_len:])
        record.schema = schema
        return record

    def _build_schemas(self):
        self.schemas = {TABLE_SCHEMA_INFO: list(_SCHEMA_INFO_ATTRS),
                        TABLE_SCHEMA_ATTRIBUTES: list(_SCHEMA_ATTR_ATTRS)}
        if TABLE_SCHEMA_ATTRIBUTES not in self.tables:
            return
        _base, offsets = self.tables[TABLE_SCHEMA_ATTRIBUTES]
        by_table = {}
        for record_offset in offsets:
            record = self._record(TABLE_SCHEMA_ATTRIBUTES, record_offset,
                                  list(_SCHEMA_ATTR_ATTRS))
            if record is None:
                continue
            relation = record.uint32('RelationID')
            if not relation:
                continue
            attr_id = record.uint32('AttributeID')
            name = struct.pack('>I', attr_id)
            if all(0x20 <= b <= 0x7E for b in name):
                attr_name = name.decode('ascii')
            else:
                attr_name = record.string('AttributeNameID') or \
                    f'attr_0x{attr_id:08x}'
            by_table.setdefault(relation, []).append(attr_name)
        self.schemas.update(by_table)

    def _records(self, table_id):
        if table_id not in self.tables:
            return []
        schema = self.schemas.get(table_id)
        if schema is None:
            return []
        _base, offsets = self.tables[table_id]
        out = []
        for record_offset in offsets:
            record = self._record(table_id, record_offset, schema)
            if record is not None:
                out.append(record)
        return out

    # --- metadata (always safe) ---------------------------------------

    def entries(self):
        """Every password, certificate and key as an `Entry` (metadata
        only; no secret)."""
        out = []
        for table_id, kind in ((TABLE_GENERIC, 'generic password'),
                               (TABLE_INTERNET, 'internet password'),
                               (TABLE_CERTIFICATE, 'certificate'),
                               (TABLE_PRIVATE_KEY, 'private key'),
                               (TABLE_PUBLIC_KEY, 'public key')):
            for record in self._records(table_id):
                out.append(Entry(kind, record, table_id))
        return out

    def password_hash(self):
        """The '$keychain$*salt*iv*ciphertext' hash for offline cracking
        (hashcat 23100 / John), without unlocking. v1 keychains only."""
        blob = self._db_blob()
        if blob['version'] != _BLOB_V1:
            raise KeychainError("offline hash supports v1 keychains only")
        return (f"$keychain$*{blob['salt'].hex()}*{blob['iv'].hex()}*"
                f"{blob['encrypted'].hex()}")

    # --- unlocking ----------------------------------------------------

    #: The DBBlob sits a fixed 0x38 bytes past the Metadata table's base
    #: (not at a record offset) -- keychainbreaker's metadataOffsetAdjustment.
    _METADATA_ADJUST = 0x38

    def _db_blob(self):
        if TABLE_METADATA not in self.tables:
            raise KeychainError("no Metadata table")
        base, _ = self.tables[TABLE_METADATA]
        start_addr = base + self._METADATA_ADJUST
        blob = self.buf[start_addr:start_addr + _DBBLOB_SIZE]
        if len(blob) < _DBBLOB_SIZE:
            raise KeychainError("DBBlob exceeds file size")
        version = _u32(blob, 4)
        start = _u32(blob, 8)
        total = _u32(blob, 12)
        # startCryptoBlob and totalLength are relative to the blob's base;
        # the encrypted database key runs past the 92-byte struct.
        encrypted = self.buf[start_addr + start:start_addr + total]
        return {'version': version, 'salt': blob[44:64], 'iv': blob[64:72],
                'encrypted': encrypted}

    def unlock(self, password=None, master_key=None, system_key=None):
        """Derive the database key from the login password, a 24-byte
        master key (hex str or bytes), or a SystemKey file's bytes. Raises
        WrongKey when it does not fit."""
        blob = self._db_blob()
        if master_key is not None:
            key = bytes.fromhex(master_key) if isinstance(master_key, str) \
                else bytes(master_key)
            if len(key) != _KEY_LENGTH:
                raise KeychainError("master key must be 24 bytes")
        elif system_key is not None:
            if len(system_key) < 32:
                raise KeychainError("SystemKey file too small")
            key = system_key[8:32]
        elif password is not None:
            if blob['version'] != _BLOB_V1:
                raise KeychainError("password unlock supports v1 only; give "
                                    "the master key")
            key = _pbkdf2(password, blob['salt'])
        else:
            raise KeychainError("no unlock material given")
        plain = _decrypt(key, blob['iv'], blob['encrypted'])
        if len(plain) < _KEY_LENGTH:
            raise WrongKey("database key too short")
        self.db_key = plain[:_KEY_LENGTH]
        self._generate_key_list()
        return True

    @property
    def unlocked(self):
        return self.db_key is not None

    def _generate_key_list(self):
        self._key_list = {}
        for record in self._records(TABLE_SYMMETRIC_KEY):
            data = record.payload
            if len(data) < _KEYBLOB_LEN:
                continue
            magic = _u32(data, 0)
            if magic != _KEYBLOB_MAGIC:
                continue
            start = _u32(data, 8)
            total = _u32(data, 12)
            iv = data[16:24]
            ssgp_offset = total + _BLOCK
            if ssgp_offset + 4 > len(data) or \
                    data[ssgp_offset:ssgp_offset + 4] != _SSGP:
                continue
            if total > len(data) or start >= total:
                continue
            index = data[ssgp_offset:ssgp_offset + 20]
            try:
                key = self._unwrap_key(data[start:total], iv)
            except KeychainError:
                continue
            if key:
                self._key_list[index] = key
        if not self._key_list:
            self.db_key = None
            raise WrongKey("no symmetric keys recovered (wrong password?)")

    def _unwrap_key(self, encrypted, iv):
        """RFC 3217 two-stage unwrap for a 24-byte per-record key."""
        plain = _decrypt(self.db_key, _CMS_IV, encrypted)
        if len(plain) < 32:
            raise KeychainError("unwrap stage 1 too short")
        reversed_head = plain[:32][::-1]
        final = _decrypt(self.db_key, iv, reversed_head)
        key = final[4:]
        if len(key) != _KEY_LENGTH:
            raise KeychainError("unwrapped key wrong length")
        return key

    # --- secrets (explicit, never stored by TRACE) --------------------

    def secret(self, entry):
        """The decrypted bytes of one password entry, for a caller that
        unlocked the keychain and explicitly asks. '' when the item has no
        stored secret. TRACE does not write this anywhere."""
        if not self.unlocked:
            raise KeychainError("unlock the keychain first")
        if entry.kind not in ('generic password', 'internet password'):
            raise KeychainError("not a password entry")
        blob = entry._record.blob
        if len(blob) < _SSGP_HEADER or blob[:4] != _SSGP:
            return b''
        label = blob[:20]                 # magic + label
        iv = blob[20:28]
        encrypted = blob[28:]
        if not encrypted:
            return b''
        key = self._key_list.get(label)
        if key is None:
            raise WrongKey("no per-record key for this item")
        return _decrypt(key, iv, encrypted)

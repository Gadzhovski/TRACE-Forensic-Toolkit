"""Chromium's disk caches -- Chrome, Edge, Opera, Electron apps -- read
for the pictures they keep (no Qt).

Two formats (Chromium net/disk_cache):

* **Blockfile** (Windows and macOS desktop browsers, 'Cache' folders of
  index, data_0 .. data_3 and f_XXXXXX files; disk_format.h, addr.h). The
  index is a 368-byte header (magic 0xC103CAC3) and a hash table of entry
  addresses; each entry (EntryStore, 256 bytes in data_1) holds its URL
  key and the addresses and sizes of its streams -- 0 the HTTP headers, 1
  the body. An address: bit 31 in use, bits 28-30 the file type (0 a file
  of its own, f_<hex of bits 0-27>; 2/3/4 blocks of 256 B / 1 KB / 4 KB),
  bits 24-25 extra blocks, 16-23 the data_N number, 0-15 the first block,
  after the block file's 8,192-byte header. A small body is in a block
  file, not a file: read as files, the block files are one blob each.
  A body in a file of its own is the walk's already, so it is skipped
  here. plaso's chrome_cache test folder is read in tests.
* **Simple cache** (Linux, Android, newer profiles: '<hash>_0' files,
  simple_entry_format.h). A file holds a 24-byte header (magic
  0xFCFB6D1BA7725C30, version, key length, key hash), the key, stream 1
  (the body), an EOF record (magic 0xF4FA6F45970D41D8, flags, CRC-32,
  size), stream 0 (headers), an optional SHA-256 of the key and stream
  0's EOF record. The body is not at the file's start, so the walk sees
  no picture there: `simple_body` finds it, proved by its CRC-32 when the
  EOF record carries one.

A body sent compressed (Content-Encoding gzip / deflate) is given
decoded; brotli has no decoder in the standard library and stays as it
is (and is no picture).
"""

import logging
import struct
import zlib

from trace_app.core.firefox_cache import decode, url_name

logger = logging.getLogger('TRACE.ChromeCache')

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
INDEX_HEADER = 368
BLOCK_HEADER = 8192
ENTRY = struct.Struct('<IIIiiiQiI4i4II')
ENTRY_SIZE = 256
KEY_AT = 96
#: Block sizes by address file type.
BLOCK_SIZES = {2: 256, 3: 1024, 4: 4096}
#: Chains longer than this are a damaged table, not a cache.
MAX_CHAIN = 64

SIMPLE_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_EOF_MAGIC = 0xF4FA6F45970D41D8
FLAG_CRC32, FLAG_KEY_SHA256 = 1, 2
SIMPLE_MAGIC_BYTES = struct.pack('<Q', SIMPLE_MAGIC)


def is_index(head):
    return len(head) >= 8 and struct.unpack_from('<I', head)[0] == \
        INDEX_MAGIC and struct.unpack_from('<I', head, 4)[0] >> 16 in (2, 3)


def _address(value):
    """(file type, data_N number, first block, block count, external
    file number) of a CacheAddr, or None when not in use."""
    if not value & 0x80000000:
        return None
    kind = (value >> 28) & 0x7
    if kind == 0:
        return 0, None, None, None, value & 0x0FFFFFFF
    return (kind, (value >> 16) & 0xFF, value & 0xFFFF,
            ((value >> 24) & 0x3) + 1, None)


class Cache:
    """One blockfile cache folder. `read_file(name)` -> that file's bytes
    in the folder, or None."""

    def __init__(self, read_file):
        self._read_file = read_file
        self._files = {}

    def _file(self, name):
        if name not in self._files:
            try:
                self._files[name] = self._read_file(name)
            except Exception as exc:
                logger.debug("Cache file %s not read: %s", name, exc)
                self._files[name] = None
        return self._files[name]

    def _read(self, address, length):
        """`length` bytes at a block address, or None."""
        found = _address(address)
        if found is None or found[0] not in BLOCK_SIZES:
            return None
        kind, number, first, count, _external = found
        data = self._file(f'data_{number}')
        if data is None or len(data) < BLOCK_HEADER or \
                struct.unpack_from('<I', data)[0] != BLOCK_MAGIC:
            return None
        size = BLOCK_SIZES[kind]
        if length > count * size:
            return None
        begin = BLOCK_HEADER + first * size
        piece = data[begin:begin + length]
        return piece if len(piece) == length else None

    def _entry_addresses(self):
        index = self._file('index')
        if index is None or not is_index(index[:8]):
            return
        table_len = struct.unpack_from('<i', index, 28)[0]
        end = min(len(index), INDEX_HEADER + 4 * max(table_len, 0))
        seen = set()
        for position in range(INDEX_HEADER, end - 3, 4):
            address = struct.unpack_from('<I', index, position)[0]
            for _step in range(MAX_CHAIN):
                if not address & 0x80000000 or address in seen:
                    break
                seen.add(address)
                yield address
                record = self._read(address, ENTRY_SIZE)
                if record is None:
                    break
                address = struct.unpack_from('<I', record, 4)[0]

    def entries(self):
        """Every entry whose body is in a block file: dicts of key (the
        URL), name (its file name), block_file, offset in it, size as
        stored, content (decoded), encoding, created (Unix seconds, UTC),
        content_type."""
        for address in self._entry_addresses():
            record = self._read(address, ENTRY_SIZE)
            if record is None:
                continue
            fields = ENTRY.unpack_from(record)
            key_len, long_key = fields[7], fields[8]
            sizes, addresses = fields[9:13], fields[13:17]
            key = self._key(record, key_len, long_key)
            if key is None:
                continue
            body = _address(addresses[1])
            if body is None or body[0] == 0 or not sizes[1]:
                continue                # none, or a file of its own
            stored = self._read(addresses[1], sizes[1])
            if stored is None:
                continue
            headers = self._headers(addresses[0], sizes[0])
            encoding = headers.get('content-encoding', '').lower()
            content = decode(stored, encoding) if encoding else None
            if content is None:
                content, encoding = stored, ''
            kind, number, first, _count, _external = body
            yield {'key': key, 'name': url_name(_url(key), address),
                   'block_file': f'data_{number}',
                   'offset': BLOCK_HEADER + first * BLOCK_SIZES[kind],
                   'size': sizes[1], 'content': content,
                   'encoding': encoding,
                   'created': _chrome_time(fields[6]),
                   'content_type': headers.get('content-type', '')}

    def _key(self, record, length, long_key):
        if length <= 0 or length > 64 * 1024:
            return None
        if long_key:
            raw = self._read(long_key, length + 1)
            if raw is None:
                return None
            raw = raw[:length]
        else:
            raw = record[KEY_AT:KEY_AT + length]
            if len(raw) != length:
                return None
        return raw.decode('utf-8', 'replace')

    def _headers(self, address, length):
        raw = self._read(address, length) if length else None
        return http_headers(raw or b'')


def _url(key):
    """The URL of a key: '1/0/_dk_<site> <site> <url>' (double-keyed)
    ends with it."""
    return key.rsplit(' ', 1)[-1]


def _chrome_time(value):
    """Microseconds since 1601 -> Unix seconds (0 when unset)."""
    if not value:
        return 0
    return max(0, value // 1_000_000 - 11_644_473_600)


def http_headers(raw):
    """{lower-case name: value} from Chromium's stored response headers:
    the status line and headers, NUL-separated, inside its pickle."""
    start = raw.find(b'HTTP/')
    if start < 0:
        return {}
    out = {}
    for line in raw[start:].split(b'\0')[1:]:
        if not line:
            break
        name, colon, value = line.partition(b':')
        if colon:
            out[name.strip().lower().decode('latin-1')] = \
                value.strip().decode('latin-1')
    return out


# --- the simple cache ----------------------------------------------------

def is_simple_entry(head):
    return head[:8] == SIMPLE_MAGIC_BYTES


def simple_body(read, size):
    """(start, length, key, headers) of a simple-cache entry file's body
    (stream 1), or None when the file is not one or does not add up."""
    head = read(0, 24)
    if len(head) < 24 or not is_simple_entry(head):
        return None
    _magic, _version, key_length = struct.unpack_from('<QII', head)
    for eof_size in (24, 20):
        tail = read(size - eof_size, eof_size)
        if len(tail) != eof_size:
            continue
        magic, flags, _crc, stream0 = struct.unpack_from('<QIII', tail)
        if magic != SIMPLE_EOF_MAGIC:
            continue
        sha = 32 if flags & FLAG_KEY_SHA256 else 0
        stream0_start = size - eof_size - sha - stream0
        eof1 = stream0_start - eof_size
        for header_size in (24, 20):
            body_start = header_size + key_length
            if eof1 < body_start:
                continue
            record = read(eof1, eof_size)
            if len(record) != eof_size:
                continue
            magic1, flags1, crc1, _size1 = struct.unpack_from('<QIII',
                                                              record)
            if magic1 != SIMPLE_EOF_MAGIC:
                continue
            body = read(body_start, eof1 - body_start)
            if flags1 & FLAG_CRC32 and zlib.crc32(body) != crc1:
                continue
            key = read(header_size, key_length).decode('utf-8', 'replace')
            headers = http_headers(read(stream0_start, stream0))
            return body_start, eof1 - body_start, key, headers
    return None

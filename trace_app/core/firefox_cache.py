"""Firefox's disk cache, format 1 (Firefox 1.5 to 31): what the block
files `_CACHE_001_` .. `_CACHE_003_` hold, read through `_CACHE_MAP_`
(no Qt).

A small cached object -- most web graphics -- is not a file of its own:
it is stored in 256-byte, 1 KB or 4 KB blocks of a block file, and only
the map says where. Read as files, the block files are one picture's
worth of bytes each (the M57 'Jean' image: 960 of the pictures AXIOM
listed were inside them, under the block file's name). Larger objects
are files of their own (<hash>d01), which the file walk sees already.

Layout (Mozilla's nsDiskCacheMap.h / nsDiskCacheEntry.h; all
big-endian):

* `_CACHE_MAP_`: a header -- version (major 1), data size, entry count,
  dirty flag, record count, then 32 eviction ranks and 32 bucket usages
  (276 bytes) -- followed by 16-byte records: hash, eviction rank, data
  location, metadata location.
* A location: bit 31 set when in use; bits 28-29 the file (0 = a file of
  its own, 1-3 = `_CACHE_00n_`), bits 24-25 the extra blocks, bits 0-23
  the first block. A file of its own is `%08X` hash + 'd' / 'm' + the
  generation in bits 0-7.
* A block file: a 4,096-byte bitmap, then blocks of 256 << 2(n-1) bytes.
* The metadata entry: header version, its own location (Firefox 3 often
  leaves it 0; where set, it must be the map's), fetch count, last
  fetched, last modified, expiry (seconds, UTC), data size, key size,
  metadata size; then the key ('HTTP:http://host/path') and NUL-separated
  name/value pairs, one of them the response's HTTP header.

A record is read only when its metadata and its data each fill exactly
the blocks the map gives them (the block count is the size rounded up):
blocks reused by a later object fail that.

Content sent compressed (Content-Encoding gzip / deflate) is stored as
sent: it is given decoded, with the encoding said.
"""

import gzip
import io
import logging
import re
import struct
import urllib.parse
import zlib

logger = logging.getLogger('TRACE.FirefoxCache')

MAP_NAME = '_CACHE_MAP_'
BLOCK_FILES = {1: '_CACHE_001_', 2: '_CACHE_002_', 3: '_CACHE_003_'}
BLOCK_SIZES = {1: 256, 2: 1024, 3: 4096}
BITMAP_BYTES = 4096
HEADER_BYTES = 20 + 32 * 4 * 2
RECORD_BYTES = 16
ENTRY_HEADER = struct.Struct('>9I')
#: A decoded object larger than this is not decoded (zeros inflate a
#: thousandfold).
MAX_DECODED = 64 * 1024 * 1024

_IN_USE = 0x80000000
_SELECTOR = 0x30000000
_EXTRA = 0x03000000
_BLOCK = 0x00FFFFFF


class CacheError(Exception):
    """Not a format-1 cache map."""


def is_map(head):
    """A `_CACHE_MAP_` of format 1: major version 1, a record count the
    file holds."""
    if len(head) < HEADER_BYTES:
        return False
    version, _data, entries, dirty, records = struct.unpack_from('>5I', head)
    return version >> 16 == 1 and dirty in (0, 1) and entries <= records \
        if records else version >> 16 == 1 and dirty in (0, 1)


def records(map_bytes):
    """(hash, data location, metadata location) of every record in use."""
    if not is_map(map_bytes):
        raise CacheError("not a Firefox cache map (format 1)")
    for position in range(HEADER_BYTES, len(map_bytes) - RECORD_BYTES + 1,
                          RECORD_BYTES):
        number, _rank, data, meta = struct.unpack_from('>4I', map_bytes,
                                                       position)
        if number and meta & _IN_USE:
            yield number, data, meta


def where(location):
    """(file number 0-3, first block, block count, generation)."""
    selector = (location & _SELECTOR) >> 28
    if selector == 0:
        return 0, 0, 0, location & 0xFF
    return selector, location & _BLOCK, ((location & _EXTRA) >> 24) + 1, 0


def own_file_name(number, kind, generation):
    """'98A43954d01': a cached object or its metadata in a file of its
    own (`kind` 'd' or 'm')."""
    return f"{number:08X}{kind}{generation:02X}"


class Cache:
    """One cache folder. `read_file(name)` -> the bytes of the file of that
    name in the folder, or None."""

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

    def _blocks(self, location):
        """The bytes a block location covers, or None (a file of its own
        or a block file not there)."""
        selector, first, count, _generation = where(location)
        if selector == 0:
            return None
        data = self._file(BLOCK_FILES[selector])
        if data is None:
            return None
        size = BLOCK_SIZES[selector]
        begin = BITMAP_BYTES + first * size
        piece = data[begin:begin + count * size]
        return piece if len(piece) == count * size else None

    def metadata(self, number, location):
        """The metadata entry for a record: dict, or None when what the map
        points at is not that entry -- its own location, where it records
        one, differs, or it does not fill the blocks the map gives it."""
        selector, _first, count, generation = where(location)
        if selector == 0:
            raw = self._file(own_file_name(number, 'm', generation))
        else:
            raw = self._blocks(location)
        if not raw or len(raw) < ENTRY_HEADER.size:
            return None
        (version, own, fetches, fetched, modified, expires, data_size,
         key_size, meta_size) = ENTRY_HEADER.unpack_from(raw)
        if version >> 16 != 1 or own not in (0, location):
            return None
        start = ENTRY_HEADER.size
        length = start + key_size + meta_size
        if length > len(raw) or not key_size:
            return None
        if selector and _blocks_for(length, selector) != count:
            return None
        key = raw[start:start + key_size].rstrip(b'\0').decode(
            'utf-8', 'replace')
        pairs = raw[start + key_size:start + key_size + meta_size].split(
            b'\0')
        elements = {}
        for index in range(0, len(pairs) - 1, 2):
            elements[pairs[index].decode('latin-1')] = \
                pairs[index + 1].decode('latin-1')
        return {'key': key, 'fetch_count': fetches, 'last_fetched': fetched,
                'last_modified': modified, 'expires': expires,
                'data_size': data_size, 'elements': elements}

    def entries(self):
        """Every cached object stored in a block file, as dicts: key (the
        URL), name (the URL's file name), block_file, offset in it, size
        as stored, content (decoded), encoding ('' when stored as sent),
        last_fetched / last_modified (Unix seconds, UTC), content_type."""
        data = self._file(MAP_NAME)
        if data is None:
            return
        for number, data_location, meta_location in records(data):
            if not data_location & _IN_USE:
                continue
            selector, first, count, _generation = where(data_location)
            if selector == 0:
                continue                # a file of its own: the walk has it
            meta = self.metadata(number, meta_location)
            if meta is None:
                continue
            blocks = self._blocks(data_location)
            size = meta['data_size']
            if blocks is None or not size or \
                    _blocks_for(size, selector) != count:
                continue
            stored = blocks[:size]
            head = http_headers(meta['elements'].get('response-head', ''))
            encoding = head.get('content-encoding', '').lower()
            content = decode(stored, encoding)
            if content is None:
                content, encoding = stored, ''
            yield {'key': meta['key'], 'name': url_name(meta['key'], number),
                   'block_file': BLOCK_FILES[selector],
                   'offset': BITMAP_BYTES + first * BLOCK_SIZES[selector],
                   'size': size, 'content': content,
                   'encoding': encoding if content is not stored else '',
                   'last_fetched': meta['last_fetched'],
                   'last_modified': meta['last_modified'],
                   'content_type': head.get('content-type', '')}


def _blocks_for(length, selector):
    size = BLOCK_SIZES[selector]
    return (length + size - 1) // size


def http_headers(text):
    """{lower-case name: value} of a stored HTTP response header."""
    out = {}
    for line in text.split('\r\n')[1:] if '\r\n' in text else \
            text.split('\n')[1:]:
        name, colon, value = line.partition(':')
        if colon:
            out[name.strip().lower()] = value.strip()
    return out


def decode(data, encoding):
    """`data` decoded from a Content-Encoding, or None when it is not
    (or cannot be) decoded."""
    if encoding in ('gzip', 'x-gzip'):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                out = stream.read(MAX_DECODED + 1)
            return out if len(out) <= MAX_DECODED else None
        except (OSError, EOFError, zlib.error):
            return None
    if encoding == 'deflate':
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                inflater = zlib.decompressobj(wbits)
                out = inflater.decompress(data, MAX_DECODED + 1)
                if len(out) <= MAX_DECODED:
                    return out
            except zlib.error:
                continue
    return None


_SAFE = re.compile(r'[\x00-\x1f<>:"/\\|?*]')


def url_name(key, number):
    """The file name a cached URL had ('grocery_180x150.gif'), else the
    record's hash."""
    url = key.split(':', 1)[1] if key.upper().startswith('HTTP') and \
        ':' in key else key
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        path = ''
    name = urllib.parse.unquote(path.rstrip('/').rsplit('/', 1)[-1])
    name = _SAFE.sub('_', name).strip(' .')[:120]
    return name or f"{number:08X}"

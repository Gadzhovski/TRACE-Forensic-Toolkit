"""Spotlight metadata stores (store.db / .store.db), no Qt.

Spotlight keeps, for every file it indexed, the attributes it learned:
names, sizes, content type, when the file was created, changed, *last
opened* and every day it was used, where a download came from, authors,
titles -- and it keeps them after the file itself is gone. On iOS and in
each Mac user's Library/Metadata/CoreSpotlight the same format holds what
apps donated (messages, notes, mail, web pages).

The format (version 2, macOS 10.13+ and iOS), as Yogesh Khatri documented
it in spotlight_parser / mac_apt -- read here with TRACE's own code:

* header: '8tsd', flags, then at 36 the header size, block 0's size, the
  block size, and the first block (in 4 KiB units) of each definition
  chain: properties (0x11), categories (0x21), 0x41 (unknown), and the two
  index chains (0x81) -- `indexes_1` for multi-valued categories,
  `indexes_2` for an item's kind. The volume's path is at 0x144. An iOS
  or per-user (CoreSpotlight) store has no chains (the first is 0): its
  definitions are in dbStr-<n>.map.data/.offsets/.header beside it
  (1 properties, 2 categories, 4 indexes_1, 5 indexes_2).
* block 0 (after the header, '1mbd'/'2mbd'): the metadata blocks, as
  (last item id, block number in 4 KiB units, size) of 16 bytes each.
* a block: '2pbd', physical size, logical size, type, the decoded size,
  the next block of its chain; definitions start 32 bytes in. A metadata
  block (type 0x09) is compressed from byte 20: zlib; with 0x1000 Apple
  LZ4 ('bv41' chunks) or a bare LZ4 block; with 0x2000 LZFSE ('bvx*').
* decoded metadata: records, each a 32-bit length then id, flags, item
  id, parent id (an *id*: paths are built from ids, the root is 2), date
  updated (microseconds since 1970), and attributes: a property-index step
  and a value whose encoding the property's value type and flags give.
  Numbers use Spotlight's variable length: the leading 1-bits of the first
  byte count the bytes after it (big-endian); with 5 or more, the first
  byte contributes nothing.

`Store(data, maps=None)` parses; `.items()` yields `Item`s; `.paths()`
rebuilds full paths. SpotlightError when the bytes are not a store.
"""

import logging
import struct
import zlib

logger = logging.getLogger('TRACE.Spotlight')

SIGNATURE = b'8tsd'
SIGNATURE_V1 = b'7tsd'
BLOCK_SIGNATURE = b'2pbd'
BLOCK0_SIGNATURES = (b'1mbd', b'2mbd')
PAGE = 0x1000

TYPE_METADATA = 0x09
TYPE_PROPERTIES = 0x11
TYPE_CATEGORIES = 0x21
TYPE_INDEXES = 0x81

ROOT_ID = 2
#: Decoded metadata blocks larger than this are not believed.
MAX_BLOCK_BYTES = 64 * 1024 * 1024
#: Blocks followed along one definition chain at most.
MAX_CHAIN = 100_000
#: Map files (iOS / CoreSpotlight definitions) beside a store.
MAP_FILES = {1: 'properties', 2: 'categories', 4: 'indexes_1',
             5: 'indexes_2'}


class SpotlightError(ValueError):
    """Not a Spotlight store, or damaged beyond reading."""


def is_store(data):
    return bytes(data[:4]) in (SIGNATURE, SIGNATURE_V1)


def read_number(data, pos):
    """(value, next position) of a Spotlight variable-length number."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    if first >= 0xF0:
        if first == 0xFF:
            extra, high = 8, 0
        elif first & 0x0E == 0x0E:
            extra, high = 7, 0
        elif first & 0x0C == 0x0C:
            extra, high = 6, 0
        elif first & 0x08 == 0x08:
            extra, high = 5, 0
        else:
            extra, high = 4, first & 0x0F
    elif first >= 0xE0:
        extra, high = 3, first & 0x1F
    elif first >= 0xC0:
        extra, high = 2, first & 0x3F
    else:
        extra, high = 1, first & 0x7F
    if pos + 1 + extra > len(data):
        raise SpotlightError("number runs past the end")
    value = int.from_bytes(data[pos + 1:pos + 1 + extra], 'big')
    return value | (high << (8 * extra)), pos + 1 + extra


def _leb128(data, pos):
    """A 7-bit little-endian varint (the map files' entry sizes)."""
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _signed64(value):
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= 1 << 63 else value


def _signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= 1 << 31 else value


def _first_language(raw):
    """A category's text: the first of its translations (each ends with
    0x16 0x02 and a language code)."""
    return bytes(raw).split(b'\x16\x02')[0].decode('utf-8', 'replace')


class Item:
    """One indexed object: ids and {property name: value}."""

    __slots__ = ('id', 'flags', 'item_id', 'parent_id', 'updated',
                 'attributes')

    def __init__(self):
        self.id = self.flags = self.item_id = self.parent_id = 0
        self.updated = 0
        self.attributes = {}

    @property
    def is_store_metadata(self):
        return '_kStoreMetadataVersion' in self.attributes

    @property
    def name(self):
        for key in ('_kMDItemFileName', 'kMDItemDisplayName'):
            value = self.attributes.get(key)
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                return str(value).split('\x16\x02')[0]
        return ''


class Store:
    """A parsed store.db. `maps`: {n: (data, offsets, header)} of the
    dbStr-<n>.map files beside an iOS or CoreSpotlight store."""

    def __init__(self, data, maps=None):
        data = bytes(data)
        if data[:4] == SIGNATURE_V1:
            raise SpotlightError("a version 1 store (Mac OS X 10.12 or "
                                 "earlier) is not read")
        if data[:4] != SIGNATURE:
            raise SpotlightError("not a Spotlight store (no '8tsd')")
        if len(data) < 0x244:
            raise SpotlightError("header cut short")
        self.data = data
        self.flags = struct.unpack_from('<I', data, 4)[0]
        (self.header_size, self.block0_size, self.block_size, chain_11,
         chain_21, _chain_41, chain_81_1, chain_81_2) = \
            struct.unpack_from('<8I', data, 36)
        self.original_path = data[0x144:0x244].split(b'\0', 1)[0].decode(
            'utf-8', 'replace')
        #: iOS and per-user CoreSpotlight stores keep definitions apart
        #: and record no file-system ids.
        self.external = chain_11 == 0
        self.properties = {}            # index -> (name, prop type, value type)
        self.categories = {}            # index -> raw bytes
        self.indexes_1 = {}             # index -> [category ids]
        self.indexes_2 = {}
        self.skipped_blocks = 0
        if self.external:
            if not maps:
                raise SpotlightError(
                    "an iOS / CoreSpotlight store needs the dbStr-*.map "
                    "files beside it")
            self._read_maps(maps)
        else:
            self._chain(chain_11, TYPE_PROPERTIES, self._properties)
            self._chain(chain_21, TYPE_CATEGORIES, self._categories)
            self._chain(chain_81_1, TYPE_INDEXES,
                        lambda b: self._indexes(b, self.indexes_1))
            self._chain(chain_81_2, TYPE_INDEXES,
                        lambda b: self._indexes(b, self.indexes_2))
        if not self.properties:
            raise SpotlightError("no property definitions")
        self.metadata_blocks = self._block0()

    # --- blocks -----------------------------------------------------------

    def _block(self, number):
        """(type, logical size, next block, the block's bytes) at a block
        number (4 KiB units)."""
        offset = number * PAGE
        head = self.data[offset:offset + 32]
        if len(head) < 32 or head[:4] != BLOCK_SIGNATURE:
            raise SpotlightError(f"no block at page {number}")
        physical, logical, kind, _decoded, following = struct.unpack_from(
            '<5I', head, 4)
        size = max(physical, self.block_size, logical)
        return kind, logical, following, self.data[offset:offset + size]

    def _chain(self, first, kind, parse):
        seen = set()
        number = first
        while number and number not in seen and len(seen) < MAX_CHAIN:
            seen.add(number)
            try:
                block_kind, logical, following, raw = self._block(number)
            except SpotlightError as exc:
                logger.debug("Spotlight chain 0x%x: %s", kind, exc)
                self.skipped_blocks += 1
                return
            if block_kind != kind:
                logger.debug("Spotlight chain 0x%x met a 0x%x block", kind,
                             block_kind)
                self.skipped_blocks += 1
                return
            try:
                parse(raw[:logical])
            except (struct.error, IndexError, SpotlightError) as exc:
                logger.debug("Spotlight block %d: %s", number, exc)
                self.skipped_blocks += 1
            number = following

    @staticmethod
    def _cstring(data, pos):
        end = data.find(b'\0', pos)
        end = len(data) if end < 0 else end
        return data[pos:end], end + 1

    def _properties(self, body):
        pos = 32
        while pos + 6 <= len(body):
            index, value_type, prop_type = struct.unpack_from('<IBB', body,
                                                              pos)
            name, pos = self._cstring(body, pos + 6)
            self.properties[index] = (name.decode('utf-8', 'replace'),
                                      prop_type, value_type)

    def _categories(self, body):
        pos = 32
        while pos + 4 <= len(body):
            index = struct.unpack_from('<I', body, pos)[0]
            name, pos = self._cstring(body, pos + 4)
            self.categories[index] = name

    def _indexes(self, body, into):
        pos = 32
        while pos + 4 <= len(body):
            index = struct.unpack_from('<I', body, pos)[0]
            size, pos = read_number(body, pos + 4)
            pos += size % 4
            count = size // 4
            into[index] = list(struct.unpack_from(f'<{count}i', body, pos))
            pos += count * 4

    def _read_maps(self, maps):
        def entries(number):
            data, offsets, _header = maps.get(number) or (b'', b'', b'')
            pos, index = 4, 1
            while pos + 4 <= len(offsets):
                offset = struct.unpack_from('<I', offsets, pos)[0]
                if offset == 0:
                    break
                if offset != 1 and offset < len(data):   # 1: deleted
                    yield index, offset, data
                index += 1
                pos += 4

        for index, offset, data in entries(1):
            try:
                size, pos = read_number(data, offset)
                value_type, prop_type = data[pos], data[pos + 1]
                name = data[pos + 2:pos + size].split(b'\0')[0]
                self.properties[index] = (name.decode('utf-8', 'replace'),
                                          prop_type, value_type)
            except (IndexError, SpotlightError):
                continue
        for index, offset, data in entries(2):
            try:
                size, pos = read_number(data, offset)
                self.categories[index] = data[pos:pos + size].split(b'\0')[0]
            except (IndexError, SpotlightError):
                continue
        for number, into, extra in ((4, self.indexes_1, 0),
                                    (5, self.indexes_2, 1)):
            for index, offset, data in entries(number):
                try:
                    _entry, pos = _leb128(data, offset)
                    size, pos = read_number(data, pos)
                    pos += extra
                    count = size // 4
                    into[index] = list(struct.unpack_from(f'<{count}i', data,
                                                          pos))
                except (IndexError, struct.error, SpotlightError):
                    continue

    def _block0(self):
        start = self.header_size
        head = self.data[start:start + 20]
        if head[:4] not in BLOCK0_SIGNATURES:
            raise SpotlightError("no block 0 (the metadata block list)")
        count = struct.unpack_from('<I', head, 8)[0]
        out = []
        for i in range(count):
            at = start + 20 + 16 * i
            if at + 16 > len(self.data):
                break
            _last, number, _size = struct.unpack_from('<QII', self.data, at)
            out.append(number)
        return out

    def _metadata(self, number):
        kind, logical, _following, raw = self._block(number)
        if kind & 0xFF != TYPE_METADATA:
            raise SpotlightError(f"page {number} is not a metadata block")
        decoded_size = struct.unpack_from('<I', raw, 16)[0]
        body = raw[20:logical]
        if kind & 0x1000:
            if body[:4] in (b'bv41', b'bv4-'):
                return apple_lz4(body)
            return _lz4(body, decoded_size - 20)
        if kind & 0x2000:
            if body[:3] == b'bvx':
                from trace_app.core import lzfse
                try:
                    return lzfse.decompress(body, max_length=MAX_BLOCK_BYTES)
                except lzfse.LzfseError as exc:
                    raise SpotlightError(f"LZFSE: {exc}") from exc
            return _lz4(body, decoded_size - 20)
        try:
            return zlib.decompressobj().decompress(body, MAX_BLOCK_BYTES)
        except zlib.error as exc:
            raise SpotlightError(f"zlib: {exc}") from exc

    # --- records ----------------------------------------------------------

    def items(self, limit=None):
        """Every record of every metadata block block 0 lists."""
        count = 0
        for number in self.metadata_blocks:
            try:
                body = self._metadata(number)
            except SpotlightError as exc:
                self.skipped_blocks += 1
                logger.debug("Spotlight metadata page %d: %s", number, exc)
                continue
            pos = 0
            while pos + 4 <= len(body):
                size = struct.unpack_from('<I', body, pos)[0]
                if size == 0 or pos + 4 + size > len(body):
                    break
                item = self._item(body[pos + 4:pos + 4 + size])
                pos += 4 + size
                if item is None:
                    continue
                yield item
                count += 1
                if limit is not None and count >= limit:
                    return

    def _item(self, record):
        item = Item()
        try:
            value, pos = read_number(record, 0)
            item.id = _signed64(value)
            item.flags = record[pos]
            value, pos = read_number(record, pos + 1)
            item.item_id = _signed64(value)
            value, pos = read_number(record, pos)
            item.parent_id = _signed64(value)
            item.updated, pos = read_number(record, pos)
        except (SpotlightError, IndexError):
            return None
        index = 0
        while pos < len(record):
            try:
                step, pos = read_number(record, pos)
                if step == 0 or step == 0xFFFFFFFF:
                    break               # the rest is slack
                index += step
                definition = self.properties.get(index)
                if definition is None:
                    break               # unknown property: layout unknown
                name, prop_type, value_type = definition
                value, pos = self._value(record, pos, name, prop_type,
                                         value_type)
            except (SpotlightError, struct.error, IndexError):
                break
            if value is _STOP:
                break
            if value not in (None, '', [], b''):
                item.attributes[name] = value
        return item

    def _value(self, data, pos, name, prop_type, value_type):
        multiple = bool(prop_type & 0x02)
        if value_type in (0x00, 0x02):
            return read_number(data, pos)
        if value_type == 0x06:
            if multiple:
                a, pos = read_number(data, pos)
                b, pos = read_number(data, pos)
                return [a, b], pos
            return read_number(data, pos)
        if value_type == 0x07:
            if multiple:
                header, pos = read_number(data, pos)
                values = []
                for _ in range(_signed64(header) >> 3):
                    value, pos = read_number(data, pos)
                    values.append(_signed64(value))
                return values, pos
            value, pos = read_number(data, pos)
            return _signed64(value), pos
        if value_type == 0x08:
            if name == 'kMDStoreAccumulatedSizes':
                return _STOP, pos
            if multiple:
                values = []
                for _ in range(4):
                    value, pos = read_number(data, pos)
                    values.append(value)
                return values, pos
            return read_number(data, pos)
        if value_type in (0x09, 0x0A, 0x0C):
            size, form = (4, '<f') if value_type == 0x09 else (8, '<d')
            if multiple:
                length, pos = read_number(data, pos)
                count = length // size
                values = list(struct.unpack_from(f'<{count}{form[1]}', data,
                                                 pos))
                return values, pos + length
            return struct.unpack_from(form, data, pos)[0], pos + size
        if value_type == 0x0B:
            strings, pos = _strings(data, pos)
            if multiple:
                return strings, pos
            return (strings[0] if strings else ''), pos
        if value_type == 0x0E:
            length, pos = read_number(data, pos)
            if prop_type & 0x80:
                # Binary: the length counts one byte more than is stored.
                size = max(length - 1, 0)
                return bytes(data[pos:pos + size]), pos + size
            raw = bytes(data[pos:pos + length])
            if multiple:
                pieces = [p[:-2] if p.endswith(b'\x16\x02') else p
                          for p in raw.split(b'\0') if p]
                return [_text_or_bytes(p) for p in pieces], pos + length
            # One value, kept whole (it may be binary with NULs inside):
            # only a closing NUL and language mark come off.
            if raw.endswith(b'\0'):
                raw = raw[:-1]
            if raw.endswith(b'\x16\x02'):
                raw = raw[:-2]
            return _text_or_bytes(raw), pos + length
        if value_type == 0x0F:
            raw, pos = read_number(data, pos)
            value = _signed32(raw)
            if value < 0:
                return '', pos
            if prop_type & 0x03 == 0x03:
                for category in self.indexes_2.get(value) or ():
                    if category >= 0 and category in self.categories:
                        return _first_language(self.categories[category]), pos
                return '', pos
            if multiple:
                return [_first_language(self.categories[c])
                        for c in self.indexes_1.get(value) or ()
                        if c >= 0 and c in self.categories], pos
            category = self.categories.get(value)
            return (_first_language(category) if category is not None
                    else ''), pos
        # A value type nobody has described: the rest of the record cannot
        # be read past it.
        return _STOP, pos

    # --- paths ------------------------------------------------------------

    @staticmethod
    def paths(items):
        """{id: full path} from each item's name and parent id (an id of
        another item; 2 is the volume's root). A chain that reaches an id
        no record has keeps what it has, under '…/'."""
        names = {}
        for item in items:
            if item.id > ROOT_ID and item.name and \
                    not item.is_store_metadata:
                names.setdefault(item.id, (item.name, item.parent_id))
        out = {}
        for item_id in names:
            parts, seen, current = [], set(), item_id
            rooted = False
            while current in names and current not in seen:
                seen.add(current)
                name, parent = names[current]
                parts.append(name)
                if parent in (0, ROOT_ID):
                    rooted = True
                    break
                current = parent
            out[item_id] = ('/' if rooted else '…/') + \
                '/'.join(reversed(parts))
        return out


#: Returned by _value when the record cannot be read further.
_STOP = object()


def _strings(data, pos):
    """A string value: its length, then texts split by NUL, each perhaps
    ending with the 0x16 0x02 language mark."""
    length, pos = read_number(data, pos)
    raw = bytes(data[pos:pos + length])
    out = []
    for piece in raw.split(b'\0'):
        if not piece:
            continue
        if piece.endswith(b'\x16\x02'):
            piece = piece[:-2]
        out.append(piece.decode('utf-8', 'replace'))
    return out, pos + length


def _text_or_bytes(raw):
    """Text when the bytes are UTF-8 with no control characters but
    whitespace, else the bytes (a UUID, an archived plist)."""
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw
    if any(ord(c) < 32 and c not in '\t\n\r' for c in text):
        return raw
    return text


def _lz4(body, size):
    from trace_app.core.activity.journal import lz4_block
    try:
        return bytes(lz4_block(bytes(body), max(size, 0),
                               stop_at=size if size > 0 else None))
    except Exception as exc:
        raise SpotlightError(f"LZ4: {exc}") from exc


def apple_lz4(payload):
    """Apple's LZ4 framing: 'bv41' chunks (decoded size, coded size, LZ4
    data whose matches may reach into the chunk before), 'bv4-' stored
    chunks, 'bv4$' the end."""
    from trace_app.core.activity.journal import lz4_block
    out = bytearray()
    previous = b''
    pos = 0
    while pos + 4 <= len(payload):
        magic = payload[pos:pos + 4]
        if magic == b'bv4$':
            break
        if magic == b'bv4-':
            size = struct.unpack_from('<I', payload, pos + 4)[0]
            previous = bytes(payload[pos + 8:pos + 8 + size])
            out += previous
            pos += 8 + size
        elif magic == b'bv41':
            raw, packed = struct.unpack_from('<II', payload, pos + 4)
            block = bytes(payload[pos + 12:pos + 12 + packed])
            try:
                previous = bytes(lz4_block(block, raw, stop_at=raw,
                                           history=previous))
            except Exception as exc:
                raise SpotlightError(f"LZ4: {exc}") from exc
            out += previous
            pos += 12 + packed
        else:
            break
        if len(out) > MAX_BLOCK_BYTES:
            raise SpotlightError("LZ4 block too large")
    return bytes(out)



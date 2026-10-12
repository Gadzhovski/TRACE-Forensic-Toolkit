"""Values as V8 serialises them (no Qt).

IndexedDB stores each value the way the page's JavaScript held it: run
through V8's ValueSerializer (v8/src/objects/value-serializer.cc), inside
Blink's envelope (third_party/blink/.../serialized_script_value). The
reader here follows the serializer's tags:

    _ undefined   0 null   T F booleans   I int32 (zigzag)   U uint32
    N double   Z BigInt   " Latin-1 string   c UTF-16 string   S UTF-8
    o object ... { count   A dense array ... $ props length
    a sparse array ... @ props length   D date   R regexp
    ; Map ... : length   ' Set ... , length   B ArrayBuffer
    V typed array or DataView (after its buffer)   ^ back-reference
    y x n s z boxed primitives   - hole   ? object count   \\ host object

Every object gets an id in the order it begins, which '^' refers to: one
object stored twice is one object read twice. JavaScript values become
Python ones: str, int, float, bool, None, UNDEFINED, datetime (UTC), dict,
list (a sparse array as a dict of index -> value with its length), Map as
a list of (key, value), Set as a list, bytes, and TypedArray.
"""

import datetime
import struct

#: JavaScript's undefined (None is null).
UNDEFINED = type('Undefined', (), {'__repr__': lambda self: 'undefined',
                                   '__bool__': lambda self: False})()
HOLE = type('Hole', (), {'__repr__': lambda self: '<hole>'})()

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
_VIEWS = {'b': ('Int8Array', 'b'), 'B': ('Uint8Array', 'B'),
          'C': ('Uint8ClampedArray', 'B'), 'w': ('Int16Array', 'h'),
          'W': ('Uint16Array', 'H'), 'd': ('Int32Array', 'i'),
          'D': ('Uint32Array', 'I'), 'f': ('Float32Array', 'f'),
          'F': ('Float64Array', 'd'), 'q': ('BigInt64Array', 'q'),
          'Q': ('BigUint64Array', 'Q'), '?': ('DataView', None),
          'h': ('Float16Array', 'e')}


class V8Error(ValueError):
    """Bytes that are not a V8 serialised value."""


class TypedArray:
    """A typed array or DataView: its kind and values (bytes for a
    DataView)."""

    def __init__(self, kind, values):
        self.kind, self.values = kind, values

    def __eq__(self, other):
        return isinstance(other, TypedArray) and \
            (self.kind, self.values) == (other.kind, other.values)

    def __repr__(self):
        return f"{self.kind}({self.values!r})"


class RegExp:
    def __init__(self, pattern, flags):
        self.pattern, self.flags = pattern, flags

    def __eq__(self, other):
        return isinstance(other, RegExp) and \
            (self.pattern, self.flags) == (other.pattern, other.flags)

    def __repr__(self):
        return f"/{self.pattern}/{self.flags}"


class SparseArray(dict):
    """A sparse array: {index: value}, with `length`."""

    def __init__(self, length):
        super().__init__()
        self.length = length


class HostObject:
    """A Blink object V8 does not describe itself (a File, a Blob)."""

    def __init__(self, tag, data):
        self.tag, self.data = tag, data

    def __repr__(self):
        return f"<host object {self.tag!r}>"


_REGEXP_FLAGS = (('d', 0x80), ('g', 0x01), ('i', 0x02), ('l', 0x100),
                 ('m', 0x04), ('s', 0x20), ('u', 0x10), ('v', 0x200),
                 ('y', 0x08))


class Reader:
    def __init__(self, data):
        self.data = bytes(data)
        self.position = 0
        self.objects = []
        self.version = 0

    # --- primitives ---------------------------------------------------------

    def byte(self):
        if self.position >= len(self.data):
            raise V8Error("value runs past the data")
        value = self.data[self.position]
        self.position += 1
        return value

    def varint(self):
        result = shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 70:
                raise V8Error("varint too long")

    def zigzag(self):
        value = self.varint()
        return (value >> 1) ^ -(value & 1)

    def take(self, count):
        end = self.position + count
        if end > len(self.data):
            raise V8Error("value runs past the data")
        out = self.data[self.position:end]
        self.position = end
        return out

    def double(self):
        return struct.unpack('<d', self.take(8))[0]

    # --- values --------------------------------------------------------------

    def header(self):
        """Skip V8's version tag (and padding before it)."""
        while self.position < len(self.data) and \
                self.data[self.position] == 0:
            self.position += 1
        if self.position < len(self.data) and self.data[self.position] == \
                0xFF:
            self.position += 1
            self.version = self.varint()

    def _remember(self, value):
        self.objects.append(value)
        return value

    def value(self):
        tag = chr(self.byte())
        while tag == '\x00':                       # padding
            tag = chr(self.byte())
        if tag == '?':                             # verify object count
            self.varint()
            return self.value()
        if tag == '_':
            return UNDEFINED
        if tag == '0':
            return None
        if tag == 'T':
            return True
        if tag == 'F':
            return False
        if tag == 'I':
            return self.zigzag()
        if tag == 'U':
            return self.varint()
        if tag == 'N':
            return self.double()
        if tag == 'Z':
            return self._bigint()
        if tag == '"':
            return self.take(self.varint()).decode('latin-1')
        if tag == 'c':
            return self.take(self.varint()).decode('utf-16-le',
                                                   'surrogatepass')
        if tag == 'S':
            return self.take(self.varint()).decode('utf-8', 'replace')
        if tag == '^':
            index = self.varint()
            if index >= len(self.objects):
                raise V8Error(f"reference to object {index} not yet read")
            return self.objects[index]
        if tag == 'o':
            return self._object()
        if tag == 'A':
            return self._dense_array()
        if tag == 'a':
            return self._sparse_array()
        if tag == 'D':
            milliseconds = self.double()
            try:
                moment = _EPOCH + datetime.timedelta(
                    milliseconds=milliseconds)
            except (OverflowError, ValueError):
                moment = milliseconds
            return self._remember(moment)
        if tag in 'yx':
            return self._remember(tag == 'y')
        if tag == 'n':
            return self._remember(self.double())
        if tag == 'z':
            return self._remember(self._bigint())
        if tag == 's':
            index = len(self.objects)
            self.objects.append(None)
            self.objects[index] = self.value()
            return self.objects[index]
        if tag == 'R':
            pattern = self.value()
            flags = self.varint()
            text = ''.join(letter for letter, bit in _REGEXP_FLAGS
                           if flags & bit)
            return self._remember(RegExp(pattern, text))
        if tag == ';':
            return self._map()
        if tag == "'":
            return self._set()
        if tag == 'B':
            buffer = self._remember(self.take(self.varint()))
            return self._maybe_view(buffer)
        if tag == 'V':
            raise V8Error("a view with no buffer before it")
        if tag == '-':
            return HOLE
        if tag == '\\':
            return self._host()
        if tag == 'r':
            return self._error()
        raise V8Error(f"unknown V8 tag {tag!r} at {self.position - 1}")

    def _bigint(self):
        bitfield = self.varint()
        length = bitfield >> 1
        digits = self.take(length)
        value = int.from_bytes(digits, 'little')
        return -value if bitfield & 1 else value

    def _properties(self, target, end):
        while True:
            if self.position >= len(self.data):
                raise V8Error("object runs past the data")
            if self.data[self.position] == ord(end):
                self.position += 1
                return self.varint()
            key = self.value()
            target[key] = self.value()

    def _object(self):
        out = self._remember({})
        self._properties(out, '{')
        return out

    def _dense_array(self):
        length = self.varint()
        out = self._remember([])
        for _index in range(length):
            out.append(self.value())
        extra = {}
        self._properties(extra, '$')
        self.varint()                                # length again
        for key, value in extra.items():
            if isinstance(key, int) and 0 <= key < len(out):
                out[key] = value
        return out

    def _sparse_array(self):
        out = self._remember(SparseArray(self.varint()))
        self._properties(out, '@')
        out.length = self.varint()
        return out

    def _map(self):
        out = self._remember([])
        while True:
            if self.data[self.position:self.position + 1] == b':':
                self.position += 1
                self.varint()
                return out
            out.append((self.value(), self.value()))

    def _set(self):
        out = self._remember([])
        while True:
            if self.data[self.position:self.position + 1] == b',':
                self.position += 1
                self.varint()
                return out
            out.append(self.value())

    def _maybe_view(self, buffer):
        """A typed array or DataView that follows its buffer."""
        if self.data[self.position:self.position + 1] != b'V':
            return buffer
        self.position += 1
        subtag = chr(self.byte())
        offset = self.varint()
        length = self.varint()
        if self.version >= 14:
            self.varint()                            # flags
        kind, code = _VIEWS.get(subtag, (f"view {subtag!r}", None))
        raw = buffer[offset:offset + length]
        if code is None:
            values = bytes(raw)
        else:
            size = struct.calcsize(code)
            values = list(struct.unpack(f'<{len(raw) // size}{code}',
                                        raw[:len(raw) // size * size]))
        view = TypedArray(kind, values)
        # The view takes the buffer's place as what the page stored.
        self.objects[-1] = view
        return view

    def _host(self):
        """A Blink host object: its tag and what follows it, uninterpreted
        (Blob, File, ImageData...)."""
        tag = chr(self.byte())
        return self._remember(HostObject(tag, b''))

    def _error(self):
        out = {'error': True}
        while True:
            sub = chr(self.byte())
            if sub == '.':
                return self._remember(out)
            if sub == 'm':
                out['message'] = self.value()
            elif sub == 's':
                out['stack'] = self.value()
            elif sub == 'c':
                out['cause'] = self.value()
            else:
                out.setdefault('kind', sub)


def loads(data):
    """The value V8 serialised in `data` (its header, then one value)."""
    reader = Reader(data)
    reader.header()
    return reader.value()


def blink_value(data):
    """An IndexedDB value's payload: Blink's envelope (version tag,
    version, the trailer offset tag and its 12 bytes) taken off, V8's own
    value read. Returns the value."""
    data = bytes(data)
    position = 0
    if data[:1] == b'\xff':
        reader = Reader(data)
        reader.position = 1
        blink = reader.varint()
        position = reader.position
        if blink >= 21 and data[position:position + 1] == b'\xfe':
            position += 1 + 8 + 4                     # trailer offset, size
    return loads(data[position:])


def to_text(value, limit=2000):
    """A value as a short JSON-like line, for a record's detail."""
    import json

    def plain(item, depth=0):
        if depth > 12:
            return '…'
        if item is UNDEFINED:
            return 'undefined'
        if isinstance(item, datetime.datetime):
            return item.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' UTC'
        if isinstance(item, (bytes, bytearray)):
            return f"<{len(item)} bytes {bytes(item[:32]).hex()}>"
        if isinstance(item, SparseArray):
            return {str(k): plain(v, depth + 1) for k, v in item.items()}
        if isinstance(item, dict):
            return {str(k): plain(v, depth + 1) for k, v in item.items()}
        if isinstance(item, (list, tuple)):
            return [plain(v, depth + 1) for v in item]
        if isinstance(item, (TypedArray, RegExp, HostObject)):
            return repr(item)
        if isinstance(item, float) and item != item:
            return 'NaN'
        if isinstance(item, int) and abs(item) > 2 ** 53:
            return str(item)
        return item
    text = json.dumps(plain(value), ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + '…'

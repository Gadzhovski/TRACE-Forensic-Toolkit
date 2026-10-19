"""Protocol Buffers read with no schema (no Qt, no dependency).

Apple keeps a growing share of its records as protobuf: Notes bodies
(gzip + protobuf), Biome (SEGB) payloads, parts of Screen Time and
CoreSpotlight. Without the .proto files a message is still readable as
(field number, wire type, value) triples: a varint, a 64- or 32-bit fixed
value, or a length-delimited run that is a string, bytes or a nested
message. Which of the three a run is cannot be known for certain; `parse`
calls it a message when it decodes whole as one (every tag valid, every
length inside the run), else text when it is valid UTF-8 with printable
characters, else bytes.

* `decode(data)` -> [(field, wire, value)] for one message; raises
  ProtobufError when the bytes are not a whole message.
* `parse(data)` -> {field: [values]} with nested messages parsed too
  (`Message`), the shape a reader walks with `first(message, 2, 3, 2)`.
* `strings(data)` -> every text value found anywhere, in order -- the
  generic reading of a payload nothing is known about.

Groups (wire types 3 and 4, deprecated since proto2) are refused: no Apple
format TRACE reads uses them, and refusing keeps a random byte run from
passing as a message.
"""

import struct

from trace_app.core.varint import uleb128

VARINT, FIXED64, LENGTH, START_GROUP, END_GROUP, FIXED32 = range(6)

#: Nested messages deeper than this are left as bytes.
MAX_DEPTH = 24
#: Field numbers above this are not plausible in a real message.
MAX_FIELD = (1 << 29) - 1


class ProtobufError(ValueError):
    """The bytes are not a protobuf message."""


def read_varint(data, pos):
    """(value, next position) of the base-128 varint at `pos`."""
    return uleb128(data, pos, ProtobufError)


def decode(data):
    """[(field, wire type, value)] of one whole message. A varint is an
    int, fixed values are their raw bytes, a length-delimited run bytes."""
    data = bytes(data)
    out = []
    pos, end = 0, len(data)
    while pos < end:
        key, pos = read_varint(data, pos)
        field, wire = key >> 3, key & 7
        if field == 0 or field > MAX_FIELD:
            raise ProtobufError(f"field number {field}")
        if wire == VARINT:
            value, pos = read_varint(data, pos)
        elif wire == FIXED64:
            if pos + 8 > end:
                raise ProtobufError("fixed64 runs past the end")
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == LENGTH:
            length, pos = read_varint(data, pos)
            if pos + length > end:
                raise ProtobufError("length runs past the end")
            value, pos = data[pos:pos + length], pos + length
        elif wire == FIXED32:
            if pos + 4 > end:
                raise ProtobufError("fixed32 runs past the end")
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ProtobufError(f"wire type {wire}")
        out.append((field, wire, value))
    return out


def is_message(data):
    """True when `data` decodes whole as a non-empty message."""
    if not data:
        return False
    try:
        return bool(decode(data))
    except ProtobufError:
        return False


def as_text(value):
    """`value` as text when it reads as UTF-8 of mostly printable
    characters, else None."""
    if not value:
        return None
    try:
        text = bytes(value).decode('utf-8')
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    return text if printable >= len(text) * 0.9 else None


class Message(dict):
    """{field number: [values]} -- nested messages are Messages, text is
    str, other runs bytes, varints int, fixed values their raw bytes."""


def parse(data, depth=0):
    """`data` as a Message; ProtobufError when it is not one."""
    message = Message()
    for field, wire, value in decode(data):
        if wire == LENGTH:
            value = _length_value(value, depth)
        message.setdefault(field, []).append(value)
    return message


def _length_value(value, depth):
    # A run that reads as text and as a message is usually text: short
    # ASCII strings decode as messages by accident far more often than
    # messages read as clean text.
    text = as_text(value)
    if text is not None and (len(value) < 2 or not _plainly_message(value)):
        return text
    if depth < MAX_DEPTH and is_message(value):
        try:
            return parse(value, depth + 1)
        except ProtobufError:
            pass
    return text if text is not None else bytes(value)


def _plainly_message(value):
    """A run is plainly a message when it decodes and holds something
    beyond a single tiny field -- a heuristic for the text/message tie."""
    try:
        fields = decode(value)
    except ProtobufError:
        return False
    if not fields:
        return False
    # Text bytes are mostly >= 0x20; a message's tags for fields 1-3 are
    # bytes 0x08-0x1D, which text rarely holds.
    return value[0] < 0x20


def first(message, *path):
    """The first value at a path of field numbers through nested
    Messages, or None: first(note, 2, 3, 2) is a Notes body's text."""
    value = message
    for field in path:
        if not isinstance(value, dict):
            return None
        values = value.get(field)
        if not values:
            return None
        value = values[0]
    return value


def strings(data, limit=200, min_length=2):
    """Every text value in a message and its nested messages, in order,
    up to `limit`. [] when `data` is not a message."""
    try:
        message = parse(data)
    except ProtobufError:
        return []
    out = []
    _collect(message, out, limit, min_length)
    return out


def _collect(message, out, limit, min_length):
    for field in sorted(message):
        for value in message[field]:
            if len(out) >= limit:
                return
            if isinstance(value, Message):
                _collect(value, out, limit, min_length)
            elif isinstance(value, str) and len(value.strip()) >= min_length:
                out.append(value.strip())


def fixed64_double(raw):
    """A fixed64 value read as a little-endian double."""
    return struct.unpack('<d', raw)[0]



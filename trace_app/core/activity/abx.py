"""Android Binary XML (ABX): how Android 12 and later write system settings
files -- packages.xml, WifiConfigStore.xml and others -- in place of text.

'ABX\\0', then tokens of one byte: the low four bits what it is (start /
end of document, start / end tag, text, attribute...), the high four its
data type (null, string, interned string, bytes as hex or base64, int,
int hex, long, long hex, float, double, true, false). Numbers are
big-endian; a string is a u16 length and UTF-8; an interned string is a
u16 index into the strings seen so far, 0xFFFF introducing a new one.
Per AOSP's BinaryXmlSerializer; checked against the ABX files CCL's
ccl_abx tests with, each with the XML it was written from.
"""

import base64
import struct
import xml.etree.ElementTree as ElementTree

MAGIC = b'ABX\x00'

START_DOCUMENT, END_DOCUMENT, START_TAG, END_TAG, TEXT = 0, 1, 2, 3, 4
CDSECT, ENTITY_REF, IGNORABLE_WHITESPACE = 5, 6, 7
PROCESSING_INSTRUCTION, COMMENT, DOCDECL, ATTRIBUTE = 8, 9, 10, 15

TYPE_NULL, TYPE_STRING, TYPE_STRING_INTERNED = 1, 2, 3
TYPE_BYTES_HEX, TYPE_BYTES_BASE64 = 4, 5
TYPE_INT, TYPE_INT_HEX, TYPE_LONG, TYPE_LONG_HEX = 6, 7, 8, 9
TYPE_FLOAT, TYPE_DOUBLE, TYPE_TRUE, TYPE_FALSE = 10, 11, 12, 13


class AbxError(ValueError):
    pass


class _Reader:
    def __init__(self, data):
        self.data, self.at = data, len(MAGIC)
        self.interned = []

    def take(self, size):
        if self.at + size > len(self.data):
            raise AbxError("ABX data ends inside a token")
        value = self.data[self.at:self.at + size]
        self.at += size
        return value

    def unpack(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self):
        return self.take(self.unpack('>H')).decode('utf-8', 'replace')

    def interned_string(self):
        index = self.unpack('>H')
        if index == 0xFFFF:
            value = self.string()
            self.interned.append(value)
            return value
        if index >= len(self.interned):
            raise AbxError("ABX names a string it has not defined")
        return self.interned[index]

    def value(self, kind):
        """A typed value, as the text XML would hold it."""
        if kind == TYPE_NULL:
            return None
        if kind == TYPE_STRING:
            return self.string()
        if kind == TYPE_STRING_INTERNED:
            return self.interned_string()
        if kind in (TYPE_BYTES_HEX, TYPE_BYTES_BASE64):
            raw = self.take(self.unpack('>H'))
            return raw.hex() if kind == TYPE_BYTES_HEX else \
                base64.b64encode(raw).decode('ascii')
        if kind == TYPE_INT:
            return str(self.unpack('>i'))
        if kind == TYPE_INT_HEX:
            return format(self.unpack('>i') & 0xFFFFFFFF, 'x')
        if kind == TYPE_LONG:
            return str(self.unpack('>q'))
        if kind == TYPE_LONG_HEX:
            return format(self.unpack('>q') & 0xFFFFFFFFFFFFFFFF, 'x')
        if kind == TYPE_FLOAT:
            return _number(_shortest_float(self.take(4)))
        if kind == TYPE_DOUBLE:
            return _number(self.unpack('>d'))
        if kind == TYPE_TRUE:
            return 'true'
        if kind == TYPE_FALSE:
            return 'false'
        raise AbxError(f"Unknown ABX data type {kind}")


def _shortest_float(raw):
    """A 32-bit float the way Java prints it: the fewest digits that read
    back as the same float (0.3, not 0.30000001192092896)."""
    value = struct.unpack('>f', raw)[0]
    for digits in range(1, 18):
        candidate = float(f'{value:.{digits}g}')
        if struct.pack('>f', candidate) == raw:
            return candidate
    return value


def _number(value):
    text = repr(value)
    return text[:-2] if text.endswith('.0') else text


def parse(data):
    """The document's root Element (xml.etree)."""
    if data[:4] != MAGIC:
        raise AbxError("Not Android binary XML")
    reader = _Reader(bytes(data))
    root, stack = None, []
    while reader.at < len(reader.data):
        token = reader.unpack('B')
        command, kind = token & 0x0F, token >> 4
        if command == START_DOCUMENT or command == END_DOCUMENT:
            if command == END_DOCUMENT:
                break
            continue
        if command == START_TAG:
            element = ElementTree.Element(reader.interned_string())
            if stack:
                stack[-1].append(element)
            elif root is None:
                root = element
            stack.append(element)
        elif command == END_TAG:
            name = reader.interned_string()
            if not stack or stack[-1].tag != name:
                raise AbxError(f"ABX closes <{name}> out of order")
            stack.pop()
        elif command == ATTRIBUTE:
            name = reader.interned_string()
            value = reader.value(kind)
            if not stack:
                raise AbxError("ABX attribute outside an element")
            if value is not None:
                stack[-1].set(name, value)
        elif command in (TEXT, CDSECT, ENTITY_REF, IGNORABLE_WHITESPACE):
            text = reader.value(kind) or ''
            if command == ENTITY_REF:
                text = {'amp': '&', 'lt': '<', 'gt': '>', 'quot': '"',
                        'apos': "'"}.get(text, f'&{text};')
            if command == IGNORABLE_WHITESPACE or not stack:
                continue
            element = stack[-1]
            if len(element):
                element[-1].tail = (element[-1].tail or '') + text
            else:
                element.text = (element.text or '') + text
        elif command in (PROCESSING_INSTRUCTION, COMMENT, DOCDECL):
            reader.value(kind)
        else:
            raise AbxError(f"Unknown ABX token {token:#x}")
    if root is None:
        raise AbxError("ABX holds no element")
    return root


def to_xml(data):
    """Text XML (bytes) of an ABX document."""
    return ElementTree.tostring(parse(data), encoding='utf-8')

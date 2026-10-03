"""Windows XML event logs (.evtx), read without a third-party library.

A log is a 4 KB header and 64 KB chunks. Each chunk holds event records
whose content is "binary XML": element and attribute names are kept once
per chunk, and each record is usually a reference to a template -- the
event's XML with numbered holes -- followed by the values for the holes.
Templates are parsed once per chunk and filled per record.

This reads what an examiner filters on: the event ID, its time, provider,
channel, computer, user SID, and the EventData/UserData fields by name. It
is checked record by record against python-evtx on real logs (see the
tests). A damaged chunk or record is skipped, not fatal: logs recovered from
a disk are often torn.
"""

import datetime
import struct

from trace_app.core.activity import times

CHUNK_SIZE = 65536
FILE_MAGIC = b'ElfFile\x00'
CHUNK_MAGIC = b'ElfChnk\x00'


class EvtxError(ValueError):
    """Not an event log this reader understands."""


class _Subst:
    __slots__ = ('index', 'optional')

    def __init__(self, index, optional):
        self.index, self.optional = index, optional


class Element:
    """One XML element: name, attributes and children (text or Element)."""
    __slots__ = ('name', 'attrs', 'children')

    def __init__(self, name):
        self.name = name
        self.attrs = []          # [(name, [parts])]
        self.children = []       # parts: str / Element / _Subst / value

    def find(self, name):
        for child in self.children:
            if isinstance(child, Element) and child.name == name:
                return child
        return None

    def elements(self):
        return [c for c in self.children if isinstance(c, Element)]

    def attr(self, name):
        for key, value in self.attrs:
            if key == name:
                return value
        return None

    def text(self):
        return ''.join(_text(part) for part in self.children
                       if not isinstance(part, Element))


def _text(value):
    if value is None:
        return ''
    if isinstance(value, list):
        return ', '.join(_text(v) for v in value)
    if isinstance(value, datetime.datetime):
        return times.iso(value)
    return str(value)


# --- values ----------------------------------------------------------------------

def _sid(raw):
    if len(raw) < 8:
        return raw.hex()
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], 'big')
    subs = struct.unpack_from(f'<{count}I', raw, 8) if len(raw) >= 8 + 4 * count \
        else ()
    return f"S-{revision}-{authority}" + ''.join(f'-{s}' for s in subs)


def _guid(raw):
    a, b, c = struct.unpack_from('<IHH', raw, 0)
    d = raw[8:16].hex().upper()
    return f'{{{a:08X}-{b:04X}-{c:04X}-{d[:4]}-{d[4:]}}}'


def _systemtime(raw):
    year, month, _dow, day, hour, minute, second, ms = struct.unpack_from(
        '<8H', raw, 0)
    try:
        return datetime.datetime(year, month, day, hour, minute, second,
                                 ms * 1000, tzinfo=times.UTC)
    except ValueError:
        return None


_FIXED = {0x03: '<b', 0x04: '<B', 0x05: '<h', 0x06: '<H', 0x07: '<i',
          0x08: '<I', 0x09: '<q', 0x0A: '<Q', 0x0B: '<f', 0x0C: '<d'}


def _decode(kind, raw, chunk, at):
    base = kind & 0x7F
    if kind & 0x80:                                     # array
        if base == 0x01:
            return [s for s in raw.decode('utf-16-le', 'replace').split('\x00')
                    if s]
        if base in _FIXED:
            form = _FIXED[base]
            width = struct.calcsize(form)
            return [struct.unpack_from(form, raw, i)[0]
                    for i in range(0, len(raw) - width + 1, width)]
        return raw.hex()
    if base == 0x00:
        return None
    if base == 0x01:
        return raw.decode('utf-16-le', 'replace').rstrip('\x00')
    if base == 0x02:
        return raw.decode('cp1252', 'replace').rstrip('\x00')
    if base in _FIXED:
        if len(raw) < struct.calcsize(_FIXED[base]):
            return None
        return struct.unpack_from(_FIXED[base], raw, 0)[0]
    if base == 0x0D:
        return bool(struct.unpack_from('<I', raw, 0)[0]) if len(raw) >= 4 \
            else None
    if base == 0x0E:
        return raw.hex().upper()
    if base == 0x0F:
        return _guid(raw) if len(raw) >= 16 else raw.hex()
    if base == 0x10:
        value = int.from_bytes(raw, 'little')
        return f'0x{value:x}'
    if base == 0x11:
        return times.filetime(struct.unpack_from('<Q', raw, 0)[0]) \
            if len(raw) >= 8 else None
    if base == 0x12:
        return _systemtime(raw) if len(raw) >= 16 else None
    if base == 0x13:
        return _sid(raw)
    if base == 0x14:
        return f'0x{struct.unpack_from("<I", raw, 0)[0]:08x}' \
            if len(raw) >= 4 else None
    if base == 0x15:
        return f'0x{struct.unpack_from("<Q", raw, 0)[0]:016x}' \
            if len(raw) >= 8 else None
    if base == 0x21:                                    # nested binary XML
        root = Element('')
        chunk.parse(at, root, at + len(raw))
        return root.elements()
    return raw.hex()


# --- a chunk -------------------------------------------------------------------------

class Chunk:
    def __init__(self, data):
        if data[:8] != CHUNK_MAGIC:
            raise EvtxError("bad chunk magic")
        self.data = data
        self._names = {}
        self._templates = {}

    def name(self, at):
        cached = self._names.get(at)
        if cached is None:
            count = struct.unpack_from('<H', self.data, at + 6)[0]
            cached = self.data[at + 8:at + 8 + 2 * count].decode(
                'utf-16-le', 'replace')
            self._names[at] = cached
        return cached

    def _name_ref(self, pos):
        """A name offset at `pos`; the name itself follows if it is defined
        here. Returns (name, position after)."""
        offset = struct.unpack_from('<I', self.data, pos)[0]
        pos += 4
        name = self.name(offset)
        if offset == pos:
            count = struct.unpack_from('<H', self.data, pos + 6)[0]
            pos += 8 + 2 * count + 2
        return name, pos

    def parse(self, pos, root, end=None):
        """Parse binary XML at `pos` into `root`; returns the end position."""
        data = self.data
        end = end if end is not None else len(data)
        stack = [root]
        attribute = None              # parts of the attribute being read
        while pos < end:
            token = data[pos]
            kind = token & 0x0F
            if token == 0x00:                           # end of fragment
                return pos + 1
            if kind == 0x0F:                            # fragment header
                pos += 4
            elif kind == 0x01:                          # open element
                pos += 1 + 2 + 4                # token, dependency, size
                name, pos = self._name_ref(pos)
                if token & 0x40:
                    pos += 4                    # attribute list size
                element = Element(name)
                stack[-1].children.append(element)
                stack.append(element)
                attribute = None
            elif kind == 0x02:                          # close start tag
                attribute = None
                pos += 1
            elif kind in (0x03, 0x04):                  # close element
                attribute = None
                if len(stack) > 1:
                    stack.pop()
                pos += 1
                if len(stack) == 1 and root.children:
                    # The root element closed: the fragment is over.
                    if pos < end and data[pos] == 0x00:
                        pos += 1
                    return pos
            elif kind == 0x06:                          # attribute
                name, pos = self._name_ref(pos + 1)
                attribute = []
                stack[-1].attrs.append((name, attribute))
            elif kind == 0x05:                          # value text
                value_type = data[pos + 1]
                if value_type == 0x01:
                    count = struct.unpack_from('<H', data, pos + 2)[0]
                    text = data[pos + 4:pos + 4 + 2 * count].decode(
                        'utf-16-le', 'replace')
                    pos += 4 + 2 * count
                else:
                    raise EvtxError(f"value type {value_type:#x} in text")
                (attribute if attribute is not None
                 else stack[-1].children).append(text)
            elif kind in (0x0D, 0x0E):                  # substitution
                index = struct.unpack_from('<H', data, pos + 1)[0]
                (attribute if attribute is not None
                 else stack[-1].children).append(_Subst(index, kind == 0x0E))
                pos += 4
            elif kind == 0x0C:                          # template instance
                pos = self._template_instance(pos, stack[-1])
            elif kind == 0x07:                          # CDATA
                count = struct.unpack_from('<H', data, pos + 1)[0]
                stack[-1].children.append(data[pos + 3:pos + 3 + 2 * count]
                                          .decode('utf-16-le', 'replace'))
                pos += 3 + 2 * count
            elif kind == 0x08:                          # character reference
                (attribute if attribute is not None else stack[-1].children
                 ).append(chr(struct.unpack_from('<H', data, pos + 1)[0]))
                pos += 3
            elif kind == 0x09:                          # entity reference
                name, pos = self._name_ref(pos + 1)
                (attribute if attribute is not None else stack[-1].children
                 ).append({'amp': '&', 'lt': '<', 'gt': '>', 'quot': '"',
                           'apos': "'"}.get(name, f'&{name};'))
            elif kind in (0x0A, 0x0B):                  # processing instr.
                if kind == 0x0A:
                    _name, pos = self._name_ref(pos + 1)
                else:
                    count = struct.unpack_from('<H', data, pos + 1)[0]
                    pos += 3 + 2 * count
            else:
                raise EvtxError(f"unknown token {token:#x} at {pos}")
        return pos

    def _template(self, offset):
        """The template defined at `offset`, parsed once per chunk."""
        template = self._templates.get(offset)
        if template is None:
            size = struct.unpack_from('<I', self.data, offset + 20)[0]
            template = Element('')
            self.parse(offset + 24, template, offset + 24 + size)
            self._templates[offset] = template
        return template

    def _template_instance(self, pos, parent):
        data = self.data
        definition = struct.unpack_from('<I', data, pos + 6)[0]
        pos += 10
        template = self._template(definition)
        if definition == pos:           # defined here: skip past it
            size = struct.unpack_from('<I', data, pos + 20)[0]
            pos += 24 + size
        count = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        sizes = []
        for index in range(count):
            size, kind = struct.unpack_from('<HB', data, pos + 4 * index)
            sizes.append((size, kind))
        pos += 4 * count
        values = []
        for size, kind in sizes:
            values.append(_decode(kind, data[pos:pos + size], self, pos)
                          if size else None)
            pos += size
        for element in template.elements():
            parent.children.append(_fill(element, values))
        return pos


def _fill(element, values):
    """A copy of a template element with its holes filled."""
    out = Element(element.name)
    for name, parts in element.attrs:
        filled = _fill_parts(parts, values)
        if filled is not None:
            out.attrs.append((name, filled))
    for part in element.children:
        if isinstance(part, Element):
            out.children.append(_fill(part, values))
        elif isinstance(part, _Subst):
            value = values[part.index] if part.index < len(values) else None
            if isinstance(value, list) and value and \
                    isinstance(value[0], Element):
                out.children.extend(value)
            elif value is not None or not part.optional:
                out.children.append(value)
        else:
            out.children.append(part)
    return out


def _fill_parts(parts, values):
    out = []
    for part in parts:
        if isinstance(part, _Subst):
            value = values[part.index] if part.index < len(values) else None
            if value is None and part.optional:
                return None if len(parts) == 1 else out
            out.append(value)
        else:
            out.append(part)
    return out


# --- records --------------------------------------------------------------------------

def _first(parts):
    if parts is None:
        return None
    for part in parts:
        if part is not None and part != '':
            return part
    return None


def summarise(record_id, written, root):
    """The facts of one event, from its parsed XML."""
    event = root.find('Event') or (root.elements()[0] if root.elements()
                                   else None)
    out = {'record_id': record_id, 'written': written, 'event_id': None,
           'provider': '', 'channel': '', 'computer': '', 'user_sid': '',
           'time': written, 'data': {}}
    if event is None:
        return out
    system = event.find('System')
    if system is not None:
        for child in system.elements():
            if child.name == 'EventID':
                try:
                    out['event_id'] = int(child.text() or 0)
                except ValueError:
                    pass
            elif child.name == 'Provider':
                out['provider'] = _text(_first(child.attr('Name'))) or \
                    _text(_first(child.attr('EventSourceName')))
            elif child.name == 'Channel':
                out['channel'] = child.text()
            elif child.name == 'Computer':
                out['computer'] = child.text()
            elif child.name == 'Security':
                out['user_sid'] = _text(_first(child.attr('UserID')))
            elif child.name == 'TimeCreated':
                stamp = _first(child.attr('SystemTime'))
                if isinstance(stamp, datetime.datetime):
                    out['time'] = stamp
    data = out['data']
    event_data = event.find('EventData')
    if event_data is not None:
        unnamed = 0
        for item in event_data.elements():
            name = _text(_first(item.attr('Name')))
            if not name:
                name = f'Data{unnamed}' if item.name == 'Data' else item.name
                unnamed += 1
            data[name] = item.text()
    user_data = event.find('UserData')
    if user_data is not None:
        def leaves(element):
            for child in element.elements():
                if child.elements():
                    leaves(child)
                else:
                    data[child.name] = child.text()
        leaves(user_data)
    return out


def records(data):
    """Every readable event in a log, as summarise() dicts, oldest chunk
    first. Damaged chunks and records are skipped."""
    if data[:8] != FILE_MAGIC:
        raise EvtxError("not an EVTX file")
    header_size = struct.unpack_from('<H', data, 40)[0] or 4096
    position = 4096 if header_size <= 4096 else header_size
    while position + 512 <= len(data):
        block = data[position:position + CHUNK_SIZE]
        position += CHUNK_SIZE
        if block[:8] != CHUNK_MAGIC:
            continue
        try:
            chunk = Chunk(block)
        except EvtxError:
            continue
        free = struct.unpack_from('<I', block, 48)[0]
        at = 512
        limit = min(free or len(block), len(block))
        while at + 24 <= limit:
            if block[at:at + 4] != b'\x2a\x2a\x00\x00':
                break
            size = struct.unpack_from('<I', block, at + 4)[0]
            if size < 28 or at + size > len(block):
                break
            record_id, written = struct.unpack_from('<QQ', block, at + 8)
            root = Element('')
            try:
                chunk.parse(at + 24, root, at + size - 4)
                yield summarise(record_id, times.filetime(written), root)
            except (EvtxError, struct.error, IndexError, KeyError,
                    UnicodeDecodeError, RecursionError):
                pass
            at += size

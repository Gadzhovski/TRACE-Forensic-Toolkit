"""Apple's unified log (macOS 10.12+, iOS 10+): .tracev3 files, read in
Python (no Qt).

What `log show` prints comes from three kinds of file:

* tracev3 (/private/var/db/diagnostics/{Persist,Special,Signpost,
  HighVolume}/*.tracev3, or a .logarchive's): a header chunk, then
  catalogs (the processes, their image UUIDs and subsystem strings) and
  LZ4-compressed chunksets of firehose chunks -- one per process, each a
  run of tracepoints: log, activity, trace, signpost and loss records,
  with the message's arguments, not the message. Oversize chunks carry
  arguments too big for a tracepoint; simpledump and statedump chunks
  carry whole messages.
* uuidtext (/private/var/db/uuidtext/XX/YYYY...) and dsc (.../dsc/UUID):
  the format strings, found by the tracepoint's string reference in the
  image (main executable, an absolute load address, or the shared cache)
  the flags name.
* timesync (/private/var/db/diagnostics/timesync/*.timesync): per boot,
  the timebase and pairs of continuous (mach) time and wall-clock time --
  a tracepoint's continuous time becomes a UTC time from the latest pair
  at or before it.

The message is the format string with its printf-style operators
(%{public}s, %d, %{bool}d, %{errno}d, %{private}@ ...) filled from the
arguments: strings from the public or private data ranges, numbers
inline; an argument the system did not record is '<private>'.

The layout follows libyal's documentation (dtformats, "Apple Unified
Logging and Activity Tracing formats") and plaso's parser, whose tests'
values on its unified_logging1.dmg are what tests/test_unified_log.py
checks: every entry counted, messages and times as plaso gives them.
Decoders for Apple's private types (location, mDNS, OpenDirectory...)
are not rendered: their arguments read '<decode: unsupported decoder:
name>', as plaso writes it for those it lacks.
"""

import datetime
import logging
import re
import struct
import uuid as uuid_module

from trace_app.core.activity import journal

logger = logging.getLogger('TRACE.Activity.UnifiedLog')

UTC = datetime.timezone.utc


class UnifiedLogError(Exception):
    pass


def _uuid(data, offset=0):
    return str(uuid_module.UUID(bytes=bytes(data[offset:offset + 16]))) \
        .upper()


def _cstring(data, offset):
    end = data.find(b'\0', offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode('utf-8', 'replace')


def _aligned(offset):
    return offset + (-offset % 8)


# --- string files -----------------------------------------------------------------

class UuidText:
    """A uuidtext file: format strings by offset, and the image's path."""

    def __init__(self, data):
        if data[:4] != b'\x99\x88\x77\x66':
            raise UnifiedLogError("Not a uuidtext file")
        major, minor, count = struct.unpack_from('<III', data, 4)
        if (major, minor) != (2, 1):
            raise UnifiedLogError(f"uuidtext version {major}.{minor}")
        self.data = data
        self.ranges = []
        position = 16 + count * 8
        for index in range(count):
            offset, size = struct.unpack_from('<II', data, 16 + index * 8)
            self.ranges.append((offset, size, position))
            position += size
        self.path = _cstring(data, position) if position < len(data) else ''

    def string(self, reference):
        for offset, size, position in self.ranges:
            if offset <= reference <= offset + size:
                return _cstring(self.data, position + reference - offset)
        return None


class Dsc:
    """A shared-cache strings file: ranges of format strings, each in one
    image of the shared cache."""

    def __init__(self, data):
        if data[:4] != b'hcsd':
            raise UnifiedLogError("Not a dsc file")
        major, _minor, ranges, uuids = struct.unpack_from('<HHII', data, 4)
        if major not in (1, 2):
            raise UnifiedLogError(f"dsc version {major}")
        self.data = data
        position = 16
        raw_ranges = []
        for _ in range(ranges):
            if major == 1:
                index, range_offset, data_offset, size = struct.unpack_from(
                    '<IIII', data, position)
                position += 16
            else:
                range_offset, data_offset, size, index = struct.unpack_from(
                    '<QIIQ', data, position)
                position += 24
            raw_ranges.append((index, range_offset, data_offset, size))
        self.images = []
        for _ in range(uuids):
            if major == 1:
                text_offset, text_size = struct.unpack_from('<II', data,
                                                            position)
                identifier = _uuid(data, position + 8)
                path_offset = struct.unpack_from('<I', data,
                                                 position + 24)[0]
                position += 28
            else:
                text_offset, text_size = struct.unpack_from('<QI', data,
                                                            position)
                identifier = _uuid(data, position + 12)
                path_offset = struct.unpack_from('<I', data,
                                                 position + 28)[0]
                position += 32
            self.images.append((text_offset, text_size, identifier,
                                _cstring(data, path_offset)))
        self.ranges = [(range_offset, size, data_offset) + self.images[index]
                       for index, range_offset, data_offset, size in
                       raw_ranges if index < len(self.images)]

    def lookup(self, reference, dynamic):
        """(format string, image UUID, image path, text offset) or None."""
        for range_offset, size, data_offset, text_offset, text_size, \
                identifier, path in self.ranges:
            start, length = (text_offset, text_size) if dynamic else \
                (range_offset, size)
            if start <= reference <= start + length:
                string = '%s' if dynamic else \
                    _cstring(self.data, data_offset + reference - start)
                return string, identifier, path, text_offset
        return None


class Strings:
    """The uuidtext and dsc files beside the logs, read on first use.
    `read(*parts)` returns a file's bytes under the uuidtext folder, or
    None."""

    def __init__(self, read):
        self._read = read
        self._uuidtext, self._dsc = {}, {}

    def uuidtext(self, identifier):
        if identifier not in self._uuidtext:
            name = identifier.replace('-', '')     # files: hex, no dashes
            data = self._read(name[:2], name[2:])
            try:
                self._uuidtext[identifier] = UuidText(data) if data else None
            except (UnifiedLogError, struct.error):
                self._uuidtext[identifier] = None
        return self._uuidtext[identifier]

    def dsc(self, identifier):
        if identifier not in self._dsc:
            data = self._read('dsc', identifier.replace('-', ''))
            try:
                self._dsc[identifier] = Dsc(data) if data else None
            except (UnifiedLogError, struct.error):
                self._dsc[identifier] = None
        return self._dsc[identifier]


# --- time ---------------------------------------------------------------------------

class Timesync:
    """Every boot's timebase and (continuous time, wall time) pairs, from
    the .timesync files."""

    def __init__(self, files):
        self.boots = {}
        for data in files:
            current = None
            position = 0
            while position + 4 <= len(data):
                signature, size = struct.unpack_from('<2sH', data, position)
                if size < 4:
                    break
                if signature == b'\xb0\xbb' and position + 48 <= len(data):
                    boot = _uuid(data, position + 8)
                    numerator, denominator, wall = struct.unpack_from(
                        '<IIq', data, position + 24)
                    current = self.boots.setdefault(boot, {
                        'timebase': numerator / (denominator or 1),
                        'wall': wall, 'syncs': []})
                elif signature == b'Ts' and current is not None and \
                        position + 32 <= len(data):
                    kernel, wall = struct.unpack_from('<Qq', data,
                                                      position + 8)
                    current['syncs'].append((kernel, wall))
                elif signature not in (b'\xb0\xbb', b'Ts'):
                    break
                position += size
        for boot in self.boots.values():
            boot['syncs'].sort(reverse=True)


# --- format strings ----------------------------------------------------------------

_OPERATOR = re.compile(
    r'(%(?:\{([^}]{1,128})\})?([-+0 #]{0,5})([0-9]+|\*)?'
    r'(\.(?:|[0-9]+|\*))?(?:hh|h|j|ll|l|L|t|q|z)?'
    r'([@aAcCdDeEfFgGimnoOpPsSuUxX])|%%)')
_IGNORED_DECODERS = ('', 'bluetooth:OI_STATUS', 'private', 'public',
                     'sensitive', 'xcode:size-in-bytes')
_INTERNAL = {'@': 's', 'P': 's', 's': 's', 'a': 'f', 'A': 'f', 'e': 'f',
             'E': 'f', 'f': 'f', 'F': 'f', 'g': 'f', 'G': 'f', 'd': 'i',
             'D': 'i', 'i': 'i', 'm': 'm', 'c': 'u', 'o': 'u', 'O': 'u',
             'p': 'u', 'u': 'u', 'U': 'u', 'x': 'u', 'X': 'u'}
_PYTHON = {'@': 's', 'a': 'f', 'A': 'f', 'C': 'c', 'D': 'd', 'i': 'd',
           'm': 'd', 'O': 'o', 'p': 'x', 'P': 's', 'S': 's', 'u': 'd',
           'U': 'd'}

#: macOS's errno texts (sys/errno.h), which %m and %{errno}d name.
_ERRNO = (
    'Undefined error: 0', 'Operation not permitted',
    'No such file or directory', 'No such process',
    'Interrupted system call', 'Input/output error', 'Device not configured',
    'Argument list too long', 'Exec format error', 'Bad file descriptor',
    'No child processes', 'Resource deadlock avoided',
    'Cannot allocate memory', 'Permission denied', 'Bad address',
    'Block device required', 'Resource busy', 'File exists',
    'Cross-device link', 'Operation not supported by device',
    'Not a directory', 'Is a directory', 'Invalid argument',
    'Too many open files in system', 'Too many open files',
    'Inappropriate ioctl for device', 'Text file busy', 'File too large',
    'No space left on device', 'Illegal seek', 'Read-only file system',
    'Too many links', 'Broken pipe', 'Numerical argument out of domain',
    'Result too large', 'Resource temporarily unavailable',
    'Operation now in progress', 'Operation already in progress',
    'Socket operation on non-socket', 'Destination address required',
    'Message too long', 'Protocol wrong type for socket',
    'Protocol not available', 'Protocol not supported',
    'Socket type not supported', 'Operation not supported',
    'Protocol family not supported',
    'Address family not supported by protocol family',
    'Address already in use', "Can't assign requested address",
    'Network is down', 'Network is unreachable',
    'Network dropped connection on reset',
    'Software caused connection abort', 'Connection reset by peer',
    'No buffer space available', 'Socket is already connected',
    'Socket is not connected', "Can't send after socket shutdown",
    "Too many references: can't splice", 'Operation timed out',
    'Connection refused', 'Too many levels of symbolic links',
    'File name too long', 'Host is down', 'No route to host',
    'Directory not empty', 'Too many processes', 'Too many users',
    'Disc quota exceeded', 'Stale NFS file handle')


def _errno(number):
    return _ERRNO[number] if 0 <= number < len(_ERRNO) else \
        f"Unknown error: {number}"


class Operator:
    """One printf operator: how its argument is decoded and laid out."""

    __slots__ = ('decoder', 'flags', 'width', 'precision', 'specifier',
                 '_python')

    def __init__(self, decoder, flags, width, precision, specifier):
        self.decoder, self.flags, self.width = decoder, flags, width
        self.precision, self.specifier = precision, specifier
        self._python = None

    def python(self):
        """The str.format spec printf's operator corresponds to."""
        if self._python is None:
            flags, precision = self.flags or '', self.precision or ''
            width = self.width or ''
            kind = _PYTHON.get(self.specifier, self.specifier)
            if self.specifier == 'd' and width and precision:
                flags = '0'
            if self.specifier == 'P':
                precision = ''
            elif precision == '.':
                precision = '.0'
            elif precision == '.*':
                precision = ''
            if width == '*':
                width = ''
            if kind in ('d', 'o', 'x', 'X'):
                flags, precision = flags.replace('-', '<'), ''
            elif kind == 's':
                flags = '>' if width and not flags else \
                    flags.replace('-', '<')
                if precision == '.0':
                    precision = ''
            elif kind == 'c':
                flags, precision = flags.replace('-', '<'), ''
            flags = flags.replace('#', '#' if kind in ('x', 'X', 'o')
                                  else '')
            spec = f"{{0:{flags}{precision}{width}{kind}}}"
            self._python = '0x' + spec if self.specifier == 'p' else spec
        return self._python


class Format:
    """A parsed format string: its literal text and operators."""

    def __init__(self, text):
        self.operators = []
        self.template = None
        if text is None:
            return
        pieces, last = [], 0
        for match in _OPERATOR.finditer(text):
            literal, decoder, flags, width, precision, specifier = \
                match.groups()
            start, end = match.span()
            pieces.append(text[last:start].replace('{', '{{')
                          .replace('}', '}}'))
            last = end
            if literal == '%%':
                pieces.append('%')
                continue
            names = [n.strip() for n in (decoder or '').split(',')]
            names = [n for n in names if n not in _IGNORED_DECODERS
                     and not n.startswith('name=')]
            name = names[0] if names else \
                f"internal:{_INTERNAL.get(specifier, '')}"
            pieces.append(f"{{{len(self.operators)}}}")
            self.operators.append(Operator(name, flags or None, width,
                                           precision, specifier))
        pieces.append(text[last:].replace('{', '{{').replace('}', '}}'))
        self.template = ''.join(pieces)

    def render(self, values):
        if self.template is None:
            return ''
        values = list(values) + ['<decode: missing data>'] * (
            len(self.operators) - len(values))
        try:
            return self.template.format(*values)
        except (IndexError, ValueError, KeyError):
            return self.template


def decode(operator, value):
    """One argument as `log show` writes it."""
    name = operator.decoder if operator else 'internal:s'
    if value is None:
        return '<decode: missing data>'
    value = bytes(value)
    try:
        if name == 'internal:s':
            if not value:
                return '(null)'
            try:
                text = value.decode('utf-8').rstrip('\0')
            except UnicodeDecodeError:
                return '<decode: unsupported value>'
            return operator.python().format(text) if operator else text
        if name in ('internal:i', 'internal:u'):
            if len(value) not in (1, 2, 4, 8):
                return '<decode: unsupported value>'
            number = int.from_bytes(value, 'little',
                                    signed=name == 'internal:i')
            if operator and operator.specifier == 'x' and \
                    operator.flags == '#' and number == 0:
                return '0'
            if operator and operator.specifier == 'c':
                return chr(number & 0xff)
            return operator.python().format(number) if operator else \
                str(number)
        if name == 'internal:f':
            if len(value) not in (4, 8):
                return '<decode: unsupported value>'
            number = struct.unpack('<f' if len(value) == 4 else '<d',
                                   value)[0]
            return operator.python().format(number) if operator else \
                f"{number:f}"
        if name in ('internal:m', 'errno', 'darwin.errno'):
            if len(value) != 4:
                return '<decode: unsupported value>'
            number = int.from_bytes(value, 'little')
            return _errno(number) if name == 'internal:m' else \
                f"[{number}: {_errno(number)}]"
        if name in ('bool', 'BOOL'):
            truth = int.from_bytes(value, 'little') != 0
            return ('true' if truth else 'false') if name == 'bool' else \
                ('YES' if truth else 'NO')
        if name == 'time_t':
            seconds = int.from_bytes(value, 'little')
            return datetime.datetime.fromtimestamp(seconds, UTC).strftime(
                '%Y-%m-%d %H:%M:%S')
        if name == 'uuid_t' and len(value) == 16:
            return _uuid(value)
        if name in ('in_addr', 'network:in_addr') and len(value) == 4:
            return '.'.join(str(b) for b in value)
        if name in ('in6_addr', 'network:in6_addr') and len(value) == 16:
            return ':'.join(f"{value[i] << 8 | value[i + 1]:04x}"
                            for i in range(0, 16, 2))
        if name in ('sockaddr', 'network:sockaddr'):
            if not value:
                return '<NULL>'
            if len(value) == 16 and value[1] == 2:
                return '.'.join(str(b) for b in value[4:8])
            if len(value) == 28 and value[1] == 30:
                parts = [value[i] << 8 | value[i + 1]
                         for i in range(8, 24, 2)]
                text = ':'.join(f"{p:04x}" if p else '' for p in parts)
                return '::' if text == ':::::::' else text
            return '<decode: unsupported value>'
        if name == 'mask.hash':
            import base64
            return "<mask.hash: " + (f"'{base64.b64encode(value).decode()}'"
                                     if value else '(null)') + ">"
    except (struct.error, ValueError, OverflowError, OSError):
        return '<decode: unsupported value>'
    return f"<decode: unsupported decoder: {name}>"


# --- tracev3 ------------------------------------------------------------------

LOG_TYPES = {0x00: 'Default', 0x01: 'Info', 0x02: 'Debug',
             0x03: 'Useraction', 0x10: 'Error', 0x11: 'Fault'}
EVENT_TYPES = {0x02: 'activityCreateEvent', 0x03: 'traceEvent',
               0x04: 'logEvent', 0x06: 'signpostEvent', 0x07: 'lossEvent'}

_RANGE_TYPES = (0x20, 0x21, 0x22, 0x30, 0x32, 0x40, 0x41, 0x42, 0xf2)
_STRING_TYPES = (0x20, 0x22, 0x40, 0x42)
_PRIVATE_STRING_TYPES = (0x21, 0x41)
_BINARY_TYPES = (0x30, 0x32, 0xf2)
_PRIVATE_TYPES = (0x01, 0x21, 0x25, 0x31, 0x35, 0x41, 0x45)


class _Process:
    __slots__ = ('pid', 'euid', 'main', 'dsc', 'images', 'subsystems')


class TraceV3:
    """One tracev3 file. `entries(want)` yields each entry as a dict;
    `want(process_path, subsystem, format_string)`, when given, is asked
    before the arguments are decoded, so a whole system's logs can be
    searched without rendering every message."""

    def __init__(self, data, strings, timesync=None):
        self.data = data
        self.strings = strings
        self.timesync = timesync
        tag, _sub, size = struct.unpack_from('<IIQ', data, 0)
        if tag != 0x1000 or size < 40:
            raise UnifiedLogError("Not a tracev3 file (no header chunk)")
        numerator, denominator, _start, seconds = struct.unpack_from(
            '<IIQi', data, 16)
        self.header_timebase = numerator / (denominator or 1)
        self.header_wall = seconds * 1_000_000_000
        # The sub-chunks (continuous time, system, generation, time zone)
        # are walked by their own sizes: the boot is in generation, 0x6102.
        self.boot = None
        position = 16 + 40
        while position + 8 <= 16 + size:
            sub_tag, sub_size = struct.unpack_from('<II', data, position)
            if sub_tag == 0x6102 and sub_size >= 16:
                self.boot = _uuid(data, position + 8)
                break
            if not sub_size:
                break
            position += 8 + sub_size
        self.start = _aligned(16 + size)
        boot = (timesync.boots.get(self.boot) if timesync else None) or {}
        self.timebase = boot.get('timebase', self.header_timebase)
        self.boot_wall = boot.get('wall')
        self.syncs = boot.get('syncs', [])
        self._catalog = {}
        self._uuids = []
        self._strings = {}
        self._formats = {}
        self._image_paths = {}
        self._processes = None
        self.undecoded = 0

    # -- time --

    def time_ns(self, continuous):
        """Nanoseconds since 1970 for a continuous (mach) time."""
        for kernel, wall in self.syncs:
            if continuous >= kernel:
                return wall + int((continuous - kernel) * self.timebase)
        if self.boot_wall is not None:
            return self.boot_wall + int(continuous * self.timebase)
        return self.header_wall + int(continuous * self.header_timebase)

    @staticmethod
    def as_datetime(nanoseconds):
        return datetime.datetime(1970, 1, 1, tzinfo=UTC) + \
            datetime.timedelta(microseconds=nanoseconds // 1000)

    # -- catalog --

    def _read_catalog(self, data):
        strings_at, processes_at, process_count, _sub_at, _sub_count = \
            struct.unpack_from('<HHHHH', data, 0)
        self._uuids = [_uuid(data, 24 + i) for i in range(0, strings_at, 16)]
        block = data[24 + strings_at:24 + processes_at]
        self._strings, offset = {}, 0
        for text in block.split(b'\0'):
            self._strings[offset] = text.decode('utf-8', 'replace')
            offset += len(text) + 1
        position = 24 + processes_at
        self._catalog = {}
        for _ in range(process_count):
            start = position
            (_index, _u, main, dsc, upper, lower, pid, euid, _u2,
             count, _u3) = struct.unpack_from('<HHhhQIIIIII', data, position)
            position += 40
            process = _Process()
            process.pid, process.euid = pid, euid
            process.main = self._uuids[main] if 0 <= main < len(
                self._uuids) else None
            process.dsc = self._uuids[dsc] if 0 <= dsc < len(
                self._uuids) else None
            process.images = []
            for _ in range(count):
                size, _u4, index, low, high = struct.unpack_from(
                    '<IIHIH', data, position)
                position += 16
                if index < len(self._uuids):
                    process.images.append((high, low, size,
                                           self._uuids[index]))
            subsystem_count = struct.unpack_from('<I', data, position)[0]
            position += 8
            process.subsystems = {}
            for _ in range(subsystem_count):
                identifier, subsystem, category = struct.unpack_from(
                    '<HHH', data, position)
                position += 6
                process.subsystems[identifier] = (
                    self._strings.get(subsystem),
                    self._strings.get(category))
            position = start + _aligned(position - start)
            self._catalog[(upper, lower)] = process

    # -- strings --

    def _image_path(self, identifier):
        if identifier not in self._image_paths:
            text = self.strings.uuidtext(identifier) if identifier else None
            self._image_paths[identifier] = text.path if text else None
        return self._image_paths[identifier]

    def _format(self, process, flags, fields, reference, dynamic):
        """(format string, sender image UUID, sender path) or None."""
        kind = flags & 0x000e
        identifier = None
        if kind == 0x0002:
            identifier = process.main
        elif kind in (0x0004, 0x000c):
            identifier = process.dsc
        elif kind == 0x0008:
            upper = fields.get('load_upper') or 0
            lower = fields.get('load_lower', 0)
            for high, low, size, image in process.images:
                if high == upper and low <= lower <= low + size:
                    identifier = image
                    break
            if identifier is None:
                return None
        elif kind == 0x000a:
            identifier = fields.get('uuidtext')
        else:
            return None
        if identifier is None:
            return None
        key = (identifier, reference, dynamic, kind)
        if key in self._formats:
            return self._formats[key]
        found = None
        if kind in (0x0002, 0x0008, 0x000a):
            text = self.strings.uuidtext(identifier)
            if text is not None:
                found = ('%s' if dynamic else text.string(reference),
                         identifier, text.path)
            else:
                found = (None, identifier, None)
        else:
            dsc = self.strings.dsc(identifier)
            hit = dsc.lookup(reference, dynamic) if dsc else None
            found = (hit[0], hit[1], hit[2]) if hit else \
                (None, identifier, None)
        if len(self._formats) > 20000:
            self._formats.clear()
        self._formats[key] = found
        return found

    # -- reading --

    def chunks(self):
        """(tag, data) of every top-level chunk after the header."""
        position = self.start
        while position + 16 <= len(self.data):
            tag, _sub, size = struct.unpack_from('<IIQ', self.data,
                                                 position)
            body = self.data[position + 16:position + 16 + size]
            yield tag, body
            position = _aligned(position + 16 + size)

    def entries(self, want=None, processes=None):
        """Every entry, in file order. `processes(path)`, when given,
        is asked once per firehose chunk -- each holds one process's
        tracepoints -- and a chunk it refuses is not read at all."""
        oversize = {}
        self._processes = processes
        for tag, body in self.chunks():
            if tag == 0x600b:
                self._read_catalog(body)
            elif tag == 0x600d:
                yield from self._chunkset(body, oversize, want)

    def _wanted_process(self, path):
        return self._processes is None or self._processes(path)

    def _chunkset(self, body, oversize, want):
        signature = body[:4]
        if signature == b'bv41':
            size, packed = struct.unpack_from('<II', body, 4)
            data = bytes(journal.lz4_block(body[12:12 + packed], size))
        elif signature == b'bv4-':
            size = struct.unpack_from('<I', body, 4)[0]
            data = body[8:8 + size]
        else:
            raise UnifiedLogError("Chunkset without an LZ4 block")
        position = 0
        while position + 16 <= len(data):
            tag, _sub, length = struct.unpack_from('<IIQ', data, position)
            chunk = data[position + 16:position + 16 + length]
            if tag == 0x6001:
                yield from self._firehose(chunk, oversize, want)
            elif tag == 0x6002:
                self._oversize(chunk, oversize)
            elif tag == 0x6004:
                entry = self._simpledump(chunk)
                if entry is not None and \
                        self._wanted_process(entry['process']) and \
                        (want is None or want(
                        entry['process'], entry['subsystem'],
                        entry['message'])):
                    yield entry
            elif tag == 0x6003:
                entry = self._statedump(chunk)
                if entry is not None and want is None:
                    yield entry
            position = _aligned(position + 16 + length)

    @staticmethod
    def _items(data, position, count):
        items = []
        for _ in range(count):
            kind, size = data[position], data[position + 1]
            position += 2
            if kind in _RANGE_TYPES and size == 4:
                offset, length = struct.unpack_from('<HH', data, position)
                items.append((kind, None, offset, length))
            else:
                items.append((kind, data[position:position + size], None,
                              None))
            position += size
        return items, position

    def _oversize(self, chunk, oversize):
        upper, lower = struct.unpack_from('<QI', chunk, 0)
        reference, size, private_size = struct.unpack_from('<IHH', chunk,
                                                           24)
        count = chunk[33]
        items, position = self._items(chunk, 34, count)
        values = chunk[position:position + size]
        private = chunk[position + size:position + size + private_size]
        oversize[(upper, lower, reference)] = (items, values, private)

    def _firehose(self, chunk, oversize, want):
        upper, lower = struct.unpack_from('<QI', chunk, 0)
        public_size, private_offset = struct.unpack_from('<HH', chunk, 16)
        base = struct.unpack_from('<Q', chunk, 24)[0]
        process = self._catalog.get((upper, lower))
        if process is None:
            raise UnifiedLogError(f"Process {upper}@{lower} not in the "
                                  f"catalog")
        process_path = self._image_path(process.main)
        if not self._wanted_process(process_path):
            return
        private_offset &= 0x0fff
        private = chunk[-(4096 - private_offset):] if private_offset \
            else b''
        position = 32
        # public_data_size counts from offset 16, past the proc id: read
        # to it from the chunk's start, 70 of Persist's 83,000 are lost.
        while position + 24 <= 16 + public_size:
            record, log_type, flags, reference, thread, low, high, size = \
                struct.unpack_from('<BBHIQIHH', chunk, position)
            data = chunk[position + 24:position + 24 + size]
            position = _aligned(position + 24 + size)
            if record == 0:
                continue
            continuous = base + (low | high << 32)
            try:
                entry = self._tracepoint(record, log_type, flags,
                                         reference, thread, continuous,
                                         data, process, process_path,
                                         private, private_offset,
                                         oversize, (upper, lower), want)
            except (struct.error, IndexError) as exc:
                self.undecoded += 1
                logger.debug("Tracepoint not decoded: %s", exc)
                continue
            if entry is not None:
                yield entry

    def _tracepoint(self, record, log_type, flags, reference, thread,
                    continuous, data, process, process_path, private,
                    private_offset, oversize, proc_id, want):
        fields = {}
        position = 0
        kind = flags & 0x000e

        def u(fmt):
            nonlocal position
            value = struct.unpack_from(fmt, data, position)
            position += struct.calcsize(fmt)
            return value[0]

        base = {'time_ns': self.time_ns(continuous), 'boot': self.boot,
                'thread': thread, 'pid': process.pid, 'euid': process.euid,
                'process': process_path,
                'event': EVENT_TYPES.get(record, 'logEvent'),
                'type': LOG_TYPES.get(log_type) if record != 0x06 else None,
                'subsystem': None, 'category': None, 'sender': None,
                'format': None, 'message': None, 'activity': 0}
        if record == 0x07:
            start, end, count = struct.unpack_from('<QQQ', data, 0)
            base['message'] = (f"lost >={count} unreliable messages from "
                               f"{start}-{end} (Mach continuous exact "
                               f"start-approx. end)")
            return base if want is None else None
        if record == 0x03:                       # trace: load address only
            fields['load_lower'] = u('<I')
            values = data[position:]
            count = data[-1] if data else 0
        else:
            if flags & 0x0001:
                base['activity'] = u('<Q') & ((1 << 63) - 1)
            if record == 0x02:
                if flags & 0x0010:
                    u('<Q')
                if flags & 0x0200:
                    u('<Q')
                if log_type != 0x03:
                    base['activity'] = u('<Q') & ((1 << 63) - 1)
            private_range = None
            if record in (0x04, 0x06) and flags & 0x0100:
                private_range = (u('<H'), u('<H'))
            fields['load_lower'] = u('<I')
            if flags & 0x0020:
                fields['large_offset'] = u('<H')
            if kind == 0x0008:
                fields['load_upper'] = u('<H')
            elif kind == 0x000a:
                fields['uuidtext'] = _uuid(data, position)
                position += 16
            elif kind == 0x000c:
                fields['large_cache'] = u('<H')
            if record in (0x04, 0x06) and flags & 0x0200:
                fields['subsystem'] = u('<H')
            if record == 0x06:
                fields['signpost'] = u('<Q')
            reference_index = None
            if record in (0x04, 0x06):
                if flags & 0x0400:
                    u('<B')                              # ttl
                if flags & 0x0800:
                    reference_index = u('<B')
                if record == 0x06 and flags & 0x8000:
                    fields['name_lower'] = u('<I')
                    if flags & 0x0020:
                        fields['name_upper'] = u('<H')
                u('<B')
                count = u('<B')
                items, position = self._items(data, position, count)
            else:
                items = []
            values = data[position:]
            if reference_index:
                found = oversize.get(proc_id + (reference_index,))
                if found is not None:
                    items, values, private = found
                    private_range = None
                    private_offset = 0
                else:
                    items = None
        # The format string, through its image.
        string_reference = reference
        dynamic = bool(string_reference & 0x80000000)
        string_reference &= 0x7fffffff
        extra = fields.get('large_cache') or fields.get('large_offset')
        if extra:
            string_reference |= extra << 31
        found = self._format(process, flags, fields, string_reference,
                             dynamic)
        format_string, sender_id, sender = found if found else \
            (None, None, None)
        subsystem, category = process.subsystems.get(
            fields.get('subsystem'), (None, None))
        base.update(subsystem=subsystem, category=category, sender=sender,
                    format=format_string)
        if record == 0x06:
            base['signpost'] = fields.get('signpost')
            name_reference = fields.get('name_lower')
            if name_reference:
                name_dynamic = bool(name_reference & 0x80000000)
                name_reference &= 0x7fffffff
                if fields.get('name_upper'):
                    name_reference |= fields['name_upper'] << 31
                name = self._format(process, flags, fields, name_reference,
                                    name_dynamic)
                base['signpost_name'] = name[0] if name else None
        if want is not None and not want(process_path, subsystem,
                                         format_string):
            return None
        if format_string is None:
            base['message'] = '<compose failure [missing precomposed log]>'
            return base
        parsed = self._parsed(format_string)
        if record == 0x03:
            arguments = self._trace_values(values, count, parsed)
        elif items is None:
            arguments = []
        else:
            start = (private_range[0] - private_offset) if private_range \
                else 0
            arguments = self._arguments(items, values, private, start,
                                        parsed)
        base['message'] = parsed.render(arguments)
        return base

    def _parsed(self, text):
        key = ('fmt', text)
        if key not in self._formats:
            self._formats[key] = Format(text)
        return self._formats[key]

    @staticmethod
    def _trace_values(values, count, parsed):
        out, offset = [], 0
        sizes = values[-(1 + count):-1] if count else b''
        for index, size in enumerate(sizes):
            piece = values[offset:offset + size]
            offset += size
            operator = parsed.operators[index] if index < len(
                parsed.operators) else None
            out.append(decode(operator, piece))
        return out

    @staticmethod
    def _arguments(items, values, private, private_start, parsed):
        out = []
        index = 0
        for kind, inline, offset, length in items:
            if kind in (0x10, 0x12):                       # precision
                continue
            data = None
            if kind in (0x00, 0x02):
                data = inline
            elif kind in _STRING_TYPES or kind in _BINARY_TYPES:
                data = values[offset:offset + length]
            elif kind in _PRIVATE_STRING_TYPES:
                start = private_start + offset
                data = private[start:start + length]
            if kind in _PRIVATE_TYPES and not data:
                out.append('<private>')
            else:
                operator = parsed.operators[index] if index < len(
                    parsed.operators) else None
                out.append(decode(operator, data))
            index += 1
        return out

    def _process_for(self, upper, lower):
        process = self._catalog.get((upper, lower))
        if process is None:
            return None, None
        return process, self._image_path(process.main)

    def _simpledump(self, chunk):
        upper, lower = struct.unpack_from('<QI', chunk, 0)
        log_type = chunk[13]
        continuous, thread = struct.unpack_from('<QQ', chunk, 16)
        sub_size, message_size = struct.unpack_from('<II', chunk, 76)
        subsystem = _cstring(chunk[84:84 + sub_size], 0)
        message = _cstring(chunk[84 + sub_size:84 + sub_size +
                                 message_size], 0)
        process, path = self._process_for(upper, lower)
        return {'time_ns': self.time_ns(continuous), 'boot': self.boot,
                'thread': thread, 'pid': process.pid if process else 0,
                'euid': process.euid if process else None,
                'process': path, 'event': 'logEvent',
                'type': LOG_TYPES.get(log_type), 'subsystem': subsystem,
                'category': None, 'sender': None, 'format': None,
                'message': message, 'activity': 0}

    def _statedump(self, chunk):
        upper, lower = struct.unpack_from('<QI', chunk, 0)
        continuous, activity = struct.unpack_from('<QQ', chunk, 16)
        state_type, state_size = struct.unpack_from('<II', chunk, 48)
        title = _cstring(chunk, 56 + 128)
        process, path = self._process_for(upper, lower)
        message = ''
        if state_type == 0x03:
            library = _cstring(chunk, 56)
            decoder = _cstring(chunk, 120)
            message = (f"{title}\n<decode: unsupported decoder: "
                       f"{library}:{decoder}>")
        return {'time_ns': self.time_ns(continuous), 'boot': self.boot,
                'thread': 0, 'pid': process.pid if process else 0,
                'euid': process.euid if process else None,
                'process': path, 'event': 'stateEvent', 'type': None,
                'subsystem': None, 'category': None, 'sender': None,
                'format': None, 'message': message,
                'activity': activity & ((1 << 63) - 1)}

    def timesync_entries(self):
        """The boot and wall-clock adjustments `log show` lists first."""
        out = []
        if self.boot_wall is not None:
            out.append({'time_ns': self.boot_wall, 'boot': self.boot,
                        'event': 'timesyncEvent',
                        'message': f"=== system boot: {self.boot}"})
        for kernel, wall in sorted(self.syncs):
            out.append({'time_ns': wall, 'boot': self.boot,
                        'event': 'timesyncEvent',
                        'message': '=== system wallclock time adjusted'})
        return out


# --- what an examiner reads them for --------------------------------------------

#: The processes whose messages become activity records; every other
#: process's firehose chunks are skipped unread.
WATCHED = ('sudo', 'sshd', 'sshd-session', 'su', 'login', 'loginwindow',
           'authd', 'kernel')

_AUTHORIZED = re.compile(
    r"^Succeeded authorizing right '([^']+)' by client '([^']+)' \[(\d+)\] "
    r"for authorization created by '([^']+)' \[(\d+)\]")
_AUTH_FAILED = re.compile(
    r"^Failed to authorize right '([^']+)' by client '([^']+)' \[(\d+)\] "
    r"for authorization created by '([^']+)' \[(\d+)\]")
_USBMSC = re.compile(
    r"USBMSC Identifier \(non-unique\): (\S*) (0x[0-9a-fA-F]+) "
    r"(0x[0-9a-fA-F]+) (0x[0-9a-fA-F]+)")
_SCREEN = re.compile(r'com\.apple\.sessionagent\.screenIs(Locked|Unlocked)')
_RIGHTS_WORTH = ('system.privilege.admin', 'system.preferences',
                 'system.login.console', 'system.install', 'authenticate',
                 'com.apple.')


def _watched(path):
    return bool(path) and path.rsplit('/', 1)[-1] in WATCHED


def _interesting(path, subsystem, text):
    """Before the arguments are decoded: is this format string one the
    records are made from?"""
    name = (path or '').rsplit('/', 1)[-1]
    text = text or ''
    if name == 'kernel':
        return 'USBMSC Identifier' in text
    if name == 'loginwindow':
        return 'about to post BSD notify' in text or \
            'screenIs' in text
    if name == 'authd':
        return 'authorizing right' in text or 'authorize right' in text
    return True


def log_records(entries, path, ref):
    """Activity records from decoded entries (dicts from TraceV3)."""
    from trace_app.core.activity import record
    from trace_app.core.activity.linux import Describer
    describer = Describer('unified log', path, ref)
    out = describer.out
    for entry in entries:
        when = TraceV3.as_datetime(entry['time_ns'])
        message = entry.get('message') or ''
        process = entry.get('process') or ''
        name = process.rsplit('/', 1)[-1]
        detail = {'process': process, 'pid': entry.get('pid'),
                  'subsystem': entry.get('subsystem'),
                  'category': entry.get('category'),
                  'boot': entry.get('boot'),
                  'nanoseconds': entry['time_ns'] % 1_000_000_000}
        if entry.get('event') == 'timesyncEvent':
            if message.startswith('=== system boot'):
                out.append(record('system', 'unified log', when,
                                  'System started', entry.get('boot'),
                                  {'boot': entry.get('boot')}, path=path,
                                  ref=ref))
            continue
        if name in ('sudo', 'sshd', 'sshd-session', 'su', 'login'):
            item = describer.message(when, 'sshd' if name == 'sshd-session'
                                     else name, message.rstrip())
            if item is not None:
                item['detail'].update({k: v for k, v in detail.items()
                                       if v is not None})
            continue
        if name == 'loginwindow':
            match = _SCREEN.search(message)
            if match:
                out.append(record(
                    'logons', 'unified log', when,
                    'Screen locked' if match.group(1) == 'Locked'
                    else 'Screen unlocked', 'console', detail, path=path,
                    ref=ref))
            continue
        if name == 'authd':
            match = _AUTHORIZED.match(message) or \
                _AUTH_FAILED.match(message)
            if match and match.group(1).startswith(_RIGHTS_WORTH):
                right, client, client_pid, creator, creator_pid = \
                    match.groups()
                failed = message.startswith('Failed')
                out.append(record(
                    'logons', 'unified log', when,
                    'Authorization refused' if failed else
                    'Authorization granted', right,
                    dict(detail, client=client, client_pid=client_pid,
                         created_by=creator, created_by_pid=creator_pid),
                    path=path, ref=ref))
            continue
        if name == 'kernel':
            match = _USBMSC.search(message)
            if match:
                serial, vendor, product, revision = match.groups()
                out.append(record(
                    'usb', 'unified log', when, 'USB storage connected',
                    serial or f"{vendor}:{product}",
                    dict(detail, serial=serial or None, vendor_id=vendor,
                         product_id=product, revision=revision),
                    path=path, ref=ref))
    return out


def log_folders(volume):
    """(tracev3 entries, uuidtext folder parts, timesync entries) for each
    unified log on a volume: the live one under /private/var/db, and a
    .logarchive given as evidence itself."""
    found = []
    roots = []
    for db in (('private', 'var', 'db'), ('var', 'db')):
        if volume.find(*db, 'diagnostics') is not None:
            roots.append((db + ('diagnostics',), db + ('uuidtext',)))
            break
    if volume.find('timesync') is not None and \
            volume.find('dsc') is not None:
        roots.append(((), ()))                     # a .logarchive itself
    for diagnostics, uuidtext in roots:
        traces = []
        for kind in ('Persist', 'Special', 'HighVolume'):
            folder = volume.find(*diagnostics, kind)
            traces += [e for e in volume.children(folder)
                       if e.name.endswith('.tracev3')] if folder else []
        live = volume.find(*diagnostics, 'logdata.LiveData.tracev3')
        if live is not None:
            traces.append(live)
        sync = volume.find(*diagnostics, 'timesync')
        found.append((traces, uuidtext,
                      [e for e in volume.children(sync)
                       if e.name.endswith('.timesync')] if sync else []))
    return found


def collect(volume, step, should_stop=None):
    """Activity records from every unified log on a volume."""
    out = []
    for traces, uuidtext, syncs in log_folders(volume):
        if not traces:
            continue

        def read(*parts, base=uuidtext):
            entry = volume.find(*base, *parts)
            return volume.read(entry) if entry is not None and \
                not entry.is_dir else None
        strings = Strings(read)
        timesync = Timesync(volume.read(e) for e in syncs)
        boots = set()
        for entry in traces:
            if should_stop and should_stop():
                break
            step(entry.path)
            try:
                log = TraceV3(volume.read(entry), strings, timesync)
                entries = list(log.entries(want=_interesting,
                                           processes=_watched))
                if log.boot not in boots:
                    boots.add(log.boot)
                    entries = log.timesync_entries()[:1] + entries
            except (UnifiedLogError, struct.error, IndexError) as exc:
                logger.info("%s not read: %s", entry.path, exc)
                continue
            out += log_records(entries, entry.path, volume.ref(entry))
    return out

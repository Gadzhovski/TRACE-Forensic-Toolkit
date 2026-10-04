"""The systemd journal (Linux), read in Python from its bytes.

A journal file is a header ("LPKSHHRH") and objects, 8-byte aligned: DATA
objects hold one "FIELD=value" each (shared between entries, so each is
stored once), ENTRY objects list the DATA objects an event is made of, and
ENTRY_ARRAY objects chain the entries in order. The objects are walked one
after another rather than through the arrays, so entries of a journal that
was not closed -- whose arrays were never updated -- are read too.

A DATA object may be compressed: XZ (lzma, in the standard library), LZ4
(a block format small enough to decode here) or zstd (core/zstd_decode.py:
Python 3.14's standard library when present, TRACE's own decoder on every
other Python). A field that cannot be decompressed -- damaged -- is
counted under UNDECODED and the entry kept, never dropped. Compact journals
(systemd 252+) use 32-bit offsets.

Layout: Lennart Poettering's "Journal File Format" and libyal dtformats;
expected values in the tests are plaso's for the same files.
"""

import datetime
import logging
import lzma
import struct

from trace_app.core import zstd_decode

logger = logging.getLogger('TRACE.Activity.Journal')

SIGNATURE = b'LPKSHHRH'
UTC = datetime.timezone.utc

_DATA, _FIELD, _ENTRY, _DATA_HASH, _FIELD_HASH, _ENTRY_ARRAY, _TAG = \
    range(1, 8)
_XZ, _LZ4, _ZSTD = 1, 2, 4
_COMPACT = 16

#: The key under which an entry counts its fields that could not be
#: decompressed (damaged data).
UNDECODED = '_FIELDS_NOT_DECODED'

#: Most entries read from one file; a journal is at most a few hundred MB.
MAX_ENTRIES = 2_000_000


class JournalError(Exception):
    """Not a journal, or not one that can be read."""


def zstd_available():
    """Always: TRACE decodes zstd itself where Python cannot."""
    return True


def lz4_block(source, size_hint=0):
    """Decompress one LZ4 block (no frame): literals and back-references."""
    out = bytearray()
    position, end = 0, len(source)
    while position < end:
        token = source[position]
        position += 1
        length = token >> 4
        if length == 15:
            while True:
                extra = source[position]
                position += 1
                length += extra
                if extra != 255:
                    break
        out += source[position:position + length]
        position += length
        if position >= end:
            break                       # the last sequence has no match
        offset = source[position] | (source[position + 1] << 8)
        position += 2
        if not offset or offset > len(out):
            raise JournalError("LZ4 back-reference outside the output")
        length = token & 15
        if length == 15:
            while True:
                extra = source[position]
                position += 1
                length += extra
                if extra != 255:
                    break
        length += 4
        start = len(out) - offset
        while length > 0:
            # An overlapping copy repeats the last `offset` bytes.
            take = min(length, offset)
            out += out[start:start + take]
            start += take
            length -= take
    return bytes(out)


class Journal:
    def __init__(self, data):
        if len(data) < 208 or data[:8] != SIGNATURE:
            raise JournalError("Not a systemd journal (no LPKSHHRH header).")
        self.data = data
        (self.compatible, self.incompatible) = struct.unpack_from('<II',
                                                                  data, 8)
        self.state = data[16]
        self.machine_id = data[40:56].hex()
        self.boot_id = data[56:72].hex()
        (self.header_size, self.arena_size) = struct.unpack_from('<QQ',
                                                                 data, 88)
        self.entries_declared = struct.unpack_from('<Q', data, 152)[0]
        self.compact = bool(self.incompatible & _COMPACT)
        self._fields = {}
        self.undecoded = 0

    def _object(self, offset):
        if offset + 16 > len(self.data):
            return None, 0, 0
        kind, flags = self.data[offset], self.data[offset + 1]
        size = struct.unpack_from('<Q', self.data, offset + 8)[0]
        return kind, flags, size

    def field(self, offset):
        """(key, value bytes) of the DATA object at `offset`."""
        if offset in self._fields:
            return self._fields[offset]
        kind, flags, size = self._object(offset)
        if kind != _DATA or size < 64 or offset + size > len(self.data):
            raise JournalError(f"No data object at {offset}")
        start = offset + (72 if self.compact else 64)
        payload = self.data[start:offset + size]
        try:
            if flags & _XZ:
                payload = lzma.decompress(payload)
            elif flags & _LZ4:
                expected = struct.unpack_from('<Q', payload, 0)[0]
                payload = lz4_block(payload[8:], expected)
            elif flags & _ZSTD:
                payload = zstd_decode.decompress(payload)
        except (lzma.LZMAError, zstd_decode.ZstdError, JournalError,
                IndexError, struct.error) as exc:
            # Said, not dropped: the entry is listed with how many of its
            # fields could not be read.
            logger.debug("Field at %s not decompressed: %s", offset, exc)
            self.undecoded += 1
            result = (UNDECODED, b'')
            self._fields[offset] = result
            return result
        key, _sep, value = bytes(payload).partition(b'=')
        result = (key.decode('utf-8', 'backslashreplace'), value)
        if len(self._fields) < 200000:
            self._fields[offset] = result
        return result

    def entries(self):
        """Every entry, in file order: {'_REALTIME': datetime, FIELD: str}."""
        offset = self.header_size
        tail = min(len(self.data), self.header_size + self.arena_size) \
            if self.arena_size else len(self.data)
        count = 0
        item_size = 4 if self.compact else 16
        while offset + 16 <= tail and count < MAX_ENTRIES:
            kind, _flags, size = self._object(offset)
            if not kind or size < 16:
                break                         # the end of what was written
            if kind == _ENTRY and size >= 64 and offset + size <= tail:
                count += 1
                realtime = struct.unpack_from('<Q', self.data, offset + 24)[0]
                fields = {'_REALTIME': _micro(realtime),
                          '_ENTRY_OFFSET': offset}
                position = offset + 64
                while position + item_size <= offset + size:
                    target = struct.unpack_from(
                        '<I' if self.compact else '<Q', self.data,
                        position)[0]
                    position += item_size
                    try:
                        key, value = self.field(target)
                    except (JournalError, lzma.LZMAError, IndexError,
                            struct.error) as exc:
                        logger.debug("Field at %s unreadable: %s", target,
                                     exc)
                        continue
                    if key == UNDECODED:
                        fields[key] = fields.get(key, 0) + 1
                    elif key:
                        fields[key] = value.decode('utf-8', 'backslashreplace')
                yield fields
            offset += (size + 7) & ~7


def _micro(value):
    if not value:
        return None
    try:
        return datetime.datetime(1970, 1, 1, tzinfo=UTC) + \
            datetime.timedelta(microseconds=value)
    except OverflowError:
        return None


def source_time(fields):
    """When the program said it happened (_SOURCE_REALTIME_TIMESTAMP), or
    when the journal wrote it."""
    value = fields.get('_SOURCE_REALTIME_TIMESTAMP')
    if value and value.isdigit():
        return _micro(int(value))
    return fields.get('_REALTIME')

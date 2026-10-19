"""Apple System Log (.asl) files (no Qt).

Before the unified log, macOS kept syslog-style messages in /private/var/log/
asl/*.asl: a 'ASL DB' header naming the first record, then a chain of records
each pointing to the next. A record holds the written time, the level, the
process id, the sender/facility/host/message strings (by offset, or inline in
the offset word when its top bit is set) and extra name/value fields.

`records(data, path, ref)` returns one `activity.record` per message.
Checked against plaso's applesystemlog.asl / 2019.09.26.asl and its expected
values (tests/test_asl.py).
"""

import logging
import struct

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.ASL')

_SIGNATURE = b'ASL DB\x00\x00\x00\x00\x00\x00'
#: Big-endian record: unknown1(H) data_size(I) next(Q) message_id(Q)
#: written_time(Q) written_ns(I) level(H) flags(H) pid(I) uid(i) gid(i)
#: read_uid(i) read_gid(i) ref_pid(Q) host(Q) sender(Q) facility(Q)
#: message(Q).
_RECORD = struct.Struct('>HIQQQIHHIiiiiQQQQQ')
_EXTRA = struct.Struct('>QQ')
_STRING_MSB = 1 << 63


def _string(data, offset):
    """A record string: 0 is none, the top bit means the string is packed
    into the offset word, else it is at that file offset (2 bytes unknown,
    4 bytes length, then the bytes)."""
    if not offset:
        return None
    if offset & _STRING_MSB:
        size = (offset >> 56) & 0x0F
        packed = bytes((offset >> (8 * i)) & 0xFF for i in range(6, -1, -1))
        return packed[:size].decode('utf-8', 'replace')
    if offset + 6 > len(data):
        return None
    length = struct.unpack_from('>I', data, offset + 2)[0]
    return data[offset + 6:offset + 6 + length].rstrip(b'\x00').decode(
        'utf-8', 'replace')


def records(data, path, ref):
    if data[:12] != _SIGNATURE:
        return []
    out = []
    offset = struct.unpack_from('>Q', data, 16)[0]   # first_log_entry_offset
    size = len(data)
    seen = set()
    while 0 < offset < size and offset not in seen:
        seen.add(offset)
        if offset + _RECORD.size > size:
            break
        fields = _RECORD.unpack_from(data, offset)
        (_u1, data_size, next_offset, message_id, written, written_ns, level,
         _flags, pid, uid, gid, read_uid, read_gid, _ref, host_off,
         sender_off, facility_off, message_off) = fields
        # Extra name/value fields follow the fixed part, in 16-byte pairs.
        extra = {}
        pairs_start = offset + _RECORD.size
        pairs_end = offset + 6 + data_size
        pos = pairs_start
        while pos + _EXTRA.size <= min(pairs_end, size):
            name_off, value_off = _EXTRA.unpack_from(data, pos)
            name = _string(data, name_off)
            if name:
                extra[name] = _string(data, value_off)
            pos += _EXTRA.size
        when = times.unix(written)
        detail = {
            'sender': _string(data, sender_off),
            'facility': _string(data, facility_off),
            'host': _string(data, host_off),
            'level': level,
            'pid': pid,
            'user id': uid,
            'group id': gid,
            'read user id': read_uid,
            'message id': message_id,
            'record position': offset,
        }
        extra_text = ', '.join(f'{k}: {v}' for k, v in sorted(extra.items()))
        if extra_text:
            detail['extra'] = extra_text
        message = _string(data, message_off) or ''
        detail['basis'] = 'when the log message was written'
        out.append(record('system', 'Apple System Log', when,
                          message or (detail['sender'] or 'log message'),
                          f"{detail['sender'] or ''}: {message}".strip(': '),
                          detail, path=path, ref=ref))
        if next_offset <= offset:
            break
        offset = next_offset
    return out

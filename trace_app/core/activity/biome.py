"""Apple Biome SEGB streams (no Qt).

Biome is what replaced KnowledgeC on macOS 13+ and iOS 16+: per-event
streams under .../Biome/streams/... in the SEGB container format. There are
two layouts:

* **v1** -- a 56-byte header with the magic 'SEGB' at its *end* (bytes
  52-56) and the end-of-data offset at byte 0; then records, each a 32-byte
  header ('<iiddIi': length, state, two Cocoa timestamps, a CRC-32 of the
  payload, unknown) followed by the payload, padded to an 8-byte boundary.
* **v2** -- a 32-byte header with the magic 'SEGB' at the *start*, an entry
  count and a creation time; a trailer of 16-byte entries at the end
  (end-offset, state, Cocoa timestamp); and the entries from offset 32, each
  an 8-byte sub-header (CRC-32, unknown) then the payload, padded to 4.

`records(data, path, ref)` returns one `activity.record` per entry, with the
stream name as the 'what', the state (written/deleted) and a short reading of
the payload (an NSKeyedArchiver plist; else its texts read as protobuf with
no schema, core/protobuf; else printable text). State values:
1 written, 3 deleted, 4 unknown. Checked against SecurityRonin's
segb-forensic fixtures and ccl-segb's record counts (tests/test_biome.py).
"""

import logging
import plistlib
import re
import struct
import zlib

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.Biome')

_MAGIC = b'SEGB'
_V1_HEADER = 56
_V1_RECORD = struct.Struct('<iiddIi')      # length, state, ts1, ts2, crc, _
_V2_HEADER = 32
_V2_TRAILER = struct.Struct('<iid')        # end_offset, state, timestamp
_V2_TRAILER_LENGTH = 16
_V2_SUBHEADER = 8
_STATES = {1: 'written', 3: 'deleted', 4: 'unknown'}


def version(data):
    """'v1', 'v2' or None -- which SEGB layout the bytes are."""
    if len(data) >= _V2_HEADER and data[:4] == _MAGIC:
        return 'v2'
    if len(data) >= _V1_HEADER and data[52:56] == _MAGIC:
        return 'v1'
    return None


def _payload_text(payload):
    """A short, safe reading of a record's payload: an NSKeyedArchiver
    plist's top value if it decodes, else the printable text, else ''."""
    if payload[:8] == b'bplist00':
        try:
            plist = plistlib.loads(payload)
            return _describe_archiver(plist)
        except Exception:
            pass
    # Most streams (App.InFocus, Device.Wireless.WiFi, Media.NowPlaying,
    # Notifications...) are protobuf: its texts, in field order, read
    # with no schema -- bundle ids, titles, network names.
    from trace_app.core import protobuf
    found = protobuf.strings(payload, limit=12)
    if found:
        return ' | '.join(dict.fromkeys(found))[:300]
    # A fixed layout (AppKillEvent, AppLaunchTimeEvent): its runs of four
    # or more printable characters -- a bundle id, a name.
    runs = re.findall(rb'[\x20-\x7e]{4,}', bytes(payload))
    return ' | '.join(r.decode('ascii').strip() for r in runs)[:200]


def _describe_archiver(plist):
    """The interesting strings of an NSKeyedArchiver plist (the $objects
    that are str), joined -- enough to see what the record is about."""
    objects = plist.get('$objects') if isinstance(plist, dict) else None
    if isinstance(objects, list):
        strings = [o for o in objects
                   if isinstance(o, str) and o not in ('$null',)
                   and not o.startswith('NS')]
        return ' | '.join(strings[:8])[:200]
    return str(plist)[:200]


def _v1_records(data):
    end = struct.unpack_from('<I', data, 0)[0]
    end = min(end, len(data)) if end else len(data)
    offset = _V1_HEADER
    while offset + _V1_RECORD.size <= end:
        length, state, ts1, ts2, crc, _u = _V1_RECORD.unpack_from(data,
                                                                  offset)
        if length < 0:
            break
        start = offset + _V1_RECORD.size
        payload = data[start:start + length]
        yield {'state': state, 'time': times.mac_absolute(ts1 or ts2),
               'crc_ok': (zlib.crc32(payload) & 0xFFFFFFFF) == crc,
               'payload': payload}
        offset = start + length
        if offset % 8:
            offset += 8 - (offset % 8)


def _v2_records(data):
    count = struct.unpack_from('<i', data, 4)[0]
    if count <= 0:
        return
    trailer_bytes = count * _V2_TRAILER_LENGTH
    if trailer_bytes > len(data) - _V2_HEADER:
        return
    trailer_start = len(data) - trailer_bytes
    entries = []
    for i in range(count):
        end_off, state, ts = _V2_TRAILER.unpack_from(
            data, trailer_start + i * _V2_TRAILER_LENGTH)
        entries.append((end_off, state, ts))
    # Zeroed trailer slots (state 0) point at nothing.
    entries = [e for e in entries if e[1] in _STATES]
    entries.sort(key=lambda e: e[0])
    pos = 0                             # relative to the entry area (off 32)
    previous = None
    for end_off, state, ts in entries:
        if previous is not None and end_off == previous[0]:
            # A second trailer entry for the same data (written, then
            # marked deleted): the same record in its other state.
            yield dict(previous[1], state=state,
                       time=times.mac_absolute(ts))
            continue
        if state == 4:
            continue                    # an empty record: no data of its own
        total = end_off - pos
        if total < _V2_SUBHEADER:
            pos = end_off
            if pos % 4:
                pos += 4 - (pos % 4)
            continue
        base = _V2_HEADER + pos
        crc, _u = struct.unpack_from('<Ii', data, base)
        payload = data[base + _V2_SUBHEADER:base + total]
        entry = {'state': state, 'time': times.mac_absolute(ts),
                 'crc_ok': (zlib.crc32(payload) & 0xFFFFFFFF) == crc,
                 'payload': payload}
        previous = (end_off, entry)
        yield entry
        pos = end_off
        if pos % 4:
            pos += 4 - (pos % 4)


def read_records(data):
    """[{state, time, crc_ok, payload}] for a SEGB file, or []."""
    kind = version(data)
    if kind == 'v1':
        return list(_v1_records(data))
    if kind == 'v2':
        return list(_v2_records(data))
    return []


def records(data, stream, path, ref):
    """`activity.record`s for a SEGB stream; `stream` names it (the folder
    under Biome/streams, e.g. '_DKEvent.App.InFocus')."""
    out = []
    name = stream or 'Biome event'
    for entry in read_records(data):
        if entry['state'] == 4:
            continue                    # unknown state: ccl-segb skips it
        text = _payload_text(entry['payload'])
        out.append(record(
            'usage', f'Biome · {name}', entry['time'], name, text,
            {'state': _STATES.get(entry['state'], entry['state']),
             'crc valid': entry['crc_ok'],
             'bytes': len(entry['payload']),
             'basis': 'the event time recorded in the SEGB record'},
            path=path, ref=ref))
    return out

"""Microsoft Defender Antivirus: what it detected, what it did, and the
files it quarantined -- from ProgramData\\Microsoft\\Windows Defender.

* **MPLog** (Support\\MPLog-*.log, UTF-16): `DETECTION_ADD#n` lines -- the
  time (UTC), the threat and what it was found in: a file, a command line
  (procdump against LSASS, certutil downloading), a registry value, a
  behaviour -- and "Beginning threat actions" blocks: what Defender did
  (quarantine, remove), to which file, its SHA-1 and owner. Block times are
  the machine's local wall-clock time, kept as such.
* **DetectionHistory** (Scans\\History\\Service\\DetectionHistory\\*\\*,
  Windows 10+): one file per detection -- the threat, the resources it was
  found in, and the `ThreatTracking*` values Defender recorded (the file's
  SHA-256, SHA-1, MD5 and size, when the detection started), then the user
  and the process involved.
* **Quarantine** (Quarantine\\Entries\\{GUID}): each entry RC4-encrypted
  with Defender's fixed key (published, and the same on every machine):
  when the file was quarantined, the threat, and each resource -- its path,
  size, times and the resource id under which its content is kept in
  Quarantine\\ResourceData\\xx\\<id>. That content is BackupRead's output
  -- the file's data, its alternate streams (Zone.Identifier: where it was
  downloaded from) and its security descriptor -- RC4-encrypted too;
  `resource_streams` decrypts it in memory (archives.py shows it as
  members, so a quarantined file can be previewed, hashed, scanned,
  searched -- never written out).
"""

import datetime
import re
import struct

from trace_app.core.activity import record, times

DEFENDER = ('ProgramData', 'Microsoft', 'Windows Defender')

#: Defender's quarantine RC4 key (cuckoo's quarantine.py, defender-dump,
#: dissect.target: the same 256 bytes everywhere).
RC4_KEY = bytes([
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C,
    0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9,
    0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF,
    0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
    0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64,
    0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA,
    0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40,
    0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
    0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19, 0x18, 0x18,
    0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D,
    0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85,
    0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
    0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8,
    0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D,
    0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B,
    0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD,
    0xBF, 0xF3, 0x82, 0x53])


def rc4(data, key=RC4_KEY):
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray(len(data))
    i = j = 0
    for index, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out[index] = byte ^ box[(box[i] + box[j]) & 0xFF]
    return bytes(out)


def _filetime(value):
    if not value:
        return None
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) \
            + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def _utf16(raw):
    return raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]


# --- the quarantine ---------------------------------------------------------------

#: Resource field identifiers (the low 12 bits of a field's second word).
_FIELD_RESOURCE_ID, _FIELD_PATH = 0x02, 0x0C
_FIELD_CREATED, _FIELD_ACCESSED, _FIELD_WRITTEN = 0x0F, 0x10, 0x11
_FIELD_SIZE = 0x12


def quarantine_entry(data):
    """A Quarantine\\Entries file: {'time', 'quarantine_id', 'scan_id',
    'threat_id', 'threat', 'resources': [{'kind', 'path', 'resource_id',
    'size', 'created', 'accessed', 'written'}]}. None if it is not one."""
    if len(data) < 60:
        return None
    header = rc4(data[:60])
    size1, size2 = struct.unpack_from('<II', header, 40)
    if not (40 <= size1 <= 4096) or 60 + size1 + size2 > len(data):
        return None
    first = rc4(data[60:60 + size1])
    stamp, threat_id = struct.unpack_from('<QQ', first, 32)
    name = first[52:].split(b'\x00', 1)[0].decode('latin-1')
    entry = {'quarantine_id': first[:16].hex(), 'scan_id': first[16:32].hex(),
             'time': _filetime(stamp), 'threat_id': threat_id,
             'threat': name, 'resources': []}
    second = rc4(data[60 + size1:60 + size1 + size2])
    count = struct.unpack_from('<I', second, 0)[0]
    if count > 1024:
        return entry
    for index in range(count):
        offset = struct.unpack_from('<I', second, 4 + index * 4)[0]
        try:
            entry['resources'].append(_resource(second, offset))
        except (struct.error, ValueError):
            continue
    return entry


def _resource(buf, at):
    end = at
    while end + 1 < len(buf) and buf[end:end + 2] != b'\x00\x00':
        end += 2
    path = buf[at:end].decode('utf-16-le', 'replace')
    at = end + 2
    fields = struct.unpack_from('<H', buf, at)[0]
    at += 2
    kind_end = buf.index(b'\x00', at)
    kind = buf[at:kind_end].decode('latin-1')
    at = kind_end + 1
    resource = {'kind': kind, 'path': path, 'resource_id': None,
                'size': None, 'created': None, 'accessed': None,
                'written': None}
    for _ in range(min(fields, 64)):
        at = (at + 3) & ~3
        size, packed = struct.unpack_from('<HH', buf, at)
        value = buf[at + 4:at + 4 + size]
        identifier = packed & 0x0FFF
        if identifier == _FIELD_RESOURCE_ID:
            resource['resource_id'] = value.hex().upper()
        elif identifier == _FIELD_PATH:
            resource['path'] = _utf16(value)
        elif identifier in (_FIELD_CREATED, _FIELD_ACCESSED, _FIELD_WRITTEN):
            slot = {_FIELD_CREATED: 'created', _FIELD_ACCESSED: 'accessed',
                    _FIELD_WRITTEN: 'written'}[identifier]
            resource[slot] = _filetime(int.from_bytes(value, 'little'))
        elif identifier == _FIELD_SIZE:
            resource['size'] = int.from_bytes(value, 'little')
        at += 4 + size
    return resource


#: WIN32_STREAM_ID kinds BackupRead writes.
STREAM_KINDS = {1: 'data', 2: 'extended attributes',
                3: 'security descriptor', 4: 'alternate stream', 5: 'link',
                6: 'properties', 7: 'object id', 8: 'reparse data',
                9: 'sparse block', 10: 'transaction data',
                11: 'ghosted extents'}


def resource_streams(data):
    """[(kind, name, bytes)] of a Quarantine\\ResourceData file: the
    quarantined file's content ('data'), its alternate streams (named, e.g.
    ':Zone.Identifier:$DATA') and its security descriptor. [] if `data`
    is not one."""
    plain = rc4(data)
    out = []
    at = 0
    while at + 20 <= len(plain):
        kind, _attributes, size, name_size = struct.unpack_from('<IIQI',
                                                                 plain, at)
        if kind not in STREAM_KINDS or name_size > 1024 or \
                at + 20 + name_size + size > len(plain):
            break
        name = plain[at + 20:at + 20 + name_size].decode('utf-16-le',
                                                          'replace')
        start = at + 20 + name_size
        out.append((STREAM_KINDS[kind], name, plain[start:start + size]))
        at = start + size
    return out


def is_resource_data(head):
    """Do these first bytes decrypt to a BackupRead stream header?"""
    if len(head) < 20:
        return False
    kind, attributes, size, name_size = struct.unpack_from('<IIQI',
                                                           rc4(head[:20]))
    return kind in STREAM_KINDS and attributes <= 0x1F and \
        name_size <= 1024 and size < 1 << 40


# --- DetectionHistory -------------------------------------------------------------

_TRACKING = re.compile(rb'T\x00h\x00r\x00e\x00a\x00t\x00T\x00r\x00a\x00c\x00'
                       rb'k\x00i\x00n\x00g\x00((?:[A-Za-z0-9]\x00)+)\x00\x00')
_STRING = 0x15
#: What a resource of a detection can be, as the file names it.
RESOURCE_KINDS = {'file', 'process', 'regkey', 'regkeyvalue', 'behavior',
                  'cmdline', 'startup', 'folder', 'service', 'webfile',
                  'amsi', 'containerfile', 'genericshell', 'networkfile',
                  'regfile', 'wmi', 'bootsector'}


def _strings(data):
    """[(offset, text)] of the string records (length, type 0x15, UTF-16),
    found wherever they are aligned."""
    out = []
    at = 0
    while at + 8 <= len(data):
        length, kind = struct.unpack_from('<II', data, at)
        if kind == _STRING and 2 <= length <= 8192 and \
                at + 8 + length <= len(data) and length % 2 == 0:
            text = _utf16(data[at + 8:at + 8 + length])
            if text and all(c.isprintable() or c in '\t' for c in text):
                out.append((at, text))
                at = (at + 8 + length + 7) & ~7
                continue
        at += 8
    return out


def detection_history(data):
    """One DetectionHistory file: {'threat', 'resources': [(kind, path)],
    'tracking': {name: value}, 'time', 'user', 'process'}, or None."""
    strings = _strings(data)
    if not strings or not strings[0][1].startswith('Magic.Version'):
        return None
    out = {'threat': strings[1][1] if len(strings) > 1 else '',
           'resources': [], 'tracking': {}, 'time': None, 'user': None,
           'process': None}
    tracking_end = 0
    for match in _TRACKING.finditer(data):
        key = match.group(1).decode('utf-16-le')
        at = match.end()
        if at + 4 > len(data):
            continue
        kind = struct.unpack_from('<I', data, at)[0]
        value = None
        if kind == 6 and at + 8 <= len(data):
            length = struct.unpack_from('<I', data, at + 4)[0]
            value = _utf16(data[at + 8:at + 8 + length])
            tracking_end = max(tracking_end, at + 8 + length)
        elif kind == 4 and at + 12 <= len(data):
            value = struct.unpack_from('<Q', data, at + 4)[0]
            tracking_end = max(tracking_end, at + 12)
        elif kind == 3 and at + 8 <= len(data):
            value = struct.unpack_from('<I', data, at + 4)[0]
            tracking_end = max(tracking_end, at + 8)
        elif kind == 5 and at + 5 <= len(data):
            value = data[at + 4]
            tracking_end = max(tracking_end, at + 5)
        out['tracking'][key] = value
    out['time'] = _filetime(out['tracking'].get('StartTime') or 0)
    for (_at, kind), (_next, path) in zip(strings, strings[1:]):
        if kind.lower() in RESOURCE_KINDS and _at < (tracking_end or
                                                     len(data)):
            out['resources'].append((kind, path))
    for at, text in strings:
        if at < tracking_end:
            continue
        if out['user'] is None and re.fullmatch(r'[^\\:/]+\\[^\\:/]+', text):
            out['user'] = text
        elif out['process'] is None and re.match(r'[A-Za-z]:\\', text):
            out['process'] = text
    return out


# --- MPLog --------------------------------------------------------------------------

_DETECTION_ADD = re.compile(
    r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z DETECTION_ADD#\d+ '
    r'(\S+) ([A-Za-z]+):(.*)$')
#: Resource kinds of a DETECTION_ADD line that are Defender's own
#: bookkeeping, not where the threat was.
_INTERNAL = {'internalcmdline', 'internalbehavior', 'internalfile'}


def decode_log(data):
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', 'replace')
    if len(data) > 1 and data[1:2] == b'\x00':
        return data.decode('utf-16-le', 'replace')
    return data.decode('utf-8', 'replace')


def _local(text):
    try:
        return datetime.datetime.strptime(text.strip(), '%m-%d-%Y %H:%M:%S')
    except ValueError:
        return None


def mplog_events(text):
    """[{'kind': 'detection'|'action', ...}] from an MPLog."""
    out = []
    seen = set()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _DETECTION_ADD.match(line)
        if match:
            stamp, threat, kind, resource = match.groups()
            if kind.lower() not in _INTERNAL:
                key = (stamp[:19], threat, kind, resource)
                if key not in seen:
                    seen.add(key)
                    out.append({'kind': 'detection', 'time': stamp,
                                'threat': threat, 'resource_kind': kind,
                                'resource': resource.strip()})
        elif line.strip() == 'Beginning threat actions':
            block = {}
            end = index + 1
            while end < len(lines) and end < index + 200 and \
                    lines[end].strip() not in ('Finished threat actions',
                                               'Beginning threat actions'):
                name, sep, value = lines[end].partition(':')
                if sep:
                    block.setdefault(name.strip(), value.strip())
                end += 1
            out.append({'kind': 'action',
                        'time': _local(block.get('Start time', '')),
                        'threat': block.get('Threat Name', ''),
                        'action': block.get('Action', ''),
                        'path': (block.get('File Name') or block.get('Path')
                                 or '').replace('\\\\?\\', ''),
                        'sha1': block.get('File to act on SHA1', ''),
                        'owner': block.get('File owner', ''),
                        'result': block.get('Result', '')})
            index = end
            continue
        index += 1
    return out


# --- into Activity -----------------------------------------------------------------

def _common(entry, volume):
    return {'path': entry.path, 'ref': volume.ref(entry)}


def records(volume, step):
    from trace_app.core.activity import _split
    out = []
    base = volume.find(*DEFENDER)
    if base is None:
        return out
    root = _split(base.path)
    support = volume.find(*root, 'Support')
    for entry in volume.children(support, '.log'):
        if not entry.name.lower().startswith('mplog'):
            continue
        step(entry.path)
        for event in mplog_events(decode_log(volume.read(entry))):
            if event['kind'] == 'detection':
                when = datetime.datetime.strptime(
                    event['time'][:19], '%Y-%m-%dT%H:%M:%S').replace(
                        tzinfo=datetime.timezone.utc)
                out.append(record(
                    'antivirus', 'Defender log (MPLog)', when,
                    'Threat detected', event['resource'],
                    {'threat': event['threat'],
                     'found in': event['resource_kind']},
                    **_common(entry, volume)))
            else:
                out.append(record(
                    'antivirus', 'Defender log (MPLog)', event['time'],
                    f"Threat action: {event['action'] or 'unknown'}",
                    event['path'],
                    {'threat': event['threat'], 'SHA-1': event['sha1'],
                     'file owner': event['owner'],
                     'result': event['result'],
                     'basis': "the machine's local time, as Defender "
                              "wrote it"},
                    local=True, **_common(entry, volume)))
    history = volume.find(*root, 'Scans', 'History', 'Service',
                          'DetectionHistory')
    for folder in volume.children(history, dirs=True):
        for entry in volume.children(folder):
            step(entry.path)
            facts = detection_history(volume.read(entry))
            if facts is None:
                continue
            tracking = facts['tracking']
            resources = facts['resources']
            subject = resources[0][1] if resources else facts['threat']
            out.append(record(
                'antivirus', 'Defender detection history', facts['time'],
                'Threat detected', subject,
                {'threat': facts['threat'],
                 'resources': '; '.join(f'{k}: {p}' for k, p in resources),
                 'SHA-256': tracking.get('Sha256'),
                 'SHA-1': tracking.get('Sha1'), 'MD5': tracking.get('MD5'),
                 'size': tracking.get('Size'),
                 'tracking id': tracking.get('Id'),
                 'user': facts['user'], 'process': facts['process']},
                user=(facts['user'] or '').rsplit('\\', 1)[-1],
                **_common(entry, volume)))
    entries = volume.find(*root, 'Quarantine', 'Entries')
    for entry in volume.children(entries):
        step(entry.path)
        facts = quarantine_entry(volume.read(entry))
        if facts is None:
            continue
        for resource in facts['resources']:
            out.append(record(
                'antivirus', 'Defender quarantine', facts['time'],
                f"Quarantined ({resource['kind']})", resource['path'],
                {'threat': facts['threat'], 'threat id': facts['threat_id'],
                 'size': resource['size'],
                 'content': (f"Quarantine\\ResourceData\\"
                             f"{resource['resource_id'][:2]}\\"
                             f"{resource['resource_id']}")
                 if resource['resource_id'] else None,
                 'file created': times.iso(resource['created']),
                 'file modified': times.iso(resource['written']),
                 'file accessed': times.iso(resource['accessed']),
                 'quarantine id': facts['quarantine_id'],
                 'scan id': facts['scan_id']},
                **_common(entry, volume)))
    return out

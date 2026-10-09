"""Deleted registry keys and values, recovered from a hive's free cells (no
Qt; pure Python).

A hive is 4 KB hive bins of cells; a cell's 4-byte size is negative while
it is used and positive once freed -- and freeing changes nothing else. So
a deleted key ('nk') or value ('vk') stays in its cell until something new
is written over it, and neighbouring free cells are merged, so one free
cell can hold several old records. Every free cell is searched, at each
8-byte step (cells are 8-aligned), for a record whose structure holds:

* nk: name length inside the cell and decoding cleanly (ASCII when the
  'compressed name' flag says so, else UTF-16LE), a last-written time
  between 1980 and 2100, and a parent that is a key cell (live or freed)
* vk: name and data inside the hive; data read from its cell, inline (high
  bit of the size) or as big data ('db' list of segments)

A key's path is rebuilt through parent offsets, live and deleted alike; a
deleted value belongs to the deleted key whose value list names it, else
to the live key whose list no longer does -- else it is an orphan, its
key unknown. Nothing is taken from a used cell: what is live is the
registry viewer's.

NIST's cfreds-2017-winreg "nrd" hives (keys and values deleted by RegEdit
and by hivex) are the test: every deleted key and value, against the same
hive before deletion (tests/test_nist_cfreds.py).
"""

import datetime
import struct

BASE = 4096                     # cell offsets count from the first hbin
_TYPES = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY',
          4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK',
          7: 'REG_MULTI_SZ', 8: 'REG_RESOURCE_LIST',
          9: 'REG_FULL_RESOURCE_DESCRIPTOR',
          10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD'}
_EPOCH = datetime.datetime(1601, 1, 1)
_EARLIEST = (datetime.datetime(1980, 1, 1) - _EPOCH).total_seconds() * 10**7
_LATEST = (datetime.datetime(2100, 1, 1) - _EPOCH).total_seconds() * 10**7


class Hive:
    """The cells of one hive (bytes)."""

    def __init__(self, data):
        if data[:4] != b'regf':
            raise ValueError("not a registry hive")
        self.data = data
        self.cells = {}          # offset -> (size, used)
        self.free = []           # (offset, size) of free cells
        pos = BASE
        while pos + 32 <= len(data) and data[pos:pos + 4] == b'hbin':
            size = struct.unpack_from('<I', data, pos + 8)[0]
            if size < 4096 or size % 4096:
                break
            cell = pos + 32
            end = min(pos + size, len(data))
            while cell + 4 <= end:
                length = struct.unpack_from('<i', data, cell)[0]
                if length == 0:
                    break
                used = length < 0
                # A cell cannot reach past its hive bin: a size that says
                # otherwise is damage, or a hiding place (NIST's mr hives
                # forge sizes), and is cut to the bin.
                length = min(abs(length), end - cell)
                self.cells[cell - BASE] = (length, used)
                if not used:
                    self.free.append((cell - BASE, length))
                cell += length
            pos += size

    def at(self, offset, length):
        start = BASE + offset
        return self.data[start:start + length]

    def used(self, offset):
        cell = self.cells.get(offset)
        return bool(cell and cell[1])


def _filetime(value):
    if not _EARLIEST <= value <= _LATEST:
        return None
    moment = _EPOCH + datetime.timedelta(microseconds=value // 10)
    return moment.strftime('%Y-%m-%d %H:%M:%S')


def _key(hive, offset, limit):
    """The nk record whose cell data starts at `offset` + 4, or None."""
    body = hive.at(offset + 4, min(limit, 0x4C + 512))
    if len(body) < 0x4C or body[:2] != b'nk':
        return None
    flags, stamp = struct.unpack_from('<HQ', body, 2)
    parent = struct.unpack_from('<I', body, 0x10)[0]
    values, value_list = struct.unpack_from('<II', body, 0x24)
    name_length = struct.unpack_from('<H', body, 0x48)[0]
    if not name_length or 0x4C + name_length > limit:
        return None
    raw = hive.at(offset + 4 + 0x4C, name_length)
    try:
        name = raw.decode('ascii' if flags & 0x20 else 'utf-16-le')
    except UnicodeDecodeError:
        if not flags & 0x20:
            return None
        name = raw.decode('latin-1')
    if not name.isprintable():
        return None
    when = _filetime(stamp)
    if when is None:
        return None
    return {'offset': offset, 'name': name, 'written': when,
            'parent': parent, 'values': values, 'value_list': value_list,
            'root': bool(flags & 0x04)}


def _value_data(hive, size, where, kind):
    """(bytes, complete) of a value's data."""
    if size & 0x80000000:
        size &= 0x7FFFFFFF
        return struct.pack('<I', where)[:min(size, 4)], True
    if size == 0:
        return b'', True
    cell = hive.at(where, 4)
    if len(cell) < 4:
        return b'', False
    length = abs(struct.unpack('<i', cell)[0])
    body = hive.at(where + 4, max(length - 4, 0))
    if body[:2] == b'db' and size > 16344:
        count, segments = struct.unpack_from('<HI', body, 2)
        out = bytearray()
        offsets = hive.at(segments + 4, 4 * count)
        for i in range(min(count, len(offsets) // 4)):
            segment = struct.unpack_from('<I', offsets, 4 * i)[0]
            seg_cell = hive.at(segment, 4)
            if len(seg_cell) < 4:
                break
            seg_len = abs(struct.unpack('<i', seg_cell)[0]) - 4
            out += hive.at(segment + 4, min(seg_len, 16344))
        return bytes(out[:size]), len(out) >= size
    return body[:size], len(body) >= size


def _value(hive, offset, limit):
    """The vk record whose cell data starts at `offset` + 4, or None."""
    body = hive.at(offset + 4, min(limit, 0x14 + 16384))
    if len(body) < 0x14 or body[:2] != b'vk':
        return None
    name_length, size, where, kind, flags = struct.unpack_from(
        '<HIIIH', body, 2)
    if 0x14 + name_length > limit or kind > 0xFFFF:
        return None
    raw = hive.at(offset + 4 + 0x14, name_length)
    try:
        name = raw.decode('ascii' if flags & 1 else 'utf-16-le') \
            if name_length else '(Default)'
    except UnicodeDecodeError:
        if not flags & 1:
            return None
        name = raw.decode('latin-1')
    if not name.isprintable():
        return None
    inline = bool(size & 0x80000000)
    if not inline and size and (where >= len(hive.data) or
                                (size & 0x7FFFFFFF) > len(hive.data)):
        return None
    data, complete = _value_data(hive, size, where, kind)
    return {'offset': offset, 'name': name, 'type': _TYPES.get(kind, kind),
            'type_code': kind, 'data': data, 'complete': complete,
            'size': size & 0x7FFFFFFF}


def value_text(type_code, data, limit=200):
    """A value's data as the registry viewer shows it."""
    try:
        if type_code in (1, 2, 6):                    # SZ, EXPAND_SZ, LINK
            return data.decode('utf-16-le', 'replace').split('\x00')[0]
        if type_code == 7:                            # MULTI_SZ
            return ' | '.join(
                part for part in data.decode('utf-16-le', 'replace')
                .split('\x00') if part)
        if type_code == 4 and len(data) >= 4:
            return str(struct.unpack_from('<I', data)[0])
        if type_code == 5 and len(data) >= 4:
            return str(struct.unpack_from('>I', data)[0])
        if type_code == 11 and len(data) >= 8:
            return str(struct.unpack_from('<Q', data)[0])
    except (UnicodeDecodeError, struct.error):
        pass
    text = data[:limit].hex(' ')
    return text + (f" ... ({len(data):,} bytes)" if len(data) > limit else '')


def live_value_text(value):
    """python-registry's value, read right: it takes a REG_DWORD_BIG_ENDIAN
    kept inline (in the record's data-offset field, as every 4-byte value
    is) from the four bytes after that field -- the type -- so 4 read as
    83,886,080 (NIST's cfreds-2017-winreg data-types hives)."""
    try:
        if value.value_type() == 5:
            record = value._vkrecord
            at = record.absolute_offset(0x8)
            return str(int.from_bytes(record._buf[at:at + 4], 'big'))
        return str(value.value())
    except Exception as exc:
        return f"(unreadable: {exc})"


def _list(hive, offset, count):
    raw = hive.at(offset + 4, 4 * count)
    return [struct.unpack_from('<I', raw, 4 * i)[0]
            for i in range(len(raw) // 4)]


def recover(data):
    """{'keys': [deleted key], 'values': [deleted value]} -- a key with its
    'path', 'written' and 'values'; a value with its 'key' path ('' for an
    orphan), name, type, data and 'complete' (its data cells were still
    the value's to read)."""
    hive = Hive(data)
    keys, values = {}, {}
    for offset, size in hive.free:
        for step in range(0, size - 4, 8):
            at = offset + step
            limit = size - step - 4
            record = _key(hive, at, limit) if hive.at(at + 4, 2) == b'nk' \
                else _value(hive, at, limit) \
                if hive.at(at + 4, 2) == b'vk' else None
            if record is None:
                continue
            (keys if 'parent' in record else values)[at] = record

    def key_record(offset):
        if offset in keys:
            return keys[offset]
        cell = hive.cells.get(offset)
        if cell is None:
            return None
        return _key(hive, offset, cell[0] - 4)

    paths = {}

    def path_of(offset):
        """The key's path, '/'-joined from the root; None when a key on the
        way is gone. Memoised: NIST's deepest test hive nests 512 keys."""
        start, chain, seen = offset, [], set()
        while offset not in seen:
            if offset in paths:
                break
            seen.add(offset)
            record = key_record(offset)
            if record is None:
                paths.update((o, None) for o, _n in chain)
                return None
            if record['root']:
                paths[offset] = ''
                break
            chain.append((offset, record['name']))
            offset = record['parent']
        prefix = paths.get(offset, '')
        if prefix is None:
            paths.update((o, None) for o, _n in chain)
            return None
        for node, name in reversed(chain):
            prefix = prefix + '/' + name
            paths[node] = prefix
        return paths.get(start, prefix) or '/'

    # Which deleted value belongs to which key: the value list of a deleted
    # key, or of a live key that still names it.
    owner, stale = {}, {}
    live_value_key = {}
    # Deleted keys (wherever in a free cell they lie) and live ones.
    candidates = [(offset, record, False) for offset, record in keys.items()]
    if values:
        # Only a live key's value count and list are needed -- parsing a
        # million live keys whole took NIST's deepest hive ten seconds.
        for offset, cell in hive.cells.items():
            if cell[1] and hive.at(offset + 4, 2) == b'nk':
                count, where = struct.unpack_from(
                    '<II', hive.at(offset + 4 + 0x24, 8).ljust(8, b'\x00'))
                candidates.append((offset, {'values': count,
                                            'value_list': where}, True))
    for offset, record, live in candidates:
        if record is None or record['value_list'] in (0, 0xFFFFFFFF):
            continue
        for value in _list(hive, record['value_list'], record['values']):
            if value in values:
                owner.setdefault(value, offset)
            elif live:
                live_value_key[value] = offset
        # Windows shortens a key's list in place: the slots past its count
        # still name values deleted from it -- or, when the cell was some
        # other key's list before (cells are not cleared when reused),
        # values of that key. A hint, never the owner: NIST's nrd-05 has
        # a deleted value in the stale slots of an unrelated key's list.
        list_cell = hive.cells.get(record['value_list'])
        if list_cell:
            for value in _list(hive, record['value_list'],
                               (list_cell[0] - 4) // 4)[record['values']:]:
                if value in values:
                    stale.setdefault(value, offset)
    # A value deleted from a live key is in no list the key has now -- it
    # got a new, shorter one -- but the old list's freed cell still holds
    # its offsets beside those of the key's remaining values.
    for offset, size in hive.free:
        words = hive.at(offset + 4, size - 4)
        listed = [struct.unpack_from('<I', words, i)[0]
                  for i in range(0, len(words) - 3, 4)]
        lost = [w for w in listed if w in values and w not in owner]
        if not lost:
            continue
        holders = {live_value_key[w] for w in listed if w in live_value_key}
        if len(holders) == 1:
            holder = holders.pop()
            for value in lost:
                owner[value] = holder

    found_keys = []
    for offset, record in keys.items():
        parent_path = path_of(record['parent'])
        if parent_path is None:
            parent_path = '?'                 # its parent is gone too
        record['path'] = (parent_path.rstrip('/') + '/' + record['name'])
        record['parent_deleted'] = record['parent'] in keys
        record['value_records'] = []
        found_keys.append(record)
    by_offset = {k['offset']: k for k in found_keys}
    found_values = []
    for offset, record in values.items():
        key = owner.get(offset)
        record['key'] = (path_of(key) or '?') if key is not None else ''
        hint = stale.get(offset) if key is None else None
        record['listed_with'] = (path_of(hint) or '') if hint is not None else ''
        if key in by_offset:
            by_offset[key]['value_records'].append(record)
        found_values.append(record)
    found_keys.sort(key=lambda k: k['path'])
    found_values.sort(key=lambda v: (v['key'], v['name']))
    return {'keys': found_keys, 'values': found_values}

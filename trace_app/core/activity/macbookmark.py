"""macOS bookmark data ("book"), as the shared file lists (.sfl2, .sfl3)
and recent-items plists keep it: where a file was, and on which volume.

A bookmark is a header, then items -- each a length, a type and data --
and a table of contents mapping keys to item offsets. The keys read here:
0x1004 the path's components, 0x1040 the file's creation date, 0x2002 the
volume's path, 0x2010 its name and 0xf017 the name shown. Strings are
UTF-8 (0x0101), arrays are lists of item offsets (0x0601) and dates are
big-endian doubles of seconds since 2001 (0x0400). Layout: the format as
documented by mac_alias and Howard Oakley; no Qt, no external library.
"""

import struct

from trace_app.core.activity import times

_PATH, _CREATED = 0x1004, 0x1040
_VOLUME_PATH, _VOLUME_NAME, _DISPLAY = 0x2002, 0x2010, 0xf017


class BookmarkError(Exception):
    pass


def _item(data, start, offset):
    position = start + offset
    if position + 8 > len(data):
        raise BookmarkError("Item outside the bookmark")
    length, kind = struct.unpack_from('<II', data, position)
    body = data[position + 8:position + 8 + length]
    base = kind & 0xff00
    if kind == 0x0101 or base == 0x0100:
        return body.decode('utf-8', 'replace')
    if kind == 0x0601 or base == 0x0600:
        return [_item(data, start, o) for o in
                struct.unpack_from(f'<{length // 4}I', body)]
    if kind == 0x0400:
        return times.mac_absolute(struct.unpack('>d', body[:8])[0])
    if base == 0x0300:                      # numbers
        if len(body) == 8:
            return struct.unpack('<q', body)[0]
        if len(body) == 4:
            return struct.unpack('<i', body)[0]
    if kind == 0x0201:
        return bytes(body)
    return None


def parse(data):
    """{'path', 'created', 'volume', 'volume_path', 'name'} of a bookmark."""
    if len(data) < 48 or data[:4] != b'book':
        raise BookmarkError("Not a bookmark")
    header = struct.unpack_from('<I', data, 12)[0]
    start = header
    toc = struct.unpack_from('<I', data, start)[0]
    entries = {}
    seen = set()
    while toc and toc not in seen and start + toc + 20 <= len(data):
        seen.add(toc)
        position = start + toc
        _length, magic, _ident, following, count = struct.unpack_from(
            '<IIIII', data, position)
        if magic != 0xfffffffe:
            break
        for index in range(count):
            key, offset, _reserved = struct.unpack_from(
                '<III', data, position + 20 + index * 12)
            entries.setdefault(key & 0x7fffffff, offset)
        toc = following

    def value(key):
        if key not in entries:
            return None
        try:
            return _item(data, start, entries[key])
        except (BookmarkError, struct.error, UnicodeError):
            return None

    parts = value(_PATH) or []
    return {'path': '/' + '/'.join(p for p in parts if isinstance(p, str))
            if parts else '',
            'created': value(_CREATED), 'volume': value(_VOLUME_NAME) or '',
            'volume_path': value(_VOLUME_PATH) or '',
            'name': value(_DISPLAY) or ''}

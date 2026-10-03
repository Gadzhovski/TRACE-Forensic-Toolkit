"""The Recycle Bin: what was deleted, from where, and when.

Vista and later keep a pair of files per deleted item in
$Recycle.Bin\\<user SID>\\: $R... holds the content and $I... the record --
original path, size and deletion time (version 1 up to 8.1, version 2 from
Windows 10, which stores the path's length instead of a fixed 260 chars).
XP keeps one INFO2 file per user in RECYCLER\\<SID>\\ with a record per item.
"""

import struct

from trace_app.core.activity import times


def parse_i_file(data):
    """{'path', 'size', 'deleted'} from a $I file, or None."""
    if len(data) < 24:
        return None
    version, size, deleted = struct.unpack_from('<QQQ', data, 0)
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2 and len(data) >= 28:
        length = struct.unpack_from('<I', data, 24)[0]
        raw = data[28:28 + 2 * length]
    else:
        return None
    path = raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]
    if not path:
        return None
    return {'path': path, 'size': size, 'deleted': times.filetime(deleted),
            'version': version}


def parse_info2(data):
    """[{'path', 'size', 'deleted', 'index', 'drive'}] from an XP INFO2."""
    if len(data) < 20:
        return []
    record_size = struct.unpack_from('<I', data, 12)[0]
    if record_size not in (280, 800):
        return []
    out = []
    at = 20
    while at + record_size <= len(data):
        record = data[at:at + record_size]
        index, drive, deleted, size = struct.unpack_from('<IIQI', record, 260)
        if record_size == 800:
            path = record[280:800].decode('utf-16-le', 'replace')
        else:
            path = record[:260].decode('cp1252', 'replace')
        path = path.split('\x00', 1)[0]
        if path:
            out.append({'path': path, 'size': size, 'index': index,
                        'drive': chr(ord('A') + drive) if drive < 26 else '',
                        'deleted': times.filetime(deleted)})
        at += record_size
    return out

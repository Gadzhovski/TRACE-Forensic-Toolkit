"""Safari Cookies.binarycookies (no Qt).

Safari keeps its cookies in a binary file: 'cook' magic, a big-endian page
count then each page's size, then the pages. A page is a little-endian
record count and offsets, then the records; a record holds its flags, the
offsets of the url, name, path and value strings, and the creation and
expiry times (Cocoa seconds since 2001, as doubles).

`records(data, path, ref)` returns one `activity.record` per cookie: the
host, the name and the creation time (the value is kept, as a cookie's
value is evidence of a session, not a password). Checked against plaso's
Cookies.binarycookies and its expected values (tests/test_safari_cookies.py).
"""

import logging
import struct

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.SafariCookies')


def _string(data, base, offset):
    if not offset:
        return ''
    end = data.find(b'\x00', base + offset)
    return data[base + offset:end].decode('utf-8', 'replace')


def _cookie(page, offset):
    """One cookie record at `offset` within a page's bytes."""
    (size, _unknown1, flags, _unknown2, url_offset, name_offset, path_offset,
     value_offset, _end, expiry, creation) = struct.unpack_from(
        '<iiiiiiiiqdd', page, offset)
    return {
        'url': _string(page, offset, url_offset),
        'name': _string(page, offset, name_offset),
        'path': _string(page, offset, path_offset),
        'value': _string(page, offset, value_offset),
        'flags': flags,
        'creation': times.mac_absolute(creation),
        'expiry': times.mac_absolute(expiry),
    }


def records(data, path, ref):
    if data[:4] != b'cook':
        return []
    out = []
    page_count = struct.unpack_from('>I', data, 4)[0]
    page_sizes = struct.unpack_from('>' + 'I' * page_count, data, 8)
    offset = 8 + 4 * page_count
    for page_size in page_sizes:
        page = data[offset:offset + page_size]
        offset += page_size
        if page[:4] != b'\x00\x00\x01\x00':
            continue
        count = struct.unpack_from('<I', page, 4)[0]
        starts = struct.unpack_from('<' + 'I' * count, page, 8)
        for start in starts:
            try:
                cookie = _cookie(page, start)
            except struct.error:
                continue
            secure = bool(cookie['flags'] & 1)
            out.append(record(
                'browser', 'Safari cookie', cookie['creation'],
                'Cookie', f"{cookie['url']} — {cookie['name']}",
                {'host': cookie['url'], 'name': cookie['name'],
                 'path': cookie['path'], 'value': cookie['value'],
                 'secure': secure,
                 'expires': times.iso(cookie['expiry']),
                 'basis': 'when the cookie was created'},
                path=path, ref=ref))
    return out

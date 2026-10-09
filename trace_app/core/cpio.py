"""CPIO archives, read from bytes (no Qt; pure Python -- the standard
library has no cpio module).

CPIO is what Linux initramfs images, RPM payloads and some backup tools
are made of. Four formats, all read here (as GNU cpio writes them; checked
against dfvfs's test archives):

* 'bin'  -- old binary, 26-byte header of 16-bit words in the writer's
  byte order (magic 070707 octal); the time and size are two words, the
  high one first; name and data padded to even
* 'odc'  -- portable ASCII, '070707' + octal fields, 76 bytes, no padding
* 'newc' -- '070701' + 8-digit hex fields, 110 bytes; name (after the
  header) and data padded to a multiple of 4
* 'crc'  -- '070702', as newc, with a checksum: the sum of the data's
  bytes, modulo 2**32 -- verified here, and a member that fails it is
  marked damaged rather than refused

The archive ends at the member named 'TRAILER!!!'. A symbolic link's data
is its target.
"""

import datetime
import struct

TRAILER = 'TRAILER!!!'
_TYPE_MASK, _DIRECTORY, _LINK = 0o170000, 0o040000, 0o120000


class CpioError(ValueError):
    pass


def format_of(data):
    """'bin-le', 'bin-be', 'odc', 'newc', 'crc' or None, from the start of
    `data`, after checking that the first header is consistent -- the
    binary magic is two bytes, so a name length and a NUL-terminated name
    must make sense too."""
    if len(data) < 26:
        return None
    if data[:6] == b'070707':
        kind = 'odc'
    elif data[:6] == b'070701':
        kind = 'newc'
    elif data[:6] == b'070702':
        kind = 'crc'
    elif data[:2] == b'\xc7\x71':
        kind = 'bin-le'
    elif data[:2] == b'\x71\xc7':
        kind = 'bin-be'
    else:
        return None
    try:
        member, _next = _header(data, 0, kind)
    except (CpioError, ValueError, struct.error):
        return None
    return kind if member['name'] else None


def _header(data, offset, kind):
    """(member dict with 'data_offset', offset of the next header)."""
    if kind in ('bin-le', 'bin-be'):
        order = '<' if kind == 'bin-le' else '>'
        head = data[offset:offset + 26]
        if len(head) < 26:
            raise CpioError("truncated header")
        (magic, _dev, _ino, mode, _uid, _gid, _nlink, _rdev, mtime_hi,
         mtime_lo, namesize, size_hi, size_lo) = struct.unpack(
            order + '13H', head)
        if magic != 0o070707:
            raise CpioError(f"no header at byte {offset:,}")
        mtime = (mtime_hi << 16) | mtime_lo
        size = (size_hi << 16) | size_lo
        name_at = offset + 26
        data_at = name_at + namesize + (namesize & 1)
        following = data_at + size + (size & 1)
        check = None
    elif kind == 'odc':
        head = data[offset:offset + 76]
        if len(head) < 76 or head[:6] != b'070707':
            raise CpioError(f"no header at byte {offset:,}")
        fields = head.decode('ascii')
        mode = int(fields[18:24], 8)
        mtime = int(fields[48:59], 8)
        namesize = int(fields[59:65], 8)
        size = int(fields[65:76], 8)
        name_at = offset + 76
        data_at = name_at + namesize
        following = data_at + size
        check = None
    else:
        head = data[offset:offset + 110]
        magic = b'070701' if kind == 'newc' else b'070702'
        if len(head) < 110 or head[:6] != magic:
            raise CpioError(f"no header at byte {offset:,}")
        fields = [int(head[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        mode, mtime, size, namesize = (fields[1], fields[5], fields[6],
                                       fields[11])
        check = fields[12] if kind == 'crc' else None
        name_at = offset + 110
        data_at = name_at + namesize
        data_at += -(data_at - offset) % 4
        following = data_at + size
        following += -(following - offset) % 4
    raw = data[name_at:name_at + namesize]
    if len(raw) < namesize or not namesize or raw[-1:] != b'\0':
        raise CpioError(f"bad name at byte {offset:,}")
    name = raw[:-1].decode('utf-8', 'surrogateescape')
    return {'name': name, 'mode': mode, 'mtime': mtime, 'size': size,
            'data_offset': data_at, 'check': check}, following


def members(data):
    """Every member: [{'name', 'size', 'is_dir', 'is_link', 'modified',
    'data_offset', 'damaged'}], stopping at the trailer. An archive cut
    short keeps what came before, and says so in its last member."""
    kind = format_of(data)
    if kind is None:
        raise CpioError("not a cpio archive")
    out, offset = [], 0
    while offset < len(data):
        try:
            member, following = _header(data, offset, kind)
        except CpioError as exc:
            if out:
                out[-1]['damaged'] = (f"the archive breaks off after this "
                                      f"member ({exc})")
                break
            raise
        if member['name'] == TRAILER:
            break
        end = member['data_offset'] + member['size']
        damaged = ''
        if end > len(data):
            damaged = (f"cut short: {len(data) - member['data_offset']:,} "
                       f"of {member['size']:,} bytes present")
        elif member['check'] is not None:
            total = sum(data[member['data_offset']:end]) & 0xFFFFFFFF
            if total != member['check']:
                damaged = (f"fails its checksum ({total:#x}, recorded "
                           f"{member['check']:#x})")
        kind_bits = member['mode'] & _TYPE_MASK
        out.append({
            # './etc/x' and '/etc/x' as 'etc/x' -- never '.profile' as
            # 'profile'.
            'name': _clean(member['name']),
            'size': member['size'],
            'is_dir': kind_bits == _DIRECTORY,
            'is_link': kind_bits == _LINK,
            'modified': _time(member['mtime']),
            'data_offset': member['data_offset'],
            'damaged': damaged,
            'format': kind})
        offset = following
    return out


def _clean(name):
    while name.startswith('./'):
        name = name[2:]
    return name.lstrip('/') or name


def read(data, name, limit=None):
    """A member's bytes (a link's target), up to `limit`."""
    for member in members(data):
        if member['name'] == name and not member['is_dir']:
            start = member['data_offset']
            size = member['size'] if limit is None else min(member['size'],
                                                            limit)
            return data[start:start + size]
    raise CpioError(f"No member {name!r}")


def _time(seconds):
    try:
        return datetime.datetime.fromtimestamp(
            seconds, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return ''

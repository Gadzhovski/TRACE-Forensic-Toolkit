"""NTFS directory index slack: the names a folder no longer lists, still in
its $I30 index buffers.

A folder's entries are $FILE_NAME copies kept sorted in 4 KB index buffers
($INDEX_ALLOCATION:$I30, 'INDX', protected by fixups like MFT records).
Removing a name, or re-sorting a buffer, moves the live entries down and
leaves the old bytes after the buffer's used size -- slack. Those stale
entries are whole $FILE_NAME attributes: the name, the parent folder's
reference, its four times and its size, for files deleted, renamed or moved
away since (and older copies of names still there, which are kept apart).

Carving follows the rule dfir_ntfs uses: four consecutive FILETIMEs in a
plausible range mark a $FILE_NAME, starting 8 bytes before them; an entry
whose first bytes were overwritten (the parent reference) is still read.
A name must be 1-255 characters, with no '/' or NUL, in a known namespace.
"""

import struct

INDEX_ALLOCATION = 0xA0
#: Plausible FILETIMEs: 1985-01-01 .. 2100-01-01.
EARLIEST = 119600064000000000
LATEST = 157469184000000000
NAMESPACES = {0: 'POSIX', 1: 'Win32', 2: 'DOS', 3: 'Win32 & DOS'}
DIRECTORY_FLAG = 0x10000000


def unprotect(buffer):
    """Apply an INDX buffer's fixups; None if it is not one or is torn."""
    if buffer[:4] != b'INDX' or len(buffer) < 512:
        return None
    buffer = bytearray(buffer)
    usa_offset, usa_count = struct.unpack_from('<HH', buffer, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(buffer):
        return None
    check = bytes(buffer[usa_offset:usa_offset + 2])
    for stride in range(1, usa_count):
        end = stride * 512
        if end > len(buffer):
            break
        if bytes(buffer[end - 2:end]) != check:
            return None
        fix = usa_offset + stride * 2
        buffer[end - 2:end] = buffer[fix:fix + 2]
    return bytes(buffer)


def buffer_size(data):
    """An index's buffer size, from its first buffer's fixup count."""
    if len(data) < 8 or data[:4] != b'INDX':
        return None
    count = struct.unpack_from('<H', data, 6)[0]
    size = (count - 1) * 512
    return size if 512 <= size <= 65536 else None


def slack_of(buffer):
    """The bytes after an unprotected buffer's used entries."""
    used = struct.unpack_from('<I', buffer, 0x18 + 4)[0]
    start = 0x18 + used
    return buffer[start:] if 0 < start < len(buffer) else b''


def _plausible(value):
    return EARLIEST <= value <= LATEST


def carve(slack):
    """[dict] of the $FILE_NAME attributes in a stretch of index slack:
    name, namespace, parent (index, sequence) or None when overwritten,
    times (created, modified, changed, accessed), size, allocated, is_dir,
    and the file's own MFT reference when the index entry header survived."""
    out = []
    position = 1 if len(slack) % 2 else 0
    while position + 32 <= len(slack):
        times = struct.unpack_from('<QQQQ', slack, position)
        if not all(_plausible(t) for t in times) or \
                not (position >= 8 or position in (0, 4)):
            position += 2
            continue
        start = position - 8
        rest = slack[position + 32:]
        if len(rest) < 26:
            break
        allocated, size, flags, _reparse, length, namespace = \
            struct.unpack_from('<QQIIBB', rest, 0)
        name_raw = rest[26:26 + 2 * length]
        if not 1 <= length <= 255 or namespace not in NAMESPACES or \
                len(name_raw) != 2 * length:
            position += 2
            continue
        name = name_raw.decode('utf-16-le', 'replace')
        if '/' in name or '\x00' in name or '�' in name or \
                not name.isprintable():
            position += 2
            continue
        parent = None
        if start >= 0:
            reference = struct.unpack_from('<Q', slack, start)[0]
            parent = (reference & 0xFFFFFFFFFFFF, reference >> 48)
        own = None
        if start >= 16:
            reference, entry_length, content_length = struct.unpack_from(
                '<QHH', slack, start - 16)
            index = reference & 0xFFFFFFFFFFFF
            # MFT entry numbers are 32-bit in practice; a larger one is the
            # bytes of something else.
            if content_length == 66 + 2 * length and \
                    entry_length >= content_length + 16 and \
                    0 < index < 1 << 32:
                own = (index, reference >> 48)
        out.append({'name': name, 'namespace': NAMESPACES[namespace],
                    'parent': parent, 'file': own, 'times': times,
                    'size': size, 'allocated': allocated,
                    'is_dir': bool(flags & DIRECTORY_FLAG)})
        position += 32 + 26 + 2 * length
        position += position % 2
    return out


def index_data(tsk_file):
    """The $INDEX_ALLOCATION:$I30 bytes of a folder (pytsk3 File), or None."""
    import pytsk3
    for attribute in tsk_file:
        info = attribute.info
        if int(info.type) != INDEX_ALLOCATION:
            continue
        name = info.name.decode('utf-8', 'replace') if info.name else ''
        if name != '$I30':
            continue
        size = int(info.size)
        if not size or size > 256 * 1024 * 1024:
            return None
        return tsk_file.read_random(0, size,
                                    pytsk3.TSK_FS_ATTR_TYPE_NTFS_IDXALLOC,
                                    info.id)
    return None


def folder_slack(data):
    """Every $FILE_NAME carved from a folder's index buffers' slack, each
    once (the same stale entry is often in several buffers)."""
    size = buffer_size(data or b'')
    if size is None:
        return []
    found, seen = [], set()
    for at in range(0, len(data) - size + 1, size):
        buffer = unprotect(data[at:at + size])
        if buffer is None:
            continue
        for item in carve(slack_of(buffer)):
            key = (item['name'], item['times'], item['size'])
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return found

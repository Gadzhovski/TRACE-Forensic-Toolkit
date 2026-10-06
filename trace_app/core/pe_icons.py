"""The icon a Windows program carries, read from its resources (no Qt).

Explorer shows a program by the first icon group in its resource section
(RT_GROUP_ICON); each group lists the same picture at several sizes, each
image an RT_ICON resource. This reads only what it needs through
`read(offset, length)` -- the headers, the resource directory and the one
image chosen -- so a 200 MB installer costs a few small reads.

`program_icon(read, size)` returns the bytes of a one-image .ico file (or
the PNG Windows keeps for 256-pixel icons), which Qt's and Pillow's image
readers open, or None.
"""

import logging
import struct

logger = logging.getLogger('TRACE.PeIcons')

RT_ICON, RT_GROUP_ICON = 3, 14
#: Extensions whose files are Windows programs and carry their own icon.
PROGRAM_EXTENSIONS = frozenset({'exe', 'scr', 'cpl'})
#: An icon image larger than this is not one (a damaged table).
_MAX_IMAGE = 4 * 1024 * 1024
_MAX_ENTRIES = 4096
_PNG = b'\x89PNG\r\n\x1a\n'


class _Pe:
    """Just enough of a PE to find its resources."""

    def __init__(self, read):
        self.read = read
        head = read(0, 0x40)
        if len(head) < 0x40 or head[:2] != b'MZ':
            raise ValueError("not an MZ file")
        pe = struct.unpack_from('<I', head, 0x3C)[0]
        header = read(pe, 24)
        if len(header) < 24 or header[:4] != b'PE\x00\x00':
            raise ValueError("no PE header")
        sections, optional_size = struct.unpack_from('<H12xH', header, 6)
        optional = read(pe + 24, optional_size)
        if len(optional) < 2:
            raise ValueError("no optional header")
        magic = struct.unpack_from('<H', optional, 0)[0]
        directories = {0x10B: 96, 0x20B: 112}.get(magic)
        if directories is None or len(optional) < directories + 24:
            raise ValueError("unknown optional header")
        self.rsrc_rva, self.rsrc_size = struct.unpack_from(
            '<II', optional, directories + 16)
        table = read(pe + 24 + optional_size, 40 * min(sections, 96))
        self.sections = []
        for index in range(len(table) // 40):
            size, rva, raw_size, raw = struct.unpack_from(
                '<IIII', table, index * 40 + 8)
            self.sections.append((rva, max(size, raw_size), raw))

    def offset(self, rva):
        for start, size, raw in self.sections:
            if start <= rva < start + size:
                return raw + (rva - start)
        return None

    def at(self, rva, length):
        offset = self.offset(rva)
        if offset is None:
            return b''
        return self.read(offset, length)


def _entries(pe, directory_rva):
    """[(name or id, is_directory, rva)] of one resource directory."""
    head = pe.at(directory_rva, 16)
    if len(head) < 16:
        return []
    named, ids = struct.unpack_from('<HH', head, 12)
    count = min(named + ids, _MAX_ENTRIES)
    data = pe.at(directory_rva + 16, 8 * count)
    found = []
    for index in range(len(data) // 8):
        name, target = struct.unpack_from('<II', data, index * 8)
        key = ('name', name & 0x7FFFFFFF) if name & 0x80000000 else name
        found.append((key, bool(target & 0x80000000),
                      pe.rsrc_rva + (target & 0x7FFFFFFF)))
    return found


def _leaf(pe, rva):
    """The first data entry under a name directory: its bytes."""
    for _depth in range(4):
        children = _entries(pe, rva)
        if not children:
            return None
        _key, is_dir, target = children[0]
        if not is_dir:
            entry = pe.at(target, 16)
            if len(entry) < 8:
                return None
            data_rva, size = struct.unpack_from('<II', entry, 0)
            if not 0 < size <= _MAX_IMAGE:
                return None
            return pe.at(data_rva, size)
        rva = target
    return None


def _choose(group, size):
    """The group entry to use for an icon shown at `size` pixels: the
    smallest at least that big (or else the largest), most colours."""
    if len(group) < 6:
        return None
    count = struct.unpack_from('<H', group, 4)[0]
    choices = []
    for index in range(min(count, 256)):
        entry = group[6 + index * 14: 20 + index * 14]
        if len(entry) < 14:
            break
        width, height, colours, _reserved, planes, bits, length, ident = \
            struct.unpack('<BBBBHHIH', entry)
        width = width or 256
        choices.append((width, bits or 32, entry, ident))
    if not choices:
        return None
    big_enough = [c for c in choices if c[0] >= size]
    pool = big_enough or choices
    best = min(pool, key=lambda c: (c[0], -c[1])) if big_enough else \
        max(pool, key=lambda c: (c[0], c[1]))
    return best


def program_icon(read, size=32):
    """A program's icon as .ico (or PNG) bytes, or None when it has none
    or its resources cannot be read."""
    try:
        pe = _Pe(read)
        if not pe.rsrc_rva or not pe.rsrc_size:
            return None
        types = {key: target for key, is_dir, target in
                 _entries(pe, pe.rsrc_rva) if is_dir}
        if RT_GROUP_ICON not in types or RT_ICON not in types:
            return None
        # Named groups sort before numbered ones, as Explorer reads them.
        groups = _entries(pe, types[RT_GROUP_ICON])
        if not groups:
            return None
        group = _leaf(pe, groups[0][2]) if groups[0][1] else None
        chosen = _choose(group or b'', size)
        if chosen is None:
            return None
        _width, _bits, entry, ident = chosen
        images = {key: target for key, is_dir, target in
                  _entries(pe, types[RT_ICON])}
        if ident not in images:
            return None
        image = _leaf(pe, images[ident])
        if not image:
            return None
        if image.startswith(_PNG):
            return bytes(image)
        # One ICONDIRENTRY: the group's entry with the image's offset in
        # place of its resource id.
        directory = struct.pack('<HHH', 0, 1, 1)
        header = entry[:8] + struct.pack('<II', len(image), 22)
        return directory + header + bytes(image)
    except (ValueError, struct.error, OSError) as exc:
        logger.debug("No program icon: %s", exc)
        return None


def is_program(name):
    return '.' in (name or '') and \
        name.rsplit('.', 1)[-1].lower() in PROGRAM_EXTENSIONS

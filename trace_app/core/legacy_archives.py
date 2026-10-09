"""Older and Windows-native containers, read from bytes (no Qt; pure
Python -- none has a library with wheels on every platform).

NIST's "Searching Container Files" set (cfreds-archive.nist.gov) hides
one sentence in each of 17 container types; TRACE found it in 11. These
are five of the six it missed (StuffIt X, the sixth, is proprietary and
undocumented):

* 'cab'      Microsoft Cabinet (MS-CAB): folders of CFDATA blocks. MSZIP
             blocks are 'CK' + raw Deflate, each primed with the 32 KB
             before it (the spec's rule); stored blocks as they are. LZX
             and Quantum are reported, not read.
* 'lzh'      LHA / LZH: header levels 0, 1 and 2; -lh0- (stored), -lhd-
             (directory) and -lh5- / -lh6- / -lh7- (LZSS with static
             Huffman blocks; 8, 32 and 64 KB windows). Each member's
             CRC-16 is checked: a mismatch marks it damaged.
* 'alz'      ALZip: 'ALZ\\x01', then a 'BLZ\\x01' header per member
             (stored, bzip2 or raw Deflate; CRC-32 checked). Names are
             CP949, as ALZip writes them.
* 'uue'      uuencoded (and 'begin-base64') text: one member, the file it
             carries.
* 'compress' Unix compress (.Z): LZW, 9 to 16-bit codes, with
             ncompress's habit of discarding the rest of a group of codes
             when the width grows or the table is cleared.

`kind_of(data)` names one; `members(data, kind)` lists; `read(data, kind,
name, limit)` gives a member's bytes. Damage is reported, not raised,
where a member can still be read in part.
"""

import binascii
import bz2
import datetime
import re
import struct
import zlib

KINDS = ('cab', 'lzh', 'alz', 'uue', 'compress')


class LegacyError(ValueError):
    pass


def kind_of(data):
    """One of KINDS, or None -- from the first bytes, checked further than
    the magic where the magic is short."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return None
    if data[:8] == b'MSCF\x00\x00\x00\x00' and len(data) >= 36:
        return 'cab'
    if data[:4] == b'ALZ\x01' and data[8:12] in (b'BLZ\x01', b'CLZ\x01'):
        return 'alz'
    if data[:2] == b'\x1f\x9d' and 9 <= data[2] & 0x1F <= 16:
        return 'compress'
    if _lha_header(data, 0) is not None:
        return 'lzh'
    if _uue_start(data) is not None:
        return 'uue'
    return None


def members(data, kind):
    """[{'name', 'size', 'compressed_size', 'is_dir', 'modified',
    'encrypted', 'crc', 'damaged', 'method'}]."""
    return [{key: value for key, value in m.items() if not key.startswith('_')}
            for m in _members(data, kind)]


def read(data, kind, name, limit=None):
    """The bytes of member `name` (the only one, for uue/compress)."""
    found = _members(data, kind)
    member = next((m for m in found if m['name'] == name), None) \
        if name else (found[0] if len(found) == 1 else None)
    if member is None:
        raise LegacyError(f"No member {name!r}")
    if member['is_dir']:
        return b''
    if limit is not None and member['size'] > limit:
        raise LegacyError(f"{member['name']} is {member['size']:,} bytes, "
                          f"over the {limit:,}-byte limit")
    return member['_read']()


def _members(data, kind):
    data = bytes(data)
    if kind == 'cab':
        return _cab(data)
    if kind == 'lzh':
        return _lha(data)
    if kind == 'alz':
        return _alz(data)
    if kind == 'uue':
        return _uue(data)
    if kind == 'compress':
        return _compress(data)
    raise LegacyError(f"Not a {kind}")


def _entry(name, size, packed, is_dir=False, modified='', crc='',
           method='', reader=None, encrypted=False):
    return {'name': name, 'size': size, 'compressed_size': packed,
            'is_dir': is_dir, 'modified': modified, 'encrypted': encrypted,
            'crc': crc, 'damaged': False, 'method': method,
            '_read': reader or (lambda: b'')}


def _dos_time(value):
    """'YYYY-MM-DD HH:MM:SS' of a DOS date (high word) and time (low word):
    local wall-clock time, as the archive recorded it."""
    date, time = value >> 16, value & 0xFFFF
    try:
        return datetime.datetime(
            1980 + (date >> 9), (date >> 5) & 15, date & 31, time >> 11,
            (time >> 5) & 63, (time & 31) * 2).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return ''


# --- Microsoft Cabinet ---------------------------------------------------

_CAB_METHODS = {0: 'stored', 1: 'MSZIP', 2: 'Quantum', 3: 'LZX'}


def _cab(data):
    (_sig, _r1, size, _r2, files_at, _r3, _minor, _major, folder_count,
     file_count, flags, _set, _index) = struct.unpack_from('<4sIIIIIBBHHHHH',
                                                          data, 0)
    pos = 36
    folder_reserve = data_reserve = 0
    if flags & 4:
        header_reserve, folder_reserve, data_reserve = struct.unpack_from(
            '<HBB', data, pos)
        pos += 4 + header_reserve
    for flag in (1, 2):                 # previous / next cabinet names
        if flags & flag:
            for _ in range(2):
                end = data.index(b'\x00', pos)
                pos = end + 1
    folders = []
    for _ in range(folder_count):
        start, blocks, method = struct.unpack_from('<IHH', data, pos)
        folders.append((start, blocks, method & 0x0F))
        pos += 8 + folder_reserve
    cache = {}

    def folder_bytes(index):
        if index not in cache:
            cache[index] = _cab_folder(data, folders[index], data_reserve)
        return cache[index]

    found = []
    pos = files_at
    for _ in range(file_count):
        length, offset, folder, date, time, attributes = struct.unpack_from(
            '<IIHHHH', data, pos)
        end = data.index(b'\x00', pos + 16)
        raw = data[pos + 16:end]
        pos = end + 1
        name = raw.decode('utf-8' if attributes & 0x80 else 'cp1252',
                          'replace').replace('\\', '/')
        if folder >= len(folders):
            # 0xFFFD-0xFFFF: continued from or into another cabinet.
            entry = _entry(name, length, 0, modified=_dos_time(
                date << 16 | time), method='split across cabinets')
            entry['damaged'] = True
            found.append(entry)
            continue
        method = _CAB_METHODS.get(folders[folder][2], 'unknown')

        def reader(folder=folder, offset=offset, length=length):
            return folder_bytes(folder)[offset:offset + length]
        found.append(_entry(name, length, length,
                            modified=_dos_time(date << 16 | time),
                            method=method, reader=reader))
    if size and size > len(data):
        for entry in found:
            entry['damaged'] = True     # the cabinet is cut short
    return found


def _cab_folder(data, folder, reserve):
    start, blocks, method = folder
    if method not in (0, 1):
        raise LegacyError(f"{_CAB_METHODS.get(method, 'unknown')}-"
                          f"compressed cabinet: not read")
    out = bytearray()
    pos = start
    for _ in range(blocks):
        _checksum, packed, plain = struct.unpack_from('<IHH', data, pos)
        pos += 8 + reserve
        block = data[pos:pos + packed]
        pos += packed
        if method == 0:
            out += block
            continue
        if block[:2] != b'CK':
            raise LegacyError("MSZIP block without its 'CK'")
        engine = zlib.decompressobj(-15, zdict=bytes(out[-32768:]))
        piece = engine.decompress(block[2:]) + engine.flush()
        if len(piece) != plain:
            raise LegacyError("MSZIP block of the wrong length")
        out += piece
    return bytes(out)


# --- LHA / LZH -----------------------------------------------------------

_LHA_METHOD = re.compile(rb'-(lh[0-7d]|lz[s45])-')


def _lha_header(data, pos):
    """(member dict, offset after its data) for the header at `pos`, or
    None (an end mark, or not a header)."""
    if pos + 22 > len(data) or data[pos] == 0:
        return None
    method = data[pos + 2:pos + 7]
    if not _LHA_METHOD.fullmatch(method):
        return None
    level = data[pos + 20]
    packed, size, stamp = struct.unpack_from('<III', data, pos + 7)
    directory, name, crc = '', '', None
    if level in (0, 1):
        header = data[pos] + 2
        name_length = data[pos + 21]
        raw = data[pos + 22:pos + 22 + name_length]
        name = raw.decode('cp932', 'replace')
        after = pos + 22 + name_length
        if after + 2 <= len(data):
            crc = struct.unpack_from('<H', data, after)[0]
        modified = _dos_time(stamp)
        body = pos + header
        if level == 1:
            # Extension headers follow the base header and count in the
            # packed size.
            at = body - 2
            extra = 0
            next_size = struct.unpack_from('<H', data, at)[0]
            while next_size:
                block = data[body:body + next_size]
                if len(block) < next_size:
                    return None
                directory, name = _lha_extension(block[:-2], directory,
                                                 name)
                extra += next_size
                body += next_size
                next_size = struct.unpack_from('<H', block, next_size - 2)[0]
            packed -= extra
    elif level == 2:
        header = struct.unpack_from('<H', data, pos)[0]
        crc = struct.unpack_from('<H', data, pos + 21)[0]
        try:
            modified = datetime.datetime.fromtimestamp(
                stamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        except (OverflowError, OSError, ValueError):
            modified = ''
        at = pos + 24
        next_size = struct.unpack_from('<H', data, at)[0]
        at += 2
        while next_size:
            block = data[at:at + next_size]
            if len(block) < next_size:
                return None
            directory, name = _lha_extension(block[:-2], directory, name)
            at += next_size
            next_size = struct.unpack_from('<H', block, next_size - 2)[0]
        body = pos + header
    else:
        return None
    full = (directory + '/' + name if directory and name else
            directory or name).replace('\\', '/')
    full = re.sub('/+', '/', full).strip('/')    # a directory ends in 0xFF
    method = method.decode()
    return ({'name': full, 'method': method, 'size': size, 'packed': packed,
             'modified': modified, 'crc': crc, 'data_at': body,
             'is_dir': method == '-lhd-'}, body + packed)


def _lha_extension(block, directory, name):
    """Apply one extension header ('type' byte, then its data)."""
    if not block:
        return directory, name
    kind, value = block[0], block[1:]
    if kind == 0x01:
        name = value.decode('cp932', 'replace')
    elif kind == 0x02:
        directory = value.replace(b'\xff', b'/').decode('cp932', 'replace')
    return directory, name


def _lha(data):
    found = []
    pos = 0
    while True:
        parsed = _lha_header(data, pos)
        if parsed is None:
            break
        member, pos = parsed
        if pos > len(data):
            raise LegacyError("LHA archive cut short")

        def reader(member=member):
            raw = data[member['data_at']:member['data_at'] + member['packed']]
            plain = _lha_decode(member['method'], raw, member['size'])
            if member['crc'] is not None and crc16(plain) != member['crc']:
                raise LegacyError(f"{member['name']}: CRC-16 mismatch")
            return plain
        entry = _entry(member['name'], member['size'], member['packed'],
                       is_dir=member['is_dir'], modified=member['modified'],
                       crc=f"{member['crc']:04x}" if member['crc'] is not None
                       else '', method=member['method'], reader=reader)
        found.append(entry)
    if not found:
        raise LegacyError("No LHA headers")
    return found


def crc16(data):
    """CRC-16/ARC (LHA's): reflected, polynomial 0x8005, start 0."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class _Bits:
    """MSB-first bit reader."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def get(self, count):
        if count == 0:
            return 0
        value = 0
        for _ in range(count):
            byte = self.pos >> 3
            bit = (self.data[byte] >> (7 - (self.pos & 7))) & 1 \
                if byte < len(self.data) else 0
            value = value << 1 | bit
            self.pos += 1
        return value

    def peek(self, count):
        at = self.pos
        value = self.get(count)
        self.pos = at
        return value


class _Huffman:
    """Canonical codes from lengths (as LHA's make_table assigns them)."""

    def __init__(self, lengths, single=None):
        self.single = single
        self.table = {}
        code = 0
        for length in range(1, 17):
            for symbol, size in enumerate(lengths):
                if size == length:
                    self.table[(length, code)] = symbol
                    code += 1
            code <<= 1

    def decode(self, bits):
        if self.single is not None:
            return self.single
        code = 0
        for length in range(1, 17):
            code = code << 1 | bits.get(1)
            symbol = self.table.get((length, code))
            if symbol is not None:
                return symbol
        raise LegacyError("bad Huffman code")


_NC, _NT, _TBIT, _CBIT = 510, 19, 5, 9
_LH = {'-lh5-': (13, 4), '-lh6-': (15, 5), '-lh7-': (16, 5)}


def _pt_lengths(bits, count, width, special):
    n = bits.get(width)
    if n == 0:
        return _Huffman([], single=bits.get(width))
    lengths = []
    while len(lengths) < n:
        c = bits.get(3)
        if c == 7:
            while bits.get(1):
                c += 1
        lengths.append(c)
        if len(lengths) == special:
            lengths += [0] * bits.get(2)
    lengths += [0] * (count - len(lengths))
    return _Huffman(lengths[:count])


def _c_lengths(bits, pt):
    n = bits.get(_CBIT)
    if n == 0:
        return _Huffman([], single=bits.get(_CBIT))
    lengths = []
    while len(lengths) < n:
        c = pt.decode(bits)
        if c == 0:
            lengths.append(0)
        elif c == 1:
            lengths += [0] * (bits.get(4) + 3)
        elif c == 2:
            lengths += [0] * (bits.get(_CBIT) + 20)
        else:
            lengths.append(c - 2)
    lengths += [0] * (_NC - len(lengths))
    return _Huffman(lengths[:_NC])


def _lha_decode(method, raw, size):
    if method in ('-lh0-', '-lz4-'):
        return raw[:size]
    if method == '-lhd-':
        return b''
    if method not in _LH:
        raise LegacyError(f"LHA method {method}: not read")
    window, pbit = _LH[method]
    bits = _Bits(raw)
    out = bytearray()
    remaining = 0
    c_table = p_table = None
    while len(out) < size:
        if remaining == 0:
            remaining = bits.get(16)
            if remaining == 0 or bits.pos > len(raw) * 8:
                raise LegacyError("LHA stream cut short")
            pt = _pt_lengths(bits, _NT, _TBIT, 3)
            c_table = _c_lengths(bits, pt)
            p_table = _pt_lengths(bits, window + 1, pbit, -1)
        remaining -= 1
        symbol = c_table.decode(bits)
        if symbol < 256:
            out.append(symbol)
            continue
        length = symbol - 256 + 3
        distance = p_table.decode(bits)
        if distance:
            distance = (1 << (distance - 1)) + bits.get(distance - 1)
        start = len(out) - distance - 1
        if start < 0:
            raise LegacyError("LHA match before the start")
        for i in range(length):
            out.append(out[start + i])
    return bytes(out[:size])


# --- ALZip ---------------------------------------------------------------

_ALZ_METHODS = {0: 'stored', 1: 'bzip2', 2: 'Deflate'}


def _alz(data):
    found = []
    pos = 8
    while data[pos:pos + 4] == b'BLZ\x01':
        name_length, attributes, stamp, descriptor, _unknown = \
            struct.unpack_from('<HBIBB', data, pos + 4)
        pos += 13
        width = (descriptor & 0xF0) >> 4
        method, crc, packed, size = 0, None, 0, 0
        if width:
            method, _x, crc = struct.unpack_from('<BBI', data, pos)
            pos += 6
            packed = int.from_bytes(data[pos:pos + width], 'little')
            size = int.from_bytes(data[pos + width:pos + 2 * width], 'little')
            pos += 2 * width
        raw_name = data[pos:pos + name_length]
        pos += name_length
        encrypted = bool(descriptor & 0x01)
        if encrypted:
            pos += 12
        body = pos
        pos += packed
        if pos > len(data):
            raise LegacyError("ALZ archive cut short")
        name = raw_name.decode('cp949', 'replace').replace('\\', '/')
        is_dir = bool(attributes & 0x10)

        def reader(body=body, packed=packed, method=method, size=size,
                   crc=crc, name=name, encrypted=encrypted):
            if encrypted:
                raise LegacyError(f"{name} is encrypted")
            raw = data[body:body + packed]
            if method == 0:
                plain = raw
            elif method == 1:
                plain = bz2.decompress(raw)
            elif method == 2:
                plain = zlib.decompress(raw, -15)
            else:
                raise LegacyError(f"ALZ method {method}: not read")
            if crc is not None and len(plain) == size and \
                    zlib.crc32(plain) & 0xFFFFFFFF != crc:
                raise LegacyError(f"{name}: CRC-32 mismatch")
            return plain
        found.append(_entry(name, size, packed, is_dir=is_dir,
                            modified=_dos_time(stamp),
                            crc=f"{crc:08x}" if crc is not None else '',
                            method=_ALZ_METHODS.get(method, str(method)),
                            reader=reader, encrypted=encrypted))
    if not found:
        raise LegacyError("No ALZ members")
    return found


# --- uuencode ------------------------------------------------------------

_UU_BEGIN = re.compile(rb'begin(-base64)? ([0-7]{3,4}) ([^\r\n]+)\r?\n')


def _uue_start(data):
    """(base64?, name, offset of the first data line) or None. The line
    after 'begin' must decode, or 'begin 644 x' in a letter would pass."""
    match = _UU_BEGIN.match(data[:4096])
    if not match:
        return None
    line = data[match.end():match.end() + 100].split(b'\n', 1)[0].strip(
        b'\r')
    try:
        (binascii.a2b_base64 if match.group(1) else binascii.a2b_uu)(line)
    except (binascii.Error, ValueError):
        return None
    return (bool(match.group(1)),
            match.group(3).decode('utf-8', 'replace').strip(), match.end())


def _uue(data):
    start = _uue_start(data)
    if start is None:
        raise LegacyError("Not uuencoded")
    base64, name, pos = start
    lines = data[pos:].split(b'\n')

    def reader():
        out = bytearray()
        for line in lines:
            line = line.rstrip(b'\r')
            if line in (b'end', b'====') or (not base64 and line == b'`'):
                break
            if not line:
                continue
            out += (binascii.a2b_base64 if base64 else binascii.a2b_uu)(line)
        return bytes(out)
    content = reader()
    return [_entry(name.rsplit('/', 1)[-1], len(content), len(data),
                   method='base64' if base64 else 'uuencode',
                   reader=lambda: content)]


# --- Unix compress (.Z) ----------------------------------------------------

def uncompress(data, limit=None):
    """The bytes of a .Z stream; LegacyError on damage."""
    if data[:2] != b'\x1f\x9d':
        raise LegacyError("Not compress data")
    flags = data[2]
    most, block = flags & 0x1F, flags & 0x80
    if not 9 <= most <= 16:
        raise LegacyError(f"{most}-bit codes")
    body = data[3:]
    total = len(body) * 8
    width, position, group = 9, 0, 0
    table = [bytes([i]) for i in range(256)]
    if block:
        table.append(b'')                         # 256: clear
    previous = None
    out = bytearray()

    def realign(position, group, width):
        # ncompress reads codes in groups of `width` bytes (8 codes) and
        # drops what is left of the group when the width changes.
        span = width * 8
        return group + -(-(position - group) // span) * span

    while position + width <= total:
        at = position >> 3
        code = (int.from_bytes(body[at:at + 3], 'little')
                >> (position & 7)) & ((1 << width) - 1)
        position += width
        if block and code == 256:
            position = realign(position, group, width)
            width, group, previous = 9, position, None
            del table[257:]
            continue
        if code < len(table):
            entry = table[code]
        elif code == len(table) and previous is not None:
            entry = previous + previous[:1]
        else:
            raise LegacyError("damaged compress stream")
        out += entry
        if limit is not None and len(out) > limit:
            raise LegacyError("over the size limit")
        if previous is not None and len(table) < 1 << most:
            table.append(previous + entry[:1])
        previous = entry
        if len(table) >= 1 << width and width < most:
            position = realign(position, group, width)
            width += 1
            group = position
    return bytes(out)


def _compress(data):
    content = uncompress(data)
    return [_entry('', len(content), len(data), method='LZW',
                   reader=lambda: content)]

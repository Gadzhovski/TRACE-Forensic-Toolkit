"""Zstandard decompression in Python (RFC 8878), for evidence compressed
with it: systemd journal fields since systemd 246, and anything else that
turns up. Decoding only.

Python 3.14's standard library has a zstd decoder in C (compression.zstd);
`decompress` uses it when it is there, because it is faster. This module is
what every other Python -- 3.10 to 3.13, and the packaged builds -- uses,
with no compiled library and no wheel to go missing on a platform.

The format: frames (magic 28 B5 2F FD; skippable frames skipped), each a
header and blocks -- raw, RLE or compressed. A compressed block holds
literals (raw, RLE or Huffman-coded in one or four streams) and sequences
(literal length, match length and offset, each FSE-coded) that rebuild the
output from those literals and from what was already written. Tables and
repeat offsets carry from block to block within a frame. A frame's content
checksum (the low 32 bits of XXH64) is verified when present.

Dictionaries are not supported (journals do not use them); a frame that
needs one raises ZstdError rather than producing wrong bytes.
"""

import struct

MAGIC = 0xFD2FB528
MAX_OUTPUT = 512 * 1024 * 1024


class ZstdError(Exception):
    """The data is not valid Zstandard, or needs what is not supported."""


def standard_library():
    try:
        from compression import zstd   # Python 3.14+
    except ImportError:
        return None
    return zstd


def decompress(data, max_output=MAX_OUTPUT):
    """The decompressed bytes of every frame in `data`."""
    library = standard_library()
    if library is not None:
        try:
            return library.decompress(bytes(data))
        except library.ZstdError as exc:
            raise ZstdError(str(exc)) from exc
    return decompress_python(data, max_output)


# --- bit readers -----------------------------------------------------------------

class _Backward:
    """A stream read from its end towards its start, as Huffman and FSE
    streams are written: the last byte's highest set bit marks the end."""

    __slots__ = ('data', 'position')

    def __init__(self, data):
        if not data or not data[-1]:
            raise ZstdError("Bit stream without its end marker")
        self.data = bytes(data)
        self.position = len(data) * 8 - (9 - data[-1].bit_length())

    def _bits(self, start, count):
        if count <= 0:
            return 0
        if start >= 0:
            first, last = start >> 3, (start + count - 1) >> 3
            value = int.from_bytes(self.data[first:last + 1], 'little')
            return (value >> (start & 7)) & ((1 << count) - 1)
        # Past the start of the stream: the missing low bits are zeros.
        available = count + start
        if available <= 0:
            return 0
        value = int.from_bytes(self.data[:((available - 1) >> 3) + 1],
                               'little') & ((1 << available) - 1)
        return value << -start

    def read(self, count):
        self.position -= count
        return self._bits(self.position, count)

    def peek(self, count):
        return self._bits(self.position - count, count)

    def skip(self, count):
        self.position -= count

    @property
    def overflowed(self):
        return self.position < 0


class _Forward:
    """Little-endian bits from the start (FSE table descriptions)."""

    def __init__(self, data):
        self.data = data
        self.position = 0

    def peek(self, count):
        first = self.position >> 3
        value = int.from_bytes(self.data[first:first + 8], 'little')
        return (value >> (self.position & 7)) & ((1 << count) - 1)

    def skip(self, count):
        self.position += count

    @property
    def bytes_used(self):
        return (self.position + 7) >> 3


# --- FSE --------------------------------------------------------------------------

def _highbit(value):
    return value.bit_length() - 1


class _FseTable:
    """A decoding table: per state, (symbol, bits to read, baseline)."""

    __slots__ = ('log', 'symbols', 'bits', 'baselines')

    def __init__(self, counts, log):
        size = 1 << log
        symbols = [0] * size
        high = size - 1
        following = [0] * len(counts)
        for symbol, count in enumerate(counts):
            if count == -1:
                symbols[high] = symbol
                high -= 1
                following[symbol] = 1
            else:
                following[symbol] = count
        position, step, mask = 0, (size >> 1) + (size >> 3) + 3, size - 1
        for symbol, count in enumerate(counts):
            for _ in range(max(count, 0)):
                symbols[position] = symbol
                position = (position + step) & mask
                while position > high:
                    position = (position + step) & mask
        if position:
            raise ZstdError("FSE table counts do not fill the table")
        bits, baselines = [0] * size, [0] * size
        for state in range(size):
            symbol = symbols[state]
            nxt = following[symbol]
            following[symbol] += 1
            bits[state] = log - _highbit(nxt)
            baselines[state] = (nxt << bits[state]) - size
        self.log, self.symbols, self.bits, self.baselines = \
            log, symbols, bits, baselines

    @classmethod
    def rle(cls, symbol):
        table = cls.__new__(cls)
        table.log, table.symbols, table.bits, table.baselines = \
            0, [symbol], [0], [0]
        return table


def _read_fse_counts(data, max_symbol, max_log):
    """(normalized counts, accuracy log, bytes read) of an FSE table
    description."""
    reader = _Forward(data)
    log = reader.peek(4) + 5
    reader.skip(4)
    if log > max_log:
        raise ZstdError("FSE accuracy log too large")
    remaining = (1 << log) + 1
    threshold = 1 << log
    width = log + 1
    counts = []
    while remaining > 1 and len(counts) <= max_symbol:
        largest = (2 * threshold - 1) - remaining
        bits = reader.peek(width)
        if (bits & (threshold - 1)) < largest:
            value = bits & (threshold - 1)
            reader.skip(width - 1)
        else:
            value = bits & (2 * threshold - 1)
            if value >= threshold:
                value -= largest
            reader.skip(width)
        count = value - 1
        remaining -= abs(count)
        counts.append(count)
        if count == 0:
            while True:
                repeat = reader.peek(2)
                reader.skip(2)
                counts.extend([0] * repeat)
                if repeat != 3:
                    break
        while remaining < threshold:
            width -= 1
            threshold >>= 1
    if remaining != 1 or len(counts) > max_symbol + 1:
        raise ZstdError("Corrupt FSE table description")
    return counts, log, reader.bytes_used


# --- Huffman ---------------------------------------------------------------------

def _huffman_weights(data):
    """(weights, bytes read) of a Huffman tree description."""
    header = data[0]
    if header >= 128:
        count = header - 127
        size = (count + 1) // 2
        if 1 + size > len(data):
            raise ZstdError("Truncated Huffman weights")
        weights = []
        for byte in data[1:1 + size]:
            weights += [byte >> 4, byte & 15]
        return weights[:count], 1 + size
    size = header
    body = data[1:1 + size]
    if len(body) < size:
        raise ZstdError("Truncated Huffman weights")
    counts, log, used = _read_fse_counts(body, 255, 6)
    table = _FseTable(counts, log)
    stream = _Backward(body[used:])
    one, two = stream.read(log), stream.read(log)
    weights = []
    while len(weights) < 255:
        weights.append(table.symbols[one])
        one = table.baselines[one] + stream.read(table.bits[one])
        if stream.overflowed:
            weights.append(table.symbols[two])
            break
        weights.append(table.symbols[two])
        two = table.baselines[two] + stream.read(table.bits[two])
        if stream.overflowed:
            weights.append(table.symbols[one])
            break
    return weights, 1 + size


class _Huffman:
    __slots__ = ('bits', 'symbols', 'lengths')

    def __init__(self, weights):
        total = sum(1 << (w - 1) for w in weights if w)
        if not total:
            raise ZstdError("Empty Huffman tree")
        bits = _highbit(total) + 1
        rest = (1 << bits) - total
        if rest & (rest - 1):
            raise ZstdError("Huffman weights do not complete a tree")
        weights = list(weights) + [_highbit(rest) + 1]
        if bits > 11:
            raise ZstdError("Huffman codes too long")
        size = 1 << bits
        starts, position = [0] * (bits + 2), 0
        counts = [0] * (bits + 2)
        for weight in weights:
            if weight:
                counts[weight] += 1
        for weight in range(1, bits + 1):
            starts[weight] = position
            position += counts[weight] << (weight - 1)
        symbols, lengths = [0] * size, [0] * size
        for symbol, weight in enumerate(weights):
            if not weight:
                continue
            span = (1 << weight) >> 1
            start = starts[weight]
            for index in range(start, start + span):
                symbols[index] = symbol
                lengths[index] = bits + 1 - weight
            starts[weight] += span
        self.bits, self.symbols, self.lengths = bits, symbols, lengths

    def decode(self, data, count):
        stream = _Backward(data)
        out = bytearray()
        bits, symbols, lengths = self.bits, self.symbols, self.lengths
        for _ in range(count):
            index = stream.peek(bits)
            out.append(symbols[index])
            stream.skip(lengths[index])
        if stream.position != 0:
            raise ZstdError("Huffman stream not consumed exactly")
        return out


# --- sequences ------------------------------------------------------------------

_LL_DEFAULT = (4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2,
               2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1)
_ML_DEFAULT = (1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
               1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
               1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1)
_OF_DEFAULT = (1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
               1, 1, 1, -1, -1, -1, -1, -1)

_LL_CODES = [(code, 0) for code in range(16)] + [
    (16, 1), (18, 1), (20, 1), (22, 1), (24, 2), (28, 2), (32, 3), (40, 3),
    (48, 4), (64, 6), (128, 7), (256, 8), (512, 9), (1024, 10), (2048, 11),
    (4096, 12), (8192, 13), (16384, 14), (32768, 15), (65536, 16)]
_ML_CODES = [(code + 3, 0) for code in range(32)] + [
    (35, 1), (37, 1), (39, 1), (41, 1), (43, 2), (47, 2), (51, 3), (59, 3),
    (67, 4), (83, 4), (99, 5), (131, 7), (259, 8), (515, 9), (1027, 10),
    (2051, 11), (4099, 12), (8195, 13), (16387, 14), (32771, 15),
    (65539, 16)]

_DEFAULTS = {}


def _default(kind):
    if kind not in _DEFAULTS:
        counts, log = {'ll': (_LL_DEFAULT, 6), 'ml': (_ML_DEFAULT, 6),
                       'of': (_OF_DEFAULT, 5)}[kind]
        _DEFAULTS[kind] = _FseTable(list(counts), log)
    return _DEFAULTS[kind]


class _Frame:
    def __init__(self):
        self.huffman = None
        self.tables = {'ll': None, 'ml': None, 'of': None}
        self.offsets = [1, 4, 8]

    # literals --------------------------------------------------------------

    def literals(self, data):
        """(literal bytes, bytes of the section)."""
        first = data[0]
        kind, size_format = first & 3, (first >> 2) & 3
        if kind in (0, 1):
            if size_format in (0, 2):
                size, header = first >> 3, 1
            elif size_format == 1:
                size, header = (first >> 4) + (data[1] << 4), 2
            else:
                size, header = ((first >> 4) + (data[1] << 4)
                                + (data[2] << 12)), 3
            if kind == 0:
                body = data[header:header + size]
                if len(body) != size:
                    raise ZstdError("Truncated raw literals")
                return bytes(body), header + size
            return bytes([data[header]]) * size, header + 1
        header = (3, 3, 4, 5)[size_format]
        width = (10, 10, 14, 18)[size_format]
        value = int.from_bytes(data[:header], 'little') >> 4
        regenerated = value & ((1 << width) - 1)
        compressed = (value >> width) & ((1 << width) - 1)
        streams = 1 if size_format == 0 else 4
        body = data[header:header + compressed]
        if len(body) != compressed:
            raise ZstdError("Truncated compressed literals")
        if kind == 2:
            weights, used = _huffman_weights(body)
            self.huffman = _Huffman(weights)
            body = body[used:]
        elif self.huffman is None:
            raise ZstdError("Repeated Huffman table before any table")
        if streams == 1:
            out = self.huffman.decode(body, regenerated)
        else:
            sizes = struct.unpack_from('<3H', body, 0)
            body = body[6:]
            last = len(body) - sum(sizes)
            if last < 0:
                raise ZstdError("Literal stream sizes exceed the section")
            each = (regenerated + 3) // 4
            out, position = bytearray(), 0
            for index, size in enumerate(sizes + (last,)):
                count = each if index < 3 else regenerated - 3 * each
                out += self.huffman.decode(body[position:position + size],
                                           count)
                position += size
        return bytes(out), header + compressed

    # sequences ---------------------------------------------------------------

    def _table(self, kind, mode, data, position, max_symbol, max_log):
        if mode == 0:
            table = _default(kind)
        elif mode == 1:
            table = _FseTable.rle(data[position])
            position += 1
        elif mode == 2:
            counts, log, used = _read_fse_counts(data[position:], max_symbol,
                                                 max_log)
            table = _FseTable(counts, log)
            position += used
        else:
            table = self.tables[kind]
            if table is None:
                raise ZstdError("Repeated table before any table")
        self.tables[kind] = table
        return table, position

    def block(self, data, out):
        literals, position = self.literals(data)
        first = data[position]
        if first == 0:
            out += literals
            return
        if first < 128:
            count, position = first, position + 1
        elif first < 255:
            count = ((first - 128) << 8) + data[position + 1]
            position += 2
        else:
            count = data[position + 1] + (data[position + 2] << 8) + 0x7F00
            position += 3
        if count == 0:
            # Zero sequences written in the long form: literals only.
            if position != len(data):
                raise ZstdError("Bytes after an empty sequence section")
            out += literals
            return
        modes = data[position]
        position += 1
        ll, position = self._table('ll', modes >> 6, data, position, 35, 9)
        of, position = self._table('of', (modes >> 4) & 3, data, position,
                                   31, 8)
        ml, position = self._table('ml', (modes >> 2) & 3, data, position,
                                   52, 9)
        stream = _Backward(data[position:])
        ll_state = stream.read(ll.log)
        of_state = stream.read(of.log)
        ml_state = stream.read(ml.log)
        offsets = self.offsets
        cursor = 0
        for index in range(count):
            of_code = of.symbols[of_state]
            ll_code = ll.symbols[ll_state]
            ml_code = ml.symbols[ml_state]
            if of_code > 31 or ll_code > 35 or ml_code > 52:
                raise ZstdError("Invalid sequence code")
            offset_value = (1 << of_code) + stream.read(of_code)
            base, extra = _ML_CODES[ml_code]
            match = base + stream.read(extra)
            base, extra = _LL_CODES[ll_code]
            literal = base + stream.read(extra)
            if offset_value > 3:
                offset = offset_value - 3
                offsets[:] = [offset, offsets[0], offsets[1]]
            else:
                which = offset_value + (1 if literal == 0 else 0)
                if which == 1:
                    offset = offsets[0]
                elif which == 2:
                    offset = offsets[1]
                    offsets[:] = [offset, offsets[0], offsets[2]]
                elif which == 3:
                    offset = offsets[2]
                    offsets[:] = [offset, offsets[0], offsets[1]]
                else:
                    offset = offsets[0] - 1
                    if offset <= 0:
                        raise ZstdError("Invalid repeat offset")
                    offsets[:] = [offset, offsets[0], offsets[1]]
            if cursor + literal > len(literals):
                raise ZstdError("Sequence reads past its literals")
            out += literals[cursor:cursor + literal]
            cursor += literal
            if offset > len(out) or offset <= 0:
                raise ZstdError("Match offset before the start of output")
            start = len(out) - offset
            while match > 0:
                take = min(match, offset)
                out += out[start:start + take]
                start += take
                match -= take
            if index != count - 1:
                ll_state = ll.baselines[ll_state] + \
                    stream.read(ll.bits[ll_state])
                ml_state = ml.baselines[ml_state] + \
                    stream.read(ml.bits[ml_state])
                of_state = of.baselines[of_state] + \
                    stream.read(of.bits[of_state])
        if stream.position != 0:
            raise ZstdError("Sequence stream not consumed exactly")
        out += literals[cursor:]


# --- frames -----------------------------------------------------------------------

def decompress_python(data, max_output=MAX_OUTPUT):
    try:
        return _decompress(data, max_output)
    except (IndexError, struct.error, ValueError) as exc:
        # Damaged data runs off the end of a table or a buffer.
        raise ZstdError(f"Corrupt Zstandard data ({exc})") from exc


def _decompress(data, max_output):
    data = memoryview(bytes(data))
    out = bytearray()
    position = 0
    while position < len(data):
        if len(data) - position < 4:
            raise ZstdError("Trailing bytes after the last frame")
        magic = struct.unpack_from('<I', data, position)[0]
        if magic & 0xFFFFFFF0 == 0x184D2A50:            # skippable frame
            size = struct.unpack_from('<I', data, position + 4)[0]
            position += 8 + size
            continue
        if magic != MAGIC:
            raise ZstdError("Not a Zstandard frame")
        position = _frame(data, position + 4, out, max_output)
    return bytes(out)


def _frame(data, position, out, max_output):
    descriptor = data[position]
    position += 1
    size_flag = descriptor >> 6
    single_segment = (descriptor >> 5) & 1
    checksum = (descriptor >> 2) & 1
    dictionary_flag = descriptor & 3
    if descriptor & 8:
        raise ZstdError("Reserved bit set in the frame header")
    if not single_segment:
        position += 1                                   # window descriptor
    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    if dictionary_size:
        dictionary = int.from_bytes(data[position:position + dictionary_size],
                                    'little')
        position += dictionary_size
        if dictionary:
            raise ZstdError("This frame needs a dictionary")
    size_bytes = (1 if single_segment else 0, 2, 4, 8)[size_flag]
    declared = None
    if size_bytes:
        declared = int.from_bytes(data[position:position + size_bytes],
                                  'little')
        if size_bytes == 2:
            declared += 256
        position += size_bytes
    start = len(out)
    frame = _Frame()
    while True:
        if position + 3 > len(data):
            raise ZstdError("Truncated block header")
        header = int.from_bytes(data[position:position + 3], 'little')
        position += 3
        last, kind, size = header & 1, (header >> 1) & 3, header >> 3
        if kind == 0:
            body = data[position:position + size]
            if len(body) != size:
                raise ZstdError("Truncated raw block")
            out += body
            position += size
        elif kind == 1:
            out += bytes([data[position]]) * size
            position += 1
        elif kind == 2:
            body = data[position:position + size]
            if len(body) != size:
                raise ZstdError("Truncated compressed block")
            frame.block(bytes(body), out)
            position += size
        else:
            raise ZstdError("Reserved block type")
        if len(out) > max_output:
            raise ZstdError("Output larger than the limit")
        if last:
            break
    if declared is not None and len(out) - start != declared:
        raise ZstdError("Frame size differs from its header")
    if checksum:
        stored = struct.unpack_from('<I', data, position)[0]
        position += 4
        if xxh64(bytes(out[start:])) & 0xFFFFFFFF != stored:
            raise ZstdError("Content checksum does not match")
    return position


# --- XXH64, for the content checksum ---------------------------------------------

_P1, _P2, _P3, _P4, _P5 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
                           0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
                           0x27D4EB2F165667C5)
_M = 0xFFFFFFFFFFFFFFFF


def _rotl(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & _M


def _round(acc, lane):
    acc = (acc + lane * _P2) & _M
    return (_rotl(acc, 31) * _P1) & _M


def xxh64(data, seed=0):
    length = len(data)
    position = 0
    if length >= 32:
        v1 = (seed + _P1 + _P2) & _M
        v2 = (seed + _P2) & _M
        v3 = seed
        v4 = (seed - _P1) & _M
        limit = length - 32
        while position <= limit:
            a, b, c, d = struct.unpack_from('<4Q', data, position)
            v1, v2 = _round(v1, a), _round(v2, b)
            v3, v4 = _round(v3, c), _round(v4, d)
            position += 32
        acc = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12)
               + _rotl(v4, 18)) & _M
        for value in (v1, v2, v3, v4):
            acc ^= _round(0, value)
            acc = (acc * _P1 + _P4) & _M
    else:
        acc = (seed + _P5) & _M
    acc = (acc + length) & _M
    while position + 8 <= length:
        lane = struct.unpack_from('<Q', data, position)[0]
        acc ^= _round(0, lane)
        acc = (_rotl(acc, 27) * _P1 + _P4) & _M
        position += 8
    if position + 4 <= length:
        lane = struct.unpack_from('<I', data, position)[0]
        acc ^= (lane * _P1) & _M
        acc = (_rotl(acc, 23) * _P2 + _P3) & _M
        position += 4
    while position < length:
        acc ^= (data[position] * _P5) & _M
        acc = (_rotl(acc, 11) * _P1) & _M
        position += 1
    acc ^= acc >> 33
    acc = (acc * _P2) & _M
    acc ^= acc >> 29
    acc = (acc * _P3) & _M
    acc ^= acc >> 32
    return acc

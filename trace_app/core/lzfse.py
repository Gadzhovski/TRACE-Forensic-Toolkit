"""LZFSE and LZVN, Apple's compressors, decoded in pure Python (no Qt).

Apple compresses Spotlight stores, APFS files, DMG chunks and parts of
iOS backups with LZFSE (Lempel-Ziv with Finite State Entropy coding) and
its fast sibling LZVN. Neither is in Python's standard library and the
PyPI bindings need a compiler on some platforms, so TRACE reads them
itself, following Apple's reference decoder (github.com/lzfse/lzfse,
BSD-3-Clause): the block magics, the v2 header's packed fields and
variable-length frequency tables, the FSE decoder tables, the backward bit
stream and the L/M/D match decoding are all as lzfse_decode_base.c and
lzvn_decode_base.c lay them out.

A stream is a run of blocks, each starting with a 4-byte magic:

* 'bvx-' uncompressed: raw size, then the bytes
* 'bvx1' LZFSE with the frequency tables stored whole (rare)
* 'bvx2' LZFSE with the tables packed (what the encoder writes)
* 'bvxn' LZVN: raw size, payload size, then the opcodes
* 'bvx$' end of stream

`decompress(data, max_length=)` returns the bytes; LzfseError when the
stream is damaged. Speed is a few MB/s -- enough for Spotlight blocks and
small files, not for whole disks.
"""

import struct

MAGIC_RAW = b'bvx-'
MAGIC_V1 = b'bvx1'
MAGIC_V2 = b'bvx2'
MAGIC_LZVN = b'bvxn'
MAGIC_END = b'bvx$'

L_STATES, M_STATES, D_STATES, LITERAL_STATES = 64, 64, 256, 1024
L_SYMBOLS, M_SYMBOLS, D_SYMBOLS, LITERAL_SYMBOLS = 20, 20, 64, 256

_L_EXTRA = [0] * 16 + [2, 3, 5, 8]
_L_BASE = list(range(16)) + [16, 20, 28, 60]
_M_EXTRA = [0] * 16 + [3, 5, 8, 11]
_M_BASE = list(range(16)) + [16, 24, 56, 312]
# Distances: groups of four symbols, each group with one more extra bit.
_D_EXTRA = [group for group in range(16) for _ in range(4)]
_D_BASE = []
_base = 0
for _bits in _D_EXTRA:
    _D_BASE.append(_base)
    _base += 1 << _bits
del _base, _bits

_FREQ_NBITS = (2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
               2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14)
_FREQ_VALUE = (0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
               0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1)

#: sizeof(lzfse_compressed_block_header_v1), padded to 4 bytes.
_V1_HEADER = 772


class LzfseError(ValueError):
    """The stream is not LZFSE/LZVN or is damaged."""


def decompress(data, max_length=None):
    """Decode a whole LZFSE stream (any mix of its block kinds)."""
    data = memoryview(bytes(data))
    out = bytearray()
    pos = 0
    while True:
        if pos + 4 > len(data):
            # Some writers leave the end marker off; what was decoded is
            # whole up to there.
            if out:
                return bytes(out)
            raise LzfseError("stream ends before any block")
        magic = bytes(data[pos:pos + 4])
        if magic == MAGIC_END:
            return bytes(out)
        if magic == MAGIC_RAW:
            size = _u32(data, pos + 4)
            start = pos + 8
            if start + size > len(data):
                raise LzfseError("raw block runs past the end")
            out += data[start:start + size]
            pos = start + size
        elif magic == MAGIC_LZVN:
            raw_size = _u32(data, pos + 4)
            payload = _u32(data, pos + 8)
            start = pos + 12
            if start + payload > len(data):
                raise LzfseError("LZVN block runs past the end")
            lzvn_decode(data[start:start + payload], out, raw_size)
            pos = start + payload
        elif magic in (MAGIC_V1, MAGIC_V2):
            pos = _lzfse_block(data, pos, out, magic)
        else:
            raise LzfseError(f"unknown block magic {magic!r}")
        if max_length is not None and len(out) > max_length:
            raise LzfseError(f"decodes to more than {max_length} bytes")


def _u32(data, pos):
    return struct.unpack_from('<I', data, pos)[0]


# --- LZFSE blocks -----------------------------------------------------------------

def _field(value, offset, nbits):
    return (value >> offset) & ((1 << nbits) - 1)


def _freq_value(bits):
    """(frequency, bits used) of the next packed frequency."""
    b = bits & 31
    n = _FREQ_NBITS[b]
    if n == 8:
        return 8 + ((bits >> 4) & 0xF), n
    if n == 14:
        return 24 + ((bits >> 4) & 0x3FF), n
    return _FREQ_VALUE[b], n


def _header_v2(data, pos):
    v0, v1, v2 = struct.unpack_from('<QQQ', data, pos + 8)
    header = {
        'n_raw_bytes': _u32(data, pos + 4),
        'n_literals': _field(v0, 0, 20),
        'n_literal_payload_bytes': _field(v0, 20, 20),
        'n_matches': _field(v0, 40, 20),
        'literal_bits': _field(v0, 60, 3) - 7,
        'literal_state': [_field(v1, 0, 10), _field(v1, 10, 10),
                          _field(v1, 20, 10), _field(v1, 30, 10)],
        'n_lmd_payload_bytes': _field(v1, 40, 20),
        'lmd_bits': _field(v1, 60, 3) - 7,
        'l_state': _field(v2, 32, 10),
        'm_state': _field(v2, 42, 10),
        'd_state': _field(v2, 52, 10),
    }
    header_size = _field(v2, 0, 32)
    total = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS
    freqs = [0] * total
    if header_size != 32:
        src, end = pos + 32, pos + header_size
        if end > len(data):
            raise LzfseError("v2 header runs past the end")
        accum = accum_bits = 0
        for i in range(total):
            while src < end and accum_bits + 8 <= 32:
                accum |= data[src] << accum_bits
                accum_bits += 8
                src += 1
            value, nbits = _freq_value(accum)
            if nbits > accum_bits:
                raise LzfseError("frequency table truncated")
            freqs[i] = value
            accum >>= nbits
            accum_bits -= nbits
        if accum_bits >= 8 or src != end:
            raise LzfseError("frequency table has bytes left over")
    _split_freqs(header, freqs)
    return header, pos + header_size


def _header_v1(data, pos):
    if pos + _V1_HEADER > len(data):
        raise LzfseError("v1 header runs past the end")
    (_magic, n_raw, _n_payload, n_literals, n_matches, n_lit_payload,
     n_lmd_payload, literal_bits) = struct.unpack_from('<4sIIIIIIi', data,
                                                        pos)
    literal_state = list(struct.unpack_from('<4H', data, pos + 32))
    lmd_bits, l_state, m_state, d_state = struct.unpack_from('<iHHH', data,
                                                             pos + 40)
    total = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS
    freqs = list(struct.unpack_from(f'<{total}H', data, pos + 50))
    header = {'n_raw_bytes': n_raw, 'n_literals': n_literals,
              'n_literal_payload_bytes': n_lit_payload,
              'n_matches': n_matches, 'literal_bits': literal_bits,
              'literal_state': literal_state,
              'n_lmd_payload_bytes': n_lmd_payload, 'lmd_bits': lmd_bits,
              'l_state': l_state, 'm_state': m_state, 'd_state': d_state}
    _split_freqs(header, freqs)
    return header, pos + _V1_HEADER


def _split_freqs(header, freqs):
    a = L_SYMBOLS
    b = a + M_SYMBOLS
    c = b + D_SYMBOLS
    header['l_freq'] = freqs[:a]
    header['m_freq'] = freqs[a:b]
    header['d_freq'] = freqs[b:c]
    header['literal_freq'] = freqs[c:]


def _literal_table(nstates, freqs):
    """[(k, delta, symbol)] per state -- fse_init_decoder_table."""
    table = []
    total = 0
    for symbol, f in enumerate(freqs):
        if not f:
            continue
        total += f
        if total > nstates:
            raise LzfseError("literal frequencies exceed the state count")
        k = nstates.bit_length() - f.bit_length()
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table.append((k, ((f + j) << k) - nstates, symbol))
            else:
                table.append((k - 1, (j - j0) << (k - 1), symbol))
    return table


def _value_table(nstates, freqs, extra, base):
    """[(total bits, value bits, delta, base)] per state --
    fse_init_value_decoder_table."""
    table = []
    total = 0
    for symbol, f in enumerate(freqs):
        if not f:
            continue
        total += f
        if total > nstates:
            raise LzfseError("frequencies exceed the state count")
        k = nstates.bit_length() - f.bit_length()
        j0 = ((2 * nstates) >> k) - f
        vbits = extra[symbol]
        for j in range(f):
            if j < j0:
                table.append((k + vbits, vbits, ((f + j) << k) - nstates,
                              base[symbol]))
            else:
                table.append((k - 1 + vbits, vbits, (j - j0) << (k - 1),
                              base[symbol]))
    return table


class _BackwardBits:
    """FSE's bit stream: written forwards, read from its end. `bits` is
    0 or negative -- the unused high bits of the last byte."""

    def __init__(self, data, start, end, bits):
        if bits > 0 or bits < -7:
            raise LzfseError("bad bit stream header")
        self.data = data
        self.start = start
        self.pos = (end - start) * 8 + bits      # bit position from start

    def pull(self, n):
        if n == 0:
            return 0
        self.pos -= n
        if self.pos < 0:
            raise LzfseError("bit stream read past its start")
        first = self.pos >> 3
        last = (self.pos + n + 7) >> 3
        chunk = int.from_bytes(self.data[self.start + first:
                                         self.start + last], 'little')
        return (chunk >> (self.pos & 7)) & ((1 << n) - 1)


def _lzfse_block(data, pos, out, magic):
    header, payload = (_header_v2 if magic == MAGIC_V2 else _header_v1)(
        data, pos)
    for name in ('l_state', 'm_state'):
        if header[name] >= L_STATES:
            raise LzfseError(f"{name} out of range")
    if header['d_state'] >= D_STATES or \
            any(s >= LITERAL_STATES for s in header['literal_state']):
        raise LzfseError("state out of range")
    lit_end = payload + header['n_literal_payload_bytes']
    lmd_end = lit_end + header['n_lmd_payload_bytes']
    if lmd_end > len(data):
        raise LzfseError("block payload runs past the end")

    # Literals: four interleaved FSE states over one backward stream.
    table = _literal_table(LITERAL_STATES, header['literal_freq'])
    if header['n_literals'] and len(table) != LITERAL_STATES:
        raise LzfseError("literal table incomplete")
    bits = _BackwardBits(data, payload, lit_end, header['literal_bits'])
    states = list(header['literal_state'])
    n_literals = header['n_literals']
    literals = bytearray(n_literals + 4)
    for i in range(0, n_literals, 4):
        for lane in range(4):
            k, delta, symbol = table[states[lane]]
            literals[i + lane] = symbol
            states[lane] = delta + bits.pull(k)

    # L, M, D values, then copy literals and matches.
    l_table = _value_table(L_STATES, header['l_freq'], _L_EXTRA, _L_BASE)
    m_table = _value_table(M_STATES, header['m_freq'], _M_EXTRA, _M_BASE)
    d_table = _value_table(D_STATES, header['d_freq'], _D_EXTRA, _D_BASE)
    if header['n_matches'] and (len(l_table) != L_STATES or
                                len(m_table) != M_STATES or
                                len(d_table) != D_STATES):
        raise LzfseError("match tables incomplete")
    bits = _BackwardBits(data, lit_end, lmd_end, header['lmd_bits'])
    l_state, m_state, d_state = (header['l_state'], header['m_state'],
                                 header['d_state'])
    start = len(out)
    lit = 0
    distance = 0
    for _ in range(header['n_matches']):
        total, vbits, delta, base = l_table[l_state]
        got = bits.pull(total)
        l_state = delta + (got >> vbits)
        length = base + (got & ((1 << vbits) - 1))
        total, vbits, delta, base = m_table[m_state]
        got = bits.pull(total)
        m_state = delta + (got >> vbits)
        match = base + (got & ((1 << vbits) - 1))
        total, vbits, delta, base = d_table[d_state]
        got = bits.pull(total)
        d_state = delta + (got >> vbits)
        new_distance = base + (got & ((1 << vbits) - 1))
        if new_distance:
            distance = new_distance
        if lit + length > n_literals:
            raise LzfseError("literal run past the decoded literals")
        out += literals[lit:lit + length]
        lit += length
        if match:
            _copy_match(out, distance, match)
        if len(out) - start > header['n_raw_bytes']:
            raise LzfseError("block decodes past its stated size")
    if len(out) - start != header['n_raw_bytes']:
        raise LzfseError("block decoded to the wrong size")
    return lmd_end


def _copy_match(out, distance, length):
    """Copy `length` bytes from `distance` back (matches may reach into
    earlier blocks, as the reference decoder allows)."""
    begin = len(out) - distance
    if distance <= 0 or begin < 0:
        raise LzfseError("match distance out of range")
    if distance >= length:
        out += out[begin:begin + length]
    else:
        # Overlapping: the run repeats with period `distance`.
        piece = bytes(out[begin:])
        repeats, rest = divmod(length, distance)
        out += piece * repeats + piece[:rest]


# --- LZVN ---------------------------------------------------------------------------

def lzvn_decode(src, out, raw_size):
    """Append the LZVN-coded `src` (raw_size bytes once decoded) to out."""
    src = bytes(src)
    start = len(out)
    pos, end = 0, len(src)
    distance = 0

    def literal(n, at):
        if at + n > end:
            raise LzfseError("LZVN literal runs past the end")
        out.extend(src[at:at + n])
        return at + n

    while pos < end:
        op = src[pos]
        if op == 0x06:                                  # end of stream
            break
        if op in (0x0E, 0x16):                          # nop
            pos += 1
            continue
        if op in (0x1E, 0x26, 0x2E, 0x36, 0x3E) or 0x70 <= op <= 0x7F or \
                0xD0 <= op <= 0xDF:
            raise LzfseError(f"undefined LZVN opcode 0x{op:02x}")
        if op == 0xE0:                                  # large literal
            if pos + 1 >= end:
                raise LzfseError("LZVN truncated")
            pos = literal(src[pos + 1] + 16, pos + 2)
            continue
        if 0xE1 <= op <= 0xEF:                          # small literal
            pos = literal(op & 0x0F, pos + 1)
            continue
        if op == 0xF0:                                  # large match
            if pos + 1 >= end:
                raise LzfseError("LZVN truncated")
            _copy_match(out, distance, src[pos + 1] + 16)
            pos += 2
            continue
        if 0xF1 <= op <= 0xFF:                          # small match
            _copy_match(out, distance, op & 0x0F)
            pos += 1
            continue
        if 0xA0 <= op <= 0xBF:                          # medium distance
            if pos + 2 >= end:
                raise LzfseError("LZVN truncated")
            lits = (op >> 3) & 3
            pair = src[pos + 1] | (src[pos + 2] << 8)
            match = ((op & 7) << 2 | (pair & 3)) + 3
            distance = pair >> 2
            pos = literal(lits, pos + 3)
            _copy_match(out, distance, match)
            continue
        lits = op >> 6
        match = ((op >> 3) & 7) + 3
        low = op & 7
        if low == 7:                                    # large distance
            if pos + 2 >= end:
                raise LzfseError("LZVN truncated")
            distance = src[pos + 1] | (src[pos + 2] << 8)
            pos = literal(lits, pos + 3)
        elif low == 6:                                  # previous distance
            pos = literal(lits, pos + 1)
        else:                                           # small distance
            if pos + 1 >= end:
                raise LzfseError("LZVN truncated")
            distance = (low << 8) | src[pos + 1]
            pos = literal(lits, pos + 2)
        _copy_match(out, distance, match)
        if len(out) - start > raw_size:
            raise LzfseError("LZVN decodes past its stated size")
    if len(out) - start != raw_size:
        raise LzfseError("LZVN decoded to the wrong size")

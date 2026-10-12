"""Block ciphers VeraCrypt uses that `cryptography` does not give with XTS,
in pure Python, and XTS over any of them (no Qt).

`cryptography` has AES with XTS and Camellia as a plain block cipher; it has
no Serpent, Twofish or Kuznyechik, and no wheel anywhere does without a
compiler. So:

* Serpent (Anderson, Biham, Knudsen): bit-sliced, as the cipher is designed
  to be computed -- and many blocks at once: block n's four words sit in
  lane n of four Python integers, so every Boolean operation of a round
  works on all the blocks of a read together. The S-boxes are applied from
  their published tables (each output bit an OR of the input patterns that
  set it), so they cannot be transcribed wrong. Words are little-endian,
  as VeraCrypt and the NESSIE vectors have them.
* Twofish (Schneier et al.): key-dependent S-boxes folded with the MDS
  matrix into four 256-entry tables at key setup; 16 rounds per block.
* Kuznyechik (GOST R 34.12-2015): the linear layer and the S-box folded
  into sixteen 256-entry tables of 128-bit values per direction.
* Camellia: `cryptography`'s, in ECB, block by block in C.

`xts_decrypt(cipher, tweak_cipher, unit, data)` / `xts_encrypt` follow IEEE
1619 as VeraCrypt does: the tweak is the data unit's number, little-endian,
encrypted with the second key; each 16-byte block is XORed with it before
and after the cipher; the tweak is multiplied by x in GF(2^128) per block.

Every cipher here is checked against published test vectors and, through
core/veracrypt, against volumes VeraCrypt itself made.
"""

import struct
import sys
from array import array

BLOCK = 16
_GF_POLY = 0x87                 # x^128 + x^7 + x^2 + x + 1


# --- XTS -----------------------------------------------------------------

def _tweaks(first, count):
    """The XTS tweak for each of `count` blocks, as one bytes object."""
    value = int.from_bytes(first, 'little')
    out = bytearray(count * BLOCK)
    for index in range(count):
        out[index * BLOCK:(index + 1) * BLOCK] = value.to_bytes(16, 'little')
        value <<= 1
        if value >> 128:
            value = (value & ((1 << 128) - 1)) ^ _GF_POLY
    return bytes(out)


def _xor(a, b):
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little')) \
        .to_bytes(len(a), 'little')


def xts(cipher, tweak_cipher, unit, data, decrypt=True):
    """`data` (whole blocks of one data unit) through XTS: `cipher` and
    `tweak_cipher` are block ciphers with encrypt_blocks/decrypt_blocks."""
    count = len(data) // BLOCK
    tweak = tweak_cipher.encrypt_blocks(unit.to_bytes(16, 'little'))
    pads = _tweaks(tweak, count)
    middle = _xor(data[:count * BLOCK], pads)
    middle = cipher.decrypt_blocks(middle) if decrypt else \
        cipher.encrypt_blocks(middle)
    return _xor(middle, pads)


def xts_units(cipher, tweak_cipher, first_unit, data, unit_size=512,
              decrypt=True):
    """Several consecutive data units at once: one call into the cipher
    for all their blocks (what makes the bit-sliced Serpent quick)."""
    units = len(data) // unit_size
    if not units:
        return b''
    per = unit_size // BLOCK
    starts = b''.join((first_unit + n).to_bytes(16, 'little')
                      for n in range(units))
    tweaks = tweak_cipher.encrypt_blocks(starts)
    pads = b''.join(_tweaks(tweaks[n * BLOCK:(n + 1) * BLOCK], per)
                    for n in range(units))
    body = data[:units * unit_size]
    middle = _xor(body, pads)
    middle = cipher.decrypt_blocks(middle) if decrypt else \
        cipher.encrypt_blocks(middle)
    return _xor(middle, pads)


# --- lanes: many 32-bit words side by side in one integer ------------------

def _words(data, which):
    """Word `which` (0-3) of every 16-byte block of `data`, little-endian,
    as one integer whose lane n is block n's word."""
    words = array('I')
    words.frombytes(data)
    if sys.byteorder != 'little':
        words.byteswap()
    lane = array('I', words[which::4])
    if sys.byteorder != 'little':
        lane.byteswap()
    return int.from_bytes(lane.tobytes(), 'little')


def _join(x0, x1, x2, x3, count):
    """Four lane integers back into `count` blocks of bytes."""
    lanes = []
    for value in (x0, x1, x2, x3):
        part = array('I')
        part.frombytes(value.to_bytes(count * 4, 'little'))
        if sys.byteorder != 'little':
            part.byteswap()
        lanes.append(part)
    out = array('I', bytes(count * 16))
    for which in range(4):
        out[which::4] = lanes[which]
    if sys.byteorder != 'little':
        out.byteswap()
    return out.tobytes()


class _Lanes:
    """Masks for `count` 32-bit lanes."""

    _cache = {}

    def __new__(cls, count):
        cached = cls._cache.get(count)
        if cached is not None:
            return cached
        self = super().__new__(cls)
        self.count = count
        self.all = int.from_bytes(b'\xff' * (4 * count), 'little')
        repeat = int.from_bytes(b'\x01\x00\x00\x00' * count, 'little')
        self.low = {r: ((1 << r) - 1) * repeat for r in range(33)}
        self.high = {r: self.all ^ self.low[r] for r in range(33)}
        if len(cls._cache) > 32:
            cls._cache.clear()
        cls._cache[count] = self
        return self

    def rotl(self, x, r):
        return ((x << r) & self.high[r]) | ((x >> (32 - r)) & self.low[r])

    def rotr(self, x, r):
        return self.rotl(x, 32 - r)

    def shl(self, x, r):
        return (x << r) & self.high[r]

    def spread(self, word):
        """`word` in every lane."""
        return (word & 0xFFFFFFFF) * (self.low[32] // 0xFFFFFFFF) \
            if word else 0


# --- Serpent ---------------------------------------------------------------

_SERPENT_SBOXES = (
    (3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12),
    (15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4),
    (8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2),
    (0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14),
    (1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13),
    (15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1),
    (7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0),
    (1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6),
)
_SERPENT_INVERSE = tuple(
    tuple(box.index(value) for value in range(16)) for box in _SERPENT_SBOXES)
_PHI = 0x9E3779B9


def _sbox(table, x0, x1, x2, x3, full):
    """A 4-bit S-box applied bit-sliced: output bit k is the OR of the
    input patterns v whose table[v] sets bit k."""
    n0, n1, n2, n3 = x0 ^ full, x1 ^ full, x2 ^ full, x3 ^ full
    # The 16 patterns, built pairwise.
    lo = (n0 & n1, x0 & n1, n0 & x1, x0 & x1)
    hi = (n2 & n3, x2 & n3, n2 & x3, x2 & x3)
    y0 = y1 = y2 = y3 = 0
    for value in range(16):
        out = table[value]
        if not out:
            continue
        pattern = lo[value & 3] & hi[value >> 2]
        if out & 1:
            y0 |= pattern
        if out & 2:
            y1 |= pattern
        if out & 4:
            y2 |= pattern
        if out & 8:
            y3 |= pattern
    return y0, y1, y2, y3


class Serpent:
    """Serpent with a 128-, 192- or 256-bit key (VeraCrypt: 256)."""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Serpent keys are 16, 24 or 32 bytes")
        padded = key + (b'\x01' if len(key) < 32 else b'') + \
            bytes(32 - len(key) - (1 if len(key) < 32 else 0))
        w = list(struct.unpack('<8I', padded))
        for index in range(132):
            value = (w[index] ^ w[index + 3] ^ w[index + 5] ^ w[index + 7]
                     ^ _PHI ^ index) & 0xFFFFFFFF
            w.append(((value << 11) | (value >> 21)) & 0xFFFFFFFF)
        w = w[8:]
        self._keys = []
        one = _Lanes(1)
        for index in range(33):
            box = _SERPENT_SBOXES[(3 - index) % 8]
            self._keys.append(_sbox(box, *w[4 * index:4 * index + 4],
                                    one.all))

    def _round_keys(self, lanes):
        return [tuple(lanes.spread(word) for word in key)
                for key in self._keys]

    def encrypt_blocks(self, data):
        count = len(data) // BLOCK
        if not count:
            return b''
        lanes = _Lanes(count)
        keys = self._round_keys(lanes)
        full = lanes.all
        x0, x1, x2, x3 = (_words(data[:count * BLOCK], w) for w in range(4))
        rotl, shl = lanes.rotl, lanes.shl
        for r in range(32):
            k = keys[r]
            x0, x1, x2, x3 = _sbox(_SERPENT_SBOXES[r % 8], x0 ^ k[0],
                                   x1 ^ k[1], x2 ^ k[2], x3 ^ k[3], full)
            if r == 31:
                k = keys[32]
                x0, x1, x2, x3 = x0 ^ k[0], x1 ^ k[1], x2 ^ k[2], x3 ^ k[3]
                break
            x0 = rotl(x0, 13)
            x2 = rotl(x2, 3)
            x1 ^= x0 ^ x2
            x3 ^= x2 ^ shl(x0, 3)
            x1 = rotl(x1, 1)
            x3 = rotl(x3, 7)
            x0 ^= x1 ^ x3
            x2 ^= x3 ^ shl(x1, 7)
            x0 = rotl(x0, 5)
            x2 = rotl(x2, 22)
        return _join(x0, x1, x2, x3, count)

    def decrypt_blocks(self, data):
        count = len(data) // BLOCK
        if not count:
            return b''
        lanes = _Lanes(count)
        keys = self._round_keys(lanes)
        full = lanes.all
        x0, x1, x2, x3 = (_words(data[:count * BLOCK], w) for w in range(4))
        rotr, shl = lanes.rotr, lanes.shl
        k = keys[32]
        x0, x1, x2, x3 = x0 ^ k[0], x1 ^ k[1], x2 ^ k[2], x3 ^ k[3]
        for r in range(31, -1, -1):
            if r != 31:
                x2 = rotr(x2, 22)
                x0 = rotr(x0, 5)
                x2 ^= x3 ^ shl(x1, 7)
                x0 ^= x1 ^ x3
                x3 = rotr(x3, 7)
                x1 = rotr(x1, 1)
                x3 ^= x2 ^ shl(x0, 3)
                x1 ^= x0 ^ x2
                x2 = rotr(x2, 3)
                x0 = rotr(x0, 13)
            x0, x1, x2, x3 = _sbox(_SERPENT_INVERSE[r % 8], x0, x1, x2, x3,
                                   full)
            k = keys[r]
            x0, x1, x2, x3 = x0 ^ k[0], x1 ^ k[1], x2 ^ k[2], x3 ^ k[3]
        return _join(x0, x1, x2, x3, count)


# --- Twofish ---------------------------------------------------------------

_Q0 = (
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78,
    0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30,
    0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE,
    0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45,
    0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF,
    0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED,
    0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B,
    0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F,
    0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17,
    0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68,
    0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42,
    0x4A, 0x5E, 0xC1, 0xE0)
_Q1 = (
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B,
    0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B,
    0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54,
    0x92, 0x74, 0x36, 0x51, 0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7,
    0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF,
    0x40, 0xE7, 0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D,
    0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21,
    0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 0x4F, 0xF2, 0x65, 0x8E,
    0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44,
    0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B,
    0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56,
    0x55, 0x09, 0xBE, 0x91)


def _gf_mult(a, b, poly):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return out


_MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01),
        (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
_RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
       (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
       (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
       (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))
#: The q permutation each byte of h goes through at each layer, first to
#: last: the L[3] layer (256-bit keys), L[2] (192+), L[1], L[0], then the
#: last q before the MDS -- from the specification's h (k = 2:
#: y0 = q1[q0[q0[x0] ^ L1] ^ L0], y1 = q0[q0[q1[x1] ^ L1] ^ L0], ...).
_QORD = ((_Q1, _Q1, _Q0, _Q0, _Q1),
         (_Q0, _Q1, _Q1, _Q0, _Q0),
         (_Q0, _Q0, _Q0, _Q1, _Q1),
         (_Q1, _Q0, _Q1, _Q1, _Q0))


def _mds_column(column, value):
    """MDS column `column` times byte `value`, as a 32-bit word."""
    return sum(_gf_mult(value, _MDS[row][column], 0x169) << (8 * row)
               for row in range(4))


def _h_bytes(x_bytes, words, k):
    """h for a word given as its four bytes."""
    out = 0
    for column in range(4):
        y = x_bytes[column]
        if k == 4:
            y = _QORD[column][0][y] ^ ((words[3] >> (8 * column)) & 0xFF)
        if k >= 3:
            y = _QORD[column][1][y] ^ ((words[2] >> (8 * column)) & 0xFF)
        y = _QORD[column][2][y] ^ ((words[1] >> (8 * column)) & 0xFF)
        y = _QORD[column][3][y] ^ ((words[0] >> (8 * column)) & 0xFF)
        y = _QORD[column][4][y]
        out ^= _mds_column(column, y)
    return out


def _rol(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def _ror(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF


class Twofish:
    """Twofish with a 128-, 192- or 256-bit key (VeraCrypt: 256)."""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish keys are 16, 24 or 32 bytes")
        k = len(key) // 8
        words = struct.unpack(f'<{2 * k}I', key)
        even = [words[2 * i] for i in range(k)]
        odd = [words[2 * i + 1] for i in range(k)]
        # S: the RS code of each 8-byte piece, in reverse order.
        sbox_words = []
        for i in range(k):
            piece = key[8 * i:8 * i + 8]
            value = 0
            for row in range(4):
                byte = 0
                for column in range(8):
                    byte ^= _gf_mult(piece[column], _RS[row][column], 0x14D)
                value |= byte << (8 * row)
            sbox_words.append(value)
        sbox_words.reverse()
        rho = 0x01010101
        self._k = []
        for i in range(20):
            a = _h_bytes(((2 * i * rho) & 0xFFFFFFFF).to_bytes(4, 'little'),
                         even, k)
            b = _rol(_h_bytes((((2 * i + 1) * rho) & 0xFFFFFFFF)
                              .to_bytes(4, 'little'), odd, k), 8)
            self._k.append((a + b) & 0xFFFFFFFF)
            self._k.append(_rol((a + 2 * b) & 0xFFFFFFFF, 9))
        # g's four tables: byte j of X through its q layers and MDS
        # column j, for every byte value.
        self._t = []
        for column in range(4):
            table = []
            for x in range(256):
                y = x
                if k == 4:
                    y = _QORD[column][0][y] ^ \
                        ((sbox_words[3] >> (8 * column)) & 0xFF)
                if k >= 3:
                    y = _QORD[column][1][y] ^ \
                        ((sbox_words[2] >> (8 * column)) & 0xFF)
                y = _QORD[column][2][y] ^ \
                    ((sbox_words[1] >> (8 * column)) & 0xFF)
                y = _QORD[column][3][y] ^ \
                    ((sbox_words[0] >> (8 * column)) & 0xFF)
                table.append(_mds_column(column, _QORD[column][4][y]))
            self._t.append(tuple(table))

    def _g(self, x):
        t0, t1, t2, t3 = self._t
        return (t0[x & 0xFF] ^ t1[(x >> 8) & 0xFF] ^ t2[(x >> 16) & 0xFF]
                ^ t3[x >> 24])

    def encrypt_blocks(self, data):
        k, g = self._k, self._g
        out = bytearray(len(data) // BLOCK * BLOCK)
        unpack, pack = struct.Struct('<4I').unpack_from, \
            struct.Struct('<4I').pack_into
        for at in range(0, len(out), BLOCK):
            r0, r1, r2, r3 = unpack(data, at)
            r0 ^= k[0]
            r1 ^= k[1]
            r2 ^= k[2]
            r3 ^= k[3]
            for rnd in range(16):
                t0 = g(r0)
                t1 = g(((r1 << 8) | (r1 >> 24)) & 0xFFFFFFFF)
                f0 = (t0 + t1 + k[2 * rnd + 8]) & 0xFFFFFFFF
                f1 = (t0 + 2 * t1 + k[2 * rnd + 9]) & 0xFFFFFFFF
                r2 ^= f0
                r2 = ((r2 >> 1) | (r2 << 31)) & 0xFFFFFFFF
                r3 = (((r3 << 1) | (r3 >> 31)) & 0xFFFFFFFF) ^ f1
                r0, r1, r2, r3 = r2, r3, r0, r1
            pack(out, at, r2 ^ k[4], r3 ^ k[5], r0 ^ k[6], r1 ^ k[7])
        return bytes(out)

    def decrypt_blocks(self, data):
        k, g = self._k, self._g
        out = bytearray(len(data) // BLOCK * BLOCK)
        unpack, pack = struct.Struct('<4I').unpack_from, \
            struct.Struct('<4I').pack_into
        for at in range(0, len(out), BLOCK):
            c0, c1, c2, c3 = unpack(data, at)
            r2, r3, r0, r1 = c0 ^ k[4], c1 ^ k[5], c2 ^ k[6], c3 ^ k[7]
            for rnd in range(15, -1, -1):
                r0, r1, r2, r3 = r2, r3, r0, r1
                t0 = g(r0)
                t1 = g(((r1 << 8) | (r1 >> 24)) & 0xFFFFFFFF)
                f0 = (t0 + t1 + k[2 * rnd + 8]) & 0xFFFFFFFF
                f1 = (t0 + 2 * t1 + k[2 * rnd + 9]) & 0xFFFFFFFF
                r2 = (((r2 << 1) | (r2 >> 31)) & 0xFFFFFFFF) ^ f0
                r3 ^= f1
                r3 = ((r3 >> 1) | (r3 << 31)) & 0xFFFFFFFF
            pack(out, at, r0 ^ k[0], r1 ^ k[1], r2 ^ k[2], r3 ^ k[3])
        return bytes(out)


# --- Kuznyechik --------------------------------------------------------------

_PI = (
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
    177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13,
    87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10,
    74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99,
    182)
_L_COEFF = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32,
            148, 1)


def _kuz_gf(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1C3
        b >>= 1
    return out


def _kuz_r(block):
    """R: one step of the linear layer on a 16-byte list (byte 0 first, as
    GOST R 34.12-2015 writes a block a15..a0, so a15 = list[0])."""
    x = 0
    for index in range(16):
        x ^= _kuz_gf(block[index], _L_COEFF[index])
    return [x] + block[:15]


def _kuz_l(block):
    for _step in range(16):
        block = _kuz_r(block)
    return block


def _kuz_r_inverse(block):
    rest = block[1:] + [block[0]]
    x = 0
    for index in range(16):
        x ^= _kuz_gf(rest[index], _L_COEFF[index])
    return block[1:] + [x]


def _kuz_l_inverse(block):
    for _step in range(16):
        block = _kuz_r_inverse(block)
    return block


_PI_INVERSE = tuple(_PI.index(v) for v in range(256))
_KUZ_TABLES = {}


def _kuz_tables():
    """LS (S then L) and L^-1 tables, built once: for position p and byte
    v, the 128-bit value the linear layer makes of v alone at p."""
    if _KUZ_TABLES:
        return _KUZ_TABLES
    ls, l_inverse, sl_inverse = [], [], []
    for position in range(16):
        row_ls, row_li, row_sli = [], [], []
        for value in range(256):
            block = [0] * 16
            block[position] = _PI[value]
            row_ls.append(int.from_bytes(bytes(_kuz_l(block)), 'big'))
            block = [0] * 16
            block[position] = value
            row_li.append(int.from_bytes(bytes(_kuz_l_inverse(block)),
                                         'big'))
            block = [0] * 16
            block[position] = _PI_INVERSE[value]
            row_sli.append(int.from_bytes(bytes(_kuz_l_inverse(block)),
                                          'big'))
        ls.append(tuple(row_ls))
        l_inverse.append(tuple(row_li))
        sl_inverse.append(tuple(row_sli))
    _KUZ_TABLES.update(ls=ls, l_inverse=l_inverse, sl_inverse=sl_inverse)
    return _KUZ_TABLES


def _kuz_apply(tables, x):
    out = 0
    for position in range(16):
        out ^= tables[position][(x >> (8 * (15 - position))) & 0xFF]
    return out


class Kuznyechik:
    """GOST R 34.12-2015 "Kuznyechik", 256-bit key. Blocks as VeraCrypt
    stores them: its implementation takes the 16 bytes in memory order as
    the cipher's a15..a0, which is how they are read here too."""

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("Kuznyechik keys are 32 bytes")
        tables = _kuz_tables()
        self._ls = tables['ls']
        self._li = tables['l_inverse']
        self._sli = tables['sl_inverse']
        k1 = int.from_bytes(key[:16], 'big')
        k2 = int.from_bytes(key[16:], 'big')
        keys = [k1, k2]
        constants = []
        for index in range(1, 33):
            block = [0] * 15 + [index]
            constants.append(int.from_bytes(bytes(_kuz_l(block)), 'big'))
        for group in range(4):
            for step in range(8):
                c = constants[8 * group + step]
                k1, k2 = _kuz_apply(self._ls, k1 ^ c) ^ k2, k1
            keys.extend([k1, k2])
        self._keys = keys
        # For decryption: L^-1 of each round key, so S^-1 L^-1 folds in.
        self._dkeys = [_kuz_apply(self._li, k) for k in keys]

    def _encrypt(self, x):
        keys, ls = self._keys, self._ls
        for index in range(9):
            x = _kuz_apply(ls, x ^ keys[index])
        return x ^ keys[9]

    def _decrypt(self, x):
        keys = self._keys
        x ^= keys[9]
        x = _kuz_apply(self._li, x)
        for index in range(8, 0, -1):
            x = _kuz_apply(self._sli, x) ^ self._dkeys[index]
        out = 0
        for position in range(16):
            out |= _PI_INVERSE[(x >> (8 * (15 - position))) & 0xFF] << \
                (8 * (15 - position))
        return out ^ keys[0]

    def encrypt_blocks(self, data):
        return b''.join(
            self._encrypt(int.from_bytes(data[at:at + BLOCK], 'big'))
            .to_bytes(BLOCK, 'big')
            for at in range(0, len(data) // BLOCK * BLOCK, BLOCK))

    def decrypt_blocks(self, data):
        return b''.join(
            self._decrypt(int.from_bytes(data[at:at + BLOCK], 'big'))
            .to_bytes(BLOCK, 'big')
            for at in range(0, len(data) // BLOCK * BLOCK, BLOCK))


# --- through cryptography ----------------------------------------------------

class _Ecb:
    """A `cryptography` block cipher in ECB, with encrypt_blocks /
    decrypt_blocks (AES, Camellia)."""

    def __init__(self, algorithm):
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        self._cipher = Cipher(algorithm, modes.ECB())

    def encrypt_blocks(self, data):
        worker = self._cipher.encryptor()
        return worker.update(data) + worker.finalize()

    def decrypt_blocks(self, data):
        worker = self._cipher.decryptor()
        return worker.update(data) + worker.finalize()


def AES(key):
    from cryptography.hazmat.primitives.ciphers import algorithms
    return _Ecb(algorithms.AES(key))


def Camellia(key):
    try:            # cryptography 43+: moved with the other old ciphers
        from cryptography.hazmat.decrepit.ciphers.algorithms import             Camellia as algorithm
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import             Camellia as algorithm
    return _Ecb(algorithm(key))


#: By VeraCrypt's names.
CIPHERS = {'AES': AES, 'Serpent': Serpent, 'Twofish': Twofish,
           'Camellia': Camellia, 'Kuznyechik': Kuznyechik}

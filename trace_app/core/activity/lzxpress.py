"""LZXPRESS Huffman decompression ([MS-XCA] 2.2.4), in pure Python.

Windows 10 and 11 compress their Prefetch files with it (the "MAM" header).
There is no wheel-only library for it on every platform, and the algorithm is
short: the input is a series of chunks, each producing up to 64 KB, and each
chunk starts with a 256-byte table of 512 four-bit Huffman code lengths --
256 literal bytes and 256 match symbols. Matches copy from up to 64 KB back.

Written to the specification and checked against Prefetch files from
Windows 10 whose decoded contents (run counts, times) plaso's tests record.
"""

import struct

_CHUNK = 65536


class DecompressionError(ValueError):
    """The input is not valid LZXPRESS Huffman data."""


def _decoding_table(lengths):
    """15-bit lookahead -> (symbol, code length), canonical Huffman order."""
    table = [None] * 32768
    position = 0
    for bit_length in range(1, 16):
        span = 1 << (15 - bit_length)
        for symbol in range(512):
            if lengths[symbol] == bit_length:
                if position + span > 32768:
                    raise DecompressionError("Huffman code lengths overflow")
                entry = (symbol, bit_length)
                for index in range(position, position + span):
                    table[index] = entry
                position += span
    if position == 0:
        raise DecompressionError("empty Huffman table")
    return table


def decompress(data, size):
    """Decompress `data` into exactly `size` bytes."""
    out = bytearray()
    pos = 0
    end = len(data)
    while len(out) < size:
        if pos + 256 + 4 > end:
            raise DecompressionError("input ends inside a chunk header")
        lengths = []
        for byte in data[pos:pos + 256]:
            lengths.append(byte & 15)
            lengths.append(byte >> 4)
        pos += 256
        table = _decoding_table(lengths)

        bits = (struct.unpack_from('<H', data, pos)[0] << 16) \
            | struct.unpack_from('<H', data, pos + 2)[0]
        pos += 4
        extra = 16
        chunk_end = min(len(out) + _CHUNK, size)

        while len(out) < chunk_end:
            entry = table[bits >> 17]
            if entry is None:
                raise DecompressionError("invalid Huffman code")
            symbol, length = entry
            bits = (bits << length) & 0xFFFFFFFF
            extra -= length
            if extra < 0:
                if pos + 2 > end:
                    raise DecompressionError("input ends inside a symbol")
                bits |= struct.unpack_from('<H', data, pos)[0] << -extra
                extra += 16
                pos += 2

            if symbol < 256:
                out.append(symbol)
                continue

            symbol -= 256
            match_length = symbol & 15
            offset_bits = symbol >> 4
            if match_length == 15:
                if pos >= end:
                    raise DecompressionError("input ends inside a length")
                match_length = data[pos]
                pos += 1
                if match_length == 255:
                    match_length = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    if match_length == 0:
                        match_length = struct.unpack_from('<I', data, pos)[0]
                        pos += 4
                    if match_length < 15:
                        raise DecompressionError("invalid match length")
                    match_length -= 15
                match_length += 15
            match_length += 3

            offset = (bits >> (32 - offset_bits)) if offset_bits else 0
            offset += 1 << offset_bits
            bits = (bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                if pos + 2 > end:
                    raise DecompressionError("input ends inside an offset")
                bits |= struct.unpack_from('<H', data, pos)[0] << -extra
                extra += 16
                pos += 2

            start = len(out) - offset
            if start < 0:
                raise DecompressionError("match reaches before the start")
            if offset >= match_length:
                out += out[start:start + match_length]
            else:                       # overlapping: the run repeats itself
                for index in range(match_length):
                    out.append(out[start + index])
    return bytes(out[:size])

"""Snappy block decompression in Python (no Qt, no compiled code).

AFF4 images compress their chunks with Snappy by default. The libraries
that decode it either need a compiler to install (python-snappy's own
extension) or have no wheel for every Python TRACE supports (cramjam: none
for 3.10), so this decodes the raw block format itself: a varint with the
decompressed length, then elements -- literals, and copies of earlier
output by (offset, length) with 1-, 2- or 4-byte offsets.

Copies that overlap what they produce (offset < length, the run-length
case) are expanded by repeating the source span, so a long run costs a few
slice operations rather than one per byte.
"""


class SnappyError(ValueError):
    """The data is not a valid Snappy block."""


def _varint(data, position):
    result = shift = 0
    while True:
        if position >= len(data):
            raise SnappyError("truncated length")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 35:
            raise SnappyError("length too long")


def decompress(data):
    """The decompressed bytes of one Snappy block."""
    data = memoryview(bytes(data)) if not isinstance(data, (bytes,
                                                          bytearray)) \
        else data
    expected, position = _varint(data, 0)
    out = bytearray()
    end = len(data)
    while position < end:
        tag = data[position]
        position += 1
        kind = tag & 3
        if kind == 0:                                   # literal
            length = tag >> 2
            if length >= 60:
                extra = length - 59
                length = int.from_bytes(data[position:position + extra],
                                        'little')
                position += extra
            length += 1
            if position + length > end:
                raise SnappyError("literal runs past the end")
            out += data[position:position + length]
            position += length
            continue
        if kind == 1:
            length = 4 + ((tag >> 2) & 7)
            offset = ((tag >> 5) << 8) | data[position]
            position += 1
        elif kind == 2:
            length = (tag >> 2) + 1
            offset = data[position] | (data[position + 1] << 8)
            position += 2
        else:
            length = (tag >> 2) + 1
            offset = int.from_bytes(data[position:position + 4], 'little')
            position += 4
        if offset == 0 or offset > len(out):
            raise SnappyError("copy from before the start")
        start = len(out) - offset
        if offset >= length:
            out += out[start:start + length]
        else:
            # Overlapping: the span repeats.
            span = out[start:]
            whole, part = divmod(length, offset)
            out += span * whole + span[:part]
    if len(out) != expected:
        raise SnappyError(f"decompressed to {len(out)} bytes, not "
                          f"{expected}")
    return bytes(out)

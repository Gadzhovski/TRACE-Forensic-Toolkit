"""Windows XP to 7 hibernation files: the memory they keep, decompressed
block by block, so pictures in it can be found (no Qt).

hiberfil.sys keeps the memory pages compressed in Xpress blocks: each
starts with the signature 81 81 'xpress', then a 4-byte field whose low 10
bits are the page count less one and whose high 22 bits are the
compressed size less one (rounded up to 8 bytes), then -- 32 bytes from
the start -- the data: plain LZ77 Xpress ([MS-XCA] 2.4), or the pages as
they are when the size is the pages' own (Volatility's hibernate address
space and bulk_extractor's hiberfile scanner read it so). A block holds
at most 16 pages restored together; a picture smaller than that is whole
inside one. Which physical page each is goes by tables this reader does
not follow: pictures are carved per block.

Windows 8 and later write a different file (compressed sets of pages,
Xpress Huffman, version-specific tables): not read here.
"""

import logging
import struct

logger = logging.getLogger('TRACE.Hiberfil')

SIGNATURE = b'\x81\x81xpress'
HEADER = 32
PAGE = 4096
MAX_PAGES = 16
#: Read from the file at a time while looking for blocks.
PIECE = 16 * 1024 * 1024


class XpressError(ValueError):
    """Not valid plain LZ77 Xpress data."""


def is_hibernation_name(name):
    return name.lower() == 'hiberfil.sys'


def block_header(header):
    """(pages, compressed size) of a block header, or None."""
    if len(header) < 12 or not header.startswith(SIGNATURE):
        return None
    info = struct.unpack_from('<I', header, 8)[0]
    pages = (info & 0x3FF) + 1
    size = (info >> 10) + 1
    size = size if size % 8 == 0 else (size & ~7) + 8
    if pages > MAX_PAGES or size > pages * PAGE + 8:
        return None
    return pages, size


def blocks(read, size, should_stop=None):
    """(offset, page bytes) of every Xpress block in a hibernation file,
    in file order; a block that does not decompress to its pages is
    skipped."""
    position = 0
    while position < size:
        if should_stop is not None and should_stop():
            return
        piece = read(position, min(PIECE + HEADER, size - position))
        if not piece:
            return
        cursor = piece.find(SIGNATURE)
        if cursor == -1 or cursor >= PIECE:
            position += PIECE
            continue
        at = position + cursor
        found = block_header(read(at, HEADER))
        if found is None:
            position = at + 1
            continue
        pages, length = found
        data = read(at + HEADER, length)
        expected = pages * PAGE
        try:
            output = data[:expected] if length >= expected else \
                decompress(data, expected)
        except XpressError as exc:
            logger.debug("Xpress block at %d not read: %s", at, exc)
            position = at + 1
            continue
        if len(output) == expected:
            yield at, output
        position = at + HEADER + length


def decompress(data, size):
    """Plain LZ77 Xpress ([MS-XCA] 2.4.4) to at most `size` bytes."""
    out = bytearray()
    position, length_nibble = 0, None
    flags, flag_count = 0, 0
    end = len(data)
    while len(out) < size:
        if flag_count == 0:
            if position + 4 > end:
                break
            flags = struct.unpack_from('<I', data, position)[0]
            position += 4
            flag_count = 32
        flag_count -= 1
        if not flags & (1 << flag_count):
            if position >= end:
                break
            out.append(data[position])
            position += 1
            continue
        if position + 2 > end:
            break
        match = struct.unpack_from('<H', data, position)[0]
        position += 2
        length, offset = match % 8, match // 8 + 1
        if length == 7:
            if length_nibble is None:
                if position >= end:
                    raise XpressError("length runs past the input")
                length = data[position] % 16
                length_nibble = position
                position += 1
            else:
                length = data[length_nibble] // 16
                length_nibble = None
            if length == 15:
                if position >= end:
                    raise XpressError("length runs past the input")
                length = data[position]
                position += 1
                if length == 255:
                    if position + 2 > end:
                        raise XpressError("length runs past the input")
                    length = struct.unpack_from('<H', data, position)[0]
                    position += 2
                    if length == 0:
                        if position + 4 > end:
                            raise XpressError("length runs past the input")
                        length = struct.unpack_from('<I', data, position)[0]
                        position += 4
                    if length < 15 + 7:
                        raise XpressError("a long length too short")
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3
        if offset > len(out):
            raise XpressError("a match before the start")
        start = len(out) - offset
        if offset >= length:
            out += out[start:start + length]
        else:                           # overlapping: a repeated run
            for index in range(length):
                out.append(out[start + index])
    return bytes(out[:size])

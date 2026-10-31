"""Windows XP-7 hibernation files: Xpress blocks decompressed, pictures
carved from them (core/hiberfil, core/vics' carve inside files).

No hibernation file is public and small: the decoder is held to the
examples [MS-XCA] gives for plain LZ77 Xpress, and to a compressor
written here from the same specification; hiberfil.sys is laid out as
Volatility's hibernate address space and bulk_extractor read it.
"""

import hashlib
import io
import json
import random
import struct

import pytest


def compress(data):
    """Plain LZ77 Xpress ([MS-XCA] 2.4.3): greedy matches, every length
    form (short, shared nibble, byte, 16-bit, 32-bit)."""
    out = bytearray()
    flags, flag_count, flag_at = 0, 0, 0
    nibble_at = None
    out += b'\0\0\0\0'
    position = 0

    def flag(bit):
        nonlocal flags, flag_count, flag_at
        flags = (flags << 1) | bit
        flag_count += 1
        if flag_count == 32:
            struct.pack_into('<I', out, flag_at, flags & 0xFFFFFFFF)
            flag_at = len(out)
            out.extend(b'\0\0\0\0')
            flags, flag_count = 0, 0
    while position < len(data):
        best_length, best_offset = 0, 0
        for offset in range(1, min(position, 8192) + 1):
            length = 0
            while position + length < len(data) and \
                    data[position + length - offset] == \
                    data[position + length]:
                length += 1
            if length > best_length:
                best_length, best_offset = length, offset
        # An item's flag is counted after its bytes: the 32nd item of a
        # group still belongs before the next group's flags word.
        if best_length < 3:
            out.append(data[position])
            flag(0)
            position += 1
            continue
        length = best_length - 3
        token = (best_offset - 1) << 3
        if length < 7:
            out += struct.pack('<H', token | length)
        else:
            out += struct.pack('<H', token | 7)
            length -= 7
            if nibble_at is None:
                nibble_at = len(out)
                out.append(min(length, 15))
            else:
                out[nibble_at] |= min(length, 15) << 4
                nibble_at = None
            if length >= 15:
                length -= 15
                if length < 255:
                    out.append(length)
                else:
                    out.append(255)
                    whole = best_length - 3
                    if whole < 65536:
                        out += struct.pack('<H', whole)
                    else:
                        out += struct.pack('<HI', 0, whole)
        flag(1)
        position += best_length
    while flag_count:
        flag(1)                         # the rest: ends with the input
    return bytes(out[:flag_at + 4]) if flag_at + 4 <= len(out) else \
        bytes(out)


def test_the_specifications_examples_decompress():
    from trace_app.core.hiberfil import decompress
    letters = b'abcdefghijklmnopqrstuvwxyz'
    assert decompress(bytes.fromhex('3f000000') + letters, 26) == letters
    packed = bytes.fromhex('ffffff1f6162631700' + '0fff2601')
    assert decompress(packed, 300) == b'abc' * 100


@pytest.mark.parametrize('data', [
    b'abc' * 100,
    bytes(range(256)) * 3 + b'x' * 600 + bytes(70000) + b'end',
    random.Random(7).randbytes(3000) + random.Random(8).randbytes(64) * 40,
], ids=['repeated', 'every-length-form', 'random'])
def test_what_a_compressor_writes_decompresses(data):
    from trace_app.core.hiberfil import decompress
    assert decompress(compress(data), len(data)) == data


def picture(kind, colour):
    from PIL import Image
    out = io.BytesIO()
    Image.new('RGB', (30, 20), colour).save(out, kind)
    return out.getvalue()


def block(pages, compressed=True):
    """One Xpress block of `pages` (bytes, a whole number of pages)."""
    count = len(pages) // 4096
    data = compress(pages) if compressed else pages
    length = len(data) + (-len(data) % 8)
    info = (count - 1) | ((length - 1) << 10)
    return b'\x81\x81xpress' + struct.pack('<I', info) + bytes(20) + \
        data.ljust(length, b'\0')


def test_hibernated_memory_is_carved_for_pictures(tmp_path):
    from trace_app.core import hiberfil, vics
    from trace_app.core.image_handler import ImageHandler
    png, gif = picture('PNG', 'blue'), picture('GIF', 'red')
    pages = bytearray(8192)
    pages[1000:1000 + len(png)] = png
    stored = bytearray(4096)
    stored[77:77 + len(gif)] = gif
    first = 4096
    second = first + len(block(bytes(pages)))
    data = (b'hibr' + bytes(first - 4) + block(bytes(pages)) +
            block(bytes(stored), compressed=False) + bytes(4096))
    found = list(hiberfil.blocks(
        lambda at, length: data[at:at + length], len(data)))
    assert [(at, len(out)) for at, out in found] == [(first, 8192),
                                                     (second, 4096)]
    assert found[0][1] == bytes(pages) and found[1][1] == bytes(stored)

    root = tmp_path / 'evidence'
    root.mkdir()
    (root / 'hiberfil.sys').write_bytes(data)
    handler = ImageHandler(str(root))
    assert handler.load_image()
    try:
        summary = vics.export([('EX', handler, ())], str(tmp_path / 'out'),
                              'H-1', carve_inside=True)
    finally:
        handler.close_resources()
    with open(summary['json'], encoding='utf-8') as handle:
        media = json.load(handle)['value'][0]['Media']
    names = {m['MD5']: m['MediaFiles'][0]['FileName'] for m in media}
    assert names == {
        hashlib.md5(png).hexdigest().upper(): f'{first:x}+{1000:x}.png',
        hashlib.md5(gif).hexdigest().upper(): f'{second:x}+{77:x}.gif'}

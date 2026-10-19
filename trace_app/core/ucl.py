"""UCL's NRV2B decompression in pure Python (no Qt).

QNX's mkifs compresses an image file system with UCL (Markus Oberhumer's
library, GPL; this is the format, not its code) in 64 KiB blocks, as
ucl_nrv2b_decompress_8 reads them: a bit stream refilled a byte at a time
(the 8-bit variant), literals while a bit is 1, then a match -- an offset
in a gamma code with a low byte, 2 meaning the last offset again, and
0xFFFFFFFF ending the stream; a length in two bits or a gamma code, one
longer past offset 0xD00.

Checked against libucl itself: QNX's dumpifs (askac/dumpifs, linked with
Ubuntu's libucl) decompressing openqnx's real IFS (tests/test_qnx_ifs.py).
"""


class UclError(Exception):
    pass


def nrv2b_decompress(src, limit=1 << 26):
    """The bytes an NRV2B stream decodes to; UclError on damage, never a
    read past either end. `limit` bounds the output."""
    src = bytes(src)
    end = len(src)
    dst = bytearray()
    ip = 0
    bb = 0
    last_offset = 1

    try:
        while True:
            # Literals.
            while True:
                if bb & 0x7F:
                    bb <<= 1
                else:
                    bb = src[ip] * 2 + 1
                    ip += 1
                if not (bb >> 8) & 1:
                    break
                bb &= 0xFF
                dst.append(src[ip])
                ip += 1
            bb &= 0xFF
            # The offset's gamma code.
            offset = 1
            while True:
                if bb & 0x7F:
                    bb = (bb << 1) & 0x1FF
                else:
                    bb = src[ip] * 2 + 1
                    ip += 1
                offset = offset * 2 + ((bb >> 8) & 1)
                bb &= 0xFF
                if bb & 0x7F:
                    bb = (bb << 1) & 0x1FF
                else:
                    bb = src[ip] * 2 + 1
                    ip += 1
                stop = (bb >> 8) & 1
                bb &= 0xFF
                if stop:
                    break
                if offset > 0x1000000:
                    raise UclError("offset code too long")
            if offset == 2:
                offset = last_offset
            else:
                offset = ((offset - 3) * 256 + src[ip]) & 0xFFFFFFFF
                ip += 1
                if offset == 0xFFFFFFFF:
                    break
                offset += 1
                last_offset = offset

            def bit():
                nonlocal bb, ip
                if bb & 0x7F:
                    bb = (bb << 1) & 0x1FF
                else:
                    bb = src[ip] * 2 + 1
                    ip += 1
                value = (bb >> 8) & 1
                bb &= 0xFF
                return value

            length = bit()
            length = length * 2 + bit()
            if length == 0:
                length = 1
                while True:
                    length = length * 2 + bit()
                    if bit():
                        break
                    if length > 0x1000000:
                        raise UclError("length code too long")
                length += 2
            length += 1 if offset > 0xD00 else 0
            start = len(dst) - offset
            if start < 0:
                raise UclError("a match reaches before the output")
            count = length + 1
            if len(dst) + count > limit:
                raise UclError("output past its limit")
            if offset >= count:
                dst += dst[start:start + count]
            else:
                for index in range(count):
                    dst.append(dst[start + index])
    except IndexError:
        raise UclError("the stream ends early") from None
    if ip != end:
        # ucl_nrv2b_decompress_8 reports LOOKBEHIND / INPUT_NOT_CONSUMED.
        raise UclError(f"{end - ip} bytes after the stream's end")
    return bytes(dst)

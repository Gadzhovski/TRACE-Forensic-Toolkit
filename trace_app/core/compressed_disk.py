"""Raw disk images kept compressed -- .dd.gz, .img.xz, .raw.zst, .bz2,
.lz4 -- read in place, without writing the disk out anywhere.

Incident responders image with `dd | gzip` (or xz, zstd) and evidence is
archived that way. A compressed stream is not seekable, so where the
format allows it the image is read in independent pieces:

* gzip: every member stands alone (bgzip, `split | gzip`); inside a
  member, the decompressor's state is copied every few MiB on one pass
  through the file (Python's zlib can copy it; zran does the same in C), so
  a read starts from the nearest copy;
* xz: blocks are independent, and the index at the end of each stream
  says where every block starts and how much it holds (xz -T, pixz);
* zstd: frames are independent, and each frame's header and block headers
  give its length (and its content size, when the writer knew it);
* bzip2: concatenated streams (pbzip2) are independent;
* LZ4 frames: blocks are independent unless the frame says they are
  linked (lz4 -BD).

What cannot be split -- one xz block, one zstd frame, one bzip2 stream,
linked LZ4 blocks -- is read forward from the start, a read before the
last one starting over; that works, slowly for a large image, and the note
says so. The decompressors are the standard library's, backports.zstd's,
and TRACE's own LZ4 (activity/journal.lz4_block).
"""

import bz2
import collections
import lzma
import os
import struct
import zlib

MIB = 1024 * 1024
#: Read from the compressed file this much at a time.
FEED = MIB
#: Pieces larger than this are not decoded whole: they are read forward.
MAX_PIECE = 64 * MIB
#: Inside a gzip member, the decompressor is copied at least this often.
GZIP_INTERVAL = 8 * MIB
#: Decoded pieces kept.
CACHE = 6
#: Decompressed this much per call at most.
STEP = 4 * MIB

GZIP = b'\x1f\x8b'
XZ = b'\xfd7zXZ\x00'
ZSTD = b'\x28\xb5\x2f\xfd'
BZIP2 = b'BZh'
LZ4 = b'\x04\x22\x4d\x18'
EXTENSIONS = {'.gz': 'gzip', '.xz': 'xz', '.zst': 'zstd', '.zstd': 'zstd',
              '.bz2': 'bzip2', '.lz4': 'lz4'}


class CompressedError(Exception):
    pass


def kind_of(head):
    """'gzip', 'xz', 'zstd', 'bzip2', 'lz4' from a file's first bytes."""
    if head.startswith(GZIP):
        return 'gzip'
    if head.startswith(XZ):
        return 'xz'
    if head.startswith(ZSTD):
        return 'zstd'
    if head.startswith(LZ4):
        return 'lz4'
    if head.startswith(BZIP2) and len(head) >= 10 and \
            head[3:4] in b'123456789' and \
            head[4:10] in (b'\x31\x41\x59\x26\x53\x59',
                           b'\x17\x72\x45\x38\x50\x90'):
        return 'bzip2'
    return None


class _Piece:
    """One independently decodable part: out [start, start + length)."""
    __slots__ = ('start', 'length', 'decode')

    def __init__(self, start, length, decode):
        self.start, self.length, self.decode = start, length, decode


class CompressedDisk:
    """libyal's shape (read_buffer_at_offset, get_size) over a compressed
    raw image."""

    def __init__(self, path):
        self.path = path
        self._handle = open(path, 'rb')
        self._handle.seek(0, 2)
        self.file_size = self._handle.tell()
        self.kind = kind_of(self._read(0, 16))
        if self.kind is None:
            self._handle.close()
            raise CompressedError(f"{os.path.basename(path)} is not gzip, "
                                  f"xz, zstd, bzip2 or LZ4")
        self.pieces = []
        self.sequential = None        # a factory of output chunks, or None
        self.size = 0
        self.why_sequential = ''
        try:
            getattr(self, '_scan_' + self.kind)()
        except CompressedError:
            self._handle.close()
            raise
        except (lzma.LZMAError, OSError, EOFError, ValueError, zlib.error,
                struct.error) as exc:
            self._handle.close()
            raise CompressedError(f"{self.kind} image unreadable: {exc}") \
                from exc
        self._starts = [piece.start for piece in self.pieces]
        self._cache = collections.OrderedDict()
        self._stream = None           # (generator, position, last chunk)

    def _read(self, offset, length):
        self._handle.seek(offset)
        return self._handle.read(length)

    def _chunks(self, offset, end=None):
        """The compressed file from `offset`, FEED bytes at a time."""
        end = self.file_size if end is None else end
        while offset < end:
            data = self._read(offset, min(FEED, end - offset))
            if not data:
                return
            yield offset, data
            offset += len(data)

    # -- gzip ---------------------------------------------------------------

    def _scan_gzip(self):
        """One pass: where each member starts, and a copy of the
        decompressor's state every `interval` bytes out inside a member.
        Output is taken STEP at a time: a stretch of zeros inflates a
        thousandfold, and one call would hold all of it."""
        interval = max(GZIP_INTERVAL, self.file_size * 4 // 2048)
        marks = [(0, 0, None)]        # (in, out, state; None = a member)
        out = last_mark = 0
        decoder = zlib.decompressobj(31)
        fed = False                   # input given to the current decoder
        finished = False
        for position, data in self._chunks(0):
            fed_to = position + len(data)
            while data:
                out += len(decoder.decompress(data, STEP))
                fed = True
                if decoder.eof:
                    unused = decoder.unused_data
                    member_end = fed_to - len(unused)
                    if unused and unused[:1] != GZIP[:1]:
                        if unused.strip(b'\0'):
                            raise CompressedError("data after the last "
                                                  "gzip member is not gzip")
                        finished = True       # zero padding to the end
                        break
                    # The next member starts here: a fresh decoder.
                    decoder = zlib.decompressobj(31)
                    fed = False
                    marks.append((member_end, out, None))
                    last_mark = out
                    data = unused
                    continue
                data = decoder.unconsumed_tail
                if out - last_mark >= interval:
                    # Everything up to here is consumed: resume from it.
                    marks.append((fed_to - len(data), out, decoder.copy()))
                    last_mark = out
            if finished:
                break
        if not finished and fed and not decoder.eof:
            raise CompressedError("the gzip stream is cut short")
        if not finished and not fed and len(marks) > 1:
            marks.pop()               # the "next member" that never came
        self.size = out
        for number, (start_in, start_out, state) in enumerate(marks):
            end_out = marks[number + 1][1] if number + 1 < len(marks) \
                else self.size
            if end_out > start_out:
                self.pieces.append(_Piece(
                    start_out, end_out - start_out,
                    lambda start_in=start_in, state=state,
                    length=end_out - start_out: self._gzip_piece(
                        start_in, state, length)))

    def _gzip_piece(self, start_in, state, length):
        decoder = state.copy() if state is not None else \
            zlib.decompressobj(31)
        out = bytearray()
        for _position, data in self._chunks(start_in):
            while data and len(out) < length and not decoder.eof:
                out += decoder.decompress(data, length - len(out))
                data = decoder.unconsumed_tail
            if len(out) >= length or decoder.eof:
                break
        return bytes(out[:length])

    # -- xz -----------------------------------------------------------------

    def _scan_xz(self):
        """Streams from the end, each by its footer and index: every
        block's place and size, without decompressing."""
        streams = []
        end = self.file_size
        while end > 0:
            while end >= 4 and self._read(end - 4, 4) == b'\0\0\0\0':
                end -= 4                     # stream padding
            footer = self._read(end - 12, 12)
            if len(footer) < 12 or footer[10:12] != b'YZ':
                raise CompressedError("no xz stream footer")
            index_size = (struct.unpack_from('<I', footer, 4)[0] + 1) * 4
            check = footer[9] & 0x0F
            index_at = end - 12 - index_size
            records = _xz_index(self._read(index_at, index_size))
            blocks_size = sum((unpadded + 3) // 4 * 4
                              for unpadded, _size in records)
            start = index_at - blocks_size - 12
            if self._read(start, 6) != XZ:
                raise CompressedError("xz stream header not where its index "
                                      "says")
            streams.append((start, check, records))
            end = start
        out = 0
        whole = []
        for start, check, records in reversed(streams):
            position = start + 12
            for unpadded, size in records:
                whole.append((position, unpadded, size, check, out))
                position += (unpadded + 3) // 4 * 4
                out += size
        self.size = out
        if any(size > MAX_PIECE for _p, _u, size, _c, _o in whole):
            self._go_sequential(lambda: _decoded_stream(
                self, lambda: lzma.LZMADecompressor(
                    format=lzma.FORMAT_XZ), XZ),
                "the xz image is one block (or blocks over 64 MiB): "
                "recompress with xz -T0 (or --block-size) to read it "
                "faster")
            return
        for position, unpadded, size, check, out_start in whole:
            self.pieces.append(_Piece(out_start, size, lambda position=
                                      position, unpadded=unpadded, size=size,
                                      check=check: self._xz_block(
                                          position, unpadded, size, check)))

    def _xz_block(self, position, unpadded, size, check):
        data = self._read(position, unpadded)
        header_size = (data[0] + 1) * 4
        filters = _xz_filters(data[:header_size])
        check_size = {0: 0, 1: 4, 4: 8, 10: 32}.get(check, 0)
        body = data[header_size:unpadded - check_size]
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                        filters=filters)
        out = decoder.decompress(body, size)
        if len(out) != size:
            raise CompressedError(f"xz block at {position:,} gave "
                                  f"{len(out):,} bytes, not {size:,}")
        return out

    # -- zstd ---------------------------------------------------------------

    def _scan_zstd(self):
        """Frames by their headers; a frame without its content size is
        decoded once to learn it."""
        position = 0
        out = 0
        frames = []
        while position < self.file_size:
            head = self._read(position, 18)
            magic = struct.unpack_from('<I', head)[0]
            if 0x184D2A50 <= magic <= 0x184D2A5F:
                position += 8 + struct.unpack_from('<I', head, 4)[0]
                continue
            if head[:4] != ZSTD:
                if head.strip(b'\0') == b'':
                    break
                raise CompressedError(f"no zstd frame at {position:,}")
            length, content = _zstd_frame(self, position)
            if content is None:
                content = sum(len(chunk) for chunk in _decoded_stream(
                    self, _zstd_decoder, ZSTD, position, position + length))
            frames.append((position, length, content, out))
            out += content
            position += length
        self.size = out
        if any(content > MAX_PIECE for _p, _l, content, _o in frames):
            self._go_sequential(lambda: _decoded_stream(
                self, _zstd_decoder, ZSTD),
                "the zstd image is one frame: recompress with pzstd (or "
                "zstd --rsyncable split in frames) to read it faster")
            return
        for position, length, content, out_start in frames:
            self.pieces.append(_Piece(out_start, content, lambda position=
                                      position, length=length: _zstd_decode(
                                          self._read(position, length))))

    # -- bzip2 --------------------------------------------------------------

    def _scan_bzip2(self):
        """Streams, found by decoding each once (where one ends is not
        recorded anywhere)."""
        streams = []                  # (in, in length, out, out length)
        out = 0
        for start_in, length_in, length in _streams(
                self, bz2.BZ2Decompressor, BZIP2):
            streams.append((start_in, length_in, out, length))
            out += length
        if not streams:
            raise CompressedError("no complete bzip2 stream")
        self.size = out
        if any(length > MAX_PIECE for _i, _n, _o, length in streams):
            self._go_sequential(lambda: _decoded_stream(
                self, bz2.BZ2Decompressor, BZIP2),
                "the bzip2 image is one stream: recompress with pbzip2 to "
                "read it faster")
            return
        for start_in, length_in, start_out, length in streams:
            self.pieces.append(_Piece(start_out, length, lambda start_in=
                                      start_in, length_in=length_in:
                                      bz2.decompress(self._read(start_in,
                                                                length_in))))

    # -- LZ4 ----------------------------------------------------------------

    def _scan_lz4(self):
        """Frames and their blocks, by their headers. Independent blocks
        each decode alone; linked ones only in order."""
        from trace_app.core.activity.journal import lz4_block
        position = 0
        blocks = []                   # (position, length, stored, size?)
        linked = False
        while position < self.file_size:
            head = self._read(position, 19)
            magic = struct.unpack_from('<I', head)[0]
            if 0x184D2A50 <= magic <= 0x184D2A5F:
                position += 8 + struct.unpack_from('<I', head, 4)[0]
                continue
            if head[:4] != LZ4:
                if head.strip(b'\0') == b'':
                    break
                raise CompressedError(f"no LZ4 frame at {position:,}")
            flags, descriptor = head[4], head[5]
            if flags >> 6 != 1:
                raise CompressedError("LZ4 frame version")
            linked = linked or not flags & 0x20
            block_checksum = bool(flags & 0x10)
            content_checksum = bool(flags & 0x04)
            maximum = {4: 64 << 10, 5: 256 << 10, 6: MIB,
                       7: 4 * MIB}[(descriptor >> 4) & 7]
            header = 7 + (8 if flags & 0x08 else 0) + \
                (4 if flags & 0x01 else 0)
            position += header
            while True:
                raw = struct.unpack('<I', self._read(position, 4))[0]
                position += 4
                if raw == 0:
                    break
                length = raw & 0x7FFFFFFF
                blocks.append((position, length, bool(raw >> 31), maximum))
                position += length + (4 if block_checksum else 0)
            position += 4 if content_checksum else 0
        if linked:
            # Each block may reach 64 KiB back into the ones before.
            self.size = sum(len(chunk) for chunk in _lz4_linked(self,
                                                                 blocks))
            self._go_sequential(lambda: _lz4_linked(self, blocks),
                                "the LZ4 image has linked blocks (lz4 -BD): "
                                "recompress without -BD to read it faster")
            return
        out = 0
        for number, (start, length, stored, maximum) in enumerate(blocks):
            if number + 1 < len(blocks):
                size = maximum             # every block but the last is full
            else:
                data = self._read(start, length)
                size = length if stored else len(lz4_block(data))
            self.pieces.append(_Piece(out, size, lambda start=start,
                                      length=length, stored=stored,
                                      size=size: _lz4_piece(self, start,
                                                            length, stored,
                                                            size)))
            out += size
        self.size = out

    # -- reading --------------------------------------------------------------

    def _go_sequential(self, factory, why):
        self.sequential = factory
        self.why_sequential = why

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        end = min(offset + length, self.size)
        if offset >= end:
            return b''
        if self.sequential is not None:
            return self._read_sequential(offset, end)
        out = bytearray()
        import bisect
        while offset < end:
            index = bisect.bisect_right(self._starts, offset) - 1
            piece = self.pieces[index]
            data = self._cache.get(index)
            if data is None:
                data = piece.decode()
                if len(data) != piece.length:
                    raise CompressedError(
                        f"a {self.kind} piece at {piece.start:,} gave "
                        f"{len(data):,} bytes, not {piece.length:,}")
                self._cache[index] = data
                if len(self._cache) > CACHE:
                    self._cache.popitem(last=False)
            else:
                self._cache.move_to_end(index)
            within = offset - piece.start
            take = min(end, piece.start + piece.length) - offset
            out += data[within:within + take]
            offset += take
        return bytes(out)

    def _read_sequential(self, offset, end):
        """Forward through the stream; a read behind the last chunk read
        starts over. Recent chunks are kept: The Sleuth Kit re-reads
        nearby."""
        out = bytearray()
        while offset < end:
            hit = None
            for start, data in self._cache.items():
                if start <= offset < start + len(data):
                    hit = (start, data)
                    break
            if hit is None:
                hit = self._advance(offset)
            start, data = hit
            within = offset - start
            take = min(end - offset, len(data) - within)
            out += data[within:within + take]
            offset += take
        return bytes(out)

    def _advance(self, offset):
        if self._stream is None or offset < self._stream[1]:
            self._stream = [self.sequential(), 0]
        generator, position = self._stream
        for data in generator:
            start = position
            position += len(data)
            self._stream[1] = position
            if position > offset:
                self._cache[start] = data
                if len(self._cache) > CACHE * 4:
                    self._cache.popitem(last=False)
                return start, data
        raise CompressedError(f"the {self.kind} stream ends before "
                              f"{offset:,}")

    def describe(self):
        names = {'gzip': 'gzip', 'xz': 'xz', 'zstd': 'zstd',
                 'bzip2': 'bzip2', 'lz4': 'LZ4'}
        text = (f"{names[self.kind]}-compressed raw image: {self.size:,} "
                f"bytes")
        if self.sequential is not None:
            text += f"; read in order -- {self.why_sequential}"
        else:
            text += f" in {len(self.pieces):,} independent pieces"
        return text

    def close(self):
        try:
            self._handle.close()
        except Exception:
            pass


# --- format details -------------------------------------------------------------

def _varint(data, position):
    """xz's multibyte integer."""
    value = shift = 0
    while True:
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, position


def _xz_index(data):
    """[(unpadded size, uncompressed size)] from an xz index."""
    if not data or data[0] != 0:
        raise CompressedError("no xz index")
    count, position = _varint(data, 1)
    records = []
    for _ in range(count):
        unpadded, position = _varint(data, position)
        size, position = _varint(data, position)
        records.append((unpadded, size))
    return records


def _xz_filters(header):
    """The filter chain of an xz block header, as lzma takes it."""
    flags = header[1]
    count = (flags & 0x03) + 1
    position = 2
    if flags & 0x40:
        _compressed, position = _varint(header, position)
    if flags & 0x80:
        _size, position = _varint(header, position)
    filters = []
    for _ in range(count):
        identifier, position = _varint(header, position)
        size, position = _varint(header, position)
        properties = bytes(header[position:position + size])
        position += size
        filters.append(lzma._decode_filter_properties(identifier,
                                                      properties))
    return filters


def _zstd_frame(disk, position):
    """(the frame's length in the file, its content size or None)."""
    head = disk._read(position, 18)
    descriptor = head[4]
    single = bool(descriptor & 0x20)
    checksum = bool(descriptor & 0x04)
    dictionary = (0, 1, 2, 4)[descriptor & 0x03]
    fcs_flag = descriptor >> 6
    fcs = (1 if single else 0, 2, 4, 8)[fcs_flag]
    at = 5 + (0 if single else 1) + dictionary
    content = None
    if fcs:
        content = int.from_bytes(head[at:at + fcs], 'little')
        if fcs == 2:
            content += 256
    cursor = position + at + fcs
    while True:
        block = int.from_bytes(disk._read(cursor, 3), 'little')
        last, kind, size = block & 1, (block >> 1) & 3, block >> 3
        cursor += 3 + (1 if kind == 1 else size)
        if kind == 3:
            raise CompressedError("reserved zstd block type")
        if last:
            break
    cursor += 4 if checksum else 0
    return cursor - position, content


def _zstd_decode(data):
    from trace_app.core.zstd_decode import decompress_frame
    return bytes(decompress_frame(data, 1 << 34))


def _zstd_decoder():
    from trace_app.core.zstd_decode import standard_library
    library = standard_library()
    if library is None:
        raise CompressedError("a zstd frame too large to read whole needs "
                              "backports.zstd")
    return library.ZstdDecompressor()


def _decoded_stream(disk, make, magic, start=0, end=None):
    """Output chunks (at most STEP each) of the file from `start`, stream
    after stream of the same kind -- a decompressor that stops at the end
    of its stream (xz, bzip2, zstd) is replaced by a new one."""
    decoder = make()
    for _position, data in disk._chunks(start, end):
        while True:
            out = decoder.decompress(data, STEP)
            data = b''
            if out:
                yield out
            if decoder.eof:
                rest = decoder.unused_data
                if rest.startswith(magic):
                    decoder = make()
                    data = rest
                    continue
                return
            if decoder.needs_input:
                break


def _streams(disk, make, magic):
    """(in, in length, out length) of each stream, decoding in bounded
    steps."""
    decoder = make()
    stream_in = out = 0
    for position, data in disk._chunks(0):
        fed_to = position + len(data)
        while True:
            out += len(decoder.decompress(data, STEP))
            data = b''
            if decoder.eof:
                rest = decoder.unused_data
                stream_end = fed_to - len(rest)
                yield stream_in, stream_end - stream_in, out
                stream_in, out = stream_end, 0
                if rest.startswith(magic):
                    decoder = make()
                    data = rest
                    continue
                if rest.strip(b'\0'):
                    raise CompressedError("data after the last stream")
                return
            if decoder.needs_input:
                break
    raise CompressedError("the last stream is cut short")


def _lz4_piece(disk, start, length, stored, size):
    from trace_app.core.activity.journal import lz4_block
    data = disk._read(start, length)
    return data if stored else lz4_block(data, size)


def _lz4_linked(disk, blocks):
    """Linked LZ4 blocks in order, each with up to 64 KiB of what came
    before as its history."""
    from trace_app.core.activity.journal import lz4_block
    history = b''
    for start, length, stored, maximum in blocks:
        data = disk._read(start, length)
        out = data if stored else lz4_block(data, maximum,
                                            history=history[-65536:])
        history = (history + out)[-65536:]
        yield out

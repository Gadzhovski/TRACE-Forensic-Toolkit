"""Apple UDIF (.dmg) read in Python, for what libmodi gets wrong (no Qt).

libmodi reads most DMGs, but its own bzip2 decoder fails on ordinary
bzip2 chunks ("block data index value out of bounds" -- hdiutil's UDBZ
read as a volume with no files), and it refuses some read-only (UDRO)
images hdiutil writes. Python's standard library decodes zlib and bzip2,
and UDIF itself is small: a 512-byte 'koly' trailer pointing at an XML
plist whose 'blkx' entries are 'mish' tables of chunks -- each a run of
sectors stored raw, compressed, or not stored at all (zeros).

`open_udif(path)` returns an object read like a libyal handle
(`read_buffer_at_offset`, `get_media_size`, `close`), so it slots into
containers.LibyalImgInfo unchanged. Chunk types it cannot decode (ADC,
LZFSE) raise UdifError at open: those images stay with libmodi.
"""

import bisect
import bz2
import os
import plistlib
import struct
import zlib
from collections import OrderedDict

SECTOR = 512

ZERO, RAW, IGNORE = 0x00000000, 0x00000001, 0x00000002
ADC, ZLIB, BZIP2, LZFSE, LZMA = (0x80000004, 0x80000005, 0x80000006,
                                 0x80000007, 0x80000008)
COMMENT, END = 0x7FFFFFFE, 0xFFFFFFFF

DECODED = {ZERO, RAW, IGNORE, ZLIB, BZIP2}

#: Decompressed chunks kept (hdiutil's are 1 MB; a read crossing a few
#: chunks, and the walk's locality, are served from here).
CACHED_CHUNKS = 16

#: A chunk claiming more than this is damage, not a chunk.
MAX_CHUNK_SECTORS = 1 << 20          # 512 MB


class UdifError(Exception):
    """Not a UDIF image this module can read; the message says why."""


def chunk_types(path):
    """Every chunk type in a UDIF image's tables ([] if it has none)."""
    return sorted({c[2] for c in _chunks(path)[0]})


def _koly(handle):
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size < 512:
        raise UdifError("too small to be a DMG")
    handle.seek(size - 512)
    koly = handle.read(512)
    if koly[:4] != b'koly':
        raise UdifError("no UDIF trailer ('koly')")
    data_fork = struct.unpack_from('>Q', koly, 24)[0]
    xml_offset, xml_length = struct.unpack_from('>QQ', koly, 0xd8)
    sectors = struct.unpack_from('>Q', koly, 492)[0]
    if not xml_length or xml_offset + xml_length > size:
        raise UdifError("UDIF trailer points outside the file")
    return data_fork, xml_offset, xml_length, sectors, size


def _chunks(path):
    """([(first sector, sectors, type, file offset, stored length)],
    media sectors), sorted by sector, comments and end markers left out."""
    with open(path, 'rb') as handle:
        data_fork, xml_offset, xml_length, sectors, size = _koly(handle)
        handle.seek(xml_offset)
        try:
            plist = plistlib.loads(handle.read(xml_length))
        except Exception as exc:
            raise UdifError(f"UDIF table unreadable: {exc}") from exc
    chunks = []
    for block in plist.get('resource-fork', {}).get('blkx', []):
        data = block.get('Data') or b''
        if data[:4] != b'mish' or len(data) < 204:
            continue
        first, _count, data_offset = struct.unpack_from('>QQQ', data, 8)
        count = struct.unpack_from('>I', data, 200)[0]
        if len(data) < 204 + count * 40:
            raise UdifError("UDIF table truncated")
        for index in range(count):
            kind, _comment, sector, run, offset, length = struct.unpack_from(
                '>IIQQQQ', data, 204 + index * 40)
            if kind in (COMMENT, END) or not run:
                continue
            if run > MAX_CHUNK_SECTORS:
                raise UdifError(f"chunk of {run} sectors")
            start = data_fork + data_offset + offset
            if kind not in (ZERO, IGNORE) and start + length > size:
                raise UdifError("chunk stored past the end of the file")
            chunks.append((first + sector, run, kind, start, length))
    if not chunks:
        raise UdifError("UDIF image has no chunk table")
    chunks.sort()
    if not sectors:
        sectors = max(c[0] + c[1] for c in chunks)
    return chunks, sectors


class UdifImage:
    """A UDIF image's media, decompressed as it is read."""

    def __init__(self, path):
        self.path = path
        self._chunks, sectors = _chunks(path)
        unknown = {c[2] for c in self._chunks} - DECODED
        if unknown:
            raise UdifError("chunk types not decoded here: " + ', '.join(
                f"0x{kind:08x}" for kind in sorted(unknown)))
        self._starts = [c[0] for c in self._chunks]
        self._size = sectors * SECTOR
        self._file = open(path, 'rb')
        self._cache = OrderedDict()

    def get_media_size(self):
        return self._size

    def get_size(self):
        return self._size

    def close(self):
        self._file.close()
        self._cache.clear()

    def _chunk_bytes(self, index):
        cached = self._cache.get(index)
        if cached is not None:
            self._cache.move_to_end(index)
            return cached
        first, run, kind, offset, length = self._chunks[index]
        want = run * SECTOR
        if kind in (ZERO, IGNORE):
            data = bytes(want)
        else:
            self._file.seek(offset)
            stored = self._file.read(length)
            if kind == RAW:
                data = stored
            elif kind == ZLIB:
                data = zlib.decompress(stored)
            else:
                data = bz2.decompress(stored)
            # A short chunk reads as zeros past what it holds, as libmodi
            # does; a long one is cut to its sectors.
            data = data[:want].ljust(want, b'\0')
        self._cache[index] = data
        if len(self._cache) > CACHED_CHUNKS:
            self._cache.popitem(last=False)
        return data

    def read_buffer_at_offset(self, length, offset):
        if offset >= self._size or length <= 0:
            return b''
        length = min(length, self._size - offset)
        out = bytearray()
        position = offset
        end = offset + length
        while position < end:
            sector = position // SECTOR
            index = bisect.bisect_right(self._starts, sector) - 1
            if index < 0 or sector >= self._starts[index] + \
                    self._chunks[index][1]:
                # A gap no chunk covers: nothing stored, zeros.
                following = self._starts[index + 1] * SECTOR \
                    if index + 1 < len(self._starts) else self._size
                take = min(end, following) - position
                out += bytes(take)
                position += take
                continue
            first = self._starts[index] * SECTOR
            data = self._chunk_bytes(index)
            within = position - first
            take = min(end - position, len(data) - within)
            out += data[within:within + take]
            position += take
        return bytes(out)

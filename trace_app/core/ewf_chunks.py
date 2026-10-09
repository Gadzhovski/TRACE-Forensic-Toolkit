"""Read an E01's chunks and check each one, as ewfverify does (no Qt).

libewf answers a read of a chunk that fails its checksum with zeros and
says nothing (pyewf exposes no error count): a damaged image hashes to a
"wrong" value with no hint of where, and an image that stores no hash of
its own hashes as if nothing were wrong at all. This reads the chunks
itself, so verification can say which sectors are damaged.

EWF version 1 (E01), per libewf's format documentation:

* each segment file: 13-byte header, then 76-byte section descriptors
  (type, next offset, size, padding, Adler-32 of the first 72 bytes)
* 'volume' / 'disk': chunk count, sectors per chunk, bytes per sector,
  sector count
* 'table': entry count, base offset, 24-byte header with its own
  Adler-32; then one u32 per chunk -- bit 31 set = zlib-compressed, the
  rest an offset from the base -- and an Adler-32 of the entries
* a compressed chunk is a zlib stream (its Adler-32 trailer checks it);
  a stored chunk is its bytes followed by their Adler-32
* a chunk ends where the next one starts; a table's last chunk at the
  end of the 'sectors' section that holds it
* EnCase 6.7 and earlier could let offsets run past 2**31 within one
  table; the 31-bit offset then wraps, and bit 31 is part of the offset.
  As in libewf, a wrap is taken as the start of that overflow.

Ex01 / Lx01 (EWF2) and SMART S01 are not read here: `open_chunks` raises
`NotEwf1` and the caller hashes through libewf instead.
"""

import os
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor

#: E01 only: an L01's (LVF) chunks hold a logical stream laid out
#: differently; libewf hashes those.
SIGNATURES = (b'EVF\x09\x0d\x0a\xff\x00',)
DESCRIPTOR = 76
#: Chunks decompressed per task: zlib releases the interpreter lock, so
#: batches decompress in parallel while the hash is fed in order.
BATCH = 64


class NotEwf1(ValueError):
    """Not an EWF version 1 set this reader handles (Ex01, S01...)."""


class EwfDamage(ValueError):
    """The container's own structure is damaged: a section or table whose
    checksum fails, or a set that does not account for every chunk."""


def _adler(data):
    return zlib.adler32(data) & 0xFFFFFFFF


class _Chunk:
    __slots__ = ('path', 'offset', 'size', 'compressed')

    def __init__(self, path, offset, size, compressed):
        self.path, self.offset = path, offset
        self.size, self.compressed = size, compressed


class ChunkMap:
    """Where every chunk of a segment set is. `chunks` in media order;
    `chunk_size`, `media_size`; `problems` lists structural damage found
    while mapping (section or table checksums), as sentences."""

    def __init__(self, paths):
        self.paths = list(paths)
        self.chunks = []
        self.problems = []
        self.chunk_size = self.media_size = self.chunk_count = None
        segments = []
        for path in self.paths:
            with open(path, 'rb') as handle:
                head = handle.read(13)
            if len(head) < 13 or head[:8] not in SIGNATURES:
                raise NotEwf1(f"{os.path.basename(path)} is not EWF "
                              f"version 1")
            segments.append((struct.unpack_from('<H', head, 9)[0], path))
        segments.sort()
        for _number, path in segments:
            self._map_segment(path)
        if self.chunk_size is None:
            raise NotEwf1("no volume section")
        if self.chunk_count is not None and \
                len(self.chunks) != self.chunk_count:
            self.problems.append(
                f"the tables list {len(self.chunks):,} chunks; the volume "
                f"section records {self.chunk_count:,}")

    def _map_segment(self, path):
        size = os.path.getsize(path)
        name = os.path.basename(path)
        with open(path, 'rb') as handle:
            offset, sectors_end, seen = 13, None, set()
            while offset + DESCRIPTOR <= size and offset not in seen:
                seen.add(offset)
                handle.seek(offset)
                descriptor = handle.read(DESCRIPTOR)
                kind = descriptor[:16].rstrip(b'\0').decode('ascii',
                                                            'replace')
                following, length = struct.unpack_from('<QQ', descriptor, 16)
                stored = struct.unpack_from('<I', descriptor, 72)[0]
                if stored != _adler(descriptor[:72]):
                    self.problems.append(
                        f"{name}: the '{kind}' section at byte {offset:,} "
                        f"fails its checksum")
                if kind in ('volume', 'disk') and self.chunk_size is None:
                    data = handle.read(min(length - DESCRIPTOR, 1052))
                    if len(data) < 24:
                        raise NotEwf1("SMART volume section")
                    count, per_chunk, sector, sectors = struct.unpack_from(
                        '<IIIQ', data, 4)
                    self.chunk_count = count
                    self.chunk_size = per_chunk * sector
                    self.media_size = sectors * sector
                elif kind == 'sectors':
                    sectors_end = offset + length
                elif kind == 'table':
                    self._map_table(handle, path, offset, length,
                                    sectors_end or offset)
                if kind in ('next', 'done'):
                    return
                if following <= offset:
                    break
                offset = following
        raise EwfDamage(f"{name} breaks off: its section chain ends "
                        f"without 'next' or 'done'")

    def _map_table(self, handle, path, offset, length, sectors_end):
        name = os.path.basename(path)
        header = handle.read(24)
        count, _pad, base = struct.unpack_from('<IIQ', header, 0)
        if struct.unpack_from('<I', header, 20)[0] != _adler(header[:20]):
            self.problems.append(f"{name}: the table at byte {offset:,} "
                                 f"has a damaged header")
        raw = handle.read(4 * count)
        if len(raw) < 4 * count:
            raise EwfDamage(f"{name}: the table at byte {offset:,} is cut "
                            f"short")
        footer = handle.read(4)
        if len(footer) == 4 and length - DESCRIPTOR >= 24 + 4 * count + 4 \
                and struct.unpack('<I', footer)[0] != _adler(raw):
            self.problems.append(f"{name}: the table at byte {offset:,} "
                                 f"fails its checksum")
        entries = struct.unpack(f'<{count}I', raw)
        starts, overflow, previous = [], False, -1
        for entry in entries:
            if overflow:
                start, compressed = base + entry, None
            else:
                relative = entry & 0x7FFFFFFF
                if relative < previous:
                    # EnCase's 2 GiB wrap: from here bit 31 is offset.
                    overflow = True
                    start, compressed = base + entry, None
                else:
                    start = base + relative
                    compressed = bool(entry & 0x80000000)
                previous = relative
            starts.append((start, compressed))
        for index, (start, compressed) in enumerate(starts):
            end = (starts[index + 1][0] if index + 1 < len(starts)
                   else sectors_end)
            if end <= start:
                raise EwfDamage(f"{name}: chunk at byte {start:,} has no "
                                f"extent")
            if compressed is None:
                compressed = end - start != self.chunk_size + 4
            self.chunks.append(_Chunk(path, start, end - start, compressed))

    def expected_size(self, index):
        if index < len(self.chunks) - 1:
            return self.chunk_size
        return self.media_size - self.chunk_size * (len(self.chunks) - 1)


def _decode(raw, compressed, expected):
    """(data, ok) for one chunk's stored bytes. A chunk that fails its
    checksum (or does not inflate to its size) reads as zeros of the
    expected length -- what libewf returns -- with ok False."""
    if compressed:
        try:
            inflater = zlib.decompressobj()
            data = inflater.decompress(raw, expected + 1)
            if inflater.eof and len(data) == expected:
                return data, True
        except zlib.error:
            pass
        return bytes(expected), False
    data, stored = raw[:-4], raw[-4:]
    if len(data) >= expected and len(stored) == 4 and \
            struct.unpack('<I', stored)[0] == _adler(data):
        return data[:expected], True
    return bytes(expected), False


def read_media(chunk_map, should_stop=None, workers=None):
    """Yield (offset, data, ok) for every chunk in media order, read and
    checked; ok False = it failed its checksum and reads as zeros."""
    handles = {}
    workers = workers or min(8, (os.cpu_count() or 2))
    try:
        def fetch(index):
            chunk = chunk_map.chunks[index]
            handle = handles.get(chunk.path)
            if handle is None:
                handle = handles[chunk.path] = open(chunk.path, 'rb')
            handle.seek(chunk.offset)
            raw = handle.read(chunk.size)
            if len(raw) < chunk.size:
                raise EwfDamage(
                    f"{os.path.basename(chunk.path)} ends inside chunk "
                    f"{index:,}")
            return raw, chunk.compressed, chunk_map.expected_size(index)

        def decode_batch(batch):
            return [_decode(*item) for item in batch]

        total = len(chunk_map.chunks)
        with ThreadPoolExecutor(workers) as pool:
            pending = []
            index = 0
            position = 0
            while index < total or pending:
                while index < total and len(pending) < workers * 2:
                    if should_stop is not None and should_stop():
                        return
                    batch = [fetch(i) for i in
                             range(index, min(index + BATCH, total))]
                    pending.append(pool.submit(decode_batch, batch))
                    index += len(batch)
                for data, ok in pending.pop(0).result():
                    yield position, data, ok
                    position += len(data)
    finally:
        for handle in handles.values():
            handle.close()


def damaged_ranges(bad_offsets, chunk_size, sector_size=512):
    """Merge damaged chunk offsets into [(first sector, last sector)]."""
    ranges = []
    for offset in sorted(bad_offsets):
        first = offset // sector_size
        last = (offset + chunk_size) // sector_size - 1
        if ranges and first <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], last))
        else:
            ranges.append((first, last))
    return ranges

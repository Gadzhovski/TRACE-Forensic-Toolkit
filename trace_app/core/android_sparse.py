"""Android sparse images, read in Python (no Qt).

Android ships and dumps partitions (system, vendor, userdata, super) as
"sparse" images: what img2simg and the build system write, and what many
extraction tools hand over as .img. A sparse image is not the partition;
it is a list of chunks (libsparse's sparse_format.h):

* a 28-byte header: magic 0xED26FF3A, version 1.0, header and chunk
  header sizes, block size, the partition's size in blocks, the number of
  chunks, an optional CRC-32 of the whole;
* chunks, each a 12-byte header (type, size in blocks, size in the file)
  and then: RAW -- the blocks themselves; FILL -- a 4-byte value repeated
  over the blocks; DONT_CARE -- nothing (zeros when expanded, as simg2img
  writes them); CRC32 -- a checksum of what came before.

The image reads as the partition it expands to, block by block, without
expanding it anywhere. (The sizes of the header and chunk headers are
read from the header, so later, longer versions still read.)
"""

import bisect
import struct

MAGIC = 0xED26FF3A
HEADER = struct.Struct('<IHHHHIIII')
CHUNK = struct.Struct('<HHII')
RAW, FILL, DONT_CARE, CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4


class SparseError(Exception):
    pass


def is_sparse(head):
    return len(head) >= 4 and struct.unpack_from('<I', head)[0] == MAGIC


class SparseImage:
    """libyal's shape (read_buffer_at_offset, get_size) over a sparse
    image in `source` (a file object)."""

    def __init__(self, source):
        self.source = source
        head = self._read(0, HEADER.size)
        if len(head) < HEADER.size or not is_sparse(head):
            raise SparseError("not an Android sparse image")
        (_magic, major, _minor, header_size, chunk_header_size,
         self.block_size, self.total_blocks, chunks,
         _checksum) = HEADER.unpack(head)
        if major != 1:
            raise SparseError(f"sparse format version {major}")
        if header_size < HEADER.size or chunk_header_size < CHUNK.size \
                or not self.block_size or self.block_size % 4:
            raise SparseError("sparse header sizes")
        #: [(first block, block count, type, file offset or fill value)]
        self.chunks = []
        self.counts = {RAW: 0, FILL: 0, DONT_CARE: 0, CRC32: 0}
        position = header_size
        block = 0
        for number in range(chunks):
            raw = self._read(position, chunk_header_size)
            if len(raw) < CHUNK.size:
                raise SparseError(f"chunk {number} past the end")
            kind, _reserved, count, total = CHUNK.unpack_from(raw)
            body = position + chunk_header_size
            if kind == RAW:
                if total - chunk_header_size != count * self.block_size:
                    raise SparseError(f"raw chunk {number}: sizes differ")
                self.chunks.append((block, count, RAW, body))
            elif kind == FILL:
                value = self._read(body, 4)
                self.chunks.append((block, count, FILL, value))
            elif kind == DONT_CARE:
                self.chunks.append((block, count, DONT_CARE, None))
            elif kind == CRC32:
                count = 0
            else:
                raise SparseError(f"chunk {number}: type {kind:#x}")
            self.counts[kind] = self.counts.get(kind, 0) + 1
            block += count
            position += total
        if block != self.total_blocks:
            raise SparseError(f"chunks cover {block} blocks; the header "
                              f"says {self.total_blocks}")
        self._starts = [chunk[0] for chunk in self.chunks]
        self.size = self.total_blocks * self.block_size

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        out = bytearray()
        end = min(offset + length, self.size)
        while offset < end:
            index = bisect.bisect_right(self._starts, offset //
                                        self.block_size) - 1
            first, count, kind, where = self.chunks[index]
            chunk_start = first * self.block_size
            chunk_end = (first + count) * self.block_size
            take = min(end, chunk_end) - offset
            within = offset - chunk_start
            if kind == RAW:
                data = self._read(where + within, take)
                if len(data) < take:
                    raise SparseError("raw chunk past the end of the file")
                out += data
            elif kind == FILL:
                pattern = where * (take // 4 + 2)
                out += pattern[within % 4:within % 4 + take]
            else:
                out += bytes(take)
            offset += take
        return bytes(out)

    def describe(self):
        return (f"Android sparse image: {self.size:,} bytes in "
                f"{self.counts[RAW]} raw, {self.counts[FILL]} fill and "
                f"{self.counts[DONT_CARE]} don't-care chunks")

    def close(self):
        try:
            self.source.close()
        except Exception:
            pass

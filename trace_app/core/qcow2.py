"""QEMU QCOW2 images read in Python, for what libqcow gets wrong (no Qt).

libqcow (20260703, the wheels') takes bit 0 of every L2 entry for the
"reads as zeros" flag -- but in a compressed cluster's entry that bit is
the lowest bit of the host offset (qcow2 spec, "Compressed Clusters
Descriptor"). Every compressed cluster stored at an odd byte offset then
reads as zeros, silently: on Fedora 44's cloud image, 273 of the first
559 compressed clusters of its Btrfs partition, which made the volume
unreadable. `qemu-img convert -c` images, which is how distributions and
many examiners ship them, are compressed throughout.

The format is small: a big-endian header, an L1 table of L2 tables, each
L2 entry a cluster stored plainly, compressed (deflate, or zstd when the
header says so), all-zero, or not stored (the backing file's, else
zeros). Backing files chain by the name the header records, looked up
beside the image (containers._sibling), each read by this class too.

`Qcow2Image(path)` is read like a libyal handle (`read_buffer_at_offset`,
`get_media_size`, `close`), so containers.LibyalImgInfo takes it
unchanged. What it does not read -- QCOW version 1, encryption, an
external data file, extended L2 entries -- raises Qcow2Error at open, and
those images stay with libqcow.
"""

import os
import struct
import zlib
from collections import OrderedDict

from trace_app.core import zstd_decode

MAGIC = b'QFI\xfb'

COPIED = 1 << 63
COMPRESSED = 1 << 62
ZERO = 1
OFFSET_MASK = 0x00FFFFFFFFFFFE00

# Incompatible feature bits (version 3).
DIRTY, CORRUPT, EXTERNAL_DATA, COMPRESSION_TYPE, EXTENDED_L2 = (
    1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4)

L2_TABLES_KEPT = 64
CLUSTERS_KEPT = 64
MAX_BACKING = 16


class Qcow2Error(Exception):
    """Not a QCOW2 image this module can read; the message says why."""


class Qcow2Image:
    def __init__(self, path, depth=0, sibling=None):
        self.path = path
        self._handle = open(path, 'rb')
        self.parent = None
        try:
            self._read_header(sibling, depth)
        except Exception:
            self.close()
            raise
        self._l2 = OrderedDict()
        self._clusters = OrderedDict()

    def _read_header(self, sibling, depth):
        head = self._handle.read(112)
        if len(head) < 72 or head[:4] != MAGIC:
            raise Qcow2Error("not a QCOW image")
        version = struct.unpack_from('>I', head, 4)[0]
        if version not in (2, 3):
            raise Qcow2Error(f"QCOW version {version}")
        (backing_offset, backing_size, self.cluster_bits, self.size,
         crypt, l1_size, l1_offset) = struct.unpack_from('>QIIQIIQ', head, 8)
        if crypt:
            raise Qcow2Error("encrypted")
        if not 9 <= self.cluster_bits <= 21:
            raise Qcow2Error(f"cluster bits {self.cluster_bits}")
        self.cluster_size = 1 << self.cluster_bits
        self.compression = 'zlib'
        self.incompatible = 0
        if version == 3:
            self.incompatible = struct.unpack_from('>Q', head, 72)[0]
            header_length = struct.unpack_from('>I', head, 100)[0]
            if self.incompatible & (EXTERNAL_DATA | EXTENDED_L2) or \
                    self.incompatible & ~0x1F:
                raise Qcow2Error(f"incompatible features "
                                 f"{self.incompatible:#x}")
            if self.incompatible & COMPRESSION_TYPE and \
                    header_length > 104:
                kind = head[104]
                if kind not in (0, 1):
                    raise Qcow2Error(f"compression type {kind}")
                self.compression = 'zstd' if kind == 1 else 'zlib'
        self._l2_entries = self.cluster_size // 8
        self._compressed_bits = 62 - (self.cluster_bits - 8)
        if l1_size > (1 << 26):
            raise Qcow2Error("implausible L1 table")
        self._handle.seek(l1_offset)
        table = self._handle.read(8 * l1_size)
        if len(table) < 8 * l1_size:
            raise Qcow2Error("L1 table past the end of the file")
        self._l1 = struct.unpack(f'>{l1_size}Q', table)
        if backing_offset and backing_size:
            if depth >= MAX_BACKING:
                raise Qcow2Error("backing chain too long")
            self._handle.seek(backing_offset)
            name = self._handle.read(min(backing_size, 1023)).decode(
                'utf-8', 'replace')
            self.backing_name = name
            path = sibling(self.path, name) if sibling else None
            if path is None:
                raise Qcow2Error(f"backing file {name} not found beside it")
            self.parent = Qcow2Image(path, depth + 1, sibling)
        else:
            self.backing_name = ''

    # --- libyal's vocabulary -------------------------------------------------

    def get_media_size(self):
        return self.size

    def close(self):
        if self.parent is not None:
            self.parent.close()
        try:
            self._handle.close()
        except Exception:
            pass

    def chain_length(self):
        return 1 + (self.parent.chain_length() if self.parent else 0)

    def read_buffer_at_offset(self, length, offset):
        if offset >= self.size or length <= 0:
            return b''
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            within = offset & (self.cluster_size - 1)
            part = min(length, self.cluster_size - within)
            out += self._cluster_part(offset - within, within, part)
            offset += part
            length -= part
        return bytes(out)

    # --- clusters ------------------------------------------------------------

    def _entry(self, guest):
        index = guest >> self.cluster_bits
        l1_index, l2_index = divmod(index, self._l2_entries)
        if l1_index >= len(self._l1):
            return 0
        table_offset = self._l1[l1_index] & OFFSET_MASK
        if not table_offset:
            return 0
        table = self._l2.get(table_offset)
        if table is None:
            self._handle.seek(table_offset)
            data = self._handle.read(self.cluster_size)
            data += b'\0' * (self.cluster_size - len(data))
            table = struct.unpack(f'>{self._l2_entries}Q', data)
            self._l2[table_offset] = table
            if len(self._l2) > L2_TABLES_KEPT:
                self._l2.popitem(last=False)
        else:
            self._l2.move_to_end(table_offset)
        return table[l2_index]

    def _cluster_part(self, guest, within, length):
        entry = self._entry(guest)
        if entry & COMPRESSED:
            return self._compressed(entry)[within:within + length]
        host = entry & OFFSET_MASK
        if entry & ZERO:
            return b'\0' * length
        if not host:
            if self.parent is not None:
                data = self.parent.read_buffer_at_offset(length,
                                                         guest + within)
                return data + b'\0' * (length - len(data))
            return b'\0' * length
        self._handle.seek(host + within)
        data = self._handle.read(length)
        return data + b'\0' * (length - len(data))

    def _compressed(self, entry):
        """A compressed cluster: the offset is every bit below
        `_compressed_bits` -- bit 0 included, which is libqcow's error --
        and the sectors after the first one it starts in above that."""
        descriptor = entry & ((1 << 62) - 1)
        host = descriptor & ((1 << self._compressed_bits) - 1)
        cached = self._clusters.get(host)
        if cached is not None:
            self._clusters.move_to_end(host)
            return cached
        sectors = (descriptor >> self._compressed_bits) + 1
        stored = sectors * 512 - (host & 511)
        self._handle.seek(host)
        raw = self._handle.read(stored)
        try:
            if self.compression == 'zstd':
                data = zstd_decode.decompress_frame(raw, self.cluster_size)
            else:
                data = zlib.decompressobj(-15).decompress(raw,
                                                          self.cluster_size)
        except (zlib.error, zstd_decode.ZstdError) as exc:
            raise OSError(f"compressed cluster at {host:#x} unreadable: "
                          f"{exc}") from exc
        data = data[:self.cluster_size]
        data += b'\0' * (self.cluster_size - len(data))
        self._clusters[host] = data
        if len(self._clusters) > CLUSTERS_KEPT:
            self._clusters.popitem(last=False)
        return data


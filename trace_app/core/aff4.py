"""AFF4 disk images, read in Python (no Qt, no compiled code).

AFF4 (the Advanced Forensic Format, Standard v1.0 -- what Evimetry and
pmem write) is a ZIP container. `information.turtle` (RDF; core/turtle.py)
says what is inside: an aff4:Image whose aff4:dataStream is either an
aff4:ImageStream -- the data in fixed-size chunks, compressed (Snappy, LZ4,
deflate) or stored, grouped in segments ("bevies") with an index of each
chunk's offset and length -- or an aff4:Map, which lays the disk out from
ranges of streams: the image stream, and symbolic ones for what was not
read (zeros, aff4:UnknownData for an allocated-only acquisition,
aff4:UnreadableData for read errors -- repeated so they cannot be taken
for real data).

pyaff4 cannot be installed without a compiler (it pins aff4-snappy, an
sdist, and packages with no wheels for Python 3.10+), so this reads the
format itself. Snappy is core/snappy.py; LZ4 the journal reader's decoder.

`Aff4Image(path)` is libyal-shaped -- `read_buffer_at_offset`, `size` --
so it plugs into containers.LibyalImgInfo like a virtual disk. `verify()`
re-hashes every image stream and compares the hashes it recorded at
acquisition. `facts()` gives the case details, notes, times and the disk's
make, model and serial.
"""

import hashlib
import logging
import struct
import threading
import zipfile
import zlib
from collections import OrderedDict
from urllib.parse import quote

from trace_app.core import turtle
from trace_app.core.turtle import RDF_TYPE

logger = logging.getLogger('TRACE.AFF4')

AFF4 = 'http://aff4.org/Schema#'

#: Compression IRIs -> name. Older images used the code.google.com IRIs.
COMPRESSIONS = {
    'http://code.google.com/p/snappy/': 'snappy',
    'https://code.google.com/p/snappy/': 'snappy',
    'http://code.google.com/p/lz4/': 'lz4',
    'https://code.google.com/p/lz4/': 'lz4',
    'https://tools.ietf.org/html/rfc1951': 'deflate',
    'http://tools.ietf.org/html/rfc1951': 'deflate',
    'https://www.ietf.org/rfc/rfc1950.txt': 'zlib',
    AFF4 + 'NullCompressor': 'stored',
    'http://aff4.org/Schema#NullCompressor': 'stored',
}

#: Hash datatypes that hash a stream's data, -> hashlib name.
STREAM_HASHES = {AFF4 + 'MD5': 'md5', AFF4 + 'SHA1': 'sha1',
                 AFF4 + 'SHA256': 'sha256', AFF4 + 'SHA512': 'sha512'}

#: Symbolic streams that are a repeated pattern (what a map points at for
#: what was never read).
SYMBOLIC = {AFF4 + 'Zero': b'\0', AFF4 + 'UnknownData': b'UNKNOWN',
            AFF4 + 'UnreadableData': b'UNREADABLEDATA'}

#: The tile a symbolic pattern repeats in (see _Symbolic).
_TILE = 1024 * 1024

#: Decompressed chunks kept, per stream: a 32 KB chunk is read in pieces by
#: TSK and the file walk.
_CACHED_CHUNKS = 64


class Aff4Error(Exception):
    """The container is not an AFF4 image this reader can read."""


def _types(node):
    return {t.rsplit('#', 1)[-1] for t in node.get(RDF_TYPE, ())}


def _one(node, name, default=None):
    values = node.get(AFF4 + name)
    return values[0] if values else default


class _Symbolic:
    def __init__(self, iri):
        if iri in SYMBOLIC:
            self.pattern = SYMBOLIC[iri]
        elif iri.startswith(AFF4 + 'SymbolicStream') and \
                len(iri) == len(AFF4) + len('SymbolicStream') + 2:
            self.pattern = bytes([int(iri[-2:], 16)])
        else:
            raise Aff4Error(f"Unknown symbolic stream {iri}")
        self.iri = iri

        # Repeated in tiles of exactly 1 MiB, as the reference implementation
        # (pyaff4) and Evimetry do: 'UNKNOWN' does not divide 1 MiB, so the
        # pattern's phase restarts at each MiB -- repeating it seamlessly
        # gave different bytes, and a different disk hash, after the first.
        tile = self.pattern * (_TILE // len(self.pattern))
        self.tile = tile + self.pattern[:_TILE - len(tile)]

    def read(self, offset, length):
        out = []
        while length > 0:
            within = offset % _TILE
            piece = self.tile[within:within + length]
            out.append(piece)
            offset += len(piece)
            length -= len(piece)
        return b''.join(out)


class _ImageStream:
    """Chunks in bevies: '<urn>/00000000' (the chunks) and
    '<urn>/00000000.index' (each chunk's offset and length)."""

    def __init__(self, container, urn, node):
        self.container = container
        self.urn = urn
        self.chunk_size = int(_one(node, 'chunkSize', 32768))
        self.per_segment = int(_one(node, 'chunksInSegment', 2048))
        self.size = int(_one(node, 'size', 0))
        method = _one(node, 'compressionMethod', AFF4 + 'NullCompressor')
        self.compression = COMPRESSIONS.get(method)
        if self.compression is None:
            raise Aff4Error(f"Unsupported compression {method}")
        self.hashes = {STREAM_HASHES[h.datatype]: str(h).lower()
                       for h in node.get(AFF4 + 'hash', ())
                       if getattr(h, 'datatype', '') in STREAM_HASHES}
        self._indexes = {}
        self._chunks = OrderedDict()

    def _index(self, segment):
        if segment not in self._indexes:
            data = self.container.member(self.urn, f'{segment:08d}.index')
            count = len(data) // 12
            self._indexes[segment] = [struct.unpack_from('<QI', data, i * 12)
                                      for i in range(count)]
        return self._indexes[segment]

    def chunk(self, number):
        cached = self._chunks.get(number)
        if cached is not None:
            self._chunks.move_to_end(number)
            return cached
        segment, position = divmod(number, self.per_segment)
        index = self._index(segment)
        if position >= len(index):
            raise Aff4Error(f"Chunk {number} is not in the stream")
        offset, length = index[position]
        raw = self.container.member_range(self.urn, f'{segment:08d}',
                                          offset, length)
        data = self._decompress(raw)
        self._chunks[number] = data
        if len(self._chunks) > _CACHED_CHUNKS:
            self._chunks.popitem(last=False)
        return data

    def _decompress(self, raw):
        # A chunk that would not compress is stored as it is: AFF4 marks
        # that only by its length being the chunk size.
        if len(raw) == self.chunk_size or self.compression == 'stored':
            return raw
        if self.compression == 'snappy':
            from trace_app.core.snappy import decompress
            return decompress(raw)
        if self.compression == 'lz4':
            from trace_app.core.activity.journal import lz4_block
            return lz4_block(raw, self.chunk_size)
        if self.compression == 'deflate':
            return zlib.decompress(raw, -15)
        return zlib.decompress(raw)

    def read(self, offset, length):
        end = min(offset + length, self.size)
        out = []
        while offset < end:
            number, within = divmod(offset, self.chunk_size)
            data = self.chunk(number)[within:within + end - offset]
            if not data:
                break
            out.append(data)
            offset += len(data)
        return b''.join(out)


class _Map:
    """The disk laid out from ranges of other streams: 'map' (entries of
    map offset, length, target offset, target number -- 28 bytes, little-
    endian) and 'idx' (the targets' IRIs, one per line)."""

    def __init__(self, container, urn, node):
        self.size = int(_one(node, 'size', 0))
        targets = container.member(urn, 'idx').decode('utf-8').split('\n')
        self.targets = [container.stream(t.strip()) for t in targets
                        if t.strip()]
        gap = _one(node, 'mapGapDefaultStream', AFF4 + 'Zero')
        self.gap = container.stream(gap)
        data = container.member(urn, 'map')
        entries = [struct.unpack_from('<QQQI', data, i * 28)
                   for i in range(len(data) // 28)]
        entries.sort()
        self.starts = [e[0] for e in entries]
        self.entries = entries

    def read(self, offset, length):
        import bisect
        end = min(offset + length, self.size)
        out = []
        while offset < end:
            index = bisect.bisect_right(self.starts, offset) - 1
            if index >= 0:
                start, span, target_offset, target = self.entries[index]
                if offset < start + span:
                    take = min(end, start + span) - offset
                    out.append(self.targets[target].read(
                        target_offset + offset - start, take))
                    offset += take
                    continue
            # A gap: up to the next range, from the default stream.
            following = self.starts[index + 1] \
                if index + 1 < len(self.starts) else end
            take = min(end, following) - offset
            out.append(self.gap.read(offset, take))
            offset += take
        return b''.join(out)


class Aff4Image:
    """One AFF4 container's (first) disk image, libyal-shaped."""

    def __init__(self, path):
        try:
            self.zip = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile) as exc:
            raise Aff4Error(f"Not an AFF4 container: {exc}") from exc
        self._lock = threading.Lock()
        self._names = set(self.zip.namelist())
        try:
            text = self.zip.read('information.turtle').decode('utf-8')
        except KeyError:
            self.zip.close()
            raise Aff4Error("No information.turtle: not an AFF4 Standard "
                            "container (AFF4-L logical images and pre-"
                            "standard images are not read)")
        try:
            self.graph = turtle.parse(text)
        except turtle.TurtleError as exc:
            self.zip.close()
            raise Aff4Error(f"Unreadable information.turtle: {exc}") from exc
        self._streams = {}
        images = [urn for urn, node in self.graph.items()
                  if 'Image' in _types(node) and
                  _one(node, 'dataStream') is not None]
        if not images:
            self.zip.close()
            raise Aff4Error("No disk image in this container (a striped "
                            "image's other parts, or logical evidence)")
        # A disk image before anything else (a container may hold more).
        images.sort(key=lambda urn: 'DiskImage' not in
                    _types(self.graph[urn]))
        self.image_urn = images[0]
        node = self.graph[self.image_urn]
        self.data = self.stream(_one(node, 'dataStream'))
        self.size = int(_one(node, 'size', 0) or self.data.size)

    # --- members --------------------------------------------------------------

    def _member_name(self, urn, suffix):
        name = f"{quote(urn, safe='')}/{suffix}"
        if name not in self._names:
            # Some writers escape only the scheme's ':' and '/'.
            alternative = f"{urn.replace(':', '%3A').replace('/', '%2F')}" \
                          f"/{suffix}"
            if alternative in self._names:
                return alternative
            raise Aff4Error(f"Missing {suffix} of {urn} -- a striped image "
                            f"needs all its parts")
        return name

    def member(self, urn, suffix):
        with self._lock:
            return self.zip.read(self._member_name(urn, suffix))

    def member_range(self, urn, suffix, offset, length):
        """Bytes of a stored (uncompressed) member, without reading all of
        it: a bevy is up to 64 MB."""
        with self._lock:
            with self.zip.open(self._member_name(urn, suffix)) as handle:
                handle.seek(offset)
                return handle.read(length)

    def stream(self, iri):
        iri = str(iri)
        if iri not in self._streams:
            if iri.startswith(AFF4 + 'SymbolicStream') or iri in SYMBOLIC:
                self._streams[iri] = _Symbolic(iri)
            else:
                node = self.graph.get(iri)
                if node is None:
                    raise Aff4Error(f"Stream {iri} is not described")
                kinds = _types(node)
                if 'ImageStream' in kinds:
                    self._streams[iri] = _ImageStream(self, iri, node)
                elif 'Map' in kinds:
                    self._streams[iri] = _Map(self, iri, node)
                else:
                    raise Aff4Error(f"Unsupported stream type {kinds}")
        return self._streams[iri]

    # --- what the image holds ---------------------------------------------------

    def read_buffer_at_offset(self, length, offset):
        if offset >= self.size or length <= 0:
            return b''
        return self.data.read(offset, min(length, self.size - offset))

    def get_media_size(self):
        return self.size

    def close(self):
        try:
            self.zip.close()
        except Exception:
            pass

    def image_streams(self):
        return [s for s in (self.stream(urn) for urn, node in
                            self.graph.items()
                            if 'ImageStream' in _types(node))]

    def verify(self, progress=None):
        """Re-hash every image stream's data and compare the hashes it
        recorded: [{'stream', 'algorithm', 'expected', 'computed', 'ok'}].
        `progress(done, total)` in bytes; raising from it stops."""
        streams = [s for s in self.image_streams() if s.hashes]
        total = sum(s.size for s in streams)
        done = 0
        results = []
        for stream in streams:
            hashers = {name: hashlib.new(name) for name in stream.hashes}
            chunks = (stream.size + stream.chunk_size - 1) // stream.chunk_size
            remaining = stream.size
            try:
                for number in range(chunks):
                    data = stream.chunk(number)[:remaining]
                    for hasher in hashers.values():
                        hasher.update(data)
                    remaining -= len(data)
                    done += len(data)
                    if progress is not None:
                        progress(done, total)
            except (Aff4Error, zipfile.BadZipFile, ValueError, zlib.error,
                    OSError) as exc:
                # Damage the container itself notices -- the ZIP's CRC-32 of
                # a segment, a chunk that will not decompress -- is a failed
                # check too, with its reason.
                results.append({'stream': stream.urn, 'algorithm': 'read',
                                'expected': '', 'computed': '', 'ok': False,
                                'error': str(exc)})
                continue
            for name, hasher in hashers.items():
                computed = hasher.hexdigest()
                results.append({'stream': stream.urn, 'algorithm': name,
                                'expected': stream.hashes[name],
                                'computed': computed,
                                'ok': computed == stream.hashes[name]})
        return results

    def facts(self):
        """Acquisition and case details, labelled as the E01 ones are (so
        custody fields fill from them alike)."""
        out = {'Format': 'AFF4 (Standard v1.0)'}
        node = self.graph[self.image_urn]
        for label, name in (('Disk', 'diskMake'), ('Model', 'diskModel'),
                            ('Serial', 'diskSerial'),
                            ('Device', 'diskDeviceName'),
                            ('Interface', 'diskInterfaceType'),
                            ('Partition table', 'diskPartitionTableType'),
                            ('Acquisition', 'acquisitionCompletionState')):
            value = _one(node, name)
            if value:
                out[label] = str(value)
        for urn, other in self.graph.items():
            kinds = _types(other)
            if 'CaseDetails' in kinds:
                for label, name in (('Case Number', 'caseNumber'),
                                    ('Case', 'caseName'),
                                    ('Description', 'caseDescription'),
                                    ('Examiner', 'examiner')):
                    value = _one(other, name)
                    if value and label not in out:
                        out[label] = str(value)
            elif 'CaseNotes' in kinds:
                for label, name in (('Case Number', 'caseNumber'),
                                    ('Evidence Number', 'evidenceNumber'),
                                    ('Examiner', 'examiner')):
                    value = _one(other, name)
                    if value and label not in out:
                        out[label] = str(value)
                note = _one(other, 'notes')
                if note:
                    out.setdefault('Notes', [])
                    out['Notes'].append(str(note))
            elif 'TimeStamps' in kinds:
                start = _one(other, 'startTime')
                if start and 'Acquired' not in out:
                    out['Acquired'] = str(start).replace('T', ' ').rstrip(
                        'Z') + ' UTC'
        tool = self.zip.read('version.txt').decode('utf-8', 'replace') \
            if 'version.txt' in self._names else ''
        for line in tool.splitlines():
            if line.startswith('tool='):
                out['Acquisition Tool'] = line[5:].strip()
        if isinstance(out.get('Notes'), list):
            out['Notes'] = ' / '.join(out['Notes'])
        return out


def open_aff4(path):
    """(img_info for TSK, note) for an AFF4 image."""
    from trace_app.core.containers import LibyalImgInfo
    image = Aff4Image(path)
    streams = image.image_streams()
    methods = sorted({s.compression for s in streams})
    return (LibyalImgInfo(image, image.size),
            f"AFF4 ({', '.join(methods) or 'no image stream'})")

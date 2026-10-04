"""AccessData AD1 logical images -- the "custom content images" FTK Imager
writes when an examiner exports chosen files and folders rather than a
whole disk -- read in Python and presented as a LogicalFileSystem.

An image is one or more segment files (x.ad1, x.ad2, ...). Each opens with
a 512-byte margin: 'ADSEGMENTEDFILE', its number (u32 at 24) and the
count (u32 at 28), and the segment's size, margin included (u64 at 32).
Addresses skip every margin, so the segments' payloads read as one
stream. At address 0 the image header: 'ADLOGICALIMAGE', version (3 or 4,
u32 at 16), zlib chunk size (u32 at 24), the first item (u64 at 36), the
source's name (length u32 at 44; at 48, or at the u64 at 52 in v4).

Items are a tree. Each item: next sibling, first child, first metadata
entry, chunk table, size (u64s at 0-32), type (u32 at 40: 5 a folder, 0 a
file) and its name (length u32 at 44, the name at 48). Content is stored
in zlib chunks: the table is a count, then count+1 addresses bounding
them. Metadata entries are a chain: next (u64), category, key, length
(u32s) and a text value -- hashes (category 1: 0x5001 MD5, 0x5002
SHA-1), size (3/3), flags (4), times (5: 7 accessed, 8 created, 9
modified, 0xa002 record changed; 'YYYYMMDDTHHMMSS[.ffffff]', UTC).

The layout follows P. C. Bjelland's notes and pyad1, and the Sootmark
reader. Checked on pyad1's image and dissect.evidence's: every file's
content hashes to the MD5 and SHA-1 FTK recorded for it, and the
image-wide hash this computes is the one FTK Imager logged.

Encrypted images ('ADCRYPT') are recognised and refused with that reason.
"""

import calendar
import glob
import hashlib
import logging
import os
import re
import struct
import threading
import zlib

from trace_app.core.logical import ROOT, LogicalFileSystem

logger = logging.getLogger('TRACE.AD1')

MARGIN = 512
SEGMENT_SIGNATURE = b'ADSEGMENTEDFILE'
IMAGE_SIGNATURE = b'ADLOGICALIMAGE'
ENCRYPTED_SIGNATURE = b'ADCRYPT'
FOLDER = 5
#: Metadata categories and keys.
TEXT, NUMBER, FLAG, TIME = 1, 3, 4, 5
MD5, SHA1, SIZE = 0x5001, 0x5002, 0x3
ACCESSED, CREATED, MODIFIED, RECORD_CHANGED = 0x7, 0x8, 0x9, 0xa002
#: What the flags (category 4) say, as far as they are known.
FLAG_NAMES = {0xd: 'encrypted', 0xe: 'compressed', 0x1e: 'archive',
              0x1002: 'hidden', 0x1003: 'system', 0x1004: 'read only',
              0x1005: 'archive (NTFS)'}
#: Limits past which a structure is damage, not data.
MAX_ITEMS = 20_000_000
MAX_NAME = 1 << 16
MAX_VALUE = 1 << 20
#: The trailer at the end of the last segment (v4), part of the image hash.
TRAILER = 372


class AD1Error(Exception):
    pass


def segment_paths(first):
    """x.ad1, x.ad2, ... while they exist, whatever case the extension."""
    stem = first[:-1]
    found = {}
    for path in glob.glob(glob.escape(stem) + '*'):
        match = re.fullmatch(r'(?i)\.ad(\d+)', path[len(stem) - 3:])
        if match:
            found[int(match.group(1))] = path
    out = []
    for number in range(1, len(found) + 1):
        if number not in found:
            break
        out.append(found[number])
    return out or [first]


class Image:
    """An opened AD1: its items and their content, read on demand."""

    def __init__(self, path):
        self.paths = segment_paths(path)
        self._files = []
        self._lock = threading.Lock()
        try:
            self._files = [open(p, 'rb') for p in self.paths]
            self._check_segments()
            self._read_header()
        except Exception:
            self.close()
            raise

    def close(self):
        for handle in self._files:
            try:
                handle.close()
            except OSError:
                pass
        self._files = []

    # --- the stream ----------------------------------------------------------

    def _check_segments(self):
        count = len(self._files)
        for index, handle in enumerate(self._files):
            margin = handle.read(MARGIN)
            if margin.startswith(ENCRYPTED_SIGNATURE):
                raise AD1Error("encrypted AD1 image: not supported")
            if not margin.startswith(SEGMENT_SIGNATURE):
                raise AD1Error(f"segment {index + 1} is not an AD1 segment")
            number, of = struct.unpack_from('<II', margin, 24)
            if number != index + 1 or of != count:
                missing = f" (found {count})" if of != count else ''
                raise AD1Error(f"segment {index + 1} says it is {number} of "
                               f"{of}{missing}")
            if index == 0:
                self.segment_size = struct.unpack_from('<Q', margin, 32)[0] \
                    - MARGIN
        if self.segment_size <= 0:
            raise AD1Error("segment size of 0")
        last = os.path.getsize(self.paths[-1])
        #: Where the items end: the last segment closes with a margin-sized
        #: trailer.
        self.end = (count - 1) * self.segment_size + max(0, last - 2 * MARGIN)

    def read(self, address, length):
        with self._lock:
            return self._read(address, length)

    def _read(self, address, length):
        out = bytearray()
        while length > 0:
            index, within = divmod(address, self.segment_size)
            if index >= len(self._files):
                raise AD1Error(f"address {address} is past the last segment")
            want = min(length, self.segment_size - within)
            handle = self._files[index]
            handle.seek(MARGIN + within)
            data = handle.read(want)
            if len(data) != want:
                raise AD1Error(f"segment {index + 1} ends early")
            out += data
            address += want
            length -= want
        return bytes(out)

    def _u64(self, address):
        return struct.unpack('<Q', self.read(address, 8))[0]

    # --- the header and items ------------------------------------------------

    def _read_header(self):
        header = self.read(0, 92)
        if not header.startswith(IMAGE_SIGNATURE):
            raise AD1Error("no image header (ADLOGICALIMAGE)")
        self.version = struct.unpack_from('<I', header, 16)[0]
        self.chunk_size = struct.unpack_from('<I', header, 24)[0]
        if not 0 < self.chunk_size <= 1 << 26:
            raise AD1Error(f"zlib chunk size {self.chunk_size}")
        self.first = struct.unpack_from('<Q', header, 36)[0]
        name_length = min(struct.unpack_from('<I', header, 44)[0], MAX_NAME)
        name_at = struct.unpack_from('<Q', header, 52)[0] \
            if self.version >= 4 else 48
        self.name_at, self.name_length = name_at, name_length
        self.source = _text(self.read(name_at, name_length))

    def items(self):
        """Every item, depth first, folders before what they hold:
        dicts of address, parent (address or None), name, kind, size,
        chunks (table address) and metadata [(category, key, value)]."""
        out = []
        seen = set()
        groups = [(self.first, None)]
        while groups:
            address, parent = groups.pop()
            while address:
                if address in seen or len(out) >= MAX_ITEMS:
                    raise AD1Error(f"item at {address} reached twice")
                seen.add(address)
                head = self.read(address, 48)
                (following, child, metadata, chunks,
                 size) = struct.unpack_from('<5Q', head)
                kind, name_length = struct.unpack_from('<II', head, 40)
                if name_length > MAX_NAME:
                    raise AD1Error(f"item at {address}: a name of "
                                   f"{name_length} bytes")
                out.append({'address': address, 'parent': parent,
                            'name': _text(self.read(address + 48,
                                                    name_length)),
                            'kind': kind, 'size': size, 'chunks': chunks,
                            'metadata': self._metadata(metadata)})
                if child:
                    groups.append((child, address))
                address = following
        return out

    def _metadata(self, address):
        values = []
        seen = set()
        while address and address not in seen and len(values) < 10_000:
            seen.add(address)
            head = self.read(address, 20)
            following = struct.unpack_from('<Q', head)[0]
            category, key, length = struct.unpack_from('<III', head, 8)
            values.append((category, key, _text(
                self.read(address + 20, min(length, MAX_VALUE)))))
            address = following
        return values

    # --- content ---------------------------------------------------------------

    def chunk_table(self, table, size):
        count = self._u64(table)
        needed = -(-size // self.chunk_size)
        if count != needed and not (count == 1 and size == 0):
            raise AD1Error(f"{count} chunks for {size} bytes")
        return struct.unpack(f'<{count + 1}Q', self.read(table + 8,
                                                         (count + 1) * 8))

    def chunk(self, bounds, index):
        start, end = bounds[index], bounds[index + 1]
        if end <= start or end - start > self.chunk_size * 2 + 1024:
            raise AD1Error(f"chunk {index} spans {start}..{end}")
        return zlib.decompress(self.read(start, end - start))

    def reader(self, table, size):
        """read(offset, length) over one item's content, a chunk at a
        time; the last chunk read is kept for the next read."""
        state = {'bounds': None, 'index': None, 'data': b''}

        def read(offset, length):
            if state['bounds'] is None:
                state['bounds'] = self.chunk_table(table, size)
            out = bytearray()
            while length > 0 and offset < size:
                index, within = divmod(offset, self.chunk_size)
                if state['index'] != index:
                    state['data'] = self.chunk(state['bounds'], index)
                    state['index'] = index
                piece = state['data'][within:within + length]
                if not piece:
                    break
                out += piece
                offset += len(piece)
                length -= len(piece)
            return bytes(out)
        return read

    # --- the image-wide hash --------------------------------------------------

    def image_hashes(self, progress=None, should_stop=None):
        """The MD5 and SHA-1 FTK Imager logs for the image, computed: over
        the header, the trailer at the end of the last segment, every
        item's structure and metadata as stored -- not the chunk tables or
        compressed bytes -- and then the digest of all the content,
        decompressed, in the image's order (pyad1's reading of it)."""
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        content_md5, content_sha1 = hashlib.md5(), hashlib.sha1()

        def meta(data):
            md5.update(data)
            sha1.update(data)

        fields = 16 + 4 + 4 + 4 + 8 + 8 + 4 + (44 if self.version == 4 else 0)
        header_end = fields + self.name_length
        if self.source != 'Custom Content Image([Multi])':
            header_end = max(header_end, self.first)
        meta(self.read(0, header_end))
        if self.version == 4:
            with open(self.paths[-1], 'rb') as handle:
                handle.seek(-TRAILER, os.SEEK_END)
                meta(handle.read())
        address = header_end
        while address < self.end:
            if should_stop is not None and should_stop():
                return None
            head = self.read(address, 48)
            meta(head)
            following, _child, metadata, _chunks, size = \
                struct.unpack_from('<5Q', head)
            name_length = struct.unpack_from('<I', head, 44)[0]
            meta(self.read(address + 48, name_length + 8))
            address += 48 + name_length + 8
            if size > 0:
                bounds = self.chunk_table(address, size)
                for index in range(len(bounds) - 1):
                    data = self.chunk(bounds, index)
                    content_md5.update(data)
                    content_sha1.update(data)
                address = bounds[-1]
            more = metadata
            while more:
                head = self.read(address, 20)
                meta(head)
                more = struct.unpack_from('<Q', head)[0]
                length = struct.unpack_from('<I', head, 16)[0]
                meta(self.read(address + 20, length))
                address += 20 + length
            if progress is not None:
                progress(address, self.end)
        md5.update(content_md5.digest())
        sha1.update(content_sha1.digest())
        return md5.hexdigest(), sha1.hexdigest()


def _text(raw):
    return raw.split(b'\x00', 1)[0].decode('utf-8', 'replace')


def _time(text):
    """'YYYYMMDDTHHMMSS[.ffffff]' (UTC) -> (seconds, nanoseconds)."""
    match = re.fullmatch(r'(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)'
                         r'(?:\.(\d{1,9}))?', text or '')
    if not match:
        return None
    parts = [int(g) for g in match.groups()[:6]]
    try:
        seconds = calendar.timegm((*parts, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    fraction = match.group(7) or ''
    return seconds, int(fraction.ljust(9, '0')) if fraction else 0


def open_ad1(path):
    """The image at `path` (its first segment) as a LogicalFileSystem."""
    image = Image(path)
    fs = LogicalFileSystem('AD1', path)
    fs.facts.update({
        'Format': f"AccessData AD1, version {image.version}",
        'Source': image.source,
        'Segments': f"{len(image.paths)}",
        'Chunk Size': f"{image.chunk_size:,} bytes",
        '_close': image.close,
        '_image': image})
    try:
        items = image.items()
    except AD1Error:
        image.close()
        raise
    inodes = {}
    for item in items:
        values = {}
        flags = []
        times = {}
        for category, key, value in item['metadata']:
            values[(category, key)] = value
            if category == FLAG and value == 'true' and key in FLAG_NAMES:
                flags.append(FLAG_NAMES[key])
        for slot, key in (('atime', ACCESSED), ('crtime', CREATED),
                          ('mtime', MODIFIED), ('ctime', RECORD_CHANGED)):
            stamp = _time(values.get((TIME, key)))
            if stamp is not None:
                times[slot] = stamp
        facts = {k: v for k, v in (('md5', values.get((TEXT, MD5))),
                                   ('sha1', values.get((TEXT, SHA1))),
                                   ('attributes', ', '.join(flags)))
                 if v}
        parent = inodes.get(item['parent'], ROOT)
        folder = item['kind'] == FOLDER
        size = 0 if folder else item['size']
        reader = image.reader(item['chunks'], size) \
            if item['chunks'] and size else None
        inodes[item['address']] = fs.add(
            parent, item['name'] or '(unnamed)', folder, size=size,
            times=times, reader=reader, facts=facts)
    return fs


def verify(path, progress=None, should_stop=None):
    """{'computed_md5', 'computed_sha1'} for the image at `path`."""
    image = Image(path)
    try:
        hashes = image.image_hashes(progress, should_stop)
    finally:
        image.close()
    if hashes is None:
        return None
    return {'computed_md5': hashes[0], 'computed_sha1': hashes[1]}


def logged_hashes(path):
    """The MD5 and SHA-1 FTK Imager wrote in the image's log (x.ad1.txt),
    when the log is beside it: what the image was acquired as."""
    log = path + '.txt'
    if not os.path.exists(log):
        return {}
    with open(log, 'rb') as handle:
        text = handle.read(1 << 20).decode('utf-8-sig', 'replace')
    found = {}
    computed = text.split('[Computed Hashes]', 1)[-1]
    for name, pattern in (('stored_md5', r'MD5 checksum:\s*([0-9a-fA-F]{32})'),
                          ('stored_sha1',
                           r'SHA1 checksum:\s*([0-9a-fA-F]{40})')):
        match = re.search(pattern, computed)
        if match:
            found[name] = match.group(1).lower()
    return found

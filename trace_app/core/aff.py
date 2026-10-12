"""AFF (Advanced Forensic Format, AFFLIB v1-v3) images, read in Python.

AFF was Simson Garfinkel's open image format (AFFLIB): Digital Corpora's
older images and some FTK and Helix acquisitions are AFF. AFFLIB has no
wheels. AFF4 is a different format (core/aff4.py). An .aff file is:

* the header "AFF10\\r\\n\\0";
* segments, each "AFF\\0", the name's length, the data's length and a
  32-bit argument (all big-endian), the name, the data, then "ATT\\0" and
  the segment's whole length;
* metadata segments -- 'pagesize' (argument: bytes per page; 'segsize'
  in old files), 'imagesize' (a 64-bit quad: two big-endian 32-bit
  halves, low first), 'sectorsize', 'md5' / 'sha1' / 'sha256' of the
  whole image, acquisition details;
* data segments 'page<n>' (or 'seg<n>'): page n's bytes, compressed when
  the argument says so -- zlib, bzip2, LZMA (the .lzma format), or
  "all zeros" (the data is the count, 4 bytes); a missing page was never
  written (read as zeros, and said so).

Encrypted AFF (segments named '.../aes256') is refused by name.

Split AFF, as AFFLIB writes it (affconvert -M):

* AFD: a folder 'name.afd' of ordinary .aff files (file_000.aff,
  file_001.aff, ...), the segments shared out among them -- read as one
  file whose segments are all of theirs;
* AFM: 'name.afm', an .aff file of metadata only (aff_file_type 'AFM'),
  beside the image as split raw files 'name.000', 'name.001', ... (the
  'raw_image_file_extension' segment names the first), each
  'pages_per_raw_image_file' pages long -- 0 meaning one file holds it all.
  AFFLIB's own affcat reads only the first page of such a one-file AFM;
  the recorded image size and MD5 are what TRACE goes by.
"""

import bz2
import os
import struct
import zlib

FILE_HEADER = b'AFF10\r\n\0'
SEGMENT_HEAD = b'AFF\0'
SEGMENT_TAIL = b'ATT\0'

COMPRESSED = 0x0001
ALGORITHM_MASK = 0x00F0
ZLIB, BZIP, LZMA, ZERO = 0x0000, 0x0010, 0x0020, 0x0030
ALGORITHM_NAMES = {ZLIB: 'zlib', BZIP: 'bzip2', LZMA: 'LZMA', ZERO: 'zero'}


class AffError(Exception):
    pass


def is_aff(head):
    return head[:8] == FILE_HEADER


def _quad(data):
    """AFFLIB's 64-bit value: two big-endian 32-bit halves, low first."""
    low, high = struct.unpack('>II', data[:8])
    return high << 32 | low


def afd_files(folder):
    """An AFD folder's .aff files, in their order."""
    names = sorted(n for n in os.listdir(folder)
                   if n.lower().endswith('.aff'))
    return [os.path.join(folder, n) for n in names]


def is_afd(path):
    """Whether `path` is an AFD folder: a folder whose .aff files are
    AFF."""
    if not os.path.isdir(path):
        return False
    try:
        files = afd_files(path)
        if not files:
            return False
        with open(files[0], 'rb') as handle:
            return is_aff(handle.read(8))
    except OSError:
        return False


def _raw_names(afm_path, extension):
    """The split raw files of an AFM, in order: name.000, name.001, ...
    (as many as exist)."""
    base = os.path.splitext(afm_path)[0]
    out = []
    width = len(extension)
    if extension.isdigit():
        number = int(extension)
        while True:
            candidate = f"{base}.{number:0{width}d}"
            if not os.path.exists(candidate):
                break
            out.append(candidate)
            number += 1
    elif os.path.exists(f"{base}.{extension}"):
        out.append(f"{base}.{extension}")
    return out


class AffImage:
    """libyal's shape (read_buffer_at_offset, get_size) over an .aff
    file, an AFD folder or an AFM with its raw files."""

    #: Decoded pages kept.
    CACHE = 16

    def __init__(self, path):
        self.path = path
        self.kind = 'AFF'
        files = afd_files(path) if os.path.isdir(path) else [path]
        if not files:
            raise AffError(f"{os.path.basename(path)} holds no .aff file")
        self._handles = []
        self.segments = {}       # name -> (file, data offset, length, arg)
        try:
            for number, name in enumerate(files):
                handle = open(name, 'rb')
                self._handles.append(handle)
                if not is_aff(handle.read(8)):
                    raise AffError(f"{os.path.basename(name)} is not an AFF "
                                   f"file")
                self._scan(number)
        except Exception:
            self.close()
            raise
        if os.path.isdir(path):
            self.kind = 'AFD'
        self._handle = self._handles[0]
        names = set(self.segments)
        if any(name.endswith('/aes256') for name in names) or \
                'affkey_aes256' in names:
            self.close()
            raise AffError("This AFF image is encrypted (AES-256): "
                           "decrypt it with AFFLIB (affcrypto) first")
        page = self.segments.get('pagesize') or self.segments.get('segsize')
        if page is None:
            self.close()
            raise AffError("AFF image without a page size")
        self.page_size = page[3]
        if not self.page_size:
            self.close()
            raise AffError("AFF page size 0")
        self.pages = {}
        for name in names:
            for prefix in ('page', 'seg'):
                if name.startswith(prefix) and name[len(prefix):].isdigit():
                    self.pages[int(name[len(prefix):])] = name
        self._raw = None
        file_type = self._segment('aff_file_type').strip(b'\0') \
            if 'aff_file_type' in self.segments else b''
        if file_type == b'AFM':
            self._open_raw()
        if 'imagesize' in self.segments:
            self.size = _quad(self._segment('imagesize'))
        else:
            # No recorded size: up to the last page's end.
            last = max(self.pages, default=-1)
            self.size = last * self.page_size + len(
                self._page(last)) if last >= 0 else 0
        self.missing = [] if self._raw is not None else [
            number for number in range(-(-self.size // self.page_size))
            if number not in self.pages]
        self.stored_hashes = {}
        for name, key in (('md5', 'stored_md5'), ('sha1', 'stored_sha1'),
                          ('sha256', 'stored_sha256')):
            if name in self.segments:
                self.stored_hashes[key] = self._segment(name).hex()
        self._cache = {}

    def _open_raw(self):
        """An AFM's data: its split raw files."""
        self.kind = 'AFM'
        extension = (self._segment('raw_image_file_extension')
                     .strip(b'\0').decode('ascii', 'replace')
                     if 'raw_image_file_extension' in self.segments
                     else '000')
        names = _raw_names(self.path, extension)
        if not names:
            raise AffError(f"{os.path.basename(self.path)}: its raw data "
                           f"file (.{extension}) is not beside it")
        per_file = _quad(self._segment('pages_per_raw_image_file')) \
            if 'pages_per_raw_image_file' in self.segments else 0
        self._raw = []
        for name in names:
            handle = open(name, 'rb')
            handle.seek(0, 2)
            self._raw.append((handle, handle.tell()))
            self._handles.append(handle)
        # Bytes per raw file; 0: one file holds everything.
        self._raw_span = per_file * self.page_size

    def _read_raw(self, offset, length):
        out = bytearray()
        while length > 0:
            if self._raw_span:
                index, within = divmod(offset, self._raw_span)
                room = self._raw_span - within
            else:
                index, within, room = 0, offset, length
            if index >= len(self._raw):
                break
            handle, size = self._raw[index]
            take = min(length, room, max(0, size - within))
            if take <= 0:
                break
            handle.seek(within)
            piece = handle.read(take)
            out += piece
            offset += len(piece)
            length -= len(piece)
            if len(piece) < take:
                break
        return bytes(out)

    def _scan(self, number=0):
        handle = self._handles[number]
        handle.seek(0, 2)
        end = handle.tell()
        position = len(FILE_HEADER)
        while position + 16 <= end:
            handle.seek(position)
            head = handle.read(16)
            if head[:4] != SEGMENT_HEAD:
                raise AffError(f"no segment at {position:,}")
            name_length, data_length, argument = struct.unpack('>III',
                                                              head[4:16])
            name = handle.read(name_length).decode('ascii', 'replace')
            data_at = position + 16 + name_length
            handle.seek(data_at + data_length)
            tail = handle.read(8)
            if tail[:4] != SEGMENT_TAIL:
                raise AffError(f"segment {name!r}: no tail")
            if name:              # an empty name is a deleted segment
                self.segments[name] = (number, data_at, data_length,
                                       argument)
            position = data_at + data_length + 8

    def _segment(self, name):
        number, offset, length, _argument = self.segments[name]
        handle = self._handles[number]
        handle.seek(offset)
        return handle.read(length)

    def _page(self, number):
        name = self.pages.get(number)
        if name is None:
            return None
        cached = self._cache.get(number)
        if cached is not None:
            return cached
        argument = self.segments[name][3]
        data = self._segment(name)
        if argument & COMPRESSED:
            algorithm = argument & ALGORITHM_MASK
            try:
                if algorithm == ZLIB:
                    data = zlib.decompress(data)
                elif algorithm == BZIP:
                    data = bz2.decompress(data)
                elif algorithm == LZMA:
                    from trace_app.core.squashfs import lzma_alone
                    data = lzma_alone(data, self.page_size)
                elif algorithm == ZERO:
                    data = bytes(struct.unpack('>I', data[:4])[0]
                                 if len(data) >= 4 else self.page_size)
                else:
                    raise AffError(f"page {number}: compression "
                                   f"{algorithm:#x}")
            except AffError:
                raise
            except Exception as exc:
                raise AffError(f"page {number} does not decompress: "
                               f"{exc}") from exc
        if len(self._cache) >= self.CACHE:
            self._cache.pop(next(iter(self._cache)))
        self._cache[number] = data
        return data

    def get_size(self):
        return self.size

    def read_buffer_at_offset(self, length, offset):
        end = min(offset + length, self.size)
        if self._raw is not None:
            data = self._read_raw(offset, max(0, end - offset))
            return data + bytes(max(0, end - offset - len(data)))
        out = bytearray()
        while offset < end:
            number, within = divmod(offset, self.page_size)
            take = min(end - offset, self.page_size - within)
            page = self._page(number)
            if page is None:
                out += bytes(take)            # never written
            else:
                piece = page[within:within + take]
                out += piece + bytes(take - len(piece))
            offset += take
        return bytes(out)

    def describe(self):
        if self._raw is not None:
            return (f"AFM image (AFF metadata, split raw data): "
                    f"{self.size:,} bytes in {len(self._raw)} raw "
                    f"file{'s' if len(self._raw) != 1 else ''}")
        algorithms = sorted({ALGORITHM_NAMES.get(
            self.segments[name][3] & ALGORITHM_MASK, '?')
            if self.segments[name][3] & COMPRESSED else 'stored'
            for name in self.pages.values()})
        what = 'AFD image (AFF split across ' \
            f"{len(self._handles)} files)" if self.kind == 'AFD' \
            else 'AFF image'
        text = (f"{what}: {self.size:,} bytes in {len(self.pages):,} "
                f"pages of {self.page_size:,} ({', '.join(algorithms)})")
        if self.missing:
            text += f"; {len(self.missing):,} pages never written (zeros)"
        return text

    def close(self):
        for handle in getattr(self, '_handles', []):
            try:
                handle.close()
            except Exception:
                pass

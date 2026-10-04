"""Recovering deleted files from the raw bytes of a disk image.

The engine behind file carving, with no Qt in it: the analysis job, the
quick-triage carve and tools/carve_score.py all drive this one module, so the
carvers that are scored against the DFTT/DFRWS answer keys are exactly the
ones an examiner runs.

    carve_image(image_handler, ['jpg', 'pdf'], sink, unallocated_only=True)

walks the image in CHUNK_SIZE steps (reading CARVE_OVERLAP beyond each, so a
file across a boundary is whole in the next read), skips allocated space when
asked to, and hands every file a carver finds and `is_valid_file` accepts to
`sink(content, file_type, offset)` -- once per offset, however many
overlapping reads find it. `write_carved` is the usual sink's body: it writes
the file, named after the absolute offset it was found at, and returns what
is known about it.

Most carvers read past their buffer through the image, so a file's size is
not limited by the read. A file the file system split in two is rebuilt only
where its own structure proves the split (ZIP and PDF -- see
core/reassembly.py): headers that start a sector but carve to nothing
contiguous are tried once more after the scan, and a rebuilt file reaches the
sink with `fragments=[(offset, length), ...]`, the physical pieces it was
joined from.
"""

import bisect
import hashlib
import io
import logging
import os
import re
import struct
import time
import zipfile
import zlib

from trace_app.core import carve_verify
from trace_app.core import carving_formats as formats
from trace_app.core import reassembly
from trace_app.core.carving_signatures import extract_original_timestamp
from trace_app.core.carving_signatures import is_valid_file as _is_valid
from trace_app.core.image_handler import ImageHandler
from trace_app.infra.constants import (CARVE_MAX_FOOTER_CANDIDATES,
                                       CARVE_MAX_SIZE, CARVE_MIN_SIZE,
                                       CARVE_OVERLAP, CHUNK_SIZE, SECTOR_SIZE,
                                       UNKNOWN_DATE)

logger = logging.getLogger('TRACE.Carving')


#: What can be carved, by category -- the order of the selector's menu.
#: Each entry is the extension a recovered file is saved under. "OLE" covers
#: the legacy Office trio (.doc/.xls/.ppt) and Outlook .msg, which share one
#: compound-document container and cannot be told apart from the header.
CARVE_CATEGORIES = {
    "Pictures": ["JPG", "PNG", "GIF", "BMP", "TIFF", "WEBP", "HEIC", "AVIF",
                 "PSD"],
    "Documents": ["PDF", "DOCX", "XLSX", "PPTX", "VSDX", "ODT", "ODS", "ODP",
                  "ODG", "EPUB", "OLE", "RTF", "HTML"],
    "Email": ["PST", "OST", "MBOX", "EML"],
    "Databases & logs": ["SQLITE", "WAL", "EVTX", "REGF"],
    "Windows artifacts": ["LNK"],
    "Executables": ["EXE", "DLL", "SYS", "ELF", "MACHO", "APK", "JAR"],
    "Archives": ["ZIP", "GZ", "BZ2", "XZ", "TAR", "RAR", "7Z"],
    "Audio": ["WAV", "MP3", "OGG", "OPUS", "M4A"],
    "Video": ["MP4", "MOV", "M4V", "3GP", "AVI", "WMV", "FLV", "MPG", "MKV",
              "WEBM"],
}

#: Every carvable extension, in menu order.
CARVABLE_TYPES = [t for types in CARVE_CATEGORIES.values() for t in types]

#: Which carver finds each extension. A carver can name what it found more
#: precisely than the selector that ran it: the ZIP carver recovers a .docx,
#: the MP4 atom walk a .heic. Only the selected extensions are kept.
EXTENSION_CARVER = {
    'jpg': 'jpg', 'png': 'png', 'gif': 'gif', 'bmp': 'bmp', 'tiff': 'tiff',
    'pdf': 'pdf', 'ole': 'ole', 'html': 'html', 'rar': 'rar', '7z': '7z',
    'gz': 'gz', 'wmv': 'wmv',
    **{ext: 'zip' for ext in ('zip', 'docx', 'xlsx', 'pptx', 'vsdx', 'odt',
                              'ods', 'odp', 'odg', 'epub', 'apk', 'jar')},
    **{ext: 'isobmff' for ext in ('mov', 'mp4', 'm4v', '3gp', 'heic', 'avif',
                                  'm4a')},
    **{ext: 'riff' for ext in ('wav', 'webp', 'avi')},
    'sqlite': 'sqlite', 'wal': 'wal', 'regf': 'regf', 'evtx': 'evtx',
    'pst': 'pst', 'ost': 'pst',
    'exe': 'pe', 'dll': 'pe', 'sys': 'pe',
    'lnk': 'lnk', 'mp3': 'mp3', 'ogg': 'ogg', 'opus': 'ogg', 'flv': 'flv',
    'mpg': 'mpg', 'mkv': 'mkv', 'webm': 'mkv', 'tar': 'tar', 'bz2': 'bz2',
    'xz': 'xz', 'rtf': 'rtf', 'elf': 'elf', 'macho': 'macho', 'psd': 'psd',
    'mbox': 'mbox', 'eml': 'eml',
}

# Signatures are named rather than inlined so a format's header and footer are
# stated once, next to each other, and read as a pair.
#: An ISO-BMFF atom type is four printable ASCII characters. Requiring that is
#: what stops the walk reading arbitrary bytes as a chain of tiny atoms.
_ATOM_NAME_RE = re.compile(rb'[A-Za-z0-9 _\-]{4}')

#: Bytes per value for each TIFF field type, used to work out how far an IFD's
#: out-of-line values push the end of the file.
_TIFF_TYPE_WIDTH = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1,
                    8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

#: Ceiling on what one gzip member may expand to while we look for its end.
#: A carved stream is unverified input; decompressing it without a limit is how
#: a zip bomb turns a scan into an out-of-memory crash.
_GZIP_DECOMPRESS_LIMIT = 64 * 1024 * 1024

JPG_HEADER = b'\xFF\xD8\xFF'
JPG_FOOTER = b'\xFF\xD9'
PNG_HEADER = b'\x89PNG\r\n\x1a\n'
#: IEND carries no data, so its CRC is a constant and forms part of the footer.
PNG_FOOTER = b'IEND\xAE\x42\x60\x82'
GIF_HEADER = b'GIF8'
#: Block terminator followed by the GIF trailer.
GIF_FOOTER = b'\x00\x3B'
BMP_HEADER = b'BM'
WAV_HEADER = b'RIFF'
PDF_HEADER = b'%PDF-'
PDF_FOOTER = b'%%EOF'
ZIP_LOCAL_HEADER = b'PK\x03\x04'
ZIP_EOCD = b'PK\x05\x06'
OLE_HEADER = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
GZIP_HEADER = b'\x1F\x8B\x08'
RAR_HEADER = b'Rar!\x1A\x07'
SEVENZIP_HEADER = b'7z\xBC\xAF\x27\x1C'
TIFF_HEADERS = (b'II\x2A\x00', b'MM\x00\x2A')
#: ASF Header Object GUID: the first 16 bytes of every WMV file.
ASF_HEADER_GUID = bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C')
#: ASF File Properties Object, which carries the declared file size.
ASF_PROPERTIES_GUID = bytes.fromhex('A1DCAB8C47A9CF118EE400C00C205365')


class CarvingCancelled(Exception):
    """Raised inside a carve when the examiner presses Stop."""


class Carver:
    """The signature carvers, each searching one chunk for one file type.

    Found files go to `sink(content, file_type, absolute_offset)`. The same
    file is found again in every overlapping read that contains it; the
    offset is its identity, so each is passed on once.
    """

    def __init__(self, sink, wanted=None, reader=None, image_size=None):
        self._sink = sink
        self._seen = set()
        self.found = 0
        #: Extensions to keep, or None for all. A carver may find more than
        #: was asked for -- the ZIP carver sees every .docx and .apk too.
        self.wanted = set(wanted) if wanted is not None else None
        #: `reader(offset, length)` for bytes beyond the chunk; None limits
        #: every carve to what the chunk holds.
        self._reader = reader
        self._image_size = image_size
        #: Byte ranges already carved, sorted, by carver family. A signature
        #: inside a file of its own family is part of that file -- an MPEG
        #: repeats its pack header every 2 KB, an MP4 nests atoms -- not the
        #: start of another. Across families it may well be another file: a
        #: carve sized from a fragmented file's header spans the gap where
        #: the image keeps other files, so skipping everything inside it
        #: loses them (two real files on DFRWS 2007 when this was global).
        self._spans = {}
        #: Sector-aligned headers of formats that can be reassembled, by
        #: family -- tried again after the scan if nothing was carved there.
        self._unfinished = {}
        #: Carves that contradict their own structure, held back until
        #: reassembly has had its chance: offset -> (content, file_type).
        self._deferred = {}

    def inside_carved(self, offset, family=None):
        """Is `offset` inside (not at the start of) a file already carved --
        of `family`, or of any family when it is None?"""
        lists = ([self._spans.get(family, [])] if family is not None
                 else self._spans.values())
        for spans in lists:
            index = bisect.bisect_right(spans, (offset, float('inf'))) - 1
            if index >= 0:
                begin, end = spans[index]
                if begin < offset < end:
                    return True
        return False

    def wants(self, file_type):
        return self.wanted is None or file_type in self.wanted

    def save_file(self, file_content, file_type, offset, fragments=None):
        if not self.wants(file_type):
            return
        key = (offset, file_type)
        if key in self._seen:
            return
        self._seen.add(key)
        family = EXTENSION_CARVER.get(file_type, file_type)
        for begin, length in fragments or [(offset, len(file_content))]:
            bisect.insort(self._spans.setdefault(family, []),
                          (begin, begin + length))
        self.found += 1
        if fragments:
            self._sink(file_content, file_type, offset, fragments=fragments)
        else:
            self._sink(file_content, file_type, offset)

    # --- two-fragment files ------------------------------------------------

    #: family -> (header, reassembler). Only formats whose structure records
    #: where their parts lie, with a checksum to confirm the split.
    REASSEMBLERS = {
        'zip': (ZIP_LOCAL_HEADER, reassembly.reassemble_zip),
        'pdf': (PDF_HEADER, reassembly.reassemble_pdf),
    }

    #: Reassembly attempts per run. Each reads up to the format's cap past
    #: its header, so an image littered with truncated PDFs is bounded.
    MAX_REASSEMBLY_ATTEMPTS = 1000

    def note_unfinished(self, chunk, base_offset, families, limit=None):
        """Remember every sector-aligned header of a reassemblable format in
        the first `limit` bytes of `chunk` (the part not read again next)."""
        end = len(chunk) if limit is None else min(limit, len(chunk))
        for family in families:
            if family not in self.REASSEMBLERS:
                continue
            header = self.REASSEMBLERS[family][0]
            hit = chunk.find(header, 0, end)
            while hit != -1:
                if (base_offset + hit) % SECTOR_SIZE == 0:
                    self._unfinished.setdefault(family, set()).add(
                        base_offset + hit)
                hit = chunk.find(header, hit + 1, end)

    def _save_pdf(self, content, offset):
        """Keep a contiguous PDF carve -- unless its own cross-reference
        tables say it was carved across a gap. PyMuPDF opens such a file
        regardless, so it is held back for reassembly to try first, and kept
        as carved only if no split can be proved."""
        if offset in self._deferred:
            return              # found again by the next, overlapping read
        if self.wants('pdf') and reassembly.pdf_contradicts_itself(content):
            self._deferred[offset] = (content, 'pdf')
            self._unfinished.setdefault('pdf', set()).add(offset)
        else:
            self.save_file(content, 'pdf', offset)

    def _carved_at(self, offset, family):
        """Did a carve of `family` begin at `offset`? (A header inside
        another carve is still tried: a contiguous carve of a fragmented file
        runs on into whatever lies in its gap.)"""
        spans = self._spans.get(family, [])
        index = bisect.bisect_left(spans, (offset, -1))
        return index < len(spans) and spans[index][0] == offset

    def reassemble_fragmented(self, allocated=None, should_stop=None):
        """Try each remembered header nothing was carved from as a file in
        two fragments. With `allocated`, a rebuild that would take a piece
        from allocated space is refused: that piece belongs to a live file.
        Held-back carves are kept as carved where no rebuild is proved --
        also when the examiner stops the run here."""
        try:
            self._reassemble(allocated, should_stop)
        finally:
            for offset, (content, file_type) in sorted(self._deferred.items()):
                self.save_file(content, file_type, offset)
            self._deferred.clear()

    def _reassemble(self, allocated, should_stop):
        attempts = 0
        for family, offsets in self._unfinished.items():
            header, reassemble = self.REASSEMBLERS[family]
            cap = CARVE_MAX_SIZE.get(family)
            for offset in sorted(offsets):
                if should_stop and should_stop():
                    raise CarvingCancelled()
                if self._carved_at(offset, family):
                    continue
                attempts += 1
                if attempts > self.MAX_REASSEMBLY_ATTEMPTS:
                    logger.info("Reassembly stopped after %d attempts",
                                self.MAX_REASSEMBLY_ATTEMPTS)
                    return
                source = formats.Source(b'', offset, self._reader,
                                        self._image_size)
                try:
                    rebuilt = reassemble(source, offset, cap)
                except (struct.error, ValueError, IndexError, OverflowError,
                        zlib.error) as exc:
                    logger.debug("Reassembly at %d failed: %s", offset, exc)
                    rebuilt = None
                if not rebuilt:
                    continue
                content, fragments = rebuilt
                if allocated and any(
                        self.is_offset_allocated(begin, length, allocated)
                        for begin, length in fragments):
                    continue
                file_type = self._zip_kind(content) if family == 'zip' \
                    else family
                if is_valid_file(content, file_type):
                    self._deferred.pop(offset, None)
                    self.save_file(content, file_type, offset,
                                   fragments=fragments)

    @staticmethod
    def is_offset_allocated(offset, chunk_size, allocation_map):
        """
        Check if a given offset range overlaps with any allocated regions."""
        if not allocation_map:
            return False

        chunk_end = offset + chunk_size

        # Binary search to find potential overlapping regions
        # We need to check if our chunk [offset, chunk_end) overlaps with any allocated region
        left, right = 0, len(allocation_map)

        while left < right:
            mid = (left + right) // 2
            alloc_start, alloc_end = allocation_map[mid]

            # Check for overlap: two ranges overlap if one starts before the other ends
            if offset < alloc_end and chunk_end > alloc_start:
                return True

            # If our chunk is entirely before this allocated region, search left half
            if chunk_end <= alloc_start:
                right = mid
            # If our chunk is entirely after this allocated region, search right half
            else:
                left = mid + 1

        return False

    @staticmethod
    def next_allocated_start(offset, allocation_map):
        """Where the next allocated region begins at or after `offset`.

        Carving reads past the end of its chunk so a file straddling the
        boundary stays whole, but that extra window is not covered by the
        chunk's own allocation check -- so without this it read straight into
        live file data and carved it. Trimming the buffer here keeps the
        overlap while leaving allocated space untouched.

        Returns None when nothing is allocated ahead.
        """
        if not allocation_map:
            return None

        low, high = 0, len(allocation_map)
        while low < high:
            mid = (low + high) // 2
            if allocation_map[mid][1] <= offset:
                low = mid + 1        # region ends before us; look right
            else:
                high = mid

        if low >= len(allocation_map):
            return None
        start, end = allocation_map[low]
        # A region already covering `offset` leaves no room to read at all.
        return offset if start <= offset < end else start

    def carve_pdf_files(self, chunk, global_offset):
        pdf_start_signature = PDF_HEADER
        pdf_linearization_signature = b'/Linearized'
        pdf_end_signature = PDF_FOOTER
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(pdf_start_signature, offset)
            if start_index == -1:
                break
            linearization_index = chunk.find(pdf_linearization_signature, start_index, start_index + 1024)
            if linearization_index != -1:
                file_size_start = chunk.find(b'/L ', linearization_index, linearization_index + 1024) + 3
                file_size_end = chunk.find(b'/', file_size_start)
                if file_size_end == -1:
                    file_size_end = chunk.find(b' ', file_size_start)
                if file_size_end != -1:
                    try:
                        file_size = int(chunk[file_size_start:file_size_end].split()[0])
                        pdf_content = chunk[start_index:start_index + file_size]
                        if is_valid_file(pdf_content, 'pdf'):
                            self._save_pdf(pdf_content, global_offset + start_index)
                            offset = start_index + file_size
                            continue
                    except ValueError:
                        pass
            end_index = chunk.find(pdf_end_signature, start_index)
            if end_index != -1:
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]
                if is_valid_file(pdf_content, 'pdf'):
                    self._save_pdf(pdf_content, global_offset + start_index)
                offset = end_index
            else:
                offset = start_index + 1

    def carve_riff_files(self, chunk, base_offset):
        """WAV, WEBP and AVI: a RIFF container, sized by its own header."""
        self._carve_sized(chunk, base_offset, (b'RIFF',), formats.measure_riff,
                          aligned=False)

    @staticmethod
    def _starts_a_file(offset):
        """Could a file begin at this absolute offset?

        A filesystem allocates in sectors, so a file it stored begins on a
        sector boundary -- every file in every answer key used to test this
        does. A signature found part-way through a sector is something inside
        a larger object: a thumbnail in a photo, a frame in a video, an
        attachment in a mail spool. Carving it writes out part of one file
        under the name of another, which is worse than not carving it: it
        looks like a recovered file.

        Scanning the DFRWS 2007 image, which is dense with MP3 and MPEG data,
        this rejected most of the 193 spurious JPEGs while keeping every real
        one.
        """
        return offset % SECTOR_SIZE == 0

    #: Tags that a real page has and a quoted fragment in a mail body usually
    #: does not. Requiring some structure is what separates a document from
    #: someone writing about one.
    _HTML_STRUCTURE = (b'<body', b'<head', b'<title', b'<div', b'<table',
                       b'<p>', b'<a ', b'<meta')

    @classmethod
    def _looks_like_a_page(cls, content):
        """Is this a document, or just bytes containing an <html> tag?

        HTML has no footer magic and no checksum, so nothing else here can
        reject a match. The DFRWS 2007 image carries mbox mail data whose
        bodies are full of markup, and without this the carver wrote out 602
        of them.
        """
        if len(content) < 512:
            return False
        head = content[:4096].lower()
        return sum(marker in head for marker in cls._HTML_STRUCTURE) >= 2

    def _carve_by_footer(self, chunk, base_offset, file_type,
                         header, footer):
        """Carve every `header` .. `footer` span that actually parses.

        The first footer after a header is routinely the wrong one. A JPEG's
        EXIF thumbnail ends with the same FFD9 the image does, so taking the
        first match truncates a fully recoverable photo into a fragment --
        which is how two intact JPEGs in the DFTT test image were being lost.

        So each candidate footer is tried in turn and the first that validates
        wins. A header whose footers all fail is abandoned, and the search
        resumes just past the header rather than past the failed span: a real
        file can begin inside the region a false candidate covered.
        """
        cap = CARVE_MAX_SIZE.get(file_type)
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(header, cursor)
            if start_index == -1:
                break

            if not self._starts_a_file(base_offset + start_index):
                # Mid-sector: embedded in something else, not a file of its
                # own. See _starts_a_file.
                cursor = start_index + len(header)
                continue

            end_index = start_index
            carved = False
            for _ in range(CARVE_MAX_FOOTER_CANDIDATES):
                end_index = chunk.find(footer, end_index + 1)
                if end_index == -1:
                    break

                size = end_index + len(footer) - start_index
                if cap and size > cap:
                    break               # every later footer is only further

                content = chunk[start_index:end_index + len(footer)]
                if is_valid_file(content, file_type):
                    self.save_file(content, file_type,
                                   base_offset + start_index)
                    # Resume just past this header rather than past the file.
                    # A file carved across a fragmentation gap can contain a
                    # whole other file of the same type -- DFRWS scenario 3g
                    # plants one JPEG inside another's gap -- and skipping to
                    # the end loses it. Re-scanning the span costs a little
                    # time; losing evidence inside it does not show up at all.
                    cursor = start_index + len(header)
                    carved = True
                    break

            if not carved:
                cursor = start_index + len(header)

    def carve_jpg_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'jpg',
                              JPG_HEADER, JPG_FOOTER)

    def carve_gif_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'gif',
                              GIF_HEADER, GIF_FOOTER)

    def carve_png_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'png',
                              PNG_HEADER, PNG_FOOTER)

    def carve_mov_files(self, chunk, base_offset):
        """Recover QuickTime and MP4 by walking the atom chain.

        A MOV is a flat sequence of size-prefixed atoms, so the file's extent
        is the walk itself rather than a footer to search for. The previous
        version scanned four bytes at a time for one of four atom types, then
        emitted a single file after the loop -- so it found at most one MOV per
        chunk, entered files at whichever atom happened to match first, and had
        `ftyp` commented out of its list entirely.

        MP4 is the same container, so one walk finds both and the brand in the
        `ftyp` atom decides the extension. Running the walk once and labelling
        the result is what keeps a single file from being written twice.
        """
        self._carve_atom_chain(chunk, base_offset)

    #: The atom names a QuickTime/MP4 file can open with, found in one pass.
    _ATOM_ANCHOR_RE = re.compile(rb'(?=(ftyp|moov|mdat|free|skip|wide|pnot))')

    def _carve_atom_chain(self, chunk, base_offset):
        """Walk every plausible atom chain in the chunk, in order.

        The candidates come from one regex pass over the chunk. Searching for
        each of the seven names again after every rejected candidate made
        this quadratic: `free` is an English word, and a chunk of ordinary
        text -- a GPL notice, a mail spool -- held thousands of candidates,
        each costing seven scans of the rest of a 36 MB chunk.
        """
        cap = max(CARVE_MAX_SIZE.get('mov', 0), CARVE_MAX_SIZE.get('mp4', 0))
        more = (self._image_size is not None and
                base_offset + len(chunk) < self._image_size)
        cursor = 0
        for match in self._ATOM_ANCHOR_RE.finditer(chunk, 4):
            anchor = match.start() - 4
            if anchor < cursor:
                continue
            size = int.from_bytes(chunk[anchor:anchor + 4], 'big')
            if not (size == 0 or size == 1 or size >= 8):
                continue
            if self.inside_carved(base_offset + anchor, family='isobmff'):
                # Atoms nested in a file already carved -- a HEIC's items, a
                # video's tracks -- are that file, not another one.
                continue

            end = self._walk_atoms(chunk, anchor, cap, more_follows=more)
            if end is None:
                continue
            content = chunk[anchor:end]
            file_type = formats.isobmff_kind(content)
            if self.wants(file_type) and is_valid_file(content, file_type):
                self.save_file(content, file_type, base_offset + anchor)
                cursor = end

    @staticmethod
    def _next_atom_start(chunk, cursor):
        """Offset of the next plausible container-opening atom."""
        best = None
        for name in (b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide',
                     b'pnot'):
            # The type sits 4 bytes into the atom, after its size.
            found = chunk.find(name, cursor + 4)
            while found != -1:
                start = found - 4
                size = int.from_bytes(chunk[start:start + 4], 'big')
                if size == 0 or size == 1 or size >= 8:
                    if best is None or start < best:
                        best = start
                    break
                found = chunk.find(name, found + 1)
        return best

    @staticmethod
    def _walk_atoms(chunk, start, cap, more_follows=False):
        """End offset of the atom chain beginning at `start`, or None.

        Returns None when the chain is not one: a single atom proves nothing,
        because four printable bytes preceded by a plausible length occur in
        ordinary data.

        `more_follows`: the image continues past this chunk. An atom running
        off the chunk's end then means the file is not whole in this read,
        and the walk declines rather than end at the last atom it saw -- a
        later chunk holds the file whole. Ending there carved a video's
        header atoms alone as "the file" (3,898 bytes of a 957,162-byte MP4)
        whenever it began near a chunk's end, and that truncated carve then
        took the file's offset.
        """
        pos = start
        atoms = 0
        while pos + 8 <= len(chunk):
            size = int.from_bytes(chunk[pos:pos + 4], 'big')
            kind = chunk[pos + 4:pos + 8]
            if not _ATOM_NAME_RE.match(kind):
                break
            if size == 0:
                pos = len(chunk)        # runs to the end of the file
                atoms += 1
                break
            if size == 1:
                if pos + 16 > len(chunk):
                    if more_follows:
                        return None
                    break
                size = int.from_bytes(chunk[pos + 8:pos + 16], 'big')
            if size >= 8 and pos + size > len(chunk) and more_follows and \
                    not (cap and (pos + size) - start > cap):
                return None
            if size < 8 or pos + size > len(chunk):
                break
            if cap and (pos + size) - start > cap:
                break
            pos += size
            atoms += 1

        if atoms < 2 or pos <= start:
            return None
        return pos

    def carve_wmv_files(self, chunk, base_offset):
        """Recover ASF/WMV using the size the ASF header object declares."""
        cap = CARVE_MAX_SIZE.get('wmv')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(ASF_HEADER_GUID, cursor)
            if start_index == -1:
                break

            # The Header Object's own size sits immediately after its GUID;
            # the total file size lives in the File Properties Object.
            size = self._asf_file_size(chunk, start_index)
            if size is None or size < CARVE_MIN_SIZE:
                cursor = start_index + 1
                continue
            if cap and size > cap:
                cursor = start_index + 1
                continue

            end_index = start_index + size
            if end_index > len(chunk):
                # Runs past this read; the next chunk's overlap holds it whole.
                cursor = start_index + 1
                continue

            content = chunk[start_index:end_index]
            if is_valid_file(content, 'wmv'):
                self.save_file(content, 'wmv', base_offset + start_index)
                cursor = end_index
            else:
                cursor = start_index + 1

    @staticmethod
    def _asf_file_size(chunk, start_index):
        """Total file size from the ASF File Properties Object, if present."""
        window = min(start_index + 1024, len(chunk))
        properties = chunk.find(ASF_PROPERTIES_GUID, start_index, window)
        if properties == -1:
            return None
        # GUID (16) + object size (8) + File ID (16), then the 64-bit
        # file size.
        field = properties + 40
        if field + 8 > len(chunk):
            return None
        return int.from_bytes(chunk[field:field + 8], 'little')

    def carve_zip_files(self, chunk, base_offset):
        """Recover each ZIP archive as its own file.

        The previous version joined every local file header in the chunk into
        one output named after the first, and computed each entry's stride as
        `30 + compressed_size` -- omitting the filename and extra-field
        lengths at +26 and +28. Measured against wword60t.zip in the DFTT
        image, whose single entry has an 11-byte name, every archive came out
        exactly 11 bytes short and would not open.
        """
        cap = CARVE_MAX_SIZE.get('zip')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(ZIP_LOCAL_HEADER, cursor)
            if start_index == -1:
                break

            end = self._zip_extent(chunk, start_index, cap)
            if end is None:
                cursor = start_index + len(ZIP_LOCAL_HEADER)
                continue

            content = chunk[start_index:end]
            if is_valid_file(content, 'zip'):
                self.save_file(content, self._zip_kind(content),
                               base_offset + start_index)
                cursor = end
            else:
                cursor = start_index + len(ZIP_LOCAL_HEADER)

    @staticmethod
    def _zip_kind(content):
        """docx, odt, apk... or zip: what the archive's members say it is."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                return formats.zip_kind(archive.namelist(), archive.read)
        except (zipfile.BadZipFile, OSError, KeyError, ValueError):
            return 'zip'

    @staticmethod
    def _zip_extent(chunk, start_index, cap):
        """End offset of the archive beginning at `start_index`, or None.

        Walks the local file headers to find this archive's own End of Central
        Directory record, so two archives lying next to each other stay two
        files.
        """
        pos = start_index
        while pos + 30 <= len(chunk) and chunk[pos:pos + 4] == ZIP_LOCAL_HEADER:
            try:
                flags = struct.unpack('<H', chunk[pos + 6:pos + 8])[0]
                compressed = struct.unpack('<I', chunk[pos + 18:pos + 22])[0]
                name_len = struct.unpack('<H', chunk[pos + 26:pos + 28])[0]
                extra_len = struct.unpack('<H', chunk[pos + 28:pos + 30])[0]
            except struct.error:
                return None

            if flags & 0x08 and compressed == 0:
                # Sizes were streamed into a trailing data descriptor, so the
                # local header cannot tell us the stride. The central
                # directory is the only reliable end.
                break

            pos += 30 + name_len + extra_len + compressed
            if cap and pos - start_index > cap:
                return None

        eocd = chunk.find(ZIP_EOCD, start_index)
        if eocd == -1 or eocd + 22 > len(chunk):
            return None
        try:
            comment_len = struct.unpack('<H', chunk[eocd + 20:eocd + 22])[0]
        except struct.error:
            return None

        end = eocd + 22 + comment_len
        if end > len(chunk):
            return None
        if cap and end - start_index > cap:
            return None
        return end

    def carve_bmp_files(self, chunk, base_offset):
        bmp_start_signature = BMP_HEADER
        header_size = 14  # The static header size for BMP files

        current_offset = 0
        while current_offset < len(chunk) - header_size:
            # Look for the BMP signature
            start_index = chunk.find(bmp_start_signature, current_offset)
            if start_index == -1:
                break  # No more BMP files found

            # Verify there's enough chunk left to read the BMP size
            if start_index + header_size > len(chunk) - 4:
                break  # Not enough data for size

            # Read file size directly from header
            bmp_file_size = int.from_bytes(chunk[start_index + 2:start_index + 6], byteorder='little')

            # Sanity check for BMP size (adjust max and min size as per your need)
            if bmp_file_size < 100 or bmp_file_size > 5000000:
                current_offset = start_index + 2
                continue  # Not a valid BMP size, skip to next possible start

            # Read and check dimensions for further validation
            bmp_width = int.from_bytes(chunk[start_index + 18:start_index + 22], byteorder='little')
            bmp_height = int.from_bytes(chunk[start_index + 22:start_index + 26], byteorder='little')

            # Reasonable dimensions check (adjust max width/height as per your need)
            if bmp_width <= 0 or bmp_width > 10000 or bmp_height <= 0 or bmp_height > 10000:
                current_offset = start_index + 2
                continue  # Unreasonable dimensions, likely not a BMP

            # Extract the BMP file if it's entirely within the chunk
            if start_index + bmp_file_size <= len(chunk):
                bmp_content = chunk[start_index:start_index + bmp_file_size]
                # Header plausibility is not proof: 'BM' plus a believable size
                # and dimensions matched 174 times in one 62 MB test image.
                if is_valid_file(bmp_content, 'bmp'):
                    self.save_file(bmp_content, 'bmp',
                                   base_offset + start_index)
                    current_offset = start_index + bmp_file_size
                else:
                    current_offset = start_index + 2
            else:
                break  # The BMP file exceeds the chunk boundary, stop processing

        # Return if more data is needed or if processing is complete
        return None

    def carve_ole_files(self, chunk, base_offset):
        """Recover legacy Office documents (.doc, .xls, .ppt).

        An OLE2 compound file states its own length: the header names a sector
        size and the count of sectors in each of its allocation tables, so the
        extent follows from the header rather than from a footer search. These
        formats have no footer at all, which is why a signature-and-footer
        carver could never recover them -- six of them sit unrecovered in the
        two DFTT test images.
        """
        cap = CARVE_MAX_SIZE.get('ole')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(OLE_HEADER, cursor)
            if start_index == -1:
                break

            size = self._ole_size(chunk, start_index, cap)
            if size is None:
                cursor = start_index + len(OLE_HEADER)
                continue

            # The header only bounds the file from above, and the bound
            # overshoots: on the DFTT ext2 image it ran 49 KB past the end of
            # stats.xls and swallowed the document that follows. Another OLE
            # signature is a hard stop -- a file cannot contain the start of
            # the next one.
            following = chunk.find(OLE_HEADER, start_index + len(OLE_HEADER))
            if following != -1:
                size = min(size, following - start_index)

            content = chunk[start_index:start_index + size]
            if is_valid_file(content, 'ole'):
                self.save_file(content, 'ole', base_offset + start_index)
                cursor = start_index + size
            else:
                cursor = start_index + len(OLE_HEADER)

    @staticmethod
    def _ole_size(chunk, start_index, cap):
        """Exact length of the OLE compound file starting at `start_index`.

        Read from the file's own allocation table: the FAT marks every sector
        the document occupies, so the highest allocated entry is its last
        sector. An earlier version estimated an upper bound from the FAT's
        sector count instead, which overshot 2a.doc on the DFRWS 2006 image by
        41 KB -- close enough to open, but not the file that was there, and it
        could not reproduce the published hash.
        """
        if start_index + 512 > len(chunk):
            return None
        header = chunk[start_index:start_index + 512]
        try:
            shift = struct.unpack('<H', header[30:32])[0]
            fat_sectors = struct.unpack('<I', header[44:48])[0]
        except struct.error:
            return None

        if shift not in (9, 12) or not 0 < fat_sectors < 65536:
            return None
        sector = 1 << shift

        # The header's DIFAT lists the first 109 FAT sectors. Beyond that the
        # chain continues in the file, which a carve may not have whole; 109
        # sectors already map a document far larger than the size cap.
        highest = -1
        entries_per_sector = sector // 4
        for n in range(min(fat_sectors, 109)):
            try:
                fat_sector = struct.unpack(
                    '<I', header[76 + 4 * n:80 + 4 * n])[0]
            except struct.error:
                break
            if fat_sector >= 0xFFFFFFFE:     # free or end-of-chain marker
                continue

            base = start_index + 512 + fat_sector * sector
            if base + sector > len(chunk):
                return None
            for i in range(entries_per_sector):
                try:
                    value = struct.unpack(
                        '<I', chunk[base + 4 * i:base + 4 * i + 4])[0]
                except struct.error:
                    return None
                if value != 0xFFFFFFFF:      # 0xFFFFFFFF marks a free sector
                    highest = max(highest, n * entries_per_sector + i)

        if highest < 0:
            return None

        size = 512 + (highest + 1) * sector
        if size < CARVE_MIN_SIZE:
            return None
        if cap and size > cap:
            return None
        if start_index + size > len(chunk):
            return None
        return size

    def carve_tiff_files(self, chunk, base_offset):
        """Recover TIFF by walking its IFD chain to the last entry."""
        cap = CARVE_MAX_SIZE.get('tiff')
        for header in TIFF_HEADERS:
            cursor = 0
            big_endian = header.startswith(b'MM')
            while cursor < len(chunk):
                start_index = chunk.find(header, cursor)
                if start_index == -1:
                    break

                size = self._tiff_size(chunk, start_index, big_endian, cap)
                if size is None:
                    cursor = start_index + len(header)
                    continue

                content = chunk[start_index:start_index + size]
                if is_valid_file(content, 'tiff'):
                    self.save_file(content, 'tiff', base_offset + start_index)
                    cursor = start_index + size
                else:
                    cursor = start_index + len(header)

    @staticmethod
    def _tiff_size(chunk, start_index, big_endian, cap):
        """Extent of the TIFF at `start_index`, from its IFD chain."""
        order = '>' if big_endian else '<'
        try:
            offset = struct.unpack(
                order + 'I', chunk[start_index + 4:start_index + 8])[0]
        except struct.error:
            return None

        furthest = 8
        for _ in range(16):             # bounded: a chain can be circular
            ifd = start_index + offset
            if offset < 8 or ifd + 2 > len(chunk):
                return None
            try:
                count = struct.unpack(order + 'H', chunk[ifd:ifd + 2])[0]
            except struct.error:
                return None
            if count == 0 or count > 512:
                return None

            end_of_ifd = ifd + 2 + count * 12 + 4
            if end_of_ifd > len(chunk):
                return None
            furthest = max(furthest, end_of_ifd - start_index)

            # Every entry whose value does not fit inline points outward; the
            # file has to extend past the furthest of those.
            for n in range(count):
                entry = ifd + 2 + n * 12
                try:
                    kind, length = struct.unpack(
                        order + 'HI', chunk[entry + 2:entry + 8])
                except struct.error:
                    return None
                width = _TIFF_TYPE_WIDTH.get(kind, 0)
                total = width * length
                if total > 4:
                    try:
                        at = struct.unpack(
                            order + 'I', chunk[entry + 8:entry + 12])[0]
                    except struct.error:
                        return None
                    furthest = max(furthest, at + total)

            try:
                offset = struct.unpack(
                    order + 'I', chunk[end_of_ifd - 4:end_of_ifd])[0]
            except struct.error:
                return None
            if offset == 0:
                break

        if furthest < CARVE_MIN_SIZE:
            return None
        if cap and furthest > cap:
            return None
        if start_index + furthest > len(chunk):
            return None
        return furthest

    def carve_gz_files(self, chunk, base_offset):
        """Recover gzip streams by decompressing until the stream ends.

        A gzip member carries no length, so the only honest way to find its end
        is to decompress it and ask how much input was consumed.
        """
        cap = CARVE_MAX_SIZE.get('gz')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(GZIP_HEADER, cursor)
            if start_index == -1:
                break

            window = chunk[start_index:start_index + (cap or len(chunk))]
            decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                decomp.decompress(window, _GZIP_DECOMPRESS_LIMIT)
                consumed = len(window) - len(decomp.unused_data)
            except zlib.error:
                cursor = start_index + len(GZIP_HEADER)
                continue

            if not decomp.eof or consumed < CARVE_MIN_SIZE:
                cursor = start_index + len(GZIP_HEADER)
                continue

            content = chunk[start_index:start_index + consumed]
            if is_valid_file(content, 'gz'):
                self.save_file(content, 'gz', base_offset + start_index)
                cursor = start_index + consumed
            else:
                cursor = start_index + len(GZIP_HEADER)

    def carve_rar_files(self, chunk, base_offset):
        """RAR3 and RAR5, sized by walking their CRC-checked blocks."""
        self._carve_sized(chunk, base_offset, (formats.RAR5_SIGNATURE,
                                               formats.RAR3_SIGNATURE),
                          formats.measure_rar)

    def _carve_rar_files_by_marker(self, chunk, base_offset):
        self._carve_by_marker(chunk, base_offset, 'rar', RAR_HEADER)

    def carve_7z_files(self, chunk, base_offset):
        """7z, sized by the end-header pointer in its signature header."""
        self._carve_sized(chunk, base_offset, (formats.SEVENZIP_SIGNATURE,),
                          formats.measure_7z)

    def _carve_7z_files_by_marker(self, chunk, base_offset):
        self._carve_by_marker(chunk, base_offset, '7z', SEVENZIP_HEADER)

    def _carve_by_marker(self, chunk, base_offset, file_type, header):
        """Carve an archive that runs to the next signature or the cap.

        RAR and 7z encode their extents inside structures this carver does not
        parse, so the recovered span runs to the next header of the same type.
        That is an upper bound, and the file is written only if it validates.
        """
        cap = CARVE_MAX_SIZE.get(file_type)
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(header, cursor)
            if start_index == -1:
                break

            following = chunk.find(header, start_index + len(header))
            end = following if following != -1 else len(chunk)
            if cap:
                end = min(end, start_index + cap)

            content = chunk[start_index:end]
            if is_valid_file(content, file_type):
                self.save_file(content, file_type, base_offset + start_index)
            cursor = start_index + len(header)

    def carve_html_files(self, chunk, base_offset):
        """Recover HTML documents, starting at the DOCTYPE where there is one.

        A real page usually opens with a DOCTYPE or an XML declaration, not
        with `<html`. Carving from the `<html` tag drops those leading bytes,
        which is enough to make the recovered file a different file: on the
        DFRWS 2006 image it started 83 bytes into 1a.html, so the hash could
        never match the evidence.
        """
        cap = CARVE_MAX_SIZE.get('html')
        lowered = chunk.lower()
        cursor = 0
        while cursor < len(chunk):
            tag = lowered.find(b'<html', cursor)
            if tag == -1:
                break

            start_index = self._html_start(lowered, tag)

            end_index = lowered.find(b'</html>', tag)
            if end_index == -1:
                cursor = tag + 5
                continue

            end = end_index + len(b'</html>')
            if cap and end - start_index > cap:
                cursor = tag + 5
                continue

            content = chunk[start_index:end]
            if (self._starts_a_file(base_offset + start_index)
                    and self._looks_like_a_page(content)):
                self.save_file(content, 'html', base_offset + start_index)
            cursor = tag + 5

    @staticmethod
    def _html_start(lowered, tag):
        """Where the document really begins, at or before its `<html` tag.

        Looks back a short way for a DOCTYPE or XML declaration. Bounded,
        because everything before the tag is unallocated data that happens to
        precede it, and following it far enough would swallow the file before.
        """
        window = max(0, tag - 512)
        for marker in (b'<!doctype', b'<?xml'):
            found = lowered.rfind(marker, window, tag)
            if found == -1:
                continue
            # A file saved with a leading blank line really does begin at
            # that line, and dropping it changes the hash -- 1a.html on the
            # DFRWS 2006 image is one byte of newline before its DOCTYPE.
            # But the bytes before a carved file are unallocated data that may
            # also end in whitespace, so backtracking on whitespace alone
            # overshoots. A file starts on a sector boundary; that is the
            # only defensible place to stop.
            start_of_sector = found - (found % SECTOR_SIZE)
            if (start_of_sector < found
                    and lowered[start_of_sector:found].isspace()):
                return start_of_sector
            return found
        return tag

    # --- formats sized by their own structure ----------------------------

    def _carve_sized(self, chunk, base_offset, signatures, measure,
                     aligned=True, signature_at=0, *args):
        """Carve every file whose extent `measure` can establish.

        For each signature hit (found `signature_at` bytes into the file) that
        starts a sector, `measure` reads the file's own structure for its
        size and extension. Only a wanted extension within its cap is then
        read in full -- from the chunk, or past it from the image -- and kept
        if it validates.
        """
        source = formats.Source(chunk, base_offset, self._reader,
                                self._image_size)
        for signature in signatures:
            cursor = 0
            while True:
                hit = chunk.find(signature, cursor)
                if hit == -1:
                    break
                cursor = hit + 1
                start = hit - signature_at
                if start < 0:
                    continue
                offset = base_offset + start
                if aligned and not self._starts_a_file(offset):
                    continue
                self._try_carve(source, offset, measure, args,
                                self._family(measure))

    def _try_carve(self, source, offset, measure, args, family):
        """Measure, read, validate and keep one candidate at `offset`."""
        if (offset, None) in self._seen:
            return
        if self.inside_carved(offset, family=family):
            return
        try:
            measured = measure(source, offset, *args)
        except (struct.error, ValueError, IndexError, OverflowError,
                TypeError):
            measured = None
        if not measured:
            return
        size, file_type = measured
        if not self.wants(file_type):
            return
        cap = CARVE_MAX_SIZE.get(file_type)
        if size < CARVE_MIN_SIZE or (cap and size > cap):
            return
        content = source.get(offset, size)
        if len(content) != size:
            return
        if is_valid_file(content, file_type):
            self.save_file(content, file_type, offset)
            # A later signature inside this file is part of it.
            self._seen.add((offset, None))

    #: The family each measuring function carves for. MP3 is checked against
    #: every family: its frame sync is weak enough to occur in any audio or
    #: video stream, and an MPEG's or an AVI's audio is that file's, not an
    #: MP3 of its own.
    _MEASURE_FAMILY = {}

    def _family(self, measure):
        if measure is formats.measure_mp3:
            return None
        return self._MEASURE_FAMILY.get(measure.__name__,
                                        measure.__name__.replace('measure_', ''))

    def carve_sqlite_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'SQLite format 3\x00',),
                          formats.measure_sqlite)

    def carve_wal_files(self, chunk, base_offset):
        # A -wal file: its frames' checksum chain is its extent (see
        # carving_formats.measure_sqlite_wal). Paired with its database
        # after the scan (pair_wal_files).
        self._carve_sized(chunk, base_offset, formats.WAL_MAGICS,
                          formats.measure_sqlite_wal)

    def carve_regf_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'regf',), formats.measure_regf)

    def carve_evtx_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'ElfFile\x00',),
                          formats.measure_evtx)

    def carve_pst_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'!BDN',), formats.measure_pst)

    def carve_pe_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'MZ',), formats.measure_pe)

    def carve_lnk_files(self, chunk, base_offset):
        # A shortcut is a few hundred bytes; on NTFS it is often resident in
        # its MFT record, so it need not start a sector. The 20-byte header
        # signature is specific enough to search for anywhere.
        self._carve_sized(chunk, base_offset,
                          (b'\x4c\x00\x00\x00' + formats.LNK_CLSID,),
                          formats.measure_lnk, aligned=False)

    def carve_mp3_files(self, chunk, base_offset):
        # With a tag, or straight into frames (MPEG-1 and -2 Layer III).
        self._carve_sized(chunk, base_offset,
                          (b'ID3', b'\xff\xfb', b'\xff\xfa', b'\xff\xf3',
                           b'\xff\xf2'), formats.measure_mp3)

    def carve_ogg_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'OggS\x00\x02',),
                          formats.measure_ogg)

    def carve_flv_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'FLV\x01',), formats.measure_flv)

    def carve_mpg_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'\x00\x00\x01\xba',),
                          formats.measure_mpg)

    def carve_mkv_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'\x1a\x45\xdf\xa3',),
                          formats.measure_mkv)

    def carve_tar_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'ustar',), formats.measure_tar,
                          True, 257)

    def carve_tar_v7_files(self, chunk, base_offset):
        """Pre-POSIX tars have no magic to search for: every sector start
        whose block passes a tar header's own checksum is tried instead."""
        source = formats.Source(chunk, base_offset, self._reader,
                                self._image_size)
        first = -base_offset % formats.SECTOR
        for rel in range(first, len(chunk) - 511, formats.SECTOR):
            if chunk[rel + 257:rel + 263] != b'\x00' * 6 or \
                    not formats._V7_CHECKSUM.fullmatch(chunk[rel + 148:rel + 156]):
                continue
            self._try_carve(source, base_offset + rel, formats.measure_tar_v7,
                            (), 'tar')

    def carve_bz2_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'BZh',), formats.measure_bz2,
                          True, 0, CARVE_MAX_SIZE['bz2'])

    def carve_xz_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'\xfd7zXZ\x00',),
                          formats.measure_xz, True, 0, CARVE_MAX_SIZE['xz'])

    def carve_rtf_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'{\\rtf1',),
                          formats.measure_rtf, True, 0, CARVE_MAX_SIZE['rtf'])

    def carve_elf_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'\x7fELF',), formats.measure_elf)

    def carve_macho_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset,
                          (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe',
                           b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce',
                           b'\xca\xfe\xba\xbe'), formats.measure_macho)

    def carve_psd_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'8BPS\x00\x01',),
                          formats.measure_psd)

    def carve_mbox_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, (b'From ',), formats.measure_mbox,
                          True, 0, CARVE_MAX_SIZE['mbox'])

    def carve_eml_files(self, chunk, base_offset):
        self._carve_sized(chunk, base_offset, formats.EML_STARTS,
                          formats.measure_eml, True, 0, CARVE_MAX_SIZE['eml'])

    #: Which carver each family name runs (see EXTENSION_CARVER).
    CARVERS = {
        'pdf': carve_pdf_files,
        'jpg': carve_jpg_files,
        'png': carve_png_files,
        'gif': carve_gif_files,
        'bmp': carve_bmp_files,
        'tiff': carve_tiff_files,
        'riff': carve_riff_files,
        'isobmff': carve_mov_files,
        'wmv': carve_wmv_files,
        'zip': carve_zip_files,
        'gz': carve_gz_files,
        'rar': carve_rar_files,
        '7z': carve_7z_files,
        'ole': carve_ole_files,
        'html': carve_html_files,
        'sqlite': carve_sqlite_files,
        'wal': carve_wal_files,
        'regf': carve_regf_files,
        'evtx': carve_evtx_files,
        'pst': carve_pst_files,
        'pe': carve_pe_files,
        'lnk': carve_lnk_files,
        'mp3': carve_mp3_files,
        'ogg': carve_ogg_files,
        'flv': carve_flv_files,
        'mpg': carve_mpg_files,
        'mkv': carve_mkv_files,
        'tar': carve_tar_files,
        'tar_v7': carve_tar_v7_files,
        'bz2': carve_bz2_files,
        'xz': carve_xz_files,
        'rtf': carve_rtf_files,
        'elf': carve_elf_files,
        'macho': carve_macho_files,
        'psd': carve_psd_files,
        'mbox': carve_mbox_files,
        'eml': carve_eml_files,
    }



#: The order carvers run in, per chunk. Containers before what they contain:
#: a video's audio, an archive's members and an executable's resources are
#: then recognised as inside a file already carved, rather than carved again
#: as files of their own. MP3 last -- its frame sync is the weakest signature.
_CARVE_ORDER = [
    'pst', 'sqlite', 'wal', 'regf', 'evtx', 'isobmff', 'riff', 'mkv', 'mpg', 'flv',
    'ogg', 'wmv', 'zip', 'tar', 'tar_v7', 'gz', 'bz2', 'xz', '7z', 'rar',
    'ole', 'pdf',
    'pe', 'elf', 'macho', 'psd', 'lnk', 'rtf', 'mbox', 'eml', 'html', 'tiff',
    'png',
    'gif', 'bmp', 'jpg', 'mp3',
]


#: What the current run has seen: every candidate a carver handed to a
#: validator, by type, and those it rejected. Set by carve_image.
_STATS = None


def is_valid_file(data, file_type):
    """carving_signatures.is_valid_file, counted for the run's statistics:
    every signature hit that reached validation is a candidate, and those
    that did not parse are rejected -- the false-positive rate, measured."""
    valid = _is_valid(data, file_type)
    if _STATS is not None:
        kind = (file_type or '').lower()
        _STATS['candidates'][kind] = _STATS['candidates'].get(kind, 0) + 1
        if not valid:
            _STATS['rejected'][kind] = _STATS['rejected'].get(kind, 0) + 1
    return valid


def engine_identity():
    """What did the carving, for the record of every run."""
    from trace_app import __version__
    return (f"TRACE {__version__} carver: {len(CARVABLE_TYPES)} types, "
            f"two-fragment reassembly of ZIP and PDF, structural "
            f"verification (carve_verify)")


def allocation_map(image_handler):
    """The allocated byte ranges of every file system in the image, merged.

    Carving skips them: what is allocated is a live file the tree already
    shows, and carving it again only buries the deleted data in duplicates.
    Empty (carve everything) if no file system can be read.
    """
    ranges = []
    try:
        partitions = image_handler.get_partitions()
        # The partition table lists its own sectors, unallocated gaps and
        # GPT headers too (offsets 0, 1, 2, 34...), several at one offset:
        # only file systems have allocations, each mapped once.
        offsets = sorted({p[2] for p in partitions}) if partitions else [0]
        for start in offsets:
            if image_handler.has_filesystem(start):
                ranges.extend(image_handler.build_allocation_map(start))
    except Exception as exc:
        logger.warning("Could not build the allocation map (%s); carving "
                       "the whole image", exc)
        return []
    # Merge, not just sort: is_offset_allocated binary searches this list,
    # which is only valid if the ranges are ordered AND do not overlap.
    return ImageHandler._merge_ranges(ranges)


#: Where a carve looks: free space between live files, the slack at the
#: end of live files' last clusters, or every byte of the image.
SOURCES = ('unallocated', 'slack', 'image')
SOURCE_LABELS = {'unallocated': 'Unallocated space', 'slack': 'File slack',
                 'image': 'Whole image'}

#: Checkpoint a carve's progress at least this often (seconds), so an
#: interrupted run resumes close to where it stopped.
CHECKPOINT_SECONDS = 20


def carve_image(image_handler, file_types, sink, unallocated_only=True,
                progress=None, should_stop=None, stats=None, ranges=None,
                start_offset=0, seen=()):
    """Carve `file_types` out of the image; returns how many were found.

    `progress(position, size, found)` is called once per chunk, and
    `should_stop()` consulted as often -- CarvingCancelled leaves the loop
    with everything found so far already handed to the sink. `stats`, a
    dict, is filled with what the run saw: candidates and rejections by
    type, bytes scanned and skipped as allocated.

    `ranges` -- [(offset, length), ...] in image order -- confines the carve
    to those regions alone (file slack), nothing read past their ends.
    `start_offset` resumes a carve: everything before it is skipped, and
    `seen` -- (offset, type) pairs already carved -- is not carved again.
    """
    global _STATS
    run = {'candidates': {}, 'rejected': {}, 'bytes_scanned': 0,
           'bytes_skipped': 0}
    _STATS = run
    try:
        return _carve_image(image_handler, file_types, sink,
                            unallocated_only, progress, should_stop, run,
                            ranges, start_offset, seen)
    finally:
        _STATS = None
        if stats is not None:
            stats.update(run)


def _carve_image(image_handler, file_types, sink, unallocated_only,
                 progress, should_stop, run, ranges=None, start_offset=0,
                 seen=()):
    wanted = {t.lower() for t in file_types if t.lower() in EXTENSION_CARVER}
    families = {EXTENSION_CARVER[t] for t in wanted}
    if 'tar' in families:
        families.add('tar_v7')          # the same type, without a magic
    families = sorted(families, key=_CARVE_ORDER.index)
    if not families:
        return 0
    allocated = allocation_map(image_handler) if unallocated_only else []
    if allocated:
        logger.info("Skipping %d allocated regions (%.1f MB) while carving",
                    len(allocated),
                    sum(end - begin for begin, end in allocated) / 1048576)

    size = image_handler.get_size()
    if ranges is not None:
        return _carve_ranges(image_handler, ranges, families, wanted, sink,
                             progress, should_stop, run, start_offset, seen,
                             size)
    carver = Carver(sink, wanted=wanted, reader=image_handler.read,
                    image_size=size)
    carver._seen.update(seen)
    offset = (start_offset // CHUNK_SIZE) * CHUNK_SIZE
    if offset:
        # Resuming: what was carved before is kept, but reassembly works
        # from the fragment headers the scan noted -- so the part already
        # done is read once more for those alone, carving nothing.
        for skipped in range(0, offset, CHUNK_SIZE):
            if should_stop and should_stop():
                raise CarvingCancelled()
            for begin, end in free_ranges(skipped,
                                          min(skipped + CHUNK_SIZE, size),
                                          allocated):
                chunk = image_handler.read(begin, end - begin)
                if chunk:
                    carver.note_unfinished(chunk, begin, families,
                                           limit=end - begin)
    while offset < size:
        if should_stop and should_stop():
            raise CarvingCancelled()
        if progress:
            progress(offset, size, carver.found)
        chunk_end = min(offset + CHUNK_SIZE, size)
        # Every free stretch of the chunk is carved; the live files between
        # them are not read. (Skipping a whole 4 MB chunk for one allocated
        # cluster in it, as before, left most of a real disk's deleted data
        # uncarved: live files are scattered through every chunk.)
        for begin, end in free_ranges(offset, chunk_end, allocated):
            if end - begin < SECTOR_SIZE:
                continue
            run['bytes_scanned'] += end - begin
            # Read on past the chunk for a file that crosses its end -- but
            # never into the next live file.
            limit = Carver.next_allocated_start(begin, allocated)
            read_end = min(chunk_end + CARVE_OVERLAP, size)
            if limit is not None:
                read_end = min(read_end, limit)
            chunk = image_handler.read(begin, read_end - begin)
            if not chunk:
                continue
            for family in families:
                try:
                    Carver.CARVERS[family](carver, chunk, begin)
                except Exception as exc:
                    # One malformed span must not end the scan.
                    logger.warning("%s carver failed at offset %d: %s: %s",
                                   family, begin, type(exc).__name__, exc)
            carver.note_unfinished(chunk, begin, families,
                                   limit=end - begin)
        run['bytes_skipped'] += (chunk_end - offset) - sum(
            e - b for b, e in free_ranges(offset, chunk_end, allocated))
        offset += CHUNK_SIZE

    carver.reassemble_fragmented(allocated, should_stop)
    if progress:
        progress(size, size, carver.found)
    return carver.found


def _carve_ranges(image_handler, ranges, families, wanted, sink, progress,
                  should_stop, run, start_offset, seen, size):
    """Carve inside each region alone: no reader past it, so a carve
    cannot run on into the live file in the next cluster."""
    carver = Carver(sink, wanted=wanted, reader=None, image_size=size)
    carver._seen.update(seen)
    for index, (begin, length) in enumerate(ranges):
        if begin + length <= start_offset or length < 16:
            continue
        if should_stop and should_stop():
            raise CarvingCancelled()
        if progress and index % 256 == 0:
            progress(begin, size, carver.found)
        chunk = image_handler.read(begin, length)
        if not chunk:
            continue
        run['bytes_scanned'] += len(chunk)
        for family in families:
            try:
                Carver.CARVERS[family](carver, chunk, begin)
            except Exception as exc:
                logger.warning("%s carver failed in slack at %d: %s",
                               family, begin, exc)
    if progress:
        progress(size, size, carver.found)
    return carver.found


def free_ranges(begin, end, allocated):
    """The parts of [begin, end) outside the merged, sorted `allocated`
    ranges."""
    if not allocated:
        return [(begin, end)] if end > begin else []
    out, cursor = [], begin
    index = max(0, bisect.bisect_right(allocated, (begin, float('inf'))) - 1)
    while index < len(allocated) and allocated[index][0] < end:
        low, high = allocated[index]
        if high > cursor:
            if low > cursor:
                out.append((cursor, min(low, end)))
            cursor = max(cursor, high)
        index += 1
    if cursor < end:
        out.append((cursor, end))
    return out


def read_carved(read, offset, size, fragments=None):
    """A carved file's bytes, read back from the image with `read(offset,
    length)`: the run at `offset`, or -- for a file rebuilt from fragments --
    each piece in turn. None if the image no longer gives them all."""
    pieces = fragments or [(offset, size)]
    content = b''.join(read(int(begin), int(length))
                       for begin, length in pieces)
    return content if len(content) == size else None


#: Longest name part kept after the offset.
NAME_LIMIT = 80
_UNSAFE = re.compile(r'[\x00-\x1f<>:"/\\|?*]+')
_RESERVED = re.compile(r'^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$', re.I)


def safe_name(text):
    """`text` as a file name on Windows, macOS and Linux: no separators,
    reserved characters or device names, no trailing dot or space, at most
    NAME_LIMIT characters; '' when nothing is left."""
    text = _UNSAFE.sub('_', text or '').strip(' .')
    if len(text) > NAME_LIMIT:
        stem, dot, extension = text.rpartition('.')
        if dot and 0 < len(extension) <= 8:
            text = stem[:NAME_LIMIT - len(extension) - 1].rstrip(' .') + \
                '.' + extension
        else:
            text = text[:NAME_LIMIT].rstrip(' .')
    if _RESERVED.match(text):
        text = '_' + text
    return text


def carved_name(offset, file_type, origin=None, content=None):
    """A carved file is named after where on disk it was found -- the
    offset, in hex, always first, so every name is unique and says where
    the bytes are -- then, when one is known, what it was called:

    * `<offset>-<name>` when a deleted entry names it (carve_origin); its
      extension follows the carve's type when the two disagree
      ('notes.txt.jpg'): the name is the file system's, the type is what
      the bytes are;
    * `<offset>-[title] <title>.<ext>` when the document's own metadata
      gives a title (Office, OpenDocument, PDF, OLE) -- labelled, since it
      is what the author typed, not a file name;
    * otherwise `<offset>.<ext>`.

    A slack carve's origin is the live file it was found behind, not its
    name, and is not used."""
    base = f"{offset:x}"
    named = (origin or {}).get('name')
    if named:
        name = safe_name(named)
        if name:
            if not name.lower().endswith('.' + file_type.lower()) and \
                    not _same_extension(name, file_type):
                name += f".{file_type}"
            return f"{base}-{name}"
    title = _embedded_title(content, file_type)
    if title:
        return f"{base}-{safe_name(f'[title] {title}.{file_type}')}"
    return f"{base}.{file_type}"


#: Extensions one carved type is also written under.
_ALSO = {'jpg': ('jpeg', 'jpe'), 'tiff': ('tif',), 'html': ('htm',),
         'ole': ('doc', 'xls', 'ppt', 'msg'), 'mpg': ('mpeg',),
         'exe': ('scr', 'com'), 'regf': ('dat', 'hve'),
         'sqlite': ('db', 'sqlite3', 'sqlitedb'), 'mbox': ('mbx',)}


def _same_extension(name, file_type):
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    return extension in _ALSO.get(file_type.lower(), ())


def _embedded_title(content, file_type):
    """A document's title from its own metadata, or ''."""
    if not content or file_type.lower() not in (
            'pdf', 'ole', 'docx', 'xlsx', 'pptx', 'vsdx', 'odt', 'ods',
            'odp', 'odg', 'epub', 'rtf'):
        return ''
    try:
        from trace_app.core.content_checks import document_authors
        title = document_authors(bytes(content)).get('title') or ''
    except Exception:
        return ''
    title = ' '.join(str(title).split())
    return title if len(title) >= 2 else ''


#: How a carve's analysis rows, findings and search items give its path:
#: '[carved]/<name>', with the file it was when a deleted entry says so.
CARVED_PREFIX = '[carved]/'


def carved_path(name, origin=None):
    path = f"{CARVED_PREFIX}{name}"
    if (origin or {}).get('path'):
        path += f" (was {origin['path']})"
    return path


def analyse_carve(record, content, magic=None):
    """The file analysis of one carve -- type, entropy, hidden data, photo
    metadata, authors, executables -- as a row for add_analysis_batch:
    (span ref, name, path, deleted, facts). The carve's own hashes are
    reused, not computed again."""
    from trace_app.core import analysis
    from trace_app.core.case import make_span_ref
    modules = tuple(m for m in analysis.MODULES
                    if m != analysis.MODULE_HASH
                    and (m != analysis.MODULE_MAGIC or magic is not None))
    # Judged under the name the file system gave it, when one did -- an
    # 'invoice.pdf' holding a program is a mismatch of the evidence's --
    # not under the copy's name, whose added extension ('invoice.pdf.exe')
    # would be a "deceptive name" of TRACE's own making.
    judged = (record.get('origin') or {}).get('name') or \
        f"{int(record['offset']):x}.{record['type']}"
    try:
        facts = analysis.analyse_bytes(judged, content, modules,
                                       magic=magic, size=len(content))
    except Exception as exc:
        logger.debug("Carve %s not analysed: %s", record['name'], exc)
        facts = {'size': len(content)}
    for key in ('md5', 'sha1', 'sha256'):
        facts[key] = record.get(key)
    offset = int(record['offset'])
    return (make_span_ref(0, offset, offset + len(content)), record['name'],
            carved_path(record['name'], record.get('origin')), True, facts)


def write_carved(folder, content, file_type, offset, fragments=None,
                 source='unallocated', origin=None):
    """Write one carved file into `folder`; return what is known about it.

    `fragments` -- [(offset, length), ...] -- for a file rebuilt from pieces
    the file system had split; it stays with the record, since a rebuilt file
    is a conclusion the examiner may need to show working for.

    Only a date the file carries in its own bytes means anything: a carved
    file has no directory entry, so its file-system times are gone, and
    stamping it with the time of recovery would present our own clock as
    evidence. When there is one, the written file is given it too, so the
    copy still reads correctly outside TRACE.
    """
    os.makedirs(folder, exist_ok=True)
    name = carved_name(offset, file_type, origin, content)
    path = os.path.join(folder, name)
    with open(path, 'wb') as handle:
        handle.write(content)

    carve_source = source
    stamp, date_source = extract_original_timestamp(content, file_type)
    if stamp:
        seconds = time.mktime(stamp.timetuple())
        try:
            os.utime(path, (seconds, seconds))
        except (OSError, OverflowError):
            pass
        embedded = stamp.strftime("%Y-%m-%d %H:%M:%S")
    else:
        embedded = UNKNOWN_DATE
    assessment = carve_verify.assess(content, file_type, fragments)
    return {
        'name': name,
        'path': path,
        'offset': offset,
        'size': len(content),
        'type': file_type,
        'md5': hashlib.md5(content).hexdigest(),
        'sha1': hashlib.sha1(content).hexdigest(),
        'sha256': hashlib.sha256(content).hexdigest(),
        'embedded_date': embedded,
        'date_source': date_source or '',
        'fragments': [list(piece) for piece in fragments] if fragments
        else None,
        'status': assessment['status'],
        'checks': assessment['checks'],
        'source': carve_source,
        'origin': origin,
    }


#: Databases larger than this are not replayed for pairing.
PAIR_MAX_BYTES = 64 * 1024 * 1024


def _wal_mode_page_size(database):
    """A database's page size if its header says WAL mode (read and write
    versions both 2), else None: only those have a -wal."""
    if len(database) < 100 or database[18] != 2 or database[19] != 2:
        return None
    page = struct.unpack_from('>H', database, 16)[0]
    return 65536 if page == 1 else page


def _schema(database):
    from trace_app.core.activity import sqlite_bytes
    with sqlite_bytes.open_database(database) as db:
        if db.execute("PRAGMA integrity_check(5)").fetchall() != [('ok',)]:
            return None
        return frozenset((kind, name) for kind, name in db.execute(
            "SELECT type, name FROM sqlite_master"))


def pair_wal(wal, databases):
    """Which of `databases` [(key, bytes)] a carved WAL belongs to.

    A WAL does not name its database (its salts are its own). Its
    committed frames are replayed onto each candidate in WAL mode with the
    same page size; one is the WAL's when the replayed header records the
    database size of the WAL's last commit, integrity_check passes and the
    schema is the one the database had (a WAL from another database
    rewrites pages into nonsense, into another schema, or past the end its
    header counts). Returns
    {'database': key, 'basis': ...}, {'ambiguous': [keys], ...} when more
    than one passes -- two copies of one application's database can -- or
    None."""
    from trace_app.core.activity import sqlite_bytes
    from trace_app.core.carving_formats import wal_header
    header = wal_header(wal)
    if header is None:
        return None
    page = header[0]
    pages = len(sqlite_bytes.apply_wal(b'', wal)) // page
    if not pages:
        return None                     # no committed frame: nothing to add
    proven = []
    for key, database in databases:
        if _wal_mode_page_size(database) != page:
            continue
        replayed = sqlite_bytes.apply_wal(database, wal)
        # SQLite rewrites page 1 -- and the page count in its header --
        # whenever a transaction changes the database's size, so after the
        # replay the header must record the size the WAL's last commit
        # did. Onto another database the frames land past what its header
        # counts, where integrity_check does not look.
        if struct.unpack_from('>I', replayed, 28)[0] != pages:
            continue
        try:
            before, after = _schema(database), _schema(replayed)
        except Exception:
            continue
        if before is not None and after == before:
            proven.append(key)
    if len(proven) == 1:
        return {'database': proven[0],
                'basis': "its committed frames replay onto this database: "
                         "the header then records the size of the WAL's "
                         "last commit, integrity_check passes and the "
                         "schema is unchanged; no other carved database "
                         "does"}
    if proven:
        return {'ambiguous': proven,
                'basis': "replays cleanly onto more than one carved "
                         "database: not paired"}
    return None


def pair_wal_files(read, case, evidence_id):
    """Pair each carved WAL of one evidence with its carved database
    (pair_wal), recording `related` on both. Returns pairs made."""
    wals = case.carved_files(evidence_id, 'wal', limit=10 ** 6)
    if not wals:
        return 0
    databases = []
    for row in case.carved_files(evidence_id, 'sqlite', limit=10 ** 6):
        if int(row['size']) <= PAIR_MAX_BYTES:
            try:
                data = read_carved(read, int(row['offset']), int(row['size']),
                                   row.get('fragments'))
            except Exception:
                continue
            if _wal_mode_page_size(data):
                databases.append((row, data))
    by_offset = {int(row['offset']): row for row, _data in databases}
    pairs = 0
    for wal_row in wals:
        try:
            wal = read_carved(read, int(wal_row['offset']),
                              int(wal_row['size']), wal_row.get('fragments'))
            found = pair_wal(wal, [(int(row['offset']), data)
                                   for row, data in databases])
        except Exception as exc:
            logger.debug("WAL %s not paired: %s", wal_row['name'], exc)
            continue
        if not found:
            continue
        if 'database' in found:
            database = by_offset[found['database']]
            case.set_carved_related(evidence_id, int(wal_row['offset']), {
                'database': database['name'],
                'offset': int(database['offset']), 'basis': found['basis']})
            case.set_carved_related(evidence_id, int(database['offset']), {
                'wal': wal_row['name'], 'offset': int(wal_row['offset']),
                'size': int(wal_row['size']), 'basis': found['basis']})
            pairs += 1
        else:
            case.set_carved_related(evidence_id, int(wal_row['offset']), {
                'ambiguous': [by_offset[o]['name'] for o in
                              found['ambiguous']], 'basis': found['basis']})
    case.commit()
    return pairs


def carve_evidence(image_handler, case, evidence_id, file_types,
                   unallocated_only=True, progress=None, should_stop=None,
                   on_file=None, source=None, resume=False):
    """Carve one piece of evidence into its case; returns files found.

    Results replace the previous carve of the same evidence, are written to
    the case's carved/<evidence>/ folder and recorded as rows, and the run's
    start and end go to the case's audit trail. A cancelled carve keeps what
    it found. `progress(position, size, found)` as in carve_image;
    `on_file(record)` hears of each file as it is written.
    """
    from trace_app.core import carve_origin
    types = [t.lower() for t in file_types]
    folder = case.carved_dir_for(evidence_id)
    size = image_handler.get_size()
    source = source or ('unallocated' if unallocated_only else 'image')
    previous = case.carving_state(evidence_id) if resume else None
    start_offset, seen, already = 0, set(), 0
    if previous and previous.get('status') != 'done':
        # Carry on where it stopped, with what it was doing.
        runs = case.carving_runs(evidence_id, limit=1)
        settings = runs[0]['settings'] if runs else {}
        types = settings.get('types') or types
        source = settings.get('source') or source
        start_offset = int(previous.get('bytes_done') or 0)
        rows = case.carved_files(evidence_id, limit=10 ** 7)
        seen = {(int(r['offset']), r['type']) for r in rows}
        already = len(rows)
    else:
        resume = False
        case.clear_carved(evidence_id)
    case.set_carving_state(evidence_id, 'running', types=','.join(types),
                           unallocated_only=source == 'unallocated',
                           bytes_done=start_offset, bytes_total=size,
                           found=already)
    run_id = case.start_carving_run(
        evidence_id, {'types': types, 'source': source,
                      'resumed_from': start_offset if resume else None},
        engine_identity())
    ranges, slack_list = None, []
    if source == 'slack':
        from trace_app.core import slack
        slack_list = slack.slack_ranges(image_handler, should_stop)
        ranges = [(begin, length) for begin, length, _p, _r in slack_list]
    # Where deleted files began: a carve starting there was that file.
    try:
        starts = carve_origin.deleted_file_starts(image_handler, should_stop)
    except Exception as exc:
        logger.warning("Deleted files could not be listed for naming "
                       "carves: %s", exc)
        starts = {}
    slack_owners = sorted((begin, begin + length, path, ref)
                          for begin, length, path, ref in slack_list)

    def slack_owner(offset):
        import bisect as _bisect
        index = _bisect.bisect_right(slack_owners,
                                     (offset, float('inf'), '', '')) - 1
        if index >= 0 and slack_owners[index][0] <= offset < \
                slack_owners[index][1]:
            return slack_owners[index][2], slack_owners[index][3]
        return None

    found = [already]
    tally = {'kept': {}, 'status': {}, 'named': 0}
    analysed = []
    from trace_app.core.analysis import magic_reader
    magic = magic_reader()
    import time as _time
    checkpoint = {'at': _time.monotonic(), 'position': start_offset}

    def report(position, total, count):
        checkpoint['position'] = position
        if _time.monotonic() - checkpoint['at'] >= CHECKPOINT_SECONDS:
            checkpoint['at'] = _time.monotonic()
            case.commit()
            case.set_carving_state(evidence_id, 'running',
                                   bytes_done=position, found=found[0])
        if progress:
            progress(position, total, count)

    def sink(content, file_type, offset, fragments=None):
        origin = carve_origin.match(starts, offset, len(content))
        if source == 'slack':
            owner = slack_owner(offset)
            origin = origin or ({'path': owner[0], 'ref': owner[1],
                                 'basis': f"found in the slack of the live "
                                          f"file {owner[0]}"}
                                if owner else None)
        record = write_carved(folder, content, file_type, offset, fragments,
                              source=source, origin=origin)
        case.add_carved(evidence_id, record)
        # Judged like a file on disk, while its bytes are in hand: a carved
        # executable, encrypted blob or located photo becomes a finding.
        analysed.append(analyse_carve(record, content, magic))
        if len(analysed) >= 50:
            case.add_analysis_batch(evidence_id, analysed)
            analysed.clear()
        found[0] += 1
        tally['kept'][file_type] = tally['kept'].get(file_type, 0) + 1
        tally['status'][record['status']] = \
            tally['status'].get(record['status'], 0) + 1
        tally['named'] += 1 if origin else 0
        if on_file:
            on_file(record)
        if found[0] % 50 == 0:
            case.commit()

    stats = {}

    def finish(status):
        if analysed:
            case.add_analysis_batch(evidence_id, analysed)
            analysed.clear()
        case.commit()
        try:
            paired = pair_wal_files(image_handler.read, case, evidence_id)
        except Exception as exc:
            logger.warning("Carved WAL files not paired: %s", exc)
            paired = 0
        summary = dict(stats, kept=tally['kept'], status=tally['status'],
                       named=tally['named'], wal_pairs=paired,
                       duplicates=sum(len(v) - 1 for v in
                                      case.carved_duplicates(
                                          evidence_id).values()))
        case.finish_carving_run(run_id, status, summary, found[0])
        candidates = sum(stats.get('candidates', {}).values())
        rejected = sum(stats.get('rejected', {}).values())
        case.record_event(
            'carving statistics',
            f"evidence id={evidence_id} run={run_id} status={status} "
            f"source={source} candidates={candidates} kept={found[0]} "
            f"rejected={rejected} "
            + ' '.join(f"{k}={v}" for k, v in sorted(
                tally['status'].items()))
            + f" named from deleted entries={tally['named']} "
            f"duplicates={summary['duplicates']} wal pairs={paired} "
            f"engine={engine_identity()}")

    try:
        carve_image(image_handler, types, sink, source == 'unallocated',
                    progress=report, should_stop=should_stop, stats=stats,
                    ranges=ranges, start_offset=start_offset, seen=seen)
    except CarvingCancelled:
        finish('cancelled')
        case.set_carving_state(evidence_id, 'cancelled', found=found[0],
                               bytes_done=checkpoint['position'])
        logger.info("Carving cancelled after %d file(s)", found[0])
        return found[0]
    except Exception as exc:
        finish('failed')
        case.set_carving_state(evidence_id, 'failed', found=found[0],
                               last_error=str(exc))
        raise
    finish('done')
    case.set_carving_state(evidence_id, 'done', bytes_done=size,
                           found=found[0])
    logger.info("Carved %d file(s) from evidence %s", found[0], evidence_id)
    return found[0]

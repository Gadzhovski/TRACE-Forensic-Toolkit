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

A carver abandons a file that runs off the end of its buffer, so a file
larger than CARVE_OVERLAP that straddles a chunk boundary is found only if it
also starts within the next read. Fragmented files are not reassembled.
"""

import hashlib
import logging
import os
import re
import struct
import time
import zlib

from trace_app.core.carving_signatures import (extract_original_timestamp,
                                              is_valid_file)
from trace_app.core.image_handler import ImageHandler
from trace_app.infra.constants import (CARVE_MAX_FOOTER_CANDIDATES,
                                       CARVE_MAX_SIZE, CARVE_MIN_SIZE,
                                       CARVE_OVERLAP, CHUNK_SIZE, SECTOR_SIZE,
                                       UNKNOWN_DATE)

logger = logging.getLogger('TRACE.Carving')


#: File signatures the carver can search for. Order is the menu order.
#: "OLE" covers the legacy Office trio (.doc/.xls/.ppt), which share one
#: compound-document container and cannot be told apart from the header alone.
CARVABLE_TYPES = ["PDF", "JPG", "PNG", "GIF", "BMP", "TIFF", "WAV", "MOV",
                  "MP4", "WMV", "ZIP", "GZ", "RAR", "7Z", "OLE", "HTML"]

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

    def __init__(self, sink):
        self._sink = sink
        self._seen = set()
        self.found = 0

    def save_file(self, file_content, file_type, offset):
        key = (offset, file_type)
        if key in self._seen:
            return
        self._seen.add(key)
        self.found += 1
        self._sink(file_content, file_type, offset)

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
                            self.save_file(pdf_content, 'pdf', global_offset + start_index)
                            offset = start_index + file_size
                            continue
                    except ValueError:
                        pass
            end_index = chunk.find(pdf_end_signature, start_index)
            if end_index != -1:
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]
                if is_valid_file(pdf_content, 'pdf'):
                    self.save_file(pdf_content, 'pdf', global_offset + start_index)
                offset = end_index
            else:
                offset = start_index + 1

    def carve_wav_files(self, chunk, base_offset):
        wav_start_signature = WAV_HEADER
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(wav_start_signature, cursor)
            if start_index == -1:
                break

            if chunk[start_index + 8:start_index + 12] != b'WAVE':
                cursor = start_index + 4
                continue

            file_size_bytes = chunk[start_index + 4:start_index + 8]
            file_size = int.from_bytes(file_size_bytes, byteorder='little') + 8

            if start_index + file_size > len(chunk):
                wav_content = chunk[start_index:]
                cursor = len(chunk)
            else:
                wav_content = chunk[start_index:start_index + file_size]
                cursor = start_index + file_size

            if is_valid_file(wav_content, 'wav'):
                self.save_file(wav_content, 'wav', base_offset + start_index)

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

    def carve_mp4_files(self, chunk, base_offset):
        """MP4 shares QuickTime's container, and so shares carve_mov_files.

        Deliberately empty: the atom walk already emits MP4s with the right
        extension. Carving here as well would write the same bytes a second
        time under a second name.
        """
        return

    def _carve_atom_chain(self, chunk, base_offset):
        cap = max(CARVE_MAX_SIZE.get('mov', 0), CARVE_MAX_SIZE.get('mp4', 0))
        cursor = 0
        while cursor + 8 <= len(chunk):
            anchor = self._next_atom_start(chunk, cursor)
            if anchor is None:
                break

            end = self._walk_atoms(chunk, anchor, cap)
            if end is None:
                # Not a real chain; resume just past this candidate rather
                # than past the span it would have covered.
                cursor = anchor + 4
                continue

            content = chunk[anchor:end]
            file_type = self._isobmff_extension(content)
            if is_valid_file(content, file_type):
                self.save_file(content, file_type, base_offset + anchor)
                cursor = end
            else:
                cursor = anchor + 4

    @staticmethod
    def _isobmff_extension(content):
        """'mp4' or 'mov', from the brand the file declares.

        A `ftyp` atom names the specification the file was written to. Classic
        QuickTime predates `ftyp` and simply has none, so its absence is itself
        the answer.
        """
        if content[4:8] != b'ftyp':
            return 'mov'
        brand = content[8:12]
        return 'mov' if brand in (b'qt  ', b'moov') else 'mp4'

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
    def _walk_atoms(chunk, start, cap):
        """End offset of the atom chain beginning at `start`, or None.

        Returns None when the chain is not one: a single atom proves nothing,
        because four printable bytes preceded by a plausible length occur in
        ordinary data.
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
                    break
                size = int.from_bytes(chunk[pos + 8:pos + 16], 'big')
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
                self.save_file(content, 'zip', base_offset + start_index)
                cursor = end
            else:
                cursor = start_index + len(ZIP_LOCAL_HEADER)

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
        self._carve_by_marker(chunk, base_offset, 'rar', RAR_HEADER)

    def carve_7z_files(self, chunk, base_offset):
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

    #: Which carver handles each selected type. Keys are lowercase because the
    #: menu labels are lowercased before dispatch.
    CARVERS = {
        'pdf': carve_pdf_files,
        'jpg': carve_jpg_files,
        'png': carve_png_files,
        'gif': carve_gif_files,
        'bmp': carve_bmp_files,
        'tiff': carve_tiff_files,
        'wav': carve_wav_files,
        'mov': carve_mov_files,
        'mp4': carve_mp4_files,
        'wmv': carve_wmv_files,
        'zip': carve_zip_files,
        'gz': carve_gz_files,
        'rar': carve_rar_files,
        '7z': carve_7z_files,
        'ole': carve_ole_files,
        'html': carve_html_files,
    }



def allocation_map(image_handler):
    """The allocated byte ranges of every file system in the image, merged.

    Carving skips them: what is allocated is a live file the tree already
    shows, and carving it again only buries the deleted data in duplicates.
    Empty (carve everything) if no file system can be read.
    """
    ranges = []
    try:
        partitions = image_handler.get_partitions()
        offsets = [p[2] for p in partitions] if partitions else [0]
        for start in offsets:
            if partitions or image_handler.has_filesystem(start):
                ranges.extend(image_handler.build_allocation_map(start))
    except Exception as exc:
        logger.warning("Could not build the allocation map (%s); carving "
                       "the whole image", exc)
        return []
    # Merge, not just sort: is_offset_allocated binary searches this list,
    # which is only valid if the ranges are ordered AND do not overlap.
    return ImageHandler._merge_ranges(ranges)


def carve_image(image_handler, file_types, sink, unallocated_only=True,
                progress=None, should_stop=None):
    """Carve `file_types` out of the image; returns how many were found.

    `progress(position, size, found)` is called once per chunk, and
    `should_stop()` consulted as often -- CarvingCancelled leaves the loop
    with everything found so far already handed to the sink.
    """
    file_types = [t.lower() for t in file_types if t.lower() in Carver.CARVERS]
    if not file_types:
        return 0
    allocated = allocation_map(image_handler) if unallocated_only else []
    if allocated:
        logger.info("Skipping %d allocated regions (%.1f MB) while carving",
                    len(allocated),
                    sum(end - begin for begin, end in allocated) / 1048576)

    carver = Carver(sink)
    size = image_handler.get_size()
    offset = 0
    while offset < size:
        if should_stop and should_stop():
            raise CarvingCancelled()
        if progress:
            progress(offset, size, carver.found)

        if Carver.is_offset_allocated(offset, CHUNK_SIZE, allocated):
            offset += CHUNK_SIZE
            continue
        # Stop the read at the next allocated region: the overlap window
        # beyond the chunk is not covered by the test above, and reading it
        # blindly pulls live file data into the carvers.
        limit = Carver.next_allocated_start(offset, allocated)
        read_size = CHUNK_SIZE + CARVE_OVERLAP
        span = read_size if limit is None else min(read_size, limit - offset)
        if span <= 0:
            offset += CHUNK_SIZE
            continue

        chunk = image_handler.read(offset, span)
        if not chunk:
            break
        for file_type in file_types:
            try:
                Carver.CARVERS[file_type](carver, chunk, offset)
            except Exception as exc:
                # One malformed span must not end the scan.
                logger.warning("%s carver failed at offset %d: %s: %s",
                               file_type, offset, type(exc).__name__, exc)
        offset += CHUNK_SIZE

    if progress:
        progress(size, size, carver.found)
    return carver.found


def carved_name(offset, file_type):
    """A carved file is named after where on disk it was found."""
    return f"{offset:x}.{file_type}"


def write_carved(folder, content, file_type, offset):
    """Write one carved file into `folder`; return what is known about it.

    Only a date the file carries in its own bytes means anything: a carved
    file has no directory entry, so its file-system times are gone, and
    stamping it with the time of recovery would present our own clock as
    evidence. When there is one, the written file is given it too, so the
    copy still reads correctly outside TRACE.
    """
    os.makedirs(folder, exist_ok=True)
    name = carved_name(offset, file_type)
    path = os.path.join(folder, name)
    with open(path, 'wb') as handle:
        handle.write(content)

    stamp, source = extract_original_timestamp(content, file_type)
    if stamp:
        seconds = time.mktime(stamp.timetuple())
        try:
            os.utime(path, (seconds, seconds))
        except (OSError, OverflowError):
            pass
        embedded = stamp.strftime("%Y-%m-%d %H:%M:%S")
    else:
        embedded = UNKNOWN_DATE
    return {
        'name': name,
        'path': path,
        'offset': offset,
        'size': len(content),
        'type': file_type,
        'sha256': hashlib.sha256(content).hexdigest(),
        'embedded_date': embedded,
        'date_source': source or '',
    }


def carve_evidence(image_handler, case, evidence_id, file_types,
                   unallocated_only=True, progress=None, should_stop=None,
                   on_file=None):
    """Carve one piece of evidence into its case; returns files found.

    Results replace the previous carve of the same evidence, are written to
    the case's carved/<evidence>/ folder and recorded as rows, and the run's
    start and end go to the case's audit trail. A cancelled carve keeps what
    it found. `progress(position, size, found)` as in carve_image;
    `on_file(record)` hears of each file as it is written.
    """
    types = [t.lower() for t in file_types]
    folder = case.carved_dir_for(evidence_id)
    case.clear_carved(evidence_id)
    size = image_handler.get_size()
    case.set_carving_state(evidence_id, 'running', types=','.join(types),
                           unallocated_only=unallocated_only, bytes_done=0,
                           bytes_total=size, found=0)
    found = [0]

    def sink(content, file_type, offset):
        record = write_carved(folder, content, file_type, offset)
        case.add_carved(evidence_id, record)
        found[0] += 1
        if on_file:
            on_file(record)
        if found[0] % 50 == 0:
            case.commit()

    try:
        carve_image(image_handler, types, sink, unallocated_only,
                    progress=progress, should_stop=should_stop)
    except CarvingCancelled:
        case.commit()
        case.set_carving_state(evidence_id, 'cancelled', found=found[0])
        logger.info("Carving cancelled after %d file(s)", found[0])
        return found[0]
    except Exception as exc:
        case.commit()
        case.set_carving_state(evidence_id, 'failed', found=found[0],
                               last_error=str(exc))
        raise
    case.commit()
    case.set_carving_state(evidence_id, 'done', bytes_done=size,
                           found=found[0])
    logger.info("Carved %d file(s) from evidence %s", found[0], evidence_id)
    return found[0]

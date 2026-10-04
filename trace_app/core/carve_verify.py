"""What a carved file's own structure proves about it.

Every carve has already passed its format's validator
(carving_signatures.is_valid_file) -- a signature alone is never kept. This
goes further and records, check by check, what the bytes show, and -- the
point -- whether anything in the format *proves* the file whole.

Some formats carry that proof: a PNG's every chunk has a CRC, a ZIP's every
member a CRC-32, a gzip stream a CRC and length, a SQLite database a page
count and integrity_check, an OLE file sector chains that must close, a PDF
a cross-reference whose every offset must land on its object, a PE a
checksum (when one was recorded), a JPEG with restart markers a numbered
sequence of them. Others carry none: a JPEG without restart markers decodes
foreign data without complaint, an HTML page or an MP3 has nothing that
would notice a block of another file inside it. Calling those "complete"
would claim what nothing showed -- measured on the DFRWS 2006 image, where
fragmented JPEGs and HTML pages decode and parse cleanly with another file's
bytes in them.

The status follows from the checks, not from a score:

* complete       every check passed, and the checks prove the file whole
* valid          every check passed; the format carries nothing that could
                 prove no foreign data is inside
* reconstructed  rebuilt from fragments (reassembly accepted the split only
                 because a checksum proved it)
* partial        a check failed: truncated or foreign data, a member whose
                 CRC does not match, a database shorter than its header says

A check is (result, text): True passed, False failed, None a fact that is
neither (encrypted, so not checked). No Qt here.
"""

import array
import io
import math
import re
import struct
import warnings
import zipfile
import zlib

COMPLETE, VALID, RECONSTRUCTED, PARTIAL = ('complete', 'valid',
                                           'reconstructed', 'partial')
STATUSES = (COMPLETE, VALID, RECONSTRUCTED, PARTIAL)
STATUS_LABELS = {COMPLETE: 'Complete', VALID: 'Valid',
                 RECONSTRUCTED: 'Reconstructed', PARTIAL: 'Partial'}
STATUS_MEANINGS = {
    COMPLETE: "every check passed, and the format's own checksums or "
              "counts prove the file whole",
    VALID: "every check passed, but the format carries nothing that "
           "could prove no foreign data is inside",
    RECONSTRUCTED: "rebuilt from fragments; a checksum proved the split",
    PARTIAL: "the format, but a check failed: truncated, damaged or "
             "mixed with another file's data",
}

#: Largest content decompressed to check CRCs, and image decoded.
MAX_CHECK_BYTES = 512 * 1024 * 1024
MAX_PIXELS = 80_000_000

_ZIP_KINDS = {'zip', 'docx', 'xlsx', 'pptx', 'vsdx', 'odt', 'ods', 'odp',
              'odg', 'apk', 'jar', 'epub', 'xps', 'ipa', 'kmz', 'cbz'}


def assess(content, file_type, fragments=None):
    """{'status', 'checks': [[result, text], ...]} for one carved file."""
    kind = (file_type or '').lower()
    checks = [[True, "Header and structure validated for the format"]]
    proves = False
    checker = _CHECKERS.get('zip' if kind in _ZIP_KINDS else kind)
    if checker is not None:
        try:
            more, proves = checker(content)
            checks += more
        except Exception as exc:      # a checker must never lose a carve
            checks.append([False, f"Structure could not be checked: "
                                  f"{type(exc).__name__}: {exc}"])
    failed = any(result is False for result, _text in checks)
    if not proves and not failed:
        checks.append([None, "Nothing in this format proves the file has "
                             "no foreign data inside"])
    if fragments:
        checks.append([True, f"Rebuilt from {len(fragments)} fragments; "
                             f"the split was accepted only because a "
                             f"checksum proved it"])
    if failed:
        status = PARTIAL
    elif fragments:
        status = RECONSTRUCTED
    else:
        status = COMPLETE if proves else VALID
    return {'status': status, 'checks': checks}


def _passed(checks):
    return not any(result is False for result, _text in checks)


# --- images ---------------------------------------------------------------------

def _decodes(content):
    from PIL import Image
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with Image.open(io.BytesIO(content)) as picture:
                width, height = picture.size
                if width * height > MAX_PIXELS:
                    return None, (f"{width} × {height}: too large to decode "
                                  f"here")
                picture.load()
                return True, (f"Image data decodes to the end ({width} × "
                              f"{height})")
    except Exception as exc:
        return False, f"Image data does not decode to the end ({exc})"


#: Markers that may stand between the scans of a JPEG (progressive images,
#: tables redefined): their segments are skipped, not taken for damage.
_JPEG_SEGMENTS = {0xC4, 0xCC, 0xDA, 0xDB, 0xDD, 0xFE} | set(range(0xE0, 0xF0))


def _jpeg_frame(content):
    """(frame info, restart interval, start of the first scan's data)."""
    position, frame, interval = 2, None, 0
    while position + 4 <= len(content):
        if content[position] != 0xFF:
            return frame, interval, None
        marker = content[position + 1]
        length = struct.unpack_from('>H', content, position + 2)[0]
        if marker in (0xC0, 0xC1, 0xC2) and position + 10 <= len(content):
            height, width, components = struct.unpack_from(
                '>HHB', content, position + 5)
            factors = [content[position + 11 + 3 * i]
                       for i in range(components)
                       if position + 11 + 3 * i < len(content)]
            frame = {'progressive': marker == 0xC2, 'width': width,
                     'height': height,
                     'h': max((f >> 4 for f in factors), default=1) or 1,
                     'v': max((f & 15 for f in factors), default=1) or 1}
        elif marker == 0xDD:
            interval = struct.unpack_from('>H', content, position + 4)[0]
        elif marker == 0xDA:
            return frame, interval, position + 2 + length
        if length < 2:
            return frame, interval, None
        position += 2 + length
    return frame, interval, None


def _jpeg_scan(content, start):
    """Walk the entropy-coded data: (restart markers in order as
    (offset, number), first byte pair a JPEG never writes there or None,
    offset of EOI or None)."""
    restarts, position, end = [], start, len(content)
    while True:
        position = content.find(b'\xff', position, end)
        if position == -1 or position + 1 >= end:
            return restarts, None, None
        following = content[position + 1]
        if following == 0x00:
            position += 2
            continue
        if following == 0xFF:                 # fill bytes before a marker
            position += 1
            continue
        if 0xD0 <= following <= 0xD7:
            restarts.append((position, following - 0xD0))
            position += 2
            continue
        if following == 0xD9:
            return restarts, None, position
        if following in _JPEG_SEGMENTS and position + 4 <= end:
            length = struct.unpack_from('>H', content, position + 2)[0]
            if length >= 2:
                position += 2 + length
                continue
        return restarts, position, None


def _jpeg(content):
    checks = [[content[:3] == b'\xff\xd8\xff', "Starts with an SOI marker"]]
    frame, interval, scan = _jpeg_frame(content)
    checks.append([scan is not None,
                   "Segment lengths lead to the image data" if scan else
                   "Segment lengths do not lead to the image data"])
    proves = False
    if scan is not None:
        restarts, stray, eoi = _jpeg_scan(content, scan)
        if stray is not None:
            checks.append([False, f"Bytes a JPEG never writes inside image "
                                  f"data, at +{stray:,}: other data is "
                                  f"mixed in"])
        else:
            checks.append([True, "Image data holds only what a JPEG "
                                 "writes there"])
            checks.append([eoi is not None and
                           not content[eoi + 2:].strip(b'\x00'),
                           "Ends at its EOI marker"])
        if interval and stray is None:
            in_order = bool(restarts) and restarts[0][1] == 0 and all(
                b[1] == (a[1] + 1) % 8 for a, b in zip(restarts,
                                                       restarts[1:]))
            expected = None
            if frame and not frame['progressive'] and frame['width']:
                mcus = (math.ceil(frame['width'] / (8 * frame['h']))
                        * math.ceil(frame['height'] / (8 * frame['v'])))
                expected = math.ceil(mcus / interval) - 1
            if expected is not None and in_order and \
                    len(restarts) == expected:
                checks.append([True, f"All {expected:,} restart markers "
                                     f"present, in sequence"])
                proves = True
            elif expected is None and in_order:
                checks.append([None, f"{len(restarts):,} restart markers "
                                     f"in sequence (their count cannot be "
                                     f"checked in a progressive image)"])
            elif expected:
                checks.append([False, f"Restart markers out of sequence or "
                                      f"missing ({len(restarts):,} found, "
                                      f"{expected:,} expected)"])
    result, text = _decodes(content)
    checks.append([result, text])
    return checks, proves and _passed(checks)


def _png(content):
    position, chunks, bad, ended = 8, 0, [], False
    while position + 12 <= len(content):
        length = struct.unpack_from('>I', content, position)[0]
        kind = content[position + 4:position + 8]
        body = content[position + 8:position + 8 + length]
        stored = content[position + 8 + length:position + 12 + length]
        if len(stored) < 4:
            bad.append(kind.decode('latin-1'))
            break
        chunks += 1
        if zlib.crc32(kind + body) != struct.unpack('>I', stored)[0]:
            bad.append(kind.decode('latin-1'))
        position += 12 + length
        if kind == b'IEND':
            ended = True
            break
    checks = [[not bad, f"CRC-32 of all {chunks} chunks matches" if not bad
               else f"CRC-32 fails for {len(bad)} of {chunks} chunk(s): "
                    f"{', '.join(bad[:5])}"],
              [ended, "Ends at its IEND chunk"],
              list(_decodes(content))]
    return checks, _passed(checks)


def _gif(content):
    return [[content.rstrip(b'\x00')[-1:] == b'\x3b', "Ends at its trailer"],
            list(_decodes(content))], False


def _bmp(content):
    declared = struct.unpack_from('<I', content, 2)[0]
    return [[declared == len(content),
             f"Size in its header ({declared:,} bytes) matches"
             if declared == len(content) else
             f"Header says {declared:,} bytes; {len(content):,} carved"],
            list(_decodes(content))], False


# --- documents and archives -------------------------------------------------------

_OBJECT = re.compile(rb'\s*\d+\s+\d+\s+obj')


def _pdf_xref_sections(content):
    """Offsets of every cross-reference section, newest first, following
    each trailer's /Prev."""
    match = re.search(rb'startxref\s+(\d+)', content[-2048:])
    seen, out = set(), []
    target = int(match.group(1)) if match else None
    while target is not None and target not in seen and \
            target < len(content):
        seen.add(target)
        out.append(target)
        trailer = content.find(b'trailer', target)
        previous = re.search(rb'/Prev\s+(\d+)',
                             content[trailer:trailer + 2048]) \
            if trailer != -1 else None
        target = int(previous.group(1)) if previous else None
    return out


def _pdf(content):
    checks = [[content[:5] == b'%PDF-', "Starts with a %PDF header"],
              [b'%%EOF' in content[-2048:], "Ends with %%EOF"]]
    sections = _pdf_xref_sections(content)
    classic = bool(sections) and \
        content[sections[0]:sections[0] + 4] == b'xref'
    if not sections:
        checks.append([False, "No startxref"])
    elif classic:
        good = bad = 0
        for start in sections:
            if content[start:start + 4] != b'xref':
                continue
            stop = content.find(b'trailer', start)
            for line in re.finditer(rb'(\d{10}) (\d{5}) ([nf])',
                                    content[start:stop if stop != -1
                                            else None]):
                if line.group(3) != b'n':
                    continue
                if _OBJECT.match(content, int(line.group(1))):
                    good += 1
                else:
                    bad += 1
        checks.append([bad == 0 and good > 0,
                       f"Every one of {good:,} cross-reference offsets "
                       f"lands on its object" if not bad else
                       f"{bad:,} of {good + bad:,} cross-reference offsets "
                       f"do not land on an object"])
    else:
        points = _OBJECT.match(content, sections[0]) is not None
        checks.append([points, "startxref points at a cross-reference "
                               "stream" if points else
                       "startxref does not point at a cross-reference"])
    import pymupdf
    repaired = False
    with pymupdf.open(stream=content, filetype='pdf') as document:
        checks.append([True, f"Opens: {document.page_count} page(s)"])
        if document.needs_pass:
            checks.append([None, "Encrypted: its objects were not checked"])
        repaired = bool(getattr(document, 'is_repaired', False))
        if repaired:
            checks.append([False, "The cross-reference had to be repaired "
                                  "to open it"])
    # A cross-reference stream that opens without repair: every offset in
    # it was used to find its object.
    return checks, bool(sections) and not repaired and _passed(checks)


def _zip(content):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        checks = [[True, f"Central directory and end record found: "
                         f"{len(members)} member(s)"]]
        encrypted = [m for m in members if m.flag_bits & 1]
        plain = [m for m in members if not m.flag_bits & 1 and
                 not m.is_dir()]
        if sum(m.file_size for m in plain) > MAX_CHECK_BYTES:
            checks.append([None, "Too large to check every member's CRC "
                                 "here"])
            return checks, False
        bad = []
        for member in plain:
            try:
                with archive.open(member) as handle:
                    while handle.read(1 << 20):
                        pass
            except (zipfile.BadZipFile, zlib.error, EOFError,
                    NotImplementedError, OSError) as exc:
                bad.append(f"{member.filename} ({exc})")
        checks.append([not bad, f"CRC-32 of all {len(plain)} member(s) "
                                f"matches" if not bad else
                       f"{len(bad)} of {len(plain)} member(s) fail: "
                       f"{'; '.join(bad[:3])}"])
        if encrypted:
            checks.append([None, f"{len(encrypted)} member(s) encrypted: "
                                 f"their CRCs were not checked"])
        return checks, not bad and not encrypted


def _gzip(content):
    import gzip
    with gzip.GzipFile(fileobj=io.BytesIO(content)) as handle:
        size = 0
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            size += len(block)
            if size > MAX_CHECK_BYTES:
                return [[None, "Too large to check its CRC here"]], False
    return [[True, f"CRC-32 and length match ({size:,} bytes "
                   f"inflated)"]], True


def _ole(content):
    """An OLE compound file (.doc, .xls, .ppt, .msg): opened strictly, so a
    broken sector chain or directory is a failure, and every stream read to
    its recorded size."""
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(content),
                                raise_defects=olefile.DEFECT_INCORRECT)
    except Exception as exc:
        return [[False, f"Sector chains or directory are inconsistent "
                        f"({exc})"]], False
    try:
        streams = ole.listdir()
        short = []
        for path in streams:
            try:
                expected = ole.get_size(path)
                if len(ole.openstream(path).read()) != expected:
                    short.append('/'.join(path))
            except Exception:
                short.append('/'.join(path))
        return [[not short, f"Sector chains close; all {len(streams)} "
                            f"stream(s) read to their recorded size"
                 if not short else
                 f"{len(short)} of {len(streams)} stream(s) cannot be read "
                 f"whole: {', '.join(short[:3])}"]], not short
    finally:
        ole.close()


def _html(content):
    lowered = content.lower()
    openings = lowered.count(b'<html')
    tail = lowered[-4096:]
    return [[b'</html>' in tail, "Ends with its closing </html> tag"
             if b'</html>' in tail else "No closing </html>: the page stops "
                                        "short"],
            [openings <= 1, "One page" if openings <= 1 else
             f"{openings} <html> starts: another page is mixed in"]], False


# --- databases ---------------------------------------------------------------------

def _sqlite(content):
    page_size = struct.unpack_from('>H', content, 16)[0]
    page_size = 65536 if page_size == 1 else page_size
    pages = struct.unpack_from('>I', content, 28)[0]
    checks = []
    if pages:
        expected = pages * page_size
        checks.append([expected == len(content),
                       f"{pages:,} pages of {page_size:,} bytes, as its "
                       f"header says" if expected == len(content) else
                       f"Header says {pages:,} pages ({expected:,} bytes); "
                       f"{len(content):,} carved"])
    from trace_app.core.activity import sqlite_bytes
    try:
        with sqlite_bytes.open_database(content) as db:
            result = db.execute("PRAGMA integrity_check(20)").fetchall()
            tables = db.execute("SELECT count(*) FROM sqlite_master WHERE "
                                "type = 'table'").fetchone()[0]
        ok = result == [('ok',)]
        checks.append([ok, f"integrity_check passes ({tables} table(s))"
                       if ok else
                       f"integrity_check: {result[0][0][:200]}"])
    except Exception as exc:
        checks.append([False, f"Does not open as a database ({exc})"])
    return checks, _passed(checks)


# --- executables -----------------------------------------------------------------

def pe_checksum(content, checksum_offset):
    """The PE checksum (as imagehlp's CheckSumMappedFile computes it)."""
    padded = content + b'\x00' * (-len(content) % 4)
    words = array.array('I')
    if words.itemsize != 4:                       # pragma: no cover
        words = array.array('L')
    words.frombytes(padded)
    if array.array('I', [1]).tobytes()[:1] != b'\x01':
        words.byteswap()                          # big-endian host
    total = sum(words) - words[checksum_offset // 4]
    while total >> 32:
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total + (total >> 16)) & 0xFFFF
    return total + len(content)


def _pe(content):
    pe = struct.unpack_from('<I', content, 0x3C)[0]
    checks = [[content[pe:pe + 4] == b'PE\x00\x00', "PE header found"]]
    sections = struct.unpack_from('<H', content, pe + 6)[0]
    optional = struct.unpack_from('<H', content, pe + 20)[0]
    table = pe + 24 + optional
    ends = []
    for index in range(sections):
        raw_size, raw_pointer = struct.unpack_from('<II', content,
                                                   table + index * 40 + 16)
        if raw_size:
            ends.append(raw_pointer + raw_size)
    end = max(ends, default=0)
    checks.append([end <= len(content),
                   f"All {sections} section(s) lie within the file"
                   if end <= len(content) else
                   f"Sections run to byte {end:,}; {len(content):,} carved"])
    stored = struct.unpack_from('<I', content, pe + 24 + 64)[0]
    proves = False
    if stored and end <= len(content):
        computed = pe_checksum(content, pe + 24 + 64)
        checks.append([computed == stored,
                       f"PE checksum matches ({stored:#010x})"
                       if computed == stored else
                       f"PE checksum {stored:#010x} stored, "
                       f"{computed:#010x} computed"])
        proves = computed == stored
    elif not stored:
        checks.append([None, "No PE checksum recorded (usual outside "
                             "drivers and system files)"])
    return checks, proves and _passed(checks)


_CHECKERS = {'jpg': _jpeg, 'jpeg': _jpeg, 'png': _png, 'gif': _gif,
             'bmp': _bmp, 'pdf': _pdf, 'zip': _zip, 'gz': _gzip,
             'sqlite': _sqlite, 'pe': _pe, 'exe': _pe, 'dll': _pe,
             'sys': _pe, 'ole': _ole, 'html': _html}

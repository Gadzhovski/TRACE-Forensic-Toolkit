"""Signature validation and timestamp extraction for carved data.

Pure functions over a bytes buffer -- no widget, no disk access, no state.
They live in core so this logic can be exercised without starting a GUI.
"""

import datetime
import gzip
import io
import logging
import re
import struct
import zipfile

from pymupdf import open as fitz_open
from PIL import Image, UnidentifiedImageError

from trace_app.infra.constants import CARVE_MAX_SIZE, CARVE_MIN_SIZE

logger = logging.getLogger('TRACE.Carving')

#: An ISO-BMFF atom type is four printable ASCII characters. Checking this is
#: what stops the walk treating arbitrary bytes as a chain of tiny atoms.
_ATOM_NAME = re.compile(rb'[A-Za-z0-9 _\-]{4}')

#: Atom types that mark a real QuickTime/MP4 container rather than a chance
#: four-byte match. `ftyp` is included deliberately: leaving it out is what
#: made the carver enter files at their trailing `moov` instead of their start.
_ISOBMFF_ATOMS = {b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide',
                  b'pnot', b'moof', b'mfra', b'meta', b'uuid'}

#: ASF Header Object GUID -- the first 16 bytes of every WMV/WMA/ASF file.
_ASF_HEADER_GUID = bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C')

#: OLE2 compound-document signature, shared by legacy .doc/.xls/.ppt.
_OLE_SIGNATURE = bytes.fromhex('D0CF11E0A1B11AE1')


def is_valid_file(data, file_type):
    """Does this buffer actually parse as the format it claims to be?

    A signature match is not evidence: `BM`, `RIFF` and `PK` occur
    constantly in random data, and a carve that merely starts with the right
    bytes is a fragment presented as a file. Every supported type is parsed
    here, because the alternative -- returning True for the types nobody wrote
    a check for -- writes noise to disk and calls it recovered evidence.

    Rejection is the ordinary outcome of scanning free space, not an error, so
    a failure here is logged at debug level.
    """
    kind = file_type.lower()
    if not data or len(data) < CARVE_MIN_SIZE:
        return False

    cap = CARVE_MAX_SIZE.get(kind)
    if cap and len(data) > cap:
        return False

    try:
        if kind == 'pdf':
            with fitz_open(stream=data, filetype='pdf') as doc:
                return doc.page_count >= 1

        if kind in ('jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'):
            # verify() parses the structure without decoding pixel data, so a
            # truncated or spliced image fails here rather than at display.
            image = Image.open(io.BytesIO(data))
            image.verify()
            return True

        if kind == 'wav':
            return _valid_riff(data)

        if kind in ('mov', 'mp4'):
            return _valid_isobmff(data)

        if kind == 'wmv':
            return _valid_asf(data)

        if kind == 'zip':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if not archive.namelist():
                    return False
                # testzip() returns the first member that fails its CRC.
                return archive.testzip() is None

        if kind == 'gz':
            return _valid_gzip(data)

        if kind == 'ole':
            return _valid_ole(data)

        if kind in ('rar', '7z', 'html'):
            # Carved by structure rather than parsed: the carver for each of
            # these establishes its own end, and there is no cheap library
            # check that adds anything beyond what it already proved.
            return True

    except (IOError, OSError, UnidentifiedImageError, ValueError, RuntimeError,
            struct.error, zipfile.BadZipFile, SyntaxError, EOFError,
            IndexError, KeyError) as exc:
        logger.debug("Rejected %s candidate: %s: %s",
                     file_type, type(exc).__name__, exc)
        return False

    # An unknown type has no check, so nothing here can vouch for it. Say so
    # rather than defaulting to True -- that default is what let four formats
    # reach disk unvalidated.
    logger.debug("No validator for type %s; rejecting", file_type)
    return False


def _valid_riff(data):
    """RIFF/WAVE with a length field that agrees with the buffer."""
    if data[:4] != b'RIFF' or data[8:12] != b'WAVE':
        return False
    declared = int.from_bytes(data[4:8], 'little') + 8
    # The buffer may legitimately be longer (trailing slack), never shorter.
    return CARVE_MIN_SIZE <= declared <= len(data)


def _valid_isobmff(data):
    """Walk the atom chain and require it to span the buffer coherently.

    A MOV/MP4 is a sequence of size-prefixed atoms. Random data almost never
    produces a chain that walks cleanly to the end, which makes the walk itself
    the validation.
    """
    seen = set()
    pos = 0
    while pos + 8 <= len(data):
        size = int.from_bytes(data[pos:pos + 4], 'big')
        kind = data[pos + 4:pos + 8]
        if not _ATOM_NAME.match(kind):
            return False
        if size == 0:
            seen.add(kind)          # extends to end of file
            pos = len(data)
            break
        if size == 1:
            if pos + 16 > len(data):
                return False
            size = int.from_bytes(data[pos + 8:pos + 16], 'big')
        if size < 8 or pos + size > len(data):
            return False
        seen.add(kind)
        pos += size

    # A real recording carries its media data and at least one structural atom.
    return bool(seen & {b'mdat', b'moov'}) and bool(seen & _ISOBMFF_ATOMS)


def _valid_asf(data):
    """ASF header GUID plus a declared size that fits the buffer."""
    if data[:16] != _ASF_HEADER_GUID:
        return False
    declared = int.from_bytes(data[16:24], 'little')
    return CARVE_MIN_SIZE <= declared <= len(data)


def _valid_gzip(data):
    """Decompress far enough to prove the stream is real."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        return bool(stream.read(4096))


def _valid_ole(data):
    """OLE compound file: the signature plus a sane sector shift."""
    if data[:8] != _OLE_SIGNATURE:
        return False
    shift = int.from_bytes(data[30:32], 'little')
    # 9 -> 512-byte sectors, 12 -> 4096. Nothing else is defined.
    return shift in (9, 12)


def extract_original_timestamp(file_content, file_type):
    """Recover a timestamp from inside the file itself.

    A carved file has no directory entry, so the filesystem's created, modified
    and deleted times are gone -- they lived in metadata that carving does not
    see. The only date that survives is one the format stored in its own bytes,
    and plenty of formats store none at all.

    Returns:
        ``(datetime, source)`` naming where the value came from, or
        ``(None, "")``. Never invent a value: an unknown timestamp reported as
        the time of recovery is a false statement about the evidence.
    """
    kind = file_type.lower()
    try:
        if kind in ('jpg', 'jpeg', 'png', 'tiff'):
            stamp = _exif_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'pdf':
            stamp = _pdf_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'zip':
            stamp = _zip_timestamp(file_content)
            if stamp:
                return stamp

        elif kind in ('mov', 'mp4'):
            stamp = _mov_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'wmv':
            stamp = _asf_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'gz':
            stamp = _gzip_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'ole':
            stamp = _ole_timestamp(file_content)
            if stamp:
                return stamp

    except Exception as e:
        # Never let a malformed carve stop the scan; a fragment that failed to
        # parse is expected, not exceptional.
        logger.debug("No timestamp recoverable from %s: %s", file_type, e)

    return None, ""


#: EXIF tags holding a capture or edit time, most specific first.
_EXIF_DATE_TAGS = (
    (36867, 'EXIF DateTimeOriginal'),
    (36868, 'EXIF DateTimeDigitized'),
    (306, 'EXIF DateTime'),
)


def _exif_timestamp(file_content):
    """DateTimeOriginal, else DateTimeDigitized, else the file's DateTime."""
    image = Image.open(io.BytesIO(file_content))
    exif = image.getexif()
    if not exif:
        return None

    for tag, label in _EXIF_DATE_TAGS:
        value = exif.get(tag)
        if not value:
            # Sub-IFD holds the Original/Digitized pair on most cameras.
            try:
                value = exif.get_ifd(0x8769).get(tag)
            except Exception:
                value = None
        if value:
            try:
                stamp = datetime.datetime.strptime(str(value).strip(),
                                                   '%Y:%m:%d %H:%M:%S')
                if not _plausible(stamp):
                    continue
                return stamp, label
            except ValueError:
                continue
    return None


def _pdf_timestamp(file_content):
    """The PDF's own CreationDate, else its ModDate."""
    with fitz_open(stream=file_content, filetype='pdf') as doc:
        metadata = doc.metadata or {}
        candidates = (('creationDate', 'PDF CreationDate'),
                      ('modDate', 'PDF ModDate'))
        for key, label in candidates:
            raw = metadata.get(key) or ''
            # "D:YYYYMMDDHHmmSS", optionally with a trailing zone offset.
            if raw.startswith('D:') and len(raw) >= 16:
                try:
                    stamp = datetime.datetime.strptime(raw[2:16], '%Y%m%d%H%M%S')
                except ValueError:
                    continue
                if _plausible(stamp):
                    return stamp, label
    return None


def _zip_timestamp(file_content):
    """The newest member date in the archive's central directory.

    The newest rather than the first: it is the closest thing the archive has
    to when it was written, and entry order carries no meaning.
    """
    with zipfile.ZipFile(io.BytesIO(file_content)) as archive:
        dates = []
        for info in archive.infolist():
            try:
                stamp = datetime.datetime(*info.date_time)
            except (ValueError, TypeError):
                continue
            if _plausible(stamp):
                dates.append(stamp)
        if dates:
            return max(dates), 'ZIP central directory'
    return None


#: QuickTime counts seconds from 1904, not 1970.
_QUICKTIME_EPOCH = datetime.datetime(1904, 1, 1)


def _mov_timestamp(file_content):
    """The creation time in the QuickTime movie header (``mvhd``) atom.

    ``mvhd`` sits inside ``moov`` and holds the times the recording device
    wrote, so it survives carving intact.
    """
    marker = file_content.find(b'mvhd')
    if marker < 0:
        return None

    body = marker + 4
    if body + 20 > len(file_content):
        return None

    version = file_content[body]
    if version == 1:
        created = struct.unpack('>Q', file_content[body + 4:body + 12])[0]
    else:
        created = struct.unpack('>I', file_content[body + 4:body + 8])[0]

    if not created:
        return None
    try:
        stamp = _QUICKTIME_EPOCH + datetime.timedelta(seconds=created)
    except OverflowError:
        return None
    return (stamp, 'QuickTime mvhd') if _plausible(stamp) else None


#: ASF GUID for the Properties object, which carries the creation date.
_ASF_PROPERTIES_GUID = bytes.fromhex('9107DCB7B7A9CF118EE600C00C205365')

#: Windows FILETIME counts 100ns ticks from 1601.
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1)


def _asf_timestamp(file_content):
    """The creation date in the ASF File Properties object of a WMV."""
    marker = file_content.find(_ASF_PROPERTIES_GUID)
    if marker < 0:
        return None

    # GUID (16) + object size (8) + file id (16) + file size (8), then the
    # creation date as a 64-bit FILETIME.
    field = marker + 48
    if field + 8 > len(file_content):
        return None

    ticks = struct.unpack('<Q', file_content[field:field + 8])[0]
    if not ticks:
        return None
    try:
        stamp = _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None
    return (stamp, 'ASF creation date') if _plausible(stamp) else None



def _gzip_timestamp(file_content):
    """The modification time gzip stores in its own header.

    Bytes 4-8 of a gzip member are the original file's mtime as a 32-bit
    little-endian Unix timestamp. Zero means the writer declined to record one.
    """
    if len(file_content) < 8:
        return None
    seconds = int.from_bytes(file_content[4:8], 'little')
    if not seconds:
        return None
    try:
        stamp = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None
    return (stamp, 'GZIP header mtime') if _plausible(stamp) else None


def _ole_timestamp(file_content):
    """The root storage entry's modification time in an OLE document.

    The directory's first entry is the root storage, whose 64-bit FILETIME
    fields carry the document's own timestamps -- the same values Explorer
    shows, and they survive carving because they live inside the file.
    """
    if len(file_content) < 512:
        return None
    try:
        shift = struct.unpack('<H', file_content[30:32])[0]
        first_dir = struct.unpack('<I', file_content[48:52])[0]
    except struct.error:
        return None
    if shift not in (9, 12):
        return None

    sector = 1 << shift
    # Sector numbering starts after the 512-byte header.
    directory = 512 + first_dir * sector
    if directory + 128 > len(file_content):
        return None

    entry = file_content[directory:directory + 128]
    for offset, label in ((108, 'OLE root modified'),
                          (100, 'OLE root created')):
        try:
            ticks = struct.unpack('<Q', entry[offset:offset + 8])[0]
        except struct.error:
            continue
        if not ticks:
            continue
        try:
            stamp = _FILETIME_EPOCH + datetime.timedelta(
                microseconds=ticks // 10)
        except OverflowError:
            continue
        if _plausible(stamp):
            return stamp, label
    return None

def _plausible(stamp):
    """Reject dates a real recording cannot carry.

    Carved bytes are unverified: a field read at the right offset of the wrong
    data yields a number that parses cleanly into the year 1601 or 30000. Such
    a value is worse than no value, because it looks like evidence.
    """
    return datetime.datetime(1990, 1, 1) <= stamp <= datetime.datetime.now()

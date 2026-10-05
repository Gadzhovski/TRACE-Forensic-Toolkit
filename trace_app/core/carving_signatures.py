"""Signature validation and timestamp extraction for carved data.

Pure functions over a bytes buffer -- no widget, no disk access, no state.
They live in core so this logic can be exercised without starting a GUI.
"""

import bz2
import datetime
import email
import email.utils
import gzip
import io
import logging
import lzma
import re
import sqlite3
import struct
import tarfile
import zipfile
import zlib

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

        if kind in ('webp', 'avif'):
            # Pillow parses both; verify() reads the structure, not pixels.
            image = Image.open(io.BytesIO(data))
            image.verify()
            return _valid_isobmff(data) if kind == 'avif' else \
                _valid_riff(data, b'WEBP')

        if kind == 'avi':
            return _valid_avi(data)

        if kind in ('mov', 'mp4', 'm4v', 'm4a', '3gp', 'heic'):
            return _valid_isobmff(data)

        if kind == 'wmv':
            return _valid_asf(data)

        if kind in ZIP_KINDS:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if not archive.namelist():
                    return False
                # testzip() returns the first member that fails its CRC.
                return archive.testzip() is None

        if kind == 'gz':
            return _valid_gzip(data)

        if kind == 'ole':
            return _valid_ole(data)

        validator = _VALIDATORS.get(kind)
        if validator is not None:
            return validator(data)

        if kind == 'html':
            # Carved by structure: the carver establishes its own end from
            # the document's tags, and no library check adds to that.
            return True

    except (IOError, OSError, UnidentifiedImageError, ValueError, RuntimeError,
            struct.error, zipfile.BadZipFile, SyntaxError, EOFError,
            IndexError, KeyError, sqlite3.Error, tarfile.TarError,
            lzma.LZMAError, UnicodeDecodeError) as exc:
        logger.debug("Rejected %s candidate: %s: %s",
                     file_type, type(exc).__name__, exc)
        return False

    # An unknown type has no check, so nothing here can vouch for it. Say so
    # rather than defaulting to True -- that default is what let four formats
    # reach disk unvalidated.
    logger.debug("No validator for type %s; rejecting", file_type)
    return False


def _valid_riff(data, form=b'WAVE'):
    """RIFF of the given form, with a length field that agrees with the
    buffer."""
    if data[:4] != b'RIFF' or data[8:12] != form:
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

        elif kind in ('docx', 'xlsx', 'pptx', 'vsdx', 'odt', 'ods', 'odp',
                      'odg'):
            stamp = _office_timestamp(file_content) or \
                _zip_timestamp(file_content)
            if stamp:
                return stamp

        elif kind in ZIP_KINDS:
            stamp = _zip_timestamp(file_content)
            if stamp:
                return stamp

        elif kind in _TIMESTAMPS:
            stamp = _TIMESTAMPS[kind](file_content)
            if stamp:
                return stamp

        elif kind in ('mov', 'mp4', 'm4v', 'm4a', '3gp'):
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


# --- formats added with the size-from-structure carvers ---------------------

#: Every extension a carved ZIP can be named as (carving_formats.zip_kind).
ZIP_KINDS = frozenset({'zip', 'docx', 'xlsx', 'pptx', 'vsdx', 'odt', 'ods',
                       'odp', 'odg', 'epub', 'apk', 'jar'})


def _remeasure(measure, data, *args):
    """Does the carver's own walk of `data`, alone, land exactly on its end?

    For formats with no library to parse them, the structure walk is the
    check -- run again over the carved bytes alone, it must account for every
    one of them, which random data and a misjudged extent do not.
    """
    from trace_app.core.carving_formats import Source
    result = measure(Source(data, 0), 0, *args)
    return bool(result) and result[0] == len(data)


def _valid_rar(data):
    from trace_app.core.carving_formats import measure_rar
    return _remeasure(measure_rar, data)


def _valid_7z(data):
    from trace_app.core.carving_formats import measure_7z
    return _remeasure(measure_7z, data)


def _valid_avi(data):
    if not _valid_riff(data, b'AVI '):
        return False
    # The first chunk of an AVI is the header list.
    return data[12:16] == b'LIST' and data[20:24] == b'hdrl'


def _valid_sqlite(data):
    from trace_app.core.carving_formats import measure_sqlite
    if not _remeasure(measure_sqlite, data):
        return False
    # Page 1 holds the schema table: a table b-tree page, leaf or interior.
    if data[100] not in (0x0D, 0x05):
        return False
    connection = sqlite3.connect(':memory:')
    try:
        if hasattr(connection, 'deserialize'):          # Python 3.11+
            connection.deserialize(bytes(data))
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    finally:
        connection.close()


def _valid_regf(data):
    from trace_app.core.carving_formats import measure_regf
    if not _remeasure(measure_regf, data):
        return False
    words = struct.unpack_from('<127I', data, 0)
    checksum = 0
    for word in words:
        checksum ^= word
    if checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    elif checksum == 0:
        checksum = 1
    if checksum != struct.unpack_from('<I', data, 0x1FC)[0]:
        return False
    # The root key cell: a negative (allocated) size, then 'nk'.
    root = 4096 + struct.unpack_from('<I', data, 0x24)[0]
    return data[root + 4:root + 6] == b'nk' and \
        struct.unpack_from('<i', data, root)[0] < 0


def _valid_evtx(data):
    from trace_app.core.carving_formats import EVTX_CHUNK, measure_evtx
    if not _remeasure(measure_evtx, data):
        return False
    # Every chunk carries a CRC32 of its header (first 120 bytes, then the
    # 384 bytes from 128); one valid chunk proves the log is real.
    chunk = data[4096:4096 + EVTX_CHUNK]
    header_crc = zlib.crc32(chunk[:120] + chunk[128:512]) & 0xFFFFFFFF
    return header_crc == struct.unpack_from('<I', chunk, 0x7C)[0]


def _ms_pst_crc(data):
    """MS-PST's CRC-32: the standard polynomial, no pre- or post-inversion."""
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _valid_pst(data):
    from trace_app.core.carving_formats import measure_pst
    if not _remeasure(measure_pst, data):
        return False
    return _ms_pst_crc(data[8:8 + 471]) == struct.unpack_from('<I', data, 4)[0]


def _valid_pe(data):
    from trace_app.core.carving_formats import measure_pe
    if not _remeasure(measure_pe, data):
        return False
    lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    headers = struct.unpack_from('<I', data, lfanew + 24 + 60)[0]
    return 0 < headers <= len(data)


def _valid_lnk(data):
    from trace_app.core.carving_formats import measure_lnk
    return _remeasure(measure_lnk, data)


def _valid_mp3(data):
    from trace_app.core.carving_formats import measure_mp3
    return _remeasure(measure_mp3, data)


def _valid_ogg(data):
    from trace_app.core.carving_formats import measure_ogg
    return _remeasure(measure_ogg, data)


def _valid_flv(data):
    from trace_app.core.carving_formats import measure_flv
    return _remeasure(measure_flv, data)


def _valid_mpg(data):
    from trace_app.core.carving_formats import measure_mpg
    if not _remeasure(measure_mpg, data):
        return False
    # A program stream carries video or audio packets, not only packs.
    return re.search(rb'\x00\x00\x01[\xc0-\xef]', data[:1 << 20]) is not None


def _valid_mkv(data):
    from trace_app.core.carving_formats import _ebml_id, _ebml_vint, measure_mkv
    if not _remeasure(measure_mkv, data):
        return False
    # The segment's top-level elements must tile it exactly, and include its
    # Info and Tracks.
    size, width = _ebml_vint(data, 4)
    pos = 4 + width + size
    seg_size, seg_width = _ebml_vint(data, pos + 4)
    pos += 4 + seg_width
    end = pos + seg_size
    seen = set()
    while pos < end:
        element = _ebml_id(data, pos)
        if element is None:
            return False
        length = _ebml_vint(data, pos + element[1])
        if length is None:
            return False
        seen.add(element[0])
        pos += element[1] + length[1] + length[0]
    return pos == end and {b'\x15\x49\xa9\x66', b'\x16\x54\xae\x6b'} <= seen


def _valid_tar(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        return bool(archive.getmembers())


def _valid_bz2(data):
    stream = bz2.BZ2Decompressor()
    stream.decompress(data, max_length=1 << 20)
    return True


def _valid_xz(data):
    stream = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    stream.decompress(data, max_length=1 << 20)
    return True


def _valid_rtf(data):
    from trace_app.core.carving_formats import measure_rtf
    if not data.startswith(b'{\\rtf1'):
        return False
    return _remeasure(measure_rtf, data, len(data) + 1) and \
        (b'\\fonttbl' in data[:1 << 16] or b'\\ansi' in data[:64])


def _valid_elf(data):
    from trace_app.core.carving_formats import measure_elf
    return _remeasure(measure_elf, data)


def _valid_macho(data):
    from trace_app.core.carving_formats import measure_macho
    return _remeasure(measure_macho, data)


def _valid_psd(data):
    from trace_app.core.carving_formats import measure_psd
    if not _remeasure(measure_psd, data):
        return False
    Image.open(io.BytesIO(data)).verify()
    return True


def _valid_tiff_raw(data):
    """A camera raw built on TIFF: no library here decodes them all, so the
    structure is the check -- walked again over the carved bytes alone, it
    must account for every one of them and name the same format."""
    from trace_app.core.carving_formats import Source, measure_tiff_family
    measured = measure_tiff_family(Source(data, 0), 0)
    return bool(measured) and measured[0] == len(data) and \
        measured[1] != 'tiff'


def _valid_raf(data):
    from trace_app.core.carving_formats import measure_raf
    if not _remeasure(measure_raf, data):
        return False
    # Its embedded JPEG preview must be one.
    offset, length = struct.unpack_from('>2I', data, 0x54)
    return data[offset:offset + 3] == b'\xFF\xD8\xFF' and \
        data[offset + length - 2:offset + length] == b'\xFF\xD9'


def _valid_psb(data):
    from trace_app.core.carving_formats import measure_psd
    return _remeasure(measure_psd, data)


def _valid_cr3(data):
    from trace_app.core.carving_formats import isobmff_kind
    return isobmff_kind(data) == 'cr3' and _valid_isobmff(data)


def _valid_eml(data):
    message = email.message_from_bytes(data[:1 << 16])
    return bool(message.get('From') and (message.get('Date')
                                         or message.get('Received')))


def _valid_mbox(data):
    # Every message the extent covers must parse with real mail headers;
    # the first one is required to.
    text = data.decode('utf-8', 'replace')
    first = text.split('\nFrom ', 1)[0]
    message = email.message_from_string(first.split('\n', 1)[1]
                                        if '\n' in first else '')
    return bool(message.get('From') and (message.get('Date')
                                         or message.get('Received')))


def _valid_wal(data):
    # The checksum chain is the whole proof; walked again over the carve
    # alone it must account for every byte.
    from trace_app.core.carving_formats import measure_sqlite_wal
    return _remeasure(measure_sqlite_wal, data)


_VALIDATORS = {
    'sqlite': _valid_sqlite, 'wal': _valid_wal, 'regf': _valid_regf,
    'evtx': _valid_evtx,
    'pst': _valid_pst, 'ost': _valid_pst,
    'exe': _valid_pe, 'dll': _valid_pe, 'sys': _valid_pe,
    'lnk': _valid_lnk, 'mp3': _valid_mp3, 'ogg': _valid_ogg,
    'opus': _valid_ogg, 'flv': _valid_flv, 'mpg': _valid_mpg,
    'mkv': _valid_mkv, 'webm': _valid_mkv, 'tar': _valid_tar,
    'bz2': _valid_bz2, 'xz': _valid_xz, 'rtf': _valid_rtf,
    'elf': _valid_elf, 'macho': _valid_macho, 'psd': _valid_psd,
    'mbox': _valid_mbox, 'eml': _valid_eml,
    'rar': _valid_rar, '7z': _valid_7z,
    'raf': _valid_raf, 'psb': _valid_psb, 'cr3': _valid_cr3,
    **{kind: _valid_tiff_raw for kind in ('cr2', 'nef', 'arw', 'dng', 'pef',
                                          'orf', 'rw2')},
}


# --- dates the new formats carry --------------------------------------------

def _filetime(value):
    if not value:
        return None
    stamp = _FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)
    return stamp if _plausible(stamp) else None


def _regf_timestamp(data):
    stamp = _filetime(struct.unpack_from('<Q', data, 0x0C)[0])
    return (stamp, "Hive last written") if stamp else None


def _evtx_timestamp(data):
    # The first record of the first chunk: signature, size, id, then time.
    record = 4096 + 512
    if data[record:record + 4] != b'**\x00\x00':
        return None
    stamp = _filetime(struct.unpack_from('<Q', data, record + 16)[0])
    return (stamp, "First event in log") if stamp else None


def _pe_timestamp(data):
    lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    seconds = struct.unpack_from('<I', data, lfanew + 8)[0]
    if not seconds:
        return None
    stamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=seconds)
    # Reproducible builds write a hash here, not a time; and any linker
    # value can be set by hand. Say so in the source.
    return (stamp, "PE linker timestamp (can be forged)") \
        if _plausible(stamp) else None


def _lnk_timestamp(data):
    # The target's own times, recorded when the shortcut was made or used:
    # modified first, then created.
    for at, label in ((0x2C, "LNK target modified"),
                      (0x1C, "LNK target created")):
        stamp = _filetime(struct.unpack_from('<Q', data, at)[0])
        if stamp:
            return stamp, label
    return None


_CORE_DATE = re.compile(rb'<dcterms:(modified|created)[^>]*>([^<]+)<')
_ODF_DATE = re.compile(rb'<(meta:creation-date|dc:date)>([^<]+)<')


def _parse_iso(text):
    text = text.strip().rstrip('Z')
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            stamp = datetime.datetime.strptime(text[:26], fmt)
            return stamp if _plausible(stamp) else None
        except ValueError:
            continue
    return None


def _office_timestamp(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = set(archive.namelist())
        if 'docProps/core.xml' in names:
            found = dict((kind, value) for kind, value in
                         _CORE_DATE.findall(archive.read('docProps/core.xml')))
            for kind, label in ((b'modified', "Document modified (core.xml)"),
                                (b'created', "Document created (core.xml)")):
                if kind in found:
                    stamp = _parse_iso(found[kind].decode('ascii', 'replace'))
                    if stamp:
                        return stamp, label
        if 'meta.xml' in names:
            for tag, value in _ODF_DATE.findall(archive.read('meta.xml')):
                stamp = _parse_iso(value.decode('ascii', 'replace'))
                if stamp:
                    label = ("Document created (meta.xml)"
                             if tag == b'meta:creation-date'
                             else "Document modified (meta.xml)")
                    return stamp, label
    return None


_RTF_TIME = re.compile(rb'\\(revtim|creatim)\\yr(\d+)\\mo(\d+)\\dy(\d+)'
                       rb'(?:\\hr(\d+))?(?:\\min(\d+))?')


def _rtf_timestamp(data):
    found = {m.group(1): m for m in _RTF_TIME.finditer(data[:1 << 16])}
    for kind, label in ((b'revtim', "RTF revised"), (b'creatim', "RTF created")):
        match = found.get(kind)
        if match:
            try:
                stamp = datetime.datetime(
                    int(match.group(2)), int(match.group(3)),
                    int(match.group(4)), int(match.group(5) or 0),
                    int(match.group(6) or 0))
            except ValueError:
                continue
            if _plausible(stamp):
                return stamp, label
    return None


def _mbox_timestamp(data):
    head = data[:1 << 16].decode('utf-8', 'replace')
    match = re.search(r'^Date:\s*(.+)$', head, re.M)
    if not match:
        return None
    try:
        stamp = email.utils.parsedate_to_datetime(match.group(1).strip())
    except (TypeError, ValueError):
        return None
    if stamp.tzinfo is not None:
        stamp = stamp.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return (stamp, "Date: of first message") if _plausible(stamp) else None


def _tar_timestamp(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        first = archive.next()
        if first and first.mtime:
            stamp = datetime.datetime(1970, 1, 1) + \
                datetime.timedelta(seconds=first.mtime)
            if _plausible(stamp):
                return stamp, "TAR first member mtime"
    return None


_TIMESTAMPS = {
    'regf': _regf_timestamp, 'evtx': _evtx_timestamp,
    'exe': _pe_timestamp, 'dll': _pe_timestamp, 'sys': _pe_timestamp,
    'lnk': _lnk_timestamp, 'rtf': _rtf_timestamp, 'mbox': _mbox_timestamp,
    'eml': _mbox_timestamp,
    'tar': _tar_timestamp,
}

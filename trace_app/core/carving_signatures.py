"""Signature validation and timestamp extraction for carved data.

Pure functions over a bytes buffer -- no widget, no disk access, no state.
They live in core so this logic can be exercised without starting a GUI.
"""

import datetime
import io
import logging
import struct
import zipfile

from fitz import open as fitz_open
from PIL import Image, UnidentifiedImageError

logger = logging.getLogger('TRACE.Carving')


def is_valid_file(data, file_type):
    try:
        if file_type == 'pdf':
            # Validate by parsing with PyMuPDF; a carved fragment that is
            # not a real PDF raises here.
            with fitz_open(stream=data, filetype='pdf') as doc:
                if doc.page_count < 1:
                    return False
        elif file_type in ['jpg', 'jpeg', 'png', 'gif']:
            # Validate images by attempting to open them with PIL
            image = Image.open(io.BytesIO(data))
            image.verify()  # This will not load the image but only parse it
        elif file_type == 'bmp':
            return True
        elif file_type == 'wav':
            # Basic WAV validation could check for the RIFF header, file size, etc.
            if not data.startswith(b'RIFF') or not b'WAVE' in data[:12]:
                return False
            # Additional WAV format checks could be implemented here
        elif file_type == 'mov':
            return True  # For now, we'll assume all MOV files are valid
        else:
            return True
        return True
    except (IOError, UnidentifiedImageError, ValueError, RuntimeError) as e:
        logger.error(f"Error validating file of type {file_type}: {str(e)}")
        return False


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

        elif kind == 'mov':
            stamp = _mov_timestamp(file_content)
            if stamp:
                return stamp

        elif kind == 'wmv':
            stamp = _asf_timestamp(file_content)
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


def _plausible(stamp):
    """Reject dates a real recording cannot carry.

    Carved bytes are unverified: a field read at the right offset of the wrong
    data yields a number that parses cleanly into the year 1601 or 30000. Such
    a value is worse than no value, because it looks like evidence.
    """
    return datetime.datetime(1990, 1, 1) <= stamp <= datetime.datetime.now()

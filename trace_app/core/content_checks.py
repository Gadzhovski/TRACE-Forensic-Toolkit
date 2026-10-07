"""Cheap checks that say something about a file an extension never will.

Each function takes a name and/or bytes and returns findings or facts; none
reads evidence itself. The analysis walk calls them on what it has already
read, so they add no extra pass over the image, and the File Metadata tab
calls the same functions on the one file on screen -- one implementation, two
places.

* **Deceptive names**: `invoice.pdf.exe`, a right-to-left override that makes
  `gpj.exe` display as `exe.jpg`, an extension pushed out of sight by spaces.
* **Appended data**: bytes after the real end of a JPEG, PNG or PDF. The end
  is found by parsing the format, not by searching for the last end marker --
  every camera JPEG carries a thumbnail with its own end marker inside.
* **Encryption**: password-protected archives, Office documents and PDFs,
  stated from the format rather than guessed from entropy.
* **Photo metadata**: camera, capture time, editing software and GPS position
  from EXIF.
* **Document authorship**: author, last saved by, company, application and
  template from Office, OpenDocument and PDF metadata.

No Qt here.
"""

import io
import json
import logging
import re
import zipfile
from datetime import datetime, timezone
from xml.etree import ElementTree

logger = logging.getLogger('TRACE.ContentChecks')

GRADE_SUSPICIOUS = 'suspicious'
GRADE_NOTABLE = 'notable'
GRADE_BENIGN = 'benign'

#: Findings worth putting in front of an examiner. Benign ones are stored so a
#: filter can ask for them, but a list that opens with every motion photo is a
#: list nobody reads.
REPORTED_GRADES = (GRADE_SUSPICIOUS, GRADE_NOTABLE)

MODULE_HIDDEN = 'hidden'
MODULE_PHOTO = 'photo'
MODULE_AUTHORS = 'authors'
MODULE_EXECUTABLES = 'executables'

#: Largest file read whole for these checks. Photos and documents are well
#: under it; a file above it keeps its name checks and nothing else.
MAX_INSPECT_BYTES = 64 * 1024 * 1024

#: Trailing bytes after a file's end that are padding, not data.
_PADDING = b'\x00\xff \t\r\n'

#: Less than this after the end is noise: alignment, a stray newline.
MIN_APPENDED_BYTES = 64


class Finding:
    """One thing worth saying about one file."""

    __slots__ = ('module', 'kind', 'grade', 'summary', 'detail')

    def __init__(self, module, kind, grade, summary, detail=None):
        self.module = module
        self.kind = kind
        self.grade = grade
        self.summary = summary
        self.detail = detail or {}

    def as_row(self):
        return (self.module, self.kind, self.grade, self.summary,
                json.dumps(self.detail, default=str))

    def __repr__(self):
        return f"Finding({self.module}/{self.kind}, {self.grade}: {self.summary})"


# --- what the bytes are ----------------------------------------------------------

def family(head):
    """A coarse format from the first bytes: the checks below key on this."""
    if head.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if head.startswith(b'%PDF-'):
        return 'pdf'
    if head.startswith(b'PK\x03\x04'):
        return 'zip'
    if head.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        return 'ole'
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return '7z'
    if head.startswith((b'II*\x00', b'MM\x00*')):
        return 'tiff'
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'webp'
    if head[4:12] in (b'ftypheic', b'ftypheix', b'ftypmif1', b'ftypavif',
                      b'ftypavis'):
        return 'heif'
    from trace_app.core.executables import kind_of
    if kind_of(head):
        return 'executable'
    return ''


#: Families any of the content checks want the whole file for.
NEEDS_FULL = {'jpeg', 'png', 'pdf', 'zip', 'ole', '7z', 'tiff', 'webp', 'heif',
              'executable'}


def wants_full_read(head, modules):
    """Whether these modules have anything to check in a file like this."""
    fam = family(head)
    if not fam:
        return False
    wanted = set()
    if MODULE_HIDDEN in modules:
        wanted |= {'jpeg', 'png', 'pdf', 'zip', 'ole', '7z'}
    if MODULE_PHOTO in modules:
        wanted |= {'jpeg', 'tiff', 'webp', 'heif', 'png'}
    if MODULE_AUTHORS in modules:
        wanted |= {'pdf', 'zip', 'ole'}
    if MODULE_EXECUTABLES in modules:
        wanted.add('executable')
    return fam in wanted


def inspect(name, data, modules, size=None):
    """Every finding the selected modules make about one file.

    `data` is the whole file, or just its head when it was too large or of no
    interest to read whole -- the checks that need the whole of it return
    nothing rather than guessing from part.
    """
    findings = []
    if MODULE_HIDDEN in modules:
        findings += deceptive_name(name)
        if data:
            findings += appended_data(data)
            findings += encryption(data)
    if MODULE_PHOTO in modules and data:
        facts = photo_metadata(data)
        if facts:
            findings.append(_photo_finding(facts))
    if MODULE_AUTHORS in modules and data:
        facts = document_authors(data)
        if facts:
            findings.append(Finding(
                MODULE_AUTHORS, 'document', GRADE_BENIGN,
                _authors_summary(facts), facts))
    if MODULE_EXECUTABLES in modules and data:
        finding = executable_finding(name, data)
        if finding is not None:
            findings.append(finding)
    return findings


# --- executables ---------------------------------------------------------------------

def executable_finding(name, data):
    """One finding per PE / ELF / Mach-O file (core/executables.py),
    graded by its worst indicator; what is stored is a digest of the
    analysis -- the File Metadata tab reads the whole of it again."""
    from trace_app.core import executables
    facts = executables.analyse(data)
    if facts is None:
        return None
    flags = executables.indicators(facts, name)
    grades = {grade for grade, _text in flags}
    grade = (GRADE_SUSPICIOUS if GRADE_SUSPICIOUS in grades else
             GRADE_NOTABLE if GRADE_NOTABLE in grades else GRADE_BENIGN)
    summary = executables.summary(facts)
    if flags:
        summary += '. ' + '; '.join(text for _grade, text in flags)
    return Finding(MODULE_EXECUTABLES, 'executable', grade, summary,
                   executables.digest(facts, flags))


# --- deceptive names ----------------------------------------------------------------

#: Extensions that run when opened.
_EXECUTABLE_EXT = {
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe',
    'wsf', 'wsh', 'hta', 'lnk', 'ps1', 'msi', 'jar', 'cpl', 'reg', 'dll',
    'application', 'gadget', 'msc', 'scf', 'inf',
}

#: Extensions a person expects to be a harmless document or picture.
_LURE_EXT = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'jpg',
    'jpeg', 'png', 'gif', 'bmp', 'mp3', 'mp4', 'avi', 'mov', 'zip', 'rar',
    'csv', 'odt', 'html', 'htm',
}

#: Unicode controls that change display order. In a file name their only use
#: is to make the end of the name show somewhere else.
_BIDI = re.compile('[‪-‮⁦-⁩‎‏؜]')


def deceptive_name(name):
    findings = []
    if not name:
        return findings

    controls = _BIDI.findall(name)
    if controls:
        shown = _BIDI.sub('', name)
        codes = ', '.join(f"U+{ord(c):04X}" for c in sorted(set(controls)))
        findings.append(Finding(
            MODULE_HIDDEN, 'bidi-name', GRADE_SUSPICIOUS,
            f"Name contains text-direction controls ({codes}) that reorder "
            f"how it displays — the real name is {shown!r}.",
            {'controls': codes, 'real_name': shown}))

    parts = name.lower().split('.')
    if len(parts) >= 3:
        last, before = parts[-1].strip(), parts[-2].strip()
        if last in _EXECUTABLE_EXT and before in _LURE_EXT:
            findings.append(Finding(
                MODULE_HIDDEN, 'double-extension', GRADE_SUSPICIOUS,
                f"Double extension: looks like a .{before} but runs as "
                f".{last}.", {'shown_as': before, 'runs_as': last}))

    padded = re.search(r'\s{5,}\.(\w+)$', name)
    if padded:
        findings.append(Finding(
            MODULE_HIDDEN, 'padded-name', GRADE_SUSPICIOUS
            if padded.group(1).lower() in _EXECUTABLE_EXT else GRADE_NOTABLE,
            f"The real extension .{padded.group(1)} is pushed out of view by "
            f"{len(padded.group(0)) - len(padded.group(1)) - 1} spaces.",
            {'extension': padded.group(1)}))
    return findings


# --- appended data ----------------------------------------------------------------------

def _jpeg_end(data):
    """Offset just past a JPEG's real end-of-image marker, or None.

    Walks the segments -- each carries its length, so an EXIF thumbnail's
    own markers are skipped over -- then scans the entropy-coded data after
    each start-of-scan for the next real marker.
    """
    n = len(data)
    if not data.startswith(b'\xff\xd8'):
        return None
    i = 2
    while i < n - 1:
        if data[i] != 0xFF:
            return None
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            return None
        marker = data[i]
        i += 1
        if marker == 0xD9:
            return i
        if 0xD0 <= marker <= 0xD7 or marker in (0x01, 0xD8):
            continue
        if i + 2 > n:
            return None
        length = int.from_bytes(data[i:i + 2], 'big')
        if length < 2:
            return None
        i += length
        if marker == 0xDA:
            # Entropy-coded data: 0xFF is followed by 0x00 (a stuffed byte)
            # or a restart marker inside it; anything else ends the scan.
            while True:
                j = data.find(b'\xff', i)
                if j < 0 or j + 1 >= n:
                    return None
                following = data[j + 1]
                if following == 0x00 or 0xD0 <= following <= 0xD7 \
                        or following == 0xFF:
                    i = j + (1 if following == 0xFF else 2)
                    continue
                i = j
                break
    return None


def _png_end(data):
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return None
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = int.from_bytes(data[i:i + 4], 'big')
        kind = data[i + 4:i + 8]
        i += 12 + length
        if kind == b'IEND':
            return i if i <= n else None
    return None


def _pdf_end(data):
    index = data.rfind(b'%%EOF')
    return index + 5 if index >= 0 else None


def _what_is(blob):
    """A short name for appended bytes, if their first bytes say what."""
    head = blob[:16]
    if head.startswith(b'PK\x03\x04'):
        return 'ZIP archive', GRADE_SUSPICIOUS
    if head.startswith(b'Rar!'):
        return 'RAR archive', GRADE_SUSPICIOUS
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return '7z archive', GRADE_SUSPICIOUS
    if head.startswith(b'MZ'):
        return 'Windows executable', GRADE_SUSPICIOUS
    if head.startswith(b'\x7fELF'):
        return 'Linux executable', GRADE_SUSPICIOUS
    if head.startswith(b'%PDF'):
        return 'PDF document', GRADE_NOTABLE
    if head.startswith(b'\xff\xd8\xff'):
        return 'JPEG image', GRADE_NOTABLE
    if head.startswith(b'\x89PNG'):
        return 'PNG image', GRADE_NOTABLE
    if blob[4:8] == b'ftyp':
        # Google and Samsung "motion photos" append the clip to the JPEG.
        return 'MP4 video (a motion photo)', GRADE_BENIGN
    return '', GRADE_NOTABLE


def appended_data(data):
    fam = family(data[:16])
    end = {'jpeg': _jpeg_end, 'png': _png_end, 'pdf': _pdf_end}.get(fam)
    if end is None:
        return []
    offset = end(data)
    if offset is None or offset >= len(data):
        return []
    trailing = data[offset:]
    if len(trailing.strip(_PADDING)) < MIN_APPENDED_BYTES:
        return []

    # Identified as found first: an MP4 box starts with its length, often
    # 00 00 00 xx, which stripping the padding would eat.
    label, grade = _what_is(trailing)
    if not label:
        label, grade = _what_is(trailing.lstrip(_PADDING))
    if b'SEFT' in trailing[-64:] and fam == 'jpeg':
        # Samsung's camera writes its own trailer (SEFH/SEFT) after the image.
        label, grade = label or 'Samsung camera trailer', GRADE_BENIGN
    what = label or 'unidentified data'
    fmt = fam.upper()
    return [Finding(
        MODULE_HIDDEN, 'appended-data', grade,
        f"{_size(len(trailing))} of {what} after the end of the {fmt} "
        f"(from offset {offset:#x}).",
        {'offset': offset, 'length': len(trailing), 'content': what,
         'format': fmt})]


# --- encryption -------------------------------------------------------------------------

def encryption(data):
    fam = family(data[:16])
    try:
        if fam in ('zip', '7z'):
            return _archive_encryption(data)
        if fam == 'ole':
            return _ole_encryption(data)
        if fam == 'pdf':
            return _pdf_encryption(data)
    except Exception as exc:
        logger.debug("Encryption check failed: %s", exc)
    return []


def _archive_encryption(data):
    from trace_app.core import archives
    try:
        members = archives.list_members(data)
    except archives.EncryptedArchive:
        return [Finding(MODULE_HIDDEN, 'encrypted', GRADE_NOTABLE,
                        "Encrypted archive: even the file names inside need "
                        "a password.", {'scope': 'headers'})]
    except Exception:
        # An OOXML document is a ZIP too; not being an archive TRACE can list
        # is not a finding.
        return []
    locked = [m for m in members if m.get('encrypted')]
    if not locked:
        return []
    return [Finding(
        MODULE_HIDDEN, 'encrypted', GRADE_NOTABLE,
        f"Password-protected archive: {len(locked)} of {len(members)} "
        f"member{'s' if len(members) != 1 else ''} encrypted.",
        {'encrypted': len(locked), 'members': len(members),
         'names': [m.get('name') for m in locked[:20]]})]


def _ole_encryption(data):
    # An encrypted DOCX/XLSX/PPTX is not a ZIP at all: it is an OLE file
    # holding the encrypted package. The stream names are in the directory,
    # stored as UTF-16.
    if 'EncryptedPackage'.encode('utf-16-le') in data:
        return [Finding(MODULE_HIDDEN, 'encrypted', GRADE_NOTABLE,
                        "Password-protected Office document (the content is "
                        "an encrypted package).", {'scope': 'ooxml'})]
    try:
        import olefile
    except ImportError:
        return []
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        if ole.exists('WordDocument'):
            fib = ole.openstream('WordDocument').read(12)
            # FIB flags at offset 0x0A; bit 0x0100 is fEncrypted.
            if len(fib) >= 12 and int.from_bytes(fib[10:12], 'little') & 0x0100:
                return [Finding(MODULE_HIDDEN, 'encrypted', GRADE_NOTABLE,
                                "Password-protected Word 97–2003 document.",
                                {'scope': 'word97'})]
    return []


def _pdf_encryption(data):
    if b'/Encrypt' not in data:
        return []
    from pymupdf import open as fitz_open
    with fitz_open(stream=data, filetype='pdf') as document:
        if document.needs_pass:
            return [Finding(MODULE_HIDDEN, 'encrypted', GRADE_NOTABLE,
                            "Password-protected PDF: it needs a password to "
                            "open.", {'scope': 'user-password'})]
        if document.is_encrypted or document.metadata.get('encryption'):
            return [Finding(MODULE_HIDDEN, 'encrypted', GRADE_BENIGN,
                            "Encrypted PDF that opens without a password; an "
                            "owner password restricts printing or copying.",
                            {'scope': 'owner-password'})]
    return []


def possible_encrypted_volume(mime, entropy, size):
    """A file that is random throughout, sector-aligned and has no header.

    What a VeraCrypt or TrueCrypt container looks like from outside: they
    have no signature by design. Needs both the type and the entropy.
    """
    if (mime in ('application/octet-stream', 'data') and entropy is not None
            and entropy >= 7.99 and size and size >= 1024 * 1024
            and size % 512 == 0):
        return Finding(
            MODULE_HIDDEN, 'encrypted-volume', GRADE_NOTABLE,
            f"Possible encrypted volume: {_size(size)}, random throughout "
            f"(entropy {entropy:.3f}), a whole number of 512-byte sectors, "
            f"and no identifiable header — what a VeraCrypt or TrueCrypt "
            f"container looks like.", {'entropy': entropy, 'size': size})
    return None


# --- photos ------------------------------------------------------------------------------

def _rational(value):
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            numerator, denominator = value
            return numerator / denominator if denominator else None
        except Exception:
            return None


def _degrees(dms, ref):
    try:
        d, m, s = (_rational(x) for x in dms)
    except (TypeError, ValueError):
        return None
    if None in (d, m, s):
        return None
    value = d + m / 60 + s / 3600
    if ref in ('S', 'W', b'S', b'W'):
        value = -value
    return round(value, 6)


def _text(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    return (value or '').strip('\x00 ').strip() if isinstance(value, str) \
        else ('' if value is None else str(value))


def photo_metadata(data):
    """Camera, capture time, software and GPS position, or {} if none."""
    try:
        from PIL import Image
    except ImportError:
        return {}
    try:
        with Image.open(io.BytesIO(data)) as image:
            exif = image.getexif()
    except Exception:
        return {}
    if not exif:
        return {}

    facts = {}
    for tag, key in ((0x010F, 'make'), (0x0110, 'model'),
                     (0x0131, 'software'), (0x0132, 'modified'),
                     (0x013B, 'artist'), (0x8298, 'copyright')):
        value = _text(exif.get(tag))
        if value:
            facts[key] = value
    try:
        detail = exif.get_ifd(0x8769)
    except Exception:
        detail = {}
    for tag, key in ((0x9003, 'taken'), (0x9004, 'digitized'),
                     (0xA434, 'lens'), (0xA420, 'unique_id'),
                     (0xA431, 'serial')):
        value = _text(detail.get(tag))
        if value:
            facts[key] = value

    try:
        gps = exif.get_ifd(0x8825)
    except Exception:
        gps = {}
    if gps:
        lat = _degrees(gps.get(2), _text(gps.get(1)))
        lon = _degrees(gps.get(4), _text(gps.get(3)))
        # 0,0 is the default a broken GPS writes, not a place anyone was.
        if lat is not None and lon is not None and -90 <= lat <= 90 \
                and -180 <= lon <= 180 and (lat, lon) != (0.0, 0.0):
            facts['latitude'] = lat
            facts['longitude'] = lon
            altitude = _rational(gps.get(6))
            if altitude is not None:
                if gps.get(5) in (1, b'\x01'):
                    altitude = -altitude
                facts['altitude'] = round(altitude, 1)
            stamp = _text(gps.get(29))
            if stamp:
                facts['gps_date'] = stamp
    return facts


def _photo_finding(facts):
    camera = ' '.join(p for p in (facts.get('make'), facts.get('model')) if p)
    if 'latitude' in facts:
        where = f"{facts['latitude']:.5f}, {facts['longitude']:.5f}"
        summary = f"Taken at {where}" + (f" with {camera}" if camera else '')
        grade = GRADE_NOTABLE
    elif camera:
        summary = f"Taken with {camera}"
        grade = GRADE_BENIGN
    else:
        # No camera named: say what the EXIF does record, rather than a
        # label that tells the examiner nothing.
        recorded = [f"edited with {facts['software']}"
                    if facts.get('software') else '',
                    f"by {facts['artist']}" if facts.get('artist') else '',
                    f"modified {facts['modified']}"
                    if facts.get('modified') and not facts.get('taken')
                    else '']
        summary = ("EXIF " + ', '.join(r for r in recorded if r)
                   if any(recorded) else "EXIF without camera details")
        grade = GRADE_BENIGN
    if facts.get('taken'):
        summary += f" on {facts['taken']}"
    return Finding(MODULE_PHOTO, 'exif', grade, summary + '.', facts)


# --- authorship ----------------------------------------------------------------------------

_DC = '{http://purl.org/dc/elements/1.1/}'
_CP = '{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}'
_DCT = '{http://purl.org/dc/terms/}'
_EP = '{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}'
_META = '{urn:oasis:names:tc:opendocument:xmlns:meta:1.0}'


def document_authors(data):
    """Who made a document and with what, or {} if it does not say."""
    fam = family(data[:16])
    try:
        if fam == 'zip':
            facts = _package_authors(data)
        elif fam == 'pdf':
            facts = _pdf_authors(data)
        elif fam == 'ole':
            facts = _ole_authors(data)
        else:
            return {}
    except Exception as exc:
        logger.debug("No authorship from document: %s", exc)
        return {}
    return {k: v for k, v in facts.items() if v not in (None, '', 0)}


def _xml_text(root, path):
    node = root.find(path) if root is not None else None
    return (node.text or '').strip() if node is not None else ''


def _package_authors(data):
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        names = set(package.namelist())

        def parse(name):
            if name not in names or package.getinfo(name).file_size > 4 << 20:
                return None
            try:
                return ElementTree.fromstring(package.read(name))
            except ElementTree.ParseError:
                return None

        if 'docProps/core.xml' in names:
            core = parse('docProps/core.xml')
            app = parse('docProps/app.xml')
            return {
                'author': _xml_text(core, f'{_DC}creator'),
                'last_saved_by': _xml_text(core, f'{_CP}lastModifiedBy'),
                'created': _iso_date(_xml_text(core, f'{_DCT}created')),
                'modified': _iso_date(_xml_text(core, f'{_DCT}modified')),
                'last_printed': _iso_date(
                    _xml_text(core, f'{_CP}lastPrinted')),
                'title': _xml_text(core, f'{_DC}title'),
                'revision': _xml_text(core, f'{_CP}revision'),
                'company': _xml_text(app, f'{_EP}Company'),
                'application': ' '.join(p for p in (
                    _xml_text(app, f'{_EP}Application'),
                    _xml_text(app, f'{_EP}AppVersion')) if p),
                'template': _xml_text(app, f'{_EP}Template'),
                'editing_minutes': _xml_text(app, f'{_EP}TotalTime'),
            }
        if 'meta.xml' in names:
            meta = parse('meta.xml')
            office = meta.find(
                '{urn:oasis:names:tc:opendocument:xmlns:office:1.0}meta') \
                if meta is not None else None
            return {
                'author': _xml_text(office, f'{_META}initial-creator'),
                'last_saved_by': _xml_text(office, f'{_DC}creator'),
                'created': _iso_date(
                    _xml_text(office, f'{_META}creation-date')),
                'modified': _iso_date(_xml_text(office, f'{_DC}date')),
                'title': _xml_text(office, f'{_DC}title'),
                'application': _xml_text(office, f'{_META}generator'),
            }
    return {}


def _pdf_date(value):
    """"D:20240115093000+01'00'" -> "2024-01-15 09:30:00 +01:00".

    The zone is kept. A document's times are only comparable with another's
    -- or with the filesystem's -- when it is known which zone each is in;
    dropping it made 09:30 in Paris look like 09:30 UTC.
    """
    match = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
                     r"(Z|[+-]\d{2}'?\d{2}'?)?", value or '')
    if not match:
        return value or ''
    year, month, day, hour, minute, second, zone = match.groups()
    text = (f"{year}-{month or '01'}-{day or '01'} "
            f"{hour or '00'}:{minute or '00'}:{second or '00'}")
    return text + _zone(zone)


def _zone(zone):
    """A trailing zone in one form: ' UTC', ' +01:00', or '' if unstated."""
    if not zone:
        return ''
    if zone in ('Z', 'z'):
        return ' UTC'
    digits = zone.replace("'", '').replace(':', '')
    return f" {digits[:3]}:{digits[3:5] or '00'}"


def _iso_date(value):
    """'2023-02-19T10:29:00Z' -> '2023-02-19 10:29:00 UTC'; a date with no
    zone (OpenDocument writes local time) is left without one."""
    match = re.match(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})'
                     r'(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?', value or '')
    if not match:
        return value or ''
    return f"{match.group(1)} {match.group(2)}" + _zone(match.group(3))


def _pdf_authors(data):
    from pymupdf import open as fitz_open
    with fitz_open(stream=data, filetype='pdf') as document:
        meta = document.metadata or {}
    return {
        'author': meta.get('author', ''),
        'title': meta.get('title', ''),
        'application': meta.get('creator', ''),
        'producer': meta.get('producer', ''),
        'created': _pdf_date(meta.get('creationDate', '')),
        'modified': _pdf_date(meta.get('modDate', '')),
    }


def _ole_authors(data):
    try:
        import olefile
    except ImportError:
        return {}
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        meta = ole.get_metadata()

    def text(value):
        return _text(value) if value is not None else ''

    def when(value):
        if isinstance(value, datetime):
            # OLE property times are FILETIMEs: UTC by definition.
            return value.replace(tzinfo=timezone.utc).strftime(
                '%Y-%m-%d %H:%M:%S UTC')
        return ''

    return {
        'author': text(meta.author),
        'last_saved_by': text(meta.last_saved_by),
        'company': text(meta.company),
        'title': text(meta.title),
        'application': text(meta.creating_application),
        'template': text(meta.template),
        'created': when(meta.create_time),
        'modified': when(meta.last_saved_time),
        'last_printed': when(meta.last_printed),
        'revision': text(meta.revision_number),
    }


def _authors_summary(facts):
    who = facts.get('author') or facts.get('last_saved_by')
    tool = facts.get('application') or facts.get('producer')
    if not who:
        return (f"No author recorded; made with {tool}" if tool
                else "No author recorded")
    summary = f"Author: {who}"
    if facts.get('last_saved_by') and facts['last_saved_by'] != who:
        summary += f"; last saved by {facts['last_saved_by']}"
    if facts.get('company'):
        summary += f" ({facts['company']})"
    return summary


def _size(count):
    for unit in ('bytes', 'KB', 'MB', 'GB'):
        if count < 1024 or unit == 'GB':
            return f"{count:,} {unit}" if unit == 'bytes' else \
                f"{count:.1f} {unit}"
        count /= 1024
    return f"{count} bytes"

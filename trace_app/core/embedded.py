"""Files inside documents: what a PDF, an Office or RTF document or a
photo carries besides its own text (no Qt).

An examiner reading a document sees its words; the pictures pasted into
it, the spreadsheet embedded in it, the file packed into it as an icon
(an Ole10Native "Package" -- a favourite way to slip an executable into a
Word document), a PDF's attachments, and a photo's EXIF thumbnail (which
can show the picture before it was edited or cropped) are files of their
own. Here they are listed and read, in memory, as members named under
`[embedded]/`, so everything that reads archive members -- the index,
search previews, the Listing -- reads them unchanged:

* PDF: every image XObject (as stored: JPEG stays JPEG) and every
  attached file (PyMuPDF);
* OLE compound files (.doc, .xls, .ppt, and OOXML's embeddings/*.bin):
  `\\x01Ole10Native` packages unwrapped to the original file and name,
  `Package` streams (an Office document embedded whole), `CONTENTS`
  (a PDF embedded by Acrobat) -- olefile;
* OOXML (.docx/.xlsx/.pptx) and ODF: their media and embedded objects,
  OLE ones unwrapped;
* RTF: each `\\objdata` object (OLE 1.0 header, then the object -- a
  packaged file unwrapped);
* JPEG and TIFF: the EXIF thumbnail (IFD1).

Nothing is written to disk, and `archives.MAX_MEMBER_BYTES` bounds what is
read.
"""

import io
import logging
import posixpath
import re
import struct
import zipfile

logger = logging.getLogger('TRACE.Embedded')

PREFIX = '[embedded]/'
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
#: Names whose embedded files the Listing offers to show.
DOCUMENT_SUFFIXES = ('.pdf', '.doc', '.dot', '.xls', '.xlt', '.ppt', '.pps',
                     '.rtf', '.docx', '.docm', '.dotx', '.xlsx', '.xlsm',
                     '.pptx', '.pptm', '.ppsx', '.odt', '.ods', '.odp',
                     '.jpg', '.jpeg', '.jpe', '.tif', '.tiff')


class EmbeddedView(bytes):
    """A document's bytes, to be browsed for its embedded files
    (archives.detect_archive says 'embedded' for one)."""


def kind_of(data):
    """'pdf', 'ole', 'rtf', 'office' (OOXML/ODF), 'exif' -- or None."""
    if not data or len(data) < 8:
        return None
    head = bytes(data[:1024])
    if head.startswith(OLE_MAGIC):
        return 'ole'
    if head.lstrip()[:5] == b'{\\rtf':
        return 'rtf'
    if b'%PDF-' in head:
        return 'pdf'
    if head.startswith(b'PK\x03\x04') and _office_zip(data):
        return 'office'
    if head.startswith(b'\xff\xd8') or head[:4] in (b'II*\x00', b'MM\x00*'):
        return 'exif'
    return None


def _office_zip(data):
    try:
        names = zipfile.ZipFile(io.BytesIO(bytes(data))).namelist()
    except (zipfile.BadZipFile, ValueError):
        return False
    return '[Content_Types].xml' in names or 'mimetype' in names


def _member(name, data):
    return {'name': PREFIX + name, 'size': len(data),
            'compressed_size': len(data), 'is_dir': False,
            'encrypted': False, 'modified': None}


def _unique(found, name, data):
    """Add (name, data), a repeated name getting ' (2)', ' (3)'..."""
    taken = {n for n, _d in found}
    stem, dot, extension = name.rpartition('.')
    unique, number = name, 1
    while unique in taken:
        number += 1
        unique = f"{stem} ({number}).{extension}" if dot else \
            f"{name} ({number})"
    found.append((unique, data))


def objects(data, pictures=True):
    """[(name, bytes)] of everything `data` embeds, in document order.
    `pictures` False leaves out a PDF's images: they hold no text, and
    the index has no use for them (the Listing shows them)."""
    kind = kind_of(data)
    readers = {'pdf': lambda raw: _pdf(raw, pictures),
               'ole': lambda raw: _ole(raw, pictures),
               'rtf': _rtf, 'office': _office, 'exif': _exif}
    if kind is None:
        return []
    found = []
    try:
        for name, content in readers[kind](bytes(data)):
            if content:
                _unique(found, _safe(name), content)
    except Exception as exc:              # a damaged document: what was read
        logger.debug("Embedded objects of a %s not all read: %s", kind, exc)
    return found


def _safe(name):
    name = (name or 'object').replace('\\', '/').rsplit('/', 1)[-1]
    name = re.sub(r'[\x00-\x1f]', '', name).strip() or 'object'
    return name


def list_members(data):
    return [_member(name, content) for name, content in objects(data)]


def iter_members(data, pictures=True):
    for name, content in objects(data, pictures):
        yield _member(name, content), content


def read_member(data, member_name):
    want = member_name[len(PREFIX):] if member_name.startswith(PREFIX) \
        else member_name
    for name, content in objects(data):
        if name == want:
            return content
    from trace_app.core.archives import ArchiveError
    raise ArchiveError(f"No embedded file {member_name}")


# --- PDF -------------------------------------------------------------------------

def _pdf(data, pictures=True):
    import pymupdf
    document = pymupdf.open(stream=data, filetype='pdf')
    try:
        if document.needs_pass:
            return []
        out = []
        for index in range(document.embfile_count()):
            info = document.embfile_info(index)
            out.append((info.get('filename') or info.get('name') or
                        f"attachment{index + 1}", document.embfile_get(index)))
        seen = set()
        for number, page in enumerate(document if pictures else (),
                                      start=1):
            for image in page.get_images(full=True):
                xref = image[0]
                if xref in seen:
                    continue
                seen.add(xref)
                extracted = document.extract_image(xref)
                if extracted and extracted.get('image'):
                    out.append((f"page{number}-image{xref}."
                                f"{extracted.get('ext') or 'bin'}",
                                extracted['image']))
        return out
    finally:
        document.close()


# --- OLE ---------------------------------------------------------------------------

def _ole(data, pictures=True):
    """Packaged files (Ole10Native, Package, CONTENTS) and, with
    `pictures`, the pictures a Word, Excel or PowerPoint 97-2003 document
    keeps (core/officeart)."""
    import olefile
    out = []
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        if pictures:
            from trace_app.core import officeart
            out += officeart.pictures_in_ole(ole)
        for path in ole.listdir(streams=True, storages=False):
            leaf = path[-1]
            if leaf == '\x01Ole10Native':
                packaged = ole10native(ole.openstream(path).read())
                if packaged:
                    out.append(packaged)
            elif leaf in ('Package', 'CONTENTS'):
                content = ole.openstream(path).read()
                out.append((f"{'-'.join(path[:-1]) or 'object'}-"
                            f"{leaf.lower()}{_extension(content)}", content))
    return out


def ole10native(stream):
    """(file name, bytes) of a packaged file (the Packager's format: size,
    flags, label, source path, temp path, data)."""
    try:
        position = 4 + 2              # total size, flags
        label, position = _cstring(stream, position)
        source, position = _cstring(stream, position)
        position += 4                 # reserved
        length = struct.unpack_from('<I', stream, position)[0]
        position += 4
        temp, position = _cstring(stream, position, length)
        size = struct.unpack_from('<I', stream, position)[0]
        position += 4
        content = stream[position:position + size]
    except (struct.error, ValueError):
        return None
    if len(content) != size:
        return None
    name = posixpath.basename((temp or source or label).replace('\\', '/'))
    return (name or label or 'package', content)


def _cstring(data, position, length=None):
    if length is not None:
        raw = data[position:position + length]
        return raw.split(b'\0', 1)[0].decode('latin-1'), position + length
    end = data.index(b'\0', position)
    return data[position:end].decode('latin-1'), end + 1


def _extension(content):
    if content.startswith(b'%PDF'):
        return '.pdf'
    if content.startswith(OLE_MAGIC):
        return '.ole'
    if content.startswith(b'PK\x03\x04'):
        return '.zip'
    return '.bin'


# --- OOXML and ODF ------------------------------------------------------------------

def _office(data):
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            name = info.filename
            lowered = name.lower()
            if info.is_dir() or not (
                    '/media/' in lowered or '/embeddings/' in lowered or
                    lowered.startswith('pictures/') or
                    lowered.startswith('object ')):
                continue
            from trace_app.core import archives
            if info.file_size > archives.MAX_MEMBER_BYTES:
                continue
            content = archive.read(info)
            if content.startswith(OLE_MAGIC):
                # An OLE object: the file packed in it, where there is one.
                inner = _ole(content, pictures=False)
                if inner:
                    out += inner
                    continue
            out.append((posixpath.basename(name), content))
    return out


# --- RTF -----------------------------------------------------------------------------

_OBJDATA = re.compile(rb'\\objdata\b\s*([0-9a-fA-F\s]+)')


def _rtf(data):
    out = []
    for number, match in enumerate(_OBJDATA.finditer(data), start=1):
        hexed = re.sub(rb'\s+', b'', match.group(1))
        try:
            raw = bytes.fromhex(hexed[:len(hexed) // 2 * 2].decode('ascii'))
        except ValueError:
            continue
        found = _ole1(raw)
        if found is None:
            continue
        class_name, native = found
        if class_name.lower() == 'package':
            # The Packager's data without its leading size.
            packaged = ole10native(struct.pack('<I', len(native)) + native)
            if packaged:
                out.append(packaged)
                continue
        if native.startswith(OLE_MAGIC):
            inner = _ole(native, pictures=False)
            if inner:
                out += inner
                continue
        out.append((f"object{number}-{class_name or 'object'}"
                    f"{_extension(native)}", native))
    return out


def _ole1(raw):
    """(class name, native data) of an OLE 1.0 embedded object."""
    try:
        _version, form = struct.unpack_from('<II', raw, 0)
        if form != 2:                         # 2: embedded
            return None
        position = 8
        length = struct.unpack_from('<I', raw, position)[0]
        class_name = raw[position + 4:position + 4 + length].split(
            b'\0', 1)[0].decode('latin-1')
        position += 4 + length
        for _field in range(2):               # topic, item
            length = struct.unpack_from('<I', raw, position)[0]
            position += 4 + length
        size = struct.unpack_from('<I', raw, position)[0]
        native = raw[position + 4:position + 4 + size]
    except (struct.error, ValueError):
        return None
    return (class_name, native) if len(native) == size else None


# --- EXIF thumbnails -------------------------------------------------------------------

def _exif(data):
    if data.startswith(b'\xff\xd8'):
        tiff = _jpeg_exif(data)
    else:
        tiff = data
    if not tiff:
        return []
    thumbnail = exif_thumbnail(tiff)
    return [('exif-thumbnail.jpg', thumbnail)] if thumbnail else []


def _jpeg_exif(data):
    position = 2
    while position + 4 <= len(data) and data[position] == 0xFF:
        marker = data[position + 1]
        if marker in (0xD9, 0xDA):
            break
        length = struct.unpack_from('>H', data, position + 2)[0]
        segment = data[position + 4:position + 2 + length]
        if marker == 0xE1 and segment.startswith(b'Exif\0\0'):
            return segment[6:]
        position += 2 + length
    return None


def exif_thumbnail(tiff):
    """The JPEG thumbnail IFD1 points at, or None."""
    if tiff[:2] == b'II':
        endian = '<'
    elif tiff[:2] == b'MM':
        endian = '>'
    else:
        return None
    try:
        first = struct.unpack_from(endian + 'I', tiff, 4)[0]
        count = struct.unpack_from(endian + 'H', tiff, first)[0]
        second = struct.unpack_from(endian + 'I', tiff,
                                    first + 2 + 12 * count)[0]
        if not second:
            return None
        count = struct.unpack_from(endian + 'H', tiff, second)[0]
        fields = {}
        for index in range(count):
            tag, _type, _count, value = struct.unpack_from(
                endian + 'HHII', tiff, second + 2 + 12 * index)
            fields[tag] = value
        offset, length = fields.get(0x0201), fields.get(0x0202)
    except struct.error:
        return None
    if not offset or not length:
        return None
    thumbnail = tiff[offset:offset + length]
    return thumbnail if thumbnail.startswith(b'\xff\xd8') and \
        len(thumbnail) == length else None

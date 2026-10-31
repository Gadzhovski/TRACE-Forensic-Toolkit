"""The pictures a legacy Office document keeps (no Qt): OfficeArt BLIP
records ([MS-ODRAW] 2.2.23-2.2.31) in its OLE streams.

Word 97-2003 keeps them in the Data stream, PowerPoint in Pictures,
Excel in the Workbook stream's drawing group and charts' picture fills
-- split across records every 8,224 bytes, so they are joined first
([MS-XLS] 2.4.170 MsoDrawingGroup, 2.4.128 GelFrame). A BLIP is a record header (version
0, an instance naming how many 16-byte ids follow, a type 0xF01A-0xF029,
a length), then:

* a bitmap (JPEG, PNG, DIB, TIFF): the ids, a tag byte, the file -- a DIB
  without its BITMAPFILEHEADER, which is put back so the copy opens;
* a metafile (EMF, WMF, PICT): the ids, a 34-byte header (size
  uncompressed, bounds, size, size stored, compression 0 = DEFLATE /
  0xFE = none), the data. A WMF is kept without its placeable header.

Each record is taken only when its length fits the stream and what it
holds starts as its type says.
"""

import logging
import struct
import zlib

logger = logging.getLogger('TRACE.OfficeArt')

#: recType -> (kind, extension, instances with one id; +1 = two ids).
BLIP_TYPES = {
    0xF01A: ('metafile', 'emf', 0x3D4),
    0xF01B: ('metafile', 'wmf', 0x216),
    0xF01C: ('metafile', 'pict', 0x542),
    0xF01D: ('bitmap', 'jpg', 0x46A),
    0xF02A: ('bitmap', 'jpg', 0x6E2),
    0xF01E: ('bitmap', 'png', 0x6E0),
    0xF01F: ('bitmap', 'bmp', 0x7A8),
    0xF029: ('bitmap', 'tif', 0x6E4),
}
_HEADER = struct.Struct('<HHI')
_MAX_PICTURE = 256 * 1024 * 1024
#: BIFF record types carrying OfficeArt: MsoDrawingGroup, MsoDrawing,
#: GelFrame; and CONTINUE, which carries a record on past 8,224 bytes.
_DRAWING = (0x00EB, 0x00EC, 0x1066)
_CONTINUE = 0x003C


def pictures_in_ole(ole):
    """[(name, bytes)] of the pictures an open olefile.OleFileIO holds."""
    found = []
    for path in ole.listdir(streams=True, storages=False):
        leaf = path[-1]
        if leaf not in ('Data', 'Pictures', 'Workbook', 'Book'):
            continue
        try:
            stream = ole.openstream(path).read()
        except Exception as exc:
            logger.debug("Stream %s not read: %s", '/'.join(path), exc)
            continue
        if leaf in ('Workbook', 'Book'):
            stream = drawing_group(stream)
        found += blips(stream)
    out = []
    for extension, content in found:
        out.append((f"picture {len(out) + 1}.{extension}", content))
    return out


def drawing_group(workbook):
    """The OfficeArt a BIFF8 workbook stream carries, joined: each run of
    MsoDrawingGroup, MsoDrawing or GelFrame records (a chart's picture
    fill -- Excel's chart gallery keeps its pictures there) with the
    CONTINUE records that carry it on."""
    out, position, joining = bytearray(), 0, None
    while position + 4 <= len(workbook):
        kind, length = struct.unpack_from('<HH', workbook, position)
        body = workbook[position + 4:position + 4 + length]
        if kind in _DRAWING:
            if kind != joining:
                out += bytes(8)           # a run never runs into the next
            out += body
            joining = kind
        elif kind == _CONTINUE and joining:
            out += body
        else:
            joining = None
        position += 4 + length
    return bytes(out)


def blips(stream):
    """[(extension, bytes)] of every BLIP record in `stream`, in order."""
    out = []
    position = stream.find(b'\xf0', 3)
    while position != -1:
        start = position - 3
        record = _blip_at(stream, start)
        if record is not None:
            extension, content, end = record
            out.append((extension, content))
            position = stream.find(b'\xf0', end + 3)
        else:
            position = stream.find(b'\xf0', position + 1)
    return out


def _blip_at(stream, start):
    """(extension, file bytes, end) of a BLIP record at `start`, or
    None."""
    if start < 0 or start + 8 > len(stream):
        return None
    version_instance, kind, length = _HEADER.unpack_from(stream, start)
    known = BLIP_TYPES.get(kind)
    if known is None or version_instance & 0xF:
        return None
    family, extension, instance = known
    given = version_instance >> 4
    if given not in (instance, instance + 1):
        return None
    body_start, end = start + 8, start + 8 + length
    if end > len(stream) or length > _MAX_PICTURE:
        return None
    ids = 32 if given == instance + 1 else 16
    body = stream[body_start:end]
    if family == 'bitmap':
        content = body[ids + 1:]
        content = _checked_bitmap(extension, content)
    else:
        content = _metafile(extension, body[ids:])
    if not content:
        return None
    return extension, content, end


def _checked_bitmap(extension, content):
    if extension == 'jpg' and content.startswith(b'\xff\xd8\xff'):
        return content
    if extension == 'png' and content.startswith(b'\x89PNG\r\n\x1a\n'):
        return content
    if extension == 'tif' and content[:4] in (b'II*\x00', b'MM\x00*'):
        return content
    if extension == 'bmp':
        return dib_to_bmp(content)
    return None


def dib_to_bmp(dib):
    """A device-independent bitmap with its BITMAPFILEHEADER put back
    (where the pixels start: after the info header and colour table)."""
    if len(dib) < 16:
        return None
    header = struct.unpack_from('<I', dib)[0]
    if header == 12:
        _w, _h, _planes, bits = struct.unpack_from('<HHHH', dib, 4)
        colours, entry, masks = 0, 3, 0
    elif header in (40, 52, 56, 108, 124) and len(dib) >= 40:
        (_w, _h, planes, bits, compression, _size, _x, _y, colours,
         _important) = struct.unpack_from('<iiHHIIiiII', dib, 4)
        if planes != 1:
            return None
        entry = 4
        masks = 12 if header == 40 and compression in (3, 6) else 0
    else:
        return None
    if bits not in (1, 2, 4, 8, 16, 24, 32):
        return None
    if not colours and bits <= 8:
        colours = 1 << bits
    pixels = 14 + header + masks + colours * entry
    if pixels - 14 > len(dib):
        return None
    return b'BM' + struct.pack('<IHHI', 14 + len(dib), 0, 0, pixels) + dib


def _metafile(extension, body):
    """The metafile a metafile BLIP holds, decompressed."""
    if len(body) < 34:
        return None
    (raw_size, _l, _t, _r, _b, _cx, _cy, stored, compression,
     _filter) = struct.unpack_from('<I4i2iIBB', body)
    data = body[34:34 + stored]
    if len(data) != stored or raw_size > _MAX_PICTURE:
        return None
    if compression == 0xFE:
        content = data
    elif compression == 0:
        try:
            inflater = zlib.decompressobj()
            content = inflater.decompress(data, raw_size + 1)
        except zlib.error:
            return None
    else:
        return None
    if len(content) != raw_size:
        return None
    if extension == 'emf' and content[40:44] != b' EMF':
        return None
    if extension == 'wmf' and content[:2] not in (b'\x01\x00', b'\x02\x00'):
        return None
    return content

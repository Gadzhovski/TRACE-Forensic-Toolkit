"""Picture and animation formats that libmagic names unreliably, checked
by their own structure (no Qt).

Which libmagic a platform ships decides what it says: python-magic-bin's
5.32 (Windows) calls a placeable WMF, an EMF and a Flash movie
'application/octet-stream' or 'text/plain', and a plain WMF 'image/x-tga'
-- which TRACE then refuses, since TGA has no signature and 5.41+ names
any bytes starting 00 01 02 a TGA. Read as the formats define them, the
answer is the same everywhere: the M57 'Jean' image's 814 clip-art WMFs,
57 TGAs and Flash movies were exported by X-Ways, AXIOM and Griffeye and
not by TRACE.

`sniff(head, size, read)` -> MIME type or None. `read(position, length)`
is needed only for an RLE TGA, whose packets must account for every pixel.
"""

import struct

WMF = 'image/wmf'
EMF = 'image/emf'
TGA = 'image/x-tga'
SWF = 'application/x-shockwave-flash'

#: MIME type -> the extension a copy is saved with.
EXTENSIONS = {WMF: 'wmf', EMF: 'emf', TGA: 'tga', SWF: 'swf'}

_PLACEABLE_KEY = b'\xd7\xcd\xc6\x9a'
#: META_EOF: the record every WMF ends with (3 words, function 0).
_WMF_EOF = b'\x03\x00\x00\x00\x00\x00'
_TGA_FOOTER = b'TRUEVISION-XFILE.\x00'
#: An RLE TGA is decoded to count its pixels only up to this size.
_TGA_DECODE_LIMIT = 64 * 1024 * 1024


def sniff(head, size=None, read=None, tga=True):
    """The MIME type of a file starting with `head` (`size` bytes long,
    when known), for the formats here; None for anything else. `tga`
    False leaves TGA out -- the one with no signature, for a caller that
    asks it only of what nothing else named."""
    if size is None:
        size = len(head)
    if is_wmf(head, size):
        return WMF
    if is_emf(head, size):
        return EMF
    if is_swf(head, size):
        return SWF
    if tga and is_tga(head, size, read):
        return TGA
    return None


# --- Windows Metafile -------------------------------------------------------

def _wmf_header(data, position, size):
    """META_HEADER at `position`: type 1 (memory) or 2 (disk), 9 words of
    header, version 1.0 or 3.0, and a file size in words the bytes can
    hold."""
    if len(data) < position + 18:
        return False
    kind, words, version, length, _objects, largest, members = \
        struct.unpack_from('<HHHIHIH', data, position)
    if kind not in (1, 2) or words != 9 or version not in (0x0100, 0x0300):
        return False
    if members != 0 or length < 9 + 3 or largest < 3:
        return False
    # The recorded length is a minimum; padding to a cluster is common.
    return length * 2 <= size - position + 2 and largest <= length


def is_wmf(head, size):
    if head.startswith(_PLACEABLE_KEY):
        if len(head) < 22:
            return False
        checksum = 0
        for word in struct.unpack_from('<10H', head, 0):
            checksum ^= word
        if checksum != struct.unpack_from('<H', head, 20)[0]:
            return False
        return _wmf_header(head, 22, size)
    return _wmf_header(head, 0, size)


def wmf_length(head):
    """The length a placeable WMF records for itself (22-byte placeable
    header + the metafile's size in words), or None."""
    if not head.startswith(_PLACEABLE_KEY) or len(head) < 40:
        return None
    return 22 + struct.unpack_from('<I', head, 22 + 6)[0] * 2


def metafiles_in(data, read=None, size=None):
    """(offset, length, MIME type) of every placeable WMF and EMF inside
    `data` (a file's bytes, or a piece of it whose `read(position,
    length)` gives more, `size` long) -- each proved by its header, and
    whole within the file."""
    size = len(data) if size is None else size
    read = read or (lambda position, length:
                    data[position:position + length])
    found = []
    position = data.find(_PLACEABLE_KEY)
    while position != -1:
        head = data[position:position + 64]
        length = wmf_length(head)
        if length and position + length <= size and \
                is_wmf(head, length) and \
                read(position + length - 6, 6) == _WMF_EOF:
            found.append((position, length, WMF))
        position = data.find(_PLACEABLE_KEY, position + 1)
    position = data.find(b' EMF', 40)
    while position != -1:
        start = position - 40
        head = data[start:start + 88]
        if len(head) == 88:
            total = struct.unpack_from('<I', head, 48)[0]
            if start + total <= size and is_emf(head, total) and \
                    _emf_ends(read, start, total):
                found.append((start, total, EMF))
        position = data.find(b' EMF', position + 1)
    return sorted(found)


def _emf_ends(read, start, total):
    """An EMF's last record is EMR_EOF (type 14), whose size -- palette
    entries included -- is also its last four bytes."""
    last = read(start + total - 4, 4)
    if len(last) != 4:
        return False
    record = struct.unpack('<I', last)[0]
    if 20 <= record <= total:
        head = read(start + total - record, 8)
        return len(head) == 8 and struct.unpack('<II', head) == (14, record)
    return False


# --- Enhanced Metafile ------------------------------------------------------

def is_emf(head, size):
    """EMR_HEADER: record type 1, ' EMF' at 40, version 0x10000 and a
    byte count the file holds."""
    if len(head) < 88:
        return False
    kind, record = struct.unpack_from('<II', head, 0)
    if kind != 1 or record < 88 or record > len(head) + 4096:
        return False
    if head[40:44] != b' EMF':
        return False
    version, total = struct.unpack_from('<II', head, 44)
    return version == 0x10000 and record <= total <= size + 4096


# --- Flash ------------------------------------------------------------------

def is_swf(head, size):
    """'FWS' (plain), 'CWS' (zlib) or 'ZWS' (LZMA), a version Flash used,
    and the uncompressed length its header records."""
    if len(head) < 8 or head[:3] not in (b'FWS', b'CWS', b'ZWS'):
        return False
    version = head[3]
    length = struct.unpack_from('<I', head, 4)[0]
    if not 1 <= version <= 50 or length < 21:
        return False
    if head[:3] == b'FWS':
        # The movie's own length; what follows is slack or padding.
        return length <= size <= length + 64 * 1024
    return length >= 8 and size <= length + 64 * 1024


# --- Truevision TGA ---------------------------------------------------------

_TGA_TYPES = {1: 'mapped', 2: 'true', 3: 'grey',
              9: 'mapped', 10: 'true', 11: 'grey'}


def tga_header(head):
    """The header's fields when they are a TGA's, else None."""
    if len(head) < 18:
        return None
    (id_length, map_type, image_type, map_first, map_length, map_bits,
     _x, _y, width, height, depth, descriptor) = struct.unpack_from(
        '<BBBHHBHHHHBB', head, 0)
    kind = _TGA_TYPES.get(image_type)
    if kind is None or map_type not in (0, 1) or width == 0 or height == 0:
        return None
    if descriptor & 0xC0 or (descriptor & 0x0F) > depth:
        return None
    if map_type == 0:
        if map_length or map_first or map_bits not in (0, 15, 16, 24, 32):
            return None
    elif map_length == 0 or map_bits not in (15, 16, 24, 32):
        return None
    if kind == 'mapped':
        if map_type != 1 or depth not in (8, 16):
            return None
    elif kind == 'grey':
        if map_type or depth not in (8, 16):
            return None
    elif depth not in (15, 16, 24, 32):
        return None
    return {'id_length': id_length, 'map_length': map_length,
            'map_bits': map_bits, 'width': width, 'height': height,
            'depth': depth, 'rle': image_type >= 9}


def is_tga(head, size, read=None):
    """A TGA: a header whose every field is one the format allows, and
    pixel data that fits the file exactly -- for an RLE image, packets
    that decode to width x height pixels. A file this does not prove is
    not a TGA: the format has no signature, and libmagic's guess names
    anything starting 00 01 02 one."""
    fields = tga_header(head)
    if fields is None:
        return False
    pixel = (fields['depth'] + 7) // 8
    start = 18 + fields['id_length'] + \
        fields['map_length'] * ((fields['map_bits'] + 7) // 8)
    pixels = fields['width'] * fields['height']
    has_footer = False
    if read is not None and size >= 26:
        try:
            has_footer = read(size - 18, 18) == _TGA_FOOTER
        except Exception:
            has_footer = False
    if not fields['rle']:
        end = start + pixels * pixel
        if end > size:
            return False
        # What follows the pixels is a 2.0 extension area and footer, or
        # padding to the cluster; anything longer is another file.
        return has_footer or size - end <= 4096
    if read is None or size > _TGA_DECODE_LIMIT:
        return has_footer
    end = _rle_end(read, start, pixels, pixel, size)
    return end is not None and (has_footer or size - end <= 4096)


def _rle_end(read, position, pixels, pixel, size):
    """Where the RLE packets covering `pixels` end, or None when they run
    past the file or overshoot the image."""
    buffer, base = b'', position
    while pixels > 0:
        if position + 1 > base + len(buffer):
            base = position
            buffer = read(position, min(1 << 20, size - position))
            if not buffer:
                return None
        header = buffer[position - base]
        count = (header & 0x7F) + 1
        if count > pixels:
            return None
        position += 1 + (pixel if header & 0x80 else count * pixel)
        pixels -= count
        if position > size:
            return None
    return position

"""RDP bitmap cache: pieces of the screens of remote sessions this computer
connected to, kept by the Remote Desktop client in each profile's
AppData/Local/Microsoft/Terminal Server Client/Cache.

* **Cache0000.bin .. Cache0004.bin** (Windows 7 and later): 'RDP8bmp\\0',
  a u32 version, then tiles -- key1, key2 (u32 each), width, height (u16
  each) and width x height pixels of 4 bytes (blue, green, red, unused),
  rows top-down.
* **bcache2.bmc / bcache22.bmc / bcache24.bmc** (older clients): no
  header; each tile is key1, key2, width, height, the pixel length (u32)
  and flags (u32, bit 3 = compressed), then its pixels bottom-up, in a
  slot always as large as a 64 x 64 tile. Pixels are 4 bytes or, in the
  16-bit caches, RGB 565. Compressed tiles are counted, not decoded.

A tile is at most 64 x 64: a fragment of a window, a letter of a document,
part of a desktop. Shown side by side in file order, neighbours often
assemble into readable pieces, which is how they are reviewed (the collage).
Format per ANSSI's CERTFR-2016-ACT-017; checked against dissect.target's
pixel hashes for its test caches.
"""

import io
import struct

BIN_MAGIC = b'RDP8bmp\x00'
SLOT = 64
#: Tiles per row of the collage.
COLLAGE_COLUMNS = 64


class RdpCacheError(Exception):
    pass


def is_rdp_cache_name(name):
    lower = (name or '').lower()
    return (lower.startswith('cache') and lower.endswith('.bin')
            and len(lower) == 13) or \
        (lower.startswith('bcache') and lower.endswith('.bmc'))


def is_bin(header):
    return bytes(header[:8]) == BIN_MAGIC


def _bmc_header(data, at):
    """(width, height, bytes per pixel) of an uncompressed .bmc tile
    header at `at`, or None."""
    if at + 20 > len(data):
        return None
    _k1, _k2, width, height, length, flags = struct.unpack_from(
        '<IIHHII', data, at)
    if not 0 < width <= SLOT or not 0 < height <= SLOT or flags & 0x08:
        return None
    bpp, rest = divmod(length, width * height)
    return (width, height, bpp) if bpp in (2, 4) and not rest else None


def looks_like_bmc(data):
    """A .bmc has no signature: its first tile header must be whole and
    consistent, and so must the next slot's when the file has one."""
    first = _bmc_header(data, 0)
    if first is None:
        return False
    following = 20 + SLOT * SLOT * first[2]
    return len(data) < following + 20 or \
        _bmc_header(data, following) is not None


def _bin_tiles(data):
    tiles, at = [], 12
    while at + 12 <= len(data):
        key1, key2, width, height = struct.unpack_from('<IIHH', data, at)
        at += 12
        length = width * height * 4
        if not width or not height or width > SLOT or height > SLOT or \
                at + length > len(data):
            break
        pixels = data[at:at + length]
        at += length
        # Stored top-down; kept bottom-up, as a BMP holds them.
        rows = [pixels[r * width * 4:(r + 1) * width * 4]
                for r in range(height)]
        tiles.append({'key': f"{key1:08x}{key2:08x}", 'width': width,
                      'height': height, 'offset': at - length - 12,
                      'bgrx': _opaque(b''.join(reversed(rows)))})
    return tiles


def _opaque(pixels):
    """4-byte pixels with the unused byte set to 255."""
    out = bytearray(pixels)
    out[3::4] = b'\xff' * (len(out) // 4)
    return bytes(out)


def _from_565(pixels):
    out = bytearray()
    for (value,) in struct.iter_unpack('<H', pixels[:len(pixels) & ~1]):
        red, green, blue = value >> 11, (value >> 5) & 0x3F, value & 0x1F
        out += bytes(((blue << 3) | (blue >> 2), (green << 2) | (green >> 4),
                      (red << 3) | (red >> 2), 255))
    return bytes(out)


def _bmc_tiles(data):
    tiles, skipped, at = [], 0, 0
    while at + 20 <= len(data):
        key1, key2, width, height, length, flags = struct.unpack_from(
            '<IIHHII', data, at)
        at += 20
        if not width or not height or width > SLOT or height > SLOT:
            break
        compressed = bool(flags & 0x08)
        bpp = 0 if compressed else length // (width * height)
        if compressed:
            # A compressed tile's slot is its own length.
            at += length
            skipped += 1
            continue
        if bpp not in (2, 4) or at + width * height * bpp > len(data):
            break
        pixels = data[at:at + width * height * bpp]
        # Each slot holds a whole 64 x 64 tile; what is past a smaller one
        # is an older tile's leftover pixels.
        at += SLOT * SLOT * bpp
        tiles.append({'key': f"{key1:08x}{key2:08x}", 'width': width,
                      'height': height, 'offset': at - SLOT * SLOT * bpp - 20,
                      'bgrx': _opaque(pixels) if bpp == 4 else
                      _from_565(pixels)})
    return tiles, skipped


def parse(data):
    """{'format': 'bin' | 'bmc', 'version', 'tiles': [{'key', 'width',
    'height', 'offset', 'bgrx'}], 'compressed': tiles not decoded}.
    `bgrx` is bottom-up rows of blue, green, red, 255."""
    data = bytes(data)
    if is_bin(data):
        return {'format': 'bin', 'version': struct.unpack_from('<I', data, 8)[0],
                'tiles': _bin_tiles(data), 'compressed': 0}
    tiles, skipped = _bmc_tiles(data)
    if not tiles and not skipped:
        raise RdpCacheError("Not an RDP bitmap cache")
    return {'format': 'bmc', 'version': None, 'tiles': tiles,
            'compressed': skipped}


_LAST = [None, None]


def parsed(data):
    """parse(), remembered for the last cache asked about (the grid asks
    for each of its tiles from the same bytes)."""
    if _LAST[0] is not data:
        _LAST[:] = [data, parse(data)]
    return _LAST[1]


def tile_image(tile):
    from PIL import Image
    return Image.frombuffer('RGB', (tile['width'], tile['height']),
                            tile['bgrx'], 'raw', 'BGRX', 0, -1)


def _png(image):
    out = io.BytesIO()
    image.save(out, 'PNG')
    return out.getvalue()


def tile_png(tile):
    return _png(tile_image(tile))


def collage(tiles, columns=COLLAGE_COLUMNS):
    """Every tile in file order on a grid of 64 x 64 cells: neighbouring
    tiles of one screen are usually stored together."""
    from PIL import Image
    if not tiles:
        raise RdpCacheError("The cache holds no tiles")
    columns = max(1, min(columns, len(tiles)))
    rows = -(-len(tiles) // columns)
    sheet = Image.new('RGB', (columns * SLOT, rows * SLOT), (255, 255, 255))
    for number, tile in enumerate(tiles):
        sheet.paste(tile_image(tile), ((number % columns) * SLOT,
                                       (number // columns) * SLOT))
    return sheet


def collage_png(tiles, columns=COLLAGE_COLUMNS):
    return _png(collage(tiles, columns))


# --- browsed like a folder of pictures (core/archives.py) ---------------------------

COLLAGE_NAME = 'all tiles (collage).png'


def list_members(data):
    tiles = parsed(data)['tiles']
    out = [{'name': COLLAGE_NAME, 'size': 0, 'compressed_size': 0,
            'is_dir': False, 'modified': None, 'encrypted': False,
            'crc': None}] if tiles else []
    for number, tile in enumerate(tiles, 1):
        out.append({'name': f"tile {number:04d} {tile['key']}.png",
                    'size': len(tile['bgrx']),
                    'compressed_size': len(tile['bgrx']), 'is_dir': False,
                    'modified': None, 'encrypted': False, 'crc': None})
    return out


def read_member(data, name):
    tiles = parsed(data)['tiles']
    if name == COLLAGE_NAME:
        return collage_png(tiles)
    for number, tile in enumerate(tiles, 1):
        if name == f"tile {number:04d} {tile['key']}.png":
            return tile_png(tile)
    raise RdpCacheError(f"No member {name}")


def picture(data, location):
    """A thumbnails row's picture: 'collage' or 'tile:<number>'."""
    tiles = parsed(data)['tiles']
    if location == 'collage':
        return collage_png(tiles, columns=16)
    number = int(location.split(':', 1)[1])
    return tile_png(tiles[number - 1])

"""What a picture's pixels and encoding say, beyond what it shows (no Qt).

Everything here *reads* a picture and returns facts or a new image to look
at; nothing changes the evidence, and every view it makes is a derivative
that says what was done to it (`describe`).

* **Facts** (`image_facts`): format, size, mode and bit depth, ICC profile,
  frames, EXIF orientation, JPEG subsampling and progressive coding.
* **Adjust** (`adjust`): brightness, contrast, gamma, equalised levels,
  invert, one channel alone -- alpha among them, which shows content a
  transparent layer hides. Pillow's C operations, so a large picture is
  adjusted without holding the interpreter for long.
* **Error level analysis** (`error_levels`): the JPEG saved again at a
  known quality and the difference amplified. Regions saved fewer times
  than the rest (pasted in, retouched) often differ from their
  surroundings. An indicator to look further, never proof: edges, text
  and flat colour light up on untouched pictures too.
* **JPEG quantisation** (`jpeg_tables`, `jpeg_quality`): the tables the
  encoder used, named when they are libjpeg's standard tables at some
  quality. Cameras and editors often use their own; a picture claiming to
  come straight from a camera but carrying libjpeg's tables at 75 was
  saved again by software.
* **Embedded thumbnail** (`thumbnail_check`): the EXIF thumbnail compared
  with the picture at 16x16 and by shape. Many editors change the
  picture and leave the camera's thumbnail, so a thumbnail of something
  else -- or of the uncropped scene -- is a classic sign of an edit.
* **Frames** (`frame_list`, `frame_image`): animated GIF/PNG/WebP and
  multi-page TIFF. Viewers show frame one; the rest can hold anything.

Pillow's decompression-bomb guard stays on throughout.
"""

import io
import logging

logger = logging.getLogger('TRACE.ImageForensics')

#: Neutral settings of the Adjust view: a picture shown with these is the
#: decoded file. `channel`: 'all', 'R', 'G', 'B', 'A' (alpha) or 'L' (grey).
NEUTRAL = {'brightness': 1.0, 'contrast': 1.0, 'gamma': 1.0,
           'equalise': False, 'invert': False, 'channel': 'all'}

CHANNELS = (('all', "All channels"), ('L', "Greyscale"), ('R', "Red only"),
            ('G', "Green only"), ('B', "Blue only"), ('A', "Alpha only"))

#: Quality ELA saves at. 90 is the usual choice: high enough that an
#: untouched high-quality JPEG changes little, low enough to show regions
#: that were compressed fewer times.
ELA_QUALITY = 90

#: Difference (0-100, `_difference`) beyond which the thumbnail is not
#: the picture. Untouched pictures measured at most 10.8 (see
#: `thumbnail_check`).
THUMBNAIL_DIFFERS = 15
_GRID = 16
#: Shapes (width / height) further apart than this are a crop or a
#: different picture.
THUMBNAIL_SHAPE_TOLERANCE = 0.06

#: libjpeg's standard tables (ITU-T T.81 Annex K), natural order -- as
#: Pillow reports `quantization`.
STANDARD_LUMINANCE = (
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99)
STANDARD_CHROMINANCE = (
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99)

#: EXIF orientation values and what a viewer does to show them upright.
ORIENTATIONS = {1: "as stored", 2: "mirrored", 3: "rotated 180°",
                4: "mirrored vertically", 5: "mirrored, rotated 90° left",
                6: "rotated 90° right", 7: "mirrored, rotated 90° right",
                8: "rotated 90° left"}


def open_image(data):
    """A Pillow image of `data` (the guard on), or None."""
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(bytes(data)))
        image.load()
        return image
    except Exception as exc:
        logger.debug("Not a picture Pillow reads: %s", exc)
        return None


# --- facts ----------------------------------------------------------------

_BITS = {'1': 1, 'L': 8, 'P': 8, 'RGB': 24, 'RGBA': 32, 'CMYK': 32,
         'YCbCr': 24, 'LAB': 24, 'HSV': 24, 'I': 32, 'F': 32, 'LA': 16,
         'PA': 16, 'RGBX': 32, 'RGBa': 32, 'La': 16, 'I;16': 16,
         'I;16B': 16, 'I;16L': 16}

_SAMPLING = {0: "4:4:4", 1: "4:2:2", 2: "4:2:0"}


def image_facts(data, image=None):
    """[(label, value)] about the picture in `data`: what the file is,
    not what it shows. Empty when Pillow cannot read it."""
    image = image or open_image(data)
    if image is None:
        return []
    facts = [("Format", image.format or "unknown"),
             ("Dimensions", f"{image.width:,} × {image.height:,} px"),
             ("Colour mode", f"{image.mode}"
              + (f", {_BITS[image.mode]}-bit" if image.mode in _BITS
                 else ''))]
    if image.mode == 'P':
        palette = image.getpalette() or []
        facts.append(("Palette", f"{len(palette) // 3} colours"))
    if 'transparency' in image.info or image.mode in ('RGBA', 'LA', 'PA'):
        facts.append(("Transparency", "yes"))
    count = getattr(image, 'n_frames', 1) or 1
    facts.append(("Frames", f"{count}" + (" (animated)"
                                          if getattr(image, 'is_animated',
                                                     False) else '')))
    profile = image.info.get('icc_profile')
    if profile:
        facts.append(("ICC profile", _profile_name(profile)
                      or f"{len(profile):,} bytes"))
    else:
        facts.append(("ICC profile", "none"))
    dpi = image.info.get('dpi')
    if dpi:
        try:
            facts.append(("Resolution", f"{float(dpi[0]):g} × "
                                        f"{float(dpi[1]):g} dpi"))
        except (TypeError, ValueError, IndexError):
            pass
    orientation = exif_orientation(image)
    if orientation:
        facts.append(("EXIF orientation",
                      f"{orientation} ({ORIENTATIONS.get(orientation, '?')})"))
    if image.format == 'JPEG':
        try:
            from PIL import JpegImagePlugin
            sampling = JpegImagePlugin.get_sampling(image)
            if sampling in _SAMPLING:
                facts.append(("Subsampling", _SAMPLING[sampling]))
        except Exception:
            pass
        facts.append(("Coding", "progressive"
                      if image.info.get('progressive') or
                      image.info.get('progression') else "baseline"))
        quality = jpeg_quality(jpeg_tables(image))
        if quality:
            facts.append(("Quantisation", quality['text']))
    return facts


def _profile_name(profile):
    try:
        from PIL import ImageCms
        description = ImageCms.getProfileDescription(
            ImageCms.ImageCmsProfile(io.BytesIO(profile)))
        return (description or '').strip()
    except Exception:
        return ''


def exif_orientation(image):
    """The EXIF orientation (1-8), or None when not recorded."""
    try:
        value = image.getexif().get(0x0112)
    except Exception:
        return None
    return value if isinstance(value, int) and 1 <= value <= 8 else None


def upright(image):
    """`image` turned as its EXIF orientation says the camera meant."""
    from PIL import ImageOps
    return ImageOps.exif_transpose(image)


# --- adjust ---------------------------------------------------------------

def is_neutral(settings):
    """True when `settings` change nothing."""
    settings = settings or {}
    return all(settings.get(key, value) == value
               for key, value in NEUTRAL.items())


def describe(settings):
    """What an adjusted view did, in words, for its badge and audit line
    ('' when nothing)."""
    settings = {**NEUTRAL, **(settings or {})}
    parts = []
    channel = dict(CHANNELS).get(settings['channel'])
    if settings['channel'] != 'all' and channel:
        parts.append(channel.lower())
    if settings['equalise']:
        parts.append("levels equalised")
    for key in ('brightness', 'contrast', 'gamma'):
        if abs(settings[key] - 1.0) > 1e-9:
            parts.append(f"{key} {settings[key]:.2f}")
    if settings['invert']:
        parts.append("inverted")
    return ', '.join(parts)


def adjust(image, settings):
    """A new picture: `image` with `settings` (see NEUTRAL) applied, in
    the order a channel is chosen, levels equalised, brightness, contrast
    and gamma set, then inverted. The result is RGB, RGBA or L."""
    from PIL import Image, ImageEnhance, ImageOps
    settings = {**NEUTRAL, **(settings or {})}
    channel = settings['channel']
    if channel in ('R', 'G', 'B', 'A'):
        rgba = image.convert('RGBA')
        result = rgba.getchannel(channel)
    elif channel == 'L':
        result = image.convert('L')
    else:
        result = image.convert('RGBA' if _has_alpha(image) else 'RGB')

    alpha = None
    if result.mode == 'RGBA':
        # Enhancers and ImageOps work on the colour; transparency is kept.
        alpha = result.getchannel('A')
        result = result.convert('RGB')
    if settings['equalise']:
        result = ImageOps.equalize(result)
    if settings['brightness'] != 1.0:
        result = ImageEnhance.Brightness(result).enhance(
            settings['brightness'])
    if settings['contrast'] != 1.0:
        result = ImageEnhance.Contrast(result).enhance(settings['contrast'])
    if settings['gamma'] != 1.0:
        gamma = max(0.05, float(settings['gamma']))
        table = [min(255, round(255 * (value / 255) ** (1 / gamma)))
                 for value in range(256)]
        result = result.point(table * len(result.getbands()))
    if settings['invert']:
        result = ImageOps.invert(result)
    if alpha is not None:
        result = Image.merge('RGBA', (*result.split(), alpha))
    return result


def _has_alpha(image):
    return image.mode in ('RGBA', 'LA', 'PA', 'RGBa', 'La') or \
        'transparency' in image.info


# --- error level analysis ---------------------------------------------------

def error_levels(image, quality=ELA_QUALITY):
    """(picture, highest difference): `image` saved again as a JPEG at
    `quality`, the absolute difference amplified so the largest is white.
    The highest difference (0-255) is returned as found, before scaling."""
    from PIL import Image, ImageChops
    original = image.convert('RGB')
    buffer = io.BytesIO()
    original.save(buffer, 'JPEG', quality=quality)
    resaved = Image.open(io.BytesIO(buffer.getvalue()))
    resaved.load()
    difference = ImageChops.difference(original, resaved)
    highest = max(high for _low, high in difference.getextrema()) or 1
    scale = 255.0 / highest
    return difference.point(lambda value: min(255, round(value * scale))), \
        highest


# --- JPEG quantisation -------------------------------------------------------

def jpeg_tables(image_or_data):
    """{table number: [64 values, natural order]} of a JPEG, or {}."""
    image = image_or_data
    if isinstance(image_or_data, (bytes, bytearray, memoryview)):
        image = open_image(image_or_data)
    tables = getattr(image, 'quantization', None) or {}
    return {int(key): list(values) for key, values in tables.items()
            if len(values) == 64}


def standard_table(base, quality):
    """libjpeg's `base` table scaled to `quality` (1-100), as
    jpeg_quality_scaling + jpeg_add_quant_table(force_baseline) make it."""
    quality = min(100, max(1, quality))
    scale = 5000 // quality if quality < 50 else 200 - quality * 2
    return [min(255, max(1, (value * scale + 50) // 100)) for value in base]


def jpeg_quality(tables):
    """What the quantisation tables say about the encoder: {'quality',
    'standard' (libjpeg's tables at that quality exactly), 'text'}, or
    None with no tables. A table that matches no quality gets the closest
    one, `standard` False -- the encoder's own tables (a camera, an
    editor)."""
    if not tables:
        return None
    luminance = tables.get(0)
    chrominance = tables.get(1)
    best, best_error = None, None
    for quality in range(1, 101):
        error = 0
        if luminance:
            error += sum(abs(a - b) for a, b in zip(
                luminance, standard_table(STANDARD_LUMINANCE, quality)))
        if chrominance:
            error += sum(abs(a - b) for a, b in zip(
                chrominance, standard_table(STANDARD_CHROMINANCE, quality)))
        if best_error is None or error < best_error:
            best, best_error = quality, error
        if error == 0:
            break
    standard = best_error == 0
    count = len(tables)
    text = (f"standard tables (libjpeg) at quality {best}" if standard
            else f"own tables, closest to standard quality {best}")
    text += f"; {count} table{'s' if count != 1 else ''}"
    return {'quality': best, 'standard': standard, 'text': text}


def tables_text(tables):
    """The tables as 8 rows of 8 numbers each, for display."""
    names = {0: "Luminance", 1: "Chrominance"}
    blocks = []
    for number in sorted(tables):
        values = tables[number]
        rows = [' '.join(f"{value:3d}" for value in values[row:row + 8])
                for row in range(0, 64, 8)]
        blocks.append(f"Table {number} ({names.get(number, 'other')})\n"
                      + '\n'.join(rows))
    return '\n\n'.join(blocks)


# --- embedded thumbnail ------------------------------------------------------

def embedded_thumbnail(data):
    """The EXIF thumbnail JPEG of a JPEG's bytes, or None."""
    from trace_app.core.embedded import _jpeg_exif, exif_thumbnail
    data = bytes(data[:4 * 1024 * 1024]) if data else b''
    if not data.startswith(b'\xff\xd8'):
        return None
    tiff = _jpeg_exif(data)
    return exif_thumbnail(tiff) if tiff else None


def _open_reduced(data):
    """A JPEG decoded at 1/2-1/8 scale (DCT scaling): plenty for a 16x16
    comparison, and the analysis pass checks every JPEG."""
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(bytes(data)))
        try:
            image.draft('RGB', (256, 256))
        except Exception:
            pass
        image.load()
        return image
    except Exception as exc:
        logger.debug("Not a picture Pillow reads: %s", exc)
        return None


def _trim_bars(image):
    """`image` without the black bars a camera pads a thumbnail with to
    fit 160x120 (a 16:9 picture letterboxed). Tried beside the untrimmed
    thumbnail, never instead: a dark background is picture too."""
    grey = image.convert('L').point(lambda value: 255 if value > 24 else 0)
    box = grey.getbbox()
    if not box:
        return image
    left, top, right, bottom = box
    if (right - left) * (bottom - top) < 0.5 * image.width * image.height:
        return image
    return image.crop(box)


def _grid(image):
    """`image` as 16x16 grey values, each the mean of its block."""
    from PIL import Image
    return list(image.convert('L').resize((_GRID, _GRID), Image.BOX)
                .getdata())


def _difference(a, b):
    """How far apart two 16x16 grids are, 0 (alike) to 100: the lower of
    (1 - correlation) x 100 -- blind to the brightness and contrast a
    thumbnail's resampling shifts -- and the mean absolute difference,
    which is what is left for a flat picture (noise textures, gradients:
    correlation means nothing there)."""
    count = len(a)
    mean_a, mean_b = sum(a) / count, sum(b) / count
    spread_a = sum((x - mean_a) ** 2 for x in a)
    spread_b = sum((y - mean_b) ** 2 for y in b)
    absolute = sum(abs(x - y) for x, y in zip(a, b)) / count
    if spread_a < 1e-9 or spread_b < 1e-9:
        return absolute
    correlation = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b)) / (
        spread_a * spread_b) ** 0.5
    return min(absolute, (1 - correlation) * 100)


def thumbnail_check(data, image=None):
    """Compare a JPEG's EXIF thumbnail with the picture. None when it has
    none (or either does not decode); else {'thumbnail': bytes, 'size':
    (w, h), 'difference': 0-100, 'shape': (picture ratio, thumbnail
    ratio), 'differs': bool, 'reason': text}.

    Measured on 154 untouched JPEGs with thumbnails (a macOS system's
    textures, gradients, photos, Photoshop exports): at most 10.8. A
    thumbnail of another picture scored 36-75, a picture with a region
    painted over 18-46."""
    thumbnail = embedded_thumbnail(data)
    if not thumbnail:
        return None
    small = open_image(thumbnail)
    picture = image or _open_reduced(data)
    if small is None or picture is None:
        return None
    try:
        main = upright(picture) if exif_orientation(picture) else picture
        # Thumbnails are written turned as the main picture is stored, or
        # upright, depending on the camera: compare with both.
        pictures = [picture] if main is picture else [picture, main]
        trimmed = _trim_bars(small)
        thumbnails = [small] if trimmed is small else [small, trimmed]
        grids = {id(item): _grid(item) for item in pictures + thumbnails}
        score, ratio, ratio_small = min(
            (_difference(grids[id(p)], grids[id(t)]),
             p.width / max(1, p.height), t.width / max(1, t.height))
            for p in pictures for t in thumbnails)
        shape_off = min(abs(p.width / max(1, p.height) -
                            t.width / max(1, t.height)) /
                        (p.width / max(1, p.height))
                        for p in pictures for t in thumbnails) > (
            THUMBNAIL_SHAPE_TOLERANCE)
    except Exception as exc:
        logger.debug("Thumbnail not compared: %s", exc)
        return None
    reasons = []
    if score > THUMBNAIL_DIFFERS:
        reasons.append(f"it shows something else (difference "
                       f"{score:.0f} of 100)")
    if shape_off:
        reasons.append(f"its shape differs ({ratio_small:.2f} vs "
                       f"{ratio:.2f}: cropped?)")
    return {'thumbnail': thumbnail, 'size': small.size,
            'difference': round(score, 1),
            'shape': (round(ratio, 3), round(ratio_small, 3)),
            'differs': bool(reasons),
            'reason': '; '.join(reasons) or
            f"it matches the picture (difference {score:.0f} of 100)"}


# --- frames ------------------------------------------------------------------

#: Frames listed at most; an animation can claim tens of thousands.
MAX_FRAMES = 2000


def frame_list(image):
    """[{'index', 'duration' (ms or None), 'size'}] for every frame or
    page (up to MAX_FRAMES)."""
    count = min(MAX_FRAMES, getattr(image, 'n_frames', 1) or 1)
    frames = []
    for index in range(count):
        try:
            image.seek(index)
        except EOFError:
            break
        duration = image.info.get('duration')
        frames.append({'index': index,
                       'duration': duration if isinstance(
                           duration, (int, float)) else None,
                       'size': image.size})
    try:
        image.seek(0)
    except EOFError:
        pass
    return frames


def frame_image(image, index):
    """Frame `index` of `image` as its own RGBA picture."""
    image.seek(index)
    try:
        return image.convert('RGBA')
    finally:
        try:
            image.seek(0)
        except EOFError:
            pass


def png_bytes(image):
    """`image` as PNG bytes (for a saved derivative)."""
    buffer = io.BytesIO()
    image.save(buffer, 'PNG')
    return buffer.getvalue()


# --- one view ------------------------------------------------------------------

def render(image, frame=0, upright_view=False, settings=None,
           ela_quality=None):
    """What a viewer shows: {'image', 'base', 'parts', 'derived'}.
    `base` is the file's own pixels (that frame, turned upright when
    asked); `image` is base after error level analysis (`ela_quality`)
    and the Adjust settings. `parts` names each step; `derived` is True
    when `image`'s pixels are not the file's."""
    base = frame_image(image, frame) if frame else image
    parts = []
    if frame:
        parts.append(f"frame {frame + 1}")
    if upright_view and exif_orientation(image):
        base = upright(base)
        parts.append("turned upright (EXIF orientation "
                     f"{exif_orientation(image)})")
    shown = base
    derived = False
    if ela_quality:
        shown, highest = error_levels(base, ela_quality)
        parts.append(f"error levels at quality {ela_quality} (largest "
                     f"difference {highest}, scaled to white)")
        derived = True
    if not is_neutral(settings):
        shown = adjust(shown, settings)
        parts.append(describe(settings))
        derived = True
    return {'image': shown, 'base': base, 'parts': parts, 'derived': derived}

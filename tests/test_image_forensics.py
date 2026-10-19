"""The picture viewer's examiner tools (core/image_forensics.py) and the
EXIF thumbnail check in the analysis (content_checks.thumbnail_mismatch).

Every picture is generated with Pillow. The answers come from outside
the code under test: Adjust must equal Pillow's own operations done
directly, the JPEG quality estimate must name the quality Pillow (that
is, libjpeg) was asked to save at, an animation's frames are the ones
written, and the thumbnail check is given a thumbnail of the picture and
one of something else.
"""

import io
import struct

import pytest

PIL = pytest.importorskip('PIL')
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageOps  # noqa: E402


def _jpeg(image, **options):
    buffer = io.BytesIO()
    image.save(buffer, 'JPEG', **options)
    return buffer.getvalue()


def _scene(width=320, height=240):
    """A picture with structure (gradients, shapes), not a flat colour."""
    image = Image.new('RGB', (width, height))
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            pixels[x, y] = (x * 255 // width, y * 255 // height,
                            (x + y) % 256)
    draw = ImageDraw.Draw(image)
    draw.ellipse((40, 30, 160, 150), fill=(250, 240, 20))
    draw.rectangle((200, 120, 300, 220), fill=(20, 40, 200))
    return image


def _with_exif(jpeg, thumbnail=None, orientation=None):
    """`jpeg` with an EXIF APP1 written by hand: IFD0 (Orientation) and
    IFD1 holding `thumbnail` (JPEGInterchangeFormat / Length) -- Pillow
    writes no EXIF thumbnail."""
    entries0 = []
    if orientation:
        entries0.append(struct.pack('<HHIHH', 0x0112, 3, 1, orientation, 0))
    ifd0_at = 8
    ifd0 = struct.pack('<H', len(entries0)) + b''.join(entries0)
    ifd1_at = ifd0_at + len(ifd0) + 4
    if thumbnail:
        data_at = ifd1_at + 2 + 2 * 12 + 4
        ifd1 = struct.pack('<H', 2) + \
            struct.pack('<HHII', 0x0201, 4, 1, data_at) + \
            struct.pack('<HHII', 0x0202, 4, 1, len(thumbnail)) + \
            struct.pack('<I', 0)
        tiff = b'II*\0' + struct.pack('<I', ifd0_at) + ifd0 + \
            struct.pack('<I', ifd1_at) + ifd1 + thumbnail
    else:
        tiff = b'II*\0' + struct.pack('<I', ifd0_at) + ifd0 + \
            struct.pack('<I', 0)
    body = b'Exif\0\0' + tiff
    app1 = b'\xff\xe1' + struct.pack('>H', len(body) + 2) + body
    return jpeg[:2] + app1 + jpeg[2:]


# --- Adjust ------------------------------------------------------------------

def test_adjust_is_pillows_own_operations():
    from trace_app.core import image_forensics
    image = _scene()
    settings = dict(image_forensics.NEUTRAL, brightness=1.4, contrast=0.7,
                    invert=True, equalise=True)
    got = image_forensics.adjust(image, settings)
    want = ImageOps.equalize(image)
    want = ImageEnhance.Brightness(want).enhance(1.4)
    want = ImageEnhance.Contrast(want).enhance(0.7)
    want = ImageOps.invert(want)
    assert ImageChops.difference(got, want).getbbox() is None
    assert image_forensics.describe(settings) == \
        "levels equalised, brightness 1.40, contrast 0.70, inverted"


def test_neutral_settings_change_nothing():
    from trace_app.core import image_forensics
    image = _scene(40, 30)
    assert image_forensics.is_neutral(image_forensics.NEUTRAL)
    assert image_forensics.describe(image_forensics.NEUTRAL) == ''
    same = image_forensics.adjust(image, image_forensics.NEUTRAL)
    assert ImageChops.difference(same, image).getbbox() is None


def test_the_alpha_channel_shows_what_transparency_hides():
    from trace_app.core import image_forensics
    image = Image.new('RGBA', (20, 10), (255, 0, 0, 0))
    image.putpixel((3, 4), (255, 0, 0, 200))
    alpha = image_forensics.adjust(
        image, dict(image_forensics.NEUTRAL, channel='A'))
    assert alpha.mode == 'L'
    assert alpha.getpixel((3, 4)) == 200 and alpha.getpixel((0, 0)) == 0


# --- JPEG quality and error levels -----------------------------------------

@pytest.mark.parametrize('quality', [10, 50, 75, 90, 95, 100])
def test_the_quality_estimate_is_the_quality_saved_at(quality):
    from trace_app.core import image_forensics
    data = _jpeg(_scene(64, 48), quality=quality)
    estimate = image_forensics.jpeg_quality(
        image_forensics.jpeg_tables(data))
    assert estimate['quality'] == quality
    assert estimate['standard'] is True


def test_own_tables_are_said_to_be_non_standard():
    from trace_app.core import image_forensics
    tables = {0: [2] * 64, 1: [3] * 64}
    data = _jpeg(_scene(64, 48), qtables=tables)
    estimate = image_forensics.jpeg_quality(
        image_forensics.jpeg_tables(data))
    assert estimate['standard'] is False
    assert 'own tables' in estimate['text']
    text = image_forensics.tables_text(image_forensics.jpeg_tables(data))
    assert text.count('\n') >= 15        # both 8 x 8 tables, printed


def test_error_levels_pick_out_a_region_saved_fewer_times():
    """A picture saved many times at quality 75 with a fresh patch pasted
    in at the end: the patch has more error left to lose."""
    from trace_app.core import image_forensics
    picture = _scene()
    for _ in range(6):
        picture = Image.open(io.BytesIO(_jpeg(picture, quality=75)))
        picture.load()
    patch = _scene(64, 64).transpose(Image.Transpose.ROTATE_90)
    picture = picture.convert('RGB')
    picture.paste(patch, (128, 96))
    picture = Image.open(io.BytesIO(_jpeg(picture, quality=75)))
    picture.load()
    levels, highest = image_forensics.error_levels(picture, 75)
    assert highest > 0
    grey = levels.convert('L')

    def mean(box):
        region = grey.crop(box)
        return sum(region.getdata()) / (region.width * region.height)
    inside = mean((136, 104, 184, 152))
    outside = mean((8, 8, 56, 56))
    assert inside > outside * 1.5


# --- orientation and frames ---------------------------------------------------

def test_orientation_is_shown_as_stored_until_asked():
    from trace_app.core import image_forensics
    data = _with_exif(_jpeg(_scene(64, 32)), orientation=6)
    image = image_forensics.open_image(data)
    assert image_forensics.exif_orientation(image) == 6
    stored = image_forensics.render(image)
    assert stored['image'].size == (64, 32) and not stored['parts']
    turned = image_forensics.render(image_forensics.open_image(data),
                                    upright_view=True)
    assert turned['image'].size == (32, 64)
    assert not turned['derived']           # the file's pixels, turned
    assert 'upright' in turned['parts'][0]


def test_an_animations_later_frames_are_shown():
    from trace_app.core import image_forensics
    frames = [Image.new('RGB', (20, 20), colour) for colour in
              ((255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0))]
    buffer = io.BytesIO()
    frames[0].save(buffer, 'GIF', save_all=True, append_images=frames[1:],
                   duration=[100, 200, 300, 400], loop=0)
    image = image_forensics.open_image(buffer.getvalue())
    listed = image_forensics.frame_list(image)
    assert [f['duration'] for f in listed] == [100, 200, 300, 400]
    third = image_forensics.render(image, frame=2)
    assert third['image'].convert('RGB').getpixel((5, 5)) == (0, 0, 255)
    assert third['parts'] == ['frame 3']
    facts = dict(image_forensics.image_facts(buffer.getvalue()))
    assert facts['Frames'].startswith('4')


def test_a_render_with_adjustments_says_it_is_derived():
    from trace_app.core import image_forensics
    data = _jpeg(_scene(64, 48), quality=90)
    view = image_forensics.render(
        image_forensics.open_image(data),
        settings=dict(image_forensics.NEUTRAL, contrast=1.5), ela_quality=90)
    assert view['derived'] is True
    assert view['parts'][0].startswith('error levels at quality 90')
    assert view['parts'][1] == 'contrast 1.50'


# --- the EXIF thumbnail --------------------------------------------------------

def _thumbnail_of(image):
    small = image.copy()
    small.thumbnail((160, 120))
    return _jpeg(small, quality=85)


def test_a_thumbnail_of_the_picture_matches():
    from trace_app.core import content_checks, image_forensics
    picture = _scene()
    data = _with_exif(_jpeg(picture, quality=90), _thumbnail_of(picture))
    check = image_forensics.thumbnail_check(data)
    assert check is not None and check['differs'] is False
    assert check['size'] == (160, 120)
    assert content_checks.thumbnail_mismatch(data) == []


def test_a_thumbnail_of_something_else_is_a_finding():
    from trace_app.core import content_checks, image_forensics
    picture = _scene()
    other = _scene().transpose(Image.Transpose.FLIP_LEFT_RIGHT)
    ImageDraw.Draw(other).rectangle((0, 0, 160, 240), fill=(0, 0, 0))
    data = _with_exif(_jpeg(picture, quality=90), _thumbnail_of(other))
    check = image_forensics.thumbnail_check(data)
    assert check['differs'] is True
    assert check['difference'] > image_forensics.THUMBNAIL_DIFFERS
    findings = content_checks.thumbnail_mismatch(data)
    assert [f.kind for f in findings] == ['thumbnail_mismatch']
    assert findings[0].grade == content_checks.GRADE_NOTABLE


def test_a_cropped_picture_keeps_the_wider_thumbnail():
    from trace_app.core import image_forensics
    picture = _scene(320, 240)
    cropped = picture.crop((0, 0, 180, 240))
    data = _with_exif(_jpeg(cropped, quality=90), _thumbnail_of(picture))
    check = image_forensics.thumbnail_check(data)
    assert check['differs'] is True
    assert 'shape' in check['reason'] or 'something else' in check['reason']


def test_no_thumbnail_no_check():
    from trace_app.core import image_forensics
    assert image_forensics.thumbnail_check(_jpeg(_scene(32, 32))) is None
    assert image_forensics.thumbnail_check(b'not a jpeg') is None

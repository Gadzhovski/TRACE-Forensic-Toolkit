"""A video's contact sheet: frames in a grid, each captioned with its time
and frame number, under a heading naming the file and over a footer with
its SHA-256 and how the frames were chosen. No Qt (the player hands the
frames over as PNG bytes); Pillow composes it, all C operations.

A sheet is a derivative made for a report: every caption is the time the
decoder gave for that frame, not the time asked for, and a frame the
decoder did not deliver is drawn as a labelled empty cell rather than left
out -- the grid's gaps say so.
"""

import io
import logging

logger = logging.getLogger('TRACE.ContactSheet')

#: Default grid: columns, and each frame's width in pixels.
COLUMNS = 4
FRAME_WIDTH = 320
#: Frames on one sheet at most.
MAX_FRAMES = 64

_MARGIN = 16
_GAP = 10
_CAPTION = 20
_BACKGROUND = (255, 255, 255)
_INK = (33, 37, 41)
_FAINT = (108, 117, 125)
_CELL = (233, 236, 239)


def _font(size):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size=size)
    except TypeError:               # Pillow < 10.1: one bitmap size
        return ImageFont.load_default()


def evenly(duration_ms, count):
    """`count` times spread over the video, the first and last a half step
    in from the ends (a video's first frame is often black and its last
    may not decode)."""
    count = max(1, int(count))
    duration_ms = max(0, int(duration_ms or 0))
    step = duration_ms / count
    return [int(step * (index + 0.5)) for index in range(count)]


def _fit(text, font, width, draw):
    """`text` cut with '…' to fit `width` pixels."""
    if draw.textlength(text, font=font) <= width:
        return text
    while text and draw.textlength(text + '…', font=font) > width:
        text = text[:-1]
    return text + '…'


def compose(frames, title, footer_lines=(), columns=COLUMNS,
            frame_width=FRAME_WIDTH):
    """PNG bytes of the sheet. `frames`: [(png bytes or None, caption)].
    `footer_lines`: text under the grid (file hash, how chosen)."""
    from PIL import Image, ImageDraw
    frames = list(frames)[:MAX_FRAMES]
    columns = max(1, min(columns, len(frames) or 1))
    pictures = []
    for data, caption in frames:
        picture = None
        if data:
            try:
                picture = Image.open(io.BytesIO(data))
                picture.load()
                picture = picture.convert('RGB')
                picture.thumbnail((frame_width, frame_width * 4))
            except Exception as exc:
                logger.debug("Frame not drawn: %s", exc)
                picture = None
        pictures.append((picture, caption))
    tallest = max((p.height for p, _c in pictures if p is not None),
                  default=frame_width * 9 // 16)
    rows = (len(pictures) + columns - 1) // columns
    title_font, caption_font, footer_font = _font(18), _font(13), _font(12)
    header = 34
    footer = 10 + 18 * len(footer_lines)
    width = _MARGIN * 2 + columns * frame_width + (columns - 1) * _GAP
    height = (_MARGIN * 2 + header + rows * (tallest + _CAPTION) +
              max(0, rows - 1) * _GAP + footer)
    sheet = Image.new('RGB', (width, height), _BACKGROUND)
    draw = ImageDraw.Draw(sheet)
    draw.text((_MARGIN, _MARGIN),
              _fit(title, title_font, width - 2 * _MARGIN, draw),
              fill=_INK, font=title_font)
    top = _MARGIN + header
    for index, (picture, caption) in enumerate(pictures):
        row, column = divmod(index, columns)
        x = _MARGIN + column * (frame_width + _GAP)
        y = top + row * (tallest + _CAPTION + _GAP)
        if picture is None:
            draw.rectangle((x, y, x + frame_width - 1, y + tallest - 1),
                           fill=_CELL)
            draw.text((x + 8, y + tallest // 2 - 8), "no frame decoded",
                      fill=_FAINT, font=caption_font)
        else:
            sheet.paste(picture, (x + (frame_width - picture.width) // 2,
                                  y + (tallest - picture.height) // 2))
        draw.text((x, y + tallest + 3),
                  _fit(caption, caption_font, frame_width, draw),
                  fill=_INK, font=caption_font)
    y = top + rows * (tallest + _CAPTION) + max(0, rows - 1) * _GAP + 8
    for line in footer_lines:
        draw.text((_MARGIN, y), _fit(line, footer_font, width - 2 * _MARGIN,
                                     draw), fill=_FAINT, font=footer_font)
        y += 18
    out = io.BytesIO()
    sheet.save(out, 'PNG')
    return out.getvalue()

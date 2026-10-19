"""The Timeline as a picture for the report: events per period, stacked by
source in the tab's colours, starred events marked under the axis.

Drawn with Pillow (no Qt: the report is written by a background job), as a
PNG the report embeds as a data: URI -- in HTML, PDF and Word alike.
"""

import io
import logging

from trace_app.core import timeline

logger = logging.getLogger('TRACE.Timeline')

WIDTH, HEIGHT = 1100, 300
_MARGIN_LEFT, _MARGIN_RIGHT, _MARGIN_TOP, _MARGIN_BOTTOM = 56, 16, 34, 58


def _font(size):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size=size)
    except TypeError:                       # a Pillow without sizes
        return ImageFont.load_default()


def _rgb(colour):
    colour = colour.lstrip('#')
    return tuple(int(colour[i:i + 2], 16) for i in (0, 2, 4))


def chart_png(buckets, unit, start, end, starred=(), title=''):
    """PNG bytes: `buckets` ({bucket text: {source: count}}, from
    timeline.histogram at `unit`) over [start, end), and `starred` (times)
    as gold ticks under the axis. b'' when there is nothing to draw."""
    from PIL import Image, ImageDraw
    first, last = timeline.parse(start), timeline.parse(end)
    if first is None or last is None or last <= first or not buckets:
        return b''
    image = Image.new('RGB', (WIDTH, HEIGHT), 'white')
    draw = ImageDraw.Draw(image)
    left, top = _MARGIN_LEFT, _MARGIN_TOP
    right, bottom = WIDTH - _MARGIN_RIGHT, HEIGHT - _MARGIN_BOTTOM
    span = (last - first).total_seconds()

    def x_of(moment):
        return left + (right - left) * (moment - first).total_seconds() / \
            span

    small, label = _font(11), _font(13)
    if title:
        draw.text((left, 8), title, fill=(40, 40, 40), font=label)
    peak = max(sum(c.values()) for c in buckets.values()) or 1
    # Square root, as on screen: one busy day must not flatten the rest.
    scale = (bottom - top) / peak ** 0.5
    from trace_app.core.timeline_axis import calendar_ticks
    for moment, text in calendar_ticks(first, last, 10):
        x = x_of(moment)
        draw.line([(x, top), (x, bottom)], fill=(232, 232, 232))
        draw.text((x + 2, bottom + 4), text, fill=(90, 90, 90), font=small)
    order = [key for key, _l, _c in timeline.SOURCES]
    for bucket, counts in buckets.items():
        begin = timeline.bucket_start(bucket)
        if begin is None:
            continue
        x0 = max(left, x_of(begin))
        x1 = min(right, x_of(timeline.step(begin, unit)))
        if x1 <= left or x0 >= right:
            continue
        x1 = max(x1 - 1, x0 + 1)
        total = sum(counts.values())
        height = total ** 0.5 * scale
        y = bottom
        for source in order:
            number = counts.get(source, 0)
            if not number:
                continue
            part = max(1.0, height * number / total)
            draw.rectangle([x0, y - part, x1, y],
                           fill=_rgb(timeline.SOURCE_COLOURS[source]))
            y -= part
    draw.line([(left, bottom), (right, bottom)], fill=(150, 150, 150))
    draw.text((6, top - 4), f"{peak:,}", fill=(120, 120, 120), font=small)
    for when in starred:
        moment = timeline.parse(when)
        if moment is None or not first <= moment < last:
            continue
        x = x_of(moment)
        draw.polygon([(x, bottom + 22), (x - 5, bottom + 32),
                      (x + 5, bottom + 32)], fill=(227, 160, 8))
    # Legend: the sources drawn.
    shown = [key for key in order
             if any(counts.get(key) for counts in buckets.values())]
    x = left
    for key in shown:
        draw.rectangle([x, HEIGHT - 16, x + 10, HEIGHT - 6],
                       fill=_rgb(timeline.SOURCE_COLOURS[key]))
        text = timeline.SOURCE_LABELS[key]
        draw.text((x + 14, HEIGHT - 18), text, fill=(60, 60, 60), font=small)
        x += 30 + int(draw.textlength(text, font=small))
    if starred:
        draw.polygon([(x + 5, HEIGHT - 16), (x, HEIGHT - 6),
                      (x + 10, HEIGHT - 6)], fill=(227, 160, 8))
        draw.text((x + 14, HEIGHT - 18), "Starred", fill=(60, 60, 60),
                  font=small)
    out = io.BytesIO()
    image.save(out, 'PNG', optimize=True)
    return out.getvalue()

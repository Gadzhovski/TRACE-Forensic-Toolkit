"""The Map's offline basemap: Natural Earth (public domain), bundled as
resources/offline_map.json.gz by tools/build_offline_map.py -- land, sea,
country borders, states and regions, lakes, rivers, country names and
7,342 cities and towns. Nothing is fetched: it is what the Map shows until
the examiner chooses an online map.

The file holds Web Mercator coordinates already (normalised to the world,
times `scale`), simplified at three levels of detail and delta-encoded
with each feature's bounding box. Drawing is a painter transform from
those units to the screen, only the features on screen, each built into a
QPainterPath the first time it is drawn and kept: loading is a JSON read
(0.16 s), and no zoom re-projects anything.
"""

import gzip
import json
import logging
from itertools import accumulate

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainterPath, QPen, QPolygonF

from trace_app.core import geo
from trace_app.infra.paths import resource_path

logger = logging.getLogger('TRACE.MapOffline')

#: Level of detail by zoom: the file's levels are simplified for zoom 3, 6
#: and 9 (about a pixel's error there).
def lod_for(zoom):
    return 0 if zoom < 5 else 1 if zoom < 8 else 2


#: Colours per theme: sea, land, coast, border, region border, river,
#: city text, country text, label halo.
PALETTES = {
    'light': {'sea': '#cfe0ef', 'land': '#f3f0ea', 'coast': '#9fb4c7',
              'border': '#8e7f9a', 'state': '#c9bfcf', 'river': '#94bbdd',
              'city': '#2b2b2b', 'country': '#6b6375', 'halo': '#f3f0ea',
              'dot': '#555555'},
    'dark': {'sea': '#16222e', 'land': '#2a2e33', 'coast': '#3c5266',
             'border': '#8a8199', 'state': '#474b52', 'river': '#2e4d6b',
             'city': '#e4e4e4', 'country': '#a8a2b3', 'halo': '#2a2e33',
             'dot': '#c8c8c8'},
}
#: Labels drawn at most per frame (a dense view stays readable and fast).
MAX_LABELS = 250
#: Past this zoom Natural Earth has no more detail (towns of some size,
#: regions, rivers): the footer says an online map shows more.
DETAIL_ZOOM = 9


class OfflineMap:
    """Loaded once (lazily), drawn into any MapCanvas."""

    def __init__(self, path=None):
        self.path = path or resource_path('resources', 'offline_map.json.gz')
        self._data = None
        self._paths = {}            # (layer, lod, index) -> QPainterPath
        self.available = True

    def data(self):
        if self._data is None and self.available:
            try:
                with gzip.open(self.path, 'rt', encoding='utf-8') as handle:
                    self._data = json.load(handle)
            except (OSError, ValueError) as exc:
                logger.warning("No offline map (%s): %s", self.path, exc)
                self.available = False
        return self._data

    @property
    def source(self):
        data = self.data() or {}
        return data.get('source', 'Natural Earth')

    def _path(self, layer, lod, index, feature, closed):
        key = (layer, lod, index)
        path = self._paths.get(key)
        if path is None:
            values = feature[5:]
            xs = accumulate(values[0::2])
            ys = accumulate(values[1::2])
            polygon = QPolygonF([QPointF(x, y) for x, y in zip(xs, ys)])
            path = QPainterPath()
            path.addPolygon(polygon)
            if closed:
                path.closeSubpath()
            self._paths[key] = path
        return path

    def draw(self, painter, canvas):
        """The basemap under the points: sea, land, lakes, rivers, borders,
        then labels."""
        data = self.data()
        dark = canvas.palette().color(
            canvas.palette().ColorRole.Base).lightnessF() < 0.5
        colours = {k: QColor(v) for k, v in
                   PALETTES['dark' if dark else 'light'].items()}
        painter.fillRect(canvas.rect(), colours['sea'])
        if not data:
            return
        zoom = canvas.zoom
        lod = str(lod_for(zoom))
        scale = geo.TILE_SIZE * 2 ** zoom / data['scale']
        for offset in canvas._copies():
            # Screen = units * scale + (half the view - centre + copy).
            dx = canvas.width() / 2 - canvas.cx + offset
            dy = canvas.height() / 2 - canvas.cy
            view = QRectF(-dx / scale, -dy / scale, canvas.width() / scale,
                          canvas.height() / scale)
            painter.save()
            painter.translate(dx, dy)
            painter.scale(scale, scale)
            self._layer(painter, data, 'land', lod, view, zoom,
                        fill=colours['land'], pen=_pen(colours['coast'], 0.8),
                        closed=True)
            self._layer(painter, data, 'lakes', lod, view, zoom,
                        fill=colours['sea'], pen=_pen(colours['coast'], 0.6),
                        closed=True)
            self._layer(painter, data, 'rivers', lod, view, zoom,
                        pen=_pen(colours['river'], 1.0))
            self._layer(painter, data, 'states', lod, view, zoom,
                        pen=_pen(colours['state'], 0.8, Qt.DashLine),
                        least_zoom=3)
            self._layer(painter, data, 'borders', lod, view, zoom,
                        pen=_pen(colours['border'], 1.1))
            painter.restore()
        painter.save()          # label fonts must not reach the footer
        self._labels(painter, canvas, data, zoom, scale, colours)
        painter.restore()

    def _layer(self, painter, data, layer, lod, view, zoom, fill=None,
               pen=None, closed=False, least_zoom=0):
        if zoom < least_zoom:
            return
        painter.setPen(pen if pen is not None else Qt.NoPen)
        painter.setBrush(fill if fill is not None else Qt.NoBrush)
        for index, feature in enumerate(data[layer].get(lod, ())):
            min_zoom = feature[0]
            if zoom < min_zoom:
                continue
            box = QRectF(feature[1], feature[2], feature[3] - feature[1],
                         feature[4] - feature[2])
            if not box.intersects(view) and not (
                    box.width() == 0 or box.height() == 0):
                continue
            painter.drawPath(self._path(layer, lod, index, feature, closed))

    def _labels(self, painter, canvas, data, zoom, scale, colours):
        taken = []
        drawn = 0
        width, height = canvas.width(), canvas.height()
        base = QFont(painter.font())

        metrics_of = {}

        def place(text, sx, sy, font, colour, dot=None):
            nonlocal drawn
            # Most candidates are off screen or under another name: those
            # are settled by position and an estimate, before any outline
            # is built (an outline per candidate made a repaint 0.85 s).
            if not (-200 < sx < width + 200 and -30 < sy < height + 30):
                return
            key = id(font)
            if key not in metrics_of:
                painter.setFont(font)
                metrics_of[key] = painter.fontMetrics()
            metrics = metrics_of[key]
            # Wide enough for letter spacing and capitals, which the
            # metrics' advance can leave out (names overlapped).
            w = metrics.horizontalAdvance(text) * 1.15 + 2
            h = metrics.height()
            left = sx + 5 if dot is not None else sx - w / 2
            top = sy - h / 2
            rect = QRectF(left, top, w, h)
            if rect.right() < 0 or rect.left() > width or \
                    rect.bottom() < 0 or rect.top() > height:
                return
            if any(rect.intersects(other) for other in taken):
                return
            # Room for the halo (3 px) all round: names on adjacent lines
            # had the lower one's first letter under the upper one's halo.
            taken.append(rect.adjusted(-4, -4, 4, 4))
            outline = QPainterPath()
            outline.addText(0, 0, font, text)
            shape = outline.boundingRect()
            if dot is None:
                left = sx - shape.width() / 2
            if dot is not None:
                painter.setPen(Qt.NoPen)
                painter.setBrush(colours['dot'])
                painter.drawEllipse(QPointF(sx, sy), dot, dot)
            # A halo in the land colour keeps a name readable over lines.
            outline.translate(left - shape.left(), top - shape.top())
            painter.strokePath(outline, QPen(colours['halo'], 3))
            painter.fillPath(outline, colour)
            drawn += 1

        country_font = QFont(base)
        country_font.setPointSizeF(max(7.5, base.pointSizeF()))
        country_font.setCapitalization(QFont.AllUppercase)
        country_font.setLetterSpacing(QFont.PercentageSpacing, 108)
        capital_font = QFont(base)
        capital_font.setBold(True)
        town_font = QFont(base)
        town_font.setPointSizeF(max(7.0, base.pointSizeF() - 0.5))
        for offset in canvas._copies():
            dx = width / 2 - canvas.cx + offset
            dy = height / 2 - canvas.cy
            # Countries first while zoomed out (they are the map then),
            # cities first once zoomed in.
            groups = [('countries', zoom < 6), ('places', True),
                      ('countries', zoom >= 6)]
            for group, wanted in groups:
                if not wanted:
                    continue
                for row in data[group]:
                    if drawn >= MAX_LABELS:
                        return
                    if group == 'countries':
                        name, x, y, min_zoom = row
                        if zoom < min_zoom - 1 or zoom > 9:
                            continue
                        place(name, x * scale + dx, y * scale + dy,
                              country_font, colours['country'])
                    else:
                        name, x, y, min_zoom, _pop, capital = row
                        if zoom < min_zoom:
                            continue
                        place(name, x * scale + dx, y * scale + dy,
                              capital_font if capital else town_font,
                              colours['city'], dot=3 if capital else 2)


def _pen(colour, width, style=Qt.SolidLine):
    pen = QPen(colour, width, style)
    pen.setCosmetic(True)           # width in pixels, whatever the scale
    return pen

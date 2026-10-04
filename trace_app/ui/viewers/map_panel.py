"""Map: where the case's located evidence was (core/geo.py) -- photographs'
GPS and any activity record with a position -- on a map, with the list
below it.

A Triage sub-tab. Offline by default: the points are drawn over Natural
Earth's land outline and a latitude/longitude grid, which needs no
network. **Map Tiles** fetches OpenStreetMap's tiles for the area on
screen, after saying what that discloses: every tile request tells the
tile server which area is being looked at, from this address, and when.
The examiner's yes is asked once per session and written to the case's
audit trail. Tiles are kept in memory only.

Landing on a point -- in the list, or a click on the map -- previews its
file, like every other Triage list; double-click goes to the file.
"""

import logging
import math

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView,
                               QLabel, QPushButton, QSizePolicy, QSplitter,
                               QTableWidget, QTableWidgetItem, QToolTip,
                               QVBoxLayout, QWidget)

from trace_app import __version__
from trace_app.core import geo
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.paths import resource_path
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview

logger = logging.getLogger('TRACE.MapPanel')

USER_AGENT = (f"TRACE/{__version__} (digital forensics toolkit; "
              "+https://github.com/Gadzhovski/TRACE-Forensic-Toolkit)")
#: Tiles kept in memory before the oldest are dropped.
TILE_CACHE = 512
#: A click this close to a point picks it.
PICK_RADIUS = 9

#: Point colours by kind; the selected point is drawn in the theme's
#: highlight colour.
KIND_COLOURS = {'photo': '#e8590c', 'activity': '#1c7ed6'}


class MapCanvas(QWidget):
    """The map itself: Web Mercator at a whole zoom level, centred on a
    world pixel."""

    point_clicked = Signal(int)
    point_activated = Signal(int)
    #: (fetched, failed) tile counts, for the status line.
    tiles_changed = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mapCanvas")
        self.setMouseTracking(True)
        self.setMinimumHeight(220)
        self.setFocusPolicy(Qt.StrongFocus)
        self.points = []
        self.selected = None
        self.zoom = geo.MIN_ZOOM
        self.cx, self.cy = geo.project(20.0, 0.0, self.zoom)
        self._land = None
        self._drag = None
        self._moved = False
        # Tiles: off until the examiner agrees.
        self.tiles_enabled = False
        self.style = geo.DEFAULT_STYLE
        #: (zoom, x, y) -> [url per layer, base first]; replaced in tests.
        self.tile_urls = lambda z, x, y: geo.tile_urls(z, x, y, self.style)
        self._network = None
        self._tiles = {}
        self._pending = {}
        self._failed = set()
        self.fetched = 0

    # --- state -------------------------------------------------------------

    def set_points(self, points):
        self.points = points
        self.selected = None
        self.fit()

    def fit(self):
        """Show every point (the world when there are none)."""
        zoom, lat, lon = geo.fit([(p['latitude'], p['longitude'])
                                  for p in self.points],
                                 max(self.width(), 300),
                                 max(self.height(), 220))
        zoom = min(zoom, self.max_zoom())
        self.zoom = zoom
        self.cx, self.cy = geo.project(lat, lon, zoom)
        self.update()

    def centre_on(self, index):
        point = self.points[index]
        self.selected = index
        x, y = geo.project(point['latitude'], point['longitude'], self.zoom)
        # Only move when the point is off screen: re-centring on every
        # click makes a list impossible to follow on the map.
        sx, sy = self._screen(x, y)
        if not (20 <= sx <= self.width() - 20 and
                20 <= sy <= self.height() - 20):
            self.cx, self.cy = x, y
        self.update()

    def set_zoom(self, zoom, anchor=None):
        zoom = max(geo.MIN_ZOOM, min(self.max_zoom(), zoom))
        if zoom == self.zoom:
            return
        anchor = anchor or QPointF(self.width() / 2, self.height() / 2)
        # Keep the place under the cursor where it is.
        wx = self.cx + anchor.x() - self.width() / 2
        wy = self.cy + anchor.y() - self.height() / 2
        lat, lon = geo.unproject(wx, wy, self.zoom)
        self.zoom = zoom
        nx, ny = geo.project(lat, lon, zoom)
        self.cx = nx - (anchor.x() - self.width() / 2)
        self.cy = ny - (anchor.y() - self.height() / 2)
        self.update()

    def _screen(self, x, y):
        return (x - self.cx + self.width() / 2,
                y - self.cy + self.height() / 2)

    def _world_width(self):
        return geo.TILE_SIZE * 2 ** self.zoom

    def _copies(self):
        """Horizontal offsets of the world copies on screen: panning past
        the date line keeps showing land and points."""
        width = self._world_width()
        left = self.cx - self.width() / 2
        first = math.floor(left / width)
        last = math.floor((left + self.width()) / width)
        return [n * width for n in range(first, last + 1)]

    # --- tiles ---------------------------------------------------------------

    def enable_tiles(self, enabled):
        self.tiles_enabled = enabled
        if not enabled:
            for reply in list(self._pending.values()):
                reply.abort()
            self._pending.clear()
        else:
            self._fit_zoom()
        self.update()

    def set_style(self, style):
        """Draw tiles in another of geo.TILE_STYLES."""
        if style == self.style:
            return
        self.style = style
        self._fit_zoom()
        self.update()

    def _fit_zoom(self):
        """Back within the levels the tiles are drawn at."""
        if self.zoom > self.max_zoom():
            self.set_zoom(self.max_zoom())

    def max_zoom(self):
        if self.tiles_enabled:
            return min(geo.MAX_ZOOM,
                       geo.TILE_STYLES.get(self.style, {})
                       .get('max_zoom', geo.MAX_ZOOM))
        return geo.MAX_ZOOM

    def _tile(self, x, y):
        """{layer index: pixmap} of one tile's layers that have arrived;
        the rest are requested."""
        x = x % 2 ** self.zoom
        layers = {}
        for layer, url in enumerate(self.tile_urls(self.zoom, x, y)):
            key = (self.style, layer, self.zoom, x, y)
            pixmap = self._tiles.get(key)
            if pixmap is not None:
                layers[layer] = pixmap
            elif key not in self._pending and key not in self._failed:
                self._request(key, url)
        return layers

    def _request(self, key, url):
        from PySide6.QtNetwork import (QNetworkAccessManager,
                                       QNetworkRequest)
        if self._network is None:
            self._network = QNetworkAccessManager(self)
        request = QNetworkRequest(QUrl(url))
        request.setHeader(QNetworkRequest.KnownHeaders.UserAgentHeader,
                          USER_AGENT)
        reply = self._network.get(request)
        self._pending[key] = reply
        reply.finished.connect(lambda: self._tile_arrived(key, reply))

    def _tile_arrived(self, key, reply):
        self._pending.pop(key, None)
        from PySide6.QtNetwork import QNetworkReply
        if reply.error() == QNetworkReply.NetworkError.NoError:
            pixmap = QPixmap()
            if pixmap.loadFromData(QByteArray(reply.readAll())):
                if len(self._tiles) >= TILE_CACHE:
                    self._tiles.pop(next(iter(self._tiles)))
                self._tiles[key] = pixmap
                self.fetched += 1
            else:
                self._failed.add(key)
        elif reply.error() != QNetworkReply.NetworkError.OperationCanceledError:
            logger.info("Map tile %s not fetched: %s", key,
                        reply.errorString())
            self._failed.add(key)
        reply.deleteLater()
        self.tiles_changed.emit(self.fetched, len(self._failed))
        self.update()

    # --- painting --------------------------------------------------------------

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        palette = self.palette()
        base = palette.color(palette.ColorRole.Base)
        text = palette.color(palette.ColorRole.Text)
        painter.fillRect(self.rect(), base)
        if self.tiles_enabled:
            self._paint_tiles(painter)
        else:
            self._paint_land(painter, text)
            self._paint_grid(painter, text)
        self._paint_points(painter, palette)
        self._paint_footer(painter, text, base)

    def _paint_tiles(self, painter):
        size = geo.TILE_SIZE
        for x, y in geo.visible_tiles(self.cx, self.cy, self.width(),
                                      self.height(), self.zoom):
            sx, sy = self._screen(x * size, y * size)
            # Base first, then labels over it -- and labels only over a
            # base: alone they would float on an empty background.
            layers = self._tile(x, y)
            if 0 not in layers:
                continue
            for layer in sorted(layers):
                painter.drawPixmap(QPointF(sx, sy), layers[layer])

    def _paint_land(self, painter, text):
        if self._land is None:
            self._land = geo.land_rings(resource_path('resources',
                                                      'world_land.json'))
        fill = QColor(text)
        fill.setAlpha(28)
        edge = QColor(text)
        edge.setAlpha(80)
        painter.setPen(QPen(edge, 0.8))
        painter.setBrush(fill)
        path = QPainterPath()
        for ring in self._land:
            for index, (lon, lat) in enumerate(ring):
                x, y = geo.project(lat, lon, self.zoom)
                sx, sy = self._screen(x, y)
                if index:
                    path.lineTo(sx, sy)
                else:
                    path.moveTo(sx, sy)
            path.closeSubpath()
        for offset in self._copies():
            painter.drawPath(path.translated(offset, 0))

    def _paint_grid(self, painter, text):
        line = QColor(text)
        line.setAlpha(35)
        label = QColor(text)
        label.setAlpha(140)
        step = geo.graticule_step(self.zoom)
        top_lat, left_lon = geo.unproject(self.cx - self.width() / 2,
                                          self.cy - self.height() / 2,
                                          self.zoom)
        bottom_lat, right_lon = geo.unproject(self.cx + self.width() / 2,
                                              self.cy + self.height() / 2,
                                              self.zoom)
        font = painter.font()
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        painter.setFont(font)
        lon = math.floor(left_lon / step) * step
        while lon <= right_lon:
            x, _y = self._screen(*geo.project(0, lon, self.zoom))
            painter.setPen(line)
            painter.drawLine(QPointF(x, 0), QPointF(x, self.height()))
            painter.setPen(label)
            wrapped = (lon + 180) % 360 - 180
            painter.drawText(QPointF(x + 3, 12), _degrees(wrapped, 'EW'))
            lon += step
        lat = math.floor(bottom_lat / step) * step
        while lat <= min(top_lat, geo.MAX_LATITUDE):
            if lat >= -geo.MAX_LATITUDE:
                _x, y = self._screen(*geo.project(lat, 0, self.zoom))
                painter.setPen(line)
                painter.drawLine(QPointF(0, y), QPointF(self.width(), y))
                painter.setPen(label)
                painter.drawText(QPointF(3, y - 3), _degrees(lat, 'NS'))
            lat += step

    def _paint_points(self, painter, palette):
        highlight = palette.color(palette.ColorRole.Highlight)
        outline = palette.color(palette.ColorRole.Base)
        order = [i for i in range(len(self.points)) if i != self.selected]
        if self.selected is not None:
            order.append(self.selected)       # drawn last, on top
        for offset in self._copies():
            for index in order:
                point = self.points[index]
                x, y = geo.project(point['latitude'], point['longitude'],
                                   self.zoom)
                sx, sy = self._screen(x + offset, y)
                if not (-10 <= sx <= self.width() + 10 and
                        -10 <= sy <= self.height() + 10):
                    continue
                chosen = index == self.selected
                painter.setPen(QPen(outline, 2))
                painter.setBrush(highlight if chosen else
                                 QColor(KIND_COLOURS.get(point['kind'],
                                                         '#888888')))
                radius = 7 if chosen else 5
                painter.drawEllipse(QPointF(sx, sy), radius, radius)

    def _paint_footer(self, painter, text, base):
        notes = []
        if self.tiles_enabled:
            notes.append(geo.TILE_STYLES[self.style]['attribution'])
        else:
            notes.append("Offline outline: Natural Earth")
        note = ' · '.join(notes)
        metrics = painter.fontMetrics()
        width = metrics.horizontalAdvance(note) + 10
        box = QRectF(self.width() - width - 4, self.height() - 18, width, 16)
        back = QColor(base)
        back.setAlpha(200)
        painter.setPen(Qt.NoPen)
        painter.setBrush(back)
        painter.drawRect(box)
        painter.setPen(text)
        painter.drawText(box, Qt.AlignCenter, note)

    # --- the mouse ----------------------------------------------------------------

    def _point_at(self, position):
        best, best_distance = None, PICK_RADIUS
        for offset in self._copies():
            for index, point in enumerate(self.points):
                x, y = geo.project(point['latitude'], point['longitude'],
                                   self.zoom)
                sx, sy = self._screen(x + offset, y)
                distance = math.hypot(sx - position.x(), sy - position.y())
                if distance <= best_distance:
                    best, best_distance = index, distance
        return best

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag = event.position()
            self._moved = False

    def mouseMoveEvent(self, event):
        if self._drag is not None and event.buttons() & Qt.LeftButton:
            delta = event.position() - self._drag
            if abs(delta.x()) + abs(delta.y()) > 2:
                self._moved = True
            if self._moved:
                self.cx -= delta.x()
                self.cy -= delta.y()
                self._drag = event.position()
                self.update()
            return
        index = self._point_at(event.position())
        if index is None:
            QToolTip.hideText()
            return
        point = self.points[index]
        QToolTip.showText(event.globalPosition().toPoint(),
                          f"{point['name']}\n{point['what']}\n"
                          f"{point['when'] or 'no time recorded'}\n"
                          f"{geo.describe(point['latitude'], point['longitude'])}",
                          self)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and not self._moved:
            index = self._point_at(event.position())
            if index is not None:
                self.selected = index
                self.update()
                self.point_clicked.emit(index)
        self._drag = None

    def mouseDoubleClickEvent(self, event):
        index = self._point_at(event.position())
        if index is not None:
            self.point_activated.emit(index)
        else:
            self.set_zoom(self.zoom + 1, event.position())

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        if steps:
            self.set_zoom(self.zoom + (1 if steps > 0 else -1),
                          event.position())

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key_Plus, Qt.Key_Equal):
            self.set_zoom(self.zoom + 1)
        elif key == Qt.Key_Minus:
            self.set_zoom(self.zoom - 1)
        else:
            super().keyPressEvent(event)


def _degrees(value, hemispheres):
    if abs(value) < 1e-9:
        return '0°'
    text = f"{abs(value):.3f}".rstrip('0').rstrip('.')
    return f"{text}°{hemispheres[0] if value > 0 else hemispheres[1]}"


class MapPanel(QWidget):
    #: A point's dict ('kind', 'row', ...) when the examiner lands on it.
    point_selected = Signal(dict)
    point_activated = Signal(dict)
    point_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mapPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self.points = []
        #: Tile servers the examiner agreed to this session. Asked per
        #: server: a yes to one is not a yes to another.
        self.allowed_hosts = set()
        #: How the panel asks before fetching tiles -- ask(style) -> bool;
        #: replaced in tests.
        self.ask = self._ask_for_tiles
        #: A style the examiner picked; until then it follows the theme.
        self._style_chosen = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setSizePolicy(QSizePolicy.Ignored,
                                        QSizePolicy.Preferred)
        bar.addWidget(self.status_label, 1)
        self.fit_button = QPushButton("Show All")
        self.fit_button.setToolTip("Zoom to every located item")
        bar.addWidget(self.fit_button)
        self.style_combo = QComboBox()
        self.style_combo.setObjectName("mapStyleCombo")
        for key, style in geo.TILE_STYLES.items():
            self.style_combo.addItem(style['label'], key)
            self.style_combo.setItemData(
                self.style_combo.count() - 1,
                f"Tiles from {style['host']}", Qt.ToolTipRole)
        self.style_combo.setToolTip("How map tiles are drawn. Light and "
                                    "dark follow TRACE's theme until "
                                    "another is chosen.")
        bar.addWidget(self.style_combo)
        self.tiles_button = QPushButton("Map Tiles")
        self.tiles_button.setCheckable(True)
        self.tiles_button.setToolTip(
            "Draw a map under the points. Fetches tiles for the area on "
            "screen from the chosen style's server; asks first.")
        bar.addWidget(self.tiles_button)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setObjectName("indicatorSplitter")
        layout.addWidget(splitter, 1)
        self.canvas = MapCanvas()
        splitter.addWidget(self.canvas)
        self.table = self._table(['Name', 'Kind', 'Evidence', 'When',
                                  'Position', 'Source', 'Path'])
        connect_row_preview(self.table, self._row_landed)
        self.table.itemDoubleClicked.connect(
            lambda item: self.point_activated.emit(
                self.points[self.table.item(item.row(), 0)
                            .data(Qt.UserRole)]))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        splitter.addWidget(self.table)
        splitter.setSizes([340, 200])

        self.fit_button.clicked.connect(self.canvas.fit)
        self.tiles_button.toggled.connect(self._tiles_toggled)
        self._follow_theme()
        self.style_combo.activated.connect(self._style_picked)
        self.canvas.point_clicked.connect(self._select_row)
        self.canvas.point_activated.connect(
            lambda index: self.point_activated.emit(self.points[index]))
        self.canvas.tiles_changed.connect(lambda *_a: self._set_status())
        self.refresh()

    @staticmethod
    def _table(headers):
        table = QTableWidget()
        table.setObjectName("triageTable")
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setItemDelegate(NoFocusDelegate(table))
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    # --- what to show ----------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self.refresh()

    def shutdown(self):
        self.canvas.enable_tiles(False)

    def refresh(self):
        self.points = geo.located(self.case, self.evidence_id) \
            if self.case is not None else []
        table = self.table
        table.setRowCount(len(self.points))
        for row, point in enumerate(self.points):
            cells = [point['name'], geo.KIND_LABELS.get(point['kind'], ''),
                     self._names.get(point['evidence_id'], ''),
                     str(point['when'] or ''),
                     geo.describe(point['latitude'], point['longitude']),
                     point['source'], point['path']]
            for column, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, row)
                table.setItem(row, column, item)
        for column, width in enumerate((200, 110, 140, 150, 210, 120)):
            table.setColumnWidth(column, width)
        self.canvas.set_points(self.points)
        self._set_status()
        self.count_changed.emit(len(self.points))

    def _set_status(self):
        if self.case is None:
            text = "Located evidence is kept in a case."
        elif not self.points:
            text = ("Nothing in this case records where it was yet. Photos "
                    "with GPS appear here once the photo metadata module "
                    "has run.")
        else:
            photos = sum(1 for p in self.points if p['kind'] == 'photo')
            others = len(self.points) - photos
            parts = [f"{photos:,} photo(s) with GPS"] if photos else []
            if others:
                parts.append(f"{others:,} activity record(s)")
            text = ' and '.join(parts) + " on the map"
            if self.canvas.tiles_enabled:
                text += (f" · {self.canvas.fetched:,} tile(s) from "
                         f"{self._host()}")
                if self.canvas._failed:
                    text += f", {len(self.canvas._failed):,} not fetched"
            else:
                text += " · offline: no map tiles fetched"
        self.status_label.setText(text)
        self.status_label.setToolTip(text)

    # --- selection ---------------------------------------------------------------

    def _row_landed(self, index):
        self.canvas.centre_on(index)
        self.point_selected.emit(self.points[index])

    def _select_row(self, index):
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).data(Qt.UserRole) == index:
                self.table.selectRow(row)
                self.table.scrollToItem(self.table.item(row, 0))
                return

    def _menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        index = self.table.item(item.row(), 0).data(Qt.UserRole)
        self.point_menu_requested.emit(
            self.points[index], self.table.viewport().mapToGlobal(position))

    # --- tiles --------------------------------------------------------------------

    def _host(self):
        return geo.TILE_STYLES[self.canvas.style]['host']

    def _set_style(self, style):
        index = self.style_combo.findData(style)
        if index >= 0:
            self.style_combo.setCurrentIndex(index)
        self.canvas.set_style(style)

    def _follow_theme(self):
        """Light tiles in the light theme, dark in the dark -- until the
        examiner picks a style."""
        if self._style_chosen:
            return
        from trace_app.infra.theme import read_theme
        self._set_style(geo.THEME_STYLES.get(read_theme(),
                                             geo.DEFAULT_STYLE))

    def changeEvent(self, event):
        from PySide6.QtCore import QEvent
        if event.type() in (QEvent.PaletteChange, QEvent.StyleChange):
            self._follow_theme()
        super().changeEvent(event)

    def _style_picked(self, _index):
        style = self.style_combo.currentData()
        previous = self.canvas.style
        if self.canvas.tiles_enabled and not self._agreed(style):
            self._set_style(previous)       # a no keeps what was shown
            return
        self._style_chosen = True
        self._set_style(style)
        self._set_status()

    def _agreed(self, style):
        """Whether tiles may come from `style`'s server: asked once per
        server per session, a yes written to the audit trail."""
        host = geo.TILE_STYLES[style]['host']
        if host in self.allowed_hosts:
            return True
        if not self.ask(style):
            return False
        self.allowed_hosts.add(host)
        if self.case is not None:
            self.case.record_event(
                "Map tiles fetched",
                f"from {host} for the areas viewed in the Map tab (the tile "
                f"server sees which areas, from this computer's address)")
        return True

    def _tiles_toggled(self, on):
        if on and not self._agreed(self.canvas.style):
            self.tiles_button.blockSignals(True)
            self.tiles_button.setChecked(False)
            self.tiles_button.blockSignals(False)
            return
        self.canvas.enable_tiles(on)
        self._set_status()

    def _ask_for_tiles(self, style):
        from trace_app.ui.dialogs import message
        chosen = geo.TILE_STYLES[style]
        return message.question(
            self, "Fetch map tiles?",
            f"Draw the map from {chosen['host']} "
            f"({chosen['label'].split(' (')[0].lower()} style)?",
            informative=(
                "Tiles are requested for the area on screen, so the tile "
                "server learns which areas you look at -- zoomed in on a "
                "photo, roughly where it was taken -- from this computer's "
                "internet address, and when. No file, name or list of "
                "positions is sent. Tiles are kept in memory only.\n\n"
                "Without tiles the points are drawn over an offline "
                "outline of the world."))

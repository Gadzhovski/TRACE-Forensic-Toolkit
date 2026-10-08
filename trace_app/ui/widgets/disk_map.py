"""A disk image drawn as a disk: a platter whose ring is the image's regions,
a bar of the same regions from first sector to last, and a table of them.

The regions come from core/disk_layout.py -- every sector once, tables and
unallocated runs named for what they are. A region too small to see (a
512-byte partition table on a 500 GB disk) is still drawn: it gets a
minimum arc or width, and its true size and share stay in the table and
tooltip. Hovering or clicking a region marks it in all three.
"""

import math

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QIcon, QPainter,
                           QPainterPath, QPen, QPixmap, QRadialGradient)
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QTableWidget, QTableWidgetItem,
                               QToolButton, QToolTip, QVBoxLayout, QWidget)

from trace_app.core import disk_layout
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

#: A region's colour swatch in the table, in pixels.
SWATCH = 14
#: The smallest share of the ring or bar a region is drawn with.
MIN_ARC_DEGREES = 3.0
MIN_BAR_PIXELS = 6

_FAMILIES = (('ntfs', '#3B82C4'), ('exfat', '#2AA198'), ('fat', '#3FA34D'),
             ('ext', '#8E6CC9'), ('hfs', '#D9822B'), ('apfs', '#E0A03A'),
             ('xfs', '#C2507A'), ('iso', '#B08D57'), ('ufs', '#7A8F3A'),
             ('yaffs', '#5C9EAD'), ('btrfs', '#4E8F7A'))


def region_colour(region):
    """The colour a region is drawn in: by file system for a volume."""
    theme = icons.current_theme()
    if region['kind'] == disk_layout.TABLE:
        return QColor('#5B6B7F')
    if region['kind'] == disk_layout.UNALLOCATED:
        return QColor('#68707B' if theme == 'dark' else '#C9CED6')
    if region.get('encryption'):
        return QColor('#C9A227')
    name = (region.get('name') or '').lower()
    for family, colour in _FAMILIES:
        if name.startswith(family):
            return QColor(colour)
    return QColor('#6E7681')


def describe(region, total_bytes):
    """A region in words, for a tooltip."""
    share = 100.0 * region['bytes'] / total_bytes if total_bytes else 0
    lines = [disk_layout.label(region),
             f"{FileSystemUtils.get_readable_size(region['bytes'])} "
             f"({region['bytes']:,} bytes) · {share_text(share)}",
             f"Sectors {region['start']:,} – "
             f"{region['start'] + region['sectors'] - 1:,} "
             f"({region['sectors']:,})"]
    if region.get('description') and region['kind'] == disk_layout.VOLUME:
        lines.append(f"Slot: {region['description']}")
    return '\n'.join(lines)


def share_text(percent):
    if percent == 0:
        return "0%"
    if percent < 0.01:
        return "< 0.01%"
    if percent < 1:
        return f"{percent:.2f}%"
    return f"{percent:.1f}%"


def _fractions(regions, minimum):
    """Each region's share of the drawing: its true share, but never below
    `minimum` -- the room given to tiny regions is taken from the others in
    proportion to their size."""
    total = sum(r['bytes'] for r in regions) or 1
    true = [r['bytes'] / total for r in regions]
    small = [t < minimum for t in true]
    lifted = minimum * sum(small)
    rest = sum(t for t, s in zip(true, small) if not s)
    if lifted >= 1 or rest <= 0:
        return [1 / len(regions)] * len(regions)
    scale = (1 - lifted) / rest
    return [minimum if s else t * scale for t, s in zip(true, small)]


class _RegionView(QWidget):
    """Shared state of the platter and the bar."""

    hovered = Signal(int)
    clicked = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.regions = []
        self.total = 0
        self.highlight = -1
        self._hover = -1

    def set_regions(self, regions):
        self.regions = list(regions)
        self.total = sum(r['bytes'] for r in self.regions)
        self.highlight = -1
        self.update()

    def set_highlight(self, index):
        if index != self.highlight:
            self.highlight = index
            self.update()

    def region_at(self, point):
        raise NotImplementedError

    def mouseMoveEvent(self, event):
        index = self.region_at(event.position())
        if index != self._hover:
            self._hover = index
            self.hovered.emit(index)
            self.update()
        if index >= 0:
            QToolTip.showText(event.globalPosition().toPoint(),
                              describe(self.regions[index], self.total), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, event):
        self._hover = -1
        self.hovered.emit(-1)
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        index = self.region_at(event.position())
        if index >= 0:
            self.clicked.emit(index)

    def _marked(self, index):
        return index in (self.highlight, self._hover)


class PlatterView(_RegionView):
    """The image as a hard-disk platter: its regions round the ring, from
    twelve o'clock clockwise, a spindle hub at the centre."""

    double_clicked = Signal(int)

    def mouseDoubleClickEvent(self, event):
        index = self.region_at(event.position())
        if index >= 0:
            self.double_clicked.emit(index)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("diskPlatter")
        self.setMinimumSize(160, 160)
        # Room for the table beside it, whatever the window's width: the
        # platter gives way, the table's columns do not.
        self.setMaximumSize(230, 230)
        self._spans = []

    def sizeHint(self):
        return QSize(230, 230)

    def heightForWidth(self, width):
        return width

    def _geometry(self):
        side = min(self.width(), self.height()) - 16
        centre = QPointF(self.width() / 2, self.height() / 2)
        radius = side / 2
        return centre, radius

    def set_regions(self, regions):
        super().set_regions(regions)
        self._spans = []
        if self.regions:
            angle = 90.0
            for fraction in _fractions(self.regions, MIN_ARC_DEGREES / 360):
                sweep = fraction * 360
                self._spans.append((angle, -sweep))
                angle -= sweep

    def region_at(self, point):
        centre, radius = self._geometry()
        dx, dy = point.x() - centre.x(), centre.y() - point.y()
        distance = math.hypot(dx, dy)
        if not radius * 0.48 <= distance <= radius:
            return -1
        angle = math.degrees(math.atan2(dy, dx))
        for index, (start, sweep) in enumerate(self._spans):
            low, high = start + sweep, start
            for candidate in (angle, angle + 360, angle - 360):
                if low <= candidate <= high:
                    return index
        return -1

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        centre, radius = self._geometry()
        dark = icons.current_theme() == 'dark'

        # A soft shadow, the platter, and its brushed sheen.
        shadow = QRadialGradient(centre + QPointF(0, 4), radius + 8)
        shadow.setColorAt(0.85, QColor(0, 0, 0, 70 if dark else 40))
        shadow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(shadow)
        painter.drawEllipse(centre + QPointF(0, 4), radius + 8, radius + 8)
        platter = QRadialGradient(centre, radius)
        platter.setColorAt(0.0, QColor('#6A7079' if dark else '#F4F6F9'))
        platter.setColorAt(1.0, QColor('#2C3036' if dark else '#BCC3CD'))
        painter.setBrush(platter)
        painter.setPen(QPen(QColor('#1E2125' if dark else '#9AA3AE'), 1))
        painter.drawEllipse(centre, radius, radius)
        sheen = QConicalGradient(centre, 30)
        for stop, alpha in ((0.0, 0), (0.12, 40), (0.25, 0), (0.5, 0),
                            (0.62, 40), (0.75, 0), (1.0, 0)):
            sheen.setColorAt(stop, QColor(255, 255, 255, alpha))
        painter.setBrush(sheen)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(centre, radius - 1, radius - 1)

        # The regions: a ring of arcs, a hairline of platter between them.
        outer, inner = radius * 0.94, radius * 0.50
        edge = QColor('#2C3036' if dark else '#E9ECF1')
        for index, (start, sweep) in enumerate(self._spans):
            region = self.regions[index]
            lift = 4 if self._marked(index) else 0
            path = self._arc(centre, outer + lift, inner, start, sweep)
            colour = region_colour(region)
            if self._marked(index):
                colour = colour.lighter(118)
            painter.setBrush(colour)
            painter.setPen(QPen(edge, 1))
            painter.drawPath(path)
            if region['kind'] == disk_layout.UNALLOCATED:
                painter.setBrush(QBrush(QColor(0, 0, 0, 40),
                                        Qt.BDiagPattern))
                painter.setPen(Qt.NoPen)
                painter.drawPath(path)

        # Data tracks: faint rings over the regions, as a platter has.
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(255, 255, 255, 28), 1))
        for step in range(1, 6):
            r = inner + (outer - inner) * step / 6
            painter.drawEllipse(centre, r, r)

        # The spindle hub, with its clamp screws.
        hub = radius * 0.30
        gradient = QRadialGradient(centre - QPointF(hub / 3, hub / 3),
                                   hub * 1.4)
        gradient.setColorAt(0.0, QColor('#9AA1AB' if dark else '#FFFFFF'))
        gradient.setColorAt(1.0, QColor('#3A3F46' if dark else '#AEB6C1'))
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor('#1E2125' if dark else '#8C96A3'), 1))
        painter.drawEllipse(centre, hub, hub)
        painter.setBrush(QColor('#23272C' if dark else '#7D8794'))
        painter.setPen(Qt.NoPen)
        for screw in range(6):
            angle = math.radians(screw * 60 + 30)
            point = centre + QPointF(math.cos(angle) * hub * 0.62,
                                     math.sin(angle) * hub * 0.62)
            painter.drawEllipse(point, hub * 0.07, hub * 0.07)
        painter.setBrush(QColor('#15181B' if dark else '#5E6875'))
        painter.drawEllipse(centre, hub * 0.22, hub * 0.22)
        painter.end()

    @staticmethod
    def _arc(centre, outer, inner, start, sweep):
        path = QPainterPath()
        box = QRectF(centre.x() - outer, centre.y() - outer, outer * 2,
                     outer * 2)
        hole = QRectF(centre.x() - inner, centre.y() - inner, inner * 2,
                      inner * 2)
        path.arcMoveTo(box, start)
        path.arcTo(box, start, sweep)
        path.arcTo(hole, start + sweep, -sweep)
        path.closeSubpath()
        return path


class DiskBar(_RegionView):
    """The regions in disk order, first sector at the left -- and a zoom
    into any part of it: the wheel zooms round the pointer, dragging pans,
    double-clicking a region fits it. Zoomed in, a 512-byte table is as
    wide as anything else on screen."""

    #: (first sector, end sector) shown, or the whole disk.
    window_changed = Signal(int, int)
    #: The fewest sectors the bar zooms to.
    MIN_SPAN = 8

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("diskBar")
        self.setFixedHeight(40)
        self.setCursor(Qt.OpenHandCursor)
        self._cells = []            # (QRectF, region index)
        self.window = None          # (lo, hi) sectors, or None: everything
        self._press = None

    def disk_sectors(self):
        return sum(r['sectors'] for r in self.regions)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout()

    def set_regions(self, regions):
        super().set_regions(regions)
        self.window = None
        self._layout()

    # --- the window --------------------------------------------------------------

    def span(self):
        lo, hi = self.window or (0, self.disk_sectors())
        return lo, hi

    def set_window(self, lo, hi):
        total = self.disk_sectors()
        span = max(self.MIN_SPAN, min(int(hi - lo), total))
        lo = int(max(0, min(lo, total - span)))
        self.window = None if span >= total else (lo, lo + span)
        self._layout()
        self.update()
        self.window_changed.emit(*self.span())

    def zoom(self, factor, anchor_x=None):
        """Zoom by `factor` (> 1 in), keeping the sector under `anchor_x`
        where it is."""
        lo, hi = self.span()
        span = hi - lo
        width = max(1.0, self.width() - 2)
        x = width / 2 if anchor_x is None else anchor_x
        pivot = lo + span * min(max(x / width, 0.0), 1.0)
        new = span / factor
        ratio = (pivot - lo) / span if span else 0.5
        self.set_window(pivot - new * ratio, pivot - new * ratio + new)

    def fit(self):
        self.set_window(0, self.disk_sectors())

    def zoom_to(self, index):
        """Show region `index` across about a third of the bar, with its
        neighbours either side."""
        if not 0 <= index < len(self.regions):
            return
        region = self.regions[index]
        span = max(self.MIN_SPAN, region['sectors'] * 3)
        centre = region['start'] + region['sectors'] / 2
        self.set_window(centre - span / 2, centre + span / 2)
        self.set_highlight(index)

    # --- drawing --------------------------------------------------------------

    def _layout(self):
        self._cells = []
        width = max(1, self.width() - 2)
        if not self.regions:
            return
        lo, hi = self.span()
        shown = []
        for index, region in enumerate(self.regions):
            begin = max(region['start'], lo)
            end = min(region['start'] + region['sectors'], hi)
            if end > begin:
                shown.append((index, dict(region, bytes=end - begin)))
        if not shown:
            return
        x = 1.0
        for (index, _clip), fraction in zip(
                shown, _fractions([c for _i, c in shown],
                                  MIN_BAR_PIXELS / width)):
            self._cells.append((QRectF(x, 1, fraction * width,
                                       self.height() - 2), index))
            x += fraction * width

    def region_at(self, point):
        for cell, index in self._cells:
            if cell.contains(point):
                return index
        return -1

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        dark = icons.current_theme() == 'dark'
        frame = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        clip = QPainterPath()
        clip.addRoundedRect(frame, 5, 5)
        painter.setClipPath(clip)
        edge = QColor('#2C3036' if dark else '#FFFFFF')
        marked = None
        for cell, index in self._cells:
            region = self.regions[index]
            colour = region_colour(region)
            if self._marked(index):
                colour = colour.lighter(118)
            painter.fillRect(cell, colour)
            if region['kind'] == disk_layout.UNALLOCATED:
                painter.fillRect(cell, QBrush(QColor(0, 0, 0, 40),
                                              Qt.BDiagPattern))
            painter.setPen(QPen(edge, 1))
            painter.drawLine(cell.topRight(), cell.bottomRight())
            text = f"{disk_layout.label(region)}  " \
                   f"{FileSystemUtils.get_readable_size(region['bytes'])}"
            metrics = painter.fontMetrics()
            if metrics.horizontalAdvance(text) + 12 > cell.width():
                text = FileSystemUtils.get_readable_size(region['bytes'])
            if metrics.horizontalAdvance(text) + 12 <= cell.width():
                light = colour.lightness() > 150
                painter.setPen(QColor('#1B1F24' if light else '#FFFFFF'))
                painter.drawText(cell.adjusted(6, 0, -6, 0),
                                 Qt.AlignVCenter | Qt.AlignLeft, text)
            if index == self.highlight:
                marked = cell
        painter.setClipping(False)
        painter.setPen(QPen(QColor('#1E2125' if dark else '#AEB6C1'), 1))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(frame, 5, 5)
        if marked is not None:
            painter.setPen(QPen(QColor('#FFFFFF' if dark else '#1B1F24'), 2))
            painter.drawRect(marked.adjusted(1, 1, -1, -1))
        painter.end()

    # --- the mouse --------------------------------------------------------------

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        if steps:
            self.zoom(1.35 ** steps, event.position().x())
        event.accept()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._press = (event.position().x(), self.span())
            self.setCursor(Qt.ClosedHandCursor)

    def mouseMoveEvent(self, event):
        if self._press is not None and event.buttons() & Qt.LeftButton:
            x, (lo, hi) = self._press
            moved = event.position().x() - x
            if abs(moved) > 2 and self.window is not None:
                per_pixel = (hi - lo) / max(1, self.width())
                self.set_window(lo - moved * per_pixel,
                                hi - moved * per_pixel)
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self.setCursor(Qt.OpenHandCursor)
        if self._press is not None and \
                abs(event.position().x() - self._press[0]) <= 2:
            index = self.region_at(event.position())
            if index >= 0:
                self.clicked.emit(index)
        self._press = None

    def mouseDoubleClickEvent(self, event):
        index = self.region_at(event.position())
        if index >= 0:
            self.zoom_to(index)
            self.clicked.emit(index)


class DiskMap(QWidget):
    """The platter beside the table of regions, the bar under both."""

    #: The sector count is in each row's tooltip: five columns left the
    #: region's own name no room.
    COLUMNS = ['Region', 'Size', 'Share', 'Start sector']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("diskMap")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(14)
        self.platter = PlatterView()
        top.addWidget(self.platter)
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setObjectName("diskMapTable")
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setShowGrid(False)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        # The region takes what the numbers leave; the numbers fit theirs.
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in range(1, len(self.COLUMNS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.setTextElideMode(Qt.ElideRight)
        # One line a region: wrapping broke "FAT16 volume" over two lines
        # the row had no height for, and showed "FAT16 …".
        self.table.setWordWrap(False)
        self.table.setIconSize(QSize(SWATCH, SWATCH))
        self.table.cellDoubleClicked.connect(
            lambda row, _column: self.bar.zoom_to(row))
        top.addWidget(self.table, 1)
        layout.addLayout(top, 1)

        # Over the bar: what it shows, and zoom.
        controls = QHBoxLayout()
        controls.setSpacing(4)
        self.caption = QLabel()
        self.caption.setObjectName("diskBarCaption")
        controls.addWidget(self.caption, 1)
        hint = QLabel("Wheel to zoom · drag to pan · double-click a region "
                      "to fit it")
        hint.setObjectName("diskBarCaption")
        controls.addWidget(hint)
        self.zoom_out_button = self._zoom_button(
            icons.ZOOM_OUT, "Zoom out", lambda: self.bar.zoom(1 / 2))
        self.zoom_in_button = self._zoom_button(
            icons.ZOOM_IN, "Zoom in", lambda: self.bar.zoom(2))
        self.fit_button = self._zoom_button(
            icons.ZOOM_ACTUAL, "Whole disk", lambda: self.bar.fit())
        for button in (self.zoom_out_button, self.zoom_in_button,
                       self.fit_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.bar = DiskBar()
        self.bar.window_changed.connect(self._window_changed)
        layout.addWidget(self.bar)

        for view in (self.platter, self.bar):
            view.clicked.connect(self.select)
            view.hovered.connect(self._hovered)
        self.platter.double_clicked.connect(self.bar.zoom_to)
        self.table.itemSelectionChanged.connect(self._table_selected)
        self.regions = []

    def _zoom_button(self, icon_name, tip, slot):
        button = QToolButton()
        button.setObjectName("diskZoomButton")
        icons.apply_to(button, icon_name)
        button.setToolTip(tip)
        button.setAutoRaise(True)
        button.clicked.connect(slot)
        return button

    def _window_changed(self, lo, hi):
        total = self.bar.disk_sectors()
        if not total or (lo, hi) == (0, total):
            self.caption.setText(f"Whole disk · {total:,} sectors")
        else:
            share = 100.0 * (hi - lo) / total
            self.caption.setText(f"Sectors {lo:,} – {hi - 1:,}  "
                                 f"({share_text(share)} of the disk)")

    def set_regions(self, regions):
        self.regions = list(regions)
        total = sum(r['bytes'] for r in self.regions)
        self.platter.set_regions(self.regions)
        self.bar.set_regions(self.regions)
        self._window_changed(*self.bar.span())
        self.table.setRowCount(len(self.regions))
        for row, region in enumerate(self.regions):
            share = 100.0 * region['bytes'] / total if total else 0
            name = QTableWidgetItem(disk_layout.label(region))
            name.setIcon(self._swatch(region_colour(region)))
            name.setToolTip(describe(region, total))
            cells = [name,
                     QTableWidgetItem(FileSystemUtils.get_readable_size(
                         region['bytes'])),
                     QTableWidgetItem(share_text(share)),
                     QTableWidgetItem(f"{region['start']:,}")]
            for cell in cells[1:]:
                cell.setToolTip(describe(region, total))
            for column in range(1, len(cells)):
                cells[column].setTextAlignment(Qt.AlignRight |
                                               Qt.AlignVCenter)
            for column, cell in enumerate(cells):
                self.table.setItem(row, column, cell)
        self._fit_table()

    def _fit_table(self):
        """Wide enough for every column's longest entry, so nothing is cut
        off when the window is narrow -- the platter shrinks instead. Each
        column as Qt's own delegate sizes it (icon, padding, the theme's
        font), and the region's name measured again as a floor: done when
        shown too, since the theme's font arrives then."""
        from PySide6.QtGui import QFontMetrics
        table = self.table
        table.ensurePolished()
        header = table.horizontalHeader()
        needed = 0
        for column in range(table.columnCount()):
            needed += max(table.sizeHintForColumn(column),
                          header.sectionSizeHint(column)) + 8
        metrics = QFontMetrics(table.font())
        longest = max((metrics.horizontalAdvance(table.item(r, 0).text())
                       for r in range(table.rowCount())
                       if table.item(r, 0) is not None), default=0)
        needed = max(needed, longest + SWATCH + 48 +
                     sum(max(table.sizeHintForColumn(c),
                             header.sectionSizeHint(c)) + 8
                         for c in range(1, table.columnCount())))
        scroll = table.verticalScrollBar().sizeHint().width()
        table.setMinimumWidth(needed + scroll + 2 * table.frameWidth() + 4)

    def showEvent(self, event):
        super().showEvent(event)
        self._fit_table()

    @staticmethod
    def _swatch(colour):
        """A rounded square of the region's colour, drawn at the screen's
        pixel density -- a 14-pixel bitmap scaled up on a high-DPI screen
        came out blurred and jagged."""
        from PySide6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen()
        ratio = max(2.0, screen.devicePixelRatio() if screen else 1.0)
        side = int(round(SWATCH * ratio))
        pixmap = QPixmap(side, side)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.scale(ratio, ratio)
        painter.setBrush(colour)
        painter.setPen(QPen(colour.darker(130), 1))
        painter.drawRoundedRect(QRectF(1.5, 1.5, SWATCH - 3, SWATCH - 3),
                                3, 3)
        painter.end()
        pixmap.setDevicePixelRatio(ratio)
        return QIcon(pixmap)

    def select(self, index):
        if 0 <= index < self.table.rowCount():
            self.table.selectRow(index)

    def _table_selected(self):
        rows = self.table.selectionModel().selectedRows()
        index = rows[0].row() if rows else -1
        self.platter.set_highlight(index)
        self.bar.set_highlight(index)

    def _hovered(self, index):
        # The table follows the pointer only by marking, not by moving the
        # selection: hovering must not change what is selected.
        for view in (self.platter, self.bar):
            if view._hover != index:
                view._hover = index
                view.update()

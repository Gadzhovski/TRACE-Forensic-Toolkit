"""The Timeline tab: every event the case knows of, in one place, in order.

Built from core/timeline.py. The parts:

* a histogram strip -- how many events per bucket, stacked by source.
  Drag across it to zoom to that span, click a bar to zoom into it, wheel to
  zoom around the pointer, Back to undo a zoom, double-click for the whole
  case. The selected event is marked on it;
* filters -- a time range (with presets around the selected event), a
  source per chip with its count, one image or all, text, deleted only,
  timestomped only, known-good files hidden, $SI / $FN times;
* pivots, from an event's menu -- events around it, every event of the same
  file, of the same user, in the same folder; each shows as a chip that
  removes it;
* the table, and beside it every fact about the selected event (for a file,
  both sets of NTFS times side by side and any hash-set match);
* CSV export of what the filters select, saved views, and "Add to Report".

A click previews the event's file without leaving the tab, as in Triage; a
double-click goes to it. Queries run on a thread with their own read-only
connection: a case with NTFS times is millions of rows.
"""

import html
import json
import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QDateTime, QModelIndex,
                            QPointF, QRectF, Qt, QThread, QTimer, QTimeZone,
                            Signal)
from PySide6.QtGui import (QColor, QFont, QGuiApplication, QIcon, QPainter,
                           QPixmap)
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDateTimeEdit, QFileDialog, QHBoxLayout,
                               QHeaderView, QInputDialog, QLabel, QLineEdit,
                               QMenu, QPushButton, QSizePolicy, QSplitter,
                               QTableView, QTextBrowser, QToolBar,
                               QToolButton, QToolTip, QVBoxLayout, QWidget)

from trace_app.core import timeline
from trace_app.core.case import CASE_DB_NAME
from trace_app.infra.constants import PANEL_ICON_SIZE, TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.widgets.toolbars import prepare_toolbar

logger = logging.getLogger('TRACE.Timeline')

#: Most rows read into the table at once. The histogram always counts all
#: of them; zooming in or filtering reaches the rest.
SHOWN_LIMIT = 100_000

_COLUMNS = ('Time (UTC)', 'Source', 'Type', 'Description', 'Path / subject',
            'User', 'Evidence')

_PIVOTS = (('± 1 minute', 60), ('± 5 minutes', 300), ('± 1 hour', 3600),
           ('± 1 day', 86400), ('± 1 week', 7 * 86400))


def source_icon(source, size=12):
    """A dot in the source's colour."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(timeline.SOURCE_COLOURS.get(source, '#888888')))
    painter.drawEllipse(1, 1, size - 2, size - 2)
    painter.end()
    return QIcon(pixmap)


def _description(row):
    if row['title']:
        return row['title']
    subject = row['subject'] or ''
    return subject.rsplit('/', 1)[-1] if row['source'] in ('fs',) else subject


# --- the model -------------------------------------------------------------------

class TimelineModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.names = {}
        self._icons = {}

    def set_rows(self, rows, names):
        self.beginResetModel()
        self.rows, self.names = rows, names
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return _COLUMNS[section]
        return None

    def cell(self, row, column):
        if column == 0:
            return f"{row['time']} (local)" if row['local'] else row['time']
        if column == 1:
            return timeline.SOURCE_LABELS.get(row['source'], row['source'])
        if column == 2:
            return timeline.describe_kind(row)
        if column == 3:
            return _description(row)
        if column == 4:
            return row['subject'] or ''
        if column == 5:
            return row['user'] or ''
        if column == 6:
            return self.names.get(row['evidence_id'], '') \
                if row['evidence_id'] is not None else ''
        return ''

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self.cell(row, column)
        if role == Qt.DecorationRole and column == 1:
            icon = self._icons.get(row['source'])
            if icon is None:
                icon = self._icons[row['source']] = source_icon(row['source'])
            return icon
        if role == Qt.ToolTipRole:
            if column == 0 and row['local']:
                return ("Local time of the machine or camera that wrote it: "
                        "the source keeps no time zone.")
            if row['deleted'] and column in (3, 4):
                return f"{self.cell(row, column)}\n(deleted)"
            return self.cell(row, column) or None
        if role == Qt.FontRole and row['deleted']:
            font = QFont()
            font.setItalic(True)
            return font
        if role == Qt.UserRole:
            return row
        return None


# --- the histogram ------------------------------------------------------------------

class TimelineHistogram(QWidget):
    """Events per bucket, stacked by source; drag or click to zoom."""

    range_selected = Signal(str, str)
    zoom_requested = Signal(float, float)       # centre fraction, factor
    reset_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineHistogram")
        self.setMinimumHeight(96)
        self.setMaximumHeight(120)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.buckets = {}
        self.unit = 'day'
        self.start = self.end = None
        self.marker = None
        self._drag_from = None
        self._drag_to = None
        self._bars = []             # (QRectF, bucket text, counts)

    def set_data(self, buckets, unit, start, end):
        self.buckets, self.unit = buckets or {}, unit
        self.start, self.end = timeline.parse(start), timeline.parse(end)
        self.update()

    def set_marker(self, time_text):
        self.marker = timeline.parse(time_text)
        self.update()

    def _plot(self):
        return QRectF(8, 6, max(10, self.width() - 16),
                      max(10, self.height() - 26))

    def _x(self, moment, plot):
        span = (self.end - self.start).total_seconds() or 1
        offset = (moment - self.start).total_seconds()
        return plot.left() + plot.width() * offset / span

    def _moment(self, x, plot):
        span = (self.end - self.start).total_seconds()
        fraction = min(1, max(0, (x - plot.left()) / plot.width()))
        import datetime
        return self.start + datetime.timedelta(seconds=span * fraction)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)
        palette = self.palette()
        base = palette.color(palette.ColorRole.Base)
        text = palette.color(palette.ColorRole.Text)
        grid = QColor(text)
        grid.setAlpha(40)
        painter.fillRect(self.rect(), base)
        plot = self._plot()
        painter.setPen(grid)
        painter.drawLine(plot.bottomLeft(), plot.bottomRight())
        self._bars = []
        if not self.start or not self.end or self.end <= self.start:
            painter.setPen(text)
            painter.drawText(self.rect(), Qt.AlignCenter, "No events")
            return
        totals = [sum(c.values()) for c in self.buckets.values()]
        peak = max(totals) if totals else 0
        order = [key for key, _l, _c in timeline.SOURCES]
        for bucket, counts in sorted(self.buckets.items()):
            first = timeline.bucket_start(bucket)
            if first is None:
                continue
            last = timeline.step(first, self.unit)
            left = max(plot.left(), self._x(first, plot))
            right = min(plot.right(), self._x(last, plot))
            if right <= plot.left() or left >= plot.right():
                continue
            width = max(1.0, right - left - (1 if right - left > 3 else 0))
            y = plot.bottom()
            for source in order:
                number = counts.get(source, 0)
                if not number:
                    continue
                # Square root: one install day of 50,000 events would
                # otherwise flatten every other day to nothing. The
                # tooltip gives the exact counts.
                height = max(1.5, plot.height() * (number ** 0.5)
                             / (peak ** 0.5)) if peak else 0
                height = min(height, y - plot.top())
                painter.fillRect(QRectF(left, y - height, width, height),
                                 QColor(timeline.SOURCE_COLOURS[source]))
                y -= height
            self._bars.append((QRectF(left, plot.top(), max(width, 2),
                                      plot.height()), bucket, counts))
        # Axis: the range's ends and a few ticks between.
        painter.setPen(text)
        font = painter.font()
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        painter.setFont(font)
        labels = 5 if self.width() > 700 else 3
        for i in range(labels):
            moment = self._moment(plot.left() + plot.width() * i
                                  / (labels - 1), plot)
            label = self._label(moment)
            x = plot.left() + plot.width() * i / (labels - 1)
            metrics = painter.fontMetrics()
            w = metrics.horizontalAdvance(label)
            x = min(max(plot.left(), x - w / 2), plot.right() - w)
            painter.drawText(QPointF(x, self.height() - 5), label)
        if self.marker and self.start <= self.marker <= self.end:
            x = self._x(self.marker, plot)
            accent = palette.color(palette.ColorRole.Highlight)
            painter.setPen(accent)
            painter.drawLine(QPointF(x, plot.top() - 2),
                             QPointF(x, plot.bottom()))
        if self._drag_from is not None and self._drag_to is not None:
            band = palette.color(palette.ColorRole.Highlight)
            band.setAlpha(70)
            left, right = sorted((self._drag_from, self._drag_to))
            painter.fillRect(QRectF(left, plot.top(), right - left,
                                    plot.height()), band)

    def _label(self, moment):
        span = (self.end - self.start).total_seconds()
        if span > 3 * 365 * 86400:
            return moment.strftime('%Y')
        if span > 90 * 86400:
            return moment.strftime('%Y-%m')
        if span > 2 * 86400:
            return moment.strftime('%Y-%m-%d')
        if span > 120:
            return moment.strftime('%m-%d %H:%M')
        return moment.strftime('%H:%M:%S')

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.start:
            self._drag_from = self._drag_to = event.position().x()

    def mouseMoveEvent(self, event):
        x = event.position().x()
        if self._drag_from is not None:
            self._drag_to = x
            self.update()
            return
        for rect, bucket, counts in self._bars:
            if rect.left() <= x <= rect.right():
                lines = [bucket] + [
                    f"{timeline.SOURCE_LABELS[s]}: {counts[s]:,}"
                    for s, _l, _c in timeline.SOURCES if counts.get(s)]
                QToolTip.showText(event.globalPosition().toPoint(),
                                  '\n'.join(lines), self)
                return
        QToolTip.hideText()

    def mouseReleaseEvent(self, event):
        if self._drag_from is None:
            return
        plot = self._plot()
        left, right = sorted((self._drag_from, event.position().x()))
        self._drag_from = self._drag_to = None
        self.update()
        if right - left >= 4:
            first, last = self._moment(left, plot), self._moment(right, plot)
            self.range_selected.emit(timeline.text(first),
                                     timeline.text(last))
            return
        for rect, bucket, _counts in self._bars:
            if rect.left() <= left <= rect.right():
                first = timeline.bucket_start(bucket)
                last = timeline.step(first, self.unit)
                self.range_selected.emit(timeline.text(first),
                                         timeline.text(last))
                return

    def mouseDoubleClickEvent(self, _event):
        self._drag_from = self._drag_to = None
        self.reset_requested.emit()

    def wheelEvent(self, event):
        if not self.start:
            return
        plot = self._plot()
        fraction = min(1, max(0, (event.position().x() - plot.left())
                              / plot.width()))
        factor = 0.5 if event.angleDelta().y() > 0 else 2.0
        self.zoom_requested.emit(fraction, factor)


# --- loading -----------------------------------------------------------------------

class _Load(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, filters, find_bounds,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.find_bounds = filters, find_bounds

    def run(self):
        result = {'rows': [], 'counts': {}, 'histogram': {}, 'total': 0,
                  'bounds': None, 'outside': 0, 'error': ''}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                         timeout=10)
            try:
                filters = dict(self.filters)
                if self.find_bounds or not filters.get('start'):
                    first, last, outside = timeline.bounds(connection,
                                                           filters)
                    result['bounds'] = (first, last)
                    result['outside'] = outside
                    if first:
                        unit = timeline.unit_for(first, last)
                        begin = timeline.floor(timeline.parse(first), unit)
                        finish = timeline.step(timeline.floor(
                            timeline.parse(last), unit), unit)
                        filters['start'] = timeline.text(begin)
                        filters['end'] = timeline.text(finish)
                result['filters'] = filters
                if filters.get('start'):
                    unit = timeline.unit_for(filters['start'],
                                             filters['end'])
                    result['unit'] = unit
                    result['histogram'] = timeline.histogram(
                        connection, filters, unit)
                result['counts'] = timeline.source_counts(connection,
                                                          filters)
                result['total'] = sum(
                    n for s, n in result['counts'].items()
                    if s in (filters.get('sources') or ()))
                result['rows'] = timeline.events(connection, filters,
                                                 SHOWN_LIMIT)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read the timeline: %s", exc)
            result['error'] = str(exc)
        self.loaded.emit(self.generation, result)


class _Export(QThread):
    done = Signal(int, str, str)

    def __init__(self, folder, filters, path, names, parent=None):
        super().__init__(parent)
        self.folder, self.filters, self.path, self.names = \
            folder, filters, path, names

    def run(self):
        try:
            connection = sqlite3.connect(
                f'file:{os.path.join(self.folder, CASE_DB_NAME)}?mode=ro',
                uri=True, timeout=10)
            try:
                rows = timeline.write_csv(connection, self.filters, self.path,
                                          self.names)
            finally:
                connection.close()
        except Exception as exc:        # reported, never left hanging
            logger.error("Timeline export failed: %s", exc)
            self.done.emit(0, self.path, str(exc) or type(exc).__name__)
            return
        self.done.emit(rows, self.path, '')


# --- the panel ------------------------------------------------------------------

class TimelinePanel(QWidget):
    row_selected = Signal(dict)
    row_activated = Signal(dict)
    #: (rows, title) -- the host adds them to the report.
    report_requested = Signal(list)
    #: The CSV was written: (path, rows), for the audit trail.
    exported = Signal(str, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelinePanel")
        self.case = None
        self._names = {}
        self.filters = timeline.default_filters()
        self._history = []
        self._generation = 0
        self._loads = {}
        self._dirty = True
        self._export = None
        self.counts = {}
        self.total = 0
        #: Set by the host: menu_extender(menu, row) adds its own actions
        #: (Show in Listing, bookmark, VirusTotal).
        self.menu_extender = None
        #: Set by the host: detail_extender(row) -> extra HTML for the pane.
        self.detail_extender = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        icon_label = QLabel()
        icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(icon_label, icons.TIMELINE, PANEL_ICON_SIZE)
        self.toolbar.addWidget(icon_label)
        title = QLabel("Timeline")
        title.setObjectName("panelTitle")
        self.toolbar.addWidget(title)
        self.status_label = QLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Preferred)
        self.toolbar.addWidget(self.status_label)
        self.evidence_filter = QComboBox()
        self.evidence_filter.setObjectName("triageEvidenceFilter")
        self.evidence_filter.setToolTip("Every image in the case, or one.")
        self.evidence_filter.currentIndexChanged.connect(
            self._evidence_changed)
        self.toolbar.addWidget(self.evidence_filter)
        self.views_button = QPushButton("Views")
        self.views_button.setObjectName("triageRunButton")
        self.views_button.setToolTip("Save these filters as a named view, "
                                     "or go back to one")
        self.views_button.setMenu(QMenu(self.views_button))
        self.views_button.menu().aboutToShow.connect(self._fill_views_menu)
        self.toolbar.addWidget(self.views_button)
        self.export_button = QPushButton("Export CSV…")
        self.export_button.setObjectName("triageRunButton")
        self.export_button.setToolTip("Every event the filters select -- "
                                      "not only the rows shown")
        self.export_button.clicked.connect(self.export_csv)
        self.toolbar.addWidget(self.export_button)
        outer.addWidget(self.toolbar)

        body = QVBoxLayout()
        body.setContentsMargins(6, 4, 6, 4)
        body.setSpacing(4)
        outer.addLayout(body, 1)

        # Range and text.
        row = QHBoxLayout()
        row.setSpacing(6)
        self.back_button = QToolButton()
        self.back_button.setObjectName("timelineBack")
        self.back_button.setIcon(icons.icon(icons.BACK))
        self.back_button.setToolTip("Back to the previous range")
        self.back_button.clicked.connect(self.back)
        row.addWidget(self.back_button)
        row.addWidget(QLabel("From"))
        self.from_edit = self._time_edit()
        row.addWidget(self.from_edit)
        row.addWidget(QLabel("to"))
        self.to_edit = self._time_edit()
        row.addWidget(self.to_edit)
        apply_range = QToolButton()
        apply_range.setObjectName("timelineApply")
        apply_range.setText("Go")
        apply_range.setToolTip("Show this range (UTC)")
        apply_range.clicked.connect(self._range_typed)
        row.addWidget(apply_range)
        self.range_button = QToolButton()
        self.range_button.setObjectName("timelineRangeButton")
        self.range_button.setText("Range")
        self.range_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.range_button.setPopupMode(QToolButton.InstantPopup)
        range_menu = QMenu(self.range_button)
        range_menu.addAction("Whole case").triggered.connect(self.reset_range)
        range_menu.addSeparator()
        for label, seconds in _PIVOTS:
            range_menu.addAction(f"Selected event {label}").triggered \
                .connect(lambda _c=False, s=seconds: self.around_selected(s))
        self.range_button.setMenu(range_menu)
        row.addWidget(self.range_button)
        row.addStretch(1)
        self.fs_combo = QComboBox()
        self.fs_combo.setObjectName("timelineFsCombo")
        for label, value in (("$SI and $FN times", 'both'),
                             ("$STANDARD_INFORMATION only", 'SI'),
                             ("$FILE_NAME only", 'FN')):
            self.fs_combo.addItem(label, value)
        self.fs_combo.setToolTip("Which NTFS times the File system source "
                                 "shows")
        self.fs_combo.currentIndexChanged.connect(self._fs_changed)
        row.addWidget(self.fs_combo)
        self.text_input = QLineEdit()
        self.text_input.setObjectName("activityFilter")
        self.text_input.setPlaceholderText("Filter…")
        self.text_input.setClearButtonEnabled(True)
        self.text_input.setMaximumWidth(260)
        self._text_timer = QTimer(self)
        self._text_timer.setSingleShot(True)
        self._text_timer.setInterval(350)
        self._text_timer.timeout.connect(self._text_changed)
        self.text_input.textChanged.connect(
            lambda _t: self._text_timer.start())
        row.addWidget(self.text_input)
        body.addLayout(row)

        # Sources and switches.
        row = QHBoxLayout()
        row.setSpacing(4)
        self.source_buttons = {}
        for key, label, _colour in timeline.SOURCES:
            button = QToolButton()
            button.setObjectName("timelineSourceChip")
            button.setCheckable(True)
            button.setChecked(key in self.filters['sources'])
            button.setIcon(source_icon(key))
            button.setText(label)
            button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            button.toggled.connect(self._sources_changed)
            self.source_buttons[key] = button
            row.addWidget(button)
        row.addSpacing(10)
        self.deleted_box = QCheckBox("Deleted only")
        self.deleted_box.setToolTip("Deleted files' $MFT times, and "
                                    "deletions in the change journal")
        self.deleted_box.toggled.connect(
            lambda on: self._set_filter('deleted_only', on))
        row.addWidget(self.deleted_box)
        self.stomped_box = QCheckBox("Timestomped only")
        self.stomped_box.setToolTip("Files whose times look set by hand "
                                    "(Triage ▸ NTFS)")
        self.stomped_box.toggled.connect(
            lambda on: self._set_filter('timestomped_only', on))
        row.addWidget(self.stomped_box)
        self.known_good_box = QCheckBox("Hide known good")
        self.known_good_box.setToolTip("Leave out files matching a "
                                       "known-good hash set (NSRL)")
        self.known_good_box.toggled.connect(
            lambda on: self._set_filter('hide_known_good', on))
        row.addWidget(self.known_good_box)
        row.addStretch(1)
        body.addLayout(row)

        # Pivots in force, each removable.
        self.pivot_row = QHBoxLayout()
        self.pivot_row.setSpacing(4)
        self.pivot_holder = QWidget()
        self.pivot_holder.setLayout(self.pivot_row)
        self.pivot_holder.setVisible(False)
        body.addWidget(self.pivot_holder)

        self.histogram = TimelineHistogram()
        self.histogram.range_selected.connect(self.set_range)
        self.histogram.zoom_requested.connect(self._zoom)
        self.histogram.reset_requested.connect(self.reset_range)
        body.addWidget(self.histogram)

        self.model = TimelineModel(self)
        self.table = QTableView()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((205, 130, 200, 240, 380, 90)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._landed(current))
        self.table.clicked.connect(self._landed)
        self.table.doubleClicked.connect(self._activated)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)

        self.detail = QTextBrowser()
        self.detail.setObjectName("timelineDetail")
        self.detail.setOpenLinks(False)
        self.detail.setMinimumWidth(240)
        self.detail.setPlaceholderText(
            "Select an event to see everything about it -- for a file, "
            "both sets of NTFS times side by side and what Triage found.")

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("timelineSplitter")
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([900, 320])
        body.addWidget(splitter, 1)

        self.set_case(None)

    @staticmethod
    def _time_edit():
        edit = QDateTimeEdit()
        edit.setObjectName("timelineTimeEdit")
        edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        edit.setTimeZone(QTimeZone.utc())
        edit.setCalendarPopup(True)
        edit.setMinimumDateTime(QDateTime.fromString(
            "1601-01-01 00:00:00", "yyyy-MM-dd HH:mm:ss"))
        return edit

    # --- the case ------------------------------------------------------------

    @property
    def loading(self):
        return bool(self._loads)

    def set_case(self, case):
        """Show `case`; the query itself waits until the tab is seen."""
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        self.evidence_filter.blockSignals(True)
        self.evidence_filter.clear()
        self.evidence_filter.addItem("All evidence", None)
        for evidence_id, name in sorted(self._names.items(),
                                        key=lambda kv: kv[1].lower()):
            self.evidence_filter.addItem(name, evidence_id)
        index = self.evidence_filter.findData(self.filters.get('evidence_id'))
        self.evidence_filter.setCurrentIndex(max(index, 0))
        self.filters['evidence_id'] = self.evidence_filter.currentData()
        self.evidence_filter.blockSignals(False)
        self.evidence_filter.setVisible(len(self._names) > 1)
        options = self._hash_options()
        self.known_good_box.blockSignals(True)
        self.known_good_box.setEnabled(bool(options.get('enabled')))
        self.known_good_box.setChecked(bool(options.get('enabled') and
                                            options.get('hide_known_good')))
        self.filters['hide_known_good'] = self.known_good_box.isChecked()
        self.known_good_box.blockSignals(False)
        for widget in (self.export_button, self.views_button):
            widget.setEnabled(case is not None)
        self._dirty = True
        if self.isVisible():
            self.refresh()
        elif case is None:
            self.model.set_rows([], {})
            self.status_label.setText("The timeline is built from a case. "
                                      "File ▸ New Case starts one.")

    def _hash_options(self):
        if self.case is None:
            return {}
        try:
            from trace_app.core import hashsets
            return hashsets.case_options(self.case)
        except Exception:
            return {}

    def showEvent(self, event):
        super().showEvent(event)
        if self._dirty:
            self.refresh()

    # --- filters ---------------------------------------------------------------

    def _set_filter(self, key, value, keep_range=True):
        self.filters[key] = value
        self.refresh(find_bounds=not keep_range)

    def _evidence_changed(self, _index):
        self.filters['evidence_id'] = self.evidence_filter.currentData()
        self.refresh()

    def _fs_changed(self, _index):
        self._set_filter('fs_attributes', self.fs_combo.currentData())

    def _text_changed(self):
        self._set_filter('text', self.text_input.text().strip())

    def _sources_changed(self, _on):
        self.filters['sources'] = [k for k, b in self.source_buttons.items()
                                   if b.isChecked()]
        self.refresh()

    def set_range(self, start, end, remember=True):
        if not start or not end or start >= end:
            return
        if remember:
            self._history.append((self.filters.get('start'),
                                  self.filters.get('end')))
        self.filters['start'], self.filters['end'] = start, end
        self.refresh()

    def reset_range(self):
        self.refresh(find_bounds=True)

    def back(self):
        if not self._history:
            return
        start, end = self._history.pop()
        self.filters['start'], self.filters['end'] = start, end
        self.refresh(find_bounds=start is None)

    def _zoom(self, fraction, factor):
        first = timeline.parse(self.filters.get('start'))
        last = timeline.parse(self.filters.get('end'))
        if not first or not last:
            return
        import datetime
        span = (last - first).total_seconds()
        centre = first + datetime.timedelta(seconds=span * fraction)
        half = max(1, span * factor / 2)
        start = centre - datetime.timedelta(seconds=half * fraction * 2)
        end = start + datetime.timedelta(seconds=half * 2)
        self.set_range(timeline.text(start), timeline.text(end))

    def _range_typed(self):
        start = self.from_edit.dateTime().toUTC().toString(
            "yyyy-MM-dd HH:mm:ss")
        end = self.to_edit.dateTime().toUTC().toString("yyyy-MM-dd HH:mm:ss")
        self.set_range(start, end)

    def around_selected(self, seconds):
        row = self.current_row()
        if row is None:
            return
        start, end = timeline.around(row['time'], seconds)
        self.set_range(start, end)

    def add_pivot(self, key, value, label):
        """Narrow to a file, a user or a folder."""
        self.filters[key] = value
        self._show_pivots()
        self.refresh(find_bounds=True)

    def _show_pivots(self):
        while self.pivot_row.count():
            item = self.pivot_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        shown = False
        for key, label in (('focus_ref', 'File'), ('user', 'User'),
                           ('folder', 'Folder')):
            value = self.filters.get(key)
            if not value:
                continue
            text = value[1] if key == 'focus_ref' else value
            if key == 'focus_ref':
                text = getattr(self, '_focus_label', text)
            chip = QToolButton()
            chip.setObjectName("timelinePivotChip")
            chip.setText(f"{label}: {text}  ✕")
            chip.setToolTip("Remove this filter")
            chip.clicked.connect(lambda _c=False, k=key: self._drop_pivot(k))
            self.pivot_row.addWidget(chip)
            shown = True
        self.pivot_row.addStretch(1)
        self.pivot_holder.setVisible(shown)

    def _drop_pivot(self, key):
        self.filters[key] = None
        self._show_pivots()
        self.refresh(find_bounds=True)

    # --- loading -----------------------------------------------------------------

    def refresh(self, find_bounds=False):
        if self.case is None:
            self.model.set_rows([], {})
            self.histogram.set_data({}, 'day', None, None)
            self.status_label.setText("The timeline is built from a case. "
                                      "File ▸ New Case starts one.")
            self._dirty = False
            return
        self._dirty = False
        if find_bounds and self.filters.get('start'):
            # The range follows what is now selected; Back returns to it.
            self._history.append((self.filters.get('start'),
                                  self.filters.get('end')))
            self.filters['start'] = self.filters['end'] = None
        self._generation += 1
        load = _Load(self.case.folder, self._generation, dict(self.filters),
                     find_bounds, self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        self.status_label.setText("Loading…")
        load.start()

    def _loaded(self, generation, result):
        self._loads.pop(generation, None)
        if generation != self._generation:
            return
        filters = result.get('filters') or self.filters
        if filters.get('start') and not self.filters.get('start'):
            self.filters['start'], self.filters['end'] = \
                filters['start'], filters['end']
        self.counts = result['counts']
        self.total = result['total']
        self.model.set_rows(result['rows'], self._names)
        self.histogram.set_data(result['histogram'], result.get('unit',
                                                                'day'),
                                self.filters.get('start'),
                                self.filters.get('end'))
        self._show_range()
        for key, button in self.source_buttons.items():
            button.setText(f"{timeline.SOURCE_LABELS[key]} "
                           f"({self.counts.get(key, 0):,})")
        self.back_button.setEnabled(bool(self._history))
        self.status_label.setText(self._status(result))

    def _status(self, result):
        if result.get('error'):
            return f"Could not read the timeline: {result['error']}"
        if not self.total and not any(self.counts.values()):
            filters = self.filters
            if any(filters.get(k) for k in ('text', 'focus_ref', 'user',
                                             'folder', 'deleted_only',
                                             'timestomped_only')):
                return "Nothing matches these filters."
            return ("Nothing to show yet. The timeline is built from "
                    "Analysis ▸ Run Analysis Modules: NTFS times and the "
                    "change journal, activity, photo and document dates.")
        shown = len(result['rows'])
        text = f"{self.total:,} event(s) in this range"
        if shown < self.total:
            text += (f"; the first {shown:,} listed — zoom in on the "
                     f"histogram or filter to reach the rest")
        if result.get('outside'):
            text += (f". {result['outside']:,} dated before "
                     f"{timeline.PLAUSIBLE_FROM[:4]} or in the future are "
                     f"outside the view (type a range to see them)")
        return text

    def _show_range(self):
        for edit, value in ((self.from_edit, self.filters.get('start')),
                            (self.to_edit, self.filters.get('end'))):
            if value:
                moment = QDateTime.fromString(value[:19],
                                              "yyyy-MM-dd HH:mm:ss")
                moment.setTimeZone(QTimeZone.utc())
                edit.setDateTime(moment)

    # --- rows ---------------------------------------------------------------------

    def current_row(self):
        index = self.table.currentIndex()
        if not index.isValid():
            return None
        return self.model.data(index, Qt.UserRole)

    def selected_rows(self):
        rows = sorted({index.row() for index in
                       self.table.selectionModel().selectedRows()})
        return [self.model.rows[r] for r in rows]

    def _payload(self, row):
        """The row as the host's preview/open take it."""
        subject = row['subject'] or ''
        name = row['title'] or subject.rsplit('/', 1)[-1]
        payload = {'artifact_ref': row['artifact_ref'],
                   'evidence_id': row['evidence_id'],
                   'name': name, 'path': subject,
                   'label': timeline.describe_kind(row),
                   'summary': f"{row['time']} — {timeline.describe_kind(row)}"}
        if row['source'] == 'activity':
            try:
                extra = json.loads(row['extra'] or '{}')
            except ValueError:
                extra = {}
            path = extra.get('source_path') or ''
            payload['name'] = path.replace('\\', '/').rsplit('/', 1)[-1]
            payload['path'] = path
        return payload

    def _landed(self, index):
        if index is None or not index.isValid():
            return
        row = self.model.data(index, Qt.UserRole)
        if not row:
            return
        self.histogram.set_marker(row['time'])
        self._show_detail(row)
        if row['artifact_ref'] and row['evidence_id'] is not None:
            self.row_selected.emit(self._payload(row))

    def _activated(self, index):
        row = self.model.data(index, Qt.UserRole)
        if row and row['artifact_ref'] and row['evidence_id'] is not None:
            self.row_activated.emit(self._payload(row))

    def _show_detail(self, row):
        e = html.escape
        lines = [f"<h3>{e(timeline.describe_kind(row))}</h3>",
                 "<table cellspacing='2'>"]

        def add(label, value):
            if value not in (None, ''):
                lines.append(f"<tr><td><b>{e(label)}</b></td>"
                             f"<td>{e(str(value))}</td></tr>")
        add("Time", row['time'] + (" (local, no zone)" if row['local']
                                    else " UTC"))
        add("Source", timeline.SOURCE_LABELS.get(row['source']))
        add("Description", _description(row))
        add("Path / subject", row['subject'])
        add("User", row['user'])
        add("Evidence", self._names.get(row['evidence_id']))
        add("Deleted", "yes" if row['deleted'] else None)
        try:
            extra = json.loads(row['extra'] or '{}')
        except (TypeError, ValueError):
            extra = {}
        if isinstance(extra, dict):
            detail = extra.pop('detail', None)
            for key, value in extra.items():
                if row['source'] == 'usn' and key == 'flags':
                    from trace_app.core.ntfs import usn_reason_names
                    value = f"0x{value:08x} " + ' | '.join(
                        usn_reason_names(value))
                if key in ('latitude', 'longitude', 'taken', 'make',
                           'model', 'software', 'author', 'last_saved_by',
                           'company', 'application', 'created', 'modified',
                           'usn', 'entry', 'sequence', 'parent', 'flags',
                           'offset', 'size', 'type', 'source',
                           'source_path'):
                    add(key.replace('_', ' ').capitalize(), value)
            if isinstance(detail, dict):
                for key, value in detail.items():
                    add(key, value)
        add("Reference", row['artifact_ref'])
        lines.append("</table>")
        if self.detail_extender is not None:
            try:
                lines.append(self.detail_extender(row) or '')
            except Exception as exc:
                logger.debug("Detail for %s: %s", row['artifact_ref'], exc)
        self.detail.setHtml(''.join(lines))

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.model.data(index, Qt.UserRole)
        menu = QMenu(self)
        around = menu.addMenu("Show events around this")
        for label, seconds in _PIVOTS:
            around.addAction(label).triggered.connect(
                lambda _c=False, s=seconds: self._around(row, s))
        has_file = bool(row['artifact_ref'] and row['evidence_id']
                        is not None and row['source'] != 'activity')
        same_file = menu.addAction("All events for this file")
        same_file.setEnabled(has_file)
        same_file.triggered.connect(lambda: self._focus_file(row))
        same_user = menu.addAction(
            f"Same user ({row['user']})" if row['user'] else "Same user")
        same_user.setEnabled(bool(row['user']))
        same_user.triggered.connect(
            lambda: self.add_pivot('user', row['user'], row['user']))
        folder = (row['subject'] or '').rsplit('/', 1)[0] \
            if '/' in (row['subject'] or '') else ''
        same_folder = menu.addAction("Same folder" + (
            f" ({folder})" if folder else ''))
        same_folder.setEnabled(bool(folder) and row['source'] in (
            'fs', 'usn', 'photo', 'document'))
        same_folder.triggered.connect(
            lambda: self.add_pivot('folder', folder, folder))
        menu.addSeparator()
        selected = self.selected_rows() or [row]
        report = menu.addAction(
            f"Add {len(selected)} Event(s) to Report")
        report.setIcon(icons.icon(icons.REPORT))
        report.triggered.connect(lambda: self.report_requested.emit(selected))
        copy = menu.addAction("Copy Row(s)")
        copy.triggered.connect(lambda: self._copy(selected))
        if self.menu_extender is not None and has_file:
            menu.addSeparator()
            self.menu_extender(menu, self._payload(row))
        menu.exec(self.table.viewport().mapToGlobal(point))

    def _around(self, row, seconds):
        start, end = timeline.around(row['time'], seconds)
        self.set_range(start, end)

    def _focus_file(self, row):
        self._focus_label = _description(row) or row['artifact_ref']
        self.add_pivot('focus_ref', (row['evidence_id'], row['artifact_ref']),
                       self._focus_label)

    def _copy(self, rows):
        lines = ['\t'.join(str(v) for v in timeline.csv_row(r, self._names))
                 for r in rows]
        QGuiApplication.clipboard().setText('\n'.join(lines))

    # --- export and views ------------------------------------------------------

    def export_csv(self, path=None):
        if self.case is None:
            return
        if path is None:
            default = os.path.join(self.case.folder, 'exports',
                                   'timeline.csv')
            os.makedirs(os.path.dirname(default), exist_ok=True)
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Timeline", default, "CSV (*.csv)")
            if not path:
                return
        self.export_button.setEnabled(False)
        self.status_label.setText("Exporting…")
        self._export = _Export(self.case.folder, dict(self.filters), path,
                               self._names, self)
        self._export.done.connect(self._exported)
        self._export.start()

    def _exported(self, rows, path, error):
        self._export.wait()
        self._export = None
        self.export_button.setEnabled(True)
        if error:
            self.status_label.setText(f"Export failed: {error}")
            return
        self.status_label.setText(f"Exported {rows:,} event(s) to {path}")
        self.exported.emit(path, rows)

    def _fill_views_menu(self):
        menu = self.views_button.menu()
        menu.clear()
        save = menu.addAction("Save Current View…")
        save.triggered.connect(self._save_view)
        views = (self.case.setting('timeline_views') or {}) \
            if self.case else {}
        if views:
            menu.addSeparator()
            for name in sorted(views):
                menu.addAction(name).triggered.connect(
                    lambda _c=False, n=name: self.load_view(n))
            remove = menu.addMenu("Delete View")
            for name in sorted(views):
                remove.addAction(name).triggered.connect(
                    lambda _c=False, n=name: self._delete_view(n))

    def _save_view(self):
        name, ok = QInputDialog.getText(self, "Save View", "Name:")
        if ok and name.strip():
            self.save_view(name.strip())

    def save_view(self, name):
        views = dict(self.case.setting('timeline_views') or {})
        stored = dict(self.filters)
        if stored.get('focus_ref'):
            stored['focus_ref'] = list(stored['focus_ref'])
            stored['focus_label'] = getattr(self, '_focus_label', '')
        views[name] = stored
        self.case.set_setting('timeline_views', views)

    def load_view(self, name):
        views = self.case.setting('timeline_views') or {}
        stored = views.get(name)
        if not stored:
            return
        filters = timeline.default_filters()
        filters.update(stored)
        if filters.get('focus_ref'):
            filters['focus_ref'] = tuple(filters['focus_ref'])
            self._focus_label = stored.get('focus_label') or ''
        filters.pop('focus_label', None)
        self._history.append((self.filters.get('start'),
                              self.filters.get('end')))
        self.filters = filters
        self._sync_controls()
        self._show_pivots()
        self.refresh(find_bounds=not filters.get('start'))

    def _delete_view(self, name):
        views = dict(self.case.setting('timeline_views') or {})
        views.pop(name, None)
        self.case.set_setting('timeline_views', views)

    def _sync_controls(self):
        for widget in (self.deleted_box, self.stomped_box,
                       self.known_good_box, self.text_input, self.fs_combo,
                       self.evidence_filter, *self.source_buttons.values()):
            widget.blockSignals(True)
        self.deleted_box.setChecked(bool(self.filters.get('deleted_only')))
        self.stomped_box.setChecked(bool(self.filters.get(
            'timestomped_only')))
        self.known_good_box.setChecked(bool(self.filters.get(
            'hide_known_good')))
        self.text_input.setText(self.filters.get('text') or '')
        self.fs_combo.setCurrentIndex(max(0, self.fs_combo.findData(
            self.filters.get('fs_attributes') or 'both')))
        self.evidence_filter.setCurrentIndex(max(0, self.evidence_filter
                                                 .findData(self.filters.get(
                                                     'evidence_id'))))
        for key, button in self.source_buttons.items():
            button.setChecked(key in (self.filters.get('sources') or ()))
        for widget in (self.deleted_box, self.stomped_box,
                       self.known_good_box, self.text_input, self.fs_combo,
                       self.evidence_filter, *self.source_buttons.values()):
            widget.blockSignals(False)

    def show_file(self, evidence_id, artifact_ref, label=''):
        """From elsewhere: every event of one file."""
        self._focus_label = label or artifact_ref
        self.filters['focus_ref'] = (evidence_id, artifact_ref)
        self._show_pivots()
        self.refresh(find_bounds=True)

    def shutdown(self):
        for load in list(self._loads.values()):
            load.wait(5000)
        self._loads.clear()
        if self._export is not None:
            self._export.wait(30000)


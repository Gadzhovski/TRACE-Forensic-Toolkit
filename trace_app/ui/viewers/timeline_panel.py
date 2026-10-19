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

import json
import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QByteArray, QDateTime,
                            QModelIndex, QPoint, QPointF, QRectF, Qt,
                            QThread, QTimer, QTimeZone, Signal)
from PySide6.QtGui import (QActionGroup, QBrush, QColor, QFont, QGuiApplication,
                           QPainter, QPen,
                           QStandardItem, QStandardItemModel)
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog,
                               QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QLineEdit, QMenu, QPushButton, QSizePolicy,
                               QSplitter, QTableView, QTextBrowser, QToolBar,
                               QStackedWidget, QStyle,
                               QStyledItemDelegate, QTabWidget,
                               QToolButton, QToolTip, QVBoxLayout, QWidget,
                               QWidgetAction)

from trace_app.core import timeline, timeline_export
from trace_app.core.timeline_axis import calendar_ticks  # noqa: F401 (re-exported)
from trace_app.core.case import CASE_DB_NAME
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.widgets.flow_layout import FlowLayout
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.wheel_zoom import zoom_on_wheel
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.toolbars import prepare_toolbar
from trace_app.ui.widgets.context_menus import show_menu
from trace_app.ui.process_worker import ProcessWorker
from trace_app.infra.sqlite_uri import connect_read_only

logger = logging.getLogger('TRACE.Timeline')


class FsTimesWorker(ProcessWorker):
    """One image's file-system times (core/fs_times) in a child
    process."""

    progressed = Signal(object, object, str)
    finished_fstimes = Signal(int, str)

    kind = 'fstimes'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_fstimes.emit(count, error)

#: Rows read at a time. The table holds no cap: the next page is read as
#: the view nears the end (and the one before as it nears the top, after a
#: jump), each from where the last stopped (timeline.events_after).
PAGE_ROWS = 5000

_COLUMNS = ('Time (UTC)', 'Source', 'Type', 'MACB', 'Description',
            'Path / subject', 'User', 'Evidence')
#: Column positions.
(TIME, SOURCE, TYPE, MACB, DESCRIPTION, SUBJECT, USER, EVIDENCE) = \
    range(len(_COLUMNS))
#: Each column's filter (timeline.COLUMN_FILTERS key), for the filter row.
_COLUMN_FILTER = {TIME: 'time', SOURCE: 'sources', TYPE: 'kind',
                  MACB: 'macb', DESCRIPTION: 'title', SUBJECT: 'subject',
                  USER: 'user', EVIDENCE: 'evidence_ids'}
#: How times are shown: UTC as stored, the case's display zone, or both.
TIME_MODES = (('utc', "UTC"), ('zone', "Display zone"), ('both', "Both"))

_PIVOTS = (('± 1 minute', 60), ('± 5 minutes', 300), ('± 1 hour', 3600),
           ('± 1 day', 86400), ('± 1 week', 7 * 86400))


def source_icon(source):
    """A dot in the source's colour, sharp at any size and display scale."""
    return icons.dot_icon(timeline.SOURCE_COLOURS.get(source, '#888888'))


#: A burst window's prefix length, in words.
_WINDOW_WORDS = {18: '10 seconds', 16: 'minute', 15: '10 minutes',
                 13: 'hour'}


def _description(row):
    if row['title']:
        return row['title']
    subject = row['subject'] or ''
    return subject.rsplit('/', 1)[-1] if row['source'] in ('fs',) else subject


# --- the model -------------------------------------------------------------------

def shown_time(text, mode):
    """A UTC time as the time switch shows it: as stored ('utc'), in the
    case's display zone ('zone'), or both. Zoneless local times and a case
    with no display zone are shown as they are."""
    if mode == 'utc' or not text:
        return text
    from trace_app.core.settings import alongside
    both = alongside(text)
    if mode == 'both' or '  ·  ' not in both:
        return both
    return both.split('  ·  ', 1)[1]


class TimelineModel(QAbstractTableModel):
    """The rows read so far, which grow at either end as the view scrolls
    (`more_after` / `more_before`: there are rows past them)."""

    #: The view neared the end, or the top, of the rows read.
    more_wanted = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.names = {}
        self._icons = {}
        self.time_mode = 'utc'
        #: {event_key: (starred, colour, comment)} -- the examiner's marks.
        self.marks = {}
        #: Highlight rules, compiled (timeline.compile_highlights).
        self.highlights = []
        self.more_after = False
        self.more_before = False
        self.fetching = False

    def set_rows(self, rows, names, more_after=False, more_before=False):
        self.beginResetModel()
        self.rows, self.names = rows, names
        self.more_after, self.more_before = more_after, more_before
        self.fetching = False
        self.endResetModel()

    def insert_rows(self, position, rows):
        if rows:
            self.beginInsertRows(QModelIndex(), position,
                                 position + len(rows) - 1)
            self.rows[position:position] = rows
            self.endInsertRows()

    def remove_rows(self, position, count):
        if count > 0:
            self.beginRemoveRows(QModelIndex(), position,
                                 position + count - 1)
            del self.rows[position:position + count]
            self.endRemoveRows()

    def row_changed(self, position):
        self.dataChanged.emit(self.index(position, 0),
                              self.index(position, len(_COLUMNS) - 1))

    def append_rows(self, rows, more_after):
        self.fetching = False
        self.more_after = more_after
        if rows:
            self.beginInsertRows(QModelIndex(), len(self.rows),
                                 len(self.rows) + len(rows) - 1)
            self.rows.extend(rows)
            self.endInsertRows()

    def prepend_rows(self, rows, more_before):
        self.fetching = False
        self.more_before = more_before
        if rows:
            self.beginInsertRows(QModelIndex(), 0, len(rows) - 1)
            self.rows[:0] = rows
            self.endInsertRows()

    def canFetchMore(self, parent=QModelIndex()):
        return not parent.isValid() and self.more_after and not self.fetching

    def fetchMore(self, parent=QModelIndex()):
        if self.canFetchMore(parent):
            self.fetching = True
            self.more_wanted.emit(True)

    def mark_of(self, row):
        """(starred, colour, comment) for a row, or None."""
        if row.get('burst'):
            return None
        key = row.get('_key')
        if key is None:
            key = row['_key'] = timeline.event_key(row)
        return self.marks.get(key)

    def colour_of(self, row):
        """The row's tint: its mark's colour, else its highlight's."""
        mark = self.mark_of(row)
        if mark and mark[1]:
            return mark[1]
        if not self.highlights or row.get('burst'):
            return None
        if '_hl' not in row:
            row['_hl'] = timeline.highlight_of(row, self.highlights)
        return row['_hl']

    def set_highlights(self, compiled):
        self.highlights = compiled
        for row in self.rows:
            row.pop('_hl', None)
        self.refresh_all()

    def refresh_all(self):
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(
                len(self.rows) - 1, len(_COLUMNS) - 1))

    def set_time_mode(self, mode):
        self.time_mode = mode
        if self.rows:
            self.dataChanged.emit(self.index(0, TIME),
                                  self.index(len(self.rows) - 1, TIME))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section == TIME:
                return {'utc': "Time (UTC)", 'zone': "Time",
                        'both': "Time (UTC · zone)"}[self.time_mode]
            return _COLUMNS[section]
        if orientation == Qt.Horizontal and role == Qt.ToolTipRole \
                and section == MACB:
            return ("Which file-system times changed at this moment: "
                    "Modified, Accessed, Changed (entry), Born (created)")
        return None

    def cell(self, row, column):
        if row.get('burst'):
            return self._burst_cell(row, column)
        if column == TIME:
            if row['local']:
                return f"{row['time']} (local)"
            return shown_time(row['time'], self.time_mode)
        if column == SOURCE:
            label = timeline.SOURCE_LABELS.get(row['source'], row['source'])
            readers = read_by(row)
            if readers and readers != ['TRACE']:
                label += f" — {', '.join(readers)}"
            return label
        if column == TYPE:
            return timeline.describe_kind(row)
        if column == MACB:
            return timeline.macb(row)
        if column == DESCRIPTION:
            # A burst's events, expanded beneath it, are indented.
            return ('      ' if row.get('in_burst') else '') + \
                _description(row)
        if column == SUBJECT:
            return row['subject'] or ''
        if column == USER:
            return row['user'] or ''
        if column == EVIDENCE:
            return self.names.get(row['evidence_id'], '') \
                if row['evidence_id'] is not None else ''
        return ''

    def _burst_cell(self, row, column):
        """A collapsed burst's row: its span, what and how many, where."""
        if column == TIME:
            first = row['time'] if row['local'] else shown_time(
                row['time'], self.time_mode)
            last = (row['last'] or '')[11:19]
            if (row['last'] or '')[:19] == (row['time'] or '')[:19]:
                return first
            return f"{first} – {last}"
        if column == DESCRIPTION:
            mark = '▾' if row.get('expanded') else '▸'
            return f"{mark} {row['title']}"
        if column == USER:
            users = row.get('users') or []
            return users[0] if len(users) == 1 else (
                f"{len(users)} users" if users else '')
        if column == SUBJECT:
            return row['subject'] or ''
        if column == SOURCE:
            return timeline.SOURCE_LABELS.get(row['source'], row['source'])
        if column == TYPE:
            return timeline.describe_kind(row)
        if column == MACB:
            return timeline.macb(row)
        if column == EVIDENCE:
            return self.names.get(row['evidence_id'], '') \
                if row['evidence_id'] is not None else ''
        return ''

    def _burst_tip(self, row):
        lines = [f"{row['count']:,} events of one kind in one "
                 f"{_WINDOW_WORDS.get(len(row['window']), 'window')}: "
                 f"collapsed. Double-click (or Enter) lists them.",
                 f"{row['time'][:19]} to {(row['last'] or '')[:19]}"]
        if row.get('deleted'):
            lines.append(f"{row['deleted']:,} of them deleted")
        folders = row.get('folders') or []
        for folder, number in folders[:8]:
            lines.append(f"  {number:>7,}  {folder or '(no folder)'}")
        if len(folders) > 8:
            lines.append(f"  … {len(folders) - 8:,} more folders")
        return '\n'.join(lines)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self.cell(row, column)
        if row.get('burst'):
            if role == Qt.FontRole:
                font = QFont()
                font.setBold(True)
                return font
            if role == Qt.ToolTipRole:
                return self._burst_tip(row)
        if role == Qt.DecorationRole and column == TIME:
            mark = self.mark_of(row)
            if mark and mark[0]:
                return icons.icon(icons.TIMELINE_STAR, tint='#E3A008')
            return None
        if role == Qt.BackgroundRole:
            colour = self.colour_of(row)
            return QColor(colour) if colour else None
        if role == Qt.DecorationRole and column == SOURCE:
            icon = self._icons.get(row['source'])
            if icon is None:
                icon = self._icons[row['source']] = source_icon(row['source'])
            return icon
        if role == Qt.TextAlignmentRole and column == MACB:
            return int(Qt.AlignCenter)
        if role == Qt.FontRole and column == MACB:
            font = QFont("Consolas, Menlo, monospace")
            font.setStyleHint(QFont.Monospace)
            font.setItalic(bool(row['deleted']))
            return font
        if role == Qt.ToolTipRole:
            if column == TIME and row['local']:
                return ("Local time of the machine or camera that wrote it: "
                        "the source keeps no time zone.")
            if column == MACB and row['source'] == 'fs':
                letters = timeline.macb(row)
                return ', '.join(timeline.MACB_WORDS[c] for c in letters
                                 if c != '.')
            mark = self.mark_of(row)
            note = f"\n\nComment: {mark[2]}" if mark and mark[2] else ''
            if row['deleted'] and column in (DESCRIPTION, SUBJECT):
                return f"{self.cell(row, column)}\n(deleted){note}"
            return (self.cell(row, column) or '') + note or None
        if role == Qt.FontRole and row['deleted']:
            font = QFont()
            font.setItalic(True)
            return font
        if role == Qt.UserRole:
            return row
        return None


# --- the histogram ------------------------------------------------------------------

class TimelineHistogram(QWidget):
    """Events per bucket, stacked by source.

    Drag across it to zoom to that span; double-click a bar to zoom into
    it; click a bar to jump the table there without zooming; the wheel
    zooms around the pointer."""

    range_selected = Signal(str, str)
    zoom_requested = Signal(float, float)       # pointer fraction, factor
    time_clicked = Signal(str, str)             # a bar's start and end

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineHistogram")
        self.setMinimumHeight(110)
        self.setMaximumHeight(140)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.buckets = {}
        self.unit = 'day'
        self.start = self.end = None
        self.marker = None
        self.gaps = []
        self._drag_from = None
        self._drag_to = None
        self._hover = None
        self._bars = []             # (QRectF, bucket text, counts)
        self.setCursor(Qt.CrossCursor)
        self.setToolTip('')

    def set_data(self, buckets, unit, start, end):
        self.buckets, self.unit = buckets or {}, unit
        self.start, self.end = timeline.parse(start), timeline.parse(end)
        self.update()

    def set_marker(self, time_text):
        self.marker = timeline.parse(time_text)
        self.update()

    def set_gaps(self, gaps):
        """Stretches with no events (Insights), drawn hatched."""
        self.gaps = [(timeline.parse(a), timeline.parse(b))
                     for a, b in gaps or ()]
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
        # Gaps (Insights): hatched, so "nothing" reads as a finding.
        if self.gaps:
            hatch = QColor(text)
            hatch.setAlpha(45)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(hatch, Qt.BDiagPattern))
            for first, last in self.gaps:
                if first is None or last is None or last <= self.start or \
                        first >= self.end:
                    continue
                left = max(plot.left(), self._x(first, plot))
                right = min(plot.right(), self._x(last, plot))
                if right - left >= 2:
                    painter.drawRect(QRectF(left, plot.top(), right - left,
                                            plot.height()))
            painter.setBrush(Qt.NoBrush)
        # The bar under the pointer, outlined.
        if self._hover is not None and self._drag_from is None:
            for rect, _bucket, _counts in self._bars:
                if rect.left() - 1 <= self._hover <= rect.right() + 1:
                    outline = palette.color(palette.ColorRole.Highlight)
                    painter.setPen(QPen(outline, 1))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawRect(rect.adjusted(-1, -1, 0, 0))
                    break
        # Axis: ticks on calendar boundaries (years, months, days, hours...)
        # with a faint line up through the plot.
        font = painter.font()
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        painter.setFont(font)
        metrics = painter.fontMetrics()
        faint = QColor(text)
        faint.setAlpha(22)
        last_right = -1e9
        for moment, label in calendar_ticks(self.start, self.end,
                                            max(2, int(plot.width() // 90))):
            x = self._x(moment, plot)
            if not plot.left() <= x <= plot.right():
                continue
            painter.setPen(faint)
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
            w = metrics.horizontalAdvance(label)
            left = min(max(plot.left(), x - w / 2), plot.right() - w)
            if left <= last_right + 8:
                continue        # it would overlap the label before
            painter.setPen(text)
            painter.drawText(QPointF(left, self.height() - 5), label)
            last_right = left + w
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
            if right - left >= 4:
                # The span the drag will zoom to, written at its ends.
                painter.setPen(text)
                for x, moment in ((left, self._moment(left, plot)),
                                  (right, self._moment(right, plot))):
                    label = self._label(moment, fine=True)
                    w = painter.fontMetrics().horizontalAdvance(label)
                    x = min(max(plot.left(), x - w / 2), plot.right() - w)
                    painter.drawText(QPointF(x, plot.top() + 10), label)
        elif self._hover is not None and plot.left() <= self._hover \
                <= plot.right():
            guide = QColor(text)
            guide.setAlpha(110)
            painter.setPen(guide)
            painter.drawLine(QPointF(self._hover, plot.top()),
                             QPointF(self._hover, plot.bottom()))

    def _label(self, moment, fine=False):
        span = (self.end - self.start).total_seconds()
        if fine:
            return moment.strftime('%Y-%m-%d %H:%M:%S' if span < 2 * 86400
                                   else '%Y-%m-%d %H:%M')
        if span > 3 * 365 * 86400:
            return moment.strftime('%Y')
        if span > 90 * 86400:
            return moment.strftime('%Y-%m')
        if span > 2 * 86400:
            return moment.strftime('%Y-%m-%d')
        if span > 120:
            return moment.strftime('%m-%d %H:%M')
        return moment.strftime('%H:%M:%S')

    def _bar_at(self, x):
        for rect, bucket, counts in self._bars:
            if rect.left() - 1 <= x <= rect.right() + 1:
                return bucket, counts
        return None, None

    def _bucket_span(self, bucket):
        first = timeline.bucket_start(bucket)
        return timeline.text(first), timeline.text(timeline.step(first,
                                                                 self.unit))

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.start:
            self._drag_from = self._drag_to = event.position().x()

    def mouseMoveEvent(self, event):
        x = event.position().x()
        self._hover = x
        if self._drag_from is not None:
            self._drag_to = x
            self.update()
            return
        self.update()
        if not self.start:
            return
        moment = self._moment(x, self._plot())
        lines = [self._label(moment, fine=True)]
        bucket, counts = self._bar_at(x)
        if bucket:
            lines = [f"{bucket}  ({sum(counts.values()):,} events)"] + [
                f"{timeline.SOURCE_LABELS[s]}: {counts[s]:,}"
                for s, _l, _c in timeline.SOURCES if counts.get(s)]
            lines.append("Click: go there · double-click: zoom in")
        lines.append("Drag: zoom to a span · wheel: zoom")
        QToolTip.showText(event.globalPosition().toPoint(), '\n'.join(lines),
                          self)

    def leaveEvent(self, event):
        self._hover = None
        self.update()
        super().leaveEvent(event)

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
        # A click is not a zoom: it goes to that moment in the table.
        bucket, _counts = self._bar_at(left)
        if bucket:
            self.time_clicked.emit(*self._bucket_span(bucket))

    def mouseDoubleClickEvent(self, event):
        self._drag_from = self._drag_to = None
        bucket, _counts = self._bar_at(event.position().x())
        if bucket:
            self.range_selected.emit(*self._bucket_span(bucket))

    def wheelEvent(self, event):
        zoom_on_wheel(self, event, self._plot())


# --- loading -----------------------------------------------------------------------

def _module_telemetry(connection):
    """How many module telemetry events the case holds (hidden unless
    asked for) -- read on the loading thread: 710,002 on a real iPhone
    took 0.5 s on the window's."""
    try:
        return connection.execute(
            "SELECT COUNT(*) FROM module_events "
            "WHERE kind = 'telemetry'").fetchone()[0]
    except sqlite3.Error:
        return 0          # before schema 24, or no module ever ran


class _Load(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, filters, find_bounds,
                 parent=None, whole=False, collapse=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.find_bounds = filters, find_bounds
        #: A burst window (timeline_clusters.WINDOWS key), or None.
        self.collapse = collapse
        #: The whole span, not just where most events are.
        self.whole = whole

    def run(self):
        result = {'rows': [], 'counts': {}, 'histogram': {}, 'total': 0,
                  'bounds': None, 'outside': 0, 'error': ''}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = connect_read_only(path)
            try:
                filters = dict(self.filters)
                if self.find_bounds or not filters.get('start'):
                    spread = timeline.spread(connection, filters)
                    if spread:
                        first, last = spread['first'], spread['last']
                        result['bounds'] = (first, last)
                        result['outside'] = spread['outside']
                        # Open where the events are (the whole span is a
                        # click away): software's own 1990s dates or one
                        # stray year would flatten the rest.
                        if self.whole:
                            low, high = first, last
                        else:
                            low = spread['dense_first']
                            high = spread['dense_last']
                            result['trimmed'] = spread['dense_outside']
                        unit = timeline.unit_for(low, high)
                        begin = timeline.floor(timeline.parse(low), unit)
                        finish = timeline.step(timeline.floor(
                            timeline.parse(high), unit), unit)
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
                items = None
                if self.collapse:
                    from trace_app.core import timeline_clusters
                    items, _complete = timeline_clusters.collapse(
                        connection, filters, self.collapse)
                    result['too_varied'] = items is None
                if items is not None:
                    result['rows'] = items
                    result['collapsed'] = True
                    result['bursts'] = sum(1 for r in items
                                           if r.get('burst'))
                else:
                    rows = timeline.events_after(connection, filters, None,
                                                 PAGE_ROWS + 1)
                    result['more_after'] = len(rows) > PAGE_ROWS
                    result['rows'] = rows[:PAGE_ROWS]
                result['marks'] = {
                    key: (bool(starred), colour, comment)
                    for key, starred, colour, comment in connection.execute(
                        "SELECT event_key, starred, colour, comment FROM "
                        "timeline_marks")}
                result['fs_kinds'] = timeline.fs_kinds(
                    connection, filters.get('evidence_id'))
                result['telemetry'] = _module_telemetry(connection)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read the timeline: %s", exc)
            result['error'] = str(exc)
        self.loaded.emit(self.generation, result)


class _Page(QThread):
    """One page of rows: after the last row read ('after'), before the
    first ('before'), or starting at a time ('at': a jump, which also says
    whether rows come before it)."""

    paged = Signal(int, str, object)

    def __init__(self, folder, generation, filters, how, key, parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.how, self.key = filters, how, key

    def run(self):
        result = {'rows': [], 'more': False, 'more_before': False,
                  'error': ''}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = connect_read_only(path)
            try:
                if self.how == 'burst':
                    # A burst's own events: self.key is their filters.
                    result['rows'] = list(timeline.iter_events(connection,
                                                               self.key))
                elif self.how == 'before':
                    rows = timeline.events_before(connection, self.filters,
                                                  self.key, PAGE_ROWS + 1)
                    result['more'] = len(rows) > PAGE_ROWS
                    result['rows'] = rows[-PAGE_ROWS:]
                else:
                    rows = timeline.events_after(connection, self.filters,
                                                 self.key, PAGE_ROWS + 1)
                    result['more'] = len(rows) > PAGE_ROWS
                    result['rows'] = rows[:PAGE_ROWS]
                    if self.how == 'at':
                        result['more_before'] = timeline.count_before(
                            connection, self.filters, self.key) > 0
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read the timeline: %s", exc)
            result['error'] = str(exc)
        self.paged.emit(self.generation, self.how, result)


class _Export(QThread):
    done = Signal(int, str, str)

    def __init__(self, folder, filters, path, names, parent=None,
                 fmt='csv'):
        super().__init__(parent)
        self.folder, self.filters, self.path, self.names = \
            folder, filters, path, names
        self.fmt = fmt

    def run(self):
        try:
            connection = connect_read_only(
                os.path.join(self.folder, CASE_DB_NAME))
            try:
                rows = timeline_export.write(self.fmt, connection,
                                             self.filters, self.path,
                                             self.names)
            finally:
                connection.close()
        except Exception as exc:        # reported, never left hanging
            logger.error("Timeline export failed: %s", exc)
            self.done.emit(0, self.path, str(exc) or type(exc).__name__)
            return
        self.done.emit(rows, self.path, '')


# --- the column filter row ------------------------------------------------------------

#: What each column's filter box suggests.
_FILTER_HINTS = {TIME: "2024-05", SOURCE: "source", TYPE: "created",
                 MACB: "MB", DESCRIPTION: "name", SUBJECT: "path",
                 USER: "user", EVIDENCE: "image"}


class ColumnFilterRow(QWidget):
    """A filter box over each visible column of `table`, kept over its
    column as columns are resized, moved, hidden or scrolled. `changed`
    carries {column: text} of the boxes with text, once typing pauses."""

    #: object, not dict: PySide hands a dict over as a Qt map, whose keys
    #: are strings -- the int column keys were dropped, every filter lost.
    changed = Signal(object)

    def __init__(self, table, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineColumnFilters")
        self.table = table
        self.edits = {}
        for column in range(len(_COLUMNS)):
            edit = QLineEdit(self)
            edit.setObjectName("timelineColumnFilter")
            edit.setPlaceholderText(_FILTER_HINTS.get(column, ''))
            edit.setClearButtonEnabled(True)
            edit.setToolTip(f"Only events whose {_COLUMNS[column]} "
                            f"contains this")
            edit.textChanged.connect(lambda _t: self._timer.start())
            self.edits[column] = edit
        self.setFixedHeight(self.edits[TIME].sizeHint().height() + 4)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(350)
        self._timer.timeout.connect(lambda: self.changed.emit(self.values()))
        header = table.horizontalHeader()
        header.sectionResized.connect(lambda *_a: self._place())
        header.sectionMoved.connect(lambda *_a: self._place())
        header.geometriesChanged.connect(self._place)
        table.horizontalScrollBar().valueChanged.connect(
            lambda _v: self._place())

    def values(self):
        return {column: edit.text().strip()
                for column, edit in self.edits.items()
                if edit.text().strip()}

    def clear(self):
        for edit in self.edits.values():
            edit.blockSignals(True)
            edit.clear()
            edit.blockSignals(False)
        self.changed.emit({})

    def clear_column(self, column):
        if self.edits[column].text():
            self.edits[column].clear()

    def set_values(self, values):
        """Fill the boxes without filtering again (a saved view)."""
        for column, edit in self.edits.items():
            edit.blockSignals(True)
            edit.setText(values.get(column, ''))
            edit.blockSignals(False)

    def showEvent(self, event):
        super().showEvent(event)
        self._place()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._place()

    def _place(self):
        header = self.table.horizontalHeader()
        # Where the table's viewport starts, from this row's left edge.
        offset = (self.table.viewport().mapToGlobal(QPoint(0, 0)).x()
                  - self.mapToGlobal(QPoint(0, 0)).x())
        for column, edit in self.edits.items():
            if header.isSectionHidden(column):
                edit.hide()
                continue
            left = header.sectionViewportPosition(column) + offset
            edit.setGeometry(left + 1, 2, max(20, header.sectionSize(column)
                                              - 2), self.height() - 4)
            edit.show()


def read_by(row):
    """[readers] of an activity event (its extra: reader, also), cached on
    the row; [] for any other source."""
    if row.get('source') != 'activity':
        return []
    found = row.get('_read_by')
    if found is None:
        try:
            extra = json.loads(row.get('extra') or '{}')
        except ValueError:
            extra = {}
        found = [extra.get('reader') or 'TRACE']
        for name in (extra.get('also') or '').split(','):
            if name and name not in found:
                found.append(name)
        found.sort(key=lambda r: (r != 'TRACE', r))
        row['_read_by'] = found
    return found


def _kind_label(kind):
    """A Type value as the table shows it ('M SI' is 'Modified ($SI)')."""
    import re
    source = 'fs' if re.match(r'^[MACB.]+ ', kind or '') else ''
    return timeline.describe_kind({'source': source, 'kind': kind or ''})


class _Summary(QThread):
    summed = Signal(int, object)

    def __init__(self, folder, generation, filters, by, parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.by = filters, by

    def run(self):
        rows, error = [], ''
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = connect_read_only(path)
            try:
                rows = timeline.summary(connection, self.filters, self.by)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            error = str(exc)
        self.summed.emit(self.generation, (rows, error))


class _ShareDelegate(QStyledItemDelegate):
    """The Events column with a bar of the group's share behind it."""

    def paint(self, painter, option, index):
        share = index.data(Qt.UserRole + 1) or 0
        if share > 0:
            bar = QColor(option.palette.color(option.palette.ColorRole
                                              .Highlight))
            bar.setAlpha(60)
            rect = option.rect.adjusted(2, 4, -2, -4)
            rect.setWidth(max(2, int(rect.width() * share)))
            painter.fillRect(rect, bar)
        super().paint(painter, option, index)


class SummaryView(QWidget):
    """The events of the view counted by one column, most first. Double-
    click a group to see its events."""

    group_activated = Signal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineSummary")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Group by"))
        self.by_combo = QComboBox()
        for key, (label, _sql) in timeline.SUMMARY_BY.items():
            self.by_combo.addItem(label, key)
        self.by_combo.setCurrentIndex(self.by_combo.findData('folder'))
        self.by_combo.currentIndexChanged.connect(lambda _i: self._reload())
        bar.addWidget(self.by_combo)
        self.status = QLabel()
        self.status.setObjectName("triageStatus")
        bar.addWidget(self.status, 1)
        layout.addLayout(bar)
        self.model = QStandardItemModel(0, 4, self)
        self.model.setHorizontalHeaderLabels(
            ["Value", "Events", "First", "Last"])
        self.table = QTableView()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setItemDelegateForColumn(1, _ShareDelegate(self.table))
        self.table.setSortingEnabled(True)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column, width in ((1, 140), (2, 160), (3, 160)):
            self.table.setColumnWidth(column, width)
        self.table.doubleClicked.connect(self._activated)
        layout.addWidget(self.table, 1)
        self._case = self._filters = None
        self._names = {}
        self._generation = 0
        self._jobs = KeptThreads(self)

    def load(self, case, filters, names):
        self._case, self._filters, self._names = case, dict(filters), names
        self._reload()

    def _reload(self):
        if self._case is None:
            return
        self._generation += 1
        job = _Summary(self._case.folder, self._generation, self._filters,
                       self.by_combo.currentData(), self)
        job.summed.connect(self._summed)
        self._jobs[self._generation] = job
        self.status.setText("Counting…")
        job.start()

    def _label(self, by, value):
        if by == 'source':
            return timeline.SOURCE_LABELS.get(value, value)
        if by == 'evidence':
            return self._names.get(value, '(none)')
        if by == 'kind':
            return _kind_label(value)
        if by == 'extension':
            return f".{value}" if value else "(no extension)"
        return value or "(none)"

    def _summed(self, generation, answer):
        if generation != self._generation:
            return
        rows, error = answer
        if error:
            self.status.setText(f"Could not count: {error}")
            return
        by = self.by_combo.currentData()
        self.table.setSortingEnabled(False)
        self.model.removeRows(0, self.model.rowCount())
        most = max((count for _v, count, _f, _l in rows), default=0)
        for value, count, first, last in rows:
            label = QStandardItem(self._label(by, value))
            label.setData(value, Qt.UserRole)
            label.setToolTip(label.text())
            number = QStandardItem(f"{count:,}")
            number.setData(count, Qt.UserRole + 2)
            number.setData(count / most if most else 0, Qt.UserRole + 1)
            number.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.model.appendRow([label, number,
                                  QStandardItem((first or '')[:19]),
                                  QStandardItem((last or '')[:19])])
        self.model.setSortRole(Qt.UserRole + 2)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(1, Qt.DescendingOrder)
        total = sum(count for _v, count, _f, _l in rows)
        self.status.setText(f"{len(rows):,} group(s), {total:,} events"
                            + (" (the 5,000 largest)" if len(rows) >= 5000
                               else "") +
                            " · double-click one to see its events")

    def _activated(self, index):
        item = self.model.item(index.row(), 0)
        if item is not None:
            self.group_activated.emit(self.by_combo.currentData(),
                                      item.data(Qt.UserRole))

    def shutdown(self):
        for job in list(self._jobs.values()):
            try:
                job.wait(5000)
            except RuntimeError:
                pass


class _TintDelegate(QStyledItemDelegate):
    """A marked or highlighted row's colour: a light tint over the cell, a
    bar of the full colour at the row's left edge. Painted after the cell:
    the themes' ::item background covers any colour set under it."""

    def paint(self, painter, option, index):
        if option.state & QStyle.State_HasFocus:
            option.state &= ~QStyle.State_HasFocus
        super().paint(painter, option, index)
        colour = index.data(Qt.BackgroundRole)
        if colour is None:
            return
        if not option.state & QStyle.State_Selected:
            tint = QColor(colour)
            tint.setAlpha(42)
            painter.fillRect(option.rect, tint)
        # The bar: on the leftmost column shown (columns can be moved).
        if self.parent().horizontalHeader().visualIndex(index.column()) == 0:
            painter.fillRect(option.rect.adjusted(0, 0, -option.rect.width()
                                                  + 3, 0), QColor(colour))


class TimelineTable(QTableView):
    """The events table, with room under its header for a row of column
    filters (`set_filter_row`), where an examiner looks for them."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_row = None
        self._placing = False

    def set_filter_row(self, row):
        self._filter_row = row
        row.setParent(self)
        self.updateGeometries()

    def filter_row_height(self):
        row = self._filter_row
        return row.height() if row is not None and not row.isHidden() else 0

    def updateGeometries(self):
        super().updateGeometries()
        if self._placing:
            return
        extra = self.filter_row_height()
        header = self.horizontalHeader()
        height = header.height() if not header.isHidden() else 0
        margins = self.viewportMargins()
        if margins.top() != height + extra:
            self._placing = True
            try:
                self.setViewportMargins(margins.left(), height + extra,
                                        margins.right(), margins.bottom())
            finally:
                self._placing = False
        if self._filter_row is not None:
            area = self.viewport().geometry()
            header.setGeometry(area.left(), area.top() - extra - height,
                               area.width(), height)
            if extra:
                self._filter_row.setGeometry(area.left(), area.top() - extra,
                                             area.width(), extra)
                self._filter_row.raise_()


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
        self._loads = KeptThreads(self)
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
        self.status_label = ElidedLabel()
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
        # Per operating system (Case.systems): a dual-boot disk's Windows
        # or its Linux, or every Windows in the case.
        self.system_filter = QComboBox()
        self.system_filter.setObjectName("triageEvidenceFilter")
        self.system_filter.setToolTip(
            "Every system, or the events on the volumes of one operating "
            "system (or of every system of one kind)")
        self.system_filter.currentIndexChanged.connect(self._system_changed)
        self.toolbar.addWidget(self.system_filter)
        # How times read: as stored (UTC), in the case's display zone
        # (Options ▸ Settings), or both. Display only.
        self.time_combo = QComboBox()
        self.time_combo.setObjectName("timelineTimeMode")
        for key, label in TIME_MODES:
            self.time_combo.addItem(icons.icon(icons.TIMELINE_CLOCK),
                                    label, key)
        self.time_combo.setToolTip(
            "Show times in UTC (as stored), in the case's display zone "
            "(Options ▸ Settings ▸ Case), or both. Times without a zone "
            "(FAT, EXIF) are shown as they are.")
        self.time_combo.currentIndexChanged.connect(self._time_mode_changed)
        self.toolbar.addWidget(self.time_combo)
        self.views_button = QPushButton("Views")
        self.views_button.setObjectName("triageRunButton")
        self.views_button.setToolTip("Save these filters as a named view, "
                                     "or go back to one")
        self.views_button.setMenu(QMenu(self.views_button))
        self.views_button.setProperty("dropdown", True)
        self.views_button.menu().aboutToShow.connect(self._fill_views_menu)
        self.toolbar.addWidget(self.views_button)
        self.export_button = QPushButton("Export…")
        self.export_button.setObjectName("triageRunButton")
        self.export_button.setToolTip(
            "Every event the filters select -- not only the rows shown -- "
            "as CSV, or for Timesketch, plaso or mactime")
        self.export_button.setProperty("dropdown", True)
        export_menu = QMenu(self.export_button)
        for fmt, (label, _extension, _pattern) in \
                timeline_export.FORMATS.items():
            action = export_menu.addAction(label + "…")
            action.triggered.connect(
                lambda _=False, fmt=fmt: self.export_csv(fmt=fmt))
        self.export_button.setMenu(export_menu)
        self.toolbar.addWidget(self.export_button)
        outer.addWidget(self.toolbar)

        body = QVBoxLayout()
        body.setContentsMargins(6, 4, 6, 0)
        body.setSpacing(4)
        outer.addLayout(body, 1)

        # Navigation, range, text and the filters, in groups that wrap as
        # wholes, so the panel never demands more width than its widest
        # group (it once asked 2,000 px, and Qt took them from the tree).
        controls_holder = QWidget()
        controls_holder.setObjectName("timelineControls")
        controls = FlowLayout(controls_holder, spacing=10)
        row = self._group(controls)
        self.back_button = self._tool_button(icons.BACK,
                                             "Back to the previous range")
        self.back_button.clicked.connect(self.back)
        row.addWidget(self.back_button)
        for glyph, tip, factor in ((icons.ZOOM_IN, "Zoom in", 0.5),
                                   (icons.ZOOM_OUT, "Zoom out", 2.0)):
            button = self._tool_button(
                glyph, f"{tip} (or the wheel over the histogram)")
            button.clicked.connect(
                lambda _c=False, f=factor: self._zoom(0.5, f))
            row.addWidget(button)
        whole = self._tool_button(icons.FIT_WINDOW, "Whole case: every "
                                  "event, from the first to the last")
        whole.clicked.connect(self.whole_case)
        row.addWidget(whole)

        # The range: one button saying it, which opens From / To and the
        # presets.
        row = self._group(controls)
        self.range_button = QToolButton()
        self.range_button.setObjectName("timelineRangeButton")
        self.range_button.setIcon(icons.icon(icons.TIMELINE_CALENDAR))
        self.range_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.range_button.setPopupMode(QToolButton.InstantPopup)
        self.range_button.setProperty("dropdown", True)
        self.range_button.setToolTip("The range shown (UTC): type one, or "
                                     "pick a preset")
        self.range_button.setMenu(self._range_menu())
        row.addWidget(self.range_button)

        row = self._group(controls)
        self.text_input = QLineEdit()
        self.text_input.setObjectName("timelineSearch")
        self.text_input.setPlaceholderText("Search events…")
        self.text_input.setClearButtonEnabled(True)
        self.text_input.addAction(icons.icon(icons.SEARCH),
                                  QLineEdit.LeadingPosition)
        self.text_input.setMinimumWidth(160)
        self.text_input.setMaximumWidth(280)
        self._text_timer = QTimer(self)
        self._text_timer.setSingleShot(True)
        self._text_timer.setInterval(350)
        self._text_timer.timeout.connect(self._text_changed)
        self.text_input.textChanged.connect(
            lambda _t: self._text_timer.start())
        row.addWidget(self.text_input)

        row = self._group(controls)
        self.fs_combo = QComboBox()
        self.fs_combo.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.fs_combo.setMinimumContentsLength(18)
        self.fs_combo.setObjectName("timelineFsCombo")
        # Filled from what the case holds (_fill_fs_combo): NTFS's
        # $SI / $FN / index-slack times, other file systems' own times.
        self.fs_combo.addItem("All file-system times", 'both')
        self.fs_combo.setToolTip("Which file-system times the File system "
                                 "source shows")
        self.fs_combo.setVisible(False)
        self.fs_combo.currentIndexChanged.connect(self._fs_changed)
        row.addWidget(self.fs_combo)
        # Its own group: beside the buttons it made the narrowest the
        # panel could be too wide for a laptop (test_no_tab_squeezes_the_tree).
        row = self._group(controls)
        # The switches, in one menu; each one on shows as a chip below.
        self.filters_button = QToolButton()
        self.filters_button.setObjectName("timelineRangeButton")
        self.filters_button.setIcon(icons.icon(icons.TIMELINE_FILTER))
        self.filters_button.setText("Filters")
        self.filters_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.filters_button.setPopupMode(QToolButton.InstantPopup)
        self.filters_button.setProperty("dropdown", True)
        flags = QMenu(self.filters_button)
        self.deleted_box = flags.addAction("Deleted only")
        self.deleted_box.setToolTip("Deleted files' $MFT times, and "
                                    "deletions in the change journal")
        self.stomped_box = flags.addAction("Timestomped only")
        self.stomped_box.setToolTip("Files whose times look set by hand "
                                    "(Triage ▸ NTFS)")
        self.known_good_box = flags.addAction("Hide known good")
        self.known_good_box.setToolTip("Leave out files matching a "
                                       "known-good hash set (NSRL)")
        for action, key in ((self.deleted_box, 'deleted_only'),
                            (self.stomped_box, 'timestomped_only'),
                            (self.known_good_box, 'hide_known_good')):
            action.setCheckable(True)
            action.toggled.connect(
                lambda on, k=key: self._flag_changed(k, on))
        self.starred_box = flags.addAction("Starred only")
        self.starred_box.setCheckable(True)
        self.starred_box.setToolTip("Only the events you starred (S), with "
                                    "your comments")
        self.starred_box.toggled.connect(
            lambda on: self._flag_changed('starred_only', on))
        flags.setToolTipsVisible(True)
        flags.addSeparator()
        self.telemetry_box = flags.addAction("Telemetry from Modules")
        self.telemetry_box.setCheckable(True)
        self.telemetry_box.setToolTip(
            "External modules' device telemetry -- log lines, power and "
            "health samples, cache entries -- hidden unless this is on "
            "(core/modules/routes; the Modules tab lists every artifact)")
        self.telemetry_box.toggled.connect(
            lambda on: self._flag_changed('module_telemetry', on))
        self.readers_menu = flags.addMenu("Read By")
        self.readers_menu.setToolTipsVisible(True)
        self._reader_actions = QActionGroup(self.readers_menu)
        self._reader_actions.setExclusive(True)
        self._fill_readers([])
        flags.addSeparator()
        flags.addAction("Highlight Rules…").triggered.connect(
            self.edit_highlights)
        self.column_filters_action = flags.addAction("Column Filters")
        self.column_filters_action.setCheckable(True)
        self.column_filters_action.setToolTip(
            "A filter box over each column of the table")
        self.column_filters_action.toggled.connect(
            self._show_column_filters)
        self.filters_button.setMenu(flags)
        row.addWidget(self.filters_button)

        # Bursts: thousands of one kind in one moment as one row.
        from trace_app.core import timeline_clusters
        self.collapse_button = QToolButton()
        self.collapse_button.setObjectName("timelineRangeButton")
        self.collapse_button.setIcon(icons.icon(icons.TIMELINE_COLLAPSE))
        self.collapse_button.setText("Collapse bursts")
        self.collapse_button.setCheckable(True)
        self.collapse_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.collapse_button.setPopupMode(QToolButton.MenuButtonPopup)
        self.collapse_button.setToolTip(
            f"Show events of one source and type, in one image, that fall in "
            f"the same window as one row when there are "
            f"{timeline_clusters.MINIMUM} or more of them -- a package "
            f"install, a scan, a copy. Double-click a burst to list it.")
        windows = QMenu(self.collapse_button)
        self._window_actions = {}
        for key, label, _length in timeline_clusters.WINDOWS:
            action = windows.addAction(f"Window: {label}")
            action.setCheckable(True)
            action.triggered.connect(
                lambda _c=False, k=key: self._set_window(k))
            self._window_actions[key] = action
        self.collapse_button.setMenu(windows)
        self.collapse_button.toggled.connect(self._collapse_toggled)
        row.addWidget(self.collapse_button)

        # Which view: the events, or them summed by a column.
        row = self._group(controls)
        self.view_buttons = {}
        for key, label, tip in (
                ('events', "Events", "Every event, in time order"),
                ('summary', "Summary", "The events counted by source, type, "
                                       "folder, extension, user or image"),
                ('lanes', "Lanes", "The events on one time axis, a lane per "
                                   "source, image, user or type")):
            button = QToolButton()
            button.setObjectName("timelineViewSwitch")
            button.setText(label)
            button.setToolTip(tip)
            button.setCheckable(True)
            button.setAutoExclusive(True)
            button.clicked.connect(lambda _c=False, k=key: self.set_view(k))
            self.view_buttons[key] = button
            row.addWidget(button)
        self.view_buttons['events'].setChecked(True)
        body.addWidget(controls_holder)

        # Sources, wrapping one by one: each a coloured chip with its count.
        switches_holder = QWidget()
        row = FlowLayout(switches_holder, spacing=6)
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
        body.addWidget(switches_holder)

        # Everything narrowing the view, each removable: pivots, switches,
        # column filters.
        self.pivot_holder = QWidget()
        self.pivot_holder.setObjectName("timelineChips")
        self.pivot_row = FlowLayout(self.pivot_holder, spacing=6)
        self.pivot_holder.setVisible(False)
        body.addWidget(self.pivot_holder)

        self.histogram = TimelineHistogram()
        self.histogram.range_selected.connect(self.set_range)
        self.histogram.zoom_requested.connect(self._wheel_zoom)
        self.histogram.time_clicked.connect(self.go_to_time)
        # Wheel notches gather here and one query runs when they stop.
        self._pending_range = None
        self._wheel_timer = QTimer(self)
        self._wheel_timer.setSingleShot(True)
        self._wheel_timer.setInterval(350)
        self._wheel_timer.timeout.connect(self._apply_pending_zoom)
        self._case_bounds = None
        body.addWidget(self.histogram)

        self.model = TimelineModel(self)
        self.model.more_wanted.connect(self._fetch_more)
        self.table = TimelineTable()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.model)
        self.table.setItemDelegate(_TintDelegate(self.table))
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.setSectionsMovable(True)
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._header_menu)
        for column, width in enumerate((175, 120, 190, 56, 220, 360, 90)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._landed(current))
        self.table.clicked.connect(self._landed)
        self.table.doubleClicked.connect(self._activated)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        # Near the top after a jump: the page before is read in.
        self.table.verticalScrollBar().valueChanged.connect(
            self._scrolled)
        self.column_filters = ColumnFilterRow(self.table)
        self.column_filters.changed.connect(self._column_filters_changed)
        self.column_filters.setVisible(False)
        self.table.set_filter_row(self.column_filters)

        self.detail = QTextBrowser()
        self.detail.setObjectName("timelineDetail")
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(self._detail_link)
        self.detail.setMinimumWidth(240)
        self.detail.setPlaceholderText(
            "Select an event to see everything about it -- for a file, "
            "both sets of NTFS times side by side and what Triage found.")

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("timelineSplitter")
        self.summary = SummaryView(self)
        self.summary.group_activated.connect(self.apply_group)
        self.views = QStackedWidget()
        self.views.addWidget(self.table)
        self.views.addWidget(self.summary)
        from trace_app.ui.viewers.timeline_lanes import LanesView
        self.lanes = LanesView(lambda: self._names, _kind_label, self)
        canvas = self.lanes.canvas
        canvas.range_selected.connect(self.set_range)
        canvas.zoom_requested.connect(self._wheel_zoom)
        canvas.time_clicked.connect(self.go_to_time)
        canvas.event_clicked.connect(self.select_event)
        canvas.event_menu.connect(self._lane_menu)
        canvas.mark_of = self.model.mark_of
        canvas.colour_of = self.model.colour_of
        self.views.addWidget(self.lanes)
        splitter.addWidget(self.views)
        from trace_app.ui.viewers.timeline_insights import InsightsView
        self.insights = InsightsView()
        self.insights.cell_clicked.connect(self._hours_chosen)
        self.insights.gap_clicked.connect(self._gap_chosen)
        self.insights.finding_clicked.connect(self.apply_finding)
        self.insights.ready.connect(
            lambda: self.histogram.set_gaps(
                self.insights.longest_gaps()))
        self.side = QTabWidget()
        self.side.setObjectName("timelineSide")
        self.side.setDocumentMode(True)
        self.side.addTab(self.detail, "Details")
        self.side.addTab(self.insights, "Insights")
        self.side.currentChanged.connect(self._side_changed)
        splitter.addWidget(self.side)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([900, 340])
        body.addWidget(splitter, 1)

        self._paging = KeptThreads(self)
        self._page_generation = 0
        self._pending_jump = None
        self._hours_label = ''
        self._collapsed_view = False
        from trace_app.infra.window_state import read_value
        self._window = read_value('Timeline', 'burst_window') or \
            timeline_clusters.DEFAULT_WINDOW
        if self._window not in self._window_actions:
            self._window = timeline_clusters.DEFAULT_WINDOW
        self._window_actions[self._window].setChecked(True)
        self.collapse_button.blockSignals(True)
        self.collapse_button.setChecked(
            read_value('Timeline', 'collapse', '1') == '1')
        self.collapse_button.blockSignals(False)
        self._whole = False
        self._restore_columns()
        self._install_keys()

        self.set_case(None)

    @staticmethod
    def _tool_button(glyph, tip):
        """A flat icon button of the navigation group."""
        button = QToolButton()
        button.setObjectName("timelineTool")
        button.setIcon(icons.icon(glyph))
        button.setToolTip(tip)
        button.setAutoRaise(True)
        return button

    def _range_menu(self):
        """From / To with Go, then presets."""
        menu = QMenu(self)
        holder = QWidget(menu)
        holder.setObjectName("timelineRangePopup")
        grid = QHBoxLayout(holder)
        grid.setContentsMargins(10, 8, 10, 8)
        grid.setSpacing(6)
        grid.addWidget(QLabel("From"))
        self.from_edit = self._time_edit()
        grid.addWidget(self.from_edit)
        grid.addWidget(QLabel("to"))
        self.to_edit = self._time_edit()
        grid.addWidget(self.to_edit)
        apply_range = QPushButton("Go")
        apply_range.setObjectName("timelineApply")
        apply_range.setToolTip("Show this range (UTC)")
        apply_range.clicked.connect(self._range_typed)
        apply_range.clicked.connect(menu.close)
        grid.addWidget(apply_range)
        field = QWidgetAction(menu)
        field.setDefaultWidget(holder)
        menu.addAction(field)
        menu.addSeparator()
        menu.addAction("Where most events are").triggered.connect(
            self.reset_range)
        menu.addAction("Whole case").triggered.connect(self.whole_case)
        latest = menu.addMenu("Last of the evidence")
        for label, seconds in (("Last 24 hours", 86400),
                               ("Last 7 days", 7 * 86400),
                               ("Last 30 days", 30 * 86400),
                               ("Last year", 365 * 86400)):
            latest.addAction(label).triggered.connect(
                lambda _c=False, s=seconds: self.last_of_evidence(s))
        around = menu.addMenu("Around the selected event")
        for label, seconds in _PIVOTS:
            around.addAction(label).triggered.connect(
                lambda _c=False, s=seconds: self.around_selected(s))
        return menu

    @staticmethod
    def _group(flow):
        """A run of controls that wraps as one, added to `flow`."""
        holder = QWidget()
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        flow.addWidget(holder)
        return layout

    @staticmethod
    def _time_edit():
        # As wide as a whole time and its button; the calendar in TRACE's
        # style (ui/widgets/date_fields.py).
        from trace_app.ui.widgets.date_fields import utc_edit
        return utc_edit("timelineTimeEdit")

    # --- columns -------------------------------------------------------------

    def _header_menu(self, point):
        """Which columns show: every one but Time can be hidden."""
        header = self.table.horizontalHeader()
        menu = QMenu(self)
        for column, label in enumerate(_COLUMNS):
            action = menu.addAction(self.model.headerData(
                column, Qt.Horizontal) or label)
            action.setCheckable(True)
            action.setChecked(not header.isSectionHidden(column))
            action.setEnabled(column != TIME)
            action.toggled.connect(
                lambda on, c=column: self._set_column_shown(c, on))
        menu.addSeparator()
        menu.addAction("Column Filters").triggered.connect(
            lambda: self.column_filters_action.setChecked(
                not self.column_filters_action.isChecked()))
        menu.addAction("Reset Columns").triggered.connect(
            self._reset_columns)
        menu.exec(header.mapToGlobal(point))

    def _set_column_shown(self, column, shown):
        self.table.horizontalHeader().setSectionHidden(column, not shown)
        if not shown:
            self.column_filters.clear_column(column)
        self._save_columns()

    def _reset_columns(self):
        header = self.table.horizontalHeader()
        for column in range(len(_COLUMNS)):
            header.setSectionHidden(column, False)
            header.moveSection(header.visualIndex(column), column)
        for column, width in enumerate((175, 120, 190, 56, 220, 360, 90)):
            self.table.setColumnWidth(column, width)
        self._save_columns()

    def _save_columns(self):
        from trace_app.infra.window_state import save_value
        header = self.table.horizontalHeader()
        save_value('Timeline', 'columns',
                           bytes(header.saveState().toHex()).decode())
        save_value('Timeline', 'column_filters',
                           '1' if self.column_filters_action.isChecked()
                           else '0')

    def _restore_columns(self):
        from trace_app.infra.window_state import read_value
        header = self.table.horizontalHeader()
        state = read_value('Timeline', 'columns')
        if state:
            try:
                header.restoreState(QByteArray.fromHex(state.encode()))
            except (ValueError, TypeError):
                pass
        header.setSectionHidden(TIME, False)
        if header.count() != len(_COLUMNS):
            self._reset_columns()
        header.sectionResized.connect(lambda *_a: self._save_columns_soon())
        header.sectionMoved.connect(lambda *_a: self._save_columns_soon())
        self._columns_timer = QTimer(self)
        self._columns_timer.setSingleShot(True)
        self._columns_timer.setInterval(500)
        self._columns_timer.timeout.connect(self._save_columns)
        self.column_filters_action.setChecked(
            read_value('Timeline', 'column_filters') == '1')

    def _save_columns_soon(self):
        self._columns_timer.start()

    def _show_column_filters(self, on):
        self.column_filters.setVisible(on)
        self.table.updateGeometries()
        if not on and self.column_filters.values():
            self.column_filters.clear()
        self._save_columns()

    def _column_filters_changed(self, values):
        """The filter row's boxes, as timeline column filters: Source and
        Evidence by their names, matched to their keys here. Exact filters
        from a Summary group stay."""
        columns = {key: value for key, value in
                   (self.filters.get('columns') or {}).items()
                   if key in ('kind_is', 'folder_is', 'extension')}
        for column, text in values.items():
            key = _COLUMN_FILTER[column]
            if key == 'sources':
                lowered = text.lower()
                columns[key] = [k for k, label, _c in timeline.SOURCES
                                if lowered in label.lower()]
            elif key == 'evidence_ids':
                lowered = text.lower()
                columns[key] = [i for i, name in self._names.items()
                                if lowered in name.lower()]
            else:
                columns[key] = text
        self.filters['columns'] = columns
        self._show_pivots()
        self.refresh()

    # --- keys -------------------------------------------------------------------

    def _install_keys(self):
        from PySide6.QtGui import QKeySequence, QShortcut
        for keys, slot in (("S", self._star_key),
                           ("N", lambda: self._next_starred(1)),
                           ("Shift+N", lambda: self._next_starred(-1))):
            shortcut = QShortcut(QKeySequence(keys), self.table)
            shortcut.setContext(Qt.WidgetShortcut)
            shortcut.activated.connect(slot)
        for keys in ("Return", "Enter"):
            enter = QShortcut(QKeySequence(keys), self.table)
            enter.setContext(Qt.WidgetShortcut)
            enter.activated.connect(self._enter)
        for keys, slot in (("Ctrl+G", self._ask_time),
                           ("]", lambda: self._next_of_source(1)),
                           ("[", lambda: self._next_of_source(-1))):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setContext(Qt.WidgetWithChildrenShortcut)
            shortcut.activated.connect(slot)

    def _star_key(self):
        rows = self.selected_rows()
        if not rows or self.case is None:
            return
        starred = all((self.model.mark_of(r) or (False,))[0] for r in rows)
        self.mark(rows, starred=not starred)

    def _next_starred(self, step):
        """The next (or previous) starred event among the rows read."""
        position = self.table.currentIndex().row() + step
        while 0 <= position < len(self.model.rows):
            mark = self.model.mark_of(self.model.rows[position])
            if mark and mark[0]:
                self.table.selectRow(position)
                self.table.scrollTo(self.model.index(position, 0))
                return
            position += step

    def mark(self, rows, starred=None, colour=None, comment=None):
        """Star / colour / comment on events: kept in the case, audited."""
        rows = [r for r in rows if not r.get('burst')]
        if not rows or self.case is None:
            return 0
        changed = self.case.mark_events(rows, starred=starred, colour=colour,
                                        comment=comment)
        self.model.marks = {
            key: (bool(m['starred']), m['colour'], m['comment'])
            for key, m in self.case.timeline_marks().items()}
        self.model.refresh_all()
        self.lanes.canvas.update()
        row = self.current_row()
        if row is not None and not row.get('burst'):
            self._show_detail(row)
        if self.filters.get('starred_only') and starred is not None:
            self.refresh()
        return changed

    def comment(self, rows):
        rows = [r for r in rows if not r.get('burst')]
        if not rows:
            return
        mark = self.model.mark_of(rows[0])
        text, ok = QInputDialog.getMultiLineText(
            self, "Comment", f"Comment on {len(rows)} event(s) -- kept in "
            f"the case and its report (empty removes it):",
            (mark[2] if mark else '') or '')
        if ok:
            self.mark(rows, comment=text)

    # --- highlight rules ------------------------------------------------------

    def highlight_rules(self):
        if self.case is None:
            return list(timeline.DEFAULT_HIGHLIGHTS)
        stored = self.case.setting('timeline_highlights')
        return list(stored) if stored is not None else \
            [dict(rule) for rule in timeline.DEFAULT_HIGHLIGHTS]

    def apply_highlights(self):
        self.model.set_highlights(timeline.compile_highlights(
            self.highlight_rules()))

    def edit_highlights(self):
        from trace_app.ui.dialogs.timeline_highlights import \
            HighlightRulesDialog
        dialog = HighlightRulesDialog(self.highlight_rules(), self)
        if dialog.exec() and self.case is not None:
            self.case.set_setting('timeline_highlights', dialog.rules())
            self.apply_highlights()

    def _enter(self):
        index = self.table.currentIndex()
        if index.isValid():
            self._activated(index)

    def _ask_time(self):
        """Ctrl+G: go to a time typed in."""
        start = self.filters.get('start') or ''
        text, ok = QInputDialog.getText(
            self, "Go to Time", "Time (UTC), as 2024-05-01 or "
            "2024-05-01 13:45:00:", text=start[:19])
        moment = timeline.parse(text.strip()) if ok and text.strip() \
            else None
        if moment is None:
            return
        self.jump_to(timeline.text(moment))

    def _next_of_source(self, step):
        """The next (or previous) loaded event of the selected one's
        source."""
        row = self.current_row()
        if row is None:
            return
        position = self.table.currentIndex().row() + step
        while 0 <= position < len(self.model.rows):
            if self.model.rows[position]['source'] == row['source']:
                self.table.selectRow(position)
                self.table.scrollTo(self.model.index(position, 0))
                return
            position += step

    # --- time display ------------------------------------------------------------

    def _time_mode_changed(self, _index):
        self.model.set_time_mode(self.time_combo.currentData())
        self.model.headerDataChanged.emit(Qt.Horizontal, TIME, TIME)
        from trace_app.infra.window_state import save_value
        save_value('Timeline', 'time_mode',
                           self.time_combo.currentData())
        row = self.current_row()
        if row is not None:
            self._show_detail(row)

    def _offer_time_modes(self):
        """The display-zone choices only when the case names a zone."""
        from trace_app.core.settings import current
        zone = current('display_zone')
        from trace_app.infra.window_state import read_value
        wanted = read_value('Timeline', 'time_mode') or 'utc'
        self.time_combo.blockSignals(True)
        self.time_combo.setItemText(1, zone or "Display zone")
        self.time_combo.setVisible(bool(zone))
        index = self.time_combo.findData(wanted if zone else 'utc')
        self.time_combo.setCurrentIndex(max(0, index))
        self.time_combo.blockSignals(False)
        self.model.set_time_mode(self.time_combo.currentData())
        self.model.headerDataChanged.emit(Qt.Horizontal, TIME, TIME)

    # --- paging --------------------------------------------------------------------

    def _fetch_more(self, _after=True):
        """The view reached the last row read: read the next page."""
        rows = self.model.rows
        if not rows or self.case is None:
            self.model.fetching = False
            return
        last = rows[-1]
        self._start_page('after', (last['time'], last['row_key']))

    def _scrolled(self, value):
        """At the top of rows that do not start at the range's start (a
        jump), read the page before."""
        if value == self.table.verticalScrollBar().minimum() and \
                self.model.more_before and not self.model.fetching and \
                self.model.rows and self.case is not None:
            first = self.model.rows[0]
            self.model.fetching = True
            self._start_page('before', (first['time'], first['row_key']))

    def _start_page(self, how, key):
        page = _Page(self.case.folder, self._generation, dict(self.filters),
                     how, key, self)
        page.paged.connect(self._paged)
        self._page_generation += 1
        self._paging[self._page_generation] = page
        page.start()

    def _paged(self, generation, how, result):
        if generation != self._generation:
            return              # a page of a view since replaced
        if result.get('error'):
            self.model.fetching = False
            self.status_label.setText(
                f"Could not read the timeline: {result['error']}")
            return
        if how == 'after':
            self.model.append_rows(result['rows'], result['more'])
        elif how == 'before':
            bar = self.table.verticalScrollBar()
            keep = bar.value()
            self.model.prepend_rows(result['rows'], result['more'])
            # Stay on the rows that were in view.
            bar.setValue(keep + len(result['rows']) *
                         self.table.verticalHeader().defaultSectionSize())
        else:                   # 'at': a jump
            self.model.set_rows(result['rows'], self._names,
                                more_after=result['more'],
                                more_before=result['more_before'])
            if result['rows']:
                self.table.selectRow(0)
                self.table.scrollTo(self.model.index(0, 0),
                                    QAbstractItemView.PositionAtTop)
                self.table.setFocus()
        self.status_label.setText(self._status({}))

    def jump_to(self, moment):
        if self._collapsed_view:
            import bisect
            times = [row['time'] for row in self.model.rows]
            index = min(bisect.bisect_left(times, moment),
                        len(times) - 1)
            if index >= 0:
                self.table.selectRow(index)
                self.table.scrollTo(self.model.index(index, 0),
                                    QAbstractItemView.PositionAtTop)
            return
        self._jump_to(moment)

    def _jump_to(self, moment):
        """List from the first event at or after `moment` (rows before it
        are read in as the view scrolls up). Outside the range shown, the
        range moves there first."""
        start, end = self.filters.get('start'), self.filters.get('end')
        if (start and moment < start) or (end and moment >= end):
            span = None
            if start and end:
                span = timeline.parse(end) - timeline.parse(start)
            if span is not None:
                half = span / 2
                centre = timeline.parse(moment)
                self.set_range(timeline.text(centre - half),
                               timeline.text(centre + half))
            return
        self.model.fetching = True
        self._start_page('at', (moment, ''))

    def last_of_evidence(self, seconds):
        """The last `seconds` before the case's last event."""
        last = (self._case_bounds or (None, None))[1]
        if not last:
            return
        end = timeline.parse(last)
        if end is None:
            return
        import datetime
        end += datetime.timedelta(seconds=1)
        self.set_range(timeline.text(end - datetime.timedelta(
            seconds=seconds)), timeline.text(end))

    def whole_case(self):
        """Every event, from the first plausible time to the last."""
        self._whole = True
        self.refresh(find_bounds=True)

    def _flag_changed(self, key, on):
        self.filters[key] = on
        self._show_pivots()
        self.refresh()

    def _fill_readers(self, readers):
        """The Read By menu: everyone, each reader, each reader alone."""
        self.readers_menu.clear()
        for action in list(self._reader_actions.actions()):
            self._reader_actions.removeAction(action)
        chosen = (self.filters.get('reader'), bool(
            self.filters.get('reader_only')))
        entries = [(None, False, "Every reader")]
        entries += [(name, False, name) for name in readers]
        if len(readers) > 1:
            entries += [(name, True, f"Only {name}") for name in readers]
        for name, only, text in entries:
            if only and name == readers[0] and len(entries) > 2:
                self.readers_menu.addSeparator()
            action = self.readers_menu.addAction(text)
            action.setCheckable(True)
            action.setChecked((name, only) == chosen or
                              (name is None and chosen[0] is None))
            action.setToolTip(
                "Every event, whoever read it" if name is None else
                f"Records {name} read and no other reader did" if only
                else f"What {name} read (with what others read too)")
            self._reader_actions.addAction(action)
            action.triggered.connect(
                lambda _on=False, n=name, o=only: self._reader_chosen(n, o))
        self.readers_menu.setEnabled(len(readers) > 1)

    def _reader_chosen(self, name, only):
        self.filters['reader'] = name
        self.filters['reader_only'] = bool(only and name)
        self._show_pivots()
        self.refresh()

    def _readers_of_case(self):
        case = self.case
        if case is None:
            return []
        try:
            readers = case.activity_readers()
            tools = [run['tool'] for run in case.module_runs()
                     if run['status'] == 'complete']
        except Exception:
            return []
        for tool in tools:
            if tool not in readers:
                readers.append(tool)
        if 'TRACE' not in readers:
            readers.insert(0, 'TRACE')
        return readers

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
        self._fill_systems()
        self.filters['reader'] = None
        self.filters['reader_only'] = False
        self._fill_readers(self._readers_of_case())
        self._telemetry_count = 0       # the next load counts them
        defaults = timeline.default_filters()
        for key in ('sources', 'activity_categories', 'tool_activity'):
            self.filters[key] = defaults[key]
        for key, button in getattr(self, 'source_buttons', {}).items():
            button.blockSignals(True)
            button.setChecked(key in self.filters['sources'])
            button.blockSignals(False)
        options = self._hash_options()
        self.known_good_box.blockSignals(True)
        self.known_good_box.setEnabled(bool(options.get('enabled')))
        self.known_good_box.setChecked(bool(options.get('enabled') and
                                            options.get('hide_known_good')))
        self.filters['hide_known_good'] = self.known_good_box.isChecked()
        self.known_good_box.blockSignals(False)
        for widget in (self.export_button, self.views_button):
            widget.setEnabled(case is not None)
        self._offer_time_modes()
        self.apply_highlights()
        self._whole = False
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

    def _fill_systems(self):
        """The system filter's entries: all, each kind found more than
        once (every Windows), then each system with its image."""
        from trace_app.ui import icons
        combo = self.system_filter
        combo.blockSignals(True)
        combo.clear()
        combo.addItem("All systems", None)
        found = self.case.systems() if self.case is not None else {}
        entries = [(evidence_id, system) for evidence_id, systems in
                   found.items() for system in systems
                   if evidence_id in self._names]
        kinds = {}
        for evidence_id, system in entries:
            kinds.setdefault(system['family'], []).append(
                [evidence_id, system['volume_key']])
        labels = {'windows': 'Windows', 'linux': 'Linux', 'macos': 'macOS',
                  'android': 'Android'}
        for family, pairs in sorted(kinds.items()):
            if len(pairs) > 1:
                logo = next(s['logo'] for _e, s in entries
                            if s['family'] == family)
                combo.addItem(icons.os_logo(logo),
                              f"Every {labels.get(family, family)} "
                              f"({len(pairs)})", pairs)
        for evidence_id, system in entries:
            combo.addItem(icons.os_logo(system['logo']),
                          f"{system['name']} — {self._names[evidence_id]}",
                          [[evidence_id, system['volume_key']]])
            combo.setItemData(combo.count() - 1,
                              f"{system.get('volume') or ''} on "
                              f"{self._names[evidence_id]}",
                              Qt.ToolTipRole)
        wanted = self.filters.get('systems')
        index = next((i for i in range(combo.count())
                      if combo.itemData(i) == wanted), 0)
        combo.setCurrentIndex(index)
        self.filters['systems'] = combo.currentData()
        combo.blockSignals(False)
        combo.setVisible(bool(entries))

    def _system_changed(self, _index):
        self.filters['systems'] = self.system_filter.currentData()
        self.refresh()

    def _evidence_changed(self, _index):
        self.filters['evidence_id'] = self.evidence_filter.currentData()
        self.refresh()

    def _fs_changed(self, _index):
        self._set_filter('fs_attributes', self.fs_combo.currentData())

    def _text_changed(self):
        self._set_filter('text', self.text_input.text().strip())

    def apply_case_settings(self):
        """The case's choices of what the Timeline shows (Settings ▸
        Results: sources it opens with, Activity kinds, external tools'
        evidence) -- on opening a case and when they change."""
        defaults = timeline.default_filters()
        for key in ('sources', 'activity_categories', 'tool_activity'):
            self.filters[key] = defaults[key]
        for key, button in getattr(self, 'source_buttons', {}).items():
            button.blockSignals(True)
            button.setChecked(key in self.filters['sources'])
            button.blockSignals(False)
        self._dirty = True
        if self.isVisible():
            self.refresh(find_bounds=True)

    def _sources_changed(self, _on):
        self.filters['sources'] = [k for k, b in self.source_buttons.items()
                                   if b.isChecked()]
        self.refresh()

    def set_range(self, start, end, remember=True):
        safe = timeline.clamp_range(start, end)
        if safe is None:
            return
        start, end = safe
        if remember:
            self._history.append((self.filters.get('start'),
                                  self.filters.get('end')))
        self.filters['start'], self.filters['end'] = start, end
        self.refresh()

    def reset_range(self):
        """Where most events are (the view's opening range)."""
        self._whole = False
        self.refresh(find_bounds=True)

    def back(self):
        if not self._history:
            return
        start, end = self._history.pop()
        self.filters['start'], self.filters['end'] = start, end
        self.refresh(find_bounds=start is None)

    def _zoom(self, fraction, factor):
        """Zoom now (the buttons)."""
        start, end = self._pending_range or (self.filters.get('start'),
                                             self.filters.get('end'))
        zoomed = timeline.zoom_range(start, end, fraction, factor,
                                     self._case_bounds)
        if zoomed and zoomed != (self.filters.get('start'),
                                 self.filters.get('end')):
            self._wheel_timer.stop()
            self._pending_range = None
            self.set_range(*zoomed)

    def _wheel_zoom(self, fraction, factor):
        """Zoom when the wheel stops: the range moves at once in From /
        To, the query runs once."""
        start, end = self._pending_range or (self.filters.get('start'),
                                             self.filters.get('end'))
        zoomed = timeline.zoom_range(start, end, fraction, factor,
                                     self._case_bounds)
        if not zoomed:
            return
        self._pending_range = zoomed
        self._show_range(*zoomed)
        self._wheel_timer.start()

    def _apply_pending_zoom(self):
        pending, self._pending_range = self._pending_range, None
        if pending and pending != (self.filters.get('start'),
                                   self.filters.get('end')):
            self.set_range(*pending)

    def case_span(self):
        """(first, last) event time of the case under these filters."""
        return self._case_bounds or (None, None)

    def go_to_time(self, start, end):
        """Select the first event at or after `start`: among the rows read,
        or listed from there (the rows before follow as the view scrolls
        up). The range stays."""
        import bisect
        times = [row['time'] for row in self.model.rows]
        index = bisect.bisect_left(times, start)
        if index < len(times) and (index > 0 or not self.model.more_before):
            self.table.selectRow(index)
            self.table.scrollTo(self.model.index(index, 0),
                                QAbstractItemView.PositionAtTop)
            self.table.setFocus()
            return
        self.jump_to(start)

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
        """A chip for everything narrowing the view, each removing it."""
        while self.pivot_row.count():
            item = self.pivot_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        chips = []
        for key, label in (('focus_ref', 'File'), ('user', 'User'),
                           ('folder', 'Folder')):
            value = self.filters.get(key)
            if not value:
                continue
            text = value[1] if key == 'focus_ref' else value
            if key == 'focus_ref':
                text = getattr(self, '_focus_label', text)
            chips.append((f"{label}: {text}",
                          lambda k=key: self._drop_pivot(k)))
        for key, label in (('deleted_only', 'Deleted only'),
                           ('timestomped_only', 'Timestomped only'),
                           ('hide_known_good', 'Known good hidden'),
                           ('starred_only', 'Starred only'),
                           ('module_telemetry', 'Module telemetry shown')):
            if self.filters.get(key):
                chips.append((label, lambda k=key: self._drop_flag(k)))
        if self.filters.get('reader'):
            chips.append(((f"Only read by: {self.filters['reader']}"
                           if self.filters.get('reader_only') else
                           f"Read by: {self.filters['reader']}"),
                          lambda: self._reader_chosen(None, False)))
        hidden = getattr(self, '_telemetry_count', 0)
        columns = self.filters.get('columns') or {}
        if columns.get('hours') is not None:
            chips.append((f"Hours: {self._hours_label}",
                          lambda: self._drop_hours()))
        for key, label in (('kind_is', 'Type is'), ('folder_is', 'Folder is'),
                           ('extension', 'Extension')):
            if columns.get(key) is not None:
                shown = columns[key]
                if key == 'kind_is':
                    shown = _kind_label(shown)
                elif key == 'extension':
                    shown = f".{shown}" if shown else '(none)'
                chips.append((f"{label}: {shown or '(none)'}",
                              lambda k=key: self._drop_column(k)))
        for column, text in self.column_filters.values().items():
            chips.append((f"{_COLUMNS[column].split(' (')[0]}: {text}",
                          lambda c=column: self.column_filters.clear_column(
                              c)))
        for text, drop in chips:
            chip = QToolButton()
            chip.setObjectName("timelinePivotChip")
            chip.setText(f"{text}  ✕")
            chip.setToolTip("Remove this filter")
            chip.clicked.connect(lambda _c=False, d=drop: d())
            self.pivot_row.addWidget(chip)
        if hidden and not self.filters.get('module_telemetry'):
            # Not a filter one removes: what is left out, and the way to
            # bring it in.
            shown = QToolButton()
            shown.setObjectName("timelinePivotChip")
            shown.setText(f"{hidden:,} module telemetry events hidden — "
                          f"show")
            shown.setToolTip("External modules' log lines and device "
                             "samples (Filters ▸ Telemetry from Modules)")
            shown.clicked.connect(
                lambda _c=False: self.telemetry_box.setChecked(True))
            self.pivot_row.addWidget(shown)
            chips.append(('telemetry', None))
        if len(chips) > 1:
            clear = QToolButton()
            clear.setObjectName("timelineClearChips")
            clear.setText("Clear all")
            clear.clicked.connect(self._clear_filters)
            self.pivot_row.addWidget(clear)
        self.pivot_holder.setVisible(bool(chips))

    def _drop_hours(self):
        self.insights.heatmap.chosen = None
        self.insights.heatmap.update()
        self._drop_column('hours')

    def _drop_column(self, key):
        columns = dict(self.filters.get('columns') or {})
        columns.pop(key, None)
        self.filters['columns'] = columns
        self._show_pivots()
        self.refresh()

    def _drop_flag(self, key):
        action = {'deleted_only': self.deleted_box,
                  'timestomped_only': self.stomped_box,
                  'hide_known_good': self.known_good_box,
                  'starred_only': self.starred_box,
                  'module_telemetry': self.telemetry_box}[key]
        action.setChecked(False)

    def _clear_filters(self):
        """Every pivot, switch and column filter off; one query."""
        for key in ('focus_ref', 'user', 'folder'):
            self.filters[key] = None
        for action, key in ((self.deleted_box, 'deleted_only'),
                            (self.stomped_box, 'timestomped_only'),
                            (self.known_good_box, 'hide_known_good'),
                            (self.starred_box, 'starred_only'),
                            (self.telemetry_box, 'module_telemetry')):
            action.blockSignals(True)
            action.setChecked(False)
            action.blockSignals(False)
            self.filters[key] = False
        self.filters['reader'] = None
        self.filters['reader_only'] = False
        self._fill_readers(self._readers_of_case())
        self.column_filters.set_values({})
        self.filters['columns'] = {}
        self.filters['user'] = None
        self._show_pivots()
        self.refresh(find_bounds=True)

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
                     find_bounds, self, whole=self._whole,
                     collapse=self._window
                     if self.collapse_button.isChecked() else None)
        load.loaded.connect(self._loaded)
        self._loads[self._generation] = load
        self.status_label.setText("Loading…")
        load.start()

    def _loaded(self, generation, result):
        if generation != self._generation:
            return
        filters = result.get('filters') or self.filters
        if filters.get('start') and not self.filters.get('start'):
            self.filters['start'], self.filters['end'] = \
                filters['start'], filters['end']
        if result.get('bounds') and result['bounds'][0]:
            self._case_bounds = result['bounds']
        if self._fill_fs_combo(result.get('fs_kinds') or []):
            return                  # the narrowing chosen is gone: re-read
        self.counts = result['counts']
        self.total = result['total']
        telemetry = result.get('telemetry', 0)
        if telemetry != getattr(self, '_telemetry_count', 0):
            self._telemetry_count = telemetry
            self._show_pivots()         # its "N hidden" chip
        if 'trimmed' in result or result.get('bounds'):
            self._trimmed = result.get('trimmed', 0)
        self._collapsed_view = bool(result.get('collapsed'))
        self._bursts = result.get('bursts', 0)
        self._too_varied = result.get('too_varied', False)
        self.model.marks = result.get('marks') or {}
        self.model.set_rows(result['rows'], self._names,
                            more_after=result.get('more_after', False))
        if self.views.currentWidget() is self.summary:
            self.summary.load(self.case, self.filters, self._names)
        elif self.views.currentWidget() is self.lanes:
            self.lanes.load(self.case, self.filters)
        if self.side.currentWidget() is self.insights:
            self.insights.load(self.case, self.filters, self._zone())
        else:
            self.histogram.set_gaps([])
        if self._pending_jump:
            moment, self._pending_jump = self._pending_jump, None
            self.go_to_time(moment[:19], '9999')
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

    def _fill_fs_combo(self, kinds):
        """Offer the file-system time kinds the case (or image) holds --
        nothing to choose, nothing shown. Returns True when the chosen kind
        is no longer there and the timeline is read again without it."""
        labels = {key: label for key, label, _s in timeline.FS_KINDS}
        wanted = ['both'] + list(kinds)
        present = [self.fs_combo.itemData(i)
                   for i in range(self.fs_combo.count())]
        if present != wanted:
            self.fs_combo.blockSignals(True)
            self.fs_combo.clear()
            self.fs_combo.addItem("All file-system times", 'both')
            for key in kinds:
                self.fs_combo.addItem(labels[key], key)
            self.fs_combo.blockSignals(False)
        self.fs_combo.setVisible(len(kinds) > 1)
        chosen = self.filters.get('fs_attributes') or 'both'
        if chosen not in wanted:
            self.filters['fs_attributes'] = 'both'
            self.fs_combo.blockSignals(True)
            self.fs_combo.setCurrentIndex(0)
            self.fs_combo.blockSignals(False)
            self.refresh()
            return True
        self.fs_combo.blockSignals(True)
        self.fs_combo.setCurrentIndex(max(0, self.fs_combo.findData(chosen)))
        self.fs_combo.blockSignals(False)
        return False

    def _status(self, result):
        if result.get('error'):
            return f"Could not read the timeline: {result['error']}"
        if not self.total and not any(self.counts.values()):
            filters = self.filters
            if any(filters.get(k) for k in ('text', 'focus_ref', 'user',
                                             'folder', 'deleted_only',
                                             'timestomped_only', 'columns')):
                return "Nothing matches these filters."
            return ("Nothing to show yet. The timeline is built from "
                    "Analysis ▸ Run Analysis Modules: NTFS times and the "
                    "change journal, activity, photo and document dates.")
        text = f"{self.total:,} event(s) in this range"
        if self._collapsed_view and self._bursts:
            text += (f", {len(self.model.rows):,} rows with "
                     f"{self._bursts:,} burst(s) collapsed")
        elif getattr(self, '_too_varied', False):
            text += " (too varied to collapse: listed one by one)"
        trimmed = getattr(self, '_trimmed', 0)
        if trimmed and not self._whole:
            text += (f" · opened where most events are; {trimmed:,} lie "
                     f"outside (Range ▸ Whole case)")
        if result.get('outside'):
            text += (f" · {result['outside']:,} dated before "
                     f"{timeline.PLAUSIBLE_FROM[:4]} or in the future are "
                     f"left out (type a range to see them)")
        return text

    def _show_range(self, start=None, end=None):
        start = start or self.filters.get('start')
        end = end or self.filters.get('end')
        if start and end:
            self.range_button.setText(f"{start[:16]}  →  {end[:16]}")
        for edit, value in ((self.from_edit, start), (self.to_edit, end)):
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
        """The events selected (a collapsed burst's row is not one)."""
        rows = sorted({index.row() for index in
                       self.table.selectionModel().selectedRows()})
        return [self.model.rows[r] for r in rows
                if not self.model.rows[r].get('burst')]

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
        self.lanes.canvas.set_marker(row['time'])
        if row.get('burst'):
            self._show_burst(row)
            return
        self._show_detail(row)
        if row['artifact_ref'] and row['evidence_id'] is not None:
            self.row_selected.emit(self._payload(row))

    def _activated(self, index):
        row = self.model.data(index, Qt.UserRole)
        if row and row.get('burst'):
            self.toggle_burst(index.row())
            return
        if row and row['artifact_ref'] and row['evidence_id'] is not None:
            self.row_activated.emit(self._payload(row))

    # --- bursts ---------------------------------------------------------------

    def _collapse_toggled(self, on):
        from trace_app.infra.window_state import save_value
        save_value('Timeline', 'collapse', '1' if on else '0')
        self.refresh()

    def _set_window(self, key):
        from trace_app.infra.window_state import save_value
        self._window = key
        for other, action in self._window_actions.items():
            action.setChecked(other == key)
        save_value('Timeline', 'burst_window', key)
        if self.collapse_button.isChecked():
            self.refresh()
        else:
            self.collapse_button.setChecked(True)

    def toggle_burst(self, position):
        """List a burst's events beneath it, or fold them away again."""
        burst = self.model.rows[position]
        if burst.get('expanded'):
            end = position + 1
            while end < len(self.model.rows) and \
                    self.model.rows[end].get('in_burst') == burst['row_key']:
                end += 1
            self.model.remove_rows(position + 1, end - position - 1)
            burst['expanded'] = False
            self.model.row_changed(position)
            return
        if burst.get('loading'):
            return
        from trace_app.core import timeline_clusters
        burst['loading'] = True
        page = _Page(self.case.folder, self._generation, dict(self.filters),
                     'burst', timeline_clusters.burst_filters(self.filters,
                                                              burst), self)
        page.paged.connect(
            lambda generation, _how, result, key=burst['row_key']:
            self._burst_listed(generation, key, result))
        self._page_generation += 1
        self._paging[self._page_generation] = page
        page.start()

    def _burst_listed(self, generation, key, result):
        if generation != self._generation:
            return
        position = next((i for i, row in enumerate(self.model.rows)
                         if row['row_key'] == key), None)
        if position is None:
            return
        burst = self.model.rows[position]
        burst['loading'] = False
        if result.get('error'):
            self.status_label.setText(
                f"Could not read the burst: {result['error']}")
            return
        rows = result['rows']
        for row in rows:
            row['in_burst'] = key
        burst['expanded'] = True
        self.model.insert_rows(position + 1, rows)
        self.model.row_changed(position)

    def _show_burst(self, row):
        from trace_app.ui.widgets import detail_html as d
        colour = timeline.SOURCE_COLOURS.get(row['source'], '#888888')
        span = f"{row['time'][:19]} – {(row['last'] or '')[:19]}"
        title = (f"<table cellspacing='0' cellpadding='0'><tr>"
                 f"<td bgcolor='{colour}' width='4'></td><td width='8'>"
                 f"</td><td>{d.heading(row['title'], span)}</td></tr>"
                 f"</table>")
        pairs = [("Source", timeline.SOURCE_LABELS.get(row['source'])),
                 ("Type", timeline.describe_kind(row)),
                 ("Events", f"{row['count']:,}"),
                 ("Deleted", f"{row['deleted']:,}" if row.get('deleted')
                  else None),
                 ("Users", ', '.join(row.get('users') or []) or None),
                 ("Evidence", self._names.get(row['evidence_id'])),
                 ("Examples", ', '.join(row.get('names') or []) or None)]
        folders = row.get('folders') or []
        lines = ''.join(
            f"<tr><td class='mono'>{number:,}</td>"
            f"<td>{d.breakable(folder or '(no folder)')}</td></tr>"
            for folder, number in folders[:25])
        more = (f"<p class='note'>… and {len(folders) - 25:,} more "
                f"folders</p>" if len(folders) > 25 else '')
        links = ("<p><a href='burst:toggle'>"
                 + ("Fold its events away" if row.get('expanded')
                    else "List its events") +
                 "</a> &nbsp;·&nbsp; <a href='burst:zoom'>Zoom to it</a></p>")
        self.detail.setHtml(d.STYLE + title + d.facts(pairs) + links
                            + d.section(f"Folders ({len(folders):,})")
                            + "<table cellspacing='0' cellpadding='0'>"
                            + lines + "</table>" + more)

    def zoom_to_burst(self, row):
        import datetime
        last = timeline.parse(row['last']) or timeline.parse(row['time'])
        self.set_range(row['time'][:19], timeline.text(
            last + datetime.timedelta(seconds=1)))

    # --- the Summary view ---------------------------------------------------------

    def set_view(self, key):
        """'events' (the table) or 'summary'."""
        self.view_buttons[key].setChecked(True)
        if key == 'summary':
            self.views.setCurrentWidget(self.summary)
            if self.case is not None:
                self.summary.load(self.case, self.filters, self._names)
        elif key == 'lanes':
            self.views.setCurrentWidget(self.lanes)
            if self.case is not None:
                self.lanes.load(self.case, self.filters)
        else:
            self.views.setCurrentWidget(self.table)

    def apply_group(self, by, value):
        """A Summary group double-clicked: the events narrowed to it."""
        columns = dict(self.filters.get('columns') or {})
        if by == 'source':
            self.filters['sources'] = [value]
            self._sync_controls()
        elif by == 'kind':
            columns['kind_is'] = value
        elif by == 'folder':
            columns['folder_is'] = value
        elif by == 'extension':
            columns['extension'] = value
        elif by == 'user':
            self.filters['user'] = value or None
        elif by == 'evidence':
            self.filters['evidence_id'] = value
            self._sync_controls()
        self.filters['columns'] = columns
        self._show_pivots()
        self.set_view('events')
        self.refresh()

    def _show_detail(self, row):
        from trace_app.ui.widgets import detail_html as d
        pairs = [("Source", timeline.SOURCE_LABELS.get(row['source'])),
                 ("Description", _description(row)),
                 ("Path", row['subject'], 'path'),
                 ("User", row['user']),
                 ("Evidence", self._names.get(row['evidence_id'])),
                 ("Deleted", "yes" if row['deleted'] else None)]
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
                    pairs.append((key.replace('_', ' ').capitalize(), value,
                                  'path' if key == 'source_path' else ''))
            if isinstance(detail, dict):
                for key, value in detail.items():
                    pairs.append((key, value))
        pairs.append(("Reference", row['artifact_ref'], 'mono'))
        if row['local']:
            time = row['time'] + " (local, no zone)"
        else:
            mode = self.model.time_mode
            time = shown_time(row['time'], 'both' if mode == 'utc'
                              else mode)
            if time == row['time']:
                time += " UTC"
        letters = timeline.macb(row)
        if letters:
            pairs.insert(1, ("MACB", letters, 'mono'))
        colour = timeline.SOURCE_COLOURS.get(row['source'], '#888888')
        # The source's colour as a bar beside the heading, as in the table
        # and the histogram.
        title = (f"<table cellspacing='0' cellpadding='0'><tr>"
                 f"<td bgcolor='{colour}' width='4'></td><td width='8'>"
                 f"</td><td>{d.heading(timeline.describe_kind(row), time)}"
                 f"</td></tr></table>")
        parts = [d.STYLE, title, d.facts(pairs)]
        if self.detail_extender is not None:
            try:
                parts.append(self.detail_extender(row) or '')
            except Exception as exc:
                logger.debug("Detail for %s: %s", row['artifact_ref'], exc)
        mark = self.model.mark_of(row)
        if mark:
            starred, colour, comment = mark
            parts.append(d.section("Your mark"))
            parts.append(d.facts([
                ("Starred", "yes" if starred else None),
                ("Colour", next((n for n, v in
                                 self.case.MARK_COLOURS.items()
                                 if v == colour), colour)
                 if colour and self.case is not None else None),
                ("Comment", comment)]))
        parts.append(self._nearby_html(row))
        self.detail.setHtml(''.join(parts))

    #: How near in time "Nearby on this file" looks, and how many it lists.
    NEARBY_SECONDS = 300
    NEARBY_SHOWN = 12

    def _nearby_html(self, row):
        """Other events of the same file within NEARBY_SECONDS, from the
        rows read: links that select them."""
        from trace_app.ui.widgets import detail_html as d
        if not row['artifact_ref'] or row['evidence_id'] is None:
            return ''
        start, end = timeline.around(row['time'], self.NEARBY_SECONDS)
        found = [r for r in self.model.rows
                 if r['artifact_ref'] == row['artifact_ref']
                 and r['evidence_id'] == row['evidence_id']
                 and r['row_key'] != row['row_key']
                 and start <= r['time'] < end][:self.NEARBY_SHOWN]
        if not found:
            return ''
        lines = ''.join(
            f"<tr><td class='mono'>{d.e(r['time'][:19])}</td>"
            f"<td><a href='row:{d.e(r['row_key'])}'>"
            f"{d.e(timeline.describe_kind(r))}</a></td></tr>"
            for r in found)
        return (d.section(f"Nearby on this file (± "
                          f"{self.NEARBY_SECONDS // 60} min)")
                + "<table cellspacing='0' cellpadding='0'>" + lines
                + "</table>")

    def _detail_link(self, url):
        """A 'row:<row_key>' link in the detail pane selects that event."""
        text = url.toString()
        if text.startswith('burst:'):
            index = self.table.currentIndex()
            row = self.current_row()
            if row is None or not row.get('burst'):
                return
            if text == 'burst:toggle':
                self.toggle_burst(index.row())
                self._show_burst(row)
            else:
                self.zoom_to_burst(row)
            return
        if not text.startswith('row:'):
            return
        key = text[4:]
        for position, row in enumerate(self.model.rows):
            if row['row_key'] == key:
                self.table.selectRow(position)
                self.table.scrollTo(self.model.index(position, 0))
                return

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.model.data(index, Qt.UserRole)
        menu = QMenu(self)
        if row.get('burst'):
            toggle = menu.addAction("Fold Its Events Away"
                                    if row.get('expanded')
                                    else "List Its Events")
            toggle.triggered.connect(
                lambda: self.toggle_burst(index.row()))
            menu.addAction("Zoom to This Burst").triggered.connect(
                lambda: self.zoom_to_burst(row))
            show_menu(menu, self.table.viewport().mapToGlobal(point))
            return
        self._event_menu(menu, row, self.selected_rows() or [row])
        show_menu(menu, self.table.viewport().mapToGlobal(point))

    def _lane_menu(self, row, position):
        """A Lanes marker right-clicked: the event's own menu."""
        menu = QMenu(self)
        self._event_menu(menu, row, [row])
        show_menu(menu, position)

    def _event_menu(self, menu, row, selected):
        if self.case is not None:
            mark = self.model.mark_of(row)
            starred = bool(mark and mark[0])
            star = menu.addAction(
                f"{'Unstar' if starred else 'Star'} {len(selected)} "
                f"Event(s)\tS")
            star.setIcon(icons.icon(icons.TIMELINE_STAR, tint='#E3A008'))
            star.triggered.connect(
                lambda: self.mark(selected, starred=not starred))
            colours = menu.addMenu("Colour")
            for name, value in self.case.MARK_COLOURS.items():
                action = colours.addAction(icons.dot_icon(value),
                                           name.capitalize())
                action.triggered.connect(
                    lambda _c=False, v=value: self.mark(selected, colour=v))
            colours.addSeparator()
            colours.addAction("None").triggered.connect(
                lambda: self.mark(selected, colour=''))
            menu.addAction("Comment…").triggered.connect(
                lambda: self.comment(selected))
            menu.addSeparator()
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
        report = menu.addAction(
            f"Add {len(selected)} Event(s) to Report")
        report.setIcon(icons.icon(icons.REPORT))
        report.triggered.connect(lambda: self.report_requested.emit(selected))
        copy = menu.addAction("Copy Row(s)")
        copy.triggered.connect(lambda: self._copy(selected))
        if self.menu_extender is not None and has_file:
            menu.addSeparator()
            self.menu_extender(menu, self._payload(row))

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

    def export_csv(self, path=None, fmt='csv'):
        """Every selected event in `fmt` (timeline_export.FORMATS)."""
        if self.case is None:
            return
        label, extension, pattern = timeline_export.FORMATS[fmt]
        # Only a real path: a button's `checked` flag once arrived here as
        # False, and open(False) is the console.
        if not isinstance(path, str) or not path:
            # The case's export folder -- its exports/, or the one its
            # settings name (Options > Settings > Carving & exports).
            stem = 'timeline' if fmt == 'csv' else f'timeline-{fmt}'
            default = os.path.join(self.case.exports_dir, stem + extension)
            os.makedirs(os.path.dirname(default), exist_ok=True)
            path, _ = QFileDialog.getSaveFileName(
                self, f"Export Timeline as {label}", default, pattern)
            if not path:
                return
        self.export_button.setEnabled(False)
        self.status_label.setText("Exporting…")
        self._export = _Export(self.case.folder, dict(self.filters), path,
                               self._names, self, fmt=fmt)
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
        # The boxes' own text: Source and Evidence filters are kept as
        # keys, which the boxes cannot show again.
        stored['column_texts'] = {str(c): t for c, t in
                                  self.column_filters.values().items()}
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
        texts = filters.pop('column_texts', None) or {}
        self.column_filters.set_values({int(c): t for c, t in texts.items()})
        if texts:
            self.column_filters_action.setChecked(True)
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
        self.starred_box.blockSignals(True)
        self.starred_box.setChecked(bool(self.filters.get('starred_only')))
        self.starred_box.blockSignals(False)
        self.text_input.setText(self.filters.get('text') or '')
        self.fs_combo.setCurrentIndex(max(0, self.fs_combo.findData(
            self.filters.get('fs_attributes') or 'both')))
        self.evidence_filter.setCurrentIndex(max(0, self.evidence_filter
                                                 .findData(self.filters.get(
                                                     'evidence_id'))))
        self.system_filter.blockSignals(True)
        self.system_filter.setCurrentIndex(next(
            (i for i in range(self.system_filter.count())
             if self.system_filter.itemData(i) ==
             self.filters.get('systems')), 0))
        self.system_filter.blockSignals(False)
        for key, button in self.source_buttons.items():
            button.setChecked(key in (self.filters.get('sources') or ()))
        self._show_pivots()
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

    # --- Insights --------------------------------------------------------------

    @staticmethod
    def _zone():
        from trace_app.core.settings import current
        return current('display_zone') or None

    def _side_changed(self, _index):
        if self.side.currentWidget() is self.insights and \
                self.case is not None:
            self.insights.load(self.case, self.filters, self._zone())

    def _hours_chosen(self, day, hour):
        """A heatmap cell: only that hour of that weekday (again: all)."""
        columns = dict(self.filters.get('columns') or {})
        cell = (day, hour)
        if self.insights.heatmap.chosen == cell:
            columns.pop('hours', None)
            self.insights.heatmap.chosen = None
        else:
            columns['hours'] = self.insights.cells.get(cell, [])
            self.insights.heatmap.chosen = cell
            self._hours_label = (f"{timeline.WEEKDAYS[day]} {hour:02d}:00–"
                                 f"{(hour + 1) % 24:02d}:00"
                                 + (f" ({self.insights.zone})"
                                    if self.insights.zone else " UTC"))
        self.insights.heatmap.update()
        self.filters['columns'] = columns
        self._show_pivots()
        self.refresh()

    def _gap_chosen(self, start, end):
        """A gap: the range around it, a tenth of it either side."""
        first, last = timeline.parse(start), timeline.parse(end)
        margin = (last - first) / 10
        self.set_range(timeline.text(first - margin),
                       timeline.text(last + margin))

    def apply_finding(self, finding):
        """A check clicked: its events (core/timeline_anomalies actions)."""
        action = finding.get('action') or {}
        for key, value in (action.get('filters') or {}).items():
            self.filters[key] = value
        if action.get('columns'):
            columns = dict(self.filters.get('columns') or {})
            columns.update(action['columns'])
            self.filters['columns'] = columns
            texts = self.column_filters.values()
            if 'title' in action['columns']:
                texts[DESCRIPTION] = action['columns']['title']
                self.column_filters.set_values(texts)
                self.column_filters_action.setChecked(True)
        self._sync_controls()
        self._show_pivots()
        self.side.setCurrentWidget(self.detail)
        if action.get('jump'):
            self._pending_jump = action['jump']
        if action.get('range'):
            self.set_range(*action['range'])
        else:
            self.refresh(find_bounds=True)

    def select_event(self, row):
        """An event picked elsewhere (a Lanes marker): selected in the
        table when it is listed, and shown and previewed either way."""
        for position, listed in enumerate(self.model.rows):
            if listed['row_key'] == row['row_key']:
                self.table.selectRow(position)
                self.table.scrollTo(self.model.index(position, 0))
                return
        self.histogram.set_marker(row['time'])
        self.lanes.canvas.set_marker(row['time'])
        self._show_detail(row)
        if row['artifact_ref'] and row['evidence_id'] is not None:
            self.row_selected.emit(self._payload(row))

    def shutdown(self):
        self.insights.shutdown()
        self.summary.shutdown()
        self.lanes.shutdown()
        self._loads.clear()
        self._paging.clear()
        if self._export is not None:
            self._export.wait(30000)


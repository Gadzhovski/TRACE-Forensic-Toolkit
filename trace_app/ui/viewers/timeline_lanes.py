"""The Timeline's Lanes view: the events of the range on one time axis, a
lane per source (or image, user, type).

Where the range holds many events each lane is a density strip -- one
query counts them per lane per few pixels (`timeline.lane_counts`) -- so
it reads at any zoom, as a heat line. Where it holds few (`SPARSE_MOST`),
every event is a marker, stacked within its lane so neighbours do not hide
each other, with its name beside it when there is room: what happened in
those minutes, at a glance. As in Autopsy's Details view.

Same gestures as the histogram: drag to zoom to a span, the wheel to zoom
around the pointer. A click on a marker selects that event (its details
show beside the view); on a strip it goes to that moment.
"""

import datetime
import logging
import os
import sqlite3

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QSizePolicy,
                               QToolTip, QVBoxLayout, QWidget)

from trace_app.core import timeline
from trace_app.core.case import CASE_DB_NAME
from trace_app.core.timeline_axis import calendar_ticks
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.wheel_zoom import zoom_on_wheel
from trace_app.infra.sqlite_uri import connect_read_only

logger = logging.getLogger('TRACE.Timeline')

#: At most this many events in the range and each is drawn as a marker.
SPARSE_MOST = 2000
#: Pixels of time per density bucket.
BUCKET_PIXELS = 3
LABEL_WIDTH = 150
LANE_HEIGHT = 38
#: Marker rows within a lane before markers overlap.
MARKER_SLOTS = 3
#: Lanes shown when lanes are types (there can be dozens): the busiest;
#: the rest share one.
MOST_LANES = 12
_OTHER = '\x00other'
#: Lane colours where the lanes are not sources.
_PALETTE = ('#4C8BF5', '#E8743B', '#3FB950', '#9B6CF0', '#E3A008',
            '#17A2B8', '#E5534B', '#8A939E', '#D45087', '#2F9E9E',
            '#B07AA1', '#7A9E3F', '#A0A0A0')


class _LaneLoad(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, filters, by, buckets,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.by, self.buckets = filters, by, buckets

    def run(self):
        result = {'counts': {}, 'events': None, 'error': '',
                  'buckets': self.buckets}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = connect_read_only(path)
            try:
                result['counts'] = timeline.lane_counts(
                    connection, self.filters, self.by, self.buckets)
                total = sum(sum(c.values())
                            for c in result['counts'].values())
                if total <= SPARSE_MOST:
                    result['events'] = timeline.events_after(
                        connection, self.filters, None, SPARSE_MOST)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read the lanes: %s", exc)
            result['error'] = str(exc)
        self.loaded.emit(self.generation, result)


class LanesCanvas(QWidget):
    """The painted lanes. Signals as the histogram's, plus the event
    clicked (a timeline row) and the event right-clicked (row, global
    position)."""

    range_selected = Signal(str, str)
    zoom_requested = Signal(float, float)
    time_clicked = Signal(str, str)
    event_clicked = Signal(dict)
    event_menu = Signal(dict, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineLanes")
        self.setMouseTracking(True)
        self.setCursor(Qt.CrossCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.lanes = []             # [(key, label, colour)]
        self.counts = {}            # lane key -> {bucket: count}
        self.events = None          # rows, when few
        self.buckets = 1
        self.start = self.end = None
        self.marker = None
        self.message = ''
        self._markers = []          # (QRectF, row)
        self._drag_from = self._drag_to = None
        self._hover = None

    def set_data(self, lanes, counts, events, buckets, start, end):
        self.lanes, self.counts, self.events = lanes, counts, events
        self.buckets = max(1, buckets)
        self.start, self.end = timeline.parse(start), timeline.parse(end)
        self.message = ''
        self.update()

    def set_message(self, text):
        self.message = text
        self.update()

    def set_marker(self, time_text):
        self.marker = timeline.parse(time_text)
        self.update()

    def plot(self):
        top = 6
        height = max(LANE_HEIGHT * max(1, len(self.lanes)),
                     self.height() - top - 24)
        return QRectF(LABEL_WIDTH, top, max(10, self.width() - LABEL_WIDTH
                                            - 10), height)

    def lane_rect(self, position):
        plot = self.plot()
        # The lanes share the height there is, up to a comfortable most.
        height = min(LANE_HEIGHT * 3, plot.height() / max(1, len(self.lanes)))
        return QRectF(plot.left(), plot.top() + position * height,
                      plot.width(), height)

    def _x(self, moment, plot):
        span = (self.end - self.start).total_seconds() or 1
        return plot.left() + plot.width() * \
            (moment - self.start).total_seconds() / span

    def _moment(self, x, plot):
        span = (self.end - self.start).total_seconds()
        fraction = min(1, max(0, (x - plot.left()) / plot.width()))
        return self.start + datetime.timedelta(seconds=span * fraction)

    # --- painting -----------------------------------------------------------

    def paintEvent(self, _event):
        painter = QPainter(self)
        palette = self.palette()
        base = palette.color(palette.ColorRole.Base)
        text = palette.color(palette.ColorRole.Text)
        painter.fillRect(self.rect(), base)
        faint = QColor(text)
        faint.setAlpha(22)
        self._markers = []
        if self.message or not self.start or not self.end or \
                self.end <= self.start or not self.lanes:
            painter.setPen(text)
            painter.drawText(self.rect(), Qt.AlignCenter,
                             self.message or "No events in this range")
            return
        plot = self.plot()
        font = painter.font()
        # Ticks and gridlines.
        small = painter.font()
        small.setPointSizeF(max(7.0, small.pointSizeF() - 1.5))
        painter.setFont(small)
        metrics = painter.fontMetrics()
        last_right = -1e9
        bottom = self.lane_rect(len(self.lanes) - 1).bottom()
        for moment, label in calendar_ticks(self.start, self.end,
                                            max(2, int(plot.width() // 90))):
            x = self._x(moment, plot)
            painter.setPen(faint)
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, bottom))
            w = metrics.horizontalAdvance(label)
            left = min(max(plot.left(), x - w / 2), plot.right() - w)
            if left > last_right + 8:
                painter.setPen(text)
                painter.drawText(QPointF(left, bottom + 14), label)
                last_right = left + w
        painter.setFont(font)
        metrics = painter.fontMetrics()
        # Lanes.
        for position, (key, label, colour) in enumerate(self.lanes):
            lane = self.lane_rect(position)
            if position % 2:
                stripe = QColor(text)
                stripe.setAlpha(8)
                painter.fillRect(QRectF(0, lane.top(), self.width(),
                                        lane.height()), stripe)
            painter.setPen(QColor(colour))
            painter.setBrush(QColor(colour))
            painter.drawEllipse(QRectF(8, lane.center().y() - 4, 8, 8))
            painter.setPen(text)
            total = sum(self.counts.get(key, {}).values())
            painter.drawText(QRectF(22, lane.top(), LABEL_WIDTH - 26,
                                    lane.height()),
                             Qt.AlignVCenter | Qt.AlignLeft,
                             metrics.elidedText(f"{label} ({total:,})",
                                                Qt.ElideRight,
                                                LABEL_WIDTH - 26))
            if self.events is not None:
                self._paint_markers(painter, plot, lane, key, colour, text)
            else:
                self._paint_density(painter, plot, lane, key, colour)
        self._paint_overlays(painter, plot, bottom, text, palette)

    def _paint_density(self, painter, plot, lane, key, colour):
        counts = self.counts.get(key) or {}
        if not counts:
            return
        # Each lane against its own busiest moment: a lane of 88 events
        # beside one of 500,000 must still show where its 88 are.
        peak = max(counts.values())
        width = plot.width() / self.buckets
        middle = lane.center().y()
        full = lane.height() - 10
        baseline = QColor(colour)
        baseline.setAlpha(50)
        painter.setPen(QPen(baseline, 1))
        painter.drawLine(QPointF(plot.left(), middle),
                         QPointF(plot.right(), middle))
        painter.setPen(Qt.NoPen)
        for bucket, number in counts.items():
            # Square root, as the histogram: one burst must not flatten
            # the rest of the lane to nothing.
            share = (number / peak) ** 0.5
            height = max(5.0, full * share)
            shade = QColor(colour)
            shade.setAlpha(150 + int(105 * share))
            painter.fillRect(QRectF(plot.left() + bucket * width,
                                    middle - height / 2,
                                    max(1.5, width), height), shade)

    def _paint_markers(self, painter, plot, lane, key, colour, text):
        rows = [r for r in self.events if self.lane_key(r) == key]
        slot_height = (lane.height() - 4) / MARKER_SLOTS
        ends = [-1e9] * MARKER_SLOTS
        metrics = painter.fontMetrics()
        labels = []
        for row in rows:
            moment = timeline.parse(row['time'])
            if moment is None:
                continue
            x = self._x(moment, plot)
            # The first slot whose last label this marker clears; else the
            # one free longest ago, the marker drawn without a label (its
            # tooltip says what it is).
            free = next((i for i in range(MARKER_SLOTS) if ends[i] < x - 4),
                        None)
            slot = free if free is not None else min(
                range(MARKER_SLOTS), key=lambda i: ends[i])
            y = lane.top() + 2 + slot * slot_height + slot_height / 2
            rect = QRectF(x - 4, y - 4, 8, 8)
            # The examiner's colour, or a highlight's, over the lane's.
            fill = QColor(self.colour_of(row) or colour)
            painter.setPen(QPen(fill.darker(130), 1))
            painter.setBrush(fill)
            painter.drawEllipse(rect)
            mark = self.mark_of(row)
            if mark and mark[0]:
                painter.setPen(QPen(QColor('#E3A008'), 2))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(rect.adjusted(-3, -3, 3, 3))
            self._markers.append((rect.adjusted(-3, -3, 3, 3), row))
            label = _short(row)
            room = plot.right() - x - 10
            width = metrics.horizontalAdvance(label)
            if free is not None and width < room and                     slot_height >= metrics.height() - 2:
                labels.append((x + 7, y, label, width))
                ends[slot] = x + 9 + width
            else:
                ends[slot] = max(ends[slot], x + 6)
        # Labels after every marker, each on a patch of the background:
        # a later marker no longer prints over an earlier name.
        base = self.palette().color(self.palette().ColorRole.Base)
        for left, y, label, width in labels:
            painter.fillRect(QRectF(left - 1, y - metrics.height() / 2,
                                    width + 3, metrics.height()), base)
            painter.setPen(text)
            painter.drawText(QPointF(left, y + metrics.ascent() / 2 - 1),
                             label)

    def _paint_overlays(self, painter, plot, bottom, text, palette):
        accent = palette.color(palette.ColorRole.Highlight)
        if self.marker and self.start <= self.marker <= self.end:
            x = self._x(self.marker, plot)
            painter.setPen(QPen(accent, 1))
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, bottom))
        if self._drag_from is not None and self._drag_to is not None:
            band = QColor(accent)
            band.setAlpha(60)
            left, right = sorted((self._drag_from, self._drag_to))
            painter.fillRect(QRectF(left, plot.top(), right - left,
                                    bottom - plot.top()), band)
        elif self._hover is not None and plot.left() <= self._hover <= \
                plot.right():
            guide = QColor(text)
            guide.setAlpha(90)
            painter.setPen(guide)
            painter.drawLine(QPointF(self._hover, plot.top()),
                             QPointF(self._hover, bottom))

    # --- lanes -------------------------------------------------------------------

    #: Set by the view: row -> its lane's key.
    lane_key = staticmethod(lambda row: row.get('source'))
    #: Set by the panel: row -> (starred, colour, comment) or None, and
    #: row -> its tint (mark or highlight) or None.
    mark_of = staticmethod(lambda row: None)
    colour_of = staticmethod(lambda row: None)

    def _lane_at(self, y):
        for position, lane in enumerate(self.lanes):
            if self.lane_rect(position).top() <= y < \
                    self.lane_rect(position).bottom():
                return lane
        return None

    def _marker_at(self, point):
        for rect, row in reversed(self._markers):
            if rect.contains(point):
                return row
        return None

    # --- mouse ----------------------------------------------------------------------

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.start:
            self._drag_from = self._drag_to = event.position().x()
        elif event.button() == Qt.RightButton:
            row = self._marker_at(event.position())
            if row is not None:
                self.event_menu.emit(row, event.globalPosition().toPoint())

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
        plot = self.plot()
        row = self._marker_at(event.position())
        if row is not None:
            tip = (f"{row['time'][:19]}"
                   f"{' (local)' if row['local'] else ' UTC'}\n"
                   f"{timeline.describe_kind(row)}\n{_short(row, 200)}")
        else:
            moment = self._moment(x, plot)
            tip = moment.strftime('%Y-%m-%d %H:%M:%S')
            lane = self._lane_at(event.position().y())
            if lane is not None and self.events is None:
                bucket = int((x - plot.left()) / plot.width() * self.buckets)
                number = (self.counts.get(lane[0]) or {}).get(bucket, 0)
                tip += f"\n{lane[1]}: {number:,} event(s) here"
            tip += "\nDrag: zoom to a span · wheel: zoom"
        QToolTip.showText(event.globalPosition().toPoint(), tip, self)

    def leaveEvent(self, event):
        self._hover = None
        self.update()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._drag_from is None:
            return
        plot = self.plot()
        left, right = sorted((self._drag_from, event.position().x()))
        self._drag_from = self._drag_to = None
        self.update()
        if right - left >= 4:
            self.range_selected.emit(
                timeline.text(self._moment(left, plot)),
                timeline.text(self._moment(right, plot)))
            return
        row = self._marker_at(event.position())
        if row is not None:
            self.event_clicked.emit(row)
            return
        if plot.left() <= left <= plot.right():
            moment = self._moment(left, plot)
            span = (self.end - self.start) / max(1, self.buckets)
            self.time_clicked.emit(timeline.text(moment),
                                   timeline.text(moment + span))

    def wheelEvent(self, event):
        zoom_on_wheel(self, event, self.plot())


def _short(row, most=60):
    """A marker's label: what the event is about."""
    title = row.get('title') or ''
    if not title:
        subject = row.get('subject') or ''
        title = subject.replace('\\', '/').rsplit('/', 1)[-1] or subject
    title = title or timeline.describe_kind(row)
    return title if len(title) <= most else title[:most - 1] + '…'


class LanesView(QWidget):
    """The Lanes view: 'Lanes by' above the canvas; loads on a thread."""

    def __init__(self, names_of, kind_label, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineLanesView")
        self._names_of = names_of
        self._kind_label = kind_label
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Lanes by"))
        self.by_combo = QComboBox()
        for key, (label, _sql) in timeline.LANES_BY.items():
            self.by_combo.addItem(label, key)
        self.by_combo.currentIndexChanged.connect(lambda _i: self.reload())
        bar.addWidget(self.by_combo)
        self.status = QLabel()
        self.status.setObjectName("triageStatus")
        self.status.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bar.addWidget(self.status, 1)
        layout.addLayout(bar)
        self.canvas = LanesCanvas()
        layout.addWidget(self.canvas, 1)
        self._case = self._filters = None
        self._generation = 0
        self._jobs = KeptThreads(self)

    def load(self, case, filters):
        self._case, self._filters = case, dict(filters)
        self.reload()

    def reload(self):
        if self._case is None or not self._filters or \
                not self._filters.get('start'):
            return
        by = self.by_combo.currentData()
        buckets = max(10, int(max(200, self.canvas.plot().width())
                              // BUCKET_PIXELS))
        self._generation += 1
        job = _LaneLoad(self._case.folder, self._generation, self._filters,
                        by, buckets, self)
        job.loaded.connect(self._loaded)
        self._jobs[self._generation] = job
        self.status.setText("Loading…")
        job.start()

    @property
    def loading(self):
        return bool(self._jobs)

    def _loaded(self, generation, result):
        if generation != self._generation:
            return
        if result['error']:
            self.canvas.set_message(f"Could not read the lanes: "
                                    f"{result['error']}")
            self.status.setText('')
            return
        by = self.by_combo.currentData()
        counts = result['counts']
        events = result['events']
        order = sorted(counts, key=lambda k: -sum(counts[k].values()))
        if by == 'kind' and len(order) > MOST_LANES:
            # The busiest types each a lane; the rest share one.
            kept = set(order[:MOST_LANES - 1])
            other = {}
            for key in order[MOST_LANES - 1:]:
                for bucket, number in counts.pop(key).items():
                    other[bucket] = other.get(bucket, 0) + number
            counts[_OTHER] = other
            order = order[:MOST_LANES - 1] + [_OTHER]
        else:
            kept = None
        lanes = []
        for number, key in enumerate(order):
            if by == 'source':
                label = timeline.SOURCE_LABELS.get(key, key)
                colour = timeline.SOURCE_COLOURS.get(key, '#888888')
            else:
                label = self._label(by, key)
                colour = _PALETTE[number % len(_PALETTE)]
            lanes.append((key, label, colour))
        column = {'source': 'source', 'evidence': 'evidence_id',
                  'user': 'user', 'kind': 'kind'}[by]

        def lane_key(row):
            value = row.get(column)
            if column in ('user', 'kind'):
                value = value or ''
            if kept is not None and value not in kept:
                return _OTHER
            return value
        self.canvas.lane_key = lane_key
        self.canvas.set_data(lanes, counts, events, result['buckets'],
                             self._filters.get('start'),
                             self._filters.get('end'))
        total = sum(sum(c.values()) for c in counts.values())
        self.status.setText(
            f"{total:,} event(s) in {len(lanes)} lane(s)"
            + (" · each event drawn" if events is not None else
               f" · density; zoom in to {SPARSE_MOST:,} or fewer to see "
               f"each event"))

    def _label(self, by, key):
        if key == _OTHER:
            return "Other types"
        if by == 'evidence':
            return self._names_of().get(key, '(none)')
        if by == 'kind':
            return self._kind_label(key)
        return key or '(none)'

    def shutdown(self):
        for job in list(self._jobs.values()):
            try:
                job.wait(5000)
            except RuntimeError:
                pass


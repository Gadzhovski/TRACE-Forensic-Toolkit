"""Charts drawn by TRACE (no QtCharts): bars over time, ranked bars, a
measurement over time, and intervals in lanes.

Drawn with QPainter in the palette's colours, as the disk map and the
Timeline are, so they follow the theme and need nothing beyond PySide6.
Each chart says what is under the pointer, emits what a click chose, and
offers its picture (right-click ▸ Copy Picture / Save Picture…) -- saved
through evidence_export.save_bytes, so the case's audit trail records it.

Time axes take datetimes (UTC digits, or a zoneless local time as written:
the charts never convert) and share the Timeline's calendar ticks.
"""

import bisect
import datetime
import math

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QFileDialog, QMenu, QSizePolicy, QToolTip, \
    QWidget

from trace_app.core.timeline_axis import calendar_ticks

#: Stack and lane colours, as the Timeline's lanes.
PALETTE = ('#4C8BF5', '#E8743B', '#3FB950', '#9B6CF0', '#E3A008',
           '#17A2B8', '#E5534B', '#D45087', '#2F9E9E', '#B07AA1',
           '#7A9E3F', '#8A939E')
OTHER_COLOUR = '#8A939E'


def colour_at(index):
    return QColor(PALETTE[index % len(PALETTE)])


def nice_step(peak, most=5):
    """A round gridline step (1, 2, 2.5, 5 x 10^n) giving at most `most`
    lines up to `peak`."""
    if peak <= 0:
        return 1
    raw = peak / max(1, most)
    power = 10 ** math.floor(math.log10(raw))
    for factor in (1, 2, 2.5, 5, 10):
        if factor * power >= raw:
            return factor * power
    return 10 * power


def _number(value):
    from trace_app.core.record_views import number_text
    return number_text(value)


class Chart(QWidget):
    """What every chart shares: colours, the empty message, the picture
    menu."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.message = ''
        #: The picture's name when saved ('Browser — records over time').
        self.title = 'chart'
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._picture_menu)

    def set_message(self, text):
        self.message = text
        self.update()

    def colours(self):
        palette = self.palette()
        text = palette.color(palette.ColorRole.Text)
        base = palette.color(palette.ColorRole.Base)
        faint = QColor(text)
        faint.setAlpha(28)
        dim = QColor(text)
        dim.setAlpha(150)
        accent = palette.color(palette.ColorRole.Highlight)
        return text, base, faint, dim, accent

    def small_font(self, painter):
        font = painter.font()
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        return font

    def paint_message(self, painter, text):
        painter.setPen(self.colours()[3])
        painter.drawText(self.rect(), Qt.AlignCenter | Qt.TextWordWrap, text)

    # --- the picture -------------------------------------------------------

    def picture(self):
        """The chart as PNG bytes, at the screen's pixel ratio."""
        from PySide6.QtCore import QBuffer, QByteArray, QIODevice
        pixmap = self.grab()
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.WriteOnly)
        pixmap.save(buffer, 'PNG')
        buffer.close()
        return bytes(data)

    def _picture_menu(self, point):
        from trace_app.ui import icons
        from trace_app.ui.widgets.context_menus import show_menu
        menu = QMenu(self)
        copy = menu.addAction(icons.icon(icons.COPY), "Copy Picture")
        save = menu.addAction(icons.icon(icons.SAVE_PICTURE),
                              "Save Picture…")
        self.extend_menu(menu, point)
        chosen = show_menu(menu, self.mapToGlobal(point))
        if chosen == copy:
            QGuiApplication.clipboard().setPixmap(self.grab())
        elif chosen == save:
            self.save_picture()

    def extend_menu(self, menu, point):
        """Charts add their own entries (a bar's records...)."""

    def save_picture(self):
        from trace_app.core import evidence_export, record_views
        target, _kind = QFileDialog.getSaveFileName(
            self, "Save Picture", record_views.chart_file_name(self.title),
            "PNG picture (*.png)")
        if not target:
            return
        try:
            evidence_export.save_bytes(target, self.picture(), 'chart saved',
                                       f"chart '{self.title}'")
        except OSError as exc:
            from trace_app.ui.dialogs import message
            message.warning(self, "Save Picture",
                            f"The picture could not be saved: {exc}")


# --- time --------------------------------------------------------------------

def _seconds(moment, origin):
    return (moment - origin).total_seconds()


class _TimeAxis:
    """x <-> datetime over [start, end] within a plot rectangle."""

    def __init__(self, start, end, plot):
        self.start, self.end, self.plot = start, end, plot
        self.span = max((end - start).total_seconds(), 1e-6)

    def x(self, moment):
        return self.plot.left() + self.plot.width() * \
            _seconds(moment, self.start) / self.span

    def moment(self, x):
        fraction = (x - self.plot.left()) / max(1.0, self.plot.width())
        fraction = min(1.0, max(0.0, fraction))
        return self.start + datetime.timedelta(seconds=self.span * fraction)

    def paint_ticks(self, painter, chart, bottom, top=None):
        text, _base, faint, _dim, _accent = chart.colours()
        painter.save()
        painter.setFont(chart.small_font(painter))
        metrics = painter.fontMetrics()
        last_right = -1e9
        top = self.plot.top() if top is None else top
        for moment, label in calendar_ticks(
                self.start, self.end, max(2, int(self.plot.width() // 95))):
            x = self.x(moment)
            painter.setPen(faint)
            painter.drawLine(QPointF(x, top), QPointF(x, bottom))
            width = metrics.horizontalAdvance(label)
            left = min(max(self.plot.left(), x - width / 2),
                       self.plot.right() - width)
            if left > last_right + 8:
                painter.setPen(text)
                painter.drawText(QPointF(left, bottom + metrics.ascent() + 3),
                                 label)
                last_right = left + width
        painter.restore()


def _paint_value_grid(painter, chart, plot, peak, label=_number):
    """Horizontal gridlines with their values, left of the plot."""
    text, _base, faint, dim, _accent = chart.colours()
    painter.save()
    painter.setFont(chart.small_font(painter))
    metrics = painter.fontMetrics()
    step = nice_step(peak)
    value = 0.0
    while value <= peak * 1.0001:
        y = plot.bottom() - plot.height() * (value / peak if peak else 0)
        painter.setPen(faint)
        painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        painter.setPen(dim)
        words = label(value)
        painter.drawText(QRectF(0, y - metrics.height() / 2,
                                plot.left() - 6, metrics.height()),
                         Qt.AlignRight | Qt.AlignVCenter, words)
        value += step
    painter.restore()


def _legend(painter, chart, entries, left, top, right):
    """Coloured swatches with their labels in one row (wrapping); returns
    the height used."""
    if not entries:
        return 0
    text = chart.colours()[0]
    painter.save()
    painter.setFont(chart.small_font(painter))
    metrics = painter.fontMetrics()
    x, y = left, top
    line = metrics.height() + 4
    for label, colour in entries:
        label = metrics.elidedText(label, Qt.ElideRight, 220)
        width = 14 + metrics.horizontalAdvance(label) + 14
        if x + width > right and x > left:
            x, y = left, y + line
        painter.fillRect(QRectF(x, y + line / 2 - 5, 10, 10), colour)
        painter.setPen(text)
        painter.drawText(QPointF(x + 14, y + metrics.ascent() + 2), label)
        x += width
    painter.restore()
    return y - top + line


class TimeBars(Chart):
    """Counts per time bucket, stacked. `set_data(buckets, stacks)` with
    buckets [(start, end, {stack: n})] (datetimes) and stacks [(key,
    label, QColor)]. A click on a bar emits its index."""

    bucket_clicked = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordTimeBars")
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.buckets, self.stacks = [], []
        self.unit_label = ''
        self._bars = []             # (QRectF, index)
        self._hover = None

    def set_data(self, buckets, stacks, unit_label=''):
        self.buckets, self.stacks = list(buckets), list(stacks)
        self.unit_label = unit_label
        self.message = ''
        self._hover = None
        self.update()

    def sizeHint(self):
        return QSize(600, 240)

    def _geometry(self, painter):
        metrics = painter.fontMetrics()
        legend = _legend(painter, self,
                         [(label, colour) for _k, label, colour
                          in self.stacks] if len(self.stacks) > 1 else [],
                         64, 4, self.width() - 8) if painter else 0
        top = 8 + legend
        return QRectF(64, top, max(10, self.width() - 64 - 12),
                      max(20, self.height() - top - metrics.height() - 12))

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)
        text, base, faint, dim, accent = self.colours()
        painter.fillRect(self.rect(), base)
        self._bars = []
        if self.message or not self.buckets:
            self.paint_message(painter, self.message or "No records with a "
                                                        "time")
            return
        plot = self._geometry(painter)
        start = self.buckets[0][0]
        end = self.buckets[-1][1]
        axis = _TimeAxis(start, end, plot)
        peak = max(sum(counts.values()) for _s, _e, counts in self.buckets)
        peak = nice_step(peak) * math.ceil(peak / nice_step(peak)) or 1
        _paint_value_grid(painter, self, plot, peak)
        axis.paint_ticks(painter, self, plot.bottom(), plot.top())
        for index, (begin, finish, counts) in enumerate(self.buckets):
            left, right = axis.x(begin), axis.x(finish)
            width = max(1.0, right - left - (1 if right - left > 3 else 0))
            y = plot.bottom()
            for key, _label, colour in self.stacks:
                number = counts.get(key, 0)
                if not number:
                    continue
                height = plot.height() * number / peak
                fill = QColor(colour)
                if self._hover is not None and self._hover != index:
                    fill.setAlpha(150)
                painter.fillRect(QRectF(left, y - height, width, height), fill)
                y -= height
            self._bars.append((QRectF(left, plot.top(), max(width, 2),
                                      plot.height()), index))
        if self._hover is not None:
            rect = next((r for r, i in self._bars if i == self._hover), None)
            if rect is not None:
                band = QColor(accent)
                band.setAlpha(40)
                painter.fillRect(rect, band)

    def _bar_at(self, point):
        for rect, index in self._bars:
            if rect.left() - 1 <= point.x() <= rect.right() + 1 and \
                    rect.top() <= point.y() <= rect.bottom():
                return index
        return None

    def mouseMoveEvent(self, event):
        index = self._bar_at(event.position())
        if index != self._hover:
            self._hover = index
            self.update()
        if index is None:
            QToolTip.hideText()
            return
        begin, finish, counts = self.buckets[index]
        total = sum(counts.values())
        lines = [f"{self.label_of(begin, finish)}: {total:,} record(s)"]
        for key, label, _colour in self.stacks:
            if counts.get(key):
                lines.append(f"  {label}: {counts[key]:,}")
        lines.append("Click: these records in the table")
        QToolTip.showText(event.globalPosition().toPoint(), '\n'.join(lines),
                          self)

    def leaveEvent(self, _event):
        self._hover = None
        self.update()

    def label_of(self, begin, finish):
        span = (finish - begin).total_seconds()
        if span >= 360 * 86400:
            return begin.strftime('%Y')
        if span >= 27 * 86400:
            return begin.strftime('%Y-%m')
        if span >= 86400:
            return begin.strftime('%Y-%m-%d')
        if span >= 3600:
            return begin.strftime('%Y-%m-%d %H:00')
        return begin.strftime('%Y-%m-%d %H:%M:%S')

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            index = self._bar_at(event.position())
            if index is not None:
                self.bucket_clicked.emit(index)


class RankBars(Chart):
    """Values with their counts as horizontal bars, busiest first.
    `set_data(entries, others)` with entries [(key, label, count)]. A click
    emits the key."""

    value_clicked = Signal(str)
    ROW = 22

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordRankBars")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.entries, self.others = [], 0
        self.colour = colour_at(0)
        self._hover = None
        self.setFixedHeight(self.ROW * 3)

    def sizeHint(self):
        return QSize(320, self.height())

    def set_data(self, entries, others=0, colour=None):
        self.entries, self.others = list(entries), others
        if colour is not None:
            self.colour = QColor(colour)
        self._hover = None
        rows = len(self.entries) + (1 if others else 0)
        self.setFixedHeight(max(self.ROW * 2, self.ROW * rows + 6))
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        text, base, faint, dim, accent = self.colours()
        painter.fillRect(self.rect(), base)
        if not self.entries:
            self.paint_message(painter, self.message or "Nothing to count")
            return
        metrics = painter.fontMetrics()
        peak = max(count for _k, _l, count in self.entries) or 1
        label_width = min(260, max(90, int(self.width() * 0.38)))
        number_width = metrics.horizontalAdvance('0,000,000') + 8
        bar_left = label_width + 8
        bar_width = max(10, self.width() - bar_left - number_width - 4)
        rows = list(self.entries)
        if self.others:
            rows.append((None, "Other values", self.others))
        for position, (key, label, count) in enumerate(rows):
            top = 3 + position * self.ROW
            if position == self._hover and key is not None:
                band = QColor(accent)
                band.setAlpha(35)
                painter.fillRect(QRectF(0, top, self.width(), self.ROW), band)
            painter.setPen(dim if key is None else text)
            painter.drawText(QRectF(4, top, label_width - 4, self.ROW),
                             Qt.AlignVCenter | Qt.AlignLeft,
                             metrics.elidedText(str(label), Qt.ElideMiddle,
                                                label_width - 6))
            share = min(1.0, count / peak)
            bar = QRectF(bar_left, top + 5, max(2.0, bar_width * share),
                         self.ROW - 10)
            fill = QColor(OTHER_COLOUR if key is None else self.colour)
            if key is None:
                fill.setAlpha(110)
            painter.fillRect(bar, fill)
            painter.setPen(dim)
            painter.drawText(QRectF(bar.right() + 6, top, number_width,
                                    self.ROW),
                             Qt.AlignVCenter | Qt.AlignLeft, f"{count:,}")

    def _row_at(self, point):
        position = int((point.y() - 3) // self.ROW)
        if 0 <= position < len(self.entries):
            return position
        return None

    def mouseMoveEvent(self, event):
        position = self._row_at(event.position())
        if position != self._hover:
            self._hover = position
            self.update()
        if position is None:
            QToolTip.hideText()
            return
        _key, label, count = self.entries[position]
        total = sum(c for _k, _l, c in self.entries) + self.others
        share = 100.0 * count / total if total else 0
        QToolTip.showText(event.globalPosition().toPoint(),
                          f"{label}\n{count:,} record(s), {share:.1f}%\n"
                          f"Click: these records in the table", self)

    def leaveEvent(self, _event):
        self._hover = None
        self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            position = self._row_at(event.position())
            if position is not None:
                self.value_clicked.emit(self.entries[position][0])


class _Zoomable(Chart):
    """A time chart the examiner zooms by dragging across it; a
    double-click (or Show Whole Range) shows everything again."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CrossCursor)
        self.full = None            # (start, end) of the data
        self.view = None            # (start, end) shown
        self._drag_from = self._drag_to = None

    def plot(self):
        return QRectF(70, 10, max(10, self.width() - 82),
                      max(20, self.height() - 34))

    def axis(self):
        start, end = self.view or self.full
        return _TimeAxis(start, end, self.plot())

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.full:
            self._drag_from = self._drag_to = event.position().x()

    def mouseMoveEvent(self, event):
        if self._drag_from is not None:
            self._drag_to = event.position().x()
            self.update()
            return
        self.hover(event)

    def mouseReleaseEvent(self, event):
        if self._drag_from is None:
            return
        left, right = sorted((self._drag_from, event.position().x()))
        self._drag_from = self._drag_to = None
        if right - left >= 6:
            axis = self.axis()
            self.view = (axis.moment(left), axis.moment(right))
            self.update()
        else:
            self.clicked(event)
            self.update()

    def mouseDoubleClickEvent(self, _event):
        self.view = None
        self.update()

    def hover(self, event):
        """The tooltip for the point under the pointer."""

    def clicked(self, event):
        """A click that was not a drag."""

    def paint_drag(self, painter):
        if self._drag_from is None or self._drag_to is None:
            return
        accent = self.colours()[4]
        band = QColor(accent)
        band.setAlpha(60)
        left, right = sorted((self._drag_from, self._drag_to))
        plot = self.plot()
        painter.fillRect(QRectF(left, plot.top(), right - left,
                                plot.height()), band)

    def extend_menu(self, menu, _point):
        if self.view is not None:
            menu.addSeparator()
            whole = menu.addAction("Show Whole Range")
            whole.triggered.connect(self.mouseDoubleClickEvent)


class SeriesChart(_Zoomable):
    """A measurement over time: `set_data(points, label)` with points
    [(start datetime, end datetime, count, mean, low, high)] -- each a
    bucket's average and its range, drawn as a line over a band."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordSeries")
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.points = []
        self.label = ''
        self._starts = []

    def set_data(self, points, label=''):
        self.points = list(points)
        self._starts = [p[0] for p in self.points]
        self.label = label
        self.message = ''
        self.full = (self.points[0][0], self.points[-1][1]) \
            if self.points else None
        self.view = None
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        text, base, faint, dim, accent = self.colours()
        painter.fillRect(self.rect(), base)
        if self.message or not self.points:
            self.paint_message(painter, self.message or "No values")
            return
        axis = self.axis()
        plot = axis.plot
        shown = [p for p in self.points
                 if p[1] >= axis.start and p[0] <= axis.end] or self.points
        low = min(p[4] for p in shown)
        high = max(p[5] for p in shown)
        floor = 0.0 if low >= 0 and low <= high * 0.5 else low
        span = (high - floor) or 1.0
        step = nice_step(span)
        floor = math.floor(floor / step) * step
        top = math.ceil(high / step) * step
        if top <= floor:
            top = floor + step
        scale = top - floor

        def y(value):
            return plot.bottom() - plot.height() * (value - floor) / scale

        # Value grid.
        painter.save()
        painter.setFont(self.small_font(painter))
        metrics = painter.fontMetrics()
        value = floor
        while value <= top + step * 1e-6:
            painter.setPen(faint)
            painter.drawLine(QPointF(plot.left(), y(value)),
                             QPointF(plot.right(), y(value)))
            painter.setPen(dim)
            painter.drawText(QRectF(0, y(value) - metrics.height() / 2,
                                    plot.left() - 6, metrics.height()),
                             Qt.AlignRight | Qt.AlignVCenter, _number(value))
            value += step
        painter.restore()
        axis.paint_ticks(painter, self, plot.bottom())
        painter.save()
        painter.setClipRect(plot.adjusted(-1, -2, 1, 2))
        painter.setRenderHint(QPainter.Antialiasing, True)
        colour = colour_at(0)
        band = QColor(colour)
        band.setAlpha(55)
        # Gaps longer than three buckets break the line: no data is not a
        # straight line between two readings.
        runs, run = [], []
        for point in shown:
            if run and (point[0] - run[-1][1]).total_seconds() > \
                    3 * max(1.0, (run[-1][1] - run[-1][0]).total_seconds()):
                runs.append(run)
                run = []
            run.append(point)
        if run:
            runs.append(run)
        for run in runs:
            middle = [axis.x(p[0] + (p[1] - p[0]) / 2) for p in run]
            if any(p[4] != p[5] for p in run):
                path = QPainterPath()
                path.moveTo(middle[0], y(run[0][5]))
                for x, p in zip(middle, run):
                    path.lineTo(x, y(p[5]))
                for x, p in zip(reversed(middle), reversed(run)):
                    path.lineTo(x, y(p[4]))
                path.closeSubpath()
                painter.fillPath(path, band)
            line = QPainterPath()
            line.moveTo(middle[0], y(run[0][3]))
            for x, p in zip(middle[1:], run[1:]):
                line.lineTo(x, y(p[3]))
            painter.setPen(QPen(colour, 1.8))
            painter.setBrush(Qt.NoBrush)
            if len(run) == 1:
                painter.setBrush(colour)
                painter.drawEllipse(QPointF(middle[0], y(run[0][3])), 2.5,
                                    2.5)
            else:
                painter.drawPath(line)
        painter.restore()
        self.paint_drag(painter)

    def hover(self, event):
        if not self.points:
            return
        moment = self.axis().moment(event.position().x())
        index = max(0, bisect.bisect_right(self._starts, moment) - 1)
        begin, finish, count, mean, low, high = self.points[index]
        if not (begin <= moment <= finish + (finish - begin)):
            QToolTip.hideText()
            return
        span = f"{begin:%Y-%m-%d %H:%M:%S} – {finish:%Y-%m-%d %H:%M:%S}"
        lines = [span, f"{self.label}: {_number(mean)}"
                       + (" (average)" if count > 1 else '')]
        if count > 1:
            lines.append(f"lowest {_number(low)}, highest {_number(high)}, "
                         f"{count:,} reading(s)")
        lines.append("Drag across the chart to zoom; double-click for all")
        QToolTip.showText(event.globalPosition().toPoint(), '\n'.join(lines),
                          self)


class IntervalChart(_Zoomable):
    """Spans of time in lanes: `set_data(intervals, lanes)` with intervals
    [(start, end, lane key, payload)] (datetimes; a moment has end ==
    start) and lanes [(key, label, QColor)]. A click on a span emits its
    payload."""

    interval_clicked = Signal(object)
    LANE = 26
    LABEL = 150

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordIntervals")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.intervals, self.lanes = [], []
        self._lane_of = {}
        self._drawn = []

    def set_data(self, intervals, lanes):
        self.intervals = sorted(intervals, key=lambda i: i[0])
        self.lanes = list(lanes)
        self._lane_of = {key: n for n, (key, _l, _c) in enumerate(self.lanes)}
        self.message = ''
        if self.intervals:
            start = self.intervals[0][0]
            end = max(i[1] for i in self.intervals)
            if end <= start:
                end = start + datetime.timedelta(minutes=1)
            self.full = (start, end)
        else:
            self.full = None
        self.view = None
        self.setMinimumHeight(max(160, 40 + self.LANE * len(self.lanes)))
        self.update()

    def plot(self):
        height = max(self.LANE * max(1, len(self.lanes)),
                     self.height() - 34)
        return QRectF(self.LABEL, 8, max(10, self.width() - self.LABEL - 12),
                      height)

    def paintEvent(self, _event):
        painter = QPainter(self)
        text, base, faint, dim, accent = self.colours()
        painter.fillRect(self.rect(), base)
        self._drawn = []
        if self.message or not self.intervals:
            self.paint_message(painter, self.message or "No spans of time")
            return
        axis = self.axis()
        plot = axis.plot
        lane_height = min(self.LANE * 2,
                          plot.height() / max(1, len(self.lanes)))
        bottom = plot.top() + lane_height * len(self.lanes)
        axis.paint_ticks(painter, self, bottom)
        metrics = painter.fontMetrics()
        for position, (key, label, colour) in enumerate(self.lanes):
            top = plot.top() + position * lane_height
            if position % 2:
                stripe = QColor(text)
                stripe.setAlpha(8)
                painter.fillRect(QRectF(0, top, self.width(), lane_height),
                                 stripe)
            painter.fillRect(QRectF(8, top + lane_height / 2 - 4, 8, 8),
                             colour)
            painter.setPen(text)
            painter.drawText(QRectF(22, top, self.LABEL - 26, lane_height),
                             Qt.AlignVCenter | Qt.AlignLeft,
                             metrics.elidedText(label, Qt.ElideRight,
                                                self.LABEL - 28))
        painter.save()
        painter.setClipRect(QRectF(plot.left(), plot.top(), plot.width(),
                                   bottom - plot.top()))
        # Spans narrower than a pixel merge: tens of thousands of screen
        # unlocks must not be tens of thousands of rectangles each paint.
        last = {}
        for begin, finish, key, payload in self.intervals:
            if finish < axis.start or begin > axis.end:
                continue
            position = self._lane_of.get(key)
            if position is None:
                continue
            left = axis.x(begin)
            right = max(left + 2, axis.x(finish))
            previous = last.get(position)
            if previous is not None and left <= previous[1] + 0.5:
                previous[1] = max(previous[1], right)
                previous[2] += 1
                continue
            if previous is not None:
                self._draw_span(painter, previous, plot, lane_height)
            last[position] = [left, right, 1, position, payload, begin, finish]
        for previous in last.values():
            self._draw_span(painter, previous, plot, lane_height)
        painter.restore()
        self.paint_drag(painter)

    def _draw_span(self, painter, span, plot, lane_height):
        left, right, merged, position, payload, begin, finish = span
        colour = self.lanes[position][2]
        top = plot.top() + position * lane_height + 4
        rect = QRectF(left, top, right - left, lane_height - 8)
        painter.fillRect(rect, colour)
        self._drawn.append((rect, merged, payload, begin, finish, position))

    def _span_at(self, point):
        for rect, merged, payload, begin, finish, position in self._drawn:
            if rect.adjusted(-2, 0, 2, 0).contains(point):
                return merged, payload, begin, finish, position
        return None

    def hover(self, event):
        found = self._span_at(event.position())
        if found is None:
            QToolTip.hideText()
            return
        merged, _payload, begin, finish, position = found
        label = self.lanes[position][1]
        if merged > 1:
            words = (f"{label}: {merged:,} spans here, too close to tell "
                     f"apart -- drag across them to zoom in")
        else:
            from trace_app.core.record_views import duration_text
            length = (finish - begin).total_seconds()
            words = (f"{label}\n{begin:%Y-%m-%d %H:%M:%S}"
                     + (f" – {finish:%Y-%m-%d %H:%M:%S} "
                        f"({duration_text(length)})" if length > 0 else '')
                     + "\nClick: the row")
        QToolTip.showText(event.globalPosition().toPoint(), words, self)

    def clicked(self, event):
        found = self._span_at(event.position())
        if found is not None and found[0] == 1:
            self.interval_clicked.emit(found[1])

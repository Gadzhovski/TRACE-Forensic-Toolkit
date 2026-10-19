"""The Timeline's Insights: when the events happen, when nothing did, and
what in them cannot be right.

* a weekday × hour heatmap of the events in view (in the case's display
  zone, or UTC) -- when this user is active, and what falls outside it;
  a click narrows the timeline to that hour of that weekday;
* the longest gaps -- stretches with no event at all inside the range:
  the machine off, its clock wrong, or records wiped;
* the checks of core/timeline_anomalies -- events after the image was
  taken, zero dates, a clock set back, logs cleared... -- each a click
  away from its events.

Read on a thread with its own connection, as the rest of the tab.
"""

import logging
import os
import sqlite3

from PySide6.QtCore import QRectF, Qt, QThread, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (QLabel, QSizePolicy, QTextBrowser,
                               QToolTip, QVBoxLayout, QWidget)

from trace_app.core import timeline
from trace_app.core.case import CASE_DB_NAME
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.infra.sqlite_uri import connect_read_only

logger = logging.getLogger('TRACE.Timeline')

#: Gaps listed, longest first.
GAPS_LISTED = 10
_GRADE_COLOURS = {'suspicious': '#E5534B', 'notable': '#D9822B',
                  'info': '#8A8F98'}


class _InsightsLoad(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, filters, evidence, zone,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.filters, self.evidence, self.zone = filters, evidence, zone

    def run(self):
        result = {'grid': None, 'cells': {}, 'gaps': [], 'findings': [],
                  'error': ''}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = connect_read_only(path)
            try:
                hours = timeline.hour_counts(connection, self.filters)
                result['grid'], result['cells'] = timeline.weekday_hours(
                    hours, self.zone)
                if self.filters.get('start'):
                    result['gaps'] = timeline.gaps(
                        hours, self.filters['start'], self.filters['end'])
                from trace_app.core import timeline_anomalies
                result['findings'] = timeline_anomalies.analyse(
                    connection, self.filters, self.evidence)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read the timeline's insights: %s", exc)
            result['error'] = str(exc)
        self.loaded.emit(self.generation, result)


class Heatmap(QWidget):
    """Events per weekday and hour; a click on a cell emits it."""

    cell_clicked = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineHeatmap")
        self.setMouseTracking(True)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.grid = None
        self.chosen = None
        self.colour = QColor('#4C8BF5')

    def set_grid(self, grid):
        self.grid = grid
        self.update()

    def _geometry(self):
        left, top = 34, 16
        width = max(24, self.width() - left - 4)
        height = max(7, self.height() - top - 4)
        return left, top, width / 24, height / 7

    def _cell_at(self, point):
        left, top, cw, ch = self._geometry()
        hour = int((point.x() - left) // cw)
        day = int((point.y() - top) // ch)
        if 0 <= hour < 24 and 0 <= day < 7:
            return day, hour
        return None

    def paintEvent(self, _event):
        painter = QPainter(self)
        palette = self.palette()
        text = palette.color(palette.ColorRole.Text)
        base = palette.color(palette.ColorRole.Base)
        painter.fillRect(self.rect(), base)
        if not self.grid:
            painter.setPen(text)
            painter.drawText(self.rect(), Qt.AlignCenter, "No events")
            return
        left, top, cw, ch = self._geometry()
        peak = max(max(row) for row in self.grid) or 1
        font = painter.font()
        font.setPointSizeF(max(7.0, font.pointSizeF() - 1.5))
        painter.setFont(font)
        painter.setPen(text)
        for hour in range(0, 24, 3):
            painter.drawText(QRectF(left + hour * cw, 0, cw * 3, top - 2),
                             Qt.AlignLeft | Qt.AlignBottom, f"{hour:02d}")
        for day, name in enumerate(timeline.WEEKDAYS):
            painter.setPen(text)
            painter.drawText(QRectF(0, top + day * ch, left - 4, ch),
                             Qt.AlignRight | Qt.AlignVCenter, name)
            for hour in range(24):
                number = self.grid[day][hour]
                cell = QRectF(left + hour * cw + 1, top + day * ch + 1,
                              cw - 2, ch - 2)
                if number:
                    shade = QColor(self.colour)
                    # Square root: a busy hour must not wash out the rest.
                    shade.setAlpha(40 + int(215 * (number / peak) ** 0.5))
                    painter.fillRect(cell, shade)
                else:
                    empty = QColor(text)
                    empty.setAlpha(14)
                    painter.fillRect(cell, empty)
                if self.chosen == (day, hour):
                    accent = palette.color(palette.ColorRole.Highlight)
                    painter.setPen(accent)
                    painter.drawRect(cell.adjusted(-1, -1, 0, 0))

    def mouseMoveEvent(self, event):
        cell = self._cell_at(event.position())
        if cell is None or not self.grid:
            QToolTip.hideText()
            return
        day, hour = cell
        QToolTip.showText(event.globalPosition().toPoint(),
                          f"{timeline.WEEKDAYS[day]} {hour:02d}:00–"
                          f"{(hour + 1) % 24:02d}:00: "
                          f"{self.grid[day][hour]:,} event(s)\n"
                          f"Click: only these hours", self)

    def mouseReleaseEvent(self, event):
        cell = self._cell_at(event.position())
        if cell is not None and self.grid:
            self.cell_clicked.emit(*cell)


class InsightsView(QWidget):
    """The heatmap above, gaps and checks below. `cell_clicked`,
    `gap_clicked` (from, to) and `finding_clicked` (finding) for the panel
    to act on."""

    cell_clicked = Signal(int, int)
    gap_clicked = Signal(str, str)
    finding_clicked = Signal(object)
    #: A load finished: the gaps are known (the histogram hatches them).
    ready = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineInsights")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        self.heading = QLabel()
        self.heading.setObjectName("timelineInsightsHeading")
        self.heading.setWordWrap(True)
        layout.addWidget(self.heading)
        self.heatmap = Heatmap()
        self.heatmap.cell_clicked.connect(self.cell_clicked)
        layout.addWidget(self.heatmap)
        self.text = QTextBrowser()
        self.text.setObjectName("timelineDetail")
        self.text.setOpenLinks(False)
        self.text.anchorClicked.connect(self._link)
        layout.addWidget(self.text, 1)
        self.cells = {}
        self.gaps = []
        self.findings = []
        self.zone = None
        self._generation = 0
        self._jobs = KeptThreads(self)

    @property
    def loading(self):
        return bool(self._jobs)

    def load(self, case, filters, zone):
        if case is None:
            return
        self.zone = zone
        evidence = [dict(row) for row in case.evidence()]
        self._generation += 1
        job = _InsightsLoad(case.folder, self._generation, dict(filters),
                            evidence, zone, self)
        job.loaded.connect(self._loaded)
        self._jobs[self._generation] = job
        self.heading.setText("Reading…")
        job.start()

    def _loaded(self, generation, result):
        if generation != self._generation:
            return
        if result['error']:
            self.heading.setText(f"Could not read: {result['error']}")
            return
        self.cells = result['cells']
        self.gaps = result['gaps']
        self.findings = result['findings']
        self.heatmap.set_grid(result['grid'])
        total = sum(sum(row) for row in result['grid'] or [])
        self.heading.setText(
            f"<b>When</b> — {total:,} event(s) in view, by weekday and hour "
            f"({self.zone or 'UTC'}; times with no zone as written)")
        self.text.setHtml(self._html())
        self.ready.emit()

    def _html(self):
        from trace_app.ui.widgets import detail_html as d
        parts = [d.STYLE]
        parts.append(d.section(f"Checks ({len(self.findings)})"))
        if not self.findings:
            parts.append("<p class='note'>Nothing found: no event after "
                         "the image was taken, no zero or future dates, "
                         "no clock change or cleared log recorded, the "
                         "change journal in order.</p>")
        for number, finding in enumerate(self.findings):
            colour = _GRADE_COLOURS.get(finding['grade'], '#8A8F98')
            parts.append(
                f"<p><span style='color:{colour}'>●</span> "
                f"<a href='finding:{number}'>{d.e(finding['title'])}</a>"
                f"<br/><span class='note'>{d.e(finding['detail'])}</span>"
                f"</p>")
        longest = self.longest_gaps()
        parts.append(d.section(f"Gaps ({len(self.gaps):,})"))
        if not self.gaps:
            parts.append("<p class='note'>No stretch without events long "
                         "enough to note in this range.</p>")
        else:
            parts.append("<p class='note'>Stretches with no event at all "
                         "inside the range: the machine off, its clock "
                         "wrong, or records wiped. The longest:</p>")
            rows = []
            for start, end in longest:
                length = timeline.parse(end) - timeline.parse(start)
                rows.append(
                    f"<tr><td class='mono'><a href='gap:{start}|{end}'>"
                    f"{d.e(start[:16])} → {d.e(end[:16])}</a></td>"
                    f"<td>{_length(length)}</td></tr>")
            parts.append("<table cellspacing='0' cellpadding='0'>"
                         + ''.join(rows) + "</table>")
        return ''.join(parts)

    def longest_gaps(self):
        """The GAPS_LISTED longest gaps, longest first."""
        return sorted(self.gaps, key=lambda g: timeline.parse(g[0]) -
                      timeline.parse(g[1]))[:GAPS_LISTED]

    def _link(self, url):
        text = url.toString()
        if text.startswith('finding:'):
            index = int(text.split(':', 1)[1])
            if 0 <= index < len(self.findings):
                self.finding_clicked.emit(self.findings[index])
        elif text.startswith('gap:'):
            start, end = text[4:].split('|', 1)
            self.gap_clicked.emit(start, end)

    def shutdown(self):
        for job in list(self._jobs.values()):
            try:
                job.wait(5000)
            except RuntimeError:
                pass


def _length(delta):
    days = delta.days
    hours = delta.seconds // 3600
    if days >= 2:
        return f"{days} days"
    if days == 1:
        return f"1 day {hours} h"
    return f"{hours} h {delta.seconds % 3600 // 60} min"

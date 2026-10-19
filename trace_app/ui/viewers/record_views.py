"""Activity records shown another way: Charts and Items beside the Table.

* `RecordOverview` (Charts): records over time, stacked by what the
  category is about; weekday x hour; the top values of the fields that
  matter (core/record_views.BREAKDOWNS). Every bar, cell and value is a
  way in: a click narrows the table to those records.
* `ItemsView` (Items): a card per device, network, program, site, person
  or account (core/record_views.ITEM_KEYS) -- first and last seen, how
  often, who read it, what every record of it agrees on, and a strip of
  its activity over the records' span. A click previews its newest
  record's source; a double-click lists its records.
* `ArtifactChart`: what an external module left in its own database
  (Activity ▸ Others), charted by SQL on a thread: a measurement over
  time, spans of time in lanes, or rows per time.

The Activity tab's rows are already in memory (at most SHOWN_LIMIT); the
overview and the items are worked out from them when the view is shown,
not before.
"""

import collections
import datetime
import logging

from PySide6.QtCore import (QAbstractListModel, QModelIndex, QRectF, QSize,
                            Qt, QThread, Signal)
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPainter, QPalette
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QGridLayout,
                               QHBoxLayout, QLabel, QListView, QMenu,
                               QScrollArea, QSizePolicy, QStackedWidget,
                               QStyle, QStyledItemDelegate, QVBoxLayout,
                               QWidget)

from trace_app.core import record_views
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.charts import (OTHER_COLOUR, IntervalChart,
                                         RankBars, SeriesChart, TimeBars,
                                         colour_at)
from trace_app.ui.widgets.kept_threads import KeptThreads

logger = logging.getLogger('TRACE.RecordViews')

_UNIT_WORDS = {'hour': "per hour", 'day': "per day", 'month': "per month",
               'year': "per year"}


def _heading(text):
    label = QLabel(text)
    label.setObjectName("recordChartTitle")
    return label


def _note(text=''):
    label = QLabel(text)
    label.setObjectName("triageStatus")
    label.setWordWrap(True)
    return label


def _zone():
    try:
        from trace_app.core.settings import current
        return current('display_zone') or None
    except Exception:
        return None


# --- Charts ---------------------------------------------------------------------

class RecordOverview(QScrollArea):
    """The Charts view of a category's records."""

    #: (row ids, what they are): the table, narrowed to them.
    narrow_requested = Signal(object, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordOverview")
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self.result = None
        self.category = None
        self.category_label = ''

        page = QWidget()
        page.setObjectName("recordOverviewPage")
        # The charts' own background between them, not the window's.
        page.setAutoFillBackground(True)
        page.setBackgroundRole(QPalette.Base)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(6)
        self.summary = _note()
        layout.addWidget(self.summary)

        self.time_title = _heading("Records over time")
        layout.addWidget(self.time_title)
        self.time_bars = TimeBars()
        self.time_bars.setMinimumHeight(230)
        self.time_bars.bucket_clicked.connect(self._bucket_clicked)
        layout.addWidget(self.time_bars)

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(4)
        from trace_app.ui.viewers.timeline_insights import Heatmap
        self.heatmap_title = _heading("When: weekday and hour")
        self.heatmap = Heatmap()
        self.heatmap.setMinimumHeight(170)
        self.heatmap.cell_clicked.connect(self._cell_clicked)
        self.heatmap_note = _note()
        grid.addWidget(self.heatmap_title, 0, 0)
        grid.addWidget(self.heatmap, 1, 0)
        grid.addWidget(self.heatmap_note, 2, 0)
        self.rank_titles, self.ranks = [], []
        for number in range(3):
            title = _heading('')
            bars = RankBars()
            bars.value_clicked.connect(
                lambda key, n=number: self._value_clicked(n, key))
            self.rank_titles.append(title)
            self.ranks.append(bars)
            row, column = divmod(number + 1, 2)
            grid.addWidget(title, row * 3, column)
            grid.addWidget(bars, row * 3 + 1, column)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addStretch(1)
        self.setWidget(page)

    def show_rows(self, rows, category, label):
        """Work out and draw the overview of `rows`."""
        self.show_result(record_views.overview(rows, category, _zone()),
                         category, label)

    def show_working(self, total):
        self.result = None
        self.summary.setText(f"Working out the charts of {total:,} "
                             f"record(s)…")
        for chart in [self.time_bars] + self.ranks:
            chart.set_message("Working…")
        self.heatmap.set_grid(None)

    def show_result(self, result, category, label):
        """Draw an overview worked out by core/record_views.overview."""
        self.category, self.category_label = category, label
        self.result = result
        name = label or "All"
        if not result['total']:
            self.summary.setText("No records to chart.")
        else:
            parts = [f"{result['total']:,} record(s)"]
            if result['first']:
                parts.append(f"from {result['first'][:10]} to "
                             f"{result['last'][:10]}")
            if result['untimed']:
                parts.append(f"{result['untimed']:,} with no usable time "
                             f"(not in the time charts)")
            if result['local']:
                parts.append(f"{result['local']:,} in a local time with no "
                             f"zone, counted as written")
            self.summary.setText(' · '.join(parts) + ". Click a bar, cell "
                                 "or value to list those records.")
        unit = result['unit']
        stacks = []
        for n, (key, label_) in enumerate(result['stacks']):
            if key == record_views.OTHER:
                colour = QColor(OTHER_COLOUR)
            elif key == record_views.NONE:
                colour = QColor(OTHER_COLOUR)
                colour.setAlpha(110)
            else:
                colour = colour_at(n)
            stacks.append((key, label_, colour))
        buckets = []
        for prefix, counts in result['buckets']:
            start = record_views.bucket_start(prefix, unit)
            buckets.append((start, record_views.bucket_end(start, unit),
                            counts))
        self.time_title.setText(
            f"Records {_UNIT_WORDS.get(unit, '')}"
            + (f", by {result['breakdowns'][0][0].lower()}"
               if len(stacks) > 1 else ''))
        self.time_bars.title = f"{name} — records over time"
        self.time_bars.set_data(buckets, stacks)
        self.heatmap.set_grid(result['grid'])
        zone = _zone()
        self.heatmap_note.setText(
            f"Hours in {zone}." if zone else
            "Hours in UTC (Settings ▸ display zone shows them in another).")
        for number, (title, bars) in enumerate(zip(self.rank_titles,
                                                   self.ranks)):
            if number < len(result['breakdowns']):
                heading, _field, entries, others = \
                    result['breakdowns'][number]
                title.setText(heading)
                bars.title = f"{name} — {heading.lower()}"
                bars.set_data(entries, others, colour_at(0) if number == 0
                              else colour_at(number + 1))
                title.show()
                bars.show()
            else:
                title.hide()
                bars.hide()

    def _bucket_clicked(self, index):
        if self.result is None or not 0 <= index < len(
                self.result['buckets']):
            return
        prefix = self.result['buckets'][index][0]
        self.narrow_requested.emit(
            self.result['ids'].get(('bucket', prefix), []), prefix)

    def _cell_clicked(self, day, hour):
        if self.result is None:
            return
        from trace_app.core import timeline
        self.heatmap.chosen = (day, hour)
        self.heatmap.update()
        self.narrow_requested.emit(
            self.result['hours'].get((day, hour), []),
            f"{timeline.WEEKDAYS[day]} {hour:02d}:00–{(hour + 1) % 24:02d}:00")

    def _value_clicked(self, number, key):
        if self.result is None:
            return
        heading, field, entries, _others = self.result['breakdowns'][number]
        label = next((l for k, l, _n in entries if k == key), key)
        self.narrow_requested.emit(self.result['ids'].get((field, key), []),
                                   f"{heading}: {label}")


# --- Items -------------------------------------------------------------------------

CARD_WIDTH, CARD_HEIGHT = 330, 158
_SORTS = (('count', "Most records"), ('last', "Most recent"),
          ('first', "Earliest"), ('title', "Name"))


class ItemsModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.items = []
        self.names = {}

    def set_items(self, items, names):
        self.beginResetModel()
        self.items, self.names = items, names
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.items)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        item = self.items[index.row()]
        if role == Qt.DisplayRole:
            return item['title']
        if role == Qt.ToolTipRole:
            return self.tooltip(item)
        if role == Qt.UserRole:
            # The newest record: what the window's row hooks (tag,
            # bookmark, export) act on.
            return item['latest']
        return None

    def tooltip(self, item):
        lines = [item['title']]
        if item['subtitle']:
            lines.append(item['subtitle'])
        lines.append(f"{item['count']:,} record(s)")
        if item['first']:
            lines.append(f"First: {item['first']}"
                         + (" (local)" if item['local'] else ''))
            lines.append(f"Last: {item['last']}")
        for what, number in item['whats'][:8]:
            lines.append(f"  {what}: {number:,}")
        if item['users']:
            lines.append("Users: " + ', '.join(item['users'][:6]))
        lines.append("Read by " + ', '.join(item['readers']))
        evidence = [self.names.get(e, '') for e in item['evidence']]
        if any(evidence):
            lines.append("Evidence: " + ', '.join(filter(None, evidence)))
        for key, value in item['facts']:
            lines.append(f"{key}: {value}")
        lines.append("Double-click: its records in the table")
        return '\n'.join(lines)


class CardDelegate(QStyledItemDelegate):
    """Paints an item as a card in the palette's colours."""

    def __init__(self, view, parent=None):
        super().__init__(parent)
        self.view = view
        self.icon = None

    def sizeHint(self, _option, _index):
        return QSize(CARD_WIDTH, CARD_HEIGHT)

    def paint(self, painter, option, index):
        item = index.model().items[index.row()]
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        palette = option.palette
        text = palette.color(palette.ColorRole.Text)
        base = palette.color(palette.ColorRole.Base)
        accent = palette.color(palette.ColorRole.Highlight)
        dim = QColor(text)
        dim.setAlpha(160)
        card = QRectF(option.rect).adjusted(5, 5, -5, -5)
        fill = QColor(text)
        fill.setAlpha(10)
        border = QColor(text)
        border.setAlpha(45)
        if option.state & QStyle.State_Selected:
            fill = QColor(accent)
            fill.setAlpha(40)
            border = QColor(accent)
        elif option.state & QStyle.State_MouseOver:
            fill.setAlpha(22)
        painter.setPen(border)
        painter.setBrush(base)
        painter.drawRoundedRect(card, 6, 6)
        painter.setBrush(fill)
        painter.drawRoundedRect(card, 6, 6)
        inner = card.adjusted(12, 10, -12, -10)
        if self.icon is not None:
            self.icon.paint(painter, int(inner.left()), int(inner.top()) + 1,
                            20, 20)
        font = QFont(option.font)
        font.setBold(True)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        line = metrics.height()
        count = f"{item['count']:,}"
        painter.setFont(option.font)
        count_width = painter.fontMetrics().horizontalAdvance(count) + 6
        painter.setFont(font)
        painter.setPen(text)
        title_rect = QRectF(inner.left() + 28, inner.top(),
                            inner.width() - 28 - count_width, line + 2)
        painter.drawText(title_rect, Qt.AlignLeft | Qt.AlignVCenter,
                         metrics.elidedText(item['title'], Qt.ElideMiddle,
                                            int(title_rect.width())))
        painter.setFont(option.font)
        metrics = painter.fontMetrics()
        painter.setPen(accent)
        painter.drawText(QRectF(inner.right() - count_width, inner.top(),
                                count_width, line + 2),
                         Qt.AlignRight | Qt.AlignVCenter, count)
        y = inner.top() + line + 4

        def write(words, colour=dim):
            nonlocal y
            if not words or y + line > inner.bottom() - 18:
                return
            painter.setPen(colour)
            painter.drawText(QRectF(inner.left(), y, inner.width(), line),
                             Qt.AlignLeft | Qt.AlignVCenter,
                             metrics.elidedText(words, Qt.ElideRight,
                                                int(inner.width())))
            y += line + 1

        write(item['subtitle'])
        if item['first']:
            first, last = item['first'][:16], item['last'][:16]
            write(f"{first}  →  {last}" if first != last else first,
                  text)
        whats = ', '.join(f"{w} ×{n:,}" if n > 1 else w
                          for w, n in item['whats'][:3])
        write(whats)
        for key, value in item['facts'][:2]:
            write(f"{key}: {value}")
        readers = [r for r in item['readers'] if r != 'TRACE']
        if readers:
            write("Read by " + ', '.join(item['readers']))
        # The strip: this item's records across every item's span.
        strip = item['strip']
        if strip:
            peak = max(strip) or 1
            width = inner.width() / len(strip)
            bottom = inner.bottom()
            colour = QColor(accent)
            painter.setPen(Qt.NoPen)
            for n, value in enumerate(strip):
                if not value:
                    continue
                height = max(2.0, 14 * (value / peak) ** 0.5)
                painter.fillRect(QRectF(inner.left() + n * width + 0.5,
                                        bottom - height,
                                        max(1.0, width - 1.5), height),
                                 colour)
            baseline = QColor(text)
            baseline.setAlpha(40)
            painter.fillRect(QRectF(inner.left(), bottom, inner.width(), 1),
                             baseline)
        painter.restore()


class ItemsView(QWidget):
    """The Items view of a category's records."""

    #: The newest record of the item clicked: preview its source.
    item_selected = Signal(dict)
    #: (row ids, what they are): the table, narrowed to them.
    narrow_requested = Signal(object, str)
    #: The newest record: go to its source file.
    item_activated = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("recordItems")
        self.category = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 0)
        layout.setSpacing(4)
        top = QHBoxLayout()
        self.status = _note()
        top.addWidget(self.status, 1)
        top.addWidget(QLabel("Sort:"))
        self.sort = QComboBox()
        self.sort.setObjectName("triageEvidenceFilter")
        for key, label in _SORTS:
            self.sort.addItem(label, key)
        self.sort.currentIndexChanged.connect(self._resort)
        top.addWidget(self.sort)
        layout.addLayout(top)
        self.model = ItemsModel(self)
        self.list = QListView()
        self.list.setObjectName("recordCards")
        self.list.setViewMode(QListView.IconMode)
        self.list.setFlow(QListView.LeftToRight)
        self.list.setWrapping(True)
        self.list.setResizeMode(QListView.Adjust)
        self.list.setMovement(QListView.Static)
        self.list.setUniformItemSizes(True)
        self.list.setSpacing(2)
        self.list.setMouseTracking(True)
        self.list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.delegate = CardDelegate(self.list, self)
        self.list.setItemDelegate(self.delegate)
        self.list.setModel(self.model)
        self.list.selectionModel().currentChanged.connect(
            lambda current, _old: self._selected(current))
        self.list.clicked.connect(self._selected)
        self.list.doubleClicked.connect(self._narrow)
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.list, 1)

    def show_rows(self, rows, category, label, names):
        self.show_items(record_views.inventory(rows, category),
                        record_views.unnamed(rows, category), len(rows),
                        category, names)

    def show_working(self, total, category):
        self.category = category
        self.model.set_items([], {})
        self.status.setText(f"Working out the items of {total:,} "
                            f"record(s)…")

    def show_items(self, items, missing, total, category, names):
        """Draw items worked out by core/record_views.inventory."""
        self.category = category
        self.delegate.icon = icons.icon(
            icons.ACTIVITY_CATEGORIES.get(category, icons.ACTIVITY))
        self.model.set_items(self._sorted(items), names)
        what = record_views.ITEM_NAMES.get(category, 'item')
        text = (f"{len(items):,} {what}(s) in {total:,} record(s)"
                if items else f"No {what}s named in these records.")
        if missing:
            text += f" · {missing:,} record(s) name no {what}"
        self.status.setText(text + ". Double-click a card for its records.")

    def _sorted(self, items):
        key = self.sort.currentData()
        if key == 'last':
            return sorted(items, key=lambda i: i['last'] or '', reverse=True)
        if key == 'first':
            return sorted(items, key=lambda i: i['first'] or '￿')
        if key == 'title':
            return sorted(items, key=lambda i: i['title'].lower())
        return sorted(items, key=lambda i: (-i['count'], i['title'].lower()))

    def _resort(self, _index):
        self.model.set_items(self._sorted(self.model.items), self.model.names)

    def _item(self, index):
        if index is None or not index.isValid():
            return None
        return self.model.items[index.row()]

    def _selected(self, index):
        item = self._item(index)
        if item is not None:
            self.item_selected.emit(item['latest'])

    def _narrow(self, index):
        item = self._item(index)
        if item is not None:
            what = record_views.ITEM_NAMES.get(self.category, 'item')
            self.narrow_requested.emit(item['ids'],
                                       f"{what.capitalize()}: "
                                       f"{item['title']}")

    def _menu(self, point):
        from trace_app.ui.widgets.context_menus import show_menu
        index = self.list.indexAt(point)
        item = self._item(index)
        if item is None:
            return
        menu = QMenu(self)
        records = menu.addAction(icons.icon(icons.VIEW_LIST),
                                 "Show Records in Table")
        source = menu.addAction("Show Newest Record's Source File")
        source.setEnabled(bool(item['latest'].get('source_ref')))
        copy = menu.addAction(icons.icon(icons.COPY), "Copy Summary")
        chosen = show_menu(menu, self.list.viewport().mapToGlobal(point),
                           view=False)
        if chosen == records:
            self._narrow(index)
        elif chosen == source:
            self.item_activated.emit(item['latest'])
        elif chosen == copy:
            QGuiApplication.clipboard().setText(self.model.tooltip(item)
                                                .rsplit('\n', 1)[0])


# --- an external module's own table -----------------------------------------------

class _ChartQuery(QThread):
    """One chart's SQL over a tool's database (SQLite releases the
    interpreter lock while it works, as Triage ▸ Indicators' queries)."""

    loaded = Signal(int, object)

    def __init__(self, generation, report, artifact, request, parent=None):
        super().__init__(parent)
        self.generation = generation
        self.report, self.artifact, self.request = report, artifact, request

    def run(self):
        from trace_app.core.modules import lava
        result = {'error': ''}
        try:
            connection = lava.connect(self.report)
            try:
                kind = self.request.get('kind')
                if kind == 'shape':
                    result['shape'] = record_views.artifact_shape(
                        connection, self.artifact)
                elif kind == 'series':
                    result['series'] = record_views.series_query(
                        connection, self.artifact, self.request['time'],
                        self.request['value'])
                elif kind == 'counts':
                    result['counts'] = record_views.counts_query(
                        connection, self.artifact, self.request['time'],
                        self.request.get('label'))
                elif kind == 'intervals':
                    result['intervals'] = record_views.intervals_query(
                        connection, self.artifact, self.request['time'],
                        self.request['end'], self.request.get('label'))
            finally:
                connection.close()
        except Exception as exc:
            logger.error("Could not chart %s: %s",
                         self.artifact.get('name'), exc)
            result['error'] = str(exc)
        self.loaded.emit(self.generation, result)


class RecordViewTask(ProcessWorker):
    """Charts or Items of many records, worked out in a child process
    (core/background.job_record_view); `done(result)` -- an Exception if
    it failed."""

    done = Signal(object)

    kind = 'record_view'

    def __init__(self, params, parent=None):
        super().__init__(params, parent)
        self._result = None

    def on_item(self, record):
        self._result = record

    def on_done(self, count, error):
        if self._stop.is_set():
            return
        self.done.emit(RuntimeError(error) if error else self._result)


#: How each chart of a tool's artifact is offered.
_KIND_WORDS = {'series': "Values over time", 'intervals': "Spans of time",
               'counts': "Rows over time"}


def _moment(seconds):
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(
        seconds=float(seconds))


class ArtifactChart(QWidget):
    """A LEAPP artifact charted from the tool's own database."""

    #: A span's row id (intervals): the row, as the table would give it.
    row_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("artifactChart")
        self.run = self.artifact = None
        self.shape = None
        self.kind = None
        self._generation = 0
        self._queries = KeptThreads(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)
        top = QHBoxLayout()
        self.status = _note()
        top.addWidget(self.status, 1)
        self.kind_label = QLabel("Show:")
        self.kind_combo = QComboBox()
        self.kind_combo.setObjectName("triageEvidenceFilter")
        self.kind_combo.currentIndexChanged.connect(self._kind_changed)
        top.addWidget(self.kind_label)
        top.addWidget(self.kind_combo)
        self.value_label = QLabel("Value:")
        self.value_combo = QComboBox()
        self.value_combo.setObjectName("triageEvidenceFilter")
        self.value_combo.currentIndexChanged.connect(self._redraw)
        self.label_label = QLabel("By:")
        self.label_combo = QComboBox()
        self.label_combo.setObjectName("triageEvidenceFilter")
        self.label_combo.currentIndexChanged.connect(self._redraw)
        for widget in (self.value_label, self.value_combo, self.label_label,
                       self.label_combo):
            top.addWidget(widget)
        layout.addLayout(top)
        self.stack = QStackedWidget()
        self.empty = _note()
        self.empty.setAlignment(Qt.AlignCenter)
        self.series = SeriesChart()
        self.intervals = IntervalChart()
        self.intervals.interval_clicked.connect(
            lambda rowid: self.row_requested.emit(int(rowid)))
        self.bars = TimeBars()
        for widget in (self.empty, self.series, self.intervals, self.bars):
            self.stack.addWidget(widget)
        layout.addWidget(self.stack, 1)
        self._controls(None)

    def _controls(self, kind):
        series = kind == 'series'
        labelled = kind in ('counts', 'intervals')
        choices = kind is not None and self.kind_combo.count() > 1
        self.kind_label.setVisible(choices)
        self.kind_combo.setVisible(choices)
        self.value_label.setVisible(series)
        self.value_combo.setVisible(series)
        self.label_label.setVisible(labelled and self.label_combo.count() > 1)
        self.label_combo.setVisible(labelled and self.label_combo.count() > 1)

    def show_artifact(self, run, artifact):
        """Chart `artifact` of `run` (the window's run dict)."""
        self.run, self.artifact, self.shape = run, artifact, None
        self._generation += 1
        if artifact is None:
            self._show_empty("Choose an artifact on the left.")
            return
        self._show_empty("Reading the tool's database…")
        self._query({'kind': 'shape'})

    def _show_empty(self, text):
        self.empty.setText(text)
        self.stack.setCurrentWidget(self.empty)
        self.status.setText('')
        self._controls(None)

    def _query(self, request):
        query = _ChartQuery(self._generation, self.run['report'],
                            self.artifact, request, self)
        query.loaded.connect(self._loaded)
        self._queries[(self._generation, request.get('kind'))] = query
        query.start()

    def _loaded(self, generation, result):
        if generation != self._generation:
            return
        if result.get('error'):
            self._show_empty(f"Could not read the tool's database: "
                             f"{result['error']}")
            return
        if 'shape' in result:
            self._shape_known(result['shape'])
        elif 'series' in result:
            self._draw_series(result['series'])
        elif 'counts' in result:
            self._draw_counts(result['counts'])
        elif 'intervals' in result:
            self._draw_intervals(*result['intervals'])

    def _shape_known(self, shape):
        self.shape = shape
        if shape.get('kind') is None:
            self._show_empty(f"Nothing to chart: {shape.get('why')} The "
                             f"table shows its rows.")
            return
        self.kind = shape['kind']
        self.kind_combo.blockSignals(True)
        self.kind_combo.clear()
        for kind in shape.get('kinds') or [self.kind]:
            self.kind_combo.addItem(_KIND_WORDS[kind], kind)
        self.kind_combo.setCurrentIndex(max(0, self.kind_combo.findData(
            self.kind)))
        self.kind_combo.blockSignals(False)
        for combo, columns, none in (
                (self.value_combo, shape.get('numbers') or [], None),
                (self.label_combo, shape.get('labels') or [], "Not split")):
            combo.blockSignals(True)
            combo.clear()
            if none:
                combo.addItem(none, None)
            for number, column in enumerate(columns):
                combo.addItem(column.get('label') or column['name'], number)
            if combo is self.label_combo and columns:
                combo.setCurrentIndex(1)
            combo.blockSignals(False)
        self._controls(self.kind)
        self._redraw()

    def _kind_changed(self, _index):
        kind = self.kind_combo.currentData()
        if kind and self.shape:
            self.kind = kind
            self._controls(kind)
            self._redraw()

    def _redraw(self, _index=None):
        shape = self.shape
        if not shape or not shape.get('kind'):
            return
        self._generation += 1
        label_index = self.label_combo.currentData()
        label = shape['labels'][label_index] \
            if label_index is not None and shape.get('labels') else None
        if self.kind == 'series':
            number = self.value_combo.currentData() or 0
            self._query({'kind': 'series', 'time': shape['time'],
                         'value': shape['numbers'][number]})
        elif self.kind == 'intervals':
            self._query({'kind': 'intervals', 'time': shape['time'],
                         'end': shape['end'], 'label': label})
        else:
            self._query({'kind': 'counts', 'time': shape['time'],
                         'label': label})
        self.status.setText("Reading…")

    def _title(self, what):
        return f"{self.artifact['name']} — {what}"

    def _draw_series(self, series):
        points = []
        step = series['step'] or 1
        for start, count, mean, low, high in series['points']:
            begin = _moment(start)
            points.append((begin, begin + datetime.timedelta(seconds=step),
                           count, mean, low, high))
        column = self.shape['numbers'][self.value_combo.currentData() or 0]
        label = column.get('label') or column['name']
        if not points:
            self._show_empty(f"No row has both a time and a value of "
                             f"'{label}'.")
            return
        self.series.title = self._title(label)
        self.series.set_data(points, label)
        self.stack.setCurrentWidget(self.series)
        each = (f", averaged per {_step_words(step)}" if any(
            p[2] > 1 for p in points) else '')
        self.status.setText(
            f"{label} over {self.shape['time'].get('label')}: "
            f"{series['rows']:,} reading(s) from "
            f"{record_views.epoch_text(series['first'])} to "
            f"{record_views.epoch_text(series['last'])} UTC{each}. "
            f"Drag to zoom.")

    def _draw_counts(self, counts):
        labels = counts['labels']
        stacks = [(key, "Other" if key == record_views.OTHER else
                   (key or "Rows"),
                   QColor(OTHER_COLOUR) if key == record_views.OTHER
                   else colour_at(n)) for n, key in enumerate(labels)]
        step = counts['step'] or 1
        buckets = [(_moment(start),
                    _moment(start) + datetime.timedelta(seconds=step),
                    values) for start, values in counts['buckets']]
        if not buckets:
            self._show_empty("No row has a usable time.")
            return
        self.bars.title = self._title("rows over time")
        self.bars.set_data(buckets, stacks)
        self.stack.setCurrentWidget(self.bars)
        self.status.setText(
            f"{counts['rows']:,} row(s) per {_step_words(step)} by "
            f"'{self.shape['time'].get('label')}', "
            f"{record_views.epoch_text(counts['first'])} to "
            f"{record_views.epoch_text(counts['last'])} UTC.")

    def _draw_intervals(self, intervals, total):
        if not intervals:
            self._show_empty("No row has a usable start time.")
            return
        counter = collections.Counter(label for _s, _e, label, _r
                                      in intervals)
        top = [label for label, _n in counter.most_common(12)]
        chosen = set(top)
        lanes = [(label, label or self.artifact['name'], colour_at(n))
                 for n, label in enumerate(top)]
        spans = []
        other = False
        for start, end, label, rowid in intervals:
            if label not in chosen:
                label, other = record_views.OTHER, True
            spans.append((_moment(start), _moment(end), label, rowid))
        if other:
            lanes.append((record_views.OTHER, "Other",
                          QColor(OTHER_COLOUR)))
        self.intervals.title = self._title("spans of time")
        self.intervals.set_data(spans, lanes)
        self.stack.setCurrentWidget(self.intervals)
        shown = (f"the first {len(intervals):,} of {total:,}"
                 if total > len(intervals) else f"{total:,}")
        self.status.setText(
            f"{shown} span(s) from '{self.shape['time'].get('label')}' to "
            f"'{self.shape['end'].get('label')}' (UTC). Drag to zoom; click "
            f"a span for its row.")

    def shutdown(self):
        self._generation += 1
        self._queries.clear()


def _step_words(step):
    for seconds, words in ((365 * 86400, "year"), (91 * 86400, "quarter"),
                           (30 * 86400, "30 days"), (7 * 86400, "week"),
                           (86400, "day"), (3600, "hour"), (60, "minute"),
                           (1, "second")):
        if step >= seconds:
            count = step // seconds
            return words if count == 1 else f"{count:g} {words}s"
    return f"{step:g} s"

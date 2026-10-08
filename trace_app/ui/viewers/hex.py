"""The Hex tab: a file's bytes, a page at a time, with search, a data
inspector and the offsets an examiner reports.

What it reads is a *source* (core/hex_source.py): a file on the image is
read a page at a time as it is shown -- never whole -- and bytes already in
memory (an archive member, a carve, unallocated space) are shown as they
are. Beside the bytes:

- **Search** (Text, UTF-16 -- both any case -- Hex bytes, or Go to offset):
  run over the whole file on a thread with a reader of its own, listed by
  exact byte offset; every match on the page is highlighted and F3 /
  Shift+F3 step through them;
- **Data inspector**: the bytes at the cursor as integers, floats and the
  time formats evidence keeps (FILETIME, Unix, WebKit, DOS, HFS+, Apple),
  little- or big-endian;
- **Status line**: the cursor's offset, the selection, and where the byte
  lies on the image -- absolute offset and sector -- from the file's data
  runs;
- **Selection**: copy as hex, a C array, Python bytes, Base64 or text;
  export to a file; bookmark the range (a byte-range reference on the
  image, so it reopens after the case does).

Offsets show in hex or decimal, 8, 16 or 32 bytes to a line.
"""

import bisect
import logging

from PySide6.QtCore import (QEvent, QObject, QRect, QSize, Qt, QThread,
                            QTimer, Signal)
from PySide6.QtGui import (QAction, QActionGroup, QColor, QFont,
                           QFontMetrics, QKeySequence, QPalette,
                           QResizeEvent, QShortcut)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox,
                               QStyleOptionViewItem,
                               QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QSizePolicy, QSplitter,
                               QStyle,
                               QTableWidget, QTableWidgetItem,
                               QTableWidgetSelectionRange, QToolBar,
                               QToolButton, QVBoxLayout, QWidget)

from trace_app.core import hex_source
from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import fonts, icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.export_button import ExportButton
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.widgets.context_menus import show_menu

logger = logging.getLogger('TRACE.Hex')

#: The right-hand panel's width at first, and the least it can be dragged to.
SEARCH_PANEL_WIDTH = 320
SEARCH_PANEL_MIN = 240
SEARCH_KIND_WIDTH = 86
SEARCH_GAP = 4
#: Lines on one page of the table.
LINES_PER_PAGE = 1024
BYTES_PER_LINE = (8, 16, 32)
FONT_SIZES = (8, 9, 10, 11, 12, 14, 16, 18, 20, 24)
#: Search kinds, as the combo box beside the search field offers them.
SEARCH_TEXT, SEARCH_UTF16, SEARCH_HEX, SEARCH_OFFSET = \
    'text', 'utf16', 'hex', 'offset'
SEARCH_KINDS = ((SEARCH_TEXT, "Text", "Text, ASCII or UTF-8, any case"),
                (SEARCH_UTF16, "UTF-16", "Text as Windows stores it "
                                         "(UTF-16LE), any case"),
                (SEARCH_HEX, "Hex", "Bytes, written in hex: 4A 46 49 46, "
                                    "4a464946 or \\x4a\\x46"),
                (SEARCH_OFFSET, "Offset", "Go to a byte offset: 0x1A2B, "
                                          "1A2Bh or 6699"))
#: Results listed at most: past this the list says so.
MAX_MATCHES = 10000
#: A selection larger than this is not put on the clipboard.
MAX_COPY = 16 * 1024 * 1024
#: Every match on the page, behind its bytes: translucent amber, which
#: reads on both themes and under the selection colour.
MATCH_COLOUR = QColor(255, 190, 0, 90)
#: The item data role that marks a byte inside a match.
MATCH_ROLE = Qt.UserRole + 7
#: Bytes are drawn in groups of eight, this far apart; the ASCII text this
#: far in from its column's edge.
GROUP = 8
GROUP_GAP = 8
ASCII_PAD = 10
#: From this width the side panel shows search results and the inspector
#: side by side; below it, one above the other.
SIDE_BY_SIDE = 560


def needle(query, kind):
    """The bytes a query asks for (lower-cased for the any-case kinds).
    Raises ValueError for hex that is not hex."""
    if kind == SEARCH_HEX:
        cleaned = ''.join(query.split()).replace('\\x', '').replace(
            '0x', '').replace(',', '')
        if not cleaned or len(cleaned) % 2:
            raise ValueError(query)
        return bytes.fromhex(cleaned)
    if kind == SEARCH_UTF16:
        return query.lower().encode('utf-16-le')
    return query.lower().encode('utf-8')


def parse_offset(text):
    """A byte offset typed as 0x1A2B, 1A2Bh or 6699. Raises ValueError."""
    text = text.strip().lower().replace('_', '').replace(',', '')
    if text.startswith('0x'):
        return int(text, 16)
    if text.endswith('h'):
        return int(text[:-1], 16)
    if text.isdigit():
        return int(text)
    return int(text, 16)


def printable(data):
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)


class _SearchWorker(QObject):
    finished = Signal(list, int)

    def __init__(self, source, query_bytes, fold):
        super().__init__()
        self.source = source
        self.query_bytes = query_bytes
        self.fold = fold
        self.stopped = False

    def run(self):
        try:
            matches = hex_source.find_all(
                self.source, self.query_bytes, fold=self.fold,
                limit=MAX_MATCHES, stop=lambda: self.stopped)
        except Exception as exc:
            logger.warning("Hex search failed: %s", exc)
            matches = []
        if not self.stopped:
            self.finished.emit(matches, len(self.query_bytes))


#: The theme's selection colour, for the ASCII characters of selected
#: bytes (the byte cells get it from the style).
SELECTION_COLOURS = {'light': QColor('#CCE8FF'), 'dark': QColor('#505050')}


class _HexDelegate(NoFocusDelegate):
    """Draws the hex table's cells: a gap after every eight bytes (as hex
    editors group them), the ASCII column a character at a time -- centred
    in the column, each character lit when its byte is selected or inside
    a match -- and a match's mark over its byte cell. The themes' `::item`
    rules make the style ignore a cell's own background, so marks are
    painted here, translucent so text and selection read through."""

    def __init__(self, viewer):
        super().__init__(viewer.hex_table)
        self.viewer = viewer

    def paint(self, painter, option, index):
        width = self.viewer.bytes_per_line
        column = index.column()
        if column == width + 1:
            self._paint_ascii(painter, option, index)
            return
        opt = option
        if 1 <= column < width and column % GROUP == 0:
            # The row's own background under the gap too, then the cell
            # drawn short of it.
            self._paint_row(painter, option, index)
            opt = QStyleOptionViewItem(option)
            opt.rect = option.rect.adjusted(0, 0, -GROUP_GAP, 0)
        super().paint(painter, opt, index)
        # The current match is the selection; the others are marked.
        if index.data(MATCH_ROLE) and \
                not option.state & QStyle.State_Selected:
            painter.fillRect(opt.rect, MATCH_COLOUR)

    def _paint_row(self, painter, option, index):
        """The cell's background as the row has it (base or alternate),
        with no text and no selection."""
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ''
        opt.state &= ~QStyle.State_Selected
        opt.state &= ~QStyle.State_HasFocus
        widget = opt.widget
        style = widget.style() if widget is not None else \
            QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt,
                          painter, widget)

    def _paint_ascii(self, painter, option, index):
        viewer = self.viewer
        self._paint_row(painter, option, index)
        text = index.data(Qt.DisplayRole) or ''
        left, advance = viewer.ascii_geometry(option.rect)
        line = viewer._page_start + index.row() * viewer.bytes_per_line
        selected = viewer._selection_cache
        marks = viewer._page_marks
        chosen = SELECTION_COLOURS.get(icons.current_theme(),
                                       SELECTION_COLOURS['light'])
        painter.save()
        painter.setFont(viewer.hex_table.font())
        painter.setPen(option.palette.color(QPalette.Text))
        for position, character in enumerate(text):
            offset = line + position
            cell = QRect(left + position * advance, option.rect.top(),
                         advance, option.rect.height())
            if selected and selected[0] <= offset < selected[1]:
                painter.fillRect(cell, chosen)
            elif offset in marks:
                painter.fillRect(cell, MATCH_COLOUR)
            painter.drawText(cell, Qt.AlignCenter, character)
        painter.restore()


class _SidePanel(QSplitter):
    """The side panel, saying when its width changes: its arrangement
    (side by side or stacked) and the search strip above it follow."""

    resized = Signal()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.resized.emit()


class HexViewer(QWidget):
    #: (image begin, image end, description): bookmark this byte range.
    bookmark_requested = Signal(int, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.source = None
        self.data = {}
        self.current_page = 0
        self.bytes_per_line = 16
        self.decimal_offsets = False
        self.matches = []
        self._match_length = 1
        self._match_index = -1
        self._last_search = None
        self._search_thread = None
        self._search_worker = None
        #: Bumped by every new or stopped search: a result from an older
        #: one is dropped when it arrives.
        self._search_generation = 0
        self._page_start = 0
        self._page_bytes = b''
        #: (begin, end) of the selected bytes, for the ASCII column; the
        #: offsets on this page inside a match; where an ASCII drag began.
        self._selection_cache = None
        self._page_marks = set()
        self._ascii_anchor = None
        self._ascii_fit = 0
        #: The active image's sector size, and whether a case is open to
        #: keep bookmarks; the window sets both.
        self.sector_size = lambda: 512
        self.bookmarks_enabled = lambda: False
        self.initialize_ui()

    # --- building -----------------------------------------------------------

    def initialize_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.setup_toolbar()
        # The controls, then the search in a strip of its own as wide as the
        # side panel below it: inside the controls' toolbar it was sized by
        # guesswork and, on a narrow window, moved into the overflow menu.
        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(0)
        top.addWidget(self.toolbar, 1)
        self.search_toolbar = QToolBar(self)
        prepare_toolbar(self.search_toolbar)
        self.search_toolbar.setObjectName("compactToolbar")
        self.search_toolbar.setContextMenuPolicy(Qt.PreventContextMenu)
        self.search_toolbar.addWidget(self.search_box)
        align_controls(self.search_toolbar)
        top.addWidget(self.search_toolbar)
        self.layout.addLayout(top)

        self.splitter = QSplitter(Qt.Horizontal, self)
        self.splitter.setObjectName("hexSplitter")
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setSizePolicy(QSizePolicy.Expanding,
                                    QSizePolicy.Expanding)

        left = QWidget()
        left.setObjectName("hexBytesPanel")
        self.bytes_panel = left
        column = QVBoxLayout(left)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        self.setup_hex_table()
        column.addWidget(self.hex_table, 1)
        self.status_label = QLabel()
        self.status_label.setObjectName("hexStatus")
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        column.addWidget(self.status_label)
        self.splitter.addWidget(left)

        # Right: search results and the data inspector -- side by side
        # when there is room (_arrange_side), else one above the other.
        self.side = _SidePanel(Qt.Vertical)
        self.side.resized.connect(self._align_search_controls)
        self.side.setObjectName("hexSide")
        self.side.setChildrenCollapsible(False)
        self.side.setMinimumWidth(SEARCH_PANEL_MIN)
        self.results_table = self._side_table("hexSearchResults",
                                              ["Offset", "Match"])
        self.results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results_table.itemSelectionChanged.connect(
            self._result_activated)
        self.side.addWidget(self.results_table)

        inspector = QWidget()
        inspector.setObjectName("hexInspectorPanel")
        self.inspector_panel = inspector
        rows = QVBoxLayout(inspector)
        rows.setContentsMargins(0, 0, 0, 0)
        rows.setSpacing(0)
        # Its header in line with the hex table's and the results'; the
        # byte order is chosen in the toolbar.
        self.inspector = self._side_table("hexInspector",
                                          ["Data inspector", "Value"])
        self.inspector.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.inspector.setContextMenuPolicy(Qt.ActionsContextMenu)
        copy = QAction("Copy", self.inspector)
        copy.triggered.connect(self._copy_inspector)
        self.inspector.addAction(copy)
        rows.addWidget(self.inspector, 1)
        self.side.addWidget(inspector)
        self.side.setSizes([200, 300])
        self.side.splitterMoved.connect(
            lambda *_: self._align_search_controls())
        self.splitter.addWidget(self.side)
        # A wider window widens the side panel; the bytes keep their width.
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.splitterMoved.connect(self._divider_moved)
        #: The width the bytes need; the divider starts there and follows
        #: it until the examiner moves it.
        self._content_width = 0
        self._user_split = False
        self.layout.addWidget(self.splitter, 1)
        from trace_app.infra.window_state import read_value
        self.set_inspector_visible(read_value('Hex', 'inspector', '1') != '0',
                                   remember=False)
        bytes_per_line, decimal = self._initial_view
        self.set_bytes_per_line(bytes_per_line)
        self.set_decimal_offsets(decimal)

        QShortcut(QKeySequence(Qt.Key_F3), self, self.find_next,
                  context=Qt.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence(Qt.SHIFT | Qt.Key_F3), self,
                  self.find_previous, context=Qt.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence.Find, self, self._focus_search,
                  context=Qt.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence(Qt.CTRL | Qt.Key_G), self, self._go_to_offset,
                  context=Qt.WidgetWithChildrenShortcut)
        self._show_status()

    @staticmethod
    def _side_table(name, headers):
        """A table beside the bytes, headed and spaced like the hex table."""
        table = QTableWidget(0, len(headers))
        table.setObjectName(name)
        table.setHorizontalHeaderLabels(headers)
        header = table.horizontalHeader()
        header.setObjectName("hexTableHeader")
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(20)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setWordWrap(False)
        table.setFont(fonts.monospace(9))
        return table

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.toolbar.setObjectName("compactToolbar")
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        self.first_action = icons.action(icons.UP, "First page", self)
        self.first_action.triggered.connect(self.load_first_page)
        self.toolbar.addAction(self.first_action)
        self.prev_action = icons.action(icons.BACK, "Previous page", self)
        self.prev_action.triggered.connect(self.previous_page)
        self.toolbar.addAction(self.prev_action)
        self.page_entry = QLineEdit(self)
        self.page_entry.setFixedWidth(48)
        self.page_entry.setAlignment(Qt.AlignCenter)
        self.page_entry.setPlaceholderText("1")
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)
        self.total_pages_label = QLabel("of —")
        # Fixed: the count growing would shift every control to its right.
        self.total_pages_label.setFixedWidth(64)
        self.toolbar.addWidget(self.total_pages_label)
        self.next_action = icons.action(icons.FORWARD, "Next page", self)
        self.next_action.triggered.connect(self.next_page)
        self.toolbar.addAction(self.next_action)
        self.last_action = icons.action(icons.DOWN, "Last page", self)
        self.last_action.triggered.connect(self.load_last_page)
        self.toolbar.addAction(self.last_action)
        self.toolbar.addSeparator()

        self.export_button = ExportButton(self._export_content, "Hex View",
                                          self)
        self.toolbar.addWidget(self.export_button)
        self.inspector_action = icons.action(icons.INSPECTOR,
                                             "Data Inspector", self)
        self.inspector_action.setCheckable(True)
        self.inspector_action.setToolTip(
            "Show or hide the data inspector: the bytes at the cursor as "
            "numbers, times and a GUID")
        self.inspector_action.toggled.connect(self.set_inspector_visible)
        self.toolbar.addAction(self.inspector_action)
        self._build_view_menu()

        # The search: what to look for, the field, and previous / next --
        # one box as wide as the panel below it (_align_now).
        self.search_box = QWidget()
        self.search_box.setObjectName("hexSearchBox")
        row = QHBoxLayout(self.search_box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SEARCH_GAP)
        self.search_kind = QComboBox(self.search_box)
        self.search_kind.setObjectName("hexSearchKind")
        for key, label, tip in SEARCH_KINDS:
            self.search_kind.addItem(label, key)
            self.search_kind.setItemData(self.search_kind.count() - 1, tip,
                                         Qt.ToolTipRole)
        self.search_kind.setFixedWidth(SEARCH_KIND_WIDTH)
        self.search_kind.currentIndexChanged.connect(self._kind_changed)
        row.addWidget(self.search_kind)
        self.search_bar = QLineEdit(self.search_box)
        self.search_bar.setObjectName("hexSearchField")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.returnPressed.connect(self._search_or_next)
        row.addWidget(self.search_bar, 1)
        self.find_prev_button = self._step_button(
            icons.UP, "Previous match (Shift+F3)", self.find_previous)
        self.find_next_button = self._step_button(
            icons.DOWN, "Next match (F3)", self.find_next)
        row.addWidget(self.find_prev_button)
        row.addWidget(self.find_next_button)
        self.search_box.setFixedWidth(SEARCH_PANEL_WIDTH)
        self._kind_changed()
        align_controls(self.toolbar)

    def _build_view_menu(self):
        """View ▾: font size, bytes per line, offsets and the inspector's
        byte order -- one button instead of four boxes, so the toolbar fits
        a narrow window. Each choice is remembered."""
        from trace_app.infra.window_state import read_value
        self.view_button = QToolButton(self)
        self.view_button.setObjectName("listingViewButton")
        self.view_button.setProperty("dropdown", True)
        self.view_button.setPopupMode(QToolButton.InstantPopup)
        icons.apply_to(self.view_button, icons.VIEW_OPTIONS)
        self.view_button.setToolTip("View: font size, bytes per line, "
                                    "offsets, byte order")
        menu = QMenu(self.view_button)
        self.view_actions = {}

        def group(key, title, choices, current, apply):
            sub = menu.addMenu(title)
            actions = QActionGroup(self)
            actions.setExclusive(True)
            self.view_actions[key] = {}
            for value, label in choices:
                action = sub.addAction(label)
                action.setCheckable(True)
                action.setChecked(value == current)
                action.triggered.connect(
                    lambda _c=False, v=value: self._view_choice(key, v,
                                                                apply))
                actions.addAction(action)
                self.view_actions[key][value] = action

        def stored(key, default, kind):
            try:
                return kind(read_value('Hex', key, str(default)))
            except ValueError:
                return default

        self.font_size = stored('font', 10, int)
        if self.font_size not in FONT_SIZES:
            self.font_size = 10
        bytes_per_line = stored('bytes', 16, int)
        decimal = read_value('Hex', 'offsets', 'hex') == 'decimal'
        self.little_endian = read_value('Hex', 'byte_order',
                                        'little') != 'big'
        group('bytes', "Bytes per Line",
              [(n, f"{n} bytes") for n in BYTES_PER_LINE],
              bytes_per_line if bytes_per_line in BYTES_PER_LINE else 16,
              self.set_bytes_per_line)
        group('offsets', "Offsets",
              [(False, "Hexadecimal"), (True, "Decimal")], decimal,
              self.set_decimal_offsets)
        group('font', "Font Size", [(n, f"{n} pt") for n in FONT_SIZES],
              self.font_size, self.set_font_size)
        group('byte_order', "Inspector Byte Order",
              [(True, "Little-endian"), (False, "Big-endian")],
              self.little_endian, self.set_little_endian)
        menu.addSeparator()
        menu.addAction(self.inspector_action)
        self.view_button.setMenu(menu)
        self.toolbar.addWidget(self.view_button)
        self._initial_view = (bytes_per_line if bytes_per_line in
                              BYTES_PER_LINE else 16, decimal)

    def _view_choice(self, key, value, apply):
        from trace_app.infra.window_state import save_value
        apply(value)
        saved = {'offsets': lambda v: 'decimal' if v else 'hex',
                 'byte_order': lambda v: 'little' if v else 'big'}
        save_value('Hex', key, saved.get(key, str)(value))

    def set_font_size(self, size):
        self.font_size = int(size)
        self.update_font_size()

    def set_little_endian(self, little):
        self.little_endian = bool(little)
        self._update_cursor()

    def _step_button(self, icon_name, tip, slot):
        button = QToolButton(self.search_box)
        button.setObjectName("hexFindStep")
        icons.apply_to(button, icon_name)
        button.setToolTip(tip)
        button.setAutoRaise(True)
        button.setEnabled(False)
        button.clicked.connect(slot)
        return button

    def setup_hex_table(self):
        self.hex_table = QTableWidget()
        self.hex_table.setObjectName("hexTable")
        self.hex_table.verticalHeader().setDefaultSectionSize(20)
        self.hex_table.verticalHeader().setVisible(False)
        font = fonts.monospace()
        font.setPointSize(10)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 1)
        self.hex_table.setFont(font)
        header = self.hex_table.horizontalHeader()
        header.setObjectName("hexTableHeader")
        header.setStretchLastSection(True)
        self.hex_table.setShowGrid(False)
        self.hex_table.setAlternatingRowColors(True)
        self.hex_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.hex_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.hex_table.setItemDelegate(_HexDelegate(self))
        self.hex_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hex_table.customContextMenuRequested.connect(self._table_menu)
        self.hex_table.itemSelectionChanged.connect(self._update_cursor)
        self.hex_table.currentCellChanged.connect(
            lambda *_: self._update_cursor())
        # Drags in the ASCII column select bytes; its width follows the
        # table's.
        self.hex_table.viewport().installEventFilter(self)
        # Ctrl+C is this view's own (bytes as hex), not the shared cell copy.
        from trace_app.ui.widgets.context_menus import OWN_COPY
        self.hex_table.setProperty(OWN_COPY, True)
        self.hex_table.installEventFilter(self)
        self.hex_table.viewport().setMouseTracking(False)
        self._set_columns()

    def _set_columns(self):
        width = self.bytes_per_line
        self.hex_table.setColumnCount(width + 2)
        self.hex_table.setHorizontalHeaderLabels(
            ['Offset'] + [f'{i:02X}' for i in range(width)] + ['ASCII'])
        self.update_font_size()

    # --- layout -------------------------------------------------------------

    def showEvent(self, event):
        super().showEvent(event)
        self._set_split()
        self._align_search_controls()

    def resizeEvent(self, event: QResizeEvent):
        super().resizeEvent(event)
        if self.isVisible():
            self._set_split()
        self._align_search_controls()

    def _set_split(self):
        """Put the divider where the bytes end -- until the examiner drags
        it: from then on, theirs stands (either way, as far as they like)."""
        if self._user_split or not self._content_width:
            return
        total = self.splitter.width()
        if total <= SEARCH_PANEL_MIN:
            return
        left = min(self._content_width, total - SEARCH_PANEL_MIN)
        if self.splitter.sizes()[0] != left:
            self.splitter.setSizes([left, total - left])

    def _divider_moved(self, *_args):
        self._user_split = True
        self._align_search_controls()

    def _align_search_controls(self):
        QTimer.singleShot(0, self._align_now)

    def _align_now(self):
        """Arrange the side panel for its width, then size the search strip
        over the results: the results are the side panel's last column,
        at the right edge, so the strip there is as wide as they are and
        the controls' toolbar has the rest of the row. The strip reaches
        left by its own layout margin, so the box lines up exactly."""
        if not self.side.isVisible():
            return
        self._arrange_side()
        margins = self.search_toolbar.layout().contentsMargins()
        results = self.results_table.width() or self.side.width()
        self.search_toolbar.setFixedWidth(results + margins.left())
        box = max(SEARCH_KIND_WIDTH + 120, results - margins.right())
        if box != self.search_box.width():
            self.search_box.setFixedWidth(box)

    def _arrange_side(self):
        """Side by side when wide enough -- the inspector first, the
        results last, under the search -- else the results above the
        inspector."""
        side_by_side = self.inspector_panel.isVisible() and \
            self.side.width() >= SIDE_BY_SIDE
        wanted = Qt.Horizontal if side_by_side else Qt.Vertical
        if self.side.orientation() == wanted:
            return
        self.side.setOrientation(wanted)
        if side_by_side:
            self.side.insertWidget(0, self.inspector_panel)
            extent = self.side.width()
        else:
            self.side.insertWidget(0, self.results_table)
            extent = self.side.height()
        self.side.setSizes([extent // 2, extent - extent // 2])
        QTimer.singleShot(0, self._align_now)

    def set_inspector_visible(self, visible, remember=True):
        """Show or hide the data inspector (remembered)."""
        visible = bool(visible)
        self.inspector_panel.setVisible(visible)
        if self.inspector_action.isChecked() != visible:
            self.inspector_action.blockSignals(True)
            self.inspector_action.setChecked(visible)
            self.inspector_action.blockSignals(False)
        if visible:
            self._update_cursor()
        if remember:
            from trace_app.infra.window_state import save_value
            save_value('Hex', 'inspector', '1' if visible else '0')
        self._align_search_controls()

    def update_font_size(self, *_args):
        """Font size, then every column sized to what it holds, measured
        from the font: the hex block takes the width it needs and no more
        (the ASCII column used to stretch across the rest, its text
        stranded at the left), and the side panel gets the remainder."""
        size = getattr(self, 'font_size', 10)
        table = self.hex_table
        font = table.font()
        font.setPointSize(size)
        table.setFont(font)
        header_font = table.horizontalHeader().font()
        header_font.setPointSize(size)
        table.horizontalHeader().setFont(header_font)
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item:
                    item.setFont(font)
        self._fit_columns()

    def _fit_columns(self):
        from PySide6.QtGui import QFontMetrics
        table = self.hex_table
        width = self.bytes_per_line
        metrics = QFontMetrics(table.font())
        header_metrics = QFontMetrics(table.horizontalHeader().font())
        table.verticalHeader().setDefaultSectionSize(
            max(20, metrics.height() + 6))
        header = table.horizontalHeader()
        header.setStretchLastSection(False)
        largest = (self.source.size - 1) if self.source is not None and \
            self.source.size else 0
        sample = max(self._offset_text(largest), self._offset_text(0),
                     key=len)
        columns = [max(metrics.horizontalAdvance(sample),
                       header_metrics.horizontalAdvance("Offset")) + 24]
        byte = max(metrics.horizontalAdvance('00'),
                   header_metrics.horizontalAdvance('00')) + 12
        for index in range(width):
            gap = GROUP_GAP if (index + 1) % GROUP == 0 and \
                index + 1 < width else 0
            columns.append(byte + gap)
        # The font's letter spacing is not in its metrics: added per
        # character, or the line's last characters were cut off.
        spacing = int(table.font().letterSpacing())
        columns.append(max(metrics.horizontalAdvance('W' * width)
                           + spacing * width,
                           header_metrics.horizontalAdvance('ASCII'))
                       + ASCII_PAD * 2 + 6)
        for index, extent in enumerate(columns):
            header.setSectionResizeMode(index, QHeaderView.Fixed)
            table.setColumnWidth(index, extent)
        self._ascii_fit = columns[-1]
        scroll = table.verticalScrollBar().sizeHint().width()
        # A few pixels spare: the frame and the style's margins, or a
        # horizontal scroll bar appears for nothing.
        # The header's own length, not the sum asked for: a section is
        # never narrower than the header's minimum section size.
        self._content_width = header.length() + scroll + \
            2 * table.frameWidth() + 2
        self._stretch_ascii()
        if self.isVisible():
            self._set_split()
        self._align_search_controls()

    def _stretch_ascii(self):
        """The ASCII column fills what the bytes leave of the table's
        width, never narrower than its characters: widening the panel
        widens the header bar with it, the text centred."""
        table = self.hex_table
        last = table.columnCount() - 1
        others = sum(table.columnWidth(c) for c in range(last))
        wanted = max(self._ascii_fit, table.viewport().width() - others)
        if table.columnWidth(last) != wanted:
            table.setColumnWidth(last, wanted)

    def ascii_geometry(self, rect):
        """(x of the first character, advance) in an ASCII cell `rect`:
        the line's characters centred as a block of bytes_per_line, so the
        columns of characters stay aligned line to line."""
        font = self.hex_table.font()
        advance = QFontMetrics(font).horizontalAdvance('W') + \
            int(font.letterSpacing())
        block = advance * self.bytes_per_line
        return rect.left() + max(0, (rect.width() - block) // 2), advance

    # --- selecting in the ASCII column ---------------------------------------------

    def _ascii_offset_at(self, point, clamp=False):
        """The byte under `point` in the ASCII column, or None. With
        `clamp`, a point beside or past the column gives the nearest."""
        table = self.hex_table
        width = self.bytes_per_line
        row = table.rowAt(point.y())
        if row < 0:
            if not clamp or not table.rowCount():
                return None
            row = 0 if point.y() < 0 else table.rowCount() - 1
        rect = table.visualRect(table.model().index(row, width + 1))
        if not clamp and not rect.contains(point):
            return None
        left, advance = self.ascii_geometry(rect)
        line = self._page_start + row * width
        count = min(width, self._page_start + len(self._page_bytes) - line)
        if count <= 0:
            return None
        position = (point.x() - left) // advance
        if not clamp and not 0 <= position < count:
            return None
        return line + max(0, min(count - 1, position))

    def eventFilter(self, watched, event):
        if watched is self.hex_table and event.type() == QEvent.KeyPress \
                and event.matches(QKeySequence.Copy):
            # The selected bytes, as hex; the whole lines when the
            # selection is in the ASCII column.
            if self.selection():
                self.copy_selection('hex')
            else:
                self.copy_to_clipboard()
            return True
        if watched is self.hex_table.viewport():
            kind = event.type()
            if kind == QEvent.Resize:
                QTimer.singleShot(0, self._stretch_ascii)
            elif kind == QEvent.MouseButtonPress and \
                    event.button() == Qt.LeftButton:
                offset = self._ascii_offset_at(event.position().toPoint())
                if offset is not None:
                    if event.modifiers() & Qt.ShiftModifier and \
                            self._selection_cache:
                        anchor = self._selection_cache[0]
                    else:
                        anchor = offset
                    self._ascii_anchor = anchor
                    self._select_bytes(min(anchor, offset),
                                       max(anchor, offset) + 1)
                    self.hex_table.setFocus()
                    return True
            elif kind == QEvent.MouseMove and \
                    self._ascii_anchor is not None and \
                    event.buttons() & Qt.LeftButton:
                offset = self._ascii_offset_at(event.position().toPoint(),
                                               clamp=True)
                if offset is not None:
                    anchor = self._ascii_anchor
                    self._select_bytes(min(anchor, offset),
                                       max(anchor, offset) + 1)
                return True
            elif kind == QEvent.MouseButtonRelease and \
                    self._ascii_anchor is not None:
                self._ascii_anchor = None
                return True
        return super().eventFilter(watched, event)

    def _select_bytes(self, begin, end):
        """Select the byte cells of [begin, end) on this page."""
        table = self.hex_table
        width = self.bytes_per_line
        table.blockSignals(True)
        table.clearSelection()
        position = begin
        first = None
        end = min(end, self._page_start + len(self._page_bytes))
        while position < end:
            row = (position - self._page_start) // width
            column = position % width + 1
            last = min(width, column + (end - position) - 1)
            table.setRangeSelected(
                QTableWidgetSelectionRange(row, column, row, last), True)
            if first is None:
                first = (row, column)
            position += last - column + 1
        if first is not None:
            table.setCurrentCell(first[0], first[1],
                                 table.selectionModel().SelectionFlag.NoUpdate)
        table.blockSignals(False)
        self._update_cursor()
        return first

    # --- content ------------------------------------------------------------

    def display_hex_content(self, file_content, data=None):
        """Bytes already in memory. Where they are one stretch of the image
        (unallocated space, a carve not rebuilt) their image offsets are
        known too."""
        data = data or {}
        base = None
        sector = self.sector_size()
        if data.get('is_carved') and not data.get('fragments') and \
                data.get('offset') is not None:
            base = int(data['offset'])
        elif data.get('is_unallocated') and \
                data.get('start_offset') is not None:
            base = int(data['start_offset']) * sector
        self.display_source(hex_source.BytesSource(file_content, base,
                                                   sector), data)

    def display_source(self, source, data=None):
        """Show `source`, from its first page."""
        self._stop_search()
        self.source = source
        self.data = data or {}
        self.current_page = 0
        self.matches = []
        self._match_index = -1
        self._last_search = None
        self.results_table.setRowCount(0)
        self._set_result_count(None)
        self._update_find_buttons()
        self._fit_columns()
        self.display_current_page()

    def clear_content(self):
        self._stop_search()
        self.source = None
        self.data = {}
        self.matches = []
        self._page_bytes = b''
        self.hex_table.setRowCount(0)
        self.results_table.setRowCount(0)
        self.inspector.setRowCount(0)
        self._set_result_count(None)
        self._update_find_buttons()
        self.update_navigation_states()
        self._show_status()

    def page_size(self):
        return LINES_PER_PAGE * self.bytes_per_line

    def total_pages(self):
        if self.source is None:
            return 0
        return max(1, -(-self.source.size // self.page_size()))

    def _offset_text(self, offset):
        return f"{offset:,}" if self.decimal_offsets else f"{offset:08X}"

    def display_current_page(self):
        table = self.hex_table
        table.setRowCount(0)
        if self.source is None:
            return
        width = self.bytes_per_line
        self._page_start = self.current_page * self.page_size()
        try:
            self._page_bytes = self.source.read(self._page_start,
                                                self.page_size())
        except Exception as exc:
            logger.warning("Hex page read failed: %s", exc)
            self._page_bytes = b''
        page = self._page_bytes
        lines = -(-len(page) // width)
        font = table.font()
        table.setUpdatesEnabled(False)
        table.blockSignals(True)
        table.setRowCount(lines)
        highlighted = self._highlights()
        self._page_marks = highlighted
        for row in range(lines):
            chunk = page[row * width:(row + 1) * width]
            offset = self._page_start + row * width
            address = QTableWidgetItem(self._offset_text(offset))
            address.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            address.setFont(font)
            table.setItem(row, 0, address)
            for column, value in enumerate(chunk):
                cell = QTableWidgetItem(f"{value:02X}")
                cell.setTextAlignment(Qt.AlignCenter)
                cell.setFont(font)
                if offset + column in highlighted:
                    cell.setData(MATCH_ROLE, True)
                table.setItem(row, column + 1, cell)
            text = QTableWidgetItem(printable(chunk))
            # Drawn a character at a time by _HexDelegate, centred.
            text.setTextAlignment(Qt.AlignCenter)
            text.setFont(font)
            table.setItem(row, width + 1, text)
        table.blockSignals(False)
        table.setUpdatesEnabled(True)
        self.update_navigation_states()
        self._update_cursor()

    def _highlights(self):
        """Offsets on this page inside a match."""
        if not self.matches:
            return set()
        begin = self._page_start
        end = begin + len(self._page_bytes)
        first = bisect.bisect_left(self.matches,
                                   begin - self._match_length + 1)
        marked = set()
        for start in self.matches[first:]:
            if start >= end:
                break
            marked.update(range(max(start, begin),
                                min(start + self._match_length, end)))
        return marked

    def set_bytes_per_line(self, count):
        """8, 16 or 32 bytes to a line; the selection stays on its bytes."""
        self.view_actions['bytes'][count].setChecked(True)
        if count == self.bytes_per_line:
            return
        keep = self.selection()
        self.bytes_per_line = count
        self._set_columns()
        if self.source is not None:
            if keep:
                self.current_page = keep[0] // self.page_size()
            self.display_current_page()
            if keep:
                self.show_bytes(keep[0], keep[1] - keep[0])

    def set_decimal_offsets(self, decimal):
        self.decimal_offsets = bool(decimal)
        self.view_actions['offsets'][self.decimal_offsets].setChecked(True)
        self._fit_columns()
        for row in range(self.hex_table.rowCount()):
            item = self.hex_table.item(row, 0)
            if item is not None:
                item.setText(self._offset_text(
                    self._page_start + row * self.bytes_per_line))
        for row in range(self.results_table.rowCount()):
            item = self.results_table.item(row, 0)
            if item is not None:
                item.setText(self._offset_text(item.data(Qt.UserRole)))
        self._update_cursor()

    def _export_content(self):
        """The page on screen as text, for the export button."""
        if self.source is None:
            return None
        width = self.bytes_per_line
        header = ("Offset    " + ' '.join(f'{i:02X}' for i in range(width))
                  + "  ASCII")
        lines = []
        for row in range(0, len(self._page_bytes), width):
            chunk = self._page_bytes[row:row + width]
            hexes = ' '.join(f"{b:02X}" for b in chunk).ljust(width * 3 - 1)
            lines.append(f"{self._offset_text(self._page_start + row)}  "
                         f"{hexes}  {printable(chunk)}")
        return f"{header}\n\n" + '\n'.join(lines)

    # --- pages ----------------------------------------------------------------

    def load_first_page(self):
        self._go_to_page(0)

    def load_last_page(self):
        self._go_to_page(self.total_pages() - 1)

    def next_page(self):
        self._go_to_page(self.current_page + 1)

    def previous_page(self):
        self._go_to_page(self.current_page - 1)

    def _go_to_page(self, page):
        if self.source is None:
            return
        page = max(0, min(page, self.total_pages() - 1))
        if page != self.current_page or not self.hex_table.rowCount():
            self.current_page = page
            self.display_current_page()

    def go_to_page_by_entry(self):
        try:
            page = int(self.page_entry.text()) - 1
        except ValueError:
            message.warning(self, "Invalid Page",
                            "Please enter a valid page number.")
            return
        if not 0 <= page < self.total_pages():
            message.warning(self, "Invalid Page", "Page number out of range.")
            return
        self._go_to_page(page)

    def update_navigation_states(self):
        pages = self.total_pages()
        has = self.source is not None
        self.prev_action.setEnabled(has and self.current_page > 0)
        self.first_action.setEnabled(has and self.current_page > 0)
        self.next_action.setEnabled(has and self.current_page < pages - 1)
        self.last_action.setEnabled(has and self.current_page < pages - 1)
        self.page_entry.setText(str(self.current_page + 1) if has else '')
        self.total_pages_label.setText(f"of {pages:,}" if has else "of —")

    # --- the cursor, the selection, the inspector, the status line ----------------

    def _cell_offset(self, row, column):
        """The file offset a cell shows: a byte cell its byte, the offset or
        ASCII column the line's first byte."""
        width = self.bytes_per_line
        base = self._page_start + row * width
        if 1 <= column <= width:
            return base + column - 1
        return base

    def selection(self):
        """(begin, end) of the bytes selected, or None. A selected ASCII
        cell stands for its whole line."""
        if self.source is None:
            return None
        width = self.bytes_per_line
        page_end = self._page_start + len(self._page_bytes)
        offsets = []
        for index in self.hex_table.selectedIndexes():
            if 1 <= index.column() <= width:
                offsets.append(self._cell_offset(index.row(),
                                                 index.column()))
            elif index.column() == width + 1:
                begin = self._cell_offset(index.row(), 1)
                offsets.extend((begin, min(begin + width, page_end) - 1))
        if not offsets:
            return None
        return min(offsets), min(max(offsets) + 1, self.source.size)

    def cursor_offset(self):
        if self.source is None or not self.source.size:
            return None
        selected = self.selection()
        if selected:
            return selected[0]
        row, column = self.hex_table.currentRow(), \
            self.hex_table.currentColumn()
        if row < 0:
            return None
        return min(self._cell_offset(row, max(column, 0)),
                   self.source.size - 1)

    def _update_cursor(self):
        self._selection_cache = self.selection()
        self.hex_table.viewport().update()
        offset = self.cursor_offset()
        self._fill_inspector(offset)
        self._show_status(offset)

    def _fill_inspector(self, offset):
        if offset is None or self.source is None:
            self.inspector.setRowCount(0)
            return
        try:
            data = self.source.read(offset, hex_source.INSPECT_BYTES)
        except Exception:
            data = b''
        rows = hex_source.interpret(data, self.little_endian)
        self.inspector.setRowCount(len(rows))
        for index, (label, value) in enumerate(rows):
            self.inspector.setItem(index, 0, QTableWidgetItem(label))
            cell = QTableWidgetItem(value)
            cell.setToolTip(value)
            self.inspector.setItem(index, 1, cell)

    def _copy_inspector(self):
        rows = sorted({i.row() for i in self.inspector.selectedIndexes()})
        text = '\n'.join(f"{self.inspector.item(r, 0).text()}\t"
                         f"{self.inspector.item(r, 1).text()}" for r in rows)
        if text:
            QApplication.clipboard().setText(text)

    def _number(self, value):
        return f"{value:,}" if self.decimal_offsets else f"0x{value:X}"

    def _where(self, offset):
        """'  ·  Image offset 0x…  ·  sector N', or why there is none."""
        source = self.source
        image = source.image_offset(offset)
        from trace_app.core.image_handler import ImageHandler
        if image is not None and image >= ImageHandler.CARVE_SPACE:
            # Carved inside a decrypted, logical or RAID volume: its own
            # address range (ImageHandler.carve_volumes), not the image's.
            within = (image - ImageHandler.CARVE_SPACE) % \
                ImageHandler.CARVE_SPAN
            return (f"  ·  Volume offset {self._number(within)} (inside a "
                    f"decrypted, LVM or RAID volume, not on the image)")
        if image is not None:
            sector = image // max(1, getattr(source, 'sector_size', 512))
            return (f"  ·  Image offset {self._number(image)}  ·  "
                    f"sector {sector:,}")
        note = source.describe()
        return f"  ·  {note[0].upper() + note[1:]}" if note else ''

    def _show_status(self, offset=None):
        if self.source is None:
            self.status_label.setText("No file shown")
            return
        size = self.source.size
        if offset is None:
            self.status_label.setText(f"{size:,} bytes")
            return
        text = f"Offset {self._number(offset)}"
        if not self.decimal_offsets:
            text += f" ({offset:,})"
        selected = self.selection()
        if selected and selected[1] - selected[0] > 1:
            begin, end = selected
            text += (f"  ·  Selected {end - begin:,} bytes "
                     f"{self._number(begin)}–{self._number(end - 1)}")
        text += self._where(offset)
        text += f"  ·  {size:,} bytes"
        self.status_label.setText(text)

    # --- selection tools ------------------------------------------------------------

    def _table_menu(self, point):
        selected = self.selection()
        menu = QMenu(self)
        menu.setToolTipsVisible(True)
        copy = menu.addAction("Copy")
        copy.triggered.connect(self.copy_to_clipboard)
        copy_as = menu.addMenu("Copy Selection As")
        for kind, label in hex_source.COPY_KINDS:
            action = copy_as.addAction(label)
            action.triggered.connect(
                lambda _c=False, k=kind: self.copy_selection(k))
        copy_as.setEnabled(bool(selected))
        menu.addSeparator()
        export = menu.addAction("Export Selection…")
        export.setEnabled(bool(selected))
        export.triggered.connect(self.export_selection)
        bookmark = menu.addAction("Bookmark Selection…")
        reason = self._bookmark_refusal(selected)
        bookmark.setEnabled(reason is None)
        if reason:
            bookmark.setToolTip(reason)
        bookmark.triggered.connect(self.bookmark_selection)
        menu.addSeparator()
        go = menu.addAction("Go to Offset…")
        go.setShortcut(QKeySequence(Qt.CTRL | Qt.Key_G))
        go.triggered.connect(self._go_to_offset)
        show_menu(menu, self.hex_table.viewport().mapToGlobal(point), view=False)

    def copy_to_clipboard(self):
        """The selected cells as shown, a line per row."""
        indexes = sorted(self.hex_table.selectedIndexes(),
                         key=lambda i: (i.row(), i.column()))
        lines, row, current = [], None, []
        for index in indexes:
            if index.row() != row and current:
                lines.append(' '.join(current))
                current = []
            row = index.row()
            current.append(index.data(Qt.DisplayRole) or '')
        if current:
            lines.append(' '.join(current))
        if lines:
            QApplication.clipboard().setText('\n'.join(lines))

    def selected_bytes(self, limit=MAX_COPY):
        selected = self.selection()
        if not selected:
            return None
        begin, end = selected
        if end - begin > limit:
            message.warning(self, "Selection too large",
                            f"{end - begin:,} bytes is more than the "
                            f"clipboard takes here ({limit:,}). Export the "
                            f"selection to a file instead.")
            return None
        return self.source.read(begin, end - begin)

    def copy_selection(self, kind):
        data = self.selected_bytes()
        if data is not None:
            QApplication.clipboard().setText(hex_source.copy_as(data, kind))

    def export_selection(self, path=None):
        selected = self.selection()
        if not selected:
            return None
        begin, end = selected
        if path is None:
            name = (self.data.get('name') or 'selection').replace('/', '_')
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Selection", f"{name}.{begin:x}-{end - 1:x}.bin")
            if not path:
                return None
        try:
            with open(path, 'wb') as handle:
                position = begin
                while position < end:
                    piece = self.source.read(position,
                                             min(4 << 20, end - position))
                    if not piece:
                        break
                    handle.write(piece)
                    position += len(piece)
        except OSError as exc:
            message.warning(self, "Export failed", str(exc))
            return None
        message.information(self, "Selection exported",
                            f"{end - begin:,} bytes written to\n{path}")
        return path

    def _bookmark_refusal(self, selected):
        """Why the selection cannot be bookmarked, or None."""
        if not selected:
            return "Select the bytes to bookmark"
        if not self.bookmarks_enabled():
            return "Bookmarks are kept in a case"
        if not self.source.contiguous(*selected):
            return ("These bytes are not one stretch of the image: resident, "
                    "sparse, split across fragments, or on a volume that is "
                    "not the image's own bytes")
        return None

    def bookmark_selection(self):
        selected = self.selection()
        if self._bookmark_refusal(selected):
            return
        begin, end = selected
        image = self.source.image_offset(begin)
        name = self.data.get('name') or 'bytes'
        self.bookmark_requested.emit(
            image, image + (end - begin),
            f"{name}: bytes {begin:,}–{end - 1:,}")

    # --- searching --------------------------------------------------------------

    def _kind_changed(self, *_args):
        key = self.search_kind.currentData()
        self.search_bar.setPlaceholderText(
            {SEARCH_TEXT: "Find text...", SEARCH_UTF16: "Find UTF-16 text...",
             SEARCH_HEX: "Find bytes: 4A 46 49 46",
             SEARCH_OFFSET: "Go to offset: 0x1A2B"}[key])
        self.search_bar.setToolTip(dict(
            (k, tip) for k, _label, tip in SEARCH_KINDS)[key])

    def _focus_search(self):
        self.search_bar.setFocus()
        self.search_bar.selectAll()

    def _go_to_offset(self):
        self.search_kind.setCurrentIndex(
            self.search_kind.findData(SEARCH_OFFSET))
        self._focus_search()

    def _search_or_next(self):
        """Enter: search -- or, for the same search again, the next match."""
        query = (self.search_kind.currentData(),
                 self.search_bar.text().strip())
        if query == self._last_search and self.matches and \
                query[0] != SEARCH_OFFSET:
            self.find_next()
        else:
            self.trigger_search()

    def trigger_search(self):
        query = self.search_bar.text().strip()
        if not query or self.source is None:
            return
        kind = self.search_kind.currentData()
        if kind == SEARCH_OFFSET:
            try:
                offset = parse_offset(query)
            except ValueError:
                message.warning(self, "Go to offset",
                                f"'{query}' is not an offset. Use 0x1A2B "
                                f"(hex) or 6699 (decimal).")
                return
            if not 0 <= offset < self.source.size:
                message.warning(self, "Go to offset",
                                f"Offset {offset:,} is past the end of this "
                                f"file ({self.source.size:,} bytes).")
                return
            self.show_bytes(offset, 1)
            return
        try:
            query_bytes = needle(query, kind)
        except ValueError:
            message.warning(self, "Find bytes",
                            f"'{query}' is not hex bytes: two hex digits a "
                            f"byte, such as 4A 46 49 46.")
            return
        self._stop_search()
        self._last_search = (kind, query)
        try:
            reader = self.source.clone()
        except Exception as exc:
            message.warning(self, "Search",
                            f"The file could not be read: {exc}")
            return
        self._set_result_count(None, searching=True)
        thread = QThread(self)
        worker = _SearchWorker(reader, query_bytes,
                               fold=kind in (SEARCH_TEXT, SEARCH_UTF16))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        self._search_generation += 1
        worker.finished.connect(
            lambda found, length, g=self._search_generation:
            self._search_finished(g, found, length))
        worker.finished.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda t=thread: self._search_done(t))
        self._search_thread, self._search_worker = thread, worker
        thread.start()

    def _search_finished(self, generation, matches, length):
        if generation == self._search_generation:
            self.handle_search_results(matches, length)

    def _search_done(self, thread):
        if self._search_thread is thread:
            self._search_thread = self._search_worker = None

    def _stop_search(self):
        worker, thread = self._search_worker, self._search_thread
        self._search_generation += 1
        if worker is not None:
            worker.stopped = True
        if thread is not None:
            try:
                thread.quit()
                thread.wait(2000)
            except RuntimeError:
                pass
        self._search_thread = self._search_worker = None

    def closeEvent(self, event):
        self._stop_search()
        super().closeEvent(event)

    def _set_result_count(self, count, capped=False, searching=False):
        if searching:
            label = "Match (searching…)"
        elif count is None:
            label = "Match"
        else:
            label = f"Match ({count:,}{'+' if capped else ''})"
        self.results_table.setHorizontalHeaderItem(1, QTableWidgetItem(label))

    def handle_search_results(self, matches, length=1):
        """Each match: its byte offset and the bytes around it."""
        self.matches = sorted(matches)
        self._match_length = max(1, length)
        self._match_index = -1
        table = self.results_table
        table.blockSignals(True)
        # Cleared, so selecting the first result is always a change -- the
        # last search's row 0 may still be selected.
        table.clearSelection()
        table.setRowCount(len(self.matches))
        for row, offset in enumerate(self.matches):
            where = QTableWidgetItem(self._offset_text(offset))
            where.setData(Qt.UserRole, offset)
            where.setToolTip(f"Byte {offset:,} (0x{offset:X})")
            table.setItem(row, 0, where)
            try:
                around = self.source.read(max(0, offset - 4),
                                          max(24, length + 4))
            except Exception:
                around = b''
            table.setItem(row, 1, QTableWidgetItem(printable(around)))
        table.blockSignals(False)
        self._set_result_count(len(self.matches),
                               len(self.matches) >= MAX_MATCHES)
        self._update_find_buttons()
        # Every match on the page, highlighted.
        self.display_current_page()
        if self.matches:
            # Shown directly: inserting rows may have selected row 0
            # already, and selecting it again then signals nothing.
            table.blockSignals(True)
            table.selectRow(0)
            table.blockSignals(False)
            self._result_activated()
        else:
            message.information(self, "Search", "No matches found.")

    def _update_find_buttons(self):
        has = bool(self.matches)
        self.find_prev_button.setEnabled(has)
        self.find_next_button.setEnabled(has)

    def find_next(self):
        self._step(1)

    def find_previous(self):
        self._step(-1)

    def _step(self, direction):
        if not self.matches:
            return
        index = (self._match_index + direction) % len(self.matches)
        self.results_table.selectRow(index)

    def _result_activated(self):
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            return
        item = self.results_table.item(rows[0].row(), 0)
        if item is None:
            return
        self._match_index = rows[0].row()
        self.results_table.scrollToItem(item)
        self.show_bytes(item.data(Qt.UserRole), self._match_length)

    def search_result_clicked(self, item):
        self.results_table.selectRow(item.row())

    def show_bytes(self, offset, length=1):
        """Go to `offset` and select the `length` bytes there -- in the
        theme's selection colour, across lines when they wrap."""
        if self.source is None:
            return
        page = offset // self.page_size()
        if page != self.current_page or not self.hex_table.rowCount():
            self.current_page = page
            self.display_current_page()
        first = self._select_bytes(offset, offset + max(1, length))
        if first is not None:
            self.hex_table.scrollToItem(self.hex_table.item(*first),
                                        QAbstractItemView.PositionAtCenter)

    def navigate_to_address(self, address):
        try:
            self.show_bytes(int(address, 16), 1)
        except ValueError:
            message.warning(self, "Navigation Error", "Invalid address.")

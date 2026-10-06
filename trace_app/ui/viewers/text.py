"""The Text tab: a file as text, or the strings inside it.

A file that is text -- UTF-8, UTF-16 with its byte-order mark, or a
single-byte Western encoding -- is shown as written, line breaks and all.
Anything else shows its strings, as `strings` does: runs of at least four
printable ASCII characters, and the same in UTF-16LE (how Windows stores
text in binaries, the registry and memory), each with the byte offset it
was found at. Show picks either by hand.

Search ignores case; every match on the page is marked, the current one
selected, "3 of 12" beside the field; Enter / F3 for the next, Shift+Enter /
Shift+F3 for the previous. Pages split at line breaks.

Selecting text and resting the pointer on it shows what it decodes to --
Base64, hex, URL encoding, HTML entities, binary, octal -- but only when it
really does decode to readable text; the right-click menu decodes on
request.
"""

import base64
import binascii
import html
import re
import urllib.parse
from enum import Enum

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QKeySequence, QShortcut, QTextCharFormat, \
    QTextCursor
from PySide6.QtWidgets import (QComboBox, QLabel, QLineEdit, QTextEdit,
                               QToolBar, QToolButton, QToolTip, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import fonts, icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.export_button import ExportButton
from trace_app.ui.widgets.context_menus import show_menu
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar, \
    stretch

#: Every match on the page, behind its text (as the Hex tab marks them).
MATCH_COLOUR = QColor(255, 190, 0, 90)
#: Characters to a page, about: a page ends at the next line break.
PAGE_CHARACTERS = 100_000
MIN_STRING = 4
SHOW_AUTO, SHOW_TEXT, SHOW_STRINGS = 'auto', 'text', 'strings'
#: Encoding shown -> (Python codec, byte-order mark length).
_CODECS = {'UTF-8': ('utf-8', 0), 'UTF-16LE': ('utf-16-le', 2),
           'UTF-16BE': ('utf-16-be', 2), 'Windows-1252': ('cp1252', 0),
           'empty': ('utf-8', 0)}
#: A strings line starts '00001A2B  U ' -- the text after these characters.
_STRING_PREFIX = 12


class SearchDirection(Enum):
    NEXT = 1
    PREVIOUS = 2


# --- what the bytes are --------------------------------------------------------------

def _printable_share(text):
    if not text:
        return 1.0
    good = sum(1 for c in text if c.isprintable() or c in '\r\n\t\f')
    return good / len(text)


def decode_text(data):
    """(text, encoding name) when `data` is text, else None."""
    if not data:
        return '', 'empty'
    if data.startswith(b'\xef\xbb\xbf'):
        return data[3:].decode('utf-8', 'replace'), 'UTF-8'
    for bom, codec, name in ((b'\xff\xfe', 'utf-16-le', 'UTF-16LE'),
                             (b'\xfe\xff', 'utf-16-be', 'UTF-16BE')):
        if data.startswith(bom):
            return data[2:].decode(codec, 'replace'), name
    if b'\x00' in data[:4096]:
        return None                   # binary (or BOM-less UTF-16)
    try:
        text = data.decode('utf-8')
        if _printable_share(text[:20000]) >= 0.97:
            return text, 'UTF-8'
    except UnicodeDecodeError:
        pass
    text = data.decode('cp1252', 'replace')
    if _printable_share(text[:20000]) >= 0.97:
        return text, 'Windows-1252'
    return None


_ASCII_RUN = re.compile(rb'[\x20-\x7e\t]{%d,}' % MIN_STRING)
_UTF16_RUN = re.compile(rb'(?:[\x20-\x7e\t]\x00){%d,}' % MIN_STRING)


def extract_strings(data):
    """[(offset, text, 'A' or 'U')] -- ASCII and UTF-16LE strings in file
    order. An ASCII run that is only one letter of a UTF-16 string is not
    listed twice."""
    found = [(m.start(), m.group().decode('utf-16-le'), 'U')
             for m in _UTF16_RUN.finditer(data)]
    wide = [(start, start + len(text) * 2) for start, text, _ in found]
    import bisect
    starts = [w[0] for w in wide]
    for m in _ASCII_RUN.finditer(data):
        index = bisect.bisect_right(starts, m.start()) - 1
        if index >= 0 and wide[index][0] <= m.start() < wide[index][1]:
            continue
        found.append((m.start(), m.group().decode('ascii'), 'A'))
    found.sort()
    return found


class TextViewerManager:
    """The text shown, its pages, and searching it."""

    def __init__(self):
        self.file_content = b''
        self.text_content = ''
        self.description = ''
        self.mode = SHOW_TEXT
        self.page_starts = [0]
        self.current_page = 0
        self.matches = []
        self.match_length = 0
        self.current_match_index = -1
        self.last_search_str = ''
        self.page_changed_callback = None
        self._folded = None
        self.codec, self.bom = 'cp1252', 0

    # --- loading ----------------------------------------------------------------

    def load_text_content(self, file_content, show=SHOW_AUTO):
        self.file_content = bytes(file_content or b'')
        decoded = decode_text(self.file_content) if show != SHOW_STRINGS \
            else None
        if decoded is not None and show != SHOW_STRINGS:
            self.text_content, encoding = decoded
            self.mode = SHOW_TEXT
            self.description = f"Text · {encoding}"
            self.codec, self.bom = _CODECS.get(encoding, ('cp1252', 0))
            if encoding == 'UTF-8' and \
                    self.file_content.startswith(b'\xef\xbb\xbf'):
                self.bom = 3
        elif show == SHOW_TEXT:
            self.text_content = self.file_content.decode('cp1252', 'replace')
            self.mode = SHOW_TEXT
            self.description = "Text · Windows-1252 (not text)"
            self.codec, self.bom = 'cp1252', 0
        else:
            strings = extract_strings(self.file_content)
            self.text_content = '\n'.join(
                f"{offset:08X}  {'U' if kind == 'U' else ' '} {text}"
                for offset, text, kind in strings)
            self.mode = SHOW_STRINGS
            wide = sum(1 for s in strings if s[2] == 'U')
            self.description = (f"Strings · {len(strings):,} "
                                f"({wide:,} UTF-16, marked U)")
        self._folded = None
        self._paginate()
        self.current_page = 0
        self.matches = []
        self.current_match_index = -1
        self.last_search_str = ''

    def byte_range(self, begin, end):
        """(first byte, end byte) in the file of the text's characters
        [begin, end) -- through the encoding the text was read in, or, for
        strings, each line's own offset -- or None."""
        text = self.text_content
        if not text or end <= begin:
            return None
        if self.mode == SHOW_TEXT:
            def at(position):
                return self.bom + len(text[:position].encode(
                    self.codec, 'replace'))
            return at(begin), at(end)

        def at(position, closing):
            start = text.rfind('\n', 0, position) + 1
            line = text[start:text.find('\n', start) if
                        text.find('\n', start) != -1 else len(text)]
            try:
                offset = int(line[:8], 16)
            except ValueError:
                return None
            width = 2 if line[10:11] == 'U' else 1
            column = max(0, min(position - start, len(line)) - _STRING_PREFIX)
            if closing and position - start <= _STRING_PREFIX:
                column = 0
            return offset + column * width
        first, last = at(begin, False), at(end, True)
        if first is None or last is None or last <= first:
            return None
        return first, last

    def _paginate(self):
        """Pages of about PAGE_CHARACTERS, each ending at a line break."""
        text = self.text_content
        starts = [0]
        while starts[-1] + PAGE_CHARACTERS < len(text):
            cut = text.rfind('\n', starts[-1] + PAGE_CHARACTERS // 2,
                             starts[-1] + PAGE_CHARACTERS)
            starts.append(cut + 1 if cut != -1 else
                          starts[-1] + PAGE_CHARACTERS)
        self.page_starts = starts

    def get_total_pages(self):
        return len(self.page_starts)

    def page_range(self, page=None):
        page = self.current_page if page is None else page
        begin = self.page_starts[page]
        end = self.page_starts[page + 1] if page + 1 < len(self.page_starts) \
            else len(self.text_content)
        return begin, end

    def get_text_content_for_current_page(self):
        begin, end = self.page_range()
        return self.text_content[begin:end]

    def page_of(self, position):
        import bisect
        return max(0, bisect.bisect_right(self.page_starts, position) - 1)

    def change_page(self, delta):
        self.go_to_page(self.current_page + delta)

    def go_to_page(self, page):
        page = max(0, min(page, self.get_total_pages() - 1))
        if page != self.current_page:
            self.current_page = page
            if self.page_changed_callback:
                self.page_changed_callback()

    def jump_to_start(self):
        self.go_to_page(0)

    def jump_to_end(self):
        self.go_to_page(self.get_total_pages() - 1)

    # --- searching ----------------------------------------------------------------

    def search_for_string(self, search_str, direction=SearchDirection.NEXT):
        """Step to the next (or previous) match of `search_str`, any case.
        Returns the match's position in the text, or None."""
        if not search_str:
            return None
        if search_str.lower() != self.last_search_str:
            if self._folded is None:
                self._folded = self.text_content.lower()
            needle = search_str.lower()
            self.matches = []
            position = self._folded.find(needle)
            while position != -1:
                self.matches.append(position)
                position = self._folded.find(needle, position + 1)
            self.match_length = len(search_str)
            self.last_search_str = needle
            self.current_match_index = -1
        if not self.matches:
            return None
        step = 1 if direction == SearchDirection.NEXT else -1
        self.current_match_index = \
            (self.current_match_index + step) % len(self.matches)
        position = self.matches[self.current_match_index]
        self.current_page = self.page_of(position)
        return position

    def clear_content(self):
        self.__init__()


class TextViewer(QWidget):
    #: (first byte, end byte, text): bookmark these bytes of the file.
    bookmark_requested = Signal(int, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = TextViewerManager()
        self.manager.page_changed_callback = self.refresh_content
        self._show = SHOW_AUTO
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.setup_toolbar()
        self.setup_text_edit()
        self.setLayout(self.layout)
        align_controls(self.toolbar)
        QShortcut(QKeySequence(Qt.Key_F3), self, self.search_next,
                  context=Qt.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence(Qt.SHIFT | Qt.Key_F3), self,
                  self.search_previous, context=Qt.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence.Find, self, self._focus_search,
                  context=Qt.WidgetWithChildrenShortcut)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.toolbar.setObjectName("compactToolbar")
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        self.first_action = icons.action(icons.UP, "First page", self)
        self.first_action.triggered.connect(self.manager.jump_to_start)
        self.toolbar.addAction(self.first_action)
        self.prev_action = icons.action(icons.BACK, "Previous page", self)
        self.prev_action.triggered.connect(
            lambda: self.manager.change_page(-1))
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
        self.next_action.triggered.connect(
            lambda: self.manager.change_page(1))
        self.toolbar.addAction(self.next_action)
        self.last_action = icons.action(icons.DOWN, "Last page", self)
        self.last_action.triggered.connect(self.manager.jump_to_end)
        self.toolbar.addAction(self.last_action)
        self.toolbar.addSeparator()

        self.toolbar.addWidget(QLabel("Show: "))
        self.show_combo = QComboBox(self)
        self.show_combo.setObjectName("textShow")
        for key, label in ((SHOW_AUTO, "Automatic"), (SHOW_TEXT, "Text"),
                           (SHOW_STRINGS, "Strings")):
            self.show_combo.addItem(label, key)
        self.show_combo.setToolTip(
            "Automatic: text files as text, anything else as the strings "
            "inside it (ASCII and UTF-16, with their offsets)")
        self.show_combo.setFixedWidth(110)
        self.show_combo.currentIndexChanged.connect(self._show_changed)
        self.toolbar.addWidget(self.show_combo)
        self.toolbar.addWidget(QLabel(" Font: "))
        self.font_size_combobox = QComboBox(self)
        self.font_size_combobox.setFixedWidth(64)
        self.font_size_combobox.addItems(
            ["8", "9", "10", "11", "12", "14", "16", "18", "20", "24"])
        self.font_size_combobox.setCurrentText("10")
        self.font_size_combobox.currentTextChanged.connect(
            self.update_font_size)
        self.toolbar.addWidget(self.font_size_combobox)
        self.toolbar.addSeparator()
        self.export_button = ExportButton(self._export_content, "Text View",
                                          self)
        self.toolbar.addWidget(self.export_button)
        self.mode_label = QLabel()
        self.mode_label.setObjectName("textMode")
        self.toolbar.addWidget(self.mode_label)

        self.toolbar.addWidget(stretch())
        self.search_input = QLineEdit(self)
        self.search_input.setObjectName("textSearchField")
        self.search_input.setPlaceholderText("Find text...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(180)
        self.search_input.setMaximumWidth(260)
        self.search_input.returnPressed.connect(self.search_next)
        self.search_input.installEventFilter(self)
        self.toolbar.addWidget(self.search_input)
        self.match_label = QLabel()
        self.match_label.setObjectName("textMatchCount")
        self.match_label.setMinimumWidth(70)
        self.match_label.setAlignment(Qt.AlignCenter)
        self.toolbar.addWidget(self.match_label)
        self.find_prev_button = self._step_button(
            icons.UP, "Previous match (Shift+F3)", self.search_previous)
        self.find_next_button = self._step_button(
            icons.DOWN, "Next match (F3)", self.search_next)
        self.toolbar.addWidget(self.find_prev_button)
        self.toolbar.addWidget(self.find_next_button)
        self.layout.addWidget(self.toolbar)

    def _step_button(self, icon_name, tip, slot):
        button = QToolButton(self)
        icons.apply_to(button, icon_name)
        button.setToolTip(tip)
        button.setAutoRaise(True)
        button.clicked.connect(slot)
        return button

    def setup_text_edit(self):
        self.text_edit = CustomTextEdit(self)
        # A content surface, not an input field (see the themes).
        self.text_edit.setObjectName("textContentView")
        self.text_edit.setReadOnly(True)
        self.text_edit.setLineWrapMode(QTextEdit.NoWrap)
        self.text_edit.setFont(fonts.monospace(10))
        self.layout.addWidget(self.text_edit)

    # --- content ----------------------------------------------------------------

    def display_text_content(self, file_content):
        self.manager.load_text_content(file_content, self._show)
        self.match_label.setText('')
        self.refresh_content()

    def _show_changed(self, *_args):
        self._show = self.show_combo.currentData()
        if self.manager.file_content:
            self.display_text_content(self.manager.file_content)

    def _export_content(self):
        """The page shown, as plain text, for the export button."""
        text = self.text_edit.toPlainText()
        return text if text else None

    def clear_content(self):
        self.text_edit.clear()
        self.manager.clear_content()
        self.manager.page_changed_callback = self.refresh_content
        self.mode_label.setText('')
        self.match_label.setText('')
        self.page_entry.setText('')
        self.total_pages_label.setText("of —")

    def refresh_content(self):
        self.text_edit.setPlainText(
            self.manager.get_text_content_for_current_page())
        self.page_entry.setText(str(self.manager.current_page + 1))
        self.total_pages_label.setText(
            f"of {self.manager.get_total_pages():,}")
        self.mode_label.setText(f"  {self.manager.description}")
        self._mark_matches()

    def update_font_size(self):
        font = self.text_edit.font()
        font.setPointSize(int(self.font_size_combobox.currentText()))
        self.text_edit.setFont(font)

    def go_to_page_by_entry(self):
        try:
            page = int(self.page_entry.text()) - 1
        except ValueError:
            message.warning(self, "Invalid Page",
                            "Please enter a valid page number.")
            return
        if not 0 <= page < self.manager.get_total_pages():
            message.warning(self, "Invalid Page", "Page number out of range.")
            return
        self.manager.go_to_page(page)

    # --- searching ----------------------------------------------------------------

    def eventFilter(self, watched, event):
        from PySide6.QtCore import QEvent
        if watched is self.search_input and event.type() == QEvent.KeyPress \
                and event.key() in (Qt.Key_Return, Qt.Key_Enter) and \
                event.modifiers() & Qt.ShiftModifier:
            self.search_previous()
            return True
        return super().eventFilter(watched, event)

    def _focus_search(self):
        self.search_input.setFocus()
        self.search_input.selectAll()

    def bookmark_selection(self):
        """The selected text, as the bytes of the file it was read from."""
        cursor = self.text_edit.textCursor()
        if not cursor.hasSelection():
            return
        begin, _end = self.manager.page_range()
        found = self.manager.byte_range(begin + cursor.selectionStart(),
                                        begin + cursor.selectionEnd())
        if found is None:
            return
        self.bookmark_requested.emit(
            found[0], found[1],
            cursor.selectedText().replace('\u2029', ' ').strip())

    def search_next(self):
        self._search(SearchDirection.NEXT)

    def search_previous(self):
        self._search(SearchDirection.PREVIOUS)

    def _search(self, direction):
        query = self.search_input.text()
        if not query:
            self.match_label.setText('')
            self._mark_matches()
            return
        page = self.manager.current_page
        position = self.manager.search_for_string(query, direction)
        if position is None:
            self.match_label.setText("No matches")
            self._mark_matches()
            return
        if self.manager.current_page != page:
            self.refresh_content()
        else:
            self._mark_matches()
        self.match_label.setText(
            f"{self.manager.current_match_index + 1:,} of "
            f"{len(self.manager.matches):,}")
        self.update_highlighted_text()

    def update_highlighted_text(self):
        """Select the current match -- in the theme's selection colour --
        and bring it into view."""
        manager = self.manager
        if not manager.matches or manager.current_match_index < 0:
            return
        begin, _end = manager.page_range()
        start = manager.matches[manager.current_match_index] - begin
        cursor = self.text_edit.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(start + manager.match_length,
                           QTextCursor.KeepAnchor)
        self.text_edit.setTextCursor(cursor)
        self.text_edit.ensureCursorVisible()
        # In the middle of the view, not on its edge.
        bar = self.text_edit.verticalScrollBar()
        rect = self.text_edit.cursorRect()
        bar.setValue(bar.value() + rect.center().y() -
                     self.text_edit.viewport().height() // 2)

    def _mark_matches(self):
        """Every match on the page marked, without touching the text."""
        manager = self.manager
        marks = []
        if manager.matches and self.search_input.text():
            begin, end = manager.page_range()
            document = self.text_edit.document()
            fill = QTextCharFormat()
            fill.setBackground(MATCH_COLOUR)
            import bisect
            first = bisect.bisect_left(manager.matches, begin)
            for position in manager.matches[first:]:
                if position >= end:
                    break
                selection = QTextEdit.ExtraSelection()
                cursor = QTextCursor(document)
                cursor.setPosition(position - begin)
                cursor.setPosition(min(position - begin +
                                       manager.match_length, end - begin),
                                   QTextCursor.KeepAnchor)
                selection.cursor = cursor
                selection.format = fill
                marks.append(selection)
        self.text_edit.setExtraSelections(marks)


# --- decoding a selection --------------------------------------------------------------

def _readable(text):
    return bool(text) and text.strip() and _printable_share(text) >= 0.9


def decode_selection(text):
    """[(kind, decoded)] for every way the selection really decodes to
    readable text that differs from it -- empty when it is just text."""
    text = text.replace(' ', '\n').strip()
    if len(text) < 4:
        return []
    found = []
    compact = re.sub(r'\s+', '', text)
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', compact) and \
            len(compact) % 4 == 0 and len(compact) >= 8:
        try:
            decoded = base64.b64decode(compact, validate=True).decode('utf-8')
            if _readable(decoded):
                found.append(("Base64", decoded))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    hexed = re.sub(r'(0x|\\x|[\s:,-])', '', text, flags=re.I)
    if re.fullmatch(r'[0-9A-Fa-f]+', hexed) and len(hexed) % 2 == 0 and \
            len(hexed) >= 8:
        try:
            decoded = bytes.fromhex(hexed).decode('utf-8')
            if _readable(decoded):
                found.append(("Hex", decoded))
        except (ValueError, UnicodeDecodeError):
            pass
    if re.search(r'%[0-9A-Fa-f]{2}', text):
        decoded = urllib.parse.unquote_plus(text)
        if decoded != text and _readable(decoded):
            found.append(("URL encoding", decoded))
    if re.search(r'&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z]+);', text):
        decoded = html.unescape(text)
        if decoded != text and _readable(decoded):
            found.append(("HTML entities", decoded))
    groups = text.split()
    if groups and all(re.fullmatch(r'[01]{8}', g) for g in groups):
        decoded = ''.join(chr(int(g, 2)) for g in groups)
        if _readable(decoded):
            found.append(("Binary", decoded))
    if groups and all(re.fullmatch(r'[0-7]{3}', g) for g in groups):
        decoded = ''.join(chr(int(g, 8)) for g in groups)
        if _readable(decoded):
            found.append(("Octal", decoded))
    return found


class CustomTextEdit(QTextEdit):
    DECODINGS = ("Base64", "Hex", "URL encoding", "HTML entities", "Binary",
                 "Octal")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setMouseTracking(True)
        self._hint_for = None

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        selected = self.textCursor().selectedText()
        viewer = self.parent()
        if selected and hasattr(viewer, 'bookmark_selection'):
            menu.addSeparator()
            menu.addAction("Bookmark Selection…").triggered.connect(
                viewer.bookmark_selection)
        if selected:
            menu.addSeparator()
            decoded = dict(decode_selection(selected))
            for kind in self.DECODINGS:
                action = menu.addAction(f"Decode {kind}")
                action.setEnabled(kind in decoded)
                action.triggered.connect(
                    lambda _c=False, k=kind, d=decoded:
                    self._show_decoded(k, d.get(k)))
        show_menu(menu, event.globalPos(), view=False)

    def _show_decoded(self, kind, decoded):
        QToolTip.showText(self.mapToGlobal(self.cursorRect().bottomLeft()),
                          f"{kind}:\n{decoded}" if decoded else
                          f"Not {kind}", self)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        selected = self.textCursor().selectedText()
        if not selected:
            if self._hint_for is not None:
                QToolTip.hideText()
                self._hint_for = None
            return
        # Over the selection only, and only when it decodes to something
        # else: it used to echo the selected text back on every move.
        cursor = self.cursorForPosition(event.position().toPoint())
        inside = self.textCursor().selectionStart() <= cursor.position() \
            <= self.textCursor().selectionEnd()
        decoded = decode_selection(selected) if inside else []
        if not decoded:
            if self._hint_for is not None:
                QToolTip.hideText()
                self._hint_for = None
            return
        if self._hint_for != selected:
            self._hint_for = selected
            QToolTip.showText(
                event.globalPosition().toPoint(),
                '\n\n'.join(f"{kind}: {value[:500]}"
                            for kind, value in decoded), self)

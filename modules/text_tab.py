from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel
from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
from enum import Enum
import codecs
import chardet
import re

class SearchDirection(Enum):
    NEXT = 1
    PREVIOUS = 2


class TextViewerManager:
    PAGE_SIZE = 2000

    def __init__(self):
        self.file_content = b""  # Store raw byte content
        self.text_content = ""  # This will store the extracted strings
        self.current_page = 0
        self.encoding = 'utf-8'
        self.last_search_str = ""
        self.current_match_index = -1
        self.page_changed_callback = None

        self.matches = []

    def detect_encoding(self, file_content_chunk):
        detector = chardet.detect(file_content_chunk)
        encoding = detector.get('encoding')
        return encoding if encoding else 'utf-8'

    def extract_strings_from_content(self):
        # Attempt to decode with UTF-8, fallback to UTF-16 if it fails
        try:
            text = self.file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text = self.file_content.decode('utf-16')
            except:
                text = self.file_content.decode('ISO-8859-1')  # Fallback to ISO-8859-1 if both UTF-8 and UTF-16 fail

        # Use regex to extract sequences of printable characters (length >= 4)
        strings = re.findall(r"[ -~]{4,}", text)

        # Join the strings with newlines to store them
        self.text_content = "\n".join(strings)

    def load_text_content(self, file_content):
        self.file_content = file_content
        self.extract_strings_from_content()  # Extract printable strings
        self.current_page = 0

    def get_text_content_for_current_page(self):
        start_idx = self.current_page * self.PAGE_SIZE
        end_idx = (self.current_page + 1) * self.PAGE_SIZE
        return self.text_content[start_idx:end_idx]
    # def change_page(self, delta):
    #     new_page = self.current_page + delta
    #     if 0 <= new_page * self.PAGE_SIZE < len(self.file_content):
    #         self.current_page = new_page
    #
    # def jump_to_start(self):
    #     self.current_page = 0
    #
    # def jump_to_end(self):
    #     self.current_page = len(self.file_content) // self.PAGE_SIZE

    def change_page(self, delta):
        new_page = self.current_page + delta
        if 0 <= new_page * self.PAGE_SIZE < len(self.text_content):
            self.current_page = new_page
            if self.page_changed_callback:
                self.page_changed_callback()

    def jump_to_start(self):
        self.current_page = 0
        if self.page_changed_callback:
            self.page_changed_callback()

    def jump_to_end(self):
        self.current_page = len(self.text_content) // self.PAGE_SIZE
        if self.page_changed_callback:
            self.page_changed_callback()

    def search_for_string(self, search_str, direction=SearchDirection.NEXT):
        if not search_str:  # If search string is empty, do nothing
            return

        current_text = self.get_text_content_for_current_page()

        # Try to search in the current page first
        if direction == SearchDirection.NEXT:
            next_match = current_text.find(search_str)
        else:
            next_match = current_text.rfind(search_str)

        if next_match != -1:
            self.matches.append(next_match)
            self.current_match_index += 1
        else:
            # If not found in the current page, search in the entire content
            decoded_content = self.file_content.decode(self.encoding, errors='replace')
            if direction == SearchDirection.NEXT:
                next_match = decoded_content.find(search_str)
            else:
                next_match = decoded_content.rfind(search_str)

            if next_match != -1:
                self.matches = [next_match]
                self.current_match_index = 0

        if self.matches:
            match_position = self.matches[self.current_match_index]
            self.current_page = match_position // self.PAGE_SIZE

    def clear_content(self):
        self.file_content = b""
        self.current_page = 0
        self.last_search_str = ""
        self.current_match_index = -1
        self.matches = []



class TextViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = TextViewerManager()

        self.manager.page_changed_callback = self.refresh_content

        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        self.setup_toolbar()
        self.setup_text_edit()

        self.setLayout(self.layout)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")

        actions_data = [
            ("icons8-thick-arrow-pointing-up-50.png", 'Jump to Start', self.manager.jump_to_start),
            ("icons8-left-arrow-50.png", 'Previous Page', lambda: self.manager.change_page(-1)),
            ("icons8-right-arrow-50.png", 'Next Page', lambda: self.manager.change_page(1)),
            ("icons8-down-50.png", 'Jump to End', self.manager.jump_to_end),
            ("icons8-left-arrow-50.png", 'Search Previous',
             lambda: self.manager.search_for_string(self.search_input.text(), SearchDirection.PREVIOUS)),
            ("icons8-right-arrow-50.png", 'Search Next',
             lambda: self.manager.search_for_string(self.search_input.text(), SearchDirection.NEXT)),
        ]

        for icon_name, text, handler in actions_data:
            action = QAction(QIcon(f"gui/nav_icons/{icon_name}"), text, self)
            action.triggered.connect(handler)
            self.toolbar.addAction(action)

        self.toolbar.addWidget(QLabel("Font Size: "))

        self.font_size_combobox = QComboBox(self)
        self.font_size_combobox.addItems(["8", "10", "12", "14", "16", "18", "20", "24", "28", "32", "36"])
        self.font_size_combobox.currentTextChanged.connect(self.update_font_size)
        self.toolbar.addWidget(self.font_size_combobox)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.toolbar.addWidget(spacer)

        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Search...")
        self.search_input.setMaximumWidth(200)
        self.search_input.setContentsMargins(10, 0, 10, 0)
        self.search_input.returnPressed.connect(self.perform_search)
        self.toolbar.addWidget(self.search_input)

        self.layout.addWidget(self.toolbar)

    def setup_text_edit(self):
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

    def display_text_content(self, file_content):
        self.manager.load_text_content(file_content)
        text_content = self.manager.get_text_content_for_current_page()
        self.text_edit.setPlainText(text_content)

    def clear_content(self):
        self.text_edit.clear()
        self.manager.clear_content()

    def search_prev(self):
        self.manager.search_for_string(self.search_input.text(), SearchDirection.PREVIOUS)
        self.update_highlighted_text()

    def search_next(self):
        self.manager.search_for_string(self.search_input.text(), SearchDirection.NEXT)
        self.update_highlighted_text()


    def update_highlighted_text(self):
        if not self.manager.matches or not (0 <= self.manager.current_match_index < len(self.manager.matches)):
            return

        cursor = self.text_edit.textCursor()
        cursor.clearSelection()

        start_pos = self.manager.matches[self.manager.current_match_index] % self.manager.PAGE_SIZE
        end_pos = start_pos + len(self.search_input.text())

        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor("yellow"))

        cursor.setPosition(start_pos, QTextCursor.MoveAnchor)
        cursor.setPosition(end_pos, QTextCursor.KeepAnchor)
        cursor.setCharFormat(highlight_format)
    def perform_search(self):
        self.search_next()

    def update_font_size(self):
        selected_size = int(self.font_size_combobox.currentText())
        current_font = self.text_edit.font()
        current_font.setPointSize(selected_size)
        self.text_edit.setFont(current_font)

    def refresh_content(self):
        text_content = self.manager.get_text_content_for_current_page()
        self.text_edit.setPlainText(text_content)
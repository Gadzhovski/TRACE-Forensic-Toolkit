from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel, \
    QMessageBox
from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
from enum import Enum
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

    def get_total_pages(self):
        return (len(self.text_content) - 1) // self.PAGE_SIZE + 1

    @staticmethod
    def detect_encoding(file_content_chunk):
        detector = chardet.detect(file_content_chunk)
        encoding = detector.get('encoding')
        return encoding if encoding else 'utf-8'

    def extract_strings_from_content(self):
        encoding = self.detect_encoding(self.file_content[:1024])  # Detect encoding based on the first 1024 bytes
        try:
            text = self.file_content.decode(encoding)
        except UnicodeDecodeError:
            text = self.file_content.decode('ISO-8859-1')  # Fallback to ISO-8859-1 if decoding fails

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

        # Only find all occurrences of the search string if the search string has changed
        if self.last_search_str != search_str:
            self.matches = []
            self.current_match_index = -1

            # Find all occurrences of the search string in the text content
            start_idx = 0
            while start_idx < len(self.text_content):
                idx = self.text_content.find(search_str, start_idx)
                if idx == -1:
                    break
                self.matches.append(idx)
                start_idx = idx + len(search_str)  # Update the start index to the end of the current match

            self.last_search_str = search_str

        # If no matches were found, return
        if not self.matches:
            return

        # Update the current match index based on the search direction
        if direction == SearchDirection.NEXT:
            self.current_match_index = (self.current_match_index + 1) % len(self.matches)
        else:
            self.current_match_index = (self.current_match_index - 1) % len(self.matches)

        # Update the current page to the page containing the current match
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
        ]

        for icon_name, text, handler in actions_data:
            action = QAction(QIcon(f"gui/nav_icons/{icon_name}"), text, self)
            action.triggered.connect(handler)
            self.toolbar.addAction(action)

        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setPlaceholderText("1")
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)

        self.total_pages_label = QLabel(self)
        self.toolbar.addWidget(self.total_pages_label)

        actions_data = [
            ("icons8-right-arrow-50.png", 'Next Page', lambda: self.manager.change_page(1)),
            ("icons8-down-50.png", 'Jump to End', self.manager.jump_to_end),
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
        self.search_input.returnPressed.connect(self.search_next)
        self.toolbar.addWidget(self.search_input)

        self.layout.addWidget(self.toolbar)

    def setup_text_edit(self):
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

    def display_text_content(self, file_content):
        self.manager.load_text_content(file_content)
        self.refresh_content()

    def clear_content(self):
        self.text_edit.clear()
        self.manager.clear_content()

    def search_next(self):
        # Call the search_for_string method with the updated match index
        self.manager.search_for_string(self.search_input.text(), SearchDirection.NEXT)

        # Update the highlighted text to highlight the current match
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

    def update_font_size(self):
        selected_size = int(self.font_size_combobox.currentText())
        current_font = self.text_edit.font()
        current_font.setPointSize(selected_size)
        self.text_edit.setFont(current_font)

    def go_to_page_by_entry(self):
        try:
            page_num = int(self.page_entry.text()) - 1
            if 0 <= page_num < self.manager.get_total_pages():
                self.manager.current_page = page_num
                self.refresh_content()
            else:
                QMessageBox.warning(self, "Invalid Page", "Page number out of range.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Page", "Please enter a valid page number.")

    def refresh_content(self):
        text_content = self.manager.get_text_content_for_current_page()
        self.text_edit.setPlainText(text_content)
        current_page = self.manager.current_page + 1  # Pages start from 1
        total_pages = self.manager.get_total_pages()
        self.page_entry.setText(str(current_page))
        self.total_pages_label.setText(f" of {total_pages}")

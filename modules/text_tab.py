# from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel, \
#     QTabWidget
# from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
#
#
# class TextViewerManager:
#     PAGE_SIZE = 2000
#
#     def __init__(self):
#         self.text_content = ""
#         self.current_page = 0
#         self.last_search_str = ""
#         self.current_match_index = -1
#         self.matches = []
#
#     def load_text_content(self, file_content):
#         text_content = file_content.decode('utf-8', errors='ignore')
#         self.text_content = text_content
#         self.current_page = 0
#
#     def get_text_content_for_current_page(self):
#         start_idx = self.current_page * self.PAGE_SIZE
#         end_idx = (self.current_page + 1) * self.PAGE_SIZE
#         return self.text_content[start_idx:end_idx]
#
#     def next_page(self):
#         if (self.current_page + 1) * self.PAGE_SIZE < len(self.text_content):
#             self.current_page += 1
#
#     def prev_page(self):
#         if self.current_page > 0:
#             self.current_page -= 1
#
#     def jump_to_start(self):
#         self.current_page = 0
#
#     def jump_to_end(self):
#         self.current_page = len(self.text_content) // self.PAGE_SIZE
#
#     def search_for_string(self, search_str, direction="next"):
#         if not search_str:  # If search string is empty, do nothing
#             return
#
#         if search_str != self.last_search_str:
#             # New search string, so reset matches and current index
#             self.matches = []
#             self.current_match_index = -1
#             self.last_search_str = search_str
#
#         # Search direction: next
#         if direction == "next":
#             # Start searching from the position after the last found match
#             start_pos = self.matches[self.current_match_index] + 1 if self.matches else 0
#             next_match = self.text_content.find(search_str, start_pos)
#
#             if next_match != -1:
#                 self.matches.append(next_match)
#                 self.current_match_index += 1
#             else:
#                 # If no more matches, wrap the search from the beginning
#                 next_match = self.text_content.find(search_str)
#
#                 if next_match != -1:
#                     self.matches = [next_match]
#                     self.current_match_index = 0
#
#         # Search direction: previous
#         elif direction == "prev":
#             # Start searching backward from the position before the last found match
#             end_pos = self.matches[self.current_match_index] - 1 if self.matches else len(self.text_content) - 1
#             prev_match = self.text_content.rfind(search_str, 0, end_pos)
#
#             if prev_match != -1:
#                 self.matches.insert(0, prev_match)
#                 self.current_match_index = 0
#             else:
#                 # If no more matches, wrap the search from the end
#                 prev_match = self.text_content.rfind(search_str)
#
#                 if prev_match != -1:
#                     self.matches = [prev_match]
#                     self.current_match_index = 0
#
#         if self.matches:
#             match_position = self.matches[self.current_match_index]
#             self.current_page = match_position // self.PAGE_SIZE
#
#     def clear_content(self):
#         self.text_content = ""
#         self.current_page = 0
#         self.last_search_str = ""
#         self.current_match_index = -1
#         self.matches = []
#
# class TextViewer(QWidget):
#     def __init__(self, parent=None):
#         super().__init__(parent)
#         self.manager = TextViewerManager()
#         self.init_ui()
#
#     def init_ui(self):
#         self.layout = QVBoxLayout(self)
#         self.layout.setContentsMargins(0, 0, 0, 0)
#         self.layout.setSpacing(0)
#
#         # Set up toolbar
#         self.toolbar = QToolBar(self)
#         self.toolbar.setContentsMargins(0, 0, 0, 0)
#         self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")
#         self.layout.addWidget(self.toolbar)
#
#         # Add toolbar buttons for paging
#         self.jump_to_start_action = QAction(QIcon("gui/icons/go-up.png"), 'Jump to Start', self)
#         self.toolbar.addAction(self.jump_to_start_action)
#
#         self.prev_page_action = QAction(QIcon("gui/icons/go-previous.png"), 'Previous Page', self)
#         self.toolbar.addAction(self.prev_page_action)
#
#         self.next_page_action = QAction(QIcon("gui/icons/go-next.png"), 'Next Page', self)
#         self.toolbar.addAction(self.next_page_action)
#
#         self.jump_to_end_action = QAction(QIcon("gui/icons/go-down.png"), 'Jump to End', self)
#         self.toolbar.addAction(self.jump_to_end_action)
#
#         # Add label for font size
#         self.toolbar.addWidget(QLabel("Font Size: "))
#
#         # Add font size combobox
#         self.font_size_combobox = QComboBox(self)
#         self.font_size_combobox.addItems(["8", "10", "12", "14", "16", "18", "20", "24", "28", "32", "36"])
#         # self.font_size_combobox.setCurrentText("10")  # Default font size
#         self.font_size_combobox.currentTextChanged.connect(self.update_font_size)
#         self.toolbar.addWidget(self.font_size_combobox)
#
#         # Add spacer to push search input to the right
#         spacer = QWidget(self)
#         spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
#         self.toolbar.addWidget(spacer)
#
#         # Add search buttons
#         self.search_prev_action = QAction(QIcon("gui/icons/go-previous.png"), 'Search Previous', self)
#         self.toolbar.addAction(self.search_prev_action)
#
#         self.search_next_action = QAction(QIcon("gui/icons/go-next.png"), 'Search Next', self)
#         self.toolbar.addAction(self.search_next_action)
#
#         # Add search input
#         self.search_input = QLineEdit(self)
#         self.search_input.setPlaceholderText("Search...")
#         self.search_input.setMaximumWidth(200)
#         self.search_input.setContentsMargins(10, 0, 10, 0)
#         self.search_input.returnPressed.connect(self.perform_search)
#         self.toolbar.addWidget(self.search_input)
#
#         # Text edit to display content
#         self.text_edit = QTextEdit(self)
#         self.text_edit.setReadOnly(True)
#         self.layout.addWidget(self.text_edit)
#
#         self.setLayout(self.layout)
#
#         # Connect toolbar actions to functions
#         self.jump_to_start_action.triggered.connect(self.manager.jump_to_start)
#         self.prev_page_action.triggered.connect(self.manager.prev_page)
#         self.next_page_action.triggered.connect(self.manager.next_page)
#         self.jump_to_end_action.triggered.connect(self.manager.jump_to_end)
#         self.search_prev_action.triggered.connect(self.search_prev)
#         self.search_next_action.triggered.connect(self.search_next)
#
#     def display_text_content(self, file_content):
#         # Use the manager to load and display text content
#         self.manager.load_text_content(file_content)
#         text_content = self.manager.get_text_content_for_current_page()
#         self.text_edit.setPlainText(text_content)
#
#     def clear_content(self):
#         self.text_edit.clear()
#         self.manager.clear_content()
#
#     def search_prev(self):
#         search_str = self.search_input.text()
#         self.manager.search_for_string(search_str, direction="prev")
#         self.update_highlighted_text()
#
#     def search_next(self):
#         search_str = self.search_input.text()
#         self.manager.search_for_string(search_str, direction="next")
#         self.update_highlighted_text()
#
#     def update_highlighted_text(self):
#         # Clear any previous highlights
#         cursor = self.text_edit.textCursor()
#         cursor.select(QTextCursor.Document)
#         cursor.setCharFormat(QTextCharFormat())
#         cursor.clearSelection()
#
#         # Calculate start and end positions of the current match
#         if self.manager.matches and 0 <= self.manager.current_match_index < len(self.manager.matches):
#             start_pos = self.manager.matches[self.manager.current_match_index] % self.manager.PAGE_SIZE
#             end_pos = start_pos + len(self.search_input.text())
#
#             # Highlight the current match
#             highlight_format = QTextCharFormat()
#             highlight_format.setBackground(QColor("yellow"))
#
#             cursor.setPosition(start_pos, QTextCursor.MoveAnchor)
#             cursor.setPosition(end_pos, QTextCursor.KeepAnchor)
#             cursor.setCharFormat(highlight_format)
#
#     def perform_search(self):
#         self.search_next()
#
#     def update_font_size(self):
#         selected_size = int(self.font_size_combobox.currentText())
#         current_font = self.text_edit.font()
#         current_font.setPointSize(selected_size)
#         self.text_edit.setFont(current_font)


from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel
from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
from enum import Enum
import codecs
import chardet


class SearchDirection(Enum):
    NEXT = 1
    PREVIOUS = 2


class TextViewerManager:
    PAGE_SIZE = 2000

    def __init__(self):
        self.text_content = ""
        self.current_page = 0
        self.last_search_str = ""
        self.current_match_index = -1
        self.matches = []

    def detect_encoding(self, file_content):
        detector = chardet.universaldetector.UniversalDetector()
        for line in file_content.splitlines():
            detector.feed(line)
            if detector.done:
                break
        detector.close()
        encoding = detector.result['encoding']
        return encoding if encoding else 'utf-8'  # Provide a default encoding (e.g., utf-8) when detection fails

    def load_text_content(self, file_content):
        encoding = self.detect_encoding(file_content)
        text_content = file_content.decode(encoding, errors='replace')
        self.text_content = text_content
        self.current_page = 0

    def get_text_content_for_current_page(self):
        start_idx = self.current_page * self.PAGE_SIZE
        end_idx = (self.current_page + 1) * self.PAGE_SIZE
        return self.text_content[start_idx:end_idx]

    def change_page(self, delta):
        new_page = self.current_page + delta
        if 0 <= new_page * self.PAGE_SIZE < len(self.text_content):
            self.current_page = new_page

    def jump_to_start(self):
        self.current_page = 0

    def jump_to_end(self):
        self.current_page = len(self.text_content) // self.PAGE_SIZE

    def search_for_string(self, search_str, direction=SearchDirection.NEXT):
        if not search_str:  # If search string is empty, do nothing
            return

        if search_str != self.last_search_str:
            # New search string, so reset matches and current index
            self.matches = []
            self.current_match_index = -1
            self.last_search_str = search_str

        if direction == SearchDirection.NEXT:
            start_pos = self.matches[self.current_match_index] + 1 if self.matches else 0
            next_match = self.text_content.find(search_str, start_pos)
        else:
            end_pos = self.matches[self.current_match_index] - 1 if self.matches else len(self.text_content) - 1
            next_match = self.text_content.rfind(search_str, 0, end_pos)

        if next_match != -1:
            self.matches.append(next_match)
            self.current_match_index += 1
        else:
            if direction == SearchDirection.NEXT:
                next_match = self.text_content.find(search_str)
            else:
                next_match = self.text_content.rfind(search_str)

            if next_match != -1:
                self.matches = [next_match]
                self.current_match_index = 0

        if self.matches:
            match_position = self.matches[self.current_match_index]
            self.current_page = match_position // self.PAGE_SIZE

    def clear_content(self):
        self.text_content = ""
        self.current_page = 0
        self.last_search_str = ""
        self.current_match_index = -1
        self.matches = []


class TextViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = TextViewerManager()
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
            ("go-up.png", 'Jump to Start', self.manager.jump_to_start),
            ("go-previous.png", 'Previous Page', lambda: self.manager.change_page(-1)),
            ("go-next.png", 'Next Page', lambda: self.manager.change_page(1)),
            ("go-down.png", 'Jump to End', self.manager.jump_to_end),
            ("go-previous.png", 'Search Previous',
             lambda: self.manager.search_for_string(self.search_input.text(), SearchDirection.PREVIOUS)),
            ("go-next.png", 'Search Next',
             lambda: self.manager.search_for_string(self.search_input.text(), SearchDirection.NEXT)),
        ]

        for icon_name, text, handler in actions_data:
            action = QAction(QIcon(f"gui/icons/{icon_name}"), text, self)
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
        cursor = self.text_edit.textCursor()
        cursor.select(QTextCursor.Document)
        cursor.setCharFormat(QTextCharFormat())
        cursor.clearSelection()

        if self.manager.matches and 0 <= self.manager.current_match_index < len(self.manager.matches):
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

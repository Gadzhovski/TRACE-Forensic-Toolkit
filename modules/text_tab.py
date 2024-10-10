import base64
import html
import re
import sqlite3
import urllib
import urllib.parse
from enum import Enum
from functools import partial

import chardet
from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel, \
    QMessageBox, QToolTip


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

        actions_data = [
            ("icons8-thick-arrow-pointing-up-50.png", 'Jump to Start', self.manager.jump_to_start),
            ("icons8-left-arrow-50.png", 'Previous Page', lambda: self.manager.change_page(-1)),
        ]

        for icon_name, text, handler in actions_data:
            action = QAction(QIcon(f"Icons/{icon_name}"), text, self)
            action.triggered.connect(handler)
            self.toolbar.addAction(action)

        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setPlaceholderText("1")
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)

        self.total_pages_label = QLabel(" of ")
        self.toolbar.addWidget(self.total_pages_label)

        actions_data = [
            ("icons8-right-arrow-50.png", 'Next Page', lambda: self.manager.change_page(1)),
            ("icons8-down-50.png", 'Jump to End', self.manager.jump_to_end),
        ]

        for icon_name, text, handler in actions_data:
            action = QAction(QIcon(f"Icons/{icon_name}"), text, self)
            action.triggered.connect(handler)
            self.toolbar.addAction(action)

        # add spacer
        spacer = QWidget(self)
        spacer.setFixedSize(50, 0)
        self.toolbar.addWidget(spacer)

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
        self.search_input.setFixedHeight(35)
        self.search_input.setContentsMargins(10, 0, 10, 0)
        self.search_input.returnPressed.connect(self.search_next)
        self.toolbar.addWidget(self.search_input)

        self.layout.addWidget(self.toolbar)

    def setup_text_edit(self):
        self.text_edit = CustomTextEdit(self)
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


class CustomTextEdit(QTextEdit):
    def __init__(self, *args, **kwargs):
        super(CustomTextEdit, self).__init__(*args, **kwargs)
        self.setMouseTracking(True)

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        menu.addSeparator()

        # Define all decoding actions
        decoding_actions = {
            "Decode Base64": self.decodeBase64,
            "Decode Hex": self.decodeHex,
            "Decode URL": self.decodeURL,
            "Decode HTML": self.decodeHTML,
            "Decode Octal": self.decodeOctal,
            "Decode Binary": self.decodeBinary,
        }

        for action_text, method in decoding_actions.items():
            action = menu.addAction(action_text)
            action.triggered.connect(partial(method))

        menu.exec(event.globalPos())

    def decodeBase64(self):
        self.decodeSelectedText('base64')

    def decodeHex(self):
        self.decodeSelectedText('hex')

    def decodeURL(self):
        self.decodeSelectedText('url')

    def decodeHTML(self):
        self.decodeSelectedText('html')

    def decodeOctal(self):
        self.decodeSelectedText('octal')

    def decodeBinary(self):
        self.decodeSelectedText('binary')

    def decodeSelectedText(self, encoding_type):
        selected_text = self.textCursor().selectedText()
        try:
            if encoding_type == 'base64':
                decoded_bytes = base64.b64decode(selected_text)
            elif encoding_type == 'hex':
                decoded_bytes = bytes.fromhex(selected_text)
            elif encoding_type == 'url':
                decoded_text = urllib.parse.unquote_plus(selected_text)
                QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), decoded_text)
                return
            elif encoding_type == 'html':
                decoded_text = html.unescape(selected_text)
                QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), decoded_text)
                return
            elif encoding_type == 'octal':
                decoded_text = ''.join(chr(int(octal, 8)) for octal in selected_text.split())
                QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), decoded_text)
                return
            elif encoding_type == 'binary':
                decoded_text = ''.join(chr(int(i, 2)) for i in selected_text.split())
                QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), decoded_text)
                return

            if encoding_type in ['base64', 'hex']:
                decoded_text = decoded_bytes.decode('utf-8')
                QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), decoded_text)



        except Exception as e:
            QToolTip.showText(self.mapToGlobal(self.cursorRect().topLeft()), f"Invalid {encoding_type.upper()}")

    def getDecodedText(self, selected_text):
        # Attempt decoding in various formats
        decoders = [
            self.tryDecodeBinary,
            self.tryDecodeOctal,
            self.tryDecodeBase64,
            self.tryDecodeHex,
            self.tryDecodeURL,
            self.tryDecodeHTML
        ]
        for decoder in decoders:
            decoded_text = decoder(selected_text)
            if decoded_text:
                return decoded_text
        return None

    def tryDecodeBase64(self, text):
        try:
            decoded_bytes = base64.b64decode(text, validate=True)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def tryDecodeHex(self, text):
        try:
            decoded_bytes = bytes.fromhex(text)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def tryDecodeURL(self, text):
        try:
            return urllib.parse.unquote_plus(text)
        except Exception:
            return None

    def tryDecodeHTML(self, text):
        try:
            return html.unescape(text)
        except Exception:
            return None

    def tryDecodeOctal(self, text):
        try:
            return ''.join(chr(int(octal, 8)) for octal in text.split())
        except Exception:
            return None

    def tryDecodeBinary(self, text):
        try:
            decoded_text = ''.join(chr(int(i, 2)) for i in text.split())

            return decoded_text
        except Exception:
            return None

    def mouseMoveEvent(self, event):
        super(CustomTextEdit, self).mouseMoveEvent(event)
        # Check if there's selected text
        selected_text = self.textCursor().selectedText()
        if selected_text:
            tooltip_text = self.getDecodedText(selected_text)
            if tooltip_text:
                QToolTip.showText(event.globalPos(), tooltip_text)
        else:
            QToolTip.hideText()  # Hide any existing tooltip if there's no selection





##### new implementation with problems #####
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
#     def get_total_pages(self):
#         return (len(self.text_content) - 1) // self.PAGE_SIZE + 1
#
#
#     def detect_encoding(self, file_content):
#         detector = chardet.universaldetector.UniversalDetector()
#         for line in file_content.splitlines():
#             detector.feed(line)
#             if detector.done:
#                 break
#         detector.close()
#         encoding = detector.result['encoding']
#         return encoding if encoding else 'utf-8'  # Provide a default encoding (e.g., utf-8) when detection fails
#
#     def load_text_content(self, file_content):
#         encoding = self.detect_encoding(file_content)
#         text_content = file_content.decode(encoding, errors='replace')
#         self.text_content = text_content
#         self.current_page = 0
#
#     def get_text_content_for_current_page(self):
#         start_idx = self.current_page * self.PAGE_SIZE
#         end_idx = (self.current_page + 1) * self.PAGE_SIZE
#         return self.text_content[start_idx:end_idx]
#
#     def change_page(self, delta):
#         new_page = self.current_page + delta
#         if 0 <= new_page * self.PAGE_SIZE < len(self.text_content):
#             self.current_page = new_page
#
#     def jump_to_start(self):
#         self.current_page = 0
#
#     def jump_to_end(self):
#         self.current_page = len(self.text_content) // self.PAGE_SIZE
#
#     def search_for_string(self, search_str, direction=SearchDirection.NEXT):
#         if not search_str:  # If search string is empty, do nothing
#             return
#
#         if search_str != self.last_search_str:
#             # New search string, so reset matches and current index
#             self.matches = []
#             self.current_match_index = -1
#             self.last_search_str = search_str
#
#         if direction == SearchDirection.NEXT:
#             start_pos = self.matches[self.current_match_index] + 1 if self.matches else 0
#             next_match = self.text_content.find(search_str, start_pos)
#         else:
#             end_pos = self.matches[self.current_match_index] - 1 if self.matches else len(self.text_content) - 1
#             next_match = self.text_content.rfind(search_str, 0, end_pos)
#
#         if next_match != -1:
#             self.matches.append(next_match)
#             self.current_match_index += 1
#         else:
#             if direction == SearchDirection.NEXT:
#                 next_match = self.text_content.find(search_str)
#             else:
#                 next_match = self.text_content.rfind(search_str)
#
#             if next_match != -1:
#                 self.matches = [next_match]
#                 self.current_match_index = 0
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

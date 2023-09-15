
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QWidget, QVBoxLayout,
                               QLineEdit, QTableWidget, QHeaderView, QTableWidgetItem)

from managers.hex_viewer_manager import HexFormatter


class HexViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hex_formatter = None
        self.current_page = 0
        self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        self.setup_toolbar()
        self.layout.addWidget(self.toolbar)
        self.setup_hex_table()
        self.layout.addWidget(self.hex_table)
        self.setLayout(self.layout)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")

        # Navigation buttons
        self.first_action = QAction(QIcon("gui/icons/go-up.png"), "First", self)
        self.first_action.triggered.connect(self.load_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("gui/icons/go-previous.png"), "Previous", self)
        self.prev_action.triggered.connect(self.previous_page)
        self.toolbar.addAction(self.prev_action)

        # Page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setAlignment(Qt.AlignRight)
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)

        # Total pages label
        self.total_pages_label = QLabel(" of ")
        self.toolbar.addWidget(self.total_pages_label)

        self.next_action = QAction(QIcon("gui/icons/go-next.png"), "Next", self)
        self.next_action.triggered.connect(self.next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("gui/icons/go-down.png"), "Last", self)
        self.last_action.triggered.connect(self.load_last_page)
        self.toolbar.addAction(self.last_action)

    def setup_hex_table(self):
        self.hex_table = QTableWidget()
        self.hex_table.setColumnCount(18)
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])
        self.hex_table.verticalHeader().setVisible(False)
        self.hex_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.hex_table.setShowGrid(False)

    def display_hex_content(self, hex_content):
        self.hex_formatter = HexFormatter(hex_content)
        self.update_navigation_states()
        self.display_current_page()

    def parse_hex_line(self, line):
        if ":" not in line:
            return None, None, None
        address, rest = line.split(":", maxsplit=1)
        hex_chunk, ascii_repr = rest.split("  ", maxsplit=1)
        return address.strip(), hex_chunk.strip(), ascii_repr.strip()

    def clear_content(self):
        self.hex_table.clear()

    def load_first_page(self):
        self.current_page = 0
        self.display_current_page()

    def load_last_page(self):
        self.current_page = self.hex_formatter.total_pages() - 1
        self.display_current_page()

    def next_page(self):
        if self.current_page < self.hex_formatter.total_pages() - 1:
            self.current_page += 1
        self.display_current_page()

    def previous_page(self):
        if self.current_page > 0:
            self.current_page -= 1
        self.display_current_page()


    def display_current_page(self):
        formatted_hex = self.hex_formatter.format_hex(self.current_page)

        # Clear the table first
        self.hex_table.setRowCount(0)

        hex_lines = formatted_hex.split('\n')

        # Ensure we set the correct row count
        self.hex_table.setRowCount(len(hex_lines))

        for row, line in enumerate(hex_lines):
            address, hex_chunk, ascii_repr = self.parse_hex_line(line)
            if not address or not hex_chunk:  # Skip if there's an error in parsing
                continue

            # Set address and center-align
            address_item = QTableWidgetItem(address)
            address_item.setTextAlignment(Qt.AlignCenter)
            self.hex_table.setItem(row, 0, address_item)

            # Set hex values and center-align
            for col, byte in enumerate(hex_chunk.split()):
                byte_item = QTableWidgetItem(byte)
                byte_item.setTextAlignment(Qt.AlignCenter)
                self.hex_table.setItem(row, col + 1, byte_item)

            # Set ASCII representation and center-align
            ascii_item = QTableWidgetItem(ascii_repr)
            ascii_item.setTextAlignment(Qt.AlignCenter)
            self.hex_table.setItem(row, 17, ascii_item)

        self.update_navigation_states()

    def go_to_page_by_entry(self):
        try:
            page_num = int(self.page_entry.text()) - 1
            if 0 <= page_num < self.hex_formatter.total_pages():
                self.current_page = page_num
                self.display_current_page()
                self.update_navigation_states()
            else:
                QMessageBox.warning(self, "Invalid Page", "Page number out of range.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Page", "Please enter a valid page number.")

    def update_navigation_states(self):
        if not self.hex_formatter:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < self.hex_formatter.total_pages() - 1)
        self.page_entry.setText(str(self.current_page + 1))
        self.total_pages_label.setText(f"of {self.hex_formatter.total_pages()}")

    def update_total_pages_label(self):
        total_pages = self.hex_formatter.total_pages()
        current_page = self.current_page + 1
        self.total_pages_label.setText(f"{current_page} of {total_pages}")



from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QWidget, QVBoxLayout,
                               QLineEdit, QTableWidget, QHeaderView, QTableWidgetItem, QListWidget,
                               QDialog, QSizePolicy, QHBoxLayout, QFrame)

from managers.hex_viewer_manager import HexViewerManager


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

        # Create a horizontal layout for the hex table and search results
        self.horizontal_layout = QHBoxLayout()

        self.setup_hex_table()
        self.horizontal_layout.addWidget(self.hex_table)

        # Create a QVBoxLayout for the search results and its title
        self.search_results_layout = QVBoxLayout()

        self.search_results_frame = QFrame(self)  # This frame will contain the title and the search results
        self.search_results_frame.setMaximumWidth(200)
        self.search_results_frame.setStyleSheet("border: 1px solid gray; border-radius: 5px; padding: 5px;")

        self.search_results_title = QLabel("Search Results", self.search_results_frame)
        self.search_results_title.setAlignment(Qt.AlignCenter)

        self.search_results_title.setStyleSheet("font-weight: bold;")  # Optional: make it bold
        self.search_results_layout.addWidget(self.search_results_title)

        self.search_results_widget = QListWidget(self.search_results_frame)
        self.search_results_widget.itemClicked.connect(self.search_result_clicked)
        self.search_results_widget.setMaximumWidth(200)
        self.search_results_layout.addWidget(self.search_results_widget)

        self.search_results_frame.setLayout(self.search_results_layout)
        self.horizontal_layout.addWidget(self.search_results_frame)

        # Initially hide the entire frame
        self.search_results_frame.setVisible(False)

        # Add the horizontal layout to the main layout
        self.layout.addLayout(self.horizontal_layout)

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

        # Add a spacer to push the following widgets to the right
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # After adding the search components to the toolbar:
        fixed_spacer = QWidget()
        fixed_spacer.setFixedSize(850, 10)  # Adjust 10 to control the distance from the window's border
        self.toolbar.addWidget(fixed_spacer)

        # Search bar components
        self.search_bar = QLineEdit(self)
        self.search_bar.setMaximumWidth(200)  # Adjust the number as per your needs
        self.search_bar.setContentsMargins(5, 0, 5, 0)
        self.search_bar.setPlaceholderText("Enter search query...")
        self.search_bar.returnPressed.connect(self.trigger_search)

        self.toolbar.addWidget(self.search_bar)


    def setup_hex_table(self):
        self.hex_table = QTableWidget()
        self.hex_table.setColumnCount(18)
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])
        self.hex_table.verticalHeader().setVisible(False)
        self.hex_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.hex_table.setShowGrid(False)

    def display_hex_content(self, hex_content):
        self.search_results_widget.clear()
        self.search_results_frame.setVisible(False)
        # Clear the search bar text
        self.search_bar.setText("")
        self.hex_formatter = HexViewerManager(hex_content)
        self.update_navigation_states()
        self.display_current_page()
        # clear the page number entry
        self.page_entry.setText("")

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

    def search_result_clicked(self, item):
        address = item.text().split(":")[1].strip()
        self.navigate_to_address(address)

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
                byte_item.setBackground(Qt.white)  # Clear any previous highlight
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

    def trigger_search(self):
        query = self.search_bar.text()
        if not query:
            QMessageBox.warning(self, "Search Error", "Please enter a search query.")
            return

        matches = self.hex_formatter.search(query)
        self.search_results_widget.clear()  # Clear previous results

        if matches:
            for match in matches:
                address = f"0x{match * 16:08x}"  # Calculate the address from line number
                self.search_results_widget.addItem(f"Address: {address}")

            # Show the search results frame
            self.search_results_frame.setVisible(True)

        else:
            QMessageBox.warning(self, "Search Result", "No matches found.")
            # Hide the search results frame if no matches
            self.search_results_frame.setVisible(False)

    def navigate_to_search_result(self, address):
        # Convert the address string back to an integer
        address_int = int(address, 16)

        # Determine the line number from the address
        line = address_int // 16

        if line is not None:
            # The rest of the logic remains the same
            self.current_page = line // self.hex_formatter.LINES_PER_PAGE
            self.display_current_page()

            # Navigate to the specific row on that page and highlight it
            row_in_page = line % self.hex_formatter.LINES_PER_PAGE
            self.hex_table.selectRow(row_in_page)
            for col in range(1, 17):
                item = self.hex_table.item(row_in_page, col)
                if item:
                    item.setBackground(Qt.yellow)
            self.update_navigation_states()
        else:
            QMessageBox.warning(self, "Navigation Error", "Invalid address.")

    def navigate_to_address(self, address):
        # Convert the address string back to an integer
        address_int = int(address, 16)

        # Determine the line number from the address
        line = address_int // 16

        if line is not None:
            # The rest of the logic remains the same
            self.current_page = line // self.hex_formatter.LINES_PER_PAGE
            self.display_current_page()

            # Navigate to the specific row on that page and highlight it
            row_in_page = line % self.hex_formatter.LINES_PER_PAGE
            self.hex_table.selectRow(row_in_page)
            for col in range(1, 17):
                item = self.hex_table.item(row_in_page, col)
                if item:
                    item.setBackground(Qt.yellow)
            self.update_navigation_states()
        else:
            QMessageBox.warning(self, "Navigation Error", "Invalid address.")


class SearchResultsDialog(QDialog):
    navigate_to_address = Signal(str)  # Emit the address as a string

    def __init__(self, matches, parent=None):
        super().__init__(parent)
        self.matches = matches
        self.list_widget = QListWidget(self)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        for line in self.matches:
            address = f"0x{line * 16:08x}"  # Calculate the address from line number
            self.list_widget.addItem(f"Address: {address}")
        layout.addWidget(self.list_widget)
        self.setLayout(layout)

        # Connect the itemClicked signal to a slot
        self.list_widget.itemClicked.connect(self.item_clicked)

    def item_clicked(self, item):
        address = item.text().split(":")[1].strip()
        self.navigate_to_address.emit(address)  # Emit the address


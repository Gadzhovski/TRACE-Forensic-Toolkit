import os
from functools import lru_cache

from PySide6.QtCore import Qt, QObject, Signal, QThread, QSize
from PySide6.QtGui import QAction, QIcon, QFont, QResizeEvent
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QWidget, QVBoxLayout,
                               QLineEdit, QTableWidget, QHeaderView, QTableWidgetItem, QListWidget,
                               QSizePolicy, QFrame, QApplication, QMenu, QAbstractItemView, QFileDialog,
                               QToolButton, QComboBox, QSplitter)


class SearchWorker(QObject):
    search_finished = Signal(list)

    def __init__(self, hex_viewer_manager, query):
        super().__init__()
        self.hex_viewer_manager = hex_viewer_manager
        self.query = query

    def run(self):
        matches = self.hex_viewer_manager.search(self.query)
        self.search_finished.emit(matches)


class HexViewerManager:
    LINES_PER_PAGE = 1024

    def __init__(self, hex_content, byte_content):
        self.hex_content = hex_content
        self.byte_content = byte_content
        self.num_total_pages = (len(hex_content) // 32) // self.LINES_PER_PAGE
        if (len(hex_content) // 32) % self.LINES_PER_PAGE:
            self.num_total_pages += 1

    @lru_cache(maxsize=None)
    def format_hex(self, page=0):
        start_index = page * self.LINES_PER_PAGE * 32
        end_index = start_index + (self.LINES_PER_PAGE * 32)
        lines = []
        chunk_starts = range(start_index, end_index, 32)
        for start in chunk_starts:
            if start >= len(self.hex_content):
                break
            lines.append(self.format_hex_chunk(start))
        return '\n'.join(lines)

    def format_hex_chunk(self, start):
        hex_part = []
        ascii_repr = []
        for j in range(start, start + 32, 2):
            chunk = self.hex_content[j:j + 2]
            if not chunk:
                break
            chunk_int = int(chunk, 16)
            hex_part.append(chunk.upper())
            ascii_repr.append(chr(chunk_int) if 32 <= chunk_int <= 126 else '.')
        hex_line = ' '.join(hex_part)
        padding = ' ' * (48 - len(hex_line))
        ascii_line = ''.join(ascii_repr)
        line = f'0x{start // 2:08x}: {hex_line}{padding}  {ascii_line}'
        return line

    def total_pages(self):
        return self.num_total_pages

    def search(self, query):
        if all(part.isalnum() or part.isspace() for part in query.split()):
            try:
                query_bytes = bytes.fromhex(query.replace(" ", ""))
                return self.search_by_hex(query_bytes)
            except ValueError:
                pass  # Invalid hex value

        if query.startswith("0x"):
            return self.search_by_address(query)
        else:
            return self.search_by_string(query)

    def search_by_address(self, address):
        """Searches for the line that contains the given address (offset)"""
        try:
            address_int = int(address, 16)
            line_number = address_int // 16
            if 0 <= line_number < len(self.byte_content) // 16:
                return [line_number]
            else:
                return []
        except ValueError:
            return []

    def search_by_string(self, query):
        # Implementation for searching by string
        matches = []
        query_bytes = query.encode('utf-8')

        start = 0
        while start < len(self.byte_content):
            position = self.byte_content.find(query_bytes, start)
            if position == -1:
                break
            start = position + 1  # Move the start to the next character
            line_number = position // 16  # Calculate line number
            matches.append(line_number)

        return matches

    def search_by_hex(self, hex_query):
        if all(part.isalnum() for part in hex_query.split()):
            try:
                query_bytes = bytes.fromhex(hex_query.replace(" ", ""))
            except ValueError:
                return []  # Invalid hex value
        else:
            return []  # Non-alphanumeric characters in the query

        matches = []
        start = 0
        while start < len(self.byte_content):
            position = self.byte_content[start:].find(query_bytes)
            if position == -1:
                break
            start += position  # Adjust the start to the found position
            line_number = start // 16  # Calculate line number
            matches.append(line_number)
            start += len(query_bytes)  # Move past the current match
        return matches


class HexViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hex_viewer_manager = None
        self.current_page = 0

        self.context_menu = QMenu(self)
        self.copy_action = QAction("Copy", self)
        self.copy_action.triggered.connect(self.copy_to_clipboard)
        self.context_menu.addAction(self.copy_action)

        # Set up a context menu event handler
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

        self.initialize_ui()

    def show_context_menu(self, pos):
        # Show the context menu at the cursor position
        self.context_menu.exec_(self.mapToGlobal(pos))

    def copy_to_clipboard(self):
        selected_text = ""

        # Check if any cells in the hex_table are selected
        selected_indexes = self.hex_table.selectedIndexes()
        if selected_indexes:
            # Sort the selected indexes by row
            selected_indexes.sort(key=lambda index: index.row())

            for i, index in enumerate(selected_indexes):
                selected_text += index.data(Qt.DisplayRole)

                if index.column() == 16:  # The last column (ASCII), add a newline
                    selected_text += "\n"
                else:
                    next_index = selected_indexes[i + 1] if i + 1 < len(selected_indexes) else None

                    # Add a space if the next cell is in the same row
                    if next_index and next_index.row() == index.row():
                        selected_text += " "

        # Copy the selected text to the clipboard
        if selected_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(selected_text)

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        self.setup_toolbar()
        self.layout.addWidget(self.toolbar)

        # Create a QSplitter for dynamic resizing
        self.splitter = QSplitter(Qt.Horizontal, self)  # Horizontal splitter for hex_table and search_results_frame

        # Setup Hex Table
        self.setup_hex_table()
        self.hex_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  # Make hex table expandable

        # Add the hex table to the splitter
        self.splitter.addWidget(self.hex_table)

        # Create a QVBoxLayout for the search results and its title
        self.search_results_layout = QVBoxLayout()
        self.search_results_layout.setContentsMargins(2, 2, 2, 2)
        self.search_results_layout.setSpacing(2)

        self.search_results_frame = QFrame(self)  # This frame will contain the title and the search results
        self.search_results_frame.setMaximumWidth(180)  # Make it narrower
        self.search_results_frame.setObjectName("search_results_frame")  # Set object name for stylesheet targeting
        self.search_results_frame.setSizePolicy(QSizePolicy.Fixed,
                                                QSizePolicy.Expanding)  # Fixed width, expandable height

        self.search_results_title = QLabel("Search Results", self.search_results_frame)
        self.search_results_title.setAlignment(Qt.AlignCenter)
        self.search_results_title.setFixedHeight(22)
        self.search_results_title.setObjectName("search_results_title")  # Set object name for stylesheet targeting
        self.search_results_layout.addWidget(self.search_results_title)

        self.search_results_widget = QListWidget(self.search_results_frame)
        self.search_results_widget.setObjectName("search_results_widget")  # Set object name for stylesheet targeting
        self.search_results_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # Show scroll bar when needed
        self.search_results_widget.itemClicked.connect(self.search_result_clicked)
        self.search_results_widget.setFont(QFont("Courier", 9))  # Smaller font
        self.search_results_layout.addWidget(self.search_results_widget)

        self.search_results_frame.setLayout(self.search_results_layout)

        # Add the search results frame to the splitter
        self.splitter.addWidget(self.search_results_frame)

        # Set both widgets to expand in both directions
        self.splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Add the splitter to the main layout
        self.layout.addWidget(self.splitter)

        # Set the main layout
        self.setLayout(self.layout)

    def resizeEvent(self, event: QResizeEvent):
        """Handle window resizing to update layout."""
        # Adjust splitter sizes dynamically based on new window dimensions
        total_width = event.size().width()
        total_height = event.size().height()

        # Set sizes for horizontal splitter: 75% for hex_table and 25% for search_results_frame
        self.splitter.setSizes([int(total_width * 0.75), int(total_width * 0.25)])

        super().resizeEvent(event)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(16, 16))  # Reduce icon size
        self.toolbar.setFixedHeight(32)  # Reduce toolbar height
        self.toolbar.setStyleSheet("""
            QToolBar {
                spacing: 2px;
                padding: 1px;
            }
            QToolButton {
                padding: 2px;
                margin: 1px;
            }
        """)
        # disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        # Navigation buttons
        self.first_action = QAction(QIcon("Icons/icons8-thick-arrow-pointing-up-50.png"), "First", self)
        self.first_action.triggered.connect(self.load_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("Icons/icons8-left-arrow-50.png"), "Previous", self)
        self.prev_action.triggered.connect(self.previous_page)
        self.toolbar.addAction(self.prev_action)

        # Page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setFixedHeight(25)  # Set fixed height for input
        self.page_entry.setPlaceholderText("1")
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)

        # Total pages label
        self.total_pages_label = QLabel(" of ")
        self.total_pages_label.setFixedHeight(25)  # Set fixed height for label
        self.toolbar.addWidget(self.total_pages_label)

        self.next_action = QAction(QIcon("Icons/icons8-right-arrow-50.png"), "Next", self)
        self.next_action.triggered.connect(self.next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("Icons/icons8-down-50.png"), "Last", self)
        self.last_action.triggered.connect(self.load_last_page)
        self.toolbar.addAction(self.last_action)

        # Add a small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(20, 0)
        self.toolbar.addWidget(spacer)

        # Add a QLabel and a QComboBox for font size to the toolbar
        font_label = QLabel("Font Size: ")
        font_label.setFixedHeight(25)  # Set fixed height for label
        self.toolbar.addWidget(font_label)

        self.font_size_combobox = QComboBox(self)
        self.font_size_combobox.setFixedHeight(25)  # Set fixed height for combobox
        self.font_size_combobox.setFixedWidth(60)  # Increase width to show full numbers
        self.font_size_combobox.addItems(["8", "10", "12", "14", "16", "18", "20", "24", "28", "32", "36"])
        self.font_size_combobox.currentTextChanged.connect(self.update_font_size)
        self.toolbar.addWidget(self.font_size_combobox)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(20, 0)
        self.toolbar.addWidget(spacer)

        self.export_button = QToolButton(self)
        self.export_button.setObjectName("exportButton")  # Assign a unique object name
        self.export_button.setText("Export")
        self.export_button.setToolButtonStyle(Qt.ToolButtonTextOnly)  # Change to text only since no icon is used
        self.export_button.setFixedHeight(25)  # Set fixed height
        self.export_button.setFixedWidth(100)  # Set fixed width to show full text
        self.export_button.setPopupMode(QToolButton.MenuButtonPopup)  # Set the popup mode

        # Add format options to the menu
        self.export_menu = QMenu(self)

        self.text_format_action = QAction("Text (.txt)", self)
        self.text_format_action.triggered.connect(lambda: self.export_content("txt"))
        self.export_menu.addAction(self.text_format_action)

        self.html_format_action = QAction("HTML (.html)", self)
        self.html_format_action.triggered.connect(lambda: self.export_content("html"))
        self.export_menu.addAction(self.html_format_action)

        self.export_button.setMenu(self.export_menu)
        self.toolbar.addWidget(self.export_button)

        # Add a spacer to push the following widgets to the right
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # Search bar components
        self.search_bar = QLineEdit(self)
        self.search_bar.setMaximumWidth(180)  # Reduce width to save space
        self.search_bar.setFixedHeight(25)  # Reduce height
        self.search_bar.setContentsMargins(5, 0, 5, 0)  # Reduce margins
        self.search_bar.setPlaceholderText("Search...")
        self.search_bar.returnPressed.connect(self.trigger_search)
        self.toolbar.addWidget(self.search_bar)

    def update_font_size(self):
        # Get the current font size from the combobox
        selected_size = int(self.font_size_combobox.currentText())

        # Set the new font size to the hex_table
        current_font = self.hex_table.font()
        current_font.setPointSize(selected_size)
        self.hex_table.setFont(current_font)

        # Dynamically adjust column widths based on the font size
        address_width = selected_size * 10  # Proportional width for Address column
        byte_width = selected_size * 3  # Proportional width for each byte column
        ascii_width = selected_size * 8  # Proportional width for ASCII column

        # Set column widths dynamically
        self.hex_table.setColumnWidth(0, address_width)  # Address column
        for i in range(1, 17):  # Set uniform width for each byte column
            self.hex_table.setColumnWidth(i, byte_width)
        self.hex_table.setColumnWidth(17, ascii_width)  # ASCII column

        # Update the font size for the headers as well
        header_font = self.hex_table.horizontalHeader().font()
        header_font.setPointSize(selected_size)
        self.hex_table.horizontalHeader().setFont(header_font)

        # Apply the font to all existing data cells
        for row in range(self.hex_table.rowCount()):
            for col in range(self.hex_table.columnCount()):
                item = self.hex_table.item(row, col)
                if item:
                    item_font = item.font()
                    # Ensure we have a valid font size before setting it
                    if selected_size > 0:
                        item_font.setPointSize(selected_size)
                        item.setFont(item_font)

        # Adjust the horizontal scrollbar policy if needed
        if self.hex_table.horizontalHeader().length() > self.hex_table.viewport().width():
            self.hex_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        else:
            self.hex_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def setup_hex_table(self):
        self.hex_table = QTableWidget()
        self.hex_table.verticalHeader().setDefaultSectionSize(20)  # Smaller row height

        # Set the font of the hex_table
        font = QFont("Courier")
        font.setPointSize(10)  # Default smaller font size
        font.setLetterSpacing(QFont.AbsoluteSpacing, 1)  # Reduce letter spacing
        self.hex_table.setFont(font)

        # Configure the columns and headers
        self.hex_table.setColumnCount(18)  # 16 bytes + 1 address + 1 ASCII
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])
        self.hex_table.verticalHeader().setVisible(False)

        # Set resizing policies for the header
        header = self.hex_table.horizontalHeader()
        header.setStyleSheet("QHeaderView::section { padding: 2px; }")  # Reduce header padding
        header.setDefaultSectionSize(25)  # Set a smaller default size

        # Address column - Resize based on content
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)

        # Byte columns - Fixed width for each byte column
        for i in range(1, 17):  # 00 to 0F columns
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            self.hex_table.setColumnWidth(i, 25)  # Smaller byte column width

        # ASCII column - Stretch to fill remaining space
        header.setSectionResizeMode(17, QHeaderView.Stretch)

        # Adjust for remaining space in the ASCII column
        header.setStretchLastSection(True)

        # Set the initial column widths
        self.hex_table.setColumnWidth(0, 120)  # Address column initial width
        self.hex_table.setColumnWidth(17, 200)  # ASCII column initial width

        self.hex_table.setStyleSheet("""
            QTableWidget {
                gridline-color: transparent;
                border: 1px solid #d3d3d3;
            }
            QTableWidget::item {
                padding: 0px;
                border: none;
            }
        """)
        self.hex_table.setShowGrid(False)
        self.hex_table.setAlternatingRowColors(True)
        self.hex_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def display_hex_content(self, file_content):
        hex_content = file_content.hex()
        self.search_results_widget.clear()
        # self.search_results_frame.setVisible(False)

        # Clear the search bar text
        self.search_bar.setText("")
        self.hex_viewer_manager = HexViewerManager(hex_content, file_content)
        self.update_navigation_states()
        self.display_current_page()
        # clear the page number entry
        self.page_entry.setText("")

    def export_content(self, selected_format):
        if not self.hex_viewer_manager:
            QMessageBox.warning(self, "No Content", "No content available to export.")
            return

        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly  # Allow read-only access to the selected file

        if selected_format == "txt":
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Export Hex Content", "", "Text Files (*.txt)", options=options
            )
            self.export_as_text(file_name)
        elif selected_format == "html":
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Export Hex Content", "", "HTML Files (*.html)", options=options
            )
            self.export_as_html(file_name)
        else:
            QMessageBox.warning(self, "Unsupported Format", "Unsupported export format selected.")

    def export_as_text(self, file_name):
        with open(file_name, "w") as text_file:
            # Add the header line with green color using ANSI escape codes
            header_line = "Address     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F        ASCII"
            text_file.write(header_line + "\n")

            # Add an empty line
            text_file.write("\n")

            # Write the formatted hex content
            formatted_hex = self.hex_viewer_manager.format_hex(self.current_page)
            text_file.write(formatted_hex)

    def export_as_html(self, file_name):
        html_content = "<html><body>\n"
        html_content += "<pre>\n"

        # Add a smaller and less prominent header with the original text
        header_line = '<div style="font-size:14px; color:#888;">Generated by Trace</div>'
        html_content += header_line + "<br><br>\n"

        # Add directory and file name information
        directory, filename = os.path.split(file_name)
        html_content += f'<span style="color:blue;">Directory: {directory}</span><br>\n'
        html_content += f'<span style="color:blue;">File Name: {filename}</span><br><br>\n'

        # Add the green header line
        header_line = ('<span style="color:green;">Address     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F        '
                       'ASCII</span>')
        html_content += header_line + "<br>\n"

        html_content += self.hex_viewer_manager.format_hex(self.current_page).replace("\n", "<br>")
        html_content += "</pre>\n"
        html_content += "</body></html>"

        with open(file_name, "w") as html_file:
            html_file.write(html_content)

    def parse_hex_line(self, line):
        if ":" not in line:
            return None, None, None
        address, rest = line.split(":", maxsplit=1)
        hex_chunk, ascii_repr = rest.split("  ", maxsplit=1)
        return address.strip(), hex_chunk.strip(), ascii_repr.strip()

    def clear_content(self):
        self.hex_table.clear()

    def load_first_page(self):
        try:
            self.current_page = 0
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def load_last_page(self):
        try:
            self.current_page = self.hex_viewer_manager.total_pages() - 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def next_page(self):
        try:
            if self.current_page < self.hex_viewer_manager.total_pages() - 1:
                self.current_page += 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def previous_page(self):
        try:
            if self.current_page > 0:
                self.current_page -= 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def search_result_clicked(self, item):
        address = item.text().split(":")[1].strip()
        self.navigate_to_address(address)

    def display_current_page(self):
        formatted_hex = self.hex_viewer_manager.format_hex(self.current_page)

        # Clear the table first
        self.hex_table.setRowCount(0)
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])

        hex_lines = formatted_hex.split('\n')

        # Ensure we set the correct row count
        self.hex_table.setRowCount(len(hex_lines))

        # Get the current font size with fallback to default
        current_font = self.hex_table.font()
        current_font_size = current_font.pointSize()
        if current_font_size <= 0:  # Use default if invalid
            current_font_size = 10  # Default font size

        for row, line in enumerate(hex_lines):
            address, hex_chunk, ascii_repr = self.parse_hex_line(line)
            if not address or not hex_chunk:  # Skip if there's an error in parsing
                continue

            # Set address and center-align
            address_item = QTableWidgetItem(address + ":")  # Add a colon after the address
            address_item.setTextAlignment(Qt.AlignCenter)
            item_font = address_item.font()
            item_font.setPointSize(current_font_size)
            address_item.setFont(item_font)
            self.hex_table.setItem(row, 0, address_item)

            # Set hex values and center-align
            for col, byte in enumerate(hex_chunk.split()):
                byte_item = QTableWidgetItem(byte)
                byte_item.setTextAlignment(Qt.AlignCenter)
                byte_item.setBackground(Qt.white)  # Clear any previous highlight
                item_font = byte_item.font()
                item_font.setPointSize(current_font_size)
                byte_item.setFont(item_font)
                self.hex_table.setItem(row, col + 1, byte_item)

            # Set ASCII representation and center-align
            ascii_item = QTableWidgetItem(ascii_repr)
            ascii_item.setTextAlignment(Qt.AlignCenter)
            item_font = ascii_item.font()
            item_font.setPointSize(current_font_size)
            ascii_item.setFont(item_font)
            self.hex_table.setItem(row, 17, ascii_item)

        self.update_navigation_states()

    def go_to_page_by_entry(self):
        try:
            page_num = int(self.page_entry.text()) - 1
            if 0 <= page_num < self.hex_viewer_manager.total_pages():
                self.current_page = page_num
                self.display_current_page()
                self.update_navigation_states()
            else:
                QMessageBox.warning(self, "Invalid Page", "Page number out of range.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Page", "Please enter a valid page number.")

    def update_navigation_states(self):
        if not self.hex_viewer_manager:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < self.hex_viewer_manager.total_pages() - 1)
        self.page_entry.setText(str(self.current_page + 1))
        self.total_pages_label.setText(f"of {self.hex_viewer_manager.total_pages()}")

    def update_total_pages_label(self):
        total_pages = self.hex_viewer_manager.total_pages()
        current_page = self.current_page + 1
        self.total_pages_label.setText(f"{current_page} of {total_pages}")

    def trigger_search(self):
        query = self.search_bar.text()
        if not query:
            QMessageBox.warning(self, "Search Error", "Please enter a search query.")
            return

        # Check if a search is already ongoing. If so, stop it before starting a new one.
        if hasattr(self, 'search_thread') and self.search_thread.isRunning():
            self.search_thread.quit()
            self.search_thread.wait()

        # Start the search in a new thread
        self.search_thread = QThread()
        self.search_worker = SearchWorker(self.hex_viewer_manager, query)
        self.search_worker.moveToThread(self.search_thread)

        # Connect signals and slots
        self.search_worker.search_finished.connect(self.handle_search_results)
        self.search_thread.started.connect(self.search_worker.run)
        self.search_thread.finished.connect(self.cleanup_thread_resources)

        # Start the thread
        self.search_thread.start()

    def cleanup_thread_resources(self):
        # Ensure safe cleanup by checking the existence of resources before deleting
        if hasattr(self, 'search_worker'):
            self.search_worker.deleteLater()
            del self.search_worker
        if hasattr(self, 'search_thread'):
            self.search_thread.deleteLater()
            del self.search_thread

    def closeEvent(self, event):
        if hasattr(self, 'search_thread') and self.search_thread.isRunning():
            self.search_thread.quit()
            self.search_thread.wait()
        super().closeEvent(event)

    def handle_search_results(self, matches):
        self.search_results_widget.clear()  # Clear previous results
        if matches:
            for match in matches:
                address = f"0x{match * 16:08x}"  # Calculate the address from line number
                self.search_results_widget.addItem(f"Address: {address}")

            # Show the search results frame and resize the splitter to allocate more space to results
            self.search_results_frame.setVisible(True)
            self.splitter.setSizes([self.width() * 0.6, self.width() * 0.4])  # Adjust sizes dynamically

        else:
            QMessageBox.warning(self, "Search Result", "No matches found.")
            # Even if no matches are found, the search results frame will still be shown
            self.splitter.setSizes([self.width() * 0.75, self.width() * 0.25])

    def navigate_to_address(self, address):
        try:
            # Convert the address string back to an integer
            address_int = int(address, 16)

            # Determine the line number from the address
            line = address_int // 16

            # The rest of the logic remains the same
            self.current_page = line // self.hex_viewer_manager.LINES_PER_PAGE
            self.display_current_page()

            # Navigate to the specific row on that page and highlight it
            row_in_page = line % self.hex_viewer_manager.LINES_PER_PAGE
            self.hex_table.selectRow(row_in_page)
            for col in range(1, 17):
                item = self.hex_table.item(row_in_page, col)
                if item:
                    item.setBackground(Qt.yellow)
            self.update_navigation_states()
        except ValueError:
            QMessageBox.warning(self, "Navigation Error", "Invalid address.")

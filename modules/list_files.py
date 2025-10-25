
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QHeaderView, \
    QGroupBox, QCheckBox, QGridLayout, QLabel, QToolBar, QLineEdit, QSpacerItem, QSizePolicy


class SizeTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))


class FileSearchWidget(QWidget):

    def __init__(self, image_handler):
        super(FileSearchWidget, self).__init__()
        self.image_handler = image_handler
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Create the toolbar
        self.toolbar = QToolBar()
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.toolbar)

        # Add icon and title to the toolbar
        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap('Icons/icons8-piece-of-evidence-50.png'))  # Update the path to your icon
        self.icon_label.setFixedSize(48, 48)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("File Search")
        self.title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                color: #37c6d0;
                font-weight: bold;
                margin-left: 8px;
            }
        """)
        self.toolbar.addWidget(self.title_label)

        # Add spacer to push remaining widgets to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # Add the checkboxes to the toolbar
        self.extensionGroupBox = QGroupBox()
        self.extensionLayout = QGridLayout()  # Use QGridLayout for checkboxes

        # Define file types
        self.fileTypes = ['', '.txt', '.jpg', '.jpeg', '.png', '.pdf', '.doc',
                          '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        self.checkBoxes = {}

        row = 0
        col = 0
        for fileType in self.fileTypes:
            checkBox = QCheckBox(fileType if fileType else 'All')
            checkBox.stateChanged.connect(self.on_file_type_selected)
            self.extensionLayout.addWidget(checkBox, row, col)
            self.checkBoxes[fileType] = checkBox
            col += 1
            if col >= 6:
                row += 1
                col = 0

        self.extensionGroupBox.setLayout(self.extensionLayout)
        self.toolbar.addWidget(self.extensionGroupBox)

        # Add a small spacer between checkboxes and search field
        small_spacer = QWidget()
        small_spacer.setFixedWidth(50)  # Adjust this value for appropriate spacing
        self.toolbar.addWidget(small_spacer)

        # Add search bar to the right side of the toolbar
        self.searchBar = QLineEdit()
        self.searchBar.setPlaceholderText("Search files by name or ext.")
        self.searchBar.textChanged.connect(self.on_search_bar_selected)
        self.searchBar.setFixedHeight(35)
        self.searchBar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.toolbar.addWidget(self.searchBar)

        # Increase the size of the spacer after the search bar
        end_spacer = QWidget()
        end_spacer.setFixedWidth(10)  # Increase the width here to add more space after the search bar
        self.toolbar.addWidget(end_spacer)

        # Files table setup
        self.filesTable = QTableWidget()
        # In the init_ui method of FileSearchWidget, after creating the table
        self.filesTable.verticalHeader().setVisible(False)

        self.filesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.filesTable.setEditTriggers(QTableWidget.NoEditTriggers)

        # Set column count to 8, considering "Id" as the first column
        self.filesTable.setColumnCount(8)

        # Ensure that only one set of headers is defined
        self.filesTable.setHorizontalHeaderLabels(
            ['Id', 'Name', 'Path', 'Size', 'Created', 'Accessed', 'Modified', 'Changed'])

        # Set up the initial column structure and dynamic resizing behavior
        header = self.filesTable.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Id column
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Name column
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Path column
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Size column
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Created Date
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Accessed Date
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Modified Date
        header.setSectionResizeMode(7, QHeaderView.Interactive)  # Changed Date

        # Set initial column widths for the interactive columns
        self.filesTable.setColumnWidth(0, 30)  # Id column
        self.filesTable.setColumnWidth(3, 70)  # Size
        self.filesTable.setColumnWidth(4, 130)  # Created Date
        self.filesTable.setColumnWidth(5, 130)  # Accessed Date
        self.filesTable.setColumnWidth(6, 130)  # Modified Date
        self.filesTable.setColumnWidth(7, 130)  # Changed Date

        layout.addWidget(self.filesTable)

        # Connect the table resize event
        self.filesTable.resizeEvent = self.handle_resize_event

    def handle_resize_event(self, event):
        # Automatically adjust the column widths when the table is resized
        total_width = self.filesTable.width()
        remaining_width = total_width - (self.filesTable.columnWidth(0) +  # Id column
                                         self.filesTable.columnWidth(3) +
                                         self.filesTable.columnWidth(4) +
                                         self.filesTable.columnWidth(5) +
                                         self.filesTable.columnWidth(6) +
                                         self.filesTable.columnWidth(7))

        # Dynamically resize the "Name" and "Path" columns
        self.filesTable.setColumnWidth(1, remaining_width // 2)  # Allocate half of remaining space to "Name"
        self.filesTable.setColumnWidth(2, remaining_width // 2)  # Allocate half of remaining space to "Path"

        super(QTableWidget, self.filesTable).resizeEvent(event)

    def on_search_bar_selected(self):
        search_query = self.searchBar.text().strip()
        if search_query:
            # Call the search_files method with the search query
            self.search_files(search_query)
        else:
            # If the search bar is empty, list files based on the selected checkboxes
            self.on_file_type_selected()

    def search_files(self, search_query):
        self.clear()
        files = self.image_handler.search_files(search_query)
        for file in files:
            self.populate_table_row(file)

    def on_file_type_selected(self):
        selectedExtensions = [ext for ext, cb in self.checkBoxes.items() if cb.isChecked()]
        self.list_files(None if '' in selectedExtensions else ([] if not selectedExtensions else selectedExtensions))

    def populate_table_row(self, file):
        row_pos = self.filesTable.rowCount()
        self.filesTable.insertRow(row_pos)
        self.filesTable.setItem(row_pos, 0, QTableWidgetItem(str(row_pos + 1)))  # "Id" column
        self.filesTable.setItem(row_pos, 1, QTableWidgetItem(file['name']))
        self.filesTable.setItem(row_pos, 2, QTableWidgetItem(file['path']))
        size_item = SizeTableWidgetItem(self.image_handler.get_readable_size(file['size']))
        size_item.setData(Qt.UserRole, file['size'])
        self.filesTable.setItem(row_pos, 3, size_item)
        self.filesTable.setItem(row_pos, 4, QTableWidgetItem(file['created']))
        self.filesTable.setItem(row_pos, 5, QTableWidgetItem(file['accessed']))
        self.filesTable.setItem(row_pos, 6, QTableWidgetItem(file['modified']))
        self.filesTable.setItem(row_pos, 7, QTableWidgetItem(file['changed']))

    def list_files(self, extension):
        self.filesTable.setSortingEnabled(False)
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()
        if extension is not None and not extension:
            return
        files = self.image_handler.list_files(extension)
        for file in files:
            self.populate_table_row(file)
        self.filesTable.setSortingEnabled(True)

    def clear(self):
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()
        for checkBox in self.checkBoxes.values():
            checkBox.setChecked(False)

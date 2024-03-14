
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QHeaderView, \
    QGroupBox, QCheckBox, QGridLayout, QLabel, QToolBar, QLineEdit


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

        # add spacer to the toolbar
        spacer = QWidget()
        spacer.setFixedWidth(50)
        self.toolbar.addWidget(spacer)

        # add the checkboxes to the toolbar
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

        # Add a spacer to the toolbar
        spacer = QWidget()
        spacer.setFixedWidth(50)
        self.toolbar.addWidget(spacer)

        # add search bar to search for files by file name or only file extension using '*.jpg' for example
        self.searchBar = QLineEdit()
        self.searchBar.setFixedWidth(250)
        self.searchBar.setPlaceholderText("Search for files by name or extension")
        self.searchBar.textChanged.connect(self.on_search_bar_selected)
        self.toolbar.addWidget(self.searchBar)

        # Files table setup
        self.filesTable = QTableWidget()
        self.filesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.filesTable.setEditTriggers(QTableWidget.NoEditTriggers)

        self.filesTable.setColumnCount(7)
        self.filesTable.setHorizontalHeaderLabels(
            ['Name', 'Path', 'Size', 'Created', 'Accessed', 'Modified', 'Changed'])
        self.filesTable.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        self.filesTable.setColumnWidth(0, 250)  # Name
        self.filesTable.setColumnWidth(1, 280)  # Path
        self.filesTable.setColumnWidth(2, 100)  # Size
        self.filesTable.setColumnWidth(3, 150)  # Accessed Date
        self.filesTable.setColumnWidth(4, 150)  # Modified Date
        self.filesTable.setColumnWidth(5, 150)  # Created Date
        self.filesTable.setColumnWidth(6, 150)  # Changed Date

        layout.addWidget(self.filesTable)

    def on_search_bar_selected(self):
        search_query = self.searchBar.text().strip()
        if search_query:
            # Call the search_files method with the search query
            self.search_files(search_query)
        else:
            # If the search bar is empty, list files based on the selected checkboxes
            self.on_file_type_selected()

    def search_files(self, search_query):
        # Clear the table before displaying new results
        self.clear()
        files = self.image_handler.search_files(search_query)
        for file in files:
            self.populate_table_row(file)

    def on_file_type_selected(self):
        # Gather all selected extensions.
        selectedExtensions = [ext for ext, cb in self.checkBoxes.items() if cb.isChecked()]

        # If "All Files" is selected, pass None to list all files.
        # If no checkboxes are selected, pass an empty list to display no files.
        # Otherwise, pass the list of selected extensions.
        self.list_files(None if '' in selectedExtensions else ([] if not selectedExtensions else selectedExtensions))

    def create_table_item(self, value, user_role=None):
        item = QTableWidgetItem(value)
        if user_role is not None:
            item.setData(Qt.UserRole, user_role)
        return item

    def insert_table_row(self):
        row_pos = self.filesTable.rowCount()
        self.filesTable.insertRow(row_pos)
        return row_pos

    def populate_table_row(self, file):
        row_pos = self.insert_table_row()
        name_item = QTableWidgetItem(file['name'])
        path_item = QTableWidgetItem(file['path'])

        # Store the numeric size in Qt.UserRole for sorting
        size_item = SizeTableWidgetItem(self.image_handler.get_readable_size(file['size']))
        size_item.setData(Qt.UserRole, file['size'])

        accessed_item = QTableWidgetItem(file['accessed'])
        modified_item = QTableWidgetItem(file['modified'])
        created_item = QTableWidgetItem(file['created'])
        changed_item = QTableWidgetItem(file['changed'])

        self.filesTable.setItem(row_pos, 0, name_item)
        self.filesTable.setItem(row_pos, 1, path_item)
        self.filesTable.setItem(row_pos, 2, size_item)
        self.filesTable.setItem(row_pos, 3, accessed_item)
        self.filesTable.setItem(row_pos, 4, modified_item)
        self.filesTable.setItem(row_pos, 5, created_item)
        self.filesTable.setItem(row_pos, 6, changed_item)

    def list_files(self, extension):
        self.filesTable.setSortingEnabled(False)
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()

        if extension is not None and not extension:  # If extension is an empty list, do not list any files
            return

        files = self.image_handler.list_files(extension)
        for file in files:
            self.populate_table_row(file)

        self.filesTable.setSortingEnabled(True)

    # clear the table
    def clear(self):
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()
        # reset the checkboxes
        for checkBox in self.checkBoxes.values():
            checkBox.setChecked(False)

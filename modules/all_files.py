from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QHeaderView, \
    QGroupBox, QCheckBox, QGridLayout, QScrollArea, QHBoxLayout, QLabel, QSizePolicy, QToolBar, QLineEdit


class SizeTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


class AllFilesWidget(QWidget):
    def __init__(self, image_handler):
        super(AllFilesWidget, self).__init__()
        self.image_handler = image_handler
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Create the toolbar
        self.toolbar = QToolBar()
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.toolbar)

        # Add icon and title to the toolbar
        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap('Icons/icons8-drag-50.png'))  # Update the path to your icon
        self.icon_label.setFixedSize(48, 48)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("All Files")
        self.title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                color: #37c6d0;
                font-weight: bold;
                margin-left: 8px;
            }
        """)
        self.toolbar.addWidget(self.title_label)

        #add the checkboxes to the toolbar
        self.extensionGroupBox = QGroupBox("Select file types")
        self.extensionLayout = QGridLayout()  # Use QGridLayout for checkboxes

        # Define file types
        self.fileTypes = ['', '.txt', '.jpg', '.jpeg', '.png', '.pdf', '.doc',
                            '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        self.checkBoxes = {}

        row = 0
        col = 0
        for fileType in self.fileTypes:
            checkBox = QCheckBox(fileType if fileType else 'All')
            checkBox.stateChanged.connect(self.onFileTypeSelected)
            self.extensionLayout.addWidget(checkBox, row, col)
            self.checkBoxes[fileType] = checkBox
            col += 1
            if col >= 6:
                row += 1
                col = 0

        self.extensionGroupBox.setLayout(self.extensionLayout)
        self.toolbar.addWidget(self.extensionGroupBox)

        # add search bar to search for files by file name or only file extension using '*.jpg' for example
        self.searchBar = QLineEdit()
        self.searchBar.setPlaceholderText("Search for files by name or extension")
        self.searchBar.textChanged.connect(self.onSearchBarTextChanged)
        self.toolbar.addWidget(self.searchBar)


        # Files table setup
        self.filesTable = QTableWidget()
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


    def onSearchBarTextChanged(self):
        searchText = self.searchBar.text()
        if searchText.startswith('*'):
            searchText = searchText[1:]  # Remove '*' if searching by file extension
        self.list_files(searchText)


    def onFileTypeSelected(self):
        # Gather all selected extensions.
        selectedExtensions = [ext for ext, cb in self.checkBoxes.items() if cb.isChecked()]

        # If "All Files" is selected, pass None to list all files.
        # If no checkboxes are selected, pass an empty list to display no files.
        # Otherwise, pass the list of selected extensions.
        self.list_files(None if '' in selectedExtensions else ([] if not selectedExtensions else selectedExtensions))

    def list_files(self, extension):
        self.clear()

        if extension is not None and not extension:  # If extension is an empty list, do not list any files
            return

        files = self.image_handler.list_files(extension)
        for file in files:
            row_pos = self.filesTable.rowCount()
            self.filesTable.insertRow(row_pos)

            name_item = QTableWidgetItem(file['name'])
            self.filesTable.setItem(row_pos, 0, name_item)

            path_item = QTableWidgetItem(file['path'])
            self.filesTable.setItem(row_pos, 1, path_item)

            # Create a QTableWidgetItem for size and set its data for sorting to be the byte value
            size_item = SizeTableWidgetItem(self.format_size(file['size']))
            size_item.setData(Qt.UserRole, file['size'])

            self.filesTable.setItem(row_pos, 2, size_item)
            self.filesTable.setItem(row_pos, 5, QTableWidgetItem(file['created']))
            self.filesTable.setItem(row_pos, 3, QTableWidgetItem(file['accessed']))
            self.filesTable.setItem(row_pos, 4, QTableWidgetItem(file['modified']))
            self.filesTable.setItem(row_pos, 6, QTableWidgetItem(file['changed']))

        self.filesTable.setSortingEnabled(True)

    def format_size(self, size):
        # Format size from bytes to a more readable format
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    # clear the table
    def clear(self):
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()

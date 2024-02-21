from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QHeaderView, \
    QGroupBox, QCheckBox, QGridLayout, QScrollArea, QHBoxLayout, QLabel, QSizePolicy, QToolBar, QLineEdit

from modules.hex_tab import HexViewer


class SizeTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


class FileSearchWidget(QWidget):

    def __init__(self, image_handler):
        super(FileSearchWidget, self).__init__()
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

        #add spacer to the toolbar
        spacer = QWidget()
        spacer.setFixedWidth(50)
        self.toolbar.addWidget(spacer)


        #add the checkboxes to the toolbar
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
            checkBox.stateChanged.connect(self.onFileTypeSelected)
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
        search_query = self.searchBar.text().strip()
        if search_query:
            # Call the search_files method with the search query
            self.search_files(search_query)
        else:
            # If the search bar is empty, list files based on the selected checkboxes
            self.onFileTypeSelected()

    def search_files(self, search_query):
        # Clear the table before displaying new results
        self.clear()
        files = self.image_handler.search_files(search_query)
        for file in files:
            self.populate_table_row(file)


    def onFileTypeSelected(self):
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
        self.filesTable.setItem(row_pos, 0, self.create_table_item(file['name']))
        self.filesTable.setItem(row_pos, 1, self.create_table_item(file['path']))
        self.filesTable.setItem(row_pos, 2, self.create_table_item(self.format_size(file['size']), file['size']))
        self.filesTable.setItem(row_pos, 3, self.create_table_item(file['accessed']))
        self.filesTable.setItem(row_pos, 4, self.create_table_item(file['modified']))
        self.filesTable.setItem(row_pos, 5, self.create_table_item(file['created']))
        self.filesTable.setItem(row_pos, 6, self.create_table_item(file['changed']))

    def list_files(self, extension):
        self.clear()

        if extension is not None and not extension:  # If extension is an empty list, do not list any files
            return

        files = self.image_handler.list_files(extension)
        for file in files:
            self.populate_table_row(file)

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


    #function to pass the file content to hex viewer when a file is clicked


###################

    # def list_files(self, extension):
    #     self.clear()
    #
    #     if extension is not None and not extension:  # If extension is an empty list, do not list any files
    #         return
    #
    #     files = self.image_handler.list_files(extension)
    #     for file in files:
    #         row_pos = self.filesTable.rowCount()
    #         self.filesTable.insertRow(row_pos)
    #
    #         name_item = QTableWidgetItem(file['name'])
    #         self.filesTable.setItem(row_pos, 0, name_item)
    #
    #         path_item = QTableWidgetItem(file['path'])
    #         self.filesTable.setItem(row_pos, 1, path_item)
    #         size_item = SizeTableWidgetItem(self.format_size(file['size']))
    #         size_item.setData(Qt.UserRole, file['size'])
    #         self.filesTable.setItem(row_pos, 2, size_item)
    #         self.filesTable.setItem(row_pos, 5, QTableWidgetItem(file['created']))
    #         self.filesTable.setItem(row_pos, 3, QTableWidgetItem(file['accessed']))
    #         self.filesTable.setItem(row_pos, 4, QTableWidgetItem(file['modified']))
    #         self.filesTable.setItem(row_pos, 6, QTableWidgetItem(file['changed']))
    #
    #     self.filesTable.setSortingEnabled(True)


    # Refactor the code that populates the table into a separate method
    # def populate_table_row(self, file):
    #     row_pos = self.filesTable.rowCount()
    #     self.filesTable.insertRow(row_pos)
    #     self.filesTable.setItem(row_pos, 0, QTableWidgetItem(file['name']))
    #     self.filesTable.setItem(row_pos, 1, QTableWidgetItem(file['path']))
    #     size_item = SizeTableWidgetItem(self.format_size(file['size']))
    #     size_item.setData(Qt.UserRole, file['size'])
    #     self.filesTable.setItem(row_pos, 2, size_item)
    #     self.filesTable.setItem(row_pos, 3, QTableWidgetItem(file['accessed']))
    #     self.filesTable.setItem(row_pos, 4, QTableWidgetItem(file['modified']))
    #     self.filesTable.setItem(row_pos, 5, QTableWidgetItem(file['created']))
    #     self.filesTable.setItem(row_pos, 6, QTableWidgetItem(file['changed']))

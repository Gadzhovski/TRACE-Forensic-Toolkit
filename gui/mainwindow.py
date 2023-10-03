import os
from hashlib import md5

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QTreeWidget, QTabWidget, QTreeWidgetItem,
                               QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem)

from modules.exif_tab import ExifViewer
from modules.hex_tab import HexViewer
from modules.text_tab import TextViewer

from modules.metadata_tab import MetadataViewerManager
from managers.new_database_manager import DatabaseManager
from managers.evidence_utils import EvidenceUtils
from managers.image_manager import ImageManager
from modules.unified_application_manager import UnifiedViewer
from modules.virus_total_tab import VirusTotal


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize instance attributes
        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.db_manager = DatabaseManager("new_database_mappings.db")  # Directly instantiate the DatabaseManager
        self.image_manager = ImageManager()
        self.evidence_utils = EvidenceUtils()
        self.metadata_viewer = MetadataViewerManager(self.current_image_path, self.evidence_utils)

        self.image_manager.operationCompleted.connect(
            lambda success, message: (
                QMessageBox.information(self, "Image Operation", message) if success else QMessageBox.critical(self,
                                                                                                               "Image "
                                                                                                               "Operation",
                                                                                                               message),
                setattr(self, "image_mounted", not self.image_mounted) if success else None)[1]
        )

        self.initialize_ui()

    def initialize_ui(self):
        self.setWindowTitle('GUI4n6')
        self.setGeometry(100, 100, 1200, 800)

        # Create a menu bar
        menu_bar = QMenuBar(self)
        file_menu = QMenu('File', self)

        # Add the "Add Evidence File" action to the File menu
        add_evidence_file_action = file_menu.addAction('Add Evidence File')
        add_evidence_file_action.triggered.connect(self.load_image_evidence)

        # Remove evidence file action
        remove_evidence_file_action = file_menu.addAction('Remove Evidence File')
        remove_evidence_file_action.triggered.connect(self.remove_image_evidence)

        # Add "Image Mounting" submenu to the File menu
        image_mounting_menu = file_menu.addAction('Image Mounting')
        image_mounting_menu.triggered.connect(self.image_manager.mount_image)

        # Add the "Image Unmounting" action to the File menu
        image_unmounting_menu = file_menu.addAction('Image Unmounting')
        image_unmounting_menu.triggered.connect(self.image_manager.dismount_image)

        # Add the "Exit" action to the File menu
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)

        edit_menu = QMenu('Edit', self)
        view_menu = QMenu('View', self)
        tools_menu = QMenu('Tools', self)

        # Add "Dual-Tool Verification" action to the Tools menu
        dual_tool_verification_action = tools_menu.addAction('Dual-Tool Verification')

        help_menu = QMenu('Help', self)
        user_guide_action = help_menu.addAction('User Guide')
        about_action = help_menu.addAction('About')
        menu_bar.addMenu(file_menu)
        menu_bar.addMenu(edit_menu)
        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(help_menu)

        self.setMenuBar(menu_bar)

        main_toolbar = QToolBar('Main Toolbar', self)
        self.addToolBar(Qt.TopToolBarArea, main_toolbar)

        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setIconSize(QSize(16, 16))
        self.tree_viewer.setHeaderHidden(True)

        tree_dock = QDockWidget('Tree Viewer', self)

        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)

        result_viewer = QTabWidget(self)
        self.setCentralWidget(result_viewer)

        # Create a QTableWidget for the Listing
        self.listing_table = QTableWidget()

        # Set icon size for listing table
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(5)  # Assuming 3 columns: Name, Inode, and Description
        self.listing_table.setHorizontalHeaderLabels(['Name', 'Inode', 'Description', 'Size', 'Modified Date'])

        self.listing_table.cellClicked.connect(self.on_listing_table_item_clicked)  ###

        # Add the QTableWidget to your result_viewer QTabWidget
        result_viewer.addTab(self.listing_table, 'Listing')
        result_viewer.addTab(QTextEdit(self), 'Results')
        result_viewer.addTab(QTextEdit(self), 'Deleted Files')

        self.viewer_tab = QTabWidget(self)

        # Create Hex viewer
        self.hex_viewer = HexViewer(self)
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        # Create Text viewer
        self.text_viewer = TextViewer(self)
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        # Create Application viewer
        self.application_viewer = UnifiedViewer(self)
        # remove the borders and spacing
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        # Create File Metadata viewer
        self.metadata_viewer = MetadataViewerManager(self.current_image_path, self.evidence_utils)
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        # Create exif data viewer
        self.exif_viewer = ExifViewer(self)
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        # tab for Virus total api
        self.virus_total_api = VirusTotal()
        self.viewer_tab.addTab(self.virus_total_api, 'Virus Total API')

        self.viewer_dock = QDockWidget('Viewer', self)

        self.viewer_dock.setWidget(self.viewer_tab)

        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        # Set initial size constraints for the dock widget
        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)

        # Connect the visibilityChanged signal to a custom slot
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)

        # Connect the currentChanged signal to
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        # details_area = QTextEdit(self)
        # details_dock = QDockWidget('Details Area', self)
        # details_dock.setWidget(details_area)
        # self.addDockWidget(Qt.RightDockWidgetArea, details_dock)

    def on_viewer_dock_focus(self, visible):
        if visible:  # If the QDockWidget is focused/visible
            self.viewer_dock.setMaximumSize(16777215, 16777215)  # Remove size constraints
        else:  # If the QDockWidget loses focus
            current_height = self.viewer_dock.size().height()  # Get the current height
            self.viewer_dock.setMinimumSize(1200, current_height)
            self.viewer_dock.setMaximumSize(1200, current_height)

    # Clear UI components and reset internal state
    def clear_ui(self):
        self.listing_table.clearContents()
        self.clear_viewers()

        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False

    # Clear all viewers
    def clear_viewers(self):
        self.hex_viewer.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_viewer.clear()
        self.exif_viewer.clear_content()

    def load_image_evidence(self):
        """Open an image."""
        # Open a file dialog to select the image
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.E01);;All Files (*)")
        # Check if a file was selected
        if image_path:
            # Normalize the path
            image_path = os.path.normpath(image_path)

            # Load the image structure into the tree viewer
            self.load_image_structure_into_tree(image_path)

    # Remove all items from the tree viewer
    def remove_image_evidence(self):
        # Check if an image is currently loaded
        if self.current_image_path is None:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        # Remove the image from the tree viewer
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == self.current_image_path:
                root.removeChild(item)
                break

        self.clear_ui()
        QMessageBox.information(self, "Remove Evidence", "Evidence has been removed.")

    # Close the application
    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit Confirmation', 'Are you sure you want to exit?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if self.image_mounted:
                dismount_reply = QMessageBox.question(self, 'Dismount Image',
                                                      'Do you want to dismount the mounted image before exiting?',
                                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                      QMessageBox.StandardButton.Yes)

                if dismount_reply == QMessageBox.StandardButton.Yes:
                    # Assuming you have a method to dismount the image
                    self.image_manager.dismount_image()

            self.cleanup_temp_directory()
            event.accept()
        else:
            event.ignore()

    # def display_content_for_active_tab(self):
    #     item = self.tree_viewer.currentItem()
    #     if not item:
    #         return
    #
    #     data = item.data(0, Qt.UserRole)
    #     inode_number = data.get("inode_number") if data else None
    #     offset = data.get("offset", self.current_offset) if data else self.current_offset
    #
    #     if inode_number:
    #         file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
    #         if file_content:
    #             self.update_viewer_with_file_content(file_content, inode_number, offset)
    def display_content_for_active_tab(self):
        if self.tree_viewer.hasFocus():
            item = self.tree_viewer.currentItem()
            if not item:
                return

            data = item.data(0, Qt.UserRole)
            inode_number = data.get("inode_number") if data else None
            offset = data.get("offset", self.current_offset) if data else self.current_offset

            if inode_number:
                file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
                if file_content:
                    self.update_viewer_with_file_content(file_content, inode_number, offset)
        elif self.listing_table.hasFocus():
            selected_rows = self.listing_table.selectedItems()
            if not selected_rows:
                return
            row = selected_rows[0].row()
            inode_item = self.listing_table.item(row, 1)
            inode_number = inode_item.text()
            file_content = self.evidence_utils.get_file_content(self.current_offset, self.current_image_path,
                                                                inode_number)
            if file_content:
                self.update_viewer_with_file_content(file_content, inode_number, self.current_offset)

    def on_listing_table_item_clicked(self, row, column):
        inode_item = self.listing_table.item(row, 1)
        inode_number = inode_item.text()

        file_content = self.evidence_utils.get_file_content(self.current_offset, self.current_image_path, inode_number)
        if file_content:
            item_name = self.listing_table.item(row, 0).text()
            full_file_path = self.construct_full_file_path_for_listing(item_name)
            self.update_viewer_with_file_content(file_content, inode_number, self.current_offset, full_file_path)

    def construct_full_file_path_for_listing(self, file_name):
        directory_path = self.construct_full_file_path(self.tree_viewer.currentItem())
        return os.path.join(directory_path, file_name)

    def update_viewer_with_file_content(self, file_content, inode_number, offset, full_file_path=None):
        # full_file_path = self.construct_full_file_path(self.tree_viewer.currentItem())
        if not full_file_path:
            full_file_path = self.construct_full_file_path(self.tree_viewer.currentItem())

        index = self.viewer_tab.currentIndex()
        if index == 0:  # Hex tab
            self.hex_viewer.display_hex_content(file_content)
        elif index == 1:  # Text tab
            self.text_viewer.display_text_content(file_content)
        elif index == 2:  # Application tab
            self.display_application_content(file_content, full_file_path)
        elif index == 3:  # File Metadata tab
            self.metadata_viewer.display_metadata(file_content, self.tree_viewer.currentItem(), full_file_path, offset,
                                                  inode_number)
        elif index == 4:  # Exif Data tab
            self.exif_viewer.load_and_display_exif_data(file_content)
        elif index == 5:  # Assuming VirusTotal tab is the 6th tab (0-based index)
            file_hash = md5(file_content).hexdigest()
            self.virus_total_api.set_file_hash(file_hash)

    def display_application_content(self, file_content, full_file_path):
        file_extension = os.path.splitext(full_file_path)[-1].lower()
        file_type = "text"  # default

        audio_extensions = ['.mp3', '.wav', '.aac', '.ogg', '.m4a']
        video_extensions = ['.mp4', '.mkv', '.flv', '.avi', '.mov']

        if file_extension in audio_extensions:
            file_type = "audio"
        elif file_extension in video_extensions:
            file_type = "video"
        self.application_viewer.display(file_content, file_type=file_type, file_extension=file_extension)

    def handle_directory(self, data):
        entries = self.evidence_utils.handle_directory(data, self.current_image_path)
        self.update_listing_table(entries)

    def update_listing_table(self, entries):
        self.listing_table.setRowCount(0)
        for entry in entries:
            entry_parts = entry.split()
            entry_type = entry_parts[0]
            entry_inode = entry_parts[1].split('-')[0]
            entry_name = " ".join(entry_parts[2:])

            description, icon_name, icon_type = self.evidence_utils.determine_file_properties(entry_type, entry_name)
            self.insert_row_into_listing_table(entry_name, entry_inode, description, icon_name, icon_type)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type):
        icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
        icon = QIcon(icon_path)

        # Add new row to the table
        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        name_item = QTableWidgetItem(entry_name)
        name_item.setIcon(icon)  # Set the icon

        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, QTableWidgetItem(entry_inode))
        self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))

    def on_item_clicked(self, item):
        # Clear the viewers first
        self.clear_viewers()
        # set current tab to hex
        self.viewer_tab.setCurrentIndex(0)

        data = item.data(0, Qt.UserRole)
        inode_number = data.get("inode_number") if data else None

        if data is None:  # Check if data is None before proceeding
            return

        # If it's a directory or a partition
        if 'd' in data.get("type", "") or inode_number is None:
            self.handle_directory(data)
            return

        self.display_content_for_active_tab()

    def load_image_structure_into_tree(self, image_path):
        """Load the image structure into the tree viewer."""
        root_item = QTreeWidgetItem(self.tree_viewer)
        root_item.setText(0, image_path)

        # Set the icon for the root item
        root_item.setIcon(0, QIcon(self.db_manager.get_icon_path('device', 'media-optical')))
        # set the icon size for root item
        self.current_image_path = image_path
        self.metadata_viewer.set_image_path(image_path)

        partitions = self.evidence_utils.get_partitions(image_path)

        if not partitions:  # If there are no partitions
            self.populate_tree_with_files(root_item, image_path, None, None)  # Call with default offset and inode
            return

        for partition in partitions:
            offset = partition["start"]
            end_sector = partition["end"]
            formatted_size = self.format_size(partition["size"])
            partition_item = QTreeWidgetItem(root_item)
            partition_item.setText(0,
                                   f"{partition['description']} - {formatted_size} [Sectors: {offset} - {end_sector}]")
            # Set the icon for the partition item
            partition_item.setIcon(0, QIcon(self.db_manager.get_icon_path('device', 'drive-harddisk')))

            self.populate_tree_with_files(partition_item, image_path, offset)

    def populate_tree_with_files(self, parent_item, image_path, offset, inode_number=None):
        """Recursively populate the tree with files and directories."""
        self.current_offset = offset

        if offset is None and inode_number is None:  # No partitions
            entries = self.evidence_utils.list_files(image_path)
        else:
            entries = self.evidence_utils.list_files(image_path, offset, inode_number)

        for entry in entries:
            entry_parts = entry.split()
            entry_type = entry_parts[0]
            entry_name = " ".join(entry_parts[2:])

            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry_name)

            if 'd' in entry_type:  # It's a directory
                self._populate_directory_item(child_item, entry_name, entry_parts, image_path, offset)
            else:  # It's a file
                self._populate_file_item(child_item, entry_name, entry_parts, offset)

    def _populate_directory_item(self, child_item, entry_name, entry_parts, image_path, offset):
        inode_number = entry_parts[1].split('-')[0]

        # Fetch the icon path from the database
        icon_path = self._get_icon_path('folder', entry_name, default="Default_Folder")
        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {"inode_number": inode_number, "offset": offset, "type": "directory"})

        # Check if the folder is empty
        if self.evidence_utils.list_files(image_path, offset, inode_number):
            child_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

    def _populate_file_item(self, child_item, entry_name, entry_parts, offset):
        file_extension = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'
        inode_number = entry_parts[1].split('-')[0]

        # Fetch the icon path from the database
        icon_path = self._get_icon_path('file', file_extension, default="default_file")
        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {"inode_number": inode_number, "offset": offset, "type": "file"})

    def _get_icon_path(self, item_type, name, default=None):
        icon_path = self.db_manager.get_icon_path(item_type, name)
        return icon_path or self.db_manager.get_icon_path(item_type, default)

    def on_item_expanded(self, item):
        data = item.data(0, Qt.UserRole)
        offset = data.get("offset", self.current_offset) if data else self.current_offset
        inode_number = data.get("inode_number") if data else None

        # Check if this folder has been expanded before
        if data and data.get("expanded", False):
            print(f"Item already expanded: {item.text(0)}")
            return  # Skip if already expanded

        if inode_number or offset:
            self.populate_tree_with_files(item, self.current_image_path, offset, inode_number)

        # Mark this folder as expanded
        if data is None:
            data = {}
        data["expanded"] = True
        item.setData(0, Qt.UserRole, data)
        print(f"Item expanded: {item.text(0)}")

    @staticmethod
    def format_size(size_str):
        """Formats a size string by removing leading zeros and expanding the unit."""
        unit = size_str[-1]  # The last character is the unit (K, M, G, T, etc.)
        number = int(size_str[:-1])  # Remove the unit and convert to integer

        # Expand the unit abbreviation
        unit_expanded = {
            'K': 'KB',
            'M': 'MB',
            'G': 'GB',
            'T': 'TB'
        }.get(unit, unit)

        return f"{number} {unit_expanded}"

    @staticmethod
    def cleanup_temp_directory():
        temp_dir_path = os.path.join(os.getcwd(), 'temp')
        for filename in os.listdir(temp_dir_path):
            file_path = os.path.join(temp_dir_path, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    @staticmethod
    def construct_full_file_path(item):
        full_file_path = item.text(0)
        parent_item = item.parent()
        while parent_item is not None:
            full_file_path = f"{parent_item.text(0)}/{full_file_path}"
            parent_item = parent_item.parent()
        return full_file_path

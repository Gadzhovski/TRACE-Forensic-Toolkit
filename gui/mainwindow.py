import os
import subprocess

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QTreeWidget, QTabWidget, QTreeWidgetItem,
                               QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem)

from gui.widgets.exif_viewer import ExifViewer
from gui.widgets.hex_viewer import HexViewer
from gui.widgets.metadata_viewer import MetadataViewer
from gui.widgets.text_viewer import TextViewer
from managers.database_manager import DatabaseManager
from managers.evidence_utils import EvidenceUtils
from managers.image_manager import ImageManager
from managers.unified_viewer_manager import UnifiedViewer


class DetailedAutopsyGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize instance attributes
        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.db_manager = DatabaseManager("icon_mappings.db")  # Directly instantiate the DatabaseManager
        self.image_manager = ImageManager()
        self.evidence_utils = EvidenceUtils()
        self.metadata_viewer = MetadataViewer(self.current_image_path, self.evidence_utils)

        self.image_manager.operationCompleted.connect(self.on_image_operation_completed)
        self.image_manager.showMessage.connect(self.display_message)

        self.initialize_ui()

    def initialize_ui(self):
        self.setWindowTitle('Detailed Autopsy GUI')
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
        image_mounting_menu.triggered.connect(self.mount_image)

        # Add the "Image Unmounting" action to the File menu
        image_unmounting_menu = file_menu.addAction('Image Unmounting')
        image_unmounting_menu.triggered.connect(self.dismount_image)

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
        self.listing_table.setColumnCount(5)  # Assuming 3 columns: Name, Inode, and Description
        self.listing_table.setHorizontalHeaderLabels(['Name', 'Inode', 'Description', 'Size', 'Modified Date'])

        # Add the QTableWidget to your result_viewer QTabWidget
        result_viewer.addTab(self.listing_table, 'Listing')
        result_viewer.addTab(QTextEdit(self), 'Results')
        result_viewer.addTab(QTextEdit(self), 'Deleted Files')

        self.viewer_tab = QTabWidget(self)

        # Create Hex viewer
        self.hex_viewer_widget = HexViewer(self)
        self.viewer_tab.addTab(self.hex_viewer_widget, 'Hex')

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
        self.metadata_viewer = MetadataViewer(self.current_image_path, self.evidence_utils)
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        # Create exif data viewer
        self.exif_viewer = ExifViewer(self)
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        self.viewer_dock = QDockWidget('Viewer', self)

        self.viewer_dock.setWidget(self.viewer_tab)

        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        # Set initial size constraints for the dock widget
        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)

        # Connect the visibilityChanged signal to a custom slot
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)

        # Connect the currentChanged signal to handle_viewer_tab_change
        self.viewer_tab.currentChanged.connect(self.handle_viewer_tab_change)

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

    # Clear UI components and reset internal state
    def clear_ui(self):
        self.listing_table.clearContents()
        self.clear_viewers()

        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False

    # Clear all viewers
    def clear_viewers(self):
        self.hex_viewer_widget.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_viewer.clear()
        self.exif_viewer.clear_content()

    # Remove all items from the tree viewer
    def remove_image_evidence(self):
        # Check if an image is currently loaded
        if self.current_image_path is None:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        # Check if an image is currently mounted
        if self.image_mounted:
            # Prompt the user to confirm if they want to dismount the mounted image
            dismount_reply = QMessageBox.question(self, 'Dismount Image',
                                                  'Do you want to dismount the mounted image before removing it?',
                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                  QMessageBox.StandardButton.Yes)
            if dismount_reply == QMessageBox.StandardButton.Yes:
                self.dismount_image()

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
                    self.dismount_image()

            self.cleanup_temp_directory()
            event.accept()
        else:
            event.ignore()

    def mount_image(self):
        supported_formats = "EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;VHD Files (*.vhd);;VDI Files (" \
                            "*.vdi);;XVA Files (*.xva);;VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow " \
                            "*.qcow2);;All Files (*)"
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Disk Image", "", supported_formats)
        self.image_manager.mount_image(image_path)  # Use ImageManager to mount the image

    def dismount_image(self):
        self.image_manager.dismount_image()  # Use ImageManager to dismount the image

    def on_image_operation_completed(self, success, message):
        if success:
            self.image_mounted = not self.image_mounted  # Toggle the state depending on the operation
            QMessageBox.information(self, "Image Operation", message)
        else:
            QMessageBox.critical(self, "Image Operation", message)

    def display_message(self, title, content):
        QMessageBox.warning(self, title, content)

    def get_icon_path(self, icon_type, name):
        return self.db_manager.get_icon_path(icon_type, name)

    def handle_directory(self, data, item):
        inode_number = data.get("inode_number")
        offset = data.get("offset", self.current_offset)
        entries = self.evidence_utils.list_files(self.current_image_path, offset, inode_number)

        self.listing_table.setRowCount(0)
        for entry in entries:
            entry_type, entry_inode, entry_name = entry.split()[0], entry.split()[1].split('-')[0], entry.split()[-1]

            description = "Directory" if 'd' in entry_type else "File"

            # Determine the icon path based on the file extension or folder name
            icon_path = self.get_icon_path('folder' if 'd' in entry_type else 'file', entry_name)
            icon = QIcon(icon_path)

            # Add new row to the table
            row_position = self.listing_table.rowCount()
            self.listing_table.insertRow(row_position)

            name_item = QTableWidgetItem(entry_name)
            name_item.setIcon(icon)  # Set the icon

            self.listing_table.setItem(row_position, 0, name_item)
            self.listing_table.setItem(row_position, 1, QTableWidgetItem(entry_inode))
            self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))

    def display_hex_content(self, inode_number, offset):
        try:
            # Get the file content using the EvidenceUtils utility class
            file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)

            # Display hex content in the HexViewer widget
            hex_content = file_content.hex()
            self.hex_viewer_widget.display_hex_content(hex_content)

            return file_content  # Return file_content for further processing

        except subprocess.CalledProcessError as e:
            print(f"Error executing icat: {e}")
            return None

    def display_content_for_active_tab(self):
        item = self.tree_viewer.currentItem()
        if not item:
            return

        data = item.data(0, Qt.UserRole)
        inode_number = data.get("inode_number") if data else None
        offset = data.get("offset", self.current_offset) if data else self.current_offset

        # Construct the full path of the file by traversing the tree upwards
        full_file_path = item.text(0)
        parent_item = item.parent()
        while parent_item is not None:
            full_file_path = f"{parent_item.text(0)}/{full_file_path}"
            parent_item = parent_item.parent()

        # Check if the item represents a file
        if inode_number:
            index = self.viewer_tab.currentIndex()
            if index == 0:  # Hex tab
                self.display_hex_content(inode_number, offset)
            elif index == 1:  # Text tab
                file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
                if file_content:
                    self.text_viewer.display_text_content(file_content)
            elif index == 2:  # Application tab
                file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
                if file_content:
                    # Determine the file type based on the file extension
                    file_extension = os.path.splitext(full_file_path)[-1].lower()
                    file_type = "text"  # default

                    # Define known file extensions for audio and video
                    audio_extensions = ['.mp3', '.wav', '.aac', '.ogg', '.m4a']
                    video_extensions = ['.mp4', '.mkv', '.flv', '.avi', '.mov']

                    if file_extension in audio_extensions:
                        file_type = "audio"
                    elif file_extension in video_extensions:
                        file_type = "video"

                    # Pass the file_extension to the display method
                    self.application_viewer.display(file_content, file_type=file_type, file_extension=file_extension)

            elif index == 3:  # File Metadata tab
                file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
                if file_content:
                    self.metadata_viewer.display_metadata(file_content, item, full_file_path, offset, inode_number)
            elif index == 4:  # Exif Data tab
                file_content = self.evidence_utils.get_file_content(offset, self.current_image_path, inode_number)
                if file_content:
                    self.extract_exif_data(file_content)

    def on_item_clicked(self, item):
        # Clear the viewers first
        self.clear_viewers()
        # set current tab to hex
        self.viewer_tab.setCurrentIndex(0)

        data = item.data(0, Qt.UserRole)
        inode_number = data.get("inode_number") if data else None
        offset = data.get("offset", self.current_offset) if data else self.current_offset

        if data is None:  # Check if data is None before proceeding
            return

        # If it's a directory or a partition
        if 'd' in data.get("type", "") or inode_number is None:
            self.handle_directory(data, item)
            return

        self.display_content_for_active_tab()

    def handle_viewer_tab_change(self, index):
        self.display_content_for_active_tab()

    def load_image_structure_into_tree(self, image_path):
        """Load the image structure into the tree viewer."""
        root_item = QTreeWidgetItem(self.tree_viewer)
        root_item.setText(0, image_path)
        root_item.setIcon(0, QIcon(self.get_icon_path('special', 'Image')))
        self.current_image_path = image_path

        self.metadata_viewer.current_image_path = image_path
        self.metadata_viewer.metadata_manager.set_image_path(image_path)

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
            partition_item.setIcon(0, QIcon(self.get_icon_path('special', 'Partition')))

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
            entry_name = " ".join(entry_parts[2:])  # Adjusted parsing

            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry_name)

            if 'd' in entry_type:  # It's a directory
                # Extract inode number
                inode_number = entry.split()[1].split('-')[0]

                # Check if the folder is empty
                is_empty = not bool(self.evidence_utils.list_files(image_path, offset, inode_number))

                # Fetch the icon path from the database
                icon_path = self.get_icon_path('folder', entry_name)
                if not icon_path:
                    icon_path = self.get_icon_path('folder', 'Default_Folder')  # Fallback to default folder icon

                icon = QIcon(icon_path)
                child_item.setIcon(0, icon)
                child_item.setData(0, Qt.UserRole,
                                   {"inode_number": inode_number, "offset": offset, "type": "directory"})

                if not is_empty:
                    child_item.setChildIndicatorPolicy(
                        QTreeWidgetItem.ShowIndicator)  # Show expand arrow only if directory is not empty

            else:  # It's a file
                # Extract the file extension and set the appropriate icon
                file_extension = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'

                # Fetch the icon path from the database
                icon_path = self.get_icon_path('file', file_extension)
                if not icon_path:
                    icon_path = self.get_icon_path('file', 'default_file')  # Fallback to default file icon

                icon = QIcon(icon_path)
                child_item.setIcon(0, icon)

                # Extract inode number for the file
                inode_number = entry.split()[1].split('-')[0]
                child_item.setData(0, Qt.UserRole, {"inode_number": inode_number, "offset": offset, "type": "file"})

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

    def extract_exif_data(self, file_content):
        # Use the ExifViewer widget to load and display EXIF data
        exif_data = self.exif_viewer.manager.load_exif_data(file_content)

        if exif_data:
            # Display the EXIF data using the ExifViewer widget
            self.exif_viewer.display_exif_data(exif_data)
        else:
            self.exif_viewer.clear_content()

        return exif_data

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

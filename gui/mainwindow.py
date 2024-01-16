from magic import Magic
import os
import hashlib
import datetime
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTextEdit, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView)

from managers.database_manager import DatabaseManager
from managers.evidence_utils import ImageHandler
from modules.hex_tab import HexViewer
from modules.exif_tab import ExifViewer
# from modules.metadata_tab import MetadataViewerManager
from modules.text_tab import TextViewer

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
        self.image_handler = None
        self.image_manager = ImageManager()
        self.db_manager = DatabaseManager('new_database_mappings.db')
        self.current_selected_data = None

        # Initialize a list to store evidence files
        self.evidence_files = []

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
        self.setWindowTitle('4n6Factor')
        # set logo for the application
        self.setWindowIcon(QIcon('gui/logo.png'))
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
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)

        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        tree_dock = QDockWidget('Tree Viewer', self)
        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        result_viewer = QTabWidget(self)
        # set qstyle for the tab
        # result_viewer.setStyleSheet("QTabBar::tab { height: 30px; width: 100px; }")
        # modern style for the tab
        # #result_viewer.setStyleSheet("QTabBar::tab { height: 30px; width: 100px; }"
        #                                     "QTabBar::tab:selected { background: #a8a8a8; }"
        #                                     "QTabBar::tab:!selected { background: #d8d8d8; }"
        #                                     "QTabBar::tab:!selected:hover { background: #a8a8a8; }")

        self.setCentralWidget(result_viewer)

        # Create a QTableWidget for the Listing
        self.listing_table = QTableWidget()

        # Set icon size for listing table
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(9)
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Description', 'Size', 'Modified Date', 'Created Date', 'Accessed Date', 'Changed Date',
             'Flags'])

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

        # # Create File Metadata viewer
        # add the metadata text edit
        self.metadata_text_edit = QTextEdit(self)
        self.metadata_text_edit.setReadOnly(True)
        self.viewer_tab.addTab(self.metadata_text_edit, 'File Metadata')

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

    def on_viewer_dock_focus(self, visible):
        if visible:  # If the QDockWidget is focused/visible
            self.viewer_dock.setMaximumSize(16777215, 16777215)  # Remove size constraints
        else:  # If the QDockWidget loses focus
            current_height = self.viewer_dock.size().height()  # Get the current height
            self.viewer_dock.setMinimumSize(1200, current_height)
            self.viewer_dock.setMaximumSize(1200, current_height)

    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)

        self.clear_viewers()
        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False

    # Clear all viewers
    def clear_viewers(self):
        self.hex_viewer.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_text_edit.clear()
        self.exif_viewer.clear_content()

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

    def load_image_evidence(self):
        """Open an image."""
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "",
                                                    "Supported Image Files (*.e01 *.s01 *.l01 *.raw *.img *.dd)")
        if image_path:
            image_path = os.path.normpath(image_path)
            self.image_handler = ImageHandler(image_path)  # Create or update the ImageHandler instance

            self.evidence_files.append(image_path)

            self.current_image_path = image_path  # ensure this line is present
            self.load_partitions_into_tree(image_path)

        partitions = self.image_handler.get_partitions()
        for part in partitions:
            os_version = self.image_handler.get_windows_version(part[2])  # part[2] is the start offset
            # print(f"Partition {part[0]} OS Version: {os_version}")

    def remove_image_evidence(self):
        if not self.evidence_files:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        # Prepare the options for the dialog
        options = self.evidence_files + ["Remove All"]
        selected_option, ok = QInputDialog.getItem(self, "Remove Evidence File",
                                                   "Select an evidence file to remove or 'Remove All':",
                                                   options, 0, False)

        if ok:
            if selected_option == "Remove All":
                # Remove all evidence files
                self.tree_viewer.invisibleRootItem().takeChildren()  # Remove all children from the tree viewer
                self.evidence_files.clear()  # Clear evidence files list
                self.clear_ui()  # Clear the UI
                QMessageBox.information(self, "Remove Evidence", "All evidence files have been removed.")
            else:
                # Remove the selected evidence file
                self.evidence_files.remove(selected_option)
                self.remove_from_tree_viewer(selected_option)
                self.clear_ui()
                QMessageBox.information(self, "Remove Evidence", f"{selected_option} has been removed.")
        # clear all tabs if there are no evidence files loaded
        if not self.evidence_files:
            self.clear_ui()

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == evidence_name:
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        if not self.image_handler.has_partitions():
            # Handle images without partitions here. You can directly load the directory structure
            # of the image if needed.
            root_item_tree = QTreeWidgetItem(self.tree_viewer)
            root_item_tree.setText(0, image_path)
            root_item_tree.setIcon(0, QIcon(self.db_manager.get_icon_path('device', 'media-optical')))
            self.populate_contents(root_item_tree, {"start_offset": 0})
            return

        # Set the image file as the root item in the QTreeWidget
        root_item_tree = QTreeWidgetItem(self.tree_viewer)
        root_item_tree.setText(0, image_path)
        root_item_tree.setIcon(0, QIcon(self.db_manager.get_icon_path('device', 'media-optical')))

        # Load partitions from the image
        partitions = self.image_handler.get_partitions()

        # Assuming a sector size of 512 bytes. Adjust if needed.
        SECTOR_SIZE = 512

        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * SECTOR_SIZE
            readable_size = self.get_readable_size(size_in_bytes)

            item_text = f"vol{addr} ({desc.decode('utf-8')}: {start}-{end}, Size: {readable_size})"
            item = QTreeWidgetItem(root_item_tree)
            item.setText(0, item_text)
            item.setIcon(0, QIcon(self.db_manager.get_icon_path('device', 'drive-harddisk')))
            item.setData(0, Qt.UserRole, {"inode_number": None, "start_offset": start})

            # Check if the partition has contents and set it as expandable
            if self.image_handler.check_partition_contents(start):
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            else:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicatorWhenChildless)

    def get_readable_size(self, size_in_bytes):
        """Convert bytes to a human-readable string (e.g., KB, MB, GB, TB)."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024.0

    def populate_contents(self, item, data, inode=None):
        if self.current_image_path is None:
            return

        entries = self.image_handler.get_directory_contents(data["start_offset"], inode)

        for entry in entries:
            child_item = QTreeWidgetItem(item)
            child_item.setText(0, entry["name"])

            if entry["is_directory"]:
                sub_entries = self.image_handler.get_directory_contents(data["start_offset"], entry["inode_number"])

                if sub_entries:  # If the directory has sub-entries
                    self.populate_directory_item(child_item, entry["name"], entry["inode_number"],
                                                 data["start_offset"])
                    child_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:  # If the directory does not have sub-entries
                    self.populate_directory_item(child_item, entry["name"], entry["inode_number"],
                                                 data["start_offset"])
                    child_item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicatorWhenChildless)
            else:
                self.populate_file_item(child_item, entry["name"], entry["inode_number"], data["start_offset"])

    def on_item_expanded(self, item):
        data = item.data(0, Qt.UserRole)
        if data is None:
            return

        if data.get("inode_number") is None:  # It's a partition
            self.populate_contents(item, data)
        else:  # It's a directory
            self.populate_contents(item, data, data.get("inode_number"))

    def populate_directory_item(self, child_item, entry_name, inode_number, start_offset=None):
        icon_path = self.db_manager.get_icon_path('folder', entry_name)
        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {
            "inode_number": inode_number,
            "type": "directory",
            "start_offset": start_offset
        })

    def populate_file_item(self, child_item, entry_name, inode_number, start_offset):
        file_extension = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'
        icon_path = self.db_manager.get_icon_path('file', file_extension)

        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {
            "inode_number": inode_number,
            "type": "file",
            "start_offset": start_offset,
            "name": entry_name  # Add this line
        })

    def get_file_content(self, inode_number, offset):
        fs = self.image_handler.get_fs_info(offset)
        if not fs:
            return None, None

        try:
            file_obj = fs.open_meta(inode=inode_number)
            if file_obj.info.meta.size == 0:
                print("File has no content or is a special metafile!")
                return None, None

            content = file_obj.read_random(0, file_obj.info.meta.size)
            metadata = file_obj.info.meta  # Collect the metadata

            return content, metadata

        except Exception as e:
            print(f"Error reading file: {e}")
            return None, None

    def on_item_clicked(self, item, column):
        self.clear_viewers()

        data = item.data(0, Qt.UserRole)

        self.current_selected_data = data

        if not data or "inode_number" not in data or "start_offset" not in data:
            return

        if data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))
            self.populate_listing_table(entries, data["start_offset"])
        else:
            file_content, metadata = self.get_file_content(data["inode_number"], data["start_offset"])
            if file_content:
                self.update_viewer_with_file_content(file_content, metadata, data)

            # Call this to make sure the content is displayed based on the active tab
        self.display_content_for_active_tab()

    def update_viewer_with_file_content(self, file_content, metadata, data):  # Add the data parameter here
        index = self.viewer_tab.currentIndex()
        if index == 0:  # Hex tab
            self.hex_viewer.display_hex_content(file_content)
        elif index == 1:  # Text tab
            self.text_viewer.display_text_content(file_content)
        elif index == 2:  # Application tab
            full_file_path = data.get("name", "")  # Retrieve the name from the data dictionary
            self.display_application_content(file_content, full_file_path)
        elif index == 3:  # File Metadata tab
            self.display_metadata_in_tab(metadata, data, file_content)

        elif index == 4:  # Exif Data tab
            self.exif_viewer.load_and_display_exif_data(file_content)
        elif index == 5:  # Assuming VirusTotal tab is the 6th tab (0-based index)
            file_hash = hashlib.md5(file_content).hexdigest()
            self.virus_total_api.set_file_hash(file_hash)

    def display_content_for_active_tab(self):
        if not self.current_selected_data:
            return

        inode_number = self.current_selected_data.get("inode_number")
        offset = self.current_selected_data.get("start_offset", self.current_offset)

        if inode_number:
            file_content, metadata = self.get_file_content(inode_number, offset)
            if file_content:
                self.update_viewer_with_file_content(file_content, metadata,
                                                     self.current_selected_data)  # Use the stored data

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

    def populate_listing_table(self, entries, offset):
        self.listing_table.setRowCount(0)
        for entry in entries:
            entry_name = entry["name"]
            inode_number = entry["inode_number"]
            description = "Directory" if entry["is_directory"] else "File"
            size_in_bytes = entry["size"] if "size" in entry else 0
            readable_size = self.get_readable_size(size_in_bytes)
            created = entry["created"] if "created" in entry else None
            modified = entry["modified"] if "modified" in entry else None
            accessed = entry["accessed"] if "accessed" in entry else None
            changed = entry["changed"] if "changed" in entry else None
            flags = entry["flag(??)"] if "flag(??)" in entry else None

            # Revised logic for determining icon_name and icon_type
            if entry["is_directory"]:
                icon_name, icon_type = 'folder', 'folder'
            else:
                if '.' in entry_name:
                    icon_name = 'file'
                    icon_type = entry_name.split('.')[-1].lower()  # Ensure the extension is in lowercase

                else:
                    icon_name, icon_type = 'file', 'unknown'

            # self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset)
            self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset,
                                               readable_size, modified, created, accessed, changed, flags)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      modified, created, accessed, changed, flags):
        icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
        icon = QIcon(icon_path)

        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        name_item = QTableWidgetItem(entry_name)
        name_item.setIcon(icon)  # Ensure that the icon is set here
        name_item.setData(Qt.UserRole, {
            "inode_number": entry_inode,
            "start_offset": offset,
            "type": "directory" if icon_type == 'folder' else 'file',
            "name": entry_name,
            "size": size,
        })

        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))  # Convert inode to string
        self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
        self.listing_table.setItem(row_position, 3, QTableWidgetItem(size))
        self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(modified)))
        self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(created)))
        self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(accessed)))
        self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))
        self.listing_table.setItem(row_position, 8, QTableWidgetItem(str(flags)))

    def on_listing_table_item_clicked(self, row, column):
        inode_item = self.listing_table.item(row, 1)
        inode_number = int(inode_item.text())
        data = self.listing_table.item(row, 0).data(Qt.UserRole)

        self.current_selected_data = data

        if data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)
            self.populate_listing_table(entries, data["start_offset"])
        else:
            file_content, metadata = self.get_file_content(inode_number, data["start_offset"])
            if file_content:
                self.update_viewer_with_file_content(file_content, metadata, data)  #######

            # Call this to make sure the content is displayed based on the active tab
        self.display_content_for_active_tab()

    @staticmethod
    def cleanup_temp_directory():
        temp_dir_path = os.path.join(os.getcwd(), 'temp')
        for filename in os.listdir(temp_dir_path):
            file_path = os.path.join(temp_dir_path, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    def open_tree_context_menu(self, position):
        # Get the selected item
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            # Check if the selected item is a root item
            if selected_item and selected_item.parent() is None:
                menu = QMenu()
                view_os_info_action = menu.addAction("View Image Information")
                action = menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

                # Handle the action
                if action == view_os_info_action:
                    self.view_os_information(indexes[0])

    def view_os_information(self, index):
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            # Ensure that only the root item triggers the OS information display
            return

        partitions = self.image_handler.get_partitions()
        table = QTableWidget()

        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Partition", "OS Information", "File System Type"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setFont(QFont("Arial", 10, QFont.Bold))
        table.verticalHeader().setVisible(False)

        partition_icon = QIcon('gui/Eleven/24/devices/drive-harddisk.svg')  # Replace with your partition icon path
        os_icon = QIcon('gui/Eleven/24/places/start-here.svg')  # Replace with your OS icon path

        for row, part in enumerate(partitions):
            start_offset = part[2]
            fs_type = self.image_handler.get_fs_type(start_offset)

            os_version = "N/A"
            if fs_type == "NTFS":
                os_version = self.image_handler.get_windows_version(start_offset) or "Unknown"

            table.insertRow(row)
            partition_item = QTableWidgetItem(f"Partition {part[0]}")
            partition_item.setIcon(partition_icon)
            os_version_item = QTableWidgetItem(os_version)
            if os_version != "N/A" and os_version != "Unknown":
                os_version_item.setIcon(os_icon)
            fs_type_item = QTableWidgetItem(fs_type or "Unrecognized")

            table.setItem(row, 0, partition_item)
            table.setItem(row, 1, os_version_item)
            table.setItem(row, 2, fs_type_item)

        table.resizeRowsToContents()
        table.resizeColumnsToContents()

        # Dialog for displaying the table
        dialog = QDialog(self)
        dialog.setWindowTitle("OS and File System Information")
        dialog.resize(460, 320)
        layout = QVBoxLayout(dialog)
        layout.addWidget(table)

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
        buttonBox.accepted.connect(dialog.accept)
        layout.addWidget(buttonBox)

        dialog.exec_()

    def display_metadata_in_tab(self, metadata, data, file_content):
        if not metadata:
            self.metadata_text_edit.setHtml("<b>No metadata available.</b>")
            return

        # Function to convert epoch time to a readable format
        def format_epoch_time(epoch_time):
            if epoch_time:
                return datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
            return 'N/A'

        # Calculate MD5 and SHA-256 hashes
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()

        # Determine MIME type
        mime_type = Magic().from_buffer(file_content)

        # Format the times
        created_time = format_epoch_time(metadata.crtime)
        modified_time = format_epoch_time(metadata.mtime)
        accessed_time = format_epoch_time(metadata.atime)
        changed_time = format_epoch_time(metadata.ctime)

        extended_metadata = f"""
            <style>
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                td, th {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    word-wrap: break-word;
                }}
                th {{
                    background-color: #f2f2f2;
                    text-align: left;
                }}
            </style>
            <b>File Metadata:</b><br>
            <table>
                <tr><th>Attribute</th><th>Value</th></tr>
                <tr><td>Name</td><td>{data.get('name', 'N/A')}</td></tr>
                <tr><td>Inode Number</td><td>{data.get('inode_number', 'N/A')}</td></tr>
                <tr><td>Size</td><td>{metadata.size if metadata.size else 'N/A'}</td></tr>
                <tr><td>Created Time</td><td>{created_time}</td></tr>
                <tr><td>Modified Time</td><td>{modified_time}</td></tr>
                <tr><td>Accessed Time</td><td>{accessed_time}</td></tr>
                <tr><td>Changed Time</td><td>{changed_time}</td></tr>
                <tr><td>MIME Type</td><td>{mime_type}</td></tr>
                <tr><td>MD5 Hash</td><td>{md5_hash}</td></tr>
                <tr><td>SHA-256 Hash</td><td>{sha256_hash}</td></tr>
            </table>
        """

        self.metadata_text_edit.setHtml(extended_metadata)

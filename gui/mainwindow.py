import hashlib
import os

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont, QPalette, QBrush, QAction
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView, QWidget)

from managers.database_manager import DatabaseManager
from managers.evidence_utils import ImageHandler
from managers.image_manager import ImageManager
from modules.about_tab import AboutDialog
from modules.exif_tab import ExifViewer
from modules.file_carving import FileCarvingWidget
from modules.hex_tab import HexViewer
from modules.metadata_tab import MetadataViewer
from modules.registry import RegistryExtractor
from modules.text_tab import TextViewer
from modules.unified_application_manager import UnifiedViewer
from modules.virus_total_tab import VirusTotal
from modules.verification import VerificationWidget
from modules.all_files import FileSearchWidget
from modules.converter import ConversionWidget

SECTOR_SIZE = 512

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

        self.evidence_files = []

        self.image_manager.operationCompleted.connect(
            lambda success, message: (
                QMessageBox.information(self, "Image Operation", message) if success else QMessageBox.critical(self,
                                                                                                               "Image "
                                                                                                               "Operation",
                                                                                                               message),
                setattr(self, "image_mounted", not self.image_mounted) if success else None)[1])

        self.initialize_ui()

    def initialize_ui(self):
        self.setWindowTitle('Trace 1.0.0')
        self.setWindowIcon(QIcon('Icons/logo.png'))

        if os.name == 'nt':
            import ctypes
            myappid = 'Trace'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

        self.setGeometry(100, 100, 1200, 800)

        menu_bar = QMenuBar(self)
        file_actions = {
            'Add Evidence File': self.load_image_evidence,
            'Remove Evidence File': self.remove_image_evidence,
            'Image Mounting': self.image_manager.mount_image,
            'Image Unmounting': self.image_manager.dismount_image,
            'Exit': self.close
        }

        self.create_menu(menu_bar, 'File', file_actions)

        view_menu = QMenu('View', self)

        # Create the "Full Screen" action and connect it to the showFullScreen slot
        full_screen_action = QAction("Full Screen", self)
        full_screen_action.triggered.connect(self.showFullScreen)
        view_menu.addAction(full_screen_action)

        # Create the "Normal Screen" action and connect it to the showNormal slot
        normal_screen_action = QAction("Normal Screen", self)
        normal_screen_action.triggered.connect(self.showNormal)
        view_menu.addAction(normal_screen_action)

        tools_menu = QMenu('Tools', self)

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.verify_image)
        tools_menu.addAction(verify_image_action)

        # # Inside your MainWindow.__init__ or setup method where you define your menu actions
        # conversion_action = QAction("Convert E01 to DD/RAW", self)
        # conversion_action.triggered.connect(lambda: ConversionWidget().exec_())
        # tools_menu.addAction(conversion_action)

        conversion_action = QAction("Convert E01 to DD/RAW", self)
        conversion_action.triggered.connect(self.show_conversion_widget)
        tools_menu.addAction(conversion_action)


        help_menu = QMenu('Help', self)
        help_menu.addAction("About")
        help_menu.triggered.connect(lambda: AboutDialog(self).exec_())

        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(help_menu)

        self.setMenuBar(menu_bar)

        self.main_toolbar = QToolBar('Main Toolbar', self)
        self.main_toolbar.setToolTip("Main Toolbar")

        # add load image button to the toolbar
        load_image_action = QAction(QIcon('Icons/icons8-evidence-48.png'), "Load Image", self)
        load_image_action.triggered.connect(self.load_image_evidence)
        self.main_toolbar.addAction(load_image_action)

        # add remove image button to the toolbar
        remove_image_action = QAction(QIcon('Icons/icons8-evidence-96.png'), "Remove Image", self)
        remove_image_action.triggered.connect(self.remove_image_evidence)
        self.main_toolbar.addAction(remove_image_action)

        # add the separator
        self.main_toolbar.addSeparator()

        # Initialize and add the verify image action
        self.verify_image_button = QAction(QIcon('Icons/icons8-verify-blue.png'), "Verify Image", self)
        self.verify_image_button.triggered.connect(self.verify_image)
        self.main_toolbar.addAction(self.verify_image_button)

        # add the separator
        self.main_toolbar.addSeparator()

        # if os is windows, add the mount and unmount actions to the toolbar
        if os.name == 'nt':
            # Initialize and add the mount image action
            self.mount_image_button = QAction(QIcon('Icons/devices/icons8-hard-disk-48.png'), "Mount Image", self)
            self.mount_image_button.triggered.connect(self.image_manager.mount_image)
            self.main_toolbar.addAction(self.mount_image_button)

            # Initialize and add the unmount image action
            self.unmount_image_button = QAction(QIcon('Icons/devices/icons8-hard-disk-48_red.png'), "Unmount Image",
                                                self)
            self.unmount_image_button.triggered.connect(self.image_manager.dismount_image)
            self.main_toolbar.addAction(self.unmount_image_button)

        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)

        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setIconSize(QSize(16, 16))
        self.tree_viewer.setHeaderHidden(True)
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        tree_dock = QDockWidget('Tree View', self)

        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        self.result_viewer = QTabWidget(self)
        self.setCentralWidget(self.result_viewer)

        self.listing_table = QTableWidget()
        # allow sorting
        self.listing_table.setSortingEnabled(True)

        self.listing_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #D3D3D3;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 5px;
                color: #000000;
                background-color: #F5F5F5;
            }
            QTableWidget::item:selected {
                background-color: #D3D3D3;
            }
            QHeaderView::section {
                background-color: #D3D3D3;
                color: #000000;
                padding: 5px;
                border-style: none;
                border-bottom: 1px solid #F5F5F5;
                border-right: 1px solid #F5F5F5;
            }
            QHeaderView::section:horizontal {
                border-top: 1px solid #F5F5F5;
            }
            QHeaderView::section:vertical {
                border-left: 1px solid #F5F5F5;
            }
        """)
        self.listing_table.verticalHeader().setVisible(False)

        # Use alternate row colors
        self.listing_table.setAlternatingRowColors(True)
        self.listing_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(8)
        self.listing_table.setColumnWidth(0, 250)  # Name
        self.listing_table.setColumnWidth(1, 50)  # Inode
        self.listing_table.setColumnWidth(2, 50)  # Description
        self.listing_table.setColumnWidth(3, 70)  # Size
        self.listing_table.setColumnWidth(4, 150)  # Created Date
        self.listing_table.setColumnWidth(5, 150)  # Accessed Date
        self.listing_table.setColumnWidth(6, 150)  # Modified Date
        self.listing_table.setColumnWidth(7, 150)  # Changed Date
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date', 'Modified Date', 'Changed Date'])
        self.listing_table.itemDoubleClicked.connect(self.on_listing_table_item_clicked)
        self.listing_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listing_table.customContextMenuRequested.connect(self.open_listing_context_menu)
        self.listing_table.setSelectionBehavior(QTableWidget.SelectRows)
        # Set the color of the selected row
        palette = self.listing_table.palette()
        palette.setBrush(QPalette.Highlight, QBrush(Qt.lightGray))  # Change Qt.red to the color you want
        self.listing_table.setPalette(palette)
        header = self.listing_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)

        self.result_viewer.addTab(self.listing_table, 'Listing')

        self.deleted_files_widget = FileCarvingWidget(self)
        self.result_viewer.addTab(self.deleted_files_widget, 'Deleted Files')

        self.registry_extractor_widget = RegistryExtractor(self.image_handler)
        self.result_viewer.addTab(self.registry_extractor_widget, 'Registry')

        # #add tab for displaying all files chosen by user
        self.file_search_widget = FileSearchWidget(self.image_handler)
        self.result_viewer.addTab(self.file_search_widget, 'File Search')

        self.viewer_tab = QTabWidget(self)

        self.hex_viewer = HexViewer(self)
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        self.text_viewer = TextViewer(self)
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        self.application_viewer = UnifiedViewer(self)
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        self.metadata_viewer = MetadataViewer(self.image_handler)
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')


        self.exif_viewer = ExifViewer(self)
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        self.virus_total_api = VirusTotal()
        self.viewer_tab.addTab(self.virus_total_api, 'Virus Total API')

        self.viewer_dock = QDockWidget('Utils', self)
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        # disable all tabs before loading an image file
        self.enable_tabs(False)

    # Inside your MainWindow class
    def show_conversion_widget(self):
        self.conversion_widget = ConversionWidget()
        self.conversion_widget.show()



    def verify_image(self):
        if self.image_handler is None:
            QMessageBox.warning(self, "Verify Image", "No image is currently loaded.")
            return

        # Show the verification widget (assuming it handles its own verification logic)
        self.verification_widget = VerificationWidget(self.image_handler)
        self.verification_widget.show()

        if self.verification_widget.is_verified:
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-48_gren.png'))
        else:
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.deleted_files_widget.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)

    def create_menu(self, menu_bar, menu_name, actions):
        menu = QMenu(menu_name, self)
        for action_name, action_function in actions.items():
            action = menu.addAction(action_name)
            action.triggered.connect(action_function)
        menu_bar.addMenu(menu)
        return menu

    @staticmethod
    def create_tree_item(parent, text, icon_path, data):
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, data)
        return item

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
        self.file_search_widget.clear()
        self.evidence_files.clear()
        self.deleted_files_widget.clear()

    def clear_viewers(self):
        self.hex_viewer.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_viewer.clear()
        self.exif_viewer.clear_content()
        self.registry_extractor_widget.clear()

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

            # pass the image handler to the widgets
            self.deleted_files_widget.set_image_handler(self.image_handler)
            self.registry_extractor_widget.image_handler = self.image_handler
            self.file_search_widget.image_handler = self.image_handler
            self.metadata_viewer.image_handler = self.image_handler

            self.enable_tabs(True)

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
            # disable all tabs
            self.enable_tabs(False)
            # set the icon back to the original
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == evidence_name:
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        root_item_tree = self.create_tree_item(self.tree_viewer, image_path,
                                               self.db_manager.get_icon_path('device', 'media-optical'),
                                               {"start_offset": 0})

        partitions = self.image_handler.get_partitions()

        # Check if the image has partitions or a recognizable file system
        if not partitions:
            if self.image_handler.has_filesystem(0):
                # The image has a filesystem but no partitions, populate root directory
                self.populate_contents(root_item_tree, {"start_offset": 0})
            else:
                # Entire image is considered as unallocated space
                size_in_bytes = self.image_handler.get_size()
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                unallocated_item_text = f"Unallocated Space: Size: {readable_size}"
                self.create_tree_item(root_item_tree, unallocated_item_text,
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": 0,
                                       "end_offset": size_in_bytes // SECTOR_SIZE})
            return

        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * SECTOR_SIZE
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            fs_type = self.image_handler.get_fs_type(start)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            item_text = f"vol{addr} ({desc_str}: {start}-{end}, Size: {readable_size}, FS: {fs_type})"
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')
            data = {"inode_number": None, "start_offset": start, "end_offset": end}
            item = self.create_tree_item(root_item_tree, item_text, icon_path, data)

            # Determine if the partition is special or contains unallocated space
            special_partitions = ["Primary Table", "Safety Table", "GPT Header"]
            is_special = any(special_case in desc_str for special_case in special_partitions)
            is_unallocated = "Unallocated" in desc_str or "Microsoft reserved" in desc_str

            if is_special:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            elif is_unallocated:
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                # Directly add unallocated space under the partition
                self.create_tree_item(item, f"Unallocated Space: Size: {readable_size}",
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": start, "end_offset": end})
            else:
                if self.image_handler.check_partition_contents(start):
                    item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)

    def populate_contents(self, item, data, inode=None):
        if self.current_image_path is None:
            return

        entries = self.image_handler.get_directory_contents(data["start_offset"], inode)

        for entry in entries:
            child_item = QTreeWidgetItem(item)
            child_item.setText(0, entry["name"])

            if entry["is_directory"]:
                sub_entries = self.image_handler.get_directory_contents(data["start_offset"], entry["inode_number"])
                has_sub_entries = bool(sub_entries)

                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=True)
                child_item.setChildIndicatorPolicy(
                    QTreeWidgetItem.ShowIndicator if has_sub_entries else QTreeWidgetItem.DontShowIndicatorWhenChildless)
            else:
                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=False)

    def populate_item(self, child_item, entry_name, inode_number, start_offset, is_directory):
        if is_directory:
            icon_key = 'folder'
        else:
            # For files, determine the icon based on the file extension
            file_extension = entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown'
            icon_key = file_extension

        icon_path = self.db_manager.get_icon_path('folder' if is_directory else 'file', icon_key)

        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {
            "inode_number": inode_number,
            "type": 'directory' if is_directory else 'file',
            "start_offset": start_offset,
            "name": entry_name
        })

    def on_item_expanded(self, item):
        # Check if the item already has children; if so, don't repopulate
        if item.childCount() > 0:
            return

        data = item.data(0, Qt.UserRole)
        if data is None:
            return

        if data.get("inode_number") is None:  # It's a partition
            self.populate_contents(item, data)
        else:  # It's a directory
            self.populate_contents(item, data, data.get("inode_number"))

    def on_item_clicked(self, item, column):
        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        self.current_selected_data = data

        if data.get("is_unallocated"):
            # Handle unallocated space
            unallocated_space = self.image_handler.read_unallocated_space(data["start_offset"], data["end_offset"])
            if unallocated_space is not None:
                # use the update_viewer_with_file_content method to display the unallocated space for hex and text tabs
                #self.update_viewer_with_file_content(unallocated_space, None, data)
                self.update_viewer_with_file_content(unallocated_space, data)######
            else:
                print("Invalid size for unallocated space or unable to read.")
        elif data.get("type") == "directory":
            # # Handle directories
            entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))
            self.populate_listing_table(entries, data["start_offset"])
        elif data.get("inode_number") is not None:
            # Handle files
            file_content, _ = self.image_handler.get_file_content(data["inode_number"], data["start_offset"])##################################
            if file_content:
                self.update_viewer_with_file_content(file_content, data)
            else:
                print("Unable to read file content.")
        elif data.get("start_offset") is not None:
            # Handle partitions
            entries = self.image_handler.get_directory_contents(data["start_offset"], 5)  # 5 is the root inode for NTFS
            self.populate_listing_table(entries, data["start_offset"])
        else:
            print("Clicked item is not a file, directory, or unallocated space.")

        self.display_content_for_active_tab()


    def display_content_for_active_tab(self):
        if not self.current_selected_data:
            return

        inode_number = self.current_selected_data.get("inode_number")
        offset = self.current_selected_data.get("start_offset", self.current_offset)

        if inode_number:
            file_content, _ = self.image_handler.get_file_content(inode_number, offset)
            if file_content:
                self.update_viewer_with_file_content(file_content, self.current_selected_data)  # Use the stored data



    def update_viewer_with_file_content(self, file_content, data):
        index = self.viewer_tab.currentIndex()
        if index == 0:  # Hex tab
            self.hex_viewer.display_hex_content(file_content)
        elif index == 1:  # Text tab
            self.text_viewer.display_text_content(file_content)
        elif index == 2:  # Application tab
            full_file_path = data.get("name", "")  # Retrieve the name from the data dictionary
            self.application_viewer.display_application_content(file_content, full_file_path)
        elif index == 3:  # File Metadata tab
            self.metadata_viewer.display_metadata(data)
        elif index == 4:  # Exif Data tab
            self.exif_viewer.load_and_display_exif_data(file_content)
        elif index == 5:  # Assuming VirusTotal tab is the 6th tab (0-based index)
            file_hash = hashlib.md5(file_content).hexdigest()
            self.virus_total_api.set_file_hash(file_hash)
            self.virus_total_api.set_file_content(file_content, data.get("name", ""))

    def populate_listing_table(self, entries, offset):
        self.listing_table.setRowCount(0)

        for entry in entries:
            entry_name = entry["name"]
            inode_number = entry["inode_number"]
            description = "Directory" if entry["is_directory"] else "File"
            size_in_bytes = entry["size"] if "size" in entry else 0
            # readable_size = self.get_readable_size(size_in_bytes)
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            created = entry["created"] if "created" in entry else None
            accessed = entry["accessed"] if "accessed" in entry else None
            modified = entry["modified"] if "modified" in entry else None
            changed = entry["changed"] if "changed" in entry else None
            icon_name, icon_type = ('folder', 'folder') if entry["is_directory"] else (
                'file', entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown')

            self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset,
                                               readable_size, created, accessed, modified, changed)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      created, accessed, modified, changed):
        icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
        icon = QIcon(icon_path)
        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        name_item = QTableWidgetItem(entry_name)
        name_item.setIcon(icon)
        name_item.setData(Qt.UserRole, {
            "inode_number": entry_inode,
            "start_offset": offset,
            "type": "directory" if icon_type == 'folder' else 'file',
            "name": entry_name,
            "size": size,
        })

        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))
        self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
        self.listing_table.setItem(row_position, 3, QTableWidgetItem(size))
        self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(created)))
        self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(accessed)))
        self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(modified)))
        self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))

    def on_listing_table_item_clicked(self, item):
        row = item.row()
        column = item.column()

        inode_item = self.listing_table.item(row, 1)
        inode_number = int(inode_item.text())
        data = self.listing_table.item(row, 0).data(Qt.UserRole)

        self.current_selected_data = data

        if data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)
            self.populate_listing_table(entries, data["start_offset"])
        else:
            file_content, metadata = self.image_handler.get_file_content(inode_number, data["start_offset"])
            if file_content:
                self.update_viewer_with_file_content(file_content, data)

        # Call this to make sure the content is displayed based on the active tab
        self.display_content_for_active_tab()


    def open_listing_context_menu(self, position):
        # Get the selected item
        indexes = self.listing_table.selectedIndexes()
        if indexes:
            selected_item = self.listing_table.item(indexes[0].row(),
                                                    0)  # Assuming the first column contains the item data
            data = selected_item.data(Qt.UserRole)
            menu = QMenu()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(lambda: self.export_item_from_table(data))

            menu.exec_(self.listing_table.viewport().mapToGlobal(position))

    def export_item_from_table(self, data):
        dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory")
        if dest_dir:
            if data.get("type") == "directory":
                self.export_directory(data["inode_number"], data["start_offset"], dest_dir, data["name"])
            else:
                self.export_file(data["inode_number"], data["start_offset"], dest_dir, data["name"])

    def open_tree_context_menu(self, position):
        # Get the selected item
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            menu = QMenu()

            # Check if the selected item is a root item
            if selected_item and selected_item.parent() is None:
                view_os_info_action = menu.addAction("View Image Information")
                view_os_info_action.triggered.connect(lambda: self.view_os_information(indexes[0]))

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(self.export_item)

            menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

    def export_item(self):
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            data = selected_item.data(0, Qt.UserRole)
            dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory")
            if dest_dir:
                if data.get("type") == "directory":
                    self.export_directory(data["inode_number"], data["start_offset"], dest_dir, selected_item.text(0))
                else:
                    self.export_file(data["inode_number"], data["start_offset"], dest_dir, selected_item.text(0))

    def export_directory(self, inode_number, offset, dest_dir, dir_name):
        new_dest_dir = os.path.join(dest_dir, dir_name)
        os.makedirs(new_dest_dir, exist_ok=True)
        entries = self.image_handler.get_directory_contents(offset, inode_number)
        for entry in entries:
            entry_name = entry.get("name")
            if entry["is_directory"]:
                self.export_directory(entry["inode_number"], offset, new_dest_dir, entry_name)
            else:
                self.export_file(entry["inode_number"], offset, new_dest_dir, entry_name)

    def export_file(self, inode_number, offset, dest_dir, file_name):
        file_content = self.image_handler.get_file_content(inode_number, offset)
        if file_content:
            file_path = os.path.join(dest_dir, file_name)
            with open(file_path, 'wb') as f:
                f.write(file_content)

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

        partition_icon = QIcon('Icons/devices/drive-harddisk.svg')  # Replace with your partition icon path
        os_icon = QIcon('Icons/start-here.svg')  # Replace with your OS icon path

        for row, part in enumerate(partitions):
            start_offset = part[2]  # Start offset of the partition
            fs_type = self.image_handler.get_fs_type(start_offset)

            os_version = None
            if fs_type == "NTFS":
                os_version = self.image_handler.get_windows_version(start_offset)

            table.insertRow(row)
            partition_item = QTableWidgetItem(f"Partition {part[0]}")
            partition_item.setIcon(partition_icon)
            os_version_item = QTableWidgetItem(os_version if os_version else "N/A")
            if os_version:
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

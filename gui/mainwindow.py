import hashlib
import io
import os
import re
import sqlite3
import subprocess

import magic
from PIL import Image
from PIL.ExifTags import TAGS
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QTreeWidget, QLabel, QTabWidget, QTreeWidgetItem,
                               QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem)

from gui.widgets.pdf_viewer import PDFViewer
from managers.unified_viewer import UnifiedViewer


class ImageMounter(QThread):
    imageMounted = Signal(bool, str)  # Signal to indicate mounting completion

    def __init__(self, image_path):
        super().__init__()
        self.image_path = os.path.normpath(image_path)
        self.file_name = os.path.basename(self.image_path)

    def run(self):
        try:
            subprocess.Popen(['tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--mount', '--readonly',
                              '--filename=' + self.image_path])

            self.imageMounted.emit(True, f"Image {self.file_name} mounted successfully.")
        except Exception as e:
            self.imageMounted.emit(False, f"Failed to mount the image. Error: {e}")


class ImageDismounter(QThread):
    imageDismounted = Signal(bool, str)  # Signal to indicate dismounting completion

    def run(self):
        try:
            subprocess.run(['tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--dismount'], check=True)
            self.imageDismounted.emit(True, f"Image was dismounted successfully.")
        except subprocess.CalledProcessError:
            self.imageDismounted.emit(False, "Failed to dismount the image.")


class DatabaseManager:
    def __init__(self, db_path):
        self.db_conn = sqlite3.connect(db_path)

    def __del__(self):
        self.db_conn.close()

    def get_icon_path(self, icon_type, name):
        c = self.db_conn.cursor()
        try:
            c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (icon_type, name))
            result = c.fetchone()

            if result:
                return result[0]
            else:
                # Fallback to default icons
                if icon_type == 'folder':
                    c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (icon_type, 'Default_Folder'))
                    result = c.fetchone()
                    return result[0] if result else 'gui/icons/unknown.png'
                else:
                    return 'gui/icons/unknown.png'
        finally:
            c.close()


class HexFormattingThread(QThread):
    hexFormattingCompleted = Signal(str)  # Signal to emit formatted hex string

    def __init__(self, hex_content):
        super().__init__()
        self.hex_content = hex_content

    def format_hex_chunk(self, start, hex_content):
        hex_part = []
        ascii_repr = []
        for j in range(start, start + 32, 2):
            chunk = hex_content[j:j + 2]
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

    def run(self):
        lines = []
        chunk_starts = range(0, len(self.hex_content), 32)

        for start in chunk_starts:
            lines.append(self.format_hex_chunk(start, self.hex_content))

        formatted_hex = '\n'.join(lines)
        self.hexFormattingCompleted.emit(formatted_hex)


class ImageLoader(QThread):
    imageLoaded = Signal(bool, str)  # Signal to indicate completion

    def __init__(self, gui):
        super().__init__()
        self.gui = gui

    def run(self):
        self.gui.load_image_structure_into_tree()


class DetailedAutopsyGUI(QMainWindow):
    def __init__(self, db_manager):
        super().__init__()

        # Initialize instance attributes
        self.imageDismounter = None
        self.imageMounter = None
        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.hexFormattingThread = None
        self.db_manager = db_manager  # Store the DatabaseManager instance

        self.initialize_ui()

    def initialize_ui(self):

        # [Your GUI initialization code here]
        self.setWindowTitle('Detailed Autopsy GUI')
        self.setGeometry(100, 100, 1200, 800)

        # Create a menu bar
        menu_bar = QMenuBar(self)
        file_menu = QMenu('File', self)

        # Add the "Add Evidence File" action to the File menu
        add_evidence_file_action = file_menu.addAction('Add Evidence File')
        add_evidence_file_action.triggered.connect(self.open_image_evidence)

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
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)
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
        self.hex_viewer = QTextEdit()
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        # Create Text viewer
        self.text_viewer = QTextEdit()
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        # Create Application viewer
        self.application_viewer = UnifiedViewer(self)
        # remove the borders and spacing
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        # Create File Metadata viewer
        self.metadata_viewer = QTextEdit()
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        # Create exif data viewer
        self.exif_viewer = QTextEdit()
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        self.viewer_dock = QDockWidget('Viewer', self)
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        # Set initial size constraints for the dock widget
        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)

        # Connect the visibilityChanged signal to a custom slot
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)

        details_area = QTextEdit(self)
        details_dock = QDockWidget('Details Area', self)
        details_dock.setWidget(details_area)
        self.addDockWidget(Qt.RightDockWidgetArea, details_dock)

    def on_viewer_dock_focus(self, visible):
        if visible:  # If the QDockWidget is focused/visible
            self.viewer_dock.setMaximumSize(16777215, 16777215)  # Remove size constraints
        else:  # If the QDockWidget loses focus
            current_height = self.viewer_dock.size().height()  # Get the current height
            self.viewer_dock.setMinimumSize(1200, current_height)
            self.viewer_dock.setMaximumSize(1200, current_height)

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
        # Assuming self.tree_viewer is your QTreeWidget instance
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == self.current_image_path:
                root.removeChild(item)
                break

        # Clear other UI components, e.g., listing_table, hex_viewer, etc.
        self.listing_table.clearContents()
        self.hex_viewer.clear()
        self.text_viewer.clear()
        self.application_viewer.clear()
        self.metadata_viewer.clear()

        # Reset internal state
        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False

        QMessageBox.information(self, "Remove Evidence", "Evidence has been removed.")

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

            event.accept()
        else:
            event.ignore()

    def mount_image(self):
        supported_formats = "EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;VHD Files (*.vhd);;VDI Files (" \
                            "*.vdi);;XVA Files (*.xva);;VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow " \
                            "*.qcow2);;All Files (*)"
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Disk Image", "", supported_formats)
        if image_path:  # Check if a file was selected
            image_path = os.path.normpath(image_path)  # Normalize the path
            self.imageMounter = ImageMounter(image_path)
            self.imageMounter.imageMounted.connect(self.on_image_mounted)
            self.imageMounter.start()
        else:
            print("No file selected.")

    def on_image_mounted(self, success, message):
        if success:
            self.image_mounted = True
            QMessageBox.information(self, "Image Mounting", message)
        else:
            QMessageBox.critical(self, "Image Mounting", message)

    def dismount_image(self):
        if not self.image_mounted:  # Check if an image is mounted
            QMessageBox.warning(self, "Image Dismounting", "There is no mounted image.")
            return
        self.imageDismounter = ImageDismounter()
        self.imageDismounter.imageDismounted.connect(self.on_image_dismounted)
        self.imageDismounter.start()

    def on_image_dismounted(self, success, message):
        if success:
            self.image_mounted = False
            QMessageBox.information(self, "Image Dismounting", message)
        else:
            QMessageBox.critical(self, "Image Dismounting", message)

    def get_icon_path(self, icon_type, name):
        return self.db_manager.get_icon_path(icon_type, name)

    def on_item_clicked(self, item):
        data = item.data(0, Qt.UserRole)
        inode_number = data.get("inode_number") if data else None
        offset = data.get("offset", self.current_offset) if data else self.current_offset

        index = self.viewer_tab.indexOf(self.application_viewer)
        if isinstance(self.application_viewer, PDFViewer) and index != -1:
            self.viewer_tab.removeTab(index)
            self.application_viewer = QLabel(self.viewer_tab)
            desired_index = self.viewer_tab.indexOf(self.text_viewer) + 1  # One index after Text tab
            self.viewer_tab.insertTab(desired_index, self.application_viewer, 'Application')

        if data is None:  # Check if data is None before proceeding
            return

        # If it's a directory or a partition
        if 'd' in data.get("type", "") or inode_number is None:
            entries = list_files(self.current_image_path, offset, inode_number)
            self.listing_table.setRowCount(0)
            for entry in entries:
                entry_type, entry_inode, entry_name = entry.split()[0], entry.split()[1].split('-')[0], \
                    entry.split()[-1]
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

        # For other types (e.g., QLabel or QTextEdit), clear their content
        if isinstance(self.application_viewer, QLabel) or isinstance(self.application_viewer, QTextEdit):
            self.application_viewer.clear()

        # Construct the full path of the file by traversing the tree upwards
        full_file_path = item.text(0)
        parent_item = item.parent()
        while parent_item is not None:
            full_file_path = f"{parent_item.text(0)}/{full_file_path}"
            parent_item = parent_item.parent()

        if inode_number:  # It's a file
            try:
                cmd = ["tools/sleuthkit-4.12.0-win32/bin/icat.exe", "-o", str(offset), self.current_image_path, str(inode_number)]
                result = subprocess.run(cmd, capture_output=True, text=False, check=True)
                file_content = result.stdout

                # # Display hex content in formatted manner
                hex_content = result.stdout.hex()
                self.hexFormattingThread = HexFormattingThread(hex_content)
                self.hexFormattingThread.hexFormattingCompleted.connect(self.on_hex_formatting_completed)
                self.hexFormattingThread.start()

                # Display text content
                try:
                    text_content = file_content.decode('utf-8')
                except UnicodeDecodeError:
                    text_content = "Non-text file"
                self.text_viewer.setPlainText(text_content)

                self.application_viewer.display(file_content)

                try:
                    exif_data = self.extract_exif_data(file_content)

                    # Convert EXIF data into an HTML table
                    exif_table = "<table border='1'>"
                    for key, value in exif_data:
                        exif_table += f"<tr><td><b>{key}</b></td><td>{value}</td></tr>"
                    exif_table += "</table>"

                    self.exif_viewer.setHtml(exif_table)
                except Exception as e:
                    print(f"Error extracting EXIF data: {e}")
                    self.exif_viewer.setPlainText("Error extracting EXIF data.")

                # Calculate MD5 and SHA-256 hashes
                md5_hash = hashlib.md5(file_content).hexdigest()
                sha256_hash = hashlib.sha256(file_content).hexdigest()

                # Determine MIME type
                mime_type = magic.Magic().from_buffer(file_content)

                # Fetch metadata using istat
                metadata_cmd = ["tools/sleuthkit-4.12.0-win32/bin/istat.exe", "-o", str(offset), self.current_image_path, str(inode_number)]
                metadata_result = subprocess.run(metadata_cmd, capture_output=True, text=True, check=True)
                metadata_content = metadata_result.stdout

                # Extract times using regular expressions
                created_time = re.search(r"Created:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                         metadata_content)
                modified_time = re.search(r"File Modified:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                          metadata_content)
                accessed_time = re.search(r"Accessed:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                          metadata_content)
                changed_time = re.search(r"MFT Modified:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                         metadata_content)

                # Combine all metadata in a table
                extended_metadata = f"<b>Metadata:</b><br><table border='1'>"
                extended_metadata += f"<tr><td>Name</td><td>{item.text(0)}</td></tr>"
                extended_metadata += f"<tr><td>Path</td><td>{full_file_path}</td></tr>"
                extended_metadata += f"<tr><td>Type</td><td>File</td></tr>"
                extended_metadata += f"<tr><td>MIME Type</td><td>{mime_type}</td></tr>"
                extended_metadata += f"<tr><td>Size</td><td>{len(file_content)}</td></tr>"
                extended_metadata += f"<tr><td>Modified</b></td><td>{modified_time.group(1) if modified_time else 'N/A'}</td></tr>"
                extended_metadata += f"<tr><td>Accessed</b></td><td>{accessed_time.group(1) if accessed_time else 'N/A'}</td></tr>"
                extended_metadata += f"<tr><td>Created</b></td><td>{created_time.group(1) if created_time else 'N/A'}</td></tr>"
                extended_metadata += f"<tr><td>Changed</b></td><td>{changed_time.group(1) if changed_time else 'N/A'}</td></tr>"
                extended_metadata += f"<tr><td>MD5</td><td>{md5_hash}</td></tr>"
                extended_metadata += f"<tr><td>SHA-256</td><td>{sha256_hash}</td></tr>"
                extended_metadata += f"</table>"
                extended_metadata += f"<br>"
                extended_metadata += f"<b>From The Sleuth Kit istat Tool</b><pre>{metadata_content}</pre>"
                self.metadata_viewer.setHtml(extended_metadata)

            except subprocess.CalledProcessError as e:
                print(f"Error executing icat: {e}")

        # Set the current tab to Hex after processing the file
        hex_tab_index = self.viewer_tab.indexOf(self.hex_viewer)
        self.viewer_tab.setCurrentIndex(hex_tab_index)

    def on_hex_formatting_completed(self, formatted_hex):
        self.hex_viewer.setPlainText(formatted_hex)

    def load_image_structure_into_tree(self, image_path):
        """Load the image structure into the tree viewer."""
        root_item = QTreeWidgetItem(self.tree_viewer)
        root_item.setText(0, image_path)
        root_item.setIcon(0, QIcon(self.get_icon_path('special', 'Image')))  # Set an icon for the disk
        self.current_image_path = image_path
        partitions = get_partitions(image_path)

        for partition in partitions:
            offset = partition["start"]
            end_sector = partition["end"]
            formatted_size = self.format_size(partition["size"])
            partition_item = QTreeWidgetItem(root_item)
            partition_item.setText(0,
                                   f"{partition['description']} - {formatted_size} [Sectors: {offset} - {end_sector}]")  # Display size, start, and end sectors next to the name
            partition_item.setIcon(0,
                                   QIcon(self.get_icon_path('special', 'Partition')))  # Set an icon for the partition

            self.populate_tree_with_files(partition_item, image_path, offset)

    def format_size(self, size_str):
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

    def populate_tree_with_files(self, parent_item, image_path, offset, inode_number=None):
        """Recursively populate the tree with files and directories."""
        self.current_offset = offset

        entries = list_files(image_path, offset, inode_number)
        for entry in entries:
            entry_type, entry_name = entry.split()[0], entry.split()[-1]
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry_name)

            if 'd' in entry_type:  # It's a directory
                # Extract inode number
                inode_number = entry.split()[1].split('-')[0]

                # Check if the folder is empty
                is_empty = not bool(list_files(image_path, offset, inode_number))

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

    def open_image_evidence(self):
        """Open an image."""
        # Open a file dialog to select the image
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.E01);;All Files (*)")
        # Check if a file was selected
        if image_path:
            # Normalize the path
            image_path = os.path.normpath(image_path)

            # Load the image structure into the tree viewer
            self.load_image_structure_into_tree(image_path)

    def extract_exif_data(self, image_content):
        image = Image.open(io.BytesIO(image_content))

        # Check if the image format supports EXIF
        if image.format != "JPEG":
            return []

        exif_data = image._getexif()
        structured_data = []
        if exif_data is not None:
            for key in exif_data.keys():
                if key in TAGS and isinstance(exif_data[key], (str, bytes)):
                    try:
                        tag_name = TAGS[key]
                        tag_value = exif_data[key]
                        structured_data.append((tag_name, tag_value))
                    except Exception as e:
                        print(f"Error processing key {key}: {e}")
            return structured_data
        return []


def get_partitions(image_path):
    """Get partitions from an image using mmls."""
    result = subprocess.run(
        ["tools/sleuthkit-4.12.0-win32/bin/mmls.exe", "-M", "-B", image_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    partitions = []

    for line in lines:
        parts = line.split()
        # Check if the line starts with a number (partition entry)
        if parts and re.match(r"^\d{3}:", parts[0]):
            start_sector = int(parts[2])
            end_sector = int(parts[3])
            size_str = parts[5]  # Assuming that the size is now directly in the 5th column
            description = " ".join(parts[6:])  # Description of the partition

            # Run fsstat to get the file system type
            fsstat_cmd = ["tools/sleuthkit-4.12.0-win32/bin/fsstat.exe", "-o", str(start_sector), "-t", image_path]
            try:
                fsstat_result = subprocess.run(fsstat_cmd, capture_output=True, text=True, check=True)
                fs_type = fsstat_result.stdout.strip().upper()
                fs_type = f"[{fs_type}]"
            except subprocess.CalledProcessError:
                fs_type = ""

            partitions.append({
                "start": start_sector,
                "end": end_sector,
                "size": size_str,
                "description": f"{description} {fs_type}"
            })

    return partitions


def list_files(image_path, offset, inode_number=None):
    """List files in a directory using fls."""
    try:
        cmd = ["tools/sleuthkit-4.12.0-win32/bin/fls.exe", "-o", str(offset)]
        if inode_number:
            cmd.append(image_path)
            cmd.append(str(inode_number))
            # print(f"Executing command: {' '.join(cmd)}")  # Debugging line
        else:
            cmd.append(image_path)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        return lines
    except subprocess.CalledProcessError as e:
        # print(f"Error executing fls: {e}")
        return []

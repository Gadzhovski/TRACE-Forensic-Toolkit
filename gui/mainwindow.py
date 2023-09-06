import hashlib
import os
import re
import sqlite3
import subprocess

import magic
from PySide6.QtCore import Qt, QThread, Signal, QByteArray
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QStatusBar, QTreeWidget, QLabel, QTabWidget, QTreeWidgetItem,
                               QFileDialog, QMessageBox)



class ImageMounter(QThread):
    imageMounted = Signal(bool, str)  # Signal to indicate mounting completion

    def __init__(self, image_path):
        super().__init__()
        self.image_path = os.path.normpath(image_path)
        self.file_name = os.path.basename(self.image_path)

    def run(self):
        try:
            subprocess.Popen(['Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--mount', '--readonly', '--filename=' + self.image_path])

            self.imageMounted.emit(True, f"Image {self.file_name} mounted successfully.")
        except Exception as e:
            self.imageMounted.emit(False, f"Failed to mount the image. Error: {e}")


class ImageDismounter(QThread):
    imageDismounted = Signal(bool, str)  # Signal to indicate dismounting completion

    def run(self):
        try:
            subprocess.run(['Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--dismount'], check=True)
            self.imageDismounted.emit(True, f"Image was dismounted successfully.")
        except subprocess.CalledProcessError:
            self.imageDismounted.emit(False, "Failed to dismount the image.")


class DatabaseManager:
    def __init__(self, db_path):
        self.db_conn = sqlite3.connect(db_path)

    def __del__(self):
        self.db_conn.close()

    def get_icon_path(self, type, name):
        c = self.db_conn.cursor()
        try:
            c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (type, name))
            result = c.fetchone()

            if result:
                return result[0]
            else:
                # Fallback to default icons
                if type == 'folder':
                    c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (type, 'Default_Folder'))
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

        self.initialize_ui()
        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.hexFormattingThread = None
        self.db_manager = db_manager  # Store the DatabaseManager instance

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
        result_viewer.addTab(QTextEdit(self), 'Listing')
        result_viewer.addTab(QTextEdit(self), 'Results')
        result_viewer.addTab(QTextEdit(self), 'Deleted Files')
        self.setCentralWidget(result_viewer)

        self.viewer_tab = QTabWidget(self)

        # Create Hex viewer
        self.hex_viewer = QTextEdit()
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        # Create Text viewer
        self.text_viewer = QTextEdit()
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        # Create Application viewer
        self.application_viewer = QLabel()
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        # Create File Metadata viewer
        self.metadata_viewer = QTextEdit()
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        # Create a dock widget for the viewer and set the QTabWidget as its widget
        viewer_dock = QDockWidget('Viewer', self)
        viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, viewer_dock)

        details_area = QTextEdit(self)
        details_dock = QDockWidget('Details Area', self)
        details_dock.setWidget(details_area)
        self.addDockWidget(Qt.RightDockWidgetArea, details_dock)
        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)


    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit Confirmation', 'Are you sure you want to exit?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if self.image_mounted:
                dismount_reply = QMessageBox.question(self, 'Dismount Image', 'Do you want to dismount the mounted image before exiting?',
                                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)

                if dismount_reply == QMessageBox.StandardButton.Yes:
                    # Assuming you have a method to dismount the image
                    self.dismount_image()

            event.accept()
        else:
            event.ignore()

    def mount_image(self):
        supported_formats = "EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;VHD Files (*.vhd);;VDI Files (*.vdi);;XVA Files (*.xva);;VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow *.qcow2);;All Files (*)"
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

    def get_icon_path(self, type, name):
        return self.db_manager.get_icon_path(type, name)

    def display_image_from_hex(self, hex_data):
        # Convert hex data to bytes
        byte_data = bytes.fromhex(hex_data)
        # Create a QPixmap from the byte data
        image = QPixmap()
        image.loadFromData(QByteArray(byte_data))

        self.application_viewer.setPixmap(image)

    def on_item_clicked(self, item):
        data = item.data(0, Qt.UserRole)
        inode_number = data.get("inode_number") if data else None
        offset = data.get("offset", self.current_offset) if data else self.current_offset

        # Construct the full path of the file by traversing the tree upwards
        full_file_path = item.text(0)
        parent_item = item.parent()
        while parent_item is not None:
            full_file_path = f"{parent_item.text(0)}/{full_file_path}"
            parent_item = parent_item.parent()

        if inode_number:  # It's a file
            try:
                cmd = ["icat", "-o", str(offset), self.current_image_path, str(inode_number)]
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

                # Check if it's an image file by magic number
                magic_number = file_content[:4]
                if magic_number == b'\xFF\xD8\xFF\xE0' or magic_number == b'\x89\x50\x4E\x47':
                    hex_data = result.stdout.hex()
                    self.display_image_from_hex(hex_data)
                    print(f"Image file: {inode_number}")  # Debugging line
                else:
                    # Optionally, you can clear the image in the 'Application' tab
                    self.application_viewer.clear()

                # Calculate MD5 and SHA-256 hashes
                md5_hash = hashlib.md5(file_content).hexdigest()
                sha256_hash = hashlib.sha256(file_content).hexdigest()

                # Determine MIME type
                mime_type = magic.Magic().from_buffer(file_content)

                # Fetch metadata using istat
                metadata_cmd = ["istat", "-o", str(offset), self.current_image_path, str(inode_number)]
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
                child_item.setData(0, Qt.UserRole, {"inode_number": inode_number, "offset": offset})

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
                child_item.setData(0, Qt.UserRole, {"inode_number": inode_number, "offset": offset})


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


def get_partitions(image_path):
    """Get partitions from an image using mmls."""
    result = subprocess.run(
        ["mmls", "-M", "-B", image_path],
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
            fsstat_cmd = ["fsstat", "-o", str(start_sector), "-t", image_path]
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
        cmd = ["fls", "-o", str(offset)]
        if inode_number:
            cmd.append(image_path)
            cmd.append(str(inode_number))
            #print(f"Executing command: {' '.join(cmd)}")  # Debugging line
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
        #print(f"Error executing fls: {e}")
        return []

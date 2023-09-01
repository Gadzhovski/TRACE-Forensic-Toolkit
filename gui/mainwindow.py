import os
import re
import sqlite3
import subprocess

from PySide6.QtCore import Qt, QThread, Signal, QByteArray
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QStatusBar, QTreeWidget, QLabel, QTabWidget, QTreeWidgetItem,
                               QFileDialog)


class MountThread(QThread):
    mountCompleted = Signal(bool, str)  # Signal to indicate completion

    def __init__(self, cmd):
        super().__init__()
        self.cmd = cmd

    def run(self):
        try:
            result = subprocess.run(self.cmd, capture_output=True, text=True, check=True)
            if "successfully added" in result.stdout.lower():
                self.mountCompleted.emit(True, f"Successfully mounted {self.cmd[-1]}.")
            else:
                self.mountCompleted.emit(False, f"Failed to mount {self.cmd[-1]}.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            self.mountCompleted.emit(False, f"Error executing Arsenal Image Mounter: {e}\n{e.stdout}")


class DetailedAutopsyGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # [Your GUI initialization code here]
        self.setWindowTitle('Detailed Autopsy GUI')
        self.setGeometry(100, 100, 1200, 800)
        # set icon for the application
        # self.setWindowIcon(QIcon('gui/icons/Screenshot.png'))

        # Create a menu bar
        menu_bar = QMenuBar(self)
        file_menu = QMenu('File', self)

        # Add the "Add Evidence File" action to the File menu
        add_evidence_file_action = file_menu.addAction('Add Evidence File')
        add_evidence_file_action.triggered.connect(self.open_image)

        # Add "Image Mounting" submenu to the File menu
        image_mounting_menu = file_menu.addAction('Image Mounting')
        image_mounting_menu.triggered.connect(self.image_mount)

        # Add the "Image Unmounting" action to the File menu
        image_unmounting_menu = file_menu.addAction('Image Unmounting')
        image_unmounting_menu.triggered.connect(self.image_unmount)

        # Add the "Exit" action to the File menu
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)

        edit_menu = QMenu('Edit', self)
        view_menu = QMenu('View', self)
        tools_menu = QMenu('Tools', self)
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
        result_viewer.addTab(QTextEdit(self), 'Extracted Content')
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
        self.current_offset = None
        self.current_image_path = None

    def get_icon_path(self, type, name):
        conn = sqlite3.connect('icon_mappings.db')
        c = conn.cursor()
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
            conn.close()

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

        if inode_number:  # It's a file
            try:
                cmd = ["icat", "-o", str(offset), self.current_image_path, str(inode_number)]
                result = subprocess.run(cmd, capture_output=True, text=False, check=True)
                file_content = result.stdout

                # Display hex content in formatted manner
                hex_content = result.stdout.hex()
                formatted_hex_content = ''
                for i in range(0, len(hex_content), 32):
                    line = hex_content[i:i + 32]
                    ascii_repr = ''.join(
                        [chr(int(line[j:j + 2], 16)) if 32 <= int(line[j:j + 2], 16) <= 126 else '.' for j in
                         range(0, len(line), 2)])
                    hex_part = ' '.join([line[j:j + 2].upper() for j in range(0, len(line), 2)])
                    padding = ' ' * (48 - len(hex_part))  # Add padding to align text
                    formatted_line = f'0x{i // 2:08x}: {hex_part}{padding}  {ascii_repr}'
                    formatted_hex_content += formatted_line + '\n'
                self.hex_viewer.setPlainText(formatted_hex_content)

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

            except subprocess.CalledProcessError as e:
                print(f"Error executing icat: {e}")

    def load_image_structure_into_tree(self, image_path):
        """Load the E01 image structure into the tree viewer."""
        root_item = QTreeWidgetItem(self.tree_viewer)
        root_item.setText(0, image_path)
        root_item.setIcon(0, QIcon(self.get_icon_path('special', 'Image')))  # Set an icon for the disk
        self.current_image_path = image_path
        partitions = get_partitions(image_path)

        for partition in partitions:
            offset = partition["start"]
            end_sector = partition["end"]
            size_in_mb = partition["size"]
            size_in_mb_rounded = int(round(size_in_mb))  # Round to the nearest integer
            partition_item = QTreeWidgetItem(root_item)
            partition_item.setData(0, Qt.UserRole, {"offset": offset})
            partition_item.setText(0,
                                   f"{partition['description']} - {size_in_mb_rounded} MB [Sectors: {offset} - {end_sector}]")  # Display size, start, and end sectors next to the name
            partition_item.setIcon(0,
                                   QIcon(self.get_icon_path('special', 'Partition')))  # Set an icon for the partition
            self.populate_tree_with_files(partition_item, image_path, offset)

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

        if inode_number or offset:
            self.populate_tree_with_files(item, self.current_image_path, offset, inode_number)
        print(f"Item expanded: {item.text(0)}")

    def open_image(self):
        """Open an image."""
        # Open a file dialog to select the image
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.E01);;All Files (*)")
        # Check if a file was selected
        if image_path:
            # Normalize the path
            image_path = os.path.normpath(image_path)
            # Load the image structure into the tree viewer
            self.load_image_structure_into_tree(image_path)

    def image_mount(self):
        # Open a file dialog to select the EWF image
        ewf_path, _ = QFileDialog.getOpenFileName(self, "Select EWF Image", "", "EWF Files (*.E01);;All Files (*)")
        # Normalize the path
        ewf_path = os.path.normpath(ewf_path)
        cmd = ['Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--mount', '--readonly', '--filename=' + ewf_path]
        self.mountThread = MountThread(cmd)
        self.mountThread.mountCompleted.connect(self.on_mount_completed)
        self.mountThread.start()

    def on_mount_completed(self, success, message):
        print(message)

    def image_unmount(self):
        cmd = ['Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--dismount']
        self.unmountThread = MountThread(cmd)
        self.unmountThread.mountCompleted.connect(self.on_mount_completed)
        self.unmountThread.start()


def get_partitions(image_path):
    """Return the partitions of the image."""
    result = subprocess.run(
        ["mmls", "-M", image_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    partitions = []
    sector_size = 512  # Default sector size

    # Detect sector size from mmls output
    for line in lines:
        if "Units are in" in line:
            sector_size = int(line.split("Units are in")[1].split("-byte")[0].strip())
            break

    for line in lines:
        parts = line.split()
        # Check if the line starts with a number (partition entry)
        if parts and re.match(r"^\d{3}:", parts[0]):
            start_sector = int(parts[2])
            end_sector = int(parts[3])
            size_in_sectors = end_sector - start_sector + 1
            size_in_mb = (size_in_sectors * sector_size) / (1024 * 1024)
            partitions.append({
                "start": start_sector,  # Start sector
                "end": end_sector,  # End sector
                "size": size_in_mb,  # Size in MB
                "description": " ".join(parts[5:])  # Description of the partition
            })
    return partitions  # Return both the partitions and the detected sector size


def list_files(image_path, offset, inode_number=None):
    """List files in a directory using fls."""
    try:
        cmd = ["fls", "-o", str(offset)]
        if inode_number:
            cmd.append(image_path)
            cmd.append(str(inode_number))
            print(f"Executing command: {' '.join(cmd)}")  # Debugging line
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
        print(f"Error executing fls: {e}")
        return []

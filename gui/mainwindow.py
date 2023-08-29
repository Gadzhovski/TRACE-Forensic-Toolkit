from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QStatusBar, QTreeWidget, QTabWidget, QVBoxLayout, QWidget, QLabel, QListWidget,
                               QStackedWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QInputDialog)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon

import subprocess
import os
import re

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

        data_sources = QListWidget(self)
        left_dock = QDockWidget('Data Source', self)
        left_dock.setWidget(data_sources)
        self.addDockWidget(Qt.LeftDockWidgetArea, left_dock)
        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setHeaderLabel('Tree Viewer')
        tree_dock = QDockWidget('Tree Viewer', self)
        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)


        result_viewer = QTabWidget(self)
        result_viewer.addTab(QTextEdit(self), 'Extracted Content')
        result_viewer.addTab(QTextEdit(self), 'Results')
        result_viewer.addTab(QTextEdit(self), 'Deleted Files')
        self.setCentralWidget(result_viewer)

        self.viewer = QStackedWidget(self)
        self.viewer.addWidget(QTextEdit(self))
        self.viewer.addWidget(QLabel('Image Viewer'))
        self.viewer.addWidget(QLabel('Video Viewer'))
        viewer_dock = QDockWidget('Viewer', self)
        viewer_dock.setWidget(self.viewer)
        self.addDockWidget(Qt.BottomDockWidgetArea, viewer_dock)


        details_area = QTextEdit(self)
        details_dock = QDockWidget('Details Area', self)
        details_dock.setWidget(details_area)
        self.addDockWidget(Qt.RightDockWidgetArea, details_dock)

        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)
        # Load the E01 image structure into the tree viewer
        self.load_image_structure_into_tree(".\\2020JimmyWilson.E01")



    def load_image_structure_into_tree(self, image_path):
        """Load the E01 image structure into the tree viewer."""
        root_item = QTreeWidgetItem(self.tree_viewer)
        root_item.setText(0, image_path)
        root_item.setIcon(0, QIcon('gui/icons/media-optical.png'))  # Set an icon for the disk

        partitions = get_partitions(image_path)

        for partition in partitions:
            offset = partition["start"]
            end_sector = partition["end"]
            size_in_mb = partition["size"]
            size_in_mb_rounded = int(round(size_in_mb))  # Round to the nearest integer
            partition_item = QTreeWidgetItem(root_item)
            partition_item.setText(0,
                                   f"{partition['description']} - {size_in_mb_rounded} MB [Sectors: {offset} - {end_sector}]")  # Display size, start, and end sectors next to the name

            partition_item.setIcon(0, QIcon('gui/icons/volume.png'))  # Set an icon for the partition

            self.populate_tree_with_files(partition_item, image_path, offset)

    def populate_tree_with_files(self, parent_item, image_path, offset):
        """Recursively populate the tree with files and directories."""
        # Define a dictionary to map file extensions to icon paths
        icon_dict = {
            'txt': 'gui/icons/text-x-generic.png',
            'pdf': 'gui/icons/application-pdf.png',
            'jpg': 'gui/icons/application-image-jpg.png',
            'png': 'gui/icons/application-image-png.png',
            'cd': 'application-x-cd-image.png',
            'iso': 'application-x-cd-image.png',
            'xml': 'gui/icons/application-xml.png',
            'zip': 'file-roller.png',
            'rar': 'file-roller.png',
            'gz': 'file-roller.png',
            'tar': 'file-roller.png',
            'mp4': 'gui/icons/video-x-generic.png',
            'mov': 'gui/icons/video-x-generic.png',
            'avi': 'gui/icons/video-x-generic.png',
            'wmv': 'gui/icons/video-x-generic.png',
            'mp3': 'gui/icons/audio-x-generic.png',
            'wav': 'gui/icons/audio-x-generic.png',
            'xls': 'gui/icons/libreoffice-oasis-spreadsheet.png',
            'xlsx': 'gui/icons/libreoffice-oasis-spreadsheet.png',
            'doc': 'gui/icons/libreoffice-oasis-text.png',
            'docx': 'gui/icons/libreoffice-oasis-text.png',
            'ppt': 'gui/icons/libreoffice-oasis-presentation.png',
            'pptx': 'gui/icons/libreoffice-oasis-presentation.png',
            'eml': 'gui/icons/emblem-mail.png',
            'msg': 'gui/icons/emblem-mail.png',
            'exe': 'gui/icons/application-x-executable.png',
            'html': 'gui/icons/text-html.png',
            'htm': 'gui/icons/text-html.png',

            # Add more mappings here
        }

        folder_icon_dict = {
        'Desktop': 'gui/icons/folder_types/user-desktop.png',
        'Documents': 'gui/icons/folder_types/folder-documents.png',
        'Downloads': 'gui/icons/folder_types/folder-downloads.png',
        'Music': 'gui/icons/folder_types/folder-music.png',
        'Pictures': 'gui/icons/folder_types/folder-pictures.png',
        'Videos': 'gui/icons/folder_types/folder-videos.png',
        'Templates': 'gui/icons/folder_types/folder-templates.png',
        'Public': 'gui/icons/folder_types/folder-public-share.png'}


        entries = list_files(image_path, offset)
        for entry in entries:
            entry_type, entry_name = entry.split()[0], entry.split()[-1]
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry_name)

            if 'd' in entry_type:  # It's a directory
                # Check if the folder name matches any special folder types
                icon_path = folder_icon_dict.get(entry_name, 'gui/icons/folder.png')
                icon = QIcon(icon_path)
                child_item.setIcon(0, icon)
                identifier = entry.split()[2]
                if identifier.replace('-', '').isdigit():  # Check if it's a number or something that can be converted
                    new_offset = int(identifier.split('-')[0])  # Extract the first part before '-'
                    self.populate_tree_with_files(child_item, image_path, new_offset)
            else:  # It's a file
                # Extract the file extension and set the appropriate icon
                file_extension = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'
                icon_path = icon_dict.get(file_extension,
                                          'gui/icons/unknown.png')  # Default to 'unknown' icon if the extension is not in the dictionary
                icon = QIcon(icon_path)
                child_item.setIcon(0, icon)

    def open_image(self):
        """Open an image."""
        # Open a file dialog to select the EWF image
        ewf_path, _ = QFileDialog.getOpenFileName(self, "Select EWF Image", "", "EWF Files (*.E01);;All Files (*)")

        # Normalize the path
        ewf_path = os.path.normpath(ewf_path)

        # Ask the user to enter the offset
        offset, ok = QInputDialog.getInt(self, "Enter Offset", "Enter the offset in sectors:", 0, 0, 1000000000, 1)
        if ok:
            # Load the E01 image structure into the tree viewer
            self.load_image_structure_into_tree(ewf_path)


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
        ["mmls","-M", image_path],
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
            size_in_sectors = end_sector - start_sector + 1
            size_in_mb = (size_in_sectors * 512) / (1024 * 1024)  # Convert size to MB
            partitions.append({
                "start": start_sector, # Start sector
                "end": end_sector, # End sector
                "size": size_in_mb,  # Size in MB
                "description": " ".join(parts[5:])  # Description of the partition
            })
    return partitions

def list_files(image_path, offset):
    """List files in a directory using fls."""
    try:
        result = subprocess.run(
            ["fls", "-o", str(offset), "-r", "-p", image_path],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        return lines
    except subprocess.CalledProcessError as e:
        print(f"Error executing fls: {e}")
        return []


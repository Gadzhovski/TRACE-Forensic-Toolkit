from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QStatusBar, QTreeWidget, QTabWidget, QVBoxLayout, QWidget, QLabel, QListWidget,
                               QStackedWidget, QTreeWidgetItem)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from tools.image_analysis import get_partitions, list_files


class DetailedAutopsyGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # [Your GUI initialization code here]
        self.setWindowTitle('Detailed Autopsy GUI')
        self.setGeometry(100, 100, 1200, 800)

        menu_bar = QMenuBar(self)
        file_menu = QMenu('File', self)
        edit_menu = QMenu('Edit', self)
        view_menu = QMenu('View', self)
        tools_menu = QMenu('Tools', self)
        menu_bar.addMenu(file_menu)
        menu_bar.addMenu(edit_menu)
        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        self.setMenuBar(menu_bar)

        main_toolbar = QToolBar('Main Toolbar', self)
        self.addToolBar(Qt.TopToolBarArea, main_toolbar)

        data_sources = QListWidget(self)
        left_dock = QDockWidget('Data Sources', self)
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

        viewer = QStackedWidget(self)
        viewer.addWidget(QTextEdit(self))
        viewer.addWidget(QLabel('Image Viewer'))
        viewer.addWidget(QLabel('Video Viewer'))
        viewer_dock = QDockWidget('Viewer', self)
        viewer_dock.setWidget(viewer)
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

        partitions = get_partitions(image_path)

        for partition in partitions:
            offset = partition["start"]
            partition_item = QTreeWidgetItem(root_item)
            partition_item.setText(0, partition["description"])

            self.populate_tree_with_files(partition_item, image_path, offset)

    def populate_tree_with_files(self, parent_item, image_path, offset):
        """Recursively populate the tree with files and directories."""
        entries = list_files(image_path, offset)
        for entry in entries:
            entry_type, entry_name = entry.split()[0], entry.split()[-1]
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry_name)
            if entry_type == "d":  # It's a directory
                new_offset = int(entry.split()[2])  # Assuming inode number is the 3rd column
                self.populate_tree_with_files(child_item, image_path, new_offset)


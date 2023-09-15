
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTextEdit,
                               QTreeWidget, QLabel, QTabWidget, QTreeWidgetItem,
                               QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, QWidget, QVBoxLayout,
                               QPushButton)

from managers.hex_viewer_manager import HexFormatter


class HexViewer(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hex_formatter = None

        # Setup UI
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Toolbar with buttons
        toolbar = QToolBar()
        button1 = QPushButton("Button1")
        button2 = QPushButton("Button2")
        # Connect buttons to functions if needed
        # button1.clicked.connect(self.some_function)
        toolbar.addWidget(button1)
        toolbar.addWidget(button2)

        # Add toolbar to layout
        layout.addWidget(toolbar)

        # TextEdit for displaying hex content
        self.text_area = QTextEdit()
        layout.addWidget(self.text_area)

        self.setLayout(layout)

    def display_hex_content(self, hex_content):
        self.hex_formatter = HexFormatter(hex_content)
        formatted_hex = self.hex_formatter.format_hex()
        self.text_area.setPlainText(formatted_hex)

    # Add other functions for button actions or other functionalities as needed

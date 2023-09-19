# text_viewer.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from managers.text_viewer_manager import TextViewerManager


class TextViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = TextViewerManager()

        self.init_ui()

    def init_ui(self):
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

    def display_text_content(self, file_content):
        # Use the manager to load and display text content
        self.manager.load_text_content(file_content)
        text_content = self.manager.get_text_content()
        self.text_edit.setPlainText(text_content)

    def clear_content(self):
        self.text_edit.clear()
        self.manager.clear_content()

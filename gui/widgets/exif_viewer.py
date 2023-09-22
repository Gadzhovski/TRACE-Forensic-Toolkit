# from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
#
# from managers.exif_viewer_manager import ExifViewerManager
#
#
# class ExifViewer(QWidget):
#     def __init__(self, parent=None):
#         super().__init__(parent)
#         self.manager = ExifViewerManager()
#
#         self.init_ui()
#
#     def init_ui(self):
#         self.text_edit = QTextEdit(self)
#         self.text_edit.setReadOnly(True)
#         self.text_edit.setContentsMargins(0, 0, 0, 0)
#
#         layout = QVBoxLayout()
#         layout.setContentsMargins(0, 0, 0, 0)
#         layout.addWidget(self.text_edit)
#         self.setLayout(layout)
#
#     def display_exif_data(self, exif_data):
#         if exif_data:
#             # Create an HTML table from the EXIF data
#             exif_table = "<table border='1'>"
#             for key, value in exif_data:
#                 exif_table += f"<tr><td><b>{key}</b></td><td>{value}</td></tr>"
#             exif_table += "</table>"
#
#             self.text_edit.setHtml(exif_table)
#         else:
#             self.text_edit.clear()
#
#     def clear_content(self):
#         self.text_edit.clear()


# exif_viewer.py

from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from managers.exif_viewer_manager import ExifViewerManager

class ExifViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = ExifViewerManager()
        self.init_ui()

    def init_ui(self):
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setContentsMargins(0, 0, 0, 0)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

    def display_exif_data(self, exif_data):
        if exif_data:
            # Create an HTML table from the EXIF data
            exif_table = "<table border='1'>"
            for key, value in exif_data:
                exif_table += f"<tr><td><b>{key}</b></td><td>{value}</td></tr>"
            exif_table += "</table>"

            self.text_edit.setHtml(exif_table)
        else:
            self.text_edit.clear()

    def clear_content(self):
        self.text_edit.clear()

    def load_and_display_exif_data(self, file_content):
        exif_data = self.manager.load_exif_data(file_content)
        self.display_exif_data(exif_data)

from PySide6.QtWidgets import QWidget, QVBoxLayout, QStackedWidget

from gui.widgets.picture_viewer import PictureViewer
from gui.widgets.pdf_viewer import PDFViewer


class UnifiedViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.stacked_widget = QStackedWidget(self)

        self.picture_viewer = PictureViewer(self)
        self.pdf_viewer = PDFViewer(parent=self)

        self.stacked_widget.addWidget(self.picture_viewer)
        self.stacked_widget.addWidget(self.pdf_viewer)

        self.layout.addWidget(self.stacked_widget)
        self.setLayout(self.layout)

    def display(self, content):
        # Try to identify the type of content
        if content.startswith(b'%PDF'):
            self.pdf_viewer.display(content)
            self.stacked_widget.setCurrentWidget(self.pdf_viewer)
        else:
            # Default to displaying as an image
            self.picture_viewer.display(content)
            self.stacked_widget.setCurrentWidget(self.picture_viewer)

    def clear(self):
        self.picture_viewer.clear()
        self.pdf_viewer.clear()

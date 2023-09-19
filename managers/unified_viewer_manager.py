
from PySide6.QtWidgets import QWidget, QVBoxLayout
from gui.widgets.pdf_viewer import PDFViewer
from gui.widgets.picture_viewer import PictureViewer


class UnifiedViewer(QWidget):
    def __init__(self, parent=None):
        super(UnifiedViewer, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        # Initialize the viewers
        self.pdf_viewer = PDFViewer()
        self.picture_viewer = PictureViewer(self)

        # Add the viewers to the layout
        self.layout.addWidget(self.pdf_viewer)
        self.layout.addWidget(self.picture_viewer)

        # Hide both viewers initially
        self.pdf_viewer.hide()
        self.picture_viewer.hide()

    def display(self, content):
        # A simple check to determine content type.
        # This can be extended to handle other types or be more sophisticated.
        if content.startswith(b"%PDF"):
            self.picture_viewer.hide()
            self.pdf_viewer.show()
            self.pdf_viewer.display(content)
        else:
            self.pdf_viewer.hide()
            self.picture_viewer.show()
            self.picture_viewer.display(content)

    def clear(self):
        self.pdf_viewer.clear()
        self.picture_viewer.clear()

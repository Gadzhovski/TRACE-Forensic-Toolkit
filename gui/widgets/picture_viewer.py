from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget, QScrollArea


class PictureViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignCenter)

        # Create QLabel for displaying the image
        self.image_label = QLabel(self)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidget(self.image_label)
        self.scroll_area.setWidgetResizable(True)
        self.layout.addWidget(self.scroll_area)

        self.setLayout(self.layout)

    def display(self, image_data):
        # Convert byte data to QPixmap
        qt_image = QImage.fromData(image_data)
        pixmap = QPixmap.fromImage(qt_image)
        self.image_label.setPixmap(pixmap)

    def clear(self):
        self.image_label.clear()

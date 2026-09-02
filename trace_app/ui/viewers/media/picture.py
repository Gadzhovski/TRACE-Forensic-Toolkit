"""Image viewer with zoom, rotation and save."""

import logging

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QTransform
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QToolBar, QScrollArea,
                               QFileDialog, QMessageBox, QSizePolicy)

from trace_app.infra.paths import resource_path
from trace_app.infra.constants import TOOLBAR_HEIGHT, TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar

logger = logging.getLogger('TRACE.Viewer.Picture')


class PictureViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.original_pixmap = None  # Store the original QPixmap
        self.original_image_bytes = None  # Store the original image bytes
        self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        # Create a container for the toolbar and the application viewer
        container_widget = QWidget(self)

        container_layout = QVBoxLayout()
        container_layout.setContentsMargins(0, 0, 0, 0)  # Remove any margins
        container_layout.setSpacing(0)  # Remove spacing between toolbar and viewer

        # Create and set up the toolbar
        self.setup_toolbar()

        # Add the toolbar to the container layout
        container_layout.addWidget(self.toolbar)

        self.image_label = QLabel(self)
        self.image_label.setContentsMargins(0, 0, 0, 0)
        self.image_label.setAlignment(Qt.AlignCenter)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setWidget(self.image_label)
        self.scroll_area.setWidgetResizable(True)

        container_layout.addWidget(self.scroll_area)
        container_widget.setLayout(container_layout)
        self.layout.addWidget(container_widget)
        self.setLayout(self.layout)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        # Disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        zoom_in_icon = icons.icon(icons.ZOOM_IN)
        zoom_out_icon = icons.icon(icons.ZOOM_OUT)
        rotate_left_icon = icons.icon(icons.ROTATE_LEFT)
        rotate_right_icon = icons.icon(icons.ROTATE_RIGHT)
        reset_icon = icons.icon(icons.ROTATE_RESET)
        export_icon = icons.icon(icons.SAVE_AS)

        zoom_in_action = QAction(zoom_in_icon, 'Zoom In', self)
        zoom_out_action = QAction(zoom_out_icon, 'Zoom Out', self)
        rotate_left_action = QAction(rotate_left_icon, 'Rotate Left', self)
        rotate_right_action = QAction(rotate_right_icon, 'Rotate Right', self)
        reset_action = QAction(reset_icon, 'Reset', self)
        self.export_action = QAction(export_icon, 'Save Image', self)

        zoom_in_action.triggered.connect(self.zoom_in)
        zoom_out_action.triggered.connect(self.zoom_out)
        rotate_left_action.triggered.connect(self.rotate_left)
        rotate_right_action.triggered.connect(self.rotate_right)
        reset_action.triggered.connect(self.reset)
        self.export_action.triggered.connect(self.export_original_image)

        # Add actions to the toolbar
        self.toolbar.addAction(zoom_in_action)
        self.toolbar.addAction(zoom_out_action)
        self.toolbar.addAction(rotate_left_action)
        self.toolbar.addAction(rotate_right_action)
        self.toolbar.addAction(reset_action)
        self.toolbar.addAction(self.export_action)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)

    def display(self, content):
        self.original_image_bytes = content  # Save the original image bytes
        # Convert byte data to QPixmap
        qt_image = QImage.fromData(content)
        pixmap = QPixmap.fromImage(qt_image)
        self.original_pixmap = pixmap.copy()  # Save the original pixmap
        self.image_label.setPixmap(pixmap)

    def clear(self):
        self.image_label.clear()

    def zoom_in(self):
        self.image_label.setPixmap(self.image_label.pixmap().scaled(
            self.image_label.width() * 1.2, self.image_label.height() * 1.2, Qt.KeepAspectRatio,
            Qt.SmoothTransformation))

    def zoom_out(self):
        self.image_label.setPixmap(self.image_label.pixmap().scaled(
            self.image_label.width() * 0.8, self.image_label.height() * 0.8, Qt.KeepAspectRatio,
            Qt.SmoothTransformation))

    def rotate_left(self):
        transform = QTransform().rotate(-90)
        pixmap = self.image_label.pixmap().transformed(transform)
        self.image_label.setPixmap(pixmap)

    def rotate_right(self):
        transform = QTransform().rotate(90)
        pixmap = self.image_label.pixmap().transformed(transform)
        self.image_label.setPixmap(pixmap)

    def reset(self):
        if self.original_pixmap:
            self.image_label.setPixmap(self.original_pixmap)

    def export_original_image(self):
        # Ensure that an image is currently loaded
        if not self.original_image_bytes:
            QMessageBox.warning(self, "Export Error", "No image is currently loaded.")
            return

        # Ask the user where to save the exported image
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Image", "",
                                                   "PNG (*.png);;JPEG (*.jpg *.jpeg);;All Files (*)")

        # If a location is chosen, save the image
        if file_name:
            with open(file_name, 'wb') as f:
                f.write(self.original_image_bytes)
            QMessageBox.information(self, "Export Success", "Image exported successfully!")

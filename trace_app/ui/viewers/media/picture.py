"""Image viewer with zoom, rotation and save.

Qt decodes most formats itself. What it cannot -- AVIF, JPEG 2000, PSD, PCX,
DDS -- goes through Pillow, so the list of viewable images is the union of
both rather than whichever one happened to be called.
"""

import io
import logging

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QPixmap, QImage, QAction, QTransform
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QToolBar, QScrollArea,
                               QFileDialog)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar, stretch

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

        # Grouped rather than run together: six icons of the same weight in one
        # unbroken row gave no clue which did what. Zoom, then rotate, then
        # reset -- with Save pushed to the right, where the PDF toolbar also
        # puts it, so the two viewers read the same way.
        self.toolbar.addAction(zoom_in_action)
        self.toolbar.addAction(zoom_out_action)

        self.toolbar.addSeparator()
        self.toolbar.addAction(rotate_left_action)
        self.toolbar.addAction(rotate_right_action)

        self.toolbar.addSeparator()
        self.toolbar.addAction(reset_action)

        self.toolbar.addWidget(stretch())
        self.toolbar.addAction(self.export_action)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)

    def display(self, content):
        """Show `content`. Returns '' on success, or why it could not be read.

        A null image used to be set as an empty pixmap, so a corrupt or
        unsupported picture showed as a blank pane -- indistinguishable from
        an image that is genuinely empty.
        """
        self.original_image_bytes = content
        qt_image = QImage.fromData(content)
        problem = ''
        if qt_image.isNull():
            qt_image, problem = _decode_with_pillow(content)
        if qt_image is None or qt_image.isNull():
            self.original_pixmap = None
            self.image_label.clear()
            return problem or "The image data could not be decoded."
        pixmap = QPixmap.fromImage(qt_image)
        self.original_pixmap = pixmap.copy()
        self.image_label.setPixmap(pixmap)
        return ''

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
            message.warning(self, "Export Error", "No image is currently loaded.")
            return

        # Ask the user where to save the exported image
        from trace_app.core.settings import export_dir
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Image", export_dir(),
                                                   "PNG (*.png);;JPEG (*.jpg *.jpeg);;All Files (*)")

        # If a location is chosen, save the image
        if file_name:
            with open(file_name, 'wb') as f:
                f.write(self.original_image_bytes)
            message.information(self, "Export Success", "Image exported successfully!")


def _decode_with_pillow(content):
    """(QImage, '') via Pillow, or (None, reason) when it cannot either.

    Pillow's decompression-bomb guard stays on: a crafted header claiming
    billions of pixels is refused rather than allocated. Only the first frame
    of an animation is shown, as Qt does.
    """
    try:
        from PIL import Image
    except ImportError:
        return None, "Pillow is not installed."
    try:
        with Image.open(io.BytesIO(content)) as image:
            image.load()
            rgba = image.convert('RGBA')
            data = rgba.tobytes('raw', 'RGBA')
            result = QImage(data, rgba.width, rgba.height, rgba.width * 4,
                            QImage.Format_RGBA8888)
            # copy(): the QImage above borrows `data`, which is about to go.
            return result.copy(), ''
    except Image.UnidentifiedImageError:
        return None, ("The content is not in any image format TRACE can read. "
                      "It may be damaged, encrypted, or not an image at all; "
                      "the Hex tab shows the raw bytes.")
    except Image.DecompressionBombError as exc:
        return None, f"Refused: the image claims to be too large to decode "                      f"safely ({exc})."
    except Exception as exc:
        logger.debug("Pillow could not decode the image: %s", exc)
        return None, f"The image data could not be decoded ({exc})."

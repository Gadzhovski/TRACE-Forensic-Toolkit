import logging
from io import BytesIO as io_BytesIO

from PIL import Image
from PIL.ExifTags import TAGS
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from trace_app.ui.widgets.property_table import PropertyTable

logger = logging.getLogger('TRACE.Exif')


class ExifViewerManager:
    def __init__(self):
        self.exif_data = None

    @staticmethod
    def get_exif_data_from_content(file_content):
        """Extract EXIF data from the given file content."""
        try:
            # Open the image from the given content
            image = Image.open(io_BytesIO(file_content))

            # Return None if the image format doesn't support EXIF
            if image.format != "JPEG":
                return None

            # Return the extracted EXIF data
            return image._getexif()
        except Exception as e:
            logger.error(f"Error extracting EXIF data: {e}")
            return None

    def load_exif_data(self, file_content):
        """Load and process the EXIF data from the file content."""
        exif_data = self.get_exif_data_from_content(file_content)
        structured_data = []

        # If EXIF data is found, process it
        if exif_data:
            for key in exif_data.keys():
                if key in TAGS and isinstance(exif_data[key], (str, bytes)):
                    try:
                        tag_name = TAGS[key]
                        tag_value = exif_data[key]
                        structured_data.append((tag_name, tag_value))
                    except Exception as e:
                        logger.error(f"Error processing key {key}: {e}")
            return structured_data
        else:
            return None


class ExifViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Initialize the manager to handle EXIF data
        self.manager = ExifViewerManager()
        self.init_ui()

    def init_ui(self):
        """A single scrolling surface, matching the Metadata pane.

        The table grows to its full content height inside a scroll area rather
        than providing its own scrollbar, so the pane reads top to bottom with
        one scrollbar however short the dock is.
        """
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.scroll = QScrollArea(self)
        self.scroll.setObjectName("metadataScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)

        content = QWidget()
        content.setObjectName("metadataContent")
        inner = QVBoxLayout(content)
        inner.setContentsMargins(12, 10, 12, 12)
        inner.setSpacing(0)

        self.empty_label = QLabel("No EXIF data in this file.", content)
        self.empty_label.setObjectName("emptyStateLabel")
        inner.addWidget(self.empty_label)

        self.table = PropertyTable("Tag", "Value", content)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner.addWidget(self.table)

        inner.addStretch(1)
        self.scroll.setWidget(content)
        layout.addWidget(self.scroll)

    def _fit_to_contents(self):
        """Size the table to its rows; the scroll area handles overflow."""
        rows = self.table.rowCount()
        height = sum(self.table.rowHeight(r) for r in range(rows))
        self.table.setFixedHeight(height + 2 * self.table.frameWidth())
        self.table.setVisible(rows > 0)
        self.empty_label.setVisible(rows == 0)

    def display_exif_data(self, exif_data):
        """Display the provided EXIF tags.

        Previously rendered as an HTML table with an inline stylesheet whose
        colours were hardcoded for a light background, so this pane was
        unreadable in dark mode. A real table follows the application theme.
        """
        self.table.set_rows(list(exif_data) if exif_data else [])
        self._fit_to_contents()

    def clear_content(self):
        """Clear the displayed content."""
        self.table.clear_rows()
        self._fit_to_contents()

    def load_and_display_exif_data(self, file_content):
        """Load the EXIF data from the file content and display it."""
        exif_data = self.manager.load_exif_data(file_content)
        self.display_exif_data(exif_data)

from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from PIL import Image
from PIL.ExifTags import TAGS
import io


class ExifViewerManager:
    def __init__(self):
        # Initialize exif_data attribute to store the EXIF information
        self.exif_data = None

    @staticmethod
    def get_exif_data_from_content(file_content):
        """Extract EXIF data from the given file content."""
        try:
            # Open the image from the given content
            image = Image.open(io.BytesIO(file_content))

            # Return None if the image format doesn't support EXIF
            if image.format != "JPEG":
                return None

            # Return the extracted EXIF data
            return image._getexif()
        except Exception as e:
            print(f"Error extracting EXIF data: {e}")
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
                        print(f"Error processing key {key}: {e}")
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
        """Initialize the user interface components."""
        # Set up a read-only text edit for displaying the EXIF data
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.setContentsMargins(0, 0, 0, 0)

        # Create the layout and add the text edit to it
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.text_edit)

        # Set the layout for the widget
        self.setLayout(layout)

    def display_exif_data(self, exif_data):
        """Display the provided EXIF data in the text edit."""
        if exif_data:
            # Format the EXIF data as an HTML table
            exif_table = "<table border='1'>"
            for key, value in exif_data:
                exif_table += f"<tr><td><b>{key}</b></td><td>{value}</td></tr>"
            exif_table += "</table>"
            self.text_edit.setHtml(exif_table)
        else:
            # Clear the text edit if there's no EXIF data to display
            self.text_edit.clear()

    def clear_content(self):
        """Clear the displayed content."""
        self.text_edit.clear()

    def load_and_display_exif_data(self, file_content):
        """Load the EXIF data from the file content and display it."""
        exif_data = self.manager.load_exif_data(file_content)
        self.display_exif_data(exif_data)
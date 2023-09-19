import os

from PySide6.QtWidgets import QWidget, QVBoxLayout
from gui.widgets.pdf_viewer import PDFViewer
from gui.widgets.picture_viewer import PictureViewer
from gui.widgets.audio_video_viewer import AudioVideoViewer


class UnifiedViewer(QWidget):
    def __init__(self, parent=None):
        super(UnifiedViewer, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        # Initialize the viewers
        self.pdf_viewer = PDFViewer()
        self.picture_viewer = PictureViewer(self)
        self.audio_video_viewer = AudioVideoViewer(self)

        # Add the viewers to the layout
        self.layout.addWidget(self.pdf_viewer)
        self.layout.addWidget(self.picture_viewer)
        self.layout.addWidget(self.audio_video_viewer)

        # Hide all viewers initially
        self.pdf_viewer.hide()
        self.picture_viewer.hide()
        self.audio_video_viewer.hide()

    def display(self, content, file_type="text"):
        # Clear all views first
        self.pdf_viewer.clear()
        self.picture_viewer.clear()
        self.audio_video_viewer.clear()

        # Determine content type and show the appropriate viewer
        if file_type == "text":
            if content.startswith(b"%PDF"):
                self.picture_viewer.hide()
                self.audio_video_viewer.hide()
                self.pdf_viewer.show()
                self.pdf_viewer.display(content)
            else:
                self.pdf_viewer.hide()
                self.audio_video_viewer.hide()
                self.picture_viewer.show()
                self.picture_viewer.display(content)
        elif file_type == "audio_video":
            self.pdf_viewer.hide()
            self.picture_viewer.hide()
            self.audio_video_viewer.show()

            # Save content to a temporary file
            temp_file_path = os.path.join(os.getcwd(), 'temp_media_file')
            with open(temp_file_path, 'wb') as f:
                f.write(content)

            # Pass the path to AudioVideoViewer's display method
            self.audio_video_viewer.display(temp_file_path)

    def clear(self):
        self.pdf_viewer.clear()
        self.picture_viewer.clear()
        self.audio_video_viewer.clear()


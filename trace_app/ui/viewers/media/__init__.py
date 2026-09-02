"""Multi-format file viewer.

UnifiedViewer inspects the content it is handed and delegates to the right
specialised viewer: images, PDFs, or audio/video. Each of those lives in its own
module in this package.
"""

import logging
import mimetypes
import os
import time

from PySide6.QtCore import Qt, QUrl, QSize, QTimer, QBuffer, QByteArray, QIODevice
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QColor, QPen, QPainter
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QToolBar,
                               QPushButton, QMessageBox, QFileDialog, QSizePolicy,
                               QApplication)

from trace_app.core.stream_device import PyTsk3StreamDevice
from trace_app.infra.paths import resource_path
from trace_app.ui.viewers.media.audiovideo import AudioVideoPlayer
from trace_app.ui.viewers.media.pdf import PDFViewer
from trace_app.ui.viewers.media.picture import PictureViewer

logger = logging.getLogger('TRACE.Viewer')

__all__ = ['UnifiedViewer', 'PictureViewer', 'PDFViewer', 'AudioVideoPlayer',
           'PyTsk3StreamDevice']


class UnifiedViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_path = None
        self.main_app = None
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        # Check if Icons directory exists and create it if needed
        self.ensure_icons_directory()

        # Create placeholder widget to show when nothing is loaded
        self.placeholder = QLabel("No content loaded")
        self.placeholder.setObjectName("placeholderLabel")  # For stylesheet targeting
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.placeholder)

        # Initialize viewers as None for lazy loading
        self._pdf_viewer = None
        self._picture_viewer = None
        self._audio_video_player = None

        # Store media buffer for in-memory playback (keeps buffer alive during playback)
        self._media_buffer = None

        # Store stream device and file object for streaming playback from disk images
        self._media_stream_device = None
        self._media_file_obj = None

    def ensure_icons_directory(self):
        """Check if Icons directory exists and create it if needed"""
        # Resolve against the bundled resource dir, not the working directory --
        # a bare "Icons" created a stray folder wherever the app happened to be
        # launched from. In a normal install this directory always exists, so
        # the placeholder-generation below is a no-op.
        icons_dir = resource_path("Icons")
        if not os.path.exists(icons_dir):
            try:
                os.makedirs(icons_dir)
                logger.debug(f"Created missing Icons directory: {icons_dir}")

                # Create missing default icons
                self.create_default_icon(os.path.join(icons_dir, "play.png"), (50, 50), (0, 255, 0))
                self.create_default_icon(os.path.join(icons_dir, "pause.png"), (50, 50), (255, 165, 0))
                self.create_default_icon(os.path.join(icons_dir, "stop.png"), (50, 50), (255, 0, 0))
                self.create_default_icon(os.path.join(icons_dir, "volume.png"), (50, 50), (0, 0, 255))
                self.create_default_icon(os.path.join(icons_dir, "mute.png"), (50, 50), (128, 128, 128))
            except Exception as e:
                logger.error(f"Error creating Icons directory: {e}")

    def create_default_icon(self, path, size, color):
        """Create a simple colored square icon at the specified path"""
        try:
            image = QImage(size[0], size[1], QImage.Format_ARGB32)
            # Use literal transparent color instead of Qt.transparent
            image.fill(QColor(0, 0, 0, 0))

            painter = QPainter(image)
            painter.setPen(QPen(QColor(*color)))
            # Create a QColor with proper alpha channel
            brush_color = QColor(*color)
            brush_color.setAlpha(128)  # Semi-transparent
            painter.setBrush(brush_color)

            if "play" in path:
                # Draw play triangle
                points = [
                    QPoint(10, 10),
                    QPoint(10, 40),
                    QPoint(40, 25)
                ]
                painter.drawPolygon(points)
            elif "pause" in path:
                # Draw pause symbol
                painter.drawRect(15, 10, 8, 30)
                painter.drawRect(27, 10, 8, 30)
            elif "stop" in path:
                # Draw stop symbol
                painter.drawRect(15, 15, 20, 20)
            elif "volume" in path:
                # Draw volume symbol
                painter.drawRect(10, 20, 10, 10)
                painter.drawArc(20, 10, 20, 30, -45 * 16, 90 * 16)
            elif "mute" in path:
                # Draw mute symbol
                painter.drawRect(10, 20, 10, 10)
                painter.drawLine(25, 15, 35, 35)
                painter.drawLine(35, 15, 25, 35)

            painter.end()
            image.save(path)
        except Exception as e:
            logger.error(f"Error creating default icon {path}: {e}")


    def get_pdf_viewer(self):
        """Lazy initialization of PDF viewer"""
        if self._pdf_viewer is None:
            self._pdf_viewer = PDFViewer(self)
            self._pdf_viewer.setVisible(False)
            self.layout.addWidget(self._pdf_viewer)
        return self._pdf_viewer

    def get_picture_viewer(self):
        """Lazy initialization of picture viewer"""
        if self._picture_viewer is None:
            self._picture_viewer = PictureViewer(self)
            self._picture_viewer.setVisible(False)
            self.layout.addWidget(self._picture_viewer)
        return self._picture_viewer

    def get_audio_video_player(self):
        """Lazy initialization of audio/video player"""
        if self._audio_video_player is None:
            self._audio_video_player = AudioVideoPlayer(self)
            self._audio_video_player.setVisible(False)
            self.layout.addWidget(self._audio_video_player)
        return self._audio_video_player

    def load(self, content=None, mime_type=None, path=None, file_obj=None, file_size=None):
        """Load content into the appropriate viewer."""
        # Clear any previous content
        self.clear()
        self.current_path = path

        # Check if we have either content or file_obj
        if not content and not file_obj:
            self.placeholder.setVisible(True)
            return

        try:
            # Process PDF files
            if mime_type.startswith('application/pdf'):
                viewer = self.get_pdf_viewer()
                viewer.display(content)
                viewer.setVisible(True)
                self.placeholder.setVisible(False)
                return True

            # Process images
            elif mime_type.startswith('image/'):
                viewer = self.get_picture_viewer()
                viewer.display(content)
                viewer.setVisible(True)
                self.placeholder.setVisible(False)
                return True

            # Process audio and video - use streaming if file_obj provided, otherwise QBuffer
            elif mime_type.startswith(('audio/', 'video/')):
                player = self.get_audio_video_player()

                # Create a hint URL with the mime type to help the media backend
                # identify the format correctly
                hint_url = QUrl()
                hint_url.setScheme("memory")
                suffix = mimetypes.guess_extension(mime_type) or '.tmp'
                hint_url.setPath(f"media{suffix}")

                # OPTION 1: Stream from pytsk3 file object (for large files from disk images)
                if file_obj is not None and file_size is not None:
                    logger.debug(f"Using streaming playback for {file_size} byte media file")

                    # Create custom stream device
                    self._media_stream_device = PyTsk3StreamDevice(file_obj, file_size, self)

                    # Open the stream device for reading
                    if not self._media_stream_device.open(QIODevice.ReadOnly):
                        logger.error("Failed to open stream device for reading")
                        self.placeholder.setText("Error: Could not open stream device")
                        self.placeholder.setVisible(True)
                        return False

                    # Keep file_obj reference alive
                    self._media_file_obj = file_obj

                    # Set the media source from stream device
                    player.media_player.setSourceDevice(self._media_stream_device, hint_url)

                # OPTION 2: Use QBuffer for in-memory playback (small files or pre-loaded content)
                elif content is not None:
                    # Determine if we should use QBuffer based on size
                    file_size_mb = len(content) / (1024 * 1024)
                    logger.debug(f"Using in-memory playback for {file_size_mb:.2f} MB media file")

                    # Create QBuffer for in-memory playback
                    # QBuffer needs to stay alive during playback, so we store it as instance variable
                    self._media_buffer = QBuffer()

                    # Wrap content in QByteArray and set it to the buffer
                    byte_array = QByteArray(content)
                    self._media_buffer.setData(byte_array)

                    # Open buffer for reading
                    if not self._media_buffer.open(QIODevice.ReadOnly):
                        logger.error("Failed to open media buffer for reading")
                        self.placeholder.setText("Error: Could not open media buffer")
                        self.placeholder.setVisible(True)
                        return False

                    # Set the media source from buffer
                    player.media_player.setSourceDevice(self._media_buffer, hint_url)

                else:
                    self.placeholder.setText("Error: No content or stream source provided")
                    self.placeholder.setVisible(True)
                    return False

                player.setVisible(True)
                self.placeholder.setVisible(False)

                # For audio files, configure for audio-only mode
                if mime_type.startswith('audio/'):
                    try:
                        player.set_audio_only_mode(True)
                    except Exception as e:
                        logger.error(f"Warning: Could not set audio-only mode: {e}")

                return True

            # Unsupported file type
            else:
                self.placeholder.setText(f"Unsupported file type: {mime_type}")
                self.placeholder.setVisible(True)
                return False

        except Exception as e:
            self.placeholder.setText(f"Error loading content: {str(e)}")
            self.placeholder.setVisible(True)
            return False

    def clear(self):
        """Clear all viewers and free up resources."""
        # Hide all viewers
        if self._pdf_viewer:
            self._pdf_viewer.clear()
            self._pdf_viewer.setVisible(False)

        if self._picture_viewer:
            self._picture_viewer.clear()
            self._picture_viewer.setVisible(False)

        # Clean up media player
        if self._audio_video_player:
            try:
                # Stop playback
                self._audio_video_player.stop()
            except Exception as e:
                logger.error(f"Error stopping media player: {e}")
            self._audio_video_player.setVisible(False)

        # Clean up media buffer
        if self._media_buffer:
            try:
                if self._media_buffer.isOpen():
                    self._media_buffer.close()
                self._media_buffer = None
            except Exception as e:
                logger.error(f"Error closing media buffer: {e}")

        # Clean up stream device - with safety delay
        if self._media_stream_device:
            # Store reference for delayed cleanup
            old_stream_device = self._media_stream_device
            old_file_obj = self._media_file_obj

            # Clear references immediately
            self._media_stream_device = None
            self._media_file_obj = None

            # Close the device after a short delay to let background threads finish
            # This is non-blocking and happens asynchronously
            def delayed_cleanup():
                try:
                    if old_stream_device and old_stream_device.isOpen():
                        old_stream_device.close()
                except Exception as e:
                    logger.error(f"Error in delayed stream device cleanup: {e}")

            # Schedule cleanup after 100ms (non-blocking)
            QTimer.singleShot(100, delayed_cleanup)
        else:
            # No stream device, just clear file object
            self._media_file_obj = None

        # Show the placeholder
        self.placeholder.setText("No content loaded")
        self.placeholder.setVisible(True)
        self.current_path = None

    def display_application_content(self, file_content, full_file_path):
        """Wrapper for backward compatibility - converts file extension to MIME type."""
        file_extension = os.path.splitext(full_file_path)[-1].lower()
        mime_type = None

        # Map common extensions to MIME types
        if file_extension in ['.pdf']:
            mime_type = 'application/pdf'
        elif file_extension in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            mime_type = f'image/{file_extension[1:]}'
        elif file_extension in ['.mp3', '.wav', '.ogg', '.aac', '.m4a']:
            mime_type = f'audio/{file_extension[1:]}'
        elif file_extension in ['.mp4', '.mkv', '.flv', '.avi', '.mov', '.wmv']:
            mime_type = 'video/mp4'
        else:
            # Default to binary data
            mime_type = 'application/octet-stream'

        # Call the new load method with the determined MIME type
        return self.load(file_content, mime_type, full_file_path)

    def closeEvent(self, event):
        """Handle proper cleanup when the widget is closed"""
        # Make sure to stop any media playback
        if self._audio_video_player:
            try:
                self._audio_video_player.stop()
            except RuntimeError as e:
                logger.debug("Media player already gone during close: %s", e)

        # Clean up media buffer
        if self._media_buffer:
            try:
                if self._media_buffer.isOpen():
                    self._media_buffer.close()
                self._media_buffer = None
            except RuntimeError as e:
                logger.debug("Media buffer already closed: %s", e)

        # Clean up stream device (immediate, not delayed)
        if self._media_stream_device:
            try:
                if self._media_stream_device.isOpen():
                    self._media_stream_device.close()
                self._media_stream_device = None
            except RuntimeError as e:
                logger.debug("Stream device already closed: %s", e)

        # Release file object
        self._media_file_obj = None

        # Accept the close event
        super().closeEvent(event)

    def __del__(self):
        """Ensure proper cleanup when the object is garbage collected"""
        # Clean up media resources
        try:
            if self._media_buffer and self._media_buffer.isOpen():
                self._media_buffer.close()
            if self._media_stream_device and self._media_stream_device.isOpen():
                self._media_stream_device.close()
            self._media_file_obj = None
        except Exception:
            # __del__ can run during interpreter shutdown, when globals and
            # even the logger may already be torn down. Nothing useful can be
            # done or reported here.
            pass

    def shutdown(self):
        """Properly shut down all resources, especially media players.
        Call this method before the application exits."""
        try:
            # Force close any open viewers first
            if self._pdf_viewer:
                self._pdf_viewer.clear()

            if self._picture_viewer:
                self._picture_viewer.clear()

            # Explicit shutdown of audio/video player
            if self._audio_video_player:
                try:
                    # Stop media playback and remove references
                    self._audio_video_player.safe_stop()
                    QApplication.processEvents()

                    # Release reference
                    player = self._audio_video_player
                    self._audio_video_player = None
                except Exception as e:
                    logger.error(f"Error during audio/video player shutdown: {e}")

            # Clean up media buffer
            if self._media_buffer:
                try:
                    if self._media_buffer.isOpen():
                        self._media_buffer.close()
                    self._media_buffer = None
                except Exception as e:
                    logger.error(f"Error closing media buffer during shutdown: {e}")

            # Clean up stream device
            if self._media_stream_device:
                try:
                    if self._media_stream_device.isOpen():
                        self._media_stream_device.close()
                    self._media_stream_device = None
                except Exception as e:
                    logger.error(f"Error closing stream device during shutdown: {e}")

            # Release file object reference
            self._media_file_obj = None

            # Process any pending events
            QApplication.processEvents()

        except Exception as e:
            logger.error(f"Error during UnifiedViewer shutdown: {e}")

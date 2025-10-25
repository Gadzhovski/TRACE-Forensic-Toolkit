import tempfile
import os
from ctypes import cast, POINTER
from weakref import WeakValueDictionary
import mimetypes
import platform
import time

from PySide6.QtCore import Qt, QUrl, Slot, QSize, QTimer, QPoint
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QPageLayout, QPainter, QColor, QPen, QTransform
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtPrintSupport import QPrinter, QPrintDialog
from PySide6.QtWidgets import (QToolBar, QMessageBox, QScrollArea, QLineEdit, QFileDialog, QApplication)
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QSlider, QLabel, QHBoxLayout, QComboBox, \
    QSpacerItem, QSizePolicy
# from comtypes import CLSCTX_ALL
from fitz import open as fitz_open, Matrix

# from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

if os.name == "nt":  # Windows
    from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
    from comtypes import CLSCTX_ALL


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
        self.placeholder.setAlignment(Qt.AlignCenter)
        # Use explicit colors instead of named colors
        self.placeholder.setStyleSheet(
            "background-color: rgb(240, 240, 240); font-size: 16px; color: rgb(136, 136, 136); padding: 10px;")
        self.layout.addWidget(self.placeholder)

        # Initialize viewers as None for lazy loading
        self._pdf_viewer = None
        self._picture_viewer = None
        self._audio_video_player = None

        # Set up a timer for cleanup of temporary files
        self.cleanup_timer = QTimer(self)
        self.cleanup_timer.timeout.connect(self.cleanup_temporary_files)
        self.cleanup_timer.start(5 * 60 * 1000)  # Cleanup every 5 minutes

        # Track temporary files for cleanup
        self.temp_files = []

    def ensure_icons_directory(self):
        """Check if Icons directory exists and create it if needed"""
        icons_dir = "Icons"
        if not os.path.exists(icons_dir):
            try:
                os.makedirs(icons_dir)
                print(f"Created missing Icons directory: {icons_dir}")

                # Create missing default icons
                self.create_default_icon(os.path.join(icons_dir, "play.png"), (50, 50), (0, 255, 0))
                self.create_default_icon(os.path.join(icons_dir, "pause.png"), (50, 50), (255, 165, 0))
                self.create_default_icon(os.path.join(icons_dir, "stop.png"), (50, 50), (255, 0, 0))
                self.create_default_icon(os.path.join(icons_dir, "volume.png"), (50, 50), (0, 0, 255))
                self.create_default_icon(os.path.join(icons_dir, "mute.png"), (50, 50), (128, 128, 128))
            except Exception as e:
                print(f"Error creating Icons directory: {e}")

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
            print(f"Error creating default icon {path}: {e}")

    def cleanup_temporary_files(self):
        """Clean up temporary files that were created during playback"""
        # Make sure media playback is stopped first
        if self._audio_video_player:
            try:
                self._audio_video_player.safe_stop()
                # Wait a moment to ensure resources are released
                QApplication.processEvents()
                time.sleep(0.1)  # Short delay to let system release files
            except Exception as e:
                print(f"Error stopping media player before cleanup: {e}")

        # Try to delete temporary files with retry
        remaining_files = []
        for temp_file in self.temp_files[:]:
            try:
                if os.path.exists(temp_file):
                    # Try to remove the file
                    os.remove(temp_file)
                    self.temp_files.remove(temp_file)
                else:
                    # File doesn't exist, remove from tracking list
                    self.temp_files.remove(temp_file)
            except Exception as e:
                print(f"Error removing temporary file {temp_file}: {e}")
                # Keep track of files we couldn't delete for retry
                remaining_files.append(temp_file)

        # If we have files that couldn't be deleted, schedule a retry
        if remaining_files:
            self.temp_files = remaining_files
            # Schedule a retry after a delay
            QTimer.singleShot(2000, self.retry_cleanup_files)

    def retry_cleanup_files(self):
        """Retry cleaning up files that couldn't be deleted earlier"""
        remaining_files = []
        for temp_file in self.temp_files[:]:
            try:
                if os.path.exists(temp_file):
                    # Try to remove the file again
                    os.remove(temp_file)
                    self.temp_files.remove(temp_file)
                else:
                    # File doesn't exist, remove from tracking list
                    self.temp_files.remove(temp_file)
            except Exception as e:
                print(f"Retry failed to remove temporary file {temp_file}: {e}")
                remaining_files.append(temp_file)

        # Update the list with any files still remaining
        self.temp_files = remaining_files

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

    def load(self, content, mime_type, path=None):
        # Clear any previous content
        self.clear()
        self.current_path = path

        if not content:
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

            # Process audio and video
            elif mime_type.startswith(('audio/', 'video/')):
                # For audio/video, we need to write content to a temporary file
                suffix = mimetypes.guess_extension(mime_type) or '.tmp'
                fd, tmp_path = tempfile.mkstemp(suffix=suffix)
                os.write(fd, content)
                os.close(fd)

                # Add to temp file list for cleanup
                self.temp_files.append(tmp_path)

                player = self.get_audio_video_player()

                # Set up special options for MP3 files with embedded artwork
                if mime_type.startswith('audio/'):
                    # For MP3 files, the media player will use higher values for analyzeduration and probesize
                    # to better handle embedded artwork
                    media_player = player.media_player
                    try:
                        # Try to set the options using different ways depending on PySide6 version
                        if hasattr(media_player, 'setOption'):
                            # Newer QMediaPlayer API
                            media_player.setOption("analyzeduration", "10000000")  # 10 seconds
                            media_player.setOption("probesize", "20000000")  # 20MB
                        elif hasattr(media_player, 'setMedia'):
                            # Older QMediaPlayer API - might not support options directly
                            print("Using older QMediaPlayer API - options may not be supported")
                    except Exception as e:
                        print(f"Warning: Could not set media player options: {e}")

                # Set the media source
                player.media_player.setSource(QUrl.fromLocalFile(tmp_path))
                player.setVisible(True)
                self.placeholder.setVisible(False)

                # For MP3 files, hide the video widget since it's audio only
                if mime_type.startswith('audio/'):
                    try:
                        player.video_widget.setVisible(False)
                    except Exception as e:
                        print(f"Warning: Could not hide video widget: {e}")

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

        if self._audio_video_player:
            # Ensure the media player is stopped properly
            try:
                self._audio_video_player.stop()
            except Exception as e:
                print(f"Error stopping media player: {e}")
            self._audio_video_player.setVisible(False)

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
        elif file_extension in ['.mp4', '.mkv', '.flv', '.avi', '.mov']:
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
            self._audio_video_player.stop()

        # Clean up temporary files
        self.cleanup_temporary_files()

        # Accept the close event
        super().closeEvent(event)

    def __del__(self):
        """Ensure proper cleanup when the object is garbage collected"""
        # Clean up temporary files
        try:
            self.cleanup_temporary_files()
        except:
            pass  # Ignore errors during cleanup in destructor

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

                    # Wait a moment for resources to be released
                    QApplication.processEvents()
                    time.sleep(0.1)  # Short delay

                    # Release reference
                    player = self._audio_video_player
                    self._audio_video_player = None
                except Exception as e:
                    print(f"Error during audio/video player shutdown: {e}")

            # Wait a bit for resources to be released
            QApplication.processEvents()
            time.sleep(0.2)  # Wait for any pending operations

            # Cleanup temporary files
            self.cleanup_temporary_files()
        except Exception as e:
            print(f"Error during UnifiedViewer shutdown: {e}")


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
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(16, 16))  # Reduce icon size
        self.toolbar.setFixedHeight(32)  # Reduce toolbar height
        self.toolbar.setStyleSheet("""
            QToolBar {
                spacing: 2px;
                padding: 1px;
            }
            QToolButton {
                padding: 2px;
                margin: 1px;
            }
        """)
        # Disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        zoom_in_icon = QIcon("Icons/icons8-zoom-in-50.png")
        zoom_out_icon = QIcon("Icons/icons8-zoom-out-50.png")
        rotate_left_icon = QIcon("Icons/icons8-rotate-left-50.png")
        rotate_right_icon = QIcon("Icons/icons8-rotate-right-50.png")
        reset_icon = QIcon("Icons/icons8-no-rotation-50.png")
        export_icon = QIcon("Icons/icons8-save-as-50.png")

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


class PDFViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pdf = None
        self.current_page = 0
        self.zoom_factor = 1.0
        self.rotation_angle = 0
        self.is_panning = False
        self.pan_start_x = 0
        self.pan_start_y = 0
        self.pan_mode = False

        # Optimize performance with page caching
        self._page_cache = {}  # Cache for rendered pages
        self._cache_size = 5  # Maximum number of pages to cache

        self.initialize_ui()

    def initialize_ui(self):
        # Set up the main layout
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        # Create a container for the toolbar and the application viewer
        container_widget = QWidget(self)
        container_layout = QVBoxLayout()
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Create and set up the toolbar
        self.setup_toolbar()

        # Add the toolbar to the container layout
        container_layout.addWidget(self.toolbar)

        # Set up the PDF display area
        self.setup_pdf_display_area()
        container_layout.addWidget(self.scroll_area)

        container_widget.setLayout(container_layout)
        self.layout.addWidget(container_widget)

        self.setLayout(self.layout)
        self.update_navigation_states()

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(16, 16))  # Reduce icon size
        self.toolbar.setFixedHeight(32)  # Reduce toolbar height
        self.toolbar.setStyleSheet("""
            QToolBar {
                spacing: 2px;
                padding: 1px;
            }
            QToolButton {
                padding: 2px;
                margin: 1px;
            }
        """)
        # Disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        # Navigation buttons
        self.first_action = QAction(QIcon("Icons/icons8-thick-arrow-pointing-up-50.png"), "First", self)
        self.first_action.triggered.connect(self.show_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("Icons/icons8-left-arrow-50.png"), "Previous", self)
        self.prev_action.triggered.connect(self.show_previous_page)
        self.toolbar.addAction(self.prev_action)

        # Page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setFixedHeight(22)  # Set fixed height
        self.page_entry.setAlignment(Qt.AlignRight)
        self.page_entry.returnPressed.connect(self.go_to_page)
        self.toolbar.addWidget(self.page_entry)

        # Total pages label
        self.total_pages_label = QLabel(f"of {len(self.pdf)}" if self.pdf else "of 0")
        self.total_pages_label.setFixedHeight(22)  # Set fixed height
        self.toolbar.addWidget(self.total_pages_label)

        # Navigation buttons
        self.next_action = QAction(QIcon("Icons/icons8-right-arrow-50.png"), "Next", self)
        self.next_action.triggered.connect(self.show_next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("Icons/icons8-down-50.png"), "Last", self)
        self.last_action.triggered.connect(self.show_last_page)
        self.toolbar.addAction(self.last_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(20, 0)
        self.toolbar.addWidget(spacer)

        # Zoom actions
        self.zoom_in_action = QAction(QIcon("Icons/icons8-zoom-in-50.png"), "Zoom In", self)
        self.zoom_in_action.triggered.connect(self.zoom_in)
        self.toolbar.addAction(self.zoom_in_action)

        # QLineEdit for zoom percentage
        self.zoom_percentage_entry = QLineEdit(self)
        self.zoom_percentage_entry.setFixedWidth(60)  # Set a fixed width for consistency
        self.zoom_percentage_entry.setFixedHeight(22)  # Set fixed height
        self.zoom_percentage_entry.setAlignment(Qt.AlignRight)
        self.zoom_percentage_entry.setPlaceholderText("100%")  # Default zoom is 100%
        self.zoom_percentage_entry.returnPressed.connect(self.set_zoom_from_entry)
        self.toolbar.addWidget(self.zoom_percentage_entry)

        self.zoom_out_action = QAction(QIcon("Icons/icons8-zoom-out-50.png"), "Zoom Out", self)
        self.zoom_out_action.triggered.connect(self.zoom_out)
        self.toolbar.addAction(self.zoom_out_action)

        # Create a reset zoom button with its icon and add it to the toolbar
        reset_zoom_icon = QIcon("Icons/icons8-zoom-to-actual-size-50.png")
        self.reset_zoom_action = QAction(reset_zoom_icon, "Reset Zoom", self)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.toolbar.addAction(self.reset_zoom_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(20, 0)
        self.toolbar.addWidget(spacer)

        # Fit in window
        fit_window_icon = QIcon("Icons/icons8-enlarge-50.png")
        self.fit_window_action = QAction(fit_window_icon, "Fit in Window", self)
        self.fit_window_action.triggered.connect(self.fit_window)
        self.toolbar.addAction(self.fit_window_action)

        # Fit in width
        fit_width_icon = QIcon("Icons/icons8-resize-horizontal-50.png")
        self.fit_width_action = QAction(fit_width_icon, "Fit in Width", self)
        self.fit_width_action.triggered.connect(self.fit_width)
        self.toolbar.addAction(self.fit_width_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(20, 0)
        self.toolbar.addWidget(spacer)

        # Pan tool button
        self.pan_tool_icon = QIcon("Icons/icons8-drag-50.png")
        self.pan_tool_action = QAction(self.pan_tool_icon, "Pan Tool", self)
        self.pan_tool_action.setCheckable(True)
        self.pan_tool_action.toggled.connect(self.toggle_pan_mode)
        self.toolbar.addAction(self.pan_tool_action)

        # Add a spacer to push the following buttons to the right
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # Print button
        self.print_icon = QIcon("Icons/icons8-print-50.png")
        self.print_action = QAction(self.print_icon, "Print", self)
        self.print_action.triggered.connect(self.print_pdf)
        self.toolbar.addAction(self.print_action)

        self.save_pdf_action = QAction(QIcon("Icons/icons8-save-as-50.png"), "Save PDF", self)
        self.save_pdf_action.triggered.connect(self.save_pdf)
        self.toolbar.addAction(self.save_pdf_action)

    def setup_pdf_display_area(self):
        self.page_label = QLabel(self)
        self.page_label.setContentsMargins(0, 0, 0, 0)
        self.page_label.setAlignment(Qt.AlignCenter)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setWidget(self.page_label)
        self.scroll_area.setWidgetResizable(True)

    def set_current_page(self, page_num):
        """Set the current page and update the view."""
        if not self.pdf:
            return

        max_pages = len(self.pdf)
        if 0 <= page_num < max_pages:
            self.current_page = page_num
            self.show_page(page_num)

    def go_to_page(self):
        """Navigate to the page entered in the page entry field."""
        try:
            page_num = int(self.page_entry.text()) - 1  # Minus 1 because pages start from 0
            self.set_current_page(page_num)
        except ValueError:
            QMessageBox.warning(self, "Invalid Page Number", "Please enter a valid page number.")

    def update_navigation_states(self):
        """Update UI elements based on current PDF and page."""
        if not self.pdf:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            self.first_action.setEnabled(False)
            self.last_action.setEnabled(False)
            self.total_pages_label.setText("of 0")
            self.page_entry.setText("")
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < len(self.pdf) - 1)
        self.first_action.setEnabled(self.current_page > 0)
        self.last_action.setEnabled(self.current_page < len(self.pdf) - 1)
        self.total_pages_label.setText(f"of {len(self.pdf)}")
        self.page_entry.setText(str(self.current_page + 1))

    def show_previous_page(self):
        """Navigate to the previous page."""
        self.set_current_page(self.current_page - 1)
        self.update_navigation_states()

    def show_next_page(self):
        """Navigate to the next page."""
        self.set_current_page(self.current_page + 1)
        self.update_navigation_states()

    def show_page(self, page_num):
        """Display the specified page with caching for better performance."""
        if not self.pdf:
            return

        try:
            # Check if the page is in the cache
            cache_key = (page_num, self.zoom_factor, self.rotation_angle)
            if cache_key in self._page_cache:
                # Use cached pixmap
                self.page_label.setPixmap(self._page_cache[cache_key])
            else:
                # Render the page and cache it
                page = self.pdf[page_num]
                mat = Matrix(self.zoom_factor, self.zoom_factor).prerotate(self.rotation_angle)
                image = page.get_pixmap(matrix=mat)

                qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
                pixmap = QPixmap.fromImage(qt_image)

                # Cache the pixmap
                self._page_cache[cache_key] = pixmap

                # Manage cache size
                if len(self._page_cache) > self._cache_size:
                    # Remove oldest entry (first key)
                    oldest_key = next(iter(self._page_cache))
                    del self._page_cache[oldest_key]

                self.page_label.setPixmap(pixmap)

            self.update_navigation_states()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to render page: {e}")

    def display(self, content):
        """Load and display a PDF from content bytes."""
        # Clear existing PDF and cache
        self.clear()

        if content:
            try:
                self.pdf = fitz_open(stream=content, filetype="pdf")
                self.current_page = 0
                self.zoom_factor = 1.0
                self.rotation_angle = 0
                self.show_page(self.current_page)
                self.update_navigation_states()
            except Exception as e:
                print(f"Failed to load PDF: {e}")
        else:
            self.page_label.clear()

    def clear(self):
        """Close the PDF and clear all resources."""
        if self.pdf:
            self.pdf.close()
            self.pdf = None

        # Clear the cache
        self._page_cache.clear()
        self.page_label.clear()
        self.update_navigation_states()

    def show_first_page(self):
        """Navigate to the first page."""
        self.set_current_page(0)

    def show_last_page(self):
        """Navigate to the last page."""
        if self.pdf:
            self.set_current_page(len(self.pdf) - 1)

    def zoom_in(self):
        """Increase zoom level."""
        # Don't allow extreme zoom levels
        if self.zoom_factor < 5.0:
            self.zoom_factor *= 1.2
            # Clear cache on zoom change
            self._page_cache.clear()
            self.show_page(self.current_page)
            # Update zoom display
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def zoom_out(self):
        """Decrease zoom level."""
        # Don't allow extreme zoom levels
        if self.zoom_factor > 0.1:
            self.zoom_factor *= 0.8
            # Clear cache on zoom change
            self._page_cache.clear()
            self.show_page(self.current_page)
            # Update zoom display
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def set_zoom_from_entry(self):
        """Set zoom level from the entry field."""
        try:
            # Extract the percentage from the QLineEdit
            text = self.zoom_percentage_entry.text().strip('%')
            percentage = float(text) / 100

            if 0.1 <= percentage <= 5:  # Enforce reasonable zoom limits
                self.zoom_factor = percentage
                # Clear cache on zoom change
                self._page_cache.clear()
                self.show_page(self.current_page)
            else:
                QMessageBox.warning(self, "Invalid Zoom", "Please enter a zoom percentage between 10% and 500%.")
                # Reset the entry to the current zoom
                self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")
        except ValueError:
            QMessageBox.warning(self, "Invalid Zoom", "Please enter a valid zoom percentage.")
            # Reset the entry to the current zoom
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def reset_zoom(self):
        """Reset zoom to original size."""
        self.zoom_factor = 1.0
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        self.zoom_percentage_entry.setText("100%")

    def fit_window(self):
        """Adjust zoom to fit the entire page in the window."""
        if not self.pdf or self.current_page >= len(self.pdf):
            return

        page = self.pdf[self.current_page]
        zoom_x = self.scroll_area.width() / page.rect.width
        zoom_y = self.scroll_area.height() / page.rect.height
        self.zoom_factor = min(zoom_x, zoom_y) * 0.95  # 95% to add a small margin
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        # Update zoom display
        self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def fit_width(self):
        """Adjust zoom to fit the page width in the window."""
        if not self.pdf or self.current_page >= len(self.pdf):
            return

        page = self.pdf[self.current_page]
        self.zoom_factor = self.scroll_area.width() / page.rect.width * 0.95  # 95% to add a small margin
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        # Update zoom display
        self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def rotate_left(self):
        """Rotate the page 90 degrees counterclockwise."""
        self.rotation_angle -= 90
        # Clear cache on rotation change
        self._page_cache.clear()
        self.show_page(self.current_page)

    def rotate_right(self):
        """Rotate the page 90 degrees clockwise."""
        self.rotation_angle += 90
        # Clear cache on rotation change
        self._page_cache.clear()
        self.show_page(self.current_page)

    def toggle_pan_mode(self, checked):
        """Enable or disable panning mode."""
        self.pan_mode = checked
        self.setCursor(Qt.OpenHandCursor if checked else Qt.ArrowCursor)

    def mousePressEvent(self, event):
        """Handle mouse press events for panning."""
        if event.button() == Qt.LeftButton and self.pan_mode:
            self.is_panning = True
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
            self.setCursor(Qt.ClosedHandCursor)  # Change to closed hand cursor while panning
        event.accept()

    def mouseMoveEvent(self, event):
        """Handle mouse move events for panning."""
        if self.is_panning and self.pan_mode:
            # Calculate the distance moved
            dx = event.x() - self.pan_start_x
            dy = event.y() - self.pan_start_y

            # Update scroll position
            self.scroll_area.horizontalScrollBar().setValue(self.scroll_area.horizontalScrollBar().value() - dx)
            self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().value() - dy)

            # Update the mouse position for the next move
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
        event.accept()

    def mouseReleaseEvent(self, event):
        """Handle mouse release events for panning."""
        if event.button() == Qt.LeftButton and self.is_panning and self.pan_mode:
            self.is_panning = False
            self.setCursor(Qt.OpenHandCursor)  # Change back to open hand cursor
        event.accept()

    def print_pdf(self):
        """Print the current PDF."""
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to print.")
            return

        printer = QPrinter()
        printer.setFullPage(True)
        printer.setPageOrientation(QPageLayout.Portrait)

        print_dialog = QPrintDialog(printer, self)
        if print_dialog.exec_() == QPrintDialog.Accepted:
            from PySide6.QtGui import QPainter

            try:
                painter = QPainter()
                if not painter.begin(printer):
                    QMessageBox.critical(self, "Error", "Failed to initialize printer.")
                    return

                num_pages = len(self.pdf)
                for i in range(num_pages):
                    if i != 0:  # start a new page after the first one
                        printer.newPage()

                    # Render the page at a higher resolution for printing
                    page = self.pdf[i]
                    image = page.get_pixmap(matrix=Matrix(2.0, 2.0))  # Higher resolution for print

                    qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
                    pixmap = QPixmap.fromImage(qt_image)

                    # Scale to printer page
                    rect = painter.viewport()
                    size = pixmap.size()
                    size.scale(rect.size(), Qt.KeepAspectRatio)
                    painter.setViewport(rect.x(), rect.y(), size.width(), size.height())
                    painter.setWindow(pixmap.rect())
                    painter.drawPixmap(0, 0, pixmap)

                painter.end()
                QMessageBox.information(self, "Print Complete", "Document was sent to the printer.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to print document: {e}")
                if painter.isActive():
                    painter.end()

    def save_pdf(self):
        """Save the current PDF to a file."""
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to save.")
            return

        options = QFileDialog.Options()
        filePath, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf);;All Files (*)",
                                                  options=options)

        if not filePath:
            return  # user cancelled the dialog

        if not filePath.endswith(".pdf"):
            filePath += ".pdf"

        try:
            self.pdf.save(filePath)  # save the PDF to the specified path
            QMessageBox.information(self, "Success", "PDF saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save PDF: {e}")


class AudioVideoPlayer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        # Initialize attributes before calling methods that use them
        self._is_playing = False
        self._current_volume = 50  # Default volume level
        self._is_muted = False
        self._previous_volume = 50  # Store previous volume when muting
        self._audio_session = None
        self._volume_interface = None
        self._is_audio_only = False  # Flag to track if we're playing audio-only content
        self._shutting_down = False  # Flag to indicate shutdown in progress

        # Now initialize UI and connections
        self.initialize_ui()
        self.setup_connections()
        self._setup_os_volume()

    def initialize_ui(self):
        # Main layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Create video widget
        self.video_widget = QVideoWidget(self)
        self.video_widget.setMinimumSize(QSize(400, 300))

        # Create media player
        self.media_player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.media_player.setVideoOutput(self.video_widget)
        self.media_player.setAudioOutput(self.audio_output)

        # Create label to display when playing audio-only content
        self.audio_label = QLabel("Playing Audio", self)
        self.audio_label.setAlignment(Qt.AlignCenter)
        # Use explicit RGB colors instead of hex for better compatibility
        self.audio_label.setStyleSheet(
            "background-color: rgb(224, 224, 224); font-size: 18px; color: rgb(68, 68, 68); padding: 20px;")
        self.audio_label.setVisible(False)

        # Set default volume
        self.audio_output.setVolume(self._current_volume / 100.0)

        # Create controls
        self.create_controls()

        # Add widgets to layout
        self.layout.addWidget(self.video_widget)
        self.layout.addWidget(self.audio_label)
        self.layout.addWidget(self.control_widget)

    def set_audio_only_mode(self, is_audio_only=True):
        """Configure the player for audio-only content"""
        self._is_audio_only = is_audio_only
        self.video_widget.setVisible(not is_audio_only)
        self.audio_label.setVisible(is_audio_only)

        # Set the media player flags accordingly
        try:
            if hasattr(self.media_player, 'setOption'):
                if is_audio_only:
                    # For audio-only content, set flags that optimize for audio playback
                    self.media_player.setOption("audio-only", "true")
                    self.media_player.setOption("skip-video", "true")
                else:
                    # Reset flags for video content
                    self.media_player.setOption("audio-only", "false")
                    self.media_player.setOption("skip-video", "false")
        except Exception as e:
            print(f"Warning: Could not set audio-only mode options: {e}")

    def handle_media_status_change(self, status):
        """Handle media status changes"""
        # If this is an audio file and we see no video streams, switch to audio-only mode
        try:
            if status == QMediaPlayer.LoadedMedia:
                # Check if we can detect if this is audio-only content
                has_video = False

                if hasattr(self.media_player, 'hasVideo'):
                    has_video = self.media_player.hasVideo()

                # Set the appropriate mode
                self.set_audio_only_mode(not has_video)
        except Exception as e:
            print(f"Warning: Error detecting audio/video mode: {e}")

    def setup_connections(self):
        # Media player signals (updated for newer API)
        self.media_player.errorOccurred.connect(self.handle_error)
        self.media_player.positionChanged.connect(self.update_position)
        self.media_player.durationChanged.connect(self.update_duration)
        self.media_player.playbackStateChanged.connect(self.update_play_state)

        # Media status signals - if available in this version
        if hasattr(self.media_player, 'mediaStatusChanged'):
            self.media_player.mediaStatusChanged.connect(self.handle_media_status_change)

        # Control signals
        self.play_button.clicked.connect(self.toggle_play)
        self.stop_button.clicked.connect(self.stop)
        self.position_slider.sliderMoved.connect(self.set_position)
        self.volume_button.clicked.connect(self.toggle_mute)
        self.volume_slider.valueChanged.connect(self.set_volume)

    def _setup_os_volume(self):
        """Set up OS-specific volume control (Windows only)"""
        if platform.system() == "Windows":
            try:
                from comtypes import CLSCTX_ALL
                from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

                devices = AudioUtilities.GetSpeakers()
                self._audio_session = AudioUtilities.GetAllSessions()
                interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                self._volume_interface = cast(interface, POINTER(IAudioEndpointVolume))
            except Exception as e:
                print(f"Could not initialize Windows audio integration: {e}")

    def set_os_volume(self, volume_level):
        """Set system volume (Windows only)"""
        if self._volume_interface and platform.system() == "Windows":
            try:
                # Convert from 0-100 to 0.0-1.0 range
                self._volume_interface.SetMasterVolumeLevelScalar(volume_level / 100.0, None)
            except Exception as e:
                print(f"Error setting system volume: {e}")

    def toggle_play(self):
        if self._is_playing:
            self.media_player.pause()
        else:
            self.media_player.play()

    def stop(self):
        """Stop playback and reset position"""
        try:
            if hasattr(self, 'media_player') and self.media_player:
                self.media_player.stop()
                self._is_playing = False
                self.update_controls()
        except Exception as e:
            print(f"Error stopping media playback: {e}")

    def update_play_state(self, state):
        # Updated for newer API
        self._is_playing = (state == QMediaPlayer.PlayingState)
        self.update_controls()

    def update_controls(self):
        if self._is_playing:
            # Try different pause icon paths
            pause_icon_paths = [
                "Icons/icons8-pause-50.png",
                "Icons/pause.png",
                "Icons/icons8-pause-button-50.png"
            ]
            icon_set = False
            for path in pause_icon_paths:
                if os.path.exists(path):
                    self.play_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.play_button.setText("Pause")
        else:
            # Try different play icon paths
            play_icon_paths = [
                "Icons/icons8-play-50.png",
                "Icons/play.png",
                "Icons/icons8-circled-play-50.png"
            ]
            icon_set = False
            for path in play_icon_paths:
                if os.path.exists(path):
                    self.play_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.play_button.setText("Play")

    def set_position(self, position):
        self.media_player.setPosition(position)

    def update_position(self, position):
        # Block signals to prevent slider feedback loops
        self.position_slider.blockSignals(True)
        self.position_slider.setValue(position)
        self.position_slider.blockSignals(False)

        # Update time label
        self.current_time_label.setText(self.format_time(position))

    def update_duration(self, duration):
        self.position_slider.setRange(0, duration)
        self.total_time_label.setText(self.format_time(duration))

    def format_time(self, milliseconds):
        seconds = milliseconds // 1000
        minutes = seconds // 60
        seconds %= 60
        return f"{minutes:02d}:{seconds:02d}"

    def toggle_mute(self):
        self._is_muted = not self._is_muted
        if self._is_muted:
            self._previous_volume = self._current_volume
            self.set_volume(0)
            # Try different mute icon paths
            mute_icon_paths = [
                "Icons/icons8-mute-50.png",
                "Icons/mute.png"
            ]
            icon_set = False
            for path in mute_icon_paths:
                if os.path.exists(path):
                    self.volume_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.volume_button.setText("Mute")
        else:
            self.set_volume(self._previous_volume)
            # Try different volume icon paths
            volume_icon_paths = [
                "Icons/icons8-audio-50.png",
                "Icons/volume.png",
                "Icons/audio.png"
            ]
            icon_set = False
            for path in volume_icon_paths:
                if os.path.exists(path):
                    self.volume_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.volume_button.setText("Vol")

        # Update system volume if enabled
        self.set_os_volume(self._current_volume)

    def set_volume(self, volume):
        self._current_volume = volume
        self.audio_output.setVolume(volume / 100.0)

        # Update volume slider
        self.volume_slider.blockSignals(True)
        self.volume_slider.setValue(volume)
        self.volume_slider.blockSignals(False)

        # Update mute button icon based on volume
        if volume == 0:
            self._is_muted = True
            # Try different mute icon paths
            mute_icon_paths = [
                "Icons/icons8-mute-50.png",
                "Icons/mute.png"
            ]
            icon_set = False
            for path in mute_icon_paths:
                if os.path.exists(path):
                    self.volume_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.volume_button.setText("Mute")
        else:
            self._is_muted = False
            # Try different volume icon paths
            volume_icon_paths = [
                "Icons/icons8-audio-50.png",
                "Icons/volume.png",
                "Icons/audio.png"
            ]
            icon_set = False
            for path in volume_icon_paths:
                if os.path.exists(path):
                    self.volume_button.setIcon(QIcon(path))
                    icon_set = True
                    break

            if not icon_set:
                self.volume_button.setText("Vol")

        # Update system volume if enabled
        self.set_os_volume(volume)

    def handle_error(self, error, error_string):
        if error != QMediaPlayer.NoError:
            QMessageBox.warning(self, "Media Error", f"Error: {error_string}")

    def closeEvent(self, event):
        # Clean up resources
        try:
            if hasattr(self, 'media_player') and self.media_player:
                self.media_player.stop()
        except Exception as e:
            print(f"Error stopping media player during close: {e}")
        super().closeEvent(event)

    def __del__(self):
        # Clean up any lingering resources
        try:
            if not hasattr(self, '_shutting_down') or not self._shutting_down:
                self.safe_stop()
        except Exception:
            # Silently ignore errors during destruction
            pass

    def create_controls(self):
        # Control widget and layout
        self.control_widget = QWidget(self)
        self.control_layout = QHBoxLayout(self.control_widget)
        self.control_layout.setContentsMargins(2, 2, 2, 2)
        self.control_layout.setSpacing(2)

        # Play/Pause button with fallback icon paths
        self.play_button = QPushButton(self)
        # Try different icon paths
        play_icon_paths = [
            "Icons/icons8-play-50.png",
            "Icons/play.png",
            "Icons/icons8-circled-play-50.png"
        ]
        for path in play_icon_paths:
            if os.path.exists(path):
                self.play_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.play_button.setText("Play")

        self.play_button.setIconSize(QSize(16, 16))
        self.play_button.setFixedHeight(22)
        self.play_button.setFlat(True)
        self.play_button.setToolTip("Play/Pause")

        # Stop button with fallback icon paths
        self.stop_button = QPushButton(self)
        # Try different icon paths
        stop_icon_paths = [
            "Icons/icons8-stop-50.png",
            "Icons/stop.png",
            "Icons/icons8-stop-circled-50.png"
        ]
        for path in stop_icon_paths:
            if os.path.exists(path):
                self.stop_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.stop_button.setText("Stop")

        self.stop_button.setIconSize(QSize(16, 16))
        self.stop_button.setFixedHeight(22)
        self.stop_button.setFlat(True)
        self.stop_button.setToolTip("Stop")

        # Position slider
        self.position_slider = QSlider(Qt.Horizontal, self)
        self.position_slider.setFixedHeight(22)
        self.position_slider.setRange(0, 0)  # Will be updated when media is loaded
        self.position_slider.setToolTip("Position")
        self.position_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                height: 5px;
                margin: 2px 0;
            }
            QSlider::handle:horizontal {
                width: 10px;
                margin: -3px 0;
            }
        """)

        # Time labels
        self.current_time_label = QLabel("00:00", self)
        self.current_time_label.setFixedHeight(22)
        self.current_time_label.setMinimumWidth(40)
        self.total_time_label = QLabel("00:00", self)
        self.total_time_label.setFixedHeight(22)
        self.total_time_label.setMinimumWidth(40)

        # Volume button with fallback icon paths
        self.volume_button = QPushButton(self)
        # Try different icon paths
        volume_icon_paths = [
            "Icons/icons8-audio-50.png",
            "Icons/volume.png",
            "Icons/audio.png"
        ]
        for path in volume_icon_paths:
            if os.path.exists(path):
                self.volume_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.volume_button.setText("Vol")

        self.volume_button.setIconSize(QSize(16, 16))
        self.volume_button.setFixedHeight(22)
        self.volume_button.setFlat(True)
        self.volume_button.setToolTip("Mute/Unmute")

        self.volume_slider = QSlider(Qt.Horizontal, self)
        self.volume_slider.setFixedHeight(22)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(self._current_volume)
        self.volume_slider.setMaximumWidth(80)
        self.volume_slider.setToolTip("Volume")
        self.volume_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                height: 5px;
                margin: 2px 0;
            }
            QSlider::handle:horizontal {
                width: 10px;
                margin: -3px 0;
            }
        """)

        # Add controls to layout
        self.control_layout.addWidget(self.play_button)
        self.control_layout.addWidget(self.stop_button)
        self.control_layout.addWidget(self.current_time_label)
        self.control_layout.addWidget(self.position_slider)
        self.control_layout.addWidget(self.total_time_label)
        self.control_layout.addWidget(self.volume_button)
        self.control_layout.addWidget(self.volume_slider)

    def safe_stop(self):
        """Safely stop playback even during shutdown."""
        try:
            if hasattr(self, 'media_player') and self.media_player:
                # Set flag to indicate we're shutting down
                self._shutting_down = True

                # Stop playback
                self.media_player.stop()

                # Process events to ensure stop command is processed
                QApplication.processEvents()

                # Release audio output
                if hasattr(self, 'audio_output') and self.audio_output:
                    # Remove it from the media player first
                    if hasattr(self.media_player, 'setAudioOutput'):
                        try:
                            self.media_player.setAudioOutput(None)
                            # Process events to ensure this is applied
                            QApplication.processEvents()
                        except Exception as e:
                            print(f"Error removing audio output: {e}")

                # Set media to null/empty to release resources
                if hasattr(self.media_player, 'setSource'):
                    try:
                        self.media_player.setSource(QUrl())
                        # Process events to ensure this is applied
                        QApplication.processEvents()
                    except Exception as e:
                        print(f"Error clearing media source: {e}")

                # Wait a moment for resources to be released
                time.sleep(0.1)
        except Exception as e:
            print(f"Error in safe_stop: {e}")

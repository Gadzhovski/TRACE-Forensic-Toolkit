"""Multi-format file viewer.

UnifiedViewer asks trace_app.core.filetypes how to show a file -- from its name
and its content, so a JPEG named .txt is shown as a JPEG -- and delegates to
the specialised viewer: pictures, paged documents (PDF, EPUB, XPS, CBZ, FB2,
MOBI), audio/video, or the offline HTML viewer, which also shows Office
documents read into static HTML. Each lives in its own module here.

When the content and the extension disagree, a notice above the file says so:
in a forensic tool, why a file is shown the way it is matters as much as the
picture.
"""

import logging
import mimetypes
import os

from PySide6.QtCore import Qt, QUrl, QTimer, QBuffer, QByteArray, QIODevice
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QApplication)

from trace_app.core import document_preview
from trace_app.core.filetypes import (VIEW_AUDIO, VIEW_DATABASE,
                                      VIEW_DOCUMENT, VIEW_HTML, VIEW_IMAGE,
                                      VIEW_OFFICE, VIEW_VIDEO, not_a_pdf,
                                      plan_view)
from trace_app.core.stream_device import PyTsk3StreamDevice
from trace_app.ui.viewers.media.audiovideo import AudioVideoPlayer
from trace_app.ui.viewers.media.html import SafeHtmlViewer
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

        # Why the file is shown as it is, when that is not obvious from its
        # name: "Shown as JPEG image: its content does not match .txt".
        self.notice = QLabel()
        self.notice.setObjectName("viewerNotice")
        self.notice.setWordWrap(True)
        self.notice.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.notice.setVisible(False)
        self.layout.addWidget(self.notice)

        # Create placeholder widget to show when nothing is loaded
        self.placeholder = QLabel("No content loaded")
        self.placeholder.setObjectName("placeholderLabel")  # For stylesheet targeting
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setWordWrap(True)
        self.layout.addWidget(self.placeholder, 1)

        # A password-protected Office document: decrypted in memory with a
        # password the examiner gives (msoffcrypto-tool), never written.
        from PySide6.QtWidgets import QPushButton
        self.unlock_button = QPushButton("Unlock with Password…", self)
        self.unlock_button.setObjectName("unlockDocumentButton")
        self.unlock_button.setVisible(False)
        self.unlock_button.clicked.connect(self._ask_password)
        self.layout.addWidget(self.unlock_button, 0, Qt.AlignHCenter)
        self._locked = None             # (content, plan) awaiting a password

        # Initialize viewers as None for lazy loading
        self._pdf_viewer = None
        self._picture_viewer = None
        self._audio_video_player = None
        self._html_viewer = None
        self._database_viewer = None
        #: `reader(data)` -> the bytes of a database's -wal beside it, or
        #: None; set by the window, which knows the image.
        self.database_wal_reader = None
        #: (content, label) -> show a database cell's bytes as a file.
        self.database_blob_opener = None

        # Store media buffer for in-memory playback (keeps buffer alive during playback)
        self._media_buffer = None

        # Store stream device and file object for streaming playback from disk images
        self._media_stream_device = None
        self._media_file_obj = None

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

    def get_html_viewer(self):
        """Lazy initialization of the offline HTML / document viewer"""
        if self._html_viewer is None:
            self._html_viewer = SafeHtmlViewer(self)
            self._html_viewer.setVisible(False)
            self.layout.addWidget(self._html_viewer, 1)
        return self._html_viewer

    def get_database_viewer(self):
        """Lazy initialization of the SQLite viewer."""
        if self._database_viewer is None:
            from trace_app.ui.viewers.database_viewer import DatabaseViewer
            self._database_viewer = DatabaseViewer(self)
            self._database_viewer.setVisible(False)
            self.layout.addWidget(self._database_viewer, 1)
        self._database_viewer.wal_reader = self.database_wal_reader
        self._database_viewer.blob_opener = self.database_blob_opener
        return self._database_viewer

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
                player.source_name = path or ''

                # Create a hint URL with the mime type to help the media backend
                # identify the format correctly
                hint_url = QUrl()
                hint_url.setScheme("memory")
                # The file's own extension first: the backend picks a demuxer
                # from it, and "video/mp4" for every video told it an MKV or
                # WebM was an MP4.
                suffix = (os.path.splitext(path or '')[1]
                          or mimetypes.guess_extension(mime_type) or '.tmp')
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
        self._locked = None
        self.unlock_button.setVisible(False)
        # Hide all viewers
        if self._pdf_viewer:
            self._pdf_viewer.clear()
            self._pdf_viewer.setVisible(False)

        if self._picture_viewer:
            self._picture_viewer.clear()
            self._picture_viewer.setVisible(False)

        if self._html_viewer:
            self._html_viewer.clear()
            self._html_viewer.setVisible(False)

        if self._database_viewer:
            self._database_viewer.clear()
            self._database_viewer.setVisible(False)

        self.notice.clear()
        self.notice.setVisible(False)

        # Clean up media player
        if self._audio_video_player:
            try:
                # Stop playback, then let go of the source: the FFmpeg
                # backend's reader holds the device until it is replaced.
                self._audio_video_player.stop()
                self._audio_video_player.media_player.setSource(QUrl())
            except Exception as e:
                logger.error(f"Error stopping media player: {e}")
            self._audio_video_player.setVisible(False)

        # Clean up media buffer -- closed a beat later, like the stream
        # device below. Closed at once, under a player that had played and
        # paused, the next file's setSourceDevice waited for ever.
        if self._media_buffer:
            old_buffer, self._media_buffer = self._media_buffer, None

            def close_buffer():
                try:
                    if old_buffer.isOpen():
                        old_buffer.close()
                except Exception as e:
                    logger.error(f"Error closing media buffer: {e}")
            QTimer.singleShot(100, close_buffer)

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
                # The image's file object is held until the device is
                # closed: the backend's reader may still be reading through
                # it, and dropping the last reference at once could free it
                # mid-read.
                nonlocal old_file_obj
                try:
                    if old_stream_device and old_stream_device.isOpen():
                        old_stream_device.close()
                except Exception as e:
                    logger.error(f"Error in delayed stream device cleanup: {e}")
                finally:
                    old_file_obj = None

            # Schedule cleanup after 100ms (non-blocking)
            QTimer.singleShot(100, delayed_cleanup)
        else:
            # No stream device, just clear file object
            self._media_file_obj = None

        # Show the placeholder
        self.placeholder.setText("No content loaded")
        self.placeholder.setVisible(True)
        self.current_path = None

    def display_application_content(self, file_content, full_file_path,
                                    data=None):
        """Show a file, choosing the viewer from its name and its content.
        `data` is the selection (path, volume): a database's -wal beside it
        is found from it."""
        self.clear()
        self.current_path = full_file_path
        if not file_content:
            return self._unavailable("This file is empty.")

        plan = plan_view(full_file_path, file_content)
        if plan is None:
            return self._unavailable(
                "There is no preview for this kind of file.\n"
                "The Hex and Text tabs show its contents.")

        try:
            if plan.kind == VIEW_IMAGE:
                viewer = self.get_picture_viewer()
                problem = viewer.display(file_content)
                if problem:
                    return self._unavailable(problem, plan.note)
                return self._showing(viewer, plan.note)

            if plan.kind == VIEW_DOCUMENT:
                if plan.subtype == 'pdf':
                    problem = not_a_pdf(file_content)
                    if problem:
                        return self._unavailable(problem, plan.note)
                viewer = self.get_pdf_viewer()
                viewer.display(file_content, plan.subtype)
                if getattr(viewer, 'pdf', None) is None:
                    return self._unavailable(
                        f"This {plan.label} could not be opened; it may be "
                        f"damaged or not what it appears to be.", plan.note)
                return self._showing(viewer, plan.note)

            if plan.kind in (VIEW_AUDIO, VIEW_VIDEO):
                mime = plan.mime or f"{plan.kind}/{plan.subtype}"
                loaded = self.load(file_content, mime, full_file_path)
                self._set_notice(plan.note)
                return loaded

            if plan.kind == VIEW_DATABASE:
                viewer = self.get_database_viewer()
                viewer.display(file_content, data or {})
                return self._showing(viewer, plan.note)

            if plan.kind == VIEW_HTML:
                text, _encoding = document_preview.decode_html(file_content)
                viewer = self.get_html_viewer()
                viewer.display(text, "HTML page", [plan.note])
                return self._showing(viewer)

            if plan.kind == VIEW_OFFICE:
                return self._show_office(file_content, plan)
        except Exception as exc:
            logger.error("Could not display %s: %s", full_file_path, exc)
            return self._unavailable(f"Error loading content: {exc}")

        return self._unavailable("There is no preview for this kind of file.")

    def _show_office(self, content, plan, decrypted=False):
        try:
            markup, findings = document_preview.to_html(content,
                                                        plan.subtype)
        except document_preview.EncryptedDocument as exc:
            self._locked = (content, plan)
            shown = self._unavailable(str(exc), plan.note)
            self.unlock_button.setVisible(True)
            return shown
        except document_preview.PreviewError as exc:
            return self._unavailable(
                f"This {plan.label} could not be read: {exc}", plan.note)
        viewer = self.get_html_viewer()
        notes = [plan.note or f"{plan.label.capitalize()}."]
        if decrypted:
            notes.append("Decrypted in memory with the password given; "
                         "nothing was written and the evidence is "
                         "unchanged.")
        if plan.subtype not in ('msg', 'pcap'):
            findings = [*findings, "Text and structure only; the original "
                        "layout, fonts and images are not reproduced."]
        viewer.display(markup, plan.label.capitalize(), [*notes, *findings],
                       from_evidence=False)
        return self._showing(viewer)

    def _ask_password(self):
        from PySide6.QtWidgets import QInputDialog, QLineEdit
        password, ok = QInputDialog.getText(
            self, "Unlock Document", "Password for this document:",
            QLineEdit.Password)
        if ok and password:
            self.unlock_document(password)

    def unlock_document(self, password):
        """Decrypt the document on screen with `password` and show it.
        Returns True when it decrypted."""
        if self._locked is None:
            return False
        content, plan = self._locked
        try:
            plain = document_preview.decrypt(content, password)
        except document_preview.PreviewError as exc:
            self.placeholder.setText(f"{exc}\n\nTry another password.")
            return False
        self._locked = None
        self.unlock_button.setVisible(False)
        from trace_app.core.filetypes import plan_view
        inner = plan_view(self.current_path or '', plain) or plan
        return bool(self._show_office(plain, inner, decrypted=True))

    def _showing(self, viewer, note=''):
        viewer.setVisible(True)
        self.placeholder.setVisible(False)
        self._set_notice(note)
        return True

    def _unavailable(self, text, note=''):
        self.placeholder.setText(text)
        self.placeholder.setVisible(True)
        self._set_notice(note)
        return False

    def _set_notice(self, note):
        self.notice.setText(note or '')
        self.notice.setVisible(bool(note))

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

            if self._html_viewer:
                self._html_viewer.clear()

            # Explicit shutdown of audio/video player
            if self._audio_video_player:
                try:
                    # Stop media playback and remove references
                    self._audio_video_player.safe_stop()
                    QApplication.processEvents()

                    # Release the widget, and with it its QMediaPlayer.
                    player = self._audio_video_player
                    self._audio_video_player = None
                    player.deleteLater()
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

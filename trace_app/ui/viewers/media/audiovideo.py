"""Audio and video player.

Plays either from a QBuffer or straight from the disk image via
PyTsk3StreamDevice, so large media does not have to be read into memory first.

Nothing plays until asked, but a loaded video shows its first frame --
paused at the start, which the FFmpeg backend draws -- and a line above the controls says what is loaded ("Video · 00:58 ·
352×240 · ready"). Before, a video opened as a black panel and an audio
file announced "Playing Audio" while nothing played; carved media, opened
one after another, looked broken. A file that will not decode says so in
the player, not in a dialog per file.
"""

import logging
import platform

from PySide6.QtCore import QSize, Qt, QTimer, QUrl
from PySide6.QtMultimedia import QAudioOutput, QMediaMetaData, QMediaPlayer
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                               QLabel, QPushButton, QSlider)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons

logger = logging.getLogger('TRACE.Viewer.Media')


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
        #: The first frame has been asked for (paused at the start).
        self._primed = False
        self._has_video = False
        self._first_frame = None
        self._failed = ""

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

        # Shown instead of the video for audio, and for a file that will
        # not decode.
        self.audio_label = QLabel("", self)
        self.audio_label.setObjectName("audioOnlyLabel")  # For stylesheet targeting
        self.audio_label.setAlignment(Qt.AlignCenter)
        self.audio_label.setWordWrap(True)
        self.audio_label.setVisible(False)

        # What is loaded, and whether it is playing.
        self.status_label = QLabel("", self)
        self.status_label.setObjectName("mediaStatusLine")
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # The first frame of a video, caught as it is primed.
        self.video_widget.videoSink().videoFrameChanged.connect(
            self._frame_arrived)

        # Set default volume
        self.audio_output.setVolume(self._current_volume / 100.0)

        # Create controls
        self.create_controls()

        # Add widgets to layout
        self.layout.addWidget(self.video_widget, 1)
        self.layout.addWidget(self.audio_label, 1)
        self.layout.addWidget(self.status_label)
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
            logger.error(f"Warning: Could not set audio-only mode options: {e}")

    def handle_media_status_change(self, status):
        """A new source loading resets; once loaded, say what it is and,
        for a video, show its first frame."""
        try:
            if status in (QMediaPlayer.LoadingMedia, QMediaPlayer.NoMedia):
                self._primed = False
                self._first_frame = None
                self._failed = ""
                if status == QMediaPlayer.LoadingMedia:
                    self.status_label.setText("Loading…")
            elif status == QMediaPlayer.LoadedMedia:
                self._has_video = bool(self.media_player.hasVideo())
                self.set_audio_only_mode(not self._has_video)
                self._describe()
                if self._has_video and not self._primed:
                    QTimer.singleShot(0, self._show_first_frame)
            elif status == QMediaPlayer.InvalidMedia:
                self._show_failure(self.media_player.errorString()
                                   or "the data is not playable media")
            elif status == QMediaPlayer.EndOfMedia:
                self._describe()
        except Exception as e:
            logger.error(f"Warning: Error detecting audio/video mode: {e}")

    # --- the first frame ---------------------------------------------

    def _show_first_frame(self):
        """Paused at the start, which the FFmpeg backend draws: the first
        frame shows and nothing plays or sounds. Called on the next turn of
        the loop, never from inside the player's own signal -- the backend
        holds its lock there, and controlling the player waited for ever."""
        self._primed = True
        if self.media_player.playbackState() == QMediaPlayer.StoppedState:
            self.media_player.pause()

    def _frame_arrived(self, frame):
        # Only noted: the picture's size, for the line above the controls.
        if frame.isValid() and self._first_frame is None:
            self._first_frame = frame.size()
            QTimer.singleShot(0, lambda: self._describe(self._first_frame))

    # --- what the line says --------------------------------------------

    def _describe(self, size=None):
        if self._failed:
            return
        duration = self.media_player.duration()
        parts = ["Video" if self._has_video else "Audio"]
        if duration > 0:
            parts.append(self.format_time(duration))
        if self._has_video:
            if size is None or not size.isValid():
                try:
                    size = self.media_player.metaData().value(
                        QMediaMetaData.Resolution)
                except Exception:
                    size = None
            if size is not None and getattr(size, 'isValid',
                                            lambda: False)():
                parts.append(f"{size.width()}×{size.height()}")
        state = self.media_player.playbackState()
        parts.append("playing" if state == QMediaPlayer.PlayingState
                     else
                     "paused" if state == QMediaPlayer.PausedState and
                     self.media_player.position() > 0 else
                     "ready — press Play")
        self.status_label.setText(" · ".join(parts))
        if not self._has_video:
            self.audio_label.setText(
                "Audio" + (f" · {self.format_time(duration)}"
                           if duration > 0 else ''))

    def _show_failure(self, reason):
        self._failed = reason
        self.video_widget.setVisible(False)
        self.audio_label.setText(
            f"This file could not be played: {reason}.\n\nA damaged or "
            "partly overwritten file often cannot be decoded; the Hex tab "
            "shows its bytes.")
        self.audio_label.setVisible(True)
        self.status_label.setText("Not playable")

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
                # Imported here, on Windows only: a failure is the volume
                # control's, not the whole media viewer's.
                from ctypes import POINTER, cast
                from comtypes import CLSCTX_ALL
                from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

                devices = AudioUtilities.GetSpeakers()
                self._audio_session = AudioUtilities.GetAllSessions()
                interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                self._volume_interface = cast(interface, POINTER(IAudioEndpointVolume))
            except Exception as e:
                logger.error(f"Could not initialize Windows audio integration: {e}")

    def set_os_volume(self, volume_level):
        """Set system volume (Windows only)"""
        if self._volume_interface and platform.system() == "Windows":
            try:
                # Convert from 0-100 to 0.0-1.0 range
                self._volume_interface.SetMasterVolumeLevelScalar(volume_level / 100.0, None)
            except Exception as e:
                logger.error(f"Error setting system volume: {e}")

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
            logger.error(f"Error stopping media playback: {e}")

    def update_play_state(self, state):
        # Updated for newer API
        self._is_playing = (state == QMediaPlayer.PlayingState)
        self.update_controls()
        self._describe()

    def update_controls(self):
        if self._is_playing:
            self.play_button.setIcon(icons.icon(icons.PAUSE))
        else:
            self.play_button.setIcon(icons.icon(icons.PLAY))

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
            self.volume_button.setIcon(icons.icon(icons.MUTE))
        else:
            self.set_volume(self._previous_volume)
            self.volume_button.setIcon(icons.icon(icons.VOLUME))

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
            self.volume_button.setIcon(icons.icon(icons.MUTE))
        else:
            self._is_muted = False
            self.volume_button.setIcon(icons.icon(icons.VOLUME))

        # Update system volume if enabled
        self.set_os_volume(volume)

    def handle_error(self, error, error_string):
        """In the player, not a dialog: clicking through carved files, a
        pop-up per damaged one would be a dialog per click."""
        if error != QMediaPlayer.NoError:
            logger.info("Media not playable: %s", error_string)
            self._show_failure(error_string or "unknown error")

    def closeEvent(self, event):
        # Clean up resources
        try:
            if hasattr(self, 'media_player') and self.media_player:
                self.media_player.stop()
        except Exception as e:
            logger.error(f"Error stopping media player during close: {e}")
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

        # Play/Pause button 
        self.play_button = QPushButton(self)
        self.play_button.setIcon(icons.icon(icons.PLAY))

        self.play_button.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.play_button.setFlat(True)
        self.play_button.setToolTip("Play/Pause")

        # Stop button 
        self.stop_button = QPushButton(self)
        self.stop_button.setIcon(icons.icon(icons.STOP))

        self.stop_button.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.stop_button.setFlat(True)
        self.stop_button.setToolTip("Stop")

        # Position slider
        self.position_slider = QSlider(Qt.Horizontal, self)
        self.position_slider.setRange(0, 0)  # Will be updated when media is loaded
        self.position_slider.setToolTip("Position")

        # Time labels
        self.current_time_label = QLabel("00:00", self)
        self.current_time_label.setMinimumWidth(40)
        self.total_time_label = QLabel("00:00", self)
        self.total_time_label.setMinimumWidth(40)

        # Volume button 
        self.volume_button = QPushButton(self)
        self.volume_button.setIcon(icons.icon(icons.VOLUME))

        self.volume_button.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.volume_button.setFlat(True)
        self.volume_button.setToolTip("Mute/Unmute")

        self.volume_slider = QSlider(Qt.Horizontal, self)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(self._current_volume)
        self.volume_slider.setMaximumWidth(80)
        self.volume_slider.setToolTip("Volume")

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
                            logger.error(f"Error removing audio output: {e}")

                # Set media to null/empty to release resources
                if hasattr(self.media_player, 'setSource'):
                    try:
                        self.media_player.setSource(QUrl())
                        # Process events to ensure this is applied
                        QApplication.processEvents()
                    except Exception as e:
                        logger.error(f"Error clearing media source: {e}")

        except Exception as e:
            logger.error(f"Error in safe_stop: {e}")

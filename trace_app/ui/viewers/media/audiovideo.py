"""Audio and video player.

Plays either from a QBuffer or straight from the disk image via
PyTsk3StreamDevice, so large media does not have to be read into memory first.
"""

import logging
import os
import platform

from PySide6.QtCore import Qt, QUrl, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                               QSlider, QSizePolicy)

from trace_app.infra.paths import resource_path
from trace_app.infra.constants import CONTROL_HEIGHT, TOOLBAR_ICON_SIZE
from trace_app.ui import icons

logger = logging.getLogger('TRACE.Viewer.Media')

if os.name == "nt":  # Windows
    # cast/POINTER are only used by the pycaw volume interface below, so they
    # belong inside the Windows guard alongside it.
    from ctypes import cast, POINTER
    from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
    from comtypes import CLSCTX_ALL


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
        self.audio_label.setObjectName("audioOnlyLabel")  # For stylesheet targeting
        self.audio_label.setAlignment(Qt.AlignCenter)
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
            logger.error(f"Warning: Could not set audio-only mode options: {e}")

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
            logger.error(f"Warning: Error detecting audio/video mode: {e}")

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

    def update_controls(self):
        if self._is_playing:
            # Try different pause icon paths
            pause_icon_paths = [
                icons.path(icons.PAUSE),
                icons.path(icons.PAUSE),
                icons.path(icons.PAUSE)
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
                icons.path(icons.PLAY),
                icons.path(icons.PLAY),
                icons.path(icons.PLAY)
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
                icons.path(icons.MUTE),
                icons.path(icons.MUTE)
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
                icons.path(icons.AUDIO),
                icons.path(icons.VOLUME),
                icons.path(icons.AUDIO)
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
                icons.path(icons.MUTE),
                icons.path(icons.MUTE)
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
                icons.path(icons.AUDIO),
                icons.path(icons.VOLUME),
                icons.path(icons.AUDIO)
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

        # Play/Pause button with fallback icon paths
        self.play_button = QPushButton(self)
        # Try different icon paths
        play_icon_paths = [
            icons.path(icons.PLAY),
            icons.path(icons.PLAY),
            icons.path(icons.PLAY)
        ]
        for path in play_icon_paths:
            if os.path.exists(path):
                self.play_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.play_button.setText("Play")

        self.play_button.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.play_button.setFlat(True)
        self.play_button.setToolTip("Play/Pause")

        # Stop button with fallback icon paths
        self.stop_button = QPushButton(self)
        # Try different icon paths
        stop_icon_paths = [
            icons.path(icons.STOP),
            icons.path(icons.STOP),
            icons.path(icons.STOP)
        ]
        for path in stop_icon_paths:
            if os.path.exists(path):
                self.stop_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.stop_button.setText("Stop")

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

        # Volume button with fallback icon paths
        self.volume_button = QPushButton(self)
        # Try different icon paths
        volume_icon_paths = [
            icons.path(icons.AUDIO),
            icons.path(icons.VOLUME),
            icons.path(icons.AUDIO)
        ]
        for path in volume_icon_paths:
            if os.path.exists(path):
                self.volume_button.setIcon(QIcon(path))
                break
        else:
            # Fallback - create a text button
            self.volume_button.setText("Vol")

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

                # Wait a moment for resources to be released
                time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error in safe_stop: {e}")

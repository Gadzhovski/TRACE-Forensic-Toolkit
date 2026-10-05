"""Audio and video player.

Plays either from a QBuffer or straight from the disk image via
PyTsk3StreamDevice, so large media does not have to be read into memory first.

Nothing plays until asked, but a loaded video shows its first frame --
paused at the start, which the FFmpeg backend draws -- and a line above the
controls says what is loaded ("Video · 00:58 · 352×240 · ready"). Before, a
video opened as a black panel and an audio file announced "Playing Audio"
while nothing played; carved media, opened one after another, looked broken.
A file that will not decode says so in the player, not in a dialog per file.

The controls are a toolbar like every other viewer's (tabler icons, the
shared height), always visible: the picture shrinks to make room for them.
It used to insist on 400×300, which in the Utils dock pushed the controls
out of sight until the dock was enlarged. For examining rather than
watching: frame-by-frame stepping, 5-second jumps, speed, loop, times to a
tenth of a second, and Save Frame -- the frame on screen as a PNG named after
the file and the moment in it.

Volume is the player's own. It used to set Windows' master volume, so moving
the slider changed every application's sound on the examiner's machine.
"""

import logging
import os

from PySide6.QtCore import QSize, Qt, QTimer, QUrl
from PySide6.QtMultimedia import QAudioOutput, QMediaMetaData, QMediaPlayer
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import (QApplication, QComboBox, QFileDialog, QLabel,
                               QSizePolicy, QSlider, QStyle,
                               QStyleOptionSlider, QToolBar, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.widgets.toolbars import prepare_toolbar

logger = logging.getLogger('TRACE.Viewer.Media')

#: How far the jump buttons and the arrow keys move.
JUMP_MS = 5000
#: Used to step a frame when the file does not say its frame rate.
DEFAULT_FPS = 25.0
#: Playback speeds offered.
SPEEDS = (0.25, 0.5, 1.0, 1.5, 2.0)


class SeekSlider(QSlider):
    """A position slider that jumps to where it is clicked -- QSlider only
    pages towards the click, a step at a time."""

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.maximum() > 0:
            option = QStyleOptionSlider()
            self.initStyleOption(option)
            groove = self.style().subControlRect(
                QStyle.CC_Slider, option, QStyle.SC_SliderGroove, self)
            handle = self.style().subControlRect(
                QStyle.CC_Slider, option, QStyle.SC_SliderHandle, self)
            if not handle.contains(event.position().toPoint()):
                span = max(1, groove.width() - handle.width())
                x = event.position().x() - groove.x() - handle.width() / 2
                value = QStyle.sliderValueFromPosition(
                    self.minimum(), self.maximum(), int(x), span)
                self.setValue(value)
                self.sliderMoved.emit(value)
                event.accept()
                return
        super().mousePressEvent(event)


class AudioVideoPlayer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setObjectName("mediaPlayer")
        self.setFocusPolicy(Qt.StrongFocus)

        self._is_playing = False
        self._current_volume = 80
        self._is_muted = False
        self._is_audio_only = False
        self._shutting_down = False
        #: The first frame has been asked for (paused at the start).
        self._primed = False
        self._has_video = False
        self._first_frame = None
        self._failed = ""
        #: What is loaded, for Save Frame's file name.
        self.source_name = ''

        self.initialize_ui()
        self.setup_connections()
        self._set_enabled(False)

    # --- building ----------------------------------------------------------

    def initialize_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # The picture takes what room there is -- and gives it up, so the
        # controls below always show.
        self.video_widget = QVideoWidget(self)
        self.video_widget.setObjectName("mediaVideo")
        self.video_widget.setMinimumSize(QSize(160, 90))
        self.video_widget.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)

        self.media_player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.media_player.setVideoOutput(self.video_widget)
        self.media_player.setAudioOutput(self.audio_output)
        self.audio_output.setVolume(self._current_volume / 100.0)

        # Shown instead of the video for audio, and for a file that will
        # not decode.
        self.audio_label = QLabel("", self)
        self.audio_label.setObjectName("audioOnlyLabel")
        self.audio_label.setAlignment(Qt.AlignCenter)
        self.audio_label.setWordWrap(True)
        self.audio_label.setMinimumHeight(60)
        self.audio_label.setSizePolicy(QSizePolicy.Expanding,
                                       QSizePolicy.Expanding)
        self.audio_label.setVisible(False)

        # What is loaded, and whether it is playing.
        self.status_label = QLabel("", self)
        self.status_label.setObjectName("mediaStatusLine")
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.video_widget.videoSink().videoFrameChanged.connect(
            self._frame_arrived)

        self.create_controls()

        self.layout.addWidget(self.video_widget, 1)
        self.layout.addWidget(self.audio_label, 1)
        self.layout.addWidget(self.status_label)
        self.layout.addWidget(self.control_widget)

    def create_controls(self):
        """One toolbar, built like the other viewers': transport, then
        stepping, the position, then speed, loop, Save Frame and volume."""
        bar = QToolBar(self)
        prepare_toolbar(bar)
        bar.setObjectName("compactToolbar")
        bar.setContextMenuPolicy(Qt.PreventContextMenu)
        self.control_widget = bar

        def action(icon, text, slot, shortcut=''):
            act = icons.action(icon, text, self)
            if shortcut:
                act.setToolTip(f"{text} ({shortcut})")
            act.triggered.connect(slot)
            bar.addAction(act)
            return act

        self.play_action = action(icons.PLAY, "Play", self.toggle_play,
                                  "Space")
        self.stop_action = action(icons.STOP, "Stop", self.stop)
        bar.addSeparator()
        self.back_action = action(icons.SEEK_BACK, "Back 5 seconds",
                                  lambda: self.jump(-JUMP_MS), "Left")
        self.frame_back_action = action(icons.FRAME_BACK, "Previous frame",
                                        lambda: self.step_frame(-1), ",")
        self.frame_next_action = action(icons.FRAME_FORWARD, "Next frame",
                                        lambda: self.step_frame(1), ".")
        self.forward_action = action(icons.SEEK_FORWARD, "Forward 5 seconds",
                                     lambda: self.jump(JUMP_MS), "Right")
        bar.addSeparator()

        self.current_time_label = QLabel("00:00.0", self)
        self.current_time_label.setObjectName("mediaTime")
        bar.addWidget(self.current_time_label)
        self.position_slider = SeekSlider(Qt.Horizontal, self)
        self.position_slider.setObjectName("mediaPosition")
        self.position_slider.setRange(0, 0)
        self.position_slider.setToolTip("Position: click or drag to move")
        self.position_slider.setSizePolicy(QSizePolicy.Expanding,
                                           QSizePolicy.Fixed)
        self.position_slider.setMinimumWidth(80)
        bar.addWidget(self.position_slider)
        self.total_time_label = QLabel("00:00.0", self)
        self.total_time_label.setObjectName("mediaTime")
        bar.addWidget(self.total_time_label)
        bar.addSeparator()

        self.speed_combo = QComboBox(self)
        self.speed_combo.setObjectName("mediaSpeed")
        self.speed_combo.setToolTip("Playback speed")
        for speed in SPEEDS:
            self.speed_combo.addItem(f"{speed:g}×", speed)
        self.speed_combo.setCurrentIndex(SPEEDS.index(1.0))
        self.speed_combo.currentIndexChanged.connect(
            lambda _i: self.media_player.setPlaybackRate(
                self.speed_combo.currentData()))
        bar.addWidget(self.speed_combo)
        self.loop_action = action(icons.LOOP, "Loop", self._set_loop)
        self.loop_action.setCheckable(True)
        self.snapshot_action = action(icons.SNAPSHOT, "Save Frame...",
                                      self.save_frame)
        self.snapshot_action.setToolTip(
            "Save the frame on screen as a PNG, named after the file and the "
            "moment in it")
        bar.addSeparator()
        self.volume_action = action(icons.VOLUME, "Mute", self.toggle_mute,
                                    "M")
        self.volume_slider = QSlider(Qt.Horizontal, self)
        self.volume_slider.setObjectName("mediaVolume")
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(self._current_volume)
        self.volume_slider.setFixedWidth(80)
        self.volume_slider.setToolTip("Volume")
        bar.addWidget(self.volume_slider)
        bar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))

    def setup_connections(self):
        self.media_player.errorOccurred.connect(self.handle_error)
        self.media_player.positionChanged.connect(self.update_position)
        self.media_player.durationChanged.connect(self.update_duration)
        self.media_player.playbackStateChanged.connect(self.update_play_state)
        self.media_player.mediaStatusChanged.connect(
            self.handle_media_status_change)
        self.position_slider.sliderMoved.connect(self.set_position)
        self.volume_slider.valueChanged.connect(self.set_volume)

    # --- the loaded file ----------------------------------------------------

    def set_audio_only_mode(self, is_audio_only=True):
        """Audio: a panel instead of the picture, and no picture controls."""
        self._is_audio_only = is_audio_only
        self.video_widget.setVisible(not is_audio_only)
        self.audio_label.setVisible(is_audio_only)
        for act in (self.frame_back_action, self.frame_next_action,
                    self.snapshot_action):
            act.setEnabled(not is_audio_only and not self._failed)

    def handle_media_status_change(self, status):
        """A new source loading resets; once loaded, say what it is and,
        for a video, show its first frame."""
        try:
            if status in (QMediaPlayer.LoadingMedia, QMediaPlayer.NoMedia):
                self._primed = False
                self._first_frame = None
                self._failed = ""
                self._set_enabled(False)
                # Nothing of the last file may linger on the next.
                self.update_duration(0)
                self.update_position(0)
                if status == QMediaPlayer.LoadingMedia:
                    self.status_label.setText("Loading…")
                else:
                    self.status_label.setText("")
            elif status == QMediaPlayer.LoadedMedia:
                self._has_video = bool(self.media_player.hasVideo())
                self._set_enabled(True)
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

    def _set_enabled(self, enabled):
        for act in (self.play_action, self.stop_action, self.back_action,
                    self.forward_action, self.frame_back_action,
                    self.frame_next_action, self.loop_action,
                    self.snapshot_action):
            act.setEnabled(enabled)
        self.position_slider.setEnabled(enabled)
        self.speed_combo.setEnabled(enabled)

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

    def _frame_rate(self):
        try:
            rate = float(self.media_player.metaData().value(
                QMediaMetaData.VideoFrameRate) or 0)
        except (TypeError, ValueError):
            rate = 0
        return rate if 1 <= rate <= 240 else DEFAULT_FPS

    # --- what the line says --------------------------------------------

    def _describe(self, size=None):
        if self._failed:
            return
        duration = self.media_player.duration()
        parts = ["Video" if self._has_video else "Audio"]
        if duration > 0:
            parts.append(self.format_time(duration, tenths=False))
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
            parts.append(f"{round(self._frame_rate(), 2):g} fps")
        state = self.media_player.playbackState()
        parts.append("playing" if state == QMediaPlayer.PlayingState
                     else
                     "paused" if state == QMediaPlayer.PausedState and
                     self.media_player.position() > 0 else
                     "ready — press Play")
        self.status_label.setText(" · ".join(parts))
        if not self._has_video:
            self.audio_label.setText(
                "Audio" + (f" · {self.format_time(duration, tenths=False)}"
                           if duration > 0 else ''))

    def _show_failure(self, reason):
        self._failed = reason
        self._set_enabled(False)
        self.update_duration(0)
        self.update_position(0)
        self.video_widget.setVisible(False)
        self.audio_label.setText(
            f"This file could not be played: {reason}.\n\nA damaged or "
            "partly overwritten file often cannot be decoded; the Hex tab "
            "shows its bytes.")
        self.audio_label.setVisible(True)
        self.status_label.setText("Not playable")

    # --- transport ---------------------------------------------------------

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

    def jump(self, delta_ms):
        duration = self.media_player.duration()
        position = self.media_player.position() + delta_ms
        if duration > 0:
            position = min(position, duration - 1)
        self.media_player.setPosition(max(0, position))

    def step_frame(self, frames):
        """One frame on or back, paused: what an examiner looks at."""
        if not self._has_video:
            return
        if self._is_playing:
            self.media_player.pause()
        step = 1000.0 / self._frame_rate()
        self.jump(int(round(frames * step)))

    def _set_loop(self, on):
        self.media_player.setLoops(QMediaPlayer.Infinite if on else 1)

    def update_play_state(self, state):
        self._is_playing = (state == QMediaPlayer.PlayingState)
        self.update_controls()
        self._describe()

    def update_controls(self):
        playing = self._is_playing
        icons.apply_to(self.play_action, icons.PAUSE if playing
                       else icons.PLAY)
        self.play_action.setText("Pause" if playing else "Play")
        self.play_action.setToolTip(("Pause" if playing else "Play")
                                    + " (Space)")

    def set_position(self, position):
        self.media_player.setPosition(position)

    def update_position(self, position):
        self.position_slider.blockSignals(True)
        self.position_slider.setValue(position)
        self.position_slider.blockSignals(False)
        self.current_time_label.setText(self.format_time(position))

    def update_duration(self, duration):
        self.position_slider.setRange(0, duration)
        self.position_slider.setPageStep(max(1000, duration // 20))
        self.total_time_label.setText(self.format_time(duration))

    @staticmethod
    def format_time(milliseconds, tenths=True):
        """'01:05.3', or '1:02:05.3' past an hour; tenths of a second,
        because 'the frame at 00:12' covers a dozen frames."""
        milliseconds = max(0, int(milliseconds or 0))
        seconds, rest = divmod(milliseconds, 1000)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        text = (f"{hours}:{minutes:02d}:{seconds:02d}" if hours
                else f"{minutes:02d}:{seconds:02d}")
        return f"{text}.{rest // 100}" if tenths else text

    # --- volume ---------------------------------------------------------

    def toggle_mute(self):
        self._is_muted = not self._is_muted
        self.audio_output.setMuted(self._is_muted)
        self._volume_icon()

    def set_volume(self, volume):
        self._current_volume = volume
        self.audio_output.setVolume(volume / 100.0)
        self.volume_slider.blockSignals(True)
        self.volume_slider.setValue(volume)
        self.volume_slider.blockSignals(False)
        if self._is_muted and volume > 0:
            self._is_muted = False
            self.audio_output.setMuted(False)
        self._volume_icon()

    def _volume_icon(self):
        silent = self._is_muted or self._current_volume == 0
        icons.apply_to(self.volume_action, icons.MUTE if silent
                       else icons.VOLUME)
        self.volume_action.setText("Unmute" if self._is_muted else "Mute")
        self.volume_action.setToolTip(self.volume_action.text() + " (M)")

    # --- Save Frame -------------------------------------------------------

    def current_frame_image(self):
        """The frame on screen as a QImage, or a null one."""
        frame = self.video_widget.videoSink().videoFrame()
        from PySide6.QtGui import QImage
        return frame.toImage() if frame.isValid() else QImage()

    def frame_file_name(self):
        """'<file> @ 00m12.4s.png': the file and the moment in it."""
        base = os.path.splitext(os.path.basename(self.source_name or
                                                 'video'))[0] or 'video'
        position = self.media_player.position()
        seconds, rest = divmod(position, 1000)
        minutes, seconds = divmod(seconds, 60)
        stamp = f"{minutes:02d}m{seconds:02d}.{rest // 100}s"
        safe = ''.join(c if c.isalnum() or c in ' -_.()[]' else '_'
                       for c in base)[:80]
        return f"{safe} @ {stamp}.png"

    def save_frame(self, path=None):
        """Save the frame on screen as a PNG. Returns the path, or ''."""
        image = self.current_frame_image()
        if image.isNull():
            self.status_label.setText("No frame to save yet: play or step "
                                      "to one.")
            return ''
        if path is None:
            from trace_app.core import settings as case_settings
            folder = case_settings.export_dir() or os.path.expanduser('~')
            path, _ = QFileDialog.getSaveFileName(
                self, "Save frame", os.path.join(folder,
                                                 self.frame_file_name()),
                "PNG image (*.png)")
            if not path:
                return ''
        if not image.save(path, 'PNG'):
            self.status_label.setText(f"Could not save {path}")
            return ''
        self.status_label.setText(f"Frame saved: {path}")
        logger.info("Frame at %d ms of %s saved to %s",
                    self.media_player.position(), self.source_name, path)
        return path

    # --- keys ---------------------------------------------------------------

    def keyPressEvent(self, event):
        if self._failed or self.media_player.mediaStatus() in (
                QMediaPlayer.NoMedia, QMediaPlayer.LoadingMedia):
            return super().keyPressEvent(event)
        key = event.key()
        if key == Qt.Key_Space:
            self.toggle_play()
        elif key == Qt.Key_Left:
            self.jump(-JUMP_MS)
        elif key == Qt.Key_Right:
            self.jump(JUMP_MS)
        elif key == Qt.Key_Comma:
            self.step_frame(-1)
        elif key == Qt.Key_Period:
            self.step_frame(1)
        elif key == Qt.Key_M:
            self.toggle_mute()
        else:
            return super().keyPressEvent(event)
        event.accept()

    def mousePressEvent(self, event):
        # Clicking the picture gives the keys to the player.
        self.setFocus(Qt.MouseFocusReason)
        super().mousePressEvent(event)

    # --- errors and teardown ------------------------------------------------

    def handle_error(self, error, error_string):
        """In the player, not a dialog: clicking through carved files, a
        pop-up per damaged one would be a dialog per click."""
        if error != QMediaPlayer.NoError:
            logger.info("Media not playable: %s", error_string)
            self._show_failure(error_string or "unknown error")

    def closeEvent(self, event):
        try:
            if hasattr(self, 'media_player') and self.media_player:
                self.media_player.stop()
        except Exception as e:
            logger.error(f"Error stopping media player during close: {e}")
        super().closeEvent(event)

    def __del__(self):
        try:
            if not hasattr(self, '_shutting_down') or not self._shutting_down:
                self.safe_stop()
        except Exception:
            # Silently ignore errors during destruction
            pass

    def safe_stop(self):
        """Safely stop playback even during shutdown."""
        try:
            if hasattr(self, 'media_player') and self.media_player:
                self._shutting_down = True
                self.media_player.stop()
                QApplication.processEvents()
                if hasattr(self, 'audio_output') and self.audio_output:
                    try:
                        self.media_player.setAudioOutput(None)
                        QApplication.processEvents()
                    except Exception as e:
                        logger.error(f"Error removing audio output: {e}")
                try:
                    self.media_player.setSource(QUrl())
                    QApplication.processEvents()
                except Exception as e:
                    logger.error(f"Error clearing media source: {e}")
        except Exception as e:
            logger.error(f"Error in safe_stop: {e}")

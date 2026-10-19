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
import time

from PySide6.QtCore import (QEventLoop, QObject, QPointF, QRectF, QSize, Qt,
                            QThread, QTimer, QUrl, Signal, Slot)
from PySide6.QtGui import (QActionGroup, QColor, QImage, QPainter,
                           QPainterPath, QPen)
from PySide6.QtMultimedia import (QAudioOutput, QMediaMetaData,
                                  QMediaPlayer, QVideoSink)
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QMenu,
                               QPushButton, QSizePolicy, QSlider, QSpinBox,
                               QSplitter, QStackedWidget, QStyle,
                               QStyleOptionSlider, QTabWidget, QToolBar,
                               QToolButton, QVBoxLayout, QWidget)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.image_adjust import AdjustPanel
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.property_table import PropertyTable
from trace_app.ui.widgets.toolbars import prepare_toolbar, stretch

logger = logging.getLogger('TRACE.Viewer.Media')

#: How far the jump buttons and the arrow keys move.
JUMP_MS = 5000
#: Used to step a frame when the file does not say its frame rate.
DEFAULT_FPS = 25.0
#: Playback speeds offered.
SPEEDS = (0.25, 0.5, 1.0, 1.5, 2.0)
#: A stop() still running after this long is logged with the window's
#: stack -- it is the backend's own wait, which nothing here can end.
STOP_WATCHDOG_SECONDS = 5.0
#: The paused frame enlarges up to this (pixels drawn as blocks).
FRAME_MAX_ZOOM = 16.0
#: A frame asked for (contact sheet, export) that has not come by then is
#: recorded as not decoded.
GRAB_TIMEOUT_MS = 5000
#: Frames one export writes at most.
MAX_EXPORT_FRAMES = 2000
#: Frames on a contact sheet by default.
SHEET_FRAMES = 16
#: Audio files decoded for the waveform when in memory up to this size.
WAVEFORM_MAX_BYTES = 256 * 1024 * 1024
#: Below this width the volume slider gives way (the button still mutes):
#: in a narrow dock the controls' row would otherwise overflow.
VOLUME_SLIDER_FROM = 620
#: The side panel's share of the player's width when it opens, and its
#: bounds in pixels.
SIDE_SHARE = 0.36
SIDE_WIDTH = (260, 360)


def _drain(seconds):
    """Run pending events for `seconds`: the frames already on their way
    to the window arrive before the player is torn down."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        QApplication.processEvents(QEventLoop.AllEvents, 20)


class _StopWatchdog:
    """Logs where the window's thread is if QMediaPlayer.stop() has not
    returned in STOP_WATCHDOG_SECONDS. The wait is inside Qt's FFmpeg
    backend; a thread cannot end it, but the log then says it happened and
    where, instead of a window that froze with nothing recorded."""

    def __init__(self):
        import threading
        self._main = threading.get_ident()
        self._timer = threading.Timer(STOP_WATCHDOG_SECONDS, self._report)
        self._timer.daemon = True
        self._timer.start()

    def _report(self):
        import sys
        import traceback
        frame = sys._current_frames().get(self._main)
        stack = ''.join(traceback.format_stack(frame)) if frame else '?'
        logger.error("The media player has not stopped after %.0f s (Qt's "
                     "FFmpeg backend is waiting); the window's thread is "
                     "at:\n%s", STOP_WATCHDOG_SECONDS, stack)

    def cancel(self):
        self._timer.cancel()


def frame_number(position_ms, fps):
    """The frame shown at `position_ms`, counting from 0."""
    return int(max(0, position_ms) * fps / 1000 + 1e-6)


def parse_position(text, fps):
    """A position typed by the examiner, in ms, or None: '83.4' seconds,
    '01:23.4', '1:02:03', or a frame: 'f2071' / '#2071' / 'frame 2071'."""
    text = (text or '').strip().lower()
    if not text:
        return None
    for prefix in ('frame', 'f', '#'):
        if text.startswith(prefix):
            number = text[len(prefix):].strip()
            if number.isdigit():
                return int(round(int(number) * 1000 / fps))
            return None
    parts = text.split(':')
    if len(parts) > 3:
        return None
    try:
        values = [float(part) for part in parts]
    except ValueError:
        return None
    if any(value < 0 for value in values) or \
            any(value >= 60 for value in values[1:]):
        return None
    seconds = 0.0
    for value in values:
        seconds = seconds * 60 + value
    return int(round(seconds * 1000))


class SeekSlider(QSlider):
    """A position slider that jumps to where it is clicked -- QSlider only
    pages towards the click, a step at a time. Markers are drawn on it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.markers = []

    def set_markers(self, markers):
        self.markers = list(markers)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.markers or self.maximum() <= 0:
            return
        option = QStyleOptionSlider()
        self.initStyleOption(option)
        groove = self.style().subControlRect(
            QStyle.CC_Slider, option, QStyle.SC_SliderGroove, self)
        handle = self.style().subControlRect(
            QStyle.CC_Slider, option, QStyle.SC_SliderHandle, self)
        span = max(1, groove.width() - handle.width())
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        colour = QColor(self.palette().highlight().color())
        if not self.isEnabled():
            colour.setAlpha(110)
        # A pin above the track and a tick across it: seen beside the
        # handle, and never hidden under it.
        middle = groove.center().y() + 0.5
        for marker in self.markers:
            x = groove.x() + handle.width() / 2 + QStyle.sliderPositionFromValue(
                self.minimum(), self.maximum(), int(marker), span)
            painter.setPen(QPen(colour, 2))
            painter.drawLine(QPointF(x, middle - 4), QPointF(x, middle + 4))
            pin = QPainterPath()
            pin.moveTo(x - 4, 0.5)
            pin.lineTo(x + 4, 0.5)
            pin.lineTo(x, 5.5)
            pin.closeSubpath()
            painter.setPen(Qt.NoPen)
            painter.setBrush(colour)
            painter.drawPath(pin)
        painter.end()

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


class FrameView(QWidget):
    """The picture: the newest frame, scaled to fit (never cropped), on
    black. It reads a plain QVideoSink rather than being a QVideoWidget:
    QVideoWidget hands frames over in a way that made the FFmpeg backend's
    render thread wait for the window's thread, so a stop(), a new source
    or a detach while a frame was on its way waited for ever (1 run in 10
    under load, Linux and macOS). A sink only signals, queued to this
    thread; nothing in the backend ever waits on the window."""

    #: A new decoded frame arrived (the adjusted view, if any, is gone).
    frame_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sink = QVideoSink(self)
        self._image = QImage()
        #: An adjusted copy of the frame, shown in its place while set.
        self._view = None
        #: 1 = the frame fits; above, enlarged about `_centre` (0..1).
        self.zoom = 1.0
        self._centre = QPointF(0.5, 0.5)
        self._drag = None
        self._sink.videoFrameChanged.connect(self._frame)
        self.setAttribute(Qt.WA_OpaquePaintEvent)
        self.setToolTip("Ctrl+wheel zooms the frame (pixels drawn as "
                        "blocks when enlarged); drag to move; double-click "
                        "to fit")

    def videoSink(self):
        return self._sink

    def _frame(self, frame):
        if frame.isValid():
            image = frame.toImage()
            if not image.isNull():
                self._image = image
                self._view = None
                self.update()
                self.frame_changed.emit()

    def frame(self):
        """The decoded frame on screen (QImage; null when none)."""
        return self._image

    def set_view(self, image):
        """Show `image` (an adjusted frame) instead; None = the frame."""
        self._view = image
        self.update()

    def clear(self):
        self._image = QImage()
        self._view = None
        self.zoom = 1.0
        self._centre = QPointF(0.5, 0.5)
        self.update()

    def _target(self, image):
        """Where `image` is drawn: fitted, then zoomed about the centre."""
        size = image.size().scaled(self.size(), Qt.KeepAspectRatio)
        width, height = size.width() * self.zoom, size.height() * self.zoom
        x = self.width() / 2 - self._centre.x() * width
        y = self.height() / 2 - self._centre.y() * height
        if self.zoom <= 1:
            x = (self.width() - width) / 2
            y = (self.height() - height) / 2
        return QRectF(x, y, width, height)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0))
        image = self._view if self._view is not None else self._image
        if image.isNull():
            return
        target = self._target(image)
        # Reduced, smoothed; enlarged, each pixel a block (nothing made up).
        enlarged = target.width() * self.devicePixelRatioF() >= image.width()
        painter.setRenderHint(QPainter.SmoothPixmapTransform, not enlarged)
        painter.drawImage(target, image)

    def set_zoom(self, zoom, anchor=None):
        image = self._view if self._view is not None else self._image
        if image.isNull():
            return
        if anchor is not None and self.zoom > 1:
            target = self._target(image)
            self._centre = QPointF(
                (anchor.x() - target.x()) / max(1.0, target.width()),
                (anchor.y() - target.y()) / max(1.0, target.height()))
        elif self.zoom <= 1 and anchor is not None:
            target = self._target(image)
            self._centre = QPointF(
                min(1, max(0, (anchor.x() - target.x()) /
                           max(1.0, target.width()))),
                min(1, max(0, (anchor.y() - target.y()) /
                           max(1.0, target.height()))))
        self.zoom = min(FRAME_MAX_ZOOM, max(1.0, zoom))
        if self.zoom == 1:
            self._centre = QPointF(0.5, 0.5)
        self.update()

    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier:
            step = 1.25 if event.angleDelta().y() > 0 else 1 / 1.25
            self.set_zoom(self.zoom * step, event.position())
            event.accept()
            return
        super().wheelEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.zoom > 1:
            self._drag = event.position()
            self.setCursor(Qt.ClosedHandCursor)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drag is not None:
            image = self._view if self._view is not None else self._image
            target = self._target(image)
            delta = event.position() - self._drag
            self._drag = event.position()
            self._centre = QPointF(
                min(1, max(0, self._centre.x() -
                           delta.x() / max(1.0, target.width()))),
                min(1, max(0, self._centre.y() -
                           delta.y() / max(1.0, target.height()))))
            self.update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._drag is not None:
            self._drag = None
            self.unsetCursor()
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        self.set_zoom(1.0)
        super().mouseDoubleClickEvent(event)


class _AdjustJob(QThread):
    """The Adjust settings on one paused frame, with Pillow (C) off the
    window's thread."""

    done = Signal(object)

    def __init__(self, serial, image, settings, parent=None):
        super().__init__(parent)
        self.serial = serial
        self.image = image.convertToFormat(QImage.Format_RGBA8888)
        self.settings = settings

    def run(self):
        result = {'serial': self.serial}
        try:
            from PIL import Image
            from trace_app.core import image_forensics
            from trace_app.ui.viewers.media.picture import to_qimage
            source = self.image
            data = bytes(source.constBits())[:source.sizeInBytes()]
            picture = Image.frombuffer(
                'RGBA', (source.width(), source.height()), data, 'raw',
                'RGBA', source.bytesPerLine(), 1).convert('RGB')
            result['image'] = to_qimage(
                image_forensics.adjust(picture, self.settings))
            result['steps'] = image_forensics.describe(self.settings)
        except Exception as exc:
            logger.debug("Frame not adjusted: %s", exc)
            result['error'] = str(exc)
        self.done.emit(result)


class _FrameGrabber(QObject):
    """Frames at chosen times, read through the player itself: paused,
    moved to each time on the next turn of the loop (never from inside a
    player signal), and the first frame the sink delivers at or after it
    kept, with the time the decoder gave it. A time that brings no frame in
    `GRAB_TIMEOUT_MS` is kept as None and said so."""

    #: [(asked ms, decoded ms or None, QImage or None)]
    finished = Signal(object)
    progress = Signal(int, int)

    def __init__(self, player, times, parent=None):
        super().__init__(parent)
        self.player = player
        self.times = list(times)
        self.results = []
        self.cancelled = False
        self._waiting = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._timed_out)

    def start(self):
        self.player.video_widget.videoSink().videoFrameChanged.connect(
            self._frame)
        QTimer.singleShot(0, self._next)

    def cancel(self):
        self.cancelled = True

    @Slot()
    def _next(self):
        if self.cancelled or len(self.results) >= len(self.times):
            self._end()
            return
        self.progress.emit(len(self.results), len(self.times))
        target = self.times[len(self.results)]
        self._waiting = True
        self._timer.start(GRAB_TIMEOUT_MS)
        self.player.media_player.setPosition(target)

    @Slot(object)
    def _frame(self, frame):
        if not self._waiting or not frame.isValid():
            return
        target = self.times[len(self.results)]
        start = frame.startTime()
        tolerance = 1500.0 / max(1.0, self.player._frame_rate())
        if start >= 0 and start / 1000 < target - tolerance:
            return                      # a frame from before the move
        image = frame.toImage()
        if image.isNull():
            return
        self._waiting = False
        self._timer.stop()
        self.results.append((target, start / 1000 if start >= 0 else None,
                             image))
        QTimer.singleShot(0, self._next)

    @Slot()
    def _timed_out(self):
        if not self._waiting:
            return
        self._waiting = False
        self.results.append((self.times[len(self.results)], None, None))
        QTimer.singleShot(0, self._next)

    def _end(self):
        self._timer.stop()
        try:
            self.player.video_widget.videoSink().videoFrameChanged.disconnect(
                self._frame)
        except (RuntimeError, TypeError):
            pass
        self.finished.emit(self.results)


class _ExportFramesDialog(QDialog):
    """From, to, and how often."""

    def __init__(self, parent, start, end, rate):
        super().__init__(parent)
        self.setWindowTitle("Export frames")
        form = QFormLayout(self)
        self.start = QLineEdit(start, self)
        self.end = QLineEdit(end, self)
        self.every = QSpinBox(self)
        self.every.setRange(1, 3600)
        self.every.setValue(1)
        self.unit = QComboBox(self)
        self.unit.addItem("seconds", 'seconds')
        self.unit.addItem(f"frames (at {rate:g} fps)", 'frames')
        every = QHBoxLayout()
        every.addWidget(self.every)
        every.addWidget(self.unit, 1)
        form.addRow("From", self.start)
        form.addRow("To", self.end)
        form.addRow("Every", every)
        note = QLabel(f"Times as 83.4, 01:23.4 or f2071. At most "
                      f"{MAX_EXPORT_FRAMES:,} frames; each PNG's SHA-256 "
                      "goes in manifest.csv beside them.", self)
        note.setObjectName("adjustNote")
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok |
                                   QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)


def _scrolled(page, parent):
    """`page` in a scroll area: a side page taller than a short dock
    scrolls instead of holding the player taller than the dock."""
    from PySide6.QtWidgets import QFrame, QScrollArea
    area = QScrollArea(parent)
    area.setObjectName("mediaSideScroll")
    area.setFrameShape(QFrame.NoFrame)
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    area.setWidget(page)
    return area


class AudioVideoPlayer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setObjectName("mediaPlayer")
        self.setFocusPolicy(Qt.StrongFocus)

        self._is_playing = False
        self._current_volume = 80
        self._is_muted = False
        self._shutting_down = False
        #: The first frame has been asked for (paused at the start).
        self._primed = False
        self._has_video = False
        self._first_frame = None
        self._failed = ""
        #: What is loaded, for Save Frame's file name.
        self.source_name = ''
        #: The container's own metadata (core/media_metadata), or None.
        self.metadata = None
        #: The file's bytes when it is in memory (else streamed), and
        #: their SHA-256 once worked out.
        self._content = None
        self._content_sha256 = None
        #: Moments marked: [(position ms, note)], in time order.
        self.markers = []
        #: (label) -> bookmark the file; (lat, lon, name, what) -> Map.
        self.bookmark_hook = None
        self.show_place_hook = None
        self._jobs = KeptThreads(self)
        self._adjust_serial = 0
        self._adjusted_steps = ''
        self._grabber = None
        self._adjusted_view = None
        #: The last contact sheet saved: {'path', 'sha256', ...}.
        self.last_sheet = None

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
        self.video_widget = FrameView(self)
        self.video_widget.setObjectName("mediaVideo")
        # Small: a short Utils dock still shows every control below.
        self.video_widget.setMinimumSize(QSize(120, 36))
        self.video_widget.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)

        self.media_player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.media_player.setVideoOutput(self.video_widget.videoSink())
        self.media_player.setAudioOutput(self.audio_output)
        self.audio_output.setVolume(self._current_volume / 100.0)

        # Shown instead of the video for audio, and for a file that will
        # not decode.
        self.audio_label = QLabel("", self)
        self.audio_label.setObjectName("audioOnlyLabel")
        self.audio_label.setAlignment(Qt.AlignCenter)
        self.audio_label.setWordWrap(True)
        self.audio_label.setMinimumHeight(36)
        self.audio_label.setSizePolicy(QSizePolicy.Expanding,
                                       QSizePolicy.Expanding)
        self.audio_label.setVisible(False)

        # What is loaded, and whether it is playing (cut short with '…'
        # when the dock is narrow, the whole line in its tooltip).
        self.status_label = ElidedLabel("", self)
        self.status_label.setObjectName("mediaStatusLine")

        self.video_widget.videoSink().videoFrameChanged.connect(
            self._frame_arrived)

        self.video_widget.frame_changed.connect(self._new_frame)

        from trace_app.ui.viewers.media.waveform import WaveformView
        self.waveform = WaveformView(self)
        self.waveform.setVisible(False)
        self.waveform.seek_requested.connect(self.set_position)

        self.create_controls()

        picture = QWidget(self)
        column = QVBoxLayout(picture)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self.video_widget, 1)
        column.addWidget(self.audio_label, 1)
        column.addWidget(self.waveform, 1)
        self.side = self._build_side()
        self.side.setVisible(False)
        self.splitter = QSplitter(Qt.Horizontal, self)
        self.splitter.setObjectName("mediaSplitter")
        self.splitter.addWidget(picture)
        self.splitter.addWidget(self.side)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setChildrenCollapsible(False)

        self.layout.addWidget(self.splitter, 1)
        self.layout.addWidget(self.controls_panel)

    def _build_side(self):
        """Info (the container's own metadata), Markers, Adjust."""
        side = QTabWidget(self)
        side.setObjectName("mediaSidePanel")
        side.setDocumentMode(True)
        side.tabBar().setExpanding(True)
        side.setMinimumWidth(SIDE_WIDTH[0])

        # Info: what the file is in a line, then the container's own facts
        # as a table -- a label column and the values beside it.
        info = QWidget(side)
        info.setObjectName("mediaSidePage")
        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(10, 10, 10, 10)
        info_layout.setSpacing(6)
        self.info_title = ElidedLabel("", info)
        self.info_title.setObjectName("mediaInfoTitle")
        self.info_summary = QLabel("", info)
        self.info_summary.setObjectName("mediaInfoSummary")
        self.info_summary.setWordWrap(True)
        info_layout.addWidget(self.info_title)
        info_layout.addWidget(self.info_summary)
        self.info_view = PropertyTable(parent=info)
        self.info_view.setObjectName("mediaInfoTable")
        info_layout.addWidget(self.info_view, 1)
        self.info_notes = QLabel("", info)
        self.info_notes.setObjectName("adjustNote")
        self.info_notes.setWordWrap(True)
        self.info_notes.setVisible(False)
        info_layout.addWidget(self.info_notes)
        self.map_button = QPushButton("Show on Map", info)
        self.map_button.setObjectName("mediaMapButton")
        icons.apply_to(self.map_button, icons.MEDIA_MAP)
        self.map_button.setToolTip("The place the file records it was made, "
                                   "on Triage ▸ Map")
        self.map_button.clicked.connect(self.show_on_map)
        self.map_button.setVisible(False)
        info_layout.addWidget(self.map_button, 0, Qt.AlignLeft)
        side.addTab(_scrolled(info, side), "Info")

        # Markers: their tools in a row above the list (icons, each named
        # in its tooltip), the list -- or what to do while it is empty.
        markers = QWidget(side)
        markers.setObjectName("mediaSidePage")
        markers_layout = QVBoxLayout(markers)
        markers_layout.setContentsMargins(0, 0, 0, 0)
        markers_layout.setSpacing(0)
        tools = QToolBar(markers)
        prepare_toolbar(tools)
        tools.setObjectName("mediaMarkerTools")
        tools.setContextMenuPolicy(Qt.PreventContextMenu)

        def tool(icon, text, tip, slot):
            act = icons.action(icon, text, self)
            act.setToolTip(tip)
            act.triggered.connect(slot)
            tools.addAction(act)
            return act

        tool(icons.MEDIA_MARKER, "Mark Moment",
             "Mark the moment on screen (K)", lambda: self.add_marker())
        self.bookmark_moment_action = tool(
            icons.BOOKMARK, "Bookmark",
            "Bookmark the file at the selected marker (or the moment on "
            "screen), labelled with its time and frame",
            self.bookmark_moment)
        self.remove_marker_action = tool(
            icons.DELETE, "Remove Marker", "Remove the selected marker",
            self.remove_marker)
        self.video_tools_separator = tools.addSeparator()
        self.export_frames_action = tool(
            icons.MEDIA_EXPORT_FRAMES, "Export Frames…",
            "Export frames between the first and last marker (or any "
            "times), every so often, as PNGs with a manifest of hashes",
            self.export_frames)
        self.sheet_side_action = tool(
            icons.CONTACT_SHEET, "Contact Sheet…",
            "One frame per marker (or frames spread evenly) on one "
            "picture, each with its time and frame number",
            self.make_contact_sheet)
        markers_layout.addWidget(tools)
        self.marker_stack = QStackedWidget(markers)
        self.markers_empty = QLabel(
            "No markers yet.\n\nPress K, or the marker button, to mark the "
            "moment on screen. Bookmark keeps a moment in the case; "
            "markers last while the file is open.", markers)
        self.markers_empty.setObjectName("mediaEmptyHint")
        self.markers_empty.setWordWrap(True)
        self.markers_empty.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        self.marker_list = QListWidget(markers)
        self.marker_list.setObjectName("mediaMarkerList")
        self.marker_list.itemActivated.connect(self._marker_activated)
        self.marker_list.itemClicked.connect(self._marker_activated)
        self.marker_list.currentRowChanged.connect(
            lambda _row: self._marker_tools())
        self.marker_stack.addWidget(self.markers_empty)
        self.marker_stack.addWidget(self.marker_list)
        markers_layout.addWidget(self.marker_stack, 1)
        self.markers_note = QLabel(
            "Click a marker to go to it. Markers last while the file is "
            "open; Bookmark keeps a moment in the case.", markers)
        self.markers_note.setObjectName("adjustNote")
        self.markers_note.setWordWrap(True)
        self.markers_note.setContentsMargins(10, 6, 10, 8)
        markers_layout.addWidget(self.markers_note)
        self.markers_page = _scrolled(markers, side)
        side.addTab(self.markers_page, "Markers")

        # Adjust: the shared controls, Save under them, then what it is.
        adjust = QWidget(side)
        adjust.setObjectName("mediaSidePage")
        adjust_layout = QVBoxLayout(adjust)
        adjust_layout.setContentsMargins(0, 0, 0, 0)
        self.adjust_panel = AdjustPanel(adjust)
        self.adjust_panel.changed.connect(self._adjust_changed)
        adjust_layout.addWidget(self.adjust_panel, 1)
        self.save_adjusted_button = QPushButton("Save Adjusted Frame…",
                                                adjust)
        icons.apply_to(self.save_adjusted_button, icons.SNAPSHOT)
        self.save_adjusted_button.setObjectName("mediaSaveAdjusted")
        self.save_adjusted_button.clicked.connect(self.save_adjusted_frame)
        self.save_adjusted_button.setEnabled(False)
        adjust_note = QLabel("Applies to a paused frame; playback is shown "
                             "as decoded.", adjust)
        adjust_note.setObjectName("adjustNote")
        adjust_note.setWordWrap(True)
        # Above the panel's closing stretch, beside Reset -- not at the
        # foot of a tall panel, far from the controls it saves.
        panel_layout = self.adjust_panel.layout()
        at = panel_layout.count() - 1
        panel_layout.insertWidget(at, self.save_adjusted_button, 0,
                                  Qt.AlignLeft)
        panel_layout.insertWidget(at + 1, adjust_note)
        self.adjust_page = _scrolled(adjust, side)
        side.addTab(self.adjust_page, "Adjust")
        return side

    def _marker_tools(self):
        """Remove needs a marker chosen; the others work without one."""
        chosen = 0 <= self.marker_list.currentRow() < len(self.markers)
        self.remove_marker_action.setEnabled(chosen)

    def create_controls(self):
        """The position across the whole width (times either side, markers
        on it), and under it one toolbar built like the other viewers':
        transport and stepping, what is loaded, then speed, loop, the
        examiner's tools, the side panel and volume. The slider used to
        share the toolbar and was squeezed to a stub in a narrow dock,
        pushing the last controls into the overflow menu."""
        panel = QWidget(self)
        panel.setObjectName("mediaControls")
        column = QVBoxLayout(panel)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        self.controls_panel = panel

        # What is loaded (or just done), and the badge when the frame on
        # screen is an adjusted view: a slim line of their own -- in the
        # toolbar they were squeezed to a word in a narrow dock.
        line = QHBoxLayout()
        line.setContentsMargins(10, 4, 10, 0)
        line.setSpacing(8)
        self.view_badge = QLabel(panel)
        self.view_badge.setObjectName("pictureViewBadge")
        self.view_badge.setProperty('tone', 'warn')
        self.view_badge.setVisible(False)
        line.addWidget(self.status_label, 1)
        line.addWidget(self.view_badge)
        column.addLayout(line)

        seek = QHBoxLayout()
        seek.setContentsMargins(10, 2, 10, 0)
        seek.setSpacing(8)
        self.current_time_label = QLabel("00:00.0", panel)
        self.current_time_label.setObjectName("mediaTime")
        self.position_slider = SeekSlider(Qt.Horizontal, panel)
        self.position_slider.setObjectName("mediaPosition")
        self.position_slider.setRange(0, 0)
        self.position_slider.setToolTip("Position: click or drag to move; "
                                        "markers show above the track")
        self.position_slider.setSizePolicy(QSizePolicy.Expanding,
                                           QSizePolicy.Fixed)
        self.position_slider.setMinimumWidth(80)
        self.total_time_label = QLabel("00:00.0", panel)
        self.total_time_label.setObjectName("mediaTotalTime")
        seek.addWidget(self.current_time_label)
        seek.addWidget(self.position_slider, 1)
        seek.addWidget(self.total_time_label)
        column.addLayout(seek)

        bar = QToolBar(panel)
        prepare_toolbar(bar)
        bar.setObjectName("mediaToolbar")
        bar.setContextMenuPolicy(Qt.PreventContextMenu)
        self.control_widget = bar
        column.addWidget(bar)

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
        self.go_to_action = action(icons.MEDIA_GO_TO, "Go to Time or Frame…",
                                   self.go_to, "Ctrl+G")
        bar.addSeparator()

        bar.addWidget(stretch())

        # Speed: a button opening a menu. A combo box in the toolbar was
        # held to the bar's control height below its own and drew cut off.
        self.speed_button = QToolButton(self)
        self.speed_button.setObjectName("mediaSpeed")
        self.speed_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.speed_button.setPopupMode(QToolButton.InstantPopup)
        self.speed_button.setProperty('dropdown', True)
        self.speed_button.setToolTip("Playback speed")
        menu = QMenu(self.speed_button)
        group = QActionGroup(self.speed_button)
        group.setExclusive(True)
        self.speed_actions = {}
        for speed in SPEEDS:
            act = menu.addAction(f"{speed:g}×")
            act.setCheckable(True)
            act.triggered.connect(
                lambda _checked=False, s=speed: self.set_speed(s))
            group.addAction(act)
            self.speed_actions[speed] = act
        self.speed_button.setMenu(menu)
        bar.addWidget(self.speed_button)
        self.loop_action = action(icons.LOOP, "Loop", self._set_loop)
        self.loop_action.setCheckable(True)
        bar.addSeparator()
        self.marker_action = action(icons.MEDIA_MARKER, "Mark Moment",
                                    self.add_marker, "K")
        self.snapshot_action = action(icons.SNAPSHOT, "Save Frame...",
                                      self.save_frame)
        self.snapshot_action.setToolTip(
            "Save the frame on screen as a PNG, named after the file and the "
            "moment in it")
        self.sheet_action = action(icons.CONTACT_SHEET, "Contact Sheet…",
                                   self.make_contact_sheet)
        self.sheet_action.setToolTip(
            "Frames spread over the video (or one per marker) on one "
            "picture, each with its time and frame number")
        self.info_action = action(icons.MEDIA_INFO, "Info, Markers, Adjust",
                                  self._show_side)
        self.info_action.setCheckable(True)
        self.info_action.setToolTip(
            "The file's own metadata (when and with what it was recorded, "
            "where), the moments marked, and Adjust for a paused frame")
        bar.addSeparator()
        self.volume_action = action(icons.VOLUME, "Mute", self.toggle_mute,
                                    "M")
        self.volume_slider = QSlider(Qt.Horizontal, self)
        self.volume_slider.setObjectName("mediaVolume")
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(self._current_volume)
        self.volume_slider.setFixedWidth(80)
        self.volume_slider.setToolTip("Volume")
        self.volume_slider_action = bar.addWidget(self.volume_slider)
        bar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        self.set_speed(1.0)

    def set_speed(self, speed):
        """Play at `speed` (one of SPEEDS), shown on the speed button."""
        self.media_player.setPlaybackRate(speed)
        self.speed_button.setText(f"{speed:g}×")
        if speed in self.speed_actions:
            self.speed_actions[speed].setChecked(True)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.volume_slider_action.setVisible(
            self.width() >= VOLUME_SLIDER_FROM)

    def setup_connections(self):
        self.media_player.errorOccurred.connect(self.handle_error)
        self.media_player.positionChanged.connect(self.update_position)
        self.media_player.durationChanged.connect(self.update_duration)
        # Queued: the player emits these from inside stop(), setSource()
        # and pause(), with the FFmpeg backend's lock held, and a slot
        # that touches the widgets there could wait for ever (CI hung in
        # _set_enabled under stop()). They run on the next turn instead.
        self.media_player.playbackStateChanged.connect(
            self.update_play_state, Qt.QueuedConnection)
        self.media_player.mediaStatusChanged.connect(
            self.handle_media_status_change, Qt.QueuedConnection)
        self.position_slider.sliderMoved.connect(self.set_position)
        self.volume_slider.valueChanged.connect(self.set_volume)

    # --- the loaded file ----------------------------------------------------

    def set_audio_only_mode(self, is_audio_only=True):
        """Audio: a panel instead of the picture, and no picture controls."""
        self.video_widget.setVisible(not is_audio_only)
        waveform = is_audio_only and not self._failed
        self.waveform.setVisible(waveform)
        self.audio_label.setVisible(is_audio_only and not waveform)
        for act in (self.frame_back_action, self.frame_next_action,
                    self.snapshot_action, self.sheet_action):
            act.setEnabled(not is_audio_only and not self._failed)
        for act in (self.export_frames_action, self.sheet_side_action,
                    self.video_tools_separator):
            act.setVisible(not is_audio_only)
        self.side.setTabVisible(self.side.indexOf(self.adjust_page),
                                not is_audio_only)
        if waveform and self._content is not None and \
                not self.waveform.decoded():
            if len(self._content) <= WAVEFORM_MAX_BYTES:
                self.waveform.load(self._content)
            else:
                self.waveform.set_unavailable(
                    "No waveform: the file is too large to decode a second "
                    "time in memory.")
        elif waveform and self._content is None:
            self.waveform.set_unavailable(
                "No waveform for audio streamed from the image (export the "
                "file to see one).")

    def prepare(self, content=None, metadata=None):
        """A new file: its bytes when in memory (for the waveform and the
        hash on a contact sheet), and the container's own metadata."""
        self._content = bytes(content) if content is not None else None
        self._content_sha256 = None
        self.metadata = metadata
        self.markers = []
        self._refresh_markers()
        self._drop_adjusted()
        self.video_widget.clear()
        self.waveform.clear()
        self._show_info()

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
                self._has_video = False
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
                self.update_position(self.media_player.position())
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
                    self.snapshot_action, self.go_to_action,
                    self.marker_action, self.sheet_action):
            act.setEnabled(enabled)
        self.position_slider.setEnabled(enabled)
        self.speed_button.setEnabled(enabled)

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
        return self.frame_rate_and_source()[0]

    def frame_rate_and_source(self):
        """(fps, where it came from): the container's own record (stts,
        avih, DefaultDuration), else what Qt's decoder reports, else
        DEFAULT_FPS -- said to be assumed."""
        if self.metadata:
            from trace_app.core.media_metadata import frame_rate
            rate = frame_rate(self.metadata)
            if rate and 1 <= rate <= 1000:
                return rate, 'container'
        try:
            rate = float(self.media_player.metaData().value(
                QMediaMetaData.VideoFrameRate) or 0)
        except (TypeError, ValueError):
            rate = 0
        if 1 <= rate <= 240:
            return rate, 'decoder'
        return DEFAULT_FPS, 'assumed'

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
            rate, source = self.frame_rate_and_source()
            parts.append(f"{round(rate, 3):g} fps"
                         + (" (assumed: the file does not say)"
                            if source == 'assumed' else ''))
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
            self.waveform.set_caption(self.audio_label.text())

    def _show_failure(self, reason):
        self._failed = reason
        self._set_enabled(False)
        self.update_duration(0)
        self.update_position(0)
        self.video_widget.setVisible(False)
        self.waveform.setVisible(False)
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
        if getattr(self, '_shutting_down', False):
            # safe_stop's stop() delivers this signal synchronously, with
            # the FFmpeg backend mid-stop: redrawing the controls from
            # inside it deadlocked (macOS CI, setIcon never returned), and
            # a player being destroyed has no controls worth updating.
            return
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
        text = self.format_time(position)
        if self._has_video:
            text += f" · f {frame_number(position, self._frame_rate()):,}"
        self.current_time_label.setText(text)
        self.waveform.set_position(position)

    def update_duration(self, duration):
        self.waveform.set_duration(duration)
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

    def moment_text(self, position=None):
        """'01:23.4 (frame 2,071)' -- the frame number only for video."""
        position = self.media_player.position() if position is None \
            else position
        text = self.format_time(position)
        if self._has_video:
            text += f" (frame {frame_number(position, self._frame_rate()):,})"
        return text

    def _base_name(self):
        return os.path.basename(self.source_name or '') or 'video'

    def _ask_save(self, title, name, kind="PNG image (*.png)"):
        from trace_app.core import settings as case_settings
        from trace_app.core.evidence_export import safe_component
        folder = case_settings.export_dir() or os.path.expanduser('~')
        path, _ = QFileDialog.getSaveFileName(
            self, title, os.path.join(folder, safe_component(name, 'frame.png')),
            kind)
        return path

    def _save_png(self, path, image, what, source):
        """`image` (QImage) to `path` as PNG through the audited writer.
        Returns the digests, or None (the reason is on the status line)."""
        from trace_app.core import evidence_export
        from trace_app.ui.viewers.media.picture import png_of
        try:
            return evidence_export.save_bytes(path, png_of(image), what,
                                              source)
        except Exception as exc:
            self.status_label.setText(f"Could not save {path}: {exc}")
            return None

    def save_frame(self, path=None):
        """Save the decoded frame on screen as a PNG (audited, with its
        time and frame number). Returns the path, or ''."""
        image = self.current_frame_image()
        if image.isNull():
            self.status_label.setText("No frame to save yet: play or step "
                                      "to one.")
            return ''
        if path is None:
            path = self._ask_save("Save frame", self.frame_file_name())
            if not path:
                return ''
        digests = self._save_png(
            path, image, 'video frame saved',
            f"{self._base_name()} @ {self.moment_text()}, as decoded")
        if not digests:
            return ''
        self.status_label.setText(f"Frame saved: {path}")
        logger.info("Frame at %d ms of %s saved to %s",
                    self.media_player.position(), self.source_name, path)
        return path

    # --- the side panel: Info ---------------------------------------------

    def _show_side(self, on):
        self.info_action.setChecked(on)
        self.side.setVisible(on)
        if on and not any(self.splitter.sizes()[1:]):
            total = max(1, self.splitter.width())
            width = int(min(SIDE_WIDTH[1], max(SIDE_WIDTH[0],
                                               total * SIDE_SHARE)))
            self.splitter.setSizes([max(1, total - width), width])

    def _show_info(self):
        from trace_app.core import media_metadata
        meta = self.metadata
        self.info_title.setText(self._base_name() if self.source_name
                                else '')
        self._info_lines = []
        if not meta:
            self.info_summary.setText(
                "The container records nothing TRACE reads for this file "
                "(MP4/MOV/3GP/M4A, AVI, WAV, MKV/WebM are read)."
                if meta is not None else '')
            self.info_view.set_rows([])
            self.info_view.setVisible(False)
            self.info_notes.setVisible(False)
            self.map_button.setVisible(False)
            return
        facts = media_metadata.facts(meta)
        rows = []
        summary = []
        for label, value in facts:
            self._info_lines.append(f"{label}: {value}")
            if label == 'Track':
                continue                # a section per track, below
            if label == 'Container':
                summary.append(meta.get('container') or str(value))
            # The panel is narrow: the table's tooltip keeps the whole
            # value, the File Metadata tab says "(as recorded)" in full.
            shown = str(value).replace(' (as recorded)', '')
            # A place recorded is what an examiner looks for first.
            rows.append((label, shown, 'warning') if label == 'Location'
                        else (label, shown))
        for track in meta.get('tracks') or []:
            rows.extend(self._track_rows(track))
            if track.get('kind') == 'video' and track.get('width'):
                summary.append(f"{track['width']} × {track['height']}")
        if meta.get('duration'):
            summary.append(media_metadata.duration_text(meta['duration']))
        notes = list(meta.get('notes') or [])
        self._info_lines.extend(f"Note: {note}" for note in notes)
        self.info_summary.setText(" · ".join(summary) or
                                  "From the container's own records")
        self.info_view.set_rows(rows)
        self.info_view.setVisible(bool(rows))
        self.info_notes.setText('\n'.join(notes))
        self.info_notes.setVisible(bool(notes))
        self.map_button.setVisible(meta.get('latitude') is not None and
                                   meta.get('longitude') is not None)

    @staticmethod
    def _track_rows(track):
        """A heading and a row per fact of one track: in a narrow panel
        one line of everything ('video avc1, 512 × 288, 29.969 fps, ...')
        was cut off after the codec."""
        from trace_app.core.media_metadata import duration_text
        kind = (track.get('kind') or 'track').capitalize()
        heading = f"{kind} track" + (f" · {track['codec']}"
                                     if track.get('codec') else '')
        rows = [(None, heading)]
        if track.get('width') and track.get('height'):
            rows.append(("Size", f"{track['width']} × {track['height']}"))
        if track.get('frame_rate'):
            rows.append(("Frame rate", f"{track['frame_rate']:g} fps"))
        if track.get('samples') and track.get('kind') == 'video':
            rows.append(("Frames", f"{track['samples']:,}"))
        if track.get('rotation'):
            rows.append(("Rotation", f"{track['rotation']}°"))
        if track.get('sample_rate'):
            rows.append(("Sample rate", f"{track['sample_rate']:,} Hz"))
        if track.get('channels'):
            rows.append(("Channels", f"{track['channels']}"))
        if track.get('language'):
            rows.append(("Language", track['language']))
        if track.get('duration'):
            rows.append(("Duration", duration_text(track['duration'])))
        return rows

    def info_text(self):
        """The Info tab's facts as lines of text ('Label: value')."""
        return '\n'.join([self.info_summary.text()] +
                         getattr(self, '_info_lines', []))

    def show_on_map(self):
        meta = self.metadata or {}
        if self.show_place_hook is None or meta.get('latitude') is None:
            return
        when = meta.get('creation_date') or meta.get('created') or ''
        self.show_place_hook(meta['latitude'], meta['longitude'],
                             self._base_name(),
                             f"Recorded here{', ' + when if when else ''} "
                             "(the file's own metadata)")

    # --- markers and moments ----------------------------------------------

    def add_marker(self, note=''):
        """Mark the moment on screen (K)."""
        if self.media_player.mediaStatus() in (QMediaPlayer.NoMedia,
                                               QMediaPlayer.LoadingMedia):
            return
        position = self.media_player.position()
        if any(abs(position - ms) < 1 for ms, _n in self.markers):
            return
        self.markers.append((position, note or ''))
        self.markers.sort()
        self._refresh_markers()
        self.status_label.setText(f"Marked {self.moment_text(position)}")

    def remove_marker(self):
        row = self.marker_list.currentRow()
        if 0 <= row < len(self.markers):
            del self.markers[row]
            self._refresh_markers()

    def _refresh_markers(self):
        self.marker_list.clear()
        for number, (position, note) in enumerate(self.markers, 1):
            item = QListWidgetItem(
                f"{number}.  {self.moment_text(position)}"
                + (f" — {note}" if note else ''), self.marker_list)
            item.setToolTip("Click to go to this moment")
        self.marker_stack.setCurrentWidget(
            self.marker_list if self.markers else self.markers_empty)
        self._marker_tools()
        times = [ms for ms, _n in self.markers]
        self.position_slider.set_markers(times)
        self.waveform.set_markers(times)

    def _marker_activated(self, item):
        row = self.marker_list.row(item)
        if 0 <= row < len(self.markers):
            if self._is_playing:
                self.media_player.pause()
            self.media_player.setPosition(self.markers[row][0])

    def bookmark_moment(self):
        """A case bookmark of the file, labelled with the moment: the
        selected marker's, else the one on screen."""
        if self.bookmark_hook is None:
            self.status_label.setText("Bookmarks need a case.")
            return
        row = self.marker_list.currentRow()
        position, note = self.markers[row] if 0 <= row < len(self.markers) \
            else (self.media_player.position(), '')
        label = f"{self._base_name()} @ {self.moment_text(position)}"
        if note:
            label += f" — {note}"
        self.bookmark_hook(label)

    def go_to(self):
        """Go to a time or a frame (Ctrl+G), paused there."""
        rate, source = self.frame_rate_and_source()
        text, ok = QInputDialog.getText(
            self, "Go to",
            "Time (83.4, 01:23.4, 1:02:03) or frame (f2071):"
            + ("" if source != 'assumed' else
               f"\nFrames are counted at an assumed {rate:g} fps."),
            text=self.format_time(self.media_player.position()))
        if not ok:
            return
        position = parse_position(text, rate)
        if position is None:
            self.status_label.setText(f"Not a time or frame: {text}")
            return
        duration = self.media_player.duration()
        if duration > 0:
            position = min(position, duration - 1)
        if self._is_playing:
            self.media_player.pause()
        self.media_player.setPosition(position)

    # --- Adjust (a paused frame) ------------------------------------------

    @Slot()
    def _new_frame(self):
        """A frame arrived: any adjusted view was of the last one."""
        self._adjusted_steps = ''
        self.save_adjusted_button.setEnabled(False)
        if self._adjusting() and not self._is_playing:
            QTimer.singleShot(0, self._render_adjusted)
        else:
            self._show_badge()

    def _adjusting(self):
        from trace_app.core.image_forensics import is_neutral
        return not is_neutral(self.adjust_panel.settings())

    def _adjust_changed(self, _settings):
        if not self._adjusting():
            self._drop_adjusted()
            return
        if self._is_playing:
            self._show_badge()
            return
        self._render_adjusted()

    def _render_adjusted(self):
        frame = self.video_widget.frame()
        if frame.isNull() or not self._adjusting():
            return
        self._adjust_serial += 1
        job = _AdjustJob(self._adjust_serial, frame,
                         self.adjust_panel.settings())
        job.done.connect(self._adjusted)
        self._jobs[('adjust', self._adjust_serial)] = job
        job.start()

    @Slot(object)
    def _adjusted(self, result):
        if result.get('serial') != self._adjust_serial or self._is_playing:
            return
        if result.get('error'):
            self.status_label.setText(f"Not adjusted: {result['error']}")
            return
        self.video_widget.set_view(result['image'])
        self._adjusted_view = result['image']
        self._adjusted_steps = result['steps']
        self.save_adjusted_button.setEnabled(True)
        self._show_badge()

    def _drop_adjusted(self):
        self._adjust_serial += 1
        self._adjusted_steps = ''
        self._adjusted_view = None
        self.video_widget.set_view(None)
        if hasattr(self, 'save_adjusted_button'):
            self.save_adjusted_button.setEnabled(False)
        self._show_badge()

    def _show_badge(self):
        if self._adjusted_steps:
            self.view_badge.setText("Adjusted frame, not as decoded: "
                                    + self._adjusted_steps)
        elif self._adjusting() and self._has_video:
            self.view_badge.setText("Adjust shows on a paused frame")
        else:
            self.view_badge.setVisible(False)
            return
        self.view_badge.setToolTip(self.view_badge.text())
        self.view_badge.setVisible(True)

    def save_adjusted_frame(self):
        image = getattr(self, '_adjusted_view', None)
        if image is None or not self._adjusted_steps:
            return
        base = os.path.splitext(self.frame_file_name())[0]
        path = self._ask_save("Save adjusted frame", f"{base} (adjusted).png")
        if not path:
            return
        digests = self._save_png(
            path, image, 'video frame saved',
            f"{self._base_name()} @ {self.moment_text()} -- adjusted, not "
            f"as decoded: {self._adjusted_steps}")
        if digests:
            self.status_label.setText(f"Adjusted frame saved: {path}")

    # --- frames at chosen times: contact sheet, export ----------------------

    def _grab(self, times, done):
        """Read the frames at `times` through the player, then call
        done(results); the position on screen is put back afterwards."""
        if self._grabber is not None:
            self.status_label.setText("Already reading frames…")
            return
        if self._is_playing:
            self.media_player.pause()
        self._drop_adjusted()
        back = self.media_player.position()
        grabber = _FrameGrabber(self, times, self)
        self._grabber = grabber

        def progress(index, total):
            self.status_label.setText(f"Reading frame {index + 1} of "
                                      f"{total}… (Esc stops)")

        def finished(results):
            self._grabber = None
            grabber.deleteLater()
            QTimer.singleShot(0, lambda: self.media_player.setPosition(back))
            done(results)

        grabber.progress.connect(progress)
        grabber.finished.connect(finished)
        grabber.start()

    def _file_sha256(self):
        """The SHA-256 of the file's bytes when they are in memory."""
        if self._content is None:
            return None
        if self._content_sha256 is None:
            import hashlib
            self._content_sha256 = hashlib.sha256(self._content).hexdigest()
        return self._content_sha256

    def make_contact_sheet(self):
        """Frames spread over the video -- or one per marker -- on one PNG,
        each captioned with the decoder's time and frame number."""
        from trace_app.core import contact_sheet
        duration = self.media_player.duration()
        if not self._has_video or duration <= 0:
            self.status_label.setText("A contact sheet needs a video.")
            return
        if self.markers:
            times = [ms for ms, _n in self.markers][:contact_sheet.MAX_FRAMES]
            how = f"one frame per marker ({len(times)})"
        else:
            count, ok = QInputDialog.getInt(
                self, "Contact sheet", "Frames, spread evenly:",
                SHEET_FRAMES, 4, contact_sheet.MAX_FRAMES)
            if not ok:
                return
            times = contact_sheet.evenly(duration, count)
            how = f"{count} frames spread evenly"
        self._grab(times, lambda results: self._sheet_ready(results, how))

    def _sheet_ready(self, results, how):
        from trace_app.core import contact_sheet
        from trace_app.ui.viewers.media.picture import png_of
        rate = self._frame_rate()
        frames = []
        for asked, decoded, image in results:
            when = decoded if decoded is not None else asked
            caption = self.format_time(when) + \
                f" · frame {frame_number(when, rate):,}"
            if decoded is None and image is not None:
                caption += " (time not reported)"
            frames.append((png_of(image) if image is not None else None,
                           caption))
        missing = sum(1 for _a, _d, image in results if image is None)
        sha = self._file_sha256()
        footer = [f"File SHA-256 {sha}" if sha else
                  "File SHA-256 not computed here: the file is streamed "
                  "from the image (its export and analysis hash it).",
                  f"Frames: {how}; times as the decoder reported them; "
                  f"frame numbers at {rate:g} fps "
                  f"({self.frame_rate_and_source()[1]})."
                  + (f" {missing} not decoded." if missing else '')]
        meta = self.metadata or {}
        title = self._base_name()
        if meta.get('creation_date') or meta.get('created'):
            title += f" — recorded {meta.get('creation_date') or meta['created']}"
        png = contact_sheet.compose(frames, title, footer)
        base = os.path.splitext(self._base_name())[0]
        path = self._ask_save("Save contact sheet",
                              f"{base} (contact sheet).png")
        if not path:
            self.status_label.setText("Contact sheet not saved.")
            return
        from trace_app.core import evidence_export
        try:
            digests = evidence_export.save_bytes(
                path, png, 'contact sheet saved',
                f"{self._base_name()}: {how}"
                + (f", file SHA-256 {sha}" if sha else ''))
        except Exception as exc:
            self.status_label.setText(f"Could not save {path}: {exc}")
            return
        self.status_label.setText(f"Contact sheet saved: {path}")
        self.last_sheet = {'path': path, 'sha256': digests['sha256'],
                           'file': self._base_name(), 'how': how,
                           'file_sha256': sha, 'frames': len(results),
                           'missing': missing}
        if self.sheet_hook is not None and message.question(
                self, "Contact sheet saved",
                f"Saved as {path}.\n\nAdd it to the case report?"):
            self.sheet_hook(self.last_sheet)

    #: (sheet dict) -> add a saved contact sheet to the report; set by the
    #: window when a case is open.
    sheet_hook = None

    def export_frames(self):
        """Frames between two times, every so often, as PNGs and a
        manifest (time asked, time decoded, frame, SHA-256)."""
        duration = self.media_player.duration()
        if not self._has_video or duration <= 0:
            self.status_label.setText("Exporting frames needs a video.")
            return
        rate = self._frame_rate()
        start, end = 0, duration
        if len(self.markers) >= 2:
            start, end = self.markers[0][0], self.markers[-1][0]
        dialog = _ExportFramesDialog(self, self.format_time(start),
                                     self.format_time(end), rate)
        if dialog.exec() != QDialog.Accepted:
            return
        first = parse_position(dialog.start.text(), rate)
        last = parse_position(dialog.end.text(), rate)
        if first is None or last is None or last < first:
            self.status_label.setText("Export: the times were not read.")
            return
        step = max(1, int(round(dialog.every.value() * 1000 / rate))) \
            if dialog.unit.currentData() == 'frames' else \
            max(1, int(round(dialog.every.value() * 1000)))
        times = list(range(first, min(last, duration - 1) + 1, step))
        if len(times) > MAX_EXPORT_FRAMES:
            self.status_label.setText(
                f"{len(times):,} frames: at most {MAX_EXPORT_FRAMES:,} a "
                "time -- choose a wider step or a shorter stretch.")
            return
        from trace_app.core import settings as case_settings
        folder = QFileDialog.getExistingDirectory(
            self, "Export frames to", case_settings.export_dir() or
            os.path.expanduser('~'))
        if not folder:
            return
        self._grab(times, lambda results: self._frames_ready(results,
                                                             folder))

    def _frames_ready(self, results, folder):
        import csv
        import io
        from trace_app.core import evidence_export
        from trace_app.ui.viewers.media.picture import png_of
        rate = self._frame_rate()
        base = os.path.splitext(self._base_name())[0]
        target = evidence_export.unique_path(
            folder, evidence_export.safe_component(f"{base} frames", 'frames'))
        os.makedirs(target)
        rows = []
        for asked, decoded, image in results:
            when = decoded if decoded is not None else asked
            frame = frame_number(when, rate)
            if image is None:
                rows.append([self.format_time(asked), '', '', '', '',
                             'no frame decoded'])
                continue
            name = f"{base} @ {self.format_time(when).replace(':', 'm')}s " \
                   f"f{frame}.png"
            name = evidence_export.safe_component(name, f"f{frame}.png")
            path = evidence_export.unique_path(target, name)
            data = png_of(image)
            try:
                digests = evidence_export.write_verified(
                    path, lambda offset, length, data=data:
                    data[offset:offset + length], len(data))
            except Exception as exc:
                rows.append([self.format_time(asked), '', frame, '', '',
                             str(exc)])
                continue
            rows.append([self.format_time(asked),
                         self.format_time(decoded) if decoded is not None
                         else '', frame, os.path.basename(path),
                         digests['sha256'], ''])
        text = io.StringIO()
        writer = csv.writer(text)
        writer.writerow(['time asked', 'time decoded', 'frame', 'file',
                         'sha256', 'problem'])
        writer.writerows(rows)
        sha = self._file_sha256()
        written = sum(1 for row in rows if row[3])
        digests = evidence_export.save_bytes(
            os.path.join(target, 'manifest.csv'),
            text.getvalue().encode('utf-8'), 'video frames exported',
            f"{self._base_name()}: {written} of {len(rows)} frame(s) as PNG"
            f" at {rate:g} fps" + (f", file SHA-256 {sha}" if sha else ''))
        self.status_label.setText(
            f"{written} frame(s) exported to {target} (manifest SHA-256 "
            f"{digests['sha256'][:16]}…)")

    # --- keys ---------------------------------------------------------------

    def keyPressEvent(self, event):
        if self._failed or self.media_player.mediaStatus() in (
                QMediaPlayer.NoMedia, QMediaPlayer.LoadingMedia):
            return super().keyPressEvent(event)
        key = event.key()
        if key == Qt.Key_Escape and self._grabber is not None:
            self._grabber.cancel()
        elif key == Qt.Key_G and event.modifiers() & Qt.ControlModifier:
            self.go_to()
        elif key == Qt.Key_K:
            self.add_marker()
        elif key == Qt.Key_Space:
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
        """Stop a player that is being destroyed (not one that will play
        again: its video output is detached)."""
        try:
            if self._grabber is not None:
                self._grabber.cancel()
            self.waveform.clear()
            self._jobs.clear()
            if hasattr(self, 'media_player') and self.media_player:
                self._shutting_down = True
                # Paused, and the frames already on their way delivered,
                # before stop() joins the backend's threads: a frame step's
                # frame still in flight to the window when stop() waited
                # for its thread left both waiting (CI, once in a few runs,
                # in stop() itself). Paused, the backend decodes no more.
                if self.media_player.playbackState() == \
                        QMediaPlayer.PlayingState:
                    self.media_player.pause()
                _drain(0.05)
                watchdog = _StopWatchdog()
                try:
                    self.media_player.stop()
                finally:
                    watchdog.cancel()
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

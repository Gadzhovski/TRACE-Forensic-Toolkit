"""Thumbnails of video, for the Listing's icon views and the carved-files
gallery.

Pictures are decoded from their bytes; a video needs a decoder, and the
file can be gigabytes. One hidden, silent QMediaPlayer with its own video
sink works through a queue, one video at a time: the source is opened (a
stream over the file on the image, read on demand, or a carve's bytes), the
player is paused a little way in -- many videos open on black -- which the
FFmpeg backend draws, and that frame is the thumbnail. A video that will not
decode, or takes longer than TIMEOUT_MS, gets none.

The player is never controlled from inside its own signals: the FFmpeg
backend holds its lock there, and pause() or setSource() then waits for ever
(the media player found this first). Every step is queued with
QTimer.singleShot(0, ...).
"""

import logging
import os

from PySide6.QtCore import QObject, QPointF, QRectF, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QImage, QPainter, QPainterPath, QPixmap
from PySide6.QtMultimedia import QMediaPlayer, QVideoSink

logger = logging.getLogger('TRACE.VideoThumbnails')

#: How long one video may take before it is given up on.
TIMEOUT_MS = 5000
#: The frame used: this far in, at most (milliseconds) ...
FRAME_AT_MS = 1000
#: ... and never past this share of the video.
FRAME_AT_SHARE = 0.1


def with_play_badge(pixmap):
    """The thumbnail with a small play mark in its corner, so a video is not
    taken for a picture."""
    if pixmap.isNull():
        return pixmap
    marked = QPixmap(pixmap)
    side = max(14, min(marked.width(), marked.height()) // 4)
    margin = max(3, side // 5)
    painter = QPainter(marked)
    painter.setRenderHint(QPainter.Antialiasing)
    circle = QRectF(margin, marked.height() - side - margin, side, side)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(0, 0, 0, 150))
    painter.drawEllipse(circle)
    triangle = QPainterPath()
    centre = circle.center()
    r = side * 0.22
    triangle.moveTo(QPointF(centre.x() - r * 0.8, centre.y() - r))
    triangle.lineTo(QPointF(centre.x() - r * 0.8, centre.y() + r))
    triangle.lineTo(QPointF(centre.x() + r * 1.1, centre.y()))
    triangle.closeSubpath()
    painter.setBrush(QColor(255, 255, 255, 230))
    painter.drawPath(triangle)
    painter.end()
    return marked


class VideoThumbnailer(QObject):
    """Queue videos; `ready(key, image)` gives each one's frame (a null
    QImage when there is none)."""

    ready = Signal(object, QImage)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._queue = []
        self._keys = set()
        self._active = None
        self._device = None
        self._target_us = 0
        self._loaded = False
        self.player = QMediaPlayer(self)      # no audio output: silent
        self.sink = QVideoSink(self)
        self.player.setVideoSink(self.sink)
        self.player.mediaStatusChanged.connect(self._status)
        self.player.errorOccurred.connect(
            lambda *_a: QTimer.singleShot(0, lambda: self._finish(None)))
        self.sink.videoFrameChanged.connect(self._frame)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(lambda: self._finish(None))

    def request(self, key, opener, name=''):
        """Queue a video. `opener()` returns an open QIODevice over its
        bytes (or None); `name` gives the backend its extension."""
        if key in self._keys:
            return
        self._keys.add(key)
        self._queue.append((key, opener, name))
        if self._active is None:
            QTimer.singleShot(0, self._next)

    def pending(self, key):
        return key in self._keys

    def clear(self):
        """Forget the queue (the listing changed); the running one ends."""
        for key, _opener, _name in self._queue:
            self._keys.discard(key)
        self._queue = []

    # --- one video ------------------------------------------------------------

    def _next(self):
        if self._active is not None or not self._queue:
            return
        key, opener, name = self._queue.pop(0)
        self._active = key
        self._loaded = False
        self._target_us = 0
        try:
            self._device = opener()
        except Exception as exc:
            logger.debug("Video %s not opened: %s", name, exc)
            self._device = None
        if self._device is None:
            QTimer.singleShot(0, lambda: self._finish(None))
            return
        hint = QUrl()
        hint.setScheme('memory')
        hint.setPath('media' + (os.path.splitext(name)[1] or '.tmp'))
        self._timer.start(TIMEOUT_MS)
        self.player.setSourceDevice(self._device, hint)

    def _status(self, status):
        if self._active is None:
            return
        if status == QMediaPlayer.LoadedMedia and not self._loaded:
            self._loaded = True
            QTimer.singleShot(0, self._seek_in)
        elif status == QMediaPlayer.InvalidMedia:
            QTimer.singleShot(0, lambda: self._finish(None))

    def _seek_in(self):
        if self._active is None:
            return
        if not self.player.hasVideo():
            self._finish(None)
            return
        duration = self.player.duration()
        target = int(min(FRAME_AT_MS, duration * FRAME_AT_SHARE)) \
            if duration > 0 else 0
        self._target_us = max(0, target - 50) * 1000
        if target:
            self.player.setPosition(target)
        self.player.pause()

    def _frame(self, frame):
        if self._active is None or not self._loaded or not frame.isValid():
            return
        if frame.startTime() >= 0 and frame.startTime() < self._target_us:
            return          # the frame before the seek landed
        image = frame.toImage()
        if not image.isNull():
            QTimer.singleShot(0, lambda image=image: self._finish(image))

    def _finish(self, image):
        if self._active is None:
            return
        key, self._active = self._active, None
        self._timer.stop()
        self._keys.discard(key)
        device, self._device = self._device, None
        self.player.stop()
        self.player.setSource(QUrl())
        if device is not None:
            # Closed a beat later, as the viewer does: the backend's reader
            # may still be reading it.
            QTimer.singleShot(100, device.close)
            QTimer.singleShot(150, device.deleteLater)
        self.ready.emit(key, image if image is not None else QImage())
        QTimer.singleShot(0, self._next)


def buffer_opener(content):
    """An opener over bytes in memory (a carve)."""
    def open_buffer():
        from PySide6.QtCore import QBuffer, QByteArray, QIODevice
        if not content:
            return None
        buffer = QBuffer()
        buffer.setData(QByteArray(bytes(content)))
        buffer.open(QIODevice.ReadOnly)
        return buffer
    return open_buffer

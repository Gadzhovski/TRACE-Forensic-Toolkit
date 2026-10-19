"""An audio file's waveform, in place of a bare "Audio" label.

Qt Multimedia's QAudioDecoder (FFmpeg, inside the PySide6 wheel -- nothing
to install) decodes to 16-bit mono at `RATE`; each buffer is reduced as it
arrives to one (lowest, highest) pair per `BUCKET_MS`, with `array` and
min/max over slices -- C builtins, a few hundred thousand calls for an
hour. Painting reduces those pairs again to the widget's width.

A click seeks; the position and the markers are drawn over it. The decoder
reads its own copy of the bytes (an audio file loaded in memory); a file
streamed from the image is not decoded twice at once, and the widget says
so instead of guessing at a picture.
"""

import logging
from array import array

from PySide6.QtCore import (QBuffer, QByteArray, QIODevice, QPointF, QRectF,
                            Qt, Signal, Slot)
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtMultimedia import QAudioDecoder, QAudioFormat
from PySide6.QtWidgets import QSizePolicy, QWidget

logger = logging.getLogger('TRACE.Viewer.Waveform')

#: Decoded at this rate, one channel: plenty for a picture of loudness.
RATE = 8000
#: One (lowest, highest) pair per this many milliseconds.
BUCKET_MS = 10
_SAMPLES = RATE * BUCKET_MS // 1000


def reduce_samples(data, carry=None):
    """[(low, high)] per `_SAMPLES` of 16-bit little-endian mono `data`;
    `carry` holds samples left from the last call (and is updated)."""
    samples = array('h')
    samples.frombytes(bytes(data[:len(data) // 2 * 2]))
    if carry:
        samples = carry + samples
        del carry[:]
    whole = len(samples) // _SAMPLES * _SAMPLES
    if carry is not None and whole < len(samples):
        carry.extend(samples[whole:])
    pairs = []
    for start in range(0, whole, _SAMPLES):
        piece = samples[start:start + _SAMPLES]
        pairs.append((min(piece), max(piece)))
    return pairs


class WaveformView(QWidget):
    """The decoded loudness of an audio file over time."""

    #: Clicked: go to this position (ms).
    seek_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mediaWaveform")
        self.setMinimumHeight(36)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCursor(Qt.PointingHandCursor)
        self._lows, self._highs = array('h'), array('h')
        self._carry = array('h')
        self._duration = 0
        self._position = 0
        self._markers = []
        self._state = ''
        self._caption = ''
        self._decoder = None
        self._buffer = None
        self._columns = None

    # --- loading ------------------------------------------------------------

    def clear(self):
        self._stop()
        self._lows, self._highs = array('h'), array('h')
        self._carry = array('h')
        self._columns = None
        self._position = 0
        self._markers = []
        self._state = ''
        self.update()

    def set_unavailable(self, why):
        self.clear()
        self._state = why
        self.update()

    def load(self, data):
        """Decode `data` (the audio file's bytes)."""
        self.clear()
        self._state = "Decoding the waveform…"
        self._buffer = QBuffer()
        self._buffer.setData(QByteArray(bytes(data)))
        self._buffer.open(QIODevice.ReadOnly)
        decoder = QAudioDecoder(self)
        audio = QAudioFormat()
        audio.setSampleFormat(QAudioFormat.Int16)
        audio.setChannelCount(1)
        audio.setSampleRate(RATE)
        decoder.setAudioFormat(audio)
        decoder.bufferReady.connect(self._buffer_ready)
        decoder.finished.connect(self._finished)
        decoder.error.connect(self._failed)
        decoder.setSourceDevice(self._buffer)
        self._decoder = decoder
        decoder.start()
        self.update()

    def _stop(self):
        decoder, self._decoder = self._decoder, None
        if decoder is not None:
            try:
                decoder.bufferReady.disconnect(self._buffer_ready)
                decoder.finished.disconnect(self._finished)
                decoder.error.disconnect(self._failed)
            except (RuntimeError, TypeError):
                pass
            decoder.stop()
            decoder.deleteLater()
        if self._buffer is not None:
            self._buffer.close()
            self._buffer = None

    @Slot()
    def _buffer_ready(self):
        if self._decoder is None:
            return
        buffer = self._decoder.read()
        if not buffer.isValid():
            return
        for low, high in reduce_samples(buffer.constData(), self._carry):
            self._lows.append(low)
            self._highs.append(high)
        self._columns = None
        self.update()

    @Slot()
    def _finished(self):
        self._state = '' if self._lows else "No sound decoded."
        self._stop()
        self.update()

    @Slot(object)
    def _failed(self, _error):
        reason = self._decoder.errorString() if self._decoder else ''
        self._state = f"Waveform not decoded: {reason or 'decoder error'}"
        self._stop()
        self.update()

    # --- what is drawn over it ---------------------------------------------

    def decoded(self):
        """The (lowest, highest) pairs so far, one per BUCKET_MS."""
        return list(zip(self._lows, self._highs))

    def set_duration(self, duration):
        self._duration = max(0, int(duration or 0))
        self.update()

    def set_position(self, position):
        self._position = max(0, int(position or 0))
        self.update()

    def set_markers(self, markers):
        self._markers = list(markers)
        self.update()

    def set_caption(self, text):
        self._caption = text
        self.update()

    def _span(self):
        return max(self._duration, len(self._lows) * BUCKET_MS, 1)

    def _x_of(self, ms):
        return round(ms / self._span() * max(1, self.width() - 1))

    def _reduced(self, width):
        """One (low, high) per column of the widget."""
        if self._columns is not None and self._columns[0] == width:
            return self._columns[1]
        count = len(self._lows)
        span_buckets = self._span() / BUCKET_MS
        columns = []
        for column in range(width):
            first = int(column * span_buckets / width)
            last = min(count, max(first + 1,
                                  int((column + 1) * span_buckets / width)))
            if first >= last:
                columns.append(None)
                continue
            # Slices of arrays and min/max over them: C, not Python.
            columns.append((min(self._lows[first:last]),
                            max(self._highs[first:last])))
        self._columns = (width, columns)
        return columns

    def paintEvent(self, _event):
        painter = QPainter(self)
        palette = self.palette()
        painter.fillRect(self.rect(), palette.base())
        middle = self.height() / 2
        half = max(1.0, middle - 14)
        painter.setPen(QPen(palette.mid().color(), 1))
        painter.drawLine(0, round(middle), self.width(), round(middle))
        here = self._x_of(self._position) if (self._duration or
                                              self._lows) else -1
        # What has played in the accent colour, what is still to come
        # fainter: the waveform reads as progress too.
        played = QColor(palette.highlight().color())
        ahead = QColor(played)
        ahead.setAlpha(120)
        if self._lows:
            for x, pair in enumerate(self._reduced(max(1, self.width()))):
                if pair is None:
                    continue
                low, high = pair
                painter.setPen(QPen(played if x <= here else ahead, 1))
                painter.drawLine(x, round(middle - high / 32768 * half),
                                 x, round(middle - low / 32768 * half))
        painter.setRenderHint(QPainter.Antialiasing)
        marker_colour = QColor(palette.highlight().color()).lighter(130)
        line = QColor(marker_colour)
        line.setAlpha(150)
        for marker in self._markers:
            x = self._x_of(marker) + 0.5
            painter.setPen(QPen(line, 1, Qt.DashLine))
            painter.drawLine(QPointF(x, 8), QPointF(x, self.height()))
            pin = QPainterPath()
            pin.moveTo(x - 5, 0)
            pin.lineTo(x + 5, 0)
            pin.lineTo(x, 7)
            pin.closeSubpath()
            painter.setPen(Qt.NoPen)
            painter.setBrush(marker_colour)
            painter.drawPath(pin)
        if here >= 0:
            painter.setPen(QPen(palette.text().color(), 1))
            painter.drawLine(QPointF(here + 0.5, 0),
                             QPointF(here + 0.5, self.height()))
        caption = self._state or self._caption
        if caption:
            painter.setPen(QPen(palette.placeholderText().color(), 1))
            painter.drawText(QRectF(10, 6, self.width() - 20, 18),
                             Qt.AlignLeft | Qt.AlignVCenter, caption)
        painter.end()

    def resizeEvent(self, event):
        self._columns = None
        super().resizeEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and (self._duration or
                                                self._lows):
            x = min(max(0.0, event.position().x()), self.width() - 1)
            self.seek_requested.emit(
                int(x / max(1, self.width() - 1) * self._span()))
            event.accept()
            return
        super().mousePressEvent(event)

"""TRACE's progress cards: one look for everything that makes the examiner
wait -- the card between the launcher and the window (opening_splash.py)
and `ProgressDialog`, which takes QProgressDialog's place.

Drawn by hand in the palette's colours (no stylesheet), at the screen's own
pixel ratio, on a frameless window with rounded corners and a soft shadow
where the platform can show see-through corners. A card says three things:
what is being done (the title and the evidence or file), the step now, and
how far along it is -- with the time spent, ticking, so a long step never
looks like a hang. A step whose length is not known draws a busy bar; a
known one sweeps a light along its filled part while the event loop runs.
"""

import math
import sys
import time

from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (QColor, QFont, QFontInfo, QFontMetrics,
                           QGuiApplication, QImage, QLinearGradient,
                           QPainter, QPainterPath, QPen, QPixmap)
from PySide6.QtWidgets import QPushButton, QSizePolicy, QWidget

from trace_app.infra.paths import resource_path
from trace_app.ui import icons

SHADOW = 18
RADIUS = 12
BAR_HEIGHT = 6
#: Frames of the busy bar and the sweep (ms).
FRAME_MS = 33
#: The time spent is shown once a step has taken this long (s).
SHOW_ELAPSED_AFTER = 1.0
#: Lines kept for the step's text.
STEP_LINES = 2
#: A stage's row in a card's stage list, and the space above the list (px).
STAGE_ROW = 24
STAGES_GAP = 14
#: The widest the time and share on the title's line get.
RIGHT_TEXT_ROOM = "0:00:00  ·  100%"


def translucent_windows():
    """Whether a frameless window can have see-through corners here. X11
    without a compositor paints the transparent part black, so there the
    card is a plain rectangle."""
    if sys.platform in ('win32', 'darwin'):
        return True
    return QGuiApplication.platformName() in ('wayland', 'offscreen')


def mix(a, b, share):
    """`a` moved `share` of the way towards `b`."""
    return QColor(round(a.red() + (b.red() - a.red()) * share),
                  round(a.green() + (b.green() - a.green()) * share),
                  round(a.blue() + (b.blue() - a.blue()) * share))


def card_colours(palette):
    window = palette.window().color()
    text = palette.windowText().color()
    dark = window.lightness() < 128
    return {
        # A step lighter than the window on the dark theme; the window's
        # own colour on the light one.
        'card': mix(window, text, 0.06 if dark else 0.0),
        'text': text,
        'quiet': mix(text, window, 0.42),
        'border': mix(window, text, 0.22 if dark else 0.16),
        'track': mix(window, text, 0.14 if dark else 0.10),
        'accent': palette.highlight().color(),
        'dark': dark,
    }


def pixel_font(base, scale, weight=None, least=11):
    """`base` at `scale` times its pixel size. The themes size fonts in
    pixels, so a point size can be -1."""
    font = QFont(base)
    font.setPixelSize(max(least, round((QFontInfo(base).pixelSize() or 13)
                                       * scale)))
    if weight is not None:
        font.setWeight(weight)
    return font


def two_lines(metrics, text, width):
    """`text` broken at spaces into at most two lines of `width` pixels,
    the second elided -- a step naming a volume runs long."""
    words, first = text.split(' '), ''
    while words:
        trial = f"{first} {words[0]}" if first else words[0]
        if metrics.horizontalAdvance(trial) > width:
            break
        first = trial
        words.pop(0)
    if not first:                       # one word wider than the line
        return [metrics.elidedText(text, Qt.ElideMiddle, width)]
    if not words:
        return [first]
    return [first, metrics.elidedText(' '.join(words), Qt.ElideRight,
                                      width)]


def elapsed_text(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}:{seconds:02d}"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


class LogoCache:
    """The transparent logo (icons.LOGO -- Icons/logo.png has a white
    background), reduced once per size and pixel ratio in one smooth
    step: drawing the full-size image into a small rectangle aliases."""

    _image = None

    def __init__(self):
        self._kept = {}

    def pixmap(self, size, ratio):
        if LogoCache._image is None:
            LogoCache._image = QImage(resource_path(*icons.LOGO.split('/')))
        if LogoCache._image.isNull():
            return None
        key = (size, ratio)
        if key not in self._kept:
            side = round(size * ratio)
            pixmap = QPixmap.fromImage(LogoCache._image.scaled(
                side, side, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            pixmap.setDevicePixelRatio(ratio)
            self._kept[key] = pixmap
        return self._kept[key]


def draw_card(painter, widget, card, shadow, colours):
    """The card's shadow, fill and border."""
    shape = QPainterPath()
    if shadow:
        painter.save()
        painter.setPen(Qt.NoPen)
        strongest = 70 if colours['dark'] else 34
        for step in range(shadow, 0, -1):
            alpha = round(strongest * (1 - step / shadow) ** 2 / 3)
            if not alpha:
                continue
            ring = card.adjusted(-step, -step + 4, step, step + 4)
            ring = ring.intersected(QRectF(widget.rect()))
            painter.setBrush(QColor(0, 0, 0, alpha))
            painter.drawRoundedRect(ring, RADIUS + step, RADIUS + step)
        painter.restore()
        shape.addRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5),
                             RADIUS, RADIUS)
    else:
        shape.addRect(card.adjusted(0.5, 0.5, -0.5, -0.5))
    painter.fillPath(shape, colours['card'])
    painter.setPen(QPen(colours['border'], 1))
    painter.drawPath(shape)


def draw_bar(painter, track, colours, fraction, phase=None, busy=False):
    """The bar: `fraction` filled, or (busy) a segment sliding to and fro.
    `phase` (0..1, or None) places the light sweeping the filled part."""
    radius = track.height() / 2
    painter.save()
    painter.setPen(Qt.NoPen)
    painter.setBrush(colours['track'])
    painter.drawRoundedRect(track, radius, radius)
    accent = colours['accent']
    if busy:
        width = track.width() * 0.28
        # Eased to and fro across the track.
        position = 0.5 - 0.5 * math.cos((phase or 0.0) * 2 * math.pi)
        segment = QRectF(track.left() + (track.width() - width) * position,
                         track.top(), width, track.height())
        painter.setBrush(accent)
        painter.drawRoundedRect(segment, radius, radius)
    elif fraction > 0:
        filled = QRectF(track)
        filled.setWidth(max(track.height(), track.width() * fraction))
        painter.setBrush(accent)
        painter.drawRoundedRect(filled, radius, radius)
        if phase is not None and fraction < 1:
            # A light moving along what is done: the work goes on.
            span = max(filled.width() * 0.35, 40)
            centre = filled.left() - span + (filled.width() + 2 * span) * phase
            glow = QLinearGradient(centre - span / 2, 0, centre + span / 2, 0)
            light = QColor(255, 255, 255, 0)
            glow.setColorAt(0, light)
            light.setAlpha(90)
            glow.setColorAt(0.5, light)
            light.setAlpha(0)
            glow.setColorAt(1, light)
            clip = QPainterPath()
            clip.addRoundedRect(filled, radius, radius)
            painter.setClipPath(clip)
            painter.fillRect(filled, glow)
    painter.restore()


class SlimBar(QWidget):
    """The cards' bar as a widget, in QProgressBar's place inside windows
    (the job bar, External Modules, Hash Sets): QProgressBar's range,
    value and format, drawn slim -- the text beside the bar ('beside', for
    a percentage) or over it ('above', for a sentence). Range 0..0 = busy.
    Its frames run only while it is shown and working."""

    def __init__(self, parent=None, text='beside', bar_height=BAR_HEIGHT):
        super().__init__(parent)
        self._minimum, self._maximum, self._value = 0, 100, 0
        self._format, self._text_visible = "%p%", text == 'beside'
        self._text_position = text
        self._bar_height = bar_height
        # Its own height, never a layout's spare room.
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._phase = 0.0
        self._frames = QTimer(self)
        self._frames.setInterval(FRAME_MS)
        self._frames.timeout.connect(self._next_frame)

    # QProgressBar's names.
    def setRange(self, minimum, maximum):
        self._minimum, self._maximum = minimum, maximum
        self._value = min(max(self._value, minimum), max(minimum, maximum))
        self._changed()

    def setMinimum(self, minimum):
        self.setRange(minimum, self._maximum)

    def setMaximum(self, maximum):
        self.setRange(self._minimum, maximum)

    def minimum(self):
        return self._minimum

    def maximum(self):
        return self._maximum

    def value(self):
        return self._value

    def setValue(self, value):
        self._value = value
        self._changed()

    def reset(self):
        self.setValue(self._minimum)

    def setFormat(self, text):
        self._format = text
        self.updateGeometry()
        self.update()

    def format(self):
        return self._format

    def setTextVisible(self, visible):
        self._text_visible = visible
        self.updateGeometry()
        self.update()

    def text(self):
        if self.fraction() is None:
            return self._format.replace('%p%', '').strip()
        return self._format.replace(
            '%p', str(round(self.fraction() * 100))).replace(
            '%v', str(self._value)).replace('%m', str(self._maximum))

    def fraction(self):
        span = self._maximum - self._minimum
        if span <= 0:
            return None
        return min(1.0, max(0.0, (self._value - self._minimum) / span))

    # --- frames -----------------------------------------------------------

    def _working(self):
        fraction = self.fraction()
        return fraction is None or 0 < fraction < 1

    def _changed(self):
        if self.isVisible() and self._working():
            if not self._frames.isActive():
                self._frames.start()
        else:
            self._frames.stop()
        self.update()

    def showEvent(self, event):
        super().showEvent(event)
        self._changed()

    def hideEvent(self, event):
        self._frames.stop()
        super().hideEvent(event)

    def _next_frame(self):
        self._phase = (self._phase + FRAME_MS / 1600) % 1.0
        self.update()

    # --- size and drawing ---------------------------------------------------

    def _text_font(self):
        return pixel_font(QFont(self.font()), 0.92)

    def sizeHint(self):
        line = QFontMetrics(self._text_font()).height()
        if self._text_visible and self._text_position == 'above':
            return QSize(200, line + 4 + self._bar_height)
        return QSize(200, max(line, self._bar_height))

    def minimumSizeHint(self):
        return self.sizeHint()

    def paintEvent(self, event):
        colours = card_colours(self.palette())
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing
                               | QPainter.TextAntialiasing)
        rect = QRectF(self.rect())
        text = self.text() if self._text_visible else ''
        font = self._text_font()
        metrics = QFontMetrics(font)
        track_left, track_width = rect.left(), rect.width()
        track_top = rect.top() + (rect.height() - self._bar_height) / 2
        painter.setFont(font)
        painter.setPen(colours['quiet'])
        if text and self._text_position == 'above':
            painter.drawText(
                QRectF(rect.left(), rect.top(), rect.width(),
                       metrics.height()),
                Qt.AlignLeft | Qt.AlignVCenter,
                metrics.elidedText(text, Qt.ElideRight, int(rect.width())))
            track_top = rect.bottom() - self._bar_height
        elif text:
            room = metrics.horizontalAdvance("100%") + 8
            room = max(room, metrics.horizontalAdvance(text) + 8)
            room = min(room, rect.width() / 2)
            painter.drawText(
                QRectF(rect.right() - room, rect.top(), room, rect.height()),
                Qt.AlignRight | Qt.AlignVCenter,
                metrics.elidedText(text, Qt.ElideRight, int(room)))
            track_width -= room
        fraction = self.fraction()
        draw_bar(painter, QRectF(track_left, track_top, track_width,
                                 self._bar_height), colours,
                 fraction or 0.0,
                 self._phase if self._frames.isActive() else None,
                 busy=fraction is None)
        painter.end()


class ProgressCard(QWidget):
    """A frameless card: logo and title, what it is about, the step now
    with the time spent, a bar, and an optional Cancel button.

    `set_progress(fraction, step)`; `fraction` None = not known (busy bar).
    Painted with the event loop (its frames run while a job or a nested
    loop waits); it never pumps the loop itself."""

    canceled = Signal()
    #: Whether the bar may only move on (a dialog's value may be reset).
    forward_only = True

    WIDTH = 460
    PADDING = 22
    LOGO = 30

    def __init__(self, title, about='', parent=None, cancel_text=None):
        flags = Qt.FramelessWindowHint | (Qt.Dialog if parent is not None
                                          else Qt.Tool
                                          | Qt.WindowStaysOnTopHint)
        super().__init__(parent, flags)
        self.setObjectName("progressCard")
        self._shadow = SHADOW if translucent_windows() else 0
        if self._shadow:
            self.setAttribute(Qt.WA_TranslucentBackground)
        self.title = title
        self.about = about
        self.step = ''
        self.fraction = None
        self._logo = LogoCache()
        self._started = time.monotonic()
        self._step_started = self._started
        self._cancel = None
        self._phase = 0.0
        self._frames = QTimer(self)
        self._frames.setInterval(FRAME_MS)
        self._frames.timeout.connect(self._next_frame)
        if cancel_text:
            self._cancel = QPushButton(cancel_text, self)
            self._cancel.setObjectName("progressCardCancel")
            self._cancel.clicked.connect(self._cancelled)
        self._was_cancelled = False
        #: [(name, fraction it starts at)]: the stages listed with a tick
        #: once done (`set_stages`); the current one is the last started.
        self.stages = []
        self._fit()

    # --- what it says -----------------------------------------------------

    def set_stages(self, stages):
        """List `stages` -- (name, the bar's fraction where it starts) --
        under the title: done ones ticked, the current one marked. The
        step line below says what the current stage is doing."""
        self.stages = sorted(stages, key=lambda stage: stage[1])
        self._fit()
        if self.isVisible():
            self.update()

    def current_stage(self):
        """Index of the stage under way (len(stages) once all are done)."""
        if not self.stages:
            return -1
        fraction = self.fraction or 0.0
        if fraction >= 1.0:
            return len(self.stages)
        current = 0
        for number, (_name, start) in enumerate(self.stages):
            if fraction >= start:
                current = number
        return current

    def set_progress(self, fraction, step=None):
        """`fraction` 0..1 (never backwards), or None for "not known"."""
        if fraction is not None:
            fraction = min(1.0, max(0.0, float(fraction)))
            if self.forward_only and self.fraction is not None:
                fraction = max(self.fraction, fraction)
        self.fraction = fraction
        if step is not None and step != self.step:
            self.step = step
            self._step_started = time.monotonic()
        # Painted with the next frame: a byte counter can call this
        # hundreds of times a second.
        if self.isVisible():
            self.update()

    def set_about(self, about):
        self.about = about
        if self.isVisible():
            self.update()

    def set_cancellable(self, cancellable):
        if self._cancel is not None:
            self._cancel.setVisible(cancellable)
            self._fit()

    def was_cancelled(self):
        return self._was_cancelled

    def _cancelled(self):
        self._was_cancelled = True
        if self._cancel is not None:
            self._cancel.setEnabled(False)
        self.step = "Cancelling…"
        self.update()
        self.canceled.emit()

    # --- showing ----------------------------------------------------------

    def show_now(self):
        """Show it, centred on its window (or the screen), and paint."""
        self._centre()
        self.show()
        self.raise_()
        self.repaint()

    def showEvent(self, event):
        super().showEvent(event)
        self._frames.start()

    def hideEvent(self, event):
        self._frames.stop()
        super().hideEvent(event)

    def _next_frame(self):
        self._phase = (self._phase + FRAME_MS / 1600) % 1.0
        self.update()

    def _centre(self):
        parent = self.parentWidget()
        if parent is not None and parent.isVisible():
            centre = parent.window().frameGeometry().center()
        else:
            from PySide6.QtGui import QCursor
            screen = QGuiApplication.screenAt(QCursor.pos()) or \
                QGuiApplication.primaryScreen()
            if screen is None:
                return
            centre = screen.availableGeometry().center()
        self.move(centre.x() - self.width() // 2,
                  centre.y() - self.height() // 2)

    # --- layout and drawing -------------------------------------------------

    def _fonts(self):
        base = QFont(self.font())
        return (pixel_font(base, 1.25, QFont.DemiBold),
                pixel_font(base, 1.0), pixel_font(base, 0.92))

    def _fit(self):
        title, normal, small = self._fonts()
        height = (self.PADDING + max(self.LOGO, QFontMetrics(title).height()
                                     + QFontMetrics(small).height())
                  + self._stages_height()
                  + 16 + STEP_LINES * QFontMetrics(normal).height() + 10
                  + BAR_HEIGHT
                  + self.PADDING)
        if self._cancel is not None and not self._cancel.isHidden():
            height += 14 + self._cancel.sizeHint().height()
        self.setFixedSize(self.WIDTH + 2 * self._shadow,
                          height + 2 * self._shadow)
        if self._cancel is not None:
            hint = self._cancel.sizeHint()
            width = max(hint.width(), 96)
            self._cancel.setGeometry(
                self.width() - self._shadow - self.PADDING - width + 8,
                self.height() - self._shadow - self.PADDING - hint.height(),
                width, hint.height())

    def paintEvent(self, event):
        colours = card_colours(self.palette())
        title_font, normal, small = self._fonts()
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing
                               | QPainter.TextAntialiasing
                               | QPainter.SmoothPixmapTransform)
        card = QRectF(self._shadow, self._shadow, self.WIDTH,
                      self.height() - 2 * self._shadow)
        draw_card(painter, self, card, self._shadow, colours)

        left = card.left() + self.PADDING
        width = card.width() - 2 * self.PADDING
        top = card.top() + self.PADDING
        logo = self._logo.pixmap(self.LOGO, self.devicePixelRatioF())
        if logo is not None:
            painter.drawPixmap(int(left), int(top), logo)
        text_left = left + self.LOGO + 12
        text_width = width - self.LOGO - 12
        title_metrics, small_metrics = (QFontMetrics(title_font),
                                        QFontMetrics(small))
        header = title_metrics.height() + (small_metrics.height()
                                           if self.about else 0)
        line = top + max(0, (self.LOGO - header) / 2)
        painter.setFont(title_font)
        painter.setPen(colours['text'])
        painter.drawText(QRectF(text_left, line, text_width,
                                title_metrics.height()),
                         Qt.AlignLeft | Qt.AlignVCenter,
                         title_metrics.elidedText(
                             self.title, Qt.ElideRight, int(
                                 text_width - 12 - small_metrics
                                 .horizontalAdvance(RIGHT_TEXT_ROOM))))
        if self.about:
            painter.setFont(small)
            painter.setPen(colours['quiet'])
            painter.drawText(
                QRectF(text_left, line + title_metrics.height(), text_width,
                       small_metrics.height()),
                Qt.AlignLeft | Qt.AlignVCenter,
                small_metrics.elidedText(self.about, Qt.ElideMiddle,
                                         int(text_width)))

        # The time spent and the share done, on the title's line.
        right = self._right_text()
        if right:
            painter.setFont(small)
            painter.setPen(colours['quiet'])
            painter.drawText(
                QRectF(left, line, width, title_metrics.height()),
                Qt.AlignRight | Qt.AlignVCenter, right)

        stages_top = top + max(self.LOGO, header)
        if self.stages:
            self._draw_stages(painter, colours, normal, left,
                              stages_top + STAGES_GAP, width)

        # The step: two lines kept for it, so the card never changes size.
        normal_metrics = QFontMetrics(normal)
        step_top = stages_top + self._stages_height() + 16
        painter.setFont(normal)
        painter.setPen(colours['text'])
        for number, text in enumerate(
                two_lines(normal_metrics, self.step, int(width))):
            painter.drawText(
                QRectF(left, step_top + number * normal_metrics.height(),
                       width, normal_metrics.height()),
                Qt.AlignLeft | Qt.AlignVCenter, text)

        bar_top = step_top + STEP_LINES * normal_metrics.height() + 10
        draw_bar(painter, QRectF(left, bar_top, width, BAR_HEIGHT), colours,
                 self.fraction or 0.0, self._phase if self._frames.isActive()
                 else None, busy=self.fraction is None)
        painter.end()

    def _stages_height(self):
        if not self.stages:
            return 0
        return STAGES_GAP + len(self.stages) * STAGE_ROW + 4

    def _draw_stages(self, painter, colours, font, left, top, width):
        """Each stage on a row: a ticked disc once done, a ring with a
        pulsing dot for the one under way, a faint ring for those ahead."""
        current = self.current_stage()
        accent = colours['accent']
        bold = QFont(font)
        bold.setWeight(QFont.DemiBold)
        metrics = QFontMetrics(font)
        mark = 14
        painter.save()
        for number, (name, _start) in enumerate(self.stages):
            row = top + number * STAGE_ROW
            disc = QRectF(left + 1, row + (STAGE_ROW - mark) / 2, mark, mark)
            if number < current:
                painter.setPen(Qt.NoPen)
                painter.setBrush(accent)
                painter.drawEllipse(disc)
                tick = QPen(QColor(255, 255, 255), 1.8)
                tick.setCapStyle(Qt.RoundCap)
                tick.setJoinStyle(Qt.RoundJoin)
                painter.setPen(tick)
                path = QPainterPath()
                path.moveTo(disc.left() + mark * 0.28, disc.top() + mark * 0.52)
                path.lineTo(disc.left() + mark * 0.44, disc.top() + mark * 0.68)
                path.lineTo(disc.left() + mark * 0.73, disc.top() + mark * 0.35)
                painter.setBrush(Qt.NoBrush)
                painter.drawPath(path)
                pen, text_font = colours['quiet'], font
            elif number == current:
                painter.setPen(QPen(accent, 1.6))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(disc.adjusted(0.8, 0.8, -0.8, -0.8))
                pulse = 0.5 + 0.5 * math.sin(self._phase * 2 * math.pi)
                dot = mark * (0.28 + 0.12 * pulse)
                painter.setPen(Qt.NoPen)
                painter.setBrush(accent)
                painter.drawEllipse(disc.center(), dot / 2, dot / 2)
                pen, text_font = colours['text'], bold
            else:
                painter.setPen(QPen(colours['border'], 1.4))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(disc.adjusted(0.8, 0.8, -0.8, -0.8))
                pen, text_font = colours['quiet'], font
            painter.setFont(text_font)
            painter.setPen(pen)
            text_left = left + mark + 12
            painter.drawText(
                QRectF(text_left, row, width - mark - 12, STAGE_ROW),
                Qt.AlignLeft | Qt.AlignVCenter,
                metrics.elidedText(name, Qt.ElideRight,
                                   int(width - mark - 12)))
        painter.restore()

    def _right_text(self):
        pieces = []
        spent = time.monotonic() - self._started
        if spent >= SHOW_ELAPSED_AFTER:
            pieces.append(elapsed_text(spent))
        if self.fraction is not None:
            pieces.append(f"{round(self.fraction * 100)}%")
        return "  ·  ".join(pieces)


class ProgressDialog(ProgressCard):
    """QProgressDialog's subset that TRACE uses, as a progress card:
    label, range and value, Cancel and `canceled`, a minimum duration
    before it shows, window modality. A range of 0..0 is a busy bar.

    A label of two lines is the step and, under the title, what it is
    about."""

    forward_only = False

    def __init__(self, label, cancel_text, minimum, maximum, parent=None):
        super().__init__("", '', parent, cancel_text or None)
        self._minimum, self._maximum, self._value = minimum, maximum, minimum
        self._minimum_duration = 0
        self._shown_once = False
        self._created = time.monotonic()
        self._show_timer = QTimer(self)
        self._show_timer.setSingleShot(True)
        self._show_timer.timeout.connect(self._show_if_running)
        self.setMinimumDuration(4000)
        self.setLabelText(label)
        self._update_fraction()

    # QProgressDialog's names.
    def setWindowTitle(self, title):
        super().setWindowTitle(title)
        self.title = title
        self.update()

    def setLabelText(self, text):
        step, _, about = (text or '').partition('\n')
        if about:
            self.about = about.strip()
        self.set_progress(self.fraction, step.strip())
        self._show_if_due()

    def labelText(self):
        return self.step

    def setCancelButton(self, button):
        if button is None:
            self.set_cancellable(False)

    def setMinimumDuration(self, ms):
        self._minimum_duration = ms
        if not self._shown_once:
            self._show_timer.start(max(0, ms))

    def setAutoClose(self, value):
        pass

    def setAutoReset(self, value):
        pass

    def setRange(self, minimum, maximum):
        self._minimum, self._maximum = minimum, maximum
        self._update_fraction()

    def setMaximum(self, maximum):
        self.setRange(self._minimum, maximum)

    def maximum(self):
        return self._maximum

    def value(self):
        return self._value

    def setValue(self, value):
        self._value = value
        self._update_fraction()
        self._show_if_due()

    def wasCanceled(self):
        return self.was_cancelled()

    def _update_fraction(self):
        span = self._maximum - self._minimum
        self.set_progress(None if span <= 0 else
                          (self._value - self._minimum) / span)

    def _show_if_due(self):
        if not self._shown_once and \
                (time.monotonic() - self._created) * 1000 >= \
                self._minimum_duration:
            self._show_if_running()

    def _show_if_running(self):
        if self._shown_once or getattr(self, '_closed', False):
            return
        self._shown_once = True
        self.show_now()

    def show(self):
        self._shown_once = True
        if not self.isVisible():
            self._centre()
        super().show()

    def closeEvent(self, event):
        self._closed = True
        self._show_timer.stop()
        super().closeEvent(event)

    def close(self):
        self._closed = True
        self._show_timer.stop()
        return super().close()

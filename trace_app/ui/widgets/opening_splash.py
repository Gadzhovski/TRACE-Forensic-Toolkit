"""The card shown between the launcher and the window while the window is
built: TRACE's logo, what is opening, and a progress bar fed by
`MainWindow(progress=)`. Drawn as every progress card is
(ui/widgets/progress_card.py), larger.

The window is built on the GUI thread, so between steps no events are
processed: `set_progress` repaints the card synchronously (`repaint`)
rather than pumping the event loop. Pumping it there would run timers the
half-built window had just queued.
"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QFont, QFontMetrics, QGuiApplication, QPainter
from PySide6.QtWidgets import QApplication, QWidget

from trace_app import __version__
from trace_app.ui.widgets.progress_card import (
    BAR_HEIGHT, SHADOW, LogoCache, card_colours, draw_bar, draw_card,
    pixel_font, translucent_windows)

#: The card itself, in logical pixels.
CARD_WIDTH, CARD_HEIGHT = 480, 196
LOGO_SIZE = 76
TAGLINE = "Toolkit for Retrieval and Analysis of Cyber Evidence"


class OpeningSplash(QWidget):
    """A frameless card on top, centred on the screen under the pointer."""

    def __init__(self, what):
        super().__init__(None, Qt.SplashScreen | Qt.FramelessWindowHint
                         | Qt.WindowStaysOnTopHint)
        self.setObjectName("openingSplash")
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self._shadow = SHADOW if translucent_windows() else 0
        if self._shadow:
            self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(CARD_WIDTH + 2 * self._shadow,
                          CARD_HEIGHT + 2 * self._shadow)
        self.what = what
        self.step = "Starting…"
        self.fraction = 0.0
        self._logo = LogoCache()
        self._centre()

    # --- feeding it -------------------------------------------------------

    def set_progress(self, fraction, step=None):
        """Move the bar to `fraction` (0..1, never backwards) and say what is
        being done; painted at once."""
        self.fraction = max(self.fraction, min(1.0, max(0.0, fraction)))
        if step:
            self.step = step
        if self.isVisible():
            self.repaint()

    def start(self):
        """Show it and let it paint before the window is built."""
        self.show()
        self.raise_()
        QApplication.processEvents()
        self.repaint()

    def finish(self):
        self.set_progress(1.0, "Ready")
        self.close()
        self.deleteLater()

    # --- drawing ----------------------------------------------------------

    def _centre(self):
        from PySide6.QtGui import QCursor
        screen = QGuiApplication.screenAt(QCursor.pos()) or \
            QGuiApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        self.move(area.center().x() - self.width() // 2,
                  area.center().y() - self.height() // 2)

    def _logo_pixmap(self, ratio):
        return self._logo.pixmap(LOGO_SIZE, ratio)

    def paintEvent(self, event):
        colours = card_colours(self.palette())
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing
                               | QPainter.TextAntialiasing
                               | QPainter.SmoothPixmapTransform)
        card = QRectF(self._shadow, self._shadow, CARD_WIDTH, CARD_HEIGHT)
        draw_card(painter, self, card, self._shadow, colours)

        left = card.left() + 28
        top = card.top() + 26
        logo = self._logo_pixmap(self.devicePixelRatioF())
        if logo is not None:
            painter.drawPixmap(QPointF(left, top), logo)
        text_left = left + LOGO_SIZE + 20
        text_width = card.right() - 28 - text_left

        base = QFont(self.font())
        title = pixel_font(base, 2.2, QFont.DemiBold)
        title.setLetterSpacing(QFont.PercentageSpacing, 104)
        small = pixel_font(base, 0.92)
        painter.setFont(title)
        painter.setPen(colours['text'])
        title_height = QFontMetrics(title).height()
        painter.drawText(QRectF(text_left, top, text_width, title_height),
                         Qt.AlignLeft | Qt.AlignVCenter, "TRACE")
        painter.setFont(small)
        painter.setPen(colours['quiet'])
        metrics = QFontMetrics(small)
        line = top + title_height
        painter.drawText(QRectF(text_left, line, text_width, metrics.height()),
                         Qt.AlignLeft | Qt.AlignVCenter,
                         metrics.elidedText(TAGLINE, Qt.ElideRight,
                                            int(text_width)))
        painter.drawText(
            QRectF(text_left, line + metrics.height() + 2, text_width,
                   metrics.height()),
            Qt.AlignLeft | Qt.AlignVCenter, f"Version {__version__}")

        # What is opening, the step, and the bar along the bottom.
        bar_left = card.left() + 28
        bar_width = CARD_WIDTH - 56
        bar_top = card.bottom() - 26 - BAR_HEIGHT
        normal = QFont(base)
        normal_metrics = QFontMetrics(normal)
        status_top = bar_top - 10 - normal_metrics.height()
        percent = f"{round(self.fraction * 100)}%"
        percent_width = metrics.horizontalAdvance("100%") + 4
        painter.setFont(normal)
        painter.setPen(colours['text'])
        painter.drawText(
            QRectF(bar_left, status_top - normal_metrics.height() - 2,
                   bar_width, normal_metrics.height()),
            Qt.AlignLeft | Qt.AlignVCenter,
            normal_metrics.elidedText(self.what, Qt.ElideMiddle,
                                      int(bar_width)))
        painter.setFont(small)
        painter.setPen(colours['quiet'])
        painter.drawText(
            QRectF(bar_left, status_top, bar_width - percent_width,
                   normal_metrics.height()),
            Qt.AlignLeft | Qt.AlignVCenter,
            metrics.elidedText(self.step, Qt.ElideRight,
                               int(bar_width - percent_width)))
        painter.drawText(
            QRectF(bar_left + bar_width - percent_width, status_top,
                   percent_width, normal_metrics.height()),
            Qt.AlignRight | Qt.AlignVCenter, percent)
        draw_bar(painter, QRectF(bar_left, bar_top, bar_width, BAR_HEIGHT),
                 colours, self.fraction)
        painter.end()

"""A one-line label that gives way: elided with "…" when there is no room,
the whole text in its tooltip.

A plain QLabel's minimum width is its whole text. In a toolbar, a long
status ("161,839 event(s) in this range; the first 100,000 listed …") then
pushed the buttons after it out of reach on a laptop screen.
"""

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QLabel, QSizePolicy


class ElidedLabel(QLabel):
    def __init__(self, text='', parent=None):
        super().__init__(text, parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def minimumSizeHint(self):
        return QSize(40, super().minimumSizeHint().height())

    def sizeHint(self):
        # Modest: a toolbar sizes by hint, and the Expanding policy hands
        # this label whatever room the buttons leave.
        hint = super().sizeHint()
        return QSize(min(hint.width(), 160), hint.height())

    def setText(self, text):
        super().setText(text)
        self._sync_tooltip()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_tooltip()

    def _elided(self):
        rect = self.contentsRect()
        return self.fontMetrics().elidedText(self.text(), Qt.ElideRight,
                                             rect.width())

    def _sync_tooltip(self):
        self.setToolTip(self.text() if self._elided() != self.text() else '')

    def paintEvent(self, _event):
        from PySide6.QtGui import QPainter
        painter = QPainter(self)
        self.style().drawItemText(
            painter, self.contentsRect(),
            int(self.alignment()) | int(Qt.AlignVCenter), self.palette(),
            self.isEnabled(), self._elided(), self.foregroundRole())
        painter.end()


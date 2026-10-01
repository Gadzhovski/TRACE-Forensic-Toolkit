"""Tree view that draws its own expand arrows.

Qt rasterises a stylesheet `image:` without antialiasing, so the chevron in
`QTreeWidget::branch` came out as a staircase of hard squares. Rendering the
Tabler SVG through QSvgRenderer instead fixed the antialiasing but not the
look: Tabler's 2-unit stroke on a 24-unit grid, fitted into a 14px strip, is a
1.2px line, and on a 125% display it lands between device pixels and smears
into a grey blur.

So the chevron is drawn here as a path, sized for the strip it sits in. Its
stroke is a whole number of device pixels and its centre sits on the device
pixel grid, so the vertical extent of the arrow is crisp at every scale
factor and only the diagonals are antialiased -- which is what they need.
"""

import math

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QTreeWidget

from trace_app.ui import icons

#: Half the chevron's long side, in logical pixels. Eight pixels tall reads as
#: an arrow at a glance without competing with the row's 20px icon.
CHEVRON_HALF = 4.0

#: Stroke width in logical pixels, before it is rounded to device pixels.
CHEVRON_STROKE = 1.5

#: How much of the theme's foreground the arrow takes. Full strength made the
#: arrows the darkest marks in the tree, louder than the names beside them.
CHEVRON_OPACITY = 0.75


class BranchTreeWidget(QTreeWidget):
    """A QTreeWidget whose expand arrows are painted, not stylesheet images."""

    def drawBranches(self, painter, rect, index):
        """Draw the row's expand arrow, and nothing else.

        The base implementation is not called. It paints one branch cell per
        ancestor level, each inset slightly, so a selected row showed a row of
        separate boxes stepping out to its depth rather than one continuous
        highlight. `rect` spans the whole indentation area, so filling it once
        gives the unbroken strip the row deserves.
        """
        selected = self.selectionModel().isSelected(index)
        if selected:
            painter.fillRect(rect, self.palette().highlight())

        if not self.model().hasChildren(index):
            return

        # The arrow belongs in the strip immediately left of the item, one
        # indentation step wide.
        step = self.indentation()
        centre = QPointF(rect.right() + 1 - step / 2,
                         rect.top() + rect.height() / 2)
        self._draw_chevron(painter, centre, self.isExpanded(index), selected)

    def _draw_chevron(self, painter, centre, expanded, selected):
        device = painter.device()
        dpr = device.devicePixelRatioF() if device else 1.0

        # A whole number of device pixels, never less than one.
        stroke = max(1, round(CHEVRON_STROKE * dpr)) / dpr

        # Snap the centre to the device grid. An odd-width stroke is centred
        # on a pixel's middle, an even one on its edge; either way the line
        # covers whole pixels instead of two half-lit ones.
        offset = 0.5 if round(stroke * dpr) % 2 else 0.0
        cx = (math.floor(centre.x() * dpr) + offset) / dpr
        cy = (math.floor(centre.y() * dpr) + offset) / dpr

        half = CHEVRON_HALF
        path = QPainterPath()
        if expanded:
            # Pointing down: wide and shallow.
            path.moveTo(cx - half, cy - half / 2)
            path.lineTo(cx, cy + half / 2)
            path.lineTo(cx + half, cy - half / 2)
        else:
            # Pointing right: tall and narrow.
            path.moveTo(cx - half / 2, cy - half)
            path.lineTo(cx + half / 2, cy)
            path.lineTo(cx - half / 2, cy + half)

        if selected:
            colour = self.palette().highlightedText().color()
        else:
            colour = QColor(icons.foreground())
            colour.setAlphaF(CHEVRON_OPACITY)

        pen = QPen(colour, stroke)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)
        painter.restore()

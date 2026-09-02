"""Tree view that draws its own expand arrows.

Qt rasterises a stylesheet `image:` without antialiasing, so the chevron in
`QTreeWidget::branch` came out as a staircase of hard squares -- three distinct
grey levels across the whole strip. Widening the stroke and changing the
indentation both failed to help, because neither addresses the missing
antialiasing.

Painting the arrow here instead, through QPainter with Antialiasing on, gives
eleven grey levels and a smooth diagonal. It also renders from the vector at
whatever size the strip happens to be, including the fractional sizes a scaled
display asks for, so it stays sharp at any DPI.
"""

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QTreeWidget

from trace_app.infra.paths import resource_path

#: Fraction of the indentation strip the glyph occupies. Less than the full
#: width, so the arrow has air around it rather than touching the row's icon.
GLYPH_SCALE = 0.7


class BranchTreeWidget(QTreeWidget):
    """A QTreeWidget whose expand arrows are painted, not stylesheet images."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._renderers = {}
        self._closed = 'Icons/tabler/themed/chevron-right-light.svg'
        self._open = 'Icons/tabler/themed/chevron-down-light.svg'

    def set_branch_icons(self, closed_path, open_path):
        """Point the arrows at the current theme's chevrons."""
        self._closed = closed_path
        self._open = open_path
        self._renderers.clear()
        self.viewport().update()

    def _renderer(self, name):
        renderer = self._renderers.get(name)
        if renderer is None:
            renderer = QSvgRenderer(resource_path(name))
            self._renderers[name] = renderer
        return renderer

    def drawBranches(self, painter, rect, index):
        """Draw the row's expand arrow, and nothing else.

        The base implementation is not called. It paints one branch cell per
        ancestor level, each inset slightly, so a selected row showed a row of
        separate boxes stepping out to its depth rather than one continuous
        highlight. `rect` spans the whole indentation area, so filling it once
        gives the unbroken strip the row deserves.
        """
        if self.selectionModel().isSelected(index):
            painter.fillRect(rect, self.palette().highlight())

        if not self.model().hasChildren(index):
            return

        name = self._open if self.isExpanded(index) else self._closed
        renderer = self._renderer(name)
        if not renderer.isValid():
            return

        # The arrow belongs in the strip immediately left of the item, one
        # indentation step wide.
        step = self.indentation()
        cell = QRectF(rect.right() - step, rect.top(), step, rect.height())

        size = min(cell.width(), cell.height()) * GLYPH_SCALE
        target = QRectF(cell.center().x() - size / 2,
                        cell.center().y() - size / 2,
                        size, size)

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        renderer.render(painter, target)
        painter.restore()

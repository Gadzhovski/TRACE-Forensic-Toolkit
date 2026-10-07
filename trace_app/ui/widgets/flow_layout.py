"""A layout that wraps its widgets onto as many rows as the width needs.

Qt has no such layout built in. A row of filters and chips in an
QHBoxLayout makes its widest content the window's minimum width: the
Timeline's two rows once demanded 2,000 px, and Qt took the room from the
tree dock, squeezing it to a sliver on every laptop. Wrapped, the same
controls fit in whatever width there is.

Adapted from Qt's Flow Layout example (BSD).
"""

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtWidgets import QLayout, QSizePolicy


class FlowLayout(QLayout):
    """Left to right, wrapping; every row as tall as its tallest item."""

    def __init__(self, parent=None, spacing=6):
        super().__init__(parent)
        self._items = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) \
            else None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        """As wide as the widest single item -- never the whole row."""
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(),
                            margins.top() + margins.bottom())

    def _arrange(self, rect, apply):
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(),
                             -margins.right(), -margins.bottom())
        x, y, row_height = area.x(), area.y(), 0
        for item in self._items:
            widget = item.widget()
            if widget is not None and not widget.isVisibleTo(
                    widget.parentWidget()):
                continue
            hint = item.sizeHint()
            if x + hint.width() > area.right() + 1 and row_height:
                x = area.x()
                y += row_height + self._spacing
                row_height = 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self._spacing
            row_height = max(row_height, hint.height())
        return y + row_height - rect.y() + margins.bottom()


def flow_row(parent, widgets, spacing=6):
    """A widget holding `widgets` in a FlowLayout, for a parent layout."""
    from PySide6.QtWidgets import QWidget
    holder = QWidget(parent)
    holder.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
    layout = FlowLayout(holder, spacing)
    for widget in widgets:
        layout.addWidget(widget)
    return holder

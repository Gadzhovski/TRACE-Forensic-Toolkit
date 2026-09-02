"""An item delegate that draws no focus rectangle.

Qt marks the item that holds keyboard focus with a dotted rectangle, drawn by
the platform style. Inside a row that is already painted with a selection
colour it adds nothing -- the selection says which row is current -- and on
Windows it reads as a stray dotted frame around the text.

The state flag is cleared before the base class paints, which is the supported
way to suppress it; the alternative, a stylesheet rule, does not reach a
style-drawn primitive.
"""

from PySide6.QtWidgets import QStyle, QStyledItemDelegate


class NoFocusDelegate(QStyledItemDelegate):
    """Paints items normally, minus the focus rectangle."""

    def paint(self, painter, option, index):
        if option.state & QStyle.State_HasFocus:
            option.state &= ~QStyle.State_HasFocus
        super().paint(painter, option, index)

"""An item delegate that draws no focus rectangle, and honours a cell's colour.

Qt marks the item that holds keyboard focus with a dotted rectangle, drawn by
the platform style. Inside a row that is already painted with a selection
colour it adds nothing -- the selection says which row is current -- and on
Windows it reads as a stray dotted frame around the text.

The state flag is cleared before the base class paints, which is the supported
way to suppress it; the alternative, a stylesheet rule, does not reach a
style-drawn primitive.

A cell given a colour with setForeground() is also drawn in it. Both themes set
`QTableWidget::item { color: ... }`, and a stylesheet colour beats an item's
own, so every coloured cell in the application -- the listing's red "Type
mismatch" flag, the VirusTotal verdicts -- was being painted in plain text
colour. The item's background, selection and padding are still drawn by the
style; only the text is painted here.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QStyle, QStyledItemDelegate,
                               QStyleOptionViewItem)


class NoFocusDelegate(QStyledItemDelegate):
    """Paints items normally, minus the focus rectangle."""

    def paint(self, painter, option, index):
        if option.state & QStyle.State_HasFocus:
            option.state &= ~QStyle.State_HasFocus

        tone = index.data(Qt.ForegroundRole)
        if tone is None:
            super().paint(painter, option, index)
            return

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        widget = opt.widget
        style = widget.style() if widget is not None else QApplication.style()

        # Where the style would put the text, measured while there is text.
        rect = style.subElementRect(QStyle.SubElement.SE_ItemViewItemText, opt, widget)
        text = opt.text
        opt.text = ''
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)

        margin = style.pixelMetric(QStyle.PixelMetric.PM_FocusFrameHMargin, None,
                                   widget) + 1
        rect = rect.adjusted(margin, 0, -margin, 0)
        painter.save()
        painter.setFont(opt.font)
        painter.setPen(tone.color() if hasattr(tone, 'color') else tone)
        painter.drawText(rect, int(opt.displayAlignment),
                         opt.fontMetrics.elidedText(text, opt.textElideMode,
                                                    rect.width()))
        painter.restore()

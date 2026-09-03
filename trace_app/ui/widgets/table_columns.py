"""Sizing table columns to what they actually contain.

Fixed column widths are guesses made before any data exists, so they are
usually wrong in both directions: an Inode column 50px wide for a four-digit
number, and a Type column too narrow for "Deleted Dir". Measuring the content
fixes that, but measuring alone is not enough for a file listing -- a full path
or an NTFS attribute list is long enough to push the timestamp columns off
screen, so the widest columns are capped and elide with a tooltip instead.
"""

from PySide6.QtGui import QFontMetrics

#: Space either side of a cell's text, so fitted columns are not flush.
CELL_PADDING = 24

#: Nothing narrower than this, however short its content.
MIN_COLUMN_WIDTH = 48


def fit_columns(table, caps=None, sample_limit=400):
    """Size each column to its content, capped where `caps` says.

    `caps` maps a column index to its maximum width; a column not named there
    is fitted exactly. Only the first `sample_limit` rows are measured -- a
    directory of thousands of files takes noticeably longer to measure than to
    show, and the longest name is almost always within the first few hundred.

    The header is measured too, because a column sized only to its cells can
    end up narrower than its own heading.
    """
    caps = caps or {}
    header = table.horizontalHeader()
    metrics = QFontMetrics(table.font())
    header_metrics = QFontMetrics(header.font())
    rows = min(table.rowCount(), sample_limit)

    for column in range(table.columnCount()):
        if table.isColumnHidden(column):
            continue

        heading = table.horizontalHeaderItem(column)
        widest = (header_metrics.horizontalAdvance(heading.text())
                  if heading else 0)

        for row in range(rows):
            item = table.item(row, column)
            if item is None:
                continue
            width = metrics.horizontalAdvance(item.text())
            if not item.icon().isNull():
                width += table.iconSize().width() + 6
            if width > widest:
                widest = width

        widest += CELL_PADDING
        cap = caps.get(column)
        if cap is not None:
            widest = min(widest, cap)
        table.setColumnWidth(column, max(widest, MIN_COLUMN_WIDTH))

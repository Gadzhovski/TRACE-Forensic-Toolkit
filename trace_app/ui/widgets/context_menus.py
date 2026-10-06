"""What every right-click menu and every list offers.

- `show_menu(menu, global_pos)` shows a context menu after adding, for the
  list or table under the pointer, Copy (Ctrl+C), Copy Rows with Headers,
  Copy Column "...", and Export Table to CSV...; and gives every entry
  without one an icon, from the verb it starts with, in the theme's own
  line icons -- Qt's standard Copy / Select All icons were near-invisible
  on the light theme.
- `install(app)` makes Ctrl+C copy the selection of any list, table or
  tree, and gives a list with no menu of its own one with those entries.

A copy is the cells as shown, tab-separated, a line per row -- what a
spreadsheet or a report takes.
"""

import csv
import logging
import re

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QFileDialog,
                               QMenu)

logger = logging.getLogger('TRACE.ContextMenus')

#: A view that copies in its own way (the hex table) sets this property.
OWN_COPY = 'traceOwnCopy'


def _icons():
    from trace_app.ui import icons
    return icons


def _verb_icons():
    """Leading words of a menu entry -> icon name, first match wins."""
    icons = _icons()
    return (
        (r'copy', icons.COPY), (r'select all', icons.SELECT_ALL),
        (r'export|save', icons.EXPORT), (r'(add |remove )?bookmark',
                                         icons.BOOKMARK),
        (r'edit|rename', icons.EDIT),
        (r'delete|remove|forget|clear', icons.DELETE),
        (r'show (in|file|content|in listing)|go to|reveal|open (in|file)',
         icons.EXTERNAL_LINK),
        (r'open (containing )?folder|open log folder', icons.OPEN_FOLDER),
        (r'preview|view', icons.DISPLAY),
        (r'verify', icons.VERIFY),
        (r'look up|upload|virustotal', icons.VIRUSTOTAL_MENU),
        (r'decode', icons.CODE),
        (r'find|search', icons.SEARCH),
        (r'unlock', icons.VOLUME_UNLOCKED),
        (r'image information|properties|details', icons.INFO),
        (r'browse archive|open archive', icons.OPEN_FOLDER),
        (r'play', icons.PLAY),
    )


def _plain(text):
    return text.replace('&', '').split('\t')[0].strip().lower()


def add_icons(menu):
    """Every entry of `menu` (and its submenus) without an icon gets one
    from its verb. Checkable entries keep none: the tick goes there."""
    icons = _icons()
    patterns = _verb_icons()
    for action in menu.actions():
        sub = action.menu()
        if sub is not None:
            add_icons(sub)
        if action.isSeparator() or action.isCheckable():
            continue
        if not action.icon().isNull() and \
                action.objectName() not in ('edit-copy', 'select-all'):
            continue
        text = _plain(action.text())
        for pattern, name in patterns:
            if name and re.match(pattern, text):
                action.setIcon(icons.icon(name))
                break


# --- copying a view's selection --------------------------------------------------------

def _model_text(view, index):
    value = view.model().data(index, Qt.DisplayRole)
    return '' if value is None else str(value).replace('\t', ' ') \
        .replace('\n', ' ')


def _visible_columns(view):
    header = view.horizontalHeader() if hasattr(view, 'horizontalHeader') \
        else view.header() if hasattr(view, 'header') else None
    model = view.model()
    columns = [c for c in range(model.columnCount())
               if not (header is not None and header.isSectionHidden(c))
               and not (hasattr(view, 'isColumnHidden') and
                        view.isColumnHidden(c))]
    if header is not None:
        columns.sort(key=header.visualIndex)
    return columns


def _headers(view, columns):
    model = view.model()
    return [str(model.headerData(c, Qt.Horizontal) or '') for c in columns]


def selected_rows(view):
    """The selected rows' indexes (column 0), in view order."""
    selection = view.selectionModel()
    if selection is None:
        return []
    rows = {}
    for index in selection.selectedIndexes():
        key = (index.parent(), index.row())
        rows.setdefault(key, index.sibling(index.row(), 0))
    return sorted(rows.values(), key=lambda i: view.visualRect(i).top())


def selection_text(view, headers=False, whole_rows=False):
    """The selection as tab-separated text: the cells selected (or whole
    rows), a line per row."""
    selection = view.selectionModel()
    if selection is None or not selection.hasSelection():
        current = view.currentIndex()
        return _model_text(view, current) if current.isValid() else ''
    columns = _visible_columns(view)
    picked = {}
    for index in selection.selectedIndexes():
        picked.setdefault((index.parent(), index.row()), set()).add(
            index.column())
    used = columns if whole_rows else \
        [c for c in columns if any(c in cols for cols in picked.values())]
    lines = ['\t'.join(_headers(view, used))] if headers else []
    for index in selected_rows(view):
        cols = picked[(index.parent(), index.row())]
        lines.append('\t'.join(
            _model_text(view, index.sibling(index.row(), c))
            if whole_rows or c in cols else '' for c in used))
    return '\n'.join(lines)


def column_text(view, column):
    """One column's values, of the selected rows -- or of every row shown
    when none is selected."""
    rows = selected_rows(view) or _all_rows(view)
    return '\n'.join(_model_text(view, i.sibling(i.row(), column))
                     for i in rows)


def _all_rows(view, parent=None):
    """Every row shown, in view order (a tree's expanded rows too)."""
    from PySide6.QtCore import QModelIndex
    from PySide6.QtWidgets import QTreeView
    model = view.model()
    parent = parent if parent is not None else QModelIndex()
    tree = isinstance(view, QTreeView)
    found = []
    for row in range(model.rowCount(parent)):
        if tree:
            hidden = view.isRowHidden(row, parent)
        else:
            hidden = view.isRowHidden(row) if hasattr(view, 'isRowHidden') \
                else False
        if hidden:
            continue
        index = model.index(row, 0, parent)
        found.append(index)
        if tree and view.isExpanded(index):
            found.extend(_all_rows(view, index))
    return found


def export_csv(view, path=None, parent=None):
    """Every row shown, every column shown, to a CSV file."""
    if path is None:
        path, _ = QFileDialog.getSaveFileName(
            parent or view, "Export Table", "table.csv",
            "CSV files (*.csv)")
        if not path:
            return None
    columns = _visible_columns(view)
    with open(path, 'w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(_headers(view, columns))
        for index in _all_rows(view):
            writer.writerow([_model_text(view, index.sibling(index.row(), c))
                             for c in columns])
    return path


def copy_to_clipboard(text):
    if text:
        QApplication.clipboard().setText(text)


def add_view_actions(menu, view, global_pos):
    """Copy, Copy Rows with Headers, Copy Column "...", Export Table."""
    if view is None or view.property(OWN_COPY):
        return
    model = view.model()
    if model is None or not model.rowCount():
        return
    point = view.viewport().mapFromGlobal(global_pos)
    index = view.indexAt(point)
    if menu.actions():
        menu.addSeparator()
    copy = menu.addAction("Copy")
    copy.setShortcut(QKeySequence.Copy)
    copy.triggered.connect(lambda: copy_to_clipboard(selection_text(view)))
    rows = menu.addAction("Copy Rows with Headers")
    rows.triggered.connect(lambda: copy_to_clipboard(
        selection_text(view, headers=True, whole_rows=True)))
    if index.isValid() and model.columnCount() > 1:
        name = str(model.headerData(index.column(), Qt.Horizontal) or
                   f"column {index.column() + 1}")
        column = menu.addAction(f"Copy Column “{name}”")
        column.triggered.connect(lambda c=index.column(): copy_to_clipboard(
            column_text(view, c)))
    export = menu.addAction("Export Table to CSV…")
    export.triggered.connect(lambda: export_csv(view))


def view_at(global_pos):
    """The list, table or tree under a screen position, if any."""
    widget = QApplication.widgetAt(global_pos)
    while widget is not None and not isinstance(widget, QAbstractItemView):
        widget = widget.parentWidget()
    return widget


#: `hook(menu, row)`, set by the window: adds what a row naming a file on
#: the evidence should offer wherever it is listed (Export File, Add
#: Bookmark) when the menu has not already.
_row_hook = None


def set_row_hook(hook):
    global _row_hook
    _row_hook = hook


def row_at(view, global_pos):
    """The row data (a dict, column 0's UserRole) under the pointer."""
    index = view.indexAt(view.viewport().mapFromGlobal(global_pos))
    if not index.isValid():
        return None
    data = index.sibling(index.row(), 0).data(Qt.UserRole)
    return data if isinstance(data, dict) else None


def show_menu(menu, global_pos, view=None):
    """Show a context menu with the common entries and icons. `view`: the
    list it is for (found under the pointer when not given); False for
    none."""
    if view is None:
        view = view_at(global_pos)
    if view:
        row = row_at(view, global_pos)
        if row is not None and _row_hook is not None:
            try:
                _row_hook(menu, row)
            except Exception as exc:
                logger.debug("Menu extras failed: %s", exc)
        add_view_actions(menu, view, global_pos)
    add_icons(menu)
    return menu.exec(global_pos)


# --- every view: Ctrl+C, and a menu where there is none ----------------------------------

class _Copier(QObject):
    def eventFilter(self, watched, event):
        kind = event.type()
        if kind == QEvent.KeyPress and event.matches(QKeySequence.Copy):
            view = watched if isinstance(watched, QAbstractItemView) else None
            if view is not None and not view.property(OWN_COPY) and \
                    view.model() is not None:
                copy_to_clipboard(selection_text(view))
                return True
        elif kind == QEvent.ContextMenu:
            parent = watched.parentWidget() if hasattr(watched,
                                                       'parentWidget') \
                else None
            if isinstance(parent, QAbstractItemView) and \
                    watched is parent.viewport() and \
                    parent.contextMenuPolicy() == Qt.DefaultContextMenu and \
                    not parent.property(OWN_COPY) and \
                    parent.model() is not None and parent.model().rowCount():
                menu = QMenu(parent)
                show_menu(menu, event.globalPos(), parent)
                return True
        return False


_copier = None


def install(app):
    """Ctrl+C and a basic menu for every list, table and tree."""
    global _copier
    if _copier is None:
        _copier = _Copier(app)
        app.installEventFilter(_copier)

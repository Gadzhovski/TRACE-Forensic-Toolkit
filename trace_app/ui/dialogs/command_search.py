"""Find a command by name and run it (Ctrl+K).

Every command in the menus, findable by typing part of its name or menu:
"verify" finds Tools ▸ Verify Image and Case ▸ Verify All Evidence,
"carve" Start Carving. Words match in any order, against the command and
its menu path; commands whose name starts with what was typed come first.
A command that cannot run now is listed greyed, with why (its tooltip),
and does not run.
"""

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QDialog, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMenu, QVBoxLayout)

from trace_app.ui import icons

#: What a command's text loses for searching and showing: mnemonics,
#: trailing ellipses, a shortcut after a tab.
_NOISE = re.compile(r'&(?!&)|\.\.\.$|…$')


def clean(text):
    return _NOISE.sub('', (text or '').split('\t')[0]).strip()


def commands(menu_bar):
    """[(action, 'Tools ▸ Verify Image')] for every command in the menu
    bar's menus, in menu order: not separators, submenus themselves,
    hidden entries, or the checkable choices of a group (themes, sizes).

    Menus are found as the window's QMenu children and matched to their
    entries by menuAction(). QAction.menu() is not called: the QMenu
    wrapper PySide returns from it can take ownership, and deleted the
    whole menu -- every action in it -- once it was collected."""
    root = menu_bar.window() or menu_bar
    menus = {menu.menuAction(): menu for menu in root.findChildren(QMenu)}
    out = []

    def walk(menu, path):
        for action in menu.actions():
            if action.isSeparator() or not action.isVisible():
                continue
            child = menus.get(action)
            if child is not None:
                walk(child, path + [clean(action.text())])
                continue
            if action.isCheckable() and action.actionGroup() is not None:
                continue                # a radio choice: not a command
            if not clean(action.text()):
                continue
            out.append((action, ' ▸ '.join(path + [clean(action.text())])))

    for action in menu_bar.actions():
        menu = menus.get(action)
        if menu is not None and action.isVisible():
            walk(menu, [clean(action.text())])
    return out


def matches(query, found):
    """`found` filtered to `query` (words in any order, any case), the
    commands whose own name starts with the query first."""
    words = query.lower().split()
    if not words:
        return list(found)
    hits = []
    for action, path in found:
        haystack = path.lower()
        if all(word in haystack for word in words):
            name = clean(action.text()).lower()
            hits.append((0 if name.startswith(query.lower().strip()) else
                         1 if name.startswith(words[0]) else 2, path,
                         action))
    hits.sort(key=lambda h: (h[0], h[1].lower()))
    return [(action, path) for _rank, path, action in hits]


class CommandSearch(QDialog):
    """The search box and the commands that match it."""

    def __init__(self, menu_bar, parent=None):
        super().__init__(parent, Qt.Popup | Qt.FramelessWindowHint)
        self.setObjectName("commandSearch")
        self.setMinimumWidth(520)
        self._all = commands(menu_bar)
        self.ran = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)
        self.search = QLineEdit()
        self.search.setObjectName("commandSearchBox")
        self.search.setPlaceholderText("Find a command… (verify, carve, "
                                       "export, report)")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter)
        self.search.installEventFilter(self)
        layout.addWidget(self.search)
        self.results = QListWidget()
        self.results.setObjectName("commandSearchList")
        self.results.setUniformItemSizes(True)
        self.results.itemActivated.connect(self._run_item)
        layout.addWidget(self.results, 1)
        self.hint = QLabel("Enter runs it · Esc closes")
        self.hint.setObjectName("commandSearchHint")
        layout.addWidget(self.hint)
        self.resize(560, 420)
        self._filter('')

    def _filter(self, text):
        self.results.clear()
        for action, path in matches(text, self._all):
            shortcut = action.shortcut().toString(
                action.shortcut().SequenceFormat.NativeText)
            item = QListWidgetItem(
                action.icon() if not action.icon().isNull()
                else icons.icon(icons.RUN),
                path + (f"    {shortcut}" if shortcut else ''))
            item.setData(Qt.UserRole, action)
            if not action.isEnabled():
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
                item.setToolTip(action.toolTip() or "Not available now")
            self.results.addItem(item)
        for row in range(self.results.count()):
            if self.results.item(row).flags() & Qt.ItemIsEnabled:
                self.results.setCurrentRow(row)
                break

    def eventFilter(self, watched, event):
        # Up/Down/Enter in the box move and run in the list.
        if watched is self.search and event.type() == event.Type.KeyPress:
            key = event.key()
            if key in (Qt.Key_Down, Qt.Key_Up, Qt.Key_PageDown,
                       Qt.Key_PageUp):
                self.results.keyPressEvent(event)
                return True
            if key in (Qt.Key_Return, Qt.Key_Enter):
                self._run_item(self.results.currentItem())
                return True
        return super().eventFilter(watched, event)

    def _run_item(self, item):
        if item is None or not item.flags() & Qt.ItemIsEnabled:
            return
        action = item.data(Qt.UserRole)
        if not isinstance(action, QAction) or not action.isEnabled():
            return
        self.ran = action
        self.accept()
        action.trigger()


def find_command(window):
    """Show the search over `window`'s menus."""
    dialog = CommandSearch(window.menuBar(), window)
    centre = window.geometry().center()
    dialog.move(centre.x() - dialog.width() // 2,
                window.geometry().top() + 90)
    dialog.search.setFocus()
    dialog.exec()
    return dialog.ran

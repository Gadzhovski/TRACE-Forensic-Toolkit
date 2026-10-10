"""Tools ▸ Manage Tags: the case's tags -- add, rename, recolour, remove.

Every change goes through the case (core/case.py), which audits it. Removing
a tag takes it off every file that carries it, so the dialog asks first and
says how many.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QColorDialog, QDialog, QDialogButtonBox,
                               QHBoxLayout, QInputDialog, QLabel, QListWidget,
                               QListWidgetItem, QPushButton, QVBoxLayout)

from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.viewers.tags_panel import tag_icon

#: Colours a new tag is given in turn (the examiner can change it).
PALETTE = ('#2F81F7', '#3FB950', '#A371F7', '#DB61A2', '#F0883E',
           '#39C5CF', '#D29922', '#E5534B')


def next_colour(case):
    """A colour no tag uses yet, else the palette's next in turn."""
    used = {(t.get('colour') or '').upper() for t in case.tags()}
    for colour in PALETTE:
        if colour.upper() not in used:
            return colour
    return PALETTE[len(used) % len(PALETTE)]


def ask_new_tag(parent, case):
    """Ask for a name; returns the new tag's id, or None."""
    name, ok = QInputDialog.getText(parent, "New Tag", "Tag name:")
    if not ok or not name.strip():
        return None
    return case.add_tag(name.strip(), next_colour(case))


class ManageTagsDialog(QDialog):
    def __init__(self, case, parent=None):
        super().__init__(parent)
        self.case = case
        self.changed = False
        self.setWindowTitle("Manage Tags")
        self.setObjectName("manageTagsDialog")
        self.resize(420, 360)

        layout = QVBoxLayout(self)
        intro = QLabel("Tags are your own verdicts on files. The first three "
                       "are on the keys 1, 2 and 3 in any list; 0 clears.")
        intro.setWordWrap(True)
        intro.setObjectName("dialogIntro")
        layout.addWidget(intro)

        body = QHBoxLayout()
        self.list = QListWidget()
        self.list.setObjectName("tagList")
        self.list.itemDoubleClicked.connect(lambda _item: self.rename())
        self.list.currentRowChanged.connect(self._enable)
        body.addWidget(self.list, 1)
        buttons = QVBoxLayout()
        self.new_button = self._button(buttons, "New…", icons.TAG, self.new)
        self.rename_button = self._button(buttons, "Rename…", icons.EDIT,
                                          self.rename)
        self.colour_button = self._button(buttons, "Colour…", icons.TAG,
                                          self.recolour)
        self.remove_button = self._button(buttons, "Remove", icons.DELETE,
                                          self.remove)
        buttons.addStretch(1)
        body.addLayout(buttons)
        layout.addLayout(body, 1)

        close = QDialogButtonBox(QDialogButtonBox.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        self.refresh()

    def _button(self, layout, text, icon, slot):
        button = QPushButton(text)
        icons.apply_to(button, icon)
        button.clicked.connect(slot)
        layout.addWidget(button)
        return button

    def refresh(self, select=None):
        current = select if select is not None else self.current_id()
        self.list.clear()
        for number, tag in enumerate(self.case.tags(), start=1):
            key = f"   [{number}]" if number <= 3 else ''
            item = QListWidgetItem(tag_icon(tag['colour']),
                                   f"{tag['name']}  ({tag['files']:,} "
                                   f"file(s)){key}")
            item.setData(Qt.UserRole, tag)
            self.list.addItem(item)
            if tag['id'] == current:
                self.list.setCurrentItem(item)
        if self.list.currentRow() < 0 and self.list.count():
            self.list.setCurrentRow(0)
        self._enable()

    def current(self):
        item = self.list.currentItem()
        return item.data(Qt.UserRole) if item else None

    def current_id(self):
        tag = self.current()
        return tag['id'] if tag else None

    def _enable(self, *_args):
        chosen = self.current() is not None
        for button in (self.rename_button, self.colour_button,
                       self.remove_button):
            button.setEnabled(chosen)

    def new(self):
        tag_id = ask_new_tag(self, self.case)
        if tag_id is not None:
            self.changed = True
            self.refresh(tag_id)

    def rename(self):
        tag = self.current()
        if tag is None:
            return
        name, ok = QInputDialog.getText(self, "Rename Tag", "Tag name:",
                                        text=tag['name'])
        if ok and name.strip() and name.strip() != tag['name']:
            if any(t['name'] == name.strip() and t['id'] != tag['id']
                   for t in self.case.tags()):
                message.warning(self, "Rename Tag",
                                f"There is already a tag called "
                                f"{name.strip()!r}.")
                return
            self.case.update_tag(tag['id'], name=name.strip())
            self.changed = True
            self.refresh(tag['id'])

    def recolour(self):
        tag = self.current()
        if tag is None:
            return
        colour = QColorDialog.getColor(QColor(tag['colour'] or '#8B949E'),
                                       self, "Tag Colour")
        if colour.isValid():
            self.case.update_tag(tag['id'], colour=colour.name().upper())
            self.changed = True
            self.refresh(tag['id'])

    def remove(self):
        tag = self.current()
        if tag is None:
            return
        detail = (f"It is on {tag['files']:,} file(s); they lose it."
                  if tag['files'] else "No file carries it.")
        if not message.question(self, "Remove Tag",
                                f"Remove the tag {tag['name']!r}?", detail):
            return
        self.case.remove_tag(tag['id'])
        self.changed = True
        self.refresh()

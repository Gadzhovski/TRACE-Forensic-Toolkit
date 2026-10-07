"""A dropdown that selects several items at once.

Qt has no multi-select combo box, so a row of check boxes is the usual
workaround. That does not scale: the file-carving toolbar carried ten of them
plus Start and Stop, which left the bar crowded and the controls squeezed.

This is the same idea in one control -- a button showing a summary of what is
selected, with the check boxes moved into its menu, where they have room and
can be grouped. With categories (file carving has nearly sixty types) each
category is a submenu with an "All" toggle, and its title counts what is
chosen in it. Ticking an item leaves the menu open: choosing six types should
not mean opening it six times.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QToolButton


class _StayOpenMenu(QMenu):
    """A menu that does not close when a check box in it is toggled."""

    def mouseReleaseEvent(self, event):
        action = self.activeAction()
        if action is not None and action.isEnabled() and \
                (action.isCheckable() or action.property('keepOpen')):
            action.trigger()
            return
        super().mouseReleaseEvent(event)


class MultiSelectButton(QToolButton):
    """A button whose menu holds a checkable item per option.

    The label summarises the selection ("All types", "3 types", "PDF"), so the
    control stays a fixed width regardless of how many options exist.
    `categories`, a {name: [option, ...]} mapping, groups the options into
    submenus; options outside every category stay at the top level.
    """

    #: Emitted with the list of selected option names whenever it changes.
    selectionChanged = Signal(list)

    def __init__(self, options, parent=None, noun="types", categories=None):
        super().__init__(parent)
        self._noun = noun
        self._actions = {}
        self._category_menus = {}
        self._updating = False

        self.setObjectName("multiSelectButton")
        self.setPopupMode(QToolButton.InstantPopup)
        self.setToolButtonStyle(Qt.ToolButtonTextOnly)

        menu = _StayOpenMenu(self)
        menu.setObjectName("multiSelectMenu")

        select_all = QAction("Select all", self)
        select_all.setProperty('keepOpen', True)
        select_all.triggered.connect(lambda: self.set_selected(list(options)))
        menu.addAction(select_all)

        clear = QAction("Clear", self)
        clear.setProperty('keepOpen', True)
        clear.triggered.connect(lambda: self.set_selected([]))
        menu.addAction(clear)
        menu.addSeparator()

        grouped = set()
        for name, members in (categories or {}).items():
            members = [m for m in members if m in options]
            if not members:
                continue
            grouped.update(members)
            submenu = _StayOpenMenu(name, menu)
            submenu.setObjectName("multiSelectMenu")
            every = QAction(f"All {name.lower()}", self)
            every.setProperty('keepOpen', True)
            every.triggered.connect(
                lambda _=False, m=tuple(members): self._toggle_group(m))
            submenu.addAction(every)
            submenu.addSeparator()
            for option in members:
                submenu.addAction(self._make_action(option))
            menu.addMenu(submenu)
            self._category_menus[name] = (submenu, members)

        for option in options:
            if option not in grouped:
                menu.addAction(self._make_action(option))

        self.setMenu(menu)
        self._refresh_label()

    def _make_action(self, option):
        action = QAction(option, self)
        action.setCheckable(True)
        action.toggled.connect(self._on_toggled)
        self._actions[option] = action
        return action

    def _toggle_group(self, members):
        """Select every member of a category -- or, if all already are,
        none of them."""
        chosen = set(self.selected())
        if all(m in chosen for m in members):
            chosen.difference_update(members)
        else:
            chosen.update(members)
        self.set_selected([o for o in self._actions if o in chosen])

    # --- selection ---------------------------------------------------------

    def selected(self):
        """Names of the checked options, in the order they were declared."""
        return [name for name, action in self._actions.items() if action.isChecked()]

    def set_selected(self, names):
        """Check exactly `names`, emitting one change rather than several."""
        wanted = set(names)
        self._updating = True
        try:
            for name, action in self._actions.items():
                action.setChecked(name in wanted)
        finally:
            self._updating = False
        self._refresh_label()
        self.selectionChanged.emit(self.selected())

    def _on_toggled(self, _checked):
        if self._updating:
            return
        self._refresh_label()
        self.selectionChanged.emit(self.selected())

    # --- presentation ------------------------------------------------------

    def _refresh_label(self):
        chosen = self.selected()
        total = len(self._actions)

        if not chosen:
            text = f"No {self._noun}"
        elif len(chosen) == total:
            text = f"All {self._noun}"
        elif len(chosen) == 1:
            text = chosen[0]
        else:
            text = f"{len(chosen)} {self._noun}"

        self.setText(text)
        self.setToolTip("Selected: " + (", ".join(chosen) if chosen else "none"))

        picked = set(chosen)
        for name, (submenu, members) in self._category_menus.items():
            count = sum(1 for m in members if m in picked)
            submenu.setTitle(f"{name}  ({count}/{len(members)})")

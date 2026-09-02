"""A dropdown that selects several items at once.

Qt has no multi-select combo box, so a row of check boxes is the usual
workaround. That does not scale: the file-carving toolbar carried ten of them
plus Start and Stop, which left the bar crowded and the controls squeezed.

This is the same idea in one control -- a button showing a summary of what is
selected, with the check boxes moved into its menu, where they have room and
can be grouped.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QToolButton, QWidgetAction


class MultiSelectButton(QToolButton):
    """A button whose menu holds a checkable item per option.

    The label summarises the selection ("All types", "3 types", "PDF"), so the
    control stays a fixed width regardless of how many options exist.
    """

    #: Emitted with the list of selected option names whenever it changes.
    selectionChanged = Signal(list)

    def __init__(self, options, parent=None, noun="types"):
        super().__init__(parent)
        self._noun = noun
        self._actions = {}
        self._updating = False

        self.setObjectName("multiSelectButton")
        self.setPopupMode(QToolButton.InstantPopup)
        self.setToolButtonStyle(Qt.ToolButtonTextOnly)

        menu = QMenu(self)
        menu.setObjectName("multiSelectMenu")

        select_all = QAction("Select all", self)
        select_all.triggered.connect(lambda: self.set_selected(list(options)))
        menu.addAction(select_all)

        clear = QAction("Clear", self)
        clear.triggered.connect(lambda: self.set_selected([]))
        menu.addAction(clear)
        menu.addSeparator()

        for option in options:
            action = QAction(option, self)
            action.setCheckable(True)
            action.toggled.connect(self._on_toggled)
            menu.addAction(action)
            self._actions[option] = action

        self.setMenu(menu)
        self._refresh_label()

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

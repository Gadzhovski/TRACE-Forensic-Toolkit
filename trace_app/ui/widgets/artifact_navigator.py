"""The Artifacts tab beside the evidence tree: every kind of artifact the
case holds, in one list grouped by what it is about, with counts
(core/artifact_catalogue). A click opens the existing view on it --
Triage's sub-tab, Activity's category, a panel -- so a list is worked
down from here without hunting through tab rows.

An entry whose scan has not run, or stopped before the end, is listed
greyed ("not run" / "stopped"), with Run… on its menu; one whose scan ran
and found nothing is hidden unless "Show empty artifact types" is on; one
that cannot exist in this evidence (NTFS on a FAT card) is never shown."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QPalette
from PySide6.QtWidgets import (QComboBox, QLabel, QLineEdit, QMenu,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from trace_app.core import artifact_catalogue as catalogue
from trace_app.ui import icons
from trace_app.ui.widgets.tree_branch import BranchTreeWidget

#: Where the examiner's choices are kept (config.ini).
SECTION = 'Artifacts'
#: Item data roles: what an item is ('overview', 'section', 'entry',
#: 'run') and its key -- strings, never dicts (PySide copies a dict set as
#: item data into a Qt map, deeply, on every read).
KIND_ROLE, KEY_ROLE = Qt.UserRole, Qt.UserRole + 1
#: Sections open the first time: the ones an examiner reads first.
OPEN_AT_FIRST = ('communication', 'web', 'media', 'files', 'flags')
_STATE_TEXT = {catalogue.NOT_RUN: "not run", catalogue.STOPPED: "stopped",
               catalogue.RUNNING: "running…"}


def entry_icon(entry):
    """The icon an entry is drawn with: an Activity category's, or a
    named one from the icon registry."""
    if entry.icon.startswith('activity:'):
        return icons.icon(icons.ACTIVITY_CATEGORIES[entry.icon.split(':')[1]])
    return icons.icon(getattr(icons, entry.icon))


class ArtifactNavigator(QWidget):
    """Signals carry keys: `open_requested(key, evidence id or None)` for
    an entry ('overview' for the Case Overview), `run_requested(keys,
    evidence id)` for the scans of entries not run, `module_run_requested
    (run key)` for an external tool's run."""

    open_requested = Signal(str, object)
    run_requested = Signal(list, object)
    module_run_requested = Signal(object)
    #: The evidence filter changed: the host counts again for it.
    evidence_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("artifactNavigator")
        self._found, self._states, self._runs = {}, {}, []
        self._expanded = set(OPEN_AT_FIRST)
        self._first = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        self.evidence = QComboBox()
        self.evidence.setObjectName("artifactEvidence")
        self.evidence.addItem("All evidence", None)
        self.evidence.currentIndexChanged.connect(
            lambda _index: self.evidence_changed.emit(self.evidence_id))
        layout.addWidget(self.evidence)
        self.find = QLineEdit()
        self.find.setObjectName("artifactFind")
        self.find.setPlaceholderText("Find an artifact type…")
        self.find.setClearButtonEnabled(True)
        self.find.textChanged.connect(self._apply_find)
        layout.addWidget(self.find)
        self.tree = BranchTreeWidget()
        self.tree.setObjectName("artifactTree")
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(2)
        self.tree.setIndentation(14)
        self.tree.setUniformRowHeights(True)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, header.ResizeMode.Stretch)
        header.setSectionResizeMode(1, header.ResizeMode.ResizeToContents)
        self.tree.itemClicked.connect(self._clicked)
        self.tree.itemActivated.connect(self._clicked)
        self.tree.itemExpanded.connect(self._remember_open)
        self.tree.itemCollapsed.connect(self._remember_open)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.tree, 1)
        self.hint = QLabel()
        self.hint.setObjectName("artifactHint")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)
        from trace_app.infra.window_state import read_value
        self.show_empty = read_value(SECTION, 'show_empty', '0') == '1'

    # --- what is shown -----------------------------------------------------

    @property
    def evidence_id(self):
        return self.evidence.currentData()

    def set_evidence(self, rows):
        """The case's evidence for the filter: [(id, name)]."""
        current = self.evidence_id
        self.evidence.blockSignals(True)
        self.evidence.clear()
        self.evidence.addItem("All evidence", None)
        for evidence_id, name in rows:
            self.evidence.addItem(name, evidence_id)
        index = self.evidence.findData(current)
        self.evidence.setCurrentIndex(index if index >= 0 else 0)
        self.evidence.blockSignals(False)

    def set_data(self, found, states, runs=()):
        """`found` {entry key: count}, `states` {entry key: state},
        `runs` [(run key, label, count, tool)] of external tools."""
        self._found, self._states, self._runs = found, states, list(runs)
        self._build()

    def set_show_empty(self, on):
        from trace_app.infra.window_state import save_value
        self.show_empty = bool(on)
        save_value(SECTION, 'show_empty', '1' if on else '0')
        self._build()

    def counts_text(self, key):
        """What the row of entry `key` says beside its name now ('' when
        it is not listed) -- for tests and the Overview's links."""
        item = self._item_for(key)
        return item.text(1) if item is not None else ''

    def _shown(self, entry):
        state = self._states.get(entry.key, catalogue.FOUND)
        if state == catalogue.NOT_APPLICABLE:
            return False
        if state == catalogue.NONE_FOUND:
            return self.show_empty
        return True

    def _build(self):
        current = self.tree.currentItem()
        current_key = current.data(0, KEY_ROLE) if current else 'overview'
        self.tree.clear()
        bold = QFont(self.tree.font())
        bold.setBold(True)
        overview = QTreeWidgetItem(self.tree, ["Case Overview", ""])
        overview.setIcon(0, icons.icon(icons.CASE))
        overview.setData(0, KIND_ROLE, 'overview')
        overview.setData(0, KEY_ROLE, 'overview')
        waiting = 0
        for key, title, members in catalogue.SECTIONS:
            shown = [e for e in members if self._shown(e)]
            if not shown:
                continue
            total = sum(self._found.get(e.key) or 0 for e in members)
            section = QTreeWidgetItem(self.tree, [title, f"{total:,}"
                                                  if total else ""])
            section.setFont(0, bold)
            section.setData(0, KIND_ROLE, 'section')
            section.setData(0, KEY_ROLE, key)
            section.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            for entry in shown:
                item = self._entry_item(section, entry)
                if self._states.get(entry.key) in (catalogue.NOT_RUN,
                                                   catalogue.STOPPED):
                    waiting += 1
                if entry.key == current_key:
                    self.tree.setCurrentItem(item)
            section.setExpanded(key in self._expanded)
        if self._runs:
            section = QTreeWidgetItem(self.tree, ["External tools", ""])
            section.setFont(0, bold)
            section.setData(0, KIND_ROLE, 'section')
            section.setData(0, KEY_ROLE, 'external')
            for run_key, label, count, tool in self._runs:
                item = QTreeWidgetItem(section, [label, f"{count:,}"
                                                 if count else ""])
                item.setIcon(0, icons.module_logo(tool))
                item.setData(0, KIND_ROLE, 'run')
                item.setData(0, KEY_ROLE, run_key)
                item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            section.setExpanded('external' in self._expanded)
        if current_key == 'overview' or self.tree.currentItem() is None:
            self.tree.setCurrentItem(overview)
        self.hint.setText(
            f"{waiting} greyed: their scans have not run, or stopped "
            "before the end — right-click ▸ Run." if waiting else
            "Types the scans found nothing of are hidden (right-click "
            "▸ Show Empty Types).")
        self._apply_find(self.find.text())

    def _entry_item(self, section, entry):
        count = self._found.get(entry.key)
        state = self._states.get(entry.key, catalogue.FOUND)
        text = f"{count:,}" if count else _STATE_TEXT.get(state, "")
        if count == 0 and state == catalogue.NONE_FOUND:
            text = "0"
        item = QTreeWidgetItem(section, [entry.label, text])
        item.setIcon(0, entry_icon(entry))
        item.setData(0, KIND_ROLE, 'entry')
        item.setData(0, KEY_ROLE, entry.key)
        item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        if state in _STATE_TEXT and not count:
            grey = self.palette().color(QPalette.PlaceholderText)
            italic = QFont(self.tree.font())
            italic.setItalic(True)
            for column in (0, 1):
                item.setForeground(column, grey)
            item.setFont(1, italic)
            item.setToolTip(0, {
                catalogue.NOT_RUN: "Its scan has not run on this evidence "
                                   "— right-click ▸ Run.",
                catalogue.STOPPED: "Its scan stopped before the end — "
                                   "right-click ▸ Run again.",
                catalogue.RUNNING: "Its scan is running."}[state])
        return item

    def _item_for(self, key):
        for index in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(index)
            if top.data(0, KEY_ROLE) == key:
                return top
            for child in range(top.childCount()):
                if top.child(child).data(0, KEY_ROLE) == key:
                    return top.child(child)
        return None

    def _apply_find(self, text):
        words = text.strip().lower()
        for index in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(index)
            if top.childCount() == 0:
                top.setHidden(bool(words) and words not in
                              top.text(0).lower())
                continue
            any_shown = False
            for child in range(top.childCount()):
                item = top.child(child)
                match = not words or words in item.text(0).lower() or \
                    words in top.text(0).lower()
                item.setHidden(not match)
                any_shown = any_shown or match
            top.setHidden(not any_shown)
            if words and any_shown:
                top.setExpanded(True)

    def _remember_open(self, item):
        if item.data(0, KIND_ROLE) != 'section':
            return
        key = item.data(0, KEY_ROLE)
        if item.isExpanded():
            self._expanded.add(key)
        else:
            self._expanded.discard(key)

    # --- what it does ------------------------------------------------------

    def _clicked(self, item, _column=0):
        kind, key = item.data(0, KIND_ROLE), item.data(0, KEY_ROLE)
        if kind in ('entry', 'overview'):
            self.open_requested.emit(key, self.evidence_id)
        elif kind == 'run':
            self.module_run_requested.emit(key)
        elif kind == 'section':
            item.setExpanded(not item.isExpanded())

    def select(self, key):
        """Mark entry `key` as the one shown (the host opened it another
        way)."""
        item = self._item_for(key)
        if item is not None:
            self.tree.setCurrentItem(item)

    def waiting(self):
        """Entry keys whose scan has not run or stopped."""
        return [e.key for e in catalogue.entries()
                if self._shown(e) and self._states.get(e.key) in
                (catalogue.NOT_RUN, catalogue.STOPPED)
                and not self._found.get(e.key)]

    def _menu(self, position):
        item = self.tree.itemAt(position)
        menu = QMenu(self)
        if item is not None and item.data(0, KIND_ROLE) in ('entry',
                                                            'overview'):
            key = item.data(0, KEY_ROLE)
            menu.addAction("Open").triggered.connect(
                lambda: self.open_requested.emit(key, self.evidence_id))
            if key in self.waiting():
                state = self._states.get(key)
                menu.addAction("Run Again" if state == catalogue.STOPPED
                               else "Run Its Scan").triggered.connect(
                    lambda: self.run_requested.emit([key],
                                                    self.evidence_id))
            menu.addSeparator()
        waiting = self.waiting()
        if waiting:
            menu.addAction(f"Run Every Scan Not Run ({len(waiting)} "
                           f"types)…").triggered.connect(
                lambda: self.run_requested.emit(waiting, self.evidence_id))
        empty = menu.addAction("Show Empty Types")
        empty.setCheckable(True)
        empty.setChecked(self.show_empty)
        empty.toggled.connect(self.set_show_empty)
        from trace_app.ui.widgets import context_menus
        context_menus.show_menu(menu, self.tree.viewport().mapToGlobal(
            position), view=False)

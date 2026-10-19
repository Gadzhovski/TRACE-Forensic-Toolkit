"""Triage ▸ Tags: the files the examiner tagged, under each tag.

A tag is the examiner's own verdict on a file (core/case.py: Relevant,
Needs review, Ignore, or one of their own). Files are tagged from any list
-- right-click ▸ Tag, or the keys 1, 2, 3 (0 clears) -- and gathered here,
grouped by tag, each naming its evidence, path, who tagged it and when.
Landing on a file previews it; double-click goes to its folder.

Project VIC categories (core/vics.CATEGORIES) are listed above the tags,
most serious first: right-click ▸ Project VIC Category, or Alt+0..4
(Alt+5 = Uncategorized). One per file; the VICS export writes them.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QMenu, QPushButton, QTreeWidgetItem, QVBoxLayout, QWidget)

from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.tree_branch import BranchTreeWidget

COLUMNS = ('File', 'Evidence', 'Tagged', 'By', 'Path')


def tag_icon(colour):
    """A filled dot in the tag's colour, drawn as a shape (icons.dot_icon)
    so it is sharp at any display scale."""
    return icons.dot_icon(colour or '#8B949E')


class TagsPanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    #: Tagged files, for the sub-tab's label.
    count_changed = Signal(int)
    #: Manage Tags… was asked for (the window owns the dialog).
    manage_requested = Signal()
    #: Delete on selected files: take off the mark each was listed under
    #: (rows carry 'tag_id' or 'vic_category').
    remove_requested = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("tagsPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setWordWrap(True)
        bar.addWidget(self.status_label, 1)
        manage = QPushButton("Manage Tags…")
        manage.setObjectName("tagsManage")
        icons.apply_to(manage, icons.TAG)
        manage.clicked.connect(self.manage_requested)
        bar.addWidget(manage)
        layout.addLayout(bar)

        self.tree = BranchTreeWidget()
        self.tree.setObjectName("triageTable")
        self.tree.setColumnCount(len(COLUMNS))
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setItemDelegate(NoFocusDelegate(self.tree))
        self.tree.setUniformRowHeights(True)
        # No column of expand arrows and no indent: the tags are always
        # open, and both left a white strip -- left of every tag's dot, and
        # beside a selected file (the theme's item rule paints over the
        # branch area). A tag's row is bold instead, its files under it.
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((260, 140, 150, 110)):
            self.tree.setColumnWidth(column, width)
        self.tree.currentItemChanged.connect(self._landed)
        self.tree.itemDoubleClicked.connect(self._activated)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.installEventFilter(self)
        layout.addWidget(self.tree, 1)
        self.refresh()

    def eventFilter(self, watched, event):
        from PySide6.QtCore import QEvent
        if watched is self.tree and event.type() == QEvent.KeyPress and \
                event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            rows = self.selected_rows()
            if rows:
                self.remove_requested.emit(rows)
                return True
        return super().eventFilter(watched, event)

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id != self.evidence_id:
            self.evidence_id = evidence_id
            self.refresh()

    def refresh(self):
        self.tree.clear()
        if self.case is None:
            self.status_label.setText("Tags are kept in a case.")
            self.count_changed.emit(0)
            return
        categorised = self._add_vic_groups()
        rows = self.case.tagged(evidence_id=self.evidence_id)
        groups = {}
        for tag in self.case.tags():
            head = QTreeWidgetItem([f"{tag['name']}", '', '', '', ''])
            head.setIcon(0, tag_icon(tag['colour']))
            head.setFirstColumnSpanned(True)
            head.setData(0, Qt.UserRole + 1, tag['id'])
            groups[tag['id']] = head
        for row in rows:
            head = groups.get(row['tag_id'])
            if head is None:
                continue
            item = QTreeWidgetItem([
                row.get('name') or row['artifact_ref'],
                self._names.get(row.get('evidence_id'), ''),
                (row.get('tagged_utc') or '').replace('T', ' ')[:19],
                row.get('examiner') or '', row.get('path') or ''])
            item.setData(0, Qt.UserRole, {
                'evidence_id': row.get('evidence_id'),
                'artifact_ref': row['artifact_ref'],
                'name': row.get('name') or '', 'path': row.get('path') or '',
                'tag_id': row['tag_id']})
            item.setToolTip(4, row.get('path') or '')
            head.addChild(item)
        for head in groups.values():
            count = head.childCount()
            if not count:
                continue
            head.setText(0, f"{head.text(0)} ({count:,})")
            font = head.font(0)
            font.setBold(True)
            head.setFont(0, font)
            self.tree.addTopLevelItem(head)
            head.setExpanded(True)
        # Files, not marks: a file with two tags is one file.
        tagged = {(row.get('evidence_id'), row['artifact_ref'])
                  for row in rows if row['tag_id'] in groups}
        shown = len(tagged)
        parts = []
        if shown:
            parts.append(f"{shown:,} tagged file(s)")
        if categorised:
            parts.append(f"{len(categorised):,} with a Project VIC category")
        self.status_label.setText(
            ', '.join(parts) if parts else
            "No file is tagged yet: right-click a file ▸ Tag, or select "
            "files and press 1, 2 or 3 (0 clears). Project VIC categories "
            "(pictures and videos): right-click ▸ Project VIC Category, or "
            "Alt+0 to Alt+4 (Alt+5 clears). Delete here takes a mark off.")
        self.count_changed.emit(len(tagged | categorised))

    def _add_vic_groups(self):
        """A group per Project VIC category the examiner gave (most
        serious first), above the tags. Returns the files in them."""
        from trace_app.core import vics
        rows = self.case.vic_categories(evidence_id=self.evidence_id)
        heads = {}
        for row in rows:
            category = row['category']
            head = heads.get(category)
            if head is None:
                head = QTreeWidgetItem([
                    f"Project VIC {vics.category_label(category)}",
                    '', '', '', ''])
                head.setIcon(0, icons.dot_icon(
                    vics.CATEGORY_COLOURS.get(category, '#8B949E')))
                head.setFirstColumnSpanned(True)
                heads[category] = head
            item = QTreeWidgetItem([
                row.get('name') or row['artifact_ref'],
                self._names.get(row.get('evidence_id'), ''),
                (row.get('categorised_utc') or '').replace('T', ' ')[:19],
                row.get('examiner') or '', row.get('path') or ''])
            item.setData(0, Qt.UserRole, {
                'evidence_id': row.get('evidence_id'),
                'artifact_ref': row['artifact_ref'],
                'name': row.get('name') or '', 'path': row.get('path') or '',
                'vic_category': category})
            item.setToolTip(4, row.get('path') or '')
            head.addChild(item)
        for category in sorted(heads, key=vics.SEVERITY.index):
            head = heads[category]
            head.setText(0, f"{head.text(0)} ({head.childCount():,})")
            font = head.font(0)
            font.setBold(True)
            head.setFont(0, font)
            self.tree.addTopLevelItem(head)
            head.setExpanded(True)
        return {(row.get('evidence_id'), row['artifact_ref'])
                for row in rows}

    # --- rows ------------------------------------------------------------------

    def selected_rows(self):
        return [item.data(0, Qt.UserRole) for item in
                self.tree.selectedItems() if item.data(0, Qt.UserRole)]

    def _landed(self, current, _previous):
        data = current.data(0, Qt.UserRole) if current else None
        if data:
            self.file_selected.emit(data)

    def _activated(self, item, _column):
        data = item.data(0, Qt.UserRole)
        if data:
            self.file_activated.emit(data)

    def _menu(self, point):
        item = self.tree.itemAt(point)
        data = item.data(0, Qt.UserRole) if item else None
        if data:
            self.file_menu_requested.emit(
                data, self.tree.viewport().mapToGlobal(point))
            return
        menu = QMenu(self)
        menu.addAction("Manage Tags…").triggered.connect(
            self.manage_requested)
        from trace_app.ui.widgets.context_menus import show_menu
        show_menu(menu, self.tree.viewport().mapToGlobal(point), False)

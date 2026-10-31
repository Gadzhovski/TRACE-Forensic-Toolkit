"""Options > Supported Features: what this installation can do.

One row per feature: available or not, the component providing it and its
version, and -- when it is missing -- why, and what to do. A feature
unavailable here (YARA on Windows on ARM, say) is greyed out where it would
be used, with the same reason as its tooltip.
"""

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QDialogButtonBox,
                               QHeaderView, QTreeWidgetItem)

from trace_app.infra import capabilities
from trace_app.ui import icons
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.dialog_page import PageDialog, badge
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.tree_branch import BranchTreeWidget


class SupportedFeaturesDialog(PageDialog):
    def __init__(self, parent=None):
        missing = [c for c in capabilities.CAPABILITIES if not c.available]
        available = len(capabilities.CAPABILITIES) - len(missing)
        super().__init__(
            "Supported Features",
            "What this installation of TRACE can do, the library providing "
            "each feature and its version." + (
                " The unavailable ones are greyed out where they would be "
                "used." if missing else
                " Everything TRACE can do works here."),
            icon=icons.VERIFY_OK, parent=parent, scroll=False,
            object_name="supportedFeaturesDialog")
        self.setMinimumSize(900, 600)
        self.header_tail.addWidget(badge(
            f"{available} of {len(capabilities.CAPABILITIES)} available",
            'warn' if missing else 'ok'), 0, Qt.AlignTop)
        self.set_footer_hint(' · '.join(
            f"{label} {value}" for label, value
            in capabilities.system_summary()))
        layout = self.body
        layout.setContentsMargins(24, 8, 24, 16)

        self.tree = BranchTreeWidget()
        self.tree.setObjectName("supportedFeatures")
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(['Feature', 'Status', 'Provided by',
                                   'Version'])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.NoSelection)
        self.tree.setItemDelegate(NoFocusDelegate(self.tree))
        self.tree.setWordWrap(True)
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column, width in ((1, 140), (2, 160), (3, 84)):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            self.tree.setColumnWidth(column, width)
        #: External tools' rows, to say when a newer release is out.
        self._tool_items = {}
        for group in capabilities.GROUPS:
            parent = QTreeWidgetItem([group])
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            parent.setFirstColumnSpanned(True)
            self.tree.addTopLevelItem(parent)
            for capability in capabilities.CAPABILITIES:
                if capability.group != group:
                    continue
                ok = capability.available
                # A tool the examiner installs is not missing until then,
                # just not installed: said so, not in the colour of a fault.
                on_request = capability.key in capabilities.ON_REQUEST
                item = QTreeWidgetItem(parent, [
                    capability.feature,
                    "Available" if ok else
                    "Not installed" if on_request else "Unavailable",
                    capability.component, capability.version])
                item.setToolTip(0, capability.feature)
                if on_request:
                    item.setIcon(0, icons.module_logo(capability.key))
                    self._tool_items[capability.key] = item
                item.setIcon(1, icons.icon(
                    icons.VERIFY_OK if ok else
                    icons.MODULES if on_request else icons.FINDINGS))
                item.setForeground(1, verdict_brush(
                    'clean' if ok else 'unknown' if on_request
                    else 'malicious'))
                if not ok:
                    item.setToolTip(0, capability.reason())
                    note = QTreeWidgetItem(item, [capability.reason()])
                    note.setFirstColumnSpanned(True)
                    note.setForeground(0, verdict_brush('unknown'))
                    item.setExpanded(True)
            parent.setExpanded(True)
        self.tree.setRootIsDecorated(bool(missing))
        layout.addWidget(self.tree, 1)

        buttons = QDialogButtonBox()
        copy = buttons.addButton("Copy Report", QDialogButtonBox.ActionRole)
        copy.setToolTip("The whole list as text, for a bug report")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(
            capabilities.report_text()))
        close = buttons.addButton(QDialogButtonBox.Close)
        close.clicked.connect(self.accept)
        self.add_button(buttons)
        self._check_tool_updates()

    # --- newer releases of the installed tools (core/modules/updates) ----

    def _check_tool_updates(self):
        from trace_app.ui.widgets.kept_threads import KeptThreads
        from trace_app.ui.widgets.module_updates import ReleaseCheck
        self._checks = KeptThreads(self)
        check = ReleaseCheck(parent=self)
        check.checked.connect(self._tool_updates)
        self._checks[0] = check
        check.start()

    @Slot(int, object)
    def _tool_updates(self, _generation, result):
        from trace_app.core.modules import updates
        from trace_app.core.modules.spec import TOOLS
        for tool_id, old, new in updates.pending(result):
            item = self._tool_items.get(tool_id)
            if item is None:
                continue
            item.setText(1, "Update available")
            item.setIcon(1, icons.icon(icons.MODULES))
            item.setForeground(1, verdict_brush('unknown'))
            text = (f"{TOOLS[tool_id].name} {new} is published (this "
                    f"computer has {old}): Tools ▸ External Modules "
                    f"downloads it.")
            item.setToolTip(1, text)
            note = QTreeWidgetItem(item, [text])
            note.setFirstColumnSpanned(True)
            note.setForeground(0, verdict_brush('unknown'))
            item.setExpanded(True)
            self.tree.setRootIsDecorated(True)

    def done(self, result):
        # The check holds no evidence: waited for, never left running
        # without a reference (Qt aborts).
        self._checks.clear(timeout=35000)
        super().done(result)

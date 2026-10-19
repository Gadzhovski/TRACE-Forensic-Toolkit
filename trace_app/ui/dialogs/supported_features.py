"""Options > Supported Features: what this installation can do.

One row per feature: available or not, the component providing it and its
version, and -- when it is missing -- why, and what to do. A feature
unavailable here (YARA on Windows on ARM, say) is greyed out where it would
be used, with the same reason as its tooltip.
"""

from PySide6.QtCore import Qt
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
        for column, width in ((1, 112), (2, 160), (3, 84)):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            self.tree.setColumnWidth(column, width)
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

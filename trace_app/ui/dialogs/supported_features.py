"""Options > Supported Features: what this installation can do.

One row per feature: available or not, the component providing it and its
version, and -- when it is missing -- why, and what to do. A feature
unavailable here (YARA on Windows on ARM, say) is greyed out where it would
be used, with the same reason as its tooltip.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox,
                               QHeaderView, QLabel, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout)

from trace_app.infra import capabilities
from trace_app.ui import icons
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate


class SupportedFeaturesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Supported Features")
        self.setObjectName("supportedFeaturesDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumSize(900, 600)
        layout = QVBoxLayout(self)

        summary = ' · '.join(f"{label} {value}" for label, value
                             in capabilities.system_summary())
        missing = [c for c in capabilities.CAPABILITIES if not c.available]
        heading = QLabel(
            f"<b>{len(capabilities.CAPABILITIES) - len(missing)} of "
            f"{len(capabilities.CAPABILITIES)} features are available on "
            f"this system.</b>" + (
                " The unavailable ones are greyed out where they would be "
                "used." if missing else
                " Everything TRACE can do works here.")
            + f"<br><span>{summary}</span>")
        heading.setObjectName("analysisModulesIntro")
        heading.setTextFormat(Qt.RichText)
        heading.setWordWrap(True)
        layout.addWidget(heading)

        self.tree = QTreeWidget()
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
                item = QTreeWidgetItem(parent, [
                    capability.feature,
                    "Available" if ok else "Unavailable",
                    capability.component, capability.version])
                item.setToolTip(0, capability.feature)
                item.setIcon(1, icons.icon(icons.VERIFY_OK if ok
                                           else icons.FINDINGS))
                item.setForeground(1, verdict_brush('clean' if ok
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
        layout.addWidget(buttons)

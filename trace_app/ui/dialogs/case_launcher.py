"""The chooser shown before the main window: new case, open case, or triage.

Not every use of a forensic tool is a case. Someone handed a USB stick who
wants to know what is on it should not have to name an investigation and pick a
folder first. So the launcher offers three doors, and quick triage leads to
exactly the application TRACE was before cases existed.

Follows AboutDialog: a real QDialog subclass with an objectName so the theme
files can style it. No inline setStyleSheet -- styling lives in styles/*.qss.
"""

import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFormLayout,
                               QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QPushButton,
                               QTextEdit, QVBoxLayout)

from trace_app import __version__
from trace_app.core.case import Case, CaseError, is_case_folder
from trace_app.infra.constants import (BUTTON_WIDTH_WIDE, CONTROL_HEIGHT,
                                       INPUT_FIELD_MIN_WIDTH)
from trace_app.infra.paths import read_recent_cases, remember_case
from trace_app.ui import icons
from trace_app.ui.dialogs import message

logger = logging.getLogger('TRACE.CaseLauncher')

#: What the launcher returns for "just let me look at an image".
TRIAGE = 'triage'


class NewCaseDialog(QDialog):
    """Collect the details of a new case, and the folder to put it in."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Case")
        self.setObjectName("newCaseDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.case = None

        layout = QFormLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        self.name_input = QLineEdit()
        self.name_input.setMinimumWidth(INPUT_FIELD_MIN_WIDTH)
        self.name_input.setPlaceholderText("Operation Nightingale")
        layout.addRow("Case name:", self.name_input)

        self.number_input = QLineEdit()
        self.number_input.setPlaceholderText("2026-014")
        layout.addRow("Case number:", self.number_input)

        self.examiner_input = QLineEdit()
        self.examiner_input.setPlaceholderText("Your name")
        layout.addRow("Examiner:", self.examiner_input)

        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText(
            "What this case concerns, where the evidence came from, anything "
            "the next person reading it will need to know.")
        self.description_input.setFixedHeight(80)
        layout.addRow("Description:", self.description_input)

        # Folder row: a read-only field plus a browse button, so the chosen
        # path is visible before the case is created rather than after.
        folder_row = QHBoxLayout()
        self.folder_input = QLineEdit()
        self.folder_input.setReadOnly(True)
        self.folder_input.setPlaceholderText("Choose where to keep this case")
        browse = QPushButton("Browse...")
        browse.setFixedHeight(CONTROL_HEIGHT)
        browse.clicked.connect(self._choose_folder)
        folder_row.addWidget(self.folder_input)
        folder_row.addWidget(browse)
        layout.addRow("Case folder:", folder_row)

        hint = QLabel(
            "The case folder holds the case database, carved files and any "
            "reports. Evidence itself is never copied into it.")
        hint.setObjectName("caseFolderHint")
        hint.setWordWrap(True)
        layout.addRow("", hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Create Case")
        buttons.accepted.connect(self._create)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose a case folder")
        if folder:
            self.folder_input.setText(os.path.normpath(folder))

    def _create(self):
        name = self.name_input.text().strip()
        folder = self.folder_input.text().strip()

        if not name:
            message.warning(self, "Name the case",
                            "A case needs a name so it can be told apart from "
                            "the others in the recent list.")
            return
        if not folder:
            message.warning(self, "Choose a folder",
                            "Pick a folder for the case. Everything the case "
                            "produces is written there.")
            return

        # An empty folder is the usual choice, but a subfolder named after the
        # case is what most people mean when they pick their Cases directory.
        if is_case_folder(folder):
            message.warning(
                self, "That folder already holds a case",
                "Open it from the launcher instead, or choose another folder.")
            return

        try:
            self.case = Case.create(
                folder, name,
                self.number_input.text().strip(),
                self.examiner_input.text().strip(),
                self.description_input.toPlainText().strip())
        except CaseError as exc:
            message.critical(self, "Could not create the case", str(exc))
            return

        remember_case(folder, name)
        self.accept()


class CaseLauncher(QDialog):
    """New case, open an existing one, or skip cases entirely.

    `result_case` is the opened Case, the string TRIAGE, or None if the user
    closed the dialog -- in which case the application should not start.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("TRACE")
        self.setObjectName("caseLauncher")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.result_case = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(14)

        title = QLabel("TRACE")
        title.setObjectName("launcherTitle")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel(f"Toolkit for Retrieval and Analysis of Cyber "
                          f"Evidence   ·   {__version__}")
        subtitle.setObjectName("launcherSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        recent = read_recent_cases()
        if recent:
            heading = QLabel("Recent cases")
            heading.setObjectName("launcherHeading")
            layout.addWidget(heading)

            self.recent_list = QListWidget()
            self.recent_list.setObjectName("recentCaseList")
            for entry in recent:
                item = QListWidgetItem(f"{entry['name']}\n{entry['folder']}")
                item.setData(Qt.UserRole, entry['folder'])
                item.setIcon(icons.icon(icons.CASE))
                self.recent_list.addItem(item)
            self.recent_list.itemDoubleClicked.connect(self._open_recent)
            self.recent_list.setFixedHeight(140)
            layout.addWidget(self.recent_list)
        else:
            self.recent_list = None

        for label, handler, tip in (
            ("New Case", self._new_case,
             "Start an investigation: evidence, hashes, notes and findings "
             "kept together."),
            ("Open Case", self._open_case,
             "Reopen a case folder created earlier."),
            ("Quick Triage", self._triage,
             "Look inside an image without creating a case. Nothing is saved "
             "between sessions."),
        ):
            button = QPushButton(label)
            button.setObjectName("launcherButton")
            button.setToolTip(tip)
            button.setMinimumWidth(BUTTON_WIDTH_WIDE)
            button.setFixedHeight(CONTROL_HEIGHT + 10)
            button.clicked.connect(handler)
            layout.addWidget(button)

        layout.addStretch()
        self.setFixedWidth(460)

    # --- actions ----------------------------------------------------------

    def _new_case(self):
        dialog = NewCaseDialog(self)
        if dialog.exec() == QDialog.Accepted and dialog.case is not None:
            self.result_case = dialog.case
            self.accept()

    def _open_case(self):
        folder = QFileDialog.getExistingDirectory(self, "Open a case folder")
        if folder:
            self._load(os.path.normpath(folder))

    def _open_recent(self, item):
        self._load(item.data(Qt.UserRole))

    def _load(self, folder):
        if not is_case_folder(folder):
            message.warning(
                self, "Not a case folder",
                f"{folder} does not contain a case. Choose the folder that "
                f"holds case.db.")
            return
        try:
            case = Case.open(folder)
        except CaseError as exc:
            message.critical(self, "Could not open the case", str(exc))
            return

        remember_case(folder, case.name)
        self.result_case = case
        self.accept()

    def _triage(self):
        self.result_case = TRIAGE
        self.accept()


def choose_case(parent=None):
    """Run the launcher. Returns a Case, TRIAGE, or None if it was closed."""
    launcher = CaseLauncher(parent)
    launcher.exec()
    return launcher.result_case


class CasePropertiesDialog(QDialog):
    """View and edit an open case's details.

    The folder and creation date are shown but not editable: a case's identity
    is where it lives and when it was opened, and letting either be retyped
    would make the record describe something other than what happened.
    """

    def __init__(self, case, parent=None):
        super().__init__(parent)
        self.case = case
        self.setWindowTitle("Case Properties")
        self.setObjectName("casePropertiesDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))

        metadata = case.metadata

        layout = QFormLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        self.name_input = QLineEdit(metadata.get('name', ''))
        self.name_input.setMinimumWidth(INPUT_FIELD_MIN_WIDTH)
        layout.addRow("Case name:", self.name_input)

        self.number_input = QLineEdit(metadata.get('number', ''))
        layout.addRow("Case number:", self.number_input)

        self.examiner_input = QLineEdit(metadata.get('examiner', ''))
        layout.addRow("Examiner:", self.examiner_input)

        self.description_input = QTextEdit(metadata.get('description', ''))
        self.description_input.setFixedHeight(80)
        layout.addRow("Description:", self.description_input)

        for label, value in (("Case folder:", case.folder),
                             ("Created:", metadata.get('created_utc', '—')),
                             ("Evidence:", str(len(case.evidence())))):
            field = QLabel(value)
            field.setObjectName("casePropertyValue")
            field.setWordWrap(True)
            field.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addRow(label, field)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _save(self):
        name = self.name_input.text().strip()
        if not name:
            message.warning(self, "Name the case",
                            "A case needs a name so it can be told apart from "
                            "the others in the recent list.")
            return
        try:
            self.case.update_metadata(
                name=name,
                number=self.number_input.text().strip(),
                examiner=self.examiner_input.text().strip(),
                description=self.description_input.toPlainText().strip())
        except Exception as exc:
            message.critical(self, "Could not save", str(exc))
            return
        remember_case(self.case.folder, name)
        self.accept()

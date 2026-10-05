"""The welcome screen shown before the main window: new case, open case, or
triage.

Not every use of a forensic tool is a case. Someone handed a USB stick who
wants to know what is on it should not have to name an investigation and pick a
folder first. So the screen offers three doors -- New Case (the guided
wizard, ui/dialogs/case_wizard.py), Open Case, Quick Triage -- beside the
recent cases, each with its number, examiner, evidence count and when it was
last opened, read from the case without opening it.

A recent case whose folder is not there (a drive not plugged in) stays in
the list, greyed and marked, rather than vanishing: it is still the
examiner's case.

Follows AboutDialog: a real QDialog subclass with an objectName so the theme
files can style it. No inline setStyleSheet -- styling lives in styles/*.qss.
"""

import logging
import os

from PySide6.QtCore import QSize, Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QFrame, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from trace_app import __version__
from trace_app.core.case import (Case, CaseError, is_case_folder,
                                 read_case_summary)
from trace_app.infra.constants import INPUT_FIELD_MIN_WIDTH, TABLE_ROW_HEIGHT
from trace_app.infra.paths import (forget_case, read_recent_cases,
                                   remember_case)
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.CaseLauncher')

#: What the launcher returns for "just let me look at an image".
TRIAGE = 'triage'

#: A recent case whose folder is not there: a grey that reads as muted on
#: both themes (the palette's disabled colour is near-white on the dark one).
MISSING_GREY = QColor('#8A8F98')


class ActionTile(QPushButton):
    """A start-screen action: icon, title and a line saying what it does.

    QCommandLinkButton was the obvious widget, but under a style sheet it
    clipped its description and kept its own arrow for an icon.
    """

    def __init__(self, title, description, icon, parent=None):
        super().__init__(parent)
        self.setObjectName("launcherAction")
        self.setCursor(Qt.PointingHandCursor)
        self.setAccessibleName(title)
        self.setAccessibleDescription(description)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(10)
        glyph = QLabel()
        glyph.setObjectName("launcherActionIcon")
        glyph.setPixmap(icons.icon(icon).pixmap(QSize(20, 20)))
        glyph.setAlignment(Qt.AlignTop)
        layout.addWidget(glyph)
        words = QVBoxLayout()
        words.setSpacing(2)
        heading = QLabel(title)
        heading.setObjectName("launcherActionTitle")
        words.addWidget(heading)
        # One line, unwrapped: a wrapped label inside a button reports a
        # height the button then clips.
        text = QLabel(description)
        text.setObjectName("launcherActionText")
        words.addWidget(text)
        layout.addLayout(words, 1)
        for label in (glyph, heading, text):
            label.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._layout = layout

    # QPushButton sizes itself from its own text, of which it has none.
    def sizeHint(self):
        return self._layout.sizeHint()

    def minimumSizeHint(self):
        return self._layout.minimumSize()


def _when(iso):
    """'Today 14:05', 'Yesterday', '2 Oct 2026' from a stored UTC ISO time,
    shown in the examiner's local time (this is about when *they* last
    worked on it, not evidence)."""
    if not iso:
        return ''
    import datetime
    try:
        moment = datetime.datetime.fromisoformat(str(iso))
    except ValueError:
        return str(iso)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    local = moment.astimezone()
    today = datetime.datetime.now().astimezone().date()
    if local.date() == today:
        return f"Today {local:%H:%M}"
    if (today - local.date()).days == 1:
        return f"Yesterday {local:%H:%M}"
    return f"{local.day} {local:%b %Y}"


class CaseLauncher(QDialog):
    """New case, open an existing one, or skip cases entirely.

    `result_case` is the opened Case, the string TRIAGE, or None if the user
    closed the dialog -- in which case the application should not start.
    `setup` is the New Case wizard's {'verify', 'choice'} for a new case.
    """

    COLUMNS = ['Case', 'Number', 'Examiner', 'Evidence', 'Last opened']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"TRACE {__version__}")
        self.setObjectName("caseLauncher")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.result_case = None
        self.setup = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_side())
        layout.addWidget(self._build_recent(), 1)

        self.resize(980, 560)
        self.setMinimumSize(820, 480)
        self._fill()

    # --- building ---------------------------------------------------------------

    def _build_side(self):
        side = QFrame()
        side.setObjectName("launcherSide")
        side.setFixedWidth(330)
        layout = QVBoxLayout(side)
        layout.setContentsMargins(28, 28, 24, 20)
        layout.setSpacing(6)

        brand = QHBoxLayout()
        brand.setSpacing(12)
        logo = QLabel()
        logo.setObjectName("launcherLogo")
        logo.setPixmap(icons.icon(icons.LOGO).pixmap(48, 48))
        brand.addWidget(logo)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel("TRACE")
        title.setObjectName("launcherTitle")
        titles.addWidget(title)
        subtitle = QLabel("Toolkit for Retrieval and\nAnalysis of Cyber "
                          "Evidence")
        subtitle.setObjectName("launcherSubtitle")
        titles.addWidget(subtitle)
        brand.addLayout(titles, 1)
        layout.addLayout(brand)
        layout.addSpacing(18)

        self.action_buttons = {}
        for key, label, description, icon, handler in (
                ('new', "New Case", "Details, evidence and analysis",
                 icons.CASE_PROPERTIES, self._new_case),
                ('open', "Open Case…", "A case folder on disk",
                 icons.OPEN_FOLDER, self._open_case),
                ('triage', "Quick Triage", "Look inside an image; nothing "
                 "saved", icons.TRIAGE, self._triage)):
            button = ActionTile(label, description, icon)
            button.setToolTip({
                'new': "Start an investigation with the guided setup: case "
                       "details, the evidence, and what to analyse.",
                'open': "Reopen a case folder created earlier.",
                'triage': "Look inside an image without creating a case. "
                          "Nothing is saved between sessions."}[key])
            button.clicked.connect(handler)
            layout.addWidget(button)
            self.action_buttons[key] = button

        layout.addStretch(1)
        version = QLabel(f"Version {__version__}")
        version.setObjectName("launcherVersion")
        layout.addWidget(version)
        return side

    def _build_recent(self):
        panel = QWidget()
        panel.setObjectName("launcherRecent")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 28, 28, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        heading = QLabel("Recent cases")
        heading.setObjectName("launcherHeading")
        top.addWidget(heading)
        top.addStretch(1)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("launcherFilter")
        self.filter_input.setPlaceholderText("Filter by name, number, "
                                             "examiner…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setFixedWidth(250)
        self.filter_input.textChanged.connect(self._apply_filter)
        top.addWidget(self.filter_input)
        layout.addLayout(top)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setObjectName("recentCaseTable")
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT
                                                          + 4)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.itemDoubleClicked.connect(lambda _item: self._open_selected())
        self.table.itemSelectionChanged.connect(self._update_buttons)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column, width in ((1, 110), (2, 130), (3, 76), (4, 130)):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            self.table.setColumnWidth(column, width)
        layout.addWidget(self.table, 1)

        self.empty_label = QLabel(
            "No recent cases.\n\nStart one with New Case, or open a case "
            "folder from disk.")
        self.empty_label.setObjectName("launcherEmpty")
        self.empty_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.empty_label, 1)

        self.path_label = QLabel()
        self.path_label.setObjectName("launcherPath")
        self.path_label.setWordWrap(True)
        self.path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.path_label)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.remove_button = QPushButton("Remove from List")
        self.remove_button.setObjectName("recentCaseButton")
        self.remove_button.clicked.connect(self._forget_selected)
        buttons.addWidget(self.remove_button)
        self.open_button = QPushButton("Open")
        self.open_button.setObjectName("recentCaseButton")
        self.open_button.setDefault(True)
        self.open_button.clicked.connect(self._open_selected)
        buttons.addWidget(self.open_button)
        layout.addLayout(buttons)
        return panel

    # --- the list -----------------------------------------------------------------

    def _fill(self):
        self.entries = read_recent_cases(include_missing=True)
        self.table.setRowCount(0)
        for entry in self.entries:
            summary = None if entry['missing'] else \
                read_case_summary(entry['folder'])
            if not entry['missing'] and summary is None and \
                    not is_case_folder(entry['folder']):
                entry['missing'] = True     # the folder is there, the case not
            entry['summary'] = summary or {}
            row = self.table.rowCount()
            self.table.insertRow(row)
            name = entry['summary'].get('name') or entry['name']
            if entry['missing']:
                values = [name, '', '', '', 'Folder not found']
            else:
                values = [name, entry['summary'].get('number', ''),
                          entry['summary'].get('examiner', ''),
                          f"{entry['summary'].get('evidence', 0):,}",
                          _when(entry.get('opened'))]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.UserRole, entry['folder'])
                cell.setToolTip(entry['folder'] if not entry['missing'] else
                                f"Not found: {entry['folder']}")
                if column == 0:
                    cell.setIcon(icons.icon(icons.ALERT if entry['missing']
                                            else icons.CASE))
                if column == 3:
                    cell.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if entry['missing']:
                    # Greyed by colour, not disabled: a disabled row cannot
                    # be selected, and then cannot be removed from the list.
                    cell.setForeground(MISSING_GREY)
                self.table.setItem(row, column, cell)
        has = bool(self.entries)
        self.table.setVisible(has)
        self.filter_input.setEnabled(has)
        self.empty_label.setVisible(not has)
        if has:
            first = next((i for i, e in enumerate(self.entries)
                          if not e['missing']), None)
            if first is not None:
                self.table.selectRow(first)
        self._update_buttons()

    def _apply_filter(self, text):
        text = text.strip().lower()
        for row, entry in enumerate(self.entries):
            haystack = ' '.join([entry['name'], entry['folder']] + [
                str(v) for v in entry['summary'].values()]).lower()
            self.table.setRowHidden(row, bool(text) and text not in haystack)

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.entries[rows[0].row()]

    def _update_buttons(self):
        entry = self._selected()
        self.open_button.setEnabled(bool(entry) and not entry['missing'])
        self.remove_button.setEnabled(bool(entry))
        if entry is None:
            self.path_label.setText('')
        elif entry['missing']:
            self.path_label.setText(f"Folder not found: {entry['folder']} — "
                                    f"connect its drive, or remove it from "
                                    f"the list.")
        else:
            self.path_label.setText(entry['folder'])

    def _menu(self, position):
        entry = self._selected()
        if entry is None:
            return
        menu = QMenu(self)
        open_action = menu.addAction(icons.icon(icons.OPEN_FOLDER), "Open")
        open_action.setEnabled(not entry['missing'])
        show_action = menu.addAction(icons.icon(icons.CASE),
                                     "Show Case Folder")
        show_action.setEnabled(not entry['missing'])
        menu.addSeparator()
        forget_action = menu.addAction(icons.icon(icons.CLOSE),
                                       "Remove from List")
        chosen = menu.exec(self.table.viewport().mapToGlobal(position))
        if chosen is open_action:
            self._open_selected()
        elif chosen is show_action:
            QDesktopServices.openUrl(QUrl.fromLocalFile(entry['folder']))
        elif chosen is forget_action:
            self._forget_selected()

    def _forget_selected(self):
        entry = self._selected()
        if entry is None:
            return
        forget_case(entry['folder'])
        self._fill()

    # --- actions ----------------------------------------------------------

    def _new_case(self):
        from trace_app.ui.dialogs.case_wizard import new_case
        case, setup = new_case(self)
        if case is not None:
            self.result_case = case
            self.setup = setup
            self.accept()

    def _open_case(self):
        from trace_app.core import settings
        folder = QFileDialog.getExistingDirectory(
            self, "Open a case folder", settings.user('case_folder'))
        if folder:
            self._load(os.path.normpath(folder))

    def _open_selected(self):
        entry = self._selected()
        if entry is not None and not entry['missing']:
            self._load(entry['folder'])

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
    """Run the welcome screen: (Case | TRIAGE | None, setup or None). None
    means it was closed and the application should not start."""
    launcher = CaseLauncher(parent)
    launcher.exec()
    return launcher.result_case, launcher.setup


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

        self.organisation_input = QLineEdit(metadata.get('organisation', ''))
        layout.addRow("Organisation:", self.organisation_input)

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
                organisation=self.organisation_input.text().strip(),
                description=self.description_input.toPlainText().strip())
        except Exception as exc:
            message.critical(self, "Could not save", str(exc))
            return
        remember_case(self.case.folder, name)
        self.accept()

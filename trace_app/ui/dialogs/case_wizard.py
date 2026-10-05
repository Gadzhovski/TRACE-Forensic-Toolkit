"""New Case and Add Evidence: one guided flow, from details to a running case.

A case used to start as an empty window: the evidence had to be found under
File, and the analysis modules were never offered for it. The wizard takes
what a case needs in the order an examiner thinks of it --

  1. Details    who, what, where the case is kept
  2. Evidence   what goes in, each item opened and checked as it is added
  3. Modules    what to run over it, as a profile or one by one
  4. Review     everything once more, then Create Case

-- and nothing is written until Create: Cancel leaves no folder behind.
Add Evidence on an open case is pages 2 to 4.

The pages are plain widgets in a stack under a step bar, rather than a
QWizard: QWizard looks different on each platform (Aero, Mac, classic), and
a tool that has to look the same in a screenshot from any examiner's
machine is better served by one layout.
"""

import html
import logging
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QCompleter, QDialog, QFileDialog,
                               QFormLayout, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QPushButton,
                               QSizePolicy, QStackedWidget, QTextBrowser,
                               QVBoxLayout, QWidget)

from trace_app.core.case import (EVIDENCE_DETAILS, Case, case_folder_name,
                                 is_case_folder)
from trace_app.infra.paths import remember_case
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.dialogs.analysis_modules import (
    DESCRIPTIONS, MODULE_CARVE, ModuleSelector, PROFILE_LABELS,
    availability, remember_profile, remembered_profile, selected_keys)
from trace_app.ui.widgets.evidence_intake import EvidenceIntake

logger = logging.getLogger('TRACE.CaseWizard')

def default_case_folder():
    """Where new cases go unless the examiner has said: Settings, else
    Documents/TRACE Cases."""
    from trace_app.core import settings
    chosen = (settings.user('case_folder') or '').strip()
    if chosen:
        return os.path.normpath(chosen)
    home = os.path.expanduser('~')
    documents = os.path.join(home, 'Documents')
    return os.path.join(documents if os.path.isdir(documents) else home,
                        'TRACE Cases')


def _escape(text):
    return html.escape(str(text if text is not None else ''))


# --- the frame ------------------------------------------------------------------

class StepBar(QWidget):
    """'1 Details — 2 Evidence — 3 Modules — 4 Review', the current step
    marked, the ones behind ticked."""

    def __init__(self, titles, parent=None):
        super().__init__(parent)
        self.setObjectName("wizardStepBar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.labels = []
        for number, title in enumerate(titles, start=1):
            if number > 1:
                rule = QFrame()
                rule.setObjectName("wizardStepRule")
                rule.setFrameShape(QFrame.HLine)
                rule.setFixedWidth(28)
                layout.addWidget(rule)
            label = QLabel()
            label.setObjectName("wizardStep")
            label.setProperty('number', number)
            label.setProperty('title', title)
            layout.addWidget(label)
            self.labels.append(label)
        layout.addStretch(1)

    def set_current(self, index):
        for i, label in enumerate(self.labels):
            state = 'done' if i < index else 'current' if i == index \
                else 'todo'
            mark = '✓' if state == 'done' else str(label.property('number'))
            label.setText(f"{mark}  {label.property('title')}")
            label.setProperty('state', state)
            label.style().unpolish(label)
            label.style().polish(label)


class WizardPage(QWidget):
    """A page: its heading, whether Next may be pressed, and why not."""

    #: is_complete() may have changed.
    completeChanged = Signal()

    title = ''
    subtitle = ''

    def is_complete(self):
        return not self.problem()

    def problem(self):
        """Why the page cannot be left forwards yet, or ''."""
        return ''

    def enter(self):
        """The page is about to be shown."""


class SetupWizard(QDialog):
    """Pages under a step bar, with Back / Next / Finish and Cancel."""

    finish_text = "Finish"

    def __init__(self, pages, parent=None):
        super().__init__(parent)
        self.setObjectName("caseWizard")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setModal(True)
        self.pages = pages

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("wizardHeader")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 20, 12)
        header_layout.setSpacing(6)
        self.step_bar = StepBar([page.title for page in pages])
        header_layout.addWidget(self.step_bar)
        self.heading = QLabel()
        self.heading.setObjectName("wizardTitle")
        header_layout.addWidget(self.heading)
        self.subheading = QLabel()
        self.subheading.setObjectName("wizardSubtitle")
        self.subheading.setWordWrap(True)
        header_layout.addWidget(self.subheading)
        layout.addWidget(header)

        self.stack = QStackedWidget()
        self.stack.setObjectName("wizardBody")
        for page in pages:
            holder = QWidget()
            holder_layout = QVBoxLayout(holder)
            holder_layout.setContentsMargins(20, 14, 20, 8)
            holder_layout.addWidget(page)
            self.stack.addWidget(holder)
            page.completeChanged.connect(self._update_buttons)
        layout.addWidget(self.stack, 1)

        footer = QFrame()
        footer.setObjectName("wizardFooter")
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(20, 10, 12, 10)
        buttons.setSpacing(0)
        self.problem_label = QLabel()
        self.problem_label.setObjectName("wizardProblem")
        self.problem_label.setWordWrap(True)
        buttons.addWidget(self.problem_label, 1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("wizardButton")
        self.cancel_button.clicked.connect(self.reject)
        self.back_button = QPushButton("< Back")
        self.back_button.setObjectName("wizardButton")
        self.back_button.clicked.connect(self.back)
        self.next_button = QPushButton("Next >")
        self.next_button.setObjectName("wizardButton")
        self.next_button.setDefault(True)
        self.next_button.clicked.connect(self.next)
        # Back / Next, then Cancel: the order of the application's other
        # dialogs (OK, Cancel), with the step buttons where OK would be.
        for button in (self.back_button, self.next_button,
                       self.cancel_button):
            buttons.addWidget(button)
        layout.addWidget(footer)

        self._size_to_screen()
        self.go_to(0)

    def _size_to_screen(self):
        screen = self.screen().availableGeometry() if self.screen() else None
        width, height = 880, 640
        if screen is not None:
            width = min(width, int(screen.width() * 0.92))
            height = min(height, int(screen.height() * 0.9))
        self.resize(width, height)
        self.setMinimumSize(min(720, width), min(540, height))

    @property
    def index(self):
        return self.stack.currentIndex()

    def page(self):
        return self.pages[self.index]

    def go_to(self, index):
        index = max(0, min(index, len(self.pages) - 1))
        page = self.pages[index]
        page.enter()
        self.stack.setCurrentIndex(index)
        self.step_bar.set_current(index)
        self.heading.setText(page.title)
        self.subheading.setText(page.subtitle)
        self._update_buttons()

    def back(self):
        if self.index > 0:
            self.go_to(self.index - 1)

    def next(self):
        if not self.page().is_complete():
            return
        if self.index == len(self.pages) - 1:
            self.finish()
        else:
            self.go_to(self.index + 1)

    def finish(self):
        self.accept()

    def _update_buttons(self):
        last = self.index == len(self.pages) - 1
        self.back_button.setEnabled(self.index > 0)
        self.next_button.setText(self.finish_text if last else "Next >")
        problem = self.page().problem()
        self.next_button.setEnabled(not problem)
        self.problem_label.setText(problem)

    def has_input(self):
        """Is there anything a Cancel would throw away?"""
        return False

    def reject(self):
        if self.has_input() and not message.question(
                self, "Discard?",
                "Close the wizard? What was entered here is discarded; "
                "nothing has been written yet."):
            return
        self.stop()
        super().reject()

    def stop(self):
        for page in self.pages:
            if isinstance(page, EvidencePage):
                page.intake.stop()

    def accept(self):
        self.stop()
        super().accept()


# --- the pages --------------------------------------------------------------------

class DetailsPage(WizardPage):
    title = "Case details"
    subtitle = ("Who is examining what, and where the case is kept. The case "
                "folder holds the case database, findings, carved files and "
                "reports — evidence itself is never copied into it.")

    def __init__(self, parent=None):
        super().__init__(parent)
        from trace_app.core import settings
        self._touched = set()
        self._errors = {}

        # The form sits at the top with the spare height below it; without
        # the stretch the form shares that height out between its rows.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        layout = QFormLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(14)
        layout.setVerticalSpacing(10)
        layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        outer.addLayout(layout)
        outer.addStretch(1)

        def field(key, label, placeholder, value=''):
            edit = QLineEdit(value)
            edit.setObjectName("wizardField")
            edit.setPlaceholderText(placeholder)
            edit.textChanged.connect(lambda _t, key=key: self._edited(key))
            error = QLabel()
            error.setObjectName("wizardFieldError")
            error.setVisible(False)
            box = QVBoxLayout()
            box.setSpacing(2)
            box.addWidget(edit)
            box.addWidget(error)
            layout.addRow(label, box)
            self._errors[key] = error
            return edit

        self.name_input = field('name', "Case name *",
                                "e.g. Operation Nightingale")
        self.number_input = field('number', "Case number", "e.g. 2026-014")
        self.examiner_input = field('examiner', "Examiner *", "Your name",
                                    settings.user('examiner') or '')
        self.organisation_input = field(
            'organisation', "Organisation", "Agency, firm or department",
            settings.user('organisation') or '')

        self.description_input = QPlainTextEdit()
        self.description_input.setObjectName("wizardField")
        self.description_input.setPlaceholderText(
            "What the case concerns, where the evidence came from, anything "
            "the next person reading it will need to know.")
        self.description_input.setFixedHeight(76)
        self.description_input.setTabChangesFocus(True)
        layout.addRow("Description", self.description_input)

        folder_row = QHBoxLayout()
        folder_row.setSpacing(6)
        self.folder_input = QLineEdit(default_case_folder())
        self.folder_input.setObjectName("wizardField")
        self.folder_input.textChanged.connect(lambda _t: self._edited(
            'folder'))
        browse = QPushButton("Browse...")
        browse.setObjectName("wizardButton")
        browse.clicked.connect(self._choose_folder)
        folder_row.addWidget(self.folder_input, 1)
        folder_row.addWidget(browse)
        folder_box = QVBoxLayout()
        folder_box.setSpacing(3)
        folder_box.addLayout(folder_row)
        self.target_label = QLabel()
        self.target_label.setObjectName("wizardTargetPath")
        self.target_label.setWordWrap(True)
        self.target_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.target_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        folder_box.addWidget(self.target_label)
        self._errors['folder'] = QLabel()
        self._errors['folder'].setObjectName("wizardFieldError")
        self._errors['folder'].setVisible(False)
        folder_box.addWidget(self._errors['folder'])
        layout.addRow("Keep cases in *", folder_box)

        self.zone_combo = QComboBox()
        self.zone_combo.setObjectName("wizardZoneCombo")
        self.zone_combo.setEditable(True)
        self.zone_combo.setInsertPolicy(QComboBox.NoInsert)
        self.zone_combo.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Fixed)
        self.zone_combo.addItem("UTC only", '')
        for zone in settings.zones():
            self.zone_combo.addItem(zone, zone)
        completer = QCompleter([self.zone_combo.itemText(i) for i in
                                range(self.zone_combo.count())], self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setFilterMode(Qt.MatchContains)
        self.zone_combo.setCompleter(completer)
        self.zone_combo.currentTextChanged.connect(
            lambda _t: self._edited('zone'))
        zone_box = QVBoxLayout()
        zone_box.setSpacing(2)
        zone_box.addWidget(self.zone_combo)
        zone_note = QLabel("Times are always kept and shown in UTC; a zone "
                           "named here is shown beside them, never instead.")
        zone_note.setObjectName("wizardFieldNote")
        zone_note.setWordWrap(True)
        zone_note.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        zone_box.addWidget(zone_note)
        self._errors['zone'] = QLabel()
        self._errors['zone'].setObjectName("wizardFieldError")
        self._errors['zone'].setVisible(False)
        zone_box.addWidget(self._errors['zone'])
        layout.addRow("Display time zone", zone_box)

        self._update_target()

    # --- values -------------------------------------------------------------

    def values(self):
        zone_text = self.zone_combo.currentText().strip()
        zone = '' if zone_text in ('', 'UTC only') else zone_text
        return {'name': self.name_input.text().strip(),
                'number': self.number_input.text().strip(),
                'examiner': self.examiner_input.text().strip(),
                'organisation': self.organisation_input.text().strip(),
                'description': self.description_input.toPlainText().strip(),
                'base_folder': self.folder_input.text().strip(),
                'folder': self.target_folder(),
                'display_zone': zone}

    def target_folder(self):
        base = self.folder_input.text().strip()
        name = self.name_input.text().strip()
        if not base or not name:
            return ''
        return os.path.normpath(os.path.join(base, case_folder_name(name)))

    def _issues(self):
        """{field: why it is not acceptable}."""
        from trace_app.core import settings
        values = self.values()
        issues = {}
        if not values['name']:
            issues['name'] = "Name the case: it is how the case is told apart."
        if not values['examiner']:
            issues['examiner'] = ("Name the examiner: reports and the audit "
                                  "trail state who did the work.")
        base = values['base_folder']
        if not base:
            issues['folder'] = "Choose where cases are kept."
        elif not os.path.isabs(base):
            issues['folder'] = "Give a full path (e.g. D:\\Cases)."
        elif values['folder']:
            target = values['folder']
            if is_case_folder(target):
                issues['folder'] = ("A case is already kept there. Open it "
                                    "from the start screen, or give this one "
                                    "another name.")
            elif os.path.exists(target) and not os.path.isdir(target):
                issues['folder'] = "A file of that name is in the way."
            elif not _writable(target):
                issues['folder'] = ("That folder cannot be written to (or its "
                                    "drive is not connected).")
        if values['display_zone'] and \
                not settings.valid_zone(values['display_zone']):
            issues['zone'] = "Not a time zone this system knows " \
                             "(e.g. Europe/London)."
        return issues

    def problem(self):
        issues = self._issues()
        for key in ('name', 'examiner', 'folder', 'zone'):
            if key in issues:
                return issues[key]
        return ''

    # --- reacting -------------------------------------------------------------

    def _edited(self, key):
        self._touched.add(key)
        if key in ('name', 'folder'):
            self._update_target()
        issues = self._issues()
        for name, label in self._errors.items():
            text = issues.get(name, '') if name in self._touched else ''
            label.setText(text)
            label.setVisible(bool(text))
        self.completeChanged.emit()

    def _update_target(self):
        target = self.target_folder()
        if not target:
            self.target_label.setText("The case folder is named after the "
                                      "case.")
            return
        note = ''
        if os.path.isdir(target) and not is_case_folder(target):
            try:
                if os.listdir(target):
                    note = " (exists; the case is added beside what is there)"
            except OSError:
                pass
        self.target_label.setText(f"Will be created at  {target}{note}")

    def _choose_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Where cases are kept", self.folder_input.text())
        if folder:
            self.folder_input.setText(os.path.normpath(folder))

    def enter(self):
        self.name_input.setFocus()


def _writable(target):
    """Can a folder be created / written at `target`? Asks the nearest part
    of the path that exists."""
    probe = target
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            return False
        probe = parent
    return bool(probe) and os.path.isdir(probe) and os.access(probe, os.W_OK)


class EvidencePage(WizardPage):
    title = "Evidence"
    subtitle = ("Add the images and folders this case examines. Each is "
                "opened as it is added, so a missing segment or an "
                "unreadable file shows now rather than later. Evidence is "
                "only ever read.")

    def __init__(self, parent=None, existing=None, require=False):
        super().__init__(parent)
        self.require = require
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.intake = EvidenceIntake(self, existing)
        self.intake.changed.connect(self.completeChanged)
        layout.addWidget(self.intake)

    def problem(self):
        pending = self.intake.pending()
        if pending:
            return (f"Checking {len(pending)} item"
                    f"{'s' if len(pending) != 1 else ''}…")
        new = self.intake.new_items()
        if new and not self.intake.usable():
            return ("None of the listed items can be read. Remove them, or "
                    "add evidence that can.")
        if self.require and not new:
            return "Add at least one image, file or folder."
        return ''


class ModulesPage(WizardPage):
    title = "Analysis modules"
    subtitle = ("What runs over the evidence once it is open. Everything "
                "runs in the background, one job at a time, while you work; "
                "findings appear as they are made.")

    def __init__(self, evidence_page, parent=None, case=None, libraries=None,
                 preselected=None):
        super().__init__(parent)
        self.evidence_page = evidence_page
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.no_evidence = QLabel(
            "No evidence was added, so there is nothing to analyse yet. The "
            "modules are offered again when evidence is added (File ▸ Add "
            "Evidence).")
        self.no_evidence.setObjectName("wizardBanner")
        self.no_evidence.setWordWrap(True)
        layout.addWidget(self.no_evidence)
        unavailable, _in_use = availability(case, libraries)
        self.selector = ModuleSelector(self, unavailable)
        if preselected:
            self.selector.set_choice(preselected)
        else:
            self.selector.apply_profile(remembered_profile())
        layout.addWidget(self.selector, 1)
        self.selector.changed.connect(self.completeChanged)

    def has_evidence(self):
        return bool(self.evidence_page.intake.usable())

    def enter(self):
        has = self.has_evidence()
        self.no_evidence.setVisible(not has)
        self.selector.setEnabled(has)
        self.selector.set_evidence_size(self.evidence_page.intake
                                        .total_bytes())

    def choice(self):
        """The modules chosen, or None when there is nothing to run them on
        or nothing was chosen."""
        if not self.has_evidence() or not self.selector.any_selected():
            return None
        return dict(self.selector.choice(), evidence_ids=None)


class ReviewPage(WizardPage):
    title = "Review"
    subtitle = ("Check everything once more. Nothing has been written yet; "
                "use Edit to change a section.")

    def __init__(self, wizard_summary, parent=None):
        super().__init__(parent)
        self._summary = wizard_summary
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.browser = QTextBrowser()
        self.browser.setObjectName("wizardReview")
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        layout.addWidget(self.browser, 1)
        self.error = QLabel()
        self.error.setObjectName("wizardError")
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        layout.addWidget(self.error)
        #: Set by the wizard: called with a page index for an Edit link.
        self.edit_requested = None
        self.browser.anchorClicked.connect(self._anchor)

    def _anchor(self, url):
        text = url.toString()
        if text.startswith('edit:') and self.edit_requested is not None:
            self.edit_requested(int(text.split(':', 1)[1]))

    def enter(self):
        self.error.setVisible(False)
        self.browser.setHtml(self._summary())

    def show_error(self, text):
        self.error.setText(text)
        self.error.setVisible(True)


# --- review text --------------------------------------------------------------------

def _section(title, page_index, body):
    edit = (f" &nbsp;<a href='edit:{page_index}'>Edit</a>"
            if page_index is not None else '')
    return f"<h3>{_escape(title)}{edit}</h3>{body}"


def _facts(pairs):
    rows = ''.join(f"<tr><td class='k'>{_escape(k)}</td>"
                   f"<td>{_escape(v)}</td></tr>"
                   for k, v in pairs if v)
    return f"<table cellspacing='0' cellpadding='3'>{rows}</table>"


def _evidence_html(items, verify):
    from trace_app.infra.utils import FileSystemUtils
    if not items:
        return ("<p>No evidence yet. It can be added once the case is open "
                "(File ▸ Add Evidence).</p>")
    out = []
    for item in items:
        result = item.get('result') or {}
        size = result.get('size')
        details = item.get('details') or {}
        pairs = [("Path", item['path']),
                 ("Format", result.get('format')),
                 ("Size", FileSystemUtils.get_readable_size(size)
                  if size else ''),
                 ("Contents", result.get('contents'))]
        pairs += [(EVIDENCE_DETAILS[k], details.get(k))
                  for k in EVIDENCE_DETAILS]
        notes = ''.join(f"<li>{_escape(n)}</li>"
                        for n in result.get('notes') or ())
        out.append(f"<p><b>{_escape(item['display_name'])}</b></p>"
                   + _facts(pairs) + (f"<ul>{notes}</ul>" if notes else ''))
    out.append("<p>Hashes are verified in the background once the case "
               "opens.</p>" if verify else
               "<p><i>Hash verification was not requested.</i> It can be "
               "run later from Case ▸ Verify All Evidence.</p>")
    return ''.join(out)


def _modules_html(choice):
    if choice is None:
        return "<p>None — the evidence opens for browsing only.</p>"
    keys = selected_keys(choice)
    profile = PROFILE_LABELS.get(choice.get('profile'), ('Custom',))[0]
    rows = ''.join(f"<li>{_escape(DESCRIPTIONS[k][0])}</li>"
                   for k in DESCRIPTIONS if k in keys)
    carve = ''
    if MODULE_CARVE in keys:
        where = ('unallocated space' if choice.get('unallocated_only')
                 else 'the whole image')
        carve = (f"<p>Carving looks for {len(choice['carve_types'])} file "
                 f"types in {where}.</p>")
    return f"<p>Profile: <b>{_escape(profile)}</b></p><ul>{rows}</ul>{carve}"


#: The review's own document style. The link colour is a mid blue that
#: reads on both themes: Qt's default link blue vanishes on the dark one.
_REVIEW_STYLE = ("<style>h3 { margin-top: 14px; margin-bottom: 4px; } "
                 "td.k { padding-right: 18px; font-weight: 600; } "
                 "a { color: #3D8BFD; text-decoration: none; "
                 "font-weight: normal; font-size: small; } "
                 "ul { margin-top: 2px; }</style>")


# --- the wizards ----------------------------------------------------------------------

class CaseWizard(SetupWizard):
    """New Case. `case` (open) and `setup` are set when it is accepted:
    setup = {'verify': bool, 'choice': module choice or None}."""

    finish_text = "Create Case"

    def __init__(self, parent=None):
        self.details_page = DetailsPage()
        self.evidence_page = EvidencePage()
        self.modules_page = ModulesPage(self.evidence_page)
        self.review_page = ReviewPage(self.summary_html)
        super().__init__([self.details_page, self.evidence_page,
                          self.modules_page, self.review_page], parent)
        self.setWindowTitle("New Case")
        self.review_page.edit_requested = self.go_to
        self.case = None
        self.setup = None

    def has_input(self):
        values = self.details_page.values()
        return bool(values['name'] or values['number'] or
                    values['description'] or
                    self.evidence_page.intake.new_items())

    def summary_html(self):
        values = self.details_page.values()
        intake = self.evidence_page.intake
        items = intake.usable()
        unreadable = intake.unreadable()
        case = _facts([("Name", values['name']),
                       ("Number", values['number']),
                       ("Examiner", values['examiner']),
                       ("Organisation", values['organisation']),
                       ("Description", values['description']),
                       ("Case folder", values['folder']),
                       ("Times", "UTC" + (f", also shown in "
                                          f"{values['display_zone']}"
                                          if values['display_zone'] else
                                          ''))])
        evidence = _evidence_html(items, intake.verify_after())
        if unreadable:
            evidence += (f"<p><i>{len(unreadable)} unreadable item"
                         f"{'s are' if len(unreadable) != 1 else ' is'} not "
                         f"added.</i></p>")
        return (_REVIEW_STYLE
                + _section("Case", 0, case)
                + _section(f"Evidence ({len(items)})", 1, evidence)
                + _section("Analysis modules", 2,
                           _modules_html(self.modules_page.choice())))

    def finish(self):
        values = self.details_page.values()
        problem = self.details_page.problem()
        if problem:
            self.go_to(0)
            return
        items = self.evidence_page.intake.usable()
        choice = self.modules_page.choice()
        verify = self.evidence_page.intake.verify_after() and bool(items)
        folder = values['folder']
        existed = os.path.exists(folder)
        case = None
        try:
            case = Case.create(folder, values['name'], values['number'],
                               values['examiner'], values['description'],
                               values['organisation'])
            for item in items:
                case.add_evidence(item['path'], item['display_name'],
                                  item['details'])
            if values['display_zone']:
                from trace_app.core import settings
                settings.save_case(case, {'display_zone':
                                          values['display_zone']})
            modules = ', '.join(DESCRIPTIONS[k][0] for k in DESCRIPTIONS
                                if choice and k in selected_keys(choice))
            case.record_event(
                'case set up',
                f"{len(items)} evidence item(s); hash verification "
                f"{'queued' if verify else 'not requested'}; modules: "
                f"{modules or 'none'}")
        except Exception as exc:          # CaseError, OSError, sqlite3
            logger.exception("Creating the case in %s failed", folder)
            if case is not None:
                try:
                    case.close()
                except Exception:
                    pass
            if not existed:
                import shutil
                shutil.rmtree(folder, ignore_errors=True)
            self.review_page.show_error(
                f"The case could not be created: {exc}. Nothing was kept.")
            return

        remember_case(folder, values['name'])
        if choice:
            remember_profile(choice.get('profile'))
        self.case = case
        self.setup = {'verify': verify, 'choice': choice}
        self.accept()


class AddEvidenceWizard(SetupWizard):
    """Add Evidence to an open case: Evidence, Modules, Review. `setup` is
    set when accepted: {'items': [{path, display_name, details}], 'verify',
    'choice'} -- the window adds, opens and queues them."""

    finish_text = "Add Evidence"

    def __init__(self, case, parent=None, libraries=None, preselected=None,
                 paths=None):
        existing = [(row['path'], row.get('display_name')
                     or os.path.basename(row['path']))
                    for row in case.evidence()]
        self.evidence_page = EvidencePage(existing=existing, require=True)
        self.modules_page = ModulesPage(self.evidence_page, case=case,
                                        libraries=libraries,
                                        preselected=preselected)
        self.review_page = ReviewPage(self.summary_html)
        super().__init__([self.evidence_page, self.modules_page,
                          self.review_page], parent)
        self.setWindowTitle(f"Add Evidence — {case.name}")
        self.review_page.edit_requested = self.go_to
        self.setup = None
        if paths:
            self.evidence_page.intake.add_paths(paths)

    def has_input(self):
        return bool(self.evidence_page.intake.new_items())

    def summary_html(self):
        intake = self.evidence_page.intake
        items = intake.usable()
        return (_REVIEW_STYLE
                + _section(f"Evidence to add ({len(items)})", 0,
                           _evidence_html(items, intake.verify_after()))
                + _section("Analysis modules", 1,
                           _modules_html(self.modules_page.choice())))

    def finish(self):
        items = self.evidence_page.intake.usable()
        choice = self.modules_page.choice()
        if choice:
            remember_profile(choice.get('profile'))
        self.setup = {'items': items,
                      'verify': self.evidence_page.intake.verify_after(),
                      'choice': choice}
        self.accept()


def new_case(parent=None):
    """Run the New Case wizard: (Case, setup) or (None, None)."""
    wizard = CaseWizard(parent)
    if wizard.exec() == QDialog.Accepted and wizard.case is not None:
        return wizard.case, wizard.setup
    return None, None

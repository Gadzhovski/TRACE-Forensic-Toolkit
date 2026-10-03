"""Choosing what to run before the evidence is opened.

These modules read every file on the image, which takes minutes rather than
seconds, so they are not something to discover halfway through an examination.
The dialog asks once, at the point a case is opened, and then gets out of the
way: the chosen modules run in the background while the examiner works, and
the findings appear as they arrive.

Which evidence is asked once too: every image in the case, or one. File
carving is offered beside the file-by-file modules but is a different kind of
pass -- it reads the raw image rather than its files -- so it has its own
options (which types, unallocated space or the whole image) and runs as its
own job.

Nothing here is mandatory. "Just browse" is a first-class answer -- a quick
look at an image should not cost a full pass over it.
"""

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFrame, QHBoxLayout, QLabel,
                               QScrollArea,
                               QVBoxLayout, QWidget)

from trace_app.core.analysis import (MODULE_AUTHORS, MODULE_ENTROPY,
                                     MODULE_HASH, MODULE_HIDDEN, MODULE_MAGIC,
                                     MODULE_PHOTO, magic_reader)
from trace_app.core.carving import CARVABLE_TYPES, CARVE_CATEGORIES
from trace_app.ui import icons
from trace_app.ui.widgets.multi_select import MultiSelectButton

logger = logging.getLogger('TRACE.AnalysisDialog')

#: The carving option's key in a choice: not one of analysis.MODULES, since
#: it does not walk the file systems.
MODULE_CARVE = 'carve'

#: The search index's key: its own walk (core/indexer.py), into search.db
#: rather than case.db, so it too runs as a job of its own.
MODULE_INDEX = 'index'

#: Windows activity and browser history (core/activity): reads known
#: locations rather than every file, so it is its own, short job.
MODULE_ACTIVITY = 'activity'

#: NTFS internals (core/ntfs): reads each NTFS volume's $MFT and change
#: journal directly, so it is a job of its own too.
MODULE_NTFS = 'ntfs'

#: Matching against the examiner's hash sets (core/hashsets): reads the
#: digests the hash module stores, so it is queued after the analysis.
MODULE_HASHSETS = 'hashsets'

#: YARA rules over every file and carved file (core/yara_rules): its own
#: job, after the analysis.
MODULE_YARA = 'yara'

#: Autostarts (core/persistence): reads the hives, tasks and Startup
#: folders, then the files they start.
MODULE_PERSISTENCE = 'persistence'

#: Keyword lists (core/keywords): searches the case's index, so it is
#: queued after indexing.
MODULE_KEYWORDS = 'keywords'

#: What each module is for, in the terms an examiner would use to decide
#: whether they want it. The cost line matters as much as the description:
#: the whole point of asking is that these are not free.
_DESCRIPTIONS = {
    MODULE_MAGIC: (
        "File type detection",
        "Identify every file by its content rather than its extension, and "
        "flag disguises — an executable named .jpg, a document that is not "
        "one.",
        "Fast: reads the first few KB of each file."),
    MODULE_ENTROPY: (
        "Entropy analysis",
        "Score how random each file's contents look, to find packed, "
        "compressed or encrypted data that nothing else marks as unusual.",
        "Slower: reads every file in full."),
    MODULE_HASH: (
        "File hashes and duplicates",
        "MD5, SHA-1 and SHA-256 for every file, so the case can be searched "
        "by hash, identical copies grouped together and files matched "
        "against hash sets.",
        "Slower: reads every file in full."),
    MODULE_HIDDEN: (
        "Hidden data",
        "Disguised names (invoice.pdf.exe, reversed text), data hidden after "
        "the end of an image or PDF, password-protected archives, documents "
        "and PDFs, and files that look like encrypted volumes.",
        "Fast: names cost nothing; only images, PDFs and archives are read."),
    MODULE_PHOTO: (
        "Photo metadata",
        "Camera, capture time, editing software and GPS position from every "
        "photo's EXIF.",
        "Fast: reads photos only."),
    MODULE_AUTHORS: (
        "Document authors",
        "Author, last saved by, company, application and template from "
        "Office, OpenDocument and PDF files — who made a document, and with "
        "what.",
        "Fast: reads documents only."),
}

_INDEXING = (
    "Search index and indicators",
    "Extract the text of every file, registry value and archive member so "
    "the whole case can be searched, and list the email addresses, URLs, "
    "domains, IPs, phone numbers, card numbers, IBANs, Bitcoin addresses and "
    "hashes found in it (Triage ▸ Indicators).",
    "Slower: reads every file in full; replaces a previous index of the "
    "same image.")

_ACTIVITY = (
    "Windows activity and browser history",
    "What the users did: programs run (Prefetch, Amcache, Shimcache, "
    "UserAssist, BAM, Run dialog), files and folders opened (shortcuts, "
    "Jump Lists, RecentDocs, ShellBags, Windows Timeline), USB devices and "
    "the shares each user mounted, the Recycle Bin, logons and remote "
    "desktop, networks joined, app and network use (SRUM), installed "
    "programs and the time zone, and Chrome, Edge, Internet Explorer, "
    "Firefox and Safari history, downloads and searches (Activity tab).",
    "Fast: reads the places Windows and the browsers keep these, not every "
    "file.")

_NTFS = (
    "NTFS: $MFT times, change journal and streams",
    "Both sets of NTFS times for every file — including deleted ones still "
    "in the $MFT — to spot timestamps set by hand (timestomping); the "
    "$UsnJrnl change journal, with every create, rename and delete it "
    "recorded; alternate data streams, and where downloaded files came from "
    "(Mark of the Web). All of it feeds the Timeline.",
    "Fast: reads the $MFT and the journal, not every file.")

_HASHSETS = (
    "Hash sets",
    "Match every hashed file against the hash sets this case uses — hide "
    "known-good files (NSRL), flag known-bad and notable ones (Tools ▸ Hash "
    "Sets chooses which).",
    "Fast: a lookup per digest, after the hashes are taken.")

_PERSISTENCE = (
    "Persistence (autoruns)",
    "Everything set to start by itself — Run keys, services and drivers, "
    "scheduled tasks, Startup folders, Winlogon, IFEO debuggers, WMI "
    "consumers — each graded by the file it starts: present or missing, "
    "signed or not, in a hash set, disguised as a Windows program.",
    "Fast: reads the hives and task files, then each started file once.")

_YARA = (
    "YARA rules",
    "Scan every file and carved file with the YARA rules this case uses "
    "(Tools ▸ YARA Rules); a match is a finding with the rule and the "
    "strings it matched.",
    "Slower: reads every file, up to the size set for the case.")

_KEYWORDS = (
    "Keyword lists",
    "Search the whole case for the terms in the keyword lists this case "
    "uses (Tools ▸ Keyword Lists) — words, prefixes and regular "
    "expressions — in every file, archive member, message and attachment; "
    "each term's hits are findings (Triage ▸ Keywords).",
    "Fast: reads the search index, not the evidence; needs it built.")

_CARVING = (
    "File carving",
    "Recover deleted files whose directory entries are gone, by searching "
    "the raw image for file signatures (pictures, documents, archives, "
    "audio and video). Recovered files are saved in the case.",
    "Slowest: reads the whole image, or all of its unallocated space.")


def default_choice(modules=None):
    """What the dialog offers before the examiner has chosen anything."""
    return {'modules': list(modules or ()), 'evidence_ids': None,
            'index': bool(modules), 'activity': bool(modules),
            'ntfs': bool(modules), 'hashsets': False,
            'persistence': bool(modules),
            'carve_types': [], 'unallocated_only': True}


class AnalysisModulesDialog(QDialog):
    """Ask which analysis modules to run, and against which evidence."""

    def __init__(self, parent=None, preselected=None, evidence=None):
        super().__init__(parent)
        self.setWindowTitle("Analysis Modules")
        self.setObjectName("analysisModulesDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(560)

        choice = preselected or default_choice()
        evidence = list(evidence or [])
        self.choice = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        heading = QLabel(
            "Choose what to examine. These run in the background while you "
            "work — you can start browsing straight away, and findings appear "
            "as they are made.")
        heading.setObjectName("analysisModulesIntro")
        heading.setWordWrap(True)
        layout.addWidget(heading)

        # Which evidence: the whole case unless the examiner narrows it. One
        # image needs no choosing.
        self.evidence_combo = QComboBox()
        self.evidence_combo.setObjectName("analysisEvidenceCombo")
        if len(evidence) > 1:
            self.evidence_combo.addItem(f"All {len(evidence)} images", None)
        for evidence_id, name in evidence:
            self.evidence_combo.addItem(name, evidence_id)
        wanted = choice.get('evidence_ids')
        if wanted and len(wanted) == 1:
            index = self.evidence_combo.findData(wanted[0])
            self.evidence_combo.setCurrentIndex(max(index, 0))
        if len(evidence) > 1:
            row = QHBoxLayout()
            label = QLabel("Evidence:")
            label.setObjectName("analysisEvidenceLabel")
            row.addWidget(label)
            row.addWidget(self.evidence_combo, 1)
            layout.addLayout(row)

        # Magic detection is the one module with a system dependency. Offering
        # a tick box that silently does nothing is worse than saying why it is
        # unavailable.
        magic_available = magic_reader() is not None

        # The modules scroll: there are nine, each with a two-line note, and
        # on a 768-pixel screen the dialog otherwise squeezed every note to
        # one clipped line.
        dialog_layout = layout
        modules = QWidget()
        modules.setObjectName("analysisModulesList")
        layout = QVBoxLayout(modules)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(10)

        self.boxes = {}
        preselected_modules = set(choice.get('modules') or ())
        for key, (title, description, cost) in _DESCRIPTIONS.items():
            box = self._module(layout, title, description, cost)
            box.setChecked(key in preselected_modules)
            if key == MODULE_MAGIC and not magic_available:
                box.setChecked(False)
                box.setEnabled(False)
                box.setToolTip(
                    "libmagic is not available on this system, so file type "
                    "detection cannot run.")
            self.boxes[key] = box

        self.index_box = self._module(layout, *_INDEXING)
        self.index_box.setChecked(bool(choice.get('index')))
        self.boxes[MODULE_INDEX] = self.index_box

        self.activity_box = self._module(layout, *_ACTIVITY)
        self.activity_box.setChecked(bool(choice.get('activity')))
        self.boxes[MODULE_ACTIVITY] = self.activity_box

        self.ntfs_box = self._module(layout, *_NTFS)
        self.ntfs_box.setChecked(bool(choice.get('ntfs')))
        self.boxes[MODULE_NTFS] = self.ntfs_box

        self.hash_sets_box = self._module(layout, *_HASHSETS)
        available = choice.get('hashsets_available', True)
        self.hash_sets_box.setChecked(bool(choice.get('hashsets'))
                                      and available)
        if not available:
            self.hash_sets_box.setEnabled(False)
            self.hash_sets_box.setToolTip(
                "No hash sets are in use for this case. Tools ▸ Hash Sets "
                "imports them and switches them on.")
        self.boxes[MODULE_HASHSETS] = self.hash_sets_box

        self.persistence_box = self._module(layout, *_PERSISTENCE)
        self.persistence_box.setChecked(bool(choice.get('persistence')))
        self.boxes[MODULE_PERSISTENCE] = self.persistence_box

        self.yara_box = self._module(layout, *_YARA)
        yara_ok = choice.get('yara_available', True)
        self.yara_box.setChecked(bool(choice.get('yara')) and yara_ok)
        if not yara_ok:
            self.yara_box.setEnabled(False)
            self.yara_box.setToolTip(choice.get('yara_reason') or
                                     "No YARA rules are in use for this "
                                     "case (Tools ▸ YARA Rules).")
        self.boxes[MODULE_YARA] = self.yara_box

        self.keywords_box = self._module(layout, *_KEYWORDS)
        keywords_ok = choice.get('keywords_available', True)
        self.keywords_box.setChecked(bool(choice.get('keywords'))
                                     and keywords_ok)
        if not keywords_ok:
            self.keywords_box.setEnabled(False)
            self.keywords_box.setToolTip(
                "No keyword lists are in use for this case. Tools ▸ "
                "Keyword Lists imports or types them.")
        self.boxes[MODULE_KEYWORDS] = self.keywords_box

        rule = QFrame()
        rule.setObjectName("analysisModulesRule")
        rule.setFrameShape(QFrame.HLine)
        layout.addWidget(rule)

        self.carve_box = self._module(layout, *_CARVING)
        self.carve_box.setChecked(bool(choice.get('carve_types')))
        self.boxes[MODULE_CARVE] = self.carve_box

        self.carve_options = QWidget()
        options = QHBoxLayout(self.carve_options)
        options.setContentsMargins(22, 0, 0, 0)
        options.addWidget(QLabel("Look for"))
        self.carve_types = MultiSelectButton(CARVABLE_TYPES, self,
                                             noun="types",
                                             categories=CARVE_CATEGORIES)
        self.carve_types.set_selected(
            [t.upper() for t in choice.get('carve_types') or ()]
            or CARVABLE_TYPES)
        options.addWidget(self.carve_types)
        self.unallocated_box = QCheckBox("Unallocated space only")
        self.unallocated_box.setChecked(choice.get('unallocated_only', True))
        self.unallocated_box.setToolTip(
            "Skip space that belongs to live files: they are already in the "
            "tree. Untick to search the whole image.")
        options.addWidget(self.unallocated_box)
        options.addStretch(1)
        layout.addWidget(self.carve_options)
        self.carve_box.toggled.connect(self.carve_options.setEnabled)
        self.carve_options.setEnabled(self.carve_box.isChecked())

        layout = dialog_layout
        scroll = QScrollArea()
        scroll.setObjectName("analysisModulesScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(modules)
        # As tall as the list where the screen allows, scrolling where not.
        screen = self.screen().availableGeometry().height() \
            if self.screen() is not None else 800
        modules.setMinimumWidth(520)
        wanted = modules.sizeHint().height() + 4
        # What the rest of the dialog needs: the intro, the evidence picker,
        # the footer (two wrapped lines) and the buttons, with margins.
        chrome = 260
        scroll.setMinimumHeight(min(wanted, max(240,
                                                int(screen * 0.88) - chrome)))
        layout.addWidget(scroll, 1)

        footer = QLabel(
            "You can run these later from Analysis ▸ Run Analysis Modules, "
            "and cancel a run at any time from the status bar.")
        footer.setObjectName("analysisModulesFooter")
        footer.setWordWrap(True)
        # A wrapped label under-reports its height to a squeezed layout,
        # which then draws the list over it.
        footer.setMinimumHeight(footer.heightForWidth(520))
        layout.addWidget(footer)

        buttons = QDialogButtonBox()
        # "Just browse" rather than Cancel: skipping the modules is a choice
        # about how to work, not an abandoned dialog, and the button should
        # say what it does.
        self.run_button = buttons.addButton("Run Selected",
                                            QDialogButtonBox.AcceptRole)
        buttons.addButton("Just Browse", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        for box in self.boxes.values():
            box.toggled.connect(self._update_run_button)
        self._update_run_button()

    def _module(self, layout, title, description, cost):
        box = QCheckBox(title)
        box.setObjectName("analysisModuleCheck")
        layout.addWidget(box)
        note = QLabel(f"{description}  <i>{cost}</i>")
        note.setObjectName("analysisModuleNote")
        note.setWordWrap(True)
        note.setTextFormat(Qt.RichText)
        note.setIndent(22)
        layout.addWidget(note)
        return box

    def _update_run_button(self):
        chosen = any(box.isChecked() for box in self.boxes.values())
        self.run_button.setEnabled(chosen)
        self.run_button.setToolTip(
            '' if chosen else "Select at least one module, or just browse.")

    def _accept(self):
        target = self.evidence_combo.currentData()
        carving = self.carve_box.isChecked()
        self.choice = {
            'modules': [key for key, box in self.boxes.items()
                        if key not in (MODULE_CARVE, MODULE_INDEX,
                                       MODULE_ACTIVITY, MODULE_NTFS,
                                       MODULE_HASHSETS, MODULE_YARA,
                                       MODULE_PERSISTENCE, MODULE_KEYWORDS)
                        and box.isChecked()],
            'evidence_ids': None if target is None else [target],
            'index': self.index_box.isChecked(),
            'activity': self.activity_box.isChecked(),
            'ntfs': self.ntfs_box.isChecked(),
            'hashsets': self.hash_sets_box.isChecked(),
            'yara': self.yara_box.isChecked(),
            'persistence': self.persistence_box.isChecked(),
            'keywords': self.keywords_box.isChecked(),
            'carve_types': ([t.lower() for t in self.carve_types.selected()]
                            if carving else []),
            'unallocated_only': self.unallocated_box.isChecked(),
        }
        self.accept()


def choose_modules(parent=None, preselected=None, evidence=None):
    """Ask; return the choice, or None for "just browse".

    `evidence` is [(evidence_id, name)]. The choice is a dict: `modules`
    (analysis.MODULES to run), `evidence_ids` (None for every image),
    `index` (build the search index), `activity` (read Windows activity and
    browser history), `ntfs` ($MFT, change journal, streams), `carve_types` (empty: no carving) and
    `unallocated_only`.
    """
    dialog = AnalysisModulesDialog(parent, preselected, evidence)
    if dialog.exec() == QDialog.Accepted:
        return dialog.choice
    return None

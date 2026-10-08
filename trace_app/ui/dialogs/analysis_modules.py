"""Choosing what to run over the evidence.

These modules read every file on the image, which takes minutes rather than
seconds, so they are not something to discover halfway through an examination.
They are chosen where evidence enters a case -- the New Case and Add Evidence
wizards (ui/dialogs/case_wizard.py) -- and from Analysis ▸ Run Analysis
Modules; the chosen modules run in the background while the examiner works,
and the findings appear as they arrive.

`ModuleSelector` is the one list both use: profiles (Quick, Standard, Full,
Custom) over the modules in four groups, each with what it finds and what it
costs. A module that cannot run -- no YARA rules in use, libmagic missing --
is greyed with the reason beside it, never a tick box that silently does
nothing.

File carving is offered beside the file-by-file modules but is a different
kind of pass -- it reads the raw image rather than its files -- so it has its
own options (which types, unallocated space or the whole image) and runs as
its own job.

Nothing here is mandatory. "Just browse" is a first-class answer -- a quick
look at an image should not cost a full pass over it.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFrame, QGridLayout,
                               QHBoxLayout, QLabel, QScrollArea, QVBoxLayout,
                               QWidget)

from trace_app.core.analysis import (MODULE_AUTHORS, MODULE_ENTROPY,
                                     MODULE_EXECUTABLES, MODULE_HASH,
                                     MODULE_HIDDEN, MODULE_MAGIC,
                                     MODULE_PHOTO, MODULES, magic_reader)
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

#: File-system times of every other file system (core/fs_times): a walk of
#: names and times, no file contents -- what the timeline lacked off NTFS.
MODULE_FSTIMES = 'fstimes'

#: Matching against the examiner's hash sets (core/hashsets): reads the
#: digests the hash module stores, so it is queued after the analysis.
MODULE_HASHSETS = 'hashsets'

#: YARA rules over every file and carved file (core/yara_rules): its own
#: job, after the analysis.
MODULE_YARA = 'yara'

#: Sigma rules over every event log (core/sigma): its own job.
MODULE_SIGMA = 'sigma'

#: Autostarts (core/persistence): reads the hives, tasks and Startup
#: folders, then the files they start.
MODULE_PERSISTENCE = 'persistence'

#: Keyword lists (core/keywords): searches the case's index, so it is
#: queued after indexing.
MODULE_KEYWORDS = 'keywords'

#: Thumbnail caches (core/thumbnails): finds Thumbs.db, thumbcache_*.db
#: and RDP bitmap caches by name, then reads only those.
MODULE_THUMBNAILS = 'thumbnails'

#: Deleted files (core/deleted): lists what the file systems still record,
#: and measures how much of each is left.
MODULE_DELETED = 'deleted'

#: The modules that are jobs of their own, each a boolean in a choice; the
#: rest (analysis.MODULES) are listed under 'modules'.
JOB_MODULES = (MODULE_INDEX, MODULE_ACTIVITY, MODULE_NTFS, MODULE_FSTIMES,
               MODULE_HASHSETS,
               MODULE_YARA, MODULE_SIGMA, MODULE_PERSISTENCE,
               MODULE_KEYWORDS, MODULE_THUMBNAILS, MODULE_DELETED)

#: What a module costs, as the badge beside it says.
FAST, EVERY_FILE, WHOLE_IMAGE = 'fast', 'every file', 'whole image'
_COST_LABELS = {FAST: "Fast", EVERY_FILE: "Reads every file",
                WHOLE_IMAGE: "Reads the image"}

#: key -> (title, what it finds, what it costs in words, cost level). The
#: cost line matters as much as the description: the whole point of asking
#: is that these are not free.
DESCRIPTIONS = {
    MODULE_MAGIC: (
        "File type detection",
        "Identify every file by its content rather than its extension, and "
        "flag disguises — an executable named .jpg, a document that is not "
        "one.",
        "Reads the first few KB of each file.", FAST),
    MODULE_HASH: (
        "File hashes and duplicates",
        "MD5, SHA-1 and SHA-256 for every file, so the case can be searched "
        "by hash, identical copies grouped together and files matched "
        "against hash sets.",
        "Reads every file in full.", EVERY_FILE),
    MODULE_ENTROPY: (
        "Entropy analysis",
        "Score how random each file's contents look, to find packed, "
        "compressed or encrypted data that nothing else marks as unusual.",
        "Reads every file in full.", EVERY_FILE),
    MODULE_HIDDEN: (
        "Hidden data",
        "Disguised names (invoice.pdf.exe, reversed text), data hidden after "
        "the end of an image or PDF, password-protected archives, documents "
        "and PDFs, and files that look like encrypted volumes.",
        "Names cost nothing; only images, PDFs and archives are read.", FAST),
    MODULE_PHOTO: (
        "Photo metadata",
        "Camera, capture time, editing software and GPS position from every "
        "photo's EXIF.",
        "Reads photos only.", FAST),
    MODULE_AUTHORS: (
        "Document authors",
        "Author, last saved by, company, application and template from "
        "Office, OpenDocument and PDF files — who made a document, and with "
        "what.",
        "Reads documents only.", FAST),
    MODULE_EXECUTABLES: (
        "Executables",
        "Windows, Linux and macOS programs and libraries read from their "
        "headers: architecture, link time, signer, imports, sections and "
        "appended data — flagging packers, writable code, process-injection "
        "imports and files that call themselves something else.",
        "Reads executables only.", FAST),
    MODULE_INDEX: (
        "Search index and indicators",
        "Extract the text of every file, registry value and archive member so "
        "the whole case can be searched, and list the email addresses, URLs, "
        "domains, IPs, phone numbers, card numbers, IBANs, Bitcoin addresses "
        "and hashes found in it (Triage ▸ Indicators).",
        "Reads every file in full; replaces a previous index of the same "
        "image.", EVERY_FILE),
    MODULE_ACTIVITY: (
        "User activity and browser history",
        "What the users did. Windows: programs run (Prefetch, Amcache, Shimcache, "
        "UserAssist, BAM, Run dialog), files and folders opened (shortcuts, "
        "Jump Lists, RecentDocs, ShellBags, Windows Timeline), USB devices and "
        "the shares each user mounted, the Recycle Bin, logons and remote "
        "desktop, networks joined, app and network use (SRUM), installed "
        "programs and the time zone, and Chrome, Edge, Internet Explorer, "
        "Firefox and Safari history, downloads and searches. Linux: shell "
        "histories, logons and sudo, the journal, the system, its accounts, "
        "software installed (dnf, apt) and SSH hosts and keys. macOS, "
        "phones, chat and cloud sync too (Activity tab).",
        "Reads the places each system and the browsers keep these, not "
        "every file.", FAST),
    MODULE_NTFS: (
        "NTFS: $MFT times, change journal and streams",
        "Both sets of NTFS times for every file — including deleted ones "
        "still in the $MFT — to spot timestamps set by hand (timestomping); "
        "the $UsnJrnl change journal, with every create, rename and delete it "
        "recorded; alternate data streams, and where downloaded files came "
        "from (Mark of the Web). All of it feeds the Timeline.",
        "Reads the $MFT and the journal, not every file.", FAST),
    MODULE_FSTIMES: (
        "File system timeline",
        "Created, modified, accessed and changed times of every file and "
        "folder — deleted ones too, while their metadata is still theirs — "
        "on every file system but NTFS (which the NTFS module covers): ext, "
        "Btrfs, XFS, HFS+, APFS, FAT and exFAT (their times have no zone and "
        "are shown as local). All of it feeds the Timeline.",
        "Reads names and times, not file contents.", FAST),
    MODULE_PERSISTENCE: (
        "Persistence (autoruns)",
        "Everything set to start by itself — Windows: Run keys, services "
        "and drivers, scheduled tasks, Startup folders, Winlogon, IFEO "
        "debuggers, WMI consumers. Linux: systemd units, cron, SysV and "
        "Upstart, rc.local, ld.so.preload, autostart, SSH keys. macOS: "
        "launch agents and daemons. Each graded by what it starts.",
        "Reads the hives and task files, then each started file once.", FAST),
    MODULE_THUMBNAILS: (
        "Thumbnail caches",
        "The pictures Windows kept in Thumbs.db (XP, network shares) and "
        "thumbcache_*.db (Vista to 11) — often of pictures and documents since "
        "deleted. A Thumbs.db names each file; those no longer in their folder "
        "are findings. Also Remote Desktop's bitmap caches: tiles of the "
        "screens of sessions this computer connected to (Triage ▸ "
        "Thumbnails).",
        "Lists the file systems, then reads only the caches.", FAST),
    MODULE_HASHSETS: (
        "Hash sets",
        "Match every hashed file against the hash sets this case uses — hide "
        "known-good files (NSRL), flag known-bad and notable ones (Tools ▸ "
        "Hash Sets chooses which).",
        "A lookup per digest, after the hashes are taken.", FAST),
    MODULE_YARA: (
        "YARA rules",
        "Scan every file and carved file with the YARA rules this case uses "
        "(Tools ▸ YARA Rules); a match is a finding with the rule and the "
        "strings it matched.",
        "Reads every file, up to the size set for the case.", EVERY_FILE),
    MODULE_SIGMA: (
        "Event log detection (Sigma)",
        "Check every Windows event log — on the disk or in a collection — "
        "with the Sigma rules this case uses (Tools ▸ Sigma Rules): log "
        "clearing, credential dumping, lateral movement, malicious services. "
        "Each event a rule matches is a finding with its level and ATT&CK "
        "techniques.",
        "Reads the event logs only.", FAST),
    MODULE_KEYWORDS: (
        "Keyword lists",
        "Search the whole case for the terms in the keyword lists this case "
        "uses (Tools ▸ Keyword Lists) — words, prefixes and regular "
        "expressions — in every file, archive member, message and attachment; "
        "each term's hits are findings (Triage ▸ Keywords).",
        "Reads the search index, not the evidence; needs it built.", FAST),
    MODULE_DELETED: (
        "Deleted files",
        "Every deleted file and folder the file systems still list — original "
        "path and times — and how much of each is left: recoverable, partly "
        "or wholly overwritten by live files, its entry reused (Triage ▸ "
        "Deleted files). Carved files are named from the same entries.",
        "Walks the directories and reads no file content.", FAST),
    MODULE_CARVE: (
        "File carving",
        "Recover deleted files whose directory entries are gone, by searching "
        "the raw image for file signatures (pictures, documents, archives, "
        "audio and video). Recovered files are saved in the case.",
        "Slowest: reads the whole image, or all of its unallocated space.",
        WHOLE_IMAGE),
}

#: How the list is grouped, in the order shown.
GROUPS = (
    ("File analysis", (MODULE_MAGIC, MODULE_HASH, MODULE_ENTROPY,
                       MODULE_HIDDEN, MODULE_PHOTO, MODULE_AUTHORS,
                       MODULE_EXECUTABLES, MODULE_INDEX)),
    ("Activity and system", (MODULE_ACTIVITY, MODULE_NTFS, MODULE_FSTIMES,
                             MODULE_PERSISTENCE, MODULE_THUMBNAILS)),
    ("Rules and lists", (MODULE_HASHSETS, MODULE_YARA, MODULE_SIGMA,
                         MODULE_KEYWORDS)),
    ("Recovery", (MODULE_DELETED, MODULE_CARVE)),
)

#: Profiles: what each ticks. Modules that cannot run are left unticked
#: whatever the profile says.
QUICK, STANDARD, FULL, CUSTOM = 'quick', 'standard', 'full', 'custom'
_QUICK = {MODULE_MAGIC, MODULE_HIDDEN, MODULE_PHOTO, MODULE_AUTHORS,
          MODULE_ACTIVITY, MODULE_NTFS, MODULE_FSTIMES, MODULE_PERSISTENCE,
          MODULE_THUMBNAILS, MODULE_DELETED, MODULE_SIGMA}
_STANDARD = _QUICK | {MODULE_HASH, MODULE_EXECUTABLES, MODULE_INDEX,
                      MODULE_HASHSETS, MODULE_YARA, MODULE_KEYWORDS}
_FULL = _STANDARD | {MODULE_ENTROPY, MODULE_CARVE}
PROFILES = {QUICK: _QUICK, STANDARD: _STANDARD, FULL: _FULL}
PROFILE_LABELS = {
    QUICK: ("Quick", "Fast modules only: nothing reads every file in full."),
    STANDARD: ("Standard", "Everything but entropy and carving: hashes, "
               "the search index and the rules this case uses."),
    FULL: ("Full", "Every module, including entropy and file carving of "
           "unallocated space. The slowest."),
    CUSTOM: ("Custom", "Your own selection."),
}

#: Where a profile choice is remembered (config.ini).
PROFILE_SECTION, PROFILE_KEY = 'Wizard', 'profile'


def remembered_profile():
    from trace_app.infra.window_state import read_value
    name = read_value(PROFILE_SECTION, PROFILE_KEY, STANDARD)
    return name if name in PROFILES else STANDARD


def remember_profile(name):
    if name in PROFILES:
        from trace_app.infra.window_state import save_value
        save_value(PROFILE_SECTION, PROFILE_KEY, name)


def default_choice(modules=None):
    """What the dialog offers before the examiner has chosen anything."""
    return {'modules': list(modules or ()), 'evidence_ids': None,
            'index': bool(modules), 'activity': bool(modules),
            'ntfs': bool(modules), 'fstimes': bool(modules),
            'hashsets': False,
            'persistence': bool(modules), 'thumbnails': bool(modules),
            'deleted': bool(modules),
            'carve_types': [], 'unallocated_only': True}


def selected_keys(choice):
    """The module keys a choice selects, file modules and jobs alike."""
    keys = set(choice.get('modules') or ())
    keys |= {key for key in JOB_MODULES if choice.get(key)}
    if choice.get('carve_types'):
        keys.add(MODULE_CARVE)
    return keys


def availability(case=None, libraries=None):
    """{module key: reason it cannot run} for those that cannot; and which
    rule-driven modules start ticked (their sets are in use). `libraries`
    are the window's cached ones (hash, yara, sigma, keyword), or None to
    read them here. Works with no case: a new case's options are the
    defaults, which use whatever the library holds."""
    from trace_app.core import hashsets, keywords, sigma, yara_rules
    libraries = libraries or {}
    unavailable, in_use = {}, set()

    if magic_reader() is None:
        unavailable[MODULE_MAGIC] = ("libmagic is not available on this "
                                     "system, so file type detection cannot "
                                     "run.")

    library = libraries.get('hash') or hashsets.Library()
    options = hashsets.case_options(case, library)
    if options.get('enabled') and any(hashsets.set_enabled_in(options, entry)
                                      for entry in library.sets()):
        if options.get('auto_match', True):
            in_use.add(MODULE_HASHSETS)
    else:
        unavailable[MODULE_HASHSETS] = ("No hash sets in use — Tools ▸ Hash "
                                        "Sets imports them.")

    for key, module, getter, noun, menu in (
            (MODULE_YARA, yara_rules, 'yara', 'YARA rules', 'YARA Rules'),
            (MODULE_SIGMA, sigma, 'sigma', 'Sigma rules', 'Sigma Rules')):
        if not module.available():
            unavailable[key] = module.unavailable_reason()
            continue
        library = libraries.get(getter) or module.Library()
        options = module.case_options(case, library)
        if options.get('enabled') and any(module.set_enabled_in(options, e)
                                          for e in library.sets()):
            in_use.add(key)
        else:
            unavailable[key] = f"No {noun} in use — Tools ▸ {menu}."

    library = libraries.get('keyword') or keywords.Library()
    options = keywords.case_options(case, library)
    if options.get('enabled') and any(keywords.list_enabled_in(options, e)
                                      for e in library.lists()):
        in_use.add(MODULE_KEYWORDS)
    else:
        unavailable[MODULE_KEYWORDS] = ("No keyword lists in use — Tools ▸ "
                                        "Keyword Lists.")
    return unavailable, in_use


class ModuleSelector(QWidget):
    """Profiles over the grouped list of modules; `choice()` is the same
    dict the dialog always returned."""

    #: The selection changed (a box, a profile, the carving options).
    changed = Signal()

    def __init__(self, parent=None, unavailable=None):
        super().__init__(parent)
        self.setObjectName("moduleSelector")
        self.unavailable = dict(unavailable or {})
        self._evidence_bytes = None
        self._applying = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        # Profile row.
        top = QHBoxLayout()
        top.setSpacing(8)
        label = QLabel("Profile")
        label.setObjectName("moduleProfileLabel")
        top.addWidget(label)
        self.profile_combo = QComboBox()
        self.profile_combo.setObjectName("moduleProfileCombo")
        for key in (QUICK, STANDARD, FULL, CUSTOM):
            self.profile_combo.addItem(PROFILE_LABELS[key][0], key)
        self.profile_combo.currentIndexChanged.connect(self._profile_chosen)
        top.addWidget(self.profile_combo)
        self.profile_note = QLabel()
        self.profile_note.setObjectName("moduleProfileNote")
        self.profile_note.setWordWrap(True)
        top.addWidget(self.profile_note, 1)
        outer.addLayout(top)

        # The grouped list, scrolling where the screen is short.
        body = QWidget()
        body.setObjectName("moduleList")
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(2)
        self.boxes = {}
        self._notes = {}
        for title, keys in GROUPS:
            heading = QLabel(title)
            heading.setObjectName("moduleGroupHeading")
            layout.addWidget(heading)
            for key in keys:
                self.boxes[key] = self._module(layout, key)
                if key == MODULE_CARVE:
                    layout.addWidget(self._carve_options())
        layout.addStretch(1)

        self.scroll = QScrollArea()
        self.scroll.setObjectName("moduleScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setWidget(body)
        outer.addWidget(self.scroll, 1)

        self.summary = QLabel()
        self.summary.setObjectName("moduleSummary")
        self.summary.setWordWrap(True)
        outer.addWidget(self.summary)

        for key, box in self.boxes.items():
            box.toggled.connect(self._box_toggled)
        self.carve_box.toggled.connect(self.carve_options.setEnabled)
        self.carve_options.setEnabled(False)
        self.apply_profile(STANDARD)

    # --- building ----------------------------------------------------------

    def _module(self, layout, key):
        title, description, cost_text, level = DESCRIPTIONS[key]
        row = QWidget()
        row.setObjectName("moduleRow")
        grid = QGridLayout(row)
        grid.setContentsMargins(0, 6, 0, 4)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)
        box = QCheckBox(title)
        box.setObjectName("analysisModuleCheck")
        grid.addWidget(box, 0, 0)
        badge = QLabel(_COST_LABELS[level])
        badge.setObjectName("moduleCost")
        badge.setProperty('level', level.replace(' ', '-'))
        badge.setToolTip(cost_text)
        grid.addWidget(badge, 0, 1, Qt.AlignRight | Qt.AlignVCenter)
        note = QLabel(f"{description} <i>{cost_text}</i>")
        note.setObjectName("analysisModuleNote")
        note.setWordWrap(True)
        note.setTextFormat(Qt.RichText)
        note.setIndent(22)
        grid.addWidget(note, 1, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        reason = self.unavailable.get(key)
        if reason:
            box.setEnabled(False)
            box.setToolTip(reason)
            why = QLabel(reason)
            why.setObjectName("moduleUnavailable")
            why.setWordWrap(True)
            why.setIndent(22)
            grid.addWidget(why, 2, 0, 1, 2)
            note.setEnabled(False)
        layout.addWidget(row)
        self._notes[key] = note
        return box

    def _carve_options(self):
        self.carve_options = QWidget()
        self.carve_options.setObjectName("moduleCarveOptions")
        options = QHBoxLayout(self.carve_options)
        options.setContentsMargins(22, 0, 0, 6)
        options.addWidget(QLabel("Look for"))
        self.carve_types = MultiSelectButton(CARVABLE_TYPES, self,
                                             noun="types",
                                             categories=CARVE_CATEGORIES)
        self.carve_types.set_selected(CARVABLE_TYPES)
        self.carve_types.selectionChanged.connect(
            lambda _selected: self.changed.emit())
        options.addWidget(self.carve_types)
        self.unallocated_box = QCheckBox("Unallocated space only")
        self.unallocated_box.setChecked(True)
        self.unallocated_box.setToolTip(
            "Skip space that belongs to live files: they are already in the "
            "tree. Untick to search the whole image.")
        self.unallocated_box.toggled.connect(lambda _on: self._refresh())
        options.addWidget(self.unallocated_box)
        options.addStretch(1)
        return self.carve_options

    @property
    def carve_box(self):
        return self.boxes[MODULE_CARVE]

    # --- profiles and choices ------------------------------------------------

    def apply_profile(self, name):
        """Tick what a profile names (what can run of it)."""
        if name not in PROFILES:
            self._set_combo(CUSTOM)
            self._refresh()
            return
        self._applying = True
        try:
            for key, box in self.boxes.items():
                box.setChecked(key in PROFILES[name]
                               and key not in self.unavailable)
        finally:
            self._applying = False
        self._set_combo(name)
        self._refresh()

    def set_choice(self, choice):
        """Tick what a choice dict selects, showing its profile if it is
        exactly one."""
        choice = choice or {}
        keys = selected_keys(choice)
        self._applying = True
        try:
            for key, box in self.boxes.items():
                box.setChecked(key in keys and key not in self.unavailable)
        finally:
            self._applying = False
        if choice.get('carve_types'):
            self.carve_types.set_selected(
                [t.upper() for t in choice['carve_types']])
        self.unallocated_box.setChecked(choice.get('unallocated_only', True))
        self._set_combo(self._matching_profile())
        self._refresh()

    def profile(self):
        return self.profile_combo.currentData()

    def choice(self):
        """{'modules', 'index', 'activity', ..., 'carve_types',
        'unallocated_only', 'profile'} -- evidence is the host's to add."""
        on = {key for key, box in self.boxes.items()
              if box.isChecked() and box.isEnabled()}
        out = {'modules': [key for key in MODULES if key in on]}
        for key in JOB_MODULES:
            out[key] = key in on
        out['carve_types'] = ([t.lower() for t in self.carve_types.selected()]
                              if MODULE_CARVE in on else [])
        out['unallocated_only'] = self.unallocated_box.isChecked()
        out['profile'] = self.profile()
        return out

    def any_selected(self):
        return any(box.isChecked() and box.isEnabled()
                   for box in self.boxes.values())

    def set_evidence_size(self, total_bytes):
        """The evidence's size, so the summary can say what carving reads."""
        self._evidence_bytes = total_bytes
        self._refresh()

    def summary_text(self):
        on = [key for key, box in self.boxes.items()
              if box.isChecked() and box.isEnabled()]
        if not on:
            return "Nothing selected: the evidence opens for browsing only."
        levels = {DESCRIPTIONS[key][3] for key in on}
        parts = [f"{len(on)} module{'s' if len(on) != 1 else ''}"]
        if EVERY_FILE in levels:
            parts.append("reads every file in full")
        else:
            parts.append("reads only what each module needs")
        if WHOLE_IMAGE in levels:
            where = ("unallocated space" if self.unallocated_box.isChecked()
                     else "the whole image")
            if self._evidence_bytes:
                from trace_app.infra.utils import FileSystemUtils
                size = FileSystemUtils.get_readable_size(self._evidence_bytes)
                parts.append(f"carving reads {where} (up to {size})")
            else:
                parts.append(f"carving reads {where}")
        return ' · '.join(parts).capitalize() + '.'

    # --- internals ----------------------------------------------------------

    def _matching_profile(self):
        on = {key for key, box in self.boxes.items() if box.isChecked()}
        for name, keys in PROFILES.items():
            if on == {k for k in keys if k not in self.unavailable}:
                return name
        return CUSTOM

    def _set_combo(self, name):
        index = self.profile_combo.findData(name)
        self.profile_combo.blockSignals(True)
        self.profile_combo.setCurrentIndex(index)
        self.profile_combo.blockSignals(False)
        self.profile_note.setText(PROFILE_LABELS[name][1])

    def _profile_chosen(self, _index):
        name = self.profile_combo.currentData()
        if name == CUSTOM:
            self.profile_note.setText(PROFILE_LABELS[CUSTOM][1])
            return
        self.apply_profile(name)

    def _box_toggled(self, _on):
        if self._applying:
            return
        self._set_combo(self._matching_profile())
        self._refresh()

    def _refresh(self):
        self.summary.setText(self.summary_text())
        self.changed.emit()


class AnalysisModulesDialog(QDialog):
    """Ask which analysis modules to run, and against which evidence."""

    def __init__(self, parent=None, preselected=None, evidence=None):
        super().__init__(parent)
        self.setWindowTitle("Analysis Modules")
        self.setObjectName("analysisModulesDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(640)

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

        # What cannot run, from the host (the window knows the case's rule
        # libraries); libmagic is checked here, as it always was.
        unavailable = dict(choice.get('unavailable') or {})
        if magic_reader() is None:
            unavailable.setdefault(MODULE_MAGIC, (
                "libmagic is not available on this system, so file type "
                "detection cannot run."))
        for key, flag, reason_key, fallback in (
                (MODULE_HASHSETS, 'hashsets_available', None,
                 "No hash sets are in use for this case. Tools ▸ Hash Sets "
                 "imports them and switches them on."),
                (MODULE_YARA, 'yara_available', 'yara_reason',
                 "No YARA rules are in use for this case (Tools ▸ YARA "
                 "Rules)."),
                (MODULE_SIGMA, 'sigma_available', 'sigma_reason',
                 "No Sigma rules are in use for this case (Tools ▸ Sigma "
                 "Rules)."),
                (MODULE_KEYWORDS, 'keywords_available', None,
                 "No keyword lists are in use for this case. Tools ▸ "
                 "Keyword Lists imports or types them.")):
            if not choice.get(flag, True):
                unavailable.setdefault(
                    key, (choice.get(reason_key) if reason_key else None)
                    or fallback)

        self.selector = ModuleSelector(self, unavailable)
        if choice.get('profile') in PROFILES:
            self.selector.apply_profile(choice['profile'])
        else:
            self.selector.set_choice(choice)
        # As tall as the list where the screen allows, scrolling where not.
        screen = self.screen().availableGeometry().height() \
            if self.screen() is not None else 800
        self.selector.scroll.setMinimumHeight(
            max(260, min(620, int(screen * 0.88) - 260)))
        layout.addWidget(self.selector, 1)

        # The old attribute names, which callers and tests address.
        self.boxes = self.selector.boxes
        for name, key in (('index_box', MODULE_INDEX),
                          ('activity_box', MODULE_ACTIVITY),
                          ('ntfs_box', MODULE_NTFS),
                          ('fstimes_box', MODULE_FSTIMES),
                          ('hash_sets_box', MODULE_HASHSETS),
                          ('persistence_box', MODULE_PERSISTENCE),
                          ('deleted_box', MODULE_DELETED),
                          ('thumbnails_box', MODULE_THUMBNAILS),
                          ('yara_box', MODULE_YARA),
                          ('sigma_box', MODULE_SIGMA),
                          ('keywords_box', MODULE_KEYWORDS),
                          ('carve_box', MODULE_CARVE)):
            setattr(self, name, self.boxes[key])
        self.carve_types = self.selector.carve_types
        self.unallocated_box = self.selector.unallocated_box
        self.carve_options = self.selector.carve_options

        footer = QLabel(
            "You can run these later from Analysis ▸ Run Analysis Modules, "
            "and cancel a run at any time from the status bar.")
        footer.setObjectName("analysisModulesFooter")
        footer.setWordWrap(True)
        # A wrapped label under-reports its height to a squeezed layout,
        # which then draws the list over it.
        footer.setMinimumHeight(footer.heightForWidth(600))
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

        self.selector.changed.connect(self._update_run_button)
        self._update_run_button()

    def _update_run_button(self):
        chosen = self.selector.any_selected()
        self.run_button.setEnabled(chosen)
        self.run_button.setToolTip(
            '' if chosen else "Select at least one module, or just browse.")

    def _accept(self):
        target = self.evidence_combo.currentData()
        self.choice = dict(self.selector.choice(),
                           evidence_ids=None if target is None else [target])
        remember_profile(self.choice['profile'])
        self.accept()


def choose_modules(parent=None, preselected=None, evidence=None):
    """Ask; return the choice, or None for "just browse".

    `evidence` is [(evidence_id, name)]. The choice is a dict: `modules`
    (analysis.MODULES to run), `evidence_ids` (None for every image),
    `index` (build the search index), `activity` (read Windows activity and
    browser history), `ntfs` ($MFT, change journal, streams), the other
    JOB_MODULES as booleans, `carve_types` (empty: no carving),
    `unallocated_only` and `profile`.
    """
    dialog = AnalysisModulesDialog(parent, preselected, evidence)
    if dialog.exec() == QDialog.Accepted:
        return dialog.choice
    return None

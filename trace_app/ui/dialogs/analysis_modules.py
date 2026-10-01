"""Choosing what to run before the evidence is opened.

These modules read every file on the image, which takes minutes rather than
seconds, so they are not something to discover halfway through an examination.
The dialog asks once, at the point a case is opened, and then gets out of the
way: the chosen modules run in the background while the examiner works, and
the findings appear as they arrive.

Nothing here is mandatory. "Just browse" is a first-class answer -- a quick
look at an image should not cost a full pass over it.
"""

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QLabel,
                               QVBoxLayout)

from trace_app.core.analysis import (MODULE_AUTHORS, MODULE_ENTROPY,
                                     MODULE_HASH, MODULE_HIDDEN, MODULE_MAGIC,
                                     MODULE_PHOTO, magic_reader)
from trace_app.ui import icons

logger = logging.getLogger('TRACE.AnalysisDialog')

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
        "MD5 and SHA-256 for every file, so the case can be searched by hash "
        "and identical copies grouped together.",
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
        "photo's EXIF. Photos that record where they were taken are listed "
        "as findings.",
        "Fast: reads photos only."),
    MODULE_AUTHORS: (
        "Document authors",
        "Author, last saved by, company, application and template from "
        "Office, OpenDocument and PDF files — who made a document, and with "
        "what.",
        "Fast: reads documents only."),
}


class AnalysisModulesDialog(QDialog):
    """Ask which analysis modules to run against the evidence."""

    def __init__(self, parent=None, preselected=None):
        super().__init__(parent)
        self.setWindowTitle("Analysis Modules")
        self.setObjectName("analysisModulesDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)

        self.selected = []

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

        # Magic detection is the one module with a system dependency. Offering
        # a tick box that silently does nothing is worse than saying why it is
        # unavailable.
        magic_available = magic_reader() is not None

        self.boxes = {}
        preselected = set(preselected or ())
        for key, (title, description, cost) in _DESCRIPTIONS.items():
            box = QCheckBox(title)
            box.setObjectName("analysisModuleCheck")
            box.setChecked(key in preselected)
            if key == MODULE_MAGIC and not magic_available:
                box.setChecked(False)
                box.setEnabled(False)
                box.setToolTip(
                    "libmagic is not available on this system, so file type "
                    "detection cannot run.")
            layout.addWidget(box)
            self.boxes[key] = box

            note = QLabel(f"{description}  <i>{cost}</i>")
            note.setObjectName("analysisModuleNote")
            note.setWordWrap(True)
            note.setTextFormat(Qt.RichText)
            note.setIndent(22)
            layout.addWidget(note)

        footer = QLabel(
            "You can run these later from Analysis ▸ Run Analysis Modules, "
            "and cancel a run at any time from the status bar.")
        footer.setObjectName("analysisModulesFooter")
        footer.setWordWrap(True)
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

    def _update_run_button(self):
        chosen = any(box.isChecked() for box in self.boxes.values())
        self.run_button.setEnabled(chosen)
        self.run_button.setToolTip(
            '' if chosen else "Select at least one module, or just browse.")

    def _accept(self):
        self.selected = [key for key, box in self.boxes.items()
                         if box.isChecked()]
        self.accept()


def choose_modules(parent=None, preselected=None):
    """Ask, and return the chosen modules. Empty means browse only."""
    dialog = AnalysisModulesDialog(parent, preselected)
    if dialog.exec() == QDialog.Accepted:
        return dialog.selected
    return []

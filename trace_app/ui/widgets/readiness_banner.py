"""What an export will lack because a scan has not run
(core/export_readiness), said before the export starts.

`ReadinessBanner` is the card -- one line per evidence item and module --
for a dialog that already exists (the Project VICS export's).
`ReadinessDialog` asks on its own, for exports with no dialog of their
own before the file name (DFXML, CASE/UCO, the Timeline) and before the
report's: Run Missing Scans, Then Export / Export Anyway / Cancel."""

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFrame, QLabel, QPushButton, QVBoxLayout)

from trace_app.core import export_readiness
from trace_app.ui.widgets.dialog_page import PageDialog

#: Where the examiner can run the scans by hand.
WHERE = "Analysis ▸ Run Analysis Modules"


def module_title(module):
    """'File carving', 'Hashes'... as the Analysis Modules dialog names
    the module."""
    from trace_app.ui.dialogs.analysis_modules import DESCRIPTIONS
    entry = DESCRIPTIONS.get(module)
    return entry[0] if entry else module


_STATES = {export_readiness.NOT_RUN: "not run",
           export_readiness.CANCELLED: "cancelled before it finished",
           export_readiness.FAILED: "failed",
           export_readiness.RUNNING: "still running",
           export_readiness.LESS: "ran with less"}


def gap_lines(gaps):
    """[(evidence name, [line])] in the order found: modules missing in
    the same way, for the same reason, share a line (a report draws on
    every module)."""
    grouped = {}
    for gap in gaps:
        grouped.setdefault(gap.evidence, {}).setdefault(
            (gap.state, gap.why), []).append(module_title(gap.module))
    return [(evidence, [f"{', '.join(titles)}: {_STATES[state]} — "
                        f"{why}" for (state, why), titles in lines.items()])
            for evidence, lines in grouped.items()]


def gap_html(gaps):
    parts = []
    for evidence, lines in gap_lines(gaps):
        parts.append(f"<b>{html.escape(evidence)}</b><ul style="
                     f"'margin-top:2px; margin-bottom:6px;'>" + ''.join(
                         f"<li>{html.escape(line)}</li>" for line in lines)
                     + "</ul>")
    return ''.join(parts)


def intro_text(kind):
    name = export_readiness.EXPORT_NAMES[kind]
    return (f"The {name} reads what TRACE's scans found. For the most "
            f"complete export, run these first, or run them yourself from "
            f"{WHERE}.")


class ReadinessBanner(QFrame):
    """A warning card listing the gaps; hidden when there are none."""

    def __init__(self, kind, parent=None):
        super().__init__(parent)
        self.kind = kind
        self.gaps = []
        self.setObjectName("readinessBanner")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        self.title = QLabel("Some scans this export draws on have not run")
        self.title.setObjectName("readinessTitle")
        layout.addWidget(self.title)
        self.intro = QLabel(intro_text(kind))
        self.intro.setObjectName("readinessIntro")
        self.intro.setWordWrap(True)
        layout.addWidget(self.intro)
        self.body = QLabel()
        self.body.setObjectName("readinessBody")
        self.body.setWordWrap(True)
        self.body.setTextFormat(Qt.RichText)
        layout.addWidget(self.body)
        self.setVisible(False)

    def set_gaps(self, gaps):
        self.gaps = list(gaps)
        self.body.setText(gap_html(self.gaps))
        self.setVisible(bool(self.gaps))

    def runnable(self):
        """Whether running something would close a gap (a scan still
        running closes by itself)."""
        return bool(export_readiness.missing_modules(self.gaps))


#: What ReadinessDialog.exec's choice was.
RUN_FIRST, EXPORT_NOW = 'run first', 'export now'


class ReadinessDialog(PageDialog):
    """Asks before an export when scans it draws on have not run.
    `choice` after exec: RUN_FIRST, EXPORT_NOW or None (cancelled)."""

    def __init__(self, kind, gaps, parent=None):
        name = export_readiness.EXPORT_NAMES[kind]
        super().__init__(f"Before the {name}", intro_text(kind),
                         parent=parent, object_name="readinessDialog")
        self.choice = None
        self.banner = ReadinessBanner(kind)
        self.banner.title.hide()
        self.banner.intro.hide()
        self.banner.set_gaps(gaps)
        self.body.addWidget(self.banner)
        self.finish_body()
        self.set_footer_hint("Scans run on the job bar; the export follows "
                             "the last of them.")
        self.run_button = QPushButton("Run Missing Scans, Then Export")
        self.run_button.setObjectName("readinessRun")
        self.run_button.setEnabled(self.banner.runnable())
        self.run_button.clicked.connect(lambda: self._choose(RUN_FIRST))
        self.add_button(self.run_button)
        self.now_button = QPushButton("Export Anyway")
        self.now_button.clicked.connect(lambda: self._choose(EXPORT_NOW))
        self.add_button(self.now_button)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.add_button(cancel)
        self.run_button.setDefault(True)
        self.setMinimumWidth(560)

    def _choose(self, choice):
        self.choice = choice
        self.accept()

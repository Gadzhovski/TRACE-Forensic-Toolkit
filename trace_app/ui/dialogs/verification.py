"""Evidence verification: the job that hashes, and the dialog that shows
what a check found.

There is one way evidence is verified: `EvidenceVerifyWorker` hashes it
in full on a thread (core/case.hash_evidence), and the window judges and
records the run on its own thread (Case.apply_verification, or
core/case.verdict in quick triage, where nothing is recorded). The
dialog only shows the outcome; closing it writes nothing. An earlier
dialog computed and judged hashes itself and saved whatever it had just
computed as the case's reference when it was closed -- so a mismatch,
once seen, became the baseline the next check matched.
"""

import logging

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QApplication, QDialog, QHBoxLayout, QLabel,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QHeaderView)

from trace_app.ui import icons

logger = logging.getLogger('TRACE.Verify')


class EvidenceVerifyWorker(QThread):
    """Hash one piece of evidence in full for the job bar.

    Only the reading happens here; the verdict is recorded on the UI
    thread, which owns the case's database connection. Cancel is
    cooperative: the next progress report stops it.
    """

    #: (bytes done, bytes total) -- objects, as images pass 2**31 bytes.
    progressed = Signal(object, object)
    #: {'row', 'results', 'cancelled'}: results are calculate_hashes' (or
    #: an outcome with a 'status' when there was nothing to hash).
    verified = Signal(dict)

    def __init__(self, row, parent=None):
        super().__init__(parent)
        self.row = dict(row)
        self._stop = False
        self._last = -1

    def stop(self):
        self._stop = True

    def _progress(self, done, total):
        from trace_app.core.image_handler import HashingCancelled
        if self._stop:
            raise HashingCancelled()
        if total:
            percent = int(done * 100 / total)
            if percent != self._last:
                self._last = percent
                self.progressed.emit(done, total)

    def run(self):
        from trace_app.core.case import hash_evidence
        from trace_app.core.image_handler import HashingCancelled
        out = {'row': self.row, 'cancelled': False, 'results': None}
        try:
            out['results'] = hash_evidence(self.row, self._progress)
        except HashingCancelled:
            out['cancelled'] = True
        except Exception as exc:
            logger.exception("Verifying %s failed", self.row.get('path'))
            out['results'] = {'path': self.row.get('path'),
                              'error': str(exc)}
        self.verified.emit(out)


def summary_rows(row, results, outcome):
    """[(algorithm, this check, recorded by the case, stored with the
    image or its acquisition, result)] for the hashes a check involved."""
    from trace_app.core.case import HASH_NAMES, acquisition_hashes
    results = results or {}
    stored = acquisition_hashes(row, results)
    rows = []
    for name in HASH_NAMES:
        computed = (results.get(f'computed_{name}') or '').lower()
        recorded = ((row or {}).get(name) or '').lower()
        kept = stored.get(name, '')
        if not (computed or recorded or kept):
            continue
        against = [v for v in (recorded, kept) if v]
        if not computed:
            result = 'not computed' if against else ''
        elif not against:
            result = 'nothing to compare'
        elif all(v == computed for v in against):
            result = 'match'
        else:
            result = 'DIFFERENT'
        rows.append((name.upper(), computed, recorded, kept, result))
    return rows


class VerificationDialog(QDialog):
    """What one check of one piece of evidence found -- read-only.

    `row` is the case's evidence row (or {'path', 'display_name'} in
    quick triage), `results` the hashing run (None when only the case's
    record is known), `outcome` the verdict {status, detail}, `history`
    the case's earlier checks, newest first. "Verify Again" emits
    `verify_again`; nothing here writes to the case.
    """

    verify_again = Signal()

    def __init__(self, row, results, outcome, history=(), checked=None,
                 parent=None):
        super().__init__(parent)
        from trace_app.ui.viewers.case_panel import (STATUS_ICON,
                                                     STATUS_TEXT,
                                                     STATUS_TONE)
        from trace_app.ui.viewers.virustotal import verdict_brush
        from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
        self.setObjectName('verificationDialog')
        name = row.get('display_name') or row.get('path')
        self.setWindowTitle(f"Verification -- {name}")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.resize(820, 520)
        status = outcome.get('status')
        self._text = []

        layout = QVBoxLayout(self)
        heading = QLabel(name)
        heading.setObjectName('subtitleLabel')
        layout.addWidget(heading)
        path = QLabel(row.get('path', ''))
        path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path.setWordWrap(True)
        layout.addWidget(path)

        verdict = QTableWidget(1, 1)
        verdict.setObjectName('verificationStatus')
        verdict.horizontalHeader().hide()
        verdict.verticalHeader().hide()
        verdict.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        verdict.setItemDelegate(NoFocusDelegate(verdict))
        cell = QTableWidgetItem(STATUS_TEXT.get(status, status or ''))
        if STATUS_TONE.get(status):
            cell.setForeground(verdict_brush(STATUS_TONE[status]))
        if status in STATUS_ICON:
            cell.setIcon(icons.icon(STATUS_ICON[status]))
        verdict.setItem(0, 0, cell)
        verdict.setFixedHeight(verdict.rowHeight(0) + 4)
        verdict.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(verdict)

        detail = QLabel(outcome.get('detail') or '')
        detail.setWordWrap(True)
        detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(detail)
        self._text += [f"Evidence: {name}", f"Path: {row.get('path', '')}",
                       f"Status: {STATUS_TEXT.get(status, status)}",
                       f"Detail: {outcome.get('detail') or ''}"]

        facts = []
        if results and results.get('size'):
            facts.append(f"Bytes hashed: {results['size']:,}")
        if checked:
            facts.append(f"Checked: {checked} UTC")
        if row.get('stored_source'):
            facts.append(f"Acquisition hashes from: {row['stored_source']}")
        if facts:
            line = QLabel('   ·   '.join(facts))
            layout.addWidget(line)
            self._text += facts

        hashes = summary_rows(row, results, outcome)
        table = QTableWidget(len(hashes), 5)
        table.setObjectName('verificationHashes')
        table.setHorizontalHeaderLabels(
            ["Hash", "This check", "Recorded by the case",
             "Stored with the image / acquisition", "Result"])
        table.verticalHeader().hide()
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setItemDelegate(NoFocusDelegate(table))
        for r, values in enumerate(hashes):
            for c, value in enumerate(values):
                item = QTableWidgetItem(value or '—')
                if c == 4 and value in ('match', 'DIFFERENT'):
                    item.setForeground(verdict_brush(
                        'clean' if value == 'match' else 'malicious'))
                table.setItem(r, c, item)
            self._text.append(' | '.join(v or '-' for v in values))
        table.resizeColumnsToContents()
        layout.addWidget(table)

        if history:
            label = QLabel("Every check of this evidence, newest first")
            layout.addWidget(label)
            past = QTableWidget(len(history), 3)
            past.setObjectName('verificationHistory')
            past.setHorizontalHeaderLabels(["When (UTC)", "Status",
                                            "Detail"])
            past.verticalHeader().hide()
            past.setEditTriggers(QTableWidget.NoEditTriggers)
            past.setItemDelegate(NoFocusDelegate(past))
            self._text.append("History:")
            for r, entry in enumerate(history):
                state = entry.get('status')
                cells = [entry.get('utc') or '',
                         STATUS_TEXT.get(state, state or ''),
                         entry.get('detail') or '']
                for c, value in enumerate(cells):
                    item = QTableWidgetItem(value)
                    if c == 1 and STATUS_TONE.get(state):
                        item.setForeground(verdict_brush(STATUS_TONE[state]))
                    past.setItem(r, c, item)
                self._text.append('  ' + ' | '.join(cells))
            past.resizeColumnsToContents()
            layout.addWidget(past)

        buttons = QHBoxLayout()
        copy = QPushButton("Copy")
        icons.apply_to(copy, icons.COPY)
        copy.clicked.connect(self.copy_text)
        again = QPushButton("Verify Again")
        icons.apply_to(again, icons.REFRESH)
        again.clicked.connect(self._again)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        buttons.addWidget(copy)
        buttons.addStretch()
        buttons.addWidget(again)
        buttons.addWidget(close)
        layout.addLayout(buttons)

    def text(self):
        return '\n'.join(self._text)

    def copy_text(self):
        QApplication.clipboard().setText(self.text())

    def _again(self):
        self.verify_again.emit()
        self.accept()

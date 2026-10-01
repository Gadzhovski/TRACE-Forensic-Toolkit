"""VirusTotal: the worker that asks, and the tab that shows the answers.

This used to be a permanent viewer tab with two buttons that acted on
whichever file happened to be selected. It MD5-hashed every file the examiner
clicked whether they wanted VirusTotal or not, made its requests on the UI
thread, and kept only one report -- checking a second file threw the first
away.

Now a lookup starts from the file, by right-click, and this tab appears when
there is something to show. It keeps every lookup made in the case, so the
examiner can compare files and come back to a result after reopening.
"""

import hashlib
import logging
import queue
import threading
import webbrowser
from datetime import datetime, timezone

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QPushButton, QSizePolicy, QSplitter,
                               QStackedWidget,
                               QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core import virustotal as vt
from trace_app.core.image_handler import ImageHandler
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.property_table import PropertyTable
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.VirusTotal')

METHOD_HASH = 'hash'
METHOD_UPLOAD = 'upload'

#: States an entry passes through before it has a result.
STATE_QUEUED = 'queued'
STATE_RUNNING = 'running'

#: Read size when streaming a file out of the image to hash it.
_BLOCK = 1024 * 1024


# --- verdicts --------------------------------------------------------------

def verdict_state(entry):
    """The one word the QSS and the colour tables key on."""
    status = entry.get('status')
    if status in (STATE_QUEUED, STATE_RUNNING, vt.STATUS_PENDING):
        return 'pending'
    if status == vt.STATUS_FOUND:
        report = entry.get('report') or {}
        stats = report.get('stats') or {}
        if stats.get('malicious'):
            return 'malicious'
        if entry.get('positives'):
            return 'suspicious'
        return 'clean'
    if status == vt.STATUS_NOT_FOUND:
        return 'unknown'
    return 'error'


def verdict_text(entry):
    """Short form, for a table cell: '3/72', 'Not found', 'Checking…'."""
    status = entry.get('status')
    if status == STATE_QUEUED:
        return 'Queued'
    if status == STATE_RUNNING:
        return entry.get('progress') or 'Checking…'
    if status == vt.STATUS_PENDING:
        return 'Still scanning'
    if status == vt.STATUS_FOUND:
        return f"{entry.get('positives') or 0}/{entry.get('total') or 0}"
    if status == vt.STATUS_NOT_FOUND:
        return 'Not found'
    return 'Error'


#: Text colour for a verdict, per theme. Item text is painted by the view, not
#: the stylesheet, so it cannot take a QSS state the way a label does. Each
#: pair is chosen to read on that theme's table background -- the listing's
#: #C62828 is legible on white and nearly lost on #2E2E2E.
_TONES = {
    'light': {'malicious': '#C62828', 'suspicious': '#B45309',
              'clean': '#1A7F37', 'unknown': '#6B7480', 'pending': '#6B7480',
              'error': '#B45309'},
    'dark': {'malicious': '#FF6B6B', 'suspicious': '#E3A008',
             'clean': '#3FB950', 'unknown': '#9AA0A6', 'pending': '#9AA0A6',
             'error': '#E3A008'},
}


def verdict_brush(state):
    tones = _TONES.get(icons.current_theme(), _TONES['light'])
    return QBrush(QColor(tones.get(state, tones['unknown'])))


def _when(utc_text):
    """'2026-10-01T13:06:41+00:00' as local '2026-10-01 16:06'."""
    if not utc_text:
        return ''
    try:
        moment = datetime.fromisoformat(utc_text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone().strftime('%Y-%m-%d %H:%M')
    except ValueError:
        return utc_text


# --- the worker ------------------------------------------------------------

class VirusTotalWorker(QThread):
    """Works through queued lookups and uploads, one at a time.

    One worker for all of them, so every request draws on the same rate
    limiter in order: two workers would both believe they had the minute's
    four requests. Jobs added while it runs join its queue.

    The case is not touched from here -- a SQLite connection belongs to the
    thread that opened it. Results go back by signal and the UI thread
    records them.
    """

    #: (job key, text) while a job is in progress.
    progressed = Signal(str, str)
    #: (job key) when a job is picked up.
    job_started = Signal(str)
    #: (job, result, sent) when a job ends. `sent` is whether anything
    #: reached VirusTotal, which is what decides the audit line.
    job_finished = Signal(dict, dict, bool)
    #: Text for the panel and status bar while waiting on the rate limit.
    waiting = Signal(str)

    def __init__(self, api_key, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self._queue = queue.Queue()
        self._lock = threading.Lock()
        self._closing = False
        self._stop = False
        self._handlers = {}

    def add(self, jobs):
        """Queue more work. False if this worker is already winding down.

        The check and the put happen under the same lock the run loop takes
        before deciding it has nothing left, so a job cannot be queued into a
        worker that has just decided to exit.
        """
        with self._lock:
            if self._closing:
                return False
            for job in jobs:
                self._queue.put(job)
            return True

    def stop(self):
        self._stop = True

    def _next(self):
        with self._lock:
            try:
                return self._queue.get_nowait()
            except queue.Empty:
                self._closing = True
                return None

    def run(self):
        current_key = {'key': ''}
        client = None
        try:
            client = vt.VirusTotalClient(
                self.api_key,
                should_stop=lambda: self._stop,
                on_wait=lambda seconds: self.waiting.emit(
                    f"Waiting {seconds:.0f}s for VirusTotal's rate limit "
                    f"(4 requests a minute on a free key)"))
        except vt.VirusTotalError as exc:
            self._drain(str(exc))
            return

        try:
            while not self._stop:
                job = self._next()
                if job is None:
                    break
                current_key['key'] = job['key']
                self.job_started.emit(job['key'])
                self._run_job(client, job)
        finally:
            self._drain("Cancelled before it was sent." if self._stop else '')
            for handler in self._handlers.values():
                try:
                    handler.close_resources()
                except Exception:
                    pass

    def _drain(self, reason):
        """Close out whatever is still queued, so no entry stays 'Queued'."""
        with self._lock:
            self._closing = True
            pending = []
            while True:
                try:
                    pending.append(self._queue.get_nowait())
                except queue.Empty:
                    break
        for job in pending:
            self.job_finished.emit(job, {'status': vt.STATUS_ERROR,
                                         'sha256': job.get('sha256') or '',
                                         'error': reason or 'Not run.'},
                                   False)

    def _run_job(self, client, job):
        key = job['key']
        sent = False
        try:
            if job['method'] == METHOD_UPLOAD:
                self.progressed.emit(key, 'Reading file')
                data = self._read(job)
                sha256 = hashlib.sha256(data).hexdigest()
                job['sha256'] = sha256
                sent = True
                result = client.upload(
                    data, job.get('name') or sha256, sha256,
                    on_progress=lambda text: self.progressed.emit(key, text))
            else:
                sha256 = job.get('sha256')
                if not sha256:
                    self.progressed.emit(key, 'Hashing')
                    sha256 = self._hash(job)
                    job['sha256'] = sha256
                self.progressed.emit(key, 'Asking VirusTotal')
                sent = True
                result = client.lookup(sha256)
        except vt.Cancelled:
            self._stop = True
            result = {'status': vt.STATUS_ERROR,
                      'sha256': job.get('sha256') or '',
                      'error': 'Cancelled.'}
            # Cancelled while waiting for the rate limit means the request
            # was never made.
            sent = False
        except (vt.AuthError, vt.QuotaExhausted) as exc:
            # Nothing later in the queue can succeed either; say so for each
            # rather than spending requests to find out.
            self.job_finished.emit(job, {'status': vt.STATUS_ERROR,
                                         'sha256': job.get('sha256') or '',
                                         'error': str(exc)}, False)
            self._drain(str(exc))
            return
        except Exception as exc:
            logger.error("VirusTotal %s of %s failed: %s", job['method'],
                         job.get('name'), exc)
            result = {'status': vt.STATUS_ERROR,
                      'sha256': job.get('sha256') or '', 'error': str(exc)}
        self.job_finished.emit(job, result, sent)

    # --- reading evidence -------------------------------------------------

    def _file(self, job):
        path = job['image_path']
        handler = self._handlers.get(path)
        if handler is None:
            # Opened here, not borrowed: a pytsk3 handle opened on the UI
            # thread reads nothing useful from this one.
            handler = ImageHandler(path)
            if not handler.load_image():
                raise vt.VirusTotalError(f"Could not open {path}.")
            self._handlers[path] = handler
        fs = handler.get_fs_info(job['start_offset'])
        if fs is None:
            raise vt.VirusTotalError("Could not read the volume holding "
                                     "this file.")
        file_obj = fs.open_meta(inode=job['inode'])
        return file_obj, int(file_obj.info.meta.size or 0)

    def _blocks(self, job):
        file_obj, size = self._file(job)
        if size == 0:
            raise vt.VirusTotalError("The file is empty; there is nothing "
                                     "to check.")
        for offset in range(0, size, _BLOCK):
            if self._stop:
                raise vt.Cancelled("Cancelled.")
            block = file_obj.read_random(offset, min(_BLOCK, size - offset))
            if not block:
                break
            yield block

    def _hash(self, job):
        digest = hashlib.sha256()
        for block in self._blocks(job):
            digest.update(block)
        return digest.hexdigest()

    def _read(self, job):
        _, size = self._file(job)
        if size > vt.MAX_UPLOAD:
            raise vt.VirusTotalError(
                f"VirusTotal accepts files up to "
                f"{vt.MAX_UPLOAD // (1024 * 1024)} MB; this one is "
                f"{size // (1024 * 1024)} MB.")
        return b''.join(self._blocks(job))


# --- the tab -----------------------------------------------------------------

class VirusTotalPanel(QWidget):
    """Every lookup made in the case, and the report for the one selected."""

    #: An entry the examiner wants checked again, or uploaded.
    lookup_requested = Signal(dict)
    upload_requested = Signal(dict)
    #: An entry whose file should be shown in the listing.
    reveal_requested = Signal(dict)
    #: The examiner pressed Cancel.
    cancel_requested = Signal()

    _HISTORY_COLUMNS = ['File', 'Verdict', 'Method', 'Checked']
    _ENGINE_COLUMNS = ['Engine', 'Verdict', 'Result', 'Version', 'Updated']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("vtPanel")
        self._entries = []          # newest first
        self._has_key = False
        self._busy_text = ''

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)

        # --- header: wordmark, status, cancel ---
        header = QHBoxLayout()
        header.setSpacing(8)
        self.wordmark = icons.apply_svg(QSvgWidget(), icons.VIRUSTOTAL_LOGO)
        self.wordmark.setFixedSize(94, 18)
        self.wordmark.setToolTip("virustotal.com")
        self.wordmark.setCursor(Qt.PointingHandCursor)
        self.wordmark.mousePressEvent = (
            lambda _event: webbrowser.open("https://www.virustotal.com"))
        header.addWidget(self.wordmark)

        self.status_label = QLabel()
        self.status_label.setObjectName("vtStatus")
        header.addWidget(self.status_label, 1)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setFixedHeight(CONTROL_HEIGHT)
        self.cancel_button.clicked.connect(self.cancel_requested.emit)
        self.cancel_button.setVisible(False)
        header.addWidget(self.cancel_button)
        layout.addLayout(header)

        # --- body: empty state, or history beside report ---
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self.empty_label = QLabel()
        self.empty_label.setObjectName("emptyStateLabel")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.stack.addWidget(self.empty_label)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("vtSplitter")
        splitter.setChildrenCollapsible(False)
        self.stack.addWidget(splitter)

        self.history = self._table(self._HISTORY_COLUMNS, "vtHistory")
        self.history.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history.itemSelectionChanged.connect(self._show_selected)
        self.history.itemDoubleClicked.connect(
            lambda _item: self._emit_selected(self.reveal_requested))
        splitter.addWidget(self.history)

        splitter.addWidget(self._build_report())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 5)
        # Wide enough for all four history columns; the splitter scales these
        # to whatever width the dock actually has.
        splitter.setSizes([400, 1000])

        self._update_status()
        self._refresh_body()

    # --- construction -----------------------------------------------------

    def _table(self, headers, name):
        table = QTableWidget(0, len(headers))
        table.setObjectName(name)
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        # Paints a cell's own colour, which the theme's item colour would
        # otherwise override -- the verdicts are the point of both tables.
        table.setItemDelegate(NoFocusDelegate(table))
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        return table

    def _build_report(self):
        report = QWidget()
        report.setObjectName("vtReport")
        layout = QVBoxLayout(report)
        layout.setContentsMargins(10, 2, 0, 0)
        layout.setSpacing(6)

        # The verdict, as large as anything in the dock: it is the answer,
        # and everything below it is the working.
        top = QHBoxLayout()
        top.setSpacing(12)
        self.score_label = QLabel()
        self.score_label.setObjectName("vtScore")
        self.score_label.setAlignment(Qt.AlignCenter)
        # Its own height, not the row's: a wrapped headline beside it should
        # not stretch the badge into a tall block.
        self.score_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        top.addWidget(self.score_label, 0, Qt.AlignVCenter)

        words = QVBoxLayout()
        words.setSpacing(0)
        self.verdict_label = QLabel()
        self.verdict_label.setObjectName("vtVerdict")
        self.detail_label = QLabel()
        self.detail_label.setObjectName("vtVerdictDetail")
        self.detail_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        # Wrapping, so a long file name or explanation gives way to the
        # buttons beside it instead of pushing them until their text clips.
        for label in (self.verdict_label, self.detail_label):
            label.setWordWrap(True)
            label.setMinimumWidth(120)
        words.addStretch(1)
        words.addWidget(self.verdict_label)
        words.addWidget(self.detail_label)
        words.addStretch(1)
        top.addLayout(words, 1)

        self.reveal_button = self._button(
            "Show File", icons.FORWARD,
            lambda: self._emit_selected(self.reveal_requested))
        self.again_button = self._button(
            "Check Again", icons.REFRESH,
            lambda: self._emit_selected(self.lookup_requested))
        self.upload_button = self._button(
            "Upload…", icons.UPLOAD,
            lambda: self._emit_selected(self.upload_requested))
        self.browser_button = self._button(
            "Open in VirusTotal", icons.EXTERNAL_LINK, self._open_in_browser)
        for button in (self.reveal_button, self.again_button,
                       self.upload_button, self.browser_button):
            top.addWidget(button, 0, Qt.AlignVCenter)
        layout.addLayout(top)

        self.report_tabs = QTabWidget()
        self.report_tabs.setObjectName("vtReportTabs")
        self.report_tabs.setDocumentMode(True)
        self.engine_table = self._table(self._ENGINE_COLUMNS, "vtEngines")
        self.engine_table.setSortingEnabled(True)
        self.report_tabs.addTab(self.engine_table, "Engines")
        self.details = PropertyTable("Property", "Value")
        self.report_tabs.addTab(self.details, "Details")
        # Remember an explicit choice of Details, so moving between results
        # does not keep flipping the examiner back to the engines.
        self._details_chosen = False
        self.report_tabs.tabBarClicked.connect(
            lambda index: setattr(self, '_details_chosen', index == 1))
        layout.addWidget(self.report_tabs, 1)
        return report

    def _button(self, text, icon_name, slot):
        button = QPushButton(text)
        button.setObjectName("vtActionButton")
        button.setIcon(icons.icon(icon_name))
        button.setIconSize(QSize(14, 14))
        button.setFixedHeight(CONTROL_HEIGHT)
        button.clicked.connect(slot)
        return button

    # --- state from the host ----------------------------------------------

    def set_has_key(self, has_key):
        self._has_key = bool(has_key)
        self._refresh_body()

    def set_entries(self, entries):
        """Replace the history, e.g. on opening a case. Newest first."""
        self._entries = list(entries)
        self._fill_history()
        self._refresh_body()

    def add_entries(self, entries):
        """New lookups go to the top, and the first of them is selected."""
        self._entries[0:0] = list(entries)
        self._fill_history()
        self._refresh_body()
        if entries:
            self.history.selectRow(0)

    def update_entry(self, key, **changes):
        for position, entry in enumerate(self._entries):
            if entry.get('key') == key:
                entry.update(changes)
                self._fill_history_row(position, entry)
                if self._selected_key() == key:
                    self._show_selected()
                return entry
        return None

    def entries(self):
        """Every entry, newest first."""
        return list(self._entries)

    def entry(self, key):
        return next((e for e in self._entries if e.get('key') == key), None)

    def set_busy(self, busy, text=''):
        self.cancel_button.setVisible(busy)
        self._busy_text = text if busy else ''
        self._update_status()

    def retheme(self):
        """Repaint the cells whose colour is chosen per theme."""
        self._fill_history()
        self._show_selected()

    # --- drawing ----------------------------------------------------------

    def _refresh_body(self):
        if self._entries:
            self.stack.setCurrentIndex(1)
            return
        if self._has_key:
            self.empty_label.setText(
                "No VirusTotal lookups yet.\n\nRight-click a file and choose "
                "VirusTotal ▸ Look Up Hash. Only the hash leaves this "
                "machine.")
        else:
            self.empty_label.setText(
                "No VirusTotal API key is set.\n\nAdd one under Options ▸ "
                "API Keys. A free key allows four lookups a minute.")
        self.stack.setCurrentIndex(0)
        self._update_status()

    def _update_status(self):
        busy = self._busy_text
        if busy:
            self.status_label.setText(busy)
            return
        done = [e for e in self._entries
                if e.get('status') not in (STATE_QUEUED, STATE_RUNNING)]
        flagged = sum(1 for e in done
                      if verdict_state(e) in ('malicious', 'suspicious'))
        if not done:
            self.status_label.setText('')
            return
        text = f"{len(done)} lookup{'s' if len(done) != 1 else ''}"
        if flagged:
            text += f" · {flagged} flagged"
        self.status_label.setText(text)

    def _fill_history(self):
        selected = self._selected_key()
        self.history.setRowCount(len(self._entries))
        for position, entry in enumerate(self._entries):
            self._fill_history_row(position, entry)
        fit_columns(self.history, {0: 260})
        self._update_status()
        if selected:
            self._select_key(selected)

    def _fill_history_row(self, position, entry):
        state = verdict_state(entry)
        method = 'Upload' if entry.get('method') == METHOD_UPLOAD else 'Hash'
        cells = [entry.get('name') or entry.get('sha256') or '',
                 verdict_text(entry), method, _when(entry.get('queried'))]
        for column, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if column == 0:
                item.setData(Qt.UserRole, entry.get('key'))
                item.setToolTip(entry.get('path') or '')
            if column == 1:
                item.setForeground(verdict_brush(state))
                if state == 'error':
                    item.setToolTip(entry.get('error') or '')
            self.history.setItem(position, column, item)
        self._update_status()

    def _selected_key(self):
        rows = self.history.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.history.item(rows[0].row(), 0)
        return item.data(Qt.UserRole) if item else None

    def _select_key(self, key):
        for row in range(self.history.rowCount()):
            item = self.history.item(row, 0)
            if item and item.data(Qt.UserRole) == key:
                self.history.selectRow(row)
                return

    def _emit_selected(self, signal):
        entry = self.entry(self._selected_key())
        if entry is not None:
            signal.emit(entry)

    def _open_in_browser(self):
        entry = self.entry(self._selected_key())
        if entry and entry.get('sha256'):
            webbrowser.open(vt.report_url(entry['sha256']))

    def _show_selected(self):
        entry = self.entry(self._selected_key())
        if entry is None and self._entries:
            entry = self._entries[0]
        if entry is None:
            return

        state = verdict_state(entry)
        report = entry.get('report') or {}
        status = entry.get('status')

        self.score_label.setText(
            verdict_text(entry) if status == vt.STATUS_FOUND else
            {'pending': '…', 'unknown': '?', 'error': '!'}.get(state, ''))
        headline, detail = self._headline(entry, state, report)
        self.verdict_label.setText(headline)
        self.detail_label.setText(detail)
        for label in (self.score_label, self.verdict_label):
            label.setProperty('state', state)
            label.style().unpolish(label)
            label.style().polish(label)

        has_hash = bool(entry.get('sha256'))
        can_reach_file = bool(entry.get('artifact_ref'))
        settled = status not in (STATE_QUEUED, STATE_RUNNING)
        self.browser_button.setEnabled(has_hash)
        self.reveal_button.setEnabled(can_reach_file)
        self.again_button.setEnabled(settled and (has_hash or can_reach_file))
        self.upload_button.setVisible(status == vt.STATUS_NOT_FOUND
                                      and can_reach_file)

        engines = report.get('engines') or []
        self._fill_engines(engines)
        self._fill_details(entry, report)
        # A result with no engine verdicts -- not found, still scanning,
        # failed -- has nothing to show in an empty engine table.
        self.report_tabs.setTabEnabled(0, bool(engines))
        if not engines:
            self.report_tabs.setCurrentIndex(1)
        elif self.report_tabs.currentIndex() == 1 and not self._details_chosen:
            self.report_tabs.setCurrentIndex(0)

    @staticmethod
    def _headline(entry, state, report):
        name = entry.get('name') or entry.get('sha256') or ''
        when = report.get('scan_date') or ''
        if state == 'malicious' or state == 'suspicious':
            positives = entry.get('positives') or 0
            headline = (f"Flagged by {positives} "
                        f"engine{'s' if positives != 1 else ''}")
            if state == 'suspicious':
                headline += " as suspicious"
        elif state == 'clean':
            headline = (f"No engine flagged this file "
                        f"({entry.get('total') or 0} checked)")
        elif state == 'unknown':
            headline = "VirusTotal has never seen this file"
            when = "Uploading it would make it available to VirusTotal users."
            return headline, f"{name} — {when}"
        elif state == 'pending':
            headline = {STATE_QUEUED: "Queued",
                        STATE_RUNNING: entry.get('progress') or "Checking…"
                        }.get(entry.get('status'),
                              "Submitted — VirusTotal is still scanning")
        else:
            headline = "The lookup did not complete"
            when = entry.get('error') or ''
        detail = name + (f" — last analysed {when}"
                         if when and state != 'error' else
                         (f" — {when}" if when else ''))
        return headline, detail

    def _fill_engines(self, engines):
        flagged = sum(1 for e in engines if e.get('category') in vt.DETECTED)
        self.report_tabs.setTabText(
            0, f"Engines ({flagged}/{len(engines)})" if engines else "Engines")
        self.engine_table.setSortingEnabled(False)
        self.engine_table.setRowCount(len(engines))
        for row, engine in enumerate(engines):
            category = engine.get('category') or ''
            state = ('malicious' if category == 'malicious' else
                     'suspicious' if category == 'suspicious' else
                     'clean' if category in ('undetected', 'harmless') else
                     'unknown')
            cells = [engine.get('engine', ''),
                     category.replace('-', ' ').capitalize(),
                     engine.get('result') or '',
                     engine.get('version') or '',
                     engine.get('update') or '']
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column in (1, 2) and state in ('malicious', 'suspicious'):
                    item.setForeground(verdict_brush(state))
                self.engine_table.setItem(row, column, item)
        fit_columns(self.engine_table, {2: 320})

    def _fill_details(self, entry, report):
        rows = [(None, 'File'),
                ('Name', entry.get('name') or ''),
                ('Path', entry.get('path') or '')]
        if report.get('type'):
            rows.append(('Type', report['type']))
        if report.get('size') is not None:
            rows.append(('Size', FileSystemUtils.get_readable_size(
                report['size'])))
        rows += [(None, 'Hashes'),
                 ('SHA-256', entry.get('sha256') or '')]
        if report.get('md5'):
            rows.append(('MD5', report['md5']))
        if report.get('sha1'):
            rows.append(('SHA-1', report['sha1']))

        rows.append((None, 'VirusTotal'))
        stats = report.get('stats') or {}
        if stats:
            rows.append(('Verdicts', ', '.join(
                f"{count} {name.replace('-', ' ')}"
                for name, count in sorted(stats.items(),
                                          key=lambda kv: -kv[1]) if count)))
        if report.get('reputation') is not None:
            rows.append(('Reputation', str(report['reputation'])))
        if report.get('first_seen'):
            rows.append(('First seen', report['first_seen']))
        if report.get('scan_date'):
            rows.append(('Last analysed', report['scan_date']))
        if report.get('names'):
            rows.append(('Known as', ', '.join(report['names'])))
        if report.get('tags'):
            rows.append(('Tags', ', '.join(report['tags'])))
        rows.append(('Method', 'File uploaded'
                     if entry.get('method') == METHOD_UPLOAD
                     else 'Hash lookup'))
        rows.append(('Checked', _when(entry.get('queried'))))
        if entry.get('error'):
            rows.append(('Error', entry['error'], 'warning'))
        self.details.set_rows(rows)

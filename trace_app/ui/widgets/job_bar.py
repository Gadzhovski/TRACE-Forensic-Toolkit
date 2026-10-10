"""One place where an examiner can see what the application is doing.

Indexing, analysis and anything added later all report here rather than each
growing a progress bar of its own. Two reasons. An examiner watching a long
run should have one place to look, not three that appear in different corners
depending on what was started; and jobs that all read the same evidence should
queue rather than compete -- two pytsk3 readers on one image are slower than
one, so running them together would make both feel broken.

The bar occupies no height when nothing is running: a permanently visible
progress area that is empty most of the time is a strip of wasted window.

It keeps its width while it runs. The label is a fixed width and shortens
what it shows in the middle (the whole text is its tooltip): sized to its
text, it grew and shrank with every file name a job reported, and the
progress bar and Cancel beside it jumped about the status bar. "Job 2 of 5"
opens the list of this run's jobs -- finished (and how), running and
queued -- with Cancel for the one running or all of them.

One job may run *beside* the queue (`submit(job, lane=SIDE)`): hashing an
image for verification reads it end to end, sequentially, while analysis
reads it file by file -- on an SSD or a network share they overlap well,
and queued behind each other a 500 GB E01's hash held up every finding for
an hour. Side jobs queue among themselves; the side lane has its own label,
progress and Cancel.
"""

import logging

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMenu, QProgressBar,
                               QToolButton, QWidget)

from trace_app.infra.constants import CONTROL_HEIGHT
from trace_app.ui import icons

logger = logging.getLogger('TRACE.JobBar')

#: The lanes a job can run in.
MAIN, SIDE = 'main', 'side'

#: How a finished job ended, as the job list shows it.
DONE, CANCELLED, FAILED = 'done', 'cancelled', 'failed'

#: Fixed widths (px): the bar never changes size while it runs.
LABEL_WIDTH = 320
SIDE_LABEL_WIDTH = 200
PROGRESS_WIDTH = 150
SIDE_PROGRESS_WIDTH = 100


class Job:
    """One unit of background work the bar knows how to show.

    A plain holder rather than the worker itself, so the bar does not care
    whether the work is a QThread, and a queued job costs nothing until it
    starts.
    """

    def __init__(self, key, title, start, stop=None):
        #: Identifies the job, so the same work is not queued twice.
        self.key = key
        #: What the examiner sees while it runs.
        self.title = title
        #: Called to begin. Takes the Job, returns the running worker.
        self.start = start
        #: Called to cancel. Takes the worker returned by start.
        self.stop = stop
        self.worker = None
        #: Set once Cancel was asked for: it then ended "cancelled".
        self.cancelled = False
        #: The last progress it reported: (done, total, detail).
        self.reported = (0, 0, '')


class JobBar(QWidget):
    """A queue of background jobs, and the status bar's view of them."""

    #: Emitted when the queue empties, so a host can refresh what the work
    #: produced without polling for it.
    all_finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("jobBar")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.label = QLabel()
        self.label.setObjectName("jobBarLabel")
        self.label.setFixedWidth(LABEL_WIDTH)
        layout.addWidget(self.label)

        self.progress = self._progress_bar(PROGRESS_WIDTH)
        layout.addWidget(self.progress)

        # "Job 2 of 5": every job of this run, finished and waiting.
        self.steps_button = QToolButton()
        self.steps_button.setObjectName("jobBarSteps")
        self.steps_button.setFixedHeight(CONTROL_HEIGHT - 6)
        self.steps_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.steps_button.setPopupMode(QToolButton.InstantPopup)
        self.steps_button.setToolTip("Jobs in this run: finished, running "
                                     "and waiting")
        self.steps_menu = QMenu(self.steps_button)
        self.steps_menu.setObjectName("jobBarMenu")
        self.steps_menu.aboutToShow.connect(self._fill_steps_menu)
        self.steps_button.setMenu(self.steps_menu)
        layout.addWidget(self.steps_button)

        self.cancel_button = self._cancel_button()
        self.cancel_button.clicked.connect(self.cancel_current)
        layout.addWidget(self.cancel_button)

        # The side lane: one job beside the queue (verification).
        self.side_label = QLabel()
        self.side_label.setObjectName("jobBarLabel")
        self.side_label.setFixedWidth(SIDE_LABEL_WIDTH)
        layout.addWidget(self.side_label)
        self.side_progress = self._progress_bar(SIDE_PROGRESS_WIDTH)
        layout.addWidget(self.side_progress)
        self.side_cancel_button = self._cancel_button()
        self.side_cancel_button.clicked.connect(self.cancel_side)
        layout.addWidget(self.side_cancel_button)

        self._queue = []
        self._current = None
        self._side_queue = []
        self._side = None
        #: (job, outcome) for every job this run has finished, in order.
        #: A run starts when work is submitted to an idle bar.
        self.history = []
        self._show_side(False)
        self._show_main(False)
        self.setVisible(False)

    @staticmethod
    def _progress_bar(width):
        bar = QProgressBar()
        bar.setObjectName("jobBarProgress")
        bar.setFixedWidth(width)
        bar.setFixedHeight(CONTROL_HEIGHT - 6)
        bar.setTextVisible(True)
        bar.setFormat("%p%")
        return bar

    @staticmethod
    def _cancel_button():
        # An icon, not a "Cancel" push button as wide as a word.
        button = QToolButton()
        button.setObjectName("jobBarCancel")
        side = CONTROL_HEIGHT - 6
        button.setFixedSize(side, side)
        button.setIconSize(QSize(12, 12))
        icons.apply_to(button, icons.CLOSE)
        button.setToolTip("Cancel")
        button.setAutoRaise(True)
        return button

    # --- queueing ------------------------------------------------------

    def submit(self, job, lane=MAIN):
        """Add a job, starting it if nothing else is running in its lane.

        A job whose key is already queued or running is dropped rather than
        duplicated: pressing Build Index twice should not walk the image
        twice.
        """
        running = [j for j in (self._current, self._side) if j is not None]
        if any(j.key == job.key for j in running):
            logger.debug("Job %s is already running", job.key)
            return False
        if any(queued.key == job.key for queued in
               self._queue + self._side_queue):
            logger.debug("Job %s is already queued", job.key)
            return False
        if not self.busy and not self._queue and not self._side_queue:
            self.history = []           # a new run

        if lane == SIDE:
            self._side_queue.append(job)
            if self._side is None:
                self._start_side()
            else:
                self._refresh_side()
            self._refresh_steps()
            return True

        self._queue.append(job)
        if self._current is None:
            self._start_next()
        else:
            # Say so, rather than leaving the examiner wondering why pressing
            # the button did nothing visible.
            self._refresh_label()
        self._refresh_steps()
        return True

    def _start_next(self):
        if not self._queue:
            self._current = None
            self._show_main(False)
            self._idle_check()
            return
        self._show_main(True)

        self._current = self._queue.pop(0)
        self.progress.setRange(0, 0)        # indeterminate until it counts
        self.progress.setValue(0)
        self.setVisible(True)
        self._refresh_label()
        self._refresh_steps()

        try:
            self._current.worker = self._current.start(self._current)
        except Exception as exc:
            logger.error("Could not start %s: %s", self._current.key, exc)
            self.job_finished(error=str(exc))

    # --- what the running job reports ----------------------------------

    def report(self, done, total, detail='', job=None):
        """Progress from a running job (the main lane's, unless `job` is the
        side lane's)."""
        if job is not None and job is self._side:
            job.reported = (done, total, detail)
            if total:
                self.side_progress.setRange(0, total)
                self.side_progress.setValue(done)
            self._refresh_side(detail)
            return
        if self._current is None:
            return
        self._current.reported = (done, total, detail)
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
        self._refresh_label(detail)

    def job_finished(self, job=None, error=None):
        """A running job has ended, however it ended (the main lane's,
        unless `job` is the side lane's). `error`, when it failed, is shown
        in the job list."""
        if job is not None and job is self._side:
            self._record(self._side, error)
            self._side = None
            self._start_side()
            self._refresh_steps()
            return
        if self._current is not None:
            self._record(self._current, error)
        self._current = None
        self._start_next()
        self._refresh_steps()

    def _record(self, job, error):
        outcome = (FAILED if error else CANCELLED if job.cancelled
                   else DONE)
        self.history.append((job, outcome if not error
                             else f"{FAILED}: {error}"))

    def cancel_current(self):
        """Ask the running job to stop.

        Cooperative: the worker is asked and stops at its next check, rather
        than being terminated. A killed thread halfway through a write leaves
        the case holding a half-written row.
        """
        if self._current is None:
            return
        self._current.cancelled = True
        self._set_text(self.label, LABEL_WIDTH, "Cancelling…")
        if self._current.stop and self._current.worker is not None:
            try:
                self._current.stop(self._current.worker)
            except Exception as exc:
                logger.error("Could not cancel %s: %s", self._current.key, exc)

    def cancel_all(self):
        """Drop the queues and stop what is running. For window close."""
        self._queue.clear()
        self._side_queue.clear()
        self.cancel_current()
        self.cancel_side()
        self._refresh_steps()

    def cancel_side(self):
        """Ask the side lane's job to stop (cooperatively, like the main)."""
        if self._side is None:
            return
        self._side.cancelled = True
        self._set_text(self.side_label, SIDE_LABEL_WIDTH, "Cancelling…")
        if self._side.stop and self._side.worker is not None:
            try:
                self._side.stop(self._side.worker)
            except Exception as exc:
                logger.error("Could not cancel %s: %s", self._side.key, exc)

    @property
    def busy(self):
        """Anything running, in either lane."""
        return self._current is not None or self._side is not None

    @property
    def main_busy(self):
        return self._current is not None

    def jobs(self):
        """This run's jobs in order, as (job, state): finished ones with
        their outcome, then 'running', then 'queued'."""
        out = list(self.history)
        out += [(job, 'running') for job in (self._current, self._side)
                if job is not None]
        out += [(job, 'queued') for job in self._queue + self._side_queue]
        return out

    # --- the side lane ------------------------------------------------------

    def _start_side(self):
        if not self._side_queue:
            self._side = None
            self._show_side(False)
            self._idle_check()
            return
        self._side = self._side_queue.pop(0)
        self.side_progress.setRange(0, 0)
        self.side_progress.setValue(0)
        self._show_side(True)
        self._refresh_side()
        try:
            self._side.worker = self._side.start(self._side)
        except Exception as exc:
            logger.error("Could not start %s: %s", self._side.key, exc)
            self.job_finished(self._side, error=str(exc))

    def _refresh_side(self, detail=''):
        if self._side is None:
            return
        text = self._side.title + (f" — {detail}" if detail else '')
        if self._side_queue:
            text += f"  (+{len(self._side_queue)} queued)"
        self._set_text(self.side_label, SIDE_LABEL_WIDTH, text)
        self.side_cancel_button.setToolTip(f"Cancel {self._side.title}")

    def _show_side(self, shown):
        for widget in (self.side_label, self.side_progress,
                       self.side_cancel_button):
            widget.setVisible(shown)
        if shown:
            self.setVisible(True)

    def _show_main(self, shown):
        for widget in (self.label, self.progress, self.cancel_button):
            widget.setVisible(shown)
        if shown:
            self.setVisible(True)

    def _idle_check(self):
        """Hidden, and all_finished, once both lanes are empty."""
        if self._current is None and self._side is None:
            self.setVisible(False)
            self.all_finished.emit()

    def _refresh_label(self, detail=''):
        if self._current is None:
            return
        text = self._current.title
        if detail:
            text += f" — {detail}"
        self._set_text(self.label, LABEL_WIDTH, text)
        self.cancel_button.setToolTip(f"Cancel {self._current.title}")

    def _set_text(self, label, width, text):
        """`text` shortened in the middle to the label's fixed width -- the
        start (what the job is) and the end (the file name) both matter;
        the whole of it is the tooltip."""
        label.setText(label.fontMetrics().elidedText(
            text, Qt.ElideMiddle, width - 6))
        label.setToolTip(text)

    # --- the job list -----------------------------------------------------------

    def _refresh_steps(self):
        jobs = self.jobs()
        total = len(jobs)
        place = len(self.history) + sum(
            1 for job in (self._current, self._side) if job is not None)
        self.steps_button.setText(f"Job {min(place, total)} of {total}")
        self.steps_button.setVisible(total > 1 or bool(self.history))

    def _fill_steps_menu(self):
        """The run's jobs, as the menu opens: what is done, what runs, what
        waits."""
        menu = self.steps_menu
        menu.clear()
        for job, state in self.jobs():
            if state == 'running':
                done, total, detail = job.reported
                share = f"{done * 100 // total}%" if total else "running"
                text = f"{job.title} — {share}"
                glyph = icons.RUN
            elif state == 'queued':
                text, glyph = f"{job.title} — waiting", icons.JOB_WAITING
            elif state == DONE:
                text, glyph = f"{job.title} — done", icons.SUCCESS
            elif state == CANCELLED:
                text, glyph = f"{job.title} — cancelled", icons.CANCEL
            else:
                text, glyph = f"{job.title} — {state}", icons.ERROR
            # Information, not commands -- but not greyed out either:
            # rebuilt each time the menu opens, so not theme-tracked.
            menu.addAction(icons.icon(glyph), text)
        if self.busy or self._queue or self._side_queue:
            menu.addSeparator()
            if self._current is not None:
                stop = menu.addAction(icons.icon(icons.CANCEL),
                                      f"Cancel {self._current.title}")
                stop.triggered.connect(self.cancel_current)
            stop_all = menu.addAction(icons.icon(icons.CLOSE),
                                      "Cancel All Jobs")
            stop_all.triggered.connect(self.cancel_all)

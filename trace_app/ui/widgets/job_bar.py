"""One place where an examiner can see what the application is doing.

Indexing, analysis and anything added later all report here rather than each
growing a progress bar of its own. Two reasons. An examiner watching a long
run should have one place to look, not three that appear in different corners
depending on what was started; and jobs that all read the same evidence should
queue rather than compete -- two pytsk3 readers on one image are slower than
one, so running them together would make both feel broken.

The bar occupies no height when nothing is running: a permanently visible
progress area that is empty most of the time is a strip of wasted window.

One job may run *beside* the queue (`submit(job, lane=SIDE)`): hashing an
image for verification reads it end to end, sequentially, while analysis
reads it file by file -- on an SSD or a network share they overlap well,
and queued behind each other a 500 GB E01's hash held up every finding for
an hour. Side jobs queue among themselves; the side lane has its own label,
progress and Cancel.
"""

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QProgressBar, QPushButton,
                               QWidget)

from trace_app.infra.constants import CONTROL_HEIGHT

logger = logging.getLogger('TRACE.JobBar')

#: The lanes a job can run in.
MAIN, SIDE = 'main', 'side'


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
        layout.setSpacing(8)

        self.label = QLabel()
        self.label.setObjectName("jobBarLabel")
        layout.addWidget(self.label)

        self.progress = QProgressBar()
        self.progress.setObjectName("jobBarProgress")
        self.progress.setFixedWidth(180)
        self.progress.setFixedHeight(CONTROL_HEIGHT - 6)
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("jobBarCancel")
        self.cancel_button.setFixedHeight(CONTROL_HEIGHT - 6)
        self.cancel_button.clicked.connect(self.cancel_current)
        layout.addWidget(self.cancel_button)

        # The side lane: one job beside the queue (verification).
        self.side_label = QLabel()
        self.side_label.setObjectName("jobBarLabel")
        layout.addWidget(self.side_label)
        self.side_progress = QProgressBar()
        self.side_progress.setObjectName("jobBarProgress")
        self.side_progress.setFixedWidth(120)
        self.side_progress.setFixedHeight(CONTROL_HEIGHT - 6)
        self.side_progress.setTextVisible(True)
        layout.addWidget(self.side_progress)
        self.side_cancel_button = QPushButton("Cancel")
        self.side_cancel_button.setObjectName("jobBarCancel")
        self.side_cancel_button.setFixedHeight(CONTROL_HEIGHT - 6)
        self.side_cancel_button.clicked.connect(self.cancel_side)
        layout.addWidget(self.side_cancel_button)

        self._queue = []
        self._current = None
        self._side_queue = []
        self._side = None
        self._show_side(False)
        self._show_main(False)
        self.setVisible(False)

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

        if lane == SIDE:
            self._side_queue.append(job)
            if self._side is None:
                self._start_side()
            else:
                self._refresh_side()
            return True

        self._queue.append(job)
        if self._current is None:
            self._start_next()
        else:
            # Say so, rather than leaving the examiner wondering why pressing
            # the button did nothing visible.
            self._refresh_label()
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

        try:
            self._current.worker = self._current.start(self._current)
        except Exception as exc:
            logger.error("Could not start %s: %s", self._current.key, exc)
            self.job_finished()

    # --- what the running job reports ----------------------------------

    def report(self, done, total, detail='', job=None):
        """Progress from a running job (the main lane's, unless `job` is the
        side lane's)."""
        if job is not None and job is self._side:
            if total:
                self.side_progress.setRange(0, total)
                self.side_progress.setValue(done)
            self._refresh_side(detail)
            return
        if self._current is None:
            return
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
        self._refresh_label(detail)

    def job_finished(self, job=None):
        """A running job has ended, however it ended (the main lane's,
        unless `job` is the side lane's)."""
        if job is not None and job is self._side:
            self._side = None
            self._start_side()
            return
        self._current = None
        self._start_next()

    def cancel_current(self):
        """Ask the running job to stop.

        Cooperative: the worker is asked and stops at its next check, rather
        than being terminated. A killed thread halfway through a write leaves
        the case holding a half-written row.
        """
        if self._current is None:
            return
        self.label.setText("Cancelling…")
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

    def cancel_side(self):
        """Ask the side lane's job to stop (cooperatively, like the main)."""
        if self._side is None:
            return
        self.side_label.setText("Cancelling…")
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
            self.job_finished(self._side)

    def _refresh_side(self, detail=''):
        if self._side is None:
            return
        text = self._side.title + (f" — {detail}" if detail else '')
        if self._side_queue:
            text += f"  (+{len(self._side_queue)} queued)"
        self.side_label.setText(text)

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
            # Only the tail of a long path: the useful part is the filename,
            # and a full path pushes the progress bar off the status bar.
            text += f" — {detail if len(detail) <= 60 else '…' + detail[-59:]}"
        if self._queue:
            text += f"  (+{len(self._queue)} queued)"
        self.label.setText(text)

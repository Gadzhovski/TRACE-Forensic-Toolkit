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
import time

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMenu,
                               QToolButton, QWidget)

from trace_app.infra.constants import CONTROL_HEIGHT
from trace_app.ui.widgets.progress_card import SlimBar
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


#: QProgressBar's range is a C int.
_BAR_MAX = 2 ** 31 - 1


def _show_progress(bar, done, total):
    """Set `bar` to done of total. Byte counts of a large image pass a C
    int (64 GB of free space being indexed): setRange raised, and the bar
    stayed on its busy animation with no percentage. Such totals are
    shown in ten-thousandths."""
    if total > _BAR_MAX:
        done, total = int(done * 10000 // total), 10000
    bar.setRange(0, int(total))
    bar.setValue(int(min(done, total)))


#: Seconds of a step before a time left is guessed: the first moments'
#: rate says little.
_ETA_AFTER = 5


def _duration(seconds):
    if seconds < 60:
        return "under a minute"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60:02d} min"


def _remaining(job, done, total, detail):
    """'about 14 min left' for a job's step (a new detail or total is a
    new step, timed from where it began); '' until it can tell. The bar
    beside it shows the percentage."""
    if not total:
        job.phase = None
        return ''
    now = time.monotonic()
    step = (total, detail.split(' — ')[0] if detail else '')
    if getattr(job, 'phase', None) != step:
        job.phase, job.phase_start = step, (now, done)
    began, at = job.phase_start
    if now - began >= _ETA_AFTER and done > at:
        left = (total - done) * (now - began) / (done - at)
        return f"about {_duration(left)} left"
    return ''



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
        #: time.monotonic() when it started and ended; None until then.
        self.started = self.ended = None

    def duration(self):
        """'6m 12s' -- how long it ran (so far, while running); '' if it
        has not started."""
        if self.started is None:
            return ''
        return elapsed_text((self.ended or time.monotonic()) - self.started)


def elapsed_text(seconds):
    """'45s', '6m 12s', '2h 05m'."""
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


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

        # Beside the bar it stops, saying what it does.
        self.cancel_button = self._cancel_button()
        self.cancel_button.clicked.connect(self.cancel_current)
        layout.addWidget(self.cancel_button)
        # How long is left, "about 14 min left", from the rate since this
        # step began (the bar shows how far).
        self.eta_label = QLabel()
        self.eta_label.setObjectName("jobBarEta")
        layout.addWidget(self.eta_label)

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
        # Spare width after the controls, not between them: every one is a
        # fixed width, and without this Qt spread the bar's extra space as
        # gaps -- Cancel ended up far from the job it cancels.
        layout.addStretch(1)

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
        # The progress cards' bar (ui/widgets/progress_card.py), the
        # percentage beside it.
        bar = SlimBar()
        bar.setObjectName("jobBarProgress")
        bar.setFixedWidth(width)
        bar.setFixedHeight(CONTROL_HEIGHT - 6)
        bar.setTextVisible(True)
        bar.setFormat("%p%")
        return bar

    @staticmethod
    def _cancel_button():
        # A stop icon and the word: an x alone did not say what it closed.
        button = QToolButton()
        button.setObjectName("jobBarCancel")
        button.setText("Cancel")
        button.setFixedHeight(CONTROL_HEIGHT - 6)
        button.setIconSize(QSize(12, 12))
        button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        icons.apply_to(button, icons.CANCEL)
        button.setToolTip("Cancel")
        return button

    # --- queueing ------------------------------------------------------

    def submit(self, job, lane=MAIN):
        """Add a job, starting it if nothing else is running in its lane.

        A job whose key is already queued or running is dropped rather than
        duplicated: pressing Build Index twice should not walk the image
        twice.
        """
        if getattr(self, '_closed', False):
            logger.debug("Job %s not started: the window is closing",
                         job.key)
            return False
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
        self.eta_label.clear()
        self.setVisible(True)
        self._refresh_label()
        self._refresh_steps()

        self._current.started = time.monotonic()
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
                _show_progress(self.side_progress, done, total)
            else:
                self.side_progress.setRange(0, 0)
            self._refresh_side(detail)
            return
        if self._current is None:
            return
        self._current.reported = (done, total, detail)
        if total:
            _show_progress(self.progress, done, total)
        else:
            # A step that cannot say how far it is (an external tool
            # starting): busy, not the last step's 99% standing still.
            self.progress.setRange(0, 0)
        self.eta_label.setText(_remaining(self._current, done, total,
                                          detail))
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
        job.ended = time.monotonic()
        outcome = (FAILED if error else CANCELLED if job.cancelled
                   else DONE)
        self.history.append((job, outcome if not error
                             else f"{FAILED}: {error}"))
        # Every job's time in the log, so the slow one is found without a
        # profiler.
        logger.info("%s: %s in %s", job.title, outcome, job.duration())

    def cancel_current(self):
        """Ask the running job to stop.

        Cooperative: the worker is asked and stops at its next check, rather
        than being terminated. A killed thread halfway through a write leaves
        the case holding a half-written row.
        """
        self._cancel(self._current, self.label, LABEL_WIDTH)

    def _cancel(self, job, label, width):
        if job is None:
            return
        job.cancelled = True
        self._set_text(label, width, "Cancelling…")
        if job.stop and job.worker is not None:
            try:
                job.stop(job.worker)
            except Exception as exc:
                logger.error("Could not cancel %s: %s", job.key, exc)

    def cancel_all(self):
        """Drop the queues and stop what is running. For window close."""
        self._queue.clear()
        self._side_queue.clear()
        self.cancel_current()
        self.cancel_side()
        self._refresh_steps()

    def close(self):
        """The window is closing: stop everything, and start nothing from
        now on -- closing the evidence refreshes views that queue jobs, and
        one started after the window's wait outlived the window."""
        self._closed = True
        self.cancel_all()

    def cancel_side(self):
        """Ask the side lane's job to stop (cooperatively, like the main)."""
        self._cancel(self._side, self.side_label, SIDE_LABEL_WIDTH)

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
        self._side.started = time.monotonic()
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
        for widget in (self.label, self.progress, self.cancel_button,
                       self.eta_label):
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
            took = job.duration()
            if state == 'running':
                done, total, detail = job.reported
                share = f"{done * 100 // total}%" if total else "running"
                text = f"{job.title} — {share}, {took}"
                glyph = icons.RUN
            elif state == 'queued':
                text, glyph = f"{job.title} — waiting", icons.JOB_WAITING
            elif state == DONE:
                text, glyph = f"{job.title} — done in {took}", icons.SUCCESS
            elif state == CANCELLED:
                text, glyph = (f"{job.title} — cancelled after {took}",
                               icons.CANCEL)
            else:
                text, glyph = f"{job.title} — {state} ({took})", icons.ERROR
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

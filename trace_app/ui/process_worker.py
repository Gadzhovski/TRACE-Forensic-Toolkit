"""A background job in a child process, seen by the window as a QThread.

core/background.py runs the job; this thread starts it, relays what it
sends as signals and asks it to stop. The thread spends its life blocked on
the queue, which releases the interpreter lock, so it costs the window
nothing. The analysis, indexing and carving workers are thin subclasses that
keep the signals the window already connects to.
"""

import logging
import queue as queue_module
import time

from PySide6.QtCore import QThread, Signal

from trace_app.core import background

logger = logging.getLogger('TRACE.Jobs')

#: How long to wait for a cancelled job to finish its current file before
#: the process is ended. Only on window close; a cancel from the job bar
#: waits as long as it takes.
CLOSE_GRACE_SECONDS = 10
#: How long the closing window waits for a worker it closed: the grace,
#: then the process ended and joined (run's finally), with room to spare.
CLOSE_WAIT_MS = (CLOSE_GRACE_SECONDS + 10) * 1000


class ProcessWorker(QThread):
    """Run background job `kind` with `params` in a child process."""

    #: The job's progress payload, as it sent it.
    job_progress = Signal(object)
    #: One item the job produced (a carved file's record).
    job_item = Signal(dict)
    #: (count, error) -- error is '' on success or cancel.
    job_done = Signal(int, str)

    kind = None

    def __init__(self, params, parent=None):
        super().__init__(parent)
        self.params = dict(params)
        # Made here, on the UI thread, so stop() works even before run().
        self._stop = background.context().Event()
        self._process = None
        self._closing = None

    def stop(self):
        self._stop.set()

    def close(self):
        """The window is closing: stop, and end the process if it has not
        finished within CLOSE_GRACE_SECONDS -- the thread must be done
        before the window that owns it is deleted (Qt aborts the process
        on a QThread destroyed while running). A cancel from the job bar
        (`stop`) still waits as long as the job takes."""
        if self._closing is None:
            self._closing = time.monotonic()
        self.stop()

    def run(self):
        count, error = 0, ''
        process = None
        try:
            ctx = background.context()
            channel = ctx.Queue()
            process = ctx.Process(
                target=background.child_main,
                args=(self.kind, self.params, channel, self._stop),
                name=f'TRACE {self.kind}')  # not a daemon: see
            # background.start -- indexing starts processes of its own
            process.start()
            self._process = process
            count, error = self._relay(channel, process)
        except Exception as exc:
            logger.error("%s job could not run: %s", self.kind, exc)
            error = str(exc)
        finally:
            # Only a started process can be joined: when start() itself
            # failed, joining raised a second error over the first.
            if process is not None and self._process is process:
                process.join(CLOSE_GRACE_SECONDS if self._stop.is_set()
                             else None)
                if process.is_alive():
                    logger.warning("%s job did not stop; ending it",
                                   self.kind)
                    process.terminate()
                    process.join(5)
        self.on_done(count, error)

    def _relay(self, channel, process):
        while True:
            if self._closing is not None and process.is_alive() and                     time.monotonic() - self._closing > CLOSE_GRACE_SECONDS:
                logger.warning("%s job did not stop as the window closed; "
                               "ending it", self.kind)
                process.terminate()
                process.join(5)
                return 0, ''
            try:
                message = channel.get(timeout=0.25)
            except queue_module.Empty:
                if not process.is_alive():
                    # Gone without saying so: killed, or crashed in C.
                    try:
                        message = channel.get(timeout=1)
                    except queue_module.Empty:
                        return 0, (f"the {self.kind} process ended "
                                   f"unexpectedly (exit code "
                                   f"{process.exitcode})")
                else:
                    continue
            kind = message[0]
            if kind == 'progress':
                self.on_progress(*message[1])
            elif kind == 'item':
                self.on_item(message[1])
            elif kind == 'log':
                record = message[1]
                logging.getLogger(record.name).handle(record)
            elif kind == 'done':
                return message[1], message[2]

    # Overridden to emit each worker's own signals.
    def on_progress(self, *payload):
        self.job_progress.emit(payload)

    def on_item(self, record):
        self.job_item.emit(record)

    def on_done(self, count, error):
        self.job_done.emit(count, error)

"""Text extraction on several processes, rows written in order (no Qt).

Indexing reads a file, pulls its text out (text_extract) and finds the
indicators in it (search_index) -- and the last two are almost all of the
time: regexes over every byte of every program on a Linux image. They are
pure functions of the bytes, so they run here on a pool of worker
processes while the indexing job goes on reading the image; the job still
writes every row itself, in the order it read them, so the index is the
same whichever worker finished first.

`spawn` everywhere (as core/background.py): a frozen build needs
multiprocessing.freeze_support() first in main.py, which it has. Each worker
applies the case's settings (core/settings.py) before its first file, as a
job's process does. Small runs, and one worker, stay in-process: starting
workers costs seconds.
"""

import collections
import logging
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool

logger = logging.getLogger('TRACE.TextPool')

#: Below this many files the pool is not worth starting.
MIN_FILES = 2000
#: Most worker processes, whatever the machine has.
MAX_WORKERS = 8
#: Files and bytes handed out but not yet written: bounds the memory held.
#: Many files, because rows are written in order: one slow file (a large
#: library's strings) holds back everything after it, and with a short
#: queue the other workers sat idle behind it.
MAX_IN_FLIGHT = 8192
MAX_IN_FLIGHT_BYTES = 512 * 1024 * 1024


def default_workers():
    """Worker processes to use: the user setting 'worker_processes' (0 =
    automatic: two cores left for the window and the reading job, at most
    MAX_WORKERS)."""
    try:
        from trace_app.core import settings
        chosen = int(settings.user('worker_processes') or 0)
    except Exception:
        chosen = 0
    if chosen > 0:
        return chosen
    return max(1, min(MAX_WORKERS, (os.cpu_count() or 2) - 2))


def extract(content, name, limit, skip_packed=False):
    """(text, [(kind, value)] indicators) of one file's bytes -- what a
    worker does, and what the pipeline does in-process."""
    from trace_app.core.search_index import entities_of
    from trace_app.core.text_extract import extract_text
    text = extract_text(content, name, limit=limit, skip_packed=skip_packed)
    return text, sorted(entities_of(text)) if text else []


def _start_worker(case_folder):
    """In each worker, first: the examiner's and the case's settings (which
    indicators are on, among them)."""
    from trace_app.core.background import watch_parent
    watch_parent()
    try:
        from trace_app.core import settings
        settings.apply_user()
        if case_folder:
            settings.apply_case(settings.StoredCase(case_folder))
    except Exception as exc:
        logger.debug("Worker settings not applied: %s", exc)


class _Done:
    """A finished result standing in a queue of futures."""

    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value

    def cancel(self):
        return False


class TextPipeline:
    """Hands out extraction, and calls `write(text, entities, payload)` for
    each file in the order `submit` was called."""

    def __init__(self, write, workers=1, case_folder=None):
        self.write = write
        self.pool = None
        if workers > 1:
            try:
                self.pool = ProcessPoolExecutor(
                    max_workers=workers,
                    mp_context=multiprocessing.get_context('spawn'),
                    initializer=_start_worker, initargs=(case_folder,))
            except Exception as exc:
                logger.warning("Text extraction stays in one process: %s",
                               exc)
        self._pending = collections.deque()
        self._bytes = 0

    @property
    def parallel(self):
        return self.pool is not None

    def submit(self, content, name, limit, payload, skip_packed=False):
        if self.pool is None:
            text, entities = extract(content, name, limit, skip_packed)
            self.write(text, entities, payload)
            return
        try:
            future = self.pool.submit(extract, bytes(content), name, limit,
                                      skip_packed)
        except (BrokenProcessPool, RuntimeError, AssertionError,
                OSError) as exc:
            # The pool could not start its processes (a daemonic parent
            # raises AssertionError): one process does the work.
            self._lose_pool(exc)
            self.submit(content, name, limit, payload, skip_packed)
            return
        size = len(content)
        self._pending.append((future, payload, size, content, name, limit,
                              skip_packed))
        self._bytes += size
        while len(self._pending) > MAX_IN_FLIGHT or \
                self._bytes > MAX_IN_FLIGHT_BYTES:
            self._write_oldest()

    def put(self, payload, text='', entities=()):
        """A row whose text is already known (an empty file, an encrypted
        member), written in its place in the order."""
        if not self._pending:
            self.write(text, list(entities), payload)
            return
        self._pending.append((_Done((text, list(entities))), payload, 0,
                              None, '', 0, False))

    def _write_oldest(self):
        future, payload, size, content, name, limit, skip_packed = \
            self._pending.popleft()
        self._bytes -= size
        try:
            text, entities = future.result()
        except BrokenProcessPool as exc:
            # A worker died (in C, on some file): this file in-process,
            # and the rest of the run too.
            self._lose_pool(exc)
            text, entities = extract(content, name, limit, skip_packed)
        except Exception as exc:
            logger.debug("No text from %s: %s", name, exc)
            text, entities = '', []
        self.write(text, entities, payload)

    def _lose_pool(self, exc):
        logger.warning("Text extraction pool stopped (%s); going on in one "
                       "process", exc)
        pool, self.pool = self.pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)

    def flush(self):
        """Write everything handed out so far."""
        while self._pending:
            self._write_oldest()

    def close(self, cancel=False):
        """Write what is pending (or drop it, on `cancel`), and stop the
        workers."""
        if cancel:
            for future, *_rest in self._pending:
                future.cancel()
            self._pending.clear()
            self._bytes = 0
        else:
            self.flush()
        if self.pool is not None:
            self.pool.shutdown(wait=not cancel, cancel_futures=cancel)
            self.pool = None

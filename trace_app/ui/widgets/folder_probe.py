"""Folders in the tree lose a wrong expand arrow without being clicked.

A folder gets its arrow before it is read (`ShowIndicator`): reading every
subfolder to decide made expanding WINDOWS take 47 reads on the window's
thread. So an empty folder showed an arrow that vanished when clicked.

Once a folder's children are in the tree, `FolderProbe` reads those
subfolders on a thread of its own, one at a time -- ImageHandler caches
each listing, so the read is the one expanding would have made anyway,
done early -- and reports how many entries each holds. The window drops
the arrow of the empty ones (and records the count for the status bar).
Folders opened one after another queue; `cancel()` (the tree rebuilt, an
image closed) drops what is queued, and an item freed meanwhile is
skipped. Only a listing the handler kept counts: a read that failed
returns [] uncached, and that folder keeps its arrow.
"""

import logging
import queue
import threading

from PySide6.QtCore import QObject, Signal, Slot

logger = logging.getLogger('TRACE.FolderProbe')

#: Subfolders read per opened folder at most: a folder of thousands of
#: subfolders (WinSxS) keeps the arrows it was given.
MOST_PROBED = 400


class FolderProbe(QObject):
    """`probe(handler, offset, [(item, inode)])`; `on_count(item, count)`
    for each folder read, on the window's thread."""

    _found = Signal(object, int, int)

    def __init__(self, on_count, parent=None):
        super().__init__(parent)
        self._on_count = on_count
        self._generation = 0
        self._lock = threading.Lock()
        self._queue = queue.Queue()
        self._worker = None
        self._found.connect(self._deliver)

    def probe(self, handler, start_offset, items):
        items = list(items)[:MOST_PROBED]
        if not items:
            return
        with self._lock:
            generation = self._generation
            for item, inode in items:
                self._queue.put((generation, handler, start_offset, item,
                                 inode))
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._run, name='folder-probe', daemon=True)
                self._worker.start()

    def cancel(self):
        with self._lock:
            self._generation += 1

    def _current(self, generation):
        with self._lock:
            return generation == self._generation

    def _run(self):
        while True:
            try:
                generation, handler, start_offset, item, inode = \
                    self._queue.get(timeout=2)
            except queue.Empty:
                with self._lock:
                    if self._queue.empty():
                        self._worker = None
                        return
                continue
            if not self._current(generation):
                continue
            try:
                handler.get_directory_contents(start_offset, inode)
                entries = handler.cached_directory_contents(start_offset,
                                                            inode)
            except Exception as exc:   # a damaged folder keeps its arrow
                logger.debug("Folder %s not probed: %s", inode, exc)
                continue
            if entries is not None:
                self._found.emit(item, generation, len(entries))

    @Slot(object, int, int)
    def _deliver(self, item, generation, count):
        if not self._current(generation):
            return
        import shiboken6
        if shiboken6.isValid(item):
            self._on_count(item, count)

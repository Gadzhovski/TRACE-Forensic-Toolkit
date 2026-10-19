"""Background readers (QThreads) held until their thread has really ended.

A panel's reader used to be dropped from its registry when its result
arrived -- a signal emitted at the end of run(), before the thread had
returned -- or on `finished`, which also fires just before. With nothing
left holding the Python object, the next garbage collection could free it
while the thread was still finishing: an access violation on the window's
thread, in whatever it was doing ("Garbage-collecting" in text_zoom's event
filter, with the NTFS panel's reader in query_ntfs: the $LogFile node).

Here a thread stays until its `finished` reaches the window's thread, is
then waited for (a moment: it is returning), and only then deleted.
Dict-like where the panels used a dict: `keep[key] = thread`, `bool`,
`values()`, `clear()` (which waits for every one).
"""

from PySide6.QtCore import QObject, Slot


def release(thread):
    """Delete a QThread once its thread has really returned. Call it from
    `finished` (on the window's thread) in place of `deleteLater`: Qt emits
    `finished` while the thread is still unwinding, and deleting the object
    then is a use-after-free -- an access violation on the window's thread
    with only `app.exec()` on the stack. Similar pictures did it for every
    comparison, one started per finished job; the crash came as carving
    began (tests/test_kept_threads.py)."""
    try:
        thread.wait()
        thread.deleteLater()
    except RuntimeError:
        pass                    # already deleted


class KeptThreads(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._threads = {}

    def __setitem__(self, key, thread):
        self._threads[key] = thread
        # A slot of this object (in the window's thread), so it runs
        # there, queued -- never a lambda on the worker's side.
        thread.finished.connect(self._ended)

    def __bool__(self):
        return bool(self._threads)

    def __len__(self):
        return len(self._threads)

    def __contains__(self, key):
        return key in self._threads

    def get(self, key, default=None):
        return self._threads.get(key, default)

    def values(self):
        return list(self._threads.values())

    def clear(self, timeout=5000):
        """Wait for every thread (closing), then let them go."""
        for thread in self.values():
            try:
                thread.wait(timeout)
            except RuntimeError:
                pass            # already deleted
        self._threads.clear()

    @Slot()
    def _ended(self):
        thread = self.sender()
        if thread is None:
            return
        for key, kept in list(self._threads.items()):
            if kept is thread:
                del self._threads[key]
        release(thread)

"""A running QThread must never lose its last reference.

Qt aborts the whole process -- "QThread: Destroyed while thread is still
running", no Python stack -- when one is freed while it runs. Clicking a
second Unallocated Space node before the first had been read rebound
MainWindow.unallocated_worker and did exactly that (an examiner browsing
X-Ways' Lost Partitions image). These run the real click handler with a
read held open, collect garbage, and expect the process to survive and
the reads to end in order.
"""

import gc
import threading

from PySide6.QtCore import QThread
from PySide6.QtWidgets import QTreeWidgetItem
from PySide6.QtCore import Qt

from tests.conftest import pump


class _SlowImage:
    """An image handler whose unallocated reads wait for `release`."""

    sector_size = 512

    def __init__(self):
        self.release = threading.Event()
        self.started = []

    def get_readable_size(self, size):
        return f"{size} B"

    def read_unallocated_space(self, start, end):
        self.started.append(start)
        self.release.wait(10)
        return b'U' * (end - start)


def _window(qapp, monkeypatch):
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    # Closing asks whether to exit; a modal question blocks offscreen.
    monkeypatch.setattr(message, 'question', lambda *a, **k: True)
    window = MainWindow()
    window.activate_item_image = lambda item: True
    return window


def test_clicking_unallocated_nodes_quickly_keeps_each_read_alive(
        qapp, monkeypatch):
    window = _window(qapp, monkeypatch)
    image = _SlowImage()
    window.image_handler = image
    shown = []
    window.update_viewer_with_file_content = \
        lambda content, data: shown.append(data['start_offset'])
    try:
        for start in (0, 4096, 8192):
            item = QTreeWidgetItem(['Unallocated Space'])
            item.setData(0, Qt.UserRole, {'is_unallocated': True,
                                          'start_offset': start,
                                          'end_offset': start + 512})
            window.on_item_clicked(item, 0)
            pump(qapp, 2, until=lambda: len(image.started) > start // 4096)
        assert image.started == [0, 4096, 8192]
        # Every earlier worker has been replaced on the attribute; nothing
        # else may be what keeps it alive -- but something must.
        gc.collect()
        running = [w for w in window._active_workers if w.isRunning()]
        assert len(running) == 3
        image.release.set()
        assert pump(qapp, 10, until=lambda: not window._active_workers)
        # Only the last click's content reaches the viewer.
        assert shown == [8192]
    finally:
        image.release.set()
        window.close()


def test_a_retained_worker_is_let_go_only_once_its_thread_has_ended(
        qapp, monkeypatch):
    window = _window(qapp, monkeypatch)

    class Quick(QThread):
        def run(self):
            pass

    workers = [window._retain_worker(Quick()) for _ in range(50)]
    for worker in workers:
        worker.start()
    del workers
    assert pump(qapp, 10, until=lambda: not window._active_workers)
    gc.collect()
    window.close()

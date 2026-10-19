"""A panel's background reader is held until its thread has ended
(ui/widgets/kept_threads.py).

The NTFS tab's reader was dropped when its rows arrived -- a signal sent at
the end of run(), before the thread had returned -- and the next garbage
collection on the window's thread freed it while it was still finishing:
an access violation the first time the examiner opened $LogFile records.
"""

import gc
import threading

from PySide6.QtCore import QThread, Signal

from tests.conftest import pump


class _Reader(QThread):
    done = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.release = threading.Event()

    def run(self):
        self.done.emit(1)
        # Still running after its result went, as run() returning is --
        # until the test lets it end.
        self.release.wait(10)


def test_a_reader_is_kept_until_its_thread_has_ended(qapp):
    from PySide6.QtWidgets import QWidget
    from trace_app.ui.widgets.kept_threads import KeptThreads
    owner = QWidget()
    kept = KeptThreads(owner)
    results = []
    reader = _Reader(owner)
    reader.done.connect(results.append)
    kept[1] = reader
    reader.start()
    release = reader.release
    del reader
    assert pump(qapp, 5, lambda: results)
    # The result is in; the thread is not done: still held.
    for _ in range(5):
        gc.collect()
    assert kept and 1 in kept and not kept.values()[0].isFinished()
    release.set()
    assert pump(qapp, 5, lambda: not kept)
    gc.collect()
    owner.deleteLater()


def test_closing_waits_for_every_reader(qapp):
    from trace_app.ui.widgets.kept_threads import KeptThreads
    kept = KeptThreads()
    readers = [_Reader() for _ in range(3)]
    for number, reader in enumerate(readers):
        kept[number] = reader
        reader.start()
        reader.release.set()
    kept.clear()
    assert not kept and all(r.isFinished() for r in readers)


def test_the_panels_keep_their_readers(qapp):
    """Every panel reading on a thread holds it in KeptThreads -- none in a
    plain dict it empties when the result arrives."""
    import inspect
    from trace_app.ui.viewers import (activity_panel, conversations_panel,
                                      hash_matches_panel, indicators_panel,
                                      ntfs_panel, persistence_panel,
                                      timeline_insights, timeline_lanes,
                                      timeline_panel)
    for module in (activity_panel, conversations_panel, hash_matches_panel,
                   indicators_panel, ntfs_panel, persistence_panel,
                   timeline_insights, timeline_lanes, timeline_panel):
        source = inspect.getsource(module)
        assert 'KeptThreads(self)' in source, module.__name__
        assert '._loads.pop(' not in source and '._jobs.pop(' not in \
            source and '._queries.pop(' not in source, module.__name__


def test_release_frees_a_thread_only_once_it_has_returned(qapp):
    """`finished` comes while the thread is still unwinding: deleting it
    then was the access violation as carving began (Similar pictures
    freed every comparison that way, one started per finished job)."""
    from trace_app.ui.widgets.kept_threads import release
    reader = _Reader()
    reader.start()
    threading.Timer(0.3, reader.release.set).start()
    release(reader)
    assert reader.isFinished()
    release(reader)             # twice, or after Qt freed it: no error


def test_no_thread_is_deleted_from_its_own_finished(qapp):
    """Nowhere in the window is a QThread handed to deleteLater straight
    from `finished`; kept_threads.release (or KeptThreads) waits first."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / 'trace_app' / 'ui'
    pattern = re.compile(r"finished\.connect\([^)]*deleteLater")
    offenders = [f"{path.relative_to(root)}:{number}"
                 for path in root.rglob('*.py')
                 for number, line in enumerate(
                     path.read_text(encoding='utf-8').splitlines(), 1)
                 if pattern.search(line)]
    assert not offenders, offenders


def test_similar_pictures_releases_each_comparison(qapp, tmp_path,
                                                   monkeypatch):
    """A comparison is started per finished job and the last replaces the
    one before: each is released through kept_threads.release, finished."""
    from trace_app.core.case import Case
    from trace_app.ui.viewers import similar_pictures_panel
    released = []

    def recording(thread):
        real_release(thread)
        released.append(thread.isFinished())
    real_release = similar_pictures_panel.release
    monkeypatch.setattr(similar_pictures_panel, 'release', recording)
    case = Case.create(str(tmp_path / 'Case'), 'Similar')
    panel = similar_pictures_panel.SimilarPicturesPanel()
    try:
        panel.set_case(case)
        panel.refresh()
        panel.refresh()
        assert pump(qapp, 60, lambda: len(released) >= 3 and
                    panel._task is None)
        assert all(released)
    finally:
        panel.shutdown()
        panel.deleteLater()
        case.close()

"""Evidence reads the window asks for run off its thread
(MainWindow._wait_for, _directory_contents).

A big folder or file read on the window's thread froze it for seconds; it
now runs on a thread while an event loop keeps the window painting -- and
takes no input, so no click starts a second navigation half-way through.
"""

import threading
import time
import types

import pytest
from PySide6.QtCore import QTimer

from trace_app.ui.main_window import MainWindow


@pytest.fixture
def window_like(qapp):
    return types.SimpleNamespace(
        SLOW_READ_AFTER=MainWindow.SLOW_READ_AFTER,
        _quit_when_done=MainWindow._quit_when_done)


def test_a_slow_read_lets_the_window_run_but_takes_no_input(window_like,
                                                           monkeypatch):
    from PySide6.QtCore import QEventLoop
    from trace_app.ui import main_window
    flags = []

    class Recorded(QEventLoop):
        def exec(self, how=QEventLoop.AllEvents):
            flags.append(how)
            return super().exec(how)
    monkeypatch.setattr(main_window, 'QEventLoop', Recorded)
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(time.perf_counter()))
    timer.start()

    def slow(value):
        time.sleep(0.6)
        return value * 2
    start = time.perf_counter()
    assert MainWindow._wait_for(window_like, slow, 21) == 42
    finished = time.perf_counter()
    timer.stop()
    assert finished - start >= 0.6
    assert sum(start < t < finished for t in ticks) >= 5     # not frozen
    # Window-system input (clicks, keys) waits until the read is done.
    assert flags == [QEventLoop.ExcludeUserInputEvents]


def test_errors_reach_the_caller(window_like):
    def fails():
        time.sleep(0.3)
        raise OSError("bad sector")
    with pytest.raises(OSError, match='bad sector'):
        MainWindow._wait_for(window_like, fails)


def test_quick_reads_and_other_threads_are_plain_calls(window_like):
    assert MainWindow._wait_for(window_like, len, 'abc') == 3
    seen = []

    def elsewhere():
        seen.append(MainWindow._wait_for(
            window_like, threading.current_thread))
    thread = threading.Thread(target=elsewhere)
    thread.start()
    thread.join()
    assert seen == [thread]          # ran inline on the calling thread

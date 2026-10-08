"""A crash in C leaves its stack (trace_app/infra/crash_log.py): a child
interpreter really crashes, and the next start reports it in the log."""

import logging
import os
import subprocess
import sys

from tests.conftest import ROOT


def test_a_native_crash_is_written_and_reported_next_time(tmp_path, caplog):
    path = str(tmp_path / 'crash.log')
    code = ("import sys; sys.path.insert(0, sys.argv[1]);"
            "from trace_app.infra import crash_log;"
            "crash_log.enable(sys.argv[2]);"
            "import faulthandler\n"
            "def reading_evidence():\n"
            "    faulthandler._sigsegv()\n"
            "reading_evidence()")
    result = subprocess.run([sys.executable, '-c', code, ROOT, path],
                            capture_output=True, timeout=60)
    assert result.returncode != 0
    with open(path, encoding='utf-8') as handle:
        written = handle.read()
    assert 'Fatal Python error' in written and 'reading_evidence' in written

    from trace_app.infra import crash_log
    caplog.set_level(logging.ERROR, logger='TRACE.Crash')
    kept = crash_log.report_previous(path)
    assert kept and os.path.basename(kept).startswith('crash-')
    assert not os.path.exists(path)
    assert 'previous session crashed' in caplog.text
    assert 'reading_evidence' in caplog.text
    # Nothing to report the time after.
    assert crash_log.report_previous(path) is None


def test_an_unhandled_exception_reaches_the_log(tmp_path):
    log = str(tmp_path / 'trace.log')
    code = ("import sys, logging, threading;"
            "sys.path.insert(0, sys.argv[1]);"
            "logging.basicConfig(filename=sys.argv[3]);"
            "from trace_app.infra import crash_log;"
            "crash_log.enable(sys.argv[2]);"
            "t = threading.Thread(target=lambda: 1 / 0, name='reader');"
            "t.start(); t.join()")
    subprocess.run([sys.executable, '-c', code, ROOT,
                    str(tmp_path / 'crash.log'), log], timeout=60)
    with open(log, encoding='utf-8') as handle:
        text = handle.read()
    assert 'Unhandled exception in thread reader' in text
    assert 'ZeroDivisionError' in text

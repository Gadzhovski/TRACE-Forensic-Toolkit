"""Crashes leave a trace (no Qt).

A crash inside C -- Qt, The Sleuth Kit, a libyal library -- ends the
process before Python can log anything, and a packaged build has no
console: the examiner saw the window vanish and trace.log stop mid-run,
with nothing to report. `faulthandler` writes every thread's Python stack
to crash.log as the process dies; an unhandled Python exception (in a Qt
slot, or a thread) goes to the log instead of a stderr nobody sees.

The next start reads crash.log: if it holds anything, trace.log says the
previous session crashed, with the stack, and the file is kept under a
dated name (crash-YYYYmmdd-HHMMSS.log) beside it. Background jobs (child
processes) write to the same file.
"""

import datetime
import faulthandler
import logging
import os
import sys
import threading

logger = logging.getLogger('TRACE.Crash')

CRASH_LOG = 'crash.log'
#: How much of a previous crash's stack trace.log repeats.
REPORTED_LINES = 60

_handle = None


def crash_path():
    from trace_app.infra.paths import user_data_dir
    return os.path.join(user_data_dir(), CRASH_LOG)


def report_previous(path=None):
    """Log a crash the previous session left in crash.log, and keep it
    under a dated name. Returns the kept file's path, or None."""
    path = path or crash_path()
    try:
        if not os.path.getsize(path):
            return None
        with open(path, encoding='utf-8', errors='replace') as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    stamp = datetime.datetime.fromtimestamp(
        os.path.getmtime(path), datetime.timezone.utc).strftime(
        '%Y%m%d-%H%M%S')
    kept = os.path.join(os.path.dirname(path), f"crash-{stamp}.log")
    try:
        os.replace(path, kept)
    except OSError:
        kept = path
    logger.error("The previous session crashed (%s UTC); its stack is in "
                 "%s:\n%s", stamp, kept,
                 '\n'.join(lines[-REPORTED_LINES:]))
    return kept


def enable(path=None):
    """Write a native crash's stacks to crash.log, and send unhandled
    Python exceptions -- main thread, other threads -- to the log."""
    global _handle
    path = path or crash_path()
    try:
        _handle = open(path, 'a', encoding='utf-8')
        faulthandler.enable(_handle, all_threads=True)
    except (OSError, ValueError, RuntimeError) as exc:
        logger.debug("No crash log: %s", exc)

    def excepthook(kind, value, trace):
        if issubclass(kind, KeyboardInterrupt):
            sys.__excepthook__(kind, value, trace)
            return
        logger.critical("Unhandled exception", exc_info=(kind, value, trace))

    def thread_hook(args):
        if issubclass(args.exc_type, SystemExit):
            return
        logger.critical("Unhandled exception in thread %s",
                        getattr(args.thread, 'name', '?'),
                        exc_info=(args.exc_type, args.exc_value,
                                  args.exc_traceback))

    sys.excepthook = excepthook
    threading.excepthook = thread_hook

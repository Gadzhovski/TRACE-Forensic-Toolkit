#!/usr/bin/env python3
"""Launcher for TRACE.

Kept at the repository root so `python main.py` continues to work, as the
install scripts and documentation describe. The application itself lives in
the trace_app package.

`--self-test REPORT.json [IMAGE ...]` checks this copy of TRACE instead of
starting it (trace_app/selftest.py). It is dispatched before the application
module is imported, so its sandbox is in place before anything reads a
per-user setting.
"""

import multiprocessing
import sys

if __name__ == '__main__':
    # Background jobs run in child processes (trace_app/core/background.py).
    # In a packaged build the child is this executable again, and this call
    # is what turns it into the job instead of a second copy of the app. A
    # no-op when running from source.
    multiprocessing.freeze_support()

    if sys.argv[1:2] == ['--self-test']:
        from trace_app.selftest import main as self_test
        sys.exit(self_test(sys.argv[2:]))

    from trace_app.app import main
    sys.exit(main())

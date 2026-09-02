#!/usr/bin/env python3
"""Launcher for TRACE.

Kept at the repository root so `python main.py` continues to work, as the
install scripts and documentation describe. The application itself lives in
the trace_app package.
"""

import sys

from trace_app.app import main

if __name__ == '__main__':
    sys.exit(main())

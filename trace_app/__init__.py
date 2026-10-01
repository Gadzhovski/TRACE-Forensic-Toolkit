"""TRACE - Toolkit for Retrieval and Analysis of Cyber Evidence.

Layout:
    core/   disk image access, background workers, lookups. No UI imports.
    ui/     the Qt application: main window, viewer tabs, dialogs.
    infra/  paths, constants, shared helpers, startup checks.

The rule worth keeping: nothing in core/ may import from ui/.
"""

import os
import sys
import time

__version__ = "2.0.0"


def _pin_utc():
    """Run the process in UTC, before The Sleuth Kit is loaded.

    FAT and exFAT store wall-clock times with no zone. The Sleuth Kit turns
    them into epoch seconds with the C library's local-time conversion, so
    the numbers it returns depend on the time zone of the machine doing the
    examination: the same file read in Sofia and on a UTC build server came
    back three hours apart. (pytsk3 releases before 2026 happened to behave
    as if in UTC; the wheel-built ones honour the machine's zone.)

    Pinned to UTC, that conversion is the identity, so TSK hands back exactly
    the digits on disk on every machine -- which is what TRACE displays,
    labelled "(local, no zone)" for FAT and exFAT. TRACE shows evidence times
    in UTC throughout; nothing here relies on the examiner's zone.

    This lives in the package's __init__ because every entry point -- the
    application, the tools, the tests -- imports trace_app before anything
    that loads pytsk3.
    """
    os.environ['TZ'] = 'UTC0'
    if hasattr(time, 'tzset'):
        time.tzset()                    # macOS, Linux
    elif sys.platform == 'win32':
        # Python has no time.tzset on Windows; the C runtime's own resets the
        # conversion state that pytsk3's mktime() uses.
        try:
            import ctypes
            ctypes.CDLL('ucrtbase')._tzset()
        except OSError:
            pass


_pin_utc()

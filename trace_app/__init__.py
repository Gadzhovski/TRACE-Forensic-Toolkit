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


def _bundled_libmagic():
    """On macOS, use the libmagic shipped in the pylibmagic wheel.

    python-magic is only a binding; libmagic itself is a C library that
    macOS does not provide. pylibmagic carries it (and its signature
    database) as a wheel, so a Mac needs no Homebrew. Importing it puts its
    directory first on DYLD_LIBRARY_PATH, which ctypes' find_library -- the
    first place python-magic looks -- consults, so the bundled copy is used
    even when Homebrew has another. Every Mac then names a file the same way.

    MAGIC is set to the bundled database alone, not prepended to whatever
    the environment held: which signatures identified a file should not
    depend on the examiner's shell.

    Must run before anything imports `magic`, which loads the library at
    import time. Windows' python-magic-bin carries its own DLL; Linux takes
    libmagic1 from apt, which it needs anyway for Qt.
    """
    if sys.platform != 'darwin':
        return
    try:
        import pylibmagic
    except ImportError:
        return                          # source checkout: Homebrew's, if any
    os.environ['MAGIC'] = str(pylibmagic.data.joinpath('magic.mgc'))


_pin_utc()
_bundled_libmagic()

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

__version__ = "2.1.0"


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


#: Database bytes handed to libmagic, kept for the life of the process:
#: magic_load_buffers does not copy them.
_MAGIC_DATABASES = {}


def _unicode_safe_libmagic():
    """On Windows, let libmagic load its database from any path.

    python-magic-bin's libmagic (5.32) opens magic.mgc with the C runtime's
    narrow fopen, which reads the path in the ANSI code page. Installed under
    a folder whose name has a character outside it -- a Cyrillic, Greek or
    accented user name, say -- every Magic() fails with "could not find any
    valid magic files", and file-type identification silently disappears
    (the packaged build's self-test found this). Python reads the database
    instead, which it can from any path, and libmagic takes it from memory.
    """
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        from magic import magic as binding
        load_buffers = binding.libmagic.magic_load_buffers
    except Exception:
        return
    load_buffers.restype = ctypes.c_int
    load_buffers.argtypes = [binding.magic_t, ctypes.POINTER(ctypes.c_void_p),
                             ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t]

    def magic_load(cookie, filename):
        path = filename or binding.default_magic_file
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if path not in _MAGIC_DATABASES:
            with open(path, 'rb') as handle:
                data = handle.read()
            _MAGIC_DATABASES[path] = ctypes.create_string_buffer(data, len(data))
        database = _MAGIC_DATABASES[path]
        buffers = (ctypes.c_void_p * 1)(ctypes.addressof(database))
        sizes = (ctypes.c_size_t * 1)(len(database))
        if load_buffers(cookie, buffers, sizes, 1) != 0:
            raise binding.MagicException(binding.magic_error(cookie))
        return 0

    binding.magic_load = magic_load


def _heif_decoder():
    """Teach Pillow HEIC/HEIF, so iPhone photos preview, thumbnail and give
    up their EXIF like any other picture. pi-heif is the decode-only build;
    absent (Windows on ARM has no wheel), HEIC simply keeps its icon."""
    try:
        import pi_heif
        pi_heif.register_heif_opener()
    except Exception:
        pass


_pin_utc()
_bundled_libmagic()
_unicode_safe_libmagic()
_heif_decoder()

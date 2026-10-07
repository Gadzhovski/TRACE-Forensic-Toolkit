"""Startup dependency checks.

TRACE depends on a few libraries that pip cannot install on its own because
they wrap a system component: libmagic in particular. When one is missing the
failure previously surfaced as an unhandled exception inside a Qt slot, at the
moment the user clicked something -- e.g. `from magic import Magic` raising
ImportError the first time the Metadata tab was opened.

Checking once at startup lets us name what is missing and how to install it.
"""

import sys


def _install_hint(package):
    """Platform-appropriate install instruction for a system package."""
    hints = {
        'libmagic': {
            'win32': "pip install python-magic-bin",
            # Bundled by the pylibmagic wheel; Homebrew is not needed.
            'darwin': "pip install -r requirements.txt",
            'linux': "sudo apt install libmagic1",
        },
    }
    platform_key = 'win32' if sys.platform == 'win32' else 'darwin' if sys.platform == 'darwin' else 'linux'
    return hints.get(package, {}).get(platform_key, f"install {package}")


def libmagic_identity():
    """(version, path) of the libmagic actually loaded, or None.

    Signature databases change between releases, and two versions can name
    the same file differently, so which one identified a file is worth
    recording. python-magic keeps the loaded library as `magic.libmagic`;
    python-magic-bin (Windows) as `magic.magic.libmagic`.
    """
    try:
        import magic
        lib = getattr(magic, 'libmagic', None)
        if lib is None:
            lib = magic.magic.libmagic
        number = int(lib.magic_version())
    except Exception:
        return None
    return f"{number // 100}.{number % 100:02d}", getattr(lib, '_name', '?')


def check_dependencies():
    """Return a list of (name, detail, hint) for each missing dependency.

    An empty list means everything needed is present.
    """
    missing = []

    try:
        import magic  # noqa: F401
        # python-magic can import but fail to find the library at call time.
        magic.Magic()
    except Exception as e:
        missing.append((
            "libmagic",
            f"File-type detection is unavailable ({e.__class__.__name__}: {e}). "
            "The Metadata tab will not be able to report MIME types.",
            _install_hint('libmagic'),
        ))

    return missing


def format_report(missing):
    """Render missing dependencies as a human-readable block."""
    lines = []
    for name, detail, hint in missing:
        lines.append(f"{name}\n    {detail}\n    Install with:  {hint}")
    return "\n\n".join(lines)

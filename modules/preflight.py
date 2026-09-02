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
            'darwin': "brew install libmagic",
            'linux': "sudo apt install libmagic1",
        },
    }
    platform_key = 'win32' if sys.platform == 'win32' else 'darwin' if sys.platform == 'darwin' else 'linux'
    return hints.get(package, {}).get(platform_key, f"install {package}")


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

"""Filesystem location helpers.

TRACE has two distinct kinds of path, and they must not be confused:

* **Bundled resources** (icons, stylesheets, the icon-mapping database) ship
  with the application and are read-only. Use :func:`resource_path`.
* **User data** (the API-key config, carved output, the log) is written at
  runtime and must live somewhere the user can actually write. Use
  :func:`user_config_dir` / :func:`user_data_dir`.

Previously every one of these was a bare relative path such as
``'Icons/logo.png'``, resolved against the *current working directory*. That
only works when the app is started with ``cd <repo> && python main.py``.
Launched from a desktop shortcut, from another drive, or as a frozen bundle,
the CWD is somewhere else entirely: icons silently fail to load (Qt returns a
null QPixmap without raising), the stylesheet is skipped, and carved output is
written to a random directory. In a macOS .app bundle the CWD is ``/``, where
creating an output directory raises PermissionError.
"""

import os
import sys

APP_NAME = "TRACE"

# Project root: the directory containing main.py, i.e. the parent of modules/.
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_MODULE_DIR)


def is_frozen():
    """True when running from a PyInstaller bundle."""
    return getattr(sys, 'frozen', False)


def base_path():
    """Directory that bundled resources are read from.

    PyInstaller unpacks datas into ``sys._MEIPASS`` (a temp dir for --onefile,
    the app dir for --onedir); from source it is the project root.
    """
    return getattr(sys, '_MEIPASS', _PROJECT_ROOT)


def resource_path(*parts):
    """Absolute path to a bundled resource.

    Accepts either a single relative path or path segments::

        resource_path('Icons/logo.png')
        resource_path('styles', 'dark_theme.qss')

    Forward slashes in a single argument are handled, so existing literals can
    be wrapped as-is without rewriting them.
    """
    return os.path.normpath(os.path.join(base_path(), *parts))


def _xdg_dir(env_var, default_subpath):
    """Resolve an XDG base directory on Linux/BSD, falling back to ~."""
    root = os.environ.get(env_var)
    if not root:
        root = os.path.join(os.path.expanduser('~'), *default_subpath)
    return root


def user_config_dir(create=True):
    """Per-user configuration directory (API keys and similar settings).

    Windows: ``%APPDATA%\TRACE``
    macOS:   ``~/Library/Application Support/TRACE``
    Linux:   ``$XDG_CONFIG_HOME/TRACE`` or ``~/.config/TRACE``
    """
    if sys.platform == 'win32':
        root = os.environ.get('APPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
    elif sys.platform == 'darwin':
        root = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support')
    else:
        root = _xdg_dir('XDG_CONFIG_HOME', ('.config',))

    path = os.path.join(root, APP_NAME)
    if create:
        _ensure_dir(path)
    return path


def user_data_dir(create=True):
    """Per-user data directory (carved output, logs).

    Windows: ``%LOCALAPPDATA%\TRACE``
    macOS:   ``~/Library/Application Support/TRACE``
    Linux:   ``$XDG_DATA_HOME/TRACE`` or ``~/.local/share/TRACE``
    """
    if sys.platform == 'win32':
        root = os.environ.get('LOCALAPPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    elif sys.platform == 'darwin':
        root = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support')
    else:
        root = _xdg_dir('XDG_DATA_HOME', ('.local', 'share'))

    path = os.path.join(root, APP_NAME)
    if create:
        _ensure_dir(path)
    return path


def config_file(name='config.ini'):
    """Absolute path to a file inside the user config directory."""
    return os.path.join(user_config_dir(), name)


def carved_files_dir(create=True):
    """Directory that file carving writes recovered files into."""
    path = os.path.join(user_data_dir(create=create), 'carved_files')
    if create:
        _ensure_dir(path)
        _ensure_dir(os.path.join(path, 'thumbnails'))
    return path


def log_file():
    """Absolute path to the application log."""
    return os.path.join(user_data_dir(), 'trace.log')


def _ensure_dir(path):
    """Create a directory if missing, tolerating a read-only location.

    Callers get a path back either way; a failure to create surfaces at the
    point of an actual read/write rather than at import time.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path

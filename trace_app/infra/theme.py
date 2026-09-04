"""Which theme the application is in, and remembering the choice.

The theme used to be applied from inside MainWindow's menu construction, which
runs after the case launcher has already been shown -- so the first window an
examiner sees was drawn by the platform, dark on a dark desktop, whatever they
had chosen last time.

Applying it lives here instead, so the very first widget is themed, and the
choice is written next to the other user settings rather than being lost on
exit.
"""

import configparser
import logging
import os

from trace_app.infra.paths import config_file, resource_path

logger = logging.getLogger('TRACE.Theme')

#: The themes there are. Light is the default: a forensic tool is read in
#: bright rooms as often as dark ones, and a first run should not depend on
#: what the desktop happens to be set to.
THEMES = ('light', 'dark')
DEFAULT_THEME = 'light'

_SECTION = 'UI'
_KEY = 'theme'


def read_theme():
    """The theme the user last chose, or the default."""
    parser = configparser.ConfigParser()
    try:
        parser.read([config_file(), 'config.ini'])
        theme = parser.get(_SECTION, _KEY, fallback=DEFAULT_THEME)
    except (configparser.Error, OSError) as exc:
        logger.debug("Could not read the saved theme: %s", exc)
        return DEFAULT_THEME
    return theme if theme in THEMES else DEFAULT_THEME


def save_theme(theme):
    """Remember the choice, without disturbing anything else in the file."""
    if theme not in THEMES:
        return

    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass        # a damaged file is replaced, not a reason to fail

    if not parser.has_section(_SECTION):
        parser.add_section(_SECTION)
    parser.set(_SECTION, _KEY, theme)

    try:
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        # The theme still applies for this session; only the memory is lost.
        logger.warning("Could not save the theme: %s", exc)


def stylesheet_for(theme):
    """The stylesheet text for a theme, with its url() paths resolved.

    Qt resolves a relative url() against the working directory, which is not
    the project root once the application is launched from anywhere else or
    packaged -- so every icon reference is rewritten to an absolute path.
    """
    path = resource_path(f'styles/{theme}_theme.qss')
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            text = handle.read()
    except OSError as exc:
        logger.error("Could not read %s: %s", path, exc)
        return ''

    return _resolve_urls(text)


def _resolve_urls(stylesheet):
    """Rewrite url('Icons/...') to an absolute path."""
    import re

    def absolute(match):
        quote, relative = match.group(1), match.group(2)
        return f"url({quote}{resource_path(relative).replace(os.sep, '/')}{quote})"

    return re.sub(r"url\((['\"]?)([^)'\"]+)\1\)", absolute, stylesheet)


def apply_theme(app, theme=None, remember=False):
    """Put a theme on the whole application. Returns the theme applied.

    Called before any window exists, so the launcher is themed too. Only the
    stylesheet is handled here -- icon tinting belongs to the UI layer, and
    infra must not import from it.
    """
    theme = theme if theme in THEMES else read_theme()
    app.setStyleSheet(stylesheet_for(theme))
    if remember:
        save_theme(theme)
    return theme

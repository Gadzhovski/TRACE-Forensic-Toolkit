"""Where the main window was, and how its docks were sized, between runs.

Kept beside the theme in config.ini, as base64 of what Qt's saveGeometry()
and saveState() return. No Qt import here: the bytes are opaque to this
module.
"""

import base64
import binascii
import configparser
import logging

from trace_app.infra.paths import config_file

logger = logging.getLogger('TRACE.WindowState')

_SECTION = 'Window'
#: Bumped when the dock layout changes enough that an old saved state would
#: put things in the wrong place; an old one is then ignored.
LAYOUT_VERSION = 2


def screen_signature(screens):
    """A short key for a set of screens -- [(name, x, y, width, height)] --
    so each arrangement (a laptop alone, the laptop docked to a monitor)
    keeps a layout of its own."""
    import hashlib
    text = '|'.join(f"{n}:{x},{y}:{w}x{h}" for n, x, y, w, h in
                    sorted(screens))
    return hashlib.sha1(text.encode('utf-8', 'replace')).hexdigest()[:12]


def _section(signature):
    return f"{_SECTION} {signature}" if signature else _SECTION


def read_window_state(signature=None):
    """(geometry bytes, state bytes) or (None, None): the layout kept for
    this screen arrangement (`signature`), else the last one kept."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        for section in ([_section(signature)] if signature else []) + \
                [_SECTION]:
            if parser.getint(section, 'version', fallback=0) != \
                    LAYOUT_VERSION:
                continue
            geometry = parser.get(section, 'geometry', fallback='')
            state = parser.get(section, 'state', fallback='')
            if geometry or state:
                return (base64.b64decode(geometry) if geometry else None,
                        base64.b64decode(state) if state else None)
        return None, None
    except (configparser.Error, OSError, ValueError, binascii.Error) as exc:
        logger.debug("No saved window layout: %s", exc)
        return None, None


def save_window_state(geometry, state, signature=None):
    """Keep the layout -- as the last one, and for this screen arrangement
    when `signature` is given."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass
    for section in [_SECTION] + ([_section(signature)] if signature else []):
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, 'version', str(LAYOUT_VERSION))
        parser.set(section, 'geometry',
                   base64.b64encode(bytes(geometry)).decode('ascii'))
        parser.set(section, 'state',
                   base64.b64encode(bytes(state)).decode('ascii'))
    try:
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        logger.warning("Could not save the window layout: %s", exc)


def forget_window_state():
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        # Every arrangement's layout: Reset Layout means all of them.
        gone = [section for section in parser.sections()
                if section == _SECTION or section.startswith(_SECTION + ' ')]
        for section in gone:
            parser.remove_section(section)
        if gone:
            with open(config_file(), 'w', encoding='utf-8') as handle:
                parser.write(handle)
    except (configparser.Error, OSError) as exc:
        logger.debug("Could not forget the window layout: %s", exc)


_LISTING = 'Listing'


def read_listing_view(default='details', option='view'):
    """The Listing's view mode the examiner last chose (`option`
    'carved_view': the Carved files tab's)."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        return parser.get(_LISTING, option, fallback=default)
    except (configparser.Error, OSError):
        return default


def save_listing_view(mode, option='view'):
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass
    if not parser.has_section(_LISTING):
        parser.add_section(_LISTING)
    parser.set(_LISTING, option, mode)
    try:
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        logger.warning("Could not save the listing view: %s", exc)


def read_value(section, key, default=''):
    """One remembered value from config.ini (strings only)."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        return parser.get(section, key, fallback=default)
    except (configparser.Error, OSError):
        return default


def save_value(section, key, value):
    """Remember one value in config.ini, keeping everything else there."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, key, str(value))
    try:
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        logger.warning("Could not save %s.%s: %s", section, key, exc)

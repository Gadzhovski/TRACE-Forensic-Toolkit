"""Where the main window was, and how its docks were sized, between runs.

Kept beside the theme in config.ini, as base64 of what Qt's saveGeometry()
and saveState() return. No Qt import here: the bytes are opaque to this
module.
"""

import base64
import binascii
import configparser
import logging

from trace_app.infra import config_store

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
    parser = config_store.load()
    try:
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
    except (configparser.Error, ValueError, binascii.Error) as exc:
        logger.debug("No saved window layout: %s", exc)
        return None, None


def save_window_state(geometry, state, signature=None):
    """Keep the layout -- as the last one, and for this screen arrangement
    when `signature` is given."""
    values = {'version': LAYOUT_VERSION,
              'geometry': base64.b64encode(bytes(geometry)).decode('ascii'),
              'state': base64.b64encode(bytes(state)).decode('ascii')}

    def change(parser):
        for section in [_SECTION] + (
                [_section(signature)] if signature else []):
            if not parser.has_section(section):
                parser.add_section(section)
            for key, value in values.items():
                parser.set(section, key, str(value))
    config_store.update(change)


def forget_window_state():
    def change(parser):
        # Every arrangement's layout: Reset Layout means all of them.
        for section in parser.sections():
            if section == _SECTION or section.startswith(_SECTION + ' '):
                parser.remove_section(section)
    config_store.update(change)


_LISTING = 'Listing'


def read_listing_view(default='details', option='view'):
    """The Listing's view mode the examiner last chose (`option`
    'carved_view': the Carved files tab's)."""
    return config_store.get(_LISTING, option, default)


def save_listing_view(mode, option='view'):
    config_store.set_value(_LISTING, option, mode)


def read_value(section, key, default=''):
    """One remembered value from config.ini (strings only)."""
    return config_store.get(section, key, default)


def save_value(section, key, value):
    """Remember one value in config.ini, keeping everything else there."""
    config_store.set_value(section, key, value)

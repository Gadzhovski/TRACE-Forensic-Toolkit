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


def read_window_state():
    """(geometry bytes, state bytes) or (None, None)."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        if parser.getint(_SECTION, 'version', fallback=0) != LAYOUT_VERSION:
            return None, None
        geometry = parser.get(_SECTION, 'geometry', fallback='')
        state = parser.get(_SECTION, 'state', fallback='')
        return (base64.b64decode(geometry) if geometry else None,
                base64.b64decode(state) if state else None)
    except (configparser.Error, OSError, ValueError, binascii.Error) as exc:
        logger.debug("No saved window layout: %s", exc)
        return None, None


def save_window_state(geometry, state):
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass
    if not parser.has_section(_SECTION):
        parser.add_section(_SECTION)
    parser.set(_SECTION, 'version', str(LAYOUT_VERSION))
    parser.set(_SECTION, 'geometry',
               base64.b64encode(bytes(geometry)).decode('ascii'))
    parser.set(_SECTION, 'state', base64.b64encode(bytes(state)).decode(
        'ascii'))
    try:
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        logger.warning("Could not save the window layout: %s", exc)


def forget_window_state():
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        if parser.remove_section(_SECTION):
            with open(config_file(), 'w', encoding='utf-8') as handle:
                parser.write(handle)
    except (configparser.Error, OSError) as exc:
        logger.debug("Could not forget the window layout: %s", exc)


_LISTING = 'Listing'


def read_listing_view(default='details'):
    """The Listing's view mode the examiner last chose."""
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
        return parser.get(_LISTING, 'view', fallback=default)
    except (configparser.Error, OSError):
        return default


def save_listing_view(mode):
    parser = configparser.ConfigParser()
    try:
        parser.read(config_file())
    except (configparser.Error, OSError):
        pass
    if not parser.has_section(_LISTING):
        parser.add_section(_LISTING)
    parser.set(_LISTING, 'view', mode)
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

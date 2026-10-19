"""config.ini: the one reader and writer for everything kept there.

The theme, window layouts, views, text zoom, user settings and API keys
each used to read and write the file on their own -- with three different
parsers (only one without '%' interpolation, which ui_scale's '150%'
needs), no encoding on one write, and the API keys written from a copy read
when the window opened, so saving a key put back every other value as it
was then. Each change is now read-modify-write of the current file, under
one lock, written to a temporary file and moved into place.
"""

import configparser
import logging
import os
import threading

from trace_app.infra.paths import config_file

logger = logging.getLogger('TRACE.Config')

_LOCK = threading.RLock()


def load():
    """The file as it is now (empty when missing or unreadable -- a damaged
    file is replaced at the next save, never a reason to fail)."""
    parser = configparser.ConfigParser(interpolation=None)
    path = config_file()
    try:
        try:
            parser.read(path, encoding='utf-8')
        except UnicodeDecodeError:
            # Written by an older TRACE in the ANSI code page.
            parser = configparser.ConfigParser(interpolation=None)
            parser.read(path)
    except (configparser.Error, OSError, UnicodeDecodeError) as exc:
        logger.debug("config.ini unreadable: %s", exc)
    return parser


def get(section: str, key: str, default: str = '') -> str:
    """One value as text, or `default`."""
    return load().get(section, key, fallback=default)


def update(change):
    """Apply `change(parser)` to the current file and save it. False (and
    a log line) when it could not be written."""
    with _LOCK:
        parser = load()
        change(parser)
        path = config_file()
        temporary = path + '.saving'
        try:
            with open(temporary, 'w', encoding='utf-8') as handle:
                parser.write(handle)
            try:
                os.replace(temporary, path)
            except PermissionError:
                # Windows: the file held open elsewhere (a scanner, an
                # editor) refuses a rename over it, not a rewrite.
                with open(path, 'w', encoding='utf-8') as handle:
                    parser.write(handle)
            return True
        except OSError as exc:
            logger.warning("Could not save %s: %s", path, exc)
            return False
        finally:
            if os.path.exists(temporary):
                try:
                    os.remove(temporary)
                except OSError:
                    pass


def set_value(section: str, key: str, value: str) -> bool:
    """Keep one value, leaving everything else in the file as it is.
    False if the file could not be written."""
    def change(parser):
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, key, str(value))
    return update(change)


def set_values(section: str, values: dict[str, str]) -> bool:
    """Keep several values of one section at once (False: not written)."""
    def change(parser):
        if not parser.has_section(section):
            parser.add_section(section)
        for key, value in values.items():
            parser.set(section, key, str(value))
    return update(change)

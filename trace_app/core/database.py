"""Icon lookups for file types, folders and devices.

Resolves an extension (or a folder/device name) to the icon shown for it in the
tree and listing views.

This was backed by a SQLite table, opened at startup and queried once per
rendered row. The table had grown to 308 rows of which only 72 were reachable:
161 "app" icons, 16 "status", 12 "animation" and 21 entirely empty rows were
never queried by any code path, and only one of its 13 folder variants was ever
requested. The mapping now lives in trace_app/infra/file_icons.py as a plain dict --
easier to read, extend and grep, with no connection to manage and no way to
drift from the files on disk.

The class name and get_icon_path() signature are unchanged so the call sites in
the tree and listing builders did not need touching.
"""

import logging

from trace_app.infra import file_icons
from trace_app.infra.paths import resource_path

logger = logging.getLogger('TRACE.Icons')


class DatabaseManager:
    """Resolves icon paths for file types, folders and devices."""

    def __init__(self, db_path=None):
        # db_path is accepted and ignored: kept so existing construction sites
        # keep working while the SQLite table is retired.
        self._cache = {}

    def get_icon_path(self, icon_type, identifier):
        """Absolute path to the icon for `identifier` of kind `icon_type`.

        `icon_type` is 'file', 'folder' or 'device'. Unknown identifiers fall
        back to a neutral placeholder rather than failing, so an unrecognised
        extension shows a generic file icon instead of a blank cell.
        """
        key = (icon_type, identifier)
        if key in self._cache:
            return self._cache[key]

        identifier = (identifier or '').lower().lstrip('.')

        if icon_type == 'folder':
            relative = file_icons.FOLDER_ICONS.get(identifier, file_icons.FOLDER)
        elif icon_type == 'device':
            relative = file_icons.DEVICE_ICONS.get(identifier, file_icons.UNKNOWN)
        else:
            relative = file_icons.FILE_ICONS.get(identifier, file_icons.UNKNOWN)

        resolved = resource_path(relative)
        self._cache[key] = resolved
        return resolved

    def close(self):
        """No-op, kept for callers that used to close the database."""
        self._cache.clear()

"""Icon-mapping lookups.

Maps a file extension to the SVG used for it in the tree and listing views.
"""

import logging
from sqlite3 import connect as sqlite3_connect

from modules.paths import resource_path

logger = logging.getLogger('TRACE.Database')


class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.db_conn = None
        self._icon_cache = {}  # Cache for icon paths
        self._connect()

    def _connect(self):
        """Establish a connection to the database with proper error handling."""
        try:
            self.db_conn = sqlite3_connect(self.db_path)
            # Enable foreign keys
            self.db_conn.execute("PRAGMA foreign_keys = ON")
        except Exception as e:
            logger.error(f"Error connecting to database: {e}")
            self.db_conn = None

    def __del__(self):
        """Ensure connection is closed when object is destroyed."""
        self.close()

    def close(self):
        """Explicitly close the database connection."""
        if self.db_conn:
            try:
                self.db_conn.close()
                self.db_conn = None
            except Exception as e:
                logger.error(f"Error closing database connection: {e}")

    def get_icon_path(self, icon_type, identifier):
        """Get icon path with caching for performance."""
        # Check cache first
        cache_key = f"{icon_type}_{identifier}"
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]

        if not self.db_conn:
            self._connect()
            if not self.db_conn:
                return resource_path('Icons/mimetypes/application-x-zerosize.svg')

        try:
            c = self.db_conn.cursor()
            # First, try to get the icon for the specific identifier
            c.execute("SELECT path FROM icons WHERE type = ? AND extention = ?", (icon_type, identifier))
            result = c.fetchone()

            # If a specific icon exists for the identifier, cache and return it
            if result:
                icon_path = resource_path(result[0])
                self._icon_cache[cache_key] = icon_path
                return icon_path

            # If no specific icon exists, check for default icons
            if icon_type == 'folder':
                c.execute("SELECT path FROM icons WHERE type = ? AND extention = 'folder'", (icon_type,))
                result = c.fetchone()
                default_path = resource_path(result[0]) if result else resource_path(
                    'Icons/mimetypes/application-x-zerosize.svg')
            else:
                # Try to find a generic icon for the file type first
                generic_key = f"{icon_type}_generic"
                if generic_key not in self._icon_cache:
                    c.execute("SELECT path FROM icons WHERE type = ? AND extention = 'generic'", (icon_type,))
                    result = c.fetchone()
                    self._icon_cache[generic_key] = resource_path(result[0]) if result else resource_path(
                        'Icons/mimetypes/application-x-zerosize.svg')

                default_path = self._icon_cache[generic_key]

            # Cache the result before returning
            self._icon_cache[cache_key] = default_path
            return default_path

        except Exception as e:
            logger.error(f"Error fetching icon: {e}")
            return resource_path('Icons/mimetypes/application-x-zerosize.svg')
        finally:
            if 'c' in locals():
                c.close()

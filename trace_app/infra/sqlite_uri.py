"""Read-only SQLite connections, opened by URI with the path quoted.

``sqlite3.connect(f"file:{path}?mode=ro", uri=True)`` is wrong for any path
holding '#', '?' or '%': the URI ends at '#' (the rest is a fragment), so
``mode=ro`` is lost and SQLite opens -- read-write, creating it -- a new
empty database at the truncated path. A case named "Case #12" made every
background job fail with "no such table" and left a stray file beside the
case folder. Every read-only open goes through here.
"""

import os
import sqlite3
from urllib.parse import quote
from typing import Any


def read_only_uri(path: str, immutable: bool = False) -> str:
    """The ``file:`` URI opening *path* read-only (and immutable if asked:
    nothing written, not even -wal/-shm, for a database nobody is writing)."""
    path = os.path.abspath(path).replace('\\', '/')
    if path.startswith('//'):
        path = '//' + path      # a UNC path: empty authority, then //server
    elif not path.startswith('/'):
        path = '/' + path       # a drive: file:/C:/...
    uri = 'file:' + quote(path, safe='/:') + '?mode=ro'
    return uri + '&immutable=1' if immutable else uri


def connect_read_only(path: str, immutable: bool = False,
                      timeout: float = 10,
                      **kwargs: Any) -> sqlite3.Connection:
    """A read-only connection to the database at *path*. Raises
    sqlite3.OperationalError when it does not exist -- never creates it."""
    return sqlite3.connect(read_only_uri(path, immutable), uri=True,
                           timeout=timeout, **kwargs)

"""The files inside a file -- archive members, the files a document
embeds, the pictures a database keeps as BLOBs -- for the media exports
(core/vics.py) (no Qt).

The M57 'Jean' image held 211 pictures Griffeye listed inside archives
(ZIP skins, .jar, .wmz, Thumbs.db); TRACE's export walked files only, so
it had none of them. (Browser caches are read by core/firefox_cache.py
and core/chrome_cache.py.)

`members(content, depth)` yields `Member`s in the order found, nested
members after their container. The archive readers are archives.py's
(every kind it browses), the document readers embedded.py's, databases
SQLite's own (activity/sqlite_bytes: in memory); nothing is written to
disk.
"""

import logging

from trace_app.core import archives, embedded

logger = logging.getLogger('TRACE.MediaInside')

#: Documents whose embedded files are read (embedded.kind_of); 'exif' --
#: a photo's own thumbnail -- is left out: every camera picture has one.
DOCUMENT_KINDS = ('pdf', 'ole', 'rtf', 'office')
SQLITE_HEADER = b'SQLite format 3\x00'
#: BLOBs read per table, at most: a database of millions of rows keeps
#: its pictures in a few tables, and a cap keeps one from taking the run.
MAX_BLOBS_PER_TABLE = 100_000
#: A BLOB this short is no picture worth a place in a review.
MIN_BLOB = 32

#: How a BLOB that is a picture or video starts -> the extension its
#: member is named with (the export judges it again, whole).
_BLOB_STARTS = (
    (b'\xff\xd8\xff', 'jpg'), (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'GIF87a', 'gif'), (b'GIF89a', 'gif'), (b'BM', 'bmp'),
    (b'II*\x00', 'tif'), (b'MM\x00*', 'tif'), (b'RIFF', 'riff'),
    (b'\x00\x00\x01\x00', 'ico'),
)


class Member:
    """One file found inside another. `chain` is the names from the
    outermost container's first member down to this one."""

    __slots__ = ('chain', 'content', 'modified', 'kind')

    def __init__(self, chain, content, modified=None, kind=''):
        self.chain, self.content = chain, content
        self.modified, self.kind = modified, kind

    @property
    def name(self):
        return self.chain[-1].replace('\\', '/').rstrip('/').rsplit(
            '/', 1)[-1] or 'member'


def kind_of(head_or_content):
    """'archive:<kind>' / 'document:<kind>' / 'database:sqlite' when the
    bytes are a container whose members are read here, else None. Cheap:
    the header only."""
    if not hasattr(head_or_content, 'read') and \
            bytes(head_or_content[:16]) == SQLITE_HEADER:
        return 'database:sqlite'
    try:
        kind = archives.detect_archive(head_or_content)
    except Exception:
        kind = None
    if kind is not None:
        return f'archive:{kind}'
    try:
        kind = embedded.kind_of(head_or_content)
    except Exception:
        kind = None
    if kind in DOCUMENT_KINDS:
        return f'document:{kind}'
    return None


def members(content, depth=None, should_stop=None, chain=()):
    """Every member of `content` (bytes, or a file object for a mailbox),
    and of the containers among them, to `depth` levels (the case's
    archive nesting setting, archives.MAX_NESTING, by default: a picture
    in a .zip in an attachment of a message in a mailbox is 3 deep)."""
    if depth is None:
        depth = archives.MAX_NESTING
    if depth <= 0 or content is None:
        return
    found = kind_of(content)
    if found is None:
        return
    family, _, kind = found.partition(':')
    if family == 'archive':
        listing = _archive_members(content, kind)
    elif family == 'database':
        listing = _database_members(content)
    else:
        listing = _document_members(content)
    for name, member_bytes, modified in listing:
        if should_stop is not None and should_stop():
            return
        here = chain + (name,)
        yield Member(here, member_bytes, modified, kind)
        if depth > 1 and member_bytes:
            yield from members(member_bytes, depth - 1, should_stop, here)


def _archive_members(content, kind):
    try:
        for member, member_bytes in archives.iter_members(content, kind):
            if member.get('is_dir') or member_bytes is None:
                continue
            if isinstance(member_bytes, Exception):
                logger.debug("Member %s not read: %s", member.get('name'),
                             member_bytes)
                continue
            yield member['name'], member_bytes, member.get('modified')
    except archives.ArchiveError as exc:
        logger.debug("Archive (%s) not listed: %s", kind, exc)
    except Exception as exc:                # a damaged container
        logger.debug("Archive (%s) not read whole: %s: %s", kind,
                     type(exc).__name__, exc)


def _document_members(content):
    try:
        for member, member_bytes in embedded.iter_members(bytes(content)):
            yield member['name'], member_bytes, None
    except Exception as exc:
        logger.debug("Embedded files not read: %s", exc)


def blob_extension(value):
    """The extension of a picture BLOB by how it starts, else None."""
    head = bytes(value[:16])
    for start, extension in _BLOB_STARTS:
        if head.startswith(start):
            if extension == 'riff':
                return {b'WEBP': 'webp', b'AVI ': 'avi'}.get(head[8:12])
            return extension
    if head[4:8] == b'ftyp':
        return 'heic' if head[8:12] in (b'heic', b'heix', b'mif1') \
            else 'mp4'
    return None


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _database_members(content):
    """Every BLOB of a SQLite database that starts as a picture or video
    does: 'table.column row N.ext' -- an avatar, a message's thumbnail, a
    cached image. SQLite types each value, not each column, so every
    column is asked (typeof = 'blob')."""
    import sqlite3
    from trace_app.core.activity import sqlite_bytes
    try:
        with sqlite_bytes.open_database(bytes(content)) as connection:
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'")]
            urls = _cfurl_names(connection, tables)
            for table in tables:
                try:
                    columns = [row[1] for row in connection.execute(
                        f"PRAGMA table_info({_quote(table)})")]
                except sqlite3.DatabaseError:
                    continue            # a virtual table's module is absent
                for column in columns:
                    for name, value, modified in _blobs(connection, table,
                                                        column):
                        if table == 'cfurl_cache_receiver_data' and urls:
                            rowid = int(name.split(' row ', 1)[1]
                                        .split('.', 1)[0])
                            name = urls.get(rowid, name)
                        yield name, value, modified
    except sqlite3.DatabaseError as exc:
        logger.debug("Database not read: %s", exc)


def _cfurl_names(connection, tables):
    """Apple's URL cache (Safari's and every app's Cache.db): receiver
    data row id -> the file name of the URL it was fetched from, from
    cfurl_cache_response (entry_ID, request_key). A body kept on disk
    instead (isDataOnFS, fsCachedData/<uuid>) is a file the walk sees."""
    import sqlite3
    if not {'cfurl_cache_receiver_data', 'cfurl_cache_response'} <= \
            set(tables):
        return {}
    from trace_app.core.firefox_cache import url_name
    try:
        rows = connection.execute(
            "SELECT d.rowid, r.request_key FROM cfurl_cache_receiver_data d "
            "JOIN cfurl_cache_response r ON r.entry_ID = d.entry_ID")
        return {rowid: url_name(str(key or ''), rowid)
                for rowid, key in rows}
    except sqlite3.DatabaseError as exc:
        logger.debug("Cache.db URLs not read: %s", exc)
        return {}


def _blobs(connection, table, column):
    import sqlite3
    where = (f"WHERE typeof({_quote(column)}) = 'blob' AND "
             f"length({_quote(column)}) >= {MIN_BLOB} "
             f"LIMIT {MAX_BLOBS_PER_TABLE}")
    try:
        rows = connection.execute(
            f"SELECT rowid, {_quote(column)} FROM {_quote(table)} {where}")
    except sqlite3.DatabaseError:
        try:                            # WITHOUT ROWID: number them
            values = connection.execute(
                f"SELECT {_quote(column)} FROM {_quote(table)} {where}")
            rows = enumerate((row[0] for row in values), 1)
        except sqlite3.DatabaseError as exc:
            logger.debug("%s.%s not read: %s", table, column, exc)
            return
    try:
        for rowid, value in rows:
            extension = blob_extension(value)
            if extension:
                yield (f"{table}.{column} row {rowid}.{extension}",
                       bytes(value), None)
    except sqlite3.DatabaseError as exc:
        logger.debug("%s.%s not read whole: %s", table, column, exc)

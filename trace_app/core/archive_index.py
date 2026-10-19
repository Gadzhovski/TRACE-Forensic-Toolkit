"""Big archives browsed from an index, never read whole (no Qt).

A phone extraction is a 16 GB tar of 342,453 members. Opened like any
archive it was read whole into memory and listed flat, on the window's
thread: TRACE froze until all of it was in the Listing. Here an archive
too big to hold (over archives.MAX_MEMBER_BYTES) is indexed once, in a
background job (`build`): an uncompressed tar's headers, read one after
another -- its data skipped by a seek each -- or a ZIP's central directory.
The index is a small SQLite file kept beside the case (or in the user data
folder for quick triage), keyed by where the archive is and its size and
time, so opening it again is instant. The Listing then shows one folder at
a time (`IndexedArchive.level`), and a member is read at the offset its
header gave (`IndexedArchive.read`): a tar member is plain bytes in place.

Compressed tars (.tar.gz) cannot be read from the middle and stay what
they were: read whole when small enough, refused when not.
"""

import datetime
import hashlib
import logging
import os
import posixpath
import sqlite3
import tarfile
import zipfile

from trace_app.infra.sqlite_uri import connect_read_only

logger = logging.getLogger('TRACE.ArchiveIndex')

#: What can be indexed and read from the middle.
KINDS = ('tar', 'zip')
#: Index format; a change rebuilds old indexes.
VERSION = 2
#: Rows written per transaction.
BATCH = 5000


class IndexCancelled(Exception):
    pass


class ArchiveIndexError(Exception):
    """The archive could not be indexed or a member read."""


def index_file(folder, image_path, start_offset, inode, size, mtime=''):
    """Where the index of one archive on one piece of evidence lives."""
    key = hashlib.sha1(
        f"{os.path.normpath(image_path)}|{start_offset}|{inode}|{size}|"
        f"{mtime}|{VERSION}".encode('utf-8', 'replace')).hexdigest()
    return os.path.join(folder, f"{key}.sqlite")


def is_complete(path):
    """Whether a finished index is at `path`."""
    if not os.path.isfile(path):
        return False
    try:
        connection = connect_read_only(path)
        try:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'complete'").fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return False
    return bool(row and row[0] == '1')


def _clean(name):
    name = name.replace('\\', '/')
    while name.startswith('./'):
        name = name[2:]
    return posixpath.normpath(name.strip('/')) if name.strip('/') else ''


def _utc(seconds):
    try:
        return datetime.datetime.fromtimestamp(
            seconds, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return None


def build(stream, kind, target, should_stop=None, progress=None):
    """Index the archive `stream` (a seekable file object) of `kind` into
    `target`, written beside it and renamed only when whole: a cancel or a
    failure leaves no index. Returns the member count.

    Stored as a tree -- each member its own name and its folder's id --
    not by full path: 342,453 paths, twice over with their index, made a
    232 MB file."""
    if kind not in KINDS:
        raise ArchiveIndexError(f"{kind} archives are not indexed")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    partial = target + '.partial'
    if os.path.exists(partial):
        os.remove(partial)
    connection = sqlite3.connect(partial)
    try:
        connection.executescript(
            "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;"
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE members (id INTEGER PRIMARY KEY, parent INTEGER, "
            "name TEXT, is_dir INTEGER, size INTEGER, compressed INTEGER, "
            "modified TEXT, offset INTEGER, encrypted INTEGER, crc INTEGER, "
            "link TEXT);")
        stream.seek(0, os.SEEK_END)
        total = stream.tell()
        stream.seek(0)
        rows = (_tar_rows if kind == 'tar' else _zip_rows)(
            stream, total, should_stop, progress)
        count = _write(connection, rows)
        connection.execute("CREATE UNIQUE INDEX members_parent ON "
                           "members (parent, name)")
        connection.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [('kind', kind), ('count', str(count)), ('size', str(total)),
             ('version', str(VERSION)), ('complete', '1')])
        connection.commit()
    except BaseException:
        connection.close()
        try:
            os.remove(partial)
        except OSError:
            pass
        raise
    connection.close()
    os.replace(partial, target)
    return count


#: The top folder's id (it has no row).
ROOT = 0


def _write(connection, rows):
    """Rows into the members table. A path listed twice (a tar appended
    to) keeps its last entry, as tar itself does on extraction."""
    folders = {'': ROOT}
    files = {}
    pending, count = [], 0
    next_id = [ROOT]

    def new_id():
        next_id[0] += 1
        return next_id[0]

    def folder_id(path):
        # Every folder a member sits in, whether the archive lists it or
        # not (tars often hold files only).
        if path in folders:
            return folders[path]
        parent = folder_id(posixpath.dirname(path))
        ident = new_id()
        folders[path] = ident
        pending.append((ident, parent, posixpath.basename(path), 1, 0, 0,
                        None, None, 0, None, None))
        return ident

    def flush():
        connection.executemany(
            "INSERT OR REPLACE INTO members VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            pending)
        pending.clear()

    for row in rows:
        path = row[0]
        if not path:
            continue
        parent = folder_id(posixpath.dirname(path))
        if row[3]:                          # a folder entry
            if path in folders:
                continue
            ident = folders[path] = new_id()
        else:
            ident = files.get(path)
            if ident is None:
                ident = files[path] = new_id()
            else:
                count -= 1              # the same member, written again
        pending.append((ident, parent, posixpath.basename(path)) + row[3:])
        count += 1
        if len(pending) >= BATCH:
            flush()
    if pending:
        flush()
    return count


def _tar_rows(stream, total, should_stop, progress):
    """(path, '', '', is_dir, size, compressed, modified, offset,
    encrypted, crc, link) per member, header after header."""
    try:
        tar = tarfile.open(fileobj=stream, mode='r:')
    except tarfile.TarError as exc:
        raise ArchiveIndexError(f"Not a readable tar: {exc}") from exc
    number = 0
    while True:
        try:
            info = tar.next()
        except tarfile.TarError as exc:
            # A tar cut short (an acquisition stopped): what came before
            # is listed, and the index says where it stopped.
            logger.warning("Tar ends in damage after %s members: %s",
                           number, exc)
            break
        if info is None:
            break
        tar.members.clear()     # 342,453 TarInfos held were ~300 MB
        number += 1
        if number % 2000 == 0:
            if should_stop is not None and should_stop():
                raise IndexCancelled()
            if progress is not None:
                progress(info.offset, total,
                         f"{number:,} members listed")
        path = _clean(info.name)
        link = info.linkname if (info.issym() or info.islnk()) else None
        yield (path, '', '', 1 if info.isdir() else 0,
               0 if info.isdir() or link else info.size,
               0 if info.isdir() or link else info.size, _utc(info.mtime),
               info.offset_data if info.isreg() else None, 0, None, link)


def _zip_rows(stream, total, should_stop, progress):
    try:
        zipped = zipfile.ZipFile(stream)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveIndexError(f"Not a readable ZIP: {exc}") from exc
    infos = zipped.infolist()
    for number, info in enumerate(infos, start=1):
        if number % 2000 == 0:
            if should_stop is not None and should_stop():
                raise IndexCancelled()
            if progress is not None:
                progress(number, len(infos), f"{number:,} members listed")
        try:
            modified = datetime.datetime(*info.date_time).strftime(
                '%Y-%m-%d %H:%M:%S')
        except ValueError:
            modified = None
        yield (_clean(info.filename), '', '', 1 if info.is_dir() else 0,
               info.file_size, info.compress_size, modified,
               info.header_offset, 1 if info.flag_bits & 0x1 else 0,
               info.CRC, None)


class IndexedArchive:
    """An indexed archive: its folders level by level, its members read
    where they are. `opener()` gives a fresh seekable stream over the
    archive (from the image, or the file itself)."""

    def __init__(self, path, opener, name=''):
        self.path, self.opener, self.name = path, opener, name
        self._db = connect_read_only(path, check_same_thread=False)
        meta = dict(self._db.execute("SELECT key, value FROM meta"))
        self.kind = meta['kind']
        self.count = int(meta['count'])
        self._stream = None
        self._zip = None

    def close(self):
        self._db.close()

    _COLUMNS = ("id, name, is_dir, size, compressed, modified, encrypted, "
                "crc, link")

    @staticmethod
    def _member(folder, row):
        (_ident, name, is_dir, size, compressed, modified, encrypted, crc,
         link) = row
        return {'name': posixpath.join(folder, name) if folder else name,
                'size': size or 0, 'compressed_size': compressed or 0,
                'is_dir': bool(is_dir), 'modified': modified,
                'encrypted': bool(encrypted), 'crc': crc, 'link': link}

    def _folder_id(self, folder):
        ident = ROOT
        for part in [p for p in _clean(folder).split('/') if p]:
            row = self._db.execute(
                "SELECT id FROM members WHERE parent = ? AND name = ? "
                "AND is_dir = 1", (ident, part)).fetchone()
            if row is None:
                return None
            ident = row[0]
        return ident

    def level(self, folder=''):
        """The members directly inside `folder` ('' = the top), folders
        first, as archives.list_members gives them (full paths)."""
        folder = _clean(folder)
        ident = self._folder_id(folder)
        if ident is None:
            return []
        return [self._member(folder, row) for row in self._db.execute(
            f"SELECT {self._COLUMNS} FROM members WHERE parent = ? "
            f"ORDER BY is_dir DESC, name", (ident,))]

    def member(self, path):
        path = _clean(path)
        parent = self._folder_id(posixpath.dirname(path))
        if parent is None:
            return None
        row = self._db.execute(
            f"SELECT {self._COLUMNS}, offset FROM members WHERE parent = ? "
            f"AND name = ?", (parent, posixpath.basename(path))).fetchone()
        if row is None:
            return None
        found = self._member(posixpath.dirname(path), row[:-1])
        found['offset'] = row[-1]
        return found

    def _source(self):
        if self._stream is None:
            self._stream = self.opener()
            if self._stream is None:
                raise ArchiveIndexError(f"{self.name} could not be opened")
        return self._stream

    def read(self, path, limit=None):
        """A member's bytes, read where it is."""
        from trace_app.core import archives
        limit = archives.MAX_MEMBER_BYTES if limit is None else limit
        member = self.member(path)
        if member is None:
            raise archives.ArchiveError(f"No member {path} in {self.name}")
        if member['is_dir']:
            raise archives.ArchiveError(f"{path} is a folder")
        if member['link']:
            raise archives.ArchiveError(
                f"{path} is a link to {member['link']}")
        if member['size'] > limit:
            raise archives.ArchiveError(
                f"{path} is {member['size']:,} bytes, more than the "
                f"{limit:,} read from an archive (Settings ▸ Analysis)")
        stream = self._source()
        if self.kind == 'tar':
            stream.seek(member['offset'])
            data = stream.read(member['size'])
            if len(data) != member['size']:
                raise archives.ArchiveError(f"{path} is cut short")
            return data
        if member['encrypted']:
            raise archives.EncryptedArchive(f"{path} is encrypted")
        if self._zip is None:
            self._zip = zipfile.ZipFile(stream)
        try:
            return self._zip.read(member['name'] if member['name'] in
                                  self._zip.NameToInfo else
                                  self._zip_name(path))
        except (zipfile.BadZipFile, KeyError, OSError, EOFError) as exc:
            raise archives.ArchiveError(f"{path}: {exc}") from exc

    def _zip_name(self, path):
        wanted = _clean(path)
        for name in self._zip.namelist():
            if _clean(name) == wanted:
                return name
        raise KeyError(path)

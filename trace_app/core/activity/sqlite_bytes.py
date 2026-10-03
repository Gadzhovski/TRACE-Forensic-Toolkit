"""Reading a SQLite database that exists only as bytes from the evidence.

Browsers keep history in SQLite, and recent changes often sit in the
write-ahead log beside it (Firefox's places.sqlite-wal) rather than in the
database. Both are read from the image; the log's committed frames -- those
whose checksums and salts hold, up to the last commit -- are applied to a
copy of the database pages here, so what is read is what the browser last
committed, not what it last checkpointed.

The copy is opened in memory where Python can (sqlite3 deserialize, Python
3.11+). On 3.10 there is no in-memory loader, so it goes to a private
temporary file, deleted as soon as it is read; the evidence is never
written to.
"""

import contextlib
import os
import sqlite3
import struct
import tempfile

HEADER = b'SQLite format 3\x00'


def apply_wal(database, wal):
    """`database` with the committed frames of `wal` applied."""
    if not wal or len(wal) < 32:
        return database
    magic = struct.unpack_from('>I', wal, 0)[0]
    if magic not in (0x377F0682, 0x377F0683):
        return database
    big = magic == 0x377F0683
    page_size = struct.unpack_from('>I', wal, 8)[0] or 65536
    salt = wal[16:24]
    s0, s1 = _checksum(wal[:24], 0, 0, big)
    if (s0, s1) != struct.unpack_from('>II', wal, 24):
        return database
    pages = bytearray(database)
    committed, pending = {}, {}
    size_in_pages = None
    at = 32
    while at + 24 + page_size <= len(wal):
        header = wal[at:at + 24]
        if header[8:16] != salt:
            break
        s0, s1 = _checksum(header[:8], s0, s1, big)
        page = wal[at + 24:at + 24 + page_size]
        s0, s1 = _checksum(page, s0, s1, big)
        if (s0, s1) != struct.unpack_from('>II', header, 16):
            break                       # torn or stale: stop here
        number, commit = struct.unpack_from('>II', header, 0)
        pending[number] = page
        if commit:                      # a transaction's last frame
            committed.update(pending)
            pending = {}
            size_in_pages = commit
        at += 24 + page_size
    if size_in_pages is None:
        return database
    needed = size_in_pages * page_size
    if len(pages) < needed:
        pages.extend(b'\x00' * (needed - len(pages)))
    for number, page in committed.items():
        start = (number - 1) * page_size
        pages[start:start + page_size] = page
    return bytes(pages[:needed])


def _checksum(data, s0, s1, big):
    form = '>' if big else '<'
    for x0, x1 in struct.iter_unpack(form + 'II', data[:len(data) // 8 * 8]):
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF
    return s0, s1


@contextlib.contextmanager
def open_database(database, wal=None):
    """A read-only connection to `database` (bytes), its WAL applied."""
    if database[:16] != HEADER:
        raise sqlite3.DatabaseError("not a SQLite database")
    data = bytearray(apply_wal(database, wal))
    # Mark the copy as rollback-journal mode: in WAL mode SQLite would look
    # for -wal and -shm files that are not there (and already applied).
    data[18] = data[19] = 1
    if hasattr(sqlite3.Connection, 'deserialize'):
        connection = sqlite3.connect(':memory:')
        try:
            connection.deserialize(bytes(data))
            connection.execute('PRAGMA query_only = ON')
            yield connection
        finally:
            connection.close()
        return
    folder = tempfile.mkdtemp(prefix='trace-sqlite-')
    path = os.path.join(folder, 'copy.sqlite')
    try:
        with open(path, 'wb') as handle:
            handle.write(data)
        connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            yield connection
        finally:
            connection.close()
    finally:
        try:
            os.remove(path)
            os.rmdir(folder)
        except OSError:
            pass


def tables(connection):
    return {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def columns(connection, table):
    return {row[1] for row in connection.execute(
        f"PRAGMA table_info('{table}')")}

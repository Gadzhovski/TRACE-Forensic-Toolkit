"""Deleted records in a SQLite database, read from where SQLite leaves them.

SQLite does not erase what it deletes (unless secure_delete is on). A
deleted row stays where it was until its space is reused:

* **freelist pages** -- a page emptied by deletes goes on the freelist with
  its cells untouched; read as the table page it was, every cell is whole
  (rowid and all)
* **freeblocks** -- a single deleted cell inside a live page becomes a
  freeblock, its first four bytes overwritten by the freeblock's own header
  (next pointer, size). The rest of the record header and the values
  survive; the lost leading bytes are rebuilt where the schema allows it (an
  INTEGER PRIMARY KEY column is stored as NULL, its value in the rowid) and
  marked as lost where it does not
* **unused space inside a page** -- between the cell pointer array and the
  cells, where whole cells can remain after the page was rewritten
* **the WAL** -- every frame is a version of a page; versions older than the
  last committed one hold rows as they were before an update or delete

Each record is matched to a table by its column count and the kinds of its
values (an INTEGER column holding text is not that table's). What a record
is is never guessed beyond that: a record no table fits is listed with its
column count alone.

Format: sqlite.org/fileformat2.html. No Qt here.
"""

import logging
import re
import sqlite3
import struct

logger = logging.getLogger('TRACE.SQLiteRecover')

TABLE_LEAF, TABLE_INTERIOR = 0x0D, 0x05
MAX_PAGES = 2_000_000
MAX_RECORDS = 100_000


class RecoverError(Exception):
    pass


def varint(data, position):
    """(value, next position) of a SQLite varint."""
    value = 0
    for index in range(9):
        if position + index >= len(data):
            raise IndexError("varint runs off the end")
        byte = data[position + index]
        if index == 8:
            return (value << 8) | byte, position + 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, position + index + 1
    raise IndexError("varint too long")       # pragma: no cover


def serial_size(kind):
    """Bytes a value of this serial type takes; -1 for the reserved 10
    and 11, which no record holds."""
    if kind in (10, 11):
        return -1
    if kind < 12:
        return (0, 1, 2, 3, 4, 6, 8, 8, 0, 0)[kind]
    return (kind - 12) // 2 if kind % 2 == 0 else (kind - 13) // 2


def serial_value(kind, data, encoding='utf-8'):
    if kind == 0:
        return None
    if 1 <= kind <= 6:
        return int.from_bytes(data, 'big', signed=True)
    if kind == 7:
        return struct.unpack('>d', data)[0]
    if kind == 8:
        return 0
    if kind == 9:
        return 1
    if kind >= 13 and kind % 2:
        return data.decode(encoding, 'replace')
    return bytes(data)


def _kind_name(kind):
    if kind == 0:
        return 'null'
    if 1 <= kind <= 6 or kind in (8, 9):
        return 'integer'
    if kind == 7:
        return 'real'
    return 'text' if kind % 2 else 'blob'


class Table:
    def __init__(self, name, columns, affinities, rowid_alias, pages):
        self.name, self.columns = name, columns
        self.affinities, self.rowid_alias = affinities, rowid_alias
        self.pages = pages

    def fits(self, kinds):
        """Could a record with these serial types be a row of this table?"""
        if len(kinds) != len(self.columns):
            return False
        for kind, affinity in zip(kinds, self.affinities):
            name = _kind_name(kind)
            if name == 'null':
                continue
            if affinity == 'integer' and name in ('text', 'blob'):
                return False
            if affinity == 'text' and name in ('real', 'blob'):
                return False
        return True


def _affinity(declared):
    declared = (declared or '').upper()
    if 'INT' in declared:
        return 'integer'
    if any(word in declared for word in ('CHAR', 'CLOB', 'TEXT')):
        return 'text'
    if 'BLOB' in declared or not declared:
        return 'blob'
    if any(word in declared for word in ('REAL', 'FLOA', 'DOUB')):
        return 'real'
    return 'numeric'


#: Full-text-search and statistics tables SQLite keeps for itself: their
#: rows are index structures of integers and blobs, which random bytes fit
#: as easily as real rows -- recovering "rows" of them is noise.
_SHADOW = ('_segments', '_segdir', '_docsize', '_stat', '_idx', '_data',
           '_config')


def _telling(values):
    """Does a recovered record hold anything an examiner can read -- a
    text of two characters or more, or a blob of four bytes? A record of
    small integers and NULLs is what random bytes most easily look like."""
    return any((isinstance(v, str) and len(v.strip()) >= 2) or
               (isinstance(v, bytes) and len(v) >= 4) for v in values)


class Database:
    """A SQLite database's pages, schema and the tables' pages."""

    def __init__(self, data):
        if data[:16] != b'SQLite format 3\x00':
            raise RecoverError("Not a SQLite database")
        self.data = data
        size = struct.unpack_from('>H', data, 16)[0]
        self.page_size = 65536 if size == 1 else size
        self.usable = self.page_size - data[20]
        self.pages = min(len(data) // self.page_size, MAX_PAGES)
        self.encoding = {1: 'utf-8', 2: 'utf-16-le', 3: 'utf-16-be'}.get(
            struct.unpack_from('>I', data, 56)[0], 'utf-8')
        self.tables = self._schema()

    def page(self, number):
        start = (number - 1) * self.page_size
        return self.data[start:start + self.page_size]

    def _schema(self):
        from trace_app.core.activity import sqlite_bytes
        tables = []
        try:
            with sqlite_bytes.open_database(self.data) as db:
                rows = db.execute("SELECT name, rootpage, sql FROM "
                                  "sqlite_master WHERE type = 'table'"
                                  ).fetchall()
                for name, root, sql in rows:
                    if not root or name.startswith('sqlite_') or \
                            name.endswith(_SHADOW):
                        continue
                    info = db.execute(f'PRAGMA table_info("{name}")'
                                      ).fetchall()
                    columns = [c[1] for c in info]
                    affinities = [_affinity(c[2]) for c in info]
                    alias = next((i for i, c in enumerate(info) if c[5] and
                                  (c[2] or '').upper() == 'INTEGER'), None)
                    if 'WITHOUT ROWID' in (sql or '').upper():
                        continue
                    tables.append(Table(name, columns, affinities, alias,
                                        self._tree(root)))
        except sqlite3.DatabaseError as exc:
            logger.debug("Schema unreadable: %s", exc)
        return tables

    def _tree(self, root):
        """Leaf pages of a table's b-tree."""
        leaves, stack, seen = [], [root], set()
        while stack:
            number = stack.pop()
            if number in seen or not 0 < number <= self.pages:
                continue
            seen.add(number)
            page = self.page(number)
            header = 100 if number == 1 else 0
            kind = page[header]
            if kind == TABLE_LEAF:
                leaves.append(number)
            elif kind == TABLE_INTERIOR:
                count = struct.unpack_from('>H', page, header + 3)[0]
                stack.append(struct.unpack_from('>I', page, header + 8)[0])
                for index in range(count):
                    pointer = struct.unpack_from('>H', page,
                                                 header + 12 + 2 * index)[0]
                    if pointer + 4 <= len(page):
                        stack.append(struct.unpack_from('>I', page,
                                                        pointer)[0])
        return leaves

    def freelist(self):
        """Every page on the freelist (trunk and leaf)."""
        out, trunk, seen = [], struct.unpack_from('>I', self.data, 32)[0], \
            set()
        while trunk and trunk not in seen and trunk <= self.pages:
            seen.add(trunk)
            out.append(trunk)
            page = self.page(trunk)
            following, count = struct.unpack_from('>II', page, 0)
            for index in range(min(count, (self.usable - 8) // 4)):
                leaf = struct.unpack_from('>I', page, 8 + 4 * index)[0]
                if 0 < leaf <= self.pages:
                    out.append(leaf)
            trunk = following
        return out

    def table_of_page(self):
        return {number: table for table in self.tables
                for number in table.pages}

    # --- reading records -----------------------------------------------------

    def record(self, data, position, columns=None, end=None):
        """(serial types, values, end) of the record header at `position`,
        or None. `columns` checks the count; nothing may run past `end`."""
        end = len(data) if end is None else end
        try:
            header_size, cursor = varint(data, position)
            header_end = position + header_size
            if header_size < 2 or header_end > end:
                return None
            kinds = []
            while cursor < header_end:
                kind, cursor = varint(data, cursor)
                if kind in (10, 11):
                    return None
                kinds.append(kind)
            if cursor != header_end or not kinds:
                return None
            if columns is not None and len(kinds) != columns:
                return None
            return self._values(data, header_end, kinds, end)
        except IndexError:
            return None

    def _values(self, data, body, kinds, end):
        values, cursor = [], body
        for kind in kinds:
            size = serial_size(kind)
            if size < 0 or cursor + size > end:
                return None
            values.append(serial_value(kind, data[cursor:cursor + size],
                                       self.encoding))
            cursor += size
        return kinds, values, cursor

    def cells(self, page, number):
        """(rowid, kinds, values) of every cell of a table leaf page (as it
        was, if it is a freed page), whole cells only."""
        header = 100 if number == 1 else 0
        if page[header] != TABLE_LEAF:
            return
        count = struct.unpack_from('>H', page, header + 3)[0]
        for index in range(min(count, self.page_size // 2)):
            pointer = struct.unpack_from('>H', page,
                                         header + 8 + 2 * index)[0]
            cell = self._cell(page, pointer)
            if cell:
                yield cell

    def _cell(self, page, pointer):
        try:
            payload, cursor = varint(page, pointer)
            rowid, cursor = varint(page, cursor)
        except IndexError:
            return None
        if payload > self.usable - 35:
            return None                  # spills to overflow pages: skipped
        parsed = self.record(page, cursor, end=cursor + payload)
        if parsed is None:
            return None
        kinds, values, stop = parsed
        if stop != cursor + payload:
            return None                  # a cell is exactly its payload
        return rowid, kinds, values

    def live_rows(self):
        """The content keys of every row that is not deleted."""
        out = set()
        for table in self.tables:
            for number in table.pages:
                for _rowid, _kinds, values in self.cells(self.page(number),
                                                         number):
                    out.add(_key(table, values))
        return out


def _comparable(values):
    return [v if not isinstance(v, float) else round(v, 9) for v in values]


def _match(tables, kinds):
    fits = [t for t in tables if t.fits(kinds)]
    return fits[0] if len(fits) == 1 else None


def _row(table, kinds, values, rowid, source, page, offset, note=''):
    if table is not None and table.rowid_alias is not None and rowid is not \
            None and values[table.rowid_alias] is None:
        values = list(values)
        values[table.rowid_alias] = rowid
    return {'table': table.name if table else None,
            'columns': list(table.columns) if table else
            [f'column {i + 1}' for i in range(len(values))],
            'values': list(values), 'rowid': rowid, 'source': source,
            'page': page, 'offset': offset, 'note': note}


def _freeblocks(page, number):
    header = 100 if number == 1 else 0
    position, seen = struct.unpack_from('>H', page, header + 1)[0], set()
    while position and position not in seen and position + 4 <= len(page):
        seen.add(position)
        following, size = struct.unpack_from('>HH', page, position)
        if size < 4 or position + size > len(page):
            break
        yield position, size
        position = following


def _from_freeblock(db, table, page, number, start, size):
    """A deleted cell from a freeblock: its first four bytes are the
    freeblock's header now. The record header is looked for just after them
    (or a byte or two later), with up to two leading serial types lost --
    taken as NULL where the column is the rowid alias, as SQLite stores it,
    and reported lost otherwise."""
    end = start + size
    best = None
    for lost in (0, 1, 2):
        wanted = len(table.columns) - lost
        if wanted < 1:
            continue
        for first in range(start + 4, min(start + 8, end)):
            kinds, cursor = [], first
            try:
                while len(kinds) < wanted:
                    kind, cursor = varint(page, cursor)
                    if kind in (10, 11):
                        raise IndexError
                    kinds.append(kind)
            except IndexError:
                continue
            known = sum(serial_size(k) for k in kinds)
            # A lost value takes the space the known ones leave: a
            # freeblock is the deleted cell's size. Two lost values cannot
            # be told apart, so only NULLs are assumed for them.
            spare = end - cursor - known
            if lost == 1 and spare > 0:
                lost_bytes = page[cursor:cursor + spare]
                lost_value = lost_bytes.decode(db.encoding, 'replace')
                if _garbled(lost_value):
                    continue
                leading_kind = 13 + 2 * spare       # text of that length
                body = cursor + spare
            else:
                lost_value, leading_kind, body = None, 0, cursor
            leading = [leading_kind] * lost if lost == 1 else [0] * lost
            if not table.fits(leading + kinds):
                continue
            parsed = db._values(page, body, kinds, end)
            if parsed is None:
                continue
            _kinds, values, stop = parsed
            if any(isinstance(v, str) and _garbled(v) for v in values):
                continue
            if not _telling(([lost_value] if lost_value else []) + values):
                continue                  # nothing in it is evidence
            score = (lost, abs(end - stop), first - start - 4)
            if best is None or score < best[0]:
                note = '' if not lost else (
                    f"the first {lost} value(s)' type was overwritten by "
                    f"the freeblock header; "
                    + ("its length is what the other values leave"
                       if lost == 1 and lost_value is not None else
                       "taken as empty"))
                restored = ([lost_value] if lost == 1 else
                            [None] * lost) + list(values)
                best = (score, leading + kinds, restored, note)
    if best is None:
        return None
    _score, kinds, values, note = best
    if table.rowid_alias is not None and values[table.rowid_alias] is None:
        note = ("its id (the rowid) was in the bytes the freeblock header "
                "overwrote" + (f"; {note}" if note else ''))
    return _row(table, kinds, values, None, 'freeblock', number, start,
                note)


_CONTROL = re.compile(r'[\x00-\x08\x0e-\x1f]')


def _garbled(text):
    return bool(text) and (len(_CONTROL.findall(text)) > len(text) // 8
                           or '�' in text)


def _stale_freeblocks(page, begin, end):
    """Old freeblock headers in a stretch of a page: (start, size) where
    the four bytes read as one -- a next pointer of 0 or further on, a size
    that fits -- left behind when the page was rewritten."""
    position = begin
    while position + 8 <= end:
        following, size = struct.unpack_from('>HH', page, position)
        if 12 <= size <= end - position and (
                following == 0 or position < following < len(page)):
            yield position, size
        position += 1


def _from_unused(db, table, page, number, seen):
    """Records in the gap between the cell pointers and the cells: whole
    cells, and cells behind old freeblock headers (the page was rewritten
    since they were deleted; their values are where they were)."""
    header = 100 if number == 1 else 0
    count = struct.unpack_from('>H', page, header + 3)[0]
    gap_start = header + 8 + 2 * count
    content = struct.unpack_from('>H', page, header + 5)[0] or 65536
    out = []
    for start, size in _stale_freeblocks(page, gap_start,
                                         min(content, len(page))):
        row = _from_freeblock(db, table, page, number, start, size)
        if row is None:
            continue
        key = _key(table, row['values'])
        if key not in seen:
            seen.add(key)
            row['source'] = 'unused space in page'
            out.append(row)
    position = gap_start
    while position < min(content, len(page)) - 3:
        cell = db._cell(page, position)
        if cell and len(cell[1]) == len(table.columns) and \
                table.fits(cell[1]) and _telling(cell[2]) and not any(
                    isinstance(v, str) and _garbled(v) for v in cell[2]):
            rowid, kinds, values = cell
            key = _key(table, values)
            if key not in seen:
                out.append(_row(table, kinds, values, rowid,
                                'unused space in page', number, position))
                seen.add(key)
            position += 2
            continue
        position += 1
    return out


def _scan_cells(db, page, number, tables, seen, source, note='',
                begin=None, end=None):
    """Whole cells anywhere in a page (or in [begin, end) of it) that no
    longer lists them: a freed page's cell count is 0 -- each cell's
    pointer was dropped as it was deleted -- but the cells are where they
    were; deleted cells side by side merge into one freeblock, of which
    only the first loses its leading bytes."""
    out = []
    header = 100 if number == 1 else 0
    position = max(8, header + 8) if begin is None else begin
    limit = len(page) if end is None else end
    while position < limit - 3:
        cell = db._cell(page, position)
        if cell:
            rowid, kinds, values = cell
            table = next((t for t in tables if t.fits(kinds)), None) \
                if len(tables) != 1 else (tables[0] if tables[0].fits(kinds)
                                          else None)
            if table is not None and not any(
                    isinstance(v, str) and _garbled(v) for v in values) \
                    and _telling(values):
                key = _key(table, values)
                if key not in seen:
                    seen.add(key)
                    out.append(_row(table, kinds, values, rowid, source,
                                    number, position, note))
                position += 2
                continue
        position += 1
    return out


def _key(table, values):
    """What identifies a row's content, the rowid alias aside (a
    freeblock loses the rowid; the same row from the WAL keeps it)."""
    values = list(values)
    if table is not None and table.rowid_alias is not None and \
            table.rowid_alias < len(values):
        values[table.rowid_alias] = None
    return (table.name if table else None,
            tuple(_comparable(values)))


def wal_frames(wal, page_size):
    """[(frame number, page number, commit size, page bytes)] of a WAL,
    every frame whose salts match the header's."""
    if not wal or len(wal) < 32 or wal[:4] not in (b'\x37\x7f\x06\x82',
                                                  b'\x37\x7f\x06\x83'):
        return []
    size = struct.unpack_from('>I', wal, 8)[0]
    salts = wal[16:24]
    out, position, number = [], 32, 0
    while position + 24 + size <= len(wal):
        page, commit = struct.unpack_from('>II', wal, position)
        number += 1
        if wal[position + 8:position + 16] == salts and page:
            out.append((number, page, commit,
                        wal[position + 24:position + 24 + size]))
        position += 24 + size
    return out


def recover(data, wal=None, limit=MAX_RECORDS):
    """Records deleted (or overwritten by an update) that are still in the
    database or its WAL, as dicts -- see _row. With a WAL, the database is
    read as SQLite would read it (committed frames applied), and the older
    versions of its pages -- in the main file and in earlier frames -- are
    searched for rows that version no longer has."""
    from trace_app.core.activity.sqlite_bytes import apply_wal
    original = data
    if wal:
        data = apply_wal(data, wal)
    db = Database(data)
    seen = db.live_rows()
    out = []
    by_page = db.table_of_page()

    def keep(row):
        if row and len(out) < limit:
            out.append(row)

    # 1. Freelist pages: every cell still in them, whichever table's.
    for number in db.freelist():
        for row in _scan_cells(db, db.page(number), number, db.tables, seen,
                               'freelist page'):
            keep(row)
    # 2. Freeblocks and unused space in each table's live leaf pages.
    for number, table in by_page.items():
        page = db.page(number)
        for start, size in _freeblocks(page, number):
            row = _from_freeblock(db, table, page, number, start, size)
            if row is not None:
                key = _key(table, row['values'])
                if key not in seen:
                    seen.add(key)
                    keep(row)
            for row in _scan_cells(db, page, number, [table], seen,
                                   'freeblock', begin=start + 4,
                                   end=start + size):
                keep(row)
        for row in _from_unused(db, table, page, number, seen):
            keep(row)
    # 3. Older versions of pages: the main file's, where the WAL replaced
    #    them, and every frame of the WAL.
    if wal and original is not data:
        before = Database.__new__(Database)
        before.__dict__.update(db.__dict__)
        before.data = original
        for number in range(1, min(len(original) // db.page_size,
                                   db.pages) + 1):
            page = before.page(number)
            if number == 1 or page == db.page(number):
                continue                  # page 1 is the schema
            for row in _scan_cells(db, page, number, db.tables, seen,
                                   'database file, before its WAL',
                                   'an earlier version of the page'):
                keep(row)
    for frame, number, _commit, page in wal_frames(wal, db.page_size):
        if number == 1:
            continue
        for row in _scan_cells(db, page, number, db.tables, seen,
                               f'WAL frame {frame}',
                               'an earlier version of the page'):
            keep(row)
    return out

"""Chromium's IndexedDB, read from its LevelDB files (no Qt).

A site's (or an Electron app's) IndexedDB is one LevelDB database
(core/leveldb.py) under IndexedDB/<origin>.indexeddb.leveldb, whose keys
start with a prefix -- database, object store and index ids, each
little-endian in as many bytes as the first byte says (content/browser/
indexed_db/indexed_db_leveldb_coding.cc):

* database 0 is the metadata: a database's name -> its id (type 201: the
  origin, then the name, each a length and UTF-16BE), an object store's
  name (type 50: the store id, then 0) -> UTF-16BE;
* index 1 of a store is its records: the record's IndexedDB key (type
  byte, then a string, number, date, array or binary), and the value: a
  version varint, then the value as Blink and V8 serialised it
  (core/v8_values.py).

Every version LevelDB still holds is read, so overwritten and deleted
records come back with the current ones.
"""

import logging
import struct

from trace_app.core import leveldb, v8_values

logger = logging.getLogger('TRACE.IndexedDB')

_DATABASE_NAME = 201
_OBJECT_STORE_META = 50
_RECORDS_INDEX = 1


class IndexedDBError(ValueError):
    pass


def prefix(key):
    """(database id, object store id, index id, rest of the key)."""
    if not key:
        raise IndexedDBError("empty key")
    first = key[0]
    sizes = ((first >> 5) + 1, ((first >> 2) & 7) + 1, (first & 3) + 1)
    position, ids = 1, []
    for size in sizes:
        if position + size > len(key):
            raise IndexedDBError("key prefix runs past the key")
        ids.append(int.from_bytes(key[position:position + size], 'little'))
        position += size
    return ids[0], ids[1], ids[2], key[position:]


def _string_with_length(data, position):
    length, position = leveldb.varint(data, position)
    end = position + 2 * length
    return data[position:end].decode('utf-16-be', 'replace'), end


def decode_key(data, position=0):
    """(an IndexedDB key, position after): str, float, datetime, list or
    bytes."""
    kind = data[position]
    position += 1
    if kind == 0:
        return None, position
    if kind == 1:
        return _string_with_length(data, position)
    if kind in (2, 3):
        value = struct.unpack_from('<d', data, position)[0]
        position += 8
        if kind == 2:
            import datetime
            try:
                value = datetime.datetime(
                    1970, 1, 1, tzinfo=datetime.timezone.utc) + \
                    datetime.timedelta(milliseconds=value)
            except (OverflowError, ValueError):
                pass
        return value, position
    if kind == 4:
        count, position = leveldb.varint(data, position)
        items = []
        for _ in range(count):
            item, position = decode_key(data, position)
            items.append(item)
        return items, position
    if kind == 6:
        length, position = leveldb.varint(data, position)
        return bytes(data[position:position + length]), position + length
    raise IndexedDBError(f"unknown key type {kind}")


def metadata(records):
    """{database id: {'name', 'origin', 'stores': {store id: name}}}."""
    current = leveldb.live(records)
    databases = {}
    for key, value in current.items():
        try:
            database, store, index, rest = prefix(key)
        except IndexedDBError:
            continue
        if (database, store, index) == (0, 0, 0) and rest[:1] == \
                bytes([_DATABASE_NAME]):
            try:
                origin, position = _string_with_length(rest, 1)
                name, _position = _string_with_length(rest, position)
                identifier, _ = leveldb.varint(value, 0)
            except (leveldb.LevelDBError, IndexError):
                continue
            databases.setdefault(identifier, {'stores': {}}).update(
                name=name, origin=origin)
    for key, value in current.items():
        try:
            database, store, index, rest = prefix(key)
        except IndexedDBError:
            continue
        if database in databases and (store, index) == (0, 0) and \
                rest[:1] == bytes([_OBJECT_STORE_META]):
            try:
                identifier, position = leveldb.varint(rest, 1)
            except leveldb.LevelDBError:
                continue
            if rest[position:position + 1] == b'\x00':
                databases[database]['stores'][identifier] = value.decode(
                    'utf-16-be', 'replace')
    return databases


def object_records(records):
    """Every object-store record LevelDB holds: dicts of database, store
    (names), key, value (or 'error'), state ('current' / 'overwritten' /
    'deleted') and sequence."""
    names = metadata(records)
    by_key = {}
    for record in records:
        try:
            database, store, index, rest = prefix(record.key)
        except IndexedDBError:
            continue
        if database == 0 or index != _RECORDS_INDEX:
            continue
        by_key.setdefault(record.key, []).append(
            (record, database, store, rest))
    out = []
    for versions in by_key.values():
        versions.sort(key=lambda item: item[0].sequence)
        newest = versions[-1][0]
        for record, database, store, rest in versions:
            if record.deleted:
                continue
            info = names.get(database, {})
            item = {'database': info.get('name', f"database {database}"),
                    'origin': info.get('origin', ''),
                    'store': info.get('stores', {}).get(store,
                                                        f"store {store}"),
                    'sequence': record.sequence,
                    'state': 'current' if record is newest else
                    'deleted' if newest.deleted else 'overwritten'}
            try:
                item['key'], _ = decode_key(rest)
            except (IndexedDBError, IndexError, struct.error,
                    leveldb.LevelDBError) as exc:
                item['key'] = rest.hex()
                logger.debug("Undecoded key: %s", exc)
            try:
                _version, position = leveldb.varint(record.value, 0)
                item['value'] = v8_values.blink_value(
                    record.value[position:])
            except (v8_values.V8Error, leveldb.LevelDBError, IndexError,
                    struct.error, UnicodeDecodeError, RecursionError) as exc:
                item['value'] = None
                item['error'] = str(exc)
            out.append(item)
    return out

"""Chromium's storage: LevelDB (core/leveldb.py), Local and Session
Storage (activity/chromium_storage.py), IndexedDB (core/indexeddb.py) and
V8's serialised values (core/v8_values.py).

The databases are Chromium's own: tools/testdata/build/
make_chromium_storage.py runs a page in Playwright's pinned Chromium that
writes every kind of value, overwrites and deletes some, and reports what
it did (key.json). Linux CI builds them; these tests skip elsewhere. The
log framing is also checked against a writer here that follows LevelDB's
log format (blocks, fragments, masked CRC-32C)."""

import datetime
import json
import math
import os
import shutil
import struct

import pytest

from tests.conftest import image_path
from trace_app.core import indexeddb, leveldb, v8_values

STORAGE = 'chromium-storage'


def _folder(*parts):
    return os.path.join(image_path(STORAGE), *parts)


def _key():
    with open(_folder('key.json'), encoding='utf-8') as handle:
        return json.load(handle)


IDB = ('IndexedDB', 'http_127.0.0.1_8765.indexeddb.leveldb')


# --- LevelDB's log, from a writer of its own --------------------------------------

def _record(kind, body):
    crc = leveldb.masked_crc(bytes([kind]) + body)
    return struct.pack('<IHB', crc, len(body), kind) + body


def _batch(sequence, operations):
    out = struct.pack('<QI', sequence, len(operations))
    for key, value in operations:
        out += bytes([0 if value is None else 1])
        out += leveldb.write_varint(len(key)) + key
        if value is not None:
            out += leveldb.write_varint(len(value)) + value
    return out


def _log(batches, block=leveldb.BLOCK):
    """A log with each batch fragmented across blocks as LevelDB does."""
    out = bytearray()
    for batch in batches:
        position, first = 0, True
        while True:
            room = block - len(out) % block
            if room < 7:
                out += bytes(room)
                continue
            piece = batch[position:position + room - 7]
            position += len(piece)
            last = position >= len(batch)
            kind = (1 if last else 2) if first else (4 if last else 3)
            out += _record(kind, piece)
            first = False
            if last:
                break
    return bytes(out)


def test_log_batches_are_reassembled_across_blocks():
    big = os.urandom(70_000)                      # spans three blocks
    batches = [_batch(1, [(b'a', b'1'), (b'b', b'2')]),
               _batch(3, [(b'big', big)]), _batch(4, [(b'a', None)]),
               _batch(5, [(b'a', b'3')])]
    records = leveldb.records_from_files([('000003.log', _log(batches))])
    assert [(r.key, r.sequence, r.deleted) for r in records] == [
        (b'a', 1, False), (b'b', 2, False), (b'big', 3, False),
        (b'a', 4, True), (b'a', 5, False)]
    assert all(r.verified for r in records)
    assert leveldb.live(records) == {b'a': b'3', b'b': b'2', b'big': big}
    older = [(old.value, new.sequence) for old, new in
             leveldb.superseded(records)]
    assert older == [(b'1', 4)]


def test_a_damaged_record_is_kept_as_unverified():
    log = bytearray(_log([_batch(1, [(b'k', b'value')])]))
    log[10] ^= 0xFF                               # inside the batch
    records = leveldb.records_from_files([('000003.log', bytes(log))])
    assert records and not records[0].verified


# --- V8 values, by hand --------------------------------------------------------------

def test_v8_back_references_and_holes():
    # {a: obj, b: <the same obj>}: 'o' a 'o' x 1 '{' 1, b '^' 1 '{' 2
    data = bytes([0xFF, 0x0F]) + b'o"\x01ao"\x01xI\x02{\x01"\x01b^\x01{\x02'
    value = v8_values.loads(data)
    assert value == {'a': {'x': 1}, 'b': {'x': 1}}
    assert value['a'] is value['b']
    with pytest.raises(v8_values.V8Error):
        v8_values.loads(bytes([0xFF, 0x0F]) + b'\x99')


# --- Chromium's own databases --------------------------------------------------------

def test_local_storage_reads_as_the_page_left_it():
    from trace_app.core.activity import chromium_storage
    key = _key()
    items = chromium_storage.local_storage(
        leveldb.records(_folder('Local Storage', 'leveldb')))
    current = {i['key']: i['value'] for i in items if i['state'] == 'current'}
    assert current == key['local']
    deleted = [i for i in items if i['state'].startswith('deleted')]
    assert [i['key'] for i in deleted] == [k for k, _v in
                                           key['local_deleted']]


def test_session_storage_closed_with_its_tab_comes_back():
    from trace_app.core.activity import chromium_storage
    key = _key()
    items = chromium_storage.session_storage(
        leveldb.records(_folder('Session Storage')))
    assert {i['key']: i['value'] for i in items} == key['session']
    # The tab closed, so Chromium deleted them; LevelDB still has them.
    assert {i['state'] for i in items} == {'deleted (still in the database)'}


def _typed(value):
    """A decoded value in the page's report form (make_chromium_storage's
    typed())."""
    if value is v8_values.UNDEFINED:
        return {'t': 'undefined'}
    if value is None:
        return {'t': 'null'}
    if isinstance(value, bool):
        return {'t': 'boolean', 'v': value}
    if isinstance(value, int) and abs(value) > 2 ** 53:
        return {'t': 'bigint', 'v': str(value)}
    if isinstance(value, float) and math.isnan(value):
        return {'t': 'nan'}
    if isinstance(value, (int, float)):
        return {'t': 'number', 'v': value}
    if isinstance(value, str):
        return {'t': 'string', 'v': value}
    if isinstance(value, datetime.datetime):
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        return {'t': 'date', 'v': round((value - epoch).total_seconds()
                                        * 1000)}
    if isinstance(value, v8_values.RegExp):
        return {'t': 'regexp', 'v': value.pattern, 'f': value.flags}
    if isinstance(value, bytes):
        return {'t': 'arraybuffer', 'v': list(value)}
    if isinstance(value, v8_values.TypedArray):
        size = {'Uint8Array': 'B', 'Int32Array': 'i',
                'Float64Array': 'd'}[value.kind]
        raw = struct.pack(f'<{len(value.values)}{size}', *value.values)
        return {'t': value.kind, 'v': list(raw)}
    if isinstance(value, v8_values.SparseArray):
        return {'t': 'array', 'length': value.length,
                'v': {str(k): _typed(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {'t': 'array', 'length': len(value),
                'v': {str(i): _typed(v) for i, v in enumerate(value)}}
    if isinstance(value, dict):
        return {'t': 'object', 'v': {k: _typed(v) for k, v in value.items()}}
    raise AssertionError(f"unexpected {value!r}")


def _typed_collection(name, value):
    """Map and Set decode to lists of pairs / items; the report names
    them."""
    if name == 'map':
        return {'t': 'map', 'v': [[_typed(k), _typed(v)] for k, v in value]}
    if name == 'set':
        return {'t': 'set', 'v': [_typed(v) for v in value]}
    return _typed(value)


def test_every_value_v8_serialised_reads_back():
    key = _key()
    items = indexeddb.object_records(leveldb.records(_folder(*IDB)))
    values = {i['key']: i['value'] for i in items
              if i['store'] == 'values' and i['state'] == 'current'}
    assert set(values) == set(key['idb']['values'])
    for name, expected in key['idb']['values'].items():
        assert _typed_collection(name, values[name]) == expected, name
    shared = values['shared']
    assert shared['first'] is shared['second']     # one object, twice


def test_records_keys_and_deletions():
    key = _key()
    records = leveldb.records(_folder(*IDB))
    assert any(r.source.endswith('.ldb') for r in records)  # a table read
    assert all(r.verified for r in records)
    meta = indexeddb.metadata(records)
    database = next(iter(meta.values()))
    assert database['name'] == 'traceTest'
    assert set(database['stores'].values()) == {'values', 'messages', 'keys',
                                                'bulk'}
    items = indexeddb.object_records(records)
    messages = {i['key']: i for i in items if i['store'] == 'messages'}
    expected = {m['v']['id']['v']: m for m in key['idb']['messages']}
    assert set(messages) == set(expected)
    for number, item in messages.items():
        assert _typed(item['value']) == expected[number]
        state = 'deleted' if number in key['idb_deleted'] else 'current'
        assert item['state'] == state, number
    keys = [(_typed(i['key']), i['value']) for i in items
            if i['store'] == 'keys']
    want = [(k if k['t'] != 'Uint8Array' else
             {'t': 'arraybuffer', 'v': k['v']}, v)
            for k, v in key['idb']['keys']]
    # IndexedDB keeps number keys as doubles: compared as values (1.0 == 1).
    assert sorted(keys, key=lambda pair: pair[1]) == \
        sorted(want, key=lambda pair: pair[1])
    bulk = {int(i['key']): len(i['value']) for i in items
            if i['store'] == 'bulk'}
    assert bulk == {int(k): v for k, v in key['bulk'].items()}


def test_profiles_are_found_on_evidence(tmp_path):
    """A Windows home holding a Chrome profile and an Electron app's
    folder, opened as folder evidence and read by the activity module."""
    from trace_app.core.activity import run_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'collection'
    home = root / 'Users' / 'sam'
    chrome = home / 'AppData' / 'Local' / 'Google' / 'Chrome' / \
        'User Data' / 'Default'
    slack = home / 'AppData' / 'Roaming' / 'Slack'
    for target in (chrome, slack):
        for sub in ('Local Storage', 'Session Storage', 'IndexedDB'):
            shutil.copytree(_folder(sub), target / sub)
    (root / 'Windows' / 'System32').mkdir(parents=True)
    handler = ImageHandler(str(root))
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), 'Storage')
    try:
        evidence = case.add_evidence(str(root))
        run_evidence(handler, case, evidence)
        rows = case.user_activity(evidence, 'web')
        sources = {r['source'] for r in rows}
        assert {'Local Storage (Chrome)', 'Session Storage (Chrome)',
                'IndexedDB (Chrome)', 'Local Storage (Slack)',
                'IndexedDB (Slack)'} <= sources
        greeting = next(r for r in rows
                        if r['source'] == 'Local Storage (Slack)'
                        and r['subject'] == 'greeting')
        assert greeting['detail']['value'] == 'hello world'
        deleted = [r for r in rows if r['source'] == 'IndexedDB (Chrome)'
                   and 'deleted' in r['what']]
        assert len(deleted) == 2                 # messages 7 and 8
    finally:
        handler.close_resources()
        case.close()

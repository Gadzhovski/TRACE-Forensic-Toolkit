"""Deleted SQLite records (trace_app/core/sqlite_recover.py) and the
deleted messages and history they become (core/activity/recovered.py).

Databases are written and rows deleted by SQLite itself (secure_delete
off, its default), so what is left behind is what SQLite leaves: rows
deleted one at a time (freeblocks), a run of rows (pages emptied onto the
freelist, and pages rewritten with old cells left in their unused space),
and an update and a delete under WAL. Every deleted row still physically
in the file must come back, and nothing that was not a row. Then the real
Skype database from plaso's test data, with one message deleted by SQLite:
the message comes back in the Activity records, marked deleted.
"""

import os
import re
import shutil
import sqlite3

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
MESSAGE = re.compile(r'message number (\d+) about the plan')


def build(path, wal=False):
    db = sqlite3.connect(path)
    db.execute("PRAGMA secure_delete = OFF")
    if wal:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA wal_autocheckpoint = 0")
    db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, "
               "body TEXT, sent INTEGER)")
    db.execute("CREATE TABLE contacts (name TEXT, phone TEXT)")
    for i in range(400):
        db.execute("INSERT INTO messages (sender, body, sent) VALUES (?,?,?)",
                   (f'user{i % 7}', f'message number {i} about the plan',
                    1600000000 + i))
    db.executemany("INSERT INTO contacts VALUES (?,?)",
                   [(f'contact {i}', f'+4420795{i:04d}') for i in range(50)])
    db.commit()
    return db


def test_every_deleted_row_left_in_the_file_comes_back(tmp_path):
    from trace_app.core import sqlite_recover
    path = str(tmp_path / 'chat.db')
    db = build(path)
    db.execute("DELETE FROM messages WHERE id IN (5, 77, 150)")
    db.execute("DELETE FROM messages WHERE id BETWEEN 200 AND 330")
    db.execute("DELETE FROM contacts WHERE name = 'contact 7'")
    db.commit()
    db.close()
    with open(path, 'rb') as handle:
        data = handle.read()
    deleted = {4, 76, 149} | set(range(199, 330))   # message numbers
    present = {int(m.group(1)) for m in re.finditer(
        rb'message number (\d+) about the plan', data)} & deleted
    rows = sqlite_recover.recover(data)
    messages = [r for r in rows if r['table'] == 'messages']
    numbers = set()
    for row in messages:
        assert row['columns'] == ['id', 'sender', 'body', 'sent']
        match = MESSAGE.fullmatch(row['values'][2])
        assert match, row                     # nothing that was not a row
        numbers.add(int(match.group(1)))
        assert row['values'][3] == 1600000000 + int(match.group(1))
    assert numbers == present and len(present) >= 40
    # A row whose ids were whole keeps its id.
    assert any(r['values'][0] == int(MESSAGE.fullmatch(
        r['values'][2]).group(1)) + 1 for r in messages)
    # A two-column row whose first value's type the freeblock header
    # overwrote: its length is what the second leaves.
    (contact,) = [r for r in rows if r['table'] == 'contacts']
    assert contact['values'] == ['contact 7', '+44207950007']
    assert contact['source'] == 'freeblock' and contact['note']


def test_an_update_and_a_delete_under_wal(tmp_path):
    from trace_app.core import sqlite_recover
    path = str(tmp_path / 'wal.db')
    db = build(path, wal=True)
    db.execute("UPDATE messages SET body = 'changed' WHERE id = 10")
    db.execute("DELETE FROM messages WHERE id = 20")
    db.commit()
    with open(path, 'rb') as handle:
        data = handle.read()
    with open(path + '-wal', 'rb') as handle:
        wal = handle.read()
    rows = sqlite_recover.recover(data, wal)
    db.close()
    bodies = {r['values'][2] for r in rows if r['table'] == 'messages'}
    assert 'message number 9 about the plan' in bodies     # before update
    assert 'message number 19 about the plan' in bodies    # deleted
    assert 'changed' not in bodies                         # live: not here
    assert any(r['source'].startswith('WAL frame') for r in rows)


@pytest.mark.parametrize('name', ['skype_main.db', 'imessage_chat.db',
                                  'mmssms.db', 'places118.sqlite',
                                  'History.db', 'search-Windows.db'])
def test_real_databases_give_no_noise(name):
    from trace_app.core import sqlite_recover
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    with open(path, 'rb') as handle:
        rows = sqlite_recover.recover(handle.read())
    assert len(rows) <= 3                  # these were never deleted from
    for row in rows:
        assert row['table'] and any(
            isinstance(v, (str, bytes)) and len(v) >= 2
            for v in row['values'])


def test_a_deleted_skype_message_is_activity_again(tmp_path):
    from trace_app.core.activity import chat
    source = os.path.join(SAMPLES, 'skype_main.db')
    if not os.path.exists(source):
        pytest.skip("run tools/fetch_artifact_samples.py")
    path = str(tmp_path / 'main.db')
    shutil.copy(source, path)
    db = sqlite3.connect(path)
    db.execute("PRAGMA secure_delete = OFF")
    db.execute("DELETE FROM Messages WHERE body_xml = "
               "'need to know if you got it this time.'")
    db.commit()
    db.close()
    with open(path, 'rb') as handle:
        records = chat.read_database(handle.read(), None, 'gen', path, 'r')
    live = [r for r in records if r['what'] == 'Skype message']
    assert 'need to know if you got it this time.' not in \
        {r['subject'] for r in live}
    (gone,) = [r for r in records
               if r['what'] == 'Deleted Skype message (recovered)']
    assert gone['subject'] == 'need to know if you got it this time.'
    assert gone['time'] == '2013-07-30 21:27:11'
    assert gone['detail']['from'] == 'Gen Beringer'
    assert 'page' in gone['detail']['found in']

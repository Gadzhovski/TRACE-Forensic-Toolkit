"""Read-only database opens survive any folder name (infra/sqlite_uri.py).

An unquoted ``file:{path}?mode=ro`` URI ends at '#': a case named
"Case #12" made every background job fail ("no such table: case_info")
and SQLite created -- read-write -- an empty database at the cut path.
"""

import os
import sqlite3

import pytest

from trace_app.infra.sqlite_uri import connect_read_only, read_only_uri

#: Every character a URI treats specially that a folder name may hold.
AWKWARD = 'Case #12 50% [x] & y=1; Ünï'


@pytest.fixture
def case_folder(tmp_path):
    from trace_app.core.case import Case
    folder = tmp_path / AWKWARD
    case = Case.create(str(folder), AWKWARD)
    case.set_setting('settings', {'hash_md5': False})
    case.close()
    return str(folder)


def listing(folder):
    return sorted(os.listdir(folder))


def test_opens_the_named_file_read_only(tmp_path):
    folder = tmp_path / AWKWARD
    folder.mkdir()
    path = str(folder / 'x.db')
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE t (v)")
        db.execute("INSERT INTO t VALUES (7)")
    db.close()
    before = listing(tmp_path)
    connection = connect_read_only(path)
    try:
        assert connection.execute("SELECT v FROM t").fetchone() == (7,)
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            connection.execute("INSERT INTO t VALUES (8)")
    finally:
        connection.close()
    assert listing(tmp_path) == before        # no stray file at a cut path


def test_never_creates_a_missing_database(tmp_path):
    path = str(tmp_path / AWKWARD / 'missing.db')
    os.makedirs(os.path.dirname(path))
    with pytest.raises(sqlite3.OperationalError):
        connect_read_only(path)
    assert not os.path.exists(path)
    assert listing(tmp_path) == [AWKWARD]


def test_immutable_leaves_nothing_beside_a_wal_database(tmp_path):
    path = str(tmp_path / AWKWARD / 'wal.db')
    os.makedirs(os.path.dirname(path))
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE t (v)")
    db.commit()
    db.close()
    connection = connect_read_only(path, immutable=True)
    assert connection.execute("SELECT count(*) FROM t").fetchone() == (0,)
    connection.close()
    assert listing(os.path.dirname(path)) == ['wal.db']


def test_the_uri_quotes_everything_but_separators():
    uri = read_only_uri(os.path.join(os.sep, 'a #b', '50%', 'c?.db'))
    assert '#' not in uri and ' ' not in uri
    assert uri.count('?') == 1 and uri.endswith('?mode=ro')
    assert uri.startswith('file:/')


def test_a_job_reads_the_settings_of_a_case_named_with_a_hash(case_folder):
    from trace_app.core import background, settings
    stored = settings.StoredCase(case_folder)
    assert stored.setting('settings') == {'hash_md5': False}
    try:
        background._apply_settings({'case_folder': case_folder})
        assert listing(os.path.dirname(case_folder)) == [AWKWARD]
    finally:
        # The case's settings went into this process's module values (MD5
        # off): put the defaults back, or a later test in this worker
        # analyses without MD5 (test_analysis_pool's one-process run did).
        settings.apply_case(None)


def test_the_welcome_screen_reads_it(case_folder):
    from trace_app.core.case import read_case_summary
    assert read_case_summary(case_folder)['name'] == AWKWARD

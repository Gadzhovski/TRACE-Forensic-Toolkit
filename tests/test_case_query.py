"""CaseQuery: the panels' one read of case.db on a thread."""

import sqlite3

from tests.conftest import pump


def _wait(app, thread):
    results = []
    thread.loaded.connect(lambda *args: results.append(args))
    thread.start()
    assert thread.wait(10000)
    pump(app, until=lambda: results)
    return results


def test_a_read_answers_with_its_generation(qapp, tmp_path):
    from trace_app.core.case import CASE_DB_NAME
    from trace_app.ui.widgets.case_query import CaseQuery
    folder = tmp_path / 'Case #12 50% [x]'          # a URI-hostile name
    folder.mkdir()
    with sqlite3.connect(folder / CASE_DB_NAME) as connection:
        connection.execute("CREATE TABLE t (v)")
        connection.executemany("INSERT INTO t VALUES (?)", [(1,), (2,)])
    connection.close()

    query = CaseQuery(str(folder), 7,
                      lambda c: [v for (v,) in c.execute("SELECT v FROM t")],
                      [], 'numbers')
    assert _wait(qapp, query) == [(7, [1, 2])]
    # nothing written beside the case: the read was read-only
    assert sorted(p.name for p in tmp_path.iterdir()) == [folder.name]


def test_a_failed_read_answers_empty(qapp, tmp_path, caplog):
    from trace_app.ui.widgets.case_query import CaseQuery
    query = CaseQuery(str(tmp_path), 3, lambda c: c.execute(
        "SELECT * FROM missing").fetchall(), ([], {}), 'nothing')
    assert _wait(qapp, query) == [(3, ([], {}))]
    assert 'Could not read nothing' in caplog.text

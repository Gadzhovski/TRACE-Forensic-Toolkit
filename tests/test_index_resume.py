"""Indexing that stops part-way continues where it stopped (indexer.
index_evidence(resume=), index_free_space), and what a resumed run leaves
is what an uninterrupted one would: no file twice, none missing. The
answer here is a run that never stopped, over the same image."""

import sqlite3

import pytest

from tests.conftest import image_path

IMAGE = 'fat-img-kw.dd'          # DFTT #2: files, slack, free space


def _rows(index, evidence_id, kinds=None):
    rows = index._db.execute(
        "SELECT kind, artifact_ref, path, name, body FROM indexed_items "
        "WHERE evidence_id = ?", (evidence_id,)).fetchall()
    return sorted(tuple(r) for r in rows if kinds is None or r[0] in kinds)


def _folder(path):
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _handler():
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(IMAGE))
    assert handler.load_image()
    return handler


@pytest.fixture
def answer(tmp_path):
    """Every row of an uninterrupted run, files then free space."""
    from trace_app.core.indexer import index_evidence, index_free_space
    from trace_app.core.search_index import SearchIndex
    handler = _handler()
    index = SearchIndex(_folder(tmp_path / 'whole'))
    try:
        index_evidence(handler, index, 1)
        index_free_space(handler, index, 1)
        rows = _rows(index, 1)
    finally:
        index.close()
        handler.close_resources()
    assert any(r[0] == 'file' for r in rows)
    assert any(r[0] == 'unallocated' for r in rows)
    return rows


def _stopping(after):
    """progress/should_stop that stop the run once `after` files are
    counted."""
    seen = [0]

    def progress(done, total, path):
        seen[0] = done

    return progress, (lambda: seen[0] >= after)


def test_a_cancelled_index_resumes_without_doubling_or_losing_files(
        tmp_path, answer):
    from trace_app.core.indexer import index_evidence, index_free_space
    from trace_app.core.search_index import INDEX_CANCELLED, SearchIndex
    handler = _handler()
    index = SearchIndex(_folder(tmp_path / 'resumed'))
    try:
        progress, stop = _stopping(3)
        index_evidence(handler, index, 1, progress=progress,
                       should_stop=stop)
        state = index.state(1)
        assert state['status'] == INDEX_CANCELLED
        partial = [r for r in _rows(index, 1) if r[0] == 'file']
        assert 0 < len(partial) < len(
            [r for r in answer if r[0] == 'file'])
        index_evidence(handler, index, 1, resume=True)
        assert index.is_indexed(1)
        index_free_space(handler, index, 1)
        assert _rows(index, 1) == answer
    finally:
        index.close()
        handler.close_resources()


def test_a_failed_run_resumes_too_and_a_new_scope_starts_over(
        tmp_path, answer, monkeypatch):
    from trace_app.core import indexer
    from trace_app.core import scope as scope_module
    from trace_app.core.search_index import INDEX_FAILED, SearchIndex
    handler = _handler()
    index = SearchIndex(_folder(tmp_path / 'failed'))
    real = indexer._index_file
    calls = [0]

    def failing(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 4:
            raise RuntimeError("the disk went away")
        return real(*args, **kwargs)

    try:
        monkeypatch.setattr(indexer, '_index_file', failing)
        with pytest.raises(RuntimeError):
            indexer.index_evidence(handler, index, 1)
        assert index.state(1)['status'] == INDEX_FAILED
        monkeypatch.setattr(indexer, '_index_file', real)
        indexer.index_evidence(handler, index, 1, resume=True)
        indexer.index_free_space(handler, index, 1)
        assert _rows(index, 1) == answer

        # A run stopped under one scope does not resume under another:
        # it would mix two selections.
        progress, stop = _stopping(2)
        indexer.index_evidence(handler, index, 1, progress=progress,
                               should_stop=stop)
        only = scope_module.Scope.from_dict({'exclude_names': ['file1.dat']})
        indexer.index_evidence(handler, index, 1, scope=only, resume=True)
        names = {r[3] for r in _rows(index, 1) if r[0] == 'file'}
        assert 'file1.dat' not in names
        assert names == {r[3] for r in answer if r[0] == 'file'} - {
            'file1.dat'}
    finally:
        index.close()
        handler.close_resources()


def test_free_space_stopped_part_way_resumes_from_its_checkpoint(
        tmp_path, answer, monkeypatch):
    from trace_app.core import indexer
    from trace_app.core.search_index import (FREE_KINDS, INDEX_CANCELLED,
                                             INDEX_DONE, SearchIndex)
    # Pieces and checkpoints small enough that this small image has many.
    monkeypatch.setattr(indexer, 'UNALLOCATED_PIECE', 4096)
    monkeypatch.setattr(indexer, 'FREE_CHECKPOINT', 16384)
    handler = _handler()
    whole = SearchIndex(_folder(tmp_path / 'whole-free'))
    index = SearchIndex(_folder(tmp_path / 'free'))
    try:
        indexer.index_evidence(handler, whole, 1)
        indexer.index_free_space(handler, whole, 1)
        expected = _rows(whole, 1, FREE_KINDS)
        assert expected

        indexer.index_evidence(handler, index, 1)
        read = [0]

        def progress(done, total, what):
            read[0] = done

        indexer.index_free_space(handler, index, 1, progress=progress,
                                 should_stop=lambda: read[0] >= 40000)
        state = index.state(1)
        assert state['free_status'] == INDEX_CANCELLED
        assert 0 < state['free_done'] < state['free_total']
        assert index.free_unfinished(1)
        indexer.index_free_space(handler, index, 1)
        assert index.state(1)['free_status'] == INDEX_DONE
        assert _rows(index, 1, FREE_KINDS) == expected
        # The file index was not touched by any of it.
        assert index.is_indexed(1)
    finally:
        whole.close()
        index.close()
        handler.close_resources()


def test_a_version_4_index_is_upgraded_not_discarded(tmp_path):
    """Hours of indexing are kept: version 4 gains the new columns."""
    from trace_app.core.search_index import INDEX_VERSION, SearchIndex
    folder = tmp_path / 'old'
    folder.mkdir()
    db = sqlite3.connect(str(folder / 'search.db'))
    db.executescript("""
        CREATE TABLE indexed_items (id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER, artifact_ref TEXT, kind TEXT NOT NULL,
            name TEXT, path TEXT, size INTEGER, inode INTEGER,
            start_offset INTEGER, created_utc TEXT, accessed_utc TEXT,
            mtime_utc TEXT, changed_utc TEXT, is_deleted INTEGER DEFAULT 0,
            mime TEXT, indexed_utc TEXT, body TEXT);
        CREATE VIRTUAL TABLE search_fts USING fts5(name, path, body,
            content='indexed_items', content_rowid='id');
        CREATE TABLE entities (item_id INTEGER NOT NULL,
            evidence_id INTEGER, kind TEXT NOT NULL, value TEXT NOT NULL);
        CREATE TABLE index_state (evidence_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL, files_done INTEGER DEFAULT 0,
            files_total INTEGER DEFAULT 0, last_path TEXT, last_error TEXT,
            updated_utc TEXT);
        INSERT INTO indexed_items (evidence_id, artifact_ref, kind, name,
            path, body) VALUES (1, 'p0:i5:s1', 'file', 'a.txt', '/a.txt',
            'kept');
        INSERT INTO index_state (evidence_id, status, files_done)
            VALUES (1, 'running', 1);
        PRAGMA user_version = 4;
    """)
    db.commit()
    db.close()
    index = SearchIndex(str(folder))
    try:
        assert index._db.execute("PRAGMA user_version").fetchone()[0] == \
            INDEX_VERSION
        assert _rows(index, 1) == [('file', 'p0:i5:s1', '/a.txt', 'a.txt',
                                    'kept')]
        state = index.state(1)
        assert state['status'] == 'running' and 'free_status' in state
        index.set_free_state(1, 'running', 10, 100)
        assert index.free_unfinished(1)
    finally:
        index.close()

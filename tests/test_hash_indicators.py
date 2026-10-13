"""Hashes found in the evidence's text (search_index's 'hash' indicators)
and what the case holds with them (trace_app/core/hash_indicators.py).

The case's digests are those the analysis computes for ntfs1-gen2.E01's
files; the text naming them is written here, as a log on another image
would. The hash set is a plain list imported into a sandboxed library.
"""

import sqlite3

import pytest

from tests.conftest import image_path, pump


def test_hashes_are_stored_in_lower_case_and_non_digests_dropped():
    from trace_app.core.search_index import entities_of
    upper = 'D41D8CD98F00B204E9800998ECF8427E'
    text = (f"{upper} and {upper.lower()} again; "
            f"{'1' * 32} is a number, {'0' * 40} padding, {'f' * 64} filler, "
            f"{'a1' * 20} a SHA-1")
    hashes = {v for k, v in entities_of(text) if k == 'hash'}
    assert hashes == {upper.lower(), 'a1' * 20}


def test_a_version_5_index_is_migrated_not_rebuilt(tmp_path):
    """Hours of indexing are kept: stored hashes merge into lower case,
    numbers and fillers go, nothing else is touched."""
    from trace_app.core.search_index import INDEX_VERSION, SearchIndex
    index = SearchIndex(str(tmp_path))
    item = index.add_item(1, 'p0:i5:s1', 'file', 'a.txt', '/a.txt',
                          body='kept text')
    index.commit()
    index.close()
    db = sqlite3.connect(str(tmp_path / 'search.db'))
    db.execute("DELETE FROM entities")
    db.executemany(
        "INSERT INTO entities (item_id, evidence_id, kind, value) "
        "VALUES (?, 1, ?, ?)",
        [(item, 'hash', 'ABCDEF' + '0' * 26), (item, 'hash', 'abcdef' +
                                                  '0' * 26),
         (item, 'hash', '9' * 64), (item, 'hash', 'e' * 40),
         (item, 'email', 'Someone@Example.com')])
    db.execute("PRAGMA user_version = 5")
    db.commit()
    db.close()
    index = SearchIndex(str(tmp_path))
    try:
        assert index._db.execute("PRAGMA user_version").fetchone()[0] == \
            INDEX_VERSION
        rows = sorted(tuple(r) for r in index._db.execute(
            "SELECT kind, value FROM entities"))
        assert rows == [('email', 'Someone@Example.com'),
                        ('hash', 'abcdef' + '0' * 26)]
        assert index.statistics()['items'] == 1
    finally:
        index.close()


@pytest.fixture(scope='module')
def case_with_hashes(tmp_path_factory):
    """(case, evidence id, hashed files, library) for ntfs1-gen2.E01, with
    a known-bad set holding one file's MD5 and one digest of no file."""
    from trace_app.core import hashsets
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path_factory.mktemp('hash_indicators')
    case = Case.create(str(root / 'case'), 'Hash indicators')
    path = image_path('ntfs1-gen2.E01')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    analyse_evidence(handler, case, evidence_id, ['hash'])
    # Verified, so the case records the image's own hashes.
    case.apply_verification(evidence_id, handler.calculate_hashes())
    handler.close_resources()
    files = [f for f in case.hashed_files(evidence_id, False) if f['md5']]
    assert len(files) > 10
    library = hashsets.Library(str(root / 'library'))
    source = root / 'bad.txt'
    source.write_text(f"{files[1]['md5']}\n{'b7' * 16}\n")
    library.import_list(str(source), 'Contraband', hashsets.KNOWN_BAD)
    yield case, evidence_id, files, library
    case.close()



@pytest.mark.images
def test_each_hash_is_matched_against_the_case(case_with_hashes):
    from trace_app.core import hash_indicators as hi
    case, evidence_id, files, library = case_with_hashes
    first, second = files[0], files[1]
    gone = 'c3' * 32                       # a SHA-256 no file has
    in_set_only = 'b7' * 16                # an MD5 only the set has
    values = [first['md5'].upper(), second['md5'], first['sha256'], gone,
              in_set_only, 'd4' * 20]
    found = hi.match(case.folder, values, None, library)

    whole = found[first['md5']]            # the value is looked up lower
    assert whole['status'] == hi.IN_CASE and whole['algorithm'] == 'md5'
    names = {(f['origin'], f['artifact_ref'], f['evidence_id'])
             for f in whole['files']}
    assert ('file', first['artifact_ref'], evidence_id) in names
    assert whole['text'].startswith('File in case: ')
    assert found[first['sha256']]['status'] == hi.IN_CASE

    # In the case and in the set: both said.
    both = found[second['md5']]
    assert both['status'] == hi.IN_CASE
    assert both['sets'] == [('Contraband', 'known-bad')]
    assert 'Known bad: Contraband' in both['text']

    assert found[in_set_only]['status'] == hi.IN_SET
    assert found[in_set_only]['text'] == 'Known bad: Contraband'
    assert found[gone]['status'] == hi.NOT_FOUND
    assert 'not in the case' in hi.explain(found[gone])

    # SHA-1: "not found" only when files were hashed with it.
    sha1_hashed = any(f.get('sha1') for f in files)
    assert found['d4' * 20]['status'] == (
        hi.NOT_FOUND if sha1_hashed else hi.NOT_CHECKED)


@pytest.mark.images
def test_an_evidence_image_hash_in_the_text_is_the_image(case_with_hashes):
    from trace_app.core import hash_indicators as hi
    case, evidence_id, _files, library = case_with_hashes
    row = next(r for r in case.evidence() if r['id'] == evidence_id)
    digest = row['md5']
    assert digest
    result = hi.match(case.folder, [digest], None, library)[digest.lower()]
    assert result['status'] == hi.IN_CASE
    assert result['files'][0]['origin'] == 'evidence'
    assert result['text'].startswith('Evidence image: ')


@pytest.mark.images
def test_sets_follow_the_case_options(case_with_hashes):
    from trace_app.core import hash_indicators as hi
    case, _evidence_id, _files, library = case_with_hashes
    off = hi.match(case.folder, ['b7' * 16], {'enabled': False}, library)
    assert off['b7' * 16]['sets'] == []
    assert off['b7' * 16]['status'] == hi.NOT_FOUND


def test_nothing_hashed_is_not_checked_rather_than_not_found(tmp_path):
    from trace_app.core import hashsets, hash_indicators as hi
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Empty')
    try:
        result = hi.match(case.folder, ['a0' * 16], None,
                          hashsets.Library(str(tmp_path / 'lib')))
        assert result['a0' * 16]['status'] == hi.NOT_CHECKED
        assert 'MD5' in result['a0' * 16]['text']
    finally:
        case.close()


@pytest.mark.images
def test_the_indicators_tab_shows_matches_and_goes_to_the_file(
        qapp, case_with_hashes, monkeypatch):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMenu
    from trace_app.core import hash_indicators as hi
    from trace_app.core.search_index import SearchIndex
    from trace_app.ui.viewers import indicators_panel
    case, evidence_id, files, library = case_with_hashes
    monkeypatch.setattr(hi.hashsets, 'Library', lambda *a: library)
    first = files[0]
    gone = 'c3' * 32
    index = SearchIndex(case.folder)
    try:
        index.add_item(evidence_id, 'p0:i9999:s1', 'file', 'install.log',
                       '/install.log',
                       body=f"copied {first['md5'].upper()} then {gone}")
        index.commit()
    finally:
        index.close()

    panel = indicators_panel.IndicatorsPanel()
    try:
        panel.set_case(case)
        assert pump(qapp, 30, lambda: not panel.loading)
        panel.set_kind('hash')
        assert pump(qapp, 30, lambda: not panel.loading)
        table = panel.values_table
        shown = {table.item(r, indicators_panel.VALUE).text():
                 table.item(r, indicators_panel.MATCHES)
                 for r in range(table.rowCount())}
        assert set(shown) == {first['md5'], gone}
        assert shown[first['md5']].text().startswith('File in case: ')
        assert shown[first['md5']].font().bold()
        assert shown[gone].text() == 'No file in the case has it'
        assert 'another device' in shown[gone].toolTip()

        # Right-click ▸ Go to File with This Hash: the analysed file.
        position = next(r for r in range(table.rowCount())
                        if table.item(r, 0).text() == first['md5'])
        went = []
        panel.file_activated.connect(went.append)

        def choose(menu, _pos):
            # findChildren, never QAction.menu() (CLAUDE.md: the wrapper
            # can delete the menu).
            sub = next(m for m in menu.findChildren(QMenu)
                       if m.title() == 'Go to File with This Hash')
            return sub.actions()[0]
        monkeypatch.setattr(indicators_panel, 'show_menu', choose)
        panel._values_menu(table.visualItemRect(
            table.item(position, 0)).center())
        assert went and went[0]['artifact_ref'] == first['artifact_ref']
        assert went[0]['evidence_id'] == evidence_id
        assert table.item(position, 0).data(Qt.UserRole)['match']
    finally:
        panel.shutdown()
        panel.deleteLater()

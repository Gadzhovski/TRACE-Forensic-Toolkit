"""File > Remove Evidence: an image taken out of a case takes everything
recorded against it -- analysis, findings, carves (rows and files),
search index entries, bookmarks -- while its notes are kept and the audit
trail says what went. The other evidence is untouched, the image file is
never touched, and reopening the case does not bring it back."""

import os

import pytest

from tests.conftest import image_path, pump

pytestmark = [pytest.mark.ui, pytest.mark.images]

KEEP, REMOVE = '8-jpeg-search.dd', '11-carve-fat.dd'


@pytest.fixture
def answered(monkeypatch):
    """Modal dialogs answered: every question yes, messages recorded."""
    from trace_app.ui.dialogs import message
    told = []
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name,
                            lambda *a, **k: told.append(a[1:]))
    asked = []

    def question(parent, title, text, informative=None, **_):
        asked.append((text, informative))
        return True
    monkeypatch.setattr(message, 'question', question)
    return told, asked


@pytest.fixture
def case_folder(tmp_path):
    """A case with two images, the second analysed, carved, indexed,
    bookmarked and noted."""
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    folder = str(tmp_path / 'Two images')
    case = Case.create(folder, 'Two images')
    ids = {}
    for name in (KEEP, REMOVE):
        path = image_path(name)
        ids[name] = case.add_evidence(path)
        handler = ImageHandler(path)
        analyse_evidence(handler, case, ids[name], MODULES)
        index = SearchIndex(folder)
        index_evidence(handler, index, ids[name])
        index.commit()
        index.close()
        if name == REMOVE:
            # Its files are all in unallocated space: carved, then indexed
            # as the carve job does.
            from trace_app.core import settings
            from trace_app.core.indexer import index_carved
            # With copies written, so removing the evidence has a carved
            # folder to take away too.
            settings.save_case(case, {'carve_write_copies': True})
            carve_evidence(handler, case, ids[name], CARVABLE_TYPES)
            settings.apply_case(None)
            index = SearchIndex(folder)
            index_carved(handler.read, case, index, ids[name])
            index.commit()
            index.close()
        handler.close_resources()
    ref = case.carved_files(ids[REMOVE])[0]['artifact_ref']
    case.add_bookmark(ids[REMOVE], ref, 'Look at this')
    case.add_note('Seen on the second image', evidence_id=ids[REMOVE],
                  artifact_ref=ref)
    case.add_note('About the first image', evidence_id=ids[KEEP])
    case.close()
    return folder, ids


def _roots(window):
    from PySide6.QtCore import Qt
    tree = window.tree_viewer
    return [os.path.basename((tree.topLevelItem(i).data(0, Qt.UserRole)
                              or {}).get('image_path', ''))
            for i in range(tree.topLevelItemCount())
            if (tree.topLevelItem(i).data(0, Qt.UserRole) or {})
            .get('image_path')]


def _counts(folder, evidence_id):
    import sqlite3
    db = sqlite3.connect(os.path.join(folder, 'case.db'))
    try:
        tables = [t for (t,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        out = {}
        for table in tables:
            columns = [c[1] for c in db.execute(f"PRAGMA table_info({table})")]
            if 'evidence_id' in columns:
                out[table] = db.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE evidence_id = ?",
                    (evidence_id,)).fetchone()[0]
        return out
    finally:
        db.close()


def _indexed(folder, evidence_id):
    import sqlite3
    db = sqlite3.connect(os.path.join(folder, 'search.db'))
    try:
        return db.execute("SELECT COUNT(*) FROM indexed_items WHERE "
                          "evidence_id = ?", (evidence_id,)).fetchone()[0]
    finally:
        db.close()


def test_removing_evidence_takes_its_data_and_keeps_its_notes(
        qapp, case_folder, answered, monkeypatch):
    from PySide6.QtWidgets import QInputDialog, QProgressDialog
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    folder, ids = case_folder
    told, asked = answered
    case = Case.open(folder)
    carved = case._carved_folder_path(ids[REMOVE])
    assert os.path.isdir(carved) and os.listdir(carved)
    before_keep = _counts(folder, ids[KEEP])
    assert sum(_counts(folder, ids[REMOVE]).values())
    assert _indexed(folder, ids[REMOVE])

    window = MainWindow(case=case)
    try:
        pump(qapp, 60, lambda: len(window.evidence_files) == 2)
        assert sorted(_roots(window)) == sorted([KEEP, REMOVE])
        removing = os.path.normpath(image_path(REMOVE))
        monkeypatch.setattr(QInputDialog, 'getItem', staticmethod(
            lambda *a, **k: (next(o for o in a[3] if REMOVE in o), True)))

        assert window.remove_image_evidence()
        pump(qapp, 0.3)

        # Asked first, saying what goes and that the image is untouched.
        text, details = asked[-1]
        assert REMOVE in text and 'from the case' in text
        assert 'carved files' in details and 'not touched' in details
        assert 'note(s) kept' in details
        # Gone from the window...
        assert _roots(window) == [KEEP]
        assert removing not in window.evidence_files
        assert removing not in window._image_handlers
        assert window.current_image_path == os.path.normpath(
            image_path(KEEP))
        # ...and no loading dialog left behind to surface later.
        assert not [d for d in window.findChildren(QProgressDialog)
                    if d.isVisible()]
    finally:
        window.cleanup_resources()

    # Gone from the case, the index and the disk; the other image intact.
    case = Case.open(folder)
    try:
        assert [r['path'] for r in case.evidence()] == [
            os.path.normpath(os.path.abspath(image_path(KEEP)))]
        assert not any(_counts(folder, ids[REMOVE]).values())
        assert _counts(folder, ids[KEEP]) == before_keep
        assert _indexed(folder, ids[REMOVE]) == 0
        assert _indexed(folder, ids[KEEP])
        assert not os.path.exists(carved)
        assert os.path.exists(image_path(REMOVE))       # never touched
        notes = {n['body']: n for n in case.notes()}
        assert notes['About the first image']['evidence_id'] == ids[KEEP]
        kept = notes['Seen on the second image']
        assert kept['evidence_id'] is None
        assert REMOVE in kept['artifact_path']
        audit = [a for a in case.activity() if a['action'] ==
                 'evidence removed']
        assert len(audit) == 1 and REMOVE in audit[0]['detail']
        assert 'carved files' in audit[0]['detail']
        assert '1 note(s) kept' in audit[0]['detail']
    finally:
        case.close()

    # Reopened, the case does not bring it back.
    window = MainWindow(case=Case.open(folder))
    try:
        pump(qapp, 30, lambda: len(window.evidence_files) == 1)
        pump(qapp, 0.3)
        assert _roots(window) == [KEEP]
    finally:
        window.cleanup_resources()


def test_removal_waits_for_background_work(qapp, case_folder, answered):
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    folder, _ids = case_folder
    told, asked = answered
    window = MainWindow(case=Case.open(folder))
    try:
        pump(qapp, 60, lambda: len(window.evidence_files) == 2)
        window.job_bar._current = object()          # something is running
        try:
            assert not window.remove_image_evidence()
        finally:
            window.job_bar._current = None
        assert not asked
        assert 'Background work is running' in told[-1][-1]
        assert len(window.evidence_files) == 2
    finally:
        window.cleanup_resources()


def test_quick_triage_only_closes(qapp, answered):
    from trace_app.ui.main_window import MainWindow
    told, asked = answered
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path(KEEP))
        assert window.remove_image_evidence()
        assert 'Close' in asked[-1][0]
        assert 'Nothing on disk is changed' in asked[-1][1]
        assert window.evidence_files == [] and _roots(window) == []
        assert os.path.exists(image_path(KEEP))
    finally:
        window.cleanup_resources()

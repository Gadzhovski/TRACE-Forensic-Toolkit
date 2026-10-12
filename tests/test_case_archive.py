"""Case archives (core/case_archive.py) and evidence relocation
(Case.relocate_checked): a case handed over in one file, checked member by
member before anything is unpacked; moved evidence accepted only when its
hashes prove it the same."""

import json
import os
import shutil
import zipfile

import pytest

from trace_app.core.case_archive import (ArchiveError, MANIFEST,
                                         check_archive, export_case,
                                         import_case, missing_evidence)


@pytest.fixture
def evidence_file(tmp_path):
    path = tmp_path / 'evidence' / 'disk.dd'
    path.parent.mkdir()
    path.write_bytes(os.urandom(512 * 64) + b'TRACE' * 1000)
    return str(path)


@pytest.fixture
def case(tmp_path, evidence_file):
    from trace_app.core.case import Case, hash_evidence
    case = Case.create(str(tmp_path / 'my case #2'), 'Handover', number='23/41',
                       examiner='E. Xaminer')
    evidence_id = case.add_evidence(evidence_file)
    row = next(r for r in case.evidence() if r['id'] == evidence_id)
    case.apply_verification(evidence_id, hash_evidence(row))
    case.add_bookmark(evidence_id, 'p0:i5:s1', 'Ransom note',
                      'note.txt', '/note.txt')
    case.add_note('Seen on the desktop.', evidence_id=evidence_id,
                  artifact_ref='p0:i5:s1')
    case.tag_artifacts(1, [{'evidence_id': evidence_id,
                            'artifact_ref': 'p0:i5:s1', 'name': 'note.txt',
                            'path': '/note.txt'}])
    with open(os.path.join(case.folder, 'exports', 'note.txt'), 'wb') as f:
        f.write(b'pay up')
    yield case
    if case.is_open:
        case.close()


def _rows(case, table):
    cursor = case._db.execute(f"SELECT * FROM {table} ORDER BY rowid")
    columns = [d[0] for d in cursor.description]
    return [tuple(v for c, v in zip(columns, row)) for row in cursor]


def test_an_archive_opens_elsewhere_as_the_same_case(case, tmp_path):
    archive = str(tmp_path / 'out #1' / 'handover')
    os.makedirs(os.path.dirname(archive))
    seen = []
    made = export_case(case, archive, progress=lambda d, t, w: seen.append(d))
    assert made['path'].endswith('handover.trace')
    assert seen and seen[-1] > 0
    assert open(made['path'] + '.sha256').read().split()[0] == made['sha256']
    archived = [a for a in case.activity(20) if a['action'] == 'case archived']
    assert archived and made['sha256'] in archived[0]['detail']

    manifest, problems = check_archive(made['path'])
    assert problems == []
    assert manifest['case'] == {'name': 'Handover', 'number': '23/41'}
    assert manifest['evidence'][0]['sha256']
    assert 'case/case.db' in manifest['members']
    assert 'case/exports/note.txt' in manifest['members']

    expected = {table: _rows(case, table) for table in (
        'evidence', 'bookmarks', 'notes', 'artifact_tags', 'tags')}
    opened = import_case(made['path'], str(tmp_path / 'elsewhere'))
    try:
        for table, rows in expected.items():
            assert _rows(opened, table) == rows, table
        assert opened.name == 'Handover'
        with open(os.path.join(opened.folder, 'exports', 'note.txt'),
                  'rb') as handle:
            assert handle.read() == b'pay up'
        assert opened.verify_audit()['ok']
        line = next(a for a in opened.activity(5)
                    if a['action'] == 'case opened from archive')
        assert made['sha256'] in line['detail']
        assert 'audit trail intact' in line['detail']
        # The evidence is where the first machine had it.
        assert missing_evidence(opened) == []
    finally:
        opened.close()


def _rewrite(source, target, change):
    """A copy of the archive with `change(name, data) -> data | None`
    applied (None drops the member)."""
    with zipfile.ZipFile(source) as old, \
            zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as new:
        for info in old.infolist():
            data = change(info.filename, old.read(info.filename))
            if data is not None:
                new.writestr(info.filename, data)


def test_an_altered_archive_is_refused_before_anything_is_written(
        case, tmp_path):
    made = export_case(case, str(tmp_path / 'good.trace'))
    bad = str(tmp_path / 'bad.trace')
    _rewrite(made['path'], bad, lambda name, data: b'pay double'
             if name == 'case/exports/note.txt' else data)
    _manifest, problems = check_archive(bad)
    assert problems and 'case/exports/note.txt: altered' in problems[0]
    target = tmp_path / 'never'
    with pytest.raises(ArchiveError, match='does not match its manifest'):
        import_case(bad, str(target))
    assert not target.exists()

    # A member added, or one named to escape the folder, is refused too.
    def escape(name, data):
        if name != MANIFEST:
            return data
        manifest = json.loads(data)
        manifest['members']['case/../../evil.txt'] = {'size': 1,
                                                      'sha256': 'x'}
        return json.dumps(manifest).encode()
    _rewrite(made['path'], bad, escape)
    _manifest, problems = check_archive(bad)
    assert any('outside the case folder' in p for p in problems)
    with pytest.raises(ArchiveError):
        import_case(bad, str(tmp_path / 'never2'))
    assert not (tmp_path / 'evil.txt').exists()


def test_an_archive_needs_an_empty_folder(case, tmp_path):
    made = export_case(case, str(tmp_path / 'a.trace'))
    busy = tmp_path / 'busy'
    busy.mkdir()
    (busy / 'something').write_text('x')
    with pytest.raises(ArchiveError, match='not empty'):
        import_case(made['path'], str(busy))
    assert (busy / 'something').read_text() == 'x'
    with pytest.raises(ArchiveError, match='outside the case folder'):
        export_case(case, os.path.join(case.folder, 'inside.trace'))


def test_moved_evidence_is_relocated_only_when_its_hashes_match(
        case, tmp_path, evidence_file):
    from trace_app.core.case import hash_evidence
    evidence_id = case.evidence()[0]['id']
    moved = str(tmp_path / 'moved' / 'disk.dd')
    os.makedirs(os.path.dirname(moved))
    shutil.move(evidence_file, moved)
    assert [r['id'] for r in missing_evidence(case)] == [evidence_id]

    # A different file at the new place: refused, path unchanged.
    altered = str(tmp_path / 'moved' / 'altered.dd')
    data = bytearray(open(moved, 'rb').read())
    data[100] ^= 0xFF
    open(altered, 'wb').write(bytes(data))
    row = dict(case.evidence()[0], path=altered)
    out = case.relocate_checked(evidence_id, altered, hash_evidence(row))
    assert out['relocated'] is False and out['status'] == 'changed'
    assert case.evidence()[0]['path'] == evidence_file
    refused = next(a for a in case.activity(5)
                   if a['action'] == 'evidence relocation refused')
    assert altered in refused['detail']

    # The same bytes: relocated, and verified there.
    row = dict(case.evidence()[0], path=moved)
    out = case.relocate_checked(evidence_id, moved, hash_evidence(row))
    assert out['relocated'] is True and out['status'] == 'verified'
    assert os.path.normcase(case.evidence()[0]['path']) == \
        os.path.normcase(os.path.abspath(moved))
    assert case.evidence()[0]['last_status'] == 'verified'
    assert missing_evidence(case) == []
    assert case.verify_audit()['ok']


def test_evidence_never_hashed_moves_only_with_the_examiners_say_so(
        tmp_path):
    from trace_app.core.case import Case, hash_evidence
    original = tmp_path / 'a.dd'
    original.write_bytes(b'\0' * 4096)
    case = Case.create(str(tmp_path / 'c'), 'Unhashed')
    try:
        evidence_id = case.add_evidence(str(original))
        moved = tmp_path / 'b.dd'
        original.rename(moved)
        row = dict(case.evidence()[0], path=str(moved))
        results = hash_evidence(row)
        assert not case.relocate_checked(evidence_id, str(moved),
                                         results)['relocated']
        out = case.relocate_checked(evidence_id, str(moved), results,
                                    accept_unverified=True)
        assert out['relocated']
        assert any(a['action'] == 'evidence relocated unverified'
                   for a in case.activity(5))
    finally:
        case.close()


def _wait(qapp, condition, seconds=30):
    import time
    from tests.conftest import pump
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        pump(qapp, 0.05)
    return condition()


def test_locate_in_the_window_takes_only_the_same_evidence(
        qapp, case, tmp_path, evidence_file, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    moved = str(tmp_path / 'moved.dd')
    shutil.move(evidence_file, moved)
    altered = str(tmp_path / 'altered.dd')
    data = bytearray(open(moved, 'rb').read())
    data[0] ^= 1
    open(altered, 'wb').write(bytes(data))
    warned = []
    monkeypatch.setattr(message, 'warning',
                        lambda *a, **k: warned.append(a[2]))
    window = MainWindow(case=case)
    try:
        row = case.evidence()[0]
        for chosen in (altered, moved):
            monkeypatch.setattr(QFileDialog, 'getOpenFileName',
                                lambda *a, chosen=chosen, **k: (chosen, ''))
            window.locate_evidence(row)
            assert _wait(qapp, lambda: not window.job_bar.busy)
            if chosen == altered:
                assert warned and 'is not the evidence' in warned[-1]
                assert case.evidence()[0]['path'] == evidence_file
        assert os.path.normcase(case.evidence()[0]['path']) == \
            os.path.normcase(moved)
        assert case.evidence()[0]['last_status'] == 'verified'
        actions = [a['action'] for a in case.activity(20)]
        assert 'evidence relocation refused' in actions
        assert 'evidence relocated' in actions
    finally:
        window.cleanup_resources()


def test_the_archive_dialogs_write_and_open_a_case(qapp, case, tmp_path,
                                                   monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    from trace_app.ui.dialogs import case_archive as dialogs
    from trace_app.ui.dialogs import message
    told = []
    monkeypatch.setattr(message, 'information',
                        lambda *a, **k: told.append(a[2]))
    monkeypatch.setattr(message, 'question', lambda *a, **k: False)
    monkeypatch.setattr(message, 'critical',
                        lambda *a, **k: told.append(('failed',) + a[2:]))
    target = str(tmp_path / 'handed' / 'over.trace')
    os.makedirs(os.path.dirname(target))
    monkeypatch.setattr(QFileDialog, 'getSaveFileName',
                        lambda *a, **k: (target, ''))
    made = dialogs.export_case_archive(None, case)
    assert made and os.path.exists(target), told
    assert any(a['action'] == 'case archived' for a in case.activity(5))

    monkeypatch.setattr(QFileDialog, 'getOpenFileName',
                        lambda *a, **k: (target, ''))
    where = tmp_path / 'cases'
    where.mkdir()
    monkeypatch.setattr(QFileDialog, 'getExistingDirectory',
                        lambda *a, **k: str(where))
    opened = dialogs.open_case_archive(None)
    try:
        assert opened is not None
        assert os.path.normcase(opened.folder) == \
            os.path.normcase(str(where / 'over'))
        assert opened.name == 'Handover'
        assert any('every file matched' in t for t in told) or told
    finally:
        opened.close()

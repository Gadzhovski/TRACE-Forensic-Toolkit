"""The Case and Notes tabs (ui/viewers/case_panel.py, notes_panel.py)."""

import os

import pytest

from tests.conftest import pump


@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Operation Nightingale',
                       '2026-014', 'R. G.',
                       description='Suspected data theft.')
    images = tmp_path / 'images'
    images.mkdir()
    for name in ('laptop.dd', 'phone.dd'):
        (images / name).write_bytes(b'\x00' * 4096)
    case.first = case.add_evidence(str(images / 'laptop.dd'),
                                   details={'exhibit_number': 'RG-01'})
    case.second = case.add_evidence(str(images / 'phone.dd'))
    # Acquired as MD5 abab...: the first hash matches it, so verified.
    case.set_acquisition_hashes(case.first, 'custody form',
                                md5='ab' * 16)
    case.record_hashes(case.first, {'computed_md5': 'ab' * 16,
                                    'computed_sha256': 'cd' * 32})
    yield case
    case.close()


def test_the_case_card_and_evidence_table(qapp, case):
    from PySide6.QtCore import Qt
    from trace_app.ui.viewers.case_panel import CasePanel, format_utc
    panel = CasePanel()
    # What each image holds comes from the window (core/evidence_profile);
    # an image not open has none yet.
    panel.profile_for = lambda row: 'MBR · NTFS · Windows' \
        if row['path'].endswith('laptop.dd') else None
    panel.set_case(case)
    try:
        assert panel.title.text() == 'Operation Nightingale'
        assert panel.meta.text() == '2026-014  ·  R. G.'
        assert panel.facts['Evidence'].text() == \
            '2 items · 1 verified · 1 not hashed'
        table = panel.evidence_table
        assert table.rowCount() == 2
        status = {table.item(r, 0).text(): table.item(r, 2)
                  for r in range(2)}
        assert status['laptop.dd'].text() == 'Verified'
        assert status['laptop.dd'].foreground().color().name() != \
            status['phone.dd'].foreground().color().name()
        contains = {table.item(r, 0).text(): table.item(r, 5).text()
                    for r in range(2)}
        assert contains == {'laptop.dd': 'MBR · NTFS · Windows',
                            'phone.dd': '—'}
        # Hashes shortened, whole in the tooltip.
        md5 = next(table.item(r, 6) for r in range(2)
                   if table.item(r, 0).text() == 'laptop.dd')
        assert md5.text() == 'abababab…abababab' and \
            md5.toolTip() == 'ab' * 16
        # Times read as times.
        assert format_utc('2026-10-06T13:15:28+00:00') == \
            '2026-10-06 13:15 UTC'
        # The filter narrows the table in front.
        panel.filter.setText('phone')
        hidden = [table.isRowHidden(r) for r in range(2)]
        assert sorted(hidden) == [False, True]
        panel.filter.clear()
        # Verify asks the window for jobs.
        asked = []
        panel.verify_requested.connect(asked.append)
        panel.verify_button.click()
        assert len(asked[0]) == 2
        # No case: a plain statement, no tables.
        panel.set_case(None)
        assert not panel.tables.isVisibleTo(panel) and \
            panel.empty.isVisibleTo(panel)
    finally:
        panel.deleteLater()


def test_exhibit_details_are_edited_and_audited(qapp, case):
    from trace_app.ui.viewers.case_panel import EvidenceDetailsDialog
    row = next(r for r in case.evidence() if r['id'] == case.second)
    dialog = EvidenceDetailsDialog(case, row)
    dialog.fields['exhibit_number'].setText('RG-02')
    dialog.fields['acquired_by'].setText('A. Examiner')
    dialog.accept()
    row = next(r for r in case.evidence() if r['id'] == case.second)
    assert row['exhibit_number'] == 'RG-02'
    assert row['acquired_by'] == 'A. Examiner'
    assert any('RG-02' in (entry.get('detail') or '')
               for entry in case.activity())


def test_notes_are_written_edited_filtered_and_deleted(qapp, case,
                                                       monkeypatch):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from trace_app.ui.dialogs import message
    from trace_app.ui.viewers.notes_panel import (NOTE_COLUMN, NotesPanel,
                                                  SCOPE_CASE)
    panel = NotesPanel()
    panel.resize(1200, 300)
    panel.set_case(case)
    panel.show()
    try:
        assert panel.empty.isVisible()
        # About the selected file, by default; Ctrl+Enter saves.
        panel.set_artifact(case.second, 'p0:i29:s1', 'file1.jpg',
                           '/alloc/file1.jpg')
        assert panel.scope.currentText() == 'file1.jpg'
        panel.editor.setPlainText('Holiday photos, not relevant.')
        QTest.keyClick(panel.editor, Qt.Key_Return, Qt.ControlModifier)
        # The press was the editor's to handle: release Ctrl, or Qt keeps
        # it held for every test after this one.
        QTest.keyRelease(panel.editor, Qt.Key_Control)
        assert panel.editor.toPlainText() == ''
        # About the case, chosen.
        panel.scope.setCurrentIndex(panel.scope.findData(SCOPE_CASE))
        panel.editor.setPlainText('Line one\nLine two\nLine three\n'
                                  'Line four\nLine five')
        panel.save_button.click()
        notes = case.notes()
        assert {n['artifact_name'] or '' for n in notes} == {'file1.jpg', ''}
        assert panel.count_label.text() == '2 notes'
        # Long notes are shown cut, whole on hover.
        cell = next(panel.table.item(r, NOTE_COLUMN)
                    for r in range(panel.table.rowCount())
                    if 'Line one' in panel.table.item(r, NOTE_COLUMN).text())
        assert cell.text().endswith('…') and 'Line five' in cell.toolTip()
        # Filtered by scope and text.
        panel.show_filter.setCurrentIndex(1)            # this file
        assert panel.table.rowCount() == 1
        panel.show_filter.setCurrentIndex(0)
        panel.search.setText('HOLIDAY')
        assert panel.table.rowCount() == 1
        assert panel.count_label.text() == '1 of 2'
        panel.search.clear()
        # Edited in place.
        row = next(n for n in case.notes() if n['artifact_name'])
        panel._edit(row)
        assert panel.heading.text() == 'Editing note'
        panel.editor.setPlainText('Holiday photos; checked EXIF.')
        panel.save_button.click()
        assert any(n['body'] == 'Holiday photos; checked EXIF.'
                   for n in case.notes())
        assert panel.heading.text() == 'New note'
        # Its file is one click away.
        opened = []
        panel.open_artifact.connect(opened.append)
        panel._open(row)
        assert opened[0]['artifact_ref'] == 'p0:i29:s1'
        # Deleting asks first.
        monkeypatch.setattr(message, 'question', lambda *a, **k: False)
        panel._delete(row)
        assert len(case.notes()) == 2
        monkeypatch.setattr(message, 'question', lambda *a, **k: True)
        panel._delete(row)
        assert len(case.notes()) == 1
    finally:
        panel.close()
        panel.deleteLater()

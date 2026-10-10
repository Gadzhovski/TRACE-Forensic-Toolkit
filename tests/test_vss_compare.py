"""Comparing Volume Shadow Copies with later states of their volume
(core/vss_compare.py, ui/dialogs/shadow_compare.py).

dfvfs's vss.raw is an NTFS volume with two shadow copies. Its own tests
list the live volume's files, /vss1 and /vss2 among them, and libvshadow
gives the snapshots' creation times: 17:40:03 and 17:41:28 on 2021-05-01.
/vss1 was written at 17:40:10 and /vss2 at 17:41:35 -- so /vss1 is new
since the first snapshot and /vss2 since the second. That is what the
comparison must say. Deletions and renames, which the sample does not
hold, are checked on entries built by hand.
"""

import pytest

from tests.conftest import data_path, pump

STORE = ('/System Volume Information/{de81cc2b-aa8b-11eb-9339-8cdcd4557abc}'
         '{3808876b-c176-4e48-b7ae-04046e6cc752}')


@pytest.fixture
def vss():
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(data_path('samples', 'vss.raw'))
    yield handler, handler.shadow_copies(0)
    handler.close_resources()


def _changes(rows):
    return {(r['change'], r['path']) for r in rows}


def test_each_snapshot_against_what_came_after(vss):
    from trace_app.core import vss_compare
    handler, shadows = vss
    first, second = (s['key'] for s in shadows)
    assert [s['created'].strftime('%H:%M:%S') for s in shadows] == \
        ['17:40:03', '17:41:28']
    one_two = vss_compare.compare_volumes(handler, first, second)
    assert _changes(one_two) == {('added', '/vss1'), ('added', STORE)}
    two_live = vss_compare.compare_volumes(handler, second, 0)
    assert ('added', '/vss2') in _changes(two_live)
    assert ('added', '/vss1') not in _changes(two_live)
    one_live = vss_compare.compare_volumes(handler, first, 0)
    assert {('added', '/vss1'), ('added', '/vss2')} <= _changes(one_live)
    # Every file the snapshot had is still there: nothing deleted.
    assert not [r for r in one_live if r['change'] == 'deleted']
    # NTFS metadata files change with every write: left out unless asked.
    assert not any(r['path'].startswith('/$') for r in one_live)
    with_system = vss_compare.compare_volumes(handler, first, 0, system=True)
    assert any(r['path'].startswith('/$') for r in with_system)


def _entry(path, inode, size=10, modified=100, sequence=1, is_dir=False):
    return {'path': path, 'inode': inode, 'sequence': sequence,
            'size': size, 'modified': modified, 'changed': modified,
            'is_dir': is_dir}


def test_deleted_changed_and_renamed_are_told_apart():
    from trace_app.core import vss_compare
    before = {e['path'].lower(): e for e in (
        _entry('/kept.txt', 30), _entry('/wiped.docx', 31),
        _entry('/report.pdf', 32), _entry('/Old Name.txt', 33),
        _entry('/reused.txt', 34))}
    after = {e['path'].lower(): e for e in (
        _entry('/kept.txt', 30),
        _entry('/report.pdf', 32, size=20, modified=200),   # edited
        _entry('/Archive/New Name.txt', 33),                # moved
        _entry('/reused.txt', 99),                          # another file
        _entry('/new.txt', 40))}
    rows = vss_compare.compare(before, after)
    assert _changes(rows) == {
        ('deleted', '/wiped.docx'), ('changed', '/report.pdf'),
        ('renamed', '/Archive/New Name.txt'), ('changed', '/reused.txt'),
        ('added', '/new.txt')}
    renamed = next(r for r in rows if r['change'] == 'renamed')
    assert renamed['before']['path'] == '/Old Name.txt'
    assert vss_compare.summary(rows) == {'deleted': 1, 'added': 1,
                                         'changed': 2, 'renamed': 1}
    # Paths compare as NTFS names do: case does not make a new file.
    assert vss_compare.compare({'/a.txt': _entry('/a.txt', 5)},
                               {'/a.txt': _entry('/A.TXT', 5)}) == []


def test_the_dialog_compares_in_the_background_and_opens_versions(qapp):
    """Tree ▸ Compare Shadow Copies… on the first snapshot: the job runs
    in a child process, the differences are listed and filtered, and a
    double-click opens the file from the state that has it."""
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs.shadow_compare import ShadowCompareDialog
    from trace_app.core.image_handler import ImageHandler
    path = data_path('samples', 'vss.raw')
    handler = ImageHandler(path)
    try:
        shadows = handler.shadow_copies(0)
    finally:
        handler.close_resources()
    dialog = ShadowCompareDialog(path, 0, 'Volume', shadows,
                                 before=shadows[0]['key'])
    opened = []
    dialog.file_requested.connect(lambda *args: opened.append(args))
    try:
        assert dialog.after_combo.count() == 2          # snapshot 2, live
        assert dialog.after_combo.currentData() == 'live'
        dialog.start()
        assert pump(qapp, 120, lambda: dialog.worker is None)
        paths = {(r['change'], r['path']) for r in dialog.rows}
        assert {('added', '/vss1'), ('added', '/vss2')} <= paths
        dialog.filter_box.setText('vss2')
        assert dialog.table.rowCount() == 1
        assert dialog.table.item(0, 1).text() == '/vss2'
        dialog._open_row(0, 0)
        image, ref, name = opened[-1]
        assert image == path and name == 'vss2'
        assert ref.startswith('p0:')                    # the live volume
        # From the earlier snapshot to the later one instead.
        dialog.after_combo.setCurrentIndex(0)
        dialog.filter_box.clear()
        dialog.start()
        assert pump(qapp, 120, lambda: dialog.worker is None)
        assert {(r['change'], r['path']) for r in dialog.rows} == \
            {('added', '/vss1'), ('added', STORE)}
        assert dialog.table.item(0, 0).data(Qt.UserRole) is not None
    finally:
        dialog.close()
        dialog.deleteLater()
        pump(qapp, 0.2)


def test_the_tree_opens_the_comparison_on_the_image_it_belongs_to(qapp):
    """Right-click a shadow copy in the tree: the dialog is for that
    snapshot, on the image file the node belongs to (it once took a
    node's label for the image path, and the job could not open it)."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from trace_app.ui.dialogs.shadow_compare import ShadowCompareDialog
    from trace_app.ui.main_window import MainWindow
    import os
    path = data_path('samples', 'vss.raw')
    window = MainWindow()
    try:
        window.open_evidence_image(path)
        pump(qapp, 30, lambda: window.tree_viewer.topLevelItemCount() > 0)
        root = window.tree_viewer.topLevelItem(0)
        nodes = [root.child(i) for i in range(root.childCount())]
        shadow = next(n for n in nodes
                      if (n.data(0, Qt.UserRole) or {}).get('is_shadow_copy'))
        assert window._volume_has_shadows(0)
        window.compare_shadow_copies(shadow)
        dialog = next(w for w in QApplication.topLevelWidgets()
                      if isinstance(w, ShadowCompareDialog))
        assert dialog.image_path == os.path.normpath(path)
        assert dialog.before_combo.currentData() == \
            shadow.data(0, Qt.UserRole)['start_offset']
        dialog.close()
    finally:
        window.cleanup_resources()
        pump(qapp, 0.2)

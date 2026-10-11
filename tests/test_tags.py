"""Tags (core/case.py schema 19, ui/viewers/tags_panel.py): the examiner's
own verdicts on files, kept by artifact_ref with the evidence, audited,
shown in Triage, the tree, the Listing and the report."""

import os

import pytest

from tests.conftest import pump
from tools import testdata

FILE_A = {'evidence_id': None, 'artifact_ref': 'p63:i29:s1',
          'name': 'file1.jpg', 'path': '/alloc/file1.jpg'}
FILE_B = {'evidence_id': None, 'artifact_ref': 'p63:i30:s1',
          'name': 'file2.doc', 'path': '/alloc/file2.doc'}


@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Tags', examiner='E. Xaminer')
    yield case
    if case.is_open:
        case.close()


def _submenu(menu, text):
    """A submenu by its entry's text (QAction.menu() can hand back a
    wrapper that deletes the menu: look among the children instead)."""
    from PySide6.QtWidgets import QMenu
    return next(child for child in menu.findChildren(QMenu)
                if child.menuAction().text() == text)


def _tag(case, name):
    return next(t['id'] for t in case.tags() if t['name'] == name)


def test_a_new_case_starts_with_three_tags(case):
    from trace_app.core.case import DEFAULT_TAGS
    assert [(t['name'], t['colour']) for t in case.tags()] == \
        list(DEFAULT_TAGS)
    assert all(t['files'] == 0 for t in case.tags())


def test_tagging_is_counted_listed_and_audited(case):
    relevant = _tag(case, 'Relevant')
    assert case.tag_artifacts(relevant, [FILE_A, FILE_B]) == 2
    assert case.tag_artifacts(relevant, [FILE_A]) == 0      # already
    ignore = _tag(case, 'Ignore')
    case.tag_artifacts(ignore, [FILE_B])

    counts = {t['name']: t['files'] for t in case.tags()}
    assert counts == {'Relevant': 2, 'Needs review': 0, 'Ignore': 1}
    marks = case.tags_for(None, ['p63:i29:s1', 'p63:i30:s1', 'p0:i1'])
    assert [t['name'] for t in marks['p63:i29:s1']] == ['Relevant']
    assert [t['name'] for t in marks['p63:i30:s1']] == ['Relevant', 'Ignore']
    assert 'p0:i1' not in marks
    rows = case.tagged(relevant)
    assert {r['path'] for r in rows} == {'/alloc/file1.jpg',
                                         '/alloc/file2.doc'}
    assert all(r['examiner'] == 'E. Xaminer' and r['tagged_utc']
               for r in rows)

    assert case.untag([FILE_B], ignore) == 1
    assert case.untag([FILE_A]) == 1                         # every tag
    assert [r['path'] for r in case.tagged()] == ['/alloc/file2.doc']

    actions = [(a['action'], a['detail']) for a in case.activity(50)]
    tagged = [d for a, d in actions if a == 'files tagged']
    assert any(d.startswith('Relevant: 2 file(s)') and '/alloc/file1.jpg' in d
               for d in tagged)
    untagged = [d for a, d in actions if a == 'files untagged']
    assert any(d.startswith("'Ignore': 1 file(s)") for d in untagged)
    assert any(d.startswith('every tag: 1 file(s)') for d in untagged)
    assert case.verify_audit()['ok']


def test_tags_are_made_renamed_and_removed_with_their_marks(case):
    own = case.add_tag('Contraband', '#123456')
    assert case.add_tag('Contraband') == own                 # no duplicate
    case.tag_artifacts(own, [FILE_A])
    case.update_tag(own, name='Contraband (CSAM)', colour='#654321')
    tag = next(t for t in case.tags() if t['id'] == own)
    assert (tag['name'], tag['colour'], tag['files']) == \
        ('Contraband (CSAM)', '#654321', 1)
    case.remove_tag(own)
    assert own not in {t['id'] for t in case.tags()}
    assert case.tagged() == []
    actions = [a['action'] for a in case.activity(50)]
    for action in ('tag created', 'tag edited', 'tag removed'):
        assert action in actions
    removed = next(a for a in case.activity(50)
                   if a['action'] == 'tag removed')
    assert 'taken off 1 file(s)' in removed['detail']


def test_a_schema_18_case_gains_tag_columns_and_the_default_tags(tmp_path):
    from trace_app.core.case import Case, SCHEMA_VERSION
    folder = str(tmp_path / 'old')
    case = Case.create(folder, 'Old')
    # As schema 18 left it: the table without the new columns, no tags.
    case._db.executescript("""
        DROP TABLE artifact_tags;
        DELETE FROM tags;
        CREATE TABLE artifact_tags (
            tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
            artifact_ref TEXT NOT NULL,
            PRIMARY KEY (tag_id, evidence_id, artifact_ref));
    """)
    case._set('schema_version', 18)
    case.close()

    case = Case.open(folder)
    try:
        columns = {row[1] for row in case._db.execute(
            "PRAGMA table_info(artifact_tags)")}
        assert {'name', 'path', 'tagged_utc', 'examiner'} <= columns
        assert [t['name'] for t in case.tags()] == \
            ['Relevant', 'Needs review', 'Ignore']
        assert int(case._get('schema_version')) == SCHEMA_VERSION
        case.tag_artifacts(_tag(case, 'Relevant'), [FILE_A])
        assert case.tagged()[0]['name'] == 'file1.jpg'
    finally:
        case.close()
    # Opened again: not seeded twice.
    case = Case.open(folder)
    try:
        assert len(case.tags()) == 3
    finally:
        case.close()


def test_the_report_has_a_tagged_files_section(case):
    from trace_app.core import report
    case.tag_artifacts(_tag(case, 'Needs review'), [FILE_A])
    options = report.default_options(case)
    options['sections'] = [{'key': 'tags', 'enabled': True}]
    options['thumbnails'] = False
    html = report.build_html(case, options)[0]
    assert 'Tagged files' in html
    assert 'Needs review (1)' in html
    assert '/alloc/file1.jpg' in html
    assert 'E. Xaminer' in html
    assert 'tags' in {key for key, _t, _n in report.SECTIONS}


def test_the_window_tags_from_a_menu_and_the_keys(qapp, case, monkeypatch):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (QAbstractItemView, QMenu, QTableWidget,
                                   QTableWidgetItem)
    from trace_app.ui.main_window import MainWindow
    window = MainWindow(case=case)
    table = QTableWidget(2, 1)
    try:
        # A list naming files the way a findings table does.
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        for row, data in enumerate((FILE_A, FILE_B)):
            item = QTableWidgetItem(data['name'])
            item.setData(Qt.UserRole, dict(data))
            table.setItem(row, 0, item)
        table.selectAll()

        menu = QMenu()
        window._menu_extras(menu, dict(FILE_A), table)
        tag_menu = _submenu(menu, 'Tag')
        texts = [a.text() for a in tag_menu.actions() if not a.isSeparator()]
        assert texts[:3] == ['Relevant\t1', 'Needs review\t2', 'Ignore\t3']
        assert 'New Tag…' in texts and 'Manage Tags…' in texts
        assert 'Remove Tag' not in texts            # nothing carried yet
        tag_menu.actions()[0].trigger()
        assert {r['path'] for r in case.tagged(_tag(case, 'Relevant'))} == \
            {'/alloc/file1.jpg', '/alloc/file2.doc'}

        # The tab and the tree follow.
        pump(qapp)
        assert window.tags_panel.tree.topLevelItemCount() == 1
        roots = [window.tree_viewer.topLevelItem(i) for i in
                 range(window.tree_viewer.topLevelItemCount())]
        tags_root = next(r for r in roots
                         if (r.data(0, Qt.UserRole) or {}).get('is_tags_root'))
        assert tags_root.text(0) == 'Tags (2)'
        assert tags_root.child(0).childCount() == 2

        # Keys: 2 tags the selection Needs review, 0 clears every tag.
        assert window._tag_key(table, Qt.Key_2)
        assert len(case.tagged(_tag(case, 'Needs review'))) == 2
        menu = QMenu()
        window._menu_extras(menu, dict(FILE_A), table)
        tag_menu = _submenu(menu, 'Tag')
        remove = _submenu(tag_menu, 'Remove Tag')
        assert [a.text() for a in remove.actions() if not a.isSeparator()] \
            == ['Relevant', 'Needs review', 'Every Tag\t0']
        assert window._tag_key(table, Qt.Key_0)
        assert case.tagged() == []
        assert not any((window.tree_viewer.topLevelItem(i).data(
            0, Qt.UserRole) or {}).get('is_tags_root') for i in
            range(window.tree_viewer.topLevelItemCount()))
        # A row naming no file is not tagged by a key.
        empty = QTableWidget(1, 1)
        empty.setItem(0, 0, QTableWidgetItem('text'))
        empty.selectAll()
        assert not window._tag_key(empty, Qt.Key_1)
        empty.deleteLater()
    finally:
        table.deleteLater()
        window.cleanup_resources()


JPEG_IMAGE = testdata.locate('8-jpeg-search.dd') or ''


@pytest.mark.skipif(not os.path.exists(JPEG_IMAGE),
                    reason='8-jpeg-search.dd not downloaded')
def test_a_tagged_listing_row_shows_its_tag(qapp, case):
    """Key 1 on a Listing row tags that file on its image; the Flag
    column shows the tag, and 0 takes it away again."""
    from PySide6.QtCore import Qt
    from trace_app.core.case import parse_artifact_ref
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.main_window import MainWindow
    window = MainWindow(case=case)
    handler = ImageHandler(JPEG_IMAGE)
    try:
        assert window.open_evidence_image(JPEG_IMAGE)
        root = handler.get_root_inode(0)
        folder = next(e for e in handler.get_directory_contents(0, root)
                      if e['name'] == 'alloc')
        entry = next(e for e in handler.get_directory_contents(
            0, folder['inode_number']) if e['name'] == 'file1.jpg')
        window.show_listing_for_artifact({
            'start_offset': 0, 'inode_number': entry['inode_number'],
            'name': 'file1.jpg', 'path': '/alloc/file1.jpg'})
        pump(qapp, 0.3)
        table = window.listing_table
        row = next(r for r in range(table.rowCount())
                   if table.item(r, 0).text() == 'file1.jpg')
        table.clearSelection()
        table.selectRow(row)
        assert window._tag_key(table, Qt.Key_1)
        tagged = case.tagged()
        assert len(tagged) == 1
        assert tagged[0]['evidence_id'] == \
            window.evidence_id_for_path(JPEG_IMAGE)
        ref = parse_artifact_ref(tagged[0]['artifact_ref'])
        assert ref['inode'] == entry['inode_number']
        assert tagged[0]['name'] == 'file1.jpg'
        flag = table.item(row, 14)
        assert flag.text() == 'Relevant'
        assert not flag.icon().isNull()
        assert 'Tagged: Relevant' in flag.toolTip()
        assert window._tag_key(table, Qt.Key_0)
        assert case.tagged() == []
        assert table.item(row, 14).text() == ''
        assert table.item(row, 14).icon().isNull()
    finally:
        handler.close_resources()
        window.cleanup_resources()


def test_tag_dots_are_drawn_sharp_at_any_display_scale(qapp):
    """A tag's dot is a shape drawn at the size and pixel ratio asked for
    (icons.dot_icon), never a small bitmap stretched -- which a 125% or
    150% display showed jagged."""
    from PySide6.QtCore import QSize
    from trace_app.ui.viewers.tags_panel import tag_icon
    icon = tag_icon('#2F81F7')
    for scale in (1.0, 1.5, 2.0):
        pixmap = icon.pixmap(QSize(16, 16), scale)
        assert pixmap.width() == round(16 * scale), scale
        assert pixmap.devicePixelRatio() == scale
    # Anti-aliased: the edge has partly covered pixels, not a hard step.
    image = icon.pixmap(QSize(32, 32), 2.0).toImage()
    alphas = {image.pixelColor(x, 32).alpha() for x in range(64)}
    assert any(0 < a < 255 for a in alphas)

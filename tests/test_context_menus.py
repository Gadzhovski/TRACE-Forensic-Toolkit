"""Right-click menus and copying everywhere (ui/widgets/context_menus.py),
the Text tab's Bookmark Selection, and the Hex tab's Ctrl+C."""

import csv
import os

import pytest

from tests.conftest import ROOT
from tools import testdata
from tests.conftest import pump

JPEG_IMAGE = testdata.locate('8-jpeg-search.dd') or ''


@pytest.fixture
def table(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
    widget = QTableWidget(3, 3)
    widget.setHorizontalHeaderLabels(['Name', 'Size', 'Path'])
    for row, values in enumerate((('a.txt', '1 KB', '/a'),
                                  ('b.jpg', '2 KB', '/b'),
                                  ('c.exe', '3 KB', '/c'))):
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(Qt.UserRole, {'name': value})
            widget.setItem(row, column, item)
    widget.resize(500, 200)
    widget.show()
    yield widget
    widget.close()
    widget.deleteLater()


def test_a_selection_copies_as_rows_and_columns(table, tmp_path):
    from PySide6.QtCore import QItemSelectionModel
    from PySide6.QtWidgets import QAbstractItemView
    from trace_app.ui.widgets import context_menus as cm
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.selectRow(0)
    table.selectionModel().select(
        table.model().index(2, 0),
        QItemSelectionModel.SelectionFlag.Select |
        QItemSelectionModel.SelectionFlag.Rows)
    assert cm.selection_text(table) == 'a.txt\t1 KB\t/a\nc.exe\t3 KB\t/c'
    assert cm.selection_text(table, headers=True, whole_rows=True) \
        .splitlines()[0] == 'Name\tSize\tPath'
    assert cm.column_text(table, 2) == '/a\n/c'
    table.clearSelection()
    assert cm.column_text(table, 0) == 'a.txt\nb.jpg\nc.exe'   # all rows
    table.setRowHidden(1, True)
    path = cm.export_csv(table, str(tmp_path / 'out.csv'))
    rows = list(csv.reader(open(path, encoding='utf-8-sig')))
    assert rows == [['Name', 'Size', 'Path'], ['a.txt', '1 KB', '/a'],
                    ['c.exe', '3 KB', '/c']]                # hidden left out


def test_ctrl_c_copies_any_table(qapp, table):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from trace_app.ui.widgets import context_menus
    context_menus.install(qapp)
    table.setFocus()
    table.setCurrentCell(1, 2)
    table.selectRow(1)
    QApplication.clipboard().setText('')
    QTest.keyClick(table, Qt.Key_C, Qt.ControlModifier)
    QTest.keyRelease(table, Qt.Key_Control)
    assert QApplication.clipboard().text() == 'b.jpg\t2 KB\t/b'


def test_menus_get_copy_entries_icons_and_file_actions(qapp, table):
    from PySide6.QtWidgets import QMenu
    from trace_app.ui.widgets import context_menus as cm
    menu = QMenu()
    menu.addAction("Show in Listing")
    menu.addAction("Delete Note…")
    point = table.viewport().mapToGlobal(
        table.visualRect(table.model().index(1, 1)).center())
    seen = []
    cm.set_row_hook(lambda m, row: seen.append(row))
    try:
        assert cm.row_at(table, point) == {'name': 'b.jpg'}
        cm.add_view_actions(menu, table, point)
        cm.add_icons(menu)
    finally:
        cm.set_row_hook(None)
    texts = [a.text() for a in menu.actions() if not a.isSeparator()]
    assert texts[2:] == ['Copy', 'Copy Rows with Headers',
                         'Copy Column “Size”', 'Export Table to CSV…']
    assert all(not a.icon().isNull() for a in menu.actions()
               if not a.isSeparator())


def test_any_row_naming_a_file_offers_export_and_bookmark(qapp, monkeypatch):
    from PySide6.QtWidgets import QMenu
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        row = {'artifact_ref': 'p63:i29:s1', 'evidence_id': None,
               'name': 'file1.jpg', 'path': '/alloc/file1.jpg'}
        data = window._file_data_for(row)
        assert data == {'inode_number': 29, 'start_offset': 63,
                        'sequence': 1, 'name': 'file1.jpg',
                        'path': '/alloc/file1.jpg', 'type': 'file'}
        menu = QMenu()
        window._menu_extras(menu, row)
        assert [a.text() for a in menu.actions()] == ['Export File…']
        # A menu that has its own Export is left alone.
        menu = QMenu()
        menu.addAction("Export")
        window._menu_extras(menu, row)
        assert len(menu.actions()) == 1
        # Byte ranges and keys are not files.
        assert window._file_data_for({'artifact_ref': 'p0:x10-20'}) is None
        assert window._file_data_for({'artifact_ref': 'reg:SYSTEM:x'}) \
            is None
    finally:
        window.cleanup_resources()


def test_the_hex_tab_copies_bytes_with_ctrl_c(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from trace_app.ui.viewers.hex import HexViewer
    from trace_app.ui.widgets import context_menus
    context_menus.install(qapp)
    viewer = HexViewer()
    viewer.show()
    try:
        viewer.display_hex_content(b'\x00' * 16 + b'JFIF' + b'\x00' * 12)
        viewer.show_bytes(16, 4)
        viewer.hex_table.setFocus()
        QTest.keyClick(viewer.hex_table, Qt.Key_C, Qt.ControlModifier)
        QTest.keyRelease(viewer.hex_table, Qt.Key_Control)
        assert QApplication.clipboard().text() == '4A 46 49 46'
    finally:
        viewer.close()
        viewer.deleteLater()


@pytest.mark.skipif(not os.path.exists(JPEG_IMAGE),
                    reason='8-jpeg-search.dd not downloaded')
def test_text_selected_in_the_text_tab_bookmarks_its_bytes(qapp, tmp_path,
                                                          monkeypatch):
    """'JFIF' selected among a JPEG's strings bookmarks those four bytes
    of the image."""
    from PySide6.QtGui import QTextCursor
    from PySide6.QtWidgets import QInputDialog
    from trace_app.core.case import Case, parse_artifact_ref
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.main_window import MainWindow
    case = Case.create(str(tmp_path / 'case'), 'Text marks')
    window = MainWindow(case=case)
    try:
        assert window.open_evidence_image(JPEG_IMAGE)
        handler = ImageHandler(JPEG_IMAGE)
        root = handler.get_root_inode(0)
        folder = next(e for e in handler.get_directory_contents(0, root)
                      if e['name'] == 'alloc')
        entry = next(e for e in handler.get_directory_contents(
            0, folder['inode_number']) if e['name'] == 'file1.jpg')
        content, _ = handler.get_file_content(entry['inode_number'], 0)
        window.current_selected_data = {
            'type': 'file', 'name': 'file1.jpg',
            'inode_number': entry['inode_number'], 'start_offset': 0}
        viewer = window.text_viewer
        viewer.display_text_content(content)
        text = viewer.text_edit.toPlainText()
        at = text.index('JFIF')
        cursor = viewer.text_edit.textCursor()
        cursor.setPosition(at)
        cursor.setPosition(at + 4, QTextCursor.KeepAnchor)
        viewer.text_edit.setTextCursor(cursor)
        monkeypatch.setattr(QInputDialog, 'getText',
                            lambda *a, **k: (k.get('text') or 'JFIF', True))
        viewer.bookmark_selection()
        mark = case.bookmarks()[-1]
        ref = parse_artifact_ref(mark['artifact_ref'])
        assert ref['kind'] == 'span'
        assert handler.read(ref['begin'], ref['end'] - ref['begin']) == \
            b'JFIF'
        assert '“JFIF”' in mark['label']
        handler.close_resources()
    finally:
        window.cleanup_resources()
        case.close()

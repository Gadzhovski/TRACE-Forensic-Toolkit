"""The Hex tab (ui/viewers/hex.py, core/hex_source.py): search by exact
offset, the data inspector, selection tools, bytes per line, offsets in
decimal, and a file on the image read a page at a time with its image
offsets taken from the file system's data runs."""

import base64
import os
import random

import pytest

from trace_app.core import hex_source
from tests.conftest import ROOT
from tools import testdata
from tests.conftest import pump

JPEG_IMAGE = testdata.locate('8-jpeg-search.dd') or ''

DATA = (b'\x00' * 21 + b'Hello EXIF' + b'\x00' * 40 +
        'Secret'.encode('utf-16-le') + b'\x00' * 30 + b'exif\xff\xd8')


# --- core: no Qt ------------------------------------------------------------------

def test_search_finds_every_offset_across_chunks():
    data = bytearray(random.Random(3).randbytes(200_000))
    for offset in (0, 4095, 4096 - 3, 150_000, len(data) - 6):
        data[offset:offset + 6] = b'NeEdLe'
    source = hex_source.BytesSource(bytes(data))
    expected = [i for i in range(len(data))
                if data[i:i + 6].lower() == b'needle']
    # Small chunks: matches straddle the chunk edges, none counted twice.
    for chunk in (7, 4096, 1 << 20):
        assert hex_source.find_all(source, b'needle', fold=True,
                                   chunk=chunk) == expected
    assert hex_source.find_all(source, b'needle', fold=False) == []
    # Overlapping matches count; the limit holds.
    assert hex_source.find_all(hex_source.BytesSource(b'AAAA'), b'AA') == \
        [0, 1, 2]
    assert len(hex_source.find_all(hex_source.BytesSource(b'A' * 50), b'A',
                                   limit=10)) == 10


def test_needles_and_offsets():
    from trace_app.ui.viewers.hex import needle, parse_offset
    assert needle('4A 46 49 46', 'hex') == b'JFIF'
    assert needle('4a464946', 'hex') == b'JFIF'
    assert needle(r'\x4a\x46', 'hex') == b'JF'
    assert needle('0x4A,0x46', 'hex') == b'JF'
    with pytest.raises(ValueError):
        needle('4A4', 'hex')
    with pytest.raises(ValueError):
        needle('zz', 'hex')
    assert needle('Exif', 'text') == b'exif'
    assert needle('Ab', 'utf16') == b'a\x00b\x00'
    assert parse_offset('0x1B') == parse_offset('1Bh') == \
        parse_offset('27') == 27
    with pytest.raises(ValueError):
        parse_offset('nowhere')


def test_the_inspector_reads_numbers_and_times():
    # FILETIME 2020-06-26 01:38:58.272564 UTC, little-endian.
    rows = dict(hex_source.interpret(bytes.fromhex(
        '003c9f8f5a4bd601 0102030405060708'.replace(' ', ''))))
    assert rows['FILETIME'] == '2020-06-26 01:38:58.272564 UTC'
    assert rows['UInt16'] == '15,360' and rows['Int8'] == '0'
    assert rows['GUID'] == '{8F9F3C00-4B5A-01D6-0102-030405060708}'
    # Unix 1,600,000,000 = 2020-09-13 12:26:40, both byte orders.
    little = (1_600_000_000).to_bytes(4, 'little') + b'\x00' * 12
    big = (1_600_000_000).to_bytes(4, 'big') + b'\x00' * 12
    assert dict(hex_source.interpret(little))['Unix time (32-bit)'] == \
        '2020-09-13 12:26:40 UTC'
    assert dict(hex_source.interpret(big, little=False))[
        'Unix time (32-bit)'] == '2020-09-13 12:26:40 UTC'
    # A FAT time (low word time, high word date): 2009-06-15 10:30:22.
    fat = ((10 << 11) | (30 << 5) | 11) | \
        (((2009 - 1980) << 9 | 6 << 5 | 15) << 16)
    assert dict(hex_source.interpret(fat.to_bytes(4, 'little')))[
        'DOS date and time'] == '2009-06-15 10:30:22 (local, no zone)'
    # Too short, or not a plausible time: a dash, not a wrong answer.
    short = dict(hex_source.interpret(b'\x01'))
    assert short['UInt32'] == '—' and short['FILETIME'] == '—'
    assert dict(hex_source.interpret(b'\x00' * 16))['FILETIME'] == '—'


def test_selections_copy_in_every_form():
    data = b'JF\x00\xff'
    assert hex_source.copy_as(data, 'hex') == '4A 46 00 FF'
    assert hex_source.copy_as(data, 'hex_compact') == '4a4600ff'
    assert hex_source.copy_as(data, 'c') == \
        'unsigned char data[4] = {\n    0x4A, 0x46, 0x00, 0xFF\n};'
    assert hex_source.copy_as(data, 'python') == "b'JF\\x00\\xff'"
    assert base64.b64decode(hex_source.copy_as(data, 'base64')) == data
    assert hex_source.copy_as(data, 'text') == 'JF..'


# --- the viewer ---------------------------------------------------------------------

def _forget_view_choices():
    """The View menu's choices are remembered (config.ini [Hex]): each
    test's viewer starts from the defaults, not the last test's."""
    import configparser
    from trace_app.infra.paths import config_file
    parser = configparser.ConfigParser()
    parser.read(config_file())
    if parser.remove_section('Hex'):
        with open(config_file(), 'w', encoding='utf-8') as handle:
            parser.write(handle)


@pytest.fixture
def viewer(qapp):
    from trace_app.ui.viewers.hex import HexViewer
    _forget_view_choices()
    widget = HexViewer()
    widget.resize(1200, 500)
    widget.show()
    yield widget
    widget.close()
    widget.deleteLater()


def _selected(viewer):
    return sorted((i.row(), i.column())
                  for i in viewer.hex_table.selectedIndexes())


def test_each_search_kind_selects_exactly_its_bytes(qapp, viewer):
    from PySide6.QtCore import QPoint
    viewer.display_hex_content(DATA)

    def search(kind, text):
        viewer.search_kind.setCurrentIndex(viewer.search_kind.findData(kind))
        viewer.search_bar.setText(text)
        viewer.trigger_search()

    search('text', 'exif')
    assert pump(qapp, 5, lambda: viewer.results_table.rowCount() == 2)
    assert [viewer.results_table.item(r, 0).text() for r in range(2)] == \
        ['0000001B', '00000071']
    assert viewer.results_table.horizontalHeaderItem(1).text() == \
        'Match (2)'
    assert _selected(viewer) == [(1, 12), (1, 13), (1, 14), (1, 15)]
    # Every match on the page is marked, not only the one selected.
    from trace_app.ui.viewers.hex import MATCH_ROLE
    second = viewer.hex_table.item(7, 2)            # byte 113
    assert second.data(MATCH_ROLE)
    assert not viewer.hex_table.item(7, 1).data(MATCH_ROLE)
    viewer.find_next()                              # F3
    assert _selected(viewer)[0] == (7, 2)
    viewer.find_next()                              # wraps round
    assert _selected(viewer)[0] == (1, 12)
    viewer.find_previous()
    assert _selected(viewer)[0] == (7, 2)

    search('utf16', 'SECRET')                       # 12 bytes over a line
    assert pump(qapp, 5, lambda: viewer.results_table.rowCount() == 1)
    selected = _selected(viewer)
    assert selected[0] == (4, 8) and selected[-1] == (5, 3)
    assert len(selected) == 12

    search('hex', 'FF D8')
    assert pump(qapp, 5, lambda: viewer.matches == [117])
    search('offset', '0x40')
    assert _selected(viewer) == [(4, 1)]
    assert viewer.status_label.text().startswith('Offset 0x40 (64)')

    # The search box sits over the side panel, left edges together.
    pump(qapp, 0.3)
    left = viewer.side.mapTo(viewer, QPoint(0, 0)).x()
    assert abs(viewer.search_kind.mapTo(viewer, QPoint(0, 0)).x()
               - left) <= 1


def test_search_results_are_shown_on_the_gui_thread(qapp, viewer):
    """The search runs on a worker moved to a QThread. Its result used
    to reach the viewer through a lambda, which PySide runs in the
    *sender's* thread -- so the results table and the hex page were
    filled from the worker while the GUI thread painted them, and macOS
    Intel CI crashed (segfault in QTableWidgetItem::data). Where the
    result is handled is checked directly: not only when the race hits."""
    from PySide6.QtCore import QThread
    viewer.display_hex_content(DATA)
    threads = []
    original = viewer.handle_search_results

    def recording(matches, length):
        threads.append(QThread.currentThread())
        original(matches, length)
    viewer.handle_search_results = recording
    for kind, text in (('text', 'exif'), ('hex', 'FF D8'),
                       ('utf16', 'SECRET')):
        viewer.search_kind.setCurrentIndex(viewer.search_kind.findData(kind))
        viewer.search_bar.setText(text)
        viewer.trigger_search()
        count = len(threads)
        assert pump(qapp, 5, lambda: len(threads) > count)
    assert threads and all(t == qapp.thread() for t in threads)


def test_inspector_status_and_layout_follow_the_cursor(qapp, viewer):
    data = bytearray(64)
    data[16:20] = (1_600_000_000).to_bytes(4, 'little')
    viewer.display_hex_content(bytes(data), {'is_carved': True,
                                             'offset': 0x10000})
    viewer.show_bytes(16, 4)
    rows = {viewer.inspector.item(r, 0).text():
            viewer.inspector.item(r, 1).text()
            for r in range(viewer.inspector.rowCount())}
    assert rows['Unix time (32-bit)'] == '2020-09-13 12:26:40 UTC'
    viewer.view_actions['byte_order'][False].trigger()  # big-endian
    rows = {viewer.inspector.item(r, 0).text():
            viewer.inspector.item(r, 1).text()
            for r in range(viewer.inspector.rowCount())}
    assert rows['UInt32'] == f"{int.from_bytes(data[16:20], 'big'):,}"
    # A carve that was not rebuilt is one stretch of the image.
    status = viewer.status_label.text()
    assert 'Selected 4 bytes 0x10–0x13' in status
    assert 'Image offset 0x10010' in status and 'sector 128' in status

    # 32 to a line: the selection stays on its bytes.
    viewer.view_actions['bytes'][32].trigger()
    assert viewer.hex_table.columnCount() == 34
    assert _selected(viewer) == [(0, 17), (0, 18), (0, 19), (0, 20)]
    viewer.view_actions['offsets'][True].trigger()      # decimal
    assert viewer.hex_table.item(1, 0).text() == '32'
    assert 'Offset 16' in viewer.status_label.text()


def test_selection_tools(qapp, viewer, tmp_path):
    from PySide6.QtWidgets import QApplication
    from trace_app.ui.dialogs import message
    viewer.display_hex_content(DATA)
    viewer.show_bytes(27, 4)
    viewer.copy_selection('hex')
    assert QApplication.clipboard().text() == '45 58 49 46'
    viewer.copy_selection('base64')
    assert base64.b64decode(QApplication.clipboard().text()) == b'EXIF'
    saved = message.information
    message.information = lambda *a, **k: None
    try:
        path = viewer.export_selection(str(tmp_path / 'sel.bin'))
    finally:
        message.information = saved
    assert open(path, 'rb').read() == b'EXIF'
    # Bytes in memory with no place on the image cannot be bookmarked.
    assert viewer._bookmark_refusal(viewer.selection())


@pytest.mark.skipif(not os.path.exists(JPEG_IMAGE),
                    reason='8-jpeg-search.dd not downloaded')
def test_a_file_on_the_image_is_read_a_page_at_a_time(qapp, viewer):
    """The hex view reads only the page shown; byte offsets map to the
    image through the data runs, and a contiguous selection bookmarks as a
    byte range of the image."""
    from trace_app.core.hex_source import ImageFileSource
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(JPEG_IMAGE)
    try:
        start = next((p[2] for p in handler.get_partitions() or ()
                      if handler.has_filesystem(p[2])), 0)
        root = handler.get_root_inode(start)
        folder = next(e for e in handler.get_directory_contents(start, root)
                      if e['name'] == 'alloc')
        entry = next(e for e in handler.get_directory_contents(
            start, folder['inode_number']) if e['name'] == 'file1.jpg')
        content, _meta = handler.get_file_content(entry['inode_number'],
                                                  start)
        source = ImageFileSource(handler, entry['inode_number'], start)
        reads = []
        read = source.read
        source.read = lambda o, n: (reads.append(n), read(o, n))[1]
        viewer.display_source(source, {'name': 'file1.jpg'})
        assert max(reads) <= viewer.page_size()          # never whole
        assert source.size == len(content) > viewer.page_size() // 2
        # Every byte's image offset holds that byte.
        for offset in (0, 1, 4095, 4096, len(content) - 1):
            image = source.image_offset(offset)
            assert handler.read(image, 1) == content[offset:offset + 1]
        assert source.contiguous(0, 4096)
        viewer.show_bytes(0, 4)
        assert 'Image offset' in viewer.status_label.text()
        asked = []
        viewer.bookmarks_enabled = lambda: True
        viewer.bookmark_requested.connect(
            lambda b, e, d: asked.append((b, e, d)))
        viewer.bookmark_selection()
        begin, end, description = asked[0]
        assert end - begin == 4 and handler.read(begin, 4) == content[:4]
        assert description.startswith('file1.jpg: bytes 0–3')
        # The search runs over the whole file with a reader of its own.
        viewer.search_kind.setCurrentIndex(viewer.search_kind.findData('hex'))
        viewer.search_bar.setText('FF D9')
        viewer.trigger_search()
        assert pump(qapp, 10, lambda: bool(viewer.matches))
        assert viewer.matches[-1] == content.rfind(b'\xff\xd9')
    finally:
        viewer.clear_content()
        handler.close_resources()


def test_the_divider_starts_at_the_bytes_and_moves_freely(qapp, viewer):
    """The bytes panel starts as wide as its columns; the examiner can
    drag it wider (or narrower), and their split then stands."""
    viewer.resize(1700, 500)
    viewer.display_hex_content(bytes(range(256)) * 64)
    pump(qapp, 0.3)
    assert viewer.splitter.sizes()[0] == viewer._content_width
    assert viewer.hex_table.horizontalHeader().length() <= \
        viewer.hex_table.viewport().width()            # no scroll bar
    viewer.splitter.moveSplitter(1300, 1)
    pump(qapp, 0.3)
    assert viewer.splitter.sizes()[0] == 1300
    viewer.view_actions['font'][12].trigger()
    pump(qapp, 0.3)
    assert viewer.splitter.sizes()[0] == 1300


def test_the_inspector_can_be_hidden_and_the_side_panel_arranges(qapp,
                                                                viewer):
    from PySide6.QtCore import Qt
    viewer.resize(1700, 500)
    viewer.display_hex_content(bytes(64))
    pump(qapp, 0.3)
    assert viewer.side.orientation() == Qt.Horizontal     # side by side
    assert viewer.side.widget(1) is viewer.results_table  # under search
    viewer.inspector_action.trigger()                     # hide
    pump(qapp, 0.3)
    assert not viewer.inspector_panel.isVisible()
    assert viewer.side.orientation() == Qt.Vertical
    viewer.inspector_action.trigger()                     # show again
    pump(qapp, 0.3)
    assert viewer.inspector_panel.isVisible()


def test_dragging_over_ascii_selects_the_bytes(qapp, viewer):
    """A drag across characters in the ASCII column selects exactly those
    bytes in the hex columns; Shift+click extends from where it began."""
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtTest import QTest
    viewer.display_hex_content(DATA)
    pump(qapp, 0.3)
    table = viewer.hex_table
    rect = table.visualRect(table.model().index(1, viewer.bytes_per_line + 1))
    left, advance = viewer.ascii_geometry(rect)
    y = rect.center().y()
    viewport = table.viewport()
    start = QPoint(left + 11 * advance + advance // 2, y)      # byte 27
    finish = QPoint(left + 14 * advance + advance // 2, y)     # byte 30
    QTest.mousePress(viewport, Qt.LeftButton, Qt.NoModifier, start)
    QTest.mouseMove(viewport, finish)
    QTest.mouseRelease(viewport, Qt.LeftButton, Qt.NoModifier, finish)
    assert viewer.selection() == (27, 31)                      # 'EXIF'
    assert _selected(viewer) == [(1, 12), (1, 13), (1, 14), (1, 15)]
    QTest.mouseClick(viewport, Qt.LeftButton, Qt.ShiftModifier,
                     QPoint(left + advance // 2,
                            table.visualRect(table.model().index(
                                2, viewer.bytes_per_line + 1)).center().y()))
    # Qt remembers Shift as held after a click carrying it; a later test's
    # selectRow() would extend instead of select.
    QTest.keyRelease(viewport, Qt.Key_Shift)
    assert viewer.selection() == (27, 33)      # to byte 32 on the next line
    # A click on the bytes still selects bytes, as before.
    assert viewer._ascii_offset_at(QPoint(5, y)) is None


def test_the_ascii_column_fills_the_width_it_is_given(qapp, viewer):
    viewer.resize(1700, 500)
    viewer.display_hex_content(bytes(512))
    pump(qapp, 0.3)
    table = viewer.hex_table
    last = viewer.bytes_per_line + 1
    fitted = table.columnWidth(last)
    viewer.splitter.moveSplitter(1300, 1)
    pump(qapp, 0.3)
    assert table.columnWidth(last) > fitted
    assert table.horizontalHeader().length() <= table.viewport().width()


def test_the_qt_calls_each_hex_cell_makes_keep_none_alive(qapp):
    """PySide6 6.12.0's QTableWidgetItem.setTextAlignment released a
    reference to None on every call. The hex view makes it for every cell,
    so on Python 3.10 and 3.11 None's count reached zero a few pages in and
    the interpreter aborted -- CI's Linux 3.10 workers died four times. On
    3.12+ None is immortal and its count never moves, so this only bites
    (and only checks) where it can happen."""
    import sys
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
    table = QTableWidget(1, 2)
    font = QFont()
    before = sys.getrefcount(None)
    for _ in range(500):
        cell = QTableWidgetItem('00')
        cell.setTextAlignment(Qt.AlignCenter)
        cell.setFont(font)
        cell.setData(Qt.UserRole + 1, True)
        table.setItem(0, 1, cell)
    assert sys.getrefcount(None) > before - 50, \
        "PySide6 is releasing references to None (see requirements.txt)"

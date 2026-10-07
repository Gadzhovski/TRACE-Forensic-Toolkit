"""The Text tab (ui/viewers/text.py) and programs' own icons
(core/pe_icons.py, ui/widgets/program_icons.py)."""

import base64
import os

import pytest

from tests.conftest import ROOT
from tests.conftest import pump
from trace_app.ui.viewers import text as text_view

PAGEANT = os.path.join(ROOT, 'test_images', 'carve_samples', 'pageant.exe')


# --- what the bytes are -------------------------------------------------------------

def test_text_files_are_shown_as_text():
    assert text_view.decode_text('line one\n\tline two\n'.encode()) == \
        ('line one\n\tline two\n', 'UTF-8')
    assert text_view.decode_text('﻿snow ☃'.encode('utf-8'))[1] == \
        'UTF-8'
    assert text_view.decode_text(
        b'\xff\xfe' + 'Windows notes'.encode('utf-16-le')) == \
        ('Windows notes', 'UTF-16LE')
    assert text_view.decode_text('café'.encode('cp1252')) == \
        ('café', 'Windows-1252')
    assert text_view.decode_text(b'MZ\x90\x00\x03\x00\x00\x00') is None


def test_strings_are_ascii_and_utf16_with_offsets():
    data = (b'\x00\x01' + b'ASCII string' + b'\x00\x00' +
            'wide one'.encode('utf-16-le') + b'\xff\xfe' + b'ab' + b'\x00')
    found = text_view.extract_strings(data)
    assert found == [(2, 'ASCII string', 'A'), (16, 'wide one', 'U')]
    manager = text_view.TextViewerManager()
    manager.load_text_content(data)
    assert manager.mode == text_view.SHOW_STRINGS
    assert manager.text_content.splitlines() == \
        ['00000002    ASCII string', '00000010  U wide one']
    # Show: Text over a binary is the bytes as Windows-1252, by request.
    manager.load_text_content(data, text_view.SHOW_TEXT)
    assert manager.mode == text_view.SHOW_TEXT


def test_pages_end_at_line_breaks_and_search_ignores_case():
    lines = [f"line {n} {'needle' if n % 997 == 0 else 'hay'}"
             for n in range(40000)]
    manager = text_view.TextViewerManager()
    manager.load_text_content('\n'.join(lines).encode())
    assert manager.get_total_pages() > 1
    for start in manager.page_starts[1:]:
        assert manager.text_content[start - 1] == '\n'
    first = manager.search_for_string('NEEDLE')
    assert manager.text_content[first:first + 6] == 'needle'
    total = len(manager.matches)
    assert total == len([n for n in range(40000) if n % 997 == 0])
    last = manager.search_for_string('needle', text_view.SearchDirection.
                                     PREVIOUS)
    assert last == manager.matches[-1]     # wraps round to the last
    assert manager.current_page == manager.page_of(last)
    assert manager.search_for_string('NeEdLe') == first


def test_a_selection_decodes_only_when_it_really_does():
    secret = 'meet at the docks'
    assert text_view.decode_selection(
        base64.b64encode(secret.encode()).decode()) == [('Base64', secret)]
    assert ('Hex', secret) in text_view.decode_selection(
        secret.encode().hex())
    assert text_view.decode_selection('a%20b%2Fc') == \
        [('URL encoding', 'a b/c')]
    assert text_view.decode_selection('Tom &amp; Jerry') == \
        [('HTML entities', 'Tom & Jerry')]
    assert text_view.decode_selection('01001000 01101001') == \
        [('Binary', 'Hi')]
    # Ordinary text decodes to nothing -- it used to be echoed back.
    assert text_view.decode_selection('just some words here') == []
    assert text_view.decode_selection('Hello') == []


def test_the_text_tab_finds_marks_and_selects(qapp):
    viewer = text_view.TextViewer()
    viewer.resize(900, 400)
    viewer.show()
    try:
        text = '\n'.join(['alpha Beta gamma'] * 50 +
                         ['the BETA line'] * 3).encode()
        viewer.display_text_content(text)
        assert viewer.mode_label.text().strip() == 'Text · UTF-8'
        viewer.search_input.setText('beta')
        viewer.search_next()
        assert viewer.match_label.text() == '1 of 53'
        assert viewer.text_edit.textCursor().selectedText() == 'Beta'
        assert len(viewer.text_edit.extraSelections()) == 53
        viewer.search_previous()
        assert viewer.match_label.text() == '53 of 53'
        assert viewer.text_edit.textCursor().selectedText() == 'BETA'
        viewer.show_combo.setCurrentIndex(2)             # Strings
        assert viewer.manager.mode == text_view.SHOW_STRINGS
    finally:
        viewer.close()
        viewer.deleteLater()


# --- programs' own icons -------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(PAGEANT),
                    reason='carve samples not built')
def test_a_programs_icon_is_read_from_its_resources(qapp):
    from PySide6.QtGui import QImage
    from trace_app.core.pe_icons import program_icon
    data = open(PAGEANT, 'rb').read()
    reads = []

    def read(offset, length):
        reads.append(length)
        return data[offset:offset + length]

    for size, expected in ((16, 16), (32, 32), (256, 48)):
        icon = program_icon(read, size)
        image = QImage()
        assert image.loadFromData(icon)
        assert (image.width(), image.height()) == (expected, expected)
    assert sum(reads) < len(data) // 10            # never the whole file
    assert program_icon(lambda o, n: b'not a program'[o:o + n]) is None
    assert program_icon(lambda o, n: (b'MZ' + bytes(200))[o:o + n]) is None


@pytest.mark.skipif(not os.path.exists(PAGEANT),
                    reason='carve samples not built')
def test_listing_rows_get_their_programs_icons(qapp, tmp_path):
    """A program in the Listing and the tree shows its own icon once it is
    read; a text file keeps its file-type icon."""
    import shutil
    from PySide6.QtCore import Qt
    from trace_app.ui.main_window import MainWindow
    folder = tmp_path / 'apps'
    folder.mkdir()
    shutil.copyfile(PAGEANT, folder / 'pageant.exe')
    (folder / 'notes.txt').write_text('plain')
    window = MainWindow()
    try:
        assert window.open_evidence_image(str(folder))
        root = window.tree_viewer.topLevelItem(
            window.tree_viewer.topLevelItemCount() - 1)
        window.on_item_clicked(root, 0)
        pump(qapp, 0.5)
        table = window.listing_table
        rows = {table.item(r, 0).text(): table.item(r, 0)
                for r in range(table.rowCount())}
        # The program's own icon is a picture of sizes; file-type icons
        # are drawn from files and list none.
        assert pump(qapp, 10,
                    lambda: bool(rows['pageant.exe'].icon().availableSizes()))
        assert not rows['notes.txt'].icon().availableSizes()
        tree_items = [root.child(i) for i in range(root.childCount())]
        program = next(i for i in tree_items
                       if i.text(0) == 'pageant.exe')
        assert pump(qapp, 10, lambda: bool(program.icon(0).availableSizes()))
        assert window.program_icons._cache        # read once, kept
    finally:
        window.cleanup_resources()

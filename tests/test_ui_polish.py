"""Small things the light-mode screenshot showed: a live disk with no name,
'TRACE 2.4.0 - TRACE', '1 sectors', cut-off volume columns, an empty Text
tab with nothing saying why, and the Utils dock's own title row."""

import pytest

from tests.conftest import close_window, image_path


@pytest.mark.parametrize('path, name', [
    (r'\\.\PhysicalDrive0', 'PhysicalDrive0'),
    ('D:/Evidence/laptop.E01', 'laptop.E01'),
    ('D:/Evidence/Pixel 3 extraction/', 'Pixel 3 extraction'),
    ('', ''),
])
def test_evidence_has_a_name_even_a_live_disk(path, name, monkeypatch):
    """os.path.basename of '\\\\.\\PhysicalDrive0' is '' on Windows."""
    import sys
    from trace_app.core import live_disk
    if path.startswith('\\\\.\\'):
        monkeypatch.setattr(sys, 'platform', 'win32')
    assert live_disk.display_name(path) == name


def test_a_case_names_a_live_disk(tmp_path):
    """This system's own device path (on Linux a Windows one is only a
    relative file name, made absolute by add_evidence)."""
    import sys
    from trace_app.core.case import Case
    device, name = ((r'\\.\PhysicalDrive1', 'PhysicalDrive1')
                    if sys.platform == 'win32' else ('/dev/sdb', 'sdb'))
    case = Case.create(str(tmp_path / 'case'), 'Disk')
    try:
        evidence = case.add_evidence(device)
        row = next(r for r in case.evidence() if r['id'] == evidence)
        assert row['display_name'] == name
    finally:
        case.close()


def test_sector_counts_read_as_english():
    from trace_app.ui.main_window import _sectors
    assert _sectors(0) == '0 sectors'
    assert _sectors(1) == '1 sector'
    assert _sectors(2048) == '2,048 sectors'


@pytest.fixture
def window(qapp):
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    yield window
    close_window(window)


def test_the_title_names_the_case_and_qt_adds_the_version(window, qapp):
    """Qt puts ' - <display name>' after a title: the title alone once
    carried 'TRACE 2.4.0' too and the bar read 'TRACE 2.4.0 - TRACE'."""
    assert window._case_title() == ''

    class _Case:
        name, number = 'Op Archway', 'AXA-1'
    window.case = _Case()
    try:
        assert window._case_title() == 'Op Archway (AXA-1)'
    finally:
        window.case = None


@pytest.mark.parametrize('dock_name, tabs_name', [
    ('viewer_dock', 'viewer_tab'), ('tree_dock', 'tree_tabs')])
def test_utils_and_the_tree_are_headed_by_their_tabs(window, qapp,
                                                     dock_name, tabs_name):
    """No 'Utils' / 'Tree View' strip: the tab row is the header, float and
    close at its end, on the tab bar's colour (no grey band)."""
    from tests.conftest import pump
    dock, tabs = getattr(window, dock_name), getattr(window, tabs_name)
    corner = tabs.cornerWidget()
    assert dock.titleBarWidget() is not None          # Qt's strip hidden
    assert dock.titleBarWidget().objectName() == 'hiddenDockTitle'
    assert corner.objectName() == 'dockHeaderCorner'
    assert len([b for b in corner.children()
                if b.objectName() == 'dockHeaderButton']) == 2
    assert tabs.property('dockHeader') is True
    window.show()
    dock.setFloating(True)
    pump(qapp, 0.2)
    assert dock.titleBarWidget() is None              # movable again
    assert not corner.isVisible()
    dock.setFloating(False)
    pump(qapp, 0.2)
    assert dock.titleBarWidget() is not None
    assert corner.isVisibleTo(window)


@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_nothing_is_drawn_beside_the_tabs(window, qapp, theme):
    """Right of the Utils and tree tabs: one colour to the buttons and to
    the dock's edge. QTabWidget's themed frame drew a faint box there once
    the tab widget painted its own background (its property selector was
    read before the property was set)."""
    from tests.conftest import pump
    window.resize(1400, 900)
    window.apply_stylesheet(theme)
    window.show()
    pump(qapp, 0.3)
    try:
        for tabs in (window.viewer_tab, window.tree_tabs):
            image = tabs.grab().toImage()
            bar = tabs.tabBar().geometry()
            corner = tabs.cornerWidget().geometry()
            ground = image.pixelColor(corner.left() - 2, bar.height() // 2)
            for y in range(0, bar.height() - 2):
                for x in list(range(bar.right() + 3, corner.left())) + \
                        [image.width() - 1]:
                    assert image.pixelColor(x, y) == ground, \
                        (tabs.objectName(), x, y)
    finally:
        window.apply_stylesheet('light')


def test_the_result_panels_tab_row_has_float_and_close(window, qapp):
    """The row of Listing, Search... ends the same way, acting on the
    panel in front."""
    import time
    from tests.conftest import pump
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTabBar, QWidget
    docks = window.result_viewer
    window.resize(1400, 900)
    window.show()
    # The default arrangement, whatever the window opened with: one row.
    docks.arrange()

    def shown():
        rows = [b for b in window.result_area.findChildren(
            QTabBar, options=Qt.FindDirectChildrenOnly) if b.isVisible()]
        corners = [c for c in window.result_area.findChildren(QWidget)
                   if c.objectName() == 'dockHeaderCorner' and c.isVisible()]
        return rows, corners

    deadline = time.monotonic() + 3
    while True:
        pump(qapp, 0.1)
        rows, corners = shown()
        if (rows and len(corners) == len(rows)) or time.monotonic() > deadline:
            break
    assert rows and len(corners) == len(rows), (   # one per tab row
        [(b.count(), b.tabText(b.currentIndex()), b.geometry().getRect())
         for b in rows], [c.geometry().getRect() for c in corners])
    front = docks.dock(docks.currentWidget())
    float_button = next(
        c.children()[1] for c in corners
        if front.windowTitle() in c.children()[1].toolTip())
    float_button.click()
    pump(qapp, 0.3)
    assert front.isFloating()
    front.setFloating(False)
    pump(qapp, 0.3)
    assert not front.isFloating()


def test_an_empty_text_tab_says_why(window):
    from trace_app.ui.viewers.text import NOTHING_SHOWN
    viewer = window.text_viewer
    window.clear_viewers()
    assert viewer.text_edit.placeholderText() == NOTHING_SHOWN
    text = next(a for a in window.viewer_adapters if a.label == 'Text')
    text.show_nothing("This file is empty (0 bytes).")
    assert viewer.text_edit.placeholderText() == \
        "This file is empty (0 bytes)."
    assert viewer.text_edit.toPlainText() == ''
    combo = viewer.encoding_combo
    widest = max(combo.fontMetrics().horizontalAdvance(combo.itemText(i))
                 for i in range(combo.count()))
    assert combo.sizeHint().width() > widest


def test_volume_names_and_sizes_are_not_cut(window, qapp):
    from trace_app.ui.main_window import _sectors
    assert window.open_evidence_image(image_path('10-ntfs-disk.dd'))
    window.display_volumes_in_listing()
    table = window.listing_table
    assert table.rowCount() > 0
    metrics = table.fontMetrics()
    for row in range(table.rowCount()):
        for column in (0, 3):
            item = table.item(row, column)
            if item is None:
                continue
            assert table.columnWidth(column) >= \
                metrics.horizontalAdvance(item.text()), item.text()
        for column in (4, 5, 6):
            item = table.item(row, column)
            if item is not None and item.text().startswith('1 '):
                assert item.text() == _sectors(1)

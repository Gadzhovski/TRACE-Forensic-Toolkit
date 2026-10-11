"""The main window's layout: the Listing fill, the dockable panels and the
Triage sidebar."""

import pytest

from tests.conftest import image_path, pump


def _entries(prefix, count):
    return [{'name': f'{prefix}{number:04d}.txt', 'inode_number': number + 100,
             'is_directory': False, 'size': number, 'type': 'file',
             'created': 'N/A', 'accessed': 'N/A', 'modified': 'N/A',
             'changed': 'N/A', 'is_deleted': False}
            for number in range(count)]


@pytest.fixture
def window(qapp, monkeypatch):
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    window = MainWindow()
    yield window
    window.cleanup_resources()


def test_a_listing_interrupted_by_another_holds_only_the_second(qapp,
                                                                window):
    """A large folder is listed in batches, yielding to the event loop; a
    click on another folder meanwhile used to leave both folders' rows in
    the table."""
    from PySide6.QtCore import QTimer
    # Rows are drawn for an image (its inode labels): any small one.
    assert window.open_evidence_image(image_path('8-jpeg-search.dd'))
    first, second = _entries('first-', 1000), _entries('second-', 30)
    QTimer.singleShot(0, lambda: window.populate_listing_table(second, 0))
    window.populate_listing_table(first, 0)
    pump(qapp, 0.1)
    names = {window.listing_table.item(r, 0).text()
             for r in range(window.listing_table.rowCount())}
    assert names == {e['name'] for e in second}
    # An uninterrupted fill lists every entry.
    window.populate_listing_table(first, 0)
    assert window.listing_table.rowCount() == len(first)

"""Triage's Carved files and Deleted files filtered by type and shown as
icons, and the picture viewer's zoom drawing the image's own pixels.

No evidence is read: carves arrive as session rows, deleted files as rows
stored in a fresh case, and the picture is made here.
"""

import pytest


# --- the type filter's button -------------------------------------------------------

def test_the_options_follow_what_is_shown(qapp):
    from trace_app.ui.widgets.multi_select import MultiSelectButton
    button = MultiSelectButton([], None, noun="types")
    try:
        assert button.text() == "All types" and button.all_selected()
        changes = []
        button.selectionChanged.connect(changes.append)
        button.set_options(['JPG', 'PDF'], labels={'JPG': 'JPG  (2)'})
        assert button.selected() == ['JPG', 'PDF']     # all stays all
        assert changes == []                           # no signal
        button.set_selected(['JPG'])
        # A new type while one is chosen: it stays out.
        button.set_options(['JPG', 'PDF', 'ZIP'])
        assert button.selected() == ['JPG'] and button.text() == 'JPG'
        # Same options, new counts: relabelled, nothing rebuilt.
        menu = button.menu()
        button.set_options(['JPG', 'PDF', 'ZIP'], labels={'JPG': 'JPG  (3)'})
        assert button.menu() is menu
        assert button._actions['JPG'].text() == 'JPG  (3)'
    finally:
        button.deleteLater()


# --- carved files --------------------------------------------------------------------

def _carve(i, kind):
    return {'name': f'{i:08x}.{kind}', 'type': kind, 'status': 'valid',
            'size': 1000 + i, 'offset': i * 4096, 'sha256': f'{i:064x}',
            'evidence_key': 'img', 'path': ''}


def test_carves_are_filtered_by_type(qapp):
    from tests.conftest import pump
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    panel = CarvedFilesPanel()
    try:
        for i, kind in enumerate(['jpg', 'jpg', 'pdf', 'zip', 'jpg']):
            panel.add_record(_carve(i, kind))
        assert pump(qapp, 10, lambda: panel.table.rowCount() == 5)
        assert panel.kind_filter.options() == ['JPG', 'PDF', 'ZIP']
        assert panel.kind_filter._actions['JPG'].text() == 'JPG  (3)'
        panel.kind_filter.set_selected(['JPG'])
        assert panel.table.rowCount() == 3
        assert {panel.table.item(r, 2).text()
                for r in range(panel.table.rowCount())} == {'JPG'}
        assert '3 shown by the filters' in panel.status_label.text()
        assert len(panel.shown_rows()) == 3        # what Export All exports
        # A PDF carved meanwhile is counted but stays out of view.
        panel.add_record(_carve(9, 'pdf'))
        assert pump(qapp, 10, lambda: panel.kind_filter._actions['PDF']
                    .text() == 'PDF  (2)')
        assert panel.table.rowCount() == 3
        panel.kind_filter.set_selected(panel.kind_filter.options())
        assert panel.table.rowCount() == 6
    finally:
        panel.deleteLater()


def test_the_view_menu_is_on_the_filter_row(qapp):
    """At the end of the carve controls the View button went into the
    toolbar's overflow menu in a narrow dock, out of sight."""
    from PySide6.QtWidgets import QToolBar
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    panel = CarvedFilesPanel()
    try:
        filters = panel.findChild(QToolBar, 'carvedFilterBar')
        assert panel.view_button.parent() is filters
        panel.set_view('large', remember=False)
        assert panel.stack.currentWidget() is panel.gallery
    finally:
        panel.deleteLater()


# --- deleted files -------------------------------------------------------------------

@pytest.fixture
def deleted_case(tmp_path):
    from trace_app.core import deleted
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Deleted types')
    image = tmp_path / 'disk.dd'
    image.write_bytes(b'\0' * 4096)
    evidence = case.add_evidence(str(image))

    def row(inode, name, state=deleted.RECOVERABLE, is_dir=False):
        return {'ref': f'p0:i{inode}:s1', 'path': f'/{name}', 'name': name,
                'is_dir': is_dir, 'size': 0 if is_dir else 5000,
                'state': state}
    case.replace_deleted_files(evidence, [
        row(10, 'a.jpg'), row(11, 'b.JPG'), row(12, 'report.pdf'),
        row(13, 'README'), row(14, 'gone.jpg', deleted.OVERWRITTEN),
        row(15, 'old', is_dir=True)])
    yield case, evidence, str(image)
    case.close()


def test_deleted_files_are_filtered_by_type(qapp, deleted_case):
    from PySide6.QtCore import Qt
    from trace_app.ui.viewers import deleted_panel as dp
    case, evidence, image = deleted_case
    panel = dp.DeletedFilesPanel()
    try:
        panel.set_case(case)
        assert panel.table.rowCount() == 5          # files only
        assert set(panel.kind_filter.options()) == {'JPG', 'PDF',
                                                   dp.NO_EXTENSION}
        assert panel.kind_filter._actions['JPG'].text() == 'JPG  (3)'
        panel.kind_filter.set_selected(['JPG'])
        names = {panel.table.item(r, 0).text()
                 for r in range(panel.table.rowCount())}
        assert names == {'a.jpg', 'b.JPG', 'gone.jpg'}
        assert '3 of the types chosen' in panel.status_label.text()
        # Folders shown: a type of their own, out until chosen.
        panel.files_box.setChecked(False)
        assert dp.FOLDER in panel.kind_filter.options()
        assert panel.table.rowCount() == 3
        # Going to a row the type filter hides widens it.
        assert panel.select(evidence, 'p0:i12:s1')
        assert panel.kind_filter.all_selected()
        row = panel.table.item(panel.table.currentRow(), 0).data(Qt.UserRole)
        assert row['evidence_path'] == image
    finally:
        panel.deleteLater()


def test_deleted_files_show_as_icons_with_their_own_pictures_only(
        qapp, deleted_case):
    from PySide6.QtCore import Qt
    from trace_app.ui.widgets import thumbnails as thumbs
    from trace_app.ui.viewers import deleted_panel as dp
    case, _evidence, _image = deleted_case
    panel = dp.DeletedFilesPanel()
    try:
        panel.set_case(case)
        panel.set_view('extra_large', remember=False)
        assert panel.stack.currentWidget() is panel.gallery
        assert panel.view_button.actions['extra_large'].isChecked()
        rows = {panel.table.item(r, 0).text():
                panel.table.item(r, 0).data(Qt.UserRole)
                for r in range(panel.table.rowCount())}
        assert dp.deleted_item(rows['a.jpg'])[1] == thumbs.PICTURE
        assert dp.deleted_item(rows['README'])[1] == thumbs.SNIFF
        # Its clusters are another file's now: no picture as this one's.
        assert dp.deleted_item(rows['gone.jpg']) is None
        panel.content_reader = lambda row: b'read'
        assert panel._read(rows['a.jpg']) == b'read'
        panel.set_view('details', remember=False)
        assert panel.stack.currentWidget() is panel.table
    finally:
        panel.deleteLater()


# --- the picture viewer --------------------------------------------------------------

def _checker_png():
    """A 2x2 picture: red, green / blue, white."""
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QColor, QImage
    image = QImage(2, 2, QImage.Format_RGB32)
    for (x, y), colour in {(0, 0): 'red', (1, 0): 'lime', (0, 1): 'blue',
                           (1, 1): 'white'}.items():
        image.setPixelColor(x, y, QColor(colour))
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, 'PNG')
    return bytes(data)


def test_zoom_draws_the_pixels_as_they_are(qapp):
    """Zooming used to rescale the picture on screen smoothly, each step
    blurring the last: a small carved picture became a smear. Enlarged, each
    pixel is a sharp block now, drawn from the original."""
    from PySide6.QtGui import QColor
    from trace_app.ui.viewers.media.picture import PictureViewer
    viewer = PictureViewer()
    try:
        assert viewer.display(_checker_png()) == ''
        for _ in range(3):
            viewer.zoom_out()
        for _ in range(3):
            viewer.zoom_in()
        assert viewer.canvas.zoom == pytest.approx(1.0)
        viewer.canvas.set_view(zoom=8)
        assert viewer.canvas.size().width() == 16
        assert not viewer.canvas.smoothed()
        shot = viewer.canvas.grab().toImage()
        ratio = shot.devicePixelRatio()
        expected = {(0, 0): 'red', (1, 0): 'lime', (0, 1): 'blue',
                    (1, 1): 'white'}
        for (x, y), colour in expected.items():
            # Every device pixel of a block is the image pixel's colour --
            # no blending at its edges.
            for dx in (0, 7):
                for dy in (0, 7):
                    px = round((x * 8 + dx) * ratio)
                    py = round((y * 8 + dy) * ratio)
                    assert shot.pixelColor(px, py) == QColor(colour), \
                        (x, y, dx, dy)
        viewer.rotate_right()
        assert viewer.canvas.rotation == 90
        viewer.reset()
        assert (viewer.canvas.zoom, viewer.canvas.rotation) == (1.0, 0)
        viewer.canvas.set_view(zoom=0.5)
        assert viewer.canvas.smoothed() == (viewer.canvas.devicePixelRatioF()
                                            * 0.5 < 1)
        assert viewer.zoom_label.text().strip() in ('100%', '50%')
    finally:
        viewer.deleteLater()


# --- icon views stay fast, and show the carves' own pictures -------------------------

def test_a_filter_redraws_an_icon_view_once_not_per_row(qapp):
    """Ticking Named only on 6,311 carves in Large icons froze the window:
    the icon view mirrored hidden rows and looked for thumbnails over every
    row once per inserted row. One pass now, over the rows on screen."""
    from tests.conftest import pump
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    panel = CarvedFilesPanel()
    try:
        panel.resize(900, 600)
        panel.show()
        panel._session = [dict(_carve(i, ('jpg', 'pdf')[i % 2]),
                               origin={'path': f'/f{i}'} if i % 3 else None)
                          for i in range(3000)]
        panel.set_view('thumbnails', remember=False)
        panel.refresh()
        pump(qapp, 0.3)
        passes = []
        original = panel.gallery.sync_hidden
        panel.gallery.sync_hidden = lambda: (passes.append(1), original())
        looked = []
        on_screen = panel.gallery._rows_on_screen
        panel.gallery._rows_on_screen = lambda rect: looked.append(
            len(on_screen(rect))) or on_screen(rect)
        panel.named_box.setChecked(True)
        pump(qapp, 0.3)
        assert panel.table.rowCount() == 2000
        assert len(passes) <= 2, len(passes)
        assert looked and max(looked) < 200      # the screen, not 2,000
    finally:
        panel.deleteLater()


def test_the_thumbnails_view_shows_a_carves_picture(qapp):
    from tests.conftest import pump
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    from trace_app.ui.widgets.listing_views import MODES
    picture = _checker_png()
    panel = CarvedFilesPanel()
    try:
        assert 'thumbnails' in panel.view_button.actions
        assert MODES['thumbnails'][2] >= 128
        panel.content_reader = lambda row: picture
        panel.resize(700, 500)
        panel.show()
        panel._session = [dict(_carve(i, 'png'), size=len(picture))
                          for i in range(3)]
        panel.refresh()
        panel.set_view('thumbnails', remember=False)
        gallery = panel.gallery
        assert pump(qapp, 10, lambda: any(gallery._thumbs.values()))
        index = gallery.model().index(0, 0)
        assert gallery.thumbnail_for(index) is not None
    finally:
        panel.deleteLater()

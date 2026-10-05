"""The real window, offscreen, on a two-device case built from public images.

Every assertion about what is shown is checked against an independent read of
the evidence, so "the viewer showed a file" means "the viewer showed the right
bytes from the right image".
"""

import base64
import hashlib
import io
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.conftest import image_path, pump

pytestmark = [pytest.mark.ui, pytest.mark.images]

FIRST, SECOND = 'ntfs1-gen2.E01', '8-jpeg-search.dd'


# --- the case and the window ---------------------------------------------------

@pytest.fixture(scope='module')
def stubbed_dialogs():
    """A modal dialog would block an offscreen run forever: answer them."""
    from trace_app.ui.dialogs import message
    saved = {n: getattr(message, n) for n in
             ('information', 'warning', 'critical', 'question')}
    for name in ('information', 'warning', 'critical'):
        setattr(message, name, lambda *a, **k: None)
    message.question = lambda *a, **k: True
    yield
    for name, function in saved.items():
        setattr(message, name, function)


@pytest.fixture(scope='module')
def case_folder(tmp_path_factory):
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    folder = str(tmp_path_factory.mktemp('case') / 'Two devices')
    case = Case.create(folder, 'Two devices')
    for name in (FIRST, SECOND):
        path = image_path(name)
        evidence = case.add_evidence(path)
        handler = ImageHandler(path)
        analyse_evidence(handler, case, evidence, MODULES)
        handler.close_resources()
    case.close()
    return folder


@pytest.fixture(scope='module')
def window(qapp, case_folder, stubbed_dialogs):
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    win = MainWindow(case=Case.open(case_folder))
    win.resize(1400, 900)
    pump(qapp, 120, lambda: len(win.evidence_files) == 2)
    pump(qapp, 0.5)
    win.refresh_analysis_views()        # what app.py does once it is shown
    yield win
    win.cleanup_resources()


@pytest.fixture(scope='module')
def truth():
    """Independent handles on each image, to check what the window shows."""
    from trace_app.core.image_handler import ImageHandler
    handlers = {name: ImageHandler(image_path(name)) for name in (FIRST,
                                                                  SECOND)}
    yield handlers
    for handler in handlers.values():
        handler.close_resources()


def _root(window, name):
    from PySide6.QtCore import Qt
    tree = window.tree_viewer
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if (item.data(0, Qt.UserRole) or {}).get('image_path', '') \
                .endswith(name):
            return item
    raise AssertionError(f'no tree root for {name}')


def _first_volume(item):
    """The image root, or its first child that carries a file system."""
    from PySide6.QtCore import Qt
    for i in range(item.childCount()):
        data = item.child(i).data(0, Qt.UserRole) or {}
        if data.get('start_offset') is not None and not data.get(
                'is_unallocated') and item.child(i).childCount():
            return item.child(i)
    return item


def _listed(window):
    return {window.listing_table.item(r, 0).text()
            for r in range(window.listing_table.rowCount())
            if window.listing_table.item(r, 0)} - {'..'}


# --- the shell ------------------------------------------------------------------------

def test_only_the_file_viewers_are_permanent_tabs(window):
    labels = [window.viewer_tab.tabText(i)
              for i in range(window.viewer_tab.count())]
    assert not any('xif' in label or 'Virus' in label for label in labels)


def test_image_roots_are_named_by_file(window):
    root = _root(window, SECOND)
    assert root.text(0) == SECOND
    assert image_path(SECOND) in root.toolTip(0)


# --- every view reads the right image -------------------------------------------------

def test_browsing_each_image_lists_that_images_files(qapp, window, truth):
    from PySide6.QtCore import Qt
    for name in (FIRST, SECOND):
        node = _first_volume(_root(window, name))
        window.on_item_clicked(node, 0)
        pump(qapp, 0.5)
        assert os.path.basename(window.current_image_path) == name
        handler = truth[name]
        offset = (window.listing_table.item(0, 0).data(Qt.UserRole)
                  ['start_offset'] if window.listing_table.rowCount() else 0)
        expected = {e['name'] for e in handler.get_directory_contents(
            offset, handler.get_root_inode(offset))} - {'..'}
        assert _listed(window) == expected, name


def test_a_listing_row_reads_its_own_image_after_another_is_active(
        qapp, window, truth):
    from PySide6.QtCore import Qt
    window.on_item_clicked(_first_volume(_root(window, FIRST)), 0)
    pump(qapp, 0.5)
    rows = [r for r in range(window.listing_table.rowCount())
            if (window.listing_table.item(r, 0).data(Qt.UserRole) or {})
            .get('type') == 'file'
            and window.listing_table.item(r, 0).text().startswith('$')]
    assert rows, 'no system file to read in the listing'
    row = rows[0]

    # Make the other image active, as opening one of its findings does.
    other = next(f for f in window.case.findings()
                 if os.path.basename(_evidence_path(window, f)) == SECOND)
    window.preview_artifact(other)
    pump(qapp, 1.0)
    assert os.path.basename(window.current_image_path) == SECOND

    shown = _capture_viewer(window)
    item = window.listing_table.item(row, 0)
    window.on_listing_table_item_clicked(item, navigate=False)
    pump(qapp, 10, lambda: bool(shown))
    data = item.data(Qt.UserRole)
    expected, _ = truth[FIRST].get_file_content(data['inode_number'],
                                                data['start_offset'])
    assert shown and shown[-1] == expected


def test_a_finding_from_the_other_image_shows_that_images_bytes(
        qapp, window, truth):
    from trace_app.core.case import parse_artifact_ref
    for name in (FIRST, SECOND):
        finding = next(f for f in window.case.findings()
                       if os.path.basename(_evidence_path(window, f)) == name)
        window.current_selected_data = None
        shown = _capture_viewer(window)
        window.preview_artifact(finding)
        pump(qapp, 10, lambda: bool(shown))
        ref = parse_artifact_ref(finding['artifact_ref'])
        expected, _ = truth[name].get_file_content(ref['inode'],
                                                   ref['start_offset'])
        assert shown and shown[-1] == expected, name


def _evidence_path(window, row):
    return next(r['path'] for r in window.case.evidence()
                if r['id'] == row['evidence_id'])


def _capture_viewer(window):
    shown = []
    original = type(window).update_viewer_with_file_content

    def record(content, data, _self=window):
        shown.append(content)
        return original(_self, content, data)
    window.update_viewer_with_file_content = record
    return shown


# --- Triage, the tree, previews --------------------------------------------------------

def test_triage_covers_the_case_and_names_each_image(qapp, window):
    triage = window.triage_panel
    headers = [triage.mismatch_table.horizontalHeaderItem(c).text()
               for c in range(triage.mismatch_table.columnCount())]
    column = headers.index('Evidence')
    names = {triage.mismatch_table.item(r, column).text()
             for r in range(triage.mismatch_table.rowCount())}
    assert names == {FIRST, SECOND}

    filter_box = triage.evidence_filter
    second_id = next(r['id'] for r in window.case.evidence()
                     if r['path'].endswith(SECOND))
    filter_box.setCurrentIndex(filter_box.findData(second_id))
    pump(qapp, 0.3)
    narrowed = {triage.mismatch_table.item(r, column).text()
                for r in range(triage.mismatch_table.rowCount())}
    assert narrowed == {SECOND}
    filter_box.setCurrentIndex(0)
    pump(qapp, 0.3)


def test_tree_findings_are_split_by_image(window):
    from PySide6.QtCore import Qt
    window.refresh_analysis_tree()
    tree = window.tree_viewer
    root = next(tree.topLevelItem(i) for i in range(tree.topLevelItemCount())
                if (tree.topLevelItem(i).data(0, Qt.UserRole) or {})
                .get('is_analysis_root'))
    mismatches = next(root.child(i) for i in range(root.childCount())
                      if root.child(i).text(0).startswith('Type mismatches'))
    images = [mismatches.child(i).text(0).split(' (')[0]
              for i in range(mismatches.childCount())
              if (mismatches.child(i).data(0, Qt.UserRole) or {})
              .get('is_image_group')]
    assert sorted(images) == sorted([FIRST, SECOND])


def test_clicking_a_finding_previews_without_leaving_triage(qapp, window):
    from PySide6.QtCore import Qt
    triage = window.triage_panel
    window.result_viewer.setCurrentWidget(triage)
    triage.show_group('mismatch')
    shown = _capture_viewer(window)
    window.current_selected_data = None
    triage.mismatch_table.selectRow(0)
    pump(qapp, 10, lambda: bool(shown))
    assert shown
    assert window.result_viewer.currentWidget() is triage
    item = triage.mismatch_table.item(0, 0)
    triage.mismatch_table.itemDoubleClicked.emit(item)
    pump(qapp, 1.0)
    assert window.result_viewer.currentIndex() == window.LISTING_TAB
    assert item.data(Qt.UserRole)['name'] in _listed(window)


def test_theme_switch_keeps_icons_visible(qapp, window):
    from trace_app.ui import icons
    from PySide6.QtCore import QRect
    from PySide6.QtGui import QColor, QImage, QPainter
    colours = {}
    for theme in ('light', 'dark'):
        window.apply_stylesheet(theme)
        pump(qapp, 0.2)
        image = QImage(24, 24, QImage.Format_ARGB32)
        image.fill(QColor(0, 0, 0, 0))
        painter = QPainter(image)
        icons.icon(icons.BOOKMARK).paint(painter, QRect(0, 0, 24, 24))
        painter.end()
        pixels = [image.pixelColor(x, y) for x in range(24) for y in range(24)
                  if image.pixelColor(x, y).alpha() > 128]
        colours[theme] = sum(p.lightness() for p in pixels) / len(pixels)
    window.apply_stylesheet('light')
    # Light theme: dark glyph; dark theme: light glyph.
    assert colours['light'] < 100 < colours['dark']


# --- the Application tab --------------------------------------------------------------------

@pytest.fixture
def viewer(qapp):
    from trace_app.ui.viewers.media import UnifiedViewer
    unified = UnifiedViewer()
    unified.resize(800, 600)
    unified.show()
    yield unified
    unified.close()


def _shown(viewer):
    for name, widget in (('picture', viewer._picture_viewer),
                         ('document', viewer._pdf_viewer),
                         ('html', viewer._html_viewer)):
        if widget is not None and widget.isVisible():
            return name
    return 'placeholder'


@pytest.mark.parametrize('fmt,name', [('PNG', 'photo.png'),
                                      ('WEBP', 'photo.webp'),
                                      ('TIFF', 'photo.tif'),
                                      ('AVIF', 'photo.avif'),
                                      ('JPEG2000', 'photo.jp2')])
def test_images_display(qapp, viewer, fmt, name):
    from PIL import Image
    buffer = io.BytesIO()
    Image.new('RGB', (64, 48), (200, 40, 40)).save(buffer, fmt)
    viewer.display_application_content(buffer.getvalue(), name)
    pump(qapp, 0.1)
    assert _shown(viewer) == 'picture'


@pytest.mark.parametrize('content,says', [
    (b'\0' * 8192, 'all zero bytes'),
    (bytes(range(256)) * 32, 'no PDF header'),
], ids=['zeros', 'other-data'])
def test_a_pdf_name_over_other_bytes_is_not_opened(qapp, viewer, caplog,
                                                   content, says):
    """A deleted .pdf whose clusters now hold zeros or other data: said
    plainly, and nothing logged as an error (it used to log two ERRORs
    from the PDF reader per click)."""
    import logging
    with caplog.at_level(logging.INFO):
        viewer.display_application_content(content, 'invoice.pdf')
    pump(qapp, 0.1)
    assert _shown(viewer) == 'placeholder'
    assert says in viewer.placeholder.text()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert viewer._pdf_viewer is None or viewer._pdf_viewer.pdf is None


def test_a_pdf_with_bytes_before_its_header_still_opens(qapp, viewer):
    """Acrobat's rule: '%PDF-' anywhere in the first 1,024 bytes."""
    import pymupdf
    document = pymupdf.open()
    document.new_page()
    data = b'\0' * 300 + document.tobytes()
    viewer.display_application_content(data, 'carved.pdf')
    pump(qapp, 0.1)
    assert _shown(viewer) == 'document'


def test_menus_toolbar_and_views_are_consistent(qapp):
    """Every menu command has an icon (checkable entries have Qt's tick
    instead); the toolbar's buttons are the menus' own actions; and every
    table, tree and list scrolls by pixels, tables filling their width."""
    from PySide6.QtWidgets import (QAbstractItemView, QHeaderView,
                                   QTableView)
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        missing = [f"{menu.text()} > {action.text()}"
                   for menu in window.menuBar().actions()
                   for action in menu.menu().actions()
                   if not action.isSeparator() and not action.isCheckable()
                   and action.icon().isNull()]
        assert not missing, missing
        toolbar = [a for a in window.main_toolbar.actions()
                   if not a.isSeparator()]
        assert len(toolbar) == 8
        assert window.run_analysis_action in toolbar
        assert all(not a.icon().isNull() for a in toolbar)
        views = [v for v in window.findChildren(QAbstractItemView)
                 if not isinstance(v, QHeaderView)]
        assert len(views) > 20
        for view in views:
            view.ensurePolished()
            assert view.horizontalScrollMode() == \
                QAbstractItemView.ScrollPerPixel, view.objectName()
            if isinstance(view, QTableView):
                assert view.horizontalHeader().stretchLastSection(), \
                    view.objectName()
    finally:
        window.cleanup_resources()


def test_listing_views_share_the_table(qapp, monkeypatch):
    """Details, List and the icon views are one model and one selection:
    each mode shows in the stack, a click in an icon view goes through the
    listing's own handler, hidden rows stay hidden, and the choice is
    remembered."""
    from PySide6.QtWidgets import QTableWidgetItem
    from PySide6.QtCore import Qt
    from trace_app.infra import window_state
    from trace_app.ui.main_window import MainWindow
    from trace_app.ui.widgets.listing_views import ORDER
    saved = []
    monkeypatch.setattr(window_state, 'save_listing_view', saved.append)
    window = MainWindow()
    try:
        table = window.listing_table
        table.setRowCount(3)
        for row, name in enumerate(('a.jpg', 'b.txt', 'c.png')):
            item = QTableWidgetItem(name)
            item.setData(Qt.UserRole, {'type': 'file', 'name': name,
                                       'inode_number': row,
                                       'start_offset': 0, 'size': 10})
            table.setItem(row, 0, item)
        view = window.listing_icon_view
        assert view.model() is table.model()
        assert view.selectionModel() is table.selectionModel()
        for mode in ORDER:
            window.set_listing_view(mode)
            assert window._listing_view_actions[mode].isChecked()
            assert window.listing_stack.currentWidget() is (
                table if mode == 'details' else view)
        assert saved == list(ORDER)
        window.set_listing_view('large', remember=False)
        clicked = []
        monkeypatch.setattr(window, 'on_listing_table_item_clicked',
                            lambda item, navigate=True:
                            clicked.append((item.text(), navigate)))
        index = table.model().index(2, 0)
        view.clicked.emit(index)
        view.doubleClicked.emit(index)
        assert clicked == [('c.png', False), ('c.png', True)]
        table.setRowHidden(1, True)
        view.sync_hidden()
        assert view.isRowHidden(1) and not view.isRowHidden(0)
    finally:
        window.cleanup_resources()


def test_icon_views_draw_pictures_as_thumbnails(qapp):
    import io
    from PIL import Image
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
    from trace_app.ui.widgets.listing_views import (ListingIconView,
                                                    thumbnail)
    pictures = {}
    for name, size in (('wide.png', (400, 200)), ('tall.jpg', (100, 300))):
        buffer = io.BytesIO()
        Image.new('RGB', size, (200, 40, 40)).save(
            buffer, 'PNG' if name.endswith('png') else 'JPEG')
        pictures[name] = buffer.getvalue()
    # Scaled to fit, never cropped.
    wide = thumbnail(pictures['wide.png'], 96)
    assert (wide.width(), wide.height()) == (96, 48)
    tall = thumbnail(pictures['tall.jpg'], 96)
    assert (tall.width(), tall.height()) == (32, 96)
    assert thumbnail(b'not a picture', 96).isNull()
    from trace_app.ui.widgets.listing_views import size_in_bytes
    # Rows carry the size as the Size column shows it.
    assert size_in_bytes('8.25 KB') == 8448
    assert size_in_bytes(4096) == 4096 and size_in_bytes('?') is None
    table = QTableWidget(4, 1)
    for row, (name, size) in enumerate((
            ('wide.png', '8.25 KB'), ('tall.jpg', 300),
            ('notes.txt', '1.00 KB'), ('huge.jpg', '2.00 GB'))):
        item = QTableWidgetItem(name)
        item.setData(Qt.UserRole, {'type': 'file', 'name': name,
                                   'inode_number': row, 'start_offset': 0,
                                   'size': size})
        table.setItem(row, 0, item)
    read = []
    view = ListingIconView(table, lambda d: read.append(d['name'])
                           or pictures.get(d['name']))
    view.resize(600, 300)
    view.set_mode('large')
    view.show()
    pump(qapp, 2, lambda: len(view._thumbs) == 2)
    assert sorted(read) == ['tall.jpg', 'wide.png']   # pictures only
    assert view.thumbnail_for(table.model().index(0, 0)) is not None
    assert view.thumbnail_for(table.model().index(2, 0)) is None
    view.set_mode('list')                     # small icons: file-type icons
    assert view.thumbnail_for(table.model().index(0, 0)) is None
    view.close()


def test_monospace_is_an_outline_font(qapp):
    """Not "Courier": a bitmap font on Windows, which DirectWrite cannot
    draw (the "8514oem ... CreateFontFaceFromHDC() failed" warning)."""
    from PySide6.QtGui import QFontInfo
    from trace_app.ui import fonts
    font = fonts.monospace(10)
    assert 'Courier' not in font.families()
    assert font.fixedPitch()
    assert font.styleHint() == font.StyleHint.Monospace
    # Where the platform has fonts (not offscreen), one is really used.
    if QFontInfo(font).family() in fonts.MONOSPACE:
        assert QFontInfo(font).fixedPitch()


def test_qt_messages_reach_the_log(qapp, caplog):
    import logging
    from PySide6.QtCore import qInstallMessageHandler, qWarning
    from trace_app.app import route_qt_messages
    route_qt_messages()
    try:
        with caplog.at_level(logging.DEBUG, logger='TRACE.Qt'):
            qWarning("a test warning from Qt")
        assert any(r.name == 'TRACE.Qt' and r.levelno == logging.WARNING
                   and 'a test warning from Qt' in r.getMessage()
                   for r in caplog.records)
    finally:
        qInstallMessageHandler(None)


def test_a_disguised_file_is_shown_as_what_it_is(qapp, viewer):
    from PIL import Image
    buffer = io.BytesIO()
    Image.new('RGB', (8, 8)).save(buffer, 'PNG')
    viewer.display_application_content(buffer.getvalue(), 'step2.txt')
    pump(qapp, 0.1)
    assert _shown(viewer) == 'picture'
    assert '.txt' in viewer.notice.text()


def test_html_is_rendered_offline(qapp, viewer):
    hits = []

    class Recorder(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    from PIL import Image
    pixel = io.BytesIO()
    Image.new('RGB', (4, 4)).save(pixel, 'PNG')
    page = (f'<html><head><script>document.write("RAN")</script></head><body>'
            f'<p>Report</p><img src="http://127.0.0.1:{port}/pixel.gif">'
            f'<img src="file:///C:/Windows/win.ini"><img src="secret.png">'
            f'<img src="data:image/png;base64,'
            f'{base64.b64encode(pixel.getvalue()).decode()}">'
            f'</body></html>').encode()
    try:
        viewer.display_application_content(page, 'page.html')
        pump(qapp, 1.0)
        browser = viewer._html_viewer.browser
        assert _shown(viewer) == 'html'
        assert 'RAN' not in browser.toPlainText()
        assert hits == [], hits
        assert len(browser.blocked) == 3
        assert not any(b.startswith('data:') for b in browser.blocked)
    finally:
        server.shutdown()
        server.server_close()


def test_word_tracked_changes_are_shown(qapp, viewer):
    from tests.test_core import docx_with_tracked_changes
    viewer.display_application_content(docx_with_tracked_changes(),
                                       'notes.docx')
    pump(qapp, 0.2)
    text = viewer._html_viewer.browser.toPlainText()
    assert _shown(viewer) == 'html'
    assert 'account 4471' in text and 'Boss' in text
    assert 'Tracked changes' in viewer._html_viewer.notice.text()


# --- VirusTotal, network faked ---------------------------------------------------------------

def test_virustotal_lookup_and_upload_are_recorded_and_audited(
        qapp, window, monkeypatch):
    from trace_app.core import virustotal as vt

    class Response:
        def __init__(self, status, payload):
            self.status_code, self._payload = status, payload

        def json(self):
            return self._payload

    seen = []

    class Session:
        def request(self, method, url, **kwargs):
            seen.append((method, url, kwargs.get('files')))
            if method == 'POST':
                return Response(200, {'data': {'id': 'AN1'}})
            if '/analyses/' in url:
                return Response(200, {'data': {'attributes': {
                    'status': 'completed'}}})
            digest = url.rsplit('/', 1)[-1]
            return Response(200, {'data': {'attributes': {
                'sha256': digest, 'last_analysis_stats': {
                    'malicious': 1, 'undetected': 70}}}})

    # The client imports requests when it first needs it, so the library
    # itself is patched.
    import requests
    monkeypatch.setattr(requests, 'Session', Session)
    monkeypatch.setattr(vt, 'POLL_INTERVAL', 0.05)
    vt._limiters['test-key'] = vt.RateLimiter(per_minute=10000,
                                              per_day=100000)
    if not window.api_keys.has_section('API_KEYS'):
        window.api_keys.add_section('API_KEYS')
    window.api_keys.set('API_KEYS', 'virustotal', 'test-key')

    finding = next(f for f in window.case.findings() if f['module']
                   in ('authors', 'photo', 'hidden'))
    window.activate_evidence(finding['evidence_id'])
    target = window._vt_target_from_entry(finding)
    before = len(window.case.vt_results())
    window.vt_submit([target], 'hash')
    assert window.viewer_tab.currentWidget() is window.vt_panel
    pump(qapp, 30, lambda: window.vt_worker is None)
    window.vt_submit([window._vt_target_from_entry(finding)], 'upload')
    pump(qapp, 30, lambda: window.vt_worker is None)

    rows = window.case.vt_results()
    assert len(rows) == before + 2
    assert {r['method'] for r in rows[:2]} == {'hash', 'upload'}
    uploaded = next(files for method, _, files in seen if method == 'POST')
    assert not uploaded['file'][1].startswith(b'PK\x03\x04')    # not a ZIP
    assert hashlib.sha256(uploaded['file'][1]).hexdigest() == rows[0]['sha256']
    actions = [a['action'] for a in window.case.activity(20)]
    assert 'hash sent to VirusTotal' in actions
    assert 'file uploaded to VirusTotal' in actions

    window.hide_vt_panel()
    assert window.viewer_tab.indexOf(window.vt_panel) == -1
    window.show_vt_panel()
    assert window.viewer_tab.indexOf(window.vt_panel) != -1


# --- carving in Triage, and Findings in the tree ----------------------------------

def _findings_group(window, prefix):
    from PySide6.QtCore import Qt
    for i in range(window.tree_viewer.topLevelItemCount()):
        root = window.tree_viewer.topLevelItem(i)
        if (root.data(0, Qt.UserRole) or {}).get('is_analysis_root'):
            for j in range(root.childCount()):
                if root.child(j).text(0).startswith(prefix):
                    return root.child(j)
    return None


def _leaves(item):
    from PySide6.QtCore import Qt
    if (item.data(0, Qt.UserRole) or {}).get('is_finding'):
        return [item]
    return [leaf for i in range(item.childCount())
            for leaf in _leaves(item.child(i))]


def test_photos_and_authors_are_findings_in_the_tree(qapp, window):
    """Every photo with metadata (located ones marked) and every document's
    author are under Findings, not only in their Triage sub-tabs."""
    import json
    from trace_app.core.case import make_artifact_ref
    evidence = window.case.evidence()[0]['id']
    window.case._db.execute(
        "INSERT INTO file_findings (evidence_id, artifact_ref, name, path, "
        "size, module, kind, grade, summary, detail, analysed_utc) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (evidence, make_artifact_ref(0, 99999, 1), 'holiday.jpg',
         '/holiday.jpg', 1000, 'photo', 'exif', 'info', 'Canon, with GPS',
         json.dumps({'latitude': 42.69, 'longitude': 23.32}),
         '2026-10-02T00:00:00'))
    window.case._db.commit()
    window.refresh_analysis_views()

    photos = _findings_group(window, 'Photos')
    authors = _findings_group(window, 'Document authors')
    assert photos is not None and photos.text(0) == 'Photos (1)'
    assert 'with location' in _leaves(photos)[0].text(0)
    assert authors is not None
    assert len(_leaves(authors)) == window.case.analysis_summary()['authors']
    window.case._db.execute("DELETE FROM file_findings WHERE name = ?",
                            ('holiday.jpg',))
    window.case._db.commit()


def test_carving_is_a_triage_tab_with_its_findings(qapp, window, truth):
    """Carving replaces the Deleted Files tab: a Triage sub-tab whose files
    are case records, listed under Findings, previewed from the image."""
    from PySide6.QtCore import Qt
    tabs = [window.result_viewer.tabText(i)
            for i in range(window.result_viewer.count())]
    assert 'Deleted Files' not in tabs

    evidence = next(r for r in window.case.evidence()
                    if r['path'].endswith(SECOND))
    window.start_carving([evidence['id']], ['jpg'], False)
    assert pump(qapp, 120, lambda: not window.job_bar.busy)
    pump(qapp, 0.5)

    rows = window.case.carved_files(evidence['id'])
    assert rows, "the whole-image carve found no JPEG"
    assert window.carved_panel.count == len(rows)
    tab = window.triage_panel._tab_for['carved']
    assert window.triage_panel.tabs.tabText(tab) == f"Carved files ({len(rows)})"

    group = _findings_group(window, 'Carved files')
    assert group is not None and group.text(0) == f"Carved files ({len(rows)})"
    finding = _leaves(group)[0].data(0, Qt.UserRole)['finding']
    window.preview_artifact(finding)
    pump(qapp, 0.5)
    shown = window.current_selected_data or {}
    assert shown.get('is_carved')
    assert shown['file_content'] == truth[SECOND].read(finding['offset'],
                                                       finding['size'])


def test_quick_triage_carving_keeps_nothing_in_a_case(qapp, stubbed_dialogs,
                                                      tmp_path):
    """Without a case, carving still works -- for the session, as
    references into the image, like a case's."""
    from trace_app.core.carving import CARVABLE_TYPES
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path('11-carve-fat.dd'))
        window.start_carving(None, [t.lower() for t in CARVABLE_TYPES], True)
        assert pump(qapp, 120, lambda: not window.job_bar.busy
                    and window.carved_panel.count)
        pump(qapp, 0.5)
        assert window.case is None
        assert window.carved_panel.count == 16
        row = window.carved_panel._rows[0]
        assert row['path'] == ''
        assert window._carved_bytes(row) == window.image_handler.read(
            row['offset'], row['size'])
        window.preview_carved(row)
        pump(qapp, 0.5)
        assert (window.current_selected_data or {}).get('is_carved')

        # Thumbnails come from the image too: there is no copy to read.
        from trace_app.ui.viewers.carved_panel import _thumbnail
        picture = next(r for r in window.carved_panel._rows
                       if r['type'] == 'jpg' and r['status'] != 'partial')
        assert not _thumbnail(window._carved_bytes(picture), 'jpg').isNull()

        # Export: copies read from the image, each matching its hash.
        rows = window.carved_panel._rows[:3]
        out = tmp_path / 'export'
        worker = window.export_carved_rows(rows, folder=str(out))
        assert pump(qapp, 60, lambda: worker.isFinished())
        pump(qapp, 0.3)
        written = sorted(p.name for p in out.iterdir())
        assert written == sorted([r['name'] for r in rows] + ['manifest.csv'])
        manifest = (out / 'manifest.csv').read_text(encoding='utf-8')
        assert manifest.count(',yes') == 3
    finally:
        window.cleanup_resources()


def test_carving_an_image_added_to_a_case_carves_only_that_image(
        qapp, stubbed_dialogs, tmp_path):
    """Adding an image to a case, filtering Triage to it and pressing Start
    Carving carves that image and no other. The new image was missing from
    Triage's filter, and the Carve selector ignored the filter, so the carve
    ran on every image in the case."""
    import trace_app.ui.main_window as main_window
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow

    folder = str(tmp_path / 'Added image')
    case = Case.create(folder, 'Added image')
    case.add_evidence(image_path(FIRST))
    case.add_evidence(image_path(SECOND))
    case.close()

    window = MainWindow(case=Case.open(folder))
    try:
        pump(qapp, 120, lambda: len(window.evidence_files) == 2)
        new = image_path('11-carve-fat.dd')
        assert window.open_evidence_image(new)
        new_id = window.evidence_id_for_path(new)

        window.triage_panel.set_evidence_filter(new_id)
        assert window.triage_panel.evidence_id == new_id
        assert window.carved_panel.target_combo.currentData() == new_id

        window.carved_panel._request()
        assert pump(qapp, 120, lambda: not window.job_bar.busy)
        pump(qapp, 0.5)
        assert window.case.carving_state(new_id)['status'] == 'done'
        others = [r['id'] for r in window.case.evidence() if r['id'] != new_id]
        assert all(window.case.carving_state(e) is None for e in others)
        assert {r['evidence_id'] for r in window.case.carved_files()} == {new_id}

        # Run Analysis from Triage starts the dialog on the same image.
        seen = {}

        def fake_choose(parent, preselected=None, evidence=None):
            seen['evidence_ids'] = preselected['evidence_ids']
            return None
        saved = main_window.choose_modules
        main_window.choose_modules = fake_choose
        try:
            window.triage_panel.run_requested.emit()
        finally:
            main_window.choose_modules = saved
        assert seen['evidence_ids'] == [new_id]
    finally:
        window.cleanup_resources()


def test_a_carved_archive_is_browsed_like_a_folder(qapp, stubbed_dialogs):
    """Double-clicking a carved ZIP lists its members in the Listing, read
    in memory from the image; a member opens in the viewers; Up returns to
    the Carved files tab."""
    from trace_app.core import archives
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path('11-carve-fat.dd'))
        window.start_carving(None, ['zip'], True)
        assert pump(qapp, 120, lambda: not window.job_bar.busy
                    and window.carved_panel.count)
        row = next(r for r in window.carved_panel._rows if r['type'] == 'zip')

        window.open_carved(row)
        assert window.result_viewer.currentIndex() == window.LISTING_TAB
        content = window.image_handler.read(row['offset'], row['size'])
        members = [m['name'] for m in archives.list_members(content)
                   if not m['is_dir']]
        assert members and members[0] in _listed(window)
        assert window.archive_trail().endswith(row['name'])

        window.open_archive_member_row({'archive_member': members[0],
                                        'name': members[0]})
        shown = window.current_selected_data or {}
        assert shown['size'] == len(archives.read_member(content, members[0]))

        window.navigate_up_directory()
        assert not window._archive_stack
        assert window.result_viewer.currentWidget() is window.triage_panel
        assert window.triage_panel.tabs.currentWidget() is window.carved_panel
    finally:
        window.cleanup_resources()


# --- indexing and indicators ----------------------------------------------------

def test_indexing_is_a_job_and_its_indicators_are_triage_and_tree(
        qapp, window, truth):
    """Indexing runs from the analysis modules on the shared queue, for
    every image; what it extracts is listed in Triage > Indicators and
    under Findings, by kind; a file holding a value previews from its own
    image. The Search tab no longer builds anything."""
    from PySide6.QtCore import Qt
    from trace_app.core.case import parse_artifact_ref
    assert not hasattr(window.search_panel, 'index_button')

    assert window.queue_indexing(window.case.evidence()) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    panel = window.indicators_panel
    # The tab reads the index on threads of its own; wait for them.
    assert pump(qapp, 30, lambda: not panel.loading)

    index = panel.index
    by_image = {r['id']: index.indicator_summary(r['id'])
                for r in window.case.evidence()}
    assert all(by_image.values()), by_image     # both images have some
    total = sum(index.indicator_summary().values())
    tab = window.triage_panel._tab_for['indicators']
    assert window.triage_panel.tabs.tabText(tab) == f"Indicators ({total:,})"
    assert 'indexed' in window.search_panel.summary_label.text()

    # The tree: one group, one child per kind, the case's counts.
    group = _findings_group(window, 'Indicators')
    assert group is not None and group.text(0) == f"Indicators ({total:,})"
    kinds = {group.child(i).data(0, Qt.UserRole)['indicator_kind']:
             group.child(i).text(0) for i in range(group.childCount())}
    assert set(kinds) == set(index.indicator_summary())

    # Clicking a kind opens Triage on it.
    url_node = next(group.child(i) for i in range(group.childCount())
                    if group.child(i).data(0, Qt.UserRole)
                    ['indicator_kind'] == 'url')
    window.tree_viewer.setCurrentItem(url_node)
    window.tree_viewer.itemClicked.emit(url_node, 0)
    pump(qapp, 0.2)
    assert pump(qapp, 30, lambda: not panel.loading)
    assert window.result_viewer.currentWidget() is window.triage_panel
    assert window.triage_panel.tabs.currentWidget() is panel
    assert panel.kind == 'url'
    assert {panel.values_table.item(r, 1).text()
            for r in range(panel.values_table.rowCount())} == {'URL'}

    # Triage's image filter narrows the values to that image's.
    second = next(r['id'] for r in window.case.evidence()
                  if r['path'].endswith(SECOND))
    panel.set_kind('ip')
    window.triage_panel.set_evidence_filter(second)
    assert pump(qapp, 30, lambda: not panel.loading)
    shown = {panel.values_table.item(r, 0).text()
             for r in range(panel.values_table.rowCount())}
    assert shown == {r['value'] for r in index.indicators('ip', second)}

    # A value's files are that image's, and preview from that image.
    panel.values_table.selectRow(0)
    assert pump(qapp, 30, lambda: not panel.loading
                and panel.files_table.rowCount())
    position = next(r for r in range(panel.files_table.rowCount())
                    if panel.files_table.item(r, 0).data(Qt.UserRole)
                    ['kind'] == 'file')
    row = panel.files_table.item(position, 0).data(Qt.UserRole)
    assert row['evidence_id'] == second
    captured = _capture_viewer(window)
    window.current_selected_data = None
    panel.files_table.clearSelection()
    panel.files_table.selectRow(position)
    pump(qapp, 10, lambda: bool(captured))
    ref = parse_artifact_ref(row['artifact_ref'])
    expected, _ = truth[SECOND].get_file_content(ref['inode'],
                                                 ref['start_offset'])
    assert captured and captured[-1] == expected
    assert window.result_viewer.currentWidget() is window.triage_panel
    window.triage_panel.set_evidence_filter(None)
    panel.set_kind(None)
    assert pump(qapp, 30, lambda: not panel.loading)


def test_the_window_stays_responsive_while_a_job_runs(qapp, window):
    """Jobs run in a child process: while one works, the window's event
    loop keeps turning as when idle. Measured before the change, indexing
    stalled it for 15 s at a time; the threshold here is generous for slow
    CI runners, and still catches a job back on the UI's interpreter."""
    import time
    from PySide6.QtCore import QTimer
    from trace_app.core.analysis import MODULES
    gaps, last = [], [time.perf_counter()]

    def tick():
        now = time.perf_counter()
        gaps.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.timeout.connect(tick)
    timer.start(10)
    try:
        rows = window.case.evidence()
        window.queue_analysis(rows, MODULES)
        window.queue_indexing(rows)
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
    finally:
        timer.stop()
    assert len(gaps) > 50
    assert max(gaps) < 1.5, f"the window stalled for {max(gaps):.2f} s"


# --- Windows activity --------------------------------------------------------------

def test_activity_is_a_job_a_tab_and_a_tree_node(qapp, window, truth):
    """Reading activity runs on the shared queue for every image. The two
    public images hold no Windows install, so it records nothing -- and says
    so. Records pointing at real files are then listed per category, under
    Activity in the tree, filtered by image, and a row previews the file it
    was read from, from that file's own image."""
    import datetime
    from PySide6.QtCore import Qt
    from trace_app.core.activity import record
    from trace_app.core.case import parse_artifact_ref
    panel = window.activity_panel
    rows = window.case.evidence()
    assert window.queue_activity(rows) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    for row in rows:
        assert window.case.user_activity_state(row['id'])['status'] == 'done'
    assert pump(qapp, 30, lambda: not panel.loading)
    assert window.case.user_activity_summary() == {}
    assert 'Nothing read yet' in panel.status_label.text()

    # A file from each image stands in for the artifact a record came from.
    sources = {}
    for name in (FIRST, SECOND):
        finding = next(f for f in window.case.findings()
                       if _evidence_path(window, f).endswith(name))
        sources[name] = finding
    when = datetime.datetime(2024, 5, 1, 9, 30, tzinfo=datetime.timezone.utc)
    first = sources[FIRST]
    second = sources[SECOND]
    window.case.add_user_activity(first['evidence_id'], [
        record('programs', 'Prefetch', when, 'Program run',
               r'\WINDOWS\NOTEPAD.EXE', {'run count': 3},
               path=first['path'], ref=first['artifact_ref']),
        record('files', 'Shortcut (Recent)', when, 'File opened (last)',
               r'C:\Users\ann\secret.docx', user='ann',
               path=first['path'], ref=first['artifact_ref'])])
    window.case.add_user_activity(second['evidence_id'], [
        record('browser', 'Firefox', when + datetime.timedelta(hours=1),
               'Visited (typed)', 'https://example.org/', user='bob',
               path=second['path'], ref=second['artifact_ref'])])
    window.case.commit()
    window.refresh_analysis_views()
    assert pump(qapp, 30, lambda: not panel.loading)

    # The tree: Activity, a child per category.
    tree = window.tree_viewer
    root = next(tree.topLevelItem(i) for i in range(tree.topLevelItemCount())
                if (tree.topLevelItem(i).data(0, Qt.UserRole) or {})
                .get('is_activity_root'))
    assert root.text(0) == 'Activity (3)'
    children = {root.child(i).data(0, Qt.UserRole)['category']:
                root.child(i).text(0) for i in range(root.childCount())}
    assert children == {'programs': 'Programs run (1)',
                        'files': 'Files and folders (1)',
                        'browser': 'Web history (1)'}

    # A category node opens the tab on it.
    node = next(root.child(i) for i in range(root.childCount())
                if root.child(i).data(0, Qt.UserRole)['category'] == 'files')
    tree.itemClicked.emit(node, 0)
    assert pump(qapp, 30, lambda: not panel.loading
                and panel.model.rowCount() == 1)
    assert window.result_viewer.currentWidget() is panel
    assert panel.model.rows[0]['subject'] == r'C:\Users\ann\secret.docx'

    # All, newest first; then one image only.
    panel.show_category(None)
    assert pump(qapp, 30, lambda: not panel.loading
                and panel.model.rowCount() == 3)
    panel.set_evidence_filter(second['evidence_id'])
    assert pump(qapp, 30, lambda: not panel.loading
                and panel.model.rowCount() == 1)
    assert panel.model.rows[0]['user'] == 'bob'
    panel.set_evidence_filter(None)
    assert pump(qapp, 30, lambda: not panel.loading
                and panel.model.rowCount() == 3)

    # A row previews its source file, read from that file's own image.
    for name in (FIRST, SECOND):
        source = sources[name]
        position = next(r for r in range(panel.proxy.rowCount())
                        if panel.proxy.data(panel.proxy.index(r, 0),
                                            Qt.UserRole)['evidence_id']
                        == source['evidence_id'])
        captured = _capture_viewer(window)
        window.current_selected_data = None
        panel.table.clearSelection()
        panel.table.selectRow(position)
        assert pump(qapp, 10, lambda: bool(captured))
        ref = parse_artifact_ref(source['artifact_ref'])
        expected, _ = truth[name].get_file_content(ref['inode'],
                                                   ref['start_offset'])
        assert captured[-1] == expected, name
    assert window.result_viewer.currentWidget() is panel

    # Clean up for the tests after this one.
    for row in rows:
        window.case.clear_user_activity(row['id'])
    window.refresh_analysis_views()
    assert pump(qapp, 30, lambda: not panel.loading)


# --- volumes inside volumes ----------------------------------------------------------

def _artifact_sample(name):
    from tests.conftest import ROOT
    path = os.path.join(ROOT, 'test_images', 'artifact_samples', name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing: run tools/fetch_artifact_samples.py")
        pytest.skip(f"{name} missing")
    return path


def _children(item):
    from PySide6.QtCore import Qt
    return [(item.child(i).text(0), item.child(i).data(0, Qt.UserRole) or {})
            for i in range(item.childCount())]


def test_bitlocker_and_shadow_copies_in_the_tree(qapp, stubbed_dialogs,
                                                 monkeypatch):
    """A BitLocker volume shows locked, unlocks through the dialog with its
    password and then lists its files; a volume's shadow copies are nodes
    whose files preview from that snapshot."""
    from PySide6.QtCore import Qt
    from trace_app.core.containers import shadow_key
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.dialogs import bitlocker
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        bde = _artifact_sample('bdetogo.raw')
        assert window.open_evidence_image(bde)
        root = _root(window, 'bdetogo.raw')
        [(text, data)] = _children(root)
        assert data.get('is_bitlocker') and 'locked' in text
        assert window.describe_selection(data).endswith(
            'right-click ▸ Unlock BitLocker…')

        # The dialog, driven as an examiner would: wrong key, then right.
        def fake_exec(dialog):
            dialog.tabs.setCurrentIndex(1)
            dialog.password.setText('wrong')
            dialog._try()
            assert not dialog.error.isHidden()
            assert 'does not unlock' in dialog.error.text()
            dialog.password.setText('bde-TEST')
            dialog._try()
            return dialog.result()
        monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)
        window.unlock_bitlocker_item(root.child(0))
        [(text, data)] = _children(root)
        assert 'BitLocker unlocked' in text and 'FAT16' in text
        assert window._unlocks_for(bde) == {
            0: {'password': 'bde-TEST', '_kind': 'bitlocker'}}
        node = root.child(0)
        node.setExpanded(True)
        window.on_item_expanded(node)
        assert 'passwords.txt' in [t for t, _d in _children(node)]

        vss = _artifact_sample('vss.raw')
        assert window.open_evidence_image(vss)
        root = _root(window, 'vss.raw')
        shadows = [(t, d) for t, d in _children(root) if d.get('is_shadow_copy')]
        assert [d['start_offset'] for _t, d in shadows] == [
            shadow_key(0, 0), shadow_key(0, 1)]
        assert '2021-05-01 17:41:28 UTC' in shadows[1][0]
        node = next(root.child(i) for i in range(root.childCount())
                    if (root.child(i).data(0, Qt.UserRole) or {})
                    .get('start_offset') == shadow_key(0, 1))
        window.on_item_expanded(node)
        names = {t: d for t, d in _children(node)}
        assert 'vss1' in names and 'vss2' not in names
        # A file from the snapshot previews with the snapshot's bytes.
        captured = _capture_viewer(window)
        window.current_selected_data = None
        file_data = dict(names['vss1'])
        truth = ImageHandler(vss)
        try:
            expected, _ = truth.get_file_content(file_data['inode_number'],
                                                 shadow_key(0, 1))
        finally:
            truth.close_resources()
        window.preview_artifact({
            'artifact_ref': f"p{shadow_key(0, 1)}:i{file_data['inode_number']}",
            'evidence_id': None, 'name': 'vss1',
            'image_path': vss})
        pump(qapp, 5, lambda: bool(captured))
        assert captured and captured[-1] == expected
    finally:
        window.cleanup_resources()


def test_a_mailbox_browses_like_an_archive(qapp, window):
    """A PST/OST opens in the Listing: folders, messages as pages, and a
    message shows its headers in the viewer -- read lazily, as from the
    image, never extracted."""
    from PySide6.QtCore import Qt
    from tests.conftest import ROOT
    from trace_app.core.containers import ByteWindow
    path = os.path.join(ROOT, 'test_images', 'carve_samples',
                        'example-2013.ost')
    if not os.path.exists(path):
        pytest.skip("example-2013.ost missing: run tools/carve_corpus.py")
    with open(path, 'rb') as handle:
        data = handle.read()
    stream = ByteWindow(lambda o, n: data[o:o + n], 0, len(data))
    window._archive_stack = [('mail.ost', stream, {'name': 'mail.ost',
                                                   'path': '/mail.ost',
                                                   'start_offset': 0})]
    try:
        assert window.show_archive_level()
        rows = {window.listing_table.item(r, 0).text():
                window.listing_table.item(r, 0).data(Qt.UserRole)
                for r in range(window.listing_table.rowCount())
                if window.listing_table.item(r, 0)}
        name = 'Root - Mailbox/IPM_SUBTREE/Sent Items/0001 Test 2.html'
        assert name in rows
        captured = _capture_viewer(window)
        window.open_archive_member_row(rows[name])
        pump(qapp, 5, lambda: bool(captured))
        assert b'bernard.chung@apogeephysicians.com' in captured[-1]
    finally:
        window._archive_stack = []


def test_ntfs_is_a_job_a_triage_tab_and_findings(qapp, window, truth):
    """The NTFS module runs on the queue for every image (both are NTFS,
    neither keeps a change journal); each file's $STANDARD_INFORMATION times
    are The Sleuth Kit's; a finding is a Triage row and a tree leaf that
    preview the file from its own image."""
    import datetime
    import json
    from PySide6.QtCore import Qt
    from trace_app.core.case import parse_artifact_ref
    panel = window.ntfs_panel
    rows = window.case.evidence()
    ids = {name: next(r['id'] for r in rows if r['path'].endswith(name))
           for name in (FIRST, SECOND)}
    assert window.queue_ntfs(rows) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    first = window.case.ntfs_state(ids[FIRST])
    assert first['status'] == 'done' and first['volumes'] == 1
    assert first['entries'] > 30
    second = window.case.ntfs_state(ids[SECOND])
    assert second['status'] == 'done' and second['volumes'] == 1
    assert first['journal'] == second['journal'] == 0

    # A file's SI modified time, against an independent read.
    finding = next(f for f in window.case.findings()
                   if f['evidence_id'] == ids[FIRST])
    ref = parse_artifact_ref(finding['artifact_ref'])
    meta = truth[FIRST].get_fs_info(ref['start_offset']).open_meta(
        inode=ref['inode']).info.meta
    expected = datetime.datetime.fromtimestamp(
        meta.mtime, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    events = window.case.fs_events_for(ids[FIRST], finding['artifact_ref'])
    modified = [e for e in events if e['source'] == 'SI'
                and e['macb'][0] == 'M']
    assert modified and modified[0]['time_utc'].startswith(expected)

    # A suspicious finding on that file: Triage row, tree leaf, preview.
    window.case.add_ntfs_findings(ids[FIRST], [(
        finding['artifact_ref'], finding['name'], finding['path'],
        finding.get('size'), 'timestomp', 'suspicious',
        'Times set by hand', json.dumps({'standard_information': {
            'created': '2019-01-01 00:00:00.0000000'},
            'file_name': {'created': '2024-05-01 10:00:00.5550000'}}))])
    window.case.commit()
    window.refresh_analysis_views()
    group = _findings_group(window, 'Timestomping')
    assert group is not None and group.text(0) == 'Timestomping (1)'
    (leaf,) = _leaves(group)
    shown = _capture_viewer(window)
    window.tree_viewer.itemClicked.emit(leaf, 0)
    pump(qapp, 10, lambda: bool(shown))
    assert shown and shown[-1] == truth[FIRST].get_fs_info(
        ref['start_offset']).open_meta(inode=ref['inode']).read_random(
            0, meta.size)

    window.tree_viewer.itemClicked.emit(group, 0)
    assert pump(qapp, 30, lambda: not panel.loading)
    assert window.result_viewer.currentWidget() is window.triage_panel
    assert window.triage_panel.tabs.currentWidget() is panel
    assert panel.section == 'timestomp' and panel.model.rowCount() == 1
    index = panel.proxy.index(0, 5)
    assert panel.proxy.data(index) == '2024-05-01 10:00:00.5550000'
    del shown[:]
    window.current_selected_data = None
    panel.table.clicked.emit(index)
    pump(qapp, 10, lambda: bool(shown))
    assert shown
    assert window.result_viewer.currentWidget() is window.triage_panel

    panel.show_section('journal')
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.model.rowCount() == 0


def test_hash_sets_hide_known_good_flag_known_bad(qapp, window,
                                                  stubbed_dialogs):
    """A known-bad list and a linked NSRL database: matching is a job; the
    known-bad file is a finding (Triage, tree, a red Listing flag) and the
    known-good ones vanish from the Listing until the option is turned off.
    The manager dialog saves the case's options and audits the change."""
    import sqlite3
    from PySide6.QtCore import Qt
    from trace_app.core import hashsets
    from trace_app.ui.dialogs.hash_sets import HashSetsDialog
    first_id = next(r['id'] for r in window.case.evidence()
                    if r['path'].endswith(FIRST))
    files = {r['name']: r for r in window.case.hashed_files(first_id)}
    library = window.hash_library()
    folder = os.path.dirname(library.folder)
    bad_list = os.path.join(folder, 'bad.txt')
    with open(bad_list, 'w') as handle:
        handle.write(files['$Bitmap']['md5'] + '\n')
    library.import_list(bad_list, 'Lab malware', hashsets.KNOWN_BAD)
    database = os.path.join(folder, 'RDS.db')
    connection = sqlite3.connect(database)
    connection.executescript(
        "CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, crc32 TEXT, "
        "file_name TEXT, file_size INTEGER, package_id INTEGER);"
        "CREATE INDEX FILE_SHA256 ON FILE(sha256);")
    for name in ('$AttrDef', '$Boot'):
        connection.execute("INSERT INTO FILE VALUES (?,?,?,?,?,?,?)", (
            files[name]['sha256'].upper(), '', '', '', name, 1, 1))
    connection.commit()
    connection.close()
    library.link_nsrl(database)

    dialog = HashSetsDialog(window.case, library, window)
    assert dialog.table.rowCount() == 2 and dialog.use_box.isChecked()
    dialog.hide_box.setChecked(True)
    dialog.save()
    assert window.case.setting('hashsets')['hide_known_good'] is True
    assert window.case.activity()[0]['action'] == 'hash set options changed'

    assert window.queue_hash_matching()
    assert pump(qapp, 120, lambda: not window.job_bar.busy)
    counts = window.case.hash_match_counts(first_id)
    assert counts == {'known-bad': 1, 'known-good': 2}

    group = _findings_group(window, 'Known bad (hash sets)')
    assert group is not None
    assert [leaf.text(0) for leaf in _leaves(group)] == ['$Bitmap']
    panel = window.hash_panel
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.model.rowCount() == 1        # known good not listed
    panel.known_good_box.setChecked(True)
    assert pump(qapp, 30, lambda: not panel.loading)
    # The whole case: the other NTFS image has the same $AttrDef and $Boot.
    assert panel.model.rowCount() == len(window.case.hash_matches()) >= 3
    panel.known_good_box.setChecked(False)

    window.on_item_clicked(_first_volume(_root(window, FIRST)), 0)
    pump(qapp, 0.5)
    rows = {window.listing_table.item(r, 0).text(): r
            for r in range(window.listing_table.rowCount())
            if window.listing_table.item(r, 0)}
    assert window.listing_table.isRowHidden(rows['$AttrDef'])
    assert window.listing_table.isRowHidden(rows['$Boot'])
    assert not window.listing_table.isRowHidden(rows['$Bitmap'])
    assert window.listing_table.item(rows['$Bitmap'], 14).text() == \
        'Known bad: Lab malware'

    options = window.case.setting('hashsets')
    window.case.set_setting('hashsets', dict(options, hide_known_good=False))
    window.mark_analysis_rows()
    assert not window.listing_table.isRowHidden(rows['$AttrDef'])
    assert window.listing_table.item(rows['$AttrDef'], 14).text() \
        .startswith('Known good')
    window.case.set_setting('hashsets', dict(options, enabled=False))
    hashsets.match_case(window.case, library,
                        hashsets.case_options(window.case, library))
    window.refresh_analysis_views()
    assert _findings_group(window, 'Known bad (hash sets)') is None


def test_timeline_tab_previews_pivots_exports_and_feeds_the_report(
        qapp, window, tmp_path):
    """The Timeline holds the NTFS times read above for both images; a
    click previews the event's file and stays; a pivot narrows to one file;
    an event goes to the report; the CSV export is audited."""
    import csv
    from PySide6.QtCore import Qt
    panel = window.timeline_panel
    if not window.case._db.execute("SELECT 1 FROM fs_events").fetchone():
        window.queue_ntfs(window.case.evidence())
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
    window.result_viewer.setCurrentWidget(panel)
    if panel._dirty:            # offscreen, the tab is never "shown"
        panel.refresh(find_bounds=True)
    assert pump(qapp, 60, lambda: not panel.loading)
    events = window.case._db.execute(
        "SELECT COUNT(*) FROM fs_events").fetchone()[0]
    assert events and panel.counts.get('fs') == events
    assert panel.model.rowCount() > 0 and panel.histogram.buckets
    times = [row['time'] for row in panel.model.rows]
    assert times == sorted(times)

    position = next(i for i, row in enumerate(panel.model.rows)
                    if row['source'] == 'fs'
                    and not row['subject'].rsplit('/', 1)[-1].startswith('$'))
    row = panel.model.rows[position]
    shown = _capture_viewer(window)
    window.current_selected_data = None
    panel.table.clicked.emit(panel.model.index(position, 0))
    pump(qapp, 10, lambda: bool(shown))
    assert shown and window.result_viewer.currentWidget() is panel
    detail = panel.detail.toPlainText()
    assert 'NTFS times (UTC)' in detail and '$SI' in detail

    panel._focus_file(row)
    assert pump(qapp, 30, lambda: not panel.loading)
    assert {r['artifact_ref'] for r in panel.model.rows} == \
        {row['artifact_ref']}
    assert panel.pivot_holder.isVisibleTo(panel)
    panel._drop_pivot('focus_ref')
    assert pump(qapp, 30, lambda: not panel.loading)

    before = len(window.case.report_items('timeline'))
    panel.report_requested.emit([row])
    assert len(window.case.report_items('timeline')) == before + 1

    # Through the button, as an examiner does it (the save dialog answered).
    from trace_app.ui.viewers import timeline_panel as module
    out = str(tmp_path / 'timeline.csv')
    original = module.QFileDialog.getSaveFileName
    module.QFileDialog.getSaveFileName = staticmethod(
        lambda *a, **k: (out, 'CSV (*.csv)'))
    try:
        panel.export_button.click()
    finally:
        module.QFileDialog.getSaveFileName = original
    assert pump(qapp, 60, lambda: panel._export is None)
    with open(out, encoding='utf-8-sig', newline='') as handle:
        rows = list(csv.reader(handle))
    assert len(rows) - 1 == panel.total
    assert window.case.activity()[0]['action'] == 'timeline exported'


def test_report_is_a_job_and_lands_in_exports(qapp, window):
    from trace_app.core import report
    options = report.default_options(window.case)
    for section in options['sections']:
        section['enabled'] = True
    window._report_dialogs = False
    window.last_report = None
    assert window.queue_report(options)
    assert pump(qapp, 180, lambda: not window.job_bar.busy)
    written = {item['format']: item for item in window.last_report}
    assert set(written) == {'html', 'pdf'}
    for item in written.values():
        assert os.path.exists(item['path'])
        assert os.path.dirname(item['path']) == os.path.join(
            window.case.folder, 'exports')
    with open(written['html']['path'], encoding='utf-8') as handle:
        page = handle.read()
    assert FIRST in page and SECOND in page


def test_timeline_histogram_controls(qapp, window):
    """Real wheel, click and double-click events on the histogram: many
    wheel notches out stay inside the case (once an OverflowError) and run
    one query; a click goes to that moment without zooming; a double-click
    zooms into the bar; Whole case comes back."""
    from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
    from PySide6.QtGui import QMouseEvent, QWheelEvent
    from trace_app.core import timeline
    panel = window.timeline_panel
    if not window.case._db.execute("SELECT 1 FROM fs_events").fetchone():
        window.queue_ntfs(window.case.evidence())
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
    window.result_viewer.setCurrentWidget(panel)
    panel.reset_range()
    assert pump(qapp, 60, lambda: not panel.loading)
    bar = panel.histogram
    bar.resize(900, 110)
    pump(qapp, 0.2)
    whole = (panel.filters['start'], panel.filters['end'])
    point = QPointF(450, 50)

    def wheel(notches):
        event = QWheelEvent(point, bar.mapToGlobal(point), QPoint(0, 0),
                            QPoint(0, 120 * notches), Qt.NoButton,
                            Qt.NoModifier, Qt.ScrollUpdate, False)
        qapp.sendEvent(bar, event)

    def mouse(kind, x):
        spot = QPointF(x, 50)
        qapp.sendEvent(bar, QMouseEvent(kind, spot, bar.mapToGlobal(spot),
                                        Qt.LeftButton, Qt.LeftButton,
                                        Qt.NoModifier))

    generation = panel._generation
    for _ in range(4):
        wheel(1)                                  # in
    assert pump(qapp, 30, lambda: panel._generation > generation
                and not panel.loading)
    assert panel._generation == generation + 1    # one query, not four
    narrower = timeline.parse(panel.filters['end']) - timeline.parse(
        panel.filters['start'])
    assert narrower < timeline.parse(whole[1]) - timeline.parse(whole[0])

    for _ in range(60):
        wheel(-1)                                 # far out
    assert pump(qapp, 30, lambda: not panel._wheel_timer.isActive()
                and not panel.loading)
    first, last = (timeline.parse(t) for t in panel.case_span())
    assert timeline.parse(panel.filters['start']) >= first - (last - first)
    assert timeline.parse(panel.filters['end']) <= last + (last - first)

    panel.reset_range()
    assert pump(qapp, 30, lambda: not panel.loading)
    bar.grab()                  # paints it, laying out the bars (offscreen)
    assert bar._bars
    rect, bucket, _counts = bar._bars[len(bar._bars) // 2]
    before = (panel.filters['start'], panel.filters['end'])
    mouse(QEvent.MouseButtonPress, rect.center().x())
    mouse(QEvent.MouseButtonRelease, rect.center().x())
    pump(qapp, 0.3)
    assert (panel.filters['start'], panel.filters['end']) == before
    row = panel.current_row()
    assert row and row['time'] >= timeline.text(timeline.bucket_start(
        bucket))
    mouse(QEvent.MouseButtonDblClick, rect.center().x())
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.filters['start'] == timeline.text(
        timeline.bucket_start(bucket))


def test_no_tab_squeezes_the_tree(window):
    """Every tab must fit beside a proper tree on a 1366-pixel laptop: the
    Timeline's rows once demanded 2,000 px and Qt took them from the tree,
    leaving it a sliver. The tree itself has a floor."""
    tabs = window.result_viewer
    for index in range(tabs.count()):
        width = tabs.widget(index).minimumSizeHint().width()
        assert width <= 700, (tabs.tabText(index), width)
    assert tabs.minimumSizeHint().width() <= 720
    assert window.tree_viewer.minimumWidth() >= window._TREE_MIN


def test_window_layout_is_remembered(window):
    from trace_app.infra.window_state import (forget_window_state,
                                              read_window_state)
    window.save_layout()
    geometry, state = read_window_state()
    assert geometry and state
    forget_window_state()
    assert read_window_state() == (None, None)


def test_yara_is_a_job_a_triage_tab_and_findings(qapp, window, tmp_path):
    """Rules imported into the library and switched on: the scan runs on
    the queue per image, its matches fill Triage > YARA and Findings, and
    where yara-x is missing the option is greyed out with the reason."""
    pytest.importorskip('yara_x')
    from trace_app.core import yara_rules
    from trace_app.ui.dialogs.analysis_modules import AnalysisModulesDialog
    rules = tmp_path / 'rules'
    rules.mkdir()
    (rules / 'jpeg.yar').write_text(
        'rule JPEG_JFIF { strings: $j = "JFIF" condition: '
        'uint16(0) == 0xD8FF and $j }')
    window.yara_library().import_rules(str(rules), 'Pictures', 'notable')
    window.case.set_setting('yara', dict(yara_rules.default_options(),
                                         enabled=True))
    assert window.queue_yara(window.case.evidence()) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    found = window.case.findings(None, 'yara', limit=1000)
    assert found and {f['detail']['rule'] for f in found} == {'JPEG_JFIF'}
    triage = window.triage_panel
    assert triage.yara_table.rowCount() == len(found)
    assert triage.tabs.tabText(triage._tab_for['yara']).startswith('YARA (')
    group = _findings_group(window, 'YARA matches')
    assert group is not None and _leaves(group)

    dialog = AnalysisModulesDialog(None, {
        'modules': [], 'yara_available': False,
        'yara_reason': 'yara-x is not installed (Windows on ARM)'})
    assert not dialog.yara_box.isEnabled()
    assert 'Windows on ARM' in dialog.yara_box.toolTip()


def test_persistence_is_a_job_and_a_triage_tab(qapp, window):
    """Neither test image holds Windows, so the job finds nothing and the
    tab says nothing was read; a stored suspicious entry then shows, and
    previews the file it starts from its own image."""
    from trace_app.core import persistence
    panel = window.persistence_panel
    assert window.queue_persistence(window.case.evidence()) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    assert pump(qapp, 30, lambda: not panel.loading)
    assert 'Nothing read yet' in panel.status_label.text()
    first = next(f for f in window.case.findings()
                 if f['evidence_id'] == next(
                     r['id'] for r in window.case.evidence()
                     if r['path'].endswith(FIRST)))
    entry = persistence._entry('Run key', 'svchost',
                               r'C:\Users\Public\svchost.exe')
    entry.update(target=r'C:\Users\Public\svchost.exe', exists=True,
                 target_ref=first['artifact_ref'], signed=False)
    entry['grade'], entry['reasons'] = persistence.grade(entry)
    assert entry['grade'] == 'suspicious'
    window.case.replace_persistence(first['evidence_id'], [entry])
    panel.refresh()
    assert pump(qapp, 30, lambda: not panel.loading)
    assert panel.model.rowCount() == 1 and panel.count == 1
    shown = _capture_viewer(window)
    window.current_selected_data = None
    panel.table.clicked.emit(panel.proxy.index(0, 0))
    pump(qapp, 10, lambda: bool(shown))
    assert shown


def test_luks_lvm_and_apfs_volumes_in_the_tree(qapp, stubbed_dialogs,
                                               monkeypatch):
    """A LUKS volume shows locked and unlocks with its passphrase; an LVM
    group lists its logical volumes; an encrypted APFS volume shows locked
    in its container and lists its files once unlocked."""
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs import bitlocker
    from trace_app.ui.main_window import MainWindow
    passwords = {'luks': 'luksde-TEST', 'apfs': 'apfs-TEST'}

    def fake_exec(dialog):
        dialog.password.setText(passwords[dialog.encryption])
        dialog._try()
        return dialog.result()
    monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)
    window = MainWindow()
    try:
        luks = _artifact_sample('luks1.raw')
        assert window.open_evidence_image(luks)
        root = _root(window, 'luks1.raw')
        [(text, data)] = _children(root)
        assert data.get('encryption') == 'luks' and 'LUKS, locked' in text
        window.unlock_bitlocker_item(root.child(0))
        [(text, data)] = _children(root)
        assert 'LUKS unlocked' in text and 'Ext2' in text
        assert window._unlocks_for(luks) == {
            0: {'password': 'luksde-TEST', '_kind': 'luks'}}
        node = root.child(0)
        node.setExpanded(True)
        window.on_item_expanded(node)
        assert 'passwords.txt' in [t for t, _d in _children(node)]

        assert window.open_evidence_image(_artifact_sample('lvm.raw'))
        root = _root(window, 'lvm.raw')
        volumes = [(t, d) for t, d in _children(root)
                   if d.get('is_logical_volume')]
        assert [t.split(' (')[0] for t, _d in volumes] == [
            'test_volume_group / test_logical_volume1',
            'test_volume_group / test_logical_volume2']

        assert window.open_evidence_image(
            _artifact_sample('apfs_encrypted.dmg'))
        root = _root(window, 'apfs_encrypted.dmg')
        container = next(root.child(i) for i in range(root.childCount())
                         if (root.child(i).data(0, Qt.UserRole) or {})
                         .get('is_volume_group'))
        [(text, data)] = _children(container)
        assert data.get('encryption') == 'apfs' and 'locked' in text
        window.unlock_bitlocker_item(container.child(0))
        [(text, data)] = _children(container)
        assert data.get('is_apfs_volume') and 'unlocked' in text
        node = container.child(0)
        node.setExpanded(True)
        window.on_item_expanded(node)
        assert 'passwords.txt' in [t for t, _d in _children(node)]
    finally:
        window.cleanup_resources()


def test_encrypted_ios_backup_unlocks_in_the_tree(qapp, stubbed_dialogs,
                                                  monkeypatch, tmp_path):
    """An encrypted iPhone backup opens locked, its password is asked for
    like a volume's, and the phone's files list once it is given; the
    password goes to background jobs, never to the case."""
    pytest.importorskip('cryptography')
    from tests.test_mobile import MVT, PASSWORD, encrypt_backup
    from trace_app.ui.dialogs import bitlocker
    from trace_app.ui.main_window import MainWindow
    path = encrypt_backup(_artifact_sample(MVT),
                          str(tmp_path / '00008030-001A2B3C4D5E'))

    def fake_exec(dialog):
        assert dialog.encryption == 'ios_backup'
        dialog.password.setText(PASSWORD)
        dialog._try()
        return dialog.result()
    monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)
    window = MainWindow()
    try:
        assert window.open_evidence_image(path)
        root = _root(window, '00008030-001A2B3C4D5E')
        [(text, data)] = _children(root)
        assert data.get('encryption') == 'ios_backup' and 'locked' in text
        # Named for what it is, with what it takes on disk -- a folder has
        # no media size, and "Size: 0.00 B" said the backup was empty.
        stored = sum(os.path.getsize(os.path.join(folder, name))
                     for folder, _d, names in os.walk(path)
                     for name in names)
        assert text.startswith('iOS backup (Size: ')
        assert window.image_handler.get_readable_size(stored) in text
        assert '0.00 B' not in text
        window.unlock_bitlocker_item(root.child(0))
        [(text, data)] = _children(root)
        assert 'unlocked' in text and text.startswith('iOS backup (Size: ')
        assert '0.00 B' not in text
        assert window._unlocks_for(path) == {
            0: {'password': PASSWORD, '_kind': 'ios_backup'}}
        node = root.child(0)
        node.setExpanded(True)
        window.on_item_expanded(node)
        assert [t for t, _d in _children(node)] == ['Backup', 'private']
    finally:
        window.cleanup_resources()


def test_keyword_lists_are_a_job_a_triage_tab_and_findings(qapp, window,
                                                           truth):
    """A list in the library, switched on for the case: the search runs on
    the queue over the index built above, its hits fill Triage > Keywords
    and Findings > Keyword hits, and a hit previews from its own image."""
    from PySide6.QtCore import Qt
    from trace_app.core import keywords
    from trace_app.core.case import parse_artifact_ref
    from trace_app.ui.dialogs.analysis_modules import AnalysisModulesDialog
    if not window.indicators_panel.index or not \
            window.indicators_panel.index.statistics()['items']:
        window.queue_indexing(window.case.evidence())
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
    library = window.keyword_library()
    library.create('Pictures', [keywords.make_term('jpg'),
                                keywords.make_term('nothing-like-this-xyz')])
    window.case.set_setting('keywords', dict(keywords.default_options(),
                                             enabled=True))
    assert window.queue_keywords()
    assert pump(qapp, 120, lambda: not window.job_bar.busy)
    found = window.case.findings(None, 'keywords', limit=10000)
    assert found and {f['detail']['term'] for f in found} == {'jpg'}
    panel = window.keywords_panel
    triage = window.triage_panel
    assert triage.tabs.tabText(triage._tab_for['keywords']) == \
        'Keywords (1)'
    assert panel.terms_table.rowCount() == 1
    assert panel.files_table.rowCount() == len(found)

    group = _findings_group(window, 'Keyword hits')
    assert group is not None and group.childCount() == 1
    node = group.child(0)
    assert node.text(0).startswith('jpg (')
    window.tree_viewer.setCurrentItem(node)
    window.tree_viewer.itemClicked.emit(node, 0)
    pump(qapp, 0.2)
    assert window.result_viewer.currentWidget() is triage
    assert triage.tabs.currentWidget() is panel

    second = next(r['id'] for r in window.case.evidence()
                  if r['path'].endswith(SECOND))
    position = next(r for r in range(panel.files_table.rowCount())
                    if panel.files_table.item(r, 0).data(Qt.UserRole)
                    ['evidence_id'] == second and panel.files_table.item(
                        r, 0).data(Qt.UserRole)['detail']['item_kind']
                    == 'file')
    row = panel.files_table.item(position, 0).data(Qt.UserRole)
    captured = _capture_viewer(window)
    window.current_selected_data = None
    panel.files_table.clearSelection()
    panel.files_table.selectRow(position)
    pump(qapp, 10, lambda: bool(captured))
    ref = parse_artifact_ref(row['artifact_ref'])
    expected, _ = truth[SECOND].get_file_content(ref['inode'],
                                                 ref['start_offset'])
    assert captured and captured[-1] == expected
    assert window.result_viewer.currentWidget() is triage

    dialog = AnalysisModulesDialog(None, {'modules': [],
                                          'keywords_available': False})
    assert not dialog.keywords_box.isEnabled()


def test_thumbnails_are_a_job_and_a_grid_read_from_the_image(qapp, window,
                                                             truth):
    """Neither image holds a thumbnail cache, so the job finds none; a
    picture recorded against a JPEG on the second image is then drawn in
    the grid from the image and previewed from it."""
    from PySide6.QtCore import Qt
    from trace_app.core.case import make_artifact_ref
    panel = window.thumbnails_panel
    assert window.queue_thumbnails(window.case.evidence()) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    assert panel.count == 0 and 'No thumbnail caches' in \
        panel.status_label.text()
    second = next(r['id'] for r in window.case.evidence()
                  if r['path'].endswith(SECOND))
    ref = make_artifact_ref(0, 29, 1)                 # /alloc/file1.jpg
    content, _ = truth[SECOND].get_file_content(29, 0)
    window.case.replace_thumbnails(second, [{
        'cache_ref': ref, 'cache_path': '/alloc/file1.jpg',
        'cache_kind': 'thumbcache', 'cache_size': '256',
        'system': 'Windows 10/11', 'user': 'bob', 'key': '79b0d2fffa22677a',
        'location': '0', 'format': 'jpg', 'size': len(content)}])
    window.refresh_analysis_views()
    assert panel.count == 1
    triage = window.triage_panel
    assert triage.tabs.tabText(triage._tab_for['thumbnails']) == \
        'Thumbnails (1)'
    icon = panel.model.data(panel.model.index(0), Qt.DecorationRole)
    assert icon is not None and icon.availableSizes()
    captured = _capture_viewer(window)
    window.current_selected_data = None
    panel.view.clicked.emit(panel.model.index(0))
    pump(qapp, 10, lambda: bool(captured))
    assert captured and captured[-1] == content
    window.case.replace_thumbnails(second, [])
    window.refresh_analysis_views()


def test_deleted_files_are_a_job_and_a_triage_tab(qapp, window, truth):
    """The second image's two deleted JPEGs are listed as recoverable, and
    a row previews the deleted file's bytes from that image."""
    from PySide6.QtCore import Qt
    from trace_app.core.case import parse_artifact_ref
    panel = window.deleted_panel
    assert window.queue_deleted(window.case.evidence()) == 2
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    triage = window.triage_panel
    assert triage.tabs.tabText(triage._tab_for['deleted']).startswith(
        'Deleted files (')
    rows = {panel.table.item(r, 8).text(): r
            for r in range(panel.table.rowCount())}
    assert {'/del1/file6.jpg', '/del2/file7.hmm'} <= set(rows)
    position = rows['/del1/file6.jpg']
    row = panel.table.item(position, 0).data(Qt.UserRole)
    assert row['state'] == 'recoverable'
    captured = _capture_viewer(window)
    window.current_selected_data = None
    panel.table.clearSelection()
    panel.table.selectRow(position)
    pump(qapp, 10, lambda: bool(captured))
    ref = parse_artifact_ref(row['artifact_ref'])
    expected, _ = truth[SECOND].get_file_content(ref['inode'],
                                                 ref['start_offset'])
    assert captured and captured[-1] == expected
    assert expected[:3] == b'\xff\xd8\xff'


def test_an_interrupted_carve_offers_resume(qapp, window):
    """A carve that stopped part way shows Resume, which carries it on."""
    from trace_app.core.carving import CARVABLE_TYPES
    panel = window.carved_panel
    second = next(r['id'] for r in window.case.evidence()
                  if r['path'].endswith(SECOND))
    window.case.set_carving_state(second, 'cancelled',
                                  types=','.join(t.lower() for t in
                                                 CARVABLE_TYPES),
                                  unallocated_only=True, bytes_done=1024,
                                  bytes_total=10 ** 9, found=0)
    window.triage_panel.set_evidence_filter(second)
    panel.refresh()
    assert panel.resume_button.isVisibleTo(panel)
    assert window.resume_carving(second) == 1
    assert pump(qapp, 300, lambda: not window.job_bar.busy)
    assert window.case.carving_state(second)['status'] == 'done'
    panel.refresh()
    assert not panel.resume_button.isVisibleTo(panel)
    window.triage_panel.set_evidence_filter(None)


def test_a_database_shows_its_tables_and_what_it_deleted(qapp, window,
                                                         tmp_path):
    """Neither image holds a SQLite file, so one written and deleted from
    by SQLite itself goes to the Application tab the way a selected file's
    bytes do: its tables at once, the deleted rows when recovery ends. There
    is no Database tab of its own any more -- it stood empty for every
    other file."""
    import sqlite3
    path = str(tmp_path / 'history.db')
    db = sqlite3.connect(path)
    # Debian and Ubuntu build SQLite to zero deleted rows; most don't.
    db.execute("PRAGMA secure_delete = OFF")
    db.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
    db.executemany("INSERT INTO urls (url) VALUES (?)",
                   [(f'https://example.org/page/{i}',) for i in range(30)])
    db.commit()
    db.execute("DELETE FROM urls WHERE id = 12")
    db.commit()
    db.close()
    with open(path, 'rb') as handle:
        content = handle.read()
    labels = [window.viewer_tab.tabText(i)
              for i in range(window.viewer_tab.count())]
    assert 'Database' not in labels
    application = window.application_viewer
    # Nothing selected, and no read from an earlier test still to land:
    # either would show another file in this tab, over this database.
    window.current_selected_data = None
    window._cancel_worker('file_worker')
    window._cancel_worker('media_worker')
    pump(qapp, 2)
    window.viewer_tab.setCurrentWidget(application)
    pump(qapp, 1)
    # Named as nothing in particular: recognised by its header.
    window.update_viewer_with_file_content(content, {
        'name': 'History', 'path': '/History', 'start_offset': 0})
    viewer = application.get_database_viewer()
    assert viewer.isVisibleTo(application)
    assert not application.notice.isVisibleTo(application)
    assert viewer.tables.item(0).text() == 'urls (29 rows)'
    assert viewer.grid.rowCount() == 29
    assert pump(qapp, 100, lambda: viewer.tables.count() == 2),         viewer.info.text()
    assert '1 deleted record(s) recovered' in viewer.info.text()
    viewer.tables.setCurrentRow(1)
    headers = [viewer.grid.horizontalHeaderItem(c).text()
               for c in range(viewer.grid.columnCount())]
    assert headers == ['Found in', 'Page', 'Note', 'id', 'url']
    assert viewer.grid.item(0, 4).text() == 'https://example.org/page/11'

    # A misleading name is said so; another file hides the database view.
    window.update_viewer_with_file_content(content, {
        'name': 'notes.txt', 'path': '/notes.txt', 'start_offset': 0})
    assert viewer.isVisibleTo(application)
    assert 'SQLite database' in application.notice.text()
    window.update_viewer_with_file_content(b'plain words', {
        'name': 'Thumbs.db', 'path': '/Thumbs.db', 'start_offset': 0})
    assert not viewer.isVisibleTo(application)


def test_executables_are_a_triage_tab_and_flagged_ones_a_finding(qapp,
                                                                 window):
    """Neither image holds a program, so a signed one and one that calls
    itself something else are recorded as the analysis records them: both
    in Triage's Executables tab, only the flagged one under Findings."""
    import json
    from trace_app.core import content_checks
    from trace_app.core.case import make_artifact_ref
    from tests.conftest import ROOT
    path = os.path.join(ROOT, 'test_images', 'carve_samples', 'pageant.exe')
    if not os.path.exists(path):
        pytest.skip("run tools/carve_corpus.py")
    with open(path, 'rb') as handle:
        data = handle.read()
    evidence = window.case.evidence()[0]['id']
    rows = []
    for inode, name in ((99990, 'pageant.exe'), (99991, 'svchost.exe')):
        finding = content_checks.executable_finding(name, data)
        rows.append((make_artifact_ref(0, inode, 1), name, '/' + name,
                     len(data), finding.kind, finding.grade,
                     finding.summary, json.dumps(finding.detail)))
    window.case.add_module_findings(evidence, 'executables', rows)
    window.refresh_analysis_views()
    try:
        triage = window.triage_panel
        index = triage._tab_for['executables']
        assert triage.tabs.tabText(index) == 'Executables (2)'
        table = triage.executable_table
        cells = [[table.item(r, c).text() for c in range(table.columnCount())]
                 for r in range(table.rowCount())]
        assert cells[0][0] == 'svchost.exe'           # flagged first
        assert cells[0][2] == 'Notable'
        assert cells[0][7] == 'Calls itself Pageant'
        assert cells[1][2] == '' and cells[1][3] == 'PE32+ program'
        assert cells[1][6] == 'Yes, by Simon Tatham'
        group = _findings_group(window, 'Executables')
        assert group is not None and group.text(0) == 'Executables (1)'
        assert [leaf.text(0) for leaf in _leaves(group)][0].startswith(
            'svchost.exe')
    finally:
        window.case.clear_findings(evidence, 'executables')
        window.refresh_analysis_views()


def test_an_ad1_opens_as_a_tree_of_files(qapp, stubbed_dialogs):
    """FTK Imager's AD1 is logical evidence: its folders under the root, a
    picture previewed from its zlib chunks, and no carving offered on it
    -- there are files, not a disk."""
    from tests.conftest import ROOT
    from trace_app.ui.main_window import MainWindow
    path = os.path.join(ROOT, 'test_images', 'artifact_samples',
                        'text-and-pictures.ad1')
    if not os.path.exists(path):
        pytest.skip("run tools/fetch_artifact_samples.py")
    window = MainWindow()
    try:
        assert window.open_evidence_image(path)
        root = window.tree_viewer.topLevelItem(
            window.tree_viewer.topLevelItemCount() - 1)
        names = sorted(root.child(i).text(0) for i in range(root.childCount()))
        assert names == ['Pictures', 'Text']
        handler = window.image_handler
        node = handler.get_fs_info(0).lookup('/Text/norvig-big.txt')
        content, _ = handler.get_file_content(node.inode, 0)
        assert hashlib.md5(content).hexdigest() == node.facts['md5']
        assert window.start_carving(None, ['jpg'], True) == 0
    finally:
        window.cleanup_resources()


def test_sigma_detections_are_a_triage_tab_and_findings(qapp, window):
    """Sigma detections as the scan records them: every one in Triage's
    Sigma tab, most serious first; medium and above under Findings."""
    import json
    from trace_app.core.case import make_artifact_ref
    evidence = window.case.evidence()[0]['id']
    ref = make_artifact_ref(0, 99995, 1)
    rows = []
    for rule, level, grade in (('Mimikatz DC Sync', 'high', 'suspicious'),
                               ('Whoami Execution', 'medium', 'notable'),
                               ('Process Creation', 'low', 'benign')):
        detail = {'rule': rule, 'level': level, 'attack': ['T1003.006'],
                  'time': '2019-03-25 12:00:00.000000', 'event_id': 4662,
                  'computer': 'DC01', 'data': {'SubjectUserName': 'admin'}}
        rows.append((ref, 'Security.evtx', '/Security.evtx', 100, 'sigma',
                     grade, f"{rule} ({level})", json.dumps(detail)))
    window.case.add_module_findings(evidence, 'sigma', rows)
    window.refresh_analysis_views()
    try:
        triage = window.triage_panel
        assert triage.tabs.tabText(triage._tab_for['sigma']) == 'Sigma (3)'
        table = triage.sigma_table
        assert [table.item(r, 3).text() for r in range(3)] == [
            'Mimikatz DC Sync', 'Whoami Execution', 'Process Creation']
        assert table.item(0, 2).text() == 'High'
        assert 'SubjectUserName: admin' in table.item(0, 8).text()
        group = _findings_group(window, 'Sigma detections')
        assert group is not None and group.text(0) == 'Sigma detections (2)'
    finally:
        window.case.clear_findings(evidence, 'sigma')
        window.refresh_analysis_views()


def test_media_says_what_it_is_and_switches_after_playing(qapp):
    """A loaded file says what it is and waits for Play ('Audio · 00:03 ·
    ready'), not "Playing Audio" over a black panel; one that will not
    decode says so in the player, with no dialog; and a file played, paused
    and left for the next one does not hang the switch -- its buffer was
    closed under the decoder."""
    import io
    import wave
    from trace_app.ui.viewers.media import UnifiedViewer
    buffer = io.BytesIO()
    with wave.open(buffer, 'wb') as audio:
        audio.setnchannels(1)
        audio.setsampwidth(1)
        audio.setframerate(8000)
        audio.writeframes(bytes(range(256)) * 100)        # 3.2 s
    tone = buffer.getvalue()
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from trace_app.ui.viewers.media.audiovideo import AudioVideoPlayer
    viewer = UnifiedViewer()
    viewer.resize(900, 200)             # a short Utils dock
    viewer.show()
    try:
        viewer.display_application_content(tone, 'tone.wav')
        player = viewer._audio_video_player
        assert pump(qapp, 10, lambda: 'ready' in player.status_label.text())
        assert player.status_label.text().startswith('Audio · 00:03')
        assert not player._is_playing
        # The controls fit, whatever the dock's height (the picture used to
        # insist on 400x300 and push them out of sight).
        pump(qapp, 0.2)
        assert player.control_widget.isVisible()
        assert player.control_widget.geometry().bottom() <= viewer.height()
        # Audio has no frames to step or save.
        assert player.play_action.isEnabled()
        assert not player.frame_next_action.isEnabled()
        assert not player.snapshot_action.isEnabled()
        assert player.save_frame('unused.png') == ''

        player.jump(1000)
        assert pump(qapp, 3, lambda: player.media_player.position() >= 1000)
        assert player.current_time_label.text() == '00:01.0'
        player.jump(60000)                           # held at the end
        assert pump(qapp, 3,
                    lambda: player.media_player.position() < 3300)
        player.speed_combo.setCurrentIndex(player.speed_combo.findData(2.0))
        assert player.media_player.playbackRate() == 2.0
        player.loop_action.trigger()
        assert player.media_player.loops() == -1     # QMediaPlayer.Infinite
        player.loop_action.trigger()
        assert player.media_player.loops() == 1
        player.set_position(0)

        space = QKeyEvent(QEvent.KeyPress, Qt.Key_Space, Qt.NoModifier, ' ')
        player.keyPressEvent(space)                  # Space plays
        assert pump(qapp, 5, lambda: player.media_player.position() > 0)
        assert player._is_playing and player.play_action.text() == 'Pause'
        player.keyPressEvent(space)
        pump(qapp, 0.3)
        assert not player._is_playing
        assert AudioVideoPlayer.format_time(3_725_400) == '1:02:05.4'

        viewer.display_application_content(tone, 'again.wav')   # no hang
        assert pump(qapp, 10, lambda: 'ready' in player.status_label.text())

        viewer.display_application_content(
            b'\x30\x26\xb2\x75' + bytes(4000), 'damaged.wmv')
        assert pump(qapp, 10,
                    lambda: player.status_label.text() == 'Not playable')
        assert 'could not be played' in player.audio_label.text()
    finally:
        viewer.shutdown()
        viewer.deleteLater()


@pytest.mark.parametrize('name, size, fps', [
    ('VP9test.webm', (512, 288), 25),
    ('ContainerShip.webm', (1084, 738), 30),
    # Named as audio (.ogg), holding Theora video: shown as video.
    ('Wiki.OrientateEdges.ogg', (480, 480), 30),
])
def test_video_shows_its_first_frame_steps_and_saves(qapp, tmp_path, name,
                                                     size, fps):
    """Real video (CC0 clips, tools/fetch_test_images.py): the first frame
    is shown with nothing playing, the line gives size and rate, a frame
    step moves one frame and stays paused, and Save Frame writes that frame
    as a PNG named after the file and the moment."""
    from PySide6.QtGui import QImage
    from PySide6.QtMultimedia import QMediaPlayer
    from trace_app.ui.viewers.media import UnifiedViewer
    with open(image_path(name), 'rb') as handle:
        content = handle.read()
    viewer = UnifiedViewer()
    viewer.resize(800, 300)
    viewer.show()
    try:
        viewer.display_application_content(content, name)
        player = viewer._audio_video_player
        assert pump(qapp, 10, lambda: player._first_frame is not None)
        pump(qapp, 0.3)
        assert player.media_player.playbackState() == \
            QMediaPlayer.PausedState
        assert player.media_player.position() == 0
        assert player.video_widget.isVisibleTo(viewer)
        line = player.status_label.text()
        assert line.startswith('Video') and f"{size[0]}×{size[1]}" in line
        assert f"{fps} fps" in line and 'ready' in line
        assert player.frame_next_action.isEnabled()

        player.step_frame(1)
        step = round(1000 / fps)
        assert pump(qapp, 5, lambda: player.media_player.position() >= step)
        assert player.media_player.position() <= step + 1
        assert not player._is_playing

        saved = player.save_frame(str(tmp_path / player.frame_file_name()))
        assert saved.endswith(' @ 00m00.0s.png')
        image = QImage(saved)
        assert (image.width(), image.height()) == size
    finally:
        viewer.shutdown()
        viewer.deleteLater()


def test_videos_get_thumbnails_in_the_listing_and_the_gallery(qapp,
                                                               tmp_path):
    """A video in the Listing's icon views shows a frame from it, play-
    badged, streamed from the file (never read whole); one that will not
    decode keeps its icon. The window's opener streams a listed file from
    its image. The carved-files gallery gives a carved video a frame too."""
    import shutil
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.main_window import MainWindow
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    from trace_app.ui.widgets.listing_views import ListingIconView
    clip = image_path('VP9test.webm')
    with open(clip, 'rb') as handle:
        video = handle.read()

    def opener(data):
        buffer = QBuffer()
        buffer.setData(QByteArray(video if data['name'] != 'broken.mp4'
                                  else bytes(2000)))
        buffer.open(QIODevice.ReadOnly)
        return buffer

    table = QTableWidget(2, 1)
    for row, name in enumerate(('clip.webm', 'broken.mp4')):
        cell = QTableWidgetItem(name)
        cell.setData(Qt.UserRole, {'type': 'file', 'name': name,
                                   'size': str(len(video)),
                                   'inode_number': row + 10,
                                   'start_offset': 0, 'image_path': 'x'})
        table.setItem(row, 0, cell)
    view = ListingIconView(table, lambda data: None, open_video=opener)
    view.resize(600, 300)
    view.set_mode('large')
    view.show()
    try:
        keys = [view._key(table.item(r, 0).data(Qt.UserRole))
                for r in range(2)]
        assert pump(qapp, 15, lambda: all(k in view._thumbs for k in keys))
        good, broken = (view._thumbs[k] for k in keys)
        assert good and not good.isNull() and max(good.width(),
                                                  good.height()) == 96
        assert broken is False                     # stays the file's icon
        assert view.thumbnail_for(view.model().index(0, 0)) is good
    finally:
        view.deleteLater()

    # The window's opener: a stream over the file, from its own image.
    folder = tmp_path / 'collection'
    folder.mkdir()
    shutil.copyfile(clip, folder / 'clip.webm')
    handler = ImageHandler(str(folder))
    try:
        root = handler.get_root_inode(0)
        entry = next(e for e in handler.get_directory_contents(0, root)
                     if e['name'] == 'clip.webm')
        stub = type('W', (), {'_listing_image': str(folder),
                              '_image_handlers': {}, 'image_handler':
                              handler})()
        device = MainWindow._listing_video_device(
            stub, {'inode_number': entry['inode_number'], 'start_offset': 0})
        assert device.isOpen() and device.size() == len(video)
        assert bytes(device.read(64)) == video[:64]
        device.close()
    finally:
        handler.close_resources()

    panel = CarvedFilesPanel()
    panel.content_reader = lambda row: video
    panel.resize(700, 400)
    try:
        panel.view_group.button(1).setChecked(True)       # Thumbnails
        panel.add_record({'name': '1a00.webm', 'type': 'webm',
                          'offset': 0x1a00, 'size': len(video),
                          'evidence_id': None, 'image_path': 'x',
                          'evidence_label': 'x', 'status': 'valid'})
        item = panel.gallery.item(0)
        assert pump(qapp, 15, lambda: not panel._video_items)
        # A frame now, not the video glyph: a pixmap icon has its size.
        assert item.icon().availableSizes()
    finally:
        panel.deleteLater()

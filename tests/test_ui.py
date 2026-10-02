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

    monkeypatch.setattr(vt.requests, 'Session', Session)
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


def test_quick_triage_carving_keeps_nothing_in_a_case(qapp, stubbed_dialogs):
    """Without a case, carving still works -- for the session, in the
    per-user folder, one folder per image."""
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
        assert os.path.basename(os.path.dirname(row['path'])) == '11-carve-fat.dd'
        assert os.path.isfile(row['path'])
        window.preview_carved(row)
        pump(qapp, 0.5)
        assert (window.current_selected_data or {}).get('is_carved')
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
    pump(qapp, 0.5)

    index = window.indicators_panel.index
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
    pump(qapp, 0.5)
    panel = window.indicators_panel
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
    pump(qapp, 0.3)
    shown = {panel.values_table.item(r, 0).text()
             for r in range(panel.values_table.rowCount())}
    assert shown == {r['value'] for r in index.indicators('ip', second)}

    # A value's files are that image's, and preview from that image.
    panel.values_table.selectRow(0)
    pump(qapp, 0.3)
    assert panel.files_table.rowCount()
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
    pump(qapp, 0.3)

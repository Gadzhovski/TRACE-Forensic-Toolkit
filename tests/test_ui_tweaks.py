"""Interface size, text zoom, the system theme, command search, a layout
per screen setup, and About's links."""

import pytest


# --- interface size --------------------------------------------------------

def test_the_interface_size_sets_the_qt_scale_factor(monkeypatch):
    from trace_app.infra import ui_scale
    monkeypatch.delenv('QT_SCALE_FACTOR', raising=False)
    monkeypatch.delenv('TRACE_UI_SCALE_SET', raising=False)
    assert ui_scale.apply_env('150%') == 1.5
    import os
    assert os.environ['QT_SCALE_FACTOR'] == '1.5'
    # Ours: a later start with another size replaces it (a restart).
    assert ui_scale.apply_env('125%') == 1.25
    assert ui_scale.apply_env('100%') == 1.0
    assert 'QT_SCALE_FACTOR' not in os.environ
    # The examiner's own variable wins over the setting.
    monkeypatch.setenv('QT_SCALE_FACTOR', '2')
    assert ui_scale.apply_env('125%') == 2.0
    assert os.environ['QT_SCALE_FACTOR'] == '2'
    assert ui_scale.step('100%', +1) == '110%'
    assert ui_scale.step('200%', +1) == '200%'
    assert ui_scale.step('80%', -1) == '80%'
    assert ui_scale.factor('nonsense') == 1.0


# --- text zoom ---------------------------------------------------------------

@pytest.fixture
def themed(qapp):
    from trace_app.infra.theme import stylesheet_for
    before = qapp.styleSheet()
    qapp.setStyleSheet(stylesheet_for('dark'))
    yield qapp
    qapp.setStyleSheet(before)


def _wheel(widget, up=True):
    from PySide6.QtCore import QPoint, QPointF, Qt
    from PySide6.QtGui import QWheelEvent
    from PySide6.QtWidgets import QApplication
    event = QWheelEvent(QPointF(5, 5), QPointF(5, 5), QPoint(0, 0),
                        QPoint(0, 120 if up else -120), Qt.NoButton,
                        Qt.ControlModifier, Qt.NoScrollPhase, False)
    QApplication.sendEvent(widget, event)


def test_ctrl_wheel_and_keys_zoom_one_view_and_are_remembered(themed):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem
    from tests.conftest import pump
    from trace_app.ui.widgets import item_views, text_zoom
    item_views.install(themed)
    table = QTableWidget(2, 2)
    table.setObjectName('zoomTestTable')
    table.setItem(0, 0, QTableWidgetItem('text'))
    table.show()
    pump(themed, 0.2)
    start = table.font().pixelSize()
    rows = table.verticalHeader().defaultSectionSize()
    for _ in range(3):
        _wheel(table.viewport())
    pump(themed, 0.1)
    assert text_zoom.step_of(table) == 3
    assert table.font().pixelSize() == 18 > start
    assert table.verticalHeader().defaultSectionSize() >= rows
    QTest.keyClick(table, Qt.Key_Minus, Qt.ControlModifier)
    assert text_zoom.step_of(table) == 2
    # Remembered for that kind of view: a new one opens at that size.
    another = QTableWidget(1, 1)
    another.setObjectName('zoomTestTable')
    another.show()
    pump(themed, 0.2)
    assert text_zoom.step_of(another) == 2
    QTest.keyClick(table, Qt.Key_0, Qt.ControlModifier)
    assert text_zoom.step_of(table) == 0
    assert table.property(text_zoom.PROPERTY) is None
    # The hex view keeps its own font size.
    from PySide6.QtWidgets import QWidget, QVBoxLayout
    holder = QWidget()
    holder.setObjectName('hexBytesPanel')
    hex_table = QTableWidget(1, 1, holder)
    QVBoxLayout(holder).addWidget(hex_table)
    assert text_zoom.zoomable(hex_table.viewport()) is None
    for widget in (table, another, holder):
        widget.deleteLater()


# --- the system's theme ----------------------------------------------------------

def test_match_system_follows_the_colour_scheme(monkeypatch):
    from trace_app.infra import theme
    monkeypatch.setattr(theme, 'system_theme', lambda: 'dark')
    assert theme.resolve(theme.SYSTEM) == 'dark'
    monkeypatch.setattr(theme, 'system_theme', lambda: 'light')
    assert theme.resolve(theme.SYSTEM) == 'light'
    theme.save_theme(theme.SYSTEM)
    assert theme.read_choice() == theme.SYSTEM
    assert theme.read_theme() == 'light'
    theme.save_theme('dark')
    assert theme.read_choice() == 'dark' == theme.read_theme()
    theme.save_theme('light')


# --- command search ------------------------------------------------------------

def test_a_command_is_found_by_name_and_run(qapp):
    from PySide6.QtGui import QAction, QActionGroup
    from PySide6.QtWidgets import QMainWindow
    from trace_app.ui.dialogs.command_search import (CommandSearch,
                                                     commands, matches)
    window = QMainWindow()
    tools = window.menuBar().addMenu("&Tools")
    ran = []
    verify = tools.addAction("&Verify Image")
    verify.triggered.connect(lambda: ran.append('verify'))
    off = tools.addAction("Start Carving...")
    off.setEnabled(False)
    off.setToolTip("No image loaded")
    off.triggered.connect(lambda: ran.append('carve'))
    sub = tools.addMenu("Rules")
    sub.addAction("YARA Rules...")
    group = QActionGroup(window)
    radio = QAction("Dark Mode", window, checkable=True)
    group.addAction(radio)
    tools.addAction(radio)
    found = commands(window.menuBar())
    paths = [path for _a, path in found]
    assert paths == ['Tools ▸ Verify Image', 'Tools ▸ Start Carving',
                     'Tools ▸ Rules ▸ YARA Rules']
    assert [p for _a, p in matches('verify', found)] == \
        ['Tools ▸ Verify Image']
    assert [p for _a, p in matches('rules yara', found)] == \
        ['Tools ▸ Rules ▸ YARA Rules']
    dialog = CommandSearch(window.menuBar(), window)
    dialog.search.setText('verif')
    dialog._run_item(dialog.results.currentItem())
    assert ran == ['verify'] and dialog.ran is verify
    dialog = CommandSearch(window.menuBar(), window)
    dialog.search.setText('carving')
    item = dialog.results.item(0)
    assert item.toolTip() == 'No image loaded'
    dialog._run_item(item)
    assert ran == ['verify']                # disabled: not run
    window.deleteLater()


# --- a layout per screen setup ---------------------------------------------------

def test_each_screen_setup_keeps_its_layout():
    from trace_app.infra import window_state as ws
    laptop = ws.screen_signature([('eDP-1', 0, 0, 1920, 1080)])
    docked = ws.screen_signature([('eDP-1', 0, 0, 1920, 1080),
                                  ('DP-2', 1920, 0, 3840, 2160)])
    assert laptop != docked
    ws.save_window_state(b'laptop-geometry', b'laptop-state', laptop)
    ws.save_window_state(b'docked-geometry', b'docked-state', docked)
    assert ws.read_window_state(laptop) == (b'laptop-geometry',
                                            b'laptop-state')
    assert ws.read_window_state(docked) == (b'docked-geometry',
                                            b'docked-state')
    # A setup never seen: the last layout kept.
    other = ws.screen_signature([('HDMI-1', 0, 0, 1280, 1024)])
    assert ws.read_window_state(other) == (b'docked-geometry',
                                           b'docked-state')
    ws.forget_window_state()
    assert ws.read_window_state(laptop) == (None, None)


# --- About -------------------------------------------------------------------------

def test_about_links_the_website_and_the_source(qapp):
    from PySide6.QtWidgets import QLabel
    from trace_app.ui.dialogs.about import SOURCE, WEBSITE, AboutDialog
    dialog = AboutDialog()
    links = dialog.findChild(QLabel, 'aboutLinks')
    assert WEBSITE in links.text() and SOURCE in links.text()
    assert links.openExternalLinks()
    dialog.deleteLater()


# --- Check for Updates -----------------------------------------------------------

class _Answer:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


class _GitHub:
    """A stand-in for requests: records what was asked, answers as told."""

    def __init__(self, status=200, data=None):
        self.asked, self.status, self.data = [], status, data or {}

    def get(self, url, **kwargs):
        self.asked.append((url, kwargs))
        return _Answer(self.status, self.data)


def test_versions_compare_as_releases_do():
    from trace_app.core.updates import newer, parse_version
    assert newer('2.3.0', '2.2.0') and newer('v2.10.0', '2.9.9')
    assert not newer('2.2.0', '2.2.0') and not newer('2.1.9', '2.2.0')
    assert newer('2.3.0', '2.3.0-rc1') and not newer('2.3.0-rc1', '2.3.0')
    assert newer('2.3.0-rc2', '2.3.0-rc1')
    assert parse_version('nightly') is None and not newer('nightly', '2.2.0')


def test_the_newest_release_is_asked_of_github_only(monkeypatch):
    from trace_app import __version__
    from trace_app.core import settings, updates
    monkeypatch.setattr(settings, 'network_refusal', lambda kind='': None)
    monkeypatch.setattr(settings, 'user',
                        lambda key: True if key == 'check_updates' else None)
    github = _GitHub(data={'tag_name': 'v99.0.0', 'published_at':
                           '2030-01-02T00:00:00Z', 'html_url':
                           'https://github.com/x/releases/tag/v99.0.0'})
    ask = updates.latest
    release = ask(github)
    assert release['version'] == '99.0.0'
    url, kwargs = github.asked[0]
    assert url == updates.LATEST_URL
    # What is sent: TRACE's version in the User-Agent, nothing else.
    assert kwargs['headers']['User-Agent'] == \
        f'TRACE/{__version__} (update check)'
    assert 'params' not in kwargs and 'data' not in kwargs
    monkeypatch.setattr(updates, 'latest', lambda: release)
    status, text, _ = updates.check()
    assert status == 'newer' and '99.0.0 is available' in text
    monkeypatch.setattr(updates, 'latest',
                        lambda: dict(release, version=__version__))
    assert updates.check()[0] == 'current'
    for answer in (_GitHub(status=404), _GitHub(status=500),
                   _GitHub(data={'tag_name': 'nightly'})):
        try:
            ask(answer)
        except updates.UpdateError:
            pass
        else:
            raise AssertionError("an unusable answer was accepted")


def test_nothing_is_asked_when_offline_or_turned_off(monkeypatch):
    from trace_app.core import settings, updates
    github = _GitHub(data={'tag_name': 'v99.0.0'})
    monkeypatch.setattr(settings, 'user',
                        lambda key: True if key == 'check_updates' else None)
    monkeypatch.setattr(settings, 'network_refusal',
                        lambda kind='': "This case is offline")
    status, text, _ = updates.check()
    assert status == 'error' and 'offline' in text
    try:
        updates.latest(github)
    except updates.UpdateError:
        pass
    assert github.asked == []
    monkeypatch.setattr(settings, 'network_refusal', lambda kind='': None)
    monkeypatch.setattr(settings, 'user', lambda key: False)
    assert 'turned off' in (updates.refusal() or '')


def test_about_checks_and_shows_the_answer(qapp, monkeypatch):
    from PySide6.QtWidgets import QLabel
    from tests.conftest import pump
    from trace_app.core import updates
    from trace_app.ui.dialogs.about import AboutDialog
    monkeypatch.setattr(updates, 'refusal', lambda: None)
    monkeypatch.setattr(updates, 'check', lambda: (
        'newer', 'TRACE 99.0.0 is available.',
        {'url': 'https://github.com/x/releases/tag/v99.0.0'}))
    dialog = AboutDialog()
    try:
        assert dialog.update_button.isEnabled()
        dialog.check_for_updates()
        status = dialog.findChild(QLabel, 'aboutUpdateStatus')
        assert pump(qapp, 10, lambda: 'release page' in status.text())
        assert '99.0.0' in status.text() and status.property('state') == \
            'newer'
    finally:
        dialog.close()
        dialog.deleteLater()
    monkeypatch.setattr(updates, 'refusal', lambda: "This case is offline")
    dialog = AboutDialog()
    assert not dialog.update_button.isEnabled()
    assert 'offline' in dialog.update_button.toolTip()
    dialog.deleteLater()


def test_progress_of_a_large_image_reaches_the_bar(qapp):
    """Byte counts past a C int (62 GB of free space being indexed) cross
    the workers' signals and fill the job bar. IndexWorker.progressed was
    Signal(int, int, str): every report raised OverflowError and the run
    died at its unallocated-space step."""
    import time
    from trace_app.ui.viewers.search_panel import IndexWorker
    from trace_app.ui.widgets.job_bar import Job, JobBar
    done, total = 62_344_429_568, 70_000_000_000
    worker = IndexWorker('image', 'case', 1)
    received = []
    worker.progressed.connect(lambda *values: received.append(values))
    worker.on_progress(done, total, 'Unallocated space')
    assert received == [(done, total, 'Unallocated space')]

    bar = JobBar()
    bar.submit(Job('big', 'Indexing', lambda job: None))
    bar.report(done, total, 'Unallocated space')
    assert (bar.progress.value(), bar.progress.maximum()) == (8906, 10000)
    # A time left once the step has run a while.
    bar._current.phase_start = (time.monotonic() - 60, done // 2)
    bar.report(done, total, 'Unallocated space')
    assert bar.eta_label.text().startswith('about ')


def test_the_reopen_offer_waits_for_the_evidence(qapp, tmp_path, monkeypatch):
    """Reopening a case queues the evidence load and the "run modules?"
    offer together (app.main). Opening an image runs a nested event loop,
    which used to run the offer mid-load: a modal dialog over the loading
    bar, stuck at 20% until it was answered. The offer now waits for the
    load -- and does not come back once any module has run."""
    from PySide6.QtCore import QTimer
    from tests.conftest import image_path, pump
    from trace_app.core.case import Case
    from trace_app.ui import main_window as mw
    asked = []

    def choose(window, *args, **kwargs):
        asked.append((getattr(window, '_loading_case_evidence', False),
                      list(window._image_handlers)))
        return None
    monkeypatch.setattr(mw, 'choose_modules', choose)
    case = Case.create(str(tmp_path / 'case'), 'Reopen')
    evidence_id = case.add_evidence(image_path('8-jpeg-search.dd'), 'Disk')
    window = mw.MainWindow(case=case)
    try:
        QTimer.singleShot(0, window.offer_analysis_modules)   # as app.main
        pump(qapp, 60, until=lambda: asked)
        assert len(asked) == 1
        loading, opened = asked[0]
        assert not loading and opened, "offered before the evidence opened"
        # Once something has run (here: the activity module), no offer.
        case.set_user_activity_state(evidence_id, 'done', records=0)
        asked.clear()
        window.offer_analysis_modules()
        assert asked == []
    finally:
        window.cleanup_resources()

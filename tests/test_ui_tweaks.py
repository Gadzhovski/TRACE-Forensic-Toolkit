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

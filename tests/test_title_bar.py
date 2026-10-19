"""Windows' title bars in TRACE's theme (ui/widgets/title_bar.py): the
attributes asked of DWM per theme, and which windows get them. DWM itself
is replaced: the tests run offscreen, where no window has a handle."""

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QMainWindow, QWidget

from trace_app.ui.widgets import title_bar


def test_colours_are_colorrefs():
    assert title_bar.colorref('#3C3C3C') == 0x3C3C3C
    assert title_bar.colorref('#102030') == 0x302010     # 0x00BBGGRR


@pytest.fixture
def asked(monkeypatch):
    calls = []
    monkeypatch.setattr(title_bar, 'supported', lambda: True)
    monkeypatch.setattr(title_bar, '_set',
                        lambda hwnd, attribute, value:
                        calls.append((attribute, value)) or True)
    return calls


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_a_window_s_bar_takes_the_theme(qapp, asked, theme):
    window = QMainWindow()
    try:
        title_bar.theme_window(window, theme, active=True)
        colours = title_bar.COLOURS[theme]
        got = dict(asked)
        assert got[title_bar.DARK_MODE] == (theme == 'dark')
        assert got[title_bar.CORNERS] == title_bar.ROUND
        assert got[title_bar.CAPTION_COLOUR] == \
            title_bar.colorref(colours['caption'])
        assert got[title_bar.TEXT_COLOUR] == \
            title_bar.colorref(colours['text'])
        asked.clear()
        title_bar.theme_window(window, theme, active=False)
        assert dict(asked)[title_bar.TEXT_COLOUR] == \
            title_bar.colorref(colours['inactive'])
    finally:
        window.deleteLater()


def test_the_caption_is_the_menu_bar_s_colour():
    """Title and menu bar read as one header: the caption is the colour
    each theme gives QMenuBar."""
    import re
    from trace_app.infra.paths import resource_path
    for theme in ('dark', 'light'):
        with open(resource_path(f'styles/{theme}_theme.qss'),
                  encoding='utf-8') as handle:
            sheet = handle.read()
        rule = re.search(r'^QMenuBar \{([^}]*)\}', sheet, re.M).group(1)
        colour = re.search(r'background-color:\s*(#[0-9A-Fa-f]{6})',
                           rule).group(1)
        assert colour.upper() == title_bar.COLOURS[theme]['caption']


def test_only_windows_with_a_bar_are_themed(qapp, asked):
    parent = QWidget()
    child = QWidget(parent)
    frameless = QWidget(None, Qt.Window | Qt.FramelessWindowHint)
    popup = QWidget(None, Qt.Popup)
    dialog = QDialog()
    try:
        for widget in (child, frameless, popup):
            title_bar.theme_window(widget, 'dark')
        assert asked == []
        title_bar.theme_window(dialog, 'dark')
        assert asked
    finally:
        for widget in (parent, frameless, popup, dialog):
            widget.deleteLater()


def test_nothing_is_asked_offscreen(qapp, monkeypatch):
    called = []
    monkeypatch.setattr(title_bar, '_set', lambda *a: called.append(a))
    window = QMainWindow()
    try:
        assert not title_bar.supported()        # offscreen: no handles
        title_bar.theme_window(window, 'dark')
        title_bar.refresh('dark')
        assert called == []
    finally:
        window.deleteLater()

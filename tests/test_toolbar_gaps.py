"""Toolbar gaps take their look from the themes, not an inline style.

A gap widget must not paint: a bare QWidget picks up the content-surface
colour, which showed as a pale band across a toolbar. The themes make
#toolbarGap transparent; here a gap is drawn and compared with the same
toolbar drawn without it."""

import pytest

from PySide6.QtWidgets import QToolBar, QVBoxLayout, QWidget


def _toolbar_pixel(theme, with_gap):
    from trace_app.infra.theme import stylesheet_for
    from trace_app.ui.widgets import toolbars
    host = QWidget()
    # The stylesheet goes on the host, never the application: setting the
    # application's sheet again crashed later windows (test_layout).
    host.setStyleSheet(stylesheet_for(theme))
    layout = QVBoxLayout(host)
    toolbar = QToolBar()
    layout.addWidget(toolbar)
    if with_gap:
        gap = toolbars.stretch()
        assert gap.styleSheet() == ''
        assert gap.objectName() == 'toolbarGap'
        toolbar.addWidget(gap)
    host.resize(400, 60)
    host.ensurePolished()
    image = host.grab().toImage()
    point = toolbar.geometry().center()
    colour = image.pixelColor(point)
    host.deleteLater()
    return colour.name()


@pytest.mark.parametrize('theme', ['dark', 'light'])
def test_a_gap_shows_the_toolbar_behind_it(qapp, theme):
    assert (_toolbar_pixel(theme, with_gap=True)
            == _toolbar_pixel(theme, with_gap=False))


def test_a_toolbar_freed_before_its_deferred_alignment_is_left_alone(qapp):
    # A child added, then the toolbar deleted before the deferred
    # align_controls ran: the call must be dropped, not raise.
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QToolBar, QToolButton
    from tests.conftest import pump
    from trace_app.ui.widgets.toolbars import prepare_toolbar
    toolbar = prepare_toolbar(QToolBar())
    QToolButton(toolbar)                    # ChildAdded: alignment queued
    toolbar.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    pump(qapp, 0.1)                         # the queued call would run here

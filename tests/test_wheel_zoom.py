"""The wheel zooms the Timeline's histogram and its Lanes view alike
(ui/widgets/wheel_zoom, shared since the two copies were merged)."""

import datetime

import pytest
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QWheelEvent
from PySide6.QtWidgets import QApplication


def _wheel(widget, x, notches):
    event = QWheelEvent(QPointF(x, 20), QPointF(x, 20), QPoint(0, 0),
                        QPoint(0, 120 * notches), Qt.NoButton,
                        Qt.NoModifier, Qt.NoScrollPhase, False)
    QApplication.sendEvent(widget, event)


def _widgets():
    from trace_app.ui.viewers.timeline_lanes import LanesCanvas
    from trace_app.ui.viewers.timeline_panel import TimelineHistogram
    return [(TimelineHistogram, '_plot'), (LanesCanvas, 'plot')]


@pytest.mark.parametrize('index', [0, 1])
def test_the_wheel_zooms_around_the_pointer(qapp, index):
    widget_class, plot_name = _widgets()[index]
    widget = widget_class()
    widget.resize(600, 130)
    asked = []
    widget.zoom_requested.connect(lambda *args: asked.append(args))

    _wheel(widget, 100, 1)
    assert asked == []                     # no range yet: nothing to zoom

    widget.start = datetime.datetime(2026, 1, 1)
    plot = getattr(widget, plot_name)()
    middle = plot.left() + plot.width() / 2
    _wheel(widget, middle, 1)
    _wheel(widget, middle, -2)
    _wheel(widget, -50, 1)                 # left of the plot: its edge
    assert [round(f, 6) for f, _ in asked] == [0.5, 0.5, 0]
    assert [round(z, 6) for _, z in asked] == [round(1 / 1.5, 6),
                                               2.25, round(1 / 1.5, 6)]
    widget.deleteLater()

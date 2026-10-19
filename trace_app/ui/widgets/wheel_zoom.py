"""Zooming a time axis with the wheel: the Timeline's histogram and its
Lanes view share it."""

#: How much one wheel notch zooms; a touchpad's small steps zoom by as
#: much less.
NOTCH_FACTOR = 1.5


def zoom_on_wheel(widget, event, plot):
    """Emit `widget.zoom_requested(fraction, factor)` for a wheel event
    over `plot` (the drawn area, a QRect): `fraction` is where across it
    the pointer is (0..1), `factor` < 1 zooms in. Nothing before the
    widget has a range (`widget.start`) or for a sideways scroll."""
    if not widget.start:
        return
    steps = event.angleDelta().y() / 120.0
    if not steps:
        return
    fraction = min(1, max(0, (event.position().x() - plot.left())
                          / plot.width()))
    widget.zoom_requested.emit(fraction, NOTCH_FACTOR ** (-steps))
    event.accept()

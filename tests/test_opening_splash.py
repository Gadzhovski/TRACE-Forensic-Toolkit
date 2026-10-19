"""The card between the launcher and the window (ui/widgets/opening_splash.py)."""

from tests.conftest import close_window


def test_the_window_reports_its_build_in_order(qapp):
    from trace_app.ui.main_window import MainWindow
    steps = []
    window = MainWindow(progress=lambda fraction, step: steps.append(
        (fraction, step)))
    try:
        fractions = [fraction for fraction, _ in steps]
        assert len(steps) >= 5
        assert fractions == sorted(fractions)
        assert 0 < fractions[0] and fractions[-1] < 1
        assert all(step for _, step in steps)
    finally:
        close_window(window)


def test_the_bar_never_moves_back_and_stays_in_range(qapp):
    from trace_app.ui.widgets.opening_splash import OpeningSplash
    splash = OpeningSplash("Opening case “x”")
    splash.set_progress(0.5, "half")
    splash.set_progress(0.3, "earlier")
    assert splash.fraction == 0.5 and splash.step == "earlier"
    splash.set_progress(7)
    assert splash.fraction == 1.0
    splash.deleteLater()


def test_the_card_draws_the_transparent_logo_sharply(qapp):
    from PySide6.QtGui import QImage
    from trace_app.infra.paths import resource_path
    from trace_app.ui import icons
    from trace_app.ui.widgets.opening_splash import LOGO_SIZE, OpeningSplash
    # The launcher's logo, whose corners are see-through -- not the
    # white-backed Icons/logo.png the old card used.
    logo = QImage(resource_path(*icons.LOGO.split('/')))
    assert logo.pixelColor(0, 0).alpha() == 0
    splash = OpeningSplash("Starting quick triage")
    try:
        for ratio in (1.0, 2.0):
            pixmap = splash._logo_pixmap(ratio)
            # Reduced for the screen's own pixels, not scaled when drawn.
            assert pixmap.width() == round(LOGO_SIZE * ratio)
            assert pixmap.devicePixelRatio() == ratio
        image = splash.grab().toImage()
        assert not image.isNull() and image.width() >= LOGO_SIZE
    finally:
        splash.deleteLater()

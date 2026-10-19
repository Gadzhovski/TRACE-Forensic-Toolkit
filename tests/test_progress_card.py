"""Progress cards (ui/widgets/progress_card.py): the dialog that took
QProgressDialog's place, and what loading evidence says while it works."""

from tests.conftest import image_path, pump


def test_the_dialog_answers_as_qprogressdialog_did(qapp):
    from trace_app.ui.widgets.progress_card import ProgressDialog
    dialog = ProgressDialog("Starting…", "Cancel", 0, 200)
    try:
        dialog.setWindowTitle("Writing the case archive")
        assert dialog.title == "Writing the case archive"
        dialog.setValue(50)
        assert dialog.value() == 50 and dialog.fraction == 0.25
        # A value may go back (a dialog reused for a second pass).
        dialog.setValue(20)
        assert dialog.fraction == 0.1
        dialog.setRange(0, 0)
        assert dialog.fraction is None          # not known: a busy bar
        dialog.setLabelText("Hashing members\nfrom D:/case")
        assert dialog.labelText() == "Hashing members"
        assert dialog.about == "from D:/case"
        told = []
        dialog.canceled.connect(lambda: told.append(True))
        dialog._cancel.click()
        assert told == [True] and dialog.wasCanceled()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_it_waits_its_minimum_duration_then_shows(qapp):
    from trace_app.ui.widgets.progress_card import ProgressDialog
    dialog = ProgressDialog("Working…", None, 0, 10)
    try:
        dialog.setMinimumDuration(150)
        assert not dialog.isVisible()
        pump(qapp, 2, until=dialog.isVisible)
        assert dialog.isVisible()
        # Its frames run while the event loop does: a long step moves.
        phase = dialog._phase
        pump(qapp, 0.2)
        assert dialog._phase != phase
    finally:
        dialog.close()
        dialog.deleteLater()
    quick = ProgressDialog("Working…", None, 0, 10)
    quick.setMinimumDuration(5000)
    quick.close()                           # finished before it was due
    pump(qapp, 0.1)
    assert not quick.isVisible()
    quick.deleteLater()


def test_no_cancel_button_makes_a_smaller_card(qapp):
    from trace_app.ui.widgets.progress_card import ProgressDialog
    dialog = ProgressDialog("Working…", "Cancel", 0, 10)
    with_button = dialog.height()
    dialog.setCancelButton(None)
    assert dialog.height() < with_button and dialog._cancel.isHidden()
    dialog.deleteLater()


def test_a_long_step_wraps_to_two_lines():
    from PySide6.QtGui import QFont, QFontMetrics
    from trace_app.ui.widgets.progress_card import two_lines
    metrics = QFontMetrics(QFont())
    width = metrics.horizontalAdvance("x" * 30)
    assert two_lines(metrics, "short", width) == ["short"]
    text = "Volume 2 of 3: listing the root folder of Basic data partition " \
        "@ 1050624 and a great deal more that cannot fit anywhere at all"
    lines = two_lines(metrics, text, width)
    assert len(lines) == 2
    assert all(metrics.horizontalAdvance(line) <= width for line in lines)
    assert text.startswith(lines[0]) and lines[1].endswith("…")


def test_opening_evidence_names_each_step(qapp):
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.main_window import _HandlerOpener
    handler = ImageHandler(image_path('ntfs1-gen2.E01'))
    assert handler.loaded
    steps = []
    try:
        _HandlerOpener._warm(handler, lambda fraction, step:
                             steps.append((fraction, step)))
    finally:
        handler.close_resources()
    fractions = [fraction for fraction, _ in steps]
    assert fractions == sorted(fractions)
    assert 0 < fractions[0] and fractions[-1] <= _HandlerOpener.SHARE
    texts = [step for _, step in steps]
    assert texts[0] == "Reading the partition table…"
    # Each partition by number and name, and what is being read on it.
    assert any(text.startswith("Partition 1 of ") and "root folder" in text
               for text in texts)
    assert "Identifying the operating systems…" in texts


def test_the_slim_bar_answers_as_qprogressbar_did(qapp):
    from trace_app.ui.widgets.progress_card import SlimBar
    bar = SlimBar()
    bar.setRange(0, 10000)
    bar.setValue(8906)
    assert (bar.value(), bar.maximum()) == (8906, 10000)
    assert bar.text() == "89%"
    bar.setRange(0, 0)
    assert bar.fraction() is None and bar.text() == ""     # busy
    sentence = SlimBar(text='above')
    sentence.setFormat("Downloading iLEAPP (34 of 120 MB)")
    sentence.setTextVisible(True)
    sentence.setRange(0, 1000)
    sentence.setValue(283)
    assert sentence.text() == "Downloading iLEAPP (34 of 120 MB)"
    assert sentence.sizeHint().height() > bar.sizeHint().height()
    bar.deleteLater()
    sentence.deleteLater()


def test_the_slim_bar_animates_only_while_shown_and_working(qapp):
    from trace_app.ui.widgets.progress_card import SlimBar
    bar = SlimBar()
    bar.setRange(0, 100)
    bar.setValue(40)
    assert not bar._frames.isActive()           # not shown
    bar.show()
    assert bar._frames.isActive()
    bar.setValue(100)
    assert not bar._frames.isActive()           # done: still
    bar.setRange(0, 0)
    assert bar._frames.isActive()               # busy
    bar.hide()
    assert not bar._frames.isActive()
    bar.deleteLater()

"""Application entry point: logging, startup checks, and the main window."""

import logging
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from trace_app import __version__
from trace_app.infra.paths import log_file
from trace_app.infra.theme import apply_theme
from trace_app.infra.preflight import (
    check_dependencies, format_report, libmagic_identity)
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.dialogs.case_launcher import TRIAGE, choose_case
from trace_app.ui.main_window import MainWindow


def configure_logging():
    """Send diagnostics to a log file as well as the console.

    A packaged build runs windowed, so sys.stdout is None and anything printed
    is lost. The log file is the only place errors survive for an end user to
    report.
    """
    handlers = [logging.StreamHandler(sys.stdout)] if sys.stdout else []
    try:
        handlers.append(logging.FileHandler(log_file(), encoding='utf-8'))
    except OSError:
        pass  # a read-only home should not stop the app from starting

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        handlers=handlers,
    )

    # Third-party libraries are chatty at DEBUG (PIL logs every plugin import).
    # Keep the log readable for someone diagnosing a TRACE problem.
    for noisy in ('PIL', 'matplotlib', 'urllib3'):
        logging.getLogger(noisy).setLevel(logging.WARNING)


#: Windows groups taskbar buttons by this ID, and shows the icon of the
#: windows that carry it. Without one the process is "python.exe" and the
#: taskbar shows Python's icon.
APP_USER_MODEL_ID = 'TRACE.ForensicToolkit'


def set_taskbar_identity():
    """Give the process TRACE's own taskbar identity -- before any window
    exists, or the first one (the case launcher) is grouped as Python."""
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            APP_USER_MODEL_ID)
    except (AttributeError, OSError) as exc:
        logging.getLogger('TRACE').debug("No taskbar identity: %s", exc)


def main():
    configure_logging()
    set_taskbar_identity()
    logging.getLogger('TRACE').info("Starting TRACE %s on %s", __version__, sys.platform)
    from trace_app.infra.capabilities import log_unavailable
    log_unavailable()
    magic_id = libmagic_identity()
    if magic_id:
        logging.getLogger('TRACE').info("libmagic %s from %s", *magic_id)

    app = QApplication(sys.argv)
    app.setApplicationName("TRACE")
    app.setApplicationDisplayName("TRACE")
    app.setOrganizationName("TRACE")
    app.setApplicationVersion(__version__)
    # Every window's icon, the launcher's included, and the taskbar's.
    app.setWindowIcon(icons.icon(icons.LOGO))

    # Report missing system libraries once, by name, instead of letting them
    # surface later as an unhandled exception inside a Qt slot.
    missing = check_dependencies()
    if missing:
        logging.getLogger('TRACE').warning("Missing dependencies: %s",
                                           ", ".join(n for n, _, _ in missing))
        message.warning(
            None, "Missing dependencies",
            "TRACE started, but some features will not work:\n\n"
            + format_report(missing))

    # Theme first, before any window exists. Applying it from inside
    # MainWindow meant the launcher -- the first thing an examiner sees -- was
    # drawn by the platform instead, dark on a dark desktop whatever they had
    # chosen last time.
    theme = apply_theme(app)
    icons.set_theme(theme)

    # Ask what kind of session this is before building anything. Someone
    # handed a USB stick who wants to know what is on it should not have to
    # name an investigation first, so quick triage leads to exactly the
    # application TRACE was before cases existed.
    case = choose_case()
    if case is None:
        logging.getLogger('TRACE').info("Launcher dismissed; not starting")
        return 0

    window = MainWindow(case=None if case is TRIAGE else case)
    window.show_on_start()

    # Once the window is up and the case's evidence has been reopened, ask
    # what to examine. Deferred by a beat so the offer lands on a drawn
    # window rather than over a half-built one.
    if case is not TRIAGE:
        QTimer.singleShot(0, window.offer_analysis_modules)

    return app.exec()

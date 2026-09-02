from trace_app.ui.dialogs import message
"""Application entry point: logging, startup checks, and the main window."""

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from trace_app import __version__
from trace_app.infra.paths import log_file
from trace_app.infra.preflight import check_dependencies, format_report
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


def main():
    configure_logging()
    logging.getLogger('TRACE').info("Starting TRACE %s on %s", __version__, sys.platform)

    app = QApplication(sys.argv)
    app.setApplicationName("TRACE")
    app.setApplicationDisplayName("TRACE")
    app.setOrganizationName("TRACE")
    app.setApplicationVersion(__version__)

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

    window = MainWindow()
    window.show()
    return app.exec()

"""TRACE - Toolkit for Retrieval and Analysis of Cyber Evidence."""

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from modules.mainwindow import MainWindow
from modules.paths import log_file
from modules.preflight import check_dependencies, format_report

__version__ = "1.2.0"


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
        QMessageBox.warning(
            None, "Missing dependencies",
            "TRACE started, but some features will not work:\n\n"
            + format_report(missing))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == '__main__':
    sys.exit(main())

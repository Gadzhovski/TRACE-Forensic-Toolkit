"""Application entry point: logging, startup checks, and the main window."""

import logging
import os
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

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
    route_qt_messages()


#: Qt categories whose warnings describe the evidence, not TRACE: a damaged
#: JPEG ("Bogus marker length") is what carved and deleted pictures are.
EVIDENCE_CATEGORIES = ('qt.gui.imageio',)

#: (category, text) of Qt warnings that are noise, kept at DEBUG. Text
#: from evidence holding a character the font lacks makes Qt search every
#: installed font for it; Windows' legacy bitmap fonts (8514oem, Fixedsys,
#: Terminal, MS Sans Serif...) cannot be opened through DirectWrite, and
#: each logs "CreateFontFaceFromHDC() failed" -- while the character is
#: drawn from another font all the same.
NOISE = (('qt.qpa.fonts', 'CreateFontFaceFromHDC'),)


def qt_level(level, category, text):
    """The log level for one Qt message: DEBUG for warnings about the
    evidence (EVIDENCE_CATEGORIES) and for known noise (NOISE)."""
    if category.startswith(EVIDENCE_CATEGORIES) or any(
            category == noisy and part in text for noisy, part in NOISE):
        return logging.DEBUG
    return level


def route_qt_messages():
    """Qt's own messages into TRACE's log (logger 'TRACE.Qt').

    They went to stderr, which a packaged build does not have, so they were
    lost there -- and in a console they arrived without a time, unlike every
    other line. Warnings about damaged evidence are kept at DEBUG.
    """
    from PySide6.QtCore import QtMsgType, qInstallMessageHandler
    qt_log = logging.getLogger('TRACE.Qt')
    levels = {QtMsgType.QtDebugMsg: logging.DEBUG,
              QtMsgType.QtInfoMsg: logging.INFO,
              QtMsgType.QtWarningMsg: logging.WARNING,
              QtMsgType.QtCriticalMsg: logging.ERROR,
              QtMsgType.QtFatalMsg: logging.CRITICAL}

    def handler(kind, context, text):
        category = getattr(context, 'category', None) or ''
        level = qt_level(levels.get(kind, logging.WARNING), category, text)
        qt_log.log(level, "%s%s", f"{category}: " if category else '', text)

    qInstallMessageHandler(handler)


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


def _opening_splash(case):
    """The card saying what is opening, with a bar the window's build moves
    (ui/widgets/opening_splash.py), shown before the window is built."""
    from trace_app.ui.widgets.opening_splash import OpeningSplash
    splash = OpeningSplash(f"Opening case “{case.name}”" if case is not None
                           else "Starting quick triage")
    splash.start()
    return splash


def _restart_setup(text):
    """What a new case's wizard asked for, handed over a restart as JSON
    (File > Switch Case > New Case); None when there is nothing or it
    cannot be read."""
    if not text:
        return None
    import json
    try:
        setup = json.loads(text)
    except ValueError:
        logging.getLogger('TRACE').warning(
            "The new case's setup could not be read after the restart")
        return None
    return setup if isinstance(setup, dict) else None


def main():
    configure_logging()
    # The examiner's own settings: size units, the log's detail.
    from trace_app.core import settings
    settings.apply_user()
    # Interface size: Qt reads its scale factor when the application object
    # is made, so it is set before (infra/ui_scale.py).
    from trace_app.infra import ui_scale
    ui_scale.apply_env()
    set_taskbar_identity()
    logging.getLogger('TRACE').info("Starting TRACE %s on %s", __version__, sys.platform)
    # A crash in C leaves no log line: say so now if the last session did,
    # and make sure this one leaves its stack (infra/crash_log.py).
    from trace_app.infra import crash_log
    crash_log.report_previous()
    crash_log.enable()
    from trace_app.infra.capabilities import log_unavailable
    log_unavailable()
    magic_id = libmagic_identity()
    if magic_id:
        logging.getLogger('TRACE').info("libmagic %s from %s", *magic_id)

    app = QApplication(sys.argv)
    # One scrolling and column behaviour for every view, the launcher's too.
    from trace_app.ui.widgets import item_views
    item_views.install(app)
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
    # Restarted (View > Interface Size, File > Switch Case, a case
    # archive opened): straight into the case or quick triage chosen, with
    # what a new case's wizard asked for.
    reopen = os.environ.pop('TRACE_REOPEN_CASE', '')
    triage = os.environ.pop('TRACE_QUICK_TRIAGE', '') == '1'
    setup = _restart_setup(os.environ.pop('TRACE_CASE_SETUP', ''))
    if reopen and os.path.isdir(reopen):
        from trace_app.core.case import Case
        try:
            case = Case.open(reopen)
        except Exception as exc:
            logging.getLogger('TRACE').warning(
                "Could not reopen %s after the restart: %s", reopen, exc)
            case, setup = choose_case()
    elif triage:
        case, setup = TRIAGE, None
    else:
        case, setup = choose_case()
    if case is None:
        logging.getLogger('TRACE').info("Launcher dismissed; not starting")
        return 0

    # Building the window takes a second or two (every panel, then the
    # case's counts): say so at once, where the launcher was, rather than
    # leave a gap with nothing on screen.
    splash = _opening_splash(None if case is TRIAGE else case)
    app.setOverrideCursor(Qt.WaitCursor)
    try:
        window = MainWindow(case=None if case is TRIAGE else case,
                            progress=splash.set_progress)
        splash.set_progress(0.9, "Opening the window…")
        window.show_on_start()
    except BaseException:
        splash.close()
        raise
    finally:
        app.restoreOverrideCursor()
    splash.finish()

    # Is there a newer TRACE? Asked once, a few seconds on, unless turned
    # off (Settings ▸ Privacy & Network) or the case is offline.
    window.check_for_update_at_start()

    # A new case from the wizard: queue what it asked for (verification,
    # then the modules) once its evidence is open -- deferred by a beat so
    # it lands on a drawn window. A reopened case is not asked anything:
    # the wizard is where modules are chosen, and Analysis Modules in the
    # menu runs more. (Reopening offered the dialog whenever nothing had
    # run yet -- every time, for a case kept only for browsing.)
    if setup is not None:
        QTimer.singleShot(0, lambda: window.start_case_setup(setup))

    try:
        code = app.exec()
    finally:
        # Live disks' helpers stop when their connection closes.
        from trace_app.core.live_disk import close_all
        close_all()
    request = getattr(window, 'restart_request', None)
    if request:
        # MainWindow.restart from a terminal: this window has closed (the
        # case saved, its audit line written); the next TRACE runs now.
        window.deleteLater()
        from PySide6.QtCore import QCoreApplication, QEvent
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        return run_again(*request)
    return code


def has_console():
    """Whether TRACE was started from a terminal it writes to (never in a
    packaged windowed build: no stdout there)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and stream.isatty():
                return True
        except (AttributeError, ValueError, OSError):
            continue
    return False


def run_again(program, arguments, environment):
    """Run the next TRACE in this terminal and give back its exit code.
    macOS/Linux: this process becomes it (exec). Windows has no exec --
    os.execv there starts another process and returns the prompt, the very
    thing this avoids -- so this one waits for it."""
    logging.getLogger('TRACE').info("Starting TRACE again")
    if sys.platform != 'win32':
        logging.shutdown()
        os.execve(program, [program] + list(arguments), environment)
    import subprocess
    try:
        return subprocess.call([program] + list(arguments), env=environment)
    except KeyboardInterrupt:
        return 130

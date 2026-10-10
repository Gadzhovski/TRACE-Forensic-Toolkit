"""Case ▸ Export Case Archive… and Open Case Archive… (core/case_archive).

The files are written and checked on a thread with a progress dialog that
can cancel; everything that touches a case's database runs on this thread,
which owns the connection.
"""

import logging
import os

from PySide6.QtCore import QEventLoop, Qt, QThread, Signal
from PySide6.QtWidgets import QFileDialog, QProgressDialog

from trace_app.core import case_archive
from trace_app.ui.dialogs import message

logger = logging.getLogger('TRACE.CaseArchive')


class _Work(QThread):
    progressed = Signal(object, object, str)
    failed = Signal(str)

    def __init__(self, function, parent=None):
        super().__init__(parent)
        self.function = function
        self.result = None
        self.error = None
        self.cancelled = False

    def run(self):
        try:
            self.result = self.function(
                lambda done, total, what: self.progressed.emit(done, total,
                                                               what),
                lambda: self.cancelled)
        except case_archive.ArchiveCancelled:
            self.cancelled = True
        except Exception as exc:          # reported by the caller
            logger.warning("Case archive: %s", exc)
            self.error = exc


def _run(parent, title, function):
    """Run `function(progress, should_stop)` on a thread behind a progress
    dialog. Returns its result; None when cancelled; raises its error."""
    dialog = QProgressDialog(title, "Cancel", 0, 1000, parent)
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.WindowModal)
    dialog.setMinimumDuration(300)
    dialog.setAutoClose(False)
    dialog.setAutoReset(False)
    work = _Work(function, parent)

    def moved(done, total, what):
        dialog.setValue(int(done * 1000 / total) if total else 0)
        dialog.setLabelText(f"{title}\n{what}")

    work.progressed.connect(moved)
    dialog.canceled.connect(lambda: setattr(work, 'cancelled', True))
    loop = QEventLoop()
    work.finished.connect(loop.quit)
    work.start()
    loop.exec()
    work.wait()
    # Closing a progress dialog emits canceled: not the examiner's cancel.
    dialog.canceled.disconnect()
    dialog.close()
    dialog.deleteLater()
    if work.error is not None:
        raise work.error
    return None if work.cancelled else work.result


def _readable(size):
    from trace_app.infra.utils import FileSystemUtils
    return FileSystemUtils.get_readable_size(size)


def export_case_archive(parent, case):
    """Ask where, whether to include the search index, and write it.
    Returns write_archive's summary, or None."""
    from trace_app.core import settings
    start = os.path.join(settings.user('case_folder') or
                         os.path.dirname(case.folder),
                         f"{case.name or 'case'}{case_archive.SUFFIX}")
    path, _filter = QFileDialog.getSaveFileName(
        parent, "Export Case Archive", start,
        f"TRACE case archive (*{case_archive.SUFFIX})")
    if not path:
        return None
    include_index = False
    index = os.path.join(case.folder, 'search.db')
    if os.path.exists(index):
        include_index = message.question(
            parent, "Export Case Archive",
            f"Include the search index ({_readable(os.path.getsize(index))})?",
            "Without it the archive is smaller; whoever opens it rebuilds "
            "the index by running the indexing module again.")
    details = case_archive.archive_details(case)
    try:
        made = _run(parent, "Writing the case archive",
                    lambda progress, stop: case_archive.write_archive(
                        details, path, include_index, progress, stop))
    except Exception as exc:
        message.critical(parent, "Export Case Archive",
                         "The archive could not be written.", str(exc))
        return None
    if made is None:
        return None
    case_archive.record_archive(case, made)
    message.information(
        parent, "Export Case Archive",
        f"The case was written to {made['path']}.",
        f"{made['members']} file(s), {_readable(made['size'])}.\n"
        f"SHA-256 {made['sha256']} (also in the .sha256 file beside it).\n"
        "The evidence itself is not in the archive: it is referred to by "
        "path and hash. Where it is not found, Case ▸ Evidence ▸ Locate… "
        "points the case at it once its hashes match.")
    return made


def open_case_archive(parent):
    """Pick an archive and a folder for the case, check and unpack it, and
    open it. Returns the open Case, or None."""
    from trace_app.core import settings
    path, _filter = QFileDialog.getOpenFileName(
        parent, "Open Case Archive", settings.user('case_folder') or '',
        f"TRACE case archive (*{case_archive.SUFFIX});;All files (*)")
    if not path:
        return None
    try:
        manifest = case_archive.read_manifest(path)
    except case_archive.ArchiveError as exc:
        message.warning(parent, "Open Case Archive", str(exc))
        return None
    where = QFileDialog.getExistingDirectory(
        parent, "Folder to put the case in",
        settings.user('case_folder') or os.path.dirname(path))
    if not where:
        return None
    name = os.path.splitext(os.path.basename(path))[0]
    folder = os.path.join(where, name)
    suffix = 2
    while os.path.exists(folder) and os.listdir(folder):
        folder = os.path.join(where, f"{name} ({suffix})")
        suffix += 1
    try:
        unpacked = _run(parent, "Checking and unpacking the case archive",
                        lambda progress, stop: case_archive.unpack_archive(
                            path, folder, progress, stop))
        if unpacked is None:
            return None
        case = case_archive.open_unpacked(path, folder, unpacked)
    except Exception as exc:
        message.critical(parent, "Open Case Archive",
                         "The archive was not opened.", str(exc))
        return None
    intact, text = case_archive.audit_status(case, manifest)
    missing = case_archive.missing_evidence(case)
    notes = [f"Unpacked into {folder}; every file matched the archive's "
             f"manifest.", text]
    if missing:
        notes.append(f"{len(missing)} piece(s) of evidence are not where "
                     f"the case recorded them: Case tab ▸ right-click ▸ "
                     f"Locate… points the case at each once its hashes "
                     f"match.")
    (message.information if intact else message.warning)(
        parent, "Open Case Archive",
        f"Opened {case.name or 'the case'} from the archive.",
        '\n\n'.join(notes))
    return case

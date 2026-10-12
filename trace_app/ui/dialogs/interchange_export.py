"""Case ▸ Export for Other Tools: DFXML (one image's files) and CASE/UCO
JSON-LD (the case, its evidence, files and findings), core/interchange.

Written on a thread behind a progress dialog, from a read-only
connection of its own; the file's SHA-256 is audited."""

import hashlib
import logging
import os
import sqlite3

from PySide6.QtWidgets import QFileDialog, QInputDialog

from trace_app import __version__
from trace_app.core import interchange
from trace_app.ui.dialogs import message
from trace_app.ui.dialogs.case_archive import _run

logger = logging.getLogger('TRACE.Interchange')

#: kind -> (menu text, dialog title, extension, filter).
KINDS = {
    'dfxml': ("DFXML (Files of One Image)…", "Export DFXML", '.xml',
              "DFXML (*.xml *.dfxml)"),
    'case': ("CASE/UCO JSON-LD (Case, Files and Findings)…",
             "Export CASE/UCO", '.jsonld', "JSON-LD (*.jsonld *.json)"),
}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _choose_evidence(parent, case):
    """The image to export; None if cancelled. One image: no question."""
    rows = case.evidence()
    if not rows:
        message.information(parent, "Export DFXML",
                            "The case holds no evidence.")
        return None
    if len(rows) == 1:
        return rows[0]
    names = [f"{row.get('display_name') or os.path.basename(row['path'])}"
             f"  (#{row['id']})" for row in rows]
    choice, ok = QInputDialog.getItem(parent, "Export DFXML",
                                      "DFXML describes one image. Which?",
                                      names, 0, False)
    return rows[names.index(choice)] if ok else None


def export_for_tools(parent, case, kind, path=None, evidence=None):
    """Ask where, write, audit. Returns the path written, or None."""
    menu_text, title, extension, pattern = KINDS[kind]
    if kind == 'dfxml' and evidence is None:
        evidence = _choose_evidence(parent, case)
        if evidence is None:
            return None
    if path is None:
        stem = 'case' if kind == 'case' else os.path.splitext(
            os.path.basename(evidence['path']))[0]
        default = os.path.join(case.exports_dir, stem + extension)
        os.makedirs(os.path.dirname(default), exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(parent, title, default,
                                              pattern)
        if not path:
            return None
    database = os.path.join(case.folder, 'case.db')
    name, folder = case.name, case.folder

    def work(progress, should_stop):
        progress(0, 1, os.path.basename(path))
        connection = sqlite3.connect(f'file:{database}?mode=ro', uri=True,
                                     timeout=10)
        try:
            if kind == 'dfxml':
                return interchange.write_dfxml(connection, evidence['id'],
                                               path, __version__)
            return interchange.write_case_uco(connection, path, name, folder,
                                              __version__)
        finally:
            connection.close()

    try:
        count = _run(parent, title, work)
    except interchange.NothingToExport as exc:
        message.information(parent, title, str(exc).capitalize() + ".")
        return None
    except Exception as exc:
        logger.error("%s failed: %s", title, exc)
        message.warning(parent, title, f"The export failed: {exc}")
        return None
    if count is None:                     # cancelled
        return None
    what = f"evidence id={evidence['id']} " if evidence else ''
    label = 'DFXML' if kind == 'dfxml' else 'CASE/UCO'
    case.record_event(f"exported as {label}",
                      f"{what}files={count} path={path} "
                      f"sha256={_sha256(path)}")
    message.information(parent, title,
                        f"{count:,} file(s) written to {path}.")
    return path

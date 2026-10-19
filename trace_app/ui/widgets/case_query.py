"""One read of the case database on a thread, for the panels that list
what a module stored (Activity, Conversations, hash matches, NTFS,
persistence).

Each read opens its own read-only connection (the window's belongs to its
thread; SQLite refuses it elsewhere) and closes it, then emits
`loaded(generation, result)`; the panel drops a result whose generation is
not its newest. A read that fails is logged and answered with `empty`, so
the panel shows nothing rather than stale rows. Keep the thread in a
KeptThreads until it has finished (ui/widgets/kept_threads)."""

import logging
import os
import sqlite3

from PySide6.QtCore import QThread, Signal

from trace_app.core.case import CASE_DB_NAME
from trace_app.infra.sqlite_uri import connect_read_only

logger = logging.getLogger('TRACE.CaseQuery')


class CaseQuery(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, query, empty, what, parent=None):
        """`query(connection)` -> the result; `what` names it in the log
        ("Could not read <what>")."""
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.query, self.empty, self.what = query, empty, what

    def run(self):
        result = self.empty
        try:
            connection = connect_read_only(
                os.path.join(self.folder, CASE_DB_NAME))
            try:
                result = self.query(connection)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read %s: %s", self.what, exc)
        self.loaded.emit(self.generation, result)

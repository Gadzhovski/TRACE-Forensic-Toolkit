"""Background worker threads."""

from PySide6.QtCore import QThread, Signal


class ExportWorker(QThread):
    """Export files and folders from one image (core/evidence_export.py):
    streamed, hashed as written, the copy checked, a manifest beside them.
    The window records the export in the case's audit trail from `done`.
    """

    #: Bytes written so far.
    progress = Signal(object)
    status_update = Signal(str)
    #: {'files', 'bytes', 'problems', 'manifest', 'manifest_sha256',
    #:  'folder', 'cancelled', 'error'}
    done = Signal(dict)

    def __init__(self, image_handler, items, dest_dir, evidence_name):
        super().__init__()
        self.image_handler = image_handler
        self.items = list(items)
        self.dest_dir = dest_dir
        self.evidence_name = evidence_name
        self._written = 0

    def _bytes(self, count):
        self._written += count
        self.progress.emit(self._written)

    def run(self):
        from trace_app.core.evidence_export import ExportCancelled, Exporter
        exporter = Exporter(self.image_handler, self.dest_dir,
                            self.evidence_name,
                            should_stop=self.isInterruptionRequested,
                            progress=self._bytes,
                            status=self.status_update.emit)
        out = {'folder': self.dest_dir, 'cancelled': False, 'error': '',
               'manifest': '', 'manifest_sha256': ''}
        try:
            exporter.export(self.items)
        except ExportCancelled:
            out['cancelled'] = True
        except Exception as exc:
            out['error'] = str(exc)
        # What was exported is recorded even when the run was cancelled
        # or failed part-way: those copies exist.
        try:
            out['manifest'], out['manifest_sha256'] = \
                exporter.write_manifest()
        except Exception as exc:
            out['error'] = '; '.join(filter(None, (
                out['error'], f"the manifest could not be written: {exc}")))
        out.update(exporter.summary())
        self.done.emit(out)

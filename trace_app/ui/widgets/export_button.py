"""A toolbar button that saves the current view as text, PDF or HTML.

The Hex viewer had an Export button offering text and HTML; the Text viewer had
no export at all. Both now share this control, so the same formats are
available wherever content is being read.

The caller supplies the content as plain text plus a title. Rendering to PDF is
done here rather than in each viewer, so the three formats stay consistent.
"""

import html as html_module
import logging
import os

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction, QPageLayout, QPageSize, QTextDocument
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import QFileDialog, QMessageBox, QMenu, QToolButton

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.dialogs import message

logger = logging.getLogger('TRACE.Export')

#: Monospaced stack used for the PDF and HTML renderings, so column alignment
#: in hex dumps survives the export.
MONO_STACK = "'Consolas', 'Courier New', monospace"


class ExportButton(QToolButton):
    """Icon button whose menu offers Text, PDF and HTML.

    `content_provider` is called with no arguments and returns the text to
    write, or None when there is nothing to export.
    """

    def __init__(self, content_provider, title="Export", parent=None):
        super().__init__(parent)
        self._provider = content_provider
        self._title = title

        self.setObjectName("exportButton")
        # Registered rather than set directly: an icon set with
        # icons.icon() keeps its light-theme tint forever, which left the
        # save glyph near-black and invisible on a dark toolbar.
        icons.apply_to(self, icons.SAVE_AS)
        self.setToolTip("Export the current view as text, PDF or HTML")
        self.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))

        # DelayedPopup, not InstantPopup: InstantPopup makes Qt reserve room
        # inside the button for a menu arrow, which squeezed an 18px icon into
        # a 28px button and pushed it off centre. The menu is opened from
        # mousePressEvent instead, so the whole button is the icon.
        self.setPopupMode(QToolButton.DelayedPopup)

        menu = QMenu(self)
        for label, suffix in (("Text (*.txt)", "txt"),
                              ("PDF (*.pdf)", "pdf"),
                              ("HTML (*.html)", "html")):
            action = QAction(label, self)
            action.triggered.connect(lambda _=False, s=suffix: self.export(s))
            menu.addAction(action)
        self.setMenu(menu)

    def mousePressEvent(self, event):
        """Open the menu on any click, without a menu-arrow indicator."""
        if event.button() == Qt.LeftButton and self.menu():
            self.showMenu()
            event.accept()
            return
        super().mousePressEvent(event)

    # --- export ------------------------------------------------------------

    def export(self, suffix):
        content = self._provider()
        if not content:
            message.warning(self, "Nothing to export",
                                "There is no content to export yet.")
            return

        filters = {
            'txt': "Text Files (*.txt)",
            'pdf': "PDF Files (*.pdf)",
            'html': "HTML Files (*.html)",
        }
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export as {suffix.upper()}", "", filters[suffix])
        if not path:
            return  # cancelled

        if not path.lower().endswith('.' + suffix):
            path += '.' + suffix

        try:
            if suffix == 'txt':
                self._write_text(path, content)
            elif suffix == 'pdf':
                self._write_pdf(path, content)
            else:
                self._write_html(path, content)
        except OSError as e:
            logger.error("Export to %s failed: %s", path, e)
            message.critical(self, "Export failed", f"Could not write the file:\n{e}")
            return

        message.information(self, "Exported",
                                f"Saved to {os.path.basename(path)}.")

    def _write_text(self, path, content):
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(f"{self._title}\n\n{content}")

    def _write_html(self, path, content):
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(self._as_html(content))

    def _write_pdf(self, path, content):
        """Render through QTextDocument, which paginates for us."""
        document = QTextDocument()
        document.setHtml(self._as_html(content))

        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(path)
        printer.setPageSize(QPageSize(QPageSize.A4))
        printer.setPageOrientation(QPageLayout.Portrait)
        document.print_(printer)

    def _as_html(self, content):
        """Wrap plain content in a minimal, self-contained document.

        Colours are fixed rather than themed: the output is a file that will be
        read outside the application, usually printed on white.
        """
        return (
            "<!DOCTYPE html>\n<html><head><meta charset='utf-8'>"
            f"<title>{html_module.escape(self._title)}</title></head>"
            "<body style=\"font-family: sans-serif; color: #212529;\">"
            f"<h2 style=\"margin-bottom: 4px;\">{html_module.escape(self._title)}</h2>"
            "<p style=\"color: #6b7480; font-size: small; margin-top: 0;\">"
            "Exported by TRACE</p>"
            f"<pre style=\"font-family: {MONO_STACK}; font-size: 10pt; "
            "white-space: pre-wrap; word-wrap: break-word;\">"
            f"{html_module.escape(content)}</pre>"
            "</body></html>"
        )

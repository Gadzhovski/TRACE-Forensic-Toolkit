"""HTML from evidence, rendered offline.

A browser engine is the wrong tool for a page taken from a suspect's disk. It
runs the page's scripts, and it fetches the page's remote images, stylesheets
and fonts -- and a fetch is a message to whoever controls that server that the
page has been opened, from this machine's address, now. Tracking pixels exist
to do exactly that.

So this uses Qt's rich-text engine, which has no JavaScript, and overrides its
resource loading so that nothing is fetched at all: not from the network, and
not from local disk either, where a relative path would otherwise resolve
against wherever TRACE happens to be running. Images embedded in the page as
`data:` URIs are decoded, because they are part of the evidence; everything
else is counted and reported as blocked. Links are not followed.

The same viewer shows Office documents, which document_preview turns into
static HTML.
"""

import base64
import logging
from urllib.parse import unquote_to_bytes

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QImage, QTextDocument
from PySide6.QtWidgets import QLabel, QTextBrowser, QVBoxLayout, QWidget

logger = logging.getLogger('TRACE.Viewer.Html')

#: Larger pages are cut here. Qt's rich-text layout is single-threaded and
#: slows sharply on very long documents; the Text tab still has all of it.
MAX_HTML_CHARS = 5 * 1024 * 1024

#: Applied to every page and document shown here. A page is shown as a page:
#: dark text on white whatever the application theme, because pages are
#: written for that, and a page that sets only its text colour would vanish
#: on a dark background.
_BASE_CSS = """
body { color: #1f2328; background-color: #ffffff; }
h1 { font-size: 20px; } h2 { font-size: 16px; margin-top: 14px; }
h3 { font-size: 14px; }
table { border-collapse: collapse; margin: 6px 0; }
td, th { border: 1px solid #d0d7de; padding: 3px 6px; }
th { background-color: #f6f8fa; color: #57606a; font-weight: normal; }
td.formula { color: #0969da; }
pre { font-family: Consolas, 'Courier New', monospace; font-size: 12px; }
p.item { margin-left: 12px; }
p.flag, span.flag { color: #9a6700; }
p.comment { background-color: #fff8c5; padding: 4px; }
div.notes { background-color: #f6f8fa; padding: 4px; margin: 4px 0 10px 0; }
span.deleted { color: #cf222e; text-decoration: line-through; }
span.inserted { color: #1a7f37; text-decoration: underline; }
"""


class _OfflineBrowser(QTextBrowser):
    """A QTextBrowser that loads nothing from anywhere but the page itself."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("documentPage")
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.setSearchPaths([])
        self.blocked = []

    def loadResource(self, kind, url):
        if url.scheme() == 'data':
            data = _decode_data_url(url.toString())
            if data is not None:
                if kind == QTextDocument.ImageResource:
                    image = QImage.fromData(data)
                    return image if not image.isNull() else None
                return data
        target = url.toString()
        if target and target not in self.blocked:
            self.blocked.append(target)
        return None


def _decode_data_url(text):
    """The bytes of a `data:` URI, or None if it is malformed."""
    try:
        header, _, payload = text.partition(',')
        if ';base64' in header:
            return base64.b64decode(payload, validate=False)
        return unquote_to_bytes(payload)
    except Exception:
        return None


class SafeHtmlViewer(QWidget):
    """Shows HTML with scripts and every external resource disabled."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.notice = QLabel()
        self.notice.setObjectName("viewerNotice")
        self.notice.setWordWrap(True)
        self.notice.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.notice)

        self.browser = _OfflineBrowser(self)
        self.browser.anchorClicked.connect(self._link_clicked)
        layout.addWidget(self.browser, 1)

    def display(self, markup, kind_text, extra_notes=(), from_evidence=True):
        """Show `markup`; `kind_text` names it in the notice ("HTML page").

        `from_evidence` is False for HTML TRACE built itself (an Office
        document read into static HTML): there are no scripts or remote
        resources in it to speak of, so the notice does not mention them.
        """
        self.browser.blocked = []
        truncated = len(markup) > MAX_HTML_CHARS
        if truncated:
            markup = markup[:MAX_HTML_CHARS]

        document = self.browser.document()
        document.setDefaultStyleSheet(_BASE_CSS)
        # A base URL nothing can resolve against: relative links and images
        # stay relative, and reach loadResource -- where they are refused --
        # instead of being looked up beside the TRACE executable.
        document.setBaseUrl(QUrl('trace-evidence:/'))
        self.browser.setHtml(markup)
        # Images are requested during layout, not by setHtml. Lay the document
        # out now, at the width it will be shown, so every resource it asks
        # for has been asked for -- and refused -- before the count below.
        document.setTextWidth(max(self.browser.viewport().width(), 400))
        document.documentLayout().documentSize()

        if from_evidence:
            notes = [f"{kind_text} — shown offline: scripts do not run and "
                     f"nothing is fetched from the network or disk."]
        else:
            # The caller's notes already say what it is.
            notes = []
        blocked = len(self.browser.blocked)
        if blocked:
            notes.append(f"{blocked} external resource"
                         f"{'s were' if blocked != 1 else ' was'} not loaded.")
        if truncated:
            notes.append("Only the first 5 MB is shown; the Text tab has the "
                         "rest.")
        notes.extend(n for n in extra_notes if n)
        self.notice.setText(' '.join(notes))
        self.notice.setToolTip('\n'.join(self.browser.blocked[:50]))

    def clear(self):
        self.browser.clear()
        self.browser.blocked = []
        self.notice.clear()

    def _link_clicked(self, url):
        """Same-page anchors scroll; anything else is shown, not followed."""
        if url.hasFragment() and (not url.scheme()
                                  or url.scheme() == 'trace-evidence'):
            self.browser.scrollToAnchor(url.fragment())
            return
        self.notice.setText(f"Link not followed: {url.toString()}")

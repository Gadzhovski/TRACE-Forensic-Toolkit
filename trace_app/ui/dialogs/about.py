"""The About dialog."""

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from trace_app import __version__
from trace_app.infra.constants import BUTTON_WIDTH, CONTROL_HEIGHT
from trace_app.ui import icons

#: Rendered size of the logo. The source art is 1024x1024, so this is a
#: reduction and stays sharp; it is also doubled for the device pixel ratio
#: below, which keeps it crisp on a hi-DPI display.
LOGO_SIZE = 160

WEBSITE = "https://trace.gadzhovski.com"
SOURCE = "https://github.com/Gadzhovski/TRACE-Forensic-Toolkit"


class UpdateCheck(QThread):
    """core/updates.check() off the UI thread (a network request)."""

    answered = Signal(str, str, str)        # status, message, release URL

    def run(self):
        from trace_app.core import updates
        status, text, release = updates.check()
        self.answered.emit(status, text, (release or {}).get('url', ''))


class AboutDialog(QDialog):
    """Application name, version and author."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("About TRACE")
        self.setObjectName("aboutDialog")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(0)

        layout.addWidget(self._logo(), 0, Qt.AlignCenter)
        layout.addSpacing(20)

        name = QLabel("TRACE", self)
        name.setObjectName("aboutTitle")
        name.setAlignment(Qt.AlignCenter)
        layout.addWidget(name)

        subtitle = QLabel("Toolkit for Retrieval and Analysis of Cyber Evidence", self)
        subtitle.setObjectName("aboutSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addSpacing(18)

        version = QLabel(f"Version {__version__}", self)
        version.setObjectName("aboutMeta")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)

        author = QLabel("Radoslav Gadzhovski", self)
        author.setObjectName("aboutMeta")
        author.setAlignment(Qt.AlignCenter)
        layout.addWidget(author)

        licence = QLabel("Released under the MIT License", self)
        licence.setObjectName("aboutMetaQuiet")
        licence.setAlignment(Qt.AlignCenter)
        layout.addWidget(licence)

        layout.addSpacing(10)
        # Opened in the examiner's browser when clicked; TRACE fetches
        # nothing itself.
        links = QLabel(
            f'<a href="{WEBSITE}">trace.gadzhovski.com</a>'
            f' &nbsp;·&nbsp; <a href="{SOURCE}">Source on GitHub</a>', self)
        links.setObjectName("aboutLinks")
        links.setAlignment(Qt.AlignCenter)
        links.setTextFormat(Qt.RichText)
        links.setTextInteractionFlags(Qt.TextBrowserInteraction)
        links.setOpenExternalLinks(True)
        links.setToolTip(WEBSITE)
        layout.addWidget(links)

        # Is there a newer TRACE? Asked of GitHub only when clicked, and
        # never when checking is off or the open case is offline
        # (core/updates.py).
        layout.addSpacing(14)
        self.update_button = QPushButton("Check for Updates", self)
        self.update_button.setObjectName("aboutUpdateButton")
        icons.apply_to(self.update_button, icons.REFRESH)
        self.update_button.clicked.connect(self.check_for_updates)
        update_row = QHBoxLayout()
        update_row.addStretch()
        update_row.addWidget(self.update_button)
        update_row.addStretch()
        layout.addLayout(update_row)
        self.update_status = QLabel(self)
        self.update_status.setObjectName("aboutUpdateStatus")
        self.update_status.setAlignment(Qt.AlignCenter)
        self.update_status.setWordWrap(True)
        self.update_status.setTextFormat(Qt.RichText)
        self.update_status.setOpenExternalLinks(True)
        self.update_status.hide()
        layout.addSpacing(6)
        layout.addWidget(self.update_status)
        self._check = None
        from trace_app.core import updates
        why = updates.refusal()
        if why:
            self.update_button.setEnabled(False)
            self.update_button.setToolTip(why)

        layout.addSpacing(24)

        buttons = QHBoxLayout()
        buttons.addStretch()
        close_button = QPushButton("Close", self)
        close_button.setFixedSize(BUTTON_WIDTH, CONTROL_HEIGHT)
        close_button.setDefault(True)
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.setFixedWidth(420)

    def check_for_updates(self):
        from trace_app.core import updates
        why = updates.refusal()
        if why:
            self._show_update('error', why, '')
            return
        self.update_button.setEnabled(False)
        self._show_update('checking', "Asking GitHub for the newest "
                          "release…", '')
        check = UpdateCheck(self)
        check.answered.connect(self._show_update)
        check.finished.connect(lambda: self.update_button.setEnabled(True))
        self._check = check
        check.start()

    def _show_update(self, status, text, url):
        from html import escape
        if status == 'newer':
            text = (f"{escape(text)}<br><a href=\"{escape(url)}\">"
                    f"Download it from the release page</a>")
        else:
            text = escape(text)
        self.update_status.setProperty('state', status)
        self.update_status.style().unpolish(self.update_status)
        self.update_status.style().polish(self.update_status)
        self.update_status.setText(text)
        self.update_status.show()
        self.adjustSize()

    def done(self, result):
        # The request has its own timeout; wait for it rather than drop a
        # running thread (Qt aborts on that).
        if self._check is not None and self._check.isRunning():
            self._check.wait(15000)
        super().done(result)

    def closeEvent(self, event):
        if self._check is not None and self._check.isRunning():
            self._check.wait(15000)
        super().closeEvent(event)

    def _logo(self):
        """The application logo, rendered from the full-resolution source.

        This previously asked the icon registry for a 24x24 pixmap and then
        scaled that up to 400x400 -- a 16x enlargement of a thumbnail, which is
        why it looked blocky. Loading the file directly uses all the
        pixels of the source (500x500), and rendering at the device pixel ratio keeps it
        sharp on a hi-DPI screen.
        """
        label = QLabel(self)
        label.setAlignment(Qt.AlignCenter)

        ratio = self.devicePixelRatioF() or 1.0
        source = QPixmap(icons.path(icons.LOGO))
        if source.isNull():
            return label

        pixmap = source.scaled(
            int(LOGO_SIZE * ratio), int(LOGO_SIZE * ratio),
            Qt.KeepAspectRatio, Qt.SmoothTransformation)
        pixmap.setDevicePixelRatio(ratio)
        label.setPixmap(pixmap)
        label.setFixedHeight(LOGO_SIZE)
        return label

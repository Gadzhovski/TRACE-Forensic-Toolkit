"""The About dialog."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from trace_app import __version__
from trace_app.infra.constants import BUTTON_WIDTH, CONTROL_HEIGHT
from trace_app.ui import icons

#: Rendered size of the logo. The source art is 1024x1024, so this is a
#: reduction and stays sharp; it is also doubled for the device pixel ratio
#: below, which keeps it crisp on a hi-DPI display.
LOGO_SIZE = 160


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

    def _logo(self):
        """The application logo, rendered from the full-resolution source.

        This previously asked the icon registry for a 24x24 pixmap and then
        scaled that up to 400x400 -- a 16x enlargement of a thumbnail, which is
        why it looked blocky. Loading the file directly uses all 1024x1024
        pixels of the source, and rendering at the device pixel ratio keeps it
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

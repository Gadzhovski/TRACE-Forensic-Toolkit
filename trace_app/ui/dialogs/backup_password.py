"""The password of an encrypted iTunes/Finder backup an external module
(iLEAPP) is to read.

Asked when a run found the backup encrypted (core/modules/inputs): the job
checks it against the backup's keybag before the tool sees it, so a wrong
one comes back here with `wrong` set. Kept for the session only, never in
the case.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QLabel,
                               QLineEdit, QVBoxLayout)

from trace_app.ui import icons


class BackupPasswordDialog(QDialog):
    """An encrypted backup's password -- or, with `what` and `title`, a key
    another tool wants (DLEAPP's Signal key), given as a file to it."""

    def __init__(self, tool, evidence, backup, wrong='', parent=None,
                 what=None, title="Encrypted Backup"):
        super().__init__(parent)
        self.setWindowTitle(title)
        # The unlock dialog's look (both themes style these names).
        self.setObjectName("bitlockerDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        intro = QLabel(
            f"{_escape(tool)} found <b>{_escape(backup)}</b> on "
            f"{_escape(evidence)}. Give {_escape(what)} to let it read "
            f"that too." if what else
            f"<b>{_escape(backup)}</b> on {_escape(evidence)} is an "
            f"encrypted iTunes/Finder backup. Give its password to let "
            f"{_escape(tool)} read it.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)
        note = QLabel(
            f"TRACE gives it to {tool} in a file of the run's own, removed "
            "when the run ends -- never on its command line. It is kept "
            "for this session only: never in the case, its log or the "
            "tool's run log." if what else
            "TRACE checks the password against the backup first. "
            f"{tool} takes it on its command line, so other programs "
            "running as you on this computer can see it while it runs. "
            "It is kept for this session only: never in the case, its log "
            "or the tool's run log.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.field = QLineEdit()
        self.field.setEchoMode(QLineEdit.Password)
        self.field.setPlaceholderText("Key or password" if what
                                      else "Backup password")
        layout.addWidget(self.field)
        show = QCheckBox("Show password")
        show.toggled.connect(lambda on: self.field.setEchoMode(
            QLineEdit.Normal if on else QLineEdit.Password))
        layout.addWidget(show)
        self.error = QLabel(wrong)
        self.error.setObjectName("bitlockerError")
        self.error.setWordWrap(True)
        self.error.setVisible(bool(wrong))
        layout.addWidget(self.error)
        buttons = QDialogButtonBox()
        self.run_button = buttons.addButton(
            "Run Again" if what else "Read Backup",
            QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self):
        if self.field.text():
            self.accept()

    def password(self):
        return self.field.text()


def _escape(text):
    import html
    return html.escape(str(text))

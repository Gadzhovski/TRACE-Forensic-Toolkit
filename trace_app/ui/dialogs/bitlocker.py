"""Unlocking a BitLocker volume: the key the examiner has, and nothing kept.

Three ways in, as BitLocker itself offers them: the 48-digit recovery key
(the one an organisation escrows, or Microsoft's account page shows), the
user's password, or a .BEK startup key file from a USB stick. The dialog
says what the volume itself records -- its description, when it was
encrypted and which protectors it has -- so the examiner knows which to
look for.

The key stays in the window's memory for the session (background jobs get it
over their pipe) and is never written to the case: the audit line records
that a volume was unlocked and by which kind of key, not the key.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QTabWidget, QVBoxLayout, QWidget)

from trace_app.core.containers import ContainerError
from trace_app.ui import icons


class BitLockerDialog(QDialog):
    """Ask for a key and try it; `secret` holds what worked."""

    def __init__(self, handler, start_sector, volume_label, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock BitLocker Volume")
        self.setObjectName("bitlockerDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        self.handler = handler
        self.start_sector = start_sector
        #: {kind: secret} that unlocked the volume, for unlock_bitlocker().
        self.secret = None
        self.kind = None

        layout = QVBoxLayout(self)
        intro = QLabel(f"<b>{volume_label}</b> is encrypted with BitLocker. "
                       "Give a key to read it. The key is used for this "
                       "session only and is never saved in the case.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        facts = QFormLayout()
        try:
            info = handler.bitlocker_facts(start_sector)
        except Exception as exc:
            info = {'description': f'(unreadable: {exc})'}
        created = info.get('created')
        for label, value in (
                ("Description", info.get('description')),
                ("Encrypted", created.strftime('%Y-%m-%d %H:%M:%S UTC')
                 if created else None),
                ("Unlocks with", ', '.join(info.get('protectors') or [])),
                ("Cipher", info.get('method')),
                ("Volume ID", info.get('identifier'))):
            if value:
                text = QLabel(str(value))
                text.setTextInteractionFlags(Qt.TextSelectableByMouse)
                facts.addRow(f"{label}:", text)
        layout.addLayout(facts)

        self.tabs = QTabWidget()
        self.recovery = QLineEdit()
        self.recovery.setPlaceholderText(
            "123456-123456-123456-123456-123456-123456-123456-123456")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.startup = QLineEdit()
        self.startup.setPlaceholderText("A .BEK file")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        startup_row = QWidget()
        row = QHBoxLayout(startup_row)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.startup, 1)
        row.addWidget(browse)
        for widget, label, hint in (
                (self.recovery, "Recovery key",
                 "The 48-digit recovery key, with or without dashes."),
                (self.password, "Password",
                 "The password the user types to unlock the drive."),
                (startup_row, "Startup key",
                 "The .BEK startup key file (often on a USB stick).")):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            note = QLabel(hint)
            note.setWordWrap(True)
            page_layout.addWidget(note)
            page_layout.addWidget(widget)
            page_layout.addStretch(1)
            self.tabs.addTab(page, label)
        layout.addWidget(self.tabs)

        self.error = QLabel()
        self.error.setObjectName("bitlockerError")
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        layout.addWidget(self.error)

        buttons = QDialogButtonBox()
        self.unlock_button = buttons.addButton("Unlock",
                                               QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._try)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Startup key", "", "BitLocker startup key (*.BEK *.bek);;"
                                     "All files (*)")
        if path:
            self.startup.setText(path)

    def _try(self):
        page = self.tabs.currentIndex()
        kind, value = (('recovery_password', self.recovery.text().strip()),
                       ('password', self.password.text()),
                       ('startup_key', self.startup.text().strip()))[page]
        if not value:
            self._show("Enter a key first.")
            return
        try:
            self.handler.unlock_bitlocker(self.start_sector, **{kind: value})
        except ContainerError as exc:
            self._show(str(exc))
            return
        except Exception as exc:                    # an unexpected library error
            self._show(f"The volume did not unlock: {exc}")
            return
        self.secret = {kind: value}
        self.kind = {'recovery_password': 'recovery key',
                     'password': 'password',
                     'startup_key': 'startup key file'}[kind]
        self.accept()

    def _show(self, text):
        self.error.setText(text)
        self.error.setVisible(True)

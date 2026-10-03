"""Unlocking an encrypted volume: the key the examiner has, and nothing kept.

BitLocker (recovery key, password or a .BEK startup key), FileVault 2
(password or recovery key), LUKS (passphrase) and encrypted APFS volumes
(password or recovery key). For BitLocker the dialog says what the volume
itself records -- its description, when it was encrypted, which protectors
it has -- so the examiner knows which key to look for.

The key stays in the window's memory for the session (background jobs get it
over their pipe) and is never written to the case: the audit line records
that a volume was unlocked and by which kind of key, not the key.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFileDialog,
                               QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QTabWidget, QVBoxLayout, QWidget)

from trace_app.core.containers import ContainerError, ENCRYPTION_NAMES
from trace_app.ui import icons

#: The keys each kind accepts: (secret name, tab label, hint, placeholder).
_KEYS = {
    'bitlocker': (
        ('recovery_password', "Recovery key",
         "The 48-digit recovery key, with or without dashes.",
         "123456-123456-123456-123456-123456-123456-123456-123456"),
        ('password', "Password",
         "The password the user types to unlock the drive.", ''),
        ('startup_key', "Startup key",
         "The .BEK startup key file (often on a USB stick).", 'A .BEK file'),
    ),
    'fvde': (
        ('password', "Password",
         "The password of a user allowed to unlock the Mac's disk.", ''),
        ('recovery_password', "Recovery key",
         "The FileVault recovery key (24 characters in groups of four).",
         'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX'),
    ),
    'luks': (
        ('password', "Passphrase",
         "A passphrase for one of the volume's key slots.", ''),
    ),
    'apfs': (
        ('password', "Password",
         "The volume's password (or a user's, on a Mac's system volume).",
         ''),
        ('recovery_password', "Recovery key",
         "The volume's recovery key.", ''),
    ),
}

_KIND_NAMES = {'recovery_password': 'recovery key', 'password': 'password',
               'startup_key': 'startup key file'}


class UnlockVolumeDialog(QDialog):
    """Ask for a key and try it; `secret` holds what worked."""

    def __init__(self, handler, start_sector, volume_label, parent=None,
                 kind='bitlocker'):
        super().__init__(parent)
        self.encryption = kind
        name = ENCRYPTION_NAMES.get(kind, kind)
        self.setWindowTitle(f"Unlock {name} Volume")
        self.setObjectName("bitlockerDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.setMinimumWidth(520)
        self.handler = handler
        self.start_sector = start_sector
        #: {kind of key: secret} that unlocked the volume.
        self.secret = None
        self.kind = None

        layout = QVBoxLayout(self)
        intro = QLabel(f"<b>{volume_label}</b> is encrypted with {name}. "
                       "Give a key to read it. The key is used for this "
                       "session only and is never saved in the case.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        if kind == 'bitlocker':
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
        self._fields = []
        for secret_name, label, hint, placeholder in _KEYS[kind]:
            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            if secret_name == 'password':
                field.setEchoMode(QLineEdit.Password)
            widget = field
            if secret_name == 'startup_key':
                widget = QWidget()
                row = QHBoxLayout(widget)
                row.setContentsMargins(0, 0, 0, 0)
                row.addWidget(field, 1)
                browse = QPushButton("Browse…")
                browse.clicked.connect(lambda _c=False, f=field:
                                       self._browse(f))
                row.addWidget(browse)
            page = QWidget()
            page_layout = QVBoxLayout(page)
            note = QLabel(hint)
            note.setWordWrap(True)
            page_layout.addWidget(note)
            page_layout.addWidget(widget)
            page_layout.addStretch(1)
            self.tabs.addTab(page, label)
            self._fields.append((secret_name, field))
        layout.addWidget(self.tabs)
        # Names kept for BitLocker's callers and tests.
        fields = dict(self._fields)
        self.recovery = fields.get('recovery_password')
        self.password = fields.get('password')
        self.startup = fields.get('startup_key')

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

    def _browse(self, field):
        path, _ = QFileDialog.getOpenFileName(
            self, "Startup key", "", "BitLocker startup key (*.BEK *.bek);;"
                                     "All files (*)")
        if path:
            field.setText(path)

    def _try(self):
        secret_name, field = self._fields[self.tabs.currentIndex()]
        value = field.text() if secret_name == 'password' else \
            field.text().strip()
        if not value:
            self._show("Enter a key first.")
            return
        try:
            if self.encryption == 'apfs':
                self.handler.unlock_apfs(self.start_sector,
                                         **{secret_name: value})
            else:
                self.handler.unlock_volume(self.start_sector, self.encryption,
                                           **{secret_name: value})
        except ContainerError as exc:
            self._show(str(exc))
            return
        except Exception as exc:                    # an unexpected library error
            self._show(f"The volume did not unlock: {exc}")
            return
        self.secret = {secret_name: value}
        self.kind = _KIND_NAMES.get(secret_name, secret_name)
        self.accept()

    def _show(self, text):
        self.error.setText(text)
        self.error.setVisible(True)


class BitLockerDialog(UnlockVolumeDialog):
    """The BitLocker case, under the name the window has always used."""

    def __init__(self, handler, start_sector, volume_label, parent=None):
        super().__init__(handler, start_sector, volume_label, parent,
                         'bitlocker')

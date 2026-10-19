"""Unlock a macOS keychain from the evidence and look at its secrets.

The Activity module lists keychain items as metadata only -- name,
account, where, times. This dialog is the explicit step past that: the
examiner gives the user's login password, the 24-byte master key, or the
SystemKey file (System.keychain), and may then reveal one item at a time.

Nothing decrypted is written anywhere: not the case, the log, the index
or the clipboard unless the examiner copies it. The audit trail records
that the keychain was unlocked and with what kind of key (never the key),
and each item revealed by name and account (never its value).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QDialog,
                               QDialogButtonBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPushButton,
                               QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core import keychain
from trace_app.ui import icons

#: Where macOS keeps the key that opens System.keychain.
SYSTEM_KEY_PATH = '/private/var/db/SystemKey'

_HIDDEN = '••••••'
_COLUMNS = ('Kind', 'Name', 'Account', 'Where', 'Created', 'Modified',
            'Secret')
_SECRET = _COLUMNS.index('Secret')


class KeychainDialog(QDialog):
    """`data`: the keychain file's bytes; `system_key`: the SystemKey
    file's bytes from the same evidence, or None; `record(action,
    detail)`: the case's audit line writer, or None in quick triage."""

    def __init__(self, data, name, path='', system_key=None, record=None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Keychain")
        self.setObjectName("keychainDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.resize(900, 560)
        self.path = path or name
        self.system_key = system_key
        self.record = record or (lambda action, detail='': None)
        self.store = keychain.Keychain(data)
        self.entries = self.store.entries()

        layout = QVBoxLayout(self)
        intro = QLabel(
            f"<b>{_escape(name)}</b> holds {len(self.entries):,} item(s). "
            "Give the user's login password, the keychain's master key or "
            "the SystemKey file to read the secrets. Secrets are shown "
            "here only and are never saved in the case; revealing one is "
            "written to the audit trail by its name, never its value.")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        self.tabs = QTabWidget()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("The user's login password")
        self.master = QLineEdit()
        self.master.setPlaceholderText("48 hexadecimal digits")
        self.key_file = QLineEdit()
        self.key_file.setPlaceholderText(
            "SystemKey from the evidence, or a file on this computer")
        self.tabs.addTab(_page("Unlocks a user's login.keychain (a keychain "
                               "made before macOS 10.12 may need its master "
                               "key instead).", self.password), "Password")
        self.tabs.addTab(_page("The 24-byte database key, as recovered from "
                               "memory or another tool.", self.master),
                         "Master key")
        key_row = QWidget()
        row = QHBoxLayout(key_row)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.key_file, 1)
        if system_key is not None:
            self.key_file.setText(f"{SYSTEM_KEY_PATH} (from the evidence)")
            self.key_file.setReadOnly(True)
        else:
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._browse)
            row.addWidget(browse)
        self.tabs.addTab(_page("Unlocks System.keychain: the SystemKey file "
                               "beside it on the evidence.", key_row),
                         "SystemKey")
        if system_key is not None and name.lower().startswith('system'):
            self.tabs.setCurrentIndex(2)
        layout.addWidget(self.tabs)

        unlock_row = QHBoxLayout()
        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.clicked.connect(self._unlock)
        unlock_row.addWidget(self.unlock_button)
        self.status = QLabel()
        self.status.setObjectName("keychainError")
        self.status.setWordWrap(True)
        unlock_row.addWidget(self.status, 1)
        layout.addLayout(unlock_row)

        self.table = QTableWidget(len(self.entries), len(_COLUMNS))
        self.table.setObjectName("keychainTable")
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        for row_number, entry in enumerate(self.entries):
            values = (entry.kind, entry.name, entry.account, entry.where,
                      _time(entry.created), _time(entry.modified), '')
            for column, value in enumerate(values):
                self.table.setItem(row_number, column,
                                   QTableWidgetItem(value or ''))
        self.table.resizeColumnsToContents()
        self.table.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.table, 1)

        buttons = QDialogButtonBox()
        self.reveal_button = buttons.addButton(
            "Reveal Secret", QDialogButtonBox.ActionRole)
        self.copy_button = buttons.addButton(
            "Copy Secret", QDialogButtonBox.ActionRole)
        self.hash_button = buttons.addButton(
            "Copy Hash for Cracking", QDialogButtonBox.ActionRole)
        self.hash_button.setToolTip(
            "The $keychain$ hash (hashcat mode 23100, John) for recovering "
            "the password offline. It holds no secret.")
        buttons.addButton(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        self.reveal_button.clicked.connect(self._reveal)
        self.copy_button.clicked.connect(self._copy)
        self.hash_button.clicked.connect(self._copy_hash)
        layout.addWidget(buttons)
        self._revealed = {}
        self._selection_changed()

    # --- unlocking ----------------------------------------------------------

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "SystemKey file")
        if path:
            self.key_file.setText(path)

    def _unlock(self):
        page = self.tabs.currentIndex()
        try:
            if page == 0:
                if not self.password.text():
                    return self._say("Enter the password first.")
                self.store.unlock(password=self.password.text())
                method = 'the login password'
            elif page == 1:
                text = self.master.text().strip().replace(' ', '')
                if not text:
                    return self._say("Enter the master key first.")
                self.store.unlock(master_key=text)
                method = 'a master key'
            else:
                key = self.system_key
                if key is None:
                    path = self.key_file.text().strip()
                    if not path:
                        return self._say("Choose the SystemKey file first.")
                    with open(path, 'rb') as handle:
                        key = handle.read()
                self.store.unlock(system_key=key)
                method = 'the SystemKey file'
        except (keychain.KeychainError, ValueError, OSError) as exc:
            self.record("keychain unlock refused",
                        f"{self.path}: {type(exc).__name__}")
            return self._say(f"The keychain did not unlock: {exc}")
        self.password.clear()
        self.master.clear()
        self.record("keychain unlocked", f"{self.path} with {method}")
        self._say(f"Unlocked with {method}. Select an item and reveal it.",
                  error=False)
        for widget in (self.password, self.master, self.key_file,
                       self.unlock_button):
            widget.setEnabled(False)
        self._selection_changed()

    def _say(self, text, error=True):
        self.status.setProperty('ok', not error)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setText(text)

    # --- secrets ------------------------------------------------------------

    def _current(self):
        rows = self.table.selectionModel().selectedRows()
        return rows[0].row() if rows else None

    def _selection_changed(self):
        row = self._current()
        password = row is not None and self.entries[row].kind.endswith(
            'password')
        self.reveal_button.setEnabled(self.store.unlocked and password)
        self.copy_button.setEnabled(self.store.unlocked and password)
        try:
            self.store.password_hash()
            has_hash = True
        except keychain.KeychainError:
            has_hash = False
        self.hash_button.setEnabled(has_hash)

    def _secret(self, row):
        if row in self._revealed:
            return self._revealed[row]
        entry = self.entries[row]
        try:
            raw = self.store.secret(entry)
        except keychain.KeychainError as exc:
            self._say(f"{entry.name or 'This item'}: {exc}")
            return None
        text = raw.decode('utf-8', 'replace') if raw else ''
        self._revealed[row] = text
        self.record("keychain secret viewed",
                    f"{self.path}: {entry.kind} '{entry.name or ''}' "
                    f"account '{entry.account or ''}'")
        return text

    def _reveal(self):
        row = self._current()
        if row is None:
            return
        text = self._secret(row)
        if text is None:
            return
        self.table.item(row, _SECRET).setText(text or '(empty)')

    def _copy(self):
        row = self._current()
        if row is None:
            return
        text = self._secret(row)
        if text:
            QApplication.clipboard().setText(text)
            self.table.item(row, _SECRET).setText(_HIDDEN + ' (copied)')

    def _copy_hash(self):
        try:
            QApplication.clipboard().setText(self.store.password_hash())
        except keychain.KeychainError as exc:
            self._say(str(exc))
            return
        self._say("Hash copied.", error=False)


def _page(text, widget):
    page = QWidget()
    layout = QVBoxLayout(page)
    note = QLabel(text)
    note.setWordWrap(True)
    layout.addWidget(note)
    layout.addWidget(widget)
    layout.addStretch(1)
    return page


def _time(value):
    return value.strftime('%Y-%m-%d %H:%M:%S') if value else ''


def _escape(text):
    from html import escape
    return escape(text or '')

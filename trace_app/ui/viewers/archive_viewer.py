"""The Archive tab: browse an archive found in evidence without unpacking it.

An archive in a disk image is a folder the examiner cannot open. Extracting it
to look inside changes the working set and has to be explained later, so this
reads members straight from the archive's bytes and shows them as a listing.

Nested archives are followed in place: opening a member that is itself an
archive pushes onto a breadcrumb trail rather than writing anything out. The
trail is how an examiner knows, and can later state, where a file was found --
"inside backup.zip, inside evidence.tar" is part of the finding.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QMenu, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from trace_app.core.archives import (ArchiveError, EncryptedArchive,
                                     archive_summary, detect_archive,
                                     list_members, read_member, MAX_NESTING)
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.Archive')


class ArchiveViewer(QWidget):
    """Lists an archive's members; double-click opens one."""

    #: Emitted with (name, bytes) when the user opens a non-archive member, so
    #: the host can show it in the ordinary viewers.
    member_opened = Signal(str, bytes)

    #: Emitted with a member dict when the user wants to bookmark one.
    bookmark_requested = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        #: Each level is (label, archive bytes). The last is what is shown.
        self._stack = []
        self._password = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(6)
        self.back_button = QPushButton("Back")
        self.back_button.setFixedHeight(CONTROL_HEIGHT)
        self.back_button.clicked.connect(self._go_back)
        top.addWidget(self.back_button)

        self.trail_label = QLabel()
        self.trail_label.setObjectName("archiveTrail")
        self.trail_label.setWordWrap(True)
        top.addWidget(self.trail_label, 1)
        layout.addLayout(top)

        self.summary_label = QLabel()
        self.summary_label.setObjectName("archiveSummary")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.table = QTableWidget()
        self.table.setObjectName("archiveTable")
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ['Name', 'Size', 'Compressed', 'Modified', 'Notes'])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.itemDoubleClicked.connect(self._open_selected)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table)

        self.clear_content()

    # --- entry points -----------------------------------------------------

    def display_archive(self, content, data):
        """Show `content` as an archive, or explain why it is not one."""
        name = (data or {}).get('name') or 'archive'
        self._password = None
        self._stack = []

        if not content:
            self._show_message("Nothing to read.")
            return

        kind = detect_archive(content)
        if kind is None:
            self._show_message(
                "This file is not an archive TRACE recognises.\n\n"
                "Supported: ZIP, TAR, GZIP, BZIP2, XZ and 7z.")
            return

        self._stack.append((name, content))
        self._render()

    def clear_content(self):
        self._stack = []
        self._password = None
        self._show_message(
            "Select an archive to browse its contents.\n\n"
            "ZIP, TAR, GZIP, BZIP2, XZ and 7z are read directly out of the "
            "image; nothing is extracted to disk.")

    # --- rendering --------------------------------------------------------

    def _show_message(self, text):
        self.summary_label.setText(text)
        self.table.setRowCount(0)
        self.table.setVisible(False)
        self.back_button.setVisible(False)
        self.trail_label.setText('')

    def _render(self):
        if not self._stack:
            self.clear_content()
            return

        label, data = self._stack[-1]
        self.trail_label.setText(" ▸ ".join(name for name, _ in self._stack))
        self.back_button.setVisible(len(self._stack) > 1)

        try:
            members = list_members(data, password=self._password)
        except EncryptedArchive as exc:
            self._show_message(
                f"{label} is encrypted.\n\n{exc}\n\n"
                "The archive's presence and size are still evidence; its "
                "contents cannot be listed without the password.")
            self.back_button.setVisible(len(self._stack) > 1)
            return
        except ArchiveError as exc:
            self._show_message(f"{label} could not be read.\n\n{exc}")
            self.back_button.setVisible(len(self._stack) > 1)
            return

        self.summary_label.setText(archive_summary(data))
        self.table.setVisible(True)
        self.table.setRowCount(len(members))

        for row, member in enumerate(members):
            notes = []
            if member['is_dir']:
                notes.append('folder')
            if member['encrypted']:
                notes.append('ENCRYPTED')
            if not member['is_dir'] and member['size'] > member['compressed_size'] * 100:
                notes.append('very high compression')

            values = [
                member['name'],
                f"{member['size']:,}" if not member['is_dir'] else '',
                f"{member['compressed_size']:,}" if not member['is_dir'] else '',
                member['modified'] or '',
                ', '.join(notes),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.UserRole, member)
                    if member['encrypted']:
                        cell.setToolTip(
                            "This member is encrypted. Its name and size are "
                            "readable; its contents are not.")
                self.table.setItem(row, column, cell)

        fit_columns(self.table, {0: 360})

    # --- navigation -------------------------------------------------------

    def _selected_member(self):
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), 0).data(Qt.UserRole)

    def _open_selected(self, _item=None):
        member = self._selected_member()
        if not member or member['is_dir']:
            return

        if member['encrypted'] and not self._password:
            self._ask_password()
            return

        _label, data = self._stack[-1]
        try:
            content = read_member(data, member['name'],
                                  password=self._password)
        except EncryptedArchive as exc:
            message.warning(self, "Encrypted", str(exc))
            self._ask_password()
            return
        except ArchiveError as exc:
            message.warning(self, "Could not read member", str(exc))
            return

        # A member that is itself an archive is browsed in place rather than
        # handed to a viewer that would show its compressed bytes.
        if detect_archive(content):
            if len(self._stack) >= MAX_NESTING:
                message.warning(
                    self, "Too deeply nested",
                    f"Archives are followed {MAX_NESTING} levels deep. "
                    f"Beyond that an archive is more likely constructed than "
                    f"collected.")
                return
            self._stack.append((member['name'], content))
            self._password = None
            self._render()
            return

        self.member_opened.emit(member['name'], content)

    def _go_back(self):
        if len(self._stack) > 1:
            self._stack.pop()
            self._password = None
            self._render()

    def _ask_password(self):
        from PySide6.QtWidgets import QInputDialog, QLineEdit

        password, ok = QInputDialog.getText(
            self, "Encrypted archive",
            "Password:", QLineEdit.Password)
        if ok and password:
            self._password = password
            self._render()

    # --- context menu -----------------------------------------------------

    def _context_menu(self, position):
        member = self._selected_member()
        if not member:
            return

        menu = QMenu(self)
        open_action = menu.addAction("Open")
        open_action.setEnabled(not member['is_dir'])
        bookmark_action = menu.addAction("Add Bookmark")
        action = menu.exec(self.table.viewport().mapToGlobal(position))

        if action == open_action:
            self._open_selected()
        elif action == bookmark_action:
            trail = " ▸ ".join(name for name, _ in self._stack)
            self.bookmark_requested.emit({
                **member,
                'archive_trail': f"{trail} ▸ {member['name']}",
            })

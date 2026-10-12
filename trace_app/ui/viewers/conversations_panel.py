"""Triage ▸ Conversations: messages and calls as threads per contact.

The activity module reads each messaging app on its own (core/activity);
core/conversations groups those rows into conversations. Here the threads
are listed on the left -- contact, app, how much, when last -- and the
chosen one is shown on the right as an exchange: sent on one side,
received on the other, calls and files between, recovered (deleted)
messages marked. A click on a message shows the database it was read
from; double-click goes to it. Export Conversation writes HTML and CSV.
"""

import logging
import os
import sqlite3

from PySide6.QtCore import QRect, QSize, Qt, QThread, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QSplitter, QStyle,
                               QStyledItemDelegate, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from trace_app.core import conversations
from trace_app.core.case import CASE_DB_NAME, query_user_activity

logger = logging.getLogger('TRACE.Conversations')

_THREAD_COLUMNS = ('Conversation', 'App', 'Items', 'Last (UTC)')
_ROW = Qt.UserRole
_BUBBLE_WIDTH = 0.72          # of the list's width
_PAD = 8


class _Load(QThread):
    """Reads the case's communication rows with its own connection."""
    loaded = Signal(int, object)

    def __init__(self, folder, generation, evidence_id, parent=None):
        super().__init__(parent)
        self.folder, self.generation, self.evidence_id = \
            folder, generation, evidence_id

    def run(self):
        rows = []
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                         timeout=10)
            try:
                rows = query_user_activity(connection, self.evidence_id,
                                           'communication')
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read messages: %s", exc)
        self.loaded.emit(self.generation, rows)


class _BubbleDelegate(QStyledItemDelegate):
    """Draws a message as a bubble: sent on the right, received on the
    left, a call or file centred. Colours come from the palette, so both
    themes draw it."""

    def _geometry(self, option, row):
        width = option.rect.width()
        bubble = int(width * _BUBBLE_WIDTH)
        metrics = option.fontMetrics
        text = row.get('subject') or row.get('what') or ''
        body = metrics.boundingRect(QRect(0, 0, bubble - 2 * _PAD, 100000),
                                    Qt.TextWordWrap, text)
        meta_height = metrics.height()
        height = body.height() + meta_height + 3 * _PAD
        content = max(body.width(), metrics.horizontalAdvance(
            self._meta(row))) + 2 * _PAD
        content = min(bubble, max(content, 120))
        return content, height

    @staticmethod
    def _meta(row):
        parts = [(row.get('time_utc') or 'no time').replace('T', ' ')[:19]]
        if row.get('sender'):
            parts.append(row['sender'])
        if row['kind'] != 'message' or row.get('recovered'):
            parts.append(row.get('what') or '')
        return '  ·  '.join(parts)

    def sizeHint(self, option, index):
        row = index.data(_ROW)
        if not row:
            return super().sizeHint(option, index)
        _width, height = self._geometry(option, row)
        return QSize(option.rect.width(), height + 6)

    def paint(self, painter, option, index):
        row = index.data(_ROW)
        if not row:
            return super().paint(painter, option, index)
        width, height = self._geometry(option, row)
        rect = option.rect
        if row['kind'] != 'message':
            left = rect.left() + (rect.width() - width) // 2
        elif row['direction'] == 'out':
            left = rect.right() - width - 4
        else:
            left = rect.left() + 4
        box = QRect(left, rect.top() + 3, width, height)
        palette = option.palette
        if row['direction'] == 'out' and row['kind'] == 'message':
            fill = palette.color(QPalette.Highlight)
            fill.setAlpha(70)
        elif row['kind'] != 'message':
            fill = palette.color(QPalette.ToolTipBase)
        else:
            fill = palette.color(QPalette.AlternateBase)
        painter.save()
        painter.setRenderHint(painter.RenderHint.Antialiasing)
        border = palette.color(QPalette.Highlight) if \
            option.state & QStyle.State_Selected else \
            palette.color(QPalette.Mid)
        painter.setPen(border)
        painter.setBrush(fill)
        painter.drawRoundedRect(box, 9, 9)
        inner = box.adjusted(_PAD, _PAD, -_PAD, -_PAD)
        meta_color = palette.color(QPalette.PlaceholderText)
        if row.get('recovered'):
            meta_color = palette.color(QPalette.Link)
        painter.setPen(meta_color)
        metrics = option.fontMetrics
        painter.drawText(QRect(inner.left(), inner.top(), inner.width(),
                               metrics.height()), Qt.AlignLeft,
                         metrics.elidedText(self._meta(row), Qt.ElideRight,
                                            inner.width()))
        painter.setPen(palette.color(QPalette.Text))
        painter.drawText(inner.adjusted(0, metrics.height() + _PAD // 2, 0,
                                        0), Qt.TextWordWrap,
                         row.get('subject') or row.get('what') or '')
        painter.restore()


class ConversationsPanel(QWidget):
    message_selected = Signal(dict)
    message_activated = Signal(dict)
    #: (thread, rows, position) -- the window's menu (export, report).
    thread_menu_requested = Signal(dict, list, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("conversationsPanel")
        self.case = None
        self.evidence_id = None
        self._rows = []
        self._threads = []
        self._generation = 0
        self._loads = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setWordWrap(True)
        bar.addWidget(self.status_label, 1)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("conversationFilter")
        self.filter_input.setPlaceholderText("Find in conversations")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self._show_threads)
        bar.addWidget(self.filter_input)
        layout.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        self.threads_view = QTreeWidget()
        self.threads_view.setObjectName("triageTable")
        self.threads_view.setRootIsDecorated(False)
        self.threads_view.setColumnCount(len(_THREAD_COLUMNS))
        self.threads_view.setHeaderLabels(_THREAD_COLUMNS)
        self.threads_view.setUniformRowHeights(True)
        self.threads_view.header().setSectionResizeMode(
            QHeaderView.Interactive)
        for column, width in enumerate((220, 110, 60)):
            self.threads_view.setColumnWidth(column, width)
        self.threads_view.currentItemChanged.connect(self._thread_chosen)
        self.threads_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.threads_view.customContextMenuRequested.connect(
            self._thread_menu)
        split.addWidget(self.threads_view)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.title_label = QLabel()
        self.title_label.setObjectName("conversationTitle")
        self.title_label.setWordWrap(True)
        right_layout.addWidget(self.title_label)
        self.messages_view = QListWidget()
        self.messages_view.setObjectName("conversationMessages")
        self.messages_view.setItemDelegate(_BubbleDelegate(
            self.messages_view))
        self.messages_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.messages_view.setResizeMode(QListWidget.Adjust)
        self.messages_view.setWordWrap(True)
        self.messages_view.setVerticalScrollMode(
            QAbstractItemView.ScrollPerPixel)
        self.messages_view.currentItemChanged.connect(self._message_chosen)
        self.messages_view.itemDoubleClicked.connect(
            lambda item: self.message_activated.emit(item.data(_ROW)))
        right_layout.addWidget(self.messages_view, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        layout.addWidget(split, 1)
        self.refresh()

    # --- data ------------------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id != self.evidence_id:
            self.evidence_id = evidence_id
            self.refresh()

    @property
    def loading(self):
        return bool(self._loads)

    def refresh(self):
        if self.case is None:
            self._rows, self._threads = [], []
            self._show_threads()
            self.status_label.setText("Conversations are read within a "
                                      "case.")
            self.count_changed.emit(0)
            return
        self._generation += 1
        load = _Load(self.case.folder, self._generation, self.evidence_id,
                     self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        load.start()

    def _loaded(self, generation, rows):
        self._loads.pop(generation, None)
        if generation != self._generation or self.case is None or \
                not getattr(self.case, 'is_open', True):
            return
        self._rows = rows
        self._threads = conversations.threads(rows)
        self._show_threads()
        self.count_changed.emit(len(self._threads))

    # --- threads ---------------------------------------------------------------

    def _matches(self, thread, text):
        if not text:
            return True
        text = text.lower()
        if text in thread['title'].lower() or text in thread['app'].lower():
            return True
        return any(text in (row.get('subject') or '').lower()
                   for row in conversations.messages(self._rows,
                                                     thread['key']))

    def _show_threads(self):
        current = self.current_thread()
        keep = current['key'] if current else None
        text = self.filter_input.text().strip()
        self.threads_view.clear()
        shown = 0
        for thread in self._threads:
            if not self._matches(thread, text):
                continue
            items = thread['messages'] + thread['calls'] + thread['files']
            item = QTreeWidgetItem([
                thread['title'], thread['app'], f"{items:,}",
                (thread['last'] or '').replace('T', ' ')[:19]])
            tip = [f"{thread['messages']:,} message(s), "
                   f"{thread['calls']:,} call(s)"]
            if thread['recovered']:
                tip.append(f"{thread['recovered']:,} recovered (deleted)")
            item.setToolTip(0, '\n'.join([thread['title']] + tip))
            item.setData(0, _ROW, thread)
            self.threads_view.addTopLevelItem(item)
            if thread['key'] == keep:
                self.threads_view.setCurrentItem(item)
            shown += 1
        if not self._threads:
            self.status_label.setText(
                "No messages or calls yet: run Analysis ▸ User activity on "
                "the evidence (it reads Skype, iMessage/SMS, WhatsApp and "
                "call logs).")
        else:
            total = sum(t['messages'] for t in self._threads)
            self.status_label.setText(
                f"{len(self._threads):,} conversation(s), {total:,} "
                f"message(s)" + (f" — {shown:,} match" if text else ''))
        if self.threads_view.currentItem() is None:
            self.messages_view.clear()
            self.title_label.setText('')

    def current_thread(self):
        item = self.threads_view.currentItem()
        return item.data(0, _ROW) if item else None

    def select_thread(self, key):
        for index in range(self.threads_view.topLevelItemCount()):
            item = self.threads_view.topLevelItem(index)
            if item.data(0, _ROW)['key'] == key:
                self.threads_view.setCurrentItem(item)
                return True
        return False

    def thread_rows(self, thread=None):
        thread = thread or self.current_thread()
        return conversations.messages(self._rows, thread['key']) \
            if thread else []

    def _thread_chosen(self, current, _previous):
        self.messages_view.clear()
        thread = current.data(0, _ROW) if current else None
        if thread is None:
            self.title_label.setText('')
            return
        rows = self.thread_rows(thread)
        first = (thread['first'] or '?').replace('T', ' ')[:19]
        last = (thread['last'] or '?').replace('T', ' ')[:19]
        self.title_label.setText(
            f"<b>{_escape(thread['title'])}</b> — {_escape(thread['app'])}, "
            f"{len(rows):,} item(s), {first} to {last} UTC")
        for row in rows:
            item = QListWidgetItem()
            item.setData(_ROW, row)
            item.setToolTip(f"{row.get('what')}\n{row.get('source_path')}")
            self.messages_view.addItem(item)
        self.messages_view.scrollToBottom()

    def _message_chosen(self, current, _previous):
        row = current.data(_ROW) if current else None
        if row:
            self.message_selected.emit(row)

    def _thread_menu(self, point):
        item = self.threads_view.itemAt(point)
        if item is None:
            return
        thread = item.data(0, _ROW)
        self.thread_menu_requested.emit(
            thread, self.thread_rows(thread),
            self.threads_view.viewport().mapToGlobal(point))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Bubbles wrap to the width: let the list measure them again.
        self.messages_view.doItemsLayout()


def _escape(text):
    from html import escape
    return escape(str(text or ''))

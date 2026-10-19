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
import re

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPalette, QPen
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QSplitter, QStyle,
                               QStyledItemDelegate, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core import conversations
from trace_app.core.case import query_user_activity
from trace_app.infra.constants import ROW_EDGE_INSET
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.case_query import CaseQuery
from trace_app.ui.widgets.tree_branch import BranchTreeWidget

logger = logging.getLogger('TRACE.Conversations')

#: Read by beside the app, where it is seen without scrolling: which
#: tool read a thread is what an examiner checks first.
_THREAD_COLUMNS = ('Conversation', 'App', 'Read by', 'Items', 'Last (UTC)')
_ROW = Qt.UserRole
_BUBBLE_WIDTH = 0.72          # of the list's width
_PAD = 8


def _Load(folder, generation, evidence_id, parent=None):
    """Reads the case's communication rows: TRACE's own messages and those
    external modules read (core/modules/bridge), one row per record."""
    return CaseQuery(
        folder, generation,
        lambda connection: query_user_activity(connection, evidence_id,
                                               'communication'),
        [], 'messages', parent)


#: Each app's look: its icon (Tabler's brand glyph where there is one) and
#: the colour its own app gives a sent message -- matched on the start of
#: the app's name, lower-cased ('twitter x' is Twitter's).
APP_LOOKS = (
    ('whatsapp', 'brand-whatsapp', '#25D366'),
    ('messages', 'message-circle', '#0A84FF'),
    ('imessage', 'message-circle', '#0A84FF'),
    ('ios messages', 'message-circle', '#0A84FF'),
    ('sms', 'message', '#34C759'),
    ('telegram', 'brand-telegram', '#2AABEE'),
    ('signal', 'brand-signal', '#3A76F0'),
    ('discord', 'brand-discord', '#5865F2'),
    ('instagram', 'brand-instagram', '#C13584'),
    ('messenger', 'brand-messenger', '#0084FF'),
    ('facebook', 'brand-messenger', '#0084FF'),
    ('snapchat', 'brand-snapchat', '#FFFC00'),
    ('skype', 'brand-skype', '#00AFF0'),
    ('wechat', 'brand-wechat', '#07C160'),
    ('line', 'brand-line', '#06C755'),
    ('viber', 'phone', '#7360F2'),
    ('kik', 'message-circle', '#82BC23'),
    ('tiktok', 'brand-tiktok', '#FE2C55'),
    ('twitter', 'brand-x', '#1D9BF0'),
    ('x ', 'brand-x', '#1D9BF0'),
    ('zoom', 'brand-zoom', '#2D8CFF'),
    ('teams', 'brand-teams', '#5B5FC7'),
    ('slack', 'brand-slack', '#611F69'),
    ('threads', 'brand-threads', '#7A7A7A'),
    ('tinder', 'brand-tinder', '#FD5068'),
    ('reddit', 'brand-reddit', '#FF4500'),
    ('linkedin', 'brand-linkedin', '#0A66C2'),
    ('gmail', 'brand-gmail', '#EA4335'),
    ('textnow', 'message', '#7B4DD0'),
    ('burner', 'message', '#FF6B35'),
    ('mewe', 'message-circle', '#17377F'),
    ('imo', 'message-circle', '#1A8CFF'),
    ('houseparty', 'message-circle', '#F2505D'),
    ('skout', 'message-circle', '#00A0E3'),
)
DEFAULT_LOOK = ('message-circle', None)
#: Avatar colours: a person always gets the same one.
_AVATARS = ('#E57373', '#F06292', '#BA68C8', '#9575CD', '#7986CB',
            '#64B5F6', '#4DD0E1', '#4DB6AC', '#81C784', '#DCE775',
            '#FFB74D', '#A1887F')
_AVATAR = 30
_PICTURE = 220
_PICTURE_TYPES = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic')


def app_look(app):
    """(Tabler icon name, colour or None) of an app."""
    name = (app or '').strip().lower() + ' '
    for key, icon_name, colour in APP_LOOKS:
        if name.startswith(key):
            return icon_name, colour
    return DEFAULT_LOOK


def app_icon(app):
    from trace_app.ui import icons
    icon_name, colour = app_look(app)
    path = f"Icons/tabler/{icon_name}.svg"
    if not colour:
        return icons.icon(path)
    if icons.current_theme() == 'dark' and QColor(colour).lightnessF() < 0.4:
        # A dark brand colour (MeWe's navy) vanishes on the dark theme.
        colour = QColor(colour).lighter(220).name()
    return icons.icon(path, tint=colour)


def _luminance(colour):
    """Relative luminance (WCAG) of a QColor, 0 (black) to 1 (white)."""
    def channel(value):
        return value / 12.92 if value <= 0.03928 else \
            ((value + 0.055) / 1.055) ** 2.4
    return (0.2126 * channel(colour.redF()) + 0.7152 * channel(colour.greenF())
            + 0.0722 * channel(colour.blueF()))


#: WCAG's minimum contrast for normal text.
MIN_CONTRAST = 4.5


def readable_on(fill):
    """(fill, text, meta) for a bubble: text near-black or white, whichever
    contrasts more with the fill -- never a palette role, which the themes
    set for other widgets (the light theme's dark tooltip colour drew dark
    text on dark call bubbles). A fill neither reaches MIN_CONTRAST on
    (Viber's purple: 4.48 with white) is darkened until white does."""
    dark_text, light_text = QColor('#111111'), QColor('#FFFFFF')
    fill = QColor(fill)
    for _step in range(20):
        on = _luminance(fill)
        against_dark = (on + 0.05) / (_luminance(dark_text) + 0.05)
        against_light = 1.05 / (on + 0.05)
        if max(against_dark, against_light) >= MIN_CONTRAST:
            break
        fill = fill.darker(106)
    text = dark_text if against_dark >= against_light else light_text
    meta = QColor(text)
    meta.setAlpha(170)
    return fill, text, meta


def bubble_fill(base, kind):
    """The fill of a received message ('received') or a call or file
    ('event') on a view whose background is `base`: a step away from it,
    lighter on a dark theme, darker on a light one."""
    dark = base.lightnessF() < 0.5
    if kind == 'event':
        return base.lighter(165) if dark else base.darker(112)
    return base.lighter(135) if dark else base.darker(106)


def _text(row):
    """What a bubble says: the message, else what it holds."""
    if row['kind'] != 'message':
        return row.get('subject') or row.get('what') or ''
    return row.get('subject') or '(no text)'


def initials(name):
    words = [w for w in re.split(r'[\s._@-]+', name or '') if w]
    if not words:
        return '?'
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


def avatar_colour(name):
    import zlib
    return _AVATARS[zlib.crc32((name or '').lower().encode('utf-8'))
                    % len(_AVATARS)]


def _picture_file(row):
    detail = row.get('detail') or {}
    path = detail.get('attachment_file')
    if not path:
        return None
    kind = (detail.get('attachment_type') or '').lower()
    if kind.startswith('image') or path.lower().endswith(_PICTURE_TYPES):
        return path if os.path.isfile(path) else None
    return None


class _BubbleDelegate(QStyledItemDelegate):
    """Draws a message the way its app shows one: sent on the right in the
    app's own colour, received on the left beside the sender's avatar
    (initials, a colour per person) and name, a picture attachment inside
    the bubble, a call or file centred. Received bubbles and calls take
    the palette's colours, so both themes draw them."""

    def __init__(self, rows, parent=None):
        super().__init__(parent)
        self._rows = rows                   # the panel's shown rows
        self._pictures = {}                 # path -> QImage (scaled)

    def row(self, index):
        number = index.data(_ROW)
        if isinstance(number, int) and 0 <= number < len(self._rows()):
            return self._rows()[number]
        return None

    def _picture(self, row):
        path = _picture_file(row)
        if path is None:
            return None
        if path not in self._pictures:
            image = QImage()
            try:
                small = os.path.getsize(path) <= 20 * 1024 * 1024
            except OSError:
                small = False
            if small and image.load(path):
                image = image.scaled(_PICTURE, _PICTURE, Qt.KeepAspectRatio,
                                     Qt.SmoothTransformation)
            else:
                image = None
            if len(self._pictures) > 300:
                self._pictures.clear()
            self._pictures[path] = image
        return self._pictures[path]

    def _geometry(self, option, row):
        width = option.rect.width() - _AVATAR - 12
        bubble = int(width * _BUBBLE_WIDTH)
        metrics = option.fontMetrics
        picture = self._picture(row)
        text = self._shown_text(row, picture)
        body = metrics.boundingRect(QRect(0, 0, bubble - 2 * _PAD, 100000),
                                    Qt.TextWordWrap, text) if text else \
            QRect(0, 0, 0, -_PAD)
        meta_height = metrics.height()
        picture_height = picture.height() + _PAD if picture is not None \
            else 0
        height = body.height() + meta_height + 3 * _PAD + picture_height
        content = max(body.width(), metrics.horizontalAdvance(
            self._meta(row)), picture.width() if picture is not None
            else 0) + 2 * _PAD
        content = min(bubble, max(content, 120))
        return content, height

    @staticmethod
    def _shown_text(row, picture):
        """The bubble's text -- none under a picture that is all the
        message is (its text only names the file)."""
        attachment = (row.get('detail') or {}).get('attachment')
        if picture is not None and attachment and \
                row.get('subject') == f"[{attachment}]":
            return ''
        return _text(row)

    @staticmethod
    def _meta(row):
        parts = []
        if row.get('direction') == 'in' and row.get('sender'):
            parts.append(row['sender'])
        parts.append((row.get('time_utc') or 'no time')
                     .replace('T', ' ')[:19])
        if row['kind'] != 'message' or row.get('recovered'):
            parts.append(row.get('what') or '')
        readers = conversations.readers_of(row)
        if readers != ['TRACE']:       # who read it, when not TRACE alone
            parts.append(conversations.readers_text(readers))
        return '  ·  '.join(parts)

    def sizeHint(self, option, index):
        row = self.row(index)
        if not row:
            return super().sizeHint(option, index)
        _width, height = self._geometry(option, row)
        return QSize(option.rect.width(), max(height, _AVATAR) + 6)

    def paint(self, painter, option, index):
        row = self.row(index)
        if not row:
            return super().paint(painter, option, index)
        width, height = self._geometry(option, row)
        rect = option.rect
        sent = row['direction'] == 'out' and row['kind'] == 'message'
        received = row['kind'] == 'message' and not sent
        if row['kind'] != 'message':
            left = rect.left() + (rect.width() - width) // 2
        elif sent:
            left = rect.right() - width - 6
        else:
            left = rect.left() + _AVATAR + 10
        box = QRect(left, rect.top() + 3, width, height)
        palette = option.palette
        _icon, brand = app_look(conversations.app_of(row))
        base = palette.color(QPalette.Base)
        if sent:
            fill = QColor(brand) if brand else \
                palette.color(QPalette.Highlight)
        elif row['kind'] != 'message':
            fill = bubble_fill(base, 'event')
        else:
            fill = bubble_fill(base, 'received')
        # Text by contrast with the bubble itself, in both themes.
        fill, text_colour, meta_colour = readable_on(fill)
        if row.get('recovered'):
            meta_colour = palette.color(QPalette.Link)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if received:
            # The sender's avatar: their initials on their colour.
            who = row.get('sender') or row.get('thread_title') or ''
            circle = QRect(rect.left() + 4, box.top(), _AVATAR, _AVATAR)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(avatar_colour(who)))
            painter.drawEllipse(circle)
            painter.setPen(QColor('#FFFFFF'))
            small = QFont(option.font)
            small.setBold(True)
            small.setPointSizeF(max(6.0, option.font.pointSizeF() * 0.8))
            painter.setFont(small)
            painter.drawText(circle, Qt.AlignCenter, initials(who))
            painter.setFont(option.font)
        border = palette.color(QPalette.Highlight) if \
            option.state & QStyle.State_Selected else \
            (fill.darker(115) if sent else palette.color(QPalette.Mid))
        painter.setPen(QPen(border, 2 if option.state & QStyle.State_Selected
                            else 1))
        painter.setBrush(fill)
        painter.drawRoundedRect(box, 12, 12)
        inner = box.adjusted(_PAD, _PAD, -_PAD, -_PAD)
        metrics = option.fontMetrics
        painter.setPen(meta_colour)
        painter.drawText(QRect(inner.left(), inner.top(), inner.width(),
                               metrics.height()), Qt.AlignLeft,
                         metrics.elidedText(self._meta(row), Qt.ElideRight,
                                            inner.width()))
        top = inner.top() + metrics.height() + _PAD // 2
        picture = self._picture(row)
        if picture is not None:
            painter.drawImage(QRect(inner.left(), top, picture.width(),
                                    picture.height()), picture)
            top += picture.height() + _PAD
        text = self._shown_text(row, picture)
        if text:
            if not row.get('subject') and row['kind'] == 'message':
                text_colour = QColor(meta_colour)
            painter.setPen(text_colour)
            painter.drawText(QRect(inner.left(), top, inner.width(),
                                   inner.bottom() - top), Qt.TextWordWrap,
                             text)
        painter.restore()


class ConversationsPanel(QWidget):
    message_selected = Signal(dict)
    message_activated = Signal(dict)
    #: (thread, rows, position) -- the window's menu (export, report).
    thread_menu_requested = Signal(dict, list, object)
    #: (row, position) -- the window's menu for one message.
    message_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("conversationsPanel")
        self.case = None
        self.evidence_id = None
        self._rows = []
        self._threads = []
        self._shown = []            # the chosen thread's rows, as drawn
        self._generation = 0
        self._loads = KeptThreads(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, ROW_EDGE_INSET, 0)
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
        self.threads_view = BranchTreeWidget()
        self.threads_view.setObjectName("triageTable")
        self.threads_view.setRootIsDecorated(False)
        self.threads_view.setColumnCount(len(_THREAD_COLUMNS))
        self.threads_view.setHeaderLabels(_THREAD_COLUMNS)
        self.threads_view.setUniformRowHeights(True)
        self.threads_view.header().setSectionResizeMode(
            QHeaderView.Interactive)
        for column, width in enumerate((200, 100, 95, 50)):
            self.threads_view.setColumnWidth(column, width)
        self.threads_view.currentItemChanged.connect(self._thread_chosen)
        self.threads_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.threads_view.customContextMenuRequested.connect(
            self._thread_menu)
        split.addWidget(self.threads_view)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        header = QHBoxLayout()
        header.setContentsMargins(4, 0, 0, 0)
        self.app_label = QLabel()
        self.app_label.setObjectName("conversationApp")
        header.addWidget(self.app_label)
        self.title_label = QLabel()
        self.title_label.setObjectName("conversationTitle")
        self.title_label.setWordWrap(True)
        header.addWidget(self.title_label, 1)
        right_layout.addLayout(header)
        self.messages_view = QListWidget()
        self.messages_view.setObjectName("conversationMessages")
        self.messages_view.setItemDelegate(_BubbleDelegate(
            lambda: self._shown, self.messages_view))
        self.messages_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.messages_view.setResizeMode(QListWidget.Adjust)
        self.messages_view.setWordWrap(True)
        self.messages_view.setVerticalScrollMode(
            QAbstractItemView.ScrollPerPixel)
        self.messages_view.currentItemChanged.connect(self._message_chosen)
        self.messages_view.itemDoubleClicked.connect(self._activated)
        self.messages_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.messages_view.customContextMenuRequested.connect(
            self._message_menu)
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
        self._loads[self._generation] = load
        load.start()

    def _loaded(self, generation, rows):
        if generation != self._generation or self.case is None or \
                not getattr(self.case, 'is_open', True):
            return
        self._rows = rows
        self._threads = conversations.threads(rows)
        self._show_threads()
        self.count_changed.emit(len(self._threads))
        self._reveal_pending()

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
        for number, thread in enumerate(self._threads):
            if not self._matches(thread, text):
                continue
            items = thread['messages'] + thread['calls'] + thread['files']
            item = QTreeWidgetItem([
                thread['title'], thread['app'],
                conversations.readers_text(thread.get('readers') or []),
                f"{items:,}", (thread['last'] or '').replace('T', ' ')[:19]])
            tip = [f"{thread['messages']:,} message(s), "
                   f"{thread['calls']:,} call(s)"]
            if thread['recovered']:
                tip.append(f"{thread['recovered']:,} recovered (deleted)")
            tip.append("Read by " + conversations.readers_text(
                thread.get('readers') or []))
            item.setToolTip(0, '\n'.join([thread['title']] + tip))
            item.setData(0, _ROW, number)
            item.setIcon(1, app_icon(thread['app']))
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

    def _thread_of(self, item):
        """The thread a list item shows (items keep an index: a dict as
        item data is copied into a Qt map, row by row)."""
        number = item.data(0, _ROW) if item is not None else None
        if isinstance(number, int) and 0 <= number < len(self._threads):
            return self._threads[number]
        return None

    def current_thread(self):
        return self._thread_of(self.threads_view.currentItem())

    def select_thread(self, key):
        for index in range(self.threads_view.topLevelItemCount()):
            item = self.threads_view.topLevelItem(index)
            if self._thread_of(item)['key'] == key:
                self.threads_view.setCurrentItem(item)
                return True
        return False

    def reveal(self, row_id):
        """Show the message or call that is activity row `row_id` (from
        Activity's Show in Conversation): its thread, the item selected.
        Waits for a load under way."""
        self._pending = row_id
        if not self.loading:
            self._reveal_pending()

    def _reveal_pending(self):
        row_id = getattr(self, '_pending', None)
        if row_id is None:
            return
        row = next((r for r in self._rows if r.get('id') == row_id), None)
        if row is None:
            return                      # not loaded yet, or not a message
        self._pending = None
        if self.filter_input.text():
            self.filter_input.setText('')
        if not self.select_thread(conversations.thread_key(row)):
            return
        for number, shown in enumerate(self._shown):
            if shown.get('id') == row_id:
                self.messages_view.setCurrentRow(number)
                self.messages_view.scrollToItem(
                    self.messages_view.item(number))
                return

    def thread_rows(self, thread=None):
        thread = thread or self.current_thread()
        return conversations.messages(self._rows, thread['key']) \
            if thread else []

    def _thread_chosen(self, current, _previous):
        self.messages_view.clear()
        thread = self._thread_of(current)
        if thread is None:
            self._shown = []
            self.title_label.setText('')
            self.app_label.clear()
            return
        rows = self.thread_rows(thread)
        for row in rows:
            row['thread_title'] = thread['title']
        self._shown = rows
        first = (thread['first'] or '?').replace('T', ' ')[:19]
        last = (thread['last'] or '?').replace('T', ' ')[:19]
        self.app_label.setPixmap(app_icon(thread['app']).pixmap(28, 28))
        self.app_label.setToolTip(thread['app'])
        people = sorted({row['sender'] for row in rows if row.get('sender')})
        with_whom = f" · {', '.join(people[:6])}" + \
            (f" and {len(people) - 6} more" if len(people) > 6 else '') \
            if len(people) > 1 else ''
        self.title_label.setText(
            f"<b>{_escape(thread['title'])}</b> — {_escape(thread['app'])}"
            f"{_escape(with_whom)}<br>{len(rows):,} item(s), {first} to "
            f"{last} UTC")
        for number, row in enumerate(rows):
            item = QListWidgetItem()
            item.setData(_ROW, number)
            detail = row.get('detail') or {}
            tip = [row.get('what') or '', row.get('source_path') or '']
            if detail.get('module'):
                tip.append(f"read by {detail['module']}")
            if detail.get('attachment'):
                tip.append(f"attachment: {detail['attachment']}")
            readers = conversations.readers_of(row)
            tip.append(f"Read by {conversations.readers_text(readers)}"
                       + (" (one message, read by each)"
                          if len(readers) > 1 else ''))
            item.setToolTip('\n'.join(t for t in tip if t))
            self.messages_view.addItem(item)
        self.messages_view.scrollToBottom()

    def _row_of(self, item):
        number = item.data(_ROW) if item is not None else None
        if isinstance(number, int) and 0 <= number < len(self._shown):
            return self._shown[number]
        return None

    def _activated(self, item):
        row = self._row_of(item)
        if row:
            self.message_activated.emit(row)

    def _message_chosen(self, current, _previous):
        row = self._row_of(current)
        if row:
            self.message_selected.emit(row)

    def _message_menu(self, point):
        row = self._row_of(self.messages_view.itemAt(point))
        if row:
            self.message_menu_requested.emit(
                row, self.messages_view.viewport().mapToGlobal(point))

    def _thread_menu(self, point):
        item = self.threads_view.itemAt(point)
        thread = self._thread_of(item)
        if thread is None:
            return
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

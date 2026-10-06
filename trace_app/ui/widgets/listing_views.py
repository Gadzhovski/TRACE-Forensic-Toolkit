"""The Listing's other views -- List, Small, Medium, Large and Extra large
icons -- as Windows Explorer has them, beside Details (the table). The
Carved files tab uses the same view over its own table.

They are one QListView over the table's own model and selection: the same
rows, icons, sort order and selection, whichever is on screen. Nothing is
copied, so every handler written against the table (preview, open, the
context menu, bookmarks) acts on what the icon views show; the window
routes their clicks to it. Rows the table hides (known-good files) are
hidden here too.

From Medium icons up, an item shows its own picture where it has one:
pictures, a frame of a video (play-badged), a PDF's first page, the preview
an ODF/Office document carries. What a file is comes from its name, or
else from its first bytes -- a renamed or deleted picture shows itself.
They are made for the items on screen only, on a background thread
(widgets/thumbnails.py), scaled to fit -- never cropped, a cropped
thumbnail hides evidence. The table keeps its file-type icons.
"""

import logging

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QActionGroup, QIcon, QPixmap
from PySide6.QtWidgets import (QListView, QMenu, QStyledItemDelegate,
                               QStyleOptionViewItem, QToolButton)

from trace_app.ui.widgets import thumbnails as thumbs

logger = logging.getLogger('TRACE.ListingViews')

#: mode -> (label, view mode, icon size, grid size or None, flow).
MODES = {
    'details': ("Details", None, None, None, None),
    'list': ("List", QListView.ListMode, 16, None, QListView.TopToBottom),
    'small': ("Small icons", QListView.ListMode, 16, QSize(220, 24),
              QListView.LeftToRight),
    'medium': ("Medium icons", QListView.IconMode, 48, QSize(112, 96),
               QListView.LeftToRight),
    'large': ("Large icons", QListView.IconMode, 96, QSize(150, 146),
              QListView.LeftToRight),
    'extra_large': ("Extra large icons", QListView.IconMode, 192,
                    QSize(232, 244), QListView.LeftToRight),
}
ORDER = ('extra_large', 'large', 'medium', 'small', 'list', 'details')
#: From this icon size up, items show their own content.
THUMBNAIL_FROM = 48
#: Pictures larger than this are not read for a thumbnail.
THUMBNAIL_MAX_BYTES = thumbs.MAX_BYTES[thumbs.PICTURE]
PICTURE_EXTENSIONS = thumbs.PICTURE_EXTENSIONS
#: Thumbnails are made at least this big, so a step up in icon size does
#: not have to make them again.
_SMALLEST = 96


_UNITS = {'B': 1, 'BYTES': 1, 'KB': 1024, 'MB': 1024 ** 2, 'GB': 1024 ** 3,
          'TB': 1024 ** 4, 'PB': 1024 ** 5}


def size_in_bytes(value):
    """A listing row's size as bytes. Rows carry what the Size column
    shows -- a number, or text such as '8.25 KB' -- so both are read;
    None when it says nothing usable."""
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or '').strip().replace(',', '')
    if not text:
        return None
    number, _space, unit = text.partition(' ')
    try:
        multiplier = _UNITS.get(unit.upper() or 'B', 1)
        from trace_app.infra import utils
        if utils.SIZE_UNITS == 'decimal' and multiplier > 1:
            # Shown in decimal units (the examiner's setting): 1 kB = 1,000.
            multiplier = 1000 ** {'KB': 1, 'MB': 2, 'GB': 3, 'TB': 4,
                                  'PB': 5}[unit.upper()]
        return int(float(number) * multiplier)
    except ValueError:
        return None


def is_picture(name):
    return thumbs.kind_by_name(name) == thumbs.PICTURE


def is_video(name):
    return thumbs.kind_by_name(name) == thumbs.VIDEO


def video_thumbnail(image, size):
    """A video frame scaled to fit `size` x `size`, play-badged."""
    from trace_app.ui.viewers.media.video_thumbnails import with_play_badge
    if image.isNull():
        return QPixmap()
    return with_play_badge(QPixmap.fromImage(image.scaled(
        size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)))


def thumbnail(data, size):
    """A picture scaled to fit `size` x `size`, or a null pixmap."""
    return QPixmap.fromImage(thumbs.picture_image(data, size))


def listing_item(data):
    """(key, kind, size in bytes) for a Listing row that may have a
    thumbnail, or None. The kind is the name's, or SNIFF: its first bytes
    will say."""
    if not isinstance(data, dict) or data.get('type') != 'file':
        return None
    size = size_in_bytes(data.get('size'))
    if not size:
        return None
    return (ListingIconView._key(data),
            thumbs.kind_by_name(data.get('name')) or thumbs.SNIFF, size)


def _view_icons():
    from trace_app.ui import icons
    return {'details': icons.VIEW_DETAILS, 'list': icons.VIEW_LIST,
            'small': icons.VIEW_SMALL_ICONS,
            'medium': icons.VIEW_MEDIUM_ICONS,
            'large': icons.VIEW_LARGE_ICONS,
            'extra_large': icons.VIEW_EXTRA_LARGE_ICONS}


class ViewButton(QToolButton):
    """The View dropdown: Details, List and the icon sizes, and any
    `extra` views after a separator ((key, label, icon name)). Its icon is
    the view in use; `chosen(key)` when the examiner picks one."""

    chosen = Signal(str)

    def __init__(self, parent=None, extra=()):
        super().__init__(parent)
        self.setObjectName("listingViewButton")
        self.setPopupMode(QToolButton.InstantPopup)
        self.setProperty("dropdown", True)
        self._icons = _view_icons()
        self._labels = {mode: MODES[mode][0] for mode in ORDER}
        menu = QMenu(self)
        group = QActionGroup(self)
        group.setExclusive(True)
        self.actions = {}
        entries = [(mode, MODES[mode][0], self._icons[mode])
                   for mode in ORDER]
        if extra:
            entries.append(None)
        entries.extend(extra)
        for entry in entries:
            if entry is None:
                menu.addSeparator()
                continue
            key, label, icon_name = entry
            self._icons[key] = icon_name
            self._labels[key] = label
            action = QAction(label, self)
            action.setCheckable(True)
            action.triggered.connect(
                lambda _checked=False, k=key: self.chosen.emit(k))
            group.addAction(action)
            menu.addAction(action)
            self.actions[key] = action
        self.setMenu(menu)

    def set_current(self, key):
        """Show `key` as the view in use (no signal)."""
        from trace_app.ui import icons
        self.setIcon(icons.icon(self._icons[key]))
        self.setToolTip(f"Change the view ({self._labels[key]})")
        self.actions[key].setChecked(True)


class _ThumbnailDelegate(QStyledItemDelegate):
    """Draws an item with its thumbnail, when there is one, in place of the
    file-type icon -- without touching the shared model."""

    def __init__(self, view):
        super().__init__(view)
        self.view = view

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        pixmap = self.view.thumbnail_for(index)
        if pixmap is not None:
            option.icon = QIcon(pixmap)
            # Drawn only when the option says there is a decoration.
            option.features |= QStyleOptionViewItem.HasDecoration
            option.decorationSize = self.view.iconSize()


class ListingIconView(QListView):
    """The Listing (or another table) in a list or icon view, over the
    table's model."""

    def __init__(self, table, read_picture, parent=None, open_video=None,
                 read_head=None, describe=listing_item, read_icon=None):
        """`read_picture(data)` -> the bytes of the file a row's data
        names, or None; `open_video(data)` -> an open QIODevice streaming
        it, or None; `read_head(data)` -> its first bytes, to recognise it
        by content; `describe(data)` -> (key, kind, size) or None."""
        super().__init__(parent)
        self.setObjectName("listingIconView")
        self.table = table
        self.read_picture = read_picture
        self.read_head = read_head
        #: `read_icon(data, size)` -> a program's icon bytes (pe_icons).
        self.read_icon = read_icon
        self.describe = describe
        self.setModel(table.model())
        self.setSelectionModel(table.selectionModel())
        self.setModelColumn(0)
        self.setSelectionMode(QListView.ExtendedSelection)
        self.setEditTriggers(QListView.NoEditTriggers)
        self.setResizeMode(QListView.Adjust)
        self.setMovement(QListView.Static)
        self.setUniformItemSizes(True)
        self.setTextElideMode(Qt.ElideMiddle)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.setItemDelegate(_ThumbnailDelegate(self))
        self.mode = 'list'
        self.open_video = open_video
        self._videos = None             # the thumbnailer, made when needed
        self._thumbs = {}               # key -> QPixmap, or False: none
        self._thumb_size = _SMALLEST
        self._rows_for = {}             # key -> row data, while requested
        self._loader = thumbs.ThumbnailLoader(self)
        self._loader.ready.connect(self._image_ready)
        self._loader.pdf.connect(self._pdf_ready)
        self._loader.video.connect(self._is_video)
        model = table.model()
        model.modelReset.connect(self._model_changed)
        model.rowsInserted.connect(self._rows_changed)
        model.layoutChanged.connect(self._rows_changed)
        self.verticalScrollBar().valueChanged.connect(self._queue_visible)
        self.horizontalScrollBar().valueChanged.connect(self._queue_visible)

    # --- mode ------------------------------------------------------------------

    def set_mode(self, mode):
        _label, view_mode, size, grid, flow = MODES[mode]
        self.mode = mode
        self.setViewMode(view_mode)
        self.setFlow(flow)
        self.setWrapping(True)
        self.setWordWrap(view_mode == QListView.IconMode)
        self.setIconSize(QSize(size, size))
        self.setGridSize(grid or QSize())
        self.setSpacing(0 if grid else 2)
        if size > self._thumb_size:
            # Bigger than the thumbnails made: made again, at this size.
            self._thumb_size = size
            self._forget()
        self.sync_hidden()
        self._queue_visible()

    def thumbnails_on(self):
        return self.iconSize().width() >= THUMBNAIL_FROM

    def sync_hidden(self):
        """Hide what the table hides (known-good files)."""
        try:
            for row in range(self.model().rowCount()):
                self.setRowHidden(row, self.table.isRowHidden(row))
        except RuntimeError:
            pass        # the table is gone (closing): nothing to mirror

    # --- thumbnails ------------------------------------------------------------

    @staticmethod
    def _key(data):
        if not isinstance(data, dict):
            return None
        return (data.get('image_path'), data.get('start_offset'),
                data.get('inode_number'), data.get('name'))

    def thumbnail_for(self, index):
        if not self.thumbnails_on():
            return None
        described = self.describe(index.data(Qt.UserRole))
        found = self._thumbs.get(described[0]) if described else None
        return found if found else None

    def _forget(self):
        self._thumbs.clear()
        self._rows_for.clear()
        self._loader.clear()
        if self._videos is not None:
            self._videos.clear()

    def _model_changed(self):
        self._forget()
        self._rows_changed()

    def _video_thumbnailer(self):
        if self._videos is None:
            from trace_app.ui.viewers.media.video_thumbnails import \
                VideoThumbnailer
            self._videos = VideoThumbnailer(self)
            self._videos.ready.connect(self._video_ready)
        return self._videos

    def _store(self, key, pixmap):
        # Null is remembered too, so what will not decode is not read
        # again on every scroll.
        self._thumbs[key] = pixmap if not pixmap.isNull() else False
        self._rows_for.pop(key, None)
        self.viewport().update()

    def _image_ready(self, key, image):
        self._store(key, QPixmap.fromImage(image))

    def _pdf_ready(self, key, content):
        self._store(key, QPixmap.fromImage(
            thumbs.pdf_image(content, self._thumb_size)))

    def _video_ready(self, key, image):
        self._store(key, video_thumbnail(image, self._thumb_size))

    def _is_video(self, key):
        """The loader found a video by its content: a frame from it."""
        data = self._rows_for.get(key)
        if data is None or self.open_video is None:
            self._store(key, QPixmap())
            return
        self._request_video(key, data)

    def _request_video(self, key, data):
        videos = self._video_thumbnailer()
        if not videos.pending(key):
            videos.request(key, lambda data=data: self.open_video(data),
                           (data or {}).get('name') or '')

    def _rows_changed(self, *_args):
        if self.isVisible():
            self.sync_hidden()
            QTimer.singleShot(0, self._queue_visible)

    def showEvent(self, event):
        super().showEvent(event)
        self.sync_hidden()
        QTimer.singleShot(0, self._queue_visible)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        QTimer.singleShot(0, self._queue_visible)

    def _queue_visible(self, *_args):
        """Ask for thumbnails of the items on screen that have none yet."""
        if not self.thumbnails_on() or not self.isVisible():
            return
        model = self.model()
        rect = self.viewport().rect()
        for row in range(model.rowCount()):
            index = model.index(row, 0)
            if self.isRowHidden(row) or \
                    not self.visualRect(index).intersects(rect):
                continue
            data = index.data(Qt.UserRole)
            described = self.describe(data)
            if described is None:
                continue
            key, kind, size = described
            if key in self._thumbs or key in self._rows_for:
                continue
            if kind == thumbs.VIDEO:
                if self.open_video is not None:
                    # Streamed, so any size: only what the decoder asks
                    # for is read.
                    self._rows_for[key] = data
                    self._request_video(key, data)
                continue
            if kind == thumbs.SNIFF and self.read_head is None:
                continue
            if kind == thumbs.PROGRAM:
                if self.read_icon is None:
                    continue
                # Its own icon, as large as the view shows it.
                self._rows_for[key] = data
                self._loader.request(
                    key, thumbs.PICTURE, self._thumb_size,
                    lambda data=data: self.read_icon(data, self._thumb_size))
                continue
            # A file too big for its kind is not read whole for one icon.
            if kind != thumbs.SNIFF and size > thumbs.MAX_BYTES.get(kind, 0):
                continue
            self._rows_for[key] = data
            self._loader.request(
                key, kind, self._thumb_size,
                lambda data=data: self.read_picture(data),
                (lambda data=data: self.read_head(data))
                if self.read_head else None, size)

"""The Listing's other views -- List, Small, Medium, Large and Extra large
icons -- as Windows Explorer has them, beside Details (the table).

They are one QListView over the table's own model and selection: the same
rows, icons, sort order and selection, whichever is on screen. Nothing is
copied, so every handler written against the table (preview, open, the
context menu, bookmarks) acts on what the icon views show; the window
routes their clicks to it. Rows the table hides (known-good files) are
hidden here too.

From Medium icons up, a picture shows its own thumbnail, read from the
evidence for the items on screen only, a few at a time, and scaled to fit
-- never cropped, a cropped thumbnail hides evidence. The file stays
unchanged; the table keeps its file-type icons.
"""

import logging

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QIcon, QImage, QImageReader, QPixmap
from PySide6.QtWidgets import (QListView, QStyledItemDelegate,
                               QStyleOptionViewItem)

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
#: From this icon size up, pictures show their own content.
THUMBNAIL_FROM = 48
#: Pictures larger than this are not read for a thumbnail.
THUMBNAIL_MAX_BYTES = 16 * 1024 * 1024
PICTURE_EXTENSIONS = {'jpg', 'jpeg', 'jpe', 'png', 'gif', 'bmp', 'webp',
                      'tif', 'tiff', 'ico', 'heic', 'heif', 'avif'}
_PER_TICK = 6


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
    return '.' in (name or '') and \
        name.rsplit('.', 1)[-1].lower() in PICTURE_EXTENSIONS


def thumbnail(data, size):
    """A picture scaled to fit `size` x `size`, or a null pixmap."""
    from PySide6.QtCore import QBuffer, QByteArray
    buffer = QBuffer()
    buffer.setData(QByteArray(bytes(data)))
    buffer.open(QBuffer.ReadOnly)
    reader = QImageReader(buffer)
    reader.setAutoTransform(True)
    original = reader.size()
    if original.isValid() and (original.width() > size * 2 or
                               original.height() > size * 2):
        # Decoded small: a 24-megapixel photo is not decoded whole for a
        # 96-pixel icon.
        reader.setScaledSize(original.scaled(size * 2, size * 2,
                                             Qt.KeepAspectRatio))
    image = reader.read()
    if image.isNull():
        try:
            from io import BytesIO
            from PIL import Image
            with Image.open(BytesIO(bytes(data))) as picture:
                picture.thumbnail((size * 2, size * 2))
                picture = picture.convert('RGBA')
                image = QImage(picture.tobytes(), picture.width,
                               picture.height, QImage.Format_RGBA8888).copy()
        except Exception:
            return QPixmap()
    return QPixmap.fromImage(image.scaled(size, size, Qt.KeepAspectRatio,
                                          Qt.SmoothTransformation))


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
    """The Listing in a list or icon view, over the table's model."""

    def __init__(self, table, read_picture, parent=None):
        """`read_picture(data)` -> the bytes of the file a row's data
        names, or None."""
        super().__init__(parent)
        self.setObjectName("listingIconView")
        self.table = table
        self.read_picture = read_picture
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
        self._thumbs = {}
        self._queue = []
        self._timer = QTimer(self)
        self._timer.setInterval(0)
        self._timer.timeout.connect(self._draw_some)
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
        found = self._thumbs.get(self._key(index.data(Qt.UserRole)))
        return found if found else None

    def _model_changed(self):
        self._thumbs.clear()
        self._queue = []
        self._rows_changed()

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
        """Queue the pictures on screen that have no thumbnail yet."""
        if not self.thumbnails_on() or not self.isVisible():
            return
        model = self.model()
        rect = self.viewport().rect()
        queued = {self._key(d) for d in self._queue}
        for row in range(model.rowCount()):
            index = model.index(row, 0)
            if self.isRowHidden(row) or \
                    not self.visualRect(index).intersects(rect):
                continue
            data = index.data(Qt.UserRole)
            key = self._key(data)
            if key is None or key in self._thumbs or key in queued:
                continue
            size = size_in_bytes(data.get('size'))
            # A size that cannot be read is not risked: the file could be
            # anything, and it would be read whole for one icon.
            if data.get('type') != 'file' or \
                    not is_picture(data.get('name')) or \
                    size is None or size > THUMBNAIL_MAX_BYTES:
                continue
            self._queue.append(data)
            queued.add(key)
        if self._queue:
            self._timer.start()

    def _draw_some(self):
        size = self.iconSize().width()
        for _ in range(_PER_TICK):
            if not self._queue:
                self._timer.stop()
                return
            data = self._queue.pop(0)
            try:
                content = self.read_picture(data)
                pixmap = thumbnail(content, max(size, 96)) if content \
                    else QPixmap()
            except Exception as exc:
                logger.debug("No thumbnail for %s: %s", data.get('name'),
                             exc)
                pixmap = QPixmap()
            # Null is remembered too, so a picture that will not decode is
            # not read again on every scroll.
            self._thumbs[self._key(data)] = pixmap if not pixmap.isNull() \
                else False
        self.viewport().update()

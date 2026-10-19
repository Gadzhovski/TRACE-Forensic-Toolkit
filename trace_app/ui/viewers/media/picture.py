"""Image viewer: zoom, rotation and save, and the examiner's tools.

Qt decodes most formats itself. What it cannot -- AVIF, JPEG 2000, PSD, PCX,
DDS -- goes through Pillow, so the list of viewable images is the union of
both rather than whichever one happened to be called.

The tools (core/image_forensics.py does the work, on a thread -- Pillow's C
operations, never Python loops over pixels):

* an info strip: format, size, mode, ICC profile, JPEG quantisation, and
  the pixel under the pointer -- x, y and its colour as the file holds it;
* the Inspect panel: Details (every fact, the quantisation tables), Adjust
  (brightness, contrast, gamma, equalise, invert, one channel) and error
  level analysis, the embedded EXIF thumbnail against the picture, and the
  frames or pages of an animation or multi-page TIFF;
* EXIF orientation: shown as stored, or turned upright on request;
* a region dragged out: its size, Export Region, Bookmark Region; a
  magnifier that follows the pointer.

Every adjusted view says so beside the picture ("not the file's pixels").
Save Image writes the file's bytes as stored; Save View writes what is on
screen as a derivative PNG whose audit line names every step.
"""

import io
import logging

from PySide6.QtCore import (QBuffer, QByteArray, QEvent, QIODevice, QPoint,
                            QPointF, QRect, QRectF, QSize, Qt, QThread,
                            QTimer, Signal, Slot)
from PySide6.QtGui import (QAction, QColor, QGuiApplication, QImage,
                           QPainter, QPen, QPixmap, QTransform)
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout, QLabel,
                               QListWidget, QListWidgetItem, QMenu,
                               QPlainTextEdit, QScrollArea, QSpinBox,
                               QSplitter, QTabWidget, QToolBar, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.image_adjust import AdjustPanel
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar, stretch

logger = logging.getLogger('TRACE.Viewer.Picture')


#: Zoom limits and step. The picture is painted from the original at each
#: zoom, never a resampled copy kept, so a high zoom costs no memory.
MIN_ZOOM = 0.05
MAX_ZOOM = 32.0
ZOOM_STEP = 1.25

#: Delay after the last Adjust change before the view is made again: a
#: slider dragged makes dozens of changes a second.
RENDER_DELAY_MS = 150

#: The magnifier: source pixels each way, and how many screen pixels each.
LOUPE_PIXELS = 15
LOUPE_SCALE = 8


def to_qimage(image):
    """A Pillow image as a QImage of its own (safe on any thread)."""
    if image.mode == 'L':
        data = image.tobytes()
        result = QImage(data, image.width, image.height, image.width,
                        QImage.Format_Grayscale8)
        return result.copy()
    rgba = image.convert('RGBA')
    data = rgba.tobytes('raw', 'RGBA')
    result = QImage(data, rgba.width, rgba.height, rgba.width * 4,
                    QImage.Format_RGBA8888)
    # copy(): the QImage above borrows `data`, which is about to go.
    return result.copy()


def png_of(qimage):
    """A QImage as PNG bytes."""
    array = QByteArray()
    buffer = QBuffer(array)
    buffer.open(QIODevice.WriteOnly)
    qimage.save(buffer, 'PNG')
    buffer.close()
    return bytes(array)


class PictureCanvas(QWidget):
    """The picture itself, painted at `zoom` and `rotation` from the
    decoded original on every paint.

    Zooming used to rescale the pixmap already on screen, smoothly, so each
    step blurred the last one's blur, and a small carved picture enlarged
    to a smear. Enlarged, every image pixel is now a sharp block (nearest
    neighbour): the examiner sees the pixels the file holds, not detail an
    interpolation made up. Reduced, it is smoothed -- dropping pixels would
    lose them unevenly.

    A left-button drag selects a region (in image pixels); the middle
    button pans; with `loupe` on, a magnifier follows the pointer.
    """

    #: The image pixel under the pointer (QPoint), or None off the picture.
    hovered = Signal(object)
    #: The selected region (QRect in image pixels; empty = none).
    selection_changed = Signal(QRect)
    #: A middle-button drag: (dx, dy) in screen pixels.
    panned = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("pictureCanvas")
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.ClickFocus)
        self.pixmap = None
        self.zoom = 1.0
        self.rotation = 0
        self.selection = QRect()
        self.loupe = False
        self._pointer = None
        self._drag_from = None
        self._pan_from = None

    def set_pixmap(self, pixmap, keep_view=False):
        same_size = (self.pixmap is not None and pixmap is not None and
                     pixmap.size() == self.pixmap.size())
        self.pixmap = pixmap if pixmap is not None and \
            not pixmap.isNull() else None
        if not (keep_view and same_size):
            self.zoom = 1.0
            self.rotation = 0
            self.selection = QRect()
        self._resize()

    def set_view(self, zoom=None, rotation=None):
        if zoom is not None:
            self.zoom = min(MAX_ZOOM, max(MIN_ZOOM, zoom))
        if rotation is not None:
            self.rotation = rotation % 360
        self._resize()

    def shown_size(self):
        """The picture's size on screen (logical pixels), rotated."""
        if self.pixmap is None:
            return QSize(0, 0)
        width, height = self.pixmap.width(), self.pixmap.height()
        if self.rotation in (90, 270):
            width, height = height, width
        return QSize(max(1, round(width * self.zoom)),
                     max(1, round(height * self.zoom)))

    def _resize(self):
        self.setFixedSize(self.shown_size())
        self.update()

    def sizeHint(self):
        return self.shown_size()

    def smoothed(self):
        """True when the picture is drawn reduced (smoothed); enlarged or
        at actual size on a high-DPI screen, pixels are drawn as blocks."""
        return self.zoom * self.devicePixelRatioF() < 1

    def transform(self):
        """Image pixels -> this widget's coordinates, as painted."""
        transform = QTransform()
        if self.pixmap is None:
            return transform
        transform.translate(self.width() / 2, self.height() / 2)
        transform.rotate(self.rotation)
        transform.scale(self.zoom, self.zoom)
        transform.translate(-self.pixmap.width() / 2,
                            -self.pixmap.height() / 2)
        return transform

    def image_point(self, position):
        """The image pixel (QPoint) under widget position `position`, or
        None off the picture."""
        if self.pixmap is None:
            return None
        inverse, ok = self.transform().inverted()
        if not ok:
            return None
        point = inverse.map(QPointF(position))
        x, y = int(point.x() // 1), int(point.y() // 1)
        if 0 <= x < self.pixmap.width() and 0 <= y < self.pixmap.height():
            return QPoint(x, y)
        return None

    def _clamped(self, position):
        inverse, _ok = self.transform().inverted()
        point = inverse.map(QPointF(position))
        return QPoint(min(self.pixmap.width(), max(0, round(point.x()))),
                      min(self.pixmap.height(), max(0, round(point.y()))))

    def clear_selection(self):
        if not self.selection.isEmpty():
            self.selection = QRect()
            self.selection_changed.emit(QRect())
            self.update()

    def paintEvent(self, _event):
        if self.pixmap is None:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, self.smoothed())
        painter.setTransform(self.transform())
        painter.drawPixmap(0, 0, self.pixmap)
        palette = self.palette()
        if not self.selection.isEmpty():
            pen = QPen(palette.highlight().color(), 2)
            pen.setCosmetic(True)
            painter.setPen(pen)
            painter.drawRect(QRectF(self.selection))
            pen = QPen(palette.base().color(), 1, Qt.DashLine)
            pen.setCosmetic(True)
            painter.setPen(pen)
            painter.drawRect(QRectF(self.selection))
        painter.resetTransform()
        if self.loupe and self._pointer is not None:
            self._paint_loupe(painter, palette)
        painter.end()

    def _paint_loupe(self, painter, palette):
        """LOUPE_PIXELS square around the pointer, LOUPE_SCALE times, drawn
        as blocks, with the pixel under the pointer framed."""
        centre = self.image_point(self._pointer)
        if centre is None:
            return
        half = LOUPE_PIXELS // 2
        source = QRect(centre.x() - half, centre.y() - half,
                       LOUPE_PIXELS, LOUPE_PIXELS)
        side = LOUPE_PIXELS * LOUPE_SCALE
        x = self._pointer.x() + 24
        y = self._pointer.y() + 24
        if x + side > self.width():
            x = self._pointer.x() - 24 - side
        if y + side > self.height():
            y = self._pointer.y() - 24 - side
        target = QRect(x, y, side, side)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, False)
        painter.fillRect(target, palette.base())
        painter.drawPixmap(target, self.pixmap, source)
        pen = QPen(palette.highlight().color(), 2)
        painter.setPen(pen)
        painter.drawRect(target)
        middle = QRect(x + half * LOUPE_SCALE, y + half * LOUPE_SCALE,
                       LOUPE_SCALE, LOUPE_SCALE)
        painter.setPen(QPen(palette.text().color(), 1))
        painter.drawRect(middle)

    def mousePressEvent(self, event):
        if self.pixmap is None:
            return super().mousePressEvent(event)
        if event.button() == Qt.LeftButton:
            self._drag_from = self._clamped(event.position().toPoint())
            self.selection = QRect()
            self.update()
        elif event.button() == Qt.MiddleButton:
            self._pan_from = event.globalPosition().toPoint()
            self.setCursor(Qt.ClosedHandCursor)
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        position = event.position().toPoint()
        self._pointer = position
        if self._pan_from is not None:
            now = event.globalPosition().toPoint()
            delta = now - self._pan_from
            self._pan_from = now
            self.panned.emit(delta.x(), delta.y())
        elif self._drag_from is not None and self.pixmap is not None:
            corner = self._clamped(position)
            self.selection = QRect(self._drag_from, corner).normalized()
            self.selection_changed.emit(self.selection)
        self.hovered.emit(self.image_point(position))
        self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self._drag_from is not None:
            self._drag_from = None
            if self.selection.width() < 2 or self.selection.height() < 2:
                self.selection = QRect()
            self.selection_changed.emit(self.selection)
            self.update()
        elif event.button() == Qt.MiddleButton:
            self._pan_from = None
            self.unsetCursor()
        else:
            super().mouseReleaseEvent(event)

    def leaveEvent(self, event):
        self._pointer = None
        self.hovered.emit(None)
        self.update()
        super().leaveEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape and not self.selection.isEmpty():
            self.clear_selection()
            return
        super().keyPressEvent(event)


class _PictureJob(QThread):
    """One piece of Pillow work off the window's thread: 'inspect' (facts,
    tables, thumbnail check, frames) or 'render' (a view). The picture is
    opened from its bytes in the job: a Pillow image is not shared across
    threads."""

    done = Signal(object)

    def __init__(self, generation, kind, data, params=None, parent=None):
        super().__init__(parent)
        self.generation = generation
        self.kind = kind
        self.data = data
        self.params = params or {}

    def run(self):
        from trace_app.core import image_forensics
        result = {'generation': self.generation, 'kind': self.kind,
                  'serial': self.params.get('serial')}
        try:
            image = image_forensics.open_image(self.data)
            if image is None:
                result['error'] = "Pillow cannot read this picture."
            elif self.kind == 'inspect':
                result.update(_inspect(self.data, image))
            else:
                view = image_forensics.render(
                    image, self.params.get('frame', 0),
                    self.params.get('upright', False),
                    self.params.get('adjust'), self.params.get('ela'))
                result['image'] = to_qimage(view['image'])
                result['base'] = to_qimage(view['base']) \
                    if view['base'] is not view['image'] else None
                result['parts'] = view['parts']
                result['derived'] = view['derived']
        except Exception as exc:
            logger.debug("Picture job %s failed: %s", self.kind, exc)
            result['error'] = str(exc)
        self.done.emit(result)


def _inspect(data, image):
    from trace_app.core import image_forensics
    tables = image_forensics.jpeg_tables(image)
    facts = image_forensics.image_facts(data, image)
    try:
        frames = image_forensics.frame_list(image)
    except Exception:
        frames = []
    check = image_forensics.thumbnail_check(data, image) \
        if image.format == 'JPEG' else None
    return {'facts': facts, 'format': image.format or '',
            'tables': image_forensics.tables_text(tables) if tables else '',
            'quality': image_forensics.jpeg_quality(tables),
            'frames': frames,
            'orientation': image_forensics.exif_orientation(image),
            'thumbnail': check}


class PictureViewer(QWidget):
    #: What `bookmark_hook(label)` is called with: a bookmark of the file
    #: shown, its label naming the region.
    def __init__(self, parent=None):
        super().__init__(parent)
        self.original_pixmap = None  # Store the original QPixmap
        self.original_image_bytes = None  # Store the original image bytes
        self.original_image = None   # the decoded file (QImage)
        #: (label) -> bookmark the file on screen; set by the window.
        self.bookmark_hook = None
        self.source_name = None
        self._generation = 0
        self._serial = 0
        self._jobs = KeptThreads(self)
        self._info = {}
        self._frame = 0
        self._base = None           # the file's pixels as now shown
        self._shown = None          # what is on screen (QImage)
        self._parts = []
        self._derived = False
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(RENDER_DELAY_MS)
        self._render_timer.timeout.connect(self._render)
        self.initialize_ui()

    # --- building ----------------------------------------------------------------

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        self.setup_toolbar()
        self.layout.addWidget(self.toolbar)

        self.canvas = PictureCanvas(self)
        self.canvas.hovered.connect(self._hovered)
        self.canvas.selection_changed.connect(self._selection_changed)
        self.canvas.panned.connect(self._pan)
        self.canvas.setContextMenuPolicy(Qt.CustomContextMenu)
        self.canvas.customContextMenuRequested.connect(self._canvas_menu)
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setAlignment(Qt.AlignCenter)
        # The canvas keeps its own size; the area scrolls round it.
        self.scroll_area.setWidgetResizable(False)
        self.scroll_area.setWidget(self.canvas)
        self.scroll_area.viewport().installEventFilter(self)

        self.side = self._build_side()
        self.side.setVisible(False)
        self.splitter = QSplitter(Qt.Horizontal, self)
        self.splitter.setObjectName("pictureSplitter")
        self.splitter.addWidget(self.scroll_area)
        self.splitter.addWidget(self.side)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 0)
        self.splitter.setChildrenCollapsible(False)
        self.layout.addWidget(self.splitter, 1)
        self.layout.addWidget(self._build_strip())
        self.setLayout(self.layout)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        prepare_toolbar(self.toolbar)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        # Disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        zoom_in_action = icons.action(icons.ZOOM_IN, 'Zoom In', self)
        zoom_out_action = icons.action(icons.ZOOM_OUT, 'Zoom Out', self)
        fit_action = icons.action(icons.FIT_WINDOW, 'Fit to Window', self)
        rotate_left_action = icons.action(icons.ROTATE_LEFT, 'Rotate Left',
                                          self)
        rotate_right_action = icons.action(icons.ROTATE_RIGHT,
                                           'Rotate Right', self)
        reset_action = icons.action(icons.ROTATE_RESET,
                                    'Actual Size, Not Rotated', self)
        self.export_action = icons.action(icons.SAVE_AS, 'Save Image', self)
        self.export_action.setToolTip(
            "Save Image: the file's bytes as stored, unchanged")
        self.save_view_action = icons.action(icons.SAVE_PICTURE,
                                             'Save View…', self)
        self.save_view_action.setToolTip(
            "Save View: what is on screen (an adjusted view, error levels, "
            "a frame) as a PNG derivative, named and audited as such")

        zoom_in_action.triggered.connect(self.zoom_in)
        zoom_out_action.triggered.connect(self.zoom_out)
        fit_action.triggered.connect(self.fit)
        rotate_left_action.triggered.connect(self.rotate_left)
        rotate_right_action.triggered.connect(self.rotate_right)
        reset_action.triggered.connect(self.reset)
        self.export_action.triggered.connect(self.export_original_image)
        self.save_view_action.triggered.connect(self.save_view)

        # Grouped rather than run together: six icons of the same weight in one
        # unbroken row gave no clue which did what. Zoom, then rotate, then
        # reset -- with Save pushed to the right, where the PDF toolbar also
        # puts it, so the two viewers read the same way.
        self.toolbar.addAction(zoom_in_action)
        self.toolbar.addAction(zoom_out_action)
        self.toolbar.addAction(fit_action)
        self.zoom_label = QLabel()
        self.zoom_label.setObjectName("pictureZoomLabel")
        self.zoom_label.setToolTip("Zoom (Ctrl+wheel). Enlarged, each pixel "
                                   "of the image is drawn as a sharp block: "
                                   "nothing is smoothed or made up.")
        self.toolbar.addWidget(self.zoom_label)

        self.toolbar.addSeparator()
        self.toolbar.addAction(rotate_left_action)
        self.toolbar.addAction(rotate_right_action)
        self.upright_action = icons.action(icons.IMAGE_UPRIGHT,
                                           'Show Upright', self)
        self.upright_action.setCheckable(True)
        self.upright_action.setEnabled(False)
        self.upright_action.setToolTip(
            "Show the picture turned as its EXIF orientation says the "
            "camera meant. Off: as the file stores its pixels.")
        self.upright_action.toggled.connect(self._view_changed)
        self.toolbar.addAction(self.upright_action)

        self.toolbar.addSeparator()
        self.toolbar.addAction(reset_action)

        self.toolbar.addSeparator()
        self.inspect_action = icons.action(icons.IMAGE_INSPECT, 'Inspect',
                                           self)
        self.inspect_action.setCheckable(True)
        self.inspect_action.setToolTip(
            "Inspect: details and quantisation tables, Adjust and error "
            "level analysis, the embedded thumbnail, frames")
        self.inspect_action.toggled.connect(self._show_side)
        self.toolbar.addAction(self.inspect_action)
        self.loupe_action = icons.action(icons.IMAGE_PIXEL, 'Magnifier',
                                         self)
        self.loupe_action.setCheckable(True)
        self.loupe_action.setToolTip(
            f"Magnifier: {LOUPE_SCALE}× the pixels round the pointer, drawn "
            "as blocks")
        self.loupe_action.toggled.connect(self._loupe_toggled)
        self.toolbar.addAction(self.loupe_action)

        self.previous_frame_action = icons.action(icons.FRAME_BACK,
                                                  'Previous Frame', self)
        self.next_frame_action = icons.action(icons.FRAME_FORWARD,
                                              'Next Frame', self)
        self.previous_frame_action.triggered.connect(
            lambda: self.show_frame(self._frame - 1))
        self.next_frame_action.triggered.connect(
            lambda: self.show_frame(self._frame + 1))
        self.frame_separator = self.toolbar.addSeparator()
        self.toolbar.addAction(self.previous_frame_action)
        self.frame_label = QLabel()
        self.frame_label.setObjectName("pictureFrameLabel")
        self.frame_label_action = self.toolbar.addWidget(self.frame_label)
        self.toolbar.addAction(self.next_frame_action)
        self._set_frame_controls()

        self.toolbar.addWidget(stretch())
        self.toolbar.addAction(self.save_view_action)
        self.toolbar.addAction(self.export_action)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)

    def _build_side(self):
        side = QTabWidget(self)
        side.setObjectName("pictureSidePanel")
        side.setDocumentMode(True)
        side.setMinimumWidth(240)

        self.details_view = QPlainTextEdit(side)
        self.details_view.setObjectName("monoDetailView")
        self.details_view.setReadOnly(True)
        # Wrapped: the quantisation tables are narrower than the panel, and
        # the prose lines (thumbnail, quality) are not.
        self.details_view.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        side.addTab(self.details_view, "Details")

        adjust_page = QWidget(side)
        adjust_layout = QVBoxLayout(adjust_page)
        adjust_layout.setContentsMargins(0, 0, 0, 0)
        adjust_layout.setSpacing(0)
        self.adjust_panel = AdjustPanel(adjust_page)
        self.adjust_panel.changed.connect(self._view_changed)
        ela_box = QWidget(adjust_page)
        ela_box.setObjectName("elaBox")
        ela_layout = QVBoxLayout(ela_box)
        ela_layout.setContentsMargins(8, 4, 8, 8)
        row = QHBoxLayout()
        self.ela_check = QCheckBox("Error level analysis", ela_box)
        self.ela_check.setToolTip(
            "Save the JPEG again at this quality and show the difference, "
            "amplified. Regions saved fewer times than the rest (pasted "
            "in, retouched) often stand out -- but so do edges, text and "
            "flat colour in untouched pictures. An indicator, not proof.")
        self.ela_check.toggled.connect(self._view_changed)
        self.ela_quality = QSpinBox(ela_box)
        self.ela_quality.setRange(50, 100)
        self.ela_quality.setValue(90)
        self.ela_quality.setSuffix(" quality")
        self.ela_quality.valueChanged.connect(self._view_changed)
        row.addWidget(self.ela_check)
        row.addWidget(self.ela_quality)
        row.addStretch(1)
        ela_layout.addLayout(row)
        self.ela_note = QLabel(
            "JPEG only. An indicator to look further, never proof.", ela_box)
        self.ela_note.setObjectName("adjustNote")
        self.ela_note.setWordWrap(True)
        ela_layout.addWidget(self.ela_note)
        adjust_layout.addWidget(ela_box)
        adjust_layout.addWidget(self.adjust_panel, 1)
        side.addTab(adjust_page, "Adjust")

        thumbnail_page = QWidget(side)
        thumbnail_layout = QVBoxLayout(thumbnail_page)
        thumbnail_layout.setContentsMargins(8, 8, 8, 8)
        self.thumbnail_picture = QLabel(thumbnail_page)
        self.thumbnail_picture.setObjectName("embeddedThumbnail")
        self.thumbnail_picture.setAlignment(Qt.AlignCenter)
        self.thumbnail_verdict = QLabel(thumbnail_page)
        self.thumbnail_verdict.setObjectName("thumbnailVerdict")
        self.thumbnail_verdict.setWordWrap(True)
        thumbnail_layout.addWidget(self.thumbnail_picture)
        thumbnail_layout.addWidget(self.thumbnail_verdict)
        thumbnail_layout.addStretch(1)
        side.addTab(thumbnail_page, "Thumbnail")

        self.frame_list = QListWidget(side)
        self.frame_list.setObjectName("pictureFrameList")
        self.frame_list.currentRowChanged.connect(self._frame_picked)
        side.addTab(self.frame_list, "Frames")
        self._side_pages = {'thumbnail': thumbnail_page,
                            'frames': self.frame_list}
        return side

    def _build_strip(self):
        strip = QWidget(self)
        strip.setObjectName("pictureInfoStrip")
        layout = QHBoxLayout(strip)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(12)
        self.facts_label = ElidedLabel("", strip)
        self.facts_label.setObjectName("pictureFacts")
        self.view_badge = QLabel(strip)
        self.view_badge.setObjectName("pictureViewBadge")
        self.view_badge.setVisible(False)
        self.pixel_label = QLabel(strip)
        self.pixel_label.setObjectName("picturePixelReadout")
        self.pixel_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.facts_label, 1)
        layout.addWidget(self.view_badge)
        layout.addWidget(self.pixel_label)
        return strip

    # --- showing a picture ---------------------------------------------------------

    def display(self, content):
        """Show `content`. Returns '' on success, or why it could not be read.

        A null image used to be set as an empty pixmap, so a corrupt or
        unsupported picture showed as a blank pane -- indistinguishable from
        an image that is genuinely empty.
        """
        self._generation += 1
        self._render_timer.stop()
        self.original_image_bytes = content
        self._info = {}
        self._frame = 0
        self._parts = []
        self._derived = False
        self._reset_tools()
        qt_image = QImage.fromData(content)
        problem = ''
        if qt_image.isNull():
            qt_image, problem = _decode_with_pillow(content)
        if qt_image is None or qt_image.isNull():
            self.original_pixmap = None
            self.original_image = None
            self._base = self._shown = None
            self.canvas.set_pixmap(None)
            self._show_zoom()
            self._show_state()
            return problem or "The image data could not be decoded."
        self.original_image = qt_image
        self._base = self._shown = qt_image
        self.original_pixmap = QPixmap.fromImage(qt_image)
        self.canvas.set_pixmap(self.original_pixmap)
        self._show_zoom()
        self.facts_label.setText(f"{qt_image.width():,} × "
                                 f"{qt_image.height():,} px · reading…")
        self.ela_check.setEnabled(bytes(content[:3]) == b'\xff\xd8\xff')
        self._start('inspect', {})
        self._show_state()
        return ''

    def clear(self):
        self._generation += 1
        self._render_timer.stop()
        self.original_pixmap = None
        self.original_image = None
        self.original_image_bytes = None
        self._base = self._shown = None
        self._info = {}
        self.canvas.set_pixmap(None)
        self._reset_tools()
        self._show_zoom()
        self._show_state()

    def _reset_tools(self):
        """Every tool back to the file as stored, quietly."""
        for widget in (self.upright_action, self.ela_check):
            widget.blockSignals(True)
            widget.setChecked(False)
            widget.blockSignals(False)
        self.upright_action.setEnabled(False)
        self.adjust_panel.blockSignals(True)
        self.adjust_panel.reset()
        self.adjust_panel.blockSignals(False)
        self.details_view.setPlainText('')
        self.thumbnail_picture.clear()
        self.thumbnail_verdict.setText('')
        self.frame_list.blockSignals(True)
        self.frame_list.clear()
        self.frame_list.blockSignals(False)
        self.pixel_label.setText('')
        self.facts_label.setText('')
        self._set_side_page('thumbnail', False)
        self._set_side_page('frames', False)
        self._set_frame_controls()

    def _start(self, kind, params):
        self._serial += 1
        params = dict(params, serial=self._serial)
        job = _PictureJob(self._generation, kind,
                          bytes(self.original_image_bytes), params)
        job.done.connect(self._job_done)
        self._jobs[(kind, self._serial)] = job
        job.start()

    @Slot(object)
    def _job_done(self, result):
        if result.get('generation') != self._generation:
            return
        if result['kind'] == 'inspect':
            self._inspected(result)
        elif result.get('serial') == self._serial:
            self._rendered(result)

    def _inspected(self, result):
        self._info = result
        if result.get('error'):
            self.facts_label.setText(
                f"{self.original_image.width():,} × "
                f"{self.original_image.height():,} px")
            self.details_view.setPlainText(
                "Only Qt reads this picture; Pillow cannot "
                f"({result['error']}): no details beyond its size.")
            return
        facts = result['facts']
        width = max((len(label) for label, _value in facts), default=0)
        lines = [f"{label.ljust(width)}  {value}" for label, value in facts]
        if result.get('tables'):
            lines += ['', "Quantisation tables (as the encoder wrote them)",
                      '', result['tables']]
        check = result.get('thumbnail')
        if check:
            lines += ['', f"Embedded thumbnail: {check['size'][0]} × "
                          f"{check['size'][1]} px -- {check['reason']}"]
        self.details_view.setPlainText('\n'.join(lines))
        self.facts_label.setText(self._summary(result))
        self.facts_label.setToolTip('\n'.join(f"{label}: {value}"
                                              for label, value in facts))
        self.upright_action.setEnabled(
            result.get('orientation') not in (None, 1))
        if result.get('orientation') not in (None, 1):
            from trace_app.core.image_forensics import ORIENTATIONS
            self.upright_action.setToolTip(
                f"Show Upright: the file says orientation "
                f"{result['orientation']} "
                f"({ORIENTATIONS.get(result['orientation'], '?')}); it is "
                "shown as stored until this is on.")
        self.ela_check.setEnabled(result.get('format') == 'JPEG')
        self._show_thumbnail(check)
        frames = result.get('frames') or []
        self.frame_list.blockSignals(True)
        self.frame_list.clear()
        for frame in frames:
            duration = f", {frame['duration']:g} ms" \
                if frame.get('duration') is not None else ''
            QListWidgetItem(f"Frame {frame['index'] + 1}: "
                            f"{frame['size'][0]} × {frame['size'][1]}"
                            f"{duration}", self.frame_list)
        self.frame_list.setCurrentRow(0)
        self.frame_list.blockSignals(False)
        self._set_side_page('frames', len(frames) > 1)
        self._set_frame_controls()

    def _summary(self, result):
        facts = dict(result['facts'])
        parts = [facts.get('Format', ''), facts.get('Dimensions', ''),
                 facts.get('Colour mode', '')]
        frames = facts.get('Frames', '1')
        if frames.split()[0] != '1':
            parts.append(f"{frames} frames")
        if facts.get('ICC profile') and facts['ICC profile'] != 'none':
            parts.append(f"ICC {facts['ICC profile']}")
        quality = result.get('quality')
        if quality:
            parts.append(f"Q {quality['quality']}"
                         + ('' if quality['standard'] else ' (own tables)'))
        if facts.get('EXIF orientation'):
            parts.append(f"orientation {facts['EXIF orientation']}")
        check = result.get('thumbnail')
        if check and check['differs']:
            parts.append("thumbnail differs")
        return ' · '.join(p for p in parts if p)

    def _show_thumbnail(self, check):
        self._set_side_page('thumbnail', bool(check))
        if not check:
            return
        picture = QImage.fromData(check['thumbnail'])
        if not picture.isNull():
            scale = max(1, min(3, 220 // max(1, picture.width())))
            self.thumbnail_picture.setPixmap(QPixmap.fromImage(picture.scaled(
                picture.width() * scale, picture.height() * scale,
                Qt.KeepAspectRatio, Qt.FastTransformation)))
        self.thumbnail_verdict.setProperty(
            'tone', 'warn' if check['differs'] else 'ok')
        self.thumbnail_verdict.style().unpolish(self.thumbnail_verdict)
        self.thumbnail_verdict.style().polish(self.thumbnail_verdict)
        self.thumbnail_verdict.setText(
            f"The EXIF thumbnail ({check['size'][0]} × {check['size'][1]} "
            f"px) kept inside the file: {check['reason']}."
            + (" Editors often change a picture and leave the camera's "
               "thumbnail: it may show the picture before an edit or a "
               "crop." if check['differs'] else ''))

    def _set_side_page(self, key, shown):
        page = self._side_pages[key]
        index = self.side.indexOf(page)
        self.side.setTabVisible(index, shown)

    # --- the view: frame, orientation, Adjust, error levels -----------------------

    def _view_settings(self):
        ela = self.ela_quality.value() if (
            self.ela_check.isChecked() and self.ela_check.isEnabled()) \
            else None
        return {'frame': self._frame,
                'upright': self.upright_action.isChecked(),
                'adjust': self.adjust_panel.settings(), 'ela': ela}

    def _is_stored_view(self, settings):
        from trace_app.core.image_forensics import is_neutral
        return (not settings['frame'] and not settings['upright'] and
                not settings['ela'] and is_neutral(settings['adjust']))

    @Slot()
    def _view_changed(self, *_args):
        if self.original_image is None:
            return
        self._render_timer.start()

    def _render(self):
        if self.original_image is None:
            return
        settings = self._view_settings()
        if self._is_stored_view(settings):
            self._serial += 1           # anything still running is stale
            self._base = self._shown = self.original_image
            self._parts, self._derived = [], False
            self.canvas.set_pixmap(self.original_pixmap, keep_view=True)
            self._show_state()
            return
        self.view_badge.setText("Making the view…")
        self.view_badge.setVisible(True)
        self._start('render', settings)

    def _rendered(self, result):
        if result.get('error'):
            self.view_badge.setText(f"View not made: {result['error']}")
            self.view_badge.setVisible(True)
            return
        self._shown = result['image']
        self._base = result['base'] or result['image']
        self._parts = result['parts']
        self._derived = result['derived']
        self.canvas.set_pixmap(QPixmap.fromImage(self._shown),
                               keep_view=True)
        self._show_state()

    def _show_state(self):
        """The badge and Save View: an adjusted view says so."""
        if self._derived:
            self.view_badge.setText(
                "Adjusted view, not the file's pixels: "
                + '; '.join(self._parts))
            self.view_badge.setToolTip(self.view_badge.text())
            self.view_badge.setVisible(True)
        elif self._parts:
            self.view_badge.setText("Shown: " + '; '.join(self._parts))
            self.view_badge.setToolTip(self.view_badge.text())
            self.view_badge.setVisible(True)
        else:
            self.view_badge.setVisible(False)
        self.view_badge.setProperty('tone',
                                    'warn' if self._derived else 'info')
        self.view_badge.style().unpolish(self.view_badge)
        self.view_badge.style().polish(self.view_badge)
        self.save_view_action.setEnabled(bool(self._parts))
        self.export_action.setEnabled(bool(self.original_image_bytes))

    # --- frames ---------------------------------------------------------------------

    def frame_count(self):
        return len(self._info.get('frames') or []) or 1

    def show_frame(self, index):
        count = self.frame_count()
        if count < 2:
            return
        index = max(0, min(count - 1, index))
        if index == self._frame:
            return
        self._frame = index
        self.frame_list.blockSignals(True)
        self.frame_list.setCurrentRow(index)
        self.frame_list.blockSignals(False)
        self._set_frame_controls()
        self._render_timer.stop()
        self._render()

    def _frame_picked(self, row):
        if row >= 0:
            self.show_frame(row)

    def _set_frame_controls(self):
        count = self.frame_count()
        many = count > 1
        for action in (self.previous_frame_action, self.next_frame_action,
                       self.frame_label_action, self.frame_separator):
            action.setVisible(many)
        if many:
            frame = (self._info.get('frames') or [{}])[self._frame]
            duration = f" · {frame['duration']:g} ms" \
                if frame.get('duration') is not None else ''
            self.frame_label.setText(f" Frame {self._frame + 1} of "
                                     f"{count}{duration} ")
        self.previous_frame_action.setEnabled(many and self._frame > 0)
        self.next_frame_action.setEnabled(many and self._frame < count - 1)

    # --- pointer, region, magnifier ----------------------------------------------

    @Slot(object)
    def _hovered(self, point):
        if point is None or self._base is None:
            self.pixel_label.setText(self._selection_text())
            return
        text = f"x {point.x():,}  y {point.y():,}  " + \
            _colour_text(self._base, point)
        if self._derived and self._shown is not None:
            text += f"   (view {_colour_text(self._shown, point, short=True)})"
        selection = self._selection_text()
        self.pixel_label.setText(text + (f"   {selection}" if selection
                                         else ''))

    def _selection_text(self):
        region = self.canvas.selection
        if region.isEmpty():
            return ''
        return (f"region x {region.x():,}, y {region.y():,}, "
                f"{region.width():,} × {region.height():,} px")

    @Slot(QRect)
    def _selection_changed(self, _region):
        self.pixel_label.setText(self._selection_text())

    @Slot(int, int)
    def _pan(self, dx, dy):
        for bar, delta in ((self.scroll_area.horizontalScrollBar(), dx),
                           (self.scroll_area.verticalScrollBar(), dy)):
            bar.setValue(bar.value() - delta)

    def _loupe_toggled(self, on):
        self.canvas.loupe = on
        self.canvas.update()

    def _show_side(self, on):
        self.side.setVisible(on)
        if on and not any(self.splitter.sizes()[1:]):
            total = max(1, self.splitter.width())
            self.splitter.setSizes([max(1, total - 300), 300])

    def _canvas_menu(self, position):
        if self.original_image is None:
            return
        menu = QMenu(self)
        point = self.canvas.image_point(position)
        if point is not None and self._base is not None:
            value = f"x {point.x()}, y {point.y()}: " + \
                _colour_text(self._base, point)
            menu.addAction(icons.icon(icons.IMAGE_PIXEL),
                           "Copy Pixel Value").triggered.connect(
                lambda: QGuiApplication.clipboard().setText(value))
        if not self.canvas.selection.isEmpty():
            menu.addAction(icons.icon(icons.SAVE_PICTURE),
                           "Export Region…").triggered.connect(
                self.export_region)
            bookmark = menu.addAction(icons.icon(icons.BOOKMARK),
                                      "Bookmark Region…")
            bookmark.triggered.connect(self.bookmark_region)
            bookmark.setEnabled(self.bookmark_hook is not None)
            menu.addAction("Clear Selection").triggered.connect(
                self.canvas.clear_selection)
        if menu.actions():
            menu.addSeparator()
        menu.addAction(self.save_view_action)
        menu.addAction(self.export_action)
        from trace_app.ui.widgets.context_menus import show_menu
        show_menu(menu, self.canvas.mapToGlobal(position), False)

    # --- zoom and rotation: always drawn from the original ---------------------

    def _show_zoom(self):
        self.zoom_label.setText(f" {self.canvas.zoom * 100:.0f}% "
                                if self.canvas.pixmap is not None else '')

    def set_zoom(self, zoom):
        """Zoom, keeping the middle of what is in view in the middle."""
        viewport = self.scroll_area.viewport()
        bars = (self.scroll_area.horizontalScrollBar(),
                self.scroll_area.verticalScrollBar())
        extents = (viewport.width(), viewport.height())
        old = self.canvas.size()
        centres = [(bar.value() + extent / 2) / max(1, size)
                   for bar, extent, size in
                   zip(bars, extents, (old.width(), old.height()))]
        self.canvas.set_view(zoom=zoom)
        new = self.canvas.size()
        for bar, centre, extent, size in zip(bars, centres, extents,
                                             (new.width(), new.height())):
            bar.setValue(round(centre * size - extent / 2))
        self._show_zoom()

    def zoom_in(self):
        self.set_zoom(self.canvas.zoom * ZOOM_STEP)

    def zoom_out(self):
        self.set_zoom(self.canvas.zoom / ZOOM_STEP)

    def fit(self):
        """The whole picture in view, never enlarged past actual size."""
        if self.canvas.pixmap is None:
            return
        width, height = self.canvas.pixmap.width(), \
            self.canvas.pixmap.height()
        if self.canvas.rotation in (90, 270):
            width, height = height, width
        viewport = self.scroll_area.viewport().size()
        self.set_zoom(min(1.0, viewport.width() / max(1, width),
                          viewport.height() / max(1, height)))

    def rotate_left(self):
        self.canvas.set_view(rotation=self.canvas.rotation - 90)

    def rotate_right(self):
        self.canvas.set_view(rotation=self.canvas.rotation + 90)

    def reset(self):
        self.canvas.set_view(zoom=1.0, rotation=0)
        self._show_zoom()

    def eventFilter(self, watched, event):
        # Ctrl+wheel zooms, as in the text and list views.
        if event.type() == QEvent.Wheel and \
                watched is self.scroll_area.viewport() and \
                event.modifiers() & Qt.ControlModifier:
            delta = event.angleDelta().y()
            if delta > 0:
                self.zoom_in()
            elif delta < 0:
                self.zoom_out()
            return True
        return super().eventFilter(watched, event)

    # --- saving ------------------------------------------------------------------

    def _source(self):
        return getattr(self, 'source_name', None) or 'picture shown'

    def _file_stem(self):
        import os
        name = os.path.basename(str(self.source_name or '')) or 'picture'
        return os.path.splitext(name)[0] or 'picture'

    def _ask_path(self, title, suggested):
        from trace_app.core.evidence_export import safe_component
        from trace_app.core.settings import export_dir
        import os
        name = safe_component(suggested, 'picture.png')
        path, _ = QFileDialog.getSaveFileName(
            self, title, os.path.join(export_dir(), name), "PNG (*.png)")
        return path

    def _save(self, path, data, what, source):
        from trace_app.core import evidence_export
        try:
            return evidence_export.save_bytes(path, data, what, source)
        except Exception as exc:
            message.warning(self, "Export Error", str(exc))
            return None

    def save_view(self):
        """What is on screen, as a PNG derivative: named and audited with
        every step that made it."""
        if self._shown is None or not self._parts:
            return
        steps = '; '.join(self._parts)
        path = self._ask_path("Save View",
                              f"{self._file_stem()} (view).png")
        if not path:
            return
        digests = self._save(
            path, png_of(self._shown), 'picture view saved',
            f"{self._source()} -- a view, not the file's bytes: {steps}")
        if digests:
            message.information(
                self, "View saved",
                f"Saved as a derivative PNG: {steps}.\n\nThe file itself "
                f"is unchanged; Save Image writes its bytes.\n\nSHA-256 "
                f"{digests['sha256']}")

    def export_region(self):
        """The selected region of the file's pixels (this frame, turned as
        shown), as a PNG."""
        region = self.canvas.selection
        if region.isEmpty() or self._base is None:
            return
        label = (f"x {region.x()}, y {region.y()}, {region.width()} × "
                 f"{region.height()} px")
        path = self._ask_path(
            "Export Region",
            f"{self._file_stem()} region {region.x()},{region.y()} "
            f"{region.width()}x{region.height()}.png")
        if not path:
            return
        steps = '; '.join(p for p in self._parts if p)
        digests = self._save(
            path, png_of(self._base.copy(region)), 'picture region exported',
            f"{self._source()}: region {label}"
            + (f" ({steps})" if steps and not self._derived else ''))
        if digests:
            message.information(
                self, "Region exported",
                f"The file's pixels in {label}, as PNG.\n\nSHA-256 "
                f"{digests['sha256']}")

    def bookmark_region(self):
        region = self.canvas.selection
        if region.isEmpty() or self.bookmark_hook is None:
            return
        frame = f", frame {self._frame + 1}" if self._frame else ''
        self.bookmark_hook(
            f"{self._file_stem()}: region x {region.x()}, y {region.y()}, "
            f"{region.width()} × {region.height()} px{frame}")

    def export_original_image(self):
        # Ensure that an image is currently loaded
        if not self.original_image_bytes:
            message.warning(self, "Export Error", "No image is currently loaded.")
            return

        # Ask the user where to save the exported image
        from trace_app.core.settings import export_dir
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Image", export_dir(),
                                                   "PNG (*.png);;JPEG (*.jpg *.jpeg);;All Files (*)")

        # If a location is chosen, save the image
        if file_name:
            digests = self._save(file_name, bytes(self.original_image_bytes),
                                 'picture exported', self._source())
            if digests:
                message.information(
                    self, "Export Success",
                    f"Exported as stored, unchanged.\n\nSHA-256 "
                    f"{digests['sha256']}\nWritten copy: "
                    f"{digests['written_copy_check']}")

    def shutdown(self):
        """Wait for any job still running (the viewer is going)."""
        self._render_timer.stop()
        self._jobs.clear()


def _colour_text(image, point, short=False):
    """A pixel's colour: 'RGB(12, 34, 56) #0C2238' (+ alpha when it has
    one), or 'grey 128'."""
    colour = QColor(image.pixelColor(point))
    if image.format() == QImage.Format_Grayscale8:
        return f"grey {colour.red()}"
    alpha = image.hasAlphaChannel()
    values = (colour.red(), colour.green(), colour.blue())
    text = f"RGB{'A' if alpha else ''}({', '.join(map(str, values))}" + \
        (f", {colour.alpha()}" if alpha else '') + ")"
    if short:
        return text
    return text + f" #{colour.red():02X}{colour.green():02X}" \
        f"{colour.blue():02X}" + (f"{colour.alpha():02X}" if alpha else '')


def _decode_with_pillow(content):
    """(QImage, '') via Pillow, or (None, reason) when it cannot either.

    Pillow's decompression-bomb guard stays on: a crafted header claiming
    billions of pixels is refused rather than allocated. Only the first frame
    of an animation is shown, as Qt does.
    """
    try:
        from PIL import Image
    except ImportError:
        return None, "Pillow is not installed."
    try:
        with Image.open(io.BytesIO(content)) as image:
            image.load()
            return to_qimage(image.convert('RGBA')), ''
    except Image.UnidentifiedImageError:
        return None, ("The content is not in any image format TRACE can read. "
                      "It may be damaged, encrypted, or not an image at all; "
                      "the Hex tab shows the raw bytes.")
    except Image.DecompressionBombError as exc:
        return None, (f"Refused: the image claims to be too large to decode "
                      f"safely ({exc}).")
    except Exception as exc:
        logger.debug("Pillow could not decode the image: %s", exc)
        return None, f"The image data could not be decoded ({exc})."

"""Carved files: the Triage sub-tab that recovers deleted files and lists them.

Carving searches raw image bytes for file signatures (core/carving.py). Here
an examiner picks what to carve -- one image or every open one, which types,
unallocated space or the whole image -- and works down what came back, in a
table or as thumbnails.

Two modes, one engine:

* **With a case** a carve is a job on the shared queue, its files written
  under the case's carved/<evidence>/ and recorded in case.db (Case.add_carved)
  with an audit line; they appear in Triage, the Findings node and can be
  bookmarked. The Analysis Modules dialog queues the same jobs.
* **Quick triage** (no case) keeps the results for the session only, in the
  per-user carved_files/<image>/ folder.

A click previews the file read straight back from the image at its offset,
not the copy on disk -- what is examined is the evidence.
"""

import logging
import os

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QIcon, QImageReader, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox,
                               QComboBox, QHeaderView, QLabel,
                               QListWidget, QListWidgetItem, QPushButton,
                               QSizePolicy, QStackedWidget, QTableWidget,
                               QTableWidgetItem, QToolBar,
                               QVBoxLayout, QWidget)

from trace_app.core.carving import CARVABLE_TYPES, CARVE_CATEGORIES
from trace_app.infra.constants import TABLE_ROW_HEIGHT, UNKNOWN_DATE
from trace_app.infra.paths import carved_files_dir
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui import icons
from trace_app.ui.widgets.multi_select import MultiSelectButton
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar

logger = logging.getLogger('TRACE.Carving')

#: Thumbnails drawn per timer tick, so a gallery of thousands builds without
#: freezing the window.
_THUMBS_PER_TICK = 24
_THUMB = 120

#: Types shown as a rendered picture rather than an icon. Qt draws most;
#: Pillow what Qt cannot -- AVIF, PSD, and HEIC through pi-heif.
_PICTURE_TYPES = frozenset({'jpg', 'png', 'gif', 'bmp', 'tiff', 'webp',
                            'avif', 'heic', 'psd', 'pdf'})
_VIDEO = ('mov', 'mp4', 'm4v', '3gp', 'wmv', 'avi', 'flv', 'mpg', 'mkv', 'webm')
_AUDIO = ('wav', 'mp3', 'ogg', 'opus', 'm4a')
_ARCHIVE = ('zip', 'gz', 'bz2', 'xz', 'tar', 'rar', '7z')
_ICON_FOR_TYPE = {
    **{t: icons.FILE_VIDEO for t in _VIDEO},
    **{t: icons.FILE_AUDIO for t in _AUDIO},
    **{t: icons.FILE_ARCHIVE for t in _ARCHIVE},
    'ole': icons.FILE_DOC, 'html': icons.FILE_HTML,
}

_COLUMNS = ['Name', 'Evidence', 'Type', 'Size', 'Offset', 'Embedded date',
            'Date from', 'Pieces', 'SHA-256', 'Saved to']


def _pieces(row):
    """(cell text, tooltip) for how a carved file was laid out on disk."""
    fragments = row.get('fragments')
    if not fragments:
        return 'contiguous', "Carved as one run of bytes."
    lines = [f"  {length:,} bytes at 0x{begin:x}" for begin, length in fragments]
    return (f"rebuilt from {len(fragments)}",
            "Reassembled: the file system had split this file, and its own "
            "structure proved where. Joined from:\n"
            + "\n".join(lines))


def session_folder(label):
    """Quick triage's folder for one image's carved files."""
    safe = ''.join(c if c.isalnum() or c in '-_.' else '_'
                   for c in label)[:60].strip('._') or 'image'
    return os.path.join(carved_files_dir(), safe)


class CarvingWorker(ProcessWorker):
    """Carves one image in a child process (core/background.py)."""

    #: (megabytes done, megabytes total, files found)
    progressed = Signal(int, int, int)
    file_carved = Signal(dict)
    finished_carving = Signal(int, str)

    kind = 'carve'

    def __init__(self, image_path, file_types, unallocated_only,
                 case_folder=None, evidence_id=None, label='', parent=None):
        self.image_path = image_path
        self.evidence_id = evidence_id
        self.label = label or os.path.basename(image_path)
        super().__init__({
            'image_path': image_path,
            'file_types': list(file_types),
            'unallocated_only': unallocated_only,
            'case_folder': case_folder,
            'evidence_id': evidence_id,
            # Decided here: the per-user folder is the window's to choose.
            'folder': None if case_folder else session_folder(self.label),
        }, parent)

    def on_progress(self, done, total, found):
        self.progressed.emit(done, total, found)

    def on_item(self, record):
        self.file_carved.emit(dict(record, evidence_id=self.evidence_id,
                                   evidence_key=self._key(),
                                   evidence_label=self.label,
                                   image_path=self.image_path))

    def on_done(self, count, error):
        self.finished_carving.emit(count, error)

    def _key(self):
        return self.evidence_id if self.evidence_id is not None \
            else self.image_path


class _SortItem(QTableWidgetItem):
    """A cell that sorts by a number rather than by its text."""

    def __init__(self, text, key):
        super().__init__(text)
        self._key = key

    def __lt__(self, other):
        if isinstance(other, _SortItem):
            return self._key < other._key
        return super().__lt__(other)


class CarvedFilesPanel(QWidget):
    """Carve, and list what was carved."""

    #: (targets, types, unallocated_only). `targets` is a list of evidence
    #: keys -- evidence ids with a case, image paths without -- or None for
    #: every image.
    carve_requested = Signal(object, list, bool)
    #: A row the examiner landed on: preview it.
    file_selected = Signal(dict)
    #: A double-click: open it -- an archive is browsed like a folder.
    file_activated = Signal(dict)
    #: (row, global position): the host builds the menu.
    file_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("carvedPanel")
        self.case = None
        self.evidence_filter = None
        self.icon_resolver = None
        #: Quick triage's results, which live only as long as the window.
        self._session = []
        self._rows = []
        self._thumb_queue = []
        self._thumb_timer = QTimer(self)
        self._thumb_timer.setInterval(0)
        self._thumb_timer.timeout.connect(self._draw_some_thumbnails)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        bar = QToolBar()
        prepare_toolbar(bar)
        bar.setObjectName("carvedToolbar")
        bar.addWidget(QLabel("Carve"))
        self.target_combo = QComboBox()
        self.target_combo.setObjectName("carveTargetCombo")
        self.target_combo.setToolTip("Which image to search: one, or every "
                                     "image open.")
        bar.addWidget(self.target_combo)
        bar.addWidget(QLabel("for"))
        self.type_button = MultiSelectButton(CARVABLE_TYPES, self, noun="types",
                                             categories=CARVE_CATEGORIES)
        self.type_button.set_selected(CARVABLE_TYPES)
        bar.addWidget(self.type_button)
        self.unallocated_box = QCheckBox("Unallocated space only")
        self.unallocated_box.setChecked(True)
        self.unallocated_box.setToolTip(
            "Skip space that belongs to live files: they are already in the "
            "tree, and carving them again buries the deleted data in "
            "duplicates. Untick to search the whole image.")
        bar.addWidget(self.unallocated_box)
        self.carve_button = QPushButton("Start Carving")
        self.carve_button.setObjectName("carveButton")
        self.carve_button.clicked.connect(self._request)
        bar.addWidget(self.carve_button)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        bar.addWidget(spacer)

        # Table or thumbnails: one choice, two buttons. Push buttons, which
        # size to their label: the theme caps toolbar tool buttons at an
        # icon's width.
        self.view_group = QButtonGroup(self)
        for index, (text, tip) in enumerate((
                ("Table", "List carved files with their details"),
                ("Thumbnails", "Show carved files as pictures"))):
            button = QPushButton(text)
            button.setObjectName("carvedViewButton")
            button.setToolTip(tip)
            button.setCheckable(True)
            button.setChecked(index == 0)
            self.view_group.addButton(button, index)
            bar.addWidget(button)
        self.view_group.idToggled.connect(self._view_changed)
        align_controls(bar)
        layout.addWidget(bar)

        self.status_label = QLabel()
        self.status_label.setObjectName("carvedStatus")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.setSortingEnabled(True)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        connect_row_preview(self.table, self.file_selected.emit)
        self.table.itemDoubleClicked.connect(
            lambda item: self.file_activated.emit(
                self.table.item(item.row(), 0).data(Qt.UserRole)))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        self.stack.addWidget(self.table)

        self.gallery = QListWidget()
        self.gallery.setObjectName("carvedGallery")
        self.gallery.setViewMode(QListWidget.IconMode)
        self.gallery.setIconSize(QSize(_THUMB, _THUMB))
        self.gallery.setGridSize(QSize(_THUMB + 16, _THUMB + 34))
        self.gallery.setResizeMode(QListWidget.Adjust)
        self.gallery.setMovement(QListWidget.Static)
        self.gallery.setUniformItemSizes(True)
        self.gallery.currentItemChanged.connect(
            lambda item, _old: item and self.file_selected.emit(
                item.data(Qt.UserRole)))
        self.gallery.itemDoubleClicked.connect(
            lambda item: self.file_activated.emit(item.data(Qt.UserRole)))
        self.gallery.setContextMenuPolicy(Qt.CustomContextMenu)
        self.gallery.customContextMenuRequested.connect(self._gallery_menu)
        self.stack.addWidget(self.gallery)

        self.set_targets([])
        self.refresh()

    # --- what can be carved ------------------------------------------

    def set_targets(self, targets):
        """The images on offer: [(key, label)], key an evidence id with a
        case or an image path without."""
        keep = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        if len(targets) > 1:
            self.target_combo.addItem(f"All {len(targets)} images", None)
        for key, label in targets:
            self.target_combo.addItem(label, key)
        index = self.target_combo.findData(keep)
        self.target_combo.setCurrentIndex(max(index, 0))
        self.target_combo.blockSignals(False)
        if self.case is not None:
            self._select_target(self.evidence_filter)
        self.target_combo.setEnabled(bool(targets))
        self.carve_button.setEnabled(bool(targets))

    def _request(self):
        types = [t.lower() for t in self.type_button.selected()]
        if not types:
            self.status_label.setText("Choose at least one file type to "
                                      "carve for.")
            return
        key = self.target_combo.currentData()
        self.carve_requested.emit(None if key is None else [key], types,
                                  self.unallocated_box.isChecked())

    # --- what was carved ---------------------------------------------

    def set_case(self, case):
        self.case = case
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        """Show one image's carved files, or all; and carve that image.

        The Carve selector follows Triage's filter, so the image being looked
        at is the image Start Carving searches. It used to stay on "All
        images", and a carve meant for one image ran on every one.
        """
        self.evidence_filter = evidence_id
        self._select_target(evidence_id)
        self.refresh()

    def _select_target(self, evidence_id):
        if self.case is None:
            return
        index = self.target_combo.findData(evidence_id)
        if index >= 0:
            self.target_combo.setCurrentIndex(index)

    def add_record(self, record):
        """A file just carved: shown at once, before the job finishes."""
        if self.case is None:
            self._session.append(record)
        if self._shown(record):
            self._rows.append(record)
            self._add_table_row(record)
            if self.stack.currentIndex() == 1:
                self._add_gallery_item(record)
            self._update_status()

    def forget(self, key):
        """Drop one image's earlier results as it is carved again.

        From the rows on screen rather than by re-reading the case: the
        worker is clearing that evidence's rows at the same moment.
        """
        self._session = [r for r in self._session
                         if r.get('evidence_key') != key]
        self._rows = [r for r in self._rows if r.get('evidence_key') != key]
        self._show(self._rows)

    def _show(self, rows):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for row in rows:
            self._add_table_row(row, fit=False)
        self.table.setSortingEnabled(True)
        if rows:
            fit_columns(self.table, {1: 220, 8: 140, 9: 320})
            self.table.setColumnWidth(0, max(self.table.columnWidth(0), 160))
        if self.stack.currentIndex() == 1:
            self._rebuild_gallery()
        self._update_status()

    def _shown(self, record):
        return (self.case is None or self.evidence_filter is None
                or record.get('evidence_id') == self.evidence_filter)

    def refresh(self):
        if self.case is not None:
            names = {r['id']: r.get('display_name')
                     or os.path.basename(r['path'])
                     for r in self.case.evidence()}
            paths = {r['id']: r['path'] for r in self.case.evidence()}
            rows = []
            for row in self.case.carved_files(self.evidence_filter):
                row['evidence_label'] = names.get(row['evidence_id'], '')
                row['evidence_key'] = row['evidence_id']
                row['image_path'] = paths.get(row['evidence_id'], '')
                rows.append(row)
        else:
            rows = list(self._session)
        self._rows = rows
        self._show(rows)

    @property
    def count(self):
        return len(self._rows)

    def _update_status(self):
        count = len(self._rows)
        self.count_changed.emit(count)
        if count:
            images = len({r.get('evidence_key') for r in self._rows})
            where = f" from {images} images" if images > 1 else ""
            kept = ("in the case" if self.case is not None
                    else "for this session only — open a case to keep them")
            self.status_label.setText(
                f"{count:,} file(s) recovered{where}, kept {kept}.")
        elif self.case is None:
            self.status_label.setText(
                "Carving recovers deleted files from an image's raw bytes by "
                "their signatures. Without a case the results last for this "
                "session.")
        else:
            self.status_label.setText(
                "Nothing carved yet. Carving recovers deleted files from an "
                "image's raw bytes by their signatures; it can also run from "
                "Analysis ▸ Run Analysis Modules.")

    def _add_table_row(self, row, fit=True):
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        position = self.table.rowCount()
        self.table.insertRow(position)
        size = int(row.get('size') or 0)
        offset = int(row.get('offset') or 0)
        date = row.get('embedded_date') or UNKNOWN_DATE
        pieces, pieces_tip = _pieces(row)
        values = [
            QTableWidgetItem(row.get('name') or ''),
            QTableWidgetItem(row.get('evidence_label') or ''),
            QTableWidgetItem((row.get('type') or '').upper()),
            _SortItem(FileSystemUtils.get_readable_size(size), size),
            _SortItem(f"0x{offset:x}", offset),
            QTableWidgetItem(date),
            QTableWidgetItem(row.get('date_source') or ''),
            QTableWidgetItem(pieces),
            QTableWidgetItem((row.get('sha256') or '')[:16] + '…'
                             if row.get('sha256') else ''),
            QTableWidgetItem(self._shown_path(row.get('path') or '')),
        ]
        values[0].setData(Qt.UserRole, row)
        if self.icon_resolver:
            icon = self.icon_resolver(row.get('type') or 'unknown')
            if icon is not None:
                values[0].setIcon(icon)
        values[0].setToolTip(f"Found at byte {offset:,} of "
                             f"{row.get('evidence_label') or 'the image'}")
        if date == UNKNOWN_DATE:
            values[5].setToolTip(
                f"{(row.get('type') or '').upper()} carries no date in its "
                "own data, and a carved file has no file-system record to "
                "read one from.")
        values[7].setToolTip(pieces_tip)
        values[8].setToolTip(row.get('sha256') or '')
        values[9].setToolTip(row.get('path') or '')
        for column, item in enumerate(values):
            self.table.setItem(position, column, item)
        self.table.setSortingEnabled(sorting)
        if fit and position == 0:
            fit_columns(self.table, {1: 220, 8: 140, 9: 320})

    def _shown_path(self, path):
        """Inside a case, the path from the case folder: it is shorter and
        says where in the case the copy is."""
        if self.case is not None and path:
            try:
                relative = os.path.relpath(path, self.case.folder)
            except ValueError:
                return path
            if not relative.startswith('..'):
                return relative
        return path

    # --- thumbnails --------------------------------------------------

    def _view_changed(self, index, checked):
        if not checked:
            return
        self.stack.setCurrentIndex(index)
        if index == 1:
            self._rebuild_gallery()

    def _rebuild_gallery(self):
        self._thumb_timer.stop()
        self.gallery.clear()
        self._thumb_queue = []
        for row in self._rows:
            self._add_gallery_item(row)

    def _add_gallery_item(self, row):
        item = QListWidgetItem(row.get('name') or '')
        item.setData(Qt.UserRole, row)
        item.setToolTip(f"{row.get('evidence_label') or ''}\n"
                        f"{(row.get('type') or '').upper()}, "
                        f"{FileSystemUtils.get_readable_size(row.get('size') or 0)}")
        kind = row.get('type') or 'unknown'
        glyph = _ICON_FOR_TYPE.get(kind)
        fallback = self.icon_resolver(kind) if self.icon_resolver else None
        if glyph is not None:
            item.setIcon(icons.icon(glyph))
        else:
            # The file type's own icon -- until, for a picture, its thumbnail
            # is drawn; or for good, if the data will not decode.
            item.setIcon(fallback or icons.icon(icons.CARVING))
            if kind in _PICTURE_TYPES:
                self._thumb_queue.append(item)
                self._thumb_timer.start()
        self.gallery.addItem(item)

    def _draw_some_thumbnails(self):
        for _ in range(_THUMBS_PER_TICK):
            if not self._thumb_queue:
                self._thumb_timer.stop()
                return
            item = self._thumb_queue.pop(0)
            row = item.data(Qt.UserRole) or {}
            pixmap = _thumbnail(row.get('path') or '', row.get('type') or '')
            if not pixmap.isNull():
                item.setIcon(QIcon(pixmap))

    # --- menus -------------------------------------------------------

    def _table_menu(self, point):
        item = self.table.itemAt(point)
        if item is None:
            return
        row = self.table.item(item.row(), 0).data(Qt.UserRole)
        if row:
            self.file_menu_requested.emit(
                row, self.table.viewport().mapToGlobal(point))

    def _gallery_menu(self, point):
        item = self.gallery.itemAt(point)
        if item is not None:
            self.file_menu_requested.emit(
                item.data(Qt.UserRole),
                self.gallery.viewport().mapToGlobal(point))


def _pillow_thumbnail(path):
    """What Qt cannot decode -- AVIF, PSD -- through Pillow."""
    from PIL import Image
    from PySide6.QtGui import QImage
    with Image.open(path) as image:
        image.thumbnail((_THUMB * 2, _THUMB * 2))
        image = image.convert('RGBA')
        data = image.tobytes('raw', 'RGBA')
        qimage = QImage(data, image.width, image.height, QImage.Format_RGBA8888)
        return QPixmap.fromImage(qimage.copy())


def _thumbnail(path, file_type):
    """A thumbnail of a carved picture or PDF, or a null pixmap.

    Scaled to fit, never cropped: a thumbnail that trims the edges of a
    picture hides part of the evidence.
    """
    pixmap = QPixmap()
    try:
        if file_type == 'pdf':
            from pymupdf import Matrix, open as open_pdf
            with open_pdf(path) as document:
                if document.page_count:
                    page = document.load_page(0)
                    scale = _THUMB / max(page.rect.width, page.rect.height, 1)
                    image = page.get_pixmap(matrix=Matrix(scale * 2, scale * 2))
                    pixmap.loadFromData(image.tobytes('png'), 'PNG')
        elif file_type in _PICTURE_TYPES:
            reader = QImageReader(path)
            reader.setAutoTransform(True)
            size = reader.size()
            if size.isValid() and size.width() and size.height():
                factor = (_THUMB * 2) / max(size.width(), size.height())
                if factor < 1:
                    reader.setScaledSize(size * factor)
            image = reader.read()
            if not image.isNull():
                pixmap = QPixmap.fromImage(image)
            else:
                pixmap = _pillow_thumbnail(path)
    except Exception as exc:
        logger.debug("No thumbnail for %s: %s", path, exc)
        return QPixmap()
    if pixmap.isNull():
        return pixmap
    return pixmap.scaled(_THUMB, _THUMB, Qt.KeepAspectRatio,
                         Qt.SmoothTransformation)

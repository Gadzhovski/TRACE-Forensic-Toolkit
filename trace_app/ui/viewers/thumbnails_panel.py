"""Thumbnails: the pictures Windows' thumbnail caches hold
(core/thumbnails.py).

A Triage sub-tab: a grid of the pictures, Thumbs.db pictures of files that
are no longer in their folder first, each captioned with the file it is of
(Thumbs.db) or its cache id (thumbcache). A picture is read from its cache
on the image only when it scrolls into view, and kept while it stays near.
Landing on one shows it in the viewer; double-click goes to the cache file.
"""

import logging
from collections import OrderedDict

from PySide6.QtCore import (QAbstractListModel, QModelIndex, QSize, Qt,
                            Signal)
from PySide6.QtGui import QIcon, QImage, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QHBoxLayout, QLabel, QListView, QSizePolicy,
                               QVBoxLayout, QWidget)

from trace_app.infra.constants import CONTROL_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.process_worker import ProcessWorker

logger = logging.getLogger('TRACE.ThumbnailsPanel')

TILE = 112
_STATE_NOTES = {'absent': 'file gone', 'deleted': 'file deleted',
                'folder': "the folder's picture"}


class ThumbnailsWorker(ProcessWorker):
    progressed = Signal(int, int, str)
    finished_thumbnails = Signal(int, str)

    kind = 'thumbnails'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_thumbnails.emit(count, error)


def caption(row):
    label = row.get('name') or row.get('key') or row.get('location') or ''
    note = _STATE_NOTES.get(row.get('original_state'))
    return f"{label}\n{note}" if note else label


def describe(row, image_name=''):
    lines = [row.get('name') and f"Picture of: {row['name']}",
             f"Cache: {row.get('cache_path')}"
             + (' (deleted)' if row.get('cache_deleted') else ''),
             f"Kind: {row.get('cache_kind')} — {row.get('system') or ''}"
             + (f", {row['cache_size']} size" if row.get('cache_size')
                else ''),
             row.get('user') and f"User: {row['user']}",
             row.get('key') and f"Cache id: {row['key']}",
             row.get('modified_utc') and
             f"File modified (catalog): {row['modified_utc']}",
             {'folder': "The picture Windows shows for the folder itself",
              'absent': "The file is no longer in the folder",
              'deleted': "The file is in the folder only as a deleted entry",
              'present': "The file is still in the folder"}.get(
                 row.get('original_state')),
             (f"{row.get('width')} × {row.get('height')} " if row.get('width')
              else '') + f"{(row.get('format') or '').upper()}, "
             f"{FileSystemUtils.get_readable_size(row.get('size') or 0)}",
             row.get('sha256') and f"SHA-256: {row['sha256']}",
             image_name and f"Evidence: {image_name}"]
    return '\n'.join(line for line in lines if line)


class ThumbnailModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.names = {}
        self.reader = None
        self._icons = OrderedDict()
        self._placeholder = QIcon()

    def set_rows(self, rows, names):
        self.beginResetModel()
        self.rows, self.names = rows, names
        self._icons.clear()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def _icon(self, row):
        key = row['id']
        if key in self._icons:
            self._icons.move_to_end(key)
            return self._icons[key]
        icon = self._placeholder
        if self.reader is not None and row.get('format'):
            try:
                data = self.reader(row)
            except Exception as exc:
                logger.debug("Thumbnail %s unreadable: %s", key, exc)
                data = None
            image = QImage.fromData(data) if data else QImage()
            if not image.isNull():
                # Scaled to fit, never cropped: a cropped thumbnail hides
                # what is at its edges.
                icon = QIcon(QPixmap.fromImage(image.scaled(
                    TILE - 16, TILE - 32, Qt.KeepAspectRatio,
                    Qt.SmoothTransformation)))
        self._icons[key] = icon
        while len(self._icons) > 1500:
            self._icons.popitem(last=False)
        return icon

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return caption(row)
        if role == Qt.DecorationRole:
            return self._icon(row)
        if role == Qt.ToolTipRole:
            return describe(row, self.names.get(row.get('evidence_id'), ''))
        if role == Qt.UserRole:
            return row
        return None


class ThumbnailsPanel(QWidget):
    picture_selected = Signal(dict)
    picture_activated = Signal(dict)
    picture_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("thumbnailsPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self.count = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.cache_combo = QComboBox()
        self.cache_combo.setObjectName("thumbnailCacheCombo")
        self.cache_combo.setFixedHeight(CONTROL_HEIGHT)
        self.cache_combo.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.cache_combo.setMinimumContentsLength(14)
        self.cache_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        bar.addWidget(self.cache_combo)
        self.gone_box = QCheckBox("Files gone only")
        self.gone_box.setToolTip("Only pictures of files that are gone. "
                                 "Thumbs.db names the file each picture is "
                                 "of; these are no longer in the folder, or "
                                 "are there only as deleted entries.")
        self.gone_box.toggled.connect(lambda _on: self.refresh())
        bar.addWidget(self.gone_box)
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setSizePolicy(QSizePolicy.Ignored,
                                        QSizePolicy.Preferred)
        bar.addWidget(self.status_label, 1)
        layout.addLayout(bar)

        self.model = ThumbnailModel(self)
        self.view = QListView()
        self.view.setObjectName("thumbnailGrid")
        self.view.setViewMode(QListView.IconMode)
        self.view.setResizeMode(QListView.Adjust)
        self.view.setMovement(QListView.Static)
        self.view.setUniformItemSizes(True)
        self.view.setWordWrap(False)
        self.view.setTextElideMode(Qt.ElideMiddle)
        self.view.setIconSize(QSize(TILE - 16, TILE - 32))
        self.view.setGridSize(QSize(TILE + 8, TILE + 26))
        self.view.setSpacing(4)
        self.view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.view.setModel(self.model)
        self.view.selectionModel().currentChanged.connect(
            lambda current, _previous: self._emit(current,
                                                  self.picture_selected))
        self.view.clicked.connect(
            lambda index: self._emit(index, self.picture_selected))
        self.view.doubleClicked.connect(
            lambda index: self._emit(index, self.picture_activated))
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.view, 1)
        self.refresh()

    def set_reader(self, reader):
        """`reader(row)` -> the picture's bytes, read from the image."""
        self.model.reader = reader

    def _emit(self, index, signal):
        if index.isValid():
            signal.emit(self.model.rows[index.row()])

    def _menu(self, point):
        index = self.view.indexAt(point)
        if index.isValid():
            self.picture_menu_requested.emit(
                self.model.rows[index.row()],
                self.view.viewport().mapToGlobal(point))

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self._fill_caches()
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self._fill_caches()
        self.refresh()

    def shutdown(self):
        self.model.reader = None

    def _fill_caches(self):
        chosen = self.cache_combo.currentData()
        self.cache_combo.blockSignals(True)
        self.cache_combo.clear()
        self.cache_combo.addItem("All caches", None)
        if self.case is not None:
            seen = set()
            for row in self.case.thumbnails(self.evidence_id):
                key = (row['evidence_id'], row['cache_ref'])
                if key in seen:
                    continue
                seen.add(key)
                label = row['cache_path']
                if len(self._names) > 1:
                    label = f"{self._names.get(row['evidence_id'], '')}: " \
                            f"{label}"
                self.cache_combo.addItem(label, key)
        position = self.cache_combo.findData(chosen)
        self.cache_combo.setCurrentIndex(max(0, position))
        self.cache_combo.blockSignals(False)

    def refresh(self):
        rows = []
        if self.case is not None:
            chosen = self.cache_combo.currentData()
            rows = self.case.thumbnails(
                self.evidence_id if chosen is None else chosen[0],
                cache_ref=None if chosen is None else chosen[1],
                gone_only=self.gone_box.isChecked())
            rows = [r for r in rows if r.get('format')] + \
                [r for r in rows if not r.get('format')]
        self.model.set_rows(rows, self._names)
        self.count = len(rows)
        if self.case is None:
            text = "Thumbnail caches are read into a case."
        elif not rows:
            text = ("No thumbnail caches read yet. Run Analysis ▸ Thumbnail "
                    "caches finds every Thumbs.db and thumbcache_*.db.")
        else:
            counts = self.case.thumbnail_counts(self.evidence_id)
            text = (f"{counts['pictures']:,} picture(s) in "
                    f"{counts['caches']:,} cache(s)")
            if counts['gone']:
                text += (f" — {counts['gone']:,} of files no longer in "
                         f"their folder")
        self.status_label.setText(text)
        self.status_label.setToolTip(text)
        self.count_changed.emit(self.count)

    def select_row(self, predicate):
        for position, row in enumerate(self.model.rows):
            if predicate(row):
                index = self.model.index(position)
                self.view.setCurrentIndex(index)
                self.view.scrollTo(index)
                return True
        return False

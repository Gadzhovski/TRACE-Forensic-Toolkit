"""Similar pictures: the same picture, resized, re-saved or lightly edited.

A Triage sub-tab over the perceptual hashes the photo module records
(core/phash.py). Exact hashes group identical files; these group pictures
that *look* alike -- a photo and its thumbnail, a re-compressed copy sent
through a messenger, a brightened or slightly cropped version. Each group
is listed with the largest picture first (most likely the original) and how
many of 64 bits each copy differs by; "within" sets how alike counts.

Compare with Reference Pictures… takes a folder of known pictures (a victim
set, a reference set from another case) and lists, under each, the evidence
pictures that look like it. Nothing is written for it: the reference folder
is read, hashed in memory and compared.

Landing on a picture previews it; double-click goes to its folder.
"""

import logging
import os

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QHBoxLayout,
                               QHeaderView, QLabel, QPushButton, QSizePolicy,
                               QSpinBox, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core import phash
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.SimilarPictures')

#: Reference pictures are read from these extensions.
REFERENCE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.tif', '.tiff',
                        '.heic', '.heif', '.bmp', '.gif'}


class _Task(QThread):
    """Runs a function off the UI thread; `done(result)` when it ends."""

    done = Signal(object)

    def __init__(self, function, parent=None):
        super().__init__(parent)
        self.function = function

    def run(self):
        try:
            result = self.function()
        except Exception as exc:
            logger.exception("Similar pictures: %s", exc)
            result = exc
        self.done.emit(result)


def hash_folder(folder):
    """[{'name', 'path', 'phash', 'size'}] for the pictures under `folder`
    (subfolders too) that decode."""
    out = []
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            if os.path.splitext(name)[1].lower() not in REFERENCE_EXTENSIONS:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, 'rb') as handle:
                    data = handle.read()
            except OSError:
                continue
            value = phash.phash(data)
            if value:
                out.append({'name': name, 'path': path, 'phash': value,
                            'size': len(data)})
    return out


class SimilarPicturesPanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    #: Groups found, for the sub-tab's label.
    count_changed = Signal(int)

    COLUMNS = ['Picture', 'Evidence', 'Differs by', 'Size', 'Path']

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("similarPicturesPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self._task = None
        self._mode = 'groups'          # or 'reference'
        self._reference = None         # (folder, hashes)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setSizePolicy(QSizePolicy.Ignored,
                                        QSizePolicy.Preferred)
        bar.addWidget(self.status_label, 1)
        bar.addWidget(QLabel("Within"))
        self.threshold = QSpinBox()
        self.threshold.setObjectName("similarThreshold")
        self.threshold.setRange(0, 24)
        self.threshold.setValue(phash.DEFAULT_THRESHOLD)
        self.threshold.setSuffix(" bits")
        self.threshold.setToolTip(
            "How many of the 64 bits two pictures may differ by and still "
            "count as the same picture. 0: only resized and re-saved "
            "copies; 10 (default): also brightened or slightly cropped; "
            "higher finds more, and more that only look similar.")
        self.threshold.valueChanged.connect(lambda _v: self.refresh())
        bar.addWidget(self.threshold)
        self.reference_button = QPushButton("Compare with Reference "
                                            "Pictures…")
        self.reference_button.setToolTip(
            "Choose a folder of known pictures: each is listed with the "
            "evidence pictures that look like it. The folder is only read.")
        self.reference_button.clicked.connect(self.choose_reference)
        bar.addWidget(self.reference_button)
        self.groups_button = QPushButton("Show Groups")
        self.groups_button.setToolTip("Back to the pictures that look alike "
                                      "within the evidence")
        self.groups_button.clicked.connect(self.show_groups)
        self.groups_button.hide()
        bar.addWidget(self.groups_button)
        layout.addLayout(bar)

        self.tree = QTreeWidget()
        self.tree.setObjectName("triageTable")
        self.tree.setColumnCount(len(self.COLUMNS))
        self.tree.setHeaderLabels(self.COLUMNS)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setItemDelegate(NoFocusDelegate(self.tree))
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((260, 140, 80, 80)):
            self.tree.setColumnWidth(column, width)
        self.tree.currentItemChanged.connect(self._landed)
        self.tree.itemDoubleClicked.connect(self._activated)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.tree, 1)
        self.refresh()

    # --- what to show ------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self.reference_button.setEnabled(case is not None)
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self.refresh()

    def shutdown(self):
        if self._task is not None:
            self._task.wait(3000)

    def refresh(self):
        """Group (or match) the case's pictures on a thread."""
        if self.case is None:
            self.tree.clear()
            self.status_label.setText("Similar pictures are found in a "
                                      "case's analysed pictures.")
            self.count_changed.emit(0)
            return
        items = self.case.picture_hashes(self.evidence_id)
        threshold = self.threshold.value()
        if not items:
            self.tree.clear()
            self.status_label.setText(
                "No picture has a perceptual hash yet: run the analysis "
                "with Photo metadata (Analysis ▸ Run Analysis Modules).")
            self.count_changed.emit(0)
            return
        if self._mode == 'reference' and self._reference:
            references = self._reference[1]
            self._run(lambda: phash.match(references, items, threshold),
                      self._show_matches)
        else:
            self._run(lambda: phash.groups(items, threshold),
                      lambda groups: self._show_groups(groups, len(items)))
        self.status_label.setText("Comparing…")

    def _run(self, function, then):
        if self._task is not None:
            # A later request wins: the running one's result is dropped.
            try:
                self._task.done.disconnect()
            except (RuntimeError, TypeError):
                pass
        task = _Task(function, self)
        task.done.connect(lambda result: self._finished(result, then))
        task.finished.connect(lambda task=task: self._task_ended(task))
        self._task = task
        task.start()

    def _task_ended(self, task):
        # The reference goes before the object: deleteLater frees it, and a
        # later refresh asking a freed thread isRunning() crashed.
        if self._task is task:
            self._task = None
        task.deleteLater()

    def _finished(self, result, then):
        if isinstance(result, Exception):
            self.status_label.setText(f"Comparison failed: {result}")
            return
        then(result)

    # --- groups ------------------------------------------------------------

    def show_groups(self):
        self._mode = 'groups'
        self.groups_button.hide()
        self.refresh()

    def _show_groups(self, groups, total):
        self.tree.clear()
        for group in groups:
            head = QTreeWidgetItem([f"{len(group)} pictures that look "
                                    f"alike", '', '', '', ''])
            head.setIcon(0, icons.icon(icons.FINDING_DUPLICATES))
            head.setFirstColumnSpanned(True)
            self.tree.addTopLevelItem(head)
            for member in group:
                head.addChild(self._row(member))
            head.setExpanded(True)
        pictures = sum(len(g) for g in groups)
        self.status_label.setText(
            f"{len(groups):,} group(s) of look-alike pictures: {pictures:,} "
            f"of {total:,} picture(s) with a perceptual hash." if groups else
            f"No two of {total:,} picture(s) look alike within "
            f"{self.threshold.value()} bits.")
        self.count_changed.emit(len(groups))

    # --- reference pictures --------------------------------------------------

    def choose_reference(self, folder=None):
        if folder is None:
            folder = QFileDialog.getExistingDirectory(
                self, "Reference pictures to look for")
            if not folder:
                return
        self.status_label.setText(f"Reading reference pictures in "
                                  f"{folder}…")

        def hashed(references):
            if not references:
                self.status_label.setText(f"No picture in {folder} could be "
                                          f"read.")
                return
            self._reference = (folder, references)
            self._mode = 'reference'
            self.groups_button.show()
            self.refresh()
        self._run(lambda: hash_folder(folder), hashed)

    def _show_matches(self, matches):
        folder, references = self._reference
        self.tree.clear()
        for reference, items in matches:
            head = QTreeWidgetItem([reference['name'], 'reference', '',
                                    FileSystemUtils.get_readable_size(
                                        reference['size']),
                                    reference['path']])
            head.setIcon(0, icons.icon(icons.FINDING_PHOTO))
            head.setToolTip(4, reference['path'])
            self.tree.addTopLevelItem(head)
            for item in items:
                head.addChild(self._row(item))
            head.setExpanded(True)
        found = sum(len(items) for _r, items in matches)
        self.status_label.setText(
            f"{len(matches):,} of {len(references):,} reference picture(s) "
            f"from {folder} look like {found:,} evidence picture(s)."
            if matches else
            f"None of {len(references):,} reference picture(s) from "
            f"{folder} looks like an evidence picture within "
            f"{self.threshold.value()} bits.")
        self.count_changed.emit(len(matches))

    # --- rows -----------------------------------------------------------------

    def _row(self, item):
        row = QTreeWidgetItem([
            item.get('name') or '', self._names.get(item.get('evidence_id'),
                                                    ''),
            f"{item['distance']} bit{'s' if item['distance'] != 1 else ''}"
            if item.get('distance') else 'same',
            FileSystemUtils.get_readable_size(item.get('size') or 0),
            item.get('path') or ''])
        row.setData(0, Qt.UserRole, item)
        row.setToolTip(4, item.get('path') or '')
        if item.get('is_deleted'):
            row.setToolTip(0, "Deleted")
        return row

    def _item(self, row):
        return row.data(0, Qt.UserRole) if row is not None else None

    def _landed(self, current, _previous):
        item = self._item(current)
        if item and item.get('artifact_ref'):
            self.file_selected.emit(item)

    def _activated(self, row, _column):
        item = self._item(row)
        if item and item.get('artifact_ref'):
            self.file_activated.emit(item)

    def _menu(self, point):
        item = self._item(self.tree.itemAt(point))
        if item and item.get('artifact_ref'):
            self.file_menu_requested.emit(
                item, self.tree.viewport().mapToGlobal(point))

"""Picking folders from the evidence for a scope rule (core/scope.py).

The open evidence's volumes and folders, listed as each is opened (as the
main tree is); folders ticked become rules. A folder inside a system's own
tree is written from its top -- '~/home/alex', which also finds it on
another image of the same system -- and anything else from the volume
root ('/data/projects').
"""

import logging

import pytsk3
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QHeaderView, QLabel,
                               QTreeWidgetItem, QVBoxLayout)

from trace_app.core import scope as scope_module
from trace_app.ui import icons
from trace_app.ui.widgets.tree_branch import BranchTreeWidget

logger = logging.getLogger('TRACE.FolderPicker')

#: Item data: (handler, volume offset, folder path) -- folder '' = a volume.
_DATA = Qt.UserRole
#: Children not listed yet.
_UNLISTED = Qt.UserRole + 1


def rule_for(path, roots):
    """The rule naming folder `path` of a volume whose system roots are
    `roots` (core/scope.system_roots): '~' + the path below the deepest
    root holding it, else the path itself."""
    best = None
    for root in roots:
        top = root.rstrip('/')
        if path == top or path.startswith(top + '/'):
            if best is None or len(top) > len(best):
                best = top
    if best is None or (best and path == best):
        # Outside every system tree -- or a system's top itself, which '~'
        # alone would make every system's whole tree.
        return path
    below = path[len(best):]
    return '~' + (below if below.startswith('/') else '/' + below)


class FolderPicker(QDialog):
    """Tick folders of the open evidence; `rules()` once accepted."""

    def __init__(self, evidence, title="Choose Folders", parent=None):
        """`evidence`: [{'name', 'handler'}] of open images."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("folderPicker")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.resize(560, 520)
        self._roots = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        intro = QLabel("Tick the folders to add. A folder in a system's own "
                       "tree is added from its top (~/…), so it is found "
                       "wherever that system's tree sits; anything else "
                       "from the volume root.")
        intro.setObjectName("scopeNote")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.tree = BranchTreeWidget()
        self.tree.setObjectName("folderPickerTree")
        self.tree.setHeaderHidden(True)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tree.itemExpanded.connect(self._expanded)
        layout.addWidget(self.tree, 1)

        self.chosen = QLabel()
        self.chosen.setObjectName("scopeNote")
        self.chosen.setWordWrap(True)
        layout.addWidget(self.chosen)
        self.tree.itemChanged.connect(self._ticked)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok
                                   | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Add")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        for image in evidence:
            self._add_image(image)
        self._ticked()

    # --- building ---------------------------------------------------------------

    def _add_image(self, image):
        handler = image['handler']
        top = QTreeWidgetItem(self.tree, [image['name']])
        top.setIcon(0, icons.icon(icons.CASE))
        top.setFlags(top.flags() & ~Qt.ItemIsUserCheckable)
        try:
            offsets = handler.volume_offsets()
        except Exception as exc:
            logger.debug("No volumes for %s: %s", image['name'], exc)
            offsets = []
        for offset in offsets:
            fs = handler.get_fs_info(offset)
            if fs is None:
                continue
            kind = handler.get_fs_type(offset) or 'volume'
            item = QTreeWidgetItem(top, [f"{kind} @ {offset}"])
            item.setIcon(0, icons.icon(icons.IMAGE_INFO))
            item.setData(0, _DATA, (handler, offset, ''))
            item.setData(0, _UNLISTED, True)
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            item.setCheckState(0, Qt.Unchecked)
        top.setExpanded(True)

    def _expanded(self, item):
        if not item.data(0, _UNLISTED):
            return
        item.setData(0, _UNLISTED, False)
        handler, offset, path = item.data(0, _DATA)
        self.tree.blockSignals(True)
        try:
            fs = handler.get_fs_info(offset)
            directory = fs.open_dir(path=path or '/')
            names = []
            for entry in directory:
                info = entry.info
                if info.name is None or info.meta is None or \
                        info.meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
                    continue
                name = info.name.name.decode('utf-8', 'replace')
                if name not in ('.', '..'):
                    names.append(name)
            for name in sorted(names, key=str.lower):
                child = QTreeWidgetItem(item, [name])
                child.setIcon(0, icons.icon(icons.OPEN_FOLDER))
                child.setData(0, _DATA, (handler, offset, f"{path}/{name}"))
                child.setData(0, _UNLISTED, True)
                child.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                child.setCheckState(0, Qt.Unchecked)
            if not names:
                item.setChildIndicatorPolicy(
                    QTreeWidgetItem.DontShowIndicatorWhenChildless)
        except Exception as exc:
            logger.debug("Could not list %s: %s", path or '/', exc)
        finally:
            self.tree.blockSignals(False)

    # --- the result --------------------------------------------------------------

    def _checked(self):
        out = []

        def visit(item):
            for index in range(item.childCount()):
                child = item.child(index)
                if child.data(0, _DATA) and \
                        child.checkState(0) == Qt.Checked:
                    out.append(child.data(0, _DATA))
                    continue            # a ticked folder covers its own
                visit(child)
        visit(self.tree.invisibleRootItem())
        return out

    def _roots_of(self, handler, offset):
        key = (id(handler), offset)
        if key not in self._roots:
            try:
                self._roots[key] = scope_module.system_roots(
                    handler.get_fs_info(offset))
            except Exception:
                self._roots[key] = ['/']
        return self._roots[key]

    def rules(self):
        """The ticked folders as rules, each once, in tree order."""
        out = []
        for handler, offset, path in self._checked():
            rule = rule_for(path or '/', self._roots_of(handler, offset)) \
                if path else '/'
            if rule not in out:
                out.append(rule)
        return out

    def _ticked(self, *_args):
        rules = self.rules()
        self.chosen.setText("Adds: " + ', '.join(rules) if rules else
                            "Nothing ticked yet.")


def pick_folders(evidence, title="Choose Folders", parent=None):
    """Ask; the rules for the folders ticked, or [] when cancelled."""
    dialog = FolderPicker(evidence, title, parent)
    if dialog.exec() == QDialog.Accepted:
        return dialog.rules()
    return []

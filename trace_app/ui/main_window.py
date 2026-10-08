import configparser
import datetime
import gc
import logging
import os
import posixpath
import re
import tempfile
import uuid
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from PySide6.QtCore import (QByteArray, QEventLoop, Qt, QSize, QThread,
                            Signal, QTimer, QUrl)
from PySide6.QtGui import (QIcon, QPalette, QAction, QActionGroup, QColor, QCursor,
                           QDesktopServices)
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTabWidget, QFileDialog,
                               QTreeWidgetItem, QTableWidget, QTableWidgetItem, QDialog, QVBoxLayout,
                               QInputDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit, QFormLayout, QApplication,
                               QWidget, QProgressDialog, QSizePolicy, QTabBar, QToolButton,
                               QStackedWidget)

from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.tree_branch import BranchTreeWidget
from trace_app.ui.dialogs.about import AboutDialog
from trace_app.infra.constants import (API_DIALOG_WIDTH, COLUMN_WIDTHS, GROUP_SPACING,
                                       UNKNOWN_DATE, TABLE_ROW_HEIGHT,
                                       DEFAULT_WINDOW_HEIGHT,
                                       DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y,
                                       INPUT_FIELD_MIN_WIDTH, PANEL_ICON_SIZE, PROGRESS_MIN_DURATION,
                                       TABLE_BATCH_SIZE, TABLE_ICON_SIZE, TREE_ICON_SIZE,
                                       TREE_INDENTATION, VIEWER_DOCK_MIN_HEIGHT)
from trace_app import __version__
from trace_app.core.database import DatabaseManager
from trace_app.ui.viewers.carved_panel import (CarvedFilesPanel,
                                               CarvingWorker)
from trace_app.ui.viewers.hex import HexViewer
from trace_app.core import archives
from trace_app.core.carving import read_carved
from trace_app.infra.theme import read_theme, save_theme
from trace_app.infra.utils import FileSystemUtils
from trace_app.core.case import (REPORTED_FINDING_GRADES,
                                 REPORTED_MISMATCHES, make_artifact_ref,
                                 make_span_ref, parse_artifact_ref)
from trace_app.core.image_handler import ImageHandler
from trace_app.ui.viewers.metadata import MetadataViewer
from trace_app.infra.paths import config_file, resource_path
from trace_app.ui import icons
from trace_app.ui.widgets import item_views
from trace_app.core import settings as case_settings
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.viewers.registry_hive import RegistryExtractor
from trace_app.ui.viewers.text import TextViewer
from trace_app.ui.viewers.media import UnifiedViewer
from trace_app.ui.dialogs.verification import VerificationWidget
from trace_app.ui.viewers.registry_adapters import (ApplicationAdapter, HexAdapter,
                                     CaseAdapter, MetadataAdapter,
                                     NotesAdapter,
                                     TextAdapter)
from trace_app.ui.viewers.virustotal import (METHOD_HASH, METHOD_UPLOAD,
                                             STATE_QUEUED, STATE_RUNNING,
                                             VirusTotalPanel,
                                             VirusTotalWorker, verdict_brush,
                                             verdict_state, verdict_text)
from trace_app.core import virustotal as vt
from trace_app.ui.dialogs.volume_info import VolumeInfoMixin
from trace_app.core.workers import ExportWorker
from trace_app.ui.dialogs import message
from trace_app.ui.viewers.bookmarks_panel import BookmarksPanel
from trace_app.ui.viewers.case_panel import CasePanel
from trace_app.ui.viewers.notes_panel import NotesPanel
from trace_app.ui.viewers.activity_panel import ActivityPanel, ActivityWorker
from trace_app.ui.viewers.indicators_panel import IndicatorsPanel, kind_label
from trace_app.ui.viewers.ntfs_panel import NtfsPanel, NtfsWorker
from trace_app.ui.viewers.hash_matches_panel import (HashMatchesPanel,
                                                     HashMatchWorker)
from trace_app.core import containers, hashsets, rdpcache, thumbnails
from trace_app.ui.viewers.timeline_panel import TimelinePanel
from trace_app.ui.viewers.search_panel import IndexWorker, SearchPanel
from trace_app.ui.viewers.triage_panel import AnalysisWorker, TriagePanel
from trace_app.ui.widgets.job_bar import Job, JobBar
from trace_app.ui.dialogs.analysis_modules import (choose_modules,
                                                   default_choice)
from trace_app.core.analysis import MODULES, is_high_entropy
from trace_app.ui.widgets.context_menus import show_menu

#: The listing's Flag text for each hidden-data finding.
_FLAG_TEXT = {
    'double-extension': 'Double extension',
    'bidi-name': 'Disguised name',
    'padded-name': 'Disguised name',
    'appended-data': 'Appended data',
    'encrypted': 'Encrypted',
    'encrypted-volume': 'Possible encrypted volume',
}

logger = logging.getLogger('TRACE.MainWindow')

# ==================== FILE SEARCH WIDGET CLASSES ====================
class SizeTableWidgetItem(QTableWidgetItem):
    """Custom table widget item for proper size sorting."""
    def __lt__(self, other):
        return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))




#: Carved types a double-click browses like a folder (RAR is listed by the
#: carver but needs unrar, which is not bundled; it is reported, not browsed).
CARVED_ARCHIVE_TYPES = frozenset({'zip', 'gz', 'bz2', 'xz', 'tar', '7z', 'rar',
                                  'jar', 'apk', 'epub', 'pst', 'ost', 'eml',
                                  'mbox'})
#: File names the tree offers to expand as archives (the content decides
#: when one is clicked or expanded; a name only earns the arrow).
TREE_ARCHIVE_SUFFIXES = ('.zip', '.7z', '.rar', '.tar', '.gz', '.tgz',
                         '.bz2', '.tbz', '.tbz2', '.xz', '.txz', '.jar',
                         '.apk', '.pst', '.ost', '.mbox')
#: Archives the tree keeps read, so stepping through one is not a re-read.
TREE_ARCHIVES_KEPT = 3
#: ...and those that are archives inside but documents to an examiner: a
#: double-click shows the document; "Browse Archive" opens its parts.
CARVED_BROWSABLE_DOCUMENTS = frozenset({'docx', 'xlsx', 'pptx', 'vsdx', 'odt',
                                        'ods', 'odp', 'odg'})


class _HandlerOpener(QThread):
    """Opens an ImageHandler and does each volume's first reads, off the
    UI thread (MainWindow._open_handler). `done` is set however it ends;
    `handler` or `error` holds the outcome."""

    def __init__(self, image_path):
        super().__init__()
        import threading
        self.image_path = image_path
        self.handler = None
        self.error = None
        self.done = threading.Event()

    def run(self):
        try:
            self.handler = ImageHandler(self.image_path)
            if self.handler.loaded:
                self._warm(self.handler)
        except Exception as exc:
            self.error = exc
        finally:
            self.done.set()

    @staticmethod
    def _warm(handler):
        """What load_partitions_into_tree asks first, so its answers are
        cached: a failure here is the tree's to report, not this."""
        try:
            partitions = handler.get_partitions()
            starts = [p[2] for p in partitions] if partitions else [0]
            for start in starts:
                handler.volume_kind(start)
                handler.encryption(start)
                if handler.get_fs_info(start) is not None:
                    handler.get_directory_contents(start, None)
        except Exception as exc:
            logger.debug("Warming %s: %s", handler.image_path, exc)


class MainWindow(VolumeInfoMixin, QMainWindow):
    # Class variable for icon caching
    _icon_cache = {}

    #: The tree dock is never narrower than this.
    _TREE_MIN = 200

    def __init__(self, case=None):
        super().__init__()
        # Every table, tree and list scrolls by pixels and fills its width
        # (ui/widgets/item_views.py). Also done at startup for the launcher;
        # here too so a window built without app.py (tests) behaves alike.
        item_views.install()

        #: The open case, or None for quick triage. Everything case-related
        #: checks this rather than a separate mode flag: there is one source
        #: of truth for whether findings have anywhere to be kept.
        self.case = case
        # This case's settings in effect before anything reads them -- the
        # defaults for quick triage (core/settings.py).
        case_settings.apply_case(case)

        # Create a database manager for icon lookup
        self.db_manager = DatabaseManager()

        # Initialize variables for tracking
        self.current_selected_data = None
        self.current_offset = None
        self.current_path = "/"  # Initialize current path
        self.image_handler = None
        self._directory_cache = {}

        # Search/Browse mode state management
        self._search_mode = False  # False = Browse mode, True = Search mode
        self._search_query = ""  # Current search query
        self._last_browsed_state = {}  # Store last directory state for restoration


        # Directory navigation history (for Back/Forward buttons like Windows 11)
        self._directory_history = []  # List of visited directories: [(offset, inode, path), ...]
        self._history_index = -1  # Current position in history (-1 = no history)
        self._navigating_history = False  # Flag to prevent adding to history during Back/Forward

        # Load configuration
        self.api_keys = configparser.ConfigParser()
        try:
            # Read from the per-user config dir. 'config.ini' is also read so a
            # config left in the working directory by an older version still
            # applies; the next save writes to the user dir.
            self.api_keys.read([config_file(), 'config.ini'])
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")

        # Initialize instance attributes
        self.current_offset = None
        self.current_image_path = None
        self.current_selected_data = None

        #: Images loaded in this session. With a case open this is seeded
        #: from it and every add/remove writes back, so the list survives a
        #: restart; in triage it behaves as it always has and is lost on exit.
        self.evidence_files = list(case.evidence_paths()) if case else []

        #: While browsing inside an archive: a list of levels, each
        #: (display name, archive bytes, artifact data of the file it came
        #: from). Empty when browsing the filesystem. An archive inside an
        #: archive pushes another level, so the trail is also the answer to
        #: "where was this file found".
        self._archive_stack = []
        # Archives read for the tree: {(image, offset, inode): (name, content, source)}.
        self._tree_archives = {}

        #: Artifact references that carry a bookmark, so the listing can mark
        #: them without asking the database once per row.
        self._bookmarked_refs = set()

        #: Handlers for evidence other than the one on screen, opened on demand
        #: when a picker asks about an image that is not the current one and
        #: kept so the second click is instant.
        self._auxiliary_handlers = {}
        #: One open handle per image in the case, by normalised path. A case
        #: is one investigation across several devices, so every image stays
        #: readable; the window reads whichever is active (activate_image).
        self._image_handlers = {}
        #: The image the listing was filled from. A row is read from this
        #: image even after another one became active.
        self._listing_image = None
        self._evidence_profiles = {}

        #: Verification results, keyed by image path. Verification is a fact
        #: about one image, not about the session, so it is stored per image:
        #: a second image loaded alongside a verified one is not itself
        #: verified, and the previously toolbar-wide icon claimed otherwise.
        self.verification_results = {}

        self.initialize_ui()

        if case:
            # Seeded after the UI is built, not in the attribute block above:
            # marking an image verified paints its tree row, and the tree does
            # not exist until initialize_ui() has run.
            self._seed_verification_from_case()
            self.refresh_bookmarks_tree()
            # Deferred: this runs during __init__, before the window is shown,
            # and loading an image can take seconds and wants to draw progress.
            QTimer.singleShot(0, self.load_case_evidence)
            for path in self.evidence_files:
                if path in self.verification_results:
                    self.mark_image_verified(path, True)

    # ==================== HELPER METHODS ====================

    def _apply_program_icon(self, name, inode, start_offset, file_size,
                            set_icon):
        """A program (or an .ico file) shown with its own icon once it is
        read, in the background (ui/widgets/program_icons.py)."""
        if inode is None or not getattr(self, 'current_image_path', None):
            return
        if not hasattr(self, 'program_icons'):
            from trace_app.ui.widgets.program_icons import ProgramIcons
            self.program_icons = ProgramIcons(self)
        handler = self.image_handler
        self.program_icons.apply(
            (self.current_image_path, start_offset, inode), name,
            lambda: self._file_reader(handler, inode, start_offset),
            set_icon, file_size if isinstance(file_size, int) else None)

    @staticmethod
    def _file_reader(handler, inode, start_offset):
        """`read(offset, length)` over a file on the image, or None."""
        if handler is None:
            return None
        stream = handler.open_file_object(inode, start_offset)
        if stream is None:
            return None

        def read(offset, length):
            stream.seek(offset)
            return stream.read(length)
        return read

    def _listing_program_icon(self, data, size):
        """A listed program's icon at `size`, for the icon views (on the
        thumbnail thread)."""
        from trace_app.ui.widgets.listing_views import size_in_bytes
        from trace_app.ui.widgets.program_icons import icon_bytes
        read = self._file_reader(self._listing_handler(),
                                 data.get('inode_number'),
                                 data.get('start_offset'))
        if read is None:
            return None
        return icon_bytes(data.get('name'), read, size,
                          size_in_bytes(data.get('size')))

    # --- what every menu naming a file offers -------------------------------

    def _file_data_for(self, row):
        """A menu row as the Listing's data for a file on the evidence --
        what export and bookmarking take -- or None."""
        if not isinstance(row, dict):
            return None
        if row.get('artifact_ref'):
            parsed = parse_artifact_ref(row['artifact_ref'])
            if parsed.get('kind') != 'file' or parsed.get('inode') is None:
                return None
            path = row.get('path') or row.get('artifact_path') or \
                row.get('source_path') or ''
            name = row.get('name') or row.get('artifact_name') or \
                os.path.basename(path.rstrip('/')) or \
                f"inode-{parsed['inode']}"
            return {'inode_number': parsed['inode'],
                    'start_offset': parsed['start_offset'],
                    'sequence': parsed.get('sequence'), 'name': name,
                    'path': path, 'type': 'file'}
        if row.get('inode_number') is not None and \
                row.get('start_offset') is not None and \
                row.get('type') in ('file', 'directory'):
            return row
        return None

    def _menu_extras(self, menu, row):
        """Export File and Add Bookmark for any row naming a file on the
        evidence, where the menu does not offer them already (the hook of
        ui/widgets/context_menus.show_menu)."""
        data = self._file_data_for(row)
        if data is None:
            return
        texts = [action.text().replace('&', '').lower()
                 for action in menu.actions()]
        evidence_id = row.get('evidence_id')

        def on_image(then):
            if evidence_id is not None and \
                    not self.activate_evidence(evidence_id):
                return
            then()

        extras = []
        if self.case and not any('bookmark' in t for t in texts):
            extras.append(("Add Bookmark…",
                           lambda: on_image(
                               lambda: self.add_bookmark_for(data))))
        if not any(t.startswith('export') and 'table' not in t
                   for t in texts):
            label = "Export Folder…" if data.get('type') == 'directory' \
                else "Export File…"
            extras.append((label, lambda: on_image(
                lambda: self.handle_export(
                    data, QFileDialog.getExistingDirectory(
                        self, "Select Destination Directory",
                        case_settings.export_dir())))))
        if extras and menu.actions():
            menu.addSeparator()
        for label, slot in extras:
            menu.addAction(label).triggered.connect(slot)

    def _get_file_icon(self, file_extension: str) -> QIcon:
        """Get icon for file extension with caching."""
        if file_extension not in self._icon_cache:
            icon_path = self.db_manager.get_icon_path('file', file_extension)
            self._icon_cache[file_extension] = QIcon(icon_path)
        return self._icon_cache[file_extension]

    def _confirm_exit(self) -> bool:
        """Ask user to confirm exit."""
        return message.question(self, 'Exit Confirmation',
                                'Are you sure you want to exit?',
                                'Any unsaved work will be lost.')

    def _create_tree_item_for_entry(self, parent_item: QTreeWidgetItem, entry: Dict[str, Any],
                                    start_offset: int) -> QTreeWidgetItem:
        """Create tree item for a directory entry."""
        child_item = QTreeWidgetItem(parent_item)
        child_item.setText(0, entry["name"])

        if entry["is_directory"]:
            self._setup_directory_tree_item(child_item, entry, start_offset)
        else:
            self._setup_file_tree_item(child_item, entry, start_offset)

        return child_item

    def _setup_directory_tree_item(self, item: QTreeWidgetItem, entry: Dict[str, Any],
                                   start_offset: int) -> None:
        """Configure tree item for a directory entry."""
        # Check if directory has children
        sub_entries = self.image_handler.get_directory_contents(start_offset, entry["inode_number"])
        has_sub_entries = bool(sub_entries)

        # Set directory icon and data
        icon_path = self.db_manager.get_icon_path('folder', 'folder')
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, {
            "inode_number": entry["inode_number"],
            "type": 'directory',
            "start_offset": start_offset,
            "name": entry["name"],
            "size": entry.get("size"),
            "is_deleted": entry.get("is_deleted", False),
            "is_recoverable": entry.get("is_recoverable", False),
            # Already counted above; saves the status bar counting again.
            "child_count": len(sub_entries),
        })

        # Set child indicator
        item.setChildIndicatorPolicy(
            QTreeWidgetItem.ShowIndicator if has_sub_entries
            else QTreeWidgetItem.DontShowIndicatorWhenChildless
        )

    def _setup_file_tree_item(self, item: QTreeWidgetItem, entry: Dict[str, Any],
                             start_offset: int) -> None:
        """Configure tree item for a file entry."""
        # Get file extension for icon
        file_extension = entry["name"].split('.')[-1].lower() if '.' in entry["name"] else 'unknown'

        # Use cached icon lookup
        icon = self._get_file_icon(file_extension)
        item.setIcon(0, icon)
        # A program shows its own icon, once read.
        self._apply_program_icon(entry["name"], entry["inode_number"],
                                 start_offset, entry.get("size"),
                                 lambda icon, it=item: it.setIcon(0, icon))
        item.setData(0, Qt.UserRole, {
            "inode_number": entry["inode_number"],
            "type": 'file',
            "start_offset": start_offset,
            "name": entry["name"],
            # Carried so the status bar can describe a file picked from the
            # tree as fully as one picked from the listing.
            "size": entry.get("size"),
            "is_deleted": entry.get("is_deleted", False),
            "is_recoverable": entry.get("is_recoverable", False),
            # The MFT record's reuse counter. Carried so a bookmark on
            # this row can tell two generations of the same inode
            # apart -- without it a saved reference can come to mean a
            # different file.
            "sequence": entry.get("sequence"),
        })
        # An archive is a folder to an examiner: it can be expanded.
        if entry["name"].lower().endswith(TREE_ARCHIVE_SUFFIXES):
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

    def _populate_table_entry(self, row_position: int, entry: Dict[str, Any], offset: int) -> None:
        """Populate a single table row with entry data."""
        entry_name = entry.get("name", "")
        inode_number = entry.get("inode_number", 0)
        is_directory = entry.get("is_directory", False)
        description = "Dir" if is_directory else "File"
        # A deleted entry still listed in its directory is otherwise
        # indistinguishable from a live one, which is the single most
        # misleading thing a forensic listing can do. The filesystem knows;
        # say so in the Type column, which is already on screen.
        if entry.get("is_deleted"):
            description = f"Deleted {description}"
        # A row read out of an archive says so: an examiner reporting where a
        # file was found needs to know it came from inside a container rather
        # than off the volume.
        if entry.get("type") == "archive-member":
            description = ("Encrypted in archive"
                           if entry.get("archive_encrypted")
                           else "In archive")
        size_in_bytes = entry.get("size", 0)
        # The static utility rather than the handler's wrapper around it: an
        # archive member is listed from bytes already in memory and may have no
        # image handler behind it.
        readable_size = FileSystemUtils.get_readable_size(size_in_bytes)
        created = entry.get("created", "N/A")
        accessed = entry.get("accessed", "N/A")
        modified = entry.get("modified", "N/A")
        changed = entry.get("changed", "N/A")

        icon_type = 'folder' if is_directory else 'file'
        icon_name = 'folder' if is_directory else (
            entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown')

        parent_inode = self.current_selected_data.get("inode_number") if self.current_selected_data else None

        self.listing_table.insertRow(row_position)
        self.insert_row_into_listing_table(entry_name, inode_number, description,
                                          icon_name, icon_type, offset,
                                          readable_size, created, accessed,
                                          modified, changed, parent_inode,
                                          entry.get("sequence"),
                                          entry.get("attributes", ""))
        if not is_directory and entry.get('type') != 'archive-member':
            name_cell = self.listing_table.item(row_position, 0)
            if name_cell is not None:
                self._apply_program_icon(
                    entry_name, inode_number, offset, entry.get("size"),
                    lambda icon, cell=name_cell: cell.setIcon(icon))

        # A bookmarked file is marked where the examiner is looking. The
        # bookmark glyph goes in the Type column rather than replacing the
        # file's own icon, which still has to say what kind of file it is.
        if self._bookmarked_refs:
            ref = make_artifact_ref(offset, inode_number,
                                    entry.get('sequence')) \
                if inode_number is not None else None
            if ref and (self.evidence_id_for_path(self._listing_image), ref) \
                    in self._bookmarked_refs:
                type_cell = self.listing_table.item(row_position, 2)
                if type_cell is not None:
                    type_cell.setIcon(icons.icon(icons.BOOKMARK))
                    type_cell.setToolTip("Bookmarked in this case.")
                name_cell = self.listing_table.item(row_position, 0)
                if name_cell is not None:
                    font = name_cell.font()
                    font.setBold(True)
                    name_cell.setFont(font)

        # An archive member has no inode, so the row payload the click handler
        # reads has to carry what identifies it instead: its name inside the
        # archive, and the fact that it is one.
        if entry.get("type") == "archive-member":
            cell = self.listing_table.item(row_position, 0)
            if cell is not None:
                payload = dict(cell.data(Qt.UserRole) or {})
                payload.update({
                    'type': 'archive-member',
                    'archive_member': entry.get('archive_member', entry_name),
                    'archive_encrypted': entry.get('archive_encrypted', False),
                    'is_directory': is_directory,
                    'size': size_in_bytes,
                })
                cell.setData(Qt.UserRole, payload)

    # ==================== END HELPER METHODS ====================

    def initialize_ui(self):
        """Build the main window.

        Split into one method per region; this was a single 332-line method.
        """
        self._build_window()
        self._build_menus()
        self._build_toolbar()
        self._build_central_widgets()
        self._build_viewer_dock()
        self._quieten_table_headers()

    def _quieten_table_headers(self):
        """Stop headers bolding the column of the selected cell.

        Qt highlights the header section above whatever is selected, which
        makes a column heading turn bold as soon as a row is clicked. It reads
        as the heading changing meaning, and the selection already shows where
        the cursor is. Applied to every table in the window at once, so a table
        added later is covered without anyone remembering.
        """
        for table in self.findChildren(QTableWidget):
            table.horizontalHeader().setHighlightSections(False)
            table.verticalHeader().setHighlightSections(False)

    def showEvent(self, event):
        """Lay the window out once, on first show -- a beat later, when a
        maximised window knows its final size."""
        super().showEvent(event)
        if not getattr(self, '_layout_applied', False):
            self._layout_applied = True
            self._align_toolbars()
            QTimer.singleShot(0, self._apply_startup_layout)
            # TRACE's logo on the taskbar, not Qt's generic window: set now,
            # and again once the start-up work is done (ui/window_icon.py).
            self.refresh_taskbar_icon()
            QTimer.singleShot(1500, self.refresh_taskbar_icon)

    def refresh_taskbar_icon(self):
        from trace_app.ui import window_icon
        window_icon.apply(self)

    # --- window size and dock proportions --------------------------------

    #: Smallest screen worth opening a window on rather than filling.
    _MAXIMISE_BELOW = (1440, 900)

    def _place_on_screen(self):
        """Size the window from the screen it opens on: most of it, centred,
        or all of it on a small laptop screen -- not a fixed 1200x800 that is
        a postage stamp on 4K and too tall for 768 pixels."""
        screen = QApplication.primaryScreen()
        if screen is None:
            self.setGeometry(DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y,
                             DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)
            self._start_maximised = False
            return
        area = screen.availableGeometry()
        self._start_maximised = (area.width() < self._MAXIMISE_BELOW[0]
                                 or area.height() < self._MAXIMISE_BELOW[1])
        width = min(int(area.width() * 0.9), 1800)
        height = min(int(area.height() * 0.9), 1100)
        self.setGeometry(area.x() + (area.width() - width) // 2,
                         area.y() + (area.height() - height) // 2,
                         width, height)

    def show_on_start(self):
        """Show as the examiner left it, else maximised on a small screen,
        else at the size chosen for this screen."""
        if self._restore_saved_layout():
            return
        if getattr(self, '_start_maximised', False):
            self.showMaximized()
        else:
            self.show()

    def _restore_saved_layout(self):
        from trace_app.infra.window_state import read_window_state
        geometry, state = read_window_state()
        if not geometry or not self.restoreGeometry(QByteArray(geometry)):
            return False
        # A window saved on a monitor that is no longer attached would open
        # off screen: only keep it if it lands mostly on one we have.
        frame = self.frameGeometry()
        visible = any(
            screen.availableGeometry().intersected(frame).width()
            * screen.availableGeometry().intersected(frame).height()
            > 0.5 * frame.width() * frame.height()
            for screen in QApplication.screens())
        if not visible:
            self._place_on_screen()
            return False
        self._saved_state = state
        self.show()
        return True

    def _apply_startup_layout(self):
        state = getattr(self, '_saved_state', None)
        if state and self.restoreState(QByteArray(state)) \
                and self.tree_dock.width() >= self._TREE_MIN \
                and self.tree_dock.isVisible():
            return
        self._apply_default_layout()

    def save_layout(self):
        from trace_app.infra.window_state import save_window_state
        save_window_state(self.saveGeometry().data(), self.saveState().data())

    def reset_layout(self):
        """View > Reset Layout: the proportions a first run gets."""
        from trace_app.infra.window_state import forget_window_state
        forget_window_state()
        self._saved_state = None
        for dock in (self.tree_dock, self.viewer_dock):
            dock.setFloating(False)
            dock.show()
        self.addDockWidget(Qt.LeftDockWidgetArea, self.tree_dock)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)
        if self.isMaximized() or self.isFullScreen():
            self._apply_default_layout()
            return
        self._place_on_screen()
        if self._start_maximised:
            self.showMaximized()
        QTimer.singleShot(0, self._apply_default_layout)

    def _align_toolbars(self):
        """Give every toolbar in the window the same control geometry.

        Done centrally, and after the widgets exist, because Qt sizes a
        QToolButton from its icon and ignores a stylesheet max-height -- so
        heights set only in QSS came out as 26, 28, 34 and 36px side by side.
        """
        for toolbar in self.findChildren(QToolBar):
            prepare_toolbar(toolbar)
            align_controls(toolbar)

    def _apply_default_layout(self):
        """Give the file listing most of the window on first run.

        Qt otherwise sizes docks from their content's sizeHint, which left the
        Utils dock and the tree taking far more room than they need -- the
        listing is what an examiner actually reads. Done on first show, when
        the window finally knows how big it is.
        """
        width = self.width() or DEFAULT_WINDOW_WIDTH
        height = self.height() or DEFAULT_WINDOW_HEIGHT

        # Tree on the left: enough for names and the Findings groups, not a
        # third of the window.
        tree = max(self._TREE_MIN + 40, min(380, int(width * 0.2)))
        self.resizeDocks([self.tree_dock], [tree], Qt.Horizontal)

        # Utils along the bottom: tall enough to read a viewer, no more.
        viewer = max(200, min(360, int(height * 0.30)))
        self.resizeDocks([self.viewer_dock], [viewer], Qt.Vertical)

    def _build_window(self):
        """Window title, icon, geometry and platform taskbar identity."""
        self.setWindowTitle(self._case_title())

        # Set application icon for all platforms
        app_icon = icons.icon(icons.LOGO_LARGE)
        self.setWindowIcon(app_icon)

        # The application icon and the Windows taskbar identity are set in
        # app.py, before the case launcher opens; here only for a window
        # built some other way (tests, scripts).
        if QApplication.instance().windowIcon().isNull():
            QApplication.instance().setWindowIcon(app_icon)

        self._place_on_screen()
        #: What was chosen last time, so a second run does not start from
        #: nothing. Every file module, until something is chosen; carving is
        #: the slowest pass and is only run when asked for.
        self._last_choice = default_choice(MODULES)
        #: BitLocker keys that worked this session: {image path: {start
        #: sector: {kind: secret}}}. In memory only -- never in the case --
        #: and handed to background jobs so they read the volume too.
        self._bitlocker_keys = {}
        self._build_status_bar()

    def _build_status_bar(self):
        """The status bar, built now rather than on first use.

        QMainWindow.statusBar() creates one the first time it is called, which
        used to be partway through a session -- so the window lost 22px and
        everything shifted the moment the first file was clicked. Building it
        here keeps the layout still.

        Two areas: transient messages on the left, via showMessage, and a
        permanent label on the right holding what is currently selected. The
        right-hand label is why the bar is not blank between operations.
        """
        status = self.statusBar()
        status.setSizeGripEnabled(False)

        # Background work reports here, between the transient message and
        # the selection context: one place to look for everything the
        # application is doing, rather than a progress bar per feature in a
        # different corner depending on what was started.
        self.job_bar = JobBar(self)
        self.job_bar.all_finished.connect(self._on_jobs_finished)
        status.addPermanentWidget(self.job_bar)

        self.status_context = QLabel("", self)
        self.status_context.setObjectName("statusContext")
        status.addPermanentWidget(self.status_context)

        self.set_status_context("No evidence loaded")

    def set_status(self, message, timeout=0):
        """Show a transient message: what the application is doing now."""
        self.statusBar().showMessage(message, timeout)

    def clear_status(self):
        """Drop the transient message, leaving the context label in place."""
        self.statusBar().clearMessage()

    def set_status_context(self, text):
        """Set the standing right-hand text: what is currently selected."""
        if hasattr(self, 'status_context'):
            self.status_context.setText(text)

    def describe_selection(self, data, item=None):
        """One line describing the selected item, for the status bar.

        Says what an examiner would otherwise have to read off three columns:
        what it is, how big, and which MFT record it came from.

        Volumes, unallocated space and the image root are described from their
        offsets, because those carry no name or type in their item data -- only
        a start and end sector. Without that they produced an empty string and
        the bar kept whatever a previous click had left there.
        """
        if not data:
            return ""

        name = data.get('name') or ''
        kind = data.get('type') or ''

        if data.get('is_shadow_copy'):
            return (f"{data.get('volume_label', 'Volume')}   ·   shadow copy "
                    f"{data.get('shadow_index', 0) + 1}, taken "
                    f"{data.get('shadow_created', '')}   ·   read-only")
        if data.get('is_bitlocker') and self.image_handler and \
                not self.image_handler.is_unlocked(data.get('start_offset', 0)):
            name = containers.ENCRYPTION_NAMES.get(
                data.get('encryption') or 'bitlocker', 'BitLocker')
            return (f"{data.get('volume_label', 'Volume')}   ·   {name}, "
                    f"locked   ·   right-click ▸ Unlock {name}…")

        # Unallocated space: the sector range is the only thing identifying it.
        if data.get('is_unallocated'):
            return self._describe_span("Unallocated space", data)

        # A volume or the image root, neither of which carries a name.
        if not name and data.get('start_offset') is not None:
            label = (item.text(0).split('(')[0].strip()
                     if item is not None and item.text(0) else '')
            if data.get('end_offset') is not None:
                described = self._describe_span(label or "Volume", data)
                # The filesystem is the most useful thing about a volume and is
                # already known; the row text only carries the partition type.
                fs_type = (self.image_handler.get_fs_type(data['start_offset'])
                           if self.image_handler else None)
                if fs_type and fs_type != 'N/A':
                    described += f"   ·   {fs_type}"
                return described
            # No end offset and no name: this is the image itself.
            if self.current_image_path:
                partitions = len(self.image_handler.get_partitions()) if self.image_handler else 0
                return (f"{os.path.basename(self.current_image_path)}"
                        f"   ·   {partitions} partitions")
            return ""

        parts = [name] if name else []

        if kind == 'directory':
            count = data.get('child_count')
            parts.append(f"Folder, {count} items" if count is not None else "Folder")
        elif kind == 'volume':
            parts.append("Volume")

        size = data.get('size')
        if size not in (None, ''):
            if isinstance(size, (int, float)):
                size = FileSystemUtils.get_readable_size(size)
            parts.append(str(size))

        inode = data.get('inode_number')
        if inode is not None:
            label = self.image_handler.inode_label(
                data.get('start_offset'), inode) if self.image_handler \
                else inode
            parts.append(f"inode {label}")

        if data.get('is_deleted'):
            # Two very different situations both read as "deleted": one where
            # the metadata survives and the file can be opened, and one where
            # the entry points at nothing and only the name is left. Saying
            # which spares the examiner finding out by clicking.
            if data.get('is_recoverable'):
                parts.append("deleted, recoverable")
            elif 'is_recoverable' in data:
                parts.append("deleted, name only")
            else:
                parts.append("deleted")

        return "   ·   ".join(p for p in parts if p)

    def _describe_span(self, label, data):
        """Describe a run of sectors: where it starts and how much it covers."""
        start = data.get('start_offset') or 0
        end = data.get('end_offset')
        parts = [label]
        if end is not None and end >= start and self.image_handler:
            sectors = end - start + 1
            size = sectors * self.image_handler.sector_size
            parts.append(self.image_handler.get_readable_size(size))
        parts.append(f"sector {start:,}")
        return "   ·   ".join(parts)

    def update_status_for_selection(self, data, item=None):
        """Refresh the standing context text for a newly selected item."""
        described = self.describe_selection(data, item)
        if described:
            self.set_status_context(described)

    def _build_menus(self):
        """Menu bar: File, View, Tools, Options and Help."""
        menu_bar = QMenuBar(self)
        # Every command has an icon, set through icons.apply_to so it is
        # re-tinted with the theme (a plain QIcon kept the old theme's
        # colour). Checkable entries -- themes, panel toggles -- have none:
        # Qt draws their tick where the icon goes.
        file_menu = QMenu('File', self)
        # In a case, evidence comes in through the Add Evidence wizard
        # (checked, described, analysed); quick triage keeps the plain file
        # pickers, since nothing there is recorded.
        self.add_evidence_action = icons.action(
            icons.EVIDENCE_ADD,
            "Add Evidence..." if self.case else "Add Evidence File...", self)
        self.add_evidence_action.triggered.connect(self.load_image_evidence)
        self.add_folder_action = icons.action(
            icons.EVIDENCE_FOLDER, "Add Evidence Folder...", self)
        self.add_folder_action.triggered.connect(self.load_folder_evidence)
        self.add_folder_action.setVisible(not self.case)
        self.add_disk_action = icons.action(
            icons.LIVE_DISK, "Add Live Disk...", self)
        self.add_disk_action.setToolTip(
            "Read a disk attached to this computer, read-only, without "
            "imaging it (asks for administrator rights)")
        self.add_disk_action.triggered.connect(self.add_live_disk)
        self.assemble_action = icons.action(
            icons.ASSEMBLE, "Assemble RAID or Multi-Disk Volume...", self)
        self.assemble_action.setToolTip(
            "Read a Linux RAID array or a Btrfs file system across the "
            "member disks' images")
        self.assemble_action.triggered.connect(self.assemble_volume)
        self.remove_evidence_action = icons.action(
            icons.EVIDENCE_REMOVE, "Remove Evidence File...", self)
        self.remove_evidence_action.triggered.connect(
            self.remove_image_evidence)
        for action in (self.add_evidence_action, self.add_folder_action,
                       self.add_disk_action, self.assemble_action,
                       self.remove_evidence_action):
            file_menu.addAction(action)
        file_menu.addSeparator()
        exit_action = icons.action(icons.EXIT, "Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        menu_bar.addMenu(file_menu)

        # Case entries live in their own menu rather than crowding File, and
        # disable themselves in quick triage: an action that cannot work is
        # more honest greyed out than failing when clicked.
        case_menu = QMenu('Case', self)
        self.case_properties_action = QAction("Case Properties...", self)
        self.case_properties_action.triggered.connect(self.show_case_properties)
        case_menu.addAction(self.case_properties_action)

        self.verify_case_action = QAction("Verify All Evidence", self)
        self.verify_case_action.triggered.connect(self.verify_case_evidence)
        case_menu.addAction(self.verify_case_action)

        self.create_report_action = QAction(icons.icon(icons.REPORT),
                                            "Create Report...", self)
        self.create_report_action.triggered.connect(self.create_report)
        case_menu.addAction(self.create_report_action)

        case_menu.addSeparator()
        open_folder_action = QAction("Open Case Folder", self)
        open_folder_action.triggered.connect(self.open_case_folder)
        case_menu.addAction(open_folder_action)
        self.open_case_folder_action = open_folder_action

        for action in (self.case_properties_action, self.verify_case_action,
                       self.create_report_action,
                       self.open_case_folder_action):
            action.setEnabled(self.case is not None)
        if self.case is None:
            case_menu.setToolTipsVisible(True)
            for action in case_menu.actions():
                action.setToolTip("Quick triage: no case is open.")

        menu_bar.addMenu(case_menu)

        # Analysis is its own menu rather than an entry under Case: these are
        # things done to the evidence, and there will be more of them.
        analysis_menu = QMenu('Analysis', self)
        self.run_analysis_action = QAction("Run Analysis Modules...", self)
        self.run_analysis_action.triggered.connect(
            lambda: self.run_analysis_modules())
        analysis_menu.addAction(self.run_analysis_action)

        self.cancel_analysis_action = QAction("Cancel Running Analysis", self)
        self.cancel_analysis_action.triggered.connect(
            lambda: self.job_bar.cancel_all())
        analysis_menu.addAction(self.cancel_analysis_action)

        analysis_menu.addSeparator()
        self.find_by_hash_action = QAction("Find by Hash...", self)
        self.find_by_hash_action.triggered.connect(self.find_by_hash)
        analysis_menu.addAction(self.find_by_hash_action)

        self.match_hash_sets_action = QAction("Match Hash Sets", self)
        self.match_hash_sets_action.triggered.connect(
            lambda: self.queue_hash_matching())
        analysis_menu.addAction(self.match_hash_sets_action)
        self.scan_yara_action = QAction("Scan with YARA", self)
        self.scan_yara_action.triggered.connect(
            lambda: self.queue_yara(self.case.evidence() if self.case
                                    else []))
        analysis_menu.addAction(self.scan_yara_action)
        self.scan_sigma_action = QAction("Check Event Logs with Sigma", self)
        self.scan_sigma_action.triggered.connect(
            lambda: self.queue_sigma(self.case.evidence() if self.case
                                     else []))
        analysis_menu.addAction(self.scan_sigma_action)
        self.search_keywords_action = QAction("Search Keyword Lists", self)
        self.search_keywords_action.triggered.connect(
            lambda: self.queue_keywords())
        analysis_menu.addAction(self.search_keywords_action)

        for action in (self.run_analysis_action, self.cancel_analysis_action,
                       self.find_by_hash_action,
                       self.match_hash_sets_action, self.scan_yara_action,
                       self.scan_sigma_action,
                       self.search_keywords_action):
            action.setEnabled(self.case is not None)
        if self.case is None:
            analysis_menu.setToolTipsVisible(True)
            for action in analysis_menu.actions():
                action.setToolTip(
                    "Analysis findings are kept in a case; quick triage has "
                    "nowhere to record them.")

        menu_bar.addMenu(analysis_menu)

        view_menu = QMenu('View', self)
        # Kept so the docks can add their own toggles once they
        # exist -- menus are built before the docks are.
        self._view_menu = view_menu

        # Create the "Full Screen" action and connect it to the showFullScreen slot
        full_screen_action = QAction("Full Screen", self)
        full_screen_action.triggered.connect(self.showFullScreen)
        view_menu.addAction(full_screen_action)

        # Create the "Normal Screen" action and connect it to the showNormal slot
        reset_layout_action = QAction("Reset Layout", self)
        reset_layout_action.setToolTip("Put the tree and the viewers back "
                                       "where a first run has them")
        reset_layout_action.triggered.connect(lambda: self.reset_layout())

        normal_screen_action = QAction("Normal Screen", self)
        normal_screen_action.triggered.connect(self.showNormal)
        view_menu.addAction(normal_screen_action)
        view_menu.addAction(reset_layout_action)

        # Add a separator
        view_menu.addSeparator()

        # **Add Theme Selection Actions**
        # Create an action group for themes
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)  # Only one theme can be selected at a time

        # Light Theme Action
        saved_theme = read_theme()

        light_theme_action = QAction("Light Mode", self)
        light_theme_action.setCheckable(True)
        light_theme_action.setChecked(saved_theme == 'light')
        light_theme_action.triggered.connect(lambda: self.apply_stylesheet('light'))
        theme_group.addAction(light_theme_action)
        view_menu.addAction(light_theme_action)

        # Dark Theme Action
        dark_theme_action = QAction("Dark Mode", self)
        dark_theme_action.setCheckable(True)
        dark_theme_action.setChecked(saved_theme == 'dark')
        dark_theme_action.triggered.connect(lambda: self.apply_stylesheet('dark'))
        theme_group.addAction(dark_theme_action)
        view_menu.addAction(dark_theme_action)

        # Whatever was chosen last time, not a hardcoded light. app.py has
        # already applied it to the application; this brings the window's own
        # icons and palette into line.
        self.apply_stylesheet(saved_theme)

        tools_menu = QMenu('Tools', self)

        # Both entries open a picker when more than one image is loaded, so
        # they work the same way whether there is one image or several.
        image_info_action = QAction("Image Information", self)
        image_info_action.triggered.connect(self.show_image_info_menu)
        tools_menu.addAction(image_info_action)

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.show_verify_menu)
        tools_menu.addAction(verify_image_action)

        tools_menu.addSeparator()
        hash_sets_action = QAction(icons.icon(icons.HASH_SETS), "Hash Sets...",
                                   self)
        hash_sets_action.triggered.connect(self.show_hash_sets)
        tools_menu.addAction(hash_sets_action)
        yara_action = QAction(icons.icon(icons.FINDING_YARA),
                              "YARA Rules...", self)
        yara_action.triggered.connect(self.show_yara_rules)
        tools_menu.addAction(yara_action)
        sigma_action = QAction(icons.icon(icons.SIGMA), "Sigma Rules...",
                               self)
        sigma_action.triggered.connect(self.show_sigma_rules)
        tools_menu.addAction(sigma_action)
        keywords_action = QAction(icons.icon(icons.KEYWORDS),
                                  "Keyword Lists...", self)
        keywords_action.triggered.connect(self.show_keyword_lists)
        tools_menu.addAction(keywords_action)

        # Add "Options" menu for API key configuration
        options_menu = QMenu('Options', self)
        settings_action = QAction("Settings...", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.show_settings)
        options_menu.addAction(settings_action)
        api_key_action = QAction("API Keys", self)
        api_key_action.triggered.connect(self.show_api_key_dialog)
        options_menu.addAction(api_key_action)
        options_menu.addSeparator()
        features_action = QAction("Supported Features...", self)
        features_action.setToolTip("What this installation can do on this "
                                   "system, and why anything cannot")
        features_action.triggered.connect(self.show_supported_features)
        options_menu.addAction(features_action)

        help_menu = QMenu('Help', self)
        about_action = QAction("About", self)
        about_action.triggered.connect(lambda: AboutDialog(self).exec())
        help_menu.addAction(about_action)

        for action, name in (
                (self.case_properties_action, icons.CASE_PROPERTIES),
                (self.verify_case_action, icons.VERIFY),
                (self.create_report_action, icons.REPORT),
                (self.open_case_folder_action, icons.OPEN_FOLDER),
                (self.run_analysis_action, icons.RUN),
                (self.cancel_analysis_action, icons.CANCEL),
                (self.find_by_hash_action, icons.FIND_HASH),
                (self.match_hash_sets_action, icons.HASH_SETS),
                (self.scan_yara_action, icons.FINDING_YARA),
                (self.scan_sigma_action, icons.SIGMA),
                (self.search_keywords_action, icons.KEYWORDS),
                (full_screen_action, icons.FULL_SCREEN),
                (normal_screen_action, icons.NORMAL_SCREEN),
                (reset_layout_action, icons.RESET_LAYOUT),
                (image_info_action, icons.IMAGE_INFO),
                (verify_image_action, icons.VERIFY),
                (hash_sets_action, icons.HASH_SETS),
                (yara_action, icons.FINDING_YARA),
                (sigma_action, icons.SIGMA),
                (keywords_action, icons.KEYWORDS),
                (settings_action, icons.SETTINGS),
                (api_key_action, icons.API_KEYS),
                (features_action, icons.FEATURES),
                (about_action, icons.HELP)):
            icons.apply_to(action, name)
        self.image_info_action = image_info_action

        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(options_menu)
        menu_bar.addMenu(help_menu)

        self.setMenuBar(menu_bar)

    def _build_toolbar(self):
        """Main toolbar actions."""
        self.main_toolbar = QToolBar()
        prepare_toolbar(self.main_toolbar)
        # Named so the toolbar/dock context menu has a label for it; an unnamed
        # toolbar shows there as a tick box with no text. objectName lets Qt
        # save and restore its position.
        self.main_toolbar.setWindowTitle("Main Toolbar")
        self.main_toolbar.setObjectName("mainToolbar")
        self.main_toolbar.setMovable(False)
        self.main_toolbar.setFloatable(False)
        # The commands used most, in the order an examination runs: bring
        # evidence in, check it, analyse it, report. They are the menu's own
        # actions, so a button is enabled exactly when its menu entry is
        # (case-only commands grey out in quick triage, with the reason).
        for action in (self.add_evidence_action, self.add_folder_action,
                       self.remove_evidence_action):
            self.main_toolbar.addAction(action)
        self.main_toolbar.addSeparator()

        self.verify_image_button = self.create_action(icons.VERIFY, "Verify Image",
                                                     self.show_verify_menu)
        self.main_toolbar.addAction(self.verify_image_button)
        self.main_toolbar.addAction(self.image_info_action)
        self.main_toolbar.addSeparator()

        self.main_toolbar.addAction(self.run_analysis_action)
        self.main_toolbar.addAction(self.search_keywords_action)
        self.main_toolbar.addSeparator()
        self.main_toolbar.addAction(self.create_report_action)


        # Navigation buttons (Back, Forward, Up) will be added to the listing search toolbar
        # Created later in the UI setup

        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)

    def _build_central_widgets(self):
        """Tree viewer, listing table and its toolbar."""
        self.tree_viewer = BranchTreeWidget(self)
        self.tree_viewer.setObjectName("evidenceTree")
        self.tree_viewer.setIconSize(QSize(TREE_ICON_SIZE, TREE_ICON_SIZE))
        self.tree_viewer.setHeaderHidden(True)
        # No frame. A selected row runs the full width of the viewport, and the
        # frame sits immediately left of it -- lighter than the selection, so it
        # read as a white line down the edge of the highlight rather than as the
        # widget's border. It is a QFrame shape, not a QSS border, so it has to
        # come off here. The dock already separates the tree from its
        # surroundings.
        self.tree_viewer.setFrameShape(BranchTreeWidget.NoFrame)
        # Qt's default indentation. It was narrowed to 14 for a while, which
        # left the branch strip too small for the expand arrow to be drawn
        # cleanly -- a 24px glyph fitted into 14px lands on fractional pixels
        # and the diagonals break up. The default gives the arrow room.
        self.tree_viewer.setIndentation(TREE_INDENTATION)
        # No dotted focus rectangle around the current item: the selection
        # colour already shows which row is current.
        #
        # setAllColumnsShowFocus is deliberately NOT set. It makes Qt draw the
        # focus rectangle across the whole row, which is painted by the style
        # outside the item delegate -- so the delegate below cannot suppress
        # it, and it showed as a dashed box around the selected row. The tree
        # is single-column and QTreeWidget::branch:selected already carries the
        # highlight across the indentation strip, so nothing needs it.
        self.tree_viewer.setItemDelegate(NoFocusDelegate(self.tree_viewer))
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        self.tree_viewer.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        self.tree_dock = tree_dock = QDockWidget('Tree View', self)
        tree_dock.setObjectName('treeDock')

        tree_dock.setWidget(self.tree_viewer)
        # Never a sliver: a busy tab once squeezed it to 100 px.
        self.tree_viewer.setMinimumWidth(self._TREE_MIN)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        self.result_viewer = QTabWidget(self)
        self.setCentralWidget(self.result_viewer)

        self.listing_table = QTableWidget()
        self.listing_table.setSortingEnabled(True)
        self.listing_table.verticalHeader().setVisible(False)
        self.listing_table.setObjectName("listingTable")  # Set object name for specific CSS styling

        # Set size policy to expand with window
        self.listing_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Use alternate row colors
        self.listing_table.setAlternatingRowColors(True)
        self.listing_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.listing_table.setItemDelegate(NoFocusDelegate(self.listing_table))
        self.listing_table.setIconSize(QSize(TABLE_ICON_SIZE, TABLE_ICON_SIZE))
        self.listing_table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        # 12 columns. Sequence and Attributes are appended rather than slotted
        # in beside Inode, because the volume, search and file views each set
        # column visibility by hardcoded index.
        self.listing_table.setColumnCount(16)

        # Enable horizontal scrolling for smaller windows
        self.listing_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.listing_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Single click selects: a file's content is shown, a folder is only
        # highlighted. Double-click is what opens a folder, below.
        self.listing_table.itemClicked.connect(
            lambda item: self.on_listing_table_item_clicked(item, navigate=False))

        # Create a QVBoxLayout for the listing tab
        self.listing_layout = QVBoxLayout()
        self.listing_layout.setContentsMargins(0, 0, 0, 0)  # Set to zero to remove margins
        self.listing_layout.setSpacing(0)  # Remove spacing between widgets

        # ==================== CREATE UNIFIED TOOLBAR (like File Carving tab) ====================
        self.listing_toolbar = QToolBar()
        prepare_toolbar(self.listing_toolbar)
        self.listing_toolbar.setContentsMargins(0, 0, 0, 0)
        self.listing_toolbar.setMovable(False)

        # LEFT SIDE: Icon and Title
        self.listing_icon_label = QLabel()
        self.listing_icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(self.listing_icon_label, icons.SEARCH_BROWSER, PANEL_ICON_SIZE)
        self.listing_toolbar.addWidget(self.listing_icon_label)

        self.listing_title_label = QLabel("File System Browser")
        self.listing_title_label.setObjectName("panelTitle")
        self.listing_toolbar.addWidget(self.listing_title_label)

        # Add spacer after title
        title_spacer = QLabel()
        title_spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.listing_toolbar.addWidget(title_spacer)

        # MIDDLE: Navigation buttons (Back, Forward, Up) - next to title
        self.back_action = icons.action(icons.BACK, "Back", self)
        self.back_action.triggered.connect(self.navigate_back)
        self.back_action.setEnabled(False)
        self.listing_toolbar.addAction(self.back_action)

        self.forward_action = icons.action(icons.FORWARD, "Forward", self)
        self.forward_action.triggered.connect(self.navigate_forward)
        self.forward_action.setEnabled(False)
        self.listing_toolbar.addAction(self.forward_action)

        self.go_up_action = icons.action(icons.UP, "Go Up Directory", self)
        self.go_up_action.triggered.connect(self.navigate_up_directory)
        self.go_up_action.setEnabled(False)
        self.listing_toolbar.addAction(self.go_up_action)

        # Add vertical separator after navigation buttons
        self.listing_toolbar.addSeparator()

        # How the listing is shown: Details (the table), List, or icons --
        # Explorer's views, one button with a menu, as Explorer has it.
        self._build_listing_view_button()
        self.listing_toolbar.addSeparator()

        # RIGHT SIDE: Search functionality
        # Add search bar
        self.listing_search_bar = QLineEdit()
        self.listing_search_bar.setObjectName("listingSearchBar")
        self.listing_search_bar.setPlaceholderText("Filter this listing…")
        self.listing_search_bar.setToolTip(
            "Search the image for files by name.\n"
            "Press Enter to run the search.\n"
            "Wildcards are supported, for example *.pdf or report.*")
        self.listing_search_bar.setMinimumWidth(220)
        self.listing_search_bar.setMaximumWidth(380)
        # Only search when user presses Enter
        self.listing_search_bar.returnPressed.connect(self.trigger_listing_search)
        # Monitor text changes for auto-clearing results
        self.listing_search_bar.textChanged.connect(self.on_listing_search_text_changed)
        self.listing_toolbar.addWidget(self.listing_search_bar)

        # A trailing gap so the search field does not sit flush against the
        # panel edge. A zero-height spacer widget is collapsed by the toolbar,
        # so this is set as contents margins instead.
        margins = self.listing_toolbar.contentsMargins()
        self.listing_toolbar.setContentsMargins(
            margins.left(), margins.top(), GROUP_SPACING, margins.bottom())

        # Add the single toolbar and listing table to the layout
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.listing_toolbar)
        self.listing_layout.addWidget(self.listing_toolbar)
        # Below the toolbar: the table (Details) or the list/icon view over
        # the same model and selection (ui/widgets/listing_views.py).
        from trace_app.ui.widgets.listing_views import ListingIconView
        self.listing_icon_view = ListingIconView(
            self.listing_table, self._listing_picture_bytes,
            open_video=self._listing_video_device,
            read_head=self._listing_head_bytes,
            read_icon=self._listing_program_icon)
        self.listing_icon_view.clicked.connect(
            lambda index: self._listing_view_activated(index, False))
        self.listing_icon_view.doubleClicked.connect(
            lambda index: self._listing_view_activated(index, True))
        self.listing_icon_view.customContextMenuRequested.connect(
            self._listing_view_menu)
        self.listing_stack = QStackedWidget()
        self.listing_stack.addWidget(self.listing_table)
        self.listing_stack.addWidget(self.listing_icon_view)
        self.listing_layout.addWidget(self.listing_stack)
        from trace_app.infra.window_state import read_listing_view
        self.set_listing_view(read_listing_view(), remember=False)

        # Create a widget to hold the layout
        self.listing_widget = QWidget()
        self.listing_widget.setLayout(self.listing_layout)

        # Set the horizontal header with hybrid resizing approach
        header = self.listing_table.horizontalHeader()

        # All columns use Interactive mode (fixed width, manually resizable)
        # This enables horizontal scrolling on smaller windows
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Name - fixed, manually resizable
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Inode - fixed, manually resizable
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Type - fixed, manually resizable
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Size - fixed, manually resizable
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Created - fixed, manually resizable
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Accessed - fixed, manually resizable
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Modified - fixed, manually resizable
        header.setSectionResizeMode(7, QHeaderView.Interactive)  # Changed - fixed, manually resizable
        header.setSectionResizeMode(8, QHeaderView.Interactive)  # Path - fixed, manually resizable
        header.setSectionResizeMode(9, QHeaderView.Interactive)  # Info - fixed, manually resizable

        # Set initial column widths
        self.listing_table.setColumnWidth(0, COLUMN_WIDTHS['name'])      # Name - 400px (widest)
        self.listing_table.setColumnWidth(1, COLUMN_WIDTHS['inode'])     # Inode - 45px
        self.listing_table.setColumnWidth(2, COLUMN_WIDTHS['type'])      # Type - 50px
        self.listing_table.setColumnWidth(3, COLUMN_WIDTHS['size'])      # Size - 70px
        self.listing_table.setColumnWidth(4, COLUMN_WIDTHS['created'])   # Created - 90px (narrower)
        self.listing_table.setColumnWidth(5, COLUMN_WIDTHS['accessed'])  # Accessed - 90px (narrower)
        self.listing_table.setColumnWidth(6, COLUMN_WIDTHS['modified'])  # Modified - 90px (narrower)
        self.listing_table.setColumnWidth(7, COLUMN_WIDTHS['changed'])   # Changed - 90px (narrower)
        self.listing_table.setColumnWidth(8, COLUMN_WIDTHS['path'])      # Path - 300px (wide)
        self.listing_table.setColumnWidth(10, COLUMN_WIDTHS['sequence'])
        self.listing_table.setColumnWidth(11, COLUMN_WIDTHS['attributes'])
        self.listing_table.setColumnWidth(9, 250)                        # Info - 250px (for volumes)

        # Remove any extra space in the header
        header.setObjectName("listingTableHeader")
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Set the header labels
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date',
             'Modified Date', 'Changed Date', 'Path', 'Info', 'Seq',
             'Attributes', 'Detected Type', 'Entropy', 'Flag', 'VirusTotal']
        )

        self.listing_table.itemDoubleClicked.connect(self.on_listing_table_item_clicked)
        self.listing_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listing_table.customContextMenuRequested.connect(self.open_listing_context_menu)
        self.listing_table.setSelectionBehavior(QTableWidget.SelectRows)

        # The selected-row colour comes from the theme, via _apply_palette and
        # the ::item:selected rules. This used to pin it to Qt.lightGray here,
        # which ignored the active theme and stayed light grey in dark mode.

        header = self.listing_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)

        self.result_viewer.addTab(self.listing_widget, 'Listing')

        self.registry_extractor_widget = RegistryExtractor(self.image_handler)
        # Hive reading runs on a worker thread, so its progress belongs in the
        # status bar with everything else rather than only as a placeholder row
        # in the tree.
        self.registry_extractor_widget.statusMessage.connect(self.set_status)
        self.result_viewer.addTab(self.registry_extractor_widget, 'Registry')

        # Built here rather than with the viewer-dock panels: the tab below
        # needs it, and _build_central_widgets runs first.
        self.search_panel = SearchPanel()
        self.search_panel.set_case(self.case)
        self.search_panel.result_selected.connect(self.preview_search_result)
        self.search_panel.result_activated.connect(self.open_search_result)
        # The listing's own icon lookup, so a result looks like the file it is.
        self.search_panel.icon_resolver = self._get_file_icon
        self.search_panel.result_menu_requested.connect(
            self.open_search_result_menu)

        # Search results get their own tab rather than borrowing the listing
        # table. Sharing it meant every search toggled columns and saved and
        # restored browse state, and coming back was a mode change.
        self.result_viewer.addTab(self.search_panel, 'Search')

        self.triage_panel = TriagePanel()
        self.triage_panel.set_case(self.case)
        self.triage_panel.icon_resolver = self._get_file_icon
        self.triage_panel.finding_selected.connect(self.preview_artifact)
        self.triage_panel.finding_activated.connect(self.open_finding)
        self.triage_panel.finding_menu_requested.connect(
            self.open_finding_menu)
        # From Triage, the dialog starts on the image Triage is showing.
        self.triage_panel.run_requested.connect(
            lambda: self.run_analysis_modules(self.triage_panel.evidence_id))

        # Carving is a Triage sub-tab: what it recovers is reviewed like any
        # other finding, and with a case it runs as an analysis job.
        self.carved_panel = CarvedFilesPanel()
        self.carved_panel.icon_resolver = self._get_file_icon
        self.carved_panel.content_reader = self._carved_bytes
        self.carved_panel.carve_requested.connect(self.start_carving)
        self.carved_panel.resume_requested.connect(self.resume_carving)
        self.carved_panel.file_selected.connect(self.preview_carved)
        self.carved_panel.file_activated.connect(self.open_carved)
        self.carved_panel.file_menu_requested.connect(self.open_carved_menu)
        self.triage_panel.add_carved_tab(self.carved_panel)

        # What indexing extracted: every email, URL, number and address,
        # and the files each is in. Its files are search-index rows, so they
        # open, preview and get the menu exactly as search results do.
        self.indicators_panel = IndicatorsPanel()
        self.indicators_panel.icon_resolver = self._get_file_icon
        self.indicators_panel.file_selected.connect(self.preview_search_result)
        self.indicators_panel.file_activated.connect(self.open_search_result)
        self.indicators_panel.file_menu_requested.connect(
            self.open_search_result_menu)
        self.indicators_panel.search_requested.connect(self.search_for)
        self.triage_panel.add_indicators_tab(self.indicators_panel)

        # What each NTFS volume's own records say: timestomping, streams and
        # downloads, the change journal. Its rows are findings (or carry an
        # artifact_ref), so they preview, open and get the menu as findings do.
        self.ntfs_panel = NtfsPanel()
        self.ntfs_panel.file_selected.connect(self.preview_artifact)
        self.ntfs_panel.file_activated.connect(self.open_finding)
        self.ntfs_panel.file_menu_requested.connect(self.open_finding_menu)
        self.triage_panel.add_ntfs_tab(self.ntfs_panel)

        # Files matching the examiner's hash sets: known bad and notable as
        # findings, known good on request.
        self.hash_panel = HashMatchesPanel()
        self.hash_panel.file_selected.connect(self.preview_artifact)
        self.hash_panel.file_activated.connect(self.open_finding)
        self.hash_panel.file_menu_requested.connect(self.open_finding_menu)
        self.hash_panel.manage_requested.connect(self.show_hash_sets)
        self.hash_panel.match_requested.connect(
            lambda: self.queue_hash_matching())
        self.triage_panel.add_hash_tab(self.hash_panel)

        from trace_app.ui.viewers.similar_pictures_panel import             SimilarPicturesPanel
        self.similar_panel = SimilarPicturesPanel()
        self.similar_panel.file_selected.connect(self.preview_artifact)
        self.similar_panel.file_activated.connect(self.open_finding)
        self.similar_panel.file_menu_requested.connect(
            self.open_finding_menu)
        self.triage_panel.add_similar_tab(self.similar_panel)

        # Everything set to start by itself, graded.
        from trace_app.ui.viewers.persistence_panel import PersistencePanel
        self.persistence_panel = PersistencePanel()
        self.persistence_panel.file_selected.connect(self.preview_artifact)
        self.persistence_panel.file_activated.connect(self.open_finding)
        self.persistence_panel.file_menu_requested.connect(
            self.open_finding_menu)
        self.triage_panel.add_persistence_tab(self.persistence_panel)

        # The examiner's keyword lists, searched across the case.
        from trace_app.ui.viewers.keywords_panel import KeywordsPanel
        self.keywords_panel = KeywordsPanel()
        self.keywords_panel.file_selected.connect(self.preview_keyword_hit)
        self.keywords_panel.file_activated.connect(self.open_keyword_hit)
        self.keywords_panel.file_menu_requested.connect(
            self.open_finding_menu)
        self.keywords_panel.manage_requested.connect(self.show_keyword_lists)
        self.keywords_panel.search_requested.connect(
            lambda: self.queue_keywords())
        self.triage_panel.add_keywords_tab(self.keywords_panel)

        # Pictures Windows kept in its thumbnail caches.
        from trace_app.ui.viewers.thumbnails_panel import ThumbnailsPanel
        self.thumbnails_panel = ThumbnailsPanel()
        self.thumbnails_panel.set_reader(self._thumbnail_bytes)
        self.thumbnails_panel.picture_selected.connect(self.preview_thumbnail)
        self.thumbnails_panel.picture_activated.connect(
            self.open_thumbnail_cache)
        self.thumbnails_panel.picture_menu_requested.connect(
            lambda row, position: self.open_finding_menu(
                self._thumbnail_cache_row(row), position))
        self.triage_panel.add_thumbnails_tab(self.thumbnails_panel)

        # Deleted files, and how much of each is left.
        from trace_app.ui.viewers.deleted_panel import DeletedFilesPanel
        self.deleted_panel = DeletedFilesPanel()
        self.deleted_panel.file_selected.connect(self.preview_artifact)
        self.deleted_panel.file_activated.connect(self.open_finding)
        self.deleted_panel.file_menu_requested.connect(
            self.open_finding_menu)
        self.triage_panel.add_deleted_tab(self.deleted_panel)

        # Where located evidence was: photo GPS and records with a
        # position. Offline unless the examiner agrees to fetch map tiles.
        from trace_app.ui.viewers.map_panel import MapPanel
        self.map_panel = MapPanel()
        self.map_panel.point_selected.connect(self.preview_located)
        self.map_panel.point_activated.connect(self.open_located)
        self.map_panel.point_menu_requested.connect(
            lambda point, position: self.open_finding_menu(
                self._located_artifact(point), position))
        self.triage_panel.add_map_tab(self.map_panel)
        self.result_viewer.addTab(self.triage_panel, 'Triage')

        # What the users did. A tab of its own rather than a Triage sub-tab:
        # it is a record of events across the case, not a list of flagged
        # files, and it is what a timeline grows from.
        self.activity_panel = ActivityPanel()
        self.activity_panel.row_selected.connect(self.preview_activity_source)
        self.activity_panel.row_activated.connect(self.open_activity_source)
        self.activity_panel.deleted_requested.connect(self.show_deleted_file)
        self.activity_panel.run_requested.connect(
            lambda: self.run_analysis_modules(self.activity_panel.evidence_id))
        self.activity_panel.set_case(self.case)
        self.result_viewer.addTab(self.activity_panel, 'Activity')

        # Everything with a time, in one order: NTFS times and journal,
        # activity, photo and document dates, carved files' own dates, and
        # the examination itself. Reviewed like Triage: a click previews.
        self.timeline_panel = TimelinePanel()
        self.timeline_panel.row_selected.connect(self.preview_artifact)
        self.timeline_panel.row_activated.connect(self.open_finding)
        self.timeline_panel.report_requested.connect(
            self.add_timeline_to_report)
        self.timeline_panel.exported.connect(self._timeline_exported)
        self.timeline_panel.menu_extender = self._timeline_menu_extras
        self.timeline_panel.detail_extender = self._timeline_detail
        self.timeline_panel.set_case(self.case)
        self.result_viewer.addTab(self.timeline_panel, 'Timeline')

    def _build_viewer_dock(self):
        """Bottom "Utils" dock holding the viewer tabs."""
        self.viewer_tab = QTabWidget(self)

        self.hex_viewer = HexViewer(self)
        self.hex_viewer.sector_size = lambda: int(
            getattr(self.image_handler, 'sector_size', 512) or 512)
        self.hex_viewer.bookmarks_enabled = lambda: self.case is not None
        from trace_app.ui.widgets.context_menus import set_row_hook
        set_row_hook(self._menu_extras)
        self.hex_viewer.bookmark_requested.connect(self.bookmark_byte_range)
        self.text_viewer = TextViewer(self)
        self.text_viewer.bookmark_requested.connect(
            self.bookmark_text_selection)
        self.application_viewer = UnifiedViewer(self)
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.metadata_viewer = MetadataViewer(self.image_handler)

        # Each viewer is wrapped in an adapter exposing a common
        # display()/clear() interface, so nothing below has to dispatch on a
        # tab index. Tab order comes from this list alone.
        self.case_panel = CasePanel()
        self.case_panel.profile_for = lambda row: (
            self.evidence_profile(row) or {}).get('summary')
        self.case_panel.set_case(self.case)
        self.case_panel.verify_requested.connect(
            lambda rows: self.queue_verification(rows, summary=True)
            if rows else None)
        self.case_panel.properties_requested.connect(
            self.show_case_properties)

        self.notes_panel = NotesPanel()
        self.notes_panel.set_case(self.case)
        self.notes_panel.open_artifact.connect(self.go_to_bookmark)

        # A SQLite database shows in the Application tab like any other
        # format; its -wal is read from beside it on the image.
        self.application_viewer.database_wal_reader = self._sibling_wal
        self.viewer_adapters = [
            HexAdapter(self.hex_viewer),
            TextAdapter(self.text_viewer),
            ApplicationAdapter(self.application_viewer),
            MetadataAdapter(self.metadata_viewer),
            CaseAdapter(self.case_panel),
            NotesAdapter(self.notes_panel),
        ]
        for adapter in self.viewer_adapters:
            self.viewer_tab.addTab(adapter.widget, adapter.label)

        # VirusTotal is not one of the fixed tabs: it joins the dock the
        # first time a lookup is made (show_vt_panel) and can be closed.
        self.vt_worker = None
        self.vt_panel = VirusTotalPanel()
        self.vt_panel.set_has_key(self.vt_api_key())
        self.vt_panel.lookup_requested.connect(
            lambda entry: self.vt_submit([self._vt_target_from_entry(entry)],
                                         METHOD_HASH))
        self.vt_panel.upload_requested.connect(
            lambda entry: self.vt_submit([self._vt_target_from_entry(entry)],
                                         METHOD_UPLOAD))
        self.vt_panel.reveal_requested.connect(self.preview_artifact)
        self.vt_panel.cancel_requested.connect(self.vt_cancel)
        if self.case:
            self.vt_panel.set_entries(
                [self._vt_entry_from_row(r) for r in self.case.vt_results()])

        # Bookmarks are a sub-tab of Triage, beside the findings: the two lists
        # an examiner works down. They used to be a right-hand dock, hidden by
        # default, so the fuller view of them was one most people never found.
        self.bookmarks_panel = BookmarksPanel()
        self.bookmarks_panel.set_case(self.case)
        self.bookmarks_panel.bookmark_selected.connect(self.preview_artifact)
        self.bookmarks_panel.jump_requested.connect(self.go_to_bookmark)
        self.bookmarks_panel.bookmarks_changed.connect(
            self.refresh_bookmarks_tree)
        self.triage_panel.add_bookmarks_tab(self.bookmarks_panel)

        self.viewer_dock = QDockWidget('Utils', self)
        self.viewer_dock.setObjectName('utilsDock')
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        # A floor, not a fixed size: the dock stays usable but the user can
        # drag the splitter. Setting minimum == maximum (as this did) pinned it
        # and made the splitter inert.
        self.viewer_dock.setMinimumHeight(VIEWER_DOCK_MIN_HEIGHT)

        # The viewer must never be sized by what it happens to be showing.
        # Without this, opening a large image grew the dock and squeezed the
        # file listing.
        self.viewer_tab.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        # Every panel that can be shown or hidden, gathered in one place in
        # the View menu now that the docks exist.
        self._add_panel_toggles()

        # disable all tabs before loading an image file
        self.enable_tabs(False)

    def apply_stylesheet(self, theme='light'):
        if theme == 'dark':
            qss_file = resource_path('styles/dark_theme.qss')
        else:
            qss_file = resource_path('styles/light_theme.qss')

        # Monochrome icons are tinted to the theme's foreground colour, so the
        # registry needs to know which theme is active before anything asks it
        # for an icon.
        icons.set_theme(theme)

        self._apply_palette(theme)

        # BranchTreeWidget resolves its own chevrons from the active theme,
        # so no tree needs to be told about the change here. Handing them out
        # one tree at a time is what left the registry browser drawing light
        # arrows on a dark background.
        for tree in self.findChildren(BranchTreeWidget):
            tree.viewport().update()

        # Verdict colours are chosen per theme in code, since item text is not
        # reached by the stylesheet.
        if getattr(self, 'vt_panel', None) is not None:
            self.vt_panel.retheme()
            self.mark_vt_rows()

        # A verified image's icon is a recoloured pixmap built once, not a
        # registry icon, so set_theme does not reach it. The green and amber
        # are the same in both themes, but rebuilding here keeps the icon
        # correct if the underlying artwork is ever theme-dependent.
        for path, result in getattr(self, 'verification_results', {}).items():
            self.mark_image_verified(path, result.get('verified', False))

        try:
            with open(qss_file, 'r') as f:
                stylesheet = f.read()
            QApplication.instance().setStyleSheet(self._resolve_qss_urls(stylesheet))
        except Exception as e:
            logger.error(f"Error loading stylesheet {qss_file}: {e}")

        # A tab bar keeps the tab widths it measured under the old theme;
        # the light theme's tabs are wider, and the bars scrolled with room
        # to spare. Setting the icon size again makes each one measure anew.
        for bar in self.findChildren(QTabBar):
            bar.setIconSize(bar.iconSize())
            bar.updateGeometry()

        # Remembered, so the next launch -- including its launcher -- opens in
        # the theme the examiner actually chose.
        save_theme(theme)

    #: Selection colours per theme: (highlight, highlighted text). These match
    #: the ::item:selected rules in the corresponding stylesheet.
    _PALETTE_SELECTION = {
        'dark': ('#505050', '#E0E0E0'),
        'light': ('#CCE8FF', '#212529'),
    }

    def _apply_palette(self, theme):
        """Align the palette's selection colours with the stylesheet's.

        A stylesheet cannot reach everything. The tree's branch area -- the
        indentation strip holding the expand arrows -- is painted by the style
        using the palette's Highlight role, so a selected row showed the Qt
        default (#308cc6) there while the row itself used the themed colour
        from ::item:selected. The result was a blue block down the left of
        every selected row that no ::branch rule could remove.
        """
        highlight, text = self._PALETTE_SELECTION.get(
            theme, self._PALETTE_SELECTION['light'])
        palette = QApplication.instance().palette()
        palette.setColor(QPalette.Highlight, QColor(highlight))
        palette.setColor(QPalette.HighlightedText, QColor(text))
        QApplication.instance().setPalette(palette)

    #: Matches url('Icons/...') / url("styles/...") / url(Icons/...) in QSS.
    _QSS_URL = re.compile(r"""url\(\s*(['"]?)((?:Icons|styles)/[^'")]+)\1\s*\)""")

    @classmethod
    def _resolve_qss_urls(cls, stylesheet):
        """Rewrite relative url() paths in a stylesheet to absolute ones.

        Qt resolves a relative url() against the process working directory, not
        against the stylesheet's own location, so the combo-box arrow and the
        check-box tick silently disappeared whenever the application was
        started from anywhere other than the project root.
        """
        def absolute(match):
            quote, relative = match.group(1), match.group(2)
            resolved = resource_path(relative).replace('\\', '/')
            return f"url({quote}{resolved}{quote})"

        return cls._QSS_URL.sub(absolute, stylesheet)

    def show_api_key_dialog(self):
        # Create a dialog to get API keys from the user
        dialog = QDialog(self)
        dialog.setWindowTitle("API Key Configuration")
        dialog.setFixedWidth(API_DIALOG_WIDTH)  # Set a fixed width to accommodate longer API keys

        # Set layout as a form layout for better presentation
        layout = QFormLayout()
        layout.setSpacing(10)  # Add some spacing between fields
        layout.setContentsMargins(15, 15, 15, 15)  # Set content margins for better visual aesthetics

        # VirusTotal API Key
        virus_total_label = QLabel("VirusTotal API Key:")
        virus_total_input = QLineEdit()
        virus_total_input.setEchoMode(QLineEdit.Password)
        virus_total_input.setText(self.api_keys.get('API_KEYS', 'virustotal', fallback=''))
        virus_total_input.setMinimumWidth(INPUT_FIELD_MIN_WIDTH)  # Set a minimum width for the input field
        layout.addRow(virus_total_label, virus_total_input)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(
            lambda: self.save_api_keys(virus_total_input.text(), dialog))
        button_box.rejected.connect(dialog.reject)
        layout.addRow(button_box)

        # Set layout and execute dialog
        dialog.setLayout(layout)
        dialog.exec()

    def save_api_keys(self, virus_total_key, dialog):
        # Save the API keys in a configuration file
        if not self.api_keys.has_section('API_KEYS'):
            self.api_keys.add_section('API_KEYS')

        self.api_keys.set('API_KEYS', 'virustotal', virus_total_key)

        try:
            with open(config_file(), 'w') as fh:
                self.api_keys.write(fh)
        except OSError as e:
            # Previously this raised straight out of the button's slot.
            logger.error(f"Could not save API keys: {e}")
            message.warning(
                self, "Could not save API key",
                f"The API key could not be written to disk:\n{e}\n\n"
                "It will be used for this session only.")

        dialog.accept()

        self.vt_panel.set_has_key(virus_total_key)

    def handler_for(self, image_path):
        """An ImageHandler for `image_path`, reusing the loaded one if it fits.

        Only one image is open at a time, so a picker that offers several has
        to open the one it was asked for -- otherwise choosing the second image
        silently described or hashed the first.
        """
        if not image_path or image_path == self.current_image_path:
            return self.image_handler

        handler = self._image_handlers.get(os.path.normpath(image_path))
        if handler is not None:
            return handler

        handler = self._auxiliary_handlers.get(image_path)
        if handler is not None:
            return handler

        handler = ImageHandler(image_path)
        if not handler.loaded:
            logger.error("Could not open %s for this operation", image_path)
            return None
        self._auxiliary_handlers[image_path] = handler
        return handler

    def verify_image(self, image_path=None):
        """Show the verification dialog for one image.

        Defaults to the image currently loaded. Re-opening for an image already
        verified this session renders the stored result instead of hashing the
        whole image again.
        """
        if self.image_handler is None:
            message.warning(self, "Verify Image", "No image is currently loaded.")
            return

        path = image_path or self.current_image_path
        handler = self.handler_for(path)
        if handler is None:
            message.warning(self, "Verify Image",
                            f"Could not open {path} for verification.")
            return

        # A raw image has no hash inside it to check against, so the only
        # meaningful comparison is with what the case recorded earlier.
        expected = None
        if self.case:
            row = self.case.evidence_for_path(path)
            if row:
                expected = row.get('md5')

        self.verification_widget = VerificationWidget(
            handler, cached=self.verification_results.get(path),
            expected_md5=expected)
        self.verification_widget.closeEvent = (
            lambda event, p=path: self.on_verification_closed(event, p))
        self.verification_widget.show()

    def on_verification_closed(self, event, image_path=None):
        """Store the result against its image, and badge that image in the tree."""
        widget = self.verification_widget
        results = widget.results() if hasattr(widget, 'results') else None
        if results and image_path:
            self.verification_results[image_path] = results
            self.mark_image_verified(image_path, results.get('verified', False))
            # A case stores the digests themselves, so reopening it does not
            # re-hash an image the examiner already waited for.
            self.store_verification_in_case(image_path, results)

        QWidget.closeEvent(widget, event)

    def mark_image_verified(self, image_path, verified):
        """Show an image verification state on its own row in the tree.

        The image's own icon carries the state: green once its hashes verify,
        amber when they do not. Two earlier attempts put a separate mark beside
        the icon -- first in its own column, then overlaid in its corner -- and
        both were worse. The column pushed the row out of line with the volumes
        beneath it; the overlay crammed a second glyph into a 16px icon.

        This used to swap the toolbar button icon instead, which is a property
        of the window rather than of an image: with two images loaded it
        claimed both were verified.
        """
        root = self.tree_viewer.invisibleRootItem()
        disk_icon = self.db_manager.get_icon_path('device', 'media-optical')
        for i in range(root.childCount()):
            item = root.child(i)
            if self._root_image_path(item) != os.path.normpath(image_path):
                continue
            hue = icons.VERIFIED_HUE if verified else icons.UNVERIFIED_HUE
            item.setIcon(0, icons.recoloured(disk_icon, hue, TREE_ICON_SIZE))
            item.setToolTip(0, f"{image_path}\n" + (
                            "Hashes verified against those stored in the image"
                            if verified else
                            "Checked this session: hashes did not match"))
            return

    def verification_state(self, image_path):
        """Return 'verified', 'failed', or None for an image."""
        result = self.verification_results.get(image_path)
        if result is None:
            return None
        return 'verified' if result.get('verified') else 'failed'

    def show_verify_menu(self):
        """Toolbar Verify: pick an image when more than one is loaded.

        With a single image this goes straight to the dialog. With several, the
        menu is the only place that says which of them have been verified.
        """
        if not self.evidence_files:
            message.warning(self, "Verify Image", "No image is currently loaded.")
            return

        if len(self.evidence_files) == 1:
            self.verify_image(self.evidence_files[0])
            return

        menu = QMenu(self)
        for path in self.evidence_files:
            state = self.verification_state(path)
            suffix = {'verified': "verified",
                      'failed': "not verified"}.get(state, "not checked")
            entry = menu.addAction(f"{path}  \u2014 {suffix}")
            if state is not None:
                entry.setIcon(icons.icon(
                    icons.VERIFY_OK if state == 'verified' else icons.VERIFY))
            entry.triggered.connect(lambda _=False, p=path: self.verify_image(p))
        show_menu(menu, QCursor.pos())

    def _release_auxiliary_handler(self, image_path):
        """Close and forget a handler opened for evidence being removed."""
        handler = self._auxiliary_handlers.pop(image_path, None)
        if handler is None:
            return
        try:
            handler.close_resources()
        except Exception as e:
            logger.error("Error closing handler for %s: %s", image_path, e)

    def show_image_info_menu(self):
        """Tools > Image Information: pick an image when several are loaded.

        Same shape as show_verify_menu -- straight to the dialog for a single
        image, a picker otherwise.
        """
        if not self.evidence_files:
            message.warning(self, "Image Information",
                            "No image is currently loaded.")
            return

        if len(self.evidence_files) == 1:
            self.show_image_information_for(self.evidence_files[0])
            return

        menu = QMenu(self)
        for path in self.evidence_files:
            entry = menu.addAction(path)
            entry.setIcon(icons.icon(icons.EVIDENCE_ADD))
            entry.triggered.connect(
                lambda _=False, p=path: self.show_image_information_for(p))
        show_menu(menu, QCursor.pos())

    def show_image_information_for(self, image_path):
        """Open the information dialog against a named image.

        The dialog reads self.image_handler, so an image other than the one on
        screen is swapped in for the duration and put back afterwards -- the
        alternative is the dialog describing whichever image happens to be
        loaded rather than the one that was chosen.
        """
        handler = self.handler_for(image_path)
        if handler is None:
            message.warning(self, "Image Information",
                            f"Could not open {image_path}.")
            return

        original = self.image_handler
        self.image_handler = handler
        try:
            self.show_image_information()
        finally:
            self.image_handler = original

    # --- bookmarks --------------------------------------------------------

    def artifact_ref_for(self, data):
        """A durable reference to whatever `data` describes, or None.

        `data` is one of the Qt.UserRole payloads built by the listing, the
        tree or a search result. They carry the partition offset and inode; the
        MFT sequence is carried where the source had it, because two files can
        share an inode over a volume's life and a reference without it can come
        to mean a different file.
        """
        if not data:
            return None
        offset = data.get('start_offset')
        inode = data.get('inode_number')
        if offset is None or inode is None:
            return None
        return make_artifact_ref(offset, inode, data.get('sequence'))

    def evidence_id_for_current_image(self):
        """The case's id for the image on screen, or None."""
        if not self.case or not self.current_image_path:
            return None
        row = self.case.evidence_for_path(self.current_image_path)
        if row is None:
            row_id = self.case.add_evidence(self.current_image_path)
            return row_id
        return row['id']

    def open_archive_member(self, name, content):
        """Show a file that came out of an archive in the ordinary viewers.

        The member has no inode of its own -- it exists only inside the
        archive -- so the payload says so rather than inventing a location
        that would resolve to something else entirely.
        """
        data = {
            'name': name,
            'type': 'file',
            'size': len(content),
            'path': name,
            'inode_number': None,
            'start_offset': self.current_offset,
            'from_archive': True,
        }
        self.current_selected_data = data
        self.update_viewer_with_file_content(content, data)
        self.set_status(f"{name} — read from inside an archive")

    def open_carved_menu(self, row, position):
        """The context menu for a carved file.

        A carved file has no inode -- it was recovered from unallocated space,
        which is the whole point -- so it is referenced by the byte span it
        was found at, which is also what names it on disk.
        """
        menu = QMenu(self)
        path = row.get('path') or ''
        selected = [r for r in self.carved_panel.selected_rows() if r] \
            if self.sender() is self.carved_panel else []
        if row not in selected:
            selected = [row]
        export_action = menu.addAction(
            icons.icon(icons.SAVE_AS),
            f"Export {len(selected)} Files..." if len(selected) > 1
            else "Export...")
        export_action.setToolTip("Write a copy read from the image, checked "
                                 "against its recorded SHA-256, with a "
                                 "manifest of where it came from.")
        shown = self.carved_panel.shown_rows()
        export_all = menu.addAction(f"Export All Shown ({len(shown):,})...")
        export_all.setEnabled(len(shown) > len(selected))
        menu.addSeparator()
        open_action = menu.addAction("Open Externally")
        location_action = menu.addAction("Show in Folder")
        has_copy = os.path.isfile(path)
        open_action.setEnabled(has_copy)
        location_action.setEnabled(has_copy)
        if not has_copy:
            for action in (open_action, location_action):
                action.setToolTip("Kept as a reference into the image: "
                                  "export it first.")
        menu.setToolTipsVisible(True)
        browse = None
        kind = (row.get('type') or '').lower()
        if kind in CARVED_ARCHIVE_TYPES | CARVED_BROWSABLE_DOCUMENTS:
            browse = menu.addAction("Browse Archive")
            if kind in CARVED_ARCHIVE_TYPES:
                menu.setDefaultAction(browse)
        copy_hash = lookup = None
        if row.get('sha256'):
            copy_hash = menu.addAction("Copy Hashes")
            copy_hash.setToolTip("MD5, SHA-1 and SHA-256")
            if self.case and row.get('evidence_id') is not None:
                lookup = menu.addMenu("VirusTotal").addAction(
                    "Look Up Hash")
                lookup.setToolTip("Sends only the SHA-256.")

        evidence_id = row.get('evidence_id')
        if self.case and evidence_id is not None:
            menu.addSeparator()
            offset, size = int(row.get('offset') or 0), int(row.get('size') or 0)
            ref = row.get('artifact_ref') or make_span_ref(0, offset,
                                                           offset + size)
            existing = self.case.bookmark_for_artifact(evidence_id, ref)
            if existing:
                remove = menu.addAction("Remove Bookmark")
                remove.triggered.connect(
                    lambda: self._remove_bookmark_and_refresh(existing))
            else:
                add = menu.addAction("Add Bookmark")
                add.triggered.connect(
                    lambda: self._bookmark_carved(row, ref))

        chosen = show_menu(menu, position)
        if chosen == export_action:
            self.export_carved_rows(selected)
        elif chosen == export_all:
            self.export_carved_rows(shown)
        elif browse is not None and chosen == browse:
            if not self.browse_carved_archive(row):
                self.set_status(f"{row.get('name')} could not be opened as an "
                                f"archive.", 5000)
        elif chosen == open_action:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        elif chosen == location_action:
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
        elif copy_hash is not None and chosen == copy_hash:
            QApplication.clipboard().setText('\n'.join(
                f"{label}: {row[key]}" for label, key in (
                    ('MD5', 'md5'), ('SHA-1', 'sha1'), ('SHA-256', 'sha256'))
                if row.get(key)))
            self.set_status("Hashes copied")
        elif lookup is not None and chosen == lookup:
            self.vt_lookup_carved(row)

    def vt_lookup_carved(self, row):
        """Ask VirusTotal about a carved file by its SHA-256 alone."""
        if not self.activate_evidence(row.get('evidence_id')):
            return
        offset, size = int(row.get('offset') or 0), int(row.get('size') or 0)
        name = ((row.get('origin') or {}).get('name') or row.get('name')
                or '')
        self.vt_submit([{
            'name': name, 'path': f"carved at byte {offset:,}",
            'inode': None, 'start_offset': None,
            'artifact_ref': row.get('artifact_ref')
            or make_span_ref(0, offset, offset + size),
            'image_path': self.current_image_path,
            'sha256': row['sha256']}], METHOD_HASH)

    def _sibling_wal(self, data):
        """A database's -wal beside it on the volume, if there is one."""
        path = (data or {}).get('path')
        offset = (data or {}).get('start_offset')
        if not path or offset is None or not self.image_handler or \
                '!/' in path:
            return None
        return self.image_handler.read_path(offset, path + '-wal')

    def _bookmark_carved(self, row, ref):
        label, ok = QInputDialog.getText(
            self, "Add bookmark", "Label:", text=row.get('name') or '')
        if not ok or not label.strip():
            return
        self.case.add_bookmark(
            row['evidence_id'], ref, label.strip(),
            artifact_name=row.get('name') or '',
            artifact_path=row.get('path') or '')
        self.refresh_bookmarks()
        self.set_status(f"Bookmarked {label.strip()}")

    # --- carving ---------------------------------------------------------

    def _carving_targets(self):
        """The images carving can search: [(key, label)].

        With a case, its evidence (by id); without one, the images open in
        this session (by path).
        """
        if self.case is not None:
            return [(row['id'], row.get('display_name')
                     or os.path.basename(row['path']))
                    for row in self.case.evidence()
                    if os.path.exists(row['path'])]
        return [(path, os.path.basename(path))
                for path in self._image_handlers]

    def _refresh_carving_targets(self):
        panel = getattr(self, 'carved_panel', None)
        if panel is not None:
            panel.set_targets(self._carving_targets())

    def resume_carving(self, evidence_id):
        """Carry on an interrupted carve, with the settings it ran with."""
        if not self.case:
            return 0
        state = self.case.carving_state(evidence_id) or {}
        types = [t for t in (state.get('types') or '').split(',') if t]
        return self.start_carving([evidence_id], types, None, resume=True)

    def start_carving(self, targets, file_types, unallocated_only,
                      resume=False):
        """Queue one carve per image: those in `targets`, or every one.
        `unallocated_only` is a source (carving.SOURCES) or, from the
        analysis dialog, True / False for unallocated / whole image.

        Jobs share the status-bar queue with analysis and indexing -- two
        readers of one image are slower than one -- and are cancelled from
        there the same way.
        """
        jobs = []
        if self.case is not None:
            for row in self.case.evidence():
                if targets is None or row['id'] in targets:
                    jobs.append((row['id'], row['path'],
                                 row.get('display_name')
                                 or os.path.basename(row['path'])))
        else:
            for path in (list(self._image_handlers) if targets is None
                         else targets):
                jobs.append((None, path, os.path.basename(path)))

        queued = 0
        logical = []
        for evidence_id, path, label in jobs:
            if not os.path.exists(path):
                logger.warning("Skipping carving of missing %s", path)
                continue
            from trace_app.core.logical_sources import kind_of
            if kind_of(path):
                # Files, not a disk: no sectors, nothing unallocated.
                logical.append(label)
                continue
            if self._queue_carving_job(evidence_id, path, label, file_types,
                                       unallocated_only, resume):
                queued += 1
        if queued:
            self.set_status(f"Carving {queued} image(s) in the background")
        elif logical:
            self.set_status(f"Nothing to carve in {', '.join(logical)}: "
                            f"logical evidence holds files, not a disk",
                            8000)
        return queued

    def _queue_carving_job(self, evidence_id, path, label, file_types,
                           unallocated_only, resume=False):
        key = evidence_id if evidence_id is not None else path
        case_folder = self.case.folder if self.case is not None else None
        if isinstance(unallocated_only, str) or unallocated_only is None:
            source = unallocated_only
        else:
            source = 'unallocated' if unallocated_only else 'image'

        def start(job):
            if not resume:
                self.carved_panel.forget(key)
            self.carved_panel.update_resume(running={evidence_id})
            worker = CarvingWorker(path, file_types,
                                   source in (None, 'unallocated'),
                                   case_folder=case_folder,
                                   evidence_id=evidence_id, label=label,
                                   parent=self, source=source,
                                   resume=resume)
            worker.progressed.connect(
                lambda done, total, found: self.job_bar.report(
                    done, total, f"{found:,} file(s) found"))
            worker.file_carved.connect(self.carved_panel.add_record)
            worker.finished_carving.connect(
                lambda count, error: self._carving_finished(label, count,
                                                            error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"carving:{key}",
            title=f"Carving {label}",
            start=start,
            stop=lambda worker: worker.stop()))

    def _carving_finished(self, label, count, error):
        if error:
            self.set_status(f"Carving {label} failed: {error}")
        else:
            self.set_status(f"Carved {count:,} file(s) from {label}")
        self.job_bar.job_finished()
        if self.case is not None:
            # The job indexed what it carved, through its own connection.
            self.search_panel.reload_index()
            self.refresh_analysis_views()

    def _carved_reader(self, row):
        """The read(offset, size) of a carve's own image, without changing
        the window's active image (thumbnails and exports read while the
        examiner looks at something else)."""
        path = row.get('image_path')
        if not path and self.case is not None and \
                row.get('evidence_id') is not None:
            evidence = next((r for r in self.case.evidence()
                             if r['id'] == row['evidence_id']), None)
            path = evidence['path'] if evidence else None
        handler = self.handler_for(path) if path else self.image_handler
        if handler is None:
            raise OSError("the image is not open")
        return handler.read

    def _carved_bytes(self, row):
        """A carve's bytes from its image (fragments followed), quietly:
        None if it cannot be read."""
        try:
            fragments = row.get('fragments')
            if fragments is None and self.case is not None and \
                    row.get('evidence_id') is not None:
                fragments = self.case.carved_fragments(row['evidence_id'],
                                                       int(row['offset']))
            return read_carved(self._carved_reader(row), int(row['offset']),
                               int(row['size']), fragments)
        except Exception as exc:
            logger.debug("Carve at %s not read: %s", row.get('offset'), exc)
            return None

    def export_carved_rows(self, rows, folder=None):
        """Write carved files out, read from their images, into a new
        'Carved files <time>' folder with manifest.csv; checked against the
        SHA-256 recorded when each was carved, and audited. `folder` skips
        the folder dialog (tests). Returns the export worker."""
        from trace_app.ui.viewers.carved_panel import CarvedExportWorker
        rows = [r for r in rows if r]
        if not rows:
            return None
        if folder is None:
            base = QFileDialog.getExistingDirectory(
                self, "Export carved files to", case_settings.export_dir())
            if not base:
                return None
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
                '%Y-%m-%d %H%M%S UTC')
            folder = os.path.join(base, f"Carved files {stamp}")
        readers = {}
        try:
            for row in rows:
                key = row.get('evidence_id') if row.get('evidence_id') \
                    is not None else row.get('image_path')
                if key not in readers:
                    readers[key] = self._carved_reader(row)
        except OSError as exc:
            message.warning(self, "Export", "The image could not be read.",
                            str(exc))
            return None
        worker = CarvedExportWorker(
            rows, folder,
            lambda row: readers[row.get('evidence_id') if row.get(
                'evidence_id') is not None else row.get('image_path')],
            self)
        progress = QProgressDialog("Exporting carved files...", "Cancel", 0,
                                   len(rows), self)
        progress.setWindowTitle("Export")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(PROGRESS_MIN_DURATION)
        progress.canceled.connect(worker.stop)
        worker.progressed.connect(progress.setValue)
        worker.exported.connect(
            lambda results: self._carved_export_done(results, folder,
                                                     progress))
        self._retain_worker(worker)
        worker.start()
        return worker

    def _carved_export_done(self, results, folder, progress):
        progress.close()
        progress.deleteLater()
        if self.case is not None:
            self.case.record_carved_export(results, folder)
            self.carved_panel.refresh()
        written = [r for r in results if r['path']]
        mismatched = [r for r in written if not r['verified']]
        failed = [r for r in results if not r['path']]
        self.set_status(f"{len(written):,} carved file(s) exported to "
                        f"{folder}", 8000)
        if mismatched or failed:
            lines = [f"{r['row'].get('name')}: does not match the SHA-256 "
                     f"recorded when it was carved" for r in mismatched]
            lines += [f"{r['row'].get('name')}: {r['error']}"
                      for r in failed]
            message.warning(
                self, "Export",
                f"{len(written):,} of {len(results):,} file(s) exported; "
                f"some need attention. manifest.csv lists every file.",
                '\n'.join(lines[:30]))

    def _read_carved(self, row):
        """A carved file's bytes, read back from its image at its offset --
        or from each of its fragments, if it was rebuilt from them.

        Not the copy written to disk: what is examined is the evidence, and
        the copy could have been changed since. None if it cannot be read.
        """
        if row.get('evidence_id') is not None and self.case is not None:
            if not self.activate_evidence(row['evidence_id']):
                return None
        elif row.get('image_path'):
            if not self.activate_image(row['image_path']):
                return None
        if not self.image_handler:
            return None
        offset, size = int(row.get('offset') or 0), int(row.get('size') or 0)
        fragments = row.get('fragments')
        if fragments is None and self.case is not None and \
                row.get('evidence_id') is not None:
            # From a bookmark or a finding: the reference is the span, and
            # the pieces are recorded with the carve.
            fragments = self.case.carved_fragments(row['evidence_id'], offset)
        try:
            content = read_carved(self.image_handler.read, offset, size,
                                  fragments)
        except Exception as exc:
            logger.error("Could not read carved data at %d: %s", offset, exc)
            content = None
        if not content:
            self.set_status(f"Could not read {row.get('name')} from the image.",
                            5000)
            return None
        return content

    def open_carved(self, row):
        """Double-click on a carved file: browse an archive, show the rest."""
        if (row.get('type') or '').lower() not in CARVED_ARCHIVE_TYPES or \
                not self.browse_carved_archive(row):
            self.preview_carved(row)

    def browse_carved_archive(self, row):
        """List a carved archive in the Listing, as a folder.

        Through the same in-memory browser an archive on the file system
        uses: members open in the viewers, nested archives are stepped into,
        nothing is extracted to disk. Up from the top level returns to the
        Carved files tab, which is where this archive lives. Returns True
        when it was an archive and was listed.
        """
        if (row.get('type') or '').lower() not in (
                CARVED_ARCHIVE_TYPES | CARVED_BROWSABLE_DOCUMENTS):
            return False
        content = self._read_carved(row)
        if not content or not archives.detect_archive(content):
            return False
        name = row.get('name') or 'carved archive'
        label = row.get('evidence_label') or ''
        source = {
            'name': name,
            'path': f"Carved/{label}/{name}" if label else f"Carved/{name}",
            'start_offset': 0,
            'is_carved_archive': True,
        }
        self._archive_stack = [(name, content, source)]
        return self.show_archive_level()

    def preview_carved(self, row):
        """Show a carved file in the viewers, read back from the image."""
        offset, size = int(row.get('offset') or 0), int(row.get('size') or 0)
        key = f"carved:{row.get('evidence_key', row.get('evidence_id'))}:{offset}"
        if (self.current_selected_data or {}).get('_preview_ref') == key:
            return
        content = self._read_carved(row)
        if not content:
            return
        name = row.get('name') or f"{offset:x}"
        data = {
            'name': name,
            'size': size,
            'type': row.get('type') or (name.rsplit('.', 1)[-1]
                                        if '.' in name else ''),
            'offset': offset,
            'fragments': row.get('fragments') or None,
            'is_carved': True,
            'source': 'carved_file',
            'file_content': content,
            'carved_timestamp': row.get('embedded_date'),
            'carved_timestamp_source': row.get('date_source') or '',
            '_preview_ref': key,
        }
        self.clear_viewers()
        self.current_selected_data = data
        if self.active_viewer_adapter() is None:
            self.viewer_tab.setCurrentWidget(self.viewer_adapters[0].widget)
        self.update_viewer_with_file_content(content, data)
        self.viewer_dock.show()
        self.set_status(f"{name}: carved from byte {offset:,}")

    def open_search_result_menu(self, row, position):
        """The context menu for a search result.

        A result names the same artifact a listing row does, so it gets the
        same actions -- there is no reason bookmarking should depend on which
        table the examiner found the file in.
        """
        if not self.activate_evidence(row.get('evidence_id')):
            return
        parsed = parse_artifact_ref(row.get('artifact_ref'))
        data = {
            'name': row.get('name') or '',
            'path': row.get('path') or '',
            'type': 'file',
            'inode_number': parsed.get('inode'),
            'start_offset': parsed.get('start_offset'),
            'sequence': parsed.get('sequence'),
        }

        menu = QMenu(self)
        open_action = menu.addAction("Show in Listing")
        menu.addSeparator()
        self.add_bookmark_action(menu, data)
        if parsed.get('kind') == 'file':
            self.add_virustotal_menu(menu, [data])

        chosen = show_menu(menu, position)
        if chosen == open_action:
            self.open_search_result(row)

    def open_search_result(self, row):
        """Open whatever a search result points at.

        Results carry the same artifact reference bookmarks use, so this goes
        through the one resolver rather than the old show_file_in_directory,
        which hardcoded parent_inode = 5 and landed every deep file at the
        volume root.
        """
        kind = row.get('kind')
        if kind == 'archive-member':
            message.information(
                self, "Inside an archive",
                f"{row.get('name')} was found inside "
                f"{(row.get('path') or '').split('!/')[0]}.\n\n"
                f"Open that archive and use the Archive tab to read it.")
            return

        self.go_to_bookmark({
            'artifact_ref': row.get('artifact_ref'),
            'evidence_id': row.get('evidence_id'),
            'artifact_name': row.get('name'),
            'artifact_path': row.get('path'),
            'label': row.get('name'),
        })

    # --- archives as folders ---------------------------------------------

    def open_archive_if_archive(self, data):
        """If `data` names an archive, list it like a directory.

        Returns True when it did, so the caller can stop. Reading the bytes is
        the expensive part and happens once here; navigating inside the
        archive afterwards is all in memory.
        """
        loaded = self._load_archive(data)
        if loaded is None:
            return False
        self._archive_stack = [loaded]
        return self.show_archive_level()

    def _load_archive(self, data):
        """(name, content, source) when the file `data` names is an archive
        -- content being bytes, or a stream for a mailbox -- else None.
        Nothing on screen changes but the status bar."""
        inode = data.get('inode_number')
        offset = data.get('start_offset')
        if inode is None or offset is None:
            return None

        name = data.get('name') or ''
        size = data.get('size') or 0
        if isinstance(size, str):
            size = 0

        # A mailbox is browsed from the image as it is read, not from
        # memory: a PST, an OST or an mbox (Thunderbird's have no extension)
        # is routinely far bigger than any archive.
        if name.lower().endswith(('.pst', '.ost', '.mbox')) or \
                (size and size > archives.MAX_MEMBER_BYTES):
            stream = self.image_handler.open_file_object(inode, offset)
            if stream is not None and \
                    archives.detect_archive(stream) in archives.STREAMED_KINDS:
                self.set_status(f"Opening the mailbox {name}…")
                return (name, stream, dict(data))

        # Reading a large file to find out it is not an archive is wasted
        # work; the extension and a header read settle it far more cheaply.
        if size and size > archives.MAX_MEMBER_BYTES:
            return None

        try:
            header = self.image_handler.read_file_bytes(inode, offset, 512) \
                if hasattr(self.image_handler, 'read_file_bytes') else None
        except Exception:
            header = None

        # A Thumbs.db is an OLE file like a Word document; its streams, not
        # its first bytes, say what it is -- so its name earns it a read.
        if header is not None and not archives.detect_archive(header) and \
                not thumbnails.is_cache_name(name) and \
                not rdpcache.is_rdp_cache_name(name):
            return None

        self.set_status(f"Opening {name}…")
        try:
            content, _meta = self.image_handler.get_file_content(inode, offset)
        except Exception as exc:
            logger.debug("Could not read %s: %s", name, exc)
            self.clear_status()
            return None

        if not content or not archives.detect_archive(content):
            self.clear_status()
            return None
        return (name, content, dict(data))

    # --- archives in the tree -----------------------------------------------

    def _tree_archive_root(self, item):
        """The tree item of the archive file (on the evidence) that `item`
        is, or lies inside."""
        while item is not None:
            data = item.data(0, Qt.UserRole) or {}
            if data.get('type') != 'archive-member':
                return item
            item = item.parent()
        return None

    def _tree_archive_stack(self, item):
        """The archive stack (outermost first) for a tree item that is an
        archive file or a member inside one -- read again from the image
        when it is not among the last few read."""
        root_item = self._tree_archive_root(item)
        if root_item is None:
            return None
        root_data = root_item.data(0, Qt.UserRole) or {}
        key = (self.current_image_path, root_data.get('start_offset'),
               root_data.get('inode_number'))
        cached = self._tree_archives.pop(key, None)
        if cached is None:
            cached = self._load_archive(root_data)
            if cached is None:
                return None
            # The path the tree knows, for the archive trail.
            cached[2].setdefault('path', self._tree_item_path(root_item))
        self._tree_archives[key] = cached
        while len(self._tree_archives) > TREE_ARCHIVES_KEPT:
            self._tree_archives.pop(next(iter(self._tree_archives)))
        stack = [cached]
        data = item.data(0, Qt.UserRole) or {}
        for member in data.get('archive_chain') or ():
            content = archives.read_member(stack[-1][1], member)
            stack.append((member, content, cached[2]))
        return stack

    def _tree_item_path(self, item):
        parts = []
        while item is not None and item.parent() is not None:
            data = item.data(0, Qt.UserRole) or {}
            if data.get('name'):
                parts.append(data['name'])
            item = item.parent()
        return '/' + '/'.join(reversed(parts))

    def _fill_archive_tree(self, item, members, chain):
        """The members of the archive `item` is, as tree children: folders
        from the members' paths, archives inside expandable in turn."""
        item.takeChildren()
        start_offset = (item.data(0, Qt.UserRole) or {}).get('start_offset')
        folders = {'': item}

        def folder(path):
            if path in folders:
                return folders[path]
            parent_path, _sep, leaf = path.rpartition('/')
            node = QTreeWidgetItem(folder(parent_path))
            node.setText(0, leaf)
            node.setIcon(0, QIcon(self.db_manager.get_icon_path('folder',
                                                                'folder')))
            node.setData(0, Qt.UserRole, {
                'type': 'archive-member', 'name': leaf, 'is_directory': True,
                'archive_member': path, 'archive_chain': list(chain),
                'start_offset': start_offset})
            folders[path] = node
            return node

        for member in sorted(members, key=lambda m: m['name'].lower()):
            path = member['name'].strip('/')
            if not path:
                continue
            if member['is_dir']:
                folder(path)
                continue
            parent_path, _sep, leaf = path.rpartition('/')
            node = QTreeWidgetItem(folder(parent_path))
            node.setText(0, leaf)
            extension = leaf.rsplit('.', 1)[-1].lower() if '.' in leaf \
                else 'unknown'
            node.setIcon(0, self._get_file_icon(extension))
            node.setData(0, Qt.UserRole, {
                'type': 'archive-member', 'name': leaf,
                'is_directory': False, 'size': member['size'],
                'archive_member': member['name'],
                'archive_encrypted': member['encrypted'],
                'archive_chain': list(chain),
                'start_offset': start_offset})
            if leaf.lower().endswith(TREE_ARCHIVE_SUFFIXES):
                node.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        if not members:
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.DontShowIndicatorWhenChildless)

    def _expand_archive_item(self, item):
        """Fill an archive's node (the file on the image, or an archive
        inside one) with its members. False when it is not one."""
        data = item.data(0, Qt.UserRole) or {}
        try:
            stack = self._tree_archive_stack(item)
            if stack is None:
                item.setChildIndicatorPolicy(
                    QTreeWidgetItem.DontShowIndicatorWhenChildless)
                return False
            chain = list(data.get('archive_chain') or ())
            content = stack[-1][1]
            if data.get('type') == 'archive-member':
                content = archives.read_member(content,
                                               data['archive_member'])
                if not archives.detect_archive(content):
                    item.setChildIndicatorPolicy(
                        QTreeWidgetItem.DontShowIndicatorWhenChildless)
                    return False
                chain.append(data['archive_member'])
            self._fill_archive_tree(item, archives.list_members(content),
                                    chain)
            return True
        except archives.ArchiveError as exc:
            # Encrypted or damaged: a click says why; the tree just does not
            # grow.
            logger.debug("Archive %s not listed: %s", data.get('name'), exc)
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.DontShowIndicatorWhenChildless)
            return False
        finally:
            self.clear_status()

    def on_tree_archive_clicked(self, item):
        """A click on an archive, or on something inside one, in the tree:
        the Listing shows its contents (as a double-click there does) and
        the tree shows them beneath it. False when it is no archive."""
        data = item.data(0, Qt.UserRole) or {}
        try:
            stack = self._tree_archive_stack(item)
        except archives.ArchiveError as exc:
            message.warning(self, "Could not read the archive", str(exc))
            return True
        if stack is None:
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.DontShowIndicatorWhenChildless)
            return False
        self._archive_stack = stack
        if data.get('type') != 'archive-member':
            if self.show_archive_level():
                if item.childCount() == 0:
                    self._expand_archive_item(item)
                item.setExpanded(True)
            # The viewers show the archive file itself, as for any file.
            content = stack[0][1]
            if isinstance(content, (bytes, bytearray)):
                self.update_viewer_with_file_content(bytes(content), data)
            return True
        if data.get('is_directory'):
            self._show_archive_folder(data['archive_member'])
            return True
        self.open_archive_member_row(dict(data), navigate=True)
        if self._archive_stack and \
                self._archive_stack[-1][0] == data['archive_member']:
            # An archive inside the archive: stepped into; grow the tree.
            if item.childCount() == 0:
                self._expand_archive_item(item)
            item.setExpanded(True)
        return True

    def _show_archive_folder(self, folder):
        """The members directly inside `folder` of the archive on top of
        the stack, in the Listing."""
        _name, content, source = self._archive_stack[-1]
        try:
            members = archives.list_members(content)
        except archives.ArchiveError as exc:
            message.warning(self, "Could not read the archive", str(exc))
            return
        prefix = folder.strip('/') + '/'
        inside = [member for member in members
                  if member['name'].strip('/').startswith(prefix)
                  and '/' not in member['name'].strip('/')[len(prefix):]]
        entries = self._archive_entries(inside, source)
        for entry in entries:
            entry['name'] = entry['name'].strip('/').rsplit('/', 1)[-1]
        self.current_path = f"{self.archive_trail()}/{folder}"
        self.update_directory_up_button()
        if self.show_listing_entries(entries, source.get('start_offset', 0),
                                     folder):
            self.set_status(f"{self.current_path} — {len(entries)} item(s)")

    def show_archive_level(self):
        """List the archive on top of the stack in the listing table."""
        if not self._archive_stack:
            return False

        name, content, source = self._archive_stack[-1]
        try:
            members = archives.list_members(content)
        except archives.EncryptedArchive as exc:
            message.information(
                self, "Encrypted archive",
                f"{name} is encrypted.\n\n{exc}\n\n"
                "Its presence and size are still evidence; its contents "
                "cannot be listed without the password.")
            self._archive_stack.pop()
            self.clear_status()
            return False
        except archives.ArchiveError as exc:
            message.warning(self, "Could not read the archive",
                            f"{name} could not be read.\n\n{exc}")
            self._archive_stack.pop()
            self.clear_status()
            return False

        entries = self._archive_entries(members, source)
        self.current_path = self.archive_trail()
        self.update_directory_up_button()

        if not self.show_listing_entries(entries, source.get('start_offset', 0),
                                         name):
            self._archive_stack.pop()
            return False

        self.set_status(f"{self.archive_trail()} — {len(entries)} item(s)")
        return True

    def _archive_entries(self, members, source):
        """Turn archive members into listing rows.

        Members are given the same shape get_directory_contents produces, so
        the listing draws them with the same icons and columns as any other
        file. Nothing in the table builder needs to know an archive exists.
        """
        entries = []
        for member in members:
            entries.append({
                'name': member['name'],
                'is_directory': member['is_dir'],
                # A member has no inode of its own: it exists only inside the
                # archive. The name is what identifies it, and the type below
                # is what routes a click.
                'inode_number': None,
                'size': member['size'],
                'accessed': 'N/A',
                'modified': member['modified'] or 'N/A',
                'created': 'N/A',
                'changed': 'N/A',
                'is_deleted': False,
                'is_recoverable': not member['encrypted'],
                'parent_inode': None,
                'sequence': None,
                'attributes': 'encrypted' if member['encrypted'] else '',
                # Routes the click, and marks the row as living in an archive.
                'type': 'archive-member',
                'archive_member': member['name'],
                'archive_encrypted': member['encrypted'],
                'start_offset': source.get('start_offset', 0),
            })
        return entries

    def open_archive_member_row(self, data, navigate=True):
        """Open a member: descend if it is an archive, otherwise view it."""
        if not self._archive_stack:
            return

        _name, content, source = self._archive_stack[-1]
        member_name = data.get('archive_member') or data.get('name')

        if data.get('is_directory'):
            # Archive directories are prefixes rather than real entries; the
            # flat listing already shows their contents by full name.
            return

        if data.get('archive_encrypted'):
            message.information(
                self, "Encrypted member",
                f"{member_name} is encrypted. Its name and size are readable; "
                f"its contents are not.")
            return

        try:
            member_bytes = archives.read_member(content, member_name)
        except archives.ArchiveError as exc:
            message.warning(self, "Could not read member", str(exc))
            return

        # An archive inside an archive is another folder to step into.
        if navigate and archives.detect_archive(member_bytes):
            if len(self._archive_stack) >= archives.MAX_NESTING:
                message.warning(
                    self, "Too deeply nested",
                    f"Archives are followed {archives.MAX_NESTING} levels "
                    f"deep.")
                return
            self._archive_stack.append((member_name, member_bytes, source))
            self.show_archive_level()
            return

        # Otherwise it is a file, and every viewer can show it.
        view_data = dict(data)
        view_data['size'] = len(member_bytes)
        view_data['path'] = f"{self.archive_trail()}/{member_name}"
        self.current_selected_data = view_data
        self.update_viewer_with_file_content(member_bytes, view_data)
        self.update_status_for_selection(view_data)

    def archive_trail(self):
        """Where we are, as a path an examiner can quote."""
        if not self._archive_stack:
            return self.current_path
        base = self._archive_stack[0][2].get('path') or self._archive_stack[0][0]
        parts = [base] + [name for name, _c, _s in self._archive_stack[1:]]
        return '!/'.join(parts)

    def leave_archive(self):
        """Step out one archive level, or back to the filesystem.

        Returns True when it handled the request, so Up can defer to it.
        """
        if not self._archive_stack:
            return False

        base = self._archive_stack[0][2]
        self._archive_stack.pop()
        if self._archive_stack:
            self.show_archive_level()
            return True

        if base.get('is_carved_archive'):
            # A carved archive has no folder on the volume; it came from the
            # Carved files tab, so that is where Up goes.
            self.current_path = '/'
            self.update_directory_up_button()
            self.show_triage('carved')
            return True

        # Back to the filesystem, in the directory the archive was in.
        self.current_path = os.path.dirname(self.current_path.split('!/')[0]) or '/'
        parent = self.current_selected_data or {}
        offset = parent.get('start_offset', self.current_offset or 0)
        try:
            inode = self.image_handler.get_root_inode(offset)
            entries = self.image_handler.get_directory_contents(offset, inode)
            self.show_listing_entries(entries, offset, 'This volume')
        except Exception as exc:
            logger.debug("Could not return to the filesystem: %s", exc)
        self.update_directory_up_button()
        return True

    def annotate_with_case_identity(self, data):
        """Add the case's view of an artifact to a selection payload.

        The viewers receive whatever the listing or tree built; notes and
        bookmarks additionally need to know which evidence row it belongs to
        and what its durable reference is. Computing it here keeps that
        knowledge out of every individual viewer.
        """
        if not data or not self.case:
            return data
        ref = self.artifact_ref_for(data)
        if ref:
            data = dict(data)
            data['artifact_ref'] = ref
            data['evidence_id'] = self.evidence_id_for_current_image()
        return data

    def add_bookmark_action(self, menu, data, refresh=None):
        """Put Add or Remove Bookmark into `menu` for whatever `data` names.

        One method rather than an entry hand-written per menu: bookmarking was
        only reachable from the listing and the tree because each menu had its
        own copy, and a table added later simply had neither.

        `refresh` is called after the change, for a view that has to redraw
        itself rather than being redrawn by refresh_bookmarks.
        """
        if not self.case:
            action = menu.addAction("Add Bookmark")
            action.setEnabled(False)
            action.setToolTip("Bookmarks are kept in a case.")
            return

        ref = self.artifact_ref_for(data)
        if ref is None:
            return

        existing = self.case.bookmark_for_artifact(
            self.evidence_id_for_current_image(), ref)

        if existing:
            action = menu.addAction("Remove Bookmark")
            action.triggered.connect(
                lambda: self._remove_bookmark_and_refresh(existing, refresh))
        else:
            action = menu.addAction("Add Bookmark")
            action.triggered.connect(
                lambda: self._add_bookmark_and_refresh(data, refresh))
        return action

    def _add_bookmark_and_refresh(self, data, refresh=None):
        self.add_bookmark_for(data)
        if refresh:
            refresh()

    def _remove_bookmark_and_refresh(self, row, refresh=None):
        self.case.remove_bookmark(row['id'])
        self.refresh_bookmarks()
        self.set_status(f"Removed bookmark {row.get('label') or ''}".strip())
        if refresh:
            refresh()

    def add_bookmark_for(self, data, suggested_label=None):
        """Bookmark the artifact `data` describes."""
        if not self.case:
            message.information(
                self, "No case is open",
                "Bookmarks are kept in a case. Start one from File ▸ New Case "
                "to keep findings between sessions.")
            return

        ref = self.artifact_ref_for(data)
        if ref is None:
            message.warning(self, "Cannot bookmark this",
                            "This item does not have a stable location to "
                            "record.")
            return

        default = suggested_label or data.get('name') or 'Bookmark'
        label, ok = QInputDialog.getText(
            self, "Add bookmark", "Label:", text=default)
        if not ok or not label.strip():
            return

        self.case.add_bookmark(
            self.evidence_id_for_current_image(), ref, label.strip(),
            artifact_name=data.get('name') or '',
            artifact_path=data.get('path') or '')
        self.refresh_bookmarks()
        self.set_status(f"Bookmarked {label.strip()}")

    def mark_bookmarked_tree_items(self, parent=None, evidence_id=None):
        """Show which files in the tree carry a bookmark.

        Walks only what has been expanded: an unexpanded node has no visible
        children to mark, and populating the whole tree to draw an icon would
        read every directory in the image.
        """
        if not hasattr(self, 'tree_viewer'):
            return

        if parent is None:
            for index in range(self.tree_viewer.topLevelItemCount()):
                item = self.tree_viewer.topLevelItem(index)
                data = item.data(0, Qt.UserRole) or {}
                if data.get('is_bookmarks_root'):
                    continue        # the Bookmarks node is not itself a file
                self.mark_bookmarked_tree_items(
                    item, self.evidence_id_for_path(self.image_of_item(item)))
            return

        for index in range(parent.childCount()):
            child = parent.child(index)
            data = child.data(0, Qt.UserRole) or {}
            inode = data.get('inode_number')
            if inode is not None:
                ref = make_artifact_ref(data.get('start_offset', 0), inode,
                                        data.get('sequence'))
                bookmarked = (evidence_id, ref) in self._bookmarked_refs
                font = child.font(0)
                font.setBold(bookmarked)
                child.setFont(0, font)
                child.setToolTip(
                    0, "Bookmarked in this case." if bookmarked else "")
            if child.isExpanded():
                self.mark_bookmarked_tree_items(child, evidence_id)

    # --- analysis modules -------------------------------------------

    def offer_analysis_modules(self):
        """Ask what to analyse, when a case has just been opened.

        Separate from run_analysis_modules because the two have different
        manners. This one is an offer made without being asked, so it stays
        quiet when there is nothing to offer -- no case, no evidence, or a
        run whose findings are already recorded. The menu entry always asks,
        because there the examiner went looking for it.
        """
        if not self.case:
            return

        rows = self.case.evidence()
        if not rows:
            # A new case with no evidence yet: the offer belongs at the point
            # an image is added, not here.
            return

        # Already analysed: re-offering on every reopen would train an
        # examiner to dismiss the dialog without reading it.
        if any((self.case.analysis_state(row['id']) or {}).get('status')
               == 'done' for row in rows):
            self.refresh_analysis_views()
            return

        self._ask_and_queue(rows)

    def run_analysis_modules(self, evidence_id=None):
        """Ask which modules to run, then queue a run per piece of evidence.

        `evidence_id` is the image the dialog starts on; None offers them all.
        """
        if not self.case:
            message.warning(
                self, "No case open",
                "Analysis findings are kept in a case.",
                "File \u25b8 New Case starts one.")
            return

        rows = self.case.evidence()
        if not rows:
            message.warning(
                self, "No evidence",
                "There is nothing to analyse yet.",
                "Add an image to the case first.")
            return

        self._ask_and_queue(rows, evidence_id)

    def _rule_libraries(self):
        """The rule and hash-set libraries this window has loaded, for
        working out which modules can run."""
        return {'hash': self.hash_library(), 'yara': self.yara_library(),
                'sigma': self.sigma_library(),
                'keyword': self.keyword_library()}

    def _module_preselection(self, evidence_id=None):
        """What the modules dialog starts with: last time's modules (the
        evidence is not carried over -- an image left over from the last
        run is how a run reaches the wrong ones), and which modules this
        case can run."""
        from trace_app.ui.dialogs.analysis_modules import (
            MODULE_HASHSETS, MODULE_KEYWORDS, MODULE_SIGMA, MODULE_YARA,
            availability)
        preselected = dict(self._last_choice,
                           evidence_ids=None if evidence_id is None
                           else [evidence_id])
        unavailable, in_use = availability(self.case,
                                           self._rule_libraries())
        preselected['unavailable'] = unavailable
        # Rule-driven modules follow the case's own options, not the last
        # run: ticked when their sets are in use.
        for key in (MODULE_HASHSETS, MODULE_YARA, MODULE_SIGMA,
                    MODULE_KEYWORDS):
            preselected[key] = key in in_use
        return preselected

    def _ask_and_queue(self, rows, evidence_id=None):
        """Ask what to run, and against which evidence; queue the jobs.

        Every file module the first time: an examiner opening this dialog
        has asked to analyse the image, and unticking what they do not want
        is less work than finding what they do. "Just browse" is an answer,
        not a failure.
        """
        evidence = []
        for row in rows:
            found = self.evidence_profile(row)
            evidence.append((row['id'], row.get('display_name')
                             or os.path.basename(row['path']),
                             found['summary'] if found else '',
                             self._not_applicable(found)))
        choice = choose_modules(self,
                                preselected=self._module_preselection(
                                    evidence_id),
                                evidence=evidence)
        if not choice:
            return
        chosen = [row for row in rows if choice['evidence_ids'] is None
                  or row['id'] in choice['evidence_ids']]
        self.queue_choice(chosen, choice)

    def evidence_profile(self, row):
        """What an image holds (core/evidence_profile), worked out once per
        image from the handler already open; None if it cannot be read."""
        from trace_app.core import evidence_profile
        key = os.path.normpath(row['path'])
        if self._evidence_profiles.get(key) is None:
            found = None
            try:
                # Only an image already open: a profile never opens one.
                handler = self._image_handlers.get(key)
                if handler is not None and handler.loaded:
                    found = evidence_profile.profile(handler)
            except Exception as exc:
                logger.warning("Could not profile %s: %s", row['path'], exc)
            # Not kept when None: the image may simply not be open yet.
            if found is not None:
                self._evidence_profiles[key] = found
            return found
        return self._evidence_profiles[key]

    @staticmethod
    def _not_applicable(found):
        from trace_app.core import evidence_profile
        return evidence_profile.not_applicable(found) if found else {}

    def _applicable_choice(self, row, choice):
        """`choice` without the modules that cannot find anything in this
        image, and what was dropped: {key: why}."""
        from trace_app.ui.dialogs.analysis_modules import MODULE_CARVE
        dropped = self._not_applicable(self.evidence_profile(row))
        out = dict(choice)
        skipped = {}
        for key, why in dropped.items():
            if key == MODULE_CARVE:
                if out.get('carve_types'):
                    out['carve_types'] = []
                    skipped[key] = why
            elif out.get(key):
                out[key] = False
                skipped[key] = why
        return out, skipped

    def queue_choice(self, chosen, choice):
        """Queue what a modules choice selects, over the `chosen` evidence
        rows -- each image its own choice when the dialog gave one
        (`per_evidence`), and only what can find anything in it: the NTFS
        job is not queued for a Btrfs disk."""
        self._last_choice = {k: v for k, v in choice.items()
                             if k != 'per_evidence'}
        per = choice.get('per_evidence') or {}
        groups, skipped_names = [], []
        for row in chosen:
            mine, skipped = self._applicable_choice(
                row, per.get(row['id'], choice))
            name = row.get('display_name') or os.path.basename(row['path'])
            for key, why in skipped.items():
                logger.info("Not running %s on %s: %s", key, name, why)
            if skipped:
                skipped_names.append(name)
            for rows, group_choice in groups:
                if group_choice == mine:
                    rows.append(row)
                    break
            else:
                groups.append(([row], mine))
        for rows, group_choice in groups:
            self._queue_one_choice(rows, group_choice)
        if skipped_names:
            self.set_status(
                f"Modules that cannot find anything there were left out on "
                f"{', '.join(skipped_names)} (see the log)")

    def _queue_one_choice(self, chosen, choice):
        """Queue one choice over rows, in the order the jobs depend on
        each other."""
        if choice['modules']:
            self.queue_analysis(chosen, choice['modules'])
        if choice.get('index'):
            self.queue_indexing(chosen)
        if choice.get('activity'):
            self.queue_activity(chosen)
        if choice.get('ntfs'):
            self.queue_ntfs(chosen)
        if choice.get('fstimes'):
            self.queue_fs_times(chosen)
        if choice.get('hashsets'):
            # Queued after the analysis jobs, so it reads their hashes.
            self.queue_hash_matching([row['id'] for row in chosen])
        if choice.get('persistence'):
            # After hash matching, so the hash-set facts are current.
            self.queue_persistence(chosen)
        if choice.get('thumbnails'):
            self.queue_thumbnails(chosen)
        if choice.get('deleted'):
            self.queue_deleted(chosen)
        if choice.get('yara'):
            self.queue_yara(chosen)
        if choice.get('sigma'):
            self.queue_sigma(chosen)
        if choice.get('keywords'):
            # After indexing, which it reads.
            self.queue_keywords([row['id'] for row in chosen])
        if choice['carve_types']:
            self.start_carving([row['id'] for row in chosen],
                               choice['carve_types'],
                               choice['unallocated_only'])

    # --- case setup (the wizards) -------------------------------------------

    def start_case_setup(self, setup):
        """What the New Case wizard asked for, once the case's evidence is
        open: verification first, then the modules."""
        if not self.case or not setup:
            return
        if getattr(self, '_loading_case_evidence', False):
            # Still opening the evidence: run when that is done.
            self._pending_setup = setup
            return
        rows = [row for row in self.case.evidence()
                if row['path'] in self._image_handlers]
        if rows:
            self.queue_setup(rows, setup)

    def queue_setup(self, rows, setup):
        """Queue a wizard's verification and modules over `rows`, in the
        order Settings ▸ General asks: hashing alongside the analysis (its
        own lane), after it, or before it."""
        order = case_settings.user('verify_order')
        verify = bool(setup.get('verify'))
        if verify and order != 'after analysis':
            self.queue_verification(rows)
        if setup.get('choice'):
            self.queue_choice(rows, setup['choice'])
            self.set_status(f"Queued analysis of {len(rows)} piece(s) of "
                            f"evidence")
        if verify and order == 'after analysis':
            self.queue_verification(rows)

    # --- verification jobs ------------------------------------------------

    def queue_verification(self, rows, summary=False):
        """Hash (or re-check) each piece of evidence as a job on the bar.

        Evidence never hashed is hashed and compared with the hashes it
        stores (core/case.hash_verdict); evidence with a recorded hash is
        checked against it. With `summary`, the outcome of the whole batch
        is reported once it ends -- Case > Verify All Evidence.
        """
        from trace_app.ui.dialogs.verification import EvidenceVerifyWorker
        from trace_app.ui.widgets.job_bar import MAIN, SIDE
        if not self.case:
            return 0
        # Beside the analysis queue unless Settings ▸ General says otherwise:
        # hashing a large image held up every finding behind it.
        lane = SIDE if case_settings.user('verify_order') == \
            'alongside analysis' else MAIN
        batch = {'pending': 0, 'outcomes': [], 'summary': summary}
        queued = 0
        for row in rows:
            evidence_id = row['id']
            name = row.get('display_name') or os.path.basename(row['path'])

            def start(job, row=row, name=name):
                current = next((r for r in self.case.evidence()
                                if r['id'] == row['id']), row)
                worker = EvidenceVerifyWorker(current, self)
                worker.progressed.connect(
                    lambda done, total, job=job: self.job_bar.report(
                        int(done * 1000 / total) if total else 0, 1000,
                        f"{self._readable(done)} of "
                        f"{self._readable(total)}", job=job))
                worker.verified.connect(
                    lambda out, name=name, job=job:
                    self._verification_finished(out, name, batch, job))
                self._retain_worker(worker)
                worker.start()
                return worker

            title = (f"Verifying {name}" if row.get('md5') or row.get('sha1')
                     or row.get('sha256') else f"Hashing {name}")
            if self.job_bar.submit(Job(key=f"verify:{evidence_id}",
                                       title=title, start=start,
                                       stop=lambda worker: worker.stop()),
                                   lane=lane):
                queued += 1
                batch['pending'] += 1
        if summary and not queued:
            message.information(self, "Verification",
                                "Every piece of evidence is already being "
                                "verified.")
        return queued

    def _readable(self, size):
        from trace_app.infra.utils import FileSystemUtils
        return FileSystemUtils.get_readable_size(size)

    def _verification_finished(self, out, name, batch, job=None):
        """Record what a verification job found (on this thread, which owns
        the case's database), badge the image, move its lane on."""
        from trace_app.core.case import (STATUS_MISSING, STATUS_UNHASHED,
                                         STATUS_VERIFIED, hash_verdict)
        self.job_bar.job_finished(job)
        batch['pending'] -= 1
        row = out['row']
        status, detail = None, ''
        if out.get('cancelled'):
            self.set_status(f"Verification of {name} cancelled; nothing "
                            f"recorded")
        elif out.get('error'):
            status, detail = STATUS_MISSING if not os.path.exists(
                row['path']) else STATUS_UNHASHED, out['error']
            self.case.record_check(row['id'], {'status': status,
                                               'detail': detail})
        elif out.get('mode') == 'hash':
            results = out.get('results') or {}
            status, detail = hash_verdict(results)
            if status == STATUS_UNHASHED:
                self.case.record_check(row['id'], {'status': status,
                                                   'detail': detail})
            else:
                self.case.record_hashes(row['id'], results, status, detail)
                self.verification_results[row['path']] = {
                    'html': None, 'verified': status == STATUS_VERIFIED,
                    'hashes': dict(results, path=row['path'])}
        else:
            outcome = out.get('outcome') or {}
            status, detail = outcome.get('status'), outcome.get('detail', '')
            self.case.record_check(row['id'], outcome)
            if status == STATUS_VERIFIED and row['path'] in \
                    self.verification_results:
                self.verification_results[row['path']]['verified'] = True

        if status is not None:
            batch['outcomes'].append((row, status, detail))
            if row['path'] in self._image_handlers:
                self.mark_image_verified(row['path'],
                                         status == STATUS_VERIFIED)
            self.set_status(f"{name}: {detail}")
            logger.info("Verification of %s: %s (%s)", name, status, detail)
        if getattr(self, 'case_panel', None):
            self.case_panel.refresh()
        if batch['pending'] == 0:
            self._verification_batch_done(batch)

    def _verification_batch_done(self, batch):
        from trace_app.core.case import STATUS_CHANGED, STATUS_MISSING
        trouble = [(row, status, detail) for row, status, detail
                   in batch['outcomes']
                   if status in (STATUS_MISSING, STATUS_CHANGED)]
        if trouble:
            # Loudly, whether asked for or not: evidence that is not what
            # it was is the one result an examiner must not miss.
            lines = [f"{row.get('display_name') or row['path']}: {detail}"
                     for row, _status, detail in trouble]
            message.warning(
                self, "Evidence does not match",
                "Some evidence is not as it was recorded.",
                "\n\n".join(lines))
        elif batch['summary'] and batch['outcomes']:
            message.information(
                self, "Evidence verified",
                f"All {len(batch['outcomes'])} piece(s) of evidence match "
                f"what was recorded, or now have a recorded baseline.")

    def queue_analysis(self, rows, modules):
        """Put one analysis job per piece of evidence on the shared queue."""
        queued = 0
        for row in rows:
            path = row['path']
            if not os.path.exists(path):
                logger.warning("Skipping analysis of missing %s", path)
                continue
            if self._queue_analysis_job(row, modules):
                queued += 1

        if queued:
            self.set_status(
                f"Analysing {queued} piece(s) of evidence in the background")
        return queued

    def _queue_analysis_job(self, row, modules):
        """One evidence row, one job."""
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = AnalysisWorker(row['path'], self.case.folder,
                                    evidence_id, modules, self)
            worker.params['unlock'] = self._unlocks_for(row['path'])
            worker.progressed.connect(
                lambda done, total, path: self.job_bar.report(
                    done, total, os.path.basename(path)))
            worker.finished_analysis.connect(
                lambda count, error: self._analysis_finished(count, error))
            # Retained the same way every other worker is: assigning over a
            # running thread drops the last reference to it and the C++ object
            # can be collected mid-read.
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"analysis:{evidence_id}",
            title=f"Analysing {name}",
            start=start,
            stop=lambda worker: worker.stop()))

    def _analysis_finished(self, count, error):
        """One analysis job has ended, however it ended."""
        if error:
            self.set_status(f"Analysis failed: {error}")
            logger.error("Analysis failed: %s", error)
        else:
            self.set_status(f"Analysed {count:,} file(s)")

        self.job_bar.job_finished()
        self.refresh_analysis_views()

    def queue_indexing(self, rows):
        """Put one indexing job per piece of evidence on the shared queue:
        the search index and the indicators extracted with it."""
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                logger.warning("Skipping indexing of missing %s", row['path'])
                continue
            if self._queue_indexing_job(row):
                queued += 1
        if queued:
            self.set_status(f"Indexing {queued} image(s) in the background")
        return queued

    def _queue_indexing_job(self, row):
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = IndexWorker(row['path'], self.case.folder, evidence_id,
                                 self)
            worker.params['unlock'] = self._unlocks_for(row['path'])
            worker.progressed.connect(
                lambda done, total, path: self.job_bar.report(
                    done, total, os.path.basename(path)))
            worker.finished_indexing.connect(
                lambda count, error: self._indexing_finished(name, count,
                                                             error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"index:{evidence_id}",
            title=f"Indexing {name}",
            start=start,
            stop=lambda worker: worker.stop()))

    def _indexing_finished(self, name, count, error):
        if error:
            self.set_status(f"Indexing {name} failed: {error}")
            logger.error("Indexing %s failed: %s", name, error)
        else:
            self.set_status(f"Indexed {count:,} item(s) from {name}")
        self.job_bar.job_finished()
        # The job wrote through its own connection; reopen to see it.
        self.search_panel.reload_index()
        self.refresh_analysis_views()

    def queue_activity(self, rows):
        """One job per image: Windows activity and browser history."""
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                logger.warning("Skipping activity of missing %s", row['path'])
                continue
            if self._queue_activity_job(row):
                queued += 1
        if queued:
            self.set_status(f"Reading activity on {queued} image(s) in the "
                            f"background")
        return queued

    def _queue_activity_job(self, row):
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = ActivityWorker(row['path'], self.case.folder,
                                    evidence_id, self)
            worker.params['unlock'] = self._unlocks_for(row['path'])
            worker.progressed.connect(
                lambda done, total, path: self.job_bar.report(
                    done, total, os.path.basename(path)))
            worker.finished_activity.connect(
                lambda count, error: self._activity_finished(name, count,
                                                             error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"activity:{evidence_id}",
            title=f"Reading activity on {name}",
            start=start,
            stop=lambda worker: worker.stop()))

    def _activity_finished(self, name, count, error):
        if error:
            self.set_status(f"Reading activity on {name} failed: {error}")
            logger.error("Activity on %s failed: %s", name, error)
        else:
            self.set_status(f"Read {count:,} activity record(s) from {name}")
        self.job_bar.job_finished()
        self.refresh_analysis_views()

    def queue_ntfs(self, rows):
        """One job per image: $MFT times, streams and the change journal."""
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                logger.warning("Skipping NTFS of missing %s", row['path'])
                continue
            if self._queue_ntfs_job(row):
                queued += 1
        if queued:
            self.set_status(f"Reading NTFS records on {queued} image(s) in "
                            f"the background")
        return queued

    def _queue_ntfs_job(self, row):
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = NtfsWorker(row['path'], self.case.folder, evidence_id,
                                self)
            worker.params['unlock'] = self._unlocks_for(row['path'])
            worker.progressed.connect(
                lambda done, total, what: self.job_bar.report(
                    done, total, what))
            worker.finished_ntfs.connect(
                lambda count, error: self._ntfs_finished(name, count, error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"ntfs:{evidence_id}",
            title=f"Reading NTFS records on {name}",
            start=start,
            stop=lambda worker: worker.stop()))

    def queue_fs_times(self, rows):
        """One job per image: every non-NTFS file system's times, for the
        timeline (core/fs_times)."""
        from trace_app.ui.viewers.timeline_panel import FsTimesWorker
        if not self.case:
            return 0
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                continue
            evidence_id = row['id']
            name = row.get('display_name') or os.path.basename(row['path'])

            def start(job, row=row, evidence_id=evidence_id, name=name):
                worker = FsTimesWorker(row['path'], self.case.folder,
                                       evidence_id, self)
                worker.params['unlock'] = self._unlocks_for(row['path'])
                worker.progressed.connect(
                    lambda done, total, path: self.job_bar.report(
                        done, total, path))
                worker.finished_fstimes.connect(
                    lambda count, error: self._fs_times_finished(
                        name, count, error))
                self._retain_worker(worker)
                worker.start()
                return worker

            if self.job_bar.submit(Job(
                    key=f"fstimes:{evidence_id}",
                    title=f"Reading file system times on {name}",
                    start=start, stop=lambda worker: worker.stop())):
                queued += 1
        return queued

    def _fs_times_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Reading file system times on {name} failed: "
                            f"{error}")
            logger.error("File system times on %s failed: %s", name, error)
        elif count:
            self.set_status(f"File system times of {count:,} entries on "
                            f"{name} are in the timeline")
        else:
            self.set_status(f"{name} has no file system other than NTFS "
                            f"to read times from")
        self.refresh_analysis_views()

    def _ntfs_finished(self, name, count, error):
        if error:
            self.set_status(f"Reading NTFS records on {name} failed: {error}")
            logger.error("NTFS on %s failed: %s", name, error)
        elif count:
            self.set_status(f"Read {count:,} MFT entries from {name}")
        else:
            self.set_status(f"{name} has no NTFS volume to read")
        self.job_bar.job_finished()
        self.refresh_analysis_views()

    def show_settings(self):
        """Options > Settings: the examiner's preferences and this case's
        settings (core/settings.py); what they change is redrawn."""
        from trace_app.ui.dialogs.settings import SettingsDialog
        dialog = SettingsDialog(self.case, self)
        if dialog.exec() != QDialog.Accepted:
            return False
        self.apply_settings()
        return True

    def apply_settings(self):
        """Redraw what the settings shape: the listing (sizes, filters,
        times), the time columns elsewhere, carving's default source."""
        item = self.tree_viewer.currentItem()
        if item is not None:
            self.on_item_clicked(item, 0)
        if self.case is not None:
            self.refresh_analysis_views()
        panel = getattr(self, 'carved_panel', None)
        if panel is not None and hasattr(panel, 'use_settings'):
            panel.use_settings()

    def show_supported_features(self):
        from trace_app.ui.dialogs.supported_features import (
            SupportedFeaturesDialog)
        SupportedFeaturesDialog(self).exec()

    # --- the report -----------------------------------------------------

    def create_report(self):
        """Case > Create Report: ask, then write it as a job."""
        if not self.case:
            message.information(self, "No case is open",
                                "A report is made from a case.")
            return False
        from trace_app.ui.dialogs.report import ReportDialog
        dialog = ReportDialog(self.case, self)
        if dialog.exec() != QDialog.Accepted:
            return False
        return self.queue_report(dialog.options)

    def queue_report(self, options):
        from trace_app.ui.dialogs.report import ReportWorker
        chosen = options.get('evidence_ids')
        images = [(row['id'], row['path'], self._unlocks_for(row['path']))
                  for row in self.case.evidence()
                  if (chosen is None or row['id'] in chosen)
                  and os.path.exists(row['path'])]
        written = []

        def start(job):
            worker = ReportWorker(self.case.folder, options, images, self)
            worker.progressed.connect(
                lambda done, total, what: self.job_bar.report(done, total,
                                                              what))
            worker.item_written.connect(written.append)
            worker.finished_report.connect(
                lambda count, error: self._report_finished(written, error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key='report', title="Creating the report", start=start,
            stop=lambda worker: worker.stop()))

    def _report_finished(self, written, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"The report failed: {error}")
            message.warning(self, "Report not created",
                            "The report could not be written.", error)
            return
        if not written:
            self.set_status("Report cancelled")
            return
        self.set_status("Report written to " + ', '.join(
            os.path.basename(item['path']) for item in written))
        self.last_report = written
        if getattr(self, '_report_dialogs', True):
            from trace_app.ui.dialogs.report import ReportDoneDialog
            ReportDoneDialog(written, self).exec()

    # --- the timeline ---------------------------------------------------

    def show_in_timeline(self, artifact):
        """Every event of one file, on the Timeline tab."""
        self.timeline_panel.show_file(artifact.get('evidence_id'),
                                      artifact.get('artifact_ref'),
                                      artifact.get('name') or '')
        self.result_viewer.setCurrentWidget(self.timeline_panel)

    def _timeline_menu_extras(self, menu, payload):
        """Show in Listing, bookmark and VirusTotal for an event's file."""
        menu.addAction("Show in Listing").triggered.connect(
            lambda: self.open_finding(payload))
        if not self.activate_evidence(payload.get('evidence_id')):
            return
        parsed = parse_artifact_ref(payload.get('artifact_ref'))
        if parsed['kind'] == 'file':
            data = {'inode_number': parsed['inode'],
                    'start_offset': parsed['start_offset'],
                    'sequence': parsed['sequence'],
                    'name': payload.get('name') or '',
                    'path': payload.get('path') or ''}
            self.add_bookmark_action(menu, data)
            self.add_virustotal_menu(menu, [data])

    def _timeline_detail(self, row):
        """For an event on a file: both sets of NTFS times, and what
        Triage found about the file."""
        from trace_app.ui.widgets import detail_html as d
        if not self.case or not row.get('artifact_ref') \
                or row.get('evidence_id') is None \
                or row['source'] == 'activity':
            return ''
        parts = []
        events = self.case.fs_events_for(row['evidence_id'],
                                         row['artifact_ref'])
        if events:
            sets = {'SI': {}, 'FN': {}}
            for event in events:
                for letter in event['macb'].replace('.', ''):
                    sets[event['source']][letter] = event['time_utc']
            rows, earlier = [], False
            for letter, word in (('B', 'Created'), ('M', 'Modified'),
                                 ('C', 'Changed'), ('A', 'Accessed')):
                si, fn = sets['SI'].get(letter, ''), sets['FN'].get(letter,
                                                                    '')
                marked = letter == 'B' and si and fn and si < fn
                earlier = earlier or marked
                rows.append(
                    f"<tr><td class='k'>{word}</td>"
                    f"<td class='mono{' mark' if marked else ''}'>"
                    f"{d.e(si) or '—'}</td>"
                    f"<td class='mono'>{d.e(fn) or '—'}</td></tr>")
            parts.append(
                d.section("NTFS times (UTC)")
                + "<table cellspacing='0' cellpadding='0'><tr><th></th>"
                  "<th>$SI</th><th>$FN</th></tr>"
                + ''.join(rows) + "</table>")
            if earlier:
                # Stated, not judged: SI before FN alone is what installers
                # leave too; the NTFS module grades it (Triage > NTFS).
                parts.append(
                    "<p class='note'><span class='mark'>$SI created</span> "
                    "($STANDARD_INFORMATION) is earlier than $FN created "
                    "($FILE_NAME). Installers leave this too; Triage ▸ NTFS "
                    "grades it with the file's other times.</p>")
        findings = self.case.findings_map(row['evidence_id'],
                                          [row['artifact_ref']])
        notes = [((f.get('grade') or '').lower(), f.get('summary') or '')
                 for f in findings.get(row['artifact_ref'], ())
                 if f.get('grade') != 'benign']
        matches = self.case.hash_match_map(row['evidence_id'],
                                           [row['artifact_ref']])
        notes += [('', f"Hash set {m['set_name']} "
                       f"({hashsets.CATEGORIES.get(m['category'])})")
                  for m in matches.get(row['artifact_ref'], ())]
        if notes:
            lines = []
            for grade, text in notes:
                colour = d.GRADE_COLOURS.get(grade)
                label = (f"<td class='k'><span style='color:{colour}'>"
                         f"{d.e(grade.capitalize())}</span></td>"
                         if grade else "<td class='k'>Hash set</td>")
                lines.append(f"<tr>{label}<td>{d.breakable(text)}</td></tr>")
            parts.append(d.section("Findings")
                         + "<table cellspacing='0' cellpadding='0'>"
                         + ''.join(lines) + "</table>")
        return ''.join(parts)

    def add_timeline_to_report(self, rows):
        if not self.case or not rows:
            return
        from trace_app.core import timeline as timeline_core
        added = self.case.add_report_items('timeline', [{
            'evidence_id': row['evidence_id'],
            'artifact_ref': row['artifact_ref'],
            'time': row['time'],
            'title': f"{timeline_core.describe_kind(row)}: "
                     f"{row['title'] or row['subject'] or ''}",
            'detail': {'source': row['source'], 'local': row['local'],
                       'subject': row['subject'], 'user': row['user'],
                       'deleted': row['deleted']}} for row in rows])
        self.set_status(f"Added {added} event(s) to the report"
                        if added else "Already in the report")

    def _timeline_exported(self, path, rows):
        import hashlib
        digest = hashlib.sha256()
        try:
            with open(path, 'rb') as handle:
                for block in iter(lambda: handle.read(1 << 20), b''):
                    digest.update(block)
        except OSError:
            return
        self.case.record_event(
            'timeline exported',
            f"rows={rows} path={path} sha256={digest.hexdigest()}")

    # --- persistence ---------------------------------------------------

    def queue_persistence(self, rows):
        from trace_app.ui.viewers.persistence_panel import PersistenceWorker
        if not self.case:
            return 0
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                continue
            evidence_id = row['id']
            name = row.get('display_name') or os.path.basename(row['path'])

            def start(job, row=row, evidence_id=evidence_id, name=name):
                worker = PersistenceWorker(row['path'], self.case.folder,
                                           evidence_id,
                                           self.hash_library().folder, self)
                worker.params['unlock'] = self._unlocks_for(row['path'])
                worker.progressed.connect(
                    lambda done, total, path: self.job_bar.report(
                        done, total, os.path.basename(path)))
                worker.finished_persistence.connect(
                    lambda count, error: self._persistence_finished(
                        name, count, error))
                self._retain_worker(worker)
                worker.start()
                return worker

            if self.job_bar.submit(Job(
                    key=f"persistence:{evidence_id}",
                    title=f"Reading autostarts on {name}", start=start,
                    stop=lambda worker: worker.stop())):
                queued += 1
        return queued

    def _persistence_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Reading autostarts on {name} failed: {error}")
            logger.error("Persistence on %s failed: %s", name, error)
        else:
            self.set_status(f"{count:,} autostart(s) read from {name}")
        self.refresh_analysis_views()

    # --- YARA -------------------------------------------------------------

    def yara_library(self):
        from trace_app.core import yara_rules
        library = getattr(self, '_yara_library', None)
        if library is None:
            library = self._yara_library = yara_rules.Library()
        return library

    def show_yara_rules(self):
        """Tools > YARA Rules: the library, and this case's options."""
        from trace_app.ui.dialogs.yara_rules import YaraRulesDialog
        dialog = YaraRulesDialog(self.case, self.yara_library(), self)
        wanted = []
        dialog.scan_requested.connect(lambda: wanted.append(True))
        dialog.exec()
        if wanted and self.case:
            self.queue_yara(self.case.evidence())

    def queue_yara(self, rows):
        """One YARA job per image, on the shared queue."""
        from trace_app.core import yara_rules
        if not self.case:
            return 0
        if not yara_rules.available():
            message.information(self, "YARA is unavailable",
                                "YARA scanning does not work on this system.",
                                yara_rules.unavailable_reason())
            return 0
        options = yara_rules.case_options(self.case, self.yara_library())
        if not options.get('enabled') or not any(
                yara_rules.set_enabled_in(options, entry)
                for entry in self.yara_library().sets()):
            message.information(self, "No YARA rules in use",
                                "This case uses no YARA rules.",
                                "Tools \u25b8 YARA Rules imports them and "
                                "chooses which this case uses.")
            return 0
        queued = 0
        for row in rows:
            if os.path.exists(row['path']) and \
                    self._queue_yara_job(row, options):
                queued += 1
        if queued:
            self.set_status(f"Scanning {queued} image(s) with YARA in the "
                            f"background")
        return queued

    def _queue_yara_job(self, row, options):
        from trace_app.ui.dialogs.yara_rules import YaraWorker
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = YaraWorker(row['path'], self.case.folder, evidence_id,
                                self.yara_library().folder, options, self)
            worker.params['unlock'] = self._unlocks_for(row['path'])
            worker.progressed.connect(
                lambda done, total, path: self.job_bar.report(
                    done, total, os.path.basename(path)))
            worker.finished_scan.connect(
                lambda count, error: self._yara_finished(name, count, error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"yara:{evidence_id}", title=f"YARA scan of {name}",
            start=start, stop=lambda worker: worker.stop()))

    def _yara_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"YARA scan of {name} failed: {error}")
            logger.error("YARA on %s failed: %s", name, error)
        else:
            self.set_status(f"YARA: {count:,} file(s) in {name} matched")
        self.refresh_analysis_views()

    # --- Sigma ---------------------------------------------------------------

    def sigma_library(self):
        from trace_app.core import sigma
        library = getattr(self, '_sigma_library', None)
        if library is None:
            library = self._sigma_library = sigma.Library()
        return library

    def show_sigma_rules(self):
        """Tools > Sigma Rules: the library, and this case's options."""
        from trace_app.ui.dialogs.sigma_rules import SigmaRulesDialog
        dialog = SigmaRulesDialog(self.case, self.sigma_library(), self)
        wanted = []
        dialog.scan_requested.connect(lambda: wanted.append(True))
        dialog.exec()
        if wanted and self.case:
            self.queue_sigma(self.case.evidence())

    def queue_sigma(self, rows):
        """One Sigma job per image, on the shared queue."""
        from trace_app.core import sigma
        if not self.case:
            return 0
        if not sigma.available():
            message.information(self, "Sigma is unavailable",
                                "Sigma rules do not run on this system.",
                                sigma.unavailable_reason())
            return 0
        options = sigma.case_options(self.case, self.sigma_library())
        if not options.get('enabled') or not any(
                sigma.set_enabled_in(options, entry)
                for entry in self.sigma_library().sets()):
            message.information(self, "No Sigma rules in use",
                                "This case uses no Sigma rules.",
                                "Tools \u25b8 Sigma Rules imports them "
                                "(SigmaHQ's release zip, or your own) and "
                                "chooses which this case uses.")
            return 0
        queued = 0
        for row in rows:
            if os.path.exists(row['path']) and \
                    self._queue_sigma_job(row, options):
                queued += 1
        if queued:
            self.set_status(f"Checking the event logs of {queued} image(s) "
                            f"with Sigma rules in the background")
        return queued

    def _queue_sigma_job(self, row, options):
        from trace_app.ui.dialogs.sigma_rules import SigmaWorker
        evidence_id = row['id']
        name = row.get('display_name') or os.path.basename(row['path'])

        def start(job):
            worker = SigmaWorker(row['path'], self.case.folder, evidence_id,
                                 self.sigma_library().folder, options, self,
                                 unlock=self._unlocks_for(row['path']))
            worker.progressed.connect(
                lambda done, total, path: self.job_bar.report(
                    done, total, os.path.basename(path)))
            worker.finished_scan.connect(
                lambda count, error: self._sigma_finished(name, count,
                                                          error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"sigma:{evidence_id}", title=f"Sigma check of {name}",
            start=start, stop=lambda worker: worker.stop()))

    def _sigma_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Sigma check of {name} failed: {error}")
            logger.error("Sigma on %s failed: %s", name, error)
        else:
            self.set_status(f"Sigma: {count:,} detection(s) in the event "
                            f"logs of {name}")
        self.refresh_analysis_views()

    # --- deleted files -----------------------------------------------------

    def queue_deleted(self, rows):
        from trace_app.ui.viewers.deleted_panel import DeletedWorker
        if not self.case:
            return 0
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                continue
            evidence_id = row['id']
            name = row.get('display_name') or os.path.basename(row['path'])

            def start(job, row=row, evidence_id=evidence_id, name=name):
                worker = DeletedWorker(row['path'], self.case.folder,
                                       evidence_id, self)
                worker.params['unlock'] = self._unlocks_for(row['path'])
                worker.progressed.connect(
                    lambda done, total, path: self.job_bar.report(
                        done, total, os.path.basename(path)))
                worker.finished_deleted.connect(
                    lambda count, error: self._deleted_finished(
                        name, count, error))
                self._retain_worker(worker)
                worker.start()
                return worker

            if self.job_bar.submit(Job(
                    key=f"deleted:{evidence_id}",
                    title=f"Listing deleted files on {name}", start=start,
                    stop=lambda worker: worker.stop())):
                queued += 1
        return queued

    def _deleted_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Listing deleted files on {name} failed: "
                            f"{error}")
            logger.error("Deleted files on %s failed: %s", name, error)
        else:
            self.set_status(f"{count:,} deleted file(s) and folder(s) "
                            f"listed on {name}")
        self.refresh_analysis_views()

    # --- thumbnail caches ------------------------------------------------

    def queue_thumbnails(self, rows):
        from trace_app.ui.viewers.thumbnails_panel import ThumbnailsWorker
        if not self.case:
            return 0
        queued = 0
        for row in rows:
            if not os.path.exists(row['path']):
                continue
            evidence_id = row['id']
            name = row.get('display_name') or os.path.basename(row['path'])

            def start(job, row=row, evidence_id=evidence_id, name=name):
                worker = ThumbnailsWorker(row['path'], self.case.folder,
                                          evidence_id, self)
                worker.params['unlock'] = self._unlocks_for(row['path'])
                worker.progressed.connect(
                    lambda done, total, path: self.job_bar.report(
                        done, total, os.path.basename(path)))
                worker.finished_thumbnails.connect(
                    lambda count, error: self._thumbnails_finished(
                        name, count, error))
                self._retain_worker(worker)
                worker.start()
                return worker

            if self.job_bar.submit(Job(
                    key=f"thumbnails:{evidence_id}",
                    title=f"Reading thumbnail caches on {name}", start=start,
                    stop=lambda worker: worker.stop())):
                queued += 1
        return queued

    def _thumbnails_finished(self, name, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Reading thumbnail caches on {name} failed: "
                            f"{error}")
            logger.error("Thumbnails on %s failed: %s", name, error)
        else:
            self.set_status(f"{count:,} thumbnail(s) read from {name}")
        self._thumbnail_cache_bytes = None
        self.refresh_analysis_views()

    def _thumbnail_bytes(self, row):
        """A thumbnail's picture, read from its cache file on its own
        image -- without changing which image is active."""
        from trace_app.core.case import parse_artifact_ref
        evidence = next((r for r in self.case.evidence()
                         if r['id'] == row['evidence_id']), None) \
            if self.case else None
        handler = self.handler_for(evidence['path']) if evidence else None
        if handler is None:
            return None
        parsed = parse_artifact_ref(row['cache_ref'])
        if row['cache_kind'] == 'thumbcache':
            stream = handler.open_file_object(parsed['inode'],
                                              parsed['start_offset'])
            if stream is None:
                return None
            stream.seek(int(row['location']))
            return stream.read(int(row['size'] or 0))
        key = (row['evidence_id'], row['cache_ref'])
        cached = getattr(self, '_thumbnail_cache_bytes', None)
        if not cached or cached[0] != key:
            content, _ = handler.get_file_content(parsed['inode'],
                                                  parsed['start_offset'])
            cached = self._thumbnail_cache_bytes = (key, content or b'')
        return thumbnails.picture_bytes(cached[1], row)

    def _thumbnail_cache_row(self, row):
        """A thumbnail as the finding-shaped row of its cache file."""
        return {'evidence_id': row['evidence_id'],
                'artifact_ref': row['cache_ref'],
                'name': row['cache_path'].rsplit('/', 1)[-1],
                'path': row['cache_path']}

    def preview_thumbnail(self, row):
        key = f"thumbnail:{row['evidence_id']}:{row['id']}"
        if (self.current_selected_data or {}).get('_preview_ref') == key:
            return
        if not row.get('format'):
            self.set_status(f"Only the name of {row.get('name')} is left in "
                            f"{row['cache_path']}; its picture is gone.",
                            6000)
            return
        try:
            content = self._thumbnail_bytes(row)
        except Exception as exc:
            logger.error("Could not read thumbnail %s: %s", key, exc)
            content = None
        if not content:
            self.set_status("The picture could not be read from its cache.",
                            5000)
            return
        label = row.get('name') or row.get('key') or 'thumbnail'
        data = {'name': f"{label} (thumbnail).{row['format']}",
                'size': len(content), 'type': row['format'],
                'path': f"{row['cache_path']}!/{row['location']}",
                'file_content': content, 'source': 'thumbnail',
                '_preview_ref': key}
        self.clear_viewers()
        self.current_selected_data = data
        if self.active_viewer_adapter() is None:
            self.viewer_tab.setCurrentWidget(self.viewer_adapters[0].widget)
        self.update_viewer_with_file_content(content, data)
        self.viewer_dock.show()
        self.set_status(f"{label}: from {row['cache_path']}")

    def open_thumbnail_cache(self, row):
        self.open_finding(self._thumbnail_cache_row(row))

    def preview_finding(self, finding):
        """A finding under Findings in the tree, previewed the way its
        own Triage list previews it."""
        module = finding.get('module')
        if module == 'keywords':
            self.preview_keyword_hit(finding)
            return
        if module == 'thumbnails':
            stream = (finding.get('detail') or {}).get('stream')
            panel = self.thumbnails_panel
            row = next((r for r in self.case.thumbnails(
                finding.get('evidence_id'), finding.get('artifact_ref'))
                if r['location'] == stream), None) if self.case else None
            if row is not None:
                self.preview_thumbnail(row)
                panel.select_row(lambda r: r['id'] == row['id'])
                return
        self.preview_artifact(finding)

    # --- keyword lists ---------------------------------------------------

    def keyword_library(self):
        from trace_app.core import keywords
        library = getattr(self, '_keyword_library', None)
        if library is None:
            library = self._keyword_library = keywords.Library()
        return library

    def show_keyword_lists(self):
        """Tools > Keyword Lists: the library, and this case's options."""
        from trace_app.ui.dialogs.keyword_lists import KeywordListsDialog
        dialog = KeywordListsDialog(self.case, self.keyword_library(), self)
        wanted = []
        dialog.search_requested.connect(lambda: wanted.append(True))
        dialog.exec()
        if wanted:
            self.queue_keywords()

    def queue_keywords(self, evidence_ids=None):
        """Search the case's index with its keyword lists, as a job on the
        shared queue -- after any indexing already queued, which it reads."""
        from trace_app.core import keywords
        from trace_app.ui.dialogs.keyword_lists import KeywordWorker
        if not self.case:
            return False
        options = keywords.case_options(self.case, self.keyword_library())
        if not options.get('enabled') or not any(
                keywords.list_enabled_in(options, entry)
                for entry in self.keyword_library().lists()):
            message.information(
                self, "Keyword lists",
                "No keyword lists are in use for this case.",
                "Tools ▸ Keyword Lists imports or types a list and chooses "
                "which this case uses.")
            return False
        ids = [row['id'] for row in self.case.evidence()] \
            if evidence_ids is None else list(evidence_ids)

        def start(job):
            worker = KeywordWorker(self.case.folder,
                                   self.keyword_library().folder, options,
                                   ids, self)
            worker.progressed.connect(
                lambda done, total, term: self.job_bar.report(done, total,
                                                              term))
            worker.finished_search.connect(
                lambda count, error, w=worker: self._keywords_finished(
                    w, count, error))
            self._retain_worker(worker)
            worker.start()
            return worker

        return self.job_bar.submit(Job(
            key=f"keywords:{','.join(map(str, ids))}",
            title="Searching keyword lists", start=start,
            stop=lambda worker: worker.stop()))

    def _keywords_finished(self, worker, count, error):
        self.job_bar.job_finished()
        if error:
            self.set_status(f"Keyword search failed: {error}")
            logger.error("Keyword search failed: %s", error)
            return
        result = worker.result or {}
        missing = result.get('not_indexed') or []
        text = (f"Keywords: {result.get('terms_hit', 0):,} term(s) found "
                f"in {count:,} file(s)")
        if missing:
            names = {r['id']: r.get('display_name')
                     or os.path.basename(r['path'])
                     for r in self.case.evidence()}
            text += (" — not searched, not indexed yet: "
                     + ', '.join(names.get(e, f'#{e}') for e in missing))
        self.set_status(text)
        self.refresh_analysis_views()

    def preview_keyword_hit(self, finding):
        """A keyword hit: the file, or the member of an archive or
        mailbox the hit is in."""
        if (finding.get('detail') or {}).get('item_kind') == \
                'archive-member' and '!/' in (finding.get('path') or ''):
            self.preview_archive_member(finding)
            return
        self.preview_artifact(finding)

    def open_keyword_hit(self, finding):
        self.open_finding(finding)

    # --- hash sets ------------------------------------------------------

    def hash_library(self):
        library = getattr(self, '_hash_library', None)
        if library is None:
            library = self._hash_library = hashsets.Library()
        return library

    def show_hash_sets(self):
        """Tools > Hash Sets: the library, and this case's options."""
        from trace_app.ui.dialogs.hash_sets import HashSetsDialog
        dialog = HashSetsDialog(self.case, self.hash_library(), self)
        wanted = []
        dialog.match_requested.connect(lambda: wanted.append(True))
        dialog.exec()
        if wanted:
            self.queue_hash_matching()
        self.refresh_analysis_views()

    def queue_hash_matching(self, evidence_ids=None):
        """Match the case (or some of its images) against its hash sets,
        as a job on the shared queue."""
        if not self.case:
            return False
        options = hashsets.case_options(self.case, self.hash_library())
        if not options.get('enabled'):
            message.information(
                self, "Hash sets are off",
                "This case does not use hash sets.",
                "Tools \u25b8 Hash Sets imports them and switches them on.")
            return False

        def start(job):
            worker = HashMatchWorker(self.case.folder,
                                     self.hash_library().folder, options,
                                     evidence_ids, self)
            worker.progressed.connect(
                lambda done, total, name: self.job_bar.report(
                    done, total, name))
            worker.finished_matching.connect(
                lambda count, error: self._hash_matching_finished(
                    count, error, options))
            self._retain_worker(worker)
            worker.start()
            return worker

        key = 'all' if evidence_ids is None else ','.join(
            str(e) for e in evidence_ids)
        return self.job_bar.submit(Job(
            key=f"hashsets:{key}", title="Matching hash sets", start=start,
            stop=lambda worker: worker.stop()))

    def _hash_matching_finished(self, count, error, options):
        self.job_bar.job_finished()
        self.refresh_analysis_views()
        if self.listing_table.rowCount():
            self.mark_analysis_rows()
        if error:
            self.set_status(f"Hash set matching failed: {error}")
            logger.error("Hash set matching failed: %s", error)
            return
        counts = self.case.hash_match_counts()
        bad = counts.get(hashsets.KNOWN_BAD, 0)
        self.set_status(
            f"Hash sets: {bad:,} known bad, "
            f"{counts.get(hashsets.NOTABLE, 0):,} notable, "
            f"{counts.get(hashsets.KNOWN_GOOD, 0):,} known good file(s)")
        if bad and options.get('alert_known_bad'):
            message.warning(
                self, "Known-bad files found",
                f"{bad:,} file(s) match a known-bad hash set.",
                "They are listed in Triage \u25b8 Hash sets and under "
                "Findings in the tree.")
            self.show_triage('hashes')

    def show_activity(self, category=None, evidence_id=None):
        """Bring the Activity tab forward on a category."""
        self.result_viewer.setCurrentWidget(self.activity_panel)
        if evidence_id is not None:
            self.activity_panel.set_evidence_filter(evidence_id)
        self.activity_panel.show_category(category)

    @staticmethod
    def _activity_source(row):
        """An activity row as the artifact its source file is."""
        path = row.get('source_path') or ''
        return {'artifact_ref': row.get('source_ref'),
                'evidence_id': row.get('evidence_id'),
                'name': path.replace('\\', '/').rsplit('/', 1)[-1],
                'path': path, 'label': row.get('what') or 'Activity',
                'artifact_name': path.replace('\\', '/').rsplit('/', 1)[-1],
                'artifact_path': path}

    def _located_artifact(self, point):
        """A map point as the artifact it was read from: a photo finding is
        one already; an activity record is its source file."""
        return point['row'] if point['kind'] == 'photo' \
            else self._activity_source(point['row'])

    def preview_located(self, point):
        """A point landed on in the Map tab: show its file."""
        artifact = self._located_artifact(point)
        if artifact.get('artifact_ref'):
            self.preview_artifact(artifact)

    def open_located(self, point):
        self.open_finding(self._located_artifact(point))

    def preview_activity_source(self, row):
        """A click on an activity row: show the file it was read from --
        for a Recycle Bin record whose content was deleted from the bin,
        that content (what the examiner wants), not the $I record."""
        content = row.get('recycle_content')
        if content and content.get('artifact_ref'):
            self.preview_artifact(dict(content,
                                       artifact_name=content.get('name'),
                                       artifact_path=content.get('path')))
            return
        if row.get('source_ref'):
            self.preview_artifact(self._activity_source(row))

    def show_deleted_file(self, item):
        """Triage > Deleted files on one row (a deleted_files dict)."""
        self.show_triage('deleted', item.get('evidence_id'))
        self.deleted_panel.select(item.get('evidence_id'),
                                  item.get('artifact_ref'))

    def open_activity_source(self, row):
        """Double-click: go to the file it was read from."""
        if row.get('source_ref'):
            self.go_to_bookmark(self._activity_source(row))

    def search_for(self, query):
        """Bring the Search tab forward and run `query` there."""
        self.result_viewer.setCurrentWidget(self.search_panel)
        self.search_panel.query_input.setText(query)
        self.search_panel.run_search()

    def _on_jobs_finished(self):
        """The queue has emptied; show everything the runs produced."""
        self.refresh_analysis_views()

    def refresh_analysis_views(self):
        """Redraw everywhere findings are shown."""
        if getattr(self, 'triage_panel', None) is not None:
            # The whole case: an investigation spans every device in it, and
            # showing only the image loaded last hid every other image's
            # findings. Triage's own filter narrows it when asked.
            self.triage_panel.set_case(self.case)
        if getattr(self, 'activity_panel', None) is not None:
            self.activity_panel.set_case(self.case)
        if getattr(self, 'timeline_panel', None) is not None:
            self.timeline_panel.set_case(self.case)
        self.refresh_analysis_tree()
        self.refresh_activity_tree()
        self.mark_analysis_rows()

    # --- activity in the tree ---------------------------------------

    def refresh_activity_tree(self):
        """The Activity node: one child per category, with its count.

        Absent until there is something in it, like Findings and Bookmarks.
        A category opens the Activity tab on it.
        """
        from trace_app.core.activity import CATEGORIES
        for index in range(self.tree_viewer.topLevelItemCount() - 1, -1, -1):
            data = self.tree_viewer.topLevelItem(index).data(
                0, Qt.UserRole) or {}
            if data.get('is_activity_root'):
                self.tree_viewer.takeTopLevelItem(index)
        if not self.case:
            return
        summary = self.case.user_activity_summary()
        if not summary:
            return
        root = QTreeWidgetItem()
        root.setText(0, f"Activity ({sum(summary.values()):,})")
        root.setIcon(0, icons.icon(icons.ACTIVITY))
        root.setData(0, Qt.UserRole, {'is_activity_root': True})
        position = 0
        for index in range(self.tree_viewer.topLevelItemCount()):
            data = self.tree_viewer.topLevelItem(index).data(
                0, Qt.UserRole) or {}
            if data.get('is_bookmarks_root') or data.get('is_analysis_root'):
                position = index + 1
        self.tree_viewer.insertTopLevelItem(position, root)
        for key, label in CATEGORIES:
            if not summary.get(key):
                continue
            node = QTreeWidgetItem(root)
            node.setText(0, f"{label} ({summary[key]:,})")
            node.setIcon(0, icons.icon(icons.ACTIVITY_CATEGORIES[key]))
            node.setData(0, Qt.UserRole, {'is_activity_group': True,
                                          'category': key})
        root.setExpanded(True)

    # --- findings in the tree ---------------------------------------

    def refresh_analysis_tree(self):
        """Rebuild the Findings node at the top of the tree.

        Beside Bookmarks and for the same reason: the tree is where an
        examiner looks to find where something is, and a finding that lives
        only in a tab is one they have to remember to go and read. Absent
        until there is something in it -- an empty node is a permanent
        advertisement for a feature rather than a way into anything.
        """
        for index in range(self.tree_viewer.topLevelItemCount() - 1, -1, -1):
            item = self.tree_viewer.topLevelItem(index)
            data = item.data(0, Qt.UserRole) or {}
            if data.get('is_analysis_root'):
                self.tree_viewer.takeTopLevelItem(index)

        if not self.case:
            return

        # The whole case, so every device's findings are here.
        evidence_id = None
        summary = self.case.analysis_summary(evidence_id)
        indicators = self._case_indicator_summary()
        ntfs = self.case.ntfs_counts(evidence_id)
        hashed = self.case.hash_match_counts(evidence_id)
        if not summary['analysed'] and not summary['carved'] \
                and not indicators and not ntfs['timestomp'] \
                and not ntfs['streams'] \
                and not hashed.get(hashsets.KNOWN_BAD) \
                and not hashed.get(hashsets.NOTABLE) \
                and not self.case.findings(evidence_id, 'yara', limit=1) \
                and not self.case.findings(evidence_id, 'persistence',
                                           limit=1) \
                and not self.case.findings(evidence_id, 'keywords',
                                           limit=1) \
                and not self.case.findings(evidence_id, 'thumbnails',
                                           limit=1):
            return
        names = {r['id']: r.get('display_name') or os.path.basename(r['path'])
                 for r in self.case.evidence()}

        groups = [
            ('mismatch', 'Type mismatches', icons.FINDING_MISMATCH,
             summary['mismatches'],
             # The grade the count was taken at. Fetching the default
             # (suspicious only) left a group counting four notable files
             # with nothing under it.
             lambda: self.case.type_mismatches(
                 evidence_id, grade=REPORTED_MISMATCHES)),
            ('entropy', 'High entropy', icons.FINDING_ENTROPY,
             summary['high_entropy'],
             lambda: self.case.high_entropy_files(evidence_id)),
            ('duplicates', 'Duplicates', icons.FINDING_DUPLICATES,
             summary['duplicate_groups'],
             lambda: [m for g in self.case.duplicate_groups(evidence_id)
                      for m in g['members']]),
            ('hidden', 'Hidden data', icons.FINDING_HIDDEN, summary['hidden'],
             lambda: self._one_per_file(self.case.findings(
                 evidence_id, 'hidden', grades=REPORTED_FINDING_GRADES))),
            # Every photo with camera metadata; those that say where they
            # were taken carry the location pin, and sort first.
            ('photos', 'Photos', icons.FINDING_PHOTO, summary['photos'],
             lambda: self._photos_located_first(
                 self._one_per_file(self.case.findings(evidence_id,
                                                       'photo')))),
            ('authors', 'Document authors', icons.FINDING_AUTHOR,
             summary['authors'],
             lambda: self._one_per_file(self.case.findings(evidence_id,
                                                           'authors'))),
            # Executables only when something about them is worth a look;
            # the full list is Triage's Executables tab.
            ('executables', 'Executables', icons.EXECUTABLE,
             summary['executables_flagged'],
             lambda: self._one_per_file(self.case.findings(
                 evidence_id, 'executables',
                 grades=REPORTED_FINDING_GRADES))),
            ('carved', 'Carved files', icons.FINDING_CARVED,
             summary['carved'],
             lambda: [dict(row, is_carved=True, summary=(
                 f"{row['type'].upper()} carved at byte {row['offset']:,}"
                 + (f", dated {row['embedded_date']}"
                    if row.get('embedded_date')
                    and row['embedded_date'] != UNKNOWN_DATE else '')))
                 for row in self.case.carved_files(evidence_id)]),
            # NTFS: times set by hand, and hidden streams and downloads.
            # Routine rows stay in the NTFS tab.
            ('ntfs:timestomp', 'Timestomping', icons.FINDING_TIMESTOMP,
             ntfs['timestomp'],
             lambda: self.case.ntfs_rows('timestomp', evidence_id)),
            ('ntfs:streams', 'Streams and downloads', icons.FINDING_STREAM,
             ntfs['streams'],
             lambda: self.case.ntfs_rows('streams', evidence_id)),
            # Hash sets: known bad first. Known good is the opposite of a
            # finding and stays in the Hash sets tab.
            ('persistence', 'Persistence', icons.PERSISTENCE,
             len({(f['evidence_id'], f['artifact_ref']) for f in
                  self.case.findings(evidence_id, 'persistence',
                                     limit=100000)}),
             lambda: self._one_per_file(self.case.findings(
                 evidence_id, 'persistence', limit=100000))),
            # A Thumbs.db names each picture's file; the ones no longer
            # in their folder. One row per picture, not per Thumbs.db.
            ('thumbnails', 'Thumbnails of files gone', icons.THUMBNAILS,
             len(self.case.findings(evidence_id, 'thumbnails',
                                    limit=100000)),
             lambda: self.case.findings(evidence_id, 'thumbnails',
                                        limit=100000)),
            ('yara', 'YARA matches', icons.FINDING_YARA,
             len({(f['evidence_id'], f['artifact_ref']) for f in
                  self.case.findings(evidence_id, 'yara', limit=100000)}),
             lambda: self._one_per_file(self.case.findings(
                 evidence_id, 'yara', limit=100000))),
            # Each event a Sigma rule matched (medium and above): these
            # are events, so one row each, not one per log.
            ('sigma', 'Sigma detections', icons.SIGMA,
             len(self.case.findings(evidence_id, 'sigma',
                                    grades=REPORTED_FINDING_GRADES,
                                    limit=100000)),
             lambda: self.case.findings(evidence_id, 'sigma',
                                        grades=REPORTED_FINDING_GRADES,
                                        limit=100000)),
            ('hash:known-bad', 'Known bad (hash sets)', icons.HASH_SETS,
             hashed.get(hashsets.KNOWN_BAD, 0),
             lambda: self._one_per_file(self.case.hash_matches(
                 evidence_id, [hashsets.KNOWN_BAD]))),
            ('hash:notable', 'Notable (hash sets)', icons.HASH_SETS,
             hashed.get(hashsets.NOTABLE, 0),
             lambda: self._one_per_file(self.case.hash_matches(
                 evidence_id, [hashsets.NOTABLE]))),
        ]
        from trace_app.core.keywords import term_summary
        keyword_terms = term_summary(self.case.findings(
            evidence_id, 'keywords', limit=500000))
        if not any(count for _, _, _, count, _ in groups) and not indicators \
                and not keyword_terms:
            return          # analysed, and nothing stood out: say nothing

        root = QTreeWidgetItem(self.tree_viewer)
        total = sum(count for _, _, _, count, _ in groups) \
            + sum(indicators.values()) + len(keyword_terms)
        root.setText(0, f"Findings ({total})")
        root.setIcon(0, icons.icon(icons.FINDINGS))
        root.setData(0, Qt.UserRole, {'is_analysis_root': True})

        # Below Bookmarks but above the evidence: findings are why an examiner
        # opened the case, and a bookmark is something they made themselves.
        position = 1 if self._has_bookmarks_root() else 0
        self.tree_viewer.insertTopLevelItem(
            position, self.tree_viewer.takeTopLevelItem(
                self.tree_viewer.indexOfTopLevelItem(root)))
        root = self.tree_viewer.topLevelItem(position)

        for key, label, glyph, count, fetch in groups:
            if not count:
                continue
            group = QTreeWidgetItem(root)
            group.setText(0, f"{label} ({count})")
            group.setIcon(0, icons.icon(glyph))
            group.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                           'group': key})
            findings = fetch()
            images = sorted({f.get('evidence_id') for f in findings},
                            key=lambda e: names.get(e, ''))
            # Split by image once there is more than one, so which device a
            # file came from is read off the tree, not looked up.
            parents = {}
            for image in images:
                if len(images) == 1:
                    parents[image] = group
                    continue
                count_here = len({f['artifact_ref'] for f in findings
                                  if f.get('evidence_id') == image})
                node = QTreeWidgetItem(group)
                # Duplicates count sets at the group but files here; say so.
                unit = ' files' if key == 'duplicates' else ''
                node.setText(0, f"{names.get(image, f'#{image}')} "
                                f"({count_here}{unit})")
                node.setIcon(0, QIcon(self.db_manager.get_icon_path(
                    'device', 'drive-harddisk')))
                node.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                              'is_image_group': True,
                                              'group': key,
                                              'evidence_id': image})
                parents[image] = node
            # The tree is for getting to files, not for reading 4,000 of them;
            # Triage has every row. What is left out is said, not dropped.
            shown_limit = 400
            if len(findings) > shown_limit:
                more = QTreeWidgetItem(group)
                more.setText(0, f"+{len(findings) - shown_limit:,} more — "
                                f"open in Triage")
                more.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                              'group': key})
            for finding in findings[:shown_limit]:
                child = QTreeWidgetItem(parents[finding.get('evidence_id')])
                child.setText(0, finding.get('name') or '(unnamed)')
                if key == 'photos' and 'latitude' in (finding.get('detail')
                                                      or {}):
                    child.setText(0, f"{finding.get('name') or ''}  \u2014 "
                                     f"with location")
                extension = (finding.get('extension') or
                             (finding.get('name') or '').rsplit('.', 1)[-1]
                             if '.' in (finding.get('name') or '') else '')
                if key == 'photos' and 'latitude' in (finding.get('detail')
                                                      or {}):
                    child.setIcon(0, icons.icon(icons.FINDING_LOCATION))
                else:
                    child.setIcon(0, self._get_file_icon(extension
                                                         or 'unknown'))
                image = names.get(finding.get('evidence_id'), '')
                child.setToolTip(0, '\n'.join(p for p in (
                    finding.get('summary'), finding.get('path'),
                    f"Evidence: {image}" if image else '') if p))
                child.setData(0, Qt.UserRole, {'is_finding': True,
                                               'finding': finding})

        # Keyword hits by list and term, like indicators by kind: the term
        # is the finding, its files are a click away in Triage.
        if keyword_terms:
            group = QTreeWidgetItem(root)
            group.setText(0, f"Keyword hits ({len(keyword_terms):,})")
            group.setIcon(0, icons.icon(icons.KEYWORDS))
            group.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                           'group': 'keywords'})
            lists = {}
            for term in keyword_terms:
                lists.setdefault((term['list_id'], term['list']),
                                 []).append(term)
            for (list_id, list_name), terms in lists.items():
                parent = group
                if len(lists) > 1:
                    parent = QTreeWidgetItem(group)
                    parent.setText(0, f"{list_name} ({len(terms):,})")
                    parent.setIcon(0, icons.icon(icons.KEYWORDS))
                    parent.setData(0, Qt.UserRole, {
                        'is_analysis_group': True, 'group': 'keywords'})
                for term in terms:
                    node = QTreeWidgetItem(parent)
                    node.setText(0, f"{term['term']} ({term['files']:,}"
                                    f"{'+' if term['truncated'] else ''} "
                                    f"file{'s' if term['files'] != 1 else ''})")
                    node.setIcon(0, icons.icon(icons.KEYWORDS))
                    node.setToolTip(0, f"{term['hits']:,} hit(s) in "
                                       f"{list_name}")
                    node.setData(0, Qt.UserRole, {
                        'is_analysis_group': True, 'group': 'keywords',
                        'list_id': list_id, 'term': term['term']})

        # Indicators by kind, not by file: "40 URLs" is the finding, and the
        # files holding each one are a click away in Triage.
        if indicators:
            group = QTreeWidgetItem(root)
            group.setText(0, f"Indicators ({sum(indicators.values()):,})")
            group.setIcon(0, icons.icon(icons.FINDING_INDICATORS))
            group.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                           'group': 'indicators'})
            for kind, count in self._ordered_indicators(indicators):
                node = QTreeWidgetItem(group)
                node.setText(0, f"{kind_label(kind, True)} ({count:,})")
                node.setIcon(0, icons.icon(icons.FINDING_INDICATORS))
                node.setData(0, Qt.UserRole, {'is_analysis_group': True,
                                              'group': 'indicators',
                                              'indicator_kind': kind})

        root.setExpanded(True)

    def _case_indicator_summary(self):
        """{kind: distinct values} across the whole case, whatever image
        Triage is filtered to -- the tree covers the case."""
        panel = getattr(self, 'indicators_panel', None)
        index = panel.index if panel is not None else None
        if index is None:
            return {}
        try:
            return index.indicator_summary(None)
        except Exception as exc:
            logger.error("Could not read indicators: %s", exc)
            return {}

    @staticmethod
    def _ordered_indicators(counts):
        from trace_app.core.search_index import INDICATOR_KINDS
        return [(kind, counts[kind]) for kind in INDICATOR_KINDS
                if counts.get(kind)]

    @staticmethod
    def _photos_located_first(findings):
        return sorted(findings, key=lambda f: 'latitude' not in
                      (f.get('detail') or {}))

    @staticmethod
    def _one_per_file(findings):
        """The first (most serious) finding for each file: the tree lists
        files, and one file can have several findings."""
        seen, out = set(), []
        for finding in findings:
            key = (finding.get('evidence_id'), finding['artifact_ref'])
            if key not in seen:
                seen.add(key)
                out.append(finding)
        return out

    def _has_bookmarks_root(self):
        for index in range(self.tree_viewer.topLevelItemCount()):
            data = self.tree_viewer.topLevelItem(index).data(0, Qt.UserRole)
            if (data or {}).get('is_bookmarks_root'):
                return True
        return False

    # --- opening a finding ------------------------------------------

    def open_finding(self, finding):
        """Jump to the file a finding describes.

        Through the same resolver a bookmark and a search result use. A
        finding is already a row carrying an artifact_ref, which is what
        go_to_bookmark resolves -- there is one way to turn a reference into a
        selection, and this is not a second one.
        """
        if not finding.get('artifact_ref'):
            return
        if finding.get('is_carved'):
            self.show_triage('carved', finding.get('evidence_id'))
            return
        self.go_to_bookmark({
            'artifact_ref': finding['artifact_ref'],
            'evidence_id': finding.get('evidence_id'),
            'label': finding.get('name') or 'Finding',
            'artifact_name': finding.get('name') or '',
            'artifact_path': finding.get('path') or '',
        })

    def open_finding_menu(self, finding, position):
        """The same right-click menu findings deserve everywhere else."""
        if finding.get('is_carved'):
            self.open_carved_menu(finding, position)
            return
        # Bookmarking and VirusTotal below act on the finding's own image.
        if not self.activate_evidence(finding.get('evidence_id')):
            return
        menu = QMenu(self)
        open_action = menu.addAction("Show in Listing")
        open_action.triggered.connect(lambda: self.open_finding(finding))
        if self.case and finding.get('artifact_ref'):
            timeline_action = menu.addAction(icons.icon(icons.TIMELINE),
                                             "Show in Timeline")
            timeline_action.triggered.connect(
                lambda: self.show_in_timeline(finding))
        menu.addSeparator()

        # add_bookmark_action wants what the listing puts in a row, so the
        # reference is taken apart into the same shape rather than teaching it
        # a second one.
        parsed = parse_artifact_ref(finding.get('artifact_ref'))
        if parsed['kind'] == 'file':
            data = {
                'inode_number': parsed['inode'],
                'start_offset': parsed['start_offset'],
                'sequence': parsed['sequence'],
                'name': finding.get('name') or '',
                'path': finding.get('path') or '',
                # Analysis already hashed it; a lookup need not read it again.
                'sha256': finding.get('sha256') or '',
            }
            self.add_bookmark_action(menu, data)
            self.add_virustotal_menu(menu, [data])

        # Copy, not "open in a map": a map service would be told where the
        # photo was taken, and that is evidence leaving the machine.
        facts = finding.get('detail') or {}
        if 'latitude' in facts:
            coordinates = f"{facts['latitude']:.6f}, {facts['longitude']:.6f}"
            menu.addSeparator()
            menu.addAction(f"Copy Coordinates ({coordinates})").triggered \
                .connect(lambda: QApplication.clipboard().setText(coordinates))
        show_menu(menu, position)

    # --- VirusTotal -------------------------------------------------

    def vt_api_key(self):
        return self.api_keys.get('API_KEYS', 'virustotal', fallback='').strip()

    def _vt_target(self, data):
        """The file `data` names, in the shape the worker takes, or None.

        Folders, volumes and unallocated space are not files VirusTotal can
        say anything about, so they get no entry rather than a disabled one.
        """
        if not data or data.get('type') in ('directory', 'volume'):
            return None
        if data.get('is_unallocated') or not self.current_image_path:
            return None
        inode = data.get('inode_number')
        offset = data.get('start_offset')
        if inode is None or offset is None:
            return None
        return {
            'name': data.get('name') or f'inode {inode}',
            'path': data.get('path') or '',
            'inode': inode,
            'start_offset': offset,
            'artifact_ref': make_artifact_ref(offset, inode,
                                              data.get('sequence')),
            'image_path': self.current_image_path,
            'sha256': data.get('sha256') or '',
        }

    def _vt_target_from_entry(self, entry):
        if not self.activate_evidence(entry.get('evidence_id')):
            return None
        parsed = parse_artifact_ref(entry.get('artifact_ref'))
        if parsed.get('kind') != 'file':
            return None
        return self._vt_target({
            'inode_number': parsed['inode'],
            'start_offset': parsed['start_offset'],
            'sequence': parsed['sequence'],
            'name': entry.get('name'),
            'path': entry.get('path'),
            'sha256': entry.get('sha256'),
        })

    def add_virustotal_menu(self, menu, datas):
        """A VirusTotal submenu for whichever of `datas` are files."""
        targets = [t for t in (self._vt_target(d) for d in datas) if t]
        if not targets:
            return None
        submenu = menu.addMenu("VirusTotal")
        submenu.setToolTipsVisible(True)

        count = len(targets)
        lookup = submenu.addAction(
            "Look Up Hash" if count == 1 else f"Look Up {count} Hashes")
        lookup.setToolTip("Sends only the SHA-256. The file stays here.")
        lookup.triggered.connect(lambda: self.vt_submit(targets, METHOD_HASH))

        upload = submenu.addAction("Upload File…")
        if count == 1:
            upload.setToolTip("Sends the file itself, after asking.")
            upload.triggered.connect(
                lambda: self.vt_submit(targets, METHOD_UPLOAD))
        else:
            upload.setEnabled(False)
            upload.setToolTip("Upload one file at a time.")

        submenu.addSeparator()
        submenu.addAction("Show Results").triggered.connect(
            self.show_vt_panel)
        return submenu

    def vt_submit(self, targets, method):
        """Queue `targets` for a lookup or an upload."""
        targets = [t for t in targets if t]
        if not targets:
            return
        # The case's network policy (Options > Settings > Privacy) is
        # checked here, where every VirusTotal request passes.
        refusal = case_settings.network_refusal(
            'upload' if method == METHOD_UPLOAD else 'network')
        if refusal:
            message.information(self, "VirusTotal", refusal)
            return
        if not self.vt_api_key():
            self.show_api_key_dialog()
            if not self.vt_api_key():
                return

        if method == METHOD_UPLOAD:
            name = targets[0]['name']
            if not message.question(
                    self, "Upload to VirusTotal?",
                    f"Upload {name} to VirusTotal?",
                    informative=(
                        "VirusTotal keeps every uploaded file, and its "
                        "paying subscribers and partners can download it. "
                        "Whatever the file contains leaves your control and "
                        "cannot be withdrawn.\n\n"
                        "Look Up Hash sends only the SHA-256, and is usually "
                        "enough to tell whether a file is known.")):
                return

        evidence_id = self.evidence_id_for_current_image()
        if method == METHOD_HASH and self.case and evidence_id is not None:
            # Analysis stored a SHA-256 for most files already; using it saves
            # reading each file back out of the image.
            missing = [t['artifact_ref'] for t in targets if not t['sha256']]
            if missing:
                known = self.case.analysis_map(evidence_id, missing)
                for target in targets:
                    facts = known.get(target['artifact_ref']) or {}
                    target['sha256'] = (target['sha256']
                                        or facts.get('sha256') or '')

        queried = datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec='seconds')
        jobs, entries = [], []
        for target in targets:
            key = uuid.uuid4().hex
            jobs.append(dict(target, key=key, method=method,
                             evidence_id=evidence_id))
            entries.append({
                'key': key, 'evidence_id': evidence_id,
                'name': target['name'], 'path': target['path'],
                'artifact_ref': target['artifact_ref'],
                'sha256': target['sha256'], 'method': method,
                'status': STATE_QUEUED, 'queried': queried,
            })

        self.vt_panel.add_entries(entries)
        self.show_vt_panel()
        if self.vt_worker is None or not self.vt_worker.add(jobs):
            self._start_vt_worker(jobs)
        self._vt_update_busy()

    def _start_vt_worker(self, jobs):
        worker = VirusTotalWorker(self.vt_api_key())
        worker.add(jobs)
        worker.job_started.connect(
            lambda key: self.vt_panel.update_entry(key, status=STATE_RUNNING))
        worker.progressed.connect(self._vt_progressed)
        worker.waiting.connect(self._vt_waiting)
        worker.job_finished.connect(self._vt_job_finished)
        worker.finished.connect(lambda w=worker: self._vt_worker_done(w))
        self.vt_worker = self._retain_worker(worker)
        worker.start()

    def _vt_progressed(self, key, text):
        entry = self.vt_panel.update_entry(key, progress=text)
        if entry is not None:
            self.set_status(f"VirusTotal: {text} — {entry.get('name')}")
        self._vt_update_busy()

    def _vt_waiting(self, text):
        self.vt_panel.set_busy(True, text)
        self.set_status(text)

    def _vt_job_finished(self, job, result, sent):
        """Record a result -- in the case if there is one -- and show it."""
        sha256 = result.get('sha256') or job.get('sha256') or ''
        row_id = None
        # Persisted only when a request was made: the case is the record of
        # what was asked, and a job cancelled in the queue asked nothing.
        if self.case and sent:
            try:
                row_id = self.case.record_vt_result(
                    job.get('evidence_id'), job.get('artifact_ref'),
                    job.get('name'), job.get('path'), sha256,
                    job.get('method'), result, sent=True)
            except Exception as exc:
                logger.error("Could not record the VirusTotal result: %s", exc)

        self.vt_panel.update_entry(
            job['key'], status=result.get('status') or vt.STATUS_ERROR,
            sha256=sha256, positives=result.get('positives'),
            total=result.get('total'), report=result,
            error=result.get('error') or '', progress='', row_id=row_id)
        self.mark_vt_rows()
        self._vt_update_busy()

        entry = self.vt_panel.entry(job['key']) or {}
        self.set_status(f"VirusTotal: {job.get('name')} — "
                        f"{verdict_text(entry)}", 6000)

    def _vt_worker_done(self, worker):
        if self.vt_worker is worker:
            self.vt_worker = None
        self._vt_update_busy()

    def _vt_update_busy(self):
        waiting = [e for e in self.vt_panel.entries()
                   if e.get('status') in (STATE_QUEUED, STATE_RUNNING)]
        if waiting and self.vt_worker is not None:
            running = next((e for e in waiting
                            if e.get('status') == STATE_RUNNING), None)
            text = (f"{running.get('progress') or 'Checking'} — "
                    f"{running.get('name')}" if running else "Queued")
            if len(waiting) > 1:
                text += f" · {len(waiting) - 1} more queued"
            self.vt_panel.set_busy(True, text)
        else:
            self.vt_panel.set_busy(False)

    def vt_cancel(self):
        if self.vt_worker is not None:
            self.vt_worker.stop()
            self.vt_panel.set_busy(True, "Cancelling…")

    @staticmethod
    def _vt_entry_from_row(row):
        """A stored vt_results row in the shape the panel shows."""
        return {
            'key': f"row{row['id']}", 'row_id': row['id'],
            'evidence_id': row.get('evidence_id'),
            'name': row.get('name') or '', 'path': row.get('path') or '',
            'artifact_ref': row.get('artifact_ref') or '',
            'sha256': row.get('sha256') or '', 'method': row.get('method'),
            'status': row.get('status'), 'positives': row.get('positives'),
            'total': row.get('total'), 'report': row.get('report') or {},
            'error': row.get('detail') or '', 'queried': row.get('queried_utc'),
        }

    def show_vt_panel(self):
        """Bring the VirusTotal tab into the viewer dock, and to the front."""
        index = self.viewer_tab.indexOf(self.vt_panel)
        if index == -1:
            index = self.viewer_tab.addTab(self.vt_panel, "VirusTotal")
            # A close button on this tab only: the file viewers are permanent
            # and closing one would leave no way back.
            #
            # Parented to the tab bar at construction. setTabButton does not
            # hand ownership to Qt in PySide, so an unparented button is
            # deleted when this method returns, and the next removeTab reads
            # freed memory -- an access violation, not an exception.
            close = QToolButton(self.viewer_tab.tabBar())
            close.setObjectName("tabCloseButton")
            close.setIcon(icons.icon(icons.CLOSE))
            close.setIconSize(QSize(12, 12))
            close.setAutoRaise(True)
            close.setToolTip("Close VirusTotal. Lookups keep running.")
            close.clicked.connect(self.hide_vt_panel)
            self.viewer_tab.tabBar().setTabButton(index, QTabBar.RightSide,
                                                  close)
        self.viewer_dock.show()
        self.viewer_dock.raise_()
        self.viewer_tab.setCurrentIndex(index)

    def hide_vt_panel(self):
        index = self.viewer_tab.indexOf(self.vt_panel)
        if index != -1:
            self.viewer_tab.removeTab(index)

    @contextmanager
    def _listing_unsorted(self):
        """Sorting off while cells are set, so rows stay where they are."""
        table = self.listing_table
        sorting = table.isSortingEnabled()
        table.setSortingEnabled(False)
        try:
            yield table
        finally:
            table.setSortingEnabled(sorting)

    def _listing_refs(self):
        """{artifact_ref: row} for the file rows on screen."""
        refs = {}
        for row in range(self.listing_table.rowCount()):
            item = self.listing_table.item(row, 0)
            if item is None:
                continue
            data = item.data(Qt.UserRole) or {}
            if data.get('inode_number') is None:
                continue
            refs[make_artifact_ref(data.get('start_offset', 0),
                                   data['inode_number'],
                                   data.get('sequence'))] = row
        return refs

    def mark_vt_rows(self):
        """Put each listed file's latest VirusTotal verdict in its column."""
        if not hasattr(self, 'listing_table') or not hasattr(self, 'vt_panel'):
            return
        if self.listing_table.columnCount() < 16:
            return
        refs = self._listing_refs()
        if not refs:
            return

        latest = {}
        evidence_id = self.evidence_id_for_path(self._listing_image)
        if self.case and evidence_id is not None:
            latest = {ref: self._vt_entry_from_row(row) for ref, row in
                      self.case.vt_latest(evidence_id, refs.keys()).items()}
        # Session results too: quick triage has no case, and a lookup still
        # running is worth showing as one. Entries are newest first, so the
        # first seen for a file is its latest.
        for entry in self.vt_panel.entries():
            ref = entry.get('artifact_ref')
            if ref in refs and ref not in latest:
                latest[ref] = entry

        with self._listing_unsorted() as table:
            for ref, row in refs.items():
                entry = latest.get(ref)
                if entry is None:
                    continue
                cell = QTableWidgetItem(verdict_text(entry))
                cell.setForeground(verdict_brush(verdict_state(entry)))
                tip = entry.get('error') or (
                    f"Checked {entry.get('queried')}" if entry.get('queried')
                    else '')
                cell.setToolTip(tip)
                table.setItem(row, 15, cell)

    def find_by_hash(self):
        """Look up a hash across everything the case has analysed."""
        if not self.case:
            return
        digest, accepted = QInputDialog.getText(
            self, "Find by Hash",
            "MD5 or SHA-256 (the kind is worked out from the length):")
        if not accepted or not digest.strip():
            return

        rows = self.case.find_by_hash(digest)
        if not rows:
            message.information(
                self, "No match",
                "Nothing in this case has that hash.",
                "Only files covered by a hash analysis run can be found this "
                "way \u2014 run Analysis \u25b8 Run Analysis Modules with "
                "hashing selected.")
            return

        if len(rows) == 1:
            self.open_finding(rows[0])
            self.set_status(f"Found {rows[0].get('path') or ''}")
            return

        # More than one: the Triage tab's duplicate view already shows copies
        # of a hash, so send them there rather than inventing a second list.
        self.result_viewer.setCurrentWidget(self.triage_panel)
        self.triage_panel.tabs.setCurrentIndex(2)
        self.set_status(f"{len(rows)} files share that hash")

    def mark_analysis_rows(self):
        """Fill the analysis columns for the rows currently listed.

        One query for the whole directory rather than one per row: drawing a
        folder of 2,000 files should not be 2,000 round trips to SQLite.
        """
        if not self.case or not hasattr(self, 'listing_table'):
            return

        columns = self.listing_table.columnCount()
        if columns < 15:
            return          # an older listing layout; nothing to fill

        evidence_id = self.evidence_id_for_path(self._listing_image)
        if evidence_id is None:
            return

        refs = {}
        for row in range(self.listing_table.rowCount()):
            item = self.listing_table.item(row, 0)
            if item is None:
                continue
            data = item.data(Qt.UserRole) or {}
            inode = data.get('inode_number')
            if inode is None:
                continue
            refs[make_artifact_ref(data.get('start_offset', 0), inode,
                                   data.get('sequence'))] = row

        if not refs:
            return

        found = self.case.analysis_map(evidence_id, refs.keys())
        hidden = self.case.findings_map(evidence_id, refs.keys(), 'hidden',
                                        REPORTED_FINDING_GRADES)
        yara_hits = self.case.findings_map(evidence_id, refs.keys(), 'yara')
        options = hashsets.case_options(self.case)
        matched = self.case.hash_match_map(evidence_id, refs.keys()) \
            if options.get('enabled') else {}
        hide_known = bool(options.get('hide_known_good'))
        concealed_rows = 0
        for ref, row in refs.items():
            match = (matched.get(ref) or [None])[0]
            known_good = match is not None and \
                match['category'] == hashsets.KNOWN_GOOD
            self.listing_table.setRowHidden(row, known_good and hide_known)
            concealed_rows += 1 if known_good and hide_known else 0
            facts = found.get(ref)
            if not facts:
                continue

            mime = facts.get('mime') or ''
            entropy = facts.get('entropy')
            mismatch = facts.get('mismatch') or ''

            # Mismatch first: a file whose content disagrees with its name is
            # a stronger statement than a high score, and an encrypted
            # document is both. Reporting only the entropy would describe the
            # symptom and drop the finding.
            # Most serious first: a disguised executable, then anything the
            # hidden-data checks rated suspicious, then the notable grades.
            concealed = (hidden.get(ref) or [None])[0]
            flag, severity, tip = '', '', ''
            if mismatch == 'suspicious':
                flag, severity = 'Type mismatch', 'suspicious'
            elif concealed and concealed['grade'] == 'suspicious':
                flag, severity = _FLAG_TEXT.get(concealed['kind'],
                                                'Hidden data'), 'suspicious'
                tip = concealed['summary']
            elif mismatch == 'notable':
                flag, severity = 'Likely encrypted', 'notable'
            elif concealed:
                flag, severity = _FLAG_TEXT.get(concealed['kind'],
                                                'Hidden data'), 'notable'
                tip = concealed['summary']
            elif entropy is not None and is_high_entropy(
                    entropy, facts.get('entropy_peak') or 0, mime):
                flag, severity = 'High entropy', 'notable'
            yara_hit = (yara_hits.get(ref) or [None])[0]
            if yara_hit is not None and (severity != 'suspicious'
                                         or yara_hit['grade'] ==
                                         'suspicious'):
                flag = f"YARA: {(yara_hit.get('detail') or {}).get('rule')}"
                severity = yara_hit['grade']
                tip = yara_hit.get('summary') or ''
            # A known-bad match outranks every guess above: it is a
            # statement that this exact file is bad.
            if match is not None and match['category'] == hashsets.KNOWN_BAD:
                flag, severity = f"Known bad: {match['set_name']}", \
                    'suspicious'
                tip = (f"{match['algorithm'].upper()} {match['digest']} is "
                       f"in {match['set_name']}")
            elif match is not None and match['category'] == hashsets.NOTABLE \
                    and severity != 'suspicious':
                flag, severity = f"Hash set: {match['set_name']}", 'notable'
                tip = (f"{match['algorithm'].upper()} {match['digest']} is "
                       f"in {match['set_name']}")
            elif known_good and not flag:
                flag, severity = f"Known good: {match['set_name']}", ''
                tip = 'In a known-good hash set'

            for column, value in ((12, mime),
                                  (13, f"{entropy:.2f}" if entropy else ''),
                                  (14, flag)):
                cell = QTableWidgetItem(str(value))
                if column == 14 and flag and severity:
                    # The flag is the one thing here worth colouring: it is a
                    # claim that something is wrong, and it should not read
                    # like another metadata column. Theme-aware, so it stays
                    # legible in dark mode -- #C62828 did not.
                    cell.setForeground(verdict_brush(
                        'malicious' if severity == 'suspicious'
                        else 'suspicious'))
                    # A hidden-data flag carries its finding as the tip.
                    if not tip and mismatch == 'suspicious':
                        tip = (f"Claims .{facts.get('extension') or ''}, "
                               f"content is {mime}")
                    elif not tip and mismatch == 'notable':
                        tip = (f"Claims .{facts.get('extension') or ''}, but "
                               f"the content cannot be identified and scores "
                               f"{entropy:.2f} of a possible 8.00")
                    elif not tip:
                        tip = f"Entropy {entropy:.2f} of a possible 8.00"
                    cell.setToolTip(tip)
                elif column == 14 and flag:
                    cell.setToolTip(tip)
                self.listing_table.setItem(row, column, cell)
        # The list and icon views hide what the table hides.
        if getattr(self, 'listing_icon_view', None) is not None:
            self.listing_icon_view.sync_hidden()
        if concealed_rows:
            self.set_status(f"{concealed_rows:,} known-good file(s) hidden "
                            f"here (Tools ▸ Hash Sets)")

    def mark_bookmarked_rows(self):
        """Put the bookmark mark on rows that have one, in place.

        Called after a bookmark is added or removed so the listing updates
        without being rebuilt -- rebuilding would lose the scroll position and
        the selection the examiner is working from.
        """
        if not hasattr(self, 'listing_table'):
            return
        listing_evidence = self.evidence_id_for_path(self._listing_image)
        for row in range(self.listing_table.rowCount()):
            name_cell = self.listing_table.item(row, 0)
            type_cell = self.listing_table.item(row, 2)
            if name_cell is None or type_cell is None:
                continue
            payload = name_cell.data(Qt.UserRole) or {}
            inode = payload.get('inode_number')
            ref = (make_artifact_ref(payload.get('start_offset', 0), inode,
                                     payload.get('sequence'))
                   if inode is not None else None)
            bookmarked = bool(ref and (listing_evidence, ref)
                              in self._bookmarked_refs)

            font = name_cell.font()
            font.setBold(bookmarked)
            name_cell.setFont(font)
            if bookmarked:
                type_cell.setIcon(icons.icon(icons.BOOKMARK))
                type_cell.setToolTip("Bookmarked in this case.")
            else:
                type_cell.setIcon(QIcon())
                type_cell.setToolTip("")

    def _reload_bookmarked_refs(self):
        """Cache which artifacts are bookmarked, for the listing to mark."""
        self._bookmarked_refs = set()
        if not self.case:
            return
        for row in self.case.bookmarks():
            ref = row.get('artifact_ref')
            if ref:
                # With its image: an artifact_ref is partition, inode and
                # sequence, which another device's file can share.
                self._bookmarked_refs.add((row.get('evidence_id'), ref))

    def refresh_bookmarks(self):
        """Redraw both views of the bookmark list.

        The tree node and the dock panel show the same rows; refreshing one
        and forgetting the other is how they drift apart.
        """
        self._reload_bookmarked_refs()
        if getattr(self, 'bookmarks_panel', None) is not None:
            self.bookmarks_panel.refresh()
        self.refresh_bookmarks_tree()
        # Both places a file is shown pick the change up now, rather than the
        # next time the directory happens to be rebuilt -- a bookmark removed
        # used to stay marked until the examiner navigated away and back.
        self.mark_bookmarked_rows()
        self.mark_bookmarked_tree_items()

    def refresh_bookmarks_tree(self):
        """Rebuild the Bookmarks node at the top of the tree.

        Bookmarks sit beside the evidence rather than in a panel of their own,
        because the tree is already where an examiner looks to find where
        something is. The node is only present when there is a case and at
        least one bookmark -- an empty node is a permanent reminder of a
        feature rather than a way into anything.
        """
        # Drop the previous node, wherever it ended up.
        for index in range(self.tree_viewer.topLevelItemCount() - 1, -1, -1):
            item = self.tree_viewer.topLevelItem(index)
            data = item.data(0, Qt.UserRole) or {}
            if data.get('is_bookmarks_root'):
                self.tree_viewer.takeTopLevelItem(index)

        if not self.case:
            return

        rows = self.case.bookmarks()
        self._bookmarked_refs = {(r.get('evidence_id'), r['artifact_ref'])
                                 for r in rows if r.get('artifact_ref')}
        if not rows:
            return

        root = QTreeWidgetItem(self.tree_viewer)
        root.setText(0, f"Bookmarks ({len(rows)})")
        root.setIcon(0, icons.icon(icons.BOOKMARK))
        root.setData(0, Qt.UserRole, {'is_bookmarks_root': True})
        # First, so it is the first thing seen rather than buried under a
        # long evidence tree.
        self.tree_viewer.insertTopLevelItem(0, self.tree_viewer.takeTopLevelItem(
            self.tree_viewer.indexOfTopLevelItem(root)))
        root = self.tree_viewer.topLevelItem(0)

        for row in rows:
            child = QTreeWidgetItem(root)
            child.setText(0, row.get('label') or '(unlabelled)')
            child.setToolTip(0, row.get('artifact_path')
                             or row.get('artifact_name') or '')
            name = row.get('artifact_name') or ''
            if '.' in name:
                child.setIcon(0, self._get_file_icon(
                    name.rsplit('.', 1)[-1].lower()))
            else:
                # No extension to go on: the bookmark glyph says what the row
                # is, rather than a generic unknown-file mark that says
                # nothing.
                child.setIcon(0, icons.icon(icons.BOOKMARK))
            # Marked as a bookmark so a click resolves it rather than trying
            # to read an inode the tree does not have.
            child.setData(0, Qt.UserRole, {'is_bookmark': True,
                                           'bookmark': row})

        root.setExpanded(True)

    def go_to_bookmark(self, row):
        """Open whatever a bookmark points at.

        This is the one place that turns an artifact reference back into a
        selection, shared by bookmarks and by search results. It replaces
        show_file_in_directory, which hardcoded parent_inode = 5 and so landed
        every deep file at the volume root with nothing selected.
        """
        parsed = parse_artifact_ref(row.get('artifact_ref'))
        if not self.activate_evidence(row.get('evidence_id')):
            return

        if parsed['kind'] == 'span':
            self.preview_artifact(row)
            return
        if parsed['kind'] != 'file':
            # Registry keys need their own viewer; say so rather than
            # silently doing nothing.
            self.set_status(
                f"{row.get('label') or 'Bookmark'} points at a "
                f"{parsed['kind']}, which opens in its own viewer.")
            return

        if not self.image_handler:
            message.information(self, "No image loaded",
                                "Load the evidence this bookmark belongs to "
                                "first.")
            return

        offset, inode = parsed['start_offset'], parsed['inode']
        try:
            content, metadata = self.image_handler.get_file_content(inode, offset)
        except Exception as exc:
            logger.error("Could not open bookmarked artifact: %s", exc)
            message.warning(self, "Could not open",
                            f"The bookmarked item could not be read: {exc}")
            return

        data = {
            'inode_number': inode,
            'start_offset': offset,
            'type': 'file',
            'name': row.get('artifact_name') or f'inode {inode}',
            'path': row.get('artifact_path') or '',
            'size': getattr(metadata, 'size', 0) if metadata else 0,
        }
        self.current_selected_data = data

        # Show the file where an examiner is actually looking: the listing,
        # positioned in the directory that holds it, with the file selected.
        # Selecting it in the tree alone left the listing showing whatever was
        # there before, so a bookmark appeared to do nothing.
        self.show_listing_for_artifact(data)
        self.select_tree_item_by_inode(inode, offset)
        self.update_viewer_with_file_content(content, data)
        self.set_status(f"Opened {data['name']}")

    def on_item_double_clicked(self, item, _column):
        """Double-click on a bookmark or finding: go to the file's folder."""
        data = item.data(0, Qt.UserRole) or {}
        if data.get('is_bookmark'):
            self.go_to_bookmark(data['bookmark'])
        elif data.get('is_finding'):
            self.open_finding(data['finding'])

    def preview_artifact(self, row):
        """Show the file `row` refers to in the viewers, and stay put.

        `row` is any of the shapes that carry an artifact_ref: a bookmark, a
        finding, a search result, a VirusTotal entry. Nothing here touches the
        Listing or the result tabs -- the examiner stepping down a list of
        findings stays on that list, and only the viewer dock changes.
        go_to_bookmark is the other half: the deliberate trip to the folder.
        """
        ref = row.get('artifact_ref')
        parsed = parse_artifact_ref(ref)
        name = (row.get('artifact_name') or row.get('name')
                or row.get('label') or '')
        # The reference is only partition, inode and sequence: it means a
        # file only on the image it came from. Read that image or nothing.
        if not self.activate_evidence(row.get('evidence_id')):
            return
        ref_key = f"{row.get('evidence_id')}:{ref}"
        if parsed['kind'] == 'span':
            # Carved data, or a bookmarked byte range: read it back.
            name = name or f"{parsed['begin']:x}"
            self.preview_carved({
                'evidence_id': row.get('evidence_id'),
                'name': name,
                'offset': parsed['begin'],
                'size': parsed['end'] - parsed['begin'],
                'type': name.rsplit('.', 1)[-1] if '.' in name else '',
                'embedded_date': row.get('embedded_date'),
                'date_source': row.get('date_source'),
            })
            return
        if parsed['kind'] != 'file':
            self.set_status(
                f"{name or 'This item'} is a {parsed['kind']} reference — "
                f"double-click to open it.", 5000)
            return
        if not self.image_handler:
            self.set_status("Load the evidence this belongs to first.", 5000)
            return

        # Selection and click both report the same row; the second is a
        # repeat of what is already on screen.
        current = self.current_selected_data or {}
        if current.get('_preview_ref') == ref_key:
            return

        data = {
            'inode_number': parsed['inode'],
            'start_offset': parsed['start_offset'],
            'sequence': parsed['sequence'],
            'type': 'file',
            'name': name or f"inode {parsed['inode']}",
            'path': row.get('artifact_path') or row.get('path') or '',
            '_preview_ref': ref_key,
        }
        self.clear_viewers()
        self.current_selected_data = data
        self.update_status_for_selection(data)

        if self.active_viewer_adapter() is None:
            # The VirusTotal tab shows reports, not files. Bring a file viewer
            # forward; its tab change displays the selection.
            self.viewer_tab.setCurrentWidget(self.viewer_adapters[0].widget)
        else:
            self.display_content_for_active_tab()
        self.viewer_dock.show()

    def preview_search_result(self, row):
        """A search hit, previewed -- including one inside an archive."""
        if row.get('kind') == 'archive-member':
            self.preview_archive_member(row)
            return
        self.preview_artifact(row)

    def preview_archive_member(self, row):
        """Read a member out of its archive, in memory, and show it.

        The hit's path names the chain -- 'a.zip!/b.zip!/c.jpg' -- and its
        artifact_ref names the outermost archive, which is the only part that
        exists as a file on the volume. Nothing is extracted to disk.
        """
        parsed = parse_artifact_ref(row.get('artifact_ref'))
        chain = (row.get('path') or '').split('!/')
        name = row.get('name') or chain[-1]
        if parsed['kind'] not in ('file', 'span') or len(chain) < 2:
            self.set_status(f"Cannot locate {name} inside its archive.", 5000)
            return
        if not self.image_handler:
            self.set_status("Load the evidence this belongs to first.", 5000)
            return

        if not self.activate_evidence(row.get('evidence_id')):
            return
        key = f"{row.get('evidence_id')}:{row.get('path')}"
        if (self.current_selected_data or {}).get('_preview_ref') == key:
            return
        try:
            if parsed['kind'] == 'span':
                # Inside a carved file: read back from the image (and its
                # fragments, if it was rebuilt from them).
                content = self._read_carved({
                    'evidence_id': row.get('evidence_id'),
                    'offset': parsed['begin'],
                    'size': parsed['end'] - parsed['begin']})
            else:
                content = self._archive_source(row.get('evidence_id'),
                                               parsed)
            for member in chain[1:]:
                content = archives.read_member(content or b'', member)
        except archives.EncryptedArchive:
            self.set_status(f"{name} is in an encrypted archive; it needs a "
                            f"password to read.", 6000)
            return
        except Exception as exc:
            logger.error("Could not read %s from its archive: %s", key, exc)
            self.set_status(f"Could not read {name} from its archive: {exc}",
                            6000)
            return

        self.clear_viewers()
        if self.active_viewer_adapter() is None:
            self.viewer_tab.setCurrentWidget(self.viewer_adapters[0].widget)
        self.open_archive_member(name, content)
        self.current_selected_data['_preview_ref'] = key
        self.viewer_dock.show()

    def _archive_source(self, evidence_id, parsed):
        """The outermost archive of a member's chain: a mailbox as a
        stream from the image (kept for the next member, so it is parsed
        once), anything else read whole."""
        key = (evidence_id, parsed['start_offset'], parsed['inode'])
        cached = getattr(self, '_streamed_archive', None)
        if cached and cached[0] == key:
            return cached[1]
        stream = self.image_handler.open_file_object(parsed['inode'],
                                                     parsed['start_offset'])
        if stream is not None and \
                archives.detect_archive(stream) in archives.STREAMED_KINDS:
            self._streamed_archive = (key, stream)
            return stream
        content, _ = self.image_handler.get_file_content(
            parsed['inode'], parsed['start_offset'])
        return content

    def show_triage(self, group=None, evidence_id=None):
        """Bring the Triage tab forward, on `group`'s sub-tab if given, and
        narrowed to one image if `evidence_id` is."""
        self.result_viewer.setCurrentWidget(self.triage_panel)
        self.triage_panel.set_evidence_filter(evidence_id)
        if group:
            self.triage_panel.show_group(group)

    def show_listing_for_artifact(self, data):
        """List the directory holding `data`, and select the file in it.

        Uses the parent recorded in the filesystem rather than a path string,
        so it works at any depth and on any filesystem -- the reason the old
        show_file_in_directory could only ever land at the volume root.
        """
        offset = data.get('start_offset')
        inode = data.get('inode_number')
        if offset is None or inode is None:
            return

        parent = None
        fs_info = None
        try:
            fs_info = self.image_handler.get_fs_info(offset)
        except Exception as exc:
            logger.debug("Could not open the filesystem at %s: %s",
                         offset, exc)

        # By path first. open_meta(inode=...) returns a file with no name
        # entry -- info.name is None -- so it cannot say what the parent is,
        # and every file outside the root used to fall through to the root
        # and select nothing. Opening the same file by path does carry the
        # name entry, and with it the real par_addr.
        artifact_path = (data.get('path') or '').replace('\\', '/')
        if fs_info is not None and artifact_path:
            try:
                located = fs_info.open(artifact_path)
                parent = getattr(located.info.name, 'par_addr', None)
            except Exception as exc:
                logger.debug("Could not open %s by path: %s",
                             artifact_path, exc)

        # No path, or the path no longer resolves: ask by inode anyway. It
        # answers for some filesystems, and costs nothing when it does not.
        if parent is None and fs_info is not None:
            try:
                meta = fs_info.open_meta(inode=inode)
                parent = getattr(meta.info.name, 'par_addr', None)
            except Exception as exc:
                logger.debug("Could not find the parent of inode %s: %s",
                             inode, exc)

        # Last resort: the directory the path names, resolved directly. This
        # is what recovers a file whose own entry has gone.
        if parent is None and fs_info is not None and '/' in artifact_path:
            directory = artifact_path.rsplit('/', 1)[0] or '/'
            try:
                parent = fs_info.open_dir(path=directory).info.fs_file.meta.addr
            except Exception as exc:
                logger.debug("Could not open directory %s: %s", directory, exc)

        if parent is None:
            parent = self.image_handler.get_root_inode(offset)

        try:
            entries = self.image_handler.get_directory_contents(offset, parent)
        except Exception as exc:
            logger.debug("Could not list the parent directory: %s", exc)
            return

        # The listing's Path column is built from current_path; left as it
        # was, every row read '/<name>' as if the folder were the root.
        if parent == self.image_handler.get_root_inode(offset):
            self.current_path = '/'
        elif '/' in artifact_path.strip('/'):
            self.current_path = '/' + artifact_path.strip('/').rsplit('/', 1)[0]

        if not self.show_listing_entries(entries, offset,
                                         data.get('name') or 'This folder'):
            return

        # Put the cursor on the file itself, so the row is visible and the
        # other tabs describe it.
        for row in range(self.listing_table.rowCount()):
            cell = self.listing_table.item(row, 0)
            payload = cell.data(Qt.UserRole) if cell else None
            if payload and payload.get('inode_number') == inode:
                self.listing_table.selectRow(row)
                self.listing_table.scrollToItem(cell)
                break

    # --- case ------------------------------------------------------------

    def load_case_evidence(self):
        """Open the images this case already holds.

        Reopening a case should put the examiner back where they were. Each
        image is verified as present first: evidence that has moved or changed
        is reported once, together, rather than as a string of failures that
        looks like the application is broken.
        """
        if not self.case:
            return

        rows = self.case.evidence()
        if not rows:
            return

        missing = []
        opened = 0
        from trace_app.core.live_disk import is_device_path
        # A New Case wizard's jobs wait for this (start_case_setup).
        self._loading_case_evidence = True
        try:
            for row in rows:
                path = row['path']
                # A live disk has no file to find: it is reconnected (the
                # administrator prompt again).
                if not is_device_path(path) and not os.path.exists(path):
                    missing.append((row, 'is not where the case recorded '
                                         'it'))
                    continue
                if self.open_evidence_image(path, record_in_case=False):
                    opened += 1
                else:
                    missing.append((row, 'could not be opened'))
        finally:
            self._loading_case_evidence = False
        pending, self._pending_setup = getattr(self, '_pending_setup',
                                               None), None
        if pending:
            QTimer.singleShot(0, lambda: self.start_case_setup(pending))

        if opened:
            self.set_status(
                f"Reopened {opened} of {len(rows)} piece(s) of evidence")
        # Reopening kept the window busy while the taskbar asked for its
        # icon: send it again now that it can answer.
        self.refresh_taskbar_icon()

        if missing:
            lines = [f"{row.get('display_name') or row['path']} {why}"
                     for row, why in missing]
            message.warning(
                self, "Some evidence could not be opened",
                f"{len(missing)} of {len(rows)} piece(s) of evidence in this "
                f"case could not be loaded.",
                "\n".join(lines)
                + "\n\nUse Case ▸ Verify All Evidence to check the rest, or "
                  "add the image again from its new location.")

    def _seed_verification_from_case(self):
        """Rebuild the in-memory verification map from stored hashes.

        A case records the digests themselves, so a reopened case can show an
        image as verified without reading it again. Only evidence that was
        actually hashed counts: an entry added but never verified stays
        unverified rather than inheriting a green tick it never earned.
        """
        for row in self.case.evidence():
            if not (row.get('md5') or row.get('sha1')):
                continue
            hashes = {
                'computed_md5': row.get('md5'),
                'computed_sha1': row.get('sha1'),
                'computed_sha256': row.get('sha256'),
                'stored_md5': row.get('stored_md5'),
                'stored_sha1': row.get('stored_sha1'),
                'size': row.get('size'),
                'path': row['path'],
            }
            self.verification_results[row['path']] = {
                'html': None,       # re-rendered on demand by the dialog
                'verified': row.get('last_status') == 'verified',
                'hashes': hashes,
            }

    def _case_title(self):
        """Window title, naming the case when there is one."""
        base = f'TRACE {__version__}'
        if not self.case:
            return base
        number = self.case.number
        name = self.case.name or 'Untitled case'
        return f'{base}  —  {name}' + (f' ({number})' if number else '')

    def record_evidence_in_case(self, image_path):
        """Add an image to the open case, if there is one."""
        if not self.case:
            return
        try:
            self.case.add_evidence(image_path)
        except Exception as exc:
            # A case that cannot record evidence must not stop the examiner
            # looking at it; the panel will show the discrepancy.
            logger.error("Could not record evidence in the case: %s", exc)
            return
        # The new image joins Triage's filter and the images carving offers
        # at once. Without this the filter did not list it until the case was
        # reopened, so choosing it fell back to "All evidence" -- and a carve
        # meant for the new image ran on every one.
        self.triage_panel.set_case(self.case)
        self._refresh_carving_targets()

    def store_verification_in_case(self, image_path, results):
        """Persist computed hashes against the case's evidence row."""
        if not self.case or not results:
            return
        hashes = results.get('hashes')
        if not hashes:
            return
        row = self.case.evidence_for_path(image_path)
        if row is None:
            row_id = self.case.add_evidence(image_path)
        else:
            row_id = row['id']
        try:
            self.case.record_hashes(row_id, hashes)
        except Exception as exc:
            logger.error("Could not store hashes in the case: %s", exc)
        if getattr(self, 'case_panel', None):
            self.case_panel.refresh()

    def show_case_properties(self):
        """Show, and allow editing of, the open case's details."""
        if not self.case:
            return
        from trace_app.ui.dialogs.case_launcher import CasePropertiesDialog
        dialog = CasePropertiesDialog(self.case, self)
        if dialog.exec() == QDialog.Accepted:
            self.setWindowTitle(self._case_title())
            if getattr(self, 'case_panel', None):
                self.case_panel.refresh()

    def verify_case_evidence(self):
        """Re-check every piece of evidence against its recorded hash (and
        hash any never hashed), as jobs on the bar: hashing an image on the
        UI thread froze the window for as long as it took."""
        if not self.case:
            return
        rows = self.case.evidence()
        if not rows:
            message.information(self, "No evidence",
                                "This case has no evidence to check yet.")
            return
        self.queue_verification(rows, summary=True)

    def open_case_folder(self):
        """Show the case folder in the system file manager."""
        if not self.case:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.case.folder))

    def _add_panel_toggles(self):
        """Put a show/hide entry in View for each dockable panel.

        Called after the docks are built, because the menu bar is constructed
        first and these actions cannot exist before the docks they belong to.

        Qt's own toggleViewAction is used rather than a hand-written action, so
        the menu tick and the panel's own close button cannot disagree about
        whether it is open.
        """
        self._view_menu.addSeparator()

        for dock, label in ((self.tree_dock, "Tree View"),
                            (self.viewer_dock, "Utils Panel")):
            action = dock.toggleViewAction()
            action.setText(label)
            self._view_menu.addAction(action)

        # Not a dock toggle: the tab is closed by its own button and reopened
        # here, or by the next lookup.
        vt_action = self._view_menu.addAction("VirusTotal Results")
        icons.apply_to(vt_action, icons.SEARCH_BROWSER)
        vt_action.triggered.connect(self.show_vt_panel)

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)
        self.search_panel.setEnabled(state)


    @staticmethod
    def create_tree_item(parent, text, icon_path, data):
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, data)
        return item


    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)
        self.clear_evidence_views()
        self.set_status_context("No evidence loaded")
        self.current_image_path = None
        self.current_offset = None
        self.evidence_files.clear()
        self._refresh_carving_targets()

        # Clear search bar and reset filters
        self.listing_search_bar.clear()

        # Clear navigation history
        self._directory_history = []
        self._history_index = -1
        self._update_navigation_buttons()

        # Disable directory up button
        self.go_up_action.setEnabled(False)

    def active_viewer_adapter(self):
        """Adapter for the currently selected viewer tab, or None.

        Matched by widget, not by index: the VirusTotal tab comes and goes,
        so a tab's position no longer says which viewer it is.
        """
        widget = self.viewer_tab.currentWidget()
        for adapter in self.viewer_adapters:
            if adapter.widget is widget:
                return adapter
        return None

    def clear_viewers(self):
        """Empty the file viewers, ready for another file.

        The registry browser is deliberately left alone. It shows a hive
        extracted from the image, not the selected file, so clearing it here
        threw away a loaded hive every time the user clicked a file -- and
        reloading one takes seconds.
        """
        for adapter in self.viewer_adapters:
            adapter.clear()

    def clear_evidence_views(self):
        """Empty everything tied to the loaded image, registry included."""
        self.clear_viewers()
        self.registry_extractor_widget.clear()

    def closeEvent(self, event):
        """Handle application close event."""
        if not self._confirm_exit():
            event.ignore()
            return

        self.save_layout()
        # Cleanup resources
        self.cleanup_resources()
        event.accept()

    def cleanup_resources(self):
        """Clean up all resources when closing the application."""
        # Background jobs first, and cooperatively. The sweep below looks for
        # QThreads held on attributes and calls quit() on them; the analysis
        # worker is held in _active_workers instead, and quit() would not stop
        # it anyway -- it ends an event loop, and this thread is inside a walk
        # over the evidence. Left running, it would keep reading an image
        # whose handler is closed a few lines further down.
        try:
            if getattr(self, 'job_bar', None) is not None:
                self.job_bar.cancel_all()
            if getattr(self, 'vt_worker', None) is not None:
                self.vt_worker.stop()
            for worker in list(getattr(self, '_active_workers', ())):
                if hasattr(worker, 'stop'):
                    worker.stop()
            for worker in list(getattr(self, '_active_workers', ())):
                if worker.isRunning():
                    # Generous, because the wait is for the current file to
                    # finish rather than for the whole run.
                    worker.wait(5000)
        except Exception as exc:
            logger.error("Error stopping background jobs: %s", exc)

        # Clean up application viewer first to ensure media players are properly shut down
        try:
            if hasattr(self, 'application_viewer'):
                if hasattr(self.application_viewer, 'shutdown'):
                    self.application_viewer.shutdown()
                else:
                    self.application_viewer.clear()
        except Exception as e:
            logger.error(f"Error shutting down application viewer: {e}")

        # Stop any running background operations
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            # Check if it's a thread and running
            if isinstance(attr, QThread) and hasattr(attr, 'isRunning') and attr.isRunning():
                try:
                    # Try to stop it gracefully
                    attr.quit()
                    attr.wait(1000)  # Wait up to 1 second

                    # If still running, terminate it
                    if attr.isRunning():
                        attr.terminate()
                except Exception as e:
                    logger.error(f"Error stopping thread {attr_name}: {str(e)}")

        # Every image in the case was open, not just the active one.
        self._close_image_handlers()

        # Handlers opened for other evidence hold file descriptors of their
        # own, so they have to be closed too.
        for path, handler in getattr(self, '_auxiliary_handlers', {}).items():
            try:
                handler.close_resources()
            except Exception as e:
                logger.error("Error closing handler for %s: %s", path, e)
        if hasattr(self, '_auxiliary_handlers'):
            self._auxiliary_handlers.clear()

        # The search index holds a connection and may have a worker walking
        # the image; both have to stop before the handler closes under them.
        for panel in ('search_panel', 'indicators_panel', 'activity_panel',
                      'ntfs_panel', 'hash_panel', 'timeline_panel',
                      'persistence_panel', 'map_panel', 'similar_panel',
                      'registry_extractor_widget'):
            if getattr(self, panel, None) is not None:
                try:
                    getattr(self, panel).shutdown()
                except Exception as exc:
                    logger.error("Error closing the search index: %s", exc)

        # A case holds an open SQLite connection; closing it also writes
        # the closing line of the audit trail.
        if getattr(self, 'case', None) is not None:
            try:
                self.case.close()
            except Exception as exc:
                logger.error("Error closing case: %s", exc)


        # Close database connection
        if hasattr(self, 'db_manager') and self.db_manager:
            try:
                self.db_manager.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}")

        # Clean up temp files
        temp_dir = tempfile.gettempdir()
        try:
            for item in os.listdir(temp_dir):
                if item.startswith("trace_temp_"):
                    item_path = os.path.join(temp_dir, item)
                    try:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                        elif os.path.isdir(item_path):
                            import shutil
                            shutil.rmtree(item_path)
                    except Exception as e:
                        logger.error(f"Error removing temp file {item_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error cleaning up temp files: {str(e)}")

        # Release any other resources
        gc.collect()  # Encourage garbage collection

    def load_image_evidence(self):
        """File > Add Evidence: the Add Evidence wizard in a case; in quick
        triage, a file picker straight to the image."""
        if self.case:
            self.add_evidence_to_case()
            return
        from trace_app.ui.widgets.evidence_intake import EVIDENCE_FILE_FILTER
        image_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", EVIDENCE_FILE_FILTER)
        if image_path:
            self.open_evidence_image(image_path)

    def load_folder_evidence(self):
        """A folder of collected files as evidence -- a triage collection
        (KAPE, Velociraptor, UAC), a phone's extraction, exported files.
        Read in place, never written to."""
        if self.case:
            self.add_evidence_to_case()
            return
        folder = QFileDialog.getExistingDirectory(self, "Select Evidence "
                                                        "Folder")
        if folder:
            self.open_evidence_image(folder)

    def add_live_disk(self):
        """File > Add Live Disk: choose a disk; in a case it goes through
        the Add Evidence wizard (described, analysed), in quick triage it
        opens at once."""
        from trace_app.ui.dialogs.live_disk import choose_live_disk
        device = choose_live_disk(self)
        if not device:
            return
        if self.case:
            self.add_evidence_to_case(paths=[device])
        else:
            self.open_evidence_image(device)

    def assemble_volume(self):
        """File > Assemble RAID or Multi-Disk Volume: members among the
        open evidence grouped (core/assembly.py); the chosen one is saved
        as a descriptor -- in the case folder, or the user's data folder in
        quick triage -- and added like any other evidence."""
        from trace_app.core import assembly
        from trace_app.infra.paths import user_data_dir
        from trace_app.ui.dialogs.assemble import choose_group
        handlers = dict(self._image_handlers)
        try:
            groups = assembly.find_groups(handlers)
        except Exception as exc:
            logger.exception("Looking for multi-disk volumes failed")
            message.critical(self, "Assemble Volume",
                             f"The open evidence could not be examined: "
                             f"{exc}")
            return
        names = {}
        if self.case:
            for path in handlers:
                row = self.case.evidence_for_path(path)
                if row and row.get('display_name'):
                    names[path] = row['display_name']
        group = choose_group(groups, names, self)
        if group is None:
            return
        folder = (os.path.join(self.case.folder, 'assembled') if self.case
                  else os.path.join(user_data_dir(), 'assembled'))
        try:
            path = assembly.write(folder, group)
        except OSError as exc:
            message.critical(self, "Assemble Volume",
                             f"The descriptor could not be saved: {exc}")
            return
        if self.case:
            self.add_evidence_to_case(paths=[path])
        else:
            self.open_evidence_image(path)

    def add_evidence_to_case(self, paths=None):
        """The Add Evidence wizard: items checked and described, modules
        chosen; then each is recorded, opened and its jobs queued."""
        from trace_app.ui.dialogs.case_wizard import AddEvidenceWizard
        if not self.case:
            return
        wizard = AddEvidenceWizard(self.case, self,
                                   libraries=self._rule_libraries(),
                                   paths=paths)
        if wizard.exec() != QDialog.Accepted or not wizard.setup:
            return
        setup = wizard.setup
        rows = []
        for item in setup['items']:
            try:
                evidence_id = self.case.add_evidence(
                    item['path'], item['display_name'], item['details'])
            except Exception as exc:
                logger.error("Could not record %s: %s", item['path'], exc)
                message.critical(self, "Could not add evidence",
                                 f"{item['path']} could not be recorded in "
                                 f"the case: {exc}")
                continue
            if self.open_evidence_image(item['path'], record_in_case=False):
                self.triage_panel.set_case(self.case)
                self._refresh_carving_targets()
            rows.append(next(r for r in self.case.evidence()
                             if r['id'] == evidence_id))
        if rows:
            self.queue_setup(rows, setup)

    def open_evidence_image(self, image_path, record_in_case=True):
        """Load an image and show it. Returns True when it opened.

        Separated from the file dialog so reopening a case can load the
        evidence it already knows about through exactly this code -- a second
        implementation of image loading would drift from this one, and this is
        what decides whether an image opens at all.
        """
        progress = None
        try:
            image_path = os.path.normpath(image_path)

            # Create a progress dialog to show loading status
            progress = QProgressDialog("Loading image...", "Cancel", 0, 100, self)
            progress.setWindowTitle("Loading Evidence")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(PROGRESS_MIN_DURATION)  # Show dialog only if operation takes more than threshold
            progress.setValue(10)

            # The images already open stay open. Closing the previous handler
            # here is what left an earlier image's branch of the tree reading
            # whichever image had been loaded since -- wrong evidence under
            # the right name.
            progress.setValue(20)
            QApplication.processEvents()

            previous = self._image_handlers.pop(image_path, None)
            if previous is not None:
                previous.close_resources()
            handler = self._open_handler(image_path, progress)
            if not handler.loaded:
                raise ValueError(
                    "The evidence could not be opened"
                    + (f": {handler.load_error}." if handler.load_error
                       else ". It may be corrupt, incomplete (a missing .E02 "
                            "segment, say), or an unsupported format."))
            progress.setValue(50)

            self._image_handlers[image_path] = handler

            # Add the image to evidence files list
            if image_path not in self.evidence_files:
                self.evidence_files.append(image_path)
            # A case remembers its evidence; triage does not. Skipped
            # when the case is what asked for this load, since the row is
            # already there.
            if record_in_case:
                self.record_evidence_in_case(image_path)
            if getattr(self, 'case_panel', None):
                self.case_panel.refresh()

            progress.setValue(70)
            self.activate_image(image_path)
            progress.setValue(80)

            # Load partitions into tree view
            QApplication.processEvents()
            self.load_partitions_into_tree(image_path)
            # The evidence tree just grew a root; keep bookmarks above it.
            self.refresh_bookmarks_tree()
            progress.setValue(100)

            # Enable all tabs since we have a valid image
            self.enable_tabs(True)
            return True

        except Exception as e:
            if progress is not None:
                progress.close()
            message.critical(self, "Error Loading Image", f"Failed to load image: {str(e)}")
            # Remove the image from evidence files if it was added but failed to load
            if image_path in self.evidence_files:
                self.evidence_files.remove(image_path)
            return False
        finally:
            # Closed however loading ended. Left open (an error, an early
            # return), its own timer showed it later, stuck part-way --
            # over the next dialog, as if the window had hung.
            if progress is not None:
                progress.close()
                progress.deleteLater()

    def _open_handler(self, image_path, progress):
        """An ImageHandler, opened on a thread with each volume's first
        reads done (partitions, file systems, root folders: cached, so the
        tree is built from memory). On the UI thread a live disk froze the
        window -- the administrator prompt is waited for, and the first
        listing of a big NTFS volume reads its whole MFT through the
        helper -- and a large image did the same, more briefly."""
        from trace_app.core.live_disk import is_device_path
        if is_device_path(image_path):
            progress.setLabelText(
                "Waiting for administrator approval, then reading the "
                "disk's partitions and file systems...")
        else:
            progress.setLabelText("Reading partitions and file systems...")
        # Cancel cannot stop a read already under way.
        progress.setCancelButton(None)
        opener = _HandlerOpener(image_path)
        self._retain_worker(opener)
        loop = QEventLoop()
        timer = QTimer()
        timer.setInterval(50)
        timer.timeout.connect(
            lambda: loop.quit() if opener.done.is_set() else None)
        timer.start()
        opener.start()
        if not opener.done.is_set():
            loop.exec()
        timer.stop()
        if opener.error is not None:
            raise opener.error
        return opener.handler

    def _close_image_handlers(self):
        for path, handler in list(self._image_handlers.items()):
            try:
                handler.close_resources()
            except Exception as exc:
                logger.error("Error closing handler for %s: %s", path, exc)
        self._image_handlers.clear()
        self.image_handler = None
        self._refresh_carving_targets()
        self._refresh_registry_evidence()

    def _refresh_registry_evidence(self):
        """Tell the Registry tab which evidence is open: it reads the one
        the examiner picks there, not the active image."""
        widget = getattr(self, 'registry_extractor_widget', None)
        if widget is None:
            return
        # Its threads open their own copy of each image, unlocked with the
        # keys this session holds.
        widget.unlocks_for = self._unlocks_for
        evidence = []
        for path, handler in self._image_handlers.items():
            row = self.case.evidence_for_path(path) \
                if getattr(self, 'case', None) is not None else None
            name = (row or {}).get('display_name') or os.path.basename(path)
            evidence.append((path, name, handler))
        widget.set_evidence(evidence)

    def activate_image(self, image_path):
        """Make `image_path` the image the window reads from.

        The one place the active image changes. Every consumer that reads
        evidence -- carving, the registry browser, metadata, search -- is
        pointed at it here, so none can be left reading the previous image.
        Returns False if the image is not open in this case.
        """
        if not image_path:
            return False
        image_path = os.path.normpath(image_path)
        handler = self._image_handlers.get(image_path)
        if handler is None:
            return False
        self._refresh_registry_evidence()
        if handler is self.image_handler and \
                image_path == self.current_image_path:
            return True

        self.image_handler = handler
        self.current_image_path = image_path
        # These widgets are built before any image is loaded, with
        # image_handler=None, and pointed at the active handler here.
        for widget in (self.registry_extractor_widget,
                       self.metadata_viewer):
            widget.set_image_handler(handler)
        self._refresh_carving_targets()
        self.set_status_context(
            f"{os.path.basename(image_path)}   ·   "
            f"{len(handler.get_partitions())} partitions")
        return True

    def activate_evidence(self, evidence_id):
        """Activate the image a case evidence row names. False if it cannot be
        -- the row is gone, or the image is not open -- in which case nothing
        must be read, rather than reading the active image instead."""
        if evidence_id is None or not self.case:
            return evidence_id is None
        row = next((r for r in self.case.evidence() if r['id'] == evidence_id),
                   None)
        if row is None or not self.activate_image(row['path']):
            name = os.path.basename(row['path']) if row else f"#{evidence_id}"
            self.set_status(f"{name} is not open; it cannot be read.", 6000)
            return False
        return True

    def evidence_id_for_path(self, image_path):
        """The case's id for an image, or None. Never creates a row."""
        if not self.case or not image_path:
            return None
        row = self.case.evidence_for_path(image_path)
        return row['id'] if row else None

    @staticmethod
    def _root_image_path(item):
        """The image path a top-level evidence node stands for."""
        data = item.data(0, Qt.UserRole) or {}
        path = data.get('image_path') or item.text(0)
        return os.path.normpath(path) if path else ''

    def image_of_item(self, item):
        """The image a tree node belongs to: the path its top-level node names.

        None for nodes outside any image -- Bookmarks, Findings.
        """
        while item is not None and item.parent() is not None:
            item = item.parent()
        if item is None:
            return None
        data = item.data(0, Qt.UserRole) or {}
        path = data.get('image_path') or item.text(0)
        path = os.path.normpath(path) if path else None
        return path if path in self._image_handlers else None

    def activate_item_image(self, item):
        """Activate the image a tree node belongs to, if it belongs to one."""
        path = self.image_of_item(item)
        return self.activate_image(path) if path else True

    # --- listing views -----------------------------------------------------

    def _build_listing_view_button(self):
        """A View button whose menu picks the listing's view; its icon is
        the view in use. The Carved files tab has the same one."""
        from trace_app.ui.widgets.listing_views import ViewButton
        self.listing_view_button = ViewButton()
        self.listing_view_button.chosen.connect(self.set_listing_view)
        self._listing_view_actions = self.listing_view_button.actions
        self.listing_toolbar.addWidget(self.listing_view_button)

    def set_listing_view(self, mode, remember=True):
        """Show the listing as `mode` (listing_views.MODES)."""
        from trace_app.ui.widgets.listing_views import MODES
        if mode not in MODES:
            mode = 'details'
        self.listing_view = mode
        if mode == 'details':
            self.listing_stack.setCurrentWidget(self.listing_table)
        else:
            self.listing_icon_view.set_mode(mode)
            self.listing_stack.setCurrentWidget(self.listing_icon_view)
        # Line icons are tinted at paint time, so this one follows the theme.
        self.listing_view_button.set_current(mode)
        if remember:
            from trace_app.infra.window_state import save_listing_view
            save_listing_view(mode)

    def _listing_view_activated(self, index, navigate):
        """A click (or double-click) in the list/icon view: what the same
        click on the table's row does."""
        item = self.listing_table.item(index.row(), 0)
        if item is not None:
            self.on_listing_table_item_clicked(item, navigate=navigate)

    def _listing_view_menu(self, position):
        """The listing's context menu, from the list/icon view: the menu
        reads the shared selection and needs only where to appear."""
        point = self.listing_icon_view.viewport().mapToGlobal(position)
        self.open_listing_context_menu(
            self.listing_table.viewport().mapFromGlobal(point))

    def _listing_handler(self):
        """The handler of the image the listing was filled from, not
        whichever is active."""
        path = os.path.normpath(self._listing_image) \
            if self._listing_image else None
        handler = self._image_handlers.get(path) if path else None
        return handler or self.image_handler

    def _listing_picture_bytes(self, data):
        """The bytes of a listing row's file, for its thumbnail (read on
        the thumbnail thread)."""
        handler = self._listing_handler()
        if handler is None or data.get('inode_number') is None:
            return None
        content, _meta = handler.get_file_content(data['inode_number'],
                                                  data['start_offset'])
        return content

    def _listing_head_bytes(self, data):
        """A listing row's first bytes, to tell by content whether it has
        a thumbnail (a renamed picture)."""
        from trace_app.ui.widgets.thumbnails import HEAD_BYTES
        handler = self._listing_handler()
        if handler is None or data.get('inode_number') is None:
            return None
        return handler.read_file_bytes(data['inode_number'],
                                       data['start_offset'], HEAD_BYTES)

    def _listing_video_device(self, data):
        """A stream over a listing row's video, for its thumbnail: read on
        demand from the image the listing was filled from, never whole."""
        from trace_app.core.stream_device import PyTsk3StreamDevice
        from PySide6.QtCore import QIODevice
        path = os.path.normpath(self._listing_image) \
            if self._listing_image else None
        handler = self._image_handlers.get(path) if path else None
        handler = handler or self.image_handler
        if handler is None or data.get('inode_number') is None:
            return None
        fs = handler.get_fs_info(data.get('start_offset'))
        if fs is None:
            return None
        entry = fs.open_meta(inode=data['inode_number'])
        size = int(entry.info.meta.size)
        if size <= 0:
            return None
        device = PyTsk3StreamDevice(entry, size)
        if not device.open(QIODevice.ReadOnly):
            return None
        return device

    def activate_listing_image(self):
        """Activate the image the listing was filled from."""
        return self.activate_image(self._listing_image) \
            if self._listing_image else True

    def remove_image_evidence(self):
        """File > Remove Evidence: take an image out of the session -- and,
        in a case, out of the case with everything recorded against it
        (Case.remove_evidence). The image file itself is never touched."""
        if not self.evidence_files:
            message.warning(self, "Remove Evidence",
                            "No evidence is currently loaded.")
            return False
        if self.job_bar.busy:
            # A job reads the image and writes rows against it: removing
            # either under it fails the job or leaves rows with no evidence.
            message.information(
                self, "Remove Evidence",
                "Background work is running. Wait for it to finish, or "
                "cancel it in the status bar, then remove the evidence.")
            return False

        names = {}
        for path in self.evidence_files:
            row = self.case.evidence_for_path(path) if self.case else None
            label = (row or {}).get('display_name') or os.path.basename(path)
            names[f"{label}   ({path})"] = path
        everything = "All evidence"
        if len(names) == 1:
            chosen = [next(iter(names.values()))]
        else:
            picked, ok = QInputDialog.getItem(
                self, "Remove Evidence", "Evidence to remove:",
                list(names) + [everything], 0, False)
            if not ok:
                return False
            chosen = list(names.values()) if picked == everything \
                else [names[picked]]

        if not message.question(self, "Remove Evidence",
                                self._removal_question(chosen),
                                informative=self._removal_details(chosen)):
            return False

        for path in chosen:
            self._remove_evidence(path)
        self._after_evidence_removed()
        self.set_status(
            f"Removed {len(chosen)} piece{'s' if len(chosen) != 1 else ''} "
            f"of evidence", 6000)
        return True

    def _removal_question(self, paths):
        what = os.path.basename(paths[0]) if len(paths) == 1 \
            else f"these {len(paths)} pieces of evidence"
        if self.case is None:
            return f"Close {what}?"
        return f"Remove {what} from the case?"

    def _removal_details(self, paths):
        """What removing `paths` deletes, said before it is done."""
        if self.case is None:
            return ("It is closed for this session. Nothing on disk is "
                    "changed.")
        lines = []
        for path in paths:
            row = self.case.evidence_for_path(path)
            if row is None:
                continue
            footprint = self.case.evidence_footprint(row['id'])
            notes = self.case.notes_for_evidence(row['id'])
            recorded = ', '.join(f"{count:,} {what}"
                                 for what, count in footprint)
            lines.append(f"{os.path.basename(path)}: "
                         f"{recorded or 'nothing recorded yet'}"
                         + (f"; {notes} note(s) kept" if notes else ''))
        return ("Deleted from the case: " + '\n'.join(lines) + "\n\n"
                "Its carved copies and search index entries go too. Notes "
                "are kept, and the audit trail records the removal. The "
                "image file itself is not touched -- add it again to "
                "re-examine it.")

    def _remove_evidence(self, path):
        """Close one image and, in a case, remove it from the case."""
        path = os.path.normpath(path)
        evidence_id = self.evidence_id_for_path(path)
        self._release_auxiliary_handler(path)
        handler = self._image_handlers.pop(path, None)
        if handler is not None:
            if handler is self.image_handler:
                self.image_handler = None
                self.current_image_path = None
            try:
                handler.close_resources()
            except Exception as exc:
                logger.error("Error closing %s: %s", path, exc)
        if path in self.evidence_files:
            self.evidence_files.remove(path)
        # Keys given for its volumes are forgotten with it.
        self._bitlocker_keys.pop(path, None)
        self.remove_from_tree_viewer(path)
        if self.case is not None and evidence_id is not None:
            try:
                self.case.remove_evidence(evidence_id)
            except Exception as exc:
                logger.error("Could not remove %s from the case: %s",
                             path, exc)
                message.critical(self, "Remove Evidence",
                                 f"{os.path.basename(path)} was closed but "
                                 f"could not be removed from the case: "
                                 f"{exc}")

    def _after_evidence_removed(self):
        """Redraw everything that showed the removed evidence's data."""
        remaining = list(self.evidence_files)
        self.clear_ui()
        # clear_ui forgets the open images; the others are still open.
        self.evidence_files.extend(remaining)
        self._refresh_registry_evidence()
        self._refresh_carving_targets()
        if remaining:
            self.activate_image(remaining[-1])
        else:
            self.enable_tabs(False)
        if self.case is not None:
            for panel in ('case_panel', 'carved_panel', 'notes_panel'):
                widget = getattr(self, panel, None)
                if widget is not None and hasattr(widget, 'refresh'):
                    widget.refresh()
            if getattr(self, 'search_panel', None) is not None:
                self.search_panel.reload_index()
            self.refresh_analysis_views()
            self.refresh_bookmarks()

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if self._root_image_path(item) == os.path.normpath(evidence_name):
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        # The image's own name, not its path: with several devices in a case
        # every root began "D:\Cases\..." and was cut off before the part
        # that differs. The path is kept in the data and the tooltip.
        root_item_tree = self.create_tree_item(self.tree_viewer,
                                               os.path.basename(image_path),
                                               self.db_manager.get_icon_path('device', 'media-optical'),
                                               {"start_offset": 0,
                                                "image_path": image_path})
        root_item_tree.setToolTip(0, image_path)

        if self.image_handler.container_note:
            root_item_tree.setToolTip(
                0, f"{image_path}\n{self.image_handler.container_note}")
        found = self.evidence_profile({'path': image_path})
        if found:
            root_item_tree.setToolTip(
                0, f"{root_item_tree.toolTip(0)}\n{found['summary']}")

        partitions = self.image_handler.get_partitions()

        # Check if the image has partitions or a recognizable file system
        if not partitions:
            kind = self.image_handler.volume_kind(0)
            if self.image_handler.encryption(0):
                # A volume image of an encrypted drive: what TSK would list
                # is its decoy (To Go's FAT32 discovery volume) or nothing.
                label, size = "Volume", self.image_handler.get_size()
                if self.image_handler.is_logical:
                    # An encrypted iPhone backup: a folder, so no media
                    # size -- what it takes on disk instead.
                    from trace_app.core.logical_sources import KIND_LABELS
                    facts = self.image_handler.logical_fs.facts
                    label = KIND_LABELS.get(facts.get('_locked') or
                                            self.image_handler.
                                            unlocked_kind(0), "Evidence")
                    size = facts.get('_stored_size')
                self._add_bitlocker_node(root_item_tree, 0, label, size)
            elif kind == 'lvm':
                self._add_lvm_nodes(root_item_tree, 0, "Volume")
            elif kind == 'apfs':
                self._add_apfs_nodes(root_item_tree, 0, "Volume")
            elif self.image_handler.has_filesystem(0):
                # The image has a filesystem but no partitions, populate root directory
                self.populate_contents(root_item_tree, {"start_offset": 0})
                self._add_shadow_copy_nodes(root_item_tree, 0, "Volume")
            else:
                # Entire image is considered as unallocated space
                size_in_bytes = self.image_handler.get_size()
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                unallocated_item_text = f"Unallocated Space: Size: {readable_size}"
                self.create_tree_item(root_item_tree, unallocated_item_text,
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": 0,
                                       "end_offset": size_in_bytes // self.image_handler.sector_size})
            return

        sector_size = self.image_handler.sector_size
        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * sector_size
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            kind = self.image_handler.volume_kind(start)
            if self.image_handler.encryption(start):
                self._add_bitlocker_node(
                    root_item_tree, start, f"vol{addr}", size_in_bytes,
                    f"{desc_str}: {start}-{end}", end)
                continue
            if kind in ('lvm', 'apfs'):
                group = QTreeWidgetItem(root_item_tree)
                group.setText(0, f"vol{addr} ({desc_str}: {start}-{end}, "
                                 f"Size: {readable_size}, "
                                 f"{'LVM volume group' if kind == 'lvm' else 'APFS container'})")
                group.setIcon(0, QIcon(self.db_manager.get_icon_path(
                    'device', 'drive-harddisk')))
                group.setData(0, Qt.UserRole, {
                    "inode_number": None, "start_offset": start,
                    "end_offset": end, "is_volume_group": True})
                (self._add_lvm_nodes if kind == 'lvm' else
                 self._add_apfs_nodes)(group, start, f"vol{addr}")
                group.setExpanded(True)
                continue
            fs_type = self.image_handler.get_fs_type(start)
            item_text = f"vol{addr} ({desc_str}: {start}-{end}, Size: {readable_size}, FS: {fs_type})"
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')
            data = {"inode_number": None, "start_offset": start, "end_offset": end}
            item = self.create_tree_item(root_item_tree, item_text, icon_path, data)

            # Determine if the partition is special or contains unallocated space
            special_partitions = ["Primary Table", "Safety Table", "GPT Header"]
            is_special = any(special_case in desc_str for special_case in special_partitions)
            is_unallocated = "Unallocated" in desc_str or "Microsoft reserved" in desc_str

            if is_special:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            elif is_unallocated:
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                # Directly add unallocated space under the partition
                self.create_tree_item(item, f"Unallocated Space: Size: {readable_size}",
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": start, "end_offset": end})
            else:
                if self.image_handler.check_partition_contents(start):
                    item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
                self._add_shadow_copy_nodes(root_item_tree, start,
                                            f"vol{addr}")

    # --- volumes inside partitions ---------------------------------------

    def _add_bitlocker_node(self, parent, start, label, size_in_bytes,
                            where='', end=None):
        """A BitLocker volume: locked until a key is given (right-click),
        then its decrypted file system -- and its shadow copies."""
        handler = self.image_handler
        kind = handler.encryption(start) or handler.unlocked_kind(start) \
            or 'bitlocker'
        name = containers.ENCRYPTION_NAMES.get(kind, kind)
        unlocked = handler.is_unlocked(start)
        inner_lvm = unlocked and handler.inner_kind(start) == 'lvm'
        holds = ('LVM volume group' if inner_lvm
                 else f"FS: {handler.get_fs_type(start)}")
        state = (f"{holds}, {name} unlocked" if unlocked
                 else f"{name}, locked -- right-click to unlock")
        size = (f"Size: {handler.get_readable_size(size_in_bytes)}, "
                if size_in_bytes else '')
        text = f"{label} ({where + ', ' if where else ''}{size}{state})"
        data = {"inode_number": None, "start_offset": start,
                "end_offset": end, "is_bitlocker": True,
                "encryption": kind, "volume_label": label}
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, icons.icon(icons.VOLUME_UNLOCKED if unlocked
                                   else icons.VOLUME_LOCKED))
        item.setData(0, Qt.UserRole, data)
        item.setToolTip(0, f"Encrypted with {name}. Right-click ▸ Unlock "
                           f"{name}… with a key for it." if not unlocked
                        else f"{name} volume, unlocked for this session.")
        if inner_lvm:
            # The usual encrypted Linux install: LVM inside LUKS, its
            # logical volumes under the unlocked volume.
            data['is_volume_group'] = True
            item.setData(0, Qt.UserRole, data)
            self._add_lvm_nodes(item, start, label)
            return item
        item.setChildIndicatorPolicy(
            QTreeWidgetItem.ShowIndicator if unlocked
            and handler.check_partition_contents(start)
            else QTreeWidgetItem.DontShowIndicator)
        if unlocked:
            self._add_shadow_copy_nodes(parent, start, label)
        return item

    def _add_shadow_copy_nodes(self, parent, start, label):
        """A node per Volume Shadow Copy of the volume at `start`, after
        it: the volume as it was when the snapshot was taken."""
        try:
            shadows = self.image_handler.shadow_copies(start)
        except Exception as exc:
            logger.warning("Could not read shadow copies at %s: %s", start,
                           exc)
            return
        for shadow in shadows:
            created = shadow['created'].strftime('%Y-%m-%d %H:%M:%S UTC') \
                if shadow['created'] else 'time unknown'
            item = QTreeWidgetItem(parent)
            item.setText(0, f"{label} — shadow copy {shadow['index'] + 1} "
                            f"({created})")
            item.setIcon(0, icons.icon(icons.SHADOW_COPY))
            item.setData(0, Qt.UserRole, {
                "inode_number": None, "start_offset": shadow['key'],
                "is_shadow_copy": True, "shadow_index": shadow['index'],
                "shadow_created": created, "volume_label": label})
            item.setToolTip(0, f"Volume Shadow Copy {shadow['index'] + 1} of "
                               f"{label}, taken {created}: the volume as it "
                               f"was then, read-only. Files deleted or "
                               f"changed since are here as they were.")
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)

    def _add_lvm_nodes(self, parent, start, label):
        """A node per logical volume of the LVM group at `start`."""
        try:
            volumes = self.image_handler.logical_volumes(start)
        except Exception as exc:
            logger.warning("Could not read LVM at %s: %s", start, exc)
            return
        for volume in volumes:
            fs_type = self.image_handler.get_fs_type(volume['key'])
            item = QTreeWidgetItem(parent)
            item.setText(0, f"{volume['group']} / {volume['name']} (Size: "
                            f"{self.image_handler.get_readable_size(volume['size'])}"
                            f", FS: {fs_type})")
            item.setIcon(0, QIcon(self.db_manager.get_icon_path(
                'device', 'drive-harddisk')))
            item.setData(0, Qt.UserRole, {
                "inode_number": None, "start_offset": volume['key'],
                "is_logical_volume": True,
                "volume_label": f"{label} {volume['name']}"})
            item.setToolTip(0, f"LVM logical volume {volume['name']} of "
                               f"volume group {volume['group']}")
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.ShowIndicator if self.image_handler
                .check_partition_contents(volume['key'])
                else QTreeWidgetItem.DontShowIndicator)

    def _add_apfs_nodes(self, parent, start, label):
        """A node per volume of the APFS container at `start`: locked
        ones until a key is given, like BitLocker's."""
        try:
            volumes = self.image_handler.apfs_volumes(start)
        except Exception as exc:
            logger.warning("Could not read APFS at %s: %s", start, exc)
            return
        for volume in volumes:
            self._apfs_volume_node(parent, volume, label)

    def _apfs_volume_node(self, parent, volume, label):
        name = volume['name'] or f"volume {volume['index'] + 1}"
        locked = volume['locked'] and not self.image_handler.is_unlocked(
            volume['key'])
        item = QTreeWidgetItem(parent)
        data = {"inode_number": None, "start_offset": volume['key'],
                "is_apfs_volume": True, "volume_label": f"APFS {name}"}
        if locked:
            data.update(is_bitlocker=True, encryption='apfs')
            item.setText(0, f"APFS {name} (encrypted, locked -- right-click "
                            f"to unlock)")
            item.setIcon(0, icons.icon(icons.VOLUME_LOCKED))
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
        else:
            # Once unlocked, libfsapfs no longer calls it locked; it was.
            encrypted = volume['locked'] or \
                self.image_handler.unlocked_kind(volume['key']) == 'apfs'
            item.setText(0, f"APFS {name} (FS: APFS"
                            f"{', encrypted, unlocked' if encrypted else ''})")
            item.setIcon(0, icons.icon(icons.VOLUME_UNLOCKED)
                         if encrypted else QIcon(
                self.db_manager.get_icon_path('device', 'drive-harddisk')))
            item.setChildIndicatorPolicy(
                QTreeWidgetItem.ShowIndicator if self.image_handler
                .check_partition_contents(volume['key'])
                else QTreeWidgetItem.DontShowIndicator)
        item.setData(0, Qt.UserRole, data)
        return item

    def unlock_bitlocker_item(self, item):
        """Ask for a key for the encrypted volume `item` stands for:
        BitLocker, FileVault 2, LUKS or an encrypted APFS volume."""
        from PySide6.QtWidgets import QDialog
        from trace_app.ui.dialogs.bitlocker import UnlockVolumeDialog
        if not self.activate_item_image(item):
            return
        data = item.data(0, Qt.UserRole) or {}
        start = data.get('start_offset', 0)
        kind = data.get('encryption') or 'bitlocker'
        name = containers.ENCRYPTION_NAMES.get(kind, kind)
        label = data.get('volume_label') or 'This volume'
        dialog = UnlockVolumeDialog(self.image_handler, start, label, self,
                                    kind)
        if dialog.exec() != QDialog.Accepted or not dialog.secret:
            return
        path = os.path.normpath(self.image_handler.image_path)
        self._bitlocker_keys.setdefault(path, {})[start] = dict(
            dialog.secret, _kind=kind)
        # What the image holds is known now: profile it again.
        self._evidence_profiles.pop(path, None)
        if getattr(self, 'case_panel', None):
            self.case_panel.refresh()
        # The Registry tab searches the unlocked volume too.
        self._refresh_registry_evidence()
        if self.case is not None:
            row = self.case.evidence_for_path(path)
            self.case.record_event(
                f"{name} volume unlocked",
                f"evidence id={row['id'] if row else '?'} "
                f"volume={label} key={start} with a {dialog.kind} "
                f"(the key is not recorded)")
        parent = item.parent() or self.tree_viewer.invisibleRootItem()
        index = parent.indexOfChild(item)
        parent.removeChild(item)
        if kind == 'apfs':
            volume = next(v for v in self.image_handler.apfs_volumes(
                containers.split_apfs_key(start)[0]) if v['key'] == start)
            fresh = self._apfs_volume_node(parent, volume, label)
            parent.removeChild(fresh)
            parent.insertChild(index, fresh)
            self.tree_viewer.setCurrentItem(fresh)
            fresh.setExpanded(True)
            self.set_status(f"{label} unlocked: its files can now be browsed,"
                            f" and analysis reads them too.")
            return
        size = self.image_handler.logical_fs.facts.get('_stored_size') \
            if self.image_handler.is_logical else \
            self.image_handler.partition_bytes(start)[1]
        fresh = self._add_bitlocker_node(parent, start, label, size,
                                         end=data.get('end_offset'))
        # Back where the locked node was, its shadow copies after it.
        parent.removeChild(fresh)
        parent.insertChild(index, fresh)
        self.tree_viewer.setCurrentItem(fresh)
        fresh.setExpanded(True)
        self.set_status(f"{label} unlocked: its files can now be browsed, "
                        f"and analysis reads them too.")

    def _unlocks_for(self, path):
        """The keys this session holds for an image, for a background job."""
        return dict(self._bitlocker_keys.get(os.path.normpath(path), {}))

    def populate_contents(self, item: QTreeWidgetItem, data: Dict[str, Any], inode: Optional[int] = None) -> None:
        """Populate tree widget item with directory contents."""
        if self.current_image_path is None:
            return

        entries = self.image_handler.get_directory_contents(data["start_offset"], inode)

        for entry in entries:
            self._create_tree_item_for_entry(item, entry, data["start_offset"])

    def on_item_expanded(self, item):
        # Check if the item already has children; if so, don't repopulate
        if item.childCount() > 0:
            return
        if not self.activate_item_image(item):
            return

        data = item.data(0, Qt.UserRole)
        if data is None:
            return
        if data.get('type') in ('file', 'archive-member'):
            # Only archives are expandable files.
            self._expand_archive_item(item)
            return

        if data.get("inode_number") is None:  # It's a partition
            self.populate_contents(item, data)
        else:  # It's a directory
            self.populate_contents(item, data, data.get("inode_number"))

    class FileContentWorker(QThread):
        """Worker thread class for handling file operations in the background."""
        completed = Signal(bytes, object)
        error = Signal(str)

        def __init__(self, image_handler, inode_number, offset):
            super().__init__()
            self.image_handler = image_handler
            self.inode_number = inode_number
            self.offset = offset

        def run(self):
            try:
                file_content, metadata = self.image_handler.get_file_content(self.inode_number, self.offset)
                if file_content:
                    self.completed.emit(file_content, metadata)
                elif self._is_empty():
                    # A volume label, $BadBlockFile, an empty log: read
                    # correctly, and nothing is in it -- not an error.
                    self.completed.emit(b'', metadata)
                else:
                    self.error.emit("Unable to read file content.")
            except Exception as e:
                self.error.emit(f"Error reading file: {str(e)}")

        def _is_empty(self):
            try:
                fs = self.image_handler.get_fs_info(self.offset)
                return fs is not None and not fs.open_meta(
                    inode=self.inode_number).info.meta.size
            except Exception:
                return False

    # Worker thread for opening media files for streaming (doesn't load content into memory)
    class MediaStreamWorker(QThread):
        completed = Signal(object, int, object)  # file_obj, file_size, metadata
        error = Signal(str)

        def __init__(self, image_handler, inode_number, offset):
            super().__init__()
            self.image_handler = image_handler
            self.inode_number = inode_number
            self.offset = offset

        def run(self):
            try:
                # Get filesystem info
                fs = self.image_handler.get_fs_info(self.offset)
                if not fs:
                    self.error.emit("Unable to get filesystem info.")
                    return

                # Open the file object (don't read content)
                file_obj = fs.open_meta(inode=self.inode_number)
                if not file_obj:
                    self.error.emit("Unable to open file.")
                    return

                file_size = file_obj.info.meta.size
                metadata = file_obj.info.meta

                if file_size == 0:
                    self.error.emit("File has no content or is a special metafile!")
                    return

                # Return the file object for streaming (don't read content)
                self.completed.emit(file_obj, file_size, metadata)

            except Exception as e:
                self.error.emit(f"Error opening file for streaming: {str(e)}")

    # Create a worker thread class for handling unallocated space operations in the background
    class UnallocatedSpaceWorker(QThread):
        completed = Signal(bytes)
        error = Signal(str)

        def __init__(self, image_handler, start_offset, end_offset):
            super().__init__()
            self.image_handler = image_handler
            self.start_offset = start_offset
            self.end_offset = end_offset

        def run(self):
            try:
                unallocated_space = self.image_handler.read_unallocated_space(self.start_offset, self.end_offset)
                if unallocated_space:
                    self.completed.emit(unallocated_space)
                else:
                    self.error.emit("Unable to read unallocated space.")
            except Exception as e:
                self.error.emit(f"Error reading unallocated space: {str(e)}")

    #: Index of the Listing tab in the result viewer.
    LISTING_TAB = 0

    def show_listing_entries(self, entries, start_offset, label=None):
        """Fill the listing with `entries` and bring it to the front.

        Nothing happens when there is nothing to show. Clicking an empty folder
        used to clear the listing and leave a blank table -- worse than useless,
        because whatever was on screen before was at least something. An empty
        directory is reported in the status bar instead, and the previous view
        stays put.

        Returns True when the listing was populated.
        """
        if not entries:
            name = label or "This folder"
            self.set_status(f"{name} is empty", 4000)
            return False

        self.populate_listing_table(entries, start_offset)
        # Selecting in the tree is a request to browse, so the Listing is what
        # the user wants in front -- not whichever of Deleted Files or Registry
        # they happened to leave open.
        self.result_viewer.setCurrentIndex(self.LISTING_TAB)
        return True

    def on_item_clicked(self, item, column):
        # A bookmark node resolves to its artifact; it has no inode of its own
        # for the ordinary tree handling below to read.
        data = item.data(0, Qt.UserRole) or {}
        # Bookmarks and findings are reviewed, not browsed: a click shows the
        # file in the viewers and leaves the Listing alone. Double-click (below)
        # is what goes to its folder.
        if data.get('is_bookmark'):
            self.preview_artifact(data['bookmark'])
            return
        if data.get('is_finding'):
            self.preview_finding(data['finding'])
            return
        # A group node opens its list in Triage, where each has a sub-tab.
        if data.get('is_bookmarks_root'):
            self.show_triage('bookmarks')
            return
        if data.get('is_analysis_root'):
            self.show_triage()
            return
        if data.get('is_activity_root') or data.get('is_activity_group'):
            self.show_activity(data.get('category'))
            return
        if data.get('is_analysis_group'):
            self.show_triage(data.get('group'), data.get('evidence_id'))
            if data.get('group') == 'indicators':
                self.indicators_panel.set_kind(data.get('indicator_kind'))
            if data.get('group') == 'keywords' and data.get('term'):
                self.keywords_panel.select_term(data.get('list_id'),
                                                data.get('term'))
            return

        # Everything below reads the image this node belongs to.
        if not self.activate_item_image(item):
            return

        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        if not data:
            return

        # Store the current selection data. The item goes along so a volume,
        # which carries no name in its data, can be labelled from its row.
        self.current_selected_data = data
        self.update_status_for_selection(data, item)

        # An archive, or a member inside one: opened like a folder.
        if data.get('type') == 'archive-member' or (
                data.get('type') == 'file' and
                (data.get('name') or '').lower().endswith(
                    TREE_ARCHIVE_SUFFIXES)):
            if self.on_tree_archive_clicked(item):
                return

        # Show a status message in the UI to indicate loading
        self.set_status("Loading content...")

        # Use a background worker thread if processing large files or unallocated space
        try:
            # Check if this is the root disk image item (has start_offset but no type/inode)
            if (data.get("start_offset") == 0 and
                not data.get("type") and
                not data.get("inode_number") and
                not data.get("is_unallocated")):
                # The image itself. A partitioned disk lists its volumes; an
                # image that is one bare filesystem -- a formatted USB stick,
                # a camera card, most small exhibits -- has no partition table
                # to list, so its root directory is what to show. Listing
                # partitions there produced an empty table.
                if self.image_handler.get_partitions():
                    self.display_volumes_in_listing()
                    self.result_viewer.setCurrentIndex(self.LISTING_TAB)
                elif self.image_handler.has_filesystem(0):
                    self.current_path = "/"
                    root_inode = self.image_handler.get_root_inode(0)
                    self.show_listing_entries(
                        self.image_handler.get_directory_contents(0, root_inode),
                        0, "This image")
                self.clear_status()
                return

            if data.get("is_unallocated"):
                # Handle unallocated space in background
                self.unallocated_worker = self.UnallocatedSpaceWorker(
                    self.image_handler, data["start_offset"], data["end_offset"])
                self.unallocated_worker.completed.connect(
                    lambda content: self.update_viewer_with_file_content(content, data))
                self.unallocated_worker.error.connect(
                    lambda msg: (self.log_error(msg), self.clear_status()))
                self.unallocated_worker.start()

            elif data.get("type") == "directory":
                # For directories, find parent inode to enable up navigation
                if "parent_inode" not in data and data.get("inode_number"):
                    parent_inode = self.find_parent_inode(data["start_offset"], data["inode_number"])
                    if parent_inode:
                        data["parent_inode"] = parent_inode
                        # Update the stored data with parent information
                        self.current_selected_data = data
                        self.update_status_for_selection(data)

                # Handle directories - populate the listing synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))

                # Update current path for directory navigation
                if data.get("name"):
                    if data.get("inode_number") == self.image_handler.get_root_inode(
                            data["start_offset"]):
                        self.current_path = "/"
                    else:
                        # If it's a regular directory, update the path
                        self.current_path = data.get("path", posixpath.join(self.current_path, data.get("name", "")))

                # An empty directory leaves the current view alone rather
                # than replacing it with a blank table.
                if not self.show_listing_entries(entries, data["start_offset"],
                                                 data.get("name")):
                    return

                # Update directory up button state
                self.update_directory_up_button()

                # Add to navigation history
                self._add_to_history(data)

                self.clear_status()

            elif data.get("inode_number") is not None:
                if self._show_in_hex_from_image(data):
                    return
                # Handle files in background
                self.file_worker = self._retain_worker(self.FileContentWorker(
                    self.image_handler, data["inode_number"], data["start_offset"]))
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), self.clear_status()))
                self.file_worker.start()

            elif data.get("start_offset") is not None:
                # Handle partitions
                # The root's number is the file system's: NTFS 5, FAT and
                # ext 2, Btrfs 256 -- never assumed.
                root_inode = self.image_handler.get_root_inode(
                    data["start_offset"])
                entries = self.image_handler.get_directory_contents(
                    data["start_offset"], root_inode)

                # Reset path to root when viewing partitions
                self.current_path = "/"

                # Treat partition as a volume for history
                if "type" not in data:
                    data["type"] = "volume"
                if data.get("inode_number") is None:
                    data["inode_number"] = root_inode

                if not self.show_listing_entries(entries, data["start_offset"],
                                                 data.get("name") or "This volume"):
                    return

                # Add to navigation history
                self._add_to_history(data)

                self.clear_status()

            else:
                self.log_error("Clicked item is not a file, directory, or unallocated space.")
                self.clear_status()

        except Exception as e:
            self.log_error(f"Error processing item: {str(e)}")
            self.clear_status()

    def update_directory_up_button(self):
        """Update the state of the directory up button based on current selection"""
        # Inside an archive there is always somewhere to go up to, whether
        # that is an outer archive or back to the filesystem.
        if self._archive_stack:
            self.go_up_action.setEnabled(True)
            return

        if not self.current_selected_data:
            self.go_up_action.setEnabled(False)
            return

        # Check if this is a directory
        if self.current_selected_data.get("type") == "directory":
            inode_number = self.current_selected_data.get("inode_number")
            start_offset = self.current_selected_data.get("start_offset")

            # At the volume root there is nowhere to go up to. Which inode
            # that is depends on the filesystem, so ask rather than assume.
            is_root = (start_offset is not None
                       and inode_number == self.image_handler.get_root_inode(start_offset))

            # If parent_inode isn't set yet, try to find it
            if "parent_inode" not in self.current_selected_data and not is_root and inode_number is not None:
                parent_inode = self.find_parent_inode(start_offset, inode_number)
                if parent_inode:
                    # Update the dictionary in place
                    self.current_selected_data["parent_inode"] = parent_inode

            has_parent = self.current_selected_data.get("parent_inode") is not None
            self.go_up_action.setEnabled(not is_root and has_parent)
        else:
            self.go_up_action.setEnabled(False)

    def find_parent_inode(self, start_offset, inode_number):
        """Helper method to find the parent inode for a directory from tree view"""
        try:
            # The volume root has no parent.
            if inode_number == self.image_handler.get_root_inode(start_offset):
                return None

            # Get directory entries for the directory
            entries = self.image_handler.get_directory_contents(start_offset, inode_number)

            # Look for parent directory entry (..)
            for entry in entries:
                if entry.get("name") == "..":
                    return entry.get("inode_number")

            # If we can't find the proper parent, return None
            return None

        except Exception as e:
            self.log_error(f"Error finding parent inode: {str(e)}")
            return None

    def navigate_up_directory(self):
        """Navigate to the parent directory"""
        # Inside an archive, Up means "out of this archive level" -- the
        # filesystem's parent directory is not where the user is.
        if self._archive_stack and self.leave_archive():
            return
        if not self.activate_listing_image():
            return

        if not self.current_selected_data:
            return

        # Ensure we have valid information
        start_offset = self.current_selected_data.get("start_offset")
        inode_number = self.current_selected_data.get("inode_number")

        if not start_offset or not inode_number:
            return

        # If parent_inode isn't already set, try to find it
        if "parent_inode" not in self.current_selected_data and self.current_selected_data.get("type") == "directory":
            parent_inode = self.find_parent_inode(start_offset, inode_number)
            if parent_inode:
                self.current_selected_data["parent_inode"] = parent_inode

        # Make sure we have a parent to navigate to
        parent_inode = self.current_selected_data.get("parent_inode")
        if not parent_inode:
            return

        self.set_status("Loading parent directory...")

        try:
            # Create data for parent directory
            parent_data = {
                "inode_number": parent_inode,
                "start_offset": start_offset,
                "type": "directory",
                # Get the grandparent inode if available (for consecutive up navigation)
                "parent_inode": self.get_grandparent_inode(parent_inode, start_offset)
            }

            # Update current path (navigate to parent directory)
            self.current_path = os.path.dirname(self.current_path)
            if self.current_path == "":
                self.current_path = "/"

            # Load the parent directory
            entries = self.image_handler.get_directory_contents(
                parent_data["start_offset"],
                parent_data["inode_number"]
            )

            self.current_selected_data = parent_data

            # Update directory up button state
            self.update_directory_up_button()

            # Update both the tree view selection and listing table
            self.populate_listing_table(entries, parent_data["start_offset"])

            # Add to navigation history
            self._add_to_history(parent_data)

            # Find and select the corresponding item in the tree view if possible
            self.select_tree_item_by_inode(parent_data["inode_number"], parent_data["start_offset"])

            self.clear_status()

        except Exception as e:
            self.log_error(f"Error navigating to parent directory: {str(e)}")
            self.clear_status()

    def _add_to_history(self, directory_data):
        """Add a directory to the navigation history."""
        # Skip if we're navigating through history
        if self._navigating_history:
            return

        # Only add directories to history (not files)
        if directory_data.get("type") != "directory" and directory_data.get("type") != "volume":
            return

        # Create a history entry with essential data
        history_entry = {
            "inode_number": directory_data.get("inode_number"),
            "start_offset": directory_data.get("start_offset"),
            "type": directory_data.get("type"),
            "name": directory_data.get("name"),
            "path": self.current_path,
            "parent_inode": directory_data.get("parent_inode"),
            # History spans images: Back must return to the right device.
            "image_path": self.current_image_path
        }

        # If we're in the middle of history (not at the end), remove everything after current position
        if self._history_index < len(self._directory_history) - 1:
            self._directory_history = self._directory_history[:self._history_index + 1]

        # Add new entry to history
        self._directory_history.append(history_entry)
        self._history_index = len(self._directory_history) - 1

        # Update navigation buttons
        self._update_navigation_buttons()

    def _update_navigation_buttons(self):
        """Update the enabled state of Back/Forward navigation buttons."""
        # Enable Back button if we can go back
        can_go_back = self._history_index > 0
        self.back_action.setEnabled(can_go_back)

        # Enable Forward button if we can go forward
        can_go_forward = self._history_index < len(self._directory_history) - 1
        self.forward_action.setEnabled(can_go_forward)

    def navigate_back(self):
        """Navigate to the previous directory in history."""
        if self._history_index <= 0:
            return

        try:
            # Set flag to prevent adding to history
            self._navigating_history = True

            # Move back in history
            self._history_index -= 1
            history_entry = self._directory_history[self._history_index]

            # Navigate to the directory
            self._navigate_to_history_entry(history_entry)

        finally:
            # Always clear the flag
            self._navigating_history = False
            self._update_navigation_buttons()

    def navigate_forward(self):
        """Navigate to the next directory in history."""
        if self._history_index >= len(self._directory_history) - 1:
            return

        try:
            # Set flag to prevent adding to history
            self._navigating_history = True

            # Move forward in history
            self._history_index += 1
            history_entry = self._directory_history[self._history_index]

            # Navigate to the directory
            self._navigate_to_history_entry(history_entry)

        finally:
            # Always clear the flag
            self._navigating_history = False
            self._update_navigation_buttons()

    def _navigate_to_history_entry(self, history_entry):
        """Navigate to a specific directory from history."""
        self.set_status("Navigating...")

        try:
            if not self.activate_image(history_entry.get("image_path")
                                       or self.current_image_path):
                return
            # Restore the path
            self.current_path = history_entry.get("path", "/")

            # Get directory contents
            inode_number = history_entry.get("inode_number")
            start_offset = history_entry.get("start_offset")

            if history_entry.get("type") == "volume":
                # For volumes, list the root directory.
                entries = self.image_handler.get_directory_contents(
                    start_offset, self.image_handler.get_root_inode(start_offset))
            else:
                # For regular directories, use stored inode
                entries = self.image_handler.get_directory_contents(start_offset, inode_number)

            # Update current selected data
            self.current_selected_data = history_entry.copy()

            # Update directory up button state
            self.update_directory_up_button()

            # Populate the listing table
            self.populate_listing_table(entries, start_offset)

            # Find and select the corresponding item in the tree view if possible
            if inode_number:
                self.select_tree_item_by_inode(inode_number, start_offset)

            self.clear_status()

        except Exception as e:
            self.log_error(f"Error navigating from history: {str(e)}")
            self.clear_status()

    def select_tree_item_by_inode(self, inode_number, start_offset):
        """Attempt to find and select the item in the tree view that matches the given inode"""
        try:
            # Skip if inode_number is None
            if inode_number is None:
                return

            # Search only the active image's branch: inode numbers repeat
            # across images, and the first match could be another device's.
            root_item = self.tree_viewer.invisibleRootItem()
            for index in range(root_item.childCount()):
                top = root_item.child(index)
                if self.image_of_item(top) == self.current_image_path:
                    root_item = top
                    break

            # Find the item with matching inode and start_offset (recursive search)
            found_item = self.find_tree_item_recursive(root_item, inode_number, start_offset)

            if found_item:
                # Temporarily disconnect the item clicked signal to prevent loops
                self.tree_viewer.itemClicked.disconnect(self.on_item_clicked)

                # Select the item and make it visible
                self.tree_viewer.setCurrentItem(found_item)
                self.tree_viewer.scrollToItem(found_item)

                # Reconnect the signal
                self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        except Exception as e:
            self.log_error(f"Error selecting tree item: {str(e)}")

    def find_tree_item_recursive(self, parent_item, inode_number, start_offset):
        """Recursively search for a tree item with matching inode and start_offset"""
        # Check all children of the parent item
        for i in range(parent_item.childCount()):
            item = parent_item.child(i)
            data = item.data(0, Qt.UserRole)

            # Check if this item matches (allow matching based on inode only)
            if data and data.get("inode_number") == inode_number:
                # If start_offset is also provided and doesn't match, continue searching
                if start_offset is not None and data.get("start_offset") != start_offset:
                    continue
                return item

            # If it has children, search recursively
            if item.childCount() > 0:
                found = self.find_tree_item_recursive(item, inode_number, start_offset)
                if found:
                    return found

        # Not found
        return None

    def display_volumes_in_listing(self) -> None:
        """Display all volumes/partitions in the listing table when disk image root is clicked."""
        self._listing_image = self.current_image_path
        # Clear existing content
        self.listing_table.setRowCount(0)
        self.listing_table.setSortingEnabled(False)

        # Show columns with volume information, hide file-specific columns
        self.listing_table.setColumnHidden(1, False)  # Show Inode (for Volume #)
        self.listing_table.setColumnHidden(4, False)  # Show Created (for Start Offset)
        self.listing_table.setColumnHidden(5, False)  # Show Accessed (for End Offset)
        self.listing_table.setColumnHidden(6, False)  # Show Modified (for Length)
        self.listing_table.setColumnHidden(7, False)  # Show Changed (for Block Size)
        self.listing_table.setColumnHidden(8, True)   # Hide Path (not relevant for volumes)
        self.listing_table.setColumnHidden(9, False)  # Show Info (for additional details)
        self.listing_table.setColumnHidden(10, True)  # Seq: per-file, not per-volume
        self.listing_table.setColumnHidden(11, True)  # Attributes: likewise

        # Update column headers for volume context
        self.listing_table.setHorizontalHeaderLabels([
            'Name', 'Volume #', 'Type', 'Size', 'Start Offset', 'End Offset',
            'Length', 'Block Size', 'Path', 'Details', 'Seq', 'Attributes'
        ])

        # Make Info column much wider for detailed information
        self.listing_table.setColumnWidth(9, 1200)

        # Reset path to root
        self.current_path = "/"

        # Clear navigation history when returning to disk image root
        self._directory_history = []
        self._history_index = -1
        self._update_navigation_buttons()

        # Disable the up button since we're at the disk image root
        self.go_up_action.setEnabled(False)

        # Get all partitions
        partitions = self.image_handler.get_partitions()

        if not partitions:
            # No partitions found
            self.listing_table.setSortingEnabled(True)
            return

        try:
            for addr, desc, start, length in partitions:
                row_position = self.listing_table.rowCount()
                self.listing_table.insertRow(row_position)

                # Calculate volume information
                sector_size = self.image_handler.sector_size
                end = start + length - 1
                size_in_bytes = length * sector_size
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                fs_type = self.image_handler.get_fs_type(start)
                desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc

                # Get additional filesystem details
                try:
                    fs_info = self.image_handler.get_fs_info(start)
                    if fs_info and hasattr(fs_info.info, 'block_size'):
                        block_size = f"{fs_info.info.block_size:,} bytes"
                    else:
                        block_size = "N/A"
                except (AttributeError, IOError, OSError, RuntimeError) as e:
                    # "N/A" is shown either way, but an unreadable filesystem
                    # should leave a trace rather than looking like a volume
                    # that simply has no block size.
                    logger.warning("Could not read block size at offset %s: %s", start, e)
                    block_size = "N/A"

                # Volume name
                volume_name = f"vol{addr}"
                name_item = QTableWidgetItem(volume_name)
                icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')
                name_item.setIcon(QIcon(icon_path))

                # Store volume data for potential future use
                volume_data = {
                    "name": volume_name,
                    "type": "volume",
                    "start_offset": start,
                    "end_offset": end,
                    "addr": addr,
                    "description": desc_str,
                    "filesystem": fs_type
                }
                name_item.setData(Qt.UserRole, volume_data)

                # Create table items with detailed information
                inode_item = QTableWidgetItem(str(addr))  # Volume number in Inode column
                type_item = QTableWidgetItem(fs_type)
                size_item = QTableWidgetItem(readable_size)

                # Use timestamp columns for partition geometry
                start_offset_item = QTableWidgetItem(f"{start:,} sectors")
                end_offset_item = QTableWidgetItem(f"{end:,} sectors")
                length_item = QTableWidgetItem(f"{length:,} sectors")
                block_size_item = QTableWidgetItem(block_size)

                # Build comprehensive info string
                info_parts = []
                # Add description first without label if it exists
                if desc_str and desc_str.strip():
                    info_parts.append(desc_str)
                # Add detailed partition information
                info_parts.append(f"Start: {start:,} sectors ({start * sector_size:,} bytes)")
                info_parts.append(f"End: {end:,} sectors ({end * sector_size:,} bytes)")
                info_parts.append(f"Length: {length:,} sectors ({size_in_bytes:,} bytes)")
                if block_size != "N/A":
                    info_parts.append(f"Block Size: {block_size}")
                info_parts.append(f"Filesystem: {fs_type}")

                info_item = QTableWidgetItem(" | ".join(info_parts))

                # Set items in table
                self.listing_table.setItem(row_position, 0, name_item)
                self.listing_table.setItem(row_position, 1, inode_item)
                self.listing_table.setItem(row_position, 2, type_item)
                self.listing_table.setItem(row_position, 3, size_item)
                self.listing_table.setItem(row_position, 4, start_offset_item)
                self.listing_table.setItem(row_position, 5, end_offset_item)
                self.listing_table.setItem(row_position, 6, length_item)
                self.listing_table.setItem(row_position, 7, block_size_item)
                self.listing_table.setItem(row_position, 9, info_item)

        finally:
            self.listing_table.setSortingEnabled(True)

    def populate_listing_table(self, entries: List[Dict[str, Any]], offset: int) -> None:
        """Populate the listing table with directory entries in batches for better performance."""
        self._listing_image = self.current_image_path
        # Clear existing content
        self.listing_table.setRowCount(0)

        # Restore original column headers for file/folder view
        self.listing_table.setHorizontalHeaderLabels([
            'Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date',
            'Modified Date', 'Changed Date', 'Path', 'Info', 'Seq', 'Attributes'
        ])

        # Show columns relevant for files/folders, hide Info column
        self.listing_table.setColumnHidden(1, False)  # Show Inode
        self.listing_table.setColumnHidden(4, False)  # Show Created
        self.listing_table.setColumnHidden(5, False)  # Show Accessed
        self.listing_table.setColumnHidden(6, False)  # Show Modified
        self.listing_table.setColumnHidden(7, False)  # Show Changed
        self.listing_table.setColumnHidden(8, False)  # Show Path
        self.listing_table.setColumnHidden(9, True)   # Hide Info
        self.listing_table.setColumnHidden(10, False)  # Show Seq
        self.listing_table.setColumnHidden(11, False)  # Show Attributes

        # The examiner's listing filters (Options > Settings > Display):
        # deleted entries, and the file system's own $-named metadata files.
        if not case_settings.user('show_deleted'):
            entries = [e for e in entries if not e.get('is_deleted')]
        if not case_settings.user('show_system'):
            entries = [e for e in entries
                       if not str(e.get('name') or '').startswith('$')]

        if not entries:
            return

        # Enable/disable the up button based on whether we're in the root directory
        self.update_directory_up_button()

        # Disable sorting and updates for better performance during bulk population
        self.listing_table.setSortingEnabled(False)
        self.listing_table.setUpdatesEnabled(False)

        try:
            total_entries = len(entries)

            # Process in batches to keep UI responsive
            for batch_start in range(0, total_entries, TABLE_BATCH_SIZE):
                batch_end = min(batch_start + TABLE_BATCH_SIZE, total_entries)
                batch = entries[batch_start:batch_end]

                # Populate the batch
                for entry in batch:
                    row_position = self.listing_table.rowCount()
                    self._populate_table_entry(row_position, entry, offset)

                # Process events periodically to keep UI responsive
                if batch_end < total_entries:
                    QApplication.processEvents()

        finally:
            # What the case already knows about these files. Filled before
            # sorting is switched back on: setting a cell in a sorted table
            # can move its row out from under the loop. Until now this ran
            # only when an analysis finished, so every folder opened later
            # showed empty analysis columns.
            try:
                self.mark_analysis_rows()
                self.mark_vt_rows()
            except Exception as exc:
                logger.error("Could not mark listing rows: %s", exc)
            # Re-enable updates and sorting
            self.listing_table.setUpdatesEnabled(True)
            self.listing_table.setSortingEnabled(True)
            self._fit_listing_columns()

    #: Widest a listing column may grow when fitted. Path and Attributes hold
    #: strings long enough to push the timestamps off screen, so they elide
    #: with a tooltip rather than setting the table's width. Detected Type is
    #: capped for the same reason: a full MIME string is longer than the
    #: filename it describes.
    _LISTING_COLUMN_CAPS = {8: 420, 11: 320, 12: 200}

    def _fit_listing_columns(self):
        """Size the listing's columns to what the current directory holds.

        The fixed widths this replaces were chosen before any directory was
        read, so Inode reserved 50px for a four-digit number while Type was too
        narrow for "Deleted Dir".
        """
        try:
            fit_columns(self.listing_table, self._LISTING_COLUMN_CAPS)
        except Exception as e:
            logger.debug("Could not fit the listing columns: %s", e)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      created, accessed, modified, changed, parent_inode=None,
                                      sequence=None, attributes=""):
        """Insert a row into the listing table with proper caching and error handling."""
        try:
            icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
            icon = QIcon(icon_path)
            row_position = self.listing_table.rowCount() - 1  # Current row (rows are 0-indexed)

            # Calculate the full path for this item
            file_path = posixpath.join(self.current_path, entry_name) if entry_name != ".." else os.path.dirname(
                self.current_path)

            name_item = QTableWidgetItem(entry_name)
            name_item.setIcon(icon)
            name_item.setData(Qt.UserRole, {
                "inode_number": entry_inode,
                "start_offset": offset,
                "type": "directory" if icon_type == 'folder' else 'file',
                "name": entry_name,
                "size": size,
                "parent_inode": parent_inode,  # Store parent directory inode for "Go Up" functionality
                "path": file_path,  # Store the full path
                # The MFT record's reuse counter -- see _setup_file_tree_item.
                "sequence": sequence,
            })

            self.listing_table.setItem(row_position, 0, name_item)
            self.listing_table.setItem(row_position, 1, QTableWidgetItem(
                self.image_handler.inode_label(offset, entry_inode)))
            self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
            self.listing_table.setItem(row_position, 3, QTableWidgetItem(str(size)))
            self.listing_table.setItem(row_position, 4, QTableWidgetItem(
                case_settings.alongside(str(created))))
            self.listing_table.setItem(row_position, 5, QTableWidgetItem(
                case_settings.alongside(str(accessed))))
            self.listing_table.setItem(row_position, 6, QTableWidgetItem(
                case_settings.alongside(str(modified))))
            self.listing_table.setItem(row_position, 7, QTableWidgetItem(
                case_settings.alongside(str(changed))))
            self.listing_table.setItem(row_position, 8, QTableWidgetItem(file_path))
            self.listing_table.setItem(row_position, 9, QTableWidgetItem(""))  # Empty Info column for files/folders

            # MFT sequence: which use of this record the row refers to. Sorted
            # as a number, so 10 does not fall between 1 and 2.
            sequence_item = QTableWidgetItem()
            if sequence is not None:
                sequence_item.setData(Qt.DisplayRole, int(sequence))
            self.listing_table.setItem(row_position, 10, sequence_item)

            # Attribute list. A named $DATA entry here is an alternate data
            # stream, which is worth spotting from the listing.
            attributes_item = QTableWidgetItem(attributes or "")
            if attributes:
                attributes_item.setToolTip(attributes)
            self.listing_table.setItem(row_position, 11, attributes_item)

        except Exception as e:
            self.log_error(f"Error adding row to listing table: {str(e)}")
            # Try to recover by removing the incomplete row
            try:
                if row_position >= 0:
                    self.listing_table.removeRow(row_position)
            except RuntimeError as e:
                logger.debug("Could not remove incomplete row %s: %s", row_position, e)

    def update_viewer_with_file_content(self, file_content, data):
        """Update the active viewer tab with the file content.

        This method is called after file content is loaded, either directly
        or from a background thread.
        """
        # Clear the status message if it exists
        self.clear_status()

        adapter = self.active_viewer_adapter()
        if adapter is None:
            return

        # The Metadata viewer reads the file itself, so it is the one viewer
        # that still has something to show without loaded content.
        if not file_content and adapter.needs_content():
            from trace_app.ui.widgets.listing_views import size_in_bytes
            # Rows carry the Size column's text ('0.00 B') or a number.
            if file_content is not None and \
                    size_in_bytes((data or {}).get('size')) == 0:
                # An empty file, read correctly: nothing to show.
                adapter.clear()
                self.set_status(f"{(data or {}).get('name', 'File')}: "
                                f"empty file (0 bytes)")
                return
            self.log_error("No content available to display")
            return

        # Notes and bookmarks need to know which evidence row and which
        # durable reference this selection is; the listing and tree do not
        # carry that, so it is added once here rather than in each viewer.
        annotated = self.annotate_with_case_identity(data)

        try:
            adapter.display(file_content, annotated)
        except Exception as e:
            self.log_error(f"Error displaying content in viewer: {str(e)}")



    def _show_in_hex_from_image(self, data):
        """When the Hex tab is in front, give it the file to read from
        the image a page at a time -- nothing is loaded whole. True when it
        did; False leaves the caller to read the file as before."""
        adapter = self.active_viewer_adapter()
        if adapter is None or not getattr(adapter, 'reads_itself',
                                          lambda _d: False)(data):
            return False
        from trace_app.core.hex_source import ImageFileSource
        try:
            source = ImageFileSource(self.image_handler,
                                     data['inode_number'],
                                     data['start_offset'])
        except Exception as exc:
            logger.debug("Hex view cannot read %s from the image: %s",
                         data.get('name'), exc)
            return False
        if not source.size:
            return False
        adapter.widget.display_source(
            source, self.annotate_with_case_identity(data))
        self.clear_status()
        return True

    def bookmark_text_selection(self, begin, end, text):
        """Text selected in the Text tab: bytes [begin, end) of the file
        shown. Bookmarked as that byte range of the image when the bytes
        are one stretch of it; else the file itself, the text its label."""
        data = self.current_selected_data or {}
        name = data.get('name') or 'file'
        quoted = f"“{text[:60]}{'…' if len(text) > 60 else ''}”"
        image = None
        if data.get('type') == 'file' and \
                data.get('inode_number') is not None:
            from trace_app.core.hex_source import ImageFileSource
            try:
                source = ImageFileSource(self.image_handler,
                                         data['inode_number'],
                                         data['start_offset'])
                if source.contiguous(begin, end):
                    image = source.image_offset(begin)
            except Exception as exc:
                logger.debug("No image offset for the text: %s", exc)
        elif data.get('is_carved') and not data.get('fragments') and \
                data.get('offset') is not None:
            image = int(data['offset']) + begin
        if image is not None:
            self.bookmark_byte_range(image, image + (end - begin),
                                     f"{name}: {quoted}")
            return
        target = self._file_data_for(data) or data
        self.add_bookmark_for(target, suggested_label=f"{quoted} in {name}")

    def bookmark_byte_range(self, begin, end, description):
        """Bookmark bytes [begin, end) of the active image -- a hex
        selection. The reference is the byte range itself, so it opens
        again (read from the image) after the case is reopened."""
        if not self.case:
            message.information(
                self, "No case is open",
                "Bookmarks are kept in a case. Start one from File ▸ New Case "
                "to keep findings between sessions.")
            return
        label, ok = QInputDialog.getText(self, "Bookmark bytes", "Label:",
                                         text=description)
        if not ok or not label.strip():
            return
        name = (self.current_selected_data or {}).get('name') or ''
        self.case.add_bookmark(
            self.evidence_id_for_current_image(),
            make_span_ref(0, begin, end), label.strip(),
            artifact_name=f"{name} [{end - begin:,} bytes]" if name
            else f"{end - begin:,} bytes",
            artifact_path=f"image bytes 0x{begin:X}-0x{end - 1:X}")
        self.refresh_bookmarks()
        self.set_status(f"Bookmarked {label.strip()}")

    def update_viewer_with_media_stream(self, file_obj, file_size, metadata, data):
        """Update the application viewer with a media stream for playback."""
        # Clear the status message if it exists
        self.clear_status()

        try:
            adapter = self.active_viewer_adapter()
            if adapter is None or not hasattr(adapter, 'display_stream'):
                return
            adapter.display_stream(file_obj, file_size, data)
        except Exception as e:
            self.log_error(f"Error setting up media stream: {str(e)}")

    def _retain_worker(self, worker):
        """Keep a running QThread alive until it finishes.

        Workers are stored on attributes such as self.file_worker, so starting
        a new one rebinds the attribute and drops the last Python reference to
        a thread that is still running. The wrapped C++ object can then be
        collected mid-read, which surfaces as
        "RuntimeError: Internal C++ object already deleted" or a hard crash.
        Holding the worker in a set until its finished signal fires prevents
        that; the discard is queued through the signal, so it runs on the UI
        thread after the thread has actually stopped.
        """
        if not hasattr(self, '_active_workers'):
            self._active_workers = set()
        self._active_workers.add(worker)
        worker.finished.connect(lambda: self._active_workers.discard(worker))
        return worker

    def _cancel_worker(self, attr_name):
        """Ask the worker held on `attr_name` to stop, if it is still running."""
        worker = getattr(self, attr_name, None)
        if worker is None:
            return
        try:
            if not worker.isRunning():
                return
            # Drop callbacks first so a late completion cannot write into the
            # viewer after we have moved on to another file.
            worker.completed.disconnect()
            worker.error.disconnect()
            worker.requestInterruption()
        except (RuntimeError, TypeError) as e:
            # RuntimeError: the underlying thread object is already gone.
            # TypeError: the signals had no remaining connections.
            logger.debug("Could not cancel %s: %s", attr_name, e)

    def display_content_for_active_tab(self):
        """Display content appropriate for the currently active tab."""
        if not self.current_selected_data:
            return

        self.set_status("Updating view...")

        try:
            # Cancel any in-flight workers before starting new ones, so a
            # rapid selection change does not race two reads into the viewer.
            self._cancel_worker('media_worker')
            self._cancel_worker('file_worker')

            inode_number = self.current_selected_data.get("inode_number")
            offset = self.current_selected_data.get("start_offset", self.current_offset)

            adapter = self.active_viewer_adapter()
            if adapter is None:
                # A tab that is not a file viewer -- VirusTotal -- shows
                # nothing of the selection, so there is nothing to read.
                self.clear_status()
                return

            if inode_number:
                if self._show_in_hex_from_image(self.current_selected_data):
                    return
                # Ask the active viewer whether it wants a stream, rather than
                # hardcoding the Application tab's index here.
                if adapter.wants_stream(self.current_selected_data):
                    # Use MediaStreamWorker for streaming playback (doesn't load content)
                    self.media_worker = self._retain_worker(self.MediaStreamWorker(self.image_handler, inode_number, offset))
                    self.media_worker.completed.connect(
                        lambda file_obj, file_size, metadata: self.update_viewer_with_media_stream(
                            file_obj, file_size, metadata, self.current_selected_data))
                    self.media_worker.error.connect(
                        lambda msg: (self.log_error(msg), self.clear_status()))
                    self.media_worker.start()
                else:
                    # For non-media files or other tabs, use FileContentWorker (loads content)
                    self.file_worker = self._retain_worker(self.FileContentWorker(self.image_handler, inode_number, offset))
                    self.file_worker.completed.connect(
                        lambda content, _: self.update_viewer_with_file_content(content, self.current_selected_data))
                    self.file_worker.error.connect(
                        lambda msg: (self.log_error(msg), self.clear_status()))
                    self.file_worker.start()
            else:
                self.clear_status()
        except Exception as e:
            self.log_error(f"Error updating active tab: {str(e)}")
            self.clear_status()

    def open_listing_context_menu(self, position):
        # Get the selected item
        indexes = self.listing_table.selectedIndexes()
        if indexes:
            self.activate_listing_image()
            selected_item = self.listing_table.item(indexes[0].row(),
                                                    0)  # Assuming the first column contains the item data
            data = selected_item.data(Qt.UserRole)
            menu = QMenu()

            # If in search mode and item is a file, add "Open File" and "Show in Directory"
            if self._search_mode and data.get('type') == 'file':
                # Open File action
                open_action = menu.addAction("Open File")
                open_action.triggered.connect(lambda: self.open_search_result_file(data))

                # Show in Directory action
                show_in_dir_action = menu.addAction("Show in Directory")
                show_in_dir_action.triggered.connect(lambda: self.show_file_in_directory(data))

                # Add separator
                menu.addSeparator()

            self.add_bookmark_action(menu, data)
            # Every selected row, not just the first: a batch lookup starts
            # from a multi-selection.
            rows = sorted({index.row() for index in indexes})
            self.add_virustotal_menu(menu, [
                self.listing_table.item(row, 0).data(Qt.UserRole)
                for row in rows if self.listing_table.item(row, 0)])
            menu.addSeparator()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(lambda: self.handle_export(data, QFileDialog.getExistingDirectory(
                self, "Select Destination Directory", case_settings.export_dir())))

            show_menu(menu, self.listing_table.viewport().mapToGlobal(position))

    def handle_export(self, data, dest_dir):
        """Export the selected item in a background thread with progress display."""
        if not dest_dir:
            return

        try:
            # Create a progress dialog
            progress_dialog = QProgressDialog("Preparing to export...", "Cancel", 0, 100, self)
            progress_dialog.setWindowTitle("Exporting Files")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(0)
            progress_dialog.show()

            # Create and configure the worker
            self.export_worker = ExportWorker(
                self.image_handler,
                data["inode_number"],
                data["start_offset"],
                dest_dir,
                data["name"],
                data["type"] == "directory"
            )

            # Connect worker signals
            self.export_worker.progress.connect(
                lambda current, total: progress_dialog.setValue(int(current * 100 / total) if total > 0 else 0)
            )
            self.export_worker.status_update.connect(progress_dialog.setLabelText)
            self.export_worker.error.connect(lambda msg: message.warning(self, "Export Error", msg))
            self.export_worker.finished.connect(progress_dialog.close)

            # Connect the cancel button
            # requestInterruption, not terminate: terminate kills the thread at an
            # arbitrary point, which can leave the pytsk3 handle in a bad state
            # mid-read. ExportWorker checks isInterruptionRequested() each entry.
            progress_dialog.canceled.connect(self.export_worker.requestInterruption)

            # Start the worker
            self.export_worker.start()

        except Exception as e:
            message.critical(self, "Export Error", f"Error starting export: {str(e)}")

    def log_error(self, message):
        """Log an error message to the console and potentially to a log file."""
        logger.error(f"Error: {message}")
        # Could also log to a file or status bar here

    def open_tree_context_menu(self, position):
        # Get the selected item
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            # Export, bookmark and VirusTotal all read the node's own image.
            self.activate_item_image(selected_item)
            menu = QMenu()
            data = selected_item.data(0, Qt.UserRole)

            # A bookmark in the tree gets the actions the panel offers, so the
            # dock is genuinely optional rather than the only way to manage
            # them.
            if data and data.get('is_bookmark'):
                row = data['bookmark']
                go_action = menu.addAction("Show in Listing")
                rename_action = menu.addAction("Rename Bookmark...")
                menu.addSeparator()
                remove_action = menu.addAction("Remove Bookmark")
                chosen = show_menu(
                    menu, self.tree_viewer.viewport().mapToGlobal(position))
                if chosen == go_action:
                    self.go_to_bookmark(row)
                elif chosen == rename_action:
                    label, ok = QInputDialog.getText(
                        self, "Rename bookmark", "Label:",
                        text=row.get('label') or '')
                    if ok and label.strip():
                        self.case.update_bookmark(row['id'],
                                                  label=label.strip())
                        self.refresh_bookmarks()
                elif chosen == remove_action:
                    self.case.remove_bookmark(row['id'])
                    self.refresh_bookmarks()
                return

            # A finding gets the menu it has in the Triage tab. The nodes
            # that only group bookmarks or findings have nothing to act on --
            # and being top-level, they would otherwise be offered the disk
            # image's Verify and Image Information below.
            if data and data.get('is_finding'):
                self.open_finding_menu(
                    data['finding'],
                    self.tree_viewer.viewport().mapToGlobal(position))
                return
            if data and (data.get('is_bookmarks_root')
                         or data.get('is_activity_root')
                         or data.get('is_activity_group')
                         or data.get('is_analysis_root')
                         or data.get('is_analysis_group')
                         or data.get('type') == 'archive-member'):
                # A member inside an archive has no inode to export or
                # bookmark; it is read through its archive.
                return

            if data and data.get('is_bitlocker') and \
                    not self.image_handler.is_unlocked(
                        data.get('start_offset', 0)):
                unlock = menu.addAction(
                    icons.icon(icons.VOLUME_UNLOCKED),
                    f"Unlock {containers.ENCRYPTION_NAMES.get(data.get('encryption') or 'bitlocker')}…")
                unlock.triggered.connect(
                    lambda _=False, it=selected_item:
                    self.unlock_bitlocker_item(it))
                show_menu(menu, self.tree_viewer.viewport().mapToGlobal(position))
                return

            # Check if the selected item is a root item (disk image)
            if selected_item and selected_item.parent() is None:
                # The row names the image, so describe that one rather than
                # whichever handler happens to be current.
                image_path = self._root_image_path(selected_item)
                view_os_info_action = menu.addAction("View Image Information")
                view_os_info_action.triggered.connect(
                    lambda _=False, p=image_path: self.show_image_information_for(p))

                # Verifying is about one image, so it belongs on that image own
                # row as well as on the toolbar.
                state = self.verification_state(image_path)
                verify_action = menu.addAction(
                    "Verify Image" if state is None else "View Verification Result")
                verify_action.triggered.connect(
                    lambda _=False, p=image_path: self.verify_image(p))

            if data and data.get('inode_number') is not None:
                self.add_bookmark_action(menu, data)
                self.add_virustotal_menu(menu, [data])
                menu.addSeparator()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(
                lambda: self.handle_export(self.tree_viewer.itemFromIndex(indexes[0]).data(0, Qt.UserRole),
                                           QFileDialog.getExistingDirectory(
                                               self, "Select Destination Directory",
                                               case_settings.export_dir())))

            show_menu(menu, self.tree_viewer.viewport().mapToGlobal(position))

    def create_action(self, icon_name, text, callback):
        """Toolbar action whose icon follows the theme.

        Takes a registry name (icons.EVIDENCE_ADD), not a filesystem path:
        building the QIcon from a path skipped tinting, which is why these
        toolbar icons rendered black in both themes.
        """
        action = icons.action(icon_name, text, self)
        action.triggered.connect(callback)
        return action

    def get_grandparent_inode(self, parent_inode, start_offset):
        """Helper method to determine the grandparent inode"""
        # The root directory has no parent (its number is the file
        # system's own: NTFS 5, FAT and ext 2, Btrfs 256).
        if parent_inode == self.image_handler.get_root_inode(start_offset):
            return None

        try:
            # Get directory entries for parent
            parent_entries = self.image_handler.get_directory_contents(start_offset, parent_inode)

            # Look for parent directory entry (..)
            for entry in parent_entries:
                if entry.get("name") == "..":
                    return entry.get("inode_number")

            # If we can't find the proper parent, try filesystem-specific approach
            # For NTFS, parent of non-root directories is often inode 5
            return 5

        except Exception as e:
            logger.error(f"Error finding grandparent inode: {str(e)}")
            return None

    # ==================== SEARCH AND FILTER HANDLERS ====================

    def navigate_tree_to_path(self, path, file_data):
        """Navigate and expand the tree view to show the specified path."""
        if not path or not self.tree_viewer:
            return

        # Split the path into components (e.g., "/folder1/folder2/file.txt" -> ["folder1", "folder2", "file.txt"])
        # Remove leading/trailing slashes and split
        path_parts = [p for p in path.split('/') if p]

        if not path_parts:
            return

        # Start from the root - find the partition/volume first
        root = self.tree_viewer.invisibleRootItem()
        current_item = None

        # Find the correct partition by matching the start_offset from file_data
        start_offset = file_data.get('start_offset')
        if start_offset is not None:
            for i in range(root.childCount()):
                child = root.child(i)
                child_data = child.data(0, Qt.UserRole)
                if child_data and child_data.get('start_offset') == start_offset:
                    current_item = child
                    current_item.setExpanded(True)
                    break

        if not current_item:
            return

        # Now traverse the path, expanding each folder
        for part_index, part_name in enumerate(path_parts):
            found = False

            # Expand current item to load its children
            if not current_item.isExpanded():
                current_item.setExpanded(True)
                # Give Qt time to process the expansion and load children
                QApplication.processEvents()

            # Search through children for the next part
            for i in range(current_item.childCount()):
                child = current_item.child(i)
                child_text = child.text(0)

                if child_text == part_name:
                    current_item = child
                    found = True

                    # If this is not the last part, expand it
                    if part_index < len(path_parts) - 1:
                        current_item.setExpanded(True)
                        QApplication.processEvents()
                    break

            if not found:
                # Path component not found, stop navigation
                break

        # Select and highlight the final item
        if current_item:
            self.tree_viewer.setCurrentItem(current_item)
            self.tree_viewer.scrollToItem(current_item)

            # Set a special background color to highlight the search result
            # Store the original background to restore later
            if not hasattr(self, '_original_tree_item_background'):
                self._original_tree_item_background = None

            # Clear previous highlight
            if hasattr(self, '_highlighted_tree_item') and self._highlighted_tree_item:
                if self._original_tree_item_background:
                    self._highlighted_tree_item.setBackground(0, self._original_tree_item_background)

            # Save current item and its background
            self._highlighted_tree_item = current_item
            self._original_tree_item_background = current_item.background(0)

            # Set red highlight for the found item
            from PySide6.QtGui import QBrush, QColor
            current_item.setBackground(0, QBrush(QColor(255, 100, 100, 100)))  # Semi-transparent red

    def on_listing_search_text_changed(self):
        """Handle text changes in search bar - auto-clear results if empty."""
        search_query = self.listing_search_bar.text().strip()

        # Auto-clear results when user manually empties the search bar
        if not search_query and self._search_mode:
            self.switch_to_browse_mode()

    def trigger_listing_search(self):
        """Trigger search when Enter is pressed."""
        search_query = self.listing_search_bar.text().strip()

        if not search_query:
            # If empty, just return to browse mode
            self.switch_to_browse_mode()
            return

        # Store the query
        self._search_query = search_query

        # switch_to_search_mode runs the search itself, so calling
        # perform_search here as well walked the whole filesystem twice on the
        # first search of every session.
        if not self._search_mode:
            self.switch_to_search_mode()
        else:
            self.perform_search(search_query)

    def switch_to_search_mode(self):
        """Switch from Browse mode to Search mode."""
        if self._search_mode:
            return  # Already in search mode

        # Save current browse state
        self._last_browsed_state = {
            'offset': self.current_offset,
            'path': self.current_path,
            'directory_data': self.current_selected_data
        }

        # Switch to search mode
        self._search_mode = True

        # Keep tree view enabled - user can still navigate while searching
        # (removed: self.tree_viewer.setEnabled(False))

        # Show Path column (critical for search results)
        self.listing_table.setColumnHidden(8, False)  # Path column

        # Update status bar
        self.set_status(f"Searching for '{self._search_query}'...")

        # Perform the search
        self.perform_search(self._search_query)

    def switch_to_browse_mode(self):
        """Switch from Search mode to Browse mode."""
        if not self._search_mode:
            return  # Already in browse mode

        # Switch to browse mode
        self._search_mode = False
        self._search_query = ""

        # Clear any tree view highlights from search results
        if hasattr(self, '_highlighted_tree_item') and self._highlighted_tree_item:
            if hasattr(self, '_original_tree_item_background') and self._original_tree_item_background:
                self._highlighted_tree_item.setBackground(0, self._original_tree_item_background)
            self._highlighted_tree_item = None
            self._original_tree_item_background = None

        # Tree view stays enabled (removed: self.tree_viewer.setEnabled(True))

        # Hide Path column in browse mode (tree shows location)
        self.listing_table.setColumnHidden(8, True)

        # Restore previous browse state
        if self._last_browsed_state:
            directory_data = self._last_browsed_state.get('directory_data')
            path = self._last_browsed_state.get('path')

            if directory_data and path:
                try:
                    # Navigate the tree view back to this location
                    # This will also update the listing table via on_item_clicked
                    self._restore_tree_selection(path, directory_data)
                except Exception as e:
                    self.set_status(f"Error restoring directory view: {str(e)}")

        # Clear status bar
        self.clear_status()

    def _restore_tree_selection(self, path, directory_data):
        """Restore tree view selection to a previous location."""
        if not path or not self.tree_viewer:
            return

        # Reuse the navigate_tree_to_path logic but without the red highlight
        path_parts = [p for p in path.split('/') if p]
        if not path_parts:
            # Root path, select the partition
            root = self.tree_viewer.invisibleRootItem()
            start_offset = directory_data.get('start_offset')
            if start_offset is not None:
                for i in range(root.childCount()):
                    child = root.child(i)
                    child_data = child.data(0, Qt.UserRole)
                    if child_data and child_data.get('start_offset') == start_offset:
                        self.tree_viewer.setCurrentItem(child)
                        self.tree_viewer.scrollToItem(child)
                        # Manually trigger the item clicked event to update the listing table
                        self.on_item_clicked(child, 0)
                        break
            return

        # Full path restoration
        root = self.tree_viewer.invisibleRootItem()
        current_item = None

        # Find the correct partition
        start_offset = directory_data.get('start_offset')
        if start_offset is not None:
            for i in range(root.childCount()):
                child = root.child(i)
                child_data = child.data(0, Qt.UserRole)
                if child_data and child_data.get('start_offset') == start_offset:
                    current_item = child
                    current_item.setExpanded(True)
                    break

        if not current_item:
            return

        # Traverse the path
        for part_index, part_name in enumerate(path_parts):
            found = False
            if not current_item.isExpanded():
                current_item.setExpanded(True)
                QApplication.processEvents()

            for i in range(current_item.childCount()):
                child = current_item.child(i)
                if child.text(0) == part_name:
                    current_item = child
                    found = True
                    if part_index < len(path_parts) - 1:
                        current_item.setExpanded(True)
                        QApplication.processEvents()
                    break

            if not found:
                break

        # Select the final item and trigger the click to update listing table
        if current_item:
            self.tree_viewer.setCurrentItem(current_item)
            self.tree_viewer.scrollToItem(current_item)
            # Manually trigger the item clicked event to update the listing table
            self.on_item_clicked(current_item, 0)

    def _wildcard_to_regex(self, pattern):
        """Convert wildcard pattern (*.pdf, name.*) to regex pattern."""
        # Escape special regex characters except * and ?
        pattern = re.escape(pattern)
        # Replace escaped wildcards with regex equivalents
        pattern = pattern.replace(r'\*', '.*')  # * matches any characters
        pattern = pattern.replace(r'\?', '.')   # ? matches single character
        return f"^{pattern}$"  # Match entire string

    def _matches_wildcard(self, filename, pattern):
        """Check if filename matches wildcard pattern."""
        regex_pattern = self._wildcard_to_regex(pattern)
        return re.match(regex_pattern, filename, re.IGNORECASE) is not None

    def perform_search(self, search_query):
        """Execute file search with wildcard support."""
        if not self.image_handler:
            return

        self.set_status(f"Searching for '{search_query}'...")

        try:
            # Check if search query contains wildcards
            has_wildcards = '*' in search_query or '?' in search_query

            if has_wildcards:
                # For wildcard searches, get all files and filter locally
                files = self.image_handler.search_files(None)
                # Filter by wildcard pattern
                files = [f for f in files if self._matches_wildcard(f['name'], search_query)]
            else:
                # Regular substring search
                files = self.image_handler.search_files(search_query)

            # Clear and populate table. The rows are this image's: a result
            # opened after another image became active (a Triage or
            # Search-tab preview) must still read this one.
            self._listing_image = self.current_image_path
            self.listing_table.setRowCount(0)
            self.listing_table.setSortingEnabled(False)

            # Show columns relevant for search results
            self.listing_table.setColumnHidden(1, False)  # Show Inode
            self.listing_table.setColumnHidden(2, False)  # Show Type (can be files or folders)
            self.listing_table.setColumnHidden(4, False)  # Show Created
            self.listing_table.setColumnHidden(5, False)  # Show Accessed
            self.listing_table.setColumnHidden(6, False)  # Show Modified
            self.listing_table.setColumnHidden(7, False)  # Show Changed
            self.listing_table.setColumnHidden(8, False)  # Show Path (critical for search)
            self.listing_table.setColumnHidden(9, True)   # Hide Info

            # Populate with search results
            for file in files:
                self.insert_search_result_row(file)

            self.listing_table.setSortingEnabled(True)

            # Update status bar with result count
            self.set_status(f"{len(files)} result(s) for '{search_query}'")

        except Exception as e:
            self.set_status(f"Search error: {str(e)}")

    def insert_search_result_row(self, file_data):
        """Insert a search result into the listing table."""
        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        # Get file icon based on type
        file_name = file_data.get('name', '')
        is_directory = file_data.get('is_directory', False)

        if is_directory:
            # Directory icon
            icon_path = self.db_manager.get_icon_path('folder', 'folder')
        else:
            # File icon based on extension
            extension = os.path.splitext(file_name)[1].lower()
            # Remove the dot from extension for icon lookup (e.g., '.pdf' -> 'pdf')
            ext_without_dot = extension[1:] if extension else 'txt'
            icon_path = self.db_manager.get_icon_path('file', ext_without_dot)

        # Create name item with icon
        name_item = QTableWidgetItem(file_name)
        name_item.setIcon(QIcon(icon_path))
        name_item.setData(Qt.UserRole, file_data)

        # Create other items
        inode_item = QTableWidgetItem(self.image_handler.inode_label(
            file_data.get('start_offset'), file_data.get('inode_number', '')))
        type_item = QTableWidgetItem("Folder" if is_directory else "File")
        size_item = SizeTableWidgetItem(self.image_handler.get_readable_size(file_data.get('size', 0)))
        size_item.setData(Qt.UserRole, file_data.get('size', 0))

        created_item = QTableWidgetItem(file_data.get('created', ''))
        accessed_item = QTableWidgetItem(file_data.get('accessed', ''))
        modified_item = QTableWidgetItem(file_data.get('modified', ''))
        changed_item = QTableWidgetItem(file_data.get('changed', ''))
        path_item = QTableWidgetItem(file_data.get('path', ''))

        # Set items in table
        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, inode_item)
        self.listing_table.setItem(row_position, 2, type_item)  # Type column
        self.listing_table.setItem(row_position, 3, size_item)
        self.listing_table.setItem(row_position, 4, created_item)
        self.listing_table.setItem(row_position, 5, accessed_item)
        self.listing_table.setItem(row_position, 6, modified_item)
        self.listing_table.setItem(row_position, 7, changed_item)
        self.listing_table.setItem(row_position, 8, path_item)

    def open_search_result_file(self, file_data):
        """Open a file from search results in the viewer tabs."""
        # This is the same as double-clicking - open in viewer
        # Use the existing file opening logic
        self.load_file_content(file_data)

    def show_file_in_directory(self, file_data):
        """Reveal a search result where it lives.

        The previous version hardcoded parent_inode = 5 -- the NTFS root MFT
        record -- with its own TODO, so every file below the root landed the
        examiner at the volume root with nothing selected. Selecting by inode
        works at any depth and on any filesystem.
        """
        inode = file_data.get('inode_number')
        offset = file_data.get('start_offset')
        if inode is None or offset is None:
            self.set_status("This result has no location to reveal.")
            return

        self.listing_search_bar.clear()     # leaves search mode
        self.current_selected_data = file_data
        self.select_tree_item_by_inode(inode, offset)
        self.set_status(f"Showing {file_data.get('name', 'file')} in place")

    def on_listing_table_item_clicked(self, item, navigate=True):
        """Act on a row in the listing table.

        `navigate` is False for a single click, which selects a file and shows
        its content but leaves folders alone. Opening a directory on a single
        click made the listing hard to browse: selecting a folder to read its
        metadata moved you into it instead. Double-click navigates, as it does
        in any file manager.
        """
        row = item.row()

        # Get data from the name column (column 0)
        data = self.listing_table.item(row, 0).data(Qt.UserRole)
        if not data:
            return
        # The row belongs to the image the listing was filled from, which may
        # no longer be the active one.
        if not self.activate_listing_image():
            return

        self.current_selected_data = data
        self.update_status_for_selection(data)

        if not navigate and data.get("type") in ("volume", "directory"):
            # Single click on a folder: select it, so the metadata and other
            # tabs describe it, but stay where we are.
            self.select_tree_item_by_inode(data.get("inode_number"),
                                           data.get("start_offset"))
            return

        self.set_status("Loading content...")

        try:
            if data.get("type") == "volume":
                # Handle volume/partition - navigate into its root directory
                start_offset = data.get("start_offset", 0)

                # Reset path to root of this volume
                self.current_path = "/"

                # List the volume's root directory, whichever inode that is.
                entries = self.image_handler.get_directory_contents(
                    start_offset, self.image_handler.get_root_inode(start_offset))

                # Update directory up button - should be disabled since we're at volume root
                self.update_directory_up_button()

                # Populate listing table with volume contents. An empty
                # volume leaves the view alone -- see show_listing_entries.
                if not self.show_listing_entries(entries, start_offset,
                                                 data.get("name") or "This volume"):
                    return

                # Add to navigation history
                self._add_to_history(data)

                self.clear_status()

            elif data.get("type") == "directory":
                inode_number = data.get("inode_number", 0)

                # Find and select the corresponding item in the tree view if possible
                self.select_tree_item_by_inode(inode_number, data["start_offset"])

                # Update current path for directory navigation
                if data.get("name") == "..":
                    # Go to parent directory
                    self.current_path = os.path.dirname(self.current_path)
                    if self.current_path == "":
                        self.current_path = "/"
                elif data.get("inode_number") == self.image_handler.get_root_inode(
                        data["start_offset"]):
                    self.current_path = "/"
                else:
                    # Navigate into directory
                    self.current_path = posixpath.join(self.current_path, data.get("name", ""))

                # Directories are processed synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)

                # Update directory up button state
                self.update_directory_up_button()

                if not self.show_listing_entries(entries, data["start_offset"],
                                                 data.get("name")):
                    return

                # Add to navigation history
                self._add_to_history(data)

                self.clear_status()
            elif data.get("type") == "archive-member":
                # A member already read out of the archive on screen.
                self.open_archive_member_row(data, navigate)
                return

            else:
                # A double-click on an archive opens it like a folder, because
                # that is what it is. Single click still just selects, so the
                # viewers describe the archive file itself.
                if navigate and self.open_archive_if_archive(data):
                    return

                # Reveal the file's location in the tree view. In search mode the
                # result may live in a directory the tree has not expanded yet, so
                # navigate by path; otherwise select by inode.
                if getattr(self, '_search_mode', False) and data.get('path'):
                    self.navigate_tree_to_path(data['path'], data)
                else:
                    self.select_tree_item_by_inode(data.get("inode_number"), data["start_offset"])

                if self._show_in_hex_from_image(data):
                    return
                # Files are processed in a background thread
                inode_number = data.get("inode_number", 0)
                self.file_worker = self._retain_worker(self.FileContentWorker(self.image_handler, inode_number, data["start_offset"]))
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), self.clear_status()))
                self.file_worker.start()

        except Exception as e:
            self.log_error(f"Error processing listing table click: {str(e)}")
            self.clear_status()



# Add a worker thread for exporting files and directories
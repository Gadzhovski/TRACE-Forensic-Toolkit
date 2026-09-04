import configparser
import datetime
import gc
import logging
import os
import re
import tempfile
import time
from typing import Any, Dict, List, Optional

import pytsk3
from Registry import Registry
from PySide6.QtCore import Qt, QSize, QThread, Signal, QTimer, QUrl
from PySide6.QtGui import (QIcon, QPalette, QBrush, QAction, QActionGroup, QPixmap,
                           QColor, QCursor, QDesktopServices)
from PySide6.QtCharts import QChart
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit,
                               QFormLayout, QApplication, QWidget, QProgressDialog, QSizePolicy)

from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.tree_branch import BranchTreeWidget
from trace_app.ui.dialogs.about import AboutDialog
from trace_app.infra.constants import (API_DIALOG_WIDTH, COLUMN_WIDTHS, CONTROL_HEIGHT,
                                       GROUP_SPACING,
                                       TABLE_ROW_HEIGHT,
                                       CONTROL_SPACING, DEFAULT_WINDOW_HEIGHT, DEFAULT_WINDOW_WIDTH,
                                       DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y, INPUT_FIELD_MIN_WIDTH,
                                       PANEL_ICON_SIZE, PROGRESS_MIN_DURATION, QT_MAX_SIZE,
                                       TABLE_BATCH_SIZE, TABLE_ICON_SIZE,
                                       TREE_ICON_SIZE, TREE_INDENTATION, VIEWER_DOCK_MAX_WIDTH, VIEWER_DOCK_MIN_HEIGHT)
from trace_app import __version__
from trace_app.core.database import DatabaseManager
from trace_app.ui.viewers.exif import ExifViewer
from trace_app.ui.viewers.carving import FileCarvingWidget
from trace_app.ui.viewers.hex import HexViewer
from trace_app.core import archives
from trace_app.infra.utils import FileSystemUtils
from trace_app.core.case import make_artifact_ref, parse_artifact_ref
from trace_app.core.image_handler import ImageHandler
from trace_app.ui.viewers.metadata import MetadataViewer
from trace_app.infra.paths import config_file, resource_path
from trace_app.ui import icons
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.viewers.registry_hive import RegistryExtractor
from trace_app.ui.viewers.text import TextViewer
from trace_app.ui.viewers.media import UnifiedViewer
from trace_app.ui.dialogs.verification import VerificationWidget
from trace_app.ui.viewers.registry_adapters import (ApplicationAdapter, ExifAdapter, HexAdapter,
                                     CaseAdapter, MetadataAdapter,
                                     NotesAdapter,
                                     TextAdapter,
                                     VirusTotalAdapter)
from trace_app.ui.viewers.virustotal import VirusTotal
from trace_app.ui.dialogs.volume_info import VolumeInfoMixin
from trace_app.core.workers import ExportWorker
from trace_app.ui.dialogs import message
from trace_app.ui.viewers.bookmarks_panel import BookmarksPanel
from trace_app.ui.viewers.case_panel import CasePanel
from trace_app.ui.viewers.notes_panel import NotesPanel
from trace_app.ui.viewers.search_panel import SearchPanel

logger = logging.getLogger('TRACE.MainWindow')

# ==================== FILE SEARCH WIDGET CLASSES ====================
class SizeTableWidgetItem(QTableWidgetItem):
    """Custom table widget item for proper size sorting."""
    def __lt__(self, other):
        return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))




class MainWindow(VolumeInfoMixin, QMainWindow):
    # Class variable for icon caching
    _icon_cache = {}

    def __init__(self, case=None):
        super().__init__()

        #: The open case, or None for quick triage. Everything case-related
        #: checks this rather than a separate mode flag: there is one source
        #: of truth for whether findings have anywhere to be kept.
        self.case = case

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

        #: Artifact references that carry a bookmark, so the listing can mark
        #: them without asking the database once per row.
        self._bookmarked_refs = set()

        #: Handlers for evidence other than the one on screen, opened on demand
        #: when a picker asks about an image that is not the current one and
        #: kept so the second click is instant.
        self._auxiliary_handlers = {}

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
                           else f"In archive")
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

        # A bookmarked file is marked where the examiner is looking. The
        # bookmark glyph goes in the Type column rather than replacing the
        # file's own icon, which still has to say what kind of file it is.
        if self._bookmarked_refs:
            ref = make_artifact_ref(offset, inode_number,
                                    entry.get('sequence'))                 if inode_number is not None else None
            if ref and ref in self._bookmarked_refs:
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
        """Apply the default dock proportions once, on first show."""
        super().showEvent(event)
        if not getattr(self, '_layout_applied', False):
            self._layout_applied = True
            self._apply_default_layout()
            self._align_toolbars()

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

        # Tree on the left: enough for a path, not a third of the window.
        self.resizeDocks([self.tree_dock], [int(width * 0.22)], Qt.Horizontal)

        # Utils along the bottom: tall enough to read a viewer, no more.
        self.resizeDocks([self.viewer_dock], [int(height * 0.30)], Qt.Vertical)
        # Narrower than the tree: a bookmark list is labels, not paths.
        self.resizeDocks([self.bookmarks_dock], [int(width * 0.18)],
                         Qt.Horizontal)

    def _build_window(self):
        """Window title, icon, geometry and platform taskbar identity."""
        self.setWindowTitle(self._case_title())

        # Set application icon for all platforms
        app_icon = icons.icon(icons.LOGO_LARGE)
        self.setWindowIcon(app_icon)

        # Set taskbar/dock icon for different platforms
        if os.name == 'nt':  # Windows
            import ctypes
            myappid = 'Trace'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        else:  # macOS and Linux
            # For macOS and Linux, setting the app icon at application level
            QApplication.instance().setWindowIcon(app_icon)

        self.setGeometry(DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y, DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)
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
            parts.append(f"inode {inode}")

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
        file_actions = {
            'Add Evidence File': self.load_image_evidence,
            'Remove Evidence File': self.remove_image_evidence,
            'separator': None,  # This will add a separator
            'Exit': self.close
        }

        self.create_menu(menu_bar, 'File', file_actions)

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

        case_menu.addSeparator()
        open_folder_action = QAction("Open Case Folder", self)
        open_folder_action.triggered.connect(self.open_case_folder)
        case_menu.addAction(open_folder_action)
        self.open_case_folder_action = open_folder_action

        for action in (self.case_properties_action, self.verify_case_action,
                       self.open_case_folder_action):
            action.setEnabled(self.case is not None)
        if self.case is None:
            case_menu.setToolTipsVisible(True)
            for action in case_menu.actions():
                action.setToolTip("Quick triage: no case is open.")

        menu_bar.addMenu(case_menu)

        view_menu = QMenu('View', self)
        # Kept so the docks can add their own toggles once they
        # exist -- menus are built before the docks are.
        self._view_menu = view_menu

        # Create the "Full Screen" action and connect it to the showFullScreen slot
        full_screen_action = QAction("Full Screen", self)
        full_screen_action.triggered.connect(self.showFullScreen)
        view_menu.addAction(full_screen_action)

        # Create the "Normal Screen" action and connect it to the showNormal slot
        normal_screen_action = QAction("Normal Screen", self)
        normal_screen_action.triggered.connect(self.showNormal)
        view_menu.addAction(normal_screen_action)

        # Add a separator
        view_menu.addSeparator()

        # **Add Theme Selection Actions**
        # Create an action group for themes
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)  # Only one theme can be selected at a time

        # Light Theme Action
        light_theme_action = QAction("Light Mode", self)
        light_theme_action.setCheckable(True)
        light_theme_action.setChecked(True)  # Set Light Theme as default
        light_theme_action.triggered.connect(lambda: self.apply_stylesheet('light'))
        theme_group.addAction(light_theme_action)
        view_menu.addAction(light_theme_action)

        # Dark Theme Action
        dark_theme_action = QAction("Dark Mode", self)
        dark_theme_action.setCheckable(True)
        dark_theme_action.triggered.connect(lambda: self.apply_stylesheet('dark'))
        theme_group.addAction(dark_theme_action)
        view_menu.addAction(dark_theme_action)

        # **Apply the default stylesheet**
        self.apply_stylesheet('light')

        tools_menu = QMenu('Tools', self)

        # Both entries open a picker when more than one image is loaded, so
        # they work the same way whether there is one image or several.
        image_info_action = QAction("Image Information", self)
        image_info_action.triggered.connect(self.show_image_info_menu)
        tools_menu.addAction(image_info_action)

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.show_verify_menu)
        tools_menu.addAction(verify_image_action)

        # Add "Options" menu for API key configuration
        options_menu = QMenu('Options', self)
        api_key_action = QAction("API Keys", self)
        api_key_action.triggered.connect(self.show_api_key_dialog)
        options_menu.addAction(api_key_action)

        help_menu = QMenu('Help', self)
        about_action = QAction("About", self)
        about_action.triggered.connect(lambda: AboutDialog(self).exec())
        help_menu.addAction(about_action)

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
        self.main_toolbar.addAction(
            self.create_action(icons.EVIDENCE_ADD, "Load Image", self.load_image_evidence))
        self.main_toolbar.addAction(
            self.create_action(icons.EVIDENCE_REMOVE, "Remove Image", self.remove_image_evidence))
        self.main_toolbar.addSeparator()

        # Create verify_image_button as an attribute of MainWindow
        self.verify_image_button = self.create_action(icons.VERIFY, "Verify Image",
                                                     self.show_verify_menu)
        self.main_toolbar.addAction(self.verify_image_button)


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
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        self.tree_dock = tree_dock = QDockWidget('Tree View', self)
        tree_dock.setObjectName('treeDock')

        tree_dock.setWidget(self.tree_viewer)
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
        self.listing_table.setColumnCount(12)

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
        self.listing_layout.addWidget(self.listing_table)  # Table below toolbar

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
             'Modified Date', 'Changed Date', 'Path', 'Info', 'Seq', 'Attributes']
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

        self.deleted_files_widget = FileCarvingWidget(self)
        # Inject what the widget needs rather than letting it reach back up
        # through a MainWindow reference into db_manager.
        self.deleted_files_widget.icon_resolver = self.db_manager.get_icon_path
        self.deleted_files_widget.carved_file_opened.connect(self.update_viewer_with_file_content)
        self.result_viewer.addTab(self.deleted_files_widget, 'Deleted Files')

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
        self.search_panel.result_activated.connect(self.open_search_result)

        # Search results get their own tab rather than borrowing the listing
        # table. Sharing it meant every search toggled columns and saved and
        # restored browse state, and coming back was a mode change.
        self.result_viewer.addTab(self.search_panel, 'Search')

    def _build_viewer_dock(self):
        """Bottom "Utils" dock holding the viewer tabs."""
        self.viewer_tab = QTabWidget(self)

        self.hex_viewer = HexViewer(self)
        self.text_viewer = TextViewer(self)
        self.application_viewer = UnifiedViewer(self)
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.metadata_viewer = MetadataViewer(self.image_handler)
        self.exif_viewer = ExifViewer(self)
        self.virus_total_api = VirusTotal()

        # Each viewer is wrapped in an adapter exposing a common
        # display()/clear() interface, so nothing below has to dispatch on a
        # tab index. Tab order comes from this list alone.
        self.case_panel = CasePanel()
        self.case_panel.set_case(self.case)

        self.notes_panel = NotesPanel()
        self.notes_panel.set_case(self.case)

        self.viewer_adapters = [
            HexAdapter(self.hex_viewer),
            TextAdapter(self.text_viewer),
            ApplicationAdapter(self.application_viewer),
            MetadataAdapter(self.metadata_viewer),
            ExifAdapter(self.exif_viewer),
            VirusTotalAdapter(self.virus_total_api),
            CaseAdapter(self.case_panel),
            NotesAdapter(self.notes_panel),
        ]
        for adapter in self.viewer_adapters:
            self.viewer_tab.addTab(adapter.widget, adapter.label)

        # Set the API key if it exists
        virus_total_key = self.api_keys.get('API_KEYS', 'virustotal', fallback='')
        self.virus_total_api.set_api_key(virus_total_key)

        # Bookmarks live in the right dock, which was unused: they are a
        # standing list an examiner returns to, not something to page to
        # through a tab.
        self.bookmarks_panel = BookmarksPanel()
        self.bookmarks_panel.set_case(self.case)
        self.bookmarks_panel.jump_requested.connect(self.go_to_bookmark)
        self.bookmarks_panel.bookmarks_changed.connect(
            self.refresh_bookmarks_tree)
        self.bookmarks_dock = QDockWidget('Bookmarks', self)
        self.bookmarks_dock.setObjectName("bookmarksDock")
        self.bookmarks_dock.setWidget(self.bookmarks_panel)
        self.addDockWidget(Qt.RightDockWidgetArea, self.bookmarks_dock)
        # Hidden by default. The listing is where the investigation happens and
        # it should have the width; bookmarks live in the tree, and this dock
        # is for anyone who wants the fuller view with labels and dates.
        self.bookmarks_dock.hide()

        # Qt gives every dock a checkable show/hide action; using it means the
        # menu and the dock's own close button can never disagree.
        bookmarks_action = self.bookmarks_dock.toggleViewAction()
        bookmarks_action.setText("Bookmarks Panel")
        self._view_menu.addAction(bookmarks_action)
        self._view_menu.addSeparator()

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

        # Pass the updated API keys to the appropriate modules
        self.virus_total_api.set_api_key(virus_total_key)

    def handler_for(self, image_path):
        """An ImageHandler for `image_path`, reusing the loaded one if it fits.

        Only one image is open at a time, so a picker that offers several has
        to open the one it was asked for -- otherwise choosing the second image
        silently described or hashed the first.
        """
        if not image_path or image_path == self.current_image_path:
            return self.image_handler

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
            if item.text(0) != image_path:
                continue
            hue = icons.VERIFIED_HUE if verified else icons.UNVERIFIED_HUE
            item.setIcon(0, icons.recoloured(disk_icon, hue, TREE_ICON_SIZE))
            item.setToolTip(0,
                            "Hashes verified against those stored in the image"
                            if verified else
                            "Checked this session: hashes did not match")
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
        menu.exec(QCursor.pos())

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
        menu.exec(QCursor.pos())

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
        inode = data.get('inode_number')
        offset = data.get('start_offset')
        if inode is None or offset is None:
            return False

        name = data.get('name') or ''
        size = data.get('size') or 0
        if isinstance(size, str):
            size = 0

        # Reading a large file to find out it is not an archive is wasted
        # work; the extension and a header read settle it far more cheaply.
        if size and size > archives.MAX_MEMBER_BYTES:
            return False

        try:
            header = self.image_handler.read_file_bytes(inode, offset, 512) \
                if hasattr(self.image_handler, 'read_file_bytes') else None
        except Exception:
            header = None

        if header is not None and not archives.detect_archive(header):
            return False

        self.set_status(f"Opening {name}…")
        try:
            content, _meta = self.image_handler.get_file_content(inode, offset)
        except Exception as exc:
            logger.debug("Could not read %s: %s", name, exc)
            self.clear_status()
            return False

        if not content or not archives.detect_archive(content):
            self.clear_status()
            return False

        self._archive_stack = [(name, content, dict(data))]
        return self.show_archive_level()

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

        self._archive_stack.pop()
        if self._archive_stack:
            self.show_archive_level()
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

    def mark_bookmarked_rows(self):
        """Put the bookmark mark on rows that have one, in place.

        Called after a bookmark is added or removed so the listing updates
        without being rebuilt -- rebuilding would lose the scroll position and
        the selection the examiner is working from.
        """
        if not hasattr(self, 'listing_table'):
            return
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
            bookmarked = bool(ref and ref in self._bookmarked_refs)

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
                self._bookmarked_refs.add(ref)

    def refresh_bookmarks(self):
        """Redraw both views of the bookmark list.

        The tree node and the dock panel show the same rows; refreshing one
        and forgetting the other is how they drift apart.
        """
        self._reload_bookmarked_refs()
        if getattr(self, 'bookmarks_panel', None) is not None:
            self.bookmarks_panel.refresh()
        self.refresh_bookmarks_tree()
        # Redraw the listing so a newly bookmarked row picks up its mark.
        self.mark_bookmarked_rows()

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
        self._bookmarked_refs = {r['artifact_ref'] for r in rows
                                 if r.get('artifact_ref')}
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

        if parsed['kind'] != 'file':
            # Byte ranges and registry keys need their own viewers; say so
            # rather than silently doing nothing.
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
        try:
            fs_info = self.image_handler.get_fs_info(offset)
            if fs_info is not None:
                meta = fs_info.open_meta(inode=inode)
                parent = getattr(meta.info.name, 'par_addr', None)
        except Exception as exc:
            logger.debug("Could not find the parent of inode %s: %s",
                         inode, exc)

        if parent is None:
            parent = self.image_handler.get_root_inode(offset)

        try:
            entries = self.image_handler.get_directory_contents(offset, parent)
        except Exception as exc:
            logger.debug("Could not list the parent directory: %s", exc)
            return

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
        for row in rows:
            path = row['path']
            if not os.path.exists(path):
                missing.append((row, 'is not where the case recorded it'))
                continue
            if self.open_evidence_image(path, record_in_case=False):
                opened += 1
            else:
                missing.append((row, 'could not be opened'))

        if opened:
            self.set_status(
                f"Reopened {opened} of {len(rows)} piece(s) of evidence")

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
        """Re-check every piece of evidence against its recorded hash."""
        if not self.case:
            return
        outcomes = self.case.verify_evidence()
        if not outcomes:
            message.information(self, "No evidence",
                                "This case has no evidence to check yet.")
            return

        trouble = [(row, status, detail) for row, status, detail in outcomes
                   if status in ('missing', 'changed')]
        if getattr(self, 'case_panel', None):
            self.case_panel.refresh()

        if not trouble:
            message.information(
                self, "Evidence verified",
                f"All {len(outcomes)} piece(s) of evidence match what the "
                f"case recorded.")
            return

        lines = [f"{row['display_name'] or row['path']}: {detail}"
                 for row, _status, detail in trouble]
        message.warning(
            self, "Evidence does not match",
            "Some evidence is not as the case recorded it.",
            "\n\n".join(lines))

    def open_case_folder(self):
        """Show the case folder in the system file manager."""
        if not self.case:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.case.folder))

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.deleted_files_widget.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)
        self.search_panel.setEnabled(state)

    def create_menu(self, menu_bar, menu_name, actions):
        menu = QMenu(menu_name, self)
        for action_name, action_function in actions.items():
            if action_name == 'separator':
                menu.addSeparator()
            else:
                action = menu.addAction(action_name)
                action.triggered.connect(action_function)
        menu_bar.addMenu(menu)
        return menu

    @staticmethod
    def create_tree_item(parent, text, icon_path, data):
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, data)
        return item

    def on_viewer_dock_focus(self, visible):
        """Kept for the visibilityChanged connection; no longer resizes.

        This used to strip the dock's size constraints when it became visible
        and re-pin them when it did not, which is how a large image in the
        Application tab ended up resizing the whole dock. The dock now keeps a
        simple minimum height and is otherwise the user's to size.
        """
        return

    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)
        self.clear_evidence_views()
        self.set_status_context("No evidence loaded")
        self.current_image_path = None
        self.current_offset = None
        self.evidence_files.clear()
        self.deleted_files_widget.clear()

        # Clear search bar and reset filters
        self.listing_search_bar.clear()

        # Clear navigation history
        self._directory_history = []
        self._history_index = -1
        self._update_navigation_buttons()

        # Disable directory up button
        self.go_up_action.setEnabled(False)

    def active_viewer_adapter(self):
        """Adapter for the currently selected viewer tab, or None."""
        index = self.viewer_tab.currentIndex()
        if 0 <= index < len(self.viewer_adapters):
            return self.viewer_adapters[index]
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

        # Cleanup resources
        self.cleanup_resources()
        event.accept()

    def cleanup_resources(self):
        """Clean up all resources when closing the application."""
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

        # Clean up image handler resources
        if self.image_handler:
            try:
                self.image_handler.close_resources()
            except Exception as e:
                logger.error(f"Error closing image handler: {str(e)}")

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
        if getattr(self, 'search_panel', None) is not None:
            try:
                self.search_panel.shutdown()
            except Exception as exc:
                logger.error("Error stopping the search index: %s", exc)

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
        pattern = "trace_temp_*"
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
        """Open an image with a specific filter on Kali Linux."""
        # Define the supported image file extensions, including both lowercase and uppercase variants
        supported_image_extensions = ["*.e01", "*.E01", "*.s01", "*.S01",
                                      "*.l01", "*.L01", "*.raw", "*.RAW",
                                      "*.img", "*.IMG", "*.dd", "*.DD",
                                      "*.iso", "*.ISO", "*.ad1", "*.AD1",
                                      "*.001", "*.s01", "*.ex01", "*.dmg",
                                      "*.sparse", "*.sparseimage"]

        # Construct the file filter string with both uppercase and lowercase extensions
        file_filter = "Supported Image Files ({})".format(" ".join(supported_image_extensions))

        # Open file dialog with the specified file filter
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", file_filter)

        if image_path:
            self.open_evidence_image(image_path)

    def open_evidence_image(self, image_path, record_in_case=True):
        """Load an image and show it. Returns True when it opened.

        Separated from the file dialog so reopening a case can load the
        evidence it already knows about through exactly this code -- a second
        implementation of image loading would drift from this one, and this is
        what decides whether an image opens at all.
        """
        try:
            image_path = os.path.normpath(image_path)

            # Create a progress dialog to show loading status
            progress = QProgressDialog("Loading image...", "Cancel", 0, 100, self)
            progress.setWindowTitle("Loading Evidence")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(PROGRESS_MIN_DURATION)  # Show dialog only if operation takes more than threshold
            progress.setValue(10)

            # Clean up any existing ImageHandler resources
            if self.image_handler:
                self.image_handler.close_resources()

            # Create or update the ImageHandler instance with progress updates
            progress.setValue(20)

            # Process events to update UI
            QApplication.processEvents()

            # Create a new ImageHandler with the selected image
            self.image_handler = ImageHandler(image_path)
            if not self.image_handler.loaded:
                raise ValueError(
                    "The file could not be opened as a disk image. It may be "
                    "corrupt, incomplete (a missing .E02 segment, say), or an "
                    "unsupported format.")
            progress.setValue(50)

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

            self.current_image_path = image_path
            self.set_status_context(
                f"{os.path.basename(image_path)}   ·   "
                f"{len(self.image_handler.get_partitions())} partitions")
            progress.setValue(70)

            # Pass the image handler to widgets that need it
            # One mechanism for every consumer. These widgets are built
            # before an image is loaded, so they are constructed with
            # image_handler=None and pointed at the real handler here.
            for widget in (self.deleted_files_widget,
                           self.registry_extractor_widget,
                           self.metadata_viewer):
                widget.set_image_handler(self.image_handler)
            # Carved output belongs inside the case when there is one:
            # carved files are named after their offset alone, so two
            # images sharing one directory overwrite each other.
            self.deleted_files_widget.set_case_folder(
                self.case.folder if self.case else None)
            self.search_panel.set_image_handler(self.image_handler)
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
            message.critical(self, "Error Loading Image", f"Failed to load image: {str(e)}")
            # Remove the image from evidence files if it was added but failed to load
            if image_path in self.evidence_files:
                self.evidence_files.remove(image_path)
            return False

    def remove_image_evidence(self):
        if not self.evidence_files:
            message.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        # Prepare the options for the dialog
        options = self.evidence_files + ["Remove All"]
        selected_option, ok = QInputDialog.getItem(self, "Remove Evidence File",
                                                   "Select an evidence file to remove or 'Remove All':",
                                                   options, 0, False)

        if ok:
            if selected_option == "Remove All":
                # Remove all evidence files
                self.tree_viewer.invisibleRootItem().takeChildren()  # Remove all children from the tree viewer
                self.clear_ui()  # Clear the UI
                message.information(self, "Remove Evidence", "All evidence files have been removed.")
            else:
                # Remove the selected evidence file
                self.evidence_files.remove(selected_option)
                self._release_auxiliary_handler(selected_option)
                self.remove_from_tree_viewer(selected_option)
                self.clear_ui()
                message.information(self, "Remove Evidence", f"{selected_option} has been removed.")
        # clear all tabs if there are no evidence files loaded
        if not self.evidence_files:
            self.clear_ui()
            # disable all tabs
            self.enable_tabs(False)
            # The toolbar icon no longer tracks verification -- that is shown
            # per image in the tree -- so there is nothing to reset here.

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == evidence_name:
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        root_item_tree = self.create_tree_item(self.tree_viewer, image_path,
                                               self.db_manager.get_icon_path('device', 'media-optical'),
                                               {"start_offset": 0})

        partitions = self.image_handler.get_partitions()

        # Check if the image has partitions or a recognizable file system
        if not partitions:
            if self.image_handler.has_filesystem(0):
                # The image has a filesystem but no partitions, populate root directory
                self.populate_contents(root_item_tree, {"start_offset": 0})
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
            fs_type = self.image_handler.get_fs_type(start)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
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

        data = item.data(0, Qt.UserRole)
        if data is None:
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
                else:
                    self.error.emit("Unable to read file content.")
            except Exception as e:
                self.error.emit(f"Error reading file: {str(e)}")

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
        if data.get('is_bookmark'):
            self.go_to_bookmark(data['bookmark'])
            return
        if data.get('is_bookmarks_root'):
            item.setExpanded(not item.isExpanded())
            return

        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        if not data:
            return

        # Store the current selection data. The item goes along so a volume,
        # which carries no name in its data, can be labelled from its row.
        self.current_selected_data = data
        self.update_status_for_selection(data, item)

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
                        self.current_path = data.get("path", os.path.join(self.current_path, data.get("name", "")))

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
                entries = self.image_handler.get_directory_contents(data["start_offset"],
                                                                    5)  # 5 is the root inode for NTFS

                # Reset path to root when viewing partitions
                self.current_path = "/"

                # Treat partition as a volume for history
                if "type" not in data:
                    data["type"] = "volume"
                if "inode_number" not in data:
                    data["inode_number"] = self.image_handler.get_root_inode(
                        data["start_offset"])

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
            "parent_inode": directory_data.get("parent_inode")
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

            # Get the root items
            root_item = self.tree_viewer.invisibleRootItem()

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
            # Re-enable updates and sorting
            self.listing_table.setUpdatesEnabled(True)
            self.listing_table.setSortingEnabled(True)
            self._fit_listing_columns()

    #: Widest a listing column may grow when fitted. Path and Attributes hold
    #: strings long enough to push the timestamps off screen, so they elide
    #: with a tooltip rather than setting the table's width.
    _LISTING_COLUMN_CAPS = {8: 420, 11: 320}

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
            file_path = os.path.join(self.current_path, entry_name) if entry_name != ".." else os.path.dirname(
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
            self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))
            self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
            self.listing_table.setItem(row_position, 3, QTableWidgetItem(str(size)))
            self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(created)))
            self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(accessed)))
            self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(modified)))
            self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))
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

            if inode_number:
                # Ask the active viewer whether it wants a stream, rather than
                # hardcoding the Application tab's index here.
                adapter = self.active_viewer_adapter()
                if adapter is not None and adapter.wants_stream(self.current_selected_data):
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

            bookmark_action = menu.addAction("Add Bookmark")
            bookmark_action.setEnabled(self.case is not None)
            if self.case is None:
                bookmark_action.setToolTip("Bookmarks are kept in a case.")
            bookmark_action.triggered.connect(
                lambda: self.add_bookmark_for(data))
            menu.addSeparator()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(lambda: self.handle_export(data, QFileDialog.getExistingDirectory(self,
                                                                                                              "Select Destination Directory")))

            menu.exec_(self.listing_table.viewport().mapToGlobal(position))

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
            menu = QMenu()
            data = selected_item.data(0, Qt.UserRole)

            # A bookmark in the tree gets the actions the panel offers, so the
            # dock is genuinely optional rather than the only way to manage
            # them.
            if data and data.get('is_bookmark'):
                row = data['bookmark']
                go_action = menu.addAction("Go to Artifact")
                rename_action = menu.addAction("Rename Bookmark...")
                menu.addSeparator()
                remove_action = menu.addAction("Remove Bookmark")
                chosen = menu.exec_(
                    self.tree_viewer.viewport().mapToGlobal(position))
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

            # Check if the selected item is a root item (disk image)
            if selected_item and selected_item.parent() is None:
                # The row names the image, so describe that one rather than
                # whichever handler happens to be current.
                image_path = selected_item.text(0)
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
                bookmark_action = menu.addAction("Add Bookmark")
                bookmark_action.setEnabled(self.case is not None)
                bookmark_action.triggered.connect(
                    lambda: self.add_bookmark_for(data))
                menu.addSeparator()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(
                lambda: self.handle_export(self.tree_viewer.itemFromIndex(indexes[0]).data(0, Qt.UserRole),
                                           QFileDialog.getExistingDirectory(self, "Select Destination Directory")))

            menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

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
        # Root directory (5 is typically root in NTFS) has no parent
        if parent_inode == 5:
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

            # Clear and populate table
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
        inode_item = QTableWidgetItem(str(file_data.get('inode_number', '')))
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
                    self.current_path = os.path.join(self.current_path, data.get("name", ""))

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
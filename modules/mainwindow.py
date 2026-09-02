import configparser
import os
import datetime
import pyewf
import pytsk3
import tempfile
import gc
import time
import logging
import re
from typing import Optional, Dict, Any, List
from Registry import Registry
from sqlite3 import connect as sqlite3_connect
from contextlib import contextmanager
from functools import lru_cache
from PySide6.QtCore import Qt, QSize, QThread, Signal, QTimer, QMargins
from PySide6.QtGui import QIcon, QFont, QPalette, QBrush, QAction, QActionGroup, QPixmap, QPainter, QColor
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QHBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit,
                               QFormLayout, QApplication, QWidget, QProgressDialog, QSizePolicy, QGroupBox,
                               QCheckBox, QGridLayout, QScrollArea, QPushButton, QToolButton)

from modules.about import AboutDialog
from modules.converter import Main
from modules.exif_tab import ExifViewer
from modules.file_carving import FileCarvingWidget
from modules.hex_tab import HexViewer
from modules.metadata_tab import MetadataViewer
from modules.registry import RegistryExtractor
from modules.text_tab import TextViewer
from modules.unified_application_manager import UnifiedViewer
from modules.verification import VerificationWidget
from modules.virus_total_tab import VirusTotal
from modules.constants import (API_DIALOG_WIDTH, COLUMN_WIDTHS, DEFAULT_WINDOW_HEIGHT,
                               DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_X, DEFAULT_WINDOW_Y,
                               INPUT_FIELD_MIN_WIDTH, PROGRESS_DIALOG_WIDTH, PROGRESS_MIN_DURATION,
                               QT_MAX_SIZE, SECTOR_SIZE, TABLE_BATCH_SIZE, TABLE_COLUMN_COUNT,
                               TABLE_ICON_SIZE, TOOLBAR_ICON_SIZE, TREE_ICON_SIZE,
                               VIEWER_DOCK_MAX_SIZE, VIEWER_DOCK_MAX_WIDTH, VIEWER_DOCK_MIN_HEIGHT)
from modules.database import DatabaseManager
from modules.image_handler import EWFImgInfo, ImageHandler
from modules.paths import config_file, resource_path
from modules.utils import FileSystemUtils, safe_datetime
from modules.viewer_registry import (ApplicationAdapter, ExifAdapter, HexAdapter,
                                     MetadataAdapter, TextAdapter, VirusTotalAdapter)
from modules.workers import ExportWorker

logger = logging.getLogger('TRACE.MainWindow')

# ==================== FILE SEARCH WIDGET CLASSES ====================
class SizeTableWidgetItem(QTableWidgetItem):
    """Custom table widget item for proper size sorting."""
    def __lt__(self, other):
        return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))




class MainWindow(QMainWindow):
    # Class variable for icon caching
    _icon_cache = {}

    def __init__(self):
        super().__init__()

        # Create a database manager for icon lookup
        self.db_manager = DatabaseManager(resource_path('tools/new_database_mappings.db'))

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

        # Search debounce timer - wait for user to stop typing before searching
        self._search_timer = QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(500)  # 500ms delay after last keystroke
        self._search_timer.timeout.connect(self._execute_search)

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

        self.evidence_files = []

        self.initialize_ui()

    # ==================== HELPER METHODS ====================

    def _get_file_icon(self, file_extension: str) -> QIcon:
        """Get icon for file extension with caching."""
        if file_extension not in self._icon_cache:
            icon_path = self.db_manager.get_icon_path('file', file_extension)
            self._icon_cache[file_extension] = QIcon(icon_path)
        return self._icon_cache[file_extension]

    def _confirm_exit(self) -> bool:
        """Ask user to confirm exit."""
        reply = QMessageBox.question(
            self, 'Exit Confirmation',
            'Are you sure you want to exit?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        return reply == QMessageBox.StandardButton.Yes

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
            "name": entry["name"]
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
            "name": entry["name"]
        })

    def _populate_table_entry(self, row_position: int, entry: Dict[str, Any], offset: int) -> None:
        """Populate a single table row with entry data."""
        entry_name = entry.get("name", "")
        inode_number = entry.get("inode_number", 0)
        is_directory = entry.get("is_directory", False)
        description = "Dir" if is_directory else "File"
        size_in_bytes = entry.get("size", 0)
        readable_size = self.image_handler.get_readable_size(size_in_bytes)
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
                                          modified, changed, parent_inode)

    # ==================== END HELPER METHODS ====================

    def initialize_ui(self):
        self.setWindowTitle('Trace 1.2.0')

        # Set application icon for all platforms
        app_icon = QIcon(resource_path('Icons/logo_prev_ui.png'))
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

        menu_bar = QMenuBar(self)
        file_actions = {
            'Add Evidence File': self.load_image_evidence,
            'Remove Evidence File': self.remove_image_evidence,
            'separator': None,  # This will add a separator
            'Exit': self.close
        }

        self.create_menu(menu_bar, 'File', file_actions)

        view_menu = QMenu('View', self)

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

        # Add the view menu to the menu bar
        menu_bar.addMenu(view_menu)

        # **Apply the default stylesheet**
        self.apply_stylesheet('light')

        tools_menu = QMenu('Tools', self)

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.verify_image)
        tools_menu.addAction(verify_image_action)

        conversion_action = QAction("Convert E01 to DD/RAW", self)
        conversion_action.triggered.connect(self.show_conversion_widget)
        tools_menu.addAction(conversion_action)

        # Add "Options" menu for API key configuration
        options_menu = QMenu('Options', self)
        api_key_action = QAction("API Keys", self)
        api_key_action.triggered.connect(self.show_api_key_dialog)
        options_menu.addAction(api_key_action)

        help_menu = QMenu('Help', self)
        help_menu.addAction("About")
        help_menu.triggered.connect(lambda: AboutDialog(self).exec_())

        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(options_menu)
        menu_bar.addMenu(help_menu)

        self.setMenuBar(menu_bar)

        self.main_toolbar = QToolBar()
        self.main_toolbar.setMovable(False)
        self.main_toolbar.setFloatable(False)
        self.main_toolbar.addAction(
            self.create_action(resource_path('Icons/icons8-evidence-48.png'), "Load Image", self.load_image_evidence))
        self.main_toolbar.addAction(
            self.create_action(resource_path('Icons/icons8-evidence-96.png'), "Remove Image", self.remove_image_evidence))
        self.main_toolbar.addSeparator()

        # Create verify_image_button as an attribute of MainWindow
        self.verify_image_button = self.create_action(resource_path('Icons/icons8-verify-blue.png'), "Verify Image", self.verify_image)
        self.main_toolbar.addAction(self.verify_image_button)


        # Navigation buttons (Back, Forward, Up) will be added to the listing search toolbar
        # Created later in the UI setup

        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)

        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setIconSize(QSize(16, 16))
        self.tree_viewer.setHeaderHidden(True)
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        tree_dock = QDockWidget('Tree View', self)

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
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(10)  # 10 columns: Name, Inode, Type, Size, 4 timestamps, Path, Info

        # Enable horizontal scrolling for smaller windows
        self.listing_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.listing_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Connect click event to handle navigation in search mode
        self.listing_table.itemClicked.connect(self.on_listing_table_item_clicked)

        # Create a QVBoxLayout for the listing tab
        self.listing_layout = QVBoxLayout()
        self.listing_layout.setContentsMargins(0, 0, 0, 0)  # Set to zero to remove margins
        self.listing_layout.setSpacing(0)  # Remove spacing between widgets

        # ==================== CREATE UNIFIED TOOLBAR (like File Carving tab) ====================
        self.listing_toolbar = QToolBar()
        self.listing_toolbar.setContentsMargins(0, 0, 0, 0)
        self.listing_toolbar.setMovable(False)

        # LEFT SIDE: Icon and Title
        self.listing_icon_label = QLabel()
        self.listing_icon_label.setPixmap(QPixmap(resource_path('Icons/icons8-search-in-browser-50.png')))
        self.listing_icon_label.setFixedSize(48, 48)
        self.listing_toolbar.addWidget(self.listing_icon_label)

        self.listing_title_label = QLabel("File System Browser")
        self.listing_title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                color: #37c6d0;
                font-weight: bold;
                margin-left: 8px;
            }
        """)
        self.listing_toolbar.addWidget(self.listing_title_label)

        # Add spacer after title
        title_spacer = QLabel()
        title_spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.listing_toolbar.addWidget(title_spacer)

        # MIDDLE: Navigation buttons (Back, Forward, Up) - next to title
        self.back_action = QAction(QIcon(resource_path("Icons/icons8-left-arrow-50.png")), "Back", self)
        self.back_action.triggered.connect(self.navigate_back)
        self.back_action.setEnabled(False)
        self.listing_toolbar.addAction(self.back_action)

        self.forward_action = QAction(QIcon(resource_path("Icons/icons8-right-arrow-50.png")), "Forward", self)
        self.forward_action.triggered.connect(self.navigate_forward)
        self.forward_action.setEnabled(False)
        self.listing_toolbar.addAction(self.forward_action)

        self.go_up_action = QAction(QIcon(resource_path("Icons/icons8-thick-arrow-pointing-up-50.png")), "Go Up Directory", self)
        self.go_up_action.triggered.connect(self.navigate_up_directory)
        self.go_up_action.setEnabled(False)
        self.listing_toolbar.addAction(self.go_up_action)

        # Add vertical separator after navigation buttons
        self.listing_toolbar.addSeparator()

        # RIGHT SIDE: Search functionality
        # Add search bar
        self.listing_search_bar = QLineEdit()
        self.listing_search_bar.setObjectName("listingSearchBar")
        self.listing_search_bar.setPlaceholderText("Search files (press Enter, supports wildcards: *.pdf, name.*)")
        self.listing_search_bar.setFixedHeight(35)
        self.listing_search_bar.setFixedWidth(450)
        # Only search when user presses Enter
        self.listing_search_bar.returnPressed.connect(self.trigger_listing_search)
        # Monitor text changes for auto-clearing results
        self.listing_search_bar.textChanged.connect(self.on_listing_search_text_changed)
        self.listing_toolbar.addWidget(self.listing_search_bar)

        # Add small end spacer
        end_spacer = QWidget()
        end_spacer.setFixedWidth(10)
        self.listing_toolbar.addWidget(end_spacer)

        # Add the single toolbar and listing table to the layout
        self.listing_layout.addWidget(self.listing_toolbar)  # Single unified toolbar
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
        self.listing_table.setColumnWidth(9, 250)                        # Info - 250px (for volumes)

        # Remove any extra space in the header
        header.setStyleSheet("QHeaderView::section { margin-top: 0px; padding-top: 2px; }")
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Set the header labels
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date', 'Modified Date', 'Changed Date', 'Path', 'Info']
        )

        self.listing_table.itemDoubleClicked.connect(self.on_listing_table_item_clicked)
        self.listing_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listing_table.customContextMenuRequested.connect(self.open_listing_context_menu)
        self.listing_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Set the color of the selected row
        palette = self.listing_table.palette()
        palette.setBrush(QPalette.Highlight, QBrush(Qt.lightGray))  # Change Qt.lightGray to your preferred color
        self.listing_table.setPalette(palette)

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
        self.result_viewer.addTab(self.registry_extractor_widget, 'Registry')

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
        self.viewer_adapters = [
            HexAdapter(self.hex_viewer),
            TextAdapter(self.text_viewer),
            ApplicationAdapter(self.application_viewer),
            MetadataAdapter(self.metadata_viewer),
            ExifAdapter(self.exif_viewer),
            VirusTotalAdapter(self.virus_total_api),
        ]
        for adapter in self.viewer_adapters:
            self.viewer_tab.addTab(adapter.widget, adapter.label)

        # Set the API key if it exists
        virus_total_key = self.api_keys.get('API_KEYS', 'virustotal', fallback='')
        self.virus_total_api.set_api_key(virus_total_key)

        self.viewer_dock = QDockWidget('Utils', self)
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        self.viewer_dock.setMinimumSize(VIEWER_DOCK_MAX_WIDTH, VIEWER_DOCK_MIN_HEIGHT)
        self.viewer_dock.setMaximumSize(VIEWER_DOCK_MAX_WIDTH, VIEWER_DOCK_MIN_HEIGHT)
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        # disable all tabs before loading an image file
        self.enable_tabs(False)

    def apply_stylesheet(self, theme='light'):
        if theme == 'dark':
            qss_file = resource_path('styles/dark_theme.qss')
        else:
            qss_file = resource_path('styles/light_theme.qss')  # Ensure your existing QSS file is named 'light_theme.qss'

        try:
            with open(qss_file, 'r') as f:
                stylesheet = f.read()
            QApplication.instance().setStyleSheet(stylesheet)
        except Exception as e:
            logger.error(f"Error loading stylesheet {qss_file}: {e}")

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
        dialog.exec_()

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
            QMessageBox.warning(
                self, "Could not save API key",
                f"The API key could not be written to disk:\n{e}\n\n"
                "It will be used for this session only.")

        dialog.accept()

        # Pass the updated API keys to the appropriate modules
        self.virus_total_api.set_api_key(virus_total_key)

    def show_conversion_widget(self):
        """Show the conversion widget."""
        self.select_dialog = Main()
        self.select_dialog.show()

    def verify_image(self):
        if self.image_handler is None:
            QMessageBox.warning(self, "Verify Image", "No image is currently loaded.")
            return

        # Show the verification widget
        self.verification_widget = VerificationWidget(self.image_handler)

        # Connect a signal when the verification widget is closed to update the icon
        self.verification_widget.closeEvent = lambda event: self.on_verification_closed(event)

        # Show the widget
        self.verification_widget.show()

    def on_verification_closed(self, event):
        """Handle the verification widget being closed."""
        # Make sure verify_image_button exists before trying to change its icon
        if hasattr(self, 'verify_image_button'):
            if hasattr(self.verification_widget, 'is_verified') and self.verification_widget.is_verified:
                self.verify_image_button.setIcon(QIcon(resource_path('Icons/icons8-verify-48_gren.png')))
            else:
                self.verify_image_button.setIcon(QIcon(resource_path('Icons/icons8-verify-blue.png')))

        # Call the original closeEvent to close the widget
        QWidget.closeEvent(self.verification_widget, event)

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.deleted_files_widget.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)

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
        if visible:  # If the QDockWidget is focused/visible
            self.viewer_dock.setMaximumSize(QT_MAX_SIZE, QT_MAX_SIZE)  # Remove size constraints
        else:  # If the QDockWidget loses focus
            current_height = self.viewer_dock.size().height()  # Get the current height
            self.viewer_dock.setMinimumSize(VIEWER_DOCK_MAX_WIDTH, current_height)
            self.viewer_dock.setMaximumSize(VIEWER_DOCK_MAX_WIDTH, current_height)

    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)
        self.clear_viewers()
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
        for adapter in self.viewer_adapters:
            adapter.clear()
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
                progress.setValue(50)

                # Add the image to evidence files list
                if image_path not in self.evidence_files:
                    self.evidence_files.append(image_path)

                self.current_image_path = image_path
                progress.setValue(70)

                # Pass the image handler to widgets that need it
                # One mechanism for every consumer. These widgets are built
                # before an image is loaded, so they are constructed with
                # image_handler=None and pointed at the real handler here.
                for widget in (self.deleted_files_widget,
                               self.registry_extractor_widget,
                               self.metadata_viewer):
                    widget.set_image_handler(self.image_handler)
                progress.setValue(80)

                # Load partitions into tree view
                QApplication.processEvents()
                self.load_partitions_into_tree(image_path)
                progress.setValue(100)

                # Enable all tabs since we have a valid image
                self.enable_tabs(True)

            except Exception as e:
                QMessageBox.critical(self, "Error Loading Image", f"Failed to load image: {str(e)}")
                # Remove the image from evidence files if it was added but failed to load
                if image_path in self.evidence_files:
                    self.evidence_files.remove(image_path)

    def remove_image_evidence(self):
        if not self.evidence_files:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
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
                QMessageBox.information(self, "Remove Evidence", "All evidence files have been removed.")
            else:
                # Remove the selected evidence file
                self.evidence_files.remove(selected_option)
                self.remove_from_tree_viewer(selected_option)
                self.clear_ui()
                QMessageBox.information(self, "Remove Evidence", f"{selected_option} has been removed.")
        # clear all tabs if there are no evidence files loaded
        if not self.evidence_files:
            self.clear_ui()
            # disable all tabs
            self.enable_tabs(False)
            # set the icon back to the original - only if verify_image_button exists
            if hasattr(self, 'verify_image_button'):
                self.verify_image_button.setIcon(QIcon(resource_path('Icons/icons8-verify-blue.png')))

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
                                       "end_offset": size_in_bytes // SECTOR_SIZE})
            return

        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * SECTOR_SIZE
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

    def on_item_clicked(self, item, column):
        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        if not data:
            return

        # Store the current selection data
        self.current_selected_data = data

        # Show a status message in the UI to indicate loading
        statusbar = self.statusBar()
        statusbar.showMessage("Loading content...")

        # Use a background worker thread if processing large files or unallocated space
        try:
            # Check if this is the root disk image item (has start_offset but no type/inode)
            if (data.get("start_offset") == 0 and
                not data.get("type") and
                not data.get("inode_number") and
                not data.get("is_unallocated")):
                # This is the root disk image - display all volumes/partitions
                self.display_volumes_in_listing()
                statusbar.clearMessage()
                return

            if data.get("is_unallocated"):
                # Handle unallocated space in background
                self.unallocated_worker = self.UnallocatedSpaceWorker(
                    self.image_handler, data["start_offset"], data["end_offset"])
                self.unallocated_worker.completed.connect(
                    lambda content: self.update_viewer_with_file_content(content, data))
                self.unallocated_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.unallocated_worker.start()

            elif data.get("type") == "directory":
                # For directories, find parent inode to enable up navigation
                if "parent_inode" not in data and data.get("inode_number"):
                    parent_inode = self.find_parent_inode(data["start_offset"], data["inode_number"])
                    if parent_inode:
                        data["parent_inode"] = parent_inode
                        # Update the stored data with parent information
                        self.current_selected_data = data

                # Handle directories - populate the listing synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))

                # Update current path for directory navigation
                if data.get("name"):
                    if data.get("inode_number") == 5:  # Root directory
                        self.current_path = "/"
                    else:
                        # If it's a regular directory, update the path
                        self.current_path = data.get("path", os.path.join(self.current_path, data.get("name", "")))

                # Update directory up button state
                self.update_directory_up_button()

                # Populate the listing table with directory contents
                self.populate_listing_table(entries, data["start_offset"])

                # Add to navigation history
                self._add_to_history(data)

                statusbar.clearMessage()

            elif data.get("inode_number") is not None:
                # Handle files in background
                self.file_worker = self.FileContentWorker(
                    self.image_handler, data["inode_number"], data["start_offset"])
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
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
                    data["inode_number"] = 5

                self.populate_listing_table(entries, data["start_offset"])

                # Add to navigation history
                self._add_to_history(data)

                statusbar.clearMessage()

            else:
                self.log_error("Clicked item is not a file, directory, or unallocated space.")
                statusbar.clearMessage()

        except Exception as e:
            self.log_error(f"Error processing item: {str(e)}")
            statusbar.clearMessage()

    def update_directory_up_button(self):
        """Update the state of the directory up button based on current selection"""
        if not self.current_selected_data:
            self.go_up_action.setEnabled(False)
            return

        # Check if this is a directory
        if self.current_selected_data.get("type") == "directory":
            inode_number = self.current_selected_data.get("inode_number")
            start_offset = self.current_selected_data.get("start_offset")

            # Check if this is root directory (inode 5 in NTFS)
            is_root = inode_number == 5

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
            # Root directory (5 is typically root in NTFS) has no parent
            if inode_number == 5:
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

        statusbar = self.statusBar()
        statusbar.showMessage("Loading parent directory...")

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

            statusbar.clearMessage()

        except Exception as e:
            self.log_error(f"Error navigating to parent directory: {str(e)}")
            statusbar.clearMessage()

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
        statusbar = self.statusBar()
        statusbar.showMessage("Navigating...")

        try:
            # Restore the path
            self.current_path = history_entry.get("path", "/")

            # Get directory contents
            inode_number = history_entry.get("inode_number")
            start_offset = history_entry.get("start_offset")

            if history_entry.get("type") == "volume":
                # For volumes, get root directory (inode 5)
                entries = self.image_handler.get_directory_contents(start_offset, 5)
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

            statusbar.clearMessage()

        except Exception as e:
            self.log_error(f"Error navigating from history: {str(e)}")
            statusbar.clearMessage()

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

        # Update column headers for volume context
        self.listing_table.setHorizontalHeaderLabels([
            'Name', 'Volume #', 'Type', 'Size', 'Start Offset', 'End Offset',
            'Length', 'Block Size', 'Path', 'Details'
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
                end = start + length - 1
                size_in_bytes = length * SECTOR_SIZE
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
                except:
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
                info_parts.append(f"Start: {start:,} sectors ({start * SECTOR_SIZE:,} bytes)")
                info_parts.append(f"End: {end:,} sectors ({end * SECTOR_SIZE:,} bytes)")
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
            'Modified Date', 'Changed Date', 'Path', 'Info'
        ])

        # Show columns relevant for files/folders, hide Info column
        self.listing_table.setColumnHidden(1, False)  # Show Inode
        self.listing_table.setColumnHidden(4, False)  # Show Created
        self.listing_table.setColumnHidden(5, False)  # Show Accessed
        self.listing_table.setColumnHidden(6, False)  # Show Modified
        self.listing_table.setColumnHidden(7, False)  # Show Changed
        self.listing_table.setColumnHidden(8, False)  # Show Path
        self.listing_table.setColumnHidden(9, True)   # Hide Info

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

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      created, accessed, modified, changed, parent_inode=None):
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
                "path": file_path  # Store the full path
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

        except Exception as e:
            self.log_error(f"Error adding row to listing table: {str(e)}")
            # Try to recover by removing the incomplete row
            try:
                if row_position >= 0:
                    self.listing_table.removeRow(row_position)
            except:
                pass

    def update_viewer_with_file_content(self, file_content, data):
        """Update the active viewer tab with the file content.

        This method is called after file content is loaded, either directly
        or from a background thread.
        """
        # Clear the status message if it exists
        statusbar = self.statusBar()
        statusbar.clearMessage()

        adapter = self.active_viewer_adapter()
        if adapter is None:
            return

        # The Metadata viewer reads the file itself, so it is the one viewer
        # that still has something to show without loaded content.
        if not file_content and adapter.needs_content():
            self.log_error("No content available to display")
            return

        try:
            adapter.display(file_content, data)
        except Exception as e:
            self.log_error(f"Error displaying content in viewer: {str(e)}")

    def update_viewer_with_media_stream(self, file_obj, file_size, metadata, data):
        """Update the application viewer with a media stream for playback."""
        # Clear the status message if it exists
        statusbar = self.statusBar()
        statusbar.clearMessage()

        try:
            adapter = self.active_viewer_adapter()
            if adapter is None or not hasattr(adapter, 'display_stream'):
                return
            adapter.display_stream(file_obj, file_size, data)
        except Exception as e:
            self.log_error(f"Error setting up media stream: {str(e)}")

    def display_content_for_active_tab(self):
        """Display content appropriate for the currently active tab."""
        if not self.current_selected_data:
            return

        statusbar = self.statusBar()
        statusbar.showMessage("Updating view...")

        try:
            # IMPORTANT: Cancel any running workers before starting new ones
            # This prevents race conditions when switching between files
            if hasattr(self, 'media_worker') and self.media_worker and self.media_worker.isRunning():
                try:
                    # Disconnect signals to prevent callbacks
                    self.media_worker.completed.disconnect()
                    self.media_worker.error.disconnect()
                    # Request interruption (graceful)
                    self.media_worker.requestInterruption()
                    # Don't wait - let it finish naturally
                except Exception as e:
                    print(f"Error cancelling media worker: {e}")

            if hasattr(self, 'file_worker') and self.file_worker and self.file_worker.isRunning():
                try:
                    # Disconnect signals to prevent callbacks
                    self.file_worker.completed.disconnect()
                    self.file_worker.error.disconnect()
                    # Request interruption (graceful)
                    self.file_worker.requestInterruption()
                    # Don't wait - let it finish naturally
                except Exception as e:
                    print(f"Error cancelling file worker: {e}")

            inode_number = self.current_selected_data.get("inode_number")
            offset = self.current_selected_data.get("start_offset", self.current_offset)

            if inode_number:
                # Ask the active viewer whether it wants a stream, rather than
                # hardcoding the Application tab's index here.
                adapter = self.active_viewer_adapter()
                if adapter is not None and adapter.wants_stream(self.current_selected_data):
                    # Use MediaStreamWorker for streaming playback (doesn't load content)
                    self.media_worker = self.MediaStreamWorker(self.image_handler, inode_number, offset)
                    self.media_worker.completed.connect(
                        lambda file_obj, file_size, metadata: self.update_viewer_with_media_stream(
                            file_obj, file_size, metadata, self.current_selected_data))
                    self.media_worker.error.connect(
                        lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                    self.media_worker.start()
                else:
                    # For non-media files or other tabs, use FileContentWorker (loads content)
                    self.file_worker = self.FileContentWorker(self.image_handler, inode_number, offset)
                    self.file_worker.completed.connect(
                        lambda content, _: self.update_viewer_with_file_content(content, self.current_selected_data))
                    self.file_worker.error.connect(
                        lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                    self.file_worker.start()
            else:
                statusbar.clearMessage()
        except Exception as e:
            self.log_error(f"Error updating active tab: {str(e)}")
            statusbar.clearMessage()

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
            self.export_worker.error.connect(lambda msg: QMessageBox.warning(self, "Export Error", msg))
            self.export_worker.finished.connect(progress_dialog.close)

            # Connect the cancel button
            progress_dialog.canceled.connect(self.export_worker.terminate)

            # Start the worker
            self.export_worker.start()

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error starting export: {str(e)}")

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

            # Check if the selected item is a root item (disk image)
            if selected_item and selected_item.parent() is None:
                view_os_info_action = menu.addAction("View Image Information")
                view_os_info_action.triggered.connect(lambda: self.view_os_information(indexes[0]))

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(
                lambda: self.handle_export(self.tree_viewer.itemFromIndex(indexes[0]).data(0, Qt.UserRole),
                                           QFileDialog.getExistingDirectory(self, "Select Destination Directory")))

            menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

    def view_os_information(self, index):
        """Display comprehensive disk image information with space allocation pie chart."""
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            # Ensure that only the root item triggers the information display
            return

        # Create modern dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Disk Image Information")
        dialog.resize(1200, 800)

        # Main vertical layout
        main_layout = QVBoxLayout(dialog)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # === TOP SECTION: Image Overview with Chart ===
        top_widget = QWidget()
        top_widget.setStyleSheet("background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;")
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(20, 20, 20, 20)
        top_layout.setSpacing(30)

        # Left: Image Summary Card
        summary_card = QWidget()
        summary_card.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dee2e6;
            }
        """)
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(20, 20, 20, 20)
        summary_layout.setSpacing(12)

        # Title
        title_label = QLabel("Disk Image Overview")
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #212529; border: none;")
        summary_layout.addWidget(title_label)

        # Key info
        image_info = self._get_image_info()
        key_fields = ["Image Path", "Image Type", "Total Size", "Partition Scheme", "Number of Partitions", "Status"]

        for field in key_fields:
            if field in image_info:
                info_row = QWidget()
                info_row.setStyleSheet("border: none;")
                info_row_layout = QHBoxLayout(info_row)
                info_row_layout.setContentsMargins(0, 0, 0, 0)
                info_row_layout.setSpacing(10)

                label = QLabel(f"{field}:")
                label.setStyleSheet("font-weight: bold; color: #495057; font-size: 10pt; border: none;")
                label.setMinimumWidth(140)

                value = QLabel(str(image_info[field]))
                value.setStyleSheet("color: #212529; font-size: 10pt; border: none;")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)

                info_row_layout.addWidget(label)
                info_row_layout.addWidget(value, 1)

                summary_layout.addWidget(info_row)

        summary_layout.addStretch()
        summary_card.setFixedWidth(450)

        # Right: Pie Chart with Legend
        chart_widget = QWidget()
        chart_widget.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dee2e6;
            }
        """)
        chart_outer_layout = QVBoxLayout(chart_widget)
        chart_outer_layout.setContentsMargins(15, 15, 15, 15)
        chart_outer_layout.setSpacing(10)

        chart_title = QLabel("Space Allocation")
        chart_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #212529; border: none;")
        chart_title.setAlignment(Qt.AlignCenter)
        chart_outer_layout.addWidget(chart_title)

        # Create horizontal layout for legend (left) and chart (right)
        chart_content_layout = QHBoxLayout()
        chart_content_layout.setSpacing(15)

        # Create chart
        chart_view, partition_info_list = self._create_space_allocation_chart()

        # Compact legend on the left
        if partition_info_list:
            legend_widget = QWidget()
            legend_widget.setStyleSheet("border: none;")
            legend_layout = QVBoxLayout(legend_widget)
            legend_layout.setContentsMargins(5, 5, 5, 5)
            legend_layout.setSpacing(6)

            for label_text, color in partition_info_list:
                legend_row = QWidget()
                legend_row.setStyleSheet("border: none;")
                legend_row_layout = QHBoxLayout(legend_row)
                legend_row_layout.setContentsMargins(0, 0, 0, 0)
                legend_row_layout.setSpacing(8)

                color_indicator = QLabel()
                color_indicator.setFixedSize(16, 16)
                color_indicator.setStyleSheet(f"""
                    background-color: rgb({color.red()}, {color.green()}, {color.blue()});
                    border: 1px solid #adb5bd;
                    border-radius: 3px;
                """)

                text_label = QLabel(label_text)
                text_label.setStyleSheet("color: #495057; font-size: 9pt; border: none;")
                text_label.setWordWrap(True)

                legend_row_layout.addWidget(color_indicator)
                legend_row_layout.addWidget(text_label, 1)

                legend_layout.addWidget(legend_row)

            legend_layout.addStretch()
            legend_widget.setMaximumWidth(300)
            chart_content_layout.addWidget(legend_widget)

        chart_content_layout.addWidget(chart_view, 1)
        chart_outer_layout.addLayout(chart_content_layout, 1)

        top_layout.addWidget(summary_card)
        top_layout.addWidget(chart_widget, 1)

        main_layout.addWidget(top_widget)

        # === BOTTOM SECTION: Detailed Partition Information ===
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(20, 20, 20, 20)
        bottom_layout.setSpacing(15)

        # Section title
        details_title = QLabel("Volume Details")
        details_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #212529; padding-bottom: 10px;")
        bottom_layout.addWidget(details_title)

        # Professional table view for volume information
        volume_table = QTableWidget()
        volume_table.setSortingEnabled(True)
        volume_table.verticalHeader().setVisible(False)
        volume_table.setObjectName("volumeInfoTable")
        volume_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        volume_table.setAlternatingRowColors(True)
        volume_table.setEditTriggers(QTableWidget.NoEditTriggers)
        volume_table.setIconSize(QSize(24, 24))
        volume_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Enable horizontal scrolling for smaller windows
        volume_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        volume_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Set column count and headers
        volume_table.setColumnCount(10)
        volume_table.setHorizontalHeaderLabels([
            'Volume', 'Filesystem', 'Offset (Sectors)', 'Block Size', 'Volume Size',
            'Total Blocks', 'First Block', 'Last Block', 'Inode Count', 'Root Inode'
        ])

        # Configure header - all columns use Interactive mode for horizontal scrolling
        header = volume_table.horizontalHeader()
        for i in range(10):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Set column widths
        volume_table.setColumnWidth(0, 100)   # Volume
        volume_table.setColumnWidth(1, 120)   # Filesystem
        volume_table.setColumnWidth(2, 140)   # Offset
        volume_table.setColumnWidth(3, 100)   # Block Size
        volume_table.setColumnWidth(4, 120)   # Volume Size
        volume_table.setColumnWidth(5, 120)   # Total Blocks
        volume_table.setColumnWidth(6, 120)   # First Block
        volume_table.setColumnWidth(7, 120)   # Last Block
        volume_table.setColumnWidth(8, 120)   # Inode Count
        volume_table.setColumnWidth(9, 100)   # Root Inode

        # Set header alignment
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Populate table with partition data
        partitions = self.image_handler.get_partitions()

        if partitions:
            self._populate_volume_table(volume_table, partitions)
        else:
            # Show message in table if no partitions
            volume_table.setRowCount(1)
            no_part_item = QTableWidgetItem("No partitions detected or single filesystem image")
            no_part_item.setForeground(QBrush(QColor(108, 117, 125)))
            font = no_part_item.font()
            font.setItalic(True)
            no_part_item.setFont(font)
            volume_table.setItem(0, 0, no_part_item)
            volume_table.setSpan(0, 0, 1, 10)

        bottom_layout.addWidget(volume_table, 1)

        # Close button at bottom right
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        close_button.setMinimumWidth(100)

        button_layout.addWidget(close_button)
        bottom_layout.addLayout(button_layout)

        main_layout.addWidget(bottom_widget, 1)

        dialog.exec_()

    def _populate_volume_table(self, table, partitions):
        """Populate the volume table with partition information."""
        table.setRowCount(len(partitions))
        table.setSortingEnabled(False)  # Disable sorting while populating

        for idx, partition in enumerate(partitions):
            addr, desc, start, length = partition

            # Get volume information
            volume_info = self._extract_comprehensive_volume_info(start)

            # Combine all info
            all_info = {}
            all_info.update(volume_info["basic"])
            all_info.update(volume_info["filesystem"])

            # Get filesystem type for icon
            fs_type = all_info.get("Filesystem Type", "Unknown")
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')

            # Column 0: Volume (with icon)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            volume_text = f"vol{addr}"
            if desc_str and desc_str.strip():
                volume_text += f" ({desc_str})"

            volume_item = QTableWidgetItem(volume_text)
            volume_item.setIcon(QIcon(icon_path))
            table.setItem(idx, 0, volume_item)

            # Column 1: Filesystem
            fs_item = QTableWidgetItem(fs_type)
            table.setItem(idx, 1, fs_item)

            # Column 2: Offset (Sectors)
            offset_value = all_info.get("Partition Offset", "N/A")
            # Extract just the sector count
            if "sectors" in offset_value:
                offset_value = offset_value.split("sectors")[0].strip()
            offset_item = QTableWidgetItem(offset_value)
            table.setItem(idx, 2, offset_item)

            # Column 3: Block Size
            block_size = all_info.get("Block Size", "N/A")
            block_size_item = QTableWidgetItem(block_size)
            table.setItem(idx, 3, block_size_item)

            # Column 4: Volume Size
            volume_size = all_info.get("Volume Size", "N/A")
            volume_size_item = QTableWidgetItem(volume_size)
            table.setItem(idx, 4, volume_size_item)

            # Column 5: Total Blocks
            total_blocks = all_info.get("Total Blocks", "N/A")
            total_blocks_item = QTableWidgetItem(total_blocks)
            table.setItem(idx, 5, total_blocks_item)

            # Column 6: First Block
            first_block = all_info.get("First Block", "N/A")
            first_block_item = QTableWidgetItem(first_block)
            table.setItem(idx, 6, first_block_item)

            # Column 7: Last Block
            last_block = all_info.get("Last Block", "N/A")
            last_block_item = QTableWidgetItem(last_block)
            table.setItem(idx, 7, last_block_item)

            # Column 8: Inode Count
            inode_count = all_info.get("Inode Count", "N/A")
            inode_count_item = QTableWidgetItem(inode_count)
            table.setItem(idx, 8, inode_count_item)

            # Column 9: Root Inode
            root_inode = all_info.get("Root Inode", "N/A")
            root_inode_item = QTableWidgetItem(root_inode)
            table.setItem(idx, 9, root_inode_item)

        table.setSortingEnabled(True)  # Re-enable sorting after populating

    def _extract_comprehensive_volume_info(self, start_offset):
        """Extract basic pytsk3 information from a volume."""
        info = {
            "basic": {},
            "filesystem": {}
        }

        try:
            # Get filesystem info
            fs_info = self.image_handler.get_fs_info(start_offset)
            if not fs_info:
                info["basic"]["Status"] = "Unable to access filesystem"
                return info

            fs_type = self.image_handler.get_fs_type(start_offset)

            # === BASIC INFO ===
            info["basic"]["Partition Offset"] = f"{start_offset:,} sectors ({start_offset * 512:,} bytes)"
            info["basic"]["Filesystem Type"] = fs_type or "Unknown"

            if hasattr(fs_info.info, 'block_size'):
                info["basic"]["Block Size"] = f"{fs_info.info.block_size:,} bytes"
            if hasattr(fs_info.info, 'block_count'):
                total_blocks = fs_info.info.block_count
                total_size = total_blocks * fs_info.info.block_size
                info["basic"]["Total Blocks"] = f"{total_blocks:,}"
                info["basic"]["Volume Size"] = FileSystemUtils.get_readable_size(total_size)

            # === FILESYSTEM DETAILS ===
            if hasattr(fs_info.info, 'first_block'):
                info["filesystem"]["First Block"] = f"{fs_info.info.first_block:,}"
            if hasattr(fs_info.info, 'last_block'):
                info["filesystem"]["Last Block"] = f"{fs_info.info.last_block:,}"
            if hasattr(fs_info.info, 'inum_count'):
                info["filesystem"]["Inode Count"] = f"{fs_info.info.inum_count:,}"
            if hasattr(fs_info.info, 'root_inum'):
                info["filesystem"]["Root Inode"] = f"{fs_info.info.root_inum}"

        except Exception as e:
            logger.error(f"Error extracting volume info: {e}")
            info["basic"]["Error"] = str(e)

        return info

    def _get_image_info(self):
        """Extract comprehensive disk image information."""
        info = {}

        try:
            # Basic image info
            info["Image Path"] = self.image_handler.image_path
            info["Image Type"] = self.image_handler.get_image_type().upper()

            # Image size
            total_size = self.image_handler.get_size()
            info["Total Size"] = FileSystemUtils.get_readable_size(total_size)
            info["Total Size (Bytes)"] = f"{total_size:,}"

            # Sector information
            sector_count = total_size // 512
            info["Total Sectors"] = f"{sector_count:,}"
            info["Bytes per Sector"] = "512"

            # Volume information
            if self.image_handler.volume_info:
                try:
                    vol_type = self.image_handler.volume_info.info.vstype
                    volume_types = {
                        pytsk3.TSK_VS_TYPE_DOS: "DOS/MBR",
                        pytsk3.TSK_VS_TYPE_GPT: "GPT (GUID Partition Table)",
                        pytsk3.TSK_VS_TYPE_MAC: "Mac Partition Map",
                        pytsk3.TSK_VS_TYPE_BSD: "BSD Disk Label",
                        pytsk3.TSK_VS_TYPE_SUN: "Sun VTOC",
                    }
                    info["Partition Scheme"] = volume_types.get(vol_type, f"Unknown ({vol_type})")
                    info["Number of Partitions"] = len(self.image_handler.get_partitions())
                except Exception as e:
                    logger.debug(f"Could not get volume type: {e}")
            else:
                info["Partition Scheme"] = "No partition table detected"

            # Check if wiped
            if self.image_handler.is_wiped():
                info["Status"] = "⚠️ Wiped/Empty Image"
            else:
                info["Status"] = "✓ Valid Image"

            # File modification time
            if os.path.exists(self.image_handler.image_path):
                mod_time = os.path.getmtime(self.image_handler.image_path)
                info["File Modified"] = datetime.datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M:%S")

        except Exception as e:
            logger.error(f"Error getting image info: {e}")
            info["Error"] = str(e)

        return info

    def _get_filesystem_colors(self):
        """Return consistent color mapping for filesystem types."""
        return {
            "NTFS": QColor(41, 128, 185),      # Blue
            "FAT32": QColor(46, 204, 113),     # Green
            "FAT16": QColor(26, 188, 156),     # Turquoise
            "FAT12": QColor(22, 160, 133),     # Dark Turquoise
            "exFAT": QColor(52, 152, 219),     # Light Blue
            "EXT4": QColor(231, 76, 60),       # Red
            "EXT3": QColor(192, 57, 43),       # Dark Red
            "EXT2": QColor(155, 89, 182),      # Purple
            "HFS+": QColor(241, 196, 15),      # Yellow
            "APFS": QColor(243, 156, 18),      # Orange
            "ISO9660": QColor(230, 126, 34),   # Dark Orange
            "Unallocated": QColor(149, 165, 166),  # Gray
            "Unknown": QColor(127, 140, 141),  # Dark Gray
        }

    def _create_space_allocation_chart(self):
        """Create a pie chart showing allocated vs unallocated space."""
        # Create pie series
        series = QPieSeries()
        legend_items = []  # Track items for legend

        try:
            total_size = self.image_handler.get_size()
            partitions = self.image_handler.get_partitions()

            # Get filesystem color mapping
            fs_colors = self._get_filesystem_colors()

            # Calculate allocated space (partitions)
            allocated_space = 0
            partition_details = []

            if partitions:
                for part in partitions:
                    addr, desc, start, length = part
                    size = length * 512
                    allocated_space += size

                    # Get filesystem type
                    fs_type = self.image_handler.get_fs_type(start)
                    if not fs_type:
                        fs_type = "Unknown"

                    partition_details.append((fs_type, size, part[0]))

            # Calculate unallocated space
            unallocated_space = total_size - allocated_space

            # Add partition slices with consistent colors
            for idx, (fs_type, size, part_num) in enumerate(partition_details):
                percentage = (size / total_size) * 100

                # Don't show label on slice - use legend instead
                slice = series.append("", size)

                # Use consistent color based on filesystem type
                color = fs_colors.get(fs_type, fs_colors["Unknown"])
                slice.setColor(color)
                slice.setLabelVisible(False)  # Hide labels on pie

                # Add border between slices for clear separation
                slice.setBorderColor(QColor(255, 255, 255))
                slice.setBorderWidth(3)

                # Add to legend with full details
                legend_label = f"{fs_type} - Partition {part_num} ({FileSystemUtils.get_readable_size(size)}, {percentage:.1f}%)"
                legend_items.append((legend_label, color))

            # Add unallocated space
            if unallocated_space > 0:
                percentage = (unallocated_space / total_size) * 100
                unalloc_slice = series.append("", unallocated_space)
                unalloc_slice.setColor(fs_colors["Unallocated"])
                unalloc_slice.setLabelVisible(False)
                unalloc_slice.setBorderColor(QColor(255, 255, 255))
                unalloc_slice.setBorderWidth(3)

                # Add to legend
                legend_label = f"Unallocated Space ({FileSystemUtils.get_readable_size(unallocated_space)}, {percentage:.1f}%)"
                legend_items.append((legend_label, fs_colors["Unallocated"]))

            # If no partitions, show entire disk as unallocated
            if not partitions:
                slice = series.append("", total_size)
                slice.setColor(fs_colors["Unallocated"])
                slice.setLabelVisible(False)

                # Add to legend
                legend_label = f"Entire Disk ({FileSystemUtils.get_readable_size(total_size)}, 100%)"
                legend_items.append((legend_label, fs_colors["Unallocated"]))

        except Exception as e:
            logger.error(f"Error creating allocation chart: {e}")
            # Add error slice
            series.append("Error Loading Data", 1)

        # Create chart
        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setVisible(False)  # Use custom legend instead

        # Minimal margins for maximum chart size
        chart.setMargins(QMargins(0, 0, 0, 0))
        chart.setBackgroundVisible(False)

        # Create chart view
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        chart_view.setMinimumSize(350, 350)
        chart_view.setStyleSheet("border: none; background: transparent;")

        return chart_view, legend_items

    def create_action(self, icon_path, text, callback):
        action = QAction(QIcon(icon_path), text, self)
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

        # Switch to search mode if not already
        if not self._search_mode:
            self.switch_to_search_mode()

        # Perform the search
        self.perform_search(search_query)

    def _execute_search(self):
        """Execute the search after debounce delay."""
        if self._search_query:
            # Switch to search mode and perform search
            self.switch_to_search_mode()

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
        statusbar = self.statusBar()
        statusbar.showMessage(f"Searching for '{self._search_query}'...")

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
                    self.statusBar().showMessage(f"Error restoring directory view: {str(e)}")

        # Clear status bar
        self.statusBar().clearMessage()

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

        statusbar = self.statusBar()
        statusbar.showMessage(f"Searching for '{search_query}'...")

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
            statusbar.showMessage(f"{len(files)} result(s) for '{search_query}'")

        except Exception as e:
            statusbar.showMessage(f"Search error: {str(e)}")

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
        """Navigate to the file's directory in browse mode and select the file."""
        try:
            # Clear search and switch to browse mode
            self.listing_search_bar.clear()  # This triggers switch_to_browse_mode

            # Get file's location details
            start_offset = file_data.get('start_offset')
            file_path = file_data.get('path', '')
            file_inode = file_data.get('inode_number')

            if start_offset is None or not file_path:
                self.statusBar().showMessage("Cannot determine file location")
                return

            # Parse the path to get parent directory
            # file_path format: "/path/to/file.txt"
            path_parts = file_path.split('/')
            if len(path_parts) < 2:
                # File is in root
                parent_inode = 5
                self.current_path = "/"
            else:
                # Need to navigate to parent directory
                # For simplicity, navigate to root for now
                # TODO: Implement proper path-to-inode resolution for deep directories
                parent_inode = 5
                self.current_path = "/"

            # Load the parent directory contents
            entries = self.image_handler.get_directory_contents(start_offset, parent_inode)
            self.current_offset = start_offset
            self.populate_listing_table(entries, start_offset)

            # Find and select the file in the table
            for row in range(self.listing_table.rowCount()):
                item = self.listing_table.item(row, 0)
                if item:
                    item_data = item.data(Qt.UserRole)
                    if item_data and item_data.get('inode_number') == file_inode:
                        # Select this row
                        self.listing_table.selectRow(row)
                        # Scroll to make it visible
                        self.listing_table.scrollToItem(item)
                        break

            # Update status bar
            self.statusBar().showMessage(f"Showing {file_data.get('name', 'file')} in directory")

            # TODO: Expand tree view to show this location
            # This would require traversing the tree to find and expand the correct nodes

        except Exception as e:
            logger.error(f"Error showing file in directory: {str(e)}")
            self.statusBar().showMessage(f"Error navigating to file location: {str(e)}")

    # ==================== END SEARCH AND FILTER HANDLERS ====================

    def on_listing_table_item_clicked(self, item):
        """Handle click events on the listing table."""
        row = item.row()

        # Get data from the name column (column 0)
        data = self.listing_table.item(row, 0).data(Qt.UserRole)
        if not data:
            return

        self.current_selected_data = data

        statusbar = self.statusBar()
        statusbar.showMessage("Loading content...")

        try:
            if data.get("type") == "volume":
                # Handle volume/partition - navigate into its root directory
                start_offset = data.get("start_offset", 0)

                # Reset path to root of this volume
                self.current_path = "/"

                # Get root directory contents of the volume (inode 5 is typically root for NTFS)
                entries = self.image_handler.get_directory_contents(start_offset, 5)

                # Update directory up button - should be disabled since we're at volume root
                self.update_directory_up_button()

                # Populate listing table with volume contents
                self.populate_listing_table(entries, start_offset)

                # Add to navigation history
                self._add_to_history(data)

                statusbar.clearMessage()

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
                elif data.get("inode_number") == 5:  # Root directory
                    self.current_path = "/"
                else:
                    # Navigate into directory
                    self.current_path = os.path.join(self.current_path, data.get("name", ""))

                # Directories are processed synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)

                # Update directory up button state
                self.update_directory_up_button()

                self.populate_listing_table(entries, data["start_offset"])

                # Add to navigation history
                self._add_to_history(data)

                statusbar.clearMessage()
            else:
                # Reveal the file's location in the tree view. In search mode the
                # result may live in a directory the tree has not expanded yet, so
                # navigate by path; otherwise select by inode.
                if getattr(self, '_search_mode', False) and data.get('path'):
                    self.navigate_tree_to_path(data['path'], data)
                else:
                    self.select_tree_item_by_inode(data.get("inode_number"), data["start_offset"])

                # Files are processed in a background thread
                inode_number = data.get("inode_number", 0)
                self.file_worker = self.FileContentWorker(self.image_handler, inode_number, data["start_offset"])
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.file_worker.start()

        except Exception as e:
            self.log_error(f"Error processing listing table click: {str(e)}")
            statusbar.clearMessage()



# Add a worker thread for exporting files and directories
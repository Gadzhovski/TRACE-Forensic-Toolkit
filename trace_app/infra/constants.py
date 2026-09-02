"""Shared UI and I/O constants."""

SECTOR_SIZE = 512
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks for processing
FILE_BUFFER_SIZE = 4096  # 4KB for file operations

# ==================== CONFIGURATION CONSTANTS ====================
# Window dimensions
DEFAULT_WINDOW_WIDTH = 1200
DEFAULT_WINDOW_HEIGHT = 800
DEFAULT_WINDOW_X = 100
DEFAULT_WINDOW_Y = 100

# Dock sizes
# Floor for the bottom Utils dock. Kept modest so the file listing, which
# is what an examiner reads, keeps the bulk of the window.
VIEWER_DOCK_MIN_HEIGHT = 160
VIEWER_DOCK_MAX_WIDTH = 1200
VIEWER_DOCK_MAX_SIZE = 16777215  # Qt maximum size value

# Column widths for listing table
COLUMN_WIDTHS = {
    'name': 400,        # Widest - file names can be long
    'inode': 50,        # Compact - numbers don't vary much
    'type': 50,         # Compact - short text like "File", "Dir"
    'size': 100,         # Compact - formatted sizes
    'created': 160,      # Narrower - timestamps are consistent length
    'accessed': 160,     # Narrower - timestamps are consistent length
    'modified': 160,     # Narrower - timestamps are consistent length
    'changed': 160,      # Narrower - timestamps are consistent length
    'path': 1100         # Wide - paths can be long
}

# Progress dialog settings
PROGRESS_DIALOG_WIDTH = 300

# Timeouts (in seconds)
INFO_TIMEOUT = 10
PROCESS_TIMEOUT = 30
THREAD_SLEEP_MS = 1000  # milliseconds

# Minimum duration for progress dialog (milliseconds)
PROGRESS_MIN_DURATION = 1500

# ==================== UI METRICS ====================
# One scale for the whole interface. Control heights had drifted to seven
# different values (22, 25, 27, 30, 32, 35, 40) set widget by widget, which is
# what made toolbars look ragged: a 25px combo box beside a 22px button beside
# a 35px search field.
#
# Everything below is a multiple of 4, so controls line up on a common grid.

#: Height of a control that sits in a toolbar (buttons, combos, line edits).
CONTROL_HEIGHT = 24

#: Height of a toolbar itself: a control plus breathing room above and below.
TOOLBAR_HEIGHT = 36

#: Standard gap between related controls in a row.
CONTROL_SPACING = 6

#: Wider gap used to separate groups of controls in the same toolbar.
GROUP_SPACING = 16

#: Row height in the listing, tree and property tables.
TABLE_ROW_HEIGHT = 26

# --- Icon sizes -----------------------------------------------------------
TREE_ICON_SIZE = 16
TABLE_ICON_SIZE = 20
TOOLBAR_ICON_SIZE = 18
#: Icon beside a panel heading (File System Browser, File Carving, Registry).
#: A Tabler glyph carries internal padding, so this renders at roughly the
#: same visual weight as the heading text next to it.
PANEL_ICON_SIZE = 22

# --- Button widths --------------------------------------------------------
#: Dialog buttons (Close, Save, Copy) so they line up in a row.
BUTTON_WIDTH = 96
#: Wider action buttons that carry a longer label.
BUTTON_WIDTH_WIDE = 130

# Table settings
TABLE_COLUMN_COUNT = 9
TABLE_BATCH_SIZE = 200  # Number of rows to process before updating UI

# Input field settings
INPUT_FIELD_MIN_WIDTH = 400
API_DIALOG_WIDTH = 600

# Qt maximum size constant
QT_MAX_SIZE = 16777215
# ================================================================

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

#: Vertical breathing room above and below a toolbar's controls, set as
#: QToolBar padding in the stylesheets. Qt adds its own item margin on top of
#: this, so the effective offset is larger -- see TOOLBAR_HEIGHT.
TOOLBAR_PADDING_Y = 5

#: Left and right inset for a toolbar's contents.
TOOLBAR_PADDING_X = 8

#: Qt's own inset above a toolbar item, on top of the QSS padding. Measured
#: rather than derived: QToolBar positions items with PM_ToolBarItemMargin and
#: PM_ToolBarFrameWidth, which the stylesheet does not override.
TOOLBAR_ITEM_INSET = 8

#: Height of a toolbar. The tallest control is a square icon button
#: (CONTROL_HEIGHT + 4); it sits TOOLBAR_ITEM_INSET from the top, so the bar
#: needs the same gap beneath it to look centred rather than top-heavy.
TOOLBAR_HEIGHT = TOOLBAR_ITEM_INSET + (CONTROL_HEIGHT + 4) + TOOLBAR_ITEM_INSET

#: Standard gap between related controls in a row.
CONTROL_SPACING = 6

#: Wider gap used to separate groups of controls in the same toolbar.
GROUP_SPACING = 16

#: Space a QSplitter reserves for its drag handle. Qt defaults to 7, wide
#: enough to read as a grey band between panes; the stylesheet paints a 1px
#: rule in it, and Qt still widens the hit region so it stays draggable.
SPLITTER_HANDLE_WIDTH = 1

#: Row height in the listing, tree and property tables.
TABLE_ROW_HEIGHT = 26

# --- Icon sizes -----------------------------------------------------------
#
# The icon set is drawn on a 24x24 grid. Rendering at 24, or at a whole
# division of it, resamples cleanly; anything else lands the strokes on
# fractional pixels and the diagonals stair-step -- which is what "pixelated"
# looks like on a line icon. 16px is the worst common case: a 1.5x reduction
# that halves some strokes and not others.
#
# So prefer 24 where there is room, and 12 where there is not. If a size in
# between is unavoidable, expect the glyph to soften.

#: Icon beside a row in the evidence and registry trees. At 16 the fine detail
#: in glyphs like the key and the folder broke up visibly; 24 is exact but
#: leaves a 24px glyph in a 26px row with nothing around it. 20 keeps the
#: detail legible and the row breathing.
TREE_ICON_SIZE = 20

#: Horizontal step per tree level, and so the width of the strip the expand
#: arrow is drawn into. This was 14 for a while, to close the gap between the
#: arrow and the icon beside it; the gap did close, but a 24px chevron fitted
#: into a 14px strip lands on fractional pixels and its diagonals break up.
#: Qt's default is worth the few pixels -- a legible arrow beats a tight one.
TREE_INDENTATION = 20

TABLE_ICON_SIZE = 20
TOOLBAR_ICON_SIZE = 18
#: Icon beside a panel heading (File System Browser, File Carving, Registry).
#: A Tabler glyph carries internal padding, so this renders at roughly the
#: same visual weight as the heading text next to it.
PANEL_ICON_SIZE = 22

#: Size of the glyph beside a message-dialog's text. Larger than a toolbar
#: icon: it is the dialog's only piece of art and carries the message's tone.
DIALOG_ICON_SIZE = 40

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

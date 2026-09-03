"""Shared UI and I/O constants."""

#: Fallback bytes-per-sector, used only when an image exposes no volume
#: system to ask. Everything else reads ImageHandler.sector_size, because the
#: real value is a property of the evidence: a 4Kn drive reports 4096, and
#: assuming 512 there places every partition eight times too early.
SECTOR_SIZE = 512

#: How deep the allocation-map walk will follow directories. Cycles are
#: already stopped by the walk's visited-inode set, so this is only a
#: backstop; it is set high because silently truncating a legitimately deep
#: tree is the worse failure -- an incomplete map means live files get carved
#: as though they were deleted. Hitting it is logged.
MAX_DIRECTORY_DEPTH = 256

#: Bytes per read for hashing, file reads and carving. EWF throughput is flat
#: from 64 KB to 16 MB (measured 68-69 MB/s), so this is a memory decision
#: rather than a speed one.
CHUNK_SIZE = 4 * 1024 * 1024

#: Extra bytes read past the end of each carving chunk, so a file straddling a
#: chunk boundary is still whole in the following read. Carvers reconstruct a
#: file from its header, and one that runs off the end of the buffer is
#: abandoned, so this has to exceed the largest file a carver will rebuild.
CARVE_OVERLAP = 32 * 1024 * 1024

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
    'path': 1100,        # Wide - paths can be long
    'sequence': 50,      # Compact - MFT sequence is a small number
    'attributes': 320    # Wide - a list of NTFS attribute names
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

# Shown where a carved file carries no date of its own. Carving recovers bytes
# from unallocated space, not directory entries, so most formats yield nothing
# -- and saying so is more useful than substituting the time of recovery.
UNKNOWN_DATE = "Unknown"

# Qt maximum size constant
QT_MAX_SIZE = 16777215
# ================================================================

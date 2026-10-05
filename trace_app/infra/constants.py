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

#: Largest file each carver will reconstruct, by type. A signature is only a
#: few bytes, so random data produces header hits constantly; without a ceiling
#: a stray match runs to whatever byte pattern happens to end it, and writes
#: megabytes of noise as though it were evidence.
#:
#: A cap must REJECT a candidate, never truncate one -- a file cut to the cap
#: looks like a recovered file and is not. Values sit above what these formats
#: plausibly reach on the media being examined, and every one is below
#: CARVE_OVERLAP so a capped file still fits in a single read.
CARVE_MAX_SIZE = {
    'jpg': 32 * 1024 * 1024,
    'png': 32 * 1024 * 1024,
    'gif': 16 * 1024 * 1024,
    'bmp': 32 * 1024 * 1024,
    # TIFF is now sized by its structure and read from the image in full,
    # like the camera raws built on it.
    'tiff': 256 * 1024 * 1024,
    **{ext: 256 * 1024 * 1024 for ext in ('cr2', 'nef', 'arw', 'dng', 'pef',
                                          'orf', 'rw2', 'raf')},
    # CR3 is ISO-BMFF, walked within the read-ahead like MP4.
    'cr3': 32 * 1024 * 1024,
    'pdf': 32 * 1024 * 1024,
    'zip': 32 * 1024 * 1024,
    'gz': 32 * 1024 * 1024,
    # Sized from their own headers, so read whole like the formats below.
    'rar': 256 * 1024 * 1024,
    '7z': 256 * 1024 * 1024,
    'ole': 32 * 1024 * 1024,
    'html': 4 * 1024 * 1024,
    'wav': 32 * 1024 * 1024,
    'mov': 32 * 1024 * 1024,
    'mp4': 32 * 1024 * 1024,
    'wmv': 32 * 1024 * 1024,
    # Office and other formats named from a carved ZIP share its cap.
    **{ext: 32 * 1024 * 1024 for ext in ('docx', 'xlsx', 'pptx', 'vsdx',
                                         'odt', 'ods', 'odp', 'odg', 'epub',
                                         'apk', 'jar')},
    **{ext: 32 * 1024 * 1024 for ext in ('m4v', '3gp', 'heic', 'avif',
                                         'm4a')},
    # Formats sized by their own header or structure are read from the image
    # in full rather than out of the read-ahead, so they are not bound by
    # CARVE_OVERLAP. Their caps only bound memory: a carved file is held
    # whole while it is validated and hashed.
    'webp': 64 * 1024 * 1024,
    'avi': 256 * 1024 * 1024,
    'sqlite': 256 * 1024 * 1024,
    'wal': 256 * 1024 * 1024,
    'regf': 256 * 1024 * 1024,
    'evtx': 256 * 1024 * 1024,
    'pst': 256 * 1024 * 1024,
    'ost': 256 * 1024 * 1024,
    'exe': 256 * 1024 * 1024,
    'dll': 256 * 1024 * 1024,
    'sys': 64 * 1024 * 1024,
    'lnk': 1024 * 1024,
    'mp3': 64 * 1024 * 1024,
    'ogg': 64 * 1024 * 1024,
    'opus': 64 * 1024 * 1024,
    'flv': 256 * 1024 * 1024,
    'mpg': 256 * 1024 * 1024,
    'mkv': 256 * 1024 * 1024,
    'webm': 256 * 1024 * 1024,
    'tar': 256 * 1024 * 1024,
    'bz2': 256 * 1024 * 1024,
    'xz': 256 * 1024 * 1024,
    'rtf': 32 * 1024 * 1024,
    'elf': 256 * 1024 * 1024,
    'macho': 256 * 1024 * 1024,
    'psd': 256 * 1024 * 1024,
    'psb': 1024 * 1024 * 1024,         # Photoshop's large document
    # The one heuristic extent: kept small, since it is where text stops.
    'mbox': 64 * 1024 * 1024,
    'eml': 64 * 1024 * 1024,
}

#: Smallest carve worth writing. Below this a "file" is a header and little
#: else -- it cannot be opened, and it buries real recoveries in the listing.
CARVE_MIN_SIZE = 64

#: How many candidate footers to try before giving up on a header. A JPEG's
#: EXIF thumbnail ends with the same FFD9 the image does, so the first footer
#: is routinely the wrong one; taking it truncates a perfectly recoverable
#: file. Bounded because each retry costs a full decode attempt.
CARVE_MAX_FOOTER_CANDIDATES = 24

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
#: 20, not 18: icons are drawn on Tabler's 24-unit grid, and 20 px at a
#: 125% display is 25 device pixels, drawn at exactly 24 -- every stroke on
#: whole pixels (icons._TintedSvgEngine). 18 px was 22.5, and blurred.
TOOLBAR_ICON_SIZE = 20
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

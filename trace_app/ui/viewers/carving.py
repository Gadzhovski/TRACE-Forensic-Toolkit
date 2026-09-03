import logging
import datetime
import io
import os
import re
import struct
import zlib
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import TAGS
from PySide6.QtCore import QSize, QUrl, QRectF
from PySide6.QtCore import Qt
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QAction, QDesktopServices, QPixmap, QPainter, QImage
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QToolBar, QSizePolicy, QHBoxLayout, \
    QCheckBox, QHeaderView
from PySide6.QtWidgets import QMenu
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
                               QPushButton, QLabel, QTabWidget, QMessageBox)
from fitz import open as fitz_open, Matrix

from trace_app.core.carving_signatures import (extract_original_timestamp,
                                              is_valid_file)
from trace_app.core.image_handler import ImageHandler
from trace_app.infra.paths import carved_files_dir, resource_path
from trace_app.infra.constants import (CARVE_MAX_FOOTER_CANDIDATES,
                                       CARVE_MAX_SIZE, CARVE_MIN_SIZE,
                                       CARVE_OVERLAP, CHUNK_SIZE,
                                       PANEL_ICON_SIZE, TABLE_ICON_SIZE,
                                       UNKNOWN_DATE)
from trace_app.ui import icons
from trace_app.ui.widgets.multi_select import MultiSelectButton
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.dialogs import message

logger = logging.getLogger('TRACE.Carving')


#: File signatures the carver can search for. Order is the menu order.
#: "OLE" covers the legacy Office trio (.doc/.xls/.ppt), which share one
#: compound-document container and cannot be told apart from the header alone.
CARVABLE_TYPES = ["PDF", "JPG", "PNG", "GIF", "BMP", "TIFF", "WAV", "MOV",
                  "MP4", "WMV", "ZIP", "GZ", "RAR", "7Z", "OLE", "HTML"]

# Signatures are named rather than inlined so a format's header and footer are
# stated once, next to each other, and read as a pair.
#: An ISO-BMFF atom type is four printable ASCII characters. Requiring that is
#: what stops the walk reading arbitrary bytes as a chain of tiny atoms.
_ATOM_NAME_RE = re.compile(rb'[A-Za-z0-9 _\-]{4}')

#: Carved types that get a generic icon rather than a rendered preview,
#: grouped by the icon each one takes.
VIDEO_TYPES = frozenset({'mov', 'mp4', 'wmv'})
ARCHIVE_TYPES = frozenset({'zip', 'gz', 'rar', '7z'})
AUDIO_TYPES = frozenset({'wav'})
DOCUMENT_TYPES = frozenset({'ole', 'html'})
#: Everything above: these already arrive square, so cropping only trims them.
ICON_TYPES = VIDEO_TYPES | ARCHIVE_TYPES | AUDIO_TYPES | DOCUMENT_TYPES

#: Bytes per value for each TIFF field type, used to work out how far an IFD's
#: out-of-line values push the end of the file.
_TIFF_TYPE_WIDTH = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1,
                    8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

#: Ceiling on what one gzip member may expand to while we look for its end.
#: A carved stream is unverified input; decompressing it without a limit is how
#: a zip bomb turns a scan into an out-of-memory crash.
_GZIP_DECOMPRESS_LIMIT = 64 * 1024 * 1024

JPG_HEADER = b'\xFF\xD8\xFF'
JPG_FOOTER = b'\xFF\xD9'
PNG_HEADER = b'\x89PNG\r\n\x1a\n'
#: IEND carries no data, so its CRC is a constant and forms part of the footer.
PNG_FOOTER = b'IEND\xAE\x42\x60\x82'
GIF_HEADER = b'GIF8'
#: Block terminator followed by the GIF trailer.
GIF_FOOTER = b'\x00\x3B'
BMP_HEADER = b'BM'
WAV_HEADER = b'RIFF'
PDF_HEADER = b'%PDF-'
PDF_FOOTER = b'%%EOF'
ZIP_LOCAL_HEADER = b'PK\x03\x04'
ZIP_EOCD = b'PK\x05\x06'
OLE_HEADER = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
GZIP_HEADER = b'\x1F\x8B\x08'
RAR_HEADER = b'Rar!\x1A\x07'
SEVENZIP_HEADER = b'7z\xBC\xAF\x27\x1C'
TIFF_HEADERS = (b'II\x2A\x00', b'MM\x00\x2A')
#: ASF Header Object GUID: the first 16 bytes of every WMV file.
ASF_HEADER_GUID = bytes.fromhex('3026B2758E66CF11A6D900AA0062CE6C')
#: ASF File Properties Object, which carries the declared file size.
ASF_PROPERTIES_GUID = bytes.fromhex('A1DCAB8C47A9CF118EE400C00C205365')




class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        self_value = self.text().split()[0]  # Extract numeric part of the text
        other_value = other.text().split()[0]  # Extract numeric part of the text
        self_unit = self.text().split()[1]  # Extract unit part of the text
        other_unit = other.text().split()[1]  # Extract unit part of the text
        units = {'B': 0, 'KB': 1, 'MB': 2, 'GB': 3, 'TB': 4}

        # Convert to bytes for comparison
        self_bytes = float(self_value) * (1024 ** units[self_unit])
        other_bytes = float(other_value) * (1024 ** units[other_unit])

        return self_bytes < other_bytes


class FileCarvingWidget(QWidget):
    file_carved = Signal(str, str, str, str, str, str)  # Unified signal for file carving
    #: Emitted when a scan ends. Carrying this as a signal rather than calling
    #: straight from the worker matters: file_carved is a queued cross-thread
    #: signal, so its rows are still waiting in the event queue when the worker
    #: finishes. Anything the worker does directly -- such as sizing columns --
    #: therefore runs against a table that is not filled in yet.
    carving_finished = Signal()
    #: Emitted when the user opens a carved file, so the host can show it in a
    #: viewer. Replaces reaching up into MainWindow directly.
    carved_file_opened = Signal(bytes, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.image_handler = None
        #: Resolves (type, extension) -> icon path. Injected by the host so
        #: this widget does not have to reach through a MainWindow reference
        #: into its DatabaseManager.
        self.icon_resolver = None
        self.executor = ThreadPoolExecutor(max_workers=4)  # ThreadPoolExecutor for background tasks
        self._stop_requested = False  # cooperative cancellation flag for carve_files()
        self.carved_files = []
        self.carved_file_names = set()  # Track carved file names to avoid duplicates
        self.allocation_map = []  # Map of allocated disk regions to skip during carving
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)  # Set the spacing to zero

        self.toolbar = QToolBar()

        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(self.icon_label, icons.CARVING, PANEL_ICON_SIZE)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("File Carving")
        self.title_label.setObjectName("panelTitle")
        self.toolbar.addWidget(self.title_label)

        self.spacer = QLabel()
        self.spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(self.spacer)

        self.table_widget = self.create_table_widget()
        # Column widths come from the content once a scan finishes; the
        # resize handler that used to split the width between Name and File
        # Path fought that on every resize.

        self.list_widget = self.create_list_widget()

        # One dropdown instead of ten check boxes. The old row also carried an
        # "All" check box that was treated as a file type in its own right, so
        # ticking it searched for a signature named "all"; select-all is now a
        # menu command rather than an option.
        self.file_type_button = MultiSelectButton(CARVABLE_TYPES, self, noun="types")
        self.file_type_button.set_selected(CARVABLE_TYPES)
        self.toolbar.addWidget(QLabel("Carve:"))
        self.toolbar.addWidget(self.file_type_button)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_carving)

        self.toolbar.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_carving)
        self.stop_button.setEnabled(False)

        self.toolbar.addWidget(self.stop_button)
        self.layout.addWidget(self.tab_widget)

        self.file_carved.connect(self.display_carved_file)
        self.carving_finished.connect(self._fit_carved_columns)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)

    def create_table_widget(self):
        table_widget = QTableWidget()
        # Id, Name, Size, Type, Embedded Date, Date Source, File Path
        table_widget.setColumnCount(7)
        table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        table_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        table_widget.setSortingEnabled(True)
        table_widget.verticalHeader().setVisible(False)
        table_widget.setObjectName("fileCarvingTable")  # For CSS styling

        # Set size policy to expand with window
        table_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Use alternate row colors (matching Listing tab)
        table_widget.setAlternatingRowColors(True)
        table_widget.setIconSize(QSize(TABLE_ICON_SIZE, TABLE_ICON_SIZE))

        # Enable horizontal scrolling for smaller windows (matching Listing tab)
        table_widget.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        table_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Configure header - all columns use Interactive mode for horizontal scrolling
        header = table_widget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Id - fixed, manually resizable
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Name - fixed, manually resizable
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Size - fixed, manually resizable
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Type - fixed, manually resizable
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Embedded Date
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # Date Source
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # File Path - fixed, manually resizable

        # Set column widths (matching Listing tab style)
        table_widget.setColumnWidth(0, 100)   # Id - compact
        table_widget.setColumnWidth(1, 400)  # Name - widest (matching Listing tab)
        table_widget.setColumnWidth(2, 100)   # Size - compact (matching Listing tab)
        table_widget.setColumnWidth(3, 100)   # Type - compact (matching Listing tab)
        table_widget.setColumnWidth(4, 160)   # Embedded Date - matching Listing
        table_widget.setColumnWidth(5, 170)   # Date Source
        table_widget.setColumnWidth(5, 1100)  # File Path - wide (matching Listing tab)

        # Set header alignment (matching Listing tab)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Set the header labels
        table_widget.setHorizontalHeaderLabels(
            ['Id', 'Name', 'Size', 'Type', 'Embedded Date', 'Date Source',
             'File Path'])

        # Context menu and click handlers
        table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        table_widget.customContextMenuRequested.connect(self.open_context_menu)
        table_widget.cellClicked.connect(self.on_carved_file_clicked)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(table_widget, "File List")
        return table_widget

    def create_list_widget(self):
        list_widget = QListWidget()
        list_widget.setViewMode(QListWidget.IconMode)
        list_widget.setIconSize(QSize(120, 120))
        list_widget.setResizeMode(QListWidget.Adjust)
        list_widget.setUniformItemSizes(True)
        list_widget.setSpacing(5)
        list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        list_widget.customContextMenuRequested.connect(self.open_context_menu)
        # Connect click event to open file in internal viewer
        list_widget.itemClicked.connect(self.on_carved_file_clicked)

        toolbar = QToolBar()

        # Define actions
        action_small_size = (QAction("Small Size", self))
        icons.apply_to(action_small_size, icons.ICONS_SMALL)

        action_medium_size = (QAction("Medium Size", self))
        icons.apply_to(action_medium_size, icons.ICONS_MEDIUM)

        action_large_size = (QAction("Large Size", self))
        icons.apply_to(action_large_size, icons.ICONS_LARGE)

        # Set icons

        # Connect actions to new slot methods
        action_small_size.triggered.connect(self.set_small_size)
        action_medium_size.triggered.connect(self.set_medium_size)
        action_large_size.triggered.connect(self.set_large_size)

        # Add actions to the toolbar
        toolbar.addAction(action_small_size)
        toolbar.addAction(action_medium_size)
        toolbar.addAction(action_large_size)

        # Create a layout and add the toolbar and the list widget to it
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(toolbar)
        layout.addWidget(list_widget)

        # Create a new widget, set its layout and add it to the tab widget
        widget = QWidget()
        widget.setLayout(layout)
        self.tab_widget.addTab(widget, "Thumbnails")
        return list_widget

    @staticmethod
    def center_crop_to_square(pixmap, target_size):
        """Crop pixmap to center square and scale to target size for uniform thumbnails."""
        if pixmap.isNull():
            return pixmap

        width = pixmap.width()
        height = pixmap.height()

        if width == height:
            # Already square, just scale
            return pixmap.scaled(target_size, target_size, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

        # Determine the crop size (smaller dimension)
        crop_size = min(width, height)

        # Calculate crop position to center the crop
        x = (width - crop_size) // 2
        y = (height - crop_size) // 2

        # Crop to square
        cropped = pixmap.copy(x, y, crop_size, crop_size)

        # Scale to target size
        return cropped.scaled(target_size, target_size, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

    @staticmethod
    def render_svg_to_pixmap(svg_path, target_size):
        """Render SVG file at target resolution for crisp icons."""
        renderer = QSvgRenderer(svg_path)
        if not renderer.isValid():
            return QPixmap()

        # Create QImage at target size with transparency
        image = QImage(target_size, target_size, QImage.Format_ARGB32)
        image.fill(Qt.transparent)

        # Render SVG onto the image
        painter = QPainter(image)
        renderer.render(painter, QRectF(0, 0, target_size, target_size))
        painter.end()

        # Convert QImage to QPixmap
        return QPixmap.fromImage(image)

    def set_icon_size(self, size):
        self.list_widget.setIconSize(QSize(size, size))
        for index in range(self.list_widget.count()):
            item = self.list_widget.item(index)
            item.setSizeHint(QSize(size + 10, size + 25))  # Compact padding with space for text

    def set_small_size(self):
        self.set_icon_size(80)

    def set_medium_size(self):
        self.set_icon_size(120)

    def set_large_size(self):
        self.set_icon_size(180)

    def start_carving(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_ui()
        self.carved_files.clear()
        self.carved_file_names.clear()

        # Carved output goes to the per-user data dir, not the working
        # directory -- the CWD is not reliably writable (a macOS .app bundle
        # runs with CWD '/') and output does not belong in the source tree.
        carved_dir = carved_files_dir()
        thumbnail_folder = os.path.join(carved_dir, "thumbnails")

        # Build allocation map for all partitions to skip allocated files
        logger.debug("Building allocation map for allocated files...")
        self.allocation_map = []

        try:
            partitions = self.image_handler.get_partitions()

            if partitions:
                # Process each partition
                for partition_info in partitions:
                    # partition_info is (addr, desc, start, len)
                    start_offset = partition_info[2]  # start offset in sectors

                    # Build allocation map for this partition
                    partition_map = self.image_handler.build_allocation_map(start_offset)
                    self.allocation_map.extend(partition_map)
                    logger.debug(f"  Partition at offset {start_offset}: {len(partition_map)} allocated regions")
            else:
                # No partitions, try offset 0 (single filesystem)
                if self.image_handler.has_filesystem(0):
                    partition_map = self.image_handler.build_allocation_map(0)
                    self.allocation_map.extend(partition_map)
                    logger.debug(f"  Single filesystem: {len(partition_map)} allocated regions")

            # Merge, not just sort. is_offset_allocated binary searches this
            # list, which is only valid if the ranges are ordered AND do not
            # overlap; combining several partitions' maps can produce overlaps
            # that a plain sort leaves in place.
            self.allocation_map = ImageHandler._merge_ranges(self.allocation_map)
            covered = sum(end - begin for begin, end in self.allocation_map)
            logger.info("Skipping %d allocated regions (%.1f MB) while carving",
                        len(self.allocation_map), covered / (1024 * 1024))

        except Exception as e:
            logger.error(f"Warning: Could not build allocation map: {e}")
            logger.debug("Will carve from entire disk (may include duplicates)")
            self.allocation_map = []

        selected_file_types = [name.lower() for name in self.file_type_button.selected()]
        if not selected_file_types:
            message.information(self, "Nothing to carve",
                                    "Select at least one file type to search for.")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
        self.executor.submit(self.carve_files, selected_file_types)

    def stop_carving(self):
        """Ask the running carve to stop.

        Cooperative: carve_files() checks _stop_requested once per chunk. The
        executor is deliberately not shut down here -- shutdown() does not
        cancel a running task, it blocks until that task finishes (freezing the
        UI), and it is terminal, so the widget could never carve again.
        """
        self._stop_requested = True
        self.stop_button.setEnabled(False)

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self.start_button.setEnabled(True)

    @staticmethod
    def is_offset_allocated(offset, chunk_size, allocation_map):
        """
        Check if a given offset range overlaps with any allocated regions."""
        if not allocation_map:
            return False

        chunk_end = offset + chunk_size

        # Binary search to find potential overlapping regions
        # We need to check if our chunk [offset, chunk_end) overlaps with any allocated region
        left, right = 0, len(allocation_map)

        while left < right:
            mid = (left + right) // 2
            alloc_start, alloc_end = allocation_map[mid]

            # Check for overlap: two ranges overlap if one starts before the other ends
            if offset < alloc_end and chunk_end > alloc_start:
                return True

            # If our chunk is entirely before this allocated region, search left half
            if chunk_end <= alloc_start:
                right = mid
            # If our chunk is entirely after this allocated region, search right half
            else:
                left = mid + 1

        return False

    @staticmethod
    def next_allocated_start(offset, allocation_map):
        """Where the next allocated region begins at or after `offset`.

        Carving reads past the end of its chunk so a file straddling the
        boundary stays whole, but that extra window is not covered by the
        chunk's own allocation check -- so without this it read straight into
        live file data and carved it. Trimming the buffer here keeps the
        overlap while leaving allocated space untouched.

        Returns None when nothing is allocated ahead.
        """
        if not allocation_map:
            return None

        low, high = 0, len(allocation_map)
        while low < high:
            mid = (low + high) // 2
            if allocation_map[mid][1] <= offset:
                low = mid + 1        # region ends before us; look right
            else:
                high = mid

        if low >= len(allocation_map):
            return None
        start, end = allocation_map[low]
        # A region already covering `offset` leaves no room to read at all.
        return offset if start <= offset < end else start

    def open_context_menu(self, position):
        menu = QMenu()

        open_location_action = QAction("Open File Location")
        open_location_action.triggered.connect(self.open_file_location)

        open_image_action = QAction("Open Externally")
        open_image_action.triggered.connect(self.open_image)

        menu.addAction(open_location_action)
        menu.addAction(open_image_action)
        menu.exec_(self.table_widget.viewport().mapToGlobal(position))

    def open_image(self):
        if self.tab_widget.currentIndex() == 0:  # If the table tab is active
            current_item = self.table_widget.currentItem()
        else:  # If the thumbnail tab is active
            current_item = self.list_widget.currentItem()

        if current_item:
            file_name = current_item.text()
            for file_info in self.carved_files:
                if file_info[0] == file_name:
                    file_path = file_info[3]  # The file path is now at index 3
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                    break

    def open_file_location(self):
        current_item = self.list_widget.currentItem()
        if current_item:
            file_name = current_item.text()
            for file_info in self.carved_files:
                if file_info[0] == file_name:
                    file_path = file_info[3]  # The file path is now at index 3
                    QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(file_path)))
                    break

    def get_carved_timestamp(self, file_name):
        """The date this carved file carries in its own bytes, if any."""
        for file_info in self.carved_files:
            if file_info[0] == file_name:
                return file_info[4]
        return None

    def get_carved_timestamp_source(self, file_name):
        """Which field the carved file's date was read from."""
        for file_info in self.carved_files:
            if file_info[0] == file_name:
                return file_info[5]
        return ''

    def on_carved_file_clicked(self, *args):
        """Handle click on carved file to display in internal viewer.

        Reads file content directly from disk image (forensically sound) instead of
        from the carved file on disk. This ensures we're analyzing the original data.
        """
        # Get clicked file name (works for both table cellClicked and list itemClicked)
        if len(args) == 2:  # cellClicked(row, column) from table
            row = args[0]
            # Get file name from column 1 (Name column, column 0 is Id)
            file_name_item = self.table_widget.item(row, 1)
            if not file_name_item:
                return
            file_name = file_name_item.text()
        elif len(args) == 1:  # itemClicked(item) from list
            item = args[0]
            file_name = item.text()
        else:
            return

        # Find file info in carved_files list
        for file_info in self.carved_files:
            if file_info[0] == file_name:
                file_size_str = file_info[1]  # Size at index 1
                file_type = file_info[2]  # Type at index 2
                file_size = int(file_size_str)

                try:
                    # Extract disk offset from filename (hex format without extension)
                    offset_hex = os.path.splitext(file_name)[0]
                    offset = int(offset_hex, 16)

                    # Read file content directly from disk image (forensically sound!)
                    if not self.image_handler:
                        logger.debug("No image handler available")
                        return

                    file_content = self.image_handler.read(offset, file_size)
                    if not file_content:
                        logger.error(f"Unable to read content from offset {hex(offset)}")
                        return

                    # Create data dict for viewer (matches mainwindow's format)
                    data = {
                        'name': file_name,
                        'size': file_size,
                        'type': file_type,
                        'offset': offset,
                        'is_carved': True,  # Flag indicating this is a carved file
                        'source': 'carved_file',
                        'file_content': file_content,  # Include content so metadata viewer doesn't re-read
                        'carved_timestamp': self.get_carved_timestamp(file_name),
                        'carved_timestamp_source': self.get_carved_timestamp_source(file_name)
                    }

                    self.carved_file_opened.emit(file_content, data)

                except Exception as e:
                    logger.error(f"Error opening carved file in viewer: {e}")
                    import traceback
                    traceback.print_exc()

                break


    def carve_pdf_files(self, chunk, global_offset):
        pdf_start_signature = PDF_HEADER
        pdf_linearization_signature = b'/Linearized'
        pdf_end_signature = PDF_FOOTER
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(pdf_start_signature, offset)
            if start_index == -1:
                break
            linearization_index = chunk.find(pdf_linearization_signature, start_index, start_index + 1024)
            if linearization_index != -1:
                file_size_start = chunk.find(b'/L ', linearization_index, linearization_index + 1024) + 3
                file_size_end = chunk.find(b'/', file_size_start)
                if file_size_end == -1:
                    file_size_end = chunk.find(b' ', file_size_start)
                if file_size_end != -1:
                    try:
                        file_size = int(chunk[file_size_start:file_size_end].split()[0])
                        pdf_content = chunk[start_index:start_index + file_size]
                        if is_valid_file(pdf_content, 'pdf'):
                            self.save_file(pdf_content, 'pdf', global_offset + start_index)
                            offset = start_index + file_size
                            continue
                    except ValueError:
                        pass
            end_index = chunk.find(pdf_end_signature, start_index)
            if end_index != -1:
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]
                if is_valid_file(pdf_content, 'pdf'):
                    self.save_file(pdf_content, 'pdf', global_offset + start_index)
                offset = end_index
            else:
                offset = start_index + 1

    def carve_wav_files(self, chunk, base_offset):
        wav_start_signature = WAV_HEADER
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(wav_start_signature, cursor)
            if start_index == -1:
                break

            if chunk[start_index + 8:start_index + 12] != b'WAVE':
                cursor = start_index + 4
                continue

            file_size_bytes = chunk[start_index + 4:start_index + 8]
            file_size = int.from_bytes(file_size_bytes, byteorder='little') + 8

            if start_index + file_size > len(chunk):
                wav_content = chunk[start_index:]
                cursor = len(chunk)
            else:
                wav_content = chunk[start_index:start_index + file_size]
                cursor = start_index + file_size

            if is_valid_file(wav_content, 'wav'):
                self.save_file(wav_content, 'wav', base_offset + start_index)

    def _carve_by_footer(self, chunk, base_offset, file_type,
                         header, footer):
        """Carve every `header` .. `footer` span that actually parses.

        The first footer after a header is routinely the wrong one. A JPEG's
        EXIF thumbnail ends with the same FFD9 the image does, so taking the
        first match truncates a fully recoverable photo into a fragment --
        which is how two intact JPEGs in the DFTT test image were being lost.

        So each candidate footer is tried in turn and the first that validates
        wins. A header whose footers all fail is abandoned, and the search
        resumes just past the header rather than past the failed span: a real
        file can begin inside the region a false candidate covered.
        """
        cap = CARVE_MAX_SIZE.get(file_type)
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(header, cursor)
            if start_index == -1:
                break

            end_index = start_index
            carved = False
            for _ in range(CARVE_MAX_FOOTER_CANDIDATES):
                end_index = chunk.find(footer, end_index + 1)
                if end_index == -1:
                    break

                size = end_index + len(footer) - start_index
                if cap and size > cap:
                    break               # every later footer is only further

                content = chunk[start_index:end_index + len(footer)]
                if is_valid_file(content, file_type):
                    self.save_file(content, file_type,
                                   base_offset + start_index)
                    cursor = end_index + len(footer)
                    carved = True
                    break

            if not carved:
                cursor = start_index + len(header)

    def carve_jpg_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'jpg',
                              JPG_HEADER, JPG_FOOTER)

    def carve_gif_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'gif',
                              GIF_HEADER, GIF_FOOTER)

    def carve_png_files(self, chunk, base_offset):
        self._carve_by_footer(chunk, base_offset, 'png',
                              PNG_HEADER, PNG_FOOTER)

    def carve_mov_files(self, chunk, base_offset):
        """Recover QuickTime and MP4 by walking the atom chain.

        A MOV is a flat sequence of size-prefixed atoms, so the file's extent
        is the walk itself rather than a footer to search for. The previous
        version scanned four bytes at a time for one of four atom types, then
        emitted a single file after the loop -- so it found at most one MOV per
        chunk, entered files at whichever atom happened to match first, and had
        `ftyp` commented out of its list entirely.

        MP4 is the same container, so one walk finds both and the brand in the
        `ftyp` atom decides the extension. Running the walk once and labelling
        the result is what keeps a single file from being written twice.
        """
        self._carve_atom_chain(chunk, base_offset)

    def carve_mp4_files(self, chunk, base_offset):
        """MP4 shares QuickTime's container, and so shares carve_mov_files.

        Deliberately empty: the atom walk already emits MP4s with the right
        extension. Carving here as well would write the same bytes a second
        time under a second name.
        """
        return

    def _carve_atom_chain(self, chunk, base_offset):
        cap = max(CARVE_MAX_SIZE.get('mov', 0), CARVE_MAX_SIZE.get('mp4', 0))
        cursor = 0
        while cursor + 8 <= len(chunk):
            anchor = self._next_atom_start(chunk, cursor)
            if anchor is None:
                break

            end = self._walk_atoms(chunk, anchor, cap)
            if end is None:
                # Not a real chain; resume just past this candidate rather
                # than past the span it would have covered.
                cursor = anchor + 4
                continue

            content = chunk[anchor:end]
            file_type = self._isobmff_extension(content)
            if is_valid_file(content, file_type):
                self.save_file(content, file_type, base_offset + anchor)
                cursor = end
            else:
                cursor = anchor + 4

    @staticmethod
    def _isobmff_extension(content):
        """'mp4' or 'mov', from the brand the file declares.

        A `ftyp` atom names the specification the file was written to. Classic
        QuickTime predates `ftyp` and simply has none, so its absence is itself
        the answer.
        """
        if content[4:8] != b'ftyp':
            return 'mov'
        brand = content[8:12]
        return 'mov' if brand in (b'qt  ', b'moov') else 'mp4'

    @staticmethod
    def _next_atom_start(chunk, cursor):
        """Offset of the next plausible container-opening atom."""
        best = None
        for name in (b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide',
                     b'pnot'):
            # The type sits 4 bytes into the atom, after its size.
            found = chunk.find(name, cursor + 4)
            while found != -1:
                start = found - 4
                size = int.from_bytes(chunk[start:start + 4], 'big')
                if size == 0 or size == 1 or size >= 8:
                    if best is None or start < best:
                        best = start
                    break
                found = chunk.find(name, found + 1)
        return best

    @staticmethod
    def _walk_atoms(chunk, start, cap):
        """End offset of the atom chain beginning at `start`, or None.

        Returns None when the chain is not one: a single atom proves nothing,
        because four printable bytes preceded by a plausible length occur in
        ordinary data.
        """
        pos = start
        atoms = 0
        while pos + 8 <= len(chunk):
            size = int.from_bytes(chunk[pos:pos + 4], 'big')
            kind = chunk[pos + 4:pos + 8]
            if not _ATOM_NAME_RE.match(kind):
                break
            if size == 0:
                pos = len(chunk)        # runs to the end of the file
                atoms += 1
                break
            if size == 1:
                if pos + 16 > len(chunk):
                    break
                size = int.from_bytes(chunk[pos + 8:pos + 16], 'big')
            if size < 8 or pos + size > len(chunk):
                break
            if cap and (pos + size) - start > cap:
                break
            pos += size
            atoms += 1

        if atoms < 2 or pos <= start:
            return None
        return pos

    def carve_wmv_files(self, chunk, base_offset):
        """Recover ASF/WMV using the size the ASF header object declares."""
        cap = CARVE_MAX_SIZE.get('wmv')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(ASF_HEADER_GUID, cursor)
            if start_index == -1:
                break

            # The Header Object's own size sits immediately after its GUID;
            # the total file size lives in the File Properties Object.
            size = self._asf_file_size(chunk, start_index)
            if size is None or size < CARVE_MIN_SIZE:
                cursor = start_index + 1
                continue
            if cap and size > cap:
                cursor = start_index + 1
                continue

            end_index = start_index + size
            if end_index > len(chunk):
                # Runs past this read; the next chunk's overlap holds it whole.
                cursor = start_index + 1
                continue

            content = chunk[start_index:end_index]
            if is_valid_file(content, 'wmv'):
                self.save_file(content, 'wmv', base_offset + start_index)
                cursor = end_index
            else:
                cursor = start_index + 1

    @staticmethod
    def _asf_file_size(chunk, start_index):
        """Total file size from the ASF File Properties Object, if present."""
        window = min(start_index + 1024, len(chunk))
        properties = chunk.find(ASF_PROPERTIES_GUID, start_index, window)
        if properties == -1:
            return None
        # GUID (16) + object size (8) + File ID (16), then the 64-bit
        # file size.
        field = properties + 40
        if field + 8 > len(chunk):
            return None
        return int.from_bytes(chunk[field:field + 8], 'little')

    def carve_zip_files(self, chunk, base_offset):
        """Recover each ZIP archive as its own file.

        The previous version joined every local file header in the chunk into
        one output named after the first, and computed each entry's stride as
        `30 + compressed_size` -- omitting the filename and extra-field
        lengths at +26 and +28. Measured against wword60t.zip in the DFTT
        image, whose single entry has an 11-byte name, every archive came out
        exactly 11 bytes short and would not open.
        """
        cap = CARVE_MAX_SIZE.get('zip')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(ZIP_LOCAL_HEADER, cursor)
            if start_index == -1:
                break

            end = self._zip_extent(chunk, start_index, cap)
            if end is None:
                cursor = start_index + len(ZIP_LOCAL_HEADER)
                continue

            content = chunk[start_index:end]
            if is_valid_file(content, 'zip'):
                self.save_file(content, 'zip', base_offset + start_index)
                cursor = end
            else:
                cursor = start_index + len(ZIP_LOCAL_HEADER)

    @staticmethod
    def _zip_extent(chunk, start_index, cap):
        """End offset of the archive beginning at `start_index`, or None.

        Walks the local file headers to find this archive's own End of Central
        Directory record, so two archives lying next to each other stay two
        files.
        """
        pos = start_index
        while pos + 30 <= len(chunk) and chunk[pos:pos + 4] == ZIP_LOCAL_HEADER:
            try:
                flags = struct.unpack('<H', chunk[pos + 6:pos + 8])[0]
                compressed = struct.unpack('<I', chunk[pos + 18:pos + 22])[0]
                name_len = struct.unpack('<H', chunk[pos + 26:pos + 28])[0]
                extra_len = struct.unpack('<H', chunk[pos + 28:pos + 30])[0]
            except struct.error:
                return None

            if flags & 0x08 and compressed == 0:
                # Sizes were streamed into a trailing data descriptor, so the
                # local header cannot tell us the stride. The central
                # directory is the only reliable end.
                break

            pos += 30 + name_len + extra_len + compressed
            if cap and pos - start_index > cap:
                return None

        eocd = chunk.find(ZIP_EOCD, start_index)
        if eocd == -1 or eocd + 22 > len(chunk):
            return None
        try:
            comment_len = struct.unpack('<H', chunk[eocd + 20:eocd + 22])[0]
        except struct.error:
            return None

        end = eocd + 22 + comment_len
        if end > len(chunk):
            return None
        if cap and end - start_index > cap:
            return None
        return end

    def carve_bmp_files(self, chunk, base_offset):
        bmp_start_signature = BMP_HEADER
        header_size = 14  # The static header size for BMP files

        current_offset = 0
        while current_offset < len(chunk) - header_size:
            # Look for the BMP signature
            start_index = chunk.find(bmp_start_signature, current_offset)
            if start_index == -1:
                break  # No more BMP files found

            # Verify there's enough chunk left to read the BMP size
            if start_index + header_size > len(chunk) - 4:
                break  # Not enough data for size

            # Read file size directly from header
            bmp_file_size = int.from_bytes(chunk[start_index + 2:start_index + 6], byteorder='little')

            # Sanity check for BMP size (adjust max and min size as per your need)
            if bmp_file_size < 100 or bmp_file_size > 5000000:
                current_offset = start_index + 2
                continue  # Not a valid BMP size, skip to next possible start

            # Read and check dimensions for further validation
            bmp_width = int.from_bytes(chunk[start_index + 18:start_index + 22], byteorder='little')
            bmp_height = int.from_bytes(chunk[start_index + 22:start_index + 26], byteorder='little')

            # Reasonable dimensions check (adjust max width/height as per your need)
            if bmp_width <= 0 or bmp_width > 10000 or bmp_height <= 0 or bmp_height > 10000:
                current_offset = start_index + 2
                continue  # Unreasonable dimensions, likely not a BMP

            # Extract the BMP file if it's entirely within the chunk
            if start_index + bmp_file_size <= len(chunk):
                bmp_content = chunk[start_index:start_index + bmp_file_size]
                # Header plausibility is not proof: 'BM' plus a believable size
                # and dimensions matched 174 times in one 62 MB test image.
                if is_valid_file(bmp_content, 'bmp'):
                    self.save_file(bmp_content, 'bmp',
                                   base_offset + start_index)
                    current_offset = start_index + bmp_file_size
                else:
                    current_offset = start_index + 2
            else:
                break  # The BMP file exceeds the chunk boundary, stop processing

        # Return if more data is needed or if processing is complete
        return None

    def carve_ole_files(self, chunk, base_offset):
        """Recover legacy Office documents (.doc, .xls, .ppt).

        An OLE2 compound file states its own length: the header names a sector
        size and the count of sectors in each of its allocation tables, so the
        extent follows from the header rather than from a footer search. These
        formats have no footer at all, which is why a signature-and-footer
        carver could never recover them -- six of them sit unrecovered in the
        two DFTT test images.
        """
        cap = CARVE_MAX_SIZE.get('ole')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(OLE_HEADER, cursor)
            if start_index == -1:
                break

            size = self._ole_size(chunk, start_index, cap)
            if size is None:
                cursor = start_index + len(OLE_HEADER)
                continue

            # The header only bounds the file from above, and the bound
            # overshoots: on the DFTT ext2 image it ran 49 KB past the end of
            # stats.xls and swallowed the document that follows. Another OLE
            # signature is a hard stop -- a file cannot contain the start of
            # the next one.
            following = chunk.find(OLE_HEADER, start_index + len(OLE_HEADER))
            if following != -1:
                size = min(size, following - start_index)

            content = chunk[start_index:start_index + size]
            if is_valid_file(content, 'ole'):
                self.save_file(content, 'ole', base_offset + start_index)
                cursor = start_index + size
            else:
                cursor = start_index + len(OLE_HEADER)

    @staticmethod
    def _ole_size(chunk, start_index, cap):
        """Length of the OLE compound file starting at `start_index`.

        Derived from the highest sector the header's FAT accounts for. This is
        an upper bound on a well-formed file, which is what carving wants: the
        alternative is guessing, and a short guess truncates a document.
        """
        if start_index + 512 > len(chunk):
            return None
        header = chunk[start_index:start_index + 512]
        try:
            shift = struct.unpack('<H', header[30:32])[0]
            fat_sectors = struct.unpack('<I', header[44:48])[0]
            dir_sectors = struct.unpack('<I', header[40:44])[0]
            mini_sectors = struct.unpack('<I', header[64:68])[0]
        except struct.error:
            return None

        if shift not in (9, 12):
            return None
        sector = 1 << shift
        if not 0 < fat_sectors < 65536:
            return None

        # Each FAT sector maps sector/4 sectors of file.
        mapped = fat_sectors * (sector // 4)
        size = (1 + mapped) * sector
        if dir_sectors or mini_sectors:
            size += (dir_sectors + mini_sectors) * sector

        if size < CARVE_MIN_SIZE:
            return None
        if cap and size > cap:
            return None
        if start_index + size > len(chunk):
            size = len(chunk) - start_index
        return size

    def carve_tiff_files(self, chunk, base_offset):
        """Recover TIFF by walking its IFD chain to the last entry."""
        cap = CARVE_MAX_SIZE.get('tiff')
        for header in TIFF_HEADERS:
            cursor = 0
            big_endian = header.startswith(b'MM')
            while cursor < len(chunk):
                start_index = chunk.find(header, cursor)
                if start_index == -1:
                    break

                size = self._tiff_size(chunk, start_index, big_endian, cap)
                if size is None:
                    cursor = start_index + len(header)
                    continue

                content = chunk[start_index:start_index + size]
                if is_valid_file(content, 'tiff'):
                    self.save_file(content, 'tiff', base_offset + start_index)
                    cursor = start_index + size
                else:
                    cursor = start_index + len(header)

    @staticmethod
    def _tiff_size(chunk, start_index, big_endian, cap):
        """Extent of the TIFF at `start_index`, from its IFD chain."""
        order = '>' if big_endian else '<'
        try:
            offset = struct.unpack(
                order + 'I', chunk[start_index + 4:start_index + 8])[0]
        except struct.error:
            return None

        furthest = 8
        for _ in range(16):             # bounded: a chain can be circular
            ifd = start_index + offset
            if offset < 8 or ifd + 2 > len(chunk):
                return None
            try:
                count = struct.unpack(order + 'H', chunk[ifd:ifd + 2])[0]
            except struct.error:
                return None
            if count == 0 or count > 512:
                return None

            end_of_ifd = ifd + 2 + count * 12 + 4
            if end_of_ifd > len(chunk):
                return None
            furthest = max(furthest, end_of_ifd - start_index)

            # Every entry whose value does not fit inline points outward; the
            # file has to extend past the furthest of those.
            for n in range(count):
                entry = ifd + 2 + n * 12
                try:
                    kind, length = struct.unpack(
                        order + 'HI', chunk[entry + 2:entry + 8])
                except struct.error:
                    return None
                width = _TIFF_TYPE_WIDTH.get(kind, 0)
                total = width * length
                if total > 4:
                    try:
                        at = struct.unpack(
                            order + 'I', chunk[entry + 8:entry + 12])[0]
                    except struct.error:
                        return None
                    furthest = max(furthest, at + total)

            try:
                offset = struct.unpack(
                    order + 'I', chunk[end_of_ifd - 4:end_of_ifd])[0]
            except struct.error:
                return None
            if offset == 0:
                break

        if furthest < CARVE_MIN_SIZE:
            return None
        if cap and furthest > cap:
            return None
        if start_index + furthest > len(chunk):
            return None
        return furthest

    def carve_gz_files(self, chunk, base_offset):
        """Recover gzip streams by decompressing until the stream ends.

        A gzip member carries no length, so the only honest way to find its end
        is to decompress it and ask how much input was consumed.
        """
        cap = CARVE_MAX_SIZE.get('gz')
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(GZIP_HEADER, cursor)
            if start_index == -1:
                break

            window = chunk[start_index:start_index + (cap or len(chunk))]
            decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                decomp.decompress(window, _GZIP_DECOMPRESS_LIMIT)
                consumed = len(window) - len(decomp.unused_data)
            except zlib.error:
                cursor = start_index + len(GZIP_HEADER)
                continue

            if not decomp.eof or consumed < CARVE_MIN_SIZE:
                cursor = start_index + len(GZIP_HEADER)
                continue

            content = chunk[start_index:start_index + consumed]
            if is_valid_file(content, 'gz'):
                self.save_file(content, 'gz', base_offset + start_index)
                cursor = start_index + consumed
            else:
                cursor = start_index + len(GZIP_HEADER)

    def carve_rar_files(self, chunk, base_offset):
        self._carve_by_marker(chunk, base_offset, 'rar', RAR_HEADER)

    def carve_7z_files(self, chunk, base_offset):
        self._carve_by_marker(chunk, base_offset, '7z', SEVENZIP_HEADER)

    def _carve_by_marker(self, chunk, base_offset, file_type, header):
        """Carve an archive that runs to the next signature or the cap.

        RAR and 7z encode their extents inside structures this carver does not
        parse, so the recovered span runs to the next header of the same type.
        That is an upper bound, and the file is written only if it validates.
        """
        cap = CARVE_MAX_SIZE.get(file_type)
        cursor = 0
        while cursor < len(chunk):
            start_index = chunk.find(header, cursor)
            if start_index == -1:
                break

            following = chunk.find(header, start_index + len(header))
            end = following if following != -1 else len(chunk)
            if cap:
                end = min(end, start_index + cap)

            content = chunk[start_index:end]
            if is_valid_file(content, file_type):
                self.save_file(content, file_type, base_offset + start_index)
            cursor = start_index + len(header)

    def carve_html_files(self, chunk, base_offset):
        """Recover HTML documents between <html and </html>."""
        cap = CARVE_MAX_SIZE.get('html')
        lowered = chunk.lower()
        cursor = 0
        while cursor < len(chunk):
            start_index = lowered.find(b'<html', cursor)
            if start_index == -1:
                break

            end_index = lowered.find(b'</html>', start_index)
            if end_index == -1:
                cursor = start_index + 5
                continue

            end = end_index + len(b'</html>')
            if cap and end - start_index > cap:
                cursor = start_index + 5
                continue

            content = chunk[start_index:end]
            if len(content) >= CARVE_MIN_SIZE:
                self.save_file(content, 'html', base_offset + start_index)
            cursor = end

    #: Which carver handles each selected type. Keys are lowercase because the
    #: menu labels are lowercased before dispatch.
    CARVERS = {
        'pdf': carve_pdf_files,
        'jpg': carve_jpg_files,
        'png': carve_png_files,
        'gif': carve_gif_files,
        'bmp': carve_bmp_files,
        'tiff': carve_tiff_files,
        'wav': carve_wav_files,
        'mov': carve_mov_files,
        'mp4': carve_mp4_files,
        'wmv': carve_wmv_files,
        'zip': carve_zip_files,
        'gz': carve_gz_files,
        'rar': carve_rar_files,
        '7z': carve_7z_files,
        'ole': carve_ole_files,
        'html': carve_html_files,
    }

    def carve_files(self, selected_file_types):
        try:
            self._stop_requested = False
            # Advance by CHUNK_SIZE but read CARVE_OVERLAP beyond it. Two
            # reasons, both measured on the test image:
            #
            # The allocation check is only as precise as this step, and any
            # span holding a single allocated byte is skipped whole. At the
            # 100 MB used previously that skipped 1.37 GB where 1.25 GB is
            # actually allocated -- 120 MB of deleted data never scanned. At
            # 4 MB the over-skip is about 10 MB.
            #
            # Chunks do not overlap by default, and a carver abandons any file
            # that runs off the end of its buffer, so a smaller step alone
            # would turn 163 boundaries into 4096 places a file can be lost.
            # The overlap makes a file crossing a boundary whole in the next
            # read; duplicates cost nothing because save_file names each file
            # after its absolute offset, so the second find rewrites the same
            # path.
            chunk_size = CHUNK_SIZE
            read_size = CHUNK_SIZE + CARVE_OVERLAP
            offset = 0
            chunks_processed = 0
            chunks_skipped = 0

            while offset < self.image_handler.get_size():
                # Check if this chunk overlaps with allocated space
                if self.is_offset_allocated(offset, chunk_size, self.allocation_map):
                    # Skip this chunk - it's in allocated space (existing files)
                    chunks_skipped += 1
                    offset += chunk_size
                    continue

                chunks_processed += 1

                # Stop the read at the next allocated region. The chunk itself
                # is known unallocated, but the overlap window beyond it is not
                # checked by the test above -- reading it blindly pulled live
                # file data into the carvers, which is precisely what the
                # allocation map exists to prevent.
                limit = self.next_allocated_start(offset, self.allocation_map)
                span = read_size if limit is None else min(read_size, limit - offset)
                if span <= 0:
                    offset += chunk_size
                    continue

                chunk = self.image_handler.read(offset, span)
                if not chunk:
                    break

                if self._stop_requested:
                    self._stop_requested = False
                    logger.info(
                        "Carving stopped. Processed %d unallocated chunks, "
                        "skipped %d allocated chunks",
                        chunks_processed, chunks_skipped)
                    # The buttons are restored by the carving_finished slot,
                    # which runs on the UI thread. Touching a widget from this
                    # worker is a data race Qt does not police.
                    self.carving_finished.emit()
                    return

                # One carver per selected type. A mapping rather than a
                # chain of elifs: adding a format is one entry here, and the
                # unreachable 'all' branch the old chain carried -- left over
                # from a check box the UI no longer has -- cannot come back.
                for file_type in selected_file_types:
                    carver = self.CARVERS.get(file_type)
                    if carver is None:
                        continue
                    try:
                        carver(self, chunk, offset)
                    except Exception as exc:
                        # One malformed span must not end the scan. Without
                        # this a struct.error on a chunk tail killed the whole
                        # carve, and the future swallowed it so the UI showed
                        # a clean finish.
                        logger.warning(
                            "%s failed at offset %d: %s: %s",
                            carver.__name__, offset, type(exc).__name__, exc)

                offset += chunk_size

            logger.info(
                "Carving complete. Recovered %d file(s) from %d unallocated "
                "chunks; skipped %d allocated chunks",
                len(self.carved_files), chunks_processed, chunks_skipped)
        finally:
            # Both the buttons and the column sizing happen in the
            # carving_finished slot: it is queued behind the rows this scan
            # emitted, so it runs on the UI thread against a filled table.
            self.carving_finished.emit()

    #: Widest a carving column may grow. File Path holds a full path, which
    #: would otherwise set the table's width on its own.
    _CARVED_COLUMN_CAPS = {6: 420}

    @Slot()
    def _fit_carved_columns(self):
        """Finish a scan: restore the buttons and size the columns.

        A slot, so it is delivered on the UI thread after every queued
        display_carved_file has run; called directly from the worker it
        measured an empty table -- and would touch widgets from the wrong
        thread.
        """
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        try:
            fit_columns(self.table_widget, self._CARVED_COLUMN_CAPS)
        except Exception as e:
            logger.debug("Could not fit the carving columns: %s", e)

    @staticmethod
    def render_pdf_thumbnail(pdf_path, thumbnail_folder, name):
        """Render page 1 of a carved PDF to a QPixmap via PyMuPDF.

        Returns an empty QPixmap if the PDF is too damaged to open, which is
        common for carved fragments; the caller falls back to a blank tile.
        """
        thumbnail_path = os.path.join(thumbnail_folder, name.rsplit('.', 1)[0] + '.png')
        try:
            with fitz_open(pdf_path) as doc:
                if doc.page_count < 1:
                    return QPixmap()
                page = doc.load_page(0)
                pix = page.get_pixmap(matrix=Matrix(1.5, 1.5))
                pix.save(thumbnail_path)
            return QPixmap(thumbnail_path)
        except Exception as e:
            logger.error(f"Could not render PDF thumbnail for {name}: {e}")
            return QPixmap()


    def save_file(self, file_content, file_type, offset):
        """Write one recovered file, named after where on disk it was found.

        `offset` must be absolute within the image, not relative to the chunk:
        it is the file's identity. Chunks overlap by CARVE_OVERLAP so that a
        file straddling a boundary is whole in the following read, which means
        the same file is genuinely found several times -- the absolute offset
        is what lets us recognise it as one file rather than nine.
        """
        carved_dir = carved_files_dir()

        offset_hex = format(offset, 'x')
        file_name = f"{offset_hex}.{file_type}"

        # Already recovered from an earlier, overlapping chunk.
        if file_name in self.carved_file_names:
            return

        file_path = os.path.join(carved_dir, file_name)

        # Write file content to disk
        with open(file_path, "wb") as f:
            f.write(file_content)

        # Only a date the file carries in its own bytes means anything here.
        # A carved file has no directory entry, so its filesystem created,
        # modified and deleted times are gone; stamping it with the time of
        # recovery would present our own clock as evidence.
        original_timestamp, source = extract_original_timestamp(file_content,
                                                                file_type)

        if original_timestamp:
            # Give the extracted file the date it claims, so it still reads
            # correctly outside TRACE.
            timestamp = time.mktime(original_timestamp.timetuple())
            os.utime(file_path, (timestamp, timestamp))
            embedded_date = original_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            embedded_date = UNKNOWN_DATE

        file_size = str(len(file_content))
        self.carved_file_names.add(file_name)
        self.carved_files.append((file_name, file_size, file_type, file_path,
                                  embedded_date, source))
        self.file_carved.emit(file_name, file_size, file_type, embedded_date,
                              file_path, source)

    @Slot(str, str, str, str, str, str)
    def display_carved_file(self, name, size, type_, embedded_date, file_path,
                            source=""):
        row = self.table_widget.rowCount()
        readable_size = self.image_handler.get_readable_size(int(size))
        self.table_widget.insertRow(row)

        # Get file icon based on type/extension
        extension = type_.lower() if type_ else 'unknown'
        icon_path = self.icon_resolver('file', extension) if self.icon_resolver else ''

        # Set Id column
        self.table_widget.setItem(row, 0, QTableWidgetItem(str(row + 1)))

        # Set Name column with icon
        name_item = QTableWidgetItem(name)
        name_item.setIcon(QIcon(icon_path))
        self.table_widget.setItem(row, 1, name_item)

        # Set other columns
        self.table_widget.setItem(row, 2, NumericTableWidgetItem(readable_size))
        self.table_widget.setItem(row, 3, QTableWidgetItem(type_))
        date_item = QTableWidgetItem(embedded_date)
        if embedded_date == UNKNOWN_DATE:
            # Say why there is no date, rather than leaving the examiner to
            # wonder whether the scan failed.
            date_item.setToolTip(
                f"{type_.upper()} carries no timestamp in its own data, and a "
                "carved file has no filesystem record to read one from.")
        self.table_widget.setItem(row, 4, date_item)
        self.table_widget.setItem(row, 5, QTableWidgetItem(source))
        self.table_widget.setItem(row, 6, QTableWidgetItem(file_path))

        # Only proceed if the file type is one of the supported formats
        if type_.lower() in ['jpg', 'jpeg', 'png', 'gif', 'mov', 'pdf', 'wmv', 'bmp', 'zip', 'wav']:
            carved_dir = carved_files_dir()
            file_full_path = os.path.join(carved_dir, name)
            thumbnail_folder = os.path.join(carved_dir, "thumbnails")

            if type_.lower() == 'pdf':
                # Render the first page with PyMuPDF, which is already a
                # dependency (the Application viewer uses it). This replaces
                # pdf2image, which needed a separate poppler install.
                pixmap = self.render_pdf_thumbnail(file_full_path, thumbnail_folder, name)

            elif type_.lower() in VIDEO_TYPES:
                # Video frame extraction previously needed moviepy (ffmpeg) for
                # .mov and OpenCV for .wmv -- roughly 100 MB of wheels plus an
                # ffmpeg binary, for a thumbnail. Carved video fragments are
                # frequently truncated and fail to decode anyway, so show a
                # generic icon instead.
                pixmap = self.render_svg_to_pixmap(icons.path(icons.FILE_VIDEO), 120)

            elif type_.lower() in ARCHIVE_TYPES:
                # Render archive icon at target size for crisp display
                pixmap = self.render_svg_to_pixmap(icons.path(icons.FILE_ARCHIVE), 120)

            elif type_.lower() in AUDIO_TYPES:
                # Render audio icon at target size for crisp display
                pixmap = self.render_svg_to_pixmap(icons.path(icons.FILE_AUDIO), 120)

            elif type_.lower() == 'ole':
                # A carved OLE file could be Word, Excel or PowerPoint: they
                # share one container and the header does not say which.
                pixmap = self.render_svg_to_pixmap(icons.path(icons.FILE_DOC), 120)

            elif type_.lower() == 'html':
                pixmap = self.render_svg_to_pixmap(icons.path(icons.FILE_HTML), 120)

            else:
                # For image files, use the original file path
                thumbnail_path = file_full_path
                pixmap = QPixmap(thumbnail_path)

            # Center-crop to a square for a uniform gallery. Skipped for the
            # generic SVG icons, which are already square and would only lose
            # their margins.
            if type_.lower() not in ICON_TYPES:
                pixmap = self.center_crop_to_square(pixmap, 120)
            icon = QIcon(pixmap)

            # Create a QListWidgetItem, set its icon, and provide a size hint to ensure the text is visible
            item = QListWidgetItem(icon, name)
            # Set a compact size for the QListWidgetItem with minimal padding for text
            item.setSizeHint(QSize(130, 145))

            # Set the item flags to not be movable and to be selectable
            item.setFlags(item.flags() & ~Qt.ItemIsDragEnabled & ~Qt.ItemIsDropEnabled)

            # Add the QListWidgetItem to the list widget
            self.list_widget.addItem(item)

    def clear(self):
        self.table_widget.setRowCount(0)
        self.list_widget.clear()
        self.carved_files.clear()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def clear_ui(self):
        self.table_widget.setRowCount(0)
        self.list_widget.clear()


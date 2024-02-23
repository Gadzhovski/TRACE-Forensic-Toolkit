import datetime
import io
import os
import olefile
import xlrd

from concurrent.futures import ThreadPoolExecutor
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError
from PySide6.QtCore import QSize, QUrl
from PySide6.QtCore import Qt
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QAction, QDesktopServices, QPixmap
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QToolBar, QSizePolicy, QHBoxLayout, \
    QCheckBox, QHeaderView
from PySide6.QtWidgets import QMenu
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QTabWidget
from moviepy.editor import VideoFileClip
from pdf2image import convert_from_path


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
    file_carved = Signal(str, str, str, str, str)  # Unified signal for file carving

    def __init__(self, parent=None):
        super().__init__(parent)
        self.image_handler = None
        self.executor = ThreadPoolExecutor(max_workers=4)  # ThreadPoolExecutor for background tasks
        self.carved_files = []
        self.carved_file_names = set()  # Track carved file names to avoid duplicates
        self.init_ui()

    def init_ui(self):

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)  # Set the spacing to zero

        self.toolbar = QToolBar()
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap('Icons/icons8-carving-64.png'))
        self.icon_label.setFixedSize(48, 48)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("File Carving")
        self.title_label.setStyleSheet("""
            QLabel {
                font-size: 20px; /* Slightly larger size for the title */
                color: #37c6d0; /* Hex color for the text */
                font-weight: bold; /* Make the text bold */
                margin-left: 8px; /* Space between icon and label */
            }
        """)
        self.toolbar.addWidget(self.title_label)

        self.spacer = QLabel()
        self.spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(self.spacer)

        self.table_widget = self.create_table_widget()
        self.list_widget = self.create_list_widget()

        self.fileTypeLayout = QHBoxLayout()
        self.fileTypes = {"All": QCheckBox("All"), "PDF": QCheckBox("PDF"), "JPG": QCheckBox("JPG"),
                          "PNG": QCheckBox("PNG"),
                          "GIF": QCheckBox("GIF"), "XLS": QCheckBox("XLS"), "WAV": QCheckBox("WAV"),
                          "MOV": QCheckBox("MOV")}

        for fileType, checkBox in self.fileTypes.items():
            self.fileTypeLayout.addWidget(checkBox)

        # Adding a widget to contain the file type checkboxes
        self.fileTypeWidget = QWidget()
        self.fileTypeWidget.setLayout(self.fileTypeLayout)
        self.toolbar.addWidget(self.fileTypeWidget)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_carving)

        self.toolbar.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_carving)
        self.stop_button.setEnabled(False)

        self.toolbar.addWidget(self.stop_button)
        self.layout.addWidget(self.tab_widget)

        self.file_carved.connect(self.display_carved_file)

    def create_table_widget(self):
        table_widget = QTableWidget()

        table_widget.setColumnCount(5)
        table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        table_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table_widget.setSortingEnabled(True)

        table_widget.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modification Date', 'File Path'])
        table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        table_widget.customContextMenuRequested.connect(self.open_context_menu)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(table_widget, "File List")
        return table_widget

    def create_list_widget(self):
        list_widget = QListWidget()
        # remove space between items
        list_widget.setViewMode(QListWidget.IconMode)

        list_widget.setIconSize(QSize(100, 100))
        list_widget.setResizeMode(QListWidget.Adjust)
        list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        list_widget.customContextMenuRequested.connect(self.open_context_menu)

        toolbar = QToolBar()

        # Define actions
        action_small_size = (QAction("Small Size", self))
        action_small_size.setIcon(QIcon('Icons/icons8-small-icons-50.png'))

        action_medium_size = (QAction("Medium Size", self))
        action_medium_size.setIcon(QIcon('Icons/icons8-medium-icons-50.png'))

        action_large_size = (QAction("Large Size", self))
        action_large_size.setIcon(QIcon('Icons/icons8-large-icons-50.png'))

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

        # self.tab_widget.addTab(list_widget, "Thumbnails")
        return list_widget

    def set_icon_size(self, size):
        self.list_widget.setIconSize(QSize(size, size))
        for index in range(self.list_widget.count()):
            item = self.list_widget.item(index)
            item.setSizeHint(QSize(size + 20, size + 20))  # Provide some padding around the icon

    def set_small_size(self):
        self.set_icon_size(50)

    def set_medium_size(self):
        self.set_icon_size(100)

    def set_large_size(self):
        self.set_icon_size(200)

    def start_carving(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Clear internal tracking and UI components to start fresh
        self.clear_ui()
        self.carved_files.clear()
        self.carved_file_names.clear()

        selected_file_types = [fileType.lower() for fileType, checkbox in self.fileTypes.items() if
                               checkbox.isChecked()]
        self.executor.submit(self.carve_files, selected_file_types)

    def stop_carving(self):
        # Code to stop the carving process...
        self.executor.shutdown(wait=True)  # Properly shutdown the executor
        self.start_button.setEnabled(True)  # Re-enable the start button
        self.stop_button.setEnabled(False)  # Disable the stop button

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self.start_button.setEnabled(True)

    def open_context_menu(self, position):
        menu = QMenu()
        open_location_action = QAction("Open File Location")
        open_location_action.triggered.connect(self.open_file_location)

        open_image_action = QAction("Open Image")
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

    def setup_buttons(self):
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_carving_thread)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_carving_thread)

    def start_carving_thread(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Launch carving in a background thread
        self.executor.submit(self.carve_files)

    def stop_carving_thread(self):
        self.executor.shutdown(wait=False)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def is_valid_file(self, data, file_type):
        try:
            if file_type == 'pdf':
                # Validate PDF by trying to read it with PyPDF2
                PdfReader(io.BytesIO(data))
            elif file_type in ['jpg', 'jpeg', 'png', 'gif']:
                # Validate images by attempting to open them with PIL
                image = Image.open(io.BytesIO(data))
                image.verify()  # This will not load the image but only parse it
            elif file_type == 'xls':
                return self.is_valid_xls(data)
            elif file_type == 'bmp':
                return True
            elif file_type == 'wav':
                # Basic WAV validation could check for the RIFF header, file size, etc.
                if not data.startswith(b'RIFF') or not b'WAVE' in data[:12]:
                    return False
                # Additional WAV format checks could be implemented here
            elif file_type == 'mov':
                return True  # For now, we'll assume all MOV files are valid
            else:
                # For file types not specifically validated, you might choose to return True or implement additional checks
                return True
            return True
        except (IOError, UnidentifiedImageError, PdfReadError, ValueError) as e:
            print(f"Error validating file of type {file_type}: {str(e)}")
            return False

    def is_valid_xls(self, data):
        try:
            # First, check if it's an OLE file
            if not olefile.isOleFile(io.BytesIO(data)):
                return False

            # Attempt to open the workbook with xlrd
            workbook = xlrd.open_workbook(file_contents=data)

            # Basic checks: Can we access sheet names?
            if workbook.nsheets > 0 and workbook.sheet_names():
                # Potentially, further checks here: Accessing cell values, etc.
                return True
            else:
                return False
        except xlrd.XLRDError as e:
            print(f"XLRD Error: {str(e)}")
            return False
        except Exception as e:
            # Generic catch-all for unexpected errors
            print(f"Unexpected error validating XLS file: {str(e)}")
            return False

    def carve_pdf_files(self, chunk, global_offset):
        pdf_start_signature = b'%PDF-'
        pdf_end_signature = b'%%EOF'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(pdf_start_signature, offset)

            if start_index == -1:  # No more PDF start signature in the chunk
                break

            # Look for the end signature starting from the current start index
            end_index = chunk.find(pdf_end_signature, start_index)
            if end_index != -1:
                # Adjust end_index to capture the end of the EOF marker
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]

                if self.is_valid_file(pdf_content, 'pdf'):
                    self.save_file(pdf_content, 'pdf', 'carved_files', start_index + global_offset)

                # Update offset to search for the next PDF file after this EOF
                offset = end_index
            else:
                # If we don't find an EOF, move to the next byte and try again
                # This simplistic approach may need refinement for handling files spanning chunks
                offset = start_index + 1

    def carve_wav_files(self, chunk, offset):
        wav_start_signature = b'RIFF'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(wav_start_signature, offset)
            if start_index == -1:
                break

            if chunk[start_index + 8:start_index + 12] != b'WAVE':
                offset = start_index + 4
                continue

            file_size_bytes = chunk[start_index + 4:start_index + 8]
            file_size = int.from_bytes(file_size_bytes, byteorder='little') + 8

            if start_index + file_size > len(chunk):
                wav_content = chunk[start_index:]
                offset = len(chunk)
            else:
                wav_content = chunk[start_index:start_index + file_size]
                offset = start_index + file_size

            if self.is_valid_file(wav_content, 'wav'):

                self.save_file(wav_content, 'wav', 'carved_files', start_index)

    def carve_mov_files(self, chunk, offset):
        mov_signatures = [
            # b'ftyp', b'moov', b'mdat', #b'pnot', b'udta', #b'uuid',
            # b'moof', b'free', b'skip', b'jP2 ', b'wide', b'load',
            # b'ctab', b'imap', b'matt', b'kmat', b'clip', b'crgn',
            # b'sync', b'chap', b'tmcd', b'scpt', b'ssrc', b'PICT'
            b'moov', b'mdat', b'free', b'wide'
        ]

        mov_file_found = False
        mov_data = b''
        mov_file_offset = offset
        mov_file_size = 0

        while offset < len(chunk):
            if offset + 8 > len(chunk):
                # Not enough data for an atom header
                break

            atom_size = int.from_bytes(chunk[offset:offset + 4], 'big')
            atom_type = chunk[offset + 4:offset + 8]

            if atom_type not in mov_signatures:
                if mov_file_found:
                    # End of MOV file
                    break
                else:
                    # Not a MOV file or just a stray header, skip ahead
                    offset += 4
                    continue

            mov_file_found = True
            mov_file_size += atom_size

            if offset + atom_size > len(chunk):
                # Atom extends beyond this chunk, store what we have and wait for more data
                mov_data += chunk[offset:]
                break
            else:
                # We have the whole atom, store it
                mov_data += chunk[offset:offset + atom_size]

            offset += atom_size

        if mov_file_found and mov_data:
            # file_name = f"carved_{mov_file_offset}.mov"
            # file_path = os.path.join("carved_files", file_name)
            # self.save_file(mov_data, 'mov', file_path)
            self.save_file(mov_data, 'mov', 'carved_files', mov_file_offset)

    def carve_xls_files(self, chunk, global_offset):
        xls_header = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
        pattern_hex = "44006F00630075006D0065006E007400530075006D006D0061007200790049006E0066006F0072006D006100740069006F006E00"
        pattern_bytes = bytes.fromhex(pattern_hex)

        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(xls_header, offset)
            if start_index == -1:
                break

            pattern_index = chunk.find(pattern_bytes, start_index)
            if pattern_index == -1:
                offset += len(chunk)
                continue

            end_index = pattern_index + len(pattern_bytes) + 74
            end_index = min(end_index, len(chunk))

            xls_data = chunk[start_index:end_index]

            if self.is_valid_file(xls_data, 'xls'):

                self.save_file(xls_data, 'xls', 'carved_files', start_index + global_offset)

            offset = end_index

    def carve_jpg_files(self, chunk, offset):
        jpg_start_signature = b'\xFF\xD8\xFF'
        jpg_end_signature = b'\xFF\xD9'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(jpg_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(jpg_end_signature, start_index)
            if end_index != -1:
                jpg_content = chunk[start_index:end_index + len(jpg_end_signature)]

                # Check if it's a valid JPG file
                if self.is_valid_file(jpg_content, 'jpg'):

                    self.save_file(jpg_content, 'jpg', 'carved_files', start_index)

                offset = end_index + len(jpg_end_signature)
            else:
                offset = start_index + 1  # Continue searching

    def carve_gif_files(self, chunk, offset):
        gif_start_signature = b'\x47\x49\x46\x38'
        gif_end_signature = b'\x00\x3B'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(gif_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(gif_end_signature, start_index)
            if end_index != -1:
                gif_content = chunk[start_index:end_index + len(gif_end_signature)]

                # Check if it's a valid GIF file
                if self.is_valid_file(gif_content, 'gif'):

                    self.save_file(gif_content, 'gif', 'carved_files', start_index)

                offset = end_index + len(gif_end_signature)
            else:
                offset = start_index + 1

    def carve_png_files(self, chunk, offset):
        png_start_signature = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        png_end_signature = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(png_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(png_end_signature, start_index)
            if end_index != -1:
                png_content = chunk[start_index:end_index + len(png_end_signature)]

                # Check if it's a valid PNG file
                if self.is_valid_file(png_content, 'png'):

                    self.save_file(png_content, 'png', 'carved_files', start_index)

                offset = end_index + len(png_end_signature)
            else:
                offset = start_index + 1

    def carve_files(self, selected_file_types):
        try:
            self.stop_carving = False
            chunk_size = 1024 * 1024 * 100
            offset = 0

            while offset < self.image_handler.get_size():
                chunk = self.image_handler.read(offset, chunk_size)
                if not chunk:
                    break

                if self.stop_carving:
                    self.stop_carving = False
                    self.start_button.setEnabled(True)
                    self.stop_button.setEnabled(False)
                    return

                # Call the carve function for each selected file type
                for file_type in selected_file_types:
                    if file_type == 'all':
                        self.carve_wav_files(chunk, offset)
                        self.carve_mov_files(chunk, offset)
                        self.carve_pdf_files(chunk, offset)
                        self.carve_xls_files(chunk, offset)
                        self.carve_jpg_files(chunk, offset)
                        self.carve_gif_files(chunk, offset)
                        self.carve_png_files(chunk, offset)
                    elif file_type == 'wav':
                        self.carve_wav_files(chunk, offset)
                    elif file_type == 'mov':
                        self.carve_mov_files(chunk, offset)
                    elif file_type == 'pdf':
                        self.carve_pdf_files(chunk, offset)
                    elif file_type == 'xls':
                        self.carve_xls_files(chunk, offset)
                    elif file_type == 'jpg':
                        self.carve_jpg_files(chunk, offset)
                    elif file_type == 'gif':
                        self.carve_gif_files(chunk, offset)
                    elif file_type == 'png':
                        self.carve_png_files(chunk, offset)

                offset += chunk_size
        finally:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def save_file(self, file_content, file_type, file_path, offset):
        # Use hex representation of the offset for a shorter name.
        offset_hex = format(offset, 'x')
        file_name = f"{offset_hex}.{file_type}"
        file_path = os.path.join("carved_files", file_name)
        with open(file_path, "wb") as f:
            f.write(file_content)

        modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_size = str(len(file_content))

        self.carved_files.append((file_name, file_size, file_type, file_path, modification_date))
        self.file_carved.emit(file_name, file_size, file_type, modification_date, file_path)
        self.carved_file_names.add(file_name)


    @Slot(str, str, str, str, str)
    def display_carved_file(self, name, size, type_, modification_date, file_path):
        row = self.table_widget.rowCount()
        readable_size = self.image_handler.get_readable_size(int(size))
        self.table_widget.insertRow(row)
        self.table_widget.setItem(row, 0, QTableWidgetItem(name))
        self.table_widget.setItem(row, 1, NumericTableWidgetItem(readable_size))
        self.table_widget.setItem(row, 2, QTableWidgetItem(type_))
        self.table_widget.setItem(row, 3, QTableWidgetItem(modification_date))
        self.table_widget.setItem(row, 4, QTableWidgetItem(file_path))
        self.table_widget.setColumnWidth(0, 250)
        self.table_widget.setColumnWidth(1, 100)
        self.table_widget.setColumnWidth(2, 90)
        self.table_widget.setColumnWidth(3, 150)
        self.table_widget.setColumnWidth(4, 317)

        # Only proceed if the file type is one of the supported image or video formats
        if type_.lower() in ['jpg', 'jpeg', 'png', 'gif', 'mov', 'pdf']:
            file_full_path = os.path.join("carved_files", name)
            # Handle MOV and PDF thumbnails
            if type_.lower() == 'mov':
                # Extract a frame from the video as a thumbnail
                clip = VideoFileClip(file_full_path)
                file_full_path = file_full_path.replace('.mov', '.png')
                clip.save_frame(file_full_path, t=0.5)  # save frame at 0.5 seconds
            elif type_.lower() == 'pdf':
                # Convert the first page of the PDF to a thumbnail
                images = convert_from_path(file_full_path)
                file_full_path = file_full_path.replace('.pdf', '.png')
                images[0].save(file_full_path, 'PNG')

            # Create the QPixmap from the full path
            pixmap = QPixmap(file_full_path)
            # Scale the pixmap to the icon size while maintaining aspect ratio
            pixmap = pixmap.scaled(QSize(150, 150), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            icon = QIcon(pixmap)

            # Create a QListWidgetItem, set its icon, and provide a size hint to ensure the text is visible
            item = QListWidgetItem(icon, name)
            # Set a fixed size for the QListWidgetItem with some extra space for the text
            item.setSizeHint(QSize(200, 200))  # Adjust the width as necessary to fit the text

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

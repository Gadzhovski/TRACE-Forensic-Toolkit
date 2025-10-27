import datetime
import io
import os
import struct
from concurrent.futures import ThreadPoolExecutor

import cv2
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
        self.allocation_map = []  # Map of allocated disk regions to skip during carving
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
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.resizeEvent = self.handle_resize_event

        self.list_widget = self.create_list_widget()

        self.fileTypeLayout = QHBoxLayout()
        self.fileTypes = {"All": QCheckBox("All"), "PDF": QCheckBox("PDF"), "JPG": QCheckBox("JPG"),
                          "PNG": QCheckBox("PNG"), "GIF": QCheckBox("GIF"), "WAV": QCheckBox("WAV"),
                          "MOV": QCheckBox("MOV"), "WMV": QCheckBox("WMV"), "ZIP": QCheckBox("ZIP"),
                          'BMP': QCheckBox("BMP")}

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
        table_widget.setColumnCount(6)  # Updated to include the 'Id' column
        table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        table_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table_widget.setSortingEnabled(True)

        # Include 'Id' as the first header
        table_widget.setHorizontalHeaderLabels(['Id', 'Name', 'Size', 'Type', 'Modification Date', 'File Path'])
        table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        table_widget.customContextMenuRequested.connect(self.open_context_menu)

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

        # Ensure the 'carved_files' and 'thumbnails' directories exist
        if not os.path.exists("carved_files"):
            os.makedirs("carved_files")
        thumbnail_folder = os.path.join("carved_files", "thumbnails")
        if not os.path.exists(thumbnail_folder):
            os.makedirs(thumbnail_folder)

        # Build allocation map for all partitions to skip allocated files
        print("Building allocation map for allocated files...")
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
                    print(f"  Partition at offset {start_offset}: {len(partition_map)} allocated regions")
            else:
                # No partitions, try offset 0 (single filesystem)
                if self.image_handler.has_filesystem(0):
                    partition_map = self.image_handler.build_allocation_map(0)
                    self.allocation_map.extend(partition_map)
                    print(f"  Single filesystem: {len(partition_map)} allocated regions")

            # Sort the combined allocation map
            self.allocation_map.sort(key=lambda x: x[0])
            print(f"Total allocated regions to skip: {len(self.allocation_map)}")

        except Exception as e:
            print(f"Warning: Could not build allocation map: {e}")
            print("Will carve from entire disk (may include duplicates)")
            self.allocation_map = []

        selected_file_types = [fileType.lower() for fileType, checkbox in self.fileTypes.items() if
                               checkbox.isChecked()]
        self.executor.submit(self.carve_files, selected_file_types)

    def stop_carving(self):
        self.executor.shutdown(wait=True)  # Properly shutdown the executor
        self.start_button.setEnabled(True)  # Re-enable the start button
        self.stop_button.setEnabled(False)  # Disable the stop button

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
                return True
            return True
        except (IOError, UnidentifiedImageError, PdfReadError, ValueError) as e:
            print(f"Error validating file of type {file_type}: {str(e)}")
            return False

    def carve_pdf_files(self, chunk, global_offset):
        pdf_start_signature = b'%PDF-'
        pdf_linearization_signature = b'/Linearized'
        pdf_end_signature = b'%%EOF'
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
                        if self.is_valid_file(pdf_content, 'pdf'):
                            self.save_file(pdf_content, 'pdf', global_offset + start_index, file_size)
                            offset = start_index + file_size
                            continue
                    except ValueError:
                        pass
            end_index = chunk.find(pdf_end_signature, start_index)
            if end_index != -1:
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]
                if self.is_valid_file(pdf_content, 'pdf'):
                    self.save_file(pdf_content, 'pdf', global_offset + start_index, end_index - start_index)
                offset = end_index
            else:
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

    def carve_wmv_files(self, chunk, offset):
        # Define ASF header signature
        asf_header_signature = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'

        current_offset = 0

        while current_offset < len(chunk):
            # Search for ASF header
            start_index = chunk.find(asf_header_signature, current_offset)
            if start_index == -1:
                break

            # Find the file properties object header within the first 512 bytes of the file
            max_search_size = min(start_index + 512, len(chunk))
            file_properties_header = b'\xA1\xDC\xAB\x8C\x47\xA9\xCF\x11\x8E\xE4\x00\xC0\x0C\x20\x53\x65'
            file_properties_index = chunk.find(file_properties_header, start_index, max_search_size)
            if file_properties_index == -1:
                current_offset = start_index + 1
                continue

            # Extract the file size located at offset 40 within the object
            file_size_offset = file_properties_index + 40
            file_size_bytes = chunk[file_size_offset:file_size_offset + 8]
            file_size = int.from_bytes(file_size_bytes, byteorder='little')

            # Calculate end index based on file size
            end_index = start_index + file_size

            # Extract WMV content
            wmv_content = chunk[start_index:end_index]

            # Save the WMV content directly into the carved_files directory
            self.save_file(wmv_content, 'wmv', 'carved_files', start_index + offset)
            current_offset = end_index

    def carve_zip_files(self, chunk, global_offset):
        # Define ZIP header signatures
        local_file_header_signature = b'\x50\x4b\x03\x04'
        end_of_central_dir_signature = b'\x50\x4b\x05\x06'

        current_pos = 0
        zip_file_parts = []  # List to hold all parts of the ZIP file

        while current_pos < len(chunk):
            # Search for local file header
            local_header_index = chunk.find(local_file_header_signature, current_pos)
            if local_header_index == -1:
                break

            # Extract compressed size from local file header
            compressed_size = struct.unpack("<I", chunk[local_header_index + 18:local_header_index + 22])[0]

            # Calculate next local file header index
            next_local_header_index = local_header_index + 30 + compressed_size

            # Extract file content
            file_content = chunk[local_header_index:next_local_header_index]
            zip_file_parts.append(file_content)  # Add the file content to the ZIP parts list

            # Move to next local file header
            current_pos = next_local_header_index

        # Now, find and append the Central Directory and End of Central Directory Record
        end_central_dir_index = chunk.find(end_of_central_dir_signature, current_pos)
        if end_central_dir_index != -1:
            # Extract comment length and calculate the total end of the ZIP file structure
            comment_length = struct.unpack("<H", chunk[end_central_dir_index + 20:end_central_dir_index + 22])[0]
            zip_end = end_central_dir_index + 22 + comment_length

            # Extract the Central Directory and End of Central Directory Record
            zip_file_structure = chunk[current_pos:zip_end]
            zip_file_parts.append(zip_file_structure)  # Add this to the ZIP parts list

        # Combine all parts into a single ZIP file content
        if zip_file_parts:
            complete_zip_file_content = b''.join(zip_file_parts)
            self.save_file(complete_zip_file_content, 'zip', 'carved_files', global_offset)

        return None

    def carve_bmp_files(self, chunk, offset):
        bmp_start_signature = b'BM'  # BMP files start with 'BM'
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
                self.save_file(bmp_content, 'bmp', 'carved_files', start_index + offset)
                current_offset = start_index + bmp_file_size  # Move past this BMP file
            else:
                break  # The BMP file exceeds the chunk boundary, stop processing

        # Return if more data is needed or if processing is complete
        return None

    def carve_files(self, selected_file_types):
        try:
            self.stop_carving = False
            chunk_size = 1024 * 1024 * 100
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

                chunk = self.image_handler.read(offset, chunk_size)
                if not chunk:
                    break

                if self.stop_carving:
                    self.stop_carving = False
                    self.start_button.setEnabled(True)
                    self.stop_button.setEnabled(False)
                    print(f"Carving stopped. Processed {chunks_processed} unallocated chunks, skipped {chunks_skipped} allocated chunks")
                    return

                # Call the carve function for each selected file type
                for file_type in selected_file_types:
                    if file_type == 'all':
                        self.carve_wav_files(chunk, offset)
                        self.carve_mov_files(chunk, offset)
                        self.carve_pdf_files(chunk, offset)
                        self.carve_jpg_files(chunk, offset)
                        self.carve_gif_files(chunk, offset)
                        self.carve_png_files(chunk, offset)
                        self.carve_wmv_files(chunk, offset)
                        self.carve_zip_files(chunk, offset)
                        self.carve_bmp_files(chunk, offset)
                    elif file_type == 'wav':
                        self.carve_wav_files(chunk, offset)
                    elif file_type == 'mov':
                        self.carve_mov_files(chunk, offset)
                    elif file_type == 'pdf':
                        self.carve_pdf_files(chunk, offset)
                    elif file_type == 'jpg':
                        self.carve_jpg_files(chunk, offset)
                    elif file_type == 'gif':
                        self.carve_gif_files(chunk, offset)
                    elif file_type == 'png':
                        self.carve_png_files(chunk, offset)
                    elif file_type == 'wmv':
                        self.carve_wmv_files(chunk, offset)
                    elif file_type == 'zip':
                        self.carve_zip_files(chunk, offset)
                    elif file_type == 'bmp':
                        self.carve_bmp_files(chunk, offset)

                offset += chunk_size

            print(f"Carving complete. Processed {chunks_processed} unallocated chunks, skipped {chunks_skipped} allocated chunks")
        finally:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def save_file(self, file_content, file_type, file_path, offset):
        # Ensure the 'carved_files' directory exists
        if not os.path.exists("carved_files"):
            os.makedirs("carved_files")

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

        # Set Id column manually
        self.table_widget.setItem(row, 0, QTableWidgetItem(str(row + 1)))  # Setting the 'Id' field
        self.table_widget.setItem(row, 1, QTableWidgetItem(name))
        self.table_widget.setItem(row, 2, NumericTableWidgetItem(readable_size))
        self.table_widget.setItem(row, 3, QTableWidgetItem(type_))
        self.table_widget.setItem(row, 4, QTableWidgetItem(modification_date))
        self.table_widget.setItem(row, 5, QTableWidgetItem(file_path))

        # Set column resize modes
        header = self.table_widget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # Id column fixed width
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Name column stretches dynamically
        header.setSectionResizeMode(2, QHeaderView.Fixed)  # Size column fixed width
        header.setSectionResizeMode(3, QHeaderView.Fixed)  # Type column fixed width
        header.setSectionResizeMode(4, QHeaderView.Fixed)  # Modification Date column fixed width
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # File Path column stretches dynamically

        # Set fixed widths for non-stretch columns
        self.table_widget.setColumnWidth(0, 30)  # Id column width
        self.table_widget.setColumnWidth(2, 70)  # Size column width
        self.table_widget.setColumnWidth(3, 50)  # Type column width
        self.table_widget.setColumnWidth(4, 130)  # Modification Date column width

        # Only proceed if the file type is one of the supported image or video formats
        if type_.lower() in ['jpg', 'jpeg', 'png', 'gif', 'mov', 'pdf', 'wmv', 'bmp']:
            file_full_path = os.path.join("carved_files", name)
            thumbnail_folder = os.path.join("carved_files", "thumbnails")  # Folder to save thumbnails

            if not os.path.exists(thumbnail_folder):
                os.makedirs(thumbnail_folder)  # Create the thumbnail folder if it doesn't exist

            if type_.lower() == 'mov':
                thumbnail_path = os.path.join(thumbnail_folder, name.replace('.mov', '.png'))
                with VideoFileClip(file_full_path) as clip:
                    clip.save_frame(thumbnail_path, t=0.5)  # save frame at 0.5 seconds
                pixmap = QPixmap(thumbnail_path)

            elif type_.lower() == 'pdf':
                # Convert the first page of the PDF to a thumbnail
                images = convert_from_path(file_full_path)
                thumbnail_path = os.path.join(thumbnail_folder, name.replace('.pdf', '.png'))
                images[0].save(thumbnail_path, 'PNG')
                # Create the QPixmap from the full path
                pixmap = QPixmap(thumbnail_path)

            elif type_.lower() == 'wmv':
                capture = cv2.VideoCapture(file_full_path)
                success, image = capture.read()
                capture.release()  # Release the capture object explicitly
                if success:
                    thumbnail_path = os.path.join(thumbnail_folder, name.replace('.wmv', '.png'))
                    cv2.imwrite(thumbnail_path, image)
                    pixmap = QPixmap(thumbnail_path)
                else:
                    print("Failed to extract thumbnail from WMV file")

            else:
                # For image files, use the original file path
                thumbnail_path = file_full_path
                pixmap = QPixmap(thumbnail_path)

            # Center-crop to perfect square for modern uniform gallery look
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

    def handle_resize_event(self, event):
        # Calculate total width of the table
        total_width = self.table_widget.width()

        # Fixed columns: Id, Size, Type, Modification Date
        fixed_width = (self.table_widget.columnWidth(0) +  # Id
                       self.table_widget.columnWidth(2) +  # Size
                       self.table_widget.columnWidth(3) +  # Type
                       self.table_widget.columnWidth(4))  # Modification Date

        # Remaining space for dynamic columns
        remaining_width = total_width - fixed_width

        # Allocate remaining space proportionally
        self.table_widget.setColumnWidth(1, remaining_width // 2)  # Name column
        self.table_widget.setColumnWidth(5, remaining_width // 2)  # File Path column

        super(QTableWidget, self.table_widget).resizeEvent(event)

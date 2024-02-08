import datetime
import io
import os
from concurrent.futures import ThreadPoolExecutor

import olefile
import xlrd
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError
from PySide6.QtCore import QSize, QUrl
from PySide6.QtCore import Qt
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QAction, QDesktopServices
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QStyle
from PySide6.QtWidgets import QMenu
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QTabWidget


class FileCarvingWidget(QWidget):
    file_carved = Signal(str, str, str, str, str)  # Unified signal for file carving

    def __init__(self, parent=None):
        super().__init__(parent)
        self.image_handler = None
        self.executor = ThreadPoolExecutor(max_workers=4)  # ThreadPoolExecutor for background tasks
        self.init_ui()
        self.carved_files = []

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.info_label = QLabel("Ready to start file carving.")
        self.table_widget = self.create_table_widget()
        self.list_widget = self.create_list_widget()
        self.carve_button, self.stop_button = self.create_control_buttons()

        self.layout.addWidget(self.info_label)
        self.layout.addWidget(self.tab_widget)
        self.layout.addWidget(self.carve_button)
        self.layout.addWidget(self.stop_button)

        self.file_carved.connect(self.display_carved_file)

    def create_table_widget(self):
        table_widget = QTableWidget()
        table_widget.setColumnCount(5)
        table_widget.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modification Date', 'File Path'])
        table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        table_widget.customContextMenuRequested.connect(self.open_context_menu)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(table_widget, "Table")
        return table_widget

    def create_list_widget(self):
        list_widget = QListWidget()
        list_widget.setViewMode(QListWidget.IconMode)

        list_widget.setIconSize(QSize(100, 100))
        list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        list_widget.customContextMenuRequested.connect(self.open_context_menu)

        self.tab_widget.addTab(list_widget, "Thumbnails")
        return list_widget

    def create_control_buttons(self):
        carve_button = QPushButton("Start Carving")
        carve_button.clicked.connect(self.start_carving)

        stop_button = QPushButton("Stop Carving")
        stop_button.clicked.connect(self.stop_carving)
        stop_button.setEnabled(False)

        return carve_button, stop_button

    def start_carving(self):
        self.carve_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.executor.submit(self.carve_files)  # Launch carving in a background thread

    def stop_carving(self):
        self.executor.shutdown(wait=False)
        self.carve_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self.info_label.setText("Ready to start file carving.")
        self.carve_button.setEnabled(True)

    def open_context_menu(self, position):
        menu = QMenu()
        open_location_action = QAction("Open File Location")
        open_location_action.triggered.connect(self.open_file_location)

        menu.addAction(open_location_action)
        menu.exec_(self.table_widget.viewport().mapToGlobal(position))

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
        self.carve_button.setEnabled(False)
        self.carve_button.clicked.connect(self.start_carving_thread)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_carving_thread)

    def start_carving_thread(self):
        self.carve_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Launch carving in a background thread
        self.executor.submit(self.carve_files)

    def stop_carving_thread(self):
        self.executor.shutdown(wait=False)
        self.carve_button.setEnabled(True)
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

    # def is_valid_file(self, data, file_type):
    #     return True

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

    def carve_pdf_files(self, chunk):
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
                    file_name = f"carved_{start_index}.pdf"
                    file_path = os.path.join("carved_files", file_name)
                    self.save_file(pdf_content, 'pdf', file_path)

                # Update offset to search for the next PDF file after this EOF
                offset = end_index
            else:
                # If we don't find an EOF, move to the next byte and try again
                # This simplistic approach may need refinement for handling files spanning chunks
                offset = start_index + 1

    def carve_wav_files(self, chunk):
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
                file_name = f"carved_{offset + start_index}.wav"
                file_path = os.path.join("carved_files", file_name)
                self.save_file(wav_content, 'wav', file_path)

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
            file_name = f"carved_{mov_file_offset}.mov"
            file_path = os.path.join("carved_files", file_name)
            self.save_file(mov_data, 'mov', file_path)

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
                file_name = f"carved_{global_offset + start_index}.xls"
                file_path = os.path.join("carved_files", file_name)
                self.save_file(xls_data, 'xls', file_path)

            offset = end_index

    def carve_jpg_files(self, chunk):
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
                    file_name = f"carved_{offset + start_index}.jpg"
                    file_path = os.path.join("carved_files", file_name)
                    self.save_file(jpg_content, 'jpg', file_path)

                offset = end_index + len(jpg_end_signature)
            else:
                offset = start_index + 1  # Continue searching

    def carve_gif_files(self, chunk):
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
                    file_name = f"carved_{offset + start_index}.gif"
                    file_path = os.path.join("carved_files", file_name)
                    self.save_file(gif_content, 'gif', file_path)

                offset = end_index + len(gif_end_signature)
            else:
                offset = start_index + 1

    def carve_png_files(self, chunk):
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
                    file_name = f"carved_{offset + start_index}.png"
                    file_path = os.path.join("carved_files", file_name)
                    self.save_file(png_content, 'png', file_path)

                offset = end_index + len(png_end_signature)
            else:
                offset = start_index + 1

    def carve_files(self):
        self.stop_carving = False
        chunk_size = 1024 * 1024 * 100
        offset = 0

        while offset < self.image_handler.get_size():
            chunk = self.image_handler.read(offset, chunk_size)
            if not chunk:
                break

            if self.stop_carving:
                self.stop_carving = False
                self.carve_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return

            # Call the carving functions for each file type
            self.carve_wav_files(chunk)
            self.carve_mov_files(chunk, offset)
            self.carve_pdf_files(chunk)
            self.carve_xls_files(chunk, offset)
            self.carve_jpg_files(chunk)
            self.carve_gif_files(chunk)
            self.carve_png_files(chunk)
            offset += chunk_size

    def save_file(self, file_content, file_type, file_path):

        with open(file_path, "wb") as f:
            f.write(file_content)

        modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_name = os.path.basename(file_path)
        file_size = str(len(file_content))

        self.carved_files.append((file_name, file_size, file_type, file_path))
        self.file_carved.emit(file_name, file_size, file_type, modification_date, file_path)

    @Slot(str, str, str, str, str)
    def display_carved_file(self, name, size, type_, modification_date, file_path):
        row = self.table_widget.rowCount()
        self.table_widget.insertRow(row)
        self.table_widget.setItem(row, 0, QTableWidgetItem(name))
        self.table_widget.setItem(row, 1, QTableWidgetItem(size))
        self.table_widget.setItem(row, 2, QTableWidgetItem(type_))
        self.table_widget.setItem(row, 3, QTableWidgetItem(modification_date))
        self.table_widget.setItem(row, 4, QTableWidgetItem(file_path))
        self.table_widget.setColumnWidth(0, 250)
        self.table_widget.setColumnWidth(1, 100)
        self.table_widget.setColumnWidth(2, 90)
        self.table_widget.setColumnWidth(3, 150)
        self.table_widget.setColumnWidth(4, 300)

        file_full_path = os.path.join("carved_files", name)
        icon = QIcon(file_full_path) if os.path.exists(file_full_path) else self.style().standardIcon(
            QStyle.SP_FileIcon)
        item = QListWidgetItem(icon, name)
        self.list_widget.addItem(item)

        total_files = self.table_widget.rowCount()
        self.info_label.setText(f"Latest Carved File: {name}, Total Files: {total_files}")

    def clear(self):
        self.table_widget.setRowCount(0)
        self.list_widget.clear()
        self.carved_files.clear()
        self.info_label.setText("Ready to start file carving.")
        self.carve_button.setEnabled(True)
        self.stop_button.setEnabled(False)

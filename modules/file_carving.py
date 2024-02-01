import io
import os
import threading
import datetime
import re

from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError
from PySide6.QtCore import QSize, QUrl
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QAction, QDesktopServices
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QStyle
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QTabWidget
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMenu


class FileCarvingWidget(QWidget):
    file_carved = Signal(str, str, str, str, str)  # Add two more str for date and path

    def __init__(self, parent=None):
        super(FileCarvingWidget, self).__init__(parent)
        self.image_handler = None
        self.init_ui()
        self.carved_files = []
        self.file_carved.connect(self.display_carved_file)
        self.stop_carving = False  # flag to determine when to stop carving
        self.carving_threads = []

    def init_ui(self):
        self.layout = QVBoxLayout(self)  # Initialize self.layout as a QVBoxLayout instance
        self.info_label = QLabel("Ready to start file carving.")
        self.layout.addWidget(self.info_label)
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)

        self.table_widget = QTableWidget()
        # Add custom context menu to the table widget
        self.table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_widget.customContextMenuRequested.connect(self.open_table_context_menu)

        self.setup_table()
        self.tab_widget.addTab(self.table_widget, "Table")

        self.list_widget = QListWidget()
        # Add custom context menu to the list widget
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.open_list_context_menu)

        self.list_widget.setViewMode(QListWidget.IconMode)
        self.list_widget.setIconSize(QSize(100, 100))  # Set the size of the icons
        self.tab_widget.addTab(self.list_widget, "Thumbnails")

        self.carve_button = QPushButton("Start Carving")  # Define self.carve_button
        self.carve_button.setEnabled(False)
        self.carve_button.clicked.connect(self.start_carving_thread)

        # stop button
        self.stop_button = QPushButton("Stop Carving")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_carving_thread)

        self.layout.addWidget(self.carve_button)
        self.layout.addWidget(self.stop_button)

    def setup_table(self):
        self.table_widget.setColumnCount(5)
        self.table_widget.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modification Date', 'File Path'])
        self.table_widget.setRowCount(0)

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self.info_label.setText("Ready to start file carving.")
        self.carve_button.setEnabled(True)

    def open_table_context_menu(self, position):
        menu = QMenu()
        open_action = QAction("Open file location", self)
        open_action.triggered.connect(self.open_file_location_table)
        menu.addAction(open_action)
        menu.exec_(self.table_widget.mapToGlobal(position))

    def open_list_context_menu(self, position):
        menu = QMenu()
        open_action = QAction("Open file location", self)
        open_action.triggered.connect(self.open_file_location_list)
        menu.addAction(open_action)
        menu.exec_(self.list_widget.mapToGlobal(position))

    def open_file_location_table(self):
        current_item = self.table_widget.currentItem()
        if current_item:
            file_path = self.table_widget.item(current_item.row(), 4).text()  # Assuming file path is in the 5th column
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(file_path)))

    def open_file_location_list(self):
        current_item = self.list_widget.currentItem()
        if current_item:
            file_name = current_item.text()
            for file_info in self.carved_files:
                if file_info[0] == file_name:
                    file_path = file_info[3]  # The file path is now at index 3
                    QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(file_path)))
                    break

    def start_carving_thread(self):
        self.carve_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        # Create multiple carving threads
        for _ in range(4):  # You can adjust the number of threads as needed
            carving_thread = threading.Thread(target=self.carve_files, daemon=True)
            self.carving_threads.append(carving_thread)
            carving_thread.start()

    def stop_carving_thread(self):
        self.stop_carving = True

    def is_valid_file(self, data, file_type):
        try:
            if file_type == 'wav':
                # Corrected check for a valid WAV file
                if data[0:4] == b'RIFF' and data[8:12] == b'WAVE':
                    return True
                return False

            # check for valid mov file
            elif file_type == 'mov':
                if data[0:4] == b'ftyp' and data[12:16] == b'qt  ':
                    return True
                return False
            elif file_type in ['jpg', 'gif']:
                Image.MAX_IMAGE_PIXELS = None
                Image.open(io.BytesIO(data)).verify()
            elif file_type == 'pdf':
                PdfReader(io.BytesIO(data))
            else:
                return False
            return True
        except (IOError, UnidentifiedImageError, PdfReadError, ValueError):
            return False

    def carve_pdf_files(self, chunk):
        pdf_start_signature = b'%PDF-'
        offset = 0
        while offset < len(chunk):
            # Step 1: Look for the header signature (%PDF)
            start_index = chunk.find(pdf_start_signature, offset)

            if start_index == -1:
                break

            # Step 2: Check for the version number [file offset 6-8]
            version = chunk[start_index + 5:start_index + 8].decode()

            # Step 3: If version no. > 1.1 go to Step 4
            if version > "1.1":
                offset = start_index + 8
                continue

            # Step 4: Search for the string "Linearized" in first few bytes of the file
            linearized_signature = b'Linearized'
            if linearized_signature in chunk[start_index:start_index + 100]:
                # Step 5: If it finds the string in Step 4, then length of the file is preceded by a "/L " character sequence
                length_index = chunk.find(b'/L ', start_index)
                if length_index != -1:
                    length = int(chunk[length_index + 3:length_index + 12])
                    pdf_content = chunk[start_index:start_index + length]
                    file_type = 'pdf'

                    # Check if it's a valid PDF
                    if self.is_valid_file(pdf_content, file_type):
                        file_name = f"carved_{self.pdf_carved_count}.pdf"
                        file_path = os.path.join("carved_files", file_name)
                        with open(file_path, "wb") as f:
                            f.write(pdf_content)

                        modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        self.carved_files.append((file_name, str(length), file_type, file_path))
                        self.file_carved.emit(file_name, str(length), file_type, modification_date, file_path)

                        self.pdf_carved_count += 1

                        if self.pdf_carved_count >= 100000:
                            return

                    offset = start_index + length
                else:
                    offset = start_index + 1  # Continue searching
            else:
                # Step 6: Use search algorithms to find footer signature (%%EOF)
                end_index = chunk.find(b'%%EOF', start_index)

                if end_index != -1:
                    pdf_content = chunk[start_index:end_index + 6]
                    file_type = 'pdf'

                    # Check if it's a valid PDF
                    if self.is_valid_file(pdf_content, file_type):
                        file_name = f"carved_{self.pdf_carved_count}.pdf"
                        file_path = os.path.join("carved_files", file_name)
                        with open(file_path, "wb") as f:
                            f.write(pdf_content)

                        modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        self.carved_files.append((file_name, str(len(pdf_content)), file_type, file_path))
                        self.file_carved.emit(file_name, str(len(pdf_content)), file_type, modification_date, file_path)

                        self.pdf_carved_count += 1

                        if self.pdf_carved_count >= 100000:
                            return

                    offset = end_index + 6  # Move offset to the end of the extracted PDF
                else:
                    offset = start_index + 1  # Continue searching

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
                # Handle cases where the WAV file extends beyond the current chunk
                # Append the remaining part of the WAV file in the next chunk to the extracted WAV file
                wav_content = chunk[start_index:]
                offset = len(chunk)
            else:
                wav_content = chunk[start_index:start_index + file_size]
                offset = start_index + file_size

            file_type = 'wav'

            if self.is_valid_file(wav_content, file_type):
                file_name = f"carved_{offset + start_index}.{file_type}"
                file_path = os.path.join("carved_files", file_name)
                with open(file_path, "ab") as f:  # Open the file in append mode
                    f.write(wav_content)

                modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                self.carved_files.append((file_name, str(len(wav_content)), file_type, file_path))
                self.file_carved.emit(file_name, str(len(wav_content)), file_type, modification_date, file_path)

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
            with open(file_path, "wb") as f:
                f.write(mov_data)

            modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.carved_files.append((file_name, str(mov_file_size), 'mov', file_path))
            self.file_carved.emit(file_name, str(mov_file_size), 'mov', modification_date, file_path)

    def carve_files(self):
        self.stop_carving = False
        print("Carving files...")
        signatures = {
            'jpg': {'start': b'\xFF\xD8\xFF', 'end': b'\xFF\xD9'},
            'gif': {'start': b'\x47\x49\x46\x38', 'end': b'\x00\x3B'},
            'pdf': {'start': b'%PDF-', 'end': b'%%EOF'},  # PDF start and end signatures
            'wav': {'start': b'RIFF', 'end': b'WAVE'},  # WAV start and end signatures
            'mov': {'start': b'\x00\x00\x00\x14ftypqt  ', 'end': None},
        }
        chunk_size = 1024 * 1024 * 100
        offset = 0
        ongoing_carvings = {}
        self.pdf_carved_count = 0
        self.ongoing_pdf_carving = b''

        output_dir = "carved_files"

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)

        while offset < self.image_handler.get_size():
            chunk = self.image_handler.read(offset, chunk_size)
            if not chunk:
                break

            if self.stop_carving:
                self.stop_carving = False
                self.carve_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return

            # Check for WAV start signatures in the chunk
            wav_start_indices = [m.start() for m in re.finditer(b'RIFF', chunk)]

            if wav_start_indices:
                # Call the WAV carving function
                self.carve_wav_files(chunk)

            # Carve MOV files
            self.carve_mov_files(chunk, offset)

            # Check for PDF start signatures in the chunk
            self.carve_pdf_files(chunk)

            # Handle other file types as before
            for file_type, sig in signatures.items():
                start = 0
                while start < len(chunk):
                    # Check for ongoing carvings
                    if file_type in ongoing_carvings:
                        start_index = 0
                    else:
                        start_index = chunk.find(sig['start'], start)

                    if start_index == -1:
                        break

                    end_index = chunk.find(sig['end'], start_index)

                    if end_index != -1:
                        carved_file_content = ongoing_carvings.pop(file_type, b'') + chunk[start_index:end_index + len(
                            sig['end'])]

                        if self.is_valid_file(carved_file_content, file_type):
                            file_name = f"carved_{offset + start_index}.{file_type}"
                            file_path = os.path.join(output_dir, file_name)
                            with open(file_path, "wb") as f:
                                f.write(carved_file_content)

                            modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                            self.carved_files.append((file_name, str(len(carved_file_content)), file_type, file_path))
                            self.file_carved.emit(file_name, str(len(carved_file_content)), file_type,
                                                  modification_date,
                                                  file_path)

                        start = end_index + len(sig['end'])
                    else:
                        ongoing_carvings[file_type] = ongoing_carvings.get(file_type, b'') + chunk[start_index:]
                        start = start_index + len(sig['start'])

            offset += chunk_size
    # print finish when function is done
    print("Finish carving files")

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
        self.table_widget.clear()
        self.list_widget.clear()
        self.setup_table()
        self.carved_files = []
        self.info_label.setText("Ready to start file carving.")
        self.carve_button.setEnabled(True)

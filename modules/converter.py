import os
import subprocess
import sys

import pyewf
from PySide6.QtCore import Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QLabel, QFileDialog, QComboBox,
    QLineEdit, QHBoxLayout, QFormLayout
)
from PySide6.QtWidgets import (
    QMainWindow, QPushButton, QWidget, QRadioButton,
    QGroupBox, QVBoxLayout, QMessageBox, QStackedWidget
)
from modules.paths import resource_path


# Helper Function to List Drives (For Physical and Logical Drive Selection)
def list_drives():
    """Return a human-readable listing of the machine's physical drives.

    Dispatches on sys.platform, not os.name: os.name is 'posix' on both macOS
    and Linux and is never 'darwin', so the previous macOS branch was
    unreachable and macOS fell through to "Unsupported OS".
    """
    if sys.platform == "win32":
        # Get-CimInstance supersedes the deprecated Get-WmiObject, which is
        # absent from PowerShell 7+.
        command = ["powershell", "-NoProfile",
                   "Get-CimInstance Win32_DiskDrive | Select-Object Model, DeviceID"]
    elif sys.platform == "darwin":
        command = ["diskutil", "list"]
    elif sys.platform.startswith("linux"):
        command = ["lsblk", "-d", "-o", "NAME,MODEL,SIZE,TYPE"]
    else:
        raise Exception(f"Listing drives is not supported on this platform ({sys.platform})")

    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        raise Exception(f"Could not run '{command[0]}' - is it installed and on PATH?")
    if result.returncode != 0:
        raise Exception(f"Failed to list drives: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Convert E01 to DD/RAW")
        self.setGeometry(100, 100, 400, 400)
        # set logo
        self.setWindowIcon(QIcon(resource_path('Icons/logo.png')))

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.init_ui()

    def init_ui(self):
        self.select_source_dialog = SelectSourceDialog(self)
        self.stacked_widget.addWidget(self.select_source_dialog)

        self.conversion_widget = ConversionWidget(self)
        self.stacked_widget.addWidget(self.conversion_widget)

        self.drive_selection_widget = DriveSelectionWidget(self)
        self.stacked_widget.addWidget(self.drive_selection_widget)

        self.select_source_dialog.sourceSelected.connect(self.show_specific_widget)
        self.drive_selection_widget.backRequested.connect(self.show_select_source)
        self.conversion_widget.backRequested.connect(self.show_select_source)

    def show_specific_widget(self, widget_name):
        if widget_name == "conversion":
            self.stacked_widget.setCurrentWidget(self.conversion_widget)
        elif widget_name == "folder_contents":
            # Handle folder contents selection
            pass  # Placeholder for actual implementation
        elif widget_name == "physical_drive":
            self.stacked_widget.setCurrentWidget(self.drive_selection_widget)

        elif widget_name == "logical_drive":
            # Handle logical drive selection
            pass  # Placeholder for actual implementation

    def show_select_source(self):
        self.stacked_widget.setCurrentWidget(self.select_source_dialog)


# New Widget for Drive Selection
class DriveSelectionWidget(QWidget):
    backRequested = Signal()
    driveSelected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.drive_combo = QComboBox()
        try:
            for drive in list_drives().split('\n'):
                if drive.strip():
                    self.drive_combo.addItem(drive.strip())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to list drives: {e}")

        layout.addWidget(QLabel("Select Drive:"))
        layout.addWidget(self.drive_combo)

        select_button = QPushButton("Select")
        select_button.clicked.connect(self.on_select_clicked)
        layout.addWidget(select_button)

        back_button = QPushButton("Back")
        back_button.clicked.connect(lambda: self.backRequested.emit())
        layout.addWidget(back_button)

    def on_select_clicked(self):
        selected_drive = self.drive_combo.currentText()
        self.driveSelected.emit(selected_drive.split()[-1])  # Assuming the device ID is the last part


class SelectSourceDialog(QWidget):
    sourceSelected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)

        self.group_box = QGroupBox("Select the Source Type")
        self.layout.addWidget(self.group_box)

        self.radio_buttons_layout = QVBoxLayout()
        # Existing options
        self.image_file_radio = QRadioButton("Image File")
        # New source options
        self.physical_drive_radio = QRadioButton("Physical Drive (not implemented)")
        self.logical_drive_radio = QRadioButton("Logical Drive (not implemented)")
        self.contents_of_folder_radio = QRadioButton("Contents of a Folder (not implemented)")

        # Add the radio buttons to the layout
        self.radio_buttons_layout.addWidget(self.image_file_radio)
        self.radio_buttons_layout.addWidget(self.physical_drive_radio)
        self.radio_buttons_layout.addWidget(self.logical_drive_radio)
        self.radio_buttons_layout.addWidget(self.contents_of_folder_radio)
        self.group_box.setLayout(self.radio_buttons_layout)

        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self.on_next_clicked)
        self.layout.addWidget(self.next_button)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(lambda: self.window().close())
        self.layout.addWidget(self.close_button)

    def on_next_clicked(self):
        if self.image_file_radio.isChecked():
            self.sourceSelected.emit("conversion")
        elif self.contents_of_folder_radio.isChecked():
            self.sourceSelected.emit("folder_contents")
        elif self.physical_drive_radio.isChecked():
            self.sourceSelected.emit("physical_drive")
        elif self.logical_drive_radio.isChecked():
            self.sourceSelected.emit("logical_drive")


class ConversionWidget(QWidget):
    backRequested = Signal()  # Signal to request going back to the source selection

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setGeometry(100, 100, 400, 400)
        self.setWindowTitle("Convert E01 to DD/RAW")
        self.setWindowIcon(QIcon(resource_path('Icons/logo.png')))
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        form_layout = QFormLayout()
        self.input_line_edit = QLineEdit()
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)

        self.format_combo_box = QComboBox()
        self.format_combo_box.addItems(["DD", "RAW"])

        self.output_line_edit = QLineEdit()
        output_dir_button = QPushButton("Select Output Directory...")
        output_dir_button.clicked.connect(self.select_output_dir)

        form_layout.addRow(QLabel("Select E01 File:"), self.input_line_edit)
        form_layout.addRow(browse_button)
        form_layout.addRow(QLabel("Select Output Format:"), self.format_combo_box)
        form_layout.addRow(QLabel("Select Output Directory:"), self.output_line_edit)
        form_layout.addRow(output_dir_button)

        layout.addLayout(form_layout)

        # Buttons layout
        buttons_layout = QHBoxLayout()
        back_button = QPushButton("Back")
        back_button.clicked.connect(self.on_back_clicked)

        convert_button = QPushButton("Convert")
        convert_button.clicked.connect(self.convert)

        buttons_layout.addWidget(back_button)
        buttons_layout.addWidget(convert_button)

        layout.addLayout(buttons_layout)

    def on_back_clicked(self):
        # backRequested is declared above and connected by Main.init_ui, the
        # same way DriveSelectionWidget already does it. The previous
        # self.parent().parent() only resolved to Main by coincidence of the
        # current QStackedWidget nesting, so adding any wrapper widget would
        # have silently broken this button.
        self.backRequested.emit()

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select E01 File", "", "E01 Files (*.e01)")
        if filename:
            self.input_line_edit.setText(filename)

    def select_output_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_line_edit.setText(directory)

    def convert(self):
        input_path = self.input_line_edit.text()
        output_format = self.format_combo_box.currentText().lower()  # 'dd' or 'raw'
        output_dir = self.output_line_edit.text()

        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self, "Error", "The specified E01 file does not exist.")
            return

        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.warning(self, "Error", "The specified output directory does not exist.")
            return

        output_filename = f"{os.path.splitext(os.path.basename(input_path))[0]}.{output_format}"
        output_path = os.path.join(output_dir, output_filename)

        try:
            self.perform_conversion(input_path, output_path)
            QMessageBox.information(self, "Success", f"File has been successfully converted to {output_path}")
        except Exception as e:
            QMessageBox.critical(self, "Conversion Failed", f"An error occurred: {str(e)}")

    def perform_conversion(self, input_path, output_path):
        normalized_input_path = os.path.normpath(input_path)
        filenames = pyewf.glob(normalized_input_path)

        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        with open(output_path, 'wb') as output_file:
            buffer_size = ewf_handle.bytes_per_sector
            while True:
                data = ewf_handle.read(buffer_size)
                if not data:
                    break
                output_file.write(data)
        ewf_handle.close()

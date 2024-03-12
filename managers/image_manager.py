import os
import subprocess
from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QFileDialog, QMessageBox, QWidget


class ImageManager(QThread):
    operationCompleted = Signal(bool, str)  # Signal to indicate operation completion (both mounting and dismounting)
    showMessage = Signal(str, str)  # Signal to show a message (Title, Content)

    def __init__(self):
        super().__init__()
        self.operation = None
        self.image_path = None
        self.file_name = None

    def run(self):
        if self.operation == 'mount' and self.image_path:
            try:
                subprocess.Popen(['tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--mount', '--readonly',
                                  '--filename=' + self.image_path])
                self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully.")
            except Exception as e:
                self.operationCompleted.emit(False, f"Failed to mount the image. Error: {e}")
        elif self.operation == 'dismount':
            try:
                subprocess.run(['tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe', '--dismount'], check=True)
                self.operationCompleted.emit(True, f"Image was dismounted successfully.")
            except subprocess.CalledProcessError:
                self.operationCompleted.emit(False, "There is no image mounted.")

    def mount_image(self):
        """Attempt to mount an image after prompting the user to select one."""
        supported_formats = ("EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;"
                             "VHD Files (*.vhd);;VDI Files (*.vdi);;XVA Files (*.xva);;"
                             "VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow *.qcow2);;All Files (*)")
        valid_extensions = ['.e01', '.dd', '.aff4', '.vhd', '.vdi', '.xva', '.vmdk', '.ova', '.qcow', '.qcow2']

        while True:
            image_path, _ = QFileDialog.getOpenFileName(QWidget(None), "Select Disk Image", "", supported_formats)

            if not image_path:
                return  # No image was selected, so just exit the function

            file_extension = os.path.splitext(image_path)[1].lower()
            if file_extension in valid_extensions:
                break  # Exit the loop if a valid image was selected
            else:
                # Show an error message for an invalid file
                QMessageBox.warning(QWidget(None), "Invalid File Type", "The selected file is not a valid disk image.")

        # Normalize the path
        self.image_path = os.path.normpath(image_path)
        self.file_name = os.path.basename(self.image_path)
        self.operation = 'mount'
        self.start()

    def dismount_image(self):
        """Attempt to dismount the currently mounted image."""
        self.operation = 'dismount'
        self.start()

import os
import subprocess

from PySide6.QtCore import QThread, Signal


class ImageManager(QThread):
    operationCompleted = Signal(bool, str)  # Signal to indicate operation completion (both mounting and dismounting)

    def __init__(self, operation, image_path=None):
        super().__init__()
        self.operation = operation
        self.image_path = os.path.normpath(image_path) if image_path else None
        self.file_name = os.path.basename(self.image_path) if self.image_path else None

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
                self.operationCompleted.emit(False, "Failed to dismount the image.")

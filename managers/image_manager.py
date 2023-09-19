
import os
import subprocess
from PySide6.QtCore import QThread, Signal


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
                self.operationCompleted.emit(False, "Failed to dismount the image.")

    def mount_image(self, image_path):
        """Attempt to mount an image from the provided path."""
        if image_path:
            # Normalize the path
            self.image_path = os.path.normpath(image_path)
            self.file_name = os.path.basename(self.image_path)
            self.operation = 'mount'
            self.start()  # This will invoke the run method
        else:
            self.showMessage.emit("Image Mounting", "No image was selected.")

    def dismount_image(self):
        """Attempt to dismount the currently mounted image."""
        self.operation = 'dismount'
        self.start()  # This will invoke the run method

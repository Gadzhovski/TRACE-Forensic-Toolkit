import os
import time
import subprocess
import platform
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
        system = platform.system()
        if self.operation == 'mount' and self.image_path:
            try:
                if system == 'Darwin':  # macOS
                    self._mount_image_macos()
                elif system == 'Linux':  # Linux (including Kali)
                    self._mount_image_linux()
                elif system == 'Windows':  # Windows
                    self._mount_image_windows()
                else:
                    raise Exception("Unsupported Operating System")
            except Exception as e:
                self.operationCompleted.emit(False, f"Failed to mount the image. Error: {e}")
        elif self.operation == 'dismount':
            try:
                if system == 'Darwin':
                    self._dismount_image_macos()
                elif system == 'Linux':
                    self._dismount_image_linux()
                elif system == 'Windows':
                    self._dismount_image_windows()
                else:
                    raise Exception("Unsupported Operating System")
            except Exception as e:
                self.operationCompleted.emit(False, f"Failed to dismount the image. Error: {e}")

    def _mount_image_windows(self):
        """Mount image on Windows using Arsenal Image Mounter."""
        try:
            subprocess.Popen([
                'tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe',
                '--mount',
                '--readonly',
                '--filename=' + self.image_path
            ])
            self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully.")
        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on Windows. Error: {e}")

    def _mount_image_macos(self):
        """Mount image on macOS using hdiutil."""
        try:
            # Step 1: Attach the image without mounting it
            attach_output = subprocess.check_output(
                ['hdiutil', 'attach', '-imagekey', 'diskimage-class=CRawDiskImage', '-nomount', self.image_path],
                stderr=subprocess.STDOUT
            )

            # Step 2: Add a short delay to ensure the system has time to process the attachment
            time.sleep(1)  # Delay for 1 second

            # Step 3: Extract the disk identifier (e.g., /dev/disk4) from the output
            lines = attach_output.decode().strip().splitlines()
            disk_identifier = None

            for line in lines:
                if line.startswith('/dev/disk'):
                    disk_identifier = line.split()[0]
                    break

            if not disk_identifier:
                raise Exception("Failed to find disk identifier after attaching the image.")

            # Step 4: Mount the disk using the identifier
            mount_output = subprocess.check_output(
                ['hdiutil', 'mount', disk_identifier],
                stderr=subprocess.STDOUT
            )

            # Step 5: Extract the mount point (e.g., /Volumes/LABEL2)
            lines = mount_output.decode().strip().splitlines()
            mount_point = None

            for line in lines:
                if line.startswith('/dev/') and '\t' in line:
                    mount_point = line.split('\t')[1]
                    break

            if mount_point:
                # Emit success with the mount point
                self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully at {mount_point}.")
            else:
                self.operationCompleted.emit(False, f"Image {self.file_name} mounted, but no volumes were detected.")

        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on macOS. Error: {e.output.decode()}")

    def _mount_image_linux(self):
        """Mount image on Linux using appropriate tools."""
        try:
            if self.image_path.lower().endswith('.e01'):
                # Use ewfmount for .e01 images
                ewf_mount_dir = '/mnt/ewf'
                os.makedirs(ewf_mount_dir, exist_ok=True)
                subprocess.run(['sudo', 'ewfmount', self.image_path, ewf_mount_dir], check=True)

                # Get the partition table info using fdisk
                fdisk_output = subprocess.check_output(['fdisk', '-l', os.path.join(ewf_mount_dir, 'ewf1')], text=True)

                # Find the partition start sector
                partition_start_sector = None
                for line in fdisk_output.splitlines():
                    if '/dev/' in line and not line.startswith('Disk '):
                        # Assuming you want the first partition listed
                        partition_start_sector = int(line.split()[1])
                        break

                if partition_start_sector is None:
                    raise Exception("Failed to find partition start sector in the EWF image.")

                # Calculate the byte offset
                byte_offset = partition_start_sector * 512

                # Mount the partition using the calculated offset
                mount_dir = '/mnt/disk_image'
                os.makedirs(mount_dir, exist_ok=True)
                subprocess.run(
                    ['sudo', 'mount', '-o', f'ro,loop,offset={byte_offset}', os.path.join(ewf_mount_dir, 'ewf1'),
                     mount_dir], check=True)

            else:
                # Use mount for .dd images and other raw formats
                mount_dir = '/mnt/disk_image'
                os.makedirs(mount_dir, exist_ok=True)
                subprocess.run(['sudo', 'mount', '-o', 'loop,ro', self.image_path, mount_dir], check=True)

            self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully.")
        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on Linux. Error: {e}")
        except Exception as e:
            self.operationCompleted.emit(False, f"An unexpected error occurred: {str(e)}")

    def _dismount_image_linux(self):
        """Dismount image on Linux."""
        try:
            # Attempt to unmount the disk image
            subprocess.run(['sudo', 'umount', '/mnt/disk_image'], check=True)
            subprocess.run(['sudo', 'umount', '/mnt/ewf'], check=True)
            self.operationCompleted.emit(True, "Image was dismounted successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to dismount the image on Linux. Error: {e}")

    def _dismount_image_macos(self):
        """Dismount image on macOS using hdiutil."""
        try:
            # Get the list of currently mounted disk images
            info_output = subprocess.check_output(['hdiutil', 'info'], stderr=subprocess.STDOUT).decode()
            lines = info_output.splitlines()
            mounted_disks = []
            current_image_path = None

            # Parse the output to find the disk identifier for the given image path
            for line in lines:
                if 'image-path' in line:
                    current_image_path = line.split(': ')[1].strip()
                elif line.startswith('/dev/disk') and current_image_path == self.image_path:
                    disk_identifier = line.split()[0]
                    mounted_disks.append(disk_identifier)
                    current_image_path = None  # Reset after finding the corresponding disk

            if not mounted_disks:
                raise Exception("No mounted images found for the specified image.")

            # Attempt to dismount all found disk identifiers
            for disk_identifier in mounted_disks:
                try:
                    subprocess.run(['hdiutil', 'detach', disk_identifier], check=True)
                except subprocess.CalledProcessError:
                    # If normal detach fails, attempt a forced detach
                    subprocess.run(['hdiutil', 'detach', '-force', disk_identifier], check=True)

            self.operationCompleted.emit(True, "Image was dismounted successfully.")

        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to dismount the image on macOS. Error: {e.output.decode()}")
        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to dismount the image on macOS. Error: {str(e)}")

    def _dismount_image_windows(self):
        """Dismount image on Windows using Arsenal Image Mounter."""
        try:
            subprocess.run([
                'tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe',
                '--dismount'
            ], check=True)
            self.operationCompleted.emit(True, "Image was dismounted successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to dismount the image on Windows. Error: {e}")

    def dismount_image(self):
        """Attempt to dismount the currently mounted image."""
        self.operation = 'dismount'
        self.start()

    def mount_image(self):
        """Attempt to mount an image after prompting the user to select one."""
        system = platform.system()

        if system == 'Darwin':  # macOS
            # Only allow .raw and .dd files on macOS
            supported_formats = "Raw Files (*.raw *.dd);;All Files (*)"
            valid_extensions = ['.raw', '.dd']
        else:
            # Original behavior for other operating systems
            supported_formats = (
                "EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;"
                "VHD Files (*.vhd);;VDI Files (*.vdi);;XVA Files (*.xva);;"
                "VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow *.qcow2);;All Files (*)"
            )
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

from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QPushButton, QApplication, QProgressBar, QHBoxLayout,
                               QFileDialog, QTextEdit)
from PySide6.QtCore import QThread, Signal, Qt


class HashCalculationThread(QThread):
    hashCalculated = Signal(dict)  # Signal for hash results
    progressUpdated = Signal(float)  # Signal for progress updates (percentage 0-100)

    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        self.isRunning = True

    def run(self):
        try:
            # Pass a progress callback to update the progress bar
            hash_results = self.image_handler.calculate_hashes(
                progress_callback=self.update_progress
            )
            if self.isRunning:  # Check if we're still running before emitting the signal
                self.hashCalculated.emit(hash_results)
        except Exception as e:
            print(f"Error in hash calculation thread: {e}")
            if self.isRunning:
                self.hashCalculated.emit({})  # Empty dict indicates error

    def update_progress(self, current, total):
        """Handle progress updates safely with large values."""
        try:
            if total > 0 and self.isRunning:
                # Convert to float to avoid overflow and limit to 0-100 range
                percentage = min(100.0, (float(current) / float(total)) * 100.0)
                self.progressUpdated.emit(percentage)
        except Exception as e:
            print(f"Progress update error: {e}")

    def stop(self):
        """Safely stop the thread."""
        self.isRunning = False


class VerificationWidget(QWidget):
    def __init__(self, image_handler, parent=None):
        super().__init__(parent)
        self.image_handler = image_handler
        self.thread = None
        self.setWindowTitle("Trace - Image Verification")
        self.setWindowIcon(QIcon('Icons/logo.png'))
        self.setGeometry(100, 100, 750, 400)  # Adjust size for better layout
        self._verified = False  # Track verification status

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        self.software_info = QLabel("Trace - Forensic Analysis Tool", self)
        self.software_info.setObjectName("softwareInfoLabel")
        layout.addWidget(self.software_info)

        self.subtitle = QLabel("Image Hash Verification", self)
        self.subtitle.setObjectName("subtitleLabel")
        layout.addWidget(self.subtitle)

        self.hash_label = QTextEdit("Calculating hashes...")
        self.hash_label.setReadOnly(True)
        self.hash_label.setFont(QFont("Courier", 10))
        self.hash_label.setStyleSheet("""
            QTextEdit {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                color: #333;
                font-family: 'Courier';
            }
            QTextEdit::indicator:checked {
                background: #b0b0b0;
            }
        """)
        layout.addWidget(self.hash_label)

        progress_bar_container = QHBoxLayout()
        progress_bar_container.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)  # Set to 100 for percentage display
        self.progress_bar.setFixedWidth(400)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #05B8CC;
                width: 20px;
            }
        """)
        progress_bar_container.addWidget(self.progress_bar)
        progress_bar_container.addStretch()
        layout.addLayout(progress_bar_container)

        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save to Text File", self)
        self.save_button.setFixedWidth(150)
        self.save_button.clicked.connect(self.save_hash)
        self.save_button.setEnabled(False)
        button_layout.addWidget(self.save_button)

        self.copy_button = QPushButton("Copy", self)
        self.copy_button.setFixedWidth(150)
        self.copy_button.clicked.connect(self.copy_hash)
        self.copy_button.setEnabled(False)
        button_layout.addWidget(self.copy_button)

        self.close_button = QPushButton("Close", self)
        self.close_button.setFixedWidth(150)
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        layout.addLayout(button_layout)

        # Start hash calculation with a slight delay to allow the UI to initialize
        QApplication.processEvents()
        self.start_hash_calculation()

    def closeEvent(self, event):
        """Override closeEvent to properly clean up resources."""
        if self.thread and self.thread.isRunning():
            self.thread.stop()  # Tell thread to stop processing
            self.thread.wait(1000)  # Wait up to 1 second

            # If thread is still running, terminate it
            if self.thread.isRunning():
                self.thread.terminate()
                self.thread.wait()

        super().closeEvent(event)

    def save_hash(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Hash", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, 'w') as file:
                file.write(self.hash_label.toPlainText())

    def start_hash_calculation(self):
        # Clean up any previous thread
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait()

        self.thread = HashCalculationThread(self.image_handler)
        self.thread.hashCalculated.connect(self.on_hash_calculated)
        self.thread.progressUpdated.connect(self.update_progress)
        self.thread.start()

    def update_progress(self, percentage):
        """Update progress bar with the given percentage."""
        try:
            self.progress_bar.setValue(int(percentage))
            QApplication.processEvents()  # Keep UI responsive
        except Exception as e:
            print(f"Error updating progress bar: {e}")

    def on_hash_calculated(self, hash_results):
        """Process hash results and update UI."""
        try:
            # Set the progress bar to 100% complete
            self.progress_bar.setValue(100)

            if hash_results and 'computed_md5' in hash_results:
                verification_results = []

                computed_md5 = hash_results.get('computed_md5')
                computed_sha1 = hash_results.get('computed_sha1')
                computed_sha256 = hash_results.get('computed_sha256')

                # Check if the loaded image file is of E01 format
                if self.image_handler and self.image_handler.get_image_type() == "ewf":
                    stored_md5 = hash_results.get('stored_md5')
                    stored_sha1 = hash_results.get('stored_sha1')

                    # Compare the computed MD5 and SHA1 hashes with the stored hashes
                    md5_result = "Match" if computed_md5 == stored_md5 else "Mismatch"
                    sha1_result = "Match" if computed_sha1 == stored_sha1 else "Mismatch"

                    # Set verification status
                    self._verified = md5_result == "Match" or sha1_result == "Match"

                    verification_results.append(f"<b>Stored MD5:</b> {stored_md5 or 'N/A'}")
                    verification_results.append(f"<b>Computed MD5:</b> {computed_md5}")
                    verification_results.append(
                        f"<b>MD5 Verify result:</b> {md5_result}<br>")  # New line after MD5 verification result

                    verification_results.append(f"<b>Stored SHA1:</b> {stored_sha1 or 'N/A'}")
                    verification_results.append(f"<b>Computed SHA1:</b> {computed_sha1}")
                    verification_results.append(
                        f"<b>SHA1 Verify result:</b> {sha1_result}<br>")  # New line after SHA1 verification result

                else:  # For other image types, only display computed hashes
                    verification_results.append(f"<b>Computed MD5:</b> {computed_md5}")
                    verification_results.append(f"<b>Computed SHA1:</b> {computed_sha1}")

                # Display computed SHA256 hash for all image types
                verification_results.append(f"<b>Computed SHA256:</b> {computed_sha256}")

                # Convert size from bytes to megabytes
                size_bytes = hash_results.get('size')
                size_mb = size_bytes / (1024 * 1024)

                hash_info = "<br>".join(verification_results)
                hash_info += f"<br><br><b>Size:</b> {size_bytes} bytes ({size_mb:.2f} MB)<br><b>Path:</b> {hash_results.get('path')}"
                self.hash_label.setHtml(hash_info)
                self.save_button.setEnabled(True)
                self.copy_button.setEnabled(True)
            else:
                self.hash_label.setText("Error calculating hashes. Please ensure the image is accessible.")
        except Exception as e:
            print(f"Error processing hash results: {e}")
            self.hash_label.setText(f"Error processing results: {str(e)}")

    def copy_hash(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.hash_label.toPlainText())

    @property
    def is_verified(self):
        # Return the verification status property
        return self._verified

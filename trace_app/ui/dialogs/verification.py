import logging
from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QPushButton, QApplication, QProgressBar, QHBoxLayout,
                               QTextEdit)
from PySide6.QtCore import QThread, Signal, Qt
from trace_app.infra.paths import resource_path
from trace_app.infra.constants import BUTTON_WIDTH
from trace_app.ui import fonts
from trace_app.ui import icons

logger = logging.getLogger('TRACE.Verify')


class HashCalculationThread(QThread):
    hashCalculated = Signal(dict)  # Signal for hash results
    progressUpdated = Signal(float)  # Signal for progress updates (percentage 0-100)

    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        self.isRunning = True
        self._last_percent = -1

    def run(self):
        try:
            # Pass a progress callback to update the progress bar
            hash_results = self.image_handler.calculate_hashes(
                progress_callback=self.update_progress
            )
            if self.isRunning:  # Check if we're still running before emitting the signal
                self.hashCalculated.emit(hash_results)
        except Exception as e:
            logger.error(f"Error in hash calculation thread: {e}")
            if self.isRunning:
                self.hashCalculated.emit({})  # Empty dict indicates error

    def update_progress(self, current, total):
        """Report progress, at most once per whole percent.

        A 16 GB image is thousands of chunks; emitting on every one queued
        thousands of cross-thread signals to move a bar that only has a
        hundred positions.
        """
        try:
            if total > 0 and self.isRunning:
                # Convert to float to avoid overflow and limit to 0-100 range
                percentage = min(100.0, (float(current) / float(total)) * 100.0)
                if int(percentage) != self._last_percent:
                    self._last_percent = int(percentage)
                    self.progressUpdated.emit(percentage)
        except Exception as e:
            logger.error(f"Progress update error: {e}")

    def stop(self):
        """Safely stop the thread."""
        self.isRunning = False


class VerificationWidget(QWidget):
    def __init__(self, image_handler, parent=None, cached=None,
                 expected_md5=None):
        """Show hashes for `image_handler`.

        `cached` is a previous result for this same image, as returned by
        `results()`. Given one, the dialog renders it and does not recompute:
        hashing a multi-gigabyte image takes minutes, and doing it again on a
        second click to show the same numbers is the kind of wait that makes a
        tool feel broken.
        """
        super().__init__(parent)
        self.image_handler = image_handler
        self.thread = None
        self._results_html = None
        #: The digests themselves, as ImageHandler computed them. The rendered
        #: HTML above is for display; a case has to store real hash values, and
        #: it cannot store what this layer threw away.
        self._hash_results = None
        #: What the case already recorded for this image, if anything. A raw
        #: image has no internal hash to check against, so this is the only
        #: thing a second verification can compare with.
        self._expected_md5 = expected_md5
        self.setWindowTitle("Trace - Image Verification")
        self.setWindowIcon(icons.icon(icons.LOGO))
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
        self.hash_label.setFont(fonts.monospace(10))
        self.hash_label.setObjectName("hashResultBox")
        layout.addWidget(self.hash_label)

        progress_bar_container = QHBoxLayout()
        progress_bar_container.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)  # Set to 100 for percentage display
        self.progress_bar.setFixedWidth(360)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setObjectName("verifyProgress")
        progress_bar_container.addWidget(self.progress_bar)
        progress_bar_container.addStretch()
        layout.addLayout(progress_bar_container)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.close_button = QPushButton("Close", self)
        self.close_button.setFixedWidth(BUTTON_WIDTH)
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        # Stretch on both sides: with only one button left, right-aligning it
        # stranded it in the corner of a 750px dialog.
        button_layout.addStretch()
        layout.addLayout(button_layout)

        if cached:
            self._restore(cached)
        else:
            # Start hash calculation with a slight delay to allow the UI to
            # initialize
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
        """Update progress bar with the given percentage.

        No processEvents here. The hashing runs in a worker thread, so the
        event loop is already free; calling it by hand on every chunk only
        forced a full event pass thousands of times during a long hash.
        """
        try:
            self.progress_bar.setValue(int(percentage))
        except Exception as e:
            logger.error(f"Error updating progress bar: {e}")

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

                else:
                    # A raw image carries no hash of its own, so there is
                    # nothing inside it to verify against. If the case recorded
                    # one earlier, that is the comparison worth making --
                    # otherwise this run establishes the baseline. Previously
                    # _verified stayed False here forever, so a .dd could never
                    # show as verified no matter how many times it was checked.
                    verification_results.append(f"<b>Computed MD5:</b> {computed_md5}")
                    verification_results.append(f"<b>Computed SHA1:</b> {computed_sha1}")

                    if self._expected_md5:
                        matches = (computed_md5 or '').lower() == self._expected_md5.lower()
                        self._verified = matches
                        verification_results.append(
                            f"<b>Recorded MD5:</b> {self._expected_md5}")
                        verification_results.append(
                            "<b>Case comparison:</b> "
                            + ("Match" if matches else "MISMATCH — this is not "
                               "the file the case recorded")
                            + "<br>")
                    else:
                        verification_results.append(
                            "<b>Case comparison:</b> no hash was recorded "
                            "before, so this run establishes the baseline.<br>")

                # SHA-256 is only computed when the image stores no hashes of
                # its own, so there is nothing to show for a verified E01.
                if computed_sha256:
                    verification_results.append(
                        f"<b>Computed SHA256:</b> {computed_sha256}")

                # Convert size from bytes to megabytes
                size_bytes = hash_results.get('size')
                size_mb = size_bytes / (1024 * 1024)

                hash_info = "<br>".join(verification_results)
                hash_info += f"<br><br><b>Size:</b> {size_bytes} bytes ({size_mb:.2f} MB)<br><b>Path:</b> {hash_results.get('path')}"
                self.hash_label.setHtml(hash_info)
                self._results_html = hash_info
                self._hash_results = dict(hash_results)
            else:
                self.hash_label.setText("Error calculating hashes. Please ensure the image is accessible.")
        except Exception as e:
            logger.error(f"Error processing hash results: {e}")
            self.hash_label.setText(f"Error processing results: {str(e)}")

    def _restore(self, cached):
        """Render a previous run without touching the image again."""
        self._results_html = cached.get('html')
        self._verified = cached.get('verified', False)
        self._hash_results = cached.get('hashes')
        self.hash_label.setHtml(self._results_html or '')
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Verified earlier this session")

    def results(self):
        """The finished result, or None while it is still being computed.

        Returned as plain data so the caller can hold it per image and hand it
        back to a later dialog.
        """
        if self._results_html is None:
            return None
        return {'html': self._results_html, 'verified': self._verified,
                'hashes': self._hash_results}

    @property
    def is_verified(self):
        # Return the verification status property
        return self._verified

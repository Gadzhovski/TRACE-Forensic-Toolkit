"""Streaming access to a file inside a disk image.

A QIODevice that reads on demand from a pytsk3 file object, so media can be
played without first loading the whole file into memory. This is I/O plumbing
over pytsk3, not a widget, which is why it lives in core rather than ui.
"""

import logging

from PySide6.QtCore import QIODevice

logger = logging.getLogger('TRACE.StreamDevice')


class PyTsk3StreamDevice(QIODevice):
    """Custom QIODevice that streams data directly from pytsk3 file objects. """

    def __init__(self, file_obj, file_size, parent=None):
        """Initialize the stream device. """
        super().__init__(parent)
        self.file_obj = file_obj
        self.file_size = file_size
        self.current_position = 0
        self._is_closed = False  # Track if device has been closed

    def size(self):
        """Return the total size of the media file."""
        return self.file_size

    def isSequential(self):
        """Return False to indicate this device supports seeking."""
        return False

    def seek(self, pos):
        """Seek to a specific position in the file."""
        if 0 <= pos <= self.file_size:
            self.current_position = pos
            # Call parent seek to update internal state
            return super().seek(pos)
        return False

    def pos(self):
        """Return the current position in the file."""
        return self.current_position

    def atEnd(self):
        """Return True if at end of file."""
        return self.current_position >= self.file_size

    def readData(self, maxSize):
        """Read data from the pytsk3 file object."""
        # Safety check: Don't read if device is closed
        if self._is_closed:
            return b''

        if self.current_position >= self.file_size:
            return b''

        # Safety check: Make sure file_obj still exists
        if not self.file_obj:
            return b''

        try:
            # Calculate how much to read
            bytes_to_read = min(maxSize, self.file_size - self.current_position)

            # Read from pytsk3 file object
            data = self.file_obj.read_random(self.current_position, bytes_to_read)

            # Update position
            self.current_position += len(data)

            return data
        except Exception as e:
            # This is expected if the device was closed while reading
            if not self._is_closed:
                logger.error(f"Error reading from pytsk3 file object: {e}")
            return b''

    def writeData(self, data):
        """Write data (not supported for read-only device)."""
        return -1

    def close(self):
        """Close the device and mark it as closed."""
        self._is_closed = True
        self.file_obj = None  # Release reference to file object
        super().close()

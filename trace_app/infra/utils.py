"""Small shared helpers."""

import datetime
import os
import tempfile
from contextlib import contextmanager


# Define a utility function for safe datetime conversion
def safe_datetime(timestamp, timezone_known=True):
    """Format a filesystem timestamp for display.

    `timezone_known` says whether the filesystem records what zone the time was
    in. NTFS, ext and HFS store UTC and it does. FAT and exFAT store the local
    wall-clock time of whatever machine wrote the file, with no zone alongside
    it -- so labelling those UTC asserts something about the evidence that is
    not known, and invites a reader to "correct" a time that was already right.
    """
    if timestamp is None or timestamp == 0:
        return "N/A"
    try:
        moment = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).replace(tzinfo=None)
    except Exception:
        return "N/A"
    stamp = moment.strftime('%Y-%m-%d %H:%M:%S')
    return f"{stamp} UTC" if timezone_known else f"{stamp} (local, no zone)"


# Utility class for common operations
class FileSystemUtils:
    @staticmethod
    def get_readable_size(size_in_bytes):
        """Convert bytes to a human-readable string (e.g., KB, MB, GB, TB)."""
        if size_in_bytes is None:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024.0
        return f"{size_in_bytes:.2f} PB"

    @staticmethod
    @contextmanager
    def temp_file():
        """Context manager for temporary files, ensuring cleanup."""
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp_path = temp.name
                yield temp_path
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)


# Class to handle EWF images

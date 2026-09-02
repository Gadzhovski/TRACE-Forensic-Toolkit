"""Small shared helpers."""

import datetime
import os
import tempfile
from contextlib import contextmanager


# Define a utility function for safe datetime conversion
def safe_datetime(timestamp):
    if timestamp is None or timestamp == 0:
        return "N/A"
    try:
        return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
    except Exception:
        return "N/A"


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

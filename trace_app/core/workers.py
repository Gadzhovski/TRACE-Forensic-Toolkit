"""Background worker threads."""

import os

from PySide6.QtCore import QThread, Signal


class ExportWorker(QThread):
    progress = Signal(int, int)  # current, total
    finished = Signal()
    error = Signal(str)
    status_update = Signal(str)

    def __init__(self, image_handler, inode_number, offset, dest_dir, name, is_directory):
        super().__init__()
        self.image_handler = image_handler
        self.inode_number = inode_number
        self.offset = offset
        self.dest_dir = dest_dir
        self.name = name
        self.is_directory = is_directory
        self.total_items = 0
        self.processed_items = 0

    def run(self):
        try:
            if self.dest_dir:
                if self.is_directory:
                    self._export_directory(self.inode_number, self.offset, self.dest_dir, self.name)
                else:
                    self._export_file(self.inode_number, self.offset, self.dest_dir, self.name)
            if self.isInterruptionRequested():
                self.status_update.emit("Export cancelled.")
            self.finished.emit()
        except Exception as e:
            self.error.emit(f"Export error: {str(e)}")

    def _export_directory(self, inode_number, offset, dest_dir, name):
        """Export a directory with progress reporting."""
        try:
            # Create the directory in the destination
            new_dest_dir = os.path.join(dest_dir, name)
            os.makedirs(new_dest_dir, exist_ok=True)

            # Get directory contents
            entries = self.image_handler.get_directory_contents(offset, inode_number)

            # Count total items for progress reporting
            self._count_items_recursive(entries, offset)

            # Export each entry
            for entry in entries:
                if self.isInterruptionRequested():
                    return
                try:
                    self._export_item(
                        entry["inode_number"],
                        offset,
                        new_dest_dir,
                        entry["name"],
                        entry["is_directory"]
                    )
                except Exception as e:
                    self.error.emit(f"Error exporting {entry['name']}: {str(e)}")

        except Exception as e:
            self.error.emit(f"Error exporting directory {name}: {str(e)}")

    def _count_items_recursive(self, entries, offset):
        """Count total items in a directory and subdirectories."""
        self.total_items += len(entries)

        # Count items in subdirectories
        for entry in entries:
            if self.isInterruptionRequested():
                return
            if entry["is_directory"]:
                sub_entries = self.image_handler.get_directory_contents(offset, entry["inode_number"])
                self._count_items_recursive(sub_entries, offset)

    def _export_item(self, inode_number, offset, dest_dir, name, is_directory):
        """Export a single item (file or directory)."""
        self.status_update.emit(f"Exporting {name}")

        if is_directory:
            sub_dest_dir = os.path.join(dest_dir, name)
            os.makedirs(sub_dest_dir, exist_ok=True)

            # Get subdirectory contents
            entries = self.image_handler.get_directory_contents(offset, inode_number)

            # Export each entry in the subdirectory
            for entry in entries:
                if self.isInterruptionRequested():
                    return
                self._export_item(
                    entry["inode_number"],
                    offset,
                    sub_dest_dir,
                    entry["name"],
                    entry["is_directory"]
                )
        else:
            self._export_file(inode_number, offset, dest_dir, name)

        # Update progress
        self.processed_items += 1
        self.progress.emit(self.processed_items, self.total_items)

    def _export_file(self, inode_number, offset, dest_dir, name):
        """Export a single file with chunked processing."""
        try:
            file_content, _ = self.image_handler.get_file_content(inode_number, offset)
            if file_content:
                file_path = os.path.join(dest_dir, name)
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                self.processed_items += 1
                self.progress.emit(self.processed_items, self.total_items)
        except Exception as e:
            self.error.emit(f"Error exporting file {name}: {str(e)}")

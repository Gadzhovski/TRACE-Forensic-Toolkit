import os
import datetime
from PySide6.QtWidgets import QTextEdit, QSizePolicy, QWidget, QVBoxLayout
import hashlib
from magic import Magic
import re


class MetadataViewer(QWidget):
    def __init__(self, image_handler):
        super(MetadataViewer, self).__init__()
        self.image_handler = image_handler
        self.init_ui()

    def init_ui(self):
        # Add the text edit to the layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.metadata_text_edit = QTextEdit()
        self.metadata_text_edit.setReadOnly(True)
        self.metadata_text_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(self.metadata_text_edit)

    def display_metadata(self, data):
        inode_number = data.get('inode_number')
        offset = data.get('start_offset')

        file_content, metadata = self.image_handler.get_file_content(inode_number, offset)

        if metadata is None:
            self.metadata_text_edit.setHtml("<b>No metadata available.</b>")
            return

        # Safe time formatting function
        # def format_time(timestamp):
        #     try:
        #         return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        #     except (OverflowError, OSError, ValueError):
        #         return "Invalid timestamp"
        def format_time(timestamp):
            if timestamp is None or timestamp == 0:
                return "N/A"
            try:
                return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            except Exception:
                return "N/A"

        created_time = format_time(metadata.crtime) if hasattr(metadata, 'crtime') else 'N/A'
        modified_time = format_time(metadata.mtime) if hasattr(metadata, 'mtime') else 'N/A'
        accessed_time = format_time(metadata.atime) if hasattr(metadata, 'atime') else 'N/A'
        changed_time = format_time(metadata.ctime) if hasattr(metadata, 'ctime') else 'N/A'

        md5_hash = hashlib.md5(file_content).hexdigest() if file_content else "N/A"
        sha256_hash = hashlib.sha256(file_content).hexdigest() if file_content else "N/A"
        mime_type = Magic().from_buffer(file_content) if file_content else "N/A"

        # Ensure size is an integer before passing to get_readable_size
        size = metadata.size if metadata.size else 'N/A'
        if isinstance(size, str):
            try:
                size = int(size)  # Convert size to int if it's a string
            except ValueError:
                size = 'N/A'  # Keep as 'N/A' if conversion fails
        else:
            size = self.image_handler.get_readable_size(size)  # Convert size to a readable format

        # extended_metadata = f"<b>Metadata</b>"
        extended_metadata = f"<b style='font-size: 20px; font-family: Courier New;'>Metadata</b>"
        extended_metadata += f"<table style='margin-left: 10px; font-family: Courier New;'>"
        extended_metadata += f"<tr><th style='text-align: left;'>Name:</th><td style='padding-left: 20px;'>{data.get('name', 'N/A')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Type:</th><td style='padding-left: 20px;'>{data.get('type')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MIME Type:</th><td style='padding-left: 20px;'>{mime_type}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Size:</th><td style='padding-left: 20px;'>{size}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Modified:</th><td style='padding-left: 20px;'>{modified_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Accessed:</th><td style='padding-left: 20px;'>{accessed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Created:</th><td style='padding-left: 20px;'>{created_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Changed:</th><td style='padding-left: 20px;'>{changed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MD5:</th><td style='padding-left: 20px;'>{md5_hash}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>SHA-256:</th><td style='padding-left: 20px;'>{sha256_hash}</td></tr>"
        extended_metadata += f"</table>"
        extended_metadata += f"<br>"
        extended_metadata += f"<br>"

        if os.name == 'nt':
            istat_output = self.run_istat(offset, inode_number, self.image_handler.image_path)
            extended_metadata += (
                f"<b style='font-size: 20px; font-family: Courier New;'>From The Sleuth Kit istat Tool</b>")
            extended_metadata += (f"<div style='margin-left: 15px; font-family: Courier New;'>")
            extended_metadata += (f"<pre>{istat_output}</pre>")
            extended_metadata += (f"</div>")

        self.metadata_text_edit.setHtml(extended_metadata)

    def run_istat(self, offset, inode_number, image_path):
        import subprocess

        if image_path is None:
            raise ValueError("Image path value is None!")
        if inode_number is None:
            raise ValueError("Inode number value is None!")

        metadata_cmd = ["tools/sleuthkit-4.12.1-win32/bin/istat.exe"]

        if offset is not None:
            metadata_cmd.extend(["-o", str(offset)])

        metadata_cmd.extend([image_path, str(inode_number)])

        metadata_result = subprocess.run(
            metadata_cmd,
            capture_output=True,
            text=True,
            check=True
        )

        metadata_content = metadata_result.stdout

        match = re.search(r"(init_size: \d+)", metadata_content)

        if match:
            end_index = match.end()
            metadata_content = metadata_content[:end_index]

        return metadata_content

    def clear(self):
        self.metadata_text_edit.clear()

import datetime
import html

import pytsk3
from PySide6.QtWidgets import QTextEdit, QSizePolicy, QWidget, QVBoxLayout
import hashlib
from magic import Magic


class MetadataViewer(QWidget):
    def __init__(self, image_handler):
        super(MetadataViewer, self).__init__()
        self.image_handler = image_handler
        self.init_ui()

    def set_image_handler(self, image_handler):
        """Point this viewer at a newly loaded image."""
        self.image_handler = image_handler

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
        # Check if this is a carved file with content already provided
        is_carved = data.get('is_carved', False)
        file_content = data.get('file_content')

        if is_carved and file_content:
            # Carved file - use provided content, no filesystem metadata available
            metadata = None
        else:
            # Regular file - read from filesystem
            inode_number = data.get('inode_number')
            offset = data.get('start_offset')
            file_content, metadata = self.image_handler.get_file_content(inode_number, offset)

            if metadata is None:
                self.metadata_text_edit.setHtml("<b>No metadata available.</b>")
                return

        def format_time(timestamp):
            if timestamp is None or timestamp == 0:
                return "N/A"
            try:
                return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            except Exception:
                return "N/A"

        # Handle timestamps - use filesystem metadata if available, otherwise use carved timestamp
        if is_carved:
            # For carved files, use the extracted/preserved timestamp
            carved_timestamp = data.get('carved_timestamp', 'N/A')
            created_time = 'N/A (carved file)'
            modified_time = carved_timestamp if carved_timestamp != 'N/A' else 'N/A (carved file)'
            accessed_time = 'N/A (carved file)'
            changed_time = 'N/A (carved file)'
        else:
            # For regular files, use filesystem metadata
            created_time = format_time(metadata.crtime) if hasattr(metadata, 'crtime') else 'N/A'
            modified_time = format_time(metadata.mtime) if hasattr(metadata, 'mtime') else 'N/A'
            accessed_time = format_time(metadata.atime) if hasattr(metadata, 'atime') else 'N/A'
            changed_time = format_time(metadata.ctime) if hasattr(metadata, 'ctime') else 'N/A'

        md5_hash = hashlib.md5(file_content).hexdigest() if file_content else "N/A"
        sha256_hash = hashlib.sha256(file_content).hexdigest() if file_content else "N/A"
        mime_type = Magic().from_buffer(file_content) if file_content else "N/A"

        # Ensure size is an integer before passing to get_readable_size
        if is_carved:
            # For carved files, use size from data dict
            size = data.get('size', 0)
            size = self.image_handler.get_readable_size(size)
        else:
            # For regular files, use filesystem metadata
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

        # Add carved file indicator if applicable
        if is_carved:
            extended_metadata += f"<p style='margin-left: 10px; font-family: Courier New; color: #ff6600;'><b>⚠ Carved File</b> (recovered from unallocated space)</p>"

        extended_metadata += f"<table style='margin-left: 10px; font-family: Courier New;'>"
        extended_metadata += f"<tr><th style='text-align: left;'>Name:</th><td style='padding-left: 20px;'>{data.get('name', 'N/A')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Type:</th><td style='padding-left: 20px;'>{data.get('type')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MIME Type:</th><td style='padding-left: 20px;'>{mime_type}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Size:</th><td style='padding-left: 20px;'>{size}</td></tr>"

        # Add disk offset for carved files
        if is_carved:
            offset_value = data.get('offset', 0)
            extended_metadata += f"<tr><th style='text-align: left;'>Disk Offset:</th><td style='padding-left: 20px;'>{hex(offset_value)} ({offset_value} bytes)</td></tr>"

        extended_metadata += f"<tr><th style='text-align: left;'>Modified:</th><td style='padding-left: 20px;'>{modified_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Accessed:</th><td style='padding-left: 20px;'>{accessed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Created:</th><td style='padding-left: 20px;'>{created_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Changed:</th><td style='padding-left: 20px;'>{changed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MD5:</th><td style='padding-left: 20px;'>{md5_hash}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>SHA-256:</th><td style='padding-left: 20px;'>{sha256_hash}</td></tr>"
        extended_metadata += f"</table>"
        extended_metadata += f"<br>"
        extended_metadata += f"<br>"

        # Skip for carved files (no inode available)
        if not is_carved:
            details = self.get_inode_details(data.get('start_offset'), data.get('inode_number'))
            if details:
                extended_metadata += (
                    f"<b style='font-size: 20px; font-family: Courier New;'>Filesystem Details</b>")
                extended_metadata += (f"<div style='margin-left: 15px; font-family: Courier New;'>")
                extended_metadata += (f"<pre>{html.escape(details)}</pre>")
                extended_metadata += (f"</div>")

        self.metadata_text_edit.setHtml(extended_metadata)

    def get_inode_details(self, offset, inode_number):
        """Render low-level filesystem details for an inode.

        This reads the same metadata The Sleuth Kit's `istat` reports, but
        through pytsk3 directly. The previous implementation shelled out to a
        bundled tools/sleuthkit-4.12.1-win32/bin/istat.exe behind an
        `os.name == 'nt'` guard, so macOS and Linux silently got a reduced
        Metadata tab with no explanation -- and a packaged build got a
        FileNotFoundError, since tools/ was never bundled.

        Returns a plain-text block, or None when the data is unavailable.
        """
        if offset is None or inode_number is None:
            return None

        try:
            fs_info = self.image_handler.get_fs_info(offset)
            if fs_info is None:
                return None
            file_obj = fs_info.open_meta(inode=inode_number)
        except Exception as e:
            return f"Filesystem details unavailable: {e}"

        meta = getattr(file_obj.info, 'meta', None)
        if meta is None:
            return None

        lines = []

        def add(label, value):
            lines.append(f"{label}: {value}")

        add("Entry", meta.addr)
        if getattr(meta, 'seq', None) is not None:
            add("Sequence", meta.seq)

        alloc = "Allocated" if int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC else "Deleted"
        meta_type = self._META_TYPES.get(int(meta.type), str(meta.type))
        add("Status", f"{alloc} {meta_type}")

        if getattr(meta, 'nlink', None) is not None:
            add("Links", meta.nlink)
        add("Size", meta.size)
        add("UID / GID", f"{meta.uid} / {meta.gid}")
        if getattr(meta, 'mode', None) is not None:
            add("Mode", oct(int(meta.mode)))

        lines.append("")
        lines.append("Timestamps:")
        for label, attr in (("Created ", 'crtime'), ("File Modified", 'mtime'),
                            ("MFT Modified", 'ctime'), ("Accessed", 'atime')):
            ts = getattr(meta, attr, None)
            lines.append(f"  {label}\t{self._format_timestamp(ts)}")

        # Attribute list -- the resident/non-resident breakdown istat prints.
        try:
            attrs = list(file_obj)
        except Exception:
            attrs = []

        if attrs:
            lines.append("")
            lines.append("Attributes:")
            for attr in attrs:
                info = attr.info
                try:
                    non_res = bool(int(info.flags) & pytsk3.TSK_FS_ATTR_NONRES)
                except Exception:
                    non_res = False
                name = info.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                type_name = self._ATTR_TYPES.get(int(info.type), str(info.type))
                lines.append(
                    f"  Type: {type_name} ({int(info.type)}-{info.id})   "
                    f"Name: {name or 'N/A'}   "
                    f"{'Non-Resident' if non_res else 'Resident'}   "
                    f"size: {info.size}")

        return "\n".join(lines)

    @staticmethod
    def _format_timestamp(ts):
        if not ts:
            return "N/A"
        try:
            return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
        except (OSError, OverflowError, ValueError):
            return "N/A"

    # NTFS attribute type identifiers, as istat labels them.
    _ATTR_TYPES = {
        16: "$STANDARD_INFORMATION", 32: "$ATTRIBUTE_LIST", 48: "$FILE_NAME",
        64: "$OBJECT_ID", 80: "$SECURITY_DESCRIPTOR", 96: "$VOLUME_NAME",
        112: "$VOLUME_INFORMATION", 128: "$DATA", 144: "$INDEX_ROOT",
        160: "$INDEX_ALLOCATION", 176: "$BITMAP", 192: "$REPARSE_POINT",
        256: "$LOGGED_UTILITY_STREAM",
    }

    # Built from the pytsk3 constants rather than hardcoded numbers, so the
    # labels cannot drift from the enum.
    _META_TYPES = {
        int(pytsk3.TSK_FS_META_TYPE_REG): "File",
        int(pytsk3.TSK_FS_META_TYPE_DIR): "Directory",
        int(pytsk3.TSK_FS_META_TYPE_FIFO): "Named Pipe",
        int(pytsk3.TSK_FS_META_TYPE_CHR): "Character Device",
        int(pytsk3.TSK_FS_META_TYPE_BLK): "Block Device",
        int(pytsk3.TSK_FS_META_TYPE_LNK): "Symbolic Link",
        int(pytsk3.TSK_FS_META_TYPE_SHAD): "Shadow",
        int(pytsk3.TSK_FS_META_TYPE_SOCK): "Socket",
        int(pytsk3.TSK_FS_META_TYPE_WHT): "Whiteout",
        int(pytsk3.TSK_FS_META_TYPE_VIRT): "Virtual",
        int(pytsk3.TSK_FS_META_TYPE_VIRT_DIR): "Virtual Directory",
        int(pytsk3.TSK_FS_META_TYPE_UNDEF): "Unknown",
    }

    def clear(self):
        self.metadata_text_edit.clear()

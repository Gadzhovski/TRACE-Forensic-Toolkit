from hashlib import md5, sha256
from magic import Magic
import re

from PySide6.QtWidgets import QTextEdit


class MetadataViewerManager(QTextEdit):

    def __init__(self, image_path, evidence_utils):
        super().__init__()
        self.current_image_path = None
        self.evidence_utils = evidence_utils
        self.setReadOnly(True)

    def set_image_path(self, image_path):
        self.current_image_path = image_path

    def generate_metadata(self, file_content, item, full_file_path, offset, inode_number):
        # Calculate MD5 and SHA-256 hashes
        md5_hash = md5(file_content).hexdigest()
        sha256_hash = sha256(file_content).hexdigest()

        # Determine MIME type
        mime_type = Magic().from_buffer(file_content)

        # Fetch metadata using EvidenceUtils utility class
        metadata_content = self.evidence_utils.get_file_metadata(offset, self.current_image_path, inode_number)

        # Extract times using regular expressions
        created_time = re.search(r"Created:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)", metadata_content)
        modified_time = re.search(r"File Modified:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                  metadata_content)
        accessed_time = re.search(r"Accessed:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)", metadata_content)
        changed_time = re.search(r"MFT Modified:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? \((.*?)\)",
                                 metadata_content)

        # Combine all metadata in a table
        extended_metadata = f"<b>Metadata:</b><br><table border='1'>"
        extended_metadata += f"<tr><td>Name</td><td>{item.text(0)}</td></tr>"
        extended_metadata += f"<tr><td>Path</td><td>{full_file_path}</td></tr>"
        extended_metadata += f"<tr><td>Type</td><td>File</td></tr>"
        extended_metadata += f"<tr><td>MIME Type</td><td>{mime_type}</td></tr>"
        extended_metadata += f"<tr><td>Size</td><td>{len(file_content)}</td></tr>"
        extended_metadata += f"<tr><td>Modified</td><td>{modified_time.group(1) if modified_time else 'N/A'}</td></tr>"
        extended_metadata += f"<tr><td>Accessed</td><td>{accessed_time.group(1) if accessed_time else 'N/A'}</td></tr>"
        extended_metadata += f"<tr><td>Created</td><td>{created_time.group(1) if created_time else 'N/A'}</td></tr>"
        extended_metadata += f"<tr><td>Changed</td><td>{changed_time.group(1) if changed_time else 'N/A'}</td></tr>"
        extended_metadata += f"<tr><td>MD5</td><td>{md5_hash}</td></tr>"
        extended_metadata += f"<tr><td>SHA-256</td><td>{sha256_hash}</td></tr>"
        extended_metadata += f"</table>"
        extended_metadata += f"<br>"
        extended_metadata += f"<b>From The Sleuth Kit istat Tool</b><pre>{metadata_content}</pre>"
        return extended_metadata

    def display_metadata(self, file_content, item, full_file_path, offset, inode_number):
        metadata_content = self.generate_metadata(file_content, item, full_file_path, offset,
                                                  inode_number)
        self.setHtml(metadata_content)

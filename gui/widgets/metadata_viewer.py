from PySide6.QtWidgets import QTextEdit
from managers.metadata_viewer_manager import MetadataViewerManager


class MetadataViewer(QTextEdit):

    def __init__(self, current_image_path, evidence_utils):
        super().__init__()
        self.current_image_path = current_image_path
        self.metadata_manager = MetadataViewerManager(current_image_path, evidence_utils)
        self.setReadOnly(True)

    def display_metadata(self, file_content, item, full_file_path, offset, inode_number):
        self.metadata_manager.set_image_path(self.current_image_path)
        metadata_content = self.metadata_manager.generate_metadata(file_content, item, full_file_path, offset,
                                                                   inode_number)
        self.setHtml(metadata_content)

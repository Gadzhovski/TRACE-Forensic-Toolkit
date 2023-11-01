from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QTableWidget, QTableWidgetItem)
from PySide6.QtWidgets import QWidget, QVBoxLayout


# class ListingTab(QWidget):
#     def __init__(self, db_manager, image_handler):
class ListingTab(QWidget):
    def __init__(self, db_manager, image_handler, get_file_content_method, update_viewer_with_file_content_method, display_content_for_active_tab_method):
        super().__init__()
        self.db_manager = db_manager
        self.image_handler = image_handler
        self.get_file_content_method = get_file_content_method
        self.update_viewer_with_file_content = update_viewer_with_file_content_method
        self.display_content_for_active_tab = display_content_for_active_tab_method

        self.layout = QVBoxLayout(self)
        self.listing_table = QTableWidget()

        # Set icon size for listing table
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(9)
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Description', 'Size', 'Modified Date', 'Created Date', 'Accessed Date', 'Changed Date',
             'Flags'])
        self.listing_table.cellClicked.connect(self.on_listing_table_item_clicked)

        self.layout.addWidget(self.listing_table)
        self.setLayout(self.layout)

    def on_listing_table_item_clicked(self, row, column):
        print("file clicked")
        inode_item = self.listing_table.item(row, 1)
        inode_number = int(inode_item.text())
        data = self.listing_table.item(row, 0).data(Qt.UserRole)

        self.current_selected_data = data

        if data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)
            self.populate_listing_table(entries, data["start_offset"])
        else:
            file_content = self.get_file_content_method(inode_number, data["start_offset"])
            print("file content:")
            if file_content:
                print("file content found")
                self.update_viewer_with_file_content(file_content, data)

            # Call this to make sure the content is displayed based on the active tab
        self.display_content_for_active_tab()


    def populate_listing_table(self, entries, offset):
        self.listing_table.setRowCount(0)
        for entry in entries:
            entry_name = entry["name"]
            inode_number = entry["inode_number"]
            description = "Directory" if entry["is_directory"] else "File"
            size_in_bytes = entry["size"] if "size" in entry else 0
            readable_size = self.get_readable_size(size_in_bytes)
            created = entry["created"] if "created" in entry else None
            modified = entry["modified"] if "modified" in entry else None
            accessed = entry["accessed"] if "accessed" in entry else None
            changed = entry["changed"] if "changed" in entry else None
            flags = entry["flag(??)"] if "flag(??)" in entry else None

            # Revised logic for determining icon_name and icon_type
            if entry["is_directory"]:
                icon_name, icon_type = 'folder', 'folder'
            else:
                if '.' in entry_name:
                    icon_name = 'file'
                    icon_type = entry_name.split('.')[-1].lower()  # Ensure the extension is in lowercase

                else:
                    icon_name, icon_type = 'file', 'unknown'

            # self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset)
            self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset,
                                               readable_size, modified, created, accessed, changed, flags)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      modified, created, accessed, changed, flags):
        icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
        icon = QIcon(icon_path)

        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        name_item = QTableWidgetItem(entry_name)
        name_item.setIcon(icon)  # Ensure that the icon is set here
        name_item.setData(Qt.UserRole, {
            "inode_number": entry_inode,
            "start_offset": offset,
            "type": "directory" if icon_type == 'folder' else 'file',
            "name": entry_name,
            "size": size,
        })

        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))  # Convert inode to string
        self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
        self.listing_table.setItem(row_position, 3, QTableWidgetItem(size))

        self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(modified)))
        self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(created)))
        self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(accessed)))
        self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))
        self.listing_table.setItem(row_position, 8, QTableWidgetItem(str(flags)))

    @staticmethod
    def get_readable_size(size_in_bytes):
        """Convert bytes to a human-readable string (e.g., KB, MB, GB, TB)."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024.0

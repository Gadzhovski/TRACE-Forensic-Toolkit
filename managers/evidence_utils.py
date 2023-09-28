import subprocess
import re


class EvidenceUtils:
    """Utility class to handle evidence related operations."""

    @staticmethod
    def get_partitions(image_path):
        """Get partitions from an image using mmls."""
        result = subprocess.run(
            ["tools/sleuthkit-4.12.0-win32/bin/mmls.exe", "-M", "-B", image_path],
            capture_output=True, text=True
        )
        lines = result.stdout.splitlines()
        partitions = []

        for line in lines:
            parts = line.split()
            # Check if the line starts with a number (partition entry)
            if parts and re.match(r"^\d{3}:", parts[0]):
                start_sector = int(parts[2])
                end_sector = int(parts[3])
                size_str = parts[5]  # Assuming that the size is now directly in the 5th column
                description = " ".join(parts[6:])  # Description of the partition

                # Run fsstat to get the file system type
                fsstat_cmd = ["tools/sleuthkit-4.12.0-win32/bin/fsstat.exe", "-o", str(start_sector), "-t", image_path]
                try:
                    fsstat_result = subprocess.run(fsstat_cmd, capture_output=True, text=True, check=True)
                    fs_type = fsstat_result.stdout.strip().upper()
                    fs_type = f"[{fs_type}]"
                except subprocess.CalledProcessError:
                    fs_type = ""

                partitions.append({
                    "start": start_sector,
                    "end": end_sector,
                    "size": size_str,
                    "description": f"{description} {fs_type}"
                })

        return partitions

    @staticmethod
    def list_files(image_path, offset=None, inode_number=None):
        """List files in a directory using fls."""
        try:
            cmd = ["tools/sleuthkit-4.12.0-win32/bin/fls.exe"]

            # Add offset to the command if it's provided
            if offset is not None:
                cmd.extend(["-o", str(offset)])

            cmd.append(image_path)

            # Add inode number to the command if it's provided
            if inode_number:
                cmd.append(str(inode_number))

            # print(f"Executing command: {' '.join(cmd)}")  # Debugging line
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            lines = result.stdout.splitlines()
            return lines
        except subprocess.CalledProcessError as e:
            # print(f"Error executing fls: {e}")
            return []

    @staticmethod
    def get_file_content(offset, image_path, inode_number):
        """Retrieve the content of a file using icat."""
        try:
            cmd = ["tools/sleuthkit-4.12.0-win32/bin/icat.exe"]

            # Add offset to the command only if it's not None
            if offset is not None:
                cmd.extend(["-o", str(offset)])

            cmd.append(image_path)
            cmd.append(str(inode_number))

            result = subprocess.run(
                cmd,
                capture_output=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            # print(f"Error executing icat: {e}")
            return None

    @staticmethod
    def get_file_metadata(offset, image_path, inode_number):
        if image_path is None:
            raise ValueError("Image path value is None!")
        if inode_number is None:
            raise ValueError("Inode number value is None!")

        metadata_cmd = ["tools/sleuthkit-4.12.0-win32/bin/istat.exe"]

        # Add offset to the command only if it's not None
        if offset is not None:
            metadata_cmd.extend(["-o", str(offset)])

        metadata_cmd.extend([image_path, str(inode_number)])

        metadata_result = subprocess.run(metadata_cmd, capture_output=True, text=True, check=True)
        metadata_content = metadata_result.stdout

        # Find the "init_size: <some number>" pattern and trim everything after it
        match = re.search(r"(init_size: \d+)", metadata_content)
        if match:
            end_index = match.end()
            metadata_content = metadata_content[:end_index]

        return metadata_content

    @staticmethod
    def construct_full_file_path(item):
        full_file_path = item.text(0)
        parent_item = item.parent()
        while parent_item is not None:
            full_file_path = f"{parent_item.text(0)}/{full_file_path}"
            parent_item = parent_item.parent()
        return full_file_path

    @staticmethod
    def determine_file_properties(entry_type, entry_name):
        description = "Directory" if 'd' in entry_type else "File"
        if 'd' in entry_type:
            icon_name = entry_name
            icon_type = 'folder'
        else:
            icon_name = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'
            icon_type = 'file'
        return description, icon_name, icon_type

    @staticmethod
    def get_file_type_from_extension(file_extension):
        audio_extensions = ['.mp3', '.wav', '.aac', '.ogg', '.m4a']
        video_extensions = ['.mp4', '.mkv', '.flv', '.avi', '.mov']

        if file_extension in audio_extensions:
            return "audio"
        elif file_extension in video_extensions:
            return "video"
        else:
            return "text"

    @staticmethod
    def handle_directory(data, current_image_path):
        inode_number = data.get("inode_number")
        offset = data.get("offset")
        entries = EvidenceUtils.list_files(current_image_path, offset, inode_number)
        return entries

    @staticmethod
    def populate_tree_with_files(parent_item, image_path, offset, inode_number=None, db_manager=None):
        current_offset = offset
        if offset is None and inode_number is None:  # No partitions
            entries = EvidenceUtils.list_files(image_path)
        else:
            entries = EvidenceUtils.list_files(image_path, offset, inode_number)
        return entries

    @staticmethod
    def _populate_directory_item(child_item, entry_name, entry_parts, image_path, offset, db_manager):
        inode_number = entry_parts[1].split('-')[0]
        icon_path = EvidenceUtils._get_icon_path('folder', entry_name, default="Default_Folder", db_manager=db_manager)
        entries = EvidenceUtils.list_files(image_path, offset, inode_number)
        return icon_path, entries

    @staticmethod
    def _populate_file_item(child_item, entry_name, entry_parts, offset, db_manager):
        file_extension = entry_name.split('.')[-1] if '.' in entry_name else 'unknown'
        inode_number = entry_parts[1].split('-')[0]
        icon_path = EvidenceUtils._get_icon_path('file', file_extension, default="default_file", db_manager=db_manager)
        return icon_path

    @staticmethod
    def _get_icon_path(item_type, name, default=None, db_manager=None):
        icon_path = db_manager.get_icon_path(item_type, name)
        return icon_path or db_manager.get_icon_path(item_type, default)

import subprocess
from re import search as re_search
from re import match as re_match


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
            if parts and re_match(r"^\d{3}:", parts[0]):
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
        match = re_search(r"(init_size: \d+)", metadata_content)
        if match:
            end_index = match.end()
            metadata_content = metadata_content[:end_index]

        return metadata_content

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

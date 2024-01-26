import os
import datetime
from Registry import Registry
import pyewf
import pytsk3
import tempfile


SECTOR_SIZE = 512  # 512 bytes

# Class to handle EWF images
class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


class ImageHandler:
    def __init__(self, image_path):
        self.image_path = image_path  # Path to the image
        self.img_info = None  # Initialized once
        self.volume_info = None  # Initialized once
        self.fs_info_cache = {}  # Cache for FS_Info objects, keyed by start offset
        self.load_image()  # Load the image

    def get_image_type(self):
        """Determine the type of the image based on its extension."""
        _, extension = os.path.splitext(self.image_path)
        extension = extension.lower()

        ewf = [".e01", ".s01", ".l01"]
        raw = [".raw", ".img", ".dd"]

        if extension in ewf:
            return "ewf"
        elif extension in raw:
            return "raw"
        else:
            raise ValueError(f"Unsupported image type: {extension}")

    def load_image(self):
        image_type = self.get_image_type()  # ewf or raw

        if image_type == "ewf":
            filenames = pyewf.glob(self.image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            self.img_info = EWFImgInfo(ewf_handle)  # instance of EWFImgInfo class to work with
        elif image_type == "raw":
            self.img_info = pytsk3.Img_Info(self.image_path)  # instance of Img_Info class to work with
        else:
            raise ValueError(f"Unsupported image type: {image_type}")

        try:
            self.volume_info = pytsk3.Volume_Info(self.img_info)  # instance of Volume_Info class to work with
        except Exception as e:
            self.volume_info = None

    def get_partitions(self):
        """Retrieve partitions from the loaded image."""
        partitions = []
        if self.volume_info:
            for partition in self.volume_info:
                if not partition.desc:
                    continue
                partitions.append((partition.addr, partition.desc, partition.start, partition.len))
        return partitions

    def has_partitions(self):
        """Check if the image has partitions."""
        return bool(self.get_partitions())

    def get_fs_info(self, start_offset):
        """Retrieve the FS_Info for a partition, initializing it if necessary."""
        if start_offset not in self.fs_info_cache:
            try:
                fs_info = pytsk3.FS_Info(self.img_info, offset=start_offset * 512)
                self.fs_info_cache[start_offset] = fs_info
            except Exception as e:
                return None
        return self.fs_info_cache[start_offset]

    def get_fs_type(self, start_offset):
        """Retrieve the file system type for a partition."""
        try:
            fs_type = self.get_fs_info(start_offset).info.ftype

            # Map the file system type to its name
            if fs_type == pytsk3.TSK_FS_TYPE_NTFS:
                return "NTFS"
            elif fs_type == pytsk3.TSK_FS_TYPE_FAT12:
                return "FAT12"
            elif fs_type == pytsk3.TSK_FS_TYPE_FAT16:
                return "FAT16"
            elif fs_type == pytsk3.TSK_FS_TYPE_FAT32:
                return "FAT32"
            elif fs_type == pytsk3.TSK_FS_TYPE_EXFAT:
                return "ExFAT"
            elif fs_type == pytsk3.TSK_FS_TYPE_EXT2:
                return "Ext2"
            elif fs_type == pytsk3.TSK_FS_TYPE_EXT3:
                return "Ext3"
            elif fs_type == pytsk3.TSK_FS_TYPE_EXT4:
                return "Ext4"
            elif fs_type == pytsk3.TSK_FS_TYPE_ISO9660:
                return "ISO9660"
            elif fs_type == pytsk3.TSK_FS_TYPE_HFS:
                return "HFS"
            elif fs_type == pytsk3.TSK_FS_TYPE_APFS:
                return "APFS"
            else:
                return "Unknown"
        except Exception as e:
            return "N/A"

    def check_partition_contents(self, partition_start_offset):
        """Check if a partition has any files or folders."""
        fs = self.get_fs_info(partition_start_offset)
        if fs:
            try:
                root_dir = fs.open_dir(path="/")
                for _ in root_dir:
                    return True
                return False
            except:
                return False
        return False

    def get_directory_contents(self, start_offset, inode_number=None):
        fs = self.get_fs_info(start_offset)
        if fs:
            try:
                directory = fs.open_dir(inode=inode_number) if inode_number else fs.open_dir(path="/")
                entries = []
                for entry in directory:
                    if entry.info.name.name not in [b".", b".."]:
                        is_directory = False
                        if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            is_directory = True

                        # Define a function to safely get datetime string or None
                        def safe_datetime(timestamp):
                            try:
                                return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                            except (OverflowError, OSError, ValueError):
                                return "N/A"

                        entries.append({
                            "name": entry.info.name.name.decode('utf-8') if hasattr(entry.info.name, 'name') else None,
                            "is_directory": is_directory,
                            "inode_number": entry.info.meta.addr if entry.info.meta else None,
                            "size": entry.info.meta.size if entry.info.meta and entry.info.meta.size is not None else 0,
                            "accessed": safe_datetime(entry.info.meta.atime) if hasattr(entry.info.meta,
                                                                                        'atime') else "N/A",
                            "modified": safe_datetime(entry.info.meta.mtime) if hasattr(entry.info.meta,
                                                                                        'mtime') else "N/A",
                            "created": safe_datetime(entry.info.meta.crtime) if hasattr(entry.info.meta,
                                                                                        'crtime') else "N/A",
                            "changed": safe_datetime(entry.info.meta.ctime) if hasattr(entry.info.meta,
                                                                                       'ctime') else "N/A",
                            #"flags": entry.info.meta.flags if entry.info.meta else None,
                        })
                return entries

            except Exception as e:
                # Log the exception for debugging purposes
                print(f"Error in get_directory_contents: {e}")
                return []
        return []


    def get_registry_hive(self, fs_info, hive_path):
        """Extract a registry hive from the given filesystem."""
        try:
            registry_file = fs_info.open(hive_path)
            hive_data = registry_file.read_random(0, registry_file.info.meta.size)
            return hive_data
        except Exception as e:
            print(f"Error reading registry hive: {e}")
            return None

    def get_all_registry_hives(self, start_offset):
        """Get all registry hives from the given filesystem."""
        fs_info = self.get_fs_info(start_offset)

        if not fs_info:
            return None

        # if file system is not ntfs, return unknown OS and exit the function
        if self.get_fs_type(start_offset) != "NTFS":
            return None

        software_hive_data = self.get_registry_hive(fs_info, "/Windows/System32/config/SOFTWARE")
        system_hive_data = self.get_registry_hive(fs_info, "/Windows/System32/config/SYSTEM")
        sam_hive_data = self.get_registry_hive(fs_info, "/Windows/System32/config/SAM")
        security_hive_data = self.get_registry_hive(fs_info, "/Windows/System32/config/SECURITY")
        ntuser_hive_data = self.get_registry_hive(fs_info, "/Users/NTUSER.DAT")

        return software_hive_data, system_hive_data, sam_hive_data, security_hive_data, ntuser_hive_data




    def get_windows_version(self, start_offset):
        """Get the Windows version from the SOFTWARE registry hive."""
        fs_info = self.get_fs_info(start_offset)

        if not fs_info:
            return None

        # if file system is not ntfs, return unknown OS and exit the function
        if self.get_fs_type(start_offset) != "NTFS":
            return None

        software_hive_data = self.get_registry_hive(fs_info, "/Windows/System32/config/SOFTWARE")

        if not software_hive_data:
            return None

        # Create a temporary file and store the hive data
        temp_hive_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_hive:
                temp_hive.write(software_hive_data)
                temp_hive_path = temp_hive.name

            if temp_hive_path:
                reg = Registry.Registry(temp_hive_path)
                key = reg.open("Microsoft\\Windows NT\\CurrentVersion")

                # Helper function to safely get registry values
                def get_reg_value(reg_key, value_name):
                    try:
                        return reg_key.value(value_name).value()
                    except Registry.RegistryValueNotFoundException:
                        return "N/A"

                # Fetching registry values
                product_name = get_reg_value(key, "ProductName")
                current_version = get_reg_value(key, "CurrentVersion")
                current_build = get_reg_value(key, "CurrentBuild")
                registered_owner = get_reg_value(key, "RegisteredOwner")
                csd_version = get_reg_value(key, "CSDVersion")
                product_id = get_reg_value(key, "ProductId")

                os_version = f"{product_name} Version {current_version}\nBuild {current_build} {csd_version}\nOwner: {registered_owner}\nProduct ID: {product_id}"
            else:
                os_version = "Failed to create temporary hive file"

            # Clean up the temporary file
            if temp_hive_path and os.path.exists(temp_hive_path):
                os.remove(temp_hive_path)

            return os_version

        except Exception as e:
            print(f"Error parsing SOFTWARE hive: {e}")
            return "Error in parsing OS version"


    def read_unallocated_space(self, start_offset, end_offset):
        try:
            start_byte_offset = start_offset * SECTOR_SIZE
            end_byte_offset = end_offset * SECTOR_SIZE
            size_in_bytes = end_byte_offset - start_byte_offset

            if size_in_bytes <= 0:
                print("Invalid size for unallocated space.")
                return None

            unallocated_space = self.img_info.read(start_byte_offset, size_in_bytes)
            if unallocated_space is None:
                print(f"Failed to read unallocated space from offset {start_byte_offset} to {end_byte_offset}")
                return None

            return unallocated_space
        except Exception as e:
            print(f"Error reading unallocated space: {e}")
            return None



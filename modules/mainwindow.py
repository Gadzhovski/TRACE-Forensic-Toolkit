import configparser
import hashlib
import os
import datetime
import pyewf
import pytsk3
import tempfile
import gc
import time
from Registry import Registry
from sqlite3 import connect as sqlite3_connect
import subprocess
import platform
from contextlib import contextmanager
from functools import lru_cache
from PySide6.QtCore import Qt, QSize, QThread, Signal, QTimer
from PySide6.QtGui import QIcon, QFont, QPalette, QBrush, QAction, QActionGroup
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit,
                               QFormLayout, QApplication, QWidget, QProgressDialog, QSizePolicy)

from modules.about import AboutDialog
from modules.converter import Main
from modules.exif_tab import ExifViewer
from modules.file_carving import FileCarvingWidget
from modules.hex_tab import HexViewer
from modules.list_files import FileSearchWidget
from modules.metadata_tab import MetadataViewer
from modules.registry import RegistryExtractor
from modules.text_tab import TextViewer
from modules.unified_application_manager import UnifiedViewer
from modules.verification import VerificationWidget
from modules.veriphone_api import VeriphoneWidget
from modules.virus_total_tab import VirusTotal

SECTOR_SIZE = 512
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks for processing
FILE_BUFFER_SIZE = 4096  # 4KB for file operations


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


# ImageHandler class with optimizations
class ImageHandler:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img_info = None
        self.volume_info = None
        self.fs_info_cache = {}
        self.fs_info = None
        self.is_wiped_image = False
        self._directory_cache = {}  # Cache for directory contents
        self._partition_cache = None  # Cache for partitions

        # Load the image with progress tracking
        self.load_image()

    def __del__(self):
        """Cleanup resources when the object is destroyed."""
        self.close_resources()

    def close_resources(self):
        """Explicitly close all open resources."""
        # Close filesystem objects
        for fs_info in self.fs_info_cache.values():
            if hasattr(fs_info, 'close'):
                try:
                    fs_info.close()
                except:
                    pass

        # Close the image
        if self.img_info:
            if hasattr(self.img_info, 'close'):
                try:
                    self.img_info.close()
                except:
                    pass
            self.img_info = None

        # Clear caches
        self.fs_info_cache.clear()
        self._directory_cache.clear()

    def get_size(self):
        """Returns the size of the disk image."""
        if self.img_info:
            return self.img_info.get_size()
        else:
            raise AttributeError("Image not loaded or unsupported format.")

    def read(self, offset, size):
        """Reads data from the image starting at `offset` for `size` bytes."""
        if self.img_info and hasattr(self.img_info, 'read'):
            return self.img_info.read(offset, size)
        else:
            raise NotImplementedError("The image format does not support direct reading.")

    def get_image_type(self):
        """Determine the type of the image based on its extension."""
        _, extension = os.path.splitext(self.image_path)
        extension = extension.lower()

        ewf = [".e01", ".s01", ".l01", ".ex01"]
        raw = [".raw", ".img", ".dd", ".iso",
               ".ad1", ".001", ".dmg", ".sparse",
               ".sparseimage"]

        if extension in ewf:
            return "ewf"
        elif extension in raw:
            return "raw"
        else:
            raise ValueError(f"Unsupported image type: {extension}")

    def calculate_hashes(self, progress_callback=None):
        """Calculate the MD5, SHA1, and SHA256 hashes for the image with progress reporting."""
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        size = 0
        total_size = 0
        stored_md5, stored_sha1 = None, None

        image_type = self.get_image_type()

        try:
            # First get total size for progress reporting
            if image_type == "ewf":
                filenames = pyewf.glob(self.image_path)
                ewf_handle = pyewf.handle()
                try:
                    ewf_handle.open(filenames)
                    total_size = ewf_handle.get_media_size()

                    try:
                        # Attempt to retrieve the stored hash values
                        stored_md5 = ewf_handle.get_hash_value("MD5")
                        stored_sha1 = ewf_handle.get_hash_value("SHA1")
                    except Exception as e:
                        print(f"Unable to retrieve stored hash values: {e}")

                    # Calculate hashes in chunks
                    while True:
                        chunk = ewf_handle.read(CHUNK_SIZE)
                        if not chunk:
                            break

                        hash_md5.update(chunk)
                        hash_sha1.update(chunk)
                        hash_sha256.update(chunk)
                        size += len(chunk)

                        # Report progress safely
                        if progress_callback and total_size > 0:
                            try:
                                progress_callback(size, total_size)
                            except Exception as e:
                                print(f"Progress callback error: {e}")
                finally:
                    ewf_handle.close()

            elif image_type == "raw":
                try:
                    total_size = os.path.getsize(self.image_path)
                    with open(self.image_path, "rb") as f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break

                            hash_md5.update(chunk)
                            hash_sha1.update(chunk)
                            hash_sha256.update(chunk)
                            size += len(chunk)

                            # Report progress safely
                            if progress_callback and total_size > 0:
                                try:
                                    progress_callback(size, total_size)
                                except Exception as e:
                                    print(f"Progress callback error: {e}")
                except Exception as e:
                    print(f"Error reading raw image: {e}")

            # Compile the computed and stored hashes in a dictionary
            hashes = {
                'computed_md5': hash_md5.hexdigest(),
                'computed_sha1': hash_sha1.hexdigest(),
                'computed_sha256': hash_sha256.hexdigest(),
                'size': size,
                'path': self.image_path,
                'stored_md5': stored_md5,
                'stored_sha1': stored_sha1
            }

            return hashes
        except Exception as e:
            print(f"Error calculating hashes: {e}")
            return {
                'computed_md5': 'Error',
                'computed_sha1': 'Error',
                'computed_sha256': 'Error',
                'size': 0,
                'path': self.image_path,
                'stored_md5': None,
                'stored_sha1': None,
                'error': str(e)
            }

    def load_image(self):
        """Load the image and retrieve volume and filesystem information."""
        image_type = self.get_image_type()

        try:
            if image_type == "ewf":
                filenames = pyewf.glob(self.image_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                self.img_info = EWFImgInfo(ewf_handle)
            elif image_type == "raw":
                self.img_info = pytsk3.Img_Info(self.image_path)
            else:
                raise ValueError(f"Unsupported image type: {image_type}")

            try:
                self.volume_info = pytsk3.Volume_Info(self.img_info)
            except Exception:
                self.volume_info = None
                # Attempt to detect a filesystem directly if no volume info
                try:
                    self.fs_info = pytsk3.FS_Info(self.img_info)
                except Exception:
                    self.fs_info = None
                    # If no volume info and no filesystem, mark as wiped
                    self.is_wiped_image = True
        except Exception as e:
            print(f"Error loading image: {e}")
            self.img_info = None
            self.volume_info = None
            self.fs_info = None
            self.is_wiped_image = True

    def has_filesystem(self, start_offset):
        fs_info = self.get_fs_info(start_offset)
        return fs_info is not None

    def is_wiped(self):
        # Image is considered wiped if no volume info, no filesystem detected
        return self.is_wiped_image

    @property
    def partitions(self):
        """Get partitions with caching."""
        if self._partition_cache is None:
            self._partition_cache = self._get_partitions()
        return self._partition_cache

    def get_partitions(self):
        """Retrieve partitions from the loaded image, or indicate unpartitioned space."""
        return self.partitions

    def _get_partitions(self):
        """Internal method to actually retrieve partitions."""
        partitions = []
        if self.volume_info:
            for partition in self.volume_info:
                if not partition.desc:
                    continue
                partitions.append((partition.addr, partition.desc, partition.start, partition.len))
        return partitions

    @lru_cache(maxsize=32)
    def get_fs_info(self, start_offset):
        """Retrieve the FS_Info for a partition, initializing it if necessary."""
        if start_offset not in self.fs_info_cache:
            try:
                fs_info = pytsk3.FS_Info(self.img_info, offset=start_offset * 512)
                self.fs_info_cache[start_offset] = fs_info
            except Exception as e:
                return None
        return self.fs_info_cache[start_offset]

    @lru_cache(maxsize=32)
    def get_fs_type(self, start_offset):
        """Retrieve the file system type for a partition."""
        try:
            fs_type = self.get_fs_info(start_offset).info.ftype

            # Map the file system type to its name
            fs_type_map = {
                pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
                pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
                pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
                pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
                pytsk3.TSK_FS_TYPE_EXFAT: "ExFAT",
                pytsk3.TSK_FS_TYPE_EXT2: "Ext2",
                pytsk3.TSK_FS_TYPE_EXT3: "Ext3",
                pytsk3.TSK_FS_TYPE_EXT4: "Ext4",
                pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
                pytsk3.TSK_FS_TYPE_HFS: "HFS",
                pytsk3.TSK_FS_TYPE_APFS: "APFS"
            }

            return fs_type_map.get(fs_type, "Unknown")
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
        """Get directory contents with caching for performance."""
        cache_key = f"{start_offset}_{inode_number}"

        # Check if we have this directory in our cache
        if cache_key in self._directory_cache:
            return self._directory_cache[cache_key]

        fs = self.get_fs_info(start_offset)
        if fs:
            try:
                directory = fs.open_dir(inode=inode_number) if inode_number else fs.open_dir(path="/")
                entries = []

                for entry in directory:
                    if entry.info.name.name in [b".", b".."]:
                        continue

                    is_directory = False
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        is_directory = True

                    entries.append({
                        "name": entry.info.name.name.decode('utf-8', errors='replace') if hasattr(entry.info.name,
                                                                                                  'name') else None,
                        "is_directory": is_directory,
                        "inode_number": entry.info.meta.addr if entry.info.meta else None,
                        "size": entry.info.meta.size if entry.info.meta and entry.info.meta.size is not None else 0,
                        "accessed": safe_datetime(entry.info.meta.atime) if hasattr(entry.info.meta,
                                                                                    'atime') else "N/A",
                        "modified": safe_datetime(entry.info.meta.mtime) if hasattr(entry.info.meta,
                                                                                    'mtime') else "N/A",
                        "created": safe_datetime(entry.info.meta.crtime) if hasattr(entry.info.meta,
                                                                                    'crtime') else "N/A",
                        "changed": safe_datetime(entry.info.meta.ctime) if hasattr(entry.info.meta, 'ctime') else "N/A",
                    })

                # Cache results
                self._directory_cache[cache_key] = entries
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

        # Use a context manager to handle the temporary file
        with FileSystemUtils.temp_file() as temp_hive_path:
            try:
                with open(temp_hive_path, 'wb') as temp_hive:
                    temp_hive.write(software_hive_data)

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

                return f"{product_name} Version {current_version}\nBuild {current_build} {csd_version}\nOwner: {registered_owner}\nProduct ID: {product_id}"

            except Exception as e:
                print(f"Error parsing SOFTWARE hive: {e}")
                return "Error in parsing OS version"

    def read_unallocated_space(self, start_offset, end_offset):
        try:
            start_byte_offset = start_offset * SECTOR_SIZE
            end_byte_offset = max(end_offset * SECTOR_SIZE, start_byte_offset + SECTOR_SIZE - 1)
            size_in_bytes = end_byte_offset - start_byte_offset + 1  # Ensuring at least some data is read

            if size_in_bytes <= 0:
                print("Invalid size for unallocated space, adjusting to read at least one sector.")
                size_in_bytes = SECTOR_SIZE  # Adjust to read at least one sector

            # For large blocks, read in chunks instead of all at once
            if size_in_bytes > CHUNK_SIZE:
                chunks = []
                for offset in range(start_byte_offset, end_byte_offset, CHUNK_SIZE):
                    remaining = min(CHUNK_SIZE, end_byte_offset - offset + 1)
                    chunk = self.img_info.read(offset, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)

                if not chunks:
                    return None

                return b''.join(chunks)
            else:
                unallocated_space = self.img_info.read(start_byte_offset, size_in_bytes)
                if unallocated_space is None or len(unallocated_space) == 0:
                    print(f"Failed to read unallocated space from offset {start_byte_offset} to {end_byte_offset}")
                    return None
                return unallocated_space

        except Exception as e:
            print(f"Error reading unallocated space: {e}")
            return None

    def open_image(self):
        if self.get_image_type() == "ewf":
            filenames = pyewf.glob(self.image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            return EWFImgInfo(ewf_handle)
        else:
            return pytsk3.Img_Info(self.image_path)

    def list_files(self, extensions=None):
        """Get a list of all files with given extensions."""
        files_list = []
        img_info = self.open_image()

        try:
            volume_info = pytsk3.Volume_Info(img_info)
            for partition in volume_info:
                if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    self.process_partition(img_info, partition.start * SECTOR_SIZE, files_list, extensions)
        except IOError:
            self.process_partition(img_info, 0, files_list, extensions)

        return files_list

    def process_partition(self, img_info, offset, files_list, extensions):
        try:
            fs_info = pytsk3.FS_Info(img_info, offset=offset)
            self._recursive_file_search(fs_info, fs_info.open_dir(path="/"), "/", files_list, extensions)
        except IOError as e:
            print(f"Unable to open filesystem at offset {offset}: {e}")

    def _recursive_file_search(self, fs_info, directory, parent_path, files_list, extensions, search_query=None):
        for entry in directory:
            if entry.info.name.name in [b".", b".."]:
                continue

            try:
                file_name = entry.info.name.name.decode("utf-8", errors='replace')
                file_extension = os.path.splitext(file_name)[1].lower()

                if search_query:
                    # If there's a search query, check if the file name contains the query
                    if search_query.startswith('.'):
                        # If the search query is an extension (e.g., '.jpg')
                        query_matches = file_extension == search_query.lower()
                    else:
                        # If the search query is a file name or part of it
                        query_matches = search_query.lower() in file_name.lower()
                else:
                    # If no search query, handle as before based on extensions
                    query_matches = extensions is None or file_extension in extensions or '' in extensions

                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub_directory = fs_info.open_dir(inode=entry.info.meta.addr)
                        self._recursive_file_search(fs_info, sub_directory, os.path.join(parent_path, file_name),
                                                    files_list,
                                                    extensions, search_query)
                    except IOError as e:
                        print(f"Unable to open directory: {e}")

                elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and query_matches:
                    file_info = self._get_file_metadata(entry, parent_path)
                    files_list.append(file_info)
            except UnicodeDecodeError:
                continue  # Skip entries with encoding issues

    def _get_file_metadata(self, entry, parent_path):
        try:
            file_name = entry.info.name.name.decode("utf-8", errors='replace')
            return {
                "name": file_name,
                "path": os.path.join(parent_path, file_name),
                "size": entry.info.meta.size if entry.info.meta else 0,
                "accessed": safe_datetime(entry.info.meta.atime if entry.info.meta else None),
                "modified": safe_datetime(entry.info.meta.mtime if entry.info.meta else None),
                "created": safe_datetime(entry.info.meta.crtime if hasattr(entry.info.meta, 'crtime') else None),
                "changed": safe_datetime(entry.info.meta.ctime if entry.info.meta else None),
                "inode_item": str(entry.info.meta.addr if entry.info.meta else 0),
            }
        except Exception as e:
            print(f"Error getting file metadata: {e}")
            # Return basic info when we encounter errors
            return {
                "name": "Error reading file",
                "path": parent_path + "/unknown",
                "size": 0,
                "accessed": "N/A",
                "modified": "N/A",
                "created": "N/A",
                "changed": "N/A",
                "inode_item": "0",
            }

    def search_files(self, search_query=None):
        files_list = []
        img_info = self.open_image()

        try:
            volume_info = pytsk3.Volume_Info(img_info)
            for partition in volume_info:
                if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    self.process_partition_search(img_info, partition.start * SECTOR_SIZE, files_list, search_query)
        except IOError:
            # No volume information, attempt to read as a single filesystem
            self.process_partition_search(img_info, 0, files_list, search_query)

        return files_list

    def process_partition_search(self, img_info, offset, files_list, search_query):
        try:
            fs_info = pytsk3.FS_Info(img_info, offset=offset)
            self._recursive_file_search(fs_info, fs_info.open_dir(path="/"), "/", files_list, None, search_query)
        except IOError as e:
            print(f"Unable to open file system for search: {e}")

    def get_file_content(self, inode_number, offset):
        fs = self.get_fs_info(offset)
        if not fs:
            return None, None

        try:
            file_obj = fs.open_meta(inode=inode_number)
            if file_obj.info.meta.size == 0:
                print("File has no content or is a special metafile!")
                return None, None

            # For large files, read in chunks
            file_size = file_obj.info.meta.size
            if file_size > CHUNK_SIZE:
                chunks = []
                for chunk_offset in range(0, file_size, CHUNK_SIZE):
                    chunk_size = min(CHUNK_SIZE, file_size - chunk_offset)
                    chunk = file_obj.read_random(chunk_offset, chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                content = b''.join(chunks)
            else:
                # Small file, read all at once
                content = file_obj.read_random(0, file_size)

            metadata = file_obj.info.meta  # Collect the metadata
            return content, metadata

        except Exception as e:
            print(f"Error reading file: {e}")
            return None, None

    # Replace static method assignment with an actual instance method
    def get_readable_size(self, size_in_bytes):
        """Convert bytes to a human-readable string, wrapper for the static utility method."""
        return FileSystemUtils.get_readable_size(size_in_bytes)


# DatabaseManager class with optimization
class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.db_conn = None
        self._icon_cache = {}  # Cache for icon paths
        self._connect()

    def _connect(self):
        """Establish a connection to the database with proper error handling."""
        try:
            self.db_conn = sqlite3_connect(self.db_path)
            # Enable foreign keys
            self.db_conn.execute("PRAGMA foreign_keys = ON")
        except Exception as e:
            print(f"Error connecting to database: {e}")
            self.db_conn = None

    def __del__(self):
        """Ensure connection is closed when object is destroyed."""
        self.close()

    def close(self):
        """Explicitly close the database connection."""
        if self.db_conn:
            try:
                self.db_conn.close()
                self.db_conn = None
            except Exception as e:
                print(f"Error closing database connection: {e}")

    def get_icon_path(self, icon_type, identifier):
        """Get icon path with caching for performance."""
        # Check cache first
        cache_key = f"{icon_type}_{identifier}"
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]

        if not self.db_conn:
            self._connect()
            if not self.db_conn:
                return 'Icons/mimetypes/application-x-zerosize.svg'

        try:
            c = self.db_conn.cursor()
            # First, try to get the icon for the specific identifier
            c.execute("SELECT path FROM icons WHERE type = ? AND extention = ?", (icon_type, identifier))
            result = c.fetchone()

            # If a specific icon exists for the identifier, cache and return it
            if result:
                self._icon_cache[cache_key] = result[0]
                return result[0]

            # If no specific icon exists, check for default icons
            if icon_type == 'folder':
                c.execute("SELECT path FROM icons WHERE type = ? AND extention = 'folder'", (icon_type,))
                result = c.fetchone()
                default_path = result[0] if result else 'Icons/mimetypes/application-x-zerosize.svg'
            else:
                # Try to find a generic icon for the file type first
                generic_key = f"{icon_type}_generic"
                if generic_key not in self._icon_cache:
                    c.execute("SELECT path FROM icons WHERE type = ? AND extention = 'generic'", (icon_type,))
                    result = c.fetchone()
                    self._icon_cache[generic_key] = result[
                        0] if result else 'Icons/mimetypes/application-x-zerosize.svg'

                default_path = self._icon_cache[generic_key]

            # Cache the result before returning
            self._icon_cache[cache_key] = default_path
            return default_path

        except Exception as e:
            print(f"Error fetching icon: {e}")
            return 'Icons/mimetypes/application-x-zerosize.svg'
        finally:
            if 'c' in locals():
                c.close()


# ImageManager class with optimizations
class ImageManager(QThread):
    operationCompleted = Signal(bool, str)  # Signal to indicate operation completion
    showMessage = Signal(str, str)  # Signal to show a message (Title, Content)
    progressUpdated = Signal(int)  # Signal for progress updates

    def __init__(self):
        super().__init__()
        self.operation = None
        self.image_path = None
        self.file_name = None
        self.is_running = False
        self._process = None

    def __del__(self):
        self.cleanup_resources()

    def cleanup_resources(self):
        """Clean up any resources used by the image mounting process."""
        if self._process and hasattr(self._process, 'poll') and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process = None
            except:
                pass

    def run(self):
        self.is_running = True
        system = platform.system()

        try:
            if self.operation == 'mount' and self.image_path:
                if system == 'Darwin':  # macOS
                    self._mount_image_macos()
                elif system == 'Linux':  # Linux (including Kali)
                    self._mount_image_linux()
                elif system == 'Windows':  # Windows
                    self._mount_image_windows()
                else:
                    raise Exception("Unsupported Operating System")
            elif self.operation == 'dismount':
                if system == 'Darwin':
                    self._dismount_image_macos()
                elif system == 'Linux':
                    self._dismount_image_linux()
                elif system == 'Windows':
                    self._dismount_image_windows()
                else:
                    raise Exception("Unsupported Operating System")
        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to {self.operation} the image. Error: {e}")
        finally:
            self.is_running = False

    def _mount_image_windows(self):
        """Mount image on Windows using Arsenal Image Mounter."""
        try:
            aim_path = 'tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe'
            if not os.path.exists(aim_path):
                self.operationCompleted.emit(False, "Arsenal Image Mounter not found. Please install it.")
                return

            cmd = [
                aim_path,
                '--mount',
                '--readonly',
                f'--filename={self.image_path}'
            ]

            # Use subprocess.Popen with proper parameter checking
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )

            # Wait for the process to complete or timeout after 30 seconds
            try:
                stdout, stderr = self._process.communicate(timeout=30)
                if self._process.returncode != 0:
                    error_msg = stderr.decode('utf-8', errors='replace')
                    self.operationCompleted.emit(False, f"Failed to mount the image: {error_msg}")
                    return
                self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully.")
            except subprocess.TimeoutExpired:
                # Process is taking too long, but this is sometimes normal for mounting
                # We'll assume it's working in the background
                self.operationCompleted.emit(True,
                                             f"Image {self.file_name} mount initiated. Check Windows Disk Management.")

        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on Windows. Error: {e}")

    def _mount_image_macos(self):
        """Mount image on macOS using hdiutil."""
        try:
            # Step 1: Attach the image without mounting it
            attach_cmd = [
                'hdiutil', 'attach',
                '-imagekey', 'diskimage-class=CRawDiskImage',
                '-nomount', self.image_path
            ]

            attach_process = subprocess.Popen(
                attach_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            # Wait with timeout
            try:
                attach_output, _ = attach_process.communicate(timeout=30)
                if attach_process.returncode != 0:
                    self.operationCompleted.emit(False, f"Failed to attach image: {attach_output.decode()}")
                    return
            except subprocess.TimeoutExpired:
                attach_process.kill()
                self.operationCompleted.emit(False, "Attaching image timed out")
                return

            attach_output = attach_output.decode().strip()

            # Step 2: Add a short delay to ensure the system has time to process the attachment
            QThread.msleep(1000)  # More reliable than time.sleep in a QThread

            # Step 3: Extract the disk identifier from the output
            lines = attach_output.splitlines()
            disk_identifier = None

            for line in lines:
                if line.startswith('/dev/disk'):
                    disk_identifier = line.split()[0]
                    break

            if not disk_identifier:
                self.operationCompleted.emit(False, "Failed to find disk identifier after attaching the image.")
                return

            # Step 4: Mount the disk using the identifier
            mount_cmd = ['hdiutil', 'mount', disk_identifier]
            mount_process = subprocess.Popen(
                mount_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            try:
                mount_output, _ = mount_process.communicate(timeout=30)
                if mount_process.returncode != 0:
                    self.operationCompleted.emit(False, f"Failed to mount disk: {mount_output.decode()}")
                    return
            except subprocess.TimeoutExpired:
                mount_process.kill()
                self.operationCompleted.emit(False, "Mounting timed out")
                return

            mount_output = mount_output.decode().strip()

            # Step 5: Extract the mount point (e.g., /Volumes/LABEL2)
            lines = mount_output.splitlines()
            mount_point = None

            for line in lines:
                if line.startswith('/dev/') and '\t' in line:
                    mount_point = line.split('\t')[1]
                    break

            if mount_point:
                # Emit success with the mount point
                self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully at {mount_point}.")
            else:
                self.operationCompleted.emit(False, f"Image {self.file_name} mounted, but no volumes were detected.")

        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on macOS. Error: {e.output.decode()}")
        except Exception as e:
            self.operationCompleted.emit(False, f"Unexpected error mounting image: {str(e)}")

    def _mount_image_linux(self):
        """Mount image on Linux using appropriate tools."""
        try:
            if self.image_path.lower().endswith('.e01'):
                # Use ewfmount for .e01 images
                ewf_mount_dir = '/mnt/ewf'

                # Create mount directory if it doesn't exist
                if not os.path.exists(ewf_mount_dir):
                    os.makedirs(ewf_mount_dir, exist_ok=True)

                # Run ewfmount with proper error handling
                ewf_cmd = ['sudo', 'ewfmount', self.image_path, ewf_mount_dir]
                ewf_process = subprocess.run(ewf_cmd, check=True, capture_output=True, text=True)

                # Get the partition table info using fdisk
                fdisk_cmd = ['fdisk', '-l', os.path.join(ewf_mount_dir, 'ewf1')]
                fdisk_output = subprocess.check_output(fdisk_cmd, text=True)

                # Find the partition start sector
                partition_start_sector = None
                for line in fdisk_output.splitlines():
                    if '/dev/' in line and not line.startswith('Disk '):
                        # Assuming you want the first partition listed
                        parts = line.split()
                        if len(parts) > 1:
                            try:
                                partition_start_sector = int(parts[1])
                                break
                            except (ValueError, IndexError):
                                continue

                if partition_start_sector is None:
                    raise Exception("Failed to find partition start sector in the EWF image.")

                # Calculate the byte offset
                byte_offset = partition_start_sector * 512

                # Mount the partition using the calculated offset
                mount_dir = '/mnt/disk_image'
                os.makedirs(mount_dir, exist_ok=True)

                mount_cmd = [
                    'sudo', 'mount', '-o',
                    f'ro,loop,offset={byte_offset}',
                    os.path.join(ewf_mount_dir, 'ewf1'),
                    mount_dir
                ]

                mount_process = subprocess.run(mount_cmd, check=True, capture_output=True, text=True)

            else:
                # Use mount for .dd images and other raw formats
                mount_dir = '/mnt/disk_image'
                os.makedirs(mount_dir, exist_ok=True)

                mount_cmd = [
                    'sudo', 'mount', '-o', 'loop,ro',
                    self.image_path, mount_dir
                ]

                mount_process = subprocess.run(mount_cmd, check=True, capture_output=True, text=True)

            self.operationCompleted.emit(True, f"Image {self.file_name} mounted successfully.")
        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to mount the image on Linux. Error: {e.stderr}")
        except Exception as e:
            self.operationCompleted.emit(False, f"An unexpected error occurred: {str(e)}")

    def _dismount_image_linux(self):
        """Dismount image on Linux."""
        try:
            # Attempt to unmount the disk image
            disk_cmd = ['sudo', 'umount', '/mnt/disk_image']
            ewf_cmd = ['sudo', 'umount', '/mnt/ewf']

            try:
                # Try to unmount disk image
                subprocess.run(disk_cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                print(f"Warning: Could not unmount disk image: {e.stderr}")

            try:
                # Try to unmount EWF
                subprocess.run(ewf_cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                print(f"Warning: Could not unmount EWF: {e.stderr}")

            self.operationCompleted.emit(True, "Image was dismounted successfully.")
        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to dismount the image on Linux. Error: {str(e)}")

    def _dismount_image_macos(self):
        """Dismount image on macOS using hdiutil."""
        try:
            # Get the list of currently mounted disk images
            info_cmd = ['hdiutil', 'info']
            info_process = subprocess.Popen(
                info_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )

            try:
                info_output, _ = info_process.communicate(timeout=10)
                if info_process.returncode != 0:
                    self.operationCompleted.emit(False, f"Failed to get mounted disks: {info_output.decode()}")
                    return
            except subprocess.TimeoutExpired:
                info_process.kill()
                self.operationCompleted.emit(False, "Getting disk info timed out")
                return

            info_output = info_output.decode()

            lines = info_output.splitlines()
            mounted_disks = []
            current_image_path = None

            # Parse the output to find the disk identifier for the given image path
            for line in lines:
                if 'image-path' in line:
                    current_image_path = line.split(': ')[1].strip()
                elif line.startswith('/dev/disk') and current_image_path == self.image_path:
                    disk_identifier = line.split()[0]
                    mounted_disks.append(disk_identifier)
                    current_image_path = None  # Reset after finding the corresponding disk

            if not mounted_disks:
                # If we're not targeting a specific image, try to unmount all mounted disks
                if not self.image_path:
                    for line in lines:
                        if line.startswith('/dev/disk'):
                            disk_identifier = line.split()[0]
                            mounted_disks.append(disk_identifier)

                if not mounted_disks:
                    self.operationCompleted.emit(False, "No mounted images found.")
                    return

            # Attempt to dismount all found disk identifiers
            success = False
            errors = []

            for disk_identifier in mounted_disks:
                try:
                    detach_cmd = ['hdiutil', 'detach', disk_identifier]
                    detach_process = subprocess.run(detach_cmd, check=True, capture_output=True, text=True)
                    success = True
                except subprocess.CalledProcessError:
                    try:
                        # If normal detach fails, attempt a forced detach
                        force_detach_cmd = ['hdiutil', 'detach', '-force', disk_identifier]
                        force_process = subprocess.run(force_detach_cmd, check=True, capture_output=True, text=True)
                        success = True
                    except subprocess.CalledProcessError as e:
                        errors.append(f"Failed to detach {disk_identifier}: {e.stderr}")

            if success:
                self.operationCompleted.emit(True, "Image was dismounted successfully.")
            else:
                self.operationCompleted.emit(False, "Failed to dismount all images: " + "; ".join(errors))

        except Exception as e:
            self.operationCompleted.emit(False, f"Failed to dismount the image on macOS: {str(e)}")

    def _dismount_image_windows(self):
        """Dismount image on Windows using Arsenal Image Mounter."""
        try:
            aim_path = 'tools/Arsenal-Image-Mounter-v3.10.257/aim_cli.exe'
            if not os.path.exists(aim_path):
                self.operationCompleted.emit(False, "Arsenal Image Mounter not found. Please install it.")
                return

            cmd = [aim_path, '--dismount']

            # Use subprocess.run with proper error handling
            process = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )

            self.operationCompleted.emit(True, "Image was dismounted successfully.")
        except subprocess.CalledProcessError as e:
            self.operationCompleted.emit(False, f"Failed to dismount the image on Windows. Error: {e.stderr}")
        except Exception as e:
            self.operationCompleted.emit(False, f"Unexpected error dismounting image: {str(e)}")

    def dismount_image(self):
        """Attempt to dismount the currently mounted image."""
        if self.is_running:
            self.showMessage.emit("Operation in Progress", "Please wait for the current operation to complete.")
            return

        self.operation = 'dismount'
        self.start()

    def mount_image(self):
        """Attempt to mount an image after prompting the user to select one."""
        if self.is_running:
            self.showMessage.emit("Operation in Progress", "Please wait for the current operation to complete.")
            return

        system = platform.system()

        if system == 'Darwin':  # macOS
            # Only allow .raw and .dd files on macOS
            supported_formats = "Raw Files (*.raw *.dd);;All Files (*)"
            valid_extensions = ['.raw', '.dd']
        else:
            # Original behavior for other operating systems
            supported_formats = (
                "EWF Files (*.E01);;Raw Files (*.dd);;AFF4 Files (*.aff4);;"
                "VHD Files (*.vhd);;VDI Files (*.vdi);;XVA Files (*.xva);;"
                "VMDK Files (*.vmdk);;OVA Files (*.ova);;QCOW Files (*.qcow *.qcow2);;All Files (*)"
            )
            valid_extensions = ['.e01', '.dd', '.aff4', '.vhd', '.vdi', '.xva', '.vmdk', '.ova', '.qcow', '.qcow2']

        while True:
            image_path, _ = QFileDialog.getOpenFileName(QWidget(None), "Select Disk Image", "", supported_formats)

            if not image_path:
                return  # No image was selected, so just exit the function

            file_extension = os.path.splitext(image_path)[1].lower()
            if file_extension in valid_extensions:
                break  # Exit the loop if a valid image was selected
            else:
                # Show an error message for an invalid file
                QMessageBox.warning(QWidget(None), "Invalid File Type", "The selected file is not a valid disk image.")

        # Normalize the path
        self.image_path = os.path.normpath(image_path)
        self.file_name = os.path.basename(self.image_path)
        self.operation = 'mount'
        self.start()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Create a database manager for icon lookup
        self.db_manager = DatabaseManager('tools/new_database_mappings.db')

        # Initialize variables for tracking
        self.current_selected_data = None
        self.current_offset = None
        self.current_path = "/"  # Initialize current path
        self.image_handler = None
        self._directory_cache = {}

        # Load configuration
        self.api_keys = configparser.ConfigParser()
        try:
            self.api_keys.read('config.ini')
        except Exception as e:
            print(f"Error loading configuration: {e}")

        # Initialize instance attributes
        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.image_manager = ImageManager()
        self.current_selected_data = None

        self.evidence_files = []

        self.image_manager.operationCompleted.connect(
            lambda success, message: (
                QMessageBox.information(self, "Image Operation", message) if success else QMessageBox.critical(self,
                                                                                                               "Image "
                                                                                                               "Operation",
                                                                                                               message),
                setattr(self, "image_mounted", not self.image_mounted) if success else None)[1])

        self.initialize_ui()

    def initialize_ui(self):
        self.setWindowTitle('Trace 1.1.0')

        # Set application icon for all platforms
        app_icon = QIcon('Icons/logo_prev_ui.png')
        self.setWindowIcon(app_icon)

        # Set taskbar/dock icon for different platforms
        if os.name == 'nt':  # Windows
            import ctypes
            myappid = 'Trace'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        else:  # macOS and Linux
            # For macOS and Linux, setting the app icon at application level
            QApplication.instance().setWindowIcon(app_icon)

        self.setGeometry(100, 100, 1200, 800)

        menu_bar = QMenuBar(self)
        file_actions = {
            'Add Evidence File': self.load_image_evidence,
            'Remove Evidence File': self.remove_image_evidence,
            'Image Mounting': self.image_manager.mount_image,
            'Image Unmounting': self.image_manager.dismount_image,
            'separator': None,  # This will add a separator
            'Exit': self.close
        }

        self.create_menu(menu_bar, 'File', file_actions)

        view_menu = QMenu('View', self)

        # Create the "Full Screen" action and connect it to the showFullScreen slot
        full_screen_action = QAction("Full Screen", self)
        full_screen_action.triggered.connect(self.showFullScreen)
        view_menu.addAction(full_screen_action)

        # Create the "Normal Screen" action and connect it to the showNormal slot
        normal_screen_action = QAction("Normal Screen", self)
        normal_screen_action.triggered.connect(self.showNormal)
        view_menu.addAction(normal_screen_action)

        # Add a separator
        view_menu.addSeparator()

        # **Add Theme Selection Actions**
        # Create an action group for themes
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)  # Only one theme can be selected at a time

        # Light Theme Action
        light_theme_action = QAction("Light Mode", self)
        light_theme_action.setCheckable(True)
        light_theme_action.setChecked(True)  # Set Light Theme as default
        light_theme_action.triggered.connect(lambda: self.apply_stylesheet('light'))
        theme_group.addAction(light_theme_action)
        view_menu.addAction(light_theme_action)

        # Dark Theme Action
        dark_theme_action = QAction("Dark Mode", self)
        dark_theme_action.setCheckable(True)
        dark_theme_action.triggered.connect(lambda: self.apply_stylesheet('dark'))
        theme_group.addAction(dark_theme_action)
        view_menu.addAction(dark_theme_action)

        # Add the view menu to the menu bar
        menu_bar.addMenu(view_menu)

        # **Apply the default stylesheet**
        self.apply_stylesheet('light')

        tools_menu = QMenu('Tools', self)

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.verify_image)
        tools_menu.addAction(verify_image_action)

        conversion_action = QAction("Convert E01 to DD/RAW", self)
        conversion_action.triggered.connect(self.show_conversion_widget)
        tools_menu.addAction(conversion_action)

        veriphone_api_action = QAction("Veriphone API", self)
        veriphone_api_action.triggered.connect(self.show_veriphone_widget)
        tools_menu.addAction(veriphone_api_action)

        # Add "Options" menu for API key configuration
        options_menu = QMenu('Options', self)
        api_key_action = QAction("API Keys", self)
        api_key_action.triggered.connect(self.show_api_key_dialog)
        options_menu.addAction(api_key_action)

        help_menu = QMenu('Help', self)
        help_menu.addAction("About")
        help_menu.triggered.connect(lambda: AboutDialog(self).exec_())

        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(options_menu)
        menu_bar.addMenu(help_menu)

        self.setMenuBar(menu_bar)

        self.main_toolbar = QToolBar()
        self.main_toolbar.setMovable(False)
        self.main_toolbar.setFloatable(False)
        self.main_toolbar.addAction(
            self.create_action('Icons/icons8-evidence-48.png', "Load Image", self.load_image_evidence))
        self.main_toolbar.addAction(
            self.create_action('Icons/icons8-evidence-96.png', "Remove Image", self.remove_image_evidence))
        self.main_toolbar.addSeparator()

        # Create verify_image_button as an attribute of MainWindow
        self.verify_image_button = self.create_action('Icons/icons8-verify-blue.png', "Verify Image", self.verify_image)
        self.main_toolbar.addAction(self.verify_image_button)

        self.main_toolbar.addSeparator()
        self.main_toolbar.addAction(
            self.create_action('Icons/devices/icons8-hard-disk-48.png', "Mount Image", self.image_manager.mount_image))
        self.main_toolbar.addAction(self.create_action('Icons/devices/icons8-hard-disk-48_red.png', "Unmount Image",
                                                       self.image_manager.dismount_image))

        # Add spacer to push directory up button to the end
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.main_toolbar.addWidget(spacer)

        # Add directory up button to main toolbar
        self.go_up_action = QAction(QIcon("Icons/icons8-thick-arrow-pointing-up-50.png"), "Go Up Directory", self)
        self.go_up_action.triggered.connect(self.navigate_up_directory)
        self.go_up_action.setEnabled(False)
        self.main_toolbar.addAction(self.go_up_action)

        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)

        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setIconSize(QSize(16, 16))
        self.tree_viewer.setHeaderHidden(True)
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        tree_dock = QDockWidget('Tree View', self)

        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        self.result_viewer = QTabWidget(self)
        self.setCentralWidget(self.result_viewer)

        self.listing_table = QTableWidget()
        self.listing_table.setSortingEnabled(True)
        self.listing_table.verticalHeader().setVisible(False)
        self.listing_table.setObjectName("listingTable")  # Set object name for specific CSS styling

        # Use alternate row colors
        self.listing_table.setAlternatingRowColors(True)
        self.listing_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(9)  # Increase column count to 9 to include path

        # Create a QVBoxLayout for the listing tab
        self.listing_layout = QVBoxLayout()
        self.listing_layout.setContentsMargins(0, 0, 0, 0)  # Set to zero to remove margins
        self.listing_layout.setSpacing(0)  # Remove spacing between widgets

        # Add the toolbar and listing table to the layout
        self.listing_layout.addWidget(self.listing_table)  # <-- Table added below

        # Create a widget to hold the layout
        self.listing_widget = QWidget()
        self.listing_widget.setLayout(self.listing_layout)

        # Set the horizontal header with dynamic resizing
        header = self.listing_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)  # Make all columns interactively resizable
        # Set default widths for columns to have sensible starting sizes
        self.listing_table.setColumnWidth(0, 200)  # Name column
        self.listing_table.setColumnWidth(1, 60)  # Inode column
        self.listing_table.setColumnWidth(2, 100)  # Type column
        self.listing_table.setColumnWidth(3, 80)  # Size column
        self.listing_table.setColumnWidth(4, 150)  # Created Date column
        self.listing_table.setColumnWidth(5, 150)  # Accessed Date column
        self.listing_table.setColumnWidth(6, 150)  # Modified Date column
        self.listing_table.setColumnWidth(7, 150)  # Changed Date column
        self.listing_table.setColumnWidth(8, 200)  # Path column

        # Remove any extra space in the header
        header.setStyleSheet("QHeaderView::section { margin-top: 0px; padding-top: 2px; }")
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Set the header labels
        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date', 'Modified Date', 'Changed Date', 'Path']
        )

        self.listing_table.itemDoubleClicked.connect(self.on_listing_table_item_clicked)
        self.listing_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listing_table.customContextMenuRequested.connect(self.open_listing_context_menu)
        self.listing_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Set the color of the selected row
        palette = self.listing_table.palette()
        palette.setBrush(QPalette.Highlight, QBrush(Qt.lightGray))  # Change Qt.lightGray to your preferred color
        self.listing_table.setPalette(palette)

        header = self.listing_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)

        self.result_viewer.addTab(self.listing_widget, 'Listing')

        self.deleted_files_widget = FileCarvingWidget(self)
        self.result_viewer.addTab(self.deleted_files_widget, 'Deleted Files')

        self.registry_extractor_widget = RegistryExtractor(self.image_handler)
        self.result_viewer.addTab(self.registry_extractor_widget, 'Registry')

        # #add tab for displaying all files chosen by user
        self.file_search_widget = FileSearchWidget(self.image_handler)
        self.result_viewer.addTab(self.file_search_widget, 'File Search')

        self.viewer_tab = QTabWidget(self)

        self.hex_viewer = HexViewer(self)
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        self.text_viewer = TextViewer(self)
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        self.application_viewer = UnifiedViewer(self)
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        self.metadata_viewer = MetadataViewer(self.image_handler)
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        self.exif_viewer = ExifViewer(self)
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        self.virus_total_api = VirusTotal()
        self.viewer_tab.addTab(self.virus_total_api, 'Virus Total API')

        # Set the API key if it exists
        virus_total_key = self.api_keys.get('API_KEYS', 'virustotal', fallback='')
        self.virus_total_api.set_api_key(virus_total_key)

        self.viewer_dock = QDockWidget('Utils', self)
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        # disable all tabs before loading an image file
        self.enable_tabs(False)

    def apply_stylesheet(self, theme='light'):
        if theme == 'dark':
            qss_file = 'styles/dark_theme.qss'
        else:
            qss_file = 'styles/light_theme.qss'  # Ensure your existing QSS file is named 'light_theme.qss'

        try:
            with open(qss_file, 'r') as f:
                stylesheet = f.read()
            QApplication.instance().setStyleSheet(stylesheet)
        except Exception as e:
            print(f"Error loading stylesheet {qss_file}: {e}")

    def show_api_key_dialog(self):
        # Create a dialog to get API keys from the user
        dialog = QDialog(self)
        dialog.setWindowTitle("API Key Configuration")
        dialog.setFixedWidth(600)  # Set a fixed width to accommodate longer API keys

        # Set layout as a form layout for better presentation
        layout = QFormLayout()
        layout.setSpacing(10)  # Add some spacing between fields
        layout.setContentsMargins(15, 15, 15, 15)  # Set content margins for better visual aesthetics

        # VirusTotal API Key
        virus_total_label = QLabel("VirusTotal API Key:")
        virus_total_input = QLineEdit()
        virus_total_input.setText(self.api_keys.get('API_KEYS', 'virustotal', fallback=''))
        virus_total_input.setMinimumWidth(400)  # Set a minimum width for the input field
        layout.addRow(virus_total_label, virus_total_input)

        # Veriphone API Key
        veriphone_label = QLabel("Veriphone API Key:")
        veriphone_input = QLineEdit()
        veriphone_input.setText(self.api_keys.get('API_KEYS', 'veriphone', fallback=''))
        veriphone_input.setMinimumWidth(400)  # Set a minimum width for the input field
        layout.addRow(veriphone_label, veriphone_input)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(
            lambda: self.save_api_keys(virus_total_input.text(), veriphone_input.text(), dialog))
        button_box.rejected.connect(dialog.reject)
        layout.addRow(button_box)

        # Set layout and execute dialog
        dialog.setLayout(layout)
        dialog.exec_()

    def save_api_keys(self, virus_total_key, veriphone_key, dialog):
        # Save the API keys in a configuration file
        if not self.api_keys.has_section('API_KEYS'):
            self.api_keys.add_section('API_KEYS')

        self.api_keys.set('API_KEYS', 'virustotal', virus_total_key)
        self.api_keys.set('API_KEYS', 'veriphone', veriphone_key)

        with open('config.ini', 'w') as config_file:
            self.api_keys.write(config_file)

        dialog.accept()

        # Pass the updated API keys to the appropriate modules
        self.virus_total_api.set_api_key(virus_total_key)

        # Set Veriphone API key only if the widget is created
        if hasattr(self, 'veriphone_widget'):
            self.veriphone_widget.set_api_key(veriphone_key)

    def show_conversion_widget(self):
        # Show the conversion widget
        self.select_dialog = Main()
        self.select_dialog.show()

    def show_veriphone_widget(self):
        # Create the VeriphoneWidget only if it hasn't been created yet
        if not hasattr(self, 'veriphone_widget'):
            self.veriphone_widget = VeriphoneWidget()
            # Set the API key after creating the widget
            veriphone_key = self.api_keys.get('API_KEYS', 'veriphone', fallback='')
            self.veriphone_widget.set_api_key(veriphone_key)
        self.veriphone_widget.show()

    def verify_image(self):
        if self.image_handler is None:
            QMessageBox.warning(self, "Verify Image", "No image is currently loaded.")
            return

        # Show the verification widget
        self.verification_widget = VerificationWidget(self.image_handler)

        # Connect a signal when the verification widget is closed to update the icon
        self.verification_widget.closeEvent = lambda event: self.on_verification_closed(event)

        # Show the widget
        self.verification_widget.show()

    def on_verification_closed(self, event):
        """Handle the verification widget being closed."""
        # Make sure verify_image_button exists before trying to change its icon
        if hasattr(self, 'verify_image_button'):
            if hasattr(self.verification_widget, 'is_verified') and self.verification_widget.is_verified:
                self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-48_gren.png'))
            else:
                self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

        # Call the original closeEvent to close the widget
        QWidget.closeEvent(self.verification_widget, event)

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.deleted_files_widget.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)

    def create_menu(self, menu_bar, menu_name, actions):
        menu = QMenu(menu_name, self)
        for action_name, action_function in actions.items():
            if action_name == 'separator':
                menu.addSeparator()
            else:
                action = menu.addAction(action_name)
                action.triggered.connect(action_function)
        menu_bar.addMenu(menu)
        return menu

    @staticmethod
    def create_tree_item(parent, text, icon_path, data):
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, data)
        return item

    def on_viewer_dock_focus(self, visible):
        if visible:  # If the QDockWidget is focused/visible
            self.viewer_dock.setMaximumSize(16777215, 16777215)  # Remove size constraints
        else:  # If the QDockWidget loses focus
            current_height = self.viewer_dock.size().height()  # Get the current height
            self.viewer_dock.setMinimumSize(1200, current_height)
            self.viewer_dock.setMaximumSize(1200, current_height)

    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)
        self.clear_viewers()
        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False
        self.file_search_widget.clear()
        self.evidence_files.clear()
        self.deleted_files_widget.clear()

        # Disable directory up button
        self.go_up_action.setEnabled(False)

    def clear_viewers(self):
        self.hex_viewer.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_viewer.clear()
        self.exif_viewer.clear_content()
        self.registry_extractor_widget.clear()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit Confirmation', 'Are you sure you want to exit?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if self.image_mounted:
                dismount_reply = QMessageBox.question(self, 'Dismount Image',
                                                      'Do you want to dismount the mounted image before exiting?',
                                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                      QMessageBox.StandardButton.Yes)

                if dismount_reply == QMessageBox.StandardButton.Yes:
                    # Dismount the image
                    self.image_manager.dismount_image()

            # Show a progress dialog during cleanup
            progress = QProgressDialog("Cleaning up resources...", None, 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.setCancelButton(None)  # No cancel button
            progress.setWindowTitle("Shutting Down")

            # Set a determinate range so the progress bar shows properly
            progress.setRange(0, 100)
            progress.setValue(0)

            # Set a more compact width
            progress.setMinimumWidth(300)

            # Set a fixed size that's more compact
            dialog_width = 300
            progress.resize(dialog_width, progress.height())

            # Improve the progress bar appearance with CSS
            progress.setStyleSheet("""
                QProgressBar {
                    border: 2px solid grey;
                    border-radius: 5px;
                    text-align: center;
                    height: 20px;
                    margin: 0px 10px;  /* Reduced horizontal margin */
                }

                QProgressBar::chunk {
                    background-color: #05B8CC;
                    width: 10px;  /* Minimum chunk width */
                }

                QLabel {
                    margin-bottom: 5px;
                    font-size: 12px;
                }
            """)

            # Center the progress dialog on the parent window
            progress.setGeometry(
                self.geometry().center().x() - dialog_width // 2,
                self.geometry().center().y() - progress.height() // 2,
                dialog_width,
                progress.height()
            )

            progress.show()
            QApplication.processEvents()

            # Clean up resources properly before exiting
            self.cleanup_resources()

            # Give resources time to properly clean up and update progress
            total_steps = 10
            for i in range(total_steps + 1):
                progress.setValue(i * (100 // total_steps))
                QApplication.processEvents()
                time.sleep(0.1)

            progress.close()

            # Final processing before exit
            QApplication.processEvents()
            event.accept()
        else:
            event.ignore()

    def cleanup_resources(self):
        """Clean up all resources when closing the application."""
        # Clean up application viewer first to ensure media players are properly shut down
        try:
            if hasattr(self, 'application_viewer'):
                if hasattr(self.application_viewer, 'shutdown'):
                    self.application_viewer.shutdown()
                else:
                    self.application_viewer.clear()
        except Exception as e:
            print(f"Error shutting down application viewer: {e}")

        # Stop any running background operations
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            # Check if it's a thread and running
            if isinstance(attr, QThread) and hasattr(attr, 'isRunning') and attr.isRunning():
                try:
                    # Try to stop it gracefully
                    attr.quit()
                    attr.wait(1000)  # Wait up to 1 second

                    # If still running, terminate it
                    if attr.isRunning():
                        attr.terminate()
                except Exception as e:
                    print(f"Error stopping thread {attr_name}: {str(e)}")

        # Clean up image handler resources
        if self.image_handler:
            try:
                self.image_handler.close_resources()
            except Exception as e:
                print(f"Error closing image handler: {str(e)}")

        # Close database connection
        if hasattr(self, 'db_manager') and self.db_manager:
            try:
                self.db_manager.close()
            except Exception as e:
                print(f"Error closing database connection: {str(e)}")

        # Clean up temp files
        temp_dir = tempfile.gettempdir()
        pattern = "trace_temp_*"
        try:
            for item in os.listdir(temp_dir):
                if item.startswith("trace_temp_"):
                    item_path = os.path.join(temp_dir, item)
                    try:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                        elif os.path.isdir(item_path):
                            import shutil
                            shutil.rmtree(item_path)
                    except Exception as e:
                        print(f"Error removing temp file {item_path}: {str(e)}")
        except Exception as e:
            print(f"Error cleaning up temp files: {str(e)}")

        # Release any other resources
        gc.collect()  # Encourage garbage collection

    def load_image_evidence(self):
        """Open an image with a specific filter on Kali Linux."""
        # Define the supported image file extensions, including both lowercase and uppercase variants
        supported_image_extensions = ["*.e01", "*.E01", "*.s01", "*.S01",
                                      "*.l01", "*.L01", "*.raw", "*.RAW",
                                      "*.img", "*.IMG", "*.dd", "*.DD",
                                      "*.iso", "*.ISO", "*.ad1", "*.AD1",
                                      "*.001", "*.s01", "*.ex01", "*.dmg",
                                      "*.sparse", "*.sparseimage"]

        # Construct the file filter string with both uppercase and lowercase extensions
        file_filter = "Supported Image Files ({})".format(" ".join(supported_image_extensions))

        # Open file dialog with the specified file filter
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", file_filter)

        if image_path:
            try:
                image_path = os.path.normpath(image_path)

                # Create a progress dialog to show loading status
                progress = QProgressDialog("Loading image...", "Cancel", 0, 100, self)
                progress.setWindowTitle("Loading Evidence")
                progress.setWindowModality(Qt.WindowModal)
                progress.setMinimumDuration(500)  # Show dialog only if operation takes more than 500ms
                progress.setValue(10)

                # Clean up any existing ImageHandler resources
                if self.image_handler:
                    self.image_handler.close_resources()

                # Create or update the ImageHandler instance with progress updates
                progress.setValue(20)

                # Process events to update UI
                QApplication.processEvents()

                # Create a new ImageHandler with the selected image
                self.image_handler = ImageHandler(image_path)
                progress.setValue(50)

                # Add the image to evidence files list
                if image_path not in self.evidence_files:
                    self.evidence_files.append(image_path)

                self.current_image_path = image_path
                progress.setValue(70)

                # Pass the image handler to widgets that need it
                self.deleted_files_widget.set_image_handler(self.image_handler)
                self.registry_extractor_widget.image_handler = self.image_handler
                self.file_search_widget.image_handler = self.image_handler
                self.metadata_viewer.image_handler = self.image_handler
                progress.setValue(80)

                # Load partitions into tree view
                QApplication.processEvents()
                self.load_partitions_into_tree(image_path)
                progress.setValue(100)

                # Enable all tabs since we have a valid image
                self.enable_tabs(True)

            except Exception as e:
                QMessageBox.critical(self, "Error Loading Image", f"Failed to load image: {str(e)}")
                # Remove the image from evidence files if it was added but failed to load
                if image_path in self.evidence_files:
                    self.evidence_files.remove(image_path)

    def remove_image_evidence(self):
        if not self.evidence_files:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        # Prepare the options for the dialog
        options = self.evidence_files + ["Remove All"]
        selected_option, ok = QInputDialog.getItem(self, "Remove Evidence File",
                                                   "Select an evidence file to remove or 'Remove All':",
                                                   options, 0, False)

        if ok:
            if selected_option == "Remove All":
                # Remove all evidence files
                self.tree_viewer.invisibleRootItem().takeChildren()  # Remove all children from the tree viewer
                self.clear_ui()  # Clear the UI
                QMessageBox.information(self, "Remove Evidence", "All evidence files have been removed.")
            else:
                # Remove the selected evidence file
                self.evidence_files.remove(selected_option)
                self.remove_from_tree_viewer(selected_option)
                self.clear_ui()
                QMessageBox.information(self, "Remove Evidence", f"{selected_option} has been removed.")
        # clear all tabs if there are no evidence files loaded
        if not self.evidence_files:
            self.clear_ui()
            # disable all tabs
            self.enable_tabs(False)
            # set the icon back to the original - only if verify_image_button exists
            if hasattr(self, 'verify_image_button'):
                self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == evidence_name:
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        root_item_tree = self.create_tree_item(self.tree_viewer, image_path,
                                               self.db_manager.get_icon_path('device', 'media-optical'),
                                               {"start_offset": 0})

        partitions = self.image_handler.get_partitions()

        # Check if the image has partitions or a recognizable file system
        if not partitions:
            if self.image_handler.has_filesystem(0):
                # The image has a filesystem but no partitions, populate root directory
                self.populate_contents(root_item_tree, {"start_offset": 0})
            else:
                # Entire image is considered as unallocated space
                size_in_bytes = self.image_handler.get_size()
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                unallocated_item_text = f"Unallocated Space: Size: {readable_size}"
                self.create_tree_item(root_item_tree, unallocated_item_text,
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": 0,
                                       "end_offset": size_in_bytes // SECTOR_SIZE})
            return

        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * SECTOR_SIZE
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            fs_type = self.image_handler.get_fs_type(start)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            item_text = f"vol{addr} ({desc_str}: {start}-{end}, Size: {readable_size}, FS: {fs_type})"
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')
            data = {"inode_number": None, "start_offset": start, "end_offset": end}
            item = self.create_tree_item(root_item_tree, item_text, icon_path, data)

            # Determine if the partition is special or contains unallocated space
            special_partitions = ["Primary Table", "Safety Table", "GPT Header"]
            is_special = any(special_case in desc_str for special_case in special_partitions)
            is_unallocated = "Unallocated" in desc_str or "Microsoft reserved" in desc_str

            if is_special:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            elif is_unallocated:
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                # Directly add unallocated space under the partition
                self.create_tree_item(item, f"Unallocated Space: Size: {readable_size}",
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": start, "end_offset": end})
            else:
                if self.image_handler.check_partition_contents(start):
                    item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)

    def populate_contents(self, item, data, inode=None):
        if self.current_image_path is None:
            return

        entries = self.image_handler.get_directory_contents(data["start_offset"], inode)

        for entry in entries:
            child_item = QTreeWidgetItem(item)
            child_item.setText(0, entry["name"])

            if entry["is_directory"]:
                sub_entries = self.image_handler.get_directory_contents(data["start_offset"], entry["inode_number"])
                has_sub_entries = bool(sub_entries)

                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=True)
                child_item.setChildIndicatorPolicy(
                    QTreeWidgetItem.ShowIndicator if has_sub_entries else QTreeWidgetItem.DontShowIndicatorWhenChildless)
            else:
                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=False)

    def populate_item(self, child_item, entry_name, inode_number, start_offset, is_directory):
        if is_directory:
            icon_key = 'folder'
        else:
            # For files, determine the icon based on the file extension
            file_extension = entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown'
            icon_key = file_extension

        icon_path = self.db_manager.get_icon_path('folder' if is_directory else 'file', icon_key)

        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {
            "inode_number": inode_number,
            "type": 'directory' if is_directory else 'file',
            "start_offset": start_offset,
            "name": entry_name
        })

    def on_item_expanded(self, item):
        # Check if the item already has children; if so, don't repopulate
        if item.childCount() > 0:
            return

        data = item.data(0, Qt.UserRole)
        if data is None:
            return

        if data.get("inode_number") is None:  # It's a partition
            self.populate_contents(item, data)
        else:  # It's a directory
            self.populate_contents(item, data, data.get("inode_number"))

    # Create a worker thread class for handling file operations in the background
    class FileContentWorker(QThread):
        completed = Signal(bytes, object)
        error = Signal(str)

        def __init__(self, image_handler, inode_number, offset):
            super().__init__()
            self.image_handler = image_handler
            self.inode_number = inode_number
            self.offset = offset

        def run(self):
            try:
                file_content, metadata = self.image_handler.get_file_content(self.inode_number, self.offset)
                if file_content:
                    self.completed.emit(file_content, metadata)
                else:
                    self.error.emit("Unable to read file content.")
            except Exception as e:
                self.error.emit(f"Error reading file: {str(e)}")

    # Create a worker thread class for handling unallocated space operations in the background
    class UnallocatedSpaceWorker(QThread):
        completed = Signal(bytes)
        error = Signal(str)

        def __init__(self, image_handler, start_offset, end_offset):
            super().__init__()
            self.image_handler = image_handler
            self.start_offset = start_offset
            self.end_offset = end_offset

        def run(self):
            try:
                unallocated_space = self.image_handler.read_unallocated_space(self.start_offset, self.end_offset)
                if unallocated_space:
                    self.completed.emit(unallocated_space)
                else:
                    self.error.emit("Unable to read unallocated space.")
            except Exception as e:
                self.error.emit(f"Error reading unallocated space: {str(e)}")

    def on_item_clicked(self, item, column):
        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        if not data:
            return

        # Store the current selection data
        self.current_selected_data = data

        # Show a status message in the UI to indicate loading
        statusbar = self.statusBar()
        statusbar.showMessage("Loading content...")

        # Use a background worker thread if processing large files or unallocated space
        try:
            if data.get("is_unallocated"):
                # Handle unallocated space in background
                self.unallocated_worker = self.UnallocatedSpaceWorker(
                    self.image_handler, data["start_offset"], data["end_offset"])
                self.unallocated_worker.completed.connect(
                    lambda content: self.update_viewer_with_file_content(content, data))
                self.unallocated_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.unallocated_worker.start()

            elif data.get("type") == "directory":
                # For directories, find parent inode to enable up navigation
                if "parent_inode" not in data and data.get("inode_number"):
                    parent_inode = self.find_parent_inode(data["start_offset"], data["inode_number"])
                    if parent_inode:
                        data["parent_inode"] = parent_inode
                        # Update the stored data with parent information
                        self.current_selected_data = data

                # Handle directories - populate the listing synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))

                # Update current path for directory navigation
                if data.get("name"):
                    if data.get("inode_number") == 5:  # Root directory
                        self.current_path = "/"
                    else:
                        # If it's a regular directory, update the path
                        self.current_path = data.get("path", os.path.join(self.current_path, data.get("name", "")))

                # Update directory up button state
                self.update_directory_up_button()

                # Populate the listing table with directory contents
                self.populate_listing_table(entries, data["start_offset"])
                statusbar.clearMessage()

            elif data.get("inode_number") is not None:
                # Handle files in background
                self.file_worker = self.FileContentWorker(
                    self.image_handler, data["inode_number"], data["start_offset"])
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.file_worker.start()

            elif data.get("start_offset") is not None:
                # Handle partitions
                entries = self.image_handler.get_directory_contents(data["start_offset"],
                                                                    5)  # 5 is the root inode for NTFS

                # Reset path to root when viewing partitions
                self.current_path = "/"

                self.populate_listing_table(entries, data["start_offset"])
                statusbar.clearMessage()

            else:
                self.log_error("Clicked item is not a file, directory, or unallocated space.")
                statusbar.clearMessage()

        except Exception as e:
            self.log_error(f"Error processing item: {str(e)}")
            statusbar.clearMessage()

    def update_directory_up_button(self):
        """Update the state of the directory up button based on current selection"""
        if not self.current_selected_data:
            self.go_up_action.setEnabled(False)
            return

        # Check if this is a directory
        if self.current_selected_data.get("type") == "directory":
            inode_number = self.current_selected_data.get("inode_number")
            start_offset = self.current_selected_data.get("start_offset")

            # Check if this is root directory (inode 5 in NTFS)
            is_root = inode_number == 5

            # If parent_inode isn't set yet, try to find it
            if "parent_inode" not in self.current_selected_data and not is_root and inode_number is not None:
                parent_inode = self.find_parent_inode(start_offset, inode_number)
                if parent_inode:
                    # Update the dictionary in place
                    self.current_selected_data["parent_inode"] = parent_inode

            has_parent = self.current_selected_data.get("parent_inode") is not None
            self.go_up_action.setEnabled(not is_root and has_parent)
        else:
            self.go_up_action.setEnabled(False)

    def find_parent_inode(self, start_offset, inode_number):
        """Helper method to find the parent inode for a directory from tree view"""
        try:
            # Root directory (5 is typically root in NTFS) has no parent
            if inode_number == 5:
                return None

            # Get directory entries for the directory
            entries = self.image_handler.get_directory_contents(start_offset, inode_number)

            # Look for parent directory entry (..)
            for entry in entries:
                if entry.get("name") == "..":
                    return entry.get("inode_number")

            # If we can't find the proper parent, return None
            return None

        except Exception as e:
            self.log_error(f"Error finding parent inode: {str(e)}")
            return None

    def navigate_up_directory(self):
        """Navigate to the parent directory"""
        if not self.current_selected_data:
            return

        # Ensure we have valid information
        start_offset = self.current_selected_data.get("start_offset")
        inode_number = self.current_selected_data.get("inode_number")

        if not start_offset or not inode_number:
            return

        # If parent_inode isn't already set, try to find it
        if "parent_inode" not in self.current_selected_data and self.current_selected_data.get("type") == "directory":
            parent_inode = self.find_parent_inode(start_offset, inode_number)
            if parent_inode:
                self.current_selected_data["parent_inode"] = parent_inode

        # Make sure we have a parent to navigate to
        parent_inode = self.current_selected_data.get("parent_inode")
        if not parent_inode:
            return

        statusbar = self.statusBar()
        statusbar.showMessage("Loading parent directory...")

        try:
            # Create data for parent directory
            parent_data = {
                "inode_number": parent_inode,
                "start_offset": start_offset,
                "type": "directory",
                # Get the grandparent inode if available (for consecutive up navigation)
                "parent_inode": self.get_grandparent_inode(parent_inode, start_offset)
            }

            # Update current path (navigate to parent directory)
            self.current_path = os.path.dirname(self.current_path)
            if self.current_path == "":
                self.current_path = "/"

            # Load the parent directory
            entries = self.image_handler.get_directory_contents(
                parent_data["start_offset"],
                parent_data["inode_number"]
            )

            self.current_selected_data = parent_data

            # Update directory up button state
            self.update_directory_up_button()

            # Update both the tree view selection and listing table
            self.populate_listing_table(entries, parent_data["start_offset"])

            # Find and select the corresponding item in the tree view if possible
            self.select_tree_item_by_inode(parent_data["inode_number"], parent_data["start_offset"])

            statusbar.clearMessage()

        except Exception as e:
            self.log_error(f"Error navigating to parent directory: {str(e)}")
            statusbar.clearMessage()

    def select_tree_item_by_inode(self, inode_number, start_offset):
        """Attempt to find and select the item in the tree view that matches the given inode"""
        try:
            # Skip if inode_number is None
            if inode_number is None:
                return

            # Get the root items
            root_item = self.tree_viewer.invisibleRootItem()

            # Find the item with matching inode and start_offset (recursive search)
            found_item = self.find_tree_item_recursive(root_item, inode_number, start_offset)

            if found_item:
                # Temporarily disconnect the item clicked signal to prevent loops
                self.tree_viewer.itemClicked.disconnect(self.on_item_clicked)

                # Select the item and make it visible
                self.tree_viewer.setCurrentItem(found_item)
                self.tree_viewer.scrollToItem(found_item)

                # Reconnect the signal
                self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        except Exception as e:
            self.log_error(f"Error selecting tree item: {str(e)}")

    def find_tree_item_recursive(self, parent_item, inode_number, start_offset):
        """Recursively search for a tree item with matching inode and start_offset"""
        # Check all children of the parent item
        for i in range(parent_item.childCount()):
            item = parent_item.child(i)
            data = item.data(0, Qt.UserRole)

            # Check if this item matches (allow matching based on inode only)
            if data and data.get("inode_number") == inode_number:
                # If start_offset is also provided and doesn't match, continue searching
                if start_offset is not None and data.get("start_offset") != start_offset:
                    continue
                return item

            # If it has children, search recursively
            if item.childCount() > 0:
                found = self.find_tree_item_recursive(item, inode_number, start_offset)
                if found:
                    return found

        # Not found
        return None

    def populate_listing_table(self, entries, offset):
        """Populate the listing table with directory entries in batches for better performance."""
        # Clear existing content
        self.listing_table.setRowCount(0)

        if not entries:
            return

        # Enable/disable the up button based on whether we're in the root directory
        self.update_directory_up_button()

        # Avoid excessive processing for small directories
        if len(entries) < 500:
            # For smaller directories, populate directly for simplicity and reliability
            for entry in entries:
                row_position = self.listing_table.rowCount()
                self.listing_table.insertRow(row_position)

                entry_name = entry.get("name", "")
                inode_number = entry.get("inode_number", 0)
                is_directory = entry.get("is_directory", False)
                description = "Directory" if is_directory else "File"
                size_in_bytes = entry.get("size", 0)
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                created = entry.get("created", "N/A")
                accessed = entry.get("accessed", "N/A")
                modified = entry.get("modified", "N/A")
                changed = entry.get("changed", "N/A")

                icon_type = 'folder' if is_directory else 'file'
                icon_name = 'folder' if is_directory else (
                    entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown')

                parent_inode = self.current_selected_data.get("inode_number") if self.current_selected_data else None

                self.insert_row_into_listing_table(entry_name, inode_number, description,
                                                   icon_name, icon_type, offset,
                                                   readable_size, created, accessed,
                                                   modified, changed, parent_inode)

            # Process events to keep UI responsive
            QApplication.processEvents()
            return

        # For very large directories, batch processing improves UI responsiveness
        BATCH_SIZE = 200

        # Sort entries by name for predictable ordering and better UX
        sorted_entries = sorted(entries, key=lambda e: e.get("name", "").lower())
        total_entries = len(sorted_entries)

        # Process in batches to keep UI responsive
        for batch_start in range(0, total_entries, BATCH_SIZE):
            # Get the current batch of entries
            batch_end = min(batch_start + BATCH_SIZE, total_entries)
            batch = sorted_entries[batch_start:batch_end]

            # Populate the batch
            for entry in batch:
                row_position = self.listing_table.rowCount()
                self.listing_table.insertRow(row_position)

                entry_name = entry.get("name", "")
                inode_number = entry.get("inode_number", 0)
                is_directory = entry.get("is_directory", False)
                description = "Directory" if is_directory else "File"
                size_in_bytes = entry.get("size", 0)
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                created = entry.get("created", "N/A")
                accessed = entry.get("accessed", "N/A")
                modified = entry.get("modified", "N/A")
                changed = entry.get("changed", "N/A")

                icon_type = 'folder' if is_directory else 'file'
                icon_name = 'folder' if is_directory else (
                    entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown')

                parent_inode = self.current_selected_data.get("inode_number") if self.current_selected_data else None

                self.insert_row_into_listing_table(entry_name, inode_number, description,
                                                   icon_name, icon_type, offset,
                                                   readable_size, created, accessed,
                                                   modified, changed, parent_inode)

            # Process events to keep UI responsive during batch loading
            QApplication.processEvents()

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      created, accessed, modified, changed, parent_inode=None):
        """Insert a row into the listing table with proper caching and error handling."""
        try:
            icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
            icon = QIcon(icon_path)
            row_position = self.listing_table.rowCount() - 1  # Current row (rows are 0-indexed)

            # Calculate the full path for this item
            file_path = os.path.join(self.current_path, entry_name) if entry_name != ".." else os.path.dirname(
                self.current_path)

            name_item = QTableWidgetItem(entry_name)
            name_item.setIcon(icon)
            name_item.setData(Qt.UserRole, {
                "inode_number": entry_inode,
                "start_offset": offset,
                "type": "directory" if icon_type == 'folder' else 'file',
                "name": entry_name,
                "size": size,
                "parent_inode": parent_inode,  # Store parent directory inode for "Go Up" functionality
                "path": file_path  # Store the full path
            })

            self.listing_table.setItem(row_position, 0, name_item)
            self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))
            self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
            self.listing_table.setItem(row_position, 3, QTableWidgetItem(str(size)))
            self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(created)))
            self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(accessed)))
            self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(modified)))
            self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))
            self.listing_table.setItem(row_position, 8, QTableWidgetItem(file_path))

        except Exception as e:
            self.log_error(f"Error adding row to listing table: {str(e)}")
            # Try to recover by removing the incomplete row
            try:
                if row_position >= 0:
                    self.listing_table.removeRow(row_position)
            except:
                pass

    def update_viewer_with_file_content(self, file_content, data):
        """Update the active viewer tab with the file content.

        This method is called after file content is loaded, either directly
        or from a background thread.
        """
        # Clear the status message if it exists
        statusbar = self.statusBar()
        statusbar.clearMessage()

        # Get the active tab index
        index = self.viewer_tab.currentIndex()

        if not file_content:
            self.log_error("No content available to display")
            return

        # Use optimized display methods for each viewer type
        try:
            if index == 0:  # Hex tab
                self.hex_viewer.display_hex_content(file_content)
            elif index == 1:  # Text tab
                self.text_viewer.display_text_content(file_content)
            elif index == 2:  # Application tab
                full_file_path = data.get("name", "")  # Retrieve the name from the data dictionary
                self.application_viewer.display_application_content(file_content, full_file_path)
            elif index == 3:  # File Metadata tab
                self.metadata_viewer.display_metadata(data)
            elif index == 4:  # Exif Data tab
                self.exif_viewer.load_and_display_exif_data(file_content)
            elif index == 5:  # Assuming VirusTotal tab is the 6th tab (0-based index)
                file_hash = hashlib.md5(file_content).hexdigest()
                self.virus_total_api.set_file_hash(file_hash)
                self.virus_total_api.set_file_content(file_content, data.get("name", ""))
        except Exception as e:
            self.log_error(f"Error displaying content in viewer: {str(e)}")

    def display_content_for_active_tab(self):
        """Display content appropriate for the currently active tab."""
        if not self.current_selected_data:
            return

        statusbar = self.statusBar()
        statusbar.showMessage("Updating view...")

        try:
            inode_number = self.current_selected_data.get("inode_number")
            offset = self.current_selected_data.get("start_offset", self.current_offset)

            if inode_number:
                # For file content, use the worker thread
                self.file_worker = self.FileContentWorker(self.image_handler, inode_number, offset)
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, self.current_selected_data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.file_worker.start()
            else:
                statusbar.clearMessage()
        except Exception as e:
            self.log_error(f"Error updating active tab: {str(e)}")
            statusbar.clearMessage()

    def open_listing_context_menu(self, position):
        # Get the selected item
        indexes = self.listing_table.selectedIndexes()
        if indexes:
            selected_item = self.listing_table.item(indexes[0].row(),
                                                    0)  # Assuming the first column contains the item data
            data = selected_item.data(Qt.UserRole)
            menu = QMenu()

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(lambda: self.handle_export(data, QFileDialog.getExistingDirectory(self,
                                                                                                              "Select Destination Directory")))

            menu.exec_(self.listing_table.viewport().mapToGlobal(position))

    def handle_export(self, data, dest_dir):
        """Export the selected item in a background thread with progress display."""
        if not dest_dir:
            return

        try:
            # Create a progress dialog
            progress_dialog = QProgressDialog("Preparing to export...", "Cancel", 0, 100, self)
            progress_dialog.setWindowTitle("Exporting Files")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(0)
            progress_dialog.show()

            # Create and configure the worker
            self.export_worker = ExportWorker(
                self.image_handler,
                data["inode_number"],
                data["start_offset"],
                dest_dir,
                data["name"],
                data["type"] == "directory"
            )

            # Connect worker signals
            self.export_worker.progress.connect(
                lambda current, total: progress_dialog.setValue(int(current * 100 / total) if total > 0 else 0)
            )
            self.export_worker.status_update.connect(progress_dialog.setLabelText)
            self.export_worker.error.connect(lambda msg: QMessageBox.warning(self, "Export Error", msg))
            self.export_worker.finished.connect(progress_dialog.close)

            # Connect the cancel button
            progress_dialog.canceled.connect(self.export_worker.terminate)

            # Start the worker
            self.export_worker.start()

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error starting export: {str(e)}")

    def log_error(self, message):
        """Log an error message to the console and potentially to a log file."""
        print(f"Error: {message}")
        # Could also log to a file or status bar here

    def open_tree_context_menu(self, position):
        # Get the selected item
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            menu = QMenu()

            # Check if the selected item is a root item
            if selected_item and selected_item.parent() is None:
                view_os_info_action = menu.addAction("View Image Information")
                view_os_info_action.triggered.connect(lambda: self.view_os_information(indexes[0]))

            # Add the 'Export' option for any file or folder
            export_action = menu.addAction("Export")
            export_action.triggered.connect(
                lambda: self.handle_export(self.tree_viewer.itemFromIndex(indexes[0]).data(0, Qt.UserRole),
                                           QFileDialog.getExistingDirectory(self, "Select Destination Directory")))

            menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

    def view_os_information(self, index):
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            # Ensure that only the root item triggers the OS information display
            return

        partitions = self.image_handler.get_partitions()
        table = QTableWidget()

        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Partition", "OS Information", "File System Type"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setFont(QFont("Arial", 10, QFont.Bold))
        table.verticalHeader().setVisible(False)

        partition_icon = QIcon('Icons/devices/drive-harddisk.svg')  # Replace with your partition icon path
        os_icon = QIcon('Icons/start-here.svg')  # Replace with your OS icon path

        for row, part in enumerate(partitions):
            start_offset = part[2]  # Start offset of the partition
            fs_type = self.image_handler.get_fs_type(start_offset)

            os_version = None
            if fs_type == "NTFS":
                os_version = self.image_handler.get_windows_version(start_offset)

            table.insertRow(row)
            partition_item = QTableWidgetItem(f"Partition {part[0]}")
            partition_item.setIcon(partition_icon)
            os_version_item = QTableWidgetItem(os_version if os_version else "N/A")
            if os_version:
                os_version_item.setIcon(os_icon)
            fs_type_item = QTableWidgetItem(fs_type or "Unrecognized")

            table.setItem(row, 0, partition_item)
            table.setItem(row, 1, os_version_item)
            table.setItem(row, 2, fs_type_item)

        table.resizeRowsToContents()
        table.resizeColumnsToContents()

        # Dialog for displaying the table
        dialog = QDialog(self)
        dialog.setWindowTitle("OS and File System Information")
        dialog.resize(460, 320)
        layout = QVBoxLayout(dialog)
        layout.addWidget(table)

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
        buttonBox.accepted.connect(dialog.accept)
        layout.addWidget(buttonBox)

        dialog.exec_()

    def create_action(self, icon_path, text, callback):
        action = QAction(QIcon(icon_path), text, self)
        action.triggered.connect(callback)
        return action

    def get_grandparent_inode(self, parent_inode, start_offset):
        """Helper method to determine the grandparent inode"""
        # Root directory (5 is typically root in NTFS) has no parent
        if parent_inode == 5:
            return None

        try:
            # Get directory entries for parent
            parent_entries = self.image_handler.get_directory_contents(start_offset, parent_inode)

            # Look for parent directory entry (..)
            for entry in parent_entries:
                if entry.get("name") == "..":
                    return entry.get("inode_number")

            # If we can't find the proper parent, try filesystem-specific approach
            # For NTFS, parent of non-root directories is often inode 5
            return 5

        except Exception as e:
            print(f"Error finding grandparent inode: {str(e)}")
            return None

    def on_listing_table_item_clicked(self, item):
        """Handle click events on the listing table."""
        row = item.row()

        # Get data from the name column (column 0)
        data = self.listing_table.item(row, 0).data(Qt.UserRole)
        if not data:
            return

        self.current_selected_data = data

        statusbar = self.statusBar()
        statusbar.showMessage("Loading content...")

        try:
            if data.get("type") == "directory":
                inode_number = data.get("inode_number", 0)

                # Find and select the corresponding item in the tree view if possible
                self.select_tree_item_by_inode(inode_number, data["start_offset"])

                # Update current path for directory navigation
                if data.get("name") == "..":
                    # Go to parent directory
                    self.current_path = os.path.dirname(self.current_path)
                    if self.current_path == "":
                        self.current_path = "/"
                elif data.get("inode_number") == 5:  # Root directory
                    self.current_path = "/"
                else:
                    # Navigate into directory
                    self.current_path = os.path.join(self.current_path, data.get("name", ""))

                # Directories are processed synchronously
                entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)

                # Update directory up button state
                self.update_directory_up_button()

                self.populate_listing_table(entries, data["start_offset"])
                statusbar.clearMessage()
            else:
                # Find and select the corresponding file in the tree view if possible
                self.select_tree_item_by_inode(data.get("inode_number"), data["start_offset"])

                # Files are processed in a background thread
                inode_number = data.get("inode_number", 0)
                self.file_worker = self.FileContentWorker(self.image_handler, inode_number, data["start_offset"])
                self.file_worker.completed.connect(
                    lambda content, _: self.update_viewer_with_file_content(content, data))
                self.file_worker.error.connect(
                    lambda msg: (self.log_error(msg), statusbar.clearMessage()))
                self.file_worker.start()

        except Exception as e:
            self.log_error(f"Error processing listing table click: {str(e)}")
            statusbar.clearMessage()


# Add a worker thread for exporting files and directories
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

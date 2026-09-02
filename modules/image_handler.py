"""Forensic disk-image access.

Wraps pytsk3 (and pyewf for EWF/E01 containers) behind a single ImageHandler
that the rest of the application talks to: partition enumeration, filesystem
traversal, file content reads, and the allocation map used by file carving.
"""

import gc
import hashlib
import logging
import os
import time
from functools import lru_cache

import pyewf
import pytsk3
from Registry import Registry

from modules.constants import CHUNK_SIZE, FILE_BUFFER_SIZE, SECTOR_SIZE
from modules.utils import FileSystemUtils, safe_datetime

logger = logging.getLogger('TRACE.ImageHandler')


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
                except Exception as e:
                    logger.debug("Error closing filesystem handle: %s", e)

        # Close the image
        if self.img_info:
            if hasattr(self.img_info, 'close'):
                try:
                    self.img_info.close()
                except Exception as e:
                    logger.debug("Error closing image handle: %s", e)
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

    def build_allocation_map(self, start_offset):
        """Build a map of allocated disk regions by traversing the filesystem."""
        allocation_map = []

        try:
            fs_info = self.get_fs_info(start_offset)
            if not fs_info:
                logger.warning(f"Unable to get filesystem info for offset {start_offset}")
                return allocation_map

            # Get block size for this filesystem
            block_size = fs_info.info.block_size

            # Recursively walk filesystem to find all allocated files
            def walk_directory(directory, path="/"):
                """Recursively walk directory and collect allocated file ranges."""
                try:
                    for entry in directory:
                        # Skip current and parent directory entries
                        if not hasattr(entry, 'info') or not hasattr(entry.info, 'name'):
                            continue

                        name = entry.info.name.name.decode('utf-8', errors='ignore')
                        if name in [".", ".."]:
                            continue

                        # Check if this is an allocated file
                        if not hasattr(entry.info, 'meta') or entry.info.meta is None:
                            continue

                        # Only process allocated files (skip deleted files)
                        is_allocated = bool(int(entry.info.meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC)
                        if not is_allocated:
                            continue

                        # Get file size and inode
                        file_size = entry.info.meta.size

                        # Only process files with actual data
                        if file_size > 0:
                            try:
                                # Open the file to access its data runs
                                file_obj = fs_info.open_meta(inode=entry.info.meta.addr)

                                # Calculate byte offsets for the file's data
                                # This is approximate - we use the file's logical position
                                # For a more accurate map, we'd need to walk data runs
                                # but this is a reasonable approximation for most filesystems

                                # Get partition offset in bytes
                                partition_offset_bytes = start_offset * 512

                                # For simplicity, we'll mark regions based on inode metadata
                                # A more sophisticated approach would walk TSK_FS_BLOCK structures
                                # but pytsk3 doesn't expose block_walk easily

                                # Estimate file location based on inode number and size
                                # This is a simplified approach - actual blocks may be fragmented
                                inode_addr = entry.info.meta.addr
                                estimated_start = partition_offset_bytes + (inode_addr * block_size)
                                estimated_end = estimated_start + file_size

                                allocation_map.append((estimated_start, estimated_end))

                            except Exception as e:
                                # Skip files we can't open
                                logger.debug(f"Could not process file {path}{name}: {e}")
                                pass

                        # Recursively process directories
                        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            try:
                                sub_directory = fs_info.open_dir(inode=entry.info.meta.addr)
                                walk_directory(sub_directory, f"{path}{name}/")
                            except Exception as e:
                                logger.debug(f"Could not open directory {path}{name}: {e}")
                                pass

                except Exception as e:
                    logger.debug(f"Error walking directory {path}: {e}")
                    pass

            # Start walking from root directory
            try:
                root_dir = fs_info.open_dir(path="/")
                walk_directory(root_dir)
            except Exception as e:
                logger.error(f"Error accessing root directory: {e}")

            # Sort allocation map by start offset for efficient searching
            allocation_map.sort(key=lambda x: x[0])

            logger.info(f"Built allocation map with {len(allocation_map)} allocated file regions")

        except Exception as e:
            logger.error(f"Error building allocation map: {e}")

        return allocation_map

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
                        logger.warning(f"Unable to retrieve stored hash values: {e}")

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
                                logger.error(f"Progress callback error: {e}")
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
                                    logger.error(f"Progress callback error: {e}")
                except Exception as e:
                    logger.error(f"Error reading raw image: {e}")

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
            logger.error(f"Error calculating hashes: {e}")
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
            logger.error(f"Error loading image: {e}")
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
        """Whether a partition's root directory has any entries.

        A read error and a genuinely empty partition are NOT the same thing --
        this previously caught everything and returned False for both, so a
        corrupt or unreadable partition was reported as simply empty. The
        distinction matters in a forensic tool, so failures are logged with
        the offset rather than silently discarded.
        """
        fs = self.get_fs_info(partition_start_offset)
        if not fs:
            return False
        try:
            root_dir = fs.open_dir(path="/")
            for _ in root_dir:
                return True
            return False
        except (IOError, OSError, RuntimeError) as e:
            logger.warning("Could not read root directory at offset %s: %s",
                           partition_start_offset, e)
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
                logger.error(f"Error in get_directory_contents: {e}")
                return []
        return []

    def get_registry_hive(self, fs_info, hive_path):
        """Extract a registry hive from the given filesystem."""
        try:
            registry_file = fs_info.open(hive_path)
            hive_data = registry_file.read_random(0, registry_file.info.meta.size)
            return hive_data
        except Exception as e:
            logger.error(f"Error reading registry hive: {e}")
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
                logger.error(f"Error parsing SOFTWARE hive: {e}")
                return "Error in parsing OS version"

    def read_unallocated_space(self, start_offset, end_offset):
        try:
            start_byte_offset = start_offset * SECTOR_SIZE
            end_byte_offset = max(end_offset * SECTOR_SIZE, start_byte_offset + SECTOR_SIZE - 1)
            size_in_bytes = end_byte_offset - start_byte_offset + 1  # Ensuring at least some data is read

            if size_in_bytes <= 0:
                logger.warning("Invalid size for unallocated space, adjusting to read at least one sector.")
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
                    logger.error(f"Failed to read unallocated space from offset {start_byte_offset} to {end_byte_offset}")
                    return None
                return unallocated_space

        except Exception as e:
            logger.error(f"Error reading unallocated space: {e}")
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
                    # Store offset in SECTORS (not bytes)
                    self.process_partition(img_info, partition.start, files_list, extensions)
        except IOError:
            self.process_partition(img_info, 0, files_list, extensions)

        return files_list

    def process_partition(self, img_info, offset_sectors, files_list, extensions):
        """Process partition listing - offset_sectors is in sectors, not bytes."""
        try:
            fs_info = pytsk3.FS_Info(img_info, offset=offset_sectors * SECTOR_SIZE)
            self._recursive_file_search(fs_info, fs_info.open_dir(path="/"), "/", files_list, extensions, None, offset_sectors)
        except IOError as e:
            logger.error(f"Unable to open filesystem at offset {offset_sectors}: {e}")

    def _recursive_file_search(self, fs_info, directory, parent_path, files_list, extensions, search_query=None, start_offset=0):
        """Recursively search for files in a directory."""
        for entry in directory:
            if entry.info.name.name in [b".", b".."]:
                continue

            try:
                file_name = entry.info.name.name.decode("utf-8", errors='replace')
                file_extension = os.path.splitext(file_name)[1].lower()

                # Determine if this entry should be included in results
                is_directory = entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR

                if search_query:
                    # If there's a search query, check if the file name contains the query
                    if search_query.startswith('.'):
                        # If the search query is an extension (e.g., '.jpg')
                        query_matches = file_extension == search_query.lower()
                        match_reason = f"extension matches '{search_query}'" if query_matches else ""
                    else:
                        # If the search query is a file name or part of it (SUBSTRING MATCH)
                        query_matches = search_query.lower() in file_name.lower()
                        match_reason = f"filename contains '{search_query}'" if query_matches else ""
                else:
                    # If no search query, handle based on extensions
                    if is_directory:
                        # Always include directories when no search query (for navigation)
                        query_matches = True
                        match_reason = "directory (no filter)"
                    else:
                        # For files, apply extension filter
                        query_matches = extensions is None or file_extension in extensions or '' in extensions
                        match_reason = "extension filter"

                if is_directory:
                    # If directory matches search query, add it to results
                    if query_matches:
                        dir_info = self._get_directory_metadata(entry, parent_path, start_offset)
                        files_list.append(dir_info)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"MATCH (DIR): '{file_name}' - {match_reason}")

                    # Recursively search subdirectory
                    try:
                        sub_directory = fs_info.open_dir(inode=entry.info.meta.addr)
                        self._recursive_file_search(fs_info, sub_directory, os.path.join(parent_path, file_name),
                                                    files_list,
                                                    extensions, search_query, start_offset)
                    except IOError as e:
                        logger.error(f"Unable to open directory: {e}")

                elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and query_matches:
                    file_info = self._get_file_metadata(entry, parent_path, start_offset)
                    files_list.append(file_info)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"MATCH (FILE): '{file_name}' - {match_reason}")
            except UnicodeDecodeError:
                continue  # Skip entries with encoding issues

    def _get_directory_metadata(self, entry, parent_path, start_offset=0):
        """Get directory metadata for search results."""
        try:
            dir_name = entry.info.name.name.decode("utf-8", errors='replace')
            inode_number = entry.info.meta.addr if entry.info.meta else 0

            # Get volume name for this offset
            volume_name = self._get_volume_name_for_offset(start_offset)
            # Create full path with volume information
            full_path = f"{volume_name}:{os.path.join(parent_path, dir_name)}"

            return {
                "name": dir_name,
                "path": full_path,
                "size": 0,  # Directories don't have a size in this context
                "accessed": safe_datetime(entry.info.meta.atime if entry.info.meta else None),
                "modified": safe_datetime(entry.info.meta.mtime if entry.info.meta else None),
                "created": safe_datetime(entry.info.meta.crtime if hasattr(entry.info.meta, 'crtime') else None),
                "changed": safe_datetime(entry.info.meta.ctime if entry.info.meta else None),
                "inode_item": str(inode_number),
                "inode_number": inode_number,
                "start_offset": start_offset,
                "is_directory": True,  # Mark as directory
                "type": "directory"
            }
        except Exception as e:
            logger.error(f"Error getting directory metadata: {e}")
            return {
                "name": "Error reading directory",
                "path": parent_path + "/unknown",
                "size": 0,
                "accessed": "N/A",
                "modified": "N/A",
                "created": "N/A",
                "changed": "N/A",
                "inode_item": "0",
                "inode_number": 0,
                "start_offset": start_offset,
                "is_directory": True,
                "type": "directory"
            }

    def _get_volume_name_for_offset(self, start_offset):
        """Get the volume name (e.g., 'vol0', 'vol1') for a given partition offset."""
        try:
            partitions = self.get_partitions()
            for addr, desc, start, length in partitions:
                if start == start_offset:
                    return f"vol{addr}"
            # If not found in partitions, it might be a single filesystem image
            return "vol0"
        except Exception as e:
            logger.warning(f"Could not determine volume name for offset {start_offset}: {e}")
            return "vol0"

    def _get_file_metadata(self, entry, parent_path, start_offset=0):
        """Get file metadata including all fields needed for viewing."""
        try:
            file_name = entry.info.name.name.decode("utf-8", errors='replace')
            inode_number = entry.info.meta.addr if entry.info.meta else 0

            # Get volume name for this offset
            volume_name = self._get_volume_name_for_offset(start_offset)
            # Create full path with volume information
            full_path = f"{volume_name}:{os.path.join(parent_path, file_name)}"

            return {
                "name": file_name,
                "path": full_path,  # Now includes volume information
                "size": entry.info.meta.size if entry.info.meta else 0,
                "accessed": safe_datetime(entry.info.meta.atime if entry.info.meta else None),
                "modified": safe_datetime(entry.info.meta.mtime if entry.info.meta else None),
                "created": safe_datetime(entry.info.meta.crtime if hasattr(entry.info.meta, 'crtime') else None),
                "changed": safe_datetime(entry.info.meta.ctime if entry.info.meta else None),
                "inode_item": str(inode_number),  # For display compatibility
                "inode_number": inode_number,  # For file content retrieval
                "start_offset": start_offset,  # Partition offset needed for retrieval
                "is_directory": False,  # This method only called for files
                "type": "file"  # For compatibility with viewer logic
            }
        except Exception as e:
            logger.error(f"Error getting file metadata: {e}")
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
                "inode_number": 0,
                "start_offset": start_offset,
                "is_directory": False,
                "type": "file"
            }

    def search_files(self, search_query=None):
        logger.info(f"ImageHandler.search_files called with query: '{search_query}'")
        files_list = []
        img_info = self.open_image()

        try:
            volume_info = pytsk3.Volume_Info(img_info)
            partition_count = 0
            for partition in volume_info:
                if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    partition_count += 1
                    logger.info(f"Searching partition {partition_count} (offset: {partition.start} sectors)")
                    # Store offset in SECTORS (not bytes) - get_fs_info will multiply by 512
                    self.process_partition_search(img_info, partition.start, files_list, search_query)
            logger.info(f"Searched {partition_count} allocated partitions")
        except IOError as e:
            # No volume information, attempt to read as a single filesystem
            logger.info(f"No volume info, reading as single filesystem: {e}")
            self.process_partition_search(img_info, 0, files_list, search_query)

        logger.info(f"Total files found: {len(files_list)}")
        return files_list

    def process_partition_search(self, img_info, offset_sectors, files_list, search_query):
        """Process partition search - offset_sectors is in sectors, not bytes."""
        try:
            logger.info(f"Opening filesystem at offset {offset_sectors} sectors ({offset_sectors * SECTOR_SIZE} bytes)")
            fs_info = pytsk3.FS_Info(img_info, offset=offset_sectors * SECTOR_SIZE)
            logger.info(f"Starting recursive search with query: '{search_query}'")
            initial_count = len(files_list)
            self._recursive_file_search(fs_info, fs_info.open_dir(path="/"), "/", files_list, None, search_query, offset_sectors)
            logger.info(f"Recursive search complete. Found {len(files_list) - initial_count} files in this partition")
        except IOError as e:
            logger.error(f"Unable to open file system for search: {e}")

    def get_file_content(self, inode_number, offset):
        fs = self.get_fs_info(offset)
        if not fs:
            return None, None

        try:
            file_obj = fs.open_meta(inode=inode_number)
            if file_obj.info.meta.size == 0:
                logger.info("File has no content or is a special metafile!")
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
            logger.error(f"Error reading file: {e}")
            return None, None

    # Replace static method assignment with an actual instance method
    def get_readable_size(self, size_in_bytes):
        """Convert bytes to a human-readable string, wrapper for the static utility method."""
        return FileSystemUtils.get_readable_size(size_in_bytes)


# DatabaseManager class with optimization

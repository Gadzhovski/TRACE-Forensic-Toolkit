"""Forensic disk-image access.

Wraps pytsk3 (and pyewf for EWF/E01 containers) behind a single ImageHandler
that the rest of the application talks to: partition enumeration, filesystem
traversal, file content reads, and the allocation map used by file carving.
"""

import hashlib
import queue
import threading
import logging
import os
import re
import time
from functools import lru_cache

import pyewf
import pytsk3
from Registry import Registry

from trace_app.core import containers
from trace_app.infra.constants import (CHUNK_SIZE, MAX_DIRECTORY_DEPTH,
                                       SECTOR_SIZE)
from trace_app.infra.utils import FileSystemUtils, safe_datetime

logger = logging.getLogger('TRACE.ImageHandler')

#: UFS superblock magic, 0x00011954. Written in the byte order of the host
#: that created the filesystem, so a carved or foreign image may show either.
_UFS_MAGIC_LE = (0x00011954).to_bytes(4, 'little')
_UFS_MAGIC_BE = (0x00011954).to_bytes(4, 'big')
#: UFS2 stores the same value rotated; FreeBSD writes 0x19540119 there.
_UFS2_MAGIC_LE = (0x19540119).to_bytes(4, 'little')
_UFS2_MAGIC_BE = (0x19540119).to_bytes(4, 'big')



def _safe(thing, attribute, default):
    """A libyal property that may raise when the format omits it."""
    try:
        value = getattr(thing, attribute)
    except (IOError, OSError):
        return default
    return default if value is None else value


class _Closed:
    """Stands in for a container that would not open."""

    def close(self):
        pass

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
#: Filesystems that store a local wall-clock time with no timezone recorded.
#: Reporting one of these as UTC claims knowledge the evidence does not carry.
_TIMEZONE_NAIVE = frozenset({'FAT12', 'FAT16', 'FAT32', 'ExFAT'})

class _OrphanMeta:
    """A copy of the fields a listing needs from a TSK_FS_META.

    pytsk3's metadata object is owned by the File it came from; once that File
    is collected the fields read back as None. A deleted entry is opened by
    inode specifically because its own metadata link is gone, so this is
    exactly the path where that bites.
    """

    __slots__ = ('addr', 'size', 'type', 'flags',
                 'atime', 'mtime', 'crtime', 'ctime')

    def __init__(self, meta):
        self.addr = meta.addr
        self.size = meta.size
        self.type = meta.type
        self.flags = meta.flags
        self.atime = getattr(meta, 'atime', 0)
        self.mtime = getattr(meta, 'mtime', 0)
        self.crtime = getattr(meta, 'crtime', 0)
        self.ctime = getattr(meta, 'ctime', 0)


class ImageHandler:
    def __init__(self, image_path):
        # Normalise here so every consumer gets a well-formed path: libewf's
        # globbing rejects mixed separators like 'D:/dir/img.E01' on Windows.
        self.image_path = os.path.normpath(image_path) if image_path else image_path
        self.img_info = None
        self.volume_info = None
        self.fs_info_cache = {}
        self.fs_info = None
        self.is_wiped_image = False
        self._directory_cache = {}  # Cache for directory contents
        self._partition_cache = None  # Cache for partitions
        self._sector_size = None  # Read from the image on first use
        self._os_info_cache = {}  # Registry-derived OS details, per partition
        #: What kind of container the evidence is, for display: "VHDX",
        #: "VMDK snapshot (1 parent)"... None for raw and E01.
        self.container_note = None
        #: Why the image would not open, for the examiner (load_image False).
        self.load_error = None
        #: File systems that are not at a byte offset of the image: an
        #: unlocked BitLocker volume (keyed by its partition's start sector,
        #: which it replaces) and shadow copies (containers.shadow_key).
        self._volumes = {}
        self._bitlocker = {}        # start sector -> unlocked volume (any)
        self._unlocked_kind = {}    # start sector -> 'bitlocker'|'fvde'|...
        self._keep = {}             # start sector -> objects a volume needs
        self._shadows = {}          # start sector -> (pyvshadow volume, stores)
        self._bitlocker_checked = {}
        self._kinds = {}            # start sector -> containers.volume_kind
        self._lvm = {}              # start sector -> (handle, group, [lv])
        self._apfs = {}             # start sector -> (container, [volume])

        #: False when the image could not be opened; callers should check
        #: this rather than waiting for a later AttributeError.
        self.loaded = self.load_image()

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
        for volume in list(getattr(self, '_bitlocker', {}).values()) + \
                [shadow for shadow, _stores in
                 getattr(self, '_shadows', {}).values() if shadow]:
            try:
                volume.close()
            except Exception:
                pass
        for holder in ('_lvm', '_apfs'):
            for first, *_rest in getattr(self, holder, {}).values():
                try:
                    first.close()
                except Exception:
                    pass
        if hasattr(self, '_volumes'):
            self._volumes.clear()
            self._bitlocker.clear()
            self._shadows.clear()
            self._lvm.clear()
            self._apfs.clear()

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
        """Byte ranges occupied by allocated files, for carving to skip.

        The ranges come from each file's data runs -- the blocks the
        filesystem actually assigned to it. An earlier version estimated them
        as `inode number x block size`, which bears no relation to where NTFS
        places data: measured against the real runs on the test image, those
        estimates were 1-3 GB out. The map therefore protected the wrong
        regions, so carving skipped free space and recovered files that had
        never been deleted.

        Returned sorted and merged, so is_offset_allocated can binary search
        it.
        """
        allocation_map = []

        try:
            fs_info = self.get_fs_info(start_offset)
            if not fs_info:
                logger.warning(f"Unable to get filesystem info for offset {start_offset}")
                return allocation_map

            block_size = fs_info.info.block_size
            partition_offset = start_offset * self.sector_size
            visited = set()

            def record_runs(file_obj):
                """Add every block run this file occupies."""
                for attribute in file_obj:
                    try:
                        runs = list(attribute)
                    except Exception:
                        continue        # resident data has no runs to skip
                    for run in runs:
                        if run.len <= 0 or run.addr <= 0:
                            continue
                        begin = partition_offset + run.addr * block_size
                        allocation_map.append(
                            (begin, begin + run.len * block_size))

            def walk_directory(directory, depth=0):
                if depth > MAX_DIRECTORY_DEPTH:
                    # Audible, because the consequence is silent otherwise: an
                    # incomplete map means allocated files below this point are
                    # carved as though they had been deleted.
                    logger.warning(
                        "Allocation map stopped at depth %d; files nested "
                        "deeper are not protected from carving",
                        MAX_DIRECTORY_DEPTH)
                    return
                for entry in directory:
                    try:
                        if entry.info.meta is None or entry.info.name is None:
                            continue
                        name = entry.info.name.name.decode('utf-8', errors='ignore')
                        if name in (".", ".."):
                            continue

                        inode = entry.info.meta.addr
                        if inode in visited:
                            continue        # hard links, and directory cycles
                        visited.add(inode)

                        allocated = bool(int(entry.info.meta.flags)
                                         & pytsk3.TSK_FS_META_FLAG_ALLOC)
                        if not allocated:
                            continue        # deleted: leave it to be carved

                        if entry.info.meta.size > 0:
                            try:
                                record_runs(fs_info.open_meta(inode=inode))
                            except Exception as e:
                                logger.debug("Could not read runs for %s: %s", name, e)

                        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            try:
                                walk_directory(fs_info.open_dir(inode=inode),
                                               depth + 1)
                            except Exception as e:
                                logger.debug("Could not open directory %s: %s", name, e)
                    except Exception as e:
                        logger.debug("Skipping a directory entry: %s", e)

            try:
                walk_directory(fs_info.open_dir(path="/"))
            except Exception as e:
                logger.error(f"Error accessing root directory: {e}")

            allocation_map = self._merge_ranges(allocation_map)
            logger.info("Allocation map: %d regions covering %.1f MB",
                        len(allocation_map),
                        sum(e - b for b, e in allocation_map) / (1024 * 1024))

        except Exception as e:
            logger.error(f"Error building allocation map: {e}")

        return allocation_map

    @staticmethod
    def _merge_ranges(ranges):
        """Sort ranges and coalesce any that touch or overlap.

        A fragmented file contributes one run per fragment and neighbouring
        files often sit back to back, so merging keeps the map small enough to
        search quickly.
        """
        if not ranges:
            return []
        ranges.sort(key=lambda pair: pair[0])
        merged = [list(ranges[0])]
        for begin, end in ranges[1:]:
            if begin <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([begin, end])
        return [tuple(pair) for pair in merged]


    #: EWF header fields worth showing, in the order an examiner reads them,
    #: paired with the label to display. libewf exposes these as free-text
    #: header values written by the acquisition tool.
    _EWF_HEADER_FIELDS = (
        ('case_number', 'Case Number'),
        ('evidence_number', 'Evidence Number'),
        ('description', 'Description'),
        ('examiner_name', 'Examiner'),
        ('notes', 'Notes'),
        ('acquiry_date', 'Acquired'),
        ('system_date', 'System Date'),
        ('acquiry_software_version', 'Acquisition Tool'),
        ('acquiry_operating_system', 'Acquisition OS'),
    )

    #: libewf media type and compression identifiers, for the numbers the
    #: handle reports.
    _EWF_MEDIA_TYPES = {0: 'Removable disk', 1: 'Fixed disk',
                        3: 'Optical disc', 14: 'Logical evidence', 16: 'Memory'}
    _EWF_COMPRESSION = {0: 'None', 1: 'Deflate', 2: 'bzip2'}

    def get_acquisition_info(self):
        """Chain-of-custody metadata recorded when the image was acquired.

        An E01 carries the case and evidence numbers, the examiner's name, the
        acquisition date and the tool that wrote it. That is the provenance of
        the evidence -- the first thing an examiner documents -- and it was
        being read from disk and thrown away. Returns an empty dict for raw
        images, which carry no such record.
        """
        if self.get_image_type() != 'ewf':
            return {}

        info = {}
        handle = None
        try:
            handle = pyewf.handle()
            handle.open(pyewf.glob(self.image_path))

            try:
                available = handle.get_header_values()
            except Exception as e:
                logger.debug("No EWF header values: %s", e)
                available = {}

            for key, label in self._EWF_HEADER_FIELDS:
                value = available.get(key)
                if value:
                    info[label] = str(value).strip()

            def add(label, getter, translate=None):
                try:
                    value = getter()
                except Exception:
                    return
                if translate is not None:
                    value = translate.get(value, f"Unknown ({value})")
                info[label] = value

            add('Media Type', handle.get_media_type, self._EWF_MEDIA_TYPES)
            add('Compression', handle.get_compression_method, self._EWF_COMPRESSION)
            try:
                info['Chunk Size'] = f"{handle.get_chunk_size():,} bytes"
            except Exception:
                pass
            try:
                info['Sectors'] = f"{handle.get_number_of_sectors():,}"
            except Exception:
                pass

            # The hashes recorded at acquisition, distinct from anything the
            # verification dialog computes now.
            for algorithm in ('MD5', 'SHA1'):
                try:
                    stored = handle.get_hash_value(algorithm)
                except Exception:
                    continue
                if stored:
                    info[f'Stored {algorithm}'] = stored

        except Exception as e:
            logger.warning("Could not read acquisition metadata: %s", e)
        finally:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass

        return info

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
        elif extension in containers.VIRTUAL_DISK_EXTENSIONS:
            return "virtual"
        else:
            raise ValueError(f"Unsupported image type: {extension}")

    #: Ranges read concurrently when hashing an EWF image. Throughput rises
    #: steeply to four and flattens after six, so more workers only add
    #: handles and memory.
    HASH_WORKERS = 4

    def _hash_ewf_parallel(self, filenames, total_size, hashers,
                           progress_callback=None):
        """Hash an EWF image, decompressing several ranges at once.

        Each worker opens its own handle, seeks to its slice and decompresses
        it into a small bounded queue; this thread drains the queues in slice
        order and feeds the hashers. Order matters -- a hash is not
        associative -- so only the decompression is parallel, never the
        hashing.

        The queues are deliberately shallow: a worker that runs ahead blocks
        rather than buffering gigabytes of decompressed data.
        """
        if total_size <= 0:
            return 0

        workers = max(1, min(self.HASH_WORKERS, total_size // CHUNK_SIZE or 1))
        slice_size = total_size // workers
        queues = [queue.Queue(maxsize=2) for _ in range(workers)]
        errors = []

        def read_slice(index):
            start = index * slice_size
            end = total_size if index == workers - 1 else start + slice_size
            handle = None
            try:
                handle = pyewf.handle()
                handle.open(filenames)
                handle.seek(start)
                remaining = end - start
                while remaining > 0:
                    chunk = handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    queues[index].put(chunk)
            except Exception as e:
                logger.error("Hash worker %d failed: %s", index, e)
                errors.append(e)
            finally:
                queues[index].put(None)
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass

        threads = [threading.Thread(target=read_slice, args=(i,), daemon=True)
                   for i in range(workers)]
        for thread in threads:
            thread.start()

        size = 0
        try:
            for index in range(workers):
                while True:
                    chunk = queues[index].get()
                    if chunk is None:
                        break
                    for hasher in hashers:
                        hasher.update(chunk)
                    size += len(chunk)
                    if progress_callback:
                        try:
                            progress_callback(size, total_size)
                        except Exception as e:
                            logger.error(f"Progress callback error: {e}")
        finally:
            for thread in threads:
                thread.join(timeout=5)

        if errors:
            raise errors[0]
        return size

    def calculate_hashes(self, progress_callback=None):
        """Hash the image for verification, reporting progress as it goes.

        SHA-256 is computed only when the image carries no stored hashes to
        verify against. An E01 records MD5 and SHA-1 at acquisition, and those
        are what the result is checked against; a third digest that nothing
        compares to costs about 9% of the hashing time -- roughly 17 seconds on
        a 16 GB image -- for a number no one looks at. A raw image stores
        nothing, so there SHA-256 is the only durable identifier and is worth
        having.
        """
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = None
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

                    # Nothing to check a SHA-256 against when the image
                    # already carries its own hashes.
                    if not (stored_md5 or stored_sha1):
                        hash_sha256 = hashlib.sha256()

                    # Decompressing the image is the expensive part -- on a
                    # compressed E01 it is ~94% of the work, hashing only ~6%
                    # -- and libewf offers no threading of its own. Several
                    # handles reading disjoint ranges do decompress in
                    # parallel, though, so the read is split across workers
                    # while one hasher consumes their output in order.
                    hashers = [hash_md5, hash_sha1]
                    if hash_sha256 is not None:
                        hashers.append(hash_sha256)
                    size = self._hash_ewf_parallel(
                        filenames, total_size, hashers, progress_callback)
                finally:
                    ewf_handle.close()

            elif image_type == "virtual":
                # The disk, not its container files: a split VMDK is many
                # files, a VHDX's layout changes as it is compacted, and a
                # differencing disk is meaningless without its parents. What
                # the guest saw is what is evidence.
                total_size = self.img_info.get_size()
                hash_sha256 = hashlib.sha256()
                position = 0
                while position < total_size:
                    chunk = self.img_info.read(
                        position, min(CHUNK_SIZE, total_size - position))
                    if not chunk:
                        break
                    for hasher in (hash_md5, hash_sha1, hash_sha256):
                        hasher.update(chunk)
                    position += len(chunk)
                    size = position
                    if progress_callback and total_size > 0:
                        try:
                            progress_callback(size, total_size)
                        except Exception as e:
                            logger.error(f"Progress callback error: {e}")

            elif image_type == "raw":
                try:
                    total_size = os.path.getsize(self.image_path)
                    hash_sha256 = hashlib.sha256()
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
                'computed_sha256': hash_sha256.hexdigest() if hash_sha256 else None,
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
        """Load the image and read its volume/filesystem information.

        Returns True if the image opened, False otherwise. Previously this
        returned None either way and left the handler half-initialised, so a
        failed load only surfaced later as an AttributeError from get_size().
        """
        image_type = self.get_image_type()

        try:
            if image_type == "ewf":
                filenames = pyewf.glob(self.image_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                self.img_info = EWFImgInfo(ewf_handle)
            elif image_type == "raw":
                self.img_info = pytsk3.Img_Info(self.image_path)
            elif image_type == "virtual":
                self.img_info, self.container_note = \
                    containers.open_virtual_disk(self.image_path)
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
            return True
        except Exception as e:
            logger.error("Could not load image %s: %s", self.image_path, e)
            self.load_error = str(e)
            self.img_info = None
            self.volume_info = None
            self.fs_info = None
            self.is_wiped_image = True
            return False

    def has_filesystem(self, start_offset):
        fs_info = self.get_fs_info(start_offset)
        return fs_info is not None

    #: Filesystem signatures, as (byte offset from the partition start, the
    #: bytes to expect there, the name). Read directly rather than through
    #: TSK, so a filesystem that will not mount is still reported as present.
    _FS_SIGNATURES = (
        (3, b'NTFS    ', 'NTFS'),
        (3, b'MSDOS', 'FAT'),
        (3, b'MSWIN', 'FAT'),
        (0x36, b'FAT12', 'FAT12'),
        (0x36, b'FAT16', 'FAT16'),
        (0x52, b'FAT32', 'FAT32'),
        (3, b'EXFAT   ', 'ExFAT'),
        (0x8001, b'CD001', 'ISO9660'),
        (1024 + 56, b'\x53\xef', 'Ext2/3/4'),
        (0x400, b'H+', 'HFS+'),
        (0x400, b'HX', 'HFSX'),
        (0x20, b'NXSB', 'APFS'),
        # UFS puts its superblock well past the partition start and writes the
        # magic in the host's byte order, so both spellings have to be
        # accepted. UFS1 and UFS2 differ only in where the block sits.
        (8192 + 1372, _UFS_MAGIC_LE, 'UFS1'),
        (8192 + 1372, _UFS_MAGIC_BE, 'UFS1'),
        (65536 + 1372, _UFS_MAGIC_LE, 'UFS2'),
        (65536 + 1372, _UFS_MAGIC_BE, 'UFS2'),
        (65536 + 1372, _UFS2_MAGIC_LE, 'UFS2'),
        (65536 + 1372, _UFS2_MAGIC_BE, 'UFS2'),
    )

    def detect_filesystems(self, start_offset):
        """Every filesystem signature present at this partition offset.

        Returns a list of names, longest-standing first. More than one means
        the partition was formatted repeatedly without being wiped, and the
        earlier filesystem's structures survive underneath -- which is a
        finding in its own right, not an error: the older data is still there
        to be recovered.

        This deliberately does not ask TSK. TSK reports what it can mount;
        this reports what is on the media.
        """
        found = []
        if start_offset in self._volumes:
            return found         # not at a byte offset of the image
        try:
            base = start_offset * self.sector_size
            # One read covering every signature offset above.
            header = self.read(base, 0x11000)
        except Exception as exc:
            logger.debug("Could not read partition header at %d: %s",
                         start_offset, exc)
            return found

        if not header:
            return found

        for offset, magic, name in self._FS_SIGNATURES:
            if header[offset:offset + len(magic)] == magic and name not in found:
                found.append(name)
        return found

    def describe_filesystem(self, start_offset):
        """What to tell the examiner about this partition.

        Prefers what TSK actually opened. Falls back to the signatures when it
        opened nothing, so a partition holding an unmountable filesystem is
        never described as empty.
        """
        fs_type = self.get_fs_type(start_offset)
        signatures = self.detect_filesystems(start_offset)

        if fs_type not in ("N/A", "Unknown"):
            others = [s for s in signatures if not s.startswith(fs_type[:3])]
            if others:
                return (f"{fs_type} (also found: {', '.join(others)} -- "
                        f"reformatted, earlier data may survive)")
            return fs_type

        if len(signatures) > 1:
            return (f"{' + '.join(signatures)} -- two file systems present, "
                    f"neither can be opened")
        if signatures:
            return f"{signatures[0]} (present but not readable)"
        return fs_type

    def is_wiped(self):
        # Image is considered wiped if no volume info, no filesystem detected
        return self.is_wiped_image

    @property
    def sector_size(self):
        """Bytes per sector, as the image itself reports it.

        Partition offsets come out of pytsk3 in sectors and have to be
        multiplied to reach a byte offset. That multiplier is a property of
        the evidence, not a constant: a 4Kn drive uses 4096, and assuming 512
        there would place every partition eight times too early -- silently,
        because the only symptom is a filesystem that will not open.

        SECTOR_SIZE is the fallback for an image with no volume system, where
        there is nothing to ask.
        """
        if self._sector_size is None:
            size = SECTOR_SIZE
            volume_info = getattr(self, 'volume_info', None)
            if volume_info is not None:
                try:
                    reported = int(volume_info.info.block_size)
                    if reported > 0:
                        size = reported
                except Exception as e:
                    logger.debug("Could not read the volume's sector size: %s", e)
            if size != SECTOR_SIZE:
                logger.info("Image reports %d-byte sectors (not %d)",
                            size, SECTOR_SIZE)
            self._sector_size = size
        return self._sector_size

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

    #: Root inode to fall back on when a filesystem will not say. 5 is NTFS's,
    #: which is the common case here; FAT uses 2 and ext uses 2 as well, so a
    #: wrong guess shows an empty volume rather than an error.
    DEFAULT_ROOT_INODE = 5

    def get_root_inode(self, start_offset):
        """The root directory's inode for the volume at `start_offset`.

        Every filesystem numbers this differently -- NTFS 5, FAT 2, ext 2 --
        and TSK reports the right one. It was hardcoded to 5 throughout, so
        browsing a FAT volume asked for inode 5, got nothing back and showed
        the volume as empty.
        """
        fs_info = self.get_fs_info(start_offset)
        if fs_info is None:
            return self.DEFAULT_ROOT_INODE
        try:
            root = int(fs_info.info.root_inum)
        except Exception:
            return self.DEFAULT_ROOT_INODE
        return root if root >= 0 else self.DEFAULT_ROOT_INODE

    @lru_cache(maxsize=32)
    def get_fs_info(self, start_offset):
        """Retrieve the FS_Info for a partition, initializing it if necessary.

        `start_offset` may also name a volume inside a partition: the
        unlocked BitLocker volume at that partition, or a shadow copy's key
        (containers.shadow_key) -- opened on first use, so a bookmark into a
        snapshot resolves after the case is reopened.
        """
        if start_offset not in self.fs_info_cache:
            shadow = containers.split_shadow_key(start_offset)
            if shadow is not None and start_offset not in self._volumes:
                self.shadow_copies(shadow[0])
            logical = containers.split_lvm_key(start_offset)
            if logical is not None and start_offset not in self._volumes:
                self.logical_volumes(logical[0])
            apfs = containers.split_apfs_key(start_offset)
            if apfs is not None:
                return self._apfs_file_system(start_offset, *apfs)
            if logical is not None and start_offset not in self._volumes:
                return None
            try:
                if start_offset in self._volumes:
                    fs_info = pytsk3.FS_Info(self._volumes[start_offset],
                                             offset=0)
                elif shadow is not None:
                    return None
                else:
                    fs_info = pytsk3.FS_Info(
                        self.img_info, offset=start_offset * self.sector_size)
                self.fs_info_cache[start_offset] = fs_info
            except Exception as e:
                return None
        return self.fs_info_cache[start_offset]

    # --- one file, read lazily --------------------------------------------------

    def open_file_object(self, inode_number, start_offset):
        """A Python file object over a file on the image, read on demand --
        for what is too big to hold in memory (a 20 GB mailbox).
        None if the file cannot be opened."""
        fs = self.get_fs_info(start_offset)
        if fs is None:
            return None
        try:
            entry = fs.open_meta(inode=inode_number)
            size = int(entry.info.meta.size)
        except Exception as exc:
            logger.debug("Could not open inode %s: %s", inode_number, exc)
            return None
        return containers.ByteWindow(
            lambda offset, length: entry.read_random(offset, length),
            0, size)

    def read_file_bytes(self, inode_number, start_offset, length):
        """The first `length` bytes of a file -- enough to recognise it."""
        stream = self.open_file_object(inode_number, start_offset)
        return stream.read(length) if stream is not None else None

    # --- volumes inside partitions: BitLocker, shadow copies -----------------

    def partition_bytes(self, start_sector):
        """(byte offset, byte length) of the partition at `start_sector`;
        the whole image for an unpartitioned one at 0."""
        for _addr, _desc, start, length in self.get_partitions():
            if start == start_sector:
                return start * self.sector_size, length * self.sector_size
        if start_sector == 0:
            return 0, self.get_size()
        raise KeyError(start_sector)

    def _partition_window(self, start_sector):
        offset, length = self.partition_bytes(start_sector)
        return containers.ByteWindow(self.read, offset, length)

    def _forget_filesystem(self, key):
        """Drop what was cached about the file system at `key`."""
        stale = self.fs_info_cache.pop(key, None)
        if stale is not None and hasattr(stale, 'close'):
            try:
                stale.close()
            except Exception:
                pass
        self.get_fs_info.cache_clear()
        self.get_fs_type.cache_clear()
        self._directory_cache.clear()

    def volume_kind(self, start_sector):
        """'bitlocker', 'fvde', 'luks', 'lvm', 'apfs' or None for a
        partition (or an unpartitioned image at 0)."""
        if start_sector not in self._kinds:
            if start_sector >= containers.SHADOW_KEY_BASE:
                self._kinds[start_sector] = None
            else:
                try:
                    self._kinds[start_sector] = containers.volume_kind(
                        self._partition_window(start_sector))
                except Exception:
                    self._kinds[start_sector] = None
        return self._kinds[start_sector]

    def encryption(self, start_sector):
        """The kind of an encrypted volume at a partition, or None."""
        kind = self.volume_kind(start_sector)
        return kind if kind in ('bitlocker', 'fvde', 'luks') else None

    def unlocked_kind(self, start_sector):
        return self._unlocked_kind.get(start_sector)

    def unlock_volume(self, start_sector, kind, **secret):
        """Unlock a BitLocker, FileVault 2 or LUKS volume at a partition;
        its decrypted file system then replaces the partition's, at the same
        key. Raises containers.ContainerError with the reason."""
        if start_sector in self._bitlocker:
            return True
        window = self._partition_window(start_sector)
        keep = []
        if kind == 'bitlocker':
            volume = containers.unlock_bitlocker(
                window, secret.get('recovery_password'),
                secret.get('password'), secret.get('startup_key'))
        elif kind == 'fvde':
            volume, keep = containers.unlock_fvde(
                window, secret.get('password'),
                secret.get('recovery_password'))
        elif kind == 'luks':
            volume = containers.unlock_luks(window, secret.get('password'))
        else:
            raise containers.ContainerError(f"Cannot unlock {kind} here")
        self._bitlocker[start_sector] = volume
        self._unlocked_kind[start_sector] = kind
        self._keep[start_sector] = keep + [window]
        self._volumes[start_sector] = containers.LibyalImgInfo(
            volume, volume.get_size(), keep=[])
        self._forget_filesystem(start_sector)
        self._shadows.pop(start_sector, None)       # re-read, decrypted
        logger.info("%s volume at sector %d unlocked",
                    containers.ENCRYPTION_NAMES.get(kind, kind), start_sector)
        return True

    # --- LVM and APFS: several volumes in one partition -------------------

    def logical_volumes(self, start_sector):
        """An LVM partition's logical volumes: [{'key', 'index', 'name',
        'size', 'group'}]."""
        if start_sector not in self._lvm:
            try:
                handle, group, volumes = containers.open_lvm(
                    self._partition_window(start_sector))
            except Exception as exc:
                logger.warning("LVM at %s unreadable: %s", start_sector, exc)
                self._lvm[start_sector] = (_Closed(), None, [])
                return []
            self._lvm[start_sector] = (handle, group, volumes)
            for index, volume in enumerate(volumes):
                if volume is not None:
                    self._volumes[containers.lvm_key(start_sector, index)] = \
                        containers.LibyalImgInfo(volume, volume.size, keep=[])
        _handle, group, volumes = self._lvm[start_sector]
        return [{'key': containers.lvm_key(start_sector, index),
                 'index': index, 'name': volume.name, 'size': volume.size,
                 'group': group.name if group is not None else ''}
                for index, volume in enumerate(volumes) if volume is not None]

    def apfs_volumes(self, start_sector):
        """An APFS container's volumes: [{'key', 'index', 'name', 'size',
        'locked'}]."""
        if start_sector not in self._apfs:
            try:
                container, volumes = containers.open_apfs(
                    self._partition_window(start_sector))
            except Exception as exc:
                logger.warning("APFS at %s unreadable: %s", start_sector, exc)
                self._apfs[start_sector] = (_Closed(), [])
                return []
            self._apfs[start_sector] = (container, volumes)
        _container, volumes = self._apfs[start_sector]
        out = []
        for index, volume in enumerate(volumes):
            if volume is None:
                continue
            try:
                locked = bool(volume.is_locked())
            except (IOError, OSError):
                locked = True
            out.append({'key': containers.apfs_key(start_sector, index),
                        'index': index, 'name': _safe(volume, 'name', ''),
                        'size': _safe(volume, 'size', 0), 'locked': locked})
        return out

    def unlock_apfs(self, key, password=None, recovery_password=None):
        start, index = containers.split_apfs_key(key)
        self.apfs_volumes(start)
        volumes = self._apfs[start][1]
        if index >= len(volumes) or volumes[index] is None:
            raise containers.ContainerError("No such APFS volume")
        containers.unlock_apfs(volumes[index], password, recovery_password)
        self._unlocked_kind[key] = 'apfs'
        self._forget_filesystem(key)
        logger.info("APFS volume %d at sector %d unlocked", index, start)
        return True

    def _apfs_file_system(self, key, start, index):
        from trace_app.core.apfs import ApfsFileSystem
        if key in self.fs_info_cache:
            return self.fs_info_cache[key]
        self.apfs_volumes(start)
        container, volumes = self._apfs.get(start, (None, []))
        if index >= len(volumes) or volumes[index] is None:
            return None
        volume = volumes[index]
        try:
            if volume.is_locked():
                return None
        except (IOError, OSError):
            return None
        fs = ApfsFileSystem(volume, container)
        self.fs_info_cache[key] = fs
        return fs

    def volume_offsets(self):
        """Every file system to read: each partition's start -- or, for
        an LVM partition or APFS container, its volumes' keys (unlocked ones
        only). What analysis, indexing, activity and NTFS walk."""
        partitions = self.get_partitions()
        starts = [p[2] for p in partitions] if partitions else [0]
        out = []
        for start in dict.fromkeys(starts):
            kind = self.volume_kind(start)
            if kind == 'lvm':
                out += [v['key'] for v in self.logical_volumes(start)]
            elif kind == 'apfs':
                out += [v['key'] for v in self.apfs_volumes(start)
                        if not v['locked']]
            else:
                out.append(start)
        return out

    def is_bitlocker(self, start_sector):
        """Is the partition (or an unpartitioned image) BitLocker?

        Asked of libbde rather than read from byte 3: a BitLocker To Go
        volume begins with an ordinary FAT32 boot sector -- the "discovery
        volume" holding the reader program -- and only its metadata says
        what it is. TSK opens that decoy and lists it as FAT32.
        """
        cached = self._bitlocker_checked.get(start_sector)
        if cached is None:
            try:
                import pybde
                cached = bool(pybde.check_volume_signature_file_object(
                    self._partition_window(start_sector)))
            except Exception:
                cached = False
            self._bitlocker_checked[start_sector] = cached
        return cached

    def is_unlocked(self, start_sector):
        return start_sector in self._bitlocker or \
            self._unlocked_kind.get(start_sector) == 'apfs' or \
            self._unlocked_kind.get(start_sector) == 'apfs'

    def bitlocker_facts(self, start_sector):
        return containers.bitlocker_facts(self._partition_window(start_sector))

    def unlock_bitlocker(self, start_sector, recovery_password=None,
                         password=None, startup_key=None):
        """Unlock the BitLocker volume at a partition; from then on, its
        files are read through the decrypting volume at the same key.
        Raises containers.ContainerError with the reason if it will not."""
        return self.unlock_volume(start_sector, 'bitlocker',
                                  recovery_password=recovery_password,
                                  password=password, startup_key=startup_key)

    def apply_unlocks(self, unlocks):
        """Unlock with keys an examiner already gave: {start or volume
        key: {'_kind': ..., secret...}} -- what a background job is handed,
        in memory. A secret without '_kind' is BitLocker's (older form)."""
        for start, secret in (unlocks or {}).items():
            secret = dict(secret)
            kind = secret.pop('_kind', 'bitlocker')
            try:
                if kind == 'apfs':
                    self.unlock_apfs(int(start), **secret)
                else:
                    self.unlock_volume(int(start), kind, **secret)
            except Exception as exc:
                logger.warning("Could not unlock the volume at %s: %s",
                               start, exc)

    def _volume_stream(self, start_sector):
        """A partition's volume as a file object -- decrypted if it is an
        unlocked BitLocker volume."""
        if start_sector in self._bitlocker:
            volume = self._bitlocker[start_sector]
            return containers.ByteWindow(
                lambda offset, length: volume.read_buffer_at_offset(length,
                                                                    offset),
                0, volume.get_size())
        return self._partition_window(start_sector)

    def shadow_copies(self, start_sector):
        """The partition's Volume Shadow Copies, oldest first:
        [{'key', 'index', 'created', 'size', 'identifier'}]."""
        if start_sector not in self._shadows:
            try:
                stream = self._volume_stream(start_sector)
            except KeyError:
                return []
            shadow, stores = containers.open_shadow_copies(stream)
            self._shadows[start_sector] = (shadow, stores)
            for index, store in enumerate(stores):
                if store is None:
                    continue
                key = containers.shadow_key(start_sector, index)
                self._volumes[key] = containers.LibyalImgInfo(
                    store, store.get_volume_size(), keep=[])
        shadow, stores = self._shadows[start_sector]
        out = []
        for index, store in enumerate(stores):
            if store is None:
                continue
            created = None
            try:
                created = store.get_creation_time()
            except (IOError, OSError, AttributeError):
                pass
            if created is not None and created.tzinfo is None:
                import datetime
                created = created.replace(tzinfo=datetime.timezone.utc)
            out.append({'key': containers.shadow_key(start_sector, index),
                        'index': index, 'created': created,
                        'size': store.get_volume_size(),
                        'identifier': str(getattr(store, 'identifier', ''))})
        return out

    @lru_cache(maxsize=32)
    def get_fs_type(self, start_offset):
        """Retrieve the file system type for a partition."""
        try:
            fs = self.get_fs_info(start_offset)
            from trace_app.core.apfs import is_apfs
            if is_apfs(fs):
                return "APFS"
            fs_type = fs.info.ftype

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

    @staticmethod
    def recovery_note(entry):
        """Why a deleted entry cannot be opened, or None when it can.

        `entry` is a dict from get_directory_contents.
        """
        if not entry.get('is_deleted'):
            return None
        if entry.get('is_recoverable'):
            return None
        if not entry.get('inode_number'):
            return ('The directory entry no longer points at any metadata, so '
                    'only the file name survives. Carving unallocated space is '
                    'the remaining option.')
        return ('The metadata record survives but records no content: the file '
                'system cleared its size and block pointers on delete. Carving '
                'unallocated space is the remaining option.')

    @staticmethod
    def _meta_for_orphan(fs, inode):
        """Metadata for an entry whose directory record no longer links it.

        Returns None when the record cannot be opened, which is the ordinary
        case for a name whose MFT entry has since been reused by another file.
        """
        try:
            # The File must be bound to a name. Reading .info.meta straight
            # off the temporary lets pytsk3 collect the File first, and the
            # metadata comes back None -- silently, so the entry then reports
            # size 0 instead of raising.
            file_obj = fs.open_meta(inode=inode)
            meta = file_obj.info.meta
            if meta is None:
                return None
            # Copy out what the listing needs, so nothing depends on the
            # File's lifetime once this returns.
            return _OrphanMeta(meta)
        except Exception:
            return None

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
                # FAT and exFAT store wall-clock time with no timezone; every
                # other filesystem here stores UTC. See safe_datetime.
                zoned = self.get_fs_type(start_offset) not in _TIMEZONE_NAIVE

                for entry in directory:
                    if entry.info.name.name in [b".", b".."]:
                        continue

                    # A deleted NTFS entry keeps its name but loses the link
                    # to its metadata, so entry.info.meta is None. The MFT
                    # record number survives in the name structure, and
                    # opening it returns the file intact -- reading the inode
                    # only from info.meta is what left deleted files listed at
                    # size 0 with no way to open them.
                    meta = entry.info.meta
                    inode = meta.addr if meta else None
                    if inode is None:
                        inode = getattr(entry.info.name, 'meta_addr', None) or None
                        if inode is not None:
                            recovered = self._meta_for_orphan(fs, inode)
                            if recovered is not None:
                                meta = recovered

                    is_directory = False
                    if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        is_directory = True

                    entries.append({
                        "name": entry.info.name.name.decode('utf-8', errors='replace') if hasattr(entry.info.name,
                                                                                                  'name') else None,
                        "is_directory": is_directory,
                        "inode_number": inode,
                        "size": meta.size if meta and meta.size is not None else 0,
                        "accessed": safe_datetime(meta.atime, zoned) if hasattr(meta, 'atime') else "N/A",
                        "modified": safe_datetime(meta.mtime, zoned) if hasattr(meta, 'mtime') else "N/A",
                        "created": safe_datetime(meta.crtime, zoned) if hasattr(meta, 'crtime') else "N/A",
                        "changed": safe_datetime(meta.ctime, zoned) if hasattr(meta, 'ctime') else "N/A",
                        # Whether the filesystem still considers this entry
                        # live. TSK reports it and the listing was discarding
                        # it, so a deleted file in a directory looked exactly
                        # like a live one -- the one distinction an examiner
                        # most needs from a listing.
                        "is_deleted": self._entry_is_deleted(entry),
                        # Whether the content can still be reached. A deleted
                        # name whose inode pointer was zeroed (ext2 does this;
                        # so does NTFS once the MFT record is reused) has no
                        # metadata left to follow, so the name is all that
                        # survives. Saying so here spares the examiner
                        # discovering it one click at a time.
                        "is_recoverable": bool(inode) and bool(
                            meta and meta.size),
                        # The directory this entry belongs to, which is what
                        # locates a file when only its inode is known.
                        "parent_inode": getattr(entry.info.name, 'par_addr', None),
                        # How many times this MFT record has been reused. Two
                        # files can share an inode over a volume's life, and
                        # the sequence is what tells them apart -- which
                        # matters when correlating a deleted entry against a
                        # later allocation of the same record.
                        "sequence": getattr(entry.info.meta, 'seq', None),
                        # The NTFS attributes present, which is where alternate
                        # data streams show up.
                        "attributes": self._describe_attributes(fs, entry),
                    })

                # Cache results
                self._directory_cache[cache_key] = entries
                return entries

            except Exception as e:
                # Log the exception for debugging purposes
                logger.error(f"Error in get_directory_contents: {e}")
                return []
        return []

    #: NTFS attribute identifiers, as the Sleuth Kit tools label them.
    _ATTRIBUTE_NAMES = {
        16: '$STANDARD_INFORMATION', 32: '$ATTRIBUTE_LIST', 48: '$FILE_NAME',
        64: '$OBJECT_ID', 80: '$SECURITY_DESCRIPTOR', 96: '$VOLUME_NAME',
        112: '$VOLUME_INFORMATION', 128: '$DATA', 144: '$INDEX_ROOT',
        160: '$INDEX_ALLOCATION', 176: '$BITMAP', 192: '$REPARSE_POINT',
        256: '$LOGGED_UTILITY_STREAM',
    }

    @classmethod
    def _describe_attributes(cls, fs, entry):
        """Short summary of an entry's NTFS attributes.

        A named $DATA attribute is an alternate data stream -- a place to hide
        content that a plain listing does not show -- so the names are kept,
        not just the types.
        """
        meta = getattr(entry.info, 'meta', None)
        if meta is None:
            return ""

        try:
            file_obj = fs.open_meta(inode=meta.addr)
        except Exception:
            return ""

        parts = []
        try:
            for attribute in file_obj:
                info = attribute.info
                label = cls._ATTRIBUTE_NAMES.get(int(info.type), str(int(info.type)))
                name = info.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                if name:
                    label = f"{label}:{name}"
                if label not in parts:
                    parts.append(label)
        except Exception as e:
            logger.debug("Could not list attributes: %s", e)

        return ", ".join(parts)

    @staticmethod
    def _entry_is_deleted(entry):
        """True when the filesystem no longer considers this entry live.

        Both records are checked. A file can be unallocated in its metadata
        while its directory entry still stands, or the reverse -- the name
        removed from the directory index while the MFT record survives -- and
        either one means deleted. Reading only one flag misses roughly half
        the cases on NTFS.
        """
        try:
            name = getattr(entry.info, 'name', None)
            if name is not None and getattr(name, 'flags', None) is not None:
                if int(name.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                    return True

            meta = getattr(entry.info, 'meta', None)
            if meta is not None and getattr(meta, 'flags', None) is not None:
                if int(meta.flags) & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    return True
        except Exception as e:
            logger.debug("Could not read allocation flags: %s", e)
        return False

    def get_registry_hive(self, fs_info, hive_path, required=True):
        """Extract a registry hive from the given filesystem.

        `required` is False when the caller is only probing -- asking a volume
        whether it happens to hold a Windows installation. A data volume has no
        hives, which is normal and not worth an ERROR in the log; the registry
        browser, which is asked for a specific hive by name, still reports a
        failure as one.
        """
        try:
            registry_file = fs_info.open(hive_path)
            hive_data = registry_file.read_random(0, registry_file.info.meta.size)
            return hive_data
        except Exception as e:
            if required:
                logger.error(f"Error reading registry hive: {e}")
            else:
                logger.debug("No %s on this volume: %s", hive_path, e)
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

    def get_os_info(self, start_offset):
        """Operating system details for the volume at `start_offset`.

        Windows is read from the registry -- the version from SOFTWARE, the
        timezone from SYSTEM. The timezone matters more than it looks: NTFS
        stores every timestamp in UTC, so the machine's offset is what turns
        those into the local times a user would have seen.

        Linux and macOS keep the same information in files rather than a
        registry, so those are read too; an image of either was previously
        reported as having no operating system at all.

        Returns {} for a volume with no installation, which includes every data
        volume; there is nothing to report there rather than an error.
        """
        # Cached: reading the hives or release files costs real time, and the
        # volume table asks once per partition every time it is drawn.
        if start_offset in self._os_info_cache:
            return self._os_info_cache[start_offset]

        info = {}
        fs_type = self.get_fs_type(start_offset)
        fs_info = self.get_fs_info(start_offset)

        if fs_info:
            if fs_type == "NTFS":
                info.update(self._read_software_hive(fs_info))
                info.update(self._read_system_hive(fs_info))
            else:
                info.update(self._read_unix_os(fs_info))

        self._os_info_cache[start_offset] = info
        return info

    #: Files that name the operating system on a non-Windows volume, with how
    #: to read each one. Ordered so the most specific wins.
    _UNIX_MARKERS = (
        ('/etc/os-release', 'os_release'),
        ('/usr/lib/os-release', 'os_release'),
        ('/System/Library/CoreServices/SystemVersion.plist', 'plist'),
        ('/etc/lsb-release', 'os_release'),
        ('/etc/redhat-release', 'plain'),
        ('/etc/debian_version', 'debian'),
    )

    def _read_unix_os(self, fs_info):
        """Operating system details from a Linux or macOS volume.

        Neither keeps this in a registry: Linux writes /etc/os-release, macOS a
        SystemVersion.plist. Reading them means an image of either is described
        rather than coming back blank, which is what happened while only the
        Windows registry was consulted.
        """
        for path, kind in self._UNIX_MARKERS:
            try:
                handle = fs_info.open(path)
                raw = handle.read_random(0, min(handle.info.meta.size, 65536))
            except Exception:
                continue
            if not raw:
                continue

            text = raw.decode('utf-8', errors='replace')
            try:
                if kind == 'os_release':
                    fields = self._parse_os_release(text)
                elif kind == 'plist':
                    fields = self._parse_system_version(text)
                elif kind == 'debian':
                    fields = {'Operating System': 'Debian ' + text.strip()}
                else:
                    fields = {'Operating System': text.strip().splitlines()[0]}
            except Exception as e:
                logger.debug("Could not parse %s: %s", path, e)
                continue

            if fields:
                fields.update(self._read_unix_details(fs_info))
                return fields
        return {}

    @staticmethod
    def _parse_os_release(text):
        """PRETTY_NAME / NAME / VERSION out of an os-release file."""
        values = {}
        for line in text.splitlines():
            if '=' not in line or line.lstrip().startswith('#'):
                continue
            key, _, value = line.partition('=')
            values[key.strip()] = value.strip().strip(chr(34) + chr(39))

        name = values.get('PRETTY_NAME') or values.get('DISTRIB_DESCRIPTION')
        if not name:
            name = values.get('NAME') or values.get('DISTRIB_ID')
            version = values.get('VERSION') or values.get('DISTRIB_RELEASE')
            if name and version:
                name = name + ' ' + version
        if not name:
            return {}

        fields = {'Operating System': name}
        if values.get('VERSION_ID'):
            fields['Release'] = values['VERSION_ID']
        if values.get('BUILD_ID'):
            fields['Build'] = values['BUILD_ID']
        return fields

    @staticmethod
    def _parse_system_version(text):
        """ProductName and version out of macOS's SystemVersion.plist."""
        pairs = re.findall(r'<key>(.*?)</key>\s*<string>(.*?)</string>', text, re.DOTALL)
        values = {key.strip(): value.strip() for key, value in pairs}
        name = values.get('ProductName')
        if not name:
            return {}
        version = (values.get('ProductUserVisibleVersion')
                   or values.get('ProductVersion') or '')
        fields = {'Operating System': (name + ' ' + version).strip()}
        if values.get('ProductBuildVersion'):
            fields['Build'] = values['ProductBuildVersion']
        return fields

    def _read_unix_details(self, fs_info):
        """Hostname and timezone, where the volume records them."""
        fields = {}
        for path, label in (('/etc/hostname', 'Computer Name'),
                            ('/etc/timezone', 'Time Zone')):
            try:
                handle = fs_info.open(path)
                raw = handle.read_random(0, min(handle.info.meta.size, 4096))
                value = raw.decode('utf-8', errors='replace').strip()
                if value:
                    fields[label] = value.splitlines()[0]
            except Exception:
                continue
        return fields

    def _read_software_hive(self, fs_info):
        """Windows version details from SOFTWARE."""
        data = self.get_registry_hive(fs_info, "/Windows/System32/config/SOFTWARE",
                                      required=False)
        if not data:
            return {}

        fields = {}
        with FileSystemUtils.temp_file() as temp_path:
            try:
                with open(temp_path, 'wb') as handle:
                    handle.write(data)
                key = Registry.Registry(temp_path).open(
                    "Microsoft\\Windows NT\\CurrentVersion")
                for value_name, label in (("ProductName", "Operating System"),
                                          ("CurrentBuild", "Build"),
                                          ("DisplayVersion", "Release"),
                                          ("RegisteredOwner", "Registered Owner"),
                                          ("RegisteredOrganization", "Organisation"),
                                          ("ProductId", "Product ID"),
                                          ("InstallDate", "Installed")):
                    try:
                        value = key.value(value_name).value()
                    except Exception:
                        continue
                    if value in (None, ""):
                        continue
                    if value_name == "InstallDate":
                        value = safe_datetime(value)
                    fields[label] = str(value)
            except Exception as e:
                logger.debug("Could not read the SOFTWARE hive: %s", e)
        return fields

    def _read_system_hive(self, fs_info):
        """Timezone and computer name from SYSTEM."""
        data = self.get_registry_hive(fs_info, "/Windows/System32/config/SYSTEM",
                                      required=False)
        if not data:
            return {}

        fields = {}
        with FileSystemUtils.temp_file() as temp_path:
            try:
                with open(temp_path, 'wb') as handle:
                    handle.write(data)
                registry = Registry.Registry(temp_path)

                # Which control set was in use is recorded in Select\Current;
                # reading ControlSet001 blindly can pick the wrong one.
                try:
                    current = registry.open("Select").value("Current").value()
                except Exception:
                    current = 1
                control_set = f"ControlSet{int(current):03d}"

                try:
                    tz = registry.open(f"{control_set}\\Control\\TimeZoneInformation")
                    for value_name, label in (("TimeZoneKeyName", "Time Zone"),
                                              ("StandardName", "Time Zone (Standard)"),
                                              ("Bias", "UTC Offset")):
                        try:
                            value = tz.value(value_name).value()
                        except Exception:
                            continue
                        if value in (None, ""):
                            continue
                        # StandardName is often an unresolved resource
                        # reference such as '@tzres.dll,-112', which means
                        # nothing to a reader; TimeZoneKeyName already carries
                        # the readable name.
                        if isinstance(value, str) and value.startswith('@'):
                            continue
                        if value_name == "Bias":
                            # Bias is minutes to ADD to local time to reach
                            # UTC, so the offset a reader expects is its
                            # negation.
                            offset = -int(value)
                            sign = '+' if offset >= 0 else '-'
                            value = f"UTC{sign}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}"
                        fields[label] = str(value)
                except Exception as e:
                    logger.debug("No timezone information: %s", e)

                try:
                    name_key = registry.open(
                        f"{control_set}\\Control\\ComputerName\\ComputerName")
                    fields["Computer Name"] = str(
                        name_key.value("ComputerName").value())
                except Exception:
                    pass
            except Exception as e:
                logger.debug("Could not read the SYSTEM hive: %s", e)
        return fields

    def read_unallocated_space(self, start_offset, end_offset):
        try:
            sector = self.sector_size
            start_byte_offset = start_offset * sector
            end_byte_offset = max(end_offset * sector,
                                  start_byte_offset + sector - 1)
            size_in_bytes = end_byte_offset - start_byte_offset + 1  # Ensuring at least some data is read

            if size_in_bytes <= 0:
                logger.warning("Invalid size for unallocated space, adjusting to read at least one sector.")
                size_in_bytes = sector  # Adjust to read at least one sector

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
            fs_info = pytsk3.FS_Info(img_info,
                                     offset=offset_sectors * self.sector_size)
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
            byte_offset = offset_sectors * self.sector_size
            logger.info("Opening filesystem at offset %d sectors (%d bytes)",
                        offset_sectors, byte_offset)
            fs_info = pytsk3.FS_Info(img_info, offset=byte_offset)
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

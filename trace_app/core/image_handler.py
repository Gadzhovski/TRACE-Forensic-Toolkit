"""Forensic disk-image access.

Wraps pytsk3 (and pyewf for EWF/E01 containers) behind a single ImageHandler
that the rest of the application talks to: partition enumeration, filesystem
traversal, file content reads, and the allocation map used by file carving.
"""

import queue
import threading
import logging
import os
import re
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



class HashingCancelled(BaseException):
    """Raised from a hashing progress callback to stop the hash.

    A BaseException, like KeyboardInterrupt, on purpose: hashing reports
    progress from inside several `except Exception` blocks that keep a
    damaged chunk or a failing callback from ending the run, and a cancel
    must pass through all of them rather than be logged and ignored.
    """


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

class IncompleteEvidence(OSError):
    """A read past the data an incomplete image holds; the message says
    where the data ends and what is missing (core/ewf_check.py)."""


class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        # One handle, read from the window's thread and from workers: a
        # seek and a read from two threads interleave into wrong bytes.
        self._lock = threading.Lock()
        #: (what is missing, where the data ends) for a set that is not
        #: whole -- ImageHandler.load_image fills it.
        self.incomplete = None
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        with self._lock:
            try:
                self._ewf_handle.seek(offset)
                return self._ewf_handle.read(size)
            except OSError:
                if self.incomplete is None:
                    raise
        raise IncompleteEvidence(incomplete_message(self.incomplete,
                                                    offset))

    def get_size(self):
        return self._ewf_handle.get_media_size()


def incomplete_message(incomplete, offset=None):
    """An incomplete image's state in words: what is missing, where its
    data ends, and (for a failed read) where the read was."""
    missing, end = incomplete
    where = (f"Byte {offset:,} is not in this image. " if offset is not None
             else "")
    return (f"{where}The E01 is incomplete: {missing}. It holds data up to "
            f"{FileSystemUtils.get_readable_size(end)}; nothing past that "
            f"can be read.")


#: First segments of a split raw image: dd/split number from .000 or
#: .001 (dfvfs's ext2.splitraw.000). The Sleuth Kit finds the rest.
SPLIT_RAW_FIRST = ('.000', '.001')


def is_split_raw(path):
    return path.lower().endswith(SPLIT_RAW_FIRST)


class UnsupportedEvidence(ValueError):
    """A format TRACE recognises but cannot read; the message says what
    it is and what to do instead."""


def _starts_with(path, magic):
    try:
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                return handle.read(len(magic)) == magic
    except OSError:
        pass
    return False


# ImageHandler class with optimizations
#: Filesystems that store a local wall-clock time with no timezone recorded.
#: Reporting one of these as UTC claims knowledge the evidence does not carry.
_TIMEZONE_NAIVE = frozenset({'FAT12', 'FAT16', 'FAT32', 'ExFAT', 'ZIP'})


class _NoMedia:
    """The image of logical evidence: no sectors to read or carve."""

    def get_size(self):
        return 0

    def read(self, offset, size):
        return b''

    def close(self):
        pass

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
        self._layers = {}           # start sector -> fs_layers()
        #: start sector -> mdraid.Array (or None: not a member, or one
        #: whose array needs disks this image does not hold); see md_array.
        self._md = {}
        self._md_member = {}        # start sector -> mdraid.Member
        self._lvm = {}              # start sector -> (handle, group, [lv])
        self._apfs = {}             # start sector -> (container, [volume])
        #: Logical evidence (core/logical.py): an AD1 or L01 image, a
        #: folder, a ZIP or TAR -- one file system at 0, no sectors.
        self.logical_fs = None
        #: What replaying each hive's transaction logs did (regf_log).
        self.hive_recovery = {}

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
        if getattr(self, 'logical_fs', None) is not None:
            self.logical_fs.close()
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
        self._layers.clear()

    def get_size(self):
        """Returns the size of the disk image."""
        if self.img_info:
            return self.img_info.get_size()
        else:
            raise AttributeError("Image not loaded or unsupported format.")

    def read(self, offset, size):
        """Reads data from the image starting at `offset` for `size` bytes.
        Offsets from CARVE_SPACE up are inside a volume (carve_volumes)."""
        if offset >= self.CARVE_SPACE:
            return self._read_volume_space(offset, size)
        if self.img_info and hasattr(self.img_info, 'read'):
            return self.img_info.read(offset, size)
        else:
            raise NotImplementedError("The image format does not support direct reading.")

    # --- carving inside volumes ---------------------------------------------

    #: Carving reaches what the image's own bytes do not show plainly: an
    #: unlocked encrypted volume (decrypted), an LVM logical volume (its
    #: extents in order), a RAID array kept in one image. Each has a fixed
    #: range of addresses above any image -- CARVE_SPACE + slot *
    #: CARVE_SPAN, the slot from the partition's place among the image's
    #: partitions and the volume's index in it -- so a carve's offset reads
    #: back through read(), and its span ref stays valid after a reopen
    #: (an encrypted volume's once it is unlocked again).
    CARVE_SPACE = 1 << 61
    CARVE_SPAN = 1 << 44              # 16 TiB per volume
    _SLOTS_PER_PARTITION = 128        # the volume itself, then 64 LVs

    def carve_volumes(self):
        """[{'base', 'size', 'key', 'label'}] -- the volumes carving reads
        in their own address range, in address order."""
        if self.logical_fs is not None or self.img_info is None:
            return []
        partitions = self.get_partitions()
        starts = sorted({p[2] for p in partitions}) if partitions else [0]
        out = []
        for position, start in enumerate(starts):
            entries = []
            try:
                if start in self._bitlocker:
                    if self.inner_kind(start) == 'lvm':
                        entries = self._lv_entries(start)
                    else:
                        name = containers.ENCRYPTION_NAMES.get(
                            self._unlocked_kind.get(start), 'encrypted')
                        entries = [(0, start, f"decrypted {name} volume at "
                                              f"sector {start}")]
                elif self.volume_kind(start) == 'lvm':
                    entries = self._lv_entries(start)
                elif self.volume_kind(start) == 'ldm':
                    entries = [(1 + v['index'], v['key'],
                                f"dynamic volume {v['name']}")
                               for v in self.dynamic_volumes(start)
                               if v['readable']]
                else:
                    array = self.md_array(start)
                    if array is not None and array.level != 1:
                        entries = [(0, start, f"RAID{array.level} array at "
                                              f"sector {start}")]
            except Exception as exc:
                logger.warning("Volumes at sector %s not carved: %s", start,
                               exc)
                continue
            for index, key, label in entries:
                image = self._volumes.get(key)
                if image is None:
                    continue
                size = image.get_size()
                if size > self.CARVE_SPAN:
                    logger.warning("%s is larger than %d bytes: not carved",
                                   label, self.CARVE_SPAN)
                    continue
                slot = position * self._SLOTS_PER_PARTITION + index
                out.append({'base': self.CARVE_SPACE + slot * self.CARVE_SPAN,
                            'size': size, 'key': key, 'label': label})
        self._carve_space = {v['base']: v for v in out}
        return out

    def _lv_entries(self, start):
        return [(1 + v['index'], v['key'],
                 f"LVM volume {v['group']}/{v['name']}")
                for v in self.logical_volumes(start)]

    def _read_volume_space(self, offset, size):
        base = self.CARVE_SPACE + ((offset - self.CARVE_SPACE)
                                   // self.CARVE_SPAN * self.CARVE_SPAN)
        volume = getattr(self, '_carve_space', {}).get(base)
        if volume is None:
            self.carve_volumes()
            volume = self._carve_space.get(base)
        if volume is None:
            # Locked again, or no longer there: nothing to read.
            return b''
        within = offset - base
        if within >= volume['size']:
            return b''
        return self._volumes[volume['key']].read(
            within, min(size, volume['size'] - within))

    def volume_allocation(self, volume):
        """A carve volume's allocated ranges, in its own address range."""
        return self.build_allocation_map(volume['key'], base=volume['base'])

    def build_allocation_map(self, start_offset, base=None):
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
                # A partition with no file system TSK reads (a table, swap,
                # free space) has no allocations to map: normal, not a fault.
                logger.debug("No file system at sector %s: nothing to map",
                             start_offset)
                return allocation_map

            # Where the file system's offset 0 is: the partition, or (for
            # a volume carved in its own range) `base`.
            partition_offset = (start_offset * self.sector_size
                                if base is None else base)
            from trace_app.core.libyal_fs import is_libyal
            if is_libyal(fs_info):
                # XFS (extents of live files) and Btrfs (its extent tree):
                # no TSK runs to walk.
                allocation_map = self._merge_ranges(
                    [(partition_offset + b, partition_offset + e)
                     for b, e in fs_info.allocated_ranges()])
                logger.info("Allocation map: %d regions covering %.1f MB",
                            len(allocation_map),
                            sum(e - b for b, e in allocation_map) / 1048576)
                return allocation_map
            block_size = fs_info.info.block_size
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

    #: Volumes whose free space TRACE cannot tell from used space: their
    #: data is not where the partition's bytes are (LVM maps extents,
    #: LUKS and FileVault encrypt them).
    _UNMAPPED_KINDS = {'lvm': 'an LVM volume group', 'luks': 'a LUKS volume',
                       'fvde': 'a FileVault volume',
                       'mdraid': 'a Linux RAID member whose other disks '
                                 'are not in this image'}

    def partition_allocation(self, start_sector):
        """(allocated byte ranges, note) for carving one partition. The
        note says why a whole partition counts as used: carving it as
        "unallocated" would report live files as deleted ones."""
        kind = self.volume_kind(start_sector)
        if kind == 'ldm':
            return self._ldm_allocation(start_sector), None
        if start_sector in self._bitlocker or kind == 'lvm':
            # Encrypted bytes, or extents mapped elsewhere: the decrypted
            # volume and the logical volumes are carved in their own
            # ranges (carve_volumes), so the raw bytes are skipped.
            base, length = self.partition_bytes(start_sector)
            return [(base, base + length)], None
        array = self.md_array(start_sector)
        if array is not None:
            base, length = self.partition_bytes(start_sector)
            member = self.md_member(start_sector)
            if array.level != 1 or kind is not None:
                # The array is carved in its own range (carve_volumes).
                return [(base, base + length)], None
            # A mirror member's data is the array's, data_offset in.
            shift = member.data_offset
            return [(base, base + shift)] + [
                (b + shift, e + shift)
                for b, e in self.build_allocation_map(start_sector)], None
        if kind == 'apfs':
            base, length = self.partition_bytes(start_sector)
            volumes = self.apfs_volumes(start_sector)
            if not volumes or any(v['locked'] for v in volumes):
                return [(base, base + length)], (
                    f"the APFS container at sector {start_sector} is skipped: "
                    f"its free space cannot be told from a locked volume's "
                    f"files")
            ranges = []
            for volume in volumes:
                fs = self.get_fs_info(volume['key'])
                if fs is None:
                    return [(base, base + length)], (
                        f"the APFS container at sector {start_sector} is "
                        f"skipped: a volume could not be read")
                # Extents are container offsets.
                ranges += [(base + b, base + e)
                           for b, e in fs.allocated_ranges()]
            return self._merge_ranges(ranges), None
        if kind in ('luks', 'fvde'):
            base, length = self.partition_bytes(start_sector)
            return [(base, base + length)], (
                f"sector {start_sector} holds {self._UNMAPPED_KINDS[kind]}, "
                f"locked: unlock it to carve what is inside")
        if kind in self._UNMAPPED_KINDS:
            base, length = self.partition_bytes(start_sector)
            return [(base, base + length)], (
                f"sector {start_sector} holds {self._UNMAPPED_KINDS[kind]}: "
                f"its free space cannot be told from used space, so it is "
                f"skipped -- carve the whole image to read it")
        layers = self.fs_layers(start_sector)
        if layers:
            # Live in either file system is live: both are skipped.
            base = start_sector * self.sector_size
            return self._merge_ranges(
                [r for layer in layers for r in
                 self.build_allocation_map(layer['key'], base=base)]), None
        if self.has_filesystem(start_sector):
            return self.build_allocation_map(start_sector), None
        return [], None

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
        if self.logical_fs is not None:
            return {k: v for k, v in self.logical_fs.facts.items()
                    if not k.startswith('_')}
        if self.get_image_type() == 'aff4':
            source = getattr(self.img_info, '_source', None)
            try:
                return source.facts() if source is not None else {}
            except Exception as exc:
                logger.warning("AFF4 facts unreadable: %s", exc)
                return {}
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
        """Determine the type of the image based on its extension. A
        file with no extension (or .bin) is read as raw -- dd writes
        whatever name it is given; a format TRACE recognises but cannot
        read raises UnsupportedEvidence saying what it is."""
        from trace_app.core import assembly, live_disk, logical_sources
        if live_disk.is_device_path(self.image_path):
            return "live"
        if assembly.is_assembly(self.image_path):
            return "assembled"
        if logical_sources.kind_of(self.image_path):
            return "logical"
        _, extension = os.path.splitext(self.image_path.rstrip('/\\'))
        extension = extension.lower()

        ewf = [".e01", ".s01", ".ex01"]
        raw = [".raw", ".img", ".dd", ".iso",
               ".000", ".001", ".sparse", ".bin", ""]
        if extension == '.ctr' or _starts_with(self.image_path, b'XWFS'):
            raise UnsupportedEvidence(
                "This is an X-Ways evidence file container (.ctr), a "
                "proprietary X-Ways format TRACE cannot read. Export its "
                "contents from X-Ways Forensics (as files, or as an E01 / "
                "raw image) to examine them here.")

        if extension == '.aff4':
            return "aff4"
        if extension in ewf:
            return "ewf"
        elif extension in raw:
            return "raw"
        elif extension in containers.VIRTUAL_DISK_EXTENSIONS or \
                containers.is_parallels(self.image_path):
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
        stop = threading.Event()

        def read_slice(index):
            start = index * slice_size
            end = total_size if index == workers - 1 else start + slice_size
            handle = None
            try:
                handle = pyewf.handle()
                handle.open(filenames)
                handle.seek(start)
                remaining = end - start
                while remaining > 0 and not stop.is_set():
                    chunk = handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise IOError(f"the image ended at byte "
                                      f"{end - remaining:,}")
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
            # Cancelled (or failed) part-way: the workers stop at their next
            # chunk, and their queues are emptied so none stays blocked on a
            # put that nothing will ever take.
            stop.set()
            for thread in threads:
                while thread.is_alive():
                    for pending in queues:
                        try:
                            while True:
                                pending.get_nowait()
                        except queue.Empty:
                            pass
                    thread.join(timeout=0.05)

        if errors:
            raise errors[0]
        return size

    def calculate_hashes(self, progress_callback=None):
        """Hash the evidence for verification: every byte, or an error.

        Returns {'computed_md5', 'computed_sha1', 'computed_sha256', 'size',
        'path', 'stored_md5', 'stored_sha1'} and, when they apply,
        'damaged' (an E01's sector ranges whose chunks fail their own
        checksums), 'container_problems' (its damaged structure),
        'container_check' (AFF4) and 'live'. A failure gives 'error' and
        no digests at all (core/evidence_hash.py): a hash of the part
        that could be read is not a hash of the evidence, and recorded as
        a baseline it would make the damaged copy the reference.

        What is hashed is what the evidence holds: a raw file's bytes, an
        E01's media (checked chunk by chunk, core/ewf_chunks.py), a
        virtual disk's or an assembled array's disk, logical evidence as
        `_logical_hashes` describes. MD5, SHA-1 and SHA-256 are always
        computed, so any hash recorded elsewhere can be checked.
        """
        from trace_app.core import evidence_hash
        result = {'computed_md5': None, 'computed_sha1': None,
                  'computed_sha256': None, 'size': 0,
                  'path': self.image_path, 'stored_md5': None,
                  'stored_sha1': None}
        image_type = self.get_image_type()
        try:
            if image_type == "logical":
                digests = self._logical_hashes(result, progress_callback)
            elif image_type == "ewf":
                digests = self._ewf_hashes(result, progress_callback)
            elif image_type == "raw" and not \
                    is_split_raw(self.image_path):
                # The file's own bytes are the evidence.
                digests = evidence_hash.hash_file(self.image_path,
                                                  progress_callback)
            else:
                # The disk, not its container files: a split raw image's
                # segments, a split VMDK's extents, a VHDX whose layout
                # changes as it is compacted, a differencing disk with its
                # parents, an AFF4's streams, an assembled array, a live
                # disk -- what the guest saw is what is evidence.
                if self.img_info is None:
                    raise evidence_hash.HashingError(
                        self.load_error or "The image could not be opened")
                digests = evidence_hash.hash_reader(
                    self.img_info.read, self.img_info.get_size(),
                    progress_callback, what='disk')
            result.update({f'computed_{name}': digests[name]
                           for name in evidence_hash.ALGORITHMS})
            result['size'] = digests['size']
        except HashingCancelled:
            raise
        except Exception as exc:
            logger.error("Could not hash %s: %s", self.image_path, exc)
            result.update({'computed_md5': None, 'computed_sha1': None,
                           'computed_sha256': None, 'error': str(exc)})
        if image_type == "aff4":
            # The container's own check of what it stores: it stands
            # whether or not the disk could be hashed.
            result['container_check'] = self._aff4_check()
        if image_type == "live":
            # What was read, when: a disk in use changes as it is read.
            result['live'] = True
        return result

    def _ewf_hashes(self, result, progress_callback=None):
        """An E01 set's media, every chunk checked against its own
        checksum (core/ewf_chunks.py) -- libewf reads a damaged chunk as
        zeros without a word. The hashes it stores are read for the
        verdict. Ex01 (EWF2) goes through libewf, unchecked per chunk."""
        from trace_app.core import evidence_hash, ewf_chunks
        if self.incomplete():
            raise IncompleteEvidence(self.incomplete())
        filenames = pyewf.glob(self.image_path)
        handle = pyewf.handle()
        handle.open(filenames)
        try:
            total = handle.get_media_size()
            for algorithm, key in (('MD5', 'stored_md5'),
                                   ('SHA1', 'stored_sha1')):
                try:
                    result[key] = handle.get_hash_value(algorithm) or None
                except Exception as exc:
                    logger.debug("No stored %s: %s", algorithm, exc)
        finally:
            handle.close()
        try:
            chunk_map = ewf_chunks.ChunkMap(filenames)
        except ewf_chunks.NotEwf1:
            hashers = evidence_hash.new_hashers()
            size = self._hash_ewf_parallel(filenames, total,
                                           list(hashers.values()),
                                           progress_callback)
            if size != total:
                raise evidence_hash.HashingError(
                    f"The image gave {size:,} bytes; its media is "
                    f"{total:,}")
            return evidence_hash.digests(hashers, size)
        if chunk_map.media_size != total:
            raise evidence_hash.HashingError(
                f"The image's tables describe {chunk_map.media_size:,} "
                f"bytes; libewf reads {total:,}")
        damaged = []
        hashers = evidence_hash.new_hashers()
        position = 0
        for offset, data, ok in ewf_chunks.read_media(chunk_map):
            if not ok:
                damaged.append(offset)
            for hasher in hashers.values():
                hasher.update(data)
            position += len(data)
            if progress_callback is not None:
                progress_callback(min(position, total), total)
        # The media counts whole sectors; a source that was not a whole
        # number of them keeps its last bytes in the last chunk, and the
        # hash the image stores covers them: they are hashed too.
        if not total <= position <= total + ewf_chunks.TAIL_SLACK:
            raise evidence_hash.HashingError(
                f"The image gave {position:,} bytes; its media is "
                f"{total:,}")
        digests = evidence_hash.digests(hashers, position)
        if position > total:
            result['beyond_media'] = position - total
        if damaged:
            result['damaged'] = ewf_chunks.damaged_ranges(
                damaged, chunk_map.chunk_size, self.sector_size or 512)
        if chunk_map.problems:
            result['container_problems'] = list(chunk_map.problems)
        return digests

    def _aff4_check(self):
        """(ok, detail) from re-hashing an AFF4 image's streams against
        the hashes recorded at acquisition. Those are hashes of the stored
        stream, not of the disk (a map can lay zeros and unread regions
        around it), so they are checked here and the disk's own hashes are
        computed beside them."""
        source = getattr(self.img_info, '_source', None)
        try:
            results = source.verify()
        except Exception as exc:
            return False, f"The AFF4 streams could not be re-hashed: {exc}"
        if not results:
            return None, "The AFF4 image records no stream hashes."
        bad = [r for r in results if not r['ok']]
        names = ' and '.join(sorted({r['algorithm'].upper()
                                     for r in results if not r.get('error')}))
        if bad:
            return False, '; '.join(
                f"AFF4 stream unreadable: {r['error']}" if r.get('error')
                else f"AFF4 stream {r['algorithm'].upper()} is "
                     f"{r['computed']}; recorded {r['expected']}"
                for r in bad) + '.'
        return True, (f"The AFF4 image's stored data matches the {names} "
                      f"recorded at acquisition.")

    @property
    def is_logical(self):
        """Logical evidence: files, no disk -- nothing to carve."""
        return self.logical_fs is not None

    def _logical_hashes(self, result, progress_callback=None):
        """Verification hashes of logical evidence, into `result`
        (stored hashes) and returned as digests.

        * AD1: the image-wide MD5 and SHA-1 as FTK Imager computes them
          (core/ad1.py), checked against the ones in its log (x.ad1.txt)
          when the log is beside it; no SHA-256 (FTK defines none).
        * L01: the media hash libewf computes, checked against the one
          the file records.
        * iOS backup: every file as stored.
        * ZIP / TAR: the archive file itself.
        * A folder: over every file, in sorted path order, as path + NUL +
          content -- so a file added, removed, renamed or changed changes
          it. A file that cannot be read in full fails the hash.
        """
        from trace_app.core import evidence_hash, logical_sources
        kind = logical_sources.kind_of(self.image_path)
        if kind == 'ad1':
            from trace_app.core import ad1
            computed = ad1.verify(self.image_path,
                                  progress=progress_callback) or {}
            if not computed.get('computed_md5'):
                raise evidence_hash.HashingError(
                    "The AD1 image could not be read in full")
            result.update(ad1.logged_hashes(self.image_path))
            return {'md5': computed.get('computed_md5'),
                    'sha1': computed.get('computed_sha1'),
                    'sha256': computed.get('computed_sha256'),
                    'size': sum(os.path.getsize(p) for p in
                                ad1.segment_paths(self.image_path))}
        if kind == 'ios_backup':
            # As stored -- encrypted or not, unlocked or not.
            from trace_app.core import ios_backup
            hashers = evidence_hash.new_hashers()
            size = ios_backup.hash_folder(self.image_path,
                                          list(hashers.values()),
                                          progress_callback)
            return evidence_hash.digests(hashers, size)
        if kind == 'l01':
            filenames = pyewf.glob(self.image_path)
            handle = pyewf.handle()
            handle.open(filenames)
            try:
                total = handle.get_media_size()
                for algorithm, key in (('MD5', 'stored_md5'),
                                       ('SHA1', 'stored_sha1')):
                    try:
                        result[key] = handle.get_hash_value(algorithm) or None
                    except Exception:
                        pass
            finally:
                handle.close()
            hashers = evidence_hash.new_hashers()
            size = self._hash_ewf_parallel(filenames, total,
                                           list(hashers.values()),
                                           progress_callback)
            if size != total:
                raise evidence_hash.HashingError(
                    f"The L01 gave {size:,} bytes; its media is {total:,}")
            return evidence_hash.digests(hashers, size)
        if kind == 'folder':
            files = sorted(((self.logical_fs.path_of(n.inode), n)
                            for n in self.logical_fs.nodes.values()
                            if not n.is_dir), key=lambda pair: pair[0])
            total = sum(n.size for _p, n in files)
            hashers = evidence_hash.new_hashers()
            done = 0
            for path, node in files:
                for hasher in hashers.values():
                    hasher.update(path.encode('utf-8', 'surrogateescape')
                                  + b'\0')
                position = 0
                while position < node.size:
                    want = min(CHUNK_SIZE, node.size - position)
                    try:
                        chunk = node.reader(position, want)
                    except Exception as exc:
                        raise evidence_hash.HashingError(
                            f"{path} could not be read at byte "
                            f"{position:,}: {exc}") from exc
                    if not chunk:
                        raise evidence_hash.HashingError(
                            f"{path} ended at byte {position:,}; it was "
                            f"{node.size:,} bytes when the folder was read")
                    for hasher in hashers.values():
                        hasher.update(chunk)
                    position += len(chunk)
                    done += len(chunk)
                    if progress_callback:
                        progress_callback(done, total)
            return evidence_hash.digests(hashers, done)
        return evidence_hash.hash_file(self.image_path, progress_callback)

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
                self._check_segments(filenames)
            elif image_type == "raw":
                self.img_info = pytsk3.Img_Info(self.image_path)
            elif image_type == "live":
                # A physical disk, read-only, through the administrator
                # helper (core/live_disk.py).
                from trace_app.core.live_disk import open_live_disk
                self.img_info, self.container_note = open_live_disk(
                    self.image_path)
            elif image_type == "aff4":
                # Read in Python (core/aff4.py): pyaff4 cannot be installed
                # without a compiler.
                from trace_app.core.aff4 import open_aff4
                self.img_info, self.container_note = open_aff4(
                    self.image_path)
            elif image_type == "assembled":
                # Several member disks as one: an md array, a multi-disk
                # Btrfs file system (core/assembly.py).
                from trace_app.core.assembly import open_assembly
                self.img_info, self.container_note, self._btrfs_others, \
                    self._members = open_assembly(self.image_path)
            elif image_type == "virtual":
                try:
                    self.img_info, self.container_note = \
                        containers.open_virtual_disk(self.image_path)
                except containers.ContainerError:
                    # A raw disk named .dmg (hdiutil's UDRW has a trailer;
                    # a dd renamed does not): read it as it is.
                    if not self.image_path.lower().endswith('.dmg'):
                        raise
                    self.img_info = pytsk3.Img_Info(self.image_path)
                    self.container_note = 'DMG read as a raw disk'
            elif image_type == "logical":
                from trace_app.core.logical_sources import open_logical
                self.logical_fs = open_logical(self.image_path)
                self.img_info = _NoMedia()
                self.fs_info = self.logical_fs
                self.container_note = (
                    f"{self.logical_fs.label}: "
                    f"{len(self.logical_fs.nodes) - 1:,} items")
                return True
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
                    # What TSK cannot read, TRACE may: XFS, Btrfs.
                    self.fs_info = self.get_fs_info(0)
                    # If no volume info and no filesystem, mark as wiped
                    self.is_wiped_image = self.fs_info is None
            return True
        except Exception as e:
            logger.error("Could not load image %s: %s", self.image_path, e)
            self.load_error = str(e)
            self.img_info = None
            self.volume_info = None
            self.fs_info = None
            self.is_wiped_image = True
            return False

    def _check_segments(self, filenames):
        """A segment set missing a file, or with one cut short, opens and
        then fails at the first read past the gap. Say so up front (the
        tree's tooltip, evidence intake) and make those reads say why."""
        from trace_app.core import ewf_check
        try:
            missing = ewf_check.problem(filenames)
        except Exception as exc:
            logger.debug("Segment check failed: %s", exc)
            return
        if not missing:
            return
        size = self.img_info.get_size()
        end = ewf_check.data_end(self.img_info.read, size)
        self.img_info.incomplete = (missing, end)
        self.container_note = (
            f"Incomplete E01: {missing}; data up to "
            f"{FileSystemUtils.get_readable_size(end)} of "
            f"{FileSystemUtils.get_readable_size(size)}")
        logger.warning("%s: %s", self.image_path,
                       incomplete_message((missing, end)))

    def incomplete(self):
        """incomplete_message() for an image whose segment set is not
        whole, else None."""
        state = getattr(self.img_info, 'incomplete', None)
        return incomplete_message(state) if state else None

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
        (0, b'XFSB', 'XFS'),
        # Linux RAID (md) members: superblock 1.2 at 4 KiB, 1.1 at 0.
        (4096, b'\xfc\x4e\x2b\xa9', 'Linux RAID member'),
        (0, b'\xfc\x4e\x2b\xa9', 'Linux RAID member'),
        (0x10040, b'_BHRfS_M', 'Btrfs'),
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

    #: The Sleuth Kit's type to force for each signature detect_filesystems
    #: names, so a layered partition's file systems open one at a time.
    _TSK_TYPES = {'NTFS': 'NTFS_DETECT', 'FAT': 'FAT_DETECT',
                  'FAT12': 'FAT_DETECT', 'FAT16': 'FAT_DETECT',
                  'FAT32': 'FAT_DETECT', 'ExFAT': 'EXFAT',
                  'ISO9660': 'ISO9660_DETECT', 'Ext2/3/4': 'EXT_DETECT',
                  'HFS+': 'HFS_DETECT', 'HFSX': 'HFS_DETECT',
                  'UFS1': 'FFS_DETECT', 'UFS2': 'FFS_DETECT'}

    def fs_layers(self, start_sector):
        """The file systems layered in one partition -- formatted again
        without being wiped, so both sets of structures are intact (DFTT
        #10: NTFS under Ext2, NTFS under UFS) -- each opened on its own:
        [{'key', 'name', 'index'}], or [] when there is one or none. The
        Sleuth Kit's own detection refuses such a partition outright, and
        showing it empty hides both."""
        if start_sector in self._layers:
            return self._layers[start_sector]
        layers = []
        if self.logical_fs is None and \
                start_sector < containers.SHADOW_KEY_BASE and \
                start_sector not in self._volumes:
            kinds = list(dict.fromkeys(
                self._TSK_TYPES[name]
                for name in self.detect_filesystems(start_sector)
                if name in self._TSK_TYPES))
            if len(kinds) > 1:
                for index, kind in enumerate(kinds):
                    try:
                        fs = pytsk3.FS_Info(
                            self.img_info, start_sector * self.sector_size,
                            getattr(pytsk3, 'TSK_FS_TYPE_' + kind))
                    except Exception:
                        continue
                    key = containers.layer_key(start_sector, index)
                    self.fs_info_cache[key] = fs
                    layers.append({'key': key, 'index': index})
                if len(layers) < 2:
                    layers = []
                for layer in layers:
                    layer['name'] = self.get_fs_type(layer['key'])
                if layers:
                    logger.info("Sector %d holds %d file systems layered: %s",
                                start_sector, len(layers),
                                ', '.join(l['name'] for l in layers))
        self._layers[start_sector] = layers
        return layers

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
        if start_offset in self._volumes or self.logical_fs is not None:
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

    def partition_label(self, start_sector, description=None):
        """What the examiner sees for the slot at `start_sector`: 'EFI
        System Partition @ 2048', 'Linux Filesystem @ 4198400', 'GPT
        Header' (core/partition_names.py). The GPT's own entries -- type
        and name -- are read once."""
        from trace_app.core import partition_names
        if not hasattr(self, '_gpt_entries'):
            self._gpt_entries = {}
            if self.img_info is not None and self.logical_fs is None:
                try:
                    self._gpt_entries = partition_names.gpt_entries(
                        self.read, self.sector_size)
                except Exception as exc:
                    logger.debug("GPT entries not read: %s", exc)
        if description is None:
            # Several slots can start at one sector (the MBR's own table
            # and a partition at sector 0): the partition names it.
            found = [d for _a, d, s, _l in self.get_partitions()
                     if s == start_sector]
            real = [d for d in found if partition_names.bookkeeping(
                d.decode('utf-8', 'replace') if isinstance(d, bytes)
                else d or '') is None]
            description = (real or found or [None])[0]
            if description is None and any(
                    lost['start'] == start_sector
                    for lost in self.lost_partitions()):
                return f"Lost partition @ {start_sector}"
            description = description or b''
        try:
            scheme = int(self.volume_info.info.vstype) \
                if self.volume_info is not None else None
        except Exception:
            scheme = None
        return partition_names.label(description, start_sector,
                                     self._gpt_entries, scheme)

    def _get_partitions(self):
        """Internal method to actually retrieve partitions."""
        partitions = []
        if self.volume_info:
            for partition in self.volume_info:
                description = partition.desc
                if not description:
                    # A GPT partition's description is its name, which is
                    # optional: an unnamed one was dropped here, and every
                    # file on it with it. Only unnamed table entries go.
                    if not int(partition.flags) & \
                            pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        continue
                    description = b'Unnamed partition'
                partitions.append((partition.addr, description,
                                   partition.start, partition.len))
        return partitions

    #: Root inode to fall back on when a filesystem will not say. 5 is NTFS's,
    #: which is the common case here; FAT uses 2 and ext uses 2 as well, so a
    #: wrong guess shows an empty volume rather than an error.
    DEFAULT_ROOT_INODE = 5

    def inode_label(self, start_offset, inode):
        """An entry's number as the examiner should read it: Btrfs
        identifiers carry their subvolume in the high bits (core/btrfs.py)
        and read '4122 (subvolume 256)'; every other file system's number
        is shown as it is."""
        if inode is None or inode == '':
            return ''
        try:
            from trace_app.core.btrfs import identifier_label, is_btrfs
            if int(inode) >> 48 and start_offset is not None and \
                    is_btrfs(self.get_fs_info(start_offset)):
                return identifier_label(int(inode))
        except (TypeError, ValueError):
            pass
        return str(inode)

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
        if self.logical_fs is not None:
            return self.logical_fs if start_offset == 0 else None
        if start_offset not in self.fs_info_cache:
            layer = containers.split_layer_key(start_offset)
            if layer is not None:
                # Opened by fs_layers, which forces each type in turn.
                self.fs_layers(layer[0])
                return self.fs_info_cache.get(start_offset)
            shadow = containers.split_shadow_key(start_offset)
            if shadow is not None and start_offset not in self._volumes:
                self.shadow_copies(shadow[0])
            logical = containers.split_lvm_key(start_offset)
            if logical is not None and start_offset not in self._volumes:
                self.logical_volumes(logical[0])
            dynamic = containers.split_ldm_key(start_offset)
            if dynamic is not None:
                if start_offset not in self._volumes:
                    self.dynamic_volumes(dynamic[0])
                if start_offset not in self._volumes:
                    return None
            apfs = containers.split_apfs_key(start_offset)
            if apfs is not None:
                return self._apfs_file_system(start_offset, *apfs)
            if logical is not None and start_offset not in self._volumes:
                return None
            if start_offset < containers.SHADOW_KEY_BASE and \
                    shadow is None:
                # A Linux RAID member: what is inside the array, as the
                # kernel presents /dev/mdN (md_array).
                self.md_array(start_offset)
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
            except Exception:
                # What TSK cannot read, TRACE may: XFS (core/xfs.py,
                # libfsxfs) and Btrfs (core/btrfs.py).
                fs_info = self._other_file_system(start_offset)
                if fs_info is None:
                    return None
                self.fs_info_cache[start_offset] = fs_info
        return self.fs_info_cache[start_offset]

    def _other_file_system(self, start_offset):
        """An XFS (libfsxfs) or Btrfs (core/btrfs.py) volume at a partition
        (or an unpartitioned image), or inside a volume TRACE opened there
        -- an md array, an unlocked LUKS volume, an LVM logical volume
        (RHEL's default install is XFS on LVM) -- or None."""
        volume = self._volumes.get(start_offset)
        if volume is not None:
            window = containers.ByteWindow(volume.read, 0, volume.get_size())
        elif start_offset >= containers.SHADOW_KEY_BASE:
            return None
        else:
            try:
                window = self._partition_window(start_offset)
            except KeyError:
                return None
        from trace_app.core.btrfs import open_btrfs
        from trace_app.core.xfs import open_xfs
        # An assembled Btrfs file system: the other devices, by device.
        others = getattr(self, '_btrfs_others', ()) \
            if start_offset == 0 else ()
        return open_xfs(window) or open_btrfs(window, others)

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

    def read_path(self, start_offset, path, limit=512 * 1024 * 1024):
        """The bytes of the file at `path` on the volume at
        `start_offset`, or None -- for a file found by its name beside
        another (a database's -wal)."""
        fs = self.get_fs_info(start_offset)
        if fs is None or not path:
            return None
        try:
            handle = fs.open(path=path)
            size = int(handle.info.meta.size)
            if not size or size > limit:
                return None
            return handle.read_random(0, size)
        except (IOError, OSError, AttributeError):
            return None

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
        """The bytes a partition holds -- an md array's when it is a
        member TRACE can read as one, so LVM or LUKS inside md opens as it
        would on the machine."""
        array = self._md.get(start_sector)
        if array is not None:
            return containers.ByteWindow(array.read, 0, array.size)
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

    @containers.holding_libyal
    def inner_kind(self, start_sector):
        """What an unlocked encrypted volume holds that The Sleuth Kit
        cannot open by itself -- 'lvm' for the usual Linux install, LVM
        inside LUKS -- or None (a file system, or still locked)."""
        if start_sector not in self._bitlocker:
            return None
        key = ('inner', start_sector)
        if key not in self._kinds:
            try:
                self._kinds[key] = containers.volume_kind(
                    self._volume_stream(start_sector))
            except Exception:
                self._kinds[key] = None
        return self._kinds[key]

    # --- partitions no table points at (core/lost_partitions.py) -----------

    def lost_partitions(self):
        """File systems found where no partition table entry points:
        [{'start', 'fs', 'size'}], start in sectors -- a wiped table, a
        broken extended chain, a deleted GPT entry. Searched once, outside
        the partitions the table lists (an extended container is searched:
        its logical partitions are what goes missing)."""
        if hasattr(self, '_lost'):
            return self._lost
        self._lost = []
        if self.logical_fs is not None or self.img_info is None:
            return self._lost
        from trace_app.core import lost_partitions, partition_names
        partitions = self.get_partitions()
        if not partitions and (self.get_fs_info(0) is not None or
                               self.volume_kind(0) is not None or
                               self.fs_layers(0)):
            # A volume image, or a container (LVM, LUKS, a RAID member...)
            # whose own file systems are not lost partitions.
            return self._lost
        known = []
        for _addr, desc, start, length in partitions:
            text = desc.decode('utf-8', 'replace') if isinstance(
                desc, bytes) else str(desc)
            if partition_names.bookkeeping(text) is not None or \
                    'Extended' in text:
                continue
            known.append((start, length))

        def opens(start):
            try:
                fs = pytsk3.FS_Info(self.img_info,
                                    offset=start * self.sector_size)
            except IOError:
                return None
            self.fs_info_cache.setdefault(start, fs)
            return (self.get_fs_type(start),
                    fs.info.block_count * fs.info.block_size)
        try:
            self._lost = lost_partitions.scan(
                self.read, self.get_size() // self.sector_size, known,
                opens)
        except Exception as exc:
            logger.warning("Lost partition scan failed: %s", exc)
        return self._lost

    # --- Windows dynamic disks (core/ldm.py) -------------------------------

    def _ldm_starts(self):
        """Starts of the partitions that are a dynamic disk's data area:
        MBR type 0x42, or GPT's 'LDM data partition'."""
        from trace_app.core import ldm
        if not hasattr(self, '_ldm_slots'):
            self.partition_label(0)                      # the GPT entries
            gpt = getattr(self, '_gpt_entries', {}) or {}
            self._ldm_slots = [
                start for _a, desc, start, _l in self.get_partitions()
                if b'(0x42)' in (desc or b'') or
                gpt.get(start, ('',))[0] == ldm.GPT_LDM_DATA]
        return self._ldm_slots

    def ldm_database(self):
        """This disk's copy of its disk group's LDM database, or None."""
        from trace_app.core import ldm
        if not hasattr(self, '_ldm_db'):
            self._ldm_db = None
            if self.logical_fs is None and self.img_info is not None and \
                    self._ldm_starts():
                try:
                    self._ldm_db = ldm.Database(
                        self.read, self.get_size(),
                        getattr(self, '_gpt_entries', None))
                except (ldm.LdmError, IndexError, ValueError) as exc:
                    logger.info("No LDM database: %s", exc)
        return self._ldm_db

    def dynamic_volumes(self, start_sector):
        """The disk group's volumes, from the dynamic disk at
        `start_sector`: [{'key', 'index', 'name', 'kind', 'size', 'disks',
        'readable', 'why'}] -- 'readable' when every extent it needs is on
        this disk (simple volumes, a mirror's plex); the others need the
        group's other disks (File > Assemble).

        A volume of one extent here is a run of sectors on this disk: its
        key is its real start sector, read in place like a partition --
        so a simple volume at the partition's start keeps the references
        it had before dynamic disks were read (p63:...). Only a volume put
        together from several extents gets a containers.ldm_key."""
        from trace_app.core import hwraid, ldm
        database = self.ldm_database()
        if database is None or start_sector not in self._ldm_starts():
            return []
        here = {database.disk_guid: (self.read,
                                     database.data_start * self.sector_size)}
        out = []
        for index, volume in enumerate(database.volume_list()):
            key = containers.ldm_key(start_sector, index)
            readable, why = False, ''
            run = self._single_extent(volume, database)
            if run is not None:
                out.append({'key': run, 'index': index,
                            'name': volume['name'], 'kind': volume['kind'],
                            'size': volume['size'],
                            'disks': len(volume['disks']), 'readable': True,
                            'group': database.group_name, 'why': ''})
                continue
            if key not in self._volumes:
                try:
                    reader = ldm.volume_reader(volume, here)
                    self._volumes[key] = hwraid._Image(reader)
                except (ldm.LdmError, hwraid.RaidError) as exc:
                    why = str(exc)
            readable = key in self._volumes
            out.append({'key': key, 'index': index, 'name': volume['name'],
                        'kind': volume['kind'], 'size': volume['size'],
                        'disks': len(volume['disks']),
                        'readable': readable,
                        'group': database.group_name, 'why': why})
        return out

    def _ldm_allocation(self, start_sector):
        """Carving's map of a dynamic disk's data partition: each volume
        read in place by its file system's own allocation; the extents of
        volumes put together from several (striped, RAID5, spanned --
        their bytes here mean nothing alone) as used; the rest -- between
        and after volumes, where deleted ones were -- free."""
        database = self.ldm_database()
        ranges = []
        base = database.data_start * self.sector_size
        for volume in self.dynamic_volumes(start_sector):
            if volume['readable'] and volume['key'] < \
                    containers.SHADOW_KEY_BASE:
                ranges += self.build_allocation_map(volume['key'])
        for volume in database.volume_list():
            if self._single_extent(volume, database) is not None:
                continue
            for component in volume['components']:
                ranges += [(base + e['start'], base + e['start'] + e['size'])
                           for e in component['extents']
                           if e['disk_guid'] == database.disk_guid]
        # The database itself, at the disk's end.
        size = self.get_size()
        ranges.append((size - 2048 * self.sector_size, size))
        return self._merge_ranges(ranges)

    def _single_extent(self, volume, database):
        """The start sector of a volume that is one extent on this disk
        (in any of its plexes), else None."""
        for component in volume['components']:
            extents = component['extents']
            if len(extents) == 1 and component['kind'] not in (1, 3) and \
                    extents[0]['disk_guid'] == database.disk_guid:
                return (database.data_start * self.sector_size +
                        extents[0]['start']) // self.sector_size
        return None

    def volume_kind(self, start_sector):
        """'bitlocker', 'fvde', 'luks', 'lvm', 'apfs', 'ldm' or None for a
        partition (or an unpartitioned image at 0)."""
        if self.logical_fs is not None:
            # An encrypted iOS backup is locked until its password is given.
            return self.logical_fs.facts.get('_locked') \
                if start_sector == 0 else None
        if start_sector not in self._kinds:
            if start_sector >= containers.SHADOW_KEY_BASE:
                self._kinds[start_sector] = None
            elif start_sector in self._ldm_starts() and \
                    self.ldm_database() is not None:
                self._kinds[start_sector] = 'ldm'
            else:
                try:
                    self._kinds[start_sector] = containers.volume_kind(
                        self._partition_window(start_sector))
                except Exception:
                    self._kinds[start_sector] = None
                if self._kinds[start_sector] is None and \
                        self.md_member(start_sector) is not None and \
                        self.md_array(start_sector) is None:
                    self._kinds[start_sector] = 'mdraid'
                if self._kinds[start_sector] == 'fvde' and \
                        self._open_core_storage(start_sector):
                    self._kinds[start_sector] = 'corestorage'
        return self._kinds[start_sector]

    def _open_core_storage(self, start_sector):
        """Open a Core Storage volume that is not encrypted, as an
        unlocked one is opened (so every reader, carving and the tree work
        unchanged) -- it used to be shown as a locked FileVault volume,
        asking for a password it does not have. False if encrypted."""
        window = self._partition_window(start_sector)
        try:
            volume, keep = containers.open_core_storage(window)
        except containers.ContainerError as exc:
            logger.info("Sector %d: %s", start_sector, exc)
            return False
        if volume is None:
            return False
        self._bitlocker[start_sector] = volume
        self._unlocked_kind[start_sector] = 'corestorage'
        self._keep[start_sector] = keep + [window]
        self._volumes[start_sector] = containers.LibyalImgInfo(
            volume, volume.get_size(), keep=[])
        self._forget_filesystem(start_sector)
        logger.info("Core Storage volume at sector %d is not encrypted: "
                    "opened", start_sector)
        return True

    # --- Linux software RAID ----------------------------------------------

    def md_member(self, start_sector):
        """The md superblock of a partition (or an unpartitioned image at
        0), or None."""
        if start_sector not in self._md_member:
            member = None
            if start_sector < containers.SHADOW_KEY_BASE and \
                    self.logical_fs is None:
                try:
                    from trace_app.core import mdraid
                    offset, length = self.partition_bytes(start_sector)
                    member = mdraid.superblock(
                        lambda o, n, base=offset: self.read(base + o, n),
                        length)
                except Exception as exc:
                    logger.debug("No md superblock at %s: %s",
                                 start_sector, exc)
            self._md_member[start_sector] = member
        return self._md_member[start_sector]

    def md_array(self, start_sector):
        """The md array a partition is a member of, when this image alone
        holds enough of it -- one member of a mirror is the whole array;
        striped levels need their other disks (an assembled evidence
        item, core/assembly.py). Its bytes become the partition's: every
        reader opens what is inside, as the kernel presents /dev/mdN."""
        if start_sector in self._md:
            return self._md[start_sector]
        self._md[start_sector] = None
        member = self.md_member(start_sector)
        if member is None:
            return None
        from trace_app.core import mdraid
        offset, _length = self.partition_bytes(start_sector)
        try:
            array = mdraid.Array([(member, lambda o, n, base=offset:
                                   self.read(base + o, n))])
        except mdraid.MdError as exc:
            logger.info("RAID member at sector %s: %s (%s)", start_sector,
                        member.describe(), exc)
            return None
        self._md[start_sector] = array
        if start_sector not in self._volumes:
            self._volumes[start_sector] = mdraid.MdImgInfo(array)
        logger.info("RAID member at sector %s read as its array: %s",
                    start_sector, array.describe())
        return array

    def encryption(self, start_sector):
        """The kind of an encrypted volume at a partition, or None."""
        kind = self.volume_kind(start_sector)
        return kind if kind in ('bitlocker', 'fvde', 'luks', 'ios_backup') \
            else None

    def unlocked_kind(self, start_sector):
        return self._unlocked_kind.get(start_sector)

    @containers.holding_libyal
    def unlock_volume(self, start_sector, kind, **secret):
        """Unlock a BitLocker, FileVault 2 or LUKS volume at a partition;
        its decrypted file system then replaces the partition's, at the same
        key. Raises containers.ContainerError with the reason."""
        if start_sector in self._bitlocker:
            return True
        if kind == 'ios_backup' and self.logical_fs is not None:
            return self._unlock_backup(secret.get('password'))
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

    def _unlock_backup(self, password):
        """An encrypted iOS backup's files, listed and decrypted as read."""
        from trace_app.core import ios_backup
        unlock = self.logical_fs.facts.get('_unlock')
        if unlock is None:
            raise containers.ContainerError("This evidence has no password")
        if not password:
            raise containers.ContainerError("Enter the backup's password")
        from trace_app.infra import capabilities
        if not capabilities.available('ios_encrypted'):
            raise containers.ContainerError(
                capabilities.reason('ios_encrypted'))
        try:
            unlock(password)
        except ios_backup.BackupError as exc:
            raise containers.ContainerError(str(exc)) from exc
        self._unlocked_kind[0] = 'ios_backup'
        self._directory_cache.clear()
        self.get_fs_type.cache_clear()
        logger.info("iOS backup unlocked")
        return True

    # --- LVM and APFS: several volumes in one partition -------------------

    @containers.holding_libyal
    def logical_volumes(self, start_sector):
        """An LVM partition's logical volumes: [{'key', 'index', 'name',
        'size', 'group'}]."""
        if start_sector not in self._lvm:
            try:
                # Decrypted, when LVM is inside an unlocked LUKS volume.
                handle, group, volumes = containers.open_lvm(
                    self._volume_stream(start_sector))
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

    @containers.holding_libyal
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

    @containers.holding_libyal
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

    @containers.holding_libyal
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
        # File systems no partition table points at: read like the others.
        starts += [lost['start'] for lost in self.lost_partitions()]
        out = []
        for start in dict.fromkeys(starts):
            kind = self.volume_kind(start)
            if kind == 'lvm' or self.inner_kind(start) == 'lvm':
                out += [v['key'] for v in self.logical_volumes(start)]
            elif kind == 'ldm':
                out += [v['key'] for v in self.dynamic_volumes(start)
                        if v['readable']]
            elif self.fs_layers(start):
                out += [layer['key'] for layer in self.fs_layers(start)]
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
        if self.logical_fs is not None:
            return False
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
            self._unlocked_kind.get(start_sector) in ('apfs', 'ios_backup')

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

    @containers.holding_libyal
    def shadow_copies(self, start_sector):
        """The partition's Volume Shadow Copies, oldest first:
        [{'key', 'index', 'created', 'size', 'identifier'}]."""
        if self.logical_fs is not None:
            return []
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
            from trace_app.core.btrfs import is_btrfs
            from trace_app.core.logical import is_logical
            from trace_app.core.xfs import is_xfs
            if is_apfs(fs):
                return "APFS"
            if is_xfs(fs):
                return "XFS"
            if is_btrfs(fs):
                return "Btrfs"
            if is_logical(fs):
                return fs.label
            fs_type = fs.info.ftype

            # Map the file system type to its name
            fs_type_map = {
                pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
                pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
                pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
                pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
                pytsk3.TSK_FS_TYPE_EXFAT: "ExFAT",
                # UFS (TSK's names: FFS1 = UFS1 of the BSDs, FFS1B = Solaris's
                # UFS1, FFS2 = UFS2) and YAFFS2: TSK reads them, and they
                # showed as "Unknown".
                pytsk3.TSK_FS_TYPE_FFS1: "UFS1",
                pytsk3.TSK_FS_TYPE_FFS1B: "UFS1 (Solaris)",
                pytsk3.TSK_FS_TYPE_FFS2: "UFS2",
                pytsk3.TSK_FS_TYPE_YAFFS2: "YAFFS2",
                pytsk3.TSK_FS_TYPE_EXT2: "Ext2",
                pytsk3.TSK_FS_TYPE_EXT3: "Ext3",
                pytsk3.TSK_FS_TYPE_EXT4: "Ext4",
                pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
                pytsk3.TSK_FS_TYPE_HFS: "HFS",
                pytsk3.TSK_FS_TYPE_APFS: "APFS"
            }

            return fs_type_map.get(fs_type, "Unknown")
        except Exception:
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
            # Changes Windows had logged but not yet written into the hive
            # (core/regf_log.py), from the logs beside it.
            from trace_app.core import regf_log
            if regf_log.is_dirty(hive_data):
                logs = []
                for suffix in ('.LOG1', '.LOG2', '.LOG'):
                    try:
                        log = fs_info.open(hive_path + suffix)
                        logs.append((hive_path.rsplit('/', 1)[-1] + suffix,
                                     log.read_random(0, log.info.meta.size)))
                    except Exception:
                        continue
                hive_data, facts = regf_log.recover(hive_data, logs)
                self.hive_recovery[hive_path] = facts
            return hive_data
        except Exception as e:
            if required:
                logger.error(f"Error reading registry hive: {e}")
            else:
                logger.debug("No %s on this volume: %s", hive_path, e)
            return None


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

    def _recursive_file_search(self, fs_info, directory, parent_path, files_list, extensions, search_query=None, start_offset=0, visited=None):
        """Recursively search for files in a directory. Each directory is
        entered once (`visited`, as core/walk.py does): a deleted entry
        whose inode now belongs to a folder above it would otherwise
        recurse until Python gives up."""
        if visited is None:
            visited = set()
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
                        # An extension ('.jpg') -- or the start of a name
                        # that begins with a dot ('.bash_history', '.ssh'),
                        # which an extension match never finds.
                        query_matches = (
                            file_extension == search_query.lower() or
                            file_name.lower().startswith(search_query.lower()))
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
                    address = entry.info.meta.addr
                    if address in visited:
                        continue
                    visited.add(address)
                    try:
                        sub_directory = fs_info.open_dir(inode=address)
                        self._recursive_file_search(fs_info, sub_directory, os.path.join(parent_path, file_name),
                                                    files_list,
                                                    extensions, search_query, start_offset, visited)
                    except IOError as e:
                        # A deleted folder's blocks are often gone: expected,
                        # as in core/walk.py. A live one failing is not.
                        allocated = int(entry.info.meta.flags) & \
                            pytsk3.TSK_FS_META_FLAG_ALLOC
                        (logger.error if allocated else logger.debug)(
                            "Unable to open directory %s: %s",
                            os.path.join(parent_path, file_name), e)

                # Every entry the listing shows -- links, devices, sockets
                # too -- not regular files alone: a link listed in a folder
                # was never found by its name.
                elif entry.info.meta and query_matches:
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
        """Files (and folders) whose name matches, on every file system of
        the image -- read through get_fs_info, as everything else is, so a
        container (QCOW2, VHD, DMG, AFF4...), an unlocked or LVM/APFS
        volume, logical evidence and the file systems TSK does not read
        (XFS, Btrfs) are searched too. It used to reopen the image path as
        a raw image, which only E01 and raw files survived."""
        logger.info(f"ImageHandler.search_files called with query: '{search_query}'")
        files_list = []
        searched = 0
        for offset in self.volume_offsets():
            if self.process_partition_search(offset, files_list,
                                             search_query):
                searched += 1
        logger.info("Searched %d file system%s; total files found: %d",
                    searched, '' if searched == 1 else 's', len(files_list))
        return files_list

    def process_partition_search(self, offset, files_list, search_query):
        """Search the file system at `offset` (a partition's start in
        sectors, or a volume key). False if there is none there."""
        fs_info = self.get_fs_info(offset)
        if fs_info is None:
            return False
        try:
            initial_count = len(files_list)
            self._recursive_file_search(fs_info, fs_info.open_dir(path="/"), "/", files_list, None, search_query, offset)
            logger.info("Searched the file system at %d: %d found", offset,
                        len(files_list) - initial_count)
        except IOError as e:
            logger.error(f"Unable to search the file system at {offset}: {e}")
        return True

    def get_file_content(self, inode_number, offset):
        #: Why the last read failed, in words, for the window to show.
        self.last_read_error = None
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
            # TSK reports a failed image read in its own words; an
            # incomplete image's reason is the one worth showing.
            self.last_read_error = self.incomplete() or str(e)
            logger.error(f"Error reading file: {e}")
            return None, None

    # Replace static method assignment with an actual instance method
    def get_readable_size(self, size_in_bytes):
        """Convert bytes to a human-readable string, wrapper for the static utility method."""
        return FileSystemUtils.get_readable_size(size_in_bytes)


# DatabaseManager class with optimization

"""Where a file system keeps its own structures (no Qt).

The allocation map (ImageHandler.build_allocation_map) was the runs of the
files a directory walk reaches. A file system's own structures are not
files any walk reaches: FAT's boot sector, tables and fixed root folder;
ext's superblocks, group descriptors, bitmaps, inode tables and journal;
exFAT's boot region and tables before its cluster heap; the root folder
itself (the walk records what is in it). Counted as free, they were carved
as deleted data, indexed as "unallocated" (DFTT #2's 'SECOND' is a name in
the FAT16 root folder, found as unallocated text), and a deleted file whose
blocks became an inode table or a directory read as recoverable (NIST's
DFR-07: "overwritten by metadata").

`ranges(handler, fs, base, record_runs)` -> [(begin, end)] image byte
ranges, from each structure's own description: FAT's BPB, exFAT's boot
sector, ext's superblock and group descriptors. Whatever cannot be read
adds nothing -- the map is then what it was.
"""

import logging
import struct

import pytsk3

logger = logging.getLogger('TRACE.FsMetadata')

#: ext's special inodes holding structures, not files: the boot loader (5),
#: the reserved group descriptor blocks (7) and the journal (8).
_EXT_INODES = (5, 7, 8)


def ranges(handler, fs, base, record_runs=None):
    out = []
    try:
        kind = int(fs.info.ftype)
    except Exception:
        return out

    def read(offset, length):
        return handler.read(base + offset, length)

    if record_runs is not None:
        # The root folder: the walk records its entries, not itself (FAT32,
        # ext, HFS+ keep it in ordinary clusters).
        try:
            record_runs(fs.open_meta(inode=fs.info.root_inum))
        except Exception as exc:
            logger.debug("Root folder runs unread: %s", exc)
    try:
        if kind & pytsk3.TSK_FS_TYPE_FAT_DETECT and \
                kind != pytsk3.TSK_FS_TYPE_EXFAT:
            out += _fat(read, base)
        elif kind == pytsk3.TSK_FS_TYPE_EXFAT:
            out += _exfat(read, base)
        elif kind & pytsk3.TSK_FS_TYPE_EXT_DETECT:
            out += _ext(read, base)
            if record_runs is not None:
                journal = struct.unpack_from('<I', read(1024, 1024),
                                             0xE0)[0]
                for inode in set(_EXT_INODES) | ({journal} if journal
                                                 else set()):
                    try:
                        record_runs(fs.open_meta(inode=inode))
                    except Exception:
                        pass
    except Exception as exc:
        logger.debug("File-system structures at %d unread: %s", base, exc)
    return out


def _fat(read, base):
    """Boot sector, reserved sectors, the FATs and FAT12/16's fixed root
    folder: everything before the data area."""
    boot = read(0, 512)
    per_sector = struct.unpack_from('<H', boot, 11)[0]
    reserved = struct.unpack_from('<H', boot, 14)[0]
    tables = boot[16]
    roots = struct.unpack_from('<H', boot, 17)[0]
    size = struct.unpack_from('<H', boot, 22)[0] or \
        struct.unpack_from('<I', boot, 36)[0]
    if per_sector not in (512, 1024, 2048, 4096) or not tables or not size:
        return []
    root_sectors = -(-roots * 32 // per_sector)
    data_start = reserved + tables * size + root_sectors
    return [(base, base + data_start * per_sector)]


def _exfat(read, base):
    """Everything before the cluster heap: the boot regions and the FAT."""
    boot = read(0, 512)
    if boot[3:11] != b'EXFAT   ':
        return []
    heap = struct.unpack_from('<I', boot, 88)[0]
    return [(base, base + (heap << boot[108]))]


def _ext(read, base):
    """Superblock and group descriptors (with their backups), and each
    group's block bitmap, inode bitmap and inode table -- where the
    descriptors say they are (flex_bg moves them)."""
    sb = read(1024, 1024)
    if struct.unpack_from('<H', sb, 0x38)[0] != 0xEF53:
        return []
    blocks = struct.unpack_from('<I', sb, 4)[0]
    first = struct.unpack_from('<I', sb, 20)[0]
    block = 1024 << struct.unpack_from('<I', sb, 24)[0]
    per_group = struct.unpack_from('<I', sb, 32)[0]
    inodes_per_group = struct.unpack_from('<I', sb, 40)[0]
    inode_size = struct.unpack_from('<H', sb, 0x58)[0] or 128
    ro_compat = struct.unpack_from('<I', sb, 0x64)[0]
    incompat = struct.unpack_from('<I', sb, 0x60)[0]
    reserved_gdt = struct.unpack_from('<H', sb, 0xCE)[0]
    if incompat & 0x80:                               # 64bit
        blocks |= struct.unpack_from('<I', sb, 0x150)[0] << 32
        desc = struct.unpack_from('<H', sb, 0xFE)[0] or 64
    else:
        desc = 32
    if not per_group or not inodes_per_group:
        return []
    groups = -(-(blocks - first) // per_group)
    gdt_blocks = -(-groups * desc // block)
    table_blocks = -(-inodes_per_group * inode_size // block)
    out = []

    def add(first_block, count):
        if count > 0:
            out.append((base + first_block * block,
                        base + (first_block + count) * block))

    def has_backup(group):
        if not ro_compat & 1 or group in (0, 1):      # sparse_super
            return True
        for factor in (3, 5, 7):
            power = factor
            while power < group:
                power *= factor
            if power == group:
                return True
        return False

    out.append((base, base + 2048))                   # boot + superblock
    meta_bg = incompat & 0x10
    descriptors = read((first + 1) * block, gdt_blocks * desc and
                       gdt_blocks * block)
    for group in range(groups):
        start = first + group * per_group
        if has_backup(group):
            add(start, 1 + (0 if meta_bg else gdt_blocks + reserved_gdt))
        entry = descriptors[group * desc:(group + 1) * desc]
        if len(entry) < 12:
            break
        bitmap, inode_bitmap, table = struct.unpack_from('<III', entry, 0)
        if desc >= 64:
            high = struct.unpack_from('<III', entry, 0x20)
            bitmap |= high[0] << 32
            inode_bitmap |= high[1] << 32
            table |= high[2] << 32
        add(bitmap, 1)
        add(inode_bitmap, 1)
        add(table, table_blocks)
    return out

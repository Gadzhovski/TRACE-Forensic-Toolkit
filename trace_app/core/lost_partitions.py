"""File systems no partition table points at (no Qt).

A partition table wiped or rewritten, an extended partition's chain
broken, a GPT entry deleted: the file systems are still there, whole,
where the table used to say. The Sleuth Kit lists only what the table
says, so TRACE showed such a disk as unallocated space.

`scan` looks where partitions start -- every 1 MiB (Vista and later),
every cylinder (16,065 sectors, plus the track of 63 after it: XP and
older, and logical partitions in an extended one) and every track in
the first two cylinders -- for a boot sector or superblock (NTFS, FAT,
exFAT, ext, HFS+, XFS, APFS), outside the extents of the partitions the
table does list. Each hit is kept only when the file system opens there
(`opens`). Hits inside another lost one are kept and say so
(`overlaps`): an older partition partly written over by a newer one
leaves both mountable (the X-Ways "Lost Partitions Vista" image has a
256 MB FAT whose last half holds a 128 MB one). The backups a file
system keeps of its own boot sector (NTFS at its end, FAT32 six sectors
in) do not fall on the candidates. This is TestDisk's quick search, with
the file system's own check as the proof.
"""

import logging

logger = logging.getLogger('TRACE.LostPartitions')

SECTOR = 512
CYLINDER = 16065                         # 255 heads x 63 sectors
#: Candidates checked at most -- a 400 GB stretch at 1 MiB steps.
MAX_CANDIDATES = 400_000


def signature(head):
    """The file system a boot sector / superblock read at a candidate
    start says it is, or None."""
    if len(head) < 1100:
        return None
    if head[3:11] == b'NTFS    ' and head[510:512] == b'\x55\xaa':
        return 'NTFS'
    if head[3:11] == b'EXFAT   ':
        return 'exFAT'
    if head[510:512] == b'\x55\xaa' and (
            head[0x36:0x3B] in (b'FAT12', b'FAT16') or
            head[0x52:0x57] == b'FAT32'):
        return 'FAT'
    if head[1080:1082] == b'\x53\xef':
        # A backup superblock (one per sparse group) records its group
        # number; a file system's own has 0. Opened as a partition, a
        # backup reads every block number from the wrong place -- DFTT
        # #12, its primary superblock zeroed, showed five such "lost
        # partitions" made of the backups.
        if head[1024 + 0x5A:1024 + 0x5C] != b'\x00\x00':
            return None
        return 'Ext'
    if head[1024:1026] in (b'H+', b'HX'):
        return 'HFS+'
    if head[:4] == b'XFSB':
        return 'XFS'
    if head[32:36] == b'NXSB':
        return 'APFS'
    return None


def gaps(total_sectors, covered):
    """The stretches of [0, total) outside `covered` [(begin, end)]."""
    position = 0
    for begin, end in sorted(covered):
        if begin > position:
            yield position, min(begin, total_sectors)
        position = max(position, end)
    if position < total_sectors:
        yield position, total_sectors


def candidates(begin, end):
    """Sector numbers in [begin, end) where a partition is likely to
    start -- generated for this stretch only, never for the whole disk
    (a 12 TB disk is 23 million 1 MiB steps)."""
    end = min(end, begin + MAX_CANDIDATES * 2048)
    found = set(range(-(-begin // 2048) * 2048, end, 2048))
    for cylinder in range(begin // CYLINDER, end // CYLINDER + 1):
        found.add(cylinder * CYLINDER)
        found.add(cylinder * CYLINDER + 63)
    found.update(range(-(-begin // 63) * 63, min(end, 2 * CYLINDER), 63))
    return sorted(s for s in found if begin <= s < end)


def scan(read, total_sectors, known, opens, should_stop=None):
    """[{'start', 'fs', 'size', 'overlaps'}] -- file systems found
    outside `known`
    ([(first sector, sector count)] of the partitions listed with a file
    system). `opens(start)` -> (file system name, size in bytes) or None
    proves a hit."""
    covered = sorted((s, s + n) for s, n in known if n)
    points = []
    for begin, end in gaps(total_sectors, covered):
        points += candidates(begin, end)
        if len(points) > MAX_CANDIDATES:
            logger.info("Lost partition scan: more than %d candidates, "
                        "only the first checked", MAX_CANDIDATES)
            points = points[:MAX_CANDIDATES]
            break
    found = []
    for sector in points:
        if should_stop and should_stop():
            break
        if any(begin <= sector < end for begin, end in covered):
            continue
        try:
            kind = signature(read(sector * SECTOR, 4096))
        except Exception:
            continue
        if kind is None:
            continue
        try:
            opened = opens(sector)
        except Exception as exc:
            logger.debug("Lost partition at %d not opened: %s", sector, exc)
            opened = None
        if not opened:
            continue
        name, size = opened
        overlaps = next((p['start'] for p in found
                         if p['start'] <= sector < p['start'] +
                         -(-p['size'] // SECTOR)), None)
        found.append({'start': sector, 'fs': name or kind, 'size': size,
                      'overlaps': overlaps})
    if found:
        logger.info("Lost partitions found: %s", ', '.join(
            f"{p['fs']} @ {p['start']}" for p in found))
    return found

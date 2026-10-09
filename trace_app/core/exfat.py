"""exFAT facts The Sleuth Kit does not use (no Qt): times in UTC where an
entry records its zone, and a deleted file's own cluster chain.

Deleted files: exFAT deletes by clearing the entries' in-use bits and the
allocation bitmap; the FAT chain stays. TSK reads a deleted file as one
contiguous run from its first cluster, which is right only when the
stream entry says NoFatChain. For a fragmented file it is wrong: NIST's
DFR-05 braid image has two files' clusters interleaved, and TSK read each
as half itself, half the other. `deleted_runs` follows the chain instead,
and accepts it only when it is exactly the file's length in clusters and
ends with the end-of-chain mark.

Times:

FAT keeps local wall-clock time and nothing else. exFAT keeps the same
digits and, beside each of a file's three times, a UTC-offset byte: bit 7
says the offset is valid, bits 0-6 are the offset in 15-minute steps (two's
complement). With the bit set the time is known exactly -- UTC = digits -
offset. The Sleuth Kit ignores the byte and returns the digits, which TRACE
used to show as "(local, no zone)" even when the evidence said the zone:
NIST's DFR exFAT images record -4 h, so every time read four hours off a
label that claimed no zone was known.

TSK numbers an exFAT file by its directory entry's place: inode =
(sector - cluster heap start) * entries per sector + index + 3. The entry
is read there, and its digits must be TSK's before its offset is trusted
-- if they differ, the entry is not this file's and nothing is changed.
"""

import calendar
import logging
import struct

logger = logging.getLogger('TRACE.ExfatTimes')

#: TSK's first ordinary inode number on FAT file systems.
FIRST_INODE = 3
#: Directory entry types: a file (0x85), and the same with its in-use bit
#: cleared (deleted).
FILE_ENTRY = (0x85, 0x05)
#: (TSK's meta attribute, timestamp offset, 10 ms increment offset or None,
#: UTC offset byte) in the File directory entry.
FIELDS = (('crtime', 8, 20, 22), ('mtime', 12, 21, 23), ('atime', 16, None, 24))


class _Geometry:
    __slots__ = ('base', 'sector', 'heap', 'fat', 'cluster', 'clusters')

    def __init__(self, base, boot):
        self.base = base
        self.sector = 1 << boot[108]
        self.fat, _length, self.heap, self.clusters = struct.unpack_from(
            '<IIII', boot, 80)
        self.cluster = self.sector << boot[109]

    def cluster_offset(self, number):
        """Image byte offset of cluster `number` (the heap starts at 2)."""
        return self.base + self.heap * self.sector + \
            (number - 2) * self.cluster


def _geometry(handler, start):
    """The exFAT volume at `start`, or None; cached on the handler."""
    cache = handler.__dict__.setdefault('_exfat_geometry', {})
    if start in cache:
        return cache[start]
    found = None
    try:
        base = handler.partition_bytes(start)[0]
        boot = handler.read(base, 512)
        if boot[3:11] == b'EXFAT   ' and 9 <= boot[108] <= 12 and \
                boot[108] + boot[109] <= 25:
            found = _Geometry(base, boot)
    except Exception as exc:
        logger.debug("exFAT boot sector at %s unreadable: %s", start, exc)
    cache[start] = found
    return found


def _entry(handler, geometry, inode, length=32):
    """The bytes of the directory entry TSK numbers `inode`."""
    per_sector = geometry.sector // 32
    index = inode - FIRST_INODE
    at = geometry.base + (geometry.heap + index // per_sector) * \
        geometry.sector + (index % per_sector) * 32
    return handler.read(at, length)


#: FAT entries at or above this end a chain (0xFFFFFFF7 marks a bad
#: cluster, 0xFFFFFFF8-F the end).
END_OF_CHAIN = 0xFFFFFFF8


#: deleted_runs' answer for a file that had a chain which no longer is its
#: own (its clusters reused, the FAT rewritten): TSK's one-piece reading of
#: it is a guess past the first cluster, as on FAT.
BROKEN = ()


def deleted_runs(handler, start, meta):
    """[(image byte offset, length)] of a deleted exFAT file's data from its
    own FAT chain, in the file's order; BROKEN when it had a chain that is
    no longer exactly its own; None when TSK's reading stands (not exFAT,
    not deleted, or a contiguous file -- NoFatChain)."""
    if meta is None or handler.get_fs_type(start) != 'ExFAT':
        return None
    geometry = _geometry(handler, start)
    inode = int(getattr(meta, 'addr', 0) or 0)
    if geometry is None or inode < FIRST_INODE:
        return None
    try:
        entries = _entry(handler, geometry, inode, 64)
    except Exception:
        return None
    # A deleted file: its entries' in-use bits cleared -- or still set, in a
    # deleted folder (exFAT frees the folder's clusters and leaves the
    # entries in them as they were: NIST's DFR-12).
    if int(meta.flags) & 1 or len(entries) < 64 or \
            entries[0] & 0x7F != 0x05 or entries[32] & 0x7F != 0x40:
        return None
    flags = entries[33]
    first = struct.unpack_from('<I', entries, 32 + 20)[0]
    length = struct.unpack_from('<Q', entries, 32 + 24)[0]
    if flags & 0x02 or not length or length != int(meta.size or 0):
        return None                 # NoFatChain: contiguous, as TSK reads
    count = -(-length // geometry.cluster)
    chain = [first]
    fat_at = geometry.base + geometry.fat * geometry.sector
    while len(chain) <= count:
        cluster = chain[-1]
        if not 2 <= cluster < geometry.clusters + 2:
            return BROKEN
        following = struct.unpack('<I', handler.read(fat_at + cluster * 4,
                                                     4))[0]
        if following >= END_OF_CHAIN:
            break
        if following in chain:
            return BROKEN           # a loop: not a chain
        chain.append(following)
    if len(chain) != count:
        return BROKEN               # not this file's chain any more
    runs = []
    for cluster in chain:
        offset = geometry.cluster_offset(cluster)
        if runs and runs[-1][0] + runs[-1][1] == offset:
            runs[-1] = (runs[-1][0], runs[-1][1] + geometry.cluster)
        else:
            runs.append((offset, geometry.cluster))
    return runs


def read_deleted(handler, start, meta):
    """A deleted exFAT file's bytes from its own chain, or None (see
    deleted_runs)."""
    runs = deleted_runs(handler, start, meta)
    if not runs:
        return None
    data = b''.join(handler.read(offset, length) for offset, length in runs)
    return data[:int(meta.size)]


def _digits(value):
    """Seconds since 1970 of a DOS date/time read as if UTC -- what TSK
    returns with the process pinned to UTC -- or None."""
    date, clock = value >> 16, value & 0xFFFF
    try:
        return calendar.timegm((1980 + (date >> 9), (date >> 5) & 15,
                                date & 31, clock >> 11, (clock >> 5) & 63,
                                (clock & 31) * 2))
    except (ValueError, OverflowError):
        return None


def utc_times(handler, start, meta):
    """{'mtime': seconds, 'atime': ..., 'crtime': ...} in UTC for the exFAT
    file `meta` describes, for each time whose offset the entry records;
    {} when none does, it is not exFAT, or the entry cannot be matched."""
    if meta is None or handler.get_fs_type(start) != 'ExFAT':
        return {}
    geometry = _geometry(handler, start)
    inode = int(getattr(meta, 'addr', 0) or 0)
    if geometry is None or inode < FIRST_INODE:
        return {}
    try:
        entry = _entry(handler, geometry, inode)
    except Exception:
        return {}
    if len(entry) < 32 or entry[0] not in FILE_ENTRY:
        return {}
    found = {}
    for attribute, stamp_at, tenth_at, zone_at in FIELDS:
        value = struct.unpack_from('<I', entry, stamp_at)[0]
        local = _digits(value)
        if local is not None and tenth_at is not None:
            local += entry[tenth_at] // 100       # 10 ms steps, 0-199
        if local is None or local != int(getattr(meta, attribute, 0) or 0):
            # Not the digits TSK read: not this file's entry.
            return {}
        zone = entry[zone_at]
        if not zone & 0x80:
            continue
        minutes = ((zone & 0x7F) ^ 0x40) - 0x40          # 7-bit signed
        found[attribute] = local - minutes * 15 * 60
    return found


def entry_times(handler, start, meta, zoned):
    """({'mtime', 'atime', 'crtime', 'ctime': seconds}, known zone) for
    `meta` on the volume at `start`. `zoned` is what the file system
    promises (False for FAT/exFAT); an exFAT entry that records its offset
    for every time it has is in UTC whatever the file system's default."""
    values = {name: getattr(meta, name, None)
              for name in ('mtime', 'atime', 'crtime', 'ctime')}
    if zoned:
        return values, True
    utc = utc_times(handler, start, meta)
    present = [name for name in ('mtime', 'atime', 'crtime')
               if values.get(name)]
    if utc and present and all(name in utc for name in present):
        values.update(utc)
        return values, True
    return values, False


def orphan_names(handler, geometry, runs):
    """[(name, TSK's number for its first name entry)] of deleted File Name
    entries no entry set covers any more: the File and Stream entries
    before them were written over by a later set (a longer name, more
    entries), so the name is all that is left of the file -- NIST's
    DFR-08 exFAT image, Deneb.txt after Thuban.txt. `runs` are the
    directory's [(image offset, length)]."""
    slots = []
    for offset, length in runs:
        data = handler.read(offset, length)
        slots += [(offset + at, data[at:at + 32])
                  for at in range(0, len(data) - 31, 32)]
    covered, found, current = set(), [], None
    for index, (_at, entry) in enumerate(slots):
        if entry[0] & 0x7F == 0x05:
            for follower in range(index + 1, index + 1 + entry[1]):
                if follower < len(slots) and \
                        slots[follower][1][0] & 0x7F in (0x40, 0x41):
                    covered.add(follower)
    for index, (at, entry) in enumerate(slots):
        if entry[0] == 0x41 and index not in covered:
            text = entry[2:].decode('utf-16-le', 'replace')
            if current is not None and current[2] == index - 1:
                current[0] += text
                current[2] = index
                continue
            number = FIRST_INODE + (at - geometry.base -
                                    geometry.heap * geometry.sector) // 32
            current = [text, number, index]
            found.append(current)
        else:
            current = None
    return [(text.split('\x00')[0], number) for text, number, _i in found
            if text.split('\x00')[0]]

"""What a disk image is made of, start to end, without overlaps (no Qt).

The Sleuth Kit lists a disk's slots as it finds them, and they overlap: an
extended partition *contains* its logical partitions and their tables, and
the "Unallocated" run at the start of a disk contains the partition table
in sector 0. Adding the slots up counts space twice. `regions(handler)`
lays them out as the disk is: every sector belongs to one region -- a
volume over a table over unallocated space, containers left out because
what they contain is shown -- in disk order, with what each volume holds.

It is the one account of the disk the window gives: the tree's partition,
table and free-space nodes, the Image Information map and its volume table
all name a region with `label(region)` -- the name the tree has always used
(ImageHandler.partition_label: 'GPT Header', 'Linux Filesystem @ 4096'),
free space by where it really starts ('Unallocated Space @ 34', not
TSK's slot from sector 0, which overlaps the partition table), and a file
system no table entry points at as 'Lost partition @ n'.
"""

import logging

logger = logging.getLogger('TRACE.DiskLayout')

VOLUME, TABLE, UNALLOCATED = 'volume', 'table', 'unallocated'
#: A file system no partition table entry points at (lost_partitions).
LOST = 'lost'
#: Which claimant owns a sector two slots cover.
_PRIORITY = {VOLUME: 4, TABLE: 3, LOST: 2, UNALLOCATED: 1}
#: Extended partitions -- containers of logical ones.
_CONTAINER_TYPES = ('(0x05)', '(0x0f)', '(0x85)', '(0x0F)')


def _kind(description):
    text = description.lower()
    if text.startswith('unallocated'):
        return UNALLOCATED
    if 'table' in text or 'gpt header' in text or 'safety' in text:
        return TABLE
    if any(marker in description for marker in _CONTAINER_TYPES) or \
            'extended' in text and '(0x' in text:
        return None                       # a container: its contents show
    return VOLUME


def _describe(handler, start):
    """(file system or what the volume is, encryption or None)."""
    encryption = None
    try:
        encryption = handler.encryption(start)
    except Exception:
        pass
    name = None
    try:
        name = handler.get_fs_type(start)
    except Exception:
        pass
    if not name or name in ('N/A', 'Unknown'):
        try:
            traces = handler.detect_filesystems(start)
        except Exception:
            traces = []
        name = f"{traces[-1]} (unreadable)" if traces else None
    return name, encryption


def regions(handler):
    """[{'kind', 'start', 'sectors', 'bytes', 'name', 'slot', 'description',
    'encryption', 'label', 'volume_start'}] covering the image from sector 0
    to its end, in order. 'name' is a volume's file system; 'label' what it
    is called (`label()` adds the file system); 'volume_start' the sector
    its slot starts at (where its file system is opened)."""
    sector = int(getattr(handler, 'sector_size', 512) or 512)
    total = int(handler.get_size() or 0)
    total_sectors = -(-total // sector) if total else 0
    try:
        slots = handler.get_partitions() or []
    except Exception as exc:
        logger.debug("No partitions: %s", exc)
        slots = []

    claims = []
    for slot, description, start, length in slots:
        description = description.decode('utf-8', 'replace') \
            if isinstance(description, bytes) else str(description)
        kind = _kind(description)
        if kind is None or length <= 0:
            continue
        claims.append((int(start), int(start) + int(length), kind, slot,
                       description))
    try:
        lost = handler.lost_partitions() if claims else []
    except Exception as exc:
        logger.debug("No lost partitions: %s", exc)
        lost = []
    for partition in lost:
        if partition.get('overlaps') is not None:
            continue          # inside an older lost one: that one is drawn
        begin = int(partition['start'])
        length = -(-int(partition['size']) // sector)
        claims.append((begin, begin + length, LOST, None, 'Lost partition'))

    if not claims:
        # One file system across the image, or nothing recognisable.
        name, encryption = _describe(handler, 0)
        kind = VOLUME if name or encryption else UNALLOCATED
        found = _region(kind, 0, total_sectors, sector, name, None,
                        'Whole image', encryption)
        found['label'] = 'Volume' if kind == VOLUME else \
            'Unallocated Space @ 0'
        found['volume_start'], found['lost'] = 0, False
        return [found] if total_sectors else []

    # Every boundary; each interval goes to its most specific claimant.
    points = sorted({0, total_sectors} |
                    {c[0] for c in claims} | {c[1] for c in claims})
    points = [p for p in points if 0 <= p <= max(total_sectors, points[-1])]
    pieces = []
    for begin, end in zip(points, points[1:]):
        covering = [c for c in claims if c[0] <= begin and end <= c[1]]
        owner = max(covering, key=lambda c: (_PRIORITY[c[2]], -(c[1] - c[0])),
                    default=None)
        key = (owner[2], owner[3]) if owner else (UNALLOCATED, None)
        if pieces and pieces[-1]['key'] == key and \
                pieces[-1]['end'] == begin:
            pieces[-1]['end'] = end
        else:
            pieces.append({'key': key, 'begin': begin, 'end': end,
                           'owner': owner})

    found = []
    for piece in pieces:
        kind, slot = piece['key']
        owner = piece['owner']
        name, encryption = (None, None)
        description = owner[4] if owner else 'Unallocated'
        if kind in (VOLUME, LOST):
            name, encryption = _describe(handler, owner[0])
        region = _region(VOLUME if kind == LOST else kind, piece['begin'],
                         piece['end'] - piece['begin'], sector, name,
                         slot, description, encryption)
        region['lost'] = kind == LOST
        region['volume_start'] = owner[0] if owner else piece['begin']
        region['label'] = _name(handler, kind, piece['begin'], owner)
        found.append(region)
    return found


def _name(handler, kind, begin, owner):
    """What the tree calls the slot a region belongs to."""
    if kind == UNALLOCATED:
        return f"Unallocated Space @ {begin}"
    if kind == LOST:
        return f"Lost partition @ {owner[0]}"
    try:
        return handler.partition_label(owner[0], owner[4].encode('utf-8'))
    except Exception as exc:
        logger.debug("No name for the slot at %s: %s", owner[0], exc)
        return owner[4]


def _region(kind, start, sectors, sector_size, name, slot, description,
            encryption):
    return {'kind': kind, 'start': start, 'sectors': sectors,
            'bytes': sectors * sector_size, 'name': name, 'slot': slot,
            'description': description, 'encryption': encryption}


#: How an encrypted volume's scheme is named.
ENCRYPTION_NAMES = {'bitlocker': 'BitLocker', 'fvde': 'FileVault',
                    'luks': 'LUKS'}


def contents(region):
    """What a volume region holds: its file system, its encryption, or
    'no file system' -- None for a table or free space."""
    if region['kind'] != VOLUME:
        return None
    if region.get('encryption'):
        return ENCRYPTION_NAMES.get(region['encryption'], 'Encrypted')
    return region.get('name') or 'no file system'


def label(region):
    """How a region is named to an examiner -- as the tree names it, with
    what a volume holds: 'Linux Filesystem @ 4096 (Ext4)', 'GPT Header',
    'Unallocated Space @ 34'."""
    name = region.get('label')
    if name is None:              # a region made by hand (tests, old data)
        name = {TABLE: "Partition table",
                UNALLOCATED: "Unallocated"}.get(region['kind'], "Volume")
    what = contents(region)
    return f"{name} ({what})" if what else name

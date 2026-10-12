"""Deleted files on HFS+ (and HFSX), from the catalog's old records.

The Sleuth Kit lists no deleted files on HFS+: deleting one removes its
record from the catalog B-tree and the node is rewritten. What is left:
* on a journaled volume (the default since Mac OS X 10.3), the journal's
  copies of catalog nodes from before the deletion -- the file's record
  whole: name, folder, ID, dates and the extents of its data;
* the free space at the end of a catalog node, where a shifted record's
  old bytes can survive.
A record counts only when it decodes as a whole file record whose ID is
no longer in the live catalog and whose extents lie in the volume. On a
volume without a journal a deleted record is usually gone: NIST's DFR-01
key lists two of its four deleted HFS+ files as having no metadata left
anywhere -- and their names appear nowhere on those volumes.

The data fork's eight extents are read from the record; a file in more
pieces than that kept the rest in the extents overflow file, and only its
start is known. Each extent's blocks are checked against the allocation
file: free -> recoverable, all in use again -> overwritten.
"""

import logging
import struct

logger = logging.getLogger('TRACE.HFSDeleted')

#: HFS+ times count seconds from 1904-01-01 UTC.
HFS_EPOCH = 2082844800
FILE_RECORD, FOLDER_RECORD = 2, 1
ROOT_FOLDER = 2
JOURNALED = 0x2000


def _fork(data, at):
    """(logical size, total blocks, [(start block, count)]) of a fork."""
    logical = struct.unpack_from('>Q', data, at)[0]
    total = struct.unpack_from('>I', data, at + 12)[0]
    extents = [struct.unpack_from('>II', data, at + 16 + 8 * i)
               for i in range(8)]
    return logical, total, [e for e in extents if e[1]]


class Volume:
    """An HFS+ / HFSX volume read through `read(offset, length)`, offsets
    from the volume's start."""

    def __init__(self, read):
        self.read = read
        header = read(1024, 512)
        if header[:2] not in (b'H+', b'HX'):
            raise ValueError("not an HFS+ volume header")
        self.block = struct.unpack_from('>I', header, 0x28)[0]
        self.total_blocks = struct.unpack_from('>I', header, 0x2C)[0]
        self.attributes = struct.unpack_from('>I', header, 4)[0]
        self.journal_info = struct.unpack_from('>I', header, 12)[0]
        self.allocation = _fork(header, 0x70)
        self.catalog_fork = _fork(header, 0x110)
        self._bitmap = None

    def fork_bytes(self, fork):
        size, _total, extents = fork
        return b''.join(self.read(start * self.block, count * self.block)
                        for start, count in extents)[:size]

    def allocated(self, block):
        if self._bitmap is None:
            self._bitmap = self.fork_bytes(self.allocation)
        byte = block // 8
        return byte < len(self._bitmap) and \
            bool(self._bitmap[byte] >> (7 - block % 8) & 1)

    def journal_bytes(self):
        """The journal buffer of a journaled volume, else b''."""
        if not self.attributes & JOURNALED or not self.journal_info:
            return b''
        info = self.read(self.journal_info * self.block, 512)
        offset = struct.unpack_from('>Q', info, 36)[0]
        size = struct.unpack_from('>Q', info, 44)[0]
        if not size or size > 1 << 31:
            return b''
        return self.read(offset, size)


def _records(node, node_size, free_space=False):
    """(key offset, live) of each record in a node: those its offset table
    lists, or (free_space) every even offset in its unused space."""
    try:
        count = struct.unpack_from('>H', node, 10)[0]
        table = [struct.unpack_from('>H', node, node_size - 2 * (i + 1))[0]
                 for i in range(count + 1)]
    except struct.error:
        return []
    if any(not 14 <= t < node_size for t in table) or \
            table != sorted(table):
        return []
    if not free_space:
        return [(at, True) for at in table[:count]]
    end = node_size - 2 * (count + 1)
    return [(at, False) for at in range(table[count], end - 10, 2)]


def _decode(node, at):
    """(kind, parent, name, record offset) of the catalog key at `at`, or
    None."""
    try:
        key_length = struct.unpack_from('>H', node, at)[0]
        parent = struct.unpack_from('>I', node, at + 2)[0]
        name_length = struct.unpack_from('>H', node, at + 6)[0]
        if not 6 <= key_length <= 516 or key_length != 6 + 2 * name_length:
            return None
        name = node[at + 8:at + 8 + 2 * name_length].decode('utf-16-be')
        record = at + 2 + key_length
        kind = struct.unpack_from('>H', node, record)[0]
        return kind, parent, name, record
    except (struct.error, UnicodeDecodeError):
        return None


def _file(node, record, volume):
    """A file record's fields, or None when it does not hold together."""
    try:
        file_id = struct.unpack_from('>I', node, record + 8)[0]
        dates = struct.unpack_from('>IIII', node, record + 12)
        data = _fork(node, record + 88)
    except struct.error:
        return None
    size, total, extents = data
    if file_id < 16 or any(start + count > volume.total_blocks
                           for start, count in extents):
        return None
    if size > total * volume.block or (size and not extents):
        return None
    created, modified, changed, accessed = dates
    return {'file_id': file_id, 'size': size, 'total_blocks': total,
            'extents': extents, 'created': created, 'modified': modified,
            'changed': changed, 'accessed': accessed}


def deleted(volume):
    """[record dicts] of deleted file records, one per file ID (the most
    recently changed copy), each with 'name', 'parent', 'source'."""
    catalog = volume.fork_bytes(volume.catalog_fork)
    if len(catalog) < 512:
        return []
    node_size = struct.unpack_from('>H', catalog, 32)[0]
    if node_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
        return []
    live, folders, candidates = set(), {}, []
    for number in range(len(catalog) // node_size):
        node = catalog[number * node_size:(number + 1) * node_size]
        if node[8:9] != b'\xff':                     # leaf nodes only
            continue
        for at, _live in _records(node, node_size):
            key = _decode(node, at)
            if key is None:
                continue
            kind, parent, name, record = key
            if kind == FILE_RECORD:
                found = _file(node, record, volume)
                if found:
                    live.add(found['file_id'])
            elif kind == FOLDER_RECORD:
                folder_id = struct.unpack_from('>I', node, record + 8)[0]
                folders[folder_id] = (name, parent)
        for at, _live in _records(node, node_size, free_space=True):
            key = _decode(node, at)
            if key and key[0] == FILE_RECORD:
                found = _file(node, key[3], volume)
                if found:
                    candidates.append((found, key[1], key[2],
                                       'catalog free space'))
    journal = volume.journal_bytes()
    for at in range(0, max(len(journal) - node_size, 0), 512):
        node = journal[at:at + node_size]
        if node[8:10] != b'\xff\x01':                # a leaf, height 1
            continue
        for offset, _live in _records(node, node_size):
            key = _decode(node, offset)
            if key is None:
                continue
            kind, parent, name, record = key
            if kind == FILE_RECORD:
                found = _file(node, record, volume)
                if found:
                    candidates.append((found, parent, name, 'journal'))
            elif kind == FOLDER_RECORD:
                folder_id = struct.unpack_from('>I', node, record + 8)[0]
                folders.setdefault(folder_id, (name, parent))
    newest = {}
    for found, parent, name, source in candidates:
        if found['file_id'] in live:
            continue
        found.update(name=name, parent=parent, source=source)
        kept = newest.get(found['file_id'])
        # The newest copy is the latest *changed*: setting a file's times
        # (touch -t, as NIST did) moves its modified time into the past,
        # but its change time only ever forward.
        if kept is None or (found['changed'], found['modified']) > \
                (kept['changed'], kept['modified']):
            newest[found['file_id']] = found
    out = list(newest.values())
    for found in out:
        found['folder'] = _path(folders, found['parent'])
    return sorted(out, key=lambda f: f['file_id'])


def _path(folders, folder_id, depth=0):
    if folder_id == ROOT_FOLDER:
        return ''
    if folder_id not in folders or depth > 64:
        return '/$OrphanFiles'
    name, parent = folders[folder_id]
    return f"{_path(folders, parent, depth + 1)}/{name}"


def state_of(volume, found):
    """('recoverable' | 'partly overwritten' | 'overwritten' | 'start only'
    | 'no data recorded', bytes in use again)."""
    blocks = [start + i for start, count in found['extents']
              for i in range(count)]
    if not blocks or not found['size']:
        return 'no data recorded', 0
    taken = sum(1 for block in blocks if volume.allocated(block))
    if taken == len(blocks):
        return 'overwritten', taken * volume.block
    if taken:
        return 'partly overwritten', taken * volume.block
    if found['total_blocks'] > len(blocks):
        return 'start only', 0       # the rest in the extents overflow file
    return 'recoverable', 0


def read(volume, found):
    """The file's bytes as its record's extents hold them."""
    data = b''.join(volume.read(start * volume.block, count * volume.block)
                    for start, count in found['extents'])
    return data[:found['size']]


def hfs_volume(image_handler, start):
    """The HFS+ volume at sector `start` of an image, cached on the image
    handler; None when it is not HFS+."""
    cache = image_handler.__dict__.setdefault('_hfs_volumes', {})
    if start not in cache:
        base = start * image_handler.sector_size
        try:
            cache[start] = Volume(
                lambda offset, length: image_handler.read(base + offset,
                                                          length))
        except (ValueError, struct.error, OSError):
            cache[start] = None
    return cache[start]


def read_deleted(image_handler, start, file_id):
    """The bytes of deleted file `file_id` on the HFS+ volume at `start`,
    or None (it is not one of its deleted records)."""
    volume = hfs_volume(image_handler, start)
    if volume is None:
        return None
    records = image_handler.__dict__.setdefault('_hfs_deleted', {})
    if start not in records:
        records[start] = {found['file_id']: found
                          for found in deleted(volume)}
    found = records[start].get(file_id)
    return None if found is None else read(volume, found)


def unix(hfs_time):
    """An HFS+ time (seconds since 1904, UTC) as Unix seconds, 0 for none."""
    return hfs_time - HFS_EPOCH if hfs_time else 0

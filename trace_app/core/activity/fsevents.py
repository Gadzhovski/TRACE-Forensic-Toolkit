"""macOS FSEvents: the file system's own record of changes to paths, kept
in /.fseventsd (and /System/Volumes/Data/.fseventsd) as gzip-compressed
logs named by their last event ID.

Each log is pages ('1SLD' -- before macOS 10.13 --, '2SLD', '3SLD' from
macOS 13): a header (signature, 4 bytes, the page's size), then records --
the path (UTF-8, NUL-terminated), the event ID (u64), the flags (u32), from
version 2 the file's node ID (u64), from version 3 a further u32. A record
says what happened to a path (created, removed, renamed, modified, its
permissions or extended attributes changed...) and whether it is a file,
folder or link -- for files long deleted too, which is what makes these
logs evidence. Records carry no time: their order is the event ID's, and
the log file's own last-written time is when its last record was flushed
(plaso's reading: the same time for every record in a log). Checked
against plaso's values for its test logs.
"""

import gzip
import struct
import zlib

from trace_app.core.activity import record, times

SIGNATURES = {b'1SLD': 1, b'2SLD': 2, b'3SLD': 3}

#: Flag names, as plaso and dtformats write them.
FLAGS = (
    (0x00000001, 'Created'), (0x00000002, 'Removed'),
    (0x00000004, 'InodeMetadataModified'), (0x00000008, 'Renamed'),
    (0x00000010, 'Modified'), (0x00000020, 'Exchange'),
    (0x00000040, 'FinderInfoModified'), (0x00000080, 'DirectoryCreated'),
    (0x00000100, 'PermissionChanged'),
    (0x00000200, 'ExtendedAttributeModified'),
    (0x00000400, 'ExtendedAttributeRemoved'),
    (0x00001000, 'DocumentRevision'), (0x00004000, 'ItemCloned'),
    (0x00080000, 'LastHardLinkRemoved'), (0x00100000, 'IsHardLink'),
    (0x00400000, 'IsSymbolicLink'), (0x00800000, 'IsFile'),
    (0x01000000, 'IsDirectory'), (0x02000000, 'Mount'),
    (0x04000000, 'Unmount'), (0x20000000, 'EndOfTransaction'))
_KINDS = 0x00100000 | 0x00400000 | 0x00800000 | 0x01000000
#: What a record is listed as, by its most telling flag.
_WHAT = ((0x00000002, 'Removed'), (0x00000008, 'Renamed'),
         (0x00000001, 'Created'), (0x00000080, 'Folder created'),
         (0x00000010, 'Modified'), (0x00000100, 'Permissions changed'),
         (0x00000200, 'Extended attributes changed'),
         (0x00000400, 'Extended attribute removed'),
         (0x00000004, 'Metadata changed'), (0x02000000, 'Volume mounted'),
         (0x04000000, 'Volume unmounted'))


def flag_names(flags):
    return [name for bit, name in FLAGS if flags & bit]


def decompress(data):
    """A log's pages: gunzipped, or as they are if not compressed."""
    if data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data)
        except (OSError, EOFError, zlib.error):
            # A log cut short (still being written): what inflates.
            out = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                return out.decompress(data)
            except zlib.error:
                return b''
    return data


def records(data):
    """[{'path', 'event_id', 'flags', 'node_id', 'version'}] of one log."""
    data = decompress(data)
    out = []
    page = 0
    while page + 12 <= len(data):
        version = SIGNATURES.get(data[page:page + 4])
        if version is None:
            break
        size = struct.unpack_from('<I', data, page + 8)[0]
        end = min(page + size, len(data)) if size >= 12 else len(data)
        at = page + 12
        tail = {1: 12, 2: 20, 3: 24}[version]
        while at < end:
            nul = data.find(b'\x00', at, end)
            if nul < 0 or nul + 1 + tail > end:
                break
            path = data[at:nul].decode('utf-8', 'replace')
            event_id, flags = struct.unpack_from('<QI', data, nul + 1)
            node = struct.unpack_from('<Q', data, nul + 13)[0] \
                if version >= 2 else None
            out.append({'path': path, 'event_id': event_id, 'flags': flags,
                        'node_id': node, 'version': version})
            at = nul + 1 + tail
        if size < 12:
            break
        page += size
    return out


def describe(flags):
    what = next((label for bit, label in _WHAT if flags & bit), 'Changed')
    kind = ('folder' if flags & 0x01000000 else
            'link' if flags & 0x00400000 else
            'file' if flags & 0x00800000 else '')
    return f"{what} ({kind})" if kind else what


def activity(volume, step):
    """Records for every FSEvents log on a macOS volume."""
    out = []
    for parts in (('.fseventsd',), ('System', 'Volumes', 'Data',
                                    '.fseventsd')):
        folder = volume.find(*parts)
        for entry in volume.children(folder):
            if entry.name == 'fseventsd-uuid':
                continue
            step(entry.path)
            try:
                items = records(volume.read(entry))
            except Exception:
                continue
            written = times.iso(entry.modified) or 'at an unknown time'
            basis = (f"FSEvents keeps no time per record: the log was last "
                     f"written {written}, after its last record")
            for item in items:
                out.append(record(
                    'files', 'FSEvents', entry.modified,
                    describe(item['flags']), '/' + item['path'].lstrip('/'),
                    {'event id': item['event_id'],
                     'flags': ', '.join(flag_names(item['flags'])),
                     'node id': item['node_id'],
                     'basis': basis},
                    path=entry.path, ref=volume.ref(entry)))
    return out

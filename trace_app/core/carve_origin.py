"""Which deleted file a carved file was.

A carve has no name: it is bytes found in free space. But a file system
often still remembers the file those bytes belonged to -- an NTFS MFT entry
or a FAT directory entry marked deleted, still pointing at its first
cluster (core/deleted.py lists them). Where a carve starts exactly at the
first cluster of a deleted file's data, it is that file's content, and it
gets that file's name, path, size and times.

Only an exact start counts: a carve that merely falls somewhere inside an
old file's clusters may be anything written there since. And the deleted
entry is what the file system says, not proof the bytes are unchanged -- the
carve's own checks (carve_verify) say that; this says what it was called.

No Qt here.
"""

import logging

logger = logging.getLogger('TRACE.CarveOrigin')


def deleted_file_starts(image_handler, should_stop=None):
    """{byte offset in the image: deleted file} for every deleted file whose
    first data cluster the file system still records."""
    from trace_app.core import deleted
    starts = {}
    for record in deleted.deleted_files(image_handler,
                                        should_stop=should_stop):
        if record['is_dir'] or not record['runs'] or \
                record['state'] == deleted.REUSED:
            continue
        starts.setdefault(record['runs'][0][0], {
            'name': record['name'], 'path': record['path'],
            'ref': record['ref'], 'size': record['size'],
            'pieces': len(record['runs']),
            'modified': record.get('modified'),
            'created': record.get('created'),
            'changed': record.get('changed')})
    return starts


def match(starts, offset, size):
    """The deleted file a carve at `offset` of `size` bytes was, or None."""
    found = starts.get(offset)
    if found is None:
        return None
    origin = dict(found)
    origin['basis'] = (
        f"begins at the first cluster of the deleted file {found['path']}"
        + (" (its size matches)" if found['size'] == size else
           f" (the file was {found['size']:,} bytes; {size:,} carved)"))
    return origin

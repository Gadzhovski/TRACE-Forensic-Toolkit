"""Deleted files the file systems still remember, and how much of each is
still there.

A deleted file leaves its name in a directory (an NTFS $I30 entry, a FAT
directory entry with its first character overwritten, an ext directory
record) and often its metadata (an MFT entry or inode marked unused), which
still records where its data was. The Sleuth Kit lists the names; where it
gives a name without its metadata, the entry number the name records is
opened directly. Directories that were deleted are followed too, and NTFS's
$OrphanFiles -- MFT entries no directory points to any more.

For each file, what is left is measured, not assumed:

* recoverable          the entry is unused and none of its clusters is now
                       held by a live file
* partly overwritten   some of its clusters belong to live files now
* overwritten          all of them do
* resident             the data lives inside the MFT entry itself (small
                       NTFS files) -- there while the entry is not reused
* entry reused         the metadata now describes another file: the name
                       is all that is left
* no data recorded     the entry no longer records where its data was (ext3
                       and ext4 clear it on deletion)

No Qt here.
"""

import logging

import pytsk3

from trace_app.core.activity import times

logger = logging.getLogger('TRACE.Deleted')

RECOVERABLE, PARTLY, OVERWRITTEN, RESIDENT, REUSED, NO_DATA = (
    'recoverable', 'partly overwritten', 'overwritten', 'resident',
    'entry reused', 'no data recorded')
STATES = (RECOVERABLE, RESIDENT, PARTLY, OVERWRITTEN, NO_DATA, REUSED)

_DATA_TYPES = (pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
               pytsk3.TSK_FS_ATTR_TYPE_DEFAULT)
_DIRECTORIES = (pytsk3.TSK_FS_META_TYPE_DIR, pytsk3.TSK_FS_META_TYPE_VIRT_DIR)
MAX_DEPTH = 64


class DeletedCancelled(Exception):
    pass


def analyse_evidence(image_handler, case, evidence_id, progress=None,
                     should_stop=None):
    """List one image's deleted files into the case, replacing any;
    returns how many."""
    from trace_app.core.carving import allocation_map
    allocated = allocation_map(image_handler)
    rows = []
    for record in deleted_files(image_handler, allocated, should_stop):
        rows.append(record)
        if progress and len(rows) % 200 == 0:
            progress(len(rows), 0, record['path'])
    case.replace_deleted_files(evidence_id, rows)
    counts = {}
    for record in rows:
        counts[record['state']] = counts.get(record['state'], 0) + 1
    case.record_event(
        'deleted files listed',
        f"evidence id={evidence_id} files={len(rows)} "
        + ' '.join(f"{state.replace(' ', '_')}={count}"
                   for state, count in sorted(counts.items())))
    return len(rows)


def data_runs(handle, block_size, base):
    """([(byte offset in the image, length)], resident) of a file's unnamed
    data stream."""
    for attribute in handle:
        info = attribute.info
        if info.type not in _DATA_TYPES:
            continue
        if info.name and info.name not in (b'$Data', b''):
            continue                          # an alternate data stream
        if not int(info.flags) & pytsk3.TSK_FS_ATTR_NONRES:
            return [], True
        runs = []
        for run in attribute:
            if run.len and run.addr and not int(run.flags) & \
                    pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE:
                runs.append((base + run.addr * block_size,
                             run.len * block_size))
        return runs, False
    return [], False


def _overlap(runs, allocated):
    """Bytes of `runs` inside the merged, sorted `allocated` ranges."""
    import bisect
    total = 0
    starts = [begin for begin, _end in allocated]
    for begin, length in runs:
        end = begin + length
        index = max(0, bisect.bisect_right(starts, begin) - 1)
        while index < len(allocated) and allocated[index][0] < end:
            low = max(begin, allocated[index][0])
            high = min(end, allocated[index][1])
            if high > low:
                total += high - low
            index += 1
    return total


def _times(meta):
    return {'modified': times.iso(times.unix(getattr(meta, 'mtime', 0))),
            'accessed': times.iso(times.unix(getattr(meta, 'atime', 0))),
            'created': times.iso(times.unix(getattr(meta, 'crtime', 0))),
            'changed': times.iso(times.unix(getattr(meta, 'ctime', 0)))}


def deleted_files(image_handler, allocated=None, should_stop=None):
    """Every deleted file and folder on the image's file systems, as dicts
    (see the module docstring for 'state'). `allocated`: the image's merged
    allocated byte ranges (carving.allocation_map); measured against when
    given."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.core.walk import volume_offsets
    for offset in volume_offsets(image_handler):
        try:
            base = image_handler.partition_bytes(offset)[0]
        except Exception:
            continue                          # a logical volume: no offset
        fs = image_handler.get_fs_info(offset)
        if fs is None:
            continue
        from trace_app.core.btrfs import is_btrfs
        if is_btrfs(fs):
            # No deleted names in a Btrfs directory: the files survive in
            # the older leaves copy-on-write leaves (core/btrfs_recover).
            yield from fs.deleted_scan(should_stop).records(offset, base)
            continue
        block_size = fs.info.block_size
        seen_dirs, seen_files = set(), set()

        def visit(directory, path, depth):
            if depth > MAX_DEPTH:
                return
            for entry in directory:
                if should_stop and should_stop():
                    raise DeletedCancelled()
                info = entry.info
                if info.name is None:
                    continue
                name = info.name.name.decode('utf-8', 'replace')
                if name in ('.', '..'):
                    continue
                child = f"{path}/{name}"
                deleted = bool(int(info.name.flags) &
                               pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                meta = info.meta
                address = meta.addr if meta is not None else \
                    info.name.meta_addr
                handle = None
                if meta is None and address:
                    try:
                        handle = fs.open_meta(inode=address)
                        meta = handle.info.meta
                    except (IOError, OSError):
                        meta = None
                is_dir = meta is not None and meta.type in _DIRECTORIES
                if not deleted:
                    if is_dir and address not in seen_dirs:
                        seen_dirs.add(address)
                        try:
                            yield from visit(entry.as_directory(), child,
                                             depth + 1)
                        except (IOError, OSError) as exc:
                            logger.debug("%s unreadable: %s", child, exc)
                    continue
                key = (address, name)
                if key in seen_files:
                    continue
                seen_files.add(key)
                record = {'volume': offset, 'path': child, 'name': name,
                          'inode': address, 'is_dir': is_dir,
                          'sequence': getattr(info.name, 'meta_seq', None),
                          'size': int(meta.size) if meta is not None else 0,
                          'runs': [], 'overwritten': 0}
                record['ref'] = make_artifact_ref(offset, address,
                                                  record['sequence'])
                if meta is None or not address:
                    record['state'] = REUSED
                elif int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC:
                    # The entry belongs to another file now.
                    record['state'] = REUSED
                    record['size'] = 0
                else:
                    record.update(_times(meta))
                    if not is_dir:
                        try:
                            if handle is None:
                                handle = fs.open_meta(inode=address)
                            runs, resident = data_runs(handle, block_size,
                                                       base)
                        except (IOError, OSError):
                            runs, resident = [], False
                        record['runs'] = runs
                        if resident:
                            record['state'] = RESIDENT
                        elif not runs:
                            # Nothing says where the data was (ext3/4 clear
                            # the block list; an empty file had none).
                            record['state'] = NO_DATA
                        else:
                            lost = _overlap(runs, allocated or [])
                            record['overwritten'] = lost
                            total = sum(length for _b, length in runs)
                            record['state'] = (
                                RECOVERABLE if not lost else
                                OVERWRITTEN if lost >= total else PARTLY)
                    else:
                        record['state'] = RECOVERABLE
                yield record
                if is_dir and record['state'] != REUSED and \
                        address not in seen_dirs:
                    seen_dirs.add(address)
                    try:
                        yield from visit(fs.open_dir(inode=address), child,
                                         depth + 1)
                    except (IOError, OSError) as exc:
                        logger.debug("Deleted folder %s unreadable: %s",
                                     child, exc)

        try:
            yield from visit(fs.open_dir(path='/'), '', 0)
        except (IOError, OSError) as exc:
            logger.warning("Volume at %s could not be listed: %s", offset,
                           exc)

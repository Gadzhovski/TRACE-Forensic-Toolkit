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
                       held by a live file -- or by a deleted file that
                       took them later (settle_claims)
* partly overwritten   some of its clusters belong to such files now
* overwritten          all of them do
* resident             the data lives inside the MFT entry itself (small
                       NTFS files) -- there while the entry is not reused
* entry reused         the metadata now describes another file: the name
                       is all that is left
* no data recorded     the entry no longer records where its data was (ext3
                       and ext4 clear it on deletion)
* (ext3/ext4)          a deleted inode is emptied -- no size, no blocks --
                       so the journal's copy of it from before the
                       deletion gives them back (core/ext_journal), and its
                       copies of directory blocks name orphans
* start only           FAT keeps where a deleted file began, not where the
                       rest of it lay (deletion zeroes the cluster chain):
                       TSK reads on from the start as if the file were in one
                       piece, and when another deleted file's data lies in
                       that space the file was in pieces -- only its first
                       cluster is known to be its own
* possibly overwritten a later deleted FAT file's run (a guess past its
                       first cluster) covers this one's clusters: written
                       after this file was deleted, it overwrote them;
                       written around it while it was live, it did not --
                       FAT keeps no deletion time to tell

exFAT keeps a deleted file's chain: it is followed (core/exfat) rather than
TSK's one-piece reading, so a fragmented exFAT file is recovered whole.

No Qt here.
"""

import logging

import pytsk3

from trace_app.core.activity import times

logger = logging.getLogger('TRACE.Deleted')

(RECOVERABLE, PARTLY, OVERWRITTEN, RESIDENT, REUSED, NO_DATA, START_ONLY,
 POSSIBLY) = ('recoverable', 'partly overwritten', 'overwritten', 'resident',
              'entry reused', 'no data recorded', 'start only',
              'possibly overwritten')
STATES = (RECOVERABLE, RESIDENT, POSSIBLY, PARTLY, OVERWRITTEN, START_ONLY,
          NO_DATA, REUSED)
#: ext: a deleted inode is emptied, and the journal may hold it as it was.
_EXT_TYPES = ('Ext3', 'Ext4')

#: File systems whose deleted files keep only their first cluster: TSK's
#: runs past it are a guess.
_GUESSED_RUNS = ('FAT12', 'FAT16', 'FAT32')

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


def _times(image_handler, offset, meta, zoned):
    """The entry's times, and whether they are UTC. FAT keeps local
    wall-clock time with no zone (`times_local`: shown as such, never as
    UTC); exFAT does too unless the entry records its UTC offset."""
    from trace_app.core import exfat
    values, zoned = exfat.entry_times(image_handler, offset, meta,
                                            zoned)
    found = {key: times.iso(times.unix(values.get(field) or 0))
             for key, field in (('modified', 'mtime'), ('accessed', 'atime'),
                                ('created', 'crtime'), ('changed', 'ctime'))}
    found['times_local'] = not zoned
    return found


def deleted_files(image_handler, allocated=None, should_stop=None):
    """Every deleted file and folder on the image's file systems, as dicts
    (see the module docstring for 'state'). `allocated`: the image's merged
    allocated byte ranges (carving.allocation_map); measured against when
    given."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.core.walk import volume_offsets
    for offset in volume_offsets(image_handler):
        try:
            base, volume_length = image_handler.partition_bytes(offset)
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
        from trace_app.core.image_handler import _TIMEZONE_NAIVE
        fs_type = image_handler.get_fs_type(offset)
        zoned = fs_type not in _TIMEZONE_NAIVE
        from trace_app.core import exfat
        cluster = _fat_cluster(image_handler, base) \
            if fs_type in _GUESSED_RUNS else block_size
        geometry = None
        if fs_type == 'ExFAT':
            geometry = exfat._geometry(image_handler, offset)
            cluster = geometry.cluster if geometry else block_size
        seen_dirs, seen_files = set(), set()
        folder_paths = {}                     # folder inode -> its path
        journals = {}

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
                if is_dir:
                    folder_paths.setdefault(address, child)
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
                    record.update(_times(image_handler, offset, meta, zoned))
                    if not is_dir:
                        try:
                            if handle is None:
                                handle = fs.open_meta(inode=address)
                            runs, resident = data_runs(handle, block_size,
                                                       base)
                        except (IOError, OSError):
                            runs, resident = [], False
                        chain = exfat.deleted_runs(image_handler, offset,
                                                   meta)
                        if chain:
                            runs = chain        # the file's own, in order
                        elif (chain is exfat.BROKEN or
                              fs_type in _GUESSED_RUNS) and runs and \
                                int(meta.size or 0) > cluster:
                            # Past its first cluster TSK's run is a guess
                            # (whatever length TSK made it: it stops at
                            # the first cluster a live file holds).
                            record['guessed'] = True
                            short = sum(n for _b, n in runs) < \
                                int(meta.size or 0)
                            if short or any(b + n > base + volume_length
                                            for b, n in runs):
                                # Read on in one piece it runs off the
                                # volume, or TSK stops short of its size
                                # (NIST's DFR-06: 300 MB in pieces): the
                                # guess is wrong.
                                record['unsure'] = True
                        if runs and runs[0][0] >= base + volume_length:
                            # The entry's first cluster is not even in its
                            # volume (FAT32 deletion can clear the start
                            # cluster's high word): where the data was is
                            # not known -- nothing to judge "overwritten" by.
                            runs = []
                        record['runs'] = runs
                        if not runs and not resident and \
                                fs_type in _EXT_TYPES:
                            # ext emptied the inode; its journal may hold
                            # a copy from before (core/ext_journal).
                            logged = _journal(image_handler, offset, fs,
                                              journals)
                            found = logged.deleted_runs(address) \
                                if logged else None
                            if found:
                                runs, record['size'] = found
                                record['source'] = 'journal'
                                # Blocks another file took later, by the
                                # journal's own record of it.
                                record['journal_reused'] = logged.reused(
                                    address, runs, logged.last_place)
                                later = logged.unrecorded_after(address)
                                if later:
                                    record['possibly'] = True
                                    record.setdefault(
                                        'claimed_by',
                                        'inode %d (made and deleted later; '
                                        'its blocks are not recorded)'
                                        % later[0])
                        if resident:
                            record['state'] = RESIDENT
                        elif not runs:
                            # Nothing says where the data was (ext3/4 clear
                            # the block list; an empty file had none).
                            record['state'] = NO_DATA
                        else:
                            lost = _overlap(runs, allocated or [])
                            lost = max(lost, record.pop('journal_reused', 0))
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

        found = []
        try:
            found.extend(visit(fs.open_dir(path='/'), '', 0))
        except (IOError, OSError) as exc:
            logger.warning("Volume at %s could not be listed: %s", offset,
                           exc)
        if fs_type in _EXT_TYPES:
            _journal_names(found, journals.get(offset), folder_paths)
        if fs_type == 'ExFAT' and geometry:
            found.extend(_exfat_orphans(image_handler, offset, fs, base,
                                        geometry, found, folder_paths))
        if fs_type == 'NTFS':
            events = _logfile_events(fs, offset)
            found.extend(_logfile_deletions(fs, offset, found, folder_paths,
                                            events, should_stop))
            # When each MFT entry was last freed, in log order: of two
            # deleted files over the same clusters, the one freed later
            # wrote them (space is reused only once it is free).
            freed = {}
            for event in events:
                if event['kind'] == 'record freed':
                    freed[event['file'][0]] = event['lsn']
            for record in found:
                if record['inode'] in freed and \
                        record.get('source') != '$LogFile':
                    record['freed_lsn'] = freed[record['inode']]
        settle_claims(found, allocated or [])
        yield from found


def _journal(image_handler, offset, fs, journals):
    """The volume's ext journal (core/ext_journal), read once, or None."""
    if offset not in journals:
        from trace_app.core import ext_journal
        try:
            journals[offset] = ext_journal.Journal(image_handler, offset, fs)
        except Exception as exc:
            logger.debug("Journal of volume %s unread: %s", offset, exc)
            journals[offset] = None
    return journals[offset]


def _journal_names(records, journal, folder_paths):
    """Name the orphan inodes TSK lists as OrphanFile-N from the journal's
    copies of directory blocks: deleting a folder on ext3/4 loses the
    names with the folder's blocks, but a logged copy keeps them."""
    if journal is None:
        return
    names = None
    for record in records:
        if not record['name'].startswith('OrphanFile-'):
            continue
        if names is None:
            names = journal.names()
        known = names.get(record['inode'])
        if not known:
            continue
        name, folder = known
        record['name'] = name
        where = folder_paths.get(folder) if folder else None
        record['path'] = f"{where}/{name}" if where else \
            f"/$OrphanFiles/{name}"
        record['named_by'] = 'journal'


def _logfile_events(fs, offset):
    """$LogFile's file events for an NTFS volume, or [] (core/ntfs_logfile)."""
    from trace_app.core import ntfs_logfile
    try:
        handle = fs.open_meta(inode=2)
        size = int(handle.info.meta.size)
        log = ntfs_logfile.LogFile(handle.read_random(0, size))
        return ntfs_logfile.events(log, int(fs.info.block_size))
    except Exception as exc:
        logger.debug("$LogFile of volume %s unreadable: %s", offset, exc)
        return []


def _logfile_deletions(fs, offset, found, folder_paths, events,
                       should_stop=None):
    """Deleted files only $LogFile still names: their MFT entry holds another
    file now (or is free), so no directory or entry lists them -- NIST's
    DFR-08/10/13 NTFS images, 50 files TSK's listing never shows. A name
    the log removed counts when its entry's sequence number has moved on
    or the entry is free; a rename or a move leaves the file where it was
    (same entry and sequence, in use) and is not a deletion. State 'entry
    reused': the name, its folder, size and $FILE_NAME times are what is
    left."""
    from trace_app.core.case import make_artifact_ref
    listed = {(r['inode'], r['name'].lower()) for r in found}
    # An entry already listed under the same sequence is the same file
    # under a later name: a move into the Recycle Bin removes the old name
    # (NIST's dfr-01-recycle-ntfs: Bunda.txt became $R019S2V.txt).
    entries = {(r['inode'], r['sequence']) for r in found
               if r['state'] != REUSED}
    listed_names = {r['name'].lower() for r in found}
    out, seen = [], set()
    for event in events:
        if should_stop and should_stop():
            raise DeletedCancelled()
        if event['kind'] != 'name removed' or not event.get('name'):
            continue
        number, sequence = event['file']
        name = event['name']
        key = (number, name.lower())
        if key in seen or key in listed or (number, sequence) in entries:
            continue
        seen.add(key)
        if '~' in name and any(
                e['kind'] == 'name removed' and e['file'] == event['file']
                and '~' not in (e.get('name') or '') for e in events):
            continue                          # the 8.3 alias of a long name
        try:
            meta = fs.open_meta(inode=number).info.meta
            live = bool(int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC)
            current = int(getattr(meta, 'seq', -1))
        except (IOError, OSError):
            live, current = False, -1
        if live and current == sequence:
            continue                          # renamed or moved, not deleted
        if not live and current == sequence and name.lower() in listed_names:
            continue                          # TSK lists it already
        parent = (event.get('parent') or (None, None))[0]
        folder = '' if parent == 5 else folder_paths.get(parent)
        path = f"{folder}/{name}" if folder is not None else \
            f"/[folder {parent}]/{name}"
        times = event.get('times') or {}
        record = {'volume': offset, 'path': path, 'name': name,
                  'inode': number, 'is_dir': False, 'sequence': sequence,
                  'size': int(event.get('size') or 0), 'runs': [],
                  'overwritten': 0, 'state': REUSED, 'source': '$LogFile',
                  'times_local': False,
                  'ref': make_artifact_ref(offset, number, sequence)}
        for field, label in (('modified', 'modified'), ('accessed',
                                                        'accessed'),
                             ('created', 'created'),
                             ('changed', 'record changed')):
            record[field] = (times.get(label) or '')[:19] or None
        out.append(record)
    return out


def _exfat_orphans(image_handler, offset, fs, base, geometry, found,
                   folder_paths):
    """Deleted exFAT files whose File and Stream entries a later entry set
    took: only the name is left (exfat.orphan_names). State 'entry reused',
    no size, times or data."""
    from trace_app.core import exfat
    from trace_app.core.case import make_artifact_ref
    folders = dict(folder_paths)
    folders[fs.info.root_inum] = ''
    listed = {r['path'].lower() for r in found}
    out = []
    for folder, path in folders.items():
        try:
            handle = fs.open_meta(inode=folder)
            runs, _resident = data_runs(handle, fs.info.block_size, base)
        except (IOError, OSError):
            continue
        for name, number in exfat.orphan_names(image_handler, geometry,
                                               runs):
            child = f"{path}/{name}"
            if child.lower() in listed:
                continue
            listed.add(child.lower())
            out.append({'volume': offset, 'path': child, 'name': name,
                        'inode': number, 'is_dir': False, 'sequence': None,
                        'size': 0, 'runs': [], 'overwritten': 0,
                        'state': REUSED, 'source': 'name entry',
                        'times_local': False,
                        'ref': make_artifact_ref(offset, number, None)})
    return out


def _fat_cluster(image_handler, base):
    """Bytes per cluster of the FAT volume at byte `base`: The Sleuth Kit's
    FAT "block" is a sector, and a deleted file's run is known up to its
    first cluster, not its first sector."""
    try:
        boot = image_handler.read(base, 512)
        size = int.from_bytes(boot[11:13], 'little') * boot[13]
        return size or 512
    except Exception:
        return 512


def _later(a, b):
    """Of two deleted files whose data runs overlap, the one whose bytes
    are there now, or None when the entries do not say. Space is reused
    only once it is free, so the file that took it was deleted after the
    other: where $LogFile records both entries being freed, the later
    wins (NIST's DFR-13: a file appended to after another's deletion owns
    the clusters, though created first). Else the later creation time
    (NTFS, FAT, exFAT, ext4 keep one); without one, the later change time
    -- ext2/3 set it on deletion."""
    first, second = a.get('freed_lsn'), b.get('freed_lsn')
    if first is not None and second is not None and first != second:
        return a if first > second else b
    for field in ('created', 'changed'):
        first, second = a.get(field), b.get(field)
        if first and second and first != second:
            return a if first > second else b
    return None


def settle_claims(records, allocated):
    """Count as overwritten the bytes of a deleted file that another
    deleted file took later. Free space is not the file's own just because
    no live file holds it: NIST's DFR-07 deletes files, writes others into
    their clusters and deletes those too -- the first ones read as
    "recoverable" while every byte was the second ones'. Where the entries
    cannot say which came later, both lose the shared bytes: a contested
    cluster is never reported as recovered."""
    spans = sorted((begin, begin + length, index)
                   for index, record in enumerate(records)
                   for begin, length in record.get('runs') or ())
    lost = {}
    active = []
    for begin, end, index in spans:
        active = [item for item in active if item[1] > begin]
        for other_begin, other_end, other in active:
            if other == index:
                continue
            if records[other]['runs'] == records[index]['runs'] and \
                    records[other].get('created') == \
                    records[index].get('created'):
                # Two names for the same bytes -- a file moved (into the
                # Recycle Bin, say: it keeps its creation time) or
                # hard-linked -- not one file over another.
                continue
            low, high = max(begin, other_begin), min(end, other_end)
            if high <= low:
                continue
            guessed = [i for i in (index, other)
                       if records[i].get('guessed')]
            winner = _later(records[index], records[other])
            if len(guessed) == 2:
                # Two guesses over the same space (DFR-05's braided
                # files): neither says where its own clusters were.
                for i in guessed:
                    records[i]['unsure'] = True
                continue
            if guessed:
                # A run past a FAT file's first cluster is TSK's guess.
                # If the other file -- its clusters known -- came later,
                # the guess ran into it: the guessed file was in pieces
                # around it (DFR-05's nested file). If the guessed file
                # came later, either it took that space once the other
                # was deleted (DFR-07) or it was written around the other
                # while that was still live (DFR-08's Alphard): FAT keeps
                # no deletion time to say which.
                fat, known = guessed[0], (other if guessed[0] == index
                                          else index)
                if winner is not records[fat]:
                    records[fat]['unsure'] = True
                if winner is not records[known]:
                    records[known]['possibly'] = True
                    records[known].setdefault('claimed_by',
                                              records[fat]['path'])
                continue
            if winner is None:
                # Neither entry says which came later (created in the same
                # second, no deletion time): either may hold the space.
                for i in (index, other):
                    records[i]['possibly'] = True
                    records[i].setdefault(
                        'claimed_by',
                        records[other if i == index else index]['path'])
                continue
            for loser in (index, other):
                if winner is not records[loser]:
                    lost.setdefault(loser, []).append((low, high))
                    claimant = records[other if loser == index else index]
                    records[loser].setdefault('claimed_by', claimant['path'])
        active.append((begin, end, index))
    for record in records:
        if record.pop('unsure', False) and record['state'] in (RECOVERABLE,
                                                               PARTLY):
            record['state'] = START_ONLY
        if record.pop('possibly', False) and record['state'] in (RECOVERABLE,
                                                                 PARTLY):
            record['state'] = POSSIBLY
    for index, ranges in lost.items():
        record = records[index]
        if record['state'] not in (RECOVERABLE, PARTLY):
            continue
        taken = _merged(ranges + _intersections(record['runs'], allocated))
        total = sum(length for _b, length in record['runs'])
        record['overwritten'] = sum(end - begin for begin, end in taken)
        record['state'] = (OVERWRITTEN if record['overwritten'] >= total
                           else PARTLY)


def _merged(ranges):
    merged = []
    for begin, end in sorted(ranges):
        if merged and begin <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((begin, end))
    return merged


def _intersections(runs, allocated):
    """The parts of `runs` inside the merged, sorted `allocated` ranges."""
    import bisect
    found = []
    starts = [begin for begin, _end in allocated]
    for begin, length in runs:
        end = begin + length
        index = max(0, bisect.bisect_right(starts, begin) - 1)
        while index < len(allocated) and allocated[index][0] < end:
            low = max(begin, allocated[index][0])
            high = min(end, allocated[index][1])
            if high > low:
                found.append((low, high))
            index += 1
    return found

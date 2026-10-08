"""File-system times for the timeline, on every file system (no Qt).

The timeline's file-system source was filled by the NTFS module alone,
from $MFT: an ext4, Btrfs, XFS, HFS+, APFS, FAT or exFAT volume put not a
single file time in it, though the Listing shows them all. This walks
each volume that is not NTFS -- NTFS keeps its own module, with
$STANDARD_INFORMATION and $FILE_NAME apart -- and writes every entry's
modified / accessed / changed / born times as `fs_events` rows, one per
distinct time with its MACB letters, as the NTFS module does.

* Folders and empty files count: when a folder changed is evidence too.
* Deleted entries count while their metadata is still theirs (TSK lists
  the name, and the inode is unallocated); a name whose inode a live file
  has taken describes that file, not the deleted one, and is left out.
* FAT and exFAT store local wall-clock time with no zone: their rows are
  source 'FS-local' and the timeline shows them as local, never as UTC.
  Everything else is 'FS', UTC.
* What a file system does not record is not invented: ext2/3 have no
  birth time, FAT keeps a date for access.
"""

import datetime
import logging

import pytsk3

from trace_app.core.case import make_artifact_ref

logger = logging.getLogger('TRACE.FsTimes')

SOURCE = 'FS'
SOURCE_LOCAL = 'FS-local'
SOURCES = (SOURCE, SOURCE_LOCAL)
BATCH = 5000
MAX_DEPTH = 256


class FsTimesCancelled(Exception):
    pass


def time_text(seconds, nanoseconds=0):
    """'YYYY-MM-DD HH:MM:SS[.fffffff]' (UTC, or the stored digits for a
    zone-less file system: the process runs in UTC), or None for no time."""
    if not seconds and not nanoseconds:
        return None
    try:
        moment = datetime.datetime.fromtimestamp(int(seconds),
                                                 datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    text = moment.strftime('%Y-%m-%d %H:%M:%S')
    if nanoseconds:
        text += f".{int(nanoseconds) // 100:07d}"
    return text


def macb_rows(meta):
    """[(time text, 'MACB' letters)], one per distinct time."""
    letters = {}
    for attribute, position, letter in (('mtime', 0, 'M'), ('atime', 1, 'A'),
                                        ('ctime', 2, 'C'),
                                        ('crtime', 3, 'B')):
        text = time_text(getattr(meta, attribute, 0) or 0,
                         getattr(meta, attribute + '_nano', 0) or 0)
        if text is None:
            continue
        slot = letters.setdefault(text, ['.', '.', '.', '.'])
        slot[position] = letter
    return sorted((text, ''.join(slot)) for text, slot in letters.items())


def is_ntfs(fs):
    try:
        return bool(int(fs.info.ftype) & pytsk3.TSK_FS_TYPE_NTFS_DETECT)
    except Exception:
        return False


def volumes(image_handler):
    """(key, fs, zone-less) for every volume this module reads."""
    from trace_app.core.image_handler import _TIMEZONE_NAIVE
    out = []
    for key in image_handler.volume_offsets():
        fs = image_handler.get_fs_info(key)
        if fs is None or is_ntfs(fs):
            continue
        out.append((key, fs, image_handler.get_fs_type(key)
                    in _TIMEZONE_NAIVE))
    return out


def _walk(fs, directory, path, depth, visited, should_stop):
    """(path, meta, deleted, name) for every entry under `directory`."""
    if depth > MAX_DEPTH:
        return
    for entry in directory:
        if should_stop and should_stop():
            raise FsTimesCancelled()
        info = entry.info
        if info.name is None or info.meta is None:
            continue
        name = info.name.name.decode('utf-8', 'replace')
        if name in ('.', '..'):
            continue
        meta = info.meta
        child = f"{path}/{name}"
        name_deleted = not (int(info.name.flags)
                            & pytsk3.TSK_FS_NAME_FLAG_ALLOC)
        meta_live = bool(int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC)
        if name_deleted and meta_live:
            continue            # the inode is another, live file's now
        yield child, meta, name_deleted, info.name
        if meta.type == pytsk3.TSK_FS_META_TYPE_DIR and \
                (meta.addr, name_deleted) not in visited:
            visited.add((meta.addr, name_deleted))
            try:
                yield from _walk(fs, entry.as_directory(), child, depth + 1,
                                 visited, should_stop)
            except FsTimesCancelled:
                raise
            except Exception as exc:
                logger.debug("Could not list %s: %s", child, exc)


def analyse_evidence(image_handler, case, evidence_id, progress=None,
                     should_stop=None):
    """Every non-NTFS volume's file times into the case, replacing an
    earlier run's. Returns the number of entries read."""
    found = volumes(image_handler)
    case.clear_fs_times(evidence_id)
    entries = events = 0
    try:
        for index, (key, fs, local) in enumerate(found):
            source = SOURCE_LOCAL if local else SOURCE
            batch = []
            for path, meta, deleted, name in _walk(
                    fs, fs.open_dir(path='/'), '', 0, set(), should_stop):
                entries += 1
                ref = make_artifact_ref(key, meta.addr,
                                        getattr(name, 'meta_seq', None))
                for text, letters in macb_rows(meta):
                    batch.append((ref, path, text, letters, source,
                                  int(deleted)))
                if len(batch) >= BATCH:
                    case.add_fs_events(evidence_id, batch)
                    events += len(batch)
                    batch = []
                    if progress:
                        progress(index, len(found), path)
            case.add_fs_events(evidence_id, batch)
            events += len(batch)
            case.commit()
    except FsTimesCancelled:
        case.clear_fs_times(evidence_id)
        return 0
    logger.info("File system times: %d entries, %d events from %d "
                "volume(s) of evidence %s", entries, events, len(found),
                evidence_id)
    return entries

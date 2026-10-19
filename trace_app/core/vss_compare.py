"""What changed between two states of a volume: a Volume Shadow Copy and a
later one, or the live volume (no Qt).

A shadow copy is the volume as it was when the snapshot was taken
(ImageHandler.shadow_copies; each opens as a file system of its own).
Comparing it with what came after shows what was deleted, added, changed
or renamed in between -- often how deleted or wiped evidence turns up:
a file wiped from the live volume is still whole in the snapshot.

Entries are compared by path, case-insensitively as NTFS names are:
* deleted  -- in the earlier state, gone from the later one;
* added    -- in the later state only;
* changed  -- the same path, but its size or modified time differs, or it
              is another file now (another MFT entry);
* renamed  -- the same file (MFT entry and sequence number) under another
              path: reported once, not as a deletion and an addition.
Contents are not hashed: what differs is decided by the file system's
own records. NTFS metadata files ($MFT, $LogFile...) change with every
write and are left out unless asked for.
"""

import logging

import pytsk3

from trace_app.core.tsk_names import entry_name

logger = logging.getLogger('TRACE.VSSCompare')

DELETED, ADDED, CHANGED, RENAMED = 'deleted', 'added', 'changed', 'renamed'
CHANGES = (DELETED, ADDED, CHANGED, RENAMED)
#: Deeper than this a folder is not followed (a link loop).
MAX_DEPTH = 64


class Cancelled(Exception):
    pass


def entries(fs, system=False, should_stop=None):
    """{lower-case path: entry} of every file and folder in a file system:
    entry = {'path', 'inode', 'sequence', 'size', 'modified', 'changed',
    'is_dir'} (times as Unix seconds). NTFS metadata files ('$'-named at
    the root, and $Extend) only with `system`."""
    found = {}
    seen = set()

    def walk(directory, path, depth):
        if depth > MAX_DEPTH:
            return
        for entry in directory:
            if should_stop and should_stop():
                raise Cancelled()
            info = entry.info
            if info.name is None:
                continue
            name = entry_name(entry, fs)
            if name in ('.', '..') or (depth == 0 and name == '$OrphanFiles'):
                continue
            if not system and depth == 0 and name.startswith('$'):
                continue
            if int(info.name.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                continue                       # a deleted name: not "there"
            meta = info.meta
            if meta is None:
                continue
            child = f"{path}/{name}"
            is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            found[child.lower()] = {
                'path': child, 'inode': int(meta.addr),
                'sequence': getattr(info.name, 'meta_seq', None),
                'size': 0 if is_dir else int(meta.size or 0),
                'modified': int(getattr(meta, 'mtime', 0) or 0),
                'changed': int(getattr(meta, 'ctime', 0) or 0),
                'is_dir': is_dir}
            if is_dir and (int(meta.addr), child) not in seen:
                seen.add((int(meta.addr), child))
                try:
                    walk(entry.as_directory(), child, depth + 1)
                except (IOError, OSError) as exc:
                    logger.debug("%s not listed: %s", child, exc)

    walk(fs.open_dir(path='/'), '', 0)
    return found


def compare(before, after):
    """[{'change', 'path', 'before', 'after'}] -- `before` and `after` are
    entries() of the earlier and later state; 'before'/'after' hold the
    entry on each side, None where it is absent. Sorted by path."""
    rows = []
    gone = {key: e for key, e in before.items() if key not in after}
    new = {key: e for key, e in after.items() if key not in before}
    # The same NTFS file under another path: one rename, not two rows.
    by_file = {(e['inode'], e['sequence']): key for key, e in new.items()
               if e['sequence'] is not None}
    for key, old in list(gone.items()):
        match = by_file.get((old['inode'], old['sequence'])) \
            if old['sequence'] is not None else None
        if match is not None and match in new:
            rows.append({'change': RENAMED, 'path': new[match]['path'],
                         'before': old, 'after': new.pop(match)})
            del gone[key]
    for old in gone.values():
        rows.append({'change': DELETED, 'path': old['path'], 'before': old,
                     'after': None})
    for later in new.values():
        rows.append({'change': ADDED, 'path': later['path'], 'before': None,
                     'after': later})
    for key, old in before.items():
        later = after.get(key)
        if later is None or old['is_dir'] or later['is_dir']:
            continue
        if old['size'] != later['size'] or \
                old['modified'] != later['modified'] or \
                old['inode'] != later['inode']:
            rows.append({'change': CHANGED, 'path': later['path'],
                         'before': old, 'after': later})
    rows.sort(key=lambda r: (r['path'].lower(), CHANGES.index(r['change'])))
    return rows


def compare_volumes(handler, before_key, after_key, system=False,
                    should_stop=None):
    """compare() of two file systems of one image -- a shadow copy's key
    (containers.shadow_key) and a later one's, or the volume's own start
    sector for the live volume."""
    states = []
    for key in (before_key, after_key):
        fs = handler.get_fs_info(key)
        if fs is None:
            raise ValueError(f"No file system to read at {key}")
        states.append(entries(fs, system, should_stop))
    return compare(*states)


def summary(rows):
    """{change: count}."""
    counts = {change: 0 for change in CHANGES}
    for row in rows:
        counts[row['change']] += 1
    return counts

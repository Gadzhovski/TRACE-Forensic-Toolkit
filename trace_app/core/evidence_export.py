"""Copying evidence out, so the copy can be shown to be the evidence (no Qt).

An exported file is evidence leaving the tool; what it must carry is
proof of what it is. Every export here:

* streams the file from the image (never whole in memory) and hashes it
  as it is written -- MD5, SHA-1, SHA-256 of exactly the bytes the file
  system records, or the file is not exported (a read that fails or
  comes back short leaves no partial copy: it is written as '<name>.part'
  and removed);
* reads the written copy back and checks its SHA-256, so a copy damaged
  on the way to disk is caught;
* names it safely for any platform (carving.safe_name: names from
  evidence can hold separators, ':' or device names) and never
  overwrites -- a second 'a.txt' is 'a (2).txt';
* exports empty files too (they are evidence of a name);
* writes `export-manifest.csv` -- source evidence, path, artifact
  reference, deleted or not, the file system's times, size, hashes,
  where it was saved, what failed -- and returns the manifest's SHA-256
  for the audit line the caller writes (Case.record_event).

`save_bytes` does the same for bytes already in hand (a hex selection,
a picture shown in the viewer); the caller audits through `record`.
"""

import csv
import datetime
import os

from trace_app.core import evidence_hash

MANIFEST = 'export-manifest.csv'
MANIFEST_COLUMNS = ['exported_utc', 'evidence', 'source_path',
                    'artifact_ref', 'deleted', 'created', 'modified',
                    'accessed', 'changed', 'size', 'md5', 'sha1', 'sha256',
                    'written_copy_check', 'saved_as', 'problem']
BLOCK = 4 * 1024 * 1024

#: Called with (action, detail) for exports made outside an Exporter run
#: (save_bytes): the window points it at the open case's audit trail.
_recorder = None


class ExportCancelled(Exception):
    pass


def set_recorder(callback):
    """Where `save_bytes` reports exports: the case's audit trail."""
    global _recorder
    _recorder = callback


def record(action, detail):
    if _recorder is not None:
        try:
            _recorder(action, detail)
        except Exception:
            pass


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S')


def safe_component(name, fallback):
    from trace_app.core.carving import safe_name
    cleaned = safe_name(name or '')
    if cleaned in ('', '.', '..'):
        cleaned = fallback
    return cleaned


def unique_path(folder, name):
    """`folder/name`, or 'name (2).ext'... when that exists."""
    target = os.path.join(folder, name)
    if not os.path.exists(target):
        return target
    stem, dot, extension = name.rpartition('.')
    if not dot or not stem:
        stem, extension = name, ''
    number = 2
    while True:
        candidate = f"{stem} ({number})" + (f".{extension}" if extension
                                             else '')
        target = os.path.join(folder, candidate)
        if not os.path.exists(target):
            return target
        number += 1


def write_verified(target, read, size, should_stop=None, progress=None):
    """Write `size` bytes from read(offset, length) to `target`, hashing
    them; check the written copy. Returns the digests plus
    'written_copy_check'. Raises HashingError (nothing left behind) when
    the source cannot be read in full."""
    partial = target + '.part'
    hashers = evidence_hash.new_hashers()
    position = 0
    try:
        with open(partial, 'wb') as handle:
            while position < size:
                if should_stop is not None and should_stop():
                    raise ExportCancelled()
                want = min(BLOCK, size - position)
                try:
                    data = read(position, want)
                except Exception as exc:
                    raise evidence_hash.HashingError(
                        f"reading failed at byte {position:,} of "
                        f"{size:,}: {exc}") from exc
                if not data:
                    raise evidence_hash.HashingError(
                        f"the file ended at byte {position:,} of {size:,}")
                data = data[:want]
                handle.write(data)
                for hasher in hashers.values():
                    hasher.update(data)
                position += len(data)
                if progress is not None:
                    progress(len(data))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(partial, target)
    except BaseException:
        try:
            os.remove(partial)
        except OSError:
            pass
        raise
    digests = evidence_hash.digests(hashers, position)
    try:
        written = evidence_hash.hash_file(target)['sha256']
    except evidence_hash.HashingError as exc:
        written = None
        digests['written_copy_check'] = f"could not be read back: {exc}"
    else:
        digests['written_copy_check'] = (
            'matches' if written == digests['sha256'] else
            f"DIFFERS: the copy on disk hashes to {written}")
    return digests


class Exporter:
    """Export files and folders from one image into `folder`, with a
    manifest. `progress(bytes)` and `should_stop()` are optional."""

    def __init__(self, handler, folder, evidence_name, should_stop=None,
                 progress=None, status=None):
        self.handler = handler
        self.folder = folder
        self.evidence_name = evidence_name
        self.should_stop = should_stop
        self.progress = progress
        self.status = status
        self.rows = []

    # --- what to export -------------------------------------------------

    def export(self, items):
        """`items`: [{'start_offset', 'inode_number', 'name', 'type'
        ('directory' or a file), 'path' (on the image), 'artifact_ref',
        'is_deleted'}]."""
        os.makedirs(self.folder, exist_ok=True)
        for item in items:
            self._stop_check()
            if item.get('type') == 'directory':
                self._folder(item, self.folder, set())
            else:
                self._file(item, self.folder)
        return self.rows

    def _stop_check(self):
        if self.should_stop is not None and self.should_stop():
            raise ExportCancelled()

    def _folder(self, item, parent, seen):
        key = (item.get('start_offset'), item.get('inode_number'))
        if key in seen:
            return
        seen.add(key)
        name = safe_component(item.get('name'),
                              f"inode-{item.get('inode_number')}")
        target = unique_path(parent, name) if os.path.isfile(
            os.path.join(parent, name)) else os.path.join(parent, name)
        os.makedirs(target, exist_ok=True)
        try:
            entries = self.handler.get_directory_contents(
                item['start_offset'], item['inode_number']) or []
        except Exception as exc:
            self._row(item, problem=f"folder could not be listed: {exc}")
            return
        base = item.get('path') or item.get('name') or ''
        for entry in entries:
            self._stop_check()
            if entry.get('name') in ('.', '..', None):
                continue
            child = dict(entry, start_offset=item['start_offset'],
                         type='directory' if entry.get('is_directory')
                         else 'file',
                         path=f"{base.rstrip('/')}/{entry['name']}")
            if child['type'] == 'directory':
                self._folder(child, target, seen)
            else:
                self._file(child, target)

    def _file(self, item, folder):
        name = safe_component(item.get('name'),
                              f"inode-{item.get('inode_number')}")
        if self.status is not None:
            self.status(item.get('path') or name)
        try:
            fs = self.handler.get_fs_info(item['start_offset'])
            entry = fs.open_meta(inode=item['inode_number'])
            size = int(entry.info.meta.size or 0)
        except Exception as exc:
            self._row(item, problem=f"could not be opened: {exc}")
            return
        item = dict(item, **_facts(self.handler, item, entry))
        target = unique_path(folder, name)
        try:
            digests = write_verified(
                target, lambda offset, length:
                entry.read_random(offset, length), size,
                self.should_stop, self.progress)
        except ExportCancelled:
            raise
        except Exception as exc:
            self._row(item, size=size, problem=f"not exported: {exc}")
            return
        self._row(item, size=size, digests=digests, saved=target)

    def _row(self, item, size=None, digests=None, saved='', problem=''):
        digests = digests or {}
        check = digests.get('written_copy_check', '')
        if check and check != 'matches' and not problem:
            problem = f"written copy {check}"
        self.rows.append({
            'exported_utc': _utc_now(), 'evidence': self.evidence_name,
            'source_path': item.get('path') or item.get('name') or '',
            'artifact_ref': item.get('artifact_ref') or '',
            'deleted': 'yes' if item.get('is_deleted') else 'no',
            'created': item.get('created') or '',
            'modified': item.get('modified') or '',
            'accessed': item.get('accessed') or '',
            'changed': item.get('changed') or '',
            'size': '' if size is None else size,
            'md5': digests.get('md5', ''), 'sha1': digests.get('sha1', ''),
            'sha256': digests.get('sha256', ''),
            'written_copy_check': check,
            'saved_as': os.path.relpath(saved, self.folder) if saved else '',
            'problem': problem})

    # --- the record -------------------------------------------------------

    def write_manifest(self):
        """(path, SHA-256) of the manifest, beside the exported files; a
        manifest already there is kept and this one numbered."""
        path = unique_path(self.folder, MANIFEST)
        with open(path, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, MANIFEST_COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows)
        return path, evidence_hash.hash_file(path)['sha256']

    def summary(self):
        exported = [r for r in self.rows if r['saved_as']]
        return {'files': len(exported),
                'bytes': sum(int(r['size'] or 0) for r in exported),
                'problems': [f"{r['source_path']}: {r['problem']}"
                             for r in self.rows if r['problem']]}


def _facts(handler, item, entry):
    """What the file system records about an exported file, for the
    manifest: its reference, whether it is deleted, its four times as
    TRACE shows them (FAT's local times marked so)."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.infra.utils import safe_datetime
    facts = {}
    meta = entry.info.meta
    try:
        import pytsk3
        facts['is_deleted'] = item.get('is_deleted', not (
            int(meta.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC)))
    except Exception:
        pass
    sequence = item.get('sequence')
    if sequence is None:
        sequence = getattr(meta, 'seq', None)
    facts['artifact_ref'] = item.get('artifact_ref') or make_artifact_ref(
        item['start_offset'], item['inode_number'], sequence)
    try:
        shown = handler.entry_times_text(item['start_offset'], meta)
    except Exception:
        shown = {key: safe_datetime(getattr(meta, field, None))
                 for key, field in (('created', 'crtime'),
                                    ('modified', 'mtime'),
                                    ('accessed', 'atime'),
                                    ('changed', 'ctime'))}
    for key, text in shown.items():
        if item.get(key) and item[key] != 'N/A':
            continue
        facts[key] = text
    return facts


def save_reader(target, read, size, what, source):
    """Write `size` bytes from read(offset, length) -- a hex selection
    read from the image, a picture held in the viewer -- to `target`,
    check the copy, and record it. Returns the digests."""
    digests = write_verified(target, read, size)
    record(what, f"{source} -> {target}; {size:,} bytes; "
                 f"SHA-256 {digests['sha256']}; MD5 {digests['md5']}; "
                 f"copy {digests['written_copy_check']}")
    return digests


def save_bytes(target, data, what, source):
    """save_reader for bytes already in memory."""
    return save_reader(target, lambda offset, length:
                       data[offset:offset + length], len(data), what, source)

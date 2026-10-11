"""A whole case in one file, for handing over or keeping (no Qt).

A `.trace` is a ZIP of the case folder: its database taken with
SQLite's backup API (consistent while the case is open and a job writes
it), the search index when asked for (large, and rebuilt by indexing), and
every other file the folder holds -- exports, carved copies, reports,
assembled-volume descriptors. Evidence is never in it: a case refers to its
images by path and hash, and so does its archive.

`MANIFEST.json` names every member with its size and SHA-256, the evidence
with the hashes the case recorded for it, who made the archive and when,
and the head of the audit trail at that moment. The archive's own SHA-256
goes into the audit line and a `.sha256` file beside it.

Opening one checks every member against the manifest before anything is
written, refuses names that would land outside the chosen folder, unpacks,
opens the case and checks its audit chain -- the manifest's head must be
an entry in it -- then records where the case came from.
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import zipfile

logger = logging.getLogger('TRACE.CaseArchive')

SUFFIX = '.trace'
MANIFEST = 'MANIFEST.json'
FORMAT = 1
#: Members live under this folder in the ZIP, so an archive opened by hand
#: unpacks into one folder rather than over whatever is beside it.
ROOT = 'case'
#: SQLite databases in a case folder, copied with the backup API.
DATABASES = ('case.db', 'search.db')
#: Files never archived: a database's journal (the backup has its content)
#: and lock files.
_SKIPPED_SUFFIXES = ('-wal', '-shm', '-journal', '.part')
_BLOCK = 1024 * 1024


class ArchiveError(Exception):
    """The archive cannot be written or opened, and why."""


class ArchiveCancelled(Exception):
    """The examiner stopped it."""


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(_BLOCK), b''):
            digest.update(block)
    return digest.hexdigest()


def _backup(source, target):
    """A consistent copy of a SQLite database, readers and a writer
    notwithstanding."""
    # A plain path, not a file: URI: a case folder's name can hold a
    # space, '#' or '?'. The backup only reads the source.
    src = sqlite3.connect(source, timeout=30)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
            # One file: the copy carries no -wal of its own.
            dst.execute("PRAGMA journal_mode=DELETE")
        finally:
            dst.close()
    finally:
        src.close()


def _case_files(folder, include_index):
    """(relative path, absolute path) of the folder's files to archive,
    databases excepted (they are backed up)."""
    out = []
    for parent, folders, files in os.walk(folder):
        folders.sort()
        for name in sorted(files):
            full = os.path.join(parent, name)
            relative = os.path.relpath(full, folder).replace(os.sep, '/')
            if relative in DATABASES or name.endswith(_SKIPPED_SUFFIXES):
                continue
            if not include_index and relative.startswith('search.db'):
                continue
            if os.path.islink(full):
                continue
            out.append((relative, full))
    return out


def archive_details(case):
    """What the manifest says of the case -- read on the case's own thread
    (its connection belongs there), before the files are written."""
    from trace_app import __version__
    case.commit()
    audit = case.verify_audit()
    return {
        'folder': case.folder,
        'tool': f"TRACE {__version__}",
        'examiner': case.examiner,
        'case': {'name': case.name, 'number': case.number},
        'audit_head': audit.get('head'),
        'audit_ok': audit.get('ok'),
        'evidence': [{key: row.get(key) for key in (
            'id', 'path', 'display_name', 'size', 'md5', 'sha1', 'sha256',
            'stored_md5', 'stored_sha1', 'stored_sha256', 'exhibit_number')}
            for row in case.evidence()],
    }


def archive_path(path):
    """`path` with the archive suffix, made absolute."""
    if not path.lower().endswith(SUFFIX):
        path += SUFFIX
    return os.path.abspath(path)


def write_archive(details, path, include_index=True, progress=None,
                  should_stop=None):
    """Write the archive (any thread: no case connection used). Returns
    {'path', 'sha256', 'members', 'size', 'search_index', 'audit_head'}.
    `progress(done, total, what)` counts bytes."""
    folder = details['folder']
    path = archive_path(path)
    if os.path.commonpath([os.path.abspath(folder), path]) == \
            os.path.abspath(folder):
        raise ArchiveError("Save the archive outside the case folder.")
    work = tempfile.mkdtemp(prefix='trace-archive-')
    partial = path + '.part'
    try:
        sources = []
        for name in DATABASES:
            if name == 'search.db' and not include_index:
                continue
            source = os.path.join(folder, name)
            if os.path.exists(source):
                copy = os.path.join(work, name)
                _backup(source, copy)
                sources.append((name, copy))
        sources += _case_files(folder, include_index)
        total = sum(os.path.getsize(full) for _rel, full in sources)
        done = 0
        members = {}
        with zipfile.ZipFile(partial, 'w', zipfile.ZIP_DEFLATED,
                             allowZip64=True) as archive:
            for relative, full in sources:
                digest = hashlib.sha256()
                size = 0
                info = zipfile.ZipInfo.from_file(full, f"{ROOT}/{relative}")
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, 'rb') as source, \
                        archive.open(info, 'w', force_zip64=True) as target:
                    for block in iter(lambda: source.read(_BLOCK), b''):
                        if should_stop and should_stop():
                            raise ArchiveCancelled()
                        digest.update(block)
                        target.write(block)
                        size += len(block)
                        done += len(block)
                        if progress:
                            progress(done, total, relative)
                members[f"{ROOT}/{relative}"] = {
                    'size': size, 'sha256': digest.hexdigest()}
            manifest = dict(
                {key: value for key, value in details.items()
                 if key != 'folder'},
                format=FORMAT, created_utc=_now(),
                search_index=any(name == 'search.db'
                                 for name, _f in sources),
                members=members)
            archive.writestr(MANIFEST, json.dumps(manifest, indent=2))
        os.replace(partial, path)
    except BaseException:
        try:
            os.remove(partial)
        except OSError:
            pass
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sha256 = _sha256_file(path)
    with open(path + '.sha256', 'w', encoding='utf-8') as handle:
        handle.write(f"{sha256}  {os.path.basename(path)}\n")
    return {'path': path, 'sha256': sha256, 'members': len(members),
            'size': os.path.getsize(path),
            'search_index': manifest['search_index'],
            'audit_head': details.get('audit_head')}


def record_archive(case, made):
    """The audit line for an archive written (on the case's thread)."""
    case.record_event(
        'case archived',
        f"{made['path']} ({made['size']:,} bytes) SHA-256 "
        f"{made['sha256']}; {made['members']} file(s); search index "
        f"{'included' if made['search_index'] else 'not included'}; "
        f"audit head {made['audit_head']}")
    logger.info("Archived case %r to %s", case.name, made['path'])


def export_case(case, path, include_index=True, progress=None,
                should_stop=None):
    """Write `case` to the archive `path` and audit it -- the three steps
    above in one thread. Returns write_archive's summary."""
    made = write_archive(archive_details(case), path, include_index,
                         progress, should_stop)
    record_archive(case, made)
    return made


def _now():
    from trace_app.core.case import _utc_now
    return _utc_now()


def read_manifest(path):
    """The archive's manifest, or ArchiveError."""
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read(MANIFEST).decode('utf-8'))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"Not a TRACE case archive: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get('format') != FORMAT \
            or not isinstance(manifest.get('members'), dict):
        raise ArchiveError("Not a TRACE case archive (no usable manifest).")
    return manifest


def _safe(name):
    """Whether a member name stays inside the folder it is unpacked into."""
    parts = name.split('/')
    return bool(name) and not name.startswith('/') and '\\' not in name \
        and ':' not in name and '..' not in parts and parts[0] == ROOT \
        and all(parts[1:])


def check_archive(path, progress=None, should_stop=None):
    """(manifest, problems): every member re-hashed against the manifest;
    a member missing, extra, altered or named to escape is a problem."""
    manifest = read_manifest(path)
    expected = manifest['members']
    problems = []
    with zipfile.ZipFile(path) as archive:
        names = [info.filename for info in archive.infolist()
                 if not info.is_dir()]
        for name in names:
            if name != MANIFEST and name not in expected:
                problems.append(f"{name}: not in the manifest")
        total = sum(entry.get('size') or 0 for entry in expected.values())
        done = 0
        for name, entry in expected.items():
            if not _safe(name):
                problems.append(f"{name}: would be written outside the "
                                f"case folder")
                continue
            if name not in names:
                problems.append(f"{name}: missing")
                continue
            digest = hashlib.sha256()
            size = 0
            with archive.open(name) as member:
                for block in iter(lambda: member.read(_BLOCK), b''):
                    if should_stop and should_stop():
                        raise ArchiveCancelled()
                    digest.update(block)
                    size += len(block)
                    done += len(block)
                    if progress:
                        progress(done, total, name)
            if size != entry.get('size') or \
                    digest.hexdigest() != entry.get('sha256'):
                problems.append(f"{name}: altered (SHA-256 "
                                f"{digest.hexdigest()}, manifest "
                                f"{entry.get('sha256')})")
    return manifest, problems


def unpack_archive(path, folder, progress=None, should_stop=None):
    """Check every member against the manifest, then unpack into `folder`
    (absent or empty) -- any thread. Returns {'manifest', 'sha256'}.
    Nothing is written when a member fails its check."""
    sha256 = _sha256_file(path)
    manifest, problems = check_archive(path, progress, should_stop)
    if problems:
        raise ArchiveError("The archive does not match its manifest:\n"
                           + '\n'.join(problems[:20])
                           + (f"\n... and {len(problems) - 20} more"
                              if len(problems) > 20 else ''))
    if os.path.exists(folder) and os.listdir(folder):
        raise ArchiveError(f"{folder} is not empty: choose an empty folder "
                           f"for the case.")
    os.makedirs(folder, exist_ok=True)
    root = os.path.abspath(folder)
    try:
        with zipfile.ZipFile(path) as archive:
            for name in manifest['members']:
                target = os.path.abspath(os.path.join(
                    root, *name.split('/')[1:]))
                if os.path.commonpath([root, target]) != root:
                    raise ArchiveError(f"{name}: outside the case folder")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(name) as source, \
                        open(target, 'wb') as handle:
                    shutil.copyfileobj(source, handle, _BLOCK)
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return {'manifest': manifest, 'sha256': sha256}


def open_unpacked(path, folder, unpacked):
    """Open the unpacked case (on the thread that will use it), check its
    audit chain and record where it came from. Returns the Case."""
    from trace_app.core.case import Case
    manifest = unpacked['manifest']
    case = Case.open(folder)
    intact, _text = audit_status(case, manifest)
    case.record_event(
        'case opened from archive',
        f"{path} SHA-256 {unpacked['sha256']}, made "
        f"{manifest.get('created_utc')} by "
        f"{manifest.get('examiner') or 'unknown'} with "
        f"{manifest.get('tool')}; {len(manifest['members'])} file(s) "
        f"checked against its manifest; audit trail "
        f"{'intact' if intact else 'BROKEN'}")
    if not intact:
        logger.warning("Case archive %s: the audit trail does not hold",
                       path)
    return case


def import_case(path, folder, progress=None, should_stop=None):
    """Unpack the archive `path` into `folder` and open it: the two steps
    above in one thread. Returns the open Case."""
    unpacked = unpack_archive(path, folder, progress, should_stop)
    try:
        return open_unpacked(path, folder, unpacked)
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)
        raise


def audit_status(case, manifest):
    """Whether the opened case's audit trail holds and includes the
    archived head: (ok, text)."""
    audit = case.verify_audit()
    head = manifest.get('audit_head')
    listed = head is None or bool(case._db.execute(
        "SELECT 1 FROM activity WHERE entry_hash = ?", (head,)).fetchone())
    if audit.get('ok') and listed:
        return True, "The audit trail is intact."
    return False, ("The audit trail does not hold: "
                   + '; '.join(str(p) for p in (audit.get('problems')
                                                or [])[:5])
                   if not audit.get('ok') else
                   "The audit trail no longer includes the entry it ended "
                   "at when archived.")


def missing_evidence(case):
    """Evidence rows whose file is not where the case says (a case opened
    on another machine): what Locate is offered for."""
    from trace_app.core.live_disk import is_device_path
    return [row for row in case.evidence()
            if not is_device_path(row['path'])
            and not os.path.exists(row['path'])]

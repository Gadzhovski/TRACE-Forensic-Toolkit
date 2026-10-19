"""What to hand a tool from one image (no Qt).

A LEAPP reads loose files (`-t fs`) -- and also a whole extraction packed
in a tar or zip, and an iTunes/Finder backup (`-t tar|zip|gz|itunes`).
Phone extractions usually arrive packed: a full file system as one 16 GB
tar beside a zipped backup and sysdiagnose archives. Staging loose files
alone never opens those, and the tool reads almost nothing, without an
error. So an image's inputs are:

* 'staged'  the loose files the tool's patterns name (core/modules/stage);
* 'tar' / 'zip' / 'gz'  an archive whose members are a phone's file
  system -- 'private/var/mobile' (iOS), 'data/data' or 'data/media'
  (Android) among the first members -- run as it is (a file on disk is
  passed by its path, read-only; one inside a disk image is copied out);
* 'itunes'  a zipped iTunes/Finder backup (Manifest.db + Manifest.plist in
  one folder), unpacked into the run's folder and run as `-t itunes`. An
  encrypted one (Manifest.plist's IsEncrypted) is marked `encrypted`:
  without its password the tool reads nothing of it, so the job records it
  as skipped ('needs_password') until the examiner gives one. A password
  is checked against the backup's keybag first (`check_password`, TRACE's
  own iOS backup reader) -- a wrong one is said so at once, not after the
  tool has run -- then passed as `--itunes_password`: the LEAPPs take a
  backup's password on the command line only (their file/environment
  options are for disk images). It is masked in run.log and progress, and
  never stored: the case keeps that one was given.

Each input is its own run, and says what it was (`label`), so a run's
coverage is readable.
"""

import logging
import os
import tarfile
import zipfile

logger = logging.getLogger('TRACE.Modules')

#: Member paths that say an archive holds a phone's file system.
MARKERS = {
    'ios': ('private/var/mobile/', 'private/var/containers/',
            'private/var/root/library/', 'var/mobile/library/'),
    'android': ('data/data/', 'data/user/0/', 'data/media/0/',
                'data/system_ce/', 'data/misc/'),
}
#: Members looked at before a compressed archive is judged (it must be
#: decompressed to be read). A plain tar is read header to header to its
#: end -- its data skipped, a seek each: a phone's file system lists
#: private/ after every system folder (a 16 GB iOS tar: past 50,000).
TAR_MEMBERS = None
COMPRESSED_MEMBERS = 3000
ARCHIVE_SUFFIXES = ('.tar', '.tar.gz', '.tgz', '.tar.xz', '.zip')
MIN_ARCHIVE = 1024 * 1024


def _system_in(names, systems):
    """The first of `systems` whose markers appear in `names`, or None."""
    for name in names:
        low = '/' + name.replace('\\', '/').lower().lstrip('/')
        for system in systems:
            if any('/' + marker in low
                   for marker in MARKERS.get(system, ())):
                return system
    return None


def _backup_root(names):
    """The folder of an iTunes/Finder backup inside a zip, or None."""
    names = {n.replace('\\', '/') for n in names}
    for name in names:
        if name.endswith('/Manifest.db') or name == 'Manifest.db':
            folder = name[:-len('Manifest.db')]
            if folder + 'Manifest.plist' in names or \
                    folder + 'Info.plist' in names:
                return folder.rstrip('/')
    return None


def _encrypted(zipped, names, root):
    """True / False from the backup's Manifest.plist, None when it has
    none or does not say."""
    from trace_app.core.evidence_overview import backup_encrypted
    name = (root + '/' if root else '') + 'Manifest.plist'
    if name not in names:
        return None
    return backup_encrypted(zipped.read(name))


def check_password(handler, item, password):
    """Raise ios_backup.BackupError unless `password` unlocks the zipped
    backup `item` (from find_archives): its Manifest.plist's keybag, as
    TRACE unlocks an iOS backup folder."""
    import plistlib
    from trace_app.core.ios_backup import BackupError, Keybag
    name = (item['root'] + '/' if item.get('root') else '') + \
        'Manifest.plist'
    if item.get('os_path'):
        handle = open(item['os_path'], 'rb')
    else:
        entry = item['entry']
        handle = handler.open_file_object(entry.inode, entry.offset)
        if handle is None:
            raise BackupError(f"{item['name']} could not be read")
    try:
        with zipfile.ZipFile(handle) as zipped:
            manifest = plistlib.loads(zipped.read(name))
    except (KeyError, zipfile.BadZipFile, plistlib.InvalidFileException,
            ValueError) as exc:
        raise BackupError(f"{item['name']}: its Manifest.plist could not be "
                          f"read ({exc})") from exc
    finally:
        try:
            handle.close()
        except Exception:
            pass
    blob = manifest.get('BackupKeyBag') if isinstance(manifest, dict) \
        else None
    if not blob:
        raise BackupError(f"{item['name']}: Manifest.plist holds no keybag")
    Keybag(blob).unlock(password)


#: What `judge` says of an archive a tool's own patterns found.
PATTERNS = 'files it reads'


def _named(names, matcher):
    """Whether `matcher` names any of the archive's members."""
    if matcher is None:
        return False
    return any(matcher('/' + name.replace('\\', '/').lstrip('/'))
               for name in names)


def judge(handle, name, systems, matcher=None):
    """(kind, extra) for an archive file object: ('tar'|'gz'|'zip',
    system) for a packed extraction, ('itunes', {'root': backup folder,
    'encrypted': True/False/None}) for a zipped backup, or (None, None).
    `matcher` (core/modules/fit's specific patterns, for a tool whose
    evidence has no system -- RLEAPP's warrant returns arrive as zips)
    takes an archive whose members it names: (kind, 'files it reads')."""
    low = name.lower()
    try:
        if low.endswith('.zip'):
            with zipfile.ZipFile(handle) as zipped:
                names = zipped.namelist()
                if 'ios' in systems:
                    root = _backup_root(names)
                    if root is not None:
                        return 'itunes', {
                            'root': root,
                            'encrypted': _encrypted(zipped, names, root)}
            system = _system_in(names, systems)
            if system is None and _named(names, matcher):
                system = PATTERNS
            return ('zip', system) if system else (None, None)
        compressed = not low.endswith('.tar')
        limit = COMPRESSED_MEMBERS if compressed else TAR_MEMBERS
        names = []
        with tarfile.open(fileobj=handle, mode='r:*') as tarred:
            for member in tarred:
                names.append(member.name)
                system = _system_in(names[-1:], systems)
                if system is None and _named(names[-1:], matcher):
                    system = PATTERNS
                if system:
                    return ('tar' if low.endswith('.tar') else
                            'gz' if low.endswith(('.gz', '.tgz')) else 'tar'
                            ), system
                if limit is not None and len(names) >= limit:
                    break
                if len(names) > 4096:
                    del names[:-1]          # only the newest is looked at
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError,
            ValueError) as exc:
        logger.debug("%s not judged: %s", name, exc)
    return None, None


def find_archives(handler, systems, candidates, evidence_path=None,
                  should_stop=None, matcher=None):
    """[{'kind', 'system'|'root', 'entry', 'os_path'}] -- the packed
    extractions and zipped backups among `candidates` (FileEntry, from
    stage.find's walk). `os_path` is the file's own path when it is a file
    on this computer (folder evidence), so it is read where it is."""
    found = []
    folder = evidence_path if evidence_path and os.path.isdir(
        evidence_path) else None
    for entry in candidates:
        if should_stop is not None and should_stop():
            break
        os_path = os.path.join(folder, *entry.path.strip('/').split('/')) \
            if folder else None
        try:
            if os_path and os.path.isfile(os_path):
                with open(os_path, 'rb') as handle:
                    kind, extra = judge(handle, entry.name, systems, matcher)
            else:
                stream = handler.open_file_object(entry.inode, entry.offset)
                if stream is None:
                    continue
                kind, extra = judge(stream, entry.name, systems, matcher)
        except Exception as exc:
            logger.debug("%s not read: %s", entry.path, exc)
            continue
        if kind is None:
            continue
        item = {'kind': kind, 'entry': entry, 'os_path': os_path,
                'name': entry.name, 'path': entry.path, 'size': entry.size}
        if kind == 'itunes':
            item.update(extra)
        else:
            item['system'] = extra
        found.append(item)
    return found


#: The evidence itself, read in place by the tool (`-t raw`): an image
#: TRACE cannot open but the tool can -- a QNX head unit for VLEAPP.
RAW = 'raw'
#: Images a LEAPP's `-t raw` reads (its documentation: raw, EWF, SMART,
#: AFF, AFF4, Apple disk images, VHD/VHDX/VMDK/QCOW2, L01/AD1).
RAW_SUFFIXES = ('.img', '.dd', '.bin', '.raw', '.001', '.000', '.e01',
                '.ex01', '.s01', '.aff', '.afm', '.aff4', '.dmg',
                '.sparseimage', '.vhd', '.vhdx', '.vmdk', '.qcow2', '.l01',
                '.ad1')


def raw_input(spec, handler, evidence_path, staged_anything):
    """The evidence itself as an input, or None: when the tool reads
    images (`raw` in spec.inputs), the evidence is such an image file, and
    TRACE found volumes it cannot open (evidence_profile.
    unreadable_signatures) or nothing to give the tool at all."""
    from trace_app.core import evidence_profile
    if RAW not in spec.inputs or not evidence_path or \
            not os.path.isfile(evidence_path) or \
            not evidence_path.lower().endswith(RAW_SUFFIXES) or \
            handler.logical_fs is not None:
        return None
    unreadable = evidence_profile.unreadable_signatures(handler)
    if not unreadable and staged_anything:
        return None
    what = ', '.join(dict.fromkeys(name for _start, name in unreadable))
    return {'kind': RAW, 'os_path': evidence_path, 'entry': None,
            'name': os.path.basename(evidence_path), 'path': evidence_path,
            'size': os.path.getsize(evidence_path), 'unreadable': what}


def label(item):
    """What an input is, in a run's name and details."""
    if item['kind'] == 'staged':
        return f"{item['count']:,} loose file(s)"
    if item['kind'] == RAW:
        return (f"the image itself ({item['unreadable']})"
                if item.get('unreadable') else "the image itself")
    if item['kind'] == 'itunes':
        return f"iTunes backup in {item['name']}" + (
            " (encrypted)" if item.get('encrypted') else '')
    if item.get('system') == PATTERNS:
        # A return's zip, a car's export: no system was found in it, the
        # files the tool reads were.
        return f"files it reads in {item['name']}"
    return f"extraction in {item['name']}"

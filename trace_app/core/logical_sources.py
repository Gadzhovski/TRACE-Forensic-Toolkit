"""The logical evidence TRACE opens, each as a LogicalFileSystem
(core/logical.py): a folder, a ZIP or TAR, an AD1 image (core/ad1.py), an
EnCase L01/Lx01 image (through libewf's file entries) and an iPhone
backup (core/ios_backup.py).

A folder or archive is how triage collections arrive -- KAPE and
Velociraptor outputs, UAC, a phone's file system extraction -- and how
much other evidence is handed over. Their files are read where they are,
when they are asked for; nothing is unpacked to disk.

The times a source records are the ones shown, with what they are:
  * a folder's are its copies' on the examiner's disk (a collector that
    preserves them, as KAPE does, makes them the originals'), said in
    the file system's facts;
  * a ZIP stores local wall-clock time with no zone, so a ZIP is shown
    as FAT is, "(local, no zone)";
  * TAR, AD1 and L01 store UTC.
"""

import collections
import os
import re
import stat
import tarfile
import threading
import zipfile

from trace_app.core.logical import ROOT, LogicalFileSystem

#: A member up to this size is read whole once and kept (a few at a time)
#: rather than decompressed again for every read.
CACHE_MEMBER = 64 * 1024 * 1024
CACHED_MEMBERS = 4

KIND_LABELS = {'folder': 'Folder', 'zip': 'ZIP', 'tar': 'TAR', 'ad1': 'AD1',
               'l01': 'L01', 'ios_backup': 'iOS backup',
               'android_backup': 'Android backup',
               'ufdr': 'Cellebrite UFDR'}


def kind_of(path):
    """'folder', 'ios_backup', 'zip', 'tar', 'ad1', 'l01' -- or None for
    anything else (a disk image)."""
    if not path:
        return None
    if path.lower().rstrip('/\\').endswith('.sparsebundle'):
        return None                 # a Mac disk image that is a folder
    from trace_app.core.aff import is_afd
    if is_afd(path.rstrip('/\\')):
        return None                 # an AFD: AFF split across a folder
    from trace_app.core.containers import parallels_descriptor
    if parallels_descriptor(path):
        return None                 # a Parallels disk bundle: a folder too
    if os.path.isdir(path):
        from trace_app.core.ios_backup import is_backup
        return 'ios_backup' if is_backup(path) else 'folder'
    lowered = path.lower()
    if lowered.endswith('.ad1'):
        return 'ad1'
    if lowered.endswith(('.l01', '.lx01')):
        return 'l01'
    if lowered.endswith('.ab') or _starts(path, b'ANDROID BACKUP\n'):
        return 'android_backup'
    if lowered.endswith(('.zip', '.ufdr')):
        # A Cellebrite UFDR is a ZIP: the extracted files and report.xml
        # (core/ufdr) -- a renamed one too.
        from trace_app.core.ufdr import is_ufdr
        return 'ufdr' if is_ufdr(path) else 'zip'
    if lowered.endswith(('.tar', '.tgz', '.tar.gz', '.tar.bz2', '.tbz2',
                         '.tar.xz', '.txz')):
        return 'tar'
    return None


def _starts(path, magic):
    """Whether the file at `path` begins with `magic` (False for a folder
    or anything unreadable)."""
    try:
        with open(path, 'rb') as handle:
            return handle.read(len(magic)) == magic
    except OSError:
        return False


#: Second and later segments of a segmented image: they are read with the
#: first, so selecting every segment adds the image once.
_LATER_SEGMENT = re.compile(
    r'\.(?:e|ex|s|l|lx)(?:0[2-9]|[1-9][0-9])$|\.(?:00[2-9]|0[1-9][0-9]|'
    r'[1-9][0-9]{2})$|\.ad(?:[2-9]|[1-9][0-9]+)$', re.IGNORECASE)

#: Any segment of an image TRACE opens as one piece of evidence: EWF
#: (E01/Ex01/S01/L01/Lx01 and on), AD1 and its parts, split raw (.000,
#: .001 ...), and single-file disk images.
_IMAGE_FILE = re.compile(
    r'\.(?:e|ex|s|l|lx)[0-9]{2}$|\.ad[0-9]+$|\.[0-9]{3}$|'
    r'\.(?:dd|raw|img|iso|dmg|hdd|hds|sparseimage|vmdk|vhd|vhdx|qcow2?|'
    r'aff4?)$', re.IGNORECASE)

#: What imagers write beside an image: acquisition logs, hash lists,
#: reports -- and what operating systems leave in any folder.
_SIDE_FILE = re.compile(
    r'\.(?:txt|log|csv|xml|info|md5|sha1|sha256|hash|json|html?|pdf|rtf)$'
    r'|^(?:desktop\.ini|thumbs\.db)$|^\.', re.IGNORECASE)


def is_later_segment(path):
    """Whether `path` is a second or later segment of a segmented image."""
    # A split raw image numbered from .000 has .001 as its second part.
    if path.lower().endswith('.001') and \
            os.path.exists(path[:-4] + '.000'):
        return True
    return bool(_LATER_SEGMENT.search(path))


def folder_images(path):
    """(images, holds_other): the first segment of every disk or logical
    image directly in the folder `path`, and whether the folder holds
    anything else -- sub-folders, or files that are neither image segments
    nor what an imager leaves beside its image.

    A folder holding only images (1.E01, 1.E02, 1.E03 and the imager's
    log) is how an image is handed over: it is the image that is the
    evidence, not the folder of its segment files. Beside it count: logs
    and hash lists (`_SIDE_FILE`), and any file named after one of the
    images -- GNOME_Fedora.docx beside GNOME_Fedora.e01 is its acquisition
    report, whatever its format."""
    try:
        entries = sorted(os.scandir(path), key=lambda e: e.name.lower())
    except OSError:
        return [], True
    images, files, other = [], [], False
    for entry in entries:
        if entry.name.startswith('.'):
            continue
        if entry.is_dir(follow_symlinks=False):
            # A sparsebundle or a Parallels bundle is an image itself.
            if kind_of(entry.path) is None and \
                    entry.name.lower().endswith(('.sparsebundle', '.hdd',
                                                 '.afd')):
                images.append(entry.path)
            else:
                other = True
            continue
        if _IMAGE_FILE.search(entry.name):
            if not is_later_segment(entry.path):
                images.append(entry.path)
        elif not _SIDE_FILE.search(entry.name):
            files.append(entry.name)
    stems = {_stem(os.path.basename(image)) for image in images}
    for name in files:
        if _stem(name) not in stems:
            other = True
    return images, other


def _stem(name):
    """'GNOME_Fedora.e01' / 'GNOME_Fedora.docx' / 'x.E01.txt' -> the name
    before its first dot, lower case."""
    return name.split('.', 1)[0].lower()


def open_logical(path):
    kind = kind_of(path)
    if kind == 'ad1':
        from trace_app.core.ad1 import open_ad1
        return open_ad1(path)
    if kind == 'ios_backup':
        from trace_app.core.ios_backup import open_backup
        return open_backup(path)
    if kind == 'android_backup':
        from trace_app.core.android_backup import open_android_backup
        return open_android_backup(path)
    if kind == 'ufdr':
        from trace_app.core.ufdr import open_ufdr
        return open_ufdr(path)
    opener = {'folder': open_folder, 'zip': open_zip, 'tar': open_tar,
              'l01': open_l01}.get(kind)
    if opener is None:
        raise ValueError(f"Not logical evidence: {path}")
    return opener(path)


class _Members:
    """Whole members kept for the next read, a few at a time."""

    def __init__(self):
        self._kept = collections.OrderedDict()
        self.lock = threading.Lock()

    def get(self, key, load):
        with self.lock:
            data = self._kept.get(key)
            if data is None:
                data = load()
                self._kept[key] = data
                while len(self._kept) > CACHED_MEMBERS:
                    self._kept.popitem(last=False)
            else:
                self._kept.move_to_end(key)
            return data


# --- a folder -------------------------------------------------------------------

def _stat_times(info):
    times = {'mtime': _split(info.st_mtime_ns), 'atime': _split(info.st_atime_ns)}
    birth = getattr(info, 'st_birthtime_ns', None)
    if birth is None and os.name == 'nt':
        # Before 3.12 Windows reports creation as ctime.
        birth = info.st_ctime_ns
    elif os.name != 'nt':
        times['ctime'] = _split(info.st_ctime_ns)
    if birth is not None:
        times['crtime'] = _split(birth)
    return times


def _split(nanoseconds):
    return divmod(int(nanoseconds), 1_000_000_000)


#: Who hears how a folder's walk is going, per thread (the window's opener
#: sets it around ImageHandler; jobs leave it unset).
_WALK_REPORTS = threading.local()


class reporting:
    """with reporting(callback): a folder walked on this thread calls
    callback(entries) as it goes."""

    def __init__(self, callback):
        self.callback = callback

    def __enter__(self):
        _WALK_REPORTS.callback = self.callback
        return self

    def __exit__(self, *_exc):
        _WALK_REPORTS.callback = None


def open_folder(path):
    """A folder of files, read in place, opened read-only per read.

    Its listing (core/folder_listing) is walked once and kept: depth first
    in os.walk's order -- a folder's subfolders (sorted, case-blind), then
    its files, then each subfolder in turn -- because a node's number is
    its place in this walk, and tags, bookmarks and external modules'
    staging manifests in a case point at those numbers."""
    from trace_app.core import folder_listing
    root = os.path.abspath(path)
    listing, kept = folder_listing.listed(
        root, getattr(_WALK_REPORTS, 'callback', None))
    return folder_fs(listing, kept)


def folder_fs(listing, kept=False):
    """The LogicalFileSystem of a folder's Listing; its nodes are made as
    they are asked for (logical.ListedNodes)."""
    from trace_app.core.logical import ListedNodes
    fs = LogicalFileSystem('Folder', listing.root)
    fs.nodes = ListedNodes(listing, lambda inode, offset, length:
                           _read_file(listing.full_path(inode), offset,
                                      length))
    # Every read opens its own handle: readers on several threads at once
    # are safe (core/modules/stage copies so).
    fs.parallel_reads = True
    fs.problems = list(listing.problems)
    fs.listing = listing
    #: Whether the listing was the kept one (the window checks it again in
    #: the background) rather than walked now.
    fs.listing_kept = kept
    fs.facts.update({
        'Format': 'Folder',
        'Path': listing.root,
        'Times': "as the files have them on this disk -- the originals' only "
                 "if the collector preserved them",
        'Listing': f"walked {listing.saved} UTC ({len(listing) - 1:,} "
                   f"entries, {listing.seconds:.0f} s)"
                   + ("; kept and checked again in the background" if kept
                      else "")})
    return fs


def _read_file(full, offset, length):
    with open(full, 'rb') as handle:
        handle.seek(offset)
        return handle.read(length)


#: A Windows reparse point (junction, mount point, symlink): never followed
#: out of the folder. The attribute exists on Windows only.
_REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)


def _reparse_point(info):
    return bool(getattr(info, 'st_file_attributes', 0) & _REPARSE_POINT)


def _file_reader(full):
    def read(offset, length):
        with open(full, 'rb') as handle:
            handle.seek(offset)
            return handle.read(length)
    return read


# --- ZIP --------------------------------------------------------------------------

def open_zip(path):
    handle = open(path, 'rb')
    try:
        archive = zipfile.ZipFile(handle)
    except zipfile.BadZipFile:
        handle.close()
        raise
    fs = LogicalFileSystem('ZIP', path)
    members = _Members()
    fs.facts.update({'Format': 'Cellebrite UFDR (a ZIP: the extracted '
                               'files and report.xml)'
                     if path.lower().endswith('.ufdr') else 'ZIP archive',
                     'Members': f"{len(archive.infolist()):,}",
                     'Times': 'local wall-clock time, no zone (ZIP stores no '
                              'zone)',
                     '_close': lambda: (archive.close(), handle.close())})
    encrypted = 0
    for info in archive.infolist():
        name = info.filename.replace('\\', '/')
        try:
            stamp = _naive_seconds(info.date_time)
        except (ValueError, OverflowError):
            stamp = None
        times = {'mtime': (stamp, 0)} if stamp is not None else {}
        if info.is_dir():
            node = fs.folder(name)
            fs.nodes[node].times = times
            continue
        facts = {}
        if info.flag_bits & 0x1:
            facts['attributes'] = 'encrypted'
            encrypted += 1
        fs.add_file(name, size=info.file_size, times=times, facts=facts,
                    reader=None if info.flag_bits & 0x1 else
                    _zip_reader(archive, info, members))
    if encrypted:
        fs.problems.append(f"{encrypted} encrypted member(s): listed, not "
                           f"read")
    return fs


def _naive_seconds(date_time):
    """A ZIP's (Y, M, D, h, m, s) as seconds, as if it were UTC -- the
    digits as stored; the file system is shown as having no zone."""
    import calendar
    return calendar.timegm(tuple(date_time) + (0, 0, 0))


def _zip_reader(archive, info, members):
    def load():
        with archive.open(info) as member:
            return member.read()

    def read(offset, length):
        if info.file_size <= CACHE_MEMBER:
            data = members.get(info.filename, load)
            return data[offset:offset + length]
        with members.lock, archive.open(info) as member:
            member.seek(offset)
            return member.read(length)
    return read


# --- TAR --------------------------------------------------------------------------

def open_tar(path):
    archive = tarfile.open(path, 'r:*')
    fs = LogicalFileSystem('TAR', path)
    members = _Members()
    fs.facts.update({'Format': 'TAR archive',
                     '_close': archive.close})
    count = 0
    for info in archive:
        count += 1
        name = info.name.lstrip('./') if info.name not in ('.', './') else ''
        if not name:
            continue
        times = {'mtime': (int(info.mtime), 0)} if info.mtime else {}
        if info.isdir():
            fs.nodes[fs.folder(name)].times = times
        elif info.isreg():
            fs.add_file(name, size=info.size, times=times,
                        reader=_tar_reader(archive, info, members))
    fs.facts['Members'] = f"{count:,}"
    return fs


def _tar_reader(archive, info, members):
    def load():
        return archive.extractfile(info).read()

    def read(offset, length):
        if info.size <= CACHE_MEMBER:
            data = members.get(info.name, load)
            return data[offset:offset + length]
        with members.lock:
            member = archive.extractfile(info)
            member.seek(offset)
            return member.read(length)
    return read


# --- EnCase L01 / Lx01 ---------------------------------------------------------

def open_l01(path):
    """An EnCase logical evidence file, through libewf's file entries."""
    import pyewf
    handle = pyewf.handle()
    handle.open(pyewf.glob(os.path.normpath(path)))
    fs = LogicalFileSystem('L01', path)
    lock = threading.Lock()
    facts = {'Format': 'EnCase logical evidence (L01)',
             '_close': handle.close}
    try:
        for key, value in handle.get_header_values().items():
            if value and key in ('case_number', 'description',
                                 'examiner_name', 'evidence_number', 'notes',
                                 'acquiry_software_version',
                                 'acquiry_operating_system'):
                facts[key.replace('_', ' ').capitalize()] = str(value)
    except Exception:
        pass
    fs.facts.update(facts)

    def times(entry):
        out = {}
        for slot, getter in (('mtime', 'get_modification_time_as_integer'),
                             ('atime', 'get_access_time_as_integer'),
                             ('crtime', 'get_creation_time_as_integer'),
                             ('ctime',
                              'get_entry_modification_time_as_integer')):
            try:
                value = int(getattr(entry, getter)())
            except Exception:
                continue
            if value > 0:
                out[slot] = (value, 0)
        return out

    def stored(entry, name):
        try:
            return getattr(entry, name) or None
        except Exception:
            return None

    def reader(entry, size):
        def read(offset, length):
            with lock:
                return entry.read_buffer_at_offset(min(length, size - offset),
                                                   offset)
        return read

    def walk(entry, parent, depth):
        if depth > 256:
            return
        for index in range(entry.number_of_sub_file_entries):
            child = entry.get_sub_file_entry(index)
            name = stored(child, 'name') or f'(entry {index})'
            count = child.number_of_sub_file_entries
            size = int(stored(child, 'size') or 0)
            facts = {k: v for k, v in (('md5', stored(child, 'md5_hash_value')),
                                       ('sha1', stored(child,
                                                       'sha1_hash_value')))
                     if v}
            if count:
                inode = fs.add(parent, name, True, times=times(child))
                walk(child, inode, depth + 1)
            else:
                fs.add(parent, name, False, size=size, times=times(child),
                       facts=facts,
                       reader=reader(child, size) if size else None)

    root = handle.get_root_file_entry()
    walk(root, ROOT, 0)
    return fs

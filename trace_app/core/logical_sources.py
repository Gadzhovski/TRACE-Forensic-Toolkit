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
               'l01': 'L01', 'ios_backup': 'iOS backup'}


def kind_of(path):
    """'folder', 'ios_backup', 'zip', 'tar', 'ad1', 'l01' -- or None for
    anything else (a disk image)."""
    if not path:
        return None
    if path.lower().rstrip('/\\').endswith('.sparsebundle'):
        return None                 # a Mac disk image that is a folder
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
    if lowered.endswith('.zip'):
        return 'zip'
    if lowered.endswith(('.tar', '.tgz', '.tar.gz', '.tar.bz2', '.tbz2',
                         '.tar.xz', '.txz')):
        return 'tar'
    return None


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
                    entry.name.lower().endswith(('.sparsebundle', '.hdd')):
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


def open_folder(path):
    """A folder of files, read in place, opened read-only per read."""
    root = os.path.abspath(path)
    fs = LogicalFileSystem('Folder', root)
    fs.facts.update({
        'Format': 'Folder',
        'Path': root,
        'Times': "as the files have them on this disk -- the originals' only "
                 "if the collector preserved them"})
    inodes = {root: ROOT}
    for folder, names, files in os.walk(root):
        names.sort(key=str.lower)
        parent = inodes.get(folder)
        if parent is None:
            continue
        for name in sorted(names, key=str.lower):
            full = os.path.join(folder, name)
            try:
                info = os.lstat(full)
            except OSError as exc:
                fs.problems.append(f"{full}: {exc}")
                continue
            if stat.S_ISLNK(info.st_mode):
                continue                    # never followed out of the folder
            inodes[full] = fs.add(parent, name, True, times=_stat_times(info))
        for name in sorted(files, key=str.lower):
            full = os.path.join(folder, name)
            try:
                info = os.lstat(full)
            except OSError as exc:
                fs.problems.append(f"{full}: {exc}")
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            fs.add(parent, name, False, size=info.st_size,
                   times=_stat_times(info), reader=_file_reader(full))
    return fs


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
    fs.facts.update({'Format': 'ZIP archive', 'Members': f"{len(archive.infolist()):,}",
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

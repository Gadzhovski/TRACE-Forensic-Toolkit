"""Folder evidence's listing: walked once, kept, and checked.

A disk image is read lazily -- a folder's entries come from the file
system's own structures when the folder is opened. A folder of collected
files has no such structure: TRACE must ask the operating system for every
folder in it, and number the files in walk order (tags, bookmarks and
staging manifests point at those numbers). On Windows that listing is the
cost: 297,250 folders of a Mac collection took 25 s whatever reads them
(os.walk alone; eight threads 21 s -- Windows serialises it), and every
background job opening the evidence paid it again.

So the walk is kept as columns -- names, parents, kinds, sizes, times, and
each folder's children as one range of numbers (the walk numbers a
folder's entries together) -- in `user_data_dir()/folder_listings/`, with
the payload's SHA-256. `LogicalFileSystem` reads them through `ListedNodes`,
which makes a node only when asked for one, so a saved listing of 1.3
million entries opens in about a second, and a fresh walk spends its time
in the operating system rather than building objects.

A saved listing is only trusted as far as is cheap to check at open: the
top folder is listed again and must match. The window then has the whole
folder walked again in the background (`check`): a difference is shown,
audited, and saved *beside* the listing (`.next`) -- taken up when the
window next opens the evidence (`promote`), never during a session, so the
window and the jobs it starts keep one numbering.
"""

import hashlib
import logging
import marshal
import os
import stat
import sys
import time
from array import array
from datetime import datetime, timezone

from trace_app.core.logical import MISSING_TIME, ROOT, TIMES_KEPT, birth_ns

logger = logging.getLogger('TRACE.FolderListing')

#: The walk's rules and this file's layout. Bump when either changes: an
#: older listing is then walked again.
#: 2: creation times on macOS (st_birthtime; version 1 kept none there).
FORMAT = 2
MAGIC = b'TRACE folder listing\0'
#: No such time (the root's, or ctime on Windows).
MISSING = MISSING_TIME
#: Listings not opened for this long are removed when another is saved.
KEEP_DAYS = 90
#: Seconds between progress reports while walking.
REPORT_EVERY = 0.25

#: The attribute exists on Windows only (junctions, mount points...).
_REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
_WINDOWS = os.name == 'nt'
#: Time columns, in the order kept.
TIME_SLOTS = TIMES_KEPT


class ListingError(Exception):
    """A saved listing that cannot be used."""


class Listing:
    """A folder's walk as columns; index = inode - 1 (0 is the root)."""

    def __init__(self, root):
        self.root = root
        self.names = ['']
        self.parents = array('q', [ROOT])
        self.kinds = bytearray(b'\1')            # 1 = folder
        self.sizes = array('q', [0])
        self.times = [array('q', [MISSING]) for _ in TIME_SLOTS]
        #: Each folder's first child and how many: its children are
        #: inodes first .. first + count - 1.
        self.first = array('q', [0])
        self.count = array('q', [0])
        self.problems = []
        self.saved = ''
        self.seconds = 0.0

    def __len__(self):
        return len(self.names)

    def path(self, inode):
        """'/a/b/c' of node `inode`."""
        parts = []
        names, parents = self.names, self.parents
        while inode != ROOT:
            parts.append(names[inode - 1])
            inode = parents[inode - 1]
        return '/' + '/'.join(reversed(parts))

    def full_path(self, inode):
        """Where node `inode` is on this computer."""
        parts = []
        names, parents = self.names, self.parents
        while inode != ROOT:
            parts.append(names[inode - 1])
            inode = parents[inode - 1]
        return os.path.join(self.root, *reversed(parts))

    def all_paths(self):
        """Every node's path, by index (a parent is listed before its
        children, so one pass builds them)."""
        paths = ['']
        names, parents = self.names, self.parents
        for index in range(1, len(names)):
            paths.append(f"{paths[parents[index] - 1]}/{names[index]}")
        return paths


# --- the walk ------------------------------------------------------------------

def _level(folder):
    """A folder's entries as the walk takes them: (folders, files), each
    [(name, path, stat)] sorted case-blind; links and reparse points
    dropped (never followed out of the folder), only regular files.
    Raises OSError when the folder cannot be listed; per-entry problems
    are returned as the third value."""
    with os.scandir(folder) as listing:
        entries = list(listing)
    folders, files, problems = [], [], []
    for entry in entries:
        try:
            is_dir = entry.is_dir()         # os.walk's test (follows links)
        except OSError:
            is_dir = False
        (folders if is_dir else files).append(entry)
    kept_folders, kept_files = [], []
    for entry in sorted(folders, key=lambda e: e.name.lower()):
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            problems.append(f"{entry.path}: {exc}")
            continue
        if stat.S_ISLNK(info.st_mode) or \
                getattr(info, 'st_file_attributes', 0) & _REPARSE_POINT:
            continue
        kept_folders.append((entry.name, entry.path, info))
    for entry in sorted(files, key=lambda e: e.name.lower()):
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            problems.append(f"{entry.path}: {exc}")
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        kept_files.append((entry.name, entry.path, info))
    return kept_folders, kept_files, problems


def _times(info):
    """(mtime, atime, ctime, crtime) in ns, as TRACE has always read a
    folder's files: creation is st_birthtime_ns, or on Windows before 3.12
    st_ctime_ns; ctime (inode change) is kept off Windows only."""
    birth = birth_ns(info)
    if birth is None and _WINDOWS:
        birth = info.st_ctime_ns
    ctime = MISSING if _WINDOWS else info.st_ctime_ns
    return (info.st_mtime_ns, info.st_atime_ns, ctime,
            MISSING if birth is None else int(birth))


def walk(root, report=None, should_stop=None):
    """List `root` depth first in os.walk's order -- a folder's subfolders
    (sorted, case-blind), then its files, then each subfolder in turn --
    and return the Listing. `report(entries)` is called now and then."""
    started = time.monotonic()
    listing = Listing(root)
    names, parents, kinds, sizes = (listing.names, listing.parents,
                                    listing.kinds, listing.sizes)
    mtimes, atimes, ctimes, crtimes = listing.times
    first, count = listing.first, listing.count
    reported = started

    def add(name, parent, kind, size, info):
        names.append(name)
        parents.append(parent)
        kinds.append(kind)
        sizes.append(size)
        mtime, atime, ctime, crtime = _times(info)
        mtimes.append(mtime)
        atimes.append(atime)
        ctimes.append(ctime)
        crtimes.append(crtime)
        first.append(0)
        count.append(0)
        return len(names)

    stack = [(root, ROOT)]
    while stack:
        if should_stop is not None and should_stop():
            raise InterruptedError("Walk cancelled")
        folder, parent = stack.pop()
        try:
            folders, files, problems = _level(folder)
        except OSError as exc:
            if folder != root:
                listing.problems.append(f"{folder}: {exc}")
            continue
        listing.problems += problems
        start = len(names) + 1
        below = [(path, add(name, parent, 1, 0, info))
                 for name, path, info in folders]
        for name, _path, info in files:
            add(name, parent, 0, info.st_size, info)
        if len(names) + 1 > start:
            first[parent - 1] = start
            count[parent - 1] = len(names) + 1 - start
        # Last pushed is walked first: reversed, so the first subfolder is.
        stack.extend(reversed(below))
        if report is not None:
            now = time.monotonic()
            if now - reported >= REPORT_EVERY:
                reported = now
                report(len(names) - 1)
    listing.seconds = time.monotonic() - started
    listing.saved = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    return listing


# --- kept on disk ----------------------------------------------------------------

def listings_dir():
    from trace_app.infra.paths import user_data_dir
    return os.path.join(user_data_dir(), 'folder_listings')


def _key(root):
    return os.path.normcase(os.path.abspath(root))


def listing_file(root):
    digest = hashlib.sha256(
        _key(root).encode('utf-8', 'surrogatepass')).hexdigest()[:40]
    return os.path.join(listings_dir(), f"{digest}.listing")


def pending_file(root):
    return listing_file(root) + '.next'


def _encode(listing):
    body = marshal.dumps({
        'root': _key(listing.root), 'saved': listing.saved,
        'seconds': listing.seconds, 'problems': listing.problems,
        'names': listing.names, 'parents': listing.parents.tobytes(),
        'kinds': bytes(listing.kinds), 'sizes': listing.sizes.tobytes(),
        'times': [column.tobytes() for column in listing.times],
        'first': listing.first.tobytes(), 'count': listing.count.tobytes(),
        'byteorder': sys.byteorder})
    return (MAGIC + FORMAT.to_bytes(4, 'little')
            + hashlib.sha256(body).digest() + body)


def _column(raw, byteorder):
    column = array('q')
    column.frombytes(raw)
    if byteorder != sys.byteorder:
        column.byteswap()
    return column


def _decode(data, root):
    head = len(MAGIC)
    if not data.startswith(MAGIC) or \
            int.from_bytes(data[head:head + 4], 'little') != FORMAT:
        raise ListingError("an older or foreign listing")
    view = memoryview(data)[head + 36:]
    if hashlib.sha256(view).digest() != data[head + 4:head + 36]:
        raise ListingError("its checksum does not match")
    try:
        fields = marshal.loads(view)
    except (ValueError, EOFError, TypeError) as exc:
        raise ListingError(f"unreadable: {exc}") from exc
    if fields.get('root') != _key(root):
        raise ListingError("it lists another folder")
    order = fields['byteorder']
    listing = Listing(root)
    listing.names = fields['names']
    listing.parents = _column(fields['parents'], order)
    listing.kinds = bytearray(fields['kinds'])
    listing.sizes = _column(fields['sizes'], order)
    listing.times = [_column(raw, order) for raw in fields['times']]
    listing.first = _column(fields['first'], order)
    listing.count = _column(fields['count'], order)
    listing.problems = list(fields['problems'])
    listing.saved = fields['saved']
    listing.seconds = fields['seconds']
    if not (len(listing.names) == len(listing.parents) == len(listing.kinds)
            == len(listing.sizes) == len(listing.first)
            == len(listing.count)) or \
            any(len(column) != len(listing.names)
                for column in listing.times):
        raise ListingError("its columns disagree")
    return listing


def save(listing, target=None):
    """Write `listing` (to its listing file, or `target`) whole or not at
    all. Returns the file, or None when it could not be written."""
    target = target or listing_file(listing.root)
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        partial = f"{target}.{os.getpid()}.partial"
        with open(partial, 'wb') as handle:
            handle.write(_encode(listing))
        os.replace(partial, target)
    except OSError as exc:
        logger.warning("Folder listing not saved (%s): %s", target, exc)
        return None
    _forget_old(target)
    return target


def _forget_old(keep):
    cutoff = time.time() - KEEP_DAYS * 86400
    try:
        entries = list(os.scandir(os.path.dirname(keep)))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.path != keep and entry.stat().st_mtime < cutoff:
                os.remove(entry.path)
        except OSError:
            pass


def read(path, root):
    """The Listing kept at `path`; ListingError if unusable."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError as exc:
        raise ListingError(str(exc)) from exc
    return _decode(data, root)


def _top_agrees(listing):
    """Whether the folder's top level still is what the listing says --
    names, kinds, files' sizes and modified times. One listing of one
    folder: cheap, and it catches a folder replaced or re-collected."""
    try:
        folders, files, _problems = _level(listing.root)
    except OSError:
        return False
    first, count = listing.first[0], listing.count[0]
    saved = [(listing.names[i - 1], listing.kinds[i - 1],
              listing.sizes[i - 1] if not listing.kinds[i - 1] else 0,
              listing.times[0][i - 1] if not listing.kinds[i - 1] else 0)
             for i in range(first, first + count)] if count else []
    now = [(name, 1, 0, 0) for name, _path, _info in folders] + \
        [(name, 0, info.st_size, info.st_mtime_ns)
         for name, _path, info in files]
    return saved == now


def load(root):
    """The kept listing of `root` if it is usable and its top level still
    agrees, else None."""
    path = listing_file(root)
    if not os.path.exists(path):
        return None
    try:
        listing = read(path, root)
    except ListingError as exc:
        logger.info("Folder listing of %s walked again: %s", root, exc)
        return None
    if not _top_agrees(listing):
        logger.info("Folder listing of %s walked again: its top folder "
                    "changed", root)
        return None
    try:
        os.utime(path)                      # used: kept from _forget_old
    except OSError:
        pass
    return listing


def promote(root):
    """A newer listing a background check left beside the kept one
    becomes the kept one -- for the window, at opening the evidence."""
    pending = pending_file(root)
    if os.path.exists(pending):
        try:
            os.replace(pending, listing_file(root))
            logger.info("Folder listing of %s: the newer walk taken up",
                        root)
        except OSError as exc:
            logger.warning("Newer folder listing of %s not taken up: %s",
                           root, exc)


def listed(root, report=None):
    """The listing of `root`: the kept one, else a fresh walk (then kept).
    Returns (listing, from_kept)."""
    listing = load(root)
    if listing is not None:
        return listing, True
    listing = walk(root, report)
    save(listing)
    return listing, False


# --- the background check --------------------------------------------------------

#: Times compared by the check. Access times are not: reading a file to
#: preview or analyse it moves its access time on many systems.
_COMPARED = (0, 2, 3)


def differences(old, new, examples=20):
    """{'added', 'removed', 'changed': counts, 'examples': [text]} between
    two listings of one folder, by path."""
    # A folder is compared by being there: its times move only with its
    # contents, which are compared themselves -- and Windows' listing gives
    # a folder's times from its parent's index, updated lazily, so they
    # differed between two walks seconds apart with nothing changed.
    def entries(listing):
        paths = listing.all_paths()
        kinds, sizes, times = listing.kinds, listing.sizes, listing.times
        return {paths[i]: (1,) if kinds[i] == 1 else
                (0, sizes[i], *(times[slot][i] for slot in _COMPARED))
                for i in range(1, len(paths))}
    before, after = entries(old), entries(new)
    added = [p for p in after if p not in before]
    removed = [p for p in before if p not in after]
    changed = [p for p, value in after.items()
               if p in before and before[p] != value]
    shown = ([f"added: {p}" for p in added[:examples]]
             + [f"removed: {p}" for p in removed[:examples]]
             + [f"changed: {p}" for p in changed[:examples]])
    return {'added': len(added), 'removed': len(removed),
            'changed': len(changed), 'examples': shown[:examples]}


def check(root, report=None, should_stop=None):
    """Walk `root` again and compare it with the kept listing. A
    difference is saved beside the kept listing (`promote` takes it up at
    the next opening). Returns differences() plus 'checked' (entries) and
    'saved' (when the kept listing was made); None when there is no kept
    listing to check."""
    try:
        kept = read(listing_file(root), root)
    except ListingError:
        return None
    fresh = walk(root, report, should_stop)
    found = differences(kept, fresh)
    found['checked'] = len(fresh) - 1
    found['saved'] = kept.saved
    if found['added'] or found['removed'] or found['changed']:
        save(fresh, pending_file(root))
    return found

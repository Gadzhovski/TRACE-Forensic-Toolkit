"""What a run covers: folders in or out, file types, sizes, dates, deleted
files (no Qt).

An image holds far more than an investigation needs. On a Linux install
most files are the operating system's own -- libraries, kernel modules,
package caches -- and analysing and indexing them is most of a run's time.
A Scope lets the examiner say what to read; the analysis, the search index,
YARA and the deleted-file assessment then skip the rest, pruning a folder
before anything under it is read. Whatever a run left out is stated in the
case's audit trail and the report: an examiner must be able to say what
was not examined.

Rules name folders (or files) by path, one of three ways:

    ~/usr            at the top of the system's own tree, wherever that is:
                     '/' on a Windows volume or a plain Linux disk, '/root'
                     in Fedora's Btrfs layout, 'C' in a KAPE collection
    /home/alex       at the root of the volume
    node_modules     any folder of that name, anywhere

with * and ? as wildcards in any part ('~/Users/*/AppData/Local/Temp').
Matching ignores case: Windows names do, and an examiner typing 'users'
means 'Users'. A rule names a folder and everything in it.

Presets (PRESETS) are starting points; anything can be edited from them.
"""

import fnmatch
import json
import logging
from datetime import datetime, timezone

import pytsk3

from trace_app.core.tsk_names import entry_name

logger = logging.getLogger('TRACE.Scope')

#: How deleted files are treated.
DELETED_INCLUDE, DELETED_EXCLUDE, DELETED_ONLY = 'include', 'exclude', 'only'

#: File types by extension (lower case, with the dot). An executable on
#: Linux often has no extension: a type filter is for "only these", and
#: says so in the editor.
TYPE_GROUPS = {
    'documents': ('Documents', (
        '.doc', '.docx', '.docm', '.dot', '.dotx', '.odt', '.ott', '.rtf',
        '.txt', '.md', '.pdf', '.xls', '.xlsx', '.xlsm', '.ods', '.csv',
        '.ppt', '.pptx', '.pptm', '.odp', '.key', '.pages', '.numbers',
        '.epub', '.mobi', '.xps', '.html', '.htm', '.xml', '.json')),
    'pictures': ('Pictures', (
        '.jpg', '.jpeg', '.jpe', '.png', '.gif', '.bmp', '.tif', '.tiff',
        '.webp', '.heic', '.heif', '.avif', '.psd', '.svg', '.ico', '.raw',
        '.cr2', '.cr3', '.nef', '.arw', '.dng', '.orf', '.rw2', '.raf')),
    'video': ('Video and audio', (
        '.mp4', '.m4v', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm',
        '.mpg', '.mpeg', '.3gp', '.mp3', '.m4a', '.wav', '.ogg', '.opus',
        '.flac', '.aac', '.amr')),
    'mail': ('Mail and chat', (
        '.pst', '.ost', '.msg', '.eml', '.mbox', '.emlx', '.olm', '.dbx')),
    'archives': ('Archives', (
        '.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.cab',
        '.iso', '.dmg', '.jar', '.apk')),
    'executables': ('Programs and scripts', (
        '.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.msi', '.com',
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.lnk', '.so', '.ko',
        '.elf', '.bin', '.sh', '.py', '.pl', '.app', '.dylib', '.deb',
        '.rpm')),
    'databases': ('Databases', (
        '.db', '.sqlite', '.sqlite3', '.sqlitedb', '.edb', '.mdb', '.accdb',
        '.dat', '.plist', '.realm')),
    'logs': ('Logs and event logs', (
        '.log', '.evtx', '.evt', '.etl', '.journal')),
}

#: Folders an operating system owns, by system.
_LINUX_SYSTEM = ('~/usr', '~/lib', '~/lib32', '~/lib64', '~/libx32',
                 '~/bin', '~/sbin', '~/boot', '~/proc', '~/sys', '~/dev',
                 '~/run', '~/snap', '~/var/lib/rpm', '~/var/lib/dpkg',
                 '~/var/lib/flatpak', '~/var/lib/snapd', '~/var/cache/dnf',
                 '~/var/cache/apt', '~/var/cache/PackageKit',
                 '~/var/cache/libdnf5', '~/var/lib/containers/storage/overlay')
_WINDOWS_SYSTEM = ('~/Windows/WinSxS', '~/Windows/Installer',
                   '~/Windows/assembly', '~/Windows/servicing',
                   '~/Windows/SoftwareDistribution',
                   '~/Windows/Microsoft.NET', '~/Windows/Fonts',
                   '~/Windows/InfusedApps', '~/Windows/SystemApps')
_MACOS_SYSTEM = ('~/System', '~/Library/Apple', '~/usr/lib', '~/usr/share',
                 '~/usr/libexec', '~/bin', '~/sbin',
                 '~/Library/Developer/CommandLineTools')
#: Where people's own files are, by system.
_USER_FOLDERS = ('~/home', '~/root', '~/Users', '~/Documents and Settings',
                 '~/tmp', '~/var/tmp', '~/private/tmp', '~/var/mail',
                 '~/var/spool/mail', '~/private/var/mobile',
                 '~/data/data', '~/data/media')

#: Built-in starting points: key -> (label, description, rules).
PRESETS = {
    'everything': ('Everything', "Every file on the evidence.", {}),
    'user': ('User data only', "People's own folders: home and user "
             "profile folders, temporary folders and mail spools, on "
             "Windows, macOS, Linux, iPhone and Android.",
             {'include': list(_USER_FOLDERS)}),
    'no_system': ('Skip operating-system files', "Everything except the "
                  "folders an operating system owns: Linux /usr, /lib, "
                  "/boot and package caches; Windows WinSxS, Installer and "
                  "the .NET and font stores; macOS /System. Windows' "
                  "System32 is kept (persistence and logs live there).",
                  {'exclude': list(_LINUX_SYSTEM + _WINDOWS_SYSTEM
                                   + _MACOS_SYSTEM)}),
    'documents': ('Documents and pictures', "Documents, pictures, mail "
                  "and archives in people's own folders.",
                  {'include': list(_USER_FOLDERS),
                   'types': ['documents', 'pictures', 'mail', 'archives']}),
}
CUSTOM = 'custom'


def _split(path):
    return [part for part in path.replace('\\', '/').split('/') if part]


def _fold(part):
    return part.casefold()


class Scope:
    """A run's rules. Empty rules (the default) mean everything."""

    def __init__(self, preset='everything', include=(), exclude=(),
                 exclude_names=(), types=(), min_size=None, max_size=None,
                 modified_after=None, modified_before=None,
                 deleted=DELETED_INCLUDE):
        self.preset = preset
        self.include = [r for r in include if r and r.strip()]
        self.exclude = [r for r in exclude if r and r.strip()]
        self.exclude_names = [r for r in exclude_names if r and r.strip()]
        self.types = [t for t in types if t in TYPE_GROUPS]
        self.min_size = min_size
        self.max_size = max_size
        self.modified_after = modified_after      # 'YYYY-MM-DD', UTC
        self.modified_before = modified_before    # 'YYYY-MM-DD', inclusive
        self.deleted = deleted

    # --- making and keeping ---------------------------------------------------

    @classmethod
    def preset_scope(cls, key):
        """A Scope from a built-in preset."""
        _label, _about, rules = PRESETS.get(key, PRESETS['everything'])
        return cls(preset=key if key in PRESETS else 'everything',
                   **json.loads(json.dumps(rules)))

    @classmethod
    def from_dict(cls, value):
        """From to_dict()'s shape; None, {} or garbage mean everything."""
        if isinstance(value, Scope):
            return value
        if not isinstance(value, dict):
            return cls()
        known = ('preset', 'include', 'exclude', 'exclude_names', 'types',
                 'min_size', 'max_size', 'modified_after', 'modified_before',
                 'deleted')
        return cls(**{k: value[k] for k in known if k in value})

    def to_dict(self):
        return {'preset': self.preset, 'include': list(self.include),
                'exclude': list(self.exclude),
                'exclude_names': list(self.exclude_names),
                'types': list(self.types), 'min_size': self.min_size,
                'max_size': self.max_size,
                'modified_after': self.modified_after,
                'modified_before': self.modified_before,
                'deleted': self.deleted}

    @property
    def everything(self):
        """Whether nothing is left out."""
        return not (self.include or self.exclude or self.exclude_names
                    or self.types or self.min_size or self.max_size
                    or self.modified_after or self.modified_before
                    or self.deleted != DELETED_INCLUDE)

    @property
    def covers_free_space(self):
        """Whether unallocated space and file slack are in scope. They
        belong to no folder and no file type: a run narrowed to some
        folders, some types or deleted files only leaves them out; one
        that only leaves folders out keeps them."""
        return not (self.include or self.types
                    or self.deleted == DELETED_ONLY)

    @property
    def label(self):
        if self.preset in PRESETS:
            return PRESETS[self.preset][0]
        return 'Custom'

    def describe(self, short=False):
        """The rules in words, for the audit trail and the report --
        `short`: folder rules counted, past a few, for a dialog line (the
        whole text is its tooltip)."""
        if self.everything:
            return "Everything (no files left out)."

        def folders(rules):
            if short and len(rules) > 4:
                return '; '.join(rules[:3]) + f" and {len(rules) - 3} more"
            return '; '.join(rules)
        parts = [f"{self.label}:"]
        if self.include:
            parts.append("only in " + folders(self.include))
        if self.exclude:
            parts.append("leaving out " + folders(self.exclude))
        if self.exclude_names:
            parts.append("files named " + '; '.join(self.exclude_names)
                         + " left out")
        if self.types:
            parts.append("only " + ', '.join(
                TYPE_GROUPS[t][0].lower() for t in self.types))
        if self.min_size:
            parts.append(f"at least {self.min_size:,} bytes")
        if self.max_size:
            parts.append(f"at most {self.max_size:,} bytes")
        if self.modified_after:
            parts.append(f"modified on or after {self.modified_after}")
        if self.modified_before:
            parts.append(f"modified on or before {self.modified_before}")
        if self.deleted == DELETED_EXCLUDE:
            parts.append("deleted files left out")
        elif self.deleted == DELETED_ONLY:
            parts.append("deleted files only")
        if not self.covers_free_space:
            parts.append("unallocated space and file slack not searched")
        return ' '.join(parts[:1]) + ' ' + '; '.join(parts[1:]) + '.'

    # --- matching --------------------------------------------------------------

    def matcher(self, fs=None, roots=None):
        """A Matcher for one volume, or None when nothing is left out.
        `roots`: the volume's system roots (found from `fs` if not given)."""
        if self.everything:
            return None
        if roots is None:
            roots = system_roots(fs) if fs is not None else ['/']
        return Matcher(self, roots)


class _Rule:
    """One path rule, ready to match."""

    def __init__(self, text, roots):
        text = text.strip()
        self.text = text
        if text.startswith('~'):
            tail = _split(text[1:])
            prefixes = []
            for root in roots:
                candidate = _split(root) + tail
                # A user-data rule never takes in a whole system tree:
                # '~/root' at the volume root of Fedora's Btrfs is the
                # 'root' subvolume, the system itself.
                if '/' + '/'.join(candidate) in roots and \
                        '/' + '/'.join(candidate) != '/':
                    continue
                prefixes.append(candidate)
            self.anchored = [[_fold(p) for p in c] for c in prefixes]
            self.anywhere = None
        elif text.startswith('/') or text.startswith('\\'):
            self.anchored = [[_fold(p) for p in _split(text)]]
            self.anywhere = None
        else:
            self.anchored = []
            self.anywhere = [_fold(p) for p in _split(text)]

    def covers(self, parts):
        """Whether the path (folded parts) is this rule's folder or in it."""
        for pattern in self.anchored:
            if len(parts) >= len(pattern) and all(
                    fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pattern)):
                return True
        if self.anywhere:
            n = len(self.anywhere)
            for start in range(0, len(parts) - n + 1):
                if all(fnmatch.fnmatchcase(p, q) for p, q in
                       zip(parts[start:start + n], self.anywhere)):
                    return True
        return False

    def leads_to(self, parts):
        """Whether the folder (folded parts) is on the way to this rule's
        folder -- so a walk must go into it to reach it."""
        if self.anywhere:
            return True
        for pattern in self.anchored:
            if len(parts) < len(pattern) and all(
                    fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pattern)):
                return True
        return False


class Matcher:
    """A Scope applied to one volume's paths ('/home/alex/a.txt', as the
    walks build them)."""

    def __init__(self, scope, roots):
        self.scope = scope
        self.roots = list(roots)
        self.include = [_Rule(r, self.roots) for r in scope.include]
        self.exclude = [_Rule(r, self.roots) for r in scope.exclude]
        self.names = [_fold(n) for n in scope.exclude_names]
        self.extensions = tuple(
            ext for key in scope.types for ext in TYPE_GROUPS[key][1])
        self.after = _day_start(scope.modified_after)
        self.before = _day_end(scope.modified_before)

    def skips_folder(self, path):
        """Whether nothing in this folder can be in scope: the walk need
        not go into it."""
        parts = [_fold(p) for p in _split(path)]
        if any(rule.covers(parts) for rule in self.exclude):
            return True
        if self.include and not any(rule.covers(parts) or rule.leads_to(parts)
                                    for rule in self.include):
            return True
        return False

    def skips_path(self, path):
        """Whether a file at `path` is outside the folders in scope (its
        name, type, size and dates aside)."""
        parts = [_fold(p) for p in _split(path)]
        if any(rule.covers(parts) for rule in self.exclude):
            return True
        if self.include and not any(rule.covers(parts)
                                    for rule in self.include):
            return True
        return False

    def skips_file(self, path, size=None, mtime=None, deleted=False):
        """Whether the file at `path` is out of scope. `mtime`: seconds
        since 1970 (UTC), or None when unknown (then dates do not rule it
        out)."""
        scope = self.scope
        if scope.deleted == DELETED_EXCLUDE and deleted:
            return True
        if scope.deleted == DELETED_ONLY and not deleted:
            return True
        if self.skips_path(path):
            return True
        name = _fold(_split(path)[-1]) if _split(path) else ''
        if self.names and any(fnmatch.fnmatchcase(name, n)
                              for n in self.names):
            return True
        if self.extensions and not name.endswith(self.extensions):
            return True
        if size is not None:
            if scope.min_size and size < scope.min_size:
                return True
            if scope.max_size and size > scope.max_size:
                return True
        if mtime:
            if self.after is not None and mtime < self.after:
                return True
            if self.before is not None and mtime > self.before:
                return True
        return False


def _day_start(text):
    if not text:
        return None
    try:
        day = datetime.strptime(text[:10], '%Y-%m-%d')
    except ValueError:
        return None
    return day.replace(tzinfo=timezone.utc).timestamp()


def _day_end(text):
    start = _day_start(text)
    return None if start is None else start + 86400 - 1e-6


def system_roots(fs):
    """Folders of a volume that are the top of a system's own tree: '/' for
    a plain system volume, '/root' (a Btrfs subvolume) on Fedora, 'C' in a
    KAPE collection. ['/'] when none is found. Read two levels down, by
    marker folders (core/logical.py's)."""
    from trace_app.core import logical
    if isinstance(fs, logical.LogicalFileSystem):
        return logical.system_roots(fs)
    found = []

    def names(path):
        try:
            directory = fs.open_dir(path=path)
        except Exception:
            return None
        out = {}
        for entry in directory:
            info = entry.info
            if info.name is None or info.meta is None:
                continue
            name = info.name.name.decode('utf-8', 'replace')
            if name in ('.', '..'):
                continue
            out[name] = info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        return out

    def is_system(children):
        lowered = {n.lower() for n in children}
        return bool(lowered & logical._WINDOWS_MARKERS) or any(
            len(lowered & markers) >= 2 for markers in logical._UNIX_MARKERS)

    top = names('/') or {}
    if is_system(top):
        found.append('/')
    for name, is_dir in sorted(top.items()):
        if not is_dir:
            continue
        below = names('/' + name)
        if below and is_system(below):
            found.append('/' + name)
    return found or ['/']


def setting_value(case):
    """The case's last scope (Scope), everything when none is kept."""
    if case is None:
        return Scope()
    try:
        return Scope.from_dict(case.setting('scope'))
    except Exception as exc:
        logger.debug("No scope kept: %s", exc)
        return Scope()


def from_params(params):
    """The Scope a background job was handed (params['scope'])."""
    return Scope.from_dict((params or {}).get('scope'))


def entry_skipped(matcher, path, meta):
    """Whether a TSK entry (a folder: its whole subtree) is outside the
    matcher's scope. None matcher: nothing is."""
    if matcher is None:
        return False
    if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
        return matcher.skips_folder(path)
    return matcher.skips_file(
        path, int(meta.size or 0), file_time(meta),
        not (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC))


def file_time(meta):
    """A TSK meta's modified time in seconds (None when not recorded)."""
    try:
        value = int(getattr(meta, 'mtime', 0) or 0)
    except (TypeError, ValueError):
        return None
    return value or None


# --- what a scope leaves: counted, for the editor's estimate ------------------

class Cancelled(Exception):
    """The count was asked to stop."""


def listing(image_handler, should_stop=None, progress=None):
    """Every folder and file of an image as the analysis walk sees them,
    per volume: [{'offset', 'roots', 'folders': [path],
    'files': [(folder, name, size, mtime, deleted)]}]. Read once, kept by
    the caller, and counted against any scope by count() -- the same walk,
    the same files, the analysis and the index count."""
    from trace_app.core.walk import volume_offsets
    out, seen = [], [0]
    for offset in volume_offsets(image_handler):
        fs = image_handler.get_fs_info(offset)
        if fs is None:
            continue
        volume = {'offset': offset, 'roots': system_roots(fs),
                  'folders': [], 'files': []}
        visited = set()

        def walk(directory, path, depth):
            if depth > 64:
                return
            for entry in directory:
                if should_stop is not None and should_stop():
                    raise Cancelled()
                info = entry.info
                if info.name is None or info.meta is None:
                    continue
                # Named as the analysis walk names it (core/walk.py).
                name = entry_name(entry, fs)
                if name in ('.', '..'):
                    continue
                meta = info.meta
                if meta.addr in visited:
                    continue
                visited.add(meta.addr)
                child = f"{path}/{name}"
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    volume['folders'].append(child)
                    seen[0] += 1
                    if progress is not None and seen[0] % 200 == 0:
                        progress(seen[0], child)
                    try:
                        walk(entry.as_directory(), child, depth + 1)
                    except Cancelled:
                        raise
                    except Exception:
                        continue
                elif meta.size:
                    volume['files'].append((
                        path, name, int(meta.size), file_time(meta),
                        not (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC)))

        try:
            walk(fs.open_dir(path='/'), '', 0)
        except Cancelled:
            raise
        except Exception as exc:
            logger.debug("Volume at %s not listed: %s", offset, exc)
        out.append(volume)
    return out


def count(volumes, scope, should_stop=None):
    """(files in scope, files) of a listing(): a file counts when no folder
    above it is skipped and it is not skipped itself -- what the walks do.
    Folders are judged once each."""
    scope = Scope.from_dict(scope)
    kept = total = 0
    for volume in volumes:
        total += len(volume['files'])
        matcher = scope.matcher(roots=volume['roots'])
        if matcher is None:
            kept += len(volume['files'])
            continue
        skipped = {'': False}

        def folder_skipped(path):
            # A folder is out when it, or any folder above it, is.
            if path in skipped:
                return skipped[path]
            parent = path.rsplit('/', 1)[0]
            out = folder_skipped(parent) or matcher.skips_folder(path)
            skipped[path] = out
            return out

        for number, (folder, name, size, mtime, deleted) in \
                enumerate(volume['files']):
            if should_stop is not None and number % 4096 == 0 and \
                    should_stop():
                raise Cancelled()
            if folder_skipped(folder):
                continue
            if not matcher.skips_file(f"{folder}/{name}", size, mtime,
                                      deleted):
                kept += 1
    return kept, total

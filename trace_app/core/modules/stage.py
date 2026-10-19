"""Staging: the files a tool looks for, copied out of the evidence (no Qt).

A LEAPP reads a folder (`-t fs`). TRACE gives it one made of exactly the
files it would look for, taken from any evidence TRACE opens -- E01, AFF4,
an unlocked iOS backup, an Android backup, a UFDR, a folder -- so the tool
reads what TRACE reads, and every row it reports leads back to a file on the
evidence through the manifest.

* The patterns are the tool's own: `<program> -p` writes path_list.txt
  (globs like '**/Library/SMS/sms.db*'), cached beside the installed copy.
  A LEAPP matches them with fnmatch on full paths -- '*' crosses '/' -- and
  case-insensitively on Windows only. TRACE matches the same way but always
  ignoring case: a file staged and not used costs a copy, a file not
  staged loses an artifact.
* Matching ~1,000 globs against every file one by one is slow (52 s for
  100,000 paths), so `Matcher` indexes each glob by one of its literal
  segments -- a segment with no wildcard sits between slashes, so a path
  can only match if it has that whole segment -- and tests only the globs
  its segments call up; the few with no literal segment are one combined
  expression. Same answers, 10-35 times faster.
* Live files only: a deleted file's clusters may hold another file now.
* Copies are made by evidence_export.write_verified (hashed as written,
  read back) into `<run>/input/[<volume>/]<path>`; `staging-manifest.csv`
  maps each staged path to its evidence, path, artifact_ref and hashes.
* Free space is checked first: the copies, and the tool's own copies of
  what it parses (report/data), need about twice the matched size.
"""

import concurrent.futures
import csv
import fnmatch
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections import defaultdict

from trace_app.core import evidence_export

logger = logging.getLogger('TRACE.Modules')

MANIFEST = 'staging-manifest.csv'
MANIFEST_COLUMNS = ['staged_path', 'evidence_id', 'evidence', 'volume',
                    'source_path', 'artifact_ref', 'size', 'md5', 'sha1',
                    'sha256', 'written_copy_check', 'problem']
PATH_LIST = 'trace-path-list.txt'
#: Room asked for beyond the copies: the tool's own copies and report.
SPACE_FACTOR = 2.2
SPACE_MARGIN = 200 * 1024 * 1024
#: Copies made at once from folder evidence (whose reads are independent).
COPY_THREADS = 8
_WILD = set('*?[')
_ONE_LETTER = re.compile(r'\[([^!\]])\1*\]')
_LITERALS = re.compile(r'\[!?\]?[^\]]*\]|[*?]')
#: Folders whose candidate globs a Matcher keeps at once.
FOLDER_CACHE = 50_000


class StageError(Exception):
    pass


class StageCancelled(Exception):
    pass


def path_patterns(spec, record):
    """The tool's globs (`-p`), cached beside its installed copy."""
    cached = os.path.join(record['folder'], PATH_LIST)
    if os.path.isfile(cached):
        with open(cached, encoding='utf-8') as handle:
            return [line.rstrip('\n') for line in handle if line.strip()]
    from trace_app.core.modules.run import _group_kwargs, clean_environment
    work = tempfile.mkdtemp(prefix='trace-paths-')
    try:
        done = subprocess.run(
            [record['executable'], '-p'], cwd=work, env=clean_environment(),
            capture_output=True, timeout=600, stdin=subprocess.DEVNULL,
            **_group_kwargs())
        listed = os.path.join(work, 'path_list.txt')
        if done.returncode != 0 or not os.path.isfile(listed):
            raise StageError(f"{spec.name} did not list the paths it reads "
                             f"(exit {done.returncode}).")
        with open(listed, encoding='utf-8', errors='replace') as handle:
            patterns = sorted({line.strip() for line in handle
                               if line.strip()})
    except subprocess.TimeoutExpired as exc:
        raise StageError(f"{spec.name} took too long listing its paths.") \
            from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(cached, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(patterns) + '\n')
    return patterns


class Matcher:
    """Whether a path is one a tool's globs name (see the module).

    Each glob is tried only on the paths that could match it, found by
    its file name: a literal one ('sms.db'), one ending with a literal
    ('*.plist', by its last two letters), or starting with one ('AP.db*',
    by the first two of any part: '*' crosses '/', as LEAPP's fnmatch
    does); a glob whose name says nothing ('*') by its longest
    literal folder, as before ('Library'), else on every path; and only
    where its longest literal text is in the path. Grouped by folder
    alone, iLEAPP's globs took 113 s over a Mac folder's million files,
    9 s now; the answers are the same (the full glob decides, always)."""

    def __init__(self, patterns):
        self.names = defaultdict(list)       # file name -> globs
        self.starts = defaultdict(list)      # name's first two -> globs
        self.ends = defaultdict(list)        # name's last two -> globs
        self.by_segment = defaultdict(list)  # folder name -> globs
        self.loose = []
        for pattern in patterns:
            low = pattern.strip().lower().replace('\\', '/')
            if not low:
                continue
            # '[Nn]' lower-cased is '[nn]': one letter, which the
            # indexes below can then use ('ntuser.dat').
            low = _ONE_LETTER.sub(r'\1', low)
            # Each glob is (start of its name, end of its name, the
            # longest text it must contain, the glob): the cheap tests
            # first, the full glob last.
            name = low.rsplit('/', 1)[-1]
            head = re.split(r'[*?\[]', name, maxsplit=1)[0]
            tail = re.split(r'[*?\]]', name)[-1]
            if '[' in tail:
                tail = ''
            needle = max(_LITERALS.split(low), key=len)
            entry = (head, tail, needle,
                     re.compile(fnmatch.translate(low)).match)
            if name and not set(name) & _WILD:
                self.names[name].append(entry)
            elif len(head) >= 2:
                self.starts[head[:2]].append(entry)
            elif len(tail) >= 2:
                self.ends[tail[-2:]].append(entry)
            else:
                literal = [part for part in low.split('/')[1:]
                           if part and not set(part) & _WILD]
                if literal:
                    self.by_segment[max(literal, key=len)].append(entry)
                else:
                    self.loose.append(entry)
        self.count = len(patterns)
        #: folder (lower case) -> the globs its parts make candidates:
        #: files come a folder at a time, so each folder is split once.
        self._folders = {}

    def _folder_candidates(self, folder):
        found = self._folders.get(folder)
        if found is None:
            if len(self._folders) > FOLDER_CACHE:
                self._folders.clear()
            found = self._folders[folder] = tuple(
                entry for part in set(folder.split('/'))
                for entry in self._part_candidates(part))
        return found

    def _part_candidates(self, part):
        # '*' crosses '/' ('**/AP.db*' names /x/AP.db-dir/y too): a
        # literal start is looked for at the start of any part.
        for entry in self.starts.get(part[:2], ()):
            if part.startswith(entry[0]):
                yield entry
        yield from self.by_segment.get(part, ())

    def __call__(self, path):
        low = path.lower()
        folder, _, name = low.rpartition('/')
        for _head, _tail, needle, match in self.names.get(name, ()):
            if needle in low and match(low):
                return True
        for _head, tail, needle, match in self.ends.get(name[-2:], ()):
            if name.endswith(tail) and needle in low and match(low):
                return True
        for _head, _tail, needle, match in self._part_candidates(name):
            if needle in low and match(low):
                return True
        for _head, _tail, needle, match in self._folder_candidates(folder):
            if needle in low and match(low):
                return True
        for _head, _tail, needle, match in self.loose:
            if needle in low and match(low):
                return True
        return False


def find(handler, matcher, should_stop=None, progress=None, scope=None,
         archives=None, min_archive=None):
    """[(volume label, FileEntry)] of the live files `matcher` names.
    `archives`, a list, also gets every live file that could be a packed
    extraction (core/modules/inputs.ARCHIVE_SUFFIXES) -- the same walk."""
    from trace_app.core.modules.inputs import ARCHIVE_SUFFIXES, MIN_ARCHIVE
    from trace_app.core import walk
    offsets = list(dict.fromkeys(walk.volume_offsets(handler)))
    volumes = walk.volume_names(handler, offsets)
    found, examined = [], 0
    try:
        for entry in walk.iter_files(handler, should_stop=should_stop,
                                     offsets=offsets, scope=scope):
            examined += 1
            if progress is not None and examined % 500 == 0:
                progress(examined, 0, f"Looking for what the tool reads: "
                                      f"{examined:,} files")
            if entry.deleted:
                continue
            if matcher(entry.path):
                found.append((volumes.get(entry.offset, ''), entry))
            if archives is not None and entry.size >= (
                    MIN_ARCHIVE if min_archive is None else min_archive) and \
                    entry.name.lower().endswith(ARCHIVE_SUFFIXES):
                archives.append(entry)
    except walk.WalkCancelled:
        raise StageCancelled() from None
    return found


def staged_name(volume, path):
    """input-relative path ('/'-separated) for a file: each part made safe
    for every system (names on evidence can hold ':' or device names)."""
    parts = [evidence_export.safe_component(part, '_')
             for part in path.strip('/').split('/') if part]
    return '/'.join(([volume] if volume else []) + parts)


def stage(handler, found, input_dir, evidence_id, evidence_name,
          should_stop=None, progress=None):
    """Copy `found` (from find()) into `input_dir`, with the manifest
    beside it (`<input_dir>/../staging-manifest.csv`). Returns the
    manifest's rows."""
    total = sum(entry.size for _volume, entry in found)
    os.makedirs(input_dir, exist_ok=True)
    free = shutil.disk_usage(input_dir).free
    needed = int(total * SPACE_FACTOR) + SPACE_MARGIN
    if free < needed:
        raise StageError(
            f"Not enough free space: the files the tool reads come to "
            f"{total / 1e9:.1f} GB, and with the tool's own copies and "
            f"report about {needed / 1e9:.1f} GB are needed; "
            f"{free / 1e9:.1f} GB are free on that drive.")
    rows, taken, copied = [], set(), [0]
    lock = threading.Lock()

    def copied_bytes(length):
        with lock:
            copied[0] += length
            done = copied[0]
        if progress is not None:
            progress(done, total, "Copying what the tool reads")
    work = []
    for volume, entry in found:
        name = staged_name(volume, entry.path)
        stem, dot, extension = name.rpartition('.')
        number = 2
        # Case-blind file systems (Windows, macOS) would make two names
        # differing by case one file.
        while name.lower() in taken:
            name = (f"{stem} ({number}).{extension}" if dot and stem
                    else f"{name} ({number})")
            number += 1
        taken.add(name.lower())
        row = {'staged_path': name, 'evidence_id': evidence_id,
               'evidence': evidence_name, 'volume': volume,
               'source_path': entry.path, 'artifact_ref': entry.ref,
               'size': entry.size}
        work.append((entry, os.path.join(input_dir, *name.split('/')), row))
        rows.append(row)

    def copy(task):
        entry, target, row = task
        if should_stop is not None and should_stop():
            raise StageCancelled()
        os.makedirs(os.path.dirname(target), exist_ok=True)
        try:
            handle = entry.fs.open_meta(inode=entry.inode)
            # A working copy for the tool: no flush per file (a Mac's
            # tens of thousands of small files spent most of their time
            # there); still read back and checked.
            digests = evidence_export.write_verified(
                target, lambda at, length: handle.read_random(at, length),
                entry.size, should_stop, copied_bytes, sync=False)
            row.update({key: digests.get(key, '') for key in
                        ('md5', 'sha1', 'sha256', 'written_copy_check')})
        except evidence_export.ExportCancelled:
            raise StageCancelled() from None
        except Exception as exc:
            row['problem'] = str(exc)
            logger.warning("Not staged: %s: %s", entry.path, exc)

    # Folder evidence opens each file per read: copied on several threads,
    # each waiting on its own opens (on Windows, the antivirus scans every
    # one -- 4.6 ms a file on a Mac folder). A disk image's readers (The
    # Sleuth Kit, libewf) are one at a time.
    parallel = all(getattr(entry.fs, 'parallel_reads', False)
                   for _volume, entry in found)
    if parallel and len(work) > 1:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=COPY_THREADS) as pool:
            futures = [pool.submit(copy, task) for task in work]
            try:
                for future in futures:
                    future.result()
            except BaseException:
                for future in futures:
                    future.cancel()
                raise
    else:
        for task in work:
            copy(task)
    write_manifest(os.path.join(os.path.dirname(input_dir), MANIFEST), rows)
    return rows


def write_manifest(path, rows):
    with open(path, 'w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS,
                                extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def read_manifest(path):
    """{staged path, lower-cased, '/'-separated: row}."""
    with open(path, newline='', encoding='utf-8') as handle:
        return {row['staged_path'].replace('\\', '/').lower(): row
                for row in csv.DictReader(handle)}

"""External tools' own reports, copied beside the case report (no Qt).

A LEAPP run's report/ folder is the tool's original output. The case
report summarises each run and links to the tool's own HTML report; for
the link to mean anything to whoever receives the report, that report
travels with it:

    <report folder>/External tool reports/<tool> run <id>/   the copy
    <report folder>/External tool reports/MANIFEST.csv       every file

Copied: everything in the tool's output folder (index.html, _HTML,
_Timeline, _TSV Exports, VLEAPP's _KML Exports, media, _lava_data.lava --
a release may add more) but `NEVER`: data/, where the tool keeps its own
copies of the evidence files it parsed (hundreds of MB on a phone), and --
unless asked -- _lava_artifacts.db, every row it extracted (GBs on a big
phone; TRACE reads it in place). A file the tool's run.log
says holds a backup password TRACE could not star (job._redact: a
database) is never copied, and the case report says so.

Every file is written by `evidence_export.write_verified`: hashed while
written, read back, nothing left half-written.
"""

import csv
import logging
import os

from trace_app.core.modules import job, lava

logger = logging.getLogger('TRACE.ReportAttach')

FOLDER = 'External tool reports'
MANIFEST = 'MANIFEST.csv'
#: Parts of a tool's output never copied: its copies of the evidence.
NEVER = ('data',)
DATABASE = lava.DATABASE
#: SQLite's companions of the database, which go (or stay) with it.
_DATABASE_FILES = (DATABASE, DATABASE + '-wal', DATABASE + '-shm',
                   DATABASE + '-journal')
MANIFEST_COLUMNS = ('run', 'path', 'size', 'sha256')
#: job._redact's run.log line naming files with a password left in them.
_PASSWORD_LINE = "WARNING: the backup password is in "


def run_folder_name(run):
    """'iLEAPP run 3': short, so the copy's paths stay well inside
    Windows' 260-character limit."""
    from trace_app.core.carving import safe_name
    return safe_name(f"{run.get('tool') or 'Tool'} run {run['id']}")


def password_files(run):
    """The report's files (relative, '/') run.log says still hold a backup
    password."""
    path = os.path.join(run.get('path') or '', job.LOG)
    found = set()
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                if not line.startswith(_PASSWORD_LINE):
                    continue
                _count, _sep, names = line.partition('rewrite: ')
                found.update(name.strip().replace('\\', '/')
                             for name in names.split(', ') if name.strip())
    except OSError:
        pass
    return found


def plan(run, database=False):
    """(files, bytes, skipped): what copying `run`'s report would write.
    files = [(relative path with '/', absolute path, size)]; skipped =
    [(relative path, why)]."""
    report = os.path.join(run.get('path') or '', job.REPORT)
    withheld = password_files(run)
    files, skipped, total = [], [], 0
    if not os.path.isdir(report):
        return files, 0, skipped
    parts = [name for name in sorted(os.listdir(report))
             if name.lower() not in NEVER
             and (database or name not in _DATABASE_FILES)]
    for part in parts:
        top = os.path.join(report, part)
        if os.path.isfile(top):
            candidates = [top]
        elif os.path.isdir(top):
            candidates = []
            for base, folders, names in os.walk(top):
                folders.sort()
                candidates += [os.path.join(base, n) for n in sorted(names)]
        else:
            continue
        for path in candidates:
            relative = os.path.relpath(path, report).replace('\\', '/')
            if relative in withheld:
                skipped.append((relative, "holds the backup password "
                                          "(run.log)"))
                continue
            try:
                size = os.path.getsize(path)
            except OSError as exc:
                skipped.append((relative, str(exc)))
                continue
            files.append((relative, path, size))
            total += size
    return files, total, skipped


def copy_runs(runs, report_folder, database=False, should_stop=None):
    """Copy each run's report into `report_folder`/External tool reports.
    Returns ({run id: {'folder', 'index', 'files', 'bytes', 'skipped',
    'error'}}, manifest path or None, manifest SHA-256 or None). A run
    that fails is reported in its entry, never raised: the case report is
    still written and says so."""
    from trace_app.core import evidence_hash
    from trace_app.core.evidence_export import write_verified
    copies, lines = {}, []
    root = os.path.join(report_folder, FOLDER)
    for run in runs:
        name = run_folder_name(run)
        entry = {'folder': f"{FOLDER}/{name}", 'index': None, 'files': 0,
                 'bytes': 0, 'skipped': [], 'error': None}
        copies[run['id']] = entry
        files, _total, entry['skipped'] = plan(run, database)
        if not files:
            entry['error'] = "the tool's report folder is not there"
            continue
        target_root = os.path.join(root, name)
        for relative, source, size in files:
            if should_stop is not None and should_stop():
                from trace_app.core.report import ReportCancelled
                raise ReportCancelled()
            target = os.path.join(target_root, *relative.split('/'))
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(source, 'rb') as handle:
                    def read(offset, length, handle=handle):
                        handle.seek(offset)
                        return handle.read(length)
                    digests = write_verified(target, read, size)
            except (OSError, evidence_hash.HashingError) as exc:
                entry['skipped'].append((relative, str(exc)))
                continue
            if digests.get('written_copy_check') != 'matches':
                entry['skipped'].append((relative,
                                         digests['written_copy_check']))
                continue
            entry['files'] += 1
            entry['bytes'] += size
            lines.append((run['id'], f"{name}/{relative}", size,
                          digests['sha256']))
        if os.path.isfile(os.path.join(target_root, 'index.html')):
            entry['index'] = f"{FOLDER}/{name}/index.html"
    if not lines:
        return copies, None, None
    manifest = os.path.join(root, MANIFEST)
    with open(manifest, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(MANIFEST_COLUMNS)
        writer.writerows(lines)
    return copies, manifest, evidence_hash.hash_file(manifest)['sha256']

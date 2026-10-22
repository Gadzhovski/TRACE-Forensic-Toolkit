"""Case persistence: what an examiner establishes, kept between sessions.

Until now TRACE forgot everything on exit. Which images were loaded lived in a
Python list, the hashes it spent minutes computing lived in a dict, and both
went away with the process. A case is that state given a home, plus somewhere
for notes, bookmarks and findings to attach as those features arrive.

A case is a **folder**, not a file:

    <case>/
      case.db        this database
      carved/        carving output for this case
      exports/       generated reports
      thumbnails/

so it can be zipped and handed to another examiner, and so carved output has an
obvious place to go. Evidence is referenced by path and hash, never copied: real
evidence runs to hundreds of gigabytes, and duplicating it is both impractical
and a step examiners avoid.

No Qt imports belong here. The forensic layer stays drivable from a script or a
test without starting a GUI.
"""

import datetime
import hashlib
import json
import logging
import os
import re
import sqlite3

from trace_app.core.search_index import use_wal
from trace_app.core.live_disk import display_name as evidence_name

logger = logging.getLogger('TRACE.Case')

#: Name of the database inside a case folder.
CASE_DB_NAME = 'case.db'

#: Subdirectories created with every case. Carved output goes per-case because
#: carved files are named after their offset alone -- two images carved into one
#: shared directory overwrite each other wherever both hold the same file type
#: at the same offset.
CASE_SUBDIRS = ('carved', 'exports', 'thumbnails')

#: Bumped when the schema changes; _migrate() applies steps in order. Existing
#: cases must keep opening, so this exists from the first release rather than
#: being retrofitted once there is data to lose.
SCHEMA_VERSION = 25

#: Status values recorded against a piece of evidence.
STATUS_PENDING = 'pending'      # added, not yet hashed
STATUS_VERIFIED = 'verified'    # present and matching its recorded hash
STATUS_MISSING = 'missing'      # the file is not where the case says it is
STATUS_CHANGED = 'changed'      # present, but no longer the same bytes
STATUS_UNHASHED = 'unhashed'    # present, but nothing to compare against
STATUS_LIVE = 'live'            # a live disk: hashed as read, not verified
STATUS_BASELINE = 'baseline'    # hashed in full; nothing yet to compare with
STATUS_UNREADABLE = 'unreadable'  # present, but could not be read in full

#: The digests recorded for evidence, compared on every check.
HASH_NAMES = ('md5', 'sha1', 'sha256')

#: Chain-of-custody details an evidence row can carry (schema v16), with
#: how each reads. All optional: an image handed over with no paperwork is
#: still evidence.
EVIDENCE_DETAILS = {
    'exhibit_number': "Exhibit number",
    'description': "Description",
    'acquired_by': "Acquired by",
    'acquired_on': "Acquired on",
}


def case_folder_name(name):
    """A folder name for a case called `name`, valid on every platform:
    spaces kept (it is read by people), characters Windows refuses and
    trailing dots and spaces dropped, never empty."""
    cleaned = ''.join('_' if c in '<>:"/\\|?*' or ord(c) < 32 else c
                      for c in (name or '').strip())
    cleaned = cleaned.rstrip(' .')[:80].rstrip(' .')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{p}{n}' for p in ('COM', 'LPT')
                                                for n in range(1, 10)}
    if cleaned.split('.')[0].upper() in reserved:
        cleaned = f'_{cleaned}'
    return cleaned or 'Case'


# --- artifact references --------------------------------------------------
#
# Notes, bookmarks and tags all point at "some artifact inside some evidence".
# That pointer has to survive a case being closed and reopened, and it has to
# keep meaning the same file afterwards.
#
# Inode alone does not: a filesystem reuses inode numbers, and NTFS records the
# reuse count in the MFT sequence -- image_handler.get_directory_contents
# already reports it. Two files can share an inode over a volume's life, so a
# reference without the sequence can silently come to mean a different file.
# The partition offset is needed because inodes are only unique within a
# filesystem, and one image holds several.

#: A file inside a filesystem: partition offset, inode, and MFT sequence.
_FILE_REF = re.compile(r'^p(\d+):i(\d+)(?::s(\d+))?$')

#: A byte range in an image, used for hex selections and carved data.
_SPAN_REF = re.compile(r'^p(\d+):x([0-9a-fA-F]+)-([0-9a-fA-F]+)$')

#: A registry key or value, identified by hive and key path.
_REGISTRY_REF = re.compile(r'^reg:([^:]+):(.*)$')
_MODULE_REF = re.compile(r'^mod:(\d+):([^:]+):(\d+)$')


#: The mismatch grades worth putting in front of an examiner. Suspicious is an
#: executable in a document's clothing; notable covers a file whose content
#: cannot be identified and looks like random data, which is what an encrypted
#: document looks like from outside. Benign disagreements are recorded but not
#: reported: a list opening with every .jpe teaches people to close the list.
REPORTED_MISMATCHES = ('suspicious', 'notable')

#: The content-check grades worth showing; benign ones (a motion photo's
#: clip, an owner-password PDF) are recorded but not put in front of anyone.
REPORTED_FINDING_GRADES = ('suspicious', 'notable')
#: Sigma matches Triage lists (and counts) at most.
SIGMA_SHOWN = 50000

#: Finding modules written by jobs of their own, not the file analysis.
OWN_JOB_MODULES = ('ntfs', 'yara', 'sigma', 'persistence', 'keywords',
                   'thumbnails')

#: Analysis rows and findings of carved files: their path starts
#: '[carved]/' (carving.CARVED_PREFIX), and the carve job owns them.
CARVED_PATHS = '[carved]/%'


def make_artifact_ref(start_offset, inode, sequence=None):
    """A durable reference to a file within a piece of evidence.

    `sequence` is the MFT record's reuse counter where the filesystem provides
    one. Omitting it still produces a usable reference, but one that cannot
    tell two generations of the same inode apart -- so pass it when it is
    known.
    """
    ref = f"p{int(start_offset)}:i{int(inode)}"
    if sequence is not None:
        ref += f":s{int(sequence)}"
    return ref


def make_span_ref(start_offset, begin, end):
    """A reference to a byte range -- a hex selection, or carved data."""
    return f"p{int(start_offset)}:x{int(begin):x}-{int(end):x}"


def make_module_ref(run_id, table, rowid):
    """A reference to one row an external module (core/modules) wrote:
    its run, its LAVA table and the row's rowid there."""
    return f"mod:{int(run_id)}:{table}:{int(rowid)}"


def make_registry_ref(hive, key_path):
    """A reference to a registry key or value."""
    return f"reg:{hive}:{key_path}"


def parse_artifact_ref(ref):
    """Take a reference apart. Returns a dict describing what it points at.

    The `kind` key says which shape it is, so a caller can decide how to
    resolve it. An unrecognised reference returns kind 'unknown' rather than
    raising: a case written by a later version of TRACE should still open, with
    the references it does understand still working.
    """
    if not ref:
        return {'kind': 'unknown', 'ref': ref}

    match = _FILE_REF.match(ref)
    if match:
        return {
            'kind': 'file',
            'start_offset': int(match.group(1)),
            'inode': int(match.group(2)),
            'sequence': int(match.group(3)) if match.group(3) else None,
            'ref': ref,
        }

    match = _SPAN_REF.match(ref)
    if match:
        return {
            'kind': 'span',
            'start_offset': int(match.group(1)),
            'begin': int(match.group(2), 16),
            'end': int(match.group(3), 16),
            'ref': ref,
        }

    match = _MODULE_REF.match(ref)
    if match:
        return {
            'kind': 'module',
            'run_id': int(match.group(1)),
            'table': match.group(2),
            'rowid': int(match.group(3)),
            'ref': ref,
        }

    match = _REGISTRY_REF.match(ref)
    if match:
        return {
            'kind': 'registry',
            'hive': match.group(1),
            'key_path': match.group(2),
            'ref': ref,
        }

    return {'kind': 'unknown', 'ref': ref}


#: The tags a case starts with: (name, colour).
DEFAULT_TAGS = (('Relevant', '#E5534B'), ('Needs review', '#E3A008'),
                ('Ignore', '#8B949E'))


def _tag_detail(tag, paths):
    """An audit line's detail: the tag and the files, the first ten named."""
    shown = '; '.join(paths[:10])
    more = f" and {len(paths) - 10} more" if len(paths) > 10 else ''
    return f"{tag}: {len(paths)} file(s): {shown}{more}"


class CaseError(Exception):
    """A case could not be created, opened or written."""


class Case:
    """An open case: its metadata, its evidence, and everything recorded about it.

    Use :meth:`create` or :meth:`open` rather than constructing directly.
    """

    def __init__(self, folder, connection):
        self.folder = folder
        self._db = connection

    # --- lifecycle --------------------------------------------------------

    @classmethod
    def create(cls, folder, name, number='', examiner='', description='',
               organisation=''):
        """Make a new case in `folder`, which must not already hold one."""
        db_path = os.path.join(folder, CASE_DB_NAME)
        if os.path.exists(db_path):
            raise CaseError(
                f"{folder} already contains a case. Open it instead, or "
                f"choose an empty folder.")

        try:
            os.makedirs(folder, exist_ok=True)
            for sub in CASE_SUBDIRS:
                os.makedirs(os.path.join(folder, sub), exist_ok=True)
        except OSError as exc:
            raise CaseError(f"Could not create the case folder: {exc}") from exc

        case = cls(folder, cls._connect(db_path))
        case._create_schema()
        case._seed_tags()
        case._custody_guards()
        now = _utc_now()
        case._set_many({
            'name': name,
            'number': number,
            'examiner': examiner,
            'description': description,
            'organisation': organisation,
            'created_utc': now,
            'opened_utc': now,
        })
        case._record_activity('case created', name)
        logger.info("Created case %r in %s", name, folder)
        return case

    @classmethod
    def open(cls, folder):
        """Open the case in `folder`."""
        db_path = os.path.join(folder, CASE_DB_NAME)
        if not os.path.exists(db_path):
            raise CaseError(f"No case found in {folder}.")

        case = cls(folder, cls._connect(db_path))
        case._migrate()
        # A case moved between machines still needs its working directories.
        for sub in CASE_SUBDIRS:
            try:
                os.makedirs(os.path.join(folder, sub), exist_ok=True)
            except OSError:
                pass        # surfaces at the point of an actual write
        case._set('opened_utc', _utc_now())
        case._record_activity('case opened', case.name)
        return case

    @property
    def is_open(self):
        """Whether the database is still open: a signal arriving after the
        window closed the case (a panel's load finishing) asks this
        first."""
        return self._db is not None

    def close(self):
        """Close the database. Safe to call more than once."""
        if self._db is not None:
            try:
                self._record_activity('case closed', self.name)
                self._db.commit()
            except sqlite3.Error:
                pass        # a close should not raise over an audit line
            self._db.close()
            self._db = None

    @staticmethod
    def _connect(db_path):
        try:
            connection = sqlite3.connect(db_path)
        except sqlite3.Error as exc:
            raise CaseError(f"Could not open {db_path}: {exc}") from exc
        connection.row_factory = sqlite3.Row
        # Referential integrity is off by default in SQLite; a note whose
        # evidence has been removed is a dangling record.
        connection.execute("PRAGMA foreign_keys = ON")
        use_wal(connection)
        return connection

    # --- paths ------------------------------------------------------------

    def subdir(self, name):
        """Absolute path to one of the case's working directories."""
        path = os.path.join(self.folder, name)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass
        return path

    @property
    def carved_dir(self):
        """The case's carved/ folder -- or, when the case's settings name
        one (a larger drive, say), a folder for this case inside that."""
        return self._chosen_dir('carved_folder') or self.subdir('carved')

    @property
    def exports_dir(self):
        return self._chosen_dir('export_folder') or self.subdir('exports')

    def _chosen_dir(self, key):
        from trace_app.core.settings import chosen_dir
        chosen = (self.setting('settings') or {}).get(key)
        path = chosen_dir(chosen, self.name)
        if path is None:
            return None
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            logger.warning("%s unusable (%s); using the case folder",
                           path, exc)
            return None
        return path

    # --- metadata ---------------------------------------------------------

    @property
    def metadata(self):
        """Every case_info key as a plain dict."""
        rows = self._db.execute("SELECT key, value FROM case_info").fetchall()
        return {row['key']: row['value'] for row in rows}

    @property
    def name(self):
        return self._get('name', '')

    @property
    def number(self):
        return self._get('number', '')

    @property
    def examiner(self):
        return self._get('examiner', '')

    @property
    def description(self):
        return self._get('description', '')

    @property
    def organisation(self):
        return self._get('organisation', '')

    def update_metadata(self, **fields):
        """Change one or more case_info values."""
        known = {'name', 'number', 'examiner', 'description', 'organisation'}
        unknown = set(fields) - known
        if unknown:
            raise ValueError(f"Not case metadata: {', '.join(sorted(unknown))}")
        self._set_many(fields)
        self._record_activity('metadata edited', ', '.join(sorted(fields)))

    def setting(self, key, default=None):
        """A case option (JSON), or `default` when it was never set."""
        raw = self._get(f'setting:{key}')
        if raw is None or raw == '':
            return default
        try:
            return json.loads(raw)
        except ValueError:
            return default

    def set_setting(self, key, value):
        self._set(f'setting:{key}', json.dumps(value))

    def _get(self, key, default=None):
        row = self._db.execute(
            "SELECT value FROM case_info WHERE key = ?", (key,)).fetchone()
        return row['value'] if row else default

    def _set(self, key, value):
        self._db.execute(
            "INSERT INTO case_info (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, '' if value is None else str(value)))
        self._db.commit()

    def _set_many(self, mapping):
        for key, value in mapping.items():
            self._db.execute(
                "INSERT INTO case_info (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, '' if value is None else str(value)))
        self._db.commit()

    # --- evidence ---------------------------------------------------------

    def add_evidence(self, path, display_name=None, details=None):
        """Record an image as part of this case. Returns its evidence id.

        The file is not hashed here: hashing a multi-gigabyte image takes
        minutes and would block the caller. The row starts as `pending` and
        :meth:`record_hashes` fills it in once verification has run.
        `details` holds any of EVIDENCE_DETAILS (exhibit number and so on).
        """
        path = os.path.normpath(os.path.abspath(path))
        existing = self._db.execute(
            "SELECT id FROM evidence WHERE path = ?", (path,)).fetchone()
        if existing:
            return existing['id']

        from trace_app.core import assembly
        from trace_app.core.live_disk import is_device_path
        live = is_device_path(path)
        # An assembled volume's file is a descriptor; its media is the
        # members', so no size is recorded for it.
        assembled = assembly.is_assembly(path)
        try:
            size = None if live or assembled else os.path.getsize(path)
        except OSError:
            size = None

        details = {key: (str(value).strip() or None)
                   for key, value in (details or {}).items()
                   if key in EVIDENCE_DETAILS and value is not None}
        columns = ['path', 'display_name', 'size', 'added_utc',
                   'last_status'] + list(details)
        values = [path, display_name or evidence_name(path), size,
                  _utc_now(), STATUS_PENDING] + list(details.values())
        # What the image was acquired as, from the imaging tool's log
        # beside it (core/acquisition_log.py): the reference a raw image
        # is verified against, which it cannot store itself.
        logged, log_path = ({}, None) if live or assembled else \
            _acquisition_log(path)
        if logged:
            columns += [f'stored_{n}' for n in logged] + ['stored_source']
            values += list(logged.values()) + [
                f"acquisition log {os.path.basename(log_path)}"]
        cursor = self._db.execute(
            f"INSERT INTO evidence ({', '.join(columns)}) VALUES "
            f"({', '.join('?' * len(columns))})", values)
        self._db.commit()
        recorded = '; '.join(f"{EVIDENCE_DETAILS[k].lower()} {v}"
                             for k, v in details.items() if v)
        if logged:
            recorded = '; '.join(filter(None, (
                f"acquisition hashes from {log_path}: " + ' '.join(
                    f"{n.upper()}={v}" for n, v in logged.items()),
                recorded)))
        if live:
            recorded = '; '.join(filter(None, (
                'live disk, read-only through an administrator helper; '
                'not an image, and not verifiable', recorded)))
        if assembled:
            try:
                members = ', '.join(
                    f"{m['image']} (sector {m['start_sector']})"
                    for m in assembly.read_descriptor(path)['members'])
            except assembly.AssemblyError:
                members = 'members unreadable'
            recorded = '; '.join(filter(None, (
                f"assembled from {members}", recorded)))
        self._record_activity('evidence added',
                              path + (f" ({recorded})" if recorded else ''))
        return cursor.lastrowid

    def update_evidence_details(self, evidence_id, **details):
        """Change an evidence row's custody details; audited with the old
        and new values, since these are what a report states."""
        unknown = set(details) - set(EVIDENCE_DETAILS)
        if unknown:
            raise ValueError(f"Not evidence details: "
                             f"{', '.join(sorted(unknown))}")
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        if row is None:
            return
        changes = {}
        for key, value in details.items():
            value = (str(value).strip() or None) if value is not None else None
            if (row[key] or None) != value:
                changes[key] = (row[key], value)
        if not changes:
            return
        for key, (_old, new) in changes.items():
            self._db.execute(f"UPDATE evidence SET {key} = ? WHERE id = ?",
                             (new, evidence_id))
        self._db.commit()
        self._record_activity(
            'evidence details edited',
            f"id={evidence_id} " + '; '.join(
                f"{EVIDENCE_DETAILS[k].lower()}: {old or '(none)'} -> "
                f"{new or '(none)'}" for k, (old, new) in changes.items()))

    def evidence(self):
        """Every piece of evidence, oldest first, as a list of dicts."""
        rows = self._db.execute(
            "SELECT * FROM evidence ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def evidence_paths(self):
        """Just the paths, in the order they were added."""
        return [row['path'] for row in self.evidence()]

    def evidence_for_path(self, path):
        """The evidence row for `path`, or None."""
        path = os.path.normpath(os.path.abspath(path))
        row = self._db.execute(
            "SELECT * FROM evidence WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None

    #: What a piece of evidence has recorded against it, for the examiner
    #: to see before removing it: table -> how it is described. Every one
    #: of these goes with the evidence row (ON DELETE CASCADE).
    EVIDENCE_RECORDS = (
        ('file_analysis', 'file analysis results'),
        ('file_findings', 'findings'),
        ('carved_files', 'carved files'),
        ('deleted_files', 'deleted-file records'),
        ('user_activity', 'activity records'),
        ('fs_events', 'NTFS events'),
        ('usn_journal', 'USN journal records'),
        ('persistence', 'persistence entries'),
        ('thumbnails', 'thumbnail cache entries'),
        ('hash_matches', 'hash set matches'),
        ('vt_results', 'VirusTotal results'),
        ('bookmarks', 'bookmarks'),
        ('artifact_tags', 'tags'),
        ('vic_categories', 'Project VIC categories'),
        ('module_runs', 'external module runs'),
        ('report_items', 'report picks'),
        ('verifications', 'verification records'),
        ('evidence_systems', 'operating systems found'),
    )

    def evidence_footprint(self, evidence_id):
        """[(description, count)] of what is recorded against a piece of
        evidence, non-empty ones only; notes are counted separately
        (`notes_for_evidence`) because they are kept."""
        out = []
        for table, description in self.EVIDENCE_RECORDS:
            try:
                count = self._db.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE evidence_id = ?",
                    (evidence_id,)).fetchone()[0]
            except sqlite3.Error:
                continue
            if count:
                out.append((description, count))
        return out

    def set_systems(self, evidence_id, systems):
        """Record the operating systems found on an image's volumes:
        [{'volume_key', 'volume', 'family', 'logo', 'name', 'detail'}].
        Replaces what was recorded; writes nothing when it is unchanged
        (an image is opened every time the case is)."""
        keys = ('volume_key', 'volume', 'family', 'logo', 'name', 'detail')
        new = sorted(tuple(s.get(k) for k in keys) for s in systems)
        old = sorted(tuple(s.get(k) for k in keys)
                     for s in self.systems(evidence_id).get(evidence_id, []))
        if new == old:
            return False
        now = _utc_now()
        with self._db:
            self._db.execute("DELETE FROM evidence_systems WHERE "
                             "evidence_id = ?", (evidence_id,))
            self._db.executemany(
                "INSERT INTO evidence_systems (evidence_id, volume_key, "
                "volume, family, logo, name, detail, recorded_utc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(evidence_id, *row, now) for row in new])
        return True

    def systems(self, evidence_id=None):
        """{evidence id: [system, ...]} in volume order."""
        where, params = ('WHERE evidence_id = ?', (evidence_id,)) \
            if evidence_id is not None else ('', ())
        out = {}
        for row in self._db.execute(
                f"SELECT * FROM evidence_systems {where} ORDER BY "
                f"evidence_id, volume_key", params):
            out.setdefault(row['evidence_id'], []).append(dict(row))
        return out

    def notes_for_evidence(self, evidence_id):
        return self._db.execute(
            "SELECT COUNT(*) FROM notes WHERE evidence_id = ?",
            (evidence_id,)).fetchone()[0]

    def remove_evidence(self, evidence_id):
        """Take a piece of evidence out of the case, and everything recorded
        against it: analysis, findings, carves (rows and the files written),
        activity, its search index entries, bookmarks. The image itself is
        never touched -- the case only ever referred to it.

        Notes outlive what they describe: they are kept, detached, with the
        image's name added to where they pointed. The audit trail keeps a
        line saying what was removed, with the evidence's recorded hashes.
        Returns the footprint that was removed, or None if there was no
        such evidence."""
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        if row is None:
            return None
        row = dict(row)
        name = row.get('display_name') or evidence_name(row['path'])
        footprint = self.evidence_footprint(evidence_id)
        notes = self.notes_for_evidence(evidence_id)
        carved_folder = self._carved_folder_path(evidence_id)
        # Run folders of external modules (staged copies, the tools'
        # reports) inside the case folder: the rows cascade, the files not.
        run_folders = [run['path'] for run in self.module_runs(evidence_id)
                       if os.path.realpath(run['path']).startswith(
                           os.path.realpath(self.folder) + os.sep)]

        # Notes first: the evidence row's cascade would take them too.
        self._db.execute(
            "UPDATE notes SET evidence_id = NULL, artifact_path = "
            "'[' || ? || ' -- removed from the case] ' || "
            "COALESCE(artifact_path, '') WHERE evidence_id = ?",
            (name, evidence_id))
        self._db.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        self._db.commit()

        # The search index is its own database (search.db): a cache, but
        # its hits would name evidence that is no longer in the case.
        index_path = os.path.join(self.folder, 'search.db')
        if os.path.exists(index_path):
            try:
                from trace_app.core.search_index import SearchIndex
                index = SearchIndex(self.folder)
                try:
                    index.clear_evidence(evidence_id, keep_modules=False)
                    index.commit()
                finally:
                    index.close()
            except Exception as exc:
                logger.warning("Search index entries for %s not removed: %s",
                               name, exc)

        # The carved copies TRACE wrote for this evidence (never anything
        # the examiner exported).
        import shutil
        if carved_folder and os.path.isdir(carved_folder):
            shutil.rmtree(carved_folder, ignore_errors=True)
            if os.path.exists(carved_folder):
                logger.warning("Carved files for %s not all removed: %s",
                               name, carved_folder)

        for folder in run_folders:
            shutil.rmtree(folder, ignore_errors=True)

        hashes = ', '.join(f"{k.upper()} {row[k]}" for k in
                           ('md5', 'sha1', 'sha256') if row.get(k))
        removed = '; '.join(f"{count:,} {what}" for what, count in footprint)
        self._record_activity(
            'evidence removed',
            f"id={evidence_id} {row['path']}"
            + (f" ({hashes})" if hashes else '')
            + f"; removed: {removed or 'nothing recorded'}"
            + (f"; {notes} note(s) kept" if notes else ''))
        return footprint

    def relocate_evidence(self, evidence_id, new_path):
        """Point a piece of evidence at a file that has moved.

        The recorded hashes are kept: the whole point of relocating is to check
        that the file found elsewhere is the same evidence.
        """
        new_path = os.path.normpath(os.path.abspath(new_path))
        old = self._db.execute("SELECT path FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        self._db.execute(
            "UPDATE evidence SET path = ?, last_status = ? WHERE id = ?",
            (new_path, STATUS_PENDING, evidence_id))
        self._db.commit()
        # The recorded size is kept with the hashes: the next check
        # compares the file found here with both.
        self._record_activity(
            'evidence relocated',
            f"id={evidence_id} {old['path'] if old else '?'} -> {new_path}"
            f"; recorded hashes kept, to be checked")

    def relocate_checked(self, evidence_id, new_path, results,
                         accept_unverified=False):
        """Point evidence at `new_path` only if the file there is the same
        evidence: `results` (a hashing run of that file) must match every
        hash the case recorded and every acquisition hash. A file with
        nothing to compare against is taken only with `accept_unverified`
        (the examiner's say-so, audited as such). Returns the outcome with
        'relocated' True or False; a refusal is audited too, with what the
        file there hashed to."""
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        if row is None:
            raise CaseError(f"No evidence {evidence_id} in this case")
        row = dict(row)
        recorded = {name: row.get(name) for name in HASH_NAMES
                    if row.get(name)}
        outcome = verdict(results, recorded, acquisition_hashes(row, results))
        status = outcome['status']
        if status == STATUS_VERIFIED or (status == STATUS_BASELINE
                                         and accept_unverified):
            self.relocate_evidence(evidence_id, new_path)
            applied = self.apply_verification(evidence_id, results)
            if status == STATUS_BASELINE:
                self._record_activity(
                    'evidence relocated unverified',
                    f"id={evidence_id}: nothing recorded to compare "
                    f"{os.path.abspath(new_path)} with; accepted by the "
                    f"examiner")
            return dict(applied, relocated=True)
        computed = ' '.join(
            f"{n.upper()}={results.get(f'computed_{n}')}"
            for n in HASH_NAMES if results.get(f'computed_{n}'))
        self._record_activity(
            'evidence relocation refused',
            f"id={evidence_id} {row['path']} -> "
            f"{os.path.abspath(new_path)}: {outcome['detail']}"
            + (f" ({computed})" if computed else ''))
        return dict(outcome, relocated=False)

    def record_hashes(self, evidence_id, results, status=None, detail=None):
        """Judge a hashing run (ImageHandler.calculate_hashes) and record
        it: `apply_verification`. Kept under its old name; `status` and
        `detail` are ignored -- the verdict is never the caller's."""
        return self.apply_verification(evidence_id, results)

    def apply_verification(self, evidence_id, results):
        """Record what a hashing run of this evidence found. Returns the
        outcome {status, detail, algorithm, expected, computed}.

        The verdict (`verdict`) compares the run with everything the case
        holds: the hashes recorded when it was first hashed, the hashes
        the image stores itself (an E01's) and the acquisition hashes from
        its log or entered by the examiner; it also reports damage the
        image's own checksums show. Every one must match.

        Recorded hashes are written once -- the first time the evidence is
        hashed in full without contradicting anything -- and never
        replaced: a check that finds the evidence changed is a row in the
        history and the evidence's status, and the reference it was
        checked against stays what it was. (A dialog that saved whatever
        it had just computed as the new reference made an altered image
        "verified" on the next check.)"""
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        if row is None:
            raise CaseError(f"No evidence {evidence_id} in this case")
        row = dict(row)
        # An acquisition log found only now (placed beside the evidence
        # later, or a format TRACE learnt to read since it was added): its
        # hashes become the row's reference, audited, before judging.
        if not row.get('stored_source') and not any(
                row.get(f'stored_{n}') for n in HASH_NAMES) and \
                not results.get('live') and os.path.isfile(row['path']):
            logged, log_path = _acquisition_log(row['path'])
            if logged:
                self.set_acquisition_hashes(
                    evidence_id,
                    f"acquisition log {os.path.basename(log_path)}",
                    **logged)
                row = dict(self._db.execute(
                    "SELECT * FROM evidence WHERE id = ?",
                    (evidence_id,)).fetchone())
        recorded = {name: row.get(name) for name in HASH_NAMES
                    if row.get(name)}
        stored = acquisition_hashes(row, results)
        outcome = verdict(results, recorded, stored)
        first = not recorded and outcome['status'] in (
            STATUS_VERIFIED, STATUS_BASELINE, STATUS_LIVE)
        if first:
            self._db.execute(
                "UPDATE evidence SET md5 = ?, sha1 = ?, sha256 = ? "
                "WHERE id = ? AND md5 IS NULL AND sha1 IS NULL AND "
                "sha256 IS NULL",
                tuple(results.get(f'computed_{n}') for n in HASH_NAMES)
                + (evidence_id,))
        # What the image stores itself is kept beside the row, so the
        # report states it even for an image that is never opened again.
        for name in ('md5', 'sha1'):
            value = results.get(f'stored_{name}')
            if value and not row.get(f'stored_{name}'):
                self._db.execute(
                    f"UPDATE evidence SET stored_{name} = ?, stored_source "
                    f"= COALESCE(stored_source, 'the image') WHERE id = ?",
                    (value, evidence_id))
        if outcome['status'] == STATUS_VERIFIED:
            self._db.execute("UPDATE evidence SET verified_utc = ? WHERE "
                             "id = ?", (_utc_now(), evidence_id))
        self._db.commit()
        self._note_check(evidence_id, outcome['algorithm'],
                         outcome['expected'], outcome['computed'],
                         outcome['status'], outcome['detail'])
        if first:
            self._record_activity(
                'evidence hashes recorded',
                f"id={evidence_id} " + ' '.join(
                    f"{n.upper()}={results.get(f'computed_{n}')}"
                    for n in HASH_NAMES if results.get(f'computed_{n}'))
                + f" over {results.get('size') or 0:,} bytes")
        return outcome

    def set_acquisition_hashes(self, evidence_id, source, **hashes):
        """Record the hashes the evidence was acquired as -- from its
        acquisition log, or as the examiner reads them off the custody
        paperwork -- for every later check to compare with. Values are
        checked as hex digests of the right length; the change is audited
        with the old and new values. `source` says where they came from."""
        lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
        clean = {}
        for name, value in hashes.items():
            if name not in lengths:
                raise ValueError(f"Not a recorded hash: {name}")
            value = (value or '').strip().lower()
            if value and not re.fullmatch(f'[0-9a-f]{{{lengths[name]}}}',
                                          value):
                raise ValueError(f"{name.upper()} must be "
                                 f"{lengths[name]} hex digits")
            clean[name] = value or None
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        if row is None:
            raise CaseError(f"No evidence {evidence_id} in this case")
        changes = {n: (row[f'stored_{n}'], v) for n, v in clean.items()
                   if (row[f'stored_{n}'] or None) != v}
        if not changes:
            return
        for name, (_old, new) in changes.items():
            self._db.execute(f"UPDATE evidence SET stored_{name} = ? WHERE "
                             f"id = ?", (new, evidence_id))
        self._db.execute("UPDATE evidence SET stored_source = ? WHERE id = ?",
                         (source, evidence_id))
        self._db.commit()
        self._record_activity(
            'acquisition hashes set',
            f"id={evidence_id} from {source}: " + '; '.join(
                f"{n.upper()} {old or '-'} -> {new or '-'}"
                for n, (old, new) in changes.items()))

    def verify_evidence(self, progress=None):
        """Check every piece of evidence is still what the case recorded.

        Returns a list of `(evidence_row, status, detail)`. The status that
        matters is CHANGED: a file still present whose bytes no longer match
        is the one an examiner must be told about loudly.

        Each piece is hashed in full (`hash_evidence`) and judged by
        `apply_verification`, as the window's verification job does.
        """
        outcomes = []
        for row in self.evidence():
            results = hash_evidence(row, progress)
            if results.get('status'):           # missing, or a live disk
                self.record_check(row['id'], results)
                outcome = results
            else:
                outcome = self.apply_verification(row['id'], results)
            outcomes.append((row, outcome['status'], outcome['detail']))
        return outcomes

    def record_check(self, evidence_id, outcome):
        """Record what `check_evidence` found."""
        self._note_check(evidence_id, outcome.get('algorithm', ''),
                         outcome.get('expected', ''),
                         outcome.get('computed', ''), outcome['status'],
                         outcome['detail'])

    def _note_check(self, evidence_id, algorithm, expected, computed, status,
                    detail):
        """Record one verification: its history row, its status, its audit line.

        One method rather than three calls at seven sites, because a check that
        updates the status but forgets the history leaves a case claiming
        something it cannot show the working for -- and a re-verification that
        finds evidence CHANGED previously left nothing in the audit trail at
        all.
        """
        self.record_verification(evidence_id, algorithm, expected, computed,
                                 status, detail)
        self._set_status(evidence_id, status)
        self._record_activity(f'evidence {status}', f'id={evidence_id} {detail}')

    def _set_status(self, evidence_id, status):
        self._db.execute(
            "UPDATE evidence SET last_status = ? WHERE id = ?",
            (status, evidence_id))
        self._db.commit()

    # --- verification history --------------------------------------------

    def record_verification(self, evidence_id, algorithm, expected, computed,
                            status, detail=''):
        """Append one verification result. Never updates in place.

        Chain of custody is a history, not a current value: "this evidence
        matched when it was added and again last Tuesday" is a different claim
        from "this evidence matches", and only the first is defensible in a
        report.
        """
        named = self._db.execute(
            "SELECT COALESCE(display_name, path) AS name FROM evidence "
            "WHERE id = ?", (evidence_id,)).fetchone()
        self._db.execute(
            "INSERT INTO verifications (evidence_id, evidence_name, utc, "
            "algorithm, expected, computed, status, detail) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, named['name'] if named else None, _utc_now(),
             algorithm, expected, computed, status, detail))
        self._db.commit()

    def verifications(self, evidence_id=None, limit=200):
        """Verification history, newest first."""
        if evidence_id is None:
            rows = self._db.execute(
                "SELECT * FROM verifications ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM verifications WHERE evidence_id = ? "
                "ORDER BY id DESC LIMIT ?", (evidence_id, limit)).fetchall()
        return [dict(row) for row in rows]

    # --- VirusTotal ---------------------------------------------------------

    def record_vt_result(self, evidence_id, artifact_ref, name, path, sha256,
                         method, result, sent=True):
        """Append one VirusTotal query and, if anything left, its audit line.

        `sent` says whether the hash or the file actually reached VirusTotal.
        A query that failed before sending -- the file could not be read --
        is recorded as an error but not audited as a disclosure, because
        nothing was disclosed.
        """
        status = result.get('status') or 'error'
        report = {k: v for k, v in result.items() if k != 'error'}
        cursor = self._db.execute(
            "INSERT INTO vt_results (evidence_id, artifact_ref, name, path, "
            "sha256, method, status, positives, total, scan_date, report, "
            "detail, queried_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, artifact_ref, name, path, sha256 or '', method,
             status, result.get('positives'), result.get('total'),
             result.get('scan_date') or '', json.dumps(report),
             result.get('error') or '', _utc_now()))
        self._db.commit()

        if sent:
            what = ('file uploaded to VirusTotal' if method == 'upload'
                    else 'hash sent to VirusTotal')
            self._record_activity(
                what, f"{path or name} sha256={sha256} result={status}")
        return cursor.lastrowid

    def vt_results(self, evidence_id=None, limit=500):
        """VirusTotal history, newest first, with the report decoded."""
        query = "SELECT * FROM vt_results"
        params = []
        if evidence_id is not None:
            query += " WHERE evidence_id = ?"
            params.append(evidence_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [_decode_vt(row) for row in self._db.execute(query, params)]

    def vt_latest(self, evidence_id, refs):
        """The newest result for each of `refs` that has one, by ref."""
        refs = list(refs)
        found = {}
        for start in range(0, len(refs), 500):
            chunk = refs[start:start + 500]
            marks = ','.join('?' * len(chunk))
            rows = self._db.execute(
                f"SELECT * FROM vt_results WHERE id IN ("
                f"  SELECT MAX(id) FROM vt_results WHERE evidence_id = ? "
                f"  AND artifact_ref IN ({marks}) GROUP BY artifact_ref)",
                [evidence_id] + chunk).fetchall()
            found.update({r['artifact_ref']: _decode_vt(r) for r in rows})
        return found

    # --- read-only status -------------------------------------------------

    # --- bookmarks --------------------------------------------------------

    def add_bookmark(self, evidence_id, artifact_ref, label,
                     artifact_name='', artifact_path='', colour=''):
        """Mark an artifact worth returning to. Returns the bookmark id.

        `artifact_ref` comes from make_artifact_ref / make_span_ref /
        make_registry_ref -- it is what survives a case being closed and still
        points at the same thing afterwards. The name and path are stored
        alongside as human-readable context, so a bookmark still says something
        useful even if its evidence is missing.
        """
        existing = self._db.execute(
            "SELECT id FROM bookmarks WHERE evidence_id IS ? "
            "AND artifact_ref = ?", (evidence_id, artifact_ref)).fetchone()
        if existing:
            # Bookmarking the same artifact twice is a re-label, not a
            # duplicate: two identical rows in the list help nobody.
            self._db.execute(
                "UPDATE bookmarks SET label = ?, colour = ? WHERE id = ?",
                (label, colour, existing['id']))
            self._db.commit()
            self._record_activity('bookmark updated', f'{label} ({artifact_ref})')
            return existing['id']

        if evidence_id is not None and not self._evidence_exists(evidence_id):
            evidence_id = None

        cursor = self._db.execute(
            "INSERT INTO bookmarks (evidence_id, artifact_ref, artifact_name,"
            " artifact_path, label, colour, created_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, artifact_ref, artifact_name, artifact_path, label,
             colour, _utc_now()))
        self._db.commit()
        self._record_activity('bookmark added', f'{label} ({artifact_ref})')
        return cursor.lastrowid

    def bookmarks(self, evidence_id=None):
        """Bookmarks, newest first."""
        if evidence_id is None:
            rows = self._db.execute(
                "SELECT * FROM bookmarks ORDER BY id DESC").fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM bookmarks WHERE evidence_id = ? "
                "ORDER BY id DESC", (evidence_id,)).fetchall()
        return [dict(row) for row in rows]

    def bookmark_for_artifact(self, evidence_id, artifact_ref):
        """The bookmark on this artifact, or None."""
        row = self._db.execute(
            "SELECT * FROM bookmarks WHERE evidence_id IS ? "
            "AND artifact_ref = ?", (evidence_id, artifact_ref)).fetchone()
        return dict(row) if row else None

    def update_bookmark(self, bookmark_id, label=None, colour=None):
        """Rename or recolour a bookmark."""
        old = self._db.execute("SELECT label, colour, artifact_ref FROM "
                               "bookmarks WHERE id = ?",
                               (bookmark_id,)).fetchone()
        if old is None:
            return
        if label is not None:
            self._db.execute("UPDATE bookmarks SET label = ? WHERE id = ?",
                             (label, bookmark_id))
        if colour is not None:
            self._db.execute("UPDATE bookmarks SET colour = ? WHERE id = ?",
                             (colour, bookmark_id))
        self._db.commit()
        changes = [f"{what} {old[what]!r} -> {new!r}"
                   for what, new in (('label', label), ('colour', colour))
                   if new is not None and new != old[what]]
        if changes:
            self._record_activity(
                'bookmark edited',
                f"id={bookmark_id} ({old['artifact_ref']}): "
                + '; '.join(changes))

    def remove_bookmark(self, bookmark_id):
        """Delete a bookmark. Any notes on it are kept, and become free-standing."""
        row = self._db.execute("SELECT label, artifact_ref, artifact_path "
                               "FROM bookmarks WHERE id = ?",
                               (bookmark_id,)).fetchone()
        self._db.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
        self._db.commit()
        if row:
            self._record_activity(
                'bookmark removed',
                f"id={bookmark_id} {row['label'] or ''!r} on "
                f"{row['artifact_path'] or row['artifact_ref']}")

    # --- tags ---------------------------------------------------------------
    #
    # A tag is the examiner's own verdict on a file -- Relevant, Ignore, a
    # name of their choosing -- kept by artifact_ref with the evidence id,
    # like a bookmark, so it survives a reopen. Who tagged what, and when,
    # is custody: every change is an audit line.

    def _seed_tags(self):
        """The tags a case starts with, unless it has any."""
        if self._db.execute("SELECT COUNT(*) FROM tags").fetchone()[0]:
            return
        self._db.executemany("INSERT INTO tags (name, colour) VALUES (?, ?)",
                             DEFAULT_TAGS)
        self._db.commit()

    def tags(self):
        """Every tag, in the order made, with how many files carry it."""
        return [dict(row) for row in self._db.execute(
            "SELECT t.id, t.name, t.colour, COUNT(a.artifact_ref) AS files "
            "FROM tags t LEFT JOIN artifact_tags a ON a.tag_id = t.id "
            "GROUP BY t.id ORDER BY t.id")]

    def add_tag(self, name, colour=''):
        """A new tag; returns its id (an existing tag of that name's id)."""
        name = (name or '').strip()
        if not name:
            raise CaseError("A tag needs a name.")
        row = self._db.execute("SELECT id FROM tags WHERE name = ?",
                               (name,)).fetchone()
        if row:
            return row['id']
        cursor = self._db.execute(
            "INSERT INTO tags (name, colour) VALUES (?, ?)", (name, colour))
        self._db.commit()
        self._record_activity('tag created', f"{name!r} {colour}".strip())
        return cursor.lastrowid

    def update_tag(self, tag_id, name=None, colour=None):
        old = self._db.execute("SELECT name, colour FROM tags WHERE id = ?",
                               (tag_id,)).fetchone()
        if old is None:
            return
        if name is not None and name.strip():
            self._db.execute("UPDATE tags SET name = ? WHERE id = ?",
                             (name.strip(), tag_id))
        if colour is not None:
            self._db.execute("UPDATE tags SET colour = ? WHERE id = ?",
                             (colour, tag_id))
        self._db.commit()
        changes = [f"{what} {old[what]!r} -> {new!r}"
                   for what, new in (('name', name), ('colour', colour))
                   if new is not None and new != old[what]]
        if changes:
            self._record_activity('tag edited', f"id={tag_id}: "
                                  + '; '.join(changes))

    def remove_tag(self, tag_id):
        """Delete a tag, and its marks on files."""
        row = self._db.execute("SELECT name FROM tags WHERE id = ?",
                               (tag_id,)).fetchone()
        if row is None:
            return
        files = self._db.execute(
            "SELECT COUNT(*) FROM artifact_tags WHERE tag_id = ?",
            (tag_id,)).fetchone()[0]
        self._db.execute("DELETE FROM artifact_tags WHERE tag_id = ?",
                         (tag_id,))
        self._db.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
        self._db.commit()
        self._record_activity('tag removed', f"{row['name']!r}, taken off "
                              f"{files} file(s)")

    def tag_artifacts(self, tag_id, rows):
        """Put tag `tag_id` on files: rows of {'evidence_id', 'artifact_ref',
        'name', 'path'}. Returns how many were newly tagged."""
        tag = self._db.execute("SELECT name FROM tags WHERE id = ?",
                               (tag_id,)).fetchone()
        if tag is None:
            raise CaseError("No such tag.")
        now, who = _utc_now(), self.examiner
        added = []
        for row in rows:
            evidence_id = row.get('evidence_id')
            if evidence_id is not None and \
                    not self._evidence_exists(evidence_id):
                evidence_id = None
            # Asked first: NULLs are distinct in the primary key, so a file
            # with no evidence id would otherwise be tagged twice.
            if self._db.execute(
                    "SELECT 1 FROM artifact_tags WHERE tag_id = ? AND "
                    "evidence_id IS ? AND artifact_ref = ?",
                    (tag_id, evidence_id, row['artifact_ref'])).fetchone():
                continue
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO artifact_tags (tag_id, evidence_id, "
                "artifact_ref, name, path, tagged_utc, examiner) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tag_id, evidence_id, row['artifact_ref'],
                 row.get('name') or '', row.get('path') or '', now, who))
            if cursor.rowcount:
                added.append(row.get('path') or row.get('name')
                             or row['artifact_ref'])
        self._db.commit()
        if added:
            self._record_activity('files tagged', _tag_detail(
                tag['name'], added))
        return len(added)

    def untag(self, rows, tag_id=None):
        """Take tag `tag_id` (None: every tag) off files. Returns how many
        marks went."""
        removed = []
        for row in rows:
            query = ("DELETE FROM artifact_tags WHERE evidence_id IS ? AND "
                     "artifact_ref = ?")
            args = [row.get('evidence_id'), row['artifact_ref']]
            if tag_id is not None:
                query += " AND tag_id = ?"
                args.append(tag_id)
            if self._db.execute(query, args).rowcount:
                removed.append(row.get('path') or row.get('name')
                               or row['artifact_ref'])
        self._db.commit()
        if removed:
            name = 'every tag' if tag_id is None else repr(
                (self._db.execute("SELECT name FROM tags WHERE id = ?",
                                  (tag_id,)).fetchone() or {'name': '?'})
                ['name'])
            self._record_activity('files untagged', _tag_detail(name,
                                                                removed))
        return len(removed)

    def tags_for(self, evidence_id, refs):
        """{artifact_ref: [{'id', 'name', 'colour'}]} for the refs given."""
        refs = list(refs)
        found = {}
        for start in range(0, len(refs), 500):
            chunk = refs[start:start + 500]
            marks = ','.join('?' * len(chunk))
            for row in self._db.execute(
                    f"SELECT a.artifact_ref, t.id, t.name, t.colour "
                    f"FROM artifact_tags a JOIN tags t ON t.id = a.tag_id "
                    f"WHERE a.evidence_id IS ? AND a.artifact_ref IN "
                    f"({marks}) ORDER BY t.id", [evidence_id] + chunk):
                found.setdefault(row['artifact_ref'], []).append(
                    {'id': row['id'], 'name': row['name'],
                     'colour': row['colour']})
        return found

    def tagged(self, tag_id=None, evidence_id=None, limit=100000):
        """Tagged files, with their tag: newest first."""
        query = ("SELECT a.*, t.name AS tag, t.colour FROM artifact_tags a "
                 "JOIN tags t ON t.id = a.tag_id WHERE 1 = 1")
        args = []
        if tag_id is not None:
            query += " AND a.tag_id = ?"
            args.append(tag_id)
        if evidence_id is not None:
            query += " AND a.evidence_id = ?"
            args.append(evidence_id)
        query += " ORDER BY t.id, a.tagged_utc DESC, a.path LIMIT ?"
        args.append(limit)
        return [dict(row) for row in self._db.execute(query, args)]

    # --- Project VIC categories -----------------------------------------
    # The examiner's classification of a picture or video in Project VIC's
    # terms (core/vics.CATEGORIES), for the VICS export. One per file;
    # setting one replaces the last, and every change is audited.

    def set_vic_category(self, category, rows):
        """Give files (rows of {'evidence_id', 'artifact_ref', 'name',
        'path'}) category `category` (0-4). Returns how many changed."""
        from trace_app.core.vics import CATEGORIES, category_label
        if category not in CATEGORIES:
            raise CaseError(f"No Project VIC category {category!r}.")
        now, who = _utc_now(), self.examiner
        changed = []
        for row in rows:
            evidence_id = row.get('evidence_id')
            if evidence_id is not None and \
                    not self._evidence_exists(evidence_id):
                evidence_id = None
            old = self._db.execute(
                "SELECT category FROM vic_categories WHERE evidence_id IS ? "
                "AND artifact_ref = ?",
                (evidence_id, row['artifact_ref'])).fetchone()
            if old is not None and old['category'] == category:
                continue
            self._db.execute(
                "DELETE FROM vic_categories WHERE evidence_id IS ? AND "
                "artifact_ref = ?", (evidence_id, row['artifact_ref']))
            self._db.execute(
                "INSERT INTO vic_categories (evidence_id, artifact_ref, "
                "category, name, path, categorised_utc, examiner) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, row['artifact_ref'], category,
                 row.get('name') or '', row.get('path') or '', now, who))
            what = row.get('path') or row.get('name') or row['artifact_ref']
            changed.append(f"{what} (was {category_label(old['category'])})"
                           if old is not None else what)
        self._db.commit()
        if changed:
            self._record_activity('Project VIC category set', _tag_detail(
                category_label(category), changed))
        return len(changed)

    def clear_vic_category(self, rows):
        """Take the category off files (Uncategorized again)."""
        from trace_app.core.vics import category_label
        removed = []
        for row in rows:
            old = self._db.execute(
                "SELECT category FROM vic_categories WHERE evidence_id IS ? "
                "AND artifact_ref = ?",
                (row.get('evidence_id'), row['artifact_ref'])).fetchone()
            if old is None:
                continue
            self._db.execute(
                "DELETE FROM vic_categories WHERE evidence_id IS ? AND "
                "artifact_ref = ?",
                (row.get('evidence_id'), row['artifact_ref']))
            what = row.get('path') or row.get('name') or row['artifact_ref']
            removed.append(f"{what} (was {category_label(old['category'])})")
        self._db.commit()
        if removed:
            self._record_activity('Project VIC category cleared',
                                  _tag_detail('Uncategorized', removed))
        return len(removed)

    def vic_categories(self, evidence_id=None, limit=100000):
        """Categorised files, most serious category first."""
        query = "SELECT * FROM vic_categories"
        args = []
        if evidence_id is not None:
            query += " WHERE evidence_id = ?"
            args.append(evidence_id)
        query += (" ORDER BY CASE category WHEN 0 THEN 9 ELSE category END, "
                  "categorised_utc DESC, path LIMIT ?")
        args.append(limit)
        return [dict(row) for row in self._db.execute(query, args)]

    def vic_categories_for(self, evidence_id, refs=None):
        """{artifact_ref: category} for one image's files (all of them when
        `refs` is None)."""
        if refs is None:
            return {row['artifact_ref']: row['category'] for row in
                    self._db.execute(
                        "SELECT artifact_ref, category FROM vic_categories "
                        "WHERE evidence_id IS ?", (evidence_id,))}
        refs, found = list(refs), {}
        for start in range(0, len(refs), 500):
            chunk = refs[start:start + 500]
            marks = ','.join('?' * len(chunk))
            for row in self._db.execute(
                    f"SELECT artifact_ref, category FROM vic_categories "
                    f"WHERE evidence_id IS ? AND artifact_ref IN ({marks})",
                    [evidence_id] + chunk):
                found[row['artifact_ref']] = row['category']
        return found

    # --- external modules (core/modules) -----------------------------------

    def add_module_run(self, evidence_id, tool, version, executable_sha256,
                       params, folder):
        """Begin a run; returns its id. `folder` is absolute or relative to
        the case folder (kept relative). Audited."""
        if os.path.isabs(folder):
            try:
                folder = os.path.relpath(folder, self.folder)
            except ValueError:
                pass            # another drive: kept absolute
        cursor = self._db.execute(
            "INSERT INTO module_runs (evidence_id, tool, version, "
            "executable_sha256, params, folder, status, started_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, 'running', ?)",
            (evidence_id, tool, version, executable_sha256,
             json.dumps(params or {}), folder, _utc_now()))
        self._db.commit()
        self._record_activity(
            'external module run started',
            f"{tool} {version} on evidence id={evidence_id}; program SHA-256 "
            f"{executable_sha256}; folder {folder}")
        return cursor.lastrowid

    def finish_module_run(self, run_id, status, staged=None,
                          manifest_sha256=None, lava_sha256=None,
                          message='', params=None):
        if params is not None:
            self._db.execute("UPDATE module_runs SET params = ? WHERE id = ?",
                             (json.dumps(params), run_id))
        self._db.execute(
            "UPDATE module_runs SET status = ?, staged = ?, "
            "manifest_sha256 = ?, lava_sha256 = ?, finished_utc = ?, "
            "message = ? WHERE id = ?",
            (status, staged, manifest_sha256, lava_sha256, _utc_now(),
             message, run_id))
        self._db.commit()
        run = self.module_run(run_id) or {}
        self._record_activity(
            'external module run finished',
            f"{run.get('tool')} {run.get('version')} run id={run_id}: "
            f"{status}; {staged or 0} file(s) staged, manifest SHA-256 "
            f"{manifest_sha256}; LAVA database SHA-256 {lava_sha256}"
            + (f"; {message}" if message else ''))

    def set_module_run_params(self, run_id, params):
        """Replace a run's params (an import limit applied again)."""
        self._db.execute("UPDATE module_runs SET params = ? WHERE id = ?",
                         (json.dumps(params), run_id))
        self._db.commit()

    def drop_module_events(self, artifact_ids):
        """The Timeline events of these artifacts (a smaller import limit
        took them out)."""
        ids = list(artifact_ids)
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            self._db.execute(
                f"DELETE FROM module_events WHERE artifact_id IN "
                f"({','.join('?' * len(chunk))})", chunk)
        self._db.commit()

    def add_module_artifacts(self, run_id, artifacts):
        """Store a run's artifacts (lava.load's); returns {tablename: id}."""
        ids = {}
        for artifact in artifacts:
            cursor = self._db.execute(
                "INSERT INTO module_artifacts (run_id, category, name, "
                "tablename, module, columns, row_count, source_path, "
                "conversation, icon) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (run_id, artifact['category'], artifact['name'],
                 artifact['tablename'], artifact['module'],
                 json.dumps(artifact['columns']), artifact['record_count'],
                 artifact['source_path'],
                 json.dumps(artifact['conversation'])
                 if artifact.get('conversation') else None,
                 artifact.get('icon') or ''))
            ids[artifact['tablename']] = cursor.lastrowid
        self._db.commit()
        return ids

    def add_module_events(self, run_id, events):
        """Rows of (artifact_id, row_id, time_utc, label, summary),
        committed every 50,000 (one transaction of millions grew a WAL past
        a gigabyte, and the window's reads waited on it)."""
        batch, written = [], 0
        for event in events:
            batch.append((run_id,) + tuple(event))
            if len(batch) >= 2000:
                self._db.executemany(
                    "INSERT INTO module_events (run_id, artifact_id, row_id, "
                    "time_utc, label, summary) VALUES (?,?,?,?,?,?)", batch)
                written += len(batch)
                batch = []
                if written % 50000 == 0:
                    self._db.commit()
        if batch:
            self._db.executemany(
                "INSERT INTO module_events (run_id, artifact_id, row_id, "
                "time_utc, label, summary) VALUES (?,?,?,?,?,?)", batch)
        self._db.commit()

    def drop_module_activity(self, artifact_id):
        """The Activity rows an external module's artifact gave."""
        self._db.execute("DELETE FROM user_activity "
                         "WHERE module_artifact_id = ?", (artifact_id,))

    def set_module_event_kind(self, artifact_id, kind, name, primary_label):
        """Tag an artifact's Timeline events with its role; the events of
        its Activity rows' own time 'bridged' (shown once, as the row)."""
        self._db.execute("UPDATE module_events SET kind = ? "
                         "WHERE artifact_id = ?", (kind, artifact_id))
        if primary_label and kind == 'evidence':
            self._db.execute(
                "UPDATE module_events SET kind = 'bridged' "
                "WHERE artifact_id = ? AND label = ?",
                (artifact_id, f"{name}: {primary_label}"))

    def set_module_artifact_route(self, artifact_id, key, role, why,
                                  digest, version, superseded_by=None,
                                  sorted_by=''):
        self._db.execute(
            "UPDATE module_artifacts SET artifact_key = ?, role = ?, "
            "route_why = ?, content_sha256 = ?, bridged_version = ?, "
            "superseded_by = ?, sorted_by = ? WHERE id = ?",
            (key, role, why, digest, version, superseded_by, sorted_by,
             artifact_id))

    def _same_artifacts(self, evidence_id, tool, key, digest):
        return self._db.execute(
            "SELECT a.id, a.run_id FROM module_artifacts a "
            "JOIN module_runs r ON r.id = a.run_id "
            "WHERE r.evidence_id IS ? AND r.tool = ? AND r.status = "
            "'complete' AND COALESCE(NULLIF(a.artifact_key, ''), "
            "a.tablename) = ? AND a.content_sha256 = ?",
            (evidence_id, tool, key, digest)).fetchall()

    def newer_same_artifact(self, run_id, evidence_id, tool, key, digest):
        """The id of the same artifact (same rows) a newer run of the same
        tool read on the same evidence, or None."""
        newer = [row['id'] for row in self._same_artifacts(
            evidence_id, tool, key, digest) if row['run_id'] > run_id]
        return max(newer) if newer else None

    def supersede_older_artifacts(self, run_id, evidence_id, tool, key,
                                  digest, keep):
        """Older runs' copies of artifact `keep` (same rows) step aside:
        their Activity rows go, their events are tagged 'superseded'. They
        stay in the Modules tab. Returns how many."""
        older = [row['id'] for row in self._same_artifacts(
            evidence_id, tool, key, digest) if row['run_id'] < run_id]
        for artifact_id in older:
            self.drop_module_activity(artifact_id)
            self._db.execute("UPDATE module_events SET kind = 'superseded' "
                             "WHERE artifact_id = ?", (artifact_id,))
            self._db.execute("UPDATE module_artifacts SET superseded_by = ? "
                             "WHERE id = ?", (keep, artifact_id))
        return len(older)

    def unbridged_module_runs(self):
        """Complete runs with an artifact not yet sorted at the current
        ROUTES_VERSION (core/modules/bridge) -- the 'module_bridge' job's
        work when a case opens."""
        from trace_app.core.modules.routes import ROUTES_VERSION
        return [row[0] for row in self._db.execute(
            "SELECT DISTINCT r.id FROM module_runs r "
            "JOIN module_artifacts a ON a.run_id = r.id "
            "WHERE r.status = 'complete' AND a.bridged_version < ? "
            "ORDER BY r.id", (ROUTES_VERSION,))]

    def module_runs(self, evidence_id=None):
        """Runs, newest first, with an absolute `path` to their folder."""
        query, args = "SELECT * FROM module_runs", []
        if evidence_id is not None:
            query += " WHERE evidence_id = ?"
            args.append(evidence_id)
        query += " ORDER BY id DESC"
        return [self._module_run_row(row)
                for row in self._db.execute(query, args)]

    def module_run(self, run_id):
        row = self._db.execute("SELECT * FROM module_runs WHERE id = ?",
                               (run_id,)).fetchone()
        return self._module_run_row(row) if row else None

    def _module_run_row(self, row):
        row = dict(row)
        folder = row.get('folder') or ''
        row['path'] = folder if os.path.isabs(folder) else \
            os.path.join(self.folder, folder)
        try:
            row['params'] = json.loads(row.get('params') or '{}')
        except ValueError:
            row['params'] = {}
        return row

    def module_artifacts(self, run_id):
        """A run's artifacts, by category then name."""
        out = []
        for row in self._db.execute(
                "SELECT * FROM module_artifacts WHERE run_id = ? "
                "ORDER BY category, name", (run_id,)):
            row = dict(row)
            for key, empty in (('columns', '[]'), ('conversation', 'null')):
                try:
                    row[key] = json.loads(row.get(key) or empty)
                except ValueError:
                    row[key] = None
            out.append(row)
        return out

    def supersede_keyless_runs(self, evidence_id, tool, label, keep):
        """Forget complete runs of the same evidence, tool and input made
        without a key the tool wanted (input.secrets_wanted: DLEAPP's
        Signal key) -- once run `keep` has read it with the key: the new
        run holds all the old one did, and more. Audited, each."""
        gone = []
        for run in self.module_runs(evidence_id):
            given = run['params'].get('input') or {}
            if run['id'] != keep and run['tool'] == tool and \
                    given.get('label') == label and \
                    given.get('secrets_wanted'):
                self.remove_module_run(
                    run['id'], why=f"superseded by run id={keep}, which read "
                                   f"it with the key it wanted")
                gone.append(run['id'])
        return gone

    def supersede_password_runs(self, evidence_id, tool, label, keep):
        """Forget the runs an encrypted backup's password made needless:
        the same evidence, tool and input, skipped for want of its password
        or failed on a wrong one -- once run `keep` has read it. They never
        started the tool (no folder, no rows). Audited, each. Returns their
        ids."""
        gone = []
        for run in self.module_runs(evidence_id):
            given = run['params'].get('input') or {}
            if run['id'] == keep or run['tool'] != tool or \
                    given.get('label') != label:
                continue
            if run['status'] == 'skipped' or (
                    run['status'] == 'failed' and given.get('needs_password')):
                self.remove_module_run(
                    run['id'], why=f"superseded by run id={keep}, which read "
                                   f"the backup with its password")
                gone.append(run['id'])
        return gone

    def remove_module_run(self, run_id, why=''):
        """Forget a run (its artifacts and events go with it); the caller
        deletes its folder. Audited."""
        run = self.module_run(run_id)
        if run is None:
            return None
        # What this run's artifacts had superseded is sorted again (the
        # 'module_bridge' job): the older reading is the one left.
        self._db.execute(
            "UPDATE module_artifacts SET superseded_by = NULL, "
            "bridged_version = 0 WHERE superseded_by IN ("
            "SELECT id FROM module_artifacts WHERE run_id = ?)", (run_id,))
        self._db.execute("DELETE FROM module_runs WHERE id = ?", (run_id,))
        self._db.commit()
        if run.get('evidence_id') is not None:
            self.relink_matches(run['evidence_id'])
        index_path = os.path.join(self.folder, 'search.db')
        if os.path.exists(index_path):
            try:
                from trace_app.core.search_index import SearchIndex
                index = SearchIndex(self.folder)
                try:
                    index.clear_module_run(run_id)
                finally:
                    index.close()
            except Exception as exc:
                logger.warning("Search index rows of run %s not removed: %s",
                               run_id, exc)
        self._record_activity(
            'external module run removed',
            f"{run['tool']} {run['version']} run id={run_id} on evidence "
            f"id={run['evidence_id']}; folder {run['folder']}"
            + (f"; {why}" if why else ''))
        return run

    #: Rows that point at a file by ref and record where it was:
    #: (table, ref column, path column).
    _REF_ROWS = (('bookmarks', 'artifact_ref', 'artifact_path'),
                 ('artifact_tags', 'artifact_ref', 'path'),
                 ('vic_categories', 'artifact_ref', 'path'),
                 ('notes', 'artifact_ref', 'artifact_path'))

    def repair_file_refs(self, evidence_id, resolve):
        """Give the examiner's marks on one image's files (bookmarks, tags,
        Project VIC categories, notes) the ref the name entry makes --
        core/ref_repair.py: an older Listing named a deleted NTFS file its
        own way. `resolve(ref, path)` -> the new ref or None. Audited, the
        old and new ref of each. Returns how many rows changed."""
        changed = []
        for table, ref_column, path_column in self._REF_ROWS:
            rows = self._db.execute(
                f"SELECT rowid AS rid, {ref_column} AS ref, {path_column} AS path "
                f"FROM {table} WHERE evidence_id IS ? AND {ref_column} "
                f"LIKE 'p%:i%'", (evidence_id,)).fetchall()
            for row in rows:
                fixed = resolve(row['ref'], row['path'] or '')
                if not fixed or fixed == row['ref']:
                    continue
                # A mark already on the fixed ref (made since) wins; the
                # old row then goes rather than becoming a duplicate.
                updated = self._db.execute(
                    f"UPDATE OR IGNORE {table} SET {ref_column} = ? "
                    f"WHERE rowid = ?", (fixed, row['rid'])).rowcount
                if not updated:
                    self._db.execute(f"DELETE FROM {table} WHERE rowid = ?",
                                     (row['rid'],))
                changed.append(f"{table}: {row['path'] or row['ref']} "
                               f"{row['ref']} -> {fixed}")
        if not changed:
            return 0
        self._db.commit()
        shown = '; '.join(changed[:20])
        more = f" and {len(changed) - 20} more" if len(changed) > 20 else ''
        self._record_activity(
            'file references updated',
            f"evidence id={evidence_id}: {len(changed)} mark(s) on deleted "
            f"files now use the name entry's sequence, as the rest of TRACE "
            f"does: {shown}{more}")
        return len(changed)

    def vics_comments(self, evidence_id):
        """{artifact_ref: text} of one image's files: each bookmark's label
        and the notes written on the file or its bookmark -- what the VICS
        export writes as a picture's Comments."""
        texts = {}

        def add(ref, text):
            text = ' '.join((text or '').split())
            if ref and text and text not in texts.setdefault(ref, []):
                texts[ref].append(text)
        marks = {}
        for row in self._db.execute(
                "SELECT id, artifact_ref, label FROM bookmarks "
                "WHERE evidence_id IS ? ORDER BY id", (evidence_id,)):
            marks[row['id']] = row['artifact_ref']
            add(row['artifact_ref'], f"Bookmark: {row['label']}"
                if row['label'] else '')
        for row in self._db.execute(
                "SELECT artifact_ref, bookmark_id, body FROM notes "
                "WHERE evidence_id IS ? ORDER BY id", (evidence_id,)):
            ref = row['artifact_ref'] or marks.get(row['bookmark_id'])
            add(ref, f"Note: {row['body']}")
        return {ref: ' | '.join(parts) for ref, parts in texts.items()}

    # --- notes ------------------------------------------------------------

    def add_note(self, body, evidence_id=None, artifact_ref=None,
                 artifact_name='', artifact_path='', bookmark_id=None):
        """Write a note. Returns its id.

        Everything except the body is optional, which is the point: a note may
        be about one file, about a bookmark, or about the case as a whole, and
        an examiner should not have to select something before recording a
        thought.
        """
        now = _utc_now()
        # An evidence id that no longer exists must not cost the examiner the
        # note. The reference is dropped and the note kept: analysis is the
        # part that cannot be recovered by re-running anything.
        if evidence_id is not None and not self._evidence_exists(evidence_id):
            logger.warning("Note references unknown evidence %s; keeping the "
                           "note without it", evidence_id)
            evidence_id = None
        if bookmark_id is not None and not self._bookmark_exists(bookmark_id):
            bookmark_id = None

        cursor = self._db.execute(
            "INSERT INTO notes (evidence_id, artifact_ref, artifact_name,"
            " artifact_path, body, created_utc, updated_utc, bookmark_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, artifact_ref, artifact_name, artifact_path, body,
             now, now, bookmark_id))
        self._db.commit()
        # The whole text: the audit trail is where a note's history is
        # kept once it is edited or removed.
        self._record_activity(
            'note added',
            f"id={cursor.lastrowid} on {artifact_name or 'the case'}: "
            f"{body}")
        return cursor.lastrowid

    def notes(self, evidence_id=None, artifact_ref=None, bookmark_id=None):
        """Notes, newest first, filtered by whatever is given.

        With no arguments this returns every note in the case, which is what
        the report needs.
        """
        clauses, params = [], []
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if artifact_ref is not None:
            clauses.append("artifact_ref = ?")
            params.append(artifact_ref)
        if bookmark_id is not None:
            clauses.append("bookmark_id = ?")
            params.append(bookmark_id)

        sql = "SELECT * FROM notes"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return [dict(row) for row in self._db.execute(sql, params).fetchall()]


    def update_note(self, note_id, body):
        """Rewrite a note's body, stamping when it changed."""
        old = self._db.execute("SELECT body FROM notes WHERE id = ?",
                               (note_id,)).fetchone()
        if old is None or old['body'] == body:
            return
        self._db.execute(
            "UPDATE notes SET body = ?, updated_utc = ? WHERE id = ?",
            (body, _utc_now(), note_id))
        self._db.commit()
        # Old and new in full: a finding's wording, once changed, is
        # otherwise gone.
        self._record_activity('note edited',
                              f"id={note_id}: {old['body']!r} -> {body!r}")

    def remove_note(self, note_id):
        old = self._db.execute("SELECT body FROM notes WHERE id = ?",
                               (note_id,)).fetchone()
        self._db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        self._db.commit()
        if old is not None:
            self._record_activity('note removed',
                                  f"id={note_id}: {old['body']!r}")

    def _evidence_exists(self, evidence_id):
        return self._db.execute(
            "SELECT 1 FROM evidence WHERE id = ?",
            (evidence_id,)).fetchone() is not None

    def _bookmark_exists(self, bookmark_id):
        return self._db.execute(
            "SELECT 1 FROM bookmarks WHERE id = ?",
            (bookmark_id,)).fetchone() is not None

    # --- audit ------------------------------------------------------------

    def activity(self, limit=200):
        """The most recent audit entries, newest first."""
        rows = self._db.execute(
            "SELECT * FROM activity ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(row) for row in rows]

    def record_event(self, action, detail=''):
        """Write a line to the audit trail (see _record_activity)."""
        self._record_activity(action, detail)

    def _record_activity(self, action, detail=''):
        """Append to the audit trail, chained.

        Each entry records who (the examiner named in Settings, and the
        operating-system account), with what (TRACE's version), and the
        SHA-256 of the entry before it: `entry_hash` covers the entry's own
        fields and `prev_hash`, so changing, removing or reordering any
        entry breaks every hash after it (`verify_audit`). Triggers refuse
        UPDATE and DELETE on the table (`_custody_guards`). The chain step
        runs inside one write lock, so jobs writing from other processes
        cannot interleave.

        Deliberately swallows its own failures, logged as errors: an audit
        line must never be the reason a case operation fails, and the
        operation itself is the thing the examiner asked for.
        """
        try:
            if self._db.in_transaction:
                self._db.commit()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                last = self._db.execute(
                    "SELECT id, entry_hash FROM activity ORDER BY id DESC "
                    "LIMIT 1").fetchone()
                sequence = self._db.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = 'activity'"
                ).fetchone()
                entry = {'id': max(last['id'] if last else 0,
                                   sequence['seq'] if sequence else 0) + 1,
                         'utc': _utc_now(), 'action': action,
                         'detail': str(detail),
                         'examiner': self._examiner(),
                         'account': _account(), 'tool': _tool(),
                         'prev_hash': (last['entry_hash'] or '') if last
                         else ''}
                entry['entry_hash'] = audit_hash(entry)
                self._db.execute(
                    "INSERT INTO activity (id, utc, action, detail, "
                    "examiner, account, tool, prev_hash, entry_hash) VALUES "
                    "(:id, :utc, :action, :detail, :examiner, :account, "
                    ":tool, :prev_hash, :entry_hash)", entry)
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise
        except sqlite3.Error as exc:
            logger.error("Could not record activity %r: %s", action, exc)

    def _examiner(self):
        """The examiner using TRACE now: Settings' name, else the case's."""
        try:
            from trace_app.core import settings
            name = settings.user('examiner')
        except Exception:
            name = ''
        return (name or self._get('examiner', '') or '').strip()

    def verify_audit(self):
        """Check the audit trail's chain. Returns {'ok', 'entries',
        'head', 'problems', 'started'}: `head` is the newest entry's hash
        (a report states it, so a trail cut short after the report can be
        told); `problems` names each entry whose hash or link fails;
        `started` is the first entry written chained (entries migrated
        from before schema 18 were chained when migrated, which the trail
        itself says)."""
        rows = self._db.execute(
            "SELECT * FROM activity ORDER BY id").fetchall()
        problems, previous, previous_id = [], '', 0
        for row in rows:
            row = dict(row)
            if row['id'] != previous_id + 1 and previous_id:
                problems.append(f"entries {previous_id + 1:,} to "
                                f"{row['id'] - 1:,} are missing")
            if (row.get('prev_hash') or '') != previous:
                problems.append(f"entry {row['id']:,} does not follow the "
                                f"one before it (changed, removed or "
                                f"reordered)")
            if audit_hash(row) != row.get('entry_hash'):
                problems.append(f"entry {row['id']:,} ({row['action']}) "
                                f"was altered after it was written")
            previous, previous_id = row.get('entry_hash') or '', row['id']
        return {'ok': not problems, 'entries': len(rows), 'head': previous,
                'problems': problems}

    def _custody_guards(self):
        """Triggers that keep the custody record append-only: no UPDATE or
        DELETE of an audit entry; a verification row is never changed,
        except that removing its evidence detaches it (evidence_id NULL --
        its name stays) rather than deleting it. Anyone can still edit the
        database file by hand; the audit chain is what shows it."""
        self._db.executescript("""
            CREATE TRIGGER IF NOT EXISTS activity_no_update
            BEFORE UPDATE ON activity BEGIN
                SELECT RAISE(ABORT, 'the audit trail is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS activity_no_delete
            BEFORE DELETE ON activity BEGIN
                SELECT RAISE(ABORT, 'the audit trail is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS verifications_no_update
            BEFORE UPDATE ON verifications
            WHEN NOT (NEW.evidence_id IS NULL AND NEW.id IS OLD.id
                      AND NEW.evidence_name IS OLD.evidence_name
                      AND NEW.utc IS OLD.utc
                      AND NEW.algorithm IS OLD.algorithm
                      AND NEW.expected IS OLD.expected
                      AND NEW.computed IS OLD.computed
                      AND NEW.status IS OLD.status
                      AND NEW.detail IS OLD.detail) BEGIN
                SELECT RAISE(ABORT, 'verification history is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS verifications_no_delete
            BEFORE DELETE ON verifications BEGIN
                SELECT RAISE(ABORT, 'verification history is append-only');
            END;
        """)
        self._db.commit()

    # --- schema -----------------------------------------------------------

    # --- analysis modules -------------------------------------------

    def picture_hashes(self, evidence_id=None):
        """Every picture with a perceptual hash: [{evidence_id,
        artifact_ref, name, path, size, is_deleted, phash}]."""
        return query_picture_hashes(self._db, evidence_id)

    def add_analysis_batch(self, evidence_id, rows):
        """Record what the modules found, for a batch of files.

        A batch rather than a row at a time: a commit per file turns a
        20,000-file image into 20,000 transactions and the walk ends up
        spending its time in SQLite rather than reading evidence.

        Each row is `(artifact_ref, name, path, is_deleted, facts)`, where
        `facts` holds whatever the selected modules produced -- a module that
        was not selected leaves its columns NULL rather than zero, so "not
        measured" stays distinguishable from "measured as nothing".
        """
        now = _utc_now()
        payload = []
        for ref, name, path, deleted, facts in rows:
            payload.append((
                evidence_id, ref, name, path, facts.get('size'),
                1 if deleted else 0,
                facts.get('mime'), facts.get('extension'),
                facts.get('mismatch'), facts.get('entropy'),
                facts.get('entropy_peak'), facts.get('entropy_peak_offset'),
                facts.get('md5'), facts.get('sha256'), facts.get('note'),
                now, facts.get('sha1'), facts.get('phash')))

        self._db.executemany(
            "INSERT OR REPLACE INTO file_analysis "
            "(evidence_id, artifact_ref, name, path, size, is_deleted, "
            " mime, extension, mismatch, entropy, entropy_peak, "
            " entropy_peak_offset, md5, sha256, note, analysed_utc, sha1, "
            " phash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", payload)

        # Findings ride the same batch and the same commit, so a file's row
        # and what was found in it are never written apart.
        findings = []
        for ref, name, path, _deleted, facts in rows:
            for module, kind, grade, summary, detail in \
                    facts.get('findings') or ():
                findings.append((evidence_id, ref, name, path,
                                 facts.get('size'), module, kind, grade,
                                 summary, detail, now))
        if findings:
            self._db.executemany(
                "INSERT INTO file_findings (evidence_id, artifact_ref, name, "
                "path, size, module, kind, grade, summary, detail, "
                "analysed_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?)", findings)
        self._db.commit()

    def clear_analysis(self, evidence_id):
        """Drop a previous run's findings for one piece of evidence."""
        # Carved files' analysis belongs to the carve that wrote it
        # (paths '[carved]/...'): the file analysis walks the file systems
        # and would not put it back.
        self._db.execute("DELETE FROM file_analysis WHERE evidence_id = ? "
                         f"AND path NOT LIKE '{CARVED_PATHS}'", (evidence_id,))
        # Modules with jobs of their own keep their findings: re-running
        # the file analysis must not erase a YARA scan or the NTFS read.
        marks = ','.join('?' * len(OWN_JOB_MODULES))
        self._db.execute("DELETE FROM file_findings WHERE evidence_id = ? "
                         f"AND module NOT IN ({marks}) "
                         f"AND path NOT LIKE '{CARVED_PATHS}'",
                         (evidence_id, *OWN_JOB_MODULES))
        self._db.commit()

    def clear_findings(self, evidence_id, module):
        """Drop one module's findings for one piece of evidence."""
        self._db.execute("DELETE FROM file_findings WHERE evidence_id = ? "
                         "AND module = ?", (evidence_id, module))
        self._db.commit()

    def add_module_findings(self, evidence_id, module, rows):
        """rows: (ref, name, path, size, kind, grade, summary, detail)."""
        if not rows:
            return
        now = _utc_now()
        self._db.executemany(
            "INSERT INTO file_findings (evidence_id, artifact_ref, name, "
            "path, size, module, kind, grade, summary, detail, "
            "analysed_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id, *row[:4], module, *row[4:], now)
             for row in rows])
        self._db.commit()

    def commit(self):
        """Flush pending writes. Named for what the walk needs to call."""
        self._db.commit()

    def set_analysis_state(self, evidence_id, status, modules=None,
                           files_done=None, files_total=None, last_error=None):
        """Record how far a run got, so a cancelled one can be resumed."""
        existing = self.analysis_state(evidence_id) or {}
        self._db.execute(
            "INSERT OR REPLACE INTO analysis_state "
            "(evidence_id, status, modules, files_done, files_total, "
            " last_error, updated_utc) VALUES (?,?,?,?,?,?,?)",
            (evidence_id, status,
             modules if modules is not None else existing.get('modules'),
             files_done if files_done is not None
             else existing.get('files_done', 0),
             files_total if files_total is not None
             else existing.get('files_total', 0),
             last_error, _utc_now()))
        self._db.commit()

        if status in ('done', 'cancelled', 'failed'):
            self._record_activity(
                f"analysis {status}",
                f"evidence id={evidence_id} files={files_done or 0}"
                + (f" error={last_error}" if last_error else ''))

    def analysis_state(self, evidence_id):
        """How the last run on this evidence ended, or None."""
        row = self._db.execute(
            "SELECT * FROM analysis_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None

    # --- what the users did (core/activity) --------------------------

    def clear_user_activity(self, evidence_id):
        """TRACE's own activity rows of an image -- not what an external
        module read (core/modules/bridge), which goes with its run."""
        self._db.execute("DELETE FROM user_activity WHERE evidence_id = ? "
                         "AND module_run_id IS NULL", (evidence_id,))
        self._db.commit()

    def add_user_activity(self, evidence_id, records, module_run_id=None,
                          module_artifact_id=None, reader='TRACE'):
        """Store records made by core.activity.record() -- TRACE's own, or
        (`module_run_id`, its artifact, `reader` the tool) an external
        module's. Each gets its record key (core/activity_match); call
        relink_matches once the image's rows are in."""
        from trace_app.core.activity_match import match_key
        self._db.executemany(
            "INSERT INTO user_activity (evidence_id, category, what, "
            "time_utc, time_local, subject, user, detail, source, "
            "source_path, source_ref, reader, module_run_id, "
            "module_artifact_id, match_key) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id, r['category'], r['what'], r['time'],
              1 if r.get('local') else 0, r['subject'], r.get('user', ''),
              json.dumps(r.get('detail') or {}, default=str), r['source'],
              r.get('path', ''), r.get('ref', ''), reader or 'TRACE',
              module_run_id, module_artifact_id, match_key(r))
             for r in records])

    def relink_matches(self, evidence_id):
        """Link the image's readings of one record (same match_key) made by
        different readers: each points at one primary (TRACE's own reading
        if there is one, else the first imported). Two readings by the same
        reader are two records (a message really sent twice), so a key is
        counted per reading -- per reader, and per run and artifact of a
        tool: the n-th of one matches the n-th of another. (aLEAPP's 'SMS
        and MMS Messages' repeats its 'SMS Messages': one record, read
        twice.) Set-wise; run after anything changes the image's rows.
        With the case setting module_link_readings off, every reading is
        a row of its own."""
        from trace_app.core import settings as case_settings
        self._db.execute("UPDATE user_activity SET duplicate_of = NULL "
                         "WHERE evidence_id = ? AND duplicate_of IS NOT NULL",
                         (evidence_id,))
        if not case_settings.current('module_link_readings'):
            self._db.commit()
            return
        self._db.execute("DROP TABLE IF EXISTS temp.match_ranks")
        self._db.execute(
            "CREATE TEMP TABLE match_ranks AS "
            "SELECT id, match_key, occurrence, FIRST_VALUE(id) OVER ("
            "  PARTITION BY match_key, occurrence "
            "  ORDER BY (reader != 'TRACE'), id) AS primary_id "
            "FROM (SELECT id, match_key, reader, ROW_NUMBER() OVER ("
            "  PARTITION BY match_key, reader, COALESCE(module_run_id, 0), "
            "  COALESCE(module_artifact_id, 0) ORDER BY id) AS occurrence "
            "  FROM user_activity WHERE evidence_id = ? "
            "  AND match_key IS NOT NULL)", (evidence_id,))
        self._db.execute(
            "UPDATE user_activity SET duplicate_of = ("
            "  SELECT primary_id FROM temp.match_ranks r "
            "  WHERE r.id = user_activity.id) "
            "WHERE id IN (SELECT id FROM temp.match_ranks "
            "             WHERE primary_id != id)")
        self._db.execute("DROP TABLE IF EXISTS temp.match_ranks")
        self._db.commit()

    def readings(self, activity_id):
        """Every reading of one record: the primary and the rows linked to
        it, each with its reader -- what the details pane lists."""
        rows = query_user_activity(self._db, primary_only=False,
                                   ids_of=activity_id)
        return sorted(rows, key=lambda r: (r['id'] != activity_id, r['id']))

    def activity_readers(self):
        """The readers a case's activity has: 'TRACE' and each tool."""
        return [row[0] for row in self._db.execute(
            "SELECT DISTINCT reader FROM user_activity ORDER BY "
            "reader != 'TRACE', reader")]

    def user_activity(self, evidence_id=None, category=None, limit=None):
        """Activity rows, newest first, `detail` parsed."""
        return query_user_activity(self._db, evidence_id, category,
                                   limit=limit)

    def _communication(self, evidence_id=None):
        """Messages and calls -- TRACE's own and what external modules read
        (core/modules/bridge stores those as activity rows), one row per
        record whoever read it."""
        return query_user_activity(self._db, evidence_id, 'communication')

    def conversations(self, evidence_id=None):
        """Messages and calls grouped into threads (core/conversations)."""
        from trace_app.core import conversations
        return conversations.threads(self._communication(evidence_id))

    def conversation(self, key, evidence_id=None):
        """One thread's rows, oldest first (core/conversations.messages)."""
        from trace_app.core import conversations
        return conversations.messages(self._communication(evidence_id), key)

    def located_activity(self, evidence_id=None):
        """Activity rows whose detail holds a latitude and longitude, for
        the map (core/geo.py checks the values themselves)."""
        return query_user_activity(self._db, evidence_id, located=True)

    def user_activity_summary(self, evidence_id=None):
        """{category: rows} for the tree and the tab labels."""
        where = " WHERE duplicate_of IS NULL"
        params = []
        if evidence_id is not None:
            where += " AND evidence_id = ?"
            params.append(evidence_id)
        # One per record, as the Activity tab lists them (a record two
        # readers read is one row).
        return {row[0]: row[1] for row in self._db.execute(
            f"SELECT category, COUNT(*) FROM user_activity{where} "
            "GROUP BY category", params)}

    def set_user_activity_state(self, evidence_id, status, records=0,
                                last_error=None):
        self._db.execute(
            "INSERT OR REPLACE INTO user_activity_state (evidence_id, status, "
            "records, last_error, updated_utc) VALUES (?,?,?,?,?)",
            (evidence_id, status, records, last_error, _utc_now()))
        self._db.commit()
        if status in ('done', 'cancelled', 'failed'):
            self._record_activity(
                f"user activity {status}",
                f"evidence id={evidence_id} records={records}"
                + (f" error={last_error}" if last_error else ''))

    def activity_span(self, evidence_id):
        """(earliest, latest) UTC time of the evidence's activity records,
        or (None, None). Local-time records are left out: they have no
        zone to compare."""
        row = self._db.execute(
            "SELECT MIN(time_utc), MAX(time_utc) FROM user_activity WHERE "
            "evidence_id = ? AND time_utc IS NOT NULL AND time_local = 0",
            (evidence_id,)).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def activity_users(self, evidence_id, limit=8):
        """[(user, records)] -- the accounts activity names, most first."""
        return [tuple(row) for row in self._db.execute(
            "SELECT user, COUNT(*) FROM user_activity WHERE evidence_id = ? "
            "AND user IS NOT NULL AND user != '' GROUP BY user "
            "ORDER BY COUNT(*) DESC LIMIT ?", (evidence_id, limit))]

    def last_audited(self, action, evidence_id):
        """When the audit trail last recorded `action` for this evidence
        (its detail begins 'evidence id=<id> '), or None -- for jobs that
        leave no state row, so 'ran and found nothing' is told from
        'never ran'."""
        row = self._db.execute(
            "SELECT utc FROM activity WHERE action = ? AND (detail = ? OR "
            "detail LIKE ?) ORDER BY id DESC LIMIT 1",
            (action, f"evidence id={evidence_id}",
             f"evidence id={evidence_id} %")).fetchone()
        return row[0] if row else None

    def finding_module_counts(self, evidence_id):
        """{module: findings} for one evidence."""
        return {row[0]: row[1] for row in self._db.execute(
            "SELECT module, COUNT(*) FROM file_findings WHERE "
            "evidence_id = ? GROUP BY module", (evidence_id,))}

    def user_activity_state(self, evidence_id):
        row = self._db.execute(
            "SELECT * FROM user_activity_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None

    # --- NTFS internals ------------------------------------------------

    def clear_ntfs(self, evidence_id):
        # Only NTFS's own rows: the other file systems' times
        # (core/fs_times, sources 'FS' / 'FS-local') are another module's.
        self._db.execute("DELETE FROM fs_events WHERE evidence_id = ? AND "
                         "source IN ('SI', 'FN', 'I30')", (evidence_id,))
        self._db.execute("DELETE FROM usn_journal WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.execute("DELETE FROM file_findings WHERE evidence_id = ? "
                         "AND module = 'ntfs'", (evidence_id,))
        self._db.commit()

    def clear_fs_times(self, evidence_id):
        """Drop core/fs_times' rows for one image (not NTFS's)."""
        self._db.execute("DELETE FROM fs_events WHERE evidence_id = ? AND "
                         "source IN ('FS', 'FS-local')", (evidence_id,))
        self._db.commit()

    def add_fs_events(self, evidence_id, rows):
        """rows: (ref, path, time, macb, source, deleted) -- source 'SI',
        'FN' or 'I30' from NTFS; 'FS' or 'FS-local' (no zone) from
        core/fs_times for every other file system."""
        self._db.executemany(
            "INSERT INTO fs_events (evidence_id, artifact_ref, path, time_utc, "
            "macb, source, deleted) VALUES (?,?,?,?,?,?,?)",
            [(evidence_id,) + tuple(row) for row in rows])

    def add_usn_records(self, evidence_id, rows):
        """rows from core.ntfs.usn_row()."""
        self._db.executemany(
            "INSERT INTO usn_journal (evidence_id, usn, time_utc, "
            "artifact_ref, file_entry, file_sequence, parent_entry, "
            "parent_sequence, name, path, reasons, reason_flags, attributes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id,) + tuple(row) for row in rows])

    def add_ntfs_findings(self, evidence_id, rows):
        """rows: (ref, name, path, size, kind, grade, summary, detail)."""
        now = _utc_now()
        self._db.executemany(
            "INSERT INTO file_findings (evidence_id, artifact_ref, name, "
            "path, size, module, kind, grade, summary, detail, "
            "analysed_utc) VALUES (?,?,?,?,?,'ntfs',?,?,?,?,?)",
            [(evidence_id,) + tuple(row) + (now,) for row in rows])

    def set_ntfs_state(self, evidence_id, status, volumes=0, entries=0,
                       events=0, journal=0, last_error=None):
        self._db.execute(
            "INSERT OR REPLACE INTO ntfs_state (evidence_id, status, volumes, "
            "entries, events, journal, last_error, updated_utc) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (evidence_id, status, volumes, entries, events, journal,
             last_error, _utc_now()))
        self._db.commit()
        if status in ('done', 'cancelled', 'failed'):
            self._record_activity(
                f"ntfs analysis {status}",
                f"evidence id={evidence_id} volumes={volumes} "
                f"entries={entries} time events={events} journal={journal}"
                + (f" error={last_error}" if last_error else ''))

    def ntfs_state(self, evidence_id):
        row = self._db.execute(
            "SELECT * FROM ntfs_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None

    def fs_events_for(self, evidence_id, artifact_ref):
        """Both sets of times for one file, oldest first."""
        return [dict(row) for row in self._db.execute(
            "SELECT * FROM fs_events WHERE evidence_id = ? AND "
            "artifact_ref = ? ORDER BY time_utc", (evidence_id, artifact_ref))]

    def ntfs_counts(self, evidence_id=None):
        return ntfs_counts(self._db, evidence_id)

    def ntfs_rows(self, section, evidence_id=None, text='',
                  include_routine=False, limit=None):
        return query_ntfs(self._db, section, evidence_id, text,
                          include_routine, limit)

    def usn_records(self, evidence_id=None, text=None, limit=5000):
        """Change-journal records, newest first."""
        query = "SELECT * FROM usn_journal WHERE 1 = 1"
        params = []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if text:
            query += " AND (name LIKE ? OR path LIKE ? OR reasons LIKE ?)"
            params.extend([f'%{text}%'] * 3)
        query += " ORDER BY time_utc DESC, usn DESC LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self._db.execute(query, params)]

    # --- timeline marks (schema 21) -------------------------------------------

    #: A mark's colours, by name: the Timeline's menu and the report.
    MARK_COLOURS = {'red': '#E5534B', 'orange': '#E8743B',
                    'yellow': '#E3A008', 'green': '#3FB950',
                    'blue': '#4C8BF5', 'purple': '#9B6CF0'}

    def mark_events(self, rows, starred=None, colour=None, comment=None):
        """Star, colour or comment on timeline events (timeline rows).
        None leaves that part as it was; colour '' and comment '' clear.
        A mark left with nothing is removed. Audited: what was marked, and
        a comment's text old -> new (the audit trail is its history).
        Returns how many marks changed."""
        from trace_app.core import timeline
        now = _utc_now()
        examiner = self._examiner()
        changed, lines = 0, []
        for row in rows:
            key = timeline.event_key(row)
            old = self._db.execute(
                "SELECT starred, colour, comment FROM timeline_marks WHERE "
                "event_key = ?", (key,)).fetchone()
            was = (bool(old[0]), old[1] or '', old[2] or '') if old \
                else (False, '', '')
            new = (was[0] if starred is None else bool(starred),
                   was[1] if colour is None else (colour or ''),
                   was[2] if comment is None else (comment or '').strip())
            if new == was:
                continue
            changed += 1
            if not any(new):
                self._db.execute("DELETE FROM timeline_marks WHERE "
                                 "event_key = ?", (key,))
            else:
                self._db.execute(
                    "INSERT INTO timeline_marks (event_key, evidence_id, "
                    "source, time, local, kind, title, subject, user, "
                    "artifact_ref, deleted, starred, colour, comment, "
                    "examiner, updated_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,"
                    "?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET "
                    "starred = excluded.starred, colour = excluded.colour, "
                    "comment = excluded.comment, examiner = "
                    "excluded.examiner, updated_utc = excluded.updated_utc",
                    (key, row.get('evidence_id'), row.get('source'),
                     row.get('time'), 1 if row.get('local') else 0,
                     row.get('kind'), row.get('title'), row.get('subject'),
                     row.get('user'), row.get('artifact_ref'),
                     1 if row.get('deleted') else 0, 1 if new[0] else 0,
                     new[1] or None, new[2] or None, examiner, now))
            what = f"{row.get('time') or ''} {timeline.describe_kind(row)}" \
                f" {row.get('title') or row.get('subject') or ''}".strip()
            parts = []
            if new[0] != was[0]:
                parts.append('starred' if new[0] else 'unstarred')
            if new[1] != was[1]:
                parts.append(f"colour {was[1] or 'none'} -> "
                             f"{new[1] or 'none'}")
            if new[2] != was[2]:
                parts.append(f"comment {was[2]!r} -> {new[2]!r}")
            lines.append(f"{what} (evidence id={row.get('evidence_id')}): "
                         + ', '.join(parts))
        self._db.commit()
        if lines:
            self._record_activity('timeline events marked',
                                  '; '.join(lines[:50]) +
                                  (f"; and {len(lines) - 50} more"
                                   if len(lines) > 50 else ''))
        return changed

    def timeline_marks(self, starred_only=False):
        """{event_key: mark dict} -- every mark, or the starred ones."""
        query = "SELECT * FROM timeline_marks"
        if starred_only:
            query += " WHERE starred = 1"
        query += " ORDER BY time"
        cursor = self._db.execute(query)
        names = [d[0] for d in cursor.description]
        return {row[names.index('event_key')]: dict(zip(names, row))
                for row in cursor}

    # --- items picked for the report -----------------------------------

    def add_report_items(self, kind, items):
        """Remember rows the examiner chose for the report. `items` are
        dicts with evidence_id, artifact_ref, time, title and detail; a row
        already chosen is not added twice."""
        now = _utc_now()
        added = 0
        for item in items:
            exists = self._db.execute(
                "SELECT 1 FROM report_items WHERE kind = ? AND "
                "IFNULL(evidence_id, -1) = IFNULL(?, -1) AND "
                "IFNULL(artifact_ref, '') = IFNULL(?, '') AND "
                "IFNULL(time_utc, '') = IFNULL(?, '') AND title = ?",
                (kind, item.get('evidence_id'), item.get('artifact_ref'),
                 item.get('time'), item.get('title') or '')).fetchone()
            if exists:
                continue
            self._db.execute(
                "INSERT INTO report_items (kind, evidence_id, artifact_ref, "
                "time_utc, title, detail, added_utc) VALUES (?,?,?,?,?,?,?)",
                (kind, item.get('evidence_id'), item.get('artifact_ref'),
                 item.get('time'), item.get('title') or '',
                 json.dumps(item.get('detail') or {}, default=str), now))
            added += 1
        self._db.commit()
        if added:
            self._record_activity('added to report',
                                  f"{added} {kind} item(s)")
        return added

    def report_items(self, kind=None):
        query = "SELECT * FROM report_items"
        params = []
        if kind:
            query += " WHERE kind = ?"
            params.append(kind)
        rows = []
        for row in self._db.execute(query + " ORDER BY time_utc, id",
                                    params):
            row = dict(row)
            try:
                row['detail'] = json.loads(row.get('detail') or '{}')
            except ValueError:
                row['detail'] = {}
            rows.append(row)
        return rows

    def remove_report_items(self, ids):
        ids = list(ids)
        if not ids:
            return
        self._db.execute(
            f"DELETE FROM report_items WHERE id IN ({','.join('?' * len(ids))})",
            ids)
        self._db.commit()

    # --- persistence -------------------------------------------------

    def replace_persistence(self, evidence_id, entries):
        """Store core.persistence entries for one image, replacing any."""
        def flag(value):
            return None if value is None else (1 if value else 0)

        def when(value):
            return value.strftime('%Y-%m-%d %H:%M:%S') if hasattr(
                value, 'strftime') else (value or None)
        self._db.execute("DELETE FROM persistence WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.executemany(
            "INSERT INTO persistence (evidence_id, location, name, command, "
            "target, target_ref, user, time_utc, enabled, target_exists, "
            "signed, sha256, hash_category, grade, reasons, source, "
            "source_ref, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id, e['location'], e['name'], e['command'],
              e.get('target'), e.get('target_ref'), e.get('user'),
              when(e.get('when')), flag(e.get('enabled')),
              flag(e.get('exists')), flag(e.get('signed')), e.get('sha256'),
              e.get('hash_category'), e['grade'],
              json.dumps(e.get('reasons') or []), e.get('source'),
              e.get('source_ref'), json.dumps(e.get('detail') or {},
                                              default=str))
             for e in entries])
        self._db.commit()

    # --- thumbnail caches ------------------------------------------------

    _THUMBNAIL_COLUMNS = (
        'cache_ref', 'cache_path', 'cache_kind', 'cache_size',
        'cache_deleted', 'system', 'user', 'key', 'location', 'name',
        'original_state', 'original_ref', 'modified_utc', 'width', 'height',
        'format', 'size', 'sha256')

    def replace_thumbnails(self, evidence_id, rows):
        """Store core.thumbnails rows for one image, replacing any."""
        columns = self._THUMBNAIL_COLUMNS
        self._db.execute("DELETE FROM thumbnails WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.executemany(
            f"INSERT INTO thumbnails (evidence_id, {', '.join(columns)}, "
            f"detail) VALUES ({','.join('?' * (len(columns) + 2))})",
            [(evidence_id, *(row.get(c) for c in columns),
              json.dumps(row.get('detail') or {}, default=str))
             for row in rows])
        self._db.commit()

    def thumbnails(self, evidence_id=None, cache_ref=None, gone_only=False,
                   limit=200000):
        """Thumbnail rows: Thumbs.db pictures of files that are gone first,
        then by cache and position."""
        query, params = "SELECT * FROM thumbnails WHERE 1 = 1", []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if cache_ref is not None:
            query += " AND cache_ref = ?"
            params.append(cache_ref)
        if gone_only:
            query += " AND original_state IN ('absent', 'deleted')"
        query += (" ORDER BY CASE original_state WHEN 'absent' THEN 0 "
                  "WHEN 'deleted' THEN 1 ELSE 2 END, cache_path, id LIMIT ?")
        params.append(limit)
        rows = []
        for row in self._db.execute(query, params):
            row = dict(row)
            try:
                row['detail'] = json.loads(row.get('detail') or '{}')
            except ValueError:
                row['detail'] = {}
            rows.append(row)
        return rows

    def thumbnail_counts(self, evidence_id=None):
        """{'pictures': n, 'caches': n, 'gone': n}."""
        where, params = '', []
        if evidence_id is not None:
            where, params = " WHERE evidence_id = ?", [evidence_id]
        row = self._db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT evidence_id || ':' || "
            "cache_ref), SUM(original_state IN ('absent', 'deleted')) "
            "FROM thumbnails" + where, params).fetchone()
        return {'pictures': row[0] or 0, 'caches': row[1] or 0,
                'gone': row[2] or 0}

    def persistence(self, evidence_id=None, include_benign=True, text=''):
        return query_persistence(self._db, evidence_id, include_benign, text)

    def persistence_counts(self, evidence_id=None):
        where, params = '', []
        if evidence_id is not None:
            where, params = " WHERE evidence_id = ?", [evidence_id]
        return {row[0]: row[1] for row in self._db.execute(
            "SELECT grade, COUNT(*) FROM persistence" + where
            + " GROUP BY grade", params)}

    # --- hash sets ----------------------------------------------------

    def hashed_files(self, evidence_id, include_carved=True):
        """Every file with a digest: analysed files (MD5, SHA-1, SHA-256)
        and, if asked, carved files (SHA-256), as dicts with `origin`."""
        rows = [dict(row, origin='file') for row in self._db.execute(
            "SELECT artifact_ref, name, path, size, md5, sha1, sha256 "
            "FROM file_analysis WHERE evidence_id = ? AND "
            "(md5 IS NOT NULL OR sha256 IS NOT NULL)", (evidence_id,))]
        if include_carved:
            rows.extend(dict(row, origin='carved', md5=None, sha1=None)
                        for row in self._db.execute(
                "SELECT artifact_ref, name, path, size, sha256 FROM "
                "carved_files WHERE evidence_id = ? AND sha256 IS NOT NULL",
                (evidence_id,)))
        return rows

    def clear_hash_matches(self, evidence_id):
        self._db.execute("DELETE FROM hash_matches WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.commit()

    def replace_hash_matches(self, evidence_id, rows):
        """rows: (ref, name, path, size, origin, set id, set name,
        category, algorithm, digest)."""
        now = _utc_now()
        self._db.execute("DELETE FROM hash_matches WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.executemany(
            "INSERT INTO hash_matches (evidence_id, artifact_ref, name, path, "
            "size, origin, set_id, set_name, category, algorithm, digest, "
            "matched_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id,) + tuple(row) + (now,) for row in rows])
        self._db.commit()

    def hash_matches(self, evidence_id=None, categories=None, text='',
                     limit=None):
        return query_hash_matches(self._db, evidence_id, categories, text,
                                  limit)

    def hash_match_counts(self, evidence_id=None):
        """{category: files} -- one file in two sets counts once."""
        where, params = '', []
        if evidence_id is not None:
            where, params = " WHERE evidence_id = ?", [evidence_id]
        return {row[0]: row[1] for row in self._db.execute(
            "SELECT category, COUNT(DISTINCT evidence_id || ':' || "
            "artifact_ref) FROM hash_matches" + where + " GROUP BY category",
            params)}

    def hash_match_map(self, evidence_id, refs):
        """{artifact_ref: [match, ...]} for the refs on screen, known bad
        first."""
        refs = list(refs)
        found = {}
        for start in range(0, len(refs), 500):
            chunk = refs[start:start + 500]
            marks = ','.join('?' * len(chunk))
            for row in self._db.execute(
                    f"SELECT * FROM hash_matches WHERE evidence_id = ? AND "
                    f"artifact_ref IN ({marks}) ORDER BY CASE category "
                    f"WHEN 'known-bad' THEN 0 WHEN 'notable' THEN 1 "
                    f"ELSE 2 END", [evidence_id] + chunk):
                row = dict(row)
                found.setdefault(row['artifact_ref'], []).append(row)
        return found

    # --- carving -----------------------------------------------------

    def carved_dir_for(self, evidence_id):
        """Where one piece of evidence's carved files are written.

        A folder per image: carved files are named after their offset alone,
        so two images sharing one folder overwrite each other wherever both
        hold the same type at the same offset.
        """
        folder = self._carved_folder_path(evidence_id)
        os.makedirs(folder, exist_ok=True)
        return folder

    def _carved_folder_path(self, evidence_id):
        """carved_dir_for's folder, without creating it."""
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        label = ''
        if row is not None:
            row = dict(row)
            label = row.get('display_name') or evidence_name(row['path'])
        safe = ''.join(c if c.isalnum() or c in '-_.' else '_'
                       for c in label)[:60].strip('._')
        return os.path.join(self.carved_dir,
                            f"{evidence_id}-{safe}" if safe else
                            str(evidence_id))

    def clear_carved(self, evidence_id):
        """Forget a previous carve of one piece of evidence.

        The rows only: copies already written or exported stay where they
        are.
        """
        self._db.execute("DELETE FROM carved_files WHERE evidence_id = ?",
                         (evidence_id,))
        # And what the carve's analysis found in them.
        for table in ('file_analysis', 'file_findings'):
            self._db.execute(f"DELETE FROM {table} WHERE evidence_id = ? AND "
                             f"path LIKE '{CARVED_PATHS}'", (evidence_id,))
        # And the file-system events its MFT and index records gave
        # (core/carved_artifacts).
        from trace_app.core.carved_artifacts import FS_SOURCES
        self._db.execute(
            f"DELETE FROM fs_events WHERE evidence_id = ? AND source IN "
            f"({','.join('?' * len(FS_SOURCES))})",
            (evidence_id,) + FS_SOURCES)
        self._db.commit()

    def add_carved(self, evidence_id, record):
        """Record one carved file (carving.describe_carved / write_carved).
        `path` is '' for a carve kept as a reference only."""
        offset, size = int(record['offset']), int(record['size'])
        path = record.get('path') or ''
        if path:
            try:
                path = os.path.relpath(path, self.folder)
            except ValueError:
                pass        # another drive: keep it absolute
        self._db.execute(
            "INSERT INTO carved_files (evidence_id, artifact_ref, name, path, "
            "offset, size, type, sha256, embedded_date, date_source, "
            "carved_utc, fragments, status, checks, md5, sha1, source, "
            "origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, make_span_ref(0, offset, offset + size),
             record['name'], path, offset, size, record['type'],
             record.get('sha256'), record.get('embedded_date'),
             record.get('date_source'), _utc_now(),
             json.dumps(record['fragments']) if record.get('fragments')
             else None, record.get('status'),
             json.dumps(record['checks']) if record.get('checks') else None,
             record.get('md5'), record.get('sha1'), record.get('source'),
             json.dumps(record['origin']) if record.get('origin')
             else None))

    def record_carved_export(self, results, folder):
        """Note where exported carves were written (their 'Saved to'), and
        audit the export: how many, where, and any whose bytes no longer
        match the SHA-256 recorded when they were carved."""
        written = [r for r in results if r.get('path')]
        for result in written:
            row = result['row']
            self._db.execute(
                "UPDATE carved_files SET path = ? WHERE evidence_id = ? AND "
                "offset = ?", (result['path'], row['evidence_id'],
                               row['offset']))
        self._db.commit()
        mismatched = [r for r in written if not r.get('verified')]
        failed = [r for r in results if not r.get('path')]
        self._record_activity(
            'carved files exported',
            f"{len(written)} file(s) to {folder}"
            + (f"; {len(mismatched)} not matching their recorded SHA-256: "
               + ', '.join(r['row']['name'] for r in mismatched[:20])
               if mismatched else '; all match their recorded SHA-256')
            + (f"; {len(failed)} not written" if failed else ''))

    def set_carved_related(self, evidence_id, offset, related):
        """Record the carve one belongs with (a WAL and its database)."""
        self._db.execute(
            "UPDATE carved_files SET related = ? WHERE evidence_id = ? AND "
            "offset = ?", (json.dumps(related, default=str)
                           if related else None, evidence_id, offset))


    def carved_duplicates(self, evidence_id=None):
        """{sha256: [(evidence_id, offset), ...]} for every digest carved
        more than once -- the same bytes found in several places."""
        where, params = '', []
        if evidence_id is not None:
            where, params = " AND evidence_id = ?", [evidence_id]
        groups = {}
        for digest, evidence, offset in self._db.execute(
                "SELECT sha256, evidence_id, offset FROM carved_files "
                "WHERE sha256 IN (SELECT sha256 FROM carved_files WHERE "
                f"sha256 IS NOT NULL{where} GROUP BY sha256 HAVING "
                f"COUNT(*) > 1){where} ORDER BY evidence_id, offset",
                params + params):
            groups.setdefault(digest, []).append((evidence, offset))
        return groups

    # --- deleted files -----------------------------------------------------

    def replace_deleted_files(self, evidence_id, rows):
        """Store core.deleted records for one image, replacing any."""
        self._db.execute("DELETE FROM deleted_files WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.executemany(
            "INSERT INTO deleted_files (evidence_id, artifact_ref, path, "
            "name, is_dir, size, state, runs, overwritten, modified_utc, "
            "accessed_utc, created_utc, changed_utc, detail) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id, r['ref'], r['path'], r['name'],
              1 if r['is_dir'] else 0, r['size'], r['state'],
              len(r.get('runs') or []), r.get('overwritten') or 0,
              r.get('modified'), r.get('accessed'), r.get('created'),
              r.get('changed'),
              json.dumps({'runs': [list(run) for run in
                                   (r.get('runs') or [])[:64]],
                          'inode': r.get('inode'),
                          # FAT's times (and exFAT's without an offset) are
                          # local wall-clock digits, though the columns say
                          # _utc: the panel labels them.
                          'times_local': bool(r.get('times_local')),
                          # The deleted file that took its space later.
                          'claimed_by': r.get('claimed_by')}))
             for r in rows])
        self._db.commit()

    def deleted_files(self, evidence_id=None, state=None, limit=200000):
        query, params = "SELECT * FROM deleted_files WHERE 1 = 1", []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if state:
            query += " AND state = ?"
            params.append(state)
        query += " ORDER BY evidence_id, path LIMIT ?"
        params.append(limit)
        rows = []
        for row in self._db.execute(query, params):
            row = dict(row)
            try:
                row['detail'] = json.loads(row.get('detail') or '{}')
            except ValueError:
                row['detail'] = {}
            rows.append(row)
        return rows

    def recycle_origins(self, evidence_id=None):
        """What deleted $I/$R files were before the Recycle Bin took them
        (see `recycle_origins`)."""
        return recycle_origins(self._db, evidence_id)

    def deleted_counts(self, evidence_id=None, files_only=False):
        """{state: count}; `files_only` leaves deleted folders out, as
        the Deleted files tab does by default."""
        clauses, params = [], []
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if files_only:
            clauses.append("is_dir = 0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
        return {row[0]: row[1] for row in self._db.execute(
            "SELECT state, COUNT(*) FROM deleted_files" + where
            + " GROUP BY state", params)}

    def start_carving_run(self, evidence_id, settings, engine):
        cursor = self._db.execute(
            "INSERT INTO carving_runs (evidence_id, started_utc, status, "
            "settings, engine) VALUES (?,?,?,?,?)",
            (evidence_id, _utc_now(), 'running', json.dumps(settings),
             engine))
        self._db.commit()
        return cursor.lastrowid

    def finish_carving_run(self, run_id, status, stats, found):
        self._db.execute(
            "UPDATE carving_runs SET finished_utc = ?, status = ?, stats = ?, "
            "found = ? WHERE id = ?",
            (_utc_now(), status, json.dumps(stats), found, run_id))
        self._db.commit()

    def carving_runs(self, evidence_id=None, limit=50):
        query, params = "SELECT * FROM carving_runs", []
        if evidence_id is not None:
            query, params = query + " WHERE evidence_id = ?", [evidence_id]
        rows = []
        for row in self._db.execute(query + " ORDER BY id DESC LIMIT ?",
                                    params + [limit]):
            row = dict(row)
            for key in ('settings', 'stats'):
                try:
                    row[key] = json.loads(row.get(key) or '{}')
                except ValueError:
                    row[key] = {}
            rows.append(row)
        return rows

    def carved_fragments(self, evidence_id, offset):
        """[(offset, length), ...] of the file carved at `offset` if it was
        rebuilt from fragments; None if it is one contiguous run."""
        row = self._db.execute(
            "SELECT fragments FROM carved_files WHERE evidence_id = ? AND "
            "offset = ? AND fragments IS NOT NULL LIMIT 1",
            (evidence_id, offset)).fetchone()
        try:
            return json.loads(row[0]) if row else None
        except ValueError:
            return None

    def carved_files(self, evidence_id=None, file_type=None, limit=20000):
        """Carved files in image order, with an absolute `path`."""
        query = "SELECT * FROM carved_files WHERE 1 = 1"
        params = []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if file_type:
            query += " AND type = ?"
            params.append(file_type)
        query += " ORDER BY evidence_id, offset LIMIT ?"
        params.append(limit)
        rows = []
        for row in self._db.execute(query, params):
            row = dict(row)
            if row['path'] and not os.path.isabs(row['path']):
                row['path'] = os.path.join(self.folder, row['path'])
            for key, empty in (('fragments', 'null'), ('checks', '[]'),
                               ('origin', 'null'), ('related', 'null')):
                try:
                    row[key] = json.loads(row.get(key) or empty)
                except ValueError:
                    row[key] = None
            rows.append(row)
        return rows

    def set_carving_state(self, evidence_id, status, types=None,
                          unallocated_only=None, bytes_done=None,
                          bytes_total=None, found=None, last_error=None):
        """Record how far a carve got; the end of one goes to the audit."""
        existing = self.carving_state(evidence_id) or {}

        def pick(value, key, default):
            return value if value is not None else existing.get(key, default)

        self._db.execute(
            "INSERT OR REPLACE INTO carving_state (evidence_id, status, types, "
            "unallocated_only, bytes_done, bytes_total, found, last_error, "
            "updated_utc) VALUES (?,?,?,?,?,?,?,?,?)",
            (evidence_id, status, pick(types, 'types', ''),
             int(pick(unallocated_only, 'unallocated_only', 1)),
             pick(bytes_done, 'bytes_done', 0),
             pick(bytes_total, 'bytes_total', 0),
             pick(found, 'found', 0), last_error, _utc_now()))
        self._db.commit()

        if status == 'running' and not existing.get('status') == 'running':
            self._record_activity(
                "carving started",
                f"evidence id={evidence_id} types={types or ''} "
                f"{'unallocated space' if unallocated_only else 'whole image'}")
        if status in ('done', 'cancelled', 'failed'):
            self._record_activity(
                f"carving {status}",
                f"evidence id={evidence_id} files={found or 0}"
                + (f" error={last_error}" if last_error else ''))

    def carving_state(self, evidence_id):
        """How the last carve of this evidence ended, or None."""
        row = self._db.execute(
            "SELECT * FROM carving_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None


    def analysis_map(self, evidence_id, refs=None):
        """artifact_ref -> analysis, for a whole directory at once.

        The listing draws a page of rows in one go, and asking per row turns
        drawing a directory into one query per file. `refs` narrows it to what
        is actually on screen.
        """
        if refs is not None:
            refs = list(refs)
            if not refs:
                return {}
            # Chunked: SQLite's parameter limit is finite and a directory can
            # hold more entries than it allows in one statement.
            found = {}
            for start in range(0, len(refs), 500):
                chunk = refs[start:start + 500]
                marks = ','.join('?' * len(chunk))
                rows = self._db.execute(
                    f"SELECT * FROM file_analysis WHERE evidence_id = ? "
                    f"AND artifact_ref IN ({marks})",
                    [evidence_id] + chunk).fetchall()
                found.update({r['artifact_ref']: dict(r) for r in rows})
            return found

        rows = self._db.execute(
            "SELECT * FROM file_analysis WHERE evidence_id = ?",
            (evidence_id,)).fetchall()
        return {r['artifact_ref']: dict(r) for r in rows}

    def type_mismatches(self, evidence_id=None, grade='suspicious',
                        limit=1000):
        """Files whose content disagrees with their extension.

        Defaults to the suspicious grade only. The others are recorded so a
        filter can ask for them, but a list that opens with every `.jpe` and
        every plain-text `.log` is a list nobody reads twice.
        """
        query = ("SELECT * FROM file_analysis WHERE mismatch IS NOT NULL "
                 "AND mismatch != ''")
        params = []
        if isinstance(grade, (list, tuple, set)):
            grades = list(grade)
            query += f" AND mismatch IN ({','.join('?' * len(grades))})"
            params.extend(grades)
        elif grade:
            query += " AND mismatch = ?"
            params.append(grade)
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        query += " ORDER BY name LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._db.execute(query, params)]

    def regrade_mismatches(self):
        """Grade the stored type mismatches again (analysis.
        classify_mismatch) -- the entropy threshold, a setting, decides
        whether an unidentifiable file is notable, and every value it reads
        is stored: nothing is read from the evidence. Returns how many
        changed; audited when any did."""
        from trace_app.core import analysis
        changes = []
        for row in self._db.execute(
                "SELECT id, extension, mime, entropy, mismatch FROM "
                "file_analysis WHERE mime = 'application/octet-stream' AND "
                "entropy IS NOT NULL"):
            grade = analysis.classify_mismatch(row['extension'] or '',
                                               row['mime'], row['entropy'])
            if grade != row['mismatch']:
                changes.append((grade, row['id']))
        if changes:
            self._db.executemany(
                "UPDATE file_analysis SET mismatch = ? WHERE id = ?", changes)
            self._db.commit()
            self._record_activity(
                'type mismatches graded again',
                f"{len(changes):,} file(s) at a high-entropy threshold of "
                f"{analysis.HIGH_ENTROPY} bits per byte")
        return len(changes)

    def high_entropy_files(self, evidence_id=None, limit=1000):
        """Files that look random with no business doing so, most extreme first.

        Judged by analysis.is_high_entropy, the same rule the listing's flag
        column uses. A bare `entropy >= 7.5` listed every JPEG, MP3 and ZIP on
        the volume -- formats that score near 8 by design -- so the group was
        mostly noise and disagreed with the listing about the same file.
        """
        # Imported here: analysis imports this module for make_artifact_ref.
        from trace_app.core.analysis import (HIGH_ENTROPY, HIGH_PEAK_ENTROPY,
                                             is_high_entropy)

        query = ("SELECT * FROM file_analysis "
                 "WHERE (entropy >= ? OR entropy_peak >= ?)")
        params = [HIGH_ENTROPY, HIGH_PEAK_ENTROPY]
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        query += " ORDER BY entropy DESC"

        found = []
        for row in self._db.execute(query, params):
            if is_high_entropy(row['entropy'] or 0, row['entropy_peak'] or 0,
                               row['mime'] or ''):
                found.append(dict(row))
                if len(found) >= limit:
                    break
        return found

    def duplicate_groups(self, evidence_id=None, limit=500):
        """Files sharing a SHA-256, grouped, biggest waste first.

        Ordered by how much space the copies take rather than by how many
        there are: fifty copies of a 1KB icon matter less than three copies of
        a 2GB archive, and an examiner scanning the list wants the second.
        """
        query = ("SELECT sha256, COUNT(*) AS copies, MAX(size) AS size "
                 "FROM file_analysis WHERE sha256 IS NOT NULL AND sha256 != ''")
        params = []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        query += (" GROUP BY sha256 HAVING copies > 1 "
                  "ORDER BY (copies - 1) * size DESC LIMIT ?")
        params.append(limit)

        groups = []
        for row in self._db.execute(query, params):
            members = self._db.execute(
                "SELECT * FROM file_analysis WHERE sha256 = ? ORDER BY path",
                (row['sha256'],)).fetchall()
            groups.append({'sha256': row['sha256'], 'copies': row['copies'],
                           'size': row['size'],
                           'members': [dict(m) for m in members]})
        return groups

    def findings(self, evidence_id=None, module=None, grades=None,
                 kind=None, limit=2000):
        """Content-check findings, most serious first, detail decoded.

        `grades` narrows to those grades -- pass REPORTED_FINDING_GRADES for
        the ones worth showing; leave it None for everything recorded.
        """
        query = "SELECT * FROM file_findings WHERE 1 = 1"
        params = []
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if module:
            query += " AND module = ?"
            params.append(module)
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if grades:
            grades = list(grades)
            query += f" AND grade IN ({','.join('?' * len(grades))})"
            params.extend(grades)
        query += (" ORDER BY CASE grade WHEN 'suspicious' THEN 0 "
                  "WHEN 'notable' THEN 1 ELSE 2 END, name LIMIT ?")
        params.append(limit)
        rows = []
        for row in self._db.execute(query, params):
            row = dict(row)
            try:
                row['detail'] = json.loads(row.get('detail') or '{}')
            except ValueError:
                row['detail'] = {}
            rows.append(row)
        return rows

    def findings_map(self, evidence_id, refs, module=None, grades=None):
        """{artifact_ref: [finding, ...]} for the refs on screen."""
        refs = list(refs)
        found = {}
        for start in range(0, len(refs), 500):
            chunk = refs[start:start + 500]
            marks = ','.join('?' * len(chunk))
            query = (f"SELECT * FROM file_findings WHERE evidence_id = ? "
                     f"AND artifact_ref IN ({marks})")
            params = [evidence_id] + chunk
            if module:
                query += " AND module = ?"
                params.append(module)
            if grades:
                query += f" AND grade IN ({','.join('?' * len(grades))})"
                params.extend(grades)
            query += (" ORDER BY CASE grade WHEN 'suspicious' THEN 0 "
                      "WHEN 'notable' THEN 1 ELSE 2 END")
            for row in self._db.execute(query, params):
                row = dict(row)
                found.setdefault(row['artifact_ref'], []).append(row)
        return found

    def find_by_hash(self, digest):
        """Every file matching a hash, whichever algorithm it is.

        Takes MD5 or SHA-256 without being told which: an examiner pasting a
        hash from a report should not have to say what kind it is.
        """
        digest = (digest or '').strip().lower()
        if not digest:
            return []
        column = 'md5' if len(digest) == 32 else 'sha256'
        return [dict(r) for r in self._db.execute(
            f"SELECT * FROM file_analysis WHERE {column} = ? ORDER BY path",
            (digest,))]

    def analysis_summary(self, evidence_id=None):
        """Counts for the tree node and the Triage tab.

        Kept until the database changes -- a write on this connection
        (total_changes) or a commit by another, a job's (data_version) --
        or the entropy thresholds do: opening a case asked for the same
        counts twice, about a second each on a 500,000-file case."""
        from trace_app.core import analysis
        state = (self._db.total_changes,
                 self._db.execute("PRAGMA data_version").fetchone()[0],
                 analysis.HIGH_ENTROPY, analysis.HIGH_PEAK_ENTROPY)
        cache = self.__dict__.setdefault('_summary_cache', {})
        cached = cache.get(evidence_id)
        if cached is None or cached[0] != state:
            if cache and next(iter(cache.values()))[0] != state:
                cache.clear()
            cached = cache[evidence_id] = (state,
                                           self._analysis_summary(evidence_id))
        return dict(cached[1])

    def _analysis_summary(self, evidence_id):
        where = " WHERE evidence_id = ?" if evidence_id is not None else ""
        params = [evidence_id] if evidence_id is not None else []

        analysed = self._db.execute(
            f"SELECT COUNT(*) FROM file_analysis{where}", params).fetchone()[0]
        # Counted in SQL, capped where the lists are: the rows themselves
        # (up to 1,000 each, every column) were read only to be counted.
        from trace_app.core.analysis import (_EXPECTED_HIGH_ENTROPY,
                                             HIGH_ENTROPY, HIGH_PEAK_ENTROPY)
        scope = " AND evidence_id = ?" if evidence_id is not None else ""
        grades = list(REPORTED_MISMATCHES)
        mismatches = self._db.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM file_analysis WHERE "
            f"mismatch IN ({','.join('?' * len(grades))}){scope} "
            "LIMIT 1000)", grades + params).fetchone()[0]
        expected = sorted(_EXPECTED_HIGH_ENTROPY)
        entropy = self._db.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM file_analysis WHERE "
            "(entropy >= ? OR entropy_peak >= ?) AND COALESCE(mime, '') "
            f"NOT IN ({','.join('?' * len(expected))}){scope} LIMIT 1000)",
            [HIGH_ENTROPY, HIGH_PEAK_ENTROPY] + expected + params
        ).fetchone()[0]
        duplicates = self._db.execute(
            "SELECT COUNT(*) FROM (SELECT sha256 FROM file_analysis"
            + (" WHERE evidence_id = ?" if evidence_id is not None else "")
            + (" AND" if evidence_id is not None else " WHERE")
            + " sha256 IS NOT NULL AND sha256 != '' GROUP BY sha256"
              " HAVING COUNT(*) > 1)", params).fetchone()[0]

        def count(module, grades=None, located=False):
            query = ("SELECT COUNT(DISTINCT artifact_ref) FROM file_findings "
                     "WHERE module = ?")
            args = [module]
            if evidence_id is not None:
                query += " AND evidence_id = ?"
                args.append(evidence_id)
            if grades:
                query += f" AND grade IN ({','.join('?' * len(grades))})"
                args.extend(grades)
            if located:
                query += " AND detail LIKE '%\"latitude\"%'"
            return self._db.execute(query, args).fetchone()[0]

        carved = self._db.execute(
            f"SELECT COUNT(*) FROM carved_files{where}", params).fetchone()[0]
        # Counted here, not from the rows Triage lists, so its tabs can be
        # labelled without filling them. YARA: files (a file matching three
        # rules is one); Sigma: events, as its table lists them.
        scope = " AND evidence_id = ?" if evidence_id is not None else ""
        yara = self._db.execute(
            "SELECT COUNT(*) FROM (SELECT DISTINCT evidence_id, artifact_ref "
            "FROM file_findings WHERE module = 'yara'" + scope + ")",
            params).fetchone()[0]
        sigma = self._db.execute(
            "SELECT COUNT(*) FROM file_findings WHERE module = 'sigma'"
            + scope, params).fetchone()[0]

        return {'analysed': analysed, 'mismatches': mismatches,
                'yara': yara, 'sigma': min(sigma, SIGMA_SHOWN),
                'carved': carved,
                'high_entropy': entropy, 'duplicate_groups': duplicates,
                'hidden': count('hidden', REPORTED_FINDING_GRADES),
                'photos': count('photo'),
                'photos_located': count('photo', located=True),
                'authors': count('authors'),
                'executables': count('executables'),
                'executables_flagged': count('executables',
                                             REPORTED_FINDING_GRADES)}

    def _create_schema(self):
        """Create every table, including the ones no feature uses yet.

        Notes, bookmarks and tags have no UI at this point. Their tables are
        written now anyway: adding them later means migrating cases that
        already hold real evidence, and the shape of an artifact reference is
        the one decision that is expensive to change afterwards.
        """
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS case_info (
                key         TEXT PRIMARY KEY,
                value       TEXT
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                path          TEXT NOT NULL UNIQUE,
                display_name  TEXT,
                size          INTEGER,
                md5           TEXT,
                sha1          TEXT,
                sha256        TEXT,
                stored_md5    TEXT,
                stored_sha1   TEXT,
                stored_sha256 TEXT,
                stored_source TEXT,
                added_utc     TEXT,
                verified_utc  TEXT,
                last_status   TEXT,
                read_only     INTEGER NOT NULL DEFAULT 1,
                exhibit_number TEXT,
                description   TEXT,
                acquired_by   TEXT,
                acquired_on   TEXT
            );

            CREATE TABLE IF NOT EXISTS notes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT,
                artifact_name TEXT,
                artifact_path TEXT,
                body          TEXT NOT NULL,
                created_utc   TEXT,
                updated_utc   TEXT,
                bookmark_id   INTEGER REFERENCES bookmarks(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT,
                artifact_name TEXT,
                artifact_path TEXT,
                label         TEXT,
                colour        TEXT,
                created_utc   TEXT
            );

            -- Timeline events the examiner starred, coloured or wrote a
            -- comment on (schema 21). The event is copied, so the mark
            -- outlives a module run again (core/timeline.event_key finds
            -- it in the new rows) and the Starred filter needs no join.
            CREATE TABLE IF NOT EXISTS timeline_marks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key     TEXT NOT NULL UNIQUE,
                evidence_id   INTEGER REFERENCES evidence(id)
                              ON DELETE CASCADE,
                source        TEXT,
                time          TEXT,
                local         INTEGER NOT NULL DEFAULT 0,
                kind          TEXT,
                title         TEXT,
                subject       TEXT,
                user          TEXT,
                artifact_ref  TEXT,
                deleted       INTEGER NOT NULL DEFAULT 0,
                starred       INTEGER NOT NULL DEFAULT 0,
                colour        TEXT,
                comment       TEXT,
                examiner      TEXT,
                updated_utc   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_marks_time
                ON timeline_marks(time);

            -- The operating system found on each volume (schema 20;
            -- core/os_identity), for the Case tab, the report and the
            -- timeline's filter. Recorded when the image is opened.
            CREATE TABLE IF NOT EXISTS evidence_systems (
                evidence_id   INTEGER NOT NULL REFERENCES evidence(id)
                              ON DELETE CASCADE,
                volume_key    INTEGER NOT NULL,
                volume        TEXT,
                family        TEXT,
                logo          TEXT,
                name          TEXT,
                detail        TEXT,
                recorded_utc  TEXT,
                PRIMARY KEY (evidence_id, volume_key)
            );

            CREATE TABLE IF NOT EXISTS tags (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL UNIQUE,
                colour        TEXT
            );

            CREATE TABLE IF NOT EXISTS artifact_tags (
                tag_id        INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                name          TEXT,
                path          TEXT,
                tagged_utc    TEXT,
                examiner      TEXT,
                PRIMARY KEY (tag_id, evidence_id, artifact_ref)
            );

            -- The Project VIC category the examiner gave a picture or
            -- video (schema 22; core/vics.CATEGORIES, 0-4 -- none is
            -- Uncategorized). One per file, unlike tags: a category is a
            -- statement about the content, and the VICS export writes it.
            CREATE TABLE IF NOT EXISTS vic_categories (
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                category      INTEGER NOT NULL,
                name          TEXT,
                path          TEXT,
                categorised_utc TEXT,
                examiner      TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vic_categories
                ON vic_categories(IFNULL(evidence_id, -1), artifact_ref);

            -- External modules' runs (schema 23; core/modules): iLEAPP,
            -- aLEAPP... run on files staged from one image. `folder` is
            -- the run's folder, relative to the case folder: input/ (the
            -- staged files), staging-manifest.csv, report/ (the tool's
            -- own output, LAVA included), run.log. The rows stay in the
            -- tool's _lava_artifacts.db; the case keeps what joins need.
            CREATE TABLE IF NOT EXISTS module_runs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                tool          TEXT NOT NULL,
                version       TEXT,
                executable_sha256 TEXT,
                params        TEXT,
                folder        TEXT NOT NULL,
                status        TEXT NOT NULL,
                staged        INTEGER,
                manifest_sha256 TEXT,
                lava_sha256   TEXT,
                started_utc   TEXT,
                finished_utc  TEXT,
                message       TEXT
            );
            CREATE TABLE IF NOT EXISTS module_artifacts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id        INTEGER NOT NULL
                              REFERENCES module_runs(id) ON DELETE CASCADE,
                category      TEXT,
                name          TEXT,
                tablename     TEXT,
                module        TEXT,
                columns       TEXT,
                row_count     INTEGER,
                source_path   TEXT,
                conversation  TEXT,
                icon          TEXT,
                -- Schema 24: how core/modules/routes sorted it.
                artifact_key  TEXT,
                role          TEXT,
                route_why     TEXT,
                content_sha256 TEXT,
                bridged_version INTEGER NOT NULL DEFAULT 0,
                superseded_by INTEGER,
                -- Schema 25: what decided it (routes.Route.sorted_by).
                sorted_by     TEXT
            );
            -- One per timestamp in a row (a message's sent, read and
            -- delivered times are three), for the Timeline.
            CREATE TABLE IF NOT EXISTS module_events (
                run_id        INTEGER NOT NULL
                              REFERENCES module_runs(id) ON DELETE CASCADE,
                artifact_id   INTEGER NOT NULL
                              REFERENCES module_artifacts(id) ON DELETE CASCADE,
                row_id        INTEGER NOT NULL,
                time_utc      TEXT NOT NULL,
                label         TEXT,
                summary       TEXT,
                -- Schema 24: evidence / telemetry / other, 'bridged' (its
                -- row is in Activity: not shown twice), 'superseded' (a
                -- newer run read the same rows).
                kind          TEXT NOT NULL DEFAULT 'other'
            );
            CREATE INDEX IF NOT EXISTS idx_module_events_time
                ON module_events(time_utc);

            CREATE TABLE IF NOT EXISTS verifications (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
                evidence_name TEXT,
                utc           TEXT NOT NULL,
                algorithm     TEXT,
                expected      TEXT,
                computed      TEXT,
                status        TEXT NOT NULL,
                detail        TEXT
            );

            CREATE TABLE IF NOT EXISTS activity (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                utc           TEXT NOT NULL,
                action        TEXT NOT NULL,
                detail        TEXT,
                examiner      TEXT,
                account       TEXT,
                tool          TEXT,
                prev_hash     TEXT,
                entry_hash    TEXT
            );

            CREATE TABLE IF NOT EXISTS file_analysis (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                name          TEXT NOT NULL,
                path          TEXT,
                size          INTEGER,
                is_deleted    INTEGER NOT NULL DEFAULT 0,
                mime          TEXT,
                extension     TEXT,
                mismatch      TEXT,
                entropy       REAL,
                entropy_peak  REAL,
                entropy_peak_offset INTEGER,
                md5           TEXT,
                sha256        TEXT,
                note          TEXT,
                analysed_utc  TEXT NOT NULL,
                sha1          TEXT,
                -- Perceptual hash of a picture (core/phash.py), 16 hex.
                phash         TEXT,
                UNIQUE(evidence_id, artifact_ref)
            );

            CREATE TABLE IF NOT EXISTS analysis_state (
                evidence_id   INTEGER PRIMARY KEY
                              REFERENCES evidence(id) ON DELETE CASCADE,
                status        TEXT NOT NULL,
                modules       TEXT,
                files_done    INTEGER NOT NULL DEFAULT 0,
                files_total   INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT,
                updated_utc   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_analysis_mismatch
                ON file_analysis(evidence_id, mismatch);
            CREATE INDEX IF NOT EXISTS idx_analysis_entropy
                ON file_analysis(evidence_id, entropy);
            -- Duplicate detection is a GROUP BY over this column, so it is
            -- the one index the feature genuinely cannot do without.
            CREATE INDEX IF NOT EXISTS idx_analysis_sha256
                ON file_analysis(sha256);
            -- The same for one image: without it the group was sorted in a
            -- temporary tree, 2.4 s on a 500,000-file case.
            CREATE INDEX IF NOT EXISTS idx_analysis_evidence_sha256
                ON file_analysis(evidence_id, sha256);
            CREATE INDEX IF NOT EXISTS idx_verifications_evidence
                ON verifications(evidence_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_notes_artifact
                ON notes(evidence_id, artifact_ref);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_artifact
                ON bookmarks(evidence_id, artifact_ref);

            -- One row per VirusTotal query, never updated: "clean in March,
            -- detected by 12 engines in October" is the history a report
            -- needs, and an overwrite would keep only its last line.
            CREATE TABLE IF NOT EXISTS vt_results (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT,
                name          TEXT,
                path          TEXT,
                sha256        TEXT NOT NULL,
                method        TEXT NOT NULL,
                status        TEXT NOT NULL,
                positives     INTEGER,
                total         INTEGER,
                scan_date     TEXT,
                report        TEXT,
                detail        TEXT,
                queried_utc   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vt_artifact
                ON vt_results(evidence_id, artifact_ref, id DESC);

            -- What the content checks found: deceptive names, appended data,
            -- encryption, photo metadata, document authors. A row per
            -- finding, not per file -- one file can wear a double extension
            -- and carry an archive after its end.
            CREATE TABLE IF NOT EXISTS file_findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                name          TEXT,
                path          TEXT,
                size          INTEGER,
                module        TEXT NOT NULL,
                kind          TEXT NOT NULL,
                grade         TEXT NOT NULL,
                summary       TEXT,
                detail        TEXT,
                analysed_utc  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_module
                ON file_findings(evidence_id, module, grade);
            CREATE INDEX IF NOT EXISTS idx_findings_artifact
                ON file_findings(evidence_id, artifact_ref);

            -- Files recovered by carving, one row each. A carved file has no
            -- inode, so it is referenced by the byte span it was found at
            -- (make_span_ref), which is also what names it on disk. The copy
            -- lives under carved/<evidence>/; `path` is relative to the case
            -- folder, so a case that moves keeps finding it. `fragments` is
            -- JSON [[offset, length], ...] for a file rebuilt from the pieces
            -- the file system split it into; NULL if it was contiguous.
            CREATE TABLE IF NOT EXISTS carved_files (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id    INTEGER NOT NULL
                               REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref   TEXT NOT NULL,
                name           TEXT NOT NULL,
                path           TEXT NOT NULL,
                offset         INTEGER NOT NULL,
                size           INTEGER NOT NULL,
                type           TEXT NOT NULL,
                sha256         TEXT,
                embedded_date  TEXT,
                date_source    TEXT,
                carved_utc     TEXT NOT NULL,
                fragments      TEXT,
                -- What the file's structure proved (core/carve_verify.py),
                -- and where it came from (core/carve_origin.py).
                status         TEXT,
                checks         TEXT,
                md5            TEXT,
                sha1           TEXT,
                source         TEXT,
                origin         TEXT,
                -- The carve it belongs with: a WAL and the database it
                -- replays onto (carving.pair_wal_files), as JSON.
                related        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_carved_evidence
                ON carved_files(evidence_id, offset);

            -- Deleted files the file systems still list (core/deleted.py),
            -- with how much of each is left.
            CREATE TABLE IF NOT EXISTS deleted_files (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id    INTEGER NOT NULL
                               REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref   TEXT NOT NULL,
                path           TEXT NOT NULL,
                name           TEXT,
                is_dir         INTEGER DEFAULT 0,
                size           INTEGER,
                state          TEXT NOT NULL,
                runs           INTEGER DEFAULT 0,
                overwritten    INTEGER DEFAULT 0,
                modified_utc   TEXT,
                accessed_utc   TEXT,
                created_utc    TEXT,
                changed_utc    TEXT,
                detail         TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_deleted_files
                ON deleted_files(evidence_id, state);

            -- Every carve run: its settings, engine and what it saw.
            CREATE TABLE IF NOT EXISTS carving_runs (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id    INTEGER NOT NULL
                               REFERENCES evidence(id) ON DELETE CASCADE,
                started_utc    TEXT NOT NULL,
                finished_utc   TEXT,
                status         TEXT NOT NULL,
                settings       TEXT,
                engine         TEXT,
                stats          TEXT,
                found          INTEGER DEFAULT 0
            );

            -- How the last carve of each piece of evidence went.
            CREATE TABLE IF NOT EXISTS carving_state (
                evidence_id      INTEGER PRIMARY KEY
                                 REFERENCES evidence(id) ON DELETE CASCADE,
                status           TEXT NOT NULL,
                types            TEXT,
                unallocated_only INTEGER NOT NULL DEFAULT 1,
                bytes_done       INTEGER NOT NULL DEFAULT 0,
                bytes_total      INTEGER NOT NULL DEFAULT 0,
                found            INTEGER NOT NULL DEFAULT 0,
                last_error       TEXT,
                updated_utc      TEXT NOT NULL
            );

            -- What the people using a device did (core/activity): programs
            -- run, files opened, USB devices, deletions, logons, browsing.
            -- One row per event. `time_utc` is NULL where the source keeps
            -- no time; `time_local` is 1 where the source kept local
            -- wall-clock time with no zone (setupapi, DOS dates). `source_ref`
            -- is the artifact_ref of the file the event was read from.
            CREATE TABLE IF NOT EXISTS user_activity (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                category      TEXT NOT NULL,
                what          TEXT NOT NULL,
                time_utc      TEXT,
                time_local    INTEGER NOT NULL DEFAULT 0,
                subject       TEXT,
                user          TEXT,
                detail        TEXT,
                source        TEXT,
                source_path   TEXT,
                source_ref    TEXT,
                -- Schema 24: who read it (TRACE, or an external module's
                -- run, whose artifact it came from), and the record it is
                -- (core/activity_match) -- one read by two readers shows
                -- once, the others pointing at it (duplicate_of).
                reader        TEXT NOT NULL DEFAULT 'TRACE',
                module_run_id INTEGER
                              REFERENCES module_runs(id) ON DELETE CASCADE,
                module_artifact_id INTEGER,
                match_key     TEXT,
                duplicate_of  INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_user_activity
                ON user_activity(evidence_id, category, time_utc);

            CREATE TABLE IF NOT EXISTS user_activity_state (
                evidence_id   INTEGER PRIMARY KEY
                              REFERENCES evidence(id) ON DELETE CASCADE,
                status        TEXT NOT NULL,
                records       INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT,
                updated_utc   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS fs_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                path          TEXT,
                time_utc      TEXT NOT NULL,
                macb          TEXT NOT NULL,
                source        TEXT NOT NULL,
                deleted       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_fs_events_time
                ON fs_events(time_utc);
            CREATE INDEX IF NOT EXISTS idx_fs_events_ref
                ON fs_events(evidence_id, artifact_ref);

            CREATE TABLE IF NOT EXISTS usn_journal (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                usn           INTEGER NOT NULL,
                time_utc      TEXT NOT NULL,
                artifact_ref  TEXT NOT NULL,
                file_entry    INTEGER NOT NULL,
                file_sequence INTEGER NOT NULL,
                parent_entry  INTEGER NOT NULL,
                parent_sequence INTEGER NOT NULL,
                name          TEXT,
                path          TEXT,
                reasons       TEXT,
                reason_flags  INTEGER NOT NULL,
                attributes    INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_usn_time ON usn_journal(time_utc);
            CREATE INDEX IF NOT EXISTS idx_usn_file
                ON usn_journal(evidence_id, file_entry);

            CREATE TABLE IF NOT EXISTS ntfs_state (
                evidence_id   INTEGER PRIMARY KEY
                              REFERENCES evidence(id) ON DELETE CASCADE,
                status        TEXT NOT NULL,
                volumes       INTEGER NOT NULL DEFAULT 0,
                entries       INTEGER NOT NULL DEFAULT 0,
                events        INTEGER NOT NULL DEFAULT 0,
                journal       INTEGER NOT NULL DEFAULT 0,
                last_error    TEXT,
                updated_utc   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hash_matches (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                name          TEXT,
                path          TEXT,
                size          INTEGER,
                origin        TEXT NOT NULL DEFAULT 'file',
                set_id        TEXT NOT NULL,
                set_name      TEXT NOT NULL,
                category      TEXT NOT NULL,
                algorithm     TEXT NOT NULL,
                digest        TEXT NOT NULL,
                matched_utc   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_hash_matches
                ON hash_matches(evidence_id, artifact_ref);

            CREATE TABLE IF NOT EXISTS persistence (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                location      TEXT NOT NULL,
                name          TEXT,
                command       TEXT,
                target        TEXT,
                target_ref    TEXT,
                user          TEXT,
                time_utc      TEXT,
                enabled       INTEGER,
                target_exists INTEGER,
                signed        INTEGER,
                sha256        TEXT,
                hash_category TEXT,
                grade         TEXT NOT NULL,
                reasons       TEXT,
                source        TEXT,
                source_ref    TEXT,
                detail        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_persistence
                ON persistence(evidence_id, grade);

            -- Pictures in thumbnail caches (core/thumbnails.py): where
            -- each lies in its cache file, never a copy of it.
            CREATE TABLE IF NOT EXISTS thumbnails (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER NOT NULL
                              REFERENCES evidence(id) ON DELETE CASCADE,
                cache_ref     TEXT NOT NULL,
                cache_path    TEXT NOT NULL,
                cache_kind    TEXT NOT NULL,
                cache_size    TEXT,
                cache_deleted INTEGER DEFAULT 0,
                system        TEXT,
                user          TEXT,
                key           TEXT,
                location      TEXT NOT NULL,
                name          TEXT,
                original_state TEXT,
                original_ref  TEXT,
                modified_utc  TEXT,
                width         INTEGER,
                height        INTEGER,
                format        TEXT,
                size          INTEGER,
                sha256        TEXT,
                detail        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_thumbnails
                ON thumbnails(evidence_id, cache_ref);

            CREATE TABLE IF NOT EXISTS report_items (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                kind          TEXT NOT NULL,
                evidence_id   INTEGER
                              REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT,
                time_utc      TEXT,
                title         TEXT NOT NULL,
                detail        TEXT,
                added_utc     TEXT NOT NULL
            );
        """)
        self._db.commit()
        try:
            self._create_indexes_24()
        except sqlite3.OperationalError:
            pass        # an older case: its columns come in _migrate
        self._set('schema_version', SCHEMA_VERSION)

    def _migrate_custody(self):
        """Schema 18: acquisition hashes, a verification history that
        survives its evidence, and a chained audit trail.

        Entries written before have no chain; they are chained now, in
        order, and an entry says so -- the chain proves nothing changed
        after this point, not before it."""
        for column in ('stored_sha256 TEXT', 'stored_source TEXT'):
            try:
                self._db.execute(f"ALTER TABLE evidence ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        for column in ('examiner', 'account', 'tool', 'prev_hash',
                       'entry_hash'):
            try:
                self._db.execute(
                    f"ALTER TABLE activity ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError:
                pass
        self._db.execute("UPDATE evidence SET stored_source = 'the image' "
                         "WHERE stored_source IS NULL AND (stored_md5 IS NOT "
                         "NULL OR stored_sha1 IS NOT NULL)")
        # verifications: ON DELETE SET NULL and the evidence's name, so
        # removing evidence no longer erases its history. SQLite cannot
        # change a foreign key in place: the table is rebuilt.
        columns = [r['name'] for r in self._db.execute(
            "PRAGMA table_info(verifications)").fetchall()]
        if 'evidence_name' not in columns:
            self._db.commit()
            self._db.execute("PRAGMA foreign_keys = OFF")
            self._db.executescript("""
                BEGIN;
                DROP TRIGGER IF EXISTS verifications_no_update;
                DROP TRIGGER IF EXISTS verifications_no_delete;
                CREATE TABLE verifications_v18 (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id   INTEGER REFERENCES evidence(id)
                                  ON DELETE SET NULL,
                    evidence_name TEXT,
                    utc           TEXT NOT NULL,
                    algorithm     TEXT,
                    expected      TEXT,
                    computed      TEXT,
                    status        TEXT NOT NULL,
                    detail        TEXT
                );
                INSERT INTO verifications_v18 (id, evidence_id,
                    evidence_name, utc, algorithm, expected, computed,
                    status, detail)
                SELECT v.id, v.evidence_id,
                       (SELECT COALESCE(e.display_name, e.path)
                        FROM evidence e WHERE e.id = v.evidence_id),
                       v.utc, v.algorithm, v.expected, v.computed, v.status,
                       v.detail
                FROM verifications v;
                DROP TABLE verifications;
                ALTER TABLE verifications_v18 RENAME TO verifications;
                COMMIT;
            """)
            self._db.execute("PRAGMA foreign_keys = ON")
        unchained = self._db.execute(
            "SELECT * FROM activity WHERE entry_hash IS NULL ORDER BY id"
        ).fetchall()
        if unchained:
            previous = self._db.execute(
                "SELECT entry_hash FROM activity WHERE entry_hash IS NOT "
                "NULL ORDER BY id DESC LIMIT 1").fetchone()
            previous = previous['entry_hash'] if previous else ''
            for row in unchained:
                row = dict(row, prev_hash=previous)
                row['entry_hash'] = audit_hash(row)
                self._db.execute(
                    "UPDATE activity SET prev_hash = ?, entry_hash = ? "
                    "WHERE id = ?", (row['prev_hash'], row['entry_hash'],
                                     row['id']))
                previous = row['entry_hash']
        self._db.commit()
        if unchained:
            self._record_activity(
                'audit trail chained',
                f"entries 1 to {unchained[-1]['id']:,} were written before "
                f"TRACE chained its audit trail; they were chained now, as "
                f"found, so the chain shows changes after this point only")

    def _migrate_module_bridge(self):
        """Schema 24: readers and record keys on user_activity, routes on
        module_artifacts, kinds on module_events (core/modules/bridge).
        The LEAPP runs are sorted by the 'module_bridge' job the window
        starts once the case is open (bridged_version 0)."""
        added = (('user_activity', 'reader', "TEXT NOT NULL DEFAULT 'TRACE'"),
                 ('user_activity', 'module_run_id',
                  'INTEGER REFERENCES module_runs(id) ON DELETE CASCADE'),
                 ('user_activity', 'module_artifact_id', 'INTEGER'),
                 ('user_activity', 'match_key', 'TEXT'),
                 ('user_activity', 'duplicate_of', 'INTEGER'),
                 ('module_artifacts', 'artifact_key', 'TEXT'),
                 ('module_artifacts', 'role', 'TEXT'),
                 ('module_artifacts', 'route_why', 'TEXT'),
                 ('module_artifacts', 'content_sha256', 'TEXT'),
                 ('module_artifacts', 'bridged_version',
                  'INTEGER NOT NULL DEFAULT 0'),
                 ('module_artifacts', 'superseded_by', 'INTEGER'),
                 ('module_events', 'kind', "TEXT NOT NULL DEFAULT 'other'"))
        for table, column, kind in added:
            try:
                self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
            except sqlite3.OperationalError:
                pass            # already present (created above at v24)
        self._db.commit()
        self._create_indexes_24()
        # TRACE's own rows get their record keys now.
        from trace_app.core.activity_match import match_key
        evidence_ids = [row[0] for row in self._db.execute(
            "SELECT DISTINCT evidence_id FROM user_activity")]
        for row in query_user_activity(self._db, primary_only=False):
            self._db.execute(
                "UPDATE user_activity SET match_key = ? WHERE id = ?",
                (match_key(row), row['id']))
        self._db.commit()
        for evidence_id in evidence_ids:
            self.relink_matches(evidence_id)

    def _create_indexes_24(self):
        self._db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_user_activity_match
                ON user_activity(evidence_id, match_key);
            CREATE INDEX IF NOT EXISTS idx_user_activity_duplicate
                ON user_activity(duplicate_of);
            CREATE INDEX IF NOT EXISTS idx_user_activity_artifact
                ON user_activity(module_artifact_id);
            CREATE INDEX IF NOT EXISTS idx_module_events_artifact
                ON module_events(artifact_id);
        """)

    def _migrate(self):
        """Bring an existing case up to the current schema version."""
        # Read the version the case was written at BEFORE touching the schema.
        # _create_schema stamps the current version, so asking afterwards would
        # always report "already up to date" and every migration step would be
        # skipped -- silently, on exactly the old cases that need them.
        try:
            version = int(self._get('schema_version', 0) or 0)
        except (TypeError, ValueError):
            version = 0

        if version > SCHEMA_VERSION:
            raise CaseError(
                f"This case was written by a newer version of TRACE "
                f"(schema {version}; this build understands {SCHEMA_VERSION}). "
                f"Opening it could lose data.")

        # Tables the case predates are created unconditionally; CREATE TABLE IF
        # NOT EXISTS makes this safe for a case at the current version too.
        self._create_schema()

        if version < 24:
            self._migrate_module_bridge()

        if version < 25:
            # How each LEAPP artifact was sorted (the tool's map, a name
            # rule...): filled when the runs are sorted again
            # (routes.ROUTES_VERSION 5).
            try:
                self._db.execute(
                    "ALTER TABLE module_artifacts ADD COLUMN sorted_by TEXT")
            except sqlite3.OperationalError:
                pass            # already present (created above at v25)
            self._db.commit()

        if version < 19:
            # Tags in use (schema 19): which file, by whom, when -- the
            # table was there unused; it gains what a list of tagged files
            # shows, and the three tags every case starts with.
            for column in ('name', 'path', 'tagged_utc', 'examiner'):
                try:
                    self._db.execute(
                        f"ALTER TABLE artifact_tags ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError:
                    pass        # already present (created above at v19)
            self._db.commit()
            self._seed_tags()

        if version < 18:
            self._migrate_custody()

        if version < 17:
            # A picture's perceptual hash, for Triage > Similar pictures.
            try:
                self._db.execute(
                    "ALTER TABLE file_analysis ADD COLUMN phash TEXT")
            except sqlite3.OperationalError:
                pass            # already present (created above at v17)
            self._db.commit()

        if version < 16:
            # Chain of custody per item. acquired_on is text as the image
            # (or the examiner) recorded it: an E01's acquisition date is
            # the acquiring machine's local time, with no zone to convert.
            for column in EVIDENCE_DETAILS:
                try:
                    self._db.execute(
                        f"ALTER TABLE evidence ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError:
                    pass        # already present (created above at v16)
            self._db.commit()

        if version < 15:
            # A carved WAL and its database name each other.
            try:
                self._db.execute(
                    "ALTER TABLE carved_files ADD COLUMN related TEXT")
            except sqlite3.OperationalError:
                pass            # already present (created above at v15)
            self._db.commit()

        if version < 14:
            # deleted_files is created unconditionally above.
            self._db.commit()

        if version < 13:
            # Carved files gain what their structure proved and where they
            # came from; carving_runs is created above. Older carves keep
            # NULLs: "not checked", never "checked and found nothing".
            for column in ('status', 'checks', 'md5', 'sha1', 'source',
                           'origin'):
                try:
                    self._db.execute(
                        f"ALTER TABLE carved_files ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError:
                    pass        # already present (created above at v13)
            self._db.commit()

        if version < 12:
            # thumbnails is created unconditionally above.
            self._db.commit()

        if version < 11:
            # persistence is created unconditionally above.
            self._db.commit()

        if version < 10:
            # SHA-1 joins MD5 and SHA-256, for hash sets that carry only it
            # (NSRL's RDS keys on SHA-1). The NTFS, hash-set and report tables
            # are created unconditionally above.
            try:
                self._db.execute(
                    "ALTER TABLE file_analysis ADD COLUMN sha1 TEXT")
            except sqlite3.OperationalError:
                pass        # already present (created above at v10)
            self._db.commit()

        if version < 9:
            # user_activity and its state are created unconditionally above;
            # a case from before simply has no activity until it is read.
            self._db.commit()

        if version < 8:
            # A carved file may be reassembled from fragments; where they lie
            # is recorded with it. Older carves were all contiguous: NULL.
            try:
                self._db.execute(
                    "ALTER TABLE carved_files ADD COLUMN fragments TEXT")
            except sqlite3.OperationalError:
                pass        # already present (created above at v8)
            self._db.commit()

        if version < 7:
            # carved_files and carving_state are created unconditionally
            # above. Carving results were never stored before, so there is
            # nothing to carry over.
            self._db.commit()

        if version < 6:
            # file_findings is created unconditionally above; an older case
            # simply has no findings until the new modules are run.
            self._db.commit()

        if version < 5:
            # vt_results is created unconditionally above. VirusTotal results
            # were never stored before, so there is nothing to carry over.
            self._db.commit()

        if version < 4:
            # file_analysis and analysis_state are created unconditionally
            # above; there is nothing to alter, because no earlier version had
            # a column to preserve. A case that predates them simply has no
            # analysis until one is run.
            self._db.commit()

        if version < 3:
            # Notes can hang off a bookmark. SET NULL rather than CASCADE:
            # deleting a marker should not delete the analysis written against
            # it -- the note is the more valuable of the two.
            try:
                self._db.execute(
                    "ALTER TABLE notes ADD COLUMN bookmark_id INTEGER "
                    "REFERENCES bookmarks(id) ON DELETE SET NULL")
            except sqlite3.OperationalError:
                pass        # already present
            self._db.commit()

        if version < 2:
            # read_only arrived with the integrity work. Existing evidence
            # defaults to read-only, which is the safe reading: a case written
            # before the column existed never authorised anything to be
            # written back to its evidence.
            try:
                self._db.execute(
                    "ALTER TABLE evidence ADD COLUMN read_only "
                    "INTEGER NOT NULL DEFAULT 1")
            except sqlite3.OperationalError:
                pass        # already present
            self._db.commit()
            version = 2

        version = SCHEMA_VERSION

        if version != SCHEMA_VERSION:
            self._set('schema_version', SCHEMA_VERSION)

        self._create_indexes_24()
        # After every step: a rebuilt table loses its triggers.
        self._custody_guards()

# --- module helpers -------------------------------------------------------

def query_user_activity(connection, evidence_id=None, category=None,
                        text='', limit=None, located=False,
                        primary_only=True, reader=None, only_reader=False,
                        ids_of=None, evidence_ids=None, trace_only=False,
                        count=False):
    """Activity rows from a case database connection, newest first.

    Shared by Case and by the Activity tab's reader thread, which uses a
    read-only connection of its own. Rows without a time sort last.

    One record read by two readers (TRACE and a LEAPP, say) is one row:
    the primary, `read_by` naming every reader (core/activity_match,
    Case.relink_matches); `primary_only=False` gives every reading.
    `reader` keeps the records that reader read (as primary or not);
    with `only_reader`, those no other reader read. `ids_of`: a primary's
    readings. Older cases (before schema 24) have no reader columns.
    `evidence_ids`: rows of these images only; `trace_only`: no external
    tool's rows (a report leaving them out); `count`: the number of rows
    instead of the rows.
    """
    columns = {row[1] for row in connection.execute(
        "PRAGMA table_info(user_activity)")}
    readers = 'duplicate_of' in columns
    clauses, params = [], []
    if readers and ids_of is not None:
        clauses.append("(id = ? OR duplicate_of = ?)")
        params.extend([ids_of, ids_of])
    elif readers and primary_only:
        clauses.append("duplicate_of IS NULL")
    if readers and reader:
        if only_reader:
            clauses.append(
                "reader = ? AND NOT EXISTS (SELECT 1 FROM user_activity d "
                "WHERE d.duplicate_of = user_activity.id AND d.reader != ?)")
            params.extend([reader, reader])
        else:
            clauses.append(
                "(reader = ? OR EXISTS (SELECT 1 FROM user_activity d "
                "WHERE d.duplicate_of = user_activity.id AND d.reader = ?))")
            params.extend([reader, reader])
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    if evidence_ids is not None:
        ids = [int(i) for i in evidence_ids]
        clauses.append("evidence_id IN (" + ','.join('?' * len(ids)) + ")"
                       if ids else "0")
        params.extend(ids)
    if readers and trace_only:
        clauses.append("module_run_id IS NULL")
    if category:
        clauses.append("category = ?")
        params.append(category)
    if text:
        clauses.append("(subject LIKE ? OR what LIKE ? OR user LIKE ? "
                       "OR detail LIKE ? OR source_path LIKE ?)")
        params.extend([f'%{text}%'] * 5)
    if located:
        clauses.append("detail LIKE '%\"latitude\"%' AND "
                       "detail LIKE '%\"longitude\"%'")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
    if count:
        return connection.execute("SELECT COUNT(*) FROM user_activity"
                                  + where, params).fetchone()[0]
    query = ("SELECT * FROM user_activity" + where
             + " ORDER BY time_utc IS NULL, time_utc DESC, id")
    if limit:
        query += f" LIMIT {int(limit)}"
    cursor = connection.execute(query, params)
    names = [d[0] for d in cursor.description]
    out = []
    for values in cursor:
        row = dict(zip(names, values))
        try:
            row['detail'] = json.loads(row.get('detail') or '{}')
        except ValueError:
            row['detail'] = {}
        row['artifact_ref'] = row.get('source_ref')
        row.setdefault('reader', 'TRACE')
        row['read_by'] = [row['reader']]
        out.append(row)
    if readers and out and primary_only and ids_of is None:
        _attach_readers(connection, out)
    link_recycle_contents(connection, out)
    return out


def _attach_readers(connection, rows):
    """Each primary row's `read_by`: its reader, then the other readers of
    the same record, TRACE first."""
    by_id = {row['id']: row for row in rows}
    ids = list(by_id)
    for start in range(0, len(ids), 900):
        chunk = ids[start:start + 900]
        marks = ','.join('?' * len(chunk))
        for primary, reader in connection.execute(
                f"SELECT duplicate_of, reader FROM user_activity "
                f"WHERE duplicate_of IN ({marks})", chunk):
            found = by_id[primary]['read_by']
            if reader not in found:
                found.append(reader)
    for row in rows:
        row['read_by'].sort(key=lambda r: (r != 'TRACE', r))


def _volume_of(ref):
    """'p128:' of 'p128:i38:s1' -- which volume a ref is on."""
    return (ref or '').split(':', 1)[0] + ':'


def link_recycle_contents(connection, rows):
    """Recycle Bin records whose content ($R) is a deleted file: give each
    its Deleted Files row (`recycle_content`), and say its state in the
    detail shown. Nothing is stored; the link is made as rows are read."""
    wanted = [r for r in rows if r.get('category') == 'recycle'
              and (r.get('detail') or {}).get('content file')]
    if not wanted:
        return
    evidence = sorted({r['evidence_id'] for r in wanted})
    found = {}
    try:
        cursor = connection.execute(
            "SELECT * FROM deleted_files WHERE evidence_id IN "
            f"({','.join('?' * len(evidence))}) AND name LIKE '$R%'",
            evidence)
        names = [d[0] for d in cursor.description]
        for values in cursor:
            item = dict(zip(names, values))
            found[(item['evidence_id'], _volume_of(item['artifact_ref']),
                   item['path'].lower())] = item
    except sqlite3.Error:
        return                          # a case from before Deleted Files
    for row in wanted:
        key = (row['evidence_id'], _volume_of(row.get('source_ref')),
               row['detail']['content file'].lower())
        item = found.get(key)
        if item is None:
            continue
        try:
            item['detail'] = json.loads(item.get('detail') or '{}')
        except (TypeError, ValueError):
            item['detail'] = {} if not isinstance(item.get('detail'),
                                                  dict) else item['detail']
        row['recycle_content'] = item
        row['detail']['in Deleted Files'] = item['state']


def recycle_origins(connection, evidence_id=None):
    """{(evidence id, 'p128:', lower path): Recycle Bin record} for each
    $I record and $R content file the bin's records name -- what a
    Deleted Files row named $R019S2V.txt was before it was deleted."""
    clauses, params = ["category = 'recycle'"], []
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    out = {}
    for item in connection.execute(
            "SELECT evidence_id, time_utc, subject, user, detail, "
            "source_path, source_ref FROM user_activity WHERE "
            + " AND ".join(clauses), params):
        evidence, when, subject, user, detail, source, ref = tuple(item)
        try:
            detail = json.loads(detail or '{}')
        except ValueError:
            detail = {}
        origin = {'original': subject, 'deleted': when, 'user': user,
                  'record': detail.get('record')}
        volume = _volume_of(ref)
        if source:
            out[(evidence, volume, source.lower())] = dict(origin,
                                                           part='$I record')
        if detail.get('content file'):
            out[(evidence, volume, detail['content file'].lower())] = dict(
                origin, part='content')
    return out


#: The NTFS tab's sections, by the finding kinds each lists.
NTFS_SECTIONS = {
    'timestomp': ('timestomp',),
    'streams': ('ads', 'motw'),
    'slack': ('i30slack',),
    'logfile': ('logfile',),
}


def query_ntfs(connection, section, evidence_id=None, text='',
               include_routine=False, limit=None):
    """Rows for one section of the NTFS tab: 'timestomp', 'streams' (both
    from file_findings) or 'journal' (usn_journal), newest/most serious
    first. Routine rows -- graded benign -- only when asked for."""
    clauses, params = [], []
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    if section == 'journal':
        if text:
            clauses.append("(name LIKE ? OR path LIKE ? OR reasons LIKE ?)")
            params.extend([f'%{text}%'] * 3)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
        query = ("SELECT * FROM usn_journal" + where
                 + " ORDER BY time_utc DESC, usn DESC")
    else:
        kinds = NTFS_SECTIONS[section]
        clauses.append("module = 'ntfs'")
        clauses.append(f"kind IN ({','.join('?' * len(kinds))})")
        params.extend(kinds)
        if not include_routine and section != 'logfile':
            clauses.append("grade != 'benign'")
        if text:
            clauses.append("(name LIKE ? OR path LIKE ? OR summary LIKE ? "
                           "OR detail LIKE ?)")
            params.extend([f'%{text}%'] * 4)
        order = ("CAST(json_extract(detail, '$.lsn') AS INTEGER) DESC"
                 if section == 'logfile' else
                 "CASE grade WHEN 'suspicious' THEN 0 WHEN 'notable' THEN 1 "
                 "ELSE 2 END, path")
        query = ("SELECT * FROM file_findings WHERE " + " AND ".join(clauses)
                 + " ORDER BY " + order)
    if limit:
        query += f" LIMIT {int(limit)}"
    cursor = connection.execute(query, params)
    names = [d[0] for d in cursor.description]
    out = []
    for values in cursor:
        row = dict(zip(names, values))
        if 'detail' in row:
            try:
                row['detail'] = json.loads(row.get('detail') or '{}')
            except ValueError:
                row['detail'] = {}
        out.append(row)
    return out


def query_picture_hashes(connection, evidence_id=None):
    """`Case.picture_hashes` on any connection -- the Similar pictures job
    reads them in its own process (a whole case's pictures, read on the
    window's thread, held a big case's window for seconds)."""
    query = ("SELECT evidence_id, artifact_ref, name, path, size, "
             "is_deleted, phash FROM file_analysis WHERE phash IS NOT NULL")
    params = []
    if evidence_id is not None:
        query += " AND evidence_id = ?"
        params.append(evidence_id)
    cursor = connection.execute(query + " ORDER BY evidence_id, path",
                                params)
    names = [c[0] for c in cursor.description]
    return [dict(zip(names, row)) for row in cursor]


def ntfs_counts(connection, evidence_id=None):
    """{'timestomp': n, 'streams': n, 'journal': n, 'routine_timestomp': n,
    'routine_streams': n} -- what the tab labels and the tree show."""
    where, params = '', []
    if evidence_id is not None:
        where, params = " AND evidence_id = ?", [evidence_id]
    counts = {'timestomp': 0, 'streams': 0, 'slack': 0, 'logfile': 0,
              'routine_timestomp': 0, 'routine_streams': 0,
              'routine_slack': 0, 'routine_logfile': 0}
    for kind, grade, count in connection.execute(
            "SELECT kind, grade, COUNT(*) FROM file_findings WHERE "
            "module = 'ntfs'" + where + " GROUP BY kind, grade", params):
        section = next((s for s, kinds in NTFS_SECTIONS.items()
                        if kind in kinds), 'streams')
        key = section if grade != 'benign' or section == 'logfile' \
            else f'routine_{section}'
        counts[key] += count
    counts['journal'] = connection.execute(
        "SELECT COUNT(*) FROM usn_journal" + where.replace(' AND', ' WHERE'),
        params).fetchone()[0]
    return counts


def query_persistence(connection, evidence_id=None, include_benign=True,
                      text='', limit=None):
    """Autostart entries, most serious first."""
    clauses, params = [], []
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    if not include_benign:
        clauses.append("grade != 'benign'")
    if text:
        clauses.append("(name LIKE ? OR command LIKE ? OR target LIKE ? "
                       "OR location LIKE ? OR user LIKE ?)")
        params.extend([f'%{text}%'] * 5)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
    query = ("SELECT * FROM persistence" + where
             + " ORDER BY CASE grade WHEN 'suspicious' THEN 0 "
             "WHEN 'notable' THEN 1 ELSE 2 END, location, name")
    if limit:
        query += f" LIMIT {int(limit)}"
    cursor = connection.execute(query, params)
    names = [d[0] for d in cursor.description]
    out = []
    for values in cursor:
        row = dict(zip(names, values))
        for key in ('reasons', 'detail'):
            try:
                row[key] = json.loads(row.get(key) or ('[]' if key ==
                                                       'reasons' else '{}'))
            except ValueError:
                row[key] = [] if key == 'reasons' else {}
        out.append(row)
    return out


def query_hash_matches(connection, evidence_id=None, categories=None,
                       text='', limit=None):
    """Hash-set matches, known bad first."""
    clauses, params = [], []
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    if categories:
        categories = list(categories)
        clauses.append(f"category IN ({','.join('?' * len(categories))})")
        params.extend(categories)
    if text:
        clauses.append("(name LIKE ? OR path LIKE ? OR set_name LIKE ? "
                       "OR digest LIKE ?)")
        params.extend([f'%{text}%'] * 4)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
    query = ("SELECT * FROM hash_matches" + where
             + " ORDER BY CASE category WHEN 'known-bad' THEN 0 "
             "WHEN 'notable' THEN 1 ELSE 2 END, set_name, path")
    if limit:
        query += f" LIMIT {int(limit)}"
    cursor = connection.execute(query, params)
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, values)) for values in cursor]


def _decode_vt(row):
    """A vt_results row as a dict, its stored report parsed back out."""
    result = dict(row)
    try:
        result['report'] = json.loads(result.get('report') or '{}')
    except ValueError:
        result['report'] = {}
    return result


def _utc_now():
    """Now, as UTC ISO-8601 seconds.

    Stored as text: a case is meant to be read by another tool, another
    examiner, or a person with a SQLite browser, and an integer epoch is none
    of those things.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat()


def acquisition_hashes(row, results=None):
    """{name: hex} the evidence should hash to, from outside TRACE's own
    record: what the image stores (an E01's MD5/SHA-1, an AD1's log) and
    the acquisition hashes kept on the evidence row (its log, or entered
    by the examiner)."""
    stored = {}
    for name in HASH_NAMES:
        value = (results or {}).get(f'stored_{name}') or \
            (row or {}).get(f'stored_{name}')
        if value:
            stored[name] = str(value).lower()
    return stored


def verdict(results, recorded=None, stored=None):
    """Judge one hashing run (ImageHandler.calculate_hashes): {status,
    detail, algorithm, expected, computed}.

    In order, the first that applies:

    * the container's own check of what it stores fails (AFF4) -> CHANGED
    * the run could not read the evidence in full -> UNREADABLE (no hash)
    * a live disk -> LIVE (what was read, when; never verified)
    * chunks failing the image's own checksums (an E01) -> CHANGED, with
      the sectors
    * any hash the case recorded, or the image or its acquisition records,
      that differs from the run -> CHANGED, naming each
    * everything compared matches -> VERIFIED, naming what was compared
    * nothing to compare with -> BASELINE: hashed in full; these hashes
      are the reference later checks use
    """
    recorded = {k: str(v).lower() for k, v in (recorded or {}).items() if v}
    if stored is None:
        stored = acquisition_hashes(None, results)
    computed = {name: (results.get(f'computed_{name}') or '').lower()
                for name in HASH_NAMES}
    out = {'algorithm': '', 'expected': '', 'computed': ''}
    check = results.get('container_check')
    if check and check[0] is False:
        return dict(out, status=STATUS_CHANGED, detail=check[1])
    if results.get('error') or not any(computed.values()):
        return dict(out, status=STATUS_UNREADABLE, detail=(
            "The evidence could not be read in full, so it was not "
            f"hashed: {results.get('error') or 'nothing was read'}."))
    if results.get('live'):
        return dict(out, status=STATUS_LIVE, detail=(
            "Read live: these are the hashes of what was read, when. A "
            "disk in use changes as it is read, so they verify nothing; "
            "for evidence, image it behind a write blocker."))
    findings = []
    damaged = results.get('damaged') or []
    if damaged:
        sectors = sum(last - first + 1 for first, last in damaged)
        shown = ', '.join(f"{first:,}-{last:,}" for first, last
                          in damaged[:8])
        findings.append(
            f"{sectors:,} sectors fail the image's own chunk checksums "
            f"(sectors {shown}{', ...' if len(damaged) > 8 else ''}); "
            f"they read as zeros")
    findings += [f"the image's structure is damaged: {problem}"
                 for problem in results.get('container_problems') or []]
    compared, expected_values, differ = [], [], []
    for source, wanted in (('recorded by the case', recorded),
                           ('stored with the image', stored)):
        for name in HASH_NAMES:
            value = wanted.get(name)
            if not value:
                continue
            compared.append((name, source))
            expected_values.append(value)
            if computed[name] != value:
                differ.append(f"{name.upper()} is {computed[name] or '-'}; "
                              f"{source}: {value}")
    out.update(algorithm='+'.join(sorted({n for n, _s in compared},
                                         key=HASH_NAMES.index)) or
               '+'.join(n for n in HASH_NAMES if computed[n]),
               expected=' '.join(expected_values),
               computed=' '.join(computed[n] for n in HASH_NAMES
                                 if computed[n]))
    if differ or findings:
        return dict(out, status=STATUS_CHANGED,
                    detail='; '.join(findings + differ) + '.')
    if check and check[0] and not compared:
        # An AFF4's stored streams re-hashed to what was recorded at
        # acquisition: the data is verified; the disk's own hashes are
        # the reference from here on.
        return dict(out, status=STATUS_VERIFIED,
                    detail=f"{check[1]} The disk's hashes are recorded as "
                           f"the reference for later checks.")
    if not compared:
        return dict(out, status=STATUS_BASELINE, detail=(
            f"Hashed in full ({results.get('size') or 0:,} bytes). Nothing "
            f"was recorded to compare with -- no hash in the image and no "
            f"acquisition hash -- so these hashes are the reference every "
            f"later check uses."))
    by_source = {}
    for name, source in compared:
        by_source.setdefault(source, []).append(name.upper())
    return dict(out, status=STATUS_VERIFIED, detail='; '.join(
        f"{' and '.join(names)} match{'es' if len(names) == 1 else ''} "
        f"the hash{'es' if len(names) > 1 else ''} {source}"
        for source, names in by_source.items()) + '.')


def hash_verdict(results):
    """(status, detail) of a first hashing run with nothing recorded:
    `verdict` against the hashes the image itself stores."""
    outcome = verdict(results)
    return outcome['status'], outcome['detail']


def hash_evidence(row, progress=None):
    """Hash one evidence row in full, without the case's database (safe on
    a worker thread). Returns calculate_hashes' results -- or, when there
    is nothing to hash, an outcome {status, detail, ...} for record_check:
    the file is missing, or it is a live disk (re-reading one in use
    proves nothing)."""
    path = row['path']
    out = {'algorithm': '', 'expected': '', 'computed': ''}
    from trace_app.core.live_disk import is_device_path
    if is_device_path(path):
        return dict(out, status=STATUS_LIVE,
                    detail='A live disk is not re-checked: in use, it '
                           'changes, so a new hash would prove nothing.')
    if not os.path.exists(path):
        return dict(out, status=STATUS_MISSING,
                    detail='The file is not at its recorded location.')
    if _is_plain_image(path):
        from trace_app.core import evidence_hash
        results = {'path': path, 'stored_md5': None, 'stored_sha1': None}
        try:
            digests = evidence_hash.hash_file(path, progress)
        except evidence_hash.HashingError as exc:
            return dict(results, error=str(exc), size=0)
        results.update({f'computed_{n}': digests[n] for n in HASH_NAMES})
        results['size'] = digests['size']
        return results
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    try:
        if not handler.loaded:
            return {'path': path, 'error': handler.load_error or
                    'The evidence could not be opened.'}
        return handler.calculate_hashes(progress)
    finally:
        handler.close_resources()


def check_evidence(row, progress=None):
    """Hash one evidence row and judge it against what the row records
    (`verdict`), without the case's database. Returns {status, detail,
    algorithm, expected, computed}; Case.apply_verification is what
    records a run."""
    results = hash_evidence(row, progress)
    if results.get('status'):
        return results
    recorded = {n: row.get(n) for n in HASH_NAMES if row.get(n)}
    return verdict(results, recorded, acquisition_hashes(row, results))


def _acquisition_log(path):
    try:
        from trace_app.core import acquisition_log
        return acquisition_log.logged_hashes(path)
    except Exception as exc:
        logger.warning("Acquisition log beside %s unreadable: %s", path, exc)
        return {}, None


def audit_hash(entry):
    """The SHA-256 chaining an audit entry: over its id, time, action,
    detail, examiner, account, tool and the previous entry's hash."""
    payload = json.dumps([entry.get('id'), entry.get('utc'),
                          entry.get('action'), entry.get('detail'),
                          entry.get('examiner'), entry.get('account'),
                          entry.get('tool'), entry.get('prev_hash') or ''],
                         ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _account():
    """user@host of the operating-system account running TRACE."""
    import getpass
    import platform
    try:
        user = getpass.getuser()
    except Exception:
        user = '?'
    return f"{user}@{platform.node() or '?'}"


def _tool():
    try:
        from trace_app import __version__
    except ImportError:
        __version__ = '?'
    return f"TRACE {__version__}"


def _is_plain_image(path):
    """A single raw file whose own bytes are the evidence (dd, raw, iso
    ...), as opposed to an E01's media, a virtual disk's guest, a split
    image's segments or logical evidence -- which are hashed by what they
    hold (ImageHandler.calculate_hashes), so they are re-checked the same
    way."""
    if not os.path.isfile(path):
        return False
    try:
        from trace_app.core.image_handler import ImageHandler
        kind = ImageHandler.get_image_type(_PathOnly(path))
    except Exception:
        return True
    from trace_app.core.image_handler import is_split_raw
    return kind == 'raw' and not is_split_raw(path)


class _PathOnly:
    def __init__(self, path):
        self.image_path = path


def is_case_folder(folder):
    """Does this folder hold a case?"""
    return os.path.isfile(os.path.join(folder, CASE_DB_NAME))


def read_case_summary(folder):
    """{name, number, examiner, organisation, created_utc, opened_utc,
    evidence} for the welcome screen's list, or None if unreadable.

    Read without opening the case: no audit line ("case opened" for a
    glance at a list would be false), no migration, and nothing written to
    the folder at all -- immutable=1, because even a read-only connection
    to a WAL database leaves -wal and -shm files behind. A case open in
    another window may show slightly stale counts; that is all.
    """
    from trace_app.infra.sqlite_uri import connect_read_only
    path = os.path.join(folder, CASE_DB_NAME)
    if not os.path.isfile(path):
        return None
    try:
        connection = connect_read_only(path, immutable=True)
    except sqlite3.Error:
        return None
    try:
        info = dict(connection.execute(
            "SELECT key, value FROM case_info WHERE key IN ('name', "
            "'number', 'examiner', 'organisation', 'created_utc', "
            "'opened_utc')").fetchall())
        evidence = connection.execute(
            "SELECT COUNT(*) FROM evidence").fetchone()[0]
    except sqlite3.Error as exc:
        logger.debug("Case summary for %s unreadable: %s", folder, exc)
        return None
    finally:
        connection.close()
    out = {key: info.get(key) or '' for key in
           ('name', 'number', 'examiner', 'organisation', 'created_utc',
            'opened_utc')}
    out['evidence'] = evidence
    return out

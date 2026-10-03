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
SCHEMA_VERSION = 10

#: Status values recorded against a piece of evidence.
STATUS_PENDING = 'pending'      # added, not yet hashed
STATUS_VERIFIED = 'verified'    # present and matching its recorded hash
STATUS_MISSING = 'missing'      # the file is not where the case says it is
STATUS_CHANGED = 'changed'      # present, but no longer the same bytes
STATUS_UNHASHED = 'unhashed'    # present, but nothing to compare against


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


#: The mismatch grades worth putting in front of an examiner. Suspicious is an
#: executable in a document's clothing; notable covers a file whose content
#: cannot be identified and looks like random data, which is what an encrypted
#: document looks like from outside. Benign disagreements are recorded but not
#: reported: a list opening with every .jpe teaches people to close the list.
REPORTED_MISMATCHES = ('suspicious', 'notable')

#: The content-check grades worth showing; benign ones (a motion photo's
#: clip, an owner-password PDF) are recorded but not put in front of anyone.
REPORTED_FINDING_GRADES = ('suspicious', 'notable')

#: Finding modules written by jobs of their own, not the file analysis.
OWN_JOB_MODULES = ('ntfs', 'yara', 'persistence')


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

    match = _REGISTRY_REF.match(ref)
    if match:
        return {
            'kind': 'registry',
            'hive': match.group(1),
            'key_path': match.group(2),
            'ref': ref,
        }

    return {'kind': 'unknown', 'ref': ref}


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
    def create(cls, folder, name, number='', examiner='', description=''):
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
        now = _utc_now()
        case._set_many({
            'name': name,
            'number': number,
            'examiner': examiner,
            'description': description,
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
        return self.subdir('carved')

    @property
    def exports_dir(self):
        return self.subdir('exports')

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

    def update_metadata(self, **fields):
        """Change one or more case_info values."""
        known = {'name', 'number', 'examiner', 'description'}
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

    def add_evidence(self, path, display_name=None):
        """Record an image as part of this case. Returns its evidence id.

        The file is not hashed here: hashing a multi-gigabyte image takes
        minutes and would block the caller. The row starts as `pending` and
        :meth:`record_hashes` fills it in once verification has run.
        """
        path = os.path.normpath(os.path.abspath(path))
        existing = self._db.execute(
            "SELECT id FROM evidence WHERE path = ?", (path,)).fetchone()
        if existing:
            return existing['id']

        try:
            size = os.path.getsize(path)
        except OSError:
            size = None

        cursor = self._db.execute(
            "INSERT INTO evidence (path, display_name, size, added_utc, "
            "last_status) VALUES (?, ?, ?, ?, ?)",
            (path, display_name or os.path.basename(path), size, _utc_now(),
             STATUS_PENDING))
        self._db.commit()
        self._record_activity('evidence added', path)
        return cursor.lastrowid

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

    def remove_evidence(self, evidence_id):
        """Drop a piece of evidence, and everything recorded against it."""
        row = self._db.execute(
            "SELECT path FROM evidence WHERE id = ?",
            (evidence_id,)).fetchone()
        self._db.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        self._db.commit()
        if row:
            self._record_activity('evidence removed', row['path'])

    def relocate_evidence(self, evidence_id, new_path):
        """Point a piece of evidence at a file that has moved.

        The recorded hashes are kept: the whole point of relocating is to check
        that the file found elsewhere is the same evidence.
        """
        new_path = os.path.normpath(os.path.abspath(new_path))
        try:
            size = os.path.getsize(new_path)
        except OSError:
            size = None
        self._db.execute(
            "UPDATE evidence SET path = ?, size = ?, last_status = ? "
            "WHERE id = ?",
            (new_path, size, STATUS_PENDING, evidence_id))
        self._db.commit()
        self._record_activity('evidence relocated', new_path)

    def record_hashes(self, evidence_id, results):
        """Store the hashes verification computed.

        `results` is the dict from ImageHandler.calculate_hashes: the computed
        digests, and for an E01 the ones stored inside the image itself.
        """
        self._db.execute(
            "UPDATE evidence SET md5 = ?, sha1 = ?, sha256 = ?, "
            "stored_md5 = ?, stored_sha1 = ?, verified_utc = ?, "
            "last_status = ? WHERE id = ?",
            (results.get('computed_md5'), results.get('computed_sha1'),
             results.get('computed_sha256'), results.get('stored_md5'),
             results.get('stored_sha1'), _utc_now(), STATUS_VERIFIED,
             evidence_id))
        self._db.commit()
        # The history is the record: a hash written now does not replace the
        # fact that one was written before.
        self.record_verification(
            evidence_id, 'md5',
            results.get('stored_md5') or '',
            results.get('computed_md5') or '',
            STATUS_VERIFIED, 'Hashes computed and recorded.')
        self._record_activity(
            'evidence hashed',
            f"id={evidence_id} md5={results.get('computed_md5') or '-'}")

    def verify_evidence(self, progress=None):
        """Check every piece of evidence is still what the case recorded.

        Returns a list of `(evidence_row, status, detail)`. The status that
        matters is CHANGED: a file still present whose bytes no longer match is
        the one an examiner must be told about loudly, and it is exactly the
        case a plain "could not open" message would hide.

        Only the recorded hash is recomputed, so an image added but never
        verified reports UNHASHED rather than pretending to have checked it.
        """
        outcomes = []
        for row in self.evidence():
            path = row['path']

            if not os.path.exists(path):
                self._note_check(row['id'], '', '', '', STATUS_MISSING,
                                 'The file is not at its recorded location.')
                outcomes.append((row, STATUS_MISSING,
                                 'The file is not at its recorded location.'))
                continue

            expected = row['md5'] or row['sha1'] or row['sha256']
            if not expected:
                self._note_check(row['id'], '', '', '', STATUS_UNHASHED,
                                 'No hash was recorded, so nothing can be '
                                 'compared.')
                outcomes.append((row, STATUS_UNHASHED,
                                 'No hash was recorded, so nothing can be '
                                 'compared.'))
                continue

            # Size is far cheaper than a hash and settles most mismatches.
            try:
                size = os.path.getsize(path)
            except OSError as exc:
                self._note_check(row['id'], '', '', '', STATUS_MISSING,
                                 str(exc))
                outcomes.append((row, STATUS_MISSING, str(exc)))
                continue

            if row['size'] is not None and size != row['size']:
                self._note_check(
                    row['id'], 'size', str(row['size']), str(size),
                    STATUS_CHANGED,
                    f"The file is {size:,} bytes; the case recorded "
                    f"{row['size']:,}.")
                outcomes.append((
                    row, STATUS_CHANGED,
                    f"The file is {size:,} bytes; the case recorded "
                    f"{row['size']:,}."))
                continue

            algorithm = ('md5' if row['md5'] else
                         'sha1' if row['sha1'] else 'sha256')
            digest = _hash_file(path, algorithm, progress)
            if digest is None:
                self._note_check(row['id'], algorithm, str(expected), '',
                                 STATUS_MISSING, 'The file could not be read.')
                outcomes.append((row, STATUS_MISSING,
                                 'The file could not be read.'))
            elif digest.lower() == str(expected).lower():
                self._note_check(row['id'], algorithm, str(expected), digest,
                                 STATUS_VERIFIED,
                                 f'{algorithm.upper()} matches.')
                outcomes.append((row, STATUS_VERIFIED,
                                 f'{algorithm.upper()} matches.'))
            else:
                self._note_check(
                    row['id'], algorithm, str(expected), digest,
                    STATUS_CHANGED,
                    f"{algorithm.upper()} is {digest}; the case recorded "
                    f"{expected}.")
                outcomes.append((
                    row, STATUS_CHANGED,
                    f"{algorithm.upper()} is {digest}; the case recorded "
                    f"{expected}."))

        return outcomes

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
        self._db.execute(
            "INSERT INTO verifications (evidence_id, utc, algorithm, expected,"
            " computed, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, _utc_now(), algorithm, expected, computed, status,
             detail))
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

    def set_evidence_readonly(self, evidence_id, read_only=True):
        """Mark evidence as read-only, or release it.

        TRACE never writes to evidence, so this records intent rather than
        enforcing a filesystem permission -- but an examiner who has
        deliberately released the flag has said so on the record.
        """
        self._db.execute(
            "UPDATE evidence SET read_only = ? WHERE id = ?",
            (1 if read_only else 0, evidence_id))
        self._db.commit()
        self._record_activity(
            'evidence read-only set' if read_only else
            'evidence read-only released', f'id={evidence_id}')

    def is_readonly(self, evidence_id):
        row = self._db.execute(
            "SELECT read_only FROM evidence WHERE id = ?",
            (evidence_id,)).fetchone()
        return bool(row['read_only']) if row else True

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
        if label is not None:
            self._db.execute("UPDATE bookmarks SET label = ? WHERE id = ?",
                             (label, bookmark_id))
        if colour is not None:
            self._db.execute("UPDATE bookmarks SET colour = ? WHERE id = ?",
                             (colour, bookmark_id))
        self._db.commit()
        self._record_activity('bookmark edited', f'id={bookmark_id}')

    def remove_bookmark(self, bookmark_id):
        """Delete a bookmark. Any notes on it are kept, and become free-standing."""
        row = self._db.execute("SELECT label FROM bookmarks WHERE id = ?",
                               (bookmark_id,)).fetchone()
        self._db.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
        self._db.commit()
        if row:
            self._record_activity('bookmark removed', row['label'] or '')

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
        self._record_activity(
            'note added',
            f"{artifact_name or 'case note'}: {body[:60]}")
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

    def case_notes(self):
        """Notes not attached to any artifact -- the case's own record."""
        rows = self._db.execute(
            "SELECT * FROM notes WHERE artifact_ref IS NULL "
            "ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

    def update_note(self, note_id, body):
        """Rewrite a note's body, stamping when it changed."""
        self._db.execute(
            "UPDATE notes SET body = ?, updated_utc = ? WHERE id = ?",
            (body, _utc_now(), note_id))
        self._db.commit()
        self._record_activity('note edited', f'id={note_id}')

    def remove_note(self, note_id):
        self._db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        self._db.commit()
        self._record_activity('note removed', f'id={note_id}')

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
        """Append to the audit trail.

        Deliberately swallows its own failures: an audit line must never be the
        reason a case operation fails, and the operation itself is the thing
        the examiner asked for.
        """
        try:
            self._db.execute(
                "INSERT INTO activity (utc, action, detail) VALUES (?, ?, ?)",
                (_utc_now(), action, str(detail)))
            self._db.commit()
        except sqlite3.Error as exc:
            logger.warning("Could not record activity %r: %s", action, exc)

    # --- schema -----------------------------------------------------------

    # --- analysis modules -------------------------------------------

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
                now, facts.get('sha1')))

        self._db.executemany(
            "INSERT OR REPLACE INTO file_analysis "
            "(evidence_id, artifact_ref, name, path, size, is_deleted, "
            " mime, extension, mismatch, entropy, entropy_peak, "
            " entropy_peak_offset, md5, sha256, note, analysed_utc, sha1) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", payload)

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
        self._db.execute("DELETE FROM file_analysis WHERE evidence_id = ?",
                         (evidence_id,))
        # Modules with jobs of their own keep their findings: re-running
        # the file analysis must not erase a YARA scan or the NTFS read.
        marks = ','.join('?' * len(OWN_JOB_MODULES))
        self._db.execute("DELETE FROM file_findings WHERE evidence_id = ? "
                         f"AND module NOT IN ({marks})",
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
        self._db.execute("DELETE FROM user_activity WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.commit()

    def add_user_activity(self, evidence_id, records):
        """Store records made by core.activity.record()."""
        self._db.executemany(
            "INSERT INTO user_activity (evidence_id, category, what, "
            "time_utc, time_local, subject, user, detail, source, "
            "source_path, source_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [(evidence_id, r['category'], r['what'], r['time'],
              1 if r.get('local') else 0, r['subject'], r.get('user', ''),
              json.dumps(r.get('detail') or {}, default=str), r['source'],
              r.get('path', ''), r.get('ref', '')) for r in records])

    def user_activity(self, evidence_id=None, category=None, limit=None):
        """Activity rows, newest first, `detail` parsed."""
        return query_user_activity(self._db, evidence_id, category,
                                   limit=limit)

    def user_activity_summary(self, evidence_id=None):
        """{category: rows} for the tree and the tab labels."""
        where = " WHERE evidence_id = ?" if evidence_id is not None else ""
        params = [evidence_id] if evidence_id is not None else []
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

    def user_activity_state(self, evidence_id):
        row = self._db.execute(
            "SELECT * FROM user_activity_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None

    # --- NTFS internals ------------------------------------------------

    def clear_ntfs(self, evidence_id):
        for table in ('fs_events', 'usn_journal'):
            self._db.execute(f"DELETE FROM {table} WHERE evidence_id = ?",
                             (evidence_id,))
        self._db.execute("DELETE FROM file_findings WHERE evidence_id = ? "
                         "AND module = 'ntfs'", (evidence_id,))
        self._db.commit()

    def add_fs_events(self, evidence_id, rows):
        """rows: (ref, path, time, macb, source 'SI'|'FN', deleted)."""
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
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?",
                               (evidence_id,)).fetchone()
        label = ''
        if row is not None:
            row = dict(row)
            label = row.get('display_name') or os.path.basename(row['path'])
        safe = ''.join(c if c.isalnum() or c in '-_.' else '_'
                       for c in label)[:60].strip('._')
        folder = os.path.join(self.carved_dir,
                              f"{evidence_id}-{safe}" if safe else
                              str(evidence_id))
        os.makedirs(folder, exist_ok=True)
        return folder

    def clear_carved(self, evidence_id):
        """Forget a previous carve of one piece of evidence.

        The rows only: the files already written stay where they are, and a
        new carve writes the same names over them.
        """
        self._db.execute("DELETE FROM carved_files WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.commit()

    def add_carved(self, evidence_id, record):
        """Record one carved file (a record from carving.write_carved)."""
        offset, size = int(record['offset']), int(record['size'])
        path = record['path']
        try:
            path = os.path.relpath(path, self.folder)
        except ValueError:
            pass            # another drive: keep it absolute
        self._db.execute(
            "INSERT INTO carved_files (evidence_id, artifact_ref, name, path, "
            "offset, size, type, sha256, embedded_date, date_source, "
            "carved_utc, fragments) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, make_span_ref(0, offset, offset + size),
             record['name'], path, offset, size, record['type'],
             record.get('sha256'), record.get('embedded_date'),
             record.get('date_source'), _utc_now(),
             json.dumps(record['fragments']) if record.get('fragments')
             else None))

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
            if not os.path.isabs(row['path']):
                row['path'] = os.path.join(self.folder, row['path'])
            try:
                row['fragments'] = json.loads(row.get('fragments') or 'null')
            except ValueError:
                row['fragments'] = None
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

    def analysis_for_artifact(self, evidence_id, artifact_ref):
        """What is known about one file, for the listing to show."""
        row = self._db.execute(
            "SELECT * FROM file_analysis "
            "WHERE evidence_id = ? AND artifact_ref = ?",
            (evidence_id, artifact_ref)).fetchone()
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
        """Counts for the tree node and the Triage tab."""
        where = " WHERE evidence_id = ?" if evidence_id is not None else ""
        params = [evidence_id] if evidence_id is not None else []

        analysed = self._db.execute(
            f"SELECT COUNT(*) FROM file_analysis{where}", params).fetchone()[0]
        mismatches = len(self.type_mismatches(
            evidence_id, grade=REPORTED_MISMATCHES))
        entropy = len(self.high_entropy_files(evidence_id))
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

        return {'analysed': analysed, 'mismatches': mismatches,
                'carved': carved,
                'high_entropy': entropy, 'duplicate_groups': duplicates,
                'hidden': count('hidden', REPORTED_FINDING_GRADES),
                'photos': count('photo'),
                'photos_located': count('photo', located=True),
                'authors': count('authors')}

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
                added_utc     TEXT,
                verified_utc  TEXT,
                last_status   TEXT,
                read_only     INTEGER NOT NULL DEFAULT 1
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

            CREATE TABLE IF NOT EXISTS tags (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL UNIQUE,
                colour        TEXT
            );

            CREATE TABLE IF NOT EXISTS artifact_tags (
                tag_id        INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT NOT NULL,
                PRIMARY KEY (tag_id, evidence_id, artifact_ref)
            );

            CREATE TABLE IF NOT EXISTS verifications (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
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
                detail        TEXT
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
                fragments      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_carved_evidence
                ON carved_files(evidence_id, offset);

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
                source_ref    TEXT
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
        self._set('schema_version', SCHEMA_VERSION)

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

# --- module helpers -------------------------------------------------------

def query_user_activity(connection, evidence_id=None, category=None,
                        text='', limit=None):
    """Activity rows from a case database connection, newest first.

    Shared by Case and by the Activity tab's reader thread, which uses a
    read-only connection of its own. Rows without a time sort last.
    """
    clauses, params = [], []
    if evidence_id is not None:
        clauses.append("evidence_id = ?")
        params.append(evidence_id)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if text:
        clauses.append("(subject LIKE ? OR what LIKE ? OR user LIKE ? "
                       "OR detail LIKE ? OR source_path LIKE ?)")
        params.extend([f'%{text}%'] * 5)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
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
        out.append(row)
    return out


#: The NTFS tab's sections, by the finding kinds each lists.
NTFS_SECTIONS = {
    'timestomp': ('timestomp',),
    'streams': ('ads', 'motw'),
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
        if not include_routine:
            clauses.append("grade != 'benign'")
        if text:
            clauses.append("(name LIKE ? OR path LIKE ? OR summary LIKE ? "
                           "OR detail LIKE ?)")
            params.extend([f'%{text}%'] * 4)
        query = ("SELECT * FROM file_findings WHERE " + " AND ".join(clauses)
                 + " ORDER BY CASE grade WHEN 'suspicious' THEN 0 "
                 "WHEN 'notable' THEN 1 ELSE 2 END, path")
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


def ntfs_counts(connection, evidence_id=None):
    """{'timestomp': n, 'streams': n, 'journal': n, 'routine_timestomp': n,
    'routine_streams': n} -- what the tab labels and the tree show."""
    where, params = '', []
    if evidence_id is not None:
        where, params = " AND evidence_id = ?", [evidence_id]
    counts = {'timestomp': 0, 'streams': 0, 'routine_timestomp': 0,
              'routine_streams': 0}
    for kind, grade, count in connection.execute(
            "SELECT kind, grade, COUNT(*) FROM file_findings WHERE "
            "module = 'ntfs'" + where + " GROUP BY kind, grade", params):
        section = 'timestomp' if kind == 'timestomp' else 'streams'
        key = section if grade != 'benign' else f'routine_{section}'
        counts[key] += count
    counts['journal'] = connection.execute(
        "SELECT COUNT(*) FROM usn_journal" + where.replace(' AND', ' WHERE'),
        params).fetchone()[0]
    return counts


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


def _hash_file(path, algorithm='md5', progress=None):
    """Hash a file in chunks. Returns the hex digest, or None if unreadable."""
    digest = hashlib.new(algorithm)
    chunk_size = 4 * 1024 * 1024
    try:
        total = os.path.getsize(path)
        done = 0
        with open(path, 'rb') as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, total)
    except OSError as exc:
        logger.error("Could not hash %s: %s", path, exc)
        return None
    return digest.hexdigest()


def is_case_folder(folder):
    """Does this folder hold a case?"""
    return os.path.isfile(os.path.join(folder, CASE_DB_NAME))

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
import logging
import os
import sqlite3

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
SCHEMA_VERSION = 1

#: Status values recorded against a piece of evidence.
STATUS_PENDING = 'pending'      # added, not yet hashed
STATUS_VERIFIED = 'verified'    # present and matching its recorded hash
STATUS_MISSING = 'missing'      # the file is not where the case says it is
STATUS_CHANGED = 'changed'      # present, but no longer the same bytes
STATUS_UNHASHED = 'unhashed'    # present, but nothing to compare against


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

    def update_metadata(self, **fields):
        """Change one or more case_info values."""
        known = {'name', 'number', 'examiner', 'description'}
        unknown = set(fields) - known
        if unknown:
            raise ValueError(f"Not case metadata: {', '.join(sorted(unknown))}")
        self._set_many(fields)
        self._record_activity('metadata edited', ', '.join(sorted(fields)))

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
                self._set_status(row['id'], STATUS_MISSING)
                outcomes.append((row, STATUS_MISSING,
                                 'The file is not at its recorded location.'))
                continue

            expected = row['md5'] or row['sha1'] or row['sha256']
            if not expected:
                self._set_status(row['id'], STATUS_UNHASHED)
                outcomes.append((row, STATUS_UNHASHED,
                                 'No hash was recorded, so nothing can be '
                                 'compared.'))
                continue

            # Size is far cheaper than a hash and settles most mismatches.
            try:
                size = os.path.getsize(path)
            except OSError as exc:
                self._set_status(row['id'], STATUS_MISSING)
                outcomes.append((row, STATUS_MISSING, str(exc)))
                continue

            if row['size'] is not None and size != row['size']:
                self._set_status(row['id'], STATUS_CHANGED)
                outcomes.append((
                    row, STATUS_CHANGED,
                    f"The file is {size:,} bytes; the case recorded "
                    f"{row['size']:,}."))
                continue

            algorithm = ('md5' if row['md5'] else
                         'sha1' if row['sha1'] else 'sha256')
            digest = _hash_file(path, algorithm, progress)
            if digest is None:
                self._set_status(row['id'], STATUS_MISSING)
                outcomes.append((row, STATUS_MISSING,
                                 'The file could not be read.'))
            elif digest.lower() == str(expected).lower():
                self._set_status(row['id'], STATUS_VERIFIED)
                outcomes.append((row, STATUS_VERIFIED,
                                 f'{algorithm.upper()} matches.'))
            else:
                self._set_status(row['id'], STATUS_CHANGED)
                outcomes.append((
                    row, STATUS_CHANGED,
                    f"{algorithm.upper()} is {digest}; the case recorded "
                    f"{expected}."))

        return outcomes

    def _set_status(self, evidence_id, status):
        self._db.execute(
            "UPDATE evidence SET last_status = ? WHERE id = ?",
            (status, evidence_id))
        self._db.commit()

    # --- audit ------------------------------------------------------------

    def activity(self, limit=200):
        """The most recent audit entries, newest first."""
        rows = self._db.execute(
            "SELECT * FROM activity ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(row) for row in rows]

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
                last_status   TEXT
            );

            CREATE TABLE IF NOT EXISTS notes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
                artifact_ref  TEXT,
                artifact_name TEXT,
                artifact_path TEXT,
                body          TEXT NOT NULL,
                created_utc   TEXT,
                updated_utc   TEXT
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

            CREATE TABLE IF NOT EXISTS activity (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                utc           TEXT NOT NULL,
                action        TEXT NOT NULL,
                detail        TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_notes_artifact
                ON notes(evidence_id, artifact_ref);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_artifact
                ON bookmarks(evidence_id, artifact_ref);
        """)
        self._db.commit()
        self._set('schema_version', SCHEMA_VERSION)

    def _migrate(self):
        """Bring an existing case up to the current schema version."""
        # Tables the case predates are created unconditionally; CREATE TABLE IF
        # NOT EXISTS makes this safe for a case at the current version too.
        self._create_schema_tables_only()

        try:
            version = int(self._get('schema_version', 0) or 0)
        except (TypeError, ValueError):
            version = 0

        if version > SCHEMA_VERSION:
            raise CaseError(
                f"This case was written by a newer version of TRACE "
                f"(schema {version}; this build understands {SCHEMA_VERSION}). "
                f"Opening it could lose data.")

        # Future steps go here, each guarded by the version it upgrades from:
        #   if version < 2:
        #       self._db.execute("ALTER TABLE ...")
        #       version = 2

        if version != SCHEMA_VERSION:
            self._set('schema_version', SCHEMA_VERSION)

    def _create_schema_tables_only(self):
        """The schema without stamping a version -- used when migrating."""
        stamp = self._get('schema_version')
        self._create_schema()
        if stamp is not None:
            self._set('schema_version', stamp)


# --- module helpers -------------------------------------------------------

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

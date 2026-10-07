"""Hash sets: known files to set aside, and known files to look for.

A hash set is a list of digests with a meaning attached:

* **known good** -- operating-system and application files (NSRL). A match
  is a file nobody needs to read, and the examiner may hide them all;
* **known bad** -- malware, tools, a list from another case. A match is a
  finding, and TRACE says so;
* **notable** -- anything else worth flagging (a project's documents, a
  contraband list).

Sets live in the examiner's library (`user_data_dir()/hashsets/`), not in a
case: the same NSRL release serves every case. Each imported set is a SQLite
file of digests; an NSRL RDS v3 database can instead be *linked* -- read in
place, read-only -- because a copy of it is tens of gigabytes. Which sets a
case uses, and how, is the case's own setting (`case.setting('hashsets')`),
so the library can grow without changing what an old case reported.

Matching reads digests the triage hash module stored (MD5, SHA-1, SHA-256 in
`file_analysis`, SHA-256 of carved files) and writes one `hash_matches` row
per (file, set). No Qt here.
"""

import csv
import datetime
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import uuid

logger = logging.getLogger('TRACE.HashSets')

KNOWN_GOOD = 'known-good'
KNOWN_BAD = 'known-bad'
NOTABLE = 'notable'

CATEGORIES = {
    KNOWN_GOOD: 'Known good',
    KNOWN_BAD: 'Known bad',
    NOTABLE: 'Notable',
}

ALGORITHMS = ('md5', 'sha1', 'sha256')
ALGORITHM_LABELS = {'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}
_LENGTHS = {32: 'md5', 40: 'sha1', 64: 'sha256'}
_HEX = re.compile(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|'
                  r'[0-9A-Fa-f]{32})(?![0-9A-Fa-f])')

#: Digests written per transaction while importing.
BATCH = 50_000

LIBRARY_FILE = 'library.json'


class HashSetError(Exception):
    """A set could not be imported, opened or used."""


class ImportCancelled(Exception):
    """The examiner stopped an import."""


def algorithm_of(digest):
    return _LENGTHS.get(len(digest))


def default_options():
    """What a case does with hash sets before the examiner has said."""
    return {'enabled': False, 'sets': {}, 'algorithms': list(ALGORITHMS),
            'hide_known_good': True, 'alert_known_bad': True,
            'auto_match': True, 'include_carved': True}


def case_options(case, library=None):
    """The case's options, defaults filled in. Hash sets start switched on
    once the library has any: importing one is asking to use it."""
    stored = case.setting('hashsets') if case is not None else None
    options = default_options()
    if stored:
        options.update(stored)
    elif library is not None and library.sets():
        options['enabled'] = True
    return options


def set_enabled_in(options, entry):
    """Is library set `entry` used under these case options?"""
    chosen = (options.get('sets') or {}).get(entry['id'])
    return entry.get('enabled_by_default', True) if chosen is None \
        else bool(chosen)


# --- the library ----------------------------------------------------------------

class Library:
    """The examiner's hash sets, in one folder."""

    def __init__(self, folder=None):
        if folder is None:
            from trace_app.infra.paths import user_data_dir
            folder = os.path.join(user_data_dir(), 'hashsets')
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._path = os.path.join(folder, LIBRARY_FILE)

    # --- the manifest -------------------------------------------------------

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {'sets': []}
        except (OSError, ValueError) as exc:
            logger.error("Hash set library unreadable: %s", exc)
            return {'sets': []}
        data.setdefault('sets', [])
        return data

    def _save(self, data):
        temporary = self._path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2)
        os.replace(temporary, self._path)

    def sets(self):
        """Every set, as dicts, in the order they were added."""
        out = []
        for entry in self._load()['sets']:
            entry = dict(entry)
            entry['available'] = os.path.exists(self.database_path(entry))
            out.append(entry)
        return out

    def get(self, set_id):
        for entry in self.sets():
            if entry['id'] == set_id:
                return entry
        return None

    def update(self, set_id, **fields):
        allowed = {'name', 'category', 'description', 'enabled_by_default'}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Not a hash set field: {', '.join(unknown)}")
        if 'category' in fields and fields['category'] not in CATEGORIES:
            raise ValueError(f"Unknown category {fields['category']}")
        data = self._load()
        for entry in data['sets']:
            if entry['id'] == set_id:
                entry.update(fields)
                self._save(data)
                return entry
        raise HashSetError("No such hash set")

    def remove(self, set_id):
        data = self._load()
        keep = [e for e in data['sets'] if e['id'] != set_id]
        gone = [e for e in data['sets'] if e['id'] == set_id]
        data['sets'] = keep
        self._save(data)
        for entry in gone:
            if entry.get('kind') == 'imported':
                try:
                    os.remove(self.database_path(entry))
                except OSError:
                    pass

    def database_path(self, entry):
        if entry.get('kind') == 'linked':
            return entry['path']
        return os.path.join(self.folder, entry['file'])

    def _add(self, entry):
        data = self._load()
        data['sets'].append(entry)
        self._save(data)
        return entry

    # --- importing ------------------------------------------------------------

    def import_list(self, path, name, category, description='',
                    columns=None, progress=None, should_stop=None):
        """Import a text or CSV hash list. `columns` (CSV) names the columns
        to read; None reads every digest-shaped token on each line --
        md5sum/sha256sum output, VirusShare lists, one digest per line, and
        TRACE's own exports. Returns the new set's entry."""
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category {category}")
        size = os.path.getsize(path)
        source_hash = _file_sha256(path, should_stop)
        set_id = uuid.uuid4().hex
        file_name = f'{set_id}.db'
        final = os.path.join(self.folder, file_name)
        temporary = final + '.partial'
        connection = _new_set_database(temporary)
        counts = dict.fromkeys(ALGORITHMS, 0)
        lines = skipped = 0
        try:
            with open(path, 'rb') as raw:
                text = io.TextIOWrapper(raw, encoding='utf-8',
                                        errors='replace', newline='')
                batch = []
                for digests, ok in _digests_from(text, columns):
                    lines += 1
                    if not ok:
                        skipped += 1
                    batch.extend(digests)
                    if len(batch) >= BATCH:
                        _insert(connection, batch, counts)
                        batch = []
                        if should_stop and should_stop():
                            raise ImportCancelled()
                        if progress:
                            progress(raw.tell(), size)
                _insert(connection, batch, counts)
            connection.commit()
            total = connection.execute(
                "SELECT COUNT(*) FROM digests").fetchone()[0]
            if not total:
                raise HashSetError(
                    "No MD5, SHA-1 or SHA-256 digests were found in "
                    f"{os.path.basename(path)}.")
            per_algorithm = {algo: connection.execute(
                "SELECT COUNT(*) FROM digests WHERE algorithm = ?",
                (algo,)).fetchone()[0] for algo in ALGORITHMS}
            connection.execute("INSERT INTO meta VALUES ('name', ?)", (name,))
            connection.commit()
        except BaseException:
            connection.close()
            _remove_quietly(temporary)
            raise
        connection.close()
        os.replace(temporary, final)
        entry = {
            'id': set_id, 'name': name, 'category': category,
            'description': description, 'kind': 'imported',
            'file': file_name,
            'algorithms': [a for a in ALGORITHMS if per_algorithm[a]],
            'count': total, 'counts': per_algorithm,
            'source': os.path.basename(path), 'source_sha256': source_hash,
            'source_lines': lines, 'skipped_lines': skipped,
            'added_utc': _utc_now(), 'enabled_by_default': True,
        }
        if progress:
            progress(size, size)
        return self._add(entry)

    def link_nsrl(self, path, name=None, category=KNOWN_GOOD,
                  description=''):
        """Use an NSRL RDS v3 SQLite database in place, read-only. Only the
        digest columns it has an index on are used: an unindexed column of
        a billion rows cannot be searched."""
        try:
            connection = _open_read_only(path)
        except sqlite3.Error as exc:
            raise HashSetError(f"Could not open {os.path.basename(path)}: "
                               f"{exc}") from exc
        try:
            table, columns = _nsrl_layout(connection)
            count = None
            try:
                # The RDS keeps its counts in VERSION; COUNT(*) would read
                # the whole table.
                row = connection.execute(
                    "SELECT * FROM VERSION LIMIT 1").fetchone()
                count = _version_count(connection, row)
            except sqlite3.Error:
                pass
        finally:
            connection.close()
        if not columns:
            raise HashSetError(
                "This database has no indexed SHA-256, SHA-1 or MD5 column. "
                "Import it as a hash list instead, or use an NSRL RDS v3 "
                "release (which is indexed).")
        entry = {
            'id': uuid.uuid4().hex,
            'name': name or os.path.splitext(os.path.basename(path))[0],
            'category': category, 'description': description,
            'kind': 'linked', 'path': os.path.abspath(path),
            'table': table, 'columns': columns,
            'algorithms': [a for a in ALGORITHMS if a in columns],
            'count': count, 'source': os.path.basename(path),
            'source_sha256': None, 'added_utc': _utc_now(),
            'enabled_by_default': True,
        }
        return self._add(entry)

    def export(self, set_id, path):
        """Write a set as text: TRACE's header, then one digest per line.
        Importing the file gives the same set back."""
        entry = self.get(set_id)
        if entry is None:
            raise HashSetError("No such hash set")
        lookup = SetLookup(self, entry)
        written = 0
        try:
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(f"# TRACE hash set: {entry['name']}\n")
                handle.write(f"# category: {entry['category']}\n")
                if entry.get('description'):
                    handle.write(f"# description: {entry['description']}\n")
                for digest in lookup.all_digests():
                    handle.write(digest + '\n')
                    written += 1
        finally:
            lookup.close()
        return written


def read_export_header(path):
    """{'name', 'category', 'description'} from a TRACE export's header, or
    {} -- so re-importing restores what the set was."""
    facts = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            for _ in range(5):
                line = handle.readline()
                if not line.startswith('#'):
                    break
                key, _, value = line[1:].strip().partition(':')
                key = key.strip().lower()
                if key == 'trace hash set':
                    facts['name'] = value.strip()
                elif key in ('category', 'description'):
                    facts[key] = value.strip()
    except OSError:
        return {}
    if facts.get('category') not in CATEGORIES:
        facts.pop('category', None)
    return facts


def sniff_columns(path, sample_lines=50):
    """(header names, {column index: algorithm}) for a CSV: which columns
    hold digests, judged from the first lines. Empty for a plain list."""
    try:
        with open(path, encoding='utf-8', errors='replace', newline='') \
                as handle:
            head = ''.join(handle.readline() for _ in range(sample_lines))
    except OSError:
        return [], {}
    if ',' not in head and '\t' not in head and ';' not in head:
        return [], {}
    try:
        dialect = csv.Sniffer().sniff(head, delimiters=',;\t|')
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(head), dialect))
    if not rows:
        return [], {}
    width = max(len(r) for r in rows)
    first = rows[0]
    has_header = not any(_HEX.fullmatch(cell.strip().strip('"'))
                         for cell in first)
    header = [c.strip() for c in first] if has_header else \
        [f'Column {i + 1}' for i in range(width)]
    found = {}
    for row in rows[1 if has_header else 0:]:
        for index, cell in enumerate(row):
            cell = cell.strip().strip('"')
            if _HEX.fullmatch(cell):
                found.setdefault(index, algorithm_of(cell))
    return header, found


def is_nsrl_database(path):
    """True for an SQLite file shaped like an NSRL RDS v3 release."""
    try:
        with open(path, 'rb') as handle:
            if handle.read(16) != b'SQLite format 3\x00':
                return False
        connection = _open_read_only(path)
    except (OSError, sqlite3.Error):
        return False
    try:
        table, _columns = _nsrl_layout(connection, need_index=False)
        return table is not None
    except (sqlite3.Error, HashSetError):
        return False
    finally:
        connection.close()


# --- looking digests up ------------------------------------------------------------

class SetLookup:
    """One set, opened read-only for lookups."""

    def __init__(self, library, entry):
        self.entry = entry
        path = library.database_path(entry)
        if not os.path.exists(path):
            raise HashSetError(f"{entry['name']}: {path} is missing")
        self.connection = _open_read_only(path)

    def close(self):
        self.connection.close()

    def match(self, algorithm, digests):
        """The digests (lower-case hex) of `algorithm` found in this set."""
        digests = list(digests)
        found = set()
        if self.entry.get('kind') == 'linked':
            column = (self.entry.get('columns') or {}).get(algorithm)
            if not column:
                return found
            table = self.entry.get('table') or 'FILE'
            for start in range(0, len(digests), 400):
                chunk = digests[start:start + 400]
                # The RDS writes upper case; ask for both rather than
                # wrap the column in a function the index cannot serve.
                values = chunk + [d.upper() for d in chunk]
                marks = ','.join('?' * len(values))
                for (value,) in self.connection.execute(
                        f'SELECT "{column}" FROM "{table}" WHERE '
                        f'"{column}" IN ({marks})', values):
                    found.add(str(value).lower())
            return found
        for start in range(0, len(digests), 900):
            chunk = digests[start:start + 900]
            marks = ','.join('?' * len(chunk))
            for (value,) in self.connection.execute(
                    f"SELECT value FROM digests WHERE algorithm = ? AND "
                    f"value IN ({marks})", [algorithm] + chunk):
                found.add(value)
        return found

    def all_digests(self):
        if self.entry.get('kind') == 'linked':
            for algorithm in ALGORITHMS:
                column = (self.entry.get('columns') or {}).get(algorithm)
                if column:
                    table = self.entry.get('table') or 'FILE'
                    for (value,) in self.connection.execute(
                            f'SELECT DISTINCT "{column}" FROM "{table}"'):
                        if value:
                            yield str(value).lower()
            return
        for (value,) in self.connection.execute(
                "SELECT value FROM digests ORDER BY algorithm, value"):
            yield value


def match_case(case, library, options=None, evidence_ids=None,
               progress=None, should_stop=None):
    """Match the case's hashed files (and carved files) against the sets
    the case uses. Replaces earlier matches for the evidence matched.
    Returns {'matched': files, 'known_bad': n, 'notable': n,
    'known_good': n, 'sets': [names]}."""
    options = options or case_options(case, library)
    summary = {'matched': 0, KNOWN_BAD: 0, NOTABLE: 0, KNOWN_GOOD: 0,
               'sets': []}
    rows = case.evidence()
    targets = [r['id'] for r in rows
               if evidence_ids is None or r['id'] in evidence_ids]
    if not options.get('enabled'):
        for evidence_id in targets:
            case.clear_hash_matches(evidence_id)
        return summary
    wanted = [a for a in options.get('algorithms') or ALGORITHMS
              if a in ALGORITHMS]
    entries = [e for e in library.sets()
               if set_enabled_in(options, e) and e.get('available')]
    summary['sets'] = [e['name'] for e in entries]
    for evidence_id in targets:
        files = case.hashed_files(evidence_id,
                                  options.get('include_carved', True))
        by_digest = {algo: {} for algo in ALGORITHMS}
        for row in files:
            for algo in wanted:
                digest = (row.get(algo) or '').lower()
                if digest:
                    by_digest[algo].setdefault(digest, []).append(row)
        matches = []
        for done, entry in enumerate(entries):
            if should_stop and should_stop():
                raise ImportCancelled()
            if progress:
                progress(done, len(entries), entry['name'])
            try:
                lookup = SetLookup(library, entry)
            except (HashSetError, sqlite3.Error) as exc:
                logger.error("Hash set %s unusable: %s", entry['name'], exc)
                continue
            try:
                seen = set()
                for algo in wanted:
                    if algo not in entry.get('algorithms', ALGORITHMS):
                        continue
                    for digest in lookup.match(algo, by_digest[algo].keys()):
                        for row in by_digest[algo].get(digest, ()):
                            key = (row['artifact_ref'], entry['id'])
                            if key in seen:
                                continue
                            seen.add(key)
                            matches.append((
                                row['artifact_ref'], row.get('name'),
                                row.get('path'), row.get('size'),
                                row.get('origin', 'file'), entry['id'],
                                entry['name'], entry['category'], algo,
                                digest))
            finally:
                lookup.close()
        case.replace_hash_matches(evidence_id, matches)
        files_matched = {m[0] for m in matches}
        summary['matched'] += len(files_matched)
        for category in (KNOWN_BAD, NOTABLE, KNOWN_GOOD):
            summary[category] += len({m[0] for m in matches
                                      if m[7] == category})
    case.record_event(
        'hash sets matched',
        f"sets={', '.join(summary['sets']) or 'none'} "
        f"algorithms={','.join(wanted)} files matched={summary['matched']} "
        f"known bad={summary[KNOWN_BAD]} notable={summary[NOTABLE]} "
        f"known good={summary[KNOWN_GOOD]}")
    return summary


# --- helpers ----------------------------------------------------------------------

def _digests_from(text, columns):
    """Yield ([(algorithm, digest)], understood) per line."""
    if columns:
        sample = text.read(65536)
        rest = text
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
        except csv.Error:
            dialect = csv.excel

        def lines():
            yield from io.StringIO(sample)
            yield from rest
        reader = csv.reader(_join_partial(lines()), dialect)
        wanted = sorted(set(columns))
        for row in reader:
            found = []
            for index in wanted:
                if index < len(row):
                    cell = row[index].strip().strip('"')
                    algo = _LENGTHS.get(len(cell)) if _HEX.fullmatch(cell) \
                        else None
                    if algo:
                        found.append((algo, cell.lower()))
            yield found, bool(found)
        return
    for line in text:
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            continue
        found = [(_LENGTHS[len(m)], m.lower()) for m in _HEX.findall(line)]
        yield found, bool(found)


def _join_partial(lines):
    """Lines from the sample and the rest of the file, the line the sample
    cut in two joined back."""
    pending = ''
    for line in lines:
        if pending:
            line = pending + line
            pending = ''
        if not line.endswith(('\n', '\r')):
            pending = line
            continue
        yield line
    if pending:
        yield pending


def _insert(connection, batch, counts):
    if not batch:
        return
    connection.executemany(
        "INSERT OR IGNORE INTO digests (value, algorithm) VALUES (?, ?)",
        [(digest, algo) for algo, digest in batch])
    for algo, _digest in batch:
        counts[algo] += 1


def _new_set_database(path):
    _remove_quietly(path)
    connection = sqlite3.connect(path)
    connection.executescript("""
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        CREATE TABLE digests (value TEXT PRIMARY KEY,
                              algorithm TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    return connection


def _open_read_only(path):
    uri = 'file:' + _uri_path(os.path.abspath(path)) + '?mode=ro'
    return sqlite3.connect(uri, uri=True, timeout=10)


def _uri_path(path):
    from urllib.parse import quote
    path = path.replace('\\', '/')
    if not path.startswith('/'):
        path = '/' + path
    return quote(path, safe='/:')


def _nsrl_layout(connection, need_index=True):
    """(table, {algorithm: column}) of an RDS v3 database."""
    tables = {row[0].upper(): row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")}
    table = tables.get('FILE')
    if table is None:
        return None, {}
    columns = {row[1].lower(): row[1] for row in connection.execute(
        f'PRAGMA table_info("{table}")')}
    indexed = set()
    for index in connection.execute(f'PRAGMA index_list("{table}")'):
        info = list(connection.execute(f'PRAGMA index_info("{index[1]}")'))
        if info:
            indexed.add(info[0][2].lower())
    layout = {}
    for algorithm in ALGORITHMS:
        column = columns.get(algorithm)
        if column and (not need_index or algorithm in indexed):
            layout[algorithm] = column
    if not need_index and not layout:
        return None, {}
    return table, layout


def _version_count(connection, row):
    if row is None:
        return None
    names = [d[0].lower() for d in connection.execute(
        "SELECT * FROM VERSION LIMIT 1").description]
    for key in ('file_count', 'filecount', 'files'):
        if key in names:
            try:
                return int(row[names.index(key)])
            except (TypeError, ValueError):
                return None
    return None


def _file_sha256(path, should_stop=None):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            digest.update(block)
            if should_stop and should_stop():
                raise ImportCancelled()
    return digest.hexdigest()


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%S+00:00')

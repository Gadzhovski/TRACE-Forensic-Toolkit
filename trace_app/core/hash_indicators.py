"""Hashes written in the evidence, matched against what the case holds.

Indexing lists every hash-shaped string in the evidence's text
(search_index: 32, 40 or 64 hex digits). On its own such a string is a
lead at best -- most are cache keys and identifiers. It becomes evidence
when something has that hash: a file analysed in the case, a carve, an
evidence image itself, or an entry of the examiner's hash sets. A hash no
file in the case has, where every file was hashed with its algorithm,
names content that is not here: deleted and gone, on another device, or
not a file's hash at all.

Read-only, on its own connection, so the Indicators tab can ask from a
reader thread while a job writes the case.
"""

import logging
import os
import sqlite3

from trace_app.core import hashsets

logger = logging.getLogger('TRACE.HashIndicators')

#: A file, carve or evidence image of the case has this hash.
IN_CASE = 'in case'
#: Only a hash set has it.
IN_SET = 'in hash set'
#: Files were hashed with its algorithm, and none has it.
NOT_FOUND = 'not found'
#: No file was hashed with its algorithm (SHA-1 is off by default), so
#: whether one has it is unknown -- never reported as "not found".
NOT_CHECKED = 'not checked'

#: Matching files listed per value; the count says how many there were.
MAX_LISTED = 20

ALGORITHM_NAMES = hashsets.ALGORITHM_LABELS

_CASE_DB = 'case.db'


def match(folder, values, stored_options=None, library=None):
    """{value: result} for hash `values` (lower-case hex).

    result: 'status' (IN_CASE, IN_SET, NOT_FOUND, NOT_CHECKED), 'algorithm',
    'files' (dicts: origin 'file' | 'carved' | 'evidence', evidence_id,
    evidence_name, artifact_ref, name, path -- at most MAX_LISTED),
    'file_count', 'sets' ([(name, category)]) and 'text', a line for a
    table cell. `stored_options` is the case's 'hashsets' setting.
    """
    wanted = {}
    for value in values:
        algorithm = hashsets.algorithm_of(value)
        if algorithm:
            wanted.setdefault(algorithm, set()).add(value.lower())
    results = {value: {'algorithm': algorithm, 'files': [],
                       'file_count': 0, 'sets': []}
               for algorithm, group in wanted.items() for value in group}
    if not results:
        return {}
    hashed = set()
    connection = _open(folder)
    if connection is not None:
        try:
            hashed = _match_case(connection, wanted, results)
        except sqlite3.Error as exc:
            logger.error("Could not read the case's file hashes: %s", exc)
        finally:
            connection.close()
    _match_sets(wanted, results, stored_options, library)
    for result in results.values():
        if result['file_count']:
            result['status'] = IN_CASE
        elif result['sets']:
            result['status'] = IN_SET
        elif result['algorithm'] in hashed:
            result['status'] = NOT_FOUND
        else:
            result['status'] = NOT_CHECKED
        result['text'] = describe(result)
    return results


def describe(result):
    """One line for a table cell."""
    parts = []
    files = result['files']
    if files:
        first = files[0]
        what = {'evidence': 'Evidence image', 'carved': 'Carved file'}.get(
            first['origin'], 'File in case')
        name = first.get('name') or ''
        if first['origin'] != 'evidence' and first.get('evidence_name'):
            name += f" ({first['evidence_name']})"
        parts.append(f"{what}: {name}")
        if result['file_count'] > 1:
            parts.append(f"+{result['file_count'] - 1:,} more")
    for name, category in result['sets']:
        label = hashsets.CATEGORIES.get(category, category)
        parts.append(f"{label}: {name}")
    if parts:
        return ' · '.join(parts)
    algorithm = ALGORITHM_NAMES.get(result['algorithm'], result['algorithm'])
    if result['status'] == NOT_FOUND:
        return "No file in the case has it"
    return f"Not checked: files were not hashed with {algorithm}"


def explain(result):
    """A tooltip: what the status means for an examiner."""
    algorithm = ALGORITHM_NAMES.get(result['algorithm'], result['algorithm'])
    status = result['status']
    if status == IN_CASE:
        lines = ["A file in the case has this hash: the text that names it "
                 "refers to that content."]
        for row in result['files']:
            where = row.get('path') or row.get('name') or ''
            image = row.get('evidence_name') or ''
            lines.append(f"• {where}" + (f" — {image}" if image else ''))
        if result['file_count'] > len(result['files']):
            lines.append(f"… {result['file_count'] - len(result['files']):,}"
                         f" more")
        if result['sets']:
            lines.append("Also in: " + ', '.join(n for n, _ in result['sets']))
        return '\n'.join(lines)
    if status == IN_SET:
        return ("No file in the case has this hash, but your hash sets do: "
                + ', '.join(f"{n} ({hashsets.CATEGORIES.get(c, c)})"
                            for n, c in result['sets'])
                + ".\nThe content it names was known, and is not here: "
                  "deleted, on another device, or never stored.")
    if status == NOT_FOUND:
        return (f"Every analysed file was hashed with {algorithm} and none "
                f"has this value. If it is a file's hash, that file is not "
                f"in the case: deleted and overwritten, on another device, "
                f"or never stored here. Many such strings are not file "
                f"hashes at all (cache keys, identifiers).")
    return (f"No file in the case was hashed with {algorithm}, so whether "
            f"one has this value is unknown. Turn {algorithm} on in the "
            f"case settings and run the file analysis to check.")


# --- the case -----------------------------------------------------------------

def _open(folder):
    path = os.path.join(folder, _CASE_DB)
    if not os.path.isfile(path):
        return None
    try:
        connection = hashsets._open_read_only(path)
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error as exc:
        logger.error("Could not open the case database: %s", exc)
        return None


def _tables(connection):
    return {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(connection, table):
    return {row[1] for row in connection.execute(
        f"PRAGMA table_info({table})")}


def _match_case(connection, wanted, results):
    """Fill each result's files from the evidence, analysed and carved
    files. Returns the algorithms some file was hashed with."""
    tables = _tables(connection)
    names = {}
    if 'evidence' in tables:
        columns = _columns(connection, 'evidence')
        for row in connection.execute("SELECT * FROM evidence"):
            row = dict(row)
            names[row['id']] = (row.get('display_name') or os.path.basename(
                (row.get('path') or '').replace('\\', '/')))
            seen = set()
            for algorithm in hashsets.ALGORITHMS:
                for column in (algorithm, f'stored_{algorithm}'):
                    if column not in columns:
                        continue
                    digest = (row.get(column) or '').lower()
                    if digest in wanted.get(algorithm, ()) \
                            and digest not in seen:
                        seen.add(digest)
                        _add(results[digest], {
                            'origin': 'evidence', 'evidence_id': row['id'],
                            'evidence_name': names[row['id']],
                            'artifact_ref': None, 'name': names[row['id']],
                            'path': row.get('path')})
    hashed = set()
    for table, origin in (('file_analysis', 'file'),
                          ('carved_files', 'carved')):
        if table not in tables:
            continue
        present = [a for a in hashsets.ALGORITHMS
                   if a in _columns(connection, table)]
        for algorithm in present:
            if connection.execute(
                    f"SELECT 1 FROM {table} WHERE {algorithm} IS NOT NULL "
                    f"LIMIT 1").fetchone():
                hashed.add(algorithm)
        asked = [a for a in present if wanted.get(a)]
        if not asked:
            continue
        # One pass over the table: its hash columns carry no index, and an
        # IN list per chunk of values would scan it once per chunk.
        where = ' OR '.join(f"{a} IS NOT NULL" for a in asked)
        for row in connection.execute(
                f"SELECT evidence_id, artifact_ref, name, path, "
                f"{', '.join(asked)} FROM {table} WHERE {where}"):
            for algorithm in asked:
                digest = row[algorithm]
                if digest and digest.lower() in wanted[algorithm]:
                    _add(results[digest.lower()], {
                        'origin': origin, 'evidence_id': row['evidence_id'],
                        'evidence_name': names.get(row['evidence_id'], ''),
                        'artifact_ref': row['artifact_ref'],
                        'name': row['name'], 'path': row['path']})
    return hashed


def _add(result, row):
    result['file_count'] += 1
    if len(result['files']) < MAX_LISTED:
        result['files'].append(row)


# --- hash sets ------------------------------------------------------------------

def _match_sets(wanted, results, stored_options, library):
    """Add the sets each value is in, under the case's hash set options."""
    try:
        library = library or hashsets.Library()
        entries = library.sets()
    except Exception as exc:     # the library is the examiner's, not evidence
        logger.error("Could not read the hash set library: %s", exc)
        return
    options = hashsets.default_options()
    if stored_options:
        options.update(stored_options)
    elif entries:
        options['enabled'] = True
    if not options.get('enabled'):
        return
    for entry in entries:
        if not (hashsets.set_enabled_in(options, entry)
                and entry.get('available')):
            continue
        try:
            lookup = hashsets.SetLookup(library, entry)
        except (hashsets.HashSetError, sqlite3.Error) as exc:
            logger.error("Hash set %s unusable: %s", entry['name'], exc)
            continue
        try:
            for algorithm, group in wanted.items():
                if algorithm not in entry.get('algorithms',
                                              hashsets.ALGORITHMS):
                    continue
                for digest in lookup.match(algorithm, sorted(group)):
                    if digest in results:
                        results[digest]['sets'].append(
                            (entry['name'], entry['category']))
        except sqlite3.Error as exc:
            logger.error("Hash set %s lookup failed: %s", entry['name'], exc)
        finally:
            lookup.close()

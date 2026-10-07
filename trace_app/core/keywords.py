"""Keyword lists: the examiner's terms, searched for across a case at once.

A list is a set of terms -- words and phrases, prefixes (`term*`) and
regular expressions (`/pattern/` or `re:pattern`) -- kept in a library in
`user_data_dir()/keywords/`, imported from a text file (one term a line,
`#` comments) or a CSV (term, type, note), or typed in. Which lists a case
uses is the case's setting (`case.setting('keywords')`).

A run searches the case's search index -- what indexing extracted from
every file, archive member, mailbox message and attachment -- so it reads
no evidence and takes seconds, not hours. Words and prefixes go through the
full-text index and are then confirmed in the text (the index splits
"evil.exe" into two words and folds accents; a hit is counted only where
the term itself appears). Regular expressions are run over every item's
text in one pass.

A hit is a finding (module 'keywords', one per term per file): the term,
its list, how many times it appears and where first, in context. Findings
of earlier runs over the same images are replaced; the run is audited with
every list's terms.

No Qt here.
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
import unicodedata
import uuid

logger = logging.getLogger('TRACE.Keywords')

MODULE_KEYWORDS = 'keywords'
LIBRARY_FILE = 'library.json'
GRADES = ('notable', 'suspicious')
KINDS = ('text', 'prefix', 'regex')
KIND_LABELS = {'text': 'Word or phrase', 'prefix': 'Prefix',
               'regex': 'Regular expression'}

#: Files recorded per term. A term found in more is said to be, not listed.
MAX_FILES_PER_TERM = 5000
#: Occurrences counted per file; more is reported as "1,000+".
MAX_COUNT = 1000
CONTEXT = 60


class KeywordError(Exception):
    """A list could not be read, or a term is not valid."""


class SearchCancelled(Exception):
    """The examiner stopped the run."""


# --- terms ----------------------------------------------------------------------

def parse_term(text):
    """A typed or imported line as a term dict, or None for a blank line or
    a comment. Raises KeywordError for a regular expression that does not
    compile."""
    text = (text or '').strip()
    if not text or text.startswith('#'):
        return None
    if len(text) > 2 and text.startswith('/') and text.endswith('/'):
        return make_term(text[1:-1], 'regex')
    if text.lower().startswith('re:'):
        return make_term(text[3:].strip(), 'regex')
    if len(text) > 1 and text.endswith('*') and '*' not in text[:-1]:
        return make_term(text[:-1], 'prefix')
    if len(text) > 1 and text[0] == text[-1] == '"':
        text = text[1:-1]
    return make_term(text, 'text')


#: POSIX bracket classes, as grep writes them -- keyword lists made for
#: other tools use them -- and what Python's re spells them as.
POSIX_CLASSES = {
    'alpha': 'a-zA-Z', 'digit': '0-9', 'alnum': 'a-zA-Z0-9',
    'upper': 'A-Z', 'lower': 'a-z', 'space': r' \t\n\r\f\v',
    'blank': r' \t', 'punct': r'!-/:-@\[-`{-~', 'xdigit': '0-9A-Fa-f',
    'word': r'\w', 'cntrl': r'\x00-\x1f\x7f', 'print': r' -~',
    'graph': r'!-~',
}


def python_regex(pattern):
    """`pattern` with POSIX classes ([[:alpha:]]) in Python's spelling."""
    return re.sub(r'\[:([a-z]+):\]',
                  lambda m: POSIX_CLASSES.get(m.group(1), m.group(0)),
                  pattern)


def make_term(term, kind='text', note=''):
    term = (term or '').strip()
    if kind not in KINDS:
        raise KeywordError(f"Unknown term type: {kind}")
    if not term:
        raise KeywordError("A term cannot be empty")
    if kind == 'regex':
        try:
            re.compile(python_regex(term))
        except re.error as exc:
            raise KeywordError(f"/{term}/ is not a valid regular "
                               f"expression: {exc}") from exc
    return {'term': term, 'kind': kind, 'note': (note or '').strip()}


def display(term):
    """How a term is written back: /regex/, prefix*, or the text."""
    if term['kind'] == 'regex':
        return f"/{term['term']}/"
    if term['kind'] == 'prefix':
        return f"{term['term']}*"
    return term['term']


def read_terms(data, name=''):
    """Terms from a file's bytes: CSV (term[, type][, note]) by extension
    or a header row, otherwise one term a line. Returns (terms, problems):
    a line that is not a valid term is reported, not silently dropped."""
    for codec in ('utf-8-sig', 'utf-16', 'cp1252'):
        try:
            text = data.decode(codec)
            if codec == 'utf-16' and not data[:2] in (b'\xff\xfe', b'\xfe\xff'):
                continue
            break
        except UnicodeDecodeError:
            continue
    else:
        text = data.decode('latin-1')
    terms, problems, seen = [], [], set()
    lines = text.splitlines()
    first = lines[0].lower() if lines else ''
    is_csv = name.lower().endswith('.csv') or (
        ',' in first and first.split(',')[0].strip(' "') in ('term',
                                                              'keyword'))
    if is_csv:
        rows = list(csv.reader(io.StringIO(text)))
        if rows and rows[0] and rows[0][0].strip().lower() in ('term',
                                                               'keyword'):
            rows = rows[1:]
        for number, row in enumerate(rows, 1):
            if not row or not row[0].strip() or row[0].startswith('#'):
                continue
            kind = (row[1].strip().lower() if len(row) > 1 else '') or 'text'
            kind = {'word': 'text', 'phrase': 'text', 're': 'regex',
                    'regexp': 'regex'}.get(kind, kind)
            try:
                term = make_term(row[0], kind,
                                 row[2] if len(row) > 2 else '')
            except KeywordError as exc:
                problems.append(f"Row {number}: {exc}")
                continue
            if (term['term'], term['kind']) not in seen:
                seen.add((term['term'], term['kind']))
                terms.append(term)
        return terms, problems
    for number, line in enumerate(lines, 1):
        try:
            term = parse_term(line)
        except KeywordError as exc:
            problems.append(f"Line {number}: {exc}")
            continue
        if term and (term['term'], term['kind']) not in seen:
            seen.add((term['term'], term['kind']))
            terms.append(term)
    return terms, problems


# --- the library ------------------------------------------------------------------

def default_options():
    return {'enabled': False, 'lists': {}}


def case_options(case, library=None):
    stored = case.setting('keywords') if case is not None else None
    options = default_options()
    if stored:
        options.update(stored)
    elif library is not None and library.lists():
        options['enabled'] = True
    return options


def list_enabled_in(options, entry):
    chosen = (options.get('lists') or {}).get(entry['id'])
    return entry.get('enabled_by_default', True) if chosen is None \
        else bool(chosen)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%S+00:00')


class Library:
    def __init__(self, folder=None):
        if folder is None:
            from trace_app.infra.paths import user_data_dir
            folder = os.path.join(user_data_dir(), 'keywords')
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._path = os.path.join(folder, LIBRARY_FILE)

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {'lists': []}
        except (OSError, ValueError) as exc:
            logger.error("Keyword library unreadable: %s", exc)
            return {'lists': []}
        data.setdefault('lists', [])
        return data

    def _save(self, data):
        temporary = self._path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(temporary, self._path)

    def lists(self):
        return [dict(entry) for entry in self._load()['lists']]

    def get(self, list_id):
        return next((e for e in self.lists() if e['id'] == list_id), None)

    def create(self, name, terms, grade='notable', description='',
               source='', source_sha256=''):
        if grade not in GRADES:
            raise ValueError("Unknown grade")
        name = (name or '').strip() or 'Keywords'
        entry = {'id': uuid.uuid4().hex[:12], 'name': name,
                 'grade': grade, 'description': description,
                 'enabled_by_default': True, 'added_utc': _utc_now(),
                 'source': source, 'source_sha256': source_sha256,
                 'terms': [make_term(t['term'], t['kind'], t.get('note'))
                           for t in terms]}
        data = self._load()
        data['lists'].append(entry)
        self._save(data)
        return entry

    def import_file(self, path, name=None, grade='notable', description=''):
        """A list from a file. Raises KeywordError, naming every line that
        is not a valid term, when any is not -- nothing is kept then."""
        with open(path, 'rb') as handle:
            data = handle.read()
        terms, problems = read_terms(data, os.path.basename(path))
        if problems:
            raise KeywordError('\n'.join(problems[:20]) + (
                f"\n…and {len(problems) - 20} more" if len(problems) > 20
                else ''))
        if not terms:
            raise KeywordError(f"No terms in {os.path.basename(path)}")
        return self.create(
            name or os.path.splitext(os.path.basename(path))[0], terms,
            grade, description, os.path.abspath(path),
            hashlib.sha256(data).hexdigest())

    def update(self, list_id, **fields):
        allowed = {'name', 'grade', 'description', 'enabled_by_default',
                   'terms'}
        if set(fields) - allowed:
            raise ValueError("Not a keyword list field")
        if 'grade' in fields and fields['grade'] not in GRADES:
            raise ValueError("Unknown grade")
        if 'terms' in fields:
            fields['terms'] = [make_term(t['term'], t['kind'], t.get('note'))
                               for t in fields['terms']]
        data = self._load()
        for entry in data['lists']:
            if entry['id'] == list_id:
                entry.update(fields)
                entry['modified_utc'] = _utc_now()
                self._save(data)
                return entry
        raise KeywordError("No such keyword list")

    def remove(self, list_id):
        data = self._load()
        data['lists'] = [e for e in data['lists'] if e['id'] != list_id]
        self._save(data)

    def export_text(self, list_id, path):
        entry = self.get(list_id)
        if entry is None:
            raise KeywordError("No such keyword list")
        lines = [f"# {entry['name']}"]
        if entry.get('description'):
            lines.append(f"# {entry['description']}")
        lines += [display(t) for t in entry['terms']]
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write('\n'.join(lines) + '\n')


# --- matching ---------------------------------------------------------------------

def _fold(text):
    """Lower case, accents removed -- how the index compares words."""
    text = unicodedata.normalize('NFKD', text or '')
    return ''.join(c for c in text if not unicodedata.combining(c)).lower()


def _pattern(term):
    """The compiled pattern that confirms a term in text (folded for words
    and prefixes, as written for a regular expression)."""
    if term['kind'] == 'regex':
        return re.compile(python_regex(term['term']), re.IGNORECASE)
    folded = re.escape(_fold(term['term']))
    if term['kind'] == 'prefix':
        return re.compile(r'(?<!\w)' + folded + r'\w*')
    return re.compile(folded)


def _fts_query(term):
    """An FTS5 expression for a word or prefix term, or None when the term
    has no word the index would have kept (only punctuation)."""
    words = re.findall(r'\w+', _fold(term['term']))
    if not words:
        return None
    phrase = '"' + ' '.join(words).replace('"', '""') + '"'
    return phrase + '*' if term['kind'] == 'prefix' else phrase


def _occurrences(pattern, text, folded):
    """(how many times, the first match) in `text`."""
    haystack = _fold(text) if folded else text
    count, first = 0, None
    for match in pattern.finditer(haystack):
        if first is None:
            first = match
        count += 1
        if count >= MAX_COUNT:
            break
    return count, first


def _measure(pattern, row, folded):
    """(occurrences up to MAX_COUNT, the first in context) or (0, '').

    The content is what is counted; a term only in the file's name is one
    hit, said to be in the name. The folders on the path are not searched:
    a term naming a folder would otherwise hit every file under it."""
    body = row['body'] or ''
    count, first = _occurrences(pattern, body, folded)
    if count:
        start, end = first.span()
        # Folding can change lengths (ß, ligatures); the excerpt is cut
        # from the text as written, around the same position.
        begin = max(0, start - CONTEXT)
        excerpt = ' '.join(body[begin:end + CONTEXT].split())
        return count, ('… ' if begin else '') + excerpt + (
            ' …' if end + CONTEXT < len(body) else '')
    name = row['name'] or ''
    if _occurrences(pattern, name, folded)[0]:
        return 1, f"(in the name) {name}"
    return 0, ''


def _evidence_clause(evidence_ids, column='evidence_id'):
    ids = [int(e) for e in evidence_ids]
    return f"{column} IN ({','.join('?' * len(ids))})", ids


def search_lists(index_db, entries, evidence_ids, progress=None,
                 should_stop=None):
    """Every term of every list in `entries` over the index's items for
    `evidence_ids`. Returns {(list_id, term index): [hit, ...]}, a hit being
    the item's facts with 'hits' and 'excerpt'."""
    where, params = _evidence_clause(evidence_ids, 'i.evidence_id')
    jobs = [(entry, position, term) for entry in entries
            for position, term in enumerate(entry['terms'])]
    total = len(jobs) + 1
    out = {}
    done = 0
    regexes = []
    for entry, position, term in jobs:
        if should_stop and should_stop():
            raise SearchCancelled()
        key = (entry['id'], position)
        query = _fts_query(term) if term['kind'] != 'regex' else None
        if query is not None:
            # Name and content; the path's folders are not searched.
            query = f'{{name body}} : {query}'
        if term['kind'] == 'regex' or query is None:
            regexes.append((key, term))
            continue
        done += 1
        if progress:
            progress(done, total, display(term))
        pattern = _pattern(term)
        hits = []
        try:
            rows = index_db.execute(
                "SELECT i.id, i.evidence_id, i.artifact_ref, i.kind, i.name, "
                "i.path, i.size, i.body FROM search_fts "
                "JOIN indexed_items i ON i.id = search_fts.rowid "
                f"WHERE search_fts MATCH ? AND {where}",
                [query] + params)
            for row in rows:
                count, excerpt = _measure(pattern, row, True)
                if count:
                    hits.append(_hit(row, count, excerpt))
                    if len(hits) >= MAX_FILES_PER_TERM:
                        break
        except sqlite3.OperationalError as exc:
            logger.warning("Keyword %r could not be searched: %s",
                           term['term'], exc)
            regexes.append((key, dict(term, kind='regex',
                                      term=re.escape(term['term']))))
            continue
        out[key] = hits
    if regexes:
        if progress:
            progress(done, total, f"{len(regexes)} regular expression(s)")
        compiled = [(key, _pattern(term), term['kind'] != 'regex')
                    for key, term in regexes]
        for key, _p, _f in compiled:
            out.setdefault(key, [])
        rows = index_db.execute(
            "SELECT i.id, i.evidence_id, i.artifact_ref, i.kind, i.name, "
            f"i.path, i.size, i.body FROM indexed_items i WHERE {where}",
            params)
        for number, row in enumerate(rows):
            if number % 200 == 0 and should_stop and should_stop():
                raise SearchCancelled()
            for key, pattern, folded in compiled:
                if len(out[key]) >= MAX_FILES_PER_TERM:
                    continue
                count, excerpt = _measure(pattern, row, folded)
                if count:
                    out[key].append(_hit(row, count, excerpt))
    if progress:
        progress(total, total, '')
    return out


def _hit(row, count, excerpt):
    return {'evidence_id': row['evidence_id'],
            'artifact_ref': row['artifact_ref'], 'item_kind': row['kind'],
            'name': row['name'], 'path': row['path'], 'size': row['size'],
            'hits': count, 'excerpt': excerpt}


def run_case(case, library, options=None, evidence_ids=None, progress=None,
             should_stop=None):
    """Search the case's index with the lists it uses, for `evidence_ids`
    (every indexed image when None); replaces those images' keyword
    findings. Returns {'files': n, 'terms_hit': n, 'not_indexed': [...]}."""
    from trace_app.core.search_index import SEARCH_DB_NAME, INDEX_DONE
    options = options or case_options(case, library)
    entries = [e for e in library.lists() if list_enabled_in(options, e)]
    path = os.path.join(case.folder, SEARCH_DB_NAME)
    evidence_ids = [row['id'] for row in case.evidence()] \
        if evidence_ids is None else list(evidence_ids)
    indexed, not_indexed = [], []
    if os.path.exists(path):
        connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                     timeout=30)
        connection.row_factory = sqlite3.Row
    else:
        connection = None
    try:
        for evidence_id in evidence_ids:
            state = connection.execute(
                "SELECT status FROM index_state WHERE evidence_id = ?",
                (evidence_id,)).fetchone() if connection else None
            (indexed if state and state['status'] == INDEX_DONE
             else not_indexed).append(evidence_id)
        if not options.get('enabled') or not entries:
            for evidence_id in indexed:
                case.clear_findings(evidence_id, MODULE_KEYWORDS)
            return {'files': 0, 'terms_hit': 0, 'not_indexed': not_indexed}
        if not indexed:
            return {'files': 0, 'terms_hit': 0, 'not_indexed': not_indexed}
        case.record_event(
            'keyword search started',
            f"evidence ids={','.join(map(str, indexed))} lists="
            + '; '.join(f"{e['name']} ({len(e['terms'])} terms: "
                        + ', '.join(display(t) for t in e['terms'][:200])
                        + ')' for e in entries))
        found = search_lists(connection, entries, indexed, progress,
                             should_stop)
    except SearchCancelled:
        case.record_event('keyword search cancelled',
                          f"evidence ids={','.join(map(str, indexed))}")
        raise
    finally:
        if connection is not None:
            connection.close()

    by_evidence = {evidence_id: [] for evidence_id in indexed}
    files, terms_hit = set(), 0
    for entry in entries:
        for position, term in enumerate(entry['terms']):
            hits = found.get((entry['id'], position)) or []
            if hits:
                terms_hit += 1
            for hit in hits:
                files.add((hit['evidence_id'], hit['artifact_ref'],
                           hit['path']))
                count = f"{hit['hits']:,}" + (
                    '+' if hit['hits'] >= MAX_COUNT else '')
                detail = {'list_id': entry['id'], 'list': entry['name'],
                          'term': display(term), 'term_kind': term['kind'],
                          'note': term.get('note') or '',
                          'hits': hit['hits'], 'excerpt': hit['excerpt'],
                          'item_kind': hit['item_kind'],
                          'truncated': len(hits) >= MAX_FILES_PER_TERM}
                by_evidence.setdefault(hit['evidence_id'], []).append((
                    hit['artifact_ref'], hit['name'], hit['path'],
                    hit['size'], 'keyword', entry['grade'],
                    f"“{display(term)}” — {count} hit(s) "
                    f"({entry['name']})",
                    json.dumps(detail, default=str)))
    for evidence_id, rows in by_evidence.items():
        case.clear_findings(evidence_id, MODULE_KEYWORDS)
        for start in range(0, len(rows), 500):
            case.add_module_findings(evidence_id, MODULE_KEYWORDS,
                                     rows[start:start + 500])
    case.record_event(
        'keyword search finished',
        f"evidence ids={','.join(map(str, indexed))} terms with hits="
        f"{terms_hit} files={len(files)}"
        + (f" not indexed={','.join(map(str, not_indexed))}"
           if not_indexed else ''))
    return {'files': len(files), 'terms_hit': terms_hit,
            'not_indexed': not_indexed}


def term_summary(findings):
    """[{list, term, term_kind, grade, files, hits}] from keyword findings,
    the most widespread first within each list."""
    groups = {}
    for finding in findings:
        detail = finding.get('detail') or {}
        key = (detail.get('list_id'), detail.get('term'))
        group = groups.setdefault(key, {
            'list_id': detail.get('list_id'), 'list': detail.get('list'),
            'term': detail.get('term'), 'term_kind': detail.get('term_kind'),
            'note': detail.get('note') or '', 'grade': finding.get('grade'),
            'files': 0, 'hits': 0, 'truncated': False})
        group['files'] += 1
        group['hits'] += int(detail.get('hits') or 0)
        group['truncated'] |= bool(detail.get('truncated'))
    return sorted(groups.values(), key=lambda g: (
        (g['list'] or '').lower(), -g['files'], (g['term'] or '').lower()))

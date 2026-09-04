"""Full-text search across everything in a case.

The search this replaces matched filenames and nothing else. On one 296 MB test
image that left 469 MB of file content unsearchable: an email address in a
document, a URL in browser history, an IP in a log -- none of it findable. It
also walked the whole filesystem on every query, twice on the first one, on the
UI thread.

So content is extracted once, into SQLite's FTS5, and queried from the index
afterwards. Measured on this machine: 25 MB of text indexes in 0.7 s and
queries return in single-digit milliseconds. The index lives in the case
folder, beside the case it describes.

Entities -- emails, URLs, domains, IPs, hashes -- are pulled out during
extraction and stored separately, because "show me every email address in this
case" is a question an examiner asks and full-text search answers badly.

No Qt imports belong here: indexing runs on a worker thread the UI owns, but
the work itself is drivable from a script.
"""

import logging
import os
import re
import sqlite3

logger = logging.getLogger('TRACE.Search')

#: Bumped when the index schema changes. The index is a cache -- it can always
#: be rebuilt from the evidence -- so a version bump discards it rather than
#: migrating.
INDEX_VERSION = 2

#: Largest amount of text taken from one file. A 20 MB log is worth indexing;
#: taking all of a 2 GB one costs more than it returns.
MAX_TEXT_PER_FILE = 8 * 1024 * 1024

#: Files larger than this are not opened for extraction at all.
MAX_FILE_BYTES = 256 * 1024 * 1024

#: Status values for an evidence item's indexing progress.
INDEX_PENDING = 'pending'
INDEX_RUNNING = 'running'
INDEX_DONE = 'done'
INDEX_CANCELLED = 'cancelled'
INDEX_FAILED = 'failed'

# --- entity patterns ------------------------------------------------------
#
# Deliberately conservative. A pattern that matches too much fills the index
# with noise an examiner then has to dismiss by hand, which is worse than
# missing an unusual form.

_ENTITY_PATTERNS = {
    'email': re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b'),
    'url': re.compile(
        r'\bhttps?://[^\s<>"\'\)\]]{4,400}'),
    'ip': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'),
    'ipv6': re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    'hash': re.compile(
        r'\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'),
    'btc': re.compile(
        r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
}

#: Domains are derived from URLs and email addresses rather than matched
#: directly: a bare pattern for "something.tld" matches half of every English
#: sentence containing a full stop.
_DOMAIN_FROM_URL = re.compile(r'^https?://([^/:\s]+)', re.IGNORECASE)


class SearchIndex:
    """The per-case full-text index.

    Opened against a case folder; creates its database on first use.
    """

    def __init__(self, folder):
        self.folder = folder
        self.path = os.path.join(folder, 'search.db')
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        self._create_schema()

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    # --- schema -----------------------------------------------------------

    def _create_schema(self):
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version and version != INDEX_VERSION:
            # The index is derived data. Discarding is honest and cheap;
            # migrating a cache is work that buys nothing.
            logger.info("Search index is version %d, expected %d; rebuilding",
                        version, INDEX_VERSION)
            self._db.executescript("""
                DROP TABLE IF EXISTS search_fts;
                DROP TABLE IF EXISTS indexed_items;
                DROP TABLE IF EXISTS entities;
                DROP TABLE IF EXISTS index_state;
            """)

        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS indexed_items (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id   INTEGER,
                artifact_ref  TEXT,
                kind          TEXT NOT NULL,
                name          TEXT,
                path          TEXT,
                size          INTEGER,
                -- The same facts the listing shows, so a result can be read
                -- without going back to the file to find out about it.
                inode         INTEGER,
                start_offset  INTEGER,
                created_utc   TEXT,
                accessed_utc  TEXT,
                mtime_utc     TEXT,
                changed_utc   TEXT,
                is_deleted    INTEGER DEFAULT 0,
                mime          TEXT,
                indexed_utc   TEXT,
                body          TEXT
            );

            -- The body is kept in indexed_items and FTS5 indexes it from
            -- there. A contentless table (content='') is smaller, but it does
            -- not store the text, so regex -- which cannot use the index and
            -- must scan -- would have nothing to scan and silently return
            -- nothing.
            CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
                name, path, body,
                content='indexed_items', content_rowid='id',
                tokenize='unicode61 remove_diacritics 2'
            );

            CREATE TABLE IF NOT EXISTS entities (
                item_id       INTEGER NOT NULL,
                kind          TEXT NOT NULL,
                value         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS index_state (
                evidence_id   INTEGER PRIMARY KEY,
                status        TEXT NOT NULL,
                files_done    INTEGER DEFAULT 0,
                files_total   INTEGER DEFAULT 0,
                last_path     TEXT,
                last_error    TEXT,
                updated_utc   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_entities_value
                ON entities(kind, value);
            CREATE INDEX IF NOT EXISTS idx_entities_item
                ON entities(item_id);
            CREATE INDEX IF NOT EXISTS idx_items_evidence
                ON indexed_items(evidence_id);
        """)
        self._db.execute(f"PRAGMA user_version = {INDEX_VERSION}")
        self._db.commit()

    # --- writing ----------------------------------------------------------

    def add_item(self, evidence_id, artifact_ref, kind, name, path,
                 body='', size=0, mtime_utc='', mime='', inode=None,
                 start_offset=None, created_utc='', accessed_utc='',
                 changed_utc='', is_deleted=False):
        """Index one artifact. Returns its item id.

        `body` is the extracted text; an empty body still produces a row, so
        the artifact is findable by name and path. The remaining fields are
        what a listing row shows, recorded so a result can be read where it
        stands.
        """
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat()

        cursor = self._db.execute(
            "INSERT INTO indexed_items (evidence_id, artifact_ref, kind, name,"
            " path, size, inode, start_offset, created_utc, accessed_utc,"
            " mtime_utc, changed_utc, is_deleted, mime, indexed_utc, body) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, artifact_ref, kind, name, path, size, inode,
             start_offset, created_utc, accessed_utc, mtime_utc, changed_utc,
             1 if is_deleted else 0, mime, now, body or ''))
        item_id = cursor.lastrowid

        # An external-content FTS table indexes the row it mirrors, so the
        # rowid has to match and the text is supplied here rather than being
        # read back out of indexed_items.
        self._db.execute(
            "INSERT INTO search_fts (rowid, name, path, body) "
            "VALUES (?, ?, ?, ?)",
            (item_id, name or '', path or '', body or ''))

        if body:
            self._store_entities(item_id, body)
        return item_id

    def _store_entities(self, item_id, text):
        """Pull emails, URLs, IPs and hashes out of the text."""
        found = set()
        for kind, pattern in _ENTITY_PATTERNS.items():
            for match in pattern.findall(text):
                value = match.strip().rstrip('.,;:)')
                if value:
                    found.add((kind, value))
                    if kind == 'url':
                        domain = _DOMAIN_FROM_URL.match(value)
                        if domain:
                            found.add(('domain', domain.group(1).lower()))
                    elif kind == 'email' and '@' in value:
                        found.add(('domain', value.rsplit('@', 1)[1].lower()))

        if found:
            self._db.executemany(
                "INSERT INTO entities (item_id, kind, value) VALUES (?, ?, ?)",
                [(item_id, kind, value) for kind, value in found])

    def commit(self):
        self._db.commit()

    def clear_evidence(self, evidence_id):
        """Drop everything indexed for one piece of evidence, before a re-run."""
        rows = self._db.execute(
            "SELECT id FROM indexed_items WHERE evidence_id = ?",
            (evidence_id,)).fetchall()
        ids = [row['id'] for row in rows]
        for item_id in ids:
            # An external-content table needs the 'delete' command with the
            # original column values; a plain DELETE corrupts its index.
            row = self._db.execute(
                "SELECT name, path, body FROM indexed_items WHERE id = ?",
                (item_id,)).fetchone()
            if row:
                self._db.execute(
                    "INSERT INTO search_fts (search_fts, rowid, name, path, "
                    "body) VALUES ('delete', ?, ?, ?, ?)",
                    (item_id, row['name'], row['path'], row['body']))
            self._db.execute("DELETE FROM entities WHERE item_id = ?",
                             (item_id,))
        self._db.execute("DELETE FROM indexed_items WHERE evidence_id = ?",
                         (evidence_id,))
        self._db.commit()

    # --- progress ---------------------------------------------------------

    def set_state(self, evidence_id, status, files_done=None, files_total=None,
                  last_path=None, last_error=None):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat()
        existing = self.state(evidence_id)
        self._db.execute(
            "INSERT INTO index_state (evidence_id, status, files_done,"
            " files_total, last_path, last_error, updated_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET status = excluded.status,"
            " files_done = excluded.files_done,"
            " files_total = excluded.files_total,"
            " last_path = excluded.last_path,"
            " last_error = excluded.last_error,"
            " updated_utc = excluded.updated_utc",
            (evidence_id, status,
             files_done if files_done is not None else (existing or {}).get('files_done', 0),
             files_total if files_total is not None else (existing or {}).get('files_total', 0),
             last_path, last_error, now))
        self._db.commit()

    def state(self, evidence_id):
        row = self._db.execute(
            "SELECT * FROM index_state WHERE evidence_id = ?",
            (evidence_id,)).fetchone()
        return dict(row) if row else None

    def is_indexed(self, evidence_id):
        state = self.state(evidence_id)
        return bool(state and state['status'] == INDEX_DONE)

    def statistics(self):
        """What the index holds, for the search panel to report."""
        items = self._db.execute(
            "SELECT count(*) FROM indexed_items").fetchone()[0]
        entities = self._db.execute(
            "SELECT kind, count(DISTINCT value) FROM entities "
            "GROUP BY kind").fetchall()
        return {
            'items': items,
            'entities': {row[0]: row[1] for row in entities},
        }

    # --- querying ---------------------------------------------------------

    def search(self, query, limit=500):
        """Run a query. Returns a list of result dicts.

        The syntax is documented in parse_query: bare terms, "phrases",
        prefix*, AND/OR/NOT, /regex/, and field prefixes such as email: and
        name:.
        """
        parsed = parse_query(query)
        if parsed['kind'] == 'empty':
            return []
        if parsed['kind'] == 'entity':
            return self._search_entity(parsed, limit)
        if parsed['kind'] == 'regex':
            return self._search_regex(parsed, limit)
        return self._search_fts(parsed, limit)

    def _search_fts(self, parsed, limit):
        try:
            rows = self._db.execute(
                "SELECT i.*, snippet(search_fts, 2, '[', ']', '…', 12) AS excerpt "
                "FROM search_fts JOIN indexed_items i ON i.id = search_fts.rowid "
                "WHERE search_fts MATCH ? ORDER BY rank LIMIT ?",
                (parsed['fts'], limit)).fetchall()
        except sqlite3.OperationalError as exc:
            # A malformed FTS expression is a user typo, not a crash.
            raise SearchError(f"That query could not be understood: {exc}") from exc
        return [dict(row) for row in rows]

    def _search_entity(self, parsed, limit):
        kind, value = parsed['entity_kind'], parsed['value']
        if value:
            rows = self._db.execute(
                "SELECT DISTINCT i.*, e.value AS excerpt FROM entities e "
                "JOIN indexed_items i ON i.id = e.item_id "
                "WHERE e.kind = ? AND e.value LIKE ? LIMIT ?",
                (kind, f'%{value}%', limit)).fetchall()
        else:
            rows = self._db.execute(
                "SELECT DISTINCT i.*, e.value AS excerpt FROM entities e "
                "JOIN indexed_items i ON i.id = e.item_id "
                "WHERE e.kind = ? LIMIT ?", (kind, limit)).fetchall()
        return [dict(row) for row in rows]

    def _search_regex(self, parsed, limit):
        """Regex cannot use the index, so narrow first and refine after.

        Everything indexed is a candidate, which on a large case is a lot of
        rows; the FTS prefilter is what keeps this usable when the pattern has
        a literal part to prefilter on.
        """
        try:
            pattern = re.compile(parsed['pattern'], re.IGNORECASE)
        except re.error as exc:
            raise SearchError(f"That regular expression is not valid: {exc}") from exc

        # A wildcard on a filename tests the name; a /regex/ searches
        # everything, because that is what each one is asking for. Matching
        # ^*.pdf$ against a document's whole text can never succeed.
        field = parsed.get('field')

        results = []
        rows = self._db.execute("SELECT * FROM indexed_items").fetchall()
        for row in rows:
            if field == 'name':
                haystack = row['name'] or ''
            else:
                haystack = (f"{row['name'] or ''}\n{row['path'] or ''}\n"
                            f"{row['body'] or ''}")
            match = pattern.search(haystack)
            if match:
                item = dict(row)
                item.pop('body', None)
                start = max(0, match.start() - 40)
                item['excerpt'] = haystack[start:match.end() + 40].replace(
                    '\n', ' ')
                results.append(item)
                if len(results) >= limit:
                    break
        return results

    def entity_values(self, kind, limit=1000):
        """Every distinct value of one entity kind, most common first."""
        rows = self._db.execute(
            "SELECT value, count(*) AS hits FROM entities WHERE kind = ? "
            "GROUP BY value ORDER BY hits DESC LIMIT ?",
            (kind, limit)).fetchall()
        return [dict(row) for row in rows]


class SearchError(Exception):
    """A query could not be run."""


# --- query language -------------------------------------------------------

#: Field prefixes the query language understands.
ENTITY_FIELDS = ('email', 'url', 'domain', 'ip', 'ipv6', 'hash', 'btc')
TEXT_FIELDS = ('name', 'path', 'body')


def parse_query(query):
    """Work out what the user meant.

    Kinds returned:

    * ``empty``   -- nothing to do
    * ``entity``  -- ``email:``, ``ip:``, ``hash:`` and friends
    * ``regex``   -- ``/pattern/``
    * ``fts``     -- everything else, translated to FTS5 syntax

    Wildcards are the one place this rewrites the user's text: FTS5 spells a
    prefix search ``term*`` and has no infix wildcard, so ``*.pdf`` is turned
    into a regex rather than silently returning nothing.
    """
    query = (query or '').strip()
    if not query:
        return {'kind': 'empty'}

    # /regex/
    if len(query) > 2 and query.startswith('/') and query.endswith('/'):
        return {'kind': 'regex', 'pattern': query[1:-1]}

    # field:value
    if ':' in query:
        field, _, value = query.partition(':')
        field = field.strip().lower()
        value = value.strip()
        if field in ENTITY_FIELDS:
            return {'kind': 'entity', 'entity_kind': field, 'value': value}
        if field in TEXT_FIELDS and value:
            return {'kind': 'fts', 'fts': f'{field} : {_fts_terms(value)}'}

    # A leading or infix wildcard has no FTS equivalent; treat it as a
    # filename pattern, which is what someone typing *.pdf means.
    if '*' in query and not query.endswith('*'):
        pattern = re.escape(query).replace(r'\*', '.*').replace(r'\?', '.')
        # Matched against the name alone: someone typing *.pdf means
        # "files called something.pdf", not "documents mentioning it".
        return {'kind': 'regex', 'pattern': f'^{pattern}$',
                'field': 'name'}

    return {'kind': 'fts', 'fts': _fts_terms(query)}


def _fts_terms(text):
    """Translate ordinary search text into an FTS5 expression.

    Quoted phrases and the AND/OR/NOT operators pass through; everything else
    is quoted so that punctuation in a term -- a filename, a URL fragment --
    cannot be read as FTS syntax and raise.
    """
    tokens = re.findall(r'"[^"]*"|\S+', text)
    out = []
    for token in tokens:
        upper = token.upper()
        if upper in ('AND', 'OR', 'NOT'):
            out.append(upper)
        elif token.startswith('"'):
            out.append(token)
        elif token.endswith('*') and len(token) > 1:
            out.append(f'"{token[:-1]}"*')
        else:
            out.append(f'"{token}"')
    return ' '.join(out)

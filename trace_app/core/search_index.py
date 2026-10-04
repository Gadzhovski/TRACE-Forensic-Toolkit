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

Entities -- emails, URLs, domains, IPs, hashes, Bitcoin addresses, phone
numbers, card numbers, IBANs -- are pulled out during extraction and stored
separately, because "show me every email address in this case" is a question
an examiner asks and full-text search answers badly. They are what the
Indicators tab lists. Card numbers and IBANs must pass their own check digits
(Luhn, ISO 7064 mod 97), so a run of digits is not reported as one.

No Qt imports belong here: indexing runs on a worker thread the UI owns, but
the work itself is drivable from a script.
"""

import logging
import os
import re
import sqlite3

logger = logging.getLogger('TRACE.Search')


def use_wal(connection):
    """Put a database in write-ahead-log mode, so reading it never waits
    for a writer.

    Analysis, indexing and carving write while the window reads the same
    files. In SQLite's default mode a writer whose transaction outgrows its
    cache takes an exclusive lock until it commits, and every read the
    window made waited out the 5-second busy timeout and failed: indexing a
    168 MB image froze the window for 15 s at a time. With a WAL, readers
    see the last commit and carry on. The mode is stored in the file, so
    this also converts a case written before. A file system that cannot
    hold a WAL (some network shares) keeps the old mode, and is logged.
    """
    try:
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning("Could not switch to WAL mode: %s", exc)
        return
    if str(mode).lower() != 'wal':
        logger.warning("Database stays in %s mode; reads may wait for "
                       "background jobs", mode)

#: Bumped when the index schema changes. The index is a cache -- it can always
#: be rebuilt from the evidence -- so a version bump discards it rather than
#: migrating.
#: 3: phone, card and IBAN indicators. 4: entities carry their evidence id,
#: so counting indicators per image needs no join to the items (and their
#: text): the Indicators tab's refresh took up to 3 s against a growing index.
INDEX_VERSION = 4

#: Largest amount of text taken from one file. A 20 MB log is worth indexing;
#: taking all of a 2 GB one costs more than it returns.
MAX_TEXT_PER_FILE = 8 * 1024 * 1024

#: Files larger than this are not opened for extraction at all.
MAX_FILE_BYTES = 256 * 1024 * 1024

#: Status values for an evidence item's indexing progress.
INDEX_PENDING = 'pending'
INDEX_RUNNING = 'running'
INDEX_DONE = 'done'

#: The index's file in a case folder.
SEARCH_DB_NAME = 'search.db'
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
    # International form only (a leading +): national formats differ by
    # country and, unanchored, match every other number in a document.
    'phone': re.compile(
        r'(?<![\w+])\+\d{1,3}(?:[ .\-]?\(?\d{1,4}\)?){2,5}(?![\w])'),
    # 13-19 digits, alone or in groups of four; kept only if Luhn-valid and
    # issued under a known scheme's prefix (_valid_card).
    'card': re.compile(
        r'(?<![\d\-])(?:\d{4}[ \-]){3}\d{1,7}(?![\d\-])'
        r'|(?<![\d\-])\d{13,19}(?![\d\-])'),
    # Upper-case country code, two check digits, then the account in groups of
    # four or run together; kept only if its length is right for the country
    # and the mod-97 check holds (_valid_iban).
    'iban': re.compile(
        r'\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b'),
}

#: IBAN length by country (ISO 13616 registry). A code not listed here is not
#: an IBAN country, which rules out most upper-case words followed by digits.
IBAN_LENGTHS = {
    'AD': 24, 'AE': 23, 'AL': 28, 'AT': 20, 'AZ': 28, 'BA': 20, 'BE': 16,
    'BG': 22, 'BH': 22, 'BR': 29, 'CH': 21, 'CR': 22, 'CY': 28, 'CZ': 24,
    'DE': 22, 'DK': 18, 'DO': 28, 'EE': 20, 'EG': 29, 'ES': 24, 'FI': 18,
    'FO': 18, 'FR': 27, 'GB': 22, 'GE': 22, 'GI': 23, 'GL': 18, 'GR': 27,
    'GT': 28, 'HR': 21, 'HU': 28, 'IE': 22, 'IL': 23, 'IQ': 23, 'IS': 26,
    'IT': 27, 'JO': 30, 'KW': 30, 'KZ': 20, 'LB': 28, 'LC': 32, 'LI': 21,
    'LT': 20, 'LU': 20, 'LV': 21, 'MC': 27, 'MD': 24, 'ME': 22, 'MK': 19,
    'MR': 27, 'MT': 31, 'MU': 30, 'NL': 18, 'NO': 15, 'PK': 24, 'PL': 28,
    'PS': 29, 'PT': 25, 'QA': 29, 'RO': 24, 'RS': 22, 'SA': 24, 'SC': 31,
    'SE': 24, 'SI': 19, 'SK': 24, 'SM': 27, 'ST': 25, 'SV': 28, 'TL': 23,
    'TN': 24, 'TR': 26, 'UA': 29, 'VA': 22, 'VG': 24, 'XK': 20,
}

#: Card schemes by number prefix and lengths: Visa, Mastercard (51-55 and
#: 2221-2720), American Express, Discover, JCB, Diners Club, Maestro/UnionPay.
_CARD_SCHEMES = re.compile(
    r'^(?:4\d{12}(?:\d{3}){0,2}'
    r'|(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}'
    r'|3[47]\d{13}'
    r'|6(?:011|5\d{2}|4[4-9]\d)\d{12,15}'
    r'|35(?:2[89]|[3-8]\d)\d{12,15}'
    r'|3(?:0[0-5]|[689]\d)\d{11,16}'
    r'|62\d{14,17})$')


def luhn_valid(digits):
    """Does a string of digits pass the Luhn check every card number does?"""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if position % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _valid_card(text):
    """The card number in `text` (digits only), or None."""
    digits = re.sub(r'[ \-]', '', text)
    # The scheme prefix rules out 0000 0000 0000 0000, which passes Luhn.
    if not 13 <= len(digits) <= 19 or not _CARD_SCHEMES.match(digits)             or not luhn_valid(digits):
        return None
    return digits


def iban_valid(iban):
    """Is `iban` (no spaces) the right length for its country, with check
    digits that hold under ISO 7064 mod 97?"""
    if IBAN_LENGTHS.get(iban[:2]) != len(iban):
        return False
    moved = iban[4:] + iban[:4]
    number = ''.join(str(int(c, 36)) for c in moved)
    return int(number) % 97 == 1


def _valid_iban(text):
    iban = text.replace(' ', '')
    return iban if iban_valid(iban) else None


def _valid_phone(text):
    """The number as +digits, if it has as many as a real one: 8-15
    (E.164 allows at most 15)."""
    digits = re.sub(r'\D', '', text)
    if not 8 <= len(digits) <= 15:
        return None
    return '+' + digits


#: Normalises a match to the value stored, or rejects it (None). Kinds not
#: listed are stored as matched.
_ENTITY_CHECKS = {'card': _valid_card, 'iban': _valid_iban,
                  'phone': _valid_phone}

#: What each indicator kind is called, singular and plural, for the
#: Indicators tab and the Findings tree.
INDICATOR_KINDS = {
    'email': ('Email address', 'Email addresses'),
    'url': ('URL', 'URLs'),
    'domain': ('Domain', 'Domains'),
    'ip': ('IPv4 address', 'IPv4 addresses'),
    'ipv6': ('IPv6 address', 'IPv6 addresses'),
    'phone': ('Phone number', 'Phone numbers'),
    'card': ('Card number', 'Card numbers'),
    'iban': ('IBAN', 'IBANs'),
    'btc': ('Bitcoin address', 'Bitcoin addresses'),
    'hash': ('Hash', 'Hashes'),
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
        self.path = os.path.join(folder, SEARCH_DB_NAME)
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        use_wal(self._db)
        self._create_schema()

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    # --- schema -----------------------------------------------------------

    def _create_schema(self):
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == INDEX_VERSION:
            # Already made. Opening must not write: the window opens the
            # index to read it while a job holds the write lock, and a
            # CREATE ... IF NOT EXISTS here waited out the busy timeout.
            return
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
                evidence_id   INTEGER,
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
            CREATE INDEX IF NOT EXISTS idx_entities_evidence
                ON entities(evidence_id, kind, value);
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
            self._store_entities(item_id, evidence_id, body)
        return item_id

    def _store_entities(self, item_id, evidence_id, text):
        """Pull emails, URLs, IPs and hashes out of the text."""
        found = set()
        for kind, pattern in _ENTITY_PATTERNS.items():
            check = _ENTITY_CHECKS.get(kind)
            for match in pattern.findall(text):
                value = match.strip().rstrip('.,;:)')
                if value and check is not None:
                    value = check(value)
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
                "INSERT INTO entities (item_id, evidence_id, kind, value) "
                "VALUES (?, ?, ?, ?)",
                [(item_id, evidence_id, kind, value)
                 for kind, value in found])

    def commit(self):
        self._db.commit()

    def clear_evidence(self, evidence_id):
        """Drop everything indexed for one piece of evidence, before a re-run."""
        self._clear("evidence_id = ?", (evidence_id,))

    def clear_carved(self, evidence_id):
        """Drop one image's carved files and the members found in them,
        before they are indexed again (a new carve replaces the last)."""
        self._clear("evidence_id = ? AND artifact_ref IN (SELECT artifact_ref "
                    "FROM indexed_items WHERE evidence_id = ? AND kind = "
                    "'carved')", (evidence_id, evidence_id))

    def _clear(self, where, params):
        rows = self._db.execute(
            f"SELECT id FROM indexed_items WHERE {where}", params).fetchall()
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
            self._db.execute("DELETE FROM indexed_items WHERE id = ?",
                             (item_id,))
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

    def statistics(self, evidence_id=None):
        """What the index holds -- the whole case, or one image."""
        where, params = self._evidence_clause(evidence_id, 'evidence_id')
        items = self._db.execute(
            f"SELECT count(*) FROM indexed_items{where}", params).fetchone()[0]
        images = self._db.execute(
            "SELECT count(DISTINCT evidence_id) FROM indexed_items"
            + where, params).fetchone()[0]
        return {
            'items': items,
            'images': images,
            'entities': self.indicator_summary(evidence_id),
        }

    # --- indicators -------------------------------------------------------

    @staticmethod
    def _evidence_clause(evidence_id, column, prefix=' WHERE'):
        if evidence_id is None:
            return '', []
        return f"{prefix} {column} = ?", [evidence_id]

    def indicator_summary(self, evidence_id=None):
        """{kind: distinct values} -- the whole case, or one image."""
        where, params = self._evidence_clause(evidence_id, 'evidence_id')
        rows = self._db.execute(
            "SELECT kind, count(DISTINCT value) FROM entities" + where
            + " GROUP BY kind", params).fetchall()
        return {row[0]: row[1] for row in rows}

    def indicators(self, kind=None, evidence_id=None, contains='',
                   limit=5000):
        """One row per distinct value: kind, value, files (how many items
        hold it) and evidence_ids (which images). Most widespread first."""
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if contains:
            clauses.append("value LIKE ?")
            params.append(f'%{contains}%')
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ''
        rows = self._db.execute(
            "SELECT kind, value, count(DISTINCT item_id) AS files, "
            "group_concat(DISTINCT evidence_id) AS images FROM entities"
            + where + " GROUP BY kind, value "
            "ORDER BY files DESC, kind, value LIMIT ?",
            params + [limit]).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item['evidence_ids'] = sorted(
                int(v) for v in (item.pop('images') or '').split(',') if v)
            out.append(item)
        return out

    #: indexed_items' columns, without the body -- which can be 8 MB a row.
    _ITEM_COLUMNS = ('id, evidence_id, artifact_ref, kind, name, path, size, '
                     'inode, start_offset, created_utc, accessed_utc, '
                     'mtime_utc, changed_utc, is_deleted, mime, indexed_utc')

    def items_with(self, kind, value, evidence_id=None, limit=2000):
        """The indexed items holding one indicator, each with an `excerpt`
        of the text around it. The same shape as a search result.

        The excerpt is cut in SQL, so a value found in a thousand files does
        not read a thousand bodies into memory. Only where the stored value
        is not in the text as written -- a card's digits were spaced, a
        domain was capitalised -- is that one body read and searched.
        """
        columns = ', '.join(f'i.{c.strip()}'
                            for c in self._ITEM_COLUMNS.split(','))
        params = [value, value, value, kind, value]
        query = (f"SELECT DISTINCT {columns}, instr(i.body, ?) AS at_, "
                 f"substr(i.body, max(instr(i.body, ?) - 60, 1), "
                 f"length(?) + 130) AS around_ FROM entities e "
                 f"JOIN indexed_items i ON i.id = e.item_id "
                 f"WHERE e.kind = ? AND e.value = ?")
        if evidence_id is not None:
            query += " AND e.evidence_id = ?"
            params.append(evidence_id)
        query += " ORDER BY i.evidence_id, i.path LIMIT ?"
        params.append(limit)
        # Stored values are normalised (a card's digits, a phone's +digits);
        # in the text they may be spaced or hyphenated.
        loose = re.compile(
            r'[ ().\-]{0,2}'.join(re.escape(c) for c in value.lstrip('+')),
            re.IGNORECASE)
        out = []
        for row in self._db.execute(query, params).fetchall():
            item = dict(row)
            at, around = item.pop('at_'), item.pop('around_') or ''
            if at:
                text, offset = around, min(at - 1, 60)
            else:
                body = self._db.execute(
                    "SELECT body FROM indexed_items WHERE id = ?",
                    (item['id'],)).fetchone()[0] or ''
                match = loose.search(body)
                if match is None:
                    item['excerpt'] = value
                    out.append(item)
                    continue
                start = max(0, match.start() - 60)
                text = body[start:match.end() + 70]
                offset = match.start() - start
            item['excerpt'] = _excerpt(text, offset,
                                       offset + len(value))
            out.append(item)
        return out

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


def _excerpt(text, start, end):
    """`text` around [start, end), cut at word boundaries so the context
    does not open or close on half a word, and on one line."""
    begin = 0
    space = text.find(' ', 0, start)
    if space != -1 and start > 0:
        begin = space + 1
    finish = len(text)
    space = text.rfind(' ', end)
    if space != -1 and space >= end:
        finish = space
    body = ' '.join(text[begin:finish].split())
    return (('… ' if begin else '') + body
            + (' …' if finish < len(text) else ''))


class SearchError(Exception):
    """A query could not be run."""


# --- query language -------------------------------------------------------

#: Field prefixes the query language understands.
ENTITY_FIELDS = tuple(INDICATOR_KINDS)
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

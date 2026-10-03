"""Browser history, downloads and searches from Chromium, Firefox and Safari.

Chrome, Edge, Brave, Opera and Vivaldi share Chromium's History database;
Firefox keeps places.sqlite (and, before version 26, downloads.sqlite);
Safari keeps History.db. A database is recognised by its tables, not its
name, so a History file recovered by the carver is read the same way.

Searches are the terms typed into a search engine: Chromium records them
(keyword_search_terms); for the others they are read from the URLs of
result pages, which carry the query in a known parameter.
"""

import json
import sqlite3
import urllib.parse

from trace_app.core.activity import sqlite_bytes, times

#: Chromium visit transitions (the low byte).
_CHROME_TRANSITIONS = {
    0: 'link', 1: 'typed', 2: 'bookmark', 3: 'subframe', 4: 'subframe',
    5: 'generated', 6: 'start page', 7: 'form', 8: 'reload', 9: 'keyword',
    10: 'keyword',
}
_FIREFOX_VISITS = {
    1: 'link', 2: 'typed', 3: 'bookmark', 4: 'embedded', 5: 'redirect',
    6: 'redirect', 7: 'download', 8: 'framed link', 9: 'reload',
}
_CHROME_STATES = {0: 'in progress', 1: 'complete', 2: 'cancelled',
                  3: 'interrupted', 4: 'interrupted'}

#: Search engines: host fragment -> query parameter.
_ENGINES = (
    ('google.', 'q', 'Google'), ('bing.com', 'q', 'Bing'),
    ('duckduckgo.com', 'q', 'DuckDuckGo'), ('search.yahoo.', 'p', 'Yahoo'),
    ('yandex.', 'text', 'Yandex'), ('baidu.com', 'wd', 'Baidu'),
    ('youtube.com', 'search_query', 'YouTube'), ('ecosia.org', 'q', 'Ecosia'),
    ('startpage.com', 'query', 'Startpage'), ('ask.com', 'q', 'Ask'),
    ('search.brave.com', 'q', 'Brave Search'), ('qwant.com', 'q', 'Qwant'),
    ('amazon.', 'k', 'Amazon'), ('ebay.', '_nkw', 'eBay'),
    ('wikipedia.org', 'search', 'Wikipedia'),
)


def browser_name(path):
    lowered = (path or '').replace('/', '\\').lower()
    for marker, name in (('\\google\\chrome', 'Chrome'),
                         ('\\microsoft\\edge', 'Edge'),
                         ('\\bravesoftware', 'Brave'),
                         ('\\opera software', 'Opera'),
                         ('\\vivaldi', 'Vivaldi'),
                         ('\\chromium', 'Chromium'),
                         ('google-chrome', 'Chrome'),
                         ('\\firefox', 'Firefox'), ('.mozilla', 'Firefox'),
                         ('\\safari', 'Safari')):
        if marker in lowered:
            return name
    return ''


def search_in_url(url):
    """(engine, terms) if `url` is a search results page, else None."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or '').lower()
    for fragment, parameter, engine in _ENGINES:
        if fragment in host:
            query = urllib.parse.parse_qs(parts.query).get(parameter)
            if not query and parts.fragment:
                query = urllib.parse.parse_qs(parts.fragment).get(parameter)
            if query and query[0].strip():
                return engine, query[0].strip()
    return None


def read(database, wal=None, browser=''):
    """{'visits': [...], 'downloads': [...], 'searches': [...],
    'kind': 'chromium' | 'firefox' | 'safari'} from a history database.
    Raises sqlite3.DatabaseError if it is not one."""
    with sqlite_bytes.open_database(database, wal) as connection:
        names = sqlite_bytes.tables(connection)
        if {'urls', 'visits'} <= names:
            out = _chromium(connection, names)
        elif 'moz_places' in names or 'moz_downloads' in names:
            out = _firefox(connection, names)
        elif {'history_items', 'history_visits'} <= names:
            out = _safari(connection)
        else:
            raise sqlite3.DatabaseError("not a browser history database")
    known = {(s['time'], s['terms']) for s in out['searches']}
    for visit in out['visits']:
        found = search_in_url(visit['url'])
        if found and (visit['time'], found[1]) not in known:
            known.add((visit['time'], found[1]))
            out['searches'].append({'time': visit['time'], 'engine': found[0],
                                    'terms': found[1], 'url': visit['url']})
    out['browser'] = browser
    return out


def _chromium(connection, names):
    visits = []
    has_duration = 'visit_duration' in sqlite_bytes.columns(connection,
                                                            'visits')
    for row in connection.execute(
            "SELECT v.visit_time, u.url, u.title, v.transition, "
            + ("v.visit_duration" if has_duration else "0")
            + ", u.visit_count, u.typed_count FROM visits v "
            "JOIN urls u ON u.id = v.url ORDER BY v.visit_time"):
        stamp, url, title, transition, duration, count, typed = row
        core = (transition or 0) & 0xFF
        if core in (3, 4):
            continue                    # a frame inside a page, not a visit
        visits.append({'time': times.webkit(stamp), 'url': url or '',
                       'title': title or '',
                       'how': _CHROME_TRANSITIONS.get(core, str(core)),
                       'duration_s': round((duration or 0) / 1e6, 1),
                       'visit_count': count, 'typed_count': typed})

    downloads = []
    if 'downloads' in names:
        columns = sqlite_bytes.columns(connection, 'downloads')
        if 'target_path' in columns:             # Chrome 26+
            chains = {}
            if 'downloads_url_chains' in names:
                for download_id, url in connection.execute(
                        "SELECT id, url FROM downloads_url_chains "
                        "ORDER BY id, chain_index"):
                    chains.setdefault(download_id, []).append(url)
            extra = [c for c in ('tab_url', 'referrer', 'mime_type',
                                 'opened', 'danger_type') if c in columns]
            for row in connection.execute(
                    "SELECT id, target_path, start_time, end_time, "
                    "received_bytes, total_bytes, state"
                    + ''.join(f', {c}' for c in extra) + " FROM downloads"):
                facts = dict(zip(['id', 'path', 'start', 'end', 'received',
                                  'total', 'state'] + extra, row))
                chain = chains.get(facts['id'], [])
                downloads.append({
                    'time': times.webkit(facts['start']),
                    'finished': times.webkit(facts['end']),
                    'path': facts['path'] or '',
                    'url': chain[-1] if chain else facts.get('tab_url', ''),
                    'referrer': facts.get('referrer') or facts.get('tab_url')
                    or '',
                    'size': facts['total'] or facts['received'],
                    'state': _CHROME_STATES.get(facts['state'],
                                                str(facts['state'])),
                    'opened': bool(facts.get('opened')),
                    'mime': facts.get('mime_type') or ''})
        elif 'full_path' in columns:             # before Chrome 26
            for path, url, start, received, total, state in connection.execute(
                    "SELECT full_path, url, start_time, received_bytes, "
                    "total_bytes, state FROM downloads"):
                downloads.append({'time': times.unix(start), 'finished': None,
                                  'path': path or '', 'url': url or '',
                                  'referrer': '', 'size': total or received,
                                  'state': _CHROME_STATES.get(state, str(state)),
                                  'opened': False, 'mime': ''})

    searches = []
    if 'keyword_search_terms' in names:
        for term, url, stamp in connection.execute(
                "SELECT k.term, u.url, u.last_visit_time FROM "
                "keyword_search_terms k JOIN urls u ON u.id = k.url_id"):
            found = search_in_url(url or '')
            searches.append({'time': times.webkit(stamp),
                             'engine': found[0] if found else '',
                             'terms': term or '', 'url': url or ''})
    return {'kind': 'chromium', 'visits': visits, 'downloads': downloads,
            'searches': searches}


def _firefox(connection, names):
    visits = []
    if {'moz_historyvisits', 'moz_places'} <= names:
        for stamp, url, title, kind, count in connection.execute(
                "SELECT v.visit_date, p.url, p.title, v.visit_type, "
                "p.visit_count FROM moz_historyvisits v "
                "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"):
            if kind == 4:
                continue                # embedded resource, not a visit
            visits.append({'time': times.unix_micro(stamp), 'url': url or '',
                           'title': title or '',
                           'how': _FIREFOX_VISITS.get(kind, str(kind)),
                           'duration_s': None, 'visit_count': count,
                           'typed_count': None})

    downloads = []
    if {'moz_annos', 'moz_anno_attributes'} <= names:       # Firefox 26+
        rows = connection.execute(
            "SELECT a.place_id, n.name, a.content, a.dateAdded, p.url "
            "FROM moz_annos a JOIN moz_anno_attributes n "
            "ON n.id = a.anno_attribute_id JOIN moz_places p "
            "ON p.id = a.place_id WHERE n.name LIKE 'downloads/%'")
        by_place = {}
        for place, name, content, added, url in rows:
            entry = by_place.setdefault(place, {'url': url, 'added': added})
            if name == 'downloads/destinationFileURI':
                entry['path'] = urllib.parse.unquote(
                    (content or '').replace('file:///', '').replace('/', '\\'))
            elif name == 'downloads/metaData':
                try:
                    entry['meta'] = json.loads(content or '{}')
                except ValueError:
                    entry['meta'] = {}
        for entry in by_place.values():
            if 'path' not in entry:
                continue
            meta = entry.get('meta', {})
            downloads.append({
                'time': times.unix_micro(entry['added']),
                'finished': times.unix_micro((meta.get('endTime') or 0) * 1000),
                'path': entry['path'], 'url': entry['url'] or '',
                'referrer': '', 'size': meta.get('fileSize'),
                'state': {0: 'in progress', 1: 'complete', 2: 'failed',
                          3: 'cancelled'}.get(meta.get('state'), ''),
                'opened': False, 'mime': ''})
    if 'moz_downloads' in names:                             # before 26
        for name, source, target, start, end, state, referrer, size, mime in \
                connection.execute(
                    "SELECT name, source, target, startTime, endTime, state, "
                    "referrer, maxBytes, mimeType FROM moz_downloads"):
            downloads.append({
                'time': times.unix_micro(start),
                'finished': times.unix_micro(end),
                'path': urllib.parse.unquote(
                    (target or '').replace('file:///', '')).replace('/', '\\')
                or name or '',
                'url': source or '', 'referrer': referrer or '',
                'size': size, 'state': {1: 'complete', 2: 'failed',
                                        3: 'cancelled'}.get(state, str(state)),
                'opened': False, 'mime': mime or ''})
    return {'kind': 'firefox', 'visits': visits, 'downloads': downloads,
            'searches': []}


def _safari(connection):
    visits = []
    for stamp, url, title, count in connection.execute(
            "SELECT v.visit_time, i.url, v.title, i.visit_count "
            "FROM history_visits v JOIN history_items i "
            "ON i.id = v.history_item ORDER BY v.visit_time"):
        visits.append({'time': times.mac_absolute(stamp), 'url': url or '',
                       'title': title or '', 'how': '', 'duration_s': None,
                       'visit_count': count, 'typed_count': None})
    return {'kind': 'safari', 'visits': visits, 'downloads': [],
            'searches': []}

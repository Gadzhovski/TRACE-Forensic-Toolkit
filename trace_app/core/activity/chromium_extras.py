"""The rest of a Chromium profile: cookies, form entries, saved logins, top
sites and favicons (Chrome, Edge, Brave, Opera, Vivaldi, Chromium).

Each is a SQLite database of its own beside History, recognised by its
tables rather than its name (a carved one reads the same way):

* Cookies (Network/Cookies from Chrome 96, Cookies before): `cookies` --
  host, name, path, created / last accessed / expires (WebKit
  microseconds), secure, HTTP-only. **Values are never copied**: from
  Chrome 80 they are encrypted, and before that they are live session
  tokens; whether one is stored in clear is said, not shown;
* Web Data: `autofill` -- what was typed into a form field, by the field's
  name, with how often and when first and last (Unix seconds);
* Login Data (and Login Data For Account): `logins` -- the site, the form
  it posted to, the user name, created / last used (WebKit), times used,
  and the sites the user said never to save. **`password_value` is never
  read**;
* Top Sites: `top_sites` -- the new tab page's most visited sites, by rank
  (no time);
* Favicons: `icon_mapping` page URL -> `favicons` icon -> `favicon_bitmaps`
  last_updated (WebKit) -- pages whose icon was fetched, which outlives a
  cleared history.
"""

import sqlite3

from trace_app.core.activity import record, sqlite_bytes, times

#: The profile's files, and where (Cookies moved into Network/ in Chrome 96).
FILES = (('Network', 'Cookies'), ('Cookies',), ('Web Data',),
         ('Login Data',), ('Login Data For Account',), ('Top Sites',),
         ('Favicons',))
#: Cookies kept per database (a busy profile holds tens of thousands).
MAX_COOKIES = 20000


def kind_of(names):
    """Which of these databases a table list is, or None."""
    if 'cookies' in names:
        return 'cookies'
    if 'autofill' in names:
        return 'autofill'
    if 'logins' in names:
        return 'logins'
    if 'top_sites' in names:
        return 'top_sites'
    if {'icon_mapping', 'favicons'} <= names:
        return 'favicons'
    return None


def read(database, wal=None):
    """(kind, [row dicts]) of one of these databases. Raises
    sqlite3.DatabaseError if it is none of them."""
    with sqlite_bytes.open_database(database, wal) as connection:
        names = sqlite_bytes.tables(connection)
        kind = kind_of(names)
        if kind is None:
            raise sqlite3.DatabaseError("not a Chromium profile database")
        return kind, globals()['_' + kind](connection)


def _chrome_time(value):
    """Login Data's times: Unix seconds in the oldest databases (Chrome
    migrated them to WebKit microseconds), WebKit microseconds since."""
    if value and 0 < value < 10 ** 11:
        return times.unix(value)
    return times.webkit(value)


def _pick(columns, *names):
    return next((name for name in names if name in columns), None)


def _cookies(connection):
    columns = sqlite_bytes.columns(connection, 'cookies')
    secure = _pick(columns, 'is_secure', 'secure')
    httponly = _pick(columns, 'is_httponly', 'httponly')
    encrypted = 'encrypted_value' in columns
    access = _pick(columns, 'last_access_utc')
    update = _pick(columns, 'last_update_utc')
    query = ("SELECT host_key, name, path, creation_utc, expires_utc, "
             f"{access or 0}, {update or 0}, {secure or 0}, {httponly or 0}, "
             # length(), never the value itself.
             "length(value)" + (", length(encrypted_value)" if encrypted
                                else ", 0") +
             f" FROM cookies ORDER BY creation_utc LIMIT {MAX_COOKIES}")
    out = []
    for (host, name, path, created, expires, accessed, updated, is_secure,
         is_httponly, clear, sealed) in connection.execute(query):
        out.append({'host': host or '', 'name': name or '',
                    'path': path or '', 'created': times.webkit(created),
                    'expires': times.webkit(expires),
                    'accessed': times.webkit(accessed),
                    'updated': times.webkit(updated),
                    'secure': bool(is_secure), 'httponly': bool(is_httponly),
                    'value': 'encrypted' if sealed else
                    'stored in clear (not copied)' if clear else 'empty'})
    return out


def _autofill(connection):
    columns = sqlite_bytes.columns(connection, 'autofill')
    if 'date_created' in columns:
        query = ("SELECT name, value, date_created, date_last_used, count "
                 "FROM autofill ORDER BY date_created")
    else:                                    # before Chrome 31: no dates
        query = "SELECT name, value, 0, 0, count FROM autofill"
    return [{'field': name or '', 'value': value or '',
             'created': times.unix(created), 'last_used': times.unix(used),
             'count': count}
            for name, value, created, used, count in connection.execute(
                query)]


def _logins(connection):
    columns = sqlite_bytes.columns(connection, 'logins')
    wanted = ['origin_url', 'action_url', 'username_element',
              'username_value', 'signon_realm', 'date_created',
              'blacklisted_by_user', 'times_used', 'date_last_used',
              'date_password_modified', 'date_last_filled']
    present = [c for c in wanted if c in columns]
    # password_value is never selected.
    out = []
    for row in connection.execute(
            f"SELECT {', '.join(present)} FROM logins ORDER BY date_created"):
        facts = dict(zip(present, row))
        out.append({
            'site': facts.get('origin_url') or '',
            'posts_to': facts.get('action_url') or '',
            'realm': facts.get('signon_realm') or '',
            'user_field': facts.get('username_element') or '',
            'user': facts.get('username_value') or '',
            'never_save': bool(facts.get('blacklisted_by_user')),
            'created': _chrome_time(facts.get('date_created')),
            'last_used': _chrome_time(facts.get('date_last_used')),
            'password_changed': _chrome_time(
                facts.get('date_password_modified')),
            'last_filled': _chrome_time(facts.get('date_last_filled')),
            'times_used': facts.get('times_used')})
    return out


def _top_sites(connection):
    return [{'url': url or '', 'rank': rank, 'title': title or ''}
            for url, rank, title in connection.execute(
                "SELECT url, url_rank, title FROM top_sites ORDER BY "
                "url_rank")]


def _favicons(connection):
    names = sqlite_bytes.tables(connection)
    updated = {}
    if 'favicon_bitmaps' in names:
        for icon, stamp in connection.execute(
                "SELECT icon_id, max(last_updated) FROM favicon_bitmaps "
                "GROUP BY icon_id"):
            updated[icon] = stamp
    icons = dict(connection.execute("SELECT id, url FROM favicons"))
    return [{'page': page or '', 'icon': icons.get(icon, ''),
             'updated': times.webkit(updated.get(icon))}
            for page, icon in connection.execute(
                "SELECT page_url, icon_id FROM icon_mapping ORDER BY id")]


# --- records ------------------------------------------------------------------

def records(kind, rows, user, path, ref, browser, profile=''):
    common = dict(user=user, path=path, ref=ref)
    extra = {'browser': browser, 'profile': profile or None}
    out = []
    for row in rows:
        if kind == 'cookies':
            out.append(record(
                'browser', f'{browser} cookies', row['created'],
                'Cookie set', f"{row['host']}{row['path']} {row['name']}",
                dict(extra, **{'site': row['host'], 'cookie': row['name'],
                               'last accessed': row['accessed'],
                               'expires': row['expires'],
                               'secure': 'yes' if row['secure'] else None,
                               'HTTP only': 'yes' if row['httponly']
                               else None,
                               'value': row['value']}), **common))
        elif kind == 'autofill':
            out.append(record(
                'searches', f'{browser} form entries', row['created'],
                'Typed into a form', row['value'],
                dict(extra, **{'field': row['field'],
                               'times used': row['count'],
                               'last used': row['last_used']}), **common))
        elif kind == 'logins':
            what = ("Told never to save a password" if row['never_save']
                    else "Login saved")
            out.append(record(
                'logons', f'{browser} saved logins', row['created'], what,
                f"{row['user']} @ {row['site']}" if row['user']
                else row['site'],
                dict(extra, **{'user name': row['user'],
                               'site': row['site'],
                               'form posts to': row['posts_to'],
                               'times used': row['times_used'] or None,
                               'last used': row['last_used'],
                               'password changed': row['password_changed'],
                               'last filled': row['last_filled'],
                               'password': 'not read'}), **common))
        elif kind == 'top_sites':
            out.append(record(
                'browser', f'{browser} top sites', None,
                'Most visited (new tab page)', row['url'],
                dict(extra, title=row['title'], rank=row['rank'],
                     basis='Top Sites records no time'), **common))
        elif kind == 'favicons':
            out.append(record(
                'browser', f'{browser} favicons', row['updated'],
                'Site icon fetched', row['page'],
                dict(extra, icon=row['icon'],
                     basis="when the icon was last fetched for the page "
                           "-- kept after history is cleared"), **common))
    return out


def profile_records(volume, profile_parts, browser, user, step, profile=''):
    """Every one of these databases in a Chromium profile folder."""
    out = []
    seen = set()
    for parts in FILES:
        entry = volume.find(*profile_parts, *parts)
        if entry is None or entry.is_dir or entry.path in seen:
            continue
        seen.add(entry.path)
        step(entry.path)
        wal = volume.find(*profile_parts, *parts[:-1], parts[-1] + '-wal')
        try:
            kind, rows = read(volume.read(entry),
                              volume.read(wal) if wal else None)
        except (sqlite3.DatabaseError, ValueError):
            continue
        out += records(kind, rows, user, entry.path, volume.ref(entry),
                       browser, profile)
    return out

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
  cleared history;
* Shortcuts: `omni_box_shortcuts` -- what was typed into the address bar
  and the suggestion it was turned into, hits and last use (WebKit);
* Network Action Predictor: `network_action_predictor` -- typed text ->
  the URL then opened, hits and misses (no time);
* Media History (Chrome 86-114): `playback` / `playbackSession` -- what was
  played, for how long, where it stopped; `last_updated_time_s` is seconds
  since 1601 (Chromium's `ToDeltaSinceWindowsEpoch`);
* Offline Pages (Android, ChromeOS): `offlinepages_v1` -- pages saved for
  reading offline, their file and title (WebKit times).

Firefox's own two, beside places.sqlite (`firefox_records`):

* cookies.sqlite: `moz_cookies` -- created / last accessed in Unix
  microseconds, expiry in Unix seconds; **values never copied**, as above;
* formhistory.sqlite: `moz_formhistory` -- field name, what was typed,
  times used, first and last use (Unix microseconds).

And the profile's own JSON (`preferences`), Preferences and Secure
Preferences (where Chrome moved extension settings to): extensions with
their install time (WebKit microseconds, as a string), where they came
from (`location`: the Web Store, built in, unpacked by a developer --
`SIDELOADED` are graded notable), whether enabled; site permissions with
when last used (Unix seconds, a float); when browsing data was last
cleared; the signed-in Google account(s) and the download folder.
Expected values in the tests are plaso's for its Preferences file.
"""

import json
import sqlite3

from trace_app.core.activity import record, sqlite_bytes, times

#: The profile's files, and where (Cookies moved into Network/ in Chrome 96).
FILES = (('Network', 'Cookies'), ('Cookies',), ('Web Data',),
         ('Login Data',), ('Login Data For Account',), ('Top Sites',),
         ('Favicons',), ('Shortcuts',), ('Network Action Predictor',),
         ('Media History',), ('Offline Pages', 'metadata', 'OfflinePages.db'))
#: Firefox's, in a profile folder (places.sqlite is read as history).
FIREFOX_FILES = ('cookies.sqlite', 'formhistory.sqlite')
#: The profile's JSON files.
PREFERENCES = ('Preferences', 'Secure Preferences')
#: Chromium's Manifest::Location values.
LOCATIONS = {1: 'Web Store', 2: 'external (preferences file)',
             3: 'external (Windows registry)', 4: 'unpacked (developer mode)',
             5: 'built in', 6: 'external (preferences, downloaded)',
             7: 'external policy (downloaded)', 8: 'command line',
             9: 'external policy', 10: 'built in (external component)'}
#: Ways in that bypass the Web Store: how malicious extensions arrive.
SIDELOADED = (2, 3, 4, 6, 8)
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
    if 'omni_box_shortcuts' in names:
        return 'shortcuts'
    if 'network_action_predictor' in names:
        return 'predictor'
    if 'playback' in names and 'origin' in names:
        return 'media'
    if 'offlinepages_v1' in names:
        return 'offline_pages'
    if 'moz_cookies' in names:
        return 'firefox_cookies'
    if 'moz_formhistory' in names:
        return 'firefox_forms'
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


def _shortcuts(connection):
    columns = sqlite_bytes.columns(connection, 'omni_box_shortcuts')
    hits = 'number_of_hits' if 'number_of_hits' in columns else '0'
    return [{'typed': text or '', 'url': url or '',
             'shown': contents or '', 'title': description or '',
             'last_used': times.webkit(used), 'hits': count}
            for text, url, contents, description, used, count in
            connection.execute(
                "SELECT text, url, contents, description, last_access_time, "
                f"{hits} FROM omni_box_shortcuts ORDER BY last_access_time")]


def _predictor(connection):
    return [{'typed': text or '', 'url': url or '', 'hits': hits,
             'misses': misses}
            for text, url, hits, misses in connection.execute(
                "SELECT user_text, url, number_of_hits, number_of_misses "
                "FROM network_action_predictor ORDER BY rowid")]


def _windows_seconds(value):
    """Media History's seconds: since 1601 (13e9 in 2020); a Unix value
    (1.6e9) is taken as Unix rather than read as the 17th century."""
    if not value:
        return None
    if value > 10 ** 10:
        return times.webkit(value * 1_000_000)
    return times.unix(value)


def _media(connection):
    names = sqlite_bytes.tables(connection)
    origins = dict(connection.execute("SELECT id, origin FROM origin"))
    out = []
    for url, watched, video, audio, updated, origin in connection.execute(
            "SELECT url, watch_time_s, has_video, has_audio, "
            "last_updated_time_s, origin_id FROM playback ORDER BY "
            "last_updated_time_s"):
        out.append({'kind': 'playback', 'url': url or '',
                    'origin': origins.get(origin, ''),
                    'watched': watched, 'video': bool(video),
                    'audio': bool(audio),
                    'updated': _windows_seconds(updated)})
    if 'playbackSession' in names:
        columns = sqlite_bytes.columns(connection, 'playbackSession')
        wanted = [c for c in ('title', 'artist', 'album', 'source_title')
                  if c in columns]
        for row in connection.execute(
                "SELECT url, duration_ms, position_ms, last_updated_time_s, "
                f"origin_id{''.join(', ' + c for c in wanted)} FROM "
                "playbackSession ORDER BY last_updated_time_s"):
            url, duration, position, updated, origin = row[:5]
            facts = dict(zip(wanted, row[5:]))
            out.append({'kind': 'session', 'url': url or '',
                        'origin': origins.get(origin, ''),
                        'duration_ms': duration, 'position_ms': position,
                        'updated': _windows_seconds(updated),
                        **{k: v or '' for k, v in facts.items()}})
    return out


def _offline_pages(connection):
    columns = sqlite_bytes.columns(connection, 'offlinepages_v1')
    wanted = [c for c in ('creation_time', 'last_access_time',
                          'access_count', 'online_url', 'original_url',
                          'title', 'file_path', 'file_size',
                          'client_namespace', 'request_origin')
              if c in columns]
    out = []
    for row in connection.execute(
            f"SELECT {', '.join(wanted)} FROM offlinepages_v1"):
        facts = dict(zip(wanted, row))
        out.append({'url': facts.get('online_url') or '',
                    'original': facts.get('original_url') or '',
                    'title': facts.get('title') or '',
                    'file': facts.get('file_path') or '',
                    'size': facts.get('file_size'),
                    'saved_by': facts.get('client_namespace') or '',
                    'created': times.webkit(facts.get('creation_time')),
                    'accessed': times.webkit(facts.get('last_access_time')),
                    'times_opened': facts.get('access_count')})
    out.sort(key=lambda row: row['created'] or '')
    return out


def _firefox_cookies(connection):
    columns = sqlite_bytes.columns(connection, 'moz_cookies')
    httponly = 'isHttpOnly' if 'isHttpOnly' in columns else '0'
    out = []
    # length(value), never the value.
    for (host, name, path, expiry, accessed, created, secure, is_httponly,
         size) in connection.execute(
            "SELECT host, name, path, expiry, lastAccessed, creationTime, "
            f"isSecure, {httponly}, length(value) FROM moz_cookies "
            f"ORDER BY creationTime LIMIT {MAX_COOKIES}"):
        out.append({'host': host or '', 'name': name or '',
                    'path': path or '', 'created': times.unix_micro(created),
                    'expires': times.unix(expiry),
                    'accessed': times.unix_micro(accessed), 'updated': None,
                    'secure': bool(secure), 'httponly': bool(is_httponly),
                    'value': 'stored in clear (not copied)' if size
                    else 'empty'})
    return out


def _firefox_forms(connection):
    return [{'field': name or '', 'value': value or '',
             'created': times.unix_micro(first),
             'last_used': times.unix_micro(last), 'count': count}
            for name, value, count, first, last in connection.execute(
                "SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
                "FROM moz_formhistory ORDER BY firstUsed")]


# --- records ------------------------------------------------------------------

def records(kind, rows, user, path, ref, browser, profile=''):
    common = dict(user=user, path=path, ref=ref)
    extra = {'browser': browser, 'profile': profile or None}
    out = []
    for row in rows:
        if kind in ('cookies', 'firefox_cookies'):
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
        elif kind in ('autofill', 'firefox_forms'):
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
        elif kind == 'shortcuts':
            out.append(record(
                'searches', f'{browser} address bar shortcuts',
                row['last_used'], 'Typed into the address bar',
                row['typed'],
                dict(extra, **{'opened': row['url'], 'title': row['title'],
                               'times used': row['hits'],
                               'basis': 'when the shortcut was last used'}),
                **common))
        elif kind == 'predictor':
            out.append(record(
                'searches', f'{browser} network action predictor', None,
                'Typed into the address bar', row['typed'],
                dict(extra, **{'opened': row['url'], 'hits': row['hits'],
                               'misses': row['misses'],
                               'basis': 'the predictor records no time'}),
                **common))
        elif kind == 'media':
            session = row['kind'] == 'session'
            detail = dict(extra, **{'site': row['origin'],
                                    'basis': 'when the entry was last '
                                             'updated'})
            if session:
                detail.update({
                    'title': row.get('title') or None,
                    'artist': row.get('artist') or None,
                    'album': row.get('album') or None,
                    'source': row.get('source_title') or None,
                    'length (s)': _seconds(row['duration_ms']),
                    'stopped at (s)': _seconds(row['position_ms'])})
            else:
                detail.update({
                    'watched (s)': row['watched'],
                    'video': 'yes' if row['video'] else None,
                    'audio': 'yes' if row['audio'] else None})
            out.append(record(
                'browser', f'{browser} media history', row['updated'],
                'Media played' if session else 'Media watched', row['url'],
                detail, **common))
        elif kind == 'offline_pages':
            out.append(record(
                'browser', f'{browser} offline pages', row['created'],
                'Page saved for offline reading', row['url'],
                dict(extra, **{'title': row['title'],
                               'original URL': row['original']
                               if row['original'] != row['url'] else None,
                               'saved file': row['file'],
                               'size': row['size'],
                               'saved by': row['saved_by'] or None,
                               'last opened': row['accessed'],
                               'times opened': row['times_opened']}),
                **common))
    return out


def preferences(data):
    """{'extensions', 'permissions', 'cleared', 'accounts', 'downloads'}
    of a Preferences / Secure Preferences file, or None."""
    try:
        prefs = json.loads(data.decode('utf-8', 'replace')
                           if isinstance(data, bytes) else data)
    except ValueError:
        return None
    if not isinstance(prefs, dict):
        return None
    out = {'extensions': [], 'permissions': [], 'cleared': None,
           'accounts': [], 'downloads': None}
    settings = (prefs.get('extensions') or {}).get('settings') or {}
    for key, item in settings.items():
        if not isinstance(item, dict):
            continue
        manifest = item.get('manifest') or {}
        location = item.get('location')
        state = item.get('state')
        disabled = item.get('disable_reasons')
        out['extensions'].append({
            'id': key, 'name': manifest.get('name') or '',
            'version': manifest.get('version'),
            'installed': times.webkit(_int(item.get('install_time'))),
            'location': location, 'path': item.get('path') or '',
            'enabled': None if state is None and disabled is None else
            bool(state == 1 or (state is None and not disabled)),
            'from_webstore': item.get('from_webstore'),
            'by_default': item.get('was_installed_by_default'),
            'permissions': ', '.join(str(p) for p in (
                (item.get('active_permissions') or {}).get('api') or [])
                if isinstance(p, str))})
    exceptions = ((prefs.get('profile') or {}).get('content_settings')
                  or {}).get('exceptions') or {}
    for permission, sites in exceptions.items():
        if not isinstance(sites, dict):
            continue
        for site, value in sites.items():
            if not isinstance(value, dict) or 'last_used' not in value:
                continue
            used = value.get('last_used')
            out['permissions'].append({
                'permission': permission, 'site': site.split(',')[0],
                'embedded in': site.split(',')[1] if ',' in site else None,
                'setting': value.get('setting'),
                'last_used': times.unix(used) if isinstance(
                    used, (int, float)) else None})
    out['permissions'].sort(key=lambda p: (p['last_used'] is None,
                                           p['last_used'] or 0))
    out['cleared'] = times.webkit(_int(
        (prefs.get('browser') or {}).get('last_clear_browsing_data_time')))
    for account in prefs.get('account_info') or []:
        if isinstance(account, dict) and account.get('email'):
            out['accounts'].append({
                'email': account['email'],
                'name': account.get('full_name'),
                'gaia': account.get('gaia'),
                'domain': account.get('hosted_domain')
                if account.get('hosted_domain') not in (None, 'NO_HOSTED_DOMAIN')
                else None})
    out['downloads'] = ((prefs.get('download') or {}).get(
        'default_directory') or (prefs.get('savefile') or {}).get(
        'default_directory'))
    return out


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_PERMISSION_SETTINGS = {1: 'allowed', 2: 'blocked', 3: 'ask'}


def preferences_records(found, user, path, ref, browser, profile=''):
    common = dict(user=user, path=path, ref=ref)
    extra = {'browser': browser, 'profile': profile or None}
    out = []
    for item in found['extensions']:
        location = item['location']
        sideloaded = location in SIDELOADED
        out.append(record(
            'programs', f'{browser} extensions', item['installed'],
            'Browser extension installed', item['name'] or item['id'],
            dict(extra, **{'extension ID': item['id'],
                           'version': item['version'],
                           'came from': LOCATIONS.get(location, location),
                           'enabled': None if item['enabled'] is None else
                           ('yes' if item['enabled'] else 'no'),
                           'folder': item['path'],
                           'permissions': item['permissions'],
                           'grade': 'notable' if sideloaded else None}),
            **common))
    for item in found['permissions']:
        out.append(record(
            'browser', f'{browser} site permissions', item['last_used'],
            'Site permission used', item['site'],
            dict(extra, **{'permission': item['permission'],
                           'setting': _PERMISSION_SETTINGS.get(
                               item['setting'], item['setting']),
                           'embedded in': item['embedded in']
                           if item['embedded in'] not in ('*', '') else None,
                           'basis': 'when the site last used it'}),
            **common))
    if found['cleared']:
        out.append(record(
            'browser', f'{browser} preferences', found['cleared'],
            'Browsing data cleared', profile or browser, dict(extra),
            **common))
    for account in found['accounts']:
        out.append(record(
            'accounts', f'{browser} preferences', None,
            'Signed in to the browser', account['email'],
            dict(extra, **{'name': account['name'],
                           'Google ID': account['gaia'],
                           'domain': account['domain'],
                           'basis': 'Preferences records no sign-in time'}),
            **common))
    if found['downloads']:
        out.append(record(
            'downloads', f'{browser} preferences', None,
            'Download folder set', found['downloads'],
            dict(extra, basis='Preferences records no time for it'),
            **common))
    return out


def _seconds(milliseconds):
    return None if milliseconds is None else round(milliseconds / 1000, 1)


def firefox_records(volume, profile_parts, user, step, profile=''):
    """cookies.sqlite and formhistory.sqlite of a Firefox profile."""
    out = []
    for name in FIREFOX_FILES:
        entry = volume.find(*profile_parts, name)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        wal = volume.find(*profile_parts, name + '-wal')
        try:
            kind, rows = read(volume.read(entry),
                              volume.read(wal) if wal else None)
        except (sqlite3.DatabaseError, ValueError):
            continue
        out += records(kind, rows, user, entry.path, volume.ref(entry),
                       'Firefox', profile)
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
    seen_extensions = set()
    for name in PREFERENCES:
        entry = volume.find(*profile_parts, name)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        found = preferences(volume.read(entry))
        if found is None:
            continue
        # Secure Preferences repeats some extensions Preferences lists.
        found['extensions'] = [item for item in found['extensions']
                               if item['id'] not in seen_extensions]
        seen_extensions.update(item['id'] for item in found['extensions'])
        out += preferences_records(found, user, entry.path,
                                   volume.ref(entry), browser, profile)
    return out

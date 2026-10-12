"""Chromium's other profile databases (core/activity/chromium_extras.py).

Expected values come from outside TRACE: plaso's tests on the Cookies and
Web Data files Chrome wrote (tests/parsers/sqlite_plugins/chrome_cookies.py
and chrome_autofill.py at the plaso commit samples.py pins), and the SQL
fixtures Chromium's own migration tests load (components/test/data), whose
rows are the expected values.
"""

import datetime
import os
import sqlite3

import pytest

from tests.conftest import data_path
from trace_app.core.activity import chromium_extras

UTC = datetime.timezone.utc
WEBKIT = datetime.datetime(1601, 1, 1, tzinfo=UTC)


def _read(name):
    with open(data_path('samples', name), 'rb') as handle:
        return chromium_extras.read(handle.read())


def _from_sql(name, tmp_path, extra=''):
    """A real SQLite database built from Chromium's fixture."""
    path = str(tmp_path / (name + '.db'))
    connection = sqlite3.connect(path)
    with open(data_path('samples', name), encoding='utf-8') as handle:
        connection.executescript(handle.read() + extra)
    connection.commit()
    connection.close()
    with open(path, 'rb') as handle:
        return handle.read()


def _webkit(microseconds):
    return WEBKIT + datetime.timedelta(microseconds=microseconds)


def test_cookies_as_plaso_reads_them():
    kind, rows = _read('chrome-cookies.db')
    assert kind == 'cookies'
    found = {(r['host'].lstrip('.'), r['name']): r for r in rows}
    # plaso: www.linkedin.com leo_auth_token, created
    # 2011-08-25T21:48:20.792703, accessed 21:50:27.292367, expires
    # 2011-11-23T21:48:19.792703, not HTTP only.
    cookie = found[('www.linkedin.com', 'leo_auth_token')]
    assert cookie['created'] == datetime.datetime(
        2011, 8, 25, 21, 48, 20, 792703, tzinfo=UTC)
    assert cookie['accessed'] == datetime.datetime(
        2011, 8, 25, 21, 50, 27, 292367, tzinfo=UTC)
    assert cookie['expires'] == datetime.datetime(
        2011, 11, 23, 21, 48, 19, 792703, tzinfo=UTC)
    assert not cookie['httponly']
    # Its value is a session token: kept out of the record.
    assert cookie['value'] == 'stored in clear (not copied)'

    kind, rows = _read('chrome-Cookies-68.0.3440.106')
    utma = next(r for r in rows if r['name'] == '__utma')
    # plaso: google.com __utma, created 2018-08-14T15:03:43.650324,
    # accessed 15:03:45.489599, expires 2020-08-13T15:03:45.
    assert utma['host'].lstrip('.') == 'google.com'
    assert utma['path'] == '/gmail/about/'
    assert utma['created'] == datetime.datetime(
        2018, 8, 14, 15, 3, 43, 650324, tzinfo=UTC)
    assert utma['accessed'] == datetime.datetime(
        2018, 8, 14, 15, 3, 45, 489599, tzinfo=UTC)
    assert utma['expires'] == datetime.datetime(2020, 8, 13, 15, 3, 45,
                                                tzinfo=UTC)
    assert all(r['value'] in ('encrypted', 'empty') for r in rows)


def test_autofill_as_plaso_reads_it():
    kind, rows = _read('chrome-Web-Data')
    assert kind == 'autofill' and len(rows) == 3        # plaso: 3
    repo = next(r for r in rows if r['field'] == 'repo')
    assert repo['value'] == 'log2timeline/plaso'
    assert repo['created'] == repo['last_used'] == datetime.datetime(
        2018, 8, 17, 19, 35, 51, tzinfo=UTC)
    assert repo['count'] == 1


@pytest.mark.parametrize('fixture, created', [
    ('chromium-login_db_v43.sql', _webkit(13047429345000000)),
    # The oldest schema keeps Unix seconds.
    ('chromium-login_db_v4.sql',
     datetime.datetime.fromtimestamp(1402955745, UTC))])
def test_saved_logins_never_read_a_password(tmp_path, fixture, created):
    planted = ("UPDATE logins SET password_value = "
               "CAST('PLANTED-SECRET' AS BLOB);")
    kind, rows = chromium_extras.read(_from_sql(fixture, tmp_path, planted))
    assert kind == 'logins'
    google = next(r for r in rows if r['user'] == 'theerikchen')
    assert google['site'] == 'https://accounts.google.com/ServiceLogin'
    assert google['posts_to'] == 'https://accounts.google.com/ServiceLoginAuth'
    assert google['created'] == created
    assert google['times_used'] == 1
    records = chromium_extras.records(kind, rows, 'u', 'Login Data', '',
                                      'Chrome')
    assert 'PLANTED-SECRET' not in repr(rows) + repr(records)
    assert all(r['detail']['password'] == 'not read' for r in records)


def test_top_sites_and_favicons(tmp_path):
    kind, rows = chromium_extras.read(
        _from_sql('chromium-TopSites.v5.sql', tmp_path))
    assert kind == 'top_sites'
    assert [(r['rank'], r['url'], r['title']) for r in rows] == [
        (0, 'http://www.google.com/', 'Google'),
        (1, 'http://www.google.com/chrome/intl/en/welcome.html',
         'Welcome to Chromium'),
        (2, 'https://chrome.google.com/webstore?hl=en', 'Chrome Web Store')]
    kind, rows = chromium_extras.read(
        _from_sql('chromium-Favicons.v9.sql', tmp_path))
    assert kind == 'favicons'
    assert {(r['page'], r['icon']) for r in rows} == {
        ('http://google.com/', 'http://www.google.com/favicon.ico'),
        ('http://www.google.com/', 'http://www.google.com/favicon.ico'),
        ('http://www.google.com/', 'http://www.google.com/touch.ico'),
        ('http://yahoo.com/', 'http://www.yahoo.com/favicon.ico'),
        ('http://www.yahoo.com/', 'http://www.yahoo.com/favicon.ico')}


def test_a_profile_read_as_evidence(tmp_path):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    profile = tmp_path / 'Users' / 'ana' / 'AppData' / 'Local' / 'Google' / \
        'Chrome' / 'User Data' / 'Default'
    (profile / 'Network').mkdir(parents=True)
    with open(data_path('samples', 'chrome-Cookies-68.0.3440.106'),
              'rb') as handle:
        (profile / 'Network' / 'Cookies').write_bytes(handle.read())
    with open(data_path('samples', 'chrome-Web-Data'), 'rb') as handle:
        (profile / 'Web Data').write_bytes(handle.read())
    (profile / 'Login Data').write_bytes(
        _from_sql('chromium-login_db_v43.sql', tmp_path))
    handler = ImageHandler(str(tmp_path / 'Users' / '..'))
    try:
        rows = collect(handler)
    finally:
        handler.close_resources()
    sources = {r['source'] for r in rows}
    assert {'Chrome cookies', 'Chrome form entries',
            'Chrome saved logins'} <= sources
    logins = [r for r in rows if r['source'] == 'Chrome saved logins']
    assert all(r['category'] == 'logons' and r['user'] == 'ana'
               for r in logins)
    assert os.path.basename(logins[0]['path']) == 'Login Data'

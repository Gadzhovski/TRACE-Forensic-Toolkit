"""What lLEAPP lists that TRACE did not read (core/activity/linux_extras.py,
web_logs.py, chromium_extras.py, remote_access.py).

Expected values from outside TRACE where they exist: plaso's tests for its
.viminfo, apache_access.log, Firefox cookies and Chrome Preferences files,
and Chromium's own omnibox fixture (its rows are the expected values).
The rest is written here as the producer writes it -- the freedesktop.org
Trash spec, fstab(5), snapd's state.json, LibreOffice's registry,
Chromium's table definitions -- and read back as folder evidence.
"""

import datetime
import gzip
import json
import os
import sqlite3

from tests.conftest import data_path
from trace_app.core.activity import (chromium_extras, linux_extras,
                                     remote_access, web_logs)

UTC = datetime.timezone.utc
WEBKIT = datetime.datetime(1601, 1, 1, tzinfo=UTC)


def _sample(name, mode='r'):
    with open(data_path('samples', name), mode,
              **({} if 'b' in mode else {'encoding': 'utf-8'})) as handle:
        return handle.read()


def _at(*args):
    return datetime.datetime(*args, tzinfo=UTC)


# --- viminfo (plaso) ----------------------------------------------------------------

def test_viminfo_as_plaso_reads_it():
    items = linux_extras.viminfo(_sample('plaso-viminfo'))
    # plaso: 10 event data, in file order.
    assert len(items) == 10
    assert (items[0]['kind'], items[0]['value'], items[0]['time']) == \
        ('Vim command', 'e TEST', _at(2009, 2, 13, 23, 31, 30))
    assert (items[2]['kind'], items[2]['value'], items[2]['time']) == \
        ('Vim search', '/test_search', _at(2009, 2, 13, 23, 31, 32))
    assert (items[4]['kind'], items[4]['value'], items[4]['time']) == \
        ('Vim register', 'test register', _at(2009, 2, 13, 23, 31, 34))
    assert (items[6]['kind'], items[6]['value'], items[6]['time']) == \
        ('Vim file mark', '~\\_vimrc', _at(2009, 2, 13, 23, 31, 36))
    assert (items[8]['kind'], items[8]['value'], items[8]['time']) == \
        ('Vim jump', '~\\_vimrc', _at(2009, 2, 13, 23, 31, 38))
    assert items[5]['value'] == ('test multiline register1\n'
                                 'test multiline register2')
    assert items[7]['line'] == 12
    assert len(linux_extras.viminfo(_sample('plaso-viminfo_alt'))) == 2


def test_an_old_viminfo_lists_its_history_untimed():
    text = ("# Command Line History (newest to oldest):\n:wq\n:e /etc/hosts\n"
            "\n# Search String History (newest to oldest):\n?/password\n")
    items = linux_extras.viminfo(text)
    assert [(i['kind'], i['value'], i['time']) for i in items] == [
        ('Vim command', 'wq', None), ('Vim command', 'e /etc/hosts', None),
        ('Vim search', '/password', None)]


# --- web server logs (plaso) ------------------------------------------------------

def test_access_logs_as_plaso_reads_them():
    requests, bad = web_logs.parse(_sample('plaso-apache_access.log'))
    # plaso: 14 events; line 8 (an unterminated User-Agent) not parsed.
    assert len(requests) == 14 and bad == [8]
    first = requests[0]
    assert (first['client'], first['method'], first['target'],
            first['status'], first['size'], first['time']) == (
        '10.0.0.1', 'GET', '/wp-content/themes/darkmode/header.php?install2',
        200, 494, _at(2016, 1, 13, 19, 31, 16))
    fifth = requests[4]
    assert fifth['time'] == _at(2016, 1, 13, 17, 31, 20)     # +02:00
    assert fifth['referer'] == 'http://localhost/'
    assert fifth['agent'] == ('Mozilla/5.0 (X11; Linux i686; rv:2.0b12pre) '
                              'Gecko/20100101 Firefox/4')
    vhost = requests[8]
    assert (vhost['vhost'], vhost['port'], vhost['size'], vhost['time']) == \
        ('plaso.log2timeline.net', 443, 1063, _at(2018, 1, 13, 19, 31, 17))
    last = requests[13]
    assert (last['client'], last['user'], last['size']) == \
        ('192.168.0.64', 'pyllyukko@EXAMPLE.COM', 8264)
    assert last['time'] == _at(2019, 11, 16, 7, 46, 42)
    # Quotes inside the request line (an attack's) do not end it early.
    assert requests[11]['target'].startswith('/aaaa.xxxx/SomeText?')
    assert requests[11]['status'] == 404


def test_attacks_are_records_and_the_rest_is_summarised():
    requests, _bad = web_logs.parse(_sample('plaso-apache_access.log'))
    reasons = [web_logs.suspicious(r) for r in requests]
    assert reasons[3] == 'command injection'              # cmd=ver;uname
    assert reasons[11] == 'script injection'
    assert reasons[12] == 'code injection'                # ${...}
    assert reasons[0] is None and reasons[5] is None
    rows = web_logs.records(requests, 'web server log (apache2)', 'p', 'r')
    flagged = [r for r in rows if r['what'].startswith('Suspicious')]
    assert len(flagged) == 6
    summaries = [r for r in rows if r['what'] == 'Web requests from client']
    # One per site, address and day; every request counted once.
    assert sum(r['detail']['requests'] for r in summaries) == 14
    busiest = next(r for r in summaries if r['subject'] == '192.168.0.2'
                   and r['time'].startswith('2016'))
    assert busiest['detail']['requests'] == 3
    assert busiest['detail']['suspicious requests'] == 2


def test_posts_and_scanners_and_iis():
    log = ('203.0.113.9 - - [01/Mar/2024:10:00:00 +0000] "POST /upload.php '
           'HTTP/1.1" 200 12 "-" "curl/8.0"\n'
           '203.0.113.9 - - [01/Mar/2024:10:00:05 +0000] "GET /index.php '
           'HTTP/1.1" 200 99 "-" "sqlmap/1.7#stable"\n')
    requests, bad = web_logs.parse(log)
    assert not bad
    rows = web_logs.records(requests, 's', 'p', 'r')
    assert [r['what'] for r in rows] == [
        'Web request (POST)', 'Suspicious web request (scanner)',
        'Web requests from client']
    iis = ("#Software: Microsoft Internet Information Services 10.0\n"
           "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query "
           "s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status "
           "sc-substatus sc-win32-status time-taken\n"
           "2024-03-01 10:00:00 10.0.0.5 GET /aspnet_client/shell.aspx "
           "cmd=whoami 443 - 198.51.100.7 Mozilla/5.0+(Windows) - 200 0 0 "
           "15\n")
    [request] = web_logs.parse_w3c(iis)
    assert request['target'] == '/aspnet_client/shell.aspx?cmd=whoami'
    assert request['agent'] == 'Mozilla/5.0 (Windows)'
    assert request['time'] == _at(2024, 3, 1, 10, 0, 0)
    assert web_logs.suspicious(request) == 'command injection'


# --- Firefox and Chromium (plaso, Chromium) -------------------------------------

def _read_file(name):
    return chromium_extras.read(_sample(name, 'rb'))


def test_firefox_cookies_as_plaso_reads_them():
    kind, rows = _read_file('plaso-firefox_2_cookies.sqlite')
    assert kind == 'firefox_cookies' and len(rows) == 90
    cookie = next(r for r in rows if r['host'].lstrip('.') ==
                  's.greenqloud.com'
                  and r['name'] == '__utma')
    # plaso: created 2013-10-30T21:56:03.992499, accessed .997686, expires
    # 2015-10-30T21:56:03, neither HTTP only nor secure.
    assert cookie['created'] == _at(2013, 10, 30, 21, 56, 3, 992499)
    assert cookie['accessed'] == _at(2013, 10, 30, 21, 56, 3, 997686)
    assert cookie['expires'] == _at(2015, 10, 30, 21, 56, 3)
    assert not cookie['httponly'] and not cookie['secure']
    kind, rows = _read_file('plaso-firefox_10_cookies.sqlite')
    assert len(rows) == 13
    cookie = next(r for r in rows if r['host'] == 'en.wikipedia.org')
    assert cookie['name'] == 'WMF-Last-Access'
    assert cookie['created'] == cookie['accessed'] == \
        _at(2023, 5, 5, 16, 0, 44, 811189)
    assert cookie['expires'] == _at(2023, 6, 6, 12, 0, 0)
    assert cookie['httponly'] and cookie['secure']


def test_cookie_values_are_never_copied(tmp_path):
    path = data_path('samples', 'plaso-firefox_10_cookies.sqlite')
    connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    values = [v for (v,) in connection.execute(
        "SELECT value FROM moz_cookies") if v and len(v) > 4]
    connection.close()
    kind, rows = _read_file('plaso-firefox_10_cookies.sqlite')
    found = chromium_extras.records(kind, rows, 'u', 'p', 'r', 'Firefox')
    text = json.dumps(found)
    assert values and not any(value in text for value in values)
    assert all(r['detail']['value'] in ('stored in clear (not copied)',
                                        'empty') for r in found)


def test_chromium_shortcuts_fixture(tmp_path):
    database = tmp_path / 'Shortcuts'
    connection = sqlite3.connect(str(database))
    connection.executescript(_sample('chromium-Shortcuts.v1.sql'))
    connection.close()
    kind, rows = chromium_extras.read(database.read_bytes())
    assert kind == 'shortcuts' and len(rows) == 7
    first = next(r for r in rows if r['typed'] == 'sha')
    assert first['url'] == 'http://shacknews.com/' and first['hits'] == 3
    assert first['last_used'] == WEBKIT + datetime.timedelta(
        microseconds=13024194201806179)
    reddit = next(r for r in rows if r['typed'] == 'rdt')
    assert reddit['url'] == 'http://www.reddit.com/'


def test_chrome_preferences_as_plaso_reads_them():
    found = chromium_extras.preferences(_sample('plaso-chrome-Preferences',
                                                'rb'))
    # plaso: 30 event data -- 2 autoupdater runs (not kept), history
    # cleared, 20 extensions and 7 site permissions.
    assert len(found['extensions']) == 20
    assert len(found['permissions']) == 7
    assert found['cleared'] == _at(2016, 6, 8, 16, 17, 47, 453766)
    chrome = next(e for e in found['extensions']
                  if e['id'] == 'mgndgikekgjfcpckkfioiadnlibdjbkf')
    assert chrome['name'] == 'Chrome'
    assert chrome['installed'] == _at(2014, 11, 5, 18, 31, 24, 154837)
    assert chrome['path'] == ('C:\\Program Files\\Google\\Chrome\\'
                              'Application\\38.0.2125.111\\resources\\'
                              'chrome_app')
    midi = next(p for p in found['permissions']
                if p['permission'] == 'midi_sysex')
    assert midi['site'] == 'https://rawgit.com:443'
    assert midi['last_used'] == _at(2016, 11, 11, 16, 20, 9, 866137)
    rows = chromium_extras.preferences_records(found, 'u', 'p', 'r', 'Chrome')
    built_in = [r for r in rows if r['what'] == 'Browser extension installed'
                and r['detail'].get('came from') == 'built in']
    assert built_in and not any(r['detail'].get('grade') for r in built_in)


def test_a_sideloaded_extension_is_notable():
    prefs = {'extensions': {'settings': {'abc': {
        'install_time': '13300000000000000', 'location': 4, 'state': 1,
        'path': 'C:\\Users\\a\\ext', 'manifest': {'name': 'Helper',
                                                   'version': '1.0'}}}},
        'account_info': [{'email': 'a@example.com', 'full_name': 'A',
                          'gaia': '1', 'hosted_domain': 'example.com'}],
        'download': {'default_directory': '/home/a/Downloads'}}
    found = chromium_extras.preferences(json.dumps(prefs).encode())
    rows = chromium_extras.preferences_records(found, 'u', 'p', 'r', 'Chrome')
    extension = next(r for r in rows if r['what'] ==
                     'Browser extension installed')
    assert extension['detail']['grade'] == 'notable'
    assert extension['detail']['came from'] == 'unpacked (developer mode)'
    assert any(r['what'] == 'Signed in to the browser' and
               r['subject'] == 'a@example.com' for r in rows)
    assert any(r['what'] == 'Download folder set' for r in rows)


def _database(path, script):
    connection = sqlite3.connect(str(path))
    connection.executescript(script)
    connection.commit()
    connection.close()
    return path.read_bytes()


# Chromium's own definitions (predictors/autocomplete_action_predictor_table
# .cc, media/history/media_history_*_table.cc, offline_pages/core/
# offline_page_metadata_store.cc), rows written as Chrome writes them.
PREDICTOR = """
CREATE TABLE network_action_predictor (id TEXT PRIMARY KEY, user_text TEXT,
  url TEXT, number_of_hits INTEGER, number_of_misses INTEGER);
INSERT INTO network_action_predictor VALUES
  ('1', 'bank', 'https://bank.example/login', 4, 1);
"""
MEDIA = """
CREATE TABLE origin (id INTEGER PRIMARY KEY, origin TEXT NOT NULL UNIQUE,
  last_updated_time_s INTEGER, has_media_engagement INTEGER,
  media_engagement_visits INTEGER, media_engagement_playbacks INTEGER,
  media_engagement_last_playback_time REAL,
  media_engagement_has_high_score INTEGER);
CREATE TABLE playback (id INTEGER PRIMARY KEY, origin_id INTEGER NOT NULL,
  url TEXT, watch_time_s INTEGER, has_video INTEGER, has_audio INTEGER,
  last_updated_time_s INTEGER NOT NULL);
CREATE TABLE playbackSession (id INTEGER PRIMARY KEY, origin_id INTEGER
  NOT NULL, url TEXT, duration_ms INTEGER, position_ms INTEGER,
  last_updated_time_s INTEGER NOT NULL, title TEXT, artist TEXT,
  album TEXT, source_title TEXT);
INSERT INTO origin VALUES (1, 'https://video.example', 13350000000, 1, 1,
  1, 0, 0);
INSERT INTO playback VALUES (1, 1, 'https://video.example/watch?v=1', 125,
  1, 1, 13350000000);
INSERT INTO playbackSession VALUES (1, 1, 'https://video.example/watch?v=1',
  600000, 125000, 13350000100, 'A talk', 'Speaker', NULL, 'Video site');
"""
OFFLINE = """
CREATE TABLE offlinepages_v1 (offline_id INTEGER PRIMARY KEY NOT NULL,
  creation_time INTEGER NOT NULL, file_size INTEGER NOT NULL,
  last_access_time INTEGER NOT NULL, access_count INTEGER NOT NULL,
  system_download_id INTEGER NOT NULL DEFAULT 0, file_missing_time INTEGER
  NOT NULL DEFAULT 0, digest VARCHAR NOT NULL DEFAULT '', client_namespace
  VARCHAR NOT NULL, client_id VARCHAR NOT NULL, online_url VARCHAR NOT NULL,
  file_path VARCHAR NOT NULL, title VARCHAR NOT NULL DEFAULT '',
  original_url VARCHAR NOT NULL DEFAULT '', request_origin VARCHAR NOT NULL
  DEFAULT '', snippet VARCHAR NOT NULL DEFAULT '', attribution VARCHAR NOT
  NULL DEFAULT '');
INSERT INTO offlinepages_v1 (offline_id, creation_time, file_size,
  last_access_time, access_count, client_namespace, client_id, online_url,
  file_path, title) VALUES (7, 13300000000000000, 2048, 13300000500000000,
  2, 'download', 'x', 'https://news.example/a', '/data/x.mhtml', 'News');
"""
FORMS = """
CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT
  NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER,
  lastUsed INTEGER, guid TEXT);
INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'flights to oslo',
  3, 1700000000000000, 1700000600000000, 'g');
"""


def test_generated_chromium_and_firefox_databases(tmp_path):
    kind, rows = chromium_extras.read(_database(tmp_path / 'p', PREDICTOR))
    assert kind == 'predictor'
    assert rows == [{'typed': 'bank', 'url': 'https://bank.example/login',
                     'hits': 4, 'misses': 1}]
    kind, rows = chromium_extras.read(_database(tmp_path / 'm', MEDIA))
    assert kind == 'media' and len(rows) == 2
    # Seconds since 1601.
    assert rows[0]['updated'] == WEBKIT + datetime.timedelta(
        seconds=13350000000)
    session = rows[1]
    assert (session['title'], session['duration_ms'],
            session['position_ms']) == ('A talk', 600000, 125000)
    records = chromium_extras.records(kind, rows, 'u', 'p', 'r', 'Chrome')
    assert records[1]['detail']['stopped at (s)'] == 125.0
    kind, rows = chromium_extras.read(_database(tmp_path / 'o', OFFLINE))
    assert kind == 'offline_pages'
    assert rows[0]['url'] == 'https://news.example/a'
    assert rows[0]['created'] == WEBKIT + datetime.timedelta(
        microseconds=13300000000000000)
    kind, rows = chromium_extras.read(_database(tmp_path / 'f', FORMS))
    assert kind == 'firefox_forms'
    assert rows[0]['value'] == 'flights to oslo' and rows[0]['count'] == 3
    assert rows[0]['created'] == _at(2023, 11, 14, 22, 13, 20)


# --- a Linux system as folder evidence --------------------------------------------

def _write(root, relative, content, mtime=None):
    path = os.path.join(root, *relative.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = 'wb' if isinstance(content, bytes) else 'w'
    with open(path, mode, **({} if mode == 'wb' else
                             {'encoding': 'utf-8', 'newline': '\n'})) as f:
        f.write(content)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


FSTAB = """# /etc/fstab
UUID=1234-ABCD /boot/efi vfat umask=0077 0 1
UUID=0f0e /  ext4 errors=remount-ro 0 1
//fileserver/finance /mnt/finance cifs credentials=/root/.smbcred,uid=1000 0 0
//nas.local/backup /mnt/backup cifs username=alice,password=Hunter2Secret 0 0
nfs.example.org:/exports/home /mnt/home nfs4 defaults 0 0
/swapfile none swap sw 0 0
"""
SNAP_STATE = {
    'data': {'snaps': {
        'firefox': {'type': 'app', 'active': True, 'current': '4136',
                    'channel': 'latest/stable', 'sequence': [
                        {'name': 'firefox', 'revision': '4136',
                         'version': '125.0.2-1'}]},
        'telegram-desktop': {'type': 'app', 'active': True,
                             'current': '5800', 'channel': 'latest/stable',
                             'sequence': [{'revision': '5800',
                                           'version': '4.16.8'}]}}},
    'changes': {
        '12': {'id': '12', 'kind': 'install-snap',
               'summary': 'Install "telegram-desktop" snap',
               'spawn-time': '2024-04-02T09:15:01.123456789+02:00',
               'ready-time': '2024-04-02T09:15:40.5Z',
               'data': {'snap-names': ['telegram-desktop']}}}}
XCU = """<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry"
 xmlns:xs="http://www.w3.org/2001/XMLSchema">
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/ItemList/org.openoffice.Office.Histories:HistoryItem['file:///home/alice/Documents/Plan%20B.odt']"><prop oor:name="Filter" oor:op="fuse"><value>writer8</value></prop></item>
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/ItemList/org.openoffice.Office.Histories:HistoryItem['file:///home/alice/Documents/Plan%20B.odt']"><prop oor:name="Title" oor:op="fuse"><value>Plan B</value></prop></item>
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/ItemList/org.openoffice.Office.Histories:HistoryItem['file:///home/alice/Documents/Plan%20B.odt']"><prop oor:name="Password" oor:op="fuse"><value>ZW5jb2RlZHNlY3JldA==</value></prop></item>
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/ItemList/org.openoffice.Office.Histories:HistoryItem['file:///home/alice/old.xlsx']"><prop oor:name="Title" oor:op="fuse"><value>old</value></prop></item>
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/OrderList/org.openoffice.Office.Histories:HistoryOrder['0']"><prop oor:name="HistoryItemRef" oor:op="fuse"><value>file:///home/alice/Documents/Plan%20B.odt</value></prop></item>
<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo['PickList']/OrderList/org.openoffice.Office.Histories:HistoryOrder['1']"><prop oor:name="HistoryItemRef" oor:op="fuse"><value>file:///home/alice/old.xlsx</value></prop></item>
</oor:items>
"""


def _linux_root(tmp_path):
    root = str(tmp_path / 'linux')
    when = datetime.datetime(2024, 5, 1, tzinfo=UTC).timestamp()
    _write(root, 'etc/hostname', 'desk\n')
    _write(root, 'var/log/auth.log', '')
    _write(root, 'home/alice/.local/share/Trash/info/report 1.pdf'
                 '.trashinfo',
           '[Trash Info]\nPath=/home/alice/Documents/report%201.pdf\n'
           'DeletionDate=2024-04-30T18:22:05\n')
    _write(root, 'home/alice/.local/share/Trash/files/report 1.pdf', b'%PDF')
    _write(root, 'home/alice/.local/share/Trash/info/notes.txt.trashinfo',
           '[Trash Info]\nPath=/home/alice/notes.txt\n'
           'DeletionDate=2024-04-29T08:00:00\n')
    _write(root, '.Trash-1000/info/leak.zip.trashinfo',
           '[Trash Info]\nPath=exports/leak.zip\n'
           'DeletionDate=2024-04-28T12:00:00\n')
    _write(root, 'home/alice/.viminfo', _sample('plaso-viminfo'))
    _write(root, 'etc/fstab', FSTAB, when)
    _write(root, 'etc/crypttab', 'luks-home UUID=aa none luks\n'
                                 'data /dev/sdb1 /root/keyfile luks\n', when)
    _write(root, 'etc/mdadm/mdadm.conf',
           'ARRAY /dev/md0 metadata=1.2 name=desk:0 '
           'UUID=a1b2c3d4:e5f60718:293a4b5c:6d7e8f90\n', when)
    _write(root, 'var/lib/snapd/state.json', json.dumps(SNAP_STATE))
    _write(root, 'var/lib/flatpak/app/org.signal.Signal/x86_64/stable/'
                 'active/metadata', '[Application]\n', when)
    _write(root, 'home/alice/.config/libreoffice/4/user/'
                 'registrymodifications.xcu', XCU, when)
    _write(root, 'var/log/apache2/access.log.1.gz',
           gzip.compress(_sample('plaso-apache_access.log').encode()))
    profile = 'home/alice/.config/google-chrome/Default/'
    _write(root, profile + 'Preferences',
           _sample('plaso-chrome-Preferences', 'rb'))
    shortcuts = tmp_path / 'shortcuts.db'
    connection = sqlite3.connect(str(shortcuts))
    connection.executescript(_sample('chromium-Shortcuts.v1.sql'))
    connection.close()
    _write(root, profile + 'Shortcuts', shortcuts.read_bytes())
    firefox = 'home/alice/.mozilla/firefox/abcd.default-release/'
    _write(root, firefox + 'cookies.sqlite',
           _sample('plaso-firefox_10_cookies.sqlite', 'rb'))
    _write(root, firefox + 'formhistory.sqlite',
           _database(tmp_path / 'forms', FORMS))
    _write(root, 'home/alice/.vnc/office.vnc',
           'Host=10.1.2.3:5900\nFriendlyName=Office PC\nUserName=alice\n'
           'Password=7b2e0c1a99\nUuid=11-22\n')
    return root


def _records(root):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(root)
    try:
        assert handler.loaded
        return collect(handler)
    finally:
        handler.close_resources()


def test_a_linux_system_end_to_end(tmp_path):
    rows = _records(_linux_root(tmp_path))
    by = {}
    for row in rows:
        by.setdefault(row['what'], []).append(row)

    trashed = {r['subject']: r for r in by['Moved to Trash']}
    assert set(trashed) == {'/home/alice/Documents/report 1.pdf',
                            '/home/alice/notes.txt', '/exports/leak.zip'}
    report = trashed['/home/alice/Documents/report 1.pdf']
    assert report['time'] == '2024-04-30 18:22:05' and report['local']
    assert report['detail']['still in Trash'] == 'yes'
    assert trashed['/home/alice/notes.txt']['detail'][
        'still in Trash'].startswith('no')
    assert report['user'] == 'alice'

    assert any(r['subject'] == 'e TEST' and r['source'] == 'viminfo'
               for r in by['Command typed'])
    assert any(r['subject'] == '~\\_vimrc' for r in by['File edited'])

    shares = {r['detail']['server']: r for r in by['Network share (SMB)']}
    assert shares['fileserver']['detail']['credentials file'] == \
        '/root/.smbcred'
    assert shares['nas.local']['detail']['password in fstab'] == \
        'yes (not copied)'
    assert by['Network share (NFS)'][0]['detail']['server'] == \
        'nfs.example.org'
    assert any(r['subject'].startswith('/swapfile')
               for r in by['Swap configured'])
    keyed = {r['subject']: r for r in by['Encrypted volume configured']}
    assert keyed['data <- /dev/sdb1']['detail']['key'] == \
        'key file /root/keyfile (not read)'
    assert by['RAID array configured'][0]['detail']['UUID'] == \
        'a1b2c3d4:e5f60718:293a4b5c:6d7e8f90'

    [install] = by['Snap install snap']
    assert install['time'] == '2024-04-02 07:15:01'
    assert install['detail']['finished'] == '2024-04-02 09:15:40'
    versions = {r['subject']: r['detail']['version']
                for r in by['Snap installed']}
    assert versions == {'firefox': '125.0.2-1',
                        'telegram-desktop': '4.16.8'}
    assert [r['subject'] for r in by['Flatpak app installed']] == \
        ['org.signal.Signal']

    recent = by['Recent document (LibreOffice)']
    assert [r['subject'] for r in recent] == [
        '/home/alice/Documents/Plan B.odt', '/home/alice/old.xlsx']
    assert recent[0]['time'] and not recent[1]['time']
    assert recent[0]['detail']['password remembered'] == 'yes (not copied)'

    flagged = by['Suspicious web request (command injection)']
    assert len(flagged) == 4
    assert flagged[0]['source'] == 'web server log (apache2)'

    assert any(r['subject'] == 'sha' and r['detail']['opened'] ==
               'http://shacknews.com/'
               for r in by['Typed into the address bar'])
    assert len(by['Browser extension installed']) >= 20
    assert any(r['source'] == 'Firefox cookies' for r in by['Cookie set'])
    assert any(r['subject'] == 'flights to oslo'
               for r in by['Typed into a form'])

    [vnc] = by['VNC connection saved']
    assert vnc['subject'] == '10.1.2.3:5900'
    assert vnc['detail']['saved password'] == 'yes (not copied)'

    text = json.dumps(rows)
    for secret in ('Hunter2Secret', 'ZW5jb2RlZHNlY3JldA==', '7b2e0c1a99'):
        assert secret not in text


# --- remote access ------------------------------------------------------------------

class _Value:
    def __init__(self, value):
        self._value = value

    def value(self):
        return self._value


class _Key:
    """python-registry's key, as far as the readers use it."""

    def __init__(self, name, values=None, subkeys=(), stamp=None):
        self._name, self._values = name, values or {}
        self._subkeys, self._stamp = list(subkeys), stamp

    def name(self):
        return self._name

    def value(self, name):
        if name not in self._values:
            raise KeyError(name)
        return _Value(self._values[name])

    def subkeys(self):
        return self._subkeys

    def timestamp(self):
        return self._stamp


class _Hive:
    def __init__(self, keys):
        self.keys = keys

    def open(self, path):
        if path not in self.keys:
            raise KeyError(path)
        return self.keys[path]


def test_remote_desktop_and_vpn_from_the_registry():
    stamp = datetime.datetime(2024, 2, 1, 9, 30)
    tsc = 'Software\\Microsoft\\Terminal Server Client'
    hive = _Hive({
        tsc + '\\Default': _Key('Default', {'MRU0': '10.0.0.20',
                                            'MRU1': 'dc01.corp.local'},
                                stamp=stamp),
        tsc + '\\Servers': _Key('Servers', subkeys=[
            _Key('10.0.0.20', {'UsernameHint': 'CORP\\admin',
                               'CertHash': b'\x01' * 20},
                 stamp=datetime.datetime(2024, 2, 1, 9, 31))]),
        'Software\\Palo Alto Networks\\GlobalProtect\\Settings': _Key(
            'Settings', subkeys=[_Key('vpn.corp.example', {},
                                      stamp=stamp)]),
    })
    rows = remote_access.ntuser_records(hive, dict(user='bob', path='p',
                                                   ref='r'))
    recent = [r for r in rows
              if r['what'] == 'Remote Desktop connection (recent)']
    assert [(r['subject'], r['time']) for r in recent] == [
        ('10.0.0.20', '2024-02-01 09:30:00'), ('dc01.corp.local', None)]
    [server] = [r for r in rows if r['what'] == 'Remote Desktop server']
    assert server['detail']['user name'] == 'CORP\\admin'
    assert server['detail']['certificate accepted'] == 'yes'
    [portal] = [r for r in rows if r['what'].startswith('VPN portal')]
    assert portal['subject'] == 'vpn.corp.example'
    setup = _Hive({'Palo Alto Networks\\GlobalProtect\\PanSetup': _Key(
        'PanSetup', {'Portal': 'vpn.corp.example', 'Prelogon': '1'},
        stamp=stamp)})
    [installed] = remote_access.software_records(setup, {})
    assert installed['subject'] == 'vpn.corp.example'


def test_rdp_files_and_the_android_client(tmp_path):
    rdp = ('screen mode id:i:2\r\nfull address:s:jump.corp.example\r\n'
           'username:s:CORP\\carol\r\ngatewayhostname:s:gw.corp.example\r\n'
           'password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB\r\n')
    facts = remote_access.rdp_file(rdp)
    assert facts['full address'] == 'jump.corp.example'
    assert facts['password 51'] == '(not copied)'
    database = _database(tmp_path / 'rdp', """
        CREATE TABLE credential_table (credential_table_id INTEGER PRIMARY
          KEY, username TEXT, password TEXT);
        CREATE TABLE connection_table (connection_table_id INTEGER PRIMARY
          KEY, servername TEXT, servername_friendly TEXT, credential_id
          INTEGER);
        INSERT INTO credential_table VALUES (1, 'dave', 'S3cretPassw0rd');
        INSERT INTO connection_table VALUES (1, '192.0.2.44', 'Lab box', 1);
    """)
    rows = remote_access.rdp_connections(database)
    assert rows == [{'server': '192.0.2.44', 'name': 'Lab box',
                     'user': 'dave'}]
    root = str(tmp_path / 'phone')
    _write(root, 'data/data/com.microsoft.rdc.androidx/databases/'
                 'RDPConnection.db', database)
    _write(root, 'data/system/packages.xml', '<packages/>')
    _write(root, 'Users/carol/Documents/Default.rdp',
           b'\xff\xfe' + rdp.encode('utf-16-le'))
    rows = _records(root)
    saved = [r for r in rows if r['what'] == 'Remote Desktop server saved']
    assert saved and saved[0]['subject'] == '192.0.2.44'
    assert 'S3cretPassw0rd' not in json.dumps(rows)

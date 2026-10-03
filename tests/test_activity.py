"""Windows activity and browser history (trace_app/core/activity).

Real artifacts -- Prefetch from XP to Windows 11, hives, Jump Lists, event
logs, browser databases -- fetched and checksum-pinned by
tools/fetch_artifact_samples.py. Where plaso's own tests record a value for
the same file, the expected value here is that one: two implementations
reading the same bytes the same way. The rest are generated here.
"""

import datetime
import os
import sqlite3

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        message = (f"{name} is not in test_images/artifact_samples -- run "
                   f"'python tools/fetch_artifact_samples.py'")
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    with open(path, 'rb') as handle:
        return handle.read()


def iso(value):
    from trace_app.core.activity import times
    return times.iso(value)


# --- Prefetch, and the Windows 10 compression ---------------------------------

@pytest.mark.parametrize('name, version, runs, last, previous, files', [
    ('CMD.EXE-087B4001.pf', 17, 2, '2013-03-10 10:11:49', None, None),
    ('PING.EXE-B29F6629.pf', 23, 14, '2012-04-06 19:00:55', None, None),
    ('WUAUCLT.EXE-830BCC14.pf', 23, 25, '2012-03-15 21:17:39', None, None),
    ('TASKHOST.EXE-3AE259FC.pf', 26, 4, '2013-10-04 15:40:09', None, None),
    # Compressed (MAM, LZXPRESS Huffman), Windows 10.
    ('BYTECODEGENERATOR.EXE-C1E9BCE6.pf', 30, 7, '2015-05-14 22:11:58', None,
     None),
    ('ONEDRIVE.EXE-7E152375.pf', 30, 2, '2015-05-14 22:11:05', None, None),
    ('NOTEPAD.EXE-D8414F97.pf', 30, 2, '2019-06-05 19:55:04',
     '2019-06-05 19:23:00', 56),
])
def test_prefetch_matches_plaso(name, version, runs, last, previous, files):
    from trace_app.core.activity import prefetch
    facts = prefetch.parse(sample(name))
    assert facts['version'] == version
    assert facts['run_count'] == runs
    assert iso(facts['runs'][0]) == last
    if previous:
        assert iso(facts['runs'][1]) == previous
    if files:
        assert len(facts['files']) == files
    assert facts['path'].upper().endswith(facts['executable'].upper()[:29])


def test_prefetch_volume_and_truncated_name():
    from trace_app.core.activity import prefetch
    notepad = prefetch.parse(sample('NOTEPAD.EXE-D8414F97.pf'))
    assert notepad['volumes'][0]['serial'] == '2CA3D1AE'
    assert notepad['volumes'][0]['created'] == '2017-07-30 19:40:03'
    # Windows 11 (v31), its 29-character name cut short.
    delta = prefetch.parse(sample('AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf'))
    assert delta['version'] == 31 and delta['run_count'] == 1
    assert 'AM_DELTA_PATCH_1.443.990.0.EX' in delta['path'].upper()


def test_lzxpress_rejects_garbage():
    from trace_app.core.activity import lzxpress
    with pytest.raises(lzxpress.DecompressionError):
        lzxpress.decompress(b'\x00' * 300, 1000)


# --- shortcuts, Jump Lists, Recycle Bin ------------------------------------------

def test_shortcut_matches_plaso():
    from trace_app.core.activity import lnk
    facts = lnk.parse(sample('NeroInfoTool.lnk'))
    assert facts['target'] == ('C:\\Program Files (x86)\\Nero\\Nero 9\\'
                               'Nero InfoTool\\InfoTool.exe')
    assert facts['target_size'] == 4635160
    assert facts['volume_label'] == 'OS' and facts['drive_type'] == 'fixed'
    assert iso(facts['target_created']) == '2009-06-05 20:13:20'
    assert facts['mac_address'] == '70:5a:b6:16:a5:f3'


def test_jump_lists_match_plaso():
    from trace_app.core.activity import jumplists
    entries = jumplists.parse_automatic(
        sample('1b4dd67f29cb1962.automaticDestinations-ms'))
    downloads = entries[0]
    assert downloads['path'] == 'C:\\Users\\bperry\\Downloads'
    assert downloads['host'] == 'student-pc1' and downloads['number'] == 7
    assert iso(downloads['accessed']) == '2015-08-29 15:32:44'
    assert not downloads['pinned']
    edge = jumplists.parse_automatic(
        sample('9d1f905ce5044aee.automaticDestinations-ms'))     # DestList v3
    assert edge[0]['path'] == 'http://support.microsoft.com/kb/3124263'
    assert edge[0]['lnk']['target'] == edge[0]['path']
    custom = jumplists.parse_custom(
        sample('5afe4de1b92fc382.customDestinations-ms'))
    assert custom and custom[0]['path'].endswith('GettingStarted.exe')
    assert jumplists.app_name('1b4dd67f29cb1962.automaticDestinations-ms') \
        == ('1b4dd67f29cb1962', 'Windows Explorer')


def test_recycle_bin_matches_plaso():
    from trace_app.core.activity import recyclebin
    v2 = recyclebin.parse_i_file(sample('$I103S5F.jpg'))
    assert (v2['version'], v2['path'], v2['size']) == (
        2, 'C:\\Users\\random\\Downloads\\bunnies.jpg', 222255)
    assert iso(v2['deleted']) == '2016-06-29 21:37:45'
    v1 = recyclebin.parse_i_file(sample('$II3DF3L.zip'))
    assert v1['version'] == 1 and v1['size'] == 724919
    assert iso(v1['deleted']) == '2012-03-12 20:49:58'
    xp = recyclebin.parse_info2(sample('INFO2'))
    assert len(xp) == 4 and xp[0]['index'] == 1 and xp[0]['drive'] == 'C'
    assert iso(xp[0]['deleted']) == '2004-08-25 16:18:25'


# --- the registry ------------------------------------------------------------------

def test_userassist_matches_plaso():
    from trace_app.core.activity import registry
    xp = registry.userassist(registry.open_hive(sample('NTUSER-XP.DAT')))
    msn = next(e for e in xp if e['name'].endswith('MSN.lnk'))
    assert msn['run_count'] == 14
    assert iso(msn['last_run']) == '2009-08-04 15:11:22'
    win10 = registry.userassist(registry.open_hive(sample('NTUSER-WIN10.DAT')))
    ie = next(e for e in win10
              if e['name'] == 'Microsoft.InternetExplorer.Default')
    assert ie['run_count'] == 2 and ie['focus_count'] == 8
    assert iso(ie['last_run']) == '2016-10-09 19:58:01'
    # Known-folder GUIDs become paths.
    win7 = registry.userassist(registry.open_hive(sample('NTUSER-WIN7.DAT')))
    assert any(e['name'] == 'C:\\Windows\\System32\\calc.exe' for e in win7)


def test_recent_docs_and_shellbags():
    from trace_app.core.activity import registry
    hive = registry.open_hive(sample('NTUSER-XP.DAT'))
    docs = registry.recent_docs(hive)
    assert docs[0]['position'] == 0 and docs[0]['opened'] is not None
    assert any(d['name'] == 'Very secret document.txt' for d in docs)
    bags = {b['path']: b for b in registry.shellbags(hive)}
    folder = bags['C:\\Documents and Settings\\Administrator']
    # DOS dates in the shell item: local time, a plausible year.
    assert folder['created'].year == 2007 and folder['modified'].year == 2009
    win10 = {b['path'] for b in registry.shellbags(
        registry.open_hive(sample('UsrClass-WIN10.dat')))}
    assert ('Control Panel\\Appearance and Personalization\\Personalization'
            in win10)
    assert 'My Computer\\Pictures' in win10


def test_shimcache_usb_and_amcache():
    from trace_app.core.activity import registry
    system = registry.open_hive(sample('SYSTEM-WIN7'))
    shim = registry.shimcache(system)
    assert len(shim) == 330
    assert shim[0]['path'].endswith('\\mfeann.exe') and shim[0]['executed']
    usb = registry.usb_devices(system)
    assert len(usb) == 1
    device = usb[0]
    assert device['name'] == 'HP v100w USB Device'
    assert device['serial'] == 'AA951D0000007252&0' and device['drive'] == 'E:'
    assert iso(device['first_installed']) == '2011-04-01 04:52:38'
    assert iso(device['interface_updated']) == '2011-04-01 04:52:38'
    win10 = registry.amcache(registry.open_hive(sample('Amcache-WIN10.hve')))
    seven = next(e for e in win10 if e['path'].endswith('\\7z.exe'))
    assert seven['sha1'] == '6c7ea8bbd435163ae3945cbef30ef6b9872a4591'
    assert seven['publisher'] == 'igor pavlov'
    assert len(registry.amcache(registry.open_hive(
        sample('Amcache-WIN8.hve')))) == 1367


def test_setupapi_finds_usb_installs():
    from trace_app.core.activity import setupapi
    text = (
        "[Device Install Log]\n"
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Kingston"
        "&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C3FAE22EEA0797900F7&0]\n"
        ">>>  Section start 2019/04/02 11:22:33.444\n"
        "<<<  Section end 2019/04/02 11:22:40.000\n"
        ">>>  [Device Install (Hardware initiated) - SWD\\IP_TUNNEL_VBUS\\"
        "ISATAP_0]\n"
        ">>>  Section start 2015/11/22 17:59:28.110\n")
    found = setupapi.parse(text)
    assert len(found) == 1                  # the tunnel is not storage
    assert found[0]['installed'] == datetime.datetime(2019, 4, 2, 11, 22, 33)
    kind, vendor, product, serial = setupapi.describe(found[0]['device'])
    assert (kind, vendor, product) == ('USBSTOR', 'Kingston',
                                       'DataTraveler_3.0')
    assert serial == '60A44C3FAE22EEA0797900F7&0'


# --- event logs --------------------------------------------------------------------

def test_evtx_reads_every_record_and_the_fields():
    from trace_app.core.activity import evtx
    records = list(evtx.records(sample('RemoteConnectionManager.evtx')))
    # python-evtx reads 1774; one more is a valid record it drops.
    assert len(records) == 1775
    rdp = [r for r in records if r['event_id'] == 1149]
    assert rdp and rdp[0]['data']['Param3'] == '174.127.93.2'
    assert rdp[0]['channel'].endswith('RemoteConnectionManager/Operational')


def test_evtx_survives_a_damaged_chunk():
    from trace_app.core.activity import evtx
    assert len(list(evtx.records(sample('bad_chunk_magic.evtx')))) == 270


def test_the_events_worth_reading_are_described():
    from trace_app.core.activity import eventlogs
    created = eventlogs.from_evtx(sample('new-user-security.evtx'))
    account = next(e for e in created if e[1] == 'Account created')
    assert account[2] == 'IE8Win7\\IEUser'
    assert iso(account[0]) == '2013-10-23 16:22:39'
    remote = eventlogs.from_evtx(sample('RemoteConnectionManager.evtx'))
    assert {e[1] for e in remote} == {'Remote desktop authentication'}
    assert remote[0][2] == 'MAGNETIC-DESKTO\\mpowers'
    assert remote[0][3]['from'] == '174.127.93.2'
    system = eventlogs.from_evtx(sample('System.evtx'))
    kinds = {e[1] for e in system}
    assert {'Service installed', 'System started'} <= kinds


# --- browsers ------------------------------------------------------------------------

def test_chrome_history_downloads_and_searches():
    from trace_app.core.activity import browsers
    found = browsers.read(sample('History-chrome'))
    assert found['kind'] == 'chromium' and len(found['visits']) == 37
    assert [d['path'] for d in found['downloads']] == [
        '/home/john/Downloads/funcats_scr.exe',
        '/home/john/Downloads/Cats Demo.exe']
    assert found['downloads'][0]['size'] == 1132155
    terms = {s['terms'] for s in found['searches']}
    assert {'funny cats', 'really really funny cats'} <= terms


def test_firefox_and_safari():
    from trace_app.core.activity import browsers
    firefox = browsers.read(sample('places118.sqlite'))
    assert firefox['kind'] == 'firefox'
    assert len(firefox['visits']) == 89 and len(firefox['downloads']) == 7
    assert any(s['terms'] == 'safari on windows' for s in firefox['searches'])
    old = browsers.read(sample('downloads.sqlite'))
    assert old['downloads'][0]['path'] == \
        'D:\\plaso-static-1.0.1-win32-vs2008.zip'
    safari = browsers.read(sample('History.db'))
    assert safari['kind'] == 'safari' and len(safari['visits']) == 25


def test_search_terms_come_from_result_urls():
    from trace_app.core.activity import browsers
    assert browsers.search_in_url(
        'https://www.google.com/search?q=how+to+wipe+a+disk&hl=en') == (
        'Google', 'how to wipe a disk')
    assert browsers.search_in_url(
        'https://duckduckgo.com/?q=tor+browser') == ('DuckDuckGo',
                                                     'tor browser')
    assert browsers.search_in_url('https://example.com/?q=x') is None


def _wal_database(tmp_path):
    """A Firefox-shaped database whose newest visit is only in the WAL."""
    path = str(tmp_path / 'places.sqlite')
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA wal_autocheckpoint = 0")
    db.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT,
                                 title TEXT, visit_count INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY,
                                        from_visit INTEGER, place_id INTEGER,
                                        visit_date INTEGER,
                                        visit_type INTEGER);
        INSERT INTO moz_places VALUES (1, 'https://old.example/', 'Old', 1);
        INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1600000000000000, 1);
    """)
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.execute("INSERT INTO moz_places VALUES "
               "(2, 'https://www.bing.com/search?q=secret+plans', 'New', 1)")
    db.execute("INSERT INTO moz_historyvisits VALUES "
               "(2, 0, 2, 1700000000000000, 2)")
    db.commit()
    with open(path, 'rb') as handle:
        database = handle.read()
    with open(path + '-wal', 'rb') as handle:
        wal = handle.read()
    return db, database, wal


def test_a_wal_is_applied_and_its_visits_read(tmp_path):
    from trace_app.core.activity import browsers
    db, database, wal = _wal_database(tmp_path)
    try:
        assert wal                     # the newest visit is only in the WAL
        without = browsers.read(database)
        assert [v['url'] for v in without['visits']] == ['https://old.example/']
        found = browsers.read(database, wal, 'Firefox')
        assert [v['url'] for v in found['visits']][-1].startswith(
            'https://www.bing.com/')
        assert found['searches'][0]['terms'] == 'secret plans'
        # A torn final frame is not applied: everything after it is unknown.
        torn = browsers.read(database, wal[:-100], 'Firefox')
        assert [v['url'] for v in torn['visits']] == ['https://old.example/']
    finally:
        db.close()


def test_recovered_history_is_read_like_any_other(tmp_path):
    from trace_app.core.activity import collect

    class NoVolumes:
        def get_partitions(self):
            return []

        def get_fs_info(self, _offset):
            return None

    db, database, wal = _wal_database(tmp_path)
    db.close()
    with open(str(tmp_path / 'places.sqlite'), 'rb') as handle:
        merged = handle.read()           # closing checkpointed the WAL
    records = collect(NoVolumes(), carved=[('carved 1f400.sqlite', merged,
                                            'p0:x1f400-2f400')])
    visits = [r for r in records if r['category'] == 'browser']
    assert len(visits) == 2
    assert visits[0]['source'] == 'Firefox (carved)'
    assert visits[0]['detail']['recovered'] == 'carved from unallocated space'
    assert visits[0]['ref'] == 'p0:x1f400-2f400'
    searches = [r for r in records if r['category'] == 'searches']
    assert searches[0]['subject'] == 'secret plans'


# --- into a case ---------------------------------------------------------------------

def test_activity_is_stored_per_image_and_migrates(tmp_path):
    from trace_app.core.activity import record
    from trace_app.core.case import SCHEMA_VERSION, Case
    case = Case.create(str(tmp_path / 'case'), 'Activity')
    try:
        one = case.add_evidence(str(tmp_path / 'one.dd'))
        two = case.add_evidence(str(tmp_path / 'two.dd'))
        when = datetime.datetime(2024, 5, 1, 9, 30, tzinfo=datetime.timezone.utc)
        case.add_user_activity(one, [
            record('programs', 'Prefetch', when, 'Program run',
                   '\\WINDOWS\\NOTEPAD.EXE', {'run count': 3},
                   path='/Windows/Prefetch/N.pf', ref='p0:i5:s1'),
            record('usb', 'setupapi log', datetime.datetime(2024, 4, 1, 8),
                   'USB device first connected', 'Kingston', local=True),
            record('files', 'RecentDocs', None, 'File opened', 'a.txt')])
        case.add_user_activity(two, [record('browser', 'Firefox', when,
                                            'Visited', 'https://x.example/')])
        case.commit()
        assert case.user_activity_summary() == {
            'programs': 1, 'usb': 1, 'files': 1, 'browser': 1}
        assert case.user_activity_summary(two) == {'browser': 1}
        rows = case.user_activity(one)
        assert [r['time_utc'] for r in rows] == [
            '2024-05-01 09:30:00', '2024-04-01 08:00:00', None]
        assert rows[1]['time_local'] == 1
        assert rows[0]['detail'] == {'run count': 3}
        assert rows[0]['artifact_ref'] == 'p0:i5:s1'
        case.set_user_activity_state(one, 'done', records=3)
        assert any(a['action'] == 'user activity done'
                   for a in case.activity(10))
        assert str(case._get('schema_version')) == str(SCHEMA_VERSION)
    finally:
        case.close()


def test_the_analysis_dialog_offers_activity(qapp):
    from trace_app.core.analysis import MODULES
    from trace_app.ui.dialogs.analysis_modules import (
        MODULE_ACTIVITY, AnalysisModulesDialog, default_choice)
    dialog = AnalysisModulesDialog(preselected=default_choice(MODULES),
                                   evidence=[(1, 'a.dd')])
    assert dialog.boxes[MODULE_ACTIVITY].isChecked()
    for key, box in dialog.boxes.items():
        box.setChecked(key == MODULE_ACTIVITY)
    dialog._accept()
    assert dialog.choice['activity'] is True
    assert dialog.choice['modules'] == [] and not dialog.choice['index']
    dialog.deleteLater()


def test_a_real_windows_xp_image_end_to_end():
    """The public NPS domexusers image (4.4 GB): not fetched in CI, so this
    skips without it even there. Read where an examiner would expect."""
    from tests.conftest import IMAGE_DIR
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    path = os.path.join(IMAGE_DIR, 'nps-2009-domexusers.E01')
    if not os.path.exists(path):
        pytest.skip("nps-2009-domexusers.E01 is not in test_images/")
    handler = ImageHandler(path)
    try:
        assert handler.load_image()
        records = collect(handler)
    finally:
        handler.close_resources()
    by = {}
    for item in records:
        by.setdefault(item['category'], []).append(item)
    assert {'programs', 'files', 'recycle', 'logons', 'browser',
            'searches', 'downloads'} <= set(by)
    deleted = [r for r in by['recycle'] if r['user'] == 'domex1']
    assert len(deleted) == 4
    assert any(r['subject'] == 'hotmail thunderbird' for r in by['searches'])
    assert any(r['subject'].endswith('web-mail-1-3-2.xpi')
               for r in by['downloads'])
    assert not any('{0000000C' in r['subject'] for r in by['files'])

"""More Windows evidence: SRUM, WebCache, IE index.dat, Windows Timeline, and
the registry's Run dialog, typed paths, Explorer searches, MountPoints2,
BAM, time zone, networks and installed programs.

plaso's published test data (tools/testdata/samples.py), and where
plaso's own tests record a value for the same file, the value here is that
one. BAM has no sample hive; its value bytes are plaso's test bytes.
"""

import datetime
import os

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
UTC = datetime.timezone.utc


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        message = f"{name} missing -- run python -m tools.testdata.fetch --group samples"
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    with open(path, 'rb') as handle:
        return handle.read()


def hive(name):
    from trace_app.core.activity import registry
    return registry.open_hive(sample(name))


# --- SRUM ----------------------------------------------------------------------

@pytest.fixture(scope='module')
def srum():
    from trace_app.core.activity import ese
    rows = ese.srum(sample('SRUDB.dat'))
    return {(row['table'], row['id']): row for row in rows}, rows


def test_srum_reads_plasos_three_tables_and_the_energy_one(srum):
    by_id, rows = srum
    counts = {}
    for row in rows:
        counts[row['table']] = counts.get(row['table'], 0) + 1
    # plaso: 18,283 = these three; the 2 energy rows are TRACE's extra.
    assert counts['network'] + counts['application'] + \
        counts['connectivity'] == 18283
    assert counts['energy'] == 2


def test_srum_values_match_plaso(srum):
    by_id, _rows = srum
    network = by_id[('network', 3495)]
    assert network['application'] == 'DiagTrack'
    assert network['bytes_sent'] == 2076
    assert network['interface'] == 1689399632855040
    assert network['user'] == 'S-1-5-18'
    assert network['recorded'] == datetime.datetime(2017, 11, 5, 11, 32,
                                                    tzinfo=UTC)
    assert by_id[('application', 22167)]['application'] == \
        'Memory Compression'
    connected = by_id[('connectivity', 501)]
    assert connected['connected_since'] == datetime.datetime(
        2017, 11, 5, 10, 30, 48, 167971, tzinfo=UTC)
    assert connected['recorded'] == datetime.datetime(2017, 11, 5, 13, 33,
                                                      tzinfo=UTC)


# --- WebCache and index.dat -------------------------------------------------------

def test_webcache_entry_matches_plaso():
    from trace_app.core.activity import ese
    rows = ese.webcache(sample('PartitionsEx-WebCacheV01.dat'))
    (entry,) = [r for r in rows if r['container'] == 14 and r['entry'] == 63]
    assert entry['url'] == \
        'https://www.bing.com/rs/3R/kD/ic/878ca0cd/b83d57c0.svg'
    assert entry['filename'] == 'b83d57c0[1].svg'
    assert entry['hits'] == 5 and entry['size'] == 726
    assert entry['modified'] == datetime.datetime(2019, 3, 20, 17, 22, 14,
                                                  tzinfo=UTC)
    assert entry['kind'] == 'cache'


def test_webcache_history_names_the_user():
    from trace_app.core.activity import ese
    visits = [r for r in ese.webcache(sample('WebCacheV01.dat'))
              if r['kind'] == 'visit']
    assert visits and all(r['url'] and r['accessed'] for r in visits)
    libyal = [r for r in visits
              if r['url'] == 'http://code.google.com/p/libyal/']
    assert libyal and libyal[0]['user'] == 'test'


def test_index_dat_matches_plaso():
    from trace_app.core.activity import wintimeline
    cache = wintimeline.index_dat(sample('msiecf-Content.IE5-index.dat'),
                                  'cache')
    assert len(cache) == 35
    favicon = cache[2]
    assert favicon['url'] == 'http://www.bing.com/favicon.ico'
    assert favicon['when'] == datetime.datetime(2015, 8, 25, 11, 5, 37,
                                                137000, tzinfo=UTC)
    assert favicon['second'] == datetime.datetime(2013, 10, 19, 1, 8, 6,
                                                  tzinfo=UTC)
    assert favicon['hits'] == 3 and favicon['size'] == 1150
    history = wintimeline.index_dat(sample('msiecf-History.IE5-index.dat'),
                                    'history')
    first = history[0]
    assert (first['user'], first['url']) == ('gold_administrator',
                                            'http://www.msn.com/?ocid=iehp')
    assert first['when'] == datetime.datetime(2015, 8, 25, 11, 5, 18, 512000,
                                              tzinfo=UTC)


# --- Windows Timeline ----------------------------------------------------------------

def test_windows_timeline_matches_plaso():
    from trace_app.core.activity import wintimeline
    items = wintimeline.activities(sample('windows-ActivitiesCache.db'))
    assert len(items) == 112
    engaged = [i for i in items if i['kind'] == 'in use' and
               i['application'].lower() == 'c:\\python34\\python.exe' and
               i['started'] == datetime.datetime(2018, 8, 3, 11, 29,
                                                 tzinfo=UTC)]
    assert engaged and engaged[0]['active_seconds'] == 9
    onedrive = [i for i in items if i['application'] ==
                'Microsoft.SkyDrive.Desktop' and i['started'] ==
                datetime.datetime(2018, 7, 25, 12, 4, 48, tzinfo=UTC)]
    assert onedrive and onedrive[0]['display'] == 'OneDrive'


# --- the registry --------------------------------------------------------------------

def test_user_hive_run_typed_searches_mounts():
    from trace_app.core.activity import registry
    win7 = hive('NTUSER-WIN7.DAT')
    assert registry.typed_paths(win7)[0]['path'] == '\\\\controller'
    (run,) = registry.run_mru(win7)
    assert run['command'] == '\\\\controller\\WebDavShare'
    assert run['typed'] == datetime.datetime(2010, 11, 10, 7, 59, 46, 499125,
                                             tzinfo=UTC)
    assert [q['query'] for q in registry.word_wheel_query(win7)] == \
        ['rar.exe', 'hyth']
    shares = {m['label'] for m in registry.mount_points(win7)
              if m['kind'] == 'Network share'}
    assert '\\\\controller\\home\\nfury' in shares
    win10 = registry.mount_points(hive('NTUSER-WIN10.DAT'))
    first = next(m for m in win10 if m['name'] ==
                 '{8bff1c84-9188-11e5-824f-806e6f6e6963}')
    # plaso: last written 2016-10-09T19:57:35.4892903
    assert first['mounted'] == datetime.datetime(2016, 10, 9, 19, 57, 35,
                                                 489290, tzinfo=UTC)
    assert first['kind'] == 'Volume'


def test_bam_value_matches_plaso():
    from trace_app.core.activity import registry
    data = bytes([0x15, 0x3E, 0xAE, 0x36, 0x57, 0xDE, 0xD4, 0x01]) + \
        bytes(8) + bytes([0, 0, 0, 0, 2, 0, 0, 0])
    assert registry.parse_bam_value(data) == datetime.datetime(
        2019, 3, 19, 13, 25, 26, 149685, tzinfo=UTC)


def test_system_time_zone_matches_plaso():
    from trace_app.core.activity import registry
    zone = registry.time_zone(hive('SYSTEM-WIN7'))
    assert zone['bias_minutes'] == 300 and zone['active_bias'] == 240
    assert zone['daylight_name'] == '@tzres.dll,-111'
    assert zone['name'] == 'Eastern Standard Time'


def test_software_networks_programs_install():
    from trace_app.core.activity import registry
    software = hive('SOFTWARE')
    networks = {n['name']: n for n in registry.network_profiles(software)}
    shieldbase = networks['shieldbase.local']
    assert shieldbase['type'] == 'Wired'
    assert shieldbase['gateway_mac'] == '00:18:f8:ea:2e:a2'
    # SYSTEMTIME is local wall-clock: naive, never labelled UTC.
    assert shieldbase['created'] == datetime.datetime(2010, 11, 10, 11, 23,
                                                      43, 671000)
    assert shieldbase['created'].tzinfo is None
    programs = {p['name'] for p in registry.installed_programs(software)}
    assert 'Adobe AIR' in programs and len(programs) == 21
    install = registry.windows_install(software)
    assert install['product'] == 'Windows 7 Ultimate'
    assert install['installed'] == datetime.datetime(2010, 11, 10, 16, 28,
                                                     55, tzinfo=UTC)


def test_new_categories_are_listed():
    from trace_app.core.activity import CATEGORIES
    from trace_app.ui import icons
    keys = [key for key, _label in CATEGORIES]
    for key in ('network', 'usage', 'system'):
        assert key in keys and key in icons.ACTIVITY_CATEGORIES

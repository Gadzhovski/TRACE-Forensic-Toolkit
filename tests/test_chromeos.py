"""ChromeOS (core/activity/chromeos.py, os_identity, evidence_profile,
mobile.android_base's ARC++ root).

No public Chromebook image was found, so every file is written here as
ChromeOS writes it: lsb-release / os-release as on ROOT-A, the stateful
partition's layout (home/.shadow/<SHA-1(salt + user)>, encrypted.block,
Local State, the VPD cache, the firmware event log), and a decrypted
user folder. plaso's syslog_chromeos is read as the ChromeOS syslog it is.
"""

import datetime
import hashlib
import json
import os

from tests.conftest import data_path
from trace_app.core.activity import chromeos, linux

UTC = datetime.timezone.utc
SALT = bytes(range(16))
JANE = 'jane.doe@gmail.com'
OMAR = 'omar@school.example'


def _hash(user):
    return hashlib.sha1(SALT + user.encode()).hexdigest()


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


def _records(root):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(root)
    try:
        assert handler.loaded
        return collect(handler)
    finally:
        handler.close_resources()


LSB = """CHROMEOS_AUSERVER=https://tools.google.com/service/update2
CHROMEOS_RELEASE_BOARD=octopus-signed-mp-v23keys
CHROMEOS_RELEASE_CHROME_MILESTONE=108
CHROMEOS_RELEASE_NAME=Chrome OS
CHROMEOS_RELEASE_TRACK=stable-channel
CHROMEOS_RELEASE_VERSION=15183.69.0
GOOGLE_RELEASE=15183.69.0
"""
OS_RELEASE = """BUILD_ID=15183.69.0
GOOGLE_CRASH_ID=ChromeOS
HOME_URL=https://www.chromium.org/chromium-os
ID=chromeos
NAME=Chrome OS
VERSION=108
VERSION_ID=108
"""
LOCAL_STATE = {
    'LoggedInUsers': [JANE, OMAR],
    'LastActiveUser': JANE,
    'UserDisplayName': {JANE: 'Jane Doe', OMAR: 'Omar'},
    'KnownUsers': [
        {'email': JANE, 'gaia_id': '1001', 'account_type': 'google',
         'last_online_signin': '13345678901234567'},
        {'email': OMAR, 'gaia_id': '1002', 'account_type': 'google',
         'using_saml': True}]}
VPD = '\n'.join(f'"{k}"="{v}"' for k, v in (
    ('serial_number', '5CD1234XYZ'), ('model_name', 'HP Chromebook 14'),
    ('region', 'us'), ('ActivateDate', '2022-31'),
    ('initial_timezone', 'America/Los_Angeles'),
    ('gbind_attribute', '=CikKIAAA'))) + '\n'
EVENTS = """0 | 2024-03-01 08:00:01 | Log area cleared | 4088
1 | 2024-03-01 08:00:02 | System boot | 2211
2 | 2024-03-01 08:00:02 | Chrome OS Developer Mode
3 | 2024-03-02 17:45:10 | ACPI Enter | S3
"""
MESSAGES = (
    "2024-03-01T08:01:12.123456Z INFO kernel: [    5.100000] usb 1-1: New "
    "USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00\n"
    "2024-03-01T08:01:12.123999Z INFO kernel: [    5.100100] usb 1-1: "
    "Product: Ultra\n")


def test_names_and_folders():
    assert chromeos.canonical('Jane.Doe@GoogleMail.com') == \
        'janedoe@gmail.com'
    assert chromeos.canonical('First.Last@School.Example') == \
        'first.last@school.example'
    assert chromeos.sanitized(SALT, 'janedoe@gmail.com') == \
        _hash('janedoe@gmail.com')


def test_chromeos_is_its_own_system():
    from trace_app.core import os_identity
    found = os_identity._lsb_release(LSB)
    assert found['family'] == 'chromeos' and found['logo'] == 'chromeos'
    assert found['name'] == 'Chrome OS 108'
    assert 'board octopus-signed-mp-v23keys' in found['detail']
    assert os_identity._os_release(OS_RELEASE)['family'] == 'chromeos'
    assert os_identity.from_os_info(
        {'Operating System': 'Chrome OS 108'})['family'] == 'chromeos'
    assert os_identity.from_os_info(
        {'Operating System': 'ChromeOS Flex 120'})['family'] == 'chromeos'
    assert os_identity._lsb_release('DISTRIB_ID=Ubuntu\n') is None
    assert 'chromeos' in os_identity.LOGOS
    from trace_app.ui import icons
    assert 'chromeos' in icons.OS_LOGOS
    assert os.path.isfile(os.path.join(os.path.dirname(icons.__file__),
                                       '..', '..', 'Icons', 'os',
                                       'chromeos.svg'))


def _stateful(tmp_path):
    root = str(tmp_path / 'stateful')
    when = datetime.datetime(2024, 3, 3, tzinfo=UTC).timestamp()
    _write(root, 'encrypted.block', b'\x00' * 4096, when)
    _write(root, 'home/.shadow/salt', SALT)
    jane = _hash(chromeos.canonical(JANE))
    _write(root, f'home/.shadow/{jane}/vault/user/ECRYPTFS_FNEK_X', b'x')
    _write(root, f'home/.shadow/{jane}/master.0', b'k', when)
    omar = _hash(OMAR)
    _write(root, f'home/.shadow/{omar}/mount/x', b'x')
    _write(root, f'home/.shadow/{omar}/auth_factors/password.gaia', b'k')
    _write(root, f"home/.shadow/{'f' * 40}/mount/x", b'x')
    _write(root, 'home/chronos/Local State', json.dumps(LOCAL_STATE))
    _write(root, 'var/cache/vpd/full-v2.txt', VPD)
    _write(root, 'var/log/eventlog.txt', EVENTS)
    _write(root, 'var/log/messages', MESSAGES)
    return root, jane, omar


def test_the_stateful_partition(tmp_path):
    root, jane, omar = _stateful(tmp_path)
    rows = _records(root)
    by = {}
    for row in rows:
        by.setdefault(row['what'], []).append(row)
    accounts = {r['subject']: r for r in by['ChromeOS account']}
    assert set(accounts) == {JANE, OMAR}
    assert accounts[JANE]['detail']['encrypted home'] == jane
    assert accounts[JANE]['detail']['last active'] == 'yes'
    assert accounts[JANE]['time'] == (
        datetime.datetime(1601, 1, 1, tzinfo=UTC) + datetime.timedelta(
            microseconds=13345678901234567)).strftime('%Y-%m-%d %H:%M:%S')
    assert accounts[OMAR]['detail']['SAML sign-in'] == 'yes'
    homes = {r['detail']['folder']: r for r in by['Encrypted user home']}
    assert homes[jane]['subject'] == JANE
    assert homes[jane]['detail']['encryption'] == 'eCryptfs (vault)'
    assert homes[jane]['detail']['key sets'] == 'master.0'
    assert homes[omar]['subject'] == OMAR
    assert homes[omar]['detail']['encryption'] == 'fscrypt (mount)'
    assert homes['f' * 40]['detail']['owner'].startswith('not named')
    assert by['Encrypted system data'][0]['detail']['readable'].startswith(
        'no')
    assert by['Serial number'][0]['subject'] == '5CD1234XYZ'
    assert by['Activated (year-week)'][0]['subject'] == '2022-31'
    assert by['Model'][0]['subject'] == 'HP Chromebook 14'
    boots = by['System boot']
    assert boots[0]['time'] == '2024-03-01 08:00:02' and boots[0]['local']
    assert by['Chrome OS Developer Mode'][0]['detail']['grade'] == 'notable'
    assert by['Log area cleared'][0]['detail']['grade'] == 'notable'
    usb = [r for r in rows if r['category'] == 'usb']
    assert usb and usb[0]['time'] == '2024-03-01 08:01:12'
    assert 'INFO' not in json.dumps([r['detail'] for r in usb])


def test_plaso_chromeos_syslog_reads_as_iso_with_levels():
    with open(data_path('samples', 'plaso-syslog_chromeos'),
              encoding='utf-8') as handle:
        text = handle.read()
    # Nothing in it is what an examiner reads a syslog for (no logons,
    # sudo or USB): read without error, nothing invented.
    assert linux.syslog_activity(text, 'p', 'r', 2016) == []
    line = ("2016-10-25T12:37:23.297265-07:00 INFO sudo[13707]:   chronos : "
            "TTY=pts/0 ; PWD=/home/chronos ; USER=root ; COMMAND=/bin/ls\n")
    [row] = linux.syslog_activity(line, 'p', 'r', 2016)
    assert row['time'] == '2016-10-25 19:37:23'
    assert row['subject'] == '/bin/ls' and not row['local']


def test_a_decrypted_user_and_its_android_apps(tmp_path):
    root = str(tmp_path / 'extraction')
    when = datetime.datetime(2024, 3, 4, tzinfo=UTC).timestamp()
    _write(root, 'etc/lsb-release', LSB)
    _write(root, 'home/.shadow/salt', SALT)
    _write(root, 'home/chronos/Local State', json.dumps(LOCAL_STATE))
    jane = _hash(chromeos.canonical(JANE))
    user = f'home/chronos/u-{jane}/'
    with open(data_path('samples', 'plaso-chrome-Preferences'), 'rb') as f:
        _write(root, user + 'Preferences', f.read())
    _write(root, user + '.crosh_history', 'shell\nvmc list\n', when)
    _write(root, user + 'Custom Dictionary.txt',
           'Zarathustra\nkrypto\nchecksum_v1 = 0123abcd\n')
    _write(root, user + 'crosvm/dGVybWluYQ==.img', b'\0' * 8192, when)
    arc = f'home/root/{jane}/android-data/data/'
    _write(root, arc + 'system/packages.xml', '<packages/>')
    _write(root, arc + 'data/com.example.app/shared_prefs/x.xml', '<map/>')
    rows = _records(root)
    by = {}
    for row in rows:
        by.setdefault(row['what'], []).append(row)
    crosh = [r for r in by['Command typed'] if r['source'] == 'crosh history']
    assert [r['subject'] for r in crosh] == ['shell', 'vmc list']
    assert crosh[0]['user'] == JANE
    assert [r['subject'] for r in by['Word added to the dictionary']] == \
        ['Zarathustra', 'krypto']
    [disk] = by['Linux (Crostini) VM disk']
    assert disk['detail']['size'] == 8192
    # Its Chrome profile is the user folder itself.
    extensions = by['Browser extension installed']
    assert extensions and extensions[0]['source'] == \
        'Chrome (ChromeOS) extensions'
    assert extensions[0]['user'] == JANE

    from trace_app.core import evidence_profile, os_identity
    from trace_app.core.activity import Volume, mobile
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(root)
    try:
        [volume] = Volume.all(handler, 0)
        assert mobile.android_base(volume) == (
            'home', 'root', jane, 'android-data', 'data')
        assert os_identity.identify(handler, 0)['family'] == 'chromeos'
        found = evidence_profile.profile(handler)
        assert 'ChromeOS' in found['systems']
        assert {'chromeos', 'android'} <= set(found['tool_systems'])
    finally:
        handler.close_resources()


def test_evidence_information_names_the_chromebook(tmp_path):
    from trace_app.core import evidence_overview
    from trace_app.core.image_handler import ImageHandler
    root, _jane, _omar = _stateful(tmp_path)
    handler = ImageHandler(root)
    try:
        facts = evidence_overview.device_facts(handler)
    finally:
        handler.close_resources()
    assert facts['Device'] == 'Chromebook'
    assert facts['Serial number'] == '5CD1234XYZ'
    assert facts['Initial time zone'] == 'America/Los_Angeles'

"""Microsoft Defender in Activity (trace_app/core/activity/defender.py).

Real artifacts: an APT-simulator VM's Defender folder (DFIRArtifactMuseum)
-- its MPLog and DetectionHistory, which must agree with each other on
the same detections -- and quarantine entries with a quarantined file from
dissect.target's tests, checked against the values those tests expect
(threat, path, size, IDs, the file's content and its Zone.Identifier). Then
a collection holding them: Activity lists every detection and quarantined
file, and the quarantined file opens as members, decrypted in memory.
"""

import os
import shutil
import zipfile

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
MIMIKATZ_ENTRY = 'defender-entry-{800362A7-0000-0000-FB11-12639186E0D6}'
MIMIKATZ_CONTENT = 'defender-resource-A6C8322B8A19AEED96EFBD045206966DA4C9619D'


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def read(name):
    with open(sample(name), 'rb') as handle:
        return handle.read()


def test_quarantine_entries_as_dissect_expects():
    from trace_app.core.activity import defender
    entry = defender.quarantine_entry(read(MIMIKATZ_ENTRY))
    assert entry['threat'] == 'HackTool:Win64/Mikatz!dha'
    assert entry['quarantine_id'] == 'a762038000000000fb1112639186e0d6'
    assert entry['scan_id'] == 'cdbe4600e43a964b8dc2416b0ef7a207'
    assert entry['threat_id'] == 2147705511
    assert entry['time'].date().isoformat() == '2022-12-02'
    (resource,) = entry['resources']
    assert resource['kind'] == 'file'
    assert resource['path'] == 'C:\\Users\\user\\Downloads\\mimikatz\\mimilib.dll'
    assert resource['size'] == 37376
    assert resource['resource_id'] == \
        'A6C8322B8A19AEED96EFBD045206966DA4C9619D'
    assert all(resource[k].date().isoformat() == '2022-12-02'
               for k in ('created', 'written', 'accessed'))

    ie = defender.quarantine_entry(read(
        'defender-entry-{8006A512-0000-0000-2E01-A7D5DA185F14}'))
    assert [r['kind'] for r in ie['resources']] == ['file', 'startup']
    assert ie['resources'][0]['size'] == 1784

    kms = defender.quarantine_entry(read(
        'defender-entry-{8006A512-0000-0000-2E11-A7D5DA185F24}'))
    assert sorted(r['kind'] for r in kms['resources']) == [
        'file', 'file', 'regkey', 'regkey', 'taskscheduler']
    assert kms['threat'] == 'HackTool:Win32/AutoKMS'
    files = {r['path']: r for r in kms['resources'] if r['kind'] == 'file'}
    assert files['C:\\WINDOWS\\System32\\Tasks\\KMSAuto']['resource_id'] == \
        'FCC63B61E24395BA6AA3E40EA16E3D2DD24A2916'
    assert files['C:\\Windows\\KMSAutoS\\KMSAuto x64.exe']['size'] == 1711464


def test_quarantined_content_decrypts_to_its_streams():
    from trace_app.core import archives
    data = read(MIMIKATZ_CONTENT)
    assert archives.detect_archive(data) == 'defender'
    names = [m['name'] for m in archives.list_members(data)]
    assert names == ['security descriptor', 'quarantined file',
                     'stream Zone.Identifier']
    # dissect.target's test data replaced mimikatz with this.
    assert archives.read_member(data, 'quarantined file') == b'DUMMY_PAYLOAD'
    assert archives.read_member(data, 'stream Zone.Identifier') == (
        b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\user\\"
        b"Downloads\\mimikatz_trunk.zip\r\n")
    # Owner SID of the security descriptor, as dissect expects it.
    descriptor = archives.read_member(data, 'security descriptor')
    assert descriptor[:2] == b'\x01\x00'
    # Random data is not taken for it.
    assert archives.detect_archive(os.urandom(4096)) != 'defender'


def test_mplog_and_detection_history_agree():
    """The same VM's two records of its detections: every file detection
    in DetectionHistory is in the MPLog, at the same second, and the SHA-1
    DetectionHistory keeps is the one MPLog's threat action names."""
    from trace_app.core.activity import defender
    with zipfile.ZipFile(sample('defender-APTSimulatorVM.zip')) as archive:
        mplog = defender.decode_log(archive.read(
            'Support/MPLog-20220310-113238.log'))
        history = [defender.detection_history(archive.read(n))
                   for n in archive.namelist()
                   if 'DetectionHistory/' in n and not n.endswith('/')]
    events = defender.mplog_events(mplog)
    detections = [e for e in events if e['kind'] == 'detection']
    actions = [e for e in events if e['kind'] == 'action']
    assert len(history) == 14 and all(history)
    assert {e['threat'] for e in detections} >= {
        'Trojan:BAT/Vigorf.A', 'HackTool:Win32/DumpLsass.E',
        'Backdoor:PowerShell/Powercat.A', 'Trojan:Win32/Ceprolad.A',
        'SettingsModifier:Win32/PossibleHostsFileHijack'}
    procdump = next(e for e in detections
                    if e['threat'] == 'HackTool:Win32/DumpLsass.E')
    assert procdump['resource_kind'] == 'CmdLine'
    assert 'procdump64.exe -accepteula -ma lsass.exe' in procdump['resource']
    logged = {(e['time'][:19], e['resource']) for e in detections}
    # A detection of one file is in the MPLog at the same second. (One that
    # gathered two files under a threat keeps a later start time.)
    files = [(h['time'].strftime('%Y-%m-%dT%H:%M:%S'), h['resources'][0][1])
             for h in history
             if [k for k, _p in h['resources']] == ['file']]
    assert len(files) == 8 and all(item in logged for item in files)
    by_path = {a['path']: a['sha1'].lower() for a in actions if a['sha1']}
    for entry in history:
        sha1 = entry['tracking'].get('Sha1')
        for kind, path in entry['resources']:
            if kind == 'file' and sha1 and path in by_path:
                assert by_path[path] == sha1
    powercat = next(h for h in history
                    if h['threat'] == 'Backdoor:PowerShell/Powercat.A')
    assert powercat['user'] == 'DESKTOP-TMKU40H\\TestUser'
    assert powercat['process'].endswith('\\powershell.exe')
    assert powercat['tracking']['Size'] == 37640


def test_a_collection_s_defender_folder_reaches_activity(tmp_path):
    from trace_app.core import archives
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'collection' / 'C'
    defender_dir = root / 'ProgramData' / 'Microsoft' / 'Windows Defender'
    with zipfile.ZipFile(sample('defender-APTSimulatorVM.zip')) as archive:
        archive.extractall(defender_dir)
    entries = defender_dir / 'Quarantine' / 'Entries'
    entries.mkdir(parents=True)
    shutil.copyfile(sample(MIMIKATZ_ENTRY),
                    entries / MIMIKATZ_ENTRY[len('defender-entry-'):])
    content = defender_dir / 'Quarantine' / 'ResourceData' / 'A6'
    content.mkdir(parents=True)
    shutil.copyfile(sample(MIMIKATZ_CONTENT),
                    content / MIMIKATZ_CONTENT[len('defender-resource-'):])
    logs = root / 'Windows' / 'System32' / 'winevt' / 'Logs'
    logs.mkdir(parents=True)
    shutil.copyfile(sample('defender-Operational.evtx'),
                    logs / 'Microsoft-Windows-Windows Defender%4Operational'
                           '.evtx')
    handler = ImageHandler(str(tmp_path / 'collection'))
    try:
        records = [r for r in collect(handler)
                   if r['category'] == 'antivirus']
        by_source = {}
        for item in records:
            by_source.setdefault(item['source'], []).append(item)
        assert len(by_source['Defender detection history']) == 14
        quarantined = by_source['Defender quarantine']
        assert quarantined[0]['subject'].endswith('mimilib.dll')
        assert quarantined[0]['detail']['threat'] == \
            'HackTool:Win64/Mikatz!dha'
        mplog = by_source['Defender log (MPLog)']
        assert any(r['what'] == 'Threat action: quarantine' for r in mplog)
        # The Windows 11 log records no detection, only Defender's own
        # settings churn and one history deletion -- and that is all.
        events = by_source.get(
            'Event log (Microsoft-Windows-Windows Defender%4Operational)', [])
        assert [e['what'] for e in events] == ['History deleted']
        fs = handler.get_fs_info(0)
        node = fs.lookup('/C/ProgramData/Microsoft/Windows Defender/'
                         'Quarantine/ResourceData/A6/'
                         'A6C8322B8A19AEED96EFBD045206966DA4C9619D')
        data = node.reader(0, node.size)
        assert archives.read_member(data, 'quarantined file') == \
            b'DUMMY_PAYLOAD'
    finally:
        handler.close_resources()

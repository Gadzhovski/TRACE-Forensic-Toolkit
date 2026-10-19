"""GrayKey's extraction report as an acquisition log, and the iOS version
of an extraction that holds /private alone.

Generated: a zip named as GrayKey names it, a report PDF laid out as
GrayKey's (label on one line, value on the next; a Keychain block with
hashes of its own; a passcode and an event log repeating it), written with
PyMuPDF. Local: the Magnet 2022 iPhone 8 extraction and its real report.
"""

import hashlib
import plistlib
import zipfile

import pytest

from tests.conftest import data_path, image_path

UDID = 'fb028ddefa8af7df5b12d3e729f075d150637a31'
SECRET = '804613'               # the generated report's passcode
IOS15 = UDID + '_files_full.zip'


def _zip(path, members):
    with zipfile.ZipFile(path, 'w') as package:
        for name, data in members.items():
            package.writestr(name, data)
    data = open(path, 'rb').read()
    return {'size': len(data), 'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()}


def _report(path, extraction, udid=UDID, keychain=None):
    """A GrayKey-shaped report: what PyMuPDF reads back line by line."""
    import pymupdf
    keychain = keychain or {'md5': 'a' * 32, 'sha256': 'b' * 64}
    lines = [
        'GrayKey Progress Report', 'GrayKey Serial #: 82c21ff2d481090d',
        'GrayKey Software: OS Version: 1.7.3, App Bundle: 2.2.2',
        'Report generation time: 2022-02-14 18:37:46 UTC',
        'Target Device Information',
        'Device Name', 'iPhone 8', 'Software Version', '15.0.2 [19A404]',
        'Model', 'iPhone 8 (Global) [iPhone10,1 D20AP]',
        'Unique Device ID (UDID)', udid, 'Serial Number', 'FFMC855HJC6C',
        'Phone Number', '19732941683', 'IMEI', '353219108442509',
        'Lock State', 'Before First Unlock',
        'Owner Name', 'Patrick Bentley',
        'Accounts', 'one@example.com', 'two@example.com',
        'Passcode (or unlock mechanism)', SECRET,
        'Unlock Notes', f'tried {SECRET} first',
        'Event Log',
        '2022-02-14 18:26:34 UTC: Passcode bruteforce started.',
        f'2022-02-14 18:27:28 UTC: Passcode found: {SECRET}',
        'Extraction Result Summary',
        'Full Filesystem', '2022-02-14 18:36:27.877000 UTC',
        'Extraction size',
        f"0.00GB ({extraction['size']} bytes)",
        'SHA256', extraction['sha256'], 'MD5', extraction['md5'],
        'Keychain', '30 Keys, 6 Certificates',
        'SHA256', keychain['sha256'], 'MD5', keychain['md5'],
    ]
    document = pymupdf.open()
    page = document.new_page()
    y = 40
    for line in lines:
        if y > 800:
            page = document.new_page()
            y = 40
        page.insert_text((40, y), line, fontsize=9)
        y += 14
    document.save(str(path))
    document.close()


def _everything(value):
    return repr(value)


def test_the_report_gives_the_extraction_s_hashes_and_device(tmp_path):
    from trace_app.core import acquisition_log, graykey
    evidence = tmp_path / IOS15
    made = _zip(evidence, {'private/var/mobile/x.txt': b'hello'})
    # Filed apart, as the Magnet download keeps it: a subfolder.
    (tmp_path / 'report').mkdir()
    _report(tmp_path / 'report' / (UDID + '.pdf'), made)

    hashes, log = acquisition_log.logged_hashes(str(evidence))
    assert hashes == {'md5': made['md5'], 'sha256': made['sha256']}
    assert log.endswith(UDID + '.pdf')

    device = graykey.device_facts(str(evidence))
    assert device['iOS version'] == '15.0.2 [19A404]'
    assert device['Model'] == 'iPhone 8 (Global) [iPhone10,1 D20AP]'
    assert device['Serial number'] == 'FFMC855HJC6C'
    assert device['IMEI'] == '353219108442509'
    assert device['Phone number'] == '19732941683'
    assert device['Owner'] == 'Patrick Bentley'
    assert device['Accounts'] == 'one@example.com, two@example.com'
    assert device['UDID'] == UDID

    facts = graykey.acquisition_facts(str(evidence))
    assert facts['Acquired'] == '2022-02-14 18:36:27.877000 UTC'
    assert facts['Stored SHA-256'] == made['sha256']
    assert facts['Description'].startswith('GrayKey Full Filesystem')

    # The passcode, and the event log repeating it, are nowhere.
    report = graykey.read_report(str(tmp_path / 'report' / (UDID + '.pdf')))
    for value in (report, device, facts):
        assert SECRET not in _everything(value)


def test_only_the_evidence_s_own_extraction_and_device_count(tmp_path):
    from trace_app.core import graykey
    evidence = tmp_path / IOS15
    made = _zip(evidence, {'a.txt': b'a'})
    # Another extraction's size: the device is named, no hash is taken --
    # least of all the Keychain's.
    _report(tmp_path / (UDID + '.pdf'), dict(made, size=made['size'] + 1),
            keychain={'md5': made['md5'], 'sha256': made['sha256']})
    assert graykey.logged_hashes(str(evidence)) == ({}, None)
    assert graykey.device_facts(str(evidence))['UDID'] == UDID
    assert 'Stored MD5' not in graykey.acquisition_facts(str(evidence))

    # A report about another phone is not this evidence's.
    other = 'e' * 40
    _report(tmp_path / (UDID + '.pdf'), made, udid=other)
    assert graykey.for_evidence(str(evidence)) == (None, None, None)

    # A name that is no UDID is never looked for.
    plain = tmp_path / 'phone.zip'
    _zip(plain, {'a.txt': b'a'})
    assert graykey.candidates(str(plain)) == []


def test_a_case_verifies_the_zip_against_the_report(tmp_path):
    from trace_app.core.case import STATUS_VERIFIED, Case
    evidence = tmp_path / IOS15
    made = _zip(evidence, {'private/var/mobile/x.txt': b'hello'})
    case = Case.create(str(tmp_path / 'Case'), 'GrayKey')
    try:
        # Added before the report is beside it: its next check finds it,
        # records it (audited) and verifies against it.
        case.add_evidence(str(evidence))
        assert not case.evidence()[0]['stored_sha256']
        _report(tmp_path / (UDID + '.pdf'), made)
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_VERIFIED, outcome
        row = case.evidence()[0]
        assert row['stored_sha256'] == made['sha256']
        assert row['stored_source'] == f'acquisition log {UDID}.pdf'
        assert any(line['action'] == 'acquisition hashes set'
                   for line in case.activity(10))
    finally:
        case.close()

    # Added with the report there: recorded at once.
    case = Case.create(str(tmp_path / 'Case2'), 'GrayKey')
    try:
        case.add_evidence(str(evidence))
        row = case.evidence()[0]
        assert (row['stored_md5'], row['stored_sha256']) == \
            (made['md5'], made['sha256'])
    finally:
        case.close()


def test_the_intake_fills_custody_from_the_report(tmp_path):
    from trace_app.core import evidence_probe
    evidence = tmp_path / IOS15
    made = _zip(evidence, {'private/var/mobile/x.txt': b'hello'})
    _report(tmp_path / (UDID + '.pdf'), made)
    result = evidence_probe.probe(str(evidence))
    assert result['custody']['acquired_on'] == \
        '2022-02-14 18:36:27.877000 UTC'
    assert result['custody']['description'].startswith('GrayKey')
    assert result['stored_hashes']
    assert SECRET not in repr(result)


def _gestalt():
    return plistlib.dumps({'CacheVersion': '19A404', 'CacheExtra': {
        'qNNddlUK+B/YlooNoymwgA': '15.0.2',
        'mZfUC7qo4pURNhyMHZ62RQ': '19A404',
        'ivIu8YTDnBSrYv/SN4G8Ag': 'iPhone OS',
        'Z/dqyWS6OZTRy10UcmUAhw': 'iPhone 8',
        'h9jDsbgj7xIVeIQ8S3/X3Q': 'iPhone10,1'}},
        fmt=plistlib.FMT_BINARY)


@pytest.mark.parametrize('marker', ['gestalt', 'lastbuild'])
def test_an_extraction_of_private_alone_names_its_ios(tmp_path, marker):
    from trace_app.core import os_identity
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'extraction'
    if marker == 'gestalt':
        where = root / ('private/var/containers/Shared/SystemGroup/'
                        'systemgroup.com.apple.mobilegestaltcache/Library/'
                        'Caches/com.apple.MobileGestalt.plist')
        data = _gestalt()
    else:
        where = root / ('private/var/installd/Library/MobileInstallation/'
                        'LastBuildInfo.plist')
        data = plistlib.dumps({'ProductName': 'iPhone OS',
                               'ProductVersion': '15.0.2',
                               'ProductBuildVersion': '19A404'})
    where.parent.mkdir(parents=True)
    where.write_bytes(data)
    (root / 'private/var/mobile/Library').mkdir(parents=True)
    handler = ImageHandler(str(root))
    try:
        found = os_identity.identify(handler, 0)
    finally:
        handler.close_resources()
    assert found['family'] == 'ios' and found['logo'] == 'apple'
    assert found['name'] == 'iOS 15.0.2'
    assert 'build 19A404' in found['detail']


# --- the Magnet 2022 iPhone 8 (local) --------------------------------------------

def test_magnet_ios15_report_and_version():
    from trace_app.core import acquisition_log, graykey, os_identity
    from trace_app.core.image_handler import ImageHandler
    path = image_path(IOS15)
    report = data_path('local', 'magnet-2022-ios15', UDID + '.pdf')
    # The passcode as the report writes it (never printed): the line
    # after its label.
    lines = graykey.report_lines(report)
    secret = lines[next(i for i, line in enumerate(lines)
                        if line.lower().startswith('passcode')) + 1]
    assert secret
    hashes, log = acquisition_log.logged_hashes(path)
    # GrayKey's own record; the catalog pins the download by the same.
    assert hashes['sha256'] == ('a6d180aff36c9b37ec9a3819f3d98af46efc9c47'
                                'b36a8a7b58cde791049b38c2')
    assert hashes['md5'] == '448db62270f86a773788f5d07b899f6f'
    device = graykey.device_facts(path)
    assert device['iOS version'] == '15.0.2 [19A404]'
    assert device['Serial number'] == 'FFMC855HJC6C'
    # The passcode is never read: no unknown label's value is in the facts.
    assert not any('passcode' in k.lower() for k in device)
    handler = ImageHandler(path)
    try:
        found = os_identity.identify(handler, 0)
        assert found['name'] == 'iOS 15.0.2'
        info = handler.get_acquisition_info()
        assert info['Stored MD5'] == '448db62270f86a773788f5d07b899f6f'
        assert secret not in repr((graykey.read_report(report), info))
    finally:
        handler.close_resources()

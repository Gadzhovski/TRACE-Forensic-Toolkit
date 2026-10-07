"""Executables read from their headers (trace_app/core/executables.py).

Real published binaries: PuTTY's Pageant (x64 and x86, Authenticode-
signed), SQLite's DLL, BusyBox (static ELF), bat (dynamic ELF) and ripgrep
for macOS (x86-64 unsigned, arm64 ad hoc signed). The expected values were
read from the same files by pefile and pyelftools (neither is a
dependency) -- imports, exports, sections and their entropy, version
strings and checksums agreed in full. Indicators are checked on copies
with one thing changed, and the analysis module end to end through
content_checks.
"""

import io
import os
import struct
import tarfile

import pytest

from tests.conftest import ROOT

CARVE = os.path.join(ROOT, 'test_images', 'carve_samples')
ARTIFACTS = os.path.join(ROOT, 'test_images', 'artifact_samples')


def sample(folder, name, member=None):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/carve_corpus.py and "
                    "tools/fetch_artifact_samples.py")
    if member is None:
        with open(path, 'rb') as handle:
            return handle.read()
    with tarfile.open(path) as archive:
        return archive.extractfile(member).read()


@pytest.fixture(scope='module')
def pageant():
    return sample(CARVE, 'pageant.exe')


def test_a_signed_windows_program(pageant):
    from trace_app.core import executables
    facts = executables.analyse(pageant)
    assert facts['format'] == 'PE32+' and facts['architecture'] == 'x64'
    assert facts['kind'] == 'program'
    assert facts['subsystem'] == 'Windows GUI'
    assert facts['compiled'] == '2025-02-01 11:27:28'      # 1738409248
    assert [i['library'] for i in facts['imports']] == [
        'ADVAPI32.dll', 'GDI32.dll', 'SHELL32.dll', 'USER32.dll',
        'KERNEL32.dll', 'COMDLG32.dll']
    assert sum(len(i['functions']) for i in facts['imports']) == 201
    assert [s['name'] for s in facts['sections']] == [
        '.text', '.rdata', '.data', '.pdata', '.00cfg', '.gxfg', '_RDATA',
        '.rsrc', '.reloc']
    assert facts['sections'][0]['flags'] == 'r-x'
    assert facts['sections'][0]['entropy'] == 6.474
    assert facts['version']['CompanyName'] == 'Simon Tatham'
    assert facts['version']['OriginalFilename'] == 'Pageant'
    assert facts['version']['file_version_fixed'] == '0.83.0.0'
    signature = facts['signature']
    assert signature['type'] == 'Authenticode (PKCS #7)'
    assert signature['signer'] == 'Simon Tatham'
    assert signature['issuer'] == 'Sectigo Public Code Signing CA R36'
    assert (signature['valid_from'], signature['valid_to']) == (
        '2024-09-27 00:00:00', '2027-09-27 23:59:59')
    # The signature is where PE puts it, at the end: nothing appended.
    assert 'overlay' not in facts
    assert facts['checksum'] == {'stored': '0x000ea32a',
                                 'computed': '0x000ea32a', 'matches': True}
    assert set(facts['protections']) >= {'ASLR', 'DEP'}
    assert executables.indicators(facts, 'pageant.exe') == []
    assert executables.summary(facts) == (
        'PE32+ x64 program, linked 2025-02-01 11:27:28, signed by Simon '
        'Tatham (not verified)')


def test_a_32_bit_program_and_a_library():
    from trace_app.core import executables
    facts = executables.analyse(sample(ARTIFACTS, 'pageant-w32.exe'))
    assert (facts['format'], facts['architecture']) == ('PE32', 'x86')
    assert facts['compiled'] == '2025-02-01 11:27:14'      # 1738409234
    assert sum(len(i['functions']) for i in facts['imports']) == 193
    assert facts['checksum']['stored'] == '0x000d7b98'
    assert facts['checksum']['matches']
    assert facts['signature']['signer'] == 'Simon Tatham'

    dll = executables.analyse(sample(CARVE, 'sqlite3.dll'))
    assert dll['kind'] == 'library'
    assert dll['exports']['name'] == 'sqlite3.dll'
    assert len(dll['exports']['names']) == 361
    assert dll['exports']['names'][0] == 'sqlite3_aggregate_context'
    assert dll['pdb'].endswith('\\sqlite_bld_dir\\2\\sqlite3.pdb')
    assert dll['pdb_guid'] == '54294286-52FF-4648-9BBA-9BBC7877417E'
    assert dll['compiled'] == '2024-05-23 13:54:42'
    assert 'signature' not in dll and 'checksum' not in dll
    assert executables.summary(dll).endswith(', unsigned')


def test_linux_programs():
    from trace_app.core import executables
    static = executables.analyse(sample(CARVE, 'busybox'))
    assert (static['format'], static['architecture'], static['kind'],
            static['linking']) == ('ELF64', 'x86-64', 'program', 'static')
    assert 'imports' not in static and 'interpreter' not in static

    bat = executables.analyse(sample(
        ARTIFACTS, 'bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz',
        'bat-v0.24.0-x86_64-unknown-linux-gnu/bat'))
    assert bat['kind'] == 'program (position-independent)'
    assert bat['interpreter'] == '/lib64/ld-linux-x86-64.so.2'
    assert [i['library'] for i in bat['imports']] == [
        'libgcc_s.so.1', 'librt.so.1', 'libpthread.so.0', 'libm.so.6',
        'libc.so.6', '(dynamic symbols)']
    assert len(bat['imports'][-1]['functions']) == 166
    assert bat['build_id'] == '05c45c9b7a41434cdef6e6b2cda0374f39f88b5e'
    assert 'rustc version 1.73.0 (cc66ad468 2023-10-03)' in bat['compiler']
    # ELF has no signature to look for: not called unsigned.
    assert executables.summary(bat) == \
        'ELF64 x86-64 program (position-independent)'


def test_macos_programs_thin_and_universal():
    from trace_app.core import executables
    intel = sample(CARVE, 'rg')
    arm = sample(ARTIFACTS, 'ripgrep-14.1.1-aarch64-apple-darwin.tar.gz',
                 'ripgrep-14.1.1-aarch64-apple-darwin/rg')
    facts = executables.analyse(arm)
    assert (facts['format'], facts['architecture'], facts['kind']) == (
        'Mach-O 64-bit', 'ARM64', 'program')
    assert facts['signature']['identifier'] == 'rg'
    assert facts['signature']['ad_hoc'] is True
    assert [i['library'] for i in facts['imports']] == [
        '/opt/homebrew/opt/pcre2/lib/libpcre2-8.0.dylib',
        '/usr/lib/libiconv.2.dylib', '/usr/lib/libSystem.B.dylib']
    assert (facts['platform'], facts['minimum_os']) == ('macOS', '13.0.0')
    assert facts['uuid'] == '442C4C14-85EA-39CB-A7B7-96A890396EFD'
    assert executables.summary(facts).endswith('signed ad hoc (not verified)')
    assert executables.analyse(intel)['architecture'] == 'x86-64'
    assert 'signature' not in executables.analyse(intel)

    # A universal binary of the two, laid out as lipo does (generated).
    first = 0x4000
    second = (first + len(intel) + 0x3FFF) & ~0x3FFF
    fat = bytearray(struct.pack('>II', 0xCAFEBABE, 2))
    fat += struct.pack('>iiIII', 0x01000007, 3, first, len(intel), 14)
    fat += struct.pack('>iiIII', 0x0100000C, 0, second, len(arm), 14)
    fat += bytes(first - len(fat)) + intel
    fat += bytes(second - len(fat)) + arm
    universal = executables.analyse(bytes(fat))
    assert universal['format'] == 'Mach-O universal'
    assert universal['architectures'] == ['x86-64', 'ARM64']
    assert 'overlay' not in universal
    # A Java class file shares the magic and is not taken for one.
    assert executables.kind_of(b'\xca\xfe\xba\xbe\x00\x00\x00\x34') == ''


def _renamed_section(data, old, new):
    at = data.index(old.ljust(8, b'\x00'))
    return data[:at] + new.ljust(8, b'\x00') + data[at + 8:]


def test_indicators(pageant):
    from trace_app.core import executables
    packed = executables.analyse(_renamed_section(pageant, b'.text',
                                                  b'UPX0'))
    assert ('notable', 'Packed with UPX') in \
        executables.indicators(packed, 'pageant.exe')

    # .text made writable as well as executable.
    at = pageant.index(b'.text\x00\x00\x00') + 36
    flags = struct.unpack_from('<I', pageant, at)[0] | 0x80000000
    writable = pageant[:at] + struct.pack('<I', flags) + pageant[at + 4:]
    assert ('notable', 'Writable and executable: .text') in \
        executables.indicators(executables.analyse(writable), 'pageant.exe')

    facts = executables.analyse(pageant)
    assert executables.indicators(facts, 'svchost.exe') == [
        ('notable', 'Calls itself Pageant')]
    assert executables.indicators(facts, 'PAGEANT.EXE') == []

    # Appended data after the signature table is reported, with what it is.
    appended = executables.analyse(pageant + b'PK\x03\x04' + bytes(4000))
    assert appended['overlay']['size'] == 4004
    assert appended['overlay']['starts'] == 'ZIP'

    injector = {'imports': [{'library': 'KERNEL32.dll', 'functions': [
        'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory',
        'CreateRemoteThread']}], 'sections': []}
    assert executables.indicators(injector) == [(
        'suspicious', 'Imports used together for process injection: '
        'createremotethread, openprocess, virtualallocex, '
        'writeprocessmemory')]


def test_the_analysis_module_records_one_finding(pageant):
    from trace_app.core import content_checks
    modules = (content_checks.MODULE_EXECUTABLES,)
    assert content_checks.wants_full_read(pageant[:64], modules)
    (finding,) = content_checks.inspect('svchost.exe', pageant, modules)
    assert (finding.module, finding.kind, finding.grade) == (
        'executables', 'executable', 'notable')
    assert finding.summary.endswith('. Calls itself Pageant')
    detail = finding.detail
    assert detail['signed'] == 'by Simon Tatham'
    assert detail['libraries'][0] == 'ADVAPI32.dll'
    assert detail['imported_functions'] == 201
    assert detail['indicators'] == [{'grade': 'notable',
                                     'text': 'Calls itself Pageant'}]
    assert len(finding.as_row()[4]) < 8000       # a digest, not the lists
    # Damaged or not an executable: nothing, and no exception.
    assert content_checks.inspect('x.exe', pageant[:300], modules) == []
    assert content_checks.inspect('x.exe', b'MZ' + bytes(100), modules) == []
    assert content_checks.inspect('a.txt', b'hello', modules) == []


def test_metadata_tab_rows(pageant):
    from trace_app.ui.viewers.metadata import _executable_rows
    rows = _executable_rows('svchost.exe', pageant)
    labels = {row[0]: row[1] for row in rows if row[0]}
    assert rows[0] == (None, 'Executable')
    assert rows[1] == ('Notable', 'Calls itself Pageant', 'warning')
    assert labels['Format'] == 'PE32+, x64'
    assert labels['Signature'].startswith(
        'Authenticode (PKCS #7), by Simon Tatham, issued by Sectigo')
    assert labels['Libraries'].startswith('ADVAPI32.dll, GDI32.dll')
    assert _executable_rows('a.txt', b'hello') == []


def test_truncated_and_hostile_headers_never_raise():
    from trace_app.core import executables
    data = sample(CARVE, 'busybox')
    for cut in (64, 200, 4096, len(data) // 2):
        executables.analyse(data[:cut])
    junk = bytearray(b'MZ' + bytes(0x3A) + struct.pack('<I', 0x40)
                     + b'PE\x00\x00' + b'\xff' * 400)
    executables.analyse(bytes(junk))
    for magic in (b'\x7fELF\x02\x01', b'\xcf\xfa\xed\xfe',
                  b'\xca\xfe\xba\xbe\x00\x00\x00\x02'):
        executables.analyse(magic + b'\xff' * 300)
        executables.analyse(magic + bytes(300))
    assert executables.analyse(io.BytesIO(b'').read()) is None

"""Apple's unified log (core/activity/unified_log.py).

plaso's unified_logging1.dmg (tools/testdata/samples.py) holds a
Mac's /private/var/db log tree on APFS. plaso's tests give, for each
tracev3 file, how many entries `log show` would list and every field of
one entry; TRACE reads the same files through its own APFS and DMG
readers and must agree to the entry and the nanosecond. Then the records
the activity job keeps: the boot and the sudo commands ec2-user ran.

The format-string engine is checked on its own against printf's rules.
"""

import os

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLE = os.path.join(testdata.SAMPLES,
                      'unified_logging1.dmg')
DIAGNOSTICS = ('private', 'var', 'db', 'Diagnostics')


@pytest.fixture(scope='module')
def log_tree():
    from trace_app.core.activity import Volume, unified_log
    from trace_app.core.image_handler import ImageHandler
    if not os.path.exists(SAMPLE):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail("unified_logging1.dmg missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    handler = ImageHandler(SAMPLE)
    assert handler.loaded
    (key,) = [k for k in handler.volume_offsets() if k >= 2 ** 50]
    (volume,) = Volume.all(handler, key)

    def read(*parts):
        entry = volume.find('private', 'var', 'db', 'uuidtext', *parts)
        return volume.read(entry) if entry is not None else None
    strings = unified_log.Strings(read)
    timesync = unified_log.Timesync(
        volume.read(e) for e in volume.children(
            volume.find(*DIAGNOSTICS, 'timesync')))

    def open_log(kind):
        entry = volume.find(*DIAGNOSTICS, kind, '0000000000000001.tracev3')
        log = unified_log.TraceV3(volume.read(entry), strings, timesync)
        return log.timesync_entries() + list(log.entries())
    yield handler, open_log
    handler.close_resources()


def iso(nanoseconds):
    import datetime
    seconds, rest = divmod(nanoseconds, 1_000_000_000)
    return datetime.datetime.fromtimestamp(
        seconds, datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%S') + f".{rest:09d}"


def test_persist_as_plaso_reads_it(log_tree):
    _handler, open_log = log_tree
    entries = open_log('Persist')
    assert len(entries) == 83000
    entry = entries[27]
    assert entry['message'] == ('initialize_screen: b=BE3A18000, '
                                'w=00000280, h=00000470, r=00000A00, '
                                'd=00000000\n')
    assert (entry['event'], entry['type']) == ('logEvent', 'Default')
    assert entry['process'] == entry['sender'] == '/kernel'
    assert entry['boot'] == 'DCA6F382-13F5-4A21-BF2B-4F1BE8B136BD'
    assert (entry['pid'], entry['thread'], entry['activity']) == (0, 0, 0)
    assert iso(entry['time_ns']) == '2023-01-12T01:35:35.240424708'


def test_signpost_as_plaso_reads_it(log_tree):
    _handler, open_log = log_tree
    entries = open_log('Signpost')
    assert len(entries) == 2466
    entry = entries[7]
    assert entry['event'] == 'signpostEvent' and entry['type'] is None
    assert entry['category'] == 'Speed'
    assert entry['message'] == (
        'Kext com.apple.driver.KextExcludeList v17.0.0 in codeless kext '
        'bundle com.apple.driver.KextExcludeList at /Library/Apple/System/'
        'Library/Extensions/AppleKextExcludeList.kext: FS contents are '
        'valid')
    assert entry['pid'] == 50 and entry['thread'] == 0x7CB
    assert entry['process'] == entry['sender'] == \
        '/usr/libexec/kernelmanagerd'
    assert entry['signpost'] == 0xEEEEB0B5B2B2EEEE
    assert entry['signpost_name'] == 'validateExtFilesystem(into:)'
    assert iso(entry['time_ns']) == '2023-01-12T01:36:31.338352250'


def test_special_as_plaso_reads_it(log_tree):
    _handler, open_log = log_tree
    entries = open_log('Special')
    assert len(entries) == 12159
    entry = entries[8]
    assert entry['message'] == ('Failed to look up the port for '
                                '"com.apple.windowserver.active" (1102)')
    assert entry['process'] == '/usr/libexec/UserEventAgent'
    # The format string came from the shared cache (a dsc file).
    assert entry['sender'] == ('/System/Library/PrivateFrameworks/'
                               'SkyLight.framework/Versions/A/SkyLight')
    assert entry['subsystem'] == 'com.apple.SkyLight'
    assert entry['pid'] == 24 and entry['thread'] == 0x7D1
    assert iso(entry['time_ns']) == '2023-01-12T01:36:27.111432708'
    assert entries[0]['message'] == \
        '=== system boot: DCA6F382-13F5-4A21-BF2B-4F1BE8B136BD'


def test_the_activity_job_keeps_the_boot_and_sudo(log_tree):
    from trace_app.core.activity import collect
    handler, _open_log = log_tree
    records = [r for r in collect(handler) if r['source'] == 'unified log']
    whats = sorted({r['what'] for r in records})
    assert whats == ['Command run as root (sudo)', 'System started']
    sudo = [r for r in records if r['what'].startswith('Command')]
    assert len(sudo) == 6
    first = sudo[0]
    assert first['subject'] == '/usr/sbin/sshd -T'
    assert first['user'] == 'ec2-user'
    assert first['detail']['directory'] == '/Users/ec2-user'
    assert first['detail']['process'] == '/usr/bin/sudo'
    assert first['time'].startswith('2023-01-12 01:39:20')


@pytest.mark.parametrize('text, values, expected', [
    ('%s and %d', [b'abc\0', (42).to_bytes(4, 'little')], 'abc and 42'),
    ('%{public}s: %{private}s', [b'x\0', None], 'x: <decode: missing data>'),
    ('%08x|%#x|%5s|%-5s|', [(255).to_bytes(4, 'little'),
                            (0).to_bytes(4, 'little'), b'ab\0', b'cd\0'],
     '000000ff|0|   ab|cd   |'),
    ('%{bool}d %{BOOL}d %{errno}d %m',
     [(1).to_bytes(4, 'little'), (0).to_bytes(4, 'little'),
      (2).to_bytes(4, 'little'), (13).to_bytes(4, 'little')],
     'true NO [2: No such file or directory] Permission denied'),
    ('100%% {braces} %.2f', [b'\0\0\0\0\0\0\xf8?'], '100% {braces} 1.50'),
    ('%{network:in_addr}d %{uuid_t}.16P', [
        bytes([10, 0, 0, 1]),
        bytes.fromhex('DCA6F38213F54A21BF2B4F1BE8B136BD')],
     '10.0.0.1 DCA6F382-13F5-4A21-BF2B-4F1BE8B136BD'),
    ('%{location:escape_only}s', [b'x'],
     '<decode: unsupported decoder: location:escape_only>'),
])
def test_format_strings(text, values, expected):
    from trace_app.core.activity.unified_log import Format, decode
    parsed = Format(text)
    rendered = [decode(op, value)
                for op, value in zip(parsed.operators, values)]
    assert parsed.render(rendered) == expected

"""Registry transaction logs replayed (trace_app/core/regf_log.py).

Three dirty hives with their .LOG1/.LOG2 from regipy's test data: an
NTUSER.DAT, a SYSTEM and a UsrClass.dat, all Windows 10 new-format logs.
Every log entry's two Marvin32 hashes must check; the recovered hive must
be byte-identical to what yarp -- written by the author of the registry
format specification -- recovers from the same files (its SHA-256 below);
and what only the logs held must reach TRACE's readers: ShellBags in the
UsrClass.dat that exist only in its logs become Activity records.
"""

import io
import lzma
import os
import shutil
import struct

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES

#: (hive, logs, entries applied, sequence numbers, SHA-256 of yarp's
#: recovered hive)
CASES = [
    ('transactions_NTUSER.DAT', ['transactions_ntuser.dat.log1',
                                 'transactions_ntuser.dat.log2'],
     23, (566, 588), ['transactions_ntuser.dat.log1'],
     '0a7a7b2d1eb24ab63455f5a83e554601d88fe558d0ba1c1068a7e1102c79a092'),
    ('SYSTEM_B', ['SYSTEM_B.LOG1', 'SYSTEM_B.LOG2'], 24, (2107, 2130),
     ['SYSTEM_B.LOG1', 'SYSTEM_B.LOG2'],
     '734095bf043ea72300feb8bc380a585d8a9c925cdd5ffc190ca5ff6bc5a7c231'),
    ('UsrClass.dat', ['UsrClass.dat.LOG1', 'UsrClass.dat.LOG2'], 14,
     (287, 300), ['UsrClass.dat.LOG1', 'UsrClass.dat.LOG2'],
     '0c52ea278e8c524fd13c146b060f7801af7791a1cad5b04ae9e6e06617de0e3e'),
]


def load(name):
    path = os.path.join(SAMPLES, f'regipy-{name}.xz')
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    with open(path, 'rb') as handle:
        return lzma.decompress(handle.read())


def test_a_damaged_log_entry_stops_the_replay_before_it():
    """Windows' own Marvin32 hashes are what catch a damaged entry: flip
    one byte of a page in the fifth entry of the NTUSER.DAT log and only
    the four before it are applied."""
    from trace_app.core import regf_log
    data = load('transactions_NTUSER.DAT')
    log = bytearray(load('transactions_ntuser.dat.log1'))
    position = 512
    for _ in range(4):
        position += struct.unpack_from('<I', log, position + 4)[0]
    log[position + 600] ^= 0xFF
    entries = regf_log.new_format_entries(bytes(log))
    assert len(entries) == 22 and 570 not in entries
    _recovered, facts = regf_log.recover(data, [('log1', bytes(log))])
    assert facts['applied'] == 4 and facts['sequence'] == (566, 569)


@pytest.mark.parametrize('hive, logs, applied, sequence, used, sha256',
                         CASES)
def test_dirty_hives_recover_as_yarp_recovers_them(hive, logs, applied,
                                                   sequence, used, sha256):
    import hashlib
    from Registry import Registry
    from trace_app.core import regf_log
    data = load(hive)
    loaded = [(name, load(name)) for name in logs]
    assert regf_log.is_dirty(data)
    # Every entry in both logs is genuine: both hashes check.
    for _name, log in loaded:
        position, count = 512, 0
        while log[position:position + 4] == b'HvLE':
            count += 1
            position += struct.unpack_from('<I', log, position + 4)[0]
        assert len(regf_log.new_format_entries(log)) == count > 0
    recovered, facts = regf_log.recover(data, loaded)
    assert (facts['applied'], facts['sequence'], facts['logs'],
            facts['format']) == (applied, sequence, used, 'new')
    assert not regf_log.is_dirty(recovered)
    assert struct.unpack_from('<II', recovered, 4) == (sequence[1],) * 2
    assert hashlib.sha256(recovered).hexdigest() == sha256
    Registry.Registry(io.BytesIO(recovered)).root()
    # A clean hive is left as it is, and so is one with no logs.
    assert regf_log.recover(recovered, loaded) == (
        recovered, {'dirty': False, 'applied': 0, 'format': None,
                    'logs': []})
    assert regf_log.recover(data, [])[0] == data


def test_keys_only_the_logs_held_are_read():
    from Registry import Registry
    from trace_app.core import regf_log
    data = load('transactions_NTUSER.DAT')
    logs = [(n, load(n)) for n in ('transactions_ntuser.dat.log1',
                                   'transactions_ntuser.dat.log2')]
    before = Registry.Registry(io.BytesIO(data))
    after = Registry.Registry(io.BytesIO(regf_log.recover(data, logs)[0]))
    with pytest.raises(Registry.RegistryKeyNotFoundException):
        before.open('Software\\Microsoft\\Payment')
    after.open('Software\\Microsoft\\Payment\\PaymentApps')
    names = {v.name() for v in after.open(
        'Software\\Microsoft\\OneDrive').values()}
    assert 'StandaloneUpdaterSafeMode' in names
    assert 'StandaloneUpdaterSafeMode' not in {
        v.name() for v in before.open('Software\\Microsoft\\OneDrive')
        .values()}


def test_shellbags_only_in_the_logs_reach_activity(tmp_path):
    """A user's UsrClass.dat in a triage collection, with and without its
    logs beside it: with them, the ShellBags Windows had only logged are
    read too."""
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler

    def shellbags(with_logs):
        root = tmp_path / ('with' if with_logs else 'without')
        folder = root / 'C' / 'Users' / 'jdoe' / 'AppData' / 'Local' / \
            'Microsoft' / 'Windows'
        folder.mkdir(parents=True)
        (folder / 'UsrClass.dat').write_bytes(load('UsrClass.dat'))
        if with_logs:
            for name in ('UsrClass.dat.LOG1', 'UsrClass.dat.LOG2'):
                (folder / name).write_bytes(load(name))
        (root / 'C' / 'Windows').mkdir()
        handler = ImageHandler(str(root))
        try:
            return [r for r in collect(handler)
                    if r['source'].startswith('ShellBags')]
        finally:
            handler.close_resources()
            shutil.rmtree(root, ignore_errors=True)

    without, with_logs = shellbags(False), shellbags(True)
    assert len(with_logs) > len(without) > 0
    assert {r['subject'] for r in without} < {r['subject'] for r in with_logs}

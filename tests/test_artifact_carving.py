"""System records carved from free space (the "System records" carve
types, core/carved_artifacts.py): a deleted log's EVTX chunks, MFT
records, folder index records and a hive's bins -- each kept only when its
own CRCs or fixups hold, then read by the parsers TRACE has for the live
files.

Real records are planted in random free space: a chunk of a real event log
(and a whole log, whose chunks must not be carved again), named records of
ntfs1-gen2's $MFT and its root folder's index, Amcache's hive bins without
their base block, shortcuts from a real jump list -- and decoys with the
right signature but a broken CRC, fixup or cell. What carving keeps must
be exactly the planted records, and what is read from them must equal
what the parsers read from the originals."""

import io
import os
import random

import pytest

from tests.conftest import data_path, image_path

SECTOR = 512


@pytest.fixture(scope='module')
def planted(tmp_path_factory):
    """(image path, {offset: (type, bytes)}, the originals used)."""
    import olefile
    from trace_app.core.image_handler import ImageHandler
    log = open(data_path('samples', 'attack-LM_WMI_4624_4688_TargetHost.evtx'),
               'rb').read()
    whole_log = open(data_path('samples', 'attack-DE_104_system_log_cleared'
                                          '.evtx'), 'rb').read()
    hive = open(data_path('samples', 'Amcache-WIN10.hve'), 'rb').read()
    jump = open(data_path('samples', '1b4dd67f29cb1962.automaticDestinations'
                                     '-ms'), 'rb').read()
    with olefile.OleFileIO(io.BytesIO(jump)) as ole:
        shortcuts = [ole.openstream(s).read() for s in ole.listdir()
                     if s[0] != 'DestList'][:2]
    handler = ImageHandler(image_path('ntfs1-gen2.E01'))
    assert handler.load_image()
    fs = handler.get_fs_info(handler.volume_offsets()[0])
    mft = fs.open('/$MFT')
    mft_bytes = mft.read_random(0, min(mft.info.meta.size, 1024 * 64))
    from trace_app.core import ntfs, ntfs_index
    records = [mft_bytes[o:o + 1024] for o in range(0, len(mft_bytes), 1024)]
    named = [r for r in records if (ntfs.parse_record(r, 0) or
                                    ntfs.Entry(0, 0, 0, 0, 0)).names][30:33]
    index = ntfs_index.index_data(fs.open_meta(inode=5))[:4096]
    handler.close_resources()

    rng = random.Random(11)
    image = bytearray(rng.getrandbits(8) for _ in range(8 * 1024 * 1024))
    expected = {}
    layout = []
    chunk = log[4096:4096 + 65536]
    layout.append(('evtxchunk', chunk))
    layout.append(('evtx', whole_log))
    layout += [('mftrecord', r) for r in named]
    layout.append(('indx', index))
    bins = int.from_bytes(hive[0x28:0x2C], 'little')
    layout.append(('hbin', hive[4096:4096 + bins]))   # the bins alone
    # Decoys: the signature, broken where the format checks itself.
    torn = bytearray(named[0])
    torn[1022] ^= 0xFF                      # a fixup that does not match
    bad_chunk = bytearray(chunk)
    bad_chunk[600] ^= 0xFF                  # its event records' CRC fails
    bad_index = bytearray(index)
    bad_index[2046] ^= 0xFF
    layout += [('decoy', bytes(torn)), ('decoy', bytes(bad_chunk)),
               ('decoy', bytes(bad_index)),
               ('decoy', b'hbin' + bytes(28) + b'\x00\x10\x00\x00' * 8)]
    at = 3 * SECTOR
    for kind, data in layout:
        image[at:at + len(data)] = data
        if kind != 'decoy':
            expected[at] = (kind, data)
        at += len(data) + 7 * SECTOR + rng.randrange(4) * SECTOR
    # Shortcuts are carved anywhere (they are often resident in an MFT
    # record): planted off sector boundaries.
    for shortcut in shortcuts:
        at += 123
        image[at:at + len(shortcut)] = shortcut
        expected[at] = ('lnk', shortcut)
        at += len(shortcut) + SECTOR
    path = tmp_path_factory.mktemp('artifacts') / 'free.dd'
    path.write_bytes(bytes(image))
    return {'path': str(path), 'expected': expected, 'log': log,
            'hive': hive, 'shortcuts': shortcuts, 'records': named,
            'index': index}


TYPES = ['evtxchunk', 'mftrecord', 'indx', 'hbin', 'evtx', 'lnk']


def _carve(path):
    from trace_app.core.carving import carve_image
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.load_image()
    found = {}
    try:
        carve_image(handler, TYPES, lambda data, kind, offset,
                    fragments=None: found.setdefault(offset, (kind, data)),
                    unallocated_only=False)
    finally:
        handler.close_resources()
    return found


def test_exactly_the_planted_records_are_carved(planted):
    found = _carve(planted['path'])
    assert {o: k for o, (k, _d) in found.items()} == \
        {o: k for o, (k, _d) in planted['expected'].items()}
    for offset, (kind, data) in planted['expected'].items():
        assert found[offset][1] == data, (kind, offset)


def test_what_the_records_say_matches_their_originals(planted, tmp_path):
    from trace_app.core import carved_artifacts, ntfs
    from trace_app.core.activity import eventlogs, lnk
    from trace_app.core.carving import carve_evidence, read_carved
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(planted['path'])
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), 'Artifacts')
    try:
        evidence = case.add_evidence(planted['path'])
        carve_evidence(handler, case, evidence, TYPES, source='image')
        # MFT and index records: their names and times as file-system
        # events.
        events = case._db.execute(
            "SELECT path, time_utc, macb, source FROM fs_events WHERE "
            "evidence_id = ?", (evidence,)).fetchall()
        names = {ntfs.parse_record(r, 0).best_name().name
                 for r in planted['records']}
        carved_names = {row[0].split(']/', 1)[1].split(' (parent', 1)[0]
                        for row in events if row[3] != 'I30 (carved)'}
        assert carved_names == names
        assert {row[3] for row in events} == {'SI (carved)', 'FN (carved)',
                                              'I30 (carved)'}
        # Each record's own times, as the live parser reads them.
        first = ntfs.parse_record(planted['records'][0], 0)
        want = {(t, m, f"{s} (carved)") for t, m, s in
                ntfs.entry_events(first, '')}
        got = {(row[1], row[2], row[3]) for row in events
               if first.best_name().name in row[0]}
        assert got == want
        # Activity: the chunk's events, the shortcuts, the hive's keys.
        rows = [r for kind in carved_artifacts.ACTIVITY_TYPES
                for r in case.carved_files(evidence, kind)]
        records = carved_artifacts.activity_records(
            rows, lambda r: read_carved(handler.read, r['offset'],
                                        r['size']))
        chunk_events = eventlogs.from_chunk(
            planted['log'][4096:4096 + 65536])
        from_chunk = {(r['what'], r['subject'], r['detail']['record'])
                      for r in records if r['source'] == 'Event log (carved)'
                      and r['detail']['carved at byte'] == min(
                          o for o, (k, _d) in planted['expected'].items()
                          if k == 'evtxchunk')}
        assert from_chunk == {(what, subject, detail['record'])
                              for _w, what, subject, detail, _e in
                              chunk_events}
        targets = {r['subject'] for r in records
                   if r['source'] == 'Shortcut (carved)'}
        assert targets == {lnk.parse(s)['target']
                           for s in planted['shortcuts']}
        keys = [r for r in records if r['source'] == 'Registry (carved)']
        # Every key the hive has in use, as python-registry walks it; the
        # free cells' deleted keys come on top (python-registry lists none).
        in_use = [r for r in keys if r['detail']['state'].startswith('in use')]
        assert len(in_use) == _live_key_count(planted['hive'])
        from trace_app.core.regf_deleted import recover
        assert len(keys) - len(in_use) == len(recover(planted['hive'])
                                              ['keys'])
        assert any(r['subject'].endswith('/InventoryApplicationFile')
                   for r in keys)
        # A new carve forgets the old one's file-system events.
        case.clear_carved(evidence)
        assert not case._db.execute(
            "SELECT COUNT(*) FROM fs_events WHERE evidence_id = ?",
            (evidence,)).fetchone()[0]
    finally:
        handler.close_resources()
        case.close()


def _live_key_count(hive):
    """Keys in use in the hive, as python-registry walks them."""
    from Registry import Registry
    registry = Registry.Registry(io.BytesIO(hive))
    count = 0
    pending = [registry.root()]
    while pending:
        key = pending.pop()
        count += 1
        pending += key.subkeys()
    return count


def test_spec_checks_reject_damage():
    from trace_app.core import carving_formats as formats
    from trace_app.core.carving_signatures import is_valid_file
    log = open(data_path('samples', 'attack-LM_WMI_4624_4688_TargetHost'
                                    '.evtx'), 'rb').read()
    chunk = log[4096:4096 + 65536]
    assert formats.evtx_chunk_ok(chunk)
    assert is_valid_file(chunk, 'evtxchunk')
    damaged = bytearray(chunk)
    damaged[0x7C] ^= 1
    assert not formats.evtx_chunk_ok(bytes(damaged))
    assert not is_valid_file(os.urandom(65536), 'evtxchunk')

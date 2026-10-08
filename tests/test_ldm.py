"""Windows dynamic disks (core/ldm.py; ImageHandler.dynamic_volumes;
assembly's 'ldm' groups).

* Volume assembly -- simple, spanned, striped, RAID5 (left-symmetric, as
  Windows writes it), mirrored, a disk missing -- over synthetic disks
  laid out here: every system.
* The LDM database itself is read from real dynamic disks: the X-Ways
  training sets A (mirror, striped, simple) and B (RAID5, simple,
  spanned) and a GPT dynamic disk. They are private: local only, skipped
  when test_images/X-WaysTrainingImages is absent.
"""

import os
import random

import pytest

from tests.conftest import ROOT

XWAYS = os.path.join(ROOT, 'test_images', 'X-WaysTrainingImages')
CHUNK = 4096
SECTOR = 512


def _volume(kind, extents, chunk=0, columns=0, components=1, size=None):
    component = {'kind': {'striped': 1, 'raid5': 3}.get(kind, 2),
                 'chunk': chunk, 'columns': columns, 'extents': extents}
    total = size or sum(e['size'] for e in extents)
    return {'id': 1, 'name': 'Test', 'kind': kind, 'size': total,
            'disks': sorted({e['disk_guid'] for e in extents}),
            'components': [component] * components}


def _extent(guid, start, size, offset=0, column=0):
    return {'disk_guid': guid, 'start': start, 'size': size,
            'offset': offset, 'column': column}


def _disk(data):
    return (lambda o, n: data[o:o + n]), 0


def test_simple_and_spanned_volumes():
    from trace_app.core import ldm
    first, second = b'A' * 3000 + b'\0' * 1096, b'B' * 4096
    disks = {'d1': _disk(b'\0' * 512 + first), 'd2': _disk(second)}
    spanned = _volume('spanned', [_extent('d2', 0, 4096, 4096),
                                  _extent('d1', 512, 4096, 0)])
    reader = ldm.volume_reader(spanned, disks)
    assert reader.size == 8192
    assert reader.read(2990, 20) == b'A' * 10 + b'\0' * 10
    assert reader.read(4090, 12) == b'\0' * 6 + b'B' * 6
    with pytest.raises(ldm.LdmError, match='not here'):
        ldm.volume_reader(spanned, {'d1': disks['d1']})


def test_striped_raid5_and_a_missing_disk():
    from tests.disk_builders import stripe
    from trace_app.core import ldm
    rng = random.Random(5)
    data = bytes(rng.getrandbits(8) for _ in range(CHUNK * 24))
    for kind, level, layout in (('striped', '0', 'left-asymmetric'),
                                ('raid5', '5', 'left-symmetric')):
        written, size = stripe(data, 3, level, layout, 1, CHUNK)
        disks = {f'd{i}': _disk(b'\0' * SECTOR + d)
                 for i, d in enumerate(written)}
        extents = [_extent(f'd{i}', SECTOR, len(d), 0, i)
                   for i, d in enumerate(written)]
        volume = _volume(kind, extents, CHUNK, 3, size=size)
        assert ldm.volume_reader(volume, disks).read(0, size) == data[:size]
        if kind == 'raid5':
            for gone in disks:
                partial = {k: v for k, v in disks.items() if k != gone}
                assert ldm.volume_reader(volume, partial).read(0, size) == \
                    data[:size]
        else:
            with pytest.raises(ldm.LdmError, match='every disk'):
                ldm.volume_reader(volume, {'d0': disks['d0']})


def test_a_mirror_reads_from_whichever_plex_is_here():
    from trace_app.core import ldm
    content = b'mirrored' * 512
    volume = {'id': 1, 'name': 'M', 'kind': 'mirror', 'size': len(content),
              'disks': ['d1', 'd2'],
              'components': [{'kind': 2, 'chunk': 0, 'columns': 0,
                              'extents': [_extent('d1', 0, len(content))]},
                             {'kind': 2, 'chunk': 0, 'columns': 0,
                              'extents': [_extent('d2', 0, len(content))]}]}
    for here in ('d1', 'd2'):
        reader = ldm.volume_reader(volume, {here: _disk(content)})
        assert reader.read(0, len(content)) == content


# --- private, local only --------------------------------------------------

def _handlers(*names):
    paths = [os.path.join(XWAYS, n) for n in names]
    if not all(os.path.exists(p) for p in paths):
        pytest.skip("private X-Ways training images (local only)")
    from trace_app.core.image_handler import ImageHandler
    return {p: ImageHandler(p) for p in paths}


SET_A = [f"Dyn. Disk Set A, Disk {n}.e01" for n in (1, 2, 3)]
SET_B = [f"Dyn. Disk Set B, Disk {n}.e01" for n in (1, 2, 3)]


def test_xways_databases_list_every_volume():
    handlers = _handlers(*SET_A, *SET_B)
    try:
        kinds = {}
        for path, handler in handlers.items():
            database = handler.ldm_database()
            assert database is not None, path
            kinds[database.group_name] = sorted(
                (v['name'], v['kind'], len(v['disks']))
                for v in database.volume_list())
        assert kinds == {
            'PicardDg0': [('Stripe1', 'striped', 3), ('Volume1', 'mirror', 2),
                          ('Volume2', 'simple', 1)],
            'RikerDg0': [('Raid1', 'raid5', 3), ('Volume1', 'simple', 1),
                         ('Volume2', 'spanned', 2)]}
    finally:
        for handler in handlers.values():
            handler.close_resources()


def test_xways_single_disk_volumes_open_in_their_image():
    handlers = _handlers(*SET_A[:1], "GPT Dynamic.e01")
    try:
        found = {}
        for path, handler in handlers.items():
            for _a, _d, start, _l in handler.get_partitions():
                if handler.volume_kind(start) != 'ldm':
                    continue
                for volume in handler.dynamic_volumes(start):
                    found[(os.path.basename(path), volume['name'])] = (
                        handler.get_fs_type(volume['key'])
                        if volume['readable'] else None)
        assert found == {
            ("Dyn. Disk Set A, Disk 1.e01", 'Volume1'): 'FAT32',  # mirror
            ("Dyn. Disk Set A, Disk 1.e01", 'Stripe1'): None,
            ("Dyn. Disk Set A, Disk 1.e01", 'Volume2'): None,
            ("GPT Dynamic.e01", 'Volume1'): 'FAT16',
            ("GPT Dynamic.e01", 'Volume2'): 'NTFS'}
    finally:
        for handler in handlers.values():
            handler.close_resources()


def test_xways_multi_disk_volumes_assemble_with_valid_files(tmp_path):
    from trace_app.core import assembly, hwraid
    from trace_app.core.image_handler import ImageHandler
    handlers = _handlers(*SET_A, *SET_B)
    try:
        groups = {g['name'] + ' ' + g['level']: g
                  for g in assembly.find_groups(handlers)}
        assert set(groups) == {'Stripe1 striped', 'Raid1 raid5',
                               'Volume2 spanned'}
        for group in groups.values():
            volume = ImageHandler(assembly.write(str(tmp_path), group))
            try:
                assert volume.loaded, volume.load_error
                _score, evidence = hwraid.score(volume)
                assert evidence['valid'] == evidence['checked'] == 36
            finally:
                volume.close_resources()
        # RAID5 with a disk gone: rebuilt from parity.
        partial = {p: h for p, h in handlers.items()
                   if not p.endswith('Set B, Disk 2.e01')}
        (raid,) = [g for g in assembly.find_groups(partial)
                   if g['level'] == 'raid5']
        volume = ImageHandler(assembly.write(str(tmp_path), raid))
        try:
            assert 'rebuilt from parity' in volume.container_note
            assert hwraid.score(volume)[1]['valid'] == 36
        finally:
            volume.close_resources()
    finally:
        for handler in handlers.values():
            handler.close_resources()

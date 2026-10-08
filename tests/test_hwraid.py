"""Hardware RAID rebuilt from parameters (core/hwraid.py), and the
Assemble dialog's descriptor for it (core/assembly.py).

* Synthetic arrays, striped here by a writer independent of the reader --
  every level and parity rotation, with HP's parity delay, whole and with
  a disk missing -- read back byte for byte. No images: every system.
* Against mdadm: the kernel-built arrays (tools/make_md_raid.py, Linux
  CI) read through hwraid with their own parameters equal their files.
* The X-Ways training sets (HP Smart Array RAID5 with a disk missing and
  parity delay, Adaptec RAID5, a RAID0) are private: run locally when
  test_images/X-WaysTrainingImages is there, skipped otherwise.
"""

import hashlib
import json
import os
import random

import pytest

from tests.conftest import ROOT
from tests.disk_builders import fat_volume_with_pngs as _fat_volume_with_pngs
from tests.disk_builders import stripe

TEST_IMAGES = os.path.join(ROOT, 'test_images')
XWAYS = os.path.join(TEST_IMAGES, 'X-WaysTrainingImages')
CHUNK = 4096


def members_of(disks):
    return [((lambda o, n, d=d: d[o:o + n]), len(d)) for d in disks]


@pytest.mark.parametrize('level, disks, layout, delay', [
    ('0', 3, 'left-asymmetric', 1),
    ('5', 3, 'left-asymmetric', 1),
    ('5', 4, 'right-asymmetric', 1),
    ('5', 5, 'left-symmetric', 1),
    ('5', 4, 'right-symmetric', 1),
    ('5', 8, 'left-asymmetric', 4),          # HP Smart Array
    ('5', 6, 'left-symmetric', 16),
    ('6', 5, 'left-symmetric', 1),
])
def test_arrays_read_back_whole_and_degraded(level, disks, layout, delay):
    from trace_app.core import hwraid
    rng = random.Random(f"{level}{disks}{layout}{delay}")
    data = bytes(rng.getrandbits(8) for _ in range(CHUNK * 60))
    written, size = stripe(data, disks, level, layout, delay)
    params = hwraid.Params(level, CHUNK, layout, 0, list(range(disks)),
                           delay)
    volume = hwraid.build(members_of(written), params)
    assert volume.size == size
    assert volume.read(0, size) == data[:size]
    assert volume.read(CHUNK - 7, 20) == data[CHUNK - 7:CHUNK + 13]
    if level in ('5', '6'):
        for gone in (0, disks // 2, disks - 1):
            order = [i if i != gone else None for i in range(disks)]
            params = hwraid.Params(level, CHUNK, layout, 0, order, delay)
            volume = hwraid.build(members_of(written), params)
            assert volume.read(0, size) == data[:size], gone


def test_what_cannot_be_rebuilt_is_refused():
    from trace_app.core import hwraid
    disks, _size = stripe(bytes(CHUNK * 12), 4, '5')
    with pytest.raises(hwraid.RaidError, match='missing'):
        hwraid.build(members_of(disks),
                     hwraid.Params('5', CHUNK, order=[0, None, None, 3]))
    with pytest.raises(hwraid.RaidError, match='every disk'):
        hwraid.build(members_of(disks),
                     hwraid.Params('0', CHUNK, order=[0, None, 2, 3]))
    with pytest.raises(hwraid.RaidError):
        hwraid.Params('3')


def test_jbod_and_a_data_offset():
    from trace_app.core import hwraid
    first, second = b'A' * 9000, b'B' * 7000
    span = hwraid.build(members_of([b'\0' * 512 + first,
                                    b'\0' * 512 + second]),
                        hwraid.Params('jbod', offset=512, order=[0, 1]))
    assert span.size == 16000 and span.read(8990, 20) == b'A' * 10 + \
        b'B' * 10


def test_names_give_the_order_and_the_gap():
    from trace_app.core.hwraid import name_order
    assert name_order(['1.e01', '2.e01', '4.e01', '5.e01']) == \
        [0, 1, None, 2, 3]
    assert name_order(['RAID0 3.e01', 'RAID0 1.e01', 'RAID0 2.e01']) == \
        [1, 2, 0]
    assert name_order(['disk.e01', 'another.e01']) == [0, 1]


def test_detection_finds_a_synthetic_array(tmp_path):
    """A FAT disk image striped by the writer above, members shuffled:
    detection must find the level, stripe, layout and order."""
    from trace_app.core import hwraid
    volume = _fat_volume_with_pngs()
    written, size = stripe(volume, 3, '5', 'left-symmetric', 1, 16384)
    shuffled = [written[2], written[0], written[1]]
    ranked = hwraid.detect(members_of(shuffled),
                           chunks=(8192, 16384, 32768))
    assert ranked, "nothing detected"
    best = ranked[0][1]
    assert (best.level, best.chunk, best.layout) == ('5', 16384,
                                                      'left-symmetric')
    rebuilt = hwraid.build(members_of(shuffled), best)
    assert rebuilt.read(0, size) == volume[:size]


def test_a_descriptor_opens_as_evidence(tmp_path):
    from trace_app.core import assembly, hwraid
    from trace_app.core.image_handler import ImageHandler
    volume = _fat_volume_with_pngs()
    written, size = stripe(volume, 4, '5', 'left-asymmetric', 4, 16384)
    paths = []
    for index, disk in enumerate(written):
        paths.append(str(tmp_path / f'disk{index + 1}.dd'))
        with open(paths[-1], 'wb') as handle:
            handle.write(disk)
    params = hwraid.Params('5', 16384, 'left-asymmetric', 0,
                           [0, 1, None, 2], 4)
    descriptor = assembly.write(
        str(tmp_path / 'case'),
        assembly.hardware_group([paths[0], paths[1], paths[3]], params,
                                'Test RAID'))
    handler = ImageHandler(descriptor)
    try:
        assert handler.loaded, handler.load_error
        assert 'parity delay 4' in handler.container_note
        assert handler.read(0, size) == volume[:size]
        names = {e['name'] for e in handler.get_directory_contents(0, None)}
        assert {f'PIC{n}.PNG' for n in range(8)} <= names
    finally:
        handler.close_resources()


def test_hwraid_reads_mdadm_arrays_with_their_parameters():
    """The rotations are md's names: on the kernel's own arrays they must
    mean what mdadm means (Linux CI builds them)."""
    import pytsk3
    from trace_app.core import hwraid, mdraid
    from tests.conftest import image_path
    with open(image_path('md-raid.json'), encoding='utf-8') as handle:
        arrays = json.load(handle)['arrays']
    for array in arrays:
        if array['level'] not in (0, 5, 6) or array['partitioned']:
            continue
        files = [open(image_path(n), 'rb') for n in array['members']]
        try:
            def reader(handle):
                def read(offset, length):
                    handle.seek(offset)
                    return handle.read(length)
                return read
            sizes = [os.path.getsize(f.name) for f in files]
            blocks = [mdraid.superblock(reader(f), s)
                      for f, s in zip(files, sizes)]
            order = [None] * len(blocks)
            for index, block in enumerate(blocks):
                order[block.role] = index
            layout = {0: 'left-asymmetric', 1: 'right-asymmetric',
                      2: 'left-symmetric', 3: 'right-symmetric'}.get(
                          blocks[0].layout, 'left-asymmetric')
            params = hwraid.Params(str(array['level']), blocks[0].chunk,
                                   layout, blocks[0].data_offset, order)
            volume = hwraid.build([(reader(f), s)
                                   for f, s in zip(files, sizes)], params)
            fs = pytsk3.FS_Info(hwraid._Image(volume))
            for record in array['files']:
                handle = fs.open(record['path'])
                data = handle.read_random(0, handle.info.meta.size)
                assert hashlib.sha256(data).hexdigest() == \
                    record['sha256'], (array['name'], record['path'])
        finally:
            for handle in files:
                handle.close()


# --- private, local only --------------------------------------------------

def _xways(*names):
    paths = [os.path.join(XWAYS, *n.split('/')) for n in names]
    if not all(os.path.exists(p) for p in paths):
        pytest.skip("private X-Ways training images (local only)")
    from trace_app.core.image_handler import ImageHandler
    return [ImageHandler(p) for p in paths]


@pytest.mark.parametrize('names, expected', [
    ([f'RAID5 HP 16K/{n}.e01' for n in (1, 2, 4, 5, 6, 7, 8)],
     ('5', 16384, 'left-asymmetric', 4, [0, 1, None, 2, 3, 4, 5, 6])),
    ([f'RAID0 {n}.e01' for n in (1, 2, 3)],
     ('0', 65536, 'left-asymmetric', 1, [0, 1, 2])),
    ([f'RAID5 Adaptec {n}.e01' for n in ('disk', 'another disk',
                                         'one more')],
     ('5', 65536, 'left-asymmetric', 1, [2, 0, 1])),
])
def test_xways_training_raids_are_detected(names, expected):
    from trace_app.core import hwraid
    handlers = _xways(*names)
    try:
        ranked = hwraid.detect([(h.read, h.get_size()) for h in handlers],
                               names=[os.path.basename(n) for n in names])
        score, best, evidence = ranked[0]
        assert (best.level, best.chunk, best.layout, best.delay,
                best.order) == expected
        assert evidence['valid'] == evidence['checked'] > 0
        assert score > ranked[1][0] if len(ranked) > 1 else True
    finally:
        for handler in handlers:
            handler.close_resources()

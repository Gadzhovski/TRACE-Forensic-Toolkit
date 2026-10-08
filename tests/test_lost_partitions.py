"""File systems no partition table points at (core/lost_partitions.py,
ImageHandler.lost_partitions).

* A disk written here -- an MBR whose table was wiped, with FAT volumes
  where partitions used to start (one at 1 MiB, one at an old cylinder
  boundary + 63) -- on every system: both are found, opened, read by
  every module (volume_offsets), and their live files are allocated for
  carving.
* The X-Ways training images "Lost Partitions Vista" (table wiped),
  "Lost Partitions" (a broken extended chain) and "GPT Disk" (a deleted
  GPT entry) are private: local only.
"""

import os

import pytest

from tests.conftest import ROOT

XWAYS = os.path.join(ROOT, 'test_images', 'X-WaysTrainingImages')
SECTOR = 512


def wiped_disk(path):
    from tests.disk_builders import fat_volume_with_pngs
    volume = fat_volume_with_pngs()
    total = 80000
    disk = bytearray(total * SECTOR)
    disk[510:512] = b'\x55\xaa'                       # an MBR, table empty
    for start in (2048, 2 * 16065 + 63):
        disk[start * SECTOR:start * SECTOR + len(volume)] = volume
    with open(path, 'wb') as handle:
        handle.write(disk)
    return str(path)


def test_lost_volumes_are_found_and_read(tmp_path):
    from trace_app.core import carving
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(wiped_disk(tmp_path / 'wiped.dd'))
    try:
        assert handler.get_partitions() == []
        lost = handler.lost_partitions()
        assert [(p['start'], p['fs']) for p in lost] == [
            (2048, 'FAT16'), (2 * 16065 + 63, 'FAT16')]
        for partition in lost:
            assert partition['start'] in handler.volume_offsets()
            names = {e['name'] for e in handler.get_directory_contents(
                partition['start'], None)}
            assert 'PIC0.PNG' in names
            assert handler.partition_label(partition['start']) == \
                f"Lost partition @ {partition['start']}"
        # Their live files are not free space to the carver.
        ranges = carving.allocation_map(handler)
        assert any(b >= 2048 * SECTOR for b, _e in ranges)
    finally:
        handler.close_resources()


def test_a_volume_image_is_not_searched(tmp_path):
    from tests.disk_builders import fat_volume_with_pngs
    from trace_app.core.image_handler import ImageHandler
    path = tmp_path / 'volume.dd'
    path.write_bytes(fat_volume_with_pngs())
    handler = ImageHandler(str(path))
    try:
        assert handler.lost_partitions() == []
    finally:
        handler.close_resources()


def test_signatures():
    from trace_app.core.lost_partitions import candidates, gaps, signature
    ntfs = bytearray(4096)
    ntfs[3:11] = b'NTFS    '
    ntfs[510:512] = b'\x55\xaa'
    assert signature(bytes(ntfs)) == 'NTFS'
    assert signature(bytes(4096)) is None
    assert list(gaps(100, [(10, 20), (15, 30), (50, 60)])) == \
        [(0, 10), (30, 50), (60, 100)]
    found = candidates(16000, 20000)
    assert 16065 in found and 16128 in found and 18432 in found
    assert all(16000 <= s < 20000 for s in found)


# --- private, local only --------------------------------------------------

@pytest.mark.parametrize('name, expected', [
    ('Lost Partitions Vista.e01',
     [(2048, 'FAT16', None), (133120, 'FAT16', None),
      (395264, 'FAT32', 133120), (659456, 'FAT16', None),
      (1710080, 'NTFS', None), (3809280, 'NTFS', None)]),
    ('Lost Partitions.e01',
     [(63, 'FAT12', None), (273168, 'FAT32', None), (578403, 'NTFS', None),
      (1815408, 'NTFS', None)]),
    ('GPT Disk.e01', [(657408, 'NTFS', None)]),
    ('NTFS Compression.e01', []),
])
def test_xways_lost_partitions(name, expected):
    path = os.path.join(XWAYS, name)
    if not os.path.exists(path):
        pytest.skip("private X-Ways training images (local only)")
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    try:
        assert [(p['start'], p['fs'], p['overlaps'])
                for p in handler.lost_partitions()] == expected
        for partition in handler.lost_partitions():
            assert handler.get_directory_contents(partition['start'], None)
    finally:
        handler.close_resources()

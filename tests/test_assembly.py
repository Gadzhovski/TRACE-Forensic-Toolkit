"""Evidence across several disks (core/assembly.py): Linux RAID arrays
(core/mdraid.py) and multi-disk Btrfs file systems (core/btrfs.py).

Btrfs: fox-it/dissect.btrfs's RAID0/1/5/6 test pools, one image per
device, checked against the contents its own tests publish -- whole, with
a device missing where the profile allows it, and refused where it does
not.

md: arrays mdadm itself made (tools/make_md_raid.py: every RAID level,
superblocks 0.90 / 1.0 / 1.2, two RAID5 layouts, a member inside a GPT
partition) with each file's SHA-256 as the kernel wrote it. They need root
and a loop device to build, so CI builds them on Linux and these tests
skip elsewhere.
"""

import hashlib
import json
import os
import shutil

import pytest

from tests.conftest import image_path

BTRFS_POOLS = {
    'raid0': ['btrfs-raid0-1.raw', 'btrfs-raid0-2.raw'],
    'raid1': ['btrfs-raid1-1.raw', 'btrfs-raid1-2.raw'],
    'raid5': ['btrfs-raid5-1.raw', 'btrfs-raid5-2.raw'],
    'raid6': ['btrfs-raid6-1.raw', 'btrfs-raid6-2.raw', 'btrfs-raid6-3.raw'],
}
MD_KEY = 'md-raid.json'


def handlers_for(paths):
    from trace_app.core.image_handler import ImageHandler
    handlers = {path: ImageHandler(path) for path in paths}
    assert all(h.loaded for h in handlers.values())
    return handlers


def close(handlers):
    for handler in handlers.values():
        handler.close_resources()


def assemble(paths, folder):
    """Group the images, save the one group's descriptor, open it."""
    from trace_app.core import assembly
    from trace_app.core.image_handler import ImageHandler
    handlers = handlers_for(paths)
    try:
        groups = assembly.find_groups(handlers)
    finally:
        close(handlers)
    assert len(groups) == 1
    path = assembly.write(str(folder), groups[0])
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return groups[0], path, handler


def read_path(handler, path, start=0):
    fs = handler.get_fs_info(start)
    file_object = fs.open(path)
    return file_object.read_random(0, file_object.info.meta.size)


def assert_dissect_data(handler):
    """dissect.btrfs's assert_test_data, through the assembled handler."""
    assert read_path(handler, '/path/to/a/file.txt') == b'file in dir\n'
    assert read_path(handler, '/small.txt') == \
        b'small file content goes here\n'
    assert read_path(handler, '/large.txt') == b'a' * 5242880 + b'\n'


# --- Btrfs ----------------------------------------------------------------------

@pytest.mark.parametrize('profile', sorted(BTRFS_POOLS))
def test_a_btrfs_pool_reads_whole_across_its_devices(profile, tmp_path):
    paths = [image_path(name) for name in BTRFS_POOLS[profile]]
    group, _path, handler = assemble(paths, tmp_path)
    try:
        assert group['kind'] == 'btrfs'
        assert group['complete']
        assert f"across {len(paths)} of {len(paths)} devices" in \
            handler.container_note
        assert_dissect_data(handler)
    finally:
        handler.close_resources()


def test_a_btrfs_raid6_pool_reads_with_a_device_missing(tmp_path):
    """The missing device's data stripes are rebuilt from the others and P
    parity -- dissect.btrfs does not attempt this."""
    paths = [image_path(name) for name in BTRFS_POOLS['raid6'][:2]]
    group, _path, handler = assemble(paths, tmp_path)
    try:
        assert not group['complete']
        assert_dissect_data(handler)
    finally:
        handler.close_resources()


def test_one_device_of_a_btrfs_raid0_reads_only_what_it_holds():
    """mkfs mirrors metadata over a pool's devices: the first device alone
    has the whole tree and inline files, but a striped file's data is
    partly elsewhere -- an error naming that, never zeros. The second
    device holds no copy of the chunk tree's start and does not open."""
    from trace_app.core.btrfs import BtrfsError
    from trace_app.core.image_handler import ImageHandler
    first = ImageHandler(image_path(BTRFS_POOLS['raid0'][0]))
    second = ImageHandler(image_path(BTRFS_POOLS['raid0'][1]))
    try:
        assert read_path(first, '/small.txt') == \
            b'small file content goes here\n'
        with pytest.raises(BtrfsError, match='another disk'):
            read_path(first, '/large.txt')
        assert second.get_fs_info(0) is None
    finally:
        first.close_resources()
        second.close_resources()


def test_a_pool_whose_devices_are_in_one_image_is_not_offered(tmp_path):
    from trace_app.core import assembly
    handlers = handlers_for([image_path(BTRFS_POOLS['raid1'][0])])
    try:
        assert assembly.find_groups(handlers) == []
    finally:
        close(handlers)


def test_members_are_found_beside_a_moved_descriptor(tmp_path):
    """A case folder copied elsewhere with its images: the recorded paths
    are gone, the images are beside the descriptor."""
    from trace_app.core.image_handler import ImageHandler
    moved = tmp_path / 'moved'
    moved.mkdir()
    copies = []
    for name in BTRFS_POOLS['raid1']:
        copies.append(str(moved / name))
        shutil.copyfile(image_path(name), copies[-1])
    _group, path, handler = assemble(copies, tmp_path / 'first')
    handler.close_resources()
    elsewhere = tmp_path / 'elsewhere'
    shutil.copytree(moved, elsewhere)
    shutil.copyfile(path, elsewhere / os.path.basename(path))
    shutil.rmtree(moved)
    handler = ImageHandler(str(elsewhere / os.path.basename(path)))
    try:
        assert handler.loaded, handler.load_error
        assert_dissect_data(handler)
    finally:
        handler.close_resources()


def test_a_missing_member_is_named(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    _group, path, handler = assemble(
        [image_path(n) for n in BTRFS_POOLS['raid1']], tmp_path)
    handler.close_resources()
    with open(path, encoding='utf-8') as source:
        data = json.load(source)
    data['members'][1]['image'] = str(tmp_path / 'gone.raw')
    with open(path, 'w', encoding='utf-8') as target:
        json.dump(data, target)
    handler = ImageHandler(path)
    try:
        assert not handler.loaded
        assert 'gone.raw' in (handler.load_error or '')
    finally:
        handler.close_resources()


def test_an_assembled_volume_is_verified_by_its_contents(tmp_path):
    """The descriptor is a few hundred bytes of JSON: verification hashes
    the assembled bytes, so a member changed afterwards is found."""
    from trace_app.core.case import Case, STATUS_CHANGED, STATUS_VERIFIED
    members = []
    for name in BTRFS_POOLS['raid1']:
        members.append(str(tmp_path / name))
        shutil.copyfile(image_path(name), members[-1])
    _group, path, handler = assemble(members, tmp_path / 'assembled')
    case = Case.create(str(tmp_path / 'case'), 'Assembly')
    try:
        evidence_id = case.add_evidence(path)
        row = next(r for r in case.evidence() if r['id'] == evidence_id)
        assert row['size'] is None
        assert any('assembled from' in (a.get('detail') or '')
                   for a in case.activity())
        case.record_hashes(evidence_id, handler.calculate_hashes())
        handler.close_resources()
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_VERIFIED, outcome
        # A byte on the second device changes; the descriptor does not.
        with open(members[1], 'r+b') as member:
            member.seek(0x1500000)
            byte = member.read(1)
            member.seek(0x1500000)
            member.write(bytes([byte[0] ^ 0xff]))
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_CHANGED, outcome
    finally:
        handler.close_resources()
        case.close()


# --- md -------------------------------------------------------------------------


def _md_key():
    path = image_path(MD_KEY)
    with open(path, encoding='utf-8') as source:
        return {array['name']: array for array in json.load(source)['arrays']}


MD_NAMES = ['raid1', 'raid1v090', 'raid1v10', 'raid0', 'raid5', 'raid5ra',
            'raid6', 'raid10', 'raid1part']
REDUNDANT = ['raid1', 'raid1v090', 'raid1v10', 'raid5', 'raid5ra', 'raid6',
             'raid10']


def assert_md_files(handler, array):
    starts = [p[2] for p in handler.get_partitions()] or [0]
    start = next(s for s in starts if handler.get_fs_info(s) is not None)
    for record in array['files']:
        data = read_path(handler, record['path'], start)
        assert len(data) == record['size']
        assert hashlib.sha256(data).hexdigest() == record['sha256'], \
            record['path']


@pytest.mark.parametrize('name', MD_NAMES)
def test_an_md_array_reads_as_the_kernel_wrote_it(name, tmp_path):
    array = _md_key()[name]
    paths = [image_path(member) for member in array['members']]
    group, _path, handler = assemble(paths, tmp_path)
    try:
        assert group['kind'] == 'mdraid' and group['complete']
        assert f"RAID{array['level']}" in handler.container_note
        assert_md_files(handler, array)
    finally:
        handler.close_resources()


@pytest.mark.parametrize('name', [n for n in REDUNDANT if n.startswith(
    ('raid5', 'raid6', 'raid10'))])
def test_an_md_array_reads_with_a_member_missing(name, tmp_path):
    array = _md_key()[name]
    paths = [image_path(member) for member in array['members'][1:]]
    group, _path, handler = assemble(paths, tmp_path)
    try:
        assert not group['complete']
        assert_md_files(handler, array)
    finally:
        handler.close_resources()


@pytest.mark.parametrize('name', ['raid1', 'raid1v090', 'raid1v10',
                                  'raid1part'])
def test_one_mirror_member_reads_alone(name):
    """A RAID1 member is a whole copy: opened as plain evidence, its file
    system is found inside the member without any assembling."""
    from trace_app.core.image_handler import ImageHandler
    array = _md_key()[name]
    handler = ImageHandler(image_path(array['members'][0]))
    try:
        assert handler.loaded
        assert_md_files(handler, array)
    finally:
        handler.close_resources()


def test_a_raid5_member_alone_says_what_it_is():
    from trace_app.core.image_handler import ImageHandler
    array = _md_key()['raid5']
    handler = ImageHandler(image_path(array['members'][0]))
    try:
        assert handler.loaded
        assert handler.volume_kind(0) == 'mdraid'
        assert handler.get_fs_info(0) is None
    finally:
        handler.close_resources()


def test_the_dialog_offers_only_what_can_be_read():
    from trace_app.ui.dialogs.assemble import readable

    def group(kind, level, needed, found):
        return {'kind': kind, 'level': level, 'needed': needed,
                'members': [{'slot': n} for n in range(found)]}
    assert readable(group('mdraid', 5, 3, 3))[0]
    assert readable(group('mdraid', 5, 3, 2))[0]
    assert not readable(group('mdraid', 5, 4, 2))[0]
    assert readable(group('mdraid', 6, 4, 3))[0]
    assert not readable(group('mdraid', 6, 4, 2))[0]     # P only, not Q
    assert readable(group('mdraid', 1, 3, 1))[0]
    assert not readable(group('mdraid', 0, 2, 1))[0]
    assert readable(group('btrfs', None, 3, 2))[0]

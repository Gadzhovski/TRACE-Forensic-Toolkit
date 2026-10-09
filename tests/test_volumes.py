"""FileVault 2, APFS (plain and encrypted), LUKS and LVM volumes.

dfvfs's published test images (tools/testdata/samples.py), with the
passwords dfvfs's own tests use. Each holds the same small tree --
passwords.txt, a_directory/{a_file, another_file}, a_link -- so every
volume is checked the same way: it is recognised, unlocks only with the
right key, lists that tree and reads passwords.txt to the byte; and the
analysis pass reaches the files inside.
"""

import os
import tempfile

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
PASSWORDS_HEAD = b'place,user,password\nbank,joesmith,superr'


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def handler_for(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(sample(name))
    assert handler.loaded
    return handler


def names(handler, key, inode=None):
    inode = inode or handler.get_root_inode(key)
    return {e['name'] for e in handler.get_directory_contents(key, inode)}


def read(handler, key, name):
    entry = next(e for e in handler.get_directory_contents(
        key, handler.get_root_inode(key)) if e['name'] == name)
    content, _meta = handler.get_file_content(entry['inode_number'], key)
    return content


@pytest.mark.parametrize('image, start, kind, password, fs_type', [
    ('luks1.raw', 0, 'luks', 'luksde-TEST', 'Ext2'),
    ('fvdetest.qcow2', 40, 'fvde', 'fvde-TEST', 'HFS'),
])
def test_encrypted_volumes_unlock_in_place(image, start, kind, password,
                                           fs_type):
    from trace_app.core.containers import ContainerError
    handler = handler_for(image)
    try:
        assert handler.encryption(start) == kind
        assert handler.get_fs_info(start) is None        # locked: nothing
        with pytest.raises(ContainerError):
            handler.unlock_volume(start, kind, password='wrong')
        handler.unlock_volume(start, kind, password=password)
        assert handler.is_unlocked(start)
        assert handler.get_fs_type(start).startswith(fs_type)
        assert {'passwords.txt', 'a_directory'} <= names(handler, start)
        assert read(handler, start, 'passwords.txt').startswith(
            PASSWORDS_HEAD)
        assert start in handler.volume_offsets()
    finally:
        handler.close_resources()


def test_lvm_logical_volumes_are_volumes_of_their_own():
    from trace_app.core.containers import lvm_key, split_lvm_key, \
        split_shadow_key
    handler = handler_for('lvm.raw')
    try:
        assert handler.volume_kind(0) == 'lvm'
        volumes = handler.logical_volumes(0)
        assert [v['name'] for v in volumes] == ['test_logical_volume1',
                                                'test_logical_volume2']
        assert volumes[0]['group'] == 'test_volume_group'
        key = volumes[0]['key']
        assert key == lvm_key(0, 0) and split_lvm_key(key) == (0, 0)
        assert split_shadow_key(key) is None      # not mistaken for VSS
        assert read(handler, key, 'passwords.txt').startswith(PASSWORDS_HEAD)
        assert handler.volume_offsets() == [v['key'] for v in volumes]
    finally:
        handler.close_resources()


def test_apfs_through_libfsapfs_reads_like_any_file_system():
    import pytsk3
    handler = handler_for('apfs.raw')
    try:
        assert handler.volume_kind(0) == 'apfs'
        (volume,) = handler.apfs_volumes(0)
        assert volume['name'] == 'apfs_test' and not volume['locked']
        key = volume['key']
        assert handler.get_fs_type(key) == 'APFS'
        assert names(handler, key) == {'passwords.txt', 'a_directory',
                                       'a_link', '.fseventsd'}
        assert read(handler, key, 'passwords.txt').startswith(PASSWORDS_HEAD)
        folder = next(e for e in handler.get_directory_contents(
            key, handler.get_root_inode(key)) if e['name'] == 'a_directory')
        assert folder['is_directory']
        assert {'a_file', 'another_file'} <= names(handler, key,
                                                   folder['inode_number'])
        fs = handler.get_fs_info(key)
        link = fs.open('/a_link')
        assert link.info.meta.type == pytsk3.TSK_FS_META_TYPE_LNK
        assert link.info.meta.mtime > 1600000000       # seconds, UTC
    finally:
        handler.close_resources()


def test_an_encrypted_apfs_volume_needs_its_password():
    from trace_app.core.containers import ContainerError
    handler = handler_for('apfs_encrypted.dmg')
    try:
        (volume,) = handler.apfs_volumes(40)
        assert volume['locked']
        assert handler.get_fs_info(volume['key']) is None
        assert volume['key'] not in handler.volume_offsets()
        with pytest.raises(ContainerError):
            handler.unlock_apfs(volume['key'], password='wrong')
        handler.unlock_apfs(volume['key'], password='apfs-TEST')
        assert read(handler, volume['key'], 'passwords.txt').startswith(
            PASSWORDS_HEAD)
        assert volume['key'] in handler.volume_offsets()
    finally:
        handler.close_resources()


def test_a_background_job_gets_the_keys_with_their_kind():
    """What the window hands a job: {key: {'_kind', secret}}."""
    handler = handler_for('apfs_encrypted.dmg')
    try:
        (volume,) = handler.apfs_volumes(40)
        handler.apply_unlocks({volume['key']: {'_kind': 'apfs',
                                               'password': 'apfs-TEST'}})
        assert handler.is_unlocked(volume['key'])
    finally:
        handler.close_resources()
    handler = handler_for('luks1.raw')
    try:
        handler.apply_unlocks({0: {'_kind': 'luks',
                                   'password': 'luksde-TEST'}})
        assert handler.is_unlocked(0)
    finally:
        handler.close_resources()


@pytest.mark.parametrize('image, unlock', [
    ('apfs.raw', None),
    ('lvm.raw', None),
    ('ufs1.raw', None),
    ('ufs2.raw', None),
    ('xfs.raw', None),
    ('luks1.raw', {0: {'_kind': 'luks', 'password': 'luksde-TEST'}}),
])
def test_analysis_reaches_the_files_inside(image, unlock):
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    handler = handler_for(image)
    handler.apply_unlocks(unlock)
    case = Case.create(os.path.join(tempfile.mkdtemp(), 'case'), 'volumes')
    try:
        evidence_id = case.add_evidence(sample(image))
        analyse_evidence(handler, case, evidence_id, ['hash'])
        paths = {r[0] for r in case._db.execute(
            "SELECT path FROM file_analysis")}
        assert {'/passwords.txt', '/a_directory/a_file'} <= paths
    finally:
        case.close()
        handler.close_resources()


@pytest.mark.parametrize('image, label', [('ufs1.raw', 'UFS1'),
                                          ('ufs2.raw', 'UFS2')])
def test_ufs_is_named_and_read(image, label):
    """TSK reads UFS1 and UFS2, and TRACE called them "Unknown" (its type
    map had no FFS entries): named now, in the tree and on the Evidence
    page alike."""
    from trace_app.core.evidence_probe import probe
    handler = handler_for(image)
    try:
        start = next(p[2] for p in handler.get_partitions()
                     if handler.get_fs_info(p[2]) is not None)
        assert handler.get_fs_type(start) == label
        names = {e['name'] for e in handler.get_directory_contents(
            start, handler.get_root_inode(start))}
        assert {'passwords.txt', 'a_directory', 'a_link'} <= names
    finally:
        handler.close_resources()
    assert label in probe(sample(image))['contents']


@pytest.mark.parametrize('image, unlock', [
    ('apfs.raw', None),
    ('xfs.raw', None),
    ('lvm.raw', None),
    ('ufs2.raw', None),
    ('luks1.raw', {0: {'_kind': 'luks', 'password': 'luksde-TEST'}}),
])
def test_name_search_and_links_inside_every_volume(image, unlock):
    """The Listing's search reads the volume TRACE opened -- LVM, APFS,
    an unlocked LUKS, XFS -- not the image path reopened as a raw image,
    which found nothing in any of them. A link reads as its target, as
    TSK reads one: libfsxfs refused to read a link's data, and APFS
    reported its size as 0."""
    handler = handler_for(image)
    try:
        handler.apply_unlocks(unlock)
        found = handler.search_files('passwords')
        assert [r['name'] for r in found] == ['passwords.txt']
        key, inode = found[0]['start_offset'], found[0]['inode_number']
        assert handler.get_file_content(inode, key)[0].startswith(
            PASSWORDS_HEAD)
        assert {r['name'] for r in handler.search_files('.txt')} == \
            {'passwords.txt'}
        link = next(r for r in handler.search_files('a_link'))
        if image in ('apfs.raw', 'xfs.raw'):
            target, _meta = handler.get_file_content(link['inode_number'],
                                                     link['start_offset'])
            assert target == b'a_directory/another_file'
            assert link['size'] == len(target)
    finally:
        handler.close_resources()


@pytest.mark.parametrize('image', ['xfs.raw', 'apfs.raw'])
def test_carving_does_not_take_live_files_for_free_space(image):
    """XFS and APFS entries carry no TSK runs, so carving's map was empty
    (an APFS container was not even a file system to it) and live files
    were carved as deleted. Their extents are in the map now: the bytes
    it marks used include passwords.txt's."""
    from trace_app.core import carving
    handler = handler_for(image)
    try:
        ranges = carving.allocation_map(handler)
        assert any(PASSWORDS_HEAD in handler.read(begin, end - begin)
                   for begin, end in ranges)
        assert sum(e - b for b, e in ranges) < handler.get_size() // 2
    finally:
        handler.close_resources()


def test_lvm_is_carved_volume_by_volume():
    """An LVM partition's raw bytes are extents in the group's order, not
    any volume's: they count as used, and each logical volume is carved in
    its own address range instead, its live files skipped there -- read
    back through the handler like any other offset."""
    from trace_app.core import carving
    handler = handler_for('lvm.raw')
    try:
        volumes = carving.carve_volumes(handler)
        assert [v['label'] for v in volumes] == [
            'LVM volume test_volume_group/test_logical_volume1',
            'LVM volume test_volume_group/test_logical_volume2']
        assert all(v['base'] >= handler.CARVE_SPACE for v in volumes)
        ranges = carving.allocation_map(handler)
        assert ranges[0] == (0, handler.get_size())
        first = volumes[0]
        inside = [(b, e) for b, e in ranges
                  if first['base'] <= b < first['base'] + first['size']]
        assert inside                      # ext2's live blocks
        lv = handler._volumes[first['key']]
        begin, end = inside[0]
        assert handler.read(begin, end - begin) == \
            lv.read(begin - first['base'], end - begin)
        assert carving.carve_extent(handler) == handler.get_size() + sum(
            v['size'] for v in volumes)
    finally:
        handler.close_resources()


def test_a_locked_volume_is_not_carved_and_says_so(caplog):
    import logging
    from trace_app.core import carving
    handler = handler_for('luks1.raw')
    try:
        caplog.set_level(logging.WARNING, logger='TRACE.Carving')
        assert carving.allocation_map(handler) == [(0, handler.get_size())]
        assert 'unlock it to carve' in caplog.text
        assert carving.carve_volumes(handler) == []
        handler.unlock_volume(0, 'luks', password='luksde-TEST')
        (volume,) = carving.carve_volumes(handler)
        assert volume['label'] == 'decrypted LUKS volume at sector 0'
    finally:
        handler.close_resources()


def test_xfs_is_read_where_tsk_cannot():
    """TSK (4.15) does not read XFS; libfsxfs does, shaped like pytsk3: the
    file system is named, listed with its times, read, and an unpartitioned
    XFS image is not mistaken for a wiped one."""
    import pytsk3
    from trace_app.core.evidence_probe import probe
    from trace_app.core.xfs import is_xfs, superblock_geometry
    with open(sample('xfs.raw'), 'rb') as handle:
        head = handle.read(512)
    with pytest.raises(OSError):
        pytsk3.FS_Info(pytsk3.Img_Info(sample('xfs.raw')))
    assert superblock_geometry(head) == (4096, 16 * 1024 * 1024)
    handler = handler_for('xfs.raw')
    try:
        assert not handler.is_wiped() and is_xfs(handler.get_fs_info(0))
        assert handler.get_fs_type(0) == 'XFS'
        entries = {e['name']: e for e in handler.get_directory_contents(
            0, handler.get_root_inode(0))}
        assert {'a_directory', 'passwords.txt', 'a_link'} <= set(entries)
        content, _meta = handler.get_file_content(
            entries['passwords.txt']['inode_number'], 0)
        assert content.startswith(b'place,user,password\nbank,joesmith')
        assert 'XFS' in handler.detect_filesystems(0)
    finally:
        handler.close_resources()
    assert probe(sample('xfs.raw'))['contents'] == 'XFS'

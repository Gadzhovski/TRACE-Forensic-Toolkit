"""FileVault 2, APFS (plain and encrypted), LUKS and LVM volumes.

dfvfs's published test images (tools/fetch_artifact_samples.py), with the
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

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
PASSWORDS_HEAD = b'place,user,password\nbank,joesmith,superr'


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
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

"""The Sleuth Kit's own test images (sleuthkit/sleuthkit_test_data,
fetched and SHA-256 pinned by tools/testdata/samples.py).

Expected values come from outside TRACE: the DFXML fiwalk wrote for four
of them (every file's path, size, allocation and MD5), the MD5 each E01
stores, the DFTT #1 answer key (six FAT16 partitions at published
sectors), and the GPT entries read straight from the disk.

Found by these images: an E01 of a source that was not a whole number of
sectors keeps its last bytes past the media (TRACE called them damaged
and the stored MD5 a mismatch; libewf still does); a Btrfs snapshot's
placeholder for a nested subvolume had identifier 0 -- the root's -- so
opening it listed the root again; a volume at sector 0 took the MBR
slot's name.
"""

import hashlib
import os
import xml.etree.ElementTree as ElementTree
import zipfile

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
E01S = ['tsk-apfs-apfs_pool.E01', 'tsk-btrfs-btrfs_testimage_50MB.E01',
        'tsk-btrfs-btrfs_zstd.E01', 'tsk-exfat-exfat1.E01',
        'tsk-from_brian-6-fat-undel.E01',
        'tsk-from_brian-fat32_with_efs_file.E01',
        'tsk-from_brian-imageformat_mmls_1.E01',
        'tsk-fuzzing-lvm_test_issue_3235.E01',
        'tsk-gpt-gpt_130_partitions.E01', 'tsk-ufs-image.E01',
        'tsk-xfs-xfs-raw-2GB.E01']


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        message = f"{name} is missing -- run python -m tools.testdata.fetch --group samples"
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    return path


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return handler


@pytest.mark.parametrize('name', E01S)
def test_every_e01_hashes_to_what_it_stores(name):
    from trace_app.core.case import STATUS_VERIFIED, verdict
    handler = _handler(sample(name))
    try:
        results = handler.calculate_hashes()
    finally:
        handler.close_resources()
    assert results['computed_md5'] == results['stored_md5']
    assert not results.get('damaged')
    assert verdict(results)['status'] == STATUS_VERIFIED


def test_bytes_past_the_last_whole_sector_are_hashed_not_damage():
    """btrfs_testimage_50MB came from a 50,000,000-byte file: 97,656
    sectors of media and 128 bytes more in the last chunk, which the
    stored MD5 covers."""
    handler = _handler(sample('tsk-btrfs-btrfs_testimage_50MB.E01'))
    try:
        assert handler.get_size() == 49_999_872
        results = handler.calculate_hashes()
    finally:
        handler.close_resources()
    assert results['size'] == 50_000_000
    assert results['beyond_media'] == 128


# --- every file, against fiwalk's DFXML ----------------------------------------

def _dfxml(name):
    """{(volume byte offset, path): (size, md5)} of regular files."""
    root = ElementTree.parse(sample(name)).getroot()
    found = {}
    for volume in (e for e in root.iter() if e.tag.endswith('volume')):
        offset = int(volume.get('offset', 0))
        for item in (e for e in volume.iter()
                     if e.tag.endswith('fileobject')):
            fields = {c.tag.split('}')[-1]: c for c in item}
            if getattr(fields.get('meta_type'), 'text', '') != '1':
                continue
            md5 = next(((c.text or '').lower() for c in item
                        if c.tag.endswith('hashdigest') and
                        c.get('type') == 'md5'), '') or None
            path = '/' + (fields['filename'].text or '').lstrip('/')
            if path.startswith('/$OrphanFiles/'):
                continue                    # TSK's virtual folder
            found[(offset, path)] = (int(fields['filesize'].text or 0), md5)
    return found


def _trace(handler):
    """{(volume byte offset, path): (size, md5)} of every name TRACE
    lists for a regular file -- hard links each under their own name."""
    from trace_app.core import walk
    from trace_app.core.case import parse_artifact_ref
    names = []
    list(walk.iter_files(handler, every_name=lambda offset, path, deleted,
                         ref: names.append((offset, path, ref))))
    found = {}
    for offset, path, ref in names:
        fs = handler.get_fs_info(offset)
        try:
            entry = fs.open_meta(inode=parse_artifact_ref(ref)['inode'])
            meta = entry.info.meta
            if int(meta.type) != 1:                 # regular files only
                continue
            size = int(meta.size)
            data = entry.read_random(0, size) if size else b''
        except Exception:
            continue
        base = offset * handler.sector_size if offset < 2 ** 48 else offset
        found[(base, path)] = (size, hashlib.md5(data).hexdigest())
    return found


@pytest.mark.parametrize('image, xml, unread', [
    ('tsk-from_brian-imageformat_mmls_1.E01',
     'tsk-from_brian-imageformat_mmls_1.E01.xml', set()),
    ('tsk-ufs-image.E01', 'tsk-ufs-image_dd.xml', set()),
    ('tsk-from_brian-6-fat-undel.E01', 'tsk-from_brian-6-fat-undel.dd.xml',
     set()),
    # TSK shows a Btrfs snapshot's nested subvolume with the subvolume's
    # files; Linux shows an empty directory (no ROOT_REF from the
    # snapshot), and so does TRACE.
    ('tsk-btrfs-btrfs_testimage_50MB.E01',
     'tsk-btrfs-btrfs_testimage_50MB.E01.xml',
     {'/snapshot/subvol/file_regular_again'}),
])
def test_every_file_matches_fiwalks_dfxml(image, xml, unread):
    expected = _dfxml(xml)
    handler = _handler(sample(image))
    try:
        found = _trace(handler)
    finally:
        handler.close_resources()
    for key, (size, md5) in expected.items():
        if key[1] in unread:
            assert key not in found
            continue
        assert key in found, key
        assert found[key][0] == size, key
        # fiwalk hashes a stream of NTFS's $Secure while giving its size
        # as 0: an empty file's hash says nothing.
        if md5 and size:
            assert found[key][1] == md5, key


# --- partitions ---------------------------------------------------------------

def test_dftt_1_six_fat16_partitions_in_nested_extended_tables(tmp_path):
    """DFTT #1's answer key: six FAT16 partitions -- the third entry of an
    extended table made by hand among them -- each holding one empty file
    named after it."""
    with zipfile.ZipFile(sample('tsk-from_brian-1-extend-part.zip')) as z:
        z.extract('1-extend-part/ext-part-test-2.dd', tmp_path)
    handler = _handler(str(tmp_path / '1-extend-part' / 'ext-part-test-2.dd'))
    try:
        found = {}
        for start in (63, 52416, 104832, 157311, 209727, 262143):
            assert handler.get_fs_type(start) == 'FAT16', start
            found[start] = [e['name'] for e in handler.get_directory_contents(
                start, handler.get_root_inode(start))
                if not e['name'].startswith('$')]
    finally:
        handler.close_resources()
    assert found == {63: ['primary-1.txt'], 52416: ['primary-2.txt'],
                     104832: ['primary-3.txt'], 157311: ['second-1.txt'],
                     209727: ['second-2.txt'], 262143: ['second-3.txt']}


def test_a_gpt_with_more_than_128_entries():
    from trace_app.core import partition_names
    handler = _handler(sample('tsk-gpt-gpt_130_partitions.E01'))
    try:
        partitions = [p for p in handler.get_partitions()
                      if partition_names.bookkeeping(p[1].decode()) is None]
        entries = partition_names.gpt_entries(handler.read, 512)
    finally:
        handler.close_resources()
    assert len(partitions) == len(entries) == 131
    assert [p[2] for p in partitions] == sorted(entries)


def test_a_volume_at_sector_zero_is_named_by_its_partition():
    handler = _handler(sample('tsk-fuzzing-clusterfuzz-testcase-minimized-'
                              'sleuthkit_fls_ntfs_fuzzer-5124116049166336'))
    try:
        assert handler.get_fs_type(0) == 'NTFS'
        assert handler.partition_label(0) == 'Empty (0x00) @ 0'
        handler.get_directory_contents(0, handler.get_root_inode(0))
    finally:
        handler.close_resources()


# --- volumes -----------------------------------------------------------------

def test_a_btrfs_snapshots_nested_subvolume_is_an_empty_folder():
    handler = _handler(sample('tsk-btrfs-btrfs_testimage_50MB.E01'))
    try:
        root = handler.get_root_inode(0)

        def child(inode, name):
            return next(e for e in handler.get_directory_contents(0, inode)
                        if e['name'] == name)
        placeholder = child(child(root, 'snapshot')['inode_number'],
                            'subvol')
        assert placeholder['is_directory']
        assert placeholder['inode_number'] not in (0, root)
        assert [e for e in handler.get_directory_contents(
            0, placeholder['inode_number'])
            if e['name'] not in ('.', '..')] == []
        # The live subvolume still has its file.
        live = child(root, 'subvol')
        assert [e['name'] for e in handler.get_directory_contents(
            0, live['inode_number'])] == ['file_regular_again']
    finally:
        handler.close_resources()


def test_apfs_pool_lvm_xfs_and_a_zstd_btrfs_open():
    from trace_app.core import walk
    expected = {'tsk-apfs-apfs_pool.E01': {'/test.txt', '/test2.txt',
                                           '/teste3.txt'},
                'tsk-fuzzing-lvm_test_issue_3235.E01': {'/teste1.txt',
                                                        '/teste2.txt',
                                                        '/teste3.txt'},
                'tsk-xfs-xfs-raw-2GB.E01': {'/notes.txt'},
                'tsk-btrfs-btrfs_zstd.E01': {'/test'}}
    for name, wanted in expected.items():
        handler = _handler(sample(name))
        try:
            names = set()
            list(walk.iter_files(handler, every_name=lambda o, path, d, r:
                                 names.add(path)))
        finally:
            handler.close_resources()
        assert wanted <= names, name

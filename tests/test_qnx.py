"""QNX file systems read by TRACE itself (core/qnx6.py): images made by
QNX's own tools, with the tar of the files put on each, from
NetherlandsForensicInstitute/qnxmount's test data (tools/testdata/
samples.py). Every file's path, size, SHA-256 and link target must equal
the tar's."""

import hashlib
import os
import shutil
import tarfile

import pytest
import pytsk3

from tests.conftest import data_path


def _truth(tar_name):
    """{path: ('dir',) | ('link', target) | ('file', size, sha256)} of the
    files qnxmount put on the image (its tar, made from the mount), and
    {path: (permissions, mtime, uid, gid)} -- what qnxmount's own tests
    compare."""
    out, attributes = {}, {}
    with tarfile.open(data_path('samples', tar_name)) as tar:
        for member in tar:
            name = member.name.lstrip('./')
            if not name:
                continue
            attributes[name] = (member.mode & 0o7777, member.mtime,
                                member.uid, member.gid)
            if member.isdir():
                out[name] = ('dir',)
            elif member.issym():
                out[name] = ('link', member.linkname)
            elif member.isfile():
                data = tar.extractfile(member).read()
                out[name] = ('file', member.size,
                             hashlib.sha256(data).hexdigest())
    return out, attributes


def _listing(fs, skip=()):
    """The same shapes, read through TRACE's file-system objects."""
    out, attributes = {}, {}

    def walk(directory, path):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            full = f"{path}/{name}".lstrip('/')
            if full in skip:
                continue
            meta = entry.info.meta
            attributes[full] = (meta.mode & 0o7777, meta.mtime, meta.uid,
                                meta.gid)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                out[full] = ('dir',)
                walk(entry.as_directory(), '/' + full)
            elif meta.type == pytsk3.TSK_FS_META_TYPE_LNK:
                out[full] = ('link', meta.link)
            elif meta.size or full not in _SPECIAL:
                data = entry.read_random(0, meta.size)
                out[full] = ('file', meta.size,
                             hashlib.sha256(data).hexdigest())
    walk(fs.open_dir(path='/'), '')
    return out, attributes


def _same(fs, tar_name, skip=()):
    """The file system read by TRACE equals the tar: every path, kind,
    size, SHA-256, link target, permission, mtime, owner."""
    mine, mine_attributes = _listing(fs, skip)
    truth, attributes = _truth(tar_name)
    assert {k: v for k, v in mine.items() if k not in _SPECIAL} == \
        {k: v for k, v in truth.items() if k not in _SPECIAL}
    assert {k: v for k, v in mine_attributes.items() if k in attributes} \
        == attributes
    return truth


#: Not regular files in the tar (a FIFO): TRACE lists it as an empty file.
_SPECIAL = {'this_is_a_fifo'}


def _image(tmp_path, name):
    target = tmp_path / name.split('-', 2)[-1]
    shutil.copy(data_path('samples', name), target)
    return str(target)


def test_qnx6_reads_every_file_as_mkqnx6fs_wrote_it(tmp_path):
    """qnxmount's QNX6 image (mkqnx6fs, 1 KiB blocks): a small file, a
    large one rewritten in the middle, a renamed, a copied and a moved
    file, a 27-character name, symlinks to files, links and a folder,
    permissions -- opened by ImageHandler as any evidence is."""
    from trace_app.core import evidence_profile
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(_image(tmp_path, 'qnxmount-qnx6-test_image.bin'))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'QNX6'
        fs = handler.get_fs_info(0)
        truth = _same(fs, 'qnxmount-qnx6-test_image.tar.gz', skip={'.boot'})
        assert truth['directory_1/link_message.txt'] == \
            ('link', 'directory_1_1/message.txt')
        content, _meta = handler.get_file_content(
            next(e['inode_number'] for e in handler.get_directory_contents(
                0, fs.info.root_inum) if e['name'] == 'this_file_is_large'),
            0)
        assert len(content) == truth['this_file_is_large'][1]
        assert hashlib.sha256(content).hexdigest() == \
            truth['this_file_is_large'][2]
        # A head unit's file system: VLEAPP suits it, and TRACE stages its
        # files rather than handing over the image.
        assert 'vehicle' in evidence_profile.tool_systems(handler)
        assert evidence_profile.unreadable_signatures(handler) == []
    finally:
        handler.close_resources()


def test_qnx6_takes_the_newer_superblock_and_falls_back_to_the_older(
        tmp_path):
    """The two superblocks are written in turn: the valid one with the
    higher serial is the file system now. Damage that one and the older
    state is read -- here, the fresh file system, before any file."""
    from trace_app.core import qnx6
    path = _image(tmp_path, 'qnxmount-qnx6-test_image.bin')
    with open(path, 'rb') as handle:
        fs = qnx6.open_qnx6(handle)
        assert fs.image.superblock.serial == 2
        assert len(fs.image.superblocks) == 2
        names = [e.info.name.name for e in fs.open_dir(path='/')]
        assert b'this_file_is_small' in names
        # The bitmap and the superblock agree on what is used.
        used = sum(end - begin for begin, end in fs.allocated_ranges()
                   if begin >= qnx6.BOOT_AREA + qnx6.SUPERBLOCK_AREA and
                   end <= fs.image.size - qnx6.SUPERBLOCK_AREA)
        sb = fs.image.superblock
        assert used // fs.image.block_size == \
            sb.block_count - sb.free_blocks
        newer = fs.image.superblock.where
    with open(path, 'r+b') as handle:
        handle.seek(newer + 100)
        byte = handle.read(1)
        handle.seek(newer + 100)
        handle.write(bytes([byte[0] ^ 0xFF]))
    with open(path, 'rb') as handle:
        fs = qnx6.open_qnx6(handle)
        assert fs.image.superblock.serial == 1
        assert [e.info.name.name for e in fs.open_dir(path='/')] == \
            [b'.boot']


def test_qnx6_is_found_by_its_superblock_in_either_byte_order():
    from trace_app.core import qnx6
    head = bytearray(qnx6.BOOT_AREA + 4)
    assert qnx6.byte_order(bytes(head)) is None
    head[qnx6.BOOT_AREA:] = b'\x22\x11\x19\x68'
    assert qnx6.byte_order(bytes(head)) == '<'
    head[qnx6.BOOT_AREA:] = b'\x68\x19\x11\x22'
    assert qnx6.byte_order(bytes(head)) == '>'
    # The kernel's crc32_be (MSB first): the standard check value.
    assert qnx6.crc32_be(b'123456789') == 0x89A1897F


def test_etfs_is_replayed_from_its_pages_records(tmp_path):
    """qnxmount's ETFS image (mketfs, 1 KiB pages, no superblock): the file
    system is what its pages' transaction records replay to, and equals
    the tar -- a 32-character name in its extension entry too. The older
    layout's image has no published tar: it opens and lists."""
    from trace_app.core import evidence_profile
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(_image(tmp_path, 'qnxmount-etfs-test_image.bin'))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'QNX ETFS'
        fs = handler.get_fs_info(0)
        assert fs.image.page_size == 1024
        truth = _same(fs, 'qnxmount-etfs-test_image.tar.gz')
        assert 'this_file_is_32_characters_long_' in truth
        assert 'vehicle' in evidence_profile.tool_systems(handler)
    finally:
        handler.close_resources()
    from trace_app.core import qnx_etfs
    with open(data_path('samples', 'qnxmount-etfs-old_test_image.bin'),
              'rb') as handle:
        old = qnx_etfs.open_etfs(handle)
        names = [e.info.name.name for e in old.open_dir(path='/')]
        assert b'this_file_is_small' in names


def test_etfs_is_not_taken_for_other_data():
    """No superblock: random data of a size pages would divide must not
    read as ETFS."""
    import io
    import os
    from trace_app.core import qnx_etfs
    assert qnx_etfs.open_etfs(io.BytesIO(os.urandom(1040 * 64))) is None
    assert qnx_etfs.open_etfs(io.BytesIO(bytes(1040 * 64))) is None


def test_efs_reads_mkefs_and_both_byte_orders(tmp_path):
    """qnxmount's EFS image (mkefs, 128 KiB units) equals its tar; and
    qnxprobe's flash images, little- and big-endian, each with two EFS
    partitions behind a decoy signature, equal the contents it recorded
    -- every file's mode, mtime, size and SHA-256, every link and folder."""
    import gzip
    import io
    import json
    import stat
    from trace_app.core import evidence_profile, qnx_efs
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(_image(tmp_path, 'qnxmount-efs-test_image.bin'))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'QNX EFS'
        _same(handler.get_fs_info(0), 'qnxmount-efs-test_image.tar.gz')
        assert 'vehicle' in evidence_profile.tool_systems(handler)
    finally:
        handler.close_resources()
    with open(data_path('samples', 'qnxprobe-efs.known.json')) as handle:
        known = json.load(handle)['partitions']
    for name, order in (('qnxprobe-efs-le.img.gz', '<'),
                        ('qnxprobe-efs-be.img.gz', '>')):
        data = gzip.open(data_path('samples', name)).read()
        found = qnx_efs.partitions(io.BytesIO(data))
        assert [p.base for p in found] == [k['base'] for k in known]
        assert {p.order for p in found} == {order}
        for partition, expect in zip(found, known):
            assert partition.unit_size == expect['unit_size']
            assert partition.unit_total == expect['unit_total']
            files, dirs, links = {}, {}, {}
            pending = [(qnx_efs.EfsFileSystem(partition).volume
                        .get_root_directory(), '')]
            while pending:
                entry, path = pending.pop()
                for index in range(entry.number_of_sub_file_entries):
                    child = entry.get_sub_file_entry(index)
                    full = f"{path}/{child.name}".lstrip('/')
                    shape = {'mode': child.file_mode,
                             'mtime': child.get_modification_time_as_integer()
                             // 1_000_000_000}
                    if stat.S_ISDIR(child.file_mode):
                        dirs[full] = shape
                        pending.append((child, full))
                    elif stat.S_ISLNK(child.file_mode):
                        links[full] = dict(shape,
                                           target=child.symbolic_link_target)
                    else:
                        content = child.read_buffer_at_offset(child.size, 0)
                        files[full] = dict(
                            shape, size=child.size,
                            sha256=hashlib.sha256(content).hexdigest())
            assert files == expect['files']
            assert dirs == expect['dirs']
            assert links == expect['symlinks']
    # A disk of another kind is not read whole looking for EFS.
    assert qnx_efs.partitions(io.BytesIO(b''), size=qnx_efs.MAX_SCAN + 1) \
        == []

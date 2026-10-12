"""Android sparse and super images, VirtualBox VDI, AFF and compressed raw
images (core/android_sparse.py, android_super.py, vdi.py, aff.py,
compressed_disk.py, disk_containers.py), checked against containers their
own tools wrote.

tools/testdata/build/make_container_images.py writes one GPT disk (ext4
with a known tree) into each: img2simg, lpmake (AOSP liblp, built there),
qemu-img, affconvert, gzip, xz, zstd, bzip2, pbzip2 and lz4 -- and reads
each back with the tool's own reader (simg2img, lpunpack, qemu-img,
affcat, the decompressors) for the answer. Every container must read as
exactly that disk; every super partition as lpunpack extracts it. Linux CI
builds the images; these tests skip elsewhere.
"""

import hashlib
import json
import os
import random
import struct
import zipfile

import pytest

from tests.conftest import image_path
from trace_app.core import (aff, android_sparse, android_super,
                            compressed_disk, disk_containers, vdi)

KEY = 'container-images-key.json'

DISKS = ['sparse-fs.simg', 'sparse-disk.simg', 'disk.vdi', 'disk-fixed.vdi',
         'disk.aff', 'disk-lzma.aff', 'disk-plain.aff',
         # Split AFF: a folder of .aff files, and AFMs with raw files.
         'disk.afd', 'aff-split/disk-split.afm', 'aff-split/disk-one.afm',
         'disk.raw.gz',
         'disk-members.raw.gz', 'disk.raw.xz', 'disk-blocks.raw.xz',
         'disk.raw.zst', 'disk-frames.raw.zst', 'disk.raw.bz2',
         'disk-streams.raw.bz2', 'disk.raw.lz4', 'disk-linked.raw.lz4']


def _key():
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)


def _open(name):
    image, _note = disk_containers.open_container(image_path(name))
    return image


def _sha256(image):
    digest = hashlib.sha256()
    offset, size = 0, image.get_size()
    while offset < size:
        # Odd-sized reads, across every piece boundary.
        chunk = image.read(offset, min(777_777, size - offset))
        assert chunk, offset
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


# --- every container reads as the disk it holds ------------------------------

@pytest.mark.parametrize('name', DISKS)
def test_container_reads_as_its_disk(name):
    key = _key()
    holds = key[key['images'][name]['holds']]
    image = _open(name)
    try:
        assert image.get_size() == holds['size']
        assert _sha256(image) == holds['sha256']
        # Reads anywhere, in any order, agree with a reading from the start.
        whole = image.read(0, image.get_size())
        rng = random.Random(name)
        for _ in range(30):
            offset = rng.randrange(0, image.get_size() - 10_000)
            length = rng.randrange(1, 10_000)
            assert image.read(offset, length) == whole[offset:offset +
                                                          length]
    finally:
        image.close()


@pytest.mark.parametrize('name', ['sparse-disk.simg', 'disk.vdi', 'disk.aff',
                                  'disk.afd', 'aff-split/disk-split.afm',
                                  'disk-blocks.raw.xz', 'disk.raw.gz'])
def test_opened_as_evidence_and_hashed_as_the_disk(name):
    from trace_app.core.image_handler import ImageHandler
    key = _key()
    handler = ImageHandler(image_path(name))
    try:
        assert handler.get_image_type() == 'container' and handler.loaded
        starts = [p[2] for p in handler.get_partitions()]
        assert 2048 in starts                    # the GPT partition
        assert handler.get_fs_type(2048) == 'Ext4'
        root = {e['name']: e for e in handler.get_directory_contents(2048)}
        data, _meta = handler.get_file_content(
            root['README.txt']['inode_number'], 2048)
        assert hashlib.sha256(data).hexdigest() == \
            key['tree']['/README.txt']
        result = handler.calculate_hashes()
        assert result['computed_sha256'] == key['disk']['sha256']
        if name.endswith('.aff'):
            # The image's own record of itself, for the verdict: what
            # affinfo -m validated when the image was built.
            assert 'MATCH' in key['images'][name]['affinfo']
        if name.endswith(('.aff', '.afd', '.afm')):
            assert result['stored_md5'] == result['computed_md5']
    finally:
        handler.close_resources()


def test_a_sparse_image_named_img_is_still_read_as_one(tmp_path):
    """Android tools name sparse images .img: content decides."""
    from trace_app.core.image_handler import ImageHandler
    copy = tmp_path / 'system.img'
    copy.write_bytes(open(image_path('sparse-fs.simg'), 'rb').read())
    handler = ImageHandler(str(copy))
    try:
        assert handler.get_image_type() == 'container'
        assert handler.get_fs_type(0) == 'Ext4'
    finally:
        handler.close_resources()


# --- Android super ------------------------------------------------------------

@pytest.mark.parametrize('name', ['super.img', 'super-sparse.img'])
def test_super_partitions_read_as_lpunpack_extracts_them(name):
    from trace_app.core.image_handler import ImageHandler
    key = _key()
    expected = key['images'][name]['partitions']
    handler = ImageHandler(image_path(name))
    try:
        assert handler.volume_kind(0) == 'android_super'
        volumes = {v['name']: v for v in handler.logical_volumes(0)}
        # The empty one is listed by liblp, but holds nothing to read.
        assert set(volumes) == {n for n, p in expected.items() if p['size']}
        for name_, volume in volumes.items():
            image = handler._volumes[volume['key']]
            assert image.get_size() == expected[name_]['size']
            assert _sha256(image) == expected[name_]['sha256']
            assert volume['group'] == 'main'
        assert handler.get_fs_type(volumes['system_a']['key']) == 'Ext4'
        assert handler.get_fs_type(volumes['vendor_a']['key']) == 'EROFS'
        # Every reader reaches them: they are among the volumes analysed.
        assert {v['key'] for v in volumes.values()} <= \
            set(handler.volume_offsets())
    finally:
        handler.close_resources()


def test_super_metadata_checksums_are_checked():
    data = bytearray(open(image_path('super.img'), 'rb').read(1 << 20))

    def read(offset, length):
        return bytes(data[offset:offset + length])

    android_super.SuperImage(read)
    # Damage the primary metadata: the backup is read instead.
    primary = android_super.RESERVED + 2 * android_super.GEOMETRY_SIZE
    data[primary + 200] ^= 0xFF
    assert [p.name for p in android_super.SuperImage(read).partitions] == \
        ['system_a', 'vendor_a', 'product_a']
    # Both geometries damaged: not liblp.
    data[android_super.RESERVED + 50] ^= 0xFF
    data[android_super.RESERVED + android_super.GEOMETRY_SIZE + 50] ^= 0xFF
    with pytest.raises(android_super.SuperError):
        android_super.SuperImage(read)


# --- the slow paths, forced ----------------------------------------------------

@pytest.mark.parametrize('name', ['disk.raw.gz', 'disk.raw.xz',
                                  'disk.raw.zst', 'disk.raw.bz2'])
def test_single_streams_read_correctly_when_they_cannot_be_split(
        monkeypatch, name):
    """Pieces over MAX_PIECE are read forward; gzip copies its state every
    GZIP_INTERVAL. Lowered so a small image takes those paths."""
    monkeypatch.setattr(compressed_disk, 'MAX_PIECE', 1 << 20)
    monkeypatch.setattr(compressed_disk, 'GZIP_INTERVAL', 1 << 20)
    disk = compressed_disk.CompressedDisk(image_path(name))
    try:
        if name.endswith('.gz'):
            assert len(disk.pieces) > 1 and disk.sequential is None
        else:
            assert disk.sequential is not None
            assert 'read in order' in disk.describe()
        whole = disk.read_buffer_at_offset(disk.get_size(), 0)
        assert hashlib.sha256(whole).hexdigest() == _key()['disk']['sha256']
        rng = random.Random(7)
        for _ in range(20):
            offset = rng.randrange(0, disk.get_size() - 5000)
            assert disk.read_buffer_at_offset(4000, offset) == \
                whole[offset:offset + 4000]
    finally:
        disk.close()


# --- VDI snapshots, AFF encryption, UFDR -------------------------------------------

def _vdi_header(path):
    with open(path, 'rb') as handle:
        return bytearray(handle.read())


def test_vdi_snapshot_reads_through_its_parent(tmp_path):
    """A differencing VDI (VirtualBox snapshot) whose blocks are all
    unwritten reads as its parent, found by the UUID it names; with the
    parent gone, it says which it needs."""
    import uuid
    base = _vdi_header(image_path('disk.vdi'))
    parent_uuid = uuid.UUID(bytes_le=bytes(base[0x188:0x198]))
    (tmp_path / 'base.vdi').write_bytes(bytes(base))
    child = bytearray(base)
    struct.pack_into('<I', child, 0x4C, vdi.TYPE_DIFF)
    child[0x188:0x198] = uuid.uuid4().bytes_le
    child[0x1A8:0x1B8] = parent_uuid.bytes_le
    blocks_at = struct.unpack_from('<I', child, 0x154)[0]
    count = struct.unpack_from('<I', child, 0x180)[0]
    struct.pack_into(f'<{count}I', child, blocks_at,
                     *([vdi.BLOCK_FREE] * count))
    snapshots = tmp_path / 'Snapshots'
    snapshots.mkdir()
    (snapshots / 'snap.vdi').write_bytes(bytes(child))
    disk = vdi.VdiDisk(str(snapshots / 'snap.vdi'))
    try:
        assert disk.parent is not None
        digest = hashlib.sha256(disk.read_buffer_at_offset(
            disk.get_size(), 0)).hexdigest()
        assert digest == _key()['disk']['sha256']
        assert 'base.vdi' in disk.describe()
    finally:
        disk.close()
    os.remove(tmp_path / 'base.vdi')
    with pytest.raises(vdi.VdiError, match=str(parent_uuid)):
        vdi.VdiDisk(str(snapshots / 'snap.vdi'))


def _segment(name, data=b'', argument=0):
    name = name.encode()
    body = aff.SEGMENT_HEAD + struct.pack('>III', len(name), len(data),
                                          argument) + name + data
    return body + aff.SEGMENT_TAIL + struct.pack('>I', len(body) + 8)


def test_aff_encrypted_is_refused_by_name(tmp_path):
    path = tmp_path / 'secret.aff'
    path.write_bytes(aff.FILE_HEADER + _segment('pagesize', argument=4096)
                     + _segment('page0/aes256', b'\0' * 32))
    with pytest.raises(aff.AffError, match='encrypted'):
        aff.AffImage(str(path))


def test_aff_page_never_written_reads_as_zeros(tmp_path):
    path = tmp_path / 'gap.aff'
    path.write_bytes(aff.FILE_HEADER + _segment('pagesize', argument=4)
                     + _segment('imagesize', struct.pack('>II', 12, 0))
                     + _segment('page0', b'abcd') + _segment('page2',
                                                             b'wxyz'))
    image = aff.AffImage(str(path))
    try:
        assert image.read_buffer_at_offset(12, 0) == b'abcd\0\0\0\0wxyz'
        assert image.missing == [1]
        assert 'never written' in image.describe()
    finally:
        image.close()


def test_ufdr_opens_as_logical_evidence(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    path = tmp_path / 'phone.ufdr'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('report.xml', '<project/>')
        archive.writestr('files/Image/a.jpg', b'\xff\xd8\xff' + b'x' * 100)
    handler = ImageHandler(str(path))
    try:
        assert handler.get_image_type() == 'logical'
        assert 'UFDR' in handler.logical_fs.facts['Format']
        # Nothing in this report places its files: they stay where the
        # ZIP has them, under the report's own folder (core/ufdr).
        assert {e['name'] for e in handler.get_directory_contents(0)} == \
            {'UFDR report'}
    finally:
        handler.close_resources()


# --- the formats' own rules, no data ---------------------------------------------

def test_compressed_formats_are_told_by_their_first_bytes():
    kind = compressed_disk.kind_of
    assert kind(b'\x1f\x8b\x08\0') == 'gzip'
    assert kind(b'\xfd7zXZ\x00\x00') == 'xz'
    assert kind(b'\x28\xb5\x2f\xfd\x00') == 'zstd'
    assert kind(b'\x04\x22\x4d\x18') == 'lz4'
    assert kind(b'BZh91AY&SY') == 'bzip2'
    assert kind(b'BZh is not bzip2') is None
    assert kind(b'\0' * 16) is None


def test_android_sparse_fill_and_dont_care(tmp_path):
    """A sparse image written by hand from libsparse's format: a raw
    block, a fill, a don't-care and a CRC chunk."""
    block = 4096
    raw = bytes(range(256)) * 16
    chunks = [
        struct.pack('<HHII', android_sparse.RAW, 0, 1, 12 + block) + raw,
        struct.pack('<HHII', android_sparse.FILL, 0, 2, 16) +
        b'\x01\x02\x03\x04',
        struct.pack('<HHII', android_sparse.DONT_CARE, 0, 1, 12),
        struct.pack('<HHII', android_sparse.CRC32, 0, 0, 16) + b'\0' * 4]
    head = struct.pack('<IHHHHIIII', android_sparse.MAGIC, 1, 0, 28, 12,
                       block, 4, len(chunks), 0)
    path = tmp_path / 'tiny.simg'
    path.write_bytes(head + b''.join(chunks))
    image = android_sparse.SparseImage(open(path, 'rb'))
    try:
        data = image.read_buffer_at_offset(4 * block, 0)
        assert data == raw + b'\x01\x02\x03\x04' * (2 * block // 4) + \
            bytes(block)
        assert image.read_buffer_at_offset(6, block + 2) == \
            b'\x03\x04\x01\x02\x03\x04'
    finally:
        image.close()


def test_split_aff_is_what_affconvert_split():
    """An AFD really spans its files, an AFM its raw files; a one-file AFM
    reads whole although AFFLIB's affcat stops after its first page."""
    key = _key()
    assert len(key['images']['disk.afd']['files']) > 1
    assert len([n for n in key['images']['aff-split/disk-split.afm']['files']
                if not n.endswith('.afm')]) > 1
    for name, kind in (('disk.afd', 'AFD'),
                       ('aff-split/disk-split.afm', 'AFM'),
                       ('aff-split/disk-one.afm', 'AFM')):
        image = aff.AffImage(image_path(name))
        try:
            assert image.kind == kind
            assert image.stored_hashes['stored_md5']
            assert not image.missing
        finally:
            image.close()


def test_an_afd_folder_is_evidence_not_a_folder_of_files():
    from trace_app.core import evidence_probe, logical_sources
    path = image_path('disk.afd')
    assert aff.is_afd(path)
    assert logical_sources.kind_of(path) is None
    assert disk_containers.kind_of(path) == 'aff'
    assert 'AFD' in evidence_probe.format_name(path)


# --- a VirtualBox snapshot chain VirtualBox made ------------------------------

def _vbox_key():
    with open(image_path('vbox-snapshots-key.json'), encoding='utf-8') as f:
        return json.load(f)


def test_virtualbox_snapshot_chain_reads_as_virtualbox_reads_it():
    """Base disk, a snapshot on it and one on that, each written to by
    VirtualBox (mediumio formatfat) and read back whole by it (mediumio
    cat): every disk of the chain must read exactly so -- the snapshots
    finding their parents by UUID, from Snapshots/ up to the base."""
    key = _vbox_key()
    folder = image_path('vbox-snapshots')
    assert len(key['disks']) == 3
    for name, entry in key['disks'].items():
        disk = vdi.VdiDisk(os.path.join(folder, name))
        try:
            assert disk.get_size() == entry['size']
            data = disk.read_buffer_at_offset(disk.get_size(), 0)
            assert hashlib.sha256(data).hexdigest() == entry['sha256'], name
        finally:
            disk.close()


def test_the_newest_snapshot_opens_as_evidence():
    from trace_app.core.image_handler import ImageHandler
    key = _vbox_key()
    newest = next(name for name, entry in key['disks'].items()
                  if entry['parent_uuid'] and not any(
                      other['parent_uuid'] == entry['uuid']
                      for other in key['disks'].values()))
    handler = ImageHandler(os.path.join(image_path('vbox-snapshots'),
                                        newest))
    try:
        assert handler.get_image_type() == 'container' and handler.loaded
        result = handler.calculate_hashes()
        assert result['computed_sha256'] == key['disks'][newest]['sha256']
    finally:
        handler.close_resources()


def test_a_raw_image_that_only_starts_like_a_container_reads_as_raw(tmp_path):
    """An encrypted volume is random bytes, and one in ~16 million starts
    as a gzip stream does (1f 8b 08): named as a raw image, it must open
    as raw, saying why, not fail to load. Fixed bytes after each signature
    make the header invalid (reserved gzip flags, a zstd descriptor's
    reserved bit, sparse version 14219), so the case is the same each run."""
    import random
    from trace_app.core.image_handler import ImageHandler
    noise = random.Random(2026).randbytes(1024 * 1024)
    for start in (b'\x1f\x8b\x08\xe0', b'\x28\xb5\x2f\xfd\x08',
                  b'\x3a\xff\x26\xed\x8b\x37'):
        data = start + noise[len(start):]
        path = tmp_path / 'volume.dd'
        path.write_bytes(data)
        handler = ImageHandler(str(path))
        try:
            assert handler.load_image()
            assert handler.img_info.get_size() == len(data)
            assert 'read as a raw image' in handler.container_note
            assert handler.may_be_veracrypt(0)
        finally:
            handler.close_resources()

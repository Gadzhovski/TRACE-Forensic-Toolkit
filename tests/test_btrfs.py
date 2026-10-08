"""Btrfs (core/btrfs.py), and the QCOW2 reader its real-world test needed
(core/qcow2.py).

The volumes are fox-it/dissect.btrfs's test images
(tools/fetch_test_images.py), and the values asserted are the ones its own
tests publish: the same tree in the top-level subvolume, a subvolume and a
snapshot of it, nested subvolumes, zlib / LZO / zstd files (extents and
inline), sparse files and a snapshot's partly rewritten copies, and one
disk of a two-disk RAID1 read alone.

Fedora 44's cloud image (local only, 583 MB: see test_images/README.md) is
a real installation -- GPT, root/home/var/boot subvolumes, zstd throughout
-- in a compressed QCOW2 that libqcow misreads.
"""

import hashlib
import os
import struct
import tempfile
import zlib

import pytest

from tests.conftest import image_path

SNAPSHOT = 'btrfs-subvolume-snapshot.raw'
NESTED = 'btrfs-subvolume-nested.raw'
COMPRESSION = 'btrfs-compression.raw'
SPARSE = 'btrfs-sparse.raw'
RAID1 = 'btrfs-raid1-1.raw'
FEDORA = 'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'
PAGE = 4096


def handler_for(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.loaded
    return handler


def listing(handler, start=0, inode=None):
    inode = inode if inode is not None else handler.get_root_inode(start)
    return {e['name']: e for e in handler.get_directory_contents(start,
                                                                 inode)}


def entry(handler, path, start=0):
    found = None
    for part in path.strip('/').split('/'):
        found = listing(handler, start,
                        found['inode_number'] if found else None)[part]
    return found


def content(handler, path, start=0):
    data, _meta = handler.get_file_content(
        entry(handler, path, start)['inode_number'], start)
    return data


def assert_test_data(handler):
    """dissect.btrfs's assert_test_data, through TRACE's own reads."""
    path = entry(handler, 'path')
    assert path['is_directory']
    assert content(handler, 'path/to/a/file.txt') == b'file in dir\n'
    assert content(handler, 'small.txt') == \
        b'small file content goes here\n'
    assert content(handler, 'large.txt') == b'a' * 5242880 + b'\n'
    fs = handler.get_fs_info(0)
    link = fs.open_meta(entry(handler, 'link.txt')['inode_number'])
    assert link.info.meta.link == 'path/to/a/file.txt'


def test_btrfs_is_read_where_tsk_cannot():
    """TSK (4.15) does not read Btrfs; TRACE does: named, not taken for a
    wiped image, signature found, and the probe says so."""
    import pytsk3
    from trace_app.core.btrfs import is_btrfs, superblock_geometry
    from trace_app.core.evidence_probe import probe
    path = image_path(SNAPSHOT)
    with open(path, 'rb') as handle:
        head = handle.read(0x11000)
    assert superblock_geometry(head) == (4096, 128 * 1024 * 1024,
                                         'btrfs-subvolume-snapshot')
    with pytest.raises(OSError):
        pytsk3.FS_Info(pytsk3.Img_Info(path))
    handler = handler_for(SNAPSHOT)
    try:
        assert not handler.is_wiped() and is_btrfs(handler.get_fs_info(0))
        assert handler.get_fs_type(0) == 'Btrfs'
        assert 'Btrfs' in handler.detect_filesystems(0)
    finally:
        handler.close_resources()
    assert probe(path)['contents'] == 'Btrfs'


def test_subvolume_and_snapshot():
    handler = handler_for(SNAPSHOT)
    try:
        assert_test_data(handler)
        root = listing(handler)
        assert set(root) == {'path', 'link.txt', 'small.txt', 'large.txt',
                             'subvol', 'subvol-snapshot'}
        # dissect's values for 'path'; Btrfs records no birth time there.
        path = root['path']
        assert path['accessed'] == '2023-06-28 03:04:16 UTC'
        assert path['modified'] == path['changed'] == \
            '2023-06-28 03:04:12 UTC'
        assert set(listing(handler, 0, root['subvol']['inode_number'])) == {
            'cross-volume-link.txt', 'small.txt', 'large.txt', 'some',
            'new.txt'}
        assert content(handler, 'subvol/small.txt') == b'file in subvolume\n'
        assert content(handler, 'subvol/large.txt') == \
            b'b' * 5242880 + b'\n'
        assert entry(handler, 'subvol/some/more/dirs/empty.txt')['size'] \
            == 0
        # The snapshot was taken before new.txt, and written to after.
        snap = set(listing(handler, 0,
                           root['subvol-snapshot']['inode_number']))
        assert 'new.txt' not in snap and 'in-snapshot.txt' in snap
        # Every subvolume numbers its inodes from 256: identifiers do not
        # collide, and each opens again by its identifier.
        a = entry(handler, 'subvol/small.txt')['inode_number']
        b = entry(handler, 'subvol-snapshot/small.txt')['inode_number']
        assert a != b
        fs = handler.get_fs_info(0)
        assert fs.open_meta(b).read_random(0, 100) == b'file in subvolume\n'
        assert fs.open_meta(b).info.name.name == b'small.txt'
    finally:
        handler.close_resources()


def test_nested_subvolumes():
    from trace_app.core.btrfs import is_btrfs
    handler = handler_for(NESTED)
    try:
        fs = handler.get_fs_info(0)
        assert is_btrfs(fs)
        assert fs.btrfs.subvolumes() == {256: (5, 257, 'volume'),
                                         257: (5, 256, 'default'),
                                         258: (257, 256, 'volume')}
        assert entry(handler, 'dir/volume')['is_directory']
        assert entry(handler, 'default/volume')['is_directory']
    finally:
        handler.close_resources()


def test_compression():
    handler = handler_for(COMPRESSION)
    try:
        for name in ('zlib', 'lzo', 'zstd'):
            word = name.encode()
            assert content(handler, f'{name}.txt') == \
                word * 1024 * 1024 * 5 + b'\n', name
            assert content(handler, f'{name}_inline.txt') == \
                word * 256 + b'\n', name
        assert hashlib.sha256(content(handler, 'zstd_lorem_ipsum.txt')) \
            .hexdigest() == ('ac9db55e11e804c58cb5ac8baded462c'
                             'd3e7a570e4f3c980298ef2b417467b1d')
        # A read in the middle of a compressed file, across extents.
        fs = handler.get_fs_info(0)
        lzo = fs.open_meta(entry(handler, 'lzo.txt')['inode_number'])
        offset = 128 * 1024 - 2
        assert lzo.read_random(offset, 6) == \
            (b'lzo' * 100000)[offset:offset + 6]
    finally:
        handler.close_resources()


def test_sparse_files():
    handler = handler_for(SPARSE)
    try:
        assert content(handler, 'sparse_start') == \
            b'\0' * PAGE * 40 + b'\1' * PAGE * 20
        assert content(handler, 'sparse_hole') == \
            b'\1' * PAGE * 20 + b'\0' * PAGE * 20 + b'\1' * PAGE * 20
        assert content(handler, 'sparse_end') == \
            b'\1' * PAGE * 20 + b'\0' * PAGE * 40
        assert content(handler, 'sparse_all') == b'\0' * PAGE * 1280
        assert content(handler, 'snapshot/sparse_hole') == \
            b'\1' * PAGE * 10 + b'\0' * PAGE * 50
        assert content(handler, 'snapshot/sparse_end') == (
            b'\1' * (PAGE + 123) + b'\2' + b'\1' * (PAGE * 19 - 124) +
            b'\0' * PAGE * 40)
    finally:
        handler.close_resources()


def test_one_disk_of_a_raid1_reads_alone():
    handler = handler_for(RAID1)
    try:
        assert_test_data(handler)
    finally:
        handler.close_resources()


def test_analysis_reaches_every_subvolume():
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    handler = handler_for(SNAPSHOT)
    case = Case.create(os.path.join(tempfile.mkdtemp(), 'case'), 'btrfs')
    try:
        evidence_id = case.add_evidence(image_path(SNAPSHOT))
        analyse_evidence(handler, case, evidence_id, ['hash'])
        hashes = {r[0]: r[1] for r in case._db.execute(
            "SELECT path, sha256 FROM file_analysis")}
        assert hashes['/subvol-snapshot/small.txt'] == \
            hashlib.sha256(b'file in subvolume\n').hexdigest()
        assert {'/large.txt', '/path/to/a/file.txt', '/subvol/new.txt',
                '/subvol-snapshot/in-snapshot.txt'} <= set(hashes)
    finally:
        case.close()
        handler.close_resources()


def test_name_search_reaches_every_subvolume():
    """The Listing's search goes through get_fs_info like every other
    read; it used to reopen the image path as a raw image and found
    nothing on any file system TSK cannot open."""
    handler = handler_for(SNAPSHOT)
    try:
        found = {r['path'].replace('\\', '/')
                 for r in handler.search_files('small')}
        assert found == {'vol0:/small.txt', 'vol0:/subvol/small.txt',
                         'vol0:/subvol-snapshot/small.txt'}
        assert [r['name'] for r in handler.search_files('.txt')
                if r['name'] == 'new.txt'] == ['new.txt']
    finally:
        handler.close_resources()


def _inside(ranges, begin, end):
    return any(b <= begin and end <= e for b, e in ranges)


@pytest.mark.parametrize('image', [COMPRESSION, SPARSE, SNAPSHOT])
def test_carving_never_takes_live_data_for_free_space(image):
    """Carving's allocation map came from TSK data runs, which a Btrfs
    entry has none of: it called almost the whole volume free, and live
    files were carved as if deleted (1,731 of Fedora's .gz files in the
    first 5% of its disk). It is the extent tree now: every live extent,
    data and metadata, is inside the map, and so are the superblock and
    tree nodes."""
    from trace_app.core import carving
    handler = handler_for(image)
    try:
        ranges = carving.allocation_map(handler)
        fs = handler.get_fs_info(0)
        volume = fs.btrfs
        checked = 0
        for path in ('large.txt', 'zlib.txt', 'zstd.txt', 'lzo.txt',
                     'sparse_hole', 'subvol/large.txt'):
            try:
                node = entry(handler, path)
            except KeyError:
                continue
            obj = fs.open_meta(node['inode_number'])._entry
            for extent in volume.extents(obj.tree, obj.inode_number):
                if extent[4]:
                    for physical, size in volume._physical_copies(
                            extent[4], extent[5]):
                        assert _inside(ranges, physical, physical + size)
                        checked += 1
        assert checked
        assert _inside(ranges, 0x10000, 0x11000)            # superblock
        for bytenr in list(volume._nodes)[:20]:              # tree nodes
            for physical, size in volume._physical_copies(
                    bytenr, volume.node_size):
                assert _inside(ranges, physical, physical + size)
        # And not the whole volume: there is free space left to carve.
        assert sum(e - b for b, e in ranges) < 0.5 * handler.get_size()
    finally:
        handler.close_resources()


def test_lzo1x_literal_and_match_forms():
    """LZO1X streams covering a first literal run, M2/M3/M4 matches and
    the end marker, from what Btrfs writes, decoded byte for byte."""
    from trace_app.core.btrfs import BtrfsError, lzo1x_decompress
    # 17 + 4 literals 'abcd', M2 match len 3 distance 4, then end.
    stream = bytes([21]) + b'abcd' + bytes([(2 << 5) | (3 << 2), 0]) + \
        bytes([0x11, 0, 0])
    assert lzo1x_decompress(stream) == b'abcdabc'
    with pytest.raises(BtrfsError):
        lzo1x_decompress(bytes([21]) + b'ab')        # ends early


def test_fstab_says_where_the_system_is():
    """Fedora mounts subvol=root as / and siblings as /home and /var;
    Ubuntu '@' and '@home'; openSUSE the default subvolume. Lines for
    another file system (another UUID, vfat) are not this one's."""
    from trace_app.core.btrfs import _fstab_mounts

    class Volume:
        fsid = bytes.fromhex('15c26993ac30424a9c4bfaec4434d234')
        label = 'fedora'
        default_subvolume = 300

        @staticmethod
        def subvolume_path(tree):
            return {300: '/@/.snapshots/1/snapshot', 258: '/home'}.get(tree)

    me = 'UUID=15c26993-ac30-424a-9c4b-faec4434d234'
    fedora = '\n'.join([
        f"{me} / btrfs compress=zstd:1,defaults,subvol=root 0 1",
        f"{me} /home btrfs compress=zstd:1,subvol=home 0 0",
        f"{me} /var btrfs subvol=/var 0 0",
        "UUID=5BCC-12A9 /boot/efi vfat umask=0077 0 2",
        "UUID=00000000-0000-0000-0000-000000000000 /data btrfs subvol=data",
        "# UUID=x /old btrfs subvol=old"])
    assert _fstab_mounts(fedora, Volume) == {'/': '/root', '/home': '/home',
                                             '/var': '/var'}
    ubuntu = '\n'.join([f"{me} / btrfs defaults,subvol=@ 0 0",
                        f"{me} /home btrfs defaults,subvolid=258 0 0"])
    assert _fstab_mounts(ubuntu, Volume) == {'/': '/@', '/home': '/home'}
    suse = "LABEL=fedora / btrfs defaults 0 0"
    assert _fstab_mounts(suse, Volume) == {'/': '/@/.snapshots/1/snapshot'}


# --- QCOW2 -------------------------------------------------------------------

def _qcow2(path, clusters, backing=b'', size=None, zstd=False):
    """A QCOW2 v3 file of 64 KiB clusters. `clusters` maps a guest cluster
    to ('plain', bytes) / ('deflate', bytes, pad) / ('zero',). Compressed
    clusters start `pad` bytes into the file's next free byte, so a test
    can put one at an odd offset."""
    cluster = 1 << 16
    size = size or cluster * (max(clusters) + 1)
    header_length = 112
    l1_offset, l2_offset = cluster, 2 * cluster
    data = bytearray()
    entries = {}
    where = 3 * cluster
    for index, spec in sorted(clusters.items()):
        if spec[0] == 'plain':
            data += b'\0' * (-len(data) % cluster)     # clusters align
            entries[index] = (1 << 63) | (where + len(data))
            data += spec[1].ljust(cluster, b'\0')
        elif spec[0] == 'zero':
            entries[index] = 1
        else:
            if zstd:
                from trace_app.core import zstd_decode
                packed = zstd_decode.standard_library().compress(spec[1])
            else:
                packer = zlib.compressobj(9, zlib.DEFLATED, -15)
                packed = packer.compress(spec[1]) + packer.flush()
            data += b'\xAA' * spec[2]
            host = where + len(data)
            extra = (host + len(packed) - 1) // 512 - host // 512
            entries[index] = (1 << 62) | (extra << 54) | host
            data += packed
    head = bytearray(cluster)
    backing_offset = header_length if backing else 0
    head[:header_length] = struct.pack(
        '>4sIQIIQIIQQIIQQQQII4sQ', b'QFI\xfb', 3, backing_offset,
        len(backing), 16, size, 0, 1, l1_offset, 0, 0, 0, 0,
        8 if zstd else 0, 0, 0, 4, header_length,
        bytes([1 if zstd else 0]) + b'\0' * 3, 0)[:header_length]
    head[header_length:header_length + len(backing)] = backing
    l1 = struct.pack('>Q', (1 << 63) | l2_offset).ljust(cluster, b'\0')
    l2 = bytearray(cluster)
    for index, value in entries.items():
        struct.pack_into('>Q', l2, 8 * index, value)
    with open(path, 'wb') as handle:
        handle.write(bytes(head) + l1 + bytes(l2) + bytes(data))


def test_qcow2_compressed_clusters_at_odd_offsets(tmp_path):
    """A compressed cluster's L2 entry keeps the offset's lowest bit where a
    plain cluster keeps its zero flag; libqcow (20260703) reads such a
    cluster as zeros. TRACE's reader takes the offset whole."""
    from trace_app.core import containers, qcow2
    one = bytes(range(256)) * 256
    two = b'TRACE' * 13107 + b'!'
    path = str(tmp_path / 'disk.qcow2')
    _qcow2(path, {0: ('deflate', one, 1), 1: ('deflate', two, 3),
                  2: ('plain', b'plain cluster'), 3: ('zero',)},
           size=5 << 16)
    image = qcow2.Qcow2Image(path)
    assert image.read_buffer_at_offset(65536, 0) == one
    assert image.read_buffer_at_offset(65536, 65536) == two
    assert image.read_buffer_at_offset(13, 2 << 16) == b'plain cluster'
    assert image.read_buffer_at_offset(65536 * 2, 3 << 16) == \
        b'\0' * 65536 * 2
    # Across a boundary between a compressed and a plain cluster.
    assert image.read_buffer_at_offset(8, (2 << 16) - 4) == \
        two[-4:] + b'plai'
    image.close()
    img, note = containers.open_virtual_disk(path)
    assert note == 'QCOW' and img.read(0, 65536) == one
    img.close()


def test_qcow2_backing_file(tmp_path):
    from trace_app.core import containers
    _qcow2(str(tmp_path / 'base.qcow2'), {0: ('plain', b'base 0'),
                                           1: ('plain', b'base 1')})
    _qcow2(str(tmp_path / 'top.qcow2'), {1: ('plain', b'top 1')},
           backing=b'/elsewhere/base.qcow2')
    img, note = containers.open_virtual_disk(str(tmp_path / 'top.qcow2'))
    try:
        assert note == 'QCOW overlay (1 backing file)'
        assert img.read(0, 6) == b'base 0'
        assert img.read(1 << 16, 5) == b'top 1'
    finally:
        img.close()


@pytest.mark.skipif(__import__('trace_app.core.zstd_decode', fromlist=['x'])
                    .standard_library() is None,
                    reason="compressing needs a zstd library")
def test_qcow2_zstd_clusters(tmp_path):
    from trace_app.core import qcow2
    data = b'zstd cluster ' * 5000 + b'\0' * (65536 - 65000)
    path = str(tmp_path / 'zstd.qcow2')
    _qcow2(path, {0: ('deflate', data, 7)}, zstd=True)
    image = qcow2.Qcow2Image(path)
    assert image.compression == 'zstd'
    assert image.read_buffer_at_offset(65536, 0) == data
    image.close()


@pytest.mark.parametrize('library', [True, False])
def test_zstd_first_frame_with_btrfs_padding(library, monkeypatch):
    """Btrfs pads a zstd extent with zeros to its sector's end: the first
    frame is decoded, whichever decoder is used."""
    from trace_app.core import zstd_decode
    if not library:
        monkeypatch.setattr(zstd_decode, 'standard_library', lambda: None)
    # A raw-block frame (no content size, no checksum) for 'hello'.
    frame = (struct.pack('<I', zstd_decode.MAGIC) + bytes([0x00, 0x48]) +
             (1 | (0 << 1) | (5 << 3)).to_bytes(3, 'little') + b'hello')
    padded = frame + b'\0' * 40
    assert zstd_decode.decompress_frame(padded) == b'hello'


# --- Fedora (local only) -----------------------------------------------------

def test_fedora_cloud_image():
    """Fedora 44 Cloud: GPT, an EFI FAT16 and a Btrfs root holding the
    root, boot, home and var subvolumes, zstd-compressed -- through a
    compressed QCOW2. Every tree node's CRC32C is checked, which no byte
    libqcow misread survives."""
    handler = handler_for(FEDORA)
    try:
        layout = {p[2]: handler.get_fs_type(p[2])
                  for p in handler.get_partitions()
                  if handler.get_fs_info(p[2]) is not None}
        assert layout == {6144: 'FAT16', 210944: 'Btrfs'}
        fs = handler.get_fs_info(210944)
        assert fs.btrfs.label == 'fedora'
        assert {name for _p, _d, name in fs.btrfs.subvolumes().values()} \
            == {'root', 'boot', 'home', 'var'}
        os_release = content(handler, 'root/usr/lib/os-release', 210944)
        assert b'VERSION_ID=44' in os_release
        bash = content(handler, 'root/usr/bin/bash', 210944)
        assert bash[:4] == b'\x7fELF' and len(bash) > 1_000_000
        assert _bad_nodes(fs.btrfs) == 0
        # Activity reads the system as it was mounted: / from the root
        # subvolume, /var and /home from theirs, root's home in /root.
        from trace_app.core.activity import Volume
        (system,) = Volume.all(handler, 210944)
        assert (system.root, system.mounts) == (
            '/root', {'boot': '/boot', 'home': '/home', 'var': '/var'})
        assert system.find('etc', 'fstab').path == '/root/etc/fstab'
        assert system.find('var', 'log', 'dnf5.log').path == \
            '/var/log/dnf5.log'
        assert system.find('home').is_dir
        assert system.find('root', '.ssh').path == '/root/root/.ssh'
        # Name search through the QCOW2, both file systems.
        found = {r['path'].replace('\\', '/')
                 for r in handler.search_files('os-release')}
        assert 'vol6:/root/usr/lib/os-release' in found
        assert any(r['path'].startswith('vol5:')
                   for r in handler.search_files('.efi'))
    finally:
        handler.close_resources()


def _crc32c(data):
    table = []
    for i in range(256):
        value = i
        for _ in range(8):
            value = (value >> 1) ^ 0x82F63B78 if value & 1 else value >> 1
        table.append(value)
    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _bad_nodes(volume):
    """Tree nodes (of every subvolume, the root and chunk trees) whose
    stored CRC32C does not match their bytes."""
    from trace_app.core import btrfs
    roots = {volume.root_tree} | set(volume._trees.values())
    seen, bad = set(), 0
    pending = list(roots)
    while pending:
        bytenr = pending.pop()
        if bytenr in seen:
            continue
        seen.add(bytenr)
        data = volume.read(bytenr, volume.node_size)
        if _crc32c(data[0x20:]) != struct.unpack_from('<I', data, 0)[0]:
            bad += 1
        if data[0x64]:
            for i in range(struct.unpack_from('<I', data, 0x60)[0]):
                pending.append(struct.unpack_from(
                    '<Q', data, btrfs._HEADER + 33 * i + 17)[0])
    assert len(seen) > 100
    return bad


def test_identifiers_read_as_inode_and_subvolume():
    """A Btrfs identifier keeps the subvolume in its high bits; the
    Listing shows '258 (subvolume 256)', not 72057594037928194, and a
    top-level entry its plain inode number."""
    handler = handler_for(SNAPSHOT)
    try:
        top = entry(handler, 'small.txt')['inode_number']
        inner = entry(handler, 'subvol/small.txt')['inode_number']
        assert handler.inode_label(0, top) == str(top)
        assert handler.inode_label(0, inner) == \
            f"{inner & ((1 << 48) - 1)} (subvolume {inner >> 48})"
        assert '(subvolume 256)' in handler.inode_label(0, inner)
    finally:
        handler.close_resources()

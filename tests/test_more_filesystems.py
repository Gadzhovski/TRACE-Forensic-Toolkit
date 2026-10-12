"""SquashFS, EROFS, UDF, classic HFS and JFFS2 (core/squashfs.py, erofs.py,
udf.py, hfs.py, jffs2.py): read in Python, checked against images their
own tools wrote.

tools/testdata/build/make_fs_images.py writes one tree into each with
mksquashfs (every compressor), mkfs.erofs (plain, chunks, LZ4 with compact
and full indexes, LZ4HC big clusters with tail packing, MicroLZMA with
fragments, DEFLATE with dedupe), the Linux kernel through a UDF mount
(1.02 and 2.01, 512- and 2048-byte blocks, a file deleted), genisoimage
(a UDF bridge disc), mkudffs (an empty BD-R with a VAT), hfsutils and
mkfs.jffs2 (each compressor, both byte orders). Every file's bytes, every
link's target, the listing and (where the format records one) every
modification time must equal the answer key. EROFS's key is what
erofs-utils itself extracts. Linux CI builds the images; these tests skip
elsewhere. dfvfs's hfs.raw (written by Linux's HFS driver) and the X-Ways
UDF training disc (local only) are real-world checks.
"""

import hashlib
import os

import pytest
import pytsk3

from tests.conftest import data_path, image_path
from tests.fs_answers import Source, compare, key, walk
from trace_app.core import erofs, hfs, jffs2, squashfs, udf

OPENERS = {'SquashFS': squashfs.open_squashfs, 'EROFS': erofs.open_erofs,
           'UDF': udf.open_udf, 'HFS': hfs.open_hfs,
           'JFFS2': jffs2.open_jffs2}

IMAGES = (
    ['sqfs-gzip.sqfs', 'sqfs-lzo.sqfs', 'sqfs-lz4.sqfs', 'sqfs-xz.sqfs',
     'sqfs-zstd.sqfs', 'sqfs-lzma.sqfs', 'sqfs-plain.sqfs',
     'sqfs-small-blocks.sqfs'] +
    ['erofs-plain.img', 'erofs-noinline.img', 'erofs-chunk.img',
     'erofs-lz4.img', 'erofs-lz4-legacy.img', 'erofs-lz4hc-big.img',
     'erofs-lzma.img', 'erofs-deflate.img'] +
    ['udf-102.img', 'udf-201.img', 'udf-201-2k.img', 'udf-bridge.iso',
     'udf-250-empty.img'] +
    ['hfs.img'] +
    ['jffs2-zlib.img', 'jffs2-lzo.img', 'jffs2-rtime.img', 'jffs2-none.img',
     'jffs2-be.img'])

#: A sparse file erofs-utils 1.7.1 gets wrong both ways: mkfs.erofs merges
#: its chunks by keeping each group's first entry (a hole), so the data
#: after it is written but unreferenced, and fsck.erofs then extracts the
#: file as empty although its inode says 2 MiB. The format's answer -- one
#: 2 MiB chunk marked as a hole -- is 2 MiB of zeros, as Linux reads it.
EROFS_CHUNK_SPARSE = {
    'type': 'file', 'size': 2 * 1024 * 1024,
    'sha256': hashlib.sha256(bytes(2 * 1024 * 1024)).hexdigest()}


def _open(name):
    entry = key(name)
    source = Source(image_path(name))
    fs = OPENERS[entry['fs']](source)
    assert fs is not None, name
    return fs, entry


# --- every image, file by file ------------------------------------------------

@pytest.mark.parametrize('name', IMAGES)
def test_every_file_reads_as_written(name):
    fs, entry = _open(name)
    expected = dict(entry['files'])
    if name == 'erofs-chunk.img':
        assert entry['differs_from_source'] == ['/big/sparse.bin']
        expected['/big/sparse.bin'] = EROFS_CHUNK_SPARSE
    found = walk(fs)
    # A deleted file is listed too (marked so): not part of the tree.
    deleted = set(entry.get('deleted', {}))
    live = {path: record for path, record in found.items()
            if path not in deleted}
    # Classic HFS keeps local times with no zone: hfsutils' own clock,
    # not the tree's, so its key has none to compare.
    problems = compare(live, expected, times=entry['fs'] != 'HFS')
    assert not problems, '\n'.join(problems[:20])
    # Everything readable reads whole.
    for path, record in live.items():
        if record['type'] == 'file':
            assert record['read'] == record['size'], path


def test_images_say_what_they_are():
    names = {name: type(_open(name)[0]).KIND
             for name in ('sqfs-xz.sqfs', 'erofs-lz4.img', 'udf-201.img',
                          'hfs.img', 'jffs2-be.img')}
    assert names == {'sqfs-xz.sqfs': 'SquashFS', 'erofs-lz4.img': 'EROFS',
                     'udf-201.img': 'UDF', 'hfs.img': 'HFS (classic)',
                     'jffs2-be.img': 'JFFS2'}


# --- what each format adds ----------------------------------------------------

def test_udf_lists_a_deleted_name_the_kernel_left():
    """Linux marks a deleted identifier deleted and clears where its file
    entry was: the name is evidence, its data out of reach."""
    fs, entry = _open('udf-201.img')
    assert '/gone.bin' in entry['deleted']
    gone = [item for item in fs.open_dir(inode=fs.info.root_inum)
            if item.info.name.name == b'gone.bin']
    assert len(gone) == 1
    item = gone[0]
    assert item.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC
    assert item.info.meta.size == 0
    again = fs.open_meta(inode=item.info.meta.addr)
    assert again.info.name.name == b'gone.bin'


def test_udf_bridge_disc_is_read_as_udf_not_iso9660():
    """A UDF bridge disc (DVDs, Windows install media) keeps everything in
    UDF; TRACE reads that side, with its times."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('udf-bridge.iso'))
    try:
        assert handler.get_fs_type(0) == 'UDF'
        assert 'UDF' in handler.detect_filesystems(0)
        root = {e['name']: e for e in handler.get_directory_contents(0)}
        assert 'link' in root and root['README.txt']['modified'].endswith(
            'UTC')
    finally:
        handler.close_resources()


def test_udf_write_once_disc_finds_its_vat():
    fs, _entry = _open('udf-250-empty.img')
    kinds = [m.kind for m in fs.udf.maps]
    assert kinds == ['type1', 'virtual']
    assert fs.udf.vat()
    assert fs.volume.get_root_directory().number_of_sub_file_entries == 0
    assert fs.udf.label == 'TRACE'


def test_hfs_reads_a_file_in_the_extents_overflow_file():
    """hfsutils wrote it into holes the deleted files left: more extents
    than a catalog record holds."""
    fs, _entry = _open('hfs.img')
    fragmented = fs.volume.get_file_entry_by_path('/frag/fragmented.bin')
    assert len(fragmented._fork.runs()) > 3


def test_erofs_images_cover_every_layout():
    layouts = set()
    advice = 0
    for name in ('erofs-plain.img', 'erofs-chunk.img', 'erofs-lz4.img',
                 'erofs-lz4-legacy.img', 'erofs-lz4hc-big.img',
                 'erofs-lzma.img', 'erofs-deflate.img'):
        fs, _entry = _open(name)
        for path in ('/big/log.txt', '/docs/notes.txt', '/big/video.bin'):
            inode = fs.volume.get_file_entry_by_path(path)._inode
            layouts.add(inode.layout)
            if inode.compressed:
                advice |= inode._map_header()[2]
    assert {erofs.FLAT_INLINE, erofs.CHUNK_BASED, erofs.COMPRESSED_FULL,
            erofs.COMPRESSED_COMPACT} <= layouts
    for flag in (erofs.ADVISE_BIG_PCLUSTER_1, erofs.ADVISE_INLINE_PCLUSTER,
                 erofs.ADVISE_FRAGMENT_PCLUSTER):
        assert advice & flag, hex(flag)


def test_jffs2_images_use_each_compressor():
    used = {}
    for name in ('jffs2-zlib.img', 'jffs2-lzo.img', 'jffs2-rtime.img',
                 'jffs2-be.img'):
        fs, _entry = _open(name)
        used[name] = {fields['compression']
                      for nodes in fs.image.inodes.values()
                      for _version, _offset, fields in nodes
                      if fields['dsize']}
    assert jffs2.COMPR_ZLIB in used['jffs2-zlib.img']
    assert jffs2.COMPR_LZO in used['jffs2-lzo.img']
    assert jffs2.COMPR_RTIME in used['jffs2-rtime.img']
    assert _open('jffs2-be.img')[0].image.order == '>'


# --- through ImageHandler, as the window reads them -------------------------

@pytest.mark.parametrize('name, fs_type', [
    ('sqfs-zstd.sqfs', 'SquashFS'), ('erofs-lzma.img', 'EROFS'),
    ('udf-102.img', 'UDF'), ('hfs.img', 'HFS (classic)'),
    ('jffs2-lzo.img', 'JFFS2')])
def test_opened_as_evidence(name, fs_type):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    try:
        assert handler.loaded and not handler.is_wiped()
        assert handler.get_fs_type(0) == fs_type
        root = {e['name']: e for e in handler.get_directory_contents(0)}
        data, _meta = handler.get_file_content(
            root['README.txt']['inode_number'], 0)
        assert hashlib.sha256(data).hexdigest() == \
            key(name)['files']['/README.txt']['sha256']
        if fs_type == 'HFS (classic)':
            assert root['README.txt']['modified'].endswith(
                '(local, no zone)')
        # Carving's free-space map. SquashFS and EROFS are packed whole
        # (nothing in them is free); the others keep free space.
        used, _note = handler.partition_allocation(0)
        total = sum(end - begin for begin, end in used)
        assert used and total <= handler.get_size()
        if fs_type in ('UDF', 'HFS (classic)', 'JFFS2'):
            assert total < handler.get_size()
    finally:
        handler.close_resources()


# --- real-world images ----------------------------------------------------------

def test_dfvfs_hfs_image_written_by_linux():
    """dfvfs's hfs.raw: hformat, then Linux's HFS driver wrote the files
    its utils/generate_test_data_linux.sh lists."""
    fs = hfs.open_hfs(Source(data_path('samples', 'hfs.raw')))
    assert fs is not None and fs.hfs.label == 'hfs_test'
    found = walk(fs)
    assert set(found) == {'/a_directory', '/a_directory/a_file',
                          '/a_directory/another_file', '/passwords.txt'}
    texts = {
        '/a_directory/a_file': b'This is a text file.\n\n'
                               b'We should be able to parse it.\n',
        '/a_directory/another_file': b'This is another file.\n',
        '/passwords.txt': b'place,user,password\nbank,joesmith,superrich\n'
                          b'alarm system,-,1234\ntreasure chest,-,1111\n'
                          b'uber secret laire,admin,admin\n'}
    for path, text in texts.items():
        assert found[path]['sha256'] == hashlib.sha256(text).hexdigest()


XWAYS_UDF = os.path.join(os.path.dirname(__file__), '..', 'test_images',
                         'private', 'X-WaysTrainingImages', 'UDF Image.e01')


def test_xways_udf_training_disc():
    """Local only (no public source): X-Ways' UDF training image opens as
    UDF and every .jpg on it is a JPEG."""
    if not os.path.exists(XWAYS_UDF):
        pytest.skip("X-Ways training images are local only")
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(XWAYS_UDF)
    try:
        assert handler.get_fs_type(0) == 'UDF'
        fs = handler.get_fs_info(0)
        pictures = [record for path, record in walk(fs).items()
                    if path.lower().endswith('.jpg')]
        assert len(pictures) > 20
        for record in pictures:
            assert record['read'] == record['size']
        heads = [fs.open_meta(inode=r['inode']).read_random(0, 3)
                 for r in pictures]
        assert all(head == b'\xff\xd8\xff' for head in heads)
    finally:
        handler.close_resources()


# --- the formats' own rules, no data --------------------------------------------

def test_jffs2_rtime():
    # A literal, then a repeat count copied from just after where that
    # byte value was last written (compr_rtime.c).
    assert jffs2.rtime(b'a\x03', 4) == b'aaaa'
    assert jffs2.rtime(b'a\x00b\x00a\x01', 4) == b'abab'


def test_jffs2_crc_is_the_kernels():
    # crc32(0, ...) with no inversion: nothing in, nothing out.
    assert jffs2.crc32(b'') == 0


def test_udf_names_times_and_permissions():
    assert udf.cs0(b'\x08caf\xe9') == 'café'
    assert udf.cs0(b'\x10\x00a\x30\x42') == 'aあ'
    # 2024-03-01 12:00:00 at UTC+02:00 (type 1, zone +120 minutes).
    stamp = bytes([0x78, 0x10]) + (2024).to_bytes(2, 'little') + \
        bytes([3, 1, 12, 0, 0, 0, 0, 0])
    assert udf.timestamp(stamp) == (1709287200, 0)
    # Five bits each (delete, change attributes, read, write, execute):
    # owner read/write, group read, other read.
    assert udf._permissions((0b00110 << 10) | (0b00100 << 5) | 0b00100) \
        == 0o644


def test_hfs_leaves_an_hfs_plus_wrapper_to_the_sleuth_kit():
    head = bytearray(2048)
    head[1024:1026] = b'BD'
    head[1024 + 20:1024 + 24] = (4096).to_bytes(4, 'big')
    assert hfs.is_hfs(bytes(head))
    head[1024 + 124:1024 + 126] = (0x482B).to_bytes(2, 'big')
    assert not hfs.is_hfs(bytes(head))


# --- real UDF discs: CDBurnerXP, 1.50 to 2.60 ---------------------------------

#: What the Linux kernel's UDF driver reads from each disc (mount -t udf,
#: sha256sum): the same two files on every one. Linux will not mount 2.60;
#: that disc was written by the same program in the same run, with the
#: same files.
UDF_DISC_FILES = {
    '/test1.txt': 'bc00087e144d38c29939eb46816e3649f212a8e036a711ca354be13fddc6df70',
    '/test2.txt': '177c9c1056d3e7f6570d2a3a049b41ceec390de8a4392eb3dbcab80fae6f7250',
}


@pytest.fixture(scope='module')
def udf_discs(tmp_path_factory):
    import py7zr
    folder = tmp_path_factory.mktemp('udf-discs')
    with py7zr.SevenZipFile(data_path('samples', 'udf_tests.7z')) as archive:
        archive.extractall(str(folder))
    return folder


@pytest.mark.parametrize('revision, metadata', [
    ('1.50', False), ('2.00', False), ('2.01', False),
    ('2.50', True), ('2.60', True)])
def test_real_udf_discs_of_every_revision(udf_discs, revision, metadata):
    """Discs another program burned -- 2.50 and 2.60 with their file
    entries in a metadata partition, the part tested only on discs made
    to the specification here before."""
    from trace_app.core.image_handler import ImageHandler
    path = str(udf_discs / f'test_udf_{revision}.iso')
    with open(path, 'rb') as handle:
        volume = udf.UdfVolume(handle)
        kinds = [m.kind for m in volume.maps]
    assert ('metadata' in kinds) == metadata
    handler = ImageHandler(path)
    try:
        assert handler.get_fs_type(0) == 'UDF'
        fs = handler.get_fs_info(0)
        names = {e['name'] for e in handler.get_directory_contents(0)}
        assert names == {p.strip('/') for p in UDF_DISC_FILES}
        for name, digest in UDF_DISC_FILES.items():
            entry = fs.open(name)
            data = entry.read_random(0, entry.info.meta.size)
            assert hashlib.sha256(data).hexdigest() == digest, name
    finally:
        handler.close_resources()

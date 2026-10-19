"""Flash file systems read by TRACE itself: YAFFS1 and YAFFS2
(core/yaffs.py). No superblock -- each page's spare bytes carry its tags,
and the page size, spare size and the tags' place are found by trying
them. Checked against qnxprobe's fixtures: images Aleph One's image makers
wrote, and images YAFFS's own code wrote with history, each with the
SHA-256 and stat line of every file (tools/testdata/samples.py)."""

import gzip
import hashlib
import io

import pytest
import pytsk3

from tests.conftest import data_path


def _truth(sha_name, stat_name):
    hashes, stats = {}, {}
    with open(data_path('samples', f'qnxprobe-{sha_name}'),
              encoding='utf-8') as handle:
        for line in handle:
            digest, path = line.rstrip('\n').split('  ', 1)
            hashes[path] = digest
    with open(data_path('samples', f'qnxprobe-{stat_name}'),
              encoding='utf-8') as handle:
        for line in handle:
            mode, size, mtime, path = line.rstrip('\n').split(' ', 3)
            stats[path] = (int(mode, 8), int(size), int(mtime))
    return hashes, stats


def _listing(fs):
    hashes, stats = {}, {}

    def walk(directory, path):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            full = f"{path}/{name}".lstrip('/')
            meta = entry.info.meta
            stats[full] = (meta.mode, meta.size, meta.mtime)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                walk(entry.as_directory(), '/' + full)
            elif meta.type != pytsk3.TSK_FS_META_TYPE_LNK:
                hashes[full] = hashlib.sha256(
                    entry.read_random(0, meta.size)).hexdigest()
    walk(fs.open_dir(path='/'), '')
    return hashes, stats


@pytest.mark.parametrize('image, version, page, offset, truth', [
    ('yaffs2-le', 'YAFFS2', 2048, 0, 'src'),
    ('yaffs2-be', 'YAFFS2', 2048, 0, 'src'),
    ('yaffs2-oob2', 'YAFFS2', 2048, 2, 'src'),
    ('yaffs2-history', 'YAFFS2', 2048, 0, 'yaffs2.history'),
    ('yaffs1', 'YAFFS1', 512, 0, 'src'),
    ('yaffs1-history', 'YAFFS1', 512, 0, 'yaffs1.history'),
    ('yaffs1cut-history', 'YAFFS1', 512, 0, 'yaffs1cut.history'),
])
def test_yaffs_reads_every_file_its_writers_wrote(image, version, page,
                                                  offset, truth):
    """Every file's SHA-256, every entry's mode, size and mtime -- folders'
    sizes aside (the stat lines give the source tree's), and lost+found's
    time: YAFFS makes it at mount time when the flash holds no header for
    it, so the flash has no time to give."""
    from trace_app.core import yaffs
    data = gzip.open(data_path('samples', f'qnxprobe-{image}.img.gz')).read()
    fs = yaffs.open_yaffs(io.BytesIO(data))
    assert fs is not None and fs.KIND == version
    assert (fs.image.layout.page, fs.image.layout.offset) == (page, offset)
    sha_name, stat_name = ('yaffs.src.sha256', 'yaffs.src.stat') \
        if truth == 'src' else (f'{truth}.sha256', f'{truth}.stat')
    want_hashes, want_stats = _truth(sha_name, stat_name)
    hashes, stats = _listing(fs)
    assert {k: hashes.get(k) for k in want_hashes} == want_hashes
    for path, (mode, size, mtime) in want_stats.items():
        mine = stats[path]
        if path == 'lost+found':
            assert mine[0] == mode
        elif mode & 0o170000 == 0o040000:
            assert (mine[0], mine[2]) == (mode, mtime), path
        else:
            assert mine == (mode, size, mtime), path


def test_yaffs_through_image_handler(tmp_path):
    """A YAFFS2 NAND dump opened as evidence: its file system named, its
    files listed from the root."""
    from trace_app.core.image_handler import ImageHandler
    image = tmp_path / 'nand.bin'
    image.write_bytes(gzip.open(
        data_path('samples', 'qnxprobe-yaffs2-le.img.gz')).read())
    handler = ImageHandler(str(image))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'YAFFS2'
        names = [e['name'] for e in handler.get_directory_contents(
            0, handler.get_root_inode(0))]
        assert 'dir' in names and 'lost+found' in names
    finally:
        handler.close_resources()


def test_yaffs2_as_evidence_is_read_by_trace_not_tsk(tmp_path):
    """The Sleuth Kit opens YAFFS2 too, but misreads the history image;
    as evidence TRACE's reader is used: the live files equal YAFFS's own
    reading, and Deleted Files lists the older versions."""
    from trace_app.core import deleted
    from trace_app.core.image_handler import ImageHandler
    image = tmp_path / 'nand.yaffs2'
    image.write_bytes(gzip.open(
        data_path('samples', 'qnxprobe-yaffs2-history.img.gz')).read())
    handler = ImageHandler(str(image))
    try:
        assert handler.load_image()
        fs = handler.get_fs_info(0)
        assert type(fs).__name__ == 'YaffsFileSystem'
        hashes, _stats = _listing(fs)
        truth, _ = _truth('yaffs2.history.sha256', 'yaffs2.history.stat')
        assert {p: h for p, h in hashes.items() if p in truth} == truth
        rows = list(deleted.deleted_files(handler))
    finally:
        handler.close_resources()
    paths = {(r['path'], r['state']) for r in rows}
    assert ('/gone/deleted.txt', deleted.RECOVERABLE) in paths
    assert not any('#' in r['path'] for r in rows)


def test_random_data_is_not_taken_for_yaffs():
    import os
    from trace_app.core import yaffs
    assert yaffs.open_yaffs(io.BytesIO(os.urandom(2112 * 64))) is None
    assert yaffs.open_yaffs(io.BytesIO(b'\xff' * (528 * 64))) is None


def _unblob_key():
    import json
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'expected', 'unblob_cramfs_romfs.json')
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)['images']


@pytest.mark.parametrize('image, opener, label', [
    ('unblob-fruits.cramfs_le', 'cramfs', 'little-endian'),
    ('unblob-fruits.old.cramfs_le', 'cramfs', 'little-endian'),
    ('unblob-fruits.cramfs_be', 'cramfs', 'big-endian'),
    ('unblob-fruits.old.cramfs_be', 'cramfs', 'big-endian'),
    ('unblob-fruits.romfs', 'romfs', ''),
])
def test_cramfs_and_romfs_read_as_unblob_extracts_them(tmp_path, image,
                                                       opener, label):
    """Through ImageHandler, as evidence opens: every file's bytes and every
    link's target equal what unblob extracted, unblob's own rules applied
    -- it rewrites an absolute link relative to the root, drops a link
    reaching outside the image, and extracts no device nodes."""
    import posixpath
    import shutil
    from trace_app.core.image_handler import ImageHandler
    target = tmp_path / f"{image.split('-', 1)[1].split('.')[0]}.{opener}"
    shutil.copy(data_path('samples', image), target)
    handler = ImageHandler(str(target))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == opener
        fs = handler.get_fs_info(0)
        assert label in fs.name
        mine = {}

        def walk(directory, path):
            for entry in directory:
                name = entry.info.name.name.decode('utf-8',
                                                   'surrogateescape')
                full = f"{path}/{name}".lstrip('/')
                meta = entry.info.meta
                kind = meta.mode & 0o170000
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    walk(entry.as_directory(), '/' + full)
                elif meta.type == pytsk3.TSK_FS_META_TYPE_LNK:
                    mine[full] = {'link': meta.link}
                elif kind in (0o060000, 0o020000):
                    continue                    # devices: not extracted
                else:
                    data = entry.read_random(0, meta.size)
                    mine[full] = {'size': meta.size,
                                  'sha256': hashlib.sha256(data).hexdigest()}
        walk(fs.open_dir(path='/'), '')
    finally:
        handler.close_resources()
    for path, entry in list(mine.items()):
        if 'link' not in entry:
            continue
        link, depth = entry['link'], path.count('/')
        if link.startswith('/'):
            entry['link'] = '../' * depth + link.lstrip('/')
        elif posixpath.normpath(posixpath.join(posixpath.dirname(path),
                                               link)).startswith('..'):
            del mine[path]
    assert mine == _unblob_key()[image]


# -- deleted files and earlier versions (core/yaffs_recover.py) -------------

def _history_text(n, tag, seed=0):
    """tools/yaffs_history.c's text(): numbered lines, cut at n bytes."""
    out = bytearray()
    while len(out) < n:
        out += f"{tag} line {seed:06d} of the yaffs history fixture\n" \
            .encode()
        seed += 1
    return bytes(out[:n])


def _pwrite(data, offset, payload):
    data = bytearray(data)
    if len(data) < offset:
        data += bytes(offset - len(data))
    data[offset:offset + len(payload)] = payload
    return bytes(data)


def _history_versions(churn):
    """{name: every content the history generator gave it, at a close} --
    do_write() in qnxprobe's tools/yaffs_history.c, step by step."""
    text = _history_text
    out = {}

    def add(name, *versions):
        out.setdefault(name, set()).update(versions)

    keep = text(10000, 'keep')
    add('keep.txt', keep, _pwrite(keep, 10000, text(3000, 'append', 500)))
    big = text(300000, 'big')
    add('big.bin', big, _pwrite(big, 100000, text(9000, 'overwrite', 500)))
    shrunk = text(50000, 'shrunk')
    add('shrunk.bin', shrunk, shrunk[:7000],
        shrunk[:7000] + bytes(13000))
    stale = text(50000, 'stale')
    add('gap.bin', stale, stale[:7000],
        _pwrite(stale[:7000], 60000, text(2500, 'after-gap', 500)))
    add('hole.bin', _pwrite(b'', 100000, text(2500, 'hole', 500)))
    add('deleted.txt', text(30000, 'deleted'))
    add('old_name.txt', text(5000, 'renamed'))
    add('new_name.txt', text(5000, 'renamed'))
    add('linked.txt', text(4000, 'linked'))
    add('hardlink.txt', text(4000, 'linked'))
    for i in range(40):
        small = text(100 + i * 37, 'small')
        add(f'small_{i:02d}.txt', small)
        if i % 3 == 0 and i // 3 < 12:
            add(f'small_{i:02d}.txt',
                _pwrite(small, 50, text(60, 'rewritten', 500)))
    for name in [f'churn_{r:02d}.bin' for r in range(12)] + \
            [f'cut_{r:03d}.bin' for r in range(200)]:
        add(name, text(churn, 'churn'))
    add('unclosed.bin', text(9000, 'unclosed'))
    return out


@pytest.mark.parametrize('image, churn', [
    ('yaffs2-history', 600000),
    ('yaffs1-history', 250000),
])
def test_yaffs_recovers_only_versions_its_writer_wrote(image, churn):
    """Every deleted file or earlier version TRACE calls recoverable is,
    byte for byte, a content YAFFS's own code gave that name at a close --
    never a mix of versions, never another file's pages."""
    from trace_app.core import deleted
    from trace_app.core.yaffs import open_yaffs
    data = gzip.decompress(open(
        data_path('samples', f'qnxprobe-{image}.img.gz'), 'rb').read())
    fs = open_yaffs(io.BytesIO(data))
    scan = fs.deleted_scan()
    versions = _history_versions(churn)
    page = fs.image.page_size
    rows = list(scan.records(0, 0))
    states = {}
    for row in rows:
        name = row['name']
        states[row['state']] = states.get(row['state'], 0) + 1
        entry = fs.open_meta(inode=row['inode'])
        content = entry.read_random(0, entry.info.meta.size)
        if row['state'] == deleted.RECOVERABLE:
            assert content in versions[name], (name, row['detail'])
            continue
        # Partly overwritten: every chunk still there is that version's.
        version = scan._by_id[row['inode']]
        for number, (index, _n) in enumerate(version.pages):
            if index in (None, version.MISSING):
                continue
            piece = content[number * page:(number + 1) * page]
            assert any(v[number * page:(number + 1) * page] == piece
                       for v in versions[name]), (name, number)
    assert states.get(deleted.RECOVERABLE, 0) >= 3


def test_yaffs2_finds_the_deleted_file_and_the_overwritten_bytes():
    from trace_app.core import deleted
    from trace_app.core.yaffs import open_yaffs
    data = gzip.decompress(open(
        data_path('samples', 'qnxprobe-yaffs2-history.img.gz'), 'rb').read())
    fs = open_yaffs(io.BytesIO(data))
    rows = {(r['path'], r['detail']['version']): r
            for r in fs.deleted_scan().records(0, 0)}
    found = rows[('/gone/deleted.txt', 'deleted')]
    assert found['state'] == deleted.RECOVERABLE
    content = fs.open_meta(inode=found['inode']).read_random(0, 30000)
    assert content == _history_text(30000, 'deleted')
    earlier = rows[('/docs/big.bin', 'earlier version')]
    assert fs.open_meta(inode=earlier['inode']).read_random(0, 300000) == \
        _history_text(300000, 'big')
    # The live file is not listed again as a version of itself.
    live = fs.open('/docs/big.bin')
    for (path, _kind), row in rows.items():
        if path == '/docs/big.bin':
            entry = fs.open_meta(inode=row['inode'])
            assert entry.read_random(0, 300000) != \
                live.read_random(0, live.info.meta.size)


def test_yaffs1_ecc_is_yaffs_own():
    """The ECC TRACE computes equals the one YAFFS1 wrote in every live
    page's spare (yaffs_ecc.c), so a deleted page's check means the same."""
    from trace_app.core.yaffs import open_yaffs
    from trace_app.core.yaffs_recover import ecc256
    data = gzip.decompress(open(
        data_path('samples', 'qnxprobe-yaffs1-history.img.gz'),
        'rb').read())
    fs = open_yaffs(io.BytesIO(data))
    image = fs.image
    checked = 0
    for obj, chunks in image.chunks.items():
        for _seq, index, _nbytes in chunks.values():
            page = data[index * 528:index * 528 + 528]
            assert ecc256(page[:256]) == page[512 + 8:512 + 11]
            assert ecc256(page[256:512]) == page[512 + 13:512 + 16]
            checked += 1
    assert checked > 500

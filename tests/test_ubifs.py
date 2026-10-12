"""UBI flash images and UBIFS volumes (core/ubi.py, core/ubifs.py), against
images their own tools wrote and one the Linux kernel wrote
(tools/testdata/build/make_ubifs.py -> ubifs-key.json).

The kernel image is the one that matters most: its tree was committed, then
changed -- files added, deleted, renamed, truncated, overwritten -- and only
synced to the journal, so what is in the index is not what the kernel saw.
Its key is the kernel's own listing (find, stat, sha256sum) taken just
before the flash was read out.
"""

import hashlib
import json

import pytest

from tests.conftest import image_path
from tests.fs_answers import Source, compare, walk
from trace_app.core import ubi, ubifs

KEY = 'ubifs-key.json'
BARE = ['ubifs-lzo.ubifs', 'ubifs-zlib.ubifs', 'ubifs-zstd.ubifs',
        'ubifs-none.ubifs', 'ubifs-favor-lzo.ubifs', 'ubifs-fanout4.ubifs']


def key(name):
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)['images'][name]


def _check(fs, files):
    found = walk(fs)
    problems = compare(found, files)
    assert not problems, '\n'.join(problems[:20])
    for path, record in found.items():
        if record['type'] == 'file':
            assert record['read'] == record['size'], path


@pytest.mark.parametrize('name', BARE)
def test_bare_ubifs_reads_as_written(name):
    fs = ubifs.open_ubifs(Source(image_path(name)))
    assert fs is not None and fs.KIND == 'UBIFS'
    _check(fs, key(name)['files'])


def test_compressors_are_the_ones_asked_for():
    expected = {'ubifs-lzo.ubifs': {ubifs.COMPR_LZO},
                'ubifs-zlib.ubifs': {ubifs.COMPR_ZLIB},
                'ubifs-zstd.ubifs': {ubifs.COMPR_ZSTD},
                'ubifs-none.ubifs': set()}
    for name, methods in expected.items():
        volume = ubifs.open_ubifs(Source(image_path(name))).ubifs
        used = set()
        for inum in volume.inodes:
            used |= volume.compressions(inum)
        assert used == methods, name
    mixed = ubifs.open_ubifs(Source(image_path('ubifs-favor-lzo.ubifs')))
    used = set()
    for inum in mixed.ubifs.inodes:
        used |= mixed.ubifs.compressions(inum)
    assert used == {ubifs.COMPR_LZO, ubifs.COMPR_ZLIB}


def _volumes(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.loaded and handler.volume_kind(0) == 'ubi'
    return handler, {v['name']: v for v in handler.logical_volumes(0)}


def test_ubi_image_volumes():
    expected = key('ubi-multi.ubi')['volumes']
    handler, volumes = _volumes('ubi-multi.ubi')
    try:
        assert set(volumes) == set(expected)
        # The static volume: exactly its data, by the image it was made of.
        raw = volumes['kernel']
        assert raw['size'] == expected['kernel']['size']
        data = handler._volumes[raw['key']].read(0, raw['size'])
        assert hashlib.sha256(data).hexdigest() == \
            expected['kernel']['sha256']
        for name in ('rootfs', 'data'):
            key_ = volumes[name]['key']
            assert handler.get_fs_type(key_) == 'UBIFS'
            _check(handler.get_fs_info(key_), expected[name]['files'])
        assert set(handler.volume_offsets()) == \
            {v['key'] for v in volumes.values()}
    finally:
        handler.close_resources()


def test_kernel_written_ubifs_replays_its_journal():
    entry = key('ubifs-kernel.ubi')
    handler, volumes = _volumes('ubifs-kernel.ubi')
    try:
        fs = handler.get_fs_info(volumes['rootfs']['key'])
        _check(fs, entry['volumes']['rootfs']['files'])
        found = walk(fs)
        for path in entry['gone']:
            assert path not in found
    finally:
        handler.close_resources()


def test_the_journal_is_what_changes_it():
    """Read without the journal, the kernel image is the committed tree:
    the deleted files are still there -- so the test above is a test of
    the replay, not of the index."""
    entry = key('ubifs-kernel.ubi')
    image = ubi.open_ubi(Source(image_path('ubifs-kernel.ubi')))
    volume = image.volumes[0]

    class Stream:
        def __init__(self):
            self.position = 0

        def seek(self, offset, whence=0):
            self.position = offset

        def read(self, length):
            data = volume.read_buffer_at_offset(length, self.position)
            self.position += len(data)
            return data

    replayed = ubifs.UbifsVolume(Stream())
    committed = ubifs.UbifsVolume.__new__(ubifs.UbifsVolume)
    committed._replay = lambda: None
    ubifs.UbifsVolume.__init__(committed, Stream())
    names = {name for (_parent, name) in committed.dents}
    for path in entry['gone']:
        assert path.rsplit('/', 1)[1].encode() in names
    assert len(committed.dents) > len(replayed.dents)


def test_ubi_needs_its_crcs():
    data = bytearray(open(image_path('ubi-multi.ubi'), 'rb').read(64))
    assert ubi.is_ubi(bytes(data))
    data[10] ^= 1
    assert not ubi.is_ubi(bytes(data))


def test_the_tree_shows_ubi_volumes(qapp):
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path('ubi-multi.ubi'))
        tree = window.tree_viewer
        root = tree.topLevelItem(tree.topLevelItemCount() - 1)
        texts = [root.child(i).text(0) for i in range(root.childCount())]
        assert any('ubi / rootfs' in t and 'FS: UBIFS' in t for t in texts)
        assert any('ubi / data' in t and 'FS: UBIFS' in t for t in texts)
        assert any('ubi / kernel' in t for t in texts)
    finally:
        window.cleanup_resources()

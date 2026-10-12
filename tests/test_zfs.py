"""ZFS pools (core/zfs.py) that OpenZFS itself wrote -- Ubuntu 24.04's
kernel module and zpool/zfs, in a QEMU guest (tools/testdata/build/
make_zfs.py). The key is what that guest listed (find, stat, sha256sum) for
every dataset and the snapshot before exporting the pools.

The pools cover a single disk with every compressor, 512-byte records (a
file three indirect levels deep), nested datasets and a snapshot taken
before a file was deleted; a mirror; raidz1 and raidz2 (whole, and with a
disk missing, rebuilt from parity); and a stripe of two top-level vdevs.
"""

import json

import pytest

from tests.conftest import image_path
from tests.fs_answers import compare, walk
from trace_app.core import zfs

KEY = 'zfs-key.json'
POOLS = {'solo': ['zfs-solo.img'],
         'twin': ['zfs-mirror-0.img', 'zfs-mirror-1.img'],
         'parity': [f'zfs-raidz1-{n}.img' for n in range(3)],
         'double': [f'zfs-raidz2-{n}.img' for n in range(4)],
         'wide': ['zfs-stripe-0.img', 'zfs-stripe-1.img']}
#: zpool puts the pool in partition 1, from sector 2048 (make_zfs.py).
START = 2048


def key():
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)


class Partition:
    """A file object over partition 1 of a disk image."""

    def __init__(self, name):
        self._handle = open(image_path(name), 'rb')
        self._handle.seek(0, 2)
        self._size = self._handle.tell() - START * 512
        self._position = 0

    def seek(self, offset, whence=0):
        self._position = offset if whence == 0 else self._size + offset

    def tell(self):
        return self._position

    def read(self, length=-1):
        if length is None or length < 0:
            length = self._size - self._position
        self._handle.seek(START * 512 + self._position)
        data = self._handle.read(max(0, min(length,
                                            self._size - self._position)))
        self._position += len(data)
        return data


def _pool(names):
    return zfs.ZfsPool([Partition(name) for name in names])


def _check(pool, expected):
    names = {d['name'] for d in pool.datasets}
    wanted = {name for name in expected
              if name.split('/')[0].split('@')[0] == pool.name}
    assert names == wanted
    for dataset in pool.datasets:
        fs = zfs.open_dataset(pool, dataset)
        found = walk(fs)
        problems = compare(found, expected[dataset['name']]['files'])
        assert not problems, f"{dataset['name']}:\n" + '\n'.join(problems[:20])
        for path, record in found.items():
            if record['type'] == 'file':
                assert record['read'] == record['size'], path


@pytest.mark.parametrize('pool', sorted(POOLS))
def test_every_dataset_reads_as_written(pool):
    _check(_pool(POOLS[pool]), key()['datasets'])


@pytest.mark.parametrize('pool, gone', [('parity', 0), ('parity', 1),
                                        ('parity', 2), ('double', 1),
                                        ('twin', 0)])
def test_a_missing_disk_is_rebuilt(pool, gone):
    names = [n for i, n in enumerate(POOLS[pool]) if i != gone]
    built = _pool(names)
    assert built.degraded or pool == 'twin'
    _check(built, key()['datasets'])


@pytest.mark.parametrize('names', [['zfs-raidz1-0.img'],
                                   ['zfs-raidz2-0.img', 'zfs-raidz2-3.img'],
                                   ['zfs-stripe-1.img']])
def test_too_few_disks_are_refused_up_front(names):
    """Small blocks whose sectors are all on the disks present would read
    and the rest would not: the pool is refused with the reason instead."""
    with pytest.raises(zfs.ZfsError, match='needed'):
        _pool(names)


def test_the_snapshot_keeps_what_was_deleted_after_it():
    expected = key()
    pool = _pool(POOLS['solo'])
    live = walk(zfs.open_dataset(pool, next(
        d for d in pool.datasets if d['name'] == 'solo')))
    snapshot = next(d for d in pool.datasets if d['name'] == 'solo@before')
    assert snapshot['kind'] == 'snapshot'
    before = walk(zfs.open_dataset(pool, snapshot))
    for path in expected['deleted_after_snapshot']:
        assert path in before and path not in live
    assert live['/docs/notes.txt']['sha256'] != \
        before['/docs/notes.txt']['sha256']


def _data_pointers(objset, dnode):
    """The level-0 block pointers under a file's first indirect blocks
    (indirect blocks are metadata, always lz4). On ashift 12 a small file
    cannot shrink below one sector, so ZFS stores it as is: only files of
    several blocks show the dataset's compressor."""
    pointers = dnode.blkptrs
    for _level in range(dnode.nlevels - 1):
        first = next((bp for bp in pointers if not bp.hole), None)
        if first is None:
            return []
        block = objset._indirect(first)
        pointers = [zfs.BlockPointer(block[i:i + zfs.BP])
                    for i in range(0, len(block), zfs.BP)]
    return pointers


def test_compression_of_each_dataset():
    """The datasets really are compressed as named (else the compressor
    tests above would pass on stored blocks)."""
    pool = _pool(POOLS['solo'])
    seen = {}
    for dataset in pool.datasets:
        if dataset['kind'] != 'filesystem':
            continue
        objset = pool.open_dataset(dataset)
        methods = set()
        meta = objset.meta
        for obj in range(1, (meta.maxblkid + 1) * meta.datablksz // 512):
            dnode = objset.dnode(obj)
            if dnode is None or dnode.type != 19:        # plain file
                continue
            for bp in _data_pointers(objset, dnode):
                if not bp.hole:
                    methods.add(zfs.COMPRESSION_NAMES.get(bp.compression))
        seen[dataset['name']] = methods
    expected = key()['datasets']
    for name, methods in seen.items():
        want = expected[name]['compression']
        if want == 'off':
            assert methods <= {'off'}, name
        elif methods:
            assert want in methods, (name, methods)


def test_through_image_handler_and_assembly(tmp_path):
    from trace_app.core import assembly
    from trace_app.core.image_handler import ImageHandler
    solo = ImageHandler(image_path('zfs-solo.img'))
    try:
        assert solo.volume_kind(START) == 'zfs'
        datasets = solo.zfs_datasets(START)
        assert [d['name'] for d in datasets if d['kind'] == 'snapshot'] == \
            ['solo@before']
        offsets = solo.volume_offsets()
        assert {d['key'] for d in datasets if d['kind'] == 'filesystem'} \
            <= set(offsets)
        assert solo.get_fs_type(datasets[0]['key']) == 'ZFS'
    finally:
        solo.close_resources()

    handlers = {image_path(n): ImageHandler(image_path(n))
                for n in POOLS['parity'] + POOLS['twin']}
    try:
        alone = handlers[image_path(POOLS['parity'][0])]
        assert alone.zfs_datasets(START) == []
        assert 'needed' in alone.zfs_problem(START)
        groups = assembly.find_groups(handlers)
        # The mirror reads from either disk: nothing to assemble.
        assert [(g['kind'], g['name'], g['level']) for g in groups] == \
            [('zfs', 'parity', 'raidz1')]
        descriptor = assembly.write(str(tmp_path), groups[0])
    finally:
        for handler in handlers.values():
            handler.close_resources()
    assembled = ImageHandler(descriptor)
    try:
        assert assembled.loaded and assembled.volume_kind(0) == 'zfs'
        [dataset] = assembled.zfs_datasets(0)
        fs = assembled.get_fs_info(dataset['key'])
        problems = compare(walk(fs), key()['datasets']['parity']['files'])
        assert not problems, '\n'.join(problems[:20])
    finally:
        assembled.close_resources()


def test_label_checksums_are_checked():
    source = Partition('zfs-solo.img')
    config, uberblocks = zfs.read_label(source)
    assert config['name'] == 'solo' and len(uberblocks) > 1
    # The first uberblock slot (ashift 12: 4 KiB) of label 0, as written.
    source.seek(zfs.UBERBLOCK_OFFSET)
    slot = bytearray(source.read(4096))
    assert slot[:8] == zfs.UB_MAGIC.to_bytes(8, 'little')
    assert zfs._label_checksum_ok(bytes(slot), zfs.UBERBLOCK_OFFSET)
    slot[100] ^= 1
    assert not zfs._label_checksum_ok(bytes(slot), zfs.UBERBLOCK_OFFSET)


def _tree_texts(item):
    out = [item.text(0)]
    for index in range(item.childCount()):
        out += _tree_texts(item.child(index))
    return out


def test_the_tree_shows_datasets_and_snapshots(qapp):
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path('zfs-solo.img'))
        tree = window.tree_viewer
        texts = _tree_texts(tree.topLevelItem(tree.topLevelItemCount() - 1))
        assert any('(ZFS pool' in text for text in texts)
        assert 'solo (ZFS dataset)' in texts
        assert 'solo@before (ZFS snapshot)' in texts
        assert 'solo/nested/child (ZFS dataset)' in texts
        assert window.open_evidence_image(image_path('zfs-raidz1-1.img'))
        texts = _tree_texts(tree.topLevelItem(tree.topLevelItemCount() - 1))
        assert any(text.startswith('ZFS pool not readable here') and
                   'needed' in text for text in texts)
    finally:
        window.cleanup_resources()

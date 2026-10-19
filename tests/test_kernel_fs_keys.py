"""TRACE's QNX4, QNX6, cramfs and romfs readers against the Linux kernel's
own reading of the same images (tools/testdata/build/make_kernel_keys.py:
each image mounted read-only by the kernel's driver in a QEMU guest and
listed -- path, type, size, SHA-256 or link target, mtime).

Built images are in test_images/built (Linux CI builds them; locally,
Docker -- see the builder's docstring). Read through ImageHandler, as
evidence opens.

Where the kernel itself is wrong, the test says so and holds the kernel
to what it does read:

* QNX6: Linux 6.8 picks the superblock with the higher serial ("#2
  active") and then builds the inode tree from superblock #1 anyway
  (fs/qnx6/inode.c, `qnx6_private_inode(s, &sb1->Inode)`), so it shows
  the state *before* the last commit. TRACE's current state equals the
  tar of the files QNX's mkqnx6fs was given (tests/test_qnx.py); the
  kernel's listing must equal TRACE's previous state (`state=1`).
* romfs: the kernel stops listing a folder at a name of 128 bytes or
  more (ROMFS_MAXFN); genromfs writes any length. The source tree is the
  key for the built images, and every entry the kernel did list must read
  the same.
"""

import hashlib
import json
import os
import shutil

import pytest
import pytsk3

from tests.conftest import image_path

#: The image's own file name -> (opener kind, extension it is opened by).
IMAGES = {
    'qnx4-tree.img': ('QNX4', '.img'),
    'cramfs-le.cramfs': ('cramfs', '.cramfs'),
    'cramfs-be.cramfs': ('cramfs', '.cramfs'),
    'romfs.img': ('romfs', '.img'),
    'openqnx-qnxfs.img': ('QNX4', '.img'),
    'qnxmount-qnx6-test_image.bin': ('QNX6', '.bin'),
    'unblob-fruits.cramfs_le': ('cramfs', '.cramfs'),
    'unblob-fruits.old.cramfs_le': ('cramfs', '.cramfs'),
    'unblob-fruits.romfs': ('romfs', '.romfs'),
}
#: Times these file systems keep (cramfs and romfs keep none).
TIMED = ('QNX4', 'QNX6')


def _key():
    with open(image_path('kernel-fs-key.json'), encoding='utf-8') as handle:
        return json.load(handle)['images']


def _source(name):
    if name.startswith(('openqnx-', 'qnxmount-', 'unblob-')):
        from tests.conftest import data_path
        return data_path('samples', name)
    return image_path(name)


def _walk(fs):
    """{path: record} as the guest's listing has them, live entries only;
    deleted ones apart."""
    live, deleted = {}, {}

    def walk(directory, path):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            if name in ('.', '..'):
                continue
            full = f"{path}/{name}"
            meta = entry.info.meta
            gone = bool(int(entry.info.name.flags) &
                        int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
            target = deleted if gone else live
            kind = meta.mode & 0o170000 if meta.mode else 0
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                target[full] = {'type': 'dir'}
                if not gone:
                    walk(entry.as_directory(), full)
            elif meta.type == pytsk3.TSK_FS_META_TYPE_LNK:
                target[full] = {'type': 'link', 'target': meta.link,
                                'size': len(meta.link.encode())}
            elif kind in (0o060000, 0o020000, 0o010000, 0o140000):
                target[full] = {'type': 'other'}
            else:
                data = entry.read_random(0, meta.size) if meta.size else b''
                target[full] = {'type': 'file', 'size': meta.size,
                                'sha256': hashlib.sha256(data).hexdigest(),
                                'mtime': meta.mtime}
    walk(fs.open_dir(path='/'), '')
    return live, deleted


def _open(tmp_path, name, extension):
    from trace_app.core.image_handler import ImageHandler
    target = tmp_path / (os.path.splitext(name)[0].replace('.', '-') +
                         extension)
    shutil.copy(_source(name), target)
    handler = ImageHandler(str(target))
    assert handler.load_image()
    return handler


@pytest.mark.parametrize('name', sorted(IMAGES))
def test_every_entry_reads_as_the_kernel_reads_it(tmp_path, name):
    kind, extension = IMAGES[name]
    entry = _key().get(name)
    if entry is None or 'kernel' not in entry and 'tree' not in entry:
        pytest.skip(f"{name}: not in kernel-fs-key.json (rebuild it)")
    handler = _open(tmp_path, name, extension)
    try:
        assert handler.get_fs_type(0) == kind
        live, _deleted = _walk(handler.get_fs_info(0))
    finally:
        handler.close_resources()
    if kind == 'QNX6':
        pytest.skip("the kernel reads QNX6's previous state: "
                    "test_the_kernel_reads_qnx6s_previous_state")
    expected = entry['tree'] if 'tree' in entry else entry['kernel']
    expected = {path: dict(record) for path, record in expected.items()}
    if kind not in TIMED or 'tree' in entry:
        for record in list(expected.values()) + list(live.values()):
            record.pop('mtime', None)
    assert live == expected
    for path, record in (entry.get('kernel') or {}).items() \
            if 'tree' in entry else ():
        record = dict(record)
        record.pop('mtime', None)
        assert live[path] == record, path


def test_the_kernel_reads_qnx6s_previous_state():
    from trace_app.core.qnx6 import open_qnx6
    entry = _key().get('qnxmount-qnx6-test_image.bin')
    if entry is None or 'kernel' not in entry:
        pytest.skip("not in kernel-fs-key.json (rebuild it)")
    with open(_source('qnxmount-qnx6-test_image.bin'), 'rb') as handle:
        previous, _ = _walk(open_qnx6(handle, state=1))
        current, _ = _walk(open_qnx6(handle))
    assert previous == entry['kernel']
    assert len(current) > len(previous)     # the commit the kernel misses


def test_qnx4_lists_a_deleted_file_only_while_its_blocks_are_free(tmp_path):
    entry = _key().get('qnx4-tree.img')
    if entry is None:
        pytest.skip("qnx4-tree.img: not in kernel-fs-key.json")
    handler = _open(tmp_path, 'qnx4-tree.img', '.img')
    try:
        _live, deleted = _walk(handler.get_fs_info(0))
    finally:
        handler.close_resources()
    for path in entry['overwritten']:
        assert path not in deleted          # its blocks are another file's
    for path, record in entry['deleted'].items():
        found = dict(deleted[path])
        found.pop('mtime', None)
        assert found == {'type': 'file', **record}
    assert set(deleted) == set(entry['deleted'])


def test_qnx4_free_space_is_the_bitmap(tmp_path):
    """Carving's free-space map: every block the bitmap marks, and no
    other -- checked against the bitmap file read through the reader."""
    handler = _open(tmp_path, 'openqnx-qnxfs.img', '.img')
    try:
        fs = handler.get_fs_info(0)
        ranges = fs.allocated_ranges()
        bitmap = fs.open('/.bitmap')
        bits = bitmap.read_random(0, bitmap.info.meta.size)
    finally:
        handler.close_resources()
    used = {start // 512 + n for start, length in ranges
            for n in range(length // 512)}
    # The bitmap covers 2,048 blocks of the 2,688; past it nothing says a
    # block is free.
    marked = {block for block in range(len(bits) * 8)
              if bits[block >> 3] & (1 << (block & 7))}
    assert len(bits) * 8 == 2048
    assert used == marked | set(range(2048, 1376256 // 512))
    assert fs.info.block_count * fs.info.block_size == 1376256
    # .boot -- the IFS -- lies in used blocks.
    assert all(block in used for block in range(43, 43 + 2645))

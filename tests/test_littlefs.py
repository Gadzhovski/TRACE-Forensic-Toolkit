"""LittleFS (core/littlefs.py) and the U-Boot environment
(core/uboot_env.py) against their own tools' reading of images they wrote
(tools/testdata/build/make_littlefs.py: littlefs-python, littlefs's C
code; make_uboot_env.py: mkenvimage, read by libubootenv's fw_printenv).
Through ImageHandler, as evidence opens."""

import hashlib
import io
import json
import random
import shutil

import pytest
import pytsk3

from tests.conftest import image_path


def _key(name):
    with open(image_path(name), encoding='utf-8') as handle:
        return json.load(handle)['images']


def _walk(fs):
    out = {}

    def walk(directory, path):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            full = f"{path}/{name}"
            meta = entry.info.meta
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                out[full] = {'type': 'dir'}
                walk(entry.as_directory(), full)
            else:
                data = entry.read_random(0, meta.size) if meta.size else b''
                out[full] = {'type': 'file', 'size': meta.size,
                             'sha256': hashlib.sha256(data).hexdigest()}
    walk(fs.open_dir(path='/'), '')
    return out


def _open(tmp_path, name, extension):
    from trace_app.core.image_handler import ImageHandler
    target = tmp_path / (name.rsplit('.', 1)[0] + extension)
    shutil.copy(image_path(name), target)
    handler = ImageHandler(str(target))
    assert handler.load_image()
    return handler


@pytest.mark.parametrize('name', ['lfs-512.img', 'lfs-4096.img'])
def test_littlefs_reads_as_littlefs_does(tmp_path, name):
    key = _key('littlefs-key.json')[name]
    handler = _open(tmp_path, name, '.lfs')
    try:
        assert handler.get_fs_type(0) == 'LittleFS'
        fs = handler.get_fs_info(0)
        assert fs.image.block_size == key['block_size']
        assert _walk(fs) == key['files']
        for gone in key['gone']:
            assert gone not in key['files']
        # Free space: metadata pairs and file blocks are used, the rest
        # free -- and what is used holds every file's bytes.
        used = sum(length for _start, length in fs.allocated_ranges())
        assert 0 < used < fs.image.block_count * fs.image.block_size
    finally:
        handler.close_resources()


def test_littlefs_expanded_superblock_and_relocated_pairs():
    """block_cycles 2: the superblock is in more than one pair (the root
    is the last), and metadata moved -- yet everything reads."""
    from trace_app.core.littlefs import NULL, open_littlefs
    with open(image_path('lfs-4096.img'), 'rb') as handle:
        fs = open_littlefs(handle)
        image = fs.image
        pairs, pair = 0, (0, 1)
        while pair != (NULL, NULL) and pairs < 100:
            pairs += 1
            pair = tuple(image.fetch(pair).tail)
        assert pairs > 1
        assert image.root != (0, 1)


def test_random_data_is_not_taken_for_littlefs_or_uboot():
    from trace_app.core.littlefs import open_littlefs
    from trace_app.core.uboot_env import open_uboot_env
    rng = random.Random(3)
    for _ in range(10):
        blob = bytes(rng.getrandbits(8) for _ in range(65536))
        assert open_littlefs(io.BytesIO(blob)) is None
        assert open_uboot_env(io.BytesIO(blob)) is None
    # The magic alone is not a file system.
    fake = bytearray(65536)
    fake[8:16] = b'littlefs'
    assert open_littlefs(io.BytesIO(bytes(fake))) is None


@pytest.mark.parametrize('name', ['uboot-env.bin', 'uboot-env-be.bin',
                                  'uboot-env-64k.bin',
                                  'uboot-env-redundant.bin'])
def test_uboot_environment_reads_as_fw_printenv_does(tmp_path, name):
    key = _key('uboot-env-key.json')[name]
    handler = _open(tmp_path, name, '.bin')
    try:
        assert handler.get_fs_type(0) == 'U-Boot environment'
        fs = handler.get_fs_info(0)
        names = {e.info.name.name.decode() for e in fs.open_dir(path='/')}
        text = fs.open('/environment.txt')
        lines = text.read_random(0, text.info.meta.size).decode('utf-8')
        found = dict(line.split('=', 1) for line in lines.splitlines())
        assert found == key['variables']
        if 'other_copy' in key:
            assert names == {'environment.txt', 'other-copy.txt'}
            other = fs.open('/other-copy.txt')
            lines = other.read_random(0, other.info.meta.size).decode()
            assert dict(line.split('=', 1)
                        for line in lines.splitlines()) == key['other_copy']
        else:
            assert names == {'environment.txt'}
        if name == 'uboot-env-be.bin':
            assert fs.facts()['CRC'] == 'big-endian'
    finally:
        handler.close_resources()

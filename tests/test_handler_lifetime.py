"""A closed image is let go (core/image_handler.py).

get_fs_info / get_fs_type were functools.lru_cache'd methods: the cache is
the class's, keyed by `self`, so every handler that read a volume stayed
alive with its file systems -- and on Windows a raw image could not be
moved or deleted after its evidence was removed. Unlocking one image's
volume also emptied every other image's cache.
"""

import gc
import os
import shutil
import weakref

from tests.conftest import image_path
from trace_app.core.image_handler import ImageHandler

IMAGE = '7-ntfs-undel.dd'


def _copy(tmp_path, name):
    target = tmp_path / name
    shutil.copyfile(image_path(IMAGE), target)
    return str(target)


def _read_every_volume(handler):
    keys = handler.volume_offsets()
    assert keys
    for key in keys:
        assert handler.get_fs_info(key) is not None
        assert handler.get_fs_type(key) == 'NTFS'
        handler.get_directory_contents(key)
    return keys


def test_a_closed_handler_is_collected_and_its_file_released(tmp_path):
    path = _copy(tmp_path, 'evidence.dd')
    handler = ImageHandler(path)
    _read_every_volume(handler)
    alive = weakref.ref(handler)
    handler.close_resources()
    del handler
    gc.collect()
    assert alive() is None
    os.replace(path, path + '.moved')        # Windows refuses an open file
    os.remove(path + '.moved')


def test_misses_are_remembered_per_image(tmp_path, monkeypatch):
    first = ImageHandler(_copy(tmp_path, 'a.dd'))
    second = ImageHandler(_copy(tmp_path, 'b.dd'))
    keys = _read_every_volume(first)
    _read_every_volume(second)
    calls = []
    original = ImageHandler._open_fs_info

    def counted(self, key):
        calls.append((self, key))
        return original(self, key)
    monkeypatch.setattr(ImageHandler, '_open_fs_info', counted)
    nowhere = 123456789                         # past the image's end
    assert first.get_fs_info(nowhere) is None
    assert first.get_fs_info(nowhere) is None
    assert len(calls) == 1                       # the miss was kept
    # Forgetting one image's volume leaves the other image's caches alone.
    first._forget_filesystem(keys[0])
    assert first.get_fs_info(nowhere) is None and len(calls) == 2
    assert second.get_fs_info(keys[0]) is not None
    assert all(handler is first for handler, _ in calls)
    assert first.get_fs_info(keys[0]) is not None
    for handler in (first, second):
        handler.close_resources()

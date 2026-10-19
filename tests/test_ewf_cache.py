"""EWFImgInfo's block cache returns exactly what libewf does
(core/image_handler.py)."""

import random

import pyewf

from tests.conftest import image_path
from trace_app.core.image_handler import EWFImgInfo

IMAGE = 'ntfs1-gen2.E01'


def _handle():
    handle = pyewf.handle()
    handle.open(pyewf.glob(image_path(IMAGE)))
    return handle


def test_cached_reads_equal_libewf_reads():
    cached, direct = EWFImgInfo(_handle()), _handle()
    size = direct.get_media_size()
    block = EWFImgInfo.CACHE_BLOCK
    rng = random.Random(7)
    asks = [(0, 512), (block - 3, 10), (block * 5 - 1, block * 3 + 2),
            (size - 100, 100), (size - 100, 5000), (size - 1, 1),
            (size + 10, 50), (block * 9, EWFImgInfo.CACHE_BYPASS)]
    asks += [(rng.randrange(size), rng.choice((1, 512, 4096, 65536,
                                               200_000)))
             for _ in range(400)]
    for offset, length in asks + asks[::-1]:         # again, from cache
        direct.seek(offset)
        assert cached.read(offset, length) == direct.read(length), \
            (offset, length)
    assert len(cached._blocks) <= EWFImgInfo.CACHE_BLOCKS
    cached.close()
    direct.close()


def test_the_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(EWFImgInfo, 'CACHE_BLOCKS', 8)
    cached = EWFImgInfo(_handle())
    for n in range(40):
        cached.read(n * EWFImgInfo.CACHE_BLOCK, 100)
    assert len(cached._blocks) == 8
    assert list(cached._blocks) == list(range(32, 40))     # newest kept
    cached.close()

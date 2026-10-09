"""Remote Desktop bitmap caches (trace_app/core/rdpcache.py).

dissect.target's test caches, checked against the values its tests expect:
the number of tiles and the MD5 of their pixels, bottom-up, blue-green-red
with the fourth byte 255 -- a Windows 7+ Cache0000.bin (254 tiles) and an
older bcache24.bmc (40 tiles, the leftovers of older tiles in each slot
not counted). Then a collection holding them: the thumbnails job lists
every tile under its collage, the grid's reader gives each one as a
picture, and the cache opens as members.
"""

import hashlib
import io
import os
import shutil

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
EXPECTED = {'rdp-Cache0000.bin': ('bin', 254,
                                  '7e7a88aa54efd92b3ab8e4f7b29afe3f'),
            'rdp-bcache24.bmc': ('bmc', 40,
                                 '3fb7c485c7ee83e0d5d748d2e1c9d206')}


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def read(name):
    with open(sample(name), 'rb') as handle:
        return handle.read()


@pytest.mark.parametrize('name', sorted(EXPECTED))
def test_tiles_as_dissect_expects(name):
    from trace_app.core import rdpcache
    kind, count, md5 = EXPECTED[name]
    parsed = rdpcache.parse(read(name))
    assert parsed['format'] == kind
    assert len(parsed['tiles']) == count
    assert parsed['compressed'] == 0
    assert hashlib.md5(b''.join(t['bgrx'] for t in parsed['tiles'])
                       ).hexdigest() == md5
    assert all(0 < t['width'] <= 64 and 0 < t['height'] <= 64
               for t in parsed['tiles'])


def test_tile_pictures_keep_their_pixels():
    from PIL import Image
    from trace_app.core import rdpcache
    tiles = rdpcache.parse(read('rdp-Cache0000.bin'))['tiles']
    tile = tiles[0]
    picture = Image.open(io.BytesIO(rdpcache.tile_png(tile)))
    assert picture.size == (tile['width'], tile['height'])
    # The stored rows are bottom-up: the picture's top row is the last.
    width = tile['width']
    last = tile['bgrx'][-width * 4:]
    top = [picture.getpixel((x, 0)) for x in range(width)]
    assert top == [tuple(last[x * 4 + 2 - c] for c in range(3))
                   for x in range(width)]
    sheet = rdpcache.collage(tiles)
    assert sheet.size == (64 * 64, 64 * 4)


def test_detection_by_content_and_not_by_accident():
    from trace_app.core import archives, rdpcache
    assert archives.detect_archive(read('rdp-Cache0000.bin')) == 'rdpcache'
    assert archives.detect_archive(read('rdp-bcache24.bmc')) == 'rdpcache'
    assert not rdpcache.looks_like_bmc(b'\x00' * 40000)
    assert not rdpcache.looks_like_bmc(os.urandom(40000))
    assert rdpcache.is_rdp_cache_name('Cache0001.bin')
    assert rdpcache.is_rdp_cache_name('bcache22.bmc')
    assert not rdpcache.is_rdp_cache_name('cache.bin')


def test_a_collection_s_rdp_caches_reach_thumbnails(tmp_path):
    from trace_app.core import archives, thumbnails
    from trace_app.core.case import Case, parse_artifact_ref
    from trace_app.core.image_handler import ImageHandler
    cache_dir = (tmp_path / 'collection' / 'C' / 'Users' / 'alice' /
                 'AppData' / 'Local' / 'Microsoft' /
                 'Terminal Server Client' / 'Cache')
    cache_dir.mkdir(parents=True)
    shutil.copyfile(sample('rdp-Cache0000.bin'), cache_dir / 'Cache0000.bin')
    shutil.copyfile(sample('rdp-bcache24.bmc'), cache_dir / 'bcache24.bmc')
    # A file of the same name elsewhere is not the RDP client's.
    (tmp_path / 'collection' / 'C' / 'Cache0001.bin').write_bytes(
        b'RDP8bmp\x00' + b'\x06\x00\x00\x00')
    case = Case.create(str(tmp_path / 'case'), 'RDP')
    evidence = case.add_evidence(str(tmp_path / 'collection'))
    handler = ImageHandler(str(tmp_path / 'collection'))
    try:
        assert thumbnails.analyse_evidence(handler, case, evidence) == \
            254 + 40 + 2
        rows = case.thumbnails(evidence)
        assert {r['user'] for r in rows} == {'alice'}
        by_cache = {}
        for row in rows:
            by_cache.setdefault(row['cache_path'].rsplit('/', 1)[-1],
                                []).append(row)
        assert sorted(by_cache) == ['Cache0000.bin', 'bcache24.bmc']
        bin_rows = by_cache['Cache0000.bin']
        assert bin_rows[0]['location'] == 'collage'
        assert bin_rows[1]['location'] == 'tile:1'
        # The grid's reader: the whole cache read once, a picture per row.
        parsed = parse_artifact_ref(bin_rows[0]['cache_ref'])
        content, _ = handler.get_file_content(parsed['inode'],
                                              parsed['start_offset'])
        tile = rdpcache_tiles(content)[9]
        picture = thumbnails.picture_bytes(content, bin_rows[10])
        assert picture[:8] == b'\x89PNG\r\n\x1a\n'
        assert bin_rows[10]['sha256'] == \
            hashlib.sha256(tile['bgrx']).hexdigest()
        assert thumbnails.picture_bytes(content, bin_rows[0])[:4] == \
            b'\x89PNG'
        members = archives.list_members(content, 'rdpcache')
        assert len(members) == 255
        assert archives.read_member(content, members[1]['name'],
                                    'rdpcache')[:4] == b'\x89PNG'
    finally:
        handler.close_resources()
        case.close()


def rdpcache_tiles(content):
    from trace_app.core import rdpcache
    return rdpcache.parse(content)['tiles']

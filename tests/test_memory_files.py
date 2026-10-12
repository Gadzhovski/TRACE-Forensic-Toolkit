"""Page, swap and hibernation files (core/memory_files.py): searched and
carved as free space is, each hit pointing at its bytes on the image.

A FAT volume is built here with a pagefile.sys holding text, a URL and a
JPEG at odd offsets amid noise, a live document, and a second JPEG in
free space: searching finds what is in the page file (and says where);
carving the 'memory' source recovers its JPEG byte for byte, and only it.
"""

import io
import os
import random

import pytest

from tests.disk_builders import fat16_volume

SECRET = 'the passphrase is Correct-Horse-Battery-Staple-77'
URL = 'https://example.org/hidden-page-4471'


def _jpeg(seed):
    from PIL import Image
    rng = random.Random(seed)
    picture = Image.new('RGB', (64, 48))
    picture.putdata([tuple(rng.randrange(256) for _ in range(3))
                     for _ in range(64 * 48)])
    out = io.BytesIO()
    picture.save(out, 'JPEG', quality=90)
    return out.getvalue()


@pytest.fixture(scope='module')
def volume(tmp_path_factory):
    rng = random.Random(3)
    page = bytearray(rng.getrandbits(8) for _ in range(600_000))
    text = SECRET.encode() + b'\0' * 7 + URL.encode()
    page[123_457:123_457 + len(text)] = text
    in_page = _jpeg(1)
    page[300_001:300_001 + len(in_page)] = in_page
    in_free = _jpeg(2)
    image, placed, free = fat16_volume(
        [('NOTES.TXT', b'an ordinary file\n'),
         ('PAGEFILE.SYS', bytes(page))],
        free=[])
    # A JPEG in free space too: carved from 'unallocated', not 'memory'.
    free_jpeg_at = free + 4096 * 3 + 512
    image = bytearray(image)
    image[free_jpeg_at:free_jpeg_at + len(in_free)] = in_free
    path = tmp_path_factory.mktemp('memory') / 'disk.dd'
    path.write_bytes(bytes(image))
    return {'path': str(path), 'page_at': placed['PAGEFILE.SYS'],
            'page': bytes(page), 'in_page': in_page, 'in_free': in_free,
            'free_jpeg_at': free_jpeg_at}


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.load_image()
    return handler


def test_memory_files_are_found_with_their_runs(volume):
    from trace_app.core import memory_files
    handler = _handler(volume['path'])
    try:
        found = memory_files.find(handler)
        assert [f['name'] for f in found] == ['PAGEFILE.SYS']
        item = found[0]
        assert item['size'] == len(volume['page'])
        assert sum(length for _b, length in item['runs']) == item['size']
        # The runs are the file's bytes on the image.
        data = b''.join(handler.read(b, length) for b, length in
                        item['runs'])
        assert data == volume['page']
    finally:
        handler.close_resources()


def test_search_finds_what_was_in_memory(volume, tmp_path):
    from trace_app.core.case import parse_artifact_ref
    from trace_app.core.indexer import index_evidence, index_free_space
    from trace_app.core.search_index import SearchIndex
    handler = _handler(volume['path'])
    index = SearchIndex(str(tmp_path))
    try:
        index_evidence(handler, index, 1)
        index_free_space(handler, index, 1)
        index.commit()
        hits = index.search('"Correct-Horse-Battery-Staple-77"')
        memory = [h for h in hits if h.get('kind') == 'memory']
        assert len(memory) == 1
        hit = memory[0]
        assert hit['path'].startswith('/PAGEFILE.SYS [memory]/bytes ')
        ref = parse_artifact_ref(hit['artifact_ref'])
        assert ref['kind'] == 'span'
        span = handler.read(ref['begin'], ref['end'] - ref['begin'])
        assert SECRET.encode() in span
        assert URL in {row['value'] for row in index.indicators('url')}
    finally:
        index.close()
        handler.close_resources()


def test_the_memory_source_carves_only_the_memory_files(volume, tmp_path):
    from trace_app.core.carving import carve_evidence, read_carved
    from trace_app.core.case import Case
    handler = _handler(volume['path'])
    case = Case.create(str(tmp_path / 'case'), 'Memory')
    try:
        evidence = case.add_evidence(volume['path'])
        carve_evidence(handler, case, evidence, ['jpg'], source='memory')
        rows = case.carved_files(evidence)
        assert len(rows) == 1
        row = rows[0]
        assert row['offset'] == volume['page_at'] + 300_001
        data = read_carved(handler.read, row['offset'], row['size'], None)
        assert data == volume['in_page']
        assert row['origin']['path'] == '/PAGEFILE.SYS'
        assert 'memory file' in row['origin']['basis']
        # Free space is another source: there, its own JPEG.
        carve_evidence(handler, case, evidence, ['jpg'], source='unallocated')
        offsets = {r['offset'] for r in case.carved_files(evidence)}
        assert volume['free_jpeg_at'] in offsets
        assert volume['page_at'] + 300_001 not in offsets
    finally:
        handler.close_resources()
        case.close()


def test_an_image_without_memory_files_has_none(tmp_path):
    from trace_app.core import memory_files
    image, _placed, _free = fat16_volume([('A.TXT', b'x' * 100)])
    path = tmp_path / 'plain.dd'
    path.write_bytes(image)
    handler = _handler(str(path))
    try:
        assert memory_files.find(handler) == []
        assert memory_files.ranges(handler) == []
    finally:
        handler.close_resources()


def test_the_setting_turns_memory_indexing_off(volume, tmp_path,
                                               monkeypatch):
    from trace_app.core import indexer
    from trace_app.core.search_index import SearchIndex
    monkeypatch.setattr(indexer, 'INDEX_MEMORY_FILES', False)
    handler = _handler(volume['path'])
    index = SearchIndex(str(tmp_path))
    try:
        indexer.index_evidence(handler, index, 1)
        indexer.index_free_space(handler, index, 1)
        index.commit()
        assert not [h for h in index.search('"Correct-Horse-Battery-Staple-77"')
                    if h.get('kind') == 'memory']
    finally:
        index.close()
        handler.close_resources()
    assert os.path.exists(volume['path'])

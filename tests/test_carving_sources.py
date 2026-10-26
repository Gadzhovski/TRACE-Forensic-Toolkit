"""Carving's sources kept together, pictures that start inside a sector,
and whole-image carves of live files (core/carving, core/vics).

Measured on the M57 'Jean' image (tools/score/vics_gap.py): of the
pictures AXIOM carved that TRACE did not, 634 started inside a sector --
586 byte-identical on disk, pictures kept whole inside files since
deleted. Every input here is generated.
"""

import hashlib
import io
import json

import pytest

from tests.disk_builders import fat16_volume


def picture(kind, colour, size=(40, 30)):
    from PIL import Image
    out = io.BytesIO()
    Image.new('RGB', size, colour).save(out, kind)
    return out.getvalue()


@pytest.fixture
def raw_disk(tmp_path):
    """No file system: every byte unallocated. A JPEG on a sector start,
    a PNG and a GIF part-way into sectors."""
    jpeg, png, gif = (picture('JPEG', 'red'), picture('PNG', 'blue'),
                      picture('GIF', 'green'))
    data = bytearray(64 * 1024)
    data[4096:4096 + len(jpeg)] = jpeg
    data[20000 + 77:20077 + len(png)] = png
    data[40000 + 301:40301 + len(gif)] = gif
    path = tmp_path / 'raw.dd'
    path.write_bytes(bytes(data))
    return str(path), {'jpg': (4096, jpeg), 'png': (20077, png),
                       'gif': (40301, gif)}


def _carve(path, **options):
    from trace_app.core import carving
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.load_image()
    found = {}
    try:
        carving.carve_image(handler, ['jpg', 'png', 'gif', 'bmp'],
                            lambda content, kind, offset, fragments=None:
                            found.__setitem__(offset, (kind, content)),
                            unallocated_only=True, **options)
    finally:
        handler.close_resources()
    return found


def test_pictures_inside_a_sector_are_carved_only_when_asked(raw_disk):
    from trace_app.core.carving import UNALIGNED_FAMILIES
    path, planted = raw_disk
    default = _carve(path)
    assert set(default) == {4096}
    every = _carve(path, unaligned=UNALIGNED_FAMILIES)
    assert {offset: content for offset, (_kind, content) in every.items()} \
        == {offset: content for offset, content in planted.values()}


@pytest.fixture
def case_with(tmp_path):
    from trace_app.core.case import Case
    cases = []

    def make(disk):
        case = Case.create(str(tmp_path / f'case{len(cases)}'), 'Carving')
        cases.append(case)
        return case, case.add_evidence(disk)
    yield make
    for case in cases:
        case.close()


def _carve_case(case, evidence_id, path, source, **settings):
    from trace_app.core import carving
    from trace_app.core.image_handler import ImageHandler
    if settings:
        case.set_setting('settings', settings)
    handler = ImageHandler(path)
    assert handler.load_image()
    try:
        return carving.carve_evidence(
            handler, case, evidence_id, ['jpg', 'png', 'gif'],
            source == 'unallocated', source=source)
    finally:
        handler.close_resources()


def test_the_case_setting_carves_them_and_says_where_they_start(
        raw_disk, case_with):
    from trace_app.core.carving import MID_SECTOR_NOTE
    path, planted = raw_disk
    case, evidence_id = case_with(path)
    _carve_case(case, evidence_id, path, 'unallocated',
                carve_unaligned_pictures=True)
    rows = {row['offset']: row for row in case.carved_files(evidence_id)}
    assert set(rows) == {offset for offset, _content in planted.values()}
    notes = {offset: [text for _ok, text in row['checks']]
             for offset, row in rows.items()}
    assert MID_SECTOR_NOTE not in notes[4096]
    assert MID_SECTOR_NOTE in notes[20077] and MID_SECTOR_NOTE in notes[40301]
    runs = case.carving_runs(evidence_id)
    assert runs[0]['stats']['settings']['unaligned_pictures'] is True


def test_a_carve_keeps_the_other_sources_carves(raw_disk, case_with):
    """Unallocated space, slack and memory files do not overlap: a carve
    of one keeps the others'. A whole-image carve covers them all, and a
    carve of a region replaces an earlier whole-image one."""
    from trace_app.core import carving
    path, _planted = raw_disk
    case, evidence_id = case_with(path)
    assert carving.replaced_sources('slack') == ('slack', 'image')
    assert carving.replaced_sources('image') is None
    slack = carving.describe_carved(picture('PNG', 'white'), 'png', 512,
                                    source='slack')
    case.add_carved(evidence_id, slack)
    _carve_case(case, evidence_id, path, 'unallocated')
    sources = sorted((row['source'], row['offset'])
                     for row in case.carved_files(evidence_id))
    assert sources == [('slack', 512), ('unallocated', 4096)]
    # Again: the unallocated carve is replaced, not doubled.
    _carve_case(case, evidence_id, path, 'unallocated')
    assert len(case.carved_files(evidence_id)) == 2
    _carve_case(case, evidence_id, path, 'image')
    assert {row['source'] for row in case.carved_files(evidence_id)} == \
        {'image'}


def test_what_a_carve_left_goes_only_with_its_source(raw_disk, case_with):
    path, _planted = raw_disk
    case, evidence_id = case_with(path)
    from trace_app.core import carving
    for source, offset in (('slack', 512), ('unallocated', 4096)):
        record = carving.describe_carved(picture('PNG', 'white'), 'png',
                                         offset, source=source)
        case.add_carved(evidence_id, record)
        case.add_analysis_batch(evidence_id, [carving.analyse_carve(
            record, picture('PNG', 'white'))])
    case.clear_carved(evidence_id, ('unallocated', 'image'))
    left = case._db.execute(
        "SELECT artifact_ref FROM file_analysis WHERE evidence_id = ?",
        (evidence_id,)).fetchall()
    from trace_app.core.case import make_span_ref
    assert [row[0] for row in left] == [make_span_ref(
        0, 512, 512 + len(picture('PNG', 'white')))]
    assert [row['source'] for row in case.carved_files(evidence_id)] == \
        ['slack']


def test_a_whole_image_carve_of_a_live_file_is_not_unallocated(tmp_path,
                                                              case_with):
    from trace_app.core import vics
    from trace_app.core.image_handler import ImageHandler
    photo = picture('JPEG', 'red')
    image, _placed, _free = fat16_volume([('IMG1.JPG', photo)])
    disk = tmp_path / 'card.dd'
    disk.write_bytes(image)
    case, evidence_id = case_with(str(disk))
    _carve_case(case, evidence_id, str(disk), 'image')
    rows = [{'name': r['name'], 'offset': r['offset'], 'size': r['size'],
             'type': r['type'], 'source': r['source'],
             'artifact_ref': r['artifact_ref']}
            for r in case.carved_files(evidence_id)]
    assert rows and rows[0]['source'] == 'image'
    handler = ImageHandler(str(disk))
    assert handler.load_image()
    try:
        summary = vics.export([('EX', handler, rows)], str(tmp_path / 'out'),
                              'C-1', include_deleted=False, inside=False)
    finally:
        handler.close_resources()
    with open(summary['json'], encoding='utf-8') as handle:
        media, = json.load(handle)['value'][0]['Media']
    assert media['MD5'] == hashlib.md5(photo).hexdigest().upper()
    places = {f['FileName']: f['Unallocated'] for f in media['MediaFiles']}
    assert places['IMG1.JPG'] is False
    carved = [name for name in places if name != 'IMG1.JPG']
    assert carved and places[carved[0]] is False

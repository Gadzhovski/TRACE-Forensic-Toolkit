"""A video's own metadata (core/media_metadata.py): when and with what it
was recorded, where, its tracks.

The expected values for real files are ExifTool's: its own test images,
pinned in tools/testdata/samples.py, and what exiftool printed for each
(its t/*.out files), transcribed into
tests/expected/media_metadata_exiftool.json. The edge cases ExifTool's
small samples do not have -- 64-bit box sizes, a version-1 movie header,
Apple's mdta keys with a creation date and an ISO 6709 location, a
rotated track, moov after mdat -- are written here box by box.
"""

import json
import os
import struct

import pytest

from tests.conftest import data_path

EXPECTED = os.path.join(os.path.dirname(__file__), 'expected',
                        'media_metadata_exiftool.json')


def _expected():
    with open(EXPECTED, encoding='utf-8') as handle:
        return {k: v for k, v in json.load(handle).items()
                if not k.startswith('_')}


@pytest.mark.parametrize('name', sorted(_expected()))
def test_exiftools_samples_read_as_exiftool_reads_them(name):
    from trace_app.core import media_metadata
    want = _expected()[name]
    with open(data_path('samples', name), 'rb') as handle:
        data = handle.read()
    meta = media_metadata.from_bytes(data)
    assert meta is not None
    for key in ('container', 'brand', 'created', 'modified', 'title',
                'software', 'make', 'model', 'creation_date'):
        if key in want:
            assert meta[key] == want[key], key
    if 'duration' in want:
        assert round(meta['duration'], 2) == want['duration']
    if 'duration_text' in want:
        # exiftool prints a long duration as H:MM:SS, whole seconds.
        hours, minutes, seconds = map(int, want['duration_text'].split(':'))
        assert round(meta['duration']) == hours * 3600 + minutes * 60 + \
            seconds
    assert len(meta['tracks']) == len(want['tracks'])
    for track, expected in zip(meta['tracks'], want['tracks']):
        for key, value in expected.items():
            if key == 'duration':
                assert round(track['duration'], 2) == value
            else:
                assert track.get(key) == value, (key, track)
    values = {value for _label, value in meta['tags']}
    for value in want['tags']:
        assert value in values, value


def test_the_facts_lines_name_what_matters():
    from trace_app.core import media_metadata
    with open(data_path('samples', 'exiftool-RIFF.avi'), 'rb') as handle:
        meta = media_metadata.from_bytes(handle.read())
    rows = media_metadata.facts(meta)
    facts = dict(rows)
    assert facts['Container'] == 'AVI'
    assert facts['Software'] == 'CanonMVI01'
    tracks = [value for label, value in rows if label == 'Track']
    assert len(tracks) == 2
    assert '320 × 240' in tracks[0] and '15 fps' in tracks[0]
    assert '11,024 Hz' in tracks[1]
    assert media_metadata.frame_rate(meta) == 15


# --- generated boxes ---------------------------------------------------------

def box(kind, body=b'', large=False):
    if large:
        # size 1: a 64-bit size follows the type.
        return struct.pack('>I4sQ', 1, kind, 16 + len(body)) + body
    return struct.pack('>I4s', 8 + len(body), kind) + body


def full(kind, version, body, flags=0):
    return box(kind, bytes([version]) + flags.to_bytes(3, 'big') + body)


# 1904-01-01 to 2023-05-06 12:34:56 UTC
_EPOCH_1904 = 2082844800
_RECORDED = 1683376496 + _EPOCH_1904

_ROTATE_90 = struct.pack('>9i', 0, 0x10000, 0, -0x10000, 0, 0, 0, 0,
                         0x40000000)


def _mvhd_v1():
    return full(b'mvhd', 1, struct.pack('>QQIQ', _RECORDED, _RECORDED + 60,
                                        1000, 12500) + b'\0' * 80)


def _track():
    tkhd = full(b'tkhd', 0, struct.pack('>IIII', _RECORDED, _RECORDED, 1, 0)
                + struct.pack('>I', 12500) + b'\0' * 8 + b'\0' * 8
                + _ROTATE_90 + struct.pack('>II', 1920 << 16, 1080 << 16),
                flags=3)
    mdhd = full(b'mdhd', 0, struct.pack('>IIII', _RECORDED, _RECORDED,
                                        30000, 375000)
                + struct.pack('>HH', 0x15C7, 0))       # 'eng'
    hdlr = full(b'hdlr', 0, b'\0' * 4 + b'vide' + b'\0' * 12 + b'Video\0')
    avc1 = box(b'avc1', b'\0' * 6 + struct.pack('>H', 1) + b'\0' * 16
               + struct.pack('>HH', 1920, 1080) + b'\0' * 50)
    stsd = full(b'stsd', 0, struct.pack('>I', 1) + avc1)
    stts = full(b'stts', 0, struct.pack('>III', 1, 375, 1000))
    stbl = box(b'stbl', stsd + stts)
    minf = box(b'minf', stbl)
    mdia = box(b'mdia', mdhd + hdlr + minf)
    return box(b'trak', tkhd + mdia)


def _apple_meta():
    keys = [b'com.apple.quicktime.make', b'com.apple.quicktime.model',
            b'com.apple.quicktime.software',
            b'com.apple.quicktime.creationdate',
            b'com.apple.quicktime.location.ISO6709']
    values = ['Apple', 'iPhone 14 Pro', '16.4.1',
              '2023-05-06T14:34:56+0200', '+48.8584+002.2945+035.000/']
    keys_box = full(b'keys', 0, struct.pack('>I', len(keys)) + b''.join(
        struct.pack('>I4s', 8 + len(k), b'mdta') + k for k in keys))
    items = b''
    for index, value in enumerate(values, start=1):
        data = box(b'data', struct.pack('>II', 1, 0) + value.encode())
        items += struct.pack('>I', 8 + len(data)) + \
            index.to_bytes(4, 'big') + data
    hdlr = full(b'hdlr', 0, b'\0' * 4 + b'mdta' + b'\0' * 13)
    return box(b'meta', hdlr + keys_box + box(b'ilst', items))


def _iphone_mov(moov_last=True, large_mdat=True):
    ftyp = box(b'ftyp', b'qt  ' + b'\0\0\0\0' + b'qt  ')
    moov = box(b'moov', _mvhd_v1() + _track() + _apple_meta())
    mdat = box(b'mdat', b'\0' * 4096, large=large_mdat)
    return ftyp + (mdat + moov if moov_last else moov + mdat)


@pytest.mark.parametrize('moov_last', [True, False])
def test_an_iphone_movie_its_device_place_and_time(moov_last):
    from trace_app.core import media_metadata
    meta = media_metadata.from_bytes(_iphone_mov(moov_last))
    assert meta['container'] == 'QuickTime'
    assert meta['created'] == '2023-05-06 12:34:56'
    assert meta['modified'] == '2023-05-06 12:35:56'
    assert meta['duration'] == 12.5
    assert (meta['make'], meta['model'], meta['software']) == \
        ('Apple', 'iPhone 14 Pro', '16.4.1')
    assert meta['creation_date'] == '2023-05-06T14:34:56+0200'
    assert (meta['latitude'], meta['longitude'], meta['altitude']) == \
        (48.8584, 2.2945, 35.0)
    video = meta['tracks'][0]
    assert (video['kind'], video['codec'], video['width'],
            video['height']) == ('video', 'avc1', 1920, 1080)
    assert video['rotation'] == 90
    assert video['frame_rate'] == 30
    assert video['language'] == 'eng'


def test_reading_never_loads_the_media_data():
    """A read callback over a 'file' whose mdat claims 4 GB: only box
    headers and the moov are read."""
    from trace_app.core import media_metadata
    head = box(b'ftyp', b'qt  \0\0\0\0qt  ')
    moov = box(b'moov', _mvhd_v1() + _track())
    huge = 4 * 1024 ** 3
    mdat_header = struct.pack('>I4sQ', 1, b'mdat', 16 + huge)
    size = len(head) + len(mdat_header) + huge + len(moov)
    moov_at = len(head) + len(mdat_header) + huge
    asked = []

    def read(offset, length):
        asked.append(length)
        if offset < len(head):
            return (head + mdat_header)[offset:offset + length]
        if offset >= moov_at:
            return moov[offset - moov_at:offset - moov_at + length]
        if offset < len(head) + len(mdat_header):
            return (head + mdat_header)[offset:offset + length]
        return b'\0' * min(length, 16)
    meta = media_metadata.read_metadata(read, size)
    assert meta['duration'] == 12.5
    assert sum(asked) < 1024 * 1024


def test_iso6709_places():
    from trace_app.core.media_metadata import parse_iso6709
    assert parse_iso6709('+48.8584+002.2945+035.000/') == \
        (48.8584, 2.2945, 35.0)
    assert parse_iso6709('-33.8688+151.2093/') == (-33.8688, 151.2093,
                                                    None)
    assert parse_iso6709('not a place') is None


def test_not_a_container_reads_as_nothing():
    from trace_app.core import media_metadata
    assert media_metadata.kind(b'\x89PNG\r\n\x1a\n' + b'\0' * 24) == ''
    # A HEIC is ISO-BMFF too, but a picture: the photo checks own it.
    heic = box(b'ftyp', b'heic\0\0\0\0mif1heic')
    assert media_metadata.kind(heic) == ''
    assert media_metadata.from_bytes(b'not a video at all') is None


# --- in the analysis, the Timeline and the Map ------------------------------

def test_a_located_video_is_a_photo_finding():
    from trace_app.core import content_checks
    data = _iphone_mov()
    finding = content_checks.video_finding(
        data[:4096], lambda offset, length: data[offset:offset + length],
        len(data))
    assert finding.module == content_checks.MODULE_PHOTO
    assert finding.kind == 'video'
    assert finding.grade == content_checks.GRADE_NOTABLE  # it has a place
    assert finding.detail['latitude'] == 48.8584
    assert finding.detail['recorded'] == '2023-05-06 12:34:56'
    # The tag's own digits are the camera's clock (local, zoned +02:00).
    assert finding.detail['taken'] == '2023:05:06 14:34:56'
    assert 'iPhone 14 Pro' in finding.summary


def test_the_analysis_finds_it():
    from trace_app.core import analysis, content_checks
    data = _iphone_mov(moov_last=False)
    result = analysis.analyse_bytes('IMG_0001.MOV', data,
                                    {content_checks.MODULE_PHOTO})
    kinds = [row[1] for row in result.get("findings") or []]
    assert 'video' in kinds

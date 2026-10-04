"""TRACE's own Zstandard decoder (trace_app/core/zstd_decode.py).

Zstandard's conformance files -- the frames its own decoder is tested with,
valid ones (a 128 KB block, an empty block, an RLE first block, zero
sequences in long form) and damaged ones that must be refused -- and a real
zstd-compressed systemd journal, whose values plaso's tests record. On
Python 3.14 the decoder is also checked against the standard library's on
data compressed there at every kind of level.
"""

import hashlib
import os
import random

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    with open(path, 'rb') as handle:
        return handle.read()


@pytest.mark.parametrize('name, size, digest', [
    ('block-128k.zst', 131068,
     '672003418993584239ec5c79232de911699178ad820cd3ca9779abbfe7f7ba7d'),
    ('empty-block.zst', 0,
     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ('rle-first-block.zst', 1048576,
     '30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58'),
    ('zeroSeq_2B.zst', 13,
     '03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340'),
])
def test_conformance_frames_decode(name, size, digest):
    from trace_app.core import zstd_decode
    out = zstd_decode.decompress_python(sample('zstd-' + name))
    assert len(out) == size
    assert hashlib.sha256(out).hexdigest() == digest


@pytest.mark.parametrize('name', ['off0.bin.zst', 'truncated_huff_state.zst',
                                  'zeroSeq_extraneous.zst'])
def test_damaged_frames_are_refused(name):
    from trace_app.core import zstd_decode
    with pytest.raises(zstd_decode.ZstdError):
        zstd_decode.decompress_python(sample('zstd-' + name))


def test_a_zstd_journal_on_every_python(monkeypatch):
    """systemd 246+ compresses fields with zstd; plaso's sample, decoded by
    TRACE's own decoder even where the standard library has one."""
    from trace_app.core import zstd_decode
    from trace_app.core.activity import journal
    monkeypatch.setattr(zstd_decode, 'standard_library', lambda: None)
    reader = journal.Journal(sample('user-1000.journal'))
    (entry,) = list(reader.entries())
    assert reader.compact and reader.undecoded == 0
    assert entry['MESSAGE'] == 'Some large string: ' + 'A' * 512
    assert (entry['_COMM'], entry['_PID'], entry['_HOSTNAME'],
            entry['SYSLOG_IDENTIFIER']) == ('cat', '197', 'DESKTOP-QCDE2BT',
                                            'testapp')
    assert entry['_BOOT_ID'] == '7dd8f8967ea94fec9efa46beed3d2a71'


def test_xxh64_known_values():
    from trace_app.core.zstd_decode import xxh64
    assert xxh64(b'') == 0xEF46DB3751D8E999
    assert xxh64(b'abc') == 0x44BC2CF5AD770999


def test_a_damaged_field_is_counted_not_dropped():
    from trace_app.core.activity import journal
    data = bytearray(sample('user-1000.journal'))
    reader = journal.Journal(bytes(data))
    (entry,) = list(reader.entries())
    # Spoil one zstd field's frame magic.
    position = bytes(data).find(b'\x28\xb5\x2f\xfd')
    data[position] ^= 0xFF
    reader = journal.Journal(bytes(data))
    (damaged,) = list(reader.entries())
    assert reader.undecoded == 1
    assert damaged[journal.UNDECODED] == 1
    assert len(damaged) == len(entry)        # one field fewer, one count more


def _inputs():
    rng = random.Random(11)
    words = [b'evidence', b'image', b'journal', b'\xc3\xa9t\xc3\xa9', b'ssh',
             b'sudo', b'offset', b'thumbnail']
    yield b''
    yield b'x'
    yield bytes(rng.getrandbits(8) for _ in range(5000))          # raw
    yield b'A' * 300000                                            # RLE
    yield b' '.join(rng.choice(words) for _ in range(40000))       # Huffman
    yield b''.join(b'MESSAGE=New session %d of user u%d.\n' % (i, i % 9)
                   for i in range(6000))                           # matches


@pytest.mark.skipif(__import__('trace_app.core.zstd_decode', fromlist=['x'])
                    .standard_library() is None,
                    reason="Python 3.14+ compresses; the vectors above cover "
                           "older Pythons")
def test_matches_the_standard_library():
    from trace_app.core import zstd_decode
    zstd = zstd_decode.standard_library()
    for data in _inputs():
        for level in (-5, 1, 3, 9, 19):
            options = {zstd.CompressionParameter.compression_level: level,
                       zstd.CompressionParameter.checksum_flag: 1}
            packed = zstd.compress(data, options=options)
            assert zstd_decode.decompress_python(packed) == data, \
                (len(data), level)

"""AFF4 images read in Python (core/aff4.py, core/snappy.py, core/turtle.py).

Checked against the AFF4 Standard v1.0 canonical reference images and the
disk SHA-1s pyaff4's own tests assert for them -- so a map, a symbolic
region or a chunk read wrongly shows as a different disk.
"""

import hashlib
import os
import shutil
import struct
import zipfile

import pytest

from tests.conftest import image_path

#: Disk SHA-1 of each reference image, as pyaff4's hashing_test asserts.
DISK_SHA1 = {
    'Base-Linear.aff4': '7d3d27f667f95f7ec5b9d32121622c0f4b60b48d',
    'Base-Allocated.aff4': 'e8650e89b262cf0b4b73c025312488d5a6317a26',
    'Base-Linear-ReadError.aff4': '67e245a640e2784ead30c1ff1a3f8d237b58310f',
}


def _disk_sha1(image):
    digest, position = hashlib.sha1(), 0
    while position < image.size:
        data = image.read_buffer_at_offset(1 << 20, position)
        assert data
        digest.update(data)
        position += len(data)
    return digest.hexdigest()


# --- Snappy ------------------------------------------------------------------------

def test_snappy_literals_copies_and_runs():
    from trace_app.core.snappy import SnappyError, decompress
    # 'abc': length 3, then a 3-byte literal (tag (3-1) << 2).
    assert decompress(bytes([3, 2 << 2]) + b'abc') == b'abc'
    # 'ab' then a 1-byte-offset copy of 6 at offset 2 (overlapping: a run).
    run = bytes([8, 1 << 2]) + b'ab' + bytes([1 | ((6 - 4) << 2), 2])
    assert decompress(run) == b'abababab'
    # A 2-byte-offset copy.
    two = bytes([6, 2 << 2]) + b'xyz' + bytes([2 | ((3 - 1) << 2), 3, 0])
    assert decompress(two) == b'xyzxyz'
    with pytest.raises(SnappyError):
        decompress(bytes([4, 1 << 2]) + b'ab' + bytes([1, 9]))  # offset 9
    with pytest.raises(SnappyError):
        decompress(bytes([5, 2 << 2]) + b'abc')                   # 3 != 5


# --- Turtle -------------------------------------------------------------------------

def test_turtle_reads_what_aff4_writes():
    from trace_app.core.turtle import RDF_TYPE, TurtleError, parse
    graph = parse('''
        @prefix aff4: <http://aff4.org/Schema#> .
        @prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
        @prefix :     <aff4://volume> .
        # a comment
        <aff4://stream>  a aff4:ImageStream , aff4:Thing ;
            aff4:chunkSize "32768"^^xsd:int ;
            aff4:note "line \\"one\\"\\nline two"@en ;
            aff4:count 42 ;
            aff4:stored : .
        :  a aff4:ZipVolume ; .
    ''')
    stream = graph['aff4://stream']
    assert stream[RDF_TYPE] == ['http://aff4.org/Schema#ImageStream',
                                'http://aff4.org/Schema#Thing']
    size = stream['http://aff4.org/Schema#chunkSize'][0]
    assert size == '32768' and size.as_int() == 32768
    assert size.datatype == 'http://www.w3.org/2001/XMLSchema#int'
    note = stream['http://aff4.org/Schema#note'][0]
    assert note == 'line "one"\nline two' and note.lang == 'en'
    assert stream['http://aff4.org/Schema#count'][0].as_int() == 42
    assert stream['http://aff4.org/Schema#stored'] == ['aff4://volume']
    assert 'aff4://volume' in graph
    with pytest.raises(TurtleError):
        parse('<a:b> <c:d> [ <e:f> "x" ] .')     # blank nodes: not AFF4


# --- the reference images ----------------------------------------------------------

@pytest.mark.parametrize('name', sorted(DISK_SHA1))
def test_reference_images_read_as_pyaff4_reads_them(name):
    from trace_app.core.aff4 import Aff4Image
    image = Aff4Image(image_path(name))
    try:
        assert image.size == 268435456
        assert _disk_sha1(image) == DISK_SHA1[name]
        checks = image.verify()
        assert {c['algorithm'] for c in checks} == {'md5', 'sha1'}
        assert all(c['ok'] for c in checks)
        facts = image.facts()
        assert facts['Evidence Number'] == 'Drive 1'
        assert facts['Serial'] == 'SGAT5060001234'
        assert facts['Acquisition Tool'] == 'Evimetry 2.2.0'
        assert facts['Acquired'].startswith('2016-12-07 03:40:')
    finally:
        image.close()


def test_unread_regions_tile_their_pattern_by_the_mebibyte():
    """'UNKNOWN' (7 bytes) does not divide 1 MiB: the pattern restarts at
    each MiB, as pyaff4 and Evimetry write it."""
    from trace_app.core.aff4 import AFF4, _Symbolic
    unknown = _Symbolic(AFF4 + 'UnknownData')
    mib = 1024 * 1024
    assert unknown.read(0, 14) == b'UNKNOWNUNKNOWN'
    tail = mib % 7
    assert unknown.read(mib - tail, tail + 7) == b'UNKNOWN'[:tail] + \
        b'UNKNOWN'
    assert _Symbolic(AFF4 + 'SymbolicStreamFF').read(5, 3) == b'\xff' * 3
    assert _Symbolic(AFF4 + 'Zero').read(10 ** 9, 4) == b'\0' * 4


def test_a_changed_chunk_is_caught(tmp_path):
    """One byte changed inside a stored chunk: the stream no longer matches
    its recorded hashes, and verification says so."""
    from trace_app.core.aff4 import Aff4Image
    from trace_app.core.case import STATUS_CHANGED, hash_verdict
    from trace_app.core.image_handler import ImageHandler
    copy = tmp_path / 'tampered.aff4'
    shutil.copyfile(image_path('Base-Linear.aff4'), copy)
    with zipfile.ZipFile(copy) as package:
        info = next(i for i in package.infolist()
                    if i.filename.endswith('/00000000'))
    with open(copy, 'r+b') as handle:
        handle.seek(info.header_offset + 26)
        name_length, extra_length = struct.unpack('<HH', handle.read(4))
        data_start = info.header_offset + 30 + name_length + extra_length
        handle.seek(data_start + 40000)       # inside the second chunk
        byte = handle.read(1)
        handle.seek(data_start + 40000)
        handle.write(bytes([byte[0] ^ 0xFF]))
    image = Aff4Image(str(copy))
    try:
        assert not all(c['ok'] for c in image.verify())
    finally:
        image.close()
    handler = ImageHandler(str(copy))
    try:
        results = handler.calculate_hashes()
        status, detail = hash_verdict(results)
        assert status == STATUS_CHANGED and 'AFF4 stream' in detail
    finally:
        handler.close_resources()


def test_trace_reads_an_aff4_image_like_any_disk():
    from trace_app.core.case import STATUS_VERIFIED, hash_verdict
    from trace_app.core.evidence_probe import probe
    from trace_app.core.image_handler import ImageHandler
    path = image_path('Base-Linear.aff4')
    handler = ImageHandler(path)
    try:
        assert handler.loaded and handler.container_note == 'AFF4 (snappy)'
        start = next(p[2] for p in handler.get_partitions()
                     if b'NTFS' in p[1])
        assert handler.get_fs_type(start) == 'NTFS'
        names = {e['name'] for e in handler.get_directory_contents(
            start, handler.get_root_inode(start))}
        assert {'$MFT', '$Boot', '$LogFile'} <= names
        results = handler.calculate_hashes()
        assert results['computed_sha1'] == DISK_SHA1['Base-Linear.aff4']
        status, detail = hash_verdict(results)
        assert status == STATUS_VERIFIED and 'MD5 and SHA1' in detail
        assert handler.get_acquisition_info()['Examiner'] == 'Administrator'
    finally:
        handler.close_resources()
    described = probe(path)
    assert described['format'].startswith('AFF4 image')
    assert described['contents'] == 'MBR · NTFS'
    assert described['custody']['exhibit_number'] == 'Drive 1'
    assert described['stored_hashes']


def test_what_is_not_an_aff4_image_says_why(tmp_path):
    from trace_app.core.aff4 import Aff4Error, Aff4Image
    from trace_app.core.image_handler import ImageHandler
    plain = tmp_path / 'plain.aff4'
    with zipfile.ZipFile(plain, 'w') as package:
        package.writestr('readme.txt', 'not AFF4')
    with pytest.raises(Aff4Error, match='information.turtle'):
        Aff4Image(str(plain))
    handler = ImageHandler(str(plain))
    assert not handler.loaded and 'information.turtle' in handler.load_error
    not_zip = tmp_path / 'junk.aff4'
    not_zip.write_bytes(os.urandom(1000))
    with pytest.raises(Aff4Error):
        Aff4Image(str(not_zip))

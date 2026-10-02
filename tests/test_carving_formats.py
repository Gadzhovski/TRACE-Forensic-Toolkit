"""Carving the formats whose extent is read from their own structure.

Most inputs are generated here with the standard library and Pillow; one is
the example the MS-SHLLINK specification itself publishes. Real published
files of every format are the job of the carving corpus
(tools/carve_corpus.py), checked at the end against its answer key.
"""

import base64
import bz2
import io
import json
import lzma
import os
import random
import sqlite3
import struct
import tarfile
import zipfile

import pytest

from tests.conftest import ROOT, image_path

SECTOR = 512

#: The LNK file MS-SHLLINK section 3 gives as its example: a shortcut to
#: C:\test\a.txt, its target written 2008-09-12 20:27:17 UTC.
SPEC_LNK = base64.b64decode(
    'TAAAAAEUAgAAAAAAwAAAAAAAAEabAAgAIAAAANDp7vIVFckB0Onu8hUVyQHQ6e7yFRXJAQAAAAAA'
    'AAAAAQAAAAAAAAAAAAAAAAAAAL0AFAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAA'
    'AAAAAAAAAAAARgAxAAAAAAAsOWmjEAB0ZXN0AAAyAAcABADvviw5ZaMsOWmjJgAAAAMeAAAAAPUe'
    'AAAAAAAAAAAAAHQAZQBzAHQAAAAUAEgAMgAAAAAALDlpoyAAYS50eHQANAAHAAQA774sOWmjLDlp'
    'oyYAAAAtbgAAAACWAQAAAAAAAAAAAABhAC4AdAB4AHQAAAAUAAAAPAAAABwAAAABAAAAHAAAAC0A'
    'AAAAAAAAOwAAABEAAAADAAAAgYp6MBAAAAAAQzpcdGVzdFxhLnR4dAAABwAuAFwAYQAuAHQAeAB0'
    'AAcAQwA6AFwAdABlAHMAdABgAAAAAwAAoFgAAAAAAAAAY2hyaXMteHBzAAAAAAAAAEB4x5RH+sdG'
    's1ZcLca20RXsRs17In/dEZSZABNyFodKQHjHlEf6x0azVlwtxrbRFexGzXsif90RlJkAE3IWh0oA'
    'AAAA')


class _Image:
    """Just enough of ImageHandler for carve_image over bytes."""

    def __init__(self, data):
        self.data = bytes(data)

    def get_size(self):
        return len(self.data)

    def read(self, offset, length):
        return self.data[offset:offset + length]

    def get_partitions(self):
        return []

    def has_filesystem(self, _offset):
        return False


def _carve(data, types=None):
    from trace_app.core.carving import CARVABLE_TYPES, carve_image
    found = []
    carve_image(_Image(data), types or CARVABLE_TYPES,
                lambda content, kind, offset, fragments=None:
                found.append((kind, offset, content)),
                unallocated_only=False)
    return found


# --- samples made here -----------------------------------------------------------

def _sqlite(tmp_path, rows=200, blob=0):
    path = tmp_path / 'evidence.db'
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE history (url TEXT, visited INTEGER, data BLOB)")
    db.executemany("INSERT INTO history VALUES (?, ?, ?)",
                   [(f"https://example.org/{i}", 1700000000 + i, b'')
                    for i in range(rows)])
    if blob:
        db.execute("INSERT INTO history VALUES ('big', 0, ?)",
                   (os.urandom(blob),))
    db.commit()
    db.close()
    return path.read_bytes()


def _tar():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in (('notes.txt', b'meet at dawn\n' * 300),
                           ('ledger.csv', b'1,2,3\n' * 900)):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = 1600000000
            archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def _docx():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as package:
        package.writestr('[Content_Types].xml', '<Types/>')
        package.writestr('word/document.xml', '<w:document/>' * 50)
        package.writestr('docProps/core.xml',
                         '<cp:coreProperties><dcterms:modified xsi:type="x">'
                         '2019-05-04T10:20:30Z</dcterms:modified>'
                         '</cp:coreProperties>')
    return buffer.getvalue()


def _odt_without_mimetype():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as package:
        package.writestr('content.xml', '<office:document-content/>' * 40)
        package.writestr(
            'META-INF/manifest.xml',
            '<manifest:manifest><manifest:file-entry manifest:full-path="/" '
            'manifest:media-type="application/vnd.oasis.opendocument.text"/>'
            '</manifest:manifest>')
    return buffer.getvalue()


def _rtf():
    body = ''.join(f'\\par Line {i} of the statement' for i in range(200))
    return ('{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}{\\info{\\creatim\\yr2011'
            '\\mo3\\dy14\\hr9\\min5}}\\f0 ' + body + '}').encode('ascii')


def _mbox():
    message = ("From alice@example.com Tue Mar 15 09:12:00 2011\n"
               "From: Alice <alice@example.com>\n"
               "To: Bob <bob@example.com>\n"
               "Date: Tue, 15 Mar 2011 09:12:00 +0000\n"
               "Subject: shipment\n\n" + "The crates leave on Friday.\n" * 40)
    return message.encode('ascii') * 2


def _picture(kind):
    from PIL import Image
    buffer = io.BytesIO()
    noise = Image.frombytes('RGB', (96, 64), random.Random(kind).randbytes(96 * 64 * 3))
    noise.save(buffer, kind)
    return buffer.getvalue()


#: MPEG-1 Layer III, 128 kbit/s, 44.1 kHz, no padding: 417-byte frames.
_FRAME = b'\xff\xfb\x90\x64' + b'\x00' * 413


def _mp3(tagged=True, frames=60):
    audio = _FRAME * frames
    if not tagged:
        return audio
    tag_body = b'TIT2\x00\x00\x00\x06\x00\x00\x03Test\x00'
    size = len(tag_body)
    syncsafe = bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F,
                      (size >> 7) & 0x7F, size & 0x7F])
    return b'ID3\x03\x00\x00' + syncsafe + tag_body + audio + \
        b'TAG' + b'\x00' * 125


def _flv():
    out = b'FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00'
    for i in range(12):
        data = os.urandom(300)
        tag = bytes([9]) + len(data).to_bytes(3, 'big') + \
            (i * 40).to_bytes(3, 'big') + b'\x00' + b'\x00\x00\x00'
        out += tag + data + struct.pack('>I', 11 + len(data))
    return out


def _mpg(packs=40):
    pack = (b'\x00\x00\x01\xba' + bytes([0x44, 0, 4, 0, 4, 1, 1, 0x89, 0xc3,
                                         0xf8]))
    system = b'\x00\x00\x01\xbb' + struct.pack('>H', 6) + b'\x80\x00\x01\x04\xe1\xff'
    out = b''
    for i in range(packs):
        payload = os.urandom(2000)
        pes = b'\x00\x00\x01\xe0' + struct.pack('>H', len(payload)) + payload
        out += pack + (system if i == 0 else b'') + pes
    return out + b'\x00\x00\x01\xb9'


def _layout(samples, seed=7):
    """Each sample at a sector boundary among random filler."""
    rng = random.Random(seed)
    image = bytearray(rng.randbytes(64 * 1024))
    placed = []
    for kind, data in samples:
        offset = len(image)
        image += data
        image += rng.randbytes(-len(image) % SECTOR + SECTOR * rng.randrange(8, 64))
        placed.append((kind, offset, data))
    return bytes(image), placed


# --- the tests ----------------------------------------------------------------------

def test_each_format_is_recovered_exactly_at_its_offset(tmp_path):
    samples = [
        ('sqlite', _sqlite(tmp_path)), ('tar', _tar()),
        ('bz2', bz2.compress(b'deleted report ' * 4000)),
        ('xz', lzma.compress(b'deleted report ' * 4000)),
        ('docx', _docx()), ('odt', _odt_without_mimetype()),
        ('rtf', _rtf()), ('mbox', _mbox()),
        ('webp', _picture('WEBP')), ('avif', _picture('AVIF')),
        ('mp3', _mp3()), ('flv', _flv()), ('mpg', _mpg()),
        ('lnk', SPEC_LNK),
    ]
    image, placed = _layout(samples)
    found = {(kind, offset): content for kind, offset, content in _carve(image)}
    for kind, offset, data in placed:
        assert (kind, offset) in found, f"{kind} at {offset} was not carved"
        assert found[(kind, offset)] == data, f"{kind} is not byte-exact"


def test_embedded_dates_are_read_with_their_source(tmp_path):
    from trace_app.core.carving_signatures import extract_original_timestamp
    stamp, source = extract_original_timestamp(SPEC_LNK, 'lnk')
    assert (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute) == \
        (2008, 9, 12, 20, 27)
    assert source == "LNK target modified"
    stamp, source = extract_original_timestamp(_docx(), 'docx')
    assert stamp.isoformat() == '2019-05-04T10:20:30'
    assert 'core.xml' in source
    stamp, source = extract_original_timestamp(_rtf(), 'rtf')
    assert (stamp.year, stamp.month, stamp.day) == (2011, 3, 14)
    stamp, source = extract_original_timestamp(_mbox(), 'mbox')
    assert stamp.isoformat() == '2011-03-15T09:12:00'


def test_random_data_and_bare_signatures_are_not_carved():
    """A signature is not a file: each format's magic, followed by junk,
    must produce nothing -- and neither must random data."""
    sys_path_tools = os.path.join(ROOT, 'tools')
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'carve_corpus', os.path.join(sys_path_tools, 'carve_corpus.py'))
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)

    rng = random.Random(99)
    image = bytearray(rng.randbytes(8 * 1024 * 1024))
    for decoy in corpus.DECOYS:
        image += decoy + rng.randbytes(SECTOR * 16)
        image += rng.randbytes(-len(image) % SECTOR)
    image += rng.randbytes(1024 * 1024)
    assert _carve(bytes(image)) == []


def test_a_stream_is_one_file_not_one_per_packet():
    """An MPEG repeats its pack header every packet and an MP3 its frame sync
    every frame, each often on a sector boundary: still one file each."""
    image, placed = _layout([('mpg', _mpg(packs=120)),
                             ('mp3', _mp3(tagged=False, frames=400))])
    found = _carve(image, ['MPG', 'MP3'])
    assert [(k, o) for k, o, _ in found] == [(k, o) for k, o, _ in placed]


def test_a_file_larger_than_the_read_ahead_is_recovered_whole(tmp_path):
    """Size from the header means the file is read from the image in full,
    not only when it fits in a chunk's 32 MB read-ahead."""
    from trace_app.infra.constants import CARVE_OVERLAP, CHUNK_SIZE
    big = _sqlite(tmp_path, blob=CHUNK_SIZE + CARVE_OVERLAP + 4 * 1024 * 1024)
    assert len(big) > CHUNK_SIZE + CARVE_OVERLAP
    image, placed = _layout([('sqlite', big)])
    found = _carve(image, ['SQLITE'])
    assert len(found) == 1 and found[0][2] == big


def test_a_carved_zip_is_named_for_what_it_is():
    from trace_app.core.carving import Carver
    assert Carver._zip_kind(_docx()) == 'docx'
    assert Carver._zip_kind(_odt_without_mimetype()) == 'odt'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as package:
        package.writestr('notes.txt', 'plain')
    assert Carver._zip_kind(buffer.getvalue()) == 'zip'


@pytest.mark.images
def test_the_real_file_corpus_matches_its_answer_key():
    """Real published files of every format (tools/carve_corpus.py): each
    recovered byte-exact where the key says, and nothing else."""
    import hashlib
    path = image_path('carve-corpus.dd')
    with open(os.path.join(ROOT, 'tools', 'carve_ground_truth.json'),
              encoding='utf-8') as handle:
        key = json.load(handle)['carve-corpus.dd']
    with open(path, 'rb') as handle:
        data = handle.read()
    assert hashlib.sha256(data).hexdigest() == key['sha256']
    found = {offset: (kind, content) for kind, offset, content in _carve(data)}
    expected = {int(f['offset'], 16): f for f in key['files']}
    for offset, entry in expected.items():
        assert offset in found, f"{entry['name']} was not carved"
        kind, content = found[offset]
        assert kind == entry['type'], f"{entry['name']} carved as {kind}"
        assert hashlib.md5(content).hexdigest() == entry['md5'], entry['name']
    extra = sorted(set(found) - set(expected))
    assert not extra, f"unaccounted carves at {[hex(o) for o in extra]}"

"""Pictures the VICS export finds that a file walk does not: formats
libmagic names differently per platform (core/media_formats), members of
archives and documents (core/media_inside), legacy Office pictures
(core/officeart), Firefox's cache block files (core/firefox_cache) and,
when asked, pictures carved from inside other files.

Found by comparing TRACE's export of the M57 'Jean' image with AXIOM's,
X-Ways', F-Response FEX's and Griffeye's. Every input here is generated;
the formats are written as their specifications lay them out.
"""

import gzip
import hashlib
import io
import json
import struct
import zipfile
import zlib

import pytest

from tests.disk_builders import compound_file


# --- pictures, written by Pillow or by hand ---------------------------------

def picture(kind, colour='red', size=(24, 16), **options):
    from PIL import Image
    out = io.BytesIO()
    Image.new('RGB', size, colour).save(out, kind, **options)
    return out.getvalue()


def wmf(placeable=True):
    """A Windows Metafile: header, one SetBkColor record, the end record."""
    records = struct.pack('<IHI', 5, 0x0201, 0x00FFFFFF) + \
        struct.pack('<IH', 3, 0)
    words = 9 + len(records) // 2
    body = struct.pack('<HHHIHIH', 1, 9, 0x0300, words, 0, 5, 0) + records
    if not placeable:
        return body
    head = struct.pack('<IHhhhhHI', 0x9AC6CDD7, 0, 0, 0, 100, 100, 1440, 0)
    checksum = 0
    for word in struct.unpack('<10H', head):
        checksum ^= word
    return head + struct.pack('<H', checksum) + body


def emf():
    header = bytearray(108)
    struct.pack_into('<II', header, 0, 1, 108)
    header[40:44] = b' EMF'
    end = struct.pack('<IIIII', 14, 20, 0, 16, 20)
    struct.pack_into('<II', header, 44, 0x10000, len(header) + len(end))
    return bytes(header) + end


def swf():
    body = b'\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00\x00\x18\x01\x00' + \
        b'\x40\x00\x00\x00'
    return b'FWS' + bytes([10]) + struct.pack('<I', 8 + len(body)) + body


# --- formats libmagic names differently per platform ----------------------

@pytest.mark.parametrize('make, mime', [
    (lambda: wmf(True), 'image/wmf'),
    (lambda: wmf(False), 'image/wmf'),
    (emf, 'image/emf'),
    (swf, 'application/x-shockwave-flash'),
    (lambda: picture('TGA'), 'image/x-tga'),
    (lambda: picture('TGA', compression='tga_rle'), 'image/x-tga'),
])
def test_metafiles_flash_and_tga_are_media_on_every_platform(make, mime):
    """The same answer with libmagic and without it: python-magic-bin's
    5.32 (Windows) calls a WMF 'octet-stream' or a TGA, Flash 'text'."""
    from trace_app.core import vics
    from trace_app.core.analysis import magic_reader
    data = make()

    def read(position, length):
        return data[position:position + length]
    for reader in (None, magic_reader()):
        assert vics.media_type(data[:4096], 'x', reader, len(data),
                               read) == mime


def test_a_tga_is_proved_by_its_structure_not_guessed():
    from trace_app.core import media_formats, vics
    from trace_app.core.analysis import magic_reader
    tga = picture('TGA', compression='tga_rle')
    footer = tga.index(b'TRUEVISION-XFILE')
    bare = tga[:footer - 8]                      # no extension or footer

    def reader_of(data):
        return lambda position, length: data[position:position + length]
    assert media_formats.is_tga(bare, len(bare), reader_of(bare))
    # Packets that do not add up to the picture, or run past the file.
    cut = bare[:len(bare) // 2]
    assert not media_formats.is_tga(cut, len(cut), reader_of(cut))
    # Bytes libmagic 5.41+ calls a TGA (00 01 02 ...) are not one.
    counting = bytes(range(256)) * 16
    assert vics.media_type(counting, 'x.bin', magic_reader(),
                           len(counting), reader_of(counting)) is None
    # An uncompressed TGA followed by another file's worth of bytes.
    plain = picture('TGA')
    padded = plain + bytes(64 * 1024)
    assert not media_formats.is_tga(padded, len(padded), reader_of(padded))


def test_metafile_checks_refuse_near_misses():
    from trace_app.core import media_formats
    good = wmf(True)
    broken = bytearray(good)
    broken[20] ^= 0xFF                           # placeable checksum
    assert not media_formats.is_wmf(bytes(broken), len(broken))
    assert not media_formats.is_wmf(b'\x01\x00\x09\x00\x00\x03' + bytes(30),
                                    36)
    assert not media_formats.is_emf(emf()[:40] + b'XEMF' + emf()[44:], 128)
    assert not media_formats.is_swf(b'FWS\x00' + bytes(20), 24)


# --- legacy Office pictures --------------------------------------------------

def blip_bitmap(record_type, instance, content, two_ids=False):
    ids = bytes(32 if two_ids else 16)
    body = ids + b'\xff' + content
    return struct.pack('<HHI', (instance + two_ids) << 4, record_type,
                       len(body)) + body


def blip_wmf(content):
    packed = zlib.compress(content)
    header = struct.pack('<I4i2iIBB', len(content), 0, 0, 100, 100, 9000,
                         9000, len(packed), 0, 0xFE)
    body = bytes(16) + header + packed
    return struct.pack('<HHI', 0x216 << 4, 0xF01B, len(body)) + body


def dib():
    bmp = picture('BMP', 'green', (8, 8))
    return bmp, bmp[14:]                        # the file, and its DIB


def test_powerpoint_pictures_come_out_as_files():
    from trace_app.core import embedded
    png = picture('PNG', 'blue')
    bmp, bare = dib()
    metafile = wmf(False)
    pictures = (bytes(100) + blip_bitmap(0xF01E, 0x6E0, png) +
                blip_bitmap(0xF01F, 0x7A8, bare, two_ids=True) +
                blip_wmf(metafile))
    document = compound_file({('Pictures',): pictures.ljust(4096, b'\0'),
                              ('PowerPoint Document',): bytes(4096)})
    found = dict(embedded.objects(document))
    assert found == {'picture 1.png': png, 'picture 2.bmp': bmp,
                     'picture 3.wmf': metafile}
    # Indexing asks for no pictures: it has no use for them.
    assert embedded.objects(document, pictures=False) == []


def biff(kind, body):
    return struct.pack('<HH', kind, len(body)) + body


def test_excel_pictures_split_across_records_are_joined():
    """A chart's picture fill (GelFrame) longer than one record runs on in
    CONTINUE records -- Excel's chart gallery keeps its pictures so."""
    from trace_app.core import embedded
    photo = picture('JPEG', 'orange', (64, 64), quality=100)
    record = blip_bitmap(0xF01D, 0x46A, photo)
    half = len(record) // 2
    workbook = (biff(0x0809, bytes(16)) + biff(0x1066, record[:half]) +
                biff(0x003C, record[half:]) + biff(0x000A, b''))
    document = compound_file({('Workbook',): workbook.ljust(4096, b'\0')})
    assert dict(embedded.objects(document)) == {'picture 1.jpg': photo}


# --- Firefox's disk cache (format 1) ----------------------------------------

def cache_folder(objects, own_location=True):
    """{file name: bytes} of a cache folder: `objects` is [(url, content,
    headers, (data file, data block), (meta file, meta block))].
    `own_location` False leaves the entry's own location 0, as Firefox 3
    often does."""
    blocks = {1: bytearray(4096), 2: bytearray(4096), 3: bytearray(4096)}
    sizes = {1: 256, 2: 1024, 3: 4096}

    def put(selector, block, data):
        size = sizes[selector]
        count = (len(data) + size - 1) // size
        assert count <= 4
        start = 4096 + block * size
        store = blocks[selector]
        if len(store) < start + count * size:
            store.extend(bytes(start + count * size - len(store)))
        store[start:start + len(data)] = data
        return 0x80000000 | selector << 28 | (count - 1) << 24 | block

    records = []
    for number, (url, content, headers, data_at, meta_at) in enumerate(
            objects, 1):
        data_location = put(*data_at, content)
        key = f'HTTP:{url}'.encode() + b'\0'
        head = 'HTTP/1.1 200 OK\r\n' + ''.join(
            f'{name}: {value}\r\n' for name, value in headers.items())
        meta = b'request-method\0GET\0response-head\0' + head.encode() + \
            b'\0'
        selector, block = meta_at
        count = (36 + len(key) + len(meta) + sizes[selector] - 1) // \
            sizes[selector]
        meta_location = 0x80000000 | selector << 28 | (count - 1) << 24 | \
            block
        entry = struct.pack('>9I', 0x0001000B,
                            meta_location if own_location else 0, 1,
                            1_200_000_000, 1_200_000_100, 0, len(content),
                            len(key), len(meta)) + key + meta
        assert put(selector, block, entry) == meta_location
        records.append(struct.pack('>4I', 0x1000 + number, 1,
                                   data_location, meta_location))
    header = struct.pack('>5I', 0x0001000B, 0, len(records), 0,
                         len(records)) + bytes(256)
    folder = {'_CACHE_MAP_': header + b''.join(records).ljust(
        16 * 64, b'\0')}
    for selector, store in blocks.items():
        folder[f'_CACHE_00{selector}_'] = bytes(store)
    return folder


def test_firefox_keeps_small_objects_in_block_files():
    from trace_app.core import firefox_cache
    gif = picture('GIF', 'red', (4, 4))
    png = picture('PNG', 'blue', (40, 40))
    packed = gzip.compress(png)
    folder = cache_folder([
        ('http://example.org/img/dot.gif?v=2', gif,
         {'Content-Type': 'image/gif'}, (1, 0), (1, 4)),
        ('http://example.org/logo.png', packed,
         {'Content-Type': 'image/png', 'Content-Encoding': 'gzip'},
         (2, 0), (1, 10)),
    ])
    cache = firefox_cache.Cache(folder.get)
    entries = {entry['name']: entry for entry in cache.entries()}
    assert set(entries) == {'dot.gif', 'logo.png'}
    assert entries['dot.gif']['content'] == gif
    assert entries['dot.gif']['block_file'] == '_CACHE_001_'
    assert entries['dot.gif']['last_modified'] == 1_200_000_100
    # Sent compressed, stored compressed, given as the picture.
    assert entries['logo.png']['content'] == png
    assert entries['logo.png']['encoding'] == 'gzip'
    assert entries['logo.png']['key'] == 'HTTP:http://example.org/logo.png'


def test_a_record_whose_metadata_is_not_its_own_is_skipped():
    """The metadata entry records its own location; a record pointing at
    another entry (a block reused) is not read as that one."""
    from trace_app.core import firefox_cache
    gif = picture('GIF')
    folder = cache_folder([('http://a/b.gif', gif, {}, (1, 0), (1, 4))])
    data = bytearray(folder['_CACHE_MAP_'])
    meta = struct.unpack_from('>I', data, 276 + 12)[0]
    struct.pack_into('>I', data, 276 + 12, meta + 1)   # one block on
    folder['_CACHE_MAP_'] = bytes(data)
    assert list(firefox_cache.Cache(folder.get).entries()) == []


def test_an_entry_need_not_record_its_own_location():
    """Firefox 3 leaves it 0 in most entries (M57 'Jean': 4,293 of the
    profile's 4,331 block-stored objects); the blocks must then fit."""
    from trace_app.core import firefox_cache
    gif = picture('GIF')
    folder = cache_folder([('http://a/b.gif', gif, {}, (1, 0), (1, 4))],
                          own_location=False)
    entry, = firefox_cache.Cache(folder.get).entries()
    assert entry['content'] == gif
    # The data's size says one block more than the map gives: not read.
    data = bytearray(folder['_CACHE_MAP_'])
    location = struct.unpack_from('>I', data, 276 + 8)[0]
    struct.pack_into('>I', data, 276 + 8, location + (1 << 24))
    folder['_CACHE_MAP_'] = bytes(data)
    assert list(firefox_cache.Cache(folder.get).entries()) == []


# --- the export --------------------------------------------------------------

@pytest.fixture
def evidence(tmp_path):
    root = tmp_path / 'evidence'
    skins = root / 'Program Files' / 'Player' / 'Skins'
    skins.mkdir(parents=True)
    png, jpeg = picture('PNG', 'blue'), picture('JPEG', 'yellow')
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, 'w') as archive:
        archive.writestr('deep/b.jpg', jpeg)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, 'w') as archive:
        archive.writestr('images/a.png', png)
        archive.writestr('more.zip', inner.getvalue())
        archive.writestr('readme.txt', b'not a picture\n' * 10)
    (skins / 'compact.wmz').write_bytes(outer.getvalue())

    gif = picture('GIF', 'red', (4, 4))
    cache = root / 'Firefox' / 'Profiles' / 'abc.default' / 'Cache'
    cache.mkdir(parents=True)
    for name, data in cache_folder([
            ('http://example.org/dot.gif', gif, {}, (1, 0), (1, 4))]).items():
        (cache / name).write_bytes(data)

    clipart = root / 'Clipart'
    clipart.mkdir()
    (clipart / 'BD04956_.WMF').write_bytes(wmf(True))
    (clipart / 'rules.tga').write_bytes(picture('TGA', compression='tga_rle'))

    tail = picture('JPEG', 'purple', (32, 32))
    (root / 'program.dll').write_bytes(b'MZ' + bytes(5000) + tail +
                                       bytes(3000))
    (root / 'photo.jpg').write_bytes(jpeg)
    # An Office border file: metafiles kept whole inside it.
    (clipart / 'MSART9.BDR').write_bytes(bytes(300) + wmf(True) +
                                         bytes(50) + emf() + bytes(10))

    entries = root / 'cache2' / 'entries'
    entries.mkdir(parents=True)
    meta = struct.pack('>I', 0) + struct.pack('>H', 0) + \
        struct.pack('>6I', 3, 1, 0, 0, 0, 0) + b':http://x/y.png\0' + \
        bytes(8)
    entry = png + meta + struct.pack('>I', len(png))
    (entries / ('A' * 40)).write_bytes(entry)
    return {'root': str(root), 'png': png, 'jpeg': jpeg, 'gif': gif,
            'tail': tail}


def _export(root, out, **options):
    from trace_app.core import vics
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(root)
    assert handler.load_image()
    marks = options.pop('marks', None)
    try:
        summary = vics.export([('EXHIBIT 1', handler, (), marks)],
                              str(out), 'CASE 7', version='test', **options)
    finally:
        handler.close_resources()
    with open(summary['json'], encoding='utf-8') as handle:
        media = json.load(handle)['value'][0]['Media']
    return {m['MD5']: m for m in media}


def md5(data):
    return hashlib.md5(data).hexdigest().upper()


def test_members_are_exported_under_their_container(evidence, tmp_path):
    media = _export(evidence['root'], tmp_path / 'out')
    a = media[md5(evidence['png'])]
    places = {(f['FilePath'], f['FileName']) for f in a['MediaFiles']}
    assert ('EXHIBIT 1\\Program Files\\Player\\Skins\\compact.wmz\\images',
            'a.png') in places
    b = media[md5(evidence['jpeg'])]
    places = {(f['FilePath'], f['FileName']) for f in b['MediaFiles']}
    # A picture in a zip in the skin; and the same picture as a file.
    assert ('EXHIBIT 1\\Program Files\\Player\\Skins\\compact.wmz\\'
            'more.zip\\deep', 'b.jpg') in places
    assert ('EXHIBIT 1', 'photo.jpg') in places
    for entry in a['MediaFiles']:
        if 'compact.wmz' in entry['FilePath']:
            assert 'Written' not in entry      # a ZIP's times have no zone


def test_firefox_cache_objects_are_exported_by_their_url_name(evidence,
                                                              tmp_path):
    media = _export(evidence['root'], tmp_path / 'out')
    entry, = media[md5(evidence['gif'])]['MediaFiles']
    assert entry['FileName'] == 'dot.gif'
    assert entry['FilePath'].endswith('abc.default\\Cache\\_CACHE_001_')
    assert entry['Written'] == '2008-01-10T21:21:40+00:00'
    assert entry['Accessed'] == '2008-01-10T21:20:00+00:00'


def test_metafiles_and_tga_are_exported(evidence, tmp_path):
    media = _export(evidence['root'], tmp_path / 'out')
    types = {m['MediaFiles'][0]['FileName']: m['MimeType']
             for m in media.values()}
    assert types['BD04956_.WMF'] == 'image/wmf'
    assert types['rules.tga'] == 'image/x-tga'


def test_a_cache2_entry_is_its_object_without_the_metadata(evidence,
                                                           tmp_path):
    media = _export(evidence['root'], tmp_path / 'out')
    names = {f['FileName'] for f in media[md5(evidence['png'])]['MediaFiles']}
    assert 'A' * 40 in names


def test_looking_inside_can_be_turned_off(evidence, tmp_path):
    media = _export(evidence['root'], tmp_path / 'out', inside=False)
    assert md5(evidence['gif']) not in media
    files = [f for m in media.values() for f in m['MediaFiles']]
    assert not any('compact.wmz' in f['FilePath'] for f in files)


def test_pictures_carved_inside_files_only_when_asked(evidence, tmp_path):
    plain = _export(evidence['root'], tmp_path / 'plain')
    assert md5(evidence['tail']) not in plain
    media = _export(evidence['root'], tmp_path / 'carved',
                    carve_inside=True)
    entry, = media[md5(evidence['tail'])]['MediaFiles']
    assert entry['FilePath'] == 'EXHIBIT 1\\program.dll'
    assert entry['FileName'] == f'{5002:x}.jpg'
    # A picture file is not found again inside itself.
    jpeg_places = media[md5(evidence['jpeg'])]['MediaFiles']
    assert not any(f['FilePath'].endswith('photo.jpg') for f in jpeg_places)
    # Metafiles, which carving has no carver for, by their own headers.
    border = {f['FileName']: m['MimeType'] for m in media.values()
              for f in m['MediaFiles'] if f['FilePath'].endswith('.BDR')}
    assert border == {f'{300:x}.wmf': 'image/wmf',
                      f'{300 + len(wmf(True)) + 50:x}.emf': 'image/emf'}
    assert md5(wmf(True)) in media and md5(emf()) in media


def test_a_containers_category_is_not_given_to_its_members(evidence,
                                                           tmp_path):
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core import walk
    handler = ImageHandler(evidence['root'])
    assert handler.load_image()
    try:
        ref = next(entry.ref for entry in walk.iter_files(handler)
                   if entry.name == 'compact.wmz')
    finally:
        handler.close_resources()
    media = _export(evidence['root'], tmp_path / 'out',
                    marks={'categories': {ref: 1}, 'comments': {ref: 'x'}})
    a = media[md5(evidence['png'])]
    assert 'Category' not in a and 'Comments' not in a


def test_the_job_passes_both_choices_on(evidence, tmp_path):
    from trace_app.core import background
    found = {}
    for label, choices in (('default', {}),
                           ('neither', {'inside': False}),
                           ('carved', {'carve_inside': True})):
        out = tmp_path / label
        out.mkdir()
        items = []
        background.job_vics(
            {'sources': [('EXHIBIT 1', evidence['root'], None, [])],
             'folder': str(out), 'case_number': 'J-2', **choices},
            lambda *payload: None, items.append, lambda: False)
        with open(items[0]['json'], encoding='utf-8') as handle:
            media = json.load(handle)['value'][0]['Media']
        found[label] = {m['MD5'] for m in media}
    assert md5(evidence['gif']) in found['default']
    assert md5(evidence['gif']) not in found['neither']
    assert md5(evidence['tail']) in found['carved'] - found['default']

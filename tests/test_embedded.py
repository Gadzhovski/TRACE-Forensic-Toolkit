"""Files inside files (core/embedded.py): pictures, packaged files and
attachments documents carry, and a photo's EXIF thumbnail -- listed and
read as members under '[embedded]/', so the index, search previews and the
Listing read them as archive members.

Every document is made here with a known payload, by the program's own
library where there is one (PyMuPDF writes the PDF, Pillow the JPEGs) and
otherwise by the format's published layout (a compound file with an
Ole10Native package, OOXML/ODF zips, an RTF \\objdata OLE 1.0 object).
Each member must come back byte for byte."""

import io
import os
import struct
import zipfile

import pytest

from tests.conftest import pump
from tests.disk_builders import compound_file, fat16_volume
from trace_app.core import archives, embedded

PAYLOAD = os.urandom(5000)          # what is packaged inside documents


def jpeg(size=(64, 48), seed=1):
    import random
    from PIL import Image
    rng = random.Random(seed)
    picture = Image.new('RGB', size)
    picture.putdata([tuple(rng.randrange(256) for _ in range(3))
                     for _ in range(size[0] * size[1])])
    out = io.BytesIO()
    picture.save(out, 'JPEG', quality=85)
    return out.getvalue()


def package_native(name, data):
    """The Packager's native data (no leading size): flags, label, source
    path, reserved, temp path, data."""
    temp = f"C:\\Users\\x\\AppData\\Local\\Temp\\{name}".encode() + b'\0'
    return (struct.pack('<H', 2) + name.encode() + b'\0' +
            f"C:\\Users\\x\\Desktop\\{name}".encode() + b'\0' +
            struct.pack('<I', 0x00030000) + struct.pack('<I', len(temp)) +
            temp + struct.pack('<I', len(data)) + data)


def ole10native(name, data):
    native = package_native(name, data)
    return struct.pack('<I', len(native)) + native


def word_doc(payload=PAYLOAD):
    """A legacy .doc: WordDocument, and an object pool holding a package."""
    return compound_file({
        ('WordDocument',): b'\xec\xa5' + bytes(5000),
        ('ObjectPool', '_1700000000', '\x01Ole10Native'):
            ole10native('invoice.exe', payload)})


def docx(picture, payload=PAYLOAD):
    with io.BytesIO() as out:
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('[Content_Types].xml', '<Types/>')
            archive.writestr('word/document.xml', '<w:document/>')
            archive.writestr('word/media/image1.jpeg', picture)
            archive.writestr('word/embeddings/oleObject1.bin',
                             compound_file({('\x01Ole10Native',):
                                            ole10native('payload.vbs',
                                                        payload)}))
        return out.getvalue()


def odt(picture):
    with io.BytesIO() as out:
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('mimetype',
                             'application/vnd.oasis.opendocument.text')
            archive.writestr('content.xml', '<office:document-content/>')
            archive.writestr('Pictures/100000000000.jpg', picture)
        return out.getvalue()


def pdf(picture):
    import pymupdf
    document = pymupdf.open()
    page = document.new_page()
    page.insert_image(pymupdf.Rect(50, 50, 250, 200), stream=picture)
    page.insert_text((50, 300), "Quarterly figures")
    document.embfile_add('ledger.csv', b'date,amount\n2024-01-01,9000\n',
                         filename='ledger.csv')
    data = document.tobytes()
    document.close()
    return data


def rtf():
    native = package_native('dropper.bat', PAYLOAD)
    ole1 = (struct.pack('<II', 0x00000501, 2) +
            struct.pack('<I', 8) + b'Package\0' + struct.pack('<II', 0, 0) +
            struct.pack('<I', len(native)) + native)
    hexed = ole1.hex()
    lines = '\n'.join(hexed[i:i + 64] for i in range(0, len(hexed), 64))
    return ("{\\rtf1\\ansi Open the attachment "
            "{\\object\\objemb{\\*\\objclass Package}"
            "{\\*\\objdata " + lines + "}}}").encode()


def jpeg_with_thumbnail(thumbnail):
    """A JPEG whose EXIF holds IFD1 with a JPEG thumbnail."""
    body = jpeg((320, 240), seed=5)
    ifd0 = struct.pack('<H', 0) + struct.pack('<I', 8 + 6)   # no tags, IFD1
    ifd1_at = 8 + len(ifd0)
    thumb_at = ifd1_at + 2 + 2 * 12 + 4
    ifd1 = struct.pack('<H', 2) + \
        struct.pack('<HHII', 0x0201, 4, 1, thumb_at) + \
        struct.pack('<HHII', 0x0202, 4, 1, len(thumbnail)) + \
        struct.pack('<I', 0)
    tiff = b'II*\x00' + struct.pack('<I', 8) + ifd0 + ifd1 + thumbnail
    app1 = b'Exif\0\0' + tiff
    return b'\xff\xd8' + b'\xff\xe1' + struct.pack('>H', len(app1) + 2) + \
        app1 + body[2:]


# --- every kind -------------------------------------------------------------------

def _members(data):
    return {m['name']: archives.read_member(data, m['name'])
            for m in embedded.list_members(data)}


def test_a_word_document_unpacks_its_package():
    members = _members(word_doc())
    assert members == {'[embedded]/invoice.exe': PAYLOAD}


def test_ooxml_gives_pictures_and_unwraps_ole_objects():
    picture = jpeg()
    members = _members(docx(picture))
    assert members == {'[embedded]/image1.jpeg': picture,
                       '[embedded]/payload.vbs': PAYLOAD}


def test_odf_gives_its_pictures():
    picture = jpeg(seed=2)
    assert _members(odt(picture)) == {
        '[embedded]/100000000000.jpg': picture}


def test_a_pdf_gives_its_images_as_stored_and_its_attachments():
    picture = jpeg(seed=3)
    members = _members(pdf(picture))
    images = [v for k, v in members.items() if k.endswith('.jpeg')]
    assert images == [picture]          # a JPEG stays the bytes it was
    assert members['[embedded]/ledger.csv'] == \
        b'date,amount\n2024-01-01,9000\n'


def test_rtf_objdata_packages_are_unwrapped():
    assert _members(rtf()) == {'[embedded]/dropper.bat': PAYLOAD}


def test_a_photo_gives_its_exif_thumbnail():
    thumbnail = jpeg((32, 24), seed=9)
    assert _members(jpeg_with_thumbnail(thumbnail)) == {
        '[embedded]/exif-thumbnail.jpg': thumbnail}
    assert embedded.list_members(jpeg()) == []        # none recorded


def test_documents_without_embedded_files_and_damage():
    assert embedded.list_members(b'plain text, nothing inside') == []
    damaged = word_doc()[:3000]
    assert embedded.list_members(damaged) == []       # no exception
    with pytest.raises(archives.ArchiveError):
        archives.read_member(word_doc(), '[embedded]/missing.exe')


def test_a_chain_through_an_archive_reads_anywhere():
    """'outer.zip!/report.docx!/[embedded]/payload.vbs', as a search hit's
    path names it, read the way previews read a chain."""
    with io.BytesIO() as out:
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('report.docx', docx(jpeg()))
        outer = out.getvalue()
    content = outer
    for member in ('report.docx', '[embedded]/payload.vbs'):
        content = archives.read_member(content, member)
    assert content == PAYLOAD


# --- the index and the window -------------------------------------------------------

@pytest.fixture
def disk(tmp_path):
    image, _placed, _free = fat16_volume([
        ('REPORT.DOC', word_doc()), ('MEMO.RTF', rtf()),
        ('PLAN.DOCX', docx(jpeg())), ('NOTES.TXT', b'nothing inside')])
    path = tmp_path / 'docs.dd'
    path.write_bytes(image)
    return str(path)


def test_the_index_finds_text_inside_embedded_files(disk, tmp_path):
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    secret = b'Set objShell = CreateObject("WScript.Shell") ' + \
        b'MarkerWord-Embedded-913'
    payload = secret + b'\n' * 4000
    image, _placed, _free = fat16_volume([
        ('REPORT.DOC', word_doc(payload)),
        ('PLAN.DOCX', docx(jpeg(), payload))])
    path = tmp_path / 'docs2.dd'
    path.write_bytes(image)
    handler = ImageHandler(str(path))
    assert handler.load_image()
    index = SearchIndex(str(tmp_path))
    try:
        index_evidence(handler, index, 1)
        index.commit()
        hits = index.search('"MarkerWord-Embedded-913"')
        # The test disk keeps 8.3 names: PLAN.DOCX is PLAN.DOC on it. The
        # documents' own text can hold the words too (a .doc's strings).
        inside = {h['path']: h for h in hits if '[embedded]' in h['path']}
        assert set(inside) == {
            '/PLAN.DOC!/word/embeddings/oleObject1.bin!/[embedded]/'
            'payload.vbs', '/REPORT.DOC!/[embedded]/invoice.exe'}
        assert all(h['kind'] == 'archive-member' for h in inside.values())
    finally:
        index.close()
        handler.close_resources()


def test_the_listing_shows_a_documents_embedded_files(qapp, disk,
                                                     monkeypatch):
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    window = MainWindow()
    try:
        assert window.open_evidence_image(disk)
        from trace_app.core.image_handler import ImageHandler
        handler = ImageHandler(disk)
        handler.load_image()
        entry = next(e for e in handler.get_directory_contents(
            0, handler.get_root_inode(0)) if e['name'] == 'MEMO.RTF')
        handler.close_resources()
        data = {'type': 'file', 'name': 'MEMO.RTF',
                'inode_number': entry['inode_number'], 'start_offset': 0}
        assert window.show_embedded_files(data)
        pump(qapp, 0.2)
        table = window.listing_table
        names = [table.item(r, 0).text() for r in range(table.rowCount())]
        assert '[embedded]/dropper.bat' in names
        row = names.index('[embedded]/dropper.bat')
        member = table.item(row, 0).data(Qt.UserRole)
        assert member['type'] == 'archive-member'
        # Read as a click on it reads it: out of the listed document.
        assert archives.read_member(window._archive_stack[-1][1],
                                    member['name']) == PAYLOAD
    finally:
        window.cleanup_resources()

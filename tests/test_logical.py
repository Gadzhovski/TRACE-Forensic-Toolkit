"""Logical evidence: AD1 and L01 images, folders, ZIP and TAR
(core/logical.py, core/logical_sources.py, core/ad1.py).

The AD1s are real FTK Imager images -- pyad1's four-segment one and
dissect.evidence's -- and every file's content must hash to the MD5 and
SHA-1 FTK recorded for it; the image-wide hash TRACE computes must be the
one FTK Imager logged. The L01s are real EnCase files, checked against the
MD5s EnCase recorded per file. Folders, ZIPs and TARs are made here from
real files. Then the case: analysis, indexing, search, YARA-free walks and
verification run on logical evidence exactly as on a disk.
"""

import hashlib
import io
import os
import shutil
import tarfile
import zipfile

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
CARVE = os.path.join(ROOT, 'test_images', 'carve_samples')


def sample(name, folder=SAMPLES):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py and "
                    "tools/carve_corpus.py")
    return path


def _contents(fs):
    """{path: bytes} of every file."""
    return {fs.path_of(n.inode): n.reader(0, n.size) if n.size else b''
            for n in fs.nodes.values() if not n.is_dir}


def test_an_ftk_imager_ad1_in_four_segments():
    from trace_app.core import ad1
    from trace_app.core.image_handler import ImageHandler
    path = sample('text-and-pictures.ad1')
    handler = ImageHandler(path)
    try:
        assert handler.loaded and handler.get_fs_type(0) == 'AD1'
        assert handler.is_logical and handler.get_size() == 0
        fs = handler.get_fs_info(0)
        # The tree FTK stored, as pyad1, dissect.evidence and the Sootmark
        # reader read it.
        assert sorted(fs.path_of(n.inode) for n in fs.nodes.values()
                      if n.inode != 1) == sorted([
            '/Pictures', '/Text', '/Text/norvig-big.txt',
            '/Pictures/0-0-581-Hydrangeas.jpg',
            '/Pictures/1-0-858-Chrysanthemum.jpg',
            '/Pictures/2-0-826-Desert.jpg', '/Pictures/4-0-757-Jellyfish.jpg',
            '/Pictures/5-0-762-Koala.jpg', '/Pictures/6-0-548-Lighthouse.jpg',
            '/Pictures/7-0-759-Penguins.jpg'])
        checked = 0
        for node in fs.nodes.values():
            if node.is_dir:
                continue
            data = handler.get_file_content(node.inode, 0)[0]
            assert len(data) == node.size
            assert hashlib.md5(data).hexdigest() == node.facts['md5']
            assert hashlib.sha1(data).hexdigest() == node.facts['sha1']
            checked += 1
        assert checked == 8
        big = fs.lookup('/Text/norvig-big.txt')
        assert big.size > 6_000_000                      # across segments
        # Random reads inside a chunk and across chunk boundaries.
        whole = big.reader(0, big.size)
        for offset, length in ((0, 10), (65530, 20), (1_000_000, 200_000),
                               (big.size - 5, 50)):
            assert big.reader(offset, length) == whole[offset:offset + length]
        hydrangeas = fs.lookup('/Pictures/0-0-581-Hydrangeas.jpg')
        assert hydrangeas.times['mtime'] == (1525246953, 969336000)
        assert hydrangeas.times['crtime'] == (1517123880, 0)
        info = handler.get_acquisition_info()
        assert info['Source'] == r'C:\Users\pcbje\Desktop\Data'
        assert info['Segments'] == '4'
        # The image-wide hash: what FTK Imager logged when it made it.
        hashes = handler.calculate_hashes()
        assert (hashes['computed_md5'], hashes['computed_sha1']) == (
            '24b6c553392e92dec7b6fa9c92c0216d',
            '0608982ed40664ec922f1991ac7ccf07d239ada1')
        assert (hashes['stored_md5'], hashes['stored_sha1']) == (
            hashes['computed_md5'], hashes['computed_sha1'])
        assert ad1.logged_hashes(path)['stored_sha1'] == \
            '0608982ed40664ec922f1991ac7ccf07d239ada1'
    finally:
        handler.close_resources()


@pytest.mark.parametrize('name, files', [
    ('ad1-compressed.ad1', ['/doc1.txt', '/doc2.txt']),
    ('ad1-test.ad1', ['/doc1.txt', '/doc2.txt']),
    ('ad1-long.ad1', ['/een lange filenaam 1 met spaties.txt',
                      '/Een nog langere bestandsnaam met nog meer tekens en '
                      '12345.txt'])])
def test_other_ad1_images(name, files):
    from trace_app.core.ad1 import open_ad1
    fs = open_ad1(sample(name))
    try:
        contents = _contents(fs)
        assert sorted(contents) == sorted(files)
        for path, data in contents.items():
            node = fs.lookup(path)
            assert hashlib.md5(data).hexdigest() == node.facts['md5']
    finally:
        fs.close()


def test_an_encrypted_ad1_is_refused_with_the_reason():
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(sample('ad1-encrypted.ad1'))
    assert not handler.loaded
    assert 'encrypted AD1' in handler.load_error


@pytest.mark.parametrize('name, files', [
    ('l01-docx.L01', {'/doc.doc': '827e84ea8d4f7b8e0faf0c47d4f847d2',
                      '/docx.docx': '9543174f78751e77af9b834304e41a8e'}),
    ('l01-zip.L01', {'/zip.zip': '9259dd63f39ddcc882c00a633eb682ed'})])
def test_encase_l01_files(name, files):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(sample(name))
    try:
        assert handler.loaded and handler.get_fs_type(0) == 'L01'
        fs = handler.get_fs_info(0)
        contents = _contents(fs)
        assert {p: hashlib.md5(d).hexdigest() for p, d in contents.items()} \
            == files
        assert all(fs.lookup(p).facts['md5'] == md5 for p, md5 in
                   files.items())
        entries = handler.get_directory_contents(0)
        assert {e['name'] for e in entries} == {p[1:] for p in files}
        assert all(e['modified'].startswith('2024-06-05') for e in entries)
        info = handler.get_acquisition_info()
        assert info['Format'].startswith('EnCase logical')
        assert handler.calculate_hashes()['computed_md5']
    finally:
        handler.close_resources()


def _collection(root):
    """A triage collection of real files: a Windows profile's documents,
    downloads and a browser history database."""
    files = {
        'C/Users/bob/Documents/test.docx': os.path.join(CARVE, 'test.docx'),
        'C/Users/bob/Downloads/pageant.exe': os.path.join(CARVE,
                                                          'pageant.exe'),
        'C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History':
            os.path.join(SAMPLES, 'History-chrome'),
    }
    for path in files.values():
        if not os.path.exists(path):
            pytest.skip("samples missing")
    for relative, source in files.items():
        target = os.path.join(root, *relative.split('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(source, target)
    return files


@pytest.mark.parametrize('kind', ['folder', 'zip', 'tar.gz'])
def test_folders_and_archives_as_evidence(tmp_path, kind):
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.walk import iter_files
    folder = tmp_path / 'collection'
    files = _collection(str(folder))
    if kind == 'folder':
        path = str(folder)
    elif kind == 'zip':
        path = str(tmp_path / 'collection.zip')
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for relative in files:
                archive.write(folder / relative, relative)
    else:
        path = str(tmp_path / 'collection.tar.gz')
        with tarfile.open(path, 'w:gz') as archive:
            archive.add(folder, 'collection')
    handler = ImageHandler(path)
    try:
        assert handler.loaded
        assert handler.get_fs_type(0) == {'folder': 'Folder', 'zip': 'ZIP',
                                          'tar.gz': 'TAR'}[kind]
        walked = {f.path.split('/C/', 1)[-1]: f for f in iter_files(handler)}
        assert sorted(walked) == sorted(r[2:] for r in files)
        for relative, source in files.items():
            with open(source, 'rb') as handle:
                assert walked[relative[2:]].read() == handle.read()
        # Read in pieces, as a viewer does.
        exe = walked['Users/bob/Downloads/pageant.exe']
        whole = exe.read()
        assert exe.read(100, 5000) == whole[5000:5100]
        hashes = handler.calculate_hashes()
        assert hashes['computed_sha256'] and hashes['size']
    finally:
        handler.close_resources()


def test_a_collection_is_analysed_indexed_and_verified_like_a_disk(tmp_path):
    """A folder in a case: the analysis types and hashes its files, the
    executable module reads the program, the index finds the document's
    text, the browser history is read, nothing is carved, and
    verification notices a file added to the folder afterwards."""
    from trace_app.core import carving
    from trace_app.core.activity import run_evidence
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    folder = tmp_path / 'collection'
    _collection(str(folder))
    case = Case.create(str(tmp_path / 'case'), 'Logical')
    evidence = case.add_evidence(str(folder))
    handler = ImageHandler(str(folder))
    index = SearchIndex(case.folder)
    try:
        analyse_evidence(handler, case, evidence, MODULES)
        programs = case.findings(evidence, 'executables')
        assert [p['name'] for p in programs] == ['pageant.exe']
        assert programs[0]['path'].endswith('/Users/bob/Downloads/pageant.exe')
        index_evidence(handler, index, evidence)
        assert [h['name'] for h in index.search('"python-docx was here"')
                if h['kind'] == 'file'] == ['test.docx']
        run_evidence(handler, case, evidence)
        visits = [r for r in case.user_activity(evidence)
                  if r['category'] == 'browser']
        assert visits
        assert carving.carve_evidence(handler, case, evidence, ['jpg']) == 0

        case.record_hashes(evidence, handler.calculate_hashes())
        (outcome,) = case.verify_evidence()
        assert outcome[1] == 'verified', outcome
        (folder / 'C' / 'added.txt').write_bytes(b'planted later')
        (outcome,) = case.verify_evidence()
        assert outcome[1] == 'changed', outcome
    finally:
        index.close()
        handler.close_resources()
        case.close()


def test_a_split_raw_image_is_hashed_whole(tmp_path):
    """TSK reads x.001, x.002... as one disk; the hash covers them all."""
    from tests.conftest import image_path
    from trace_app.core.image_handler import ImageHandler
    with open(image_path('8-jpeg-search.dd'), 'rb') as handle:
        data = handle.read()
    half = len(data) // 2 // 512 * 512
    (tmp_path / 'split.001').write_bytes(data[:half])
    (tmp_path / 'split.002').write_bytes(data[half:])
    handler = ImageHandler(str(tmp_path / 'split.001'))
    try:
        assert handler.get_size() == len(data)
        assert handler.calculate_hashes()['computed_md5'] == \
            hashlib.md5(data).hexdigest()
    finally:
        handler.close_resources()


def test_an_e01_verifies_by_its_media_not_its_container(tmp_path):
    """The case records an E01's media hash; verification recomputes the
    same, rather than hashing the .E01 file and calling it changed."""
    from tests.conftest import image_path
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('ntfs1-gen2.E01')
    case = Case.create(str(tmp_path / 'case'), 'E01')
    evidence = case.add_evidence(path)
    handler = ImageHandler(path)
    try:
        case.record_hashes(evidence, handler.calculate_hashes())
        (outcome,) = case.verify_evidence()
        assert outcome[1] == 'verified', outcome
    finally:
        handler.close_resources()
        case.close()
    raw = tmp_path / 'copy.dd'
    raw.write_bytes(io.BytesIO(b'\0' * 4096).getvalue())
    case = Case.create(str(tmp_path / 'case2'), 'raw')
    evidence = case.add_evidence(str(raw))
    try:
        handler = ImageHandler(str(raw))
        case.record_hashes(evidence, handler.calculate_hashes())
        handler.close_resources()
        raw.write_bytes(b'\1' + b'\0' * 4095)
        (outcome,) = case.verify_evidence()
        assert outcome[1] == 'changed'
    finally:
        case.close()


PASSWORDS = (b"place,user,password\n"
             b"bank,joesmith,superrich\n"
             b"alarm system,-,1234\n"
             b"treasure chest,-,1111\n"
             b"uber secret laire,admin,admin\n")


def _hfs_files(handler):
    """{path: bytes} of the HFS+ volume in a Mac disk image."""
    from trace_app.core.walk import iter_files
    return {f.path: f.read() for f in iter_files(handler)}


@pytest.mark.parametrize('name, note', [
    ('hfsplus_zlib.dmg', 'DMG (UDIF, zlib)'),
    ('hfsplus.sparseimage', 'Sparse image')])
def test_mac_disk_images_decompress_as_they_are_read(name, note):
    """dfvfs's test images: a zlib-compressed DMG and a sparse image, each
    a GPT disk with an HFS+ volume; its files read as dfvfs's tests
    expect."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(sample(name))
    try:
        assert handler.loaded and handler.container_note == note
        assert handler.get_partitions()[4][1] in (b'disk image', 'disk image')
        files = _hfs_files(handler)
        assert files['/passwords.txt'] == PASSWORDS
        assert files['/a_directory/another_file'][10:15] == b'other'
        assert handler.calculate_hashes()['computed_sha256']
    finally:
        handler.close_resources()


@pytest.mark.skipif(not shutil.which('hdiutil'), reason="macOS's hdiutil")
@pytest.mark.parametrize('form', ['ULFO', 'UDBZ', 'UDZO', 'UDCO', 'UDRO'])
def test_every_dmg_compression_hdiutil_writes(tmp_path, form):
    """On macOS: an image made by hdiutil itself in each format -- LZFSE,
    bzip2, zlib, ADC, uncompressed -- from a folder holding a real file;
    the file reads back byte for byte."""
    import subprocess
    from trace_app.core.image_handler import ImageHandler
    source = tmp_path / 'source'
    source.mkdir()
    with open(sample('pageant.exe', CARVE), 'rb') as handle:
        content = handle.read()
    (source / 'pageant.exe').write_bytes(content)
    image = tmp_path / f'{form}.dmg'
    subprocess.run(['hdiutil', 'create', '-quiet', '-srcfolder', str(source),
                    '-fs', 'HFS+', '-format', form, '-volname', 'Evidence',
                    str(image)], check=True)
    handler = ImageHandler(str(image))
    try:
        assert handler.loaded, handler.load_error
        files = _hfs_files(handler)
        # What was found, when the file was not: the container's reading of
        # the image, its partitions and the paths the walk saw.
        found = (f"{handler.container_note!r}; partitions "
                 f"{handler.get_partitions()}; files {sorted(files)[:20]}")
        assert '/pageant.exe' in files, found
        assert files['/pageant.exe'] == content
    finally:
        handler.close_resources()

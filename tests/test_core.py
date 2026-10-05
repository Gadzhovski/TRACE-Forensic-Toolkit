"""The forensic logic without a window: every input is built in the test."""

import io
import json
import os
import sqlite3
import sys
import zipfile

import pytest

from tests.conftest import image_path  # noqa: F401  (sets up isolation)


# --- helpers ------------------------------------------------------------------

def jpeg(exif=None, size=(64, 48)):
    from PIL import Image
    buffer = io.BytesIO()
    image = Image.new('RGB', size, (20, 90, 160))
    image.save(buffer, 'JPEG', exif=exif if exif is not None
               else image.getexif())
    return buffer.getvalue()


def zip_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as package:
        for name, data in files.items():
            package.writestr(name, data)
    return buffer.getvalue()


W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'


def docx_with_tracked_changes():
    document = f'''<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>
<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Notes</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Send to </w:t></w:r>
<w:del w:author="A"><w:r><w:delText>account 4471</w:delText></w:r></w:del>
<w:ins w:author="A"><w:r><w:t>the usual place</w:t></w:r></w:ins></w:p>
</w:body></w:document>'''
    comments = f'''<?xml version="1.0"?><w:comments xmlns:w="{W}">
<w:comment w:author="Boss" w:date="2026-01-02T10:00:00Z"><w:p><w:r>
<w:t>Delete before sending</w:t></w:r></w:p></w:comment></w:comments>'''
    core = '''<?xml version="1.0"?><cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/">
<dc:creator>J. Smith</dc:creator><cp:lastModifiedBy>K. Jones</cp:lastModifiedBy>
<dcterms:created>2023-02-19T10:29:00Z</dcterms:created></cp:coreProperties>'''
    return zip_bytes({'[Content_Types].xml': '<Types/>',
                      'word/document.xml': document,
                      'word/comments.xml': comments,
                      'docProps/core.xml': core})


# --- content checks -------------------------------------------------------------

def test_clean_camera_jpeg_has_no_appended_data():
    from trace_app.core import content_checks as cc
    assert cc.appended_data(jpeg()) == []


def test_zip_glued_to_jpeg_is_suspicious_at_the_right_offset():
    from trace_app.core import content_checks as cc
    clean = jpeg()
    found = cc.appended_data(clean + zip_bytes({'secret.txt': 'x' * 500}))
    assert found and found[0].grade == 'suspicious'
    assert found[0].detail['offset'] == len(clean)


def test_motion_photo_trailer_is_benign():
    from trace_app.core import content_checks as cc
    found = cc.appended_data(jpeg() + b'\0\0\0\x18ftypmp42' + b'x' * 200)
    assert found and found[0].grade == 'benign'


@pytest.mark.parametrize('name,kind', [
    ('invoice.pdf.exe', 'double-extension'),
    ('photo‮gpj.exe', 'bidi-name'),
    ('report.doc            .scr', 'padded-name'),
    ('archive.tar.gz', None),
])
def test_deceptive_names(name, kind):
    from trace_app.core import content_checks as cc
    kinds = [f.kind for f in cc.deceptive_name(name)]
    assert (kind in kinds) if kind else not kinds


def test_pdf_encryption_is_graded_by_what_it_blocks():
    import pymupdf
    from trace_app.core import content_checks as cc
    doc = pymupdf.open()
    doc.new_page()
    locked = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256,
                         user_pw='u', owner_pw='o')
    found = cc.encryption(locked)
    assert found and found[0].detail['scope'] == 'user-password'
    doc = pymupdf.open()
    doc.new_page()
    restricted = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256,
                             owner_pw='o', permissions=0)
    assert cc.encryption(restricted)[0].grade == 'benign'


def test_encrypted_volume_heuristic():
    from trace_app.core import content_checks as cc
    assert cc.possible_encrypted_volume('application/octet-stream', 7.9995,
                                        5 * 1024 * 1024)
    assert not cc.possible_encrypted_volume('application/octet-stream',
                                            7.9995, 5 * 1024 * 1024 + 3)


def test_photo_gps_is_decoded():
    from PIL import Image
    from PIL.TiffImagePlugin import IFDRational as R
    from trace_app.core import content_checks as cc
    exif = Image.new('RGB', (4, 4)).getexif()
    exif[0x010F], exif[0x0110] = 'Apple', 'iPhone 13'
    exif.get_ifd(0x8825).update({1: 'N', 2: (R(51), R(30), R(25.92)),
                                 3: 'W', 4: (R(0), R(7), R(39.36))})
    facts = cc.photo_metadata(jpeg(exif))
    assert abs(facts['latitude'] - 51.5072) < 1e-3
    assert abs(facts['longitude'] + 0.1276) < 1e-3


def test_document_authors_keep_their_zone():
    from trace_app.core import content_checks as cc
    facts = cc.document_authors(docx_with_tracked_changes())
    assert facts['author'] == 'J. Smith'
    assert facts['last_saved_by'] == 'K. Jones'
    assert facts['created'] == '2023-02-19 10:29:00 UTC'


# --- libmagic -----------------------------------------------------------------------

def test_libmagic_names_content_not_extension():
    """libmagic is loaded and identifies files by their bytes."""
    from PIL import Image
    from trace_app.infra.preflight import libmagic_identity
    import magic

    assert libmagic_identity(), "libmagic did not load"
    png = io.BytesIO()
    Image.new('RGB', (8, 8)).save(png, 'PNG')
    reader = magic.Magic(mime=True)
    assert reader.from_buffer(png.getvalue()) == 'image/png'
    assert reader.from_buffer(jpeg()) == 'image/jpeg'
    assert reader.from_buffer(b'%PDF-1.4\n1 0 obj\n<<>>\nendobj\n') == 'application/pdf'
    # TRACE's reader: libmagic 5.46 finds a ZIP from its end, so a buffer
    # reads as 'data' there; TRACE names it from its first header.
    from trace_app.core.analysis import magic_reader
    assert magic_reader().from_buffer(zip_bytes({'a.txt': b'x'})) ==         'application/zip'
    assert magic_reader().from_buffer(png.getvalue()) == 'image/png'


@pytest.mark.skipif(sys.platform != 'win32',
                    reason="Windows' libmagic opens its database by ANSI path")
def test_libmagic_loads_from_a_path_outside_the_ansi_code_page(tmp_path):
    """Installed under a Cyrillic or accented folder name, libmagic must
    still identify files (trace_app loads its database from memory)."""
    import shutil
    import trace_app  # noqa: F401  (installs the fix)
    import magic
    from magic import magic as binding

    folder = tmp_path / 'Пример José'
    folder.mkdir()
    database = folder / 'magic.mgc'
    shutil.copy(binding.default_magic_file, database)
    reader = magic.Magic(mime=True, magic_file=str(database))
    assert reader.from_buffer(jpeg()) == 'image/jpeg'


@pytest.mark.skipif(sys.platform != 'darwin',
                    reason="macOS takes libmagic from the pylibmagic wheel")
def test_macos_uses_the_bundled_libmagic_not_homebrew():
    """The library loaded is pylibmagic's, so a Mac needs no Homebrew and
    every Mac identifies files with the same signatures."""
    import trace_app  # noqa: F401  (must precede `import magic`)
    import pylibmagic
    from trace_app.infra.preflight import libmagic_identity

    bundled = os.path.realpath(str(pylibmagic.data))
    version, path = libmagic_identity()
    assert os.path.realpath(path).startswith(bundled + os.sep), path
    assert os.environ['MAGIC'] == str(pylibmagic.data.joinpath('magic.mgc'))
    assert version == '5.41'


# --- type detection and document reading ------------------------------------------

def test_disguised_png_is_shown_as_an_image_with_a_note():
    from PIL import Image
    from trace_app.core.filetypes import plan_view
    buffer = io.BytesIO()
    Image.new('RGB', (4, 4)).save(buffer, 'PNG')
    plan = plan_view('step2.txt', buffer.getvalue())
    assert plan.kind == 'image' and '.txt' in plan.note


def test_byte_counts_equal_a_plain_count():
    """Entropy's byte counts come from Pillow's histogram (fast); they must
    be exactly what counting each byte gives -- empty, short, odd types,
    and past the 16 MB a single histogram covers."""
    import collections
    from trace_app.core.analysis import _HISTOGRAM_SPAN, byte_counts, shannon

    def plain(data):
        counted = collections.Counter(bytes(data))
        return [counted.get(value, 0) for value in range(256)]
    big = bytes(range(256)) * (_HISTOGRAM_SPAN // 256) + b'\xff\x00\x07'
    for data in (b'', b'\x00', b'abc', os.urandom(65536), bytearray(b'xyz' * 99),
                 memoryview(b'0123456789')[2:7], big):
        assert byte_counts(data) == plain(data), len(data)
    assert byte_counts(b'') == [0] * 256
    assert shannon(bytes(range(256)) * 4) == 8.0
    assert shannon(b'a' * 1000) == 0.0


def test_a_guessed_targa_never_overrules_the_name():
    """TGA has no signature: libmagic 5.41+ (macOS, Linux) calls almost any
    bytes beginning 00 01 02 a Targa image. Passed as the MIME here, so
    every platform's libmagic is tested alike."""
    from trace_app.core.filetypes import plan_view
    plan = plan_view('invoice.pdf', bytes(range(256)) * 32,
                     mime='image/x-tga')
    assert plan.kind == 'document' and not plan.note
    assert plan_view('photo.tga', b'\0' * 64, mime='image/x-tga').kind == \
        'image'


def test_docx_keeps_tracked_deletions_and_comments():
    from trace_app.core.document_preview import to_html
    html, notices = to_html(docx_with_tracked_changes(), 'docx')
    assert 'account 4471' in html and 'deleted' in html
    assert 'Delete before sending' in html and 'Boss' in html
    assert any('Tracked changes' in n for n in notices)


def test_html_charset_is_honoured():
    from trace_app.core.document_preview import decode_html
    text, _ = decode_html('<meta charset="windows-1252"><p>Caf\xe9</p>'
                          .encode('cp1252'))
    assert 'Café' in text


# --- archives -------------------------------------------------------------------------

def _seven_zip(**kwargs):
    import py7zr
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, 'w', **kwargs) as archive:
        archive.writestr(b'ledger: 4471', 'notes/ledger.txt')
        archive.writestr(b'x' * 5000, 'data.bin')
    return buffer.getvalue()


def test_7z_lists_and_reads_in_full():
    from trace_app.core import archives
    data = _seven_zip()
    names = sorted(m['name'] for m in archives.list_members(data))
    assert names == ['data.bin', 'notes/ledger.txt']
    assert archives.read_member(data, 'data.bin') == b'x' * 5000


def test_7z_encryption_is_reported_not_hidden():
    from trace_app.core import archives, content_checks
    locked = _seven_zip(password='s3cret')
    members = archives.list_members(locked)
    assert members and all(m['encrypted'] for m in members)
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(locked, 'notes/ledger.txt')
    hidden = _seven_zip(password='s3cret', header_encryption=True)
    with pytest.raises(archives.EncryptedArchive):
        archives.list_members(hidden)
    assert 'file names' in content_checks.encryption(hidden)[0].summary


def test_7z_oversized_member_is_refused_not_truncated():
    from trace_app.core import archives
    with pytest.raises(archives.ArchiveError, match='more than'):
        archives.read_member(_seven_zip(), 'data.bin', limit=100)


# --- VirusTotal client ---------------------------------------------------------------------

class _Response:
    def __init__(self, status, payload=None):
        self.status_code, self._payload = status, payload

    def json(self):
        return self._payload


class _Session:
    def __init__(self, script):
        self.script, self.calls = script, []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for (m, suffix), responses in self.script.items():
            if m == method and url.endswith(suffix) and responses:
                return responses.pop(0)
        raise AssertionError(f'unexpected {method} {url}')


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


SHA = 'a' * 64
REPORT = {'data': {'attributes': {
    'sha256': SHA, 'last_analysis_stats': {'malicious': 3, 'undetected': 60,
                                           'harmless': 8,
                                           'type-unsupported': 5},
    'last_analysis_results': {'Mal': {'category': 'malicious',
                                      'result': 'Trojan.X'}}}}}


def test_rate_limiter_waits_instead_of_failing():
    from trace_app.core import virustotal as vt
    clock = _Clock()
    limiter = vt.RateLimiter(per_minute=4, per_day=500, clock=clock,
                             sleep=clock.sleep)
    waits = []
    for _ in range(9):
        limiter.acquire(on_wait=waits.append)
    assert len(waits) == 2 and clock.now >= 120


def test_upload_sends_raw_bytes_and_reports_by_local_hash():
    from trace_app.core import virustotal as vt
    clock = _Clock()
    session = _Session({
        ('POST', '/files'): [_Response(200, {'data': {'id': 'AN1'}})],
        ('GET', '/analyses/AN1'): [_Response(200, {'data': {'attributes': {
            'status': 'completed'}}})],
        ('GET', f'/files/{SHA}'): [_Response(200, REPORT)],
    })
    limiter = vt.RateLimiter(per_minute=1000, per_day=10000, clock=clock,
                             sleep=clock.sleep)
    client = vt.VirusTotalClient('k', session=session, limiter=limiter,
                                 sleep=clock.sleep, clock=clock)
    result = client.upload(b'MZ' + b'\0' * 100, 'evil.exe', SHA)
    sent = [c for c in session.calls if c[0] == 'POST'][0][2]['files']['file']
    assert result['status'] == vt.STATUS_FOUND and result['positives'] == 3
    assert result['total'] == 71                # unsupported engines excluded
    assert sent[1].startswith(b'MZ')            # the file, not a ZIP of it


# --- cases ------------------------------------------------------------------------------------

def test_case_records_findings_history_and_audit(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Test case')
    evidence = case.add_evidence(str(tmp_path / 'image.dd'))
    ref = 'p128:i54:s1'
    first = case.record_vt_result(evidence, ref, 'a.jpg', '/a.jpg', SHA,
                                  'hash', {'status': 'not_found'})
    second = case.record_vt_result(evidence, ref, 'a.jpg', '/a.jpg', SHA,
                                   'upload', {'status': 'found'})
    assert [r['id'] for r in case.vt_results(evidence)[:2]] == [second, first]
    actions = [a['action'] for a in case.activity(10)]
    assert 'hash sent to VirusTotal' in actions
    assert 'file uploaded to VirusTotal' in actions
    case.close()


def test_old_case_migrates_to_the_current_schema(tmp_path):
    from trace_app.core.case import SCHEMA_VERSION, Case
    folder = str(tmp_path / 'case')
    Case.create(folder, 'Old case').close()
    db = sqlite3.connect(os.path.join(folder, 'case.db'))
    db.execute("DROP TABLE vt_results")
    db.execute("DROP TABLE file_findings")
    db.execute("DROP TABLE carved_files")
    db.execute("DROP TABLE carving_state")
    db.execute("UPDATE case_info SET value='4' WHERE key='schema_version'")
    db.commit()
    db.close()
    case = Case.open(folder)
    assert str(case._get('schema_version')) == str(SCHEMA_VERSION)
    assert case.vt_results() == [] and case.findings() == []
    assert case.carved_files() == [] and case.carving_state(1) is None
    case.close()


def test_analysis_records_findings_in_one_pass():
    from trace_app.core.analysis import MODULES, analyse_bytes
    from PIL import Image
    from PIL.TiffImagePlugin import IFDRational as R
    exif = Image.new('RGB', (4, 4)).getexif()
    exif.get_ifd(0x8825).update({1: 'N', 2: (R(51), R(30), R(0)),
                                 3: 'W', 4: (R(0), R(7), R(0))})
    facts = analyse_bytes('IMG.jpg', jpeg(exif), MODULES)
    modules = {row[0]: json.loads(row[4]) for row in facts['findings']}
    assert 'photo' in modules and 'latitude' in modules['photo']
    assert facts['sha256'] and facts['entropy'] is not None


# --- carving ------------------------------------------------------------------------------

def test_carving_into_a_case_is_recorded_per_image(tmp_path):
    """Every carved file is a row addressed by its byte span, written under
    its own image's folder, hashed, and audited; a second carve replaces
    the first rather than doubling it."""
    import hashlib
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case, parse_artifact_ref
    from trace_app.core.image_handler import ImageHandler

    path = image_path('11-carve-fat.dd')
    case = Case.create(str(tmp_path / 'case'), 'Carving')
    evidence = case.add_evidence(path)
    handler = ImageHandler(path)
    try:
        found = carve_evidence(handler, case, evidence, CARVABLE_TYPES)
        assert found == 16
        rows = case.carved_files(evidence)
        assert len(rows) == found
        for row in rows:
            span = parse_artifact_ref(row['artifact_ref'])
            assert span['kind'] == 'span'
            assert span['begin'] == row['offset']
            assert span['end'] - span['begin'] == row['size']
            assert os.path.dirname(row['path']) == case.carved_dir_for(evidence)
            with open(row['path'], 'rb') as handle:
                content = handle.read()
            assert hashlib.sha256(content).hexdigest() == row['sha256']
            # The copy is the evidence's own bytes at that offset.
            assert handler.read(row['offset'], row['size']) == content
        assert case.carving_state(evidence)['status'] == 'done'
        assert case.analysis_summary()['carved'] == found

        assert carve_evidence(handler, case, evidence, ['jpg']) == \
            len([r for r in rows if r['type'] == 'jpg'])
        assert {r['type'] for r in case.carved_files(evidence)} == {'jpg'}
        actions = [a['action'] for a in case.activity(10)]
        assert actions.count('carving done') == 2
        assert 'carving started' in actions
    finally:
        handler.close_resources()
        case.close()


def test_carving_can_be_cancelled_and_keeps_what_it_found(tmp_path):
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler

    path = image_path('11-carve-fat.dd')
    case = Case.create(str(tmp_path / 'case'), 'Carving')
    evidence = case.add_evidence(path)
    handler = ImageHandler(path)
    calls = [0]

    def stop():
        calls[0] += 1
        return calls[0] > 3          # a few chunks, then Stop
    try:
        found = carve_evidence(handler, case, evidence, CARVABLE_TYPES,
                               should_stop=stop)
        state = case.carving_state(evidence)
        assert state['status'] == 'cancelled'
        assert state['found'] == found == len(case.carved_files(evidence))
        # It left at the check that said stop, not at the end of the image.
        assert calls[0] == 4
        assert 'carving cancelled' in [a['action'] for a in case.activity(5)]
    finally:
        handler.close_resources()
        case.close()


# --- RAR, listed without unrar ------------------------------------------------------

#: Two archives from rarfile's own test suite (ISC licence): a RAR3 with one
#: stored member, and a solid RAR5 whose members are compressed.
RAR3_STORED = (
    'UmFyIRoHAM+QcwAADQAAAAAAAABJBHQgkC4AAAAAAAAAAAACAAAAAJerqj4dMAkAIAAAAGFm'
    'aWxlLnR4dADwqzqJxD17AEAHAA==')
RAR5_SOLID = (
    'UmFyIRoHAQAJ78hvCwEFBwQGAQGAgIAA3vVwchwCAroABIAQtoMCoua3xYAbAQpzdGVzdDEu'
    'dHh0waw3REQj+iP2l/1iU1G+TJGBQQKMwQN5XL9Ho6otoDaT3aBYAEACANRQBHb2xH8y6p8y'
    'pcTM14PfABDoLYkcAgKNAASAELaDAqLmt8XAGwEKc3Rlc3QyLnR4dEUVCmABAAgD37f79vwd'
    'd1ZRAwUEAA==')


def test_rar_is_listed_and_stored_members_read_without_external_tools(
        monkeypatch):
    """Names, sizes and dates come from pure Python; a stored member is
    read; a compressed one is reported -- and no program is ever started,
    whatever is installed."""
    import base64
    import subprocess
    from trace_app.core import archives

    def no_programs(*args, **kwargs):
        raise AssertionError(f"started an external program: {args[0]}")
    monkeypatch.setattr(subprocess, 'Popen', no_programs)

    stored = base64.b64decode(RAR3_STORED)
    members = archives.list_members(stored)
    assert [(m['name'], m['size'], m['compressed']) for m in members] == \
        [('afile.txt', 0, False)]
    assert members[0]['modified'].startswith('2011-05-10')
    assert archives.read_member(stored, 'afile.txt') == b''

    solid = base64.b64decode(RAR5_SOLID)
    members = archives.list_members(solid)
    assert [(m['name'], m['size']) for m in members] == \
        [('stest1.txt', 2048), ('stest2.txt', 2048)]
    with pytest.raises(archives.ArchiveError, match='unrar'):
        archives.read_member(solid, 'stest1.txt')


def test_rar_and_7z_are_sized_from_their_structure():
    import base64
    from trace_app.core import carving_formats as formats
    for blob in (RAR3_STORED, RAR5_SOLID):
        data = base64.b64decode(blob)
        padded = data + os.urandom(4096)
        assert formats.measure_rar(formats.Source(padded, 0), 0) == \
            (len(data), 'rar')
    import py7zr
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, 'w') as archive:
        archive.writestr(b'ledger ' * 2000, 'ledger.txt')
    data = buffer.getvalue()
    assert formats.measure_7z(formats.Source(data + os.urandom(4096), 0), 0) \
        == (len(data), '7z')


@pytest.mark.images
def test_heic_photos_give_up_their_exif():
    """pi-heif teaches Pillow HEIC, so an iPhone/camera HEIC is a photo like
    any other -- previewed, and its EXIF read by the photo module."""
    pytest.importorskip('pi_heif')
    from trace_app.core.content_checks import photo_metadata
    path = os.path.join(os.path.dirname(image_path('carve-corpus.dd')),
                        'carve_samples', 'L_exif_xmp_iptc.heic')
    with open(path, 'rb') as handle:
        facts = photo_metadata(handle.read())
    assert facts['make'] == 'SONY' and facts['model'] == 'ILCE-7SM3'
    assert facts['taken'] == '2020:09:14 11:09:34'


# --- what this installation supports (infra/capabilities.py) -------------------

def test_every_capability_is_checked_and_reported():
    from trace_app.infra import capabilities
    keys = [c.key for c in capabilities.CAPABILITIES]
    assert len(keys) == len(set(keys))
    assert {c.group for c in capabilities.CAPABILITIES} <= \
        set(capabilities.GROUPS)
    text = capabilities.report_text()
    for capability in capabilities.CAPABILITIES:
        assert capability.feature in text
        ok, _version, detail = capability.check()
        assert ok or detail
    # On the platforms CI runs, everything the requirements promise loads.
    assert capabilities.available('tsk') and capabilities.available('ewf')


def test_an_unavailable_feature_says_why(monkeypatch):
    import platform
    import sys
    from trace_app.infra import capabilities
    probe = capabilities.Capability(
        'yara', 'File analysis', 'YARA rule scanning', 'yara-x',
        lambda: __import__('no_such_module_for_trace'))
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr(platform, 'machine', lambda: 'ARM64')
    assert not probe.available
    assert 'Windows on ARM' in probe.reason()
    assert 'yara-x' in probe.reason()


def test_evidence_summary_tells_not_run_from_found_nothing(tmp_path):
    """The Image Information window's Analysis tab: a job that never ran
    says so; one that ran and found nothing says that, with when; numbers
    are the case's; times read once as UTC."""
    import json
    from trace_app.core import evidence_summary as summary
    from trace_app.core.case import Case, make_artifact_ref
    case = Case.create(str(tmp_path / 'case'), 'Summary')
    try:
        evidence = case.add_evidence(str(tmp_path / 'disk.dd'))
        def sections(evidence_id):
            out, heading = {}, None
            for row in summary.rows_for(case, evidence_id):
                if row[0] is None:
                    heading = row[1]
                else:
                    out.setdefault(heading, {})[row[0]] = row[1:]
            return out

        rows = sections(evidence)
        assert rows['File analysis']['Status'][0] == summary.NOT_RUN
        assert rows['Deleted files']['Listed'][0] == summary.NOT_RUN
        assert rows['Integrity']['Last verification'][0] == \
            'never verified'
        case.record_event('deleted files listed',
                          f"evidence id={evidence} files=0")
        case.set_analysis_state(evidence, 'done', modules='magic',
                                files_done=3)
        case.add_module_findings(evidence, 'yara', [
            (make_artifact_ref(0, 5, 1), 'a.exe', '/a.exe', 10, 'rule',
             'suspicious', 'Matched x', json.dumps({}))])
        case.commit()
        rows = sections(evidence)
        listed = rows['Deleted files']['Listed'][0]
        assert listed.startswith('none found (') and listed.endswith(' UTC)')
        assert '+00:00' not in listed
        assert rows['File analysis']['Status'][0].startswith('done, ')
        assert rows['Carving']['Status'][0] == summary.NOT_RUN
        assert rows['Rules, hash sets and persistence'][
            'YARA rule matches'] == ('1', 'warning')
        # Another evidence's audit line is not this one's.
        other = case.add_evidence(str(tmp_path / 'other.dd'))
        assert sections(other)['Deleted files']['Listed'][0] == \
            summary.NOT_RUN
        assert summary.when('2026-10-04T23:07:58+00:00') == \
            '2026-10-04 23:07:58 UTC'
    finally:
        case.close()

"""The case report (trace_app/core/report.py).

Built from a real image (DFTT 8-jpeg-search.dd): a bookmarked JPEG, whose
picture must be in the report, read from the image; a bookmark and note
whose text is markup, which must arrive as text; and every section, in both
formats. The PDF is opened again and checked for its outline, its contents
page numbers and its running footer; the audit trail must hold each file's
SHA-256.
"""

import hashlib
import os
import re

import pytest

from tests.conftest import image_path

pytestmark = pytest.mark.images

HOSTILE = '<script>alert("x")</script><img src=http://example.org/a.png>'


@pytest.fixture(scope='module')
def written(tmp_path_factory):
    from trace_app.core import report
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.case import Case, make_artifact_ref
    from trace_app.core.image_handler import ImageHandler
    path = image_path('8-jpeg-search.dd')
    folder = str(tmp_path_factory.mktemp('report') / 'case')
    case = Case.create(folder, 'Report test', number='R-1',
                       examiner='Examiner Ä')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    analyse_evidence(handler, case, evidence_id, MODULES)
    ref = make_artifact_ref(0, 29, 1)                 # /alloc/file1.jpg
    bookmark = case.add_bookmark(evidence_id, ref, HOSTILE,
                                 artifact_name='file1.jpg',
                                 artifact_path='/alloc/file1.jpg')
    bookmark_id = bookmark['id'] if isinstance(bookmark, dict) else bookmark
    case.add_note(HOSTILE + '\nSecond line', evidence_id=evidence_id,
                  artifact_ref=ref, bookmark_id=bookmark_id)
    case.add_report_items('timeline', [{
        'evidence_id': evidence_id, 'artifact_ref': ref,
        'time': '2004-01-01 10:00:00', 'title': 'Created: file1.jpg',
        'detail': {'source': 'fs', 'subject': '/alloc/file1.jpg'}}])
    options = report.default_options(case)
    options.update(classification='RESTRICTED', organisation='Test lab',
                   summary=HOSTILE)
    for section in options['sections']:
        section['enabled'] = True
    out = report.write_report(case, options, {evidence_id: handler})
    yield case, out
    handler.close_resources()
    case.close()


def _file(out, kind):
    return next(item for item in out if item['format'] == kind)


def test_both_formats_written_and_audited(written):
    case, out = written
    assert {item['format'] for item in out} == {'html', 'pdf'}
    audit = [row['detail'] for row in case.activity(limit=50)
             if row['action'] == 'report created']
    for item in out:
        with open(item['path'], 'rb') as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        assert digest == item['sha256']
        assert any(os.path.basename(item['path']) in line
                   and f"sha256={digest}" in line for line in audit)
        assert os.path.dirname(item['path']) == os.path.join(case.folder,
                                                             'exports')


def test_evidence_text_is_never_markup(written):
    _case, out = written
    with open(_file(out, 'html')['path'], encoding='utf-8') as handle:
        page = handle.read()
    assert '<script' not in page.lower()
    assert '<img src=http' not in page
    assert '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;' in page
    # Self-contained: nothing is fetched when it is opened.
    # (Text may say "src=http..."; no tag may.)
    assert not re.search(r"""<[a-z]+[^<>]*\s(src|href)=['"]?(https?:|//)""",
                         page)


def test_the_bookmarked_picture_is_embedded_from_the_image(written):
    from trace_app.core.image_handler import ImageHandler
    _case, out = written
    with open(_file(out, 'html')['path'], encoding='utf-8') as handle:
        page = handle.read()
    pictures = re.findall(r"src='data:image/jpeg;base64,([A-Za-z0-9+/=]+)'",
                          page)
    assert pictures
    import base64
    import io
    from PIL import Image
    thumbnail = Image.open(io.BytesIO(base64.b64decode(pictures[0])))
    handler = ImageHandler(image_path('8-jpeg-search.dd'))
    handler.load_image()
    original = Image.open(io.BytesIO(handler.get_fs_info(0).open_meta(
        inode=29).read_random(0, 274260)))
    handler.close_resources()
    # Scaled to fit, never cropped: the shape is the original's.
    assert max(thumbnail.size) == 180
    assert abs(thumbnail.size[0] / thumbnail.size[1]
               - original.size[0] / original.size[1]) < 0.02


def test_pdf_has_outline_contents_and_footer(written):
    import pymupdf
    _case, out = written
    pdf = _file(out, 'pdf')
    with pymupdf.open(pdf['path']) as document:
        assert document.page_count == pdf['pages'] > 3
        outline = [entry[1] for entry in document.get_toc()]
        for title in ('Case summary', 'Evidence and verification',
                      'Bookmarks and notes', 'Timeline', 'Methods and tools',
                      'Appendix: audit trail'):
            assert title in outline
        first = document[0].get_text()
        assert 'RESTRICTED' in first and 'Report test' in first
        # The contents carry page numbers that match the outline.
        pages = {entry[1]: entry[2] for entry in document.get_toc()}
        assert re.search(rf"Methods and tools\s*\n\s*{pages['Methods and tools']}\b",
                         first + document[1].get_text())
        last = document[-1].get_text()
        assert f"Page {document.page_count} of {document.page_count}" in last
        assert any(link.get('kind') == pymupdf.LINK_GOTO
                   for link in document[0].get_links())


def test_methods_name_the_tools(written):
    _case, out = written
    with open(_file(out, 'html')['path'], encoding='utf-8') as handle:
        page = handle.read()
    import pytsk3
    assert pytsk3.TSK_VERSION_STR in page
    assert 'File analysis' in page


def test_template_round_trip_keeps_choices_not_case_text(tmp_path):
    from trace_app.core import report
    options = report.default_options()
    options.update(summary='private', case_number='X-1',
                   organisation='Lab', findings_grade='suspicious')
    options['sections'] = list(reversed(options['sections']))
    path = str(tmp_path / 't.json')
    report.save_template(options, path)
    loaded = report.load_template(path)
    assert loaded['organisation'] == 'Lab'
    assert loaded['findings_grade'] == 'suspicious'
    assert loaded['summary'] == '' and loaded['case_number'] == ''
    assert [s['key'] for s in loaded['sections']] == \
        [s['key'] for s in options['sections']]


def test_is_picture_by_content():
    from trace_app.core.report import is_picture
    assert is_picture(b'\xff\xd8\xff\xe0' + bytes(12))
    assert is_picture(b'\x00\x00\x00\x18ftypheic' + bytes(8))
    assert not is_picture(b'MZ\x90\x00')

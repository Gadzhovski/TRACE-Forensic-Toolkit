"""The report as a Word document (core/report_docx.py) and per-section
headings and text kept in report templates.

Built like tests/test_report.py's report (DFTT 8-jpeg-search.dd, a
bookmarked JPEG, markup as bookmark text) with every section. The .docx
is opened by MuPDF -- a reader that is not TRACE's -- whose text must
hold every section heading, the examiner's own section text, and the
bookmark's markup as text. The package itself must hang together: every
part is well-formed XML, every part and media type is declared, every
relationship resolves, every picture opens.
"""

import os
import re
import zipfile
import xml.etree.ElementTree as ET

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
    folder = str(tmp_path_factory.mktemp('docx') / 'case')
    case = Case.create(folder, 'Docx test', number='D-1',
                       examiner='Examiner Ä')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    analyse_evidence(handler, case, evidence_id, MODULES)
    ref = make_artifact_ref(0, 29, 1)                 # /alloc/file1.jpg
    case.add_bookmark(evidence_id, ref, HOSTILE, artifact_name='file1.jpg',
                      artifact_path='/alloc/file1.jpg')
    options = report.default_options(case)
    options.update(classification='RESTRICTED', formats=['html', 'docx'])
    for section in options['sections']:
        section['enabled'] = True
    options['sections'][0].update(title='Overview of the examination',
                                  text='Our standard method.\n'
                                       'Second line & <b>not bold</b>.')
    out = report.write_report(case, options, {evidence_id: handler})
    yield case, out, options
    handler.close_resources()
    case.close()


def _docx(out):
    return next(item['path'] for item in out if item['format'] == 'docx')


def test_written_and_audited(written):
    import hashlib
    case, out, _options = written
    path = _docx(out)
    with open(path, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert any(row['action'] == 'report created' and
               os.path.basename(path) in row['detail'] and digest in
               row['detail'] for row in case.activity(limit=20))


def test_the_package_hangs_together(written):
    from PIL import Image
    _case, out, _options = written
    with zipfile.ZipFile(_docx(out)) as archive:
        names = set(archive.namelist())
        for name in names:
            if name.endswith(('.xml', '.rels')):
                ET.fromstring(archive.read(name))           # well formed
        types = ET.fromstring(archive.read('[Content_Types].xml'))
        ns = '{http://schemas.openxmlformats.org/package/2006/content-types}'
        defaults = {d.get('Extension') for d in types.iter(ns + 'Default')}
        overrides = {o.get('PartName').lstrip('/')
                     for o in types.iter(ns + 'Override')}
        for name in names:
            assert name in overrides or name.rsplit('.', 1)[-1] in \
                defaults, name
        rels = ET.fromstring(archive.read('word/_rels/document.xml.rels'))
        targets = {r.get('Id'): r.get('Target') for r in rels}
        for target in targets.values():
            assert f"word/{target}" in names, target
        document = archive.read('word/document.xml').decode('utf-8')
        embeds = re.findall(r'r:embed="([^"]+)"', document)
        assert embeds, "the bookmarked JPEG's picture is in the document"
        for rid in embeds:
            with archive.open(f"word/{targets[rid]}") as handle:
                Image.open(handle).verify()
        assert 'RESTRICTED' in archive.read('word/header1.xml').decode()
        # Bookmarks for the headings; the contents field links to them.
        assert 'w:bookmarkStart' in document and ' TOC ' in document


def test_mupdf_reads_every_section(written):
    import pymupdf
    from trace_app.core import report
    _case, out, options = written
    document = pymupdf.open(_docx(out))
    text = ' '.join(page.get_text() for page in document)
    text = re.sub(r'\s+', ' ', text)
    for section in options['sections'][1:]:
        assert report.SECTION_TITLES[section['key']] in text, section['key']
    assert 'Overview of the examination' in text
    assert report.SECTION_TITLES['summary'] not in text.split('Contents')[0]
    assert 'Our standard method.' in text
    assert 'Second line & <b>not bold</b>.' in text     # text, not markup
    assert '<script>alert("x")</script>' in text


def test_templates_keep_section_text(written, tmp_path):
    from trace_app.core import report
    _case, _out, options = written
    path = str(tmp_path / 'template.json')
    report.save_template(options, path)
    loaded = report.load_template(path)
    first = loaded['sections'][0]
    assert first['title'] == 'Overview of the examination'
    assert first['text'].startswith('Our standard method.')
    assert 'docx' in loaded['formats']
    # A template carrying anything else in a section keeps only what a
    # section has.
    import json
    with open(path, encoding='utf-8') as handle:
        stored = json.load(handle)
    stored['sections'][0]['script'] = 'x'
    stored['sections'][1]['title'] = 7
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(stored, handle)
    loaded = report.load_template(path)
    assert set(loaded['sections'][0]) <= {'key', 'enabled', 'title', 'text'}
    assert 'title' not in loaded['sections'][1]


def test_the_dialog_collects_section_text_and_word(qapp, tmp_path):
    """Each section's page has a Heading and Section text; Output has
    Word. What the examiner types reaches the options, and a section left
    alone carries neither."""
    from trace_app.core.case import Case
    from trace_app.ui.dialogs.report import ReportDialog
    case = Case.create(str(tmp_path / 'case'), 'Dialog test')
    try:
        dialog = ReportDialog(case)
        title, text = dialog.section_custom['evidence']
        title.setText('Exhibits')
        text.setPlainText('Hashed with SHA-256.')
        dialog.docx_box.setChecked(True)
        options = dialog.collected()
        dialog.deleteLater()
    finally:
        case.close()
    sections = {s['key']: s for s in options['sections']}
    assert sections['evidence']['title'] == 'Exhibits'
    assert sections['evidence']['text'] == 'Hashed with SHA-256.'
    assert 'title' not in sections['summary']
    assert 'docx' in options['formats']

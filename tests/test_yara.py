"""YARA scanning (trace_app/core/yara_rules.py).

Rules written here, run over a real image (DFTT 8-jpeg-search.dd, whose
point is JPEGs under other names), every match checked against an
independent read of every file: the rule must flag exactly the files whose
bytes satisfy it, wherever they hide.
"""

import json
import os

import pytest

from tests.conftest import image_path

yara_x = pytest.importorskip('yara_x')

pytestmark = pytest.mark.images

JPEG_RULES = {
    'common.yar': 'private rule IsJPEG { condition: uint16(0) == 0xD8FF }\n',
    os.path.join('sub', 'jpeg.yar'):
        'include "../common.yar"\n'
        'rule JPEG_JFIF : picture { meta: severity = "low" '
        'strings: $j = "JFIF" condition: IsJPEG and $j }\n',
}


def _write(folder, files):
    for name, text in files.items():
        path = os.path.join(folder, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    return folder


@pytest.fixture
def library(tmp_path):
    from trace_app.core import yara_rules
    return yara_rules.Library(str(tmp_path / 'library'))


@pytest.fixture(scope='module')
def evidence(tmp_path_factory):
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('8-jpeg-search.dd')
    case = Case.create(str(tmp_path_factory.mktemp('yara') / 'case'),
                       'YARA')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    yield case, evidence_id, handler
    handler.close_resources()
    case.close()


def _on(options=None):
    from trace_app.core import yara_rules
    return dict(yara_rules.default_options(), enabled=True, **(options or {}))


def test_a_folder_imports_with_its_includes(tmp_path, library):
    source = _write(str(tmp_path / 'rules'), JPEG_RULES)
    entry = library.import_rules(source, 'Pictures', 'notable')
    # common.yar is included by jpeg.yar, so compiled through it only.
    assert entry['files'] == ['sub/jpeg.yar']
    assert set(entry['sha256']) == {'common.yar', 'sub/jpeg.yar'}
    assert os.path.isfile(os.path.join(library.set_folder(entry), 'sub',
                                       'jpeg.yar'))


def test_a_broken_rule_is_reported_and_nothing_kept(tmp_path, library):
    from trace_app.core import yara_rules
    source = _write(str(tmp_path / 'bad'), {'bad.yar':
                                            'rule bad { condition: nope }'})
    with pytest.raises(yara_rules.YaraError, match='nope'):
        library.import_rules(source)
    assert library.sets() == []
    assert [d for d in os.listdir(library.folder) if d != 'library.json'] \
        == []


def test_matches_are_exactly_the_files_that_satisfy_the_rule(
        tmp_path, library, evidence):
    from trace_app.core import walk, yara_rules
    case, evidence_id, handler = evidence
    library.import_rules(_write(str(tmp_path / 'rules'), JPEG_RULES),
                         'Pictures', 'notable')
    matched = yara_rules.scan_evidence(handler, case, evidence_id, library,
                                       _on())
    truth = {entry.path for entry in walk.iter_files(handler)
             if (lambda data: data[:2] == b'\xff\xd8' and b'JFIF' in data)(
                 entry.read())}
    found = case.findings(evidence_id, 'yara', limit=1000)
    assert {f['path'] for f in found} == truth and matched == len(truth)
    # A JPEG under another name is found by content.
    assert any(not path.lower().endswith('.jpg') for path in truth)
    detail = found[0]['detail']
    assert detail['rule'] == 'JPEG_JFIF' and detail['set'] == 'Pictures'
    assert detail['tags'] == ['picture']
    assert detail['strings'][0]['data'] == 'JFIF'
    assert found[0]['grade'] == 'notable'
    # Each string's offset is where the bytes are.
    first = next(e for e in walk.iter_files(handler)
                 if e.path == found[0]['path'])
    string = detail['strings'][0]
    assert first.read()[string['offset']:string['offset'] + 4] == b'JFIF'
    events = [r['action'] for r in case.activity(limit=10)]
    assert 'yara scan finished' in events


def test_severity_raises_the_grade_and_analysis_keeps_yara(
        tmp_path, library, evidence):
    from trace_app.core import yara_rules
    case, evidence_id, handler = evidence
    library.import_rules(_write(str(tmp_path / 'r'), {'m.yar': (
        'rule Bad { meta: severity = "high" strings: $j = "JFIF" '
        'condition: $j }')}), 'Lab', 'notable')
    yara_rules.scan_evidence(handler, case, evidence_id, library, _on())
    grades = {f['grade'] for f in case.findings(evidence_id, 'yara')}
    assert grades == {'suspicious'}
    case.clear_analysis(evidence_id)       # re-running file analysis
    assert case.findings(evidence_id, 'yara')


def test_carved_files_are_scanned_from_the_image(tmp_path, library,
                                                 evidence):
    from trace_app.core import yara_rules
    from trace_app.core.case import make_span_ref
    case, evidence_id, handler = evidence
    library.import_rules(_write(str(tmp_path / 'r'), JPEG_RULES), 'P')
    # A carved row pointing at the first JPEG's bytes on the image.
    head = handler.get_fs_info(0).open_meta(inode=29).read_random(0, 64)
    raw = handler.read(0, handler.get_size())    # /alloc/file1.jpg's bytes
    offset = raw.find(head)
    assert offset > 0
    case._db.execute(
        "INSERT INTO carved_files (evidence_id, artifact_ref, name, path, "
        "offset, size, type, carved_utc) VALUES (?,?,?,?,?,?,?,?)",
        (evidence_id, make_span_ref(0, offset, offset + 4096), 'c.jpg',
         'carved/c.jpg', offset, 4096, 'jpg', 'now'))
    case.commit()
    yara_rules.scan_evidence(handler, case, evidence_id, library, _on())
    assert any(f['path'] == 'carved: c.jpg'
               for f in case.findings(evidence_id, 'yara'))
    yara_rules.scan_evidence(handler, case, evidence_id, library,
                             _on({'include_carved': False}))
    assert not any(f['path'].startswith('carved:')
                   for f in case.findings(evidence_id, 'yara'))


def test_switched_off_clears_and_scans_nothing(tmp_path, library, evidence):
    from trace_app.core import yara_rules
    case, evidence_id, handler = evidence
    library.import_rules(_write(str(tmp_path / 'r'), JPEG_RULES), 'P')
    yara_rules.scan_evidence(handler, case, evidence_id, library, _on())
    assert case.findings(evidence_id, 'yara')
    assert yara_rules.scan_evidence(
        handler, case, evidence_id, library,
        dict(yara_rules.default_options(), enabled=False)) == 0
    assert case.findings(evidence_id, 'yara') == []


def test_printable_shows_text_utf16_and_hex():
    from trace_app.core.yara_rules import printable
    assert printable(b'JFIF') == 'JFIF'
    assert printable('cmd'.encode('utf-16-le')) == 'cmd  (UTF-16)'
    assert printable(b'\x00\xff\x10') == '00 ff 10'
    assert json.dumps(printable(b'\x89PNG'))

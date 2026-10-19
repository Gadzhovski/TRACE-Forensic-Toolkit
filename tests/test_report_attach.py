"""What the report lists first, what it leaves out, and the external
tools' own reports copied beside it (core/report.py, core/report_attach.py,
ui/dialogs/report.py). Every input is generated.

On a real case (2020JimmyWilson + 11-carve-fat) the report listed the
first 200 carves in disk order: 173 MFT records, so five of the six carved
JPGs never appeared; sections with nothing in them were printed empty; and
a LEAPP run was pointed at by an absolute path inside the case folder,
which means nothing to whoever receives the report.
"""

import csv
import hashlib
import os

import pytest


def _case(tmp_path):
    from trace_app.core.case import Case
    return Case.create(str(tmp_path / 'case'), 'Report options',
                       number='R-1', examiner='Examiner')


def _evidence(case, tmp_path, name='disk.dd'):
    path = tmp_path / name
    path.write_bytes(b'\0' * 4096)
    return case.add_evidence(str(path))


def _carve(case, evidence, offset, kind, status='valid'):
    case.add_carved(evidence, {
        'offset': offset, 'size': 1024, 'type': kind,
        'name': f"{offset:x}.{kind.lower()}", 'status': status,
        'sha256': hashlib.sha256(str(offset).encode()).hexdigest()})


def _sections(options, *keys):
    for section in options['sections']:
        section['enabled'] = section['key'] in keys
    return options


def _html(case, options, tmp_path):
    from trace_app.core import report
    options['formats'] = ['html']
    written = report.write_report(case, options, {},
                                  folder=str(tmp_path / 'out'))
    with open(written[0]['path'], encoding='utf-8') as handle:
        return handle.read(), written


def test_carves_an_examiner_reads_are_listed_before_system_records(tmp_path):
    from trace_app.core import report
    case = _case(tmp_path)
    try:
        evidence = _evidence(case, tmp_path)
        for number in range(5):
            _carve(case, evidence, 4096 * number, 'MFTRECORD', 'complete')
        _carve(case, evidence, 900_000, 'PDF', 'partial')
        _carve(case, evidence, 1_000_000, 'JPG')
        case._db.commit()
        options = _sections(report.default_options(case), 'carved')
        options['carved_limit'] = 2
        page, _written = _html(case, options, tmp_path)
        assert 'f4240.jpg' in page and 'dbba0.pdf' in page
        assert '0.mftrecord' not in page
        assert page.index('f4240.jpg') < page.index('dbba0.pdf')
        assert 'pictures and documents first' in page

        options['carved_order'] = 'offset'
        page, _written = _html(case, options, tmp_path)
        assert '0.mftrecord' in page and '1000.mftrecord' in page
        assert 'f4240.jpg' not in page and 'disk order' in page

        options['carved_order'] = 'kind'
        options['carved_statuses'] = ['partial']
        page, _written = _html(case, options, tmp_path)
        assert 'dbba0.pdf' in page and 'f4240.jpg' not in page
        assert 'Only: partial' in page
    finally:
        case.close()


def test_sections_with_nothing_in_them_are_left_out_and_named(tmp_path):
    from trace_app.core import report
    case = _case(tmp_path)
    try:
        evidence = _evidence(case, tmp_path)
        _carve(case, evidence, 8192, 'JPG')
        case._db.commit()
        counts = report.section_counts(case._db, folder=case.folder)
        assert counts['carved'] == 1
        assert counts['bookmarks'] == 0 and counts['virustotal'] == 0
        assert counts['indicators'] == 0
        assert all(counts[key] is None for key in report.ALWAYS_SHOWN)
        assert report.section_counts(case._db, [evidence + 1])['carved'] == 0

        options = _sections(report.default_options(case), 'summary',
                            'carved', 'virustotal', 'bookmarks', 'methods')
        page, _written = _html(case, options, tmp_path)
        assert "id='carved'" in page
        assert "id='virustotal'" not in page and "id='bookmarks'" not in page
        assert 'left out because the case holds nothing' in page
        assert SECTION('virustotal') in page.split('left out', 1)[1][:400]

        options['skip_empty'] = False
        page, _written = _html(case, options, tmp_path)
        assert "id='virustotal'" in page
    finally:
        case.close()


def SECTION(key):
    from trace_app.core.report import SECTION_TITLES
    return SECTION_TITLES[key]


def test_each_report_has_a_folder_of_its_own(tmp_path):
    from trace_app.core import report
    case = _case(tmp_path)
    try:
        options = _sections(report.default_options(case), 'summary')
        _page, first = _html(case, options, tmp_path)
        _page, second = _html(case, options, tmp_path)
        assert first[0]['folder'] != second[0]['folder']
        for written in (first, second):
            assert os.path.basename(written[0]['folder']).startswith('Report ')
            assert os.listdir(written[0]['folder']) == ['report.html']
    finally:
        case.close()


def test_a_cancelled_report_leaves_no_folder(tmp_path):
    from trace_app.core import report
    case = _case(tmp_path)
    try:
        options = _sections(report.default_options(case), 'summary')
        options['formats'] = ['html']
        out = tmp_path / 'out'
        with pytest.raises(report.ReportCancelled):
            report.write_report(case, options, {}, folder=str(out),
                                should_stop=lambda: True)
        assert not out.exists() or os.listdir(out) == []
    finally:
        case.close()


def test_source_paths_read_every_way_the_tools_write_them():
    from trace_app.core.report import source_paths
    assert source_paths('a/x.db\na/y.db\n') == ['a/x.db', 'a/y.db']
    assert source_paths('TestData/x.log TestData/x.log.1.gz') == \
        ['TestData/x.log', 'TestData/x.log.1.gz']
    assert source_paths('C:\\Cases\\rleapp run\\report\\data\\r.zip') == \
        ['data/r.zip']
    assert source_paths('') == []


def _fake_run(case, evidence, tmp_path, password_in=None):
    """A LEAPP run folder as the tools leave it: report pages, media,
    LAVA, the database, and data/ (the tool's copies of evidence)."""
    run_folder = tmp_path / 'case' / 'modules' / 'iLEAPP-1'
    report = run_folder / 'report'
    files = {
        'index.html': b"<meta http-equiv='refresh' content='0; "
                      b"url=_HTML/index.html'>",
        '_HTML/index.html': b'<html>the tool\'s report</html>',
        '_HTML/Chats.html': b'<html>chats</html>',
        '_TSV Exports/Chats.tsv': b'a\tb\n',
        'media/photo.jpg': b'\xff\xd8\xff' + b'\0' * 100,
        '_lava_data.lava': b'{}',
        '_lava_artifacts.db': b'SQLite format 3\0' + b'\0' * 200,
        'data/private/var/mobile/sms.db': b'evidence copy',
    }
    for name, data in files.items():
        path = report / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if password_in:
        (run_folder / 'run.log').write_text(
            "started\nWARNING: the backup password is in 1 file(s) TRACE "
            f"does not rewrite: {password_in}\n", encoding='utf-8')
    run = case.add_module_run(evidence, 'iLEAPP', '2026.4.4', 'x' * 64,
                              {'input': {'label': 'the file system'}},
                              str(run_folder))
    case.finish_module_run(run, 'complete')
    return run, files


def test_a_tools_report_is_copied_without_the_evidence_copies(tmp_path):
    from trace_app.core import report_attach
    case = _case(tmp_path)
    try:
        evidence = _evidence(case, tmp_path)
        run_id, files = _fake_run(case, evidence, tmp_path,
                                  password_in='_HTML/Chats.html')
        [run] = case.module_runs()
        out = tmp_path / 'report'
        copies, manifest, digest = report_attach.copy_runs([run], str(out))
        entry = copies[run_id]
        assert entry['index'] == f"{report_attach.FOLDER}/iLEAPP run " \
                                 f"{run_id}/index.html"
        with open(manifest, encoding='utf-8', newline='') as handle:
            rows = list(csv.DictReader(handle))
        copied = {row['path'].split('/', 1)[1] for row in rows}
        assert copied == {'index.html', '_HTML/index.html',
                          '_TSV Exports/Chats.tsv', 'media/photo.jpg',
                          '_lava_data.lava'}
        assert ('_HTML/Chats.html', 'holds the backup password (run.log)') \
            in entry['skipped']
        root = out / report_attach.FOLDER
        for row in rows:
            data = (root / row['path']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            assert len(data) == int(row['size'])
        assert not (root / f"iLEAPP run {run_id}" / 'data').exists()
        assert digest == hashlib.sha256(
            open(manifest, 'rb').read()).hexdigest()

        copies, manifest, _digest = report_attach.copy_runs(
            [run], str(tmp_path / 'with-db'), database=True)
        with open(manifest, encoding='utf-8', newline='') as handle:
            paths = [row['path'] for row in csv.DictReader(handle)]
        assert any(p.endswith('_lava_artifacts.db') for p in paths)
        assert not any('/data/' in p for p in paths)
    finally:
        case.close()


def test_the_report_links_the_tools_own_report_and_audits_the_copy(
        tmp_path):
    from trace_app.core import report, report_attach
    case = _case(tmp_path)
    try:
        evidence = _evidence(case, tmp_path)
        run_id, _files = _fake_run(case, evidence, tmp_path)
        options = _sections(report.default_options(case), 'modules')
        page, written = _html(case, options, tmp_path)
        link = f"{report_attach.FOLDER}/iLEAPP run {run_id}/index.html"
        assert f"href='{link}'" in page
        folder = written[0]['folder']
        assert os.path.isfile(os.path.join(folder, *link.split('/')))
        manifest = os.path.join(folder, report_attach.FOLDER,
                                report_attach.MANIFEST)
        digest = hashlib.sha256(open(manifest, 'rb').read()).hexdigest()
        assert digest in page
        audited = [row for row in case.activity()
                   if row['action'] == 'external tool reports copied']
        assert audited and digest in audited[0]['detail']

        options['copy_tool_reports'] = False
        page, written = _html(case, options, tmp_path)
        assert f"href='{link}'" not in page
        assert not os.path.exists(os.path.join(written[0]['folder'],
                                               report_attach.FOLDER))
    finally:
        case.close()


def test_the_dialog_offers_presets_counts_and_the_new_choices(qapp,
                                                              tmp_path):
    from tests.conftest import pump
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs.report import ReportDialog, CUSTOM
    case = _case(tmp_path)
    try:
        evidence = _evidence(case, tmp_path)
        _carve(case, evidence, 8192, 'JPG')
        _fake_run(case, evidence, tmp_path)
        case._db.commit()
        dialog = ReportDialog(case)
        pump(qapp, 20, until=lambda: dialog.counts)
        assert dialog.counts['carved'] == 1
        assert dialog.counts['virustotal'] == 0
        texts = {dialog.section_list.item(i).data(0x0100):
                 dialog.section_list.item(i).text()
                 for i in range(dialog.section_list.count())}
        assert texts['carved'].endswith('1')
        assert 'nothing in the case yet' in texts['virustotal']

        names = [dialog.preset_combo.itemText(i)
                 for i in range(dialog.preset_combo.count())]
        summary = names.index('Findings summary')
        dialog.preset_combo.setCurrentIndex(summary)
        assert 'findings' in dialog._ticked()
        assert 'carved' not in dialog._ticked()
        for i in range(dialog.section_list.count()):
            item = dialog.section_list.item(i)
            if item.data(0x0100) == 'carved':
                item.setCheckState(Qt.Checked)
        assert dialog.preset_combo.currentText() == CUSTOM

        options = dialog.collected()
        dialog.done(0)
        dialog.deleteLater()
        pump(qapp, 0.05)
    finally:
        case.close()
    assert options['evidence_ids'] is None
    assert options['skip_empty'] is True
    assert options['carved_order'] == 'kind'
    assert options['carved_statuses'] == []
    assert options['module_runs'] == []
    assert options['copy_tool_reports'] is True
    assert options['module_database'] is False

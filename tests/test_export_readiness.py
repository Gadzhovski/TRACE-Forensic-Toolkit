"""Before an export: which scans it draws on have not run
(core/export_readiness, ui/widgets/readiness_banner).

A tester's first comparison of TRACE's Project VICS export with AXIOM's
was made before carving had run, and nothing said so. Every input here is
generated: a FAT card with a photo, a deleted one and a text file.
"""

import hashlib
import io
import json

import pytest

from tests.disk_builders import fat16_volume


def jpeg(colour):
    from PIL import Image
    out = io.BytesIO()
    Image.new('RGB', (24, 24), colour).save(out, 'JPEG')
    return out.getvalue()


def _fat_disk(tmp_path):
    """A FAT16 card: a photo, a deleted photo, a text file."""
    photo, other = jpeg('red'), jpeg('green')
    image, _placed, _free = fat16_volume([('IMG1.JPG', photo),
                                          ('GONE.JPG', other),
                                          ('NOTE.TXT', b'text ' * 100)])
    image = bytearray(image)
    image[image.index(b'GONE    JPG')] = 0xE5     # deleted, as FAT marks it
    path = tmp_path / 'card.dd'
    path.write_bytes(bytes(image))
    return str(path), photo, other


# --- the module keys ------------------------------------------------------------

def test_the_module_keys_are_the_dialogs():
    """core keeps its own copy of the dialog's keys (core may not import
    ui): they must stay the same strings, and Full the same set."""
    from trace_app.core import export_readiness as readiness
    from trace_app.ui.dialogs import analysis_modules as dialog
    for name in ('CARVE', 'INDEX', 'INDEX_FREE', 'ACTIVITY', 'NTFS',
                 'FSTIMES', 'HASHSETS', 'YARA', 'SIGMA', 'PERSISTENCE',
                 'KEYWORDS', 'THUMBNAILS', 'DELETED'):
        assert getattr(readiness, name) == getattr(dialog, f'MODULE_{name}')
    assert readiness.FULL == dialog.PROFILES[dialog.FULL]
    from trace_app.core.background import JOBS
    assert set(readiness.RECORDED_JOBS) <= set(JOBS)


# --- gaps from states -----------------------------------------------------------

def _done(**settings):
    return {'state': 'done', 'settings': settings}


def test_a_vics_export_wants_every_picture_and_video_carved():
    from trace_app.core import export_readiness as readiness
    evidence = [(1, 'card.dd')]
    gap, = readiness.gaps('vics', evidence, {1: {}})
    assert (gap.module, gap.state) == ('carve', readiness.NOT_RUN)
    assert 'carved' in gap.why
    # Carved for JPEG only: it ran, with less than the export wants.
    gap, = readiness.gaps('vics', evidence,
                          {1: {'carve': _done(types=['jpg'])}})
    assert gap.state == readiness.LESS and 'GIF' in gap.why
    every = sorted(readiness.media_carve_types())
    assert readiness.gaps('vics', evidence,
                          {1: {'carve': _done(types=every)}}) == []
    # Cancelled: said so, and run again.
    gap, = readiness.gaps('vics', evidence, {1: {'carve': {
        'state': 'cancelled', 'settings': {'types': every}}}})
    assert gap.state == readiness.CANCELLED
    assert readiness.missing_modules([gap]) == {1: ['carve']}


def test_a_module_that_cannot_run_on_an_image_is_not_asked_for():
    """Logical evidence has no unallocated space; a FAT card has no NTFS
    -- but its other file-system times serve the same need."""
    from trace_app.core import export_readiness as readiness
    assert readiness.gaps('vics', [(1, 'folder')], {1: {}},
                          {1: {'carve': "files, not a disk"}}) == []
    states = {1: {'magic': _done(), 'hash': _done()}}
    gap, = readiness.gaps('dfxml', [(1, 'card')], states,
                          {1: {'ntfs': "no NTFS volume"}})
    assert gap.module == 'fstimes'
    states[1]['fstimes'] = _done()
    assert readiness.gaps('dfxml', [(1, 'card')], states,
                          {1: {'ntfs': "no NTFS volume"}}) == []


def test_a_running_scan_is_waited_for_not_run_again():
    from trace_app.core import export_readiness as readiness
    gap, = readiness.gaps('vics', [(1, 'card')],
                          {1: {'carve': {'state': 'running',
                                         'settings': {}}}})
    assert gap.state == readiness.RUNNING
    assert readiness.missing_modules([gap]) == {}


# --- what a case recorded ---------------------------------------------------------

@pytest.fixture
def case_with_card(tmp_path):
    from trace_app.core.case import Case
    disk, photo, _other = _fat_disk(tmp_path)
    case = Case.create(str(tmp_path / 'case'), 'Readiness', number='R-1',
                       examiner='A. Examiner')
    evidence_id = case.add_evidence(disk)
    yield case, evidence_id, disk, photo
    case.close()


def test_a_case_keeps_how_each_module_ended(case_with_card):
    from trace_app.core import export_readiness as readiness
    case, evidence_id, _disk, _photo = case_with_card
    assert readiness.module_states(case, evidence_id) == {}
    case.record_module_completion(evidence_id, 'carve', 'done',
                                  {'types': ['jpg'], 'source': 'unallocated'})
    case.record_module_completion(evidence_id, 'analysis', 'cancelled',
                                  {'modules': ['magic', 'hash']})
    case.record_module_completion(evidence_id, 'deleted', 'failed',
                                  last_error='boom')
    states = readiness.module_states(case, evidence_id)
    assert states['carve'] == {'state': 'done', 'settings': {
        'types': ['jpg'], 'source': 'unallocated'}}
    assert states['magic']['state'] == states['hash']['state'] == 'cancelled'
    assert states['deleted']['state'] == 'failed'
    assert case.module_completions(evidence_id)['deleted']['last_error'] \
        == 'boom'


def test_an_older_case_is_read_from_what_its_modules_kept(case_with_card):
    """A case from before module_completions: the analysis's and
    carving's own state, and rows a module left."""
    from trace_app.core import export_readiness as readiness
    case, evidence_id, _disk, _photo = case_with_card
    case.set_analysis_state(evidence_id, 'done', modules='magic,hash')
    case.set_carving_state(evidence_id, 'done', types='jpg,png')
    case._db.execute(
        "INSERT INTO deleted_files (evidence_id, artifact_ref, path, name, "
        "is_dir, size, state) VALUES (?, 'p0:i5:s1', '/a', 'a', 0, 1, "
        "'recoverable')", (evidence_id,))
    case._db.commit()
    states = readiness.module_states(case, evidence_id)
    assert states['magic']['state'] == 'done'
    assert 'entropy' not in states
    assert states['carve']['settings']['types'] == ['jpg', 'png']
    assert states['deleted']['state'] == 'done'
    assert 'thumbnails' not in states


def test_the_schema_records_completions(case_with_card):
    from trace_app.core.case import SCHEMA_VERSION
    case, *_rest = case_with_card
    assert SCHEMA_VERSION >= 26
    assert case._db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'module_completions'"
    ).fetchone()


def test_every_module_job_records_how_it_ended(qapp, case_with_card):
    """Written once, by the child process that ran the job: done, or
    cancelled when it was asked to stop."""
    from trace_app.ui.process_worker import ProcessWorker
    case, evidence_id, disk, _photo = case_with_card

    class Deleted(ProcessWorker):
        kind = 'deleted'

    for stop_first, expected in ((False, 'done'), (True, 'cancelled')):
        worker = Deleted({'case_folder': case.folder,
                          'evidence_id': evidence_id, 'image_path': disk})
        if stop_first:
            worker.stop()
        worker.start()
        assert worker.wait(120000)
        recorded = case.module_completions(evidence_id)['deleted']
        assert recorded['status'] == expected
        worker.deleteLater()


# --- the banner ---------------------------------------------------------------------

def test_the_banner_says_what_is_missing_per_evidence(qapp):
    from trace_app.core.export_readiness import Gap, NOT_RUN
    from trace_app.ui.widgets.readiness_banner import (ReadinessBanner,
                                                       gap_lines)
    banner = ReadinessBanner('report')
    assert not banner.isVisibleTo(None) and not banner.runnable()
    gaps = [Gap('card.dd', 1, 'carve', NOT_RUN, "its findings will be "
                "missing"),
            Gap('card.dd', 1, 'hash', NOT_RUN, "its findings will be "
                "missing")]
    banner.set_gaps(gaps)
    assert banner.runnable()
    # Two modules missing alike share a line.
    (evidence, lines), = gap_lines(gaps)
    assert evidence == 'card.dd' and len(lines) == 1
    assert lines[0].startswith('File carving, ')
    assert 'card.dd' in banner.body.text()
    banner.deleteLater()


# --- the window -----------------------------------------------------------------------

def _case_window(qapp, case):
    from tests.conftest import pump
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    folder = case.folder
    case.close()
    window = MainWindow(case=Case.open(folder))
    window._report_dialogs = False
    pump(qapp, 60, lambda: window.evidence_files)
    return window


def test_run_missing_scans_then_export_carves_first(qapp, case_with_card,
                                                    tmp_path):
    """The VICS dialog's Run Missing Scans, Then Export: carving is queued,
    then the export, which reads the carves once they are there."""
    from tests.conftest import close_window, pump
    case, evidence_id, _disk, photo = case_with_card
    window = _case_window(qapp, case)
    try:
        evidence = window._vics_evidence()
        gap, = window.export_gaps('vics', evidence)
        assert gap.module == 'carve'
        out = tmp_path / 'exports'
        out.mkdir()
        window.export_vics({'evidence': evidence,
                            'parent_folder': str(out),
                            'case_number': 'R-1', 'contact': {},
                            'model': 'US', 'include_deleted': True,
                            'include_carved': True, 'min_size': 0,
                            'run_first': True})
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
        titles = [job.title for job, _state in window.job_bar.jobs()]
        carving = next(i for i, t in enumerate(titles)
                       if t.startswith('Carving'))
        exporting = max(i for i, t in enumerate(titles)
                        if 'Project VICS' in t)
        assert carving < exporting
        assert window.export_gaps('vics', evidence) == []
        summary = window.last_vics_export
        assert summary and not summary['cancelled']
        with open(summary['json'], encoding='utf-8') as handle:
            media = json.load(handle)['value'][0]['Media']
        # The deleted photo's clusters were carved: it is there as a carve.
        assert any(f['Unallocated'] for m in media
                   for f in m['MediaFiles'])
        assert hashlib.md5(photo).hexdigest().upper() in \
            {m['MD5'] for m in media}
    finally:
        close_window(window)


def test_the_vics_dialog_shows_the_gaps_of_what_is_ticked(qapp, tmp_path):
    from PySide6.QtCore import Qt
    from trace_app.core.export_readiness import Gap, NOT_RUN
    from trace_app.ui.dialogs.vics_export import VicsExportDialog
    evidence = [{'key': 1, 'name': 'a.E01', 'source_id': 'A', 'path': 'a'},
                {'key': 2, 'name': 'b.dd', 'source_id': 'B', 'path': 'b'}]
    asked = []

    def gaps_for(chosen):
        asked.append([row['key'] for row in chosen])
        return [Gap(row['name'], row['key'], 'carve', NOT_RUN, "why")
                for row in chosen if row['key'] == 2]
    dialog = VicsExportDialog(evidence, {'folder': str(tmp_path),
                                         'case_number': 'X'},
                              gaps_for=gaps_for)
    assert dialog.readiness.isVisibleTo(dialog)
    assert dialog.run_first_button.isVisibleTo(dialog)
    dialog.evidence_list.item(1).setCheckState(Qt.Unchecked)
    assert asked[-1] == [1]
    assert not dialog.readiness.isVisibleTo(dialog)
    assert not dialog.run_first_button.isVisibleTo(dialog)
    dialog.evidence_list.item(1).setCheckState(Qt.Checked)
    dialog.run_first_button.click()
    assert dialog.options['run_first'] is True
    dialog.deleteLater()


def test_other_exports_ask_first(qapp, case_with_card, tmp_path):
    """DFXML, the Timeline and the report ask before they start; Cancel
    there writes nothing, Export Anyway goes on as before."""
    from tests.conftest import close_window
    from trace_app.ui.widgets.readiness_banner import EXPORT_NOW
    case, _evidence_id, _disk, _photo = case_with_card
    window = _case_window(qapp, case)
    try:
        asked = []

        def answer(choice):
            def ask(kind, gaps):
                asked.append((kind, {gap.module for gap in gaps}))
                return choice
            return ask
        window.ask_export_readiness = answer(None)
        assert window.export_for_tools('dfxml') is None
        assert asked[-1][0] == 'dfxml'
        assert {'magic', 'hash'} <= asked[-1][1]
        assert window._timeline_before_export('csv') is False
        assert asked[-1][0] == 'timeline'
        assert window.create_report() is False
        assert asked[-1][0] == 'report'
        window.ask_export_readiness = answer(EXPORT_NOW)
        assert window._timeline_before_export('csv') is True
    finally:
        close_window(window)


def test_quick_triage_remembers_its_carving(qapp, tmp_path):
    from tests.conftest import close_window, pump
    from trace_app.ui.main_window import MainWindow
    disk, _photo, _other = _fat_disk(tmp_path)
    window = MainWindow()
    try:
        window._report_dialogs = False
        assert window.open_evidence_image(disk)
        evidence = window._vics_evidence()
        gap, = window.export_gaps('vics', evidence)
        assert gap.module == 'carve'
        assert window.run_missing_scans('vics', [gap]) == 1
        assert pump(qapp, 300, lambda: not window.job_bar.busy)
        assert window.export_gaps('vics', evidence) == []
    finally:
        close_window(window)

"""The welcome screen, the New Case / Add Evidence wizards, evidence intake
and verification as a job.

Evidence is the public test images; a case is created for real in a temp
folder and read back -- the database, the audit trail and the folder on disk
are what the wizard is judged by, not its widgets.
"""

import os
import shutil
import sqlite3

import pytest

from tests.conftest import image_path, pump

E01, RAW = 'ntfs1-gen2.E01', '8-jpeg-search.dd'


@pytest.fixture
def quiet_dialogs(monkeypatch):
    """Answer modal message boxes (they would block offscreen) and record
    what was said."""
    from trace_app.ui.dialogs import message
    said = []
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name,
                            lambda *a, name=name, **k: said.append((name, a)))
    monkeypatch.setattr(message, 'question', lambda *a, **k: True)
    return said


# --- probing evidence ------------------------------------------------------------

@pytest.mark.images
def test_an_e01_is_described_and_its_header_fills_custody():
    from trace_app.core import evidence_probe
    result = evidence_probe.probe(image_path(E01))
    assert result['status'] == evidence_probe.NOTES
    assert result['format'] == 'EnCase image (E01)'
    assert result['contents'] == 'NTFS'
    assert result['size'] == 516554752
    assert result['stored_hashes']
    # What ntfs1-gen2's header records, as libewf reads it.
    assert result['custody']['acquired_on'] == 'Fri Feb 22 10:54:32 2013'
    assert 'ntfs1-gen2.aff' in result['custody']['description']


@pytest.mark.images
def test_a_partitioned_raw_image_names_its_scheme_and_file_systems():
    from trace_app.core import evidence_probe
    result = evidence_probe.probe(image_path('ext-part-test-2.dd'))
    assert result['status'] == evidence_probe.OK
    assert result['contents'].startswith('MBR · FAT16')


def test_unreadable_items_say_why(tmp_path):
    from trace_app.core import evidence_probe
    notes = tmp_path / 'notes.txt'
    notes.write_text('not evidence')
    result = evidence_probe.probe(str(notes))
    assert result['status'] == evidence_probe.ERROR
    assert 'Not an evidence format TRACE reads (.txt)' in result['error']
    gone = evidence_probe.probe(str(tmp_path / 'missing.E01'))
    assert gone['status'] == evidence_probe.ERROR
    assert 'does not exist' in gone['error']


def test_later_segments_are_recognised():
    from trace_app.ui.widgets.evidence_intake import is_later_segment
    for name in ('x.E02', 'x.e10', 'x.Ex05', 'x.L02', 'x.002', 'x.ad2'):
        assert is_later_segment(name), name
    for name in ('x.E01', 'x.001', 'x.dd', 'x.ad1', 'x.Lx01', 'x.vmdk'):
        assert not is_later_segment(name), name


# --- the case: custody details, schema, verdicts ------------------------------------------

def test_evidence_carries_custody_details_and_they_are_audited(tmp_path):
    from trace_app.core.case import Case
    image = tmp_path / 'disk.dd'
    image.write_bytes(b'\0' * 4096)
    case = Case.create(str(tmp_path / 'case'), 'Custody', organisation='Lab')
    try:
        evidence_id = case.add_evidence(str(image), 'Disk', {
            'exhibit_number': 'JW-01', 'description': 'Laptop HDD',
            'acquired_by': '', 'acquired_on': None, 'bogus': 'x'})
        row = case.evidence()[0]
        assert (row['exhibit_number'], row['description']) == \
            ('JW-01', 'Laptop HDD')
        assert row['acquired_by'] is None and row['acquired_on'] is None
        assert case.organisation == 'Lab'

        case.update_evidence_details(evidence_id, exhibit_number='JW-02',
                                     acquired_by='A. Examiner')
        lines = [(a['action'], a['detail']) for a in case.activity()]
        assert any(action == 'evidence added' and 'exhibit number JW-01'
                   in detail for action, detail in lines)
        assert any(action == 'evidence details edited' and
                   'JW-01 -> JW-02' in detail for action, detail in lines)
        with pytest.raises(ValueError):
            case.update_evidence_details(evidence_id, path='elsewhere')
    finally:
        case.close()


def test_a_v15_case_gains_the_custody_columns(tmp_path):
    from trace_app.core.case import EVIDENCE_DETAILS, SCHEMA_VERSION, Case
    folder = str(tmp_path / 'old')
    case = Case.create(folder, 'Old')
    case.close()
    db = sqlite3.connect(os.path.join(folder, 'case.db'))
    for column in EVIDENCE_DETAILS:
        db.execute(f"ALTER TABLE evidence DROP COLUMN {column}")
    db.execute("UPDATE case_info SET value = '15' WHERE key = "
               "'schema_version'")
    db.commit()
    db.close()

    case = Case.open(folder)
    try:
        columns = {row[1] for row in
                   case._db.execute("PRAGMA table_info(evidence)")}
        assert set(EVIDENCE_DETAILS) <= columns
        assert int(case._get('schema_version')) == SCHEMA_VERSION >= 16
    finally:
        case.close()


def test_a_first_hash_is_judged_against_what_the_image_stores():
    from trace_app.core.case import (STATUS_CHANGED, STATUS_UNHASHED,
                                     STATUS_VERIFIED, hash_verdict)
    both = {'computed_md5': 'aa', 'computed_sha1': 'bb',
            'stored_md5': 'AA', 'stored_sha1': 'BB'}
    assert hash_verdict(both)[0] == STATUS_VERIFIED
    # One stored hash differing is not "verified", whatever the other says.
    status, detail = hash_verdict(dict(both, stored_sha1='cc'))
    assert status == STATUS_CHANGED and 'SHA1 is bb' in detail
    status, detail = hash_verdict({'computed_md5': 'aa'})
    assert status == STATUS_VERIFIED and 'baseline' in detail
    assert hash_verdict({'computed_md5': 'Error', 'error': 'x'})[0] == \
        STATUS_UNHASHED


def test_case_folder_names_are_valid_everywhere():
    from trace_app.core.case import case_folder_name
    assert case_folder_name('Operation Nightingale') == 'Operation Nightingale'
    assert case_folder_name('A/B: "x"?') == 'A_B_ _x__'
    assert case_folder_name('trailing. ') == 'trailing'
    assert case_folder_name('CON') == '_CON'
    assert case_folder_name('   ') == 'Case'


# --- the module selector ----------------------------------------------------------------

def test_profiles_tick_what_can_run_and_editing_makes_custom(qapp):
    from trace_app.core.analysis import MODULES
    from trace_app.ui.dialogs.analysis_modules import (
        CUSTOM, FULL, MODULE_CARVE, MODULE_ENTROPY, MODULE_YARA, QUICK,
        STANDARD, ModuleSelector, default_choice)
    selector = ModuleSelector(unavailable={MODULE_YARA: 'No YARA rules'})
    selector.apply_profile(FULL)
    assert selector.profile() == FULL
    assert selector.boxes[MODULE_CARVE].isChecked()
    assert not selector.boxes[MODULE_YARA].isChecked()      # cannot run
    assert not selector.boxes[MODULE_YARA].isEnabled()
    choice = selector.choice()
    assert choice['carve_types'] and choice['yara'] is False
    assert 'carving reads unallocated space' in selector.summary_text()

    selector.apply_profile(QUICK)
    assert 'reads only what each module needs' in selector.summary_text()
    selector.boxes[MODULE_ENTROPY].setChecked(True)
    assert selector.profile() == CUSTOM
    selector.boxes[MODULE_ENTROPY].setChecked(False)
    assert selector.profile() == QUICK              # back to exactly Quick

    selector.set_choice(default_choice(MODULES))
    assert selector.profile() == CUSTOM
    selector.apply_profile(STANDARD)
    assert not selector.choice()['carve_types']
    selector.deleteLater()


# --- the New Case wizard ------------------------------------------------------------------

def _wizard_details(wizard, folder, name='Nightingale'):
    page = wizard.details_page
    page.name_input.setText(name)
    page.number_input.setText('2026-014')
    page.examiner_input.setText('A. Examiner')
    page.folder_input.setText(folder)


@pytest.mark.images
def test_the_new_case_wizard_creates_the_case_it_shows(qapp, tmp_path,
                                                       quiet_dialogs):
    from trace_app.core import evidence_probe
    from trace_app.ui.dialogs.analysis_modules import QUICK
    from trace_app.ui.dialogs.case_wizard import CaseWizard
    junk = tmp_path / 'junk.txt'
    junk.write_text('not evidence')
    wizard = CaseWizard()
    try:
        assert wizard.index == 0 and not wizard.next_button.isEnabled()
        _wizard_details(wizard, str(tmp_path / 'Cases'))
        assert wizard.next_button.isEnabled()
        target = wizard.details_page.target_folder()
        assert target == os.path.join(str(tmp_path / 'Cases'), 'Nightingale')
        wizard.next()

        intake = wizard.evidence_page.intake
        intake.add_paths([image_path(E01), str(junk), image_path(E01)])
        assert 'already listed' in intake.message.text()
        assert wizard.evidence_page.problem().startswith('Checking')
        assert pump(qapp, 30, lambda: not intake.pending())
        assert len(intake.unreadable()) == 1 and len(intake.usable()) == 1
        # The header filled what it records; the examiner adds the rest.
        intake.table.selectRow(0)
        assert intake.fields['acquired_on'].text() == \
            'Fri Feb 22 10:54:32 2013'
        assert intake.field_hints['acquired_on'].text() == 'from image header'
        intake.fields['exhibit_number'].setText('JW-01')
        intake.fields['exhibit_number'].textEdited.emit('JW-01')
        assert intake.table.item(0, 5).text() == 'JW-01'
        assert wizard.next_button.isEnabled()
        wizard.next()

        wizard.modules_page.selector.apply_profile(QUICK)
        wizard.next()
        html = wizard.review_page.browser.toHtml()
        assert 'Nightingale' in html and 'JW-01' in html
        assert 'not added' in html                     # the junk file
        assert wizard.next_button.text() == 'Create Case'
        assert not os.path.exists(target)              # nothing written yet
        wizard.next()

        case, setup = wizard.case, wizard.setup
        assert case is not None and os.path.isfile(os.path.join(target,
                                                                'case.db'))
        try:
            rows = case.evidence()
            assert [r['path'] for r in rows] == [
                os.path.normpath(os.path.abspath(image_path(E01)))]
            assert rows[0]['exhibit_number'] == 'JW-01'
            assert rows[0]['acquired_on'] == 'Fri Feb 22 10:54:32 2013'
            assert setup['verify'] is True
            assert setup['choice']['profile'] == QUICK
            assert setup['choice']['activity'] and \
                not setup['choice']['index']
            actions = [a['action'] for a in case.activity()]
            assert 'case created' in actions and 'case set up' in actions
        finally:
            case.close()
        assert evidence_probe.OK                       # module imported
    finally:
        wizard.deleteLater()


def test_cancel_writes_nothing(qapp, tmp_path, quiet_dialogs):
    from trace_app.ui.dialogs.case_wizard import CaseWizard
    wizard = CaseWizard()
    _wizard_details(wizard, str(tmp_path / 'Cases'))
    target = wizard.details_page.target_folder()
    wizard.reject()
    assert not os.path.exists(tmp_path / 'Cases')
    assert wizard.case is None and not os.path.exists(target)
    wizard.deleteLater()


def test_a_case_that_cannot_be_created_leaves_no_folder(qapp, tmp_path,
                                                        quiet_dialogs,
                                                        monkeypatch):
    from trace_app.core.case import Case
    from trace_app.ui.dialogs.case_wizard import CaseWizard
    wizard = CaseWizard()
    _wizard_details(wizard, str(tmp_path / 'Cases'))
    target = wizard.details_page.target_folder()

    def broken(self, *args, **kwargs):
        raise RuntimeError('disk full')
    monkeypatch.setattr(Case, 'record_event', broken)
    wizard.go_to(3)
    wizard.next()
    assert wizard.case is None and wizard.isVisible() is False
    assert not os.path.exists(target)
    assert 'disk full' in wizard.review_page.error.text()
    wizard.deleteLater()


def test_the_details_page_refuses_what_would_not_work(qapp, tmp_path):
    from trace_app.core.case import Case
    from trace_app.ui.dialogs.case_wizard import CaseWizard
    Case.create(str(tmp_path / 'Taken'), 'Taken').close()
    wizard = CaseWizard()
    page = wizard.details_page
    _wizard_details(wizard, str(tmp_path), name='Taken')
    assert 'already kept there' in page.problem()
    page.name_input.setText('Fresh')
    page.examiner_input.setText('')
    assert 'examiner' in page.problem()
    page.examiner_input.setText('A. Examiner')
    page.folder_input.setText('relative/path')
    assert 'full path' in page.problem()
    page.folder_input.setText(str(tmp_path))
    page.zone_combo.setEditText('Mars/Olympus')
    assert 'time zone' in page.problem()
    page.zone_combo.setEditText('Europe/Sofia')
    assert page.problem() == '' and page.values()['display_zone'] == \
        'Europe/Sofia'
    wizard.deleteLater()


# --- the welcome screen ------------------------------------------------------------------

def test_the_welcome_screen_lists_cases_without_touching_them(qapp, tmp_path):
    from trace_app.core.case import Case
    from trace_app.infra.paths import read_recent_cases, remember_case
    from trace_app.ui.dialogs.case_launcher import CaseLauncher
    folder = str(tmp_path / 'Listed')
    case = Case.create(folder, 'Listed', number='N-7', examiner='Ex')
    image = tmp_path / 'disk.dd'
    image.write_bytes(b'\0' * 512)
    case.add_evidence(str(image))
    case.close()
    remember_case(folder, 'Listed')
    gone = str(tmp_path / 'Unplugged')
    remember_case(gone, 'Unplugged')            # folder never existed

    before = (sorted(os.listdir(folder)),
              os.path.getmtime(os.path.join(folder, 'case.db')))
    launcher = CaseLauncher()
    try:
        texts = {launcher.table.item(r, 0).text(): r
                 for r in range(launcher.table.rowCount())}
        listed = texts['Listed']
        assert launcher.table.item(listed, 1).text() == 'N-7'
        assert launcher.table.item(listed, 2).text() == 'Ex'
        assert launcher.table.item(listed, 3).text() == '1'
        missing = texts['Unplugged']
        assert launcher.table.item(missing, 4).text() == 'Folder not found'
        launcher.table.selectRow(missing)
        assert not launcher.open_button.isEnabled()
        assert launcher.remove_button.isEnabled()
        assert 'connect its drive' in launcher.path_label.text()
        # Read without opening: no audit line, no -wal / -shm, same mtime.
        assert (sorted(os.listdir(folder)),
                os.path.getmtime(os.path.join(folder, 'case.db'))) == before

        launcher._forget_selected()
        names = [e['name'] for e in read_recent_cases(include_missing=True)]
        assert 'Unplugged' not in names and 'Listed' in names
        rows = range(launcher.table.rowCount())
        launcher.filter_input.setText('nothing like it')
        assert all(launcher.table.isRowHidden(r) for r in rows)
        launcher.filter_input.setText('n-7')
        assert [launcher.table.item(r, 0).text() for r in rows
                if not launcher.table.isRowHidden(r)] == ['Listed']
    finally:
        launcher.deleteLater()


def test_a_missing_folder_is_kept_when_another_case_is_remembered(tmp_path):
    from trace_app.infra.paths import read_recent_cases, remember_case
    gone = str(tmp_path / 'Unplugged')
    remember_case(gone, 'Unplugged')
    remember_case(str(tmp_path), 'Here')
    entries = read_recent_cases(include_missing=True)
    assert [e['name'] for e in entries][:2] == ['Here', 'Unplugged']
    assert entries[1]['missing'] is True
    assert 'Unplugged' not in [e['name'] for e in read_recent_cases()]


# --- verification as a job ------------------------------------------------------------------

@pytest.mark.images
@pytest.mark.ui
def test_verification_is_a_job_that_records_and_catches_a_change(
        qapp, tmp_path, quiet_dialogs):
    from trace_app.core.case import (STATUS_CHANGED, STATUS_VERIFIED, Case)
    from trace_app.ui.main_window import MainWindow
    copy = tmp_path / 'copy.dd'
    shutil.copyfile(image_path(RAW), copy)
    folder = str(tmp_path / 'Verify')
    case = Case.create(folder, 'Verify')
    case.add_evidence(str(copy))
    case.add_evidence(image_path(E01))
    window = MainWindow(case=case)
    try:
        assert pump(qapp, 60, lambda: len(window.evidence_files) == 2)
        window.start_case_setup({'verify': True, 'choice': None})
        assert pump(qapp, 120, lambda: not window.job_bar.busy and all(
            r['last_status'] == STATUS_VERIFIED for r in case.evidence()))
        e01 = next(r for r in case.evidence() if r['path'].endswith('E01'))
        assert e01['md5'] == e01['stored_md5']
        history = case.verifications(e01['id'])
        # ntfs1-gen2.E01 stores an MD5 only.
        assert history[0]['detail'] == \
            'MD5 matches the hash stored in the image.'

        # The examiner's copy changes: the next check says so, loudly.
        with open(copy, 'r+b') as handle:
            handle.seek(4096)
            handle.write(b'\xff')
        quiet_dialogs.clear()
        window.verify_case_evidence()
        assert pump(qapp, 120, lambda: not window.job_bar.busy and
                    any(r['last_status'] == STATUS_CHANGED
                        for r in case.evidence()))
        pump(qapp, 0.3)
        assert any(kind == 'warning' and 'does not match' in args[1]
                   for kind, args in quiet_dialogs)
    finally:
        window.cleanup_resources()
        case.close()


def test_a_side_job_runs_beside_the_queue(qapp):
    """Verification's lane: a side job starts while the main lane is busy,
    reports and finishes on its own, and the bar hides (all_finished) only
    once both lanes are empty."""
    from trace_app.ui.widgets.job_bar import SIDE, Job, JobBar
    bar = JobBar()
    started, finished = [], []
    bar.all_finished.connect(lambda: finished.append(True))

    def job(key):
        return Job(key, f"Job {key}", lambda j: started.append(j.key) or j)
    main, side = job('analysis'), job('verify')
    assert bar.submit(main)
    assert bar.submit(side, lane=SIDE)
    assert started == ['analysis', 'verify']           # both running
    assert not bar.submit(job('verify'), lane=SIDE)    # no duplicate
    bar.report(5, 10, 'half', job=side)
    assert bar.side_progress.value() == 5 and 'half' in bar.side_label.text()
    assert bar.progress.maximum() == 0                 # main untouched
    bar.job_finished(side)
    assert bar.busy and bar.main_busy and not finished
    assert not bar.side_label.isVisibleTo(bar)
    bar.job_finished()                                  # the main lane's
    assert not bar.busy and finished == [True]
    bar.deleteLater()


def test_verification_order_follows_the_setting(qapp, monkeypatch):
    """after analysis: queued behind the modules in the main lane;
    alongside: its own lane."""
    from trace_app.core import settings
    from trace_app.ui.main_window import MainWindow
    calls = []
    fake = type('W', (), {})()
    fake.queue_verification = lambda rows: calls.append('verify')
    fake.queue_choice = lambda rows, choice: calls.append('modules')
    fake.set_status = lambda *a: None
    for order, expected in (('after analysis', ['modules', 'verify']),
                            ('before analysis', ['verify', 'modules']),
                            ('alongside analysis', ['verify', 'modules'])):
        calls.clear()
        monkeypatch.setattr(settings, 'user', lambda key, o=order: o)
        MainWindow.queue_setup(fake, [{}], {'verify': True,
                                            'choice': {'modules': []}})
        assert calls == expected, order

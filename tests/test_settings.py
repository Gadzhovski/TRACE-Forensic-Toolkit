"""Options > Settings (core/settings.py, ui/dialogs/settings.py).

User settings round-trip through the sandboxed config.ini; case settings
are kept in the case, audited, applied to the modules that use them -- in
this process and in a background job's, which reads them without writing
to the case -- and stated in the report.
"""

import os

import pytest
from PySide6.QtWidgets import QDialog

from tests.conftest import close_window, image_path, pump


@pytest.fixture(autouse=True)
def defaults_afterwards():
    """Settings are module state: every test leaves the defaults."""
    from trace_app.core import settings
    yield
    settings.apply_case(None)
    settings.apply_user({key: spec[0] for key, spec in settings.USER.items()})


@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Settings case')
    yield case
    case.close()


# --- user settings ----------------------------------------------------------------

def test_user_settings_round_trip_and_take_effect():
    import logging
    from trace_app.core import settings
    from trace_app.infra import utils

    values = settings.read_user()
    assert values['size_units'] == 'binary' and values['show_deleted'] is True
    values.update(examiner='A. Examiner', size_units='decimal',
                  show_system=False, debug_log=True)
    settings.save_user(values)
    again = settings.read_user()
    assert again['examiner'] == 'A. Examiner'
    assert again['show_system'] is False
    assert settings.user('size_units') == 'decimal'
    assert utils.SIZE_UNITS == 'decimal'
    assert logging.getLogger('TRACE').level == logging.DEBUG


def test_size_units_shown_and_parsed_alike():
    from trace_app.infra import utils
    from trace_app.ui.widgets.listing_views import size_in_bytes
    utils.SIZE_UNITS = 'binary'
    shown = utils.FileSystemUtils.get_readable_size(1536)
    assert shown.endswith('KB') and shown.startswith('1.5')
    assert size_in_bytes(shown) == 1536
    utils.SIZE_UNITS = 'decimal'
    shown = utils.FileSystemUtils.get_readable_size(1500)
    assert shown.endswith('kB') and shown.startswith('1.5')
    assert size_in_bytes(shown) == 1500


# --- case settings ----------------------------------------------------------------

def test_case_settings_are_audited_and_applied(case):
    from trace_app.core import (analysis, archives, content_checks,
                                search_index, settings)

    assert settings.save_case(case, settings.for_case(case)) == {}
    changed = settings.save_case(case, {
        'hash_md5': False, 'max_analysis_mb': 10, 'max_inspect_mb': 3,
        'high_entropy': 7.9, 'archive_depth': 2, 'archive_member_mb': 5,
        'indicators': ['email', 'url'], 'not_a_setting': 1})
    assert set(changed) == {'hash_md5', 'max_analysis_mb', 'max_inspect_mb',
                            'high_entropy', 'archive_depth',
                            'archive_member_mb', 'indicators'}
    audit = [row for row in case.activity(5)
             if row['action'] == 'settings changed']
    assert len(audit) == 1
    assert 'MD5: on -> off' in audit[0]['detail']
    assert 'Largest file analysed (MB): 2048 -> 10' in audit[0]['detail']

    assert analysis.HASH_ALGORITHMS == ('sha1', 'sha256')
    assert analysis.MAX_ANALYSIS_BYTES == 10 * settings.MB
    assert content_checks.MAX_INSPECT_BYTES == 3 * settings.MB
    assert analysis.HIGH_ENTROPY == 7.9
    assert archives.MAX_NESTING == 2
    assert archives.MAX_MEMBER_BYTES == 5 * settings.MB
    assert search_index.ENABLED_INDICATORS == {'email', 'url'}

    # No case: the defaults again.
    settings.apply_case(None)
    assert analysis.HASH_ALGORITHMS == ('md5', 'sha1', 'sha256')
    assert search_index.ENABLED_INDICATORS == set(settings.INDICATORS)


def test_hashes_follow_the_setting(case):
    from trace_app.core import analysis, settings
    settings.save_case(case, {'hash_md5': False, 'hash_sha1': False})
    result = analysis.analyse_bytes('a.bin', b'x' * 5000,
                                    [analysis.MODULE_HASH])
    assert result.get('sha256')
    assert not result.get('md5') and not result.get('sha1')


def test_a_job_reads_settings_without_writing_to_the_case(case):
    from trace_app.core import analysis, settings
    settings.save_case(case, {'max_analysis_mb': 7,
                              'export_folder': ''})
    before = len(case.activity(100))
    settings.apply_case(None)

    stored = settings.StoredCase(case.folder)
    assert stored.name == 'Settings case'
    assert stored.exports_dir == os.path.join(case.folder, 'exports')
    settings.apply_case(stored)
    assert analysis.MAX_ANALYSIS_BYTES == 7 * settings.MB
    assert len(case.activity(100)) == before

    from trace_app.core.background import _apply_settings
    settings.apply_case(None)
    _apply_settings({'case_folder': case.folder})
    assert analysis.MAX_ANALYSIS_BYTES == 7 * settings.MB
    assert len(case.activity(100)) == before


def test_indicator_kinds_can_be_turned_off(tmp_path):
    from trace_app.core import search_index
    index = search_index.SearchIndex(str(tmp_path))
    text = "mail bob@example.com or call +44 20 7946 0958 at 10.1.2.3"
    try:
        search_index.ENABLED_INDICATORS = frozenset({'email'})
        item = index.add_item(1, 'p0:i5:s1', 'file', 'a.txt', '/a.txt',
                              body=text)
        index.commit()
        kinds = {row[0] for row in index._db.execute(
            "SELECT kind FROM entities WHERE item_id = ?", (item,))}
        assert kinds == {'email'}
    finally:
        index.close()


def test_chosen_folders(case, tmp_path):
    from trace_app.core import settings
    elsewhere = tmp_path / 'big drive'
    elsewhere.mkdir()
    assert case.exports_dir == os.path.join(case.folder, 'exports')
    settings.save_case(case, {'export_folder': str(elsewhere),
                              'carved_folder': str(elsewhere)})
    assert case.exports_dir == os.path.join(str(elsewhere), 'Settings_case')
    assert os.path.isdir(case.exports_dir)
    assert case.carved_dir.startswith(str(elsewhere))
    assert settings.export_dir() == case.exports_dir
    settings.apply_case(None)
    assert settings.export_dir() == ''


def test_network_refusal(case):
    from trace_app.core import settings
    assert settings.network_refusal() is None
    assert settings.network_refusal('upload') is None
    settings.save_case(case, {'vt_uploads': False})
    assert settings.network_refusal() is None
    assert 'Uploads are turned off' in settings.network_refusal('upload')
    settings.save_case(case, {'offline': True})
    assert 'offline' in settings.network_refusal()
    assert 'offline' in settings.network_refusal('upload')


def test_time_shown_alongside_utc(case):
    from trace_app.core import settings
    assert settings.alongside('2026-07-04 23:07:58') == '2026-07-04 23:07:58'
    settings.save_case(case, {'display_zone': 'Europe/Sofia'})
    # Summer (EEST, +3) and winter (EET, +2): the zone's rules, not a fixed
    # offset.
    assert settings.alongside('2026-07-04 23:07:58 UTC') == \
        '2026-07-04 23:07:58 UTC  ·  2026-07-05 02:07:58 EEST'
    assert settings.alongside('2026-01-04 23:07:58') == \
        '2026-01-04 23:07:58 UTC  ·  2026-01-05 01:07:58 EET'
    assert settings.alongside('2026-01-04T23:07:58+00:00').endswith(
        '2026-01-05 01:07:58 EET')
    # No zone recorded: never converted.
    local = '2006-03-01 10:00:00 (local, no zone)'
    assert settings.alongside(local) == local
    assert settings.alongside('') == '' and settings.alongside(None) is None
    assert settings.alongside('not a time') == 'not a time'
    assert settings.valid_zone('America/New_York')
    assert not settings.valid_zone('Mars/Olympus_Mons')
    assert 'Europe/Sofia' in settings.zones()


def test_report_states_the_settings(case):
    from trace_app.core import settings
    from trace_app.core.report import _Builder
    settings.save_case(case, {'hash_md5': False, 'offline': True,
                              'display_zone': 'Europe/Sofia'})
    builder = _Builder(case, {}, {}, None, lambda: False)
    html = ''.join(builder.section_methods())
    assert 'Settings that shaped these results' in html
    assert 'File hashes: SHA-256, SHA-1' in html
    assert 'also shown in Europe/Sofia' in html
    assert 'offline -- nothing sent' in html


@pytest.mark.images
def test_carving_minimum_size_and_analysis_switch(case):
    from trace_app.core import settings
    from trace_app.core.carving import CARVABLE_TYPES, carve_evidence
    from trace_app.core.image_handler import ImageHandler

    path = image_path('11-carve-fat.dd')
    evidence = case.add_evidence(path)
    handler = ImageHandler(path)
    try:
        everything = carve_evidence(handler, case, evidence, CARVABLE_TYPES)
        sizes = sorted(row['size'] for row in case.carved_files(evidence))
        threshold_kb = sizes[len(sizes) // 2] // 1024 + 1
        expected = len([s for s in sizes if s >= threshold_kb * 1024])

        settings.save_case(case, {'carve_min_kb': threshold_kb,
                                  'analyse_carves': False})
        kept = carve_evidence(handler, case, evidence, CARVABLE_TYPES)
        assert kept == expected < everything
        run = case.carving_runs(evidence, limit=1)[0]
        assert run['stats']['too_small'] == everything - kept
        assert run['stats']['settings'] == {'min_kb': threshold_kb,
                                            'unaligned_pictures': False,
                                            'analysed': False,
                                            'copies_written': False}
        refs = [row['artifact_ref'] for row in case.carved_files(evidence)]
        analysed = case._db.execute(
            "SELECT COUNT(*) FROM file_analysis WHERE artifact_ref IN (%s)"
            % ','.join('?' * len(refs)), refs).fetchone()[0]
        assert analysed == 0
    finally:
        handler.close_resources()


# --- the dialog and the window -----------------------------------------------------

@pytest.mark.ui
def test_dialog_saves_both_scopes(qapp, case):
    from trace_app.core import settings
    from trace_app.ui.dialogs.settings import SettingsDialog

    dialog = SettingsDialog(case)
    editors = dialog.editors
    editors[('user', 'examiner')][0].setText('Dialog Examiner')
    editors[('case', 'offline')][0].setChecked(True)
    editors[('case', 'max_inspect_mb')][0].setValue(12)
    boxes = editors[('case', 'indicators')][0].boxes
    boxes['phone'].setChecked(False)
    dialog.accept()
    assert dialog.result() == QDialog.Accepted
    assert settings.user('examiner') == 'Dialog Examiner'
    stored = settings.for_case(case)
    assert stored['offline'] is True and stored['max_inspect_mb'] == 12
    assert 'phone' not in stored['indicators']
    assert set(dialog.changed) == {'offline', 'max_inspect_mb', 'indicators'}


@pytest.mark.ui
def test_dialog_refuses_an_unknown_zone(qapp, case, monkeypatch):
    from trace_app.core import settings
    from trace_app.ui.dialogs import message
    from trace_app.ui.dialogs.settings import SettingsDialog
    warned = []
    monkeypatch.setattr(message, 'warning', lambda *a, **k: warned.append(a))
    dialog = SettingsDialog(case)
    dialog.editors[('case', 'display_zone')][0].setText('Nowhere/Atall')
    dialog.accept()
    assert warned and dialog.result() != QDialog.Accepted
    assert settings.for_case(case)['display_zone'] == ''


@pytest.mark.ui
def test_dialog_without_a_case_shows_defaults_read_only(qapp):
    from trace_app.ui.dialogs.settings import SettingsDialog
    dialog = SettingsDialog(None)
    assert not dialog.editors[('case', 'offline')][0].isEnabled()
    assert dialog.editors[('user', 'examiner')][0].isEnabled()
    dialog.accept()                       # saves the user scope only
    assert dialog.changed == {}


@pytest.mark.ui
def test_window_refuses_virustotal_when_offline(qapp, case, monkeypatch):
    from trace_app.core import settings
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    told = []
    monkeypatch.setattr(message, 'information',
                        lambda *a, **k: told.append(a[-1]))
    window = MainWindow(case=case)
    try:
        settings.save_case(case, {'offline': True})
        asked = []
        monkeypatch.setattr(window, 'show_api_keys',
                            lambda: asked.append(True))
        window.vt_submit([{'name': 'a.exe'}], 'lookup')
        assert told and 'offline' in told[-1]
        assert not asked              # refused before anything else
        pump(qapp, 0.1)
    finally:
        close_window(window)


# --- a change reaches what is already read ---------------------------------

def test_which_changes_need_the_evidence_read_again():
    from trace_app.core import settings
    needs = settings.rerun_needed({
        'hash_md5': (False, True), 'hash_sha1': (True, False),
        'max_inspect_mb': (64, 128), 'display_zone': ('', 'Europe/Sofia'),
        'indicators': (['email', 'url'], ['email']),
        'index_unallocated': (False, True), 'high_entropy': (7.5, 7.0)})
    assert needs == {'analysis': ['MD5', 'Content checks read up to (MB)'],
                     'index_free': ['Index text in unallocated space']}
    # A kind added needs the index; a kind removed is hidden at once.
    assert settings.rerun_needed(
        {'indicators': (['email'], ['email', 'phone'])}) == \
        {'index': ['Indicators extracted']}


def test_the_entropy_threshold_regrades_what_is_stored(case):
    from trace_app.core import analysis, settings
    evidence = case.add_evidence(__file__)
    case.add_analysis_batch(evidence, [
        ('p0:i5:s1', 'secret.docx', '/secret.docx', False,
         {'mime': 'application/octet-stream', 'extension': 'docx',
          'entropy': 7.2, 'mismatch': analysis.classify_mismatch(
              'docx', 'application/octet-stream', 7.2)}),
        ('p0:i6:s1', 'photo.jpg', '/photo.jpg', False,
         {'mime': 'image/jpeg', 'extension': 'jpg', 'entropy': 7.9,
          'mismatch': analysis.MISMATCH_NONE})])
    before = {r['name']: r['mismatch'] for r in case._db.execute(
        "SELECT name, mismatch FROM file_analysis")}
    assert before['secret.docx'] == analysis.MISMATCH_BENIGN   # 7.2 < 7.5
    settings.save_case(case, {'high_entropy': 7.0})
    assert case.regrade_mismatches() == 1
    after = {r['name']: r['mismatch'] for r in case._db.execute(
        "SELECT name, mismatch FROM file_analysis")}
    assert after == {'secret.docx': analysis.MISMATCH_NOTABLE,
                     'photo.jpg': analysis.MISMATCH_NONE}
    assert case.regrade_mismatches() == 0
    assert any(a['action'] == 'type mismatches graded again'
               for a in case.activity())


def test_an_indicator_kind_turned_off_is_hidden_at_once(case):
    from trace_app.core import settings
    from trace_app.core.search_index import SearchIndex
    index = SearchIndex(case.folder)
    try:
        index.add_item(1, 'p0:i5:s1', 'file', 'a.txt', '/a.txt',
                       'mail me at someone@example.org or +442071234567')
        index.commit()
        assert {'email', 'phone'} <= set(index.indicator_summary())
        settings.save_case(case, {'indicators': ['email', 'domain']})
        assert 'phone' not in index.indicator_summary()
        assert not [r for r in index.indicators() if r['kind'] == 'phone']
        settings.save_case(case, {'indicators': settings.CASE[
            'indicators'][0]})
        assert 'phone' in index.indicator_summary()
    finally:
        index.close()


def test_the_window_offers_to_read_again_with_each_images_modules(
        qapp, case, monkeypatch):
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    asked = []
    monkeypatch.setattr(message, 'question',
                        lambda *a, **k: asked.append(a) or True)
    evidence = case.add_evidence(__file__)
    case.set_analysis_state(evidence, 'done', modules='magic,entropy,hash')
    window = MainWindow(case=case)
    try:
        queued = []
        monkeypatch.setattr(window, 'queue_analysis',
                            lambda rows, modules: queued.append(
                                ([r['id'] for r in rows], modules)))
        plan = window.offer_rerun_for_settings({'hash_md5': (False, True)})
        assert queued == [([evidence], ['magic', 'entropy', 'hash'])]
        assert 'File analysis on 1 image(s) -- for MD5' in asked[0][3]
        assert plan
        # Nothing read yet, or nothing that needs it: nothing asked.
        asked.clear()
        assert window.offer_rerun_for_settings(
            {'display_zone': ('', 'UTC')}) == {}
        assert window.offer_rerun_for_settings(
            {'index_unallocated': (False, True)}) == {}   # never indexed
        assert not asked
    finally:
        close_window(window)


# --- Results: what is kept and where it shows ----------------------------------

@pytest.mark.ui
def test_the_results_page_reads_back_what_was_ticked(qapp, case):
    from trace_app.core import settings
    from trace_app.core.modules import destinations
    from trace_app.ui.dialogs.settings import PAGES, SettingsDialog
    assert any(page[0] == 'Results' for page in PAGES)
    dialog = SettingsDialog(case)
    assert dialog.show_page_named('Results')
    editors = dialog.editors
    # Every kind ticked is "all" ([]), so kinds added later are kept too.
    kinds, read_kinds = editors[('case', 'activity_categories')]
    assert all(box.isChecked() for box in kinds.boxes.values())
    assert read_kinds() == []
    kinds.boxes['files'].setChecked(False)
    sources, _read = editors[('case', 'timeline_sources')]
    assert not sources.boxes['case'].isChecked()     # the audit trail
    grid, _read = editors[('case', 'module_destinations')]
    assert grid.boxes[('evidence', 'report')].isChecked()
    assert not grid.boxes[('telemetry', 'timeline')].isChecked()
    grid.boxes[('telemetry', 'search')].setChecked(True)
    dialog.accept()
    stored = settings.for_case(case)
    assert 'files' not in stored['activity_categories']
    assert 'programs' in stored['activity_categories']
    assert stored['timeline_sources'] == []           # unchanged
    assert stored['module_destinations']['telemetry'] == ['activity',
                                                          'search']
    assert set(dialog.changed) == {'activity_categories',
                                   'module_destinations'}
    audit = [a for a in case.activity() if a['action'] == 'settings changed']
    assert 'Device telemetry: Activity & Triage, Search' in \
        audit[-1]['detail']
    assert destinations.places('telemetry') == {'activity', 'search'}
    assert any('Device telemetry: Activity & Triage, Search' in line
               for line in settings.statement(stored))


def test_activity_keeps_only_the_kinds_the_case_wants(case, monkeypatch):
    from trace_app.core import activity, settings
    from trace_app.core.activity import record
    from datetime import datetime, timezone
    moment = datetime(2020, 4, 11, tzinfo=timezone.utc)
    records = [record('programs', 'Prefetch', moment, 'Run', 'a.exe'),
               record('files', 'FSEvents', moment, 'Created', '/x'),
               record('files', 'FSEvents', moment, 'Created', '/y')]
    monkeypatch.setattr(activity, 'collect', lambda *a, **k: list(records))
    evidence = case.add_evidence(__file__)
    assert activity.run_evidence(None, case, evidence) == 3
    settings.save_case(case, {'activity_categories': ['programs']})
    assert settings.rerun_needed(
        {'activity_categories': ([], ['programs'])}) == \
        {'activity': ['Activity kept']}
    assert activity.run_evidence(None, case, evidence) == 1
    assert [r['category'] for r in case.user_activity(evidence)] == \
        ['programs']


def test_the_timeline_opens_with_the_cases_choices(case):
    from trace_app.core import settings, timeline
    from trace_app.core.activity import record
    from datetime import datetime, timezone
    evidence = case.add_evidence(__file__)
    moment = datetime(2020, 4, 11, tzinfo=timezone.utc)
    case.add_user_activity(evidence, [
        record('programs', 'Prefetch', moment, 'Run', 'a.exe'),
        record('files', 'FSEvents', moment, 'Created', '/x')])
    case.commit()

    def kinds():
        return sorted(row['kind'] for row in timeline.events_after(
            case._db, timeline.default_filters(), limit=50)
            if row['source'] == 'activity')
    assert kinds() == ['files', 'programs']
    assert 'case' not in timeline.default_filters()['sources']
    settings.save_case(case, {'timeline_activity_categories': ['programs'],
                              'timeline_sources': ['activity', 'case']})
    assert kinds() == ['programs']
    assert timeline.default_filters()['sources'] == ['activity', 'case']
    # The Activity tab still lists every kind.
    assert len(case.user_activity(evidence)) == 2


@pytest.mark.ui
def test_the_window_offers_activity_again_for_kinds_changed(
        qapp, case, monkeypatch):
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    monkeypatch.setattr(message, 'question', lambda *a, **k: True)
    read = case.add_evidence(__file__)
    case.add_evidence(os.path.dirname(__file__))    # never read
    case.set_user_activity_state(read, 'done', records=3)
    window = MainWindow(case=case)
    try:
        queued = []
        monkeypatch.setattr(window, 'queue_activity',
                            lambda rows: queued.append(
                                [r['id'] for r in rows]))
        window.offer_rerun_for_settings(
            {'activity_categories': ([], ['programs'])})
        assert queued == [[read]]
    finally:
        close_window(window)

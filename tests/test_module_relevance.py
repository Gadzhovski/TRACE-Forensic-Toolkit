"""Which modules can find anything in an image (core/evidence_profile.py),
chosen per image in the Analysis Modules dialog, and queued only where
they apply: every module used to run on every image, so the NTFS job read
a Btrfs disk and the dialog offered it as if it might find something."""

import os
import tempfile

import pytest

from tests.conftest import ROOT, image_path, pump

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
BTRFS, NTFS = 'btrfs-subvolume-snapshot.raw', 'ntfs1-gen2.E01'


def _sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    return path


def _profile(path):
    from trace_app.core import evidence_profile
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    try:
        found = evidence_profile.profile(handler)
        return found, evidence_profile.not_applicable(found)
    finally:
        handler.close_resources()


def test_what_each_image_rules_out():
    found, ruled_out = _profile(image_path(BTRFS))
    assert found['filesystems'] == ['Btrfs'] and not found['unreadable']
    assert set(ruled_out) == {'ntfs', 'persistence'}   # deleted: leaves
    assert 'No NTFS volume' in ruled_out['ntfs']

    found, ruled_out = _profile(image_path(NTFS))
    assert found['filesystems'] == ['NTFS']
    assert 'fstimes' in ruled_out and 'ntfs' not in ruled_out

    _found, ruled_out = _profile(_sample('text-and-pictures.ad1'))
    assert 'carve' in ruled_out           # files, no disk space between


def test_a_locked_volume_rules_nothing_out():
    """A locked BitLocker To Go drive opens as its FAT32 decoy: what is
    inside is unknown, so no module is ruled out."""
    found, ruled_out = _profile(_sample('bdetogo.raw'))
    assert found['unreadable'] and ruled_out == {}


def _dialog(qapp):
    from trace_app.core.case import Case  # noqa: F401 (import order)
    from trace_app.ui.dialogs.analysis_modules import (AnalysisModulesDialog,
                                                       default_choice)
    from trace_app.core.analysis import MODULES
    btrfs = {'ntfs': 'No NTFS volume on this image.',
             'deleted': 'Btrfs: not yet.',
             'persistence': 'No installation.'}
    ntfs = {'fstimes': 'Only NTFS.'}
    return AnalysisModulesDialog(
        None, default_choice(MODULES),
        [(1, 'fedora.qcow2', 'GPT · Btrfs · Linux', btrfs),
         (2, 'laptop.E01', 'MBR · NTFS · Windows', ntfs)])


def test_dialog_one_selection_for_all_images(qapp):
    dialog = _dialog(qapp)
    assert dialog.same_box.isChecked()
    # NTFS applies to one of the two: offered, with a note naming the other.
    assert dialog.ntfs_box.isEnabled()
    note = dialog.selector._why['ntfs']
    assert not note.isHidden() and 'fedora.qcow2' in note.text()
    # Untick the NTFS image: NTFS applies to none of those left.
    dialog.evidence_list.item(1).setCheckState(
        __import__('PySide6.QtCore', fromlist=['Qt']).Qt.Unchecked)
    assert not dialog.ntfs_box.isEnabled()
    assert dialog.checked_ids() == [1]


def test_dialog_a_selection_per_image(qapp):
    dialog = _dialog(qapp)
    dialog.same_box.setChecked(False)
    dialog.evidence_list.setCurrentRow(0)           # fedora
    assert not dialog.ntfs_box.isEnabled()
    assert dialog.fstimes_box.isEnabled() and dialog.fstimes_box.isChecked()
    dialog.activity_box.setChecked(False)           # fedora only
    dialog.evidence_list.setCurrentRow(1)           # laptop
    assert dialog.ntfs_box.isEnabled() and dialog.ntfs_box.isChecked()
    assert not dialog.fstimes_box.isEnabled()
    assert dialog.activity_box.isChecked()          # still on here
    dialog._accept()
    per = dialog.choice['per_evidence']
    assert per[1]['activity'] is False and per[2]['activity'] is True
    assert per[1]['ntfs'] is False and per[2]['ntfs'] is True
    assert per[1]['fstimes'] is True and per[2]['fstimes'] is False
    assert dialog.choice['evidence_ids'] is None


def test_the_queue_runs_on_each_image_only_what_applies(qapp):
    """One choice for both images: the NTFS job goes to the NTFS image
    only, the file-system times to the Btrfs one only."""
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    from trace_app.ui.dialogs.analysis_modules import default_choice
    folder = os.path.join(tempfile.mkdtemp(), 'case')
    case = Case.create(folder, 'two systems')
    for name in (BTRFS, NTFS):
        case.add_evidence(image_path(name))
    case.close()
    window = MainWindow(case=Case.open(folder))
    try:
        pump(qapp, 120, lambda: len(window.evidence_files) == 2)
        calls = {}
        for job in ('queue_ntfs', 'queue_fs_times', 'queue_persistence',
                    'queue_deleted', 'queue_activity'):
            setattr(window, job, lambda rows, job=job: calls.setdefault(
                job, []).extend(os.path.basename(r['path']) for r in rows))
        choice = dict(default_choice(), modules=[], index=False,
                      activity=True, ntfs=True, fstimes=True,
                      persistence=True, deleted=True, thumbnails=False)
        window.queue_choice(window.case.evidence(), choice)
        assert calls['queue_ntfs'] == [NTFS]
        assert calls['queue_fs_times'] == [BTRFS]
        assert sorted(calls['queue_deleted']) == sorted([BTRFS, NTFS])
        assert 'queue_persistence' not in calls     # neither has a system
        assert sorted(calls['queue_activity']) == sorted([BTRFS, NTFS])
    finally:
        window.cleanup_resources()

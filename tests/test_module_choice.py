"""Which modules suit the evidence, worked out before a case is made (the
wizard's probe, core/evidence_probe) and for open evidence alike
(core/evidence_profile.not_applicable)."""

import pytest


def _folder(tmp_path, files):
    root = tmp_path / 'evidence'
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return str(root)


def _android(tmp_path, extra=None):
    """A phone extraction as a folder: build.prop and an app's data."""
    files = {'system/build.prop': b'ro.build.version.release=10\n'
                                  b'ro.product.model=Pixel 3\n',
             'data/data/com.whatsapp/databases/msgstore.db': b'x' * 64,
             'data/system/packages.xml': b'<packages/>'}
    files.update(extra or {})
    return _folder(tmp_path, files)


def test_a_phone_folder_is_offered_only_what_can_find_anything(tmp_path):
    from trace_app.core import evidence_probe
    result = evidence_probe.probe(_android(tmp_path))
    reasons = result['not_applicable']
    for key in ('carve', 'index_free', 'ntfs', 'persistence', 'fstimes',
                'sigma', 'thumbnails', 'ileapp', 'dleapp'):
        assert key in reasons, key
    for key in ('activity', 'index', 'aleapp'):
        assert key not in reasons, key
    assert 'copies' in reasons['fstimes']
    assert '.evtx' in reasons['sigma']


def test_files_a_module_reads_keep_it_offered(tmp_path):
    from trace_app.core import evidence_probe
    root = _android(tmp_path, {
        'Logs/Security.evtx': b'ElfFile\x00' + b'\x00' * 64,
        'Users/x/AppData/Local/Microsoft/Windows/Explorer/'
        'thumbcache_256.db': b'CMMM' + b'\x00' * 64})
    reasons = evidence_probe.probe(root)['not_applicable']
    assert 'sigma' not in reasons and 'thumbnails' not in reasons


def test_a_few_pattern_matches_do_not_make_a_phone_a_return_or_a_car():
    from trace_app.core import evidence_profile
    found = {'filesystems': ['Folder'], 'systems': [], 'logical': True,
             'logical_kind': 'folder', 'present': None, 'unreadable': False,
             'tool_systems': ['android'], 'fit': {'rleapp': 6, 'vleapp': 4}}
    reasons = evidence_profile.not_applicable(found)
    assert 'only 6 file(s)' in reasons['rleapp']
    assert 'only 4 file(s)' in reasons['vleapp']
    assert 'aleapp' not in reasons
    # With nothing else found, a single file is enough (a return's zip).
    assert evidence_profile.fit_needed([]) == 1
    assert evidence_profile.fit_needed(['android']) == \
        evidence_profile.MIN_FIT_ON_SYSTEM


@pytest.mark.parametrize('items, reasons, partly', [
    ([('A', {'ntfs': 'No NTFS.'})], {'ntfs': 'No NTFS.'}, {}),
    ([('A', {'ntfs': 'No NTFS.'}), ('B', {'ntfs': 'No NTFS.'})],
     {'ntfs': 'Applies to none of the selected images: No NTFS.'}, {}),
    ([('A', {'ntfs': 'No NTFS.'}), ('B', {})], {},
     {'ntfs': 'Skipped on A (No NTFS)'}),
])
def test_several_images_are_combined(items, reasons, partly):
    from trace_app.ui.dialogs.analysis_modules import combine_not_applicable
    assert combine_not_applicable(items, ['ntfs', 'index']) == \
        (reasons, partly)


def test_the_wizard_greys_out_what_the_evidence_cannot_use(qapp, tmp_path):
    from tests.conftest import pump
    from trace_app.ui.dialogs.case_wizard import EvidencePage, ModulesPage
    evidence = EvidencePage()
    modules = ModulesPage(evidence)
    try:
        evidence.intake.add_paths([_android(tmp_path)])
        import time
        deadline = time.monotonic() + 30
        while evidence.intake.pending() and time.monotonic() < deadline:
            pump(qapp, 0.1)
        modules.enter()
        boxes = modules.selector.boxes
        for key in ('ntfs', 'sigma', 'thumbnails', 'persistence', 'carve',
                    'ileapp'):
            assert not boxes[key].isEnabled(), key
            assert not boxes[key].isChecked(), key
        for key in ('activity', 'index', 'magic'):
            assert boxes[key].isEnabled(), key
    finally:
        evidence.intake.stop()
        modules.deleteLater()
        evidence.deleteLater()

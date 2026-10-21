"""Which LEAPP suits an image (core/evidence_profile.tool_systems,
tool_reason): the one for the system TRACE finds -- and, when TRACE cannot
tell what the evidence is, every one.

Found wrong before: an iPhone extraction laid out by its tool
('filesystem2/mobile/...', iLEAPP's own test data) was nothing, so iLEAPP
was refused; a Linux disk without an os-release was nothing too, so DLEAPP
was refused and RLEAPP / VLEAPP were offered for one stray file each; and a
volume unlocked after opening kept its locked 'nothing found'."""

import os

import pytest

from tools import testdata

ALL = ('ileapp', 'aleapp', 'rleapp', 'vleapp', 'dleapp')


def _folder(tmp_path, files):
    root = tmp_path / 'evidence'
    for path, data in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return str(root)


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return handler


def _allowed(systems):
    from trace_app.core import evidence_profile
    from trace_app.core.modules.spec import TOOLS
    return {tool for tool in ALL
            if evidence_profile.tool_reason(TOOLS[tool], systems) is None}


def _systems(path, fit=None):
    from trace_app.core import evidence_profile
    handler = _handler(path)
    try:
        if fit is not None:
            evidence_profile.set_module_fit(handler, fit)
        return evidence_profile.tool_systems(handler)
    finally:
        handler.close_resources()


IOS_DATA = {
    # The data partition under the extraction tool's own folder.
    'filesystem2/mobile/Library/SMS/sms.db': b'SQLite format 3\x00' + b'\0' * 84,
    'filesystem2/mobile/Library/SMS/Attachments/22/02/IMG_0028.JPG':
        b'\xff\xd8\xff' + b'\0' * 64}
ANDROID_DATA = {
    'Dump/data/data/com.android.providers.telephony/databases/mmssms.db':
        b'SQLite format 3\x00' + b'\0' * 84}
LINUX_ROOT = {
    # A live USB's overlay: the system's folders, no os-release.
    'etc/hostname': b'ubuntu\n',
    'home/user/.bash_history': b'ls\n',
    'var/log/syslog': b'Oct 21 10:00:00 ubuntu kernel: boot\n'}


def test_an_iphone_extraction_under_a_tool_folder_is_ios(tmp_path):
    systems = _systems(_folder(tmp_path, IOS_DATA))
    assert systems == ['ios']
    assert _allowed(systems) == {'ileapp'}


def test_an_android_extraction_under_a_tool_folder_is_android(tmp_path):
    systems = _systems(_folder(tmp_path, ANDROID_DATA))
    assert systems == ['android']
    assert _allowed(systems) == {'aleapp'}


def test_a_folder_holding_both_phones_is_offered_both(tmp_path):
    systems = _systems(_folder(tmp_path, {**IOS_DATA, **ANDROID_DATA}))
    assert set(systems) == {'ios', 'android'}
    assert _allowed(systems) == {'ileapp', 'aleapp'}


def test_a_mac_users_library_is_not_an_iphone(tmp_path):
    systems = _systems(_folder(tmp_path, {
        'Users/mobile/Library/SMS/sms.db': b'x',
        'Users/mobile/Library/Preferences/com.apple.dock.plist': b'x'}))
    assert 'ios' not in systems


def test_linux_without_an_os_release_is_linux_and_stray_files_do_not_win(
        tmp_path):
    """One file each that RLEAPP's and VLEAPP's patterns name (as GNOME
    Fedora's fwupd devices.json is VLEAPP's) is that system's own."""
    systems = _systems(_folder(tmp_path, LINUX_ROOT),
                       fit={'rleapp': 1, 'vleapp': 1})
    assert systems == ['linux']
    assert _allowed(systems) == {'dleapp'}


def test_enough_files_still_add_a_pattern_tool_to_a_known_system(tmp_path):
    from trace_app.core import evidence_profile
    systems = _systems(_folder(tmp_path, LINUX_ROOT), fit={
        'vleapp': evidence_profile.MIN_FIT_ON_SYSTEM})
    assert _allowed(systems) == {'dleapp', 'vleapp'}


DOCUMENTS = {'Documents/report.docx': b'PK\x03\x04' + b'\0' * 64,
             'Pictures/beach.jpg': b'\xff\xd8\xff' + b'\0' * 64}


@pytest.mark.parametrize('fit', [
    None,                               # not counted (a disk image)
    {'rleapp': 0, 'vleapp': 0},         # nothing its patterns name
    {'rleapp': 1, 'vleapp': 1},         # a stray file each: no answer
])
def test_evidence_trace_cannot_tell_is_offered_every_tool(tmp_path, fit):
    from trace_app.core import evidence_profile
    systems = _systems(_folder(tmp_path, DOCUMENTS), fit=fit)
    assert evidence_profile.UNKNOWN in systems
    assert _allowed(systems) == set(ALL)
    found = {'filesystems': ['Folder'], 'systems': [], 'logical': True,
             'logical_kind': 'folder', 'present': None, 'unreadable': False,
             'tool_systems': systems, 'fit': fit}
    reasons = evidence_profile.not_applicable(found)
    assert not set(ALL) & set(reasons)


@pytest.mark.parametrize('tool, kind', [('rleapp', 'return'),
                                        ('vleapp', 'vehicle')])
def test_a_return_or_a_cars_export_alone_is_decided(tmp_path, tool, kind):
    """No system, and one pattern-fitted tool's files (a return's zip held
    2 on RLEAPP's Synchronoss fixture): that tool, as before."""
    systems = _systems(_folder(tmp_path, DOCUMENTS), fit={tool: 2})
    assert systems == [kind]
    assert _allowed(systems) == {tool}


def test_not_worked_out_yet_is_unknown(tmp_path):
    """The window's thread never reads (read=False): before the image's
    opening has worked it out, nothing is ruled out."""
    from trace_app.core import evidence_profile
    handler = _handler(_folder(tmp_path, LINUX_ROOT))
    try:
        assert evidence_profile.tool_systems(handler, read=False) == \
            [evidence_profile.UNKNOWN]
        assert evidence_profile.tool_systems(handler) == ['linux']
        assert evidence_profile.tool_systems(handler, read=False) == \
            ['linux']
    finally:
        handler.close_resources()


def test_unlocking_forgets_what_was_concluded_while_locked():
    from trace_app.core import evidence_profile
    path = os.path.join(testdata.SAMPLES, 'luks1.raw')
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail("luks1.raw is missing")
        pytest.skip("luks1.raw is missing -- python -m tools.testdata.fetch "
                    "--group samples")
    handler = _handler(path)
    try:
        locked = evidence_profile.tool_systems(handler)
        assert evidence_profile.UNKNOWN in locked
        assert evidence_profile.has_unread_volume(handler)
        assert handler.unlock_volume(0, 'luks', password='luksde-TEST')
        assert '_tool_systems' not in handler.__dict__
        assert '_os_identity_cache' not in handler.__dict__
        assert not evidence_profile.has_unread_volume(handler)
    finally:
        handler.close_resources()


def test_a_reset_drops_every_conclusion(tmp_path):
    from trace_app.core import evidence_profile, os_identity
    handler = _handler(_folder(tmp_path, LINUX_ROOT))
    try:
        os_identity.identify(handler, 0)
        evidence_profile.tool_systems(handler)
        handler._os_info_cache[0] = {'Operating System': 'stale'}
        handler._forget_filesystem(0)
        assert '_tool_systems' not in handler.__dict__
        assert os_identity.cached(handler, 0) is None
        assert 0 not in handler._os_info_cache
    finally:
        handler.close_resources()


def test_the_modules_tab_offers_every_tool_when_it_cannot_tell(qapp):
    from trace_app.core import evidence_profile
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.viewers.modules_panel import ModulesPanel
    panel = ModulesPanel()
    try:
        tools = [(tool, TOOLS[tool].name, TOOLS[tool].suits) for tool in ALL]

        def offered(systems):
            panel.set_targets([(1, 'Evidence', systems)], tools)
            return [panel.tool_combo.itemData(i)
                    for i in range(panel.tool_combo.count())]

        assert offered(['ios']) == ['ileapp']
        assert offered(['linux']) == ['dleapp']
        everything = offered([evidence_profile.UNKNOWN, 'return'])
        assert set(everything) == set(ALL)
        assert everything[0] == 'rleapp'        # what was found, first
        assert 'could not tell' in panel.tool_combo.toolTip()
    finally:
        panel.deleteLater()

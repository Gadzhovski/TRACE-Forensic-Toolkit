"""Which operating system a volume holds (core/os_identity), and the logo
shown for it. The release files are written as each system writes them;
the folders are opened as folder evidence, so the real readers -- links
followed, system roots found -- are what is tested."""

import os

import pytest

from trace_app.core import os_identity


def test_windows_is_named_from_the_registry_and_11_by_its_build():
    # Windows 11 keeps "Windows 10" in ProductName; the build tells.
    eleven = os_identity.from_os_info({
        'Operating System': 'Windows 10 Pro', 'Build': '22631',
        'Release': '23H2'})
    assert eleven == {'family': 'windows', 'logo': 'windows',
                      'name': 'Windows 11 Pro',
                      'detail': '23H2, build 22631'}
    ten = os_identity.from_os_info({'Operating System': 'Windows 10 Pro',
                                    'Build': '19045'})
    assert ten['name'] == 'Windows 10 Pro'
    xp = os_identity.from_os_info({'Operating System': 'Microsoft Windows XP',
                                   'Build': '2600'})
    assert (xp['family'], xp['detail']) == ('windows', 'build 2600')
    assert os_identity.from_os_info({}) is None


@pytest.mark.parametrize('os_id, name, logo', [
    ('ubuntu', 'Ubuntu 24.04.1 LTS', 'ubuntu'),
    ('', 'Kubuntu 24.04 LTS', 'kubuntu'),
    ('fedora', 'Fedora Linux 44 (Workstation Edition)', 'fedora'),
    ('rhel fedora', 'Red Hat Enterprise Linux 9.4 (Plow)', 'redhat'),
    ('kali debian', 'Kali GNU/Linux Rolling', 'kalilinux'),
    ('linuxmint ubuntu', 'Linux Mint 22', 'linuxmint'),
    ('arch', 'Arch Linux', 'archlinux'),
    ('', 'Raspbian GNU/Linux 11 (bullseye)', 'raspberrypi'),
    ('opensuse-tumbleweed opensuse suse', 'openSUSE Tumbleweed', 'opensuse'),
    ('', 'Slackware 15.0', 'linux'),
    # 'arch' inside another word is not Arch Linux.
    ('', 'Searchlight OS 1.0', 'linux'),
])
def test_a_distribution_gets_its_own_logo(os_id, name, logo):
    assert os_identity.distribution(os_id, name) == logo


def _write(root, path, text):
    full = os.path.join(root, *path.split('/'))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)


def _identify(folder):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(str(folder))
    try:
        assert handler.loaded
        return [os_identity.identify(handler, key)
                for key in handler.volume_offsets()]
    finally:
        handler.close_resources()


def test_a_linux_root_is_named_from_os_release(tmp_path):
    root = tmp_path / 'linux'
    _write(str(root), 'usr/lib/os-release',
           'NAME="Fedora Linux"\nVERSION="44 (Workstation Edition)"\n'
           'ID=fedora\nVERSION_ID=44\n'
           'PRETTY_NAME="Fedora Linux 44 (Workstation Edition)"\n')
    _write(str(root), 'etc/hostname', 'fedora\n')
    _write(str(root), 'home/user/notes.txt', 'x')
    found = [f for f in _identify(root) if f]
    assert found == [{'family': 'linux', 'logo': 'fedora',
                      'name': 'Fedora Linux 44 (Workstation Edition)',
                      'detail': ''}]


def test_an_android_system_is_named_from_build_prop(tmp_path):
    root = tmp_path / 'phone'
    _write(str(root), 'system/build.prop',
           '# begin build properties\nro.build.id=UQ1A.240105.004\n'
           'ro.build.version.release=14\n'
           'ro.product.manufacturer=Google\nro.product.model=Pixel 7\n')
    found = [f for f in _identify(root) if f]
    assert found == [{'family': 'android', 'logo': 'android',
                      'name': 'Android 14',
                      'detail': 'Google Pixel 7, build UQ1A.240105.004'}]


def test_a_mac_is_named_from_system_version(tmp_path):
    root = tmp_path / 'mac'
    _write(str(root), 'System/Library/CoreServices/SystemVersion.plist',
           '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">'
           '<dict><key>ProductBuildVersion</key><string>23G93</string>'
           '<key>ProductName</key><string>macOS</string>'
           '<key>ProductVersion</key><string>14.6.1</string></dict>'
           '</plist>\n')
    found = [f for f in _identify(root) if f]
    assert found == [{'family': 'macos', 'logo': 'macos',
                      'name': 'macOS 14.6.1', 'detail': 'build 23G93'}]


def test_a_data_volume_holds_no_system(tmp_path):
    root = tmp_path / 'usb'
    _write(str(root), 'Documents/report.docx', 'x')
    assert not any(_identify(root))


def test_every_logo_is_bundled_and_drawn(qapp):
    from trace_app.infra.paths import resource_path
    from trace_app.ui import icons
    for key in os_identity.LOGOS:
        assert key in icons.OS_LOGOS, key
        assert os.path.exists(resource_path(f'Icons/os/{key}.svg')), key
        assert not icons.os_logo(key).pixmap(16, 16).isNull(), key
    # An unknown key is drawn as Linux's, never as nothing.
    assert not icons.os_logo('plan9').pixmap(16, 16).isNull()


def test_the_systems_found_are_kept_in_the_case_shown_and_reported(
        tmp_path, qapp):
    """Case.set_systems keeps what os_identity found per volume (schema
    20); the Case tab's Evidence table shows it with the system's logo and
    the report's evidence section states it."""
    from trace_app.core.case import Case
    from trace_app.core.report import _Builder
    from trace_app.ui.viewers.case_panel import CasePanel, EVIDENCE_COLUMNS
    image = tmp_path / 'disk.dd'
    image.write_bytes(b'\0' * 4096)
    case = Case.create(str(tmp_path / 'case'), 'Systems')
    try:
        evidence_id = case.add_evidence(str(image))
        windows = {'volume_key': 2048, 'volume': 'Basic data @ 2048',
                   'family': 'windows', 'logo': 'windows',
                   'name': 'Windows 11 Pro', 'detail': '23H2, build 22631'}
        fedora = {'volume_key': 4198400, 'volume': 'Linux @ 4198400',
                  'family': 'linux', 'logo': 'fedora',
                  'name': 'Fedora Linux 44', 'detail': ''}
        assert case.set_systems(evidence_id, [fedora, windows])
        assert not case.set_systems(evidence_id, [windows, fedora])
        kept = case.systems()[evidence_id]
        assert [s['name'] for s in kept] == ['Windows 11 Pro',
                                             'Fedora Linux 44']

        panel = CasePanel()
        panel.set_case(case)
        column = EVIDENCE_COLUMNS.index('Operating system')
        cell = panel.evidence_table.item(0, column)
        assert cell.text() == ('Windows 11 Pro (23H2, build 22631) + '
                               'Fedora Linux 44')
        assert not cell.icon().isNull()
        assert 'Linux @ 4198400: Fedora Linux 44' in cell.toolTip()

        html = _Builder(case, {'sections': ['evidence']}, None, None,
                        None).section_evidence()
        assert 'Operating system' in html
        assert 'Windows 11 Pro (23H2, build 22631) -- Basic data @ 2048' \
            in html

        # Removing the evidence removes what was found on it.
        case.remove_evidence(evidence_id)
        assert case.systems() == {}
    finally:
        case.close()

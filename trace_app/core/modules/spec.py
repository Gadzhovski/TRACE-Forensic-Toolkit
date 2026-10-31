"""What an external tool is, and which download fits this computer (no Qt).

A LEAPP release (from 2026.4.3) carries, for each version:

    {Name}-{version}-windows-{x64|arm64}-portable.zip   program at the root
    {Name}-{version}-macos-{arm64|x64}.dmg              {Name}.app inside
    {Name}-{version}-linux-{x64|arm64}.AppImage         the whole program
    SHA256SUMS.txt

One program per download: without arguments it opens its window, with
arguments it is the command line TRACE uses. On Windows and macOS it needs
the folder it came in; on Linux the AppImage is unpacked
(--appimage-extract) so no FUSE is needed. Before 2026.4.3 the names and
layout were different (a separate GUI program): MIN_VERSION.
"""

import platform
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Secret:
    """A key a tool needs for some of what it reads -- Signal Desktop's
    database key for DLEAPP. Given as a file (`option FILE`): never on the
    command line."""
    id: str
    option: str
    #: What to ask for, in the dialog.
    label: str
    #: Staged files that show it is wanted (fnmatch, any case).
    patterns: tuple


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str                   # as the release names it: 'iLEAPP'
    program: str                # the executable: 'ileapp'
    repo: str
    licence: str
    description: str
    #: The version this TRACE was tested with: offered first.
    tested_version: str
    #: The oldest release laid out as this spec expects.
    min_version: str
    #: The kinds of evidence it reads (evidence_profile.KIND_NAMES): a
    #: system TRACE finds -- iOS, Android, Windows, macOS, Linux -- or a
    #: kind only its own path patterns show ('return', 'vehicle':
    #: core/modules/fit).
    suits: tuple = ()
    #: What it reads, in a reason: 'warrant returns'.
    reads: str = ''
    #: Keys it can be given (Secret).
    secrets: tuple = ()
    homepage: str = ''
    inputs: tuple = ('fs', 'zip', 'tar', 'gz', 'itunes', 'file')
    #: The log the tool writes as it goes, inside its output folder: its
    #: progress, where its piped output arrives late (a frozen Python
    #: buffers a pipe, and ignores PYTHONUNBUFFERED).
    screen_output: tuple = ('_HTML', '_Script_Logs', 'Screen_Output.html')
    extra: dict = field(default_factory=dict)

    @property
    def releases_api(self):
        return f'https://api.github.com/repos/{self.repo}/releases'

    @property
    def releases_page(self):
        return f'https://github.com/{self.repo}/releases'

    def asset_name(self, version, target=None):
        """The download for `target` ((os, arch); this computer when
        None), e.g. 'iLEAPP-2026.4.4-windows-x64-portable.zip'."""
        os_name, arch = target or current_target()
        suffix = {'windows': f'windows-{arch}-portable.zip',
                  'macos': f'macos-{arch}.dmg',
                  'linux': f'linux-{arch}.AppImage'}[os_name]
        return f'{self.name}-{version}-{suffix}'

    def executable(self, install_dir, target=None):
        """The program inside an installed copy."""
        import os
        os_name, _arch = target or current_target()
        if os_name == 'windows':
            return os.path.join(install_dir, f'{self.program}.exe')
        if os_name == 'macos':
            return os.path.join(install_dir, f'{self.name}.app', 'Contents',
                                'MacOS', self.program)
        return os.path.join(install_dir, 'squashfs-root', 'AppRun')


LEAPP_HOME = 'https://leapps.org'

ILEAPP = ToolSpec(
    id='ileapp', name='iLEAPP', program='ileapp', repo='abrignoni/iLEAPP',
    licence='MIT',
    description="iOS Logs, Events, And Plists Parser: iPhone and iPad "
                "extractions and backups -- messages, calls, apps, "
                "locations, media.",
    tested_version='2026.4.5', min_version='2026.4.3', suits=('ios',),
    homepage=LEAPP_HOME)

ALEAPP = ToolSpec(
    id='aleapp', name='ALEAPP', program='aleapp', repo='abrignoni/ALEAPP',
    licence='MIT',
    description="Android Logs, Events, And Protobuf Parser: Android "
                "extractions -- messages, calls, apps, accounts, locations, "
                "media.",
    tested_version='2026.4.4', min_version='2026.4.3', suits=('android',),
    homepage=LEAPP_HOME, inputs=('fs', 'zip', 'tar', 'gz', 'file'))

RLEAPP = ToolSpec(
    id='rleapp', name='RLEAPP', program='rleapp', repo='abrignoni/RLEAPP',
    licence='MIT',
    description="Returns Logs Events And Properties Parser: what providers "
                "hand over for a warrant -- Google, Snapchat, Synchronoss, "
                "Coinbase, Robinhood and more -- as the zips they send.",
    tested_version='2026.4.4', min_version='2026.4.3', suits=('return',),
    reads='warrant returns', homepage=LEAPP_HOME,
    inputs=('fs', 'zip', 'tar', 'gz', 'raw'))

VLEAPP = ToolSpec(
    id='vleapp', name='VLEAPP', program='vleapp', repo='abrignoni/VLEAPP',
    licence='MIT',
    description="Vehicle Logs Events And Properties Parser: infotainment "
                "and telematics extractions -- devices paired, locations, "
                "speeds, odometer. Reads QNX head units' file systems "
                "itself.",
    tested_version='2026.4.4', min_version='2026.4.3', suits=('vehicle',),
    reads='vehicle infotainment extractions', homepage=LEAPP_HOME,
    inputs=('fs', 'zip', 'tar', 'gz', 'file', 'raw', 'iva'))

DLEAPP = ToolSpec(
    id='dleapp', name='DLEAPP', program='dleapp', repo='abrignoni/DLEAPP',
    licence='MIT',
    description="Desktop Logs Events And Protobuf Parser: Windows, macOS "
                "and Linux computers -- system records, logs and the "
                "desktop apps on them, Discord, Wire and Signal among them "
                "(Signal needs its key).",
    tested_version='2026.4.4', min_version='2026.4.3',
    suits=('windows', 'macos', 'linux'),
    reads='Windows, macOS and Linux computers',
    homepage=LEAPP_HOME, inputs=('fs', 'zip', 'tar', 'gz', 'raw'),
    secrets=(
        Secret('signal', '--signal-key',
               "Signal Desktop's key: its Safe Storage credential (macOS "
               "Keychain or Windows Credential Manager, \"Signal Safe "
               "Storage\"), the 64-character database key, or -- for a Mac "
               "whose login keychain is in the evidence -- the account's "
               "login password",
               ('*/signal*/sql/db.sqlite',)),
        Secret('threema', '--threema-password',
               "Threema Desktop's password", ('*/threema.sqlite',))))

TOOLS = {spec.id: spec for spec in (ILEAPP, ALEAPP, RLEAPP, VLEAPP, DLEAPP)}


def current_target():
    """('windows' | 'macos' | 'linux', 'x64' | 'arm64') for this computer.

    The *hardware's* architecture: an Intel build of TRACE running under
    Rosetta reports x86_64, while the arm64 build of a tool runs natively."""
    if sys.platform.startswith('win'):
        os_name = 'windows'
    elif sys.platform == 'darwin':
        os_name = 'macos'
    else:
        os_name = 'linux'
    machine = platform.machine().lower()
    arch = 'arm64' if machine in ('arm64', 'aarch64', 'armv8l') else 'x64'
    if os_name == 'macos' and arch == 'x64' and _apple_silicon():
        arch = 'arm64'
    if os_name == 'windows' and arch == 'x64' and _windows_arm():
        arch = 'arm64'
    return os_name, arch


def _apple_silicon():
    try:
        out = subprocess.run(['sysctl', '-n', 'hw.optional.arm64'],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() == '1'
    except Exception:
        return False


def _windows_arm():
    """An x64 Python under Windows on ARM's emulation still says AMD64;
    the processor architecture of the machine says ARM64."""
    import os
    return 'ARM64' in (os.environ.get('PROCESSOR_IDENTIFIER', '') +
                       os.environ.get('PROCESSOR_ARCHITEW6432', '')).upper()

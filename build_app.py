"""Build TRACE as a standalone application, package it, and prove it works.

    python build_app.py              build, package, self-test the package
    python build_app.py --no-test    build and package only
    python build_app.py --require-images
                                     fail, rather than skip the image checks,
                                     when no public test image is present (CI)

Windows  dist/TRACE-<version>-windows-<arch>.zip   (TRACE\\TRACE.exe inside)
macOS    dist/TRACE-<version>-macos-<arch>.dmg     (TRACE.app inside)

Each artifact gets a .sha256 beside it, so a copy can be checked against what
was built -- the same courtesy TRACE extends to evidence.

The build is TRACE.spec; this script never edits or deletes it. Run it with
the Python of the environment TRACE is installed in (the venv), which must
include PyInstaller (it is in requirements.txt). Everything the tools print
goes to build/build.log; on a terminal one line, rewritten in place, says
what is happening now, as the installers do.

**The package is tested, not the build folder.** It is unpacked (Windows: into
a folder whose name has spaces and a non-ASCII letter, as a user's might) or
mounted read-only (macOS: straight from the DMG, as a user first runs it),
and started with --self-test against the public test images
(trace_app/selftest.py). Every check must pass, and what the packaged app
reads from each image must equal the manifest the test suite verified
(tests/manifests/) -- otherwise the build fails.

A macOS build runs on the architecture it was built on (Apple Silicon or
Intel); the native engines have no universal wheels. Neither build is signed
by a publisher, so Windows SmartScreen and macOS Gatekeeper ask once before
the first launch; the README in each package says how.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, 'dist')
BUILD = os.path.join(ROOT, 'build')
LOG = os.path.join(BUILD, 'build.log')
APP_NAME = 'TRACE'

#: Public images the packaged app is tested on, one per format/file system:
#: E01 + NTFS (compressed, EFS), FAT, exFAT, ext3, HFS+, ISO 9660.
#: `python tools/fetch_test_images.py` downloads them.
TEST_IMAGES = ('ntfs1-gen2.E01', '8-jpeg-search.dd', 'dfr-01-xfat.dd',
               'ext3-img-kw-1.dd', 'image.gen1.dmg', 'iso-endian.iso')


def main():
    parser = argparse.ArgumentParser(
        description="Build, package and self-test TRACE.")
    parser.add_argument('--no-test', action='store_true',
                        help="skip the self-test of the package")
    parser.add_argument('--require-images', action='store_true',
                        help="fail if no public test image is available")
    args = parser.parse_args()

    version = _version()
    arch = _arch()
    ui.banner(f"{_platform_name()} {arch}", version)

    if sys.platform not in ('win32', 'darwin'):
        return ui.fail("Packaging is for Windows and macOS; on Linux run "
                       "TRACE from source (./install.sh).")
    try:
        import PyInstaller
    except ImportError:
        return ui.fail("PyInstaller is not installed in this environment: "
                       "pip install -r requirements.txt")

    for folder in (BUILD, DIST):
        shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(BUILD)
    open(LOG, 'w').close()

    ui.step("Building")
    code = run_quietly("Starting PyInstaller", [
        sys.executable, '-m', 'PyInstaller', os.path.join(ROOT, 'TRACE.spec'),
        '--clean', '--noconfirm', '--distpath', DIST,
        '--workpath', os.path.join(BUILD, 'pyinstaller')], _pyinstaller_status)
    if code != 0:
        ui.log_tail()
        return ui.fail("PyInstaller failed.")
    ui.ok(f"Built with PyInstaller {PyInstaller.__version__}, "
          f"Python {platform.python_version()}")

    ui.step("Packaging")
    if sys.platform == 'win32':
        artifact = _package_windows(version, arch)
    else:
        artifact = _package_macos(version, arch)
    if artifact is None:
        ui.log_tail()
        return ui.fail("Packaging failed.")
    digest = _write_checksum(artifact)
    ui.ok(f"{os.path.relpath(artifact, ROOT)}  ({_size(artifact)})")
    ui.note(f"SHA-256 {digest}", dim=True)

    if args.no_test:
        ui.step("Testing the package")
        ui.warn("Skipped (--no-test)")
        ui.note("Full log: build/build.log", dim=True)
        return 0

    ui.step("Testing the package")
    images = [os.path.join(ROOT, 'test_images', name) for name in TEST_IMAGES
              if os.path.isfile(os.path.join(ROOT, 'test_images', name))]
    if not images:
        message = ("No public test image found; only the image-independent "
                   "checks run. Fetch them: python tools/fetch_test_images.py")
        if args.require_images:
            return ui.fail(message)
        ui.warn(message)
    if not _self_test(artifact, images, arch):
        return ui.fail("The package failed its self-test; it is not fit to "
                       "distribute.")

    ui.note("Full log: build/build.log", dim=True)
    ui.done(f"Built and verified: {os.path.relpath(artifact, ROOT)}")
    return 0


# --- packaging -----------------------------------------------------------------

def _package_windows(version, arch):
    folder = os.path.join(DIST, APP_NAME)
    _write_readme(os.path.join(folder, 'README.txt'), version, 'windows')
    for name in ('LICENSE', 'README.md'):
        shutil.copy2(os.path.join(ROOT, name), folder)

    artifact = os.path.join(DIST, f'{APP_NAME}-{version}-windows-{arch}.zip')
    files = [os.path.join(directory, name)
             for directory, _, names in os.walk(folder) for name in names]
    with Live("Compressing") as live, \
            zipfile.ZipFile(artifact, 'w', zipfile.ZIP_DEFLATED,
                            compresslevel=9) as package:
        for count, path in enumerate(files, 1):
            live.update(f"Compressing {count}/{len(files)}: "
                        f"{os.path.relpath(path, folder)}")
            package.write(path, os.path.relpath(path, DIST))
    return artifact


def _package_macos(version, arch):
    app = os.path.join(DIST, f'{APP_NAME}.app')
    # PyInstaller signs each binary; sealing the bundle as a whole (ad hoc
    # unless a Developer ID was given) is what lets macOS check it.
    identity = os.environ.get('TRACE_CODESIGN_IDENTITY') or '-'
    if run_quietly("Signing TRACE.app",
                   ['codesign', '--force', '--deep', '--sign', identity, app]) \
            or run_quietly("Verifying the signature",
                           ['codesign', '--verify', '--deep', '--strict', app]):
        return None
    ui.ok("Signed" + (" (ad hoc)" if identity == '-' else f" as {identity}"))

    staging = os.path.join(BUILD, 'dmg')
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    # ditto keeps the bundle's symlinks, extended attributes and signature.
    if run_quietly("Staging", ['ditto', app,
                               os.path.join(staging, f'{APP_NAME}.app')]):
        return None
    os.symlink('/Applications', os.path.join(staging, 'Applications'))
    _write_readme(os.path.join(staging, 'README.txt'), version, 'macos')
    shutil.copy2(os.path.join(ROOT, 'LICENSE'),
                 os.path.join(staging, 'LICENSE.txt'))

    artifact = os.path.join(DIST, f'{APP_NAME}-{version}-macos-{arch}.dmg')
    if run_hdiutil("Creating the disk image",
                   ['hdiutil', 'create', '-volname', f'{APP_NAME} {version}',
                    '-srcfolder', staging, '-fs', 'HFS+', '-format', 'UDZO',
                    '-imagekey', 'zlib-level=9', '-ov', artifact]) \
            or run_hdiutil("Verifying the disk image",
                           ['hdiutil', 'verify', artifact]):
        return None
    return artifact


def _write_checksum(artifact):
    digest = hashlib.sha256()
    with open(artifact, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    with open(artifact + '.sha256', 'w', encoding='ascii', newline='\n') as out:
        out.write(f"{digest.hexdigest()}  {os.path.basename(artifact)}\n")
    return digest.hexdigest()


# --- self-test ------------------------------------------------------------------

def _self_test(artifact, images, arch):
    """Unpack or mount the package, run its self-test, check its manifests."""
    report = os.path.join(DIST, f'selftest-{_platform_name().lower()}-{arch}.json')
    scratch = tempfile.mkdtemp(prefix='trace-build-')
    mount = None
    completed = None
    try:
        if sys.platform == 'win32':
            # Where a user might unpack it: a path with spaces and a letter
            # outside ASCII.
            target = os.path.join(scratch, 'TRACE self-test é')
            with Live("Unpacking the zip"), zipfile.ZipFile(artifact) as package:
                package.extractall(target)
            binary = os.path.join(target, APP_NAME, f'{APP_NAME}.exe')
        else:
            mount = os.path.join(scratch, 'volume')
            os.makedirs(mount)
            if run_hdiutil("Mounting the disk image read-only",
                           ['hdiutil', 'attach', '-nobrowse', '-readonly',
                            '-mountpoint', mount, artifact]):
                ui.bad("Could not mount the disk image")
                return False
            binary = os.path.join(mount, f'{APP_NAME}.app', 'Contents',
                                  'MacOS', APP_NAME)
        _log(f"\n$ {binary} --self-test {report} {' '.join(images)}\n")
        names = ', '.join(os.path.basename(i) for i in images) or 'no images'
        with Live(f"Self-test of the packaged app on {names}", timer=True):
            try:
                completed = subprocess.run(
                    [binary, '--self-test', report] + images, timeout=900,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _log(completed.stdout.decode('utf-8', 'replace'))
            except subprocess.TimeoutExpired:
                completed = None
        if completed is None:
            ui.bad("The self-test did not finish within 15 minutes")
            return False
    finally:
        if mount:
            subprocess.run(['hdiutil', 'detach', mount, '-force'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(scratch, ignore_errors=True)

    if not os.path.isfile(report):
        ui.bad(f"The app wrote no report (exit status {completed.returncode})")
        return False
    with open(report, encoding='utf-8') as handle:
        result = json.load(handle)

    # Passing checks are summarised; failures are shown in full.
    checks = result['checks']
    failed = [c for c in checks if not c['ok']]
    passed_checks = len(checks) - len(failed)
    facts = {c['name']: (c['detail'] or '').strip() for c in checks if c['ok']}
    if not failed:
        ui.ok(f"All {len(checks)} checks passed")
    else:
        ui.bad(f"{len(failed)} of {len(checks)} checks failed "
               f"({passed_checks} passed)")
    for name in ('engines', 'libmagic identifies content'):
        if name in facts:
            ui.note(facts[name].split(' from ')[0], dim=True)
    for item in failed:
        ui.bad(item['name'])
        for line in (item['detail'] or '').strip().splitlines()[-10:]:
            ui.note(f"  {line}", dim=True)

    matched, differed = [], []
    for name, manifest in sorted(result.get('manifests', {}).items()):
        expected_path = os.path.join(ROOT, 'tests', 'manifests',
                                     f'{name}.manifest.json')
        if not os.path.isfile(expected_path):
            ui.warn(f"No committed manifest for {name}; not compared")
            continue
        with open(expected_path, encoding='utf-8') as handle:
            (matched if manifest == json.load(handle) else differed).append(name)
    if matched:
        ui.ok(f"Reads {len(matched)} image{'s' if len(matched) != 1 else ''} "
              f"exactly as the test suite verified")
        ui.note(', '.join(matched), dim=True)
    for name in differed:
        ui.bad(f"Reads {name} differently from tests/manifests/")
    ui.note(f"Report: {os.path.relpath(report, ROOT)}", dim=True)

    ok_overall = not failed and not differed
    if completed.returncode != 0 and ok_overall:
        ui.bad(f"Exit status {completed.returncode}")
        ok_overall = False
    return ok_overall


# --- running tools quietly ------------------------------------------------------

def run_quietly(label, command, describe=None):
    """Run `command` with its output in the log, showing progress on one
    line. Returns the exit status."""
    _log(f"\n$ {' '.join(command)}\n")
    with Live(label) as live:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
        except OSError as exc:
            _log(f"{exc}\n")
            return 127
        for raw in process.stdout:
            line = raw.decode('utf-8', 'replace').rstrip()
            _log(line + '\n')
            text = (describe or _generic_status)(line)
            if text:
                live.update(text)
        return process.wait()


def run_hdiutil(label, command, attempts=3):
    """hdiutil, retried: on CI's macOS runners create and attach fail now
    and then with "Resource busy" while the system still holds the staging
    folder or a previous image. Each failure is in the log."""
    status = 1
    for attempt in range(1, attempts + 1):
        status = run_quietly(label if attempt == 1
                             else f"{label} (attempt {attempt})", command)
        if status == 0:
            return 0
        _log(f"hdiutil exited with {status} (attempt {attempt} of "
             f"{attempts})\n")
        if attempt < attempts:
            time.sleep(5 * attempt)
    return status


_PYINSTALLER_LINE = re.compile(r'^\d+ (?:INFO|WARNING): (.*)$')


def _pyinstaller_status(line):
    match = _PYINSTALLER_LINE.match(line)
    if not match:
        return None
    message = match.group(1)
    for pattern, text in (
            (r"Analyzing hidden import '([^']+)'", "Analysing {}"),
            (r"Analyzing (.+)", "Analysing {}"),
            (r"Processing (?:standard |pre-safe-import-|pre-find-module-path )?"
             r"module hook '?hook-([^']+?)\.py", "Running the hook for {}"),
            (r"Building PYZ", "Building the Python archive"),
            (r"Building PKG", "Building the package"),
            (r"Building EXE", "Building the executable"),
            (r"Building COLLECT", "Collecting files"),
            (r"Building BUNDLE", "Building TRACE.app"),
            (r"Signing (.+)", "Signing {}"),
            (r"Looking for dynamic libraries", "Looking for native libraries"),
            (r"Looking for Python shared library", "Finding the Python library"),
            (r"Copying (.+)", "Copying {}")):
        found = re.match(pattern, message)
        if found:
            value = os.path.basename(found.group(1).rstrip('.')) \
                if found.groups() else ''
            return text.format(value)
    return message


def _generic_status(line):
    return line.strip() or None


def _log(text):
    try:
        with open(LOG, 'a', encoding='utf-8') as handle:
            handle.write(text)
    except OSError:
        pass


# --- output ----------------------------------------------------------------------
# Kept identical in look to install.sh and install_windows.ps1: the same logo
# template, colours and symbols, sized to the window, plain where the
# terminal cannot show more.

LOGO = (
    "########]######]  #####]  ######]#######]",
    "{==##[==}##[==##]##[==##]##[====}##[====}",
    "   ##|   ######[}#######|##|     #####]  ",
    "   ##|   ##[==##]##[==##|##|     ##[==}  ",
    "   ##|   ##|  ##|##|  ##|{######]#######]",
    "   {=}   {=}  {=}{=}  {=} {=====}{======}",
)
LOGO_SMALL = (
    "^#^ #^# _^# #^^ #^^",
    " #  #^_ #^# #__ ##_",
)
GLYPHS = str.maketrans({'#': '█', '=': '═', '|': '║',
                        '[': '╔', ']': '╗', '{': '╚',
                        '}': '╝', '^': '▀', '_': '▄'})
GRADIENT = (27, 33, 39, 45, 51, 87)          # blue to cyan, top to bottom


def _enable_vt():
    """Colour codes need virtual-terminal processing on a Windows console."""
    if sys.platform != 'win32':
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class Ui:
    def __init__(self):
        out = sys.stdout
        self.tty = out.isatty()
        encoding = (out.encoding or '').lower().replace('-', '')
        self.unicode = encoding.startswith('utf8')
        self.color = self.tty and not os.environ.get('NO_COLOR') and _enable_vt()
        # The classic Windows console's fonts lack check marks; Windows
        # Terminal and VS Code have them, as do macOS and Linux terminals.
        fancy = self.unicode and (sys.platform != 'win32'
                                  or os.environ.get('WT_SESSION')
                                  or os.environ.get('TERM_PROGRAM') == 'vscode')
        if fancy:
            self.g_step, self.g_ok, self.g_fail = '▸', '✓', '✗'
            self.frames = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        else:
            self.g_step, self.g_ok, self.g_fail = '>', '+', 'x'
            self.frames = '|/-\\'
        self.g_rule = '─' if self.unicode else '-'
        self.g_dot = '·' if self.unicode else '-'

    def paint(self, text, *codes):
        if not self.color or not codes:
            return text
        return f"\033[{';'.join(str(c) for c in codes)}m{text}\033[0m"

    def width(self):
        return shutil.get_terminal_size((80, 24)).columns

    def say(self, text=''):
        print(text, flush=True)

    def banner(self, platform_name, version):
        width = self.width()
        self.say()
        if self.unicode and width >= 56:
            for shade, line in zip(GRADIENT, LOGO):
                self.say('  ' + self.paint(line.translate(GLYPHS), '38;5;%d' % shade))
            self.say()
            self.say('  ' + self.paint(
                'Toolkit for Retrieval and Analysis of Cyber Evidence', 2))
            rule = 52
        elif self.unicode and width >= 24:
            self.say('  ' + self.paint(LOGO_SMALL[0].translate(GLYPHS), '38;5;33'))
            self.say('  ' + self.paint(LOGO_SMALL[1].translate(GLYPHS), '38;5;45'))
            self.say()
            self.say('  ' + self.paint('Forensic Toolkit', 2))
            rule = 26
        else:
            self.say('  ' + self.paint('TRACE', 1, '38;5;39') + ' '
                     + self.paint('Forensic Toolkit', 2))
            rule = 26
        detail = f" {self.g_dot} {platform_name}"
        # The version is dropped where it would wrap the line.
        if width >= 32:
            detail += f" {self.g_dot} v{version}"
        self.say('  ' + self.paint('Builder', '38;5;39') + self.paint(detail, 2))
        rule = min(rule, width - 4)
        if rule > 0:
            self.say('  ' + self.paint(self.g_rule * rule, 2))

    def step(self, text):
        self.say()
        self.say(self.paint(f"{self.g_step} {text}", 1, '38;5;39'))

    def ok(self, text):
        self.say('  ' + self.paint(self.g_ok, '38;5;42') + ' ' + text)

    def warn(self, text):
        self.say('  ' + self.paint(f"! {text}", '38;5;214'))

    def bad(self, text):
        self.say('  ' + self.paint(f"{self.g_fail} {text}", '38;5;203'))

    def note(self, text, dim=False):
        self.say('    ' + (self.paint(text, 2) if dim else text))

    def done(self, text):
        self.say()
        self.say('  ' + self.paint(f"{self.g_ok} {text}", 1, '38;5;42'))
        self.say()

    def fail(self, text):
        self.say()
        self.say('  ' + self.paint(f"{self.g_fail} {text}", 1, '38;5;203'))
        if os.path.isfile(LOG):
            self.note("Full log: build/build.log", dim=True)
        self.say()
        return 1

    def log_tail(self, lines=25):
        try:
            with open(LOG, encoding='utf-8', errors='replace') as handle:
                tail = handle.read().splitlines()[-lines:]
        except OSError:
            return
        self.note("Last lines of build/build.log:")
        for line in tail:
            self.note('  ' + line, dim=True)


class Live:
    """One line, rewritten in place, saying what is happening now.

    Redrawn ten times a second so the spinner moves even while a tool is
    silent; off a terminal (CI) it prints nothing.
    """

    def __init__(self, text, timer=False):
        self.text = text
        self.timer = timer
        self.started = time.monotonic()
        self.frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if ui.tty:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def update(self, text):
        with self._lock:
            self.text = text

    def _run(self):
        while not self._stop.is_set():
            self._draw()
            self._stop.wait(0.1)

    def _draw(self):
        width = max(10, ui.width() - 6)
        with self._lock:
            text = self.text
        elapsed = int(time.monotonic() - self.started)
        if self.timer and elapsed >= 2:
            suffix = f"  {elapsed}s"
            text = text[:max(0, width - len(suffix))] + suffix
        frame = ui.frames[self.frame % len(ui.frames)]
        self.frame += 1
        sys.stdout.write('\r  ' + ui.paint(frame, '38;5;39') + ' '
                         + text[:width].ljust(width))
        sys.stdout.flush()

    def __exit__(self, *exc):
        if self._thread:
            self._stop.set()
            self._thread.join()
            sys.stdout.write('\r' + ' ' * (ui.width() - 1) + '\r')
            sys.stdout.flush()
        return False


# --- helpers ----------------------------------------------------------------------

def _write_readme(path, version, system):
    if system == 'windows':
        first_run = """\
Getting started
  1. Unzip the whole folder somewhere you can write, e.g. Documents.
     Do not run TRACE.exe from inside the zip.
  2. Double-click TRACE\\TRACE.exe.
  3. Windows SmartScreen may say it "protected your PC": TRACE is not
     signed by a publisher. Choose "More info", then "Run anyway".
     Windows asks once."""
        requirements = "Windows 10 or 11, 64-bit"
    else:
        first_run = """\
Getting started
  1. Drag TRACE into the Applications folder.
  2. Open TRACE from Applications.
  3. TRACE is not signed with an Apple Developer ID, so macOS stops the
     first launch. Control-click (right-click) TRACE in Applications, choose
     Open, then Open again. On macOS 15 and later: try to open it once,
     then go to System Settings > Privacy & Security and click
     "Open Anyway". macOS asks once.
  4. When you open a disk image on an external drive, macOS may ask
     whether TRACE may access it: allow it."""
        requirements = (f"macOS {_plist_minimum() or '13'} or later on "
                        f"{'Apple Silicon' if _arch() == 'arm64' else 'Intel'}")

    text = f"""TRACE {version}
Toolkit for Retrieval and Analysis of Cyber Evidence
Website and documentation: https://trace.gadzhovski.com
Source code: https://github.com/Gadzhovski/TRACE-Forensic-Toolkit

{first_run}

Requirements
  {requirements}. No Python or other software is needed.

Your data
  Cases live in the folders you choose. Settings and the log are kept in
  your user profile, never beside the application. Evidence is only ever
  read.

Checking this copy
  The .sha256 file published beside the download holds its SHA-256.
  To check the installed application against a known disk image:
    TRACE --self-test report.json path/to/image.E01
  (on macOS: /Applications/TRACE.app/Contents/MacOS/TRACE --self-test ...)

Licence: MIT (LICENSE). Third-party components keep their own licences.
"""
    with open(path, 'w', encoding='utf-8',
              newline='\r\n' if system == 'windows' else '\n') as handle:
        handle.write(text)


def _plist_minimum():
    try:
        import plistlib
        with open(os.path.join(DIST, f'{APP_NAME}.app', 'Contents',
                               'Info.plist'), 'rb') as handle:
            return plistlib.load(handle).get('LSMinimumSystemVersion')
    except (OSError, ValueError):
        return None


def _version():
    with open(os.path.join(ROOT, 'trace_app', '__init__.py'),
              encoding='utf-8') as handle:
        return re.search(r'^__version__ = "([^"]+)"', handle.read(),
                         re.M).group(1)


def _arch():
    machine = platform.machine().lower()
    return {'amd64': 'x64', 'x86_64': 'x64' if sys.platform == 'win32'
            else 'x86_64', 'aarch64': 'arm64'}.get(machine, machine)


def _platform_name():
    return {'win32': 'Windows', 'darwin': 'macOS'}.get(sys.platform, 'Linux')


def _size(path):
    return f"{os.path.getsize(path) / (1024 * 1024):.0f} MB"


# A path printed from the self-test can hold any character.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        _stream.reconfigure(errors='replace')
ui = Ui()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(ui.fail("Interrupted"))

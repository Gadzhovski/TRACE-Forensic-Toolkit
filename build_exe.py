"""Build TRACE as a standalone application, package it, and prove it works.

    python build_exe.py              build, package, self-test the package
    python build_exe.py --no-test    build and package only
    python build_exe.py --require-images
                                     fail, rather than skip the image checks,
                                     when no public test image is present (CI)

Windows  dist/TRACE-<version>-windows-<arch>.zip   (TRACE\\TRACE.exe inside)
macOS    dist/TRACE-<version>-macos-<arch>.dmg     (TRACE.app inside)

Each artifact gets a .sha256 beside it, so a copy can be checked against what
was built -- the same courtesy TRACE extends to evidence.

The build is TRACE.spec; this script never edits or deletes it. Run it with
the Python of the environment TRACE is installed in (the venv), which must
include PyInstaller (it is in requirements.txt).

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
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, 'dist')
BUILD = os.path.join(ROOT, 'build')
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

    if sys.platform not in ('win32', 'darwin'):
        return fail("Packaging is for Windows and macOS; on Linux run TRACE "
                    "from source (./install.sh).")
    try:
        import PyInstaller
    except ImportError:
        return fail("PyInstaller is not installed in this environment: "
                    "pip install -r requirements.txt")

    version = _version()
    arch = _arch()
    say(f"TRACE {version} for {_platform_name()} {arch}, "
        f"PyInstaller {PyInstaller.__version__}, Python {platform.python_version()}")

    step("Building")
    for folder in (BUILD, DIST):
        shutil.rmtree(folder, ignore_errors=True)
    result = subprocess.run([sys.executable, '-m', 'PyInstaller',
                             os.path.join(ROOT, 'TRACE.spec'),
                             '--clean', '--noconfirm',
                             '--distpath', DIST, '--workpath',
                             os.path.join(BUILD, 'pyinstaller')], cwd=ROOT)
    if result.returncode != 0:
        return fail("PyInstaller failed; see the output above.")

    step("Packaging")
    if sys.platform == 'win32':
        artifact = _package_windows(version, arch)
    else:
        artifact = _package_macos(version, arch)
    digest = _write_checksum(artifact)
    ok(f"{os.path.relpath(artifact, ROOT)}  ({_size(artifact)})")
    ok(f"SHA-256 {digest}")

    if args.no_test:
        say("\nSelf-test skipped (--no-test).")
        return 0

    step("Testing the package")
    images = [os.path.join(ROOT, 'test_images', name) for name in TEST_IMAGES
              if os.path.isfile(os.path.join(ROOT, 'test_images', name))]
    if not images:
        message = ("No public test image found; only the image-independent "
                   "checks run. Fetch them: python tools/fetch_test_images.py")
        if args.require_images:
            return fail(message)
        warn(message)
    if not _self_test(artifact, images, arch):
        return fail(f"The package failed its self-test; it is not fit to "
                    f"distribute. The report is in {os.path.relpath(DIST, ROOT)}.")

    say(f"\nBuilt and verified: {os.path.relpath(artifact, ROOT)}")
    return 0


# --- packaging -----------------------------------------------------------------

def _package_windows(version, arch):
    folder = os.path.join(DIST, APP_NAME)
    _write_readme(os.path.join(folder, 'README.txt'), version, 'windows')
    for name in ('LICENSE', 'README.md'):
        shutil.copy2(os.path.join(ROOT, name), folder)

    artifact = os.path.join(DIST, f'{APP_NAME}-{version}-windows-{arch}.zip')
    with zipfile.ZipFile(artifact, 'w', zipfile.ZIP_DEFLATED,
                         compresslevel=9) as package:
        for directory, _, files in os.walk(folder):
            for name in files:
                path = os.path.join(directory, name)
                package.write(path, os.path.relpath(path, DIST))
    return artifact


def _package_macos(version, arch):
    app = os.path.join(DIST, f'{APP_NAME}.app')
    # PyInstaller signs each binary; sealing the bundle as a whole (ad hoc
    # unless a Developer ID was given) is what lets macOS check it.
    identity = os.environ.get('TRACE_CODESIGN_IDENTITY') or '-'
    _run(['codesign', '--force', '--deep', '--sign', identity, app])
    _run(['codesign', '--verify', '--deep', '--strict', app])

    staging = os.path.join(BUILD, 'dmg')
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    # ditto keeps the bundle's symlinks, extended attributes and signature.
    _run(['ditto', app, os.path.join(staging, f'{APP_NAME}.app')])
    os.symlink('/Applications', os.path.join(staging, 'Applications'))
    _write_readme(os.path.join(staging, 'README.txt'), version, 'macos')
    shutil.copy2(os.path.join(ROOT, 'LICENSE'),
                 os.path.join(staging, 'LICENSE.txt'))

    artifact = os.path.join(DIST, f'{APP_NAME}-{version}-macos-{arch}.dmg')
    _run(['hdiutil', 'create', '-volname', f'{APP_NAME} {version}',
          '-srcfolder', staging, '-fs', 'HFS+', '-format', 'UDZO',
          '-imagekey', 'zlib-level=9', '-ov', artifact])
    _run(['hdiutil', 'verify', artifact])
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
    try:
        if sys.platform == 'win32':
            # Where a user might unpack it: a path with spaces and a letter
            # outside ASCII.
            target = os.path.join(scratch, 'TRACE self-test é')
            with zipfile.ZipFile(artifact) as package:
                package.extractall(target)
            binary = os.path.join(target, APP_NAME, f'{APP_NAME}.exe')
        else:
            mount = os.path.join(scratch, 'volume')
            os.makedirs(mount)
            _run(['hdiutil', 'attach', '-nobrowse', '-readonly',
                  '-mountpoint', mount, artifact])
            binary = os.path.join(mount, f'{APP_NAME}.app', 'Contents',
                                  'MacOS', APP_NAME)
        say(f"  running {binary}")
        say(f"  on {len(images)} image(s): "
            + (', '.join(os.path.basename(i) for i in images) or 'none'))
        try:
            completed = subprocess.run([binary, '--self-test', report] + images,
                                       timeout=900)
        except subprocess.TimeoutExpired:
            fail("  the self-test did not finish within 15 minutes")
            return False
    finally:
        if mount:
            subprocess.run(['hdiutil', 'detach', mount, '-force'],
                           stdout=subprocess.DEVNULL)
        shutil.rmtree(scratch, ignore_errors=True)

    if not os.path.isfile(report):
        fail(f"  the app wrote no report (exit status {completed.returncode})")
        return False
    with open(report, encoding='utf-8') as handle:
        result = json.load(handle)

    passed = True
    say(f"  {result.get('platform', '')}")
    for item in result['checks']:
        detail = (item['detail'] or '').strip()
        if item['ok']:
            ok(f"{item['name']}: {detail.splitlines()[-1] if detail else ''}")
        else:
            passed = False
            bad(f"{item['name']}")
            for line in detail.splitlines()[-12:]:
                say(f"      {line}")

    for name, manifest in sorted(result.get('manifests', {}).items()):
        expected_path = os.path.join(ROOT, 'tests', 'manifests',
                                     f'{name}.manifest.json')
        if not os.path.isfile(expected_path):
            warn(f"no committed manifest for {name}; not compared")
            continue
        with open(expected_path, encoding='utf-8') as handle:
            expected = json.load(handle)
        if manifest == expected:
            ok(f"reads {name} exactly as the test suite verified")
        else:
            passed = False
            bad(f"reads {name} differently from tests/manifests/")
    if completed.returncode != 0 and passed:
        passed = False
        bad(f"exit status {completed.returncode}")
    return passed


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
https://github.com/Gadzhovski/TRACE-Forensic-Toolkit

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
    import re
    with open(os.path.join(ROOT, 'trace_app', '__init__.py'),
              encoding='utf-8') as handle:
        return re.search(r'^__version__ = "([^"]+)"', handle.read(),
                         re.M).group(1)


def _arch():
    machine = platform.machine().lower()
    return {'amd64': 'x64', 'x86_64': 'x64' if sys.platform == 'win32'
            else 'x86_64', 'aarch64': 'arm64'}.get(machine, machine)


def _platform_name():
    return 'Windows' if sys.platform == 'win32' else 'macOS'


def _size(path):
    return f"{os.path.getsize(path) / (1024 * 1024):.0f} MB"


def _run(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"\n{' '.join(command)} failed:\n"
                         f"{result.stdout}{result.stderr}")
    return result.stdout


def say(text):
    print(text, flush=True)


def step(text):
    say(f"\n> {text}")


def ok(text):
    say(f"  + {text}")


def warn(text):
    say(f"  ! {text}")


def bad(text):
    say(f"  x {text}")


def fail(text):
    say(f"\nBUILD FAILED: {text}")
    return 1


if __name__ == '__main__':
    # Plain ASCII output: a Windows console or CI log in a legacy code page
    # cannot print emoji, and a crash there would hide the real result.
    # A path printed from the self-test can hold any character.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(fail("interrupted"))

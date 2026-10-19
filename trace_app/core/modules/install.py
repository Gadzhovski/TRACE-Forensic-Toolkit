"""Installing an external tool from its GitHub releases (no Qt).

Only when the examiner asks, and never while the open case is offline
(settings.network_refusal) -- the rule every request TRACE makes follows.
The requests carry TRACE's version in their User-Agent and nothing else.

1. `releases(spec)`  the published releases (no drafts, no pre-releases)
   at or past the spec's MIN_VERSION, newest first.
2. `install(spec, version)`:
   * the download for this computer (spec.asset_name), streamed to disk
     and hashed as it arrives; it must match the release's SHA256SUMS.txt
     -- a release without sums, or a mismatch, is refused;
   * unpacked with nothing but Python and the system: Windows zipfile
     (no member may land outside the folder); macOS hdiutil (read-only,
     not shown in the Finder) and ditto, which keeps the app's signature;
     Linux the AppImage's own --appimage-extract, so no FUSE is needed;
   * into `<tool dir>/<version>.partial`, smoke-tested (`--version` must
     name the version), then renamed to `<version>` and recorded in
     `<tool dir>/installed.json` -- a failed install leaves nothing behind.
3. `installed(spec)`, `use(spec, version)`, `remove(spec, version)`.
"""

import datetime
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile

from trace_app.core.modules import paths
from trace_app.core.modules.spec import current_target

logger = logging.getLogger('TRACE.Modules')

TIMEOUT = 30
CHUNK = 1 << 20
SUMS = 'SHA256SUMS.txt'
RECORD = 'installed.json'


class InstallError(Exception):
    """The tool could not be installed (said in words)."""


class InstallCancelled(Exception):
    pass


# --- versions -----------------------------------------------------------------

def parse_version(text):
    """'v2026.4.4' -> (2026, 4, 4); None if not a version."""
    from trace_app.core.updates import parse_version as parse
    parsed = parse((text or '').strip())
    return parsed[:3] if parsed else None


def refusal():
    """Why nothing may be fetched now, or None."""
    from trace_app.core import settings
    return settings.network_refusal()


def _get(url, session=None, stream=False, accept='application/vnd.github+json'):
    import requests
    from trace_app import __version__
    why = refusal()
    if why:
        raise InstallError(why)
    session = session or requests
    try:
        response = session.get(
            url, timeout=TIMEOUT, stream=stream, allow_redirects=True,
            headers={'Accept': accept,
                     'User-Agent': f'TRACE/{__version__} (module install)'})
    except requests.RequestException as exc:
        raise InstallError(f"GitHub could not be reached: {exc}") from exc
    if response.status_code != 200:
        raise InstallError(f"GitHub answered {response.status_code} for "
                           f"{url.rsplit('/', 1)[-1]}.")
    return response


def releases(spec, session=None):
    """[{'version', 'tag', 'published', 'url', 'assets': {name: {'url',
    'size'}}}], newest first: published releases this TRACE can drive."""
    response = _get(spec.releases_api + '?per_page=30', session)
    try:
        data = response.json()
    except ValueError as exc:
        raise InstallError("GitHub's answer could not be read.") from exc
    floor = parse_version(spec.min_version)
    out = []
    for release in data if isinstance(data, list) else ():
        if release.get('draft') or release.get('prerelease'):
            continue
        version = (release.get('tag_name') or '').lstrip('vV')
        parsed = parse_version(version)
        if parsed is None or parsed < floor:
            continue
        out.append({
            'version': version, 'tag': release.get('tag_name'),
            'published': (release.get('published_at') or '')[:10],
            'url': release.get('html_url') or spec.releases_page,
            'assets': {asset['name']: {
                'url': asset.get('browser_download_url'),
                'size': int(asset.get('size') or 0)}
                for asset in release.get('assets') or ()}})
    out.sort(key=lambda r: parse_version(r['version']), reverse=True)
    return out


def preferred(spec, found):
    """The release to offer: the tested version when published, else the
    newest."""
    for release in found:
        if release['version'] == spec.tested_version:
            return release
    return found[0] if found else None


def checksums(text):
    """{file name: sha256} from a SHA256SUMS.txt ('<hex>  <name>' lines;
    '*<name>' for binary mode)."""
    sums = {}
    for line in (text or '').splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            continue
        try:
            int(parts[0], 16)
        except ValueError:
            continue
        sums[parts[1].strip().lstrip('*')] = parts[0].lower()
    return sums


# --- install --------------------------------------------------------------------

def _download(url, target, size, session, progress, should_stop):
    """Stream `url` to `target`; returns its SHA-256."""
    digest = hashlib.sha256()
    done = 0
    response = _get(url, session, stream=True,
                    accept='application/octet-stream')
    with open(target, 'wb') as handle:
        for block in response.iter_content(CHUNK):
            if should_stop is not None and should_stop():
                raise InstallCancelled()
            if not block:
                continue
            handle.write(block)
            digest.update(block)
            done += len(block)
            if progress is not None:
                progress(done, size, f"Downloading {os.path.basename(target)}")
    return digest.hexdigest()


def safe_unzip(archive, destination):
    """Extract a zip, refusing any member that would land outside
    `destination` (an absolute path, '..', a drive letter)."""
    root = os.path.realpath(destination)
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            name = member.filename.replace('\\', '/')
            target = os.path.realpath(os.path.join(root, *name.split('/')))
            if os.path.isabs(name) or ':' in name.split('/')[0] or \
                    not (target == root or target.startswith(root + os.sep)):
                raise InstallError(f"The download holds a file outside its "
                                   f"folder ({member.filename}); refused.")
        zipped.extractall(root)


def _unpack_dmg(archive, destination, spec):
    mount = tempfile.mkdtemp(prefix='trace-dmg-')
    try:
        attach = subprocess.run(
            ['hdiutil', 'attach', '-nobrowse', '-readonly', '-noautoopen',
             '-mountpoint', mount, archive], capture_output=True, text=True,
            timeout=300)
        if attach.returncode != 0:
            raise InstallError(f"The disk image would not open: "
                               f"{attach.stderr.strip()}")
        try:
            apps = [name for name in os.listdir(mount)
                    if name.endswith('.app')]
            if not apps:
                raise InstallError("The disk image holds no application.")
            app = f'{spec.name}.app' if f'{spec.name}.app' in apps else apps[0]
            copy = subprocess.run(['ditto', os.path.join(mount, app),
                                   os.path.join(destination,
                                                f'{spec.name}.app')],
                                  capture_output=True, text=True, timeout=600)
            if copy.returncode != 0:
                raise InstallError(f"The application could not be copied: "
                                   f"{copy.stderr.strip()}")
        finally:
            subprocess.run(['hdiutil', 'detach', mount, '-force'],
                           capture_output=True, timeout=120)
    finally:
        try:
            os.rmdir(mount)
        except OSError:
            pass


def _unpack_appimage(archive, destination):
    image = os.path.join(destination, os.path.basename(archive))
    shutil.move(archive, image)
    os.chmod(image, 0o755)
    from trace_app.core.modules.run import clean_environment
    done = subprocess.run([image, '--appimage-extract'], cwd=destination,
                          env=clean_environment(), capture_output=True,
                          timeout=900)
    os.remove(image)
    if done.returncode != 0 or not os.path.isdir(
            os.path.join(destination, 'squashfs-root')):
        raise InstallError("The AppImage could not be unpacked: "
                           + (done.stderr or b'').decode('utf-8', 'replace')
                           .strip()[-300:])


def unpack(spec, archive, destination, target=None):
    os_name, _arch = target or current_target()
    os.makedirs(destination, exist_ok=True)
    if os_name == 'windows':
        safe_unzip(archive, destination)
    elif os_name == 'macos':
        _unpack_dmg(archive, destination, spec)
    else:
        _unpack_appimage(archive, destination)


def smoke_test(spec, executable, version):
    """The installed program runs and is the version downloaded."""
    from trace_app.core.modules.run import version_of
    if not os.path.isfile(executable):
        raise InstallError(f"{spec.name}'s program is not where its release "
                           f"puts it ({executable}).")
    said = version_of(executable)
    if version not in said:
        raise InstallError(
            f"{spec.name} did not start as expected"
            + (f" (it said {said!r})." if said else
               " -- an antivirus may have stopped or removed it."))


def _replace_dir(source, target, wait=30.0):
    """Rename the unpacked folder into place. On Windows a folder whose new
    program was just run (the smoke test) is often held a moment longer --
    an antivirus scanning the new executable, the program's own exit --
    and the rename is refused ("Access is denied"; RLEAPP's install failed
    so). Tried again for `wait` seconds before giving up."""
    import time
    deadline = time.monotonic() + wait
    delay = 0.2
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 2.0)


def _remove_dir(path, wait=30.0):
    """Delete a tool's folder. On Windows a file in it can be held a
    moment (an antivirus scanning the program just written or run), and
    rmtree with ignore_errors left the folder there without a word: tried
    again for `wait` seconds, then said in the log."""
    import time
    deadline = time.monotonic() + wait
    delay = 0.2
    while os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path) or time.monotonic() >= deadline:
            break
        time.sleep(delay)
        delay = min(delay * 2, 2.0)
    if os.path.exists(path):
        logger.warning("Not all of %s could be deleted (a file is in use)",
                       path)


def install(spec, version=None, session=None, progress=None,
            should_stop=None, found=None):
    """Install `version` (the preferred one when None). Returns the
    record (see installed())."""
    found = found if found is not None else releases(spec, session)
    release = next((r for r in found if r['version'] == version), None) \
        if version else preferred(spec, found)
    if release is None:
        raise InstallError(f"{spec.name} {version or ''} is not among its "
                           f"published releases.".replace('  ', ' '))
    version = release['version']
    asset = spec.asset_name(version)
    if asset not in release['assets']:
        raise InstallError(f"{spec.name} {version} has no download for this "
                           f"computer ({asset}).")
    if SUMS not in release['assets']:
        raise InstallError(f"{spec.name} {version} publishes no "
                           f"{SUMS}: the download could not be checked, so "
                           f"it is not installed.")
    expected = checksums(_get(release['assets'][SUMS]['url'], session,
                              accept='application/octet-stream').text
                         ).get(asset)
    if not expected:
        raise InstallError(f"{SUMS} does not list {asset}.")
    home = paths.tool_dir(spec.id)
    final = os.path.join(home, version)
    partial = final + '.partial'
    shutil.rmtree(partial, ignore_errors=True)
    os.makedirs(partial)
    archive = os.path.join(home, asset)
    try:
        digest = _download(release['assets'][asset]['url'], archive,
                           release['assets'][asset]['size'], session,
                           progress, should_stop)
        if digest != expected:
            raise InstallError(
                f"The download does not match its published SHA-256 "
                f"(expected {expected}, got {digest}); it was not "
                f"installed.")
        if progress is not None:
            progress(0, 0, f"Unpacking {asset}")
        unpack(spec, archive, partial)
        smoke_test(spec, spec.executable(partial), version)
        _remove_dir(final)
        _replace_dir(partial, final)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    finally:
        try:
            os.remove(archive)
        except OSError:
            pass
    record = {'version': version, 'asset': asset, 'sha256': digest,
              'url': release['assets'][asset]['url'],
              'release': release['url'],
              'installed_utc': datetime.datetime.now(
                  datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
              'folder': final,
              'executable': spec.executable(final)}
    _write_record(spec, record, use=True)
    logger.info("Installed %s %s (%s, SHA-256 %s) in %s", spec.name, version,
                asset, digest, final)
    return record


# --- what is installed --------------------------------------------------------

def _record_path(spec):
    return os.path.join(paths.tool_dir(spec.id), RECORD)


def _read_records(spec):
    try:
        with open(_record_path(spec), encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_record(spec, record, use=False):
    data = _read_records(spec)
    data.setdefault('versions', {})[record['version']] = record
    if use or not data.get('current'):
        data['current'] = record['version']
    os.makedirs(paths.tool_dir(spec.id), exist_ok=True)
    with open(_record_path(spec), 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2)


def installed(spec, version=None):
    """The record of the version in use (or `version`), or None when it is
    not installed or its program is gone. The folder is the record's own
    (it moves with the modules folder: the path is rebuilt from it)."""
    data = _read_records(spec)
    version = version or data.get('current')
    record = (data.get('versions') or {}).get(version)
    if not record:
        return None
    folder = os.path.join(paths.tool_dir(spec.id), version)
    record = dict(record, folder=folder,
                  executable=spec.executable(folder))
    return record if os.path.isfile(record['executable']) else None


def versions(spec):
    """Installed versions, newest first."""
    data = _read_records(spec)
    return sorted((v for v in (data.get('versions') or {})
                   if installed(spec, v)),
                  key=parse_version, reverse=True)


def use(spec, version):
    data = _read_records(spec)
    if version not in (data.get('versions') or {}):
        raise InstallError(f"{spec.name} {version} is not installed.")
    data['current'] = version
    with open(_record_path(spec), 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2)


def remove(spec, version=None):
    """Delete an installed version (the one in use when None). Returns the
    version removed, or None."""
    data = _read_records(spec)
    version = version or data.get('current')
    if not version:
        return None
    _remove_dir(os.path.join(paths.tool_dir(spec.id), version))
    (data.get('versions') or {}).pop(version, None)
    if data.get('current') == version:
        rest = sorted(data.get('versions') or {}, key=parse_version,
                      reverse=True)
        data['current'] = rest[0] if rest else None
    with open(_record_path(spec), 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2)
    logger.info("Removed %s %s", spec.name, version)
    return version


def executable_sha256(record):
    """The SHA-256 of a record's program, for run records and audit."""
    from trace_app.core.evidence_hash import sha256_file
    return sha256_file(record['executable'])



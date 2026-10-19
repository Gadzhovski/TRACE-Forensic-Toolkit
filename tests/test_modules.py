"""External modules (core/modules): install, stage, run, read, and the
window's Modules tab -- without the network.

The real iLEAPP and aLEAPP are run by tests/test_modules_real.py (full
tier: it downloads them). Here a fake LEAPP stands in: a Python script
behind a .cmd / shell wrapper that answers `--version` and `-p`, prints
progress lines as a LEAPP does, and writes a LAVA report (the schema
core/modules/lava.py documents, from iLEAPP 2026.4.4's own output) from
the files it was given.
"""

import csv
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import zipfile

import pytest

from trace_app.core.modules import install, lava, run, spec, stage

FAKE_TOOL = r'''
import json, os, sqlite3, sys, time
args = sys.argv[1:]
if args == ['--version']:
    print('FakeLEAPP 2026.9.9'); sys.exit(0)
if args == ['-p']:
    open('path_list.txt', 'w').write(
        '**/Library/SMS/sms.db*\n**/Library/SMS/Attachments/*/*/*/*.*\n'
        '*/databases/mmssms.db*\n**/sysdiagnose_*.tar.gz\n'
        '*/Signal*/sql/db.sqlite\n')
    sys.exit(0)
if 'sleep' in args:
    open(args[args.index('sleep') + 1], 'w').write(str(os.getpid()))
    time.sleep(600)
i = args[args.index('-i') + 1]
o = args[args.index('-o') + 1]
name = args[args.index('--custom_output_folder') + 1]
report = os.path.join(o, name)
os.makedirs(os.path.join(report, 'media'))
kind = args[args.index('-t') + 1]
files = []
if kind in ('tar', 'gz'):
    import tarfile
    files = [m.name for m in tarfile.open(i) if m.isfile()]
elif kind == 'zip':
    import zipfile
    files = [n for n in zipfile.ZipFile(i).namelist() if not n.endswith('/')]
else:
    for root, _dirs, names in os.walk(i):
        for n in names:
            files.append(os.path.relpath(os.path.join(root, n), i).replace(os.sep, '/'))
password = args[args.index('--itunes_password') + 1] if '--itunes_password' in args else None
key_file = args[args.index('--signal-key') + 1] if '--signal-key' in args else None
signal_key = open(key_file).read() if key_file else None
if signal_key:
    print('Signal database opened with key ' + signal_key, flush=True)
if password:
    print('Decrypting the backup with password ' + password, flush=True)
    os.makedirs(os.path.join(report, '_HTML'))
    open(os.path.join(report, '_HTML', 'index.html'), 'w').write(
        'Manifest.db was successfully decrypted with passcode ' + password + '<br>')
open(os.path.join(o, 'seen.json'), 'w').write(json.dumps({'kind': kind, 'input': i, 'files': files, 'password': password, 'signal_key_file': key_file, 'signal_key': signal_key}))
print('Error: a module failed reading something (a test line)' if kind == 'itunes' else 'ok', flush=True)
print('[1/2] sms [sms] artifact started at 10:00:00 UTC', flush=True)
print('[2/2] media [media] artifact started at 10:00:01 UTC', flush=True)
db = sqlite3.connect(os.path.join(report, '_lava_artifacts.db'))
db.execute('CREATE TABLE _lava_media_items (id TEXT PRIMARY KEY, source_path TEXT, extraction_path TEXT, type TEXT, metadata TEXT, created_at INTEGER, updated_at INTEGER, is_embedded INTEGER)')
db.execute('CREATE TABLE _lava_media_references (id TEXT PRIMARY KEY, media_item_id TEXT, module_name TEXT, artifact_name TEXT, name TEXT)')
db.execute("CREATE VIEW _lava_media_info AS SELECT lmr.id as 'media_ref_id', lmr.media_item_id, lmr.module_name, lmr.artifact_name, lmr.name, lmi.source_path, lmi.extraction_path, lmi.type, lmi.metadata, lmi.created_at, lmi.updated_at, lmi.is_embedded FROM _lava_media_references as lmr LEFT JOIN _lava_media_items as lmi ON lmr.media_item_id = lmi.id")
db.execute('CREATE TABLE "sms" ("message_timestamp" INTEGER, "read_timestamp" INTEGER, "sender" TEXT, "message" TEXT, "attachment_file" TEXT)')
database = next((f for f in files if f.endswith('sms.db')), None)
picture = next((f for f in files if f.endswith('.jpg')), None)
if database is None or picture is None:
    db.commit()
    json.dump({'lava_schema_version': 2, 'parser_info': {'leapp_name': 'FakeLEAPP', 'leapp_version': '2026.9.9'},
               'processing_status': 'Complete',
               'modules': [{'module_name': 'sms', 'artifact_name': 'sms', 'module_status': 'No files found'}],
               'artifacts': {}}, open(os.path.join(report, '_lava_data.lava'), 'w'))
    sys.exit(0)
db.execute("INSERT INTO _lava_media_items VALUES ('m1', ?, 'media/m1.jpg', 'image/jpeg', '', 0, 0, 0)", (picture,))
db.execute("INSERT INTO _lava_media_references VALUES ('r1', 'm1', 'sms', 'SMS', 'IMG_0001.jpg')")
db.executemany('INSERT INTO sms VALUES (?,?,?,?,?)', [
    (1681579809, 1681906418, '+15550100', 'Meet at the dock, 9pm', None),
    (1681600000, '', '+15550199', 'photo attached alice@example.org', 'r1')])
db.commit()
data = {'lava_schema_version': 2,
        'parser_info': {'leapp_name': 'FakeLEAPP', 'leapp_version': '2026.9.9',
                        'start_timestamp': 1792000000, 'end_timestamp': 1792000005},
        'processing_status': 'Complete',
        'modules': [{'module_name': 'sms', 'artifact_name': 'sms', 'module_status': 'Complete'},
                    {'module_name': 'calls', 'artifact_name': 'calls', 'module_status': 'No files found'},
                    {'module_name': 'notes', 'artifact_name': 'notes', 'module_status': 'Error'}],
        'artifacts': {'SMS & iMessage': [{
            'name': 'SMS', 'tablename': 'sms', 'module': 'sms',
            'artifact_icon': 'message',
            'column_map': {'message_timestamp': 'Message Timestamp',
                           'read_timestamp': 'Read Timestamp',
                           'sender': 'Sender', 'message': 'Message',
                           'attachment_file': 'Attachment File'},
            'record_count': 2, 'source_path': database.replace('/', '\\'),
            'object_columns': [{'name': 'message_timestamp', 'type': 'datetime'},
                               {'name': 'read_timestamp', 'type': 'datetime'},
                               {'name': 'attachment_file', 'type': 'media'}],
            'data_views': {'conversation': {'textColumn': 'message'}}}]}}
json.dump(data, open(os.path.join(report, '_lava_data.lava'), 'w'))
open(os.path.join(report, 'index.html'), 'w').write('<html>report</html>')
print('Report generation Completed.')
'''


def make_fake_tool(folder):
    """The fake tool installed as a ToolSpec would find it, and a spec for
    it. Returns (spec, record)."""
    os.makedirs(folder, exist_ok=True)
    script = os.path.join(folder, 'fake_leapp.py')
    with open(script, 'w', encoding='utf-8') as handle:
        handle.write(FAKE_TOOL)
    if sys.platform.startswith('win'):
        program = os.path.join(folder, 'fakeleapp.cmd')
        with open(program, 'w', encoding='utf-8') as handle:
            handle.write(f'@"{sys.executable}" "{script}" %*\r\n')
    else:
        program = os.path.join(folder, 'fakeleapp')
        with open(program, 'w', encoding='utf-8') as handle:
            handle.write(f'#!/bin/sh\nexec "{sys.executable}" "{script}" '
                         f'"$@"\n')
        os.chmod(program, 0o755)
    tool = spec.ToolSpec(id='fakeleapp', name='FakeLEAPP',
                         program='fakeleapp', repo='example/FakeLEAPP',
                         licence='MIT', description='A stand-in.',
                         tested_version='2026.9.9', min_version='2026.4.3',
                         suits=('ios',))
    record = {'version': '2026.9.9', 'folder': folder,
              'executable': program, 'installed_utc': '2026-10-15 10:00:00',
              'asset': 'fake', 'sha256': '0' * 64, 'url': ''}
    return tool, record


def phone_folder(root):
    """A folder like an iOS extraction: SMS database and an attachment,
    plus files no LEAPP pattern names."""
    base = os.path.join(root, 'private', 'var', 'mobile', 'Library', 'SMS')
    os.makedirs(os.path.join(base, 'Attachments', 'aa', '01', 'GUID'))
    with open(os.path.join(base, 'sms.db'), 'wb') as handle:
        handle.write(b'SQLite format 3\x00' + bytes(4080))
    with open(os.path.join(base, 'Attachments', 'aa', '01', 'GUID',
                           'IMG_0001.jpg'), 'wb') as handle:
        handle.write(b'\xff\xd8\xff\xe0' + b'JFIF' * 500)
    os.makedirs(os.path.join(root, 'private', 'var', 'tmp'))
    with open(os.path.join(root, 'private', 'var', 'tmp', 'other.txt'),
              'w') as handle:
        handle.write('not wanted')
    return root


# --- spec and install ------------------------------------------------------------

@pytest.mark.parametrize('target, name, program', [
    (('windows', 'x64'), 'iLEAPP-2026.4.4-windows-x64-portable.zip',
     'ileapp.exe'),
    (('windows', 'arm64'), 'iLEAPP-2026.4.4-windows-arm64-portable.zip',
     'ileapp.exe'),
    (('macos', 'arm64'), 'iLEAPP-2026.4.4-macos-arm64.dmg',
     os.path.join('iLEAPP.app', 'Contents', 'MacOS', 'ileapp')),
    (('macos', 'x64'), 'iLEAPP-2026.4.4-macos-x64.dmg',
     os.path.join('iLEAPP.app', 'Contents', 'MacOS', 'ileapp')),
    (('linux', 'x64'), 'iLEAPP-2026.4.4-linux-x64.AppImage',
     os.path.join('squashfs-root', 'AppRun')),
    (('linux', 'arm64'), 'iLEAPP-2026.4.4-linux-arm64.AppImage',
     os.path.join('squashfs-root', 'AppRun'))])
def test_the_download_for_each_computer(target, name, program):
    """Names as the 2026.4.3+ releases publish them (checked against the
    GitHub release listing)."""
    assert spec.ILEAPP.asset_name('2026.4.4', target) == name
    assert spec.ILEAPP.executable('/t', target).replace('\\', '/') == \
        '/t/' + program.replace('\\', '/')
    assert spec.ALEAPP.asset_name('2026.4.3', target).startswith(
        'ALEAPP-2026.4.3-')


def test_the_hardware_decides_the_architecture(monkeypatch):
    import platform
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(spec, '_apple_silicon', lambda: True)
    assert spec.current_target() == ('macos', 'arm64')   # Rosetta
    monkeypatch.setattr(spec, '_apple_silicon', lambda: False)
    assert spec.current_target() == ('macos', 'x64')
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(platform, 'machine', lambda: 'aarch64')
    assert spec.current_target() == ('linux', 'arm64')


def test_sha256sums_are_read_as_published():
    text = ("a168c7450438ac863203600fd292277164e2e8317d67932c19d068b26466e373"
            "  iLEAPP-2026.4.4-linux-arm64.AppImage\n"
            "24250D2008A6B57308BFB1B945942B66E35E99BB84A3774103529323E2294BD8"
            " *iLEAPP-2026.4.4-windows-x64-portable.zip\nnot a line\n")
    sums = install.checksums(text)
    assert sums['iLEAPP-2026.4.4-windows-x64-portable.zip'] == \
        '24250d2008a6b57308bfb1b945942b66e35e99bb84a3774103529323e2294bd8'
    assert len(sums) == 2


def test_a_zip_with_a_member_outside_its_folder_is_refused(tmp_path):
    archive = tmp_path / 'evil.zip'
    with zipfile.ZipFile(archive, 'w') as zipped:
        zipped.writestr('ok.txt', 'fine')
        zipped.writestr('../escaped.txt', 'no')
    with pytest.raises(install.InstallError):
        install.safe_unzip(str(archive), str(tmp_path / 'out'))
    assert not (tmp_path / 'escaped.txt').exists()


class _Response:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status

    def json(self):
        return json.loads(self.body)

    @property
    def text(self):
        return self.body.decode() if isinstance(self.body, bytes) \
            else self.body

    def iter_content(self, size):
        data = self.body if isinstance(self.body, bytes) else \
            self.body.encode()
        for at in range(0, len(data), size):
            yield data[at:at + size]


class _GitHub:
    """GitHub as the installer asks it: the releases listing, the sums,
    the download."""

    def __init__(self, asset_name, asset, sums=None):
        self.asset_name, self.asset = asset_name, asset
        digest = hashlib.sha256(asset).hexdigest()
        self.sums = sums if sums is not None else \
            f"{digest}  {asset_name}\n"
        self.asked = []

    def get(self, url, **kwargs):
        self.asked.append(url)
        if 'api.github.com' in url:
            assets = [{'name': self.asset_name, 'size': len(self.asset),
                       'browser_download_url': 'https://dl/asset'}]
            if self.sums is not False:
                assets.append({'name': 'SHA256SUMS.txt', 'size': 10,
                               'browser_download_url': 'https://dl/sums'})
            return _Response(json.dumps([
                {'tag_name': 'v2026.4.4', 'draft': False,
                 'prerelease': False, 'html_url': 'https://r',
                 'published_at': '2026-10-02T00:00:00Z', 'assets': assets},
                {'tag_name': 'v2026.4.2', 'draft': False,
                 'prerelease': False, 'assets': []},
                {'tag_name': 'v2026.5.0-rc1', 'draft': False,
                 'prerelease': True, 'assets': []}]))
        if url.endswith('/sums'):
            return _Response(self.sums)
        return _Response(self.asset)


@pytest.fixture
def modules_dir(tmp_path, monkeypatch):
    from trace_app.core import settings
    folder = tmp_path / 'modules'
    settings.user('examiner')
    monkeypatch.setitem(settings._user_cache, 'modules_folder', str(folder))
    return folder


def _windows_zip():
    # Fixed member times: writestr stamps the clock, and two zips made a
    # 2-second boundary apart hashed differently.
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as zipped:
        for name, data in (('ileapp.exe', b'MZ fake'),
                           ('_internal/base_library.zip', b'')):
            zipped.writestr(zipfile.ZipInfo(name, (2026, 4, 4, 0, 0, 0)),
                            data)
    return out.getvalue()


def test_install_checks_the_sum_unpacks_and_records(modules_dir,
                                                    monkeypatch):
    target = ('windows', 'x64')
    monkeypatch.setattr(install, 'current_target', lambda: target)
    monkeypatch.setattr(spec, 'current_target', lambda: target)
    tested = []
    monkeypatch.setattr(install, 'smoke_test',
                        lambda s, exe, v: tested.append((exe, v)))
    github = _GitHub('iLEAPP-2026.4.4-windows-x64-portable.zip',
                     _windows_zip())
    found = install.releases(spec.ILEAPP, github)
    # Pre-releases and releases older than the layout TRACE drives are
    # never offered.
    assert [r['version'] for r in found] == ['2026.4.4']
    record = install.install(spec.ILEAPP, session=github, found=found)
    assert record['version'] == '2026.4.4'
    assert record['sha256'] == hashlib.sha256(_windows_zip()).hexdigest()
    folder = modules_dir / 'ileapp' / '2026.4.4'
    assert (folder / 'ileapp.exe').read_bytes() == b'MZ fake'
    assert tested and tested[0][1] == '2026.4.4'
    assert not list((modules_dir / 'ileapp').glob('*.partial'))
    assert not list((modules_dir / 'ileapp').glob('*.zip'))   # removed
    assert install.installed(spec.ILEAPP)['version'] == '2026.4.4'
    assert install.versions(spec.ILEAPP) == ['2026.4.4']
    assert install.remove(spec.ILEAPP) == '2026.4.4'
    assert install.installed(spec.ILEAPP) is None
    assert not folder.exists()


def test_a_download_not_matching_its_sum_is_not_installed(modules_dir,
                                                          monkeypatch):
    target = ('windows', 'x64')
    monkeypatch.setattr(install, 'current_target', lambda: target)
    monkeypatch.setattr(spec, 'current_target', lambda: target)
    monkeypatch.setattr(install, 'smoke_test', lambda *a: None)
    name = 'iLEAPP-2026.4.4-windows-x64-portable.zip'
    tampered = _GitHub(name, _windows_zip(), sums=f"{'0' * 64}  {name}\n")
    with pytest.raises(install.InstallError, match='does not match'):
        install.install(spec.ILEAPP, session=tampered)
    unsummed = _GitHub(name, _windows_zip(), sums=False)
    with pytest.raises(install.InstallError, match='SHA256SUMS'):
        install.install(spec.ILEAPP, session=unsummed)
    assert install.installed(spec.ILEAPP) is None
    assert not list((modules_dir / 'ileapp').glob('2026*'))


def test_nothing_is_fetched_while_the_case_is_offline(monkeypatch):
    from trace_app.core import settings
    monkeypatch.setitem(settings._case_values, 'offline', True)
    github = _GitHub('x', b'')
    with pytest.raises(install.InstallError, match='offline'):
        install.releases(spec.ILEAPP, github)
    assert github.asked == []


def test_tools_live_beside_trace_unless_told_otherwise(tmp_path,
                                                       monkeypatch):
    from trace_app.core import settings
    from trace_app.core.modules import paths
    settings.user('examiner')
    monkeypatch.setitem(settings._user_cache, 'modules_folder', '')
    monkeypatch.setattr(paths, 'trace_folder', lambda: str(tmp_path))
    monkeypatch.setattr(sys, 'platform', 'win32')
    assert paths.modules_dir() == os.path.join(str(tmp_path), 'modules')
    # Somewhere TRACE may not write: the per-user folder.
    monkeypatch.setattr(paths, '_writable', lambda folder: False)
    from trace_app.infra.paths import user_data_dir
    assert paths.modules_dir() == os.path.join(user_data_dir(), 'modules')
    # The packaged macOS app: never inside TRACE.app.
    monkeypatch.setattr(paths, '_writable', lambda folder: True)
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert paths.modules_dir() == os.path.join(user_data_dir(), 'modules')
    monkeypatch.setitem(settings._user_cache, 'modules_folder',
                        str(tmp_path / 'usb'))
    assert paths.modules_dir() == str(tmp_path / 'usb')


# --- running a tool ---------------------------------------------------------------

def test_a_tool_starts_without_what_trace_set_for_itself():
    env = run.clean_environment({
        'PATH': '/bin', 'TZ': 'UTC', 'DYLD_LIBRARY_PATH': '/trace/pylibmagic',
        'MAGIC': '/trace/magic.mgc', '_PYI_APPLICATION_HOME_DIR': '/trace',
        '_MEIPASS2': '/tmp/x', 'QT_SCALE_FACTOR': '1.5',
        'LD_LIBRARY_PATH': '/trace/_internal',
        'LD_LIBRARY_PATH_ORIG': '/usr/local/lib', 'TRACE_LIVE_RELAYS': '{}'})
    assert env['PATH'] == '/bin' and env['TZ'] == 'UTC'
    for gone in ('DYLD_LIBRARY_PATH', 'MAGIC', '_PYI_APPLICATION_HOME_DIR',
                 '_MEIPASS2', 'QT_SCALE_FACTOR', 'TRACE_LIVE_RELAYS',
                 'LD_LIBRARY_PATH_ORIG'):
        assert gone not in env
    assert env['LD_LIBRARY_PATH'] == '/usr/local/lib'
    assert env['PYINSTALLER_RESET_ENVIRONMENT'] == '1'


def test_progress_lines_and_cancel_ending_the_whole_tree(tmp_path):
    _tool, record = make_fake_tool(str(tmp_path / 'tool'))
    pid_file = tmp_path / 'pid'
    seen = []
    with pytest.raises(run.ToolCancelled):
        run.run([record['executable'], 'sleep', str(pid_file)],
                record['folder'], str(tmp_path / 'run.log'),
                should_stop=lambda: pid_file.exists() and
                bool(pid_file.read_text()),
                progress=lambda *a: seen.append(a))
    pid = int(pid_file.read_text())
    if sys.platform.startswith('win'):
        listed = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'],
                                capture_output=True, text=True).stdout
        assert str(pid) not in listed
    else:
        with pytest.raises(OSError):
            os.kill(pid, 0)
    match = run.PROGRESS.match('[12/1174] sms [sms] artifact started at '
                               '12:47:32 UTC')
    assert match.groups()[:2] == ('12', '1174')


# --- staging ---------------------------------------------------------------------

def test_the_matcher_answers_as_fnmatch_does():
    import fnmatch
    patterns = ['**/Library/SMS/sms.db*', '*/databases/mmssms.db*',
                '**/*-journal', '**/Containers/Data/Application/*/Documents/'
                'Attachments/*.*', '**/AP.db*', '*/Preferences/*.plist',
                '*.logarchive/*', '*/BT/devlog_*.txt', '*/$[Rr]ecycle.bin/*',
                '*/tdata/????????????????s', '*/*/Video Content/*', 'sms.db']
    matcher = stage.Matcher(patterns)
    paths = ['/private/var/mobile/Library/SMS/sms.db',
             '/private/var/mobile/library/sms/SMS.DB-wal',
             '/data/data/com.android.providers.telephony/databases/mmssms.db',
             '/x/y.sqlite-journal', '/a/Containers/Data/Application/ID/'
             'Documents/Attachments/p.png', '/a/AP.db', '/a/b/notes.txt',
             '/Library/SMS', '/apdb',
             # '*' crosses '/', as LEAPP's fnmatch: AP.db* names a file
             # inside a folder whose name starts so; *.plist anywhere below
             '/x/AP.db-dir/y', '/u/Library/Preferences/a/b.plist',
             '/u/Library/Preferences/b.plistx', '/v/system.logarchive/a/b',
             '/c/BT/devlog_1.txt', '/c/BT/devlog_1.txtx', '/c/$Recycle.Bin/x',
             '/t/tdata/0123456789abcdefs', '/t/tdata/0123456789abcdef',
             '/a/b/Video Content/c', '/a/Video Content/c', 'sms.db',
             'nofolder']
    for path in paths:
        expected = any(fnmatch.fnmatchcase(path.lower(), p.lower())
                       for p in patterns)
        assert matcher(path) == expected, path


def test_staging_copies_what_the_tool_reads_with_a_hashed_manifest(
        tmp_path):
    from trace_app.core.image_handler import ImageHandler
    evidence = phone_folder(str(tmp_path / 'phone'))
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        matcher = stage.Matcher(['**/Library/SMS/sms.db*',
                                 '**/Library/SMS/Attachments/*/*/*/*.*'])
        found = stage.find(handler, matcher)
        names = sorted(entry.path for _volume, entry in found)
        assert names == [
            '/private/var/mobile/Library/SMS/Attachments/aa/01/GUID/'
            'IMG_0001.jpg', '/private/var/mobile/Library/SMS/sms.db']
        rows = stage.stage(handler, found, str(tmp_path / 'run' / 'input'),
                           7, 'phone')
    finally:
        handler.close_resources()
    for row in rows:
        copy = tmp_path / 'run' / 'input' / row['staged_path']
        assert hashlib.sha256(copy.read_bytes()).hexdigest() == row['sha256']
        assert row['written_copy_check'] == 'matches'
        assert row['artifact_ref'].startswith('p0:i')
    with open(tmp_path / 'run' / stage.MANIFEST, newline='') as handle:
        assert len(list(csv.DictReader(handle))) == 2
    assert not (tmp_path / 'run' / 'input' / 'private' / 'var' /
                'tmp').exists()


def test_folder_evidence_is_staged_on_threads_in_walk_order(tmp_path):
    """Folder evidence copies on several threads (each read opens its own
    file); the manifest keeps the walk's order, every copy checked; a
    cancel stops the copying."""
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'mac' / 'Users' / 'x' / 'Library' / 'Logs'
    root.mkdir(parents=True)
    for n in range(60):
        (root / f"log{n:02d}.txt").write_bytes(os.urandom(100 + n))
    handler = ImageHandler(str(tmp_path / 'mac'))
    assert handler.load_image()
    try:
        assert handler.logical_fs.parallel_reads
        found = stage.find(handler, stage.Matcher(['**/Logs/*.txt']))
        assert len(found) == 60
        rows = stage.stage(handler, found, str(tmp_path / 'run' / 'input'),
                           1, 'mac')
        assert [r['source_path'] for r in rows] ==             [entry.path for _volume, entry in found]
        for row in rows:
            copy = tmp_path / 'run' / 'input' / row['staged_path']
            assert hashlib.sha256(copy.read_bytes()).hexdigest() ==                 row['sha256']
            assert row['written_copy_check'] == 'matches'
        asked = []
        with pytest.raises(stage.StageCancelled):
            stage.stage(handler, found, str(tmp_path / 'again' / 'input'),
                        1, 'mac',
                        should_stop=lambda: asked.append(1) or
                        len(asked) > 5)
    finally:
        handler.close_resources()


def test_staging_refuses_when_the_disk_cannot_hold_it(tmp_path, monkeypatch):
    import shutil
    from trace_app.core.image_handler import ImageHandler
    evidence = phone_folder(str(tmp_path / 'phone'))
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        found = stage.find(handler, stage.Matcher(['**/sms.db']))
        monkeypatch.setattr(shutil, 'disk_usage',
                            lambda path: shutil._ntuple_diskusage(1, 1, 10))
        with pytest.raises(stage.StageError, match='Not enough free space'):
            stage.stage(handler, found, str(tmp_path / 'in'), 1, 'phone')
    finally:
        handler.close_resources()


# --- the whole run, in a case ---------------------------------------------------

@pytest.fixture
def fake_installed(tmp_path, monkeypatch):
    """The fake tool installed as iLEAPP (TOOLS['ileapp'] -> its spec)."""
    tool, record = make_fake_tool(str(tmp_path / 'tool'))
    tool = spec.ToolSpec(**{**tool.__dict__, 'id': 'ileapp'})
    monkeypatch.setitem(spec.TOOLS, 'ileapp', tool)
    monkeypatch.setattr(install, 'installed',
                        lambda s, version=None: record
                        if s.id == 'ileapp' else None)
    return tool, record


def test_a_run_is_staged_run_read_and_recorded(tmp_path, fake_installed):
    from trace_app.core import background, timeline
    from trace_app.core.case import Case, make_module_ref
    from trace_app.core.search_index import SearchIndex
    evidence = phone_folder(str(tmp_path / 'phone'))
    case = Case.create(str(tmp_path / 'case'), 'Modules')
    evidence_id = case.add_evidence(evidence)
    folder = os.path.join(case.folder, 'modules', 'run 1')
    items, progress = [], []
    count = background.job_leapp(
        {'tool': 'ileapp', 'image_path': evidence,
         'case_folder': case.folder, 'evidence_id': evidence_id,
         'folder': folder, 'evidence_name': 'phone'},
        lambda *a, **k: progress.append(a), items.append, lambda: False)
    assert count == 2
    summary = items[0]
    assert summary['status'] == 'complete' and summary['staged'] == 2
    assert summary['indexed'] == 2
    case.close()
    case = Case.open(str(tmp_path / 'case'))
    try:
        run_row = case.module_runs()[0]
        assert run_row['status'] == 'complete'
        assert run_row['manifest_sha256'] == hashlib.sha256(open(
            os.path.join(folder, stage.MANIFEST), 'rb').read()).hexdigest()
        artifacts = case.module_artifacts(run_row['id'])
        assert [(a['name'], a['row_count']) for a in artifacts] == \
            [('SMS', 2)]
        # Three timestamps in two rows: three Timeline events.
        rows = timeline.events(case._db, timeline.default_filters())
        mine = [r for r in rows if r['source'] == 'modules']
        assert len(mine) == 3
        assert mine[0]['title'] == 'FakeLEAPP: SMS'
        assert mine[0]['artifact_ref'] == make_module_ref(run_row['id'],
                                                          'sms', 1)
        assert 'Meet at the dock' in mine[0]['subject']
        actions = [e['action'] for e in case.activity()]
        assert 'external module run started' in actions
        assert 'external module run finished' in actions
        index = SearchIndex(case.folder)
        try:
            hits = index.search('dock')
            assert [h['kind'] for h in hits] == ['module']
            assert hits[0]['artifact_ref'] == make_module_ref(
                run_row['id'], 'sms', 1)
            emails = [value for kind, value in index._db.execute(
                "SELECT kind, value FROM entities")]
            assert 'alice@example.org' in emails
        finally:
            index.close()
        # Re-indexing the image keeps the run's rows; removing the run
        # takes them, its events and artifacts.
        case.remove_module_run(run_row['id'])
        assert case.module_runs() == []
        assert case._db.execute(
            "SELECT count(*) FROM module_events").fetchone()[0] == 0
        index = SearchIndex(case.folder)
        try:
            assert index.search('dock') == []
        finally:
            index.close()
    finally:
        case.close()


def test_a_run_that_finds_nothing_to_read_says_so(tmp_path, fake_installed):
    from trace_app.core import background
    from trace_app.core.case import Case
    empty = tmp_path / 'empty'
    (empty / 'docs').mkdir(parents=True)
    (empty / 'docs' / 'a.txt').write_text('nothing for a LEAPP')
    case = Case.create(str(tmp_path / 'case'), 'Nothing')
    evidence_id = case.add_evidence(str(empty))
    items = []
    background.job_leapp(
        {'tool': 'ileapp', 'image_path': str(empty),
         'case_folder': case.folder, 'evidence_id': evidence_id,
         'folder': os.path.join(case.folder, 'modules', 'r')},
        lambda *a, **k: None, items.append, lambda: False)
    assert items[0]['status'] == 'failed'
    assert 'none of the files' in items[0]['message']
    assert case.module_runs()[0]['status'] == 'failed'
    case.close()


def test_lava_reading(tmp_path):
    """The reader on a LAVA report as the LEAPPs write it."""
    _tool, record = make_fake_tool(str(tmp_path / 'tool'))
    source = phone_folder(str(tmp_path / 'in'))
    out = tmp_path / 'out'
    out.mkdir()
    code = run.run([record['executable'], '-t', 'fs', '-i', source, '-o',
                    str(out), '--custom_output_folder', 'report'],
                   record['folder'], str(tmp_path / 'log'))
    assert code == 0
    info = lava.load(str(out / 'report'))
    assert (info['tool'], info['version'], info['status']) == \
        ('FakeLEAPP', '2026.9.9', 'Complete')
    artifact = info['artifacts'][0]
    assert artifact['source_path'] == \
        'private/var/mobile/Library/SMS/sms.db'
    assert [c['type'] for c in artifact['columns']] == \
        ['datetime', 'datetime', '', '', 'media']
    connection = lava.connect(str(out / 'report'))
    try:
        rows = lava.rows(connection, artifact)
        media = lava.media(connection)
        assert lava.display(artifact['columns'][0], rows[0][1][
            'message_timestamp']) == '2023-04-15 17:30:09'
        assert lava.display(artifact['columns'][1], '') == ''
        assert lava.display(artifact['columns'][4], 'r1', media) == \
            'IMG_0001.jpg'
        assert lava.source_path(artifact, rows[1][1], media).endswith(
            'IMG_0001.jpg')
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM sms")       # read-only
    finally:
        connection.close()
    (out / 'report' / '_lava_data.lava').write_text(json.dumps(
        {'lava_schema_version': 99}))
    with pytest.raises(lava.LavaError, match='schema'):
        lava.load(str(out / 'report'))


# --- the window -------------------------------------------------------------------

def test_the_modules_tab_runs_shows_previews_tags_and_reports(
        qapp, tmp_path, fake_installed):
    from PySide6.QtCore import Qt
    from tests.conftest import close_window, pump
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    evidence = phone_folder(str(tmp_path / 'phone'))
    case = Case.create(str(tmp_path / 'case'), 'Window')
    evidence_id = case.add_evidence(evidence)
    folder = case.folder
    case.close()
    window = MainWindow(case=Case.open(folder))
    try:
        window._report_dialogs = False
        pump(qapp, 60, lambda: window.evidence_files)
        window.refresh_modules()
        panel = window.modules_panel
        assert panel.tool_combo.count() == 1
        # In-process: the child process would not see the monkeypatched
        # install, so the job runs here as the window would get it.
        from trace_app.core import background
        params = {'tool': 'ileapp', 'image_path': evidence,
                  'case_folder': window.case.folder,
                  'evidence_id': evidence_id, 'evidence_name': 'phone',
                  'folder': os.path.join(window.case.folder, 'modules',
                                         'run')}
        results = []
        background.job_leapp(params, lambda *a, **k: None, results.append,
                             lambda: False)
        window._leapp_finished(spec.TOOLS['ileapp'],
                               {'name': 'phone', 'key': evidence_id},
                               results, '')
        assert window.result_viewer.currentWidget() is panel
        run_row = panel.runs[0]
        assert (run_row['tool'], run_row['status']) == ('FakeLEAPP',
                                                        'complete')
        assert panel.select(run_row['key'], 'sms')
        assert panel.model.rowCount() == 2
        payload = panel.payload(1)
        assert payload['source']['artifact_ref'].startswith('p0:i')
        assert payload['source']['name'] == 'IMG_0001.jpg'
        # The tree: Extractions from Modules > run > category > artifact.
        root = next(window.tree_viewer.topLevelItem(i) for i in
                    range(window.tree_viewer.topLevelItemCount())
                    if (window.tree_viewer.topLevelItem(i).data(
                        0, Qt.UserRole) or {}).get('is_modules_root'))
        assert root.text(0) == 'Extractions from Modules (2)'
        assert root.child(0).child(0).child(0).text(0) == 'SMS (2)'
        # A 'mod:' ref -- from the Timeline, a tag -- opens its row.
        from trace_app.core.case import parse_artifact_ref
        parsed = parse_artifact_ref(payload['artifact_ref'])
        panel.tree.setCurrentItem(None)
        assert window.show_module_ref(parsed)
        assert panel.table.currentIndex().row() == 1
        assert window._module_ref_source(parsed)['name'] == 'IMG_0001.jpg'
        # Tags and categories on rows: the tag on the row, the category on
        # the picture's evidence file.
        rows = window._tag_rows(None, payload)
        assert rows[0]['artifact_ref'] == payload['artifact_ref']
        window.tag_rows(window.case.tags()[0]['id'], rows)
        assert window.case.tagged()[0]['artifact_ref'] == \
            payload['artifact_ref']
        vic = window._vic_rows(rows)
        assert vic == [payload['source']]
        window.categorise_rows(1, window._media_rows(vic))
        assert window.case.vic_categories_for(evidence_id) == {
            payload['source']['artifact_ref']: 1}
        assert window._vic_rows(window._tag_rows(None, panel.payload(0))) \
            == []                       # a text message carries no picture
        assert window.add_module_rows_to_report([panel.payload(0)]) == 1
        item = window.case.report_items('module_row')[0]
        assert item['detail']['values']['Message'] == \
            'Meet at the dock, 9pm'
        from trace_app.core import report
        writer = report._Builder(window.case,
                                 report.default_options(window.case), {},
                                 None, None)
        section = writer.section_modules()
        assert 'FakeLEAPP 2026.9.9' in section
        assert 'Meet at the dock, 9pm' in section
        # Delete Run: the case forgets it and the folder goes.
        assert window.remove_module_run(run_row)
        assert panel.runs == [] and not os.path.exists(run_row['folder'])
    finally:
        close_window(window)


def test_the_analysis_modules_offer_the_installed_tools(qapp, tmp_path,
                                                       monkeypatch):
    """External tools in the Analysis Modules dialog and the wizard:
    greyed out with the reason until installed, in no profile, and a
    choice with one queues it on each image."""
    from trace_app.ui.dialogs import analysis_modules
    monkeypatch.setattr(install, 'installed', lambda s, version=None: None)
    unavailable, _in_use = analysis_modules.availability()
    assert 'not installed' in unavailable['ileapp']
    selector = analysis_modules.ModuleSelector(unavailable=unavailable)
    try:
        assert not selector.boxes['ileapp'].isEnabled()
        for keys in analysis_modules.PROFILES.values():
            assert not set(keys) & set(analysis_modules.EXTERNAL_MODULES)
    finally:
        selector.deleteLater()
    _tool, record = make_fake_tool(str(tmp_path / 'tool'))
    monkeypatch.setattr(install, 'installed',
                        lambda s, version=None: record
                        if s.id == 'aleapp' else None)
    unavailable, _in_use = analysis_modules.availability()
    assert 'aleapp' not in unavailable and 'ileapp' in unavailable

    queued = []

    class Window:
        queue_leapp = staticmethod(lambda key, tool: queued.append(
            (key, tool)))
    from trace_app.ui.main_window import MainWindow
    choice = analysis_modules.default_choice()
    choice.update(modules=[], carve_types=[], aleapp=True)
    evidence = tmp_path / 'phone'
    evidence.mkdir()
    for name in ('queue_analysis', 'queue_indexing', 'queue_activity',
                 'queue_ntfs', 'queue_fs_times', 'queue_persistence',
                 'queue_thumbnails', 'queue_deleted'):
        setattr(Window, name, staticmethod(lambda *a, **k: None))
    MainWindow._queue_one_choice(Window(), [{'id': 3,
                                             'path': str(evidence)}], choice)
    assert queued == [(3, 'aleapp')]


# --- inputs packed in archives ------------------------------------------------------

def packed_phone(root):
    """A folder as phone extractions arrive: the file system in a tar, a
    zipped iTunes backup, a sysdiagnose .tar.gz (which the tool parses as
    a file), and a document. Archives over inputs.MIN_ARCHIVE."""
    import tarfile
    from trace_app.core.modules import inputs
    filler = os.urandom(inputs.MIN_ARCHIVE + 1024)
    os.makedirs(os.path.join(root, 'Extraction'))
    with tarfile.open(os.path.join(root, 'Extraction', 'fs.tar'),
                      'w') as tarred:
        for name, data in (
                ('Volumes/X/.fseventsd/a', filler),
                ('Volumes/X/private/var/mobile/Library/SMS/sms.db',
                 b'SQLite format 3\x00' + bytes(4080)),
                ('Volumes/X/private/var/mobile/Library/SMS/Attachments/'
                 'aa/01/G/IMG_0001.jpg', b'\xff\xd8\xff' + bytes(500))):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tarred.addfile(info, io.BytesIO(data))
    os.makedirs(os.path.join(root, 'iTunes Backup'))
    with zipfile.ZipFile(os.path.join(root, 'iTunes Backup', 'b.zip'),
                         'w') as zipped:
        zipped.writestr('00aa/Manifest.db', b'SQLite format 3\x00')
        zipped.writestr('00aa/Manifest.plist', b'<plist/>')
        zipped.writestr('00aa/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28',
                        filler)
    os.makedirs(os.path.join(root, 'Sysdiagnose Logs'))
    with tarfile.open(os.path.join(root, 'Sysdiagnose Logs',
                                   'sysdiagnose_2020.04.12.tar.gz'),
                      'w:gz') as tarred:
        info = tarfile.TarInfo('sysdiagnose/logs/private/var/mobile/x.log')
        info.size = len(filler)
        tarred.addfile(info, io.BytesIO(filler))
    with open(os.path.join(root, 'notes.pdf'), 'wb') as handle:
        handle.write(b'%PDF-1.4 not phone data')
    return root


def test_packed_extractions_and_backups_are_each_an_input(tmp_path,
                                                          fake_installed):
    """A tar of the file system and a zipped backup are found by what
    their members are, not their names, and each is run with the tool's
    own input type; an archive the tool's patterns name (sysdiagnose) is
    given to it as a file. Before, only loose files were staged: a 16 GB
    tar was never read, and nothing said so."""
    from trace_app.core import background
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.modules import job
    tool, record = fake_installed
    evidence = packed_phone(str(tmp_path / 'iOS Extraction'))
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        plans = job.plan(tool, record, handler, evidence)
    finally:
        handler.close_resources()
    kinds = {p['kind']: p for p in plans}
    assert set(kinds) == {'staged', 'tar', 'itunes'}
    assert [entry.name for _v, entry in kinds['staged']['found']] == \
        ['sysdiagnose_2020.04.12.tar.gz']
    assert kinds['tar']['os_path'].endswith('fs.tar')
    assert kinds['itunes']['root'] == '00aa'

    case = Case.create(str(tmp_path / 'case'), 'Packed')
    evidence_id = case.add_evidence(evidence)
    items = []
    background.job_leapp(
        {'tool': 'ileapp', 'image_path': evidence,
         'case_folder': case.folder, 'evidence_id': evidence_id,
         'evidence_name': 'iOS Extraction',
         'folder': os.path.join(case.folder, 'modules', 'run')},
        lambda *a, **k: None, items.append, lambda: False)
    assert [i['status'] for i in items] == ['complete'] * 3
    seen = {}
    for item in items:
        with open(os.path.join(item['folder'], 'seen.json')) as handle:
            seen[item['input']] = json.load(handle)
    tar_run = next(v for k, v in seen.items() if 'fs.tar' in k)
    assert tar_run['kind'] == 'tar'
    # Read where it is: a 16 GB file is not copied.
    assert tar_run['input'] == os.path.join(evidence, 'Extraction',
                                            'fs.tar')
    backup_run = next(v for k, v in seen.items() if 'iTunes' in k)
    assert backup_run['kind'] == 'itunes'
    assert 'Manifest.db' in backup_run['files']
    loose_run = next(v for k, v in seen.items() if 'loose' in k)
    assert loose_run['kind'] == 'fs'
    runs = case.module_runs()
    assert len(runs) == 3
    tar_record = next(r for r in runs
                      if r['params']['input']['kind'] == 'tar')
    with open(os.path.join(evidence, 'Extraction', 'fs.tar'), 'rb') as f:
        assert tar_record['params']['input']['sha256'] == \
            hashlib.sha256(f.read()).hexdigest()
    covered = tar_record['params']['coverage']
    assert (covered['artifacts'], covered['with_data'],
            covered['no_files']) == (3, 1, 1)
    assert [list(x) for x in covered['other']] == [['notes', 'Error']]
    assert [a['row_count'] for a in case.module_artifacts(
        tar_record['id'])] == [2]
    case.close()


def test_a_run_says_what_it_covered(qapp, tmp_path, fake_installed):
    from trace_app.core import background
    from trace_app.core.case import Case
    from trace_app.ui.viewers.modules_panel import (ModulesPanel,
                                                    details_html)
    evidence = phone_folder(str(tmp_path / 'phone'))
    case = Case.create(str(tmp_path / 'case'), 'Cover')
    evidence_id = case.add_evidence(evidence)
    background.job_leapp(
        {'tool': 'ileapp', 'image_path': evidence,
         'case_folder': case.folder, 'evidence_id': evidence_id,
         'folder': os.path.join(case.folder, 'modules', 'run')},
        lambda *a, **k: None, lambda item: None, lambda: False)
    run = dict(case.module_runs()[0])
    case.close()
    run.update(key=run['id'], run_id=run['id'], evidence='phone',
               started=run['started_utc'],
               report=os.path.join(run['path'], 'report'),
               folder=run['path'], input=run['params']['input'],
               coverage=run['params']['coverage'], artifacts=[])
    page = details_html(run, run['coverage'])
    assert '1 of 3 of its artifacts found data' in page
    assert 'notes: Error' in page
    assert 'Errors in the tool' not in page          # its log is clean
    panel = ModulesPanel()
    try:
        panel.set_runs([run])
        assert panel.select(run['key'])
        assert panel.pages.currentWidget() is panel.details
        assert '1 of 3 artifacts found data' in panel.status_label.text()
    finally:
        panel.deleteLater()


def test_the_modules_tab_lists_images_and_installed_tools_in_triage(
        qapp, tmp_path, fake_installed):
    """Quick triage, evidence opened, the tab shown: the image and the
    installed tool are offered. Its lists were filled only when a run
    finished or a tool was installed, so they stood empty."""
    from tests.conftest import close_window, pump
    from trace_app.ui.main_window import MainWindow
    evidence = phone_folder(str(tmp_path / 'phone'))
    window = MainWindow()
    try:
        assert window.case is None
        assert window.open_evidence_image(evidence)
        pump(qapp, 0.5)
        panel = window.modules_panel
        assert [panel.evidence_combo.itemText(i)
                for i in range(panel.evidence_combo.count())] == ['phone']
        assert panel.tool_combo.count() == 1
        assert panel.tool_combo.itemData(0) == 'ileapp'
    finally:
        close_window(window)


def test_an_iphone_is_named_ios_not_macos(tmp_path):
    """SystemVersion.plist says 'iPhone OS'; a backup's Info.plist names
    the device (its app list runs past 64 KB, so keys are read alone)."""
    from trace_app.core import os_identity
    found = os_identity._system_version(
        '<plist><dict><key>ProductName</key><string>iPhone OS</string>'
        '<key>ProductVersion</key><string>13.3.1</string>'
        '<key>ProductBuildVersion</key><string>17D50</string>'
        '</dict></plist>')
    assert (found['family'], found['logo']) == ('ios', 'apple')
    info = ('<plist><dict><key>Applications</key><dict>'
            + '<key>com.app</key><dict><key>x</key><string>y</string>'
            '</dict>' * 3000 + '</dict><key>Device Name</key>'
            '<string>Phone</string><key>Product Type</key>'
            '<string>iPhone8,4</string><key>Product Version</key>'
            '<string>13.3.1</string></dict></plist>')
    assert len(info) > 65536
    found = os_identity._backup_info(info)
    assert found['name'] == 'iOS 13.3.1'
    assert 'iPhone8,4' in found['detail']


def test_evidence_overview_names_the_device_and_what_is_packed(tmp_path):
    """A folder's Evidence Information: Android's model from the build.prop
    of another partition (Android 10 splits them), a zipped backup's
    Info.plist, and what each archive is."""
    import plistlib
    from trace_app.core import evidence_overview
    from trace_app.core.image_handler import ImageHandler
    android = tmp_path / 'Pixel'
    (android / 'system').mkdir(parents=True)
    (android / 'vendor').mkdir()
    (android / 'system' / 'build.prop').write_text(
        'ro.system.build.version.release=10\nro.build.id=QQ1A\n')
    (android / 'vendor' / 'build.prop').write_text(
        'ro.product.vendor.manufacturer=Google\n'
        'ro.product.vendor.model=Pixel 3\n')
    handler = ImageHandler(str(android))
    assert handler.load_image()
    try:
        facts = evidence_overview.device_facts(handler)
        assert facts['Manufacturer'] == 'Google'
        assert facts['Model'] == 'Pixel 3'
        assert facts['Android version'] == '10'
    finally:
        handler.close_resources()
    phone = tmp_path / 'iPhone'
    (phone / 'Backup').mkdir(parents=True)
    with zipfile.ZipFile(phone / 'Backup' / 'b.zip', 'w') as zipped:
        zipped.writestr('x/Manifest.db', b'SQLite format 3')
        zipped.writestr('x/Info.plist', plistlib.dumps({
            'Product Version': '13.3.1', 'IMEI': '355800076093966',
            'Serial Number': 'DX3T', 'Applications': {'a': {'b': b'c'}}}))
        zipped.writestr('x/pad', os.urandom(2 * 1024 * 1024))
    (phone / 'Logs').mkdir()
    (phone / 'Logs' / 'image_info.txt').write_text('acquired')
    handler = ImageHandler(str(phone))
    assert handler.load_image()
    try:
        facts = evidence_overview.device_facts(handler)
        assert facts['IMEI'] == '355800076093966'
        assert facts['iOS version'] == '13.3.1'
        packed = evidence_overview.contents(handler)
        assert [what for what, _p, _s in packed] == [
            'iTunes/Finder backup (zip)', 'Acquisition log or report']
        overview = evidence_overview.summary(handler)
        assert overview['files'] == 2
        assert [name for name, *_rest in overview['top']] == ['Backup',
                                                             'Logs']
    finally:
        handler.close_resources()


def _keybag(password):
    """An iTunes keybag whose class keys `password` unwraps (rounds cut
    to a few: the derivation is the same)."""
    import struct
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap

    def tlv(tag, value):
        if isinstance(value, int):
            value = struct.pack('>I', value)
        return tag.encode() + struct.pack('>I', len(value)) + value
    salt, dpsl = os.urandom(20), os.urandom(20)
    passcode = hashlib.pbkdf2_hmac('sha1', hashlib.pbkdf2_hmac(
        'sha256', password.encode(), dpsl, 10, 32), salt, 10, 32)
    bag = (tlv('VERS', 4) + tlv('TYPE', 1) + tlv('UUID', os.urandom(16))
           + tlv('WRAP', 0) + tlv('SALT', salt) + tlv('ITER', 10)
           + tlv('DPIC', 10) + tlv('DPSL', dpsl))
    for cls in (1, 2, 3):
        bag += (tlv('UUID', os.urandom(16)) + tlv('CLAS', cls)
                + tlv('WRAP', 2) + tlv('KTYP', 0)
                + tlv('WPKY', aes_key_wrap(passcode, os.urandom(32))))
    return bag


def _encrypted_phone(root, password):
    import plistlib
    os.makedirs(os.path.join(root, 'Backup'))
    with zipfile.ZipFile(os.path.join(root, 'Backup', 'b.zip'),
                         'w') as zipped:
        zipped.writestr('x/Manifest.db', b'SQLite format 3\x00')
        zipped.writestr('x/Manifest.plist', plistlib.dumps(
            {'IsEncrypted': True, 'Version': '10.0',
             'BackupKeyBag': _keybag(password)}, fmt=plistlib.FMT_BINARY))
        zipped.writestr('x/Info.plist', plistlib.dumps(
            {'Product Version': '13.3.1'}))
        zipped.writestr('x/pad', os.urandom(2 * 1024 * 1024))
    return root


def test_an_encrypted_backup_is_flagged_and_read_with_its_password(
        tmp_path, fake_installed):
    """Manifest.plist's IsEncrypted (a binary plist, as iTunes writes it)
    shows in Evidence Information. Without a password the job records the
    backup as skipped; a wrong one is refused by its keybag before the tool
    runs; the right one reaches the tool as --itunes_password, and is
    starred in run.log and written nowhere in the case."""
    import plistlib
    from trace_app.core import background, evidence_overview
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    tool, _record = fake_installed
    evidence = _encrypted_phone(str(tmp_path / 'iPhone'), 'Open-Sesame-42')
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        facts = evidence_overview.device_facts(handler)
        assert facts[evidence_overview.ENCRYPTED_FIELD].startswith('Yes')
        assert [what for what, _p, _s in evidence_overview.contents(
            handler)] == ['iTunes/Finder backup (zip, encrypted)']
    finally:
        handler.close_resources()
    assert evidence_overview.backup_encrypted(plistlib.dumps(
        {'IsEncrypted': False})) is False
    assert evidence_overview.backup_encrypted(b'not a plist') is None

    case = Case.create(str(tmp_path / 'case'), 'Encrypted')
    evidence_id = case.add_evidence(evidence)

    def run(**extra):
        items = []
        background.job_leapp(
            {'tool': 'ileapp', 'image_path': evidence,
             'case_folder': case.folder, 'evidence_id': evidence_id,
             'evidence_name': 'iPhone',
             'folder': os.path.join(case.folder, 'modules',
                                    f"run{len(case.module_runs())}"),
             **extra},
            lambda *a, **k: None, items.append, lambda: False)
        return items

    [skipped] = run()
    assert skipped['status'] == 'skipped' and skipped['needs_password']
    assert skipped['backup'] == '/Backup/b.zip'
    assert '(encrypted)' in skipped['input']
    assert not os.path.exists(os.path.join(skipped['folder'], 'seen.json'))

    [wrong] = run(backup_passwords={'/Backup/b.zip': 'guess'},
                  only_inputs=['/Backup/b.zip'])
    assert wrong['status'] == 'failed' and wrong['needs_password']
    assert 'Wrong password' in wrong['message']
    assert not os.path.exists(os.path.join(wrong['folder'], 'seen.json'))

    [done] = run(backup_passwords={'/Backup/b.zip': 'Open-Sesame-42'},
                 only_inputs=['/Backup/b.zip'])
    assert done['status'] == 'complete', done
    with open(os.path.join(done['folder'], 'seen.json')) as handle:
        seen = json.load(handle)
    assert seen['kind'] == 'itunes' and seen['password'] == 'Open-Sesame-42'
    with open(os.path.join(done['folder'], 'run.log'),
              encoding='utf-8') as handle:
        log = handle.read()
    assert 'Open-Sesame-42' not in log
    assert '--itunes_password ********' in log
    assert 'Decrypting the backup with password ********' in log
    assert 'starred the backup password' in log
    with open(os.path.join(done['folder'], 'report', '_HTML', 'index.html'),
              encoding='utf-8') as handle:
        assert handle.read() == ('Manifest.db was successfully decrypted '
                                 'with passcode ********<br>')
    # The tool's output (seen.json, beside it, is the fake's own record of
    # its arguments).
    for base, _dirs, names in os.walk(os.path.join(done['folder'],
                                                   'report')):
        for name in names:
            with open(os.path.join(base, name), 'rb') as handle:
                assert b'Open-Sesame-42' not in handle.read(), name
    # Read with its password: the skipped run and the wrong-password one
    # are gone -- audited, each naming the run that read the backup.
    statuses = [r['status'] for r in case.module_runs()]
    assert statuses == ['complete']
    assert len(done['superseded']) == 2
    removed = [a for a in case.activity()
               if a['action'] == 'external module run removed']
    assert len(removed) == 2 and all('superseded by run id=' in a['detail']
                                     for a in removed)
    recorded = next(r for r in case.module_runs()
                    if r['status'] == 'complete')
    assert recorded['params']['input']['password'].startswith('given')
    case.close()
    for name in os.listdir(case.folder):
        path = os.path.join(case.folder, name)
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                assert b'Open-Sesame-42' not in handle.read(), name


def test_tools_are_offered_only_for_what_an_image_holds(qapp):
    """iLEAPP reads iOS, aLEAPP Android: an Android folder is never offered
    iLEAPP, and an image with neither is offered nothing, saying why."""
    from trace_app.core import evidence_profile
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.viewers.modules_panel import ModulesPanel
    assert evidence_profile.tool_reason(TOOLS['ileapp'], ['ios']) is None
    assert 'holds Android' in evidence_profile.tool_reason(
        TOOLS['ileapp'], ['android'])
    assert 'no Android' in evidence_profile.tool_reason(TOOLS['aleapp'], [])
    found = {'unreadable': False, 'filesystems': ['Logical'], 'systems': [],
             'tool_systems': ['android'], 'logical': True}
    ruled = evidence_profile.not_applicable(found)
    assert 'ileapp' in ruled and 'aleapp' not in ruled
    panel = ModulesPanel()
    tools = [('ileapp', 'iLEAPP 2026.4.4', ('ios',)),
             ('aleapp', 'ALEAPP 2026.4.3', ('android',))]
    panel.set_targets([('p', 'Pixel 3', ['android']),
                       ('i', 'iPhone', ['ios']),
                       ('d', 'Laptop', [])], tools)

    def offered(index):
        panel.evidence_combo.setCurrentIndex(index)
        return [panel.tool_combo.itemData(i)
                for i in range(panel.tool_combo.count())]
    assert offered(0) == ['aleapp']
    assert offered(1) == ['ileapp']
    assert offered(2) == []
    assert not panel.run_button.isEnabled()
    assert 'No installed tool reads this image' in \
        panel.run_button.toolTip()
    assert offered(0) == ['aleapp'] and panel.run_button.isEnabled()
    panel.deleteLater()


def test_the_window_asks_for_a_backup_password_and_runs_it_again(qapp):
    """A run that met an encrypted backup asks its password (a wrong one
    saying so), keeps it for the session, and runs the tool again on that
    backup alone."""
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.main_window import MainWindow
    from tests.conftest import close_window
    window = MainWindow()
    try:
        asked, queued = [], []
        window.ask_backup_password = lambda tool, evidence, backup, wrong='': (
            asked.append((tool, evidence, backup, wrong)) or 'pw')
        window.queue_leapp = lambda key, tool, only=None: queued.append(
            (key, tool, only))
        row = {'key': 'k', 'name': 'iPhone', 'path': 'C:/x/iPhone'}
        window._ask_backup_passwords(TOOLS['ileapp'], row, [
            {'status': 'failed', 'needs_password': True,
             'backup': '/Backup/b.zip', 'message': 'Wrong password'}])
        assert asked == [('iLEAPP', 'iPhone', 'b.zip', 'Wrong password')]
        assert queued == [('k', 'ileapp', ['/Backup/b.zip'])]
        assert window._backup_passwords == {
            (os.path.normpath('C:/x/iPhone'), '/Backup/b.zip'): 'pw'}
    finally:
        close_window(window)


def test_big_artifacts_are_paged_by_rowid_and_kept_out_of_the_timeline(
        tmp_path):
    """iLEAPP's unified log of one sysdiagnose is 21 million rows: paging
    it by OFFSET was quadratic (hours), and copying it into the Timeline
    and Search made a 1.4 GB WAL. Rows are read by rowid, every one once;
    an artifact over the case's limit stays in the tool's database."""
    from trace_app.core.modules import job
    db = sqlite3.connect(str(tmp_path / 'lava.db'))
    db.execute('CREATE TABLE "t" ("a" TEXT)')
    db.executemany('INSERT INTO t (rowid, a) VALUES (?, ?)',
                   [(i * 3 - 7, f"v{i}") for i in range(5000)])
    db.commit()
    artifact = {'tablename': 't', 'columns': [{'name': 'a'}]}
    rows = list(lava.iter_rows(db, artifact, batch=700))
    assert [r for r, _v in rows] == [i * 3 - 7 for i in range(5000)]
    assert rows[10][1] == {'a': 'v10'}
    small = {'name': 'Small', 'record_count': 10}
    huge = {'name': 'Unified log', 'record_count': 21_228_231}
    added, kept = job.split_by_size([small, huge], 250_000)
    assert added == [small] and kept == [('Unified log', 21_228_231)]
    assert job.split_by_size([small, huge], 0) == ([small, huge], [])


def test_progress_follows_the_log_the_tool_writes_as_it_goes(tmp_path):
    """A frozen LEAPP's piped output arrives in blocks (iLEAPP's line for
    artifact 647 came 29 minutes late); its Screen_Output.html is written
    line by line, so progress is read from there, half-written lines
    left for the next look."""
    log = tmp_path / 'Screen_Output.html'
    log.write_text('<html><body>Processing started<br>\n'
                   '[1/9] a [a] artifact started at 10:00:00 UTC<br>\n'
                   'Found 2 records &amp; more<br>\n'
                   '[2/9] b [b] artifact started at 10:00:01 UTC<br>\n'
                   '[3/9] c [c] artifact sta', encoding='utf-8')
    follower = run._Follower(str(log))
    assert follower.newest() == '[2/9] b [b] artifact started at 10:00:01 UTC'
    assert follower.newest() is None
    with open(log, 'a', encoding='utf-8') as handle:
        handle.write('rted at 10:00:02 UTC<br>\n')
    assert follower.newest() == '[3/9] c [c] artifact started at 10:00:02 UTC'
    assert run._Follower(str(tmp_path / 'none')).newest() is None


def test_every_leapp_icon_name_draws_its_own_tabler_icon(qapp):
    """LEAPP artifacts name Feather or Tabler icons. Each now draws its own
    Tabler file (they were folded onto a dozen TRACE categories, and a name
    outside the table -- iOS Build's -- drew nothing); a name TRACE has no
    drawing for gets the generic artifact icon, never none."""
    from trace_app.infra.paths import resource_path
    from trace_app.ui import icons
    for feather, tabler in icons._LEAPP_RENAMED.items():
        assert os.path.isfile(resource_path(f"Icons/tabler/{tabler}.svg")), \
            feather
        assert icons.leapp_icon_name(feather) == \
            f"Icons/tabler/{tabler}.svg"
    assert icons.leapp_icon_name('device-mobile') == \
        "Icons/tabler/device-mobile.svg"
    assert icons.leapp_icon_name('Battery') == "Icons/tabler/battery.svg"
    assert icons.leapp_icon_name('cpu') != icons.leapp_icon_name('battery')
    assert icons.leapp_icon_name('no-such-icon') == icons.LEAPP_ARTIFACT
    assert icons.leapp_icon_name('') == icons.LEAPP_ARTIFACT
    assert not icons.leapp_icon({'icon': 'smartphone'}).isNull()
    assert icons.leapp_category_icon([]) is None
    assert not icons.leapp_category_icon(
        [{'icon': 'wifi'}, {'icon': 'map'}, {'icon': 'map'}]).isNull()


def test_the_external_modules_dialog_says_installed_at_once(
        qapp, fake_installed, monkeypatch):
    """GitHub is asked for releases as the dialog opens; until it answers
    the button said "Install" -- for a second an installed tool looked
    missing. What is installed shows from the start."""
    from trace_app.ui.dialogs import external_modules
    monkeypatch.setattr(external_modules.ExternalModulesDialog,
                        'check_releases', lambda self: None)
    dialog = external_modules.ExternalModulesDialog()
    try:
        ileapp = dialog._rows['ileapp']
        assert ileapp['install'].text() == 'Installed'
        assert not ileapp['install'].isEnabled()
        assert ileapp['remove'].isEnabled()
        assert ileapp['state'].text().startswith('Installed: ')
        # Five tools no longer push Close off the screen: the list scrolls.
        available = dialog.screen().availableGeometry().height()
        assert dialog.height() <= available
        assert dialog.scroll.widget().sizeHint().height() > 0
        aleapp = dialog._rows['aleapp']
        assert aleapp['install'].text() == 'Install'
        assert not aleapp['remove'].isEnabled()
    finally:
        dialog.deleteLater()


def test_quick_triage_drops_a_backups_skipped_run_once_it_is_read(qapp):
    """Without a case the session's runs are the list: the skipped run of
    an encrypted backup goes when the backup is read with its password."""
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.main_window import MainWindow
    from tests.conftest import close_window
    window = MainWindow()
    try:
        window._report_dialogs = False
        label = 'iTunes backup in b.zip (encrypted)'
        window._session_module_runs = [
            {'tool': 'iLEAPP', 'version': '1', 'folder': 'x (3)',
             'status': 'skipped', 'needs_password': True, 'input': label,
             'evidence': 'iPhone'},
            {'tool': 'iLEAPP', 'version': '1', 'folder': 'x (1)',
             'status': 'complete', 'input': '1 loose file(s)',
             'evidence': 'iPhone', 'report': 'none'}]
        row = {'key': 'k', 'name': 'iPhone', 'path': 'C:/x/iPhone'}
        window._leapp_finished(TOOLS['ileapp'], row, [
            {'tool': 'iLEAPP', 'version': '1', 'folder': 'y',
             'status': 'complete', 'input': label, 'backup': '/b.zip',
             'report': 'none', 'rows': 3}], None)
        assert [s['folder'] for s in window._session_module_runs] == \
            ['y', 'x (1)']
    finally:
        close_window(window)


def test_a_key_the_tool_wants_is_asked_for_and_given_as_a_file(
        tmp_path, monkeypatch):
    """DLEAPP reads Signal Desktop only with its key. A run that stages a
    Signal profile without one says it wanted it; given, the key goes to
    the tool as a file of the run's own -- path on the command line, never
    the key -- removed when the run ends, starred wherever the tool echoed
    it, and the run without it is forgotten."""
    from trace_app.core import background
    from trace_app.core.case import Case
    tool, record = make_fake_tool(str(tmp_path / 'tool'))
    real = spec.TOOLS['dleapp']
    fake = spec.ToolSpec(**{**tool.__dict__, 'id': 'dleapp',
                            'suits': real.suits, 'secrets': real.secrets})
    monkeypatch.setitem(spec.TOOLS, 'dleapp', fake)
    monkeypatch.setattr(install, 'installed',
                        lambda s, version=None: record
                        if s.id == 'dleapp' else None)
    evidence = tmp_path / 'laptop'
    profile = evidence / 'Users' / 'alice' / 'AppData' / 'Roaming' / \
        'Signal' / 'sql'
    profile.mkdir(parents=True)
    (profile / 'db.sqlite').write_bytes(b'encrypted' * 100)
    case = Case.create(str(tmp_path / 'case'), 'Keys')
    evidence_id = case.add_evidence(str(evidence))

    def run(**extra):
        items = []
        background.job_leapp(
            {'tool': 'dleapp', 'image_path': str(evidence),
             'case_folder': case.folder, 'evidence_id': evidence_id,
             'evidence_name': 'laptop',
             'folder': os.path.join(case.folder, 'modules',
                                    f"run{len(case.module_runs())}"),
             **extra},
            lambda *a, **k: None, items.append, lambda: False)
        return items

    [first] = run()
    assert first['status'] == 'complete'
    assert first['secrets_wanted'] == ['signal']
    [second] = run(tool_keys={'signal': 'K3y-Signal-0042'})
    assert second['status'] == 'complete' and not second['secrets_wanted']
    with open(os.path.join(second['folder'], 'seen.json')) as handle:
        seen = json.load(handle)
    assert seen['signal_key'] == 'K3y-Signal-0042'
    assert seen['signal_key_file'].startswith(second['folder'])
    assert not os.path.exists(seen['signal_key_file'])
    with open(os.path.join(second['folder'], 'run.log'),
              encoding='utf-8') as handle:
        log = handle.read()
    assert 'K3y-Signal-0042' not in log
    assert 'Signal database opened with key ********' in log
    [kept] = case.module_runs()
    assert kept['id'] == second['run_id']
    assert kept['params']['input']['signal_key'] == 'given by the examiner'
    case.close()
    for name in os.listdir(case.folder):
        path = os.path.join(case.folder, name)
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                assert b'K3y-Signal-0042' not in handle.read(), name


def test_the_window_asks_a_wanted_key_and_runs_the_tool_again(qapp):
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.main_window import MainWindow
    from tests.conftest import close_window
    window = MainWindow()
    try:
        asked, queued = [], []
        window.ask_tool_key = lambda tool, evidence, what, found: (
            asked.append((tool, found)) or 'the-key')
        window.queue_leapp = lambda key, tool, only=None: queued.append(
            (key, tool, only))
        row = {'key': 'k', 'name': 'laptop', 'path': 'C:/x/laptop'}
        window._ask_tool_keys(TOOLS['dleapp'], row, ['signal'])
        assert asked == [('DLEAPP', 'a Signal Desktop profile')]
        assert queued == [('k', 'dleapp', None)]
        assert window._tool_keys == {
            (os.path.normpath('C:/x/laptop'), 'dleapp', 'signal'):
            'the-key'}
    finally:
        close_window(window)


def test_fit_counts_what_specific_patterns_name_even_inside_zips(tmp_path):
    """A warrant return or a car has no system for TRACE to find: a tool
    fits where its own patterns name files -- only patterns that spell
    something out (RLEAPP's `*/*.*` names everything), and inside the zips
    a return arrives as."""
    from trace_app.core.modules import fit
    assert fit.literal_length('**/*-account-creation-ip.txt') == 20
    assert fit.literal_length('*/[Nn][Tt][Uu][Ss][Ee][Rr].[Dd][Aa][Tt]') == 9
    assert fit.literal_length('*/*.*') == 0
    patterns = ['*/*.*', '*/notes/*.txt', '**/fordlogs/pas_debug.log*']
    assert fit.specific(patterns) == ['**/fordlogs/pas_debug.log*']
    archive = tmp_path / 'return.zip'
    with zipfile.ZipFile(archive, 'w') as zipped:
        zipped.writestr('X/fordlogs/pas_debug.log', 'speed')
        zipped.writestr('X/readme.txt', 'none')
    volumes = [{'offset': 0, 'files': [
        ('/car', 'sync.zip', 10, None, False),
        ('/car/fordlogs', 'pas_debug.log.1', 5, None, False),
        ('/car/fordlogs', 'pas_debug.log.2', 5, None, True),     # deleted
        ('/docs', 'notes.txt', 5, None, False)]}]
    found, examples = fit.count(
        volumes, patterns,
        open_file=lambda offset, path: open(archive, 'rb'))
    assert found == 2
    assert examples == ['/car/sync.zip!/X/fordlogs/pas_debug.log',
                        '/car/fordlogs/pas_debug.log.1']
    assert fit.count(volumes, ['*/*.*']) == (0, [])


def test_an_archive_a_tools_patterns_name_inside_is_an_input(tmp_path):
    from trace_app.core.modules import inputs, stage
    archive = tmp_path / 'SYNTH001.zip'
    with zipfile.ZipFile(archive, 'w') as zipped:
        zipped.writestr('SYNTH001/messages/20251201.csv', 'a,b')
    matcher = stage.Matcher(['*/SYNTH001/messages/2*.csv'])
    with open(archive, 'rb') as handle:
        kind, system = inputs.judge(handle, 'SYNTH001.zip', ('return',),
                                    matcher)
    assert (kind, system) == ('zip', inputs.PATTERNS)
    with open(archive, 'rb') as handle:
        assert inputs.judge(handle, 'SYNTH001.zip', ('return',)) == \
            (None, None)
    assert inputs.label({'kind': 'zip', 'system': inputs.PATTERNS,
                         'name': 'SYNTH001.zip'}) == \
        'files it reads in SYNTH001.zip'


def test_an_image_trace_cannot_open_is_given_to_the_tool_itself(tmp_path):
    """A QNX6 head unit: TRACE names the file system from its superblock,
    counts the image as a car's, and a tool reading images (`-t raw`) is
    given the image itself -- nothing copied."""
    from trace_app.core import evidence_profile
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.modules import inputs
    image = tmp_path / 'headunit.bin'
    data = bytearray(409600)
    data[0x2000:0x2004] = b'\x22\x11\x19\x68'
    image.write_bytes(bytes(data))
    handler = ImageHandler(str(image))
    try:
        assert handler.load_image()
        assert evidence_profile.unreadable_signatures(handler) == \
            [(0, 'QNX6')]
        assert 'vehicle' in evidence_profile.tool_systems(handler)
        vleapp, aleapp = spec.TOOLS['vleapp'], spec.TOOLS['aleapp']
        assert evidence_profile.tool_reason(
            vleapp, evidence_profile.tool_systems(handler)) is None
        raw = inputs.raw_input(vleapp, handler, str(image), False)
        assert raw['kind'] == 'raw' and raw['os_path'] == str(image)
        assert inputs.label(raw) == 'the image itself (QNX6)'
        assert inputs.raw_input(aleapp, handler, str(image), False) is None
    finally:
        handler.close_resources()


def test_a_big_run_fills_the_modules_tab_quickly(qapp):
    """Items keep indices, not the run: a run dict as item data was turned
    into a Qt map whole -- every artifact and its column map -- for each
    item, so a 484-artifact iLEAPP run took 4.6 s per redraw and the
    window froze for 20 s while a case opened (four redraws)."""
    import time
    from PySide6.QtCore import Qt
    from trace_app.ui.viewers.modules_panel import ModulesPanel
    columns = {f'column_{n}': {'type': 'text', 'label': f'Column {n}'}
               for n in range(40)}
    artifacts = [{'category': f'Category {n // 4}', 'name': f'Artifact {n}',
                  'tablename': f'table_{n}', 'record_count': n,
                  'icon': 'message-circle', 'column_map': columns}
                 for n in range(600)]
    run = {'key': 1, 'run_id': 1, 'tool': 'iLEAPP', 'version': '2026.4.4',
           'evidence_id': 1, 'evidence': 'phone', 'started': '',
           'status': 'complete', 'message': '', 'report': '', 'folder': '',
           'manifest': '', 'input': {}, 'coverage': {},
           'artifacts': artifacts}
    panel = ModulesPanel()
    try:
        started = time.perf_counter()
        panel.set_runs([run])
        panel.set_runs([run])
        assert time.perf_counter() - started < 2.0
        head = panel.tree.topLevelItem(0)
        node = head.child(3).child(1)
        assert head.data(0, Qt.UserRole) == {'run': 0}
        assert node.data(0, Qt.UserRole) == {'run': 0, 'artifact': 13}
        found = panel._item_data(node)
        assert found['run'] is run and found['artifact'] is artifacts[13]
        assert panel._item_data(head)['artifact'] is None
    finally:
        panel.deleteLater()

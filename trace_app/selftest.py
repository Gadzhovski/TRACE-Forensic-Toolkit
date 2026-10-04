"""Check that this copy of TRACE -- above all a packaged build -- works.

    TRACE --self-test REPORT.json [IMAGE ...]

A packaged application fails differently from source: a data file, a native
library or a Qt plugin left out of the bundle does not stop the build, it
surfaces as a missing icon, a file type nobody can identify, or an E01 that
will not open, the first time an examiner needs it. This exercises each of
those through the code paths the application itself uses, then, for every
image given, the full case workflow -- create, add evidence, verify, analyse,
index, search, reopen, and open the main window on it -- and records a
manifest of what TRACE reads from each image (core/manifest.py).

The build script compares those manifests with the ones the test suite
checked by hand (tests/manifests/), so a packaged build is shown to read
evidence exactly as the source does. It is also a validation step an examiner
can run on an installed copy against a known image.

Everything runs in a temporary sandbox -- config, data, the case -- which is
deleted afterwards: a self-test leaves nothing on the machine. The report is
the only output, and the exit status is 0 only if every check passed.
"""

import io
import json
import os
import platform
import shutil
import sys
import tempfile
import time
import traceback


def main(argv):
    if not argv:
        sys.stderr.write("usage: TRACE --self-test REPORT.json [IMAGE ...]\n")
        return 2
    report_path = os.path.abspath(argv[0])
    images = [os.path.abspath(p) for p in argv[1:]]

    sandbox = tempfile.mkdtemp(prefix='trace-selftest-')
    _isolate(sandbox)
    report = {'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'checks': [], 'manifests': {}}
    try:
        _run(report, images, sandbox)
    except Exception:                       # the harness itself must report
        report['checks'].append({'name': 'self-test', 'ok': False,
                                 'detail': traceback.format_exc()})
    finally:
        report['passed'] = all(c['ok'] for c in report['checks'])
        with open(report_path, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=1, sort_keys=True)
        shutil.rmtree(sandbox, ignore_errors=True)
    return 0 if report['passed'] else 1


def _isolate(sandbox):
    """Point every per-user location at the sandbox before TRACE reads one,
    and run Qt without a display."""
    for name in ('APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
                 'HOME', 'USERPROFILE'):
        os.environ[name] = os.path.join(sandbox, 'home', name.lower())
        os.makedirs(os.environ[name], exist_ok=True)
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def _run(report, images, sandbox):
    from trace_app import __version__
    report['trace'] = __version__
    report['python'] = sys.version.split()[0]
    report['platform'] = f"{sys.platform} {platform.machine()} " \
                         f"{platform.platform()}"
    report['frozen'] = bool(getattr(sys, 'frozen', False))

    def check(name):
        def wrap(function):
            started = time.monotonic()
            try:
                detail = function()
                ok = True
            except Exception:
                detail, ok = traceback.format_exc(), False
            report['checks'].append({
                'name': name, 'ok': ok, 'detail': detail,
                'seconds': round(time.monotonic() - started, 2)})
            return function
        return wrap

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(['TRACE', '-platform',
                                                   os.environ['QT_QPA_PLATFORM']])

    @check('engines')
    def _():
        import pyewf
        import pytsk3
        return f"Sleuth Kit {pytsk3.TSK_VERSION_STR}, libewf {pyewf.get_version()}"

    @check('containers: VMDK, VHD/VHDX, QCOW, BitLocker, shadow copies, PST')
    def _():
        import pybde
        import pypff
        import pyqcow
        import pyvhdi
        import pyvmdk
        import pyvshadow
        return ', '.join(f"{m.__name__} {m.get_version()}" for m in
                         (pyvmdk, pyvhdi, pyqcow, pybde, pyvshadow,
                          pypff))

    @check('volumes and Windows databases: FileVault, APFS, LUKS, LVM, ESE, '
           'index.dat')
    def _():
        import pyesedb
        import pyfsapfs
        import pyfvde
        import pyluksde
        import pymsiecf
        import pyvslvm
        return ', '.join(f"{m.__name__} {m.get_version()}" for m in
                         (pyfvde, pyfsapfs, pyluksde, pyvslvm, pyesedb,
                          pymsiecf))

    @check('YARA rules compile and match (yara-x)')
    def _():
        import platform
        if sys.platform == 'win32' and platform.machine().upper() == 'ARM64':
            return 'not built for Windows on ARM (shown as unavailable)'
        import yara_x
        rules = yara_x.compile('rule t { strings: $a = "TRACE" '
                               'condition: $a }')
        assert rules.scan(b'xx TRACE xx').matching_rules
        return 'ok'

    @check('every feature this platform should have is available')
    def _():
        import platform
        from trace_app.infra import capabilities
        expected_missing = set()
        if sys.platform == 'win32' and platform.machine().upper() == 'ARM64':
            expected_missing = {'yara', 'heic'}
            # Their wheels for Windows on ARM start at these Pythons.
            if sys.version_info < (3, 12):
                expected_missing.add('sigma')
            if sys.version_info < (3, 11):
                expected_missing.add('ios_encrypted')
        missing = [c.key for c in capabilities.CAPABILITIES
                   if not c.available and c.key not in expected_missing]
        assert not missing, f"unavailable: {', '.join(missing)}"
        return f"{len(capabilities.CAPABILITIES)} features"

    @check('libmagic identifies content')
    def _():
        import magic
        from trace_app.infra.preflight import libmagic_identity
        identity = libmagic_identity()
        assert identity, "libmagic did not load"
        reader = magic.Magic(mime=True)
        found = {kind: reader.from_buffer(data) for kind, data in _samples().items()}
        want = {'png': 'image/png', 'pdf': 'application/pdf',
                'zip': 'application/zip'}
        assert found == want, found
        return f"libmagic {identity[0]} from {identity[1]}"

    @check('background jobs run in a child process')
    def _():
        # Analysis, indexing and carving run in a child process; in a frozen
        # build that child is this executable again, which works only if
        # main.py calls multiprocessing.freeze_support() first.
        import queue as queue_module
        from trace_app.core import background
        process, channel, _stop = background.start('ping', {'value': 42})
        seen = {}
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                message = channel.get(timeout=1)
            except queue_module.Empty:
                assert process.is_alive() or not channel.empty(), \
                    f"the child exited with code {process.exitcode}"
                continue
            seen[message[0]] = message
            if message[0] == 'done':
                break
        process.join(30)
        assert 'done' in seen, "no answer from the child process"
        assert seen['done'][2] == '', seen['done'][2]
        assert seen.get('item', (None, {}))[1].get('pong') == 42, seen
        return f"started, imported the engines, answered ({process.name})"

    @check('bundled resources')
    def _():
        from PySide6.QtGui import QIcon, QPixmap
        from trace_app.infra.paths import resource_path
        logo = QPixmap(resource_path('Icons/logo.png'))
        assert not logo.isNull(), "Icons/logo.png did not load"
        for theme in ('dark', 'light'):
            with open(resource_path('styles', f'{theme}_theme.qss'),
                      encoding='utf-8') as handle:
                assert handle.read().strip(), f"{theme} theme is empty"
        svg = QIcon(resource_path('Icons/devices/computer-laptop.svg'))
        assert not svg.pixmap(32, 32).isNull(), "SVG icons do not render"
        from trace_app.core import geo
        land = geo.land_rings(resource_path('resources', 'world_land.json'))
        assert len(land) > 100, "the Map tab's offline outline is missing"
        return "logo, both themes, SVG icons, the map's world outline"

    @check('image formats')
    def _():
        from PySide6.QtGui import QImageReader
        from PIL import Image
        qt = {bytes(f).decode() for f in QImageReader.supportedImageFormats()}
        missing = {'png', 'jpg', 'gif', 'bmp', 'ico', 'svg', 'tiff', 'webp'} - qt
        assert not missing, f"Qt cannot read {sorted(missing)}"
        for kind in ('AVIF', 'JPEG2000', 'WEBP'):
            buffer = io.BytesIO()
            Image.new('RGB', (16, 16), (200, 30, 30)).save(buffer, kind)
            assert Image.open(io.BytesIO(buffer.getvalue())).size == (16, 16)
        return f"Qt: {len(qt)} formats; Pillow: AVIF, JPEG 2000, WebP"

    @check('PDF rendering')
    def _():
        import pymupdf
        document = pymupdf.open()
        page = document.new_page()
        page.insert_text((72, 72), "TRACE self-test")
        assert page.get_pixmap().width > 0
        assert "TRACE self-test" in page.get_text()
        return f"PyMuPDF {pymupdf.__version__}"

    @check('archives')
    def _():
        import py7zr
        from trace_app.core.archives import list_members, read_member
        buffer = io.BytesIO()
        with py7zr.SevenZipFile(buffer, 'w') as archive:
            archive.writestr(b'evidence', 'inside.txt')
        members = [m['name'] for m in list_members(buffer.getvalue())]
        assert members == ['inside.txt'], members
        content = read_member(buffer.getvalue(), 'inside.txt')
        assert content == b'evidence', content
        return "7z read in memory"

    @check('multimedia')
    def _():
        from PySide6.QtMultimedia import QMediaFormat, QMediaPlayer
        QMediaPlayer()
        formats = QMediaFormat().supportedFileFormats(QMediaFormat.Decode)
        assert formats, "no media backend: audio and video cannot play"
        return f"{len(formats)} container formats"

    @check('other libraries')
    def _():
        import certifi
        import chardet
        import olefile  # noqa: F401
        from Registry import Registry  # noqa: F401
        import sqlite3
        assert os.path.isfile(certifi.where()), "no CA bundle: HTTPS will fail"
        assert chardet.detect('Привет мир'.encode('cp1251'))['encoding']
        db = sqlite3.connect(':memory:')
        db.execute("CREATE VIRTUAL TABLE t USING fts5(body)")
        if sys.platform == 'win32':
            import pycaw  # noqa: F401
        return f"SQLite {sqlite3.sqlite_version} with FTS5"

    if images:
        _case_workflow(check, report, images, sandbox, app)


def _case_workflow(check, report, images, sandbox, app):
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.manifest import build_manifest

    folder = os.path.join(sandbox, 'cases', 'Self-test case')

    for path in images:
        name = os.path.basename(path)

        @check(f'manifest: {name}')
        def _():
            manifest = build_manifest(path)
            report['manifests'][name] = manifest
            return f"{sum(len(v['entries']) for v in manifest['volumes'])} entries"

        if name.lower().endswith('.e01'):
            @check(f'E01 stored hash: {name}')
            def _():
                handler = ImageHandler(path)
                try:
                    result = handler.calculate_hashes()
                finally:
                    handler.close_resources()
                assert result['stored_md5'], "no acquisition MD5 read"
                assert result['computed_md5'] == result['stored_md5'], result
                return f"MD5 {result['computed_md5']}"

    @check('case: create, add, verify, analyse, index, search')
    def _():
        from trace_app.core.analysis import MODULES, analyse_evidence
        from trace_app.core.indexer import index_evidence
        from trace_app.core.search_index import SearchIndex

        case = Case.create(folder, 'Self-test case', examiner='self-test')
        try:
            counts = []
            index = SearchIndex(case.folder)
            for path in images:
                evidence = case.add_evidence(path)
                handler = ImageHandler(path)
                assert handler.loaded, f"{path} did not open"
                try:
                    counts.append(analyse_evidence(handler, case, evidence,
                                                   MODULES))
                    index_evidence(handler, index, evidence)
                finally:
                    handler.close_resources()
            # Every image's first named file must be found by name.
            found = 0
            for manifest in report['manifests'].values():
                names = [e['path'].rsplit('/', 1)[-1]
                         for v in manifest['volumes'] for e in v['entries']
                         if e.get('type') == 'file'
                         and not e['path'].rsplit('/', 1)[-1].startswith('$')]
                if names:
                    hits = index.search(f'name:"{names[0]}"')
                    assert any(h['name'] == names[0] for h in hits), \
                        f"search did not find {names[0]}"
                    found += 1
            index.close()
            outcomes = case.verify_evidence()
            assert len(outcomes) == len(images), outcomes
        finally:
            case.close()
        return (f"analysed {counts} files; {found} found by name search; "
                f"{len(images)} evidence verified")

    @check('case: reopen')
    def _():
        case = Case.open(folder)
        try:
            evidence = case.evidence()
            assert len(evidence) == len(images), evidence
            summary = case.analysis_summary()
        finally:
            case.close()
        return f"{len(evidence)} evidence, analysis {summary}"

    @check('main window on the case')
    def _():
        from trace_app.ui.dialogs import message
        from trace_app.ui.main_window import MainWindow
        for answer in ('information', 'warning', 'critical'):
            setattr(message, answer, lambda *a, **k: None)
        message.question = lambda *a, **k: True

        window = MainWindow(case=Case.open(folder))
        try:
            deadline = time.monotonic() + 120
            while len(window.evidence_files) < len(images):
                assert time.monotonic() < deadline, "evidence did not load"
                app.processEvents()
                time.sleep(0.02)
            window.refresh_analysis_views()
            app.processEvents()
            roots = window.tree_viewer.topLevelItemCount()
            assert roots >= len(images), f"{roots} tree roots"
        finally:
            window.cleanup_resources()
            window.deleteLater()
            app.processEvents()
        return f"{roots} tree roots"


def _samples():
    import zipfile
    from PIL import Image
    png = io.BytesIO()
    Image.new('RGB', (8, 8)).save(png, 'PNG')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as package:
        package.writestr('a.txt', b'x')
    return {'png': png.getvalue(),
            'pdf': b'%PDF-1.4\n1 0 obj\n<<>>\nendobj\n',
            'zip': archive.getvalue()}

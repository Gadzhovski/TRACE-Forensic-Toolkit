"""Shared test setup.

Two rules every test relies on:

* **Isolation.** TRACE keeps its config (theme, VirusTotal key, recent cases)
  and its log in per-user directories. Before anything from TRACE is imported,
  those directories are pointed at a throwaway folder, so a test run can never
  read or overwrite the examiner's own settings -- and nothing personal can
  end up in a public CI log.
* **Images are required in CI.** Test data lives in test_images/, one
  folder per group (tools/testdata). Locally, a test whose data is not here
  is skipped, saying how to get it. In CI (TRACE_REQUIRE_IMAGES=1) a missing
  image of the CI set fails instead, so CI cannot pass by quietly testing
  nothing; data CI never has (local, NIST, private) always skips.

TRACE_TEST_TIER limits what a run reads (tools/run_tests.py sets it):
'quick' skips every test that asks for data, 'ci' skips what CI does not
have -- so a local 'ci' run is the CI run -- and 'full' (the default) reads
everything present.
"""

import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools import testdata  # noqa: E402

_SANDBOX = tempfile.mkdtemp(prefix='trace-tests-')
for variable, sub in (('APPDATA', 'roaming'), ('LOCALAPPDATA', 'local'),
                      ('XDG_CONFIG_HOME', 'config'),
                      ('XDG_DATA_HOME', 'data'), ('HOME', 'home')):
    path = os.path.join(_SANDBOX, sub)
    os.makedirs(path, exist_ok=True)
    os.environ[variable] = path
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_SANDBOX, ignore_errors=True)


def _in_ci(name):
    """Whether CI has the image `name`: the downloaded CI set, the carving
    corpus it builds, and on Linux the images the kernel's own tools make
    (tools/testdata/build: Btrfs with deleted files, md RAID, LUKS + LVM)."""
    group = testdata.group_of(name)
    if group in ('ci', 'corpus'):
        return True
    return group == 'built' and sys.platform.startswith('linux')


def _missing(message, required):
    if required and testdata.TIER != 'quick' and             os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
        pytest.fail(message)
    pytest.skip(message)


def image_path(name):
    """Path to a test image, or skip/fail the test if it is missing.

    With TRACE_REQUIRE_IMAGES=1 (CI) a missing image of the CI set fails;
    the others (local, NIST, private) skip wherever they are absent.
    """
    path = testdata.locate(name)
    if path is None:
        _missing(f"{testdata.how_to_get(name)} -- not in test_images/",
                 _in_ci(name))
    return path


def data_path(group, *parts):
    """A file or folder of a data group: 'samples' (artifact files, in
    CI), 'corpus' (the carving corpus's sources, in CI), 'nist', 'local',
    'private' (never in CI). Skips -- or in CI fails, for CI groups -- when
    it is not here."""
    base = {'samples': testdata.SAMPLES, 'corpus': testdata.CORPUS_SAMPLES,
            'nist': testdata.NIST, 'local': testdata.LOCAL,
            'private': testdata.PRIVATE}[group]
    path = os.path.join(base, *parts)
    if not os.path.exists(path):
        _missing(f"{os.path.join(group, *parts)} is not in test_images/ -- "
                 f"{testdata.HOW.get(group, testdata.HOW['local'])}",
                 group in ('samples', 'corpus'))
    return path


@pytest.fixture(scope='session')
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def pump(app, seconds=0.2, until=None):
    """Process Qt events for up to `seconds`, or until `until()` is true."""
    import time
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        if until is not None and until():
            return True
        time.sleep(0.01)
    return until() if until is not None else True


def pytest_runtest_logreport(report):
    """On GitHub Actions, each failure is also an annotation: the run's
    summary then says which test failed and why, without its full log."""
    if os.environ.get('GITHUB_ACTIONS') != 'true' or not report.failed:
        return
    text = str(report.longrepr).strip().splitlines()
    detail = ' | '.join(line.strip() for line in text[-6:] if line.strip())
    detail = detail.replace('%', '%25').replace('\r', '').replace('\n', ' ')
    print(f"\n::error title={report.nodeid} ({report.when})::{detail[:900]}",
          flush=True)

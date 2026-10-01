"""Shared test setup.

Two rules every test relies on:

* **Isolation.** TRACE keeps its config (theme, VirusTotal key, recent cases)
  and its log in per-user directories. Before anything from TRACE is imported,
  those directories are pointed at a throwaway folder, so a test run can never
  read or overwrite the examiner's own settings -- and nothing personal can
  end up in a public CI log.
* **Images are required in CI.** Locally, a test whose public image has not
  been downloaded is skipped with a pointer to tools/fetch_test_images.py. In
  CI (TRACE_REQUIRE_IMAGES=1) it fails instead, so CI cannot pass by quietly
  testing nothing.
"""

import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE_DIR = os.path.join(ROOT, 'test_images')
sys.path.insert(0, ROOT)

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


def image_path(name):
    """Path to a public test image, or skip/fail the test if it is missing."""
    path = os.path.join(IMAGE_DIR, name)
    if not os.path.exists(path):
        message = (f"{name} is not in test_images/ -- run "
                   f"'python tools/fetch_test_images.py'")
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
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

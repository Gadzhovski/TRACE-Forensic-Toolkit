"""The installers' last step (trace_app/infra/install_check.py): in a
working install nothing is reported; a module that does not load is named
with its error, and the exit status says so."""

import subprocess
import sys

from trace_app.infra import install_check


def test_a_working_install_reports_nothing():
    assert install_check.problems() == []
    done = subprocess.run([sys.executable, '-m',
                           'trace_app.infra.install_check'],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip() == ''


def test_a_module_that_does_not_load_is_named(monkeypatch):
    monkeypatch.setattr(install_check, 'MODULES',
                        install_check.MODULES + ('no_such_engine_xyz',))
    found = install_check.problems()
    assert len(found) == 1
    assert found[0].startswith('no_such_engine_xyz: ModuleNotFoundError')
    assert install_check.main() == 1

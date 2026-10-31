"""The real LEAPPs -- iLEAPP, aLEAPP, RLEAPP, VLEAPP, DLEAPP -- installed
from their GitHub releases and run by TRACE on their own test fixtures
(full tier: it downloads ~300 MB).

The versions installed are the ones this TRACE was tested with
(spec.tested_version); the fixtures are pinned in tools/testdata/samples.py
-- iLEAPP's iOS 15 SMS database with its attachments, aLEAPP's Android 15
mmssms.db. The counts are what those tools report for them (their own
record_count, checked against the rows TRACE reads), so a release that
reads them differently shows here.
"""

import os
import zipfile

import pytest

from tests.conftest import data_path

pytestmark = pytest.mark.skipif(
    os.environ.get('TRACE_TEST_TIER', 'full') != 'full',
    reason="downloads iLEAPP and aLEAPP (full tier)")


@pytest.fixture(scope='module')
def modules_folder(tmp_path_factory):
    """The tools installed once for the module's tests, in a folder of
    their own."""
    from trace_app.core import settings
    from trace_app.core.modules import install
    from trace_app.core.modules.spec import TOOLS
    folder = tmp_path_factory.mktemp('modules')
    values = settings.read_user()
    values['modules_folder'] = str(folder)
    # Saved, not patched: the job's child process reads the settings file.
    settings.save_user(values)
    for spec in TOOLS.values():
        record = install.install(spec, spec.tested_version)
        assert record['version'] == spec.tested_version
    yield folder
    values['modules_folder'] = ''
    settings.save_user(values)


def _unzipped(name, folder):
    with zipfile.ZipFile(data_path('samples', name)) as zipped:
        zipped.extractall(folder)
    return str(folder)


@pytest.mark.parametrize('tool, fixture, expected', [
    ('ileapp', 'ileapp-sms-josh_ios15_ffs.zip',
     {'SMS': 48, 'SMS - Missing ROWIDs': 1}),
    ('aleapp', 'aleapp-smsmms-anne_a15.zip',
     {'SMS Messages': 25, 'MMS Messages': 67, 'SMS and MMS Messages': 92,
      'MMS Attachments': 10})])
def test_the_real_tool_runs_on_staged_files_and_its_rows_are_read(
        modules_folder, tmp_path, tool, fixture, expected):
    from trace_app.core import background, timeline
    from trace_app.core.case import Case
    from trace_app.core.modules import lava
    from trace_app.core.search_index import SearchIndex
    evidence = _unzipped(fixture, tmp_path / 'evidence')
    case = Case.create(str(tmp_path / 'case'), tool)
    evidence_id = case.add_evidence(evidence)
    items = []
    background.job_leapp(
        {'tool': tool, 'image_path': evidence, 'case_folder': case.folder,
         'evidence_id': evidence_id, 'evidence_name': fixture,
         'folder': os.path.join(case.folder, 'modules', tool)},
        lambda *a, **k: None, items.append, lambda: False)
    summary = items[0]
    assert summary['status'] == 'complete', summary
    try:
        run = case.module_runs()[0]
        artifacts = {a['name']: a for a in case.module_artifacts(run['id'])}
        for name, rows in expected.items():
            assert artifacts[name]['row_count'] == rows, name
        connection = lava.connect(os.path.join(run['path'], 'report'))
        try:
            for name in expected:
                artifact = artifacts[name]
                assert lava.count(connection, artifact) == \
                    artifact['row_count']
        finally:
            connection.close()
        events = [e for e in timeline.events(case._db,
                                             timeline.default_filters())
                  if e['source'] == 'modules']
        assert events
        _sorted_into_activity(case, run)
        index = SearchIndex(case.folder)
        try:
            assert summary['indexed'] == index._db.execute(
                "SELECT count(*) FROM indexed_items WHERE kind = 'module'"
            ).fetchone()[0]
        finally:
            index.close()
    finally:
        case.close()


def _zip_in_folder(name, folder, place):
    """The fixture zip as it arrives: a file in the evidence folder (a
    provider's return, a vehicle tool's export)."""
    import shutil
    target = os.path.join(str(folder), *place.split('/'))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copy(data_path('samples', name), target)
    return str(folder)


def _linux_root(folder):
    """A small Linux system as folder evidence: what DLEAPP reads."""
    files = {
        'etc/os-release': 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'
                          'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
        'etc/hostname': 'workstation\n',
        'etc/passwd': 'root:x:0:0:root:/root:/bin/bash\n'
                      'alice:x:1000:1000:Alice:/home/alice:/bin/bash\n',
        'etc/group': 'root:x:0:\nsudo:x:27:alice\n',
        'home/alice/.bash_history': 'ls -la\nssh bob@10.0.0.5\n',
        'var/log/auth.log': 'Oct 15 10:00:01 workstation sshd[100]: '
                            'Accepted password for alice from 10.0.0.9 '
                            'port 51000 ssh2\n'}
    for relative, text in files.items():
        path = os.path.join(str(folder), *relative.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
    return str(folder)


@pytest.mark.parametrize('tool, make, expected, given', [
    # A return's zip is the input itself (-t zip): what its members are,
    # not the zip's name, says RLEAPP reads it.
    ('rleapp', lambda folder: _zip_in_folder(
        'rleapp-synchronoss-messages.zip', folder, 'Verizon/SYNTH001.zip'),
     {'Synchronoss - Calls': 2, 'Synchronoss - MMS Media Received': 6,
      'Synchronoss - MMS Media Sent': 1,
      'Synchronoss - Messages (SMS and MMS)': 12}, 'files it reads in'),
    ('vleapp', lambda folder: _zip_in_folder(
        'vleapp-pasdegeo-sync4.zip', folder, 'sync4.zip'),
     # VLEAPP 2026.4.4 named these 'PAS Debug Log - ...' (2026.4.3:
     # 'Ford - PAS ...'); the rows are the same.
     {'PAS Debug Log - Dev Loc Results': 24328,
      'PAS Debug Log - Outside Temperature': 165,
      'PAS Debug Log - Transmission Status': 84,
      'PAS Debug Log - Vehicle Info': 1,
      'PAS Debug Log - Vehicle Speed': 4}, 'files it reads in'),
    ('dleapp', _linux_root,
     {'User Accounts (passwd)': 2, 'SSH Server Log': 1,
      'Linux System Information': 5}, 'loose file'),
])
def test_the_other_leapps_run_on_what_suits_them(modules_folder, tmp_path,
                                                 tool, make, expected,
                                                 given):
    """RLEAPP on a warrant return, VLEAPP on a car's export, DLEAPP on a
    computer: each found by what suits it (core/modules/fit,
    evidence_profile.tool_systems), run, and its rows read."""
    from trace_app.core import background, evidence_profile
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.modules.spec import TOOLS
    evidence = make(tmp_path / 'evidence')
    items = []
    background.job_module_fit(
        {'images': [{'path': evidence}], 'tools': ['rleapp', 'vleapp']},
        lambda *a, **k: None, items.append, lambda: False)
    handler = ImageHandler(evidence)
    try:
        assert handler.load_image()
        evidence_profile.set_module_fit(handler, items[0]['fit'])
        systems = evidence_profile.tool_systems(handler)
        assert evidence_profile.tool_reason(TOOLS[tool], systems) is None
        for other in ('rleapp', 'vleapp', 'dleapp'):
            if other != tool:
                assert evidence_profile.tool_reason(
                    TOOLS[other], systems) is not None, other
    finally:
        handler.close_resources()
    case = Case.create(str(tmp_path / 'case'), tool)
    evidence_id = case.add_evidence(evidence)
    items = []
    background.job_leapp(
        {'tool': tool, 'image_path': evidence, 'case_folder': case.folder,
         'evidence_id': evidence_id, 'evidence_name': tool,
         'folder': os.path.join(case.folder, 'modules', tool)},
        lambda *a, **k: None, items.append, lambda: False)
    try:
        [summary] = items
        assert summary['status'] == 'complete', summary
        assert given in summary['input']
        run = case.module_runs()[0]
        artifacts = {a['name']: a['row_count']
                     for a in case.module_artifacts(run['id'])}
        for name, rows in expected.items():
            assert artifacts[name] == rows, name
        _sorted_into_activity(case, run)
    finally:
        case.close()


def _sorted_into_activity(case, run):
    """The run was sorted (core/modules/bridge) as it finished: every
    artifact has its role, and each evidence artifact gave one Activity
    row per row the tool wrote (the fixtures are far below the import
    limit)."""
    from trace_app.core.modules import routes
    artifacts = case.module_artifacts(run['id'])
    assert artifacts
    assert {a.get('bridged_version') for a in artifacts} ==         {routes.ROUTES_VERSION}
    assert all(a.get('role') in routes.ROLES for a in artifacts)
    for artifact in artifacts:
        rows = case._db.execute(
            "SELECT COUNT(*) FROM user_activity WHERE module_artifact_id = ?",
            (artifact['id'],)).fetchone()[0]
        if artifact['role'] == 'evidence' and not artifact.get(
                'superseded_by'):
            assert rows == artifact['row_count'], artifact['name']
        else:
            assert rows == 0, artifact['name']
    assert case.unbridged_module_runs() == []

"""The Registry tab: which hives each piece of evidence holds
(core/registry_hives.py), and the browser that reads the evidence the
examiner picks rather than whichever image is active.

A Windows-shaped folder is built from public hives -- regipy's dirty
SYSTEM, NTUSER.DAT and UsrClass.dat with their transaction logs, plaso's
Amcache -- and each hive read through the browser must be, logs replayed,
byte for byte what yarp makes of it (tests/test_regf_log.py's hashes).
"""

import hashlib
import lzma
import os

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')

#: Hives recovered by yarp, SHA-256 (as tests/test_regf_log.py).
YARP = {
    'SYSTEM': '734095bf043ea72300feb8bc380a585d8a9c925cdd5ffc190ca5ff6bc5a7c231',
    'NTUSER.DAT':
        '0a7a7b2d1eb24ab63455f5a83e554601d88fe558d0ba1c1068a7e1102c79a092',
    'UsrClass.dat':
        '0c52ea278e8c524fd13c146b060f7801af7791a1cad5b04ae9e6e06617de0e3e',
}


def _sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    with open(path, 'rb') as handle:
        data = handle.read()
    return lzma.decompress(data) if name.endswith('.xz') else data


def _put(root, relative, data):
    path = os.path.join(root, *relative.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(data)


def make_windows(root):
    """C:\\ as a triage collection holds it: system hives, a user's hives
    with their logs, Amcache, and a file named SAM that is not a hive."""
    config = 'Windows/System32/config'
    _put(root, f'{config}/SYSTEM', _sample('regipy-SYSTEM_B.xz'))
    _put(root, f'{config}/SYSTEM.LOG1', _sample('regipy-SYSTEM_B.LOG1.xz'))
    _put(root, f'{config}/SYSTEM.LOG2', _sample('regipy-SYSTEM_B.LOG2.xz'))
    _put(root, f'{config}/SOFTWARE', _sample('SOFTWARE'))
    _put(root, f'{config}/SAM', b'not a hive at all')
    _put(root, f'{config}/RegBack/SOFTWARE', _sample('SOFTWARE'))
    home = 'Users/jdoe'
    _put(root, f'{home}/NTUSER.DAT',
         _sample('regipy-transactions_NTUSER.DAT.xz'))
    _put(root, f'{home}/NTUSER.DAT.LOG1',
         _sample('regipy-transactions_ntuser.dat.log1.xz'))
    _put(root, f'{home}/NTUSER.DAT.LOG2',
         _sample('regipy-transactions_ntuser.dat.log2.xz'))
    usrclass = f'{home}/AppData/Local/Microsoft/Windows/UsrClass.dat'
    _put(root, usrclass, _sample('regipy-UsrClass.dat.xz'))
    _put(root, usrclass + '.LOG1', _sample('regipy-UsrClass.dat.LOG1.xz'))
    _put(root, usrclass + '.LOG2', _sample('regipy-UsrClass.dat.LOG2.xz'))
    _put(root, 'Users/Public/NTUSER.DAT', _sample('NTUSER-WIN7.DAT'))
    _put(root, 'Windows/AppCompat/Programs/Amcache.hve',
         _sample('Amcache-WIN10.hve'))
    return root


def make_documents(root):
    _put(root, 'Documents/report.txt', b'no registry here\n')
    return root


def test_hives_found_and_read_with_their_logs(tmp_path):
    from trace_app.core import registry_hives
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(make_windows(str(tmp_path / 'C')))
    assert handler.loaded
    hives = registry_hives.find_hives(handler)
    assert [(h.name, h.kind, h.user) for h in hives] == [
        ('SYSTEM', 'system', ''), ('SOFTWARE', 'system', ''),
        ('Amcache.hve', 'amcache', ''),
        ('NTUSER.DAT', 'user', 'jdoe'), ('UsrClass.dat', 'user', 'jdoe'),
        ('SOFTWARE (RegBack)', 'regback', '')]
    assert hives[3].label == 'NTUSER.DAT — jdoe'
    # One volume: no volume names in the labels.
    assert all(not h.volume for h in hives)
    for hive in hives:
        data, facts = registry_hives.read_hive(handler, hive)
        assert data[:4] == b'regf'
        if hive.name in YARP:
            assert facts['applied'] > 0, hive.name
            assert hashlib.sha256(data).hexdigest() == YARP[hive.name]
    assert registry_hives.find_hives(
        ImageHandler(make_documents(str(tmp_path / 'D')))) == []


def test_the_browser_reads_the_evidence_chosen_in_it(qapp, tmp_path):
    """Two pieces of evidence, the Windows one first: the browser offers
    its hives, says the other has none, and a hive read names the evidence
    and file it came from."""
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.viewers.registry_hive import RegistryExtractor
    windows = make_windows(str(tmp_path / 'C'))
    documents = make_documents(str(tmp_path / 'D'))
    browser = RegistryExtractor()
    messages = []
    browser.statusMessage.connect(messages.append)
    try:
        evidence = [(documents, 'documents', ImageHandler(documents)),
                    (windows, 'workstation', ImageHandler(windows))]
        browser.set_evidence(evidence)
        browser.wait_for_search()
        selector = browser.evidenceSelector
        assert [selector.itemText(i) for i in range(selector.count())] == [
            'documents — no Windows registry', 'workstation — 6 hives']
        # The one with a registry is offered first.
        assert selector.currentData() == windows
        assert browser.hiveSelector.count() == 6
        assert browser.select_hive(windows, 'NTUSER.DAT', 'jdoe')
        browser.load_selected_hive()
        browser.wait_for_load()
        root = browser.treeWidget.topLevelItem(0)
        assert root.text(0) == 'NTUSER.DAT — jdoe'
        assert root.toolTip(0) == 'workstation: /Users/jdoe/NTUSER.DAT'
        assert 'transaction logs' in messages[-1]
        browser.on_item_clicked(root, 0)
        panel = browser.metadataPanel
        rows = {panel.item(r, 0).text(): panel.item(r, 1).text()
                for r in range(panel.rowCount()) if panel.item(r, 1)}
        assert rows['Evidence'] == 'workstation'
        assert rows['User profile'] == 'jdoe'
        assert 'applied' in rows['Transaction logs']
        # The examiner's choice stands; the other evidence says why there
        # is nothing to load.
        browser.select_hive(documents, 'SYSTEM')
        assert browser.hiveSelector.currentText() == \
            'No Windows registry on this evidence'
        assert not browser.loadHiveButton.isEnabled()
        browser.set_evidence(list(evidence))         # nothing changed
        assert selector.currentData() == documents
        # Removing the evidence a hive was read from clears it.
        browser.set_evidence(evidence[:1])
        assert browser.treeWidget.topLevelItemCount() == 0
    finally:
        browser.shutdown()

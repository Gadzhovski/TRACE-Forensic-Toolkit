"""macOS Background Task Management (core/activity/btm.py) and its place
among the autostarts (core/persistence_unix.py).

The files are BTMParser's BackgroundItems-v13.btm and macos-loginitems'
v4 and pre-Ventura backgrounditems.btm (tools/testdata/samples.py
in test_images/samples); the values asserted are the ones their
own tests publish -- 1Password Launcher's record, Syncthing's path and
creation, PoisonApple's login item -- plus what TRACE reads beyond them:
a helper's whole path inside its app, and what registered an item.
"""

import datetime
import os
import plistlib
import shutil

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
UTC = datetime.timezone.utc


def sample_path(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    return path


def items(name):
    from trace_app.core.activity import btm
    with open(sample_path(name), 'rb') as handle:
        return btm.items(handle.read())


def test_ventura_record_as_btmparser_reads_it():
    found = {i['identifier']: i for i in items('BackgroundItems-v13.btm')}
    launcher = found['4.com.1password.1password-launcher']
    assert launcher['user_uuid'] == 'DCA7C5DA-F8EE-4910-A2F5-C32EDCAC43FC'
    assert launcher['name'] == '1Password Launcher'
    assert launcher['uuid'] == 'B3A2C9E2-7993-4C73-A23C-F215C413A2AD'
    assert launcher['developer'] == 'AgileBits Inc.'
    assert launcher['team'] == '2BUA8C4S2C'
    assert (launcher['type'], launcher['type_details']) == (4, 'login item')
    assert launcher['disposition'] == 2
    assert launcher['disposition_details'] == \
        'disabled allowed visible not notified'
    assert not launcher['enabled']
    assert launcher['bundle'] == 'com.1password.1password-launcher'
    assert launcher['container'] == '2.com.1password.1password'
    assert launcher['generation'] == 1
    # Stored relative to the app that contains it; read whole.
    assert launcher['url'] == ('/Applications/1Password.app/Contents/'
                               'Library/LoginItems/1Password Launcher.app')
    helper = found['4.2BUA8C4S2C.com.1password.browser-helper']
    assert helper['enabled'] and helper['disposition_details'] == \
        'enabled allowed visible notified'


def test_ventura_v4_lists_apps_and_legacy_daemons():
    found = items('BackgroundItems-v4.btm')
    syncthing = next(i for i in found if i['name'] == 'Syncthing')
    assert syncthing['url'] == '/Applications/Syncthing.app'
    assert syncthing['type_details'] == 'app' and syncthing['enabled']
    daemon = next(i for i in found if i['name'] == 'amsdstat')
    assert daemon['type_details'] == 'legacy daemon'
    assert daemon['executable'] == '/usr/libexec/amsdstat'
    assert daemon['url'] == '/Library/LaunchDaemons/amsdstat.plist'


def test_pre_ventura_login_items_and_who_added_them():
    from trace_app.core.activity import times
    (syncthing,) = items('backgrounditems_sierra.btm')
    assert syncthing['url'] == '/Applications/Syncthing.app'
    assert syncthing['modified'] == times.mac_absolute(665473989.0)
    lulu, testing = items('backgrounditemsPoisonApple.btm')
    assert lulu['url'] == '/Applications/LuLu.app' and not lulu['added_by']
    assert testing['url'] == ('/Users/sur/Library/Python/3.8/lib/python/'
                              'site-packages/poisonapple/auxiliary/'
                              'testing.app')
    assert testing['modified'] == times.mac_absolute(678248174.9226916)
    # macos-loginitems lists System Events as a third item: it is what
    # registered testing.app (AppleScript), not something started.
    assert testing['added_by'] == \
        '/System/Library/CoreServices/System Events.app'


def test_user_uuids_are_named():
    from trace_app.core.activity import btm
    names = btm.account_uuids([plistlib.dumps({
        'name': ['tao'],
        'generateduid': ['dca7c5da-f8ee-4910-a2f5-c32edcac43fc']})])
    assert btm.user_label('DCA7C5DA-F8EE-4910-A2F5-C32EDCAC43FC',
                          names) == 'tao'
    assert btm.user_label('FFFFEEEE-DDDD-CCCC-BBBB-AAAA000000F8',
                          names) == 'uid 248'
    assert btm.user_label('FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE',
                          names) == 'nobody (uid -2)'


def test_background_items_are_autostarts(tmp_path):
    """A macOS root as folder evidence, through the persistence job's own
    collection: the system store, a user's legacy file, names from the
    local directory, and the AppleScript-added item graded."""
    from trace_app.core import persistence
    from trace_app.core.image_handler import ImageHandler
    root = tmp_path / 'mac'
    store = root / 'private' / 'var' / 'db' / \
        'com.apple.backgroundtaskmanagement'
    store.mkdir(parents=True)
    shutil.copyfile(sample_path('BackgroundItems-v13.btm'),
                    store / 'BackgroundItems-v13.btm')
    users = root / 'private' / 'var' / 'db' / 'dslocal' / 'nodes' / \
        'Default' / 'users'
    users.mkdir(parents=True)
    (users / 'tao.plist').write_bytes(plistlib.dumps({
        'name': ['tao'],
        'generateduid': ['DCA7C5DA-F8EE-4910-A2F5-C32EDCAC43FC']},
        fmt=plistlib.FMT_BINARY))
    agent = root / 'Users' / 'sur' / 'Library' / 'Application Support' / \
        'com.apple.backgroundtaskmanagementagent'
    agent.mkdir(parents=True)
    shutil.copyfile(sample_path('backgrounditemsPoisonApple.btm'),
                    agent / 'backgrounditems.btm')
    (root / 'Library').mkdir()
    (root / 'System' / 'Library').mkdir(parents=True)
    handler = ImageHandler(str(root))
    try:
        assert handler.loaded
        found = [e for e in persistence.collect(handler)
                 if e['location'] == 'Background item']
    finally:
        handler.close_resources()
    by_name = {e['name']: e for e in found}
    launcher = by_name['1Password Launcher']
    assert launcher['user'] == 'tao' and not launcher['enabled']
    assert launcher['detail']['team'] == '2BUA8C4S2C'
    assert launcher['detail']['state'] == \
        'disabled allowed visible not notified'
    testing = by_name['testing']
    assert testing['user'] == 'sur'
    assert testing['grade'] == 'notable'
    assert any('System Events' in r for r in testing['reasons'])
    assert any('outside the system' in r for r in testing['reasons'])
    lulu = by_name['LuLu']
    # In /Applications and not added by a script: only its absence from
    # this made-up root is worth a note.
    assert (lulu['grade'], lulu['reasons']) == (
        'notable', ["the file it starts is not on this image"])

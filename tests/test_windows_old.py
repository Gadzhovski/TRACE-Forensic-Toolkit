"""Windows.old: the install an upgrade or reinstall replaced is read as a
system of its own (activity.Volume.previous_installs) -- its users'
registry and logs -- and every record from it says so."""

import shutil

from tests.conftest import data_path


def _tree(root):
    """A disk after an upgrade: the live Windows with one user, and a
    Windows.old with another user's real NTUSER.DAT (plaso's Windows 7 one)."""
    (root / 'Windows' / 'System32' / 'config').mkdir(parents=True)
    live = root / 'Users' / 'ana'
    live.mkdir(parents=True)
    shutil.copy(data_path('samples', 'NTUSER-WIN10.DAT'),
                live / 'NTUSER.DAT')
    old = root / 'Windows.old'
    (old / 'Windows' / 'System32' / 'config').mkdir(parents=True)
    profile = old / 'Users' / 'nfury'
    profile.mkdir(parents=True)
    shutil.copy(data_path('samples', 'NTUSER-WIN7.DAT'),
                profile / 'NTUSER.DAT')
    return root


def test_windows_old_is_a_system_of_its_own(tmp_path):
    from trace_app.core.activity import Volume, collect
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(str(_tree(tmp_path)))
    try:
        volumes = Volume.all(handler, 0)
        assert [v.previous_install for v in volumes] == [None, 'Windows.old']
        rows = collect(handler)
    finally:
        handler.close_resources()
    old = [r for r in rows if r['detail'].get('install')]
    live = [r for r in rows if not r['detail'].get('install')]
    assert old and live
    assert {r['user'] for r in old} == {'nfury'}
    assert 'nfury' not in {r['user'] for r in live}
    assert all(r['source'].endswith('(Windows.old)') and
               r['detail']['install'] == 'previous (Windows.old)'
               for r in old)
    # The Windows 7 user's Open/Save history is there, from the old install.
    assert any(r['source'] == 'ComDlg32 (exe) (Windows.old)' for r in old)


def test_the_registry_tab_lists_its_hives(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.registry_hives import find_hives
    handler = ImageHandler(str(_tree(tmp_path)))
    try:
        hives = find_hives(handler)
    finally:
        handler.close_resources()
    users = {(h.user, h.path.split('/')[1]) for h in hives
             if h.kind == 'user'}
    assert ('nfury', 'Windows.old') in users
    assert ('ana', 'Users') in users


def test_no_windows_old_without_a_registry(tmp_path):
    from trace_app.core.activity import Volume
    from trace_app.core.image_handler import ImageHandler
    (tmp_path / 'Windows' / 'System32' / 'config').mkdir(parents=True)
    (tmp_path / 'Windows.old' / 'Users').mkdir(parents=True)
    handler = ImageHandler(str(tmp_path))
    try:
        assert [v.previous_install for v in Volume.all(handler, 0)] == [None]
    finally:
        handler.close_resources()

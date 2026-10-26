"""Newer releases of the external tools (core/modules/updates): the newest
published release is what TRACE offers -- never the pinned one it was
tested with -- a newer release than the one installed is said in the
Modules tab and Supported Features, and GitHub is asked at most once per
MAX_AGE (60 unauthenticated calls an hour)."""

import datetime
import json
import os

import pytest

from tests.conftest import pump
from trace_app.core.modules import install, spec, updates


class _Response:
    def __init__(self, body):
        self.status_code, self.body = 200, body

    def json(self):
        return json.loads(self.body)


def _release(version, names, sums=True):
    assets = [{'name': n, 'size': 1, 'browser_download_url': f'https://dl/{n}'}
              for n in names]
    if sums:
        assets.append({'name': install.SUMS, 'size': 1,
                       'browser_download_url': 'https://dl/sums'})
    return {'tag_name': f'v{version}', 'draft': False, 'prerelease': False,
            'html_url': f'https://r/{version}',
            'published_at': '2026-10-24T00:00:00Z', 'assets': assets}


class _GitHub:
    """The releases listing as GitHub answers it; counts the questions."""

    def __init__(self, releases):
        self.releases, self.asked = releases, []

    def get(self, url, **kwargs):
        self.asked.append(url)
        return _Response(json.dumps(self.releases))


TARGET = ('windows', 'x64')


@pytest.fixture
def tools(tmp_path, monkeypatch):
    from trace_app.core import settings
    settings.user('examiner')               # loads the user's settings
    monkeypatch.setitem(settings._user_cache, 'modules_folder',
                        str(tmp_path / 'modules'))
    monkeypatch.setitem(settings._user_cache, 'check_updates', True)
    monkeypatch.setattr(spec, 'current_target', lambda: TARGET)
    return tmp_path / 'modules'


def _installed(tools, tool, version):
    """A tool as install() leaves it: folder, program, record."""
    folder = tools / tool.id / version
    os.makedirs(folder)
    (folder / f'{tool.program}.exe').write_bytes(b'MZ')
    install._write_record(tool, {'version': version, 'asset': 'x',
                                 'sha256': '0' * 64, 'url': '',
                                 'release': '', 'installed_utc': 'then',
                                 'folder': str(folder),
                                 'executable': ''}, use=True)


def _names(tool, version):
    return [tool.asset_name(version, (os_name, arch)) for os_name, arch in
            (('windows', 'x64'), ('windows', 'arm64'), ('macos', 'arm64'),
             ('macos', 'x64'), ('linux', 'x64'), ('linux', 'arm64'))]


def test_the_newest_release_is_offered_not_the_tested_one(tools):
    tool = spec.ILEAPP
    found = [_release('2026.9.1', _names(tool, '2026.9.1')),
             _release(tool.tested_version, _names(tool, tool.tested_version))]
    found = [dict(r, version=r['tag_name'][1:], published='2026-10-24',
                  url='', assets={a['name']: a for a in r['assets']})
             for r in found]
    assert install.preferred(tool, found, TARGET)['version'] == '2026.9.1'
    # A newest release whose download for this computer is not up yet (its
    # build still running) gives way to the one before.
    found[0]['assets'].pop(tool.asset_name('2026.9.1', TARGET))
    assert install.preferred(tool, found, TARGET)['version'] == \
        tool.tested_version


def test_an_installed_tool_hears_of_a_newer_release(tools):
    tool = spec.ALEAPP
    _installed(tools, tool, '2026.4.3')
    github = _GitHub([_release('2026.4.4', _names(tool, '2026.4.4')),
                      _release('2026.4.3', _names(tool, '2026.4.3'))])
    result = updates.check([tool], session=github)
    assert updates.pending(result) == [('aleapp', '2026.4.3', '2026.4.4')]
    # Once it is installed, nothing is pending.
    _installed(tools, tool, '2026.4.4')
    assert updates.pending(updates.check([tool], session=github)) == []
    # A release made long after this TRACE is still suggested: nothing
    # is pinned.
    github.releases.insert(0, _release('2027.1.0', _names(tool, '2027.1.0')))
    assert updates.pending(updates.check([tool], session=github,
                                         force=True)) == \
        [('aleapp', '2026.4.4', '2027.1.0')]


def test_github_is_asked_once_per_max_age(tools, monkeypatch):
    tool = spec.RLEAPP
    github = _GitHub([_release('2026.4.4', _names(tool, '2026.4.4'))])
    first = updates.releases(tool, github)
    assert updates.releases(tool, github) == first
    assert len(github.asked) == 1                      # kept
    later = datetime.datetime.now(datetime.timezone.utc) + \
        updates.MAX_AGE + datetime.timedelta(minutes=1)
    monkeypatch.setattr(updates, '_now', lambda: later)
    updates.releases(tool, github)
    assert len(github.asked) == 2                      # too old: asked
    updates.releases(tool, github, force=True)
    assert len(github.asked) == 3


def test_turned_off_or_offline_asks_nothing(tools, monkeypatch):
    from trace_app.core import settings
    tool = spec.VLEAPP
    github = _GitHub([_release('2026.4.4', _names(tool, '2026.4.4'))])
    updates.releases(tool, github)
    monkeypatch.setitem(settings._user_cache, 'check_updates', False)
    # The kept list still answers; GitHub is not asked.
    assert updates.releases(tool, github, force=True)
    assert len(github.asked) == 1
    # The examiner asking (External Modules) is not an automatic check...
    updates.releases(tool, github, force=True, asked=True)
    assert len(github.asked) == 2
    # ...but an offline case refuses even that.
    monkeypatch.setitem(settings._case_values, 'offline', True)
    updates.releases(tool, github, force=True, asked=True)
    assert len(github.asked) == 2
    os.remove(updates._cache_path(tool))
    with pytest.raises(install.InstallError, match='offline'):
        updates.releases(tool, github, force=True, asked=True)


def test_the_modules_tab_shows_what_is_newer(qapp):
    from trace_app.ui.viewers.modules_panel import ModulesPanel
    panel = ModulesPanel()
    panel.show()
    pump(qapp, 0.05)
    assert not panel.update_notice.isVisible()
    asked = []
    panel.manage_requested.connect(lambda: asked.append(True))
    panel.set_updates([('iLEAPP', '2026.4.4', '2026.4.5')])
    assert panel.update_notice.isVisible()
    assert 'iLEAPP 2026.4.5 (you have 2026.4.4)' in panel.update_label.text()
    panel.update_button.click()
    assert asked == [True]
    panel.set_updates([])
    assert not panel.update_notice.isVisible()
    panel.close()
    panel.deleteLater()


def test_supported_features_says_an_update_is_out(qapp, tools):
    from trace_app.core.modules.spec import TOOLS
    from trace_app.ui.dialogs.supported_features import \
        SupportedFeaturesDialog
    dialog = SupportedFeaturesDialog()
    item = dialog._tool_items[TOOLS['dleapp'].id]
    dialog._tool_updates(0, {'dleapp': ('2026.4.3', {'version': '2026.4.4'},
                                        '')})
    assert item.text(1) == "Update available"
    assert 'DLEAPP 2026.4.4 is published' in item.child(
        item.childCount() - 1).text(0)
    dialog.reject()
    dialog.deleteLater()

"""config.ini has one reader and writer (infra/config_store.py), and API
keys are kept protected (infra/api_keys.py)."""

import os
import subprocess
import sys
import threading
import types
import uuid

import pytest

from trace_app.infra import api_keys, config_store, window_state
from trace_app.infra.paths import config_file


@pytest.fixture(autouse=True)
def fresh_keys(monkeypatch):
    monkeypatch.setattr(api_keys, '_session', {})
    monkeypatch.setattr(api_keys, '_read', {})


def _file_text():
    with open(config_file(), encoding='utf-8') as handle:
        return handle.read()


def _key_field(dialog, name):
    return dialog.editors[('keys', name)][0]


def test_saving_api_keys_keeps_what_was_saved_since_the_window_opened(qapp):
    # The regression: the window wrote back config.ini as read at start.
    # The keys are a page of Settings (ui/dialogs/settings.py).
    from trace_app.ui.dialogs.settings import SettingsDialog
    from trace_app.ui.main_window import MainWindow
    dialog = SettingsDialog(None)
    window_state.save_value('Hex', 'bytes_per_line', '32')
    assert dialog.show_page_named("API Keys")
    _key_field(dialog, 'virustotal').setText('vt-key')
    _key_field(dialog, 'google_maps').setText(' maps-key ')
    dialog.accept()
    assert window_state.read_value('Hex', 'bytes_per_line') == '32'
    assert api_keys.get('virustotal') == 'vt-key'
    assert api_keys.get('google_maps') == 'maps-key'
    assert dialog.keys_changed == {'virustotal': 'vt-key',
                                   'google_maps': 'maps-key'}
    # What reads a key follows a new one at once.
    shown, redrawn = [], []
    fake = types.SimpleNamespace(
        map_panel=types.SimpleNamespace(
            refresh_styles=lambda: redrawn.append(True)),
        vt_panel=types.SimpleNamespace(set_has_key=shown.append))
    MainWindow._api_keys_changed(fake, dialog.keys_changed)
    assert shown == ['vt-key'] and redrawn
    dialog.deleteLater()


def test_the_api_keys_page_hides_keys_and_saves_only_a_change(
        qapp, monkeypatch):
    from PySide6.QtWidgets import QLineEdit
    from trace_app.ui.dialogs.settings import SettingsDialog
    api_keys.save({'virustotal': 'kept-key', 'google_maps': ''})
    saved = []
    real_save = api_keys.save
    monkeypatch.setattr(api_keys, 'save',
                        lambda values: saved.append(values)
                        or real_save(values))
    dialog = SettingsDialog(None)
    field = _key_field(dialog, 'virustotal')
    assert field.text() == 'kept-key'
    assert field.echoMode() == QLineEdit.Password
    dialog.accept()                       # nothing changed: nothing written
    assert saved == [] and dialog.keys_changed == {}
    dialog.deleteLater()
    dialog = SettingsDialog(None)
    _key_field(dialog, 'virustotal').setText('')       # removed
    dialog.accept()
    assert saved == [{'virustotal': ''}]
    assert api_keys.get('virustotal') == ''
    dialog.deleteLater()


def test_percent_values_survive_every_writer():
    config_store.set_value('Settings', 'ui_scale', '"150%"')
    window_state.save_listing_view('large')
    from trace_app.infra import theme
    theme.save_theme('dark')
    assert config_store.get('Settings', 'ui_scale') == '"150%"'
    assert theme.read_choice() == 'dark'
    assert window_state.read_listing_view() == 'large'


def test_concurrent_writers_lose_nothing():
    def write(n):
        for i in range(10):
            config_store.set_value('Race', f'k{n}_{i}', str(i))
    threads = [threading.Thread(target=write, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    parser = config_store.load()
    assert len(parser.items('Race')) == 60


def test_an_old_ansi_file_is_still_read(tmp_path):
    with open(config_file(), 'w', encoding='cp1252') as handle:
        handle.write('[Settings]\nexaminer = "Ren\xe9e"\n')
    assert config_store.get('Settings', 'examiner') == '"Ren\xe9e"'
    config_store.set_value('UI', 'theme', 'light')
    assert 'Ren\xe9e' in _file_text()           # rewritten as UTF-8


def test_the_file_store_keeps_the_key_for_its_owner_only():
    assert api_keys.store_name().startswith("TRACE's settings file")
    assert api_keys.save({'virustotal': 'plain-key'}) is None
    assert api_keys.get('virustotal') == 'plain-key'
    if sys.platform != 'win32':
        import os
        import stat
        assert stat.S_IMODE(os.stat(config_file()).st_mode) == 0o600


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows DPAPI')
def test_windows_keeps_keys_with_dpapi(monkeypatch):
    monkeypatch.delenv('TRACE_KEY_STORE')
    secret = 'vt-' + uuid.uuid4().hex
    assert api_keys.save({'virustotal': secret}) is None
    assert secret not in _file_text()
    assert config_store.get('API_KEYS', 'virustotal').startswith('dpapi:')
    api_keys._read.clear()
    assert api_keys.get('virustotal') == secret
    # A key an older TRACE left in plain text is protected at start.
    config_store.set_value('API_KEYS', 'google_maps', 'old-plain')
    api_keys.protect_stored()
    assert 'old-plain' not in _file_text()
    api_keys._read.clear()
    assert api_keys.get('google_maps') == 'old-plain'
    # Cleared: nothing kept.
    api_keys.save({'virustotal': '', 'google_maps': ''})
    assert api_keys.get('virustotal') == '' == api_keys.get('google_maps')


@pytest.mark.skipif(sys.platform != 'darwin', reason='macOS Keychain')
def test_macos_keeps_keys_in_the_keychain(monkeypatch):
    monkeypatch.delenv('TRACE_KEY_STORE')
    monkeypatch.setattr(api_keys, 'SERVICE',
                        'TRACE test ' + uuid.uuid4().hex)
    secret = 'vt-' + uuid.uuid4().hex
    # Tried first in a child with a time limit: with no login keychain
    # under the sandboxed HOME (a CI runner), Security.framework waits for
    # an interaction nobody can give -- it held a worker for the whole job.
    probe = ("from trace_app.infra import api_keys; "
             f"api_keys.SERVICE = {api_keys.SERVICE!r}; "
             "api_keys._keychain_set('probe', 'x'); "
             "api_keys._keychain_set('probe', '')")
    environment = {k: v for k, v in os.environ.items()
                   if k != 'TRACE_KEY_STORE'}
    try:
        subprocess.run([sys.executable, '-c', probe], env=environment,
                       timeout=30, check=True, capture_output=True)
    except subprocess.TimeoutExpired:
        pytest.skip("the keychain waits for user interaction here")
    except subprocess.CalledProcessError as exc:
        pytest.skip(f"no usable keychain here: {exc.stderr[-300:]!r}")
    try:
        api_keys._keychain_set('virustotal', secret)
    except api_keys.KeyStoreError as exc:
        pytest.skip(f"no usable keychain here: {exc}")
    try:
        assert api_keys._keychain_get('virustotal') == secret
        assert api_keys.save({'virustotal': secret + '2'}) is None
        assert config_store.get('API_KEYS', 'virustotal') == 'keychain:'
        assert secret not in _file_text()
        api_keys._read.clear()
        assert api_keys.get('virustotal') == secret + '2'
    finally:
        api_keys._keychain_set('virustotal', '')
    assert api_keys._keychain_get('virustotal') == ''


@pytest.mark.skipif(not sys.platform.startswith('linux'),
                    reason='Linux Secret Service')
def test_linux_keeps_keys_in_the_secret_service(monkeypatch):
    monkeypatch.delenv('TRACE_KEY_STORE')
    if api_keys._store() != 'secret-service':
        pytest.skip("no secret-tool / session bus here")
    monkeypatch.setattr(api_keys, 'SERVICE',
                        'TRACE test ' + uuid.uuid4().hex)
    secret = 'vt-' + uuid.uuid4().hex
    problem = api_keys.save({'virustotal': secret})
    if problem:
        pytest.skip(f"Secret Service refused: {problem}")
    try:
        assert secret not in _file_text()
        api_keys._read.clear()
        assert api_keys.get('virustotal') == secret
    finally:
        api_keys.save({'virustotal': ''})

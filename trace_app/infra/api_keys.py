"""The examiner's API keys (VirusTotal, Google Maps Platform), protected.

They were plain text in config.ini beside the window layout -- a file that
travels in backups and support zips. Each key is now kept by the system,
with no dependency (keyring's Linux backends need system packages):

* Windows: DPAPI (CryptProtectData, through ctypes) -- the value in
  config.ini is 'dpapi:<base64>', readable only by this Windows account;
* macOS: the login Keychain (Security.framework, through ctypes) -- the
  value in config.ini is 'keychain:', a marker;
* Linux: the Secret Service (`secret-tool`, the secret on its standard
  input, never on a command line) when installed -- marker 'secret-service:';
* otherwise the key itself, in a config.ini readable by its owner only.

A plain key left by an older TRACE is still read, and stored protected the
next time keys are saved (`protect_stored`). TRACE_KEY_STORE=file (the test
suite's) keeps keys in the file, so tests never touch a real keychain.
"""

import base64
import logging
import os
import shutil
import subprocess
import sys

from trace_app.infra import config_store

logger = logging.getLogger('TRACE.Keys')

SECTION = 'API_KEYS'
NAMES = ('virustotal', 'google_maps')
#: The Keychain / Secret Service service name.
SERVICE = 'TRACE Forensic Toolkit'

_DPAPI, _KEYCHAIN, _SECRET_SERVICE = 'dpapi:', 'keychain:', 'secret-service:'

#: Keys typed this session that could not be stored anywhere.
_session: dict[str, str] = {}
#: Keys read back this session: a keychain or secret-tool round trip is
#: not made for every VirusTotal lookup.
_read: dict[str, str] = {}


class KeyStoreError(Exception):
    pass


# --- the stores -----------------------------------------------------------------

def store_name() -> str:
    """Where a saved key goes on this machine, for the dialog to say."""
    kind = _store()
    return {'dpapi': "Windows Data Protection (this account only)",
            'keychain': "your macOS Keychain",
            'secret-service': "your Secret Service keyring",
            'file': "TRACE's settings file (readable only by you)"}[kind]


def _store():
    if os.environ.get('TRACE_KEY_STORE') == 'file':
        return 'file'
    if sys.platform == 'win32':
        return 'dpapi'
    if sys.platform == 'darwin':
        return 'keychain'
    if shutil.which('secret-tool') and (
            os.environ.get('DBUS_SESSION_BUS_ADDRESS')
            or os.environ.get('XDG_RUNTIME_DIR')):
        return 'secret-service'
    return 'file'


# Windows: DPAPI

_ENTROPY = b'TRACE API key'


def _blob(data):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]
    buffer = ctypes.create_string_buffer(data, len(data))
    return Blob, Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(
        ctypes.c_char))), buffer


def _dpapi(data, protect):
    import ctypes
    Blob, source, _keep = _blob(data)
    _e, entropy, _keep_entropy = _blob(_ENTROPY)
    out = Blob()
    crypt32 = ctypes.windll.crypt32
    UI_FORBIDDEN = 0x1
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), 'TRACE API key', ctypes.byref(entropy),
            None, None, UI_FORBIDDEN, ctypes.byref(out))
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), None, ctypes.byref(entropy), None, None,
            UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise KeyStoreError(f"Windows Data Protection failed "
                            f"(error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


# macOS: the Keychain

_ITEM_NOT_FOUND = -25300


def _security():
    import ctypes
    import ctypes.util
    path = ctypes.util.find_library('Security') or \
        '/System/Library/Frameworks/Security.framework/Security'
    return ctypes.cdll.LoadLibrary(path)


def _keychain_find(lib, name):
    """(item ref or None, value or None)."""
    import ctypes
    service, account = SERVICE.encode(), name.encode()
    length, data, item = ctypes.c_uint32(), ctypes.c_void_p(), \
        ctypes.c_void_p()
    status = lib.SecKeychainFindGenericPassword(
        None, len(service), service, len(account), account,
        ctypes.byref(length), ctypes.byref(data), ctypes.byref(item))
    if status == _ITEM_NOT_FOUND:
        return None, None
    if status:
        raise KeyStoreError(f"Keychain error {status}")
    try:
        value = ctypes.string_at(data, length.value).decode('utf-8')
    finally:
        lib.SecKeychainItemFreeContent(None, data)
    return item, value


def _release(item):
    import ctypes
    import ctypes.util
    if item:
        core = ctypes.cdll.LoadLibrary(
            ctypes.util.find_library('CoreFoundation'))
        core.CFRelease(item)


def _keychain_get(name):
    lib = _security()
    item, value = _keychain_find(lib, name)
    _release(item)
    return value or ''


def _keychain_set(name, value):
    lib = _security()
    item, _old = _keychain_find(lib, name)
    try:
        if item and not value:
            status = lib.SecKeychainItemDelete(item)
        elif item:
            data = value.encode('utf-8')
            status = lib.SecKeychainItemModifyAttributesAndData(
                item, None, len(data), data)
        elif value:
            service, account = SERVICE.encode(), name.encode()
            data = value.encode('utf-8')
            status = lib.SecKeychainAddGenericPassword(
                None, len(service), service, len(account), account,
                len(data), data, None)
        else:
            status = 0
    finally:
        _release(item)
    if status:
        raise KeyStoreError(f"Keychain error {status}")


# Linux: the Secret Service

def _secret_tool(*args, value=None):
    try:
        done = subprocess.run(
            ['secret-tool', *args], input=value, capture_output=True,
            text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeyStoreError(f"secret-tool: {exc}") from exc
    return done


def _secret_get(name):
    done = _secret_tool('lookup', 'service', SERVICE, 'key', name)
    # Exit status 1 with no output: no such secret.
    return done.stdout.strip() if done.returncode == 0 else ''


def _secret_set(name, value):
    if value:
        done = _secret_tool('store', f'--label={SERVICE}: {name}',
                            'service', SERVICE, 'key', name, value=value)
    else:
        done = _secret_tool('clear', 'service', SERVICE, 'key', name)
    if done.returncode != 0 and value:
        raise KeyStoreError(
            f"secret-tool: {done.stderr.strip() or done.returncode}")


# --- reading and saving -----------------------------------------------------------

def get(name: str) -> str:
    """The key called `name`, '' when there is none."""
    if name in _session:
        return _session[name]
    if name not in _read:
        _read[name] = _get(name)
    return _read[name]


def _get(name):
    stored = config_store.get(SECTION, name, '')
    try:
        if stored.startswith(_DPAPI):
            return _dpapi(base64.b64decode(stored[len(_DPAPI):]),
                          False).decode('utf-8')
        if stored == _KEYCHAIN:
            return _keychain_get(name)
        if stored == _SECRET_SERVICE:
            return _secret_get(name)
    except (KeyStoreError, OSError, ValueError, AttributeError) as exc:
        logger.warning("The %s API key could not be read back: %s",
                       name, exc)
        return ''
    return stored.strip()


def _protected(name, value):
    """What config.ini keeps for `value` (the key itself only as a last
    resort)."""
    value = value.strip()
    if not value:
        kind = _store()
        if kind == 'keychain':
            _keychain_set(name, '')
        elif kind == 'secret-service':
            _secret_set(name, '')
        return ''
    kind = _store()
    if kind == 'dpapi':
        return _DPAPI + base64.b64encode(
            _dpapi(value.encode('utf-8'), True)).decode('ascii')
    if kind == 'keychain':
        _keychain_set(name, value)
        return _KEYCHAIN
    if kind == 'secret-service':
        _secret_set(name, value)
        return _SECRET_SERVICE
    return value


def save(values: dict[str, str]) -> str | None:
    """Store {name: key}. Returns None, or why a key is kept for this
    session only -- the dialog says so."""
    stored, problem = {}, None
    _read.clear()
    for name, value in values.items():
        try:
            stored[name] = _protected(name, value)
            _session.pop(name, None)
        except (KeyStoreError, OSError, AttributeError) as exc:
            logger.warning("The %s API key could not be stored: %s",
                           name, exc)
            _session[name] = value.strip()
            problem = str(exc)
    if stored and not config_store.set_values(SECTION, stored):
        _session.update({name: values[name].strip() for name in stored})
        problem = problem or "TRACE's settings file could not be written."
    _restrict_file()
    return problem


def protect_stored() -> None:
    """Store protected any key an older TRACE left in plain text."""
    plain = {}
    for name in NAMES:
        stored = config_store.get(SECTION, name, '')
        if stored and not stored.startswith(
                (_DPAPI, _KEYCHAIN, _SECRET_SERVICE)):
            plain[name] = stored
    if plain and _store() != 'file':
        problem = save(plain)
        if problem is None:
            logger.info("API keys moved to %s", store_name())
    elif plain:
        _restrict_file()


def _restrict_file():
    """config.ini readable by its owner only (POSIX: where a key may sit in
    it, the last resort)."""
    if sys.platform == 'win32':
        return
    try:
        from trace_app.infra.paths import config_file
        os.chmod(config_file(), 0o600)
    except OSError as exc:
        logger.debug("config.ini permissions unchanged: %s", exc)

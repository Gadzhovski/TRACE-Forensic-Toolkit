"""ChromeOS: a Chromebook's disk, or an extraction of its user data (no
Qt). The items cLEAPP lists, read from the formats themselves.

A Chromebook's disk holds ROOT-A/B (the system, ext2, read-only:
/etc/lsb-release names it -- core/os_identity) and STATE, the stateful
partition, where everything that changes lives:

* **What is encrypted, and by what.** /var and /home/chronos live in
  encrypted.block (encstateful), each user's home in home/.shadow/<hash>
  (eCryptfs `vault/`, ext4 fscrypt `mount/`, or a dm-crypt volume), and
  every key is sealed by the TPM. None of it can be opened from the disk;
  TRACE lists it -- each user's folder, by what, when last changed -- and
  says that a decrypted extraction is needed. Nothing is attempted.
* **Who each encrypted home belongs to.** The folder is named by
  SHA-1(system salt + user name) (`sanitized`, cryptohome's
  SanitizeUserNameWithSalt); with home/.shadow/salt and the e-mail
  addresses Local State lists, each folder is named.
* **Local State** (home/chronos/Local State, JSON): the accounts that have
  signed in, the last one, display names, and each known user's last
  online sign-in (WebKit microseconds, as a string).
* **VPD** (var/cache/vpd/full-v2.txt, `"key"="value"` lines): the
  device's serial number, model, region and activation date
  (`device_facts`, also shown in Evidence Information).
* **The firmware event log** (var/log/eventlog.txt, `n | time | event |
  detail`): boots, shutdowns, sleeps, firmware updates, recovery mode.
  The firmware clock's zone is not recorded: times are kept as written.
* The system logs (var/log/messages, ...), through linux.system_activity
  -- ChromeOS's syslog writes ISO times with their offset.
* **A user's data** (decrypted: home/chronos/u-<hash>, home/user/<hash>,
  or an extraction's mount/user): the Chrome profile is that folder itself
  (activity._browsers reads it through `profiles`), .crosh_history (the
  crosh shell's commands, untimed), Custom Dictionary.txt (words the user
  added), and the Linux (Crostini) VM's disk under crosvm/ -- listed with
  its size: export it and add it as evidence to read the container.
* **Android apps (ARC++)**: android-data/data under a user's root home is
  Android's /data -- activity/mobile.android_base finds it there, so every
  Android reader applies.

No public Chromebook image could be found; the tests write each file as
ChromeOS does.
"""

import hashlib
import json
import logging
import re

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.ChromeOS')

#: A cryptohome folder name: 40 hex characters.
_HASH = re.compile(r'^[0-9a-f]{40}$')
_VPD = re.compile(r'^"([^"]+)"="(.*)"\s*$')
_EVENT = re.compile(r'^\s*(\d+)\s*\|\s*(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)'
                    r'(?:([+-]\d{4}))?\s*\|\s*([^|]*?)\s*(?:\|\s*(.*?)\s*)?$')
#: VPD keys an examiner asks for, and how Evidence Information names them.
VPD_FACTS = (('serial_number', 'Serial number'),
             ('mlb_serial_number', 'Mainboard serial number'),
             ('model_name', 'Model'), ('customization_id', 'Customization'),
             ('region', 'Region'), ('initial_timezone', 'Initial time zone'),
             ('initial_locale', 'Initial locale'),
             ('keyboard_layout', 'Keyboard layout'),
             ('ActivateDate', 'Activated (year-week)'),
             ('rlz_brand_code', 'Brand code'),
             ('ethernet_mac0', 'Ethernet MAC'), ('wifi_mac0', 'Wi-Fi MAC'))
#: Firmware events that matter most, graded for the examiner.
_NOTABLE_EVENTS = ('Recovery', 'Developer', 'Firmware update', 'Log area '
                   'cleared', 'Kernel Panic', 'Watchdog')


def canonical(email):
    """Chrome's canonical account name (gaia::CanonicalizeEmail): lower
    case, and for gmail.com no dots before the '@'."""
    email = (email or '').strip().lower()
    local, _sep, domain = email.partition('@')
    if domain in ('gmail.com', 'googlemail.com'):
        return local.replace('.', '') + '@gmail.com'
    return email


def sanitized(salt, user):
    """The cryptohome folder name of a user: SHA-1(salt + user)."""
    return hashlib.sha1(salt + user.lower().encode('utf-8')).hexdigest()


def vpd(text):
    """{key: value} of a VPD dump."""
    out = {}
    for line in text.splitlines():
        match = _VPD.match(line.strip())
        if match:
            out[match.group(1)] = match.group(2)
    return out


def eventlog(text):
    """[{number, time, zone, event, detail}] of eventlog.txt."""
    import datetime
    out = []
    for line in text.splitlines():
        match = _EVENT.match(line)
        if not match:
            continue
        number, stamp, zone, event, detail = match.groups()
        try:
            when = datetime.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
        if zone:
            when = datetime.datetime.strptime(stamp + zone,
                                              '%Y-%m-%d %H:%M:%S%z')
        out.append({'number': int(number), 'time': when, 'event': event,
                    'detail': detail or None})
    return out


def local_state(data):
    """{'users': [{email, name, gaia, last_signin, type}], 'last': email,
    'last_regular': email} of Local State."""
    try:
        state = json.loads(data.decode('utf-8', 'replace')
                           if isinstance(data, bytes) else data)
    except ValueError:
        return None
    if not isinstance(state, dict):
        return None
    names = state.get('UserDisplayName') or {}
    users = {}
    for email in state.get('LoggedInUsers') or []:
        if isinstance(email, str):
            users.setdefault(email, {'email': email})
    known = state.get('KnownUsers') or state.get('known_user') or []
    for item in known if isinstance(known, list) else []:
        if not isinstance(item, dict) or not item.get('email'):
            continue
        user = users.setdefault(item['email'], {'email': item['email']})
        user['gaia'] = item.get('gaia_id')
        user['type'] = item.get('account_type')
        user['last_signin'] = times.webkit(
            _int(item.get('last_online_signin')))
        user['saml'] = item.get('using_saml')
    for email, user in users.items():
        user['name'] = names.get(email) if isinstance(names, dict) else None
        user['listed'] = email in (state.get('LoggedInUsers') or [])
    return {'users': list(users.values()),
            'last': state.get('LastActiveUser'),
            'last_regular': state.get('LastLoggedInRegularUser')}


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --- the volume ---------------------------------------------------------------------

def is_chromeos(volume):
    """A ChromeOS system or stateful partition, or a user's extraction."""
    lsb = volume.find('etc', 'lsb-release')
    if lsb is not None and b'CHROMEOS_RELEASE' in volume.read(lsb)[:4096]:
        return True
    if volume.find('home', '.shadow') is not None and (
            volume.find('home', 'chronos') is not None or
            volume.find('encrypted.block') is not None):
        return True
    return volume.find('home', 'chronos', 'Local State') is not None or \
        volume.find('var', 'cache', 'vpd', 'full-v2.txt') is not None


def _salt(volume):
    entry = volume.find('home', '.shadow', 'salt')
    return volume.read(entry) if entry is not None else b''


def _accounts(volume):
    """(Local State facts or None, its entry)."""
    entry = volume.find('home', 'chronos', 'Local State')
    if entry is None or entry.is_dir:
        return None, None
    return local_state(volume.read(entry)), entry


def owners(volume):
    """{cryptohome folder name: e-mail} for every account Local State
    names, where the system salt is on the volume."""
    salt = _salt(volume)
    state, _entry = _accounts(volume)
    if not salt or not state:
        return {}
    out = {}
    for user in state['users']:
        for name in {canonical(user['email']), user['email'].lower()}:
            out[sanitized(salt, name)] = user['email']
    return out


def device_facts(volume):
    """[(label, value)] from the VPD, for Evidence Information."""
    for parts in (('var', 'cache', 'vpd', 'full-v2.txt'),
                  ('var', 'log', 'vpd_2.0.txt')):
        entry = volume.find(*parts)
        if entry is None or entry.is_dir:
            continue
        values = vpd(volume.read(entry).decode('utf-8', 'replace'))
        if values:
            return [(label, values[key]) for key, label in VPD_FACTS
                    if values.get(key)]
    return []


def _vault_kind(volume, folder):
    names = {entry.name for entry in volume.listdir(folder.path)}
    kinds = []
    if 'vault' in names:
        kinds.append('eCryptfs (vault)')
    if 'mount' in names:
        kinds.append('fscrypt (mount)')
    if any(name.startswith(('master.', 'auth_factors')) for name in names) \
            and not kinds:
        kinds.append('dm-crypt (logical volume in the stateful partition)')
    keys = sorted(name for name in names if name.startswith('master.'))
    return ', '.join(kinds) or 'unknown', keys, names


def collect(volume, step):
    """Records of a ChromeOS volume (see the module's text)."""
    out = []
    owner_of = owners(volume)
    state, state_entry = _accounts(volume)
    shadow = volume.find('home', '.shadow')
    present = {folder.name for folder in volume.children(shadow, dirs=True)} \
        if shadow else set()
    if state:
        step(state_entry.path)
        ref = volume.ref(state_entry)
        for user in state['users']:
            # The name as the account was written, or as Chrome
            # canonicalises it: whichever folder is there.
            folder = next((h for h, e in owner_of.items()
                           if e == user['email'] and h in present), None)
            out.append(record(
                'accounts', 'ChromeOS Local State', user.get('last_signin'),
                'ChromeOS account', user['email'],
                {'name': user.get('name'), 'Google ID': user.get('gaia'),
                 'account type': user.get('type'),
                 'SAML sign-in': 'yes' if user.get('saml') else None,
                 'listed as signed in before': 'yes' if user.get('listed')
                 else None,
                 'last active': 'yes' if user['email'] == state['last']
                 else None,
                 'encrypted home': folder,
                 'basis': 'the last online sign-in' if
                 user.get('last_signin') else
                 'Local State records no time for this account'},
                user=user['email'], path=state_entry.path, ref=ref))
    shadow = volume.find('home', '.shadow')
    for folder in volume.children(shadow, dirs=True) if shadow else ():
        if not _HASH.match(folder.name):
            continue
        step(folder.path)
        kind, keys, _names = _vault_kind(volume, folder)
        email = owner_of.get(folder.name)
        out.append(record(
            'accounts', 'ChromeOS cryptohome', folder.modified,
            'Encrypted user home', email or folder.name,
            {'folder': folder.name, 'encryption': kind,
             'key sets': ', '.join(keys),
             'owner': email or ('not named: no system salt or no Local '
                                'State on this volume'),
             'readable': 'no -- the keys are sealed by the TPM; a '
                         'decrypted extraction is needed',
             'basis': "the folder's last change"},
            user=email or '', path=folder.path, ref=volume.ref(folder)))
    block = volume.find('encrypted.block')
    if block is not None and not block.is_dir:
        out.append(record(
            'system', 'ChromeOS', block.modified, 'Encrypted system data',
            'encrypted.block (/var and /home/chronos)',
            {'size': block.size,
             'readable': 'no -- its key is in the TPM\'s NVRAM',
             'basis': "the file's last change"},
            path=block.path, ref=volume.ref(block)))
    for parts in (('var', 'cache', 'vpd', 'full-v2.txt'),
                  ('var', 'log', 'vpd_2.0.txt')):
        entry = volume.find(*parts)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        values = vpd(volume.read(entry).decode('utf-8', 'replace'))
        labels = dict(VPD_FACTS)
        for key, value in values.items():
            out.append(record(
                'system', 'ChromeOS VPD', entry.modified,
                labels.get(key, 'Device fact (VPD)'),
                f"{value}" if key in labels else f"{key} = {value}",
                {'key': key, 'basis': "the VPD cache's last change"},
                path=entry.path, ref=volume.ref(entry)))
        break
    entry = volume.find('var', 'log', 'eventlog.txt')
    if entry is not None and not entry.is_dir:
        step(entry.path)
        ref = volume.ref(entry)
        for event in eventlog(volume.read(entry).decode('utf-8',
                                                        'replace')):
            zoned = event['time'].tzinfo is not None
            out.append(record(
                'system', 'ChromeOS firmware event log', event['time'],
                event['event'], event['detail'] or event['event'],
                {'entry': event['number'],
                 'grade': 'notable' if any(
                     word.lower() in event['event'].lower()
                     for word in _NOTABLE_EVENTS) else None,
                 'basis': None if zoned else
                 'the firmware clock; its zone is not recorded'},
                path=entry.path, ref=ref, local=not zoned))
    from trace_app.core.activity import linux
    if not linux.is_linux(volume):
        # The stateful partition: /var/log without /etc beside it.
        out += linux.system_activity(volume, step)
    for user, profile in profiles(volume):
        out += user_records(volume, user, profile, step)
    return out


def profiles(volume):
    """[(user, folder)] of every decrypted ChromeOS user folder: the
    folder *is* the Chrome profile (History, Preferences beside each
    other)."""
    owner_of = owners(volume)
    found = []
    chronos = volume.find('home', 'chronos')
    for child in volume.children(chronos, dirs=True) if chronos else ():
        if child.name.startswith('u-') or child.name == 'user':
            found.append((owner_of.get(child.name[2:], ''), child))
    for parts in (('home', 'user'),):
        top = volume.find(*parts)
        for child in volume.children(top, dirs=True) if top else ():
            if _HASH.match(child.name):
                found.append((owner_of.get(child.name, ''), child))
    shadow = volume.find('home', '.shadow')
    for child in volume.children(shadow, dirs=True) if shadow else ():
        user = volume.find(*_parts(child), 'mount', 'user')
        if user is not None and user.is_dir:
            found.append((owner_of.get(child.name, ''), user))
    # An extraction handed over as the user folder itself, or its parent.
    for parts in (('mount', 'user'), ('user',), ()):
        folder = volume.find(*parts) if parts else None
        if parts and folder is None:
            continue
        probe = parts
        if volume.find(*probe, 'Preferences') is not None and (
                volume.find(*probe, '.crosh_history') is not None or
                volume.find(*probe, 'Custom Dictionary.txt') is not None or
                volume.find(*probe, 'MyFiles') is not None):
            found.append(('', folder))
    seen, out = set(), []
    for user, folder in found:
        key = folder.path if folder is not None else '/'
        if key not in seen and _has_profile(volume, folder):
            seen.add(key)
            out.append((user, folder))
    return out


def _has_profile(volume, folder):
    parts = _parts(folder)
    return any(volume.find(*parts, name) is not None
               for name in ('Preferences', 'History', 'Cookies',
                            '.crosh_history', 'Custom Dictionary.txt'))


def _parts(folder):
    from trace_app.core.activity import _split
    return _split(folder.path) if folder is not None else []


def user_records(volume, user, folder, step):
    """crosh history, the custom dictionary and Crostini disks."""
    parts = _parts(folder)
    out = []
    entry = volume.find(*parts, '.crosh_history')
    if entry is not None and not entry.is_dir:
        step(entry.path)
        ref = volume.ref(entry)
        written = times.iso(entry.modified) or 'at an unknown time'
        lines = [line for line in volume.read(entry).decode(
            'utf-8', 'replace').splitlines() if line.strip()]
        for number, command in enumerate(lines, 1):
            out.append(record(
                'programs', 'crosh history', None, 'Command typed', command,
                {'shell': 'crosh', 'line': number,
                 'basis': 'crosh writes no times; the history was last '
                          f'written {written}'},
                user=user, path=entry.path, ref=ref))
    entry = volume.find(*parts, 'Custom Dictionary.txt')
    if entry is not None and not entry.is_dir:
        step(entry.path)
        ref = volume.ref(entry)
        for word in volume.read(entry).decode('utf-8',
                                              'replace').splitlines():
            word = word.strip()
            if not word or word.startswith('checksum_v1'):
                continue
            out.append(record(
                'notes', 'Chrome custom dictionary', None,
                'Word added to the dictionary', word,
                {'basis': 'the dictionary records no time per word'},
                user=user, path=entry.path, ref=ref))
    crosvm = volume.find(*parts, 'crosvm')
    if crosvm is None:
        root = volume.find('home', 'root')
        for child in volume.children(root, dirs=True) if root else ():
            crosvm = volume.find(*_parts(child), 'crosvm') or crosvm
    for disk in volume.children(crosvm) if crosvm else ():
        if not disk.name.lower().endswith(('.img', '.qcow2')):
            continue
        out.append(record(
            'programs', 'Crostini', disk.modified,
            'Linux (Crostini) VM disk', disk.name,
            {'size': disk.size,
             'how to read it': 'export it and add it as evidence: the '
                               "container's files are on it",
             'basis': "the disk's last change"},
            user=user, path=disk.path, ref=volume.ref(disk)))
    return out

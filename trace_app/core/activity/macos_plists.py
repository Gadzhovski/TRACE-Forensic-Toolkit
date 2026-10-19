"""macOS preference and configuration plists (no Qt).

The small property lists macOS keeps about what the machine is and what was
connected to it. Each reader takes the file's bytes and returns
`activity.record` dicts; times are UTC. Passwords, password hashes and keys
are never read into a record -- an account reader keeps the name, the user id
and the login/password-set times only.

Checked against plaso's test plists and its expected values
(tests/test_macos_plists.py):

* com.apple.airport.preferences.plist -- Wi-Fi networks the Mac remembers
* com.apple.bluetooth.plist -- Bluetooth devices seen and paired
* loginwindow.plist -- login/logout hooks and managed login items
* dslocal users (Local/Default/Users/<name>.plist) -- the account, when the
  password was last set and last login (no hash)
* com.apple.iPod.plist -- iOS devices connected to this Mac
* com.apple.spotlight.plist -- the Spotlight shortcuts the user typed
* VolumeConfiguration.plist -- the Spotlight stores and when they were made
* com.apple.coreservices.appleidauthenticationinfo.*.plist -- the Apple ID
* com.apple.TimeMachine.plist -- Time Machine destinations and snapshots
* com.apple.SoftwareUpdate.plist -- the last software-update check
"""

import datetime
import logging
import plistlib

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.macOSPlists')


def _utc(value):
    """A plist datetime as UTC (they are stored with no zone, in UTC)."""
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else \
            value.replace(tzinfo=datetime.timezone.utc)
    return None


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value


def airport(data, user, path, ref):
    """com.apple.airport.preferences.plist: every Wi-Fi network remembered,
    with the SSID, the security type and when it was last connected."""
    out = []
    plist = plistlib.loads(data)
    networks = plist.get('RememberedNetworks') or []
    if isinstance(networks, dict):
        networks = list(networks.values())
    for network in networks:
        if not isinstance(network, dict):
            continue
        ssid = network.get('SSIDString') or _text(network.get('SSID')) or ''
        out.append(record(
            'network', 'Wi-Fi (airport)',
            _utc(network.get('LastConnected')), 'Wi-Fi network remembered',
            ssid,
            {'security': network.get('SecurityType'),
             'BSSID': (network.get('CachedScanRecord') or {}).get('BSSID'),
             'hidden': network.get('PossiblyHiddenNetwork'),
             'auto login': network.get('AutoLogin'),
             'basis': 'the last time this Mac connected to the network'},
            user=user, path=path, ref=ref))
    return out


def bluetooth(data, user, path, ref):
    """com.apple.bluetooth.plist: every device in the cache, whether it is
    paired, with the inquiry/name/services update times."""
    out = []
    plist = plistlib.loads(data)
    paired = {str(address).lower()
              for address in (plist.get('PairedDevices') or [])}
    cache = plist.get('DeviceCache') or {}
    for address, device in cache.items():
        if not isinstance(device, dict):
            continue
        name = device.get('displayName') or device.get('Name') or ''
        out.append(record(
            'network', 'Bluetooth',
            _utc(device.get('LastInquiryUpdate')), 'Bluetooth device seen',
            name or address,
            {'mac address': address,
             'paired': str(address).lower() in paired,
             'name updated': times.iso(_utc(device.get('LastNameUpdate'))),
             'services updated': times.iso(
                 _utc(device.get('LastServicesUpdate'))),
             'battery': device.get('BatteryPercent'),
             'basis': 'the last time this Mac saw the device'},
            user=user, path=path, ref=ref))
    return out


def login_window(data, path, ref):
    """loginwindow.plist: login/logout hooks (scripts run at login) and the
    managed login items the machine launches."""
    out = []
    plist = plistlib.loads(data)
    if plist.get('LoginHook') or plist.get('LogoutHook'):
        out.append(record(
            'logons', 'Login window', None, 'Login/logout hook', '',
            {'login hook': plist.get('LoginHook'),
             'logout hook': plist.get('LogoutHook'),
             'basis': 'a script set to run at login or logout'},
            path=path, ref=ref))
    for item in plist.get('AutoLaunchedApplicationDictionary') or []:
        if not isinstance(item, dict):
            continue
        out.append(record(
            'programs', 'Login window', None, 'Managed login item',
            item.get('Path') or '',
            {'hidden': item.get('Hide'),
             'basis': 'launched at login for every user (managed)'},
            path=path, ref=ref))
    return out


def dslocal_user(data, path, ref):
    """A dslocal account plist (Local/Default/Users/<name>.plist): the
    account, its id, and when the password was last set and last used --
    never the hash or key."""
    plist = plistlib.loads(data)

    def first(key):
        value = plist.get(key)
        return value[0] if isinstance(value, list) and value else value

    name = _text(first('name')) or ''
    if not name or name.startswith('_'):
        return []                       # service accounts: not a person
    policy = {}
    raw = first('passwordpolicyoptions')
    if isinstance(raw, bytes):
        try:
            policy = plistlib.loads(raw)
        except Exception:
            policy = {}
    detail = {'user id': _text(first('uid')),
              'full name': _text(first('realname')),
              'home': _text(first('home')),
              'shell': _text(first('shell')),
              'password last set': times.iso(
                  _utc(policy.get('passwordLastSetTime'))),
              'last login': times.iso(_utc(policy.get('lastLoginTimestamp'))),
              'failed logins': policy.get('failedLoginCount'),
              'basis': 'the account record; the password set time'}
    when = _utc(policy.get('passwordLastSetTime'))
    return [record('logons', 'User account', when, 'macOS user account',
                   name, detail, user=name, path=path, ref=ref)]


def ipod_devices(data, path, ref):
    """com.apple.iPod.plist: every iOS device connected to this Mac, with
    the class, serial, IMEI and when it was last connected."""
    out = []
    for identifier, device in (plistlib.loads(data).get('Devices')
                               or {}).items():
        if not isinstance(device, dict):
            continue
        out.append(record(
            'usb', 'iPod/iOS device', _utc(device.get('Connected')),
            'iOS device connected',
            device.get('Device Class') or identifier,
            {'serial number': device.get('Serial Number'),
             'imei': device.get('IMEI'),
             'family id': device.get('Family ID'),
             'firmware': device.get('Firmware Version String'),
             'use count': device.get('Use Count'),
             'identifier': identifier,
             'basis': 'the last time the device was connected to this Mac'},
            path=path, ref=ref))
    return out


def spotlight_shortcuts(data, user, path, ref):
    """com.apple.spotlight.plist: each shortcut the user typed in Spotlight
    and the item they opened for it."""
    out = []
    for term, shortcut in (plistlib.loads(data).get('UserShortcuts')
                           or {}).items():
        if not isinstance(shortcut, dict):
            continue
        out.append(record(
            'searches', 'Spotlight', _utc(shortcut.get('LAST_USED')),
            'Searched (Spotlight)', term,
            {'opened': shortcut.get('DISPLAY_NAME'),
             'path': shortcut.get('PATH'),
             'basis': 'the last time this shortcut was used'},
            user=user, path=path, ref=ref))
    return out


def spotlight_volumes(data, path, ref):
    """VolumeConfiguration.plist: each Spotlight store (a volume indexed)
    and when it was made."""
    out = []
    for identifier, store in (plistlib.loads(data).get('Stores')
                              or {}).items():
        if not isinstance(store, dict):
            continue
        out.append(record(
            'system', 'Spotlight', _utc(store.get('CreationDate')),
            'Spotlight store created', store.get('PartialPath') or '',
            {'volume identifier': identifier,
             'made with': store.get('CreationVersion'),
             'basis': 'when the Spotlight index for this volume was made'},
            path=path, ref=ref))
    return out


def apple_account(data, path, ref):
    """com.apple.coreservices.appleidauthenticationinfo.*.plist: the Apple
    ID signed in on this Mac, with the name and connect times (no secret)."""
    out = []
    for name, account in (plistlib.loads(data).get('Accounts')
                          or {}).items():
        if not isinstance(account, dict):
            continue
        out.append(record(
            'accounts', 'Apple ID', _utc(account.get('CreationDate')),
            'Apple ID account', account.get('AppleID') or name,
            {'first name': account.get('FirstName'),
             'last name': account.get('LastName'),
             'last connected': times.iso(
                 _utc(account.get('LastSuccessfulConnect'))),
             'validated': times.iso(_utc(account.get('ValidationDate'))),
             'basis': 'when the Apple ID was first added to this Mac'},
            path=path, ref=ref))
    return out


def time_machine(data, path, ref):
    """com.apple.TimeMachine.plist: every backup destination and its
    snapshot dates."""
    out = []
    for destination in (plistlib.loads(data).get('Destinations') or []):
        if not isinstance(destination, dict):
            continue
        snapshots = [_utc(s) for s in destination.get('SnapshotDates') or []]
        snapshots = [s for s in snapshots if s]
        out.append(record(
            'system', 'Time Machine', max(snapshots) if snapshots else None,
            'Time Machine backup', destination.get('DestinationID') or '',
            {'snapshots': len(snapshots),
             'first snapshot': times.iso(min(snapshots)) if snapshots
             else None,
             'bytes used': destination.get('BytesUsed'),
             'basis': 'the most recent Time Machine snapshot'},
            path=path, ref=ref))
    return out


def software_update(data, path, ref):
    """com.apple.SoftwareUpdate.plist: when the Mac last checked for and
    found system updates."""
    plist = plistlib.loads(data)
    when = _utc(plist.get('LastFullSuccessfulDate'))
    if when is None and not plist.get('LastAttemptSystemVersion'):
        return []
    return [record(
        'system', 'Software Update', when, 'Checked for software updates',
        plist.get('LastAttemptSystemVersion') or '',
        {'updates available': plist.get('LastUpdatesAvailable'),
         'recommended': plist.get('LastRecommendedUpdatesAvailable'),
         'last background check': times.iso(
             _utc(plist.get('LastBackgroundCCDSuccessfulDate'))),
         'basis': 'the last successful software-update check'},
        path=path, ref=ref)]


# --- what the user keeps at hand, and what the Mac shares -------------------------

def _url_path(value):
    """A file URL's path ('file:///Applications/Safari.app/' ->
    '/Applications/Safari.app'), or the text as it is."""
    from urllib.parse import unquote, urlparse
    if not isinstance(value, str):
        return None
    if value.startswith('file://'):
        return unquote(urlparse(value).path).rstrip('/') or '/'
    return value


def dock(data, user, path, ref):
    """com.apple.dock.plist: the applications and folders kept in the
    Dock (persistent-apps / persistent-others) and the recent ones it
    shows (recent-apps), each with the file's date as the Dock recorded
    it (seconds since 1904)."""
    out = []
    plist = plistlib.loads(data)
    for key, what in (('persistent-apps', 'Kept in the Dock'),
                      ('recent-apps', 'Recent application in the Dock'),
                      ('persistent-others', 'Folder or file in the Dock')):
        for position, tile in enumerate(plist.get(key) or [], 1):
            if not isinstance(tile, dict):
                continue
            info = tile.get('tile-data') or {}
            file_data = info.get('file-data') or {}
            target = _url_path(file_data.get('_CFURLString'))
            label = info.get('file-label') or target or ''
            out.append(record(
                'programs' if 'apps' in key else 'files', 'Dock',
                times.hfs(info.get('file-mod-date')), what, label,
                {'path': target, 'bundle id': info.get('bundle-identifier'),
                 'position': position,
                 'parent modified': times.iso(times.hfs(
                     info.get('parent-mod-date'))),
                 'basis': "the item's modification date as the Dock "
                          "recorded it"},
                user=user, path=path, ref=ref))
    return out


def _first(plist, key):
    value = plist.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    return _text(value)


def sharepoint(data, modified, path, ref):
    """A file-sharing share point (dslocal sharepoints/<name>.plist): the
    folder shared, under which names, and over SMB / AFP / FTP."""
    plist = plistlib.loads(data)
    folder = _first(plist, 'directory_path') or ''
    protocols = [label for key, label in (('smb_shared', 'SMB'),
                                          ('afp_shared', 'AFP'),
                                          ('ftp_shared', 'FTP'))
                 if _first(plist, key) in ('1', 1, True)]
    return [record(
        'network', 'File sharing', modified, 'Folder shared',
        folder or _first(plist, 'name') or '',
        {'share name': _first(plist, 'name'),
         'SMB name': _first(plist, 'smb_name'),
         'AFP name': _first(plist, 'afp_name'),
         'shared over': ', '.join(protocols) or 'none (defined only)',
         'guest access (SMB)': _first(plist, 'smb_guestaccess'),
         'guest access (AFP)': _first(plist, 'afp_guestaccess'),
         'basis': "the share point file's modification time"},
        path=path, ref=ref)]


def smb_server(data, modified, path, ref):
    """com.apple.smb.server.plist: the name and workgroup this Mac shares
    files under."""
    plist = plistlib.loads(data)
    name = plist.get('NetBIOSName') or plist.get('LocalKerberosRealm')
    if not name and not plist.get('ServerDescription'):
        return []
    return [record(
        'network', 'File sharing', modified, 'SMB server settings',
        name or plist.get('ServerDescription') or '',
        {'NetBIOS name': plist.get('NetBIOSName'),
         'workgroup': plist.get('Workgroup'),
         'description': plist.get('ServerDescription'),
         'Kerberos realm': plist.get('LocalKerberosRealm'),
         'basis': "the settings file's modification time"},
        path=path, ref=ref)]


#: Sharing services launchd's overrides switch on and off.
SHARING_SERVICES = {
    'com.apple.screensharing': 'Screen Sharing',
    'com.apple.RemoteDesktop.agent': 'Remote Management (ARD agent)',
    'com.apple.RemoteDesktop.PrivilegeProxy': 'Remote Management',
    'com.apple.smbd': 'File Sharing (SMB)',
    'com.apple.AppleFileServer': 'File Sharing (AFP)',
    'com.openssh.sshd': 'Remote Login (SSH)',
    'com.apple.ftpd': 'FTP',
    'com.apple.ODSAgent': 'Remote Disc',
    'com.apple.InternetSharing': 'Internet Sharing',
    'com.apple.AEServer': 'Remote Apple Events',
    'org.cups.cupsd': 'Printer Sharing',
}


def launchd_overrides(data, modified, path, ref):
    """launchd's overrides (/private/var/db/launchd.db/com.apple.launchd/
    overrides.plist, and com.apple.xpc.launchd's disabled.plist): which
    sharing services the Sharing pane turned on or off."""
    plist = plistlib.loads(data)
    out = []
    for label, name in SHARING_SERVICES.items():
        if label not in plist:
            continue
        value = plist[label]
        disabled = value.get('Disabled') if isinstance(value, dict) \
            else value
        remote = any(word in name for word in ('Remote', 'Screen', 'SSH'))
        out.append(record(
            'logons' if remote else 'network', 'Sharing services', modified,
            f"{name} {'off' if disabled else 'on'}", name,
            {'launchd label': label, 'disabled': bool(disabled),
             'basis': "the overrides file's modification time (the last "
                      "change to any service)"},
            path=path, ref=ref))
    return out


def remote_management(data, modified, path, ref):
    """com.apple.RemoteManagement.plist: Apple Remote Desktop's access
    settings -- who may control the Mac and whether VNC viewers may."""
    plist = plistlib.loads(data)
    keys = ('ARD_AllLocalUsers', 'ARD_AllLocalUsersPrivs',
            'VNCLegacyConnectionsEnabled', 'ScreenSharingReqPermEnabled',
            'LoadRemoteManagementMenuExtra', 'DOCAllowRemoteConnections',
            'AdminConsoleAllowsRemoteControl')
    detail = {key: plist.get(key) for key in keys if key in plist}
    if not detail:
        return []
    detail['basis'] = "the settings file's modification time"
    return [record('logons', 'Remote Management', modified,
                   'Remote Management settings',
                   'all local users' if plist.get('ARD_AllLocalUsers')
                   else 'specific users', detail, path=path, ref=ref)]


def screen_sharing_client(data, user, modified, path, ref):
    """The Screen Sharing app's preferences: the computers this user
    connected to (recent hosts, as typed or found)."""
    plist = plistlib.loads(data)
    out = []
    seen = set()
    for key, value in plist.items():
        if not any(word in key.lower() for word in ('recent', 'host',
                                                    'connect')):
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, dict):
                item = item.get('host') or item.get('Host') or \
                    item.get('name')
            host = _text(item)
            if not isinstance(host, str) or not host or host in seen:
                continue
            seen.add(host)
            out.append(record(
                'logons', 'Screen Sharing', modified,
                'Screen Sharing host remembered', host,
                {'preference': key,
                 'basis': "the preferences file's modification time"},
                user=user, path=path, ref=ref))
    return out

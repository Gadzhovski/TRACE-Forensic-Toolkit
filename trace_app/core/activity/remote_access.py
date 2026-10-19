"""Where a user reached out to other machines: remote desktop, VNC and VPN
clients (no Qt). What lateral movement and remote work leave behind; cLEAPP
read the Android apps, and the same clients leave the same facts on
computers.

* **Microsoft Remote Desktop (mstsc)**, NTUSER.DAT: Terminal Server
  Client\\Default MRU0..MRU9 (the connection box's list; the key's last
  write dates MRU0) and Servers\\<host> (UsernameHint = the account used;
  the key's last write = the last connection that saved something).
  Default.rdp and other .rdp files (Documents, Desktop, Downloads):
  `key:type:value` lines -- full address, username, gateway. A saved
  `password 51` blob is named, never copied.
* **Microsoft Remote Desktop for Android** (RDPConnection.db): servers and
  their friendly names, the user name of the credential each uses. The
  credential's password is never selected.
* **RealVNC Viewer**: its connection files (`.vnc`, `Key=Value` lines:
  Host, FriendlyName, UserName, Uuid...) in ~/.vnc, the Windows profile's
  RealVNC folder, and the Android app's files. `Password` is never copied.
* **Palo Alto GlobalProtect**: the portals each user signed in to
  (NTUSER.DAT Software\\Palo Alto Networks\\GlobalProtect\\Settings\\
  <portal>, key last write) and the portal the client was installed
  for (SOFTWARE ...\\PanSetup).

No time without saying what it means: the registry's are key last-write
times, files' are their last change.
"""

import logging
import sqlite3

from trace_app.core.activity import record, sqlite_bytes

logger = logging.getLogger('TRACE.Activity.RemoteAccess')

_TSC = 'Software\\Microsoft\\Terminal Server Client'
_GP_USER = 'Software\\Palo Alto Networks\\GlobalProtect\\Settings'
_GP_SETUP = 'Palo Alto Networks\\GlobalProtect\\PanSetup'
#: .rdp settings worth a column, by name.
RDP_FIELDS = (('full address', 'address'), ('username', 'user name'),
              ('domain', 'domain'), ('gatewayhostname', 'gateway'),
              ('alternate full address', 'other address'),
              ('remoteapplicationprogram', 'remote program'),
              ('drivestoredirect', 'drives shared'),
              ('redirectclipboard', 'clipboard shared'))
#: .rdp / .vnc keys whose values are secrets.
_SECRETS = ('password 51', 'password', 'passwordencrypted',
            'proxypassword', 'gatewaycredentialssource')


# --- registry -----------------------------------------------------------------------

def terminal_server_client(hive):
    """{'recent': [{address, position, time}], 'servers': [{host, user,
    time, certificate}]} of an NTUSER.DAT."""
    from trace_app.core.activity.registry import _key, _utc, _value
    out = {'recent': [], 'servers': []}
    default = _key(hive, _TSC + '\\Default')
    if default is not None:
        for position in range(10):
            address = _value(default, f'MRU{position}')
            if address:
                out['recent'].append({
                    'address': str(address), 'position': position,
                    'time': _utc(default.timestamp()) if position == 0
                    else None})
    servers = _key(hive, _TSC + '\\Servers')
    for server in servers.subkeys() if servers is not None else []:
        out['servers'].append({
            'host': server.name(),
            'user': _value(server, 'UsernameHint'),
            'certificate': _value(server, 'CertHash') is not None,
            'time': _utc(server.timestamp())})
    return out


def globalprotect_portals(hive):
    """[{portal, time}] a user signed in to (NTUSER.DAT)."""
    from trace_app.core.activity.registry import _key, _utc, _value
    settings = _key(hive, _GP_USER)
    out = []
    for portal in settings.subkeys() if settings is not None else []:
        out.append({'portal': portal.name(),
                    'user': _value(portal, 'Username') or
                    _value(portal, 'UserName'),
                    'time': _utc(portal.timestamp())})
    return out


def globalprotect_setup(hive):
    """{'portal', 'time', ...} the client was installed for (SOFTWARE)."""
    from trace_app.core.activity.registry import _key, _utc, _value
    for path in (_GP_SETUP, 'WOW6432Node\\' + _GP_SETUP):
        key = _key(hive, path)
        if key is not None:
            return {'portal': _value(key, 'Portal'),
                    'prelogon': _value(key, 'Prelogon'),
                    'time': _utc(key.timestamp())}
    return None


def ntuser_records(hive, common):
    out = []
    found = terminal_server_client(hive)
    for item in found['recent']:
        out.append(record(
            'network', 'Terminal Server Client', item['time'],
            'Remote Desktop connection (recent)', item['address'],
            {'list position': item['position'] + 1,
             'basis': "the list's last change -- the newest entry only"
             if item['time'] else 'time known for the newest entry only'},
            **common))
    for item in found['servers']:
        out.append(record(
            'network', 'Terminal Server Client', item['time'],
            'Remote Desktop server', item['host'],
            {'user name': item['user'],
             'certificate accepted': 'yes' if item['certificate'] else None,
             'basis': "the server's key last written (a connection)"},
            **common))
    for item in globalprotect_portals(hive):
        out.append(record(
            'network', 'GlobalProtect', item['time'],
            'VPN portal used (GlobalProtect)', item['portal'],
            {'user name': item['user'],
             'basis': "the portal's key last written"}, **common))
    return out


def software_records(hive, common):
    setup = globalprotect_setup(hive)
    if not setup or not setup['portal']:
        return []
    return [record(
        'network', 'GlobalProtect', setup['time'],
        'VPN client installed for portal (GlobalProtect)',
        str(setup['portal']),
        {'pre-logon': setup['prelogon'],
         'basis': "the setup key's last write (the install)"}, **common)]


# --- files --------------------------------------------------------------------------

def rdp_file(text):
    """{setting: value} of a .rdp file (secrets kept out)."""
    out = {}
    for line in text.splitlines():
        parts = line.strip().split(':', 2)
        if len(parts) != 3:
            continue
        name = parts[0].strip().lower()
        if name in _SECRETS:
            out[name] = '(not copied)'
            continue
        out[name] = parts[2].strip()
    return out


def vnc_file(text):
    """{Key: value} of a RealVNC connection file (secrets kept out)."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if not sep or not key.strip():
            continue
        key = key.strip()
        out[key] = '(not copied)' if key.lower() in _SECRETS else \
            value.strip()
    return out


def _decode(data):
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', 'replace')
    return data.decode('utf-8', 'replace')


def rdp_records(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    base = _split(home.path)
    for folder in (('Documents',), ('My Documents',), ('Desktop',),
                   ('Downloads',)):
        place = volume.find(*base, *folder)
        for entry in volume.children(place, '.rdp') if place else ():
            step(entry.path)
            facts = rdp_file(_decode(volume.read(entry)))
            if not facts.get('full address'):
                continue
            detail = {label: facts.get(name) for name, label in RDP_FIELDS
                      if name != 'full address'}
            detail['saved password'] = 'yes (not copied)' \
                if facts.get('password 51') else None
            detail['basis'] = "the file's last change"
            out.append(record(
                'network', 'Remote Desktop file', entry.modified,
                'Remote Desktop connection saved', facts['full address'],
                detail, user=user, path=entry.path, ref=volume.ref(entry)))
    return out


#: Where RealVNC Viewer keeps its connections.
_VNC_PLACES = (('.vnc',), ('.vnc', 'config.d'), ('AppData', 'Roaming',
                                                 'RealVNC'),
               ('Library', 'Preferences', 'RealVNC'))
_VNC_APPS = ('com.realvnc.viewer.android',)


def vnc_records(volume, places, step, user=''):
    out = []
    for place in places:
        for entry in volume.children(place, '.vnc') if place else ():
            step(entry.path)
            facts = vnc_file(_decode(volume.read(entry)))
            host = facts.get('Host')
            if not host:
                continue
            out.append(record(
                'network', 'RealVNC Viewer', entry.modified,
                'VNC connection saved', host,
                {'name': facts.get('FriendlyName'),
                 'user name': facts.get('UserName'),
                 'connection time (as stored)': facts.get('ConnTime'),
                 'method': facts.get('ConnMethod'),
                 'ID': facts.get('Uuid'),
                 'saved password': 'yes (not copied)'
                 if facts.get('Password') else None,
                 'basis': "the file's last change"},
                user=user, path=entry.path, ref=volume.ref(entry)))
    return out


#: The Android Remote Desktop clients' packages.
_RDP_APPS = ('com.microsoft.rdc.androidx', 'com.microsoft.rdc.android')


def rdp_connections(data, wal=None):
    """[{server, name, user}] of RDPConnection.db (passwords never
    selected)."""
    with sqlite_bytes.open_database(data, wal) as connection:
        names = sqlite_bytes.tables(connection)
        if 'connection_table' not in names:
            raise sqlite3.DatabaseError('not RDPConnection.db')
        columns = sqlite_bytes.columns(connection, 'connection_table')
        friendly = 'servername_friendly' if 'servername_friendly' in \
            columns else "''"
        users = {}
        if 'credential_table' in names:
            cred = sqlite_bytes.columns(connection, 'credential_table')
            if {'credential_table_id', 'username'} <= cred:
                users = dict(connection.execute(
                    "SELECT credential_table_id, username FROM "
                    "credential_table"))
        credential = 'credential_id' if 'credential_id' in columns else \
            'NULL'
        return [{'server': server or '', 'name': name or '',
                 'user': users.get(cred_id)}
                for server, name, cred_id in connection.execute(
                    f"SELECT servername, {friendly}, {credential} FROM "
                    "connection_table")]


def android_records(volume, base, step):
    from trace_app.core.activity.mobile import _app
    out = []
    for package in _RDP_APPS:
        entry = _app(volume, base, package, 'databases', 'RDPConnection.db')
        if entry is None:
            continue
        step(entry.path)
        wal = _app(volume, base, package, 'databases',
                   'RDPConnection.db-wal')
        try:
            rows = rdp_connections(volume.read(entry),
                                   volume.read(wal) if wal else None)
        except (sqlite3.DatabaseError, ValueError) as exc:
            logger.debug("%s: %s", entry.path, exc)
            continue
        for row in rows:
            out.append(record(
                'network', 'Remote Desktop (Android)', None,
                'Remote Desktop server saved', row['server'],
                {'name': row['name'] or None, 'user name': row['user'],
                 'password': 'not read',
                 'basis': 'the database records no time'},
                path=entry.path, ref=volume.ref(entry)))
    for package in _VNC_APPS:
        files = _app(volume, base, package, 'files')
        out += vnc_records(volume, [files], step)
    return out


def collect(volume, step, homes):
    """The file-based items on any system (registry ones are read with
    each hive)."""
    from trace_app.core.activity import _split
    out = []
    for user, home in homes:
        out += rdp_records(volume, user, home, step)
        places = [volume.find(*_split(home.path), *parts)
                  for parts in _VNC_PLACES]
        out += vnc_records(volume, places, step, user)
    from trace_app.core.activity.mobile import android_base
    base = android_base(volume)
    if base is not None:
        out += android_records(volume, base, step)
    return out


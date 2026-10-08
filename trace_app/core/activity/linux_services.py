"""Networks a Linux machine joined, and the containers it ran (no Qt).

* NetworkManager: each saved connection profile
  (/etc/NetworkManager/system-connections/*, keyfile INI; older systems
  without the .nmconnection suffix) -- its name, type, Wi-Fi SSID and
  security, the addresses set, who may use it -- and when it was last
  connected: the profile's own `timestamp`, else NetworkManager's
  /var/lib/NetworkManager/timestamps, else the file's last change, said
  so. Wi-Fi passwords (psk, password, wep-key*) are never copied into a
  record, as with Windows' and Android's saved networks.
* Containers: Docker's /var/lib/docker/containers/<id>/config.v2.json --
  name, image, command, mounts, when it was created, last started and
  stopped -- and Podman's containers.json, system-wide
  (/var/lib/containers) and each user's rootless store.
"""

import configparser
import datetime
import json
import logging

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.LinuxServices')

#: Keys holding a secret; never copied out.
_SECRETS = ('psk', 'password', 'wep-key0', 'wep-key1', 'wep-key2',
            'wep-key3', 'leap-password', 'private-key-password', 'pin')


def _epoch(value):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(number, times.UTC)
    except (OverflowError, OSError, ValueError):
        return None


def nm_profile(text):
    """The facts of one NetworkManager keyfile: {section: {key: value}},
    secrets dropped. None if it is not one."""
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    if not parser.has_section('connection'):
        return None
    return {section: {key: value for key, value in parser.items(section)
                      if key not in _SECRETS}
            for section in parser.sections()}


def nm_timestamps(text):
    """{connection uuid: last connected} from NetworkManager's
    timestamps file."""
    profile = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        profile.read_string(text)
    except configparser.Error:
        return {}
    if not profile.has_section('timestamps'):
        return {}
    return {uuid: _epoch(value)
            for uuid, value in profile.items('timestamps')}


def network_activity(volume, step):
    out = []
    folder = volume.find('etc', 'NetworkManager', 'system-connections')
    if folder is None:
        return out
    last = {}
    stamps = volume.find('var', 'lib', 'NetworkManager', 'timestamps')
    if stamps is not None and not stamps.is_dir:
        last = nm_timestamps(volume.read(stamps).decode('utf-8', 'replace'))
    for entry in volume.children(folder):
        if entry.is_dir or not entry.size:
            continue
        step(entry.path)
        profile = nm_profile(volume.read(entry).decode('utf-8', 'replace'))
        if profile is None:
            continue
        connection = profile.get('connection', {})
        wifi = profile.get('wifi', profile.get('802-11-wireless', {}))
        security = profile.get('wifi-security',
                               profile.get('802-11-wireless-security', {}))
        uuid = connection.get('uuid', '')
        when = _epoch(connection.get('timestamp')) or last.get(uuid)
        basis = None
        if when is None:
            when = entry.modified
            basis = ("never recorded as connected: the time is the "
                     "profile's last change")
        kind = connection.get('type', '')
        ssid = wifi.get('ssid', '')
        addresses = ', '.join(
            value for section in ('ipv4', 'ipv6')
            for key, value in profile.get(section, {}).items()
            if key.startswith('address'))
        out.append(record(
            'network', 'NetworkManager', when,
            'Wi-Fi network saved' if ssid or 'wireless' in kind
            or kind == 'wifi' else 'Network connection saved',
            ssid or connection.get('id', entry.name),
            {'name': connection.get('id'), 'type': kind, 'ssid': ssid,
             'security': security.get('key-mgmt'),
             'mode': wifi.get('mode'),
             'hidden': wifi.get('hidden'),
             'mac address': wifi.get('mac-address') or
             profile.get('ethernet', {}).get('mac-address'),
             'interface': connection.get('interface-name'),
             'connects automatically': connection.get('autoconnect'),
             'allowed users': connection.get('permissions'),
             'addresses': addresses,
             'method': profile.get('ipv4', {}).get('method'),
             'vpn': profile.get('vpn', {}).get('service-type'),
             'uuid': uuid,
             'basis': basis or "last connected, as NetworkManager "
                               "recorded it"},
            path=entry.path, ref=volume.ref(entry)))
    return out


# --- containers -------------------------------------------------------------

def _docker_time(value):
    """Docker's RFC 3339 times with nanoseconds; 0001-01-01 = never."""
    if not value or str(value).startswith('0001-'):
        return None
    text = str(value).replace('Z', '+00:00')
    head, dot, rest = text.partition('.')
    if dot:
        width = len(rest) - len(rest.lstrip('0123456789'))
        digits, zone = rest[:width], rest[width:]
        text = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    try:
        return datetime.datetime.fromisoformat(text)
    except ValueError:
        return None


def docker_container(data):
    """The facts of a Docker config.v2.json, or None."""
    try:
        config = json.loads(data)
    except ValueError:
        return None
    if not isinstance(config, dict) or 'ID' not in config:
        return None
    inner = config.get('Config') or {}
    state = config.get('State') or {}
    command = ' '.join([config.get('Path') or ''] +
                       [str(a) for a in config.get('Args') or []]).strip()
    mounts = ', '.join(
        f"{m.get('Source') or m.get('Name') or '?'} -> "
        f"{m.get('Destination') or point}"
        for point, m in (config.get('MountPoints') or {}).items())
    return {'id': config['ID'], 'name': (config.get('Name') or '')
            .lstrip('/'), 'image': inner.get('Image') or config.get('Image'),
            'command': command, 'created': _docker_time(config.get('Created')),
            'started': _docker_time(state.get('StartedAt')),
            'finished': _docker_time(state.get('FinishedAt')),
            'running': state.get('Running'), 'exit code': state.get('ExitCode'),
            'user': inner.get('User'), 'mounts': mounts,
            'privileged': None}


def container_activity(volume, step, homes):
    out = []
    folder = volume.find('var', 'lib', 'docker', 'containers')
    for entry in volume.children(folder, dirs=True) if folder else ():
        config = volume.find(*entry.path.strip('/').split('/'),
                             'config.v2.json')
        if config is None or config.is_dir:
            continue
        step(config.path)
        facts = docker_container(volume.read(config))
        if facts is None:
            continue
        host = volume.find(*entry.path.strip('/').split('/'),
                           'hostconfig.json')
        if host is not None and not host.is_dir:
            try:
                facts['privileged'] = json.loads(volume.read(host)).get(
                    'Privileged') or None
            except ValueError:
                pass
        detail = {k: v for k, v in facts.items()
                  if k not in ('created', 'started', 'name')}
        detail['last stopped'] = facts['finished']
        subject = f"{facts['name'] or facts['id'][:12]} ({facts['image']})"
        ref = volume.ref(config)
        out.append(record('programs', 'Docker', facts['created'],
                          'Container created', subject, detail,
                          path=config.path, ref=ref))
        if facts['started']:
            out.append(record('programs', 'Docker', facts['started'],
                              'Container last started', subject, detail,
                              path=config.path, ref=ref))
    stores = [(('var', 'lib', 'containers', 'storage'), '')]
    from trace_app.core.activity import _split
    stores += [((*_split(home.path), '.local', 'share', 'containers',
                 'storage'), user) for user, home in homes]
    for parts, user in stores:
        entry = volume.find(*parts, 'overlay-containers', 'containers.json')
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        try:
            containers = json.loads(volume.read(entry))
        except ValueError:
            continue
        for item in containers if isinstance(containers, list) else ():
            names = ', '.join(item.get('names') or [])
            out.append(record(
                'programs', 'Podman', _docker_time(item.get('created')),
                'Container created',
                f"{names or str(item.get('id', ''))[:12]}",
                {'id': item.get('id'), 'image id': item.get('image'),
                 'rootless': 'yes' if user else None},
                user=user, path=entry.path, ref=volume.ref(entry)))
    return out


def collect(volume, step, homes):
    out = []
    for reader in (lambda: network_activity(volume, step),
                   lambda: container_activity(volume, step, homes)):
        try:
            out += reader()
        except Exception as exc:
            logger.warning("Linux services not read: %s", exc)
    return out

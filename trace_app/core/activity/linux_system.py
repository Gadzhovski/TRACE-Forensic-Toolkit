"""What a Linux system was and who could use it (no Qt).

* The system: its release (/etc/os-release, a link to /usr/lib on most
  distributions now), host name, time zone (/etc/localtime links to the
  zone; Debian also writes /etc/timezone) and machine-id. These have no
  "when"; each is dated by its file's last change, and says so.
* Accounts: /etc/passwd users who can log in (a shell that is not
  nologin/false) and root, with /etc/shadow's last password change -- the
  day only, which is all shadow keeps -- whether the password is locked
  or empty, and membership of the groups that may use sudo (wheel, sudo,
  admin).
* Software installed and removed: dnf5's transaction_history.sqlite
  (Fedora 41+), dnf's history.sqlite (Fedora, RHEL 8/9), apt's
  history.log (Debian, Ubuntu; local time with no zone, as apt writes
  it), each transaction one record with its command line and the
  packages asked for. dpkg.log too -- it alone sees a package installed
  with `dpkg -i` from a downloaded .deb, which apt never hears of -- one
  record per dpkg run (its 'startup' line), and yum.log (RHEL / CentOS
  7, no year: the file's, stepped back where months run backwards).
  Rotated copies (.1, .gz) included.
* SSH: the hosts each user connected to (known_hosts; hashed host names
  stay hashed -- the key is still evidence) and the keys allowed to log in
  as them (authorized_keys).
"""

import datetime
import gzip
import logging
import re
import sqlite3

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.LinuxSystem')

ADMIN_GROUPS = ('wheel', 'sudo', 'admin')
NO_LOGIN = ('nologin', 'false', 'sync', 'shutdown', 'halt')


def _text(volume, entry):
    entry = volume.resolve(entry)
    if entry is None or entry.is_dir:
        return None, None
    return volume.read(entry).decode('utf-8', 'replace'), entry


def _changed(entry):
    stamp = times.iso(entry.modified) if entry.modified else None
    return f"the file's last change ({stamp or 'unknown'})"


# --- the system -----------------------------------------------------------------

def os_release(text):
    """{KEY: value} of an os-release file."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() and not key.startswith('#'):
            out[key.strip()] = value.strip().strip('"\'')
    return out


def system_facts(volume, step):
    out = []
    release_entry = volume.find('etc', 'os-release') or \
        volume.find('usr', 'lib', 'os-release')
    if release_entry is not None:
        text, entry = _text(volume, release_entry)
        if text:
            step(entry.path)
            facts = os_release(text)
            name = facts.get('PRETTY_NAME') or ' '.join(
                p for p in (facts.get('NAME'), facts.get('VERSION')) if p)
            out.append(record(
                'system', 'os-release', entry.modified, 'Operating system',
                name, {'id': facts.get('ID'),
                       'version': facts.get('VERSION_ID'),
                       'variant': facts.get('VARIANT') or
                       facts.get('VARIANT_ID'),
                       'basis': _changed(entry)},
                path=entry.path, ref=volume.ref(entry)))
    for parts in (('etc', 'hostname'), ('etc', 'HOSTNAME')):
        text, entry = _text(volume, volume.find(*parts))
        if text and text.strip():
            out.append(record('system', 'hostname', entry.modified,
                              'Host name', text.strip().splitlines()[0],
                              {'basis': _changed(entry)}, path=entry.path,
                              ref=volume.ref(entry)))
            break
    localtime = volume.find('etc', 'localtime')
    zone = None
    if localtime is not None and getattr(localtime, 'is_link', False):
        target = volume.read(localtime).decode('utf-8', 'replace')
        if 'zoneinfo/' in target:
            zone = target.split('zoneinfo/', 1)[1].strip()
        source = localtime
    if zone is None:
        text, entry = _text(volume, volume.find('etc', 'timezone'))
        if text and text.strip():
            zone, source = text.strip(), entry
    if zone:
        out.append(record('system', 'time zone', source.modified,
                          'Time zone', zone, {'basis': _changed(source)},
                          path=source.path, ref=volume.ref(source)))
    text, entry = _text(volume, volume.find('etc', 'machine-id'))
    if text and re.fullmatch(r'[0-9a-f]{32}', text.strip()):
        out.append(record('system', 'machine-id', entry.modified,
                          'Machine ID', text.strip(),
                          {'basis': _changed(entry)}, path=entry.path,
                          ref=volume.ref(entry)))
    return out


# --- accounts -----------------------------------------------------------------------

def parse_accounts(passwd, shadow='', group=''):
    """[{name, uid, gid, comment, home, shell, changed (date or None),
    password ('set' | 'locked' | 'none' | ''), groups}] for root, the
    users (UID 1000 up) who can log in, and any service account with a
    usable password -- which is worth noticing."""
    shadows = {}
    for line in shadow.splitlines():
        fields = line.split(':')
        if len(fields) >= 3:
            shadows[fields[0]] = fields
    memberships = {}
    for line in group.splitlines():
        fields = line.split(':')
        if len(fields) >= 4:
            for member in filter(None, fields[3].split(',')):
                memberships.setdefault(member.strip(), []).append(fields[0])
    out = []
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) < 7 or line.startswith('#'):
            continue
        name, _x, uid, gid, comment, home, shell = fields[:7]
        try:
            uid = int(uid)
        except ValueError:
            continue
        if uid != 0 and shell.rsplit('/', 1)[-1] in NO_LOGIN:
            continue
        entry = shadows.get(name)
        changed, password = None, ''
        if entry:
            hashed = entry[1]
            password = ('none' if hashed == '' else
                        'locked' if hashed.startswith(('!', '*')) else 'set')
            if entry[2].isdigit() and int(entry[2]):
                changed = (datetime.datetime(1970, 1, 1, tzinfo=times.UTC)
                           + datetime.timedelta(days=int(entry[2])))
        # A service account (below 1000, older systems gave them /bin/sh)
        # is listed only if it can actually be logged into with a password.
        if 0 < uid < 1000 and password not in ('set', 'none'):
            continue
        if uid == 65534:                                   # nobody
            continue
        out.append({'name': name, 'uid': uid, 'gid': gid,
                    'comment': comment, 'home': home, 'shell': shell,
                    'changed': changed, 'password': password,
                    'groups': memberships.get(name, [])})
    return out


def account_activity(volume, step):
    passwd, entry = _text(volume, volume.find('etc', 'passwd'))
    if not passwd:
        return []
    step(entry.path)
    shadow, _ = _text(volume, volume.find('etc', 'shadow'))
    group, _ = _text(volume, volume.find('etc', 'group'))
    out = []
    for account in parse_accounts(passwd, shadow or '', group or ''):
        admin = sorted(set(account['groups']) & set(ADMIN_GROUPS))
        out.append(record(
            'system', 'passwd', account['changed'], 'User account',
            account['name'],
            {'uid': account['uid'], 'home': account['home'],
             'shell': account['shell'], 'full name': account['comment'],
             'password': {'none': 'empty -- logs in with none',
                          'locked': 'locked',
                          'set': 'set'}.get(account['password']),
             'groups': ', '.join(account['groups']),
             'can use sudo': 'yes (' + ', '.join(admin) + ')'
             if admin else None,
             'basis': "the day the password was last changed (shadow)"
             if account['changed'] else None},
            user=account['name'], path=entry.path, ref=volume.ref(entry)))
    return out


# --- software -------------------------------------------------------------------------

def _columns(db, table):
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def dnf_transactions(db):
    """[{begin, end, command, user, installed, removed, upgraded, asked}]
    from dnf5's or dnf4's history database."""
    columns = _columns(db, 'trans')
    if not {'id', 'dt_begin'} <= columns:
        return []
    item_columns = _columns(db, 'trans_item')
    action = 'action_id' if 'action_id' in item_columns else 'action'
    reason = 'reason_id' if 'reason_id' in item_columns else 'reason'
    names = {}
    if {'item_id', 'name_id'} <= _columns(db, 'rpm'):
        names = dict(db.execute(
            "SELECT r.item_id, p.name FROM rpm r JOIN pkg_name p "
            "ON p.id = r.name_id"))
    elif 'name' in _columns(db, 'rpm'):
        names = dict(db.execute("SELECT item_id, name FROM rpm"))
    out = []
    cmdline = 'cmdline' if 'cmdline' in columns else "''"
    user = 'user_id' if 'user_id' in columns else 'NULL'
    for trans_id, begin, end, command, uid in db.execute(
            f"SELECT id, dt_begin, dt_end, {cmdline}, {user} FROM trans "
            f"ORDER BY id"):
        counts = {'installed': 0, 'removed': 0, 'upgraded': 0}
        asked = []
        try:
            items = db.execute(
                f"SELECT item_id, {action}, {reason} FROM trans_item "
                f"WHERE trans_id = ?", (trans_id,)).fetchall()
        except sqlite3.Error:
            items = []
        for item_id, act, why in items:
            # Install 1, Upgrade 2, Downgrade 3, Reinstall 4, Remove 5,
            # Replaced 6 -- dnf4 and dnf5 alike; reason 2 = asked for.
            if act == 1:
                counts['installed'] += 1
            elif act == 5:
                counts['removed'] += 1
            elif act in (2, 3):
                counts['upgraded'] += 1
            if why == 2 and act in (1, 2, 4, 5) and item_id in names:
                asked.append(names[item_id])
        out.append({'begin': begin, 'end': end, 'command': command or '',
                    'user': uid, 'asked': asked, **counts})
    return out


_APT_TIME = '%Y-%m-%d  %H:%M:%S'


def apt_history(text):
    """[{start, command, user, install, remove, upgrade, purge}] from
    apt's history.log; times are local with no zone."""
    out, block = [], {}
    for line in text.splitlines() + ['']:
        if not line.strip():
            if block.get('Start-Date'):
                try:
                    start = datetime.datetime.strptime(
                        block['Start-Date'].strip(), _APT_TIME)
                except ValueError:
                    start = None
                out.append({'start': start,
                            'command': block.get('Commandline', ''),
                            'user': block.get('Requested-By', ''),
                            **{key.lower(): _apt_packages(block.get(key, ''))
                               for key in ('Install', 'Remove', 'Upgrade',
                                           'Purge')}})
            block = {}
            continue
        key, sep, value = line.partition(': ')
        if sep:
            block[key] = value
    return out


_DPKG_LINE = re.compile(
    r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+) (.*)$')
_DPKG_ACTIONS = {'install': 'installed', 'upgrade': 'upgraded',
                 'remove': 'removed', 'purge': 'purged'}


def dpkg_runs(text):
    """[{start, command, installed, upgraded, removed, purged}] from
    dpkg.log: one per dpkg run, which begins with a 'startup' line.
    Times are local with no zone, as dpkg writes them."""
    runs, current = [], None
    for line in text.splitlines():
        match = _DPKG_LINE.match(line)
        if not match:
            continue
        stamp, action, rest = match.groups()
        if action == 'startup' or current is None:
            try:
                start = datetime.datetime.strptime(stamp, _APT_TIME)
            except ValueError:
                start = None
            current = {'start': start, 'command': rest
                       if action == 'startup' else '',
                       **{v: [] for v in _DPKG_ACTIONS.values()}}
            runs.append(current)
            if action == 'startup':
                continue
        kind = _DPKG_ACTIONS.get(action)
        if kind:
            # "pkg:amd64 1.0-1 1.0-2" / "pkg:amd64 <none> 1.0-1"
            current[kind].append(rest.split()[0].split(':', 1)[0])
    return [run for run in runs
            if any(run[k] for k in _DPKG_ACTIONS.values())]


_YUM_LINE = re.compile(r'^(\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) '
                       r'(Installed|Updated|Erased|Obsoleted): (\S+)')
_MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
           'Oct', 'Nov', 'Dec')


def yum_log(text, year):
    """[(when, action, package)] from yum.log, which records no year:
    the newest line is in `year` (the file's), and the year steps back
    each time the months run backwards going up the file. Local time."""
    rows = [m.groups() for m in map(_YUM_LINE.match, text.splitlines())
            if m]
    out, current, later = [], year, None
    for month, day, hour, minute, second, action, package in \
            reversed(rows):
        number = _MONTHS.index(month) + 1 if month in _MONTHS else None
        if number is None:
            continue
        if later is not None and number > later:
            current -= 1
        later = number
        try:
            when = datetime.datetime(current, number, int(day), int(hour),
                                     int(minute), int(second))
        except ValueError:
            when = None
        out.append((when, action, package))
    out.reverse()
    return out


def _package_logs(volume, step):
    """dpkg.log and yum.log records, rotated copies included."""
    from trace_app.core.activity.linux import log_bytes
    out = []
    log = volume.find('var', 'log')
    for entry in volume.children(log):
        name = entry.name.lower()
        if entry.is_dir or not entry.size:
            continue
        if name.startswith('dpkg.log'):
            step(entry.path)
            for run in dpkg_runs(log_bytes(volume, entry).decode(
                    'utf-8', 'replace')):
                changed = run['installed'] + run['upgraded']
                gone = run['removed'] + run['purged']
                what = ('Software removed' if gone and not changed else
                        'Software installed' if run['installed'] else
                        'Software changed')
                out.append(record(
                    'system', 'dpkg log', run['start'], what,
                    ', '.join((run['installed'] or gone or
                               run['upgraded'])[:20]),
                    {'command': run['command'],
                     'installed': len(run['installed']) or None,
                     'upgraded': len(run['upgraded']) or None,
                     'removed': len(gone) or None,
                     'packages': ', '.join(run['installed'] + gone +
                                           run['upgraded']) or None},
                    path=entry.path, ref=volume.ref(entry), local=True))
        elif name.startswith('yum.log'):
            step(entry.path)
            year = (entry.modified or
                    datetime.datetime.now(times.UTC)).year
            for when, action, package in yum_log(
                    log_bytes(volume, entry).decode('utf-8', 'replace'),
                    year):
                what = {'Installed': 'Software installed',
                        'Updated': 'Software changed'}.get(
                            action, 'Software removed')
                out.append(record(
                    'system', 'yum log', when, what, package,
                    {'action': action.lower(),
                     'basis': "yum.log has no year: taken from the file's "
                              "last change, stepped back where months run "
                              "backwards"},
                    path=entry.path, ref=volume.ref(entry), local=True))
    return out


def _apt_packages(value):
    # "pkg:amd64 (1.2-3), other:amd64 (4.5, automatic)"
    return [p.split(':', 1)[0].strip()
            for p in re.split(r'\),\s*', value) if p.strip()]


def software_activity(volume, step):
    from trace_app.core.activity import sqlite_bytes
    out = []
    for parts in (('usr', 'lib', 'sysimage', 'libdnf5',
                   'transaction_history.sqlite'),
                  ('var', 'lib', 'dnf', 'history.sqlite')):
        entry = volume.find(*parts)
        if entry is None or entry.is_dir or not entry.size:
            continue
        step(entry.path)
        wal = volume.find(*parts[:-1], parts[-1] + '-wal')
        try:
            with sqlite_bytes.open_database(
                    volume.read(entry),
                    volume.read(wal) if wal is not None else None) as db:
                transactions = dnf_transactions(db)
        except (sqlite3.Error, ValueError) as exc:
            logger.debug("%s unreadable: %s", entry.path, exc)
            continue
        source = 'dnf5 history' if 'libdnf5' in parts else 'dnf history'
        for item in transactions:
            when = datetime.datetime.fromtimestamp(item['begin'], times.UTC) \
                if item['begin'] else None
            what = ('Software removed' if item['removed'] and not
                    item['installed'] else 'Software installed'
                    if item['installed'] else 'Software changed')
            out.append(record(
                'system', source, when, what,
                ', '.join(item['asked'][:20]) or item['command'],
                {'command': item['command'],
                 'installed': item['installed'] or None,
                 'removed': item['removed'] or None,
                 'upgraded': item['upgraded'] or None,
                 'asked for': ', '.join(item['asked']),
                 'user id': item['user'],
                 'finished': datetime.datetime.fromtimestamp(
                     item['end'], times.UTC) if item['end'] else None},
                path=entry.path, ref=volume.ref(entry)))
    folder = volume.find('var', 'log', 'apt')
    for entry in volume.children(folder):
        name = entry.name.lower()
        if not name.startswith('history.log'):
            continue
        step(entry.path)
        data = volume.read(entry)
        if name.endswith('.gz'):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError):
                continue
        for item in apt_history(data.decode('utf-8', 'replace')):
            what = ('Software removed' if (item['remove'] or item['purge'])
                    and not item['install'] else 'Software installed'
                    if item['install'] else 'Software changed')
            out.append(record(
                'system', 'apt history', item['start'], what,
                ', '.join((item['install'] or item['remove'] or
                           item['purge'] or item['upgrade'])[:20])
                or item['command'],
                {'command': item['command'],
                 'installed': len(item['install']) or None,
                 'removed': len(item['remove'] + item['purge']) or None,
                 'upgraded': len(item['upgrade']) or None,
                 'requested by': item['user']},
                user=item['user'].split(' (')[0], path=entry.path,
                ref=volume.ref(entry), local=True))
    return out


# --- SSH --------------------------------------------------------------------------------

def known_hosts(text):
    """[(host, key type, hashed)] from a known_hosts file."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if fields[0].startswith('@'):           # @cert-authority, @revoked
            fields = fields[1:]
        if len(fields) < 2:
            continue
        hosts = fields[0]
        hashed = hosts.startswith('|1|')
        for host in ([hosts] if hashed else hosts.split(',')):
            out.append((host, fields[1], hashed))
    return out


_KEY_TYPES = re.compile(r'(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|'
                        r'sk-\S+@openssh\.com)\s+(\S+)(\s+(.*))?$')


def authorized_keys(text):
    """[(key type, comment, options)] from an authorized_keys file."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = _KEY_TYPES.search(line)
        if not match:
            continue
        options = line[:match.start()].strip()
        out.append((match.group(1), (match.group(5) or '').strip(), options))
    return out


def ssh_activity(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    base = _split(home.path)
    entry = volume.find(*base, '.ssh', 'known_hosts')
    text, entry = _text(volume, entry) if entry is not None else (None, None)
    if text:
        step(entry.path)
        for host, kind, hashed in known_hosts(text):
            out.append(record(
                'logons', 'known_hosts', entry.modified,
                'SSH host connected to', host,
                {'key type': kind,
                 'hashed': 'yes -- the name is stored as a hash' if hashed
                 else None,
                 'basis': "known_hosts records no time per host; "
                          + _changed(entry)},
                user=user, path=entry.path, ref=volume.ref(entry)))
    for name in ('authorized_keys', 'authorized_keys2'):
        entry = volume.find(*base, '.ssh', name)
        text, entry = _text(volume, entry) if entry is not None \
            else (None, None)
        if not text:
            continue
        step(entry.path)
        for kind, comment, options in authorized_keys(text):
            out.append(record(
                'logons', 'authorized_keys', entry.modified,
                'SSH key allowed to log in', comment or kind,
                {'key type': kind, 'options': options,
                 'basis': _changed(entry)},
                user=user, path=entry.path, ref=volume.ref(entry)))
    return out


def collect(volume, step, homes):
    out = system_facts(volume, step)
    out += account_activity(volume, step)
    out += software_activity(volume, step)
    out += _package_logs(volume, step)
    for user, home in homes:
        out += ssh_activity(volume, user, home, step)
    return out

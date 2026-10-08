"""What the users of a Linux system did: commands typed, logons, files
opened, and what the system logged about them.

* Shell histories: bash (`#<epoch>` lines precede a command when
  HISTTIMEFORMAT was set; otherwise there is no time at all, and the
  commands are listed in order with none), zsh's extended history
  (`: <epoch>:<seconds>;<command>`) and fish's YAML-like file.
* utmp / wtmp / btmp: fixed records (glibc: 384 bytes, 400 on 64-bit
  time); wtmp holds every logon, logoff, boot and shutdown, btmp the failed
  logons.
* recently-used.xbel: GNOME/GTK's record of files opened, and by which
  application.
* The systemd journal (activity/journal.py) and the syslog files
  (auth.log, secure): only what an examiner reads them for -- logons local
  and remote and their failures, sudo and pkexec commands, su, accounts
  created or changed, USB devices, boots and shutdowns. A journal holds
  everything a system logged; listing every CRON line would bury these.

Expected values in the tests are plaso's and dissect's for the same files.
"""

import datetime
import logging
import re
import struct
import xml.etree.ElementTree as ElementTree

from trace_app.core.activity import journal, record, times

logger = logging.getLogger('TRACE.Activity.Linux')


# --- shell histories --------------------------------------------------------------

_BASH_TIME = re.compile(r'^#(\d{9,11})$')


def bash_history(text):
    """[(datetime or None, command)] in file order. With timestamps, a
    command runs from its time line to the next one (a multi-line command
    is joined with spaces, as bash shows it)."""
    lines = text.splitlines()
    out, when, command, timed = [], None, [], any(
        _BASH_TIME.match(line) for line in lines)
    for line in lines:
        match = _BASH_TIME.match(line)
        if match:
            if command:
                out.append((when, ' '.join(command)))
            when, command = times.unix(int(match.group(1))), []
            continue
        if not timed:
            if line.strip():
                out.append((None, line))
            continue
        if when is None:
            # Before the first time line (a history that was cut, or
            # written before HISTTIMEFORMAT was set): a command of its own.
            if line.strip():
                out.append((None, line))
            continue
        command.append(line)
    if command:
        out.append((when, ' '.join(command)))
    return out


_ZSH = re.compile(r'^: (\d{9,11}):(\d+);(.*)$')


def zsh_history(text):
    """[(datetime, elapsed seconds, command)]; a line ending in a backslash
    continues on the next."""
    out = []
    for line in text.splitlines():
        match = _ZSH.match(line)
        if match:
            out.append([times.unix(int(match.group(1))),
                        int(match.group(2)), match.group(3)])
        elif out and out[-1][2].endswith('\\'):
            out[-1][2] = out[-1][2][:-1] + '\n' + line
    return [tuple(item) for item in out]


def fish_history(text):
    """[(datetime, command, [paths])]."""
    out = []
    for line in text.splitlines():
        if line.startswith('- cmd: '):
            out.append([None, line[7:].replace('\\n', '\n')
                        .replace('\\\\', '\\'), []])
        elif out and line.startswith('  when: '):
            value = line[8:].strip()
            out[-1][0] = times.unix(int(value)) if value.isdigit() else None
        elif out and line.startswith('    - '):
            out[-1][2].append(line[6:])
    return [tuple(item) for item in out]


# --- utmp / wtmp / btmp ------------------------------------------------------------------

UT_TYPES = {1: 'run level', 2: 'boot', 3: 'clock set', 4: 'clock changed',
            5: 'init process', 6: 'login prompt', 7: 'logon', 8: 'logoff',
            9: 'accounting'}


def _text(raw):
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


def _address(raw):
    if raw[4:] == bytes(12):
        return '.'.join(str(b) for b in raw[:4]) if raw[:4] != bytes(4) \
            else ''
    try:
        import ipaddress
        return str(ipaddress.IPv6Address(bytes(raw)))
    except ValueError:
        return ''


def utmp_records(data):
    """[{'type', 'pid', 'terminal', 'terminal_id', 'user', 'host', 'ip',
    'time', 'session'}] from a glibc utmp/wtmp/btmp file."""
    size = 400 if len(data) % 384 and not len(data) % 400 else 384
    out = []
    for offset in range(0, len(data) - size + 1, size):
        raw = data[offset:offset + size]
        kind, pid = struct.unpack_from('<hxxi', raw, 0)
        if size == 384:
            session, seconds, micro = struct.unpack_from('<iii', raw, 336)
            address = raw[348:364]
        else:
            session, seconds, micro = struct.unpack_from('<qqq', raw, 336)
            address = raw[360:376]
        if kind not in UT_TYPES:
            continue                    # empty or damaged
        when = times.unix(seconds)
        if when is not None and 0 <= micro < 1_000_000:
            when = when.replace(microsecond=micro)
        out.append({'offset': offset, 'type': kind, 'pid': pid,
                    'terminal': _text(raw[8:40]),
                    'terminal_id': struct.unpack_from('<I', raw, 40)[0],
                    'user': _text(raw[44:76]), 'host': _text(raw[76:332]),
                    'ip': _address(address), 'time': when,
                    'session': session})
    return out


def wtmp_activity(data, path, ref, failed=False):
    out = []
    for item in utmp_records(data):
        kind, user = item['type'], item['user']
        detail = {'terminal': item['terminal'], 'host': item['host'],
                  'address': item['ip'], 'pid': item['pid'],
                  'record': UT_TYPES[item['type']]}
        if failed:
            what = 'Failed logon'
        elif kind == 7:
            what = 'Remote logon' if item['host'] and item['host'] not in (
                ':0', ':1') and not item['host'].startswith(':') else 'Logon'
        elif kind == 8:
            what = 'Logoff'
        elif kind == 2:
            what, user = 'System boot', ''
        elif kind == 1 and user == 'shutdown':
            what, user = 'System shutdown', ''
        else:
            continue
        if what in ('System boot', 'System shutdown'):
            # The terminal is "~"; the host field holds the kernel version.
            subject = f"kernel {item['host']}" if item['host'] else ''
        else:
            subject = f"{user} on {item['terminal']}" if user and \
                item['terminal'] else (user or item['terminal'])
        if item['host'] and what in ('Logon', 'Remote logon', 'Failed logon'):
            subject += f" from {item['host']}"
        out.append(record('logons' if 'boot' not in what and 'shutdown'
                          not in what else 'system',
                          'btmp' if failed else 'wtmp', item['time'], what,
                          subject, detail, user=user, path=path, ref=ref))
    return out


# --- recently-used.xbel ---------------------------------------------------------------

def _xbel_time(value):
    if not value:
        return None
    try:
        return datetime.datetime.strptime(
            value.rstrip('Z')[:26], '%Y-%m-%dT%H:%M:%S.%f').replace(
                tzinfo=times.UTC)
    except ValueError:
        try:
            return datetime.datetime.strptime(
                value.rstrip('Z')[:19], '%Y-%m-%dT%H:%M:%S').replace(
                    tzinfo=times.UTC)
        except ValueError:
            return None


def recently_used(data):
    """[{'href', 'added', 'modified', 'visited', 'mime', 'apps': [...]}]."""
    namespaces = {'bookmark': 'http://www.freedesktop.org/standards/'
                              'desktop-bookmarks',
                  'mime': 'http://www.freedesktop.org/standards/'
                          'shared-mime-info'}
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return []
    out = []
    for bookmark in root.iter('bookmark'):
        mime = bookmark.find('.//mime:mime-type', namespaces)
        apps = [(a.get('name'), a.get('exec'), _xbel_time(a.get('modified')),
                 a.get('count'))
                for a in bookmark.iterfind('.//bookmark:application',
                                           namespaces)]
        out.append({'href': bookmark.get('href') or '',
                    'added': _xbel_time(bookmark.get('added')),
                    'modified': _xbel_time(bookmark.get('modified')),
                    'visited': _xbel_time(bookmark.get('visited')),
                    'mime': mime.get('type') if mime is not None else '',
                    'apps': apps})
    return out


def _file_path(href):
    from urllib.parse import unquote, urlparse
    parsed = urlparse(href)
    return unquote(parsed.path) if parsed.scheme == 'file' else href


# --- logs: what is worth reading -----------------------------------------------------

_SUDO = re.compile(r'^\s*(\S+) : (?:.*?; )?TTY=(\S+) ; PWD=(.*?) ; '
                   r'USER=(\S+) ; (?:.*?; )?COMMAND=(.*)$')
_PKEXEC = re.compile(r'^(\S+): Executing command \[USER=(\S+)\] '
                     r'\[TTY=(\S+)\] \[CWD=(.*?)\] \[COMMAND=(.*)\]$')
_SSH_OK = re.compile(r'^Accepted (\S+) for (\S+) from (\S+) port (\d+)')
_SSH_FAIL = re.compile(r'^Failed (\S+) for (invalid user )?(\S+) from (\S+) '
                       r'port (\d+)')
_SSH_INVALID = re.compile(r'^Invalid user (\S*) from (\S+)')
_LOGIND_NEW = re.compile(r'^New session (\S+) of user (\S+)\.')
_LOGIND_GONE = re.compile(r'^Removed session (\S+)\.')
_SU = re.compile(r'^(?:Successful su for (\S+) by (\S+)|'
                 r'\(to (\S+)\) (\S+) on (\S+))')
_SU_FAIL = re.compile(r'^FAILED (?:SU|su) \(to (\S+)\) (\S+) on (\S+)')
_AUTH_FAIL = re.compile(r'authentication failure;.*?(?:ruser=(\S*))?.*?'
                        r'rhost=(\S*)\s+user=(\S+)')
_USERADD = re.compile(r'^new user: name=([^,]+), UID=(\d+)')
_USERDEL = re.compile(r"^delete user '([^']+)'")
_PASSWD = re.compile(r'^password (?:for \'?(\S+?)\'? )?changed(?: for (\S+))?')
_USB_NEW = re.compile(r'^usb ([\d.-]+): New USB device found, '
                      r'idVendor=(\w+), idProduct=(\w+)')
_USB_FACT = re.compile(r'^usb ([\d.-]+): (Product|Manufacturer|SerialNumber):'
                       r' (.*)$')
_USB_STORAGE = re.compile(r'^usb-storage ([\d.:-]+): USB Mass Storage device '
                          r'detected')
_STARTUP = re.compile(r'^Startup finished in ')
_SHUTDOWN = re.compile(r'^(System is (?:powering down|rebooting)|'
                       r'Reached target (?:System )?(?:Power-Off|Shutdown|'
                       r'Reboot)\.?)')


class Describer:
    """Turns log messages into activity records, keeping the USB facts the
    kernel logs line by line together as one device."""

    def __init__(self, source, path, ref, local=False):
        self.source, self.path, self.ref, self.local = source, path, ref, \
            local
        self.out = []
        self._usb = {}

    def _add(self, category, when, what, subject, detail, user=''):
        self.out.append(record(category, self.source, when, what, subject,
                               detail, user=user, path=self.path,
                               ref=self.ref, local=self.local))
        return self.out[-1]

    def message(self, when, ident, text, pid=None, host=''):
        ident = (ident or '').split('/')[-1]
        text = text or ''
        match = None
        if ident == 'sudo' and (match := _SUDO.match(text)):
            user, tty, cwd, run_as, command = match.groups()
            return self._add('programs', when, f'Command run as {run_as} '
                             f'(sudo)', command, {'terminal': tty,
                                                  'directory': cwd,
                                                  'as user': run_as},
                             user=user)
        if ident == 'pkexec' and (match := _PKEXEC.match(text)):
            user, run_as, tty, cwd, command = match.groups()
            return self._add('programs', when, f'Command run as {run_as} '
                             f'(pkexec)', command, {'terminal': tty,
                                                    'directory': cwd},
                             user=user)
        if ident == 'sshd':
            if match := _SSH_OK.match(text):
                method, user, address, port = match.groups()
                return self._add('logons', when, 'Remote logon (SSH)',
                                 f"{user} from {address}",
                                 {'method': method, 'address': address,
                                  'port': port}, user=user)
            if match := _SSH_FAIL.match(text):
                method, invalid, user, address, port = match.groups()
                return self._add('logons', when, 'Failed SSH logon',
                                 f"{user} from {address}",
                                 {'method': method, 'address': address,
                                  'port': port, 'account exists':
                                  'no' if invalid else ''}, user=user)
            if match := _SSH_INVALID.match(text):
                user, address = match.groups()
                return self._add('logons', when, 'Failed SSH logon',
                                 f"{user} from {address}",
                                 {'address': address,
                                  'account exists': 'no'}, user=user)
            return None
        if ident == 'systemd-logind':
            if match := _LOGIND_NEW.match(text):
                session, user = match.groups()
                return self._add('logons', when, 'Logon session started',
                                 f"{user} (session {session})",
                                 {'session': session}, user=user)
            if match := _LOGIND_GONE.match(text):
                return self._add('logons', when, 'Logon session ended',
                                 f"session {match.group(1)}",
                                 {'session': match.group(1)})
            if _SHUTDOWN.match(text):
                return self._add('system', when, 'System shutdown', text, {})
            return None
        if ident == 'su':
            if match := _SU_FAIL.match(text):
                target, user, tty = match.groups()
                return self._add('logons', when, 'Failed su',
                                 f"{user} to {target}", {'terminal': tty},
                                 user=user)
            if match := _SU.match(text):
                groups = match.groups()
                target, user = (groups[0], groups[1]) if groups[0] else \
                    (groups[2], groups[3])
                return self._add('logons', when, 'Switched user (su)',
                                 f"{user} to {target}", {}, user=user)
            return None
        if ident in ('useradd', 'adduser') and (match := _USERADD.match(text)):
            return self._add('system', when, 'User account created',
                             match.group(1), {'uid': match.group(2)})
        if ident == 'userdel' and (match := _USERDEL.match(text)):
            return self._add('system', when, 'User account deleted',
                             match.group(1), {})
        if ident in ('passwd', 'chpasswd') and (match := _PASSWD.match(text)):
            who = match.group(1) or match.group(2) or ''
            return self._add('system', when, 'Password changed', who, {},
                             user=who)
        if ident == 'kernel':
            if match := _USB_NEW.match(text):
                bus, vendor, product = match.groups()
                item = self._add('usb', when, 'USB device connected', bus,
                                 {'vendor id': vendor,
                                  'product id': product, 'port': bus})
                self._usb[bus] = item
                return item
            if match := _USB_FACT.match(text):
                bus, key, value = match.groups()
                item = self._usb.get(bus)
                if item is not None:
                    item['detail'][key.lower()] = value.strip()
                    if key == 'Product':
                        item['subject'] = value.strip()
                return None
            if match := _USB_STORAGE.match(text):
                bus = match.group(1).split(':')[0]
                item = self._usb.get(bus)
                if item is not None:
                    item['detail']['kind'] = 'mass storage'
                return None
            return None
        if ident == 'systemd':
            if _STARTUP.match(text) and 'user@' not in (host or ''):
                return self._add('system', when, 'System started', text, {})
            if _SHUTDOWN.match(text):
                return self._add('system', when, 'System shutdown', text, {})
        return None


def journal_activity(data, path, ref):
    """Records from one journal file, and how many entries it held."""
    try:
        reader = journal.Journal(data)
    except journal.JournalError:
        return [], 0
    describer = Describer('journal', path, ref)
    count = 0
    for fields in reader.entries():
        count += 1
        ident = fields.get('SYSLOG_IDENTIFIER') or fields.get('_COMM') or ''
        if ident == 'kernel' or fields.get('_TRANSPORT') == 'kernel':
            ident = 'kernel'
        item = describer.message(journal.source_time(fields), ident,
                                 fields.get('MESSAGE'),
                                 host=fields.get('_SYSTEMD_UNIT') or '')
        if item is not None:
            item['detail'].update({k: v for k, v in (
                ('host', fields.get('_HOSTNAME')),
                ('unit', fields.get('_SYSTEMD_UNIT')),
                ('boot', fields.get('_BOOT_ID'))) if v})
    for item in describer.out:
        if reader.undecoded:
            item['detail']['note'] = (
                f"{reader.undecoded} compressed field(s) in this file are "
                f"damaged and could not be decoded")
    return describer.out, count


_SYSLOG = re.compile(r'^(\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) '
                     r'([^:\[]+)(?:\[(\d+)\])?: (.*)$')
_ISO_SYSLOG = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?'
                         r'([+-]\d\d:\d\d|Z)? (\S+) ([^:\[]+)'
                         r'(?:\[(\d+)\])?: (.*)$')
_MONTHS = {m: i for i, m in enumerate(
    ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct',
     'Nov', 'Dec'), 1)}


def syslog_activity(text, path, ref, year):
    """Records from a syslog-format file (auth.log, secure). The classic
    format has no year and no zone: the year is the file's, stepped back
    where the months run backwards, and times are local wall-clock."""
    describer = Describer('syslog', path, ref, local=True)
    previous_month = None
    lines = text.splitlines()
    # Work backwards from the file's year: the last line is the newest.
    years, current = [], year
    for line in reversed(lines):
        match = _SYSLOG.match(line)
        month = _MONTHS.get(match.group(1)) if match else None
        if month and previous_month and month > previous_month:
            current -= 1
        if month:
            previous_month = month
        years.append(current)
    years.reverse()
    for line, line_year in zip(lines, years):
        match = _ISO_SYSLOG.match(line)
        if match:
            stamp, zone, host, ident, pid, text_ = match.groups()
            try:
                when = datetime.datetime.fromisoformat(
                    stamp + ('+00:00' if zone == 'Z' else (zone or '')))
            except ValueError:
                continue
            describer.local = when.tzinfo is None
            describer.message(when, ident, text_, host=host)
            continue
        match = _SYSLOG.match(line)
        if not match:
            continue
        month, day, hour, minute, second, host, ident, pid, text_ = \
            match.groups()
        try:
            when = datetime.datetime(line_year, _MONTHS[month], int(day),
                                     int(hour), int(minute), int(second))
        except (KeyError, ValueError):
            continue
        describer.local = True
        describer.message(when, ident, text_, host=host)
    return describer.out


# --- the volume ---------------------------------------------------------------------

_HISTORIES = (('.bash_history', 'bash'), ('.zsh_history', 'zsh'),
              ('.zhistory', 'zsh'), ('.histfile', 'zsh'),
              ('.sh_history', 'sh'), ('.ash_history', 'sh'),
              ('.python_history', 'python'), ('.mysql_history', 'mysql'),
              ('.psql_history', 'psql'), ('.lesshst', None))


def _decode(data):
    return data.decode('utf-8', 'replace')


def shell_activity(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    base = _split(home.path)
    for name, shell in _HISTORIES:
        if shell is None:
            continue
        entry = volume.find(*base, name)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        text = _decode(volume.read(entry))
        ref = volume.ref(entry)
        basis = ("bash writes no time unless HISTTIMEFORMAT was set; the "
                 "history file was last written "
                 f"{times.iso(entry.modified) or 'at an unknown time'}")
        if shell in ('bash', 'sh', 'python', 'mysql', 'psql'):
            items = bash_history(text) if shell == 'bash' else \
                [(None, line) for line in text.splitlines() if line.strip()]
            for number, (when, command) in enumerate(items, 1):
                out.append(record('programs', f'{shell} history', when,
                                  'Command typed', command,
                                  {'shell': shell, 'line': number,
                                   'basis': None if when else basis},
                                  user=user, path=entry.path, ref=ref))
        else:
            # zsh writes the extended form only with EXTENDED_HISTORY.
            items = zsh_history(text)
            if not items:
                items = [(None, 0, line) for line in text.splitlines()
                         if line.strip()]
            for number, (when, elapsed, command) in enumerate(items, 1):
                out.append(record('programs', 'zsh history', when,
                                  'Command typed', command,
                                  {'shell': 'zsh', 'line': number,
                                   'seconds': elapsed or None,
                                   'basis': None if when else basis},
                                  user=user, path=entry.path, ref=ref))
    fish = volume.find(*base, '.local', 'share', 'fish', 'fish_history')
    if fish is not None and not fish.is_dir:
        step(fish.path)
        ref = volume.ref(fish)
        for number, (when, command, paths) in enumerate(
                fish_history(_decode(volume.read(fish))), 1):
            out.append(record('programs', 'fish history', when,
                              'Command typed', command,
                              {'shell': 'fish', 'line': number,
                               'paths': ', '.join(paths)},
                              user=user, path=fish.path, ref=ref))
    return out


def recent_files_activity(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    base = _split(home.path)
    for parts in (('.local', 'share', 'recently-used.xbel'),
                  ('.recently-used.xbel',)):
        entry = volume.find(*base, *parts)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        ref = volume.ref(entry)
        for item in recently_used(volume.read(entry)):
            apps = ', '.join(a[0] for a in item['apps'] if a[0])
            out.append(record(
                'files', 'recently-used.xbel',
                item['visited'] or item['modified'] or item['added'],
                'File opened', _file_path(item['href']),
                {'application': apps, 'type': item['mime'],
                 'added': item['added'], 'modified': item['modified'],
                 'times opened': ', '.join(a[3] for a in item['apps']
                                           if a[3])},
                user=user, path=entry.path, ref=ref))
    return out


def system_activity(volume, step):
    """wtmp, btmp, the journals and the auth logs of one volume."""
    out = []
    log = volume.find('var', 'log')
    if log is None:
        return out
    for entry in volume.listdir(log.path):
        name = entry.name.lower()
        if entry.is_dir or not entry.size:
            continue
        if name.startswith(('wtmp', 'btmp')) and not name.endswith('.gz'):
            step(entry.path)
            out += wtmp_activity(volume.read(entry), entry.path,
                                 volume.ref(entry),
                                 failed=name.startswith('btmp'))
        elif (name.startswith(('auth.log', 'secure')) and
              not name.endswith(('.gz', '.xz', '.bz2'))):
            step(entry.path)
            year = (entry.modified or datetime.datetime.now(times.UTC)).year
            out += syslog_activity(_decode(volume.read(entry)), entry.path,
                                   volume.ref(entry), year)
    journals = volume.find('var', 'log', 'journal')
    folders = [journals] + volume.children(journals, dirs=True) \
        if journals is not None else []
    for folder in folders:
        for entry in volume.children(folder):
            if not entry.name.endswith(('.journal', '.journal~')):
                continue
            step(entry.path)
            records, _count = journal_activity(volume.read(entry),
                                               entry.path, volume.ref(entry))
            out += records
    return out


def is_linux(volume):
    return volume.find('etc') is not None and (
        volume.find('var', 'log') is not None or
        volume.find('home') is not None) and \
        volume.find('Windows') is None


def collect(volume, step, homes):
    from trace_app.core.activity import linux_system
    out = system_activity(volume, step)
    # The system, its accounts, its software and SSH (linux_system.py).
    out += linux_system.collect(volume, step, homes)
    for user, home in homes:
        out += shell_activity(volume, user, home, step)
        out += recent_files_activity(volume, user, home, step)
    return out


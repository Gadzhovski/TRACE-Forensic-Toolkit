"""Autostarts on Linux and macOS (no Qt), as core/persistence.py reads
Windows': the same entries, graded by what they start.

Linux:
* systemd units that are enabled -- the links in /etc/systemd/system/
  *.wants/ (and each user's ~/.config/systemd/user/), resolved to the unit
  file and its ExecStart. A unit file in /etc/systemd/system itself was
  put there by an administrator or a program, not shipped by a package
  (those live in /usr/lib/systemd): noted.
* cron: /etc/crontab, /etc/cron.d/*, the user crontabs (/var/spool/cron/*
  on Fedora and RHEL, /var/spool/cron/crontabs/* on Debian) and the
  scripts in /etc/cron.hourly, .daily, .weekly and .monthly.
* SysV init's start links (/etc/rcS.d and rc2.d to rc5.d, S*: Ubuntu
  before 15.04, RHEL 6), Upstart jobs (/etc/event.d, /etc/init),
  /etc/rc.local, /etc/ld.so.preload (a library loaded into every program
  -- rootkits use it), XDG autostart (/etc/xdg/autostart and each user's
  ~/.config/autostart) and each user's SSH authorized_keys (a way in).

macOS: launch agents and daemons outside /System -- /Library and each
user's ~/Library -- with Program / ProgramArguments, RunAtLoad and
KeepAlive. Apple's own (in /System) are part of the sealed system volume.
And Background Task Management (activity/btm.py): every login item,
agent and daemon macOS 13+ registered, per user, whether it is enabled
and allowed, its developer and team; before 13, each user's
backgrounditems.btm -- including what registered an item (System Events:
added by AppleScript, as persistence tools do).

Grading looks at what an entry starts: a program in /tmp, /var/tmp or
/dev/shm, a hidden file, a download piped into a shell, a reverse shell
or base64-decoded command, a preload library, a known-bad hash.
"""

import hashlib
import logging
import plistlib
import posixpath
import re

from trace_app.core.persistence import _entry

logger = logging.getLogger('TRACE.Persistence.Unix')

MAX_HASH_BYTES = 128 * 1024 * 1024

_TEMP = re.compile(r'^/(tmp|var/tmp|dev/shm)(/|$)')
_DOWNLOAD_TO_SHELL = re.compile(
    r'(curl|wget|fetch)\b[^|;&]*\|\s*(ba|z|da)?sh\b', re.IGNORECASE)
_REVERSE_SHELL = re.compile(
    r'(/dev/tcp/|\bnc(at)?\b[^|;]*\s-e\s|bash\s+-i\s*>&|'
    r'socat\b.*exec|python[0-9.]*\s+-c\s.*socket)', re.IGNORECASE)
_BASE64 = re.compile(r'base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/=]{40,}',
                     re.IGNORECASE)
_CRON_SPECIAL = ('@reboot', '@yearly', '@annually', '@monthly', '@weekly',
                 '@daily', '@midnight', '@hourly')


# --- reading the places --------------------------------------------------------------

def _read(volume, entry):
    entry = volume.resolve(entry)
    if entry is None or entry.is_dir or not entry.size:
        return None, entry
    return volume.read(entry).decode('utf-8', 'replace'), entry


def unit_exec(text):
    """(ExecStart command or '', Description) of a systemd unit file."""
    command, description = '', ''
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('ExecStart=') and not command:
            command = line.split('=', 1)[1].strip().lstrip('@-+!:')
        elif line.startswith('Description=') and not description:
            description = line.split('=', 1)[1].strip()
    return command, description


def cron_lines(text, system=False):
    """[(schedule, user or '', command)] from a crontab; a system crontab
    (/etc/crontab, /etc/cron.d) names the user in its sixth field."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            continue                                   # VAR=value
        fields = line.split()
        if fields[0] in _CRON_SPECIAL:
            schedule, rest = fields[0], fields[1:]
        elif len(fields) >= 6:
            schedule, rest = ' '.join(fields[:5]), fields[5:]
        else:
            continue
        user = ''
        if system and rest:
            user, rest = rest[0], rest[1:]
        if rest:
            out.append((schedule, user, ' '.join(rest)))
    return out


def upstart_exec(text):
    """The command an Upstart job runs: its exec line, or the first
    line of its script block."""
    in_script = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('exec '):
            return stripped[5:].strip()
        if stripped == 'script':
            in_script = True
            continue
        if in_script and stripped and not stripped.startswith('#'):
            return 'end script' != stripped and stripped or ''
    return ''


def launchd_plist(data):
    """(label, command, runs at load, keeps alive, disabled) of a launchd
    plist, or None."""
    try:
        plist = plistlib.loads(data)
    except Exception:
        return None
    if not isinstance(plist, dict):
        return None
    arguments = plist.get('ProgramArguments') or []
    program = plist.get('Program') or ''
    if isinstance(arguments, list) and arguments:
        command = ' '.join(str(a) for a in arguments)
        if program and not command.startswith(program):
            command = f"{program} {command}"
    else:
        command = program
    return (str(plist.get('Label') or ''), command,
            bool(plist.get('RunAtLoad')), bool(plist.get('KeepAlive')),
            bool(plist.get('Disabled')))


def desktop_exec(text):
    """(Exec, Name, Hidden or disabled) of a .desktop file."""
    command, name, off = '', '', False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('Exec=') and not command:
            command = line[5:].strip()
        elif line.startswith('Name=') and not name:
            name = line[5:].strip()
        elif line in ('Hidden=true', 'X-GNOME-Autostart-enabled=false'):
            off = True
    return command, name, off


def _linux(volume, homes, tick):
    from trace_app.core.activity import _split
    found = []
    # systemd: enabled units, system-wide and per user.
    places = [(('etc', 'systemd', 'system'), '')]
    places += [((*_split(home.path), '.config', 'systemd', 'user'), user)
               for user, home in homes]
    for parts, user in places:
        folder = volume.find(*parts)
        for wants in volume.children(folder, dirs=True):
            if not wants.name.endswith(('.wants', '.requires')):
                continue
            for link in volume.listdir(wants.path):
                if link.is_dir:
                    continue
                tick(link.path)
                text, unit = _read(volume, link)
                command, description = unit_exec(text or '')
                where = unit.path if unit is not None else ''
                found.append(_entry(
                    'systemd unit', link.name, command or link.name,
                    link.modified, user=user or 'system', source=link.path,
                    source_ref=volume.ref(link), unit_file=where,
                    target=wants.name, description=description,
                    admin_added=None if unit is None else
                    _admin_unit(volume, unit),
                    basis="when the link enabling it was made"))
    # cron
    for parts, system in ((('etc', 'crontab'), True),):
        text, entry = _read(volume, volume.find(*parts))
        if text:
            found += _cron(volume, entry, text, system, '', tick)
    for entry in volume.children(volume.find('etc', 'cron.d')):
        text, entry = _read(volume, entry)
        if text:
            found += _cron(volume, entry, text, True, '', tick)
    for parts in (('var', 'spool', 'cron'),
                  ('var', 'spool', 'cron', 'crontabs')):
        for entry in volume.children(volume.find(*parts)):
            text, real = _read(volume, entry)
            if text:
                found += _cron(volume, real, text, False, entry.name, tick)
    for period in ('hourly', 'daily', 'weekly', 'monthly'):
        for entry in volume.children(volume.find('etc', f'cron.{period}')):
            if entry.name.startswith('.') and entry.name == '.placeholder':
                continue
            tick(entry.path)
            found.append(_entry(
                'cron', entry.name, _posix(volume, entry), entry.modified,
                user='root', source=entry.path, source_ref=volume.ref(entry),
                schedule=period, basis="the script's last change"))
    # SysV init (Ubuntu before 15.04, RHEL 6): each runlevel's S links.
    seen = set()
    for level in 'S2345':
        for link in volume.children(volume.find('etc', f'rc{level}.d')):
            if not link.name.startswith('S') or link.name in seen:
                continue
            seen.add(link.name)
            tick(link.path)
            script = volume.resolve(link)
            found.append(_entry(
                'SysV init', link.name,
                _posix(volume, script) if script is not None
                else link.name, link.modified, user='root',
                source=link.path, source_ref=volume.ref(link),
                runlevel=level, basis="when the start link was made"))
    # Upstart jobs (Ubuntu 6.10-14.10): /etc/event.d early, /etc/init later.
    for parts in (('etc', 'event.d'), ('etc', 'init')):
        for entry in volume.children(volume.find(*parts)):
            if parts[-1] == 'init' and not entry.name.endswith('.conf'):
                continue
            text, real = _read(volume, entry)
            command = upstart_exec(text or '')
            if not command:
                continue
            tick(entry.path)
            found.append(_entry('Upstart job', entry.name, command,
                                entry.modified, user='root',
                                source=entry.path,
                                source_ref=volume.ref(entry),
                                basis="the job file's last change"))
    # rc.local, ld.so.preload
    for parts in (('etc', 'rc.local'), ('etc', 'rc.d', 'rc.local')):
        text, entry = _read(volume, volume.find(*parts))
        if text and any(line.strip() and not line.startswith('#') and
                        line.strip() != 'exit 0'
                        for line in text.splitlines()[1:]):
            tick(entry.path)
            found.append(_entry('rc.local', entry.name, _first_command(text),
                                entry.modified, user='root',
                                source=entry.path,
                                source_ref=volume.ref(entry),
                                basis="the file's last change"))
            break
    text, entry = _read(volume, volume.find('etc', 'ld.so.preload'))
    if text:
        for line in text.split():
            if line.startswith('#'):
                continue
            tick(entry.path)
            found.append(_entry('ld.so.preload', line.rsplit('/', 1)[-1],
                                line, entry.modified, user='every program',
                                source=entry.path,
                                source_ref=volume.ref(entry),
                                basis="the file's last change"))
    # XDG autostart
    places = [(('etc', 'xdg', 'autostart'), 'All users')]
    places += [((*_split(home.path), '.config', 'autostart'), user)
               for user, home in homes]
    for parts, user in places:
        for entry in volume.children(volume.find(*parts)):
            if not entry.name.endswith('.desktop'):
                continue
            text, real = _read(volume, entry)
            command, name, off = desktop_exec(text or '')
            if not command:
                continue
            tick(entry.path)
            found.append(_entry('XDG autostart', name or entry.name, command,
                                entry.modified, user=user,
                                source=entry.path,
                                source_ref=volume.ref(entry),
                                enabled=not off,
                                basis="the file's last change"))
    # SSH keys allowed in
    from trace_app.core.activity.linux_system import authorized_keys
    for user, home in homes:
        for name in ('authorized_keys', 'authorized_keys2'):
            text, entry = _read(volume, volume.find(*_split(home.path),
                                                    '.ssh', name))
            if not text:
                continue
            for kind, comment, options in authorized_keys(text):
                tick(entry.path)
                found.append(_entry(
                    'SSH authorized key', comment or kind,
                    options or '', entry.modified, user=user,
                    source=entry.path, source_ref=volume.ref(entry),
                    key_type=kind, basis="the file's last change"))
    return found


def _admin_unit(volume, unit):
    """True when a unit file lives in /etc (an administrator's or a
    program's), not /usr/lib (a package's)."""
    path = unit.path
    root = volume.root.rstrip('/')
    if root and path.startswith(root + '/'):
        path = path[len(root):]
    return path.startswith('/etc/')


def _posix(volume, entry):
    root = volume.root.rstrip('/')
    path = entry.path
    if root and path.startswith(root + '/'):
        path = path[len(root):]
    return path


def _first_command(text):
    for line in text.splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith('#') and line != 'exit 0':
            return line
    return ''


def _cron(volume, entry, text, system, owner, tick):
    out = []
    tick(entry.path)
    for schedule, user, command in cron_lines(text, system):
        out.append(_entry('cron', schedule, command, entry.modified,
                          user=user or owner or 'root', source=entry.path,
                          source_ref=volume.ref(entry), schedule=schedule,
                          basis="the crontab's last change"))
    return out


def _macos(volume, homes, tick):
    from trace_app.core.activity import _split
    found = []
    places = [(('Library', 'LaunchAgents'), 'All users', 'Launch agent'),
              (('Library', 'LaunchDaemons'), 'system', 'Launch daemon')]
    places += [((*_split(home.path), 'Library', 'LaunchAgents'), user,
                'Launch agent') for user, home in homes]
    for parts, user, location in places:
        for entry in volume.children(volume.find(*parts)):
            if not entry.name.endswith('.plist'):
                continue
            tick(entry.path)
            parsed = launchd_plist(volume.read(entry))
            if parsed is None:
                continue
            label, command, at_load, alive, disabled = parsed
            found.append(_entry(
                location, label or entry.name, command, entry.modified,
                user=user, source=entry.path, source_ref=volume.ref(entry),
                enabled=not disabled,
                runs_at_load='yes' if at_load else None,
                keeps_alive='yes' if alive else None,
                basis="the plist's last change"))
    found += _background_items(volume, homes, tick)
    return found


def _background_items(volume, homes, tick):
    """Background Task Management's records (activity/btm.py)."""
    from trace_app.core.activity import _split, btm
    files = []
    for root in (('private', 'var', 'db'), ('var', 'db')):
        folder = volume.find(*root, 'com.apple.backgroundtaskmanagement')
        if folder is not None:
            files += [(entry, '') for entry in volume.children(folder)
                      if entry.name.lower().startswith('backgrounditems')
                      and entry.name.lower().endswith('.btm')]
            break
    for user, home in homes:
        entry = volume.find(*_split(home.path), 'Library',
                            'Application Support',
                            'com.apple.backgroundtaskmanagementagent',
                            'backgrounditems.btm')
        if entry is not None and not entry.is_dir:
            files.append((entry, user))
    if not files:
        return []
    names = {}
    for root in (('private', 'var', 'db'), ('var', 'db')):
        users = volume.find(*root, 'dslocal', 'nodes', 'Default', 'users')
        if users is not None:
            names = btm.account_uuids(
                volume.read(e) for e in volume.children(users)
                if e.name.endswith('.plist') and not e.is_dir)
            break
    found = []
    for entry, owner in files:
        tick(entry.path)
        try:
            items = btm.items(volume.read(entry))
        except btm.BtmError as exc:
            logger.debug("%s not read: %s", entry.path, exc)
            continue
        for item in items:
            if not (item['name'] or item['url'] or item['executable']):
                continue        # a developer's entry: a grouping, no program
            command = ' '.join(filter(None, (
                item['executable'] or item['url'], item['arguments'])))
            found.append(_entry(
                'Background item', item['name'] or item['identifier'],
                command, item['modified'],
                user=owner or btm.user_label(item['user_uuid'], names),
                source=entry.path, source_ref=volume.ref(entry),
                enabled=item['enabled'],
                kind=item['type_details'],
                state=item['disposition_details'] or None,
                developer=item['developer'], team=item['team'],
                bundle=item['bundle'], parent=item['container'],
                identifier=item['identifier'] if not item['legacy']
                else None,
                app=item['url'] if item['executable'] else None,
                added_by=item['added_by'],
                basis=None if item['modified'] else
                "no time recorded for this item"))
    return found


# --- what they start ---------------------------------------------------------------

def target_of(command):
    """The program a command line starts: the first word, past an
    interpreter's own options ('sh -c', 'env X=1')."""
    words = command.strip().split()
    while words and (words[0] in ('env', 'nohup', 'exec', 'sudo') or
                     '=' in words[0] and not words[0].startswith('/')):
        words = words[1:]
    if not words:
        return ''
    if posixpath.basename(words[0]) in ('sh', 'bash', 'zsh', 'dash') and \
            len(words) > 1 and words[1] != '-c':
        return words[1]
    return words[0].strip('"\'')


def resolve(volume, item, hash_lookup):
    target = target_of(item['command'])
    item['target'] = target
    item['exists'] = None
    item['signed'] = None                # no embedded signatures here
    if not target.startswith('/'):
        return
    entry = volume.lookup(target)
    if entry is None or entry.is_dir:
        item['exists'] = False
        return
    item['exists'] = not entry.deleted
    item['target_ref'] = volume.ref(entry)
    item['target_path'] = entry.path
    item['target_size'] = entry.size
    if entry.size and entry.size <= MAX_HASH_BYTES:
        data = volume.read(entry)
        digests = {'md5': hashlib.md5(data).hexdigest(),
                   'sha1': hashlib.sha1(data).hexdigest(),
                   'sha256': hashlib.sha256(data).hexdigest()}
        item['sha256'] = digests['sha256']
        if hash_lookup is not None:
            match = hash_lookup(digests)
            if match:
                item['hash_category'], item['hash_set'] = match


def grade(entry):
    """(grade, [reasons]) for a Linux or macOS autostart."""
    reasons = []
    serious = False
    command = entry['command']
    target = entry.get('target') or ''
    location = entry['location']
    if entry.get('hash_category') == 'known-bad':
        reasons.append(f"its file is in the known-bad hash set "
                       f"{entry.get('hash_set')}")
        serious = True
    if location == 'ld.so.preload':
        reasons.append("a library loaded into every program (rootkits use "
                       "ld.so.preload)")
        serious = True
    if _TEMP.search(target) or re.search(r'\s/(tmp|var/tmp|dev/shm)/',
                                         ' ' + command):
        reasons.append("starts something in a temporary folder")
        serious = True
    if _DOWNLOAD_TO_SHELL.search(command):
        reasons.append("downloads something and runs it in a shell")
        serious = True
    if _REVERSE_SHELL.search(command):
        reasons.append("opens a shell over the network")
        serious = True
    if _BASE64.search(command):
        reasons.append("runs a base64-encoded command")
        serious = True
    if posixpath.basename(target).startswith('.') and target:
        reasons.append("starts a hidden file")
        serious = True
    if location == 'systemd unit' and entry['detail'].get('admin_added'):
        reasons.append("its unit file is in /etc, not shipped in a package "
                       "(/usr/lib/systemd)")
    if location == 'cron' and entry['source'].split('/')[-2:-1] in (
            ['cron'], ['crontabs']):
        reasons.append("a user's own crontab")
    if location in ('Launch agent', 'Launch daemon',
                    'Background item') and target and \
            not target.startswith(('/System/', '/usr/', '/Applications/',
                                   '/Library/', '/bin/', '/sbin/')):
        reasons.append("starts a program outside the system and "
                       "Applications folders")
    if location == 'Background item' and \
            'System Events' in (entry['detail'].get('added_by') or ''):
        reasons.append("registered through System Events -- by an "
                       "AppleScript, as persistence tools do")
    if location == 'SSH authorized key' and entry['user'] == 'root':
        reasons.append("lets this key log in as root")
    if location == 'rc.local':
        reasons.append("rc.local runs at every boot")
    if entry.get('exists') is False and target.startswith('/'):
        reasons.append("the file it starts is not on this image")
    if entry.get('hash_category') == 'known-good' and not serious:
        return 'benign', reasons + [f"its file is known good "
                                    f"({entry.get('hash_set')})"]
    if serious:
        return 'suspicious', reasons
    if reasons:
        return 'notable', reasons
    return 'benign', reasons


def collect(volume, homes, hash_lookup, tick):
    """Every Linux and macOS autostart on one system root, graded."""
    from trace_app.core.activity import linux, macos
    found = []
    if linux.is_linux(volume):
        found += _linux(volume, homes, tick)
    if macos.is_macos(volume):
        found += _macos(volume, homes, tick)
    for item in found:
        resolve(volume, item, hash_lookup)
        item['grade'], item['reasons'] = grade(item)
    return found

"""Persistence: everything set to start by itself, and what it starts.

Where Windows keeps autostarts, read from the image:

* Run / RunOnce / RunServices keys (machine, and each user), the Policies
  Run keys, Winlogon's Shell / Userinit / Taskman, `Windows\\Load` and
  `Run`, AppInit_DLLs, Image File Execution Options debuggers and
  SilentProcessExit monitors;
* services and drivers that start automatically (SYSTEM), with the DLL a
  svchost service loads;
* scheduled tasks (System32\\Tasks, the XML Windows writes);
* the Startup folders (all users, and each user), shortcuts resolved;
* WMI event consumers in the repository (OBJECTS.DATA) -- best effort: the
  repository is not parsed, the consumer's strings are found in it.

Each entry is graded by what it launches, found on the same image: does the
file exist, does it carry an embedded (Authenticode) signature -- present
or not, never *verified*, and Windows' own files are often catalog-signed
so its absence alone is never a flag -- is its hash in a known-bad or
known-good hash set, and does it fit a pattern persistence malware uses (a
system name outside System32, a user-writable folder, a script host with an
encoded command, a hijacked Winlogon shell). Every reason is kept.

No Qt here.
"""

import hashlib
import json
import logging
import re
import struct

logger = logging.getLogger('TRACE.Persistence')

MODULE_PERSISTENCE = 'persistence'

LOCATIONS = (
    'Run key', 'Winlogon', 'Image File Execution Options', 'AppInit DLL',
    'Service', 'Driver', 'Scheduled task', 'Startup folder', 'WMI consumer',
)

#: Largest target hashed for the hash-set lookup.
MAX_HASH_BYTES = 128 * 1024 * 1024

#: Names a dropper borrows. Outside System32/SysWOW64 they are a red flag.
_SYSTEM_NAMES = {
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe',
    'smss.exe', 'explorer.exe', 'spoolsv.exe', 'taskhost.exe',
    'taskhostw.exe', 'conhost.exe', 'dllhost.exe', 'rundll32.exe',
    'wininit.exe', 'lsm.exe', 'ctfmon.exe', 'userinit.exe', 'dwm.exe',
}
_SCRIPT_HOSTS = ('powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
                 'regsvr32', 'cmd.exe', 'cmd ', 'rundll32', 'bitsadmin',
                 'certutil')
_USER_WRITABLE = re.compile(
    r'\\(temp|tmp|appdata|application data|local settings|users\\public|'
    r'programdata\\[^\\]+\.exe|\$recycle\.bin|recycler|downloads|'
    r'perflogs)\\', re.IGNORECASE)
_ENCODED = re.compile(r'(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|'
                      r'frombase64string|downloadstring|'
                      r'iex\s*\(|invoke-expression|http[s]?://)',
                      re.IGNORECASE)
#: Defaults Windows ships, so an entry holding exactly them is routine.
_WINLOGON_DEFAULTS = {'shell': {'explorer.exe'},
                      'userinit': {'userinit.exe', 'userinit.exe,'},
                      'taskman': set()}
#: The Debugger entry Windows XP ships as an example under IFEO.
_IFEO_TEMPLATE = 'your image file name here without a path'

#: WMI consumers Windows itself registers.
_KNOWN_WMI = ('bvtconsumer', 'scm event log consumer')

_ON_PATH = {
    'powershell.exe':
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'explorer.exe': 'C:\\Windows\\explorer.exe',
    'regedit.exe': 'C:\\Windows\\regedit.exe',
    'notepad.exe': 'C:\\Windows\\System32\\notepad.exe',
}

_START_TYPES = {0: 'boot', 1: 'system', 2: 'automatic', 3: 'manual',
                4: 'disabled'}


class Entry(dict):
    """One autostart: location, name, command, target, user, when, source,
    and later the grading."""


def _entry(location, name, command, when=None, user='', source='',
           source_ref='', enabled=True, **detail):
    return Entry(location=location, name=name or '', command=command or '',
                 when=when, user=user, source=source, source_ref=source_ref,
                 enabled=enabled, detail={k: v for k, v in detail.items()
                                          if v not in (None, '', [], {})})


# --- reading the registry ---------------------------------------------------------

_RUN_KEYS = (
    'Microsoft\\Windows\\CurrentVersion\\Run',
    'Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'Microsoft\\Windows\\CurrentVersion\\RunOnceEx',
    'Microsoft\\Windows\\CurrentVersion\\RunServices',
    'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
    'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
)


def from_software(hive, source='', source_ref=''):
    from trace_app.core.activity import registry as reg
    out = []
    common = dict(source=source, source_ref=source_ref)
    for path in _RUN_KEYS:
        key = reg._key(hive, path)
        for value in key.values() if key is not None else ():
            out.append(_entry('Run key', value.name(), str(value.value()),
                              reg._utc(key.timestamp()), key_path=path,
                              basis="the key's last write", **common))
    winlogon = reg._key(hive, 'Microsoft\\Windows NT\\CurrentVersion\\'
                              'Winlogon')
    for name in ('Shell', 'Userinit', 'Taskman', 'AppSetup'):
        value = reg._value(winlogon, name) if winlogon is not None else None
        if value:
            out.append(_entry('Winlogon', name, str(value),
                              reg._utc(winlogon.timestamp()),
                              key_path='Winlogon', **common))
    windows = reg._key(hive, 'Microsoft\\Windows NT\\CurrentVersion\\'
                             'Windows')
    if windows is not None:
        dlls = str(reg._value(windows, 'AppInit_DLLs', '') or '').strip()
        if dlls:
            out.append(_entry(
                'AppInit DLL', 'AppInit_DLLs', dlls,
                reg._utc(windows.timestamp()),
                loaded='yes' if reg._value(windows, 'LoadAppInit_DLLs')
                else 'no (LoadAppInit_DLLs is 0)',
                enabled=bool(reg._value(windows, 'LoadAppInit_DLLs')),
                **common))
    ifeo = reg._key(hive, 'Microsoft\\Windows NT\\CurrentVersion\\Image File '
                          'Execution Options')
    for sub in ifeo.subkeys() if ifeo is not None else ():
        debugger = reg._value(sub, 'Debugger')
        if debugger:
            out.append(_entry('Image File Execution Options', sub.name(),
                              str(debugger), reg._utc(sub.timestamp()),
                              hijacks=sub.name(), **common))
    silent = reg._key(hive, 'Microsoft\\Windows NT\\CurrentVersion\\'
                            'SilentProcessExit')
    for sub in silent.subkeys() if silent is not None else ():
        monitor = reg._value(sub, 'MonitorProcess')
        if monitor:
            out.append(_entry('Image File Execution Options',
                              f"{sub.name()} (on exit)", str(monitor),
                              reg._utc(sub.timestamp()), **common))
    return out


def from_user(hive, user, source='', source_ref=''):
    from trace_app.core.activity import registry as reg
    out = []
    common = dict(user=user, source=source, source_ref=source_ref)
    for path in ('Software\\' + p for p in _RUN_KEYS):
        key = reg._key(hive, path)
        for value in key.values() if key is not None else ():
            out.append(_entry('Run key', value.name(), str(value.value()),
                              reg._utc(key.timestamp()),
                              key_path='HKCU\\' + path, **common))
    windows = reg._key(hive, 'Software\\Microsoft\\Windows NT\\'
                             'CurrentVersion\\Windows')
    for name in ('Load', 'Run'):
        value = reg._value(windows, name) if windows is not None else None
        if value and str(value).strip():
            out.append(_entry('Run key', f"Windows\\{name}", str(value),
                              reg._utc(windows.timestamp()), **common))
    winlogon = reg._key(hive, 'Software\\Microsoft\\Windows NT\\'
                              'CurrentVersion\\Winlogon')
    value = reg._value(winlogon, 'Shell') if winlogon is not None else None
    if value:
        out.append(_entry('Winlogon', 'Shell (this user)', str(value),
                          reg._utc(winlogon.timestamp()), **common))
    return out


def from_system(hive, source='', source_ref=''):
    """Services and drivers that start by themselves (Start 0-2)."""
    from trace_app.core.activity import registry as reg
    out = []
    control = reg.current_control_set(hive)
    services = reg._key(hive, f'{control}\\Services')
    for sub in services.subkeys() if services is not None else ():
        start = reg._value(sub, 'Start')
        image = reg._value(sub, 'ImagePath')
        if start not in (0, 1, 2) or not image:
            continue
        kind = reg._value(sub, 'Type', 0) or 0
        location = 'Driver' if kind in (1, 2, 8) else 'Service'
        service_dll = ''
        try:
            parameters = sub.subkey('Parameters')
            service_dll = str(reg._value(parameters, 'ServiceDll', '') or '')
        except Exception:
            pass
        out.append(_entry(
            location, sub.name(), str(service_dll or image),
            reg._utc(sub.timestamp()), source=source, source_ref=source_ref,
            display_name=str(reg._value(sub, 'DisplayName', '') or ''),
            start=_START_TYPES.get(start, str(start)),
            image_path=str(image) if service_dll else '',
            account=str(reg._value(sub, 'ObjectName', '') or ''),
            basis="the service key's last write"))
    return out


# --- scheduled tasks, Startup folders, WMI ---------------------------------------

_TASK_NS = re.compile(r'\sxmlns="[^"]+"')


def parse_task(data):
    """{'commands': [(command, arguments)], 'author', 'registered',
    'enabled', 'triggers', 'user', 'hidden'} from a task's XML."""
    import xml.etree.ElementTree as ElementTree
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        text = data.decode('utf-16')
    else:
        text = data.decode('utf-8', 'replace')
    text = _TASK_NS.sub('', text, count=1).lstrip('\ufeff')
    text = re.sub(r'^<\?xml[^>]*\?>', '', text.strip())
    root = ElementTree.fromstring(text)

    def first(path):
        node = root.find(path)
        return (node.text or '').strip() if node is not None and \
            node.text else ''
    commands = [((exec_node.findtext('Command') or '').strip(),
                 (exec_node.findtext('Arguments') or '').strip())
                for exec_node in root.iter('Exec')]
    handlers = [f"COM handler {(node.findtext('ClassId') or '').strip()}"
                for node in root.iter('ComHandler')]
    triggers = [child.tag for node in root.iter('Triggers') for child in node]
    return {'commands': commands, 'handlers': handlers,
            'author': first('RegistrationInfo/Author'),
            'registered': first('RegistrationInfo/Date'),
            'description': first('RegistrationInfo/Description'),
            'enabled': first('Settings/Enabled').lower() != 'false',
            'hidden': first('Settings/Hidden').lower() == 'true',
            'user': first('Principals/Principal/UserId'),
            'run_level': first('Principals/Principal/RunLevel'),
            'triggers': triggers}


def from_task(name, data, source='', source_ref='', modified=None):
    facts = parse_task(data)
    out = []
    registered = _iso_local(facts['registered'])
    for command, arguments in facts['commands'] or [('', '')]:
        if not command and not facts['handlers']:
            continue
        out.append(_entry(
            'Scheduled task', name,
            f'{command} {arguments}'.strip() or ', '.join(facts['handlers']),
            modified, user=facts['user'], source=source,
            source_ref=source_ref, enabled=facts['enabled'],
            author=facts['author'], registered=registered,
            triggers=', '.join(facts['triggers']),
            hidden='yes' if facts['hidden'] else '',
            run_level=facts['run_level'],
            description=facts['description'][:200],
            basis="the task file's last modification"))
    return out


def _iso_local(text):
    return text.replace('T', ' ')[:19] if text else ''


_WMI_CONSUMERS = (b'CommandLineEventConsumer', b'ActiveScriptEventConsumer')


def from_wmi_repository(data, source='', source_ref=''):
    """Consumers that run something, found in OBJECTS.DATA by their class
    name: the readable strings that follow it (best effort)."""
    out = []
    seen = set()
    for marker in _WMI_CONSUMERS:
        for encoded in (marker, marker.decode().encode('utf-16-le')):
            start = 0
            while True:
                at = data.find(encoded, start)
                if at < 0:
                    break
                start = at + len(encoded)
                window = data[at:at + 4096]
                # Up to the next consumer, so one does not take another's
                # command.
                cut = min([p for p in (window.find(m, len(encoded))
                                       for m in _ALL_MARKERS) if p > 0]
                          or [len(window)])
                strings = _strings(window[:cut])
                command = next((s for s in strings if _looks_runnable(s)),
                               '')
                name = next((s for s in strings[1:] if 3 <= len(s) <= 80
                             and s != command and not _looks_runnable(s)),
                            '')
                key = (marker, name, command)
                if not command or key in seen:
                    continue
                seen.add(key)
                out.append(_entry(
                    'WMI consumer', name or marker.decode(), command,
                    source=source, source_ref=source_ref,
                    consumer=marker.decode(),
                    basis='strings found beside the consumer class in the '
                          'WMI repository; not a parsed record'))
    return out


_ALL_MARKERS = tuple(m for marker in _WMI_CONSUMERS
                     for m in (marker, marker.decode().encode('utf-16-le')))


def _strings(data, minimum=4):
    """Readable ASCII and UTF-16LE strings, in the order they appear."""
    found = [(m.start(), m.group().decode('utf-16-le')) for m in
             re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % minimum, data)]
    taken = [(start, start + len(text) * 2) for start, text in found]
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minimum, data):
        if not any(a <= m.start() < b for a, b in taken):
            found.append((m.start(), m.group().decode('ascii')))
    return [text for _start, text in sorted(found)]


def _looks_runnable(text):
    lowered = text.lower()
    return any(token in lowered for token in ('.exe', '.vbs', '.ps1', '.js',
                                              '.bat', '.cmd', 'powershell',
                                              'cscript', 'wscript'))


# --- what an entry launches ----------------------------------------------------------

_EXPANSIONS = (
    ('%systemroot%', 'C:\\Windows'), ('%windir%', 'C:\\Windows'),
    ('\\systemroot\\', 'C:\\Windows\\'), ('systemroot\\', 'C:\\Windows\\'),
    ('%systemdrive%', 'C:'), ('%programfiles%', 'C:\\Program Files'),
    ('%programfiles(x86)%', 'C:\\Program Files (x86)'),
    ('%programdata%', 'C:\\ProgramData'), ('%commonprogramfiles%',
                                            'C:\\Program Files\\Common Files'),
    ('\\??\\', ''),
)


def target_of(command):
    """The executable (or DLL) a command line starts, as a Windows path."""
    text = (command or '').strip().strip('\x00')
    if not text:
        return ''
    if text.startswith('"'):
        path = text[1:].split('"', 1)[0]
    else:
        match = re.match(r'(.+?\.(exe|dll|sys|com|scr|bat|cmd|vbs|js|ps1|'
                         r'cpl|ocx|jar|hta))(\s|,|$)', text, re.IGNORECASE)
        path = match.group(1) if match else text.split(' ')[0]
    lowered = path.lower()
    for token, replacement in _EXPANSIONS:
        if lowered.startswith(token):
            path = replacement + path[len(token):]
            lowered = path.lower()
    # rundll32 X.dll,Entry and regsvr32 X.dll run the DLL.
    if lowered.endswith(('rundll32.exe', 'regsvr32.exe')):
        rest = text[len(text.split(path, 1)[0]) + len(path):].strip(' "')
        dll = re.match(r'(?:/s\s+)?"?([^",]+\.(dll|ocx|cpl))', rest,
                       re.IGNORECASE)
        if dll:
            return target_of(dll.group(1))
    if '\\' not in path and not path.lower().startswith(('c:', '\\')):
        # A bare name is found on PATH; the programs that are not in
        # System32 itself are named where they are.
        bare = path.lower()
        if '.' not in bare:
            bare += '.exe'
        path = _ON_PATH.get(bare, 'C:\\Windows\\System32\\' + bare)
    if path.lower().startswith('system32\\'):
        path = 'C:\\Windows\\' + path
    return path


def has_embedded_signature(head):
    """True when a PE's security directory is present (an Authenticode
    signature embedded in the file), False when not, None if not a PE.
    Not verified: that needs the certificate chain."""
    if head[:2] != b'MZ' or len(head) < 0x40:
        return None
    offset = struct.unpack_from('<I', head, 0x3C)[0]
    if offset + 0x18 > len(head) or head[offset:offset + 4] != b'PE\x00\x00':
        return None
    optional = offset + 24
    magic = struct.unpack_from('<H', head, optional)[0]
    directories = optional + (96 if magic == 0x10b else 112)
    security = directories + 4 * 8
    if security + 8 > len(head):
        return None
    address, size = struct.unpack_from('<II', head, security)
    return bool(address and size)


def grade(entry):
    """(grade, [reasons]) for an entry with its target facts filled in."""
    reasons = []
    serious = False
    command = entry['command']
    target = entry.get('target') or ''
    lowered = target.lower()
    folder, _, name = lowered.rpartition('\\')
    in_windows = lowered.startswith(('c:\\windows\\system32\\',
                                     'c:\\windows\\syswow64\\'))
    # Where Windows' own copies of its programs live: the folder itself,
    # not a subfolder of it (system32\dllhost\svchost.exe is a dropper).
    genuine_home = folder in ('c:\\windows\\system32',
                              'c:\\windows\\syswow64', 'c:\\windows')
    if entry.get('hash_category') == 'known-bad':
        reasons.append(f"its file is in the known-bad hash set "
                       f"{entry.get('hash_set')}")
        serious = True
    if name in _SYSTEM_NAMES and not genuine_home:
        reasons.append(f"named like the Windows file {name} but not where "
                       f"Windows keeps it")
        serious = True
    run_name = entry['name'].lower()
    run_name = run_name[:-4] if run_name.endswith('.exe') else run_name
    if entry['location'] == 'Run key' and run_name in \
            {n[:-4] for n in _SYSTEM_NAMES} and not (
                genuine_home and name == run_name + '.exe'):
        reasons.append(f"a Run entry named \u201c{entry['name']}\u201d that "
                       f"does not start the Windows program of that name")
        serious = True
    if _ENCODED.search(command):
        reasons.append("an encoded, downloading or remote command")
        serious = True
    if entry['location'] == 'Image File Execution Options':
        if entry['name'].lower() == _IFEO_TEMPLATE:
            return 'benign', ["the example entry Windows XP ships"]
        reasons.append(f"runs instead of (or after) "
                       f"{entry['detail'].get('hijacks') or entry['name']}")
        serious = True
    if entry['location'] == 'Winlogon':
        defaults = _WINLOGON_DEFAULTS.get(entry['name'].split(' ')[0]
                                          .lower(), set())
        parts = {p.strip().lower().rsplit('\\', 1)[-1]
                 for p in command.split(',') if p.strip()}
        if defaults and not parts <= defaults:
            reasons.append("Winlogon starts something besides Windows' own")
            serious = True
    if entry['location'] == 'AppInit DLL' and entry.get('enabled'):
        reasons.append("AppInit DLLs load into every program with a window")
    if entry['location'] == 'WMI consumer' and not any(
            k in (entry['name'] + command).lower() for k in _KNOWN_WMI):
        reasons.append("a WMI event consumer that runs a command")
        serious = True
    if _USER_WRITABLE.search(target + '\\') or _USER_WRITABLE.search(
            command):
        reasons.append("starts from a folder any user can write to")
    lowered_command = command.lower()
    if any(host in lowered_command for host in _SCRIPT_HOSTS) and \
            entry['location'] in ('Run key', 'Scheduled task',
                                  'Startup folder', 'Service'):
        reasons.append("starts a script host or system binary that runs "
                       "other code")
    if entry.get('exists') is False:
        reasons.append("the file it starts is not on this image")
    elif entry.get('exists') and entry.get('signed') is False and \
            not in_windows and not lowered.startswith(
                ('c:\\program files', 'c:\\windows\\')):
        reasons.append("no embedded signature, outside Windows and Program "
                       "Files")
    if entry.get('hash_category') == 'known-good' and not serious:
        return 'benign', reasons + [f"its file is known good "
                                    f"({entry.get('hash_set')})"]
    if serious:
        return 'suspicious', reasons
    # A signed file whose only oddity is where it lives is how per-user
    # installers (Google Update, Teams) work: kept as a reason, not raised.
    if reasons == ["starts from a folder any user can write to"] and \
            entry.get('signed'):
        return 'benign', reasons + ["its file carries an embedded "
                                    "signature"]
    if reasons and entry['location'] not in ('Driver',) and not (
            entry.get('exists') is False and entry['location'] in
            ('Service',) and in_windows):
        return 'notable', reasons
    return 'benign', reasons


# --- one image -----------------------------------------------------------------------

def collect(image_handler, case=None, evidence_id=None, hash_lookup=None,
            should_stop=None, progress=None):
    """Every autostart on every volume of the image, graded: Windows
    here, Linux and macOS in core/persistence_unix.py."""
    from trace_app.core.activity import (_hive, _profiles, _sid_names,
                                         _split, _volumes, lnk)
    from trace_app.core.walk import volume_offsets
    out = []
    for offset, volume in ((o, v) for o in volume_offsets(image_handler)
                           for v in _volumes(image_handler, o)):
        if volume.fs is None:
            continue
        found = []

        def tick(label, found=found):
            if should_stop and should_stop():
                raise PersistenceCancelled()
            if progress:
                progress(len(found), 0, label)

        windows = volume.find('Windows') or volume.find('WINNT')
        if windows is None:
            # Linux and macOS: systemd, cron, launchd... (persistence_unix)
            from trace_app.core import persistence_unix
            from trace_app.core.activity import _homes
            out += persistence_unix.collect(volume, _homes(volume),
                                            hash_lookup, tick)
            continue

        config = (windows.name, 'System32', 'config')
        for hive_name, reader in (('SOFTWARE', from_software),
                                  ('SYSTEM', from_system)):
            entry = volume.find(*config, hive_name)
            if entry is None:
                continue
            tick(entry.path)
            hive = _hive(volume, entry)
            if hive is not None:
                found += reader(hive, entry.path, volume.ref(entry))
        sids = _sid_names(volume, windows)
        for user, home in _profiles(volume):
            ntuser = volume.find(*_split(home.path), 'NTUSER.DAT')
            if ntuser is not None:
                tick(ntuser.path)
                hive = _hive(volume, ntuser)
                if hive is not None:
                    found += from_user(hive, user, ntuser.path,
                                       volume.ref(ntuser))
            for parts in (('AppData', 'Roaming', 'Microsoft', 'Windows',
                           'Start Menu', 'Programs', 'Startup'),
                          ('Start Menu', 'Programs', 'Startup')):
                folder = volume.find(*_split(home.path), *parts)
                found += _startup(volume, folder, user, lnk, tick)
        for parts in (('ProgramData', 'Microsoft', 'Windows', 'Start Menu',
                       'Programs', 'Startup'),
                      ('Documents and Settings', 'All Users', 'Start Menu',
                       'Programs', 'Startup')):
            found += _startup(volume, volume.find(*parts), 'All users', lnk,
                              tick)
        tasks = volume.find(windows.name, 'System32', 'Tasks')
        found += _tasks(volume, tasks, '', tick)
        for parts in (('System32', 'wbem', 'Repository', 'OBJECTS.DATA'),
                      ('System32', 'wbem', 'Repository', 'FS',
                       'OBJECTS.DATA')):
            entry = volume.find(windows.name, *parts)
            if entry is not None:
                tick(entry.path)
                found += from_wmi_repository(volume.read(entry), entry.path,
                                             volume.ref(entry))
        for item in found:
            if sids and item.get('user', '').upper() in sids:
                item['user'] = sids[item['user'].upper()]
            _resolve(volume, item, hash_lookup)
            item['grade'], item['reasons'] = grade(item)
        out += found
    return out


class PersistenceCancelled(Exception):
    """The examiner stopped the run."""


def _startup(volume, folder, user, lnk, tick):
    out = []
    for entry in volume.children(folder):
        if entry.name.lower() == 'desktop.ini':
            continue
        tick(entry.path)
        command, detail = entry.name, {}
        if entry.name.lower().endswith('.lnk'):
            try:
                facts = lnk.parse(volume.read(entry))
                command = ' '.join(p for p in (facts.get('target') or '',
                                               facts.get('arguments') or '')
                                   if p).strip() or entry.name
                detail = {'shortcut': entry.name,
                          'working folder': facts.get('working_dir')}
            except Exception:
                pass
        else:
            command = 'C:\\' + entry.path.strip('/').replace('/', '\\')
        out.append(_entry('Startup folder', entry.name, command,
                          entry.modified, user=user, source=entry.path,
                          source_ref=volume.ref(entry),
                          basis="the file's last modification", **detail))
    return out


def _tasks(volume, folder, prefix, tick, depth=0):
    out = []
    if folder is None or depth > 8:
        return out
    for entry in volume.listdir(folder.path):
        name = f"{prefix}\\{entry.name}"
        if entry.is_dir:
            out += _tasks(volume, entry, name, tick, depth + 1)
            continue
        if not entry.size or entry.size > 1024 * 1024:
            continue
        tick(entry.path)
        try:
            out += from_task(name, volume.read(entry), entry.path,
                             volume.ref(entry), entry.modified)
        except Exception as exc:
            logger.debug("Not a task: %s (%s)", entry.path, exc)
    return out


def _resolve(volume, item, hash_lookup):
    """Fill target, exists, signed, hashes and hash-set facts."""
    target = target_of(item['command'])
    item['target'] = target
    item['exists'] = None
    item['signed'] = None
    if not target or not re.match(r'^[a-z]:\\', target, re.IGNORECASE):
        return
    parts = [p for p in target[3:].split('\\') if p]
    entry = volume.find(*parts) if parts else None
    if entry is None or entry.is_dir:
        item['exists'] = False
        return
    item['exists'] = not entry.deleted
    item['target_ref'] = volume.ref(entry)
    item['target_path'] = entry.path
    item['target_size'] = entry.size
    if entry.size and entry.size <= MAX_HASH_BYTES:
        data = volume.read(entry)
        item['signed'] = has_embedded_signature(data[:1 << 20])
        digests = {'md5': hashlib.md5(data).hexdigest(),
                   'sha1': hashlib.sha1(data).hexdigest(),
                   'sha256': hashlib.sha256(data).hexdigest()}
        item['sha256'] = digests['sha256']
        if hash_lookup is not None:
            match = hash_lookup(digests)
            if match:
                item['hash_category'], item['hash_set'] = match


def hash_lookup_for(case, library=None):
    """A function digests -> (category, set name) or None, from the hash
    sets the case uses; None when hash sets are off."""
    from trace_app.core import hashsets
    library = library or hashsets.Library()
    options = hashsets.case_options(case, library)
    if not options.get('enabled'):
        return None
    lookups = []
    for entry in library.sets():
        if hashsets.set_enabled_in(options, entry) and entry.get('available'):
            try:
                lookups.append((entry, hashsets.SetLookup(library, entry)))
            except Exception as exc:
                logger.debug("Hash set %s unusable: %s", entry['name'], exc)
    if not lookups:
        return None
    order = {'known-bad': 0, 'notable': 1, 'known-good': 2}
    lookups.sort(key=lambda pair: order.get(pair[0]['category'], 3))

    def lookup(digests):
        for entry, sets in lookups:
            for algorithm, digest in digests.items():
                if algorithm in entry.get('algorithms', ()) and \
                        sets.match(algorithm, [digest]):
                    return entry['category'], entry['name']
        return None
    lookup.close = lambda: [sets.close() for _e, sets in lookups]
    return lookup


def analyse_evidence(image_handler, case, evidence_id, library=None,
                     progress=None, should_stop=None):
    """Store an image's autostarts, replacing an earlier run's; the
    suspicious and notable ones are findings too. Returns how many."""
    lookup = hash_lookup_for(case, library)
    try:
        entries = collect(image_handler, case, evidence_id, lookup,
                          should_stop, progress)
    except PersistenceCancelled:
        case.record_event('persistence cancelled',
                          f"evidence id={evidence_id}")
        return 0
    finally:
        if lookup is not None:
            lookup.close()
    case.replace_persistence(evidence_id, entries)
    findings = []
    for item in entries:
        if item['grade'] == 'benign':
            continue
        ref = item.get('target_ref') or item.get('source_ref') or ''
        path = item.get('target_path') or item.get('source') or ''
        findings.append((
            ref, re.split(r'[\\/]', item.get('target') or item['name'])[-1]
            or item['name'],
            path, item.get('target_size'), item['location'], item['grade'],
            f"{item['location']}: {item['name']} -- "
            + '; '.join(item['reasons']),
            json.dumps({k: item.get(k) for k in (
                'location', 'name', 'command', 'target', 'user', 'source',
                'reasons', 'signed', 'exists', 'hash_set')}, default=str)))
    case.clear_findings(evidence_id, MODULE_PERSISTENCE)
    case.add_module_findings(evidence_id, MODULE_PERSISTENCE, findings)
    counts = {}
    for item in entries:
        counts[item['grade']] = counts.get(item['grade'], 0) + 1
    case.record_event(
        'persistence read',
        f"evidence id={evidence_id} entries={len(entries)} "
        f"suspicious={counts.get('suspicious', 0)} "
        f"notable={counts.get('notable', 0)}")
    return len(entries)

"""What the people using a computer did: programs run, files and folders
opened, USB devices, deletions, logons, and their web browsing.

The artifacts are read where Windows (and the browsers) keep them -- not by
walking every file, so a run takes seconds to minutes rather than the length
of a full pass. Each finding becomes one record with a time, what happened,
what it happened to, who, and the file it was read from; records are what
the Activity tab lists and what a timeline will be built from.

Every source states what its time means. A Shimcache time is the program
FILE's modification time, not a run; a ShellBag time is when Explorer last
rewrote that folder's entry. Times read from local-time formats (setupapi,
shell items' DOS dates) are kept as local and marked so.

No Qt here: runs in the background job process (core/background.py).
"""

import logging
import posixpath
import re

import pytsk3

from trace_app.core.activity import (browsers, eventlogs, jumplists, lnk,
                                     prefetch, recyclebin, registry, setupapi,
                                     times)
from trace_app.infra import capabilities

logger = logging.getLogger('TRACE.Activity')

#: (key, label) in the order the Activity tab shows them.
CATEGORIES = (
    ('programs', 'Programs run'),
    ('files', 'Files and folders'),
    ('usb', 'USB devices'),
    ('recycle', 'Recycle Bin'),
    ('logons', 'Logons and remote access'),
    ('browser', 'Web history'),
    ('downloads', 'Downloads'),
    ('searches', 'Web searches'),
    ('network', 'Networks and Wi-Fi'),
    ('usage', 'App and network usage (SRUM)'),
    ('system', 'System and installed programs'),
)

#: Larger than this is not read (a 2 GB Security.evtx is real but rare).
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class ActivityCancelled(Exception):
    """The examiner stopped the run."""


def record(category, source, when, what, subject, detail=None, user='',
           path='', ref='', local=False):
    """One thing that happened, in the shape the case stores."""
    if hasattr(when, 'tzinfo') and when is not None and when.tzinfo is None \
            and not local:
        when = when.replace(tzinfo=times.UTC)
    clean = {}
    for key, value in (detail or {}).items():
        if value in (None, '', [], {}):
            continue
        if hasattr(value, 'strftime'):
            value = value.strftime('%Y-%m-%d %H:%M:%S') + \
                ('' if getattr(value, 'tzinfo', None) else ' (local)')
        clean[key] = value
    return {'category': category, 'source': source,
            'time': (when.strftime('%Y-%m-%d %H:%M:%S') if local and when
                     else times.iso(when)) if when else None,
            'local': bool(local and when), 'what': what,
            'subject': subject or '', 'user': user or '', 'detail': clean,
            'path': path, 'ref': ref}


# --- finding files ----------------------------------------------------------------

class _Entry:
    __slots__ = ('name', 'path', 'inode', 'seq', 'is_dir', 'size', 'deleted',
                 'created', 'modified')


class Volume:
    """A file system in the image, with case-insensitive path lookups --
    XP writes WINDOWS\\system32, later versions Windows\\System32."""

    def __init__(self, image_handler, offset):
        self.handler = image_handler
        self.offset = offset
        self.fs = image_handler.get_fs_info(offset)
        self._cache = {}

    def listdir(self, path):
        """Entries of the directory at `path` ('/'-separated), or []."""
        key = path.lower()
        if key in self._cache:
            return self._cache[key]
        out = []
        directory = self._open_dir(path)
        if directory is not None:
            for entry in directory:
                info = entry.info
                if info.name is None or info.meta is None:
                    continue
                name = info.name.name.decode('utf-8', 'replace')
                if name in ('.', '..'):
                    continue
                meta = info.meta
                item = _Entry()
                item.name = name
                item.path = posixpath.join(path, name)
                item.inode = meta.addr
                item.seq = getattr(meta, 'seq', None)
                item.is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                item.size = meta.size
                item.deleted = not bool(int(meta.flags)
                                        & pytsk3.TSK_FS_META_FLAG_ALLOC)
                item.created = times.unix(getattr(meta, 'crtime', 0) or 0)
                item.modified = times.unix(getattr(meta, 'mtime', 0) or 0)
                out.append(item)
        self._cache[key] = out
        return out

    def _open_dir(self, path):
        if self.fs is None:
            return None
        try:
            return self.fs.open_dir(path=path or '/')
        except (OSError, IOError):
            return None

    def find(self, *parts):
        """The entry at a case-insensitive path, or None."""
        path = '/'
        entry = None
        for part in parts:
            wanted = part.lower()
            match = [e for e in self.listdir(path) if e.name.lower() == wanted]
            # The live entry first; a deleted one of the same name after.
            match.sort(key=lambda e: e.deleted)
            if not match:
                return None
            entry = match[0]
            path = entry.path
        return entry

    def children(self, directory, suffix='', dirs=False):
        """Entries in a directory entry, filtered by name suffix."""
        if directory is None:
            return []
        return [e for e in self.listdir(directory.path)
                if e.is_dir == dirs and e.name.lower().endswith(suffix.lower())
                and (dirs or e.size)]

    def read(self, entry):
        if entry is None or not entry.size or entry.size > MAX_ARTIFACT_BYTES:
            return b''
        try:
            content, _meta = self.handler.get_file_content(entry.inode,
                                                            self.offset)
        except Exception as exc:
            logger.debug("Could not read %s: %s", entry.path, exc)
            return b''
        return content or b''

    def ref(self, entry):
        from trace_app.core.case import make_artifact_ref
        return make_artifact_ref(self.offset, entry.inode, entry.seq)


# --- the run ----------------------------------------------------------------------

def collect(image_handler, progress=None, should_stop=None, carved=()):
    """Every activity record in the image.

    `carved` is [(name, bytes, ref)] of SQLite databases the carver
    recovered, read as browser history if they are.
    """
    partitions = image_handler.get_partitions()
    offsets = [p[2] for p in partitions] if partitions else [0]
    out = []
    steps = [0]

    def step(label):
        if should_stop and should_stop():
            raise ActivityCancelled()
        steps[0] += 1
        if progress:
            progress(steps[0], 0, label)

    for offset in offsets:
        try:
            volume = Volume(image_handler, offset)
        except Exception:
            continue
        if volume.fs is None:
            continue
        try:
            out.extend(_windows(volume, step))
            out.extend(_browsers(volume, step))
        except ActivityCancelled:
            raise
        except Exception as exc:
            logger.warning("Activity on the volume at %s stopped early: %s",
                           offset, exc)
    for name, data, ref in carved:
        step(name)
        out.extend(_history(data, None, '', name, ref, '', carved=True))
    return out


def _windows(volume, step):
    windows = volume.find('Windows') or volume.find('WINNT')
    out = []
    users = _profiles(volume)
    sids = _sid_names(volume, windows) if windows is not None else {}
    if windows is not None:
        out += _prefetch(volume, windows, step)
        out += _system_hive(volume, windows, step, sids)
        out += _software_hive(volume, windows, step)
        out += _amcache(volume, windows, step)
        out += _setupapi(volume, windows, step)
        out += _event_logs(volume, windows, step)
        out += _srum(volume, windows, step, sids)
    out += _recycle_bin(volume, sids, step)
    for user, home in users:
        out += _user_registry(volume, user, home, step)
        out += _user_shortcuts(volume, user, home, step)
        out += _ie_history(volume, user, home, step)
        out += _windows_timeline(volume, user, home, step)
    return out


def _profiles(volume):
    """[(user name, home entry)] from Users\\ and Documents and Settings\\."""
    out = []
    for top in ('Users', 'Documents and Settings'):
        root = volume.find(top)
        for home in volume.children(root, dirs=True):
            if home.name.lower() in ('public', 'all users', 'default',
                                     'default user', 'localservice',
                                     'networkservice'):
                continue
            out.append((home.name, home))
    return out


def _prefetch(volume, windows, step):
    out = []
    folder = volume.find(windows.name, 'Prefetch')
    for entry in volume.children(folder, '.pf'):
        step(entry.path)
        data = volume.read(entry)
        try:
            facts = prefetch.parse(data)
        except prefetch.PrefetchError:
            continue
        # Prefetch records the path through the device: \DEVICE\
        # HARDDISKVOLUME1\WINDOWS\... or \VOLUME{...}\... The program is what
        # the examiner scans for, so the device moves to the details.
        device, subject = _split_device(facts['path'])
        subject = subject or facts['executable']
        detail = {'run count': facts['run_count'],
                  'device': device,
                  'prefetch hash': facts['hash'],
                  'files loaded': len(facts['files']),
                  'volumes': ', '.join(f"{v['device']} ({v['serial']})"
                                       for v in facts['volumes']),
                  'deleted prefetch file': entry.deleted or None}
        common = dict(path=entry.path, ref=volume.ref(entry))
        for index, when in enumerate(facts['runs']):
            out.append(record('programs', 'Prefetch', when,
                              'Program run' if index == 0
                              else 'Program run (earlier)', subject,
                              detail, **common))
        if entry.created:
            out.append(record('programs', 'Prefetch', entry.created,
                              'Program first run (approx.)', subject,
                              {'basis': 'Prefetch file created; Windows '
                                        'writes it about 10 s after the '
                                        'first run'}, **common))
    return out


_DEVICE_PREFIX = re.compile(r'^(\\DEVICE\\[^\\]+|\\VOLUME\{[^}]+\})(\\.*)$',
                            re.IGNORECASE)


def _split_device(path):
    """('\\DEVICE\\HARDDISKVOLUME1', '\\WINDOWS\\...') from a Prefetch path."""
    match = _DEVICE_PREFIX.match(path or '')
    return (match.group(1), match.group(2)) if match else ('', path or '')


def _hive(volume, entry):
    data = volume.read(entry)
    if data[:4] != b'regf':
        return None
    try:
        return registry.open_hive(data)
    except Exception as exc:
        logger.debug("Could not open hive %s: %s", entry.path, exc)
        return None


def _system_hive(volume, windows, step, sids=None):
    entry = volume.find(windows.name, 'System32', 'config', 'SYSTEM')
    if entry is None:
        return []
    step(entry.path)
    hive = _hive(volume, entry)
    if hive is None:
        return []
    common = dict(path=entry.path, ref=volume.ref(entry))
    out = []
    for item in registry.bam(hive):
        out.append(record(
            'programs', f"Registry ({item['source']})", item['last_run'],
            'Program last run', item['path'],
            {'user SID': item['sid'],
             'basis': 'the Background Activity Moderator keeps the last '
                      'run of each program, per user'},
            user=(sids or {}).get(item['sid'].upper(), item['sid']),
            **common))
    zone = registry.time_zone(hive)
    if zone:
        offset = zone['bias_minutes']
        out.append(record(
            'system', 'Registry (TimeZoneInformation)', zone['changed'],
            'Time zone configured', zone['name'],
            {'UTC offset': f"UTC{-offset / 60:+g}h" if offset is not None
             else None,
             'offset in effect': f"UTC{-zone['active_bias'] / 60:+g}h"
             if zone['active_bias'] is not None else None,
             'standard name': zone['standard_name'],
             'daylight name': zone['daylight_name'],
             'basis': "the key's last write, not necessarily when the "
                      "zone was chosen"}, **common))
    for item in registry.shimcache(hive):
        detail = {'position': item['position'],
                  'executed': {True: 'yes', False: 'not recorded'}.get(
                      item['executed']),
                  'basis': "the time is the file's last modification, "
                           "not when it ran"}
        out.append(record('programs', 'Shimcache', item['modified'],
                          'Program seen by Windows', item['path'],
                          detail, **common))
    for device in registry.usb_devices(hive):
        subject = device['name'] or f"{device['vendor']} {device['product']}"
        detail = {'serial': device['serial'], 'vendor': device['vendor'],
                  'product': device['product'], 'drive': device['drive'],
                  'device': device['device']}
        for field, what in (('first_installed', 'USB device first connected'),
                            ('last_connected', 'USB device last connected'),
                            ('last_removed', 'USB device last removed')):
            if device.get(field):
                out.append(record('usb', 'Registry (USBSTOR)', device[field],
                                  what, subject, detail, **common))
        if not device.get('last_connected') and device.get(
                'interface_updated'):
            out.append(record('usb', 'Registry (DeviceClasses)',
                              device['interface_updated'],
                              'USB device last connected', subject,
                              dict(detail, basis='device interface key last '
                                                 'written'), **common))
        if not any(device.get(f) for f in ('first_installed',
                                           'last_connected',
                                           'interface_updated')):
            out.append(record('usb', 'Registry (USBSTOR)',
                              device['key_updated'], 'USB device seen',
                              subject, dict(detail, basis='key last written'),
                              **common))
    return out


def _software_hive(volume, windows, step):
    entry = volume.find(windows.name, 'System32', 'config', 'SOFTWARE')
    if entry is None:
        return []
    step(entry.path)
    hive = _hive(volume, entry)
    if hive is None:
        return []
    common = dict(path=entry.path, ref=volume.ref(entry))
    out = []
    install = registry.windows_install(hive)
    if install and install['installed']:
        out.append(record(
            'system', 'Registry (CurrentVersion)', install['installed'],
            'Windows installed', install['product'],
            {'build': install['build'], 'registered owner': install['owner'],
             'organisation': install['organisation']}, **common))
    for network in registry.network_profiles(hive):
        detail = {'type': network['type'],
                  'description': network['description'],
                  'gateway MAC': network['gateway_mac'],
                  'DNS suffix': network['dns_suffix'],
                  'profile': network['guid']}
        for field, what in (('created', 'Network first connected'),
                            ('last_connected', 'Network last connected')):
            if network[field]:
                out.append(record('network', 'Registry (NetworkList)',
                                  network[field], what, network['name'],
                                  detail, local=True, **common))
    for program in registry.installed_programs(hive):
        out.append(record(
            'system', 'Registry (Uninstall)', program['key_written'],
            'Program installed', program['name'],
            {'version': program['version'], 'publisher': program['publisher'],
             'install date': program['install_date'],
             'location': program['location'],
             'basis': "the uninstall key's last write; the install date, "
                      "when Windows kept one, is a day only"}, **common))
    return out


def _srum(volume, windows, step, sids):
    entry = volume.find(windows.name, 'System32', 'sru', 'SRUDB.dat')
    if entry is None:
        return []
    if not capabilities.available('esedb'):
        logger.warning("SRUM not read: %s", capabilities.reason('esedb'))
        return []
    step(entry.path)
    from trace_app.core.activity import ese
    try:
        entries = ese.srum(volume.read(entry))
    except Exception as exc:
        logger.warning("Could not read SRUM %s: %s", entry.path, exc)
        return []
    common = dict(path=entry.path, ref=volume.ref(entry))
    basis = 'SRUM summarises each hour; the time is when it recorded it'
    out = []
    for item in entries:
        user = item['user']
        user = sids.get(str(user).upper(), user) if isinstance(user, str)             else str(user or '')
        subject = str(item['application'] or '')
        if item['table'] == 'network':
            out.append(record(
                'usage', 'SRUM (network use)', item['recorded'],
                'Network data used', subject,
                {'bytes sent': item['bytes_sent'],
                 'bytes received': item['bytes_received'],
                 'interface': item['interface'], 'profile': item['profile'],
                 'basis': basis}, user=user, **common))
        elif item['table'] == 'application':
            out.append(record(
                'usage', 'SRUM (application use)', item['recorded'],
                'Application resource use', subject,
                {'foreground CPU cycles': item['foreground_cycles'],
                 'background CPU cycles': item['background_cycles'],
                 'bytes read': (item['foreground_read'] or 0)
                 + (item['background_read'] or 0),
                 'bytes written': (item['foreground_written'] or 0)
                 + (item['background_written'] or 0),
                 'basis': basis}, user=user, **common))
        elif item['table'] == 'connectivity':
            out.append(record(
                'network', 'SRUM (connectivity)',
                item['connected_since'] or item['recorded'],
                'Connected to a network', subject,
                {'connected for (s)': item['connected_seconds'],
                 'interface': item['interface'], 'profile': item['profile'],
                 'recorded': item['recorded']}, user=user, **common))
        else:
            out.append(record(
                'usage', 'SRUM (energy use)', item['recorded'],
                'Energy use recorded', subject,
                {'on AC (s)': item['active_ac'],
                 'on battery (s)': item['active_dc'],
                 'energy': item['energy'], 'basis': basis},
                user=user, **common))
    return out


_IE_HISTORY_HOMES = (
    ('AppData', 'Local', 'Microsoft', 'Windows', 'History', 'History.IE5'),
    ('AppData', 'Local', 'Microsoft', 'Windows', 'History', 'Low',
     'History.IE5'),
    ('Local Settings', 'History', 'History.IE5'),
)
_IE_CACHE_HOMES = (
    ('AppData', 'Local', 'Microsoft', 'Windows', 'Temporary Internet Files',
     'Content.IE5'),
    ('AppData', 'Local', 'Microsoft', 'Windows', 'Temporary Internet Files',
     'Low', 'Content.IE5'),
    ('Local Settings', 'Temporary Internet Files', 'Content.IE5'),
)


def _ie_history(volume, user, home, step):
    """Internet Explorer and legacy Edge: WebCacheV01.dat (IE 10+) and
    the older index.dat files."""
    out = []
    base = _split(home.path)
    webcache = volume.find(*base, 'AppData', 'Local', 'Microsoft', 'Windows',
                           'WebCache', 'WebCacheV01.dat')
    if webcache is not None and capabilities.available('esedb'):
        step(webcache.path)
        from trace_app.core.activity import ese
        try:
            entries = ese.webcache(volume.read(webcache))
        except Exception as exc:
            logger.warning("Could not read %s: %s", webcache.path, exc)
            entries = []
        common = dict(path=webcache.path, ref=volume.ref(webcache))
        for item in entries:
            detail = {'visits': item['hits'], 'cached file': item['filename'],
                      'size': item['size'] or None,
                      'expires': item['expires'],
                      'container': item['directory']}
            if item['kind'] == 'visit':
                out.append(record('browser', 'Internet Explorer / Edge',
                                  item['accessed'] or item['modified'],
                                  'Page visited', item['url'], detail,
                                  user=item['user'] or user, **common))
            elif item['kind'] == 'download':
                out.append(record('downloads', 'Internet Explorer / Edge',
                                  item['accessed'] or item['created'],
                                  'File downloaded', item['url'], detail,
                                  user=user, **common))
            else:
                out.append(record('browser', 'Internet Explorer / Edge',
                                  item['accessed'] or item['created'],
                                  'Cached from the web', item['url'],
                                  dict(detail, modified=item['modified']),
                                  user=user, **common))
    elif webcache is not None:
        logger.warning("WebCache not read: %s", capabilities.reason('esedb'))
    if not capabilities.available('msiecf'):
        return out
    from trace_app.core.activity import wintimeline
    found = []
    for parts in _IE_HISTORY_HOMES:
        folder = volume.find(*base, *parts)
        if folder is None:
            continue
        index = volume.find(*_split(folder.path), 'index.dat')
        if index is not None:
            found.append((index, 'history'))
        for daily in volume.children(folder, dirs=True):
            if daily.name.upper().startswith('MSHIST'):
                index = volume.find(*_split(daily.path), 'index.dat')
                if index is not None:
                    found.append((index, 'daily'))
    for parts in _IE_CACHE_HOMES:
        folder = volume.find(*base, *parts)
        index = volume.find(*_split(folder.path), 'index.dat') \
            if folder is not None else None
        if index is not None:
            found.append((index, 'cache'))
    for entry, kind in found:
        step(entry.path)
        try:
            items = wintimeline.index_dat(volume.read(entry), kind)
        except Exception as exc:
            logger.debug("Could not read %s: %s", entry.path, exc)
            continue
        common = dict(path=entry.path, ref=volume.ref(entry))
        for item in items:
            if kind == 'cache':
                out.append(record(
                    'browser', 'Internet Explorer (index.dat)', item['when'],
                    'Cached from the web', item['url'],
                    {'cached file': item['filename'],
                     'size': item['size'] or None, 'visits': item['hits'],
                     'modified': item['second']}, user=user, **common))
            else:
                out.append(record(
                    'browser', 'Internet Explorer (index.dat)', item['when'],
                    'Page visited', item['url'],
                    {'visits': item['hits'],
                     'basis': 'daily history: the visit time is the '
                              'UTC one Windows keeps beside the local one'
                     if kind == 'daily' else None},
                    user=item['user'] or user, **common))
    return out


def _windows_timeline(volume, user, home, step):
    """ActivitiesCache.db in each ConnectedDevicesPlatform account folder."""
    out = []
    platform = volume.find(*_split(home.path), 'AppData', 'Local',
                           'ConnectedDevicesPlatform')
    from trace_app.core.activity import wintimeline
    for account in volume.children(platform, dirs=True):
        entry = volume.find(*_split(account.path), 'ActivitiesCache.db')
        if entry is None:
            continue
        step(entry.path)
        wal = volume.find(*_split(account.path), 'ActivitiesCache.db-wal')
        try:
            items = wintimeline.activities(volume.read(entry),
                                           volume.read(wal) if wal else None)
        except Exception as exc:
            logger.warning("Could not read %s: %s", entry.path, exc)
            continue
        common = dict(user=user, path=entry.path, ref=volume.ref(entry))
        for item in items:
            subject = item['description'] or item['application']
            detail = {'application': item['application'],
                      'app name': item['display'],
                      'content': item['content'] if item['content'] !=
                      'ms-shellactivity:' else None,
                      'active (s)': item['active_seconds'],
                      'ended': item['ended'],
                      'user time zone': item['time_zone'],
                      'clipboard': 'yes' if item['clipboard'] else None}
            what = {'opened': 'Opened (Windows Timeline)',
                    'in use': 'In use (Windows Timeline)'}.get(
                item['kind'], f"{item['kind'].capitalize()} "
                              f"(Windows Timeline)")
            out.append(record('files' if item['kind'] == 'opened'
                              else 'programs', 'Windows Timeline',
                              item['started'] or item['modified'], what,
                              subject, detail, **common))
    return out


def _amcache(volume, windows, step):
    entry = volume.find(windows.name, 'AppCompat', 'Programs', 'Amcache.hve')
    if entry is None:
        return []
    step(entry.path)
    hive = _hive(volume, entry)
    if hive is None:
        return []
    common = dict(path=entry.path, ref=volume.ref(entry))
    return [record('programs', 'Amcache', item['recorded'],
                   'Program recorded by Windows', item['path'],
                   {'SHA-1': item['sha1'], 'publisher': item['publisher'],
                    'version': item['version'], 'linked': item['linked'],
                    'file modified': item['modified'],
                    'basis': 'when the entry was written; near the first '
                             'run or install'}, **common)
            for item in registry.amcache(hive)]


def _setupapi(volume, windows, step):
    out = []
    folder = volume.find(windows.name, 'inf')
    candidates = [e for e in volume.children(folder, '.log')
                  if e.name.lower().startswith('setupapi.dev')]
    xp = volume.find(windows.name, 'setupapi.log')
    if xp is not None:
        candidates.append(xp)
    for entry in candidates:
        step(entry.path)
        text = volume.read(entry).decode('utf-8', 'replace')
        for item in setupapi.parse(text):
            kind, vendor, product, serial = setupapi.describe(item['device'])
            out.append(record(
                'usb', 'setupapi log', item['installed'],
                'USB device first connected' if kind == 'USBSTOR'
                else 'Device driver installed',
                f'{vendor} {product}'.strip() or item['device'],
                {'serial': serial, 'device': item['device']},
                path=entry.path, ref=volume.ref(entry), local=True))
    return out


_EVTX_LOGS = (
    'Security.evtx', 'System.evtx',
    'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational'
    '.evtx',
    'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx',
)
_EVT_LOGS = ('SecEvent.Evt', 'SysEvent.Evt')


def _event_logs(volume, windows, step):
    out = []
    logs = volume.find(windows.name, 'System32', 'winevt', 'Logs')
    wanted = {name.lower() for name in _EVTX_LOGS}
    for entry in volume.children(logs, '.evtx'):
        if entry.name.lower() not in wanted:
            continue
        step(entry.path)
        try:
            events = eventlogs.from_evtx(volume.read(entry))
        except Exception as exc:
            logger.debug("Could not read %s: %s", entry.path, exc)
            continue
        out += [record('logons', f'Event log ({entry.name[:-5]})', when,
                       what, subject, detail, path=entry.path,
                       ref=volume.ref(entry))
                for when, what, subject, detail, _event in events]
    config = volume.find(windows.name, 'System32', 'config')
    for entry in volume.children(config, '.evt'):
        if entry.name.lower() not in {n.lower() for n in _EVT_LOGS}:
            continue
        step(entry.path)
        out += [record('logons', f'Event log ({entry.name[:-4]})', when,
                       what, subject, detail, path=entry.path,
                       ref=volume.ref(entry))
                for when, what, subject, detail, _event in
                eventlogs.from_evt(volume.read(entry))]
    return out


def _sid_names(volume, windows):
    """User SID -> profile name, from the SOFTWARE hive's ProfileList."""
    entry = volume.find(windows.name, 'System32', 'config', 'SOFTWARE')
    hive = _hive(volume, entry) if entry is not None else None
    if hive is None:
        return {}
    out = {}
    try:
        key = hive.open('Microsoft\\Windows NT\\CurrentVersion\\ProfileList')
    except Exception:
        return {}
    for sub in key.subkeys():
        try:
            path = sub.value('ProfileImagePath').value()
        except Exception:
            continue
        out[sub.name().upper()] = str(path).replace('/', '\\').rsplit(
            '\\', 1)[-1]
    return out


def _recycle_bin(volume, sids, step):
    out = []
    root = volume.find('$Recycle.Bin')
    for user_dir in volume.children(root, dirs=True):
        user = sids.get(user_dir.name.upper(), user_dir.name)
        for entry in volume.children(user_dir):
            if not entry.name.upper().startswith('$I'):
                continue
            step(entry.path)
            facts = recyclebin.parse_i_file(volume.read(entry))
            if facts:
                out.append(record(
                    'recycle', 'Recycle Bin', facts['deleted'],
                    'File deleted', facts['path'],
                    {'size': facts['size'],
                     'content still present': 'yes' if volume.find(
                         *_split(user_dir.path), '$R' + entry.name[2:])
                     else 'no'},
                    user=user, path=entry.path, ref=volume.ref(entry)))
    old = volume.find('RECYCLER') or volume.find('RECYCLED')
    for user_dir in volume.children(old, dirs=True):
        info2 = volume.find(*_split(user_dir.path), 'INFO2')
        if info2 is None:
            continue
        step(info2.path)
        user = sids.get(user_dir.name.upper(), user_dir.name)
        for facts in recyclebin.parse_info2(volume.read(info2)):
            out.append(record(
                'recycle', 'Recycle Bin (INFO2)', facts['deleted'],
                'File deleted', facts['path'],
                {'size': facts['size'], 'record': facts['index']},
                user=user, path=info2.path, ref=volume.ref(info2)))
    return out


def _split(path):
    return [p for p in path.split('/') if p]


def _user_registry(volume, user, home, step):
    out = []
    ntuser = volume.find(*_split(home.path), 'NTUSER.DAT')
    usrclass = volume.find(*_split(home.path), 'AppData', 'Local',
                           'Microsoft', 'Windows', 'UsrClass.dat') or \
        volume.find(*_split(home.path), 'Local Settings', 'Application Data',
                    'Microsoft', 'Windows', 'UsrClass.dat')
    if ntuser is not None:
        step(ntuser.path)
        hive = _hive(volume, ntuser)
        if hive is not None:
            common = dict(user=user, path=ntuser.path, ref=volume.ref(ntuser))
            for item in registry.userassist(hive):
                if not item['last_run'] and not item['run_count']:
                    continue
                out.append(record(
                    'programs', 'UserAssist', item['last_run'],
                    'Shortcut opened (Explorer)' if item['kind'] == 'shortcut'
                    else 'Program run (Explorer)', item['name'],
                    {'run count': item['run_count'],
                     'focus count': item['focus_count'],
                     'focus time (s)': round(item['focus_ms'] / 1000)
                     if item['focus_ms'] else None}, **common))
            for item in registry.recent_docs(hive):
                out.append(record(
                    'files', 'RecentDocs', item['opened'],
                    'Folder opened' if item['extension'] == 'folder'
                    else 'File opened', item['name'],
                    {'list position': item['position'],
                     'basis': 'time known for the most recent item only'
                     if not item['opened'] else None}, **common))
            out += _bags(registry.shellbags(hive), common)
            for item in registry.run_mru(hive):
                out.append(record(
                    'programs', 'RunMRU', item['typed'],
                    'Command typed in Run', item['command'],
                    {'list position': item['position'],
                     'basis': 'time known for the most recent command only'
                     if not item['typed'] else None}, **common))
            for item in registry.typed_paths(hive):
                out.append(record(
                    'files', 'TypedPaths', item['typed'],
                    'Path typed in Explorer', item['path'],
                    {'list position': item['position']}, **common))
            for item in registry.word_wheel_query(hive):
                out.append(record(
                    'searches', 'WordWheelQuery', item['searched'],
                    'Searched in Explorer', item['query'],
                    {'list position': item['position']}, **common))
            for item in registry.mount_points(hive):
                out.append(record(
                    'usb', 'MountPoints2', item['mounted'],
                    'Share mounted by user' if item['kind'] ==
                    'Network share' else 'Volume mounted by user',
                    item['label'],
                    {'kind': item['kind'], 'label': item['volume_label'],
                     'basis': 'when this user last mounted it (key last '
                              'written); a volume GUID matches the USB '
                              'device that carried it'}, **common))
    if usrclass is not None:
        step(usrclass.path)
        hive = _hive(volume, usrclass)
        if hive is not None:
            out += _bags(registry.shellbags(hive),
                         dict(user=user, path=usrclass.path,
                              ref=volume.ref(usrclass)))
    return out


def _bags(bags, common):
    return [record('files', 'ShellBags', item['updated'], 'Folder viewed',
                   item['path'],
                   {'folder created': item['created'],
                    'folder modified': item['modified'],
                    'folder accessed': item['accessed'],
                    'MFT entry': f"{item['mft'][0]}-{item['mft'][1]}"
                    if item['mft'] else None,
                    'basis': "when Explorer last rewrote this folder's entry"},
                   **common)
            for item in bags if item['kind'] not in ('root',)]


def _shortcut_detail(shortcut):
    return {'target created': shortcut.get('target_created'),
            'target modified': shortcut.get('target_modified'),
            'target accessed': shortcut.get('target_accessed'),
            'target size': shortcut.get('target_size') or None,
            'volume': ' '.join(p for p in (shortcut.get('drive_type'),
                                           shortcut.get('volume_label'),
                                           shortcut.get('volume_serial'))
                               if p),
            'machine': shortcut.get('machine_id'),
            'MAC address': shortcut.get('mac_address'),
            'arguments': shortcut.get('arguments')}


def _user_shortcuts(volume, user, home, step):
    out = []
    base = _split(home.path)
    recent = volume.find(*base, 'AppData', 'Roaming', 'Microsoft', 'Windows',
                         'Recent') or volume.find(*base, 'Recent')
    office = volume.find(*base, 'AppData', 'Roaming', 'Microsoft', 'Office',
                         'Recent')
    for folder in (recent, office):
        for entry in volume.children(folder, '.lnk'):
            step(entry.path)
            try:
                shortcut = lnk.parse(volume.read(entry))
            except lnk.LnkError:
                continue
            target = shortcut.get('target') or entry.name[:-4]
            detail = _shortcut_detail(shortcut)
            common = dict(user=user, path=entry.path, ref=volume.ref(entry))
            if entry.modified:
                out.append(record('files', 'Shortcut (Recent)',
                                  entry.modified, 'File opened (last)',
                                  target, detail, **common))
            if entry.created and entry.created != entry.modified:
                out.append(record('files', 'Shortcut (Recent)', entry.created,
                                  'File opened (first)', target, detail,
                                  **common))
    for sub, parse in (('AutomaticDestinations', jumplists.parse_automatic),
                       ('CustomDestinations', jumplists.parse_custom)):
        folder = volume.find(*_split(recent.path), sub) if recent else None
        for entry in volume.children(folder):
            step(entry.path)
            try:
                items = parse(volume.read(entry))
            except Exception:
                continue
            app_id, app = jumplists.app_name(entry.name)
            for item in items:
                shortcut = item.get('lnk') or {}
                target = item.get('path') or shortcut.get('target', '')
                if not target:
                    continue
                detail = dict(_shortcut_detail(shortcut),
                              application=app or app_id,
                              pinned='yes' if item.get('pinned') else None,
                              **{'times opened': item.get('access_count'),
                                 'host': item.get('host')})
                out.append(record(
                    'files', 'Jump List', item.get('accessed'),
                    'File opened (Jump List)' if item.get('accessed')
                    else 'Jump List entry', target, detail, user=user,
                    path=entry.path, ref=volume.ref(entry)))
    return out


# --- browsers ------------------------------------------------------------------------

_CHROMIUM_HOMES = (
    ('AppData', 'Local', 'Google', 'Chrome', 'User Data'),
    ('AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
    ('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data'),
    ('AppData', 'Local', 'Vivaldi', 'User Data'),
    ('AppData', 'Local', 'Chromium', 'User Data'),
    ('AppData', 'Roaming', 'Opera Software'),
    ('Local Settings', 'Application Data', 'Google', 'Chrome', 'User Data'),
    ('Library', 'Application Support', 'Google', 'Chrome'),
    ('Library', 'Application Support', 'Microsoft Edge'),
    ('Library', 'Application Support', 'BraveSoftware', 'Brave-Browser'),
    ('.config', 'google-chrome'), ('.config', 'chromium'),
    ('.config', 'microsoft-edge'), ('.config', 'BraveSoftware',
                                    'Brave-Browser'),
)
_FIREFOX_HOMES = (
    ('AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
    ('Application Data', 'Mozilla', 'Firefox', 'Profiles'),
    ('Library', 'Application Support', 'Firefox', 'Profiles'),
    ('.mozilla', 'firefox'),
)


def _homes(volume):
    homes = list(_profiles(volume))
    for top in ('home',):
        for home in volume.children(volume.find(top), dirs=True):
            homes.append((home.name, home))
    root = volume.find('root')
    if root is not None and root.is_dir:
        homes.append(('root', root))
    return homes


def _browsers(volume, step):
    out = []
    for user, home in _homes(volume):
        base = _split(home.path)
        for parts in _CHROMIUM_HOMES:
            folder = volume.find(*base, *parts)
            if folder is None:
                continue
            profiles = [folder] + volume.children(folder, dirs=True)
            for profile in profiles:
                history = volume.find(*_split(profile.path), 'History')
                if history is None or history.is_dir:
                    continue
                step(history.path)
                out += _history(volume.read(history), None, user,
                                history.path, volume.ref(history),
                                browsers.browser_name(history.path)
                                or 'Chromium', profile=profile.name)
        for parts in _FIREFOX_HOMES:
            folder = volume.find(*base, *parts)
            for profile in volume.children(folder, dirs=True):
                for name in ('places.sqlite', 'downloads.sqlite'):
                    entry = volume.find(*_split(profile.path), name)
                    if entry is None:
                        continue
                    step(entry.path)
                    wal = volume.find(*_split(profile.path), name + '-wal')
                    out += _history(volume.read(entry),
                                    volume.read(wal) if wal else None, user,
                                    entry.path, volume.ref(entry), 'Firefox',
                                    profile=profile.name)
        safari = volume.find(*base, 'Library', 'Safari', 'History.db')
        if safari is not None:
            step(safari.path)
            wal = volume.find(*base, 'Library', 'Safari', 'History.db-wal')
            out += _history(volume.read(safari),
                            volume.read(wal) if wal else None, user,
                            safari.path, volume.ref(safari), 'Safari')
    return out


def _history(data, wal, user, path, ref, browser, profile='', carved=False):
    import sqlite3
    if not data:
        return []
    try:
        found = browsers.read(data, wal, browser)
    except (sqlite3.DatabaseError, ValueError) as exc:
        if not carved:
            logger.debug("Not browser history: %s (%s)", path, exc)
        return []
    browser = browser or {'chromium': 'Chromium-based',
                          'firefox': 'Firefox',
                          'safari': 'Safari'}[found['kind']]
    source = f'{browser} (carved)' if carved else browser
    common = dict(user=user, path=path, ref=ref)
    extra = {'browser': browser, 'profile': profile or None,
             'recovered': 'carved from unallocated space' if carved else None}
    out = []
    for visit in found['visits']:
        out.append(record('browser', source, visit['time'],
                          f"Visited ({visit['how']})" if visit['how']
                          else 'Visited', visit['url'],
                          dict(extra, title=visit['title'],
                               **{'time on page (s)': visit['duration_s']
                                  or None,
                                  'visits to this URL': visit['visit_count'],
                                  'typed': visit['typed_count'] or None}),
                          **common))
    for item in found['downloads']:
        out.append(record('downloads', source, item['time'], 'Downloaded',
                          item['path'],
                          dict(extra, **{'from': item['url'],
                                         'referrer': item['referrer'],
                                         'size': item['size'],
                                         'state': item['state'],
                                         'finished': item['finished'],
                                         'opened': 'yes' if item['opened']
                                         else None,
                                         'type': item['mime']}), **common))
    for item in found['searches']:
        out.append(record('searches', source, item['time'], 'Searched',
                          item['terms'],
                          dict(extra, engine=item['engine'], url=item['url']),
                          **common))
    return out


# --- into a case -----------------------------------------------------------------------

def run_evidence(image_handler, case, evidence_id, progress=None,
                 should_stop=None):
    """Read one image's activity into the case, replacing what an earlier
    run stored. Returns the number of records. Cancelling stores nothing:
    a half-read image would look like a complete one."""
    from trace_app.core.carving import read_carved
    carved = []
    for row in case.carved_files(evidence_id, 'sqlite'):
        try:
            data = read_carved(image_handler.read, row['offset'],
                               row['size'], row.get('fragments'))
        except Exception:
            data = None
        if data:
            carved.append((f"carved {row['name']}", data,
                           row.get('artifact_ref') or ''))
    case.set_user_activity_state(evidence_id, 'running')
    try:
        records = collect(image_handler, progress, should_stop, carved)
    except ActivityCancelled:
        case.set_user_activity_state(evidence_id, 'cancelled')
        return 0
    except Exception as exc:
        case.set_user_activity_state(evidence_id, 'failed', last_error=str(exc))
        raise
    case.clear_user_activity(evidence_id)
    for start in range(0, len(records), 1000):
        case.add_user_activity(evidence_id, records[start:start + 1000])
    case.commit()
    case.set_user_activity_state(evidence_id, 'done', records=len(records))
    logger.info("Read %d activity record(s) from evidence %s", len(records),
                evidence_id)
    return len(records)

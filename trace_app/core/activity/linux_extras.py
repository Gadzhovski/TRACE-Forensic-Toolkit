"""More of what a Linux user and system leave behind (no Qt), the items
lLEAPP lists that TRACE did not read:

* **Trash** (freedesktop.org Trash spec): each user's
  ~/.local/share/Trash and each volume's .Trash-<uid> / .Trash/<uid>.
  info/<name>.trashinfo holds the original Path (percent-encoded; relative
  to the volume's top in a volume trash) and DeletionDate (local time with
  no zone, as the spec says). Whether files/<name> is still there says if
  the trash was emptied since.
* **viminfo** (Vim 8+): command and search history, registers, file marks
  and the jump list, each with the Unix time Vim stored on its `|`
  line. Older files (no `|` lines) give the history untimed, in order.
* **Mounts and arrays**: /etc/fstab (network shares: server and share;
  a `credentials=` file is named, never read; `password=` is never
  copied), /etc/crypttab (encrypted volumes and where their key file is),
  /etc/mdadm.conf / /etc/mdadm/mdadm.conf (arrays by UUID). These have no
  "when"; each is dated by its file's last change, and says so.
* **Snap and Flatpak**: snapd's state.json (each snap's revision,
  version and channel; each change -- install, refresh, remove -- with
  its spawn and ready times) and Flatpak's installed apps (system-wide
  and per user; dated by their deploy folder).
* **LibreOffice** recent documents, on every system:
  registrymodifications.xcu's PickList -- the order, title, filter, and
  whether a thumbnail or a password is kept (a password is never copied).
  Only the newest has a time: the file's last change.

Expected values in the tests are plaso's for its .viminfo files.
"""

import datetime
import json
import logging
import posixpath
import re
import urllib.parse
import xml.etree.ElementTree as ElementTree

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.LinuxExtras')


def _changed(entry):
    stamp = times.iso(entry.modified) if entry is not None else None
    return f"the file's last change ({stamp or 'unknown'})"


def _text(volume, entry):
    if entry is None or entry.is_dir:
        return ''
    return volume.read(entry).decode('utf-8', 'replace')


# --- Trash -------------------------------------------------------------------------

def trashinfo(text):
    """{'path', 'deleted'} of a .trashinfo file, or None."""
    if '[Trash Info]' not in text:
        return None
    facts = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep:
            facts[key.strip()] = value.strip()
    if 'Path' not in facts:
        return None
    deleted = None
    stamp = facts.get('DeletionDate', '')
    for pattern in ('%Y-%m-%dT%H:%M:%S', '%Y%m%dT%H:%M:%S'):
        try:
            deleted = datetime.datetime.strptime(stamp[:19], pattern)
            break
        except ValueError:
            continue
    return {'path': urllib.parse.unquote(facts['Path']), 'deleted': deleted}


def _trash_folders(volume, homes):
    """(user, trash folder, top of the volume or None) for every trash."""
    from trace_app.core.activity import _split
    for user, home in homes:
        folder = volume.find(*_split(home.path), '.local', 'share', 'Trash')
        if folder is not None and folder.is_dir:
            yield user, folder, None
    for child in volume.listdir(volume.root):
        if not child.is_dir:
            continue
        name = child.name
        if name.startswith('.Trash-'):
            yield f"uid {name[7:]}", child, '/'
        elif name == '.Trash':
            for sub in volume.children(child, dirs=True):
                yield f"uid {sub.name}", sub, '/'


def trash_activity(volume, homes, step):
    out = []
    for user, folder, top in _trash_folders(volume, homes):
        info = _child(volume, folder, 'info')
        files = _child(volume, folder, 'files')
        present = {entry.name for entry in volume.listdir(files.path)} \
            if files is not None else set()
        for entry in volume.children(info) if info is not None else ():
            if not entry.name.endswith('.trashinfo'):
                continue
            step(entry.path)
            facts = trashinfo(_text(volume, entry))
            if facts is None:
                continue
            original = facts['path']
            if top and not original.startswith('/'):
                original = posixpath.join(top, original)
            name = entry.name[:-len('.trashinfo')]
            out.append(record(
                'recycle', 'Trash', facts['deleted'], 'Moved to Trash',
                original,
                {'trash name': name,
                 'still in Trash': 'yes' if name in present else
                 'no (emptied or restored since)',
                 'trash': folder.path},
                user=user if not user.startswith('uid ') else '',
                path=entry.path, ref=volume.ref(entry), local=True))
    return out


def _child(volume, folder, name):
    for entry in volume.listdir(folder.path):
        if entry.name == name and entry.is_dir:
            return entry
    return None


# --- viminfo -----------------------------------------------------------------------

_HISTORY_KINDS = {0: 'Vim command', 1: 'Vim search', 2: 'Vim expression',
                  3: 'Vim input', 4: 'Vim debug command'}
_HEADINGS = (('# Command Line History', 0), ('# Search String History', 1),
             ('# Expression History', 2), ('# Input Line History', 3),
             ('# Debug Line History', 4))


def _bar_fields(text):
    """The comma-separated values of a `|` line: numbers, or "strings"
    with \\\\ and \\" escaped."""
    out, i = [], 0
    while i < len(text):
        if text[i] == '"':
            i += 1
            value = []
            while i < len(text) and text[i] != '"':
                if text[i] == '\\' and i + 1 < len(text):
                    i += 1
                value.append(text[i])
                i += 1
            out.append(''.join(value))
            i += 2                                    # the quote and comma
        else:
            end = text.find(',', i)
            end = len(text) if end < 0 else end
            out.append(text[i:end])
            i = end + 1
    return out


def _number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _register(number):
    if number is None:
        return '?'
    if number < 10:
        return str(number)
    if number < 36:
        return chr(ord('a') + number - 10)
    return '-' if number == 36 else str(number)


def viminfo(text):
    """[{'kind', 'what', 'value', 'time', 'line'...}] of a .viminfo."""
    out = []
    untimed = []
    heading = None
    for line in text.splitlines():
        if line.startswith('# '):
            heading = next((kind for prefix, kind in _HEADINGS
                            if line.startswith(prefix)), None)
            continue
        if line.startswith('|'):
            fields = _bar_fields(line[1:])
            kind = _number(fields[0]) if fields else None
            if kind == 2 and len(fields) >= 5:            # history
                history = _number(fields[1])
                separator = _number(fields[3])
                value = fields[4]
                if history == 1 and separator:          # '/' or '?'
                    value = chr(separator) + value
                out.append({'kind': _HISTORY_KINDS.get(history,
                                                       'Vim history'),
                            'value': value,
                            'time': times.unix(_number(fields[2]))})
            elif kind == 3 and len(fields) >= 8:          # register
                out.append({'kind': 'Vim register',
                            'value': '\n'.join(f for f in fields[7:] if f),
                            'register': _register(_number(fields[2])),
                            'time': times.unix(_number(fields[6]))})
            elif kind == 4 and len(fields) >= 6:          # mark
                mark = _number(fields[1])
                out.append({'kind': 'Vim jump' if mark == 39 else
                            'Vim file mark', 'value': fields[5],
                            'mark': chr(mark) if mark else None,
                            'line': _number(fields[2]),
                            'column': _number(fields[3]),
                            'time': times.unix(_number(fields[4]))})
            continue
        # Before Vim 8 (or with no `|` lines): ':command', '?/search'.
        if heading in (0, 1) and line[:1] in (':', '?', '/'):
            value = line[1:]
            untimed.append({'kind': _HISTORY_KINDS[heading], 'value': value,
                            'time': None})
    if not any(item['kind'] in ('Vim command', 'Vim search')
               for item in out):
        out = untimed + out
    return out


_VIMINFO_NAMES = (('.viminfo',), ('_viminfo',), ('.vim', 'viminfo'))


def viminfo_activity(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    for parts in _VIMINFO_NAMES:
        entry = volume.find(*_split(home.path), *parts)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        ref = volume.ref(entry)
        for number, item in enumerate(viminfo(_text(volume, entry)), 1):
            kind = item['kind']
            what = {'Vim command': 'Command typed',
                    'Vim search': 'Searched for',
                    'Vim register': 'Text yanked or deleted',
                    'Vim file mark': 'File edited',
                    'Vim jump': 'File edited'}.get(kind, 'Typed')
            out.append(record(
                'files' if kind in ('Vim file mark', 'Vim jump')
                else 'programs', 'viminfo', item['time'], what,
                item['value'],
                {'kind': kind, 'register': item.get('register'),
                 'mark': item.get('mark'), 'line': item.get('line'),
                 'column': item.get('column'), 'entry': number,
                 'basis': None if item['time'] else
                 "Vim wrote no time before version 8; the file was last "
                 f"written {times.iso(entry.modified) or 'at an unknown time'}"},
                user=user, path=entry.path, ref=ref))
    return out


# --- mounts, encrypted volumes, arrays ------------------------------------------------

_NETWORK = {'nfs': 'NFS', 'nfs4': 'NFS', 'cifs': 'SMB', 'smbfs': 'SMB',
            'smb3': 'SMB', 'fuse.sshfs': 'SSHFS', 'sshfs': 'SSHFS',
            'davfs': 'WebDAV', 'fuse.rclone': 'rclone', 'glusterfs':
            'GlusterFS', 'ceph': 'Ceph', 'fuse.s3fs': 'S3'}
#: Options whose value is a secret: named, never copied.
_SECRET_OPTIONS = ('password', 'pass', 'passwd', 'pw')


def fstab(text):
    """[{device, mount, type, options}] of an fstab / mtab."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        device, mount, kind = (field.replace('\\040', ' ')
                               for field in fields[:3])
        options = fields[3] if len(fields) > 3 else ''
        out.append({'device': device, 'mount': mount, 'type': kind,
                    'options': options})
    return out


def _options(options):
    """(options without secrets, {named facts})."""
    kept, facts = [], {}
    for option in options.split(','):
        key, sep, value = option.partition('=')
        lower = key.lower()
        if lower in _SECRET_OPTIONS:
            kept.append(f'{key}=(not copied)')
            facts['password in fstab'] = 'yes (not copied)'
            continue
        if lower in ('credentials', 'cred'):
            facts['credentials file'] = value
        elif lower in ('username', 'user') and sep:
            facts['user name'] = value
        elif lower == 'domain':
            facts['domain'] = value
        kept.append(option)
    return ','.join(kept), facts


def mount_records(volume, step):
    out = []
    for parts, source in ((('etc', 'fstab'), 'fstab'),
                          (('etc', 'mtab'), 'mtab')):
        entry = volume.find(*parts)
        # mtab is a link to /proc/self/mounts on systems since 2012.
        if entry is None or entry.is_dir or getattr(entry, 'is_link', False):
            continue
        step(entry.path)
        ref = volume.ref(entry)
        for mount in fstab(_text(volume, entry)):
            if mount['type'] in ('proc', 'sysfs', 'devpts', 'tmpfs',
                                 'cgroup', 'cgroup2', 'securityfs',
                                 'debugfs', 'mqueue', 'pstore', 'bpf',
                                 'autofs', 'hugetlbfs', 'configfs',
                                 'fusectl', 'tracefs', 'devtmpfs',
                                 'binfmt_misc', 'efivarfs') or \
                    mount['type'] == 'swap' and source == 'mtab':
                continue
            options, facts = _options(mount['options'])
            network = _NETWORK.get(mount['type'].lower())
            if network:
                what = f'Network share ({network})'
                server, share = _share(mount['device'])
                facts.update({'server': server, 'share': share})
            elif mount['type'] == 'swap':
                what = 'Swap configured'
            else:
                what = 'Mounted' if source == 'mtab' else 'Mount configured'
            out.append(record(
                'system', source, entry.modified, what,
                f"{mount['device']} on {mount['mount']}",
                dict(facts, **{'file system': mount['type'],
                               'mount point': mount['mount'],
                               'options': options,
                               'basis': _changed(entry) + (
                                   '; mtab lists what was mounted when it '
                                   'was written' if source == 'mtab'
                                   else '')}),
                path=entry.path, ref=ref))
    entry = volume.find('etc', 'crypttab')
    if entry is not None and not entry.is_dir:
        step(entry.path)
        for line in _text(volume, entry).splitlines():
            fields = line.split()
            if not fields or fields[0].startswith('#') or len(fields) < 2:
                continue
            key = fields[2] if len(fields) > 2 else 'none'
            out.append(record(
                'system', 'crypttab', entry.modified,
                'Encrypted volume configured', f"{fields[0]} <- {fields[1]}",
                {'key': 'asked for at boot' if key in ('none', '-')
                 else f"key file {key} (not read)",
                 'options': fields[3] if len(fields) > 3 else None,
                 'basis': _changed(entry)},
                path=entry.path, ref=volume.ref(entry)))
    for parts in (('etc', 'mdadm.conf'), ('etc', 'mdadm', 'mdadm.conf')):
        entry = volume.find(*parts)
        if entry is None or entry.is_dir:
            continue
        step(entry.path)
        for line in _text(volume, entry).splitlines():
            fields = line.split()
            if not fields or fields[0] != 'ARRAY':
                continue
            facts = dict(field.split('=', 1) for field in fields[2:]
                         if '=' in field)
            out.append(record(
                'system', 'mdadm.conf', entry.modified,
                'RAID array configured',
                fields[1] if len(fields) > 1 else facts.get('UUID', ''),
                {'UUID': facts.get('UUID'), 'name': facts.get('name'),
                 'metadata': facts.get('metadata'),
                 'level': facts.get('level'),
                 'devices': facts.get('num-devices'),
                 'basis': _changed(entry)},
                path=entry.path, ref=volume.ref(entry)))
    return out


def _share(device):
    """(server, share) of '//server/share', 'server:/path', 'user@host:'."""
    if device.startswith('//'):
        server, _sep, share = device[2:].partition('/')
        return server, share
    if ':' in device:
        server, _sep, share = device.partition(':')
        return server.rpartition('@')[2], share
    return None, None


# --- Snap and Flatpak ---------------------------------------------------------------

def _rfc3339(value):
    """snapd's times: RFC 3339 with nanoseconds ('...45.123456789Z')."""
    if not value or value.startswith('0001-'):
        return None
    match = re.match(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?'
                     r'(Z|[+-]\d\d:\d\d)$', value)
    if not match:
        return None
    stamp, fraction, zone = match.groups()
    fraction = (fraction or '.0')[1:7].ljust(6, '0')
    try:
        return datetime.datetime.fromisoformat(
            f"{stamp}.{fraction}{'+00:00' if zone == 'Z' else zone}")
    except ValueError:
        return None


def snap_state(text):
    """(snaps, changes) of snapd's state.json."""
    try:
        state = json.loads(text)
    except ValueError:
        return [], []
    data = state.get('data') or {}
    snaps = []
    for name, snap in sorted((data.get('snaps') or {}).items()):
        current = str(snap.get('current') or '')
        version = None
        for item in snap.get('sequence') or []:
            if str(item.get('revision')) == current:
                version = item.get('version')
        snaps.append({'name': name, 'revision': current,
                      'version': version, 'channel': snap.get('channel'),
                      'type': snap.get('type'),
                      'active': snap.get('active'),
                      'devmode': snap.get('flags', {}).get('devmode')
                      if isinstance(snap.get('flags'), dict) else None})
    changes = []
    for change in (state.get('changes') or {}).values():
        changes.append({'id': change.get('id'),
                        'kind': change.get('kind'),
                        'summary': change.get('summary'),
                        'started': _rfc3339(change.get('spawn-time')),
                        'ready': _rfc3339(change.get('ready-time')),
                        'snaps': (change.get('data') or {}).get(
                            'snap-names')})
    changes.sort(key=lambda c: c['started'] or datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc))
    return snaps, changes


def package_records(volume, homes, step):
    from trace_app.core.activity import _split
    out = []
    entry = volume.find('var', 'lib', 'snapd', 'state.json')
    if entry is not None and not entry.is_dir:
        step(entry.path)
        ref = volume.ref(entry)
        snaps, changes = snap_state(_text(volume, entry))
        for change in changes:
            out.append(record(
                'programs', 'snapd', change['started'],
                f"Snap {(change['kind'] or 'change').replace('-', ' ')}",
                change['summary'] or ', '.join(change['snaps'] or []),
                {'finished': change['ready'],
                 'snaps': ', '.join(change['snaps'] or []),
                 'change': change['id']},
                path=entry.path, ref=ref))
        for snap in snaps:
            out.append(record(
                'programs', 'snapd', None, 'Snap installed', snap['name'],
                {'version': snap['version'], 'revision': snap['revision'],
                 'channel': snap['channel'], 'type': snap['type'],
                 'enabled': None if snap['active'] is None else
                 ('yes' if snap['active'] else 'no'),
                 'basis': 'state.json keeps no install time per snap; see '
                          'its changes'},
                path=entry.path, ref=ref))
    roots = [('', ('var', 'lib', 'flatpak', 'app'))]
    roots += [(user, (*_split(home.path), '.local', 'share', 'flatpak',
                      'app')) for user, home in homes]
    for user, parts in roots:
        folder = volume.find(*parts)
        if folder is None or not folder.is_dir:
            continue
        for app in volume.children(folder, dirs=True):
            step(app.path)
            current = _child(volume, app, 'current')
            when = (current or app).modified
            arches = [arch.name for arch in volume.children(app, dirs=True)
                      if arch.name != 'current']
            out.append(record(
                'programs', 'Flatpak', when, 'Flatpak app installed',
                app.name,
                {'architectures': ', '.join(arches),
                 'installed for': 'this user' if user else 'every user',
                 'basis': "the app folder's last change (an install or "
                          "update)"},
                user=user, path=app.path, ref=volume.ref(app)))
    return out


# --- LibreOffice --------------------------------------------------------------------

_OOR = '{http://openoffice.org/2001/registry}'
_PICK = re.compile(r"HistoryInfo\['PickList'\]/(OrderList|ItemList)/"
                   r"[^\[]*\['(.*?)'\]$")
_PROFILE_ROOTS = (('.config', 'libreoffice'),
                  ('AppData', 'Roaming', 'LibreOffice'),
                  ('Application Data', 'LibreOffice'),
                  ('Library', 'Application Support', 'LibreOffice'))


def libreoffice_recent(data):
    """[{url, title, filter, position, thumbnail, password, pinned}] in
    PickList order."""
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return []
    items, order = {}, {}
    for item in root.iter('item'):
        match = _PICK.search(item.get(_OOR + 'path') or '')
        if not match:
            continue
        kind, key = match.groups()
        props = {}
        for prop in item.iter('prop'):
            value = prop.find('value')
            props[prop.get(_OOR + 'name')] = '' if value is None else \
                (value.text or '')
        if kind == 'OrderList':
            if 'HistoryItemRef' in props and key.isdigit():
                order[int(key)] = props['HistoryItemRef']
        else:
            items.setdefault(key, {}).update(props)
    urls = [order[i] for i in sorted(order)]
    urls += [url for url in items if url not in urls]
    out = []
    for position, url in enumerate(urls):
        props = items.get(url, {})
        out.append({'url': url, 'position': position,
                    'title': props.get('Title') or None,
                    'filter': props.get('Filter') or None,
                    'thumbnail': bool(props.get('Thumbnail')),
                    'password': bool(props.get('Password')),
                    'pinned': props.get('Pinned') == 'true',
                    'read_only': props.get('ReadOnly') == 'true'})
    return out


def _local_path(url):
    if url.startswith('file://'):
        path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
        if re.match(r'^/[A-Za-z]:/', path):
            path = path[1:].replace('/', '\\')
        return path
    return url


def libreoffice_activity(volume, homes, step):
    from trace_app.core.activity import _split
    out = []
    for user, home in homes:
        for parts in _PROFILE_ROOTS:
            root = volume.find(*_split(home.path), *parts)
            if root is None or not root.is_dir:
                continue
            for version in volume.children(root, dirs=True):
                entry = volume.find(*_split(version.path), 'user',
                                    'registrymodifications.xcu')
                if entry is None or entry.is_dir:
                    continue
                step(entry.path)
                ref = volume.ref(entry)
                for item in libreoffice_recent(volume.read(entry)):
                    newest = item['position'] == 0
                    out.append(record(
                        'files', 'LibreOffice', entry.modified if newest
                        else None, 'Recent document (LibreOffice)',
                        _local_path(item['url']),
                        {'title': item['title'], 'filter': item['filter'],
                         'position': item['position'] + 1,
                         'pinned': 'yes' if item['pinned'] else None,
                         'read only': 'yes' if item['read_only'] else None,
                         'thumbnail kept': 'yes' if item['thumbnail']
                         else None,
                         'password remembered': 'yes (not copied)'
                         if item['password'] else None,
                         'basis': _changed(entry) + ' -- the newest only'
                         if newest else 'only the newest has a time'},
                        user=user, path=entry.path, ref=ref))
    return out


# --- everything ---------------------------------------------------------------------

def collect(volume, step, homes):
    """The Linux-only items (called from linux.collect)."""
    out = trash_activity(volume, homes, step)
    out += mount_records(volume, step)
    out += package_records(volume, homes, step)
    return out


def any_system(volume, step, homes):
    """What any system can hold (called from _other_systems): Vim's
    history, LibreOffice's recent documents, web server logs (IIS too)."""
    from trace_app.core.activity import web_logs
    out = []
    for user, home in homes:
        out += viminfo_activity(volume, user, home, step)
    out += libreoffice_activity(volume, homes, step)
    out += web_logs.collect(volume, step)
    return out

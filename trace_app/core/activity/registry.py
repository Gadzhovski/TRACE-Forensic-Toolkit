"""What the registry says a user and a system did.

From a user's NTUSER.DAT: UserAssist (programs started from Explorer, with a
count and the last time), RecentDocs (files and folders opened) and, with
UsrClass.dat, ShellBags (folders viewed in Explorer, including on drives and
shares that are gone). From SYSTEM: the Shimcache (programs Windows saw, in
order, with each file's modification time) and USB storage devices. From
Amcache.hve: programs present or run, with their SHA-1.

Hives are read from bytes with python-registry. Hive transaction logs
(.LOG1/.LOG2) are not replayed, so a hive is read as it was last flushed.
"""

import codecs
import io
import re
import struct

from Registry import Registry

from trace_app.core.activity import shellitems, times

#: Known-folder GUIDs UserAssist and Amcache put in place of a path's start.
FOLDER_PATHS = {
    '{6D809377-6AF0-444B-8957-A3773F02200E}': r'C:\Program Files',
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}': r'C:\Program Files (x86)',
    '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}': r'C:\Program Files\Common Files',
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}': r'C:\Windows\System32',
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}': r'C:\Windows\SysWOW64',
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}': r'C:\Windows',
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}':
        r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs',
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}':
        r'%APPDATA%\Microsoft\Windows\Start Menu\Programs',
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}':
        r'%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned',
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}': r'%USERPROFILE%\Desktop',
    '{374DE290-123F-4565-9164-39C4925E467B}': r'%USERPROFILE%\Downloads',
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}': r'%USERPROFILE%\Documents',
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}': r'%USERPROFILE%',
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}': r'C:\ProgramData',
}

#: UserAssist's two lists: programs, and shortcuts that were followed.
_USERASSIST_KINDS = {
    '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}': 'program',
    '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}': 'shortcut',
    '{75048700-EF1F-11D0-9888-006097DEACF9}': 'program',     # XP
    '{5E6AB780-7743-11CF-A12B-00AA004AE837}': 'Internet Explorer',  # XP
}

_GUID_PREFIX = re.compile(r'^(\{[0-9A-Fa-f-]{36}\})(.*)$')


def open_hive(data):
    return Registry.Registry(io.BytesIO(data))


def _key(hive, path):
    try:
        return hive.open(path)
    except (Registry.RegistryKeyNotFoundException, Exception):
        return None


def _utc(stamp):
    return stamp.replace(tzinfo=times.UTC) if stamp else None


def _value(key, name, default=None):
    try:
        return key.value(name).value()
    except Exception:
        return default


def expand_folder(path):
    match = _GUID_PREFIX.match(path or '')
    if match and match.group(1).upper() in FOLDER_PATHS:
        return FOLDER_PATHS[match.group(1).upper()] + match.group(2)
    return path


# --- NTUSER.DAT ---------------------------------------------------------------

def userassist(hive):
    """[{'name', 'kind', 'run_count', 'focus_count', 'focus_ms', 'last_run'}]"""
    base = _key(hive, 'Software\\Microsoft\\Windows\\CurrentVersion\\'
                      'Explorer\\UserAssist')
    if base is None:
        return []
    out = []
    for list_key in base.subkeys():
        kind = _USERASSIST_KINDS.get(list_key.name().upper(), 'program')
        try:
            count_key = list_key.subkey('Count')
        except Exception:
            continue
        for value in count_key.values():
            name = codecs.decode(value.name(), 'rot_13')
            if name.startswith(('UEME_CTL', 'UEME_RUNPATH:')) and \
                    name.startswith('UEME_CTL'):
                continue            # session counters, not programs
            data = value.raw_data()
            if len(data) >= 72:              # Windows 7 and later
                runs, focus_count, focus_ms = struct.unpack_from('<III',
                                                                 data, 4)
                last = times.filetime(struct.unpack_from('<Q', data, 60)[0])
            elif len(data) == 16:            # XP: counts start at 5
                runs = struct.unpack_from('<I', data, 4)[0]
                runs = runs - 5 if runs >= 5 else runs
                focus_count = focus_ms = None
                last = times.filetime(struct.unpack_from('<Q', data, 8)[0])
            else:
                continue
            for prefix in ('UEME_RUNPATH:', 'UEME_RUNPIDL:', 'UEME_RUNCPL:',
                           'UEME_UITOOLBAR:', 'UEME_UISCUT:'):
                if name.startswith(prefix):
                    name = name[len(prefix):]
            out.append({'name': expand_folder(name), 'raw_name': name,
                        'kind': kind, 'run_count': runs,
                        'focus_count': focus_count, 'focus_ms': focus_ms,
                        'last_run': last})
    return out


def _mru_order(key, name='MRUListEx'):
    try:
        raw = key.value(name).raw_data()
    except Exception:
        return []
    order = []
    for (index,) in struct.iter_unpack('<I', raw[:len(raw) // 4 * 4]):
        if index == 0xFFFFFFFF:
            break
        order.append(index)
    return order


def recent_docs(hive):
    """Files and folders opened: [{'name', 'extension', 'position',
    'opened'}]. The key's last-write time is when its newest item was
    opened, so only that item -- position 0 of each list -- gets a time."""
    base = _key(hive, 'Software\\Microsoft\\Windows\\CurrentVersion\\'
                      'Explorer\\RecentDocs')
    if base is None:
        return []
    newest = {}
    for sub in base.subkeys():
        order = _mru_order(sub)
        if order:
            name = _mru_name(sub, order[0])
            if name:
                newest.setdefault(name, _utc(sub.timestamp()))
    out = []
    order = _mru_order(base)
    for position, index in enumerate(order):
        name = _mru_name(base, index)
        if not name:
            continue
        opened = _utc(base.timestamp()) if position == 0 else newest.get(name)
        extension = name.rsplit('.', 1)[-1].lower() if '.' in name else \
            'folder'
        out.append({'name': name, 'extension': extension,
                    'position': position, 'opened': opened})
    return out


def _mru_name(key, index):
    try:
        raw = key.value(str(index)).raw_data()
    except Exception:
        return ''
    end = 0
    while end + 1 < len(raw) and raw[end:end + 2] != b'\x00\x00':
        end += 2
    return raw[:end].decode('utf-16-le', 'replace')


_BAG_ROOTS = (
    'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',  # UsrClass
    'Software\\Microsoft\\Windows\\Shell\\BagMRU',                  # NTUSER
    'Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU',            # XP
)


def shellbags(hive):
    """Folders a user viewed in Explorer: [{'path', 'updated', 'created',
    'modified', 'accessed', 'mft'}]. A bag's key is rewritten when the
    folder's view or children change, so its last-write time is when the
    folder was last interacted with, as near as the registry records."""
    out = []
    seen = set()
    for root_path in _BAG_ROOTS:
        root = _key(hive, root_path)
        if root is not None:
            _walk_bags(root, [], out, seen, 0)
    return out


def _walk_bags(key, parents, out, seen, depth):
    if depth > 40:
        return
    for value in key.values():
        if not value.name().isdigit():
            continue
        raw = value.raw_data()
        if len(raw) < 3:
            continue
        size = struct.unpack_from('<H', raw, 0)[0]
        item = shellitems.parse_item(raw[2:size] if 2 < size <= len(raw)
                                     else raw[2:])
        chain = parents + [item]
        path = shellitems.join_path(chain)
        try:
            child = key.subkey(value.name())
        except Exception:
            child = None
        if path and path not in seen:
            seen.add(path)
            out.append({
                'path': path,
                'updated': _utc(child.timestamp()) if child else None,
                'created': item.get('created'),
                'modified': item.get('modified'),
                'accessed': item.get('accessed'),
                'mft': (item['mft_entry'], item['mft_sequence'])
                if item.get('mft_entry') else None,
                'kind': item.get('kind'),
            })
        if child is not None:
            _walk_bags(child, chain, out, seen, depth + 1)


# --- SYSTEM ------------------------------------------------------------------------

def current_control_set(hive):
    number = _value(_key(hive, 'Select'), 'Current', 1) \
        if _key(hive, 'Select') is not None else 1
    return f'ControlSet{int(number or 1):03d}'


def shimcache(hive):
    """[{'path', 'modified', 'position', 'executed'}] -- position 0 is the
    most recent. `modified` is the FILE's last-modified time as Windows saw
    it, not when it ran; `executed` is known only on Windows 7 (and Vista)."""
    control = current_control_set(hive)
    key = _key(hive, f'{control}\\Control\\Session Manager\\AppCompatCache') \
        or _key(hive, f'{control}\\Control\\Session Manager\\'
                      'AppCompatibility')
    if key is None:
        return []
    try:
        data = key.value('AppCompatCache').raw_data()
    except Exception:
        return []
    return parse_appcompatcache(data)


def parse_appcompatcache(data):
    if len(data) < 8:
        return []
    signature = struct.unpack_from('<I', data, 0)[0]
    if signature == 0xDEADBEEF:
        return _shim_xp(data)
    if signature in (0xBADC0FEE, 0xBADC0FFE):
        return _shim_win7(data, vista=signature == 0xBADC0FFE)
    if signature in (0x30, 0x34) and data[signature:signature + 4] == b'10ts':
        return _shim_win10(data, signature)
    if len(data) > 0x84 and data[0x80:0x84] in (b'00ts', b'10ts'):
        return _shim_win8(data)
    return []


def _shim_win10(data, start):
    out = []
    at = start
    while at + 12 <= len(data) and data[at:at + 4] == b'10ts':
        entry_size = struct.unpack_from('<I', data, at + 8)[0]
        body = data[at + 12:at + 12 + entry_size]
        path_size = struct.unpack_from('<H', body, 0)[0]
        path = body[2:2 + path_size].decode('utf-16-le', 'replace')
        modified = struct.unpack_from('<Q', body, 2 + path_size)[0]
        out.append({'path': path, 'modified': times.filetime(modified),
                    'position': len(out), 'executed': None})
        at += 12 + entry_size
    return out


def _shim_win8(data):
    out = []
    at = 0x80
    while at + 12 <= len(data) and data[at:at + 4] in (b'00ts', b'10ts'):
        win81 = data[at:at + 4] == b'10ts'
        entry_size = struct.unpack_from('<I', data, at + 8)[0]
        body = data[at + 12:at + 12 + entry_size]
        path_size = struct.unpack_from('<H', body, 0)[0]
        path = body[2:2 + path_size].decode('utf-16-le', 'replace')
        cursor = 2 + path_size
        if win81:
            package_size = struct.unpack_from('<H', body, cursor)[0]
            cursor += 2 + package_size
        insert_flags = struct.unpack_from('<I', body, cursor)[0]
        modified = struct.unpack_from('<Q', body, cursor + 8)[0]
        out.append({'path': path, 'modified': times.filetime(modified),
                    'position': len(out),
                    'executed': bool(insert_flags & 2)})
        at += 12 + entry_size
    return out


def _shim_win7(data, vista):
    count = struct.unpack_from('<I', data, 4)[0]
    header = 8 if vista else 128
    # 32- or 64-bit layout: the first entry's path offset must point inside.
    layouts = ([(24, '<HHIQII'), (32, '<HHIQQII')] if vista else
               [(48, '<HH4xQQIIQQ'), (32, '<HHIQIIII')])
    for size, _form in layouts:
        if header + size * count > len(data):
            continue
        out = []
        valid = True
        for index in range(min(count, 4096)):
            at = header + index * size
            length = struct.unpack_from('<H', data, at)[0]
            if size == 48:
                offset, modified, insert_flags = struct.unpack_from(
                    '<QQI', data, at + 8)
            elif vista and size == 32:
                offset, modified, insert_flags = struct.unpack_from(
                    '<QQI', data, at + 8)
            else:
                offset, modified, insert_flags = struct.unpack_from(
                    '<IQI', data, at + 4)
            if offset + length > len(data) or length % 2:
                valid = False
                break
            path = data[offset:offset + length].decode('utf-16-le', 'replace')
            out.append({'path': path, 'modified': times.filetime(modified),
                        'position': index,
                        'executed': bool(insert_flags & 2)})
        if valid and out and all(p['path'] for p in out[:5]):
            return out
    return []


def _shim_xp(data):
    count = struct.unpack_from('<I', data, 4)[0]
    out = []
    for index in range(min(count, 96)):
        at = 400 + index * 552
        if at + 552 > len(data):
            break
        path = data[at:at + 528].decode('utf-16-le', 'replace').split(
            '\x00', 1)[0]
        modified, _size, updated = struct.unpack_from('<QQQ', data, at + 528)
        if path:
            out.append({'path': path, 'modified': times.filetime(modified),
                        'position': index, 'executed': None,
                        'updated': times.filetime(updated)})
    return out


_DEVICE_PROPERTIES = '{83da6326-97a6-4088-9453-a1923f573b29}'


def usb_devices(hive):
    """USB storage devices: [{'device', 'serial', 'name', 'vendor',
    'product', 'first', 'installed', 'last_connected', 'last_removed',
    'drive', 'key_updated'}]."""
    control = current_control_set(hive)
    base = _key(hive, f'{control}\\Enum\\USBSTOR')
    if base is None:
        return []
    letters = _mounted_letters(hive)
    connected = _interface_times(hive, control)
    out = []
    for device in base.subkeys():
        parts = dict(part.split('_', 1) for part in device.name().split('&')
                     if '_' in part)
        for instance in device.subkeys():
            serial = instance.name()
            record = {
                'device': device.name(),
                'serial': serial,
                'name': _value(instance, 'FriendlyName', '') or '',
                'vendor': parts.get('Ven', ''),
                'product': parts.get('Prod', ''),
                'revision': parts.get('Rev', ''),
                'key_updated': _utc(instance.timestamp()),
            }
            # Device properties: 0x64 first install, 0x65 last install,
            # 0x66 last arrival, 0x67 last removal (the last two from
            # Windows 8).
            for code, field in ((0x64, 'first_installed'),
                                (0x65, 'last_installed'),
                                (0x66, 'last_connected'),
                                (0x67, 'last_removed')):
                record[field] = _property_time(instance, code)
            # Windows 7 keeps no arrival time; the device interface key is
            # rewritten when the device is connected.
            record['interface_updated'] = connected.get(
                (device.name().upper(), serial.upper()))
            record['drive'] = letters.get(serial.split('&')[0].upper(), '')
            out.append(record)
    return out


def _interface_times(hive, control):
    """(device, serial) -> last write of its disk interface key."""
    key = _key(hive, f'{control}\\Control\\DeviceClasses\\'
                     '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}')
    out = {}
    if key is None:
        return out
    for sub in key.subkeys():
        # ##?#USBSTOR#<device>#<serial>#{interface class}
        pieces = sub.name().split('#')
        if 'USBSTOR' in (p.upper() for p in pieces):
            at = [p.upper() for p in pieces].index('USBSTOR')
            if len(pieces) > at + 2:
                out[(pieces[at + 1].upper(), pieces[at + 2].upper())] = \
                    _utc(sub.timestamp())
    return out


def _property_time(instance, code):
    """A FILETIME device property. Stored as Properties\\{guid}\\<code>,
    the code written as 4 or 8 hex digits, the value in the key itself or
    (Windows 7) in its 00000000 subkey as Data."""
    try:
        group = instance.subkey('Properties')
    except Exception:
        return None
    for guid_key in group.subkeys():
        if guid_key.name().lower() != _DEVICE_PROPERTIES:
            continue
        for sub in guid_key.subkeys():
            try:
                if int(sub.name(), 16) != code:
                    continue
            except ValueError:
                continue
            for holder in [sub] + list(sub.subkeys()):
                for value in holder.values():
                    raw = value.raw_data()
                    if value.name().lower() in ('', 'data') and len(raw) >= 8:
                        return times.filetime(
                            struct.unpack_from('<Q', raw, 0)[0])
    return None


def _mounted_letters(hive):
    """Device serial -> drive letter, from MountedDevices."""
    key = _key(hive, 'MountedDevices')
    if key is None:
        return {}
    letters = {}
    for value in key.values():
        name = value.name()
        if not name.startswith('\\DosDevices\\'):
            continue
        raw = value.raw_data()
        try:
            text = raw.decode('utf-16-le')
        except UnicodeDecodeError:
            continue
        if 'USBSTOR#' not in text.upper():
            continue
        pieces = text.split('#')
        if len(pieces) >= 3:
            letters[pieces[2].split('&')[0].upper()] = name[-2:]
    return letters


# --- Amcache.hve -------------------------------------------------------------

def amcache(hive):
    """Programs recorded by the Application Experience service:
    [{'path', 'sha1', 'name', 'publisher', 'version', 'recorded',
    'modified', 'linked'}]. `recorded` is the entry's key last-write time --
    when Windows recorded the program, near when it first ran or was
    installed; the SHA-1 identifies the exact binary."""
    out = []
    files = _key(hive, 'Root\\InventoryApplicationFile')
    if files is not None:                        # Windows 10 1709+
        for entry in files.subkeys():
            file_id = _value(entry, 'FileId', '') or ''
            out.append({
                'path': _value(entry, 'LowerCaseLongPath', '') or '',
                'sha1': file_id[4:] if file_id.startswith('0000') else file_id,
                'name': _value(entry, 'Name', '') or '',
                'publisher': _value(entry, 'Publisher', '') or '',
                'version': _value(entry, 'Version', '') or '',
                'linked': _value(entry, 'LinkDate', '') or '',
                'size': _value(entry, 'Size'),
                'recorded': _utc(entry.timestamp()),
                'modified': None,
            })
    volumes = _key(hive, 'Root\\File')
    if volumes is not None:                      # Windows 8 to 10 1607
        for volume in volumes.subkeys():
            for entry in volume.subkeys():
                sha1 = _value(entry, '101', '') or ''
                modified = _value(entry, '17')
                out.append({
                    'path': _value(entry, '15', '') or '',
                    'sha1': sha1[4:] if sha1.startswith('0000') else sha1,
                    'name': _value(entry, '0', '') or '',
                    'publisher': _value(entry, '1', '') or '',
                    'version': _value(entry, '6', '') or '',
                    'linked': '',
                    'size': _value(entry, '6'),
                    'recorded': _utc(entry.timestamp()),
                    'modified': times.filetime(modified)
                    if isinstance(modified, int) else None,
                })
    return [entry for entry in out if entry['path']]

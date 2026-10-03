"""Shell items: how Explorer records a path, one element at a time.

The same structure appears in a shortcut's target ID list, in ShellBags and
in RecentDocs. Each item names one step -- My Computer, C:\\, Users, a file --
and a file-entry item also carries the file's times (as DOS dates, to two
seconds, local time) and, from Windows 7, its MFT entry and sequence.

Parsing is best effort and never raises: an item this reader does not know is
shown by its type, so the rest of the path is still read.
"""

import struct



#: Root folder GUIDs Explorer puts at the start of a path.
KNOWN_FOLDERS = {
    '20D04FE0-3AEA-1069-A2D8-08002B30309D': 'My Computer',
    '871C5380-42A0-1069-A2EA-08002B30309D': 'Internet Explorer',
    '450D8FBA-AD25-11D0-98A8-0800361B1103': 'My Documents',
    '208D2C60-3AEA-1069-A2D7-08002B30309D': 'My Network Places',
    'F02C1A0D-BE21-4350-88B0-7367FC96EF3C': 'Network',
    '59031A47-3F72-44A7-89C5-5595FE6B30EE': 'User folder',
    '645FF040-5081-101B-9F08-00AA002F954E': 'Recycle Bin',
    '21EC2020-3AEA-1069-A2DD-08002B30309D': 'Control Panel',
    '26EE0668-A00A-44D7-9371-BEB064C98683': 'Control Panel',
    '031E4825-7B94-4DC3-B131-E946B44C8DD5': 'Libraries',
    '22877A6D-37A1-461A-91B0-DBDA5AAEBC99': 'Recent Places',
    '679F85CB-0220-4080-B29B-5540CC05AAB6': 'Quick Access',
    '374DE290-123F-4565-9164-39C4925E467B': 'Downloads',
    'B4BFCC3A-DB2C-424C-B029-7FE99A87C641': 'Desktop',
    'F3364BA0-65B9-11CE-A9BA-00AA004AE837': 'Shell File System Folder',
    '018D5C66-4533-4307-9B53-224DE2ED1FE6': 'OneDrive',
    '04731B67-D933-450A-90E6-4ACD2E9408FE': 'Search Folder',
    '9E3995AB-1F9C-4F13-B827-48B24B6C7174': 'User Pinned',
    '1CF1260C-4DD0-4EBB-811F-33C572699FDE': 'Music',
    '3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA': 'Pictures',
    'A0953C92-50DC-43BF-BE83-3742FED03C9C': 'Videos',
    'D3162B92-9365-467A-956B-92703ACA08AF': 'Documents',
    '088E3905-0323-4B02-9826-5D99428E115F': 'Downloads',
    '24AD3AD4-A569-4530-98E1-AB02F9417AA8': 'Pictures',
    'F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A': 'Videos',
    '3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE': 'Music',
}


#: The class of a "delegate" shell item, which wraps another folder's GUID.
_DELEGATE_FOLDER = '5E591A74-DF96-48D3-8D67-1733BCEE28BA'
_DELEGATE_BYTES = bytes.fromhex('741a595e96dfd3488d671733bcee28ba')

#: Control Panel categories (shell item 0x01) and common items (0x71).
_CPL_CATEGORIES = {
    0: 'All Control Panel Items', 1: 'Appearance and Personalization',
    2: 'Hardware and Sound', 3: 'Network and Internet',
    4: 'Sounds, Speech, and Audio Devices', 5: 'System and Security',
    6: 'Clock, Language, and Region', 7: 'Ease of Access', 8: 'Programs',
    9: 'User Accounts', 10: 'Security Center', 11: 'Mobile PC',
}
_CPL_ITEMS = {
    'ED834ED6-4B5A-4BFE-8F11-A626DCB6A921': 'Personalization',
    'BB06C0E4-D293-4F75-8A90-CB05B6477EEE': 'System',
    '7B81BE6A-CE2B-4676-A29E-EB907A5126C5': 'Programs and Features',
    '60632754-C523-4B62-B45C-4172DA012619': 'User Accounts',
    '8E908FC9-BECC-40F6-915B-F4CA0E70D03D': 'Network and Sharing Center',
    'A8A91A66-3A7D-4424-8D24-04E180695C7A': 'Devices and Printers',
    'D555645E-D4F8-4C29-A827-D93C859C4F2A': 'Ease of Access Center',
    '9C60DE1E-E5FC-40F4-A487-460851A8D915': 'AutoPlay',
    'BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6': 'Action Center',
    '025A5937-A6BE-4686-A844-36FE4BEC8B6D': 'Power Options',
    'E2E7934B-DCE5-43C4-9576-7FE4F75E7480': 'Date and Time',
    'D20EA4E1-3957-11D2-A40B-0C5020524153': 'Administrative Tools',
    '78F3955E-3B90-4184-BD14-5397C15F1EFC': 'Performance Information',
    '17CD9488-1228-4B2F-88CE-4298E93E0966': 'Default Programs',
    '4026492F-2F69-46B8-B9BF-5654FC07E423': 'Windows Firewall',
}


def guid(data, at=0):
    """The GUID at `at`, in registry form (upper case, no braces)."""
    if len(data) < at + 16:
        return ''
    a, b, c = struct.unpack_from('<IHH', data, at)
    tail = data[at + 8:at + 16].hex().upper()
    return f'{a:08X}-{b:04X}-{c:04X}-{tail[:4]}-{tail[4:]}'


def dos_datetime(value):
    """A FAT date and time as shell items store it -- the date in the low
    word, the time in the high -- local time, no zone."""
    import datetime
    date, time_ = value & 0xFFFF, value >> 16
    if not date:
        return None
    try:
        return datetime.datetime(1980 + (date >> 9), (date >> 5) & 15,
                                 date & 31, time_ >> 11, (time_ >> 5) & 63,
                                 (time_ & 31) * 2)
    except ValueError:
        return None


def _cstring(data, at, unicode=False):
    if unicode:
        end = at
        while end + 1 < len(data) and data[end:end + 2] != b'\x00\x00':
            end += 2
        return data[at:end].decode('utf-16-le', 'replace'), end + 2
    end = data.find(b'\x00', at)
    end = len(data) if end == -1 else end
    return data[at:end].decode('cp1252', 'replace'), end + 1


def _beef0004(data, at):
    """The extension block that follows a file entry's short name: the long
    name, created and accessed times, and (Windows 7+) the MFT reference."""
    out = {}
    if at + 20 > len(data):
        return out
    size, version, signature = struct.unpack_from('<HHI', data, at)
    if signature != 0xBEEF0004 or at + size > len(data):
        return out
    block = data[at:at + size]
    out['created'] = dos_datetime(struct.unpack_from('<I', block, 8)[0])
    out['accessed'] = dos_datetime(struct.unpack_from('<I', block, 12)[0])
    name_at = 46 if version >= 9 else 42 if version == 8 else \
        38 if version == 7 else 20
    if version >= 7 and len(block) >= 28:
        reference = struct.unpack_from('<Q', block, 20)[0]
        entry, sequence = reference & 0xFFFFFFFFFFFF, reference >> 48
        if entry:
            out['mft_entry'], out['mft_sequence'] = entry, sequence
    if name_at < len(block):
        name, _ = _cstring(block, name_at, unicode=True)
        if name and name.isprintable():
            out['long_name'] = name
    return out


def parse_item(item):
    """One shell item (without its size field): {'name', 'kind', ...}."""
    if not item:
        return {'name': '', 'kind': 'empty'}
    kind = item[0]
    base = kind & 0x70
    try:
        if kind == 0x1F:                            # root folder
            folder = guid(item, 2)
            return {'name': KNOWN_FOLDERS.get(folder, '{' + folder + '}'),
                    'kind': 'root', 'guid': folder}
        if kind == 0x2E:                            # known folder or device
            folder = guid(item, 2)
            delegate = item.find(_DELEGATE_BYTES)
            if folder not in KNOWN_FOLDERS and delegate != -1 and \
                    len(item) >= delegate + 32:
                # A delegate item: the delegate's class, then the folder
                # (where depends on the Windows version that wrote it).
                folder = guid(item, delegate + 16)
            return {'name': KNOWN_FOLDERS.get(folder, '{' + folder + '}'),
                    'kind': 'known folder', 'guid': folder}
        if base == 0x20:                            # volume: "C:\"
            letter = item[1:4].split(b'\x00', 1)[0]
            if len(letter) >= 2 and letter[1:2] == b':' and \
                    chr(letter[0]).isalpha():
                return {'name': letter[:2].decode('ascii') + '\\',
                        'kind': 'volume'}
            return {'name': '', 'kind': 'volume'}
        if kind == 0x01 and len(item) >= 10:        # Control Panel category
            category = struct.unpack_from('<I', item, 6)[0]
            return {'name': _CPL_CATEGORIES.get(category,
                                                f'Category {category}'),
                    'kind': 'control panel'}
        if kind == 0x71 and len(item) >= 28:        # Control Panel item
            item_guid = guid(item, 12)
            return {'name': _CPL_ITEMS.get(item_guid, '{' + item_guid + '}'),
                    'kind': 'control panel'}
        if base == 0x30:                            # file or folder
            size, modified, attributes = struct.unpack_from('<IIH', item, 2)
            unicode = bool(kind & 0x04)
            short, end = _cstring(item, 12, unicode=unicode)
            if end % 2:
                end += 1
            out = {'name': short, 'kind': 'folder' if kind & 0x01
                   else 'file', 'size': size,
                   'modified': dos_datetime(modified)}
            extension = _beef0004(item, end - 2)
            if not extension:
                # The block is found by its signature where alignment varies.
                found = item.find(b'\x04\x00\xef\xbe', end - 2)
                if found >= 4:
                    extension = _beef0004(item, found - 4)
            if extension.get('long_name'):
                out['name'] = extension.pop('long_name')
            out.update(extension)
            return out
        if base == 0x40:                            # network location
            name, _ = _cstring(item, 3)
            return {'name': name, 'kind': 'network'}
        if kind == 0x61:                            # URI
            # The URL is stored as UTF-16 or, in older items, as ASCII.
            for marker, codec in ((b'h\x00t\x00t\x00p\x00', 'utf-16-le'),
                                  (b'f\x00t\x00p\x00', 'utf-16-le'),
                                  (b'http', 'ascii')):
                at = item.find(marker)
                if at == -1:
                    continue
                if codec == 'ascii':
                    end = item.find(b'\x00', at)
                    raw = item[at:end if end != -1 else len(item)]
                    return {'name': raw.decode('ascii', 'replace'),
                            'kind': 'uri'}
                name, _ = _cstring(item, at, unicode=True)
                return {'name': name, 'kind': 'uri'}
            return {'name': 'URI', 'kind': 'uri'}
        if kind == 0x74:                            # delegate (Users files)
            inner = item.find(b'\x31', 4)
            if inner != -1:
                return parse_item(item[inner:])
        if kind == 0x00 and len(item) > 8:
            # Variable items (zip folders, MTP devices, property stores):
            # best effort on the longest readable UTF-16 string. One with
            # none is a container that adds nothing to the path.
            text = _first_utf16(item)
            return {'name': text, 'kind': 'other'}
    except (struct.error, IndexError):
        pass
    return {'name': f'[shell item {kind:#04x}]', 'kind': 'unknown'}


def _first_utf16(data):
    best = ''
    at = 0
    while at + 1 < len(data):
        if 32 <= data[at] < 127 and data[at + 1] == 0:
            end = at
            while end + 1 < len(data) and 32 <= data[end] < 127 \
                    and data[end + 1] == 0:
                end += 2
            text = data[at:end].decode('utf-16-le')
            if len(text) > len(best):
                best = text
            at = end
        at += 2
    return best if len(best) >= 3 else ''


def parse_id_list(data, at=0):
    """A sequence of shell items ending in a zero size: [item dicts]."""
    items = []
    while at + 2 <= len(data):
        size = struct.unpack_from('<H', data, at)[0]
        if size < 2 or at + size > len(data):
            break
        items.append(parse_item(data[at + 2:at + size]))
        at += size
    return items


def join_path(items):
    """Shell items as a readable path: C:\\Users\\Ann\\Desktop\\file.txt."""
    parts = []
    for item in items:
        name = item.get('name') or ''
        if item.get('kind') == 'root' and parts:
            continue
        if item.get('kind') in ('volume', 'uri', 'network') and name:
            # A drive, a share or a URL starts the path; what came before is
            # the namespace it sits in (My Computer, Network, Internet
            # Explorer).
            parts = [name.rstrip('\\') if item['kind'] == 'volume' else name]
            continue
        if name:
            parts.append(name)
    path = '\\'.join(parts)
    if len(parts) == 1 and path.endswith(':'):
        path += '\\'
    return path


def iso_local(value):
    """A naive local datetime as text, marked as having no zone."""
    return value.strftime('%Y-%m-%d %H:%M:%S') if value else None


__all__ = ['parse_item', 'parse_id_list', 'join_path', 'guid',
           'dos_datetime', 'KNOWN_FOLDERS', 'iso_local']

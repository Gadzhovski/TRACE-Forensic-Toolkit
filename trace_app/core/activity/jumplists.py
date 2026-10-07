"""Jump Lists: the per-application recent and pinned items of Windows 7+.

*.automaticDestinations-ms is an OLE compound file: one shortcut stream per
item, named by its entry number in hex, and a DestList stream that indexes
them with each item's last access time, access count and pin state.
*.customDestinations-ms is shortcuts written one after another. The file
name's first part is the AppID -- which application the list belongs to.
"""

import io
import struct

import olefile

from trace_app.core.activity import lnk, times

#: Well-known AppIDs. The rest are shown by their ID, which examiners look up.
APP_IDS = {
    '1b4dd67f29cb1962': 'Windows Explorer',
    'f01b4d95cf55d32a': 'Windows Explorer (8.1+)',
    '5f7b5f1e01b83767': 'Quick Access',
    '9b9cdc69c1c24e2b': 'Notepad (64-bit)',
    'a7bd71699cd38d1c': 'Notepad',
    '12dc1ea8e34b5a6': 'Microsoft Paint',
    '7e4dca80246863e3': 'Control Panel',
    'a4a5324453625195': 'Microsoft Word 2010',
    'fb3b0dbfee58fac8': 'Microsoft Word 365',
    'cfb56c56fa0f0478': 'Microsoft PowerPoint 2016',
    'f5ac5390b9115fdb': 'Microsoft PowerPoint 2013',
    'b8ab77100df80ab2': 'Microsoft Excel 365',
    '9839aec31243a928': 'Microsoft Excel 2010',
    'd00655d2aa12ff6d': 'Microsoft PowerPoint 2010',
    '5d6f13ed567aa2da': 'Microsoft Office Outlook 2010',
    '9d1f905ce5044aee': 'Microsoft Edge',
    '5c450709f7ae4396': 'Firefox',
    '28c8b86deab549a1': 'Internet Explorer 8 / 9 / 10',
    '6824f4a902c78fbd': 'Firefox 64-bit',
    'a52b0784bd667fc4': 'Remote Desktop Connection',
    '1bc392b8e104a00e': 'Remote Desktop',
    'b74736c2bd8cc8a5': 'WinZip',
    '290532160612e071': 'WinRAR',
    '9c32e3ab4f0b4c4a': '7-Zip',
    '74d7f43c1561fc1e': 'Windows Media Player 12',
    'be71009ff8bb02a2': 'Microsoft Office Outlook',
    'c7a4093872176c74': 'Paint Shop Pro',
    'e2a593822e01aed3': 'Adobe Flash CS5',
    '2b53c4ddf69195fc': 'Zune',
    'ee462c3b81abb6f6': 'Adobe Reader X',
    '23646679aaccfae0': 'Adobe Reader 9',
    'de48a32edcbe79e4': 'Acrobat Reader DC',
    '7a7c60efd66817a2': 'Spotify',
    '6d2bac8f1edf6668': 'Microsoft Outlook 2013',
    '9fda41b86ddcf1db': 'VLC media player',
}


def app_name(file_name):
    app_id = file_name.split('.', 1)[0].lower()
    return app_id, APP_IDS.get(app_id, '')


def parse_automatic(data):
    """[{'path', 'accessed', 'pinned', 'access_count', 'host', 'lnk'}]"""
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, ValueError, struct.error) as exc:
        raise ValueError(f"not an OLE compound file: {exc}") from exc
    try:
        entries = []
        if ole.exists('DestList'):
            entries = _destlist(ole.openstream('DestList').read())
        streams = {name[0].lower(): name[0] for name in ole.listdir()
                   if len(name) == 1 and name[0] != 'DestList'}
        for entry in entries:
            stream = streams.get(f"{entry['number']:x}")
            if stream is not None:
                try:
                    entry['lnk'] = lnk.parse(ole.openstream(stream).read())
                except (lnk.LnkError, OSError):
                    pass
        if not entries:
            # No index (or an unreadable one): the shortcuts alone.
            for stream in streams.values():
                try:
                    shortcut = lnk.parse(ole.openstream(stream).read())
                except (lnk.LnkError, OSError):
                    continue
                entries.append({'path': shortcut.get('target', ''),
                                'accessed': None, 'lnk': shortcut})
        return entries
    finally:
        ole.close()


def _destlist(data):
    if len(data) < 32:
        return []
    version, count = struct.unpack_from('<II', data, 0)
    entries = []
    at = 32
    for _ in range(min(count, 10000)):
        if at + 114 > len(data):
            break
        host = data[at + 72:at + 88].split(b'\x00', 1)[0].decode(
            'ascii', 'replace')
        number = struct.unpack_from('<I', data, at + 88)[0]
        accessed = times.filetime(struct.unpack_from('<Q', data, at + 100)[0])
        pin = struct.unpack_from('<i', data, at + 108)[0]
        if version >= 3:
            access_count = struct.unpack_from('<I', data, at + 116)[0]
            length_at, tail = 128, 4
        else:
            access_count = None
            length_at, tail = 112, 0
        length = struct.unpack_from('<H', data, at + length_at)[0]
        path_at = at + length_at + 2
        path = data[path_at:path_at + 2 * length].decode('utf-16-le',
                                                         'replace')
        entries.append({'number': number, 'host': host, 'path': path,
                        'accessed': accessed, 'pinned': pin >= 0,
                        'access_count': access_count})
        at = path_at + 2 * length + tail
    return entries


def parse_custom(data):
    """The shortcuts in a customDestinations-ms file."""
    out = []
    at = data.find(lnk.HEADER)
    while at != -1:
        following = data.find(lnk.HEADER, at + 20)
        chunk = data[at:following if following != -1 else len(data)]
        try:
            shortcut = lnk.parse(chunk)
            out.append({'path': shortcut.get('target', ''), 'accessed': None,
                        'lnk': shortcut})
        except lnk.LnkError:
            pass
        at = following
    return out

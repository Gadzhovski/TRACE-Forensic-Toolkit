"""setupapi.dev.log (Vista and later) and setupapi.log (XP): device installs.

The first time Windows sees a USB device it installs a driver for it and
logs the section with a start time -- the device's first connection, often
the only record of it once the registry has been cleaned. The times are the
machine's local time, with no zone in the file, and are kept as such.
"""

import datetime
import re

_HEADER = re.compile(r'^>>>\s+\[Device Install[^\]]*?-\s*(?P<device>[^\]]+)\]')
_START = re.compile(r'^>>>\s+Section start\s+(?P<when>\d{4}/\d{2}/\d{2} '
                    r'\d{2}:\d{2}:\d{2})')
# XP: [2008/03/12 10:15:03 1234.5] ... Driver Install ... USBSTOR\...
_XP = re.compile(r'^\[(?P<when>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})[^\]]*\]'
                 r'.*?(?P<device>(?:USBSTOR|USB)\\[^\s"\]]+)')

#: The device classes that are removable storage or how it is reached.
_STORAGE = ('USBSTOR\\', 'USB\\VID_', 'WPDBUSENUM', 'SWD\\WPDBUSENUM',
            'STORAGE\\VOLUME', 'SCSI\\DISK')


def parse(text):
    """[{'device', 'installed'}] -- `installed` is a naive local datetime."""
    out = []
    pending = None
    for line in text.splitlines():
        header = _HEADER.match(line)
        if header:
            pending = header.group('device').strip()
            continue
        start = _START.match(line)
        if start and pending:
            if pending.upper().startswith(_STORAGE):
                out.append({'device': pending,
                            'installed': _when(start.group('when'))})
            pending = None
            continue
        xp = _XP.match(line)
        if xp:
            out.append({'device': xp.group('device'),
                        'installed': _when(xp.group('when'))})
    seen, unique = set(), []
    for entry in out:                 # XP repeats a device per log line
        key = (entry['device'].upper(), entry['installed'])
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def _when(text):
    try:
        return datetime.datetime.strptime(text, '%Y/%m/%d %H:%M:%S')
    except ValueError:
        return None


def describe(device):
    """(kind, vendor, product, serial) from a device instance path."""
    parts = device.split('\\')
    serial = parts[2] if len(parts) > 2 else ''
    fields = dict(p.split('_', 1) for p in parts[1].split('&') if '_' in p) \
        if len(parts) > 1 else {}
    return (parts[0].upper(), fields.get('Ven') or fields.get('VID', ''),
            fields.get('Prod') or fields.get('PID', ''), serial)

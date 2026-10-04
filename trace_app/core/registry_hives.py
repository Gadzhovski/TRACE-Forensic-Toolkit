"""The registry hives a piece of evidence holds, found and read for the
Registry browser (no Qt).

Found on every volume (and, in a triage collection, under each system
root), case-insensitively -- XP writes WINDOWS\\system32\\config\\software:

* the system hives in <Windows>\\System32\\config -- SYSTEM, SOFTWARE, SAM,
  SECURITY, DEFAULT, COMPONENTS, DRIVERS -- and the older copies Windows
  kept in config\\RegBack;
* Amcache.hve (Windows\\AppCompat\\Programs);
* each user's NTUSER.DAT and UsrClass.dat (Vista+ AppData\\Local\\
  Microsoft\\Windows, XP Local Settings\\Application Data\\...);
* the boot configuration (Boot\\BCD, EFI\\Microsoft\\Boot\\BCD).

Only files that start with 'regf' are offered. A hive is read in memory
with its transaction logs replayed (core/regf_log.py); nothing is written
to disk.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger('TRACE.RegistryHives')

SYSTEM_HIVES = ('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT',
                'COMPONENTS', 'DRIVERS')
_USRCLASS = (('AppData', 'Local', 'Microsoft', 'Windows', 'UsrClass.dat'),
             ('Local Settings', 'Application Data', 'Microsoft', 'Windows',
              'UsrClass.dat'))
_BCD = (('Boot', 'BCD'), ('EFI', 'Microsoft', 'Boot', 'BCD'))


@dataclass
class Hive:
    """One hive file on the evidence."""
    name: str             # 'SOFTWARE', 'NTUSER.DAT', 'SOFTWARE (RegBack)'
    kind: str             # 'system', 'user', 'amcache', 'regback', 'boot'
    offset: int           # the volume's start (or volume key)
    path: str             # its path on that volume
    inode: int
    seq: object = None
    size: int = 0
    user: str = ''
    volume: str = ''      # set when the evidence has more than one volume
    facts: dict = field(default_factory=dict)

    @property
    def label(self):
        """'NTUSER.DAT -- jdoe', with the volume when there are several."""
        text = self.name + (f" — {self.user}" if self.user else '')
        return text + (f"  [{self.volume}]" if self.volume else '')


def _volume_names(image_handler, offsets):
    """{offset: 'Volume 2 (NTFS, sector 63)'} for labels."""
    partitions = {start: desc for _addr, desc, start, _len in
                  image_handler.get_partitions()}
    names = {}
    for number, offset in enumerate(offsets, 1):
        desc = (partitions.get(offset) or '').strip()
        try:
            fs_type = image_handler.get_fs_type(offset)
        except Exception:
            fs_type = ''
        inner = ', '.join(p for p in (fs_type or desc, f"sector {offset}"
                                      if offset < 2 ** 48 else '') if p)
        names[offset] = f"Volume {number}" + (f" ({inner})" if inner else '')
    return names


def _is_hive(image_handler, volume, entry):
    if entry is None or entry.is_dir or not entry.size:
        return False
    try:
        head = image_handler.read_file_bytes(entry.inode, volume.offset, 4)
    except Exception:
        return False
    return head == b'regf'


def find_hives(image_handler, should_stop=None):
    """Every hive on the evidence: [Hive], system hives first, then users,
    then the rest, volume by volume."""
    from trace_app.core.activity import Volume, _profiles
    found = []
    try:
        offsets = list(image_handler.volume_offsets())
    except Exception as exc:
        logger.debug("No volumes: %s", exc)
        return []
    for offset in offsets:
        try:
            volumes = Volume.all(image_handler, offset)
        except Exception as exc:
            logger.debug("Volume at %s unreadable: %s", offset, exc)
            continue
        for volume in volumes:
            if should_stop and should_stop():
                return found
            found += _hives_on(image_handler, volume, _profiles)
    with_hives = sorted({h.offset for h in found})
    if len(with_hives) > 1:
        names = _volume_names(image_handler, with_hives)
        for hive in found:
            hive.volume = names.get(hive.offset, '')
    return found


def _hives_on(image_handler, volume, profiles):
    out = []

    def add(entry, name, kind, user=''):
        if _is_hive(image_handler, volume, entry):
            out.append(Hive(name=name, kind=kind, offset=volume.offset,
                            path=entry.path, inode=entry.inode,
                            seq=entry.seq, size=entry.size, user=user))

    windows = volume.find('Windows') or volume.find('WINNT')
    if windows is not None and windows.is_dir:
        config = volume.find(windows.name, 'System32', 'config')
        for name in SYSTEM_HIVES:
            add(volume.find(windows.name, 'System32', 'config', name)
                if config else None, name, 'system')
        add(volume.find(windows.name, 'AppCompat', 'Programs',
                        'Amcache.hve'), 'Amcache.hve', 'amcache')
    for user, home in profiles(volume):
        add(volume.find(*_parts(home.path), 'NTUSER.DAT'), 'NTUSER.DAT',
            'user', user)
        for parts in _USRCLASS:
            entry = volume.find(*_parts(home.path), *parts)
            if entry is not None:
                add(entry, 'UsrClass.dat', 'user', user)
                break
    if windows is not None and windows.is_dir:
        for name in SYSTEM_HIVES:
            add(volume.find(windows.name, 'System32', 'config', 'RegBack',
                            name), f"{name} (RegBack)", 'regback')
    for parts in _BCD:
        add(volume.find(*parts), 'BCD', 'boot')
    return out


def _parts(path):
    return [p for p in path.split('/') if p]


def read_hive(image_handler, hive):
    """(hive bytes with its transaction logs applied, recovery facts)."""
    from trace_app.core import regf_log
    from trace_app.core.activity import Volume
    content, _meta = image_handler.get_file_content(hive.inode, hive.offset)
    data = bytes(content or b'')
    facts = {}
    if data[:4] == b'regf' and regf_log.is_dirty(data):
        volume = Volume(image_handler, hive.offset)
        parts = _parts(hive.path)
        logs = []
        for suffix in ('.LOG1', '.LOG2', '.LOG'):
            log = volume.find(*parts[:-1], parts[-1] + suffix)
            if log is not None and not log.is_dir and log.size:
                body, _meta = image_handler.get_file_content(log.inode,
                                                             hive.offset)
                if body:
                    logs.append((log.name, bytes(body)))
        data, facts = regf_log.recover(data, logs)
    return data, facts

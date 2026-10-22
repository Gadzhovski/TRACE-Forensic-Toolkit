"""What an image holds, and which analysis modules can find anything in it
(no Qt).

A case can hold a Windows laptop, a Fedora server and a phone backup at
once; every module used to run on every image, so the NTFS job read a
Btrfs disk and found nothing, and the dialog offered it as if it might.
`profile(handler)` says what the image is -- file systems, the systems
installed on it, logical or a disk -- from what TRACE already opened, and
`not_applicable(profile)` names the modules that cannot produce anything
there, each with the reason the dialog shows.

Only what is certain is ruled out. A module that searches the whole image
by name (thumbnail caches, event logs for Sigma, YARA, keywords) can find
something on any file system, and on a disk image is never ruled out;
logical evidence (a folder, a zip, an extraction) has every file name in
memory already, so there it is ruled out when none of the files it reads
is there (`present_files`). An image with a volume TRACE cannot read
(locked, damaged) rules nothing out, because what it holds is unknown.
"""

import logging

logger = logging.getLogger('TRACE.EvidenceProfile')

#: File systems The Sleuth Kit reads, whose deleted entries it lists.
_TSK_FILE_SYSTEMS = ('NTFS', 'FAT12', 'FAT16', 'FAT32', 'ExFAT', 'Ext2',
                     'Ext3', 'Ext4', 'HFS', 'HFS+', 'HFSX', 'ISO9660',
                     'UFS1', 'UFS2', 'YAFFS2',
                     # Not TSK: its deleted files come from the older
                     # leaves copy-on-write leaves (core/btrfs_recover).
                     'Btrfs')


#: What a volume TRACE cannot read yet is, as the summary says it.
_UNREAD = {'bitlocker': 'a locked BitLocker volume',
           'fvde': 'a locked FileVault 2 volume',
           'luks': 'a locked LUKS volume',
           'apfs': 'a locked APFS volume',
           'ios_backup': 'a locked (encrypted) iOS backup',
           'android_backup': 'a locked (encrypted) Android backup',
           'mdraid': 'a RAID member whose other disks are not here'}


#: The kinds of evidence external modules suit (spec.suits), as a reason
#: names them. Phones and computers TRACE finds itself; a warrant return
#: and a car's extraction are found by the tool's own patterns
#: (core/modules/fit, `PATTERN_KINDS`).
KIND_NAMES = {'ios': 'iOS (iPhone or iPad)', 'android': 'Android',
              'windows': 'Windows', 'macos': 'macOS', 'linux': 'Linux',
              'chromeos': 'ChromeOS',
              'return': 'warrant return', 'vehicle': 'vehicle'}
#: Kinds no system shows: a tool reading one fits where its patterns name
#: files (`module_fit`).
PATTERN_KINDS = ('return', 'vehicle')
#: In tool_systems when TRACE cannot tell what the evidence is -- no system
#: found and no single pattern-fitted kind (a return's zip, a car's export:
#: both fitting is no answer), a volume it cannot read (locked, damaged),
#: or not worked out yet: then no tool is ruled out (`tool_reason`).
#: Ruling one out on a guess hid the right one: a Linux disk whose
#: os-release was not found was offered RLEAPP and VLEAPP for one stray
#: file each, and DLEAPP not at all.
UNKNOWN = 'unknown'
#: Systems os_identity names that a tool can suit.
_SYSTEM_KINDS = ('ios', 'android', 'windows', 'macos', 'linux', 'chromeos')
#: On evidence TRACE knows for a phone or a computer, a pattern-fitted tool
#: needs this many files its patterns name: a few are that system's own
#: files (a Pixel 3: RLEAPP's patterns took 6 Gmail screenshot attachments,
#: VLEAPP's 4 Android crash tombstones). A return or a car's dump on its
#: own, with no system found, needs one.
MIN_FIT_ON_SYSTEM = 20
#: File systems TRACE cannot open yet whose signature says what the image
#: is from: a QNX head unit is a car's. A tool reading the image itself
#: (`-t raw`, core/modules/inputs.RAW) is offered for them.
RAW_ONLY = {'QNX6': 'vehicle', 'QNX4': 'vehicle', 'QNX IFS': 'vehicle'}
#: File systems TRACE reads that mark an image as a car's: a QNX6 volume
#: TRACE opens is still a head unit's, for VLEAPP.
VEHICLE_FILESYSTEMS = ('QNX6', 'QNX4', 'QNX IFS', 'QNX ETFS', 'QNX EFS')


def unreadable_signatures(image_handler):
    """[(volume start, file system)] the image's signatures name that
    TRACE does not open (RAW_ONLY): a QNX6 volume of a head unit."""
    if image_handler.logical_fs is not None:
        return []
    found = []
    try:
        starts = [p[2] for p in image_handler.get_partitions()] or [0]
    except Exception:
        starts = [0]
    for start in dict.fromkeys(starts):
        try:
            names = image_handler.detect_filesystems(start)
            if not names or image_handler.get_fs_info(start) is not None:
                continue
        except Exception:
            continue
        found += [(start, name) for name in names if name in RAW_ONLY]
    return found


def tool_systems(image_handler, read=True):
    """The kinds of evidence an image holds for external tools: phones
    ('ios' / 'android': a backup's kind, what os_identity found -- installed
    or packed in a tar or zipped backup inside a folder -- or a phone's
    user data, as a partial extraction has no SystemVersion.plist or
    build.prop), computers ('windows' / 'macos' / 'linux' / 'chromeos':
    os_identity, else the system's own folders), a QNX head unit
    ('vehicle'), and the kinds the tools' own patterns found (`module_fit`:
    'return', 'vehicle'). UNKNOWN among them when TRACE cannot tell (see
    UNKNOWN). Worked out once per handler (ImageHandler forgets it when a
    volume is unlocked); read=False never reads (the window's thread: the
    image's opening worked it out), and before that answers UNKNOWN."""
    known = image_handler.__dict__.get('_tool_systems')
    if known is None:
        known = _certain_kinds(image_handler, read)
        if read:
            image_handler.__dict__['_tool_systems'] = known
    found, complete = known
    fitted = [kind for kind in fitted_kinds(image_handler, found)
              if kind not in found]
    decided = any(kind in _SYSTEM_KINDS or kind == 'vehicle'
                  for kind in found) or \
        len(fitted) == 1    # a return, or a car's export, and nothing else
    return list(found) + fitted + ([] if decided and complete
                                   else [UNKNOWN])


def _certain_kinds(image_handler, read):
    """(kinds TRACE itself finds on the image -- no pattern counts --,
    complete): complete is False when part of it could not be read or
    nothing was read (read=False)."""
    from trace_app.core import logical_sources, os_identity
    found, unread = [], False
    try:
        kind = logical_sources.kind_of(image_handler.image_path) or ''
    except Exception:
        kind = ''
    if kind == 'ios_backup':
        found.append('ios')
    elif kind == 'android_backup':
        found.append('android')
    look = os_identity.identify if read else os_identity.cached
    try:
        keys = list(image_handler.volume_offsets())
        named = set()
        for key in keys:
            family = (look(image_handler, key) or {}).get('family')
            if family in _SYSTEM_KINDS:
                found.append(family)
                named.add(key)
        if read:
            phones = _phone_data(image_handler, keys)
            for key, kinds in phones.items():
                found += kinds
            found += _phone_paths(image_handler)
            # A volume nothing named and holding no phone: the system's own
            # folders, as the module profile finds them (a live USB's
            # overlay has /etc and /home but no os-release).
            found += _desktop_systems(
                image_handler, [k for k in keys
                                if k not in named and not phones.get(k)])
            found += [RAW_ONLY[name] for _start, name in
                      unreadable_signatures(image_handler)]
            for key in keys:
                try:
                    if image_handler.get_fs_type(key) in \
                            VEHICLE_FILESYSTEMS:
                        found.append('vehicle')
                except Exception:
                    continue
            unread = has_unread_volume(image_handler)
    except Exception as exc:
        logger.debug("No systems for %s: %s", image_handler.image_path, exc)
        unread = True
    return list(dict.fromkeys(found)), read and not unread


def set_module_fit(image_handler, fit):
    """Keep what core/modules/fit counted on an image: {tool id: files}."""
    image_handler.__dict__['_module_fit'] = dict(fit)


def module_fit(image_handler):
    """{tool id: files its patterns name}, or None before it is counted."""
    return image_handler.__dict__.get('_module_fit')


def fit_needed(systems):
    """Files a pattern-fitted tool must find on evidence holding `systems`
    (MIN_FIT_ON_SYSTEM where a phone or computer was found)."""
    return MIN_FIT_ON_SYSTEM if set(systems or ()) & set(_SYSTEM_KINDS) \
        else 1


def fitted_kinds(image_handler, systems=()):
    """The kinds the tools' own patterns found on the image -- enough of
    them for what else it is (fit_needed)."""
    from trace_app.core.modules.spec import TOOLS
    fit = module_fit(image_handler) or {}
    needed = fit_needed(systems)
    return list(dict.fromkeys(
        kind for tool, files in fit.items()
        if (files or 0) >= needed and tool in TOOLS
        for kind in TOOLS[tool].suits if kind in PATTERN_KINDS))


def _phone_data(image_handler, keys):
    """{volume key: ['ios' / 'android']} where a volume's system root holds
    a phone's user data (activity/mobile's own tests for it, and iOS's data
    partition on its own: mobile/ and containers/ at its top)."""
    from trace_app.core.activity import Volume, mobile
    found = {}
    for key in keys:
        if image_handler.get_fs_info(key) is None:
            continue
        for volume in Volume.all(image_handler, key):
            try:
                if mobile.is_ios(volume) or any(
                        volume.find(*parts) is not None
                        for parts in _IOS_DATA_PARTITION):
                    found.setdefault(key, []).append('ios')
                if mobile.android_base(volume) is not None:
                    found.setdefault(key, []).append('android')
            except Exception as exc:
                logger.debug("Phone check at %s failed: %s", key, exc)
    return found


#: Paths only iOS's data partition (/private/var) has at its top, for an
#: image or folder of that partition alone.
_IOS_DATA_PARTITION = (('mobile', 'Library', 'SMS'),
                       ('mobile', 'Containers', 'Data', 'Application'),
                       ('containers', 'Shared', 'SystemGroup'))
#: Folders only a phone has, anywhere in logical evidence ('/' around each
#: name, lower case). An extraction tool puts the phone's partitions under
#: folders of its own ('filesystem2/mobile/Library/SMS', iLEAPP's own test
#: data), where no system root is found. iOS's need 'mobile/library': a
#: Mac has Library/SMS-like folders under Users/<name> only.
_IOS_FOLDERS = ('/mobile/library/sms/', '/mobile/library/callhistorydb/',
                '/mobile/library/addressbook/',
                '/mobile/containers/data/application/',
                '/containers/shared/systemgroup/',
                '/mobile/library/preferences/com.apple.')
_ANDROID_FOLDERS = ('/data/data/com.android.', '/data/user/0/com.android.',
                    '/data/user_de/0/com.android.',
                    '/com.android.providers.telephony/',
                    '/com.android.providers.contacts/')


def _phone_paths(image_handler):
    """'ios' / 'android' for logical evidence whose folders only a phone
    has, at any depth (its names are in memory: no read). [] for a disk
    image -- `_phone_data` looks at its volumes' roots."""
    fs = image_handler.logical_fs
    if fs is None:
        return []
    found, seen = [], set()
    try:
        rows = fs.file_rows()
    except Exception as exc:
        logger.debug("No file rows for %s: %s", image_handler.image_path,
                     exc)
        return []
    for folder, _name, _size in rows:
        if folder in seen:
            continue
        seen.add(folder)
        text = folder.lower().replace('\\', '/').rstrip('/') + '/'
        if 'ios' not in found and '/users/' not in text and any(
                part in text for part in _IOS_FOLDERS):
            found.append('ios')
        if 'android' not in found and any(
                part in text for part in _ANDROID_FOLDERS):
            found.append('android')
        if len(found) == 2:
            break
    return found


def _desktop_systems(image_handler, keys):
    """'windows' / 'linux' / 'macos' / 'chromeos' by the system's own
    folders on the volumes at `keys` -- the module profile's test, for
    systems os_identity could not name."""
    from trace_app.core.activity import Volume, chromeos, linux, macos
    found = []
    for key in keys:
        if image_handler.get_fs_info(key) is None:
            continue
        try:
            volumes = Volume.all(image_handler, key)
        except Exception as exc:
            logger.debug("No system roots at %s: %s", key, exc)
            continue
        for volume in volumes:
            try:
                if chromeos.is_chromeos(volume):
                    found.append('chromeos')
                elif volume.find('Windows') or volume.find('WINNT'):
                    found.append('windows')
                elif macos.is_macos(volume):
                    found.append('macos')
                elif linux.is_linux(volume):
                    found.append('linux')
            except Exception as exc:
                logger.debug("System check at %s failed: %s", key, exc)
    return found


#: Volume kinds whose contents are unknown until unlocked or assembled.
_LOCKED_KINDS = ('bitlocker', 'fvde', 'luks', 'apfs', 'ios_backup',
                 'android_backup', 'mdraid')


def has_unread_volume(image_handler):
    """Whether part of the image is a volume TRACE cannot read -- locked,
    a RAID member alone, a file system it does not open -- so what the
    image holds is not known in full."""
    from trace_app.core import containers
    starts = [p[2] for p in image_handler.get_partitions()] or [0]
    for start in dict.fromkeys(starts):
        try:
            kind = image_handler.volume_kind(start)
            if kind == 'bitlocker' and not image_handler.is_unlocked(start):
                return True
            if kind == 'apfs' and any(
                    v['locked'] for v in image_handler.apfs_volumes(start)):
                return True
        except Exception as exc:
            logger.debug("Container check at %s failed: %s", start, exc)
    for key in image_handler.volume_offsets():
        if image_handler.get_fs_info(key) is not None:
            continue
        try:
            kind = image_handler.volume_kind(key) \
                if key < containers.SHADOW_KEY_BASE else None
        except Exception:
            kind = None
        if kind in _LOCKED_KINDS:
            return True
        try:
            if image_handler.detect_filesystems(key):
                return True
        except Exception:
            continue
    return False


def tool_suits(suits, systems):
    """Whether a tool suiting `suits` (spec.suits) may run on evidence
    holding `systems` (tool_systems): a tool for anything, a kind found,
    or TRACE cannot tell (UNKNOWN)."""
    return not suits or UNKNOWN in (systems or ()) or \
        bool(set(suits) & set(systems or ()))


def tool_reason(spec, systems):
    """Why an external tool (core/modules/spec) cannot run on an image
    holding `systems` (tool_systems), or None when it can."""
    if tool_suits(spec.suits, systems):
        return None
    if set(spec.suits) <= set(PATTERN_KINDS):
        return (f"{spec.name} reads {spec.reads or 'its own evidence'}: "
                f"none of the files it reads was found on this image (or "
                f"the image is still being listed).")
    wanted = ' or '.join(KIND_NAMES.get(s, s) for s in spec.suits)
    there = ' and '.join(KIND_NAMES.get(s, s) for s in systems)
    return (f"{spec.name} reads {wanted} evidence; "
            + (f"this image holds {there}." if systems else
               f"no {wanted} system was found on this image."))


def present_files(image_handler):
    """For logical evidence, which files the name-searching modules read
    are among its files: {'event_logs', 'thumbnail_caches'} -> bool. None
    for a disk image (listing it is a walk of the whole image: unknown)."""
    fs = image_handler.logical_fs
    if fs is None:
        return None
    from trace_app.core.rdpcache import is_rdp_cache_name
    from trace_app.core.thumbnails import is_cache_name
    found = {'event_logs': False, 'thumbnail_caches': False}
    for name in fs.file_names():
        if not found['event_logs'] and name.lower().endswith('.evtx'):
            found['event_logs'] = True
        if not found['thumbnail_caches'] and (
                is_cache_name(name) or is_rdp_cache_name(name)):
            found['thumbnail_caches'] = True
        if all(found.values()):
            break
    return found


def profile(image_handler):
    """{'filesystems', 'systems', 'tool_systems', 'logical',
    'logical_kind', 'present', 'unreadable', 'summary'} for an open
    image."""
    from trace_app.core import containers
    from trace_app.core.activity import Volume, chromeos, linux, macos
    filesystems, systems, unreadable = [], [], False
    #: Why some of it is not read, in words: 'a locked LUKS volume'.
    why = []
    logical = image_handler.logical_fs is not None
    # Locked containers first: a locked BitLocker To Go drive opens as its
    # FAT32 decoy, and a locked APFS volume is not among the volumes read.
    starts = [p[2] for p in image_handler.get_partitions()] or [0]
    for start in dict.fromkeys(starts):
        try:
            kind = image_handler.volume_kind(start)
            if kind == 'bitlocker' and not image_handler.is_unlocked(start):
                unreadable = True
                why.append('a locked BitLocker volume')
            elif kind == 'apfs' and any(
                    v['locked'] for v in image_handler.apfs_volumes(start)):
                unreadable = True
                why.append('a locked APFS volume')
        except Exception as exc:
            logger.debug("Container check at %s failed: %s", start, exc)
    for key in image_handler.volume_offsets():
        try:
            kind = image_handler.volume_kind(key) \
                if key < containers.SHADOW_KEY_BASE else None
        except Exception:
            kind = None
        fs = image_handler.get_fs_info(key)
        if fs is None:
            if kind in ('bitlocker', 'fvde', 'luks', 'apfs', 'ios_backup',
                        'android_backup', 'mdraid'):
                unreadable = True           # locked: what is inside is unknown
                why.append(_UNREAD[kind])
            elif image_handler.detect_filesystems(key):
                unreadable = True           # a file system TRACE cannot open
            continue
        name = image_handler.get_fs_type(key) or 'Unknown'
        filesystems.append(name)
        try:
            volumes = Volume.all(image_handler, key)
        except Exception as exc:
            logger.debug("No system roots at %s: %s", key, exc)
            volumes = []
        for volume in volumes:
            try:
                if volume.find('Windows') or volume.find('WINNT'):
                    systems.append('Windows')
                if linux.is_linux(volume):
                    systems.append('Linux')
                if macos.is_macos(volume):
                    systems.append('macOS')
                if chromeos.is_chromeos(volume):
                    systems.append('ChromeOS')
            except Exception as exc:
                logger.debug("System check at %s failed: %s", key, exc)
    systems = list(dict.fromkeys(systems))
    parts = []
    table = _table(image_handler)
    if table:
        parts.append(table)
    if filesystems:
        parts.append(', '.join(dict.fromkeys(filesystems)))
    if systems:
        parts.append(' + '.join(systems))
    if why:
        parts.append(', '.join(dict.fromkeys(why)))
    elif unreadable:
        parts.append('a volume TRACE cannot read')
    logical_kind = None
    if logical:
        from trace_app.core import logical_sources
        try:
            logical_kind = logical_sources.kind_of(image_handler.image_path)
        except Exception:
            logical_kind = None
    try:
        present = present_files(image_handler)
    except Exception as exc:
        logger.debug("Files present not known: %s", exc)
        present = None
    return {'filesystems': filesystems, 'systems': systems,
            'tool_systems': tool_systems(image_handler),
            'fit': module_fit(image_handler),
            'logical': logical, 'logical_kind': logical_kind,
            'present': present, 'unreadable': unreadable,
            'summary': ' · '.join(parts) or 'No file system found'}


def _table(image_handler):
    try:
        for _addr, description, _start, _length in \
                image_handler.get_partitions():
            text = description.decode('utf-8', 'replace') \
                if isinstance(description, bytes) else str(description)
            if 'GPT' in text or 'Safety Table' in text:
                return 'GPT'
            if 'Primary Table' in text:
                return 'MBR'
    except Exception:
        pass
    return ''


def not_applicable(found):
    """{module key: why it cannot find anything in this image}."""
    out = {}
    if found['unreadable']:
        return out
    # External tools read one kind of phone: iLEAPP on an Android
    # extraction finds nothing (and stages copies for nothing).
    from trace_app.core.modules.spec import TOOLS
    systems = found.get('tool_systems', ())
    fit = found.get('fit') or {}
    for spec in TOOLS.values():
        why = tool_reason(spec, systems)
        files = fit.get(spec.id) or 0
        if why and files and set(spec.suits) <= set(PATTERN_KINDS):
            # Some matched, too few for evidence that is something else.
            what = ' and '.join(KIND_NAMES.get(s, s) for s in systems
                                if s in _SYSTEM_KINDS)
            why = (f"{spec.name} reads {spec.reads or 'its own evidence'}: "
                   f"only {files} file(s) its patterns name were found, on "
                   f"{what} evidence -- that system's own files, not "
                   f"{' or '.join(KIND_NAMES.get(s, s) for s in spec.suits)}"
                   f" evidence (it takes {MIN_FIT_ON_SYSTEM}).")
        if why:
            out[spec.id] = why
    filesystems = found['filesystems']
    if not filesystems:
        reason = "No file system TRACE can read on this image."
        for key in ('ntfs', 'fstimes', 'deleted', 'persistence', 'activity'):
            out[key] = reason
        return out
    if 'NTFS' not in filesystems:
        out['ntfs'] = "No NTFS volume on this image."
    if all(name == 'NTFS' for name in filesystems):
        out['fstimes'] = ("Its only file system is NTFS, whose times the "
                          "NTFS module reads.")
    if not any(name in _TSK_FILE_SYSTEMS for name in filesystems):
        out['deleted'] = (f"{', '.join(dict.fromkeys(filesystems))}: "
                          f"TRACE does not list deleted entries there yet "
                          f"(carving still finds deleted data).")
    if not found['systems']:
        out['persistence'] = ("No Windows, Linux or macOS installation on "
                              "this image.")
    if found['logical']:
        out['carve'] = ("Logical evidence holds files, not disk space: "
                        "there is nothing between them to carve.")
        out['index_free'] = ("Logical evidence holds files, not disk "
                             "space: it has no free space to search.")
    if found.get('logical_kind') == 'folder':
        out['fstimes'] = ("A folder of copied files: their file-system "
                          "times are the copies', not the device's.")
    present = found.get('present')
    if present is not None:
        if not present.get('event_logs'):
            out['sigma'] = ("No Windows event log (.evtx) among its files: "
                            "Sigma rules read those.")
        if not present.get('thumbnail_caches'):
            out['thumbnails'] = ("No thumbnail cache among its files "
                                 "(thumbcache_*.db, Thumbs.db, RDP bitmap "
                                 "caches).")
    return out

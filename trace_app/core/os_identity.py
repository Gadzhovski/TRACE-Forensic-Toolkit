"""Which operating system a volume holds, as a family, a name and a logo
(no Qt).

`ImageHandler.get_os_info` reads the details the Evidence Information dialog
lists (SOFTWARE's CurrentVersion, os-release, SystemVersion.plist). This
names the system from them -- and from where that reader does not look: a
system root that is not the volume's top (Fedora's Btrfs keeps it in the
'root' subvolume, a collection in its 'C' folder), and Android's
build.prop -- so the tree and the dialog can show the system's logo.

`identify(handler, key)` -> {'family', 'logo', 'name', 'detail'} or None:

* family: 'windows', 'macos', 'ios', 'linux', 'android', 'chromeos',
  'freebsd', 'openbsd'
* logo: a key of `LOGOS` -- the distribution's own where there is one
  ('fedora', 'ubuntu', ...), else the family's
* name: 'Windows 11 Pro', 'Fedora Linux 44 (Workstation Edition)'
* detail: release and build, for a tooltip ('23H2, build 22631')

Windows 11 still writes "Windows 10" in ProductName; the build number
(22000 and up) is what tells them apart, as Microsoft documents.
"""

import logging
import re

logger = logging.getLogger('TRACE.OSIdentity')

#: First Windows 11 build (21H2). ProductName stays "Windows 10 ...".
WINDOWS_11_BUILD = 22000

#: Distributions with a logo of their own, by os-release ID (and the
#: words their names use), most specific first: Kubuntu before Ubuntu.
DISTRIBUTIONS = (
    ('kubuntu', ('kubuntu',)), ('xubuntu', ('xubuntu',)),
    ('popos', ('pop!_os', 'pop', 'pop-os')), ('elementary', ('elementary',)),
    ('zorin', ('zorin',)), ('linuxmint', ('linuxmint', 'linux mint', 'mint')),
    ('ubuntu', ('ubuntu',)), ('kalilinux', ('kali',)),
    ('raspberrypi', ('raspbian', 'raspberry pi')), ('debian', ('debian',)),
    ('fedora', ('fedora',)), ('centos', ('centos',)),
    ('rockylinux', ('rocky',)), ('almalinux', ('almalinux', 'alma')),
    ('redhat', ('rhel', 'red hat')), ('opensuse', ('opensuse',)),
    ('suse', ('sles', 'suse')), ('manjaro', ('manjaro',)),
    ('archlinux', ('arch',)), ('gentoo', ('gentoo',)),
    ('alpinelinux', ('alpine',)), ('nixos', ('nixos',)),
)

#: Every logo there is, so a caller can check a key.
LOGOS = ('windows', 'macos', 'apple', 'android', 'linux', 'freebsd',
         'openbsd', 'chromeos') + tuple(key for key, _words in DISTRIBUTIONS)


def _family_of(name):
    """(family, logo) for an operating system's name, or None."""
    lower = name.lower()
    if lower.startswith('windows') or 'microsoft windows' in lower:
        return 'windows', 'windows'
    if lower.startswith(('macos', 'mac os', 'os x')):
        return 'macos', 'macos'
    # An iPhone's SystemVersion.plist says 'iPhone OS'; an iPad's 'iPhone
    # OS' or 'iPadOS'. Not macOS, which every Apple name used to read as.
    if lower.startswith(('iphone os', 'ios', 'ipados', 'ipad os')):
        return 'ios', 'apple'
    if lower.startswith('android'):
        return 'android', 'android'
    # ChromeOS's os-release says 'Chrome OS' (Flex: 'ChromeOS Flex'),
    # Chromium OS builds 'Chromium OS'.
    if re.match(r'chrom(e|ium) ?os\b', lower):
        return 'chromeos', 'chromeos'
    if 'freebsd' in lower:
        return 'freebsd', 'freebsd'
    if 'openbsd' in lower:
        return 'openbsd', 'openbsd'
    return None


def distribution(os_id='', name=''):
    """The logo key for a Linux distribution, from os-release's ID (and
    ID_LIKE's first word) or its name; 'linux' when none is known."""
    ids = [w.lower() for w in re.split(r'[\s,]+', os_id or '') if w]
    # In order: ID before ID_LIKE -- RHEL is "like fedora", Kali "like
    # debian", and each is itself first.
    for word in ids:
        for key, words in DISTRIBUTIONS:
            if word == key or word in words:
                return key
    lower = (name or '').lower()
    for key, words in DISTRIBUTIONS:
        if any(re.search(r'(^|[^a-z])' + re.escape(w) + r'($|[^a-z])',
                         lower) for w in words):
            return key
    return 'linux'


def _windows(info):
    name = info.get('Operating System', '')
    build = info.get('Build', '')
    try:
        if int(build) >= WINDOWS_11_BUILD and 'Windows 10' in name:
            name = name.replace('Windows 10', 'Windows 11')
    except ValueError:
        pass
    detail = ', '.join(p for p in (info.get('Release', ''),
                                   f"build {build}" if build else '') if p)
    return {'family': 'windows', 'logo': 'windows', 'name': name,
            'detail': detail}


def from_os_info(info):
    """An identity from get_os_info's fields, or None."""
    name = (info or {}).get('Operating System', '')
    if not name:
        return None
    family = _family_of(name)
    if family and family[0] == 'windows':
        return _windows(info)
    detail = ', '.join(p for p in (
        f"build {info['Build']}" if info.get('Build') else '',) if p)
    if family:
        return {'family': family[0], 'logo': family[1], 'name': name,
                'detail': detail}
    return {'family': 'linux', 'logo': distribution(info.get('ID', ''), name),
            'name': name, 'detail': detail}


def _os_release(text):
    values = {}
    for line in text.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, _, value = line.partition('=')
            values[key.strip()] = value.strip().strip('"\'')
    name = values.get('PRETTY_NAME') or ' '.join(
        p for p in (values.get('NAME'), values.get('VERSION')) if p)
    if not name:
        return None
    os_id = ' '.join(p for p in (values.get('ID', ''),
                                 values.get('ID_LIKE', '')) if p)
    if values.get('ID') in ('chromeos', 'chromiumos'):
        family = ('chromeos', 'chromeos')
    else:
        family = _family_of(name)
    if family and family[0] == 'chromeos':
        return {'family': 'chromeos', 'logo': 'chromeos', 'name': name,
                'detail': (f"build {values['BUILD_ID']}"
                           if values.get('BUILD_ID') else '')}
    return {'family': 'linux', 'logo': distribution(os_id, name),
            'name': name, 'detail': (f"build {values['BUILD_ID']}"
                                     if values.get('BUILD_ID') else '')}


def _lsb_release(text):
    """ChromeOS's /etc/lsb-release (CHROMEOS_RELEASE_*); a plain Linux
    one is left to os-release."""
    values = dict(re.findall(r'^(\w+)=(.*)$', text, re.M))
    version = values.get('CHROMEOS_RELEASE_VERSION', '').strip()
    if not version:
        return None
    name = values.get('CHROMEOS_RELEASE_NAME', 'ChromeOS').strip()
    milestone = values.get('CHROMEOS_RELEASE_CHROME_MILESTONE', '').strip()
    detail = ', '.join(p for p in (
        f"Chrome {milestone}" if milestone else '',
        f"platform {version}",
        f"board {values['CHROMEOS_RELEASE_BOARD'].strip()}"
        if values.get('CHROMEOS_RELEASE_BOARD') else '',
        values.get('CHROMEOS_RELEASE_TRACK', '').strip()) if p)
    return {'family': 'chromeos', 'logo': 'chromeos',
            'name': f"{name} {milestone or version}".strip(),
            'detail': detail}


def _build_prop(text):
    props = dict(re.findall(r'^([\w.]+)=(.*)$', text, re.M))
    release = props.get('ro.build.version.release', '').strip()
    if not release and 'ro.build.fingerprint' not in props:
        return None
    device = ' '.join(props[p].strip() for p in (
        'ro.product.manufacturer', 'ro.product.model') if props.get(p))
    return {'family': 'android', 'logo': 'android',
            'name': f"Android {release}".strip(),
            'detail': ', '.join(p for p in (
                device, f"build {props['ro.build.id'].strip()}"
                if props.get('ro.build.id') else '') if p)}


def _system_version(text):
    pairs = dict(re.findall(r'<key>(.*?)</key>\s*<string>(.*?)</string>',
                            text, re.S))
    name = pairs.get('ProductName', '').strip()
    if not name:
        return None
    version = (pairs.get('ProductUserVisibleVersion')
               or pairs.get('ProductVersion') or '').strip()
    full = f"{name} {version}".strip()
    family = _family_of(full) or ('macos', 'macos')
    return {'family': family[0], 'logo': family[1], 'name': full,
            'detail': (f"build {pairs['ProductBuildVersion'].strip()}"
                       if pairs.get('ProductBuildVersion') else '')}


def _backup_info(text):
    """An iTunes/Finder backup's Info.plist: the device and its iOS. Each
    key read on its own -- the file lists every installed app (often past
    the 64 KB read), and nests dictionaries a general key/string pattern
    runs across."""
    pairs = {}
    for key in ('Product Version', 'Device Name', 'Product Type',
                'Build Version'):
        match = re.search(r'<key>' + re.escape(key) +
                          r'</key>\s*<string>([^<]*)</string>', text)
        if match:
            pairs[key] = match.group(1)
    version = (pairs.get('Product Version') or '').strip()
    if not version:
        return None
    return {'family': 'ios', 'logo': 'apple', 'name': f"iOS {version}",
            'detail': ', '.join(p for p in (
                (pairs.get('Device Name') or '').strip(),
                (pairs.get('Product Type') or '').strip(),
                f"build {pairs['Build Version'].strip()}"
                if pairs.get('Build Version') else '') if p)}


#: MobileGestalt's answers are cached under hashed key names (the MD5 of
#: the question, salted, in base64) -- the same on every iPhone and iPad.
_GESTALT = {'qNNddlUK+B/YlooNoymwgA': 'version',
            'mZfUC7qo4pURNhyMHZ62RQ': 'build',
            'ivIu8YTDnBSrYv/SN4G8Ag': 'name',
            'Z/dqyWS6OZTRy10UcmUAhw': 'marketing',
            'h9jDsbgj7xIVeIQ8S3/X3Q': 'type'}


def _apple_plist(text):
    import plistlib
    try:
        value = plistlib.loads(text.encode('utf-8'))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _ios_answer(name, version, build, device=''):
    """An iOS identity from /private/var, where an extraction holding only
    the data partition (GrayKey's, a Cellebrite FFS) keeps the version."""
    family = _family_of(name or 'iOS')
    if not version or family is None or family[0] != 'ios':
        return None
    return {'family': 'ios', 'logo': 'apple', 'name': f"iOS {version}",
            'detail': ', '.join(p for p in (
                device, f"build {build}" if build else '') if p)}


def _mobile_gestalt(text):
    """MobileGestalt's cache: the iOS the device runs now (CacheVersion is
    the build it was written by; the cache is rebuilt after an update)."""
    plist = _apple_plist(text)
    extra = plist.get('CacheExtra')
    if not isinstance(extra, dict):
        return None
    answers = {field: str(extra[key]).strip() for key, field
               in _GESTALT.items() if isinstance(extra.get(key), str)}
    device = ' '.join(p for p in (
        answers.get('marketing', ''),
        f"({answers['type']})" if answers.get('type') else '') if p)
    return _ios_answer(answers.get('name'), answers.get('version'),
                       answers.get('build') or str(
                           plist.get('CacheVersion') or '').strip(), device)


def _last_build_info(text):
    """installd's LastBuildInfo.plist: SystemVersion.plist's keys, for the
    build the app database was last rebuilt on -- the current one, since
    an update rebuilds it."""
    plist = _apple_plist(text)
    return _ios_answer(str(plist.get('ProductName') or ''),
                       str(plist.get('ProductVersion') or '').strip(),
                       str(plist.get('ProductBuildVersion') or '').strip())


#: Where a system root names its system, and how to read each.
_MARKERS = (
    ('/etc/lsb-release', _lsb_release),
    ('/etc/os-release', _os_release),
    ('/usr/lib/os-release', _os_release),
    ('/System/Library/CoreServices/SystemVersion.plist', _system_version),
    ('/system/build.prop', _build_prop),
    ('/system/system/build.prop', _build_prop),
    ('/build.prop', _build_prop),
    # An iOS backup opened as evidence (core/ios_backup): its own files.
    ('/Backup/Info.plist', _backup_info),
    # An iOS extraction of the data partition alone has no /System: the
    # version is in /private/var.
    ('/private/var/containers/Shared/SystemGroup/'
     'systemgroup.com.apple.mobilegestaltcache/Library/Caches/'
     'com.apple.MobileGestalt.plist', _mobile_gestalt),
    ('/private/var/installd/Library/MobileInstallation/LastBuildInfo.plist',
     _last_build_info),
)

#: Members of a packed extraction that name its system: (path ending,
#: reader). A tar's are found by walking its headers (its data skipped).
_PACKED_MARKERS = (
    ('/system/library/coreservices/systemversion.plist', _system_version),
    ('/system/build.prop', _build_prop),
    ('/etc/os-release', _os_release),
)
#: Archives looked into: the evidence's own top folders hold them.
_PACKED_DEPTH = 3
_PACKED_MIN = 1024 * 1024


def _plist_text(raw):
    """A plist's text in XML form, binary ones converted."""
    import plistlib
    if raw[:8] == b'bplist00':
        try:
            return plistlib.dumps(plistlib.loads(raw)).decode(
                'utf-8', 'replace')
        except Exception:
            return ''
    return raw[:65536].decode('utf-8', 'replace')


def _from_packed(handler, key):
    """Logical evidence whose phone is packed in archives -- a full file
    system as a tar, a zipped iTunes backup: the system named from inside
    them (a backup's Info.plist; a tar's SystemVersion.plist / build.prop,
    found header by header). Only folders and similar evidence: an image's
    own file systems are read by _from_roots."""
    import tarfile
    import zipfile
    from trace_app.core import walk
    if getattr(handler, 'logical_fs', None) is None:
        return None
    try:
        entries = [e for e in walk.iter_files(handler, offsets=[key])
                   if not e.deleted and e.size >= _PACKED_MIN
                   and e.path.count('/') <= _PACKED_DEPTH
                   and e.name.lower().endswith(('.tar', '.zip'))]
    except Exception as exc:
        logger.debug("No archives at %s: %s", key, exc)
        return None
    for entry in sorted(entries, key=lambda e: e.name.lower().endswith(
            '.tar')):                   # backups first: one small read
        stream = handler.open_file_object(entry.inode, entry.offset)
        if stream is None:
            continue
        try:
            if entry.name.lower().endswith('.zip'):
                with zipfile.ZipFile(stream) as zipped:
                    names = zipped.namelist()
                    info = next((n for n in names if n.endswith('/Info.plist')
                                 and n[:-len('Info.plist')] + 'Manifest.db'
                                 in names), None)
                    if info:
                        # Whole: its keys come after the app list.
                        found = _backup_info(zipped.read(info).decode(
                            'utf-8', 'replace'))
                        if found:
                            return found
                continue
            with tarfile.open(fileobj=stream, mode='r:') as tarred:
                for member in tarred:
                    low = '/' + member.name.lower().lstrip('./')
                    for ending, parse in _PACKED_MARKERS:
                        if low.endswith(ending) and member.isfile():
                            handle = tarred.extractfile(member)
                            found = parse(_plist_text(
                                handle.read(1 << 20))) if handle else None
                            if found:
                                return found
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError,
                ValueError) as exc:
            logger.debug("%s not read: %s", entry.path, exc)
    return None



def _from_roots(handler, key):
    """Read the markers on each system root of the volume (activity's
    Volume: Btrfs subvolumes, a collection's roots, links followed)."""
    from trace_app.core.activity import Volume
    try:
        volumes = Volume.all(handler, key)
    except Exception as exc:
        logger.debug("No system roots at %s: %s", key, exc)
        return None
    for volume in volumes:
        for path, parse in _MARKERS:
            try:
                entry = volume.lookup(path)
                raw = volume.read(entry) if entry is not None else b''
                # A backup's Info.plist whole: its keys follow the list of
                # every app, past 64 KB.
                if path.endswith('Info.plist'):
                    text = raw.decode('utf-8', 'replace')
                elif path.endswith('.plist'):
                    text = _plist_text(raw)     # often binary
                else:
                    text = raw[:65536].decode('utf-8', 'replace')
                found = parse(text) if raw else None
            except Exception as exc:
                logger.debug("%s at %s: %s", path, key, exc)
                found = None
            if found:
                return found
    return None


def identify(handler, key):
    """The operating system on the volume at `key`, or None. Reads the
    hive or the release file: call it off the UI thread (the window warms
    it as an image opens) and read `cached` there."""
    cache = handler.__dict__.setdefault('_os_identity_cache', {})
    if key in cache:
        return cache[key]
    found = None
    try:
        found = from_os_info(handler.get_os_info(key))
    except Exception as exc:
        logger.debug("OS details at %s: %s", key, exc)
    if found is None:
        found = _from_roots(handler, key)
    if found is None:
        found = _from_packed(handler, key)
    cache[key] = found
    return found


def cached(handler, key):
    """What `identify` found for `key`, without reading anything: None
    when it found nothing or has not run."""
    return handler.__dict__.get('_os_identity_cache', {}).get(key)


def describe(identity):
    """'Windows 11 Pro (23H2, build 22631)' for a tooltip."""
    if not identity:
        return ''
    return identity['name'] + (f" ({identity['detail']})"
                               if identity.get('detail') else '')

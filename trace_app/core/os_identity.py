"""Which operating system a volume holds, as a family, a name and a logo
(no Qt).

`ImageHandler.get_os_info` reads the details the Image Information dialog
lists (SOFTWARE's CurrentVersion, os-release, SystemVersion.plist). This
names the system from them -- and from where that reader does not look: a
system root that is not the volume's top (Fedora's Btrfs keeps it in the
'root' subvolume, a collection in its 'C' folder), and Android's
build.prop -- so the tree and the dialog can show the system's logo.

`identify(handler, key)` -> {'family', 'logo', 'name', 'detail'} or None:

* family: 'windows', 'macos', 'linux', 'android', 'freebsd', 'openbsd'
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
         'openbsd') + tuple(key for key, _words in DISTRIBUTIONS)


def _family_of(name):
    """(family, logo) for an operating system's name, or None."""
    lower = name.lower()
    if lower.startswith('windows') or 'microsoft windows' in lower:
        return 'windows', 'windows'
    if lower.startswith(('macos', 'mac os', 'os x')):
        return 'macos', 'macos'
    if lower.startswith('android'):
        return 'android', 'android'
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
    return {'family': 'linux', 'logo': distribution(os_id, name),
            'name': name, 'detail': (f"build {values['BUILD_ID']}"
                                     if values.get('BUILD_ID') else '')}


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


#: Where a system root names its system, and how to read each.
_MARKERS = (
    ('/etc/os-release', _os_release),
    ('/usr/lib/os-release', _os_release),
    ('/System/Library/CoreServices/SystemVersion.plist', _system_version),
    ('/system/build.prop', _build_prop),
    ('/system/system/build.prop', _build_prop),
    ('/build.prop', _build_prop),
)


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
                found = parse(raw[:65536].decode('utf-8', 'replace')) \
                    if raw else None
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

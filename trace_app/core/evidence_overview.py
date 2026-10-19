"""What logical evidence -- a folder, an extraction, a backup -- holds, for
the Evidence Information window (no Qt).

A disk image is described by its layout (core/disk_layout); a folder has
none. What an examiner wants of one instead:

* how much: files, folders, bytes, and the same per top-level folder;
* the device it came from (`device_facts`): an iTunes/Finder backup's
  Info.plist (name, model, iOS, serial, IMEI, MEID, ICCID, phone number,
  the last backup), Android's build.prop (maker, model, version, build,
  security patch);
* what is in it (`contents`): a phone's file system packed in a tar or
  zip, a zipped backup, sysdiagnose archives, acquisition logs;
* whether a backup is encrypted (Manifest.plist's IsEncrypted): read
  before anything is run on it -- iLEAPP, and TRACE's own reader, need its
  password.

Everything from the folder tree TRACE already holds in memory
(core/logical) plus small reads: the Info.plist and build.prop, and a
zip's central directory. A tar is named by its size and name only -- its
headers are not walked here (a 16 GB tar takes seconds).
"""

import logging
import re
import threading

logger = logging.getLogger('TRACE.EvidenceOverview')
_OVERVIEW_LOCK = threading.Lock()

#: Info.plist keys shown, in order, with their labels.
BACKUP_FIELDS = (('Product Name', 'Model'), ('Product Type', 'Model code'),
                 ('Product Version', 'iOS version'),
                 ('Build Version', 'iOS build'), ('Device Name', 'Device name'),
                 ('Serial Number', 'Serial number'), ('IMEI', 'IMEI'),
                 ('IMEI 2', 'IMEI 2'), ('MEID', 'MEID'), ('ICCID', 'ICCID'),
                 ('Phone Number', 'Phone number'),
                 ('Unique Identifier', 'UDID'),
                 ('Last Backup Date', 'Last backup (UTC)'),
                 ('iTunes Version', 'iTunes version'),
                 ('macOS Version', 'Backed up on macOS'))
#: build.prop properties shown, with their labels. Android 10 and later
#: name the device per partition (ro.product.system.model,
#: ro.product.vendor.model...) and keep a build.prop in each: the first
#: property found of each tuple, over every build.prop, is taken.
ANDROID_FIELDS = (
    (('ro.product.manufacturer', 'ro.product.vendor.manufacturer',
      'ro.product.system.manufacturer', 'ro.product.odm.manufacturer'),
     'Manufacturer'),
    (('ro.product.model', 'ro.product.vendor.model',
      'ro.product.odm.model', 'ro.product.product.model',
      'ro.product.system.model'), 'Model'),
    (('ro.product.device', 'ro.product.vendor.device',
      'ro.product.odm.device', 'ro.product.system.device'), 'Device'),
    (('ro.build.version.release', 'ro.system.build.version.release'),
     'Android version'),
    (('ro.build.version.security_patch',
      'ro.vendor.build.security_patch'), 'Security patch'),
    (('ro.build.id', 'ro.system.build.id'), 'Build'),
    (('ro.build.fingerprint', 'ro.system.build.fingerprint',
      'ro.vendor.build.fingerprint'), 'Fingerprint'),
    (('ro.serialno', 'ro.boot.serialno'), 'Serial number'))
LOG_WORDS = ('log', 'report', 'info', 'acquisition', 'extraction', 'hash')


def summary(handler):
    """{'files', 'folders', 'bytes', 'top': [(name, is_dir, files, bytes)]}
    of logical evidence; None for a disk image."""
    fs = getattr(handler, 'logical_fs', None)
    if fs is None:
        return None
    from trace_app.core.logical import ROOT
    listing = getattr(fs, 'listing', None)
    if listing is not None:
        return _listing_summary(listing)
    nodes = fs.nodes
    totals = {'files': 0, 'folders': 0, 'bytes': 0, 'top': []}

    def walk(inode):
        files = folders = size = 0
        stack = [inode]
        while stack:
            node = nodes[stack.pop()]
            for child in (node.children or {}).values():
                item = nodes[child]
                if item.is_dir:
                    folders += 1
                    stack.append(child)
                else:
                    files += 1
                    size += item.size
        return files, folders, size
    for name, child in sorted((nodes[ROOT].children or {}).items(),
                              key=lambda pair: pair[0].lower()):
        item = nodes[child]
        if item.is_dir:
            files, folders, size = walk(child)
            totals['folders'] += folders + 1
        else:
            files, size = 1, item.size
        totals['files'] += files
        totals['bytes'] += size
        totals['top'].append((name, item.is_dir, files, size))
    return totals


def overview(handler):
    """{'summary', 'device', 'contents'} of logical evidence, worked out
    once and kept on the handler: the evidence's opening does it off the
    window's thread (MainWindow's _HandlerOpener), so Evidence Information
    opens at once -- it used to read 1 million files' names twice at every
    click (14 s on the Magnet 2021 Mac folder). None for a disk image."""
    if getattr(handler, 'logical_fs', None) is None:
        return None
    kept = getattr(handler, '_overview', None)
    if kept is not None:
        return kept
    with _OVERVIEW_LOCK:
        kept = getattr(handler, '_overview', None)
        if kept is None:
            kept = {'summary': summary(handler) or {},
                    'device': device_facts(handler),
                    'contents': contents(handler)}
            handler._overview = kept
    return kept


def overview_ready(handler):
    """Whether overview() would answer without reading."""
    return getattr(handler, '_overview', None) is not None


def _listing_summary(listing):
    """summary() from a folder's listing columns (core/folder_listing):
    totals added up children first -- the walk numbers a parent before its
    children -- so no node is made (1.3 million made took 7 s)."""
    count = len(listing)
    files, folders = [0] * count, [0] * count
    size = [0] * count
    kinds, sizes, parents = listing.kinds, listing.sizes, listing.parents
    for index in range(count - 1, 0, -1):
        parent = parents[index] - 1
        if kinds[index] == 1:
            folders[parent] += folders[index] + 1
            files[parent] += files[index]
            size[parent] += size[index]
        else:
            files[parent] += 1
            size[parent] += sizes[index]
    first, number = listing.first[0], listing.count[0]
    top = []
    for inode in range(first, first + number):
        index = inode - 1
        is_dir = kinds[index] == 1
        top.append((listing.names[index], is_dir,
                    files[index] if is_dir else 1,
                    size[index] if is_dir else sizes[index]))
    top.sort(key=lambda row: row[0].lower())
    return {'files': files[0], 'folders': folders[0], 'bytes': size[0],
            'top': top}


def _read_info_plist(raw):
    """Info.plist's string fields (plistlib; the app list nests dicts)."""
    import plistlib
    try:
        data = plistlib.loads(raw)
    except Exception:
        return {}
    out = {}
    for key, value in (data.items() if isinstance(data, dict) else ()):
        if isinstance(value, str):
            out[key] = value
        elif hasattr(value, 'strftime'):
            out[key] = value.strftime('%Y-%m-%d %H:%M:%S')
    return out


def device_facts(handler):
    """{label: value} of the phone an extraction came from, or {}."""
    from trace_app.core import walk
    try:
        entries = [e for e in walk.iter_files(handler, max_depth=3)
                   if not e.deleted and e.path.count('/') <= 4]
    except Exception as exc:
        logger.debug("No files listed: %s", exc)
        return {}
    props = {}
    for entry in entries:
        name = entry.name.lower()
        try:
            if name == 'build.prop':
                text = entry.read(262144).decode('utf-8', 'replace')
                for key, value in re.findall(r'^([\w.]+)=(.*)$', text,
                                             re.M):
                    props.setdefault(key, value)
                continue
            if name in ('full-v2.txt', 'vpd_2.0.txt'):
                # A Chromebook's Vital Product Data (activity/chromeos).
                from trace_app.core.activity import chromeos
                values = chromeos.vpd(entry.read(262144).decode(
                    'utf-8', 'replace'))
                facts = {label: values[key] for key, label
                         in chromeos.VPD_FACTS if values.get(key)}
                if facts:
                    return dict({'Device': 'Chromebook'}, **facts)
                continue
            folder = entry.path[:-len(entry.name)]
            if name == 'info.plist' and any(
                    e.path in (folder + 'Manifest.db',
                               folder + 'Manifest.plist') for e in entries):
                facts = _read_info_plist(entry.read())
                if facts.get('Product Version'):
                    manifest = next((e for e in entries if e.path ==
                                     folder + 'Manifest.plist'), None)
                    encrypted = backup_encrypted(manifest.read()) \
                        if manifest is not None else None
                    return _with_encryption(facts, encrypted)
            if name.endswith('.zip') and entry.size > 1024 * 1024:
                facts, encrypted = _zipped_backup(handler, entry)
                if facts:
                    return _with_encryption(facts, encrypted)
        except Exception as exc:
            logger.debug("%s not read: %s", entry.path, exc)
    if props:
        return {label: props[key].strip() for keys, label in ANDROID_FIELDS
                for key in [next((k for k in keys if props.get(k)), None)]
                if key}
    return {}


def _zipped_backup(handler, entry):
    """(Info.plist's fields, encrypted or None) of a zipped backup, or
    ({}, None)."""
    import zipfile
    stream = handler.open_file_object(entry.inode, entry.offset)
    if stream is None:
        return {}, None
    with zipfile.ZipFile(stream) as zipped:
        names = set(zipped.namelist())
        for name in names:
            folder = name[:-len('Info.plist')]
            if name.endswith('/Info.plist') and \
                    folder + 'Manifest.db' in names:
                encrypted = backup_encrypted(zipped.read(
                    folder + 'Manifest.plist')) \
                    if folder + 'Manifest.plist' in names else None
                return _read_info_plist(zipped.read(name)), encrypted
    return {}, None


#: The row a backup's encryption is shown as.
ENCRYPTED_FIELD = 'Backup encrypted'


def backup_encrypted(raw):
    """A backup's Manifest.plist (binary or XML) -> True / False, or None
    when it does not say."""
    import plistlib
    try:
        manifest = plistlib.loads(raw)
    except Exception:
        return None
    value = manifest.get('IsEncrypted') if isinstance(manifest, dict) \
        else None
    return bool(value) if value is not None else None


def encryption_text(encrypted):
    return ("Yes -- its password is needed to read it (iLEAPP: given when "
            "it runs; TRACE: Unlock on the backup)" if encrypted else "No")


def _with_encryption(facts, encrypted):
    ordered = _ordered(facts, BACKUP_FIELDS)
    if encrypted is not None:
        ordered[ENCRYPTED_FIELD] = encryption_text(encrypted)
    return ordered


def _ordered(values, fields):
    return {label: str(values[key]).strip() for key, label in fields
            if values.get(key) not in (None, '')}


def contents(handler):
    """[(what, path, size)] -- the packed extractions, backups, sysdiagnose
    archives and acquisition logs at the evidence's top levels."""
    import zipfile
    from trace_app.core import walk
    out = []
    try:
        entries = [e for e in walk.iter_files(handler, max_depth=2)
                   if not e.deleted and e.path.count('/') <= 3]
    except Exception:
        return out
    for entry in entries:
        name = entry.name.lower()
        what = None
        if name.startswith('sysdiagnose') and name.endswith(
                ('.tar.gz', '.tgz')):
            what = 'Sysdiagnose archive'
        elif name.endswith(('.tar', '.tar.gz', '.tgz', '.tar.xz')) and \
                entry.size > 100 * 1024 * 1024:
            what = 'File system archive (tar)'
        elif name.endswith('.zip') and entry.size > 1024 * 1024:
            try:
                stream = handler.open_file_object(entry.inode, entry.offset)
                with zipfile.ZipFile(stream) as zipped:
                    members = zipped.namelist()
                    manifest = next((m for m in members
                                     if m.endswith('/Manifest.plist')
                                     or m == 'Manifest.plist'), None)
                    encrypted = backup_encrypted(zipped.read(manifest)) \
                        if manifest else None
                if any(m.endswith('/Manifest.db') or m == 'Manifest.db'
                       for m in members):
                    what = 'iTunes/Finder backup (zip)'
                    if encrypted:
                        what = 'iTunes/Finder backup (zip, encrypted)'
                elif any('private/var/mobile/' in m or 'data/data/' in m
                         for m in members[:5000]):
                    what = 'File system archive (zip)'
            except Exception:
                what = None
        elif name.endswith(('.txt', '.log', '.csv', '.pdf', '.html')) and \
                any(word in entry.path.lower() for word in LOG_WORDS):
            what = 'Acquisition log or report'
        if what:
            out.append((what, entry.path, entry.size))
    order = ('File system archive (tar)', 'File system archive (zip)',
             'iTunes/Finder backup (zip, encrypted)',
             'iTunes/Finder backup (zip)', 'Sysdiagnose archive',
             'Acquisition log or report')
    return sorted(out, key=lambda row: (order.index(row[0]), row[1]))

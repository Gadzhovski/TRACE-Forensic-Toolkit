"""What a piece of evidence is, before it joins a case (no Qt).

The New Case and Add Evidence wizards open each item the examiner picks,
so a missing E01 segment or a renamed text file is found while choosing --
not after the case exists, as a failure in a window that has already
promised to show it. `probe(path)` opens the item exactly as the case will
(ImageHandler), says what it holds, and closes it again; the wizard runs it
on a thread.

It also reads what the item records about its own acquisition -- an E01's or
L01's header -- so the custody fields arrive filled in, marked as from the
image, rather than retyped from a paper form.
"""

import logging
import os

logger = logging.getLogger('TRACE.EvidenceProbe')

OK = 'ok'
NOTES = 'notes'
ERROR = 'error'

#: Volume kinds that need a key before their files can be read.
_ENCRYPTED = {'bitlocker': 'BitLocker', 'fvde': 'FileVault 2',
              'luks': 'LUKS', 'ios_backup': 'Encrypted iOS backup'}

#: Volume kinds that hold further volumes.
_POOLS = {'lvm': 'Linux LVM', 'apfs': 'APFS container'}

#: Header labels (EWF and L01 spell them differently) -> custody field.
_CUSTODY_FROM_HEADER = {
    'evidence number': 'exhibit_number',
    'description': 'description',
    'examiner': 'acquired_by',
    'examiner name': 'acquired_by',
    'acquired': 'acquired_on',
}

_FORMATS = {
    '.e01': 'EnCase image (E01)', '.ex01': 'EnCase image (Ex01)',
    '.s01': 'SMART image (S01)', '.dd': 'Raw image', '.raw': 'Raw image',
    '.img': 'Raw image', '.000': 'Split raw image',
    '.001': 'Split raw image', '.iso': 'ISO image',
    '.vmdk': 'VMware disk (VMDK)', '.vhd': 'Virtual PC disk (VHD)',
    '.vhdx': 'Hyper-V disk (VHDX)', '.qcow2': 'QEMU disk (QCOW2)',
    '.qcow': 'QEMU disk (QCOW)', '.dmg': 'Apple disk image (DMG)',
    '.sparseimage': 'Apple sparse image', '.sparse': 'Raw image',
    '.sparsebundle': 'Apple sparse bundle', '.ad1': 'FTK logical image (AD1)',
    '.hdd': 'Parallels disk', '.hds': 'Parallels disk',
    '.aff4': 'AFF4 image',
    '.l01': 'EnCase logical evidence (L01)',
    '.lx01': 'EnCase logical evidence (Lx01)', '.zip': 'ZIP archive',
    '.tar': 'TAR archive',
    '.trace-assembly': 'Assembled volume (RAID / multi-disk)',
}


def format_name(path):
    """How an item's format reads, from its name: 'EnCase image (E01)'."""
    trimmed = path.rstrip('/\\')
    lowered = trimmed.lower()
    if lowered.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):
        return 'TAR archive'
    from trace_app.core.containers import is_parallels
    if is_parallels(trimmed):
        return 'Parallels disk'
    if os.path.isdir(trimmed) and not lowered.endswith('.sparsebundle'):
        from trace_app.core.logical_sources import kind_of
        return 'iOS backup' if kind_of(trimmed) == 'ios_backup' else 'Folder'
    return _FORMATS.get(os.path.splitext(lowered)[1], 'Disk image')


def probe(path):
    """Open `path` as the case would, describe it, close it.

    Returns a dict: status (OK / NOTES / ERROR), path, name, format, size
    (bytes of media, or None), contents (one line: 'MBR · NTFS, FAT32'),
    notes (list of lines worth reading before going on), error, custody
    ({field: value} from the image's own header) and stored_hashes (bool).
    Never raises: an item that cannot be read is an answer, not a crash.
    """
    from trace_app.core.live_disk import is_device_path
    live = is_device_path(path)
    path = path if live else os.path.normpath(path)
    result = {'path': path, 'name': os.path.basename(path.rstrip('/\\'))
              or path, 'format': format_name(path), 'size': None,
              'contents': '', 'notes': [], 'error': '', 'custody': {},
              'stored_hashes': False, 'status': ERROR}
    if not live and not os.path.exists(path):
        result['error'] = 'The file or folder does not exist.'
        return result

    from trace_app.core.image_handler import ImageHandler, \
        UnsupportedEvidence
    try:
        handler = ImageHandler(path)
    except UnsupportedEvidence as exc:       # known, and explained
        result['error'] = str(exc)
        return result
    except ValueError:                # an extension TRACE does not read
        extension = os.path.splitext(path)[1] or 'no extension'
        result['error'] = (f"Not an evidence format TRACE reads "
                           f"({extension}). Disk images (E01, dd/raw, ISO, "
                           f"VMDK, VHD/VHDX, QCOW2, DMG), AD1, L01, ZIP/TAR "
                           f"and folders can be added.")
        return result
    except Exception as exc:
        result['error'] = str(exc) or 'The evidence could not be opened.'
        return result
    try:
        if not handler.loaded:
            result['error'] = (handler.load_error or
                               'The evidence could not be opened. It may be '
                               'corrupt, incomplete (a missing segment), or '
                               'an unsupported format.')
            return result
        _describe(handler, result)
    except Exception as exc:
        logger.warning("Probing %s failed: %s", path, exc)
        result['error'] = f"The evidence opened but could not be read: {exc}"
        return result
    finally:
        try:
            handler.close_resources()
        except Exception:
            pass

    if live:
        result['format'] = 'Live disk (read-only)'
        result['notes'].insert(0, (
            "A live disk, read through the administrator helper: if it is "
            "in use it changes as it is read, and TRACE does not stop the "
            "system writing to it. For evidence, image it behind a write "
            "blocker."))
    result['status'] = NOTES if result['notes'] else OK
    return result


def _describe(handler, result):
    note = handler.container_note
    if note and handler.logical_fs is None:
        # A note that only extends the format ('Parallels disk (bundle)')
        # replaces it rather than repeating it.
        result['format'] = note if note.startswith(result['format']) else \
            f"{result['format']} · {note}"

    if handler.logical_fs is not None:
        fs = handler.logical_fs
        files = max(len(fs.nodes) - 1, 0)
        result['contents'] = f"{files:,} item{'s' if files != 1 else ''}"
        facts = fs.facts
        if facts.get('_locked'):
            result['notes'].append(
                f"{_ENCRYPTED.get(facts['_locked'], 'Encrypted')}: unlock "
                f"it after the case is created to read its files.")
        stored = facts.get('_stored_size')
        if stored:
            result['size'] = stored
        elif os.path.isfile(result['path']):
            result['size'] = os.path.getsize(result['path'])
    else:
        try:
            result['size'] = int(handler.get_size())
        except Exception:
            result['size'] = None
        result['contents'] = _volumes(handler, result['notes'])

    info = {}
    try:
        info = handler.get_acquisition_info() or {}
    except Exception as exc:
        logger.debug("No acquisition info for %s: %s", result['path'], exc)
    for label, value in info.items():
        field = _CUSTODY_FROM_HEADER.get(str(label).strip().lower())
        if field and str(value).strip() and field not in result['custody']:
            result['custody'][field] = str(value).strip()
        if str(label).lower().startswith('stored ') and value:
            result['stored_hashes'] = True
    if result['format'].startswith('AFF4'):
        result['stored_hashes'] = True      # each stream records its own
    if result['stored_hashes']:
        result['notes'].append("Stores its acquisition hashes: verification "
                               "will check them.")
    if not result['contents']:
        result['contents'] = 'No file system found'
        result['notes'].append(
            "No partition or file system was recognised: it can still be "
            "carved and viewed in hex.")


def _volumes(handler, notes):
    """'MBR · NTFS, FAT32' -- the partition scheme and every file system or
    container found; encrypted volumes are noted."""
    scheme = ''
    if handler.volume_info is not None:
        try:
            import pytsk3
            names = {pytsk3.TSK_VS_TYPE_DOS: 'MBR',
                     pytsk3.TSK_VS_TYPE_GPT: 'GPT',
                     pytsk3.TSK_VS_TYPE_MAC: 'Apple partition map',
                     pytsk3.TSK_VS_TYPE_BSD: 'BSD disklabel',
                     pytsk3.TSK_VS_TYPE_SUN: 'Sun VTOC'}
            scheme = names.get(handler.volume_info.info.vstype, 'Partitioned')
        except Exception:
            scheme = 'Partitioned'

    starts = [p[2] for p in handler.get_partitions() or ()] \
        if handler.volume_info is not None else [0]
    found = []
    for start in starts:
        kind = None
        try:
            kind = handler.volume_kind(start)
        except Exception:
            pass
        if kind in _ENCRYPTED:
            found.append(_ENCRYPTED[kind])
            notes.append(f"{_ENCRYPTED[kind]} volume: unlock it after the "
                         f"case is created to read its files.")
            continue
        if kind in _POOLS:
            found.append(_POOLS[kind])
            continue
        try:
            mounted = handler.get_fs_info(start) is not None
            name = handler.get_fs_type(start) if mounted else None
        except Exception:
            mounted, name = False, None
        if not mounted:
            # What is on the media, though TSK will not mount it: an
            # overwritten or damaged file system is a finding, not nothing.
            try:
                traces = handler.detect_filesystems(start)
            except Exception:
                traces = []
            if traces:
                found.append(f"{traces[-1]} (unreadable)")
                notes.append(f"Sector {start:,} carries {' and '.join(traces)}"
                             f" signatures but no file system opens there: "
                             f"damaged or overwritten. Carving and hex still "
                             f"read it.")
            continue
        if name and name not in ('N/A',):
            found.append(name if name != 'Unknown' else 'File system')
    if handler.volume_info is None and not found:
        return ''
    parts = [scheme] if scheme else []
    if found:
        counted = []
        for name in dict.fromkeys(found):
            count = found.count(name)
            counted.append(f"{name} ×{count}" if count > 1 else name)
        parts.append(', '.join(counted))
    elif scheme:
        parts.append('no file system recognised')
    return ' · '.join(parts)

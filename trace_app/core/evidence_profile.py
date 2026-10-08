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
something on any file system and is never ruled out; and an image with a
volume TRACE cannot read (locked, damaged) rules nothing out, because what
it holds is unknown.
"""

import logging

logger = logging.getLogger('TRACE.EvidenceProfile')

#: File systems The Sleuth Kit reads, whose deleted entries it lists.
_TSK_FILE_SYSTEMS = ('NTFS', 'FAT12', 'FAT16', 'FAT32', 'ExFAT', 'Ext2',
                     'Ext3', 'Ext4', 'HFS', 'HFS+', 'HFSX', 'ISO9660',
                     'UFS1', 'UFS2', 'YAFFS2')


def profile(image_handler):
    """{'filesystems', 'systems', 'logical', 'unreadable', 'summary'} for
    an open image."""
    from trace_app.core import containers
    from trace_app.core.activity import Volume, linux, macos
    filesystems, systems, unreadable = [], [], False
    logical = image_handler.logical_fs is not None
    # Locked containers first: a locked BitLocker To Go drive opens as its
    # FAT32 decoy, and a locked APFS volume is not among the volumes read.
    starts = [p[2] for p in image_handler.get_partitions()] or [0]
    for start in dict.fromkeys(starts):
        try:
            kind = image_handler.volume_kind(start)
            if kind == 'bitlocker' and not image_handler.is_unlocked(start):
                unreadable = True
            elif kind == 'apfs' and any(
                    v['locked'] for v in image_handler.apfs_volumes(start)):
                unreadable = True
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
            if kind in ('bitlocker', 'fvde', 'luks', 'apfs', 'ios_backup'):
                unreadable = True           # locked: what is inside is unknown
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
    if unreadable:
        parts.append('a volume TRACE cannot read')
    return {'filesystems': filesystems, 'systems': systems,
            'logical': logical, 'unreadable': unreadable,
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
    return out

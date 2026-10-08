"""Disks inside files, and volumes inside volumes.

Virtual disks (VMDK, VHD, VHDX) are containers like E01: pytsk3 reads them
through an Img_Info whose reads go to libvmdk / libvhdi. A differencing disk
holds only what changed since its parent, so the parent -- and its parent --
are opened from beside it and chained, exactly as the hypervisor does.

BitLocker volumes and Volume Shadow Copies are volumes found inside a
partition. Each is read through libbde / libvshadow from a window onto the
partition, and handed to pytsk3 as an image of its own.

No Qt here.
"""

import logging
import os
import threading

import pytsk3

logger = logging.getLogger('TRACE.Containers')


class ContainerError(Exception):
    """A container could not be opened; the message says why."""


#: Every call into a libyal object (reads, volume and container handles,
#: APFS entries) holds this. The window and its workers use one image at
#: once -- the Registry tab's hive finder walks volumes while the window
#: builds the tree -- and libyal objects are not thread-safe: on Linux and
#: macOS concurrent use returned wrong bytes (an APFS superblock failed its
#: checksum) or crashed the process. Re-entrant, because a volume's read
#: reaches its image's read on the same thread (BitLocker in a DMG).
#: Background jobs are processes of their own and do not contend.
LIBYAL_LOCK = threading.RLock()


def holding_libyal(method):
    """A method run under LIBYAL_LOCK."""
    import functools

    @functools.wraps(method)
    def locked(*args, **kwargs):
        with LIBYAL_LOCK:
            return method(*args, **kwargs)
    return locked


class LibyalImgInfo(pytsk3.Img_Info):
    """pytsk3's view of anything libyal-shaped: read_buffer_at_offset and a
    size. `keep` holds every object the read path depends on (a differencing
    disk's parents), so none is collected while this image is in use."""

    def __init__(self, source, size, keep=()):
        self._source = source
        self._size = size
        self._keep = list(keep)
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, offset, length):
        if offset >= self._size or length <= 0:
            return b''
        length = min(length, self._size - offset)
        with LIBYAL_LOCK:
            return self._source.read_buffer_at_offset(length, offset)

    def get_size(self):
        return self._size

    def close(self):
        for thing in [self._source] + self._keep:
            try:
                thing.close()
            except Exception:
                pass


class ByteWindow:
    """A byte range of an image as a Python file object -- what libbde and
    libvshadow are given to read a partition through."""

    def __init__(self, reader, start, size):
        self._reader = reader            # reader(offset, length) -> bytes
        self._start = start
        self._size = size
        self._position = 0

    def read(self, length=-1):
        if length is None or length < 0 or self._position + length > self._size:
            length = max(0, self._size - self._position)
        if not length:
            return b''
        data = self._reader(self._start + self._position, length)
        self._position += len(data)
        return data

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_CUR:
            offset += self._position
        elif whence == os.SEEK_END:
            offset += self._size
        self._position = max(0, offset)
        return self._position

    def tell(self):
        return self._position

    def get_size(self):
        return self._size


# --- volumes inside a partition ----------------------------------------------------

#: At byte 3 of a BitLocker volume, where NTFS says "NTFS    ".
BITLOCKER_SIGNATURE = b'-FVE-FS-'

#: Shadow copies are file systems of their own, keyed like partitions by an
#: integer that every reference, tree node and cache already carries. Real
#: partition offsets are sector numbers -- below 2**48 even for a 128 PB disk
#: -- so keys from here up cannot collide with one, and stay stable across
#: reopening the case: the partition and the snapshot's index fix the key.
SHADOW_KEY_BASE = 1 << 48
SHADOWS_PER_VOLUME = 64         # Windows keeps at most 64 per volume


def shadow_key(start_sector, index):
    return SHADOW_KEY_BASE + start_sector * SHADOWS_PER_VOLUME + index


def split_shadow_key(key):
    """(partition start sector, snapshot index), or None for a partition."""
    # Below the LVM range (2**49): logical and APFS volumes are keyed above.
    if key is None or not SHADOW_KEY_BASE <= key < 2 ** 49:
        return None
    return divmod(key - SHADOW_KEY_BASE, SHADOWS_PER_VOLUME)


#: How pybde names the ways a volume can be unlocked.
PROTECTOR_TYPES = {
    0x0000: 'clear key', 0x0100: 'TPM', 0x0200: 'startup key (.BEK)',
    0x0500: 'TPM + PIN', 0x0800: 'recovery password', 0x2000: 'password',
}

ENCRYPTION_METHODS = {
    0x8000: 'AES-128-CBC with diffuser', 0x8001: 'AES-256-CBC with diffuser',
    0x8002: 'AES-128-CBC', 0x8003: 'AES-256-CBC', 0x8004: 'AES-128-XTS',
    0x8005: 'AES-256-XTS',
}


def bitlocker_facts(window):
    """What a locked BitLocker volume says about itself, before any key:
    {'identifier', 'description', 'created', 'protectors', 'method'}."""
    import pybde
    volume = pybde.volume()
    try:
        volume.open_file_object(window)
    except (IOError, OSError) as exc:
        raise ContainerError(f"Not a readable BitLocker volume: {exc}") from exc
    try:
        protectors = []
        for index in range(volume.get_number_of_key_protectors()):
            try:
                kind = volume.get_key_protector(index).get_type()
            except (IOError, OSError, AttributeError):
                continue
            protectors.append(PROTECTOR_TYPES.get(kind, f'type {kind:#06x}'))
        created = None
        try:
            created = volume.get_creation_time()
        except (IOError, OSError, AttributeError):
            pass
        method = None
        try:
            method = volume.get_encryption_method()
        except (IOError, OSError, AttributeError):
            pass
        return {'identifier': str(volume.get_volume_identifier() or ''),
                'description': volume.get_description() or '',
                'created': created, 'protectors': protectors,
                'method': ENCRYPTION_METHODS.get(method, method)}
    finally:
        volume.close()


def unlock_bitlocker(window, recovery_password=None, password=None,
                     startup_key=None):
    """An unlocked pybde volume, or ContainerError saying why not.

    `recovery_password` is the 48-digit key (dashes optional), `password`
    the user's BitLocker password, `startup_key` the path of a .BEK file.
    """
    import pybde
    volume = pybde.volume()
    try:
        if recovery_password:
            digits = ''.join(c for c in recovery_password if c.isdigit())
            if len(digits) != 48:
                raise ContainerError("A recovery key is 48 digits, in eight "
                                     "groups of six.")
            volume.set_recovery_password(
                '-'.join(digits[i:i + 6] for i in range(0, 48, 6)))
        if password:
            volume.set_password(password)
        if startup_key:
            volume.read_startup_key(startup_key)
        volume.open_file_object(window)
        if volume.is_locked():
            volume.unlock()
    except ContainerError:
        _close_quietly(volume)
        raise
    except (IOError, OSError) as exc:
        _close_quietly(volume)
        raise ContainerError(f"The volume did not unlock: {exc}") from exc
    if volume.is_locked():
        _close_quietly(volume)
        raise ContainerError("That key does not unlock this volume.")
    return volume


def _close_quietly(thing):
    """Close, if it was ever opened."""
    try:
        thing.close()
    except (IOError, OSError):
        pass


def open_shadow_copies(window):
    """(pyvshadow volume, [store]) for a volume with snapshots, or
    (None, [])."""
    import pyvshadow
    try:
        if not pyvshadow.check_volume_signature_file_object(window):
            return None, []
        volume = pyvshadow.volume()
        volume.open_file_object(window)
    except (IOError, OSError) as exc:
        logger.debug("No readable shadow copies: %s", exc)
        return None, []
    stores = []
    for index in range(min(volume.get_number_of_stores(),
                           SHADOWS_PER_VOLUME)):
        try:
            stores.append(volume.get_store(index))
        except (IOError, OSError) as exc:
            logger.warning("Shadow copy %d unreadable: %s", index, exc)
            stores.append(None)
    return volume, stores


# --- other encrypted volumes, LVM, APFS ----------------------------------------

#: What an encrypted volume is called, for labels and the audit trail.
ENCRYPTION_NAMES = {'bitlocker': 'BitLocker', 'fvde': 'FileVault 2',
                    'luks': 'LUKS', 'apfs': 'APFS encryption',
                    'ios_backup': 'iOS backup encryption'}

#: Logical volumes and APFS volumes are keyed like shadow copies, each in a
#: range of its own above any real sector offset.
_LVM_BASE = 2 ** 49
_APFS_BASE = 2 ** 50
VOLUMES_PER_CONTAINER = 64


def lvm_key(start_sector, index):
    return _LVM_BASE + start_sector * VOLUMES_PER_CONTAINER + index


def apfs_key(start_sector, index):
    return _APFS_BASE + start_sector * VOLUMES_PER_CONTAINER + index


def _split(key, base, upper):
    if not isinstance(key, int) or not base <= key < upper:
        return None
    rest = key - base
    return rest // VOLUMES_PER_CONTAINER, rest % VOLUMES_PER_CONTAINER


def split_lvm_key(key):
    """(partition start, logical volume index) or None."""
    return _split(key, _LVM_BASE, _APFS_BASE)


def split_apfs_key(key):
    """(partition start, APFS volume index) or None."""
    return _split(key, _APFS_BASE, 2 ** 51)


#: A file system layered under another in one partition (formatted again
#: without wiping, both sets of structures intact): each is opened on its
#: own, keyed above APFS's range like the other volumes.
_LAYER_BASE = 2 ** 51
LAYERS_PER_PARTITION = 8


def layer_key(start_sector, index):
    return _LAYER_BASE + start_sector * LAYERS_PER_PARTITION + index


#: A Windows dynamic disk's volumes (core/ldm.py), above the layers.
_LDM_BASE = 2 ** 52


def ldm_key(start_sector, index):
    return _LDM_BASE + start_sector * VOLUMES_PER_CONTAINER + index


def split_ldm_key(key):
    """(dynamic disk partition start, volume index) or None."""
    return _split(key, _LDM_BASE, 2 ** 53)


def split_layer_key(key):
    """(partition start, layer index) or None."""
    if not isinstance(key, int) or not _LAYER_BASE <= key < 2 ** 52:
        return None
    return divmod(key - _LAYER_BASE, LAYERS_PER_PARTITION)


def volume_kind(window):
    """What a partition holds that The Sleuth Kit cannot open by itself:
    'bitlocker', 'fvde', 'luks', 'lvm', 'apfs', or None."""
    checks = (('bitlocker', 'pybde', 'check_volume_signature_file_object'),
              ('fvde', 'pyfvde', 'check_volume_signature_file_object'),
              ('luks', 'pyluksde', 'check_volume_signature_file_object'),
              ('lvm', 'pyvslvm', 'check_volume_signature_file_object'),
              ('apfs', 'pyfsapfs', 'check_container_signature_file_object'))
    for kind, module, check in checks:
        try:
            library = __import__(module)
            window.seek(0)
            if getattr(library, check)(window):
                return kind
        except Exception:
            continue
    return None


def unlock_fvde(window, password=None, recovery_password=None):
    """A FileVault 2 (Core Storage) logical volume, unlocked:
    (logical volume, [objects to keep])."""
    import pyfvde
    volume = pyfvde.volume()
    try:
        volume.open_file_object(window)
        volume.open_physical_volume_files_as_file_objects([window])
        group = volume.get_volume_group()
        logical = group.get_logical_volume(0)
        if logical.is_locked():
            if recovery_password:
                logical.set_recovery_password(recovery_password)
            elif password:
                logical.set_password(password)
            else:
                raise ContainerError("A password or recovery key is needed.")
            logical.unlock()
    except ContainerError:
        _close_quietly(volume)
        raise
    except (IOError, OSError) as exc:
        _close_quietly(volume)
        raise ContainerError(f"The volume did not unlock: {exc}") from exc
    if logical.is_locked():
        _close_quietly(volume)
        raise ContainerError("That key does not unlock this volume.")
    return logical, [volume, group]


def unlock_luks(window, password=None, key=None):
    """A LUKS volume, unlocked: the decrypting volume. LUKS2 is read by
    core/luks2.py (libluksde reads LUKS1 only)."""
    from trace_app.core import luks2
    window.seek(0)
    if luks2.is_luks2(window.read(8)):
        def read(offset, length):
            window.seek(offset)
            return window.read(length)
        try:
            return luks2.unlock(read, window.get_size(), password,
                                bytes.fromhex(key) if isinstance(key, str)
                                else key)
        except (luks2.Luks2Error, ValueError) as exc:
            raise ContainerError(str(exc)) from exc
        except ImportError as exc:
            raise ContainerError(f"LUKS2 needs the cryptography library: "
                                 f"{exc}") from exc
    import pyluksde
    volume = pyluksde.volume()
    try:
        if password:
            volume.set_password(password)
        elif key:
            volume.set_key(key)
        else:
            raise ContainerError("A passphrase is needed.")
        volume.open_file_object(window)
        if volume.is_locked():
            volume.unlock()
    except ContainerError:
        _close_quietly(volume)
        raise
    except (IOError, OSError) as exc:
        _close_quietly(volume)
        raise ContainerError(f"The volume did not unlock: {exc}") from exc
    if volume.is_locked():
        _close_quietly(volume)
        raise ContainerError("That passphrase does not unlock this volume.")
    return volume


def open_lvm(window):
    """(handle, volume group, [logical volume]) of an LVM physical volume;
    a group spanning disks not in the image reads as far as it can."""
    import pyvslvm
    handle = pyvslvm.handle()
    handle.open_file_object(window)
    handle.open_physical_volume_files_as_file_objects([window])
    group = handle.get_volume_group()
    volumes = []
    for index in range(min(group.number_of_logical_volumes,
                           VOLUMES_PER_CONTAINER)):
        try:
            volumes.append(group.get_logical_volume(index))
        except (IOError, OSError) as exc:
            logger.warning("Logical volume %d unreadable: %s", index, exc)
            volumes.append(None)
    return handle, group, volumes


def open_apfs(window):
    """(container, [volume]) of an APFS container."""
    import pyfsapfs
    container = pyfsapfs.container()
    container.open_file_object(window)
    volumes = []
    for index in range(min(container.number_of_volumes,
                           VOLUMES_PER_CONTAINER)):
        try:
            volumes.append(container.get_volume(index))
        except (IOError, OSError) as exc:
            logger.warning("APFS volume %d unreadable: %s", index, exc)
            volumes.append(None)
    return container, volumes


def unlock_apfs(volume, password=None, recovery_password=None):
    if not volume.is_locked():
        return volume
    try:
        if recovery_password:
            volume.set_recovery_password(recovery_password)
        elif password:
            volume.set_password(password)
        else:
            raise ContainerError("A password or recovery key is needed.")
        volume.unlock()
    except (IOError, OSError) as exc:
        raise ContainerError(f"The volume did not unlock: {exc}") from exc
    if volume.is_locked():
        raise ContainerError("That password does not unlock this volume.")
    return volume


# --- virtual disks --------------------------------------------------------------

VIRTUAL_DISK_EXTENSIONS = {'.vmdk': 'vmdk', '.vhd': 'vhdi', '.vhdx': 'vhdi',
                           '.qcow2': 'qcow', '.qcow': 'qcow',
                           '.dmg': 'modi', '.sparseimage': 'modi',
                           '.sparsebundle': 'modi'}

#: Deepest chain of differencing disks followed (snapshots of snapshots).
MAX_PARENTS = 32


def _sibling(path, recorded):
    """Where a parent disk the child names is: beside the child, by its
    file name (the recorded path is from the machine that made it)."""
    name = recorded.replace('\\', '/').rsplit('/', 1)[-1]
    if not name:
        return None
    folder = os.path.dirname(path)
    candidate = os.path.normpath(os.path.join(folder, name))
    if os.path.exists(candidate):
        return candidate
    lowered = name.lower()
    try:
        for entry in os.listdir(folder):
            if entry.lower() == lowered:
                return os.path.normpath(os.path.join(folder, entry))
    except OSError:
        pass
    return None


def open_virtual_disk(path):
    """(Img_Info, description) for a VMDK, VHD or VHDX, its parents chained.
    Raises ContainerError."""
    # libyal, like libewf, rejects mixed separators on Windows.
    path = os.path.normpath(path)
    kind = VIRTUAL_DISK_EXTENSIONS.get(os.path.splitext(path)[1].lower())
    if kind == 'vmdk':
        return _open_vmdk(path)
    if kind == 'vhdi':
        return _open_vhdi(path)
    if kind == 'qcow':
        return _open_qcow(path)
    if kind == 'modi':
        return _open_modi(path)
    raise ContainerError(f"{os.path.basename(path)} is not a virtual disk")


def _open_vhdi(path):
    import pyvhdi
    chain = []
    current_path = path
    try:
        disk = pyvhdi.file()
        disk.open(current_path)
        chain.append(disk)
        child = disk
        while len(chain) <= MAX_PARENTS:
            parent_name = _parent_name(child)
            if not parent_name:
                break
            parent_path = _sibling(current_path, parent_name)
            if parent_path is None:
                raise ContainerError(
                    f"{os.path.basename(current_path)} is a differencing disk; "
                    f"its parent {parent_name.rsplit(chr(92), 1)[-1]} must be "
                    f"in the same folder")
            parent = pyvhdi.file()
            parent.open(parent_path)
            child.set_parent(parent)
            chain.append(parent)
            child, current_path = parent, parent_path
    except ContainerError:
        for disk in chain:
            disk.close()
        raise
    except (IOError, OSError) as exc:
        for disk in chain:
            disk.close()
        raise ContainerError(f"Could not open {os.path.basename(path)}: "
                             f"{exc}") from exc
    top = chain[0]
    size = top.get_media_size()
    kind = 'VHDX' if path.lower().endswith('.vhdx') else 'VHD'
    note = f'{kind}, differencing ({len(chain) - 1} parent' \
        f'{"s" if len(chain) > 2 else ""})' if len(chain) > 1 else kind
    return LibyalImgInfo(top, size, chain[1:]), note


def _open_qcow(path):
    """A QCOW2 image (backing files chained) through core/qcow2.py, which
    reads compressed clusters libqcow returns as zeros; libqcow for what
    that does not read (QCOW 1, encryption, extended L2)."""
    from trace_app.core import qcow2
    try:
        image = qcow2.Qcow2Image(path, sibling=_sibling)
    except (qcow2.Qcow2Error, OSError, ValueError) as exc:
        logger.info("%s not read as QCOW2 in Python: %s",
                    os.path.basename(path), exc)
    else:
        count = image.chain_length()
        note = 'QCOW' if count == 1 else             f'QCOW overlay ({count - 1} backing file'             f'{"s" if count > 2 else ""})'
        return LibyalImgInfo(image, image.get_media_size()), note
    import pyqcow
    chain = []
    current_path = path
    try:
        disk = pyqcow.file()
        disk.open(current_path)
        chain.append(disk)
        child = disk
        while len(chain) <= MAX_PARENTS:
            parent_name = _parent_name(child)
            if not parent_name:
                break
            parent_path = _sibling(current_path, parent_name)
            if parent_path is None:
                raise ContainerError(
                    f"{os.path.basename(current_path)} is an overlay; its "
                    f"backing file {parent_name} must be in the same folder")
            parent = pyqcow.file()
            parent.open(parent_path)
            child.set_parent(parent)
            chain.append(parent)
            child, current_path = parent, parent_path
    except ContainerError:
        for disk in chain:
            disk.close()
        raise
    except (IOError, OSError) as exc:
        for disk in chain:
            disk.close()
        raise ContainerError(f"Could not open {os.path.basename(path)}: "
                             f"{exc}") from exc
    top = chain[0]
    if top.is_locked():
        for disk in chain:
            disk.close()
        raise ContainerError(f"{os.path.basename(path)} is encrypted")
    note = 'QCOW' if len(chain) == 1 else         f'QCOW overlay ({len(chain) - 1} backing file'         f'{"s" if len(chain) > 2 else ""})'
    return LibyalImgInfo(top, top.get_media_size(), chain[1:]), note


#: UDIF chunk types (the blkx table), for saying how a DMG is stored.
_UDIF_COMPRESSION = {0x80000004: 'ADC', 0x80000005: 'zlib',
                     0x80000006: 'bzip2', 0x80000007: 'LZFSE',
                     0x80000008: 'LZMA'}


def _open_modi(path):
    """A Mac disk image -- UDIF (.dmg, compressed with zlib, bzip2,
    LZFSE, LZMA or ADC, or not), a sparse image or a sparse bundle --
    through libmodi, which decompresses as it reads; or, for a UDIF image
    with bzip2 chunks or one libmodi refuses, through core/udif.py."""
    lowered = path.lower().rstrip('/\\')
    is_udif = os.path.isfile(path) and not lowered.endswith('.sparseimage')
    if is_udif and 'bzip2' in _udif_methods(path):
        # libmodi's bzip2 decoder fails on ordinary chunks (hdiutil's
        # UDBZ read as a volume with no files).
        opened = _open_udif(path)
        if opened is not None:
            return opened
    import pymodi
    handle = pymodi.handle()
    try:
        handle.open(path)
        if os.path.isdir(path):
            handle.open_band_data_files()
    except (IOError, OSError) as exc:
        try:
            handle.close()
        except Exception:
            pass
        # hdiutil's read-only UDRO images, for one, are refused.
        opened = _open_udif(path) if is_udif else None
        if opened is not None:
            return opened
        raise ContainerError(f"Could not open {os.path.basename(path)}: "
                             f"{exc}") from exc
    if lowered.endswith('.sparsebundle'):
        note = 'Sparse bundle'
    elif lowered.endswith('.sparseimage'):
        note = 'Sparse image'
    else:
        methods = _udif_methods(path)
        note = 'DMG (UDIF' + (f", {', '.join(methods)}" if methods else
                              ', uncompressed') + ')'
    return LibyalImgInfo(handle, handle.get_media_size()), note


def _open_udif(path):
    """(LibyalImgInfo, note) through core/udif.py, or None when it cannot
    read the image either."""
    from trace_app.core import udif
    try:
        image = udif.UdifImage(path)
    except (udif.UdifError, OSError, ValueError) as exc:
        logger.info("%s not read as UDIF in Python: %s",
                    os.path.basename(path), exc)
        return None
    methods = _udif_methods(path)
    note = 'DMG (UDIF' + (f", {', '.join(methods)}" if methods else
                          ', uncompressed') + ')'
    return LibyalImgInfo(image, image.get_media_size()), note


def _udif_methods(path):
    """The compressions a UDIF image's chunks use, from its koly trailer
    and blkx table; [] if it has none or cannot say."""
    import base64
    import plistlib
    import struct
    try:
        with open(path, 'rb') as handle:
            handle.seek(-512, os.SEEK_END)
            koly = handle.read(512)
            if koly[:4] != b'koly':
                return []
            offset, length = struct.unpack('>QQ', koly[0xd8:0xe8])
            if not length or length > 64 * 1024 * 1024:
                return []
            handle.seek(offset)
            plist = plistlib.loads(handle.read(length))
    except (OSError, ValueError, plistlib.InvalidFileException):
        return []
    found = []
    for block in plist.get('resource-fork', {}).get('blkx', []):
        data = block.get('Data') or b''
        if isinstance(data, str):
            data = base64.b64decode(data)
        if data[:4] != b'mish' or len(data) < 204:
            continue
        count = struct.unpack('>I', data[200:204])[0]
        for index in range(count):
            kind = struct.unpack_from('>I', data, 204 + index * 40)[0]
            name = _UDIF_COMPRESSION.get(kind)
            if name and name not in found:
                found.append(name)
    return found


def _parent_name(disk):
    for getter in ('get_parent_filename', 'get_parent_file_name',
                   'get_backing_filename'):
        try:
            name = getattr(disk, getter)()
        except (AttributeError, IOError, OSError):
            continue
        if name:
            return name
    return ''


def _open_vmdk(path):
    import pyvmdk
    chain = []
    current_path = path
    try:
        disk = pyvmdk.handle()
        disk.open(current_path)
        disk.open_extent_data_files()
        chain.append(disk)
        child = disk
        while len(chain) <= MAX_PARENTS:
            parent_name = _parent_name(child)
            if not parent_name:
                break
            parent_path = _sibling(current_path, parent_name)
            if parent_path is None:
                raise ContainerError(
                    f"{os.path.basename(current_path)} is a snapshot disk; "
                    f"its parent {parent_name} must be in the same folder")
            parent = pyvmdk.handle()
            parent.open(parent_path)
            parent.open_extent_data_files()
            child.set_parent(parent)
            chain.append(parent)
            child, current_path = parent, parent_path
    except ContainerError:
        for disk in chain:
            disk.close()
        raise
    except (IOError, OSError) as exc:
        for disk in chain:
            disk.close()
        raise ContainerError(
            f"Could not open {os.path.basename(path)}: {exc}. A VMDK "
            f"descriptor needs its extent files (-flat / -s00N) beside it."
        ) from exc
    top = chain[0]
    note = 'VMDK' if len(chain) == 1 else \
        f'VMDK snapshot ({len(chain) - 1} parent{"s" if len(chain) > 2 else ""})'
    return LibyalImgInfo(top, top.get_media_size(), chain[1:]), note

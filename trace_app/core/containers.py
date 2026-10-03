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

import pytsk3

logger = logging.getLogger('TRACE.Containers')


class ContainerError(Exception):
    """A container could not be opened; the message says why."""


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
    if key is None or key < SHADOW_KEY_BASE:
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


# --- virtual disks --------------------------------------------------------------

VIRTUAL_DISK_EXTENSIONS = {'.vmdk': 'vmdk', '.vhd': 'vhdi', '.vhdx': 'vhdi',
                           '.qcow2': 'qcow', '.qcow': 'qcow'}

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

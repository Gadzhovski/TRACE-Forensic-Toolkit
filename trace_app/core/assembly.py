"""Evidence made of several disks: a Linux RAID (md) array, a multi-disk
Btrfs file system (no Qt).

Each member disk is its own evidence -- imaged, hashed and verified on
its own -- but what was on the machine is the array (or the Btrfs pool),
and only the members together hold it. `find_groups(handlers)` looks at
the open images for members and groups them; `write(folder, group)` saves
a small JSON descriptor (`.trace-assembly`) naming the member images and
partitions; ImageHandler opens such a file like any other evidence
(`open_assembly`), so the window, the background jobs and verification
need nothing new. Member images are found where the descriptor recorded
them, or beside it by name if the case folder has moved.
"""

import json
import logging
import os
import struct

from trace_app.core import containers

logger = logging.getLogger('TRACE.Assembly')

EXTENSION = '.trace-assembly'
VERSION = 1
MDRAID, BTRFS, HWRAID = 'mdraid', 'btrfs', 'hwraid'


class AssemblyError(Exception):
    """The descriptor names members that are not there, or do not fit."""


def is_assembly(path):
    return str(path).lower().endswith(EXTENSION)


# --- finding members among the open images ----------------------------------------

def _starts(handler):
    starts = [p[2] for p in handler.get_partitions()] or [0]
    return list(dict.fromkeys(starts))


def _btrfs_device(handler, start):
    """(fsid, devid, devices, label) of a Btrfs device at a partition."""
    from trace_app.core import btrfs
    try:
        offset, length = handler.partition_bytes(start)
        head = handler.read(offset, btrfs.SUPERBLOCK_OFFSET + 4096)
    except Exception:
        return None
    if btrfs.superblock_geometry(head) is None:
        return None
    sb = head[btrfs.SUPERBLOCK_OFFSET:]
    fsid = sb[0x20:0x30]
    devices = struct.unpack_from('<Q', sb, 0x88)[0]
    devid = struct.unpack_from('<Q', sb, 0xc9)[0]
    label = sb[0x12b:0x22b].split(b'\0', 1)[0].decode('utf-8', 'replace')
    return fsid, devid, devices, label


def find_groups(handlers):
    """Multi-disk volumes among open images ({path: ImageHandler}):
    [{'kind', 'id', 'name', 'level', 'needed', 'members': [{'image',
    'start_sector', 'slot'}], 'complete', 'readable'}]. A group whose
    members all sit in one image needs no assembling and is left out; so
    is a Btrfs file system on one device."""
    groups = {}
    for path, handler in handlers.items():
        if handler is None or getattr(handler, 'logical_fs', None) \
                is not None or is_assembly(path):
            continue
        for start in _starts(handler):
            member = None
            try:
                member = handler.md_member(start)
            except Exception:
                pass
            if member is not None:
                key = (MDRAID, member.uuid)
                group = groups.setdefault(key, {
                    'kind': MDRAID, 'id': member.uuid.hex(),
                    'name': member.name or member.uuid.hex()[:8],
                    'level': member.level, 'needed': member.raid_disks,
                    'members': []})
                group['members'].append({'image': path,
                                         'start_sector': start,
                                         'slot': member.role})
                continue
            device = _btrfs_device(handler, start)
            if device is not None and device[2] > 1:
                fsid, devid, devices, label = device
                group = groups.setdefault((BTRFS, fsid), {
                    'kind': BTRFS, 'id': fsid.hex(),
                    'name': label or fsid.hex()[:8], 'level': None,
                    'needed': devices, 'members': []})
                group['members'].append({'image': path,
                                         'start_sector': start,
                                         'slot': devid})
    out = []
    for group in groups.values():
        images = {m['image'] for m in group['members']}
        if len(images) < 2:
            continue                       # all in one image: read already
        slots = {m['slot'] for m in group['members']}
        group['complete'] = len(slots) >= group['needed']
        group['members'].sort(key=lambda m: m['slot'])
        out.append(group)
    return out


def hardware_group(paths, params, name='Hardware RAID'):
    """A group for `write` from images without RAID metadata, rebuilt
    with core/hwraid.Params (its order indexes `paths`)."""
    import uuid as uuid_module
    return {'kind': HWRAID, 'id': uuid_module.uuid4().hex, 'name': name,
            'level': params.level, 'needed': len(params.order or paths),
            'params': params.as_dict(),
            'members': [{'image': path, 'start_sector': None, 'slot': index}
                        for index, path in enumerate(paths)]}


def describe(group):
    if group['kind'] == HWRAID:
        from trace_app.core import hwraid
        return (f"{group['name']}: "
                f"{hwraid.Params.from_dict(group['params']).describe()}")
    found = len({m['slot'] for m in group['members']})
    what = (f"RAID{group['level']}" if group['kind'] == MDRAID
            else 'Btrfs file system')
    return (f"{what} '{group['name']}': {found} of {group['needed']} "
            f"{'disks' if group['kind'] == MDRAID else 'devices'} found")


def write(folder, group):
    """Save the descriptor for `group`; returns its path."""
    os.makedirs(folder, exist_ok=True)
    safe = ''.join(c if c.isalnum() or c in '-_' else '_'
                   for c in group['name'])[:40] or 'volume'
    path = os.path.join(folder, f"{group['kind']}-{safe}-{group['id'][:8]}"
                                f"{EXTENSION}")
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump({'trace_assembly': VERSION, 'kind': group['kind'],
                   'name': group['name'], 'id': group['id'],
                   'level': group['level'], 'needed': group['needed'],
                   'params': group.get('params'),
                   'members': [{'image': os.path.abspath(m['image']),
                                'start_sector': m['start_sector'],
                                'slot': m['slot']}
                               for m in group['members']]},
                  handle, indent=1)
    return path


# --- opening one ----------------------------------------------------------------

def read_descriptor(path):
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise AssemblyError(f"Unreadable descriptor: {exc}") from exc
    if data.get('trace_assembly') != VERSION or \
            data.get('kind') not in (MDRAID, BTRFS, HWRAID):
        raise AssemblyError("Not a TRACE assembly descriptor")
    return data


def _member_image(recorded, descriptor):
    """Where a member image is: as recorded, or beside the descriptor."""
    if os.path.exists(recorded):
        return recorded
    beside = os.path.join(os.path.dirname(descriptor),
                          os.path.basename(recorded))
    if os.path.exists(beside):
        return beside
    raise AssemblyError(f"Member image {os.path.basename(recorded)} is not "
                        f"where it was recorded, nor beside the descriptor")


def open_assembly(path):
    """(Img_Info, note, extra Btrfs device windows, handlers to keep) for
    a descriptor. Raises AssemblyError."""
    from trace_app.core.image_handler import ImageHandler
    data = read_descriptor(path)
    handlers, windows = {}, []
    try:
        for member in data['members']:
            image = _member_image(member['image'], path)
            handler = handlers.get(image)
            if handler is None:
                handler = handlers[image] = ImageHandler(image)
                if not handler.loaded:
                    raise AssemblyError(
                        f"Member image {os.path.basename(image)} would not "
                        f"open: {handler.load_error}")
            if member['start_sector'] is None:
                # The whole disk (a hardware RAID member).
                offset, length = 0, handler.get_size()
            else:
                offset, length = handler.partition_bytes(
                    member['start_sector'])
            windows.append((handler, offset, length))
        keep = list(handlers.values())
        if data['kind'] == HWRAID:
            from trace_app.core import hwraid
            params = hwraid.Params.from_dict(data['params'])
            members = [((lambda o, n, h=h, b=b: h.read(b + o, n)), n)
                       for h, b, n in windows]
            try:
                volume = hwraid.build(members, params)
            except hwraid.RaidError as exc:
                raise AssemblyError(str(exc)) from exc
            return (_Kept(_Reader(volume), keep),
                    f"{data['name']}: {params.describe()}", (), keep)
        if data['kind'] == MDRAID:
            from trace_app.core import mdraid
            members = []
            for handler, offset, length in windows:
                read = (lambda o, n, h=handler, b=offset: h.read(b + o, n))
                found = mdraid.superblock(read, length)
                if found is None:
                    raise AssemblyError("A member no longer carries its "
                                        "RAID superblock")
                members.append((found, read))
            try:
                array = mdraid.Array(members)
            except mdraid.MdError as exc:
                raise AssemblyError(str(exc)) from exc
            return (_Kept(mdraid.MdImgInfo(array), keep),
                    f"Linux {array.describe()}", (), keep)
        # Btrfs: the devices end to end are the media; the reader is
        # given each device on its own.
        sources = [containers.ByteWindow(h.read, o, n)
                   for h, o, n in windows]
        image = _Concat([(h, o, n) for h, o, n in windows], keep)
        note = (f"Btrfs '{data['name']}' across {len(windows)} of "
                f"{data['needed']} devices")
        return image, note, sources[1:], keep
    except Exception:
        for handler in handlers.values():
            handler.close_resources()
        raise


try:
    import pytsk3

    class _Concat(pytsk3.Img_Info):
        """Members' byte ranges end to end, as one image."""

        def __init__(self, parts, keep):
            self._parts = parts
            self._keep = keep
            self._size = sum(n for _h, _o, n in parts)
            super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):
            out = bytearray()
            position = 0
            for handler, base, size in self._parts:
                if length <= 0:
                    break
                if offset < position + size:
                    within = max(0, offset - position)
                    part = min(length, size - within)
                    out += handler.read(base + within, part)
                    offset += part
                    length -= part
                position += size
            return bytes(out)

        def get_size(self):
            return self._size

        def close(self):
            for handler in self._keep:
                handler.close_resources()

    class _Reader:
        """read/get_size over a reader with read/size."""

        def __init__(self, inner):
            self._inner = inner

        def read(self, offset, length):
            return self._inner.read(offset, length)

        def get_size(self):
            return self._inner.size

    class _Kept(pytsk3.Img_Info):
        """An image whose member handlers close with it."""

        def __init__(self, inner, keep):
            self._inner = inner
            self._keep = keep
            super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):
            return self._inner.read(offset, length)

        def get_size(self):
            return self._inner.get_size()

        def close(self):
            for handler in self._keep:
                handler.close_resources()
except ImportError:                                   # pragma: no cover
    _Concat = _Kept = _Reader = None

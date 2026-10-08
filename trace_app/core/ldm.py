"""Windows dynamic disks: the Logical Disk Manager database, read in
Python (no Qt; libyal's libvsldm has no wheels).

A dynamic disk (MBR partition type 0x42, or GPT's "LDM metadata" and
"LDM data" partitions) keeps its volumes in a database copied on every
disk of its disk group: a PRIVHEAD (this disk's GUID, where its data area
and the database are), a TOCBLOCK, the VMDB, then fixed-size VBLKs, a
record spread over several when it does not fit. Records, by type:

* 0x34 / 0x44 disk (GUID), 0x35 / 0x45 disk group;
* 0x51 volume: name, type ('gen' for simple / spanned / striped /
  mirrored, 'raid5'), size;
* 0x32 component (a plex): its volume, its kind (1 striped, 2 simple or
  spanned, 3 RAID5), stripe size and columns;
* 0x33 partition (an extent): its component, its disk, start on that
  disk's data area, size, offset in the component, column.

A volume is its first readable component; a component is its extents --
end to end (simple, spanned), by column in stripes (striped), or RAID5
with parity -- left-symmetric, as Windows writes it (on the X-Ways set
every other rotation fails most files; core/hwraid.py reads it, one
missing disk rebuilt). Field positions follow the Linux
kernel's fs/partitions/ldm.c and the linux-ntfs project's LDM notes.
"""

import logging
import struct

logger = logging.getLogger('TRACE.LDM')

SECTOR = 512
GPT_LDM_METADATA = '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3'
GPT_LDM_DATA = 'AF9B60A0-1431-4F62-BC68-3311714A69AD'

KIND_STRIPED, KIND_SPANNED, KIND_RAID5 = 1, 2, 3


class LdmError(Exception):
    pass


def _vnum(data, offset):
    """A variable-length big-endian number: length byte, then bytes."""
    length = data[offset]
    if length > 8:
        raise LdmError("Number field too long")
    return int.from_bytes(data[offset + 1:offset + 1 + length], 'big')


def _vstr(data, offset):
    length = data[offset]
    return data[offset + 1:offset + 1 + length].decode('utf-8', 'replace')


def _relative(data, base, offset):
    """The kernel's ldm_relative: past the variable field at base+offset,
    as an offset from base."""
    position = base + offset
    if position >= len(data) or position + data[position] >= len(data):
        raise LdmError("Field outside the record")
    return data[position] + offset + 1


def find_privhead(read, size, gpt=None):
    """(sector, PRIVHEAD bytes): sector 6 on an MBR dynamic disk, the
    last sector of the LDM metadata partition on a GPT one, else the
    disk's last 2,048 sectors (where the database lives)."""
    candidates = [6]
    for first, (kind, _name) in (gpt or {}).items():
        if kind == GPT_LDM_METADATA:
            candidates.append(first)            # searched below
    for sector in candidates[:1]:
        data = read(sector * SECTOR, SECTOR)
        if data[:8] == b'PRIVHEAD':
            return sector, data
    total = size // SECTOR
    for start, count in ([(c, 4096) for c in candidates[1:]] +
                         [(max(0, total - 2048), 2048)]):
        block = read(start * SECTOR, count * SECTOR)
        index = block.rfind(b'PRIVHEAD')
        while index >= 0 and index % SECTOR:
            index = block.rfind(b'PRIVHEAD', 0, index)
        if index >= 0:
            return start + index // SECTOR, block[index:index + SECTOR]
    return None, None


class Database:
    """One disk's copy of its disk group's database."""

    def __init__(self, read, size, gpt=None):
        sector, head = find_privhead(read, size, gpt)
        if head is None:
            raise LdmError("No LDM PRIVHEAD")
        self.disk_guid = head[0x30:0x30 + 64].split(b'\0', 1)[0] \
            .decode('ascii', 'replace').lower()
        self.data_start, self.data_size, config_start, config_size = \
            struct.unpack_from('>QQQQ', head, 0x11B)
        if not config_start or config_start * SECTOR >= size:
            # A disk imaged short, or a GPT disk whose PRIVHEAD names the
            # database by the disk it came from: it is at the end.
            config_start = max(0, size // SECTOR - (config_size or 2048))
        area = read(config_start * SECTOR, 64 * SECTOR)
        at = area.find(b'VMDB')
        while at >= 0 and at % SECTOR:
            at = area.find(b'VMDB', at + 1)
        if at < 0:
            raise LdmError("No VMDB")
        vmdb = area[at:at + SECTOR]
        last, block, first = struct.unpack_from('>III', vmdb, 4)
        self.group_name = vmdb[0x16:0x16 + 31].split(b'\0', 1)[0] \
            .decode('utf-8', 'replace')
        if not 64 <= block <= 4096 or last > 1 << 20:
            raise LdmError("VMDB out of range")
        raw = read(config_start * SECTOR + at + first, (last + 1) * block)
        pieces = {}
        for index in range(len(raw) // block):
            vblk = raw[index * block:(index + 1) * block]
            if vblk[:4] != b'VBLK':
                continue
            group = struct.unpack_from('>I', vblk, 8)[0]
            number, count = struct.unpack_from('>HH', vblk, 12)
            pieces.setdefault(group, (count, {}))[1][number] = vblk
        self.disks, self.volumes, self.components, self.extents = \
            {}, {}, {}, {}
        self.group_guid = None
        for count, parts in pieces.values():
            if len(parts) != count or not count:
                continue
            record = parts[0][:16] + b''.join(parts[n][16:]
                                              for n in range(count))
            try:
                self._record(record)
            except (LdmError, IndexError, struct.error) as exc:
                logger.debug("LDM record not read: %s", exc)

    def _record(self, data):
        if len(data) < 0x1a:
            return
        flags, kind = data[0x12], data[0x13]
        r_objid = _relative(data, 0x18, 0)
        object_id = _vnum(data, 0x18)
        r_name = _relative(data, 0x18, r_objid)
        name = _vstr(data, 0x18 + r_objid)
        if kind == 0x34:                                  # disk, v3
            guid = _vstr(data, 0x18 + r_name)
            self.disks[object_id] = {'name': name, 'guid': guid.lower()}
        elif kind == 0x44:                                # disk, v4
            raw = data[0x18 + r_name:0x18 + r_name + 16]
            import uuid
            self.disks[object_id] = {'name': name, 'guid': str(
                uuid.UUID(bytes=bytes(raw))).lower()}
        elif kind in (0x35, 0x45):
            self.group_name = self.group_name or name
            if kind == 0x35:
                self.group_guid = _vstr(data, 0x18 + r_name).lower()
        elif kind == 0x51:                                # volume
            r_type = _relative(data, 0x18, r_name)
            r_flag = _relative(data, 0x18, r_type)
            r_child = _relative(data, 0x2D, r_flag)
            r_size = _relative(data, 0x3D, r_child)
            self.volumes[object_id] = {
                'name': name, 'type': _vstr(data, 0x18 + r_name),
                'components': _vnum(data, 0x2D + r_flag),
                'size': _vnum(data, 0x3D + r_child) * SECTOR,
                'partition_type': data[0x41 + r_size]}
        elif kind == 0x32:                                # component
            r_state = _relative(data, 0x18, r_name)
            r_child = _relative(data, 0x1D, r_state)
            r_parent = _relative(data, 0x2D, r_child)
            chunk = columns = 0
            if flags & 0x10:
                r_stripe = _relative(data, 0x2E, r_parent)
                chunk = _vnum(data, 0x2E + r_parent) * SECTOR
                columns = _vnum(data, 0x2E + r_stripe)
            self.components[object_id] = {
                'name': name, 'kind': data[0x18 + r_state],
                'children': _vnum(data, 0x1D + r_state),
                'volume': _vnum(data, 0x2D + r_child),
                'chunk': chunk, 'columns': columns}
        elif kind == 0x33:                                # partition
            r_size = _relative(data, 0x34, r_name)
            r_parent = _relative(data, 0x34, r_size)
            r_disk = _relative(data, 0x34, r_parent)
            start, offset = struct.unpack_from('>QQ', data, 0x24 + r_name)
            self.extents[object_id] = {
                'name': name, 'start': start * SECTOR,
                'offset': offset * SECTOR,
                'size': _vnum(data, 0x34 + r_name) * SECTOR,
                'component': _vnum(data, 0x34 + r_size),
                'disk': _vnum(data, 0x34 + r_parent),
                'column': data[0x35 + r_disk] if flags & 0x08 else 0}

    # --- volumes ---------------------------------------------------------

    def volume_list(self):
        """[{'id', 'name', 'kind', 'size', 'disks' (GUIDs), 'components':
        [{'kind', 'chunk', 'columns', 'extents': [...]}]}] -- every
        volume of the disk group, extents naming their disk by GUID."""
        out = []
        for volume_id, volume in sorted(self.volumes.items()):
            components = []
            for component_id, component in sorted(self.components.items()):
                if component['volume'] != volume_id:
                    continue
                extents = sorted(
                    (dict(e, disk_guid=self.disks.get(e['disk'], {}).get(
                        'guid')) for e in self.extents.values()
                     if e['component'] == component_id),
                    key=lambda e: (e['column'], e['offset']))
                components.append(dict(component, id=component_id,
                                       extents=extents))
            kinds = {c['kind'] for c in components}
            kind = ('mirror' if len(components) > 1 else
                    'raid5' if KIND_RAID5 in kinds or volume['type'] ==
                    'raid5' else 'striped' if KIND_STRIPED in kinds else
                    'spanned' if any(len(c['extents']) > 1
                                     for c in components) else 'simple')
            disks = sorted({e['disk_guid'] for c in components
                            for e in c['extents'] if e['disk_guid']})
            out.append({'id': volume_id, 'name': volume['name'],
                        'kind': kind, 'size': volume['size'],
                        'disks': disks, 'components': components})
        return out


class _Extents:
    """Extents end to end (one column, or a simple / spanned volume)."""

    def __init__(self, parts):
        self.parts = parts                      # [(read, start, size)]
        self.size = sum(size for _r, _s, size in parts)

    def read(self, offset, length):
        out = bytearray()
        position = 0
        for read, start, size in self.parts:
            if length <= 0:
                break
            if offset < position + size:
                within = offset - position
                part = min(length, size - within)
                data = read(start + within, part)
                out += data + bytes(part - len(data))
                offset += part
                length -= part
            position += size
        return bytes(out)


def volume_reader(volume, disks):
    """A reader (read, size) of a volume (from Database.volume_list).
    `disks` {disk GUID: (read, data_start bytes)} -- the disks at hand.
    A mirror reads from its first plex whose disks are all here; RAID5
    rebuilds one missing column. Raises LdmError when it cannot."""
    from trace_app.core import hwraid
    errors = []
    for component in volume['components']:
        try:
            reader = _component(component, disks, hwraid)
        except (LdmError, hwraid.RaidError) as exc:
            errors.append(str(exc))
            continue
        reader.size = min(reader.size, volume['size'] or reader.size)
        return reader
    raise LdmError('; '.join(errors) or "The volume has no extents")


def _column(extents, disks):
    parts = []
    for extent in sorted(extents, key=lambda e: e['offset']):
        disk = disks.get(extent['disk_guid'])
        if disk is None:
            return None
        read, data_start = disk
        parts.append((read, data_start + extent['start'], extent['size']))
    return _Extents(parts)


def _component(component, disks, hwraid):
    extents = component['extents']
    if not extents:
        raise LdmError("A component without extents")
    if component['kind'] not in (KIND_STRIPED, KIND_RAID5):
        whole = _column(extents, disks)
        if whole is None:
            raise LdmError("The volume needs a disk that is not here")
        return whole
    columns = component['columns'] or len({e['column'] for e in extents})
    readers = []
    for column in range(columns):
        reader = _column([e for e in extents if e['column'] == column],
                         disks)
        readers.append(reader)
    if component['kind'] == KIND_STRIPED and None in readers:
        raise LdmError("A striped volume needs every disk")
    sizes = [r.size for r in readers if r is not None]
    members = [(r.read, r.size) if r is not None else None
               for r in readers]
    present = [m for m in members if m is not None]
    order = [present.index(m) if m is not None else None for m in members]
    params = hwraid.Params('0' if component['kind'] == KIND_STRIPED
                           else '5', component['chunk'] or 65536,
                           'left-symmetric', 0, order)
    reader = hwraid.build(present, params)
    reader.size = min(reader.size, min(sizes) * (
        columns - (1 if component['kind'] == KIND_RAID5 else 0)))
    return reader

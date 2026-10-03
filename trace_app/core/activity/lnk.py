"""Windows shortcut (.lnk) files, [MS-SHLLINK].

A shortcut records what it points at as it was when it was made or last
used: the target's path (local or on a share), its size and its three times,
the volume's serial number and label, and -- in the tracker block -- the
NetBIOS name of the machine and the MAC address the target was on. Windows
writes one to Recent every time a user opens a file, which is why they matter.
"""

import struct

from trace_app.core.activity import shellitems, times

HEADER = b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00' \
         b'\x00\x00\x00\x46'

_HAS_ID_LIST = 0x01
_HAS_LINK_INFO = 0x02
_HAS_NAME = 0x04
_HAS_RELATIVE_PATH = 0x08
_HAS_WORKING_DIR = 0x10
_HAS_ARGUMENTS = 0x20
_HAS_ICON = 0x40
_IS_UNICODE = 0x80

_DRIVE_TYPES = {0: 'unknown', 1: 'no root', 2: 'removable', 3: 'fixed',
                4: 'network', 5: 'CD-ROM', 6: 'RAM disk'}


class LnkError(ValueError):
    """Not a shortcut this parser understands."""


def _string_at(data, at, unicode):
    if at <= 0 or at >= len(data):
        return ''
    if unicode:
        end = at
        while end + 1 < len(data) and data[end:end + 2] != b'\x00\x00':
            end += 2
        return data[at:end].decode('utf-16-le', 'replace')
    end = data.find(b'\x00', at)
    return data[at:end if end != -1 else len(data)].decode('cp1252',
                                                           'replace')


def parse(data):
    """A dict describing one shortcut; raises LnkError."""
    if len(data) < 76 or data[:20] != HEADER:
        raise LnkError("no shell link header")
    flags, attributes, created, accessed, written, size = \
        struct.unpack_from('<IIQQQI', data, 20)
    out = {
        'target_created': times.filetime(created),
        'target_accessed': times.filetime(accessed),
        'target_modified': times.filetime(written),
        'target_size': size,
        'attributes': attributes,
    }
    at = 76
    try:
        if flags & _HAS_ID_LIST:
            id_size = struct.unpack_from('<H', data, at)[0]
            items = shellitems.parse_id_list(data[at + 2:at + 2 + id_size])
            out['id_list_path'] = shellitems.join_path(items)
            files = [i for i in items if i.get('mft_entry')]
            if files:
                out['target_mft'] = (files[-1]['mft_entry'],
                                     files[-1]['mft_sequence'])
            at += 2 + id_size

        if flags & _HAS_LINK_INFO:
            info_size = struct.unpack_from('<I', data, at)[0]
            info = data[at:at + info_size]
            at += info_size
            out.update(_link_info(info))

        unicode = bool(flags & _IS_UNICODE)
        for flag, key in ((_HAS_NAME, 'description'),
                          (_HAS_RELATIVE_PATH, 'relative_path'),
                          (_HAS_WORKING_DIR, 'working_dir'),
                          (_HAS_ARGUMENTS, 'arguments'),
                          (_HAS_ICON, 'icon')):
            if flags & flag:
                count = struct.unpack_from('<H', data, at)[0]
                width = 2 if unicode else 1
                raw = data[at + 2:at + 2 + count * width]
                out[key] = raw.decode('utf-16-le' if unicode else 'cp1252',
                                      'replace')
                at += 2 + count * width

        out.update(_extra_blocks(data, at))
    except (struct.error, IndexError):
        pass                    # keep what was read; a tail can be damaged

    out['target'] = (out.get('local_path') or out.get('network_path')
                     or out.get('id_list_path') or out.get('relative_path')
                     or '')
    return out


def _link_info(info):
    out = {}
    if len(info) < 28:
        return out
    header_size, info_flags, volume_at, base_at, network_at, suffix_at = \
        struct.unpack_from('<IIIIII', info, 4)
    unicode_base = unicode_suffix = 0
    if header_size >= 0x24 and len(info) >= 36:
        unicode_base, unicode_suffix = struct.unpack_from('<II', info, 28)
    suffix = (_string_at(info, unicode_suffix, True) if unicode_suffix
              else _string_at(info, suffix_at, False))
    if info_flags & 1:
        volume = info[volume_at:]
        if len(volume) >= 16:
            drive_type, serial, label_at = struct.unpack_from('<III', volume, 4)
            if label_at == 0x14 and len(volume) >= 20:
                label = _string_at(volume, struct.unpack_from(
                    '<I', volume, 16)[0], True)
            else:
                label = _string_at(volume, label_at, False)
            out['drive_type'] = _DRIVE_TYPES.get(drive_type, str(drive_type))
            out['volume_serial'] = f'{serial:08X}'
            out['volume_label'] = label
        base = (_string_at(info, unicode_base, True) if unicode_base
                else _string_at(info, base_at, False))
        out['local_path'] = base + suffix
    if info_flags & 2:
        link = info[network_at:]
        if len(link) >= 20:
            net_name_at = struct.unpack_from('<I', link, 8)[0]
            share = _string_at(link, net_name_at, False)
            if len(link) >= 28 and net_name_at > 0x14:
                unicode_at = struct.unpack_from('<I', link, 20)[0]
                share = _string_at(link, unicode_at, True) or share
            out['network_path'] = share + ('\\' + suffix if suffix else '')
    return out


def _extra_blocks(data, at):
    out = {}
    while at + 8 <= len(data):
        size, signature = struct.unpack_from('<II', data, at)
        if size < 8:
            break
        block = data[at:at + size]
        if signature == 0xA0000003 and size >= 0x60:     # tracker
            machine = block[16:32].split(b'\x00', 1)[0].decode('ascii',
                                                               'replace')
            out['machine_id'] = machine
            droid_file = block[48:64]
            # A version-1 UUID ends in the node: the MAC address of the
            # machine that made it.
            if len(droid_file) == 16 and (droid_file[7] >> 4) == 1:
                out['mac_address'] = ':'.join(
                    f'{b:02x}' for b in droid_file[10:16])
        at += size
    return out

"""What to call a partition (no Qt).

The Sleuth Kit describes a slot of the partition table with a short text:
a GPT partition's *name* -- optional, and blank on what Fedora's installer
and many others write -- an MBR partition's type ('NTFS / exFAT (0x07)'),
or its own bookkeeping ('Safety Table', 'GPT Header', 'Unallocated').
TRACE used to show these as 'vol0', 'vol1'... and dropped a GPT partition
with no name altogether, file systems and all.

Here each slot gets the name an examiner expects, as other forensic tools
give it: a GPT partition its own name, else its *type* -- read from the
GPT entry, whose type GUID pytsk3 does not expose ('EFI System Partition',
'Linux Filesystem', 'Microsoft Basic Data'...) -- followed by '@ <start
sector>' so two of one type stay apart; the bookkeeping slots 'Protective
MBR', 'GPT Header', 'GPT Partition Table', 'Master Boot Record',
'Extended Partition Table' and 'Unallocated Space'.
"""

import struct
import uuid

#: Well-known GPT partition type GUIDs (UEFI spec, Microsoft, the
#: Discoverable Partitions Specification, Apple, FreeBSD).
GPT_TYPES = {
    'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': 'EFI System Partition',
    '21686148-6449-6E6F-744E-656564454649': 'BIOS Boot Partition',
    '024DEE41-33E7-11D3-9D69-0008C781F39F': 'MBR Partition Scheme',
    'E3C9E316-0B5C-4DB8-817D-F92DF00215AE': 'Microsoft Reserved',
    'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7': 'Microsoft Basic Data',
    'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC': 'Windows Recovery',
    '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3': 'Windows LDM Metadata',
    'AF9B60A0-1431-4F62-BC68-3311714A69AD': 'Windows LDM Data',
    'E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D': 'Windows Storage Spaces',
    '0FC63DAF-8483-4772-8E79-3D69D8477DE4': 'Linux Filesystem',
    '44479540-F297-41B2-9AF7-D131D5F0458A': 'Linux Root (x86)',
    '4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709': 'Linux Root (x86-64)',
    'B921B045-1DF0-41C3-AF44-4C6F280D3FAE': 'Linux Root (ARM64)',
    '69DAD710-2CE4-4E3C-B16C-21A1D49ABED3': 'Linux Root (ARM)',
    '933AC7E1-2EB4-4F13-B844-0E14E2AEF915': 'Linux /home',
    '3B8F8425-20E0-4F3B-907F-1A25A76F98E8': 'Linux /srv',
    '4D21B016-B534-45C2-A9FB-5C16E091FD2D': 'Linux /var',
    '7EC6F557-3BC5-4ACA-B293-16EF5DF639D1': 'Linux /var/tmp',
    'BC13C2FF-59E6-4262-A352-B275FD6F7172': 'Linux /boot',
    '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F': 'Linux Swap',
    'E6D6D379-F507-44C2-A23C-238F2A3DF928': 'Linux LVM',
    'A19D880F-05FC-4D3B-A006-743F0F84911E': 'Linux RAID',
    'CA7D7CCB-63ED-4C53-861C-1742536059CC': 'Linux LUKS',
    '8DA63339-0007-60C0-C436-083AC8230908': 'Linux Reserved',
    '7C3457EF-0000-11AA-AA11-00306543ECAC': 'Apple APFS',
    '48465300-0000-11AA-AA11-00306543ECAC': 'Apple HFS+',
    '55465300-0000-11AA-AA11-00306543ECAC': 'Apple UFS',
    '426F6F74-0000-11AA-AA11-00306543ECAC': 'Apple Boot',
    '52414944-0000-11AA-AA11-00306543ECAC': 'Apple RAID',
    '53746F72-6167-11AA-AA11-00306543ECAC': 'Apple Core Storage',
    '516E7CB4-6ECF-11D6-8FF8-00022D09712B': 'FreeBSD Data',
    '83BD6B9D-7F41-11DC-BE0B-001560B84F0F': 'FreeBSD Boot',
    '516E7CB5-6ECF-11D6-8FF8-00022D09712B': 'FreeBSD Swap',
    '516E7CB6-6ECF-11D6-8FF8-00022D09712B': 'FreeBSD UFS',
    '516E7CBA-6ECF-11D6-8FF8-00022D09712B': 'FreeBSD ZFS',
    '6A898CC3-1DD2-11B2-99A6-080020736631': 'ZFS',
}

#: The Sleuth Kit's bookkeeping slots, by the start of its description.
_BOOKKEEPING = (('Safety Table', 'Protective MBR'),
                ('GPT Header', 'GPT Header'),
                ('Partition Table', 'GPT Partition Table'),
                ('Primary Table', 'Master Boot Record'),
                ('Extended Table', 'Extended Partition Table'),
                ('Unallocated', 'Unallocated Space'))


def gpt_entries(read, sector_size=512):
    """{first sector: (type GUID, name)} of a GPT disk, read with
    `read(offset, length)`; {} when the disk has no GPT."""
    for size in dict.fromkeys((sector_size, 512, 4096)):
        try:
            header = read(size, 92)
        except Exception:
            return {}
        if len(header) < 92 or header[:8] != b'EFI PART':
            continue
        lba, count, entry_size = struct.unpack_from('<QII', header, 72)
        if not 0 < count <= 1024 or entry_size < 128:
            return {}
        try:
            table = read(lba * size, count * entry_size)
        except Exception:
            return {}
        found = {}
        for index in range(count):
            entry = table[index * entry_size:(index + 1) * entry_size]
            if len(entry) < 128 or not any(entry[:16]):
                continue
            kind = str(uuid.UUID(bytes_le=bytes(entry[:16]))).upper()
            first = struct.unpack_from('<Q', entry, 32)[0]
            name = entry[56:128].decode('utf-16-le', 'replace') \
                .split('\0', 1)[0].strip()
            # The table counts in its own sector size; TSK in the image's.
            found[first * size // sector_size] = (kind, name)
        return found
    return {}


def bookkeeping(description):
    """The name of a table or free-space slot, or None for a partition."""
    for prefix, name in _BOOKKEEPING:
        if description.startswith(prefix):
            return name
    return None


def label(description, start, gpt=None):
    """What the examiner sees for one slot: 'EFI System Partition @ 2048',
    'Linux Filesystem @ 4198400', 'Microsoft Basic Data @ 1050624',
    'NTFS / exFAT (0x07) @ 63', 'GPT Header', 'Unallocated Space @ 0'."""
    text = description.decode('utf-8', 'replace') \
        if isinstance(description, bytes) else (description or '')
    text = text.strip()
    if text == 'Unnamed partition':
        text = ''
    special = bookkeeping(text)
    if special is not None:
        return special if special != 'Unallocated Space' else \
            f"{special} @ {start}"
    entry = (gpt or {}).get(start)
    if entry is not None:
        kind, name = entry
        text = name or GPT_TYPES.get(kind, text or 'GPT Partition')
    return f"{text or 'Partition'} @ {start}"

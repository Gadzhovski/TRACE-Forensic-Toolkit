"""Partitions and their names (ImageHandler._get_partitions,
partition_label; core/partition_names.py).

A GPT partition's name is optional, and Fedora's installer leaves it
blank. TRACE 2.1.0 dropped every slot with no description -- for GPT,
every unnamed partition, and the file systems on them (three Fedora
images showed only their partition tables; their EFI, /boot and Btrfs
partitions were gone). The disk here is written in Python -- protective
MBR, GPT header and entries with their CRCs -- so the test needs no tool
and runs on every system.
"""

import struct
import uuid
import zlib

import pytest

SECTOR = 512
ESP = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'
LINUX = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
BASIC = 'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7'
#: (type, name, first sector, last sector)
LAYOUT = [(ESP, '', 2048, 4095), (LINUX, '', 4096, 8191),
          (BASIC, 'Data', 8192, 12287)]
DISK_SECTORS = 16384


def gpt_disk(path):
    disk = bytearray(DISK_SECTORS * SECTOR)
    # Protective MBR: one partition of type 0xEE over the disk.
    disk[446:462] = struct.pack('<B3sB3sII', 0, b'\x00\x02\x00', 0xEE,
                                b'\xff\xff\xff', 1, DISK_SECTORS - 1)
    disk[510:512] = b'\x55\xaa'
    entries = bytearray(128 * 128)
    for index, (kind, name, first, last) in enumerate(LAYOUT):
        entry = uuid.UUID(kind).bytes_le + uuid.uuid4().bytes_le + \
            struct.pack('<QQQ', first, last, 0) + \
            name.encode('utf-16-le').ljust(72, b'\0')
        entries[index * 128:(index + 1) * 128] = entry
    disk[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    header = bytearray(struct.pack(
        '<8sIIIIQQQQ16sQIII', b'EFI PART', 0x00010000, 92, 0, 0, 1,
        DISK_SECTORS - 1, 34, DISK_SECTORS - 34, uuid.uuid4().bytes_le, 2,
        128, 128, zlib.crc32(entries)))
    struct.pack_into('<I', header, 16, zlib.crc32(header))
    disk[SECTOR:SECTOR + 92] = header
    with open(path, 'wb') as handle:
        handle.write(disk)
    return str(path)


@pytest.fixture
def handler(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    image = ImageHandler(gpt_disk(tmp_path / 'gpt.dd'))
    assert image.loaded
    yield image
    image.close_resources()


def test_unnamed_gpt_partitions_are_kept(handler):
    starts = {start: desc for _a, desc, start, _l in handler.get_partitions()}
    # 2.1.0 kept only the tables, the free space and 'Data'.
    assert 2048 in starts and 4096 in starts and 8192 in starts
    assert starts[8192] == b'Data'


def test_partitions_are_named_as_forensic_tools_name_them(handler):
    names = [handler.partition_label(start, desc)
             for _a, desc, start, _l in handler.get_partitions()]
    assert names == ['Protective MBR', 'Unallocated Space @ 0',
                     'GPT Header', 'GPT Partition Table',
                     'EFI System Partition @ 2048',
                     'Linux Filesystem @ 4096', 'Data @ 8192',
                     'Unallocated Space @ 12288']


@pytest.mark.parametrize('description, expected', [
    (b'Primary Table (#0)', 'Master Boot Record'),
    (b'Extended Table (#1)', 'Extended Partition Table'),
    (b'NTFS / exFAT (0x07)', 'NTFS / exFAT (0x07) @ 63'),
    (b'Unnamed partition', 'Partition @ 63'),
    (b'Unallocated', 'Unallocated Space @ 63'),
])
def test_mbr_and_bookkeeping_names(description, expected):
    from trace_app.core.partition_names import label
    assert label(description, 63) == expected


def test_an_unknown_type_keeps_a_general_name():
    from trace_app.core.partition_names import label
    gpt = {2048: ('12345678-1234-1234-1234-123456789ABC', '')}
    assert label(b'Unnamed partition', 2048, gpt) == 'GPT Partition @ 2048'

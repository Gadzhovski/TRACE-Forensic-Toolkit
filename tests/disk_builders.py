"""Disks built in Python for the storage tests: RAID members striped by
a writer independent of TRACE's reader, and a FAT16 volume of PNGs that
only a right reconstruction reads as PNGs. Names no test image, so a
test importing it needs none (tools/ci_select.py reads imports)."""

import random

CHUNK = 4096


def stripe(data, disks, level, layout='left-asymmetric', delay=1,
           chunk=CHUNK):
    """Write `data` across `disks` the way a controller does -- the
    rotation spelled out row by row, independently of hwraid's reader."""
    parity = {'0': 0, '5': 1, '6': 2}[level]
    per_row = disks - parity
    rows = len(data) // (chunk * per_row)
    out = [bytearray() for _ in range(disks)]
    for row in range(rows):
        group = row // delay
        if parity:
            p_slot = (disks - 1 - group % disks) if layout.startswith(
                'left') else group % disks
            p_slots = [(p_slot + k) % disks for k in range(parity)]
        else:
            p_slots = []
        if layout.endswith('asymmetric') or not parity:
            data_slots = [s for s in range(disks) if s not in p_slots]
        else:
            data_slots = [(p_slots[-1] + 1 + k) % disks
                          for k in range(per_row)]
        cells = {}
        xor = 0
        for index, slot in enumerate(data_slots):
            start = (row * per_row + index) * chunk
            piece = data[start:start + chunk]
            cells[slot] = piece
            xor ^= int.from_bytes(piece, 'little')
        for slot in p_slots:
            # P is the XOR; Q (RAID6) is not read by hwraid: filler.
            cells[slot] = xor.to_bytes(chunk, 'little') if slot == \
                p_slots[0] else bytes(chunk)
        for slot in range(disks):
            out[slot] += cells[slot]
    return [bytes(d) for d in out], rows * per_row * chunk


def fat_volume_with_pngs():
    """A FAT16 volume (512-byte sectors, 2 sectors a cluster) holding
    eight different PNGs of ~50 KB -- several stripes each, so only the
    right reconstruction reads them as PNGs."""
    import struct
    import zlib
    sector, per_cluster, reserved, fats, root_entries = 512, 2, 4, 2, 512
    total = 2048 * 8
    # 2-sector clusters: ~8,000 of them -- FAT16 by the spec (FAT12
    # below 4,085, which is how a 16-bit FAT gets misread).
    fat_sectors = 32
    root_sectors = root_entries * 32 // sector
    data_start = reserved + fats * fat_sectors + root_sectors
    boot = bytearray(sector)
    boot[0:3] = b'\xeb\x3c\x90'
    boot[3:11] = b'MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', boot, 11, sector, per_cluster,
                     reserved, fats, root_entries, total, 0xF8, fat_sectors,
                     63, 255, 0, 0)
    boot[36:62] = struct.pack('<BBBI11s8s', 0x80, 0, 0x29, 0x1234,
                              b'TRACE RAID ', b'FAT16   ')
    boot[510:512] = b'\x55\xaa'
    image = bytearray(total * sector)
    image[0:sector] = boot
    fat = bytearray(fat_sectors * sector)
    struct.pack_into('<HH', fat, 0, 0xFFF8, 0xFFFF)
    root = bytearray(root_sectors * sector)
    cluster = 2
    rng = random.Random(7)
    for number in range(8):
        side = 128
        raw = b''.join(b'\0' + bytes(rng.getrandbits(8)
                                     for _ in range(side * 3))
                       for _row in range(side))

        def chunk(kind, body):
            return (struct.pack('>I', len(body)) + kind + body +
                    struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff))
        png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack(
            '>IIBBBBB', side, side, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(raw, 0)) + chunk(b'IEND', b''))
        clusters = -(-len(png) // (sector * per_cluster))
        for k in range(clusters):
            struct.pack_into('<H', fat, (cluster + k) * 2,
                             cluster + k + 1 if k < clusters - 1 else 0xFFFF)
        start = (data_start + (cluster - 2) * per_cluster) * sector
        image[start:start + len(png)] = png
        entry = struct.pack('<8s3sB10xHHHI', f'PIC{number}'.encode()
                            .ljust(8), b'PNG', 0x20, 0, 0x21, cluster,
                            len(png))
        root[number * 32:(number + 1) * 32] = entry
        cluster += clusters
    for copy in range(fats):
        at = (reserved + copy * fat_sectors) * sector
        image[at:at + len(fat)] = fat
    at = (reserved + fats * fat_sectors) * sector
    image[at:at + len(root)] = root
    return bytes(image)

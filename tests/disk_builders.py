"""Disks built in Python for the storage tests: RAID members striped by
a writer independent of TRACE's reader, and a FAT16 volume of PNGs that
only a right reconstruction reads as PNGs. Names no test image, so a
test importing it needs none (tools/testdata/ci_select.py reads imports)."""

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


def fat16_volume(files, total_sectors=2048 * 16, free=()):
    """A FAT16 volume (512-byte sectors, 4 sectors a cluster) holding
    `files` -- [(8.3 name, bytes)] in the root, each in contiguous
    clusters -- and `free`: [(byte offset in the volume, bytes)] written
    afterwards into space no file holds (offsets past the files' data)."""
    import struct
    sector, per_cluster, reserved, fats, root_entries = 512, 4, 4, 2, 512
    clusters_total = total_sectors // per_cluster
    fat_sectors = -(-(clusters_total + 2) * 2 // sector)
    root_sectors = root_entries * 32 // sector
    data_start = reserved + fats * fat_sectors + root_sectors
    boot = bytearray(sector)
    boot[0:3] = b'\xeb\x3c\x90'
    boot[3:11] = b'MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', boot, 11, sector, per_cluster,
                     reserved, fats, root_entries,
                     total_sectors if total_sectors < 65536 else 0, 0xF8,
                     fat_sectors, 63, 255, 0,
                     total_sectors if total_sectors >= 65536 else 0)
    boot[36:62] = struct.pack('<BBBI11s8s', 0x80, 0, 0x29, 0x5678,
                              b'TRACE TEST ', b'FAT16   ')
    boot[510:512] = b'\x55\xaa'
    image = bytearray(total_sectors * sector)
    image[0:sector] = boot
    fat = bytearray(fat_sectors * sector)
    struct.pack_into('<HH', fat, 0, 0xFFF8, 0xFFFF)
    root = bytearray(root_sectors * sector)
    cluster = 2
    placed = {}
    for number, (name, data) in enumerate(files):
        stem, _dot, extension = name.upper().partition('.')
        clusters = max(1, -(-len(data) // (sector * per_cluster)))
        for k in range(clusters):
            struct.pack_into('<H', fat, (cluster + k) * 2,
                             cluster + k + 1 if k < clusters - 1 else 0xFFFF)
        start = (data_start + (cluster - 2) * per_cluster) * sector
        image[start:start + len(data)] = data
        placed[name] = start
        root[number * 32:(number + 1) * 32] = struct.pack(
            '<8s3sB10xHHHI', stem.encode().ljust(8)[:8],
            extension.encode().ljust(3)[:3], 0x20, 0, 0x21,
            cluster if data else 0, len(data))
        cluster += clusters
    for copy in range(fats):
        at = (reserved + copy * fat_sectors) * sector
        image[at:at + len(fat)] = fat
    at = (reserved + fats * fat_sectors) * sector
    image[at:at + len(root)] = root
    for offset, data in free:
        image[offset:offset + len(data)] = data
    return bytes(image), placed, \
        (data_start + (cluster - 2) * per_cluster) * sector


def compound_file(streams):
    """A Compound File Binary (OLE) file, version 3, 512-byte sectors,
    holding `streams` -- {('Storage', 'Stream'): bytes} -- each at least
    4,096 bytes (so in regular sectors: this writer has no mini stream).
    Storages are made from the paths."""
    import struct
    sector = 512
    end, free, fat_mark = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    nostream = 0xFFFFFFFF
    # Directory: root, then every storage and stream.
    entries = [{'name': 'Root Entry', 'type': 5, 'children': []}]
    index_of = {(): 0}
    for path in sorted(streams):
        for depth in range(1, len(path) + 1):
            key = path[:depth]
            if key in index_of:
                continue
            is_stream = depth == len(path)
            assert not is_stream or len(streams[path]) >= 4096, path
            index_of[key] = len(entries)
            entries.append({'name': key[-1], 'type': 2 if is_stream else 1,
                            'children': [], 'data': streams.get(key)})
            entries[index_of[key[:-1]]]['children'].append(index_of[key])
    # Stream data first, then the directory, then the FAT.
    chains, sectors = {}, []
    for number, entry in enumerate(entries):
        if entry['type'] != 2:
            continue
        data = entry['data']
        count = -(-len(data) // sector)
        chains[number] = (len(sectors), count)
        for k in range(count):
            sectors.append(data[k * sector:(k + 1) * sector].ljust(sector,
                                                                    b'\0'))
    directory = bytearray()

    def sibling_tree(children):
        """Children as a binary tree in CFB order (length, then name in
        upper case), linked through right siblings."""
        ordered = sorted(children, key=lambda i: (
            len(entries[i]['name']), entries[i]['name'].upper()))
        for left, right in zip(ordered, ordered[1:]):
            entries[left]['right'] = right
        return ordered[0] if ordered else nostream
    for entry in entries:
        entry['child'] = sibling_tree(entry['children'])
    for number, entry in enumerate(entries):
        name = entry['name'].encode('utf-16-le') + b'\0\0'
        start, size = (chains[number][0], len(entry['data'])) \
            if number in chains else (end, 0)
        record = bytearray(128)
        record[0:len(name)] = name
        struct.pack_into('<HBBIII', record, 64, len(name), entry['type'], 1,
                         nostream, entry.get('right', nostream),
                         entry['child'])
        struct.pack_into('<IQ', record, 116, start, size)
        directory += record
    directory = bytes(directory.ljust(-(-len(directory) // sector) * sector,
                                      b'\0'))
    first_directory = len(sectors)
    directory_sectors = len(directory) // sector
    for k in range(directory_sectors):
        sectors.append(directory[k * sector:(k + 1) * sector])
    total = len(sectors)
    fat_sectors = 1
    while (total + fat_sectors) > fat_sectors * (sector // 4):
        fat_sectors += 1
    fat = [free] * (fat_sectors * (sector // 4))
    for start, count in chains.values():
        for k in range(count):
            fat[start + k] = start + k + 1 if k < count - 1 else end
    for k in range(directory_sectors):
        fat[first_directory + k] = first_directory + k + 1 \
            if k < directory_sectors - 1 else end
    first_fat = total
    for k in range(fat_sectors):
        fat[first_fat + k] = fat_mark
    assert fat_sectors <= 109
    header = bytearray(sector)
    header[0:8] = bytes.fromhex('D0CF11E0A1B11AE1')
    struct.pack_into('<HHHHH', header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into('<IIIIIIIII', header, 40, 0, fat_sectors,
                     first_directory, 0, 4096, end, 0, end, 0)
    difat = [first_fat + k for k in range(fat_sectors)]
    difat += [free] * (109 - len(difat))
    struct.pack_into('<109I', header, 76, *difat)
    body = b''.join(sectors) + struct.pack(f'<{len(fat)}I', *fat)
    return bytes(header) + body

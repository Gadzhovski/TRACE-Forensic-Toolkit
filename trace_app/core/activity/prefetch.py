"""Windows Prefetch files: which programs ran, how often, and when.

Versions 17 (XP/2003), 23 (Vista/7), 26 (8/8.1) and 30/31 (10/11). Since
Windows 10 the file is compressed with LZXPRESS Huffman behind a "MAM"
header, which lzxpress.py undoes. Windows 8 and later keep the last eight run
times, earlier versions only the last.
"""

import struct

from trace_app.core.activity import lzxpress, times

#: Where each version keeps the last run time(s) and the run count.
_LAYOUT = {
    17: {'times': 120, 'slots': 1, 'count': 144},
    23: {'times': 128, 'slots': 1, 'count': 152},
    26: {'times': 128, 'slots': 8, 'count': 208},
    30: {'times': 128, 'slots': 8, 'count': 208},
    31: {'times': 128, 'slots': 8, 'count': 208},
}


class PrefetchError(ValueError):
    """Not a Prefetch file this parser understands."""


def decompress(data):
    """The SCCA body of a Prefetch file, decompressed if it needs to be."""
    if data[:3] == b'MAM':
        if len(data) < 8:
            raise PrefetchError("truncated compressed header")
        kind = data[3]
        size = struct.unpack_from('<I', data, 4)[0]
        if kind & 0x0F != 4:
            raise PrefetchError(f"compression type {kind:#x} is not Huffman")
        if size > 64 * 1024 * 1024:
            raise PrefetchError("implausible decompressed size")
        # 0x80: a CRC32 follows the size before the compressed data.
        start = 12 if kind & 0x80 else 8
        try:
            return lzxpress.decompress(data[start:], size)
        except (lzxpress.DecompressionError, struct.error, IndexError) as exc:
            raise PrefetchError(f"could not decompress: {exc}") from exc
    return data


def parse(data):
    """A dict describing one Prefetch file; raises PrefetchError."""
    body = decompress(data)
    if len(body) < 84 or body[4:8] != b'SCCA':
        raise PrefetchError("no SCCA signature")
    version = struct.unpack_from('<I', body, 0)[0]
    layout = _LAYOUT.get(version)
    if layout is None:
        raise PrefetchError(f"unknown Prefetch version {version}")

    name = body[16:76].decode('utf-16-le', 'replace').split('\x00', 1)[0]
    prefetch_hash = struct.unpack_from('<I', body, 76)[0]
    (strings_offset, strings_size, volumes_offset, volumes_count,
     volumes_size) = struct.unpack_from('<IIIII', body, 100)

    count_at = layout['count']
    # Windows 10's second layout drops 8 bytes before the run count; the
    # metrics array, which follows the header, then starts 8 bytes earlier.
    metrics_offset = struct.unpack_from('<I', body, 84)[0]
    if version >= 30 and metrics_offset == 296:
        count_at = 200
    run_count = struct.unpack_from('<I', body, count_at)[0]

    runs = []
    for slot in range(layout['slots']):
        value = struct.unpack_from('<Q', body, layout['times'] + 8 * slot)[0]
        stamp = times.filetime(value)
        if stamp is not None:
            runs.append(stamp)

    files = []
    if 0 < strings_offset < len(body) and strings_size:
        raw = body[strings_offset:strings_offset + strings_size]
        files = [f for f in raw.decode('utf-16-le', 'replace').split('\x00')
                 if f]

    volumes = []
    entry_size = 40 if version == 17 else 104 if version in (23, 26) else 96
    for index in range(min(volumes_count, 64)):
        at = volumes_offset + index * entry_size
        if at + 20 > len(body):
            break
        path_offset, path_length, created, serial = \
            struct.unpack_from('<IIQI', body, at)
        path_at = volumes_offset + path_offset
        device = body[path_at:path_at + 2 * path_length].decode(
            'utf-16-le', 'replace')
        volumes.append({'device': device, 'serial': f'{serial:08X}',
                        'created': times.iso(times.filetime(created))})

    # The name field holds 29 characters; a longer name is cut, so match the
    # loaded file whose name starts with it.
    upper = name.upper()
    executable_path = next(
        (f for f in files if f.upper().rsplit('\\', 1)[-1] == upper), '') \
        or next((f for f in files
                 if f.upper().rsplit('\\', 1)[-1].startswith(upper)), '')
    return {
        'version': version,
        'executable': name,
        'path': executable_path,
        'hash': f'{prefetch_hash:08X}',
        'run_count': run_count,
        'runs': runs,                   # newest first
        'files': files,
        'volumes': volumes,
    }

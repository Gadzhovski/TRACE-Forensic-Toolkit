"""Is an E01 whole? (no Qt)

libewf opens a segment set with files missing or cut short and fails only
when a read reaches the gap -- 'missing segment file for offset ...' from
deep inside a file view, long after the image looked fine. The set says
itself whether it is whole: every segment file but the last ends with a
'next' section, the last with 'done', and segment numbers run 1, 2, 3...
`problem(paths)` reads that chain (EWF version 1: E01, S01, L01; an Ex01
is EWF2 and is not checked) and says what is wrong, or None.
`data_end(read, size)` finds where the readable data stops.
"""

import os
import struct

EWF1_SIGNATURES = (b'EVF\x09\x0d\x0a\xff\x00', b'LVF\x09\x0d\x0a\xff\x00')
HEADER = 13            # signature, fields start, segment number, fields end
DESCRIPTOR = 76        # type[16], next u64, size u64, padding, checksum


def _segment(path):
    """(segment number, last section type or None if the chain breaks,
    where it broke) -- or None for a file that is not EWF version 1."""
    size = os.path.getsize(path)
    with open(path, 'rb') as handle:
        head = handle.read(HEADER)
        if len(head) < HEADER or head[:8] not in EWF1_SIGNATURES:
            return None
        number = struct.unpack_from('<H', head, 9)[0]
        offset, last, seen = HEADER, None, set()
        while offset not in seen:
            seen.add(offset)
            if offset + DESCRIPTOR > size:
                return number, None, last
            handle.seek(offset)
            descriptor = handle.read(DESCRIPTOR)
            kind = descriptor[:16].rstrip(b'\0').decode('ascii', 'replace')
            following = struct.unpack_from('<Q', descriptor, 16)[0]
            if kind in ('next', 'done'):
                return number, kind, kind
            last = kind
            if following <= offset or following > size:
                return number, None, kind
            offset = following
        return number, None, last


def problem(paths):
    """What is missing from the segment set `paths` (libewf's glob), as a
    sentence, or None when it is whole (or not EWF version 1)."""
    segments = []
    for path in sorted(paths):
        try:
            found = _segment(path)
        except OSError:
            return None
        if found is None:
            return None
        segments.append((found[0], path, found[1], found[2]))
    if not segments:
        return None
    segments.sort()
    numbers = [s[0] for s in segments]
    expected = list(range(1, len(numbers) + 1))
    if numbers != expected:
        gaps = sorted(set(range(1, numbers[-1] + 1)) - set(numbers))
        if gaps:
            return (f"segment {', '.join(str(g) for g in gaps)} of the "
                    f"set {'is' if len(gaps) == 1 else 'are'} missing")
    for number, path, kind, where in segments:
        name = os.path.basename(path)
        if kind is None:
            return (f"{name} breaks off after its "
                    f"'{where}' section, without the section that closes "
                    f"a segment file -- the acquisition stopped or the "
                    f"file was truncated")
        if kind == 'next' and number == numbers[-1]:
            return (f"{name} says more segment files follow, and none "
                    f"is here (segment {number + 1} onwards)")
    return None


def data_end(read, size, step=32768):
    """The first byte offset (a multiple of `step`) from which `read`
    fails, assuming the readable data is a prefix -- how much of an
    incomplete set is there. `size` if everything reads."""
    def readable(offset):
        try:
            read(offset, 1)
            return True
        except Exception:
            return False
    if size <= 0 or readable(size - 1):
        return size
    if not readable(0):
        return 0
    low, high = 0, (size - 1) // step        # readable, not readable
    while high - low > 1:
        middle = (low + high) // 2
        if readable(middle * step):
            low = middle
        else:
            high = middle
    return high * step

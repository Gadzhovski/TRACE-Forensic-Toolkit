"""Registry hive transaction logs (.LOG1 / .LOG2) applied in memory, so a
hive is read with the changes Windows had logged but not yet written into
it.

Since Windows 8.1 a hive is written lazily: changes go to its logs first,
and the primary file catches up later. A hive taken from a running
system, or one shut down uncleanly, is "dirty" -- its two sequence numbers
differ -- and its newest keys and values exist only in the logs. Reading
the primary alone misses them (Registry Explorer and regipy replay the
logs for the same reason).

Following the Windows registry file format specification (M. Suhanov):

* New format (Windows 8.1+). After a 512-byte base block, log entries:
  'HvLE', size, flags, sequence number, hive bins data size, dirty page
  count, Hash-1 and Hash-2 (Marvin32), the dirty page references (offset
  in the hive bins data, size) and the pages. An entry counts only if
  both hashes match -- Hash-2 over its first 32 bytes, Hash-1 over
  everything from its references on. Entries are applied in sequence
  order from the primary's secondary sequence number on, taking each
  number from whichever of the two logs holds a valid entry for it, and
  stopping at the first number neither holds.
* Old format (Vista to 8): 'DIRT' after the base block, a bitmap with one
  bit per 512-byte page of the hive bins data, and the dirty pages from
  the next sector on, in bitmap order.

Afterwards the base block says the hive is clean (both sequence numbers
one past the last entry applied), carries the last entry's hive bins data
size, and its checksum is recomputed. The primary file itself is never
touched: this returns new bytes.
"""

import logging
import struct

logger = logging.getLogger('TRACE.RegistryLogs')

BASE_BLOCK = 4096           # in the primary file
LOG_BASE_BLOCK = 512        # in a log file
MARVIN_SEED = 0x82EF4D887A4E55C5
_MASK = 0xFFFFFFFF


def marvin32(data, seed=MARVIN_SEED):
    """The Marvin32 hash (64-bit) the registry uses for log entries."""
    lo, hi = seed & _MASK, seed >> 32

    def block(lo, hi):
        hi ^= lo
        lo = ((lo << 20) | (lo >> 12)) & _MASK
        lo = (lo + hi) & _MASK
        hi = ((hi << 9) | (hi >> 23)) & _MASK
        hi ^= lo
        lo = ((lo << 27) | (lo >> 5)) & _MASK
        lo = (lo + hi) & _MASK
        hi = ((hi << 19) | (hi >> 13)) & _MASK
        return lo, hi

    whole = len(data) // 4 * 4
    for (word,) in struct.iter_unpack('<I', data[:whole]):
        lo = (lo + word) & _MASK
        lo, hi = block(lo, hi)
    tail = data[whole:]
    final = 0x80 << (8 * len(tail))
    for index, byte in enumerate(tail):
        final |= byte << (8 * index)
    lo = (lo + final) & _MASK
    lo, hi = block(lo, hi)
    lo, hi = block(lo, hi)
    return (hi << 32) | lo


def checksum(base_block):
    """XOR-32 of the base block's first 508 bytes, as Windows writes it
    (0 becomes 1, -1 becomes -2)."""
    value = 0
    for (word,) in struct.iter_unpack('<I', base_block[:508]):
        value ^= word
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return value or 1


def is_dirty(hive):
    """Does the hive need its logs: a wrong checksum, or sequence numbers
    that differ?"""
    if len(hive) < BASE_BLOCK or hive[:4] != b'regf':
        return False
    primary, secondary = struct.unpack_from('<II', hive, 4)
    return primary != secondary or not _valid_base(hive)


def _valid_base(block):
    return len(block) >= 512 and block[:4] == b'regf' and \
        struct.unpack_from('<I', block, 508)[0] == checksum(block)


def _entry(log, position):
    """(size, flags, sequence, bins size, pages, hashes ok) of the log
    entry at `position`, or None when there is none there."""
    if position + 40 > len(log) or log[position:position + 4] != b'HvLE':
        return None
    size, flags, sequence, bins_size, count = struct.unpack_from(
        '<IIIII', log, position + 4)
    if size < 40 or size % 512 or position + size > len(log):
        return None
    entry = log[position:position + size]
    hash1, hash2 = struct.unpack_from('<QQ', entry, 24)
    good = marvin32(entry[:32]) == hash2 and marvin32(entry[40:]) == hash1
    pages = []
    data_at = 40 + count * 8
    if data_at > size:
        return None
    for index in range(count):
        offset, length = struct.unpack_from('<II', entry, 40 + index * 8)
        pages.append((offset, entry[data_at:data_at + length]))
        data_at += length
    if data_at > size:
        good = False
    return size, flags, sequence, bins_size, pages, good


def new_format_entries(log):
    """{sequence number: offset in the log} of every log entry whose hashes
    match, applicable or not -- what a log holds."""
    found = {}
    position = LOG_BASE_BLOCK
    while True:
        entry = _entry(log, position)
        if entry is None:
            break
        if entry[5]:
            found[entry[2]] = position
        position += entry[0]
    return found


def _log_chain(log, hive_secondary):
    """The entries of one new-format log that apply, in order: from the
    one numbered as its base block's primary sequence number (no lower
    than the hive's secondary one), consecutively; stopping at a gap, a
    wrong hash or a hive bins size that is not whole pages.
    [(sequence, bins size, flags, [(offset, bytes)])]."""
    if not _valid_base(log) or struct.unpack_from('<I', log, 28)[0] != 6:
        return []
    expected = struct.unpack_from('<I', log, 4)[0]
    if expected < hive_secondary:
        return []
    chain = []
    position = LOG_BASE_BLOCK
    while True:
        entry = _entry(log, position)
        if entry is None:
            break
        size, flags, sequence, bins_size, pages, good = entry
        position += size
        if sequence < expected:              # already applied before
            continue
        if sequence != expected or bins_size % 4096 or not good:
            break
        chain.append((sequence, bins_size, flags, pages))
        expected += 1
    return chain


def _old_format_pages(log, bins_size):
    """[(offset, page)] from a Vista-to-8 log ('DIRT' and a bitmap)."""
    if log[LOG_BASE_BLOCK:LOG_BASE_BLOCK + 4] != b'DIRT':
        return []
    bitmap_length = bins_size // 512 // 8
    bitmap = log[LOG_BASE_BLOCK + 4:LOG_BASE_BLOCK + 4 + bitmap_length]
    data_at = LOG_BASE_BLOCK + 4 + bitmap_length
    data_at += -data_at % 512
    pages = []
    for bit in range(len(bitmap) * 8):
        if bitmap[bit // 8] >> (bit % 8) & 1:
            page = log[data_at:data_at + 512]
            if len(page) < 512:
                break
            pages.append((bit * 512, page))
            data_at += 512
    return pages


def recover(hive, logs):
    """(bytes, facts): the hive with its logs applied, and what was done --
    {'dirty', 'applied' (entries, or pages for the old format),
    'sequence' (first, last), 'format', 'logs' (the names used)}.
    The same bytes, applied 0, when the hive is clean or no log applies.
    `logs` is [(name, bytes)]."""
    facts = {'dirty': is_dirty(hive), 'applied': 0, 'format': None,
             'logs': []}
    if not facts['dirty']:
        return hive, facts
    logs = [(name, log) for name, log in logs if log and _valid_base(log)]
    if not logs:
        return hive, facts
    out = bytearray(hive)
    secondary = struct.unpack_from('<I', hive, 8)[0]
    if not _valid_base(hive):
        # The primary's own base block is damaged: the log with the latest
        # entries supplies it, and only that log is used.
        name, best = max(logs, key=lambda pair: struct.unpack_from(
            '<I', pair[1], 4)[0])
        out[:512] = best[:512]
        struct.pack_into('<I', out, 28, 0)
        logs = [(name, best)]
        secondary = 0

    def write(offset, data):
        at = BASE_BLOCK + offset
        if len(out) < at + len(data):
            out.extend(b'\x00' * (at + len(data) - len(out)))
        out[at:at + len(data)] = data

    chains = []
    for name, log in logs:
        chain = _log_chain(log, secondary)
        if chain:
            chains.append((chain[0][0], name, chain))
    chains.sort(key=lambda item: item[0])
    last = None
    for _first, name, chain in chains:
        if last is not None:
            # The next log resumes exactly where the previous one stopped.
            chain = [e for e in chain if e[0] > last[0]]
            if not chain or chain[0][0] != last[0] + 1:
                continue
        for sequence, bins_size, flags, pages in chain:
            if len(out) < BASE_BLOCK + bins_size:
                out.extend(b'\x00' * (BASE_BLOCK + bins_size - len(out)))
            for offset, data in pages:
                write(offset, data)
            last = (sequence, bins_size, flags)
            facts['applied'] += 1
        facts['logs'].append(name)
    if last is not None:
        facts['format'] = 'new'
        facts['sequence'] = (chains[0][0], last[0])
        struct.pack_into('<II', out, 4, last[0], last[0])
        struct.pack_into('<I', out, 40, last[1])
        flags = struct.unpack_from('<I', out, 144)[0]
        struct.pack_into('<I', out, 144, (flags & ~1) | (last[2] & 1))
    else:
        # The old format: a log written with the primary (the same last
        # written time) that says it is whole (equal sequence numbers).
        stamp = hive[12:20]
        usable = [(n, l) for n, l in logs
                  if l[LOG_BASE_BLOCK:LOG_BASE_BLOCK + 4] == b'DIRT'
                  and l[12:20] == stamp and l[4:8] == l[8:12]]
        if not usable:
            return hive, facts
        name, log = usable[0]
        bins_size = struct.unpack_from('<I', log, 40)[0]
        pages = _old_format_pages(log, bins_size)
        if not pages:
            return hive, facts
        for offset, page in pages:
            write(offset, page)
        facts.update(format='old', applied=len(pages), logs=[name])
        sequence = struct.unpack_from('<I', log, 4)[0]
        struct.pack_into('<II', out, 4, sequence, sequence)
        struct.pack_into('<I', out, 40, bins_size)
    struct.pack_into('<I', out, 508, checksum(out[:512]))
    return bytes(out), facts

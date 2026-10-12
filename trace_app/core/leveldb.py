"""LevelDB databases, read in Python (no Qt).

Chromium (Chrome, Edge, Brave) and every Electron app -- Teams, Slack,
Discord, WhatsApp and Signal Desktop -- keep Local Storage, Session Storage
and IndexedDB in LevelDB. A database is a folder of files:

* `*.log`: the write-ahead log, in 32 KiB blocks of records (a masked
  CRC-32C, a length, a type: FULL / FIRST / MIDDLE / LAST), each whole
  record a write batch -- a sequence number, a count, then puts (key and
  value) and deletions (key);
* `*.ldb` / `*.sst`: sorted tables -- data blocks of prefix-compressed
  entries with restart points, an index block naming them, a 48-byte
  footer; each block raw or Snappy-compressed, with a masked CRC-32C. Keys
  in a table are "internal keys": the user key, then 8 bytes of sequence
  number and kind.

Every version is read, not only the newest: until compaction rewrites a
table, an overwritten value and a deleted key's last value are still
there, and that is what an examiner wants as much as the current state.
`records(folder)` gives them all; `live(records)` the current view, and
`superseded(records)` what was overwritten or deleted.
"""

import logging
import os
import struct

logger = logging.getLogger('TRACE.LevelDB')

BLOCK = 32 * 1024
TABLE_MAGIC = 0xDB4775248B80FB57
KIND_DELETE, KIND_PUT = 0, 1
_FULL, _FIRST, _MIDDLE, _LAST = 1, 2, 3, 4


class LevelDBError(Exception):
    """A file that is not LevelDB's."""


class Record:
    __slots__ = ('key', 'value', 'sequence', 'kind', 'source', 'verified')

    def __init__(self, key, value, sequence, kind, source, verified):
        self.key, self.value, self.sequence = key, value, sequence
        self.kind, self.source, self.verified = kind, source, verified

    @property
    def deleted(self):
        return self.kind == KIND_DELETE

    def __repr__(self):
        return (f"Record({self.key!r}, seq={self.sequence}, "
                f"{'del' if self.deleted else 'put'})")


def masked_crc(data):
    import crc32c
    crc = crc32c.crc32c(data)
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def varint(data, position):
    """(value, position after) of a LevelDB varint."""
    result = shift = 0
    while True:
        if position >= len(data):
            raise LevelDBError("varint runs past the data")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 63:
            raise LevelDBError("varint too long")


def _slice(data, position):
    length, position = varint(data, position)
    end = position + length
    if end > len(data):
        raise LevelDBError("slice runs past the data")
    return bytes(data[position:end]), end


# --- the log -----------------------------------------------------------------------

def log_batches(data):
    """(batch bytes, verified) for each whole write batch in a log. A
    record whose CRC fails is kept (verified False) when its length makes
    sense: a torn tail is evidence too."""
    pending, verified = None, True
    for block in range(0, len(data), BLOCK):
        position, end = block, min(block + BLOCK, len(data))
        while position + 7 <= end:
            crc, length, kind = struct.unpack_from('<IHB', data, position)
            if kind == 0 and length == 0:
                break                         # zero padding: the block's end
            body = data[position + 7:position + 7 + length]
            if len(body) < length or position + 7 + length > end:
                break
            ok = masked_crc(bytes([kind]) + body) == crc
            position += 7 + length
            if kind == _FULL:
                yield body, ok
                pending = None
            elif kind == _FIRST:
                pending, verified = bytearray(body), ok
            elif kind in (_MIDDLE, _LAST) and pending is not None:
                pending += body
                verified = verified and ok
                if kind == _LAST:
                    yield bytes(pending), verified
                    pending = None


def batch_records(batch, source, verified=True):
    """The puts and deletions of one write batch, in order."""
    if len(batch) < 12:
        return []
    sequence, count = struct.unpack_from('<QI', batch, 0)
    out, position = [], 12
    for index in range(count):
        if position >= len(batch):
            break
        kind = batch[position]
        position += 1
        try:
            key, position = _slice(batch, position)
            value = b''
            if kind == KIND_PUT:
                value, position = _slice(batch, position)
            elif kind != KIND_DELETE:
                break
        except LevelDBError:
            break
        out.append(Record(key, value, sequence + index, kind, source,
                          verified))
    return out


# --- tables ---------------------------------------------------------------------------

def _block(data, offset, size):
    """A table block's contents, decompressed, and whether its CRC holds."""
    raw = data[offset:offset + size]
    trailer = data[offset + size:offset + size + 5]
    if len(raw) < size or len(trailer) < 5:
        raise LevelDBError("block runs past the table")
    kind = trailer[0]
    ok = masked_crc(raw + bytes([kind])) == struct.unpack_from(
        '<I', trailer, 1)[0]
    if kind == 1:
        from trace_app.core.snappy import decompress
        raw = decompress(raw)
    elif kind != 0:
        raise LevelDBError(f"unknown block compression {kind}")
    return bytes(raw), ok


def block_entries(block):
    """(key, value) of a block's entries (prefix compression undone)."""
    if len(block) < 4:
        return
    restarts = struct.unpack_from('<I', block, len(block) - 4)[0]
    end = len(block) - 4 - 4 * restarts
    if end < 0:
        raise LevelDBError("bad restart count")
    position, key = 0, b''
    while position < end:
        shared, position = varint(block, position)
        unshared, position = varint(block, position)
        size, position = varint(block, position)
        key = key[:shared] + bytes(block[position:position + unshared])
        position += unshared
        value = bytes(block[position:position + size])
        position += size
        yield key, value


def _handle(data, position):
    offset, position = varint(data, position)
    size, position = varint(data, position)
    return offset, size, position


def table_records(data, source):
    """Every entry of a table file, its internal key split."""
    if len(data) < 48 or struct.unpack_from('<Q', data, len(data) - 8)[0] \
            != TABLE_MAGIC:
        raise LevelDBError("not a LevelDB table")
    footer = data[len(data) - 48:]
    _meta_offset, _meta_size, position = _handle(footer, 0)
    index_offset, index_size, _position = _handle(footer, position)
    index, index_ok = _block(data, index_offset, index_size)
    out = []
    for _separator, handle in block_entries(index):
        offset, size, _position = _handle(handle, 0)
        try:
            block, ok = _block(data, offset, size)
        except LevelDBError as exc:
            logger.debug("%s: block at %d unreadable: %s", source, offset,
                         exc)
            continue
        for internal, value in block_entries(block):
            if len(internal) < 8:
                continue
            tag = struct.unpack_from('<Q', internal, len(internal) - 8)[0]
            out.append(Record(internal[:-8], value, tag >> 8, tag & 0xFF,
                              source, ok and index_ok))
    return out


# --- a database -------------------------------------------------------------------------

def records_from_files(files):
    """Every record in `files` -- [(name, bytes)] of a database folder's
    .log and .ldb/.sst files -- oldest sequence first."""
    out = []
    for name, data in files:
        lowered = name.lower()
        try:
            if lowered.endswith('.log'):
                for batch, ok in log_batches(data):
                    out += batch_records(batch, name, ok)
            elif lowered.endswith(('.ldb', '.sst')):
                out += table_records(data, name)
        except (LevelDBError, struct.error) as exc:
            logger.debug("%s not read: %s", name, exc)
    # The same version can sit in a log and the table it was flushed to.
    unique = {}
    for record in out:
        unique.setdefault((record.key, record.sequence, record.kind), record)
    return sorted(unique.values(), key=lambda r: (r.sequence, r.key))


def records(folder):
    """Every record of the database in `folder` (a path on disk)."""
    files = []
    for name in sorted(os.listdir(folder)):
        if name.lower().endswith(('.log', '.ldb', '.sst')):
            with open(os.path.join(folder, name), 'rb') as handle:
                files.append((name, handle.read()))
    return records_from_files(files)


def live(all_records):
    """{key: value} as the database reads now: each key's newest record,
    keys whose newest record is a deletion left out."""
    newest = {}
    for record in all_records:
        known = newest.get(record.key)
        if known is None or record.sequence >= known.sequence:
            newest[record.key] = record
    return {key: r.value for key, r in newest.items() if not r.deleted}


def superseded(all_records):
    """Records no longer current: values overwritten later, and the last
    value of every deleted key -- with the deletion's sequence."""
    by_key = {}
    for record in all_records:
        by_key.setdefault(record.key, []).append(record)
    out = []
    for key, versions in by_key.items():
        versions.sort(key=lambda r: r.sequence)
        for older, newer in zip(versions, versions[1:]):
            if not older.deleted:
                out.append((older, newer))
    return out


# --- writing (tests: an independent check of the reader) --------------------------

def write_varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)

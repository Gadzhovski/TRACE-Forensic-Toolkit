"""Finder's .DS_Store files (no Qt).

A .DS_Store is a small B-tree (Apple's "buddy allocator" file) of records
about the entries of one folder: icon positions, view settings, comments
-- and, in a Trash, where each item was before it was deleted ('ptbL', the
folder, and 'ptbN', its original name). Names stay listed after the files
themselves are gone, so a .DS_Store can name files that no longer exist.

Layout (Mark Mentovai's and Wim Lewis's descriptions, as the Python
ds_store package reads it):

* 4 bytes 1, 'Bud1', then the root block's offset and size (offsets in the
  file are + 4);
* the root block: the block address table (each address = offset with the
  log2 of the size in its low 5 bits), the table of contents ('DSDB' ->
  block number), and free lists;
* DSDB: the B-tree's root node, levels, record count;
* a node: P (0 = leaf), count, then records -- internal nodes interleave
  child block numbers -- and a record: name (UTF-16BE, length in
  characters), a 4-character code, a 4-character type and the value
  ('long', 'shor', 'bool', 'blob', 'type', 'ustr', 'comp', 'dutc').

`records(data)` -> [(name, code, value)]; DsStoreError when not one.
"""

import struct

MAGIC = b'\x00\x00\x00\x01Bud1'
#: Nodes visited at most (a damaged file must not loop).
MAX_NODES = 100_000


class DsStoreError(ValueError):
    """Not a .DS_Store, or damaged."""


def is_ds_store(data):
    return bytes(data[:8]) == MAGIC


def _u32(data, pos):
    if pos + 4 > len(data):
        raise DsStoreError("read past the end")
    return struct.unpack_from('>I', data, pos)[0]


def records(data):
    """Every record in the file, in B-tree order."""
    data = bytes(data)
    if not is_ds_store(data):
        raise DsStoreError("not a .DS_Store (no 'Bud1')")
    root_offset = _u32(data, 8)
    root = 4 + root_offset
    count = _u32(data, root)
    addresses = [_u32(data, root + 8 + 4 * i) for i in range(count)]
    # The address table is padded to a multiple of 256 entries.
    pos = root + 8 + 4 * ((count + 255) // 256 * 256)
    toc = {}
    for _ in range(_u32(data, pos)):
        pos += 4
        length = data[pos]
        name = data[pos + 1:pos + 1 + length]
        pos += 1 + length
        toc[name] = _u32(data, pos)
    if b'DSDB' not in toc:
        raise DsStoreError("no DSDB table of contents entry")

    def block(number):
        if number >= len(addresses):
            raise DsStoreError(f"block {number} not in the table")
        address = addresses[number]
        offset = 4 + (address & ~0x1F)
        size = 1 << (address & 0x1F)
        if offset + size > len(data) + 32:
            raise DsStoreError(f"block {number} runs past the end")
        return offset

    dsdb = block(toc[b'DSDB'])
    root_node = _u32(data, dsdb)
    out = []
    pending = [root_node]
    visited = set()
    while pending:
        number = pending.pop()
        if number in visited or len(visited) > MAX_NODES:
            continue
        visited.add(number)
        pos = block(number)
        rightmost = _u32(data, pos)
        entries = _u32(data, pos + 4)
        pos += 8
        children = []
        for _ in range(entries):
            if rightmost:
                children.append(_u32(data, pos))
                pos += 4
            item, pos = _record(data, pos)
            out.append(item)
        if rightmost:
            children.append(rightmost)
        pending.extend(reversed(children))
    return out


def _record(data, pos):
    length = _u32(data, pos)
    pos += 4
    name = data[pos:pos + 2 * length].decode('utf-16-be', 'replace')
    pos += 2 * length
    code = data[pos:pos + 4].decode('latin-1')
    kind = data[pos + 4:pos + 8]
    pos += 8
    if kind == b'long' or kind == b'shor':
        value, pos = _u32(data, pos), pos + 4
    elif kind == b'bool':
        value, pos = bool(data[pos]), pos + 1
    elif kind == b'type':
        value, pos = data[pos:pos + 4].decode('latin-1'), pos + 4
    elif kind in (b'comp', b'dutc'):
        value = struct.unpack_from('>Q', data, pos)[0]
        pos += 8
    elif kind == b'blob':
        size = _u32(data, pos)
        value, pos = data[pos + 4:pos + 4 + size], pos + 4 + size
    elif kind == b'ustr':
        size = _u32(data, pos)
        value = data[pos + 4:pos + 4 + 2 * size].decode('utf-16-be',
                                                         'replace')
        pos += 4 + 2 * size
    else:
        raise DsStoreError(f"unknown record type {kind!r}")
    return (name, code, value), pos


def put_back(data):
    """{name in the Trash: (original folder, original name)} from a
    Trash's .DS_Store ('ptbL' / 'ptbN')."""
    out = {}
    for name, code, value in records(data):
        if code == 'ptbL':
            out.setdefault(name, [None, None])[0] = value
        elif code == 'ptbN':
            out.setdefault(name, [None, None])[1] = value
    return {name: tuple(pair) for name, pair in out.items()}

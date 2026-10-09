"""What an ext3/ext4 journal still holds of deleted files (no Qt; pure
Python).

Deleting a file on ext3 clears its block pointers, and on ext4 its extent
tree, so the inode no longer says where the data was -- TRACE's Deleted
Files said "no data recorded". But the journal (JBD2, inode 8) logs whole
metadata blocks as they were written: an inode-table block from before the
deletion still holds the inode with its pointers, and a directory block
still holds the name. This reads them back, as extundelete does:

* the journal superblock, then descriptor blocks (magic 0xC03B3998, type
  1), each listing the file-system blocks whose copies follow it -- tags
  of 8, 12 or 16 bytes as the 64bit / checksum features say; an escaped
  copy gets its magic back
* for a deleted inode: the newest logged copy of its inode-table block in
  which the inode is still in use (no deletion time, a size, pointers or
  extents) -- its data runs, from the block map (12 direct, single,
  double, triple indirect) or the extent tree, indirect and index blocks
  read from their newest logged copy, else from the disk
* names: every logged directory block, its entries and the deleted ones
  in record slack, inode -> name; a folder's own block ('.' first) says
  which folder the names are in

A recovered run is the file's only if no live file holds those blocks
now: core/deleted measures that as for any other run.

NIST's DFR ext images are the test (tests/test_nist_cfreds.py).
"""

import logging
import struct

logger = logging.getLogger('TRACE.ExtJournal')

MAGIC = 0xC03B3998
DESCRIPTOR, COMMIT, SUPERBLOCK_V1, SUPERBLOCK_V2, REVOKE = 1, 2, 3, 4, 5
#: Journal incompatible features.
_64BIT, _CSUM_V2, _CSUM_V3 = 0x2, 0x8, 0x10
#: Tag flags.
_ESCAPED, _SAME_UUID, _LAST = 0x1, 0x2, 0x8
EXTENT_MAGIC = 0xF30A


class Journal:
    """The logged copies of one ext volume's metadata blocks."""

    def __init__(self, handler, start, fs):
        self.handler = handler
        self.base, self.length = handler.partition_bytes(start)
        sb = handler.read(self.base + 1024, 1024)
        if struct.unpack_from('<H', sb, 0x38)[0] != 0xEF53:
            raise ValueError("not an ext file system")
        self.block = 1024 << struct.unpack_from('<I', sb, 24)[0]
        self.inodes_per_group = struct.unpack_from('<I', sb, 40)[0]
        self.inode_size = struct.unpack_from('<H', sb, 0x58)[0] or 128
        self.first_data = struct.unpack_from('<I', sb, 20)[0]
        incompat = struct.unpack_from('<I', sb, 0x60)[0]
        self.desc = (struct.unpack_from('<H', sb, 0xFE)[0] or 64) \
            if incompat & 0x80 else 32
        journal_inode = struct.unpack_from('<I', sb, 0xE0)[0]
        self.copies = {}                   # fs block -> [data], oldest first
        self.positions = {}                # fs block -> [transaction]
        self._tables = None
        if journal_inode:
            handle = fs.open_meta(inode=journal_inode)
            self._read_log(handle.read_random(0, int(handle.info.meta.size)))

    # --- the log --------------------------------------------------------

    def _read_log(self, log):
        if len(log) < 1024:
            return
        magic, kind = struct.unpack_from('>II', log, 0)
        if magic != MAGIC or kind not in (SUPERBLOCK_V1, SUPERBLOCK_V2):
            return
        size = struct.unpack_from('>I', log, 12)[0]
        incompat = struct.unpack_from('>I', log, 40)[0] \
            if kind == SUPERBLOCK_V2 else 0
        if size not in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
            return
        if incompat & _CSUM_V3:
            tag, wide = 16, True
        elif incompat & _64BIT:
            tag, wide = 12, True
        else:
            tag, wide = 8, False
        if incompat & _CSUM_V2:
            tag = 16 if not wide else 16
        blocks = len(log) // size
        number = 1
        while number < blocks:
            at = number * size
            magic, kind = struct.unpack_from('>II', log, at)
            if magic != MAGIC or kind != DESCRIPTOR:
                number += 1
                continue
            # The log is circular: where a copy lies says nothing of its
            # age, its transaction's sequence number does.
            sequence = struct.unpack_from('>I', log, at + 8)[0]
            pos, data_block = at + 12, number + 1
            end = at + size - (4 if incompat & (_CSUM_V2 | _CSUM_V3) else 0)
            while pos + tag <= end and data_block < blocks:
                target = struct.unpack_from('>I', log, pos)[0]
                if incompat & _CSUM_V3:
                    flags = struct.unpack_from('>I', log, pos + 4)[0]
                    if wide:
                        target |= struct.unpack_from('>I', log,
                                                     pos + 8)[0] << 32
                else:
                    flags = struct.unpack_from('>H', log, pos + 6)[0] \
                        if incompat & _CSUM_V2 else \
                        struct.unpack_from('>I', log, pos + 4)[0]
                    if wide:
                        target |= struct.unpack_from('>I', log,
                                                     pos + 8)[0] << 32
                copy = log[data_block * size:(data_block + 1) * size]
                if flags & _ESCAPED:
                    copy = struct.pack('>I', MAGIC) + copy[4:]
                if size == self.block:
                    self.copies.setdefault(target, []).append(copy)
                    self.positions.setdefault(target, []).append(sequence)
                data_block += 1
                pos += tag
                if not flags & _SAME_UUID:
                    pos += 16
                if flags & _LAST:
                    break
            number = data_block
        for target in self.copies:
            order = sorted(range(len(self.copies[target])),
                           key=lambda i: self.positions[target][i])
            self.copies[target] = [self.copies[target][i] for i in order]
            self.positions[target] = [self.positions[target][i]
                                      for i in order]

    def block_data(self, number):
        """A file-system block: its newest logged copy, else the disk."""
        copies = self.copies.get(number)
        if copies:
            return copies[-1]
        return self.handler.read(self.base + number * self.block,
                                 self.block)

    # --- inodes ----------------------------------------------------------

    def _inode_table(self, group):
        if self._tables is None:
            self._tables = {}
            table = self.handler.read(
                self.base + (self.first_data + 1) * self.block,
                self.block * 64)
            for index in range(len(table) // self.desc):
                entry = table[index * self.desc:(index + 1) * self.desc]
                where = struct.unpack_from('<I', entry, 8)[0]
                if self.desc >= 64:
                    where |= struct.unpack_from('<I', entry, 0x28)[0] << 32
                self._tables[index] = where
        return self._tables.get(group)

    def _where(self, inode):
        group, index = divmod(inode - 1, self.inodes_per_group)
        table = self._inode_table(group)
        if not table:
            return None
        return divmod(index * self.inode_size, self.block), table

    def inode_copies(self, inode, positions=False):
        """Every logged copy of an inode, oldest first (raw bytes; with
        `positions`, (place in the log, raw))."""
        where = self._where(inode)
        if where is None:
            return []
        (block, within), table = where
        copies = [copy[within:within + self.inode_size]
                  for copy in self.copies.get(table + block, [])]
        if positions:
            return list(zip(self.positions.get(table + block, []), copies))
        return copies

    def logged_inodes(self):
        """Every inode number some logged inode-table block holds."""
        self._inode_table(0)
        per_block = self.block // self.inode_size
        span = -(-self.inodes_per_group // per_block)
        for group, table in sorted((self._tables or {}).items()):
            for block in range(table, table + span):
                if block in self.copies:
                    first = group * self.inodes_per_group + \
                        (block - table) * per_block + 1
                    yield from range(first, first + per_block)

    def inode_now(self, inode):
        """The inode as the disk holds it now (raw bytes), or b''."""
        where = self._where(inode)
        if where is None:
            return b''
        (block, within), table = where
        return self.handler.read(self.base + (table + block) * self.block
                                 + within, self.inode_size)

    def deleted_runs(self, inode, size=0):
        """(runs, size): [(image byte offset, length)] of a deleted file's
        data in the file's order and its size, from the newest logged copy
        of its inode written before the deletion (ext empties the inode it
        deletes: size 0, no pointers) -- or None. `size`, when known, must
        match."""
        # An inode number is reused: a logged copy is this file's only if
        # its generation -- set when the inode is allocated, kept when it
        # is freed -- is the one the inode has now.
        now = self.inode_now(inode)
        generation = now[100:104] if len(now) >= 104 else None
        for place, raw in reversed(self.inode_copies(inode, True)):
            if len(raw) < 104 or (generation is not None and
                                  raw[100:104] != generation):
                continue
            mode, = struct.unpack_from('<H', raw, 0)
            logged_size = struct.unpack_from('<I', raw, 4)[0] | \
                (struct.unpack_from('<I', raw, 108)[0] << 32
                 if len(raw) > 111 else 0)
            dtime = struct.unpack_from('<I', raw, 20)[0]
            flags = struct.unpack_from('<I', raw, 32)[0]
            pointers = raw[40:100]
            if dtime or not logged_size or not any(pointers) or \
                    (size and logged_size != size) or mode >> 12 != 0o10 \
                    or logged_size > self.length:
                continue                     # in use, empty, or not sane
            try:
                if flags & 0x80000 and \
                        struct.unpack_from('<H', pointers, 0)[0] == \
                        EXTENT_MAGIC:
                    blocks = self._ordered(self._extents(pointers, 5))
                else:
                    blocks = self._block_map(pointers, logged_size)
                wanted = -(-logged_size // self.block)
                if len(blocks) < wanted:
                    continue
                self.last_place = place
                return self._runs(blocks[:wanted]), logged_size
            except (struct.error, ValueError) as exc:
                logger.debug("Inode %d's logged copy unreadable: %s",
                             inode, exc)
                continue
        return None

    def _check(self, number):
        if not 0 < number < self.length // self.block:
            raise ValueError(f"block {number} is outside the volume")

    def _runs(self, blocks):
        runs = []
        for number in blocks:
            if not number:
                raise ValueError("a hole")
            self._check(number)
            offset = self.base + number * self.block
            if runs and runs[-1][0] + runs[-1][1] == offset:
                runs[-1] = (runs[-1][0], runs[-1][1] + self.block)
            else:
                runs.append((offset, self.block))
        return runs

    def _block_map(self, pointers, size):
        per = self.block // 4
        wanted = -(-size // self.block)
        direct = list(struct.unpack_from('<15I', pointers))
        blocks = [b for b in direct[:12]]

        def indirect(number, level):
            if not number:
                return []
            self._check(number)
            entries = struct.unpack_from(f'<{per}I', self.block_data(number))
            if level == 1:
                return list(entries)
            out = []
            for entry in entries:
                if len(blocks) + len(out) >= wanted or not entry:
                    break                    # done, or the map ends here
                out += indirect(entry, level - 1)
            return out

        for position, level in ((12, 1), (13, 2), (14, 3)):
            if len(blocks) >= wanted:
                break
            blocks += indirect(direct[position], level)
        return [b for b in blocks[:wanted]]

    def _extents(self, node, depth_limit):
        """[(logical block, physical block, length)] of an extent tree;
        index nodes' children read from their newest logged copy."""
        magic, entries, _most, depth = struct.unpack_from('<HHHH', node, 0)
        if magic != EXTENT_MAGIC or depth_limit < 0:
            raise ValueError("not an extent node")
        found = []
        for index in range(entries):
            at = 12 + index * 12
            if depth == 0:
                logical, length, high, low = struct.unpack_from(
                    '<IHHI', node, at)
                if length > 32768:
                    length -= 32768          # unwritten: allocated, zeroes
                found.append((logical, (high << 32) | low, length))
            else:
                _logical, low, high = struct.unpack_from('<IIH', node, at)
                child = (high << 32) | low
                self._check(child)
                found += self._extents(self.block_data(child),
                                       depth_limit - 1)
        return found

    @staticmethod
    def _ordered(extents):
        out = []
        for logical, start, length in sorted(extents):
            if logical > len(out):
                out += [0] * (logical - len(out))   # a hole: sparse
            out += range(start, start + length)
        return out

    def unrecorded_after(self, inode):
        """Inodes of files made *and* deleted after this one was deleted
        whose blocks no logged copy records (ext empties an inode it frees):
        they may have written over this file's blocks, and nothing left
        says whether they did (NIST's DFR-07-one: Chort, written over after
        its deletion by a file that was itself deleted)."""
        now = self.inode_now(inode)
        if len(now) < 24:
            return []
        deleted = struct.unpack_from('<I', now, 20)[0]
        if not deleted:
            return []
        found = []
        for other in self.logged_inodes():
            if other == inode:
                continue
            raw = self.inode_now(other)
            if len(raw) < 104 or struct.unpack_from('<H', raw, 26)[0]:
                continue                                   # in use
            access, change, modify, gone = struct.unpack_from('<4I', raw, 8)
            if not gone or min(access, change, modify) <= deleted:
                continue                       # existed before ours went
            generation = raw[100:104]
            if any(_named_blocks(copy) - {struct.unpack_from('<I', copy,
                                                             104)[0]}
                   for copy in self.inode_copies(other)
                   if copy[100:104] == generation and
                   struct.unpack_from('<H', copy, 26)[0]):
                continue              # its blocks are known: reused() asks
            found.append(other)
        return found

    def reused(self, inode, runs, after):
        """Bytes of `runs` that another file's inode, logged after place
        `after` in the journal, names among its blocks: the blocks were
        given to it once this file let them go. Direct pointers and
        in-inode extents are read (indirect blocks are not), so this finds
        most reuse, not all."""
        mine = set()
        for offset, length in runs:
            first = (offset - self.base) // self.block
            mine.update(range(first, first + length // self.block))
        taken = set()
        per_block = self.block // self.inode_size
        for group, table in (self._tables or {}).items():
            for block in range(table, table + -(-self.inodes_per_group //
                                                 per_block)):
                for place, copy in zip(self.positions.get(block, []),
                                       self.copies.get(block, [])):
                    # The same transaction counts: two files cannot hold
                    # one block, and the other logged it as its own
                    # (NIST's DFR-07-one: Edasich over Chort, both in
                    # transaction 7).
                    if place < after:
                        continue
                    for slot in range(per_block):
                        number = group * self.inodes_per_group + \
                            (block - table) * per_block + slot + 1
                        if number == inode:
                            continue
                        raw = copy[slot * self.inode_size:
                                   (slot + 1) * self.inode_size]
                        taken.update(mine & _named_blocks(raw))
        return len(taken) * self.block

    # --- names -------------------------------------------------------------

    def names(self):
        """{inode: (name, folder inode or None)} from logged directory
        blocks, the newest copy winning; deleted entries in record slack
        too."""
        found = {}
        for copies in self.copies.values():
            for block in copies:
                entries = _directory_entries(block)
                if not entries:
                    continue
                folder = entries[0][0] if entries[0][1] == '.' else None
                for inode, name in entries:
                    if name not in ('.', '..'):
                        found[inode] = (name, folder)
        return found


def _named_blocks(raw):
    """The blocks an inode names directly: its extended-attribute block
    (kept even once the inode is freed -- NIST's DFR-07: two later files'
    'selinux' attribute block over a deleted file's first block, free again
    in the bitmap), and, while it is in use, its 12 direct pointers or the
    extents in the inode itself."""
    if len(raw) < 108:
        return set()
    attributes = struct.unpack_from('<I', raw, 104)[0]
    if len(raw) > 0x77:
        attributes |= struct.unpack_from('<H', raw, 0x76)[0] << 32
    named = {attributes} if attributes else set()
    if not struct.unpack_from('<H', raw, 26)[0]:
        return named                                   # no links: freed
    flags = struct.unpack_from('<I', raw, 32)[0]
    pointers = raw[40:100]
    if flags & 0x80000 and struct.unpack_from('<H', pointers, 0)[0] == \
            EXTENT_MAGIC:
        entries, depth = struct.unpack_from('<HxxH', pointers, 2)
        if depth:
            return named
        out = set(named)
        for index in range(min(entries, 4)):
            _logical, length, high, low = struct.unpack_from(
                '<IHHI', pointers, 12 + index * 12)
            out.update(range((high << 32) | low,
                             ((high << 32) | low) + (length & 0x7FFF)))
        return out
    return named | {b for b in struct.unpack_from('<12I', pointers) if b}


def _directory_entries(block):
    """[(inode, name)] if `block` reads as an ext directory block -- its
    records chain exactly to its end -- with entries hidden in each
    record's slack; else []."""
    out, pos = [], 0
    size = len(block)
    while pos < size:
        if pos + 8 > size:
            return []
        inode, length, name_length, _kind = struct.unpack_from(
            '<IHBB', block, pos)
        if length < 8 or length % 4 or pos + length > size or \
                (inode and 8 + name_length > length):
            return []
        if inode and name_length:
            name = _name(block[pos + 8:pos + 8 + name_length])
            if name is None:
                return []
            out.append((inode, name))
        # A deleted entry is merged into the record before it: look in
        # the slack after this record's own name.
        used = 8 + -(-name_length // 4) * 4 if inode else 0
        slack = pos + max(used, 8 if not inode else used)
        while slack + 8 <= pos + length:
            hidden, hidden_length, hidden_name, _k = struct.unpack_from(
                '<IHBB', block, slack)
            need = 8 + -(-hidden_name // 4) * 4
            if hidden and hidden_name and hidden_length >= need and \
                    slack + 8 + hidden_name <= pos + length:
                name = _name(block[slack + 8:slack + 8 + hidden_name])
                if name is not None and name not in ('.', '..'):
                    out.append((hidden, name))
                    slack += need
                    continue
            slack += 4
        pos += length
    return out if out else []


def _name(raw):
    try:
        name = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not name or '/' in name or '\x00' in name or not name.isprintable():
        return None
    return name


def read_deleted(handler, start, meta):
    """A deleted ext3/4 file's bytes from its journal copy, or None (the
    inode is not emptied, not ext, or nothing logged it)."""
    if meta is None or int(meta.flags) & 1 or int(meta.size or 0) or \
            handler.get_fs_type(start) not in ('Ext3', 'Ext4'):
        return None
    cache = handler.__dict__.setdefault('_ext_journals', {})
    if start not in cache:
        try:
            cache[start] = Journal(handler, start, handler.get_fs_info(start))
        except Exception:
            cache[start] = None
    journal = cache[start]
    found = journal.deleted_runs(int(meta.addr)) if journal else None
    if not found:
        return None
    runs, size = found
    return b''.join(handler.read(offset, length)
                    for offset, length in runs)[:size]

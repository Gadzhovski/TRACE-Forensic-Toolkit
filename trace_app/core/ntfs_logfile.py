"""NTFS $LogFile: the volume's own journal of metadata operations, read for
the files it shows being created, named, unnamed and freed.

$LogFile holds redo/undo records for every metadata change NTFS makes
before making it (the last minutes to hours of activity on a busy volume,
longer on a quiet one). Two restart pages (RSTR) give the log page size,
how many bits of a sequence number (LSN) are its wrap count, and where log
data starts in a page; then log record pages (RCRD), each with fixups like
an MFT record. A record's LSN encodes its own position -- page and offset
-- which is how a record is told from stale bytes: only those whose LSN
points back where they sit are read. A record longer than the rest of its
page continues in the data area of the next.

Each NTFS record carries a redo and an undo operation and their data. The
ones that say what happened to a file by name:
  * AddIndexEntryRoot / AddIndexEntryAllocation -- a name added to a
    folder (a file created, or renamed or moved to here): the redo data is
    the index entry, with the file's $FILE_NAME;
  * DeleteIndexEntryRoot / DeleteIndexEntryAllocation -- a name removed
    (deleted, or renamed or moved away): the undo data holds it;
  * InitializeFileRecordSegment -- an MFT record written afresh (a new
    file), its $FILE_NAME inside;
  * DeallocateFileRecordSegment -- an MFT record freed (a file deleted).
The log keeps no times of its own: the times are the ones in the $FILE_NAME
copies the records carry, and the order is the LSN's. Checked record by
record against dfir_ntfs.
"""

import struct

from trace_app.core.ntfs import (_apply_fixups, filetime_text,
                                 parse_record)

# NTFS operations.
NOOP = 0x00
INITIALIZE_FILE_RECORD = 0x02
DEALLOCATE_FILE_RECORD = 0x03
ADD_INDEX_ROOT = 0x0C
DELETE_INDEX_ROOT = 0x0D
ADD_INDEX_ALLOCATION = 0x0E
DELETE_INDEX_ALLOCATION = 0x0F

OPERATIONS = {
    0x00: 'Noop', 0x01: 'CompensationLogRecord',
    0x02: 'InitializeFileRecordSegment', 0x03: 'DeallocateFileRecordSegment',
    0x04: 'WriteEndOfFileRecordSegment', 0x05: 'CreateAttribute',
    0x06: 'DeleteAttribute', 0x07: 'UpdateResidentValue',
    0x08: 'UpdateNonresidentValue', 0x09: 'UpdateMappingPairs',
    0x0A: 'DeleteDirtyClusters', 0x0B: 'SetNewAttributeSizes',
    0x0C: 'AddIndexEntryRoot', 0x0D: 'DeleteIndexEntryRoot',
    0x0E: 'AddIndexEntryAllocation', 0x0F: 'DeleteIndexEntryAllocation',
    0x10: 'WriteEndOfIndexBuffer', 0x11: 'SetIndexEntryVcnRoot',
    0x12: 'SetIndexEntryVcnAllocation', 0x13: 'UpdateFileNameRoot',
    0x14: 'UpdateFileNameAllocation', 0x15: 'SetBitsInNonresidentBitMap',
    0x16: 'ClearBitsInNonresidentBitMap', 0x17: 'HotFix',
    0x18: 'EndTopLevelAction', 0x19: 'PrepareTransaction',
    0x1A: 'CommitTransaction', 0x1B: 'ForgetTransaction',
    0x1C: 'OpenNonresidentAttribute', 0x1D: 'OpenAttributeTableDump',
    0x1E: 'AttributeNamesDump', 0x1F: 'DirtyPageTableDump',
    0x20: 'TransactionTableDump', 0x21: 'UpdateRecordDataRoot',
    0x22: 'UpdateRecordDataAllocation', 0x23: 'UpdateRelativeDataIndex',
    0x24: 'UpdateRelativeDataAllocation', 0x25: 'ZeroEndOfFileRecord'}

CLIENT_RECORD = 1
MULTI_PAGE = 0x1


class LogFileError(ValueError):
    pass


class Record:
    __slots__ = ('lsn', 'transaction', 'redo_op', 'undo_op', 'redo', 'undo',
                 'target_attribute', 'target_vcn', 'cluster_block_offset',
                 'record_offset', 'attribute_offset')


def _unprotect(page):
    page = bytearray(page)
    if not _apply_fixups(page):
        return None
    return bytes(page)


class LogFile:
    def __init__(self, data):
        self.data = data
        restart = None
        for at in (0, 4096):
            page = data[at:at + 4096]
            if page[:4] != b'RSTR':
                continue
            page = _unprotect(page)
            if page is not None:
                restart = page
                break
        if restart is None:
            raise LogFileError("no valid restart page")
        self.page_size = struct.unpack_from('<I', restart, 0x14)[0]
        area = struct.unpack_from('<H', restart, 0x18)[0]
        minor, major = struct.unpack_from('<hh', restart, 0x1A)
        self.version = (major, minor)
        if self.page_size not in (4096, 8192, 16384, 65536):
            raise LogFileError(f"log page size {self.page_size}")
        # The restart page was unprotected at 4 KB; a bigger log page is
        # read again at its own size.
        if self.page_size != 4096:
            restart = _unprotect(data[:self.page_size]) or restart
        self.sequence_bits = struct.unpack_from('<I', restart, area + 0x10)[0]
        self.header_length = struct.unpack_from('<H', restart, area + 0x24)[0]
        self.data_offset = struct.unpack_from('<H', restart, area + 0x26)[0]
        self.current_lsn = struct.unpack_from('<Q', restart, area)[0]
        if not 3 <= self.sequence_bits < 64 or self.header_length < 48 or \
                self.data_offset < 8:
            raise LogFileError("restart area out of range")
        self._pages = {}

    # --- positions ---------------------------------------------------------------

    def _offset(self, lsn):
        absolute = ((lsn << self.sequence_bits) & 0xFFFFFFFFFFFFFFFF) >> \
            (self.sequence_bits - 3)
        return divmod(absolute, self.page_size)

    def _raw_page(self, number):
        raw = self.data[number * self.page_size:(number + 1) * self.page_size]
        if len(raw) == self.page_size and raw[:4] == b'RCRD':
            return _unprotect(raw)
        return None

    def _tail_copies(self):
        """{log page number: page} of the tail ('fast') copies kept before
        the log proper: the newest pages, not always written back yet."""
        if not hasattr(self, '_tails'):
            self._tails = {}
            for number in range(2, self.first_page):
                page = self._raw_page(number)
                if page is None:
                    continue
                if self.version[0] < 2:
                    target = struct.unpack_from('<q', page, 8)[0]
                else:
                    target = struct.unpack_from('<I', page, 60)[0]
                if target > 0 and target % self.page_size == 0:
                    found = self._tails.get(target // self.page_size)
                    last = struct.unpack_from('<Q', page, 32)[0]
                    if found is None or last > struct.unpack_from(
                            '<Q', found, 32)[0]:
                        self._tails[target // self.page_size] = page
        return self._tails

    def page(self, number):
        if number not in self._pages:
            page = self._raw_page(number)
            tail = self._tail_copies().get(number)
            if tail is not None and (page is None or struct.unpack_from(
                    '<Q', tail, 32)[0] > struct.unpack_from('<Q', page,
                                                            32)[0]):
                page = tail                 # the newer copy of this page
            self._pages[number] = page
        return self._pages[number]

    @property
    def first_page(self):
        return 4 if self.version[0] < 2 else 34

    # --- records -----------------------------------------------------------------

    def _header_at(self, number, offset):
        page = self.page(number)
        if page is None or offset + self.header_length > self.page_size:
            return None
        head = page[offset:offset + self.header_length]
        lsn = struct.unpack_from('<Q', head, 0)[0]
        if lsn == 0 or self._offset(lsn) != (number, offset):
            return None
        return head

    def _client_data(self, number, offset, length):
        """A record's client data -- in this page, or continued in the
        data areas of the pages after it. (bytes, page, offset after)."""
        start = offset + self.header_length
        page = self.page(number)
        room = self.page_size - start
        if length <= room:
            return page[start:start + length], number, start + length
        out = bytearray(page[start:])
        while len(out) < length:
            number += 1
            if number * self.page_size >= len(self.data):
                number = self.first_page
            page = self.page(number)
            if page is None:
                return None, number, 0
            take = min(length - len(out), self.page_size - self.data_offset)
            out += page[self.data_offset:self.data_offset + take]
            end = self.data_offset + take
        return bytes(out), number, end

    def records(self):
        """Every client record whose LSN is where it is, in LSN order."""
        found = {}
        resume = {}
        pages = len(self.data) // self.page_size
        for number in range(self.first_page, pages):
            page = self.page(number)
            if page is None:
                continue
            # After a record that ran on from an earlier page, its end. When
            # that is not known (the earlier page unreadable, an older
            # generation of the log), the first header whose LSN names its
            # own place -- nothing else can pass that check.
            offset = resume.get(number, self.data_offset)
            if self._header_at(number, offset) is None:
                offset = next((at for at in range(self.data_offset,
                                                  self.page_size, 8)
                               if self._header_at(number, at) is not None),
                              self.page_size)
            while offset + self.header_length <= self.page_size:
                head = self._header_at(number, offset)
                if head is None:
                    break
                lsn = struct.unpack_from('<Q', head, 0)[0]
                length = struct.unpack_from('<I', head, 24)[0]
                kind = struct.unpack_from('<I', head, 32)[0]
                transaction = struct.unpack_from('<I', head, 36)[0]
                if length < 8 or length > 64 * self.page_size:
                    break
                client, end_page, end = self._client_data(number, offset,
                                                          length)
                if client is None:
                    break
                if kind == CLIENT_RECORD and lsn not in found:
                    record = _ntfs_record(client)
                    if record is not None:
                        record.lsn, record.transaction = lsn, transaction
                        found[lsn] = record
                if end_page != number:
                    if end_page > number:
                        resume[end_page] = (end + 7) & ~7
                    break
                offset = (end + 7) & ~7
        return [found[lsn] for lsn in sorted(found)]


def _ntfs_record(client):
    if len(client) < 32:
        return None
    (redo_op, undo_op, redo_offset, redo_length, undo_offset, undo_length,
     target, lcns, record_offset, attribute_offset, cluster_block,
     _reserved, vcn) = struct.unpack_from('<12HQ', client, 0)
    if redo_op not in OPERATIONS or undo_op not in OPERATIONS:
        return None
    record = Record()
    record.redo_op, record.undo_op = redo_op, undo_op
    record.redo = client[redo_offset:redo_offset + redo_length] \
        if redo_length else b''
    record.undo = client[undo_offset:undo_offset + undo_length] \
        if undo_length else b''
    record.target_attribute, record.target_vcn = target, vcn
    record.cluster_block_offset = cluster_block
    record.record_offset = record_offset
    record.attribute_offset = attribute_offset
    return record


# --- what the records say about files --------------------------------------------

def _index_entry(data):
    """(file (index, sequence), $FILE_NAME dict) from an index entry, or
    None."""
    if len(data) < 16 + 66:
        return None
    reference, length, content = struct.unpack_from('<QHH', data, 0)
    body = data[16:16 + content]
    if content < 66 or len(body) < 66:
        return None
    parent = struct.unpack_from('<Q', body, 0)[0]
    times = struct.unpack_from('<4Q', body, 8)
    size = struct.unpack_from('<Q', body, 48)[0]
    name_length = body[64]
    name = body[66:66 + 2 * name_length].decode('utf-16-le', 'replace')
    if not name or len(name) != name_length:
        return None
    return ((reference & 0xFFFFFFFFFFFF, reference >> 48),
            {'name': name, 'namespace': body[65],
             'parent': (parent & 0xFFFFFFFFFFFF, parent >> 48),
             'times': times, 'size': size})


def events(logfile, cluster_size=4096, record_size=1024):
    """[dict] -- what the log says happened to files, in LSN order: 'kind'
    ('name added', 'name removed', 'record created', 'record freed'), the
    LSN, the transaction, the name, its folder's reference, the file's
    reference, and the $FILE_NAME times the record carries."""
    out = []
    for record in logfile.records():
        base = {'lsn': record.lsn, 'transaction': record.transaction,
                'redo': OPERATIONS[record.redo_op],
                'undo': OPERATIONS[record.undo_op]}
        if record.redo_op in (ADD_INDEX_ROOT, ADD_INDEX_ALLOCATION):
            parsed = _index_entry(record.redo)
            if parsed:
                own, name = parsed
                out.append(dict(base, kind='name added', file=own, **_fn(
                    name)))
        elif record.redo_op in (DELETE_INDEX_ROOT, DELETE_INDEX_ALLOCATION):
            parsed = _index_entry(record.undo)
            if parsed:
                own, name = parsed
                out.append(dict(base, kind='name removed', file=own,
                                **_fn(name)))
        elif record.redo_op == INITIALIZE_FILE_RECORD and \
                record.redo[:4] == b'FILE':
            entry_number = (record.target_vcn * cluster_size +
                            record.cluster_block_offset * 512) // record_size
            entry = parse_record(record.redo.ljust(record_size, b'\x00'),
                                 entry_number, fixups=False)
            name = entry.best_name() if entry is not None else None
            out.append(dict(base, kind='record created',
                            file=(entry_number,
                                  entry.sequence if entry else None),
                            name=name.name if name else '',
                            parent=(name.parent_index, name.parent_sequence)
                            if name else None,
                            times=_times(name.times) if name else {},
                            size=name.size if name else None))
        elif record.redo_op == DEALLOCATE_FILE_RECORD:
            entry_number = (record.target_vcn * cluster_size +
                            record.cluster_block_offset * 512) // record_size
            out.append(dict(base, kind='record freed',
                            file=(entry_number, None), name='', parent=None,
                            times={}, size=None))
    return out


def _times(values):
    created, modified, changed, accessed = values
    return {'created': filetime_text(created),
            'modified': filetime_text(modified),
            'record changed': filetime_text(changed),
            'accessed': filetime_text(accessed)}


def _fn(name):
    return {'name': name['name'], 'parent': name['parent'],
            'times': _times(name['times']), 'size': name['size']}

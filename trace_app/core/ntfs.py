"""NTFS internals: the $MFT's two sets of times, the change journal, and
alternate data streams.

The Sleuth Kit shows a file's $STANDARD_INFORMATION times -- the ones
Explorer shows and any program can set. NTFS keeps a second set in each
$FILE_NAME attribute, which only the file system itself writes. When the
two disagree in ways the file system never produces, someone set the first
set by hand: timestomping. Reading both needs the raw MFT records, which is
what this module parses.

`$Extend/$UsnJrnl:$J` is the change journal: a record for every create,
write, rename and delete, with its time and the file's MFT reference --
often months of history, including files long gone from the MFT.

Named $DATA streams are listed. `Zone.Identifier` is the Mark of the Web
Windows writes on a downloaded file: which zone it came from, and often the
page and the URL.

Pure Python; no Qt. Times are kept to the 100 ns the format stores, written
'YYYY-MM-DD HH:MM:SS.fffffff' (UTC), which sorts with the
'YYYY-MM-DD HH:MM:SS' TRACE writes elsewhere. Unlike activity records, any
non-zero time is kept, 1601 included: a time set to 1970 is the evidence.
"""

import datetime
import json
import logging
import struct

logger = logging.getLogger('TRACE.NTFS')

MODULE_NTFS = 'ntfs'

ROOT_ENTRY = 5
#: Entries below this are the file system's own ($MFT, $LogFile, ...).
FIRST_USER_ENTRY = 24

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

NAMESPACE_POSIX, NAMESPACE_WIN32, NAMESPACE_DOS, NAMESPACE_BOTH = 0, 1, 2, 3

#: Resident stream bytes kept (Zone.Identifier is a few hundred bytes).
KEEP_RESIDENT = 4096

ORPHAN = '$Orphan'

_MASK48 = 0xFFFFFFFFFFFF
_EPOCH = datetime.datetime(1601, 1, 1)


class NtfsCancelled(Exception):
    """The examiner stopped the run."""


# --- times ---------------------------------------------------------------------

def filetime_text(value):
    """'YYYY-MM-DD HH:MM:SS.fffffff' for a FILETIME, None for 0 or a value
    no calendar holds."""
    if not value:
        return None
    seconds, fraction = divmod(value, 10_000_000)
    try:
        moment = _EPOCH + datetime.timedelta(seconds=seconds)
    except OverflowError:
        return None
    return f"{moment:%Y-%m-%d %H:%M:%S}.{fraction:07d}"


def macb_rows(times):
    """[(time, 'MACB' letters)] for (created, modified, changed, accessed),
    one row per distinct time -- the way a timeline reads them."""
    created, modified, changed, accessed = times
    letters = {}
    for value, position, letter in ((modified, 0, 'M'), (accessed, 1, 'A'),
                                    (changed, 2, 'C'), (created, 3, 'B')):
        if not value:
            continue
        slot = letters.setdefault(value, ['.', '.', '.', '.'])
        slot[position] = letter
    return sorted((value, ''.join(slot)) for value, slot in letters.items())


# --- MFT records ------------------------------------------------------------------

class FileName:
    __slots__ = ('parent_index', 'parent_sequence', 'name', 'namespace',
                 'times', 'size', 'flags')

    def __init__(self, parent_index, parent_sequence, name, namespace, times,
                 size, flags):
        self.parent_index = parent_index
        self.parent_sequence = parent_sequence
        self.name = name
        self.namespace = namespace
        self.times = times          # (created, modified, changed, accessed)
        self.size = size
        self.flags = flags


class Stream:
    __slots__ = ('name', 'size', 'resident', 'data')

    def __init__(self, name, size, resident, data=None):
        self.name = name
        self.size = size
        self.resident = resident
        self.data = data            # resident bytes, up to KEEP_RESIDENT


class Entry:
    """One MFT record, with any extension records' attributes merged in."""

    __slots__ = ('index', 'sequence', 'in_use', 'is_dir', 'base_index',
                 'si_times', 'si_flags', 'si_usn', 'names', 'streams',
                 'has_attribute_list')

    def __init__(self, index, sequence, in_use, is_dir, base_index):
        self.index = index
        self.sequence = sequence
        self.in_use = in_use
        self.is_dir = is_dir
        self.base_index = base_index
        self.si_times = None
        self.si_flags = 0
        self.si_usn = None
        self.names = []
        self.streams = []
        self.has_attribute_list = False

    def best_name(self):
        """The long name: Win32 or POSIX before the 8.3 DOS alias."""
        best = None
        for name in self.names:
            if name.namespace != NAMESPACE_DOS:
                return name
            best = best or name
        return best

    def merge(self, extension):
        self.names.extend(extension.names)
        self.streams.extend(extension.streams)
        if self.si_times is None and extension.si_times is not None:
            self.si_times = extension.si_times


def _apply_fixups(record):
    """Restore the last two bytes of each 512-byte stride; False if the
    record was torn (a sector written without the rest)."""
    usa_offset, usa_count = struct.unpack_from('<HH', record, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(record):
        return False
    check = record[usa_offset:usa_offset + 2]
    for stride in range(1, usa_count):
        end = stride * 512
        if end > len(record):
            break
        if record[end - 2:end] != check:
            return False
        fix = usa_offset + stride * 2
        record[end - 2:end] = record[fix:fix + 2]
    return True


def parse_record(data, index, full=True):
    """An Entry from one MFT record's bytes, or None for an empty or
    unreadable record. `full=False` reads only what paths need."""
    if len(data) < 48 or data[:4] != b'FILE':
        return None
    record = bytearray(data)
    if not _apply_fixups(record):
        return None
    (sequence, _links, first_attr, flags, used) = struct.unpack_from(
        '<HHHHI', record, 16)
    base_ref = struct.unpack_from('<Q', record, 32)[0]
    if len(record) >= 48:
        stored_index = struct.unpack_from('<I', record, 44)[0]
        if stored_index and stored_index != (index & 0xFFFFFFFF):
            # XP+ records their own number; a mismatch is a stray copy.
            pass
    entry = Entry(index, sequence, bool(flags & 1), bool(flags & 2),
                  base_ref & _MASK48)
    end = min(used, len(record))
    offset = first_attr
    while offset + 16 <= end:
        attr_type, length = struct.unpack_from('<II', record, offset)
        if attr_type == ATTR_END or length < 16 or offset + length > end:
            break
        non_resident = record[offset + 8]
        name_length = record[offset + 9]
        name_offset = struct.unpack_from('<H', record, offset + 10)[0]
        attr_name = ''
        if name_length:
            start = offset + name_offset
            attr_name = bytes(record[start:start + name_length * 2]).decode(
                'utf-16-le', 'replace')
        if not non_resident:
            content_size, content_offset = struct.unpack_from(
                '<IH', record, offset + 16)
            content = bytes(record[offset + content_offset:
                                   offset + content_offset + content_size])
        else:
            content = None
        if attr_type == ATTR_FILE_NAME and content and len(content) >= 66:
            entry.names.append(_file_name(content))
        elif not full:
            pass
        elif attr_type == ATTR_STANDARD_INFORMATION and content \
                and len(content) >= 36:
            created, modified, changed, accessed, attributes = \
                struct.unpack_from('<QQQQI', content, 0)
            entry.si_times = (created, modified, changed, accessed)
            entry.si_flags = attributes
            if len(content) >= 72:
                entry.si_usn = struct.unpack_from('<Q', content, 64)[0]
        elif attr_type == ATTR_ATTRIBUTE_LIST:
            entry.has_attribute_list = True
        elif attr_type == ATTR_DATA:
            if non_resident:
                start_vcn = struct.unpack_from('<Q', record, offset + 16)[0]
                if start_vcn == 0 and offset + 56 <= end:
                    size = struct.unpack_from('<Q', record, offset + 48)[0]
                    entry.streams.append(Stream(attr_name, size, False))
            else:
                entry.streams.append(Stream(
                    attr_name, len(content), True,
                    content[:KEEP_RESIDENT] if attr_name else None))
        offset += length
    return entry


def _file_name(content):
    parent_ref = struct.unpack_from('<Q', content, 0)[0]
    created, modified, changed, accessed, _alloc, size, flags = \
        struct.unpack_from('<QQQQQQI', content, 8)
    length, namespace = content[64], content[65]
    name = content[66:66 + length * 2].decode('utf-16-le', 'replace')
    return FileName(parent_ref & _MASK48, parent_ref >> 48, name, namespace,
                    (created, modified, changed, accessed), size, flags)


def record_size_of(first_record):
    """Bytes per MFT record, from record 0's allocated size."""
    if len(first_record) >= 32 and first_record[:4] == b'FILE':
        size = struct.unpack_from('<I', first_record, 28)[0]
        if size in (1024, 2048, 4096):
            return size
    return 1024


def iter_records(stream, full=True, should_stop=None, progress=None,
                 total=None, chunk_records=1024):
    """Every non-empty record of a $MFT read from `stream` (a file
    object), as (index, Entry)."""
    stream.seek(0)
    head = stream.read(4096)
    size = record_size_of(head)
    stream.seek(0)
    index = 0
    while True:
        if should_stop and should_stop():
            raise NtfsCancelled()
        block = stream.read(size * chunk_records)
        if not block:
            break
        for start in range(0, len(block) - size + 1, size):
            entry = parse_record(block[start:start + size], index, full)
            if entry is not None:
                yield index, entry
            index += 1
        if progress and total:
            progress(index * size, total)
        if len(block) < size * chunk_records:
            break


# --- paths ------------------------------------------------------------------------

class PathTable:
    """Folder paths rebuilt from parent references.

    A name's parent is (entry, sequence). If that entry has been reused
    since -- its sequence moved on -- the parent is gone, and the path starts
    at $Orphan, as plaso and libfsntfs write it. A parent deleted along with
    the file reads one past the recorded sequence (freeing a record
    increments it) and still counts as the parent.
    """

    def __init__(self):
        # index -> (sequence, name, parent, parent sequence, in use)
        self._entries = {}
        self._cache = {}

    def add(self, entry):
        if entry.base_index:
            return
        name = entry.best_name()
        if name is None:
            self._entries.setdefault(entry.index,
                                     (entry.sequence, None, 0, 0, False))
            return
        self._entries[entry.index] = (entry.sequence, name.name,
                                      name.parent_index, name.parent_sequence,
                                      entry.in_use)

    def add_extension(self, base_index, names):
        """A long name that only an extension record holds."""
        known = self._entries.get(base_index)
        if known is None or known[1] is not None:
            return
        for name in names:
            if name.namespace != NAMESPACE_DOS:
                self._entries[base_index] = (known[0], name.name,
                                             name.parent_index,
                                             name.parent_sequence, known[4])
                return

    def folder(self, index, sequence):
        """The path of folder (index, sequence): '' for the root,
        '$Orphan...' when the chain is broken."""
        key = (index, sequence)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        parts = []
        seen = set()
        current = key
        prefix = ''
        while True:
            idx, seq = current
            if idx == ROOT_ENTRY:
                break
            known = self._entries.get(idx)
            if known is None or known[1] is None or idx in seen \
                    or len(parts) > 255 or not _same_entry(known, seq):
                prefix = ORPHAN
                break
            hit = self._cache.get(current)
            if hit is not None:
                prefix = hit
                break
            seen.add(idx)
            parts.append(known[1])
            current = (known[2], known[3])
        path = prefix + ''.join('/' + part for part in reversed(parts))
        self._cache[key] = path
        return path

    def path(self, parent_index, parent_sequence, name):
        if parent_index == ROOT_ENTRY and name == '.':
            return '/'
        return f"{self.folder(parent_index, parent_sequence)}/{name}"

    def entry_path(self, entry, name=None):
        name = name or entry.best_name()
        if name is None:
            return f"{ORPHAN}/<entry {entry.index}>"
        if entry.index == ROOT_ENTRY:
            return '/'
        return self.path(name.parent_index, name.parent_sequence, name.name)


def _same_entry(known, sequence):
    if not sequence or known[0] == sequence:
        return True
    return not known[4] and known[0] == sequence + 1


def build_path_table(open_stream, should_stop=None):
    """First pass over the $MFT: names and parents only. Returns the table
    and {base index: [extension Entry]} for the second pass to merge."""
    table = PathTable()
    extensions = {}
    for _index, entry in iter_records(open_stream(), full=True,
                                      should_stop=should_stop):
        if entry.base_index:
            extensions.setdefault(entry.base_index, []).append(entry)
        else:
            table.add(entry)
    for base, parts in extensions.items():
        for part in parts:
            table.add_extension(base, part.names)
    return table, extensions


# --- what the records show ------------------------------------------------------

#: Named streams Windows and common software write for their own reasons.
ROUTINE_STREAMS = {
    'smartscreen', 'encryptable', 'favicon', 'afp_afpinfo', 'afp_resource',
    'com.dropbox.attributes', 'com.dropbox.attrs', 'ms-properties',
    '{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}', 'zone.identifier',
    'wofcompresseddata', 'textcontent', 'ofs_capability',
}

ZONES = {0: 'Local machine', 1: 'Local intranet', 2: 'Trusted sites',
         3: 'Internet', 4: 'Restricted sites'}

_EXECUTABLE = ('.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.ps1',
               '.vbs', '.js', '.jse', '.hta', '.msi', '.lnk', '.jar', '.iso',
               '.img', '.vhd', '.vhdx', '.docm', '.xlsm', '.pptm', '.one')


def parse_zone_identifier(data):
    """{'ZoneId': '3', 'HostUrl': ..., ...} from a Zone.Identifier stream."""
    if not data:
        return {}
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        text = data.decode('utf-16', 'replace')
    else:
        text = data.decode('utf-8', 'replace').lstrip('﻿')
    facts = {}
    for line in text.splitlines():
        line = line.strip().strip('\x00')
        if '=' not in line or line.startswith('['):
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key and key not in facts:
            facts[key] = value.strip()
    return facts


def _fraction(value):
    return value % 10_000_000 if value else None


def timestomp_signs(entry):
    """Reasons to think the $STANDARD_INFORMATION times were set by hand,
    as [(kind, text)]; empty when they look as NTFS writes them."""
    if entry.si_times is None or entry.index < FIRST_USER_ENTRY:
        return []
    name = entry.best_name()
    if name is None or not name.times[0]:
        return []
    signs = []
    si_created = entry.si_times[0]
    fn_created = name.times[0]
    if si_created and si_created < fn_created - 10_000_000:
        signs.append(('si-before-fn',
                      "$STANDARD_INFORMATION created "
                      f"{filetime_text(si_created)} is before $FILE_NAME "
                      f"created {filetime_text(fn_created)}"))
    # Whole seconds where NTFS itself wrote a fraction: the file system
    # records 100 ns, a tool setting times by hand usually does not. Only
    # when $FILE_NAME's own creation time has a fraction -- setup programs
    # stamp both sets to the second, and that is not someone hiding.
    present = [value for value in entry.si_times if value]
    if present and all(_fraction(value) == 0 for value in present) \
            and _fraction(fn_created):
        signs.append(('zero-fraction',
                      "every $STANDARD_INFORMATION time is a whole second; "
                      "the file system's own creation time is not"))
    return signs


def _times_dict(times):
    keys = ('created', 'modified', 'changed', 'accessed')
    return {key: filetime_text(value) for key, value in zip(keys, times)}


def entry_findings(entry, path, read_stream=None):
    """[(kind, grade, summary, detail dict)] for one entry."""
    found = []
    signs = timestomp_signs(entry)
    if signs:
        # Earlier-than-$FILE_NAME alone is what installers and archive
        # tools produce by the thousand (Windows setup stamps its files with
        # the build date); it is kept, but not raised. Whole-second times are
        # what a tool setting them writes; both together is the pattern.
        kinds = {kind for kind, _text in signs}
        if len(kinds) > 1:
            grade = 'suspicious'
        elif 'zero-fraction' in kinds:
            grade = 'notable'
        else:
            grade = 'benign'
        name = entry.best_name()
        found.append(('timestomp', grade, signs[0][1] if len(signs) == 1 else
                      "Times set by hand: " + '; '.join(s[1] for s in signs),
                      {'signs': [s[0] for s in signs],
                       'standard_information': _times_dict(entry.si_times),
                       'file_name': _times_dict(name.times)}))
    if entry.index < FIRST_USER_ENTRY or path.startswith('/$Extend'):
        return found
    for stream in entry.streams:
        if not stream.name:
            continue
        if stream.name.lower() == 'zone.identifier':
            data = stream.data
            if data is None and read_stream is not None:
                data = read_stream(stream.name, KEEP_RESIDENT)
            facts = parse_zone_identifier(data)
            zone = facts.get('ZoneId', '')
            try:
                zone_name = ZONES.get(int(zone), f'zone {zone}')
            except ValueError:
                zone_name = zone or 'unknown zone'
            source = facts.get('HostUrl') or facts.get('ReferrerUrl') or ''
            grade = 'notable' if path.lower().endswith(_EXECUTABLE) \
                and zone in ('3', '4') else 'benign'
            summary = f"Downloaded ({zone_name})" + \
                (f" from {source}" if source else '')
            found.append(('motw', grade, summary,
                          dict(facts, zone=zone_name, stream=stream.name)))
            continue
        head = stream.data[:2] if stream.data is not None else (
            read_stream(stream.name, 2) if read_stream else None)
        routine = stream.name.lower() in ROUTINE_STREAMS
        if head == b'MZ':
            grade = 'suspicious'
            summary = f"Stream :{stream.name} holds a Windows program"
        elif routine:
            grade = 'benign'
            summary = f"Stream :{stream.name} ({stream.size:,} bytes)"
        else:
            grade = 'notable'
            summary = f"Hidden stream :{stream.name} ({stream.size:,} bytes)"
        found.append(('ads', grade, summary,
                      {'stream': stream.name, 'size': stream.size,
                       'resident': stream.resident}))
    return found


def entry_events(entry, path):
    """[(time text, macb, source)] for an entry: its $STANDARD_INFORMATION
    times and its long name's $FILE_NAME times."""
    rows = []
    if entry.si_times:
        for value, letters in macb_rows(entry.si_times):
            text = filetime_text(value)
            if text:
                rows.append((text, letters, 'SI'))
    name = entry.best_name()
    if name is not None:
        for value, letters in macb_rows(name.times):
            text = filetime_text(value)
            if text:
                rows.append((text, letters, 'FN'))
    return rows


# --- the change journal ------------------------------------------------------------

USN_REASONS = (
    (0x00000001, 'DATA_OVERWRITE', 'Data overwritten'),
    (0x00000002, 'DATA_EXTEND', 'Data added'),
    (0x00000004, 'DATA_TRUNCATION', 'Data truncated'),
    (0x00000010, 'NAMED_DATA_OVERWRITE', 'Stream overwritten'),
    (0x00000020, 'NAMED_DATA_EXTEND', 'Stream added to'),
    (0x00000040, 'NAMED_DATA_TRUNCATION', 'Stream truncated'),
    (0x00000100, 'FILE_CREATE', 'Created'),
    (0x00000200, 'FILE_DELETE', 'Deleted'),
    (0x00000400, 'EA_CHANGE', 'Extended attributes changed'),
    (0x00000800, 'SECURITY_CHANGE', 'Permissions changed'),
    (0x00001000, 'RENAME_OLD_NAME', 'Renamed from'),
    (0x00002000, 'RENAME_NEW_NAME', 'Renamed to'),
    (0x00004000, 'INDEXABLE_CHANGE', 'Indexing changed'),
    (0x00008000, 'BASIC_INFO_CHANGE', 'Attributes or times changed'),
    (0x00010000, 'HARD_LINK_CHANGE', 'Hard link changed'),
    (0x00020000, 'COMPRESSION_CHANGE', 'Compression changed'),
    (0x00040000, 'ENCRYPTION_CHANGE', 'Encryption changed'),
    (0x00080000, 'OBJECT_ID_CHANGE', 'Object ID changed'),
    (0x00100000, 'REPARSE_POINT_CHANGE', 'Reparse point changed'),
    (0x00200000, 'STREAM_CHANGE', 'Stream created or deleted'),
    (0x00400000, 'TRANSACTED_CHANGE', 'Transacted change'),
    (0x00800000, 'INTEGRITY_CHANGE', 'Integrity changed'),
    (0x80000000, 'CLOSE', 'Closed'),
)

#: The reasons worth a line of their own in a timeline.
USN_KEY_REASONS = 0x00000100 | 0x00000200 | 0x00001000 | 0x00002000 \
    | 0x00200000 | 0x00008000 | 0x00000800


def usn_reason_names(flags):
    return [name for bit, name, _label in USN_REASONS if flags & bit]


def usn_reason_text(flags):
    """'Created, Data added, Closed' -- what a person reads."""
    labels = [label for bit, _name, label in USN_REASONS if flags & bit]
    return ', '.join(labels) or f'0x{flags:08x}'


class UsnRecord:
    __slots__ = ('usn', 'time', 'file_index', 'file_sequence',
                 'parent_index', 'parent_sequence', 'reasons', 'source_info',
                 'attributes', 'name', 'version', 'offset')

    def file_reference(self):
        return (self.file_sequence << 48) | self.file_index

    def parent_reference(self):
        return (self.parent_sequence << 48) | self.parent_index


def _parse_usn(buffer, position, length):
    major = struct.unpack_from('<H', buffer, position + 4)[0]
    record = UsnRecord()
    record.version = major
    if major == 2:
        file_ref, parent_ref = struct.unpack_from('<QQ', buffer, position + 8)
        base = position + 24
        record.file_index, record.file_sequence = \
            file_ref & _MASK48, file_ref >> 48
        record.parent_index, record.parent_sequence = \
            parent_ref & _MASK48, parent_ref >> 48
    elif major == 3:
        # 128-bit references (ReFS); on NTFS the low 64 bits are the usual.
        file_lo, _file_hi, parent_lo, _parent_hi = struct.unpack_from(
            '<QQQQ', buffer, position + 8)
        base = position + 40
        record.file_index, record.file_sequence = \
            file_lo & _MASK48, file_lo >> 48
        record.parent_index, record.parent_sequence = \
            parent_lo & _MASK48, parent_lo >> 48
    else:
        return None                 # v4 is range tracking: no name, no time
    (record.usn, timestamp, record.reasons, record.source_info, _security,
     record.attributes, name_length, name_offset) = struct.unpack_from(
        '<qQIIIIHH', buffer, base)
    if name_offset + name_length > length:
        return None
    start = position + name_offset
    record.name = bytes(buffer[start:start + name_length]).decode(
        'utf-16-le', 'replace')
    record.time = timestamp
    return record


def iter_usn(stream, start=0, end=None, should_stop=None, progress=None,
             chunk=1 << 20):
    """USN records from a $J stream (a file object), skipping the zeroed
    space the journal leaves where it was trimmed."""
    end = end if end is not None else stream.get_size() \
        if hasattr(stream, 'get_size') else None
    position = start
    stream.seek(position)
    carry = b''
    carry_base = position
    while True:
        if should_stop and should_stop():
            raise NtfsCancelled()
        block = stream.read(chunk)
        if not block:
            break
        buffer = carry + block
        base = carry_base
        offset = 0
        limit = len(buffer)
        while offset + 8 <= limit:
            length = struct.unpack_from('<I', buffer, offset)[0]
            if length == 0:
                # Zero fill: jump to the next non-zero 8-byte boundary.
                rest = buffer[offset:]
                stripped = len(rest) - len(rest.lstrip(b'\x00'))
                if stripped >= len(rest):
                    offset = limit
                    break
                offset += stripped - stripped % 8
                continue
            major = struct.unpack_from('<H', buffer, offset + 4)[0]
            if length < 60 or length > 65536 or length % 8 or \
                    major not in (2, 3, 4):
                offset += 8
                continue
            if offset + length > limit:
                break               # the rest arrives with the next block
            record = _parse_usn(buffer, offset, length)
            if record is not None:
                record.offset = base + offset
                yield record
            offset += length
        carry = buffer[offset:]
        carry_base = base + offset
        if progress and end:
            progress(carry_base, end)
        if end is not None and carry_base >= end:
            break


# --- one image -------------------------------------------------------------------

def _tsk_stream_reader(entry, attribute_name):
    """(reader(offset, length), size, first non-sparse offset) for a named
    $DATA attribute of a pytsk3 file, or None."""
    import pytsk3
    for attribute in entry:
        info = attribute.info
        if int(info.type) != int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA):
            continue
        name = info.name.decode('utf-8', 'replace') if info.name else ''
        if name != attribute_name:
            continue
        attr_id, size = info.id, int(info.size)
        first = 0
        try:
            sparse = int(pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)
            block = 0
            for run in attribute:
                if int(run.flags) & sparse:
                    block = int(run.offset) + int(run.len)
                    continue
                break
            first = block * entry.info.fs_info.block_size
        except Exception:
            first = 0

        def reader(offset, length, _id=attr_id):
            return entry.read_random(
                offset, length, pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA, _id)
        return reader, size, min(first, size)
    return None


def ntfs_volumes(image_handler):
    """[(start sector, FS_Info)] of the NTFS volumes on the image."""
    import pytsk3
    from trace_app.core.walk import volume_offsets
    offsets = volume_offsets(image_handler)
    volumes = []
    for offset in dict.fromkeys(offsets):
        fs = image_handler.get_fs_info(offset)
        if fs is None:
            continue
        try:
            ftype = int(fs.info.ftype)
        except Exception:
            continue
        if ftype & int(pytsk3.TSK_FS_TYPE_NTFS_DETECT):
            volumes.append((offset, fs))
    return volumes


def analyse_volume(fs, start, sink, progress=None, should_stop=None):
    """Read one NTFS volume's $MFT and change journal into `sink`:

        sink.events(rows)      fs_events rows
        sink.findings(rows)    file_findings rows
        sink.journal(rows)     usn_journal rows

    Returns (entries, events, journal records)."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.core.containers import ByteWindow

    mft = fs.open_meta(inode=0)
    mft_size = int(mft.info.meta.size)

    def open_mft():
        return ByteWindow(lambda offset, length: mft.read_random(
            offset, length), 0, mft_size)

    def report(stage, done, total):
        if progress:
            progress(stage, done, total)

    table, extensions = build_path_table(open_mft, should_stop)
    report('mft', 0, mft_size)

    events, findings = [], []
    entries = event_count = 0
    for index, entry in iter_records(
            open_mft(), should_stop=should_stop,
            progress=lambda done, total: report('mft', done, total),
            total=mft_size):
        if entry.base_index:
            continue
        for part in extensions.get(index, ()):
            entry.merge(part)
        entries += 1
        path = table.entry_path(entry)
        ref = make_artifact_ref(start, index, ref_sequence(entry))
        deleted = 0 if entry.in_use else 1
        for when, letters, source in entry_events(entry, path):
            events.append((ref, path, when, letters, source, deleted))
        reader = _entry_stream_reader(fs, index) if any(
            s.name and (s.data is None) for s in entry.streams) else None
        for kind, grade, summary, detail in entry_findings(entry, path,
                                                           reader):
            findings.append((ref, path.rsplit('/', 1)[-1], path,
                             _main_size(entry), kind, grade, summary,
                             json.dumps(detail, default=str)))
        if len(events) >= 5000:
            event_count += len(events)
            sink.events(events)
            events = []
        if len(findings) >= 500:
            sink.findings(findings)
            findings = []
    event_count += len(events)
    sink.events(events)
    sink.findings(findings)

    journal = 0
    try:
        usn_file = fs.open('/$Extend/$UsnJrnl')
    except Exception:
        usn_file = None
    found = _tsk_stream_reader(usn_file, '$J') if usn_file is not None \
        else None
    if found is not None:
        reader, size, first = found
        window = ByteWindow(reader, 0, size)
        rows = []
        for record in iter_usn(
                window, start=first, end=size, should_stop=should_stop,
                progress=lambda done, total: report('journal', done, total)):
            rows.append(usn_row(record, table, start))
            if len(rows) >= 5000:
                journal += len(rows)
                sink.journal(rows)
                rows = []
        journal += len(rows)
        sink.journal(rows)
    return entries, event_count, journal


def ref_sequence(entry):
    """The sequence a reference to this entry carries. NTFS increments a
    record's sequence when it frees it, so a deleted file's own record
    reads one past the sequence its folder entry and every reference to it
    recorded -- which is the one The Sleuth Kit lists it under."""
    if entry.in_use or entry.sequence == 0:
        return entry.sequence
    return entry.sequence - 1


def usn_row(record, table, start):
    from trace_app.core.case import make_artifact_ref
    path = table.path(record.parent_index, record.parent_sequence,
                      record.name)
    return (record.usn, filetime_text(record.time) or '',
            make_artifact_ref(start, record.file_index, record.file_sequence),
            record.file_index, record.file_sequence, record.parent_index,
            record.parent_sequence, record.name, path,
            usn_reason_text(record.reasons), record.reasons,
            record.attributes)


def _main_size(entry):
    for stream in entry.streams:
        if not stream.name:
            return stream.size
    return None


def _entry_stream_reader(fs, index):
    try:
        tsk_entry = fs.open_meta(inode=index)
    except Exception:
        return None

    def read(name, length):
        found = _tsk_stream_reader(tsk_entry, name)
        if found is None:
            return None
        reader, size, _first = found
        try:
            return reader(0, min(length, size)) if size else b''
        except Exception:
            return None
    return read


class _CaseSink:
    def __init__(self, case, evidence_id):
        self.case = case
        self.evidence_id = evidence_id

    def events(self, rows):
        if rows:
            self.case.add_fs_events(self.evidence_id, rows)

    def findings(self, rows):
        if rows:
            self.case.add_ntfs_findings(self.evidence_id, rows)

    def journal(self, rows):
        if rows:
            self.case.add_usn_records(self.evidence_id, rows)


def analyse_evidence(image_handler, case, evidence_id, progress=None,
                     should_stop=None):
    """Every NTFS volume's $MFT times, streams and change journal into the
    case, replacing an earlier run's. Returns the number of MFT entries."""
    volumes = ntfs_volumes(image_handler)
    case.clear_ntfs(evidence_id)
    case.set_ntfs_state(evidence_id, 'running')
    totals = [0, 0, 0]
    sink = _CaseSink(case, evidence_id)

    def report(stage, done, total):
        if progress:
            label = '$MFT' if stage == 'mft' else '$UsnJrnl'
            progress(int(done // 1048576), max(1, int(total // 1048576)),
                     label)
    try:
        for start, fs in volumes:
            entries, events, journal = analyse_volume(
                fs, start, sink, report, should_stop)
            totals[0] += entries
            totals[1] += events
            totals[2] += journal
            case.commit()
    except NtfsCancelled:
        case.clear_ntfs(evidence_id)
        case.set_ntfs_state(evidence_id, 'cancelled')
        return 0
    except Exception as exc:
        case.clear_ntfs(evidence_id)
        case.set_ntfs_state(evidence_id, 'failed', last_error=str(exc))
        raise
    case.set_ntfs_state(evidence_id, 'done', entries=totals[0],
                        events=totals[1], journal=totals[2],
                        volumes=len(volumes))
    logger.info("NTFS: %d entries, %d time events, %d journal records from "
                "%d volume(s) of evidence %s", totals[0], totals[1],
                totals[2], len(volumes), evidence_id)
    return totals[0]

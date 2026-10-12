"""What carved system records say (no Qt).

Carving recovers the pieces of Windows' own records that outlive their
file -- a deleted event log's 64 KB chunks, MFT records, folder index
records, a hive's bins (core/carving_formats, the "System records"
types) -- alongside whole logs, hives and shortcuts. Here they are read
by the parsers TRACE already has for the live files:

* MFT and INDX records become file-system events (`fs_events`, sources
  'SI (carved)', 'FN (carved)', 'I30 (carved)'): a deleted file's name and
  times when its MFT entry was reused long ago. Written by the carve job,
  removed with the carve (Case.clear_carved);
* event logs and chunks, shortcuts and hive bins (whole hives too) become
  activity records marked "(carved)", read by the activity job as it reads
  carved SQLite databases (activity.run_evidence).

Each points at its carve's bytes on the image (a span ref), so a click
shows the record where it lies.
"""

import logging
import struct

logger = logging.getLogger('TRACE.CarvedArtifacts')

#: Carved types whose records become file-system events / activity.
FS_TYPES = ('mftrecord', 'indx')
ACTIVITY_TYPES = ('evtx', 'evtxchunk', 'lnk', 'hbin', 'regf')
FS_SOURCES = ('SI (carved)', 'FN (carved)', 'I30 (carved)')


# --- MFT and INDX records: file-system events ---------------------------------

def fs_rows(file_type, content, ref, offset):
    """[(ref, path, time, macb, source, deleted)] for a carved MFT or INDX
    record (Case.add_fs_events' rows)."""
    from trace_app.core import ntfs
    rows = []
    if file_type == 'mftrecord':
        entry = ntfs.parse_record(content, 0)
        if entry is None or not entry.names:
            return rows
        name = entry.best_name()
        path = (f"[carved MFT record @ {offset:,}]/{name.name}"
                f" (parent entry {name.parent_index})")
        for text, letters, source in ntfs.entry_events(entry, path):
            rows.append((ref, path, text, letters, f"{source} (carved)", 1))
    elif file_type == 'indx':
        from trace_app.core import ntfs_index
        record = ntfs_index.unprotect(content)
        if record is None:
            return rows
        seen = set()
        for found in ntfs_index.carve(record[0x18:]):
            key = (found['name'], found['parent'], found['times'])
            if key in seen:
                continue
            seen.add(key)
            parent = found['parent'][0] if found['parent'] else '?'
            path = (f"[carved index @ {offset:,}]/{found['name']}"
                    f" (parent entry {parent})")
            for value, letters in ntfs.macb_rows(found['times']):
                text = ntfs.filetime_text(value)
                if text:
                    rows.append((ref, path, text, letters, 'I30 (carved)', 1))
    return rows


# --- logs, shortcuts, hive bins: activity records ----------------------------------

def activity_records(rows, read):
    """Activity records for carved rows of ACTIVITY_TYPES; `read(row)` gives
    a row's bytes (None when they cannot be read)."""
    out = []
    for row in rows:
        kind = row.get('type')
        try:
            data = read(row)
        except Exception as exc:
            logger.debug("Carved %s unreadable: %s", row.get('name'), exc)
            continue
        if not data:
            continue
        where = dict(path=f"[carved]/{row.get('name') or row['offset']}",
                     ref=row.get('artifact_ref') or '')
        try:
            if kind in ('evtx', 'evtxchunk'):
                out += _events(kind, data, row, where)
            elif kind == 'lnk':
                out += _shortcut(data, row, where)
            elif kind in ('hbin', 'regf'):
                out += _keys(data[4096:] if kind == 'regf' else data, row,
                             where)
        except Exception as exc:          # one damaged carve, not the rest
            logger.debug("Carved %s not read: %s", row.get('name'), exc)
    return out


def _events(kind, data, row, where):
    from trace_app.core.activity import eventlogs, record
    events = eventlogs.from_chunk(data) if kind == 'evtxchunk' else \
        eventlogs.from_evtx(data)
    out = []
    for when, what, subject, detail, event in events:
        channel = event.get('channel') or ''
        detail = dict(detail, channel=channel or None,
                      **{'carved at byte': row['offset']})
        out.append(record('antivirus' if 'Defender' in channel else 'logons',
                          'Event log (carved)', when, what, subject, detail,
                          **where))
    return out


def _shortcut(data, row, where):
    from trace_app.core.activity import lnk, record
    try:
        shortcut = lnk.parse(data)
    except lnk.LnkError:
        return []
    target = shortcut.get('target') or ''
    detail = {key: shortcut.get(key) for key in (
        'arguments', 'working_dir', 'volume_label', 'volume_serial',
        'machine_id', 'target_size') if shortcut.get(key)}
    detail['carved at byte'] = row['offset']
    detail['basis'] = ("the target's times as the shortcut recorded them; "
                       "the shortcut's own file is gone")
    out = []
    for key, what in (('target_accessed', 'Shortcut target accessed'),
                      ('target_modified', 'Shortcut target modified'),
                      ('target_created', 'Shortcut target created')):
        if shortcut.get(key):
            out.append(record('files', 'Shortcut (carved)', shortcut[key],
                              what, target, detail, **where))
    if not out and target:
        out.append(record('files', 'Shortcut (carved)', None, 'Shortcut',
                          target, detail, **where))
    return out


class _Bins:
    """Carved hive bins, read at the hive offsets their cells record."""

    def __init__(self, data):
        self.bins = data
        self.base = struct.unpack_from('<I', data, 4)[0] if \
            len(data) >= 8 else 0
        self.data = range(self.base + len(data))       # len() only

    def at(self, offset, length):
        start = offset - self.base
        if start < 0:
            return b''
        return self.bins[start:start + length]


def hive_keys(data):
    """[{'path', 'name', 'written', 'values'}] of every key in carved hive
    bins -- in use or free when the bins were left -- with its path as far
    as its parents are in the bins ('…' where the chain leaves them)."""
    from trace_app.core import regf_deleted
    bins = _Bins(data)
    keys = {}
    position = 0
    while position + 32 <= len(data) and data[position:position + 4] == \
            b'hbin':
        size = struct.unpack_from('<I', data, position + 8)[0]
        cell = position + 32
        end = min(position + size, len(data))
        while cell + 4 <= end:
            length = abs(struct.unpack_from('<i', data, cell)[0])
            if length < 8:
                break
            offset = bins.base + cell
            if data[cell + 4:cell + 6] == b'nk':
                found = regf_deleted._key(bins, offset, length - 4)
                if found is not None:
                    found['free'] = struct.unpack_from('<i', data,
                                                       cell)[0] > 0
                    keys[offset] = found
            cell += length
        position += size or 4096

    def path_of(offset):
        parts, seen = [], set()
        while offset in keys and offset not in seen:
            seen.add(offset)
            key = keys[offset]
            if key['root']:
                return '/' + '/'.join(reversed(parts))
            parts.append(key['name'])
            offset = key['parent']
        return '…/' + '/'.join(reversed(parts))

    out = []
    for offset, key in keys.items():
        names = []
        if key['values'] and key['value_list'] not in (0, 0xFFFFFFFF):
            for value in regf_deleted._list(bins, key['value_list'],
                                            min(key['values'], 512)):
                body = bins.at(value, 4)
                limit = abs(struct.unpack('<i', body)[0]) - 4 \
                    if len(body) == 4 else 0
                found = regf_deleted._value(bins, value, limit) \
                    if limit > 0 else None
                if found is not None:
                    names.append(found['name'])
        out.append({'path': path_of(offset) if not key['root'] else '/',
                    'name': key['name'], 'written': key['written'],
                    'values': names, 'free': key['free']})
    return out


def _keys(data, row, where):
    import datetime
    from trace_app.core.activity import record
    out = []
    for key in hive_keys(data):
        written = datetime.datetime.strptime(
            key['written'], '%Y-%m-%d %H:%M:%S').replace(
            tzinfo=datetime.timezone.utc) if key['written'] else None
        detail = {'values': ', '.join(key['values'][:20]) or None,
                  'state': 'deleted (a free cell)' if key['free']
                  else 'in use when the bins were left',
                  'carved at byte': row['offset']}
        out.append(record('system', 'Registry (carved)', written,
                          'Key last written', key['path'], detail, **where))
    return out

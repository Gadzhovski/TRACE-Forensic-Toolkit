"""Deleted files and earlier versions on YAFFS (no Qt).

YAFFS never overwrites a page: a change writes new pages, a deletion
writes a header saying so, and the old pages stay on the flash until
garbage collection erases their block. So a NAND dump still holds files
that were deleted and what live files held before they changed. This
rebuilds them from every copy core/yaffs.py kept:

* YAFFS2 (sequence numbers): the file's state at each of its headers --
  a header is written when a file is closed (YAFFS's image makers write
  it before the data instead: a header with nothing before it is not a
  state, and is skipped) -- is, chunk by chunk, the
  newest copy written before that header that no truncation in between
  cut away. A deletion is a header naming the 'deleted' (or 'unlinked')
  folder; the version before it is the deleted file. A version is listed
  once (the same pages as a later one, or as the live file, add nothing).
  YAFFS2 keeps no checksum of a page's data, so a version counts as
  recoverable when every chunk its size needs is still there; one that
  lacks chunks (erased by garbage collection) is partly overwritten, and
  says how many bytes are missing;
* YAFFS1 (no sequence numbers -- of a page's two copies only a 2-bit
  serial tells the newer): deleted files only. YAFFS1 keeps a Hamming ECC
  of each 256 bytes in the spare (yaffs_ecc.c), so a chunk counts only
  when its ECC holds (a single flipped bit is corrected, as YAFFS
  corrects it) and only one copy of it survives -- two different copies
  with no sequence to order them are not guessed between.

Each version is a row of core/deleted.py's Deleted Files (`records`), read
like a live file (`entry`). Checked against qnxprobe's history images,
written by YAFFS's own code, whose generator (tools/yaffs_history.c) makes
every version's bytes known: each recovered version must equal one of
them exactly (tests/test_flash_filesystems.py).
"""

import logging
import stat

from trace_app.core import yaffs

logger = logging.getLogger('TRACE.YAFFS')

#: Recovered versions' identifiers, above any object id (18 bits in
#: YAFFS1, 28 in YAFFS2's tags).
VERSION_BASE = 1 << 32


def _column_parity(byte):
    """yaffs_ecc.c's column_parity_table, from its definition: bit 0 the
    byte's parity, bits 2-7 the parities of bit groups 0246, 1357, 0145,
    2367, 0123 and 4567."""
    value = bin(byte).count('1') & 1
    for shift, group in enumerate(((0, 2, 4, 6), (1, 3, 5, 7), (0, 1, 4, 5),
                                   (2, 3, 6, 7), (0, 1, 2, 3),
                                   (4, 5, 6, 7))):
        value |= (sum((byte >> n) & 1 for n in group) & 1) << (shift + 2)
    return value


_PARITY = bytes(_column_parity(b) for b in range(256))


def ecc256(data):
    """yaffs_ecc_calc: the 3 ECC bytes of 256 data bytes."""
    column = line = line_prime = 0
    for index, byte in enumerate(data):
        bits = _PARITY[byte]
        column ^= bits
        if bits & 1:
            line ^= index
            line_prime ^= ~index & 0xFF
    pairs = []
    for high in (0x80, 0x08):
        value = 0
        for step in range(4):
            mask = high >> step
            value |= (0x80 >> (2 * step)) if line & mask else 0
            value |= (0x40 >> (2 * step)) if line_prime & mask else 0
        pairs.append(~value & 0xFF)
    return bytes((pairs[1], pairs[0], (~column | 0x03) & 0xFF))


def ecc_correct(data, stored):
    """(data, ok): data as it should read given its stored ECC -- a single
    flipped data bit corrected, as yaffs_ecc_correct does -- or ok False."""
    test = ecc256(data)
    d0, d1, d2 = (a ^ b for a, b in zip(stored, test))
    if not d0 | d1 | d2:
        return data, True
    if ((d0 ^ (d0 >> 1)) & 0x55) == 0x55 and \
            ((d1 ^ (d1 >> 1)) & 0x55) == 0x55 and \
            ((d2 ^ (d2 >> 1)) & 0x54) == 0x54:
        byte = bit = 0
        for flag, value in ((d1 & 0x80, 0x80), (d1 & 0x20, 0x40),
                            (d1 & 0x08, 0x20), (d1 & 0x02, 0x10),
                            (d0 & 0x80, 0x08), (d0 & 0x20, 0x04),
                            (d0 & 0x08, 0x02), (d0 & 0x02, 0x01)):
            if flag:
                byte |= value
        for flag, value in ((d2 & 0x80, 4), (d2 & 0x20, 2), (d2 & 0x08, 1)):
            if flag:
                bit |= value
        fixed = bytearray(data)
        fixed[byte] ^= 1 << bit
        return bytes(fixed), True
    if bin(d0).count('1') + bin(d1).count('1') + bin(d2).count('1') == 1:
        return data, True                       # the ECC itself flipped
    return data, False


def _cut_away(headers, key, start):
    """True when, before `key`, a header shrank the file to `start` or
    less after one had made it longer -- what was there reads as zeros
    once the file grows again (a region never written stays unknown)."""
    longest = 0
    for seq, index, header in headers:
        if (seq, index) >= key:
            break
        if header['type'] != yaffs.FILE:
            continue
        if header['size'] <= start < longest:
            return True
        longest = max(longest, header['size'])
    return False


class Version:
    """One recovered state of an object: its header (name, parent, times,
    mode), size, and per chunk the page index it reads from (None: zeros
    the file holds there; MISSING: a chunk no longer on the flash)."""

    MISSING = -1

    def __init__(self, obj, header, size, pages, kind, written):
        self.obj = obj
        self.header = header
        self.size = size
        self.pages = pages              # [(index | None | MISSING, nbytes)]
        self.kind = kind                # 'deleted' | 'earlier version'
        self.written = written          # the header's sequence number
        self.identifier = None
        self.fixed = {}                 # chunk -> corrected bytes (YAFFS1)

    def signature(self):
        return (self.size, tuple(index for index, _n in self.pages))


class VersionScan:
    """Every deleted file and earlier version a YAFFS image still holds."""

    def __init__(self, image):
        self.image = image
        self.versions = []
        try:
            if isinstance(image, yaffs.Yaffs1Image):
                self._yaffs1()
            else:
                self._yaffs2()
        except Exception as exc:              # damage: what was found stays
            logger.warning("YAFFS recovery stopped: %s", exc)
        for number, version in enumerate(self.versions):
            version.identifier = VERSION_BASE + number
        self._by_id = {v.identifier: v for v in self.versions}

    # -- YAFFS2 ------------------------------------------------------------

    def _yaffs2(self):
        image = self.image
        page = image.page_size
        gone = (yaffs.UNLINKED, yaffs.DELETED)
        for obj, headers in image.all_headers.items():
            headers = sorted(headers, key=lambda h: h[:2])
            if not any(h[2]['type'] == yaffs.FILE for h in headers):
                continue
            copies = image.all_chunks.get(obj, {})
            live_signature = None
            if obj in image.live and \
                    image.live[obj]['type'] == yaffs.FILE:
                current = image.chunks.get(obj, {})
                size = image.sizes.get(obj, 0)
                count = -(-size // page)
                live_signature = (size, tuple(
                    current[n][1] if n in current else None
                    for n in range(1, count + 1)))
            deleted_at = next((h[:2] for h in headers
                               if h[2]['parent'] in gone), None)
            seen = set()
            found = []
            for seq, index, header in headers:
                if header['type'] != yaffs.FILE or \
                        header['parent'] in gone or not header['size']:
                    continue
                key = (seq, index)
                pages = []
                for number in range(1, -(-header['size'] // page) + 1):
                    start = (number - 1) * page
                    best = None
                    for cseq, cindex, nbytes in copies.get(number, ()):
                        ckey = (cseq, cindex)
                        if ckey >= key:
                            continue
                        cut = any(ckey < h[:2] < key and
                                  h[2]['type'] == yaffs.FILE and
                                  h[2]['size'] <= start
                                  for h in headers)
                        if cut:
                            continue
                        if best is None or ckey > best[0]:
                            best = (ckey, cindex, nbytes)
                    if best is not None:
                        pages.append((best[1], best[2]))
                    elif _cut_away(headers, key, start):
                        pages.append((None, 0))   # cut away, then regrown
                    else:
                        pages.append((Version.MISSING, 0))
                version = Version(obj, header, header['size'], pages,
                                  'earlier version', seq)
                if version.signature() in seen or \
                        version.signature() == live_signature:
                    continue
                if all(index in (None, Version.MISSING)
                       for index, _n in pages):
                    # Nothing written before this header: YAFFS's image
                    # makers write a file's header before its data. Not a
                    # state the file was in -- except a deleted file's,
                    # whose name is worth listing even with no data left.
                    if obj in image.live or deleted_at is None or \
                            key > deleted_at:
                        continue
                    if any(k < deleted_at and k > key for k, _v in found):
                        continue
                seen.add(version.signature())
                found.append((key, version))
            if deleted_at is not None and found:
                # The newest state before the deletion is the deleted
                # file; any before it, its earlier versions.
                before = [v for key, v in found if key < deleted_at]
                if before:
                    before[-1].kind = 'deleted'
            self.versions.extend(v for _key, v in found)

    # -- YAFFS1 ------------------------------------------------------------

    def _yaffs1(self):
        image = self.image
        page = image.page_size
        stride = image.layout.stride
        gone = (yaffs.UNLINKED, yaffs.DELETED)
        by_object = {}
        for obj, chunk, serial, index, nbytes, deleted in image.copies1:
            by_object.setdefault(obj, {}).setdefault(chunk, []).append(
                (serial, index, nbytes, deleted))
        for obj, chunks in by_object.items():
            if obj in image.live or obj in (yaffs.ROOT, yaffs.LOST_FOUND):
                continue
            headers = []
            for _serial, index, _nbytes, _deleted in chunks.get(0, ()):
                image.source.seek(index * stride)
                header = yaffs.parse_header(
                    image.source.read(yaffs.HEADER_SIZE),
                    image.layout.header_order)
                if header is not None:
                    headers.append(header)
            named = {(h['name'], h['parent'], h['size']) for h in headers
                     if h['type'] == yaffs.FILE and
                     h['parent'] not in gone and h['size']}
            if len(named) != 1:
                continue                    # none, or no order to choose by
            name, parent, size = named.pop()
            header = next(h for h in headers if (h['name'], h['parent'],
                                                 h['size']) ==
                          (name, parent, size))
            version = Version(obj, header, size, [], 'deleted', 0)
            for number in range(1, -(-size // page) + 1):
                copies = chunks.get(number, ())
                read = {}
                for serial, index, nbytes, _deleted in copies:
                    image.source.seek(index * stride)
                    raw = image.source.read(stride)
                    data, spare = raw[:page], raw[page:]
                    first, ok1 = ecc_correct(data[:256], spare[8:11])
                    second, ok2 = ecc_correct(data[256:512], spare[13:16])
                    if ok1 and ok2:
                        read[first + second] = (index, nbytes)
                if len(read) == 1:
                    data, (index, nbytes) = next(iter(read.items()))
                    version.pages.append((index, nbytes))
                    version.fixed[number] = data
                else:
                    version.pages.append((Version.MISSING, 0))
            self.versions.append(version)

    # -- what Deleted Files and the reader ask -------------------------------

    def read(self, version, offset, length):
        page = self.image.page_size
        end = min(version.size, offset + length)
        out = bytearray()
        number = offset // page + 1
        while (number - 1) * page < end:
            index, nbytes = version.pages[number - 1]
            if number in version.fixed:
                data = version.fixed[number][:nbytes]
            elif index in (None, Version.MISSING):
                data = b''
            else:
                self.image.source.seek(index * self.image.layout.stride)
                data = self.image.source.read(page)[:nbytes]
            data += bytes(page - len(data))
            begin = max(offset - (number - 1) * page, 0)
            out += data[begin:min(end - (number - 1) * page, page)]
            number += 1
        return bytes(out)

    def _path(self, version):
        names = []
        parent, seen = version.header['parent'], set()
        while parent not in (yaffs.ROOT, 0) and parent not in seen:
            seen.add(parent)
            header = self.image.header(parent)
            if header is None:
                found = self.image.headers.get(parent)
                header = found[2] if found else None
            if header is None:
                names.append(f'[folder {parent}]')
                break
            names.append(header['name'].decode('utf-8', 'surrogateescape'))
            parent = header['parent']
        names.reverse()
        name = version.header['name'].decode('utf-8', 'surrogateescape')
        return '/' + '/'.join(names + [name])

    def records(self, offset, base, should_stop=None, progress=None,
                assess=None):
        from trace_app.core import deleted
        from trace_app.core.activity import times
        from trace_app.core.case import make_artifact_ref
        stride = self.image.layout.stride
        for count, version in enumerate(self.versions):
            if should_stop is not None and should_stop():
                raise deleted.DeletedCancelled()
            path = self._path(version)
            if progress is not None and count % 32 == 0:
                progress(count, len(self.versions), path)
            header = version.header
            missing = sum(1 for index, _n in version.pages
                          if index == Version.MISSING)
            lost = min(version.size, missing * self.image.page_size)
            record = {'volume': offset, 'path': path,
                      'name': path.rsplit('/', 1)[-1],
                      'inode': version.identifier, 'is_dir': False,
                      'sequence': None, 'size': version.size,
                      'overwritten': lost,
                      'runs': [(base + index * stride, nbytes)
                               for index, nbytes in version.pages
                               if index not in (None, Version.MISSING)],
                      'ref': make_artifact_ref(offset, version.identifier,
                                               None)}
            for key, field in (('accessed', 'atime'), ('changed', 'ctime'),
                               ('modified', 'mtime')):
                record[key] = times.iso(times.unix(header[field])) \
                    if header[field] else None
            record['created'] = None
            if assess is not None and not assess(path):
                record['state'] = deleted.NOT_ASSESSED
            elif not missing:
                record['state'] = deleted.RECOVERABLE
            elif missing < len(version.pages):
                record['state'] = deleted.PARTLY
            else:
                record['state'] = deleted.OVERWRITTEN
            basis = ('every chunk its size needs is on the flash (YAFFS2 '
                     'keeps no data checksum)'
                     if not isinstance(self.image, yaffs.Yaffs1Image) else
                     "every chunk's ECC holds, one copy each")
            record['detail'] = {'version': version.kind,
                                'object': version.obj,
                                'sequence': version.written or None,
                                'checked': basis if not missing else
                                f'{missing} of {len(version.pages)} chunks '
                                f'erased'}
            yield record

    def entry(self, value):
        version = self._by_id.get(value)
        if version is None:
            return None
        return _VersionEntry(self, version)


class _VersionEntry:
    """A recovered version, read like a live YaffsEntry."""

    def __init__(self, scan, version):
        self._scan = scan
        self._version = version
        header = version.header
        self.identifier = version.identifier
        self.parent_identifier = header['parent']
        self.name = header['name'].decode('utf-8', 'surrogateescape')
        self.file_mode = header['mode'] or (stat.S_IFREG | 0o644)
        self.size = version.size
        self.owner_identifier = header['uid']
        self.group_identifier = header['gid']
        self.deleted = True
        self.number_of_sub_file_entries = 0

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._version.header['mtime'] * 1_000_000_000

    def get_access_time_as_integer(self):
        return self._version.header['atime'] * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._version.header['ctime'] * 1_000_000_000

    symbolic_link_target = ''

    def read_buffer_at_offset(self, length, offset):
        return self._scan.read(self._version, offset, length)

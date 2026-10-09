"""Rebuilding a file the file system split into fragments -- when its
own structure proves where.

A carver that only takes contiguous runs loses any file stored in two
fragments. Guessing where the split lies would put foreign bytes into
evidence, so TRACE reassembles only formats that record the positions of
their own parts, and only when a checksum confirms the result:

* **ZIP** (and every format built on it -- DOCX, XLSX, ODT, EPUB, APK, JAR):
  the end-of-central-directory record gives the archive's logical size, so
  the physical span on disk minus that size is the gaps' total. The
  central directory lists every member's offset, and each member's local
  header is found shifted by the gaps before it -- a whole number of
  sectors, never less than the member before it. Where the shift grows,
  a gap lies in the member before: it is decompressed with the gap removed
  at each candidate sector boundary, and its CRC-32 confirms the one that
  is right.

* **PDF**: `startxref` and the cross-reference tables record every object's
  offset -- the same reasoning finds the gaps' total and, object by object,
  where each one lies, and the split object's Flate stream (whose Adler-32
  is part of the zlib format) confirms each boundary. A split in a text
  object is accepted only if exactly one boundary leaves it clean text; in
  an encrypted stream nothing can confirm it, so nothing is rebuilt.

The model is Garfinkel's bifragment gap carving (DFRWS 2007), extended to
any number of fragments as long as each gap falls in a different member or
object, so that each split has a checksum of its own to prove it:
fragments in order, each after the last, each starting on a sector
boundary. Two gaps inside one member, or fragments stored out of order,
are not attempted. A reassembled file is reported as such, with every
fragment's location.

Where the decompressor fails tells roughly where the split is: reading the
first fragment straight on, deflate breaks shortly after the foreign data
begins. Candidates are tried backwards from there, so the right boundary is
usually the first or second tried rather than one of thousands.
"""

import re
import struct
import zlib

SECTOR = 512

#: Candidate split points tried per file before giving up.
MAX_CANDIDATES = 4096

#: How far past a header to look for the file's end record.
SEARCH_WINDOW = 64 * 1024 * 1024


def _u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _deflate_break(src, start, raw, limit):
    """Where a deflate stream read straight on from `start` stops being
    valid: (position, finished). `raw` for ZIP's headerless deflate."""
    decompressor = zlib.decompressobj(-15 if raw else 15)
    pos = start
    step = 4096
    while pos - start < limit:
        data = src.get(pos, min(step, limit - (pos - start)))
        if not data:
            return pos, False
        try:
            decompressor.decompress(data, 1 << 20)
            while decompressor.unconsumed_tail:
                decompressor.decompress(decompressor.unconsumed_tail, 1 << 20)
        except zlib.error:
            return pos + len(data), False
        if decompressor.eof:
            return pos + len(data) - len(decompressor.unused_data), True
        pos += len(data)
    return pos, False


def _candidates(low, high, start, hint):
    """Sector-aligned split offsets in (low, high], nearest `hint` first."""
    first = low + 1
    aligned = first + (-(start + first) % SECTOR)
    points = list(range(aligned, high + 1, SECTOR))
    if hint is not None:
        points.sort(key=lambda k: (k > hint, abs(hint - k)))
    return points[:MAX_CANDIDATES]


# --- ZIP ---------------------------------------------------------------------

def reassemble_zip(src, start, cap):
    """(content, fragments) for a fragmented ZIP at `start`, or None."""
    window = src.get(start, min(cap + 1024 * 1024, SEARCH_WINDOW))
    if window[:4] != b'PK\x03\x04':
        return None
    for match in re.finditer(rb'PK\x05\x06', window):
        eocd = match.start()
        tail = window[eocd:eocd + 22]
        if len(tail) < 22:
            continue
        entries = _u16(tail, 10)
        cd_size, cd_offset = _u32(tail, 12), _u32(tail, 16)
        comment = _u16(tail, 20)
        logical = cd_offset + cd_size + 22 + comment
        physical = eocd + 22 + comment
        gap = physical - logical
        if gap <= 0 or gap % SECTOR or logical > cap or not entries:
            continue
        result = _zip_with_gap(src, start, window, eocd, cd_size, entries,
                               logical, gap)
        if result:
            return result
    return None


def _runs(pieces):
    """Physical (offset, length) runs, adjacent ones merged."""
    runs = []
    for offset, length in pieces:
        if length <= 0:
            continue
        if runs and runs[-1][0] + runs[-1][1] == offset:
            runs[-1] = (runs[-1][0], runs[-1][1] + length)
        else:
            runs.append((offset, length))
    return runs


def _shifts(anchors, total, present):
    """How far each anchor (in logical order) lies from where it says:
    0 for the first, then never less than the one before, a whole number
    of sectors more, at most `total`. `present(anchor, shift)` says whether
    the anchor is found there. None if one cannot be placed."""
    shifts = []
    shift = 0
    for anchor in anchors:
        while shift <= total and not present(anchor, shift):
            shift += SECTOR
        if shift > total:
            return None
        shifts.append(shift)
    return shifts if shifts and shifts[0] == 0 else None


def _zip_with_gap(src, start, window, eocd, cd_size, entries, logical, gap):
    """The archive rebuilt around its gaps (`gap` is their total)."""
    cd = window[eocd - cd_size:eocd]
    if cd[:4] != b'PK\x01\x02':
        return None
    members = []
    pos = 0
    for _ in range(entries):
        if cd[pos:pos + 4] != b'PK\x01\x02':
            return None
        method = _u16(cd, pos + 10)
        crc = _u32(cd, pos + 16)
        compressed = _u32(cd, pos + 20)
        name_len, extra_len, note_len = (_u16(cd, pos + 28), _u16(cd, pos + 30),
                                         _u16(cd, pos + 32))
        offset = _u32(cd, pos + 42)
        name = cd[pos + 46:pos + 46 + name_len]
        members.append((offset, method, crc, compressed, name))
        pos += 46 + name_len + extra_len + note_len
    members.sort()
    # The central directory's logical offset: where it is, less the gaps.
    cd_offset = eocd - gap - cd_size

    def header_at(member, shift):
        offset, name = member[0], member[4]
        head = src.get(start + offset + shift, 30 + len(name))
        return head[:4] == b'PK\x03\x04' and head[30:30 + len(name)] == name

    shifts = _shifts(members, gap, header_at)
    if shifts is None:
        return None
    pieces = []
    bounds = [m[0] for m in members[1:]] + [cd_offset]
    after = shifts[1:] + [gap]
    for member, shift, upper, next_shift in zip(members, shifts, bounds,
                                                after):
        offset = member[0]
        if upper < offset:
            return None
        if next_shift == shift:
            pieces.append((start + offset + shift, upper - offset))
            continue
        split = _zip_split(src, start, member, shift, next_shift, upper)
        if split is None:
            return None
        pieces.append((start + offset + shift, split - offset))
        pieces.append((start + split + next_shift, upper - split))
    pieces.append((start + cd_offset + gap, logical - cd_offset))
    fragments = _runs(pieces)
    content = b''.join(src.get(o, n) for o, n in fragments)
    if len(content) != logical:
        return None
    return content, fragments


def _zip_split(src, start, member, shift, next_shift, upper):
    """Where in this member the gap begins (a logical offset), proved by
    its CRC-32 with the gap removed; None if no boundary does."""
    offset, method, crc, compressed, _name = member
    head = src.get(start + offset + shift, 30)
    data_at = offset + 30 + _u16(head, 26) + _u16(head, 28)
    if method not in (0, 8):
        return None
    if method == 8:
        hint, _done = _deflate_break(src, start + shift + data_at, True,
                                     compressed)
        hint -= start + shift
    else:
        hint = None
    gap = next_shift - shift
    for split in _candidates(data_at, min(upper, data_at + compressed),
                             start + shift, hint):
        first = src.get(start + shift + data_at, split - data_at)
        second = src.get(start + split + next_shift,
                         data_at + compressed - split)
        member_data = first + second
        if len(member_data) != compressed or gap <= 0:
            continue
        try:
            plain = zlib.decompress(member_data, -15) if method == 8 \
                else member_data
        except zlib.error:
            continue
        if (zlib.crc32(plain) & 0xFFFFFFFF) == crc:
            return split
    return None


# --- PDF ---------------------------------------------------------------------

#: Line ends in a PDF are CR LF, LF -- or, from old Mac software, a bare CR.
_XREF_TABLE = re.compile(rb'(?<![A-Za-z0-9])xref[ \t]*[\r\n]')
_STARTXREF = re.compile(rb'startxref\s+(\d+)')
_PREV = re.compile(rb'/Prev\s+(\d+)')
_SUBSECTION = re.compile(rb'(\d+)[ \t]+(\d+)[ \t]*(?:\r\n|\r|\n)')
_ENTRY = re.compile(rb'(\d{10}) (\d{5}) ([nf])')
_OBJ_HEAD = re.compile(rb'(\d+)\s+(\d+)\s+obj')
_STREAM = re.compile(rb'stream(?:\r\n|\n|\r)')


def _table_entries(data, at):
    """(entries, trailer bytes) of the classic xref table at `at`."""
    entries = {}
    pos = data.index(b'xref', at) + 4
    while True:
        while pos < len(data) and data[pos] in b' \t\r\n':
            pos += 1
        sub = _SUBSECTION.match(data, pos)
        if not sub:
            break
        first, count = int(sub.group(1)), int(sub.group(2))
        pos = sub.end()
        for number in range(first, first + count):
            entry = _ENTRY.match(data, pos)
            if not entry:
                return entries, b''
            if entry.group(3) == b'n':
                entries[number] = (int(entry.group(1)), int(entry.group(2)))
            pos = entry.end()
            while pos < len(data) and data[pos] in b' \r\n':
                pos += 1
    end = data.find(b'startxref', pos)
    return entries, data[pos:end if end != -1 else pos + 4096]


def _stream_entries(data, at):
    """(entries, dictionary) of the cross-reference *stream* object at `at`
    (PDF 1.5+): a Flate stream of fixed-width rows, as /W describes."""
    head = _OBJ_HEAD.match(data, at)
    if not head:
        return None
    found = _STREAM.search(data, head.end(), head.end() + 4096)
    if not found:
        return None
    dictionary = data[head.end():found.start()]
    if b'/XRef' not in dictionary or b'/FlateDecode' not in dictionary:
        return None
    length = re.search(rb'/Length\s+(\d+)(?!\s+\d+\s+R)', dictionary)
    widths = re.search(rb'/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]', dictionary)
    size = re.search(rb'/Size\s+(\d+)', dictionary)
    if not (length and widths and size):
        return None
    try:
        rows = zlib.decompress(data[found.end():found.end() + int(length.group(1))])
    except zlib.error:
        return None
    w = [int(x) for x in widths.groups()]
    index = re.search(rb'/Index\s*\[([\d\s]+)\]', dictionary)
    ranges = [int(x) for x in index.group(1).split()] if index else \
        [0, int(size.group(1))]
    entries = {}
    pos = 0
    width = sum(w)
    for first, count in zip(ranges[::2], ranges[1::2]):
        for number in range(first, first + count):
            row = rows[pos:pos + width]
            pos += width
            if len(row) < width:
                return entries, dictionary
            fields, at_ = [], 0
            for size_ in w:
                fields.append(int.from_bytes(row[at_:at_ + size_], 'big'))
                at_ += size_
            kind = fields[0] if w[0] else 1
            if kind == 1:
                entries[number] = (fields[1], fields[2] if w[2] else 0)
    return entries, dictionary


def pdf_contradicts_itself(content):
    """Do this PDF's own cross-reference tables list an object where its
    bytes hold none, or past its end? That is a file carved straight across
    a gap, which PyMuPDF opens anyway -- it rebuilds a broken xref by
    scanning -- so it would otherwise pass as recovered intact."""
    found = {m.start() for m in _XREF_TABLE.finditer(content)}
    at = content.find(b'/XRef')
    while at != -1:
        head = content.rfind(b' obj', max(0, at - 400), at)
        if head != -1:
            line = max(content.rfind(b'\n', 0, head),
                       content.rfind(b'\r', 0, head)) + 1
            if _OBJ_HEAD.match(content, line):
                found.add(line)
        at = content.find(b'/XRef', at + 5)
    for position in found:
        try:
            parsed = _table_entries(content, position) \
                if content.startswith(b'xref', position) or \
                _XREF_TABLE.match(content, position) \
                else _stream_entries(content, position)
        except (ValueError, IndexError):
            parsed = None
        if not parsed:
            continue
        for number, (offset, generation) in parsed[0].items():
            if not content[offset:offset + 40].startswith(
                    b'%d %d obj' % (number, generation)):
                return True
    return False


def reassemble_pdf(src, start, cap):
    """(content, fragments) for a fragmented PDF at `start`, or None."""
    window = src.get(start, min(cap + 1024 * 1024, SEARCH_WINDOW))
    if not window.startswith(b'%PDF-'):
        return None
    for eof in re.finditer(rb'%%EOF[\r\n]*', window):
        last = None
        for last in _STARTXREF.finditer(window, max(0, eof.start() - 1024),
                                        eof.start()):
            pass
        if last is None:
            continue
        result = _pdf_from_trailer(src, start, window, int(last.group(1)),
                                   last.start(), eof.end(), cap)
        if result:
            return result
    return None


def _pdf_from_trailer(src, start, window, startxref, startxref_at, end, cap):
    """Follow one file's own cross-reference chain, from the startxref just
    before a %%EOF, and let it find the gap.

    Each link names a table's logical offset. A table found where the link
    says is before the split; one that is not must have been pushed back by
    the gap, so each table actually present further on, a whole number of
    sectors later, is a candidate gap -- and the rest of the chain, followed
    with that gap, keeps it or rules it out. Every gap the chain allows is
    tried in turn: another file's tables lying inside this file's gap can
    make a wrong one look consistent, and the final checks are what reject it.
    """
    positions = []

    def table_positions():
        if not positions:
            found = {m.start() for m in _XREF_TABLE.finditer(window)}
            at = window.find(b'/XRef')
            while at != -1:
                head = window.rfind(b' obj', max(0, at - 400), at)
                if head != -1:
                    line = max(window.rfind(b'\n', 0, head),
                               window.rfind(b'\r', 0, head)) + 1
                    if _OBJ_HEAD.match(window, line):
                        found.add(line)
                at = window.find(b'/XRef', at + 5)
            positions.extend(sorted(found))
        return positions

    def parse(physical):
        if physical < 0 or physical >= len(window):
            return None
        try:
            if window.startswith(b'xref', physical) or \
                    _XREF_TABLE.match(window, physical):
                return _table_entries(window, physical)
            return _stream_entries(window, physical)
        except (ValueError, IndexError):
            return None

    def follow(offset, gap, entries, seen):
        """Yield (gap, entries) for each way the chain can be followed."""
        while offset is not None:
            if offset in seen:
                break
            seen = seen | {offset}
            parsed = parse(offset)
            if not (parsed and parsed[0]):
                if gap is None:
                    for physical in table_positions():
                        candidate = physical - offset
                        if candidate > 0 and candidate % SECTOR == 0 and \
                                end - candidate <= cap:
                            yield from follow(offset, candidate,
                                              dict(entries), seen - {offset})
                    return
                parsed = parse(offset + gap)
                if not (parsed and parsed[0]):
                    return
            table, trailer = parsed
            for number, value in table.items():
                entries.setdefault(number, value)
            prev = _PREV.search(trailer)
            offset = int(prev.group(1)) if prev else None
        if gap and len(entries) >= 2:
            yield gap, entries

    tried = 0
    for gap, entries in follow(startxref, None, {}, frozenset()):
        tried += 1
        if tried > 64:
            break
        result = _pdf_with_gap(src, start, entries, gap, end - gap,
                               startxref)
        if result:
            return result
    return None


def _pdf_with_gap(src, start, entries, gap, logical, table=None):
    """The document rebuilt around its gaps (`gap` is their total): every
    object found where the cross-reference says, shifted by the gaps
    before it; each gap proved inside the object it falls in. `table` is
    the last cross-reference's logical offset, which lies past every gap
    (that is how the total was found) -- so a gap in the last object is
    bounded too."""
    objects = sorted((offset, number, generation)
                     for number, (offset, generation) in entries.items())
    if len(objects) < 2:
        return None

    def object_at(anchor, shift):
        offset, number, generation = anchor
        return src.get(start + offset + shift, 40).startswith(
            b'%d %d obj' % (number, generation))

    shifts = _shifts(objects, gap, object_at)
    if shifts is None or gap <= 0:
        return None
    # Everything from the last cross-reference on lies past every gap.
    tail = table if table is not None and objects[-1][0] < table < logical \
        else logical
    if shifts[-1] != gap and tail == logical:
        return None
    pieces = [(start, objects[0][0])]
    bounds = [o[0] for o in objects[1:]] + [tail]
    following = shifts[1:] + [gap]
    for anchor, shift, upper, next_shift in zip(objects, shifts, bounds,
                                                following):
        offset = anchor[0]
        if next_shift == shift:
            pieces.append((start + offset + shift, upper - offset))
            continue
        split = _pdf_split(src, start, offset, upper, shift, next_shift)
        if split is None:
            return None
        pieces.append((start + offset + shift, split - offset))
        pieces.append((start + split + next_shift, upper - split))
    pieces.append((start + tail + gap, logical - tail))
    fragments = _runs(pieces)
    content = b''.join(src.get(o, n) for o, n in fragments)
    if len(content) != logical:
        return None
    if not all(content[offset:offset + 40].startswith(
            b'%d %d obj' % (number, generation))
            for offset, number, generation in objects):
        return None
    return content, fragments


def _pdf_split(src, start, offset, upper, shift, next_shift):
    """Where in the object at `offset` the gap begins (logical), or None.

    What decides it depends on the object. A Flate stream is decided by its
    checksum: the first candidate whose zlib data inflates to the end,
    Adler-32 and all, is the split. Anything else -- a dictionary, an
    uncompressed XML stream -- is text, which foreign bytes break: a
    candidate passes if the object comes out as clean text ending in
    "endobj" where the next object begins, and a split is accepted only if
    exactly one candidate passes. Two that pass would be a guess.
    """
    body = src.get(start + shift + offset, upper - offset)
    found = _STREAM.search(body)
    dictionary = body[:found.start()] if found else body
    flate = bool(found) and b'/FlateDecode' in dictionary
    if found and not flate and b'/Filter' in dictionary:
        return None             # binary stream nothing can check: not guessed
    if flate:
        low = offset + found.end()
        hint, _done = _deflate_break(src, start + shift + low, False,
                                     upper - low)
        hint -= start + shift
    else:
        low, hint = offset, None

    def joined(split):
        first = src.get(start + shift + offset, split - offset)
        second = src.get(start + split + next_shift, upper - split)
        if len(first) + len(second) != upper - offset:
            return None
        return first + second

    passing = []
    for split in _candidates(low, upper, start + shift, hint):
        text = joined(split)
        if text is None:
            continue
        if flate:
            decompressor = zlib.decompressobj()
            try:
                decompressor.decompress(text[low - offset:])
            except zlib.error:
                continue
            if decompressor.eof:
                return split
        elif _clean_object(text):
            passing.append(split)
            if len(passing) > 1:
                return None
    return passing[0] if len(passing) == 1 else None


def _clean_object(text):
    """Is this a whole PDF object written as text: printable syntax (UTF-8
    in XML metadata allowed), and "endobj" as its last word?"""
    if any(b < 0x20 and b not in (0x09, 0x0A, 0x0C, 0x0D) for b in text):
        return False
    if sum(1 for b in text if b > 0x7E) > len(text) // 20:
        return False
    return text.rstrip().endswith(b'endobj')

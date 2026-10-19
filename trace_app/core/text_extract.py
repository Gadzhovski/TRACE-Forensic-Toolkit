"""Getting readable text out of the files found in evidence.

Search is only as good as what it can read. A PDF that yields nothing to the
index is a PDF an examiner cannot find by its contents, so each format gets a
real parser where one is already available, and a printable-strings fallback
where none is.

Strings are extracted as UTF-8 *and* UTF-16LE. TRACE's text viewer has always
been ASCII-only, which is where most Windows artifacts are invisible: registry
values, shortcut targets, event log strings and most of the Windows API's
output are UTF-16.

Every extractor is defensive. A file recovered from evidence is untrusted and
frequently damaged; a parser that raises must cost one file's text, never the
indexing run.
"""

import io
import logging
import re
import zlib

logger = logging.getLogger('TRACE.TextExtract')

#: Shortest run of printable characters worth keeping. Three is noise; five
#: loses short but real strings like drive letters and registry value names.
MIN_STRING_LENGTH = 4


_PRINTABLE_ASCII = re.compile(rb'[\x20-\x7e\t\r\n]{%d,}' % MIN_STRING_LENGTH)

#: UTF-16 runs are units of two bytes at either alignment: printable
#: ASCII (high byte 00) for the strings pass, and for script_runs also a
#: letter of a non-Latin alphabet -- Greek, Cyrillic, Armenian, Hebrew,
#: Arabic (U+0370-06FF, high byte 03-06) -- mixed with ASCII spaces,
#: digits and punctuation, in either byte order. The Latin-only pass saw
#: none of that: NIST's Russian Tea Room menu (UTF-16BE) was invisible
#: wherever it was not a whole .txt file. CJK is left out: its code
#: points cover a third of all byte pairs, and blind matching would read
#: every compressed file as Chinese.
#:
#: Runs are found as re.finditer would find (?:<unit>){4,} -- leftmost
#: first, never overlapping, each as long as it goes -- with the units
#: classified in C (bytes.translate, big-int masks): that regex tried its
#: alternation at every byte offset, 13 MB/s, a tenth of indexing a
#: Windows image.
_UNIT_RUN = re.compile(rb'\x01{%d,}' % MIN_STRING_LENGTH)
_IS_ZERO = bytes([1] + [0] * 255)
_IS_PRINTABLE = bytes(1 if 0x20 <= b <= 0x7e else 0 for b in range(256))
_IS_SCRIPT = bytes(1 if 0x03 <= b <= 0x06 else 0 for b in range(256))

#: High bytes of U+0300-06FF, where the alphabets above live.
_SCRIPT_HIGH_BYTES = (b'\x03', b'\x04', b'\x05', b'\x06')


def _unit_runs(data, first, big_endian, scripts):
    """[(i, j)]: maximal runs, in code units counted from byte `first`, of
    MIN_STRING_LENGTH or more units that may belong to a run."""
    count = (len(data) - first) // 2
    if count < MIN_STRING_LENGTH:
        return []
    end = first + 2 * count
    if big_endian:
        high, low = data[first:end:2], data[first + 1:end:2]
    else:
        low, high = data[first:end:2], data[first + 1:end:2]

    def bits(raw, table):
        return int.from_bytes(raw.translate(table), 'big')
    ok = bits(high, _IS_ZERO) & bits(low, _IS_PRINTABLE)
    if scripts:
        ok |= bits(high, _IS_SCRIPT)
    return [match.span() for match in
            _UNIT_RUN.finditer(ok.to_bytes(count, 'big'))]


def _utf16_runs(data, big_endian=False, scripts=True):
    """(start, end) byte spans of the runs, in the order and extent the
    regex's finditer gives them: from each position, the earliest start in
    either alignment, as far as its run goes."""
    runs = (_unit_runs(data, 0, big_endian, scripts),
            _unit_runs(data, 1, big_endian, scripts))
    at = [0, 0]
    position = 0
    while True:
        best = None
        for first in (0, 1):
            found = runs[first]
            k = at[first]
            unit = max(0, (position - first + 1) // 2)  # first unit >= position
            while k < len(found) and \
                    found[k][1] - max(found[k][0], unit) < MIN_STRING_LENGTH:
                k += 1
            at[first] = k
            if k < len(found):
                i, j = found[k]
                start = first + 2 * max(i, unit)
                if best is None or start < best[0]:
                    best = (start, first + 2 * j)
        if best is None:
            return
        yield best
        position = best[1]


def script_runs(data, min_length=MIN_STRING_LENGTH):
    """[(offset, text)] of UTF-16 runs (either byte order) holding letters
    of a non-Latin alphabet. A run counts when most of its characters are
    letters or spaces and at least `min_length` are letters outside ASCII
    -- random bytes seldom manage that; text does. (A Latin-only UTF-16LE
    run is the strings pass's.)"""
    found = []
    data = bytes(data)
    for encoding in ('utf-16-le', 'utf-16-be'):
        # Where a code unit's high byte sits: odd bytes in LE, even in BE.
        high = 1 if encoding == 'utf-16-le' else 0
        for start, end in _utf16_runs(data, big_endian=not high):
            raw = data[start:end]
            # A letter of these alphabets has high byte 03-06, so fewer such
            # units than `min_length` cannot pass the test below. Counted in
            # C before decoding: decoding and testing every run character
            # by character -- most of them plain Latin UTF-16 in a binary --
            # was 41% of indexing a Linux image.
            units = raw[high::2]
            if sum(map(units.count, _SCRIPT_HIGH_BYTES)) < min_length:
                continue
            text = raw.decode(encoding, 'replace')
            foreign = sum(1 for c in text if c.isalpha() and ord(c) > 0x36F)
            letters = sum(1 for c in text if c.isalpha() or c.isspace())
            if foreign >= min_length and letters * 2 >= len(text) and \
                    '\ufffd' not in text:
                found.append((start, text, foreign))
    # Text in one byte order also reads in the other, a byte off, as
    # nearly the same letters (one junk character first, the last lost):
    # both readings are kept -- which is true cannot be told from the
    # letters -- and a search finds the word in the right one.
    found.sort()
    seen = set()
    kept = []
    for start, text, _foreign in found:
        if text not in seen:
            seen.add(text)
            kept.append((start, text))
    return kept


def _notepad_text(content):
    from trace_app.core.activity import notepad
    try:
        tab = notepad.parse(content)
    except (notepad.TabStateError, IndexError, ValueError):
        return None
    if 'text' not in tab:
        return None                       # a state file (.0.bin / .1.bin)
    return '\n'.join(filter(None, (tab.get('path'), tab['text'])))


def extract_text(content, name='', limit=None, skip_packed=False):
    """Readable text from `content`, chosen by what the file actually is.

    Returns an empty string rather than raising: a file whose text cannot be
    read is still indexed by name and path, and that is more useful than
    abandoning the run. `skip_packed`: a packed archive (packed_kind) that
    no parser reads gives '' rather than the strings of its bytes -- for a
    caller that has indexed its members (a damaged one keeps its strings:
    they are all there is).
    """
    if not content:
        return ''

    extension = ('.' + name.rsplit('.', 1)[-1].lower()) if '.' in name else ''

    try:
        from trace_app.core import pcap
        if pcap.is_capture(content[:4]):
            # A network capture: its hosts, looked-up names, URLs and TLS
            # server names -- what a keyword search or an indicator wants.
            text = pcap.text(pcap.summarise(content))
        elif extension == '.msg' or (
                content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' and
                _is_msg(content)):
            text = _from_msg(content)
        elif extension == '.pdf' or content[:5] == b'%PDF-':
            text = _from_pdf(content)
        elif _is_rtf(content):
            # Word writes non-ASCII as \'xx in each font's code page or as
            # \uN: read as plain text, its Russian was never searchable.
            from trace_app.core import rtf
            text = rtf.text(content)
        elif extension == '.bin' and content[:2] == b'NP' and \
                _notepad_text(content) is not None:
            # Windows 11 Notepad's tab state: the tab's text with its
            # unsaved edits applied -- typed a character per chunk, which
            # the strings of the raw bytes never join into words.
            text = _notepad_text(content)
        elif extension in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm',
                           '.pptm', '.dotm', '.xltm', '.potm', '.ppsm'):
            text = _from_ooxml(content, extension)
        elif extension in ('.doc', '.xls', '.ppt') or content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            text = _from_ole(content)
        elif extension in ('.txt', '.log', '.csv', '.json', '.xml', '.html',
                           '.htm', '.md', '.ini', '.cfg', '.conf', '.reg',
                           '.eml', '.rtf'):
            text = _from_plain(content)
        elif skip_packed and packed_kind(content):
            # A compressed or packed archive whose members the caller has
            # read and indexed on their own (indexer._index_archive): the
            # strings of its raw bytes are noise. Scanning them was a fifth
            # of indexing a Linux image -- every kernel module is an .xz.
            text = ''
        else:
            text = extract_strings(content, budget=limit)
    except Exception as exc:
        # Damaged input is the normal case here, not the exceptional one.
        logger.debug("No text from %s (%s): %s", name or '?',
                     type(exc).__name__, exc)
        try:
            text = extract_strings(content, budget=limit)
        except Exception:
            text = ''

    # Macro source is text a search should find (URLDownloadToFile, a URL).
    if content[:4] == b'PK\x03\x04' or \
            content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        try:
            from trace_app.core import vba
            project = vba.extract(content)
            if project is not None and project.modules:
                text = f"{text}\n{project.source}"
        except Exception as exc:
            logger.debug("No macro text from %s: %s", name or '?', exc)

    if limit and len(text) > limit:
        text = text[:limit]
    return text


#: Archive kinds (core/archives.detect_archive) whose own bytes hold no
#: text worth reading: compressed, or packed with their members (which are
#: indexed themselves).
_PACKED = frozenset(('zip', '7z', 'rar', 'tar', 'cpio', 'qnx_ifs', 'gzip', 'bzip2',
                     'xz', 'lzma', 'zlib', 'cab', 'lzh', 'alz', 'compress'))


def packed_kind(content):
    """The archive kind when `content` is a packed or compressed archive
    (_PACKED), else None."""
    from trace_app.core.archives import detect_archive
    try:
        kind = detect_archive(content)
    except Exception:
        return None
    return kind if kind in _PACKED else None


def _is_msg(content):
    from trace_app.core.msgfile import is_msg
    return is_msg(content)


def _is_rtf(content):
    """RTF by content, whatever the name: Word saves RTF as '.doc' too."""
    return bytes(content[:16]).lstrip()[:5] == b'{\\rtf'


def _from_msg(content):
    """An Outlook message: its header fields and body as text."""
    from trace_app.core import msgfile
    message = msgfile.Message.open(bytes(content))
    kind, body, _source = message.body()
    if kind == 'html':
        import re
        body = re.sub(r'<[^>]+>', ' ', body)
    facts = '\n'.join(f"{k}: {v}" for k, v in message.facts() if v)
    names = '\n'.join(a['name'] for a in message.attachments())
    return f"{facts}\n{names}\n{body}"


def extract_strings(content, min_length=MIN_STRING_LENGTH, budget=None):
    """Printable runs, in both ASCII and UTF-16LE.

    Windows stores most of its strings as UTF-16, so an ASCII-only pass misses
    registry values, shortcut targets and event log messages -- exactly the
    artifacts a search is most often looking for.

    `budget`: the caller keeps only that many characters (extract_text's
    limit), so the scan stops once it has them -- the text is the same as
    scanning everything and cutting it, without reading a 200 MB library to
    the end for strings that would be thrown away.
    """
    pieces = []
    size = -1                           # length of '\n'.join(pieces)
    for find, stop, separator, encoding in _STRING_SCANS:
        for found in _windows(content, find, stop):
            text = separator.join(found).decode(encoding, errors='replace')
            pieces.append(text)
            size += len(text) + 1
            if budget is not None and size >= budget:
                # More than the caller keeps; what it keeps is the same.
                return '\n'.join(pieces)

    if not _never_utf16_scripts(bytes(content[:4])):
        pieces += [text for _start, text in script_runs(content, min_length)]
    return '\n'.join(pieces)


def _latin_utf16(content, position, end):
    window = bytes(content[position:end])
    return [window[start:stop] for start, stop in
            _utf16_runs(window, scripts=False)]


#: (find, a byte no match can hold, separator, encoding) per strings pass:
#: printable ASCII, then printable UTF-16LE. Matches are taken a window at
#: a time, each window decoded once: decoding match by match was 16
#: million calls on one Windows image.
_STRING_SCANS = (
    (_PRINTABLE_ASCII.findall, re.compile(rb'[^\x20-\x7e\t\r\n]'), b'\n',
     'ascii'),
    (_latin_utf16, re.compile(rb'[^\x00\x20-\x7e]'), b'\n\x00', 'utf-16-le'),
)
_WINDOW = 1 << 20


def _windows(content, find, stop):
    """find(content, start, end) over `content`, a window at a time: each
    window ends at a byte no match can contain, so no match is cut in two
    and the matches are exactly those of one scan over the whole."""
    position, size = 0, len(content)
    while position < size:
        end = position + _WINDOW
        if end < size:
            boundary = stop.search(content, end)
            end = boundary.start() if boundary else size
        else:
            end = size
        found = find(content, position, end)
        if found:
            yield found
        position = end


def _never_utf16_scripts(head):
    """Whether a file's format never holds UTF-16 text in a non-Latin
    alphabet: ELF (Linux programs, libraries, kernel modules) and Mach-O.
    The search for it is a regex over every byte, and on a Linux image
    those formats are most of the bytes -- it was 41% of indexing one. PE
    files keep it: their resources can be Cyrillic or Arabic UTF-16."""
    return head == b'\x7fELF' or head in _MACHO_MAGICS


_MACHO_MAGICS = {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                 b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe'}


# --- format-specific ------------------------------------------------------

def _from_pdf(content):
    from pymupdf import open as fitz_open

    with fitz_open(stream=content, filetype='pdf') as document:
        return '\n'.join(page.get_text() for page in document)


def _from_ooxml(content, extension):
    """DOCX, XLSX and PPTX are ZIPs of XML; read the XML and strip the tags.

    Going through the ZIP directly rather than python-docx and openpyxl in
    turn keeps one code path for all three, and works on a file whose
    extension lies about its type.
    """
    import zipfile

    texts = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for name in archive.namelist():
            if not name.endswith('.xml'):
                continue
            if not any(part in name for part in
                       ('document', 'sheet', 'slide', 'sharedStrings',
                        'comments', 'notes')):
                continue
            try:
                xml = archive.read(name).decode('utf-8', errors='replace')
            except (KeyError, zipfile.BadZipFile, zlib.error):
                continue
            # Tags out, entities back, whitespace collapsed.
            plain = re.sub(r'<[^>]+>', ' ', xml)
            plain = (plain.replace('&amp;', '&').replace('&lt;', '<')
                     .replace('&gt;', '>').replace('&quot;', '"')
                     .replace('&apos;', "'"))
            plain = re.sub(r'\s+', ' ', plain).strip()
            if plain:
                texts.append(plain)
    return '\n'.join(texts)


def _from_ole(content):
    """Legacy Office. The streams hold text among the structure.

    Word 97 stores runs of text in WordDocument; Excel keeps strings in an SST
    record. Rather than implement two binary formats, the printable-string
    pass over the whole file gets the words, which is what search needs -- the
    layout is not being reconstructed.
    """
    return extract_strings(content)


def _from_plain(content):
    """Decode text, guessing the encoding when it is not obvious."""
    # A byte-order mark says. Counting NULs (below) does not: Cyrillic in
    # UTF-16BE is 04xx, with a NUL only for ASCII among it.
    if content[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return content.decode('utf-16', errors='replace')
    for encoding in ('utf-8-sig', 'utf-8'):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            pass

    # UTF-16 without a BOM is common in Windows logs and .reg exports; a high
    # proportion of interleaved nulls is the giveaway.
    sample = content[:4096]
    if sample.count(b'\x00') > len(sample) // 4:
        # Without a mark the NULs' side says the byte order (Python's
        # 'utf-16' assumes little-endian).
        big = sample[0::2].count(0) > sample[1::2].count(0)
        try:
            return content.decode('utf-16-be' if big else 'utf-16-le',
                                  errors='replace')
        except UnicodeDecodeError:
            pass

    # A legacy code page: the Text tab's guess, so a search finds the
    # words the examiner sees there.
    from trace_app.core import text_encoding
    return text_encoding.decode(content)[0]



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

#: Extensions handled by a real parser rather than the strings fallback.
PARSED_EXTENSIONS = {
    '.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt',
    '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.md',
    '.ini', '.cfg', '.conf', '.reg', '.eml', '.rtf',
}

_PRINTABLE_ASCII = re.compile(rb'[\x20-\x7e\t\r\n]{%d,}' % MIN_STRING_LENGTH)
_PRINTABLE_UTF16 = re.compile(
    rb'(?:[\x20-\x7e]\x00){%d,}' % MIN_STRING_LENGTH)


def extract_text(content, name='', limit=None):
    """Readable text from `content`, chosen by what the file actually is.

    Returns an empty string rather than raising: a file whose text cannot be
    read is still indexed by name and path, and that is more useful than
    abandoning the run.
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
        elif extension in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm',
                           '.pptm', '.dotm', '.xltm', '.potm', '.ppsm'):
            text = _from_ooxml(content, extension)
        elif extension in ('.doc', '.xls', '.ppt') or content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            text = _from_ole(content)
        elif extension in ('.txt', '.log', '.csv', '.json', '.xml', '.html',
                           '.htm', '.md', '.ini', '.cfg', '.conf', '.reg',
                           '.eml', '.rtf'):
            text = _from_plain(content)
        else:
            text = extract_strings(content)
    except Exception as exc:
        # Damaged input is the normal case here, not the exceptional one.
        logger.debug("No text from %s (%s): %s", name or '?',
                     type(exc).__name__, exc)
        try:
            text = extract_strings(content)
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


def _is_msg(content):
    from trace_app.core.msgfile import is_msg
    return is_msg(content)


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


def extract_strings(content, min_length=MIN_STRING_LENGTH):
    """Printable runs, in both ASCII and UTF-16LE.

    Windows stores most of its strings as UTF-16, so an ASCII-only pass misses
    registry values, shortcut targets and event log messages -- exactly the
    artifacts a search is most often looking for.
    """
    pieces = []

    for match in _PRINTABLE_ASCII.findall(content):
        pieces.append(match.decode('ascii', errors='replace'))

    for match in _PRINTABLE_UTF16.findall(content):
        pieces.append(match.decode('utf-16-le', errors='replace'))

    return '\n'.join(pieces)


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
    for encoding in ('utf-8-sig', 'utf-8'):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            pass

    # UTF-16 without a BOM is common in Windows logs and .reg exports; a high
    # proportion of interleaved nulls is the giveaway.
    sample = content[:4096]
    if sample.count(b'\x00') > len(sample) // 4:
        try:
            return content.decode('utf-16', errors='replace')
        except UnicodeDecodeError:
            pass

    try:
        import chardet
        guess = chardet.detect(content[:65536])
        if guess and guess.get('encoding'):
            return content.decode(guess['encoding'], errors='replace')
    except Exception:
        pass

    return content.decode('latin-1', errors='replace')



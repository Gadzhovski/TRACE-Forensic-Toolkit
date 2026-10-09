"""Office documents as static HTML, for the Application tab.

Rendering a DOCX the way Word does needs Word. What an examiner needs from the
Application tab is the document's content in its structure -- headings,
paragraphs, tables, sheets, slides -- and, because this is evidence, the parts
a casual reader never sees:

* **tracked changes**: text deleted under revision tracking is still in the
  file. It is shown struck through in red, insertions underlined, so what was
  removed is visible rather than silently dropped;
* **comments**, with their authors;
* **speaker notes** on slides, and **hidden** sheets.

The output is plain HTML built here, every piece of document text escaped, no
scripts, no external references. It is shown by the same offline viewer as an
HTML file, and nothing is written to disk.

No Qt here; this reads bytes and returns a string.
"""

import html
import io
import logging
import re
import zipfile
from xml.etree import ElementTree

logger = logging.getLogger('TRACE.DocumentPreview')

#: Largest member read out of an OOXML/ODF package. A document's XML is
#: rarely more than a few megabytes; anything far bigger is a decompression
#: bomb or not a document.
MAX_MEMBER_BYTES = 64 * 1024 * 1024

#: Spreadsheets are shown as tables, capped so a million-row sheet does not
#: build a million-row table. The cap is stated in the output when reached.
MAX_ROWS = 500
MAX_COLUMNS = 50

_W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
_S = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
_A = '{http://schemas.openxmlformats.org/drawingml/2006/main}'
_R = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'
_PKG = '{http://schemas.openxmlformats.org/package/2006/relationships}'
_TEXT = '{urn:oasis:names:tc:opendocument:xmlns:text:1.0}'
_TABLE = '{urn:oasis:names:tc:opendocument:xmlns:table:1.0}'
_DRAW = '{urn:oasis:names:tc:opendocument:xmlns:drawing:1.0}'
_OFFICE = '{urn:oasis:names:tc:opendocument:xmlns:office:1.0}'


class PreviewError(Exception):
    """The document could not be read as the format it claims to be."""


class EncryptedDocument(Exception):
    """The document is password-protected; `decrypt` with the password,
    then preview what it gives."""


def _count(number, noun):
    """'1 comment', '3 comments'."""
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _esc(text):
    return html.escape(text or '', quote=True)


def to_html(content, kind):
    """(html, notices) for an office document of `kind`.

    `kind` is one of filetypes.OFFICE_EXTENSIONS' values. `notices` are the
    findings worth stating outside the document -- tracked changes, comments,
    hidden sheets, speaker notes -- which the viewer puts in its notice bar,
    where they stay in view however far the document is scrolled.

    Raises PreviewError when the bytes are not that format.
    """
    readers = {'docx': _docx, 'xlsx': _xlsx, 'pptx': _pptx,
               'odt': _odf, 'ods': _odf, 'odp': _odf, 'legacy': _legacy,
               'msg': _msg, 'pcap': _pcap}
    reader = readers.get(kind)
    if reader is None:
        raise PreviewError(f"No reader for {kind}.")
    if is_encrypted(content):
        raise EncryptedDocument(
            "This Office document is password-protected: its content is "
            "encrypted. Unlock it with the password to read it.")
    if kind == 'pcap':
        return reader(content)
    if kind in ('legacy', 'msg'):
        body, notices = reader(content)
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as package:
                body, notices = reader(package)
        except zipfile.BadZipFile as exc:
            raise PreviewError(f"Not a valid {kind.upper()} package: {exc}")
    return _with_macros(content, body, notices)


def _with_macros(content, body, notices):
    """The document's VBA source after its text, and a notice saying what
    the macros do (core/vba.py). Escaped: shown, never run."""
    from trace_app.core import vba
    try:
        project = vba.extract(content)
    except Exception as exc:
        logger.debug("Macros not read: %s", exc)
        project = None
    if project is None:
        return body, notices
    found = vba.indicators(project)
    section = (f'<hr><h2>Macros (VBA source, as stored)</h2>'
               f'<p>{_esc(vba.summary(project, found))}</p>')
    for module in project.modules:
        section += (f'<h3>{_esc(module.name)}</h3>'
                    f'<pre>{_esc(module.source)}</pre>')
    grade = 'SUSPICIOUS: ' if found['grade'] == 'suspicious' else ''
    return body + section, [f"{grade}{vba.summary(project, found)}",
                            *notices]


def is_encrypted(content):
    """A password-protected Office file: an OOXML document encrypted into
    an OLE 'EncryptedPackage', or a 97-2003 file with its encryption flag
    or RC4/XOR header (msoffcrypto-tool's own test)."""
    if not bytes(content[:8]) == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return False
    if 'EncryptedPackage'.encode('utf-16-le') in content:
        return True
    try:
        import msoffcrypto
        handle = msoffcrypto.OfficeFile(io.BytesIO(content))
        return bool(handle.is_encrypted())
    except Exception:
        return False


def decrypt(content, password):
    """The document's plain bytes, decrypted in memory with `password`
    (msoffcrypto-tool: ECMA-376 agile/standard, RC4 CryptoAPI, XOR).
    Raises PreviewError when the password is wrong or the scheme unknown."""
    try:
        import msoffcrypto
    except ImportError as exc:
        from trace_app.infra import capabilities
        raise PreviewError(capabilities.reason('office_encrypted')) from exc
    try:
        handle = msoffcrypto.OfficeFile(io.BytesIO(content))
        handle.load_key(password=password)
        out = io.BytesIO()
        handle.decrypt(out)
    except Exception as exc:
        raise PreviewError(f"The document did not decrypt: {exc}") from exc
    return out.getvalue()


# --- package helpers ------------------------------------------------------------

def _read(package, name):
    """A member's bytes, or None if absent or implausibly large."""
    try:
        info = package.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_MEMBER_BYTES:
        logger.warning("Skipping %s: %d bytes uncompressed", name,
                       info.file_size)
        return None
    return package.read(info)


def _xml(package, name):
    data = _read(package, name)
    if data is None:
        return None
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        logger.debug("Could not parse %s: %s", name, exc)
        return None


def _rels(package, path):
    """{relationship id: target path} for the part at `path`."""
    folder, _, base = path.rpartition('/')
    root = _xml(package, f"{folder}/_rels/{base}.rels")
    targets = {}
    if root is None:
        return targets
    for rel in root.iter(f'{_PKG}Relationship'):
        target = rel.get('Target') or ''
        if not target.startswith('/'):
            target = f"{folder}/{target}"
        # Collapse "a/b/../c" so the name matches the ZIP's.
        parts = []
        for part in target.lstrip('/').split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part not in ('', '.'):
                parts.append(part)
        targets[rel.get('Id')] = '/'.join(parts)
    return targets


def _page(body, notices=()):
    return body, [n for n in notices if n]


# --- Word -------------------------------------------------------------------------

def _docx(package):
    root = _xml(package, 'word/document.xml')
    if root is None:
        raise PreviewError("The package has no readable word/document.xml.")
    body = root.find(f'{_W}body')
    stats = {'deleted': 0, 'inserted': 0}
    out = []
    for block in (body if body is not None else []):
        if block.tag == f'{_W}p':
            out.append(_docx_paragraph(block, stats))
        elif block.tag == f'{_W}tbl':
            out.append(_docx_table(block, stats))

    comments = _docx_comments(package)
    notices = []
    if stats['deleted'] or stats['inserted']:
        notices.append(
            f"Tracked changes: {_count(stats['deleted'], 'deletion')} and "
            f"{_count(stats['inserted'], 'insertion')} are still in the file. "
            f"Deleted text is shown struck through in red, insertions "
            f"underlined in green.")
    if comments:
        notices.append(f"{_count(len(comments), 'comment')}, listed at the "
                       f"end.")
    text = ''.join(out)
    if comments:
        text += '<h2>Comments</h2>' + ''.join(
            f'<p class="comment"><b>{_esc(author)}</b>'
            f'{" — " + _esc(date) if date else ""}<br>{_esc(body)}</p>'
            for author, date, body in comments)
    return _page(text, notices)


def _docx_runs(paragraph, stats):
    """A paragraph's text as HTML, with tracked changes marked.

    One walk carrying whether it is inside a deletion or an insertion, so a
    run is wrapped by what encloses it. Paragraph and run properties are
    skipped: they hold formatting, and revision marks on the paragraph mark
    itself, not text.
    """
    out = []

    def walk(node, mode):
        for child in node:
            tag = child.tag
            if tag in (f'{_W}pPr', f'{_W}rPr'):
                continue
            if tag == f'{_W}del':
                stats['deleted'] += 1
                walk(child, 'deleted')
            elif tag == f'{_W}ins':
                stats['inserted'] += 1
                walk(child, 'inserted')
            elif tag in (f'{_W}t', f'{_W}delText'):
                text = _esc(child.text or '')
                if mode == 'deleted' or tag == f'{_W}delText':
                    out.append(f'<span class="deleted">{text}</span>')
                elif mode == 'inserted':
                    out.append(f'<span class="inserted">{text}</span>')
                else:
                    out.append(text)
            elif tag == f'{_W}tab':
                out.append('&emsp;')
            elif tag in (f'{_W}br', f'{_W}cr'):
                out.append('<br>')
            else:
                walk(child, mode)

    walk(paragraph, '')
    return ''.join(out)


def _docx_paragraph(paragraph, stats):
    style = paragraph.find(f'{_W}pPr/{_W}pStyle')
    style = (style.get(f'{_W}val') or '') if style is not None else ''
    listed = paragraph.find(f'{_W}pPr/{_W}numPr') is not None
    text = _docx_runs(paragraph, stats)
    if not text.strip():
        return '<p>&nbsp;</p>'
    match = re.match(r'(?i)heading\s*(\d)', style)
    if style.lower() == 'title':
        return f'<h1>{text}</h1>'
    if match:
        level = min(int(match.group(1)) + 1, 6)
        return f'<h{level}>{text}</h{level}>'
    if listed:
        return f'<p class="item">• {text}</p>'
    return f'<p>{text}</p>'


def _docx_table(table, stats):
    rows = []
    for row in table.iter(f'{_W}tr'):
        cells = []
        for cell in row.findall(f'{_W}tc'):
            content = '<br>'.join(_docx_runs(p, stats)
                                  for p in cell.findall(f'{_W}p'))
            cells.append(f'<td>{content}</td>')
        rows.append(f'<tr>{"".join(cells)}</tr>')
    return f'<table>{"".join(rows)}</table>'


def _docx_comments(package):
    root = _xml(package, 'word/comments.xml')
    if root is None:
        return []
    comments = []
    for comment in root.iter(f'{_W}comment'):
        body = ' '.join(''.join(t.text or '' for t in p.iter(f'{_W}t'))
                        for p in comment.iter(f'{_W}p')).strip()
        comments.append((comment.get(f'{_W}author') or 'Unknown',
                         (comment.get(f'{_W}date') or '')[:19]
                         .replace('T', ' '), body))
    return comments


# --- Excel --------------------------------------------------------------------------

def _column_index(reference):
    letters = re.match(r'[A-Z]+', reference or '')
    if not letters:
        return None
    index = 0
    for char in letters.group(0):
        index = index * 26 + (ord(char) - 64)
    return index - 1


def _column_name(index):
    name = ''
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _xlsx(package):
    workbook = _xml(package, 'xl/workbook.xml')
    if workbook is None:
        raise PreviewError("The package has no readable xl/workbook.xml.")
    targets = _rels(package, 'xl/workbook.xml')

    shared = []
    strings = _xml(package, 'xl/sharedStrings.xml')
    if strings is not None:
        for item in strings.iter(f'{_S}si'):
            shared.append(''.join(t.text or '' for t in item.iter(f'{_S}t')))

    sections, notices = [], []
    for sheet in workbook.iter(f'{_S}sheet'):
        name = sheet.get('name') or 'Sheet'
        state = sheet.get('state') or 'visible'
        path = targets.get(sheet.get(f'{_R}id'))
        root = _xml(package, path) if path else None
        heading = _esc(name)
        if state != 'visible':
            heading += f' <span class="flag">({_esc(state)})</span>'
            notices.append(f"Sheet '{name}' is {state} in Excel.")
        if root is None:
            sections.append(f'<h2>{heading}</h2><p>(sheet not readable)</p>')
            continue
        sections.append(f'<h2>{heading}</h2>' + _xlsx_sheet(root, shared))
    return _page(''.join(sections), notices)


def _xlsx_sheet(root, shared):
    grid = {}
    truncated = False
    width = 0
    for row in root.iter(f'{_S}row'):
        try:
            number = int(row.get('r')) - 1
        except (TypeError, ValueError):
            number = len(grid)
        if number >= MAX_ROWS:
            truncated = True
            break
        for cell in row.findall(f'{_S}c'):
            column = _column_index(cell.get('r'))
            if column is None or column >= MAX_COLUMNS:
                truncated = truncated or (column or 0) >= MAX_COLUMNS
                continue
            kind = cell.get('t')
            value = cell.find(f'{_S}v')
            value = value.text if value is not None else ''
            if kind == 's':
                try:
                    value = shared[int(value)]
                except (ValueError, IndexError):
                    pass
            elif kind == 'inlineStr':
                value = ''.join(t.text or '' for t in cell.iter(f'{_S}t'))
            elif kind == 'b':
                value = 'TRUE' if value == '1' else 'FALSE'
            formula = cell.find(f'{_S}f')
            grid[(number, column)] = (value or '', formula is not None
                                      and bool(formula.text))
            width = max(width, column + 1)

    if not grid:
        return '<p>(empty sheet)</p>'
    height = max(r for r, _ in grid) + 1
    header = ''.join(f'<th>{_column_name(c)}</th>' for c in range(width))
    rows = [f'<tr><th></th>{header}</tr>']
    for r in range(height):
        cells = []
        for c in range(width):
            value, is_formula = grid.get((r, c), ('', False))
            mark = ' class="formula"' if is_formula else ''
            cells.append(f'<td{mark}>{_esc(value)}</td>')
        rows.append(f'<tr><th>{r + 1}</th>{"".join(cells)}</tr>')
    note = (f'<p class="flag">Showing the first {MAX_ROWS} rows and '
            f'{MAX_COLUMNS} columns.</p>' if truncated else '')
    return f'<table>{"".join(rows)}</table>{note}'


# --- PowerPoint -----------------------------------------------------------------------

def _slide_number(path):
    match = re.search(r'(\d+)\.xml$', path)
    return int(match.group(1)) if match else 0


def _drawing_paragraphs(root):
    out = []
    for paragraph in root.iter(f'{_A}p'):
        text = ''.join(t.text or '' for t in paragraph.iter(f'{_A}t'))
        if text.strip():
            out.append(f'<p>{_esc(text)}</p>')
    return ''.join(out)


def _pptx(package):
    slides = sorted((n for n in package.namelist()
                     if re.match(r'ppt/slides/slide\d+\.xml$', n)),
                    key=_slide_number)
    if not slides:
        raise PreviewError("The package holds no slides.")
    out, notes_count = [], 0
    for path in slides:
        number = _slide_number(path)
        root = _xml(package, path)
        body = _drawing_paragraphs(root) if root is not None else ''
        out.append(f'<h2>Slide {number}</h2>{body or "<p>(no text)</p>"}')
        for target in _rels(package, path).values():
            if 'notesSlide' in target:
                notes = _xml(package, target)
                text = _drawing_paragraphs(notes) if notes is not None else ''
                if text:
                    notes_count += 1
                    out.append(f'<div class="notes"><b>Speaker notes</b>'
                               f'{text}</div>')
    notices = ([f"{_count(notes_count, 'slide')} "
                f"{'carries' if notes_count == 1 else 'carry'} speaker notes."]
               if notes_count else [])
    return _page(''.join(out), notices)


# --- OpenDocument ----------------------------------------------------------------------

def _odf(package):
    root = _xml(package, 'content.xml')
    if root is None:
        raise PreviewError("The package has no readable content.xml.")
    body = root.find(f'{_OFFICE}body')
    out = []

    def walk(node):
        for child in node:
            tag = child.tag
            if tag == f'{_DRAW}page':
                name = child.get(f'{_DRAW}name') or 'Slide'
                out.append(f'<h2>{_esc(name)}</h2>')
                walk(child)
            elif tag == f'{_TEXT}h':
                out.append(f'<h2>{_esc("".join(child.itertext()))}</h2>')
            elif tag == f'{_TEXT}p':
                text = ''.join(child.itertext())
                out.append(f'<p>{_esc(text) if text.strip() else "&nbsp;"}'
                           f'</p>')
            elif tag == f'{_TABLE}table':
                # The table renders its own cells' paragraphs.
                out.append(_odf_table(child))
            else:
                walk(child)

    if body is not None:
        walk(body)
    return _page(''.join(out))


def _odf_table(table):
    name = table.get(f'{_TABLE}name')
    rows = []
    for row in table.iter(f'{_TABLE}table-row'):
        if len(rows) >= MAX_ROWS:
            break
        cells = []
        for cell in row.findall(f'{_TABLE}table-cell'):
            text = '<br>'.join(_esc(''.join(p.itertext()))
                               for p in cell.iter(f'{_TEXT}p'))
            repeat = int(cell.get(f'{_TABLE}number-columns-repeated') or 1)
            # Empty trailing cells are repeated thousands of times in ODS.
            cells.extend([f'<td>{text}</td>'] * (min(repeat, 1) if not text
                                                 else min(repeat, MAX_COLUMNS)))
            if len(cells) >= MAX_COLUMNS:
                break
        if any(c != '<td></td>' for c in cells):
            rows.append(f'<tr>{"".join(cells)}</tr>')
    heading = f'<h3>{_esc(name)}</h3>' if name else ''
    return f'{heading}<table>{"".join(rows)}</table>'


# --- legacy Office -------------------------------------------------------------------

def _legacy(content):
    from trace_app.core.text_extract import extract_strings
    text = extract_strings(content)
    return _page(f'<pre>{_esc(text)}</pre>', [
        "Legacy binary Office format: showing the readable text it contains. "
        "Layout and formatting are not reconstructed."])


# --- network captures ---------------------------------------------------------------

def _pcap(content):
    from trace_app.core import pcap
    try:
        summary = pcap.summarise(content)
    except pcap.PcapError as exc:
        raise PreviewError(str(exc)) from exc
    except ImportError as exc:
        from trace_app.infra import capabilities
        raise PreviewError(capabilities.reason('pcap')) from exc
    notices = [f"Network capture ({summary['format']}): "
               f"{summary['packets']:,} packets, {len(summary['hosts']):,} "
               f"hosts, {len(summary['dns']):,} DNS records, "
               f"{len(summary['http']):,} HTTP requests, "
               f"{len(summary['tls']):,} TLS server names."]
    if summary.get('damaged'):
        notices.append(f"Damaged: {summary['damaged']}.")
    return pcap.page(summary), notices


# --- Outlook messages --------------------------------------------------------------

def _msg(content):
    from trace_app.core import msgfile
    try:
        message = msgfile.Message.open(bytes(content))
    except msgfile.MsgError as exc:
        raise PreviewError(f"Not an Outlook message: {exc}") from exc
    page = message.page().decode('utf-8')
    inner = re.search(r'<body[^>]*>(.*)</body>', page, re.S | re.I)
    attachments = message.attachments()
    notices = [f"Outlook message (.msg). {len(attachments)} attachment"
               f"{'s' if len(attachments) != 1 else ''}"
               + (": open the file as an archive (double-click) to read "
                  "them." if attachments else '.')]
    hidden = [a['name'] for a in attachments if a['hidden']]
    if hidden:
        notices.append(f"Hidden attachments: {', '.join(hidden)}")
    return (inner.group(1) if inner else page), notices


# --- HTML files -----------------------------------------------------------------------

_META_CHARSET = re.compile(
    rb'<meta[^>]+charset\s*=\s*["\']?\s*([A-Za-z0-9_\-:.]+)', re.I)


def decode_html(content):
    """(text, encoding) for an HTML file, honouring its declared charset."""
    if content.startswith(b'\xef\xbb\xbf'):
        return content[3:].decode('utf-8', errors='replace'), 'utf-8'
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        return content.decode('utf-16', errors='replace'), 'utf-16'
    declared = _META_CHARSET.search(content[:4096])
    candidates = []
    if declared:
        candidates.append(declared.group(1).decode('ascii', 'ignore'))
    candidates.append('utf-8')
    for encoding in candidates:
        try:
            return content.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError):
            continue
    try:
        import chardet
        guess = (chardet.detect(content[:65536]) or {}).get('encoding')
        if guess:
            return content.decode(guess, errors='replace'), guess
    except Exception:
        pass
    return content.decode('latin-1'), 'latin-1'

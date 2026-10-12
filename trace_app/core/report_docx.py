"""The report as a Word document (.docx), written with the standard
library -- no python-docx, which needs lxml (TRACE.spec leaves lxml out).

The report's own HTML (core/report.py: every value already escaped, a
small fixed set of tags) is the one source: headings become Heading 1-4
with bookmarks named by their anchors, so the contents and every
internal link work; paragraphs, captions and "None." lines keep their
look; tables become Word tables with a repeating header row; badges are
coloured bold runs; monospace spans (hashes, paths) use Consolas;
pictures (data: URIs) become inline pictures at their pixel size. The
contents are a Word TOC field that Word and LibreOffice fill when the
file opens (settings: updateFields). A4, page numbers in the footer, the
classification (if any) in the header. No Qt.
"""

import base64
import datetime
import io
import re
import zipfile
from html.parser import HTMLParser
from xml.sax.saxutils import escape

_VOID = {'img', 'br', 'meta', 'hr', 'input', 'link'}
_BLOCK = {'p', 'div', 'h1', 'h2', 'h3', 'h4', 'table', 'ul', 'ol', 'li',
          'section', 'body', 'pre', 'blockquote'}
_GRADE_COLOURS = {'suspicious': 'C62828', 'notable': 'B26A00',
                  'clean': '2E7D32', 'benign': '5F6B7A'}
#: Pixels to EMU at 96 dpi.
_EMU = 9525
#: Widest picture on an A4 page between 2 cm margins (17 cm).
_MAX_WIDTH = int(17 / 2.54 * 914400)


class _Node:
    __slots__ = ('tag', 'attrs', 'children', 'parent')

    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []

    def classes(self):
        return set((self.attrs.get('class') or '').split())


class _Tree(HTMLParser):
    """The report's HTML as a node tree (it is generated, so well formed;
    a stray close tag is tolerated)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node('body', (), None)
        self.current = self.root

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in _VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(_Node(tag, attrs, self.current))

    def handle_endtag(self, tag):
        node = self.current
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.current = node.parent

    def handle_data(self, data):
        if data:
            self.current.children.append(data)


class _Writer:
    def __init__(self):
        self.media = []                 # (name, bytes, content type)
        self.relationships = []         # (id, type, target, external)
        self.picture_id = 0
        self.bookmark_id = 0

    # --- runs -------------------------------------------------------------------

    @staticmethod
    def _run(text, fmt):
        props = []
        if fmt.get('style'):
            props.append(f'<w:rStyle w:val="{fmt["style"]}"/>')
        if fmt.get('bold'):
            props.append('<w:b/>')
        if fmt.get('italic'):
            props.append('<w:i/>')
        if fmt.get('mono'):
            props.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" '
                         'w:cs="Consolas"/>')
        if fmt.get('colour'):
            props.append(f'<w:color w:val="{fmt["colour"]}"/>')
        if fmt.get('size'):
            props.append(f'<w:sz w:val="{fmt["size"]}"/>')
        if fmt.get('link'):
            props.append('<w:color w:val="1F5FAD"/><w:u w:val="single"/>')
        rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ''
        text = _xml_text(text)
        return (f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}'
                f'</w:t></w:r>')

    def inline(self, node, fmt):
        """Runs for an inline node (or text)."""
        if isinstance(node, str):
            text = re.sub(r'\s+', ' ', node)
            return [self._run(text, fmt)] if text else []
        tag, classes = node.tag, node.classes()
        fmt = dict(fmt)
        if tag in ('b', 'strong', 'th'):
            fmt['bold'] = True
        if tag in ('i', 'em'):
            fmt['italic'] = True
        if 'mono' in classes or tag in ('code', 'pre'):
            fmt['mono'] = True
        if 'badge' in classes:
            fmt['bold'] = True
            grade = next((c for c in classes if c in _GRADE_COLOURS), None)
            if grade:
                fmt['colour'] = _GRADE_COLOURS[grade]
        if tag == 'br':
            return ['<w:r><w:br/></w:r>']
        if tag == 'img':
            picture = self.picture(node)
            return [picture] if picture else []
        if tag in ('script', 'style', 'title', 'meta'):
            return []
        href = (node.attrs.get('href') or '') if tag == 'a' else ''
        internal = href.startswith('#') and len(href) > 1
        if internal:
            fmt['link'] = True
        runs = []
        for child in node.children:
            runs += self.inline(child, fmt)
        if internal:
            # Only links within the report: a link the evidence held
            # (a URL in a record) is text, never something to follow.
            return [f'<w:hyperlink w:anchor="{_bookmark(href[1:])}">'
                    + ''.join(runs) + '</w:hyperlink>']
        return runs

    def picture(self, node):
        source = node.attrs.get('src') or ''
        match = re.match(r'data:image/(png|jpe?g|gif);base64,(.*)$', source,
                         re.S)
        if not match:
            return None
        kind = 'jpeg' if match.group(1).startswith('jp') else match.group(1)
        try:
            data = base64.b64decode(match.group(2))
        except (ValueError, TypeError):
            return None
        width, height = _picture_size(data)
        if not width or not height:
            return None
        self.picture_id += 1
        number = self.picture_id
        name = f"image{number}.{'jpg' if kind == 'jpeg' else kind}"
        self.media.append((name, data, f"image/{kind}"))
        rid = f"rIdImage{number}"
        self.relationships.append((rid, 'image', f"media/{name}", False))
        cx, cy = width * _EMU, height * _EMU
        if cx > _MAX_WIDTH:
            cy, cx = cy * _MAX_WIDTH // cx, _MAX_WIDTH
        alt = escape(node.attrs.get('alt') or name, {'"': '&quot;'})
        return (
            '<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" '
            f'distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
            f'<wp:docPr id="{number}" name="Picture {number}" descr="{alt}"/>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/'
            'drawingml/2006/main"><a:graphicData uri="http://schemas.'
            'openxmlformats.org/drawingml/2006/picture"><pic:pic '
            'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/'
            f'picture"><pic:nvPicPr><pic:cNvPr id="{number}" '
            f'name="{name}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill>'
            f'<a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch>'
            '</pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/>'
            f'<a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect">'
            '<a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData>'
            '</a:graphic></wp:inline></w:drawing></w:r>')

    # --- blocks ------------------------------------------------------------------

    def paragraph(self, runs, style=None, keep_next=False, bookmark=None):
        props = []
        if style:
            props.append(f'<w:pStyle w:val="{style}"/>')
        if keep_next:
            props.append('<w:keepNext/>')
        ppr = f"<w:pPr>{''.join(props)}</w:pPr>" if props else ''
        mark = ''
        if bookmark:
            self.bookmark_id += 1
            mark = (f'<w:bookmarkStart w:id="{self.bookmark_id}" '
                    f'w:name="{_bookmark(bookmark)}"/>'
                    f'<w:bookmarkEnd w:id="{self.bookmark_id}"/>')
        return f"<w:p>{ppr}{mark}{''.join(runs)}</w:p>"

    def blocks(self, node, fmt=None, style=None):
        """Word blocks for a block-level node's content: inline runs
        gathered into paragraphs, nested blocks in order."""
        fmt = fmt or {}
        out, pending = [], []

        def flush():
            if any('<w:t' in r or '<w:drawing' in r or '<w:br' in r
                   for r in pending):
                out.append(self.paragraph(pending, style))
            pending.clear()

        for child in node.children:
            if isinstance(child, _Node) and child.tag in _BLOCK:
                flush()
                out += self.block(child, fmt)
            else:
                pending.extend(self.inline(child, fmt))
        flush()
        return out

    def block(self, node, fmt):
        tag, classes = node.tag, node.classes()
        if tag in ('h1', 'h2', 'h3', 'h4'):
            runs = []
            for child in node.children:
                runs += self.inline(child, {})
            return [self.paragraph(runs, f"Heading{tag[1]}", True,
                                   node.attrs.get('id'))]
        if tag == 'table':
            if 'toc' in classes:
                return []
            return [self.table(node)]
        if tag in ('ul', 'ol'):
            out = []
            for item in node.children:
                if isinstance(item, _Node) and item.tag == 'li':
                    out += self.blocks(item, fmt, 'ListBullet')
            return out
        if tag == 'p':
            style = None
            if 'caption' in classes or 'none' in classes or \
                    'note-meta' in classes:
                style = 'Caption'
            elif 'report-title' in classes:
                style = 'Title'
            elif 'report-case' in classes:
                style = 'Subtitle'
            elif 'toc-title' in classes:
                return []
            runs = []
            for child in node.children:
                runs += self.inline(child, fmt)
            return [self.paragraph(runs, style)]
        if tag == 'div' and 'toc-holder' in classes:
            return [_TOC_FIELD]
        if tag == 'div' and 'section' in classes:
            out = self.blocks(node, fmt)
            return out
        return self.blocks(node, fmt)

    def table(self, node):
        rows = []

        def collect(parent, header):
            for child in parent.children:
                if not isinstance(child, _Node):
                    continue
                if child.tag in ('thead', 'tbody', 'tfoot'):
                    collect(child, child.tag == 'thead')
                elif child.tag == 'tr':
                    rows.append((header, [c for c in child.children
                                          if isinstance(c, _Node) and
                                          c.tag in ('td', 'th')]))
        collect(node, False)
        if not rows:
            return ''
        columns = max(len(cells) for _h, cells in rows) or 1
        facts = 'facts' in node.classes()
        width = 9638 // columns          # twips across 17 cm
        grid = ''.join(f'<w:gridCol w:w="{width}"/>' for _ in range(columns))
        body = []
        for header, cells in rows:
            trpr = '<w:trPr><w:tblHeader/></w:trPr>' if header else ''
            out = [f'<w:tr>{trpr}']
            for cell in cells:
                bold = header or cell.tag == 'th'
                shade = '<w:shd w:val="clear" w:color="auto" ' \
                        'w:fill="E8EDF3"/>' if bold and not facts else ''
                content = self.blocks(cell, {'bold': bold, 'size': 18})
                if not content or not content[-1].startswith('<w:p'):
                    content.append('<w:p/>')
                out.append(f'<w:tc><w:tcPr><w:tcW w:w="{width}" '
                           f'w:type="dxa"/>{shade}</w:tcPr>'
                           + ''.join(content) + '</w:tc>')
            for _missing in range(columns - len(cells)):
                out.append(f'<w:tc><w:tcPr><w:tcW w:w="{width}" '
                           'w:type="dxa"/></w:tcPr><w:p/></w:tc>')
            out.append('</w:tr>')
            body.append(''.join(out))
        style = 'FactsTable' if facts else 'DataTable'
        return (f'<w:tbl><w:tblPr><w:tblStyle w:val="{style}"/>'
                '<w:tblW w:w="5000" w:type="pct"/><w:tblLayout '
                'w:type="autofit"/></w:tblPr>'
                f'<w:tblGrid>{grid}</w:tblGrid>' + ''.join(body) +
                '</w:tbl><w:p/>')


_TOC_FIELD = (
    '<w:p><w:pPr><w:pStyle w:val="TOCHeading"/></w:pPr><w:r><w:t>Contents'
    '</w:t></w:r></w:p><w:p><w:r><w:fldChar w:fldCharType="begin" '
    'w:dirty="true"/></w:r><w:r><w:instrText xml:space="preserve"> TOC '
    '\\o "1-2" \\h \\z \\u </w:instrText></w:r><w:r><w:fldChar '
    'w:fldCharType="separate"/></w:r><w:r><w:t>The contents are filled in '
    'when the document is opened (or: right-click, Update Field).</w:t>'
    '</w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    '<w:p><w:r><w:br w:type="page"/></w:r></w:p>')


def _bookmark(anchor):
    """A Word bookmark name: letters, digits, underscores, 40 at most,
    starting with a letter."""
    name = re.sub(r'[^A-Za-z0-9_]', '_', anchor or 'x')
    if not name[:1].isalpha():
        name = 'b' + name
    return name[:40]


def _xml_text(text):
    """Characters XML 1.0 cannot hold (raw names can) written visibly."""
    return ''.join(c if c in '\t\n\r' or 0x20 <= ord(c) < 0xD800 or
                   0xE000 <= ord(c) <= 0xFFFD or ord(c) > 0xFFFF else
                   f"\\x{ord(c):02x}" for c in text) if text else ''


def _picture_size(data):
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as image:
            return image.size
    except Exception:
        return 0, 0


_NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/'
       'main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/'
       'relationships" xmlns:wp="http://schemas.openxmlformats.org/'
       'drawingml/2006/wordprocessingDrawing"')

_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {_NS}>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri"
 w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="20"/><w:szCs w:val="20"/>
</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80"
 w:line="259" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal">
 <w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>
 <w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="1200"
 w:after="240"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3B5C"/>
 <w:sz w:val="52"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/>
 <w:basedOn w:val="Normal"/><w:rPr><w:color w:val="44546A"/>
 <w:sz w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>
 <w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr>
 <w:pageBreakBefore/><w:keepNext/><w:spacing w:before="240" w:after="120"/>
 <w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F3B5C"/>
 <w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>
 <w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/>
 <w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr>
 <w:rPr><w:b/><w:color w:val="1F3B5C"/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/>
 <w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/>
 <w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr>
 </w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/>
 <w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/>
 <w:outlineLvl w:val="3"/></w:pPr><w:rPr><w:b/><w:i/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/>
 <w:basedOn w:val="Normal"/><w:rPr><w:i/><w:color w:val="5F6B7A"/>
 <w:sz w:val="18"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name
 w:val="List Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:ind
 w:left="360" w:hanging="200"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="TOCHeading"><w:name
 w:val="TOC Heading"/><w:basedOn w:val="Heading1"/><w:pPr>
 <w:pageBreakBefore w:val="0"/><w:outlineLvl w:val="9"/></w:pPr></w:style>
<w:style w:type="table" w:styleId="DataTable"><w:name w:val="TRACE Data"/>
 <w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="B8C2CC"/>
 <w:left w:val="single" w:sz="4" w:color="B8C2CC"/><w:bottom w:val="single"
 w:sz="4" w:color="B8C2CC"/><w:right w:val="single" w:sz="4"
 w:color="B8C2CC"/><w:insideH w:val="single" w:sz="4" w:color="D5DCE3"/>
 <w:insideV w:val="single" w:sz="4" w:color="D5DCE3"/></w:tblBorders>
 <w:tblCellMar><w:left w:w="70" w:type="dxa"/><w:right w:w="70"
 w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
<w:style w:type="table" w:styleId="FactsTable"><w:name w:val="TRACE Facts"/>
 <w:tblPr><w:tblCellMar><w:left w:w="0" w:type="dxa"/><w:right w:w="120"
 w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"""


def _footer():
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:ftr {_NS}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
            '<w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t xml:space="preserve">'
            'Page </w:t></w:r><w:r><w:rPr><w:sz w:val="16"/></w:rPr>'
            '<w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText '
            'xml:space="preserve"> PAGE </w:instrText></w:r><w:r>'
            '<w:fldChar w:fldCharType="end"/></w:r><w:r><w:rPr>'
            '<w:sz w:val="16"/></w:rPr><w:t xml:space="preserve"> of </w:t>'
            '</w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r>'
            '<w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')


def _header(text):
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:hdr {_NS}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
            '<w:r><w:rPr><w:b/><w:color w:val="C62828"/><w:sz w:val="18"/>'
            f'</w:rPr><w:t>{escape(_xml_text(text))}</w:t></w:r></w:p>'
            '</w:hdr>')


def document_bytes(body_html, options, generated=None, version=''):
    """The .docx file's bytes for a report body (core/report's HTML)."""
    tree = _Tree()
    tree.feed(body_html)
    tree.close()
    writer = _Writer()
    blocks = writer.blocks(tree.root)
    generated = generated or datetime.datetime.now(datetime.timezone.utc)
    blocks.append(writer.paragraph([writer._run(
        f"Generated by TRACE {version} on "
        f"{generated.strftime('%Y-%m-%d %H:%M:%S UTC')}.", {})], 'Caption'))
    classification = (options.get('classification') or '').strip()
    rels = [('rIdStyles', 'styles', 'styles.xml', False),
            ('rIdSettings', 'settings', 'settings.xml', False),
            ('rIdFooter', 'footer', 'footer1.xml', False)]
    header_ref = ''
    if classification:
        rels.append(('rIdHeader', 'header', 'header1.xml', False))
        header_ref = '<w:headerReference w:type="default" r:id="rIdHeader"/>'
    section = (f'<w:sectPr>{header_ref}<w:footerReference w:type="default" '
               'r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/>'
               '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" '
               'w:left="1134" w:header="567" w:footer="567" w:gutter="0"/>'
               '</w:sectPr>')
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<w:document {_NS}><w:body>' + ''.join(blocks) + section +
                '</w:body></w:document>')
    base = 'http://schemas.openxmlformats.org/officeDocument/2006/' \
           'relationships/'
    rel_xml = ''.join(
        f'<Relationship Id="{rid}" Type="{base}{kind}" Target="{target}"/>'
        for rid, kind, target, _ext in rels + writer.relationships)
    types = {'png': 'image/png', 'jpg': 'image/jpeg', 'gif': 'image/gif'}
    title = escape(_xml_text(f"{options.get('title', '')} -- "
                             f"{options.get('case_name', '')}"))
    stamp = generated.strftime('%Y-%m-%dT%H:%M:%SZ')
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types"><Default Extension="rels" ContentType="'
            'application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            + ''.join(f'<Default Extension="{ext}" ContentType="{kind}"/>'
                      for ext, kind in types.items()) +
            '<Override PartName="/word/document.xml" ContentType="'
            'application/vnd.openxmlformats-officedocument.wordprocessingml.'
            'document.main+xml"/><Override PartName="/word/styles.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.'
            'wordprocessingml.styles+xml"/><Override PartName="/word/'
            'settings.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.wordprocessingml.settings+xml"/><Override '
            'PartName="/word/footer1.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
            + ('<Override PartName="/word/header1.xml" ContentType="'
               'application/vnd.openxmlformats-officedocument.'
               'wordprocessingml.header+xml"/>' if classification else '') +
            '<Override PartName="/docProps/core.xml" ContentType="'
            'application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="'
            'application/vnd.openxmlformats-officedocument.extended-'
            'properties+xml"/></Types>'))
        archive.writestr('_rels/.rels', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships"><Relationship Id="rId1" Type="'
            f'{base}officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
            'package/2006/relationships/metadata/core-properties" '
            'Target="docProps/core.xml"/><Relationship Id="rId3" Type="'
            f'{base}extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>'))
        archive.writestr('word/document.xml', document)
        archive.writestr('word/styles.xml', _STYLES)
        archive.writestr('word/settings.xml', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:settings {_NS}><w:updateFields w:val="true"/>'
            '<w:defaultTabStop w:val="720"/></w:settings>'))
        archive.writestr('word/footer1.xml', _footer())
        if classification:
            archive.writestr('word/header1.xml', _header(classification))
        archive.writestr('word/_rels/document.xml.rels', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            f'2006/relationships">{rel_xml}</Relationships>'))
        for name, data, _kind in writer.media:
            archive.writestr(f'word/media/{name}', data)
        archive.writestr('docProps/core.xml', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
            'package/2006/metadata/core-properties" xmlns:dc="http://purl.'
            'org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{title}</dc:title><dc:creator>'
            f'{escape(_xml_text(options.get("examiner") or ""))}'
            '</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">'
            f'{stamp}</dcterms:created></cp:coreProperties>'))
        archive.writestr('docProps/app.xml', (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/'
            'officeDocument/2006/extended-properties"><Application>TRACE '
            f'{escape(version)}</Application></Properties>'))
    return out.getvalue()


def write_docx(builder, body, path, options, version=''):
    """Write the report body as `path`."""
    data = document_bytes(body, options, builder.generated, version)
    with open(path, 'wb') as handle:
        handle.write(data)

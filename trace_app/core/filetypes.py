"""What the Application tab should do with a file, from its name and its content.

The viewer used to decide from the extension alone, against a list of five
image types, a few media types and PDF. Two things went wrong with that:

* Formats the libraries could already decode -- WebP, TIFF, ICO, SVG, EPUB,
  FLAC -- were reported as unsupported because nobody had listed them.
* An extension is a claim, not a fact. In a forensic tool the files most worth
  looking at are the ones whose name lies: a JPEG saved as ``step2.txt`` was
  shown as nothing, and a Word document named ``.jpg`` as a broken picture.

So the content is consulted as well. When libmagic identifies it with
confidence and that disagrees with the extension, the content wins and the plan
carries a note saying so, which the viewer shows above the file. When the
content is ambiguous -- a ZIP could be a DOCX, an EPUB or a CBZ; plain text
could be HTML -- the extension decides, because that is the case it is right
about.

No Qt here: this is a decision about evidence, and it is testable without a
display.
"""

import logging
import os

logger = logging.getLogger('TRACE.FileTypes')

VIEW_IMAGE = 'image'
VIEW_DOCUMENT = 'document'      # anything PyMuPDF renders as pages
VIEW_AUDIO = 'audio'
VIEW_VIDEO = 'video'
VIEW_HTML = 'html'
VIEW_OFFICE = 'office'          # read into structured, static HTML
VIEW_DATABASE = 'database'      # SQLite: tables and recovered records

#: Read from the head of a file to identify it.
HEAD_BYTES = 8192

# --- by extension -------------------------------------------------------------

#: Images. Qt decodes most of these itself; Pillow covers the rest (AVIF,
#: JPEG 2000, PSD, PCX, DDS, and HEIC through pi-heif) -- see the picture
#: viewer.
IMAGE_EXTENSIONS = {
    'jpg', 'jpeg', 'jpe', 'jfif', 'png', 'apng', 'bmp', 'dib', 'gif', 'webp',
    'tif', 'tiff', 'ico', 'cur', 'icns', 'svg', 'svgz', 'tga', 'pbm', 'pgm',
    'ppm', 'pnm', 'xbm', 'xpm', 'avif', 'jp2', 'j2k', 'jpf', 'jpx', 'psd',
    'pcx', 'dds', 'heic', 'heif',
}

#: Paged documents PyMuPDF opens, by extension -> its filetype name.
DOCUMENT_EXTENSIONS = {
    'pdf': 'pdf', 'epub': 'epub', 'xps': 'xps', 'oxps': 'xps', 'cbz': 'cbz',
    'fb2': 'fb2', 'mobi': 'mobi',
}

AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'oga', 'opus', 'aac', 'm4a', 'flac',
                    'wma'}
VIDEO_EXTENSIONS = {'mp4', 'm4v', 'mkv', 'webm', 'avi', 'mov', 'wmv', 'flv',
                    'mpg', 'mpeg', '3gp', 'ogv'}
HTML_EXTENSIONS = {'html', 'htm', 'xhtml', 'xht'}

#: Office formats, by extension -> the reader in document_preview.
OFFICE_EXTENSIONS = {
    'docx': 'docx', 'docm': 'docx', 'xlsx': 'xlsx', 'xlsm': 'xlsx',
    'pptx': 'pptx', 'pptm': 'pptx', 'odt': 'odt', 'ods': 'ods', 'odp': 'odp',
    'doc': 'legacy', 'xls': 'legacy', 'ppt': 'legacy',
    'dotm': 'docx', 'dotx': 'docx', 'xltm': 'xlsx', 'xltx': 'xlsx',
    'potm': 'pptx', 'ppsm': 'pptx', 'ppsx': 'pptx', 'dot': 'legacy',
    'xlt': 'legacy', 'pot': 'legacy', 'pps': 'legacy',
    'msg': 'msg',
}

# --- by content ----------------------------------------------------------------

#: libmagic answers precise enough to override an extension. Absent on
#: purpose: application/zip (a DOCX, EPUB and CBZ are all ZIPs), text/plain
#: (HTML is text), application/octet-stream (libmagic declining to say).
_MIME_DOCUMENTS = {
    'application/pdf': 'pdf',
    'application/epub+zip': 'epub',
    'application/oxps': 'xps',
    'application/vnd.ms-xpsdocument': 'xps',
    'application/x-mobipocket-ebook': 'mobi',
    'application/x-fictionbook+xml': 'fb2',
}
_MIME_OFFICE = {
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        'docx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation':
        'pptx',
    'application/vnd.oasis.opendocument.text': 'odt',
    'application/vnd.oasis.opendocument.spreadsheet': 'ods',
    'application/vnd.oasis.opendocument.presentation': 'odp',
    'application/msword': 'legacy',
    'application/vnd.ms-excel': 'legacy',
    'application/vnd.ms-powerpoint': 'legacy',
    'application/vnd.ms-outlook': 'msg',
}
_MIME_HTML = {'text/html', 'application/xhtml+xml'}
#: libmagic 5.35+ says vnd.sqlite3; 5.32 (Windows' python-magic-bin) x-sqlite3.
_MIME_DATABASE = {'application/vnd.sqlite3', 'application/x-sqlite3'}

#: SQLite's file header: a signature, so it settles what the file is.
SQLITE_HEADER = b'SQLite format 3\x00'

#: Names a SQLite database usually goes by -- only to say nothing about the
#: name. A database is never recognised *by* its name: Thumbs.db is OLE.
DATABASE_EXTENSIONS = {'db', 'sqlite', 'sqlite3', 'db3', 'sqlitedb', 'sdb',
                       'storedata', 'localstorage'}

#: What each plan is called in the viewer's notice.
_LABELS = {
    ('document', 'pdf'): 'PDF document', ('document', 'epub'): 'EPUB e-book',
    ('document', 'xps'): 'XPS document', ('document', 'cbz'): 'comic archive',
    ('document', 'fb2'): 'FictionBook e-book',
    ('document', 'mobi'): 'Mobipocket e-book',
    ('office', 'docx'): 'Word document', ('office', 'xlsx'): 'Excel workbook',
    ('office', 'pptx'): 'PowerPoint presentation',
    ('office', 'odt'): 'OpenDocument text',
    ('office', 'ods'): 'OpenDocument spreadsheet',
    ('office', 'odp'): 'OpenDocument presentation',
    ('office', 'legacy'): 'legacy Office document',
    ('office', 'msg'): 'Outlook message',
    ('office', 'pcap'): 'network capture',
    ('html', ''): 'HTML page',
    ('database', 'sqlite'): 'SQLite database',
}


class ViewPlan:
    """How to show one file: a kind, a subtype, and what to tell the examiner."""

    def __init__(self, kind, subtype='', mime='', note=''):
        self.kind = kind
        self.subtype = subtype
        self.mime = mime
        #: Shown above the file when not empty -- why it is shown as it is.
        self.note = note

    @property
    def label(self):
        if (self.kind, self.subtype) in _LABELS:
            return _LABELS[(self.kind, self.subtype)]
        if self.kind == VIEW_IMAGE:
            name = (self.subtype or 'image').upper()
            return f"{name} image" if self.subtype else 'image'
        if self.kind in (VIEW_AUDIO, VIEW_VIDEO):
            return self.kind
        return self.kind

    def __repr__(self):
        return (f"ViewPlan({self.kind!r}, {self.subtype!r}, mime={self.mime!r},"
                f" note={self.note!r})")


def extension_of(name):
    base = os.path.basename(name or '')
    return base.rsplit('.', 1)[-1].lower() if '.' in base else ''


def plan_from_name(name):
    """The plan the extension alone suggests, or None."""
    extension = extension_of(name)
    if extension in IMAGE_EXTENSIONS:
        return ViewPlan(VIEW_IMAGE, extension, f'image/{extension}')
    if extension in DOCUMENT_EXTENSIONS:
        return ViewPlan(VIEW_DOCUMENT, DOCUMENT_EXTENSIONS[extension])
    if extension in AUDIO_EXTENSIONS:
        return ViewPlan(VIEW_AUDIO, extension, f'audio/{extension}')
    if extension in VIDEO_EXTENSIONS:
        return ViewPlan(VIEW_VIDEO, extension, f'video/{extension}')
    if extension in HTML_EXTENSIONS:
        return ViewPlan(VIEW_HTML, '', 'text/html')
    if extension in OFFICE_EXTENSIONS:
        return ViewPlan(VIEW_OFFICE, OFFICE_EXTENSIONS[extension])
    return None


#: Types libmagic can only guess, from a few header values rather than a
#: signature: never confident enough to overrule an extension. TGA has no
#: magic number -- libmagic 5.41+ (macOS, Linux) calls the bytes 00 01 02
#: ... "Targa image data", so a deleted .pdf over other data was shown as a
#: broken picture there (5.32 on Windows has no such rule).
SIGNATURELESS_MIMES = frozenset({'image/x-tga'})


def plan_from_mime(mime):
    """The plan a confident libmagic answer implies, or None."""
    mime = (mime or '').lower()
    if mime in SIGNATURELESS_MIMES:
        return None
    if mime.startswith('image/'):
        subtype = mime.split('/', 1)[1]
        subtype = {'svg+xml': 'svg', 'x-icon': 'ico',
                   'vnd.microsoft.icon': 'ico', 'x-ms-bmp': 'bmp',
                   'x-portable-pixmap': 'ppm', 'vnd.adobe.photoshop': 'psd',
                   'x-tga': 'tga', 'jp2': 'jp2'}.get(subtype, subtype)
        return ViewPlan(VIEW_IMAGE, subtype, mime)
    if mime in _MIME_DOCUMENTS:
        return ViewPlan(VIEW_DOCUMENT, _MIME_DOCUMENTS[mime], mime)
    if mime in _MIME_OFFICE:
        return ViewPlan(VIEW_OFFICE, _MIME_OFFICE[mime], mime)
    if mime in _MIME_HTML:
        return ViewPlan(VIEW_HTML, '', mime)
    if mime in _MIME_DATABASE:
        return ViewPlan(VIEW_DATABASE, 'sqlite', mime)
    if mime.startswith('audio/'):
        return ViewPlan(VIEW_AUDIO, mime.split('/', 1)[1], mime)
    if mime.startswith('video/'):
        return ViewPlan(VIEW_VIDEO, mime.split('/', 1)[1], mime)
    return None


_magic = None
_magic_tried = False


def identify(content):
    """libmagic's MIME type for `content`, or '' if it cannot say."""
    global _magic, _magic_tried
    if not content:
        return ''
    if not _magic_tried:
        _magic_tried = True
        try:
            from trace_app.core.analysis import magic_reader
            _magic = magic_reader()
        except Exception as exc:
            logger.debug("libmagic unavailable: %s", exc)
    if _magic is None:
        return ''
    try:
        return _magic.from_buffer(bytes(content[:HEAD_BYTES])) or ''
    except Exception as exc:
        logger.debug("libmagic could not read the buffer: %s", exc)
        return ''


#: Acrobat accepts '%PDF-' anywhere in a file's first 1,024 bytes.
PDF_HEADER_WINDOW = 1024


def not_a_pdf(content):
    """Why `content`, named as a PDF, is not one -- or None when it starts
    like a PDF. A deleted file's name can outlive its data: the clusters
    of a deleted .pdf may be zeros or another file's bytes by now, and
    handing those to the PDF reader only produced 'Failed to open
    stream'."""
    head = bytes(content[:PDF_HEADER_WINDOW])
    if b'%PDF-' in head:
        return None
    if not head.strip(b'\0'):
        what = "its content is all zero bytes"
    else:
        mime = identify(content)
        what = ("its content is not recognisable as any format"
                if mime in ('', 'application/octet-stream') else
                f"its content is {mime}")
    return (f"Named as a PDF, but {what}: there is no PDF header in its "
            f"first {PDF_HEADER_WINDOW:,} bytes. A deleted file's clusters "
            f"can since hold zeros or another file's data. The Hex tab "
            f"shows what is there.")


def _same_family(a, b):
    """Audio and video are one family: an MP4 or ASF container holds either,
    and libmagic often names the container rather than what is in it."""
    media = (VIEW_AUDIO, VIEW_VIDEO)
    return a.kind == b.kind or (a.kind in media and b.kind in media)


def plan_view(name, content=None, mime=None):
    """Decide how to show a file, or return None if nothing can show it.

    `mime` may be passed when it is already known (analysis stored it);
    otherwise it is read from `content`.
    """
    extension = extension_of(name)
    if content and bytes(content[:len(SQLITE_HEADER)]) == SQLITE_HEADER:
        # Browser history, chat and app databases mostly have no extension
        # (Chrome's 'History') or a .db one: say so only when the name
        # suggests something else.
        plan = ViewPlan(VIEW_DATABASE, 'sqlite', 'application/vnd.sqlite3')
        named = plan_from_name(name)
        if named is not None or (extension and
                                 extension not in DATABASE_EXTENSIONS
                                 and len(extension) <= 5):
            plan.note = (f"Shown as a SQLite database: identified from its "
                         f"content, which a .{extension} file would not "
                         f"normally hold.")
        return plan
    from trace_app.core.pcap import is_capture
    if content and is_capture(content[:4]):
        # A capture is known by its magic: pcap (either byte order, micro-
        # or nanoseconds) or pcapng, whatever it is called.
        return ViewPlan(VIEW_OFFICE, 'pcap', 'application/vnd.tcpdump.pcap')
    if content and bytes(content[:8]) == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' \
            and extension != 'msg':
        # An Outlook message renamed: libmagic calls every compound file
        # 'CDFV2', so its streams say what it is.
        from trace_app.core.msgfile import is_msg
        if is_msg(content):
            plan = ViewPlan(VIEW_OFFICE, 'msg', 'application/vnd.ms-outlook')
            plan.note = ("Shown as an Outlook message: identified from its "
                         "content" + (f", which a .{extension} file would "
                                      f"not normally hold." if extension
                                      else "; the file has no extension."))
            return plan
    by_name = plan_from_name(name)
    if mime is None:
        mime = identify(content) if content else ''
    by_content = plan_from_mime(mime)

    if by_content is None:
        return by_name
    if by_name is None:
        if extension:
            by_content.note = (f"Shown as {by_content.label}: identified from "
                               f"its content, which a .{extension} file "
                               f"would not normally hold.")
        else:
            by_content.note = (f"Shown as {by_content.label}: the file has "
                               f"no extension, so it was identified from its "
                               f"content.")
        return by_content
    if _same_family(by_name, by_content):
        # The extension was right about what kind of thing this is. Prefer
        # the content's precise subtype for a document or office file, where
        # it chooses the reader; keep the name's for media and images.
        if by_name.kind in (VIEW_DOCUMENT, VIEW_OFFICE) and by_content.subtype:
            by_name.subtype = by_content.subtype
        by_name.mime = by_content.mime or by_name.mime
        return by_name

    by_content.note = (f"Shown as {by_content.label}: its content does not "
                       f"match the .{extension} extension.")
    return by_content

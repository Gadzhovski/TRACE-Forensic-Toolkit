"""Thumbnails for the icon views (the Listing's and Carved files'): what a
file is, by name and by content, and its picture, made off the UI thread.

A thumbnail is scaled to fit, never cropped -- a cropped thumbnail hides
part of the evidence. Kinds:

- picture: Qt's decoders, then Pillow (AVIF, PSD, HEIC through pi-heif);
- pdf: its first page, through PyMuPDF -- on the UI thread, since MuPDF
  shares one context and the PDF viewer uses it there (the bytes are still
  read on the loader thread);
- document: the preview an ODF file always carries
  (Thumbnails/thumbnail.png) and an Office file may (docProps/thumbnail.*),
  read with zipfile;
- video: a frame, from ui/viewers/media/video_thumbnails.py on the UI
  thread (it is a QMediaPlayer).

A file's name decides when it says one of these; otherwise its first bytes
do, so a renamed or deleted picture still shows itself.
"""

import io
import logging
import threading
import zipfile

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QObject, Qt, \
    Signal
from PySide6.QtGui import QImage, QImageReader

logger = logging.getLogger('TRACE.Thumbnails')

PICTURE, VIDEO, PDF, DOCUMENT, PROGRAM, SNIFF = 'picture', 'video', \
    'pdf', 'document', 'program', 'sniff'

PICTURE_EXTENSIONS = {'jpg', 'jpeg', 'jpe', 'jfif', 'png', 'gif', 'bmp',
                      'webp', 'tif', 'tiff', 'ico', 'heic', 'heif', 'avif',
                      'psd'}
DOCUMENT_EXTENSIONS = {'odt', 'ods', 'odp', 'odg', 'docx', 'xlsx', 'pptx',
                       'docm', 'xlsm', 'pptm', 'vsdx'}
#: Largest file read whole for a thumbnail, per kind. Videos are streamed.
MAX_BYTES = {PICTURE: 48 * 1024 * 1024, PDF: 64 * 1024 * 1024,
             DOCUMENT: 64 * 1024 * 1024,
             # Only its icon is read (core/pe_icons.py), whatever its size.
             PROGRAM: 1 << 62}
#: How much of a file is read to recognise it by content.
HEAD_BYTES = 64


def kind_by_name(name):
    """PICTURE, VIDEO, PDF, DOCUMENT, or None, from the extension."""
    if '.' not in (name or ''):
        return None
    extension = name.rsplit('.', 1)[-1].lower()
    if extension in PICTURE_EXTENSIONS:
        return PICTURE
    from trace_app.core.filetypes import VIDEO_EXTENSIONS
    if extension in VIDEO_EXTENSIONS:
        return VIDEO
    if extension == 'pdf':
        return PDF
    if extension in DOCUMENT_EXTENSIONS:
        return DOCUMENT
    from trace_app.core.pe_icons import PROGRAM_EXTENSIONS
    if extension in PROGRAM_EXTENSIONS:
        return PROGRAM
    return None


def kind_by_content(head):
    """The kind the first bytes of a file say it is, or None."""
    head = bytes(head or b'')[:HEAD_BYTES]
    if len(head) < 12:
        return None
    if head.startswith((b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'GIF87a',
                        b'GIF89a', b'II*\x00', b'MM\x00*', b'8BPS')) or \
            (head.startswith(b'BM') and head[14:15] in (b'\x0c', b'\x28',
                                                         b'\x38', b'\x40',
                                                         b'\x6c', b'\x7c')):
        return PICTURE
    if head.startswith(b'RIFF') and head[8:12] == b'WEBP':
        return PICTURE
    if head.startswith(b'RIFF') and head[8:12] == b'AVI ':
        return VIDEO
    if head[4:8] == b'ftyp':
        brand = head[8:12]
        if brand in (b'heic', b'heix', b'mif1', b'msf1', b'avif', b'avis',
                     b'hevc'):
            return PICTURE
        if brand in (b'crx ',):
            return None                     # a camera raw (CR3)
        if brand[:3] in (b'M4A', b'M4B', b'M4P') or brand == b'F4A ':
            return None                     # audio
        return VIDEO
    if head.startswith((b'\x1aE\xdf\xa3', b'FLV\x01')) or \
            head.startswith(b'0&\xb2u\x8ef\xcf\x11') or \
            head.startswith((b'\x00\x00\x01\xba', b'\x00\x00\x01\xb3')):
        return VIDEO
    if head.startswith(b'%PDF-'):
        return PDF
    if head.startswith(b'PK\x03\x04'):
        name = head[30:]
        if name.startswith((b'mimetype', b'[Content_Types].xml',
                            b'docProps', b'_rels', b'word/', b'xl/',
                            b'ppt/')):
            return DOCUMENT
    return None


# --- rendering (any thread, except PDF) ------------------------------------

def _fit(image, size):
    if image.isNull():
        return image
    return image.scaled(size, size, Qt.KeepAspectRatio,
                        Qt.SmoothTransformation)


def framed(image):
    """A page with a hairline round it: a white page on a white view would
    otherwise have no edge at all."""
    if image.isNull():
        return image
    from PySide6.QtGui import QColor, QPainter, QPen
    image = image.convertToFormat(QImage.Format_ARGB32)
    painter = QPainter(image)
    painter.setPen(QPen(QColor(150, 150, 150), 1))
    painter.drawRect(0, 0, image.width() - 1, image.height() - 1)
    painter.end()
    return image


def picture_image(content, size):
    """A picture's QImage scaled to fit `size`, or a null QImage."""
    buffer = QBuffer()
    buffer.setData(QByteArray(bytes(content)))
    buffer.open(QIODevice.ReadOnly)
    reader = QImageReader(buffer)
    reader.setAutoTransform(True)
    original = reader.size()
    if original.isValid() and (original.width() > size * 2 or
                               original.height() > size * 2):
        # Decoded small: a 24-megapixel photo is not decoded whole.
        reader.setScaledSize(original.scaled(size * 2, size * 2,
                                             Qt.KeepAspectRatio))
    image = reader.read()
    buffer.close()
    if image.isNull():
        try:
            from PIL import Image
            with Image.open(io.BytesIO(bytes(content))) as picture:
                picture.thumbnail((size * 2, size * 2))
                picture = picture.convert('RGBA')
                image = QImage(picture.tobytes(), picture.width,
                               picture.height,
                               QImage.Format_RGBA8888).copy()
        except Exception:
            return QImage()
    return _fit(image, size)


def document_image(content, size):
    """The preview an ODF or Office file carries, or a null QImage."""
    try:
        with zipfile.ZipFile(io.BytesIO(bytes(content))) as archive:
            names = {name.lower(): name for name in archive.namelist()}
            for wanted in ('thumbnails/thumbnail.png',
                           'docprops/thumbnail.jpeg', 'docprops/thumbnail.jpg',
                           'docprops/thumbnail.png'):
                if wanted in names:
                    info = archive.getinfo(names[wanted])
                    if info.file_size > 8 * 1024 * 1024:
                        return QImage()
                    return framed(picture_image(archive.read(info), size))
    except Exception:
        pass
    return QImage()


def pdf_image(content, size):
    """A PDF's first page scaled to fit -- on the UI thread only."""
    try:
        import pymupdf
        with pymupdf.open(stream=bytes(content), filetype='pdf') as document:
            if not document.page_count:
                return QImage()
            page = document.load_page(0)
            scale = size * 2 / max(page.rect.width, page.rect.height, 1)
            pixmap = page.get_pixmap(matrix=pymupdf.Matrix(scale, scale),
                                     alpha=False)
            image = QImage()
            image.loadFromData(pixmap.tobytes('png'), 'PNG')
            return framed(_fit(image, size))
    except Exception as exc:
        logger.debug("No PDF thumbnail: %s", exc)
        return QImage()


# --- the loader ---------------------------------------------------------------

class ThumbnailLoader(QObject):
    """Makes thumbnails on one background thread, newest request first (the
    items on screen now), and reports each on the UI thread:

    - ready(key, QImage): a picture or document -- null when it would not
      decode, so the caller stops asking;
    - pdf(key, bytes): a PDF's bytes, for the caller to render;
    - video(key): content says it is a video, for the caller to stream.

    A request is `request(key, kind, size, read_bytes, read_head, limit)`:
    `kind` from the name or SNIFF; `read_bytes()` the whole file;
    `read_head()` its first bytes (for SNIFF)."""

    ready = Signal(object, QImage)
    pdf = Signal(object, bytes)
    video = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._jobs = []
        self._pending = set()
        self._lock = threading.Condition()
        self._closed = False
        self._generation = 0
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name='thumbnails')
        self._thread.start()
        self.destroyed.connect(lambda *_: self.close())

    def request(self, key, kind, size, read_bytes, read_head=None,
                byte_size=None):
        with self._lock:
            if key in self._pending:
                return
            self._pending.add(key)
            self._jobs.append((self._generation, key, kind, size, read_bytes,
                               read_head, byte_size))
            self._lock.notify()

    def pending(self, key):
        return key in self._pending

    def clear(self):
        """Forget what is queued (the view changed); work under way is
        dropped when it ends."""
        with self._lock:
            self._jobs.clear()
            self._pending.clear()
            self._generation += 1

    def close(self):
        with self._lock:
            self._closed = True
            self._jobs.clear()
            self._lock.notify_all()

    def _run(self):
        while True:
            with self._lock:
                while not self._jobs and not self._closed:
                    self._lock.wait()
                if self._closed:
                    return
                job = self._jobs.pop()          # newest first
            generation, key = job[0], job[1]
            try:
                outcome = self._make(*job[2:])
            except Exception as exc:
                logger.debug("No thumbnail for %s: %s", key, exc)
                outcome = ('ready', QImage())
            with self._lock:
                if self._closed:
                    return
                current = generation == self._generation
                self._pending.discard(key)
            if not current:
                continue
            try:
                if outcome[0] == 'ready':
                    self.ready.emit(key, outcome[1])
                elif outcome[0] == 'pdf':
                    self.pdf.emit(key, outcome[1])
                elif outcome[0] == 'video':
                    self.video.emit(key)
            except RuntimeError:
                return                          # the view is gone

    @staticmethod
    def _make(kind, size, read_bytes, read_head, byte_size):
        if kind == SNIFF:
            kind = kind_by_content(read_head() if read_head else None)
            if kind is None:
                return ('ready', QImage())
        if kind == VIDEO:
            return ('video',)
        if byte_size is not None and byte_size > MAX_BYTES.get(kind, 0):
            return ('ready', QImage())
        content = read_bytes()
        if not content:
            return ('ready', QImage())
        if kind == PDF:
            return ('pdf', bytes(content))
        if kind == DOCUMENT:
            return ('ready', document_image(content, size))
        return ('ready', picture_image(content, size))

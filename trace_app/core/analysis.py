"""What a file really is, how random it looks, and whether it is a copy.

Three questions an examiner asks of every file on an image, and three that a
listing cannot answer: an extension is a claim, not a fact; a file full of
compressed or encrypted data looks like any other file; and a hundred copies
of the same photograph look like a hundred photographs.

They are one module rather than three because they all want the same bytes.
Run separately, a 16GB image is read three times to learn things that a single
pass establishes at once -- so the modules an examiner selects are combined
into one walk, and each file is read exactly once no matter how many are
enabled.

No Qt here: the walk has to be drivable from a script and a test as well as
from the background job that normally runs it.

The files are read on several processes when there are many (`workers`):
one walk lists them, each worker opens the image itself and analyses a
chunk at a time, and the job writes the rows in the walk's order -- so the
case holds the same rows whichever worker finished first.
"""

import collections
import hashlib
import logging
import math
import multiprocessing
import operator
import threading
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures.process import BrokenProcessPool

import pytsk3
from PIL import Image

from trace_app.core import content_checks
from trace_app.core import scope as scope_module
from trace_app.core.case import make_artifact_ref
from trace_app.core.content_checks import (MODULE_AUTHORS,
                                           MODULE_EXECUTABLES, MODULE_HIDDEN,
                                           MODULE_PHOTO)

logger = logging.getLogger('TRACE.Analysis')

#: What this module can be asked for. A run does whatever subset the examiner
#: selected; anything not asked for is not computed, and more importantly not
#: read. The last three are the checks in content_checks.
MODULE_MAGIC = 'magic'
MODULE_ENTROPY = 'entropy'
MODULE_HASH = 'hash'
MODULES = (MODULE_MAGIC, MODULE_ENTROPY, MODULE_HASH, MODULE_HIDDEN,
           MODULE_PHOTO, MODULE_AUTHORS, MODULE_EXECUTABLES)

#: How each module reads in a dialog and a progress line.
MODULE_LABELS = {
    MODULE_MAGIC: "File type detection",
    MODULE_ENTROPY: "Entropy analysis",
    MODULE_HASH: "File hashes and duplicates",
    MODULE_HIDDEN: "Hidden data",
    MODULE_PHOTO: "Photo metadata",
    MODULE_AUTHORS: "Document authors",
    MODULE_EXECUTABLES: "Executables",
}

#: Modules whose checks live in content_checks.
_CONTENT_MODULES = (MODULE_HIDDEN, MODULE_PHOTO, MODULE_AUTHORS,
                    MODULE_EXECUTABLES)

#: Enough for every magic signature in practice -- the longest are a few dozen
#: bytes, and libmagic's own heuristics look at rather less than this. Reading
#: 4KB to identify a 2GB file is the whole point of the module.
HEAD_BYTES = 4096

#: Entropy and hashing stream in blocks, so a large file is never held whole.
BLOCK_BYTES = 64 * 1024

#: Files larger than this are recorded by name, type and size but not hashed
#: or scored. A single 40GB VM image would otherwise dominate a run whose
#: purpose is to say where to look first.
MAX_ANALYSIS_BYTES = 2 * 1024 * 1024 * 1024

#: The file hashes computed: SHA-256 always, MD5 and SHA-1 when the case's
#: settings ask (core/settings.py). One unchosen is left NULL -- "not
#: computed", never a value.
HASH_ALGORITHMS = ('md5', 'sha1', 'sha256')

#: Directory recursion limit, matching the indexer: a filesystem loop is a real
#: thing on damaged evidence, and a visited-set alone does not stop one that
#: runs through different inodes.
MAX_DEPTH = 32

#: Above this, a file's contents are indistinguishable from random. Encrypted
#: and packed data sits here; so does every compressed container, which is why
#: the type is checked before anything is flagged.
HIGH_ENTROPY = 7.5

#: A small encrypted payload inside a large file moves the mean hardly at all,
#: so the highest-scoring block is kept too. The threshold for that peak is
#: higher than the mean's, because one random-looking block is far less
#: remarkable than a whole random-looking file.
HIGH_PEAK_ENTROPY = 7.9

#: Below this a file cannot be scored honestly: over a few dozen bytes the
#: number measures how many distinct values happened to appear rather than
#: disorder, and short files routinely score above 7 while holding nothing.
MIN_ENTROPY_BYTES = 256


class AnalysisCancelled(Exception):
    """Raised inside the walk when the examiner presses Cancel."""


# --- what a file claims to be, and what it is ----------------------------

#: Extension -> the MIME types that extension honestly describes. Only types
#: worth arguing about are here: the point is to catch a disguise, not to
#: catalogue every format in existence.
_EXPECTED = {
    'jpg': {'image/jpeg'}, 'jpeg': {'image/jpeg'}, 'jpe': {'image/jpeg'},
    'png': {'image/png'}, 'gif': {'image/gif'}, 'bmp': {'image/bmp'},
    'tif': {'image/tiff'}, 'tiff': {'image/tiff'}, 'webp': {'image/webp'},
    'ico': {'image/vnd.microsoft.icon', 'image/x-icon'},
    'pdf': {'application/pdf'},
    'rtf': {'application/rtf', 'text/rtf'},
    'doc': {'application/msword', 'application/vnd.ms-office',
            'application/x-ole-storage'},
    'xls': {'application/vnd.ms-excel', 'application/vnd.ms-office',
            'application/x-ole-storage'},
    'ppt': {'application/vnd.ms-powerpoint', 'application/vnd.ms-office',
            'application/x-ole-storage'},
    'docx': {'application/vnd.openxmlformats-officedocument'
             '.wordprocessingml.document', 'application/zip'},
    'xlsx': {'application/vnd.openxmlformats-officedocument'
             '.spreadsheetml.sheet', 'application/zip'},
    'pptx': {'application/vnd.openxmlformats-officedocument'
             '.presentationml.presentation', 'application/zip'},
    'zip': {'application/zip'}, 'rar': {'application/x-rar'},
    '7z': {'application/x-7z-compressed'}, 'gz': {'application/gzip'},
    'tar': {'application/x-tar'}, 'bz2': {'application/x-bzip2'},
    'xz': {'application/x-xz'},
    'exe': {'application/x-dosexec',
            'application/vnd.microsoft.portable-executable'},
    'dll': {'application/x-dosexec',
            'application/vnd.microsoft.portable-executable'},
    'sys': {'application/x-dosexec',
            'application/vnd.microsoft.portable-executable'},
    'msi': {'application/x-msi', 'application/x-ole-storage',
            'application/vnd.ms-office'},
    'mp3': {'audio/mpeg'}, 'wav': {'audio/x-wav', 'audio/wav'},
    'flac': {'audio/flac'}, 'ogg': {'audio/ogg'},
    'mp4': {'video/mp4'}, 'mov': {'video/quicktime'},
    'avi': {'video/x-msvideo'}, 'wmv': {'video/x-ms-asf'},
    'mkv': {'video/x-matroska'},
    'sqlite': {'application/vnd.sqlite3', 'application/x-sqlite3'},
    'db': {'application/vnd.sqlite3', 'application/x-sqlite3'},
    'txt': {'text/plain'}, 'log': {'text/plain'},
    'csv': {'text/csv', 'text/plain'},
    'html': {'text/html'}, 'htm': {'text/html'},
    'xml': {'text/xml', 'application/xml'},
    'json': {'application/json', 'text/plain'},
}

#: Types that are executable code. A file wearing a document or picture
#: extension while holding one of these is the finding this module exists for.
_EXECUTABLE = {
    'application/x-dosexec', 'application/vnd.microsoft.portable-executable',
    'application/x-executable', 'application/x-sharedlib',
    'application/x-mach-binary', 'application/x-msdownload',
    'application/x-elf',
}

#: Extensions whose file is expected to be inert data. An executable found
#: under one of these is a disguise; an executable named `.dat` is not.
_INERT = {
    'jpg', 'jpeg', 'jpe', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'ico',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'log',
    'csv', 'mp3', 'wav', 'flac', 'mp4', 'mov', 'avi', 'wmv', 'mkv',
}

#: Formats that are compressed or encrypted by definition. Their entropy sits
#: near the maximum and says nothing: flagging a ZIP for scoring 7.99 teaches
#: an examiner to ignore the flag.
_EXPECTED_HIGH_ENTROPY = {
    'application/zip', 'application/gzip', 'application/x-bzip2',
    'application/x-xz', 'application/x-7z-compressed', 'application/x-rar',
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'audio/mpeg', 'audio/flac', 'audio/ogg',
    'video/mp4', 'video/quicktime', 'video/x-matroska', 'video/x-msvideo',
    'application/pdf', 'application/x-lzma', 'application/zstd',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml'
    '.presentation',
}

#: How bad a mismatch is. Only `suspicious` is flagged; the others are recorded
#: so a filter can find them, without putting them in front of anyone.
MISMATCH_NONE = ''
MISMATCH_BENIGN = 'benign'
MISMATCH_NOTABLE = 'notable'
MISMATCH_SUSPICIOUS = 'suspicious'


def magic_reader():
    """A libmagic handle, or None if the library is missing.

    Magic detection is the one module with a system dependency, and an image
    can still be hashed and scored without it, so a missing libmagic disables
    this module rather than failing the whole run.
    """
    try:
        import magic
        return _ZipAwareMagic(magic.Magic(mime=True))
    except Exception as exc:            # ImportError, or a missing DLL
        logger.warning("File type detection unavailable: %s", exc)
        return None


_LOCALE_LOCK = threading.Lock()


def _in_c_locale(call, data):
    """`call(data)` with the C library's locale at "C", restored after.

    libmagic's text tests are regular expressions, and macOS's regex
    library refuses some bytes under a UTF-8 locale ("illegal byte
    sequence"): the type comes back as an error. Qt sets the locale from
    the environment when it starts, so in the window's process (and a test
    process that made a QApplication) a text file failed to type while a
    job's fresh process named it -- the same file typed two ways (macOS
    CI). Only a failed answer is asked again, so nothing else changes."""
    import locale
    with _LOCALE_LOCK:
        saved = {category: locale.setlocale(category)
                 for category in (locale.LC_CTYPE, locale.LC_COLLATE)}
        try:
            for category in saved:
                locale.setlocale(category, 'C')
            return call(data)
        finally:
            for category, value in saved.items():
                locale.setlocale(category, value)


#: A ZIP's first local file header, or the end record of an empty one.
_ZIP_STARTS = (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')


class _ZipAwareMagic:
    """libmagic, except that a buffer opening with a ZIP header is a ZIP.

    libmagic 5.46 (Debian 13; Ubuntu next) finds a ZIP from its end, so
    a buffer -- all TRACE ever passes, the analysis only a file's first
    4 KB -- reads as 'application/octet-stream' ('data'); `file` on the
    same bytes from a pipe says so too. 5.32-5.45 named it from its first
    bytes. Without this every ZIP, DOCX, XLSX, JAR and APK would be
    unidentified, and one with high entropy graded as encrypted."""

    def __init__(self, reader):
        self._reader = reader

    def from_buffer(self, data):
        try:
            mime = self._reader.from_buffer(data)
        except Exception:
            mime = None
        if not mime:
            mime = _in_c_locale(self._reader.from_buffer, data)
        if mime in ('application/octet-stream', '') and \
                bytes(data[:4]) in _ZIP_STARTS:
            return 'application/zip'
        return mime

    def __getattr__(self, name):
        return getattr(self._reader, name)


def classify_mismatch(extension, mime, entropy=None):
    """Grade the disagreement between an extension and the real content.

    Graded rather than boolean because most disagreements are uninteresting.
    `.jpe` holding a JPEG is not a finding; a `.jpg` holding a PE executable is
    the only thing here worth interrupting someone for.

    `entropy` is consulted for the one case where two weak signals make a
    strong one: content libmagic cannot identify is usually nothing, and a
    high score alone is usually a compressed file, but a document extension
    over unidentifiable random bytes is an encrypted document.
    """
    if not mime or not extension:
        return MISMATCH_NONE

    extension = extension.lower().lstrip('.')
    expected = _EXPECTED.get(extension)

    if mime in _EXECUTABLE and extension in _INERT:
        return MISMATCH_SUSPICIOUS

    if expected is None:
        return MISMATCH_NONE            # nothing was claimed, so nothing lied

    if mime in expected:
        return MISMATCH_NONE

    # A container read as its container type is the format working as
    # designed: every OOXML document is a ZIP, and libmagic says so whenever
    # the inner content type is not declared.
    if mime == 'application/zip' and extension in ('docx', 'xlsx', 'pptx'):
        return MISMATCH_NONE
    if mime in ('application/x-ole-storage', 'application/vnd.ms-office'):
        if extension in ('doc', 'xls', 'ppt', 'msi'):
            return MISMATCH_NONE

    # Text read as something more specific, or the reverse. Common, harmless,
    # and worth recording only so a filter can ask for it.
    if mime.startswith('text/') and extension in (
            'txt', 'log', 'csv', 'html', 'htm', 'xml', 'json'):
        return MISMATCH_BENIGN
    if mime == 'application/octet-stream':
        # Unidentifiable *and* random, under an extension that promises
        # structure: that is an encrypted file, and worth saying so.
        if entropy is not None and entropy >= HIGH_ENTROPY:
            return MISMATCH_NOTABLE
        return MISMATCH_BENIGN          # otherwise libmagic simply declined

    if mime.split('/')[0] in {e.split('/')[0] for e in expected}:
        return MISMATCH_BENIGN          # right family, wrong specific type

    return MISMATCH_NOTABLE


# --- how random it looks -------------------------------------------------

class Entropy:
    """Shannon entropy over a stream, both overall and per block.

    Both numbers are kept because they answer different questions. The mean
    says what the file is as a whole; the peak block says whether something
    random-looking hides inside a file that is otherwise ordinary -- an
    encrypted payload appended to a photograph moves the mean very little.
    """

    def __init__(self):
        self.counts = [0] * 256
        self.total = 0
        self.peak = 0.0
        self.peak_offset = 0
        self._offset = 0

    def feed(self, block):
        # Counted once, for the whole file's total and this block's score.
        counts = byte_counts(block)
        self.counts = list(map(operator.add, self.counts, counts))
        self.total += len(block)

        if len(block) >= MIN_ENTROPY_BYTES:
            score = shannon(block, counts)
            if score > self.peak:
                self.peak = score
                self.peak_offset = self._offset
        self._offset += len(block)

    @property
    def mean(self):
        if self.total < MIN_ENTROPY_BYTES:
            return 0.0
        return _entropy_of_counts(self.counts, self.total)


#: Bytes counted per histogram: bounds the 1-pixel-high image's width.
_HISTOGRAM_SPAN = 16 * 1024 * 1024


def byte_counts(data):
    """How many times each byte value occurs, as a list of 256.

    Counted by Pillow (a required dependency, wheels everywhere): the bytes
    viewed in place as a one-row greyscale image, whose histogram is the
    count of each value, in C. collections.Counter took 39% of an analysis
    run on the XP image (36 MB/s); this is ~1 GB/s, and the same numbers
    (tests.test_core checks them against Counter)."""
    counts = [0] * 256
    view = memoryview(data).cast('B') if not isinstance(data, bytes) \
        else data
    for start in range(0, len(view), _HISTOGRAM_SPAN):
        piece = view[start:start + _HISTOGRAM_SPAN]
        histogram = Image.frombuffer('L', (len(piece), 1), piece, 'raw',
                                     'L', 0, 1).histogram()
        for value in range(256):
            counts[value] += histogram[value]
    return counts


#: c * log2(c) for every count a 64 KB block can hold: entropy is then
#: log2(n) - sum(c log2 c) / n, summed in C (map over the table) rather
#: than 256 Python steps a block -- per ELF section too, that was 32
#: million log2 calls in two minutes of analysing a Linux image.
_CLOG = [0.0] + [c * math.log2(c) for c in range(1, 65537)]


def _entropy_of_counts(counts, total):
    """Shannon entropy, bits per byte, of 256 byte counts summing to
    `total`."""
    if total <= 0:
        return 0.0
    if max(counts) < len(_CLOG):
        weighted = sum(map(_CLOG.__getitem__, counts))
    else:
        weighted = sum(c * math.log2(c) for c in counts if c)
    return max(0.0, math.log2(total) - weighted / total)


def shannon(data, counts=None):
    """Entropy of one block, in bits per byte (`counts` when already
    counted)."""
    if not data:
        return 0.0
    if counts is None:
        counts = byte_counts(data)
    return _entropy_of_counts(counts, len(data))


def is_high_entropy(mean, peak, mime):
    """Whether a score is worth an examiner's attention.

    A compressed or encrypted format scoring near 8 is that format working
    normally, so the type is consulted before anything is flagged. What is left
    is a file that looks random with no business doing so.
    """
    if mime in _EXPECTED_HIGH_ENTROPY:
        return False
    return mean >= HIGH_ENTROPY or peak >= HIGH_PEAK_ENTROPY


# --- one file ------------------------------------------------------------

def analyse_bytes(name, data, modules, magic=None, size=None):
    """Everything the selected modules can say about one file's content.

    Split out from the walk so it can be tested against known bytes, and so
    archive members and carved files -- which arrive as bytes rather than as
    an inode -- go through exactly the same judgement as files on disk.
    """
    result = {}
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''

    mime = ''
    if MODULE_MAGIC in modules and magic is not None and data:
        try:
            mime = magic.from_buffer(bytes(data[:HEAD_BYTES])) or ''
        except Exception as exc:
            logger.debug("Could not type %s: %s", name, exc)
        result['mime'] = mime
        result['extension'] = extension

    if MODULE_ENTROPY in modules and data:
        meter = Entropy()
        for start in range(0, len(data), BLOCK_BYTES):
            meter.feed(data[start:start + BLOCK_BYTES])
        result['entropy'] = round(meter.mean, 3)
        result['entropy_peak'] = round(meter.peak, 3)
        result['entropy_peak_offset'] = meter.peak_offset

    # Graded last, so the entropy is available to it. Without a score it
    # grades on the type alone, which is what a magic-only run gets.
    if 'mime' in result:
        result['mismatch'] = classify_mismatch(extension, mime,
                                               result.get('entropy'))

    if MODULE_HASH in modules and data:
        for algorithm in HASH_ALGORITHMS:
            result[algorithm] = hashlib.new(algorithm, data).hexdigest()

    _add_findings(result, name, data, modules,
                  size if size is not None else len(data or b''))

    if size is not None:
        result['size'] = size
    return result


#: Picture families (content_checks.family) given a perceptual hash.
_PHASH_FAMILIES = {'jpeg', 'png', 'tiff', 'webp', 'heif'}


def _add_findings(result, name, data, modules, size):
    """Run the content checks and attach what they find to `result`."""
    if not any(m in modules for m in _CONTENT_MODULES):
        return
    if MODULE_PHOTO in modules and data and \
            content_checks.family(data[:64]) in _PHASH_FAMILIES:
        # The photo module has the whole picture in hand: what it looks like
        # (core/phash.py), for Triage > Similar pictures.
        from trace_app.core.phash import phash
        result['phash'] = phash(data)
    findings = content_checks.inspect(name, data, modules, size)
    if MODULE_HIDDEN in modules:
        volume = content_checks.possible_encrypted_volume(
            result.get('mime'), result.get('entropy'), size)
        if volume is not None:
            findings.append(volume)
    if findings:
        result['findings'] = [f.as_row() for f in findings]


def _analyse_stream(file_object, size, name, modules, magic):
    """Analyse a file on the image, reading it once in blocks.

    The head is read first and typed, then -- only if entropy or hashing was
    asked for -- the rest is streamed through both at once. A file is never
    held whole in memory, and never read twice.
    """
    result = {'size': size}
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''

    head = file_object.read_random(0, min(HEAD_BYTES, size)) if size else b''

    mime = ''
    if MODULE_MAGIC in modules and magic is not None and head:
        try:
            mime = magic.from_buffer(head) or ''
        except Exception as exc:
            logger.debug("Could not type %s: %s", name, exc)
        result['mime'] = mime
        result['extension'] = extension
        # Graded provisionally on the type alone; regraded below once the
        # entropy is known, which is what catches an encrypted document.
        result['mismatch'] = classify_mismatch(extension, mime)

    wants_entropy = MODULE_ENTROPY in modules
    wants_hash = MODULE_HASH in modules
    # The content checks want the whole file, but only for formats they have
    # something to say about -- decided from the head already read -- and
    # only up to a size where a photo or a document plausibly sits. They ride
    # the same stream as entropy and hashing, so nothing is read twice.
    wants_content = (any(m in modules for m in _CONTENT_MODULES)
                     and size <= content_checks.MAX_INSPECT_BYTES
                     and content_checks.wants_full_read(head, modules))

    if not (wants_entropy or wants_hash or wants_content):
        _add_findings(result, name, None, modules, size)
        return result

    if size > MAX_ANALYSIS_BYTES:
        # Recorded, with its type, but not scored: one enormous file should
        # not consume the run that is meant to triage the rest.
        result['note'] = 'too large to hash or score'
        _add_findings(result, name, None, modules, size)
        return result

    meter = Entropy() if wants_entropy else None
    hashers = {name: hashlib.new(name) for name in HASH_ALGORITHMS} \
        if wants_hash else {}
    kept = [] if wants_content else None

    offset = 0
    while offset < size:
        block = head if offset == 0 else file_object.read_random(
            offset, min(BLOCK_BYTES, size - offset))
        if not block:
            break
        if meter is not None:
            meter.feed(block)
        for hasher in hashers.values():
            hasher.update(block)
        if kept is not None:
            kept.append(block)
        offset += len(block)

    if meter is not None:
        result['entropy'] = round(meter.mean, 3)
        result['entropy_peak'] = round(meter.peak, 3)
        result['entropy_peak_offset'] = meter.peak_offset
        if 'mime' in result:
            result['mismatch'] = classify_mismatch(extension, mime,
                                                   result['entropy'])
    for name, hasher in hashers.items():
        result[name] = hasher.hexdigest()
    _add_findings(result, name, b''.join(kept) if kept is not None else None,
                  modules, size)
    return result


# --- the walk ------------------------------------------------------------

#: Below this many files a pool is not worth starting (seconds to start).
MIN_POOL_FILES = 1000
#: Files per piece of work handed to a worker; a piece also ends once its
#: files hold CHUNK_BYTES, so one worker is not handed every large file.
CHUNK_FILES = 64
CHUNK_BYTES = 64 * 1024 * 1024
#: Pieces handed out per worker ahead of the one being written.
IN_FLIGHT_PER_WORKER = 4


def analyse_evidence(image_handler, case, evidence_id, modules,
                     progress=None, should_stop=None, scope=None,
                     workers=1, image_path=None, unlock=None,
                     case_folder=None):
    """Run the selected modules over every file in one piece of evidence
    -- every file in `scope` (core/scope.Scope; None: every file).

    `progress(done, total, path)` is called as the walk proceeds, and
    `should_stop()` is consulted per file so Cancel feels immediate.
    `workers` > 1 reads the files on that many processes, each opening
    `image_path` itself (with `unlock`, and `case_folder`'s settings), when
    there are enough files to be worth it.

    Returns the number of files analysed. A cancelled run keeps what it read
    and records where it stopped, so resuming continues rather than starts
    again.
    """
    modules = tuple(m for m in modules if m in MODULES)
    if not modules:
        return 0

    magic = magic_reader() if MODULE_MAGIC in modules else None
    if MODULE_MAGIC in modules and magic is None:
        modules = tuple(m for m in modules if m != MODULE_MAGIC)
        if not modules:
            logger.warning("Nothing left to analyse without libmagic")
            return 0

    case.clear_analysis(evidence_id)
    case.set_analysis_state(evidence_id, 'running', modules=','.join(modules),
                            files_done=0)

    from trace_app.core.walk import volume_offsets
    offsets = volume_offsets(image_handler)

    total = 0
    done = 0
    # Declared before the listing phase, not inside it: listing raises
    # AnalysisCancelled too, and the handler reads this. Cancelling while
    # the files were still being listed would otherwise be a NameError
    # rather than a clean stop.
    counter = [0]

    matchers = {}

    def matcher(offset):
        if scope is None:
            return None
        if offset not in matchers:
            matchers[offset] = scope.matcher(
                image_handler.get_fs_info(offset))
        return matchers[offset]

    try:
        # One walk: what to read, and so how many (for an honest progress
        # bar). It used to be walked twice, once to count.
        listed = [(offset, _list_files(image_handler, offset, should_stop,
                                       matcher(offset)))
                  for offset in offsets]
        total = sum(len(files) for _offset, files in listed)
        case.set_analysis_state(evidence_id, 'running', files_total=total)
        pool_size = _pool_size(workers, total, image_handler, image_path)
        logger.info("Analysing evidence %s: %d file(s), modules %s%s%s",
                    evidence_id, total, ', '.join(modules),
                    '' if scope is None or scope.everything else
                    f"; scope: {scope.describe()}",
                    f"; {pool_size} processes" if pool_size > 1 else '')

        # counter is a list rather than a number because cancellation leaves
        # by an exception, and a returned count would be lost on the way out
        # -- the run would then record having read nothing while its rows sat
        # on disk, and a resume would start over.
        if pool_size > 1:
            _analyse_on_pool(
                image_handler, case, evidence_id, listed, modules, magic,
                counter, total, progress, should_stop, pool_size,
                (image_path, unlock, case_folder))
        else:
            for offset, files in listed:
                _analyse_files(image_handler, case, evidence_id, offset,
                               files, modules, magic, counter, total,
                               progress, should_stop)
        done = counter[0]

        case.commit()
        case.set_analysis_state(evidence_id, 'done', files_done=done,
                               files_total=total)
        logger.info("Analysed %d file(s) for evidence %s", done, evidence_id)
        return done

    except AnalysisCancelled:
        case.commit()
        done = counter[0]
        case.set_analysis_state(evidence_id, 'cancelled', files_done=done,
                               files_total=total)
        logger.info("Analysis cancelled after %d file(s)", done)
        return done

    except Exception as exc:
        case.commit()
        done = counter[0]
        case.set_analysis_state(evidence_id, 'failed', files_done=done,
                               last_error=str(exc))
        logger.error("Analysis failed: %s", exc)
        raise


def _pool_size(workers, total, image_handler, image_path):
    """Processes to read with: one for a small run, for evidence a worker
    cannot open by path, and for logical evidence and live disks -- a
    folder's files and a disk read through one helper gain nothing from
    several readers."""
    if not workers or workers <= 1 or total < MIN_POOL_FILES or \
            not image_path:
        return 1
    try:
        if image_handler.get_image_type() == 'logical':
            return 1
        from trace_app.core.live_disk import is_device_path
        if is_device_path(image_path):
            return 1
    except Exception:
        return 1
    return min(workers, max(1, total // CHUNK_FILES))


def _list_files(image_handler, offset, should_stop, matcher=None):
    """Every file with content on one volume (in scope), in walk order:
    [(inode, name, path, deleted, sequence, size)]."""
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return []

    files = []
    visited = set()

    def walk(directory, path, depth):
        if depth > MAX_DEPTH:
            return
        for entry in directory:
            if should_stop and should_stop():
                raise AnalysisCancelled()
            if entry.info.name is None or entry.info.meta is None:
                continue
            name = entry.info.name.name.decode('utf-8', 'replace')
            if name in ('.', '..'):
                continue

            meta = entry.info.meta
            inode = meta.addr
            if inode in visited:
                continue            # hard links, and directory cycles
            visited.add(inode)

            child_path = f"{path}/{name}".replace('//', '/')
            # Out of scope (core/scope): a folder is not gone into at all.
            if scope_module.entry_skipped(matcher, child_path, meta):
                continue

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    walk(entry.as_directory(), child_path, depth + 1)
                except AnalysisCancelled:
                    raise
                except Exception:
                    continue
                continue

            if not meta.size:
                continue
            files.append((
                inode, name, child_path,
                not (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC),
                getattr(entry.info.name, 'meta_seq', None), meta.size))

    try:
        walk(fs_info.open_dir(path='/'), '', 0)
    except AnalysisCancelled:
        raise
    except Exception as exc:
        logger.debug("Could not list files at offset %s: %s", offset, exc)
    return files


def _count_files(image_handler, offset, should_stop, matcher=None):
    """How many files the analysis reads on one volume (in scope)."""
    return len(_list_files(image_handler, offset, should_stop, matcher))


def _analyse_one(fs_info, offset, entry, modules, magic):
    """One listed file's row, or None when it cannot be read."""
    inode, name, path, deleted, sequence, size = entry
    try:
        file_object = fs_info.open_meta(inode=inode)
        facts = _analyse_stream(file_object, size, name, modules, magic)
    except Exception as exc:
        logger.debug("Could not analyse %s: %s", path, exc)
        return None
    return (make_artifact_ref(offset, inode, sequence), name, path,
            deleted, facts)


def _analyse_files(image_handler, case, evidence_id, offset, files, modules,
                   magic, counter, total, progress, should_stop):
    """Analyse one volume's listed files in this process. `counter` is the
    caller's running total, in a list so the count survives a cancellation
    leaving by an exception."""
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return
    pending = []
    try:
        for entry in files:
            if should_stop and should_stop():
                raise AnalysisCancelled()
            counter[0] += 1
            if progress:
                progress(counter[0], total, entry[2])
            row = _analyse_one(fs_info, offset, entry, modules, magic)
            if row is not None:
                pending.append(row)
            # Written in batches: a commit per file turns a 20,000-file
            # image into 20,000 transactions, and the walk spends its time
            # in SQLite rather than reading evidence.
            if len(pending) >= 200:
                case.add_analysis_batch(evidence_id, pending)
                pending.clear()
    finally:
        if pending:
            case.add_analysis_batch(evidence_id, pending)


# --- on several processes ---------------------------------------------------

#: In a worker: the image it opened, its libmagic, the run's modules.
_WORKER = {}


def _start_worker(image_path, unlock, case_folder, modules):
    """In each worker, first: the settings (as text_pool's workers), then
    the image, opened once for every piece this worker is given."""
    from trace_app.core.background import _open_image
    from trace_app.core.text_pool import _start_worker as settings_first
    settings_first(case_folder)
    _WORKER['handler'] = _open_image(image_path, unlock)
    _WORKER['magic'] = magic_reader() if MODULE_MAGIC in modules else None
    _WORKER['modules'] = modules


def _analyse_chunk(offset, entries):
    """A worker's piece: the rows of `entries`, files of the volume at
    `offset` (None where a file could not be read)."""
    fs_info = _WORKER['handler'].get_fs_info(offset)
    if fs_info is None:
        return [None] * len(entries)
    return [_analyse_one(fs_info, offset, entry, _WORKER['modules'],
                         _WORKER['magic']) for entry in entries]


def _chunks(listed):
    """(offset, [entries]) pieces of the listing, in order."""
    for offset, files in listed:
        piece, held = [], 0
        for entry in files:
            piece.append(entry)
            held += entry[5]
            if len(piece) >= CHUNK_FILES or held >= CHUNK_BYTES:
                yield offset, piece
                piece, held = [], 0
        if piece:
            yield offset, piece


def _analyse_on_pool(image_handler, case, evidence_id, listed, modules,
                     magic, counter, total, progress, should_stop, workers,
                     opening):
    """Analyse the listing on `workers` processes; rows written in order.
    A pool that cannot start, or loses a worker (a crash in C on some
    file), leaves the rest to this process."""
    try:
        pool = ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context('spawn'),
            initializer=_start_worker, initargs=(*opening, modules))
    except Exception as exc:
        logger.warning("Analysis stays in one process: %s", exc)
        pool = None

    pending = collections.deque()
    pieces = _chunks(listed)
    rows = []

    def in_process(offset, entries):
        fs_info = image_handler.get_fs_info(offset)
        return [_analyse_one(fs_info, offset, entry, modules, magic)
                if fs_info is not None else None for entry in entries]

    def written(offset, entries, result):
        counter[0] += len(entries)
        rows.extend(row for row in result if row is not None)
        if len(rows) >= 200:
            case.add_analysis_batch(evidence_id, rows)
            rows.clear()
        if progress:
            progress(counter[0], total, entries[-1][2])

    def wait(future):
        while True:
            if should_stop and should_stop():
                raise AnalysisCancelled()
            try:
                return future.result(timeout=0.25)
            except FutureTimeout:
                continue

    def drain_one():
        nonlocal pool, pending
        offset, entries, future = pending.popleft()
        result = None
        if future is not None:
            try:
                result = wait(future)
            except BrokenProcessPool as exc:
                logger.warning("An analysis worker stopped (%s); going on "
                               "in one process", exc)
                pool.shutdown(wait=False, cancel_futures=True)
                pool = None
                # Everything handed out is done here instead.
                pending = collections.deque(
                    (o, e, None) for o, e, _f in pending)
            except AnalysisCancelled:
                raise
            except Exception as exc:
                # The worker could not read this piece (its image would not
                # open the volume, say): this process reads it instead.
                logger.debug("A worker failed on a piece: %s", exc)
        if result is None:
            result = in_process(offset, entries)
        written(offset, entries, result)

    cancelled = False
    try:
        for offset, entries in pieces:
            if should_stop and should_stop():
                raise AnalysisCancelled()
            future = None
            if pool is not None:
                try:
                    future = pool.submit(_analyse_chunk, offset, entries)
                except (BrokenProcessPool, RuntimeError, OSError) as exc:
                    logger.warning("Analysis pool stopped (%s); going on in "
                                   "one process", exc)
                    pool.shutdown(wait=False, cancel_futures=True)
                    pool = None
            pending.append((offset, entries, future))
            while pending and (pool is None or len(pending) >=
                               workers * IN_FLIGHT_PER_WORKER):
                drain_one()
        while pending:
            drain_one()
    except AnalysisCancelled:
        cancelled = True
        raise
    finally:
        if rows:
            case.add_analysis_batch(evidence_id, rows)
        if pool is not None:
            pool.shutdown(wait=not cancelled, cancel_futures=cancelled)

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
"""

import hashlib
import logging
import math

import pytsk3

from trace_app.core.case import make_artifact_ref

logger = logging.getLogger('TRACE.Analysis')

#: The three things this module can be asked for. A run does whatever subset
#: the examiner selected; anything not asked for is not computed, and more
#: importantly not read.
MODULE_MAGIC = 'magic'
MODULE_ENTROPY = 'entropy'
MODULE_HASH = 'hash'
MODULES = (MODULE_MAGIC, MODULE_ENTROPY, MODULE_HASH)

#: How each module reads in a dialog and a progress line.
MODULE_LABELS = {
    MODULE_MAGIC: "File type detection",
    MODULE_ENTROPY: "Entropy analysis",
    MODULE_HASH: "File hashes and duplicates",
}

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
        return magic.Magic(mime=True)
    except Exception as exc:            # ImportError, or a missing DLL
        logger.warning("File type detection unavailable: %s", exc)
        return None


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
        for byte in block:
            self.counts[byte] += 1
        self.total += len(block)

        if len(block) >= MIN_ENTROPY_BYTES:
            score = shannon(block)
            if score > self.peak:
                self.peak = score
                self.peak_offset = self._offset
        self._offset += len(block)

    @property
    def mean(self):
        if self.total < MIN_ENTROPY_BYTES:
            return 0.0
        entropy = 0.0
        for count in self.counts:
            if count:
                probability = count / self.total
                entropy -= probability * math.log2(probability)
        return entropy


def shannon(data):
    """Entropy of one block, in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


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
        result['md5'] = hashlib.md5(data).hexdigest()
        result['sha256'] = hashlib.sha256(data).hexdigest()

    if size is not None:
        result['size'] = size
    return result


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
    if not (wants_entropy or wants_hash):
        return result

    if size > MAX_ANALYSIS_BYTES:
        # Recorded, with its type, but not scored: one enormous file should
        # not consume the run that is meant to triage the rest.
        result['note'] = 'too large to hash or score'
        return result

    meter = Entropy() if wants_entropy else None
    md5 = hashlib.md5() if wants_hash else None
    sha256 = hashlib.sha256() if wants_hash else None

    offset = 0
    while offset < size:
        block = head if offset == 0 else file_object.read_random(
            offset, min(BLOCK_BYTES, size - offset))
        if not block:
            break
        if meter is not None:
            meter.feed(block)
        if md5 is not None:
            md5.update(block)
            sha256.update(block)
        offset += len(block)

    if meter is not None:
        result['entropy'] = round(meter.mean, 3)
        result['entropy_peak'] = round(meter.peak, 3)
        result['entropy_peak_offset'] = meter.peak_offset
        if 'mime' in result:
            result['mismatch'] = classify_mismatch(extension, mime,
                                                   result['entropy'])
    if md5 is not None:
        result['md5'] = md5.hexdigest()
        result['sha256'] = sha256.hexdigest()
    return result


# --- the walk ------------------------------------------------------------

def analyse_evidence(image_handler, case, evidence_id, modules,
                     progress=None, should_stop=None):
    """Run the selected modules over every file in one piece of evidence.

    `progress(done, total, path)` is called as the walk proceeds, and
    `should_stop()` is consulted per file so Cancel feels immediate.

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

    partitions = image_handler.get_partitions()
    offsets = [p[2] for p in partitions] if partitions else [0]

    total = 0
    done = 0
    # Declared before the counting phase, not inside it: _count_files raises
    # AnalysisCancelled too, and the handler reads this. Cancelling while the
    # files were still being counted would otherwise be a NameError rather
    # than a clean stop.
    counter = [0]

    try:
        for offset in offsets:
            total += _count_files(image_handler, offset, should_stop)
        case.set_analysis_state(evidence_id, 'running', files_total=total)
        logger.info("Analysing evidence %s: %d file(s), modules %s",
                    evidence_id, total, ', '.join(modules))

        # counter is a list rather than a number because cancellation leaves
        # by an exception, and a returned count would be lost on the way out
        # -- the run would then record having read nothing while its rows sat
        # on disk, and a resume would start over.
        for offset in offsets:
            _analyse_partition(
                image_handler, case, evidence_id, offset, modules, magic,
                counter, total, progress, should_stop)
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


def _count_files(image_handler, offset, should_stop):
    """How many files there are, so the progress bar can be honest."""
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return 0

    count = 0
    visited = set()

    def walk(directory, depth):
        nonlocal count
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
            if meta.addr in visited:
                continue
            visited.add(meta.addr)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    walk(entry.as_directory(), depth + 1)
                except AnalysisCancelled:
                    raise
                except Exception:
                    continue
            elif meta.size:
                count += 1

    try:
        walk(fs_info.open_dir(path='/'), 0)
    except AnalysisCancelled:
        raise
    except Exception as exc:
        logger.debug("Could not count files at offset %s: %s", offset, exc)
    return count


def _analyse_partition(image_handler, case, evidence_id, offset, modules,
                       magic, counter, total, progress, should_stop):
    """Walk one volume. `counter` is the caller's running total, in a list so
    the count survives a cancellation leaving by an exception."""
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return

    visited = set()
    pending = []

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

            counter[0] += 1
            if progress:
                progress(counter[0], total, child_path)

            sequence = getattr(entry.info.name, 'meta_seq', None)
            deleted = not (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC)

            try:
                file_object = fs_info.open_meta(inode=inode)
                facts = _analyse_stream(file_object, meta.size, name,
                                        modules, magic)
            except Exception as exc:
                logger.debug("Could not analyse %s: %s", child_path, exc)
                continue

            pending.append((
                make_artifact_ref(offset, inode, sequence),
                name, child_path, deleted, facts))

            # Written in batches: a commit per file turns a 20,000-file image
            # into 20,000 transactions, and the walk spends its time in
            # SQLite rather than reading evidence.
            if len(pending) >= 200:
                case.add_analysis_batch(evidence_id, pending)
                pending.clear()

    try:
        walk(fs_info.open_dir(path='/'), '', 0)
    except AnalysisCancelled:
        if pending:
            case.add_analysis_batch(evidence_id, pending)
        raise
    except Exception as exc:
        logger.debug("Analysis walk stopped at offset %s: %s", offset, exc)

    if pending:
        case.add_analysis_batch(evidence_id, pending)

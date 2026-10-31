"""Project VICS JSON export: the pictures and videos on evidence, copied
out with a JSON file describing them, for Griffeye, AXIOM and the other
tools that review media by the Project VIC data model (no Qt).

The model itself is shared by Project VIC International under agreement;
what is written here follows the VICS 2.0 files the public can see -- an
export written by Griffeye Analyze DI 22.1 (VICS-Gallery-Maker's
test_files/TEST.json), the PhotoRec builder that writes VICS for Griffeye
(breakpointforensics/vics_json_builder) and GLEAPP's reader:

    {"@odata.context": ".../DataModels/2.0.xml/US/$metadata#Cases",
     "value": [{"CaseID", "CaseNumber", "Contact...", "TotalMediaFiles",
                "TotalPrecategorized", "SourceApplicationName",
                "SourceApplicationVersion",
                "Media": [{"MediaID", "MD5", "SHA1", "MediaSize",
                           "RelativeFilePath", "MimeType",
                           "IsPrecategorized", "Exifs": [...],
                           "MediaFiles": [{"MD5", "FileName", "FilePath",
                                           "Created", "Written", "Accessed",
                                           "Unallocated", "SourceID",
                                           "Deleted", ...}]}]}]}

* A **Media** is one picture or video by content (MD5): its hashes, size,
  type, EXIF and one copy under Files.<case>/, named by the MD5 as
  Griffeye names its own. A **MediaFiles** entry is each place it was
  found -- name, folder, times, deleted, carved -- so three copies of a
  photo are one Media, one copy on disk and three MediaFiles.
* Media are chosen by **content** (libmagic on the first 4 KB): a JPEG
  named .txt is exported, a text file named .jpg is not.
* Nothing is categorised: no Category, IsPrecategorized false. PhotoDNA is
  Microsoft's licensed hash and is never written; the reviewing tool
  computes it. A value TRACE does not know is left out, never null.
* Times are UTC with '+00:00'. A FAT time records local wall-clock with no
  zone: written into a DateTimeOffset it would be shifted silently by the
  reviewing machine, so it is left out and counted (`local_times_omitted`).
* Every copy is hashed as it is written and read back
  (evidence_export.write_verified). A cancelled export writes no JSON --
  a partial one would be loaded as the whole -- and says so in its log.
"""

import csv
import datetime
import json
import logging
import os
import shutil
import uuid

from trace_app.core import evidence_export
from trace_app.core.evidence_hash import HashingError

logger = logging.getLogger('TRACE.VICS')

CONTEXT = ("http://github.com/VICSDATAMODEL/ProjectVic/DataModels/2.0.xml/"
           "{model}/$metadata#Cases")
#: The profile after '2.0.xml/': US is Project VIC's (GLEAPP, the PhotoRec
#: builder); Griffeye's own export says CUSTOM.
MODELS = ('US', 'CUSTOM')
DEFAULT_MODEL = 'US'
#: Project VIC's categories (the US profile), as Griffeye lists them. 5 --
#: Uncategorized -- is what a file has until someone gives it another, so
#: it is never stored or written: a file without a category has none.
CATEGORIES = {
    0: "Non-Pertinent",
    1: "Child Abuse Material",
    2: "Child Exploitive (Age Difficult)",
    3: "CGI / Animation",
    4: "Comparison Images",
}
UNCATEGORIZED = 5
#: When copies of one picture carry different categories (one Media, one
#: category): the most serious wins -- never under-classify -- and the
#: export log names the conflict.
SEVERITY = (1, 2, 3, 4, 0)
#: The colours Griffeye shows them in.
CATEGORY_COLOURS = {0: '#2EA043', 1: '#E5534B', 2: '#E3B341',
                    3: '#D8C8A8', 4: '#3B5BDB'}


def category_label(category):
    return f"{category} {CATEGORIES[category]}" if category in CATEGORIES \
        else f"{UNCATEGORIZED} Uncategorized"


def most_serious(categories):
    """The category a picture is exported with, of its copies' categories."""
    present = [c for c in categories if c in CATEGORIES]
    return min(present, key=SEVERITY.index) if present else None


APPLICATION = 'TRACE'
LOG_NAME = 'vics-export.log'
HEAD = 4096
#: Read for EXIF from the start of a picture: JPEG keeps it in the first
#: segments, and a TIFF's IFDs sit near the start in every camera's files.
EXIF_BYTES = 4 * 1024 * 1024

#: photo_metadata key -> the EXIF property name written. The first six are
#: the names Griffeye writes; the rest say what they hold.
EXIF_NAMES = (
    ('make', 'Camera Make'), ('model', 'Camera Model'),
    ('serial', 'Camera Body Serial Number'), ('software', 'Software'),
    ('taken', 'Creation Date'), ('unique_id', 'Unique Image Id'),
    ('digitized', 'Digitized Date'), ('modified', 'Modification Date'),
    ('lens', 'Lens Model'), ('artist', 'Artist'),
    ('copyright', 'Copyright'), ('latitude', 'GPS Latitude'),
    ('longitude', 'GPS Longitude'), ('altitude', 'GPS Altitude'),
    ('gps_date', 'GPS Date'),
)
_DATE_KEYS = {'taken', 'digitized', 'modified'}

#: MIME type -> extension for a copy whose name says something else.
_EXTENSIONS = {
    'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif',
    'image/bmp': 'bmp', 'image/x-ms-bmp': 'bmp', 'image/tiff': 'tif',
    'image/webp': 'webp', 'image/heic': 'heic', 'image/heif': 'heif',
    'image/avif': 'avif', 'image/svg+xml': 'svg', 'image/x-icon': 'ico',
    'image/vnd.microsoft.icon': 'ico', 'image/vnd.adobe.photoshop': 'psd',
    'image/jp2': 'jp2', 'image/x-canon-cr2': 'cr2', 'image/x-nikon-nef': 'nef',
    'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/x-msvideo': 'avi',
    'video/x-matroska': 'mkv', 'video/webm': 'webm', 'video/x-ms-asf': 'wmv',
    'video/x-flv': 'flv', 'video/mpeg': 'mpg', 'video/3gpp': '3gp',
    'video/x-m4v': 'm4v', 'video/ogg': 'ogv',
    'image/wmf': 'wmf', 'image/emf': 'emf', 'image/x-tga': 'tga',
    'application/x-shockwave-flash': 'swf',
}


#: What libmagic says of bytes it cannot name: a TGA (no signature) is
#: looked for there.
_UNNAMED = ('application/octet-stream', 'data', '')


class VicsCancelled(Exception):
    """The examiner stopped the export."""


# --- what is media ----------------------------------------------------------

def media_type(head, name='', reader=None, size=None, read=None):
    """'image/...' or 'video/...' (or Flash's type) for a file starting
    with `head`, `size` bytes long, else None. Metafiles, Flash and TGA
    are judged by their structure (core/media_formats) -- libmagic's
    answer for them depends on its version, and so on the platform; for
    the rest libmagic decides when it is there, else the picture
    signatures the report uses and a video's name. `read(position,
    length)` lets an RLE TGA be checked whole."""
    from trace_app.core import media_formats
    from trace_app.core.filetypes import (SIGNATURELESS_MIMES,
                                          VIDEO_EXTENSIONS)
    size = len(head) if size is None else size
    own = media_formats.sniff(head, size, read, tga=False)
    if own is not None:
        return own
    if reader is not None:
        try:
            mime = (reader.from_buffer(head) or '').lower()
        except Exception:
            mime = ''
        if mime in SIGNATURELESS_MIMES or mime in _UNNAMED:
            return media_formats.TGA if media_formats.is_tga(
                head, size, read) else None
        if mime.startswith(('image/', 'video/')):
            return mime
        return None
    from trace_app.core.report import is_picture
    if is_picture(head):
        return _sniff_picture(head)
    if media_formats.is_tga(head, size, read):
        return media_formats.TGA
    extension = name.rpartition('.')[2].lower() if '.' in name else ''
    if extension in VIDEO_EXTENSIONS:
        return {'mov': 'video/quicktime', 'avi': 'video/x-msvideo',
                'mkv': 'video/x-matroska', 'wmv': 'video/x-ms-asf',
                'flv': 'video/x-flv', 'mpg': 'video/mpeg',
                'mpeg': 'video/mpeg', '3gp': 'video/3gpp',
                'ogv': 'video/ogg'}.get(extension, f'video/{extension}')
    return None


def _sniff_picture(head):
    if head[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    if head[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if head[:3] == b'GIF':
        return 'image/gif'
    if head[:2] == b'BM':
        return 'image/bmp'
    if head[:4] in (b'II*\x00', b'MM\x00*'):
        return 'image/tiff'
    if head[:4] == b'RIFF':
        return 'image/webp'
    return 'image/avif' if head[8:12] == b'avif' else 'image/heic'


def copy_extension(name, mime):
    """The extension a copy is saved with: the file's own when it is one
    for its kind of content, else the content's."""
    from trace_app.core import media_formats
    from trace_app.core.filetypes import IMAGE_EXTENSIONS, VIDEO_EXTENSIONS
    own = name.rpartition('.')[2].lower() if '.' in name else ''
    known = IMAGE_EXTENSIONS if mime.startswith('image/') \
        else VIDEO_EXTENSIONS if mime.startswith('video/') \
        else set(media_formats.EXTENSIONS.values())
    if own in known and (own == _EXTENSIONS.get(mime) or
                         mime not in _EXTENSIONS):
        return own
    if mime in _EXTENSIONS:
        return _EXTENSIONS[mime]
    return own if own.isalnum() and len(own) <= 5 else 'bin'


# --- times ------------------------------------------------------------------

def iso_time(seconds, nanoseconds=0):
    """'2023-06-12T17:54:57.9658552+00:00' (100 ns, as .NET writes), or
    None for an unset time."""
    try:
        seconds = int(seconds or 0)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        moment = datetime.datetime.fromtimestamp(seconds,
                                                 datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    text = moment.strftime('%Y-%m-%dT%H:%M:%S')
    ticks = int(nanoseconds or 0) // 100
    if 0 < ticks < 10_000_000:
        text += f'.{ticks:07d}'
    return text + '+00:00'


def file_times(handler, offset, meta):
    """({'Created', 'Written', 'Accessed'}: text, local) for an entry --
    `local` True when the file system kept zoneless local times, which are
    then not given."""
    from trace_app.core import exfat
    from trace_app.core.image_handler import _TIMEZONE_NAIVE
    try:
        zoned = handler.get_fs_type(offset) not in _TIMEZONE_NAIVE
    except Exception:
        zoned = True
    try:
        values, zoned = exfat.entry_times(handler, offset, meta, zoned)
    except Exception:
        values = {name: getattr(meta, name, None)
                  for name in ('mtime', 'atime', 'crtime')}
    if not zoned:
        return {}, any(values.get(name) for name in
                       ('mtime', 'atime', 'crtime'))
    out = {}
    for key, field in (('Created', 'crtime'), ('Written', 'mtime'),
                       ('Accessed', 'atime')):
        text = iso_time(values.get(field),
                        getattr(meta, field + '_nano', 0))
        if text:
            out[key] = text
    return out, False


# --- what to export ---------------------------------------------------------

def _windows_path(*parts):
    return '\\'.join(part.strip('/\\').replace('/', '\\') for part in parts
                     if part and part.strip('/\\'))


def find_media(handler, source_id, scope=None, include_deleted=True,
               carved=(), min_size=0, should_stop=None, progress=None,
               reader=None, inside=True, carve_inside=False, shadows=False):
    """Every picture and video on `handler` (and in `carved`, rows of a
    carve: name, offset, size, fragments), as candidates for `Package.add`.
    `progress(examined, path)` as files are looked at.

    `inside`: also the pictures and videos inside files -- archive members,
    the files documents embed, mailboxes' attachments, Firefox's cache
    block files (core/media_inside, core/firefox_cache) -- each listed
    under its container's path. `carve_inside`: and pictures found by
    their signature inside any file (a program's resources, a document's
    drawings, the page file), as AXIOM and X-Ways do -- every file read
    whole, so slower. `shadows`: and the files of each volume's Volume
    Shadow Copies, under 'Shadow copy N (created ...)' -- a snapshot's
    copy of a file the live volume holds unchanged (same path, same MD5)
    is left out (`same_as`, Package.add).

    Deleted files come from core/deleted.py, not the walk: the walk passes
    an NTFS name whose link to its MFT entry is gone (most deleted files),
    and it cannot tell a deleted file whose clusters a live file holds now
    -- whose bytes are another file's. Only 'recoverable' and 'resident'
    files are exported. A deleted file the walk saw and deleted.py does
    not list at all (a volume it does not read) is taken from the walk."""
    from trace_app.core import walk
    if reader is None:
        from trace_app.core.analysis import magic_reader
        reader = magic_reader()
    offsets = list(dict.fromkeys(walk.volume_offsets(handler)))
    volumes = walk.volume_names(handler, offsets, 'volume @ {offset}')
    stop = should_stop or (lambda: False)
    smallest = max(1, min_size)
    looking = {'inside': inside, 'carve_inside': carve_inside,
               'smallest': smallest, 'stop': stop, 'reader': reader}
    examined = 0
    walked_deleted = []
    try:
        for entry in walk.iter_files(handler, should_stop=stop,
                                     offsets=offsets, scope=scope):
            examined += 1
            if progress is not None:
                progress(examined, entry.path)
            # Too small to be exported itself: opened only to look inside.
            if entry.size < smallest and not (inside or carve_inside):
                continue
            if entry.deleted:
                if include_deleted:
                    walked_deleted.append(entry)
                continue
            yield from _file_candidates(handler, entry, source_id, volumes,
                                        looking)
        if shadows:
            for shadow, live in _shadow_volumes(handler, offsets, volumes):
                for entry in walk.iter_files(handler, should_stop=stop,
                                             offsets=[shadow], scope=scope):
                    examined += 1
                    if progress is not None:
                        progress(examined, entry.path)
                    if entry.deleted or (entry.size < smallest and not (
                            inside or carve_inside)):
                        continue
                    for candidate in _file_candidates(
                            handler, entry, source_id, volumes, looking):
                        candidate['same_as'] = _windows_path(
                            source_id, volumes.get(live, ''),
                            candidate['file_path'][
                                len(_windows_path(source_id,
                                                  volumes[shadow])):])
                        yield candidate
    except walk.WalkCancelled:
        raise VicsCancelled() from None
    if include_deleted:
        listed = set()
        for record in _deleted_records(handler, scope, stop, progress):
            listed.add(record.get('ref'))
            examined += 1
            if progress is not None and examined % 50 == 0:
                progress(examined, record.get('path') or '')
            if record.get('is_dir') or record.get('state') not in \
                    _EXPORTED_DELETED or not int(record.get('size') or 0):
                continue
            yield from _deleted_candidates(handler, record, source_id,
                                           volumes, looking)
        for entry in walked_deleted:
            if stop():
                raise VicsCancelled()
            if entry.ref in listed:
                continue
            yield from _file_candidates(handler, entry, source_id, volumes,
                                        looking)
    allocated = None
    for row in carved or ():
        if stop():
            raise VicsCancelled()
        examined += 1
        size = int(row.get('size') or 0)
        if size < max(1, min_size):
            continue
        candidate = _carved_candidate(handler, row, source_id, reader)
        if candidate is None:
            continue
        if row.get('source') == 'image':
            # A whole-image carve reads live files too: what lies in
            # allocated space is not from unallocated space.
            from trace_app.core.carving import Carver, allocation_map
            if allocated is None:
                allocated = allocation_map(handler)
            if Carver.is_offset_allocated(int(row['offset']), size,
                                          allocated):
                candidate['unallocated'] = False
        if progress is not None:
            progress(examined, candidate['name'])
        yield candidate


#: Deleted files whose bytes are still their own (core/deleted.py).
_EXPORTED_DELETED = ('recoverable', 'resident')
#: File systems whose deleted files TSK cannot read as they were: exFAT
#: (the cluster chain, core/exfat) and ext3/4 (the journal's copy of the
#: emptied inode) -- read whole by ImageHandler.get_file_content.
_WHOLE_READ = ('ExFAT', 'Ext3', 'Ext4')
#: A container is read whole to find what it holds, up to this size; a
#: mailbox (archives.STREAMED_KINDS) of any size is read as a stream.
MAX_CONTAINER_BYTES = 256 * 1024 * 1024


def _shadow_volumes(handler, offsets, volumes):
    """(shadow key, live volume offset) for every Volume Shadow Copy of
    the volumes, oldest first; each named in `volumes` after its volume,
    'Shadow copy N (created 2021-05-01 17:40 UTC)'."""
    out = []
    for offset in offsets:
        try:
            copies = handler.shadow_copies(offset)
        except Exception as exc:
            logger.debug("No shadow copies on %s: %s", offset, exc)
            continue
        for shadow in copies:
            created = shadow.get('created')
            label = f"Shadow copy {shadow['index'] + 1}" + (
                f" (created {created:%Y-%m-%d %H:%M} UTC)" if created
                else '')
            volumes[shadow['key']] = _windows_path(volumes.get(offset, ''),
                                                   label)
            out.append((shadow['key'], offset))
    return out


def _deleted_records(handler, scope, should_stop, progress):
    from trace_app.core import deleted
    from trace_app.core.carving import allocation_map
    if progress is not None:
        progress(0, 'Listing deleted files')
    try:
        allocated = allocation_map(handler)
        yield from deleted.deleted_files(handler, allocated, should_stop,
                                         scope=scope)
    except deleted.DeletedCancelled:
        raise VicsCancelled() from None


def _file_candidates(handler, entry, source_id, volumes, looking):
    return _candidates(handler, entry.offset, entry.inode, entry.name,
                       entry.path, entry.ref, bool(entry.deleted), source_id,
                       volumes, looking, entry.fs)


def _deleted_candidates(handler, record, source_id, volumes, looking):
    inode = record.get('inode')
    if not inode:
        return ()
    return _candidates(handler, record['volume'], inode, record['name'],
                       record['path'], record.get('ref') or '', True,
                       source_id, volumes, looking)


def _open_file(handler, offset, inode, deleted, path, fs=None):
    """(meta, size, head, read) of a file, or None when it cannot be
    read."""
    try:
        fs = fs or handler.get_fs_info(offset)
        handle = fs.open_meta(inode=inode)
        meta = handle.info.meta
        size = int(meta.size or 0)
        if deleted and handler.get_fs_type(offset) in _WHOLE_READ:
            content, _meta = handler.get_file_content(inode, offset)
            if content is None:
                return None

            def read(position, length):
                return content[position:position + length]
            return meta, len(content), content[:HEAD], read
        head = handle.read_random(0, min(HEAD, size)) if size else b''
    except Exception as exc:
        logger.debug("Not read: %s: %s", path, exc)
        return None

    def read(position, length):
        return handle.read_random(position, min(length, size - position))
    return meta, size, head, read


def _candidates(handler, offset, inode, name, path, ref, deleted, source_id,
                volumes, looking, fs=None):
    """The file as Package.add takes it when it is a picture or video, and
    (when asked) what is inside it."""
    opened = _open_file(handler, offset, inode, deleted, path, fs)
    if opened is None:
        return
    meta, size, head, read = opened
    if not size or not head:
        return
    reader = looking['reader']
    folder = path.rpartition('/')[0]
    file_path = _windows_path(source_id, volumes.get(offset, ''), folder)
    source_path = (f"{volumes[offset]}" if offset in volumes else '') + path
    size, read, head = _cache_entry_data(path, head, size, read)
    if size >= looking['smallest']:
        mime = media_type(head, name, reader, size, read)
        if mime is not None:
            times, local = file_times(handler, offset, meta)
            try:
                shown = handler.entry_times_text(offset, meta)
            except Exception:
                shown = {}
            yield {'name': name, 'size': size, 'mime': mime, 'read': read,
                   'source_id': source_id, 'file_path': file_path,
                   'source_path': source_path, 'ref': ref,
                   'deleted': deleted, 'unallocated': False,
                   'times': times, 'local_times': local, 'shown': shown}
    if not (looking['inside'] or looking['carve_inside']):
        return
    container = {'name': name, 'file_path': _windows_path(file_path, name),
                 'source_path': source_path, 'ref': ref,
                 'deleted': deleted, 'source_id': source_id}
    if looking['inside']:
        from trace_app.core.chrome_cache import is_index
        from trace_app.core.firefox_cache import MAP_NAME
        if not deleted and (name.upper() == MAP_NAME or (
                name == 'index' and is_index(head))):
            yield from _browser_cache(handler, offset, folder, container,
                                      looking)
        yield from _inside(handler, offset, inode, size, head, read,
                           container, looking)
    if looking['carve_inside']:
        from trace_app.core import hiberfil
        if hiberfil.is_hibernation_name(name):
            yield from _hibernated(size, read, container, looking)
        else:
            yield from _carved_inside(size, head, read, container, looking)


def _hibernated(size, read, container, looking):
    """Pictures in a Windows XP-7 hibernation file's memory, carved
    from each Xpress block decompressed (core/hiberfil); named '<block
    offset>+<offset in it>.<type>'."""
    from trace_app.core import hiberfil
    for at, pages in hiberfil.blocks(read, size, looking['stop']):
        yield from _carved_inside(
            len(pages), pages[:HEAD],
            lambda position, length, pages=pages:
            pages[position:position + length],
            container, looking, prefix=f'{at:x}+')


def _member_candidate(container, chain, content, looking, extra=None):
    """A file found inside `container` (`chain`: the member's names from
    the container down), as Package.add takes it, or None when it is not
    a picture or video. Its times are its container's business: a ZIP's
    are local with no zone, a mailbox's are the message's -- none is
    written. Categories are never taken from the container's."""
    if len(content) < looking['smallest']:
        return None
    member = chain[-1].replace('\\', '/').rstrip('/')
    name = member.rsplit('/', 1)[-1] or 'member'

    def read(position, length):
        return content[position:position + length]
    mime = media_type(content[:HEAD], name, looking['reader'],
                      len(content), read)
    if mime is None:
        return None
    inner = [part.replace('\\', '/') for part in chain[:-1]]
    folders = '/'.join(inner + [member.rpartition('/')[0]])
    candidate = {
        'name': name, 'size': len(content), 'mime': mime, 'read': read,
        'source_id': container['source_id'],
        'file_path': _windows_path(container['file_path'], folders),
        'source_path': container['source_path'] + ''.join(
            f'!/{part}' for part in chain),
        'ref': container['ref'], 'member': True,
        'deleted': container['deleted'], 'unallocated': False,
        'times': {}, 'local_times': False}
    candidate.update(extra or {})
    return candidate


def _inside(handler, offset, inode, size, head, read, container, looking):
    """Archive members and documents' embedded files (core/media_inside),
    to the case's archive nesting depth."""
    from trace_app.core import archives, media_inside
    kind = media_inside.kind_of(head)
    if kind is None:
        return
    if kind.partition(':')[2] in archives.STREAMED_KINDS:
        content = handler.open_file_object(inode, offset)
    elif size > MAX_CONTAINER_BYTES:
        logger.info("Not looked inside (%d bytes): %s", size,
                    container['source_path'])
        return
    else:
        try:
            content = read(0, size)
        except Exception as exc:
            logger.debug("Not read: %s: %s", container['source_path'], exc)
            return
    if content is None:
        return
    for member in media_inside.members(content,
                                       should_stop=looking['stop']):
        if looking['stop']():
            raise VicsCancelled()
        candidate = _member_candidate(container, member.chain,
                                      member.content, looking)
        if candidate is not None:
            yield candidate


def _browser_cache(handler, offset, folder, container, looking):
    """The objects a browser kept in its cache's block files beside this
    `_CACHE_MAP_` (Firefox) or `index` (Chromium's blockfile cache), each
    under its block file and the URL's file name."""
    from trace_app.core import chrome_cache, firefox_cache

    def read_file(name):
        return handler.read_path(offset, f"{folder}/{name}")
    if container['name'] == 'index':
        entries = chrome_cache.Cache(read_file).entries()
        times = (('Created', 'created'),)
    else:
        entries = firefox_cache.Cache(read_file).entries()
        times = (('Written', 'last_modified'), ('Accessed', 'last_fetched'))
    parent = container['file_path'].rpartition('\\')[0]
    try:
        for entry in entries:
            if looking['stop']():
                raise VicsCancelled()
            block = {'file_path': _windows_path(parent, entry['block_file']),
                     'source_path': container['source_path'].rpartition(
                         '/')[0] + '/' + entry['block_file'],
                     'ref': container['ref'], 'deleted': False,
                     'source_id': container['source_id']}
            shown = {}
            for key, field in times:
                text = iso_time(entry.get(field))
                if text:
                    shown[key] = text
            candidate = _member_candidate(
                block, [entry['name']], entry['content'], looking,
                {'times': shown, 'url': entry['key']})
            if candidate is not None:
                yield candidate
    except firefox_cache.CacheError as exc:
        logger.debug("Not a browser cache: %s: %s",
                     container['source_path'], exc)


def _cache_entry_data(path, head, size, read):
    """(size, read, head) of the object a browser cache entry file holds
    when it holds more than the object, else what was given:

    * a Firefox cache2 entry is the object then its metadata, whose offset
      the last 4 bytes hold (big-endian);
    * a Chromium simple-cache entry is a header and the URL, the body,
      then the headers (core/chrome_cache.simple_body)."""
    from trace_app.core import chrome_cache
    if chrome_cache.is_simple_entry(head):
        try:
            found = chrome_cache.simple_body(read, size)
        except Exception as exc:
            logger.debug("Simple cache entry not read: %s: %s", path, exc)
            found = None
        if found is None:
            return size, read, head
        start, length = found[0], found[1]

        def body(position, count):
            return read(start + position,
                        max(0, min(count, length - position)))
        return length, body, body(0, HEAD)
    if '/cache2/entries/' not in path.replace('\\', '/').lower() or size < 8:
        return size, read, head
    try:
        end = int.from_bytes(read(size - 4, 4), 'big')
    except Exception:
        return size, read, head
    # The metadata after the data: a hash per 256 KB chunk (4 bytes for
    # the whole, 2 per chunk), then its own header -- it fits the file.
    chunks = (end + 262143) // 262144
    if not 0 < end < size or end + 4 + 2 * chunks + 4 > size:
        return size, read, head

    def data(position, length):
        return read(position, max(0, min(length, end - position)))
    return end, data, head


# --- pictures carved from inside files --------------------------------------

#: The picture and video formats looked for inside other files, as carving
#: names them (core/carving.CARVE_CATEGORIES).
INSIDE_TYPES = ('jpg', 'png', 'gif', 'bmp', 'tiff', 'avi', 'wmv', 'mp4',
                'mov', 'flv', 'mkv', 'webp', 'psd')
#: Read for carving inside a file at a time (plus the carvers' overlap).
INSIDE_PIECE = 16 * 1024 * 1024


def _carved_inside(size, head, read, container, looking, prefix=''):
    """Pictures and videos inside a file, found by carving's signature
    carvers over its bytes (sized by structure, validated as carving
    validates): the files a program, a document or the page file keeps
    whole within itself. The file itself, when it is one, is not found
    again; a photo's EXIF thumbnail is (AXIOM lists those). Each is named
    `prefix` + its offset in hex + its type."""
    from trace_app.core import carving, media_formats
    found = []

    def sink(content, file_type, position, fragments=None):
        if position == 0 and len(content) == size:
            return                    # the file itself
        found.append((position, file_type, content))

    def piece_reader(position, length):
        return read(position, max(0, min(length, size - position)))
    carver = carving.Carver(sink, wanted=INSIDE_TYPES, reader=piece_reader,
                            image_size=size)
    carver.alignment = 1
    families = list(dict.fromkeys(
        carving.EXTENSION_CARVER.get(kind, kind) for kind in INSIDE_TYPES))
    families = [family for family in families
                if family in carving.Carver.CARVERS]
    position = 0
    while position < size:
        if looking['stop']():
            raise VicsCancelled()
        chunk = piece_reader(position, INSIDE_PIECE + carving.CARVE_OVERLAP)
        if not chunk:
            break
        carver.own_end = min(position + INSIDE_PIECE, size)
        for family in families:
            try:
                carving.Carver.CARVERS[family](carver, chunk, position)
            except Exception as exc:
                logger.debug("%s carver failed inside %s: %s", family,
                             container['source_path'], exc)
        carver.own_end = None
        # Metafiles: carving has no carver for them; Office's clip-art and
        # border files hold them whole (X-Ways lists each).
        for offset, length, mime in media_formats.metafiles_in(
                chunk, lambda at, length: piece_reader(position + at,
                                                       length),
                size - position):
            if offset < INSIDE_PIECE and (position + offset, length) != \
                    (0, size):
                found.append((position + offset,
                              media_formats.EXTENSIONS[mime],
                              piece_reader(position + offset, length)))
        while found:
            offset, file_type, content = found.pop(0)
            chain = [f"{prefix}{offset:x}.{file_type}"]
            candidate = _member_candidate(
                container, chain, content, looking,
                {'carved_inside': True, 'offset_in_file': offset})
            if candidate is not None:
                candidate['file_path'] = container['file_path']
                yield candidate
        position += INSIDE_PIECE


def _carved_candidate(handler, row, source_id, reader):
    from trace_app.core.carving import read_carved
    offset, size = int(row['offset']), int(row['size'])
    fragments = row.get('fragments') or None
    try:
        if fragments:
            content = read_carved(handler.read, offset, size, fragments)
            head = (content or b'')[:HEAD]
        else:
            content = None
            head = handler.read(offset, min(HEAD, size))
    except Exception as exc:
        logger.debug("Carve at %d not read: %s", offset, exc)
        return None
    if not head:
        return None
    name = row.get('name') or f"{offset:x}.{row.get('type') or 'bin'}"
    mime = media_type(head, name, reader)
    if mime is None:
        return None

    if content is not None:
        def read(position, length):
            return content[position:position + length]
    else:
        def read(position, length):
            return handler.read(offset + position,
                                min(length, size - position))
    from trace_app.core.case import make_span_ref
    return {'name': name, 'size': size, 'mime': mime, 'read': read,
            'source_id': source_id,
            'file_path': _windows_path(source_id, '[carved]'),
            'source_path': f"[carved]/{name}",
            'ref': row.get('artifact_ref') or make_span_ref(0, offset,
                                                             offset + size),
            'deleted': False, 'unallocated': True, 'times': {},
            'local_times': False, 'physical_location': offset}


# --- the package ------------------------------------------------------------

def exif_properties(data):
    """[(name, value)] from a picture's EXIF (content_checks.photo_metadata)."""
    from trace_app.core.content_checks import photo_metadata
    try:
        facts = photo_metadata(data)
    except Exception:
        return []
    out = []
    for key, name in EXIF_NAMES:
        value = facts.get(key)
        if value in (None, ''):
            continue
        value = str(value)
        if key in _DATE_KEYS and len(value) >= 19 and value[4] == ':' \
                and value[7] == ':':
            value = value[:4] + '-' + value[5:7] + '-' + value[8:]
        out.append((name, value))
    return out


def package_name(case_number):
    """'Files.<case>' and '<case>.json' share this stem."""
    return evidence_export.safe_component(case_number, 'TRACE').replace(
        ' ', '_')


class Package:
    """One VICS export folder: copies under Files.<case>/, then the JSON.

    `add(candidate)` copies a file (or, when its MD5 is already here,
    records one more place it was found); `finish()` writes the JSON, the
    manifest and the log, and returns the summary."""

    def __init__(self, folder, case_number='', contact=None,
                 model=DEFAULT_MODEL, version='', should_stop=None,
                 progress=None):
        if model not in MODELS:
            raise ValueError(f"unknown VICS model {model!r}")
        self.folder = folder
        self.case_number = case_number or ''
        self.contact = dict(contact or {})
        self.model, self.version = model, version
        self.should_stop = should_stop or (lambda: False)
        self.progress = progress
        self.stem = package_name(case_number)
        self.files_dir = f'Files.{self.stem}'
        self.media = {}                 # MD5 -> Media dict, in order found
        #: MD5 -> its copies' categories [(category, path)] and comments.
        self._marks = {}
        self.rows = []                  # manifest rows
        self.problems = []
        self.local_times_omitted = 0
        #: Files of shadow copies left out: the live volume holds them as
        #: they were.
        self.shadow_unchanged = 0
        self.bytes_copied = 0
        os.makedirs(os.path.join(folder, self.files_dir), exist_ok=True)
        self._incoming = os.path.join(folder, self.files_dir, '.incoming')
        os.makedirs(self._incoming, exist_ok=True)

    # One file ----------------------------------------------------------

    def add(self, candidate):
        if self.should_stop():
            raise VicsCancelled()
        staging = os.path.join(self._incoming, f'{len(self.rows)}.part')
        head = bytearray()
        read = candidate['read']

        def capture(position, length):
            data = read(position, length)
            if position < EXIF_BYTES and data:
                head.extend(data[:max(0, EXIF_BYTES - position)])
            return data
        try:
            digests = evidence_export.write_verified(
                staging, capture, candidate['size'], self.should_stop,
                self._copied)
        except evidence_export.ExportCancelled:
            raise VicsCancelled() from None
        except (HashingError, OSError) as exc:
            self.problems.append(f"{candidate['source_path']}: {exc}")
            self.rows.append(self._row(candidate, problem=str(exc)))
            return None
        md5 = digests['md5'].upper()
        media = self.media.get(md5)
        if media is not None and candidate.get('same_as') and any(
                place['FilePath'] == candidate['same_as'] and
                place['FileName'] == candidate['name']
                for place in media['MediaFiles']):
            # A shadow copy's copy of a file the live volume holds as it
            # is: the same file, not another place it was found.
            os.remove(staging)
            self.shadow_unchanged += 1
            return media
        if media is None:
            relative = self._place(staging, md5, candidate)
            media = {'MediaID': len(self.media), 'MD5': md5,
                     'SHA1': digests['sha1'].upper(),
                     'MediaSize': digests['size'],
                     'RelativeFilePath': relative.replace('/', '\\'),
                     'MimeType': candidate['mime'],
                     'IsPrecategorized': False}
            if candidate['mime'].startswith('image/'):
                exifs = [{'MD5': md5, 'PropertyName': name,
                          'PropertyValue': value}
                         for name, value in exif_properties(bytes(head))]
                if exifs:
                    media['Exifs'] = exifs
            media['MediaFiles'] = []
            self.media[md5] = media
            self._marks[md5] = {'categories': [], 'comments': []}
        else:
            os.remove(staging)
            relative = media['RelativeFilePath'].replace('\\', '/')
        media['MediaFiles'].append(self._media_file(md5, candidate))
        marks = self._marks[md5]
        if candidate.get('category') in CATEGORIES:
            marks['categories'].append((candidate['category'],
                                        candidate['source_path']))
        comment = (candidate.get('comment') or '').strip()
        if comment and comment not in marks['comments']:
            marks['comments'].append(comment)
        if candidate.get('local_times'):
            self.local_times_omitted += 1
        if digests.get('written_copy_check') != 'matches':
            self.problems.append(f"{candidate['source_path']}: "
                                 f"{digests.get('written_copy_check')}")
        self.rows.append(self._row(candidate, digests, relative))
        return media

    def _copied(self, length):
        self.bytes_copied += length
        if self.progress is not None:
            self.progress(self.bytes_copied)

    def _place(self, staging, md5, candidate):
        """Files.<case>/AB/CD/<rest of the MD5>.<ext>, as Griffeye lays
        out its own exports."""
        extension = copy_extension(candidate['name'], candidate['mime'])
        relative = '/'.join((self.files_dir, md5[:2], md5[2:4],
                             f'{md5[4:]}.{extension}'))
        target = os.path.join(self.folder, *relative.split('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.replace(staging, target)
        return relative

    @staticmethod
    def _media_file(md5, candidate):
        entry = {'MD5': md5, 'FileName': candidate['name'],
                 'FilePath': candidate['file_path']}
        for key in ('Created', 'Written', 'Accessed'):
            if candidate['times'].get(key):
                entry[key] = candidate['times'][key]
        entry['Unallocated'] = bool(candidate['unallocated'])
        entry['SourceID'] = candidate['source_id']
        entry['Deleted'] = bool(candidate['deleted'])
        if candidate.get('physical_location') is not None:
            entry['PhysicalLocation'] = int(candidate['physical_location'])
        return entry

    def _row(self, candidate, digests=None, saved='', problem=''):
        """The export manifest's row: times as TRACE shows them, FAT's
        marked local -- the record of what the JSON leaves out."""
        digests = digests or {}
        shown = {key: value for key, value in
                 (candidate.get('shown') or {}).items() if value != 'N/A'}
        return {'exported_utc': evidence_export._utc_now(),
                'evidence': candidate['source_id'],
                'source_path': candidate['source_path'],
                'artifact_ref': candidate.get('ref') or '',
                'deleted': 'yes' if candidate['deleted'] else 'no',
                'created': shown.get('created', ''),
                'modified': shown.get('modified', ''),
                'accessed': shown.get('accessed', ''),
                'changed': shown.get('changed', ''),
                'size': candidate['size'],
                'md5': digests.get('md5', ''), 'sha1': digests.get('sha1', ''),
                'sha256': digests.get('sha256', ''),
                'written_copy_check': digests.get('written_copy_check', ''),
                'saved_as': saved, 'problem': problem}

    # The whole -------------------------------------------------------------

    def category_of(self, md5):
        """(the category written for picture `md5` or None, and
        [(category, path)] of its copies when they disagree)."""
        given = self._marks.get(md5, {}).get('categories') or []
        chosen = most_serious(category for category, _path in given)
        disagree = len({category for category, _path in given}) > 1
        return chosen, (given if disagree else [])

    def conflicts(self):
        """[(md5, chosen, [(category, path)])] -- pictures whose copies
        the examiner categorised differently."""
        out = []
        for md5 in self.media:
            chosen, given = self.category_of(md5)
            if given:
                out.append((md5, chosen, given))
        return out

    def _media_out(self, md5, media):
        """The Media as written: Griffeye's key order, Category (the
        examiner's, the most serious of its copies') after SHA1 and the
        bookmarks' and notes' text as Comments. IsPrecategorized stays
        false: in Griffeye's own export it means a hash-database match,
        not a reviewer's verdict."""
        chosen, _given = self.category_of(md5)
        out = {}
        for key, value in media.items():
            if key == 'MediaSize' and chosen is not None:
                out['Category'] = chosen
            if key == 'MediaFiles':
                comments = self._marks.get(md5, {}).get('comments')
                if comments:
                    out['Comments'] = ' | '.join(comments)
            out[key] = value
        return out

    def document(self):
        files = sum(len(m['MediaFiles']) for m in self.media.values())
        case = {'CaseID': str(uuid.uuid4()), 'CaseNumber': self.case_number}
        for key in ('ContactName', 'ContactOrganization', 'ContactPhone',
                    'ContactEmail', 'ContactTitle'):
            case[key] = self.contact.get(key, '') or ''
        case.update({'TotalMediaFiles': files, 'TotalPrecategorized': 0,
                     'SourceApplicationName': APPLICATION,
                     'SourceApplicationVersion': self.version,
                     'Media': [self._media_out(md5, media)
                               for md5, media in self.media.items()]})
        return {'@odata.context': CONTEXT.format(model=self.model),
                'value': [case]}

    def finish(self, cancelled=False):
        """Write the JSON (not when cancelled), manifest and log. Returns
        the summary: json path and SHA-256, counts, problems."""
        shutil.rmtree(self._incoming, ignore_errors=True)
        json_path, json_sha256 = '', ''
        if not cancelled:
            json_path = os.path.join(self.folder, f'{self.stem}.json')
            with open(json_path, 'w', encoding='utf-8') as handle:
                json.dump(self.document(), handle, indent=2,
                          ensure_ascii=False)
            json_sha256 = _sha256(json_path)
        manifest = os.path.join(self.folder, evidence_export.MANIFEST)
        with open(manifest, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle,
                                    fieldnames=evidence_export.MANIFEST_COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows)
        summary = {
            'folder': self.folder, 'json': json_path,
            'json_sha256': json_sha256, 'manifest': manifest,
            'manifest_sha256': _sha256(manifest),
            'media': len(self.media),
            'media_files': sum(len(m['MediaFiles'])
                               for m in self.media.values()),
            'bytes': sum(m['MediaSize'] for m in self.media.values()),
            'local_times_omitted': self.local_times_omitted,
            'shadow_unchanged': self.shadow_unchanged,
            'categorised': sum(1 for md5 in self.media
                               if self.category_of(md5)[0] is not None),
            'commented': sum(1 for marks in self._marks.values()
                             if marks['comments']),
            'conflicts': len(self.conflicts()),
            'problems': list(self.problems), 'cancelled': cancelled,
            'model': self.model}
        self._write_log(summary)
        return summary

    def _write_log(self, summary):
        lines = [f"Project VICS export by {APPLICATION} {self.version}",
                 f"Written {evidence_export._utc_now()} UTC",
                 f"Model: VICS 2.0 {self.model}",
                 f"Case number: {self.case_number}",
                 f"Media (unique by MD5): {summary['media']:,}",
                 f"Places found (MediaFiles): {summary['media_files']:,}",
                 f"Bytes copied: {summary['bytes']:,}"]
        if summary['cancelled']:
            lines.append("CANCELLED: no VICS JSON was written; the copies "
                         "here are listed in the manifest only.")
        else:
            lines.append(f"JSON: {os.path.basename(summary['json'])} "
                         f"SHA-256 {summary['json_sha256']}")
        if summary['shadow_unchanged']:
            lines.append(
                f"{summary['shadow_unchanged']:,} file(s) in Volume Shadow "
                "Copies were the live volume's file as it is (same path, "
                "same MD5) and are not listed again.")
        if summary['local_times_omitted']:
            lines.append(
                f"{summary['local_times_omitted']:,} file(s) on FAT/exFAT "
                "volumes recorded local times with no zone. They are left "
                "out of the JSON rather than written as UTC; the manifest "
                "has them, marked local.")
        counts = {}
        for md5 in self.media:
            chosen = self.category_of(md5)[0]
            counts[chosen] = counts.get(chosen, 0) + 1
        lines.append("Project VIC categories (the examiner's, from TRACE):")
        for category in sorted(CATEGORIES, key=SEVERITY.index):
            if counts.get(category):
                lines.append(f"  {category_label(category)}: "
                             f"{counts[category]:,}")
        lines.append(f"  {category_label(None)} (no Category written): "
                     f"{counts.get(None, 0):,}")
        conflicts = self.conflicts()
        if conflicts:
            lines.append(f"Copies categorised differently ({len(conflicts):,};"
                         " the most serious was written):")
            for md5, chosen, given in conflicts:
                lines.append(f"  {md5} -> {category_label(chosen)}")
                lines += [f"    {category_label(category)}: {path}"
                          for category, path in given]
        if summary['commented']:
            lines.append(f"Comments (bookmark labels and notes): "
                         f"{summary['commented']:,} picture(s)")
        lines.append("Not written: PhotoDNA (licensed; the reviewing tool "
                     "computes it). IsPrecategorized is false: categories "
                     "here are a reviewer's, not a hash-database match.")
        if summary['problems']:
            lines.append(f"Problems ({len(summary['problems']):,}):")
            lines += [f"  {problem}" for problem in summary['problems']]
        with open(os.path.join(self.folder, LOG_NAME), 'w',
                  encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')


def _sha256(path):
    from trace_app.core.evidence_hash import sha256_file
    return sha256_file(path)


def export_folder(parent, case_number):
    """A new folder under `parent` for one export:
    'VICS <case> <UTC stamp>' (never an existing one)."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y%m%d-%H%M%S')
    name = evidence_export.safe_component(f"VICS {case_number} {stamp}"
                                          if case_number else
                                          f"VICS {stamp}", 'VICS')
    return evidence_export.unique_path(parent, name)


def export(sources, folder, case_number='', contact=None,
           model=DEFAULT_MODEL, version='', scope=None,
           include_deleted=True, include_carved=True, min_size=0,
           should_stop=None, progress=None, inside=True,
           carve_inside=False, shadows=False):
    """The whole export. `sources` is [(source id, handler, carved rows,
    marks)] -- `marks` (optional) {'categories': {artifact_ref: 0-4},
    'comments': {artifact_ref: text}} from the case; a file inside another
    takes neither from its container. `inside` / `carve_inside` /
    `shadows`: see find_media.
    `progress(examined, bytes copied, what)`. Returns Package.finish's
    summary (cancelled=True when stopped: no JSON)."""
    state = {'before': 0, 'examined': 0, 'what': ''}

    def report(copied):
        if progress is not None:
            progress(state['before'] + state['examined'], copied,
                     state['what'])

    def looked(examined, what):
        state['examined'], state['what'] = examined, what
        report(package.bytes_copied)

    package = Package(folder, case_number, contact, model, version,
                      should_stop, report)
    from trace_app.core.analysis import magic_reader
    reader = magic_reader()
    try:
        for source in sources:
            source_id, handler, carved = source[:3]
            marks = (source[3] if len(source) > 3 else None) or {}
            categories = marks.get('categories') or {}
            comments = marks.get('comments') or {}
            state['before'] += state['examined']
            state['examined'] = 0
            for candidate in find_media(
                    handler, source_id, scope, include_deleted,
                    carved if include_carved else (), min_size,
                    should_stop, looked, reader, inside, carve_inside,
                    shadows):
                if not candidate.get('member'):
                    candidate['category'] = categories.get(candidate['ref'])
                    candidate['comment'] = comments.get(candidate['ref'], '')
                package.add(candidate)
    except VicsCancelled:
        return package.finish(cancelled=True)
    return package.finish()

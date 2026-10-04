"""Thumbnail caches: pictures Windows kept of files, often after the files
themselves were deleted.

* **thumbcache_*.db** (Windows Vista to 11, in each profile's
  AppData\\Local\\Microsoft\\Windows\\Explorer): a header ("CMMM", format
  version 20 Vista, 21 Windows 7, 30 8.0, 31 8.1, 32 10/11, and which size
  the file holds), then entries back to back, each "CMMM", its size, a
  64-bit hash (the thumbnail cache id), an identifier, and the picture --
  BMP, JPEG or PNG -- with its width and height from version 30 on. The
  file does not say which file a picture is of: the cache id is what the
  Windows Search index records against a file, and is shown so it can be
  matched there. Entries are walked one after another and, where one is
  damaged, by their signature, so a picture left in a freed part of the
  file is still found. Layout: Joachim Metz's libwtcdb documentation.
* **Thumbs.db** (Windows XP, and Vista+ on network shares), an OLE
  compound file read with olefile. XP's has a Catalog stream: for each
  picture its number, the *name of the file it is of* and that file's last
  modification time, and a stream of that number reversed ("01" for 10)
  holding a short header and a JPEG. Vista's has 256_<cache id> streams and
  no names.

A Thumbs.db names the files whose pictures it holds, so each is looked up
in the folder it sits in: a picture of a file that is no longer there, or
is there only as a deleted entry, is a finding.

Nothing is extracted: the table records where each picture lies, and the
viewer reads it back from the cache file on the image. No Qt here.
"""

import datetime
import hashlib
import io
import json
import logging
import re
import struct

logger = logging.getLogger('TRACE.Thumbnails')

MODULE_THUMBNAILS = 'thumbnails'
SIGNATURE = b'CMMM'
INDEX_SIGNATURE = b'IMMM'
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

FORMAT_VERSIONS = {20: 'Windows Vista', 21: 'Windows 7', 30: 'Windows 8',
                   31: 'Windows 8.1', 32: 'Windows 10/11'}
#: Which file the cache type names, by format version.
CACHE_TYPES = {
    20: ('32', '96', '256', '1024', 'sr'),
    21: ('32', '96', '256', '1024', 'sr'),
    30: ('16', '32', '48', '96', '256', '1024', 'sr', 'wide', 'exif'),
    31: ('16', '32', '48', '96', '256', '1024', '1600', 'sr', 'wide',
         'exif', 'wide_alternate'),
    32: ('16', '32', '48', '96', '256', '768', '1280', '1920', '2560', 'sr',
         'wide', 'exif', 'wide_alternate', 'custom_stream'),
}
#: Largest cache file read whole.
MAX_CACHE_BYTES = 512 * 1024 * 1024
#: Largest single picture believed.
MAX_PICTURE_BYTES = 64 * 1024 * 1024

#: XP keeps the picture it shows for the folder itself under a GUID, not
#: a file name: no file of that name was ever in the folder.
_FOLDER_PICTURE = re.compile(r'\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-'
                             r'[0-9A-Fa-f]{12}\}')

#: Names a Thumbs.db goes by (ehthumbs: Media Center's).
THUMBS_DB_NAMES = ('thumbs.db', 'ehthumbs.db', 'ehthumbs_vista.db')


class ThumbnailError(Exception):
    """The cache could not be read."""


def picture_format(data):
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:2] == b'BM':
        return 'bmp'
    return ''


# --- thumbcache_*.db ---------------------------------------------------------------

def is_thumbcache(header):
    if len(header) < 8 or header[:4] != SIGNATURE:
        return False
    return struct.unpack_from('<I', header, 4)[0] in FORMAT_VERSIONS


def _utf16(data):
    return data.decode('utf-16-le', 'replace').split('\x00', 1)[0]


def _entry(data, offset, version):
    """One cache entry at `offset`, or None if it is not one."""
    header_size = 56 if version in (20,) or version >= 30 else 48
    if offset + header_size > len(data) or \
            data[offset:offset + 4] != SIGNATURE:
        return None
    size, entry_hash = struct.unpack_from('<IQ', data, offset + 4)
    if size < header_size or offset + size > len(data):
        return None
    extension = ''
    width = height = None
    if version == 20:
        extension = _utf16(data[offset + 16:offset + 24])
        id_size, padding, data_size = struct.unpack_from('<III', data,
                                                         offset + 24)
    else:
        id_size, padding, data_size = struct.unpack_from('<III', data,
                                                         offset + 16)
        if version >= 30:
            width, height = struct.unpack_from('<II', data, offset + 28)
    if header_size + id_size + padding + data_size > size or \
            data_size > MAX_PICTURE_BYTES or id_size > 4096:
        return None
    start = offset + header_size
    identifier = data[start:start + id_size].decode('utf-16-le', 'replace')
    data_offset = start + id_size + padding
    picture = data[data_offset:data_offset + min(data_size, 16)]
    return {'offset': offset, 'size': size, 'hash': f'{entry_hash:016x}',
            'identifier': identifier, 'extension': extension,
            'width': width or None, 'height': height or None,
            'data_offset': data_offset, 'data_size': data_size,
            'format': picture_format(picture) if data_size else ''}


def parse_thumbcache(data):
    """{'version', 'system', 'cache', 'entries': [...]} -- every entry that
    holds a picture, in file order."""
    if not is_thumbcache(data[:8]):
        raise ThumbnailError("Not a Windows thumbnail cache (no CMMM "
                             "header).")
    version, cache_type = struct.unpack_from('<II', data, 4)
    names = CACHE_TYPES.get(version, ())
    cache = names[cache_type] if cache_type < len(names) else str(cache_type)
    entries = []
    offset = 24
    while offset + 8 <= len(data):
        entry = _entry(data, offset, version)
        if entry is None:
            # Damaged or freed space: on to the next signature.
            following = data.find(SIGNATURE, offset + 1)
            if following == -1:
                break
            offset = following
            continue
        if entry['data_size'] and entry['format']:
            entries.append(entry)
        offset += entry['size']
    return {'version': version,
            'system': FORMAT_VERSIONS.get(version, f'format {version}'),
            'cache': cache, 'entries': entries}


# --- Thumbs.db -----------------------------------------------------------------------

def _filetime(value):
    if not value:
        return None
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(
            microseconds=value // 10)).strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, ValueError):
        return None


def might_be_thumbs_db(data):
    """Cheap: an OLE file with a stream named the way a Thumbs.db names
    them. (A Word document is an OLE file too.)"""
    if data[:8] != OLE_MAGIC:
        return False
    return 'Catalog'.encode('utf-16-le') in data or \
        '256_'.encode('utf-16-le') in data


def is_thumbs_db(data):
    """An OLE file whose streams are a Thumbs.db's: a Catalog, or
    256_<cache id> pictures."""
    if not might_be_thumbs_db(data):
        return False
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, IOError, ValueError):
        return False
    try:
        streams = ['/'.join(path) for path in ole.listdir()]
    finally:
        ole.close()
    return 'Catalog' in streams or any(s.startswith('256_')
                                       for s in streams)


def _stream_picture(raw):
    """The picture in a Thumbs.db stream, after its header."""
    if len(raw) >= 12:
        header = struct.unpack_from('<I', raw, 0)[0]
        if 8 <= header <= 64 and picture_format(raw[header:header + 16]):
            return raw[header:]
    for marker in (b'\xff\xd8\xff', b'\x89PNG'):
        at = raw.find(marker, 0, 256)
        if at != -1:
            return raw[at:]
    return b''


def parse_thumbs_db(data):
    """[{'stream', 'name', 'number', 'modified', 'width', 'height',
    'format', 'size'}] for every picture, with the bytes under 'data'."""
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, IOError, ValueError) as exc:
        raise ThumbnailError(f"Not a readable Thumbs.db: {exc}") from exc
    try:
        streams = ['/'.join(path) for path in ole.listdir()]
        catalog = {}
        width = height = None
        if 'Catalog' in streams:
            raw = ole.openstream('Catalog').read()
            if len(raw) >= 16:
                header, _version, count, width, height = struct.unpack_from(
                    '<HHIII', raw, 0)
                position = header or 16
                while position + 16 <= len(raw):
                    length, number, written = struct.unpack_from(
                        '<IIQ', raw, position)
                    if length < 16 or position + length > len(raw):
                        break
                    name = _utf16(raw[position + 16:position + length])
                    catalog[str(number)[::-1]] = {
                        'number': number, 'name': name,
                        'modified': _filetime(written)}
                    position += length
        out = []
        for stream in streams:
            if stream == 'Catalog':
                continue
            try:
                picture = _stream_picture(ole.openstream(stream).read())
            except (OSError, IOError):
                continue
            kind = picture_format(picture[:16])
            if not kind:
                continue
            known = catalog.get(stream, {})
            out.append({'stream': stream, 'name': known.get('name') or '',
                        'number': known.get('number'),
                        'modified': known.get('modified'),
                        'width': width if known else None,
                        'height': height if known else None,
                        'cache_id': stream[4:] if stream.startswith('256_')
                        else '', 'format': kind, 'size': len(picture),
                        'data': picture})
        # Catalog entries whose picture stream is gone are still names of
        # files that were in the folder.
        present = {entry['stream'] for entry in out}
        for stream, known in catalog.items():
            if stream not in present:
                out.append({'stream': stream, 'name': known['name'],
                            'number': known['number'],
                            'modified': known['modified'], 'width': None,
                            'height': None, 'cache_id': '', 'format': '',
                            'size': 0, 'data': b''})
        out.sort(key=lambda e: (e['number'] is None, e['number'] or 0,
                                e['stream']))
        return out
    finally:
        ole.close()


def thumbs_db_picture(data, stream):
    import olefile
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        return _stream_picture(ole.openstream(stream).read())
    finally:
        ole.close()


# --- the archive view: a cache browsed like a folder of pictures ----------------------

def list_members(data, kind):
    out = []
    for (name, size, modified), _entry in _members(data, kind):
        out.append({'name': name, 'size': size, 'compressed_size': size,
                    'is_dir': False, 'modified': modified,
                    'encrypted': False, 'crc': None})
    return out


def _members(data, kind):
    seen = set()

    def unique(name):
        base, dot, ext = name.rpartition('.')
        candidate, count = name, 2
        while candidate in seen:
            candidate = f'{base} ({count}).{ext}'
            count += 1
        seen.add(candidate)
        return candidate

    if kind == 'thumbcache':
        for number, entry in enumerate(parse_thumbcache(data)['entries'], 1):
            yield (unique(f"{number:04d} {entry['hash']}.{entry['format']}"),
                   entry['data_size'], None), entry
    else:
        for entry in parse_thumbs_db(data):
            if not entry['format']:
                continue
            label = entry['name'] or entry['cache_id'] or entry['stream']
            yield (unique(f"{label} (thumbnail).{entry['format']}"),
                   entry['size'], entry['modified']), entry


def read_member(data, name, kind, limit):
    for (member, size, _modified), entry in _members(data, kind):
        if member != name:
            continue
        if size > limit:
            raise ThumbnailError(f"{name} is {size:,} bytes, over the limit")
        if kind == 'thumbcache':
            return bytes(data[entry['data_offset']:
                              entry['data_offset'] + entry['data_size']])
        return entry['data']
    raise ThumbnailError(f"No member {name}")


# --- one image ---------------------------------------------------------------------------

def is_cache_name(name):
    lower = (name or '').lower()
    return lower in THUMBS_DB_NAMES or (lower.startswith('thumbcache_')
                                        and lower.endswith('.db'))


def _user_of(path):
    parts = [p for p in path.replace('\\', '/').split('/') if p]
    lowered = [p.lower() for p in parts]
    for home in ('users', 'documents and settings'):
        if home in lowered:
            index = lowered.index(home)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ''


def analyse_evidence(image_handler, case, evidence_id, progress=None,
                     should_stop=None):
    """Find every thumbnail cache on one image and record its pictures;
    replaces earlier rows and findings for it. Returns the picture count."""
    from trace_app.core import walk, winsearch
    caches, names, indexes = [], {}, []
    count = 0

    def note(offset, path, deleted, ref):
        # Every name on the volume, folders and empty files included: what
        # a cache's picture is of may be either.
        folder, _sep, name = path.rpartition('/')
        state = names.setdefault((offset, folder.lower()), {})
        lower = name.lower()
        # Present beats deleted: a name both allocated and in a deleted
        # entry (saved again) is there.
        if not deleted or lower not in state:
            state[lower] = (deleted, ref)

    for entry in walk.iter_files(image_handler, should_stop,
                                 every_name=note):
        count += 1
        if progress and count % 500 == 0:
            progress(count, 0, entry.path)
        if winsearch.is_index_path(entry.path) and entry.size and \
                not entry.deleted:
            indexes.append(entry)
        if is_cache_name(entry.name) and entry.size:
            caches.append(entry)

    rows, findings = [], []
    for done, cache in enumerate(caches, 1):
        if should_stop and should_stop():
            raise walk.WalkCancelled()
        if progress:
            progress(done, len(caches), cache.path)
        if cache.size > MAX_CACHE_BYTES:
            logger.info("%s is %s bytes; not read", cache.path, cache.size)
            continue
        try:
            data = cache.read(cache.size)
        except Exception as exc:
            logger.debug("Unreadable %s: %s", cache.path, exc)
            continue
        user = _user_of(cache.path)
        common = {'cache_ref': cache.ref, 'cache_path': cache.path,
                  'cache_deleted': 1 if cache.deleted else 0, 'user': user}
        try:
            if is_thumbcache(data[:8]):
                parsed = parse_thumbcache(data)
                for entry in parsed['entries']:
                    picture = data[entry['data_offset']:
                                   entry['data_offset'] + entry['data_size']]
                    rows.append(dict(
                        common, cache_kind='thumbcache',
                        cache_size=parsed['cache'],
                        system=parsed['system'], key=entry['hash'],
                        location=str(entry['data_offset']),
                        name='', original_state=None, original_ref=None,
                        modified_utc=None, width=entry['width'],
                        height=entry['height'], format=entry['format'],
                        size=entry['data_size'],
                        sha256=hashlib.sha256(picture).hexdigest(),
                        detail={'identifier': entry['identifier'],
                                'extension': entry['extension'],
                                'entry_offset': entry['offset']}))
            elif data[:8] == OLE_MAGIC:
                folder = cache.path.rsplit('/', 1)[0].lower()
                here = names.get((cache.offset, folder), {})
                for entry in parse_thumbs_db(data):
                    state, original_ref = None, None
                    if _FOLDER_PICTURE.fullmatch(entry['name'] or ''):
                        state = 'folder'
                    elif entry['name']:
                        found = here.get(entry['name'].lower())
                        if found is None:
                            state = 'absent'
                        else:
                            state = 'deleted' if found[0] else 'present'
                            original_ref = found[1]
                    rows.append(dict(
                        common, cache_kind='thumbs.db',
                        cache_size='', system='Windows XP' if entry['number']
                        is not None else 'Windows Vista or later',
                        key=entry['cache_id'] or str(entry['number'] or ''),
                        location=entry['stream'], name=entry['name'],
                        original_state=state, original_ref=original_ref,
                        modified_utc=entry['modified'], width=entry['width'],
                        height=entry['height'], format=entry['format'],
                        size=entry['size'],
                        sha256=hashlib.sha256(entry['data']).hexdigest()
                        if entry['data'] else None,
                        detail={'number': entry['number']}))
                    if state in ('absent', 'deleted'):
                        gone = 'is no longer in the folder' if \
                            state == 'absent' else \
                            'is in the folder only as a deleted entry'
                        picture = 'A picture of' if entry['format'] else \
                            'The name (no picture left) of'
                        findings.append((
                            cache.ref, entry['name'], cache.path, entry['size'],
                            f'thumbnail-{state}', 'notable',
                            f"{picture} {entry['name']}, which {gone}",
                            json.dumps({'stream': entry['stream'],
                                        'modified': entry['modified'],
                                        'original_ref': original_ref,
                                        'thumbs_db': cache.path},
                                       default=str)))
        except ThumbnailError as exc:
            logger.info("%s: %s", cache.path, exc)
        except Exception as exc:
            logger.warning("Could not read %s: %s", cache.path, exc)

    findings += _link_to_search_index(rows, indexes, names, progress)
    case.replace_thumbnails(evidence_id, rows)
    case.clear_findings(evidence_id, MODULE_THUMBNAILS)
    if findings:
        case.add_module_findings(evidence_id, MODULE_THUMBNAILS, findings)
    case.record_event(
        'thumbnail caches read',
        f"evidence id={evidence_id} caches={len(caches)} "
        f"pictures={len(rows)} of files gone={len(findings)}")
    return len(rows)


def _read_index(entry):
    """{cache id: item} from a Windows.edb (streamed) or Windows.db."""
    from trace_app.core import containers, winsearch
    if entry.name.lower().endswith('.edb'):
        handle = entry.fs.open_meta(inode=entry.inode)
        stream = containers.ByteWindow(
            lambda offset, length: handle.read_random(offset, length), 0,
            entry.size)
        return winsearch.cache_index(stream, 'edb')
    return winsearch.cache_index(entry.read(), 'db')


def _link_to_search_index(rows, indexes, names, progress=None):
    """Name the thumbcache pictures from the Windows Search index: the
    file each was made of, its times and size as indexed, and whether it is
    still on the disk. Returns findings for those that are not."""
    from trace_app.core import winsearch
    pictures = [r for r in rows if r['cache_kind'] == 'thumbcache']
    if not pictures or not indexes:
        return []
    found = {}
    for done, entry in enumerate(indexes, 1):
        if progress:
            progress(done, len(indexes), entry.path)
        try:
            for cache_id, item in _read_index(entry).items():
                found.setdefault(cache_id, (item, entry))
        except Exception as exc:
            logger.warning("Windows Search index %s unreadable: %s",
                           entry.path, exc)
    findings = []
    for row in pictures:
        match = found.get(row['key'])
        if match is None:
            continue
        item, index = match
        path = item['path']
        row['name'] = path.replace('\\', '/').rsplit('/', 1)[-1] or path
        row['detail'].update({
            'indexed path': path, 'indexed type': item['type'],
            'indexed size': item['size'],
            'indexed modified': times_text(item['datemodified']),
            'indexed created': times_text(item['datecreated']),
            'indexed on': times_text(item['search_gathertime']),
            'index': index.path})
        drive, volume_path = winsearch.volume_path(path)
        if drive != 'c' or volume_path is None:
            continue          # on another drive: its volume is not known
        folder, _sep, name = volume_path.rpartition('/')
        here = names.get((index.offset, folder.lower()), {})
        known = here.get(name.lower())
        if known is None:
            row['original_state'] = 'absent'
        else:
            row['original_state'] = 'deleted' if known[0] else 'present'
            row['original_ref'] = known[1]
        if row['original_state'] in ('absent', 'deleted'):
            gone = 'is no longer on the disk' if \
                row['original_state'] == 'absent' else \
                'is on the disk only as a deleted entry'
            findings.append((
                row['cache_ref'], row['name'], row['cache_path'], row['size'],
                f"thumbnail-{row['original_state']}", 'notable',
                f"A picture of {path}, which {gone}",
                json.dumps({'cache id': row['key'], 'indexed path': path,
                            'modified': row['detail']['indexed modified'],
                            'original_ref': row.get('original_ref'),
                            'thumbcache': row['cache_path']},
                           default=str)))
    return findings


def times_text(value):
    return value.strftime('%Y-%m-%d %H:%M:%S') if value else None


def picture_bytes(cache_data, row):
    """The picture a `thumbnails` row describes, from its cache's bytes."""
    if row['cache_kind'] == 'thumbcache':
        start = int(row['location'])
        return bytes(cache_data[start:start + int(row['size'] or 0)])
    return thumbs_db_picture(cache_data, row['location'])

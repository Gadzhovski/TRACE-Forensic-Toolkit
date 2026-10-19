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

* **RDP bitmap caches** (Cache????.bin, bcache*.bmc; core/rdpcache.py):
  tiles of remote sessions' screens, each tile a picture, plus a collage
  of them all in file order.

* **QuickLook** (macOS, /private/var/folders/.../C/
  com.apple.QuickLook.thumbnailcache): index.sqlite names each picture's
  file (folder, name, its date and size then) and where its raw RGBA
  bitmap lies in thumbnails.data; the bitmap is made a PNG when shown.

A Thumbs.db names the files whose pictures it holds, so each is looked up
in the folder it sits in: a picture of a file that is no longer there, or
is there only as a deleted entry, is a finding.

Nothing is extracted: the table records where each picture lies, and the
viewer reads it back from the cache file on the image. No Qt here.
"""

import hashlib
import io
import json
import logging
import re
import struct

from trace_app.core.timeconv import filetime_text

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

_filetime = filetime_text


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

#: macOS QuickLook's cache folder (/private/var/folders/.../C/...).
QUICKLOOK_FOLDER = 'com.apple.quicklook.thumbnailcache'
QUICKLOOK_DATA = 'thumbnails.data'


def is_cache_name(name):
    lower = (name or '').lower()
    return lower in THUMBS_DB_NAMES or lower == QUICKLOOK_DATA or (
        lower.startswith('thumbcache_') and lower.endswith('.db'))


def _is_quicklook(path):
    lower = path.lower()
    return lower.endswith('/' + QUICKLOOK_DATA) and QUICKLOOK_FOLDER in lower


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
    quicklook_indexes = {}          # (offset, QuickLook folder) -> index
    by_inode = []                   # QuickLook rows named only by inode
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
        lower = entry.name.lower()
        if (is_cache_name(entry.name) or _is_rdp_cache(entry.path)) and \
                entry.size and (lower != QUICKLOOK_DATA or
                                _is_quicklook(entry.path)):
            caches.append(entry)
        if lower == 'index.sqlite' and entry.size and \
                QUICKLOOK_FOLDER in entry.path.lower():
            folder = entry.path.rsplit('/', 1)[0].lower()
            quicklook_indexes[(entry.offset, folder)] = entry

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
            if _is_quicklook(cache.path):
                folder = cache.path.rsplit('/', 1)[0].lower()
                index = quicklook_indexes.get((cache.offset, folder))
                if index is not None:
                    found, gone = _quicklook_rows(
                        data, index.read(index.size), common, cache, names)
                    rows += found
                    findings += gone
                    if any(r['detail'].get('inode') for r in found):
                        by_inode.append(found)
            elif _is_rdp_cache(cache.path):
                rows += _rdp_rows(data, common)
            elif is_thumbcache(data[:8]):
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

    if by_inode:
        findings += _name_quicklook_inodes(image_handler, by_inode,
                                           should_stop)
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


def _is_rdp_cache(path):
    from trace_app.core import rdpcache
    name = path.rsplit('/', 1)[-1]
    if not rdpcache.is_rdp_cache_name(name):
        return False
    # A Cache0000.bin is only the RDP client's in its own folder.
    return name.lower().endswith('.bmc') or \
        'terminal server client' in path.lower()


def _rdp_rows(data, common):
    """thumbnails rows for an RDP bitmap cache: the collage first, then a
    row per tile."""
    from trace_app.core import rdpcache
    try:
        parsed = rdpcache.parse(data)
    except rdpcache.RdpCacheError:
        return []
    tiles = parsed['tiles']
    system = ('Remote Desktop, Windows 7 or later' if parsed['format'] ==
              'bin' else 'Remote Desktop, before Windows 7')
    shared = dict(common, cache_kind='rdp', cache_size='',
                  system=system, original_state=None, original_ref=None,
                  modified_utc=None, format='png')
    rows = []
    if tiles:
        rows.append(dict(
            shared, key='', location='collage',
            name=f"All {len(tiles):,} tiles, in the order stored",
            width=None, height=None, size=sum(len(t['bgrx']) for t in tiles),
            sha256=None, detail={'tiles': len(tiles),
                                 'compressed tiles': parsed['compressed']}))
    for number, tile in enumerate(tiles, 1):
        rows.append(dict(
            shared, key=tile['key'], location=f'tile:{number}',
            name=f"Tile {number}", width=tile['width'],
            height=tile['height'], size=len(tile['bgrx']),
            sha256=hashlib.sha256(tile['bgrx']).hexdigest(),
            detail={'offset': tile['offset']}))
    return rows


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


def _quicklook_rows(data, index_data, common, cache, names):
    """thumbnails rows (and findings) for a QuickLook cache.

    Two layouts of index.sqlite (as mac_apt reads them):

    * with a `files` table (to macOS 10.14): each picture's file by folder
      and name, its date and size then (the 'version' plist); RGBA;
    * `basic_files` (10.15+): the file by its inode only (fileId; the
      thumbnail's file_id has the top bit set), the row layout in a
      'bitmapFormat' plist from preference version 11; BGRA. Names come
      from the volume afterwards (`_name_quicklook_inodes`).

    A picture of a file no longer in its folder, or there only as a
    deleted entry, is a finding."""
    from trace_app.core.activity import sqlite_bytes
    try:
        with sqlite_bytes.open_database(index_data) as db:
            tables = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if 'files' in tables:
                entries = _quicklook_old(db)
            elif 'basic_files' in tables:
                entries = _quicklook_new(db, tables)
            else:
                entries = []
    except Exception as exc:
        logger.info("QuickLook index beside %s unreadable: %s", cache.path,
                    exc)
        return [], []
    rows, findings = [], []
    for entry in entries:
        location, length = entry['location'], entry['length']
        if location is None or not length or location + length > len(data):
            continue
        raw = data[location:location + length]
        row = dict(
            common, cache_kind='quicklook', cache_size='',
            system='macOS QuickLook', key=str(entry['key']),
            location=f"{location}:{length}:{entry['width']}:"
                     f"{entry['height']}:{entry['bpr']}:"
                     f"{'bgra' if entry['bgra'] else 'rgba'}",
            name=entry.get('name') or '', original_state=None,
            original_ref=None, modified_utc=entry.get('modified'),
            width=entry['width'], height=entry['height'], format='png',
            size=length, sha256=hashlib.sha256(raw).hexdigest(),
            detail={'original path': entry.get('original'),
                    'original size': entry.get('original_size'),
                    'inode': entry.get('inode'),
                    'hit count': entry['hits'],
                    'last shown': times_text(_cocoa(entry['last_hit']))})
        if entry.get('folder') is not None and row['name']:
            here = names.get((cache.offset,
                              entry['folder'].lower().rstrip('/') or '/'))
            if here is not None:
                found = here.get(row['name'].lower())
                if found is None:
                    row['original_state'] = 'absent'
                else:
                    row['original_state'] = ('deleted' if found[0]
                                             else 'present')
                    row['original_ref'] = found[1]
        rows.append(row)
        finding = _quicklook_finding(row, cache.ref, cache.path)
        if finding:
            findings.append(finding)
    return rows, findings


def _cocoa(value):
    from trace_app.core.activity import times as activity_times
    return activity_times.mac_absolute(value) if isinstance(
        value, (int, float)) else None


def _quicklook_old(db):
    """The largest thumbnail of each file, to macOS 10.14."""
    query = ("SELECT f.rowid AS key, f.folder AS folder, "
             "f.file_name AS name, f.version AS version, "
             "t.width AS width, t.height AS height, "
             "t.bytesperrow AS bpr, t.bitmapdata_location AS location, "
             "t.bitmapdata_length AS length, t.last_hit_date AS last_hit, "
             "t.hit_count AS hits, max(t.size) AS size FROM files f "
             "JOIN thumbnails t ON t.file_id = f.rowid "
             "WHERE t.size IS NOT NULL GROUP BY f.rowid")
    cursor = db.execute(query)
    columns = [c[0] for c in cursor.description]
    out = []
    for values in cursor.fetchall():
        entry = dict(zip(columns, values))
        folder = _quicklook_folder(entry['folder'])
        version = _quicklook_version(entry['version'])
        stamp = version.get('date')
        if isinstance(stamp, (int, float)):
            modified = times_text(_cocoa(stamp))
        elif hasattr(stamp, 'strftime'):
            modified = times_text(stamp)
        else:
            modified = None
        entry.update(
            folder=folder, bgra=False, modified=modified,
            original=f"{folder.rstrip('/')}/{entry['name'] or ''}",
            original_size=version.get('size'))
        out.append(entry)
    return out


def _quicklook_new(db, tables):
    """The largest thumbnail of each file, macOS 10.15 on (by inode)."""
    columns = {r[1].lower() for r in db.execute(
        "PRAGMA table_info(thumbnails)")}
    layout = ('t.bitmapFormat AS format' if 'bitmapformat' in columns
              else 't.bytesperrow AS bpr')
    query = (f"SELECT b.fileId AS inode, t.width AS width, "
             f"t.height AS height, {layout}, "
             f"t.bitmapdata_location AS location, "
             f"t.bitmapdata_length AS length, t.last_hit_date AS last_hit, "
             f"t.hit_count AS hits, max(t.size) AS size FROM thumbnails t "
             f"JOIN basic_files b "
             f"ON (b.fileId | -9223372036854775808) = t.file_id "
             f"WHERE b.fileId IS NOT NULL GROUP BY b.fileId")
    cursor = db.execute(query)
    names = [c[0] for c in cursor.description]
    out = []
    for values in cursor.fetchall():
        entry = dict(zip(names, values))
        if 'format' in entry:
            entry['bpr'] = _bitmap_format(entry.pop('format')).get('bpr')
        entry.update(key=entry['inode'], bgra=True, folder=None)
        out.append(entry)
    return out


def _bitmap_format(blob):
    """{'bpr', 'bpp', 'bpc'} from a thumbnail's bitmapFormat archive."""
    import plistlib
    try:
        objects = plistlib.loads(bytes(blob)).get('$objects') or []
    except Exception:
        return {}
    return next((o for o in objects if isinstance(o, dict) and 'bpr' in o),
                {})


def _quicklook_finding(row, cache_ref, cache_path):
    state = row['original_state']
    if state not in ('absent', 'deleted'):
        return None
    original = row['detail'].get('original path') or row['name']
    gone = ('is no longer in its folder' if state == 'absent'
            else 'is in its folder only as a deleted entry')
    return (cache_ref, row['name'], cache_path, row['size'],
            f'thumbnail-{state}', 'notable',
            f"A QuickLook picture of {original}, which {gone}",
            json.dumps({'original path': original,
                        'modified': row['modified_utc'],
                        'original_ref': row['original_ref'],
                        'quicklook': cache_path}, default=str))


def _name_quicklook_inodes(image_handler, groups, should_stop=None):
    """Name QuickLook rows that know their file only by inode (10.15+):
    one more walk of the volumes holding such caches, inode -> path. A
    file whose inode is not on the volume any more is 'absent' -- APFS
    does not reuse inode numbers -- and a finding."""
    from trace_app.core import walk
    from trace_app.core.case import parse_artifact_ref
    wanted = {}
    for rows in groups:
        for row in rows:
            offset = parse_artifact_ref(row['cache_ref']).get(
                'start_offset')
            if row['detail'].get('inode'):
                wanted.setdefault(offset, set()).add(
                    int(row['detail']['inode']))
    found = {}

    def note(offset, path, deleted, ref):
        inode = parse_artifact_ref(ref).get('inode')
        if inode in wanted.get(offset, ()):
            known = found.get((offset, inode))
            if known is None or (known[1] and not deleted):
                found[(offset, inode)] = (path, deleted, ref)

    for _entry in walk.iter_files(image_handler, should_stop,
                                  offsets=list(wanted), every_name=note):
        pass
    findings = []
    for rows in groups:
        for row in rows:
            inode = row['detail'].get('inode')
            if not inode:
                continue
            offset = parse_artifact_ref(row['cache_ref']).get(
                'start_offset')
            hit = found.get((offset, int(inode)))
            if hit is None:
                row['original_state'] = 'absent'
                row['name'] = f"inode {inode}"
            else:
                path, deleted, ref = hit
                row['name'] = path.rsplit('/', 1)[-1]
                row['detail']['original path'] = path
                row['original_state'] = 'deleted' if deleted else 'present'
                row['original_ref'] = ref
            finding = _quicklook_finding(row, row['cache_ref'],
                                         row['cache_path'])
            if finding:
                findings.append(finding)
    return findings


def _quicklook_folder(value):
    """index.sqlite's folder: a path, or a file:// URL on newer macOS."""
    from urllib.parse import unquote, urlparse
    text = value.decode('utf-8', 'replace') if isinstance(value, bytes) \
        else str(value or '')
    if text.startswith('file://'):
        text = unquote(urlparse(text).path)
    return text or '/'


def _quicklook_version(blob):
    """The 'version' plist of a QuickLook file row: the file's date
    (Cocoa seconds) and size when the thumbnail was made."""
    import plistlib
    if not blob:
        return {}
    try:
        value = plistlib.loads(bytes(blob))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def quicklook_span(location):
    """(offset, length) in thumbnails.data of a QuickLook row."""
    parts = location.split(':')
    return int(parts[0]), int(parts[1])


def quicklook_png(raw, location):
    """A QuickLook bitmap (`bytesperrow` bytes a row; RGBA before 10.15,
    BGRA after) as PNG, cropped to its width."""
    from PIL import Image
    parts = location.split(':')
    width, height, per_row = (int(p) if p not in ('', 'None') else 0
                              for p in parts[2:5])
    order = parts[5] if len(parts) > 5 else 'rgba'
    if not (width and height and per_row) or per_row * height > len(raw):
        raise ThumbnailError("QuickLook bitmap smaller than its size says")
    image = Image.frombuffer('RGBA', (per_row // 4, height), bytes(raw),
                             'raw', 'BGRA' if order == 'bgra' else 'RGBA',
                             per_row, 1)
    if per_row // 4 != width:
        image = image.crop((0, 0, min(width, per_row // 4), height))
    out = io.BytesIO()
    image.save(out, 'PNG')
    return out.getvalue()


def picture_bytes(cache_data, row):
    """The picture a `thumbnails` row describes, from its cache's bytes."""
    if row['cache_kind'] == 'quicklook':
        start, length = quicklook_span(row['location'])
        return quicklook_png(cache_data[start:start + length],
                             row['location'])
    if row['cache_kind'] == 'thumbcache':
        start = int(row['location'])
        return bytes(cache_data[start:start + int(row['size'] or 0)])
    if row['cache_kind'] == 'rdp':
        from trace_app.core import rdpcache
        return rdpcache.picture(cache_data, row['location'])
    return thumbs_db_picture(cache_data, row['location'])

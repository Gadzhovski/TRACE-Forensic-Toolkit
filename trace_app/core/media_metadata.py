"""What a video or audio file's container records about it (no Qt).

Pure Python, reading through `read(offset, length)` -- a file on the image,
a carve, bytes in memory -- and only the structures that hold metadata: a
4 GB video's sample data is skipped by its box and chunk sizes, never read.

* **ISO-BMFF / QuickTime** (MP4, MOV, M4A, M4V, 3GP): `mvhd` / `tkhd` /
  `mdhd` creation and modification times (seconds since 1904, UTC by the
  standard -- some cameras write local time, so it is labelled as
  recorded), duration, each track's handler, codec (`stsd`), frame size,
  rotation (the display matrix), sample count and frame rate (`stts`),
  language; `udta` text atoms (©mak ©mod ©swr ©day ©xyz ...), the iTunes
  `ilst`, and QuickTime `mdta` metadata (`keys` + `ilst`: Apple's
  com.apple.quicktime.make / model / software / creationdate -- with its
  zone -- / location.ISO6709, Android's com.android.version).
* **AVI** (RIFF): `avih` (frames, frame time, size), each stream's `strh`
  and `strf` (codec FourCC, rate, channels), `IDIT` (camera date), and the
  INFO list (ICRD, ISFT, IART, INAM, ICMT...).
* **Matroska / WebM** (EBML): Segment Info (DateUTC, Duration,
  MuxingApp, WritingApp, Title), Tracks (codec, size, rate, language),
  Tags; SeekHead followed to what sits after the clusters.

`read_metadata` returns a dict (see `_empty`) or None when the bytes are
none of these. `facts(meta)` gives (label, value) rows for display.
"""

import logging
import math
import re
import struct
from datetime import datetime, timedelta, timezone

logger = logging.getLogger('TRACE.MediaMetadata')

#: Largest box or chunk read whole for its metadata (moov of a long film
#: is a few MB; a sample table is skipped unless it is `stts`).
MAX_BOX_BYTES = 16 * 1024 * 1024
#: Boxes visited at most, so a crafted file cannot loop for ever.
MAX_BOXES = 20000
MAX_DEPTH = 12

_EPOCH_1904 = datetime(1904, 1, 1, tzinfo=timezone.utc)
_EPOCH_2001 = datetime(2001, 1, 1, tzinfo=timezone.utc)

#: Image brands: a HEIC/AVIF photo is ISO-BMFF too, but not a video.
_IMAGE_BRANDS = {b'heic', b'heix', b'hevc', b'heim', b'heis', b'hevm',
                 b'hevs', b'mif1', b'msf1', b'avif', b'avis', b'crx '}
_TOP_BOXES = {b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide',
              b'pnot', b'uuid'}

_XMP_UUID = bytes.fromhex('be7acfcb97a942e89c71999491e3afac')

_HANDLERS = {b'vide': 'video', b'soun': 'audio', b'text': 'text',
             b'sbtl': 'subtitle', b'subt': 'subtitle', b'tmcd': 'timecode',
             b'meta': 'metadata', b'hint': 'hint', b'clcp': 'captions'}

#: QuickTime / iTunes text atoms worth naming.
_ATOMS = {'©mak': 'make', '©mod': 'model', '©swr': 'software',
          '©too': 'encoder', '©enc': 'encoder', '©day': 'content date',
          '©xyz': 'location', '©nam': 'title', '©cmt': 'comment',
          '©ART': 'artist', '©alb': 'album', '©des': 'description',
          '©inf': 'information', '©req': 'requirements', '©fmt': 'format',
          '©src': 'source', '©prd': 'producer', '©dir': 'director',
          '©wrt': 'writer', '©aut': 'author', '©cpy': 'copyright',
          'cprt': 'copyright', 'desc': 'description', '©lyr': 'lyrics',
          '©gen': 'genre', '©grp': 'grouping', '©com': 'composer',
          'aART': 'album artist', 'covr': 'cover art', 'tmpo': 'tempo',
          'cpil': 'compilation', 'pgap': 'gapless', 'trkn': 'track',
          'disk': 'disc', '©key': 'keywords', 'keyw': 'keywords',
          'auth': 'author', 'titl': 'title', 'loci': 'location (3GPP)',
          'perf': 'performer', 'gnre': 'genre', 'albm': 'album',
          'yrrc': 'recording year'}

#: mdta keys mapped onto the common fields.
_KEYS = {'com.apple.quicktime.make': 'make',
         'com.apple.quicktime.model': 'model',
         'com.apple.quicktime.software': 'software',
         'com.apple.quicktime.creationdate': 'creation_date',
         'com.apple.quicktime.location.ISO6709': 'location',
         'com.apple.quicktime.location.iso6709': 'location',
         'com.android.version': 'software'}


def _empty(container):
    return {'container': container, 'brand': '', 'created': '',
            'modified': '', 'duration': None, 'tracks': [], 'make': '',
            'model': '', 'software': '', 'creation_date': '', 'title': '',
            'latitude': None, 'longitude': None, 'altitude': None,
            'location': '', 'tags': [], 'notes': []}


def kind(head):
    """'isobmff', 'avi', 'wav', 'matroska' -- or '' -- from a file's first bytes
    (a HEIC/AVIF picture is not a video: '')."""
    head = bytes(head[:64])
    if len(head) >= 12 and head[:4] == b'RIFF' and head[8:12] in (
            b'AVI ', b'AVIX'):
        return 'avi'
    if len(head) >= 12 and head[:4] == b'RIFF' and head[8:12] == b'WAVE':
        return 'wav'
    if head[:4] == b'\x1a\x45\xdf\xa3':
        return 'matroska'
    if len(head) >= 8 and head[4:8] in _TOP_BOXES:
        if head[4:8] == b'ftyp' and head[8:12] in _IMAGE_BRANDS:
            return ''
        size = struct.unpack('>I', head[:4])[0]
        if size in (0, 1) or size >= 8:
            return 'isobmff'
    return ''


def read_metadata(read, size, head=None):
    """The container's metadata (a dict as `_empty` makes), or None.
    `read(offset, length)` returns bytes (fewer at the end)."""
    try:
        head = head if head is not None else read(0, 64)
        which = kind(head)
        if which == 'isobmff':
            return _Mp4(read, size).run()
        if which in ('avi', 'wav'):
            return _Avi(read, size, which).run()
        if which == 'matroska':
            return _Matroska(read, size).run()
    except Exception as exc:
        logger.debug("Container metadata not read: %s", exc)
    return None


def from_bytes(data):
    """read_metadata over bytes in memory."""
    data = bytes(data)
    return read_metadata(lambda offset, length:
                         data[offset:offset + length], len(data))


# --- shared ----------------------------------------------------------------

def _mac_time(seconds):
    """1904-based seconds as 'YYYY-MM-DD HH:MM:SS' (UTC), '' for 0."""
    if not seconds:
        return ''
    try:
        return (_EPOCH_1904 + timedelta(seconds=seconds)).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (OverflowError, ValueError):
        return ''


def parse_iso6709(text):
    """(latitude, longitude, altitude or None) from an ISO 6709 string
    ('+37.3318-122.0312+012.345/', '+4851.25+00220.75/'), or None."""
    match = re.match(r'\s*([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)'
                     r'([+-]\d+(?:\.\d+)?)?', text or '')
    if not match:
        return None
    latitude = _iso_degrees(match.group(1), 2)
    longitude = _iso_degrees(match.group(2), 3)
    if latitude is None or longitude is None or \
            not (-90 <= latitude <= 90 and -180 <= longitude <= 180) or \
            (latitude, longitude) == (0.0, 0.0):
        return None
    altitude = float(match.group(3)) if match.group(3) else None
    return round(latitude, 6), round(longitude, 6), altitude


def _iso_degrees(text, degree_digits):
    """One ISO 6709 coordinate: ±DD[.D], ±DDMM[.M] or ±DDMMSS[.S] (three
    degree digits for longitude)."""
    sign = -1 if text[0] == '-' else 1
    whole, _, fraction = text[1:].partition('.')
    fraction = float('0.' + fraction) if fraction else 0.0
    digits = len(whole)
    try:
        if digits == degree_digits:
            value = int(whole) + fraction
        elif digits == degree_digits + 2:
            value = int(whole[:degree_digits]) + \
                (int(whole[degree_digits:]) + fraction) / 60
        elif digits == degree_digits + 4:
            value = int(whole[:degree_digits]) + \
                int(whole[degree_digits:degree_digits + 2]) / 60 + \
                (int(whole[degree_digits + 2:]) + fraction) / 3600
        else:
            return None
    except ValueError:
        return None
    return sign * value


def _text(raw):
    raw = bytes(raw).split(b'\0', 1)[0] if b'\0' in bytes(raw)[:-1] \
        else bytes(raw).rstrip(b'\0')
    for codec in ('utf-8', 'mac_roman'):
        try:
            return raw.decode(codec).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1').strip()


#: XMP properties worth naming (local names); an editor's CreatorTool and
#: History are where an edit says what made it.
_XMP_NAMES = {'CreatorTool': 'Creator tool (XMP)',
              'CreateDate': 'Create date (XMP)',
              'ModifyDate': 'Modify date (XMP)',
              'MetadataDate': 'Metadata date (XMP)',
              'creator': 'Creator (XMP)', 'title': 'Title (XMP)',
              'description': 'Description (XMP)',
              'softwareAgent': 'Edited with (XMP history)',
              'Make': 'Make (XMP)', 'Model': 'Model (XMP)',
              'DateTimeOriginal': 'Date taken (XMP)',
              'GPSLatitude': 'GPS latitude (XMP)',
              'GPSLongitude': 'GPS longitude (XMP)',
              'altTapeName': 'Tape name (XMP)',
              'album': 'Album (XMP)', 'xmptk': 'XMP toolkit'}


def _xmp(meta, data):
    """Add an XMP packet's telling properties to `meta`'s tags."""
    from xml.etree import ElementTree
    text = bytes(data[:1024 * 1024]).decode('utf-8', 'replace')
    start = text.find('<x:xmpmeta')
    end_tag = '</x:xmpmeta>'
    if start < 0:
        start, end_tag = text.find('<rdf:RDF'), '</rdf:RDF>'
    end = text.find(end_tag, start) if start >= 0 else -1
    if end < 0:
        return
    try:
        root = ElementTree.fromstring(text[start:end + len(end_tag)])
    except ElementTree.ParseError:
        return
    seen = set()

    def add(local, value):
        value = (value or '').strip()
        label = _XMP_NAMES.get(local)
        if label and value and (label, value) not in seen:
            seen.add((label, value))
            meta['tags'].append((label, value[:2000]))
            if local == 'CreatorTool' and not meta['software']:
                meta['software'] = value

    for element in root.iter():
        local = element.tag.rsplit('}', 1)[-1]
        for attribute, value in element.attrib.items():
            add(attribute.rsplit('}', 1)[-1], value)
        if len(element) == 0:
            if not element.tag.endswith('}li'):
                add(local, element.text)
        elif local in ('creator', 'title', 'description'):
            # dc:creator / dc:title hold an rdf:Seq / rdf:Alt of rdf:li.
            items = [item.text.strip() for item in element.iter()
                     if item.tag.endswith('}li') and len(item) == 0
                     and item.text]
            if items:
                add(local, '; '.join(items))


def _place(meta):
    """Fill latitude/longitude from `location` when it parses."""
    if meta['latitude'] is None and meta['location']:
        where = parse_iso6709(meta['location'])
        if where:
            meta['latitude'], meta['longitude'], meta['altitude'] = where


# --- ISO-BMFF / QuickTime ----------------------------------------------------

class _Mp4:
    _CONTAINERS = {b'moov', b'trak', b'mdia', b'minf', b'stbl', b'udta',
                   b'edts', b'dinf', b'tref', b'mvex', b'moof', b'traf'}

    def __init__(self, read, size):
        self.read = read
        self.size = size
        self.meta = _empty('MP4')
        self.boxes = 0
        self.track = None

    def run(self):
        self._walk(0, self.size, 0, top=True)
        meta = self.meta
        _place(meta)
        if meta['brand'] in ('qt', 'moov', ''):
            meta['container'] = 'QuickTime'
        elif meta['brand'].startswith('3g'):
            meta['container'] = '3GPP'
        elif meta['brand'].startswith('M4A'):
            meta['container'] = 'MPEG-4 audio'
        return meta

    def _headers(self, start, end):
        """(type, body start, box end) of each box in [start, end)."""
        position = start
        while position + 8 <= end:
            self.boxes += 1
            if self.boxes > MAX_BOXES:
                return
            header = self.read(position, 16)
            if len(header) < 8:
                return
            size, kind = struct.unpack('>I4s', header[:8])
            body = position + 8
            if size == 1:
                if len(header) < 16:
                    return
                size = struct.unpack('>Q', header[8:16])[0]
                body = position + 16
            elif size == 0:
                size = end - position
            if size < body - position or position + size > end + 8:
                # A cut file: the last box runs past the end.
                if position + size > end and size >= body - position:
                    size = end - position
                else:
                    return
            yield kind, body, position + size
            position += size

    def _walk(self, start, end, depth, top=False):
        if depth > MAX_DEPTH:
            return
        for kind, body, box_end in self._headers(start, end):
            if top and kind == b'ftyp':
                data = self.read(body, min(64, box_end - body))
                self.meta['brand'] = data[:4].decode('latin-1').strip()
            elif kind in self._CONTAINERS:
                if kind == b'trak':
                    self.track = {'kind': '', 'codec': ''}
                    self._walk(body, box_end, depth + 1)
                    if self.track.get('kind') or self.track.get('codec'):
                        self.meta['tracks'].append(self.track)
                    self.track = None
                elif kind == b'udta':
                    self._udta(body, box_end, depth + 1)
                else:
                    self._walk(body, box_end, depth + 1)
            elif kind == b'meta':
                self._meta(body, box_end, depth + 1)
            elif kind == b'uuid' and box_end - body <= 1024 * 1024:
                data = self.read(body, box_end - body)
                if data[:16] == _XMP_UUID:
                    _xmp(self.meta, data[16:])
            elif kind in (b'mvhd', b'tkhd', b'mdhd', b'hdlr', b'stsd',
                          b'stts'):
                if box_end - body > MAX_BOX_BYTES:
                    continue
                data = self.read(body, box_end - body)
                getattr(self, '_' + kind.decode())(data)

    # Leaf boxes.

    def _mvhd(self, data):
        version = data[0]
        if version == 1:
            created, modified, scale, duration = struct.unpack_from(
                '>QQIQ', data, 4)
        else:
            created, modified, scale, duration = struct.unpack_from(
                '>IIII', data, 4)
        self.meta['created'] = _mac_time(created)
        self.meta['modified'] = _mac_time(modified)
        if scale and duration not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            self.meta['duration'] = duration / scale

    def _tkhd(self, data):
        if self.track is None:
            return
        version = data[0]
        if version == 1:
            created, modified, track_id = struct.unpack_from('>QQI', data, 4)
            matrix_at = 4 + 8 + 8 + 4 + 4 + 8 + 8 + 2 + 2 + 2 + 2
        else:
            created, modified, track_id = struct.unpack_from('>III', data, 4)
            matrix_at = 4 + 4 + 4 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2
        self.track['id'] = track_id
        self.track['created'] = _mac_time(created)
        self.track['modified'] = _mac_time(modified)
        if len(data) >= matrix_at + 44:
            a, b = struct.unpack_from('>ii', data, matrix_at)
            angle = round(math.degrees(math.atan2(b / 65536, a / 65536)))
            self.track['rotation'] = angle % 360
            width, height = struct.unpack_from('>II', data, matrix_at + 36)
            if width or height:
                self.track['display_size'] = (width >> 16, height >> 16)

    def _mdhd(self, data):
        if self.track is None:
            return
        version = data[0]
        if version == 1:
            _c, _m, scale, duration = struct.unpack_from('>QQIQ', data, 4)
            language_at = 4 + 28
        else:
            _c, _m, scale, duration = struct.unpack_from('>IIII', data, 4)
            language_at = 4 + 16
        self.track['timescale'] = scale
        if scale and duration not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            self.track['duration'] = duration / scale
        if len(data) >= language_at + 2:
            packed = struct.unpack_from('>H', data, language_at)[0]
            if packed and packed < 0x400:
                return                       # a Macintosh language code
            letters = ''.join(chr(((packed >> shift) & 31) + 0x60)
                              for shift in (10, 5, 0))
            if letters.isalpha() and letters != 'und':
                self.track['language'] = letters

    def _hdlr(self, data):
        if self.track is None or len(data) < 12:
            return
        handler = data[8:12]
        if handler in _HANDLERS and not self.track.get('kind'):
            self.track['kind'] = _HANDLERS[handler]

    def _stsd(self, data):
        if self.track is None or len(data) < 16:
            return
        entry = data[8:]
        if len(entry) < 16:
            return
        codec = entry[4:8].decode('latin-1')
        self.track['codec'] = codec.strip() or codec
        kind = self.track.get('kind')
        if kind == 'video' and len(entry) >= 36:
            width, height = struct.unpack_from('>HH', entry, 32)
            self.track['width'], self.track['height'] = width, height
            if len(entry) >= 82:
                name = entry[50:82]
                length = name[0]
                if 0 < length < 32:
                    self.track['compressor'] = _text(name[1:1 + length])
        elif kind == 'audio' and len(entry) >= 36:
            channels, bits = struct.unpack_from('>HH', entry, 24)
            rate = struct.unpack_from('>I', entry, 32)[0] >> 16
            self.track['channels'] = channels
            self.track['sample_bits'] = bits
            if rate:
                self.track['sample_rate'] = rate

    def _stts(self, data):
        if self.track is None or len(data) < 8:
            return
        count = struct.unpack_from('>I', data, 4)[0]
        count = min(count, (len(data) - 8) // 8)
        samples = total = 0
        for index in range(count):
            number, delta = struct.unpack_from('>II', data, 8 + index * 8)
            samples += number
            total += number * delta
        self.track['samples'] = samples
        scale = self.track.get('timescale')
        if self.track.get('kind') == 'video' and scale and total:
            self.track['frame_rate'] = round(samples * scale / total, 3)

    # Metadata.

    def _udta(self, start, end, depth):
        for kind, body, box_end in self._headers(start, end):
            if kind == b'meta':
                self._meta(body, box_end, depth + 1)
                continue
            name = kind.decode('mac_roman', 'replace')
            if box_end - body > 1024 * 1024:
                continue
            if kind == b'XMP_':
                _xmp(self.meta, self.read(body, box_end - body))
                continue
            if not (name in _ATOMS or kind[:1] == b'\xa9'):
                continue
            data = self.read(body, box_end - body)
            value = self._atom_text(data)
            if value:
                self._set(_ATOMS.get(name), name, value)

    def _atom_text(self, data):
        """A QuickTime text atom (2-byte length, 2-byte language, text),
        or an iTunes-style one holding a 'data' box."""
        if len(data) >= 16 and data[4:8] == b'data':
            return self._data_value(data[8:struct.unpack('>I', data[:4])[0]])
        if len(data) >= 4:
            length = struct.unpack('>H', data[:2])[0]
            if 0 < length <= len(data) - 4:
                return _text(data[4:4 + length])
        return _text(data) if data else ''

    def _data_value(self, body):
        """The value of a 'data' box's body (type, locale, value)."""
        if len(body) < 8:
            return ''
        type_code = struct.unpack('>I', body[:4])[0] & 0xFFFFFF
        value = body[8:]
        if type_code in (1, 4):
            return _text(value)
        if type_code in (2, 5):
            return value.decode('utf-16-be', 'replace').strip('\0 ')
        if type_code == 23 and len(value) == 4:
            return f"{struct.unpack('>f', value)[0]:g}"
        if type_code == 24 and len(value) == 8:
            return f"{struct.unpack('>d', value)[0]:g}"
        if type_code in (21, 22, 65, 66, 67, 74, 75, 76, 77, 78) and \
                len(value) in (1, 2, 4, 8):
            signed = type_code in (21, 65, 66, 67, 74)
            return str(int.from_bytes(value, 'big', signed=signed))
        if type_code in (13, 14, 27):
            return f"(picture, {len(value):,} bytes)"
        return ''

    def _meta(self, start, end, depth):
        """A 'meta' box: a full box in MP4 (4 bytes of version/flags
        first), a plain one in QuickTime."""
        if depth > MAX_DEPTH:
            return
        probe = self.read(start, 8)
        if len(probe) >= 8 and probe[:4] == b'\0\0\0\0' and \
                probe[4:8] not in (b'hdlr', b'keys', b'ilst'):
            start += 4
        keys = []
        for kind, body, box_end in self._headers(start, end):
            if kind == b'keys' and box_end - body <= MAX_BOX_BYTES:
                keys = self._keys(self.read(body, box_end - body))
            elif kind == b'ilst' and box_end - body <= MAX_BOX_BYTES:
                self._ilst(body, box_end, keys)

    def _keys(self, data):
        count = struct.unpack_from('>I', data, 4)[0] if len(data) >= 8 \
            else 0
        keys, position = [], 8
        for _index in range(min(count, 4096)):
            if position + 8 > len(data):
                break
            size = struct.unpack_from('>I', data, position)[0]
            if size < 8:
                break
            keys.append(_text(data[position + 8:position + size]))
            position += size
        return keys

    def _ilst(self, start, end, keys):
        for kind, body, box_end in self._headers(start, end):
            if box_end - body > 1024 * 1024:
                continue
            index = struct.unpack('>I', kind)[0]
            if keys and 1 <= index <= len(keys):
                name = keys[index - 1]
            else:
                name = kind.decode('mac_roman', 'replace')
            data = self.read(body, box_end - body)
            value = ''
            for child, child_body, child_end in _boxes_in(data):
                if child == b'name' and kind == b'----':
                    # iTunes' freeform atom: mean, name, data.
                    name = _text(data[child_body + 4:child_end])
                elif child == b'data' and not value:
                    value = self._data_value(data[child_body:child_end])
            if value:
                self._set(_KEYS.get(name) or _ATOMS.get(name), name, value)

    def _set(self, field, name, value):
        value = value[:2000]
        meta = self.meta
        if field in ('make', 'model', 'software', 'creation_date', 'title',
                     'location') and not meta[field]:
            meta[field] = value
        elif field == 'encoder' and not meta['software']:
            meta['software'] = value
        meta['tags'].append((_label(name), value))


def _boxes_in(data):
    """(type, body start, end) of the boxes in bytes."""
    position = 0
    while position + 8 <= len(data):
        size, kind = struct.unpack_from('>I4s', data, position)
        if size < 8 or position + size > len(data):
            if size >= 8:
                yield kind, position + 8, len(data)
            return
        yield kind, position + 8, position + size
        position += size


def _label(name):
    """A tag's name for display: 'com.apple.quicktime.make' -> 'make
    (com.apple.quicktime)'; '©ART' -> 'Artist (©ART)'; others as
    written."""
    if name in _ATOMS:
        word = _ATOMS[name]
        return f"{word[0].upper()}{word[1:]} ({name})"
    if '.' in name and name.count('.') >= 2:
        prefix, _, last = name.rpartition('.')
        if prefix.endswith('.location'):
            prefix, _, place = prefix.rpartition('.')
            last = f"{place}.{last}"
        return f"{last} ({prefix})"
    return name


# --- AVI -------------------------------------------------------------------

_INFO = {'ICRD': 'Created', 'ISFT': 'Software', 'IART': 'Artist',
         'INAM': 'Title', 'ICMT': 'Comment', 'ICOP': 'Copyright',
         'IENG': 'Engineer', 'ITCH': 'Technician', 'ISRC': 'Source',
         'IPRD': 'Product', 'ISBJ': 'Subject', 'IKEY': 'Keywords',
         'IMED': 'Medium', 'IDIT': 'Recorded', 'ISMP': 'Timecode',
         'IGNR': 'Genre', 'ILNG': 'Language', 'ICNT': 'Country',
         'IARL': 'Archival location'}

#: Chunks digital cameras (Pentax, Canon) write into AVI and WAV files.
_CAMERA_CHUNKS = {'ecor': 'Make', 'emdl': 'Camera model', 'etim': 'Time',
                  'erel': 'Related image', 'ever': 'EXIF version',
                  'edat': 'Date', 'emnt': 'Maker notes', 'eucm': 'Comment'}

_WAVE_FORMATS = {1: 'PCM', 2: 'MS ADPCM', 3: 'IEEE float', 6: 'A-law',
                 7: 'µ-law', 0x11: 'IMA ADPCM', 0x55: 'MP3', 0x2000: 'AC-3',
                 0x50: 'MPEG audio', 0xFF: 'AAC', 0x161: 'WMA'}


class _Avi:
    def __init__(self, read, size, which='avi'):
        self.read = read
        self.size = size
        self.meta = _empty('AVI' if which == 'avi' else 'WAV')
        self.chunks = 0
        self.frame_time = None
        self.byte_rate = None
        self.camera = {}

    def run(self):
        # To the file's end, not the RIFF header's size: an edited or cut
        # file's header can be short of its chunks (exiftool's RIFF.wav),
        # and an OpenDML AVI continues in RIFF 'AVIX' chunks after it.
        self._list(12, self.size, 0)
        meta = self.meta
        for track in meta['tracks']:
            if track.get('kind') == 'video' and 'frame_rate' not in track \
                    and self.frame_time:
                track['frame_rate'] = round(1e6 / self.frame_time, 3)
        # A Pentax / Canon camera's own chunks: ICRD holds the date, etim
        # the time.
        if self.camera.get('etim') and meta['creation_date'] and \
                ':' not in meta['creation_date'].replace(':', '', 2):
            meta['creation_date'] += ' ' + self.camera['etim']
        return meta

    def _chunks(self, start, end):
        position = start
        while position + 8 <= end:
            self.chunks += 1
            if self.chunks > MAX_BOXES:
                return
            header = self.read(position, 12)
            if len(header) < 8:
                return
            fourcc, size = struct.unpack('<4sI', header[:8])
            yield fourcc, position + 8, min(end, position + 8 + size), \
                header[8:12]
            position += 8 + size + (size & 1)

    def _list(self, start, end, depth):
        if depth > MAX_DEPTH:
            return
        for fourcc, body, chunk_end, list_type in self._chunks(start, end):
            if fourcc == b'LIST':
                if list_type == b'movi':
                    continue                   # the frames themselves
                if list_type == b'strl':
                    self.meta['tracks'].append({'kind': '', 'codec': ''})
                self._list(body + 4, chunk_end, depth + 1)
                continue
            if fourcc == b'data':
                # A WAV's samples: their length is the duration.
                if self.byte_rate:
                    self.meta['duration'] = (chunk_end - body) / \
                        self.byte_rate
                continue
            if chunk_end - body > 1024 * 1024:
                continue
            name = fourcc.decode('latin-1')
            data = self.read(body, chunk_end - body)
            if fourcc == b'_PMX':
                _xmp(self.meta, data)
                continue
            if name in _CAMERA_CHUNKS:
                value = _text(data) if name != 'emnt' else \
                    f"(binary, {len(data):,} bytes)"
                if value:
                    self.camera[name] = value
                    self.meta['tags'].append((_CAMERA_CHUNKS[name], value))
                    field = {'ecor': 'make', 'emdl': 'model'}.get(name)
                    if field and not self.meta[field]:
                        self.meta[field] = value
                continue
            if fourcc == b'fmt ' and len(data) >= 16:
                tag, channels, rate, byte_rate, _align, bits = \
                    struct.unpack_from('<HHIIHH', data)
                self.byte_rate = byte_rate or None
                self.meta['tracks'].append({
                    'kind': 'audio', 'codec': _WAVE_FORMATS.get(
                        tag, f"0x{tag:04X}"), 'channels': channels,
                    'sample_rate': rate, 'sample_bits': bits})
                continue
            if fourcc == b'avih' and len(data) >= 40:
                (frame_time, _rate, _pad, _flags, frames, _initial,
                 _streams, _buffer, width, height) = struct.unpack_from(
                    '<10I', data)
                self.frame_time = frame_time or None
                if frame_time and frames:
                    self.meta['duration'] = frames * frame_time / 1e6
                self.meta['frames'] = frames
                self.meta['size'] = (width, height)
            elif fourcc == b'strh' and len(data) >= 36 and \
                    self.meta['tracks']:
                track = self.meta['tracks'][-1]
                kind = {b'vids': 'video', b'auds': 'audio',
                        b'txts': 'text', b'mids': 'midi'}.get(data[:4], '')
                track['kind'] = kind
                handler = data[4:8].decode('latin-1').strip('\0 ')
                if handler:
                    track['codec'] = handler
                scale, rate = struct.unpack_from('<II', data, 20)
                length = struct.unpack_from('<I', data, 32)[0]
                if scale and rate and kind == 'video':
                    track['frame_rate'] = round(rate / scale, 3)
                    track['samples'] = length
                    track['duration'] = length * scale / rate
            elif fourcc == b'strf' and self.meta['tracks']:
                track = self.meta['tracks'][-1]
                if track.get('kind') == 'video' and len(data) >= 20:
                    width, height = struct.unpack_from('<ii', data, 4)
                    track['width'], track['height'] = width, abs(height)
                    compression = data[16:20]
                    if compression.strip(b'\0'):
                        track['codec'] = compression.decode(
                            'latin-1').strip('\0 ')
                elif track.get('kind') == 'audio' and len(data) >= 16:
                    tag, channels, rate = struct.unpack_from('<HHI', data)
                    track['codec'] = _WAVE_FORMATS.get(tag, f"0x{tag:04X}")
                    track['channels'] = channels
                    track['sample_rate'] = rate
            elif name in _INFO:
                value = _text(data)
                if value:
                    self.meta['tags'].append((_INFO[name], value))
                    if name in ('ICRD', 'IDIT') and \
                            not self.meta['creation_date']:
                        self.meta['creation_date'] = _avi_date(value)
                    elif name == 'ISFT' and not self.meta['software']:
                        self.meta['software'] = value
                    elif name == 'INAM' and not self.meta['title']:
                        self.meta['title'] = value


# --- Matroska / WebM -----------------------------------------------------------

_SEGMENT, _SEEKHEAD, _INFO_ID, _TRACKS, _TAGS, _CLUSTER, _CUES = (
    0x18538067, 0x114D9B74, 0x1549A966, 0x1654AE6B, 0x1254C367,
    0x1F43B675, 0x1C53BB6B)
_MASTERS = {0x4DBB, 0xAE, 0xE0, 0xE1, 0x7373, 0x67C8, 0x63C0}
_CODEC_TRACK = {1: 'video', 2: 'audio', 3: 'complex', 16: 'logo',
                17: 'subtitle', 18: 'buttons', 32: 'control',
                33: 'metadata'}


def _vint(data, position, keep_marker):
    if position >= len(data):
        return None, position
    first = data[position]
    length = 1
    mask = 0x80
    while length <= 8 and not first & mask:
        mask >>= 1
        length += 1
    if length > 8 or position + length > len(data):
        return None, position
    value = first if keep_marker else first & (mask - 1)
    for byte in data[position + 1:position + length]:
        value = (value << 8) | byte
    if not keep_marker and value == (1 << (7 * length)) - 1:
        value = -1                                  # unknown size
    return value, position + length


class _Matroska:
    def __init__(self, read, size):
        self.read = read
        self.size = size
        self.meta = _empty('Matroska')
        self.scale = 1_000_000
        self.duration = None
        self.elements = 0
        self.done = set()

    def _element(self, position):
        """(id, data start, data end or None for unknown) at `position`."""
        header = self.read(position, 12)
        element, after = _vint(header, 0, True)
        size, after = _vint(header, after, False) if element is not None \
            else (None, after)
        if element is None or size is None:
            return None
        start = position + after
        return element, start, (None if size < 0 else start + size)

    def run(self):
        first = self._element(0)
        if first is None:
            return self.meta
        _id, start, end = first
        header = self.read(start, min(256, (end or start + 256) - start))
        for element, value in self._children(header):
            if element == 0x4282:
                doc = _text(value)
                self.meta['container'] = 'WebM' if doc == 'webm' else \
                    'Matroska'
        segment = self._element(end or 0)
        if segment is None or segment[0] != _SEGMENT:
            return self.meta
        _id, base, segment_end = segment
        segment_end = segment_end or self.size
        seeks = {}
        position = base
        while position < segment_end:
            self.elements += 1
            if self.elements > MAX_BOXES:
                break
            element = self._element(position)
            if element is None:
                break
            element_id, start, end = element
            if element_id == _CLUSTER:
                # The frames: what is left to read sits where the
                # SeekHead says.
                break
            if end is None:
                break
            self._top(element_id, start, end, seeks, base)
            position = end
        for element_id, offset in seeks.items():
            if element_id in self.done:
                continue
            element = self._element(base + offset)
            if element and element[0] == element_id and element[2]:
                self._top(element_id, element[1], element[2], {}, base)
        if self.duration is not None:
            self.meta['duration'] = self.duration * self.scale / 1e9
        return self.meta

    def _top(self, element_id, start, end, seeks, base):
        if element_id not in (_SEEKHEAD, _INFO_ID, _TRACKS, _TAGS) or \
                end - start > MAX_BOX_BYTES:
            return
        self.done.add(element_id)
        data = self.read(start, end - start)
        if element_id == _SEEKHEAD:
            for element, value in self._children(data):
                if element != 0x4DBB:
                    continue
                target = offset = None
                for child, child_value in self._children(value):
                    if child == 0x53AB:
                        target, _ = _vint(child_value, 0, True)
                    elif child == 0x53AC:
                        offset = int.from_bytes(child_value, 'big')
                if target is not None and offset is not None:
                    seeks.setdefault(target, offset)
        elif element_id == _INFO_ID:
            self._info(data)
        elif element_id == _TRACKS:
            for element, value in self._children(data):
                if element == 0xAE:
                    self._track(value)
        elif element_id == _TAGS:
            self._tags(data)

    def _children(self, data):
        position = 0
        while position < len(data):
            element, after = _vint(data, position, True)
            if element is None:
                return
            size, after = _vint(data, after, False)
            if size is None or size < 0:
                return
            yield element, data[after:after + size]
            position = after + size

    def _info(self, data):
        meta = self.meta
        for element, value in self._children(data):
            if element == 0x2AD7B1:
                self.scale = int.from_bytes(value, 'big') or 1_000_000
            elif element == 0x4489:
                self.duration = _float(value)
            elif element == 0x4461 and len(value) == 8:
                nanoseconds = int.from_bytes(value, 'big', signed=True)
                when = _EPOCH_2001 + timedelta(microseconds=nanoseconds
                                               // 1000)
                meta['created'] = when.strftime('%Y-%m-%d %H:%M:%S')
            elif element == 0x7BA9:
                meta['title'] = _text(value)
                meta['tags'].append(('Title', meta['title']))
            elif element == 0x4D80:
                meta['tags'].append(('Muxing application', _text(value)))
            elif element == 0x5741:
                meta['software'] = _text(value)
                meta['tags'].append(('Writing application', meta['software']))

    def _track(self, data):
        track = {'kind': '', 'codec': ''}
        frame_ns = None
        for element, value in self._children(data):
            if element == 0x83:
                track['kind'] = _CODEC_TRACK.get(int.from_bytes(value,
                                                                'big'), '')
            elif element == 0x86:
                track['codec'] = _text(value)
            elif element == 0x22B59C:
                language = _text(value)
                if language and language != 'und':
                    track['language'] = language
            elif element == 0x536E:
                track['name'] = _text(value)
            elif element == 0x23E383:
                nanoseconds = int.from_bytes(value, 'big')
                if nanoseconds:
                    frame_ns = nanoseconds
            elif element == 0xE0:
                for child, child_value in self._children(value):
                    if child == 0xB0:
                        track['width'] = int.from_bytes(child_value, 'big')
                    elif child == 0xBA:
                        track['height'] = int.from_bytes(child_value, 'big')
            elif element == 0xE1:
                for child, child_value in self._children(value):
                    if child == 0xB5:
                        rate = _float(child_value)
                        if rate:
                            track['sample_rate'] = round(rate)
                    elif child == 0x9F:
                        track['channels'] = int.from_bytes(child_value,
                                                           'big')
        if frame_ns and track['kind'] == 'video':
            # An audio track's default duration is a block's, not a frame.
            track['frame_rate'] = round(1e9 / frame_ns, 3)
        self.meta['tracks'].append(track)

    def _tags(self, data):
        for element, value in self._children(data):
            if element != 0x7373:
                continue
            for child, child_value in self._children(value):
                if child == 0x67C8:
                    self._simple_tag(child_value)

    def _simple_tag(self, data):
        name = text = ''
        for element, value in self._children(data):
            if element == 0x45A3:
                name = _text(value)
            elif element == 0x4487:
                text = _text(value)
            elif element == 0x67C8:
                self._simple_tag(value)
        if name and text:
            self.meta['tags'].append((name, text[:2000]))
            upper = name.upper()
            if upper in ('DATE_RECORDED', 'DATE_ENCODED', 'CREATION_TIME') \
                    and not self.meta['creation_date']:
                self.meta['creation_date'] = text
            elif upper in ('ENCODER', 'ENCODED_BY') and \
                    not self.meta['software']:
                self.meta['software'] = text
            elif upper in ('LOCATION', 'RECORDING_LOCATION'):
                self.meta['location'] = text
                _place(self.meta)


def _float(value):
    if len(value) == 4:
        return struct.unpack('>f', value)[0]
    if len(value) == 8:
        return struct.unpack('>d', value)[0]
    return None


# --- for display -------------------------------------------------------------

def duration_text(seconds):
    if seconds is None:
        return ''
    seconds = max(0.0, seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, rest = divmod(rest, 60)
    return (f"{int(hours)}:{int(minutes):02d}:{rest:06.3f}" if hours
            else f"{int(minutes)}:{rest:06.3f}")


def track_text(track):
    """One line about a track: 'video avc1 1920 × 1080, 29.97 fps,
    rotated 90°'."""
    parts = [track.get('kind') or 'track']
    if track.get('codec'):
        parts.append(track['codec'])
    text = ' '.join(parts)
    details = []
    if track.get('width') and track.get('height'):
        details.append(f"{track['width']} × {track['height']}")
    if track.get('frame_rate'):
        details.append(f"{track['frame_rate']:g} fps")
    if track.get('samples') and track.get('kind') == 'video':
        details.append(f"{track['samples']:,} frames")
    if track.get('rotation'):
        details.append(f"rotated {track['rotation']}°")
    if track.get('sample_rate'):
        details.append(f"{track['sample_rate']:,} Hz")
    if track.get('channels'):
        details.append(f"{track['channels']} channel"
                       f"{'s' if track['channels'] != 1 else ''}")
    if track.get('language'):
        details.append(track['language'])
    if track.get('duration'):
        details.append(duration_text(track['duration']))
    return text + (', ' + ', '.join(details) if details else '')


def facts(meta):
    """[(label, value)] for the Info panel and the File Metadata tab."""
    if not meta:
        return []
    rows = [("Container", meta['container']
             + (f" (brand {meta['brand']})" if meta.get('brand') else ''))]
    if meta.get('created'):
        rows.append(("Created", meta['created'] + " UTC (as recorded)"))
    if meta.get('modified') and meta['modified'] != meta.get('created'):
        rows.append(("Modified", meta['modified'] + " UTC (as recorded)"))
    if meta.get('creation_date'):
        rows.append(("Creation date (tag)", meta['creation_date']))
    if meta.get('duration') is not None:
        rows.append(("Duration", duration_text(meta['duration'])))
    camera = ' '.join(p for p in (meta.get('make'), meta.get('model')) if p)
    if camera:
        rows.append(("Device", camera))
    if meta.get('software'):
        rows.append(("Software", meta['software']))
    if meta.get('title'):
        rows.append(("Title", meta['title']))
    if meta.get('latitude') is not None:
        place = f"{meta['latitude']:.6f}, {meta['longitude']:.6f}"
        if meta.get('altitude') is not None:
            place += f", {meta['altitude']:g} m"
        rows.append(("Location", place))
    for track in meta.get('tracks') or []:
        rows.append(("Track", track_text(track)))
    shown = {value for _label, value in rows}
    for label, value in meta.get('tags') or []:
        if value not in shown:
            rows.append((label, value))
    return rows


def frame_rate(meta):
    """The first video track's frame rate, or None."""
    for track in (meta or {}).get('tracks') or []:
        if track.get('kind') == 'video' and track.get('frame_rate'):
            return track['frame_rate']
    return None


def video_finding_detail(meta):
    """What the analysis keeps about a video (content_checks finding
    detail), or {} when it records nothing an examiner would look for."""
    if not meta:
        return {}
    detail = {}
    for key in ('make', 'model', 'software', 'title'):
        if meta.get(key):
            detail[key] = meta[key]
    if meta.get('created'):
        detail['recorded'] = meta['created']
    taken = _local_digits(meta.get('creation_date'))
    if taken:
        detail['taken'] = taken
    if meta.get('creation_date'):
        detail['creation_date'] = meta['creation_date']
    if meta.get('latitude') is not None:
        detail['latitude'] = meta['latitude']
        detail['longitude'] = meta['longitude']
        if meta.get('altitude') is not None:
            detail['altitude'] = meta['altitude']
    if not detail:
        return {}
    detail['container'] = meta['container']
    if meta.get('duration') is not None:
        detail['duration'] = round(meta['duration'], 3)
    for track in meta.get('tracks') or []:
        if track.get('kind') == 'video':
            detail['codec'] = track.get('codec')
            if track.get('width'):
                detail['size'] = f"{track['width']} × {track['height']}"
            if track.get('frame_rate'):
                detail['frame_rate'] = track['frame_rate']
            break
    return detail


_MONTHS = {name: number for number, name in enumerate(
    ('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct',
     'nov', 'dec'), start=1)}


def _avi_date(text):
    """An AVI's IDIT / ICRD date as 'YYYY-MM-DD HH:MM:SS' when it is the
    C library's asctime ('Mon Mar 10 15:04:43 2003', what cameras write)
    or EXIF digits; otherwise as stored. No zone: the camera's clock."""
    text = (text or '').strip()
    match = re.match(r'(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+'
                     r'(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$', text)
    if match and match.group(1).lower() in _MONTHS:
        month = _MONTHS[match.group(1).lower()]
        return (f"{match.group(6)}-{month:02d}-{int(match.group(2)):02d} "
                f"{match.group(3)}:{match.group(4)}:{match.group(5)}")
    match = re.match(r'(\d{4}):(\d{2}):(\d{2})( \d{2}:\d{2}:\d{2})?$', text)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}" + \
            (match.group(4) or '')
    return text


def _local_digits(text):
    """A tag's creation date as EXIF-style local digits ('YYYY:MM:DD
    HH:MM:SS'), the zone dropped (the digits are the camera's wall
    clock), or ''."""
    match = re.match(r'(\d{4})[-:](\d{2})[-:](\d{2})[T ](\d{2}):(\d{2}):'
                     r'(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\s*$',
                     (text or '').strip())
    if not match or match.group(8) == 'Z':
        # A 'Z' time is UTC, not the camera's clock: `recorded` holds it.
        return ''
    year, month, day, hour, minute, second = match.groups()[:6]
    return f"{year}:{month}:{day} {hour}:{minute}:{second}"

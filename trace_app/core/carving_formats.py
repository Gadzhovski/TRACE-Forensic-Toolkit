"""Where a carved file ends, read from the file's own structure.

Each `measure_*` function is handed a `Source` and the absolute offset of a
signature hit, and returns `(size, extension)` -- or None when the bytes there
are not that format, or its extent cannot be established. A size comes from a
field in the header, or from walking the format's own chain of blocks to its
terminator; never from guessing. A guessed end turns free space into a "file",
which is fabricated evidence, so a format whose end cannot be found from its
structure is not carved at all.

Measuring decides the extent only. Whether the bytes then parse as the format
is `carving_signatures.is_valid_file`'s job, run on every candidate before it
is kept.

Specifications followed: SQLite file format; MS-PST; Windows NT registry file
format (regf); MS-EVEN6 / EVTX; PE/COFF; MS-SHLLINK; ISO/IEC 14496-12 (via
the existing atom walk); RIFF; ISO/IEC 11172-3 / 13818-3 (MP3 frames); RFC
3533 (Ogg); FLV v10; ISO/IEC 13818-1 program stream; EBML / Matroska; POSIX
ustar; XZ file format; ELF; Mach-O; Adobe Photoshop file format; RTF 1.9.
"""

import bz2
import lzma
import re
import struct
import zlib

#: Most carvers find a file only at the start of a sector: files are
#: allocated in whole sectors, so a header part-way into one is embedded in
#: something else (a thumbnail in a JPEG, an icon in an EXE).
SECTOR = 512


class Source:
    """Bytes of the image around a chunk.

    Reads inside the chunk are slices; reads past it go to the image itself,
    so a file whose size is in its header can be recovered whatever its
    length, not only when it fits in the chunk's read-ahead.
    """

    def __init__(self, chunk, base_offset, reader=None, image_size=None):
        self.chunk = chunk
        self.base = base_offset
        self.reader = reader
        self.size = image_size

    def get(self, offset, length):
        """`length` bytes at absolute `offset` -- fewer at the image's end."""
        if length <= 0:
            return b''
        rel = offset - self.base
        if 0 <= rel and rel + length <= len(self.chunk):
            return self.chunk[rel:rel + length]
        if self.reader is not None:
            if self.size is not None:
                length = max(0, min(length, self.size - offset))
            return self.reader(offset, length) if length else b''
        return self.chunk[max(rel, 0):rel + length] if rel >= 0 else b''


def _u16le(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32le(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _u64le(b, o):
    return struct.unpack_from('<Q', b, o)[0]


def _u16be(b, o):
    return struct.unpack_from('>H', b, o)[0]


def _u32be(b, o):
    return struct.unpack_from('>I', b, o)[0]


# --- databases and Windows artifacts ---------------------------------------

def measure_sqlite(src, start):
    """Page size x page count, from the 100-byte header.

    The page count at offset 28 is trusted only when the "version-valid-for"
    number at 92 equals the change counter at 24: SQLite writes both on every
    commit, and a database last written by a version older than 3.7 leaves
    the count stale. Such a database has no reliable size and is not carved.
    """
    h = src.get(start, 100)
    if len(h) < 100 or h[:16] != b'SQLite format 3\x00':
        return None
    page = _u16be(h, 16)
    page = 65536 if page == 1 else page
    if page < 512 or page & (page - 1):
        return None
    if h[21:24] != b'\x40\x20\x20':       # payload fractions, fixed by spec
        return None
    if _u32be(h, 92) != _u32be(h, 24):
        return None
    pages = _u32be(h, 28)
    if not pages:
        return None
    return page * pages, 'sqlite'


WAL_MAGICS = (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83')
WAL_VERSION = 3007000


def wal_checksum(data, s0, s1, big):
    """SQLite's WAL checksum over `data` (a multiple of 8 bytes)."""
    form = '>' if big else '<'
    for x0, x1 in struct.iter_unpack(form + 'II',
                                     data[:len(data) // 8 * 8]):
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF
    return s0, s1


def wal_header(h):
    """(page size, salt, big-endian checksums, s0, s1) of a WAL's 32-byte
    header whose own checksum holds, or None."""
    if len(h) < 32 or h[:4] not in WAL_MAGICS:
        return None
    if _u32be(h, 4) != WAL_VERSION:
        return None
    page = _u32be(h, 8)
    if page < 512 or page > 65536 or page & (page - 1):
        return None
    big = h[3] == 0x83
    s0, s1 = wal_checksum(h[:24], 0, 0, big)
    if (s0, s1) != (_u32be(h, 24), _u32be(h, 28)):
        return None
    return page, h[16:24], big, s0, s1


def measure_sqlite_wal(src, start):
    """A SQLite write-ahead log: its header, then every frame whose salt is
    the header's and whose checksum -- cumulative, over each frame header's
    first 8 bytes and its page -- continues the chain. The first frame that
    breaks it (a torn write, or a stale frame of an earlier generation
    behind the current ones) ends what the log proves; nothing past it is
    taken. At least one frame is required."""
    header = wal_header(src.get(start, 32))
    if header is None:
        return None
    page, salt, big, s0, s1 = header
    at, frames = start + 32, 0
    while True:
        frame = src.get(at, 24 + page)
        if len(frame) < 24 + page or frame[8:16] != salt:
            break
        t0, t1 = wal_checksum(frame[:8], s0, s1, big)
        t0, t1 = wal_checksum(frame[24:], t0, t1, big)
        if (t0, t1) != (_u32be(frame, 16), _u32be(frame, 20)):
            break
        if not _u32be(frame, 0):          # page numbers start at 1
            break
        s0, s1 = t0, t1
        frames += 1
        at += 24 + page
    if not frames:
        return None
    return at - start, 'wal'


# --- TIFF and the camera raw formats built on it ----------------------------

#: Signatures of the TIFF family: plain TIFF (and CR2, NEF, ARW, DNG, PEF,
#: which are TIFF), Panasonic RW2 ('IIU'), Olympus ORF ('IIRO', 'IIRS',
#: 'MMOR').
TIFF_FAMILY_HEADERS = (b'II*\x00', b'MM\x00*', b'IIU\x00', b'IIRO', b'IIRS',
                       b'MMOR')
_TIFF_WIDTH = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
               11: 4, 12: 8, 13: 4}
#: Tags whose values are IFDs to walk too: SubIFDs (where DNG, NEF and ARW
#: keep their raw image), EXIF, GPS, interoperability.
_TIFF_IFD_TAGS = (330, 34665, 34853, 40965)
#: (offsets tag, byte counts tag): strips, tiles, an embedded JPEG.
_TIFF_DATA_PAIRS = ((273, 279), (324, 325), (513, 514))
_TIFF_MAKE, _DNG_VERSION = 271, 50706
#: Camera makers whose TIFF-based raw has its own extension.
_RAW_MAKERS = (('NIKON', 'nef'), ('SONY', 'arw'), ('PENTAX', 'pef'),
               ('RICOH', 'pef'))
#: Panasonic RW2: the raw data's offset, and what sizes it.
_RW2_RAW_OFFSET, _RW2_WIDTH, _RW2_HEIGHT, _RW2_COMPRESSION = \
    0x118, 0x2, 0x3, 0xb


def _tiff_values(src, start, order, kind, count, value_at):
    """A tag's SHORT/LONG values (offsets, counts), or []."""
    width = {3: 2, 4: 4, 13: 4}.get(kind)
    if not width or not 0 < count <= 65536:
        return []
    raw = src.get(value_at, width * count)
    if len(raw) < width * count:
        return []
    return list(struct.unpack(f"{order}{count}{'H' if width == 2 else 'I'}",
                              raw))


def measure_tiff_family(src, start):
    """A TIFF, or a camera raw built on it, sized by its own structure.

    Every IFD is walked -- the chain, and the SubIFDs, EXIF, GPS and
    interoperability IFDs they point to -- and the file ends at the
    furthest byte anything in them accounts for: an IFD, a value array, a
    strip, a tile or an embedded JPEG. (The raw image of a DNG, NEF or
    ARW is in a SubIFD; a walk of the chain alone stopped short of it.)

    The extension: CR2 by the 'CR' mark after the header, RW2 and ORF by
    their magic, DNG by its version tag, NEF / ARW / PEF by the camera
    make; anything else is TIFF. A Panasonic RW2 does not record its raw
    data's length, only its start: for its packed format (compression
    34316, 16 bytes per 14 pixels in 16 KB blocks) the length follows from
    the sensor size; another compression is not carved.
    """
    head = src.get(start, 16)
    if len(head) < 16 or head[:4] not in TIFF_FAMILY_HEADERS:
        return None
    order = '<' if head[:2] == b'II' else '>'
    first = struct.unpack_from(order + 'I', head, 4)[0]
    if first < 8:
        return None
    kind = {b'IIU\x00': 'rw2', b'IIRO': 'orf', b'IIRS': 'orf',
            b'MMOR': 'orf'}.get(head[:4])
    if kind is None and head[8:10] == b'CR':
        kind = 'cr2'
    furthest, queue, seen = 8, [first], set()
    tags0 = {}
    while queue and len(seen) < 64:
        ifd = queue.pop(0)
        if ifd in seen or ifd < 8:
            continue
        seen.add(ifd)
        count_raw = src.get(start + ifd, 2)
        if len(count_raw) < 2:
            return None
        count = struct.unpack(order + 'H', count_raw)[0]
        if not 0 < count <= 1024:
            return None
        table = src.get(start + ifd + 2, count * 12 + 4)
        if len(table) < count * 12 + 4:
            return None
        furthest = max(furthest, ifd + 2 + count * 12 + 4)
        values = {}
        for n in range(count):
            tag, kind_, length, value = struct.unpack_from(
                order + 'HHII', table, n * 12)
            size = _TIFF_WIDTH.get(kind_, 0) * length
            value_at = start + ifd + 2 + n * 12 + 8
            if size > 4:
                furthest = max(furthest, value + size)
                value_at = start + value
            if tag in _TIFF_IFD_TAGS or any(tag in pair for pair in
                                            _TIFF_DATA_PAIRS):
                values[tag] = _tiff_values(src, start, order, kind_, length,
                                           value_at)
            elif len(seen) == 1:
                values[tag] = (kind_, length, value, value_at)
        if len(seen) == 1:
            tags0 = values
        for offsets, counts in _TIFF_DATA_PAIRS:
            for at, size in zip(values.get(offsets) or [],
                                values.get(counts) or []):
                if at != 0xFFFFFFFF and size != 0xFFFFFFFF:
                    furthest = max(furthest, at + size)
        for tag in _TIFF_IFD_TAGS:
            queue.extend(values.get(tag) or [])
        following = struct.unpack_from(order + 'I', table, count * 12)[0]
        if following:
            queue.append(following)
    if kind == 'rw2':
        raw = _rw2_raw_end(tags0)
        if raw is None:
            return None
        furthest = max(furthest, raw)
    if kind is None:
        kind = 'dng' if _DNG_VERSION in tags0 else 'tiff'
    if kind == 'tiff':
        make = tags0.get(_TIFF_MAKE)
        if make and make[0] == 2:
            text = (src.get(make[3], make[1]) if make[1] <= 4 else
                    src.get(start + make[2], make[1]))
            name = text.split(b'\x00')[0].decode('latin-1').upper()
            kind = next((ext for maker, ext in _RAW_MAKERS
                         if name.startswith(maker)), 'tiff')
    return furthest, kind


def _rw2_raw_end(tags):
    """Where a Panasonic RW2's raw data ends, or None if its format does
    not say."""
    def short(tag):
        entry = tags.get(tag)
        return entry[2] if entry else None
    offset = (tags.get(_RW2_RAW_OFFSET) or (None, None, None))[2]
    width, height = short(_RW2_WIDTH), short(_RW2_HEIGHT)
    if not offset or not width or not height:
        return None
    if short(_RW2_COMPRESSION) == 34316:
        packed = -(-width * height // 14) * 16
        return offset + -(-packed // 0x4000) * 0x4000
    return None


#: Fujifilm RAF: a fixed header, then (offset, length) pairs for the
#: embedded JPEG, the CFA header and the CFA (raw) data.
RAF_MAGIC = b'FUJIFILMCCD-RAW '


def measure_raf(src, start):
    """A Fujifilm RAF: the end of the furthest block its header lists."""
    head = src.get(start, 0x6C)
    if len(head) < 0x6C or head[:16] != RAF_MAGIC:
        return None
    pairs = struct.unpack_from('>6I', head, 0x54)
    ends = [offset + length for offset, length in zip(pairs[::2], pairs[1::2])
            if offset and length]
    if not ends or pairs[0] < 0x6C:
        return None
    return max(ends), 'raf'


def measure_regf(src, start):
    """4096-byte base block plus the hive-bins data size it records."""
    h = src.get(start, 4096 + 32)
    if len(h) < 4096 + 32 or h[:4] != b'regf':
        return None
    bins = _u32le(h, 0x28)
    if not bins or bins % 4096:
        return None
    if h[4096:4100] != b'hbin' or _u32le(h, 4100) != 0:
        return None
    return 4096 + bins, 'regf'


#: Microsoft's own extension-less hive names map poorly to a file system; a
#: carved hive is named for its format.
EVTX_CHUNK = 65536


def measure_evtx(src, start):
    """Header block plus its chunks -- and any dirty chunks after them.

    The header's chunk count can lag a log that was not closed cleanly, so
    chunks are counted on while the next 64 KB still opens with ElfChnk.
    """
    h = src.get(start, 4096)
    if len(h) < 4096 or h[:8] != b'ElfFile\x00':
        return None
    if _u32le(h, 0x20) != 128 or _u16le(h, 0x28) != 4096:
        return None
    if (zlib.crc32(h[:120]) & 0xFFFFFFFF) != _u32le(h, 0x7C):
        return None
    chunks = _u16le(h, 0x2A)
    if not chunks:
        return None
    size = 4096 + chunks * EVTX_CHUNK
    while src.get(start + size, 8) == b'ElfChnk\x00':
        size += EVTX_CHUNK
    if src.get(start + 4096, 8) != b'ElfChnk\x00':
        return None
    return size, 'evtx'


def measure_pst(src, start):
    """MS-PST: the file's end is recorded in its ROOT structure (ibFileEof)."""
    h = src.get(start, 0x200)
    if len(h) < 0x200 or h[:4] != b'!BDN':
        return None
    client = h[8:10]
    if client not in (b'SM', b'SO'):
        return None
    version = _u16le(h, 10)
    if version >= 23:                    # Unicode PST/OST
        size = _u64le(h, 0xB8)
    elif version in (14, 15):            # ANSI
        size = _u32le(h, 0xA8)
    else:
        return None
    if size < 0x4400:
        return None
    return size, 'pst' if client == b'SM' else 'ost'


def measure_pe(src, start):
    """End of the last section's raw data, or of the certificate table.

    Data appended after both (an installer's payload, an overlay) is not part
    of the image the loader maps and has no length recorded anywhere, so it
    is not included -- a carved installer is the executable without it.
    """
    mz = src.get(start, 64)
    if len(mz) < 64 or mz[:2] != b'MZ':
        return None
    lfanew = _u32le(mz, 0x3C)
    if lfanew < 64 or lfanew > 0x4000 or lfanew % 4:
        return None
    pe = src.get(start + lfanew, 24 + 240)
    if len(pe) < 24 or pe[:4] != b'PE\x00\x00':
        return None
    sections = _u16le(pe, 6)
    optional = _u16le(pe, 20)
    characteristics = _u16le(pe, 22)
    if not 1 <= sections <= 96 or optional < 96:
        return None
    opt = src.get(start + lfanew + 24, optional)
    if len(opt) < optional:
        return None
    magic = _u16le(opt, 0)
    if magic == 0x10B:
        dirs_at, count_at = 96, 92
    elif magic == 0x20B:
        dirs_at, count_at = 112, 108
    else:
        return None
    file_align = _u32le(opt, 36)
    headers = _u32le(opt, 60)
    subsystem = _u16le(opt, 68)
    if file_align not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) \
            and file_align < 512:
        return None

    table = src.get(start + lfanew + 24 + optional, sections * 40)
    if len(table) < sections * 40:
        return None
    end = headers
    for i in range(sections):
        raw_size = _u32le(table, i * 40 + 16)
        raw_ptr = _u32le(table, i * 40 + 20)
        if raw_size and raw_ptr:
            end = max(end, raw_ptr + raw_size)
    # The certificate table (data directory 4) is addressed by file offset
    # and sits after the sections, so it extends the file.
    count = _u32le(opt, count_at) if optional >= count_at + 4 else 0
    if count > 4 and optional >= dirs_at + 5 * 8:
        cert_off = _u32le(opt, dirs_at + 4 * 8)
        cert_size = _u32le(opt, dirs_at + 4 * 8 + 4)
        if cert_off and cert_size:
            end = max(end, cert_off + cert_size)

    if characteristics & 0x2000:
        ext = 'dll'
    elif subsystem == 1:
        ext = 'sys'
    else:
        ext = 'exe'
    return end, ext


LNK_CLSID = bytes.fromhex('0114020000000000C000000000000046')


def measure_lnk(src, start):
    """MS-SHLLINK: header, then the optional structures its flags announce,
    then extra-data blocks up to the four-byte terminal block."""
    h = src.get(start, 0x4C)
    if len(h) < 0x4C or _u32le(h, 0) != 0x4C or h[4:20] != LNK_CLSID:
        return None
    flags = _u32le(h, 0x14)
    pos = 0x4C
    if flags & 0x01:                                 # HasLinkTargetIDList
        pos += 2 + _u16le(src.get(start + pos, 2), 0)
    if flags & 0x02:                                 # HasLinkInfo
        info = _u32le(src.get(start + pos, 4), 0)
        if info < 0x1C:
            return None
        pos += info
    unicode = bool(flags & 0x80)
    for bit in (0x04, 0x08, 0x10, 0x20, 0x40):       # StringData
        if flags & bit:
            chars = _u16le(src.get(start + pos, 2), 0)
            pos += 2 + chars * (2 if unicode else 1)
    for _ in range(64):                              # ExtraData
        block = src.get(start + pos, 4)
        if len(block) < 4:
            return None
        size = _u32le(block, 0)
        if size < 4:
            return pos + 4, 'lnk'
        if size > 0x10000:
            return None
        pos += size
    return None


# --- containers and media ---------------------------------------------------

def measure_riff(src, start):
    """RIFF size field plus its 8-byte header; named by form type."""
    h = src.get(start, 12)
    if len(h) < 12 or h[:4] != b'RIFF':
        return None
    form = h[8:12]
    ext = {b'WAVE': 'wav', b'WEBP': 'webp', b'AVI ': 'avi'}.get(form)
    if ext is None:
        return None
    size = _u32le(h, 4) + 8
    return size + (size & 1), ext


#: MPEG audio bitrates (kbit/s) by [version-group][layer][index]: MPEG-1, and
#: MPEG-2/2.5 which share a table.
_BITRATES = {
    (1, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (1, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (1, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
_SAMPLE_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000),
                 0: (11025, 12000, 8000)}


def mpeg_frame(header):
    """(length, version, layer, rate) of an MPEG audio frame header, or None."""
    if len(header) < 4 or header[0] != 0xFF or header[1] & 0xE0 != 0xE0:
        return None
    version = (header[1] >> 3) & 3          # 3: MPEG-1, 2: MPEG-2, 0: 2.5
    layer = 4 - ((header[1] >> 1) & 3)      # 1, 2, 3; 4 means reserved
    if version == 1 or layer == 4:
        return None
    index = header[2] >> 4
    rate_index = (header[2] >> 2) & 3
    if index in (0, 15) or rate_index == 3:
        return None
    bitrate = _BITRATES[(1 if version == 3 else 2, layer)][index] * 1000
    rate = _SAMPLE_RATES[version][rate_index]
    padding = (header[2] >> 1) & 1
    if layer == 1:
        length = (12 * bitrate // rate + padding) * 4
    elif layer == 3 and version != 3:
        length = 72 * bitrate // rate + padding
    else:
        length = 144 * bitrate // rate + padding
    return (length, version, layer, rate) if length >= 24 else None


#: A run of this many consistent frames before an MP3 counts as one. A
#: stray 0xFFF? sync word is common; a chain of frames whose lengths land
#: exactly on the next header is not. Without an ID3 tag to say "an MP3
#: starts here", far more are required.
MP3_MIN_FRAMES = 8
MP3_MIN_FRAMES_UNTAGGED = 32


def measure_mp3(src, start):
    """Optional ID3v2 tag (sized), MPEG audio frames walked one by one, then
    an optional 128-byte ID3v1 tag."""
    head = src.get(start, 10)
    pos = start
    tagged = head[:3] == b'ID3'
    if tagged:
        if len(head) < 10 or head[3] not in (2, 3, 4) or \
                any(b & 0x80 for b in head[6:10]):
            return None
        tag = (head[6] << 21) | (head[7] << 14) | (head[8] << 7) | head[9]
        pos = start + 10 + tag + (10 if head[5] & 0x10 else 0)
        # Some encoders pad the tag with zeros beyond its declared size.
        for _ in range(4096):
            if src.get(pos, 1) == b'\x00':
                pos += 1
            else:
                break
    first = mpeg_frame(src.get(pos, 4))
    if first is None or first[2] != 3:
        return None
    frames = 0
    expect = first[1:]
    window = b''
    window_at = pos
    while True:
        if pos + 4 > window_at + len(window):
            window_at = pos
            window = src.get(pos, 1 << 20)
            if len(window) < 4:
                break
        rel = pos - window_at
        frame = mpeg_frame(window[rel:rel + 4])
        if frame is None or frame[1:] != expect:
            break
        pos += frame[0]
        frames += 1
    if frames < (MP3_MIN_FRAMES if tagged else MP3_MIN_FRAMES_UNTAGGED):
        return None
    if src.get(pos, 3) == b'TAG':
        pos += 128
    return pos - start, 'mp3'


_OGG_TABLE = []
for _i in range(256):
    _r = _i << 24
    for _ in range(8):
        _r = ((_r << 1) ^ 0x04C11DB7) if _r & 0x80000000 else (_r << 1)
    _OGG_TABLE.append(_r & 0xFFFFFFFF)


def _ogg_crc(page):
    crc = 0
    for byte in page[:22] + b'\x00\x00\x00\x00' + page[26:]:
        crc = ((crc << 8) ^ _OGG_TABLE[((crc >> 24) ^ byte) & 0xFF]) & 0xFFFFFFFF
    return crc


def measure_ogg(src, start):
    """Ogg pages, each CRC-checked, until every stream begun has ended."""
    pos = start
    open_streams = set()
    first = True
    ext = 'ogg'
    for _ in range(200000):
        header = src.get(pos, 27)
        if len(header) < 27 or header[:4] != b'OggS' or header[4] != 0:
            return None
        kind = header[5]
        serial = _u32le(header, 14)
        table = src.get(pos + 27, header[26])
        length = 27 + header[26] + sum(table)
        page = src.get(pos, length)
        if len(page) < length or _ogg_crc(page) != _u32le(header, 22):
            return None
        if first:
            if not kind & 0x02:
                return None
            if page[27 + header[26]:27 + header[26] + 8] == b'OpusHead':
                ext = 'opus'
            first = False
        if kind & 0x02:
            open_streams.add(serial)
        if serial not in open_streams:
            return None
        pos += length
        if kind & 0x04:
            open_streams.discard(serial)
            if not open_streams:
                return pos - start, ext
    return None


def measure_flv(src, start):
    """FLV header, then tags, each followed by PreviousTagSize = 11 + data."""
    h = src.get(start, 13)
    if len(h) < 13 or h[:3] != b'FLV' or h[3] != 1 or _u32be(h, 5) != 9 \
            or _u32be(h, 9) != 0:
        return None
    pos = start + 13
    tags = 0
    while True:
        tag = src.get(pos, 11)
        if len(tag) < 11 or tag[0] not in (8, 9, 18) or tag[8:11] != b'\0\0\0':
            break
        data = (tag[1] << 16) | (tag[2] << 8) | tag[3]
        back = src.get(pos + 11 + data, 4)
        if len(back) < 4 or _u32be(back, 0) != 11 + data:
            break
        pos += 11 + data + 4
        tags += 1
    return (pos - start, 'flv') if tags >= 3 else None


def measure_mpg(src, start):
    """MPEG program stream: packs and packets walked to the end code."""
    pos = start
    packs = 0
    window = b''
    window_at = pos
    for _ in range(2000000):
        if pos + 16 > window_at + len(window):
            window_at = pos
            window = src.get(pos, 1 << 20)
        rel = pos - window_at
        head = window[rel:rel + 16]
        if len(head) < 4 or head[:3] != b'\x00\x00\x01':
            break
        code = head[3]
        if code == 0xB9:                                  # program end
            pos += 4
            return (pos - start, 'mpg') if packs >= 2 else None
        if code == 0xBA:                                  # pack header
            if len(head) < 14:
                break
            if head[4] >> 6 == 1:                         # MPEG-2
                pos += 14 + (head[13] & 7)
            elif head[4] >> 4 == 2:                       # MPEG-1
                pos += 12
            else:
                break
            if packs == 0 and src.get(pos, 4) != b'\x00\x00\x01\xbb':
                # Encoders open a program stream with a system header after
                # the first pack. A pack without one is mid-stream: part of
                # another file, not the start of one.
                return None
            packs += 1
        elif code >= 0xBB:                                # system header, PES
            if len(head) < 6:
                break
            pos += 6 + _u16be(head, 4)
        else:
            break
    # No end code: many files lack one. A long, unbroken run of packs is
    # still a stream; a short one is not trusted.
    return (pos - start, 'mpg') if packs >= 64 else None


def _ebml_vint(data, at):
    """(value, width) of an EBML variable-length integer, or None."""
    if at >= len(data):
        return None
    first = data[at]
    width = 1
    while width <= 8 and not first & (0x80 >> (width - 1)):
        width += 1
    if width > 8 or at + width > len(data):
        return None
    value = first & (0xFF >> width)
    for b in data[at + 1:at + width]:
        value = (value << 8) | b
    return value, width


def _ebml_id(data, at):
    if at >= len(data):
        return None
    first = data[at]
    width = 1
    while width <= 4 and not first & (0x80 >> (width - 1)):
        width += 1
    if width > 4 or at + width > len(data):
        return None
    return data[at:at + width], width


def measure_mkv(src, start):
    """EBML header (for the DocType), then the Segment's recorded size.

    A segment of "unknown" size -- written live and never finalised -- has no
    end to read, and is not carved.
    """
    head = src.get(start, 4096)
    if head[:4] != b'\x1A\x45\xDF\xA3':
        return None
    size = _ebml_vint(head, 4)
    if size is None:
        return None
    header_end = 4 + size[1] + size[0]
    if header_end > len(head):
        return None
    doc = re.search(rb'\x42\x82[\x80-\xff](webm|matroska)', head[:header_end])
    if not doc:
        return None
    ext = 'webm' if doc.group(1) == b'webm' else 'mkv'
    element = _ebml_id(head, header_end)
    if element is None or element[0] != b'\x18\x53\x80\x67':
        return None
    seg = _ebml_vint(head, header_end + 4)
    if seg is None:
        return None
    value, width = seg
    if value == (1 << (7 * width)) - 1:
        return None
    return header_end + 4 + width + value, ext


# --- archives and documents -------------------------------------------------

def _tar_checksum_ok(block):
    try:
        stored = int(block[148:156].split(b'\x00')[0].strip() or b'0', 8)
    except ValueError:
        return False
    total = sum(block[:148]) + 8 * 32 + sum(block[156:512])
    return stored == total


#: A V7 header's checksum field: six octal digits, then NUL and space (or
#: the other way round), as tar has always written it.
_V7_CHECKSUM = re.compile(rb'[0-7 ]{6}(\x00 | \x00|\x00\x00|  )')
_V7_TYPES = frozenset(b'\x0001234567')


def plausible_v7_header(block):
    """Could this 512-byte block be a pre-POSIX (V7) tar header?

    V7 tar has no magic -- bytes 257 on are zero -- so the header's own
    checksum is what finds it, together with fields that must be printable
    or octal. Random data almost never passes the checksum.
    """
    if len(block) < 512 or block[257:263] != b'\x00' * 6:
        return False
    if not _V7_CHECKSUM.fullmatch(block[148:156]):
        return False
    if block[156] not in _V7_TYPES or not 0x20 < block[0] < 0x7F:
        return False
    name = block[:100].split(b'\x00', 1)[0]
    if not name or any(b < 0x20 or b > 0x7E for b in name):
        return False
    for field in (block[100:108], block[124:136], block[136:148]):
        if not re.fullmatch(rb'[0-7 ]*\x00?[ \x00]*', field):
            return False
    return _tar_checksum_ok(block)


def measure_tar_v7(src, start):
    """A V7 tar, found by its header checksum (see plausible_v7_header)."""
    if not plausible_v7_header(src.get(start, 512)):
        return None
    return measure_tar(src, start, v7=True)


def measure_tar(src, start, v7=False):
    """Headers walked, each checksummed, to the two zero blocks. ustar
    headers carry their magic; V7 ones (`v7`) are checked field by field."""
    pos = start
    members = 0
    for _ in range(100000):
        block = src.get(pos, 512)
        if len(block) < 512:
            return None
        if block == b'\x00' * 512:
            if src.get(pos + 512, 512) != b'\x00' * 512:
                return None
            pos += 1024
            # Archivers pad to a 10 KB record with zeros; keep the padding
            # that is there, so the carve matches the file as written.
            record = (pos - start + 10239) // 10240 * 10240
            pad = src.get(pos, start + record - pos)
            if pad and pad == b'\x00' * len(pad):
                pos = start + record
            return (pos - start, 'tar') if members else None
        if v7:
            if not plausible_v7_header(block):
                return None
        elif block[257:262] != b'ustar' or not _tar_checksum_ok(block):
            return None
        try:
            size = int(block[124:136].split(b'\x00')[0].strip() or b'0', 8)
        except ValueError:
            return None
        pos += 512 + (size + 511) // 512 * 512
        members += 1
    return None


SEVENZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"


def measure_7z(src, start):
    """The signature header records where the end header is: the archive is
    32 + next-header offset + next-header size bytes, both CRC-protected."""
    head = src.get(start, 32)
    if len(head) < 32 or head[:6] != SEVENZIP_SIGNATURE:
        return None
    if (zlib.crc32(head[12:32]) & 0xFFFFFFFF) != _u32le(head, 8):
        return None
    offset, size = _u64le(head, 12), _u64le(head, 20)
    if not size or size > 64 * 1024 * 1024:
        return None
    tail = src.get(start + 32 + offset, size)
    if len(tail) < size or \
            (zlib.crc32(tail) & 0xFFFFFFFF) != _u32le(head, 28):
        return None
    return 32 + offset + size, '7z'


RAR3_SIGNATURE = b'Rar!\x1a\x07\x00'
RAR5_SIGNATURE = b'Rar!\x1a\x07\x01\x00'


def measure_rar(src, start):
    """RAR blocks walked, each header CRC-checked, to the end-of-archive
    block. An archive whose headers are encrypted (RAR5 -hp) cannot be
    walked and is not carved."""
    head = src.get(start, 8)
    if head.startswith(RAR5_SIGNATURE):
        return _measure_rar5(src, start)
    if head.startswith(RAR3_SIGNATURE):
        return _measure_rar3(src, start)
    return None


def _measure_rar3(src, start):
    pos = start + len(RAR3_SIGNATURE)
    for _ in range(200000):
        head = src.get(pos, 11)
        if len(head) < 7:
            return None
        crc, kind, flags, size = struct.unpack_from('<HBHH', head, 0)
        if size < 7 or kind < 0x72 or kind > 0x7B:
            return None
        header = src.get(pos, size)
        if len(header) < size or \
                (zlib.crc32(header[2:]) & 0xFFFF) != crc:
            return None
        extra = 0
        if flags & 0x8000 or kind in (0x74, 0x7A):
            if size < 11:
                return None
            extra = _u32le(header, 7)
        if kind == 0x7B:                                  # end of archive
            return pos + size - start, 'rar'
        pos += size + extra
    return None


def _rar5_vint(data, at):
    value = shift = 0
    for i in range(10):
        if at + i >= len(data):
            return None
        byte = data[at + i]
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i + 1
    return None


def _measure_rar5(src, start):
    pos = start + len(RAR5_SIGNATURE)
    for _ in range(200000):
        head = src.get(pos, 4 + 3)
        if len(head) < 5:
            return None
        crc = _u32le(head, 0)
        got = _rar5_vint(src.get(pos + 4, 3), 0)
        if got is None:
            return None
        header_size, width = got
        if not 0 < header_size <= 2 * 1024 * 1024:
            return None
        header = src.get(pos + 4, width + header_size)
        if len(header) < width + header_size or \
                (zlib.crc32(header) & 0xFFFFFFFF) != crc:
            return None
        body = header[width:]
        kind, used = _rar5_vint(body, 0) or (None, 0)
        flags_at = used
        flags, used = _rar5_vint(body, flags_at) or (None, 0)
        if kind is None or flags is None:
            return None
        at = flags_at + used
        data_size = 0
        if flags & 0x01:                                  # extra area size
            _extra, used = _rar5_vint(body, at) or (0, 1)
            at += used
        if flags & 0x02:                                  # data area size
            data_size, used = _rar5_vint(body, at) or (0, 1)
        if kind == 4:                                     # encrypted headers
            return None
        end = pos + 4 + width + header_size + data_size
        if kind == 5:                                     # end of archive
            return end - start, 'rar'
        pos = end
    return None


#: Decompressing an unverified stream to find its end is bounded, as GZ is:
#: a few bytes of free space should not become gigabytes of memory.
STREAM_DECOMPRESS_LIMIT = 256 * 1024 * 1024


def _stream_end(src, start, make, cap):
    """Bytes consumed when a decompressor reaches end-of-stream, or None."""
    decompressor = make()
    consumed = 0
    produced = 0
    step = 1 << 20
    while consumed < cap:
        data = src.get(start + consumed, step)
        if not data:
            return None
        try:
            out = decompressor.decompress(data, max_length=STREAM_DECOMPRESS_LIMIT
                                          - produced)
        except (OSError, EOFError, lzma.LZMAError, ValueError):
            return None
        produced += len(out)
        if decompressor.eof:
            return consumed + len(data) - len(decompressor.unused_data)
        if produced >= STREAM_DECOMPRESS_LIMIT:
            return None
        if not getattr(decompressor, 'needs_input', True):
            # Output limit reached with input still pending: drain.
            while not decompressor.needs_input and not decompressor.eof:
                try:
                    out = decompressor.decompress(b'', max_length=1 << 20)
                except (OSError, EOFError, lzma.LZMAError, ValueError):
                    return None
                produced += len(out)
                if produced >= STREAM_DECOMPRESS_LIMIT:
                    return None
            if decompressor.eof:
                return consumed + len(data) - len(decompressor.unused_data)
        consumed += len(data)
    return None


def measure_bz2(src, start, cap):
    head = src.get(start, 10)
    if head[:3] != b'BZh' or head[3:4] not in b'123456789' or \
            head[4:10] != b'\x31\x41\x59\x26\x53\x59':
        return None
    end = _stream_end(src, start, bz2.BZ2Decompressor, cap)
    return (end, 'bz2') if end else None


def measure_xz(src, start, cap):
    head = src.get(start, 12)
    if head[:6] != b'\xFD7zXZ\x00' or head[6] != 0 or \
            (zlib.crc32(head[6:8]) & 0xFFFFFFFF) != _u32le(head, 8):
        return None
    end = _stream_end(src, start,
                      lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ), cap)
    if not end or src.get(start + end - 2, 2) != b'YZ':
        return None
    return end, 'xz'


def measure_rtf(src, start, cap):
    """Brace depth walked, escapes honoured, to the closing brace of the
    outermost group. RTF is 7-bit text; a high byte outside \\bin data means
    this is not one."""
    pos = start
    depth = 0
    window = b''
    window_at = start
    while pos - start < cap:
        if pos >= window_at + len(window):
            window_at = pos
            window = src.get(pos, 1 << 20)
            if not window:
                return None
        rel = pos - window_at
        byte = window[rel]
        if byte == 0x5C:                                  # backslash
            nxt = src.get(pos + 1, 4)
            if nxt[:3] == b'bin':
                match = re.match(rb'\\bin(\d+) ?', src.get(pos, 16))
                if match:
                    pos += match.end() + int(match.group(1))
                    continue
            pos += 2
            continue
        if byte == 0x7B:
            depth += 1
        elif byte == 0x7D:
            depth -= 1
            if depth == 0:
                return pos + 1 - start, 'rtf'
        elif byte >= 0x80 or byte == 0:
            return None
        pos += 1
    return None


def measure_elf(src, start):
    """The furthest of the section-header table and every program/section
    extent recorded in it."""
    h = src.get(start, 64)
    if len(h) < 52 or h[:4] != b'\x7fELF' or h[4] not in (1, 2) or \
            h[5] not in (1, 2) or h[6] != 1:
        return None
    end_fmt = '<' if h[5] == 1 else '>'
    if h[4] == 1:
        phoff, shoff = struct.unpack_from(end_fmt + 'II', h, 28)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(
            end_fmt + 'HHHH', h, 42)
        off_fmt, size_fmt = 'I', 'I'
        ph_off_at, ph_size_at, sh_off_at, sh_size_at = 4, 16, 16, 20
    else:
        phoff, shoff = struct.unpack_from(end_fmt + 'QQ', h, 32)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(
            end_fmt + 'HHHH', h, 54)
        off_fmt, size_fmt = 'Q', 'Q'
        ph_off_at, ph_size_at, sh_off_at, sh_size_at = 8, 32, 24, 32
    if not shoff or not shnum or shentsize < 40 or phnum > 512 or shnum > 4096:
        return None
    end = shoff + shnum * shentsize
    table = src.get(start + phoff, phnum * phentsize) if phnum else b''
    for i in range(phnum):
        entry = table[i * phentsize:(i + 1) * phentsize]
        if len(entry) < ph_size_at + 8:
            return None
        offset = struct.unpack_from(end_fmt + off_fmt, entry, ph_off_at)[0]
        size = struct.unpack_from(end_fmt + size_fmt, entry, ph_size_at)[0]
        end = max(end, offset + size)
    table = src.get(start + shoff, shnum * shentsize)
    if len(table) < shnum * shentsize:
        return None
    for i in range(shnum):
        entry = table[i * shentsize:(i + 1) * shentsize]
        kind = struct.unpack_from(end_fmt + 'I', entry, 4)[0]
        if kind == 8:                                  # SHT_NOBITS
            continue
        offset = struct.unpack_from(end_fmt + off_fmt, entry, sh_off_at)[0]
        size = struct.unpack_from(end_fmt + size_fmt, entry, sh_size_at)[0]
        end = max(end, offset + size)
    return end, 'elf'


_MACHO = {b'\xfe\xed\xfa\xce': ('>', False), b'\xce\xfa\xed\xfe': ('<', False),
          b'\xfe\xed\xfa\xcf': ('>', True), b'\xcf\xfa\xed\xfe': ('<', True)}


def _macho_thin_end(src, start):
    head = src.get(start, 32)
    kind = _MACHO.get(head[:4])
    if kind is None or len(head) < 28:
        return None
    order, wide = kind
    ncmds, sizeofcmds = struct.unpack_from(order + 'II', head, 16)
    if not 1 <= ncmds <= 4096 or sizeofcmds > 1 << 20:
        return None
    at = 32 if wide else 28
    commands = src.get(start + at, sizeofcmds)
    if len(commands) < sizeofcmds:
        return None
    end = at + sizeofcmds
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(commands):
            return None
        cmd, size = struct.unpack_from(order + 'II', commands, pos)
        if size < 8:
            return None
        if cmd == 0x1 and size >= 56:                   # LC_SEGMENT
            fileoff, filesize = struct.unpack_from(order + 'II', commands,
                                                   pos + 32)
            end = max(end, fileoff + filesize)
        elif cmd == 0x19 and size >= 72:                # LC_SEGMENT_64
            fileoff, filesize = struct.unpack_from(order + 'QQ', commands,
                                                   pos + 40)
            end = max(end, fileoff + filesize)
        elif cmd == 0x1D and size >= 16:                # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from(order + 'II', commands,
                                                   pos + 8)
            end = max(end, dataoff + datasize)
        pos += size
    return end


def measure_macho(src, start):
    """Thin binaries: the furthest segment or code signature. Universal
    ("fat") binaries: the furthest architecture slice."""
    head = src.get(start, 8)
    if head[:4] == b'\xca\xfe\xba\xbe':
        # Java class files share this magic; a fat header's architecture
        # count is small, a class file's version field is not.
        count = _u32be(head, 4)
        if not 1 <= count <= 16:
            return None
        table = src.get(start + 8, count * 20)
        end = 8 + count * 20
        for i in range(count):
            offset, size = struct.unpack_from('>II', table, i * 20 + 8)
            if _macho_thin_end(src, start + offset) is None:
                return None
            end = max(end, offset + size)
        return end, 'macho'
    end = _macho_thin_end(src, start)
    return (end, 'macho') if end else None


def measure_psd(src, start):
    """Header, then three length-prefixed sections, then the image data,
    whose length follows from its compression."""
    h = src.get(start, 26)
    if len(h) < 26 or h[:4] != b'8BPS' or _u16be(h, 4) not in (1, 2):
        return None
    # Version 2 is PSB, Photoshop's large document: the layer section's
    # length and each RLE row count are twice as wide, and the canvas may
    # be up to 300,000 pixels a side.
    big = _u16be(h, 4) == 2
    channels = _u16be(h, 12)
    height, width = _u32be(h, 14), _u32be(h, 18)
    depth = _u16be(h, 22)
    if not 1 <= channels <= 56 or depth not in (1, 8, 16, 32) or \
            not height or not width:
        return None
    pos = start + 26
    for section in range(3):                        # colour, resources, layers
        wide = big and section == 2
        length = src.get(pos, 8 if wide else 4)
        if len(length) < (8 if wide else 4):
            return None
        pos += (8 + struct.unpack('>Q', length)[0]) if wide else \
            (4 + _u32be(length, 0))
    compression = src.get(pos, 2)
    if len(compression) < 2:
        return None
    mode = _u16be(compression, 0)
    pos += 2
    if mode == 0:
        pos += channels * height * ((width * depth + 7) // 8)
    elif mode == 1:
        rows = channels * height
        width_of = 4 if big else 2
        counts = src.get(pos, rows * width_of)
        if len(counts) < rows * width_of:
            return None
        pos += rows * width_of + sum(struct.unpack(
            f">{rows}{'I' if big else 'H'}", counts))
    else:
        return None
    return pos - start, 'psb' if big else 'psd'


_MBOX_FROM = re.compile(
    rb'From \S+ +(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|'
    rb'Aug|Sep|Oct|Nov|Dec) [ \d]\d \d\d:\d\d:\d\d \d{4}')


def measure_mbox(src, start, cap):
    """An mbox: a From_ separator line, then mail text (see _mail_extent)."""
    if not _MBOX_FROM.match(src.get(start, 200)):
        return None
    size = _mail_extent(src, start, cap)
    return (size, 'mbox') if size >= 200 else None


#: Headers a saved message (.eml) begins with, as mail software writes it.
EML_STARTS = (b'Return-Path: ', b'Received: from ', b'Delivered-To: ',
              b'X-Mozilla-Status: ', b'MIME-Version: 1.0', b'MIME-version: 1.0',
              b'Message-ID: <', b'Message-Id: <')

_HEADER_LINE = re.compile(rb'^[A-Za-z][A-Za-z0-9-]{1,60}: ', re.M)


def measure_eml(src, start, cap):
    """A saved mail message: a header block, a blank line, a body.

    The header block is required to look like one -- at least four header
    lines, a From: and a Date: or Received:, and the blank line that ends
    it -- before the text heuristic is trusted with the extent.
    """
    head = src.get(start, 16384)
    if not head.startswith(EML_STARTS):
        return None
    blank = head.find(b'\n\n')
    if blank == -1:
        blank = head.find(b'\r\n\r\n')
    if blank == -1:
        return None
    headers = head[:blank]
    if len(_HEADER_LINE.findall(headers)) < 4 or \
            not re.search(rb'^From: ', headers, re.M | re.I) or \
            not re.search(rb'^(Date|Received): ', headers, re.M | re.I):
        return None
    size = _mail_extent(src, start, cap, split_at=EML_STARTS)
    return (size, 'eml') if size > blank else None


def _mail_extent(src, start, cap, split_at=None):
    """The one heuristic: mail text runs until the text stops.

    Mail has no length and no terminator, so it ends where the bytes stop
    being text. What separates text from anything else is control bytes, not
    high ones: mail in Latin-1, EUC-KR or UTF-8 is full of bytes over 0x7F,
    but holds no NUL or control character, while random data has one every
    few bytes -- a 512-byte sector of it without one does not happen. So a
    sector free of them is text, whatever its charset; in the first that is
    not, the mail ends at the last line break before the first control byte
    (a mail file ends with one; slack after it is usually zeros).

    `split_at`: header starts that, found at a sector boundary once this
    message's own header block is over, begin the next message -- saved
    messages lie back to back on disk as often as not.
    """
    pos = start
    headers_done = False
    while pos - start < cap:
        sector = src.get(pos, SECTOR)
        if not sector:
            break
        if split_at and pos > start and headers_done and \
                sector.startswith(split_at):
            break
        stop = next((i for i, b in enumerate(sector)
                     if b < 0x20 and b not in (0x09, 0x0A, 0x0C, 0x0D)), None)
        if not headers_done:
            seen = src.get(start, pos - start + len(sector))
            headers_done = b'\n\n' in seen or b'\r\n\r\n' in seen
        if stop is None and len(sector) == SECTOR:
            pos += SECTOR
            continue
        limit = stop if stop is not None else len(sector)
        newline = sector.rfind(b'\n', 0, limit)
        if newline >= 0:
            pos += newline + 1
        elif pos > start:
            # Nothing of the mail in this sector: it ended in the previous
            # one, at its last newline.
            tail = src.get(pos - SECTOR, SECTOR)
            last = tail.rfind(b'\n')
            if last >= 0:
                pos = pos - SECTOR + last + 1
        break
    return pos - start


# --- naming a ZIP by what is inside it --------------------------------------

def zip_kind(names, read):
    """What a valid ZIP actually is, from its members.

    `names` is the member list and `read(name)` returns a member's bytes. An
    Office document, an OpenDocument, an EPUB, an Android package and a Java
    archive are all ZIPs; carving them as "zip" hides what the examiner
    recovered.
    """
    names = set(names)
    if '[Content_Types].xml' in names:
        for prefix, ext in (('word/', 'docx'), ('xl/', 'xlsx'),
                            ('ppt/', 'pptx'), ('visio/', 'vsdx')):
            if any(n.startswith(prefix) for n in names):
                return ext
    if 'mimetype' in names:
        try:
            mime = read('mimetype').decode('ascii', 'replace').strip()
        except Exception:
            mime = ''
        odf = {
            'application/vnd.oasis.opendocument.text': 'odt',
            'application/vnd.oasis.opendocument.spreadsheet': 'ods',
            'application/vnd.oasis.opendocument.presentation': 'odp',
            'application/vnd.oasis.opendocument.graphics': 'odg',
            'application/epub+zip': 'epub',
        }
        if mime in odf:
            return odf[mime]
    if 'META-INF/manifest.xml' in names:
        # ODF requires the mimetype member, but not every writer includes it;
        # the manifest states the type too, as the media type of "/".
        try:
            manifest = read('META-INF/manifest.xml')
        except Exception:
            manifest = b''
        match = re.search(rb'full-path="/"[^>]*media-type="([^"]+)"|'
                          rb'media-type="([^"]+)"[^>]*full-path="/"', manifest)
        if match:
            mime = (match.group(1) or match.group(2)).decode('ascii', 'replace')
            for suffix, ext in (('opendocument.text', 'odt'),
                                ('opendocument.spreadsheet', 'ods'),
                                ('opendocument.presentation', 'odp'),
                                ('opendocument.graphics', 'odg')):
                if mime.endswith(suffix):
                    return ext
    if 'AndroidManifest.xml' in names and 'classes.dex' in names:
        return 'apk'
    if 'META-INF/MANIFEST.MF' in names and any(n.endswith('.class')
                                               for n in names):
        return 'jar'
    return 'zip'


#: ISO-BMFF major brands, and the extension each names. Anything else with
#: an ftyp is MP4; QuickTime has none, or brand 'qt  '.
ISOBMFF_BRANDS = {
    b'qt  ': 'mov', b'moov': 'mov',
    b'heic': 'heic', b'heix': 'heic', b'hevc': 'heic', b'heim': 'heic',
    b'heis': 'heic', b'hevm': 'heic', b'hevs': 'heic', b'mif1': 'heic',
    b'msf1': 'heic',
    b'avif': 'avif', b'avis': 'avif',
    b'M4A ': 'm4a', b'M4B ': 'm4a', b'M4P ': 'm4a',
    b'M4V ': 'm4v', b'M4VH': 'm4v', b'M4VP': 'm4v',
    b'crx ': 'cr3',                    # Canon CR3 raw (CRX)
    b'3gp4': '3gp', b'3gp5': '3gp', b'3gp6': '3gp', b'3gp7': '3gp',
    b'3gs7': '3gp', b'3ge6': '3gp', b'3ge7': '3gp', b'3g2a': '3gp',
}


def isobmff_kind(content):
    if content[4:8] != b'ftyp':
        return 'mov'
    brand = content[8:12]
    kind = ISOBMFF_BRANDS.get(brand, 'mp4')
    if brand == b'mif1':
        # mif1 is generic HEIF: the compatible brands say AVIF or HEIC.
        size = _u32be(content, 0)
        compatible = content[16:size]
        if b'avif' in compatible:
            return 'avif'
    return kind

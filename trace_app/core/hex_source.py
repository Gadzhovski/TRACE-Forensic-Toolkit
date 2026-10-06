"""What the hex view reads, and what it says about the bytes (no Qt).

- A *source* is a file's bytes, read a page at a time: `BytesSource` over
  bytes already in memory (an archive member, a carve, unallocated space),
  `ImageFileSource` over a file on the image, read on demand -- a 20 GB
  pagefile is browsed without being read. `clone()` gives a search thread a
  reader of its own.
- `image_offset(file_offset)` is where a byte of the file lies on the image,
  from the file system's data runs (None for a resident or sparse part, or
  a volume that is not the image's own bytes: an unlocked BitLocker volume,
  a shadow copy, an APFS/LVM/XFS volume read through libyal, logical
  evidence).
- `interpret(data, little)` reads bytes at the cursor as integers, floats
  and the time formats evidence keeps.
- `copy_as(data, kind)` writes a selection as hex, a C array, a Python
  bytes literal, Base64 or text.
"""

import base64
import datetime
import logging
import struct
import uuid

logger = logging.getLogger('TRACE.HexSource')

#: Bytes the inspector reads at the cursor.
INSPECT_BYTES = 16


class BytesSource:
    """Bytes in memory. `base` is the image offset of byte 0 when the bytes
    are one contiguous stretch of the image (unallocated space, a carve that
    was not rebuilt), else None."""

    def __init__(self, data, base=None, sector_size=512):
        self.data = bytes(data or b'')
        self.size = len(self.data)
        self.base = base
        self.sector_size = sector_size

    def read(self, offset, length):
        return self.data[offset:offset + length]

    def clone(self):
        return self

    def image_offset(self, file_offset):
        if self.base is None or not 0 <= file_offset < self.size:
            return None
        return self.base + file_offset

    def contiguous(self, begin, end):
        return self.base is not None

    def describe(self):
        return None


class ImageFileSource:
    """A file on the image, read when a page is shown."""

    def __init__(self, handler, inode, start_offset):
        self.handler = handler
        self.inode = int(inode)
        self.start_offset = start_offset
        fs = handler.get_fs_info(start_offset)
        if fs is None:
            raise OSError("The file system could not be opened")
        self._fs = fs
        self._entry = fs.open_meta(inode=self.inode)
        self.size = int(self._entry.info.meta.size)
        self.sector_size = int(getattr(handler, 'sector_size', 512) or 512)
        self._extents = None
        self.resident = False

    def read(self, offset, length):
        length = min(length, self.size - offset)
        if length <= 0:
            return b''
        return bytes(self._entry.read_random(offset, length))

    def clone(self):
        """A reader of its own, for a search running beside the view."""
        return ImageFileSource(self.handler, self.inode, self.start_offset)

    # --- where the bytes are on the image -------------------------------------

    def _volume_base(self):
        """The image offset of the volume's byte 0, or None when the volume
        is not the image's own bytes."""
        from trace_app.core import containers
        handler = self.handler
        if getattr(handler, 'is_logical', False) or \
                self.start_offset >= containers.SHADOW_KEY_BASE or \
                self.start_offset in getattr(handler, '_volumes', {}):
            return None
        if not hasattr(self._fs, 'info') or \
                not hasattr(self._fs.info, 'block_size'):
            return None
        return int(self.start_offset) * int(handler.sector_size)

    def extents(self):
        """[(file offset, image offset or None, length)] of the default data
        stream, in file order; [] if resident or unknown."""
        if self._extents is not None:
            return self._extents
        self._extents = []
        base = self._volume_base()
        if base is None:
            return self._extents
        try:
            import pytsk3
            from trace_app.core.deleted import _DATA_TYPES
            block = int(self._fs.info.block_size)
            for attribute in self._entry:
                info = attribute.info
                if info.type not in _DATA_TYPES:
                    continue
                if info.name and info.name not in (b'$Data', b''):
                    continue
                if not int(info.flags) & pytsk3.TSK_FS_ATTR_NONRES:
                    self.resident = True
                    return self._extents
                for run in attribute:
                    if not run.len:
                        continue
                    sparse = int(run.flags) & (
                        pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE |
                        pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER)
                    self._extents.append((
                        int(run.offset) * block,
                        None if sparse else base + int(run.addr) * block,
                        int(run.len) * block))
                break
        except Exception as exc:
            logger.debug("No data runs for inode %s: %s", self.inode, exc)
            self._extents = []
        return self._extents

    def image_offset(self, file_offset):
        for begin, image, length in self.extents():
            if begin <= file_offset < begin + length:
                return None if image is None else image + file_offset - begin
        return None

    def contiguous(self, begin, end):
        """Whether file bytes [begin, end) lie in one stretch of the image."""
        first = self.image_offset(begin)
        last = self.image_offset(end - 1)
        return first is not None and last is not None and \
            last - first == end - 1 - begin

    def describe(self):
        if self.resident:
            return "resident in its file record"
        return None


# --- the data inspector ---------------------------------------------------------

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
_HFS_EPOCH = datetime.datetime(1904, 1, 1, tzinfo=datetime.timezone.utc)
_COCOA_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)


def _when(epoch, seconds):
    try:
        moment = epoch + datetime.timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return None
    if not 1970 <= moment.year <= 2100:
        return None                     # not a plausible time
    text = moment.strftime('%Y-%m-%d %H:%M:%S')
    fraction = seconds - int(seconds)
    if fraction:
        text += f".{int(round(fraction * 1_000_000)):06d}".rstrip('0') \
            .rstrip('.')
    return text + ' UTC'


def _dos(value):
    """FAT's date and time: low word time, high word date; local, no zone."""
    time, date = value & 0xFFFF, value >> 16
    try:
        moment = datetime.datetime(
            1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F,
            time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2)
    except ValueError:
        return None
    return moment.strftime('%Y-%m-%d %H:%M:%S') + ' (local, no zone)'


def interpret(data, little=True):
    """[(label, value text)] for the bytes at the cursor. A value the bytes
    are too short for, or that makes no sense as that type, reads '—'."""
    data = bytes(data or b'')
    order = '<' if little else '>'
    rows = []

    def number(label, code, size):
        if len(data) < size:
            rows.append((label, '—'))
            return None
        value = struct.unpack(order + code, data[:size])[0]
        rows.append((label, f"{value:,}" if isinstance(value, int)
                     else f"{value:.9g}"))
        return value

    if data:
        rows.append(("Binary", f"{data[0]:08b}"))
    number("Int8", 'b', 1)
    number("UInt8", 'B', 1)
    number("Int16", 'h', 2)
    number("UInt16", 'H', 2)
    number("Int32", 'i', 4)
    u32 = number("UInt32", 'I', 4)
    number("Int64", 'q', 8)
    u64 = number("UInt64", 'Q', 8)
    number("Float32", 'f', 4)
    f64 = number("Float64", 'd', 8)

    def time(label, value):
        rows.append((label, value or '—'))

    time("FILETIME", _when(_FILETIME_EPOCH, u64 / 10_000_000)
         if u64 is not None else None)
    time("Unix time (32-bit)", _when(_UNIX_EPOCH, u32)
         if u32 is not None else None)
    time("Unix time (ms, 64-bit)", _when(_UNIX_EPOCH, u64 / 1000)
         if u64 is not None else None)
    time("Chrome / WebKit time", _when(_FILETIME_EPOCH, u64 / 1_000_000)
         if u64 is not None else None)
    time("DOS date and time", _dos(u32) if u32 is not None and little
         else None)
    time("HFS+ time", _when(_HFS_EPOCH, u32) if u32 is not None else None)
    # A double near zero is not a time: Apple's epoch itself is no answer.
    plausible = f64 is not None and f64 == f64 and 1 <= abs(f64) < 4e9
    time("Apple absolute time", _when(_COCOA_EPOCH, f64)
         if plausible else None)
    if len(data) >= 16:
        guid = uuid.UUID(bytes_le=data[:16]) if little else \
            uuid.UUID(bytes=data[:16])
        rows.append(("GUID", '{' + str(guid).upper() + '}'))
    else:
        rows.append(("GUID", '—'))
    if len(data) >= 2:
        unit = struct.unpack(order + 'H', data[:2])[0]
        character = chr(unit) if not 0xD800 <= unit <= 0xDFFF else ''
        # With its code point: a font may have no glyph for it.
        rows.append(("UTF-16 character", f"{character} (U+{unit:04X})"
                     if character.isprintable() and character.strip()
                     else '—'))
    return rows


# --- copying a selection ---------------------------------------------------------

COPY_KINDS = (('hex', "Hex (4A 46 49 46)"), ('hex_compact', "Hex (4a464946)"),
              ('c', "C array"), ('python', "Python bytes"),
              ('base64', "Base64"), ('text', "Text (printable)"))


def copy_as(data, kind):
    data = bytes(data)
    if kind == 'hex':
        return ' '.join(f"{b:02X}" for b in data)
    if kind == 'hex_compact':
        return data.hex()
    if kind == 'c':
        lines = [', '.join(f"0x{b:02X}" for b in data[i:i + 12])
                 for i in range(0, len(data), 12)]
        return (f"unsigned char data[{len(data)}] = {{\n    "
                + ',\n    '.join(lines) + "\n};")
    if kind == 'python':
        return repr(data)
    if kind == 'base64':
        return base64.b64encode(data).decode('ascii')
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)


def find_all(source, needle, fold=False, limit=10000, chunk=4 * 1024 * 1024,
             stop=None):
    """Every offset `needle` starts at in `source`, read a chunk at a time
    (overlapping by the needle's length, so nothing straddling two chunks
    is missed). `fold`: compare ASCII letters in any case. `stop()` ends
    it early."""
    if not needle:
        return []
    if fold:
        needle = needle.lower()
    found = []
    position = 0
    keep = len(needle) - 1
    tail = b''
    while position < source.size and len(found) < limit:
        if stop and stop():
            break
        block = source.read(position, chunk)
        if not block:
            break
        window = tail + block
        if fold:
            window = window.lower()
        origin = position - len(tail)
        index = window.find(needle)
        while index != -1 and len(found) < limit:
            found.append(origin + index)
            index = window.find(needle, index + 1)
        # The tail carried into the next window is one byte shorter than
        # the needle: nothing found here can be found there again.
        tail = window[-keep:] if keep else b''
        position += len(block)
    return found

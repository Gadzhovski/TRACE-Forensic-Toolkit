"""QNX image file systems (IFS boot images) read in pure Python (no Qt).

What a QNX system boots: the kernel (procnto), startup code, the boot
script and the drivers and libraries needed before any disk is mounted --
head units keep them in `ifs*` partitions or files (.boot on QNX4, /.boot
or ifs-*.bin on QNX6). The Sleuth Kit reads none of it. The layout, as
QNX's sys/startup.h and sys/image.h give it and QNX's dumpifs reads it:

* optionally a boot prefix (BIOS/IPL code), then the startup header
  (signature 0x00FF7EEB in the image's byte order -- bit 1 of flags1 says
  big-endian -- header size 0x100, its zero fields zero): startup_size
  bytes of startup code, never compressed, then the image file system;
* flags1 bits 2-4: the image file system is stored as is, zlib (one gzip
  stream), LZO1X or UCL NRV2B -- these two in blocks, each a 2-byte
  big-endian length and the compressed bytes, a zero length ending them;
* the image file system: 'imagefs', flags (bit 0 big-endian), its size,
  where the directory ends and starts, the boot and script inodes, the
  mount point; then directory entries -- size, extended attributes'
  offset, inode, mode, gid, uid, mtime, and per kind: a file's offset
  (from the image header) and size, a symlink's target, a device's
  numbers -- each with its path (no leading slash);
* a trailer: a 32-bit word making the sum of the image's words zero.

Folders a path names but no entry lists are made (as dumpifs makes them
when extracting). An image with no startup header (a secondary IFS) is
found by its 'imagefs' signature. Checked against dumpifs (askac/dumpifs,
QNX's own source) on openqnx's real UCL image and on that image stored
plain, with zlib and with LZO (tests/test_qnx_ifs.py).
"""

import hashlib
import io
import logging
import stat
import struct
import zlib
from collections import OrderedDict

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.QNX IFS')

KIND = 'QNX IFS'
STARTUP_SIGNATURE = 0x00FF7EEB
IMAGE_SIGNATURE = b'imagefs'
HEADER_SIZE = 0x100
COMPRESS_MASK = 0x1C
NONE, ZLIB, LZO, UCL = 0x00, 0x04, 0x08, 0x0C
COMPRESSIONS = {NONE: 'none', ZLIB: 'zlib', LZO: 'LZO', UCL: 'UCL'}
#: Where a startup header is looked for: an IPL / BIOS prefix precedes it.
SEARCH = 1 << 20
#: The decompressed image file system, at most.
MAX_IMAGE = 512 << 20
ROOT = 1
#: Inode numbers keep flags in their top bits (IFS_INO_PROCESSED_ELF...).
INO_MASK = 0x0FFFFFFF


class IfsError(Exception):
    pass


def find_startup(head):
    """(offset, byte order) of a valid startup header in `head`, or None."""
    for order in ('<', '>'):
        signature = struct.pack(order + 'I', STARTUP_SIGNATURE)
        at = head.find(signature)
        while at >= 0:
            raw = head[at:at + HEADER_SIZE]
            if len(raw) >= 64:
                header_size = struct.unpack_from(order + 'H', raw, 8)[0]
                zeros = raw[50:64]          # zero0, zero[3]
                flags1 = raw[6]
                big = bool(flags1 & 0x02)
                if header_size == HEADER_SIZE and not any(zeros) and \
                        big == (order == '>'):
                    return at, order
            at = head.find(signature, at + 1)
    return None


def _blocks(read, at, decode, limit):
    out = bytearray()
    while True:
        length = struct.unpack('>H', read(at, 2))[0]
        at += 2
        if not length:
            return bytes(out)
        out += decode(read(at, length))
        at += length
        if len(out) > limit:
            raise IfsError("the image file system is larger than TRACE "
                           "reads")


class IfsImage:
    """The image file system on `source` (a file object), decompressed into
    memory when it is stored compressed."""

    def __init__(self, source):
        self.source = source
        source.seek(0, 2)
        self.size = source.tell()
        head = self._read(0, min(self.size, SEARCH))
        self.startup = None
        self.compression = 'none'
        found = find_startup(head)
        if found is not None:
            self.startup, order = found
            raw = self._read(self.startup, HEADER_SIZE)
            (self.flags1, startup_size, stored_size) = (
                raw[6], *struct.unpack_from(order + 'I', raw, 32),
                *struct.unpack_from(order + 'I', raw, 36))
            self.startup_size = startup_size
            self.stored_size = stored_size
            method = self.flags1 & COMPRESS_MASK
            if method not in COMPRESSIONS:
                raise IfsError(f"unknown compression {method:#x}")
            self.compression = COMPRESSIONS[method]
            start = self.startup + startup_size
            if method == NONE:
                at = self._find_image(start)
                self.image = None
                self.image_offset = at
            else:
                self.image = self._decompress(method, start)
                at = self.image.find(IMAGE_SIGNATURE)
                if at < 0:
                    raise IfsError("no image file system after decompressing")
                self.image = self.image[at:]
                self.image_offset = 0
        else:
            at = self._find_image(0)
            self.image = None
            self.image_offset = at
        self._header()
        self.entries = self._directory()

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def _find_image(self, start):
        head = self._read(start, min(self.size - start, SEARCH))
        at = head.find(IMAGE_SIGNATURE)
        while at >= 0:
            if self._plausible(head[at:at + 64], self.size - start - at):
                return start + at
            at = head.find(IMAGE_SIGNATURE, at + 1)
        raise IfsError("no image file system header")

    @staticmethod
    def _plausible(raw, room):
        if len(raw) < 64:
            return False
        order = '>' if raw[7] & 0x01 else '<'
        size, dir_end, dir_start = struct.unpack_from(order + 'III', raw, 8)
        return 0 < dir_start < dir_end <= size <= room + 4

    def _decompress(self, method, at):
        if method == ZLIB:
            stream = zlib.decompressobj(47)     # gzip or zlib header
            out = bytearray()
            while not stream.eof:
                chunk = self._read(at, 1 << 20)
                if not chunk:
                    break
                out += stream.decompress(chunk, MAX_IMAGE - len(out))
                if len(out) >= MAX_IMAGE:
                    raise IfsError("the image file system is larger than "
                                   "TRACE reads")
                at += len(chunk) - len(stream.unused_data)
                if stream.unconsumed_tail:
                    raise IfsError("the image file system is larger than "
                                   "TRACE reads")
            return bytes(out)
        if method == LZO:
            from trace_app.core.btrfs import lzo1x_decompress

            def decode(data):
                return lzo1x_decompress(data, 1 << 17)
        else:
            from trace_app.core.ucl import nrv2b_decompress

            def decode(data):
                return nrv2b_decompress(data, 1 << 17)
        try:
            return _blocks(self._read, at, decode, MAX_IMAGE)
        except IfsError:
            raise
        except Exception as exc:
            raise IfsError(f"{self.compression} block damaged: {exc}") \
                from None

    def image_bytes(self, offset, length):
        """Bytes of the image file system, from its header."""
        if self.image is not None:
            return self.image[offset:offset + length]
        return self._read(self.image_offset + offset, length)

    def _header(self):
        raw = self.image_bytes(0, 128)
        if raw[:7] != IMAGE_SIGNATURE:
            raise IfsError("no 'imagefs' signature")
        self.flags = raw[7]
        self.order = '>' if self.flags & 0x01 else '<'
        (self.image_size, self.dir_end, self.dir_start) = \
            struct.unpack_from(self.order + 'III', raw, 8)
        self.boot_inodes = struct.unpack_from(self.order + '4I', raw, 20)
        self.script_inode = struct.unpack_from(self.order + 'I', raw, 36)[0]
        self.mountflags = struct.unpack_from(self.order + 'I', raw, 84)[0]
        self.mountpoint = raw[88:].split(b'\0', 1)[0].decode(
            'utf-8', 'replace') or '/'

    def checksum_ok(self):
        """True when the image's 32-bit words, trailer included, sum to
        zero -- the trailer mkifs writes."""
        data = self.image_bytes(0, self.image_size)
        if len(data) < self.image_size or self.image_size % 4:
            return False
        words = struct.unpack(f'{self.order}{self.image_size // 4}I', data)
        return sum(words) & 0xFFFFFFFF == 0

    def _directory(self):
        out = []
        at = self.dir_start
        order = self.order
        while at + 24 <= self.dir_end:
            raw = self.image_bytes(at, 24)
            size, _ext, ino, mode, gid, uid, mtime = struct.unpack(
                order + 'HHIIIII', raw)
            if size < 24:
                break
            body = self.image_bytes(at + 24, size - 24)
            at += size
            if not ino:
                continue
            entry = {'ino': ino, 'mode': mode, 'gid': gid, 'uid': uid,
                     'mtime': mtime, 'size': 0}
            kind = stat.S_IFMT(mode)
            if kind == stat.S_IFREG:
                entry['offset'], entry['size'] = struct.unpack_from(
                    order + 'II', body)
                path = body[8:]
            elif kind == stat.S_IFLNK:
                sym_offset, sym_size = struct.unpack_from(order + 'HH', body)
                path = body[4:]
                entry['target'] = path[sym_offset:sym_offset + sym_size] \
                    .split(b'\0', 1)[0]
                entry['size'] = len(entry['target'])
            elif kind == stat.S_IFDIR:
                path = body
            else:
                entry['dev'], entry['rdev'] = struct.unpack_from(
                    order + 'II', body)
                path = body[8:]
            entry['path'] = path.split(b'\0', 1)[0].strip(b'/')
            out.append(entry)
        return out

    def read(self, entry, offset, length):
        if 'offset' not in entry:
            if 'target' in entry:
                return entry['target'][offset:offset + length]
            return b''
        end = min(entry['size'], offset + length)
        if offset >= end:
            return b''
        return self.image_bytes(entry['offset'] + offset, end - offset)


class IfsEntry:
    def __init__(self, image, node, parent):
        self._image = image
        self._node = node
        entry = node['entry']
        self.identifier = node['id']
        self.parent_identifier = parent
        self.name = node['name'].decode('utf-8', 'surrogateescape')
        self.file_mode = entry['mode']
        self.size = 0 if stat.S_ISDIR(entry['mode']) else entry['size']
        self.owner_identifier = entry['uid']
        self.group_identifier = entry['gid']

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._node['entry']['mtime'] * 1_000_000_000

    @property
    def symbolic_link_target(self):
        target = self._node['entry'].get('target')
        return target.decode('utf-8', 'surrogateescape') if target else ''

    @property
    def number_of_sub_file_entries(self):
        return len(self._node['children'])

    def get_sub_file_entry(self, index):
        return IfsEntry(self._image, self._node['children'][index],
                        self.identifier)

    def read_buffer_at_offset(self, length, offset):
        return self._image.read(self._node['entry'], offset, length)


class _Volume:
    def __init__(self, image):
        self.image = image
        root_entry = next((e for e in image.entries if not e['path']), None)
        if root_entry is None:
            root_entry = {'ino': ROOT, 'mode': stat.S_IFDIR | 0o755,
                          'gid': 0, 'uid': 0, 'mtime': 0, 'size': 0}
        self.root = {'id': ROOT, 'name': b'', 'entry': root_entry,
                     'children': []}
        self.nodes = {ROOT: self.root}
        folders = {b'': self.root}
        used = {ROOT}
        spare = max([e['ino'] & INO_MASK for e in image.entries] + [ROOT]) + 1

        def ident(entry):
            nonlocal spare
            number = entry['ino'] & INO_MASK
            if number in used:
                number, spare = spare, spare + 1
            used.add(number)
            return number

        def folder(path):
            nonlocal spare
            node = folders.get(path)
            if node is not None:
                return node
            parent_path, _, name = path.rpartition(b'/')
            parent = folder(parent_path)
            entry = {'ino': 0, 'mode': stat.S_IFDIR | 0o755, 'gid': 0,
                     'uid': 0, 'mtime': 0, 'size': 0}
            node = {'id': spare, 'name': name, 'entry': entry,
                    'children': []}
            used.add(spare)
            spare += 1
            parent['children'].append(node)
            folders[path] = node
            self.nodes[node['id']] = node
            return node

        for entry in image.entries:
            if not entry['path']:
                continue
            parent_path, _, name = entry['path'].rpartition(b'/')
            parent = folder(parent_path)
            if stat.S_ISDIR(entry['mode']):
                node = folders.get(entry['path'])
                if node is not None:
                    node['entry'] = entry       # listed after its contents
                    continue
                node = {'id': ident(entry), 'name': name, 'entry': entry,
                        'children': []}
                folders[entry['path']] = node
            else:
                node = {'id': ident(entry), 'name': name, 'entry': entry,
                        'children': []}
            parent['children'].append(node)
            self.nodes[node['id']] = node

    def get_root_directory(self):
        root = IfsEntry(self.image, self.root, ROOT)
        root.name = ''
        return root

    def entry(self, identifier):
        node = self.nodes.get(identifier)
        if node is None:
            return None
        parent = next((n['id'] for n in self.nodes.values()
                       if node in n['children']), ROOT)
        return IfsEntry(self.image, node, parent)

    def get_file_entry_by_path(self, path):
        node = self.root
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            raw = part.encode('utf-8', 'surrogateescape')
            node = next((c for c in node['children'] if c['name'] == raw),
                        None)
            if node is None:
                return None
        return IfsEntry(self.image, node, ROOT)


class IfsFileSystem(LibyalFileSystem):
    KIND = KIND
    BLOCK_SIZE = 4096

    def __init__(self, image):
        self.image = image
        size = image.size
        if image.startup is not None:
            size = min(size, image.startup + image.stored_size)
        else:
            size = min(size, image.image_offset + image.image_size)
        detail = f"QNX IFS ({image.compression})" \
            if image.compression != 'none' else "QNX IFS"
        super().__init__(_Volume(image), size, detail)

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        # Everything up to the image's end is the image (code, headers,
        # files, the compressed stream).
        return [(0, self.info.block_count * self.info.block_size or
                 self.image.size)]

    def facts(self):
        image = self.image
        out = {'Compression': image.compression,
               'Mount point': image.mountpoint,
               'Checksum': 'correct' if image.checksum_ok() else 'wrong'}
        if image.startup is not None:
            out['Startup header at'] = str(image.startup)
        return out


def _time(seconds):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(
            seconds, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return ''


#: Images opened from bytes, by digest: listing an archive and reading
#: each member must not decompress the whole image each time.
_CACHE = OrderedDict()
CACHED_IMAGES = 4


def _from_bytes(data):
    data = bytes(data)
    digest = hashlib.blake2b(data, digest_size=16).digest()
    image = _CACHE.get(digest)
    if image is None:
        image = IfsImage(io.BytesIO(data))
        _CACHE[digest] = image
        while len(_CACHE) > CACHED_IMAGES:
            _CACHE.popitem(last=False)
    else:
        _CACHE.move_to_end(digest)
    return image


def members(data):
    """An IFS file's entries as archive members (core/archives.py, kind
    'qnx_ifs'): a .boot or ifs-*.bin seen inside another file system."""
    image = _from_bytes(data)
    out = []
    for entry in image.entries:
        if not entry['path']:
            continue
        out.append({'name': entry['path'].decode('utf-8', 'surrogateescape'),
                    'size': entry['size'],
                    'is_dir': stat.S_ISDIR(entry['mode']),
                    'is_link': stat.S_ISLNK(entry['mode']),
                    'modified': _time(entry['mtime'])})
    return out


def read_member(data, name, limit=None):
    image = _from_bytes(data)
    raw = name.encode('utf-8', 'surrogateescape').strip(b'/')
    for entry in image.entries:
        if entry['path'] == raw and not stat.S_ISDIR(entry['mode']):
            size = entry['size'] if limit is None else min(entry['size'],
                                                           limit)
            return image.read(entry, 0, size)
    raise IfsError(f"No member {name!r}")


def looks_like_ifs(head):
    return find_startup(head[:SEARCH]) is not None or \
        head[:7] == IMAGE_SIGNATURE


def open_ifs(source):
    try:
        source.seek(0)
        head = source.read(SEARCH)
        if not looks_like_ifs(head):
            return None
        return IfsFileSystem(IfsImage(source))
    except (IfsError, struct.error, OSError, IOError) as exc:
        logger.warning("QNX IFS not opened: %s", exc)
        return None

"""YAFFS2 (and YAFFS1) read in pure Python (no Qt).

YAFFS is the NAND file system of older Android phones, cameras and
embedded Linux: a dump of the chip with each page's spare bytes. There is
no superblock -- every page carries its tags in its spare area, and the
file system is rebuilt from them -- and the page size, the spare size and
where in the spare the tags sit are recorded nowhere: they differ with
the NAND controller. So each common geometry (`GEOMETRIES`) and every tag
offset in the spare, in either byte order, is tried, and the layout kept
is the one whose reconstruction is consistent: the files whose data adds
up to exactly the size their own header records.

YAFFS2 tags (yaffs_packedtags2.c): sequence number (per erase block,
increasing), object id, chunk id (0 = the object's header; n = its data
from (n-1) * page size), bytes used. YAFFS's own code, unlike
mkyaffs2image, keeps extra header information in the tags: chunk id with
bit 31 set holds the parent id (bits 30/29: shrink, shadows), the object
id's top four bits the object type, the byte count a file's size.

The object header (yaffs_guts.h, struct yaffs_obj_hdr): type, parent,
name (256 bytes), mode, uid, gid, atime, mtime, ctime, size (low, then
high at 496), equivalent object (a hard link), alias (a symlink's
target), shadows (an object a rename replaced). Its byte order can differ
from the tags' (an image made for a big-endian CPU).

Read as YAFFS2's own scan reads it: pages newest first (sequence, then
place), the newest header and the newest copy of each data chunk win, a
file's size is its newest header's or the end of data written after it,
whichever is further, data past it is ignored and a missing chunk inside
it reads as zeros. Objects filed under unlinked (3) or deleted (4) are
gone; lost+found (2) is always listed, as YAFFS lists it. Live files
only. Checked against Aleph One's image makers' images and YAFFS's own
code (qnxprobe's fixtures and the hashes and stat lines recorded from
the source trees -- tests/test_flash_filesystems.py).
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.YAFFS')

KIND = 'YAFFS2'
#: (page, spare) sizes tried, likeliest first.
GEOMETRIES = ((2048, 64), (512, 16), (4096, 128), (4096, 224),
              (4096, 256), (8192, 256), (8192, 448), (8192, 640),
              (2048, 128), (1024, 32), (16384, 1280))
ROOT, LOST_FOUND, UNLINKED, DELETED = 1, 2, 3, 4
FILE, SYMLINK, DIRECTORY, HARDLINK, SPECIAL = 1, 2, 3, 4, 5
EXTRA_HEADER = 0x80000000
EXTRA_SHRINK = 0x40000000
ALL_EXTRA = 0xF0000000
#: lost+found's and the root's modes, as YAFFS makes them at mount time
#: when the flash holds no header for them (yaffs_guts.h).
LOST_FOUND_MODE = stat.S_IFDIR | 0o700
ROOT_MODE = stat.S_IFDIR | 0o755
LOWEST_SEQUENCE = 0x00001000
HIGHEST_SEQUENCE = 0xEFFFFF00
#: Pages looked at to choose the layout.
PROBE_PAGES = 4096
HEADER_SIZE = 512


class YaffsError(Exception):
    pass


def _type_mode(kind):
    return {FILE: stat.S_IFREG, SYMLINK: stat.S_IFLNK,
            DIRECTORY: stat.S_IFDIR}.get(kind)


def parse_header(data, order):
    """An object header's fields, or None when it does not read as one."""
    if len(data) < HEADER_SIZE:
        return None
    kind, parent = struct.unpack_from(order + 'II', data, 0)
    if not FILE <= kind <= SPECIAL:
        return None
    (mode, uid, gid, atime, mtime, ctime, size_low, equivalent) = \
        struct.unpack_from(order + 'IIIIIIIi', data, 268)
    size_high = struct.unpack_from(order + 'I', data, 496)[0]
    shadows = struct.unpack_from(order + 'i', data, 504)[0]
    shrink = struct.unpack_from(order + 'I', data, 508)[0]
    want = _type_mode(kind)
    if want is not None and stat.S_IFMT(mode & 0xFFFF) not in (want, 0):
        return None
    if size_high == 0xFFFFFFFF:
        size_high = 0
    return {'type': kind, 'parent': parent,
            # 255 bytes at most: mkyaffsimage leaves a full-length name
            # unterminated (the field's last byte stays 0xFF).
            'name': data[10:10 + 255].split(b'\0', 1)[0],
            'mode': mode & 0xFFFF, 'uid': uid, 'gid': gid, 'atime': atime,
            'mtime': mtime, 'ctime': ctime,
            'size': size_low | (size_high << 32),
            'equivalent': equivalent,
            'alias': data[300:300 + 160].split(b'\0', 1)[0],
            'shadows': shadows if shadows > 0 else 0,
            'shrink': shrink == 1}


class _Layout:
    def __init__(self, page, spare, offset, tag_order, header_order):
        self.page, self.spare = page, spare
        self.stride = page + spare
        self.offset = offset
        self.tag_order, self.header_order = tag_order, header_order


class YaffsImage:
    """A YAFFS2 file system rebuilt from the pages of `source`."""

    def __init__(self, source, size, layout):
        self.source = source
        self.size = size
        self.layout = layout
        self.page_size = layout.page
        self.headers = {}       # obj -> (seq, index, header)
        self.chunks = {}        # obj -> {chunk: (seq, index, nbytes)}
        self.tag_types = {}     # obj -> type from tags (YAFFS's own code)
        #: obj -> [(seq, index, size)]: where a file was cut short.
        self.shrinks = {}
        #: Every copy, not only the newest: obj -> [(seq, index, header)]
        #: and obj -> {chunk: [(seq, index, nbytes)]} -- the older versions
        #: and deleted files core/yaffs_recover.py rebuilds.
        self.all_headers = {}
        self.all_chunks = {}
        self._scan()
        self._settle()

    def _pages(self):
        layout = self.layout
        count = self.size // layout.stride
        step = 1024
        tag = struct.Struct(layout.tag_order + 'IIII')
        for first in range(0, count, step):
            n = min(step, count - first)
            self.source.seek(first * layout.stride)
            data = self.source.read(n * layout.stride)
            for i in range(n):
                at = i * layout.stride
                spare = data[at + layout.page:at + layout.stride]
                if len(spare) < layout.offset + 16:
                    return
                seq, obj, chunk, nbytes = tag.unpack_from(spare,
                                                          layout.offset)
                if not LOWEST_SEQUENCE <= seq < HIGHEST_SEQUENCE:
                    continue
                yield first + i, seq, obj, chunk, nbytes, \
                    data[at:at + HEADER_SIZE]

    def _scan(self):
        for index, seq, obj, chunk, nbytes, head in self._pages():
            shrink = False
            if chunk & EXTRA_HEADER:
                self.tag_types[obj & 0x0FFFFFFF] = obj >> 28
                obj &= 0x0FFFFFFF
                shrink = bool(chunk & EXTRA_SHRINK)
                chunk = 0
            if chunk == 0:
                header = parse_header(head, self.layout.header_order)
                if header is None:
                    continue
                self.all_headers.setdefault(obj, []).append(
                    (seq, index, header))
                if (shrink or header['shrink']) and header['type'] == FILE:
                    self.shrinks.setdefault(obj, []).append(
                        (seq, index, header['size']))
                key = (seq, index)
                found = self.headers.get(obj)
                if found is None or key > found[:2]:
                    self.headers[obj] = (seq, index, header)
            else:
                if nbytes > self.page_size:
                    continue
                self.all_chunks.setdefault(obj, {}).setdefault(
                    chunk, []).append((seq, index, nbytes))
                chunks = self.chunks.setdefault(obj, {})
                found = chunks.get(chunk)
                if found is None or (seq, index) > found[:2]:
                    chunks[chunk] = (seq, index, nbytes)

    def _settle(self):
        """Sizes, the gone, renames over another name, data cut away."""
        # A chunk written before a shrink and starting past the size the
        # file was cut to is not the file's any more (YAFFS2's scan drops
        # it): the file grown again later reads zeros there.
        for obj, shrinks in self.shrinks.items():
            chunks = self.chunks.get(obj, {})
            for chunk in list(chunks):
                cseq, cindex, _n = chunks[chunk]
                start = (chunk - 1) * self.page_size
                if any((cseq, cindex) < (seq, index) and start >= size
                       for seq, index, size in shrinks):
                    del chunks[chunk]
        self.sizes = {}
        gone = {UNLINKED, DELETED}
        for obj, (seq, index, header) in self.headers.items():
            size = header['size'] if header['type'] == FILE else 0
            if header['type'] == FILE:
                for chunk, (cseq, cindex, nbytes) in \
                        self.chunks.get(obj, {}).items():
                    if (cseq, cindex) > (seq, index):
                        size = max(size, (chunk - 1) * self.page_size +
                                   nbytes)
            self.sizes[obj] = size
        self.live = {}
        for obj, (seq, index, header) in self.headers.items():
            if header['parent'] in gone or obj in gone:
                continue
            self.live[obj] = header
        for obj, (seq, index, header) in self.headers.items():
            shadowed = header['shadows']
            if shadowed and shadowed in self.live:
                other = self.headers[shadowed]
                if other[:2] < (seq, index):
                    del self.live[shadowed]
        # Every object needs a live way up to the root.
        for obj in list(self.live):
            seen, at = set(), obj
            while at not in (ROOT, LOST_FOUND) and at in self.live and \
                    at not in seen:
                seen.add(at)
                at = self.live[at]['parent']
            if at not in (ROOT, LOST_FOUND) and at not in self.live:
                self.live.pop(obj, None)

    def consistent_files(self):
        """Files whose data ends exactly at their header's size: what
        tells the true layout from a misreading."""
        good = 0
        for obj, header in self.live.items():
            if header['type'] != FILE or not header['size']:
                continue
            chunks = self.chunks.get(obj, {})
            if not chunks:
                continue
            last = max(chunks)
            end = (last - 1) * self.page_size + chunks[last][2]
            if end == header['size']:
                good += 1
        return good

    def header(self, obj):
        if obj in self.live:
            return self.live[obj]
        if obj in (ROOT, LOST_FOUND):
            # Made at mount time when the flash holds no header: the
            # mode YAFFS gives them, no time.
            return {'type': DIRECTORY, 'parent': ROOT,
                    'name': b'' if obj == ROOT else b'lost+found',
                    'mode': ROOT_MODE if obj == ROOT else LOST_FOUND_MODE,
                    'uid': 0, 'gid': 0,
                    'atime': 0, 'mtime': 0, 'ctime': 0, 'size': 0,
                    'equivalent': 0, 'alias': b'', 'shadows': 0}
        return None

    def target(self, obj):
        """A hard link's object, followed."""
        header = self.header(obj)
        seen = set()
        while header is not None and header['type'] == HARDLINK and \
                obj not in seen:
            seen.add(obj)
            obj = header['equivalent']
            header = self.header(obj)
        return obj, header

    def children(self, obj):
        out = [(header['name'], child) for child, header
               in self.live.items()
               if header['parent'] == obj and child != obj and
               child not in (ROOT,)]
        if obj == ROOT and LOST_FOUND not in self.live:
            out.append((b'lost+found', LOST_FOUND))
        return sorted(out)

    def read(self, obj, offset, length):
        size = self.sizes.get(obj, 0)
        end = min(size, offset + length)
        if offset >= end:
            return b''
        page = self.page_size
        chunks = self.chunks.get(obj, {})
        out = bytearray()
        number = offset // page + 1
        while (number - 1) * page < end:
            found = chunks.get(number)
            if found is not None:
                self.source.seek(found[1] * self.layout.stride)
                data = self.source.read(page)[:found[2]]
                data += bytes(page - len(data))
            else:
                data = bytes(page)
            begin = max(offset - (number - 1) * page, 0)
            stop = min(end - (number - 1) * page, page)
            out += data[begin:stop]
            number += 1
        return bytes(out)

    def allocated_ranges(self):
        """The pages live objects' current headers and data are in."""
        pages = set()
        for obj in self.live:
            pages.add(self.headers[obj][1])
            if self.live[obj]['type'] == FILE:
                pages.update(found[1] for found in
                             self.chunks.get(obj, {}).values())
        out = []
        stride = self.layout.stride
        for index in sorted(pages):
            begin = index * stride
            if out and out[-1][1] == begin:
                out[-1] = (out[-1][0], begin + stride)
            else:
                out.append((begin, begin + stride))
        return out


class Yaffs1Image(YaffsImage):
    """A YAFFS1 file system: 512-byte pages, 16 spare bytes holding 8 tag
    bytes around the page and block status and the ECC (struct
    yaffs_spare: tags at 0-3, 6-7, 11-12; page status at 4 -- 0 marks a
    deleted page). The tags pack chunk id (20 bits), a 2-bit serial,
    byte count (10 bits), object id (18 bits). There are no sequence
    numbers: of two copies of a page, the newer has the older's serial
    plus one, and a file's size is where its furthest live page ends."""

    def _scan(self):
        stride = self.layout.stride
        count = self.size // stride
        copies = {}           # (obj, chunk) -> (serial, index, nbytes)
        #: Every page's tags: (obj, chunk, serial, index, nbytes, deleted).
        self.copies1 = []
        for first in range(0, count, 1024):
            n = min(1024, count - first)
            self.source.seek(first * stride)
            data = self.source.read(n * stride)
            for i in range(n):
                at = i * stride
                spare = data[at + 512:at + 528]
                if len(spare) < 16:
                    continue                    # cut short
                tags = bytes((spare[0], spare[1], spare[2], spare[3],
                              spare[6], spare[7], spare[11], spare[12]))
                if tags == b'\xff' * 8:
                    continue                    # erased
                low, high = struct.unpack('<II', tags)
                chunk, serial = low & 0xFFFFF, (low >> 20) & 3
                nbytes, obj = (low >> 22) & 0x3FF, high & 0x3FFFF
                self.copies1.append((obj, chunk, serial, first + i, nbytes,
                                     spare[4] != 0xFF))
                if spare[4] != 0xFF:
                    continue                    # a deleted page
                key = (obj, chunk)
                found = copies.get(key)
                if found is not None and \
                        (serial + 1) & 3 == found[0]:
                    continue                    # the older copy
                copies[key] = (serial, first + i, nbytes)
        for (obj, chunk), (_serial, index, nbytes) in copies.items():
            if chunk == 0:
                self.source.seek(index * stride)
                header = parse_header(self.source.read(HEADER_SIZE),
                                      self.layout.header_order)
                if header is not None:
                    self.headers[obj] = (0, index, header)
            elif nbytes <= self.page_size:
                self.chunks.setdefault(obj, {})[chunk] = (0, index, nbytes)

    def _settle(self):
        super()._settle()
        for obj, header in self.live.items():
            chunks = self.chunks.get(obj, {})
            if header['type'] == FILE and chunks:
                last = max(chunks)
                self.sizes[obj] = (last - 1) * self.page_size + \
                    chunks[last][2]


def _yaffs1_layout(source, size):
    """YAFFS1's one layout, when the first pages' spares read as its
    tags and its headers parse; else None."""
    stride = 512 + 16
    if not size or size % stride:
        return None
    # Wide: YAFFS writes where garbage collection freed a block, so the
    # first pages can all be deleted copies (YAFFS's own history image).
    count = min(size // stride, 16384)
    source.seek(0)
    data = source.read(count * stride)
    used = headers = good = 0
    for i in range(count):
        spare = data[i * stride + 512:(i + 1) * stride]
        if spare[5] != 0xFF and spare[5] != 0x00:
            return None                         # no block status
        tags = bytes((spare[0], spare[1], spare[2], spare[3], spare[6],
                      spare[7], spare[11], spare[12]))
        if tags == b'\xff' * 8 or spare[4] != 0xFF:
            continue
        used += 1
        low, high = struct.unpack('<II', tags)
        if low & 0xFFFFF == 0:
            headers += 1
            for order in ('<', '>'):
                if parse_header(data[i * stride:i * stride + 512],
                                order) is not None:
                    good += 1
                    break
    if not used or not headers or good < headers * 0.9:
        return None
    for order in ('<', '>'):
        source.seek(0)
        for i in range(count):
            spare = data[i * stride + 512:(i + 1) * stride]
            low = struct.unpack('<I', bytes(spare[:4]))[0]
            if spare[4] == 0xFF and low & 0xFFFFF == 0 and \
                    parse_header(data[i * stride:i * stride + 512],
                                 order) is not None:
                return _Layout(512, 16, 0, '<', order)
    return None


def _plausible(source, size, page, spare, offset, order):
    """Whether the first pages' tags at `offset` read as YAFFS2 tags."""
    stride = page + spare
    count = min(size // stride, 256)
    source.seek(0)
    data = source.read(count * stride)
    used = good = 0
    for i in range(count):
        at = i * stride + page + offset
        if at + 16 > len(data):
            break
        seq, obj, chunk, nbytes = struct.unpack_from(order + 'IIII', data, at)
        if seq == 0xFFFFFFFF:
            continue
        used += 1
        # A header's byte count means nothing (mkyaffs2image writes 0xFFFF).
        if LOWEST_SEQUENCE <= seq < HIGHEST_SEQUENCE and \
                (obj & 0x0FFFFFFF) < 0x40000 and \
                (chunk & EXTRA_HEADER or chunk == 0 or nbytes <= page):
            good += 1
    return used and good >= used * 0.9


def find_layout(source, size):
    """The layout whose reconstruction is most consistent, or None."""
    best = None
    for page, spare in GEOMETRIES:
        stride = page + spare
        if not size or size % stride:
            continue
        for tag_order in ('<', '>'):
            for offset in range(0, spare - 15):
                if not _plausible(source, size, page, spare, offset,
                                  tag_order):
                    continue
                for header_order in ('<', '>'):
                    layout = _Layout(page, spare, offset, tag_order,
                                     header_order)
                    try:
                        image = YaffsImage(source, min(size, PROBE_PAGES *
                                                       stride), layout)
                    except (YaffsError, struct.error):
                        continue
                    if not image.live:
                        continue
                    # The layout under which the most files add up to
                    # their own size; then the most objects.
                    score = (image.consistent_files(), len(image.live))
                    if best is None or score > best[0]:
                        best = (score, layout)
    return best[1] if best else None


class YaffsEntry:
    """A file or folder, answering what libyal_fs asks a file entry."""

    def __init__(self, image, obj, name=None, parent=ROOT):
        self._image = image
        self.identifier = obj
        self.parent_identifier = parent
        target, header = image.target(obj)
        own = image.header(obj) or header
        self._target = target
        self._header = header
        self.name = (name if name is not None else own['name']).decode(
            'utf-8', 'surrogateescape')
        kind = header['type']
        mode = header['mode']
        if kind == DIRECTORY:
            mode = stat.S_IFDIR | (mode & 0o7777)
        elif kind == SYMLINK:
            mode = stat.S_IFLNK | (mode & 0o7777)
        elif kind == FILE and not stat.S_IFMT(mode):
            # YAFFS's own code keeps a file's permissions only; its type
            # is the header's.
            mode |= stat.S_IFREG
        self.file_mode = mode
        self.size = image.sizes.get(target, 0) if kind == FILE else (
            len(header['alias']) if kind == SYMLINK else 0)
        self.owner_identifier = header['uid']
        self.group_identifier = header['gid']

    def get_number_of_links(self):
        return 1

    def get_modification_time_as_integer(self):
        return self._header['mtime'] * 1_000_000_000

    def get_access_time_as_integer(self):
        return self._header['atime'] * 1_000_000_000

    def get_inode_change_time_as_integer(self):
        return self._header['ctime'] * 1_000_000_000

    @property
    def symbolic_link_target(self):
        if self._header['type'] != SYMLINK:
            return ''
        return self._header['alias'].decode('utf-8', 'surrogateescape')

    def _list(self):
        if self._header['type'] != DIRECTORY:
            return []
        return self._image.children(self.identifier)

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        name, obj = self._list()[index]
        return YaffsEntry(self._image, obj, name, self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if self._header['type'] != FILE:
            return b''
        return self._image.read(self._target, offset, length)


class _Volume:
    def __init__(self, image):
        self.image = image

    def get_root_directory(self):
        return YaffsEntry(self.image, ROOT, b'')

    def entry(self, obj):
        if obj == ROOT:
            return self.get_root_directory()
        header = self.image.header(obj)
        if header is None:
            return None
        return YaffsEntry(self.image, obj, None, header['parent'])

    def get_file_entry_by_path(self, path):
        entry = self.get_root_directory()
        for part in [p for p in path.replace('\\', '/').split('/') if p]:
            for name, obj in self.image.children(entry.identifier):
                if name.decode('utf-8', 'surrogateescape') == part:
                    entry = YaffsEntry(self.image, obj, name,
                                       entry.identifier)
                    break
            else:
                return None
        return entry


class YaffsFileSystem(LibyalFileSystem):
    """A YAFFS NAND image, read like a pytsk3.FS_Info."""

    KIND = KIND

    def __init__(self, image):
        self.image = image
        self.BLOCK_SIZE = image.page_size
        layout = image.layout
        version = 'YAFFS1' if isinstance(image, Yaffs1Image) else 'YAFFS2'
        self.KIND = version
        super().__init__(_Volume(image), image.size,
                         f"{version} ({layout.page}+{layout.spare}-byte "
                         f"pages, tags at {layout.offset})")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _last_identifier(self):
        return max(self.image.headers, default=ROOT)

    def _by_identifier(self, value):
        from trace_app.core.yaffs_recover import VERSION_BASE
        if value >= VERSION_BASE:
            # A deleted file or an earlier version (core/yaffs_recover).
            return self.deleted_scan().entry(value)
        return self.volume.entry(value)

    def allocated_ranges(self):
        return self.image.allocated_ranges()

    def deleted_scan(self, should_stop=None, progress=None):
        """Deleted files and earlier versions (core/yaffs_recover.py),
        rebuilt once per volume."""
        if getattr(self, '_versions', None) is None:
            from trace_app.core.yaffs_recover import VersionScan
            self._versions = VersionScan(self.image)
        return self._versions


def open_yaffs(source, size=None):
    """A YaffsFileSystem over a NAND image with its spare bytes, or None."""
    try:
        if size is None:
            source.seek(0, 2)
            size = source.tell()
        layout = find_layout(source, size)
        if layout is not None:
            return YaffsFileSystem(YaffsImage(source, size, layout))
        layout = _yaffs1_layout(source, size)
        if layout is not None:
            return YaffsFileSystem(Yaffs1Image(source, size, layout))
        return None
    except (YaffsError, struct.error, OSError, IOError) as exc:
        logger.debug("Not YAFFS2: %s", exc)
        return None

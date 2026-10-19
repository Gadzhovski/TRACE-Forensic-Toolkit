"""romfs read in pure Python (no Qt).

The smallest read-only file system of embedded Linux: initial RAM disks,
bootloaders, uClinux. Its layout (the Linux kernel's
Documentation/filesystems/romfs.rst), big-endian, everything aligned to
16 bytes:

* "-rom1fs-", the full size, a checksum over the first 512 bytes, the
  volume name (NUL-padded to 16);
* then file headers: next header (its low 4 bits: bit 3 executable, bits
  0-2 type -- 0 hard link, 1 folder, 2 file, 3 symlink, 4 block device,
  5 character device, 6 socket, 7 FIFO), spec info (a folder: its first
  entry; a hard link: its target), size, checksum, name (NUL-padded to
  16), then the data;
* a folder's entries are a chain through the next fields, '.' and '..'
  among them.

No owners, permissions beyond executable, or times (the kernel shows
none). Checked against unblob's test image and the files unblob extracted
from it (tests/test_flash_filesystems.py).
"""

import logging
import stat
import struct

from trace_app.core.libyal_fs import LibyalFileSystem, PathLookup

logger = logging.getLogger('TRACE.romfs')

KIND = 'romfs'
MAGIC = b'-rom1fs-'
HARDLINK, DIRECTORY, FILE, SYMLINK = 0, 1, 2, 3
_MODES = {DIRECTORY: stat.S_IFDIR | 0o755, FILE: stat.S_IFREG | 0o644,
          SYMLINK: stat.S_IFLNK | 0o777, 4: stat.S_IFBLK | 0o600,
          5: stat.S_IFCHR | 0o600, 6: stat.S_IFSOCK | 0o644,
          7: stat.S_IFIFO | 0o644}
#: Entries of one folder followed, at most (a damaged chain must end).
MAX_ENTRIES = 1 << 20


class RomfsError(Exception):
    pass


def _align(value):
    return (value + 15) & ~15


class RomfsImage:
    def __init__(self, source):
        self.source = source
        head = self._read(0, 512)
        if head[:8] != MAGIC:
            raise RomfsError("no romfs signature")
        self.size = struct.unpack_from('>I', head, 8)[0]
        name_end = head.find(b'\0', 16)
        self.name = head[16:name_end if name_end > 0 else 32]
        self.root = _align(16 + len(self.name) + 1)

    def _read(self, offset, length):
        self.source.seek(offset)
        return self.source.read(length)

    def header(self, offset):
        """{next, type, exec, info, size, name, data} of the file header at
        `offset`."""
        raw = self._read(offset, 16 + 256)
        if len(raw) < 17:
            raise RomfsError(f"no file header at {offset}")
        following, info, size, _checksum = struct.unpack_from('>IIII', raw)
        end = raw.find(b'\0', 16)
        name = raw[16:end if end > 0 else len(raw)]
        return {'next': following & ~15, 'type': following & 7,
                'exec': bool(following & 8), 'info': info, 'size': size,
                'name': name, 'data': offset + _align(16 + len(name) + 1),
                'offset': offset}

    def resolve(self, entry):
        """A hard link's target header, followed."""
        seen = set()
        while entry['type'] == HARDLINK and entry['offset'] not in seen:
            seen.add(entry['offset'])
            entry = self.header(entry['info'] & ~15)
        return entry

    def entries(self, folder):
        out, offset = [], folder['info'] & ~15
        seen = set()
        while offset and offset not in seen and len(out) < MAX_ENTRIES:
            seen.add(offset)
            entry = self.header(offset)
            if entry['name'] not in (b'.', b'..'):
                out.append(entry)
            offset = entry['next']
        return out

    def read(self, entry, offset, length):
        end = min(entry['size'], offset + length)
        if offset >= end:
            return b''
        return self._read(entry['data'] + offset, end - offset)


class RomfsEntry:
    def __init__(self, image, entry, parent):
        self._image = image
        self._entry = entry
        self._target = image.resolve(entry)
        self.identifier = entry['offset']
        self.parent_identifier = parent
        self.name = entry['name'].decode('utf-8', 'surrogateescape')
        kind = self._target['type']
        mode = _MODES.get(kind, stat.S_IFREG | 0o644)
        if self._target['exec'] and kind == FILE:
            mode |= 0o111
        self.file_mode = mode
        self.size = self._target['size'] if kind in (FILE, SYMLINK) else 0
        self.owner_identifier = self.group_identifier = 0

    def get_number_of_links(self):
        return 1

    @property
    def symbolic_link_target(self):
        if self._target['type'] != SYMLINK:
            return ''
        return self._image.read(self._target, 0, self._target['size']).rstrip(
            b'\0').decode('utf-8', 'surrogateescape')

    def _list(self):
        if self._target['type'] != DIRECTORY:
            return []
        try:
            return self._image.entries(self._target)
        except (RomfsError, struct.error) as exc:
            logger.warning("romfs folder %s unreadable: %s", self.name, exc)
            return []

    @property
    def number_of_sub_file_entries(self):
        return len(self._list())

    def get_sub_file_entry(self, index):
        return RomfsEntry(self._image, self._list()[index], self.identifier)

    def read_buffer_at_offset(self, length, offset):
        if self._target['type'] not in (FILE, SYMLINK):
            return b''
        return self._image.read(self._target, offset, length)


class _Volume(PathLookup):
    def __init__(self, image):
        self.image = image
        self._index = None

    def get_root_directory(self):
        root = self.image.header(self.image.root)
        if root['type'] != DIRECTORY:
            raise RomfsError("the first file header is not the root folder")
        entry = RomfsEntry(self.image, root, self.image.root)
        entry.name = ''
        return entry

    def entry(self, identifier):
        root = self.get_root_directory()
        if identifier == root.identifier:
            return root
        if self._index is None:
            self._index = {}
            pending = [root]
            while pending:
                folder = pending.pop()
                for index in range(folder.number_of_sub_file_entries):
                    child = folder.get_sub_file_entry(index)
                    if child.identifier in self._index:
                        continue
                    self._index[child.identifier] = child
                    if stat.S_ISDIR(child.file_mode):
                        pending.append(child)
        return self._index.get(identifier)


class RomfsFileSystem(LibyalFileSystem):
    KIND = KIND
    BLOCK_SIZE = 1024

    def __init__(self, image):
        self.image = image
        super().__init__(_Volume(image), image.size, "romfs")

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return self.image.root

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return [(0, self.image.size)]


def open_romfs(source):
    try:
        source.seek(0)
        if source.read(8) != MAGIC:
            return None
        image = RomfsImage(source)
        fs = RomfsFileSystem(image)
        fs.volume.get_root_directory()
        return fs
    except (RomfsError, struct.error, OSError, IOError) as exc:
        logger.debug("Not romfs: %s", exc)
        return None

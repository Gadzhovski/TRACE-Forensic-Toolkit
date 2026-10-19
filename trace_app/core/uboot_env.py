"""The U-Boot environment, read as a one-file volume (no Qt).

Routers, cameras, set-top boxes and head units boot with U-Boot, whose
settings -- boot command, kernel arguments, MAC and serial numbers, root
passwords some vendors keep there, last boot counters -- live in a flash
partition of their own ('u-boot-env', 'uboot-env', 'env'). Its layout
(U-Boot's include/env.h, tools/env/fw_env.c):

* a CRC-32 (zlib's) of the data area, little-endian -- big-endian on some
  big-endian boards (mkenvimage -b);
* with a redundant environment, a flags byte after it: two copies in two
  sectors, the active one the copy whose flag says newer (fw_env.c:
  'active' 1 / 'obsolete' 0, or a counter that is one more);
* the data: 'name=value' strings, each NUL-terminated, a second NUL
  ending them; the rest padded.

Found where a volume (or a raw dump's partition) starts with such a block
at one of the usual sizes (or the whole volume). Shown as one file,
environment.txt -- one 'name=value' per line, as fw_printenv prints them
-- and, when the other copy of a redundant pair holds, other-copy.txt:
the settings before the last save. Checked against libubootenv's
fw_printenv reading mkenvimage's images (tests/test_uboot_env.py).
"""

import logging
import stat
import struct
import zlib

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.U-Boot')

KIND = 'U-Boot environment'
SIZES = tuple(1 << n for n in range(10, 19))      # 1 KiB .. 256 KiB
ROOT, ENVIRONMENT, OTHER = 1, 2, 3


def _variables(data):
    """['name=value', ...] up to the double NUL, or None when the area is
    not an environment's (a string without '=', unprintable bytes)."""
    end = data.find(b'\0\0')
    if end <= 0:
        return None
    out = []
    for raw in data[:end].split(b'\0'):
        if b'=' not in raw or raw.startswith(b'='):
            return None
        if any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in raw):
            return None
        out.append(raw.decode('utf-8', 'replace'))
    return out


def parse(block):
    """(variables, flags or None, byte order) of an environment block at
    its exact size, or None. Tried without and with the flags byte, the
    CRC little- and big-endian."""
    for header in (4, 5):
        data = block[header:]
        value = zlib.crc32(data) & 0xFFFFFFFF
        for order in ('<', '>'):
            if struct.unpack(order + 'I', block[:4])[0] == value:
                variables = _variables(data)
                if variables:
                    return variables, (block[4] if header == 5 else None), \
                        order
    return None


class UbootEnvironment:
    def __init__(self, source):
        source.seek(0, 2)
        self.size = source.tell()
        self.source = source
        self.copies = []                        # (offset, size, parsed)
        sizes = sorted({s for s in SIZES if s <= self.size} |
                       ({self.size} if self.size <= SIZES[-1] else set()))
        for size in sizes:
            found = self._at(0, size)
            if found is None:
                continue
            self.copies.append((0, size, found))
            # A redundant pair: the other copy right after the first.
            if found[1] is not None and 2 * size <= self.size:
                other = self._at(size, size)
                if other is not None:
                    self.copies.append((size, size, other))
            break
        if not self.copies:
            raise ValueError("no U-Boot environment")
        self.active = self._active()

    def _at(self, offset, size):
        self.source.seek(offset)
        block = self.source.read(size)
        return parse(block) if len(block) == size else None

    def _active(self):
        """fw_env.c: of two copies, the one flagged active (1 against 0),
        or with a counter one more than the other's (wrapping at 255)."""
        if len(self.copies) < 2:
            return 0
        first, second = self.copies[0][2][1], self.copies[1][2][1]
        if first == 1 and second == 0:
            return 0
        if first == 0 and second == 1:
            return 1
        if (first + 1) & 0xFF == second:
            return 1
        return 0

    def text(self, which):
        return ''.join(f"{line}\n" for line in self.copies[which][2][0]) \
            .encode('utf-8')

    def facts(self):
        offset, size, (variables, flags, order) = self.copies[self.active]
        out = {'Environment size': str(size),
               'Variables': str(len(variables)),
               'CRC': 'big-endian' if order == '>' else 'little-endian'}
        if flags is not None:
            out['Redundant'] = f"yes, copy at {offset} active (flag {flags})"
        return out


class _Entry:
    def __init__(self, env, identifier, name, content):
        self._content = content
        self.identifier = identifier
        self.parent_identifier = ROOT
        self.name = name
        self.file_mode = stat.S_IFREG | 0o444 if content is not None else \
            stat.S_IFDIR | 0o555
        self.size = len(content) if content is not None else 0
        self.owner_identifier = self.group_identifier = 0
        self._children = []

    def get_number_of_links(self):
        return 1

    symbolic_link_target = ''

    @property
    def number_of_sub_file_entries(self):
        return len(self._children)

    def get_sub_file_entry(self, index):
        return self._children[index]

    def read_buffer_at_offset(self, length, offset):
        if self._content is None:
            return b''
        return self._content[offset:offset + length]


class _Volume:
    def __init__(self, env):
        self.env = env
        self.root = _Entry(env, ROOT, '', None)
        self.root._children.append(_Entry(env, ENVIRONMENT,
                                          'environment.txt',
                                          env.text(env.active)))
        if len(env.copies) > 1:
            other = 1 - env.active
            self.root._children.append(_Entry(env, OTHER, 'other-copy.txt',
                                              env.text(other)))
        self.by_id = {e.identifier: e for e in
                      [self.root] + self.root._children}

    def get_root_directory(self):
        return self.root

    def entry(self, identifier):
        return self.by_id.get(identifier)

    def get_file_entry_by_path(self, path):
        parts = [p for p in path.replace('\\', '/').split('/') if p]
        if not parts:
            return self.root
        return next((e for e in self.root._children
                     if len(parts) == 1 and e.name == parts[0]), None)


class UbootEnvFileSystem(LibyalFileSystem):
    KIND = KIND
    BLOCK_SIZE = 512

    def __init__(self, env):
        self.env = env
        used = sum(size for _offset, size, _found in env.copies)
        super().__init__(_Volume(env), used, KIND)

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT

    def _by_identifier(self, value):
        return self.volume.entry(value)

    def allocated_ranges(self):
        return [(offset, size) for offset, size, _found in self.env.copies]

    def facts(self):
        return self.env.facts()


def open_uboot_env(source):
    try:
        return UbootEnvFileSystem(UbootEnvironment(source))
    except (ValueError, struct.error, OSError, IOError):
        return None

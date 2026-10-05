"""APFS through libfsapfs, shaped like pytsk3's file system objects.

The Sleuth Kit in the pytsk3 wheels does not read APFS (it needs pool
support pytsk3 does not expose), so an APFS volume is read with libfsapfs,
and shaped like pytsk3 by core/libyal_fs.py (which XFS shares): browsing,
previews, exports, analysis, indexing and activity then need no APFS code.

What APFS does not have, these objects do not invent: there is no deleted
entry in an APFS directory listing (a deleted file's name is gone; its data
may live on in snapshots, which libfsapfs does not expose), so nothing here
is ever reported deleted. Times are kept to the nanosecond APFS stores.

An encrypted volume is unlocked with its password or recovery key before it
is shaped; the key stays in memory, as BitLocker's does.
"""

import logging

from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.APFS')

ROOT_IDENTIFIER = 2
BLOCK_SIZE = 4096


class ApfsFileSystem(LibyalFileSystem):
    """An unlocked APFS volume, read like a pytsk3.FS_Info."""

    KIND = 'APFS'
    BLOCK_SIZE = BLOCK_SIZE

    def __init__(self, volume, container=None, name=''):
        self.container = container
        try:
            size = int(volume.size or 0)
        except (IOError, OSError):
            size = 0
        super().__init__(volume, size,
                         name or getattr(volume, 'name', '') or 'APFS volume')

    def identifier(self, entry):
        return entry.identifier

    def _root_identifier(self):
        return ROOT_IDENTIFIER

    def _last_identifier(self):
        try:
            return int(self.volume.next_file_entry_identifier) - 1
        except (AttributeError, OSError, IOError, TypeError):
            return 0

    def _by_identifier(self, identifier):
        return self.volume.get_file_entry_by_identifier(identifier)


def is_apfs(fs):
    return isinstance(fs, ApfsFileSystem)

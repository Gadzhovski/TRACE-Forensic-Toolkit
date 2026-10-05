"""XFS through libfsxfs, shaped like pytsk3's file system objects.

XFS is the default file system of RHEL, CentOS, Rocky and Alma Linux
servers, and The Sleuth Kit (4.15, in the pytsk3 wheels) does not read it.
libfsxfs does -- a libyal library with wheels for every platform, LGPL like
libewf -- and core/libyal_fs.py gives it pytsk3's shape, as it does APFS:
browsing, previews, exports, analysis, indexing and activity need no XFS
code.

A partition is tried as XFS only when TSK will not open it and its first
sector carries the superblock magic 'XFSB'. Entries are identified by their
inode numbers, which is what XFS itself calls them; the root's is whatever
the superblock says (not a fixed number, as it is for ext or APFS).
"""

import logging
import struct

from trace_app.core.containers import holding_libyal
from trace_app.core.libyal_fs import LibyalFileSystem

logger = logging.getLogger('TRACE.XFS')

MAGIC = b'XFSB'


def superblock_geometry(head):
    """(block size, size in bytes) from an XFS superblock, or None.
    sb_blocksize is the big-endian u32 at 4, sb_dblocks the u64 at 8."""
    if len(head) < 16 or head[:4] != MAGIC:
        return None
    block_size = struct.unpack_from('>I', head, 4)[0]
    blocks = struct.unpack_from('>Q', head, 8)[0]
    if not 512 <= block_size <= 65536:
        return None
    return block_size, blocks * block_size


class XfsFileSystem(LibyalFileSystem):
    """An XFS volume, read like a pytsk3.FS_Info."""

    KIND = 'XFS'

    def __init__(self, volume, source, block_size=4096, size=0):
        #: The file object libfsxfs reads through: kept, or it is freed
        #: under the volume.
        self.source = source
        self.BLOCK_SIZE = block_size
        try:
            label = volume.label or ''
        except (OSError, IOError):
            label = ''
        super().__init__(volume, size, label or 'XFS volume')

    def identifier(self, entry):
        return entry.inode_number

    def _root_identifier(self):
        return self.volume.get_root_directory().inode_number

    def _by_identifier(self, identifier):
        return self.volume.get_file_entry_by_inode(identifier)

    @holding_libyal
    def close(self):
        try:
            self.volume.close()
        except (OSError, IOError):
            pass


@holding_libyal
def open_xfs(source):
    """An XfsFileSystem over `source` (a file object over the partition),
    or None when it is not an XFS volume libfsxfs can open."""
    try:
        source.seek(0)
        geometry = superblock_geometry(source.read(512))
    except (OSError, IOError):
        return None
    if geometry is None:
        return None
    try:
        import pyfsxfs
    except ImportError:
        logger.warning("libfsxfs is not installed: XFS cannot be read")
        return None
    try:
        source.seek(0)
        volume = pyfsxfs.volume()
        volume.open_file_object(source)
    except (OSError, IOError) as exc:
        logger.warning("XFS volume not opened: %s", exc)
        return None
    return XfsFileSystem(volume, source, *geometry)


def is_xfs(fs):
    return isinstance(fs, XfsFileSystem)

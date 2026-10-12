"""Disk images in containers TRACE reads in Python: Android sparse
images (core/android_sparse.py), VirtualBox VDI (core/vdi.py), AFF v3
(core/aff.py) and compressed raw images (core/compressed_disk.py).

Each is recognised by its content -- an Android sparse image or an AFF is
often named .img -- and opened as a disk (pytsk3's Img_Info over it), so
partitions, file systems and every reader work unchanged. What is hashed
is the disk, as for a virtual disk; an AFF's stored hashes are kept for
the verification verdict (`stored_hashes`).
"""

import os

from trace_app.core import containers

#: Named by these, whatever their first bytes say.
EXTENSIONS = {'.simg': 'sparse', '.vdi': 'vdi', '.aff': 'aff',
              '.afd': 'aff', '.afm': 'aff',
              '.gz': 'compressed', '.xz': 'compressed',
              '.bz2': 'compressed', '.zst': 'compressed',
              '.zstd': 'compressed', '.lz4': 'compressed'}
NAMES = {'sparse': 'Android sparse image', 'vdi': 'VirtualBox disk (VDI)',
         'aff': 'AFF image', 'compressed': 'Compressed raw image'}


def sniff(path):
    """'sparse', 'vdi', 'aff' or 'compressed' from a file's first bytes,
    else None."""
    from trace_app.core.aff import is_aff
    from trace_app.core.android_sparse import is_sparse
    from trace_app.core.compressed_disk import kind_of
    from trace_app.core.vdi import is_vdi
    try:
        with open(path, 'rb') as handle:
            head = handle.read(0x200)
    except (OSError, IsADirectoryError):
        return None
    if is_sparse(head):
        return 'sparse'
    if is_vdi(head):
        return 'vdi'
    if is_aff(head):
        return 'aff'
    if kind_of(head):
        return 'compressed'
    return None


def kind_of(path):
    """What container `path` is, by its name or its content, or None."""
    from trace_app.core.aff import is_afd
    if is_afd(path.rstrip('/\\')):
        return 'aff'                # an AFD: a folder of .aff files
    extension = os.path.splitext(path)[1].lower()
    return sniff(path) or (EXTENSIONS.get(extension) if os.path.isfile(path)
                           else None)


class _File:
    """A file object for a reader that seeks and reads."""

    def __init__(self, path):
        self._handle = open(path, 'rb')

    def seek(self, offset, whence=0):
        return self._handle.seek(offset, whence)

    def tell(self):
        return self._handle.tell()

    def read(self, length=-1):
        return self._handle.read(length)

    def close(self):
        self._handle.close()


def open_container(path):
    """(Img_Info, description) for a container image. Raises
    containers.ContainerError saying why it cannot be read."""
    from trace_app.core import aff, android_sparse, compressed_disk, vdi
    kind = kind_of(path)
    try:
        if kind == 'sparse':
            source = android_sparse.SparseImage(_File(path))
        elif kind == 'vdi':
            source = vdi.VdiDisk(path)
        elif kind == 'aff':
            source = aff.AffImage(path)
        elif kind == 'compressed':
            source = compressed_disk.CompressedDisk(path)
        else:
            raise containers.ContainerError(
                f"{os.path.basename(path)} is not a container TRACE reads")
    except (android_sparse.SparseError, vdi.VdiError, aff.AffError,
            compressed_disk.CompressedError, OSError) as exc:
        raise containers.ContainerError(str(exc)) from exc
    image = containers.LibyalImgInfo(source, source.get_size())
    image.stored_hashes = getattr(source, 'stored_hashes', {}) or {}
    return image, source.describe()

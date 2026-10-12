"""Shared by the file system tests: read a volume the way TRACE reads every
file system (the pytsk3-shaped interface: open_dir, info.name, info.meta,
read_random) and compare it with the answer key the image builder wrote
(tools/testdata/build/make_fs_images.py)."""

import hashlib
import json

import pytsk3

from tests.conftest import image_path

KEY = 'fs-images-key.json'


def key(name):
    """The answer key's entry for image `name`."""
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)['images'][name]


class Source:
    """A file object over an image file, as ImageHandler hands a reader a
    partition."""

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


def _digest(handle, size):
    sha = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = handle.read_random(offset, min(1 << 20, size - offset))
        if not chunk:
            break
        sha.update(chunk)
        offset += len(chunk)
    return sha.hexdigest(), offset


def walk(fs):
    """{path: {'type', 'size', 'sha256' | 'target', 'mtime'}} read through
    the pytsk3 shape, plus each entry's identifier."""
    out = {}
    root = fs.info.root_inum
    pending = [('', fs.open_dir(inode=root))]
    seen = {root}
    while pending:
        prefix, directory = pending.pop()
        for item in directory:
            name = item.info.name.name.decode('utf-8', 'surrogateescape')
            if name in ('.', '..'):
                continue
            meta = item.info.meta
            path = f'{prefix}/{name}'
            record = {'inode': meta.addr, 'mtime': meta.mtime}
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                record['type'] = 'dir'
                if meta.addr not in seen:
                    seen.add(meta.addr)
                    pending.append((path, item.as_directory()))
            elif meta.type == pytsk3.TSK_FS_META_TYPE_LNK:
                record['type'] = 'link'
                record['target'] = meta.link
                record['size'] = meta.size
            else:
                record['type'] = 'file'
                record['size'] = meta.size
                record['sha256'], record['read'] = _digest(item, meta.size)
            out[path] = record
    return out


def compare(found, expected, times=True):
    """Every difference between a walk and the key, as text lines."""
    problems = []
    for path in sorted(set(expected) - set(found)):
        problems.append(f"missing: {path}")
    for path in sorted(set(found) - set(expected)):
        problems.append(f"not in the key: {path}")
    for path in sorted(set(found) & set(expected)):
        want, got = expected[path], found[path]
        for field in ('type', 'size', 'sha256', 'target'):
            if field in want and want[field] != got.get(field):
                problems.append(f"{path}: {field} {got.get(field)!r}, "
                                f"expected {want[field]!r}")
        if times and 'mtime' in want and got.get('mtime') != want['mtime']:
            problems.append(f"{path}: mtime {got.get('mtime')}, expected "
                            f"{want['mtime']}")
    return problems

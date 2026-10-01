"""What TRACE sees in a disk image, as a deterministic record.

A manifest lists every partition, every volume's file system, and every file
and directory TRACE can reach -- path, inode, type, size, whether it is
deleted, its four timestamps, and the SHA-256 of its contents. Two manifests
of the same image diff cleanly, which is how an engine upgrade is shown not to
change what an examiner is told: the tests compare a fresh walk against a
manifest committed when the result was last checked by hand.

It opens images through ImageHandler, the path TRACE itself uses, rather than
through pytsk3 directly, so a regression in TRACE's own handling shows up too.

Run as a script to (re)write manifests:

    python -m tests.manifest test_images/7-ntfs-undel.dd -o tests/manifests
"""

import argparse
import hashlib
import json
import os
import sys

import pytsk3

#: Files larger than this are listed but not hashed, to keep a walk of a 1 GB
#: image to seconds. Every test image's files are well under it.
MAX_HASH_BYTES = 64 * 1024 * 1024

#: Directory depth limit, as in the analysis walk: damaged file systems loop.
MAX_DEPTH = 32

_TYPE = {
    pytsk3.TSK_FS_META_TYPE_REG: 'file',
    pytsk3.TSK_FS_META_TYPE_DIR: 'dir',
    pytsk3.TSK_FS_META_TYPE_LNK: 'link',
    pytsk3.TSK_FS_META_TYPE_VIRT: 'virtual',
    pytsk3.TSK_FS_META_TYPE_VIRT_DIR: 'virtual-dir',
}


def build_manifest(image_path):
    """The manifest of one image, as a dict ready for json.dump."""
    from trace_app.core.image_handler import ImageHandler

    handler = ImageHandler(image_path)
    if not handler.loaded:
        raise RuntimeError(f"TRACE could not open {image_path}")
    try:
        partitions = handler.get_partitions()
        manifest = {
            'image': os.path.basename(image_path),
            'partitions': [
                {'addr': int(addr), 'desc': _text(desc), 'start': int(start),
                 'length': int(length)}
                for addr, desc, start, length in partitions],
            'stored_hashes': _stored_hashes(handler),
            'volumes': [],
        }
        offsets = sorted({int(p[2]) for p in partitions}) if partitions \
            else [0]
        for offset in offsets:
            fs = handler.get_fs_info(offset)
            if fs is None:
                continue
            manifest['volumes'].append({
                'offset': offset,
                'fs_type': handler.get_fs_type(offset),
                'entries': _walk(fs),
            })
        return manifest
    finally:
        handler.close_resources()


def _stored_hashes(handler):
    try:
        info = handler.get_acquisition_info() or {}
    except Exception:
        return {}
    return {k: v for k, v in info.items() if k.startswith('Stored ')}


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return '' if value is None else str(value)


def _walk(fs):
    entries = []
    visited = set()

    def walk(directory, path, depth):
        if depth > MAX_DEPTH:
            return
        for entry in directory:
            if entry.info.name is None:
                continue
            name = entry.info.name.name.decode('utf-8', 'replace')
            if name in ('.', '..'):
                continue
            child = f"{path}/{name}"
            meta = entry.info.meta
            name_unalloc = bool(int(entry.info.name.flags)
                                & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            if meta is None:
                # A name whose metadata has been reused: nothing to read,
                # but the name itself is a fact about the volume.
                entries.append({'path': child, 'inode': None, 'type': None,
                                'deleted': True})
                continue
            kind = _TYPE.get(meta.type, f"type-{int(meta.type)}")
            record = {
                'path': child,
                'inode': int(meta.addr),
                'type': kind,
                'size': int(meta.size),
                'deleted': name_unalloc or not (
                    int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC),
                'mtime': int(meta.mtime or 0),
                'atime': int(meta.atime or 0),
                'ctime': int(meta.ctime or 0),
                'crtime': int(meta.crtime or 0),
            }
            if kind == 'file' and 0 < meta.size <= MAX_HASH_BYTES:
                record['sha256'] = _hash(fs, entry, meta)
            entries.append(record)

            key = (int(meta.addr), name_unalloc)
            if kind in ('dir', 'virtual-dir') and key not in visited:
                visited.add(key)
                try:
                    walk(entry.as_directory(), child, depth + 1)
                except Exception as exc:
                    record['walk_error'] = type(exc).__name__

    try:
        walk(fs.open_dir(path='/'), '', 0)
    except Exception as exc:
        entries.append({'path': '/', 'walk_error': type(exc).__name__})
    entries.sort(key=lambda e: (e['path'], e.get('inode') or -1))
    return entries


def _hash(fs, entry, meta):
    """SHA-256 of a file's contents, or 'unreadable:<error>'."""
    try:
        file_object = entry if entry.info.meta else \
            fs.open_meta(inode=meta.addr)
        digest = hashlib.sha256()
        offset, size = 0, int(meta.size)
        while offset < size:
            block = file_object.read_random(offset,
                                            min(1024 * 1024, size - offset))
            if not block:
                break
            digest.update(block)
            offset += len(block)
        return digest.hexdigest() if offset == size else \
            f"short-read:{offset}:{digest.hexdigest()}"
    except Exception as exc:
        return f"unreadable:{type(exc).__name__}"


def manifest_path(directory, image_path):
    return os.path.join(directory,
                        os.path.basename(image_path) + '.manifest.json')


def write_manifest(image_path, directory):
    manifest = build_manifest(image_path)
    os.makedirs(directory, exist_ok=True)
    target = manifest_path(directory, image_path)
    with open(target, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write('\n')
    return target, manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('images', nargs='+')
    parser.add_argument('-o', '--out', required=True)
    args = parser.parse_args(argv)
    for image in args.images:
        target, manifest = write_manifest(image, args.out)
        count = sum(len(v['entries']) for v in manifest['volumes'])
        print(f"{os.path.basename(image)}: {len(manifest['volumes'])} "
              f"volume(s), {count} entries -> {target}", flush=True)
    return 0


if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    sys.exit(main())

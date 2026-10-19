"""LittleFS images, and littlefs's own reading of them, for TRACE's reader
(core/littlefs.py).

littlefs-python is littlefs's C code (v2.11) with Python bindings: it
writes the images and, mounted again, lists and reads them -- the answer
key (littlefs-key.json: every path, type, size and SHA-256). A tool for
these test images only, never part of TRACE. Built:

* lfs-512.img   512-byte blocks: inline and CTZ files (one of 300 KB, many
                blocks of skip pointers), empty files, deep folders, a
                folder of 150 files (split over several metadata pairs
                joined by hard tails), long and non-Latin names, then a
                history -- files overwritten, truncated, deleted, renamed
                within and across folders (moves), a folder removed
* lfs-4096.img  4 KiB blocks, block_cycles 2: the root rewritten until the
                superblock expands and metadata pairs relocate

    python3 tools/testdata/build/make_littlefs.py [folder]

Needs littlefs-python==0.19.0 (wheels: any OS). In Docker:

    docker run --rm -v "$PWD:/src" -w /src python:3.12-slim sh -c \\
        "pip install -q littlefs-python==0.19.0 && \\
         python3 tools/testdata/build/make_littlefs.py"
"""

import hashlib
import json
import os
import random
import sys

from littlefs import LittleFS


def stream(seed, size):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def write(fs, path, data):
    with fs.open(path, 'wb') as handle:
        handle.write(data)


def answer(fs):
    """{path: {'type', 'size', 'sha256'}} as littlefs lists and reads it."""
    out = {}
    for root, folders, files in fs.walk('/'):
        for name in folders:
            out[f"{root.rstrip('/')}/{name}"] = {'type': 'dir'}
        for name in files:
            path = f"{root.rstrip('/')}/{name}"
            with fs.open(path, 'rb') as handle:
                data = handle.read()
            out[path] = {'type': 'file', 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()}
    return out


def small_blocks():
    fs = LittleFS(block_size=512, block_count=4096, name_max=255)
    write(fs, '/README.txt', b'LittleFS test volume for TRACE.\n' * 3)
    write(fs, '/empty.bin', b'')
    write(fs, '/inline.txt', b'small enough to live in its tag')
    write(fs, '/big.bin', stream('big', 300_000))
    write(fs, '/edge-1-block.bin', stream('e1', 512 - 8))
    write(fs, '/edge-2-block.bin', stream('e2', 2 * (512 - 8)))
    fs.makedirs('/deep/a/b/c/d')
    write(fs, '/deep/a/b/c/d/file.txt', b'deep down')
    fs.mkdir('/many')
    for number in range(150):
        write(fs, f'/many/file-{number:03d}.dat',
              stream(f'many{number}', 30 + number * 13))
    fs.mkdir('/names')
    write(fs, '/names/' + 'long-name-' * 24 + '.txt', b'a long name')
    write(fs, '/names/résumé – 履歴書.txt', 'non-Latin'.encode())
    fs.mkdir('/history')
    write(fs, '/history/overwritten.bin', stream('first', 20_000))
    write(fs, '/history/overwritten.bin', stream('second', 7_000))
    write(fs, '/history/truncated.bin', stream('trunc', 40_000))
    with fs.open('/history/truncated.bin', 'r+b') as handle:
        handle.truncate(1_234)
    write(fs, '/history/deleted.bin', stream('deleted', 9_000))
    fs.remove('/history/deleted.bin')
    write(fs, '/history/old-name.txt', b'renamed in place')
    fs.rename('/history/old-name.txt', '/history/new-name.txt')
    write(fs, '/history/moving.txt', b'moved to another folder')
    fs.rename('/history/moving.txt', '/deep/a/moved.txt')
    fs.mkdir('/gone')
    write(fs, '/gone/inside.txt', b'removed with its folder')
    fs.remove('/gone/inside.txt')
    fs.rmdir('/gone')
    for number in range(0, 150, 7):
        fs.remove(f'/many/file-{number:03d}.dat')
    return fs


def expanding_superblock():
    fs = LittleFS(block_size=4096, block_count=256, block_cycles=2)
    for round_ in range(60):
        write(fs, '/counter.txt', f'round {round_}\n'.encode() * (round_ + 1))
        write(fs, f'/log-{round_ % 5}.bin', stream(f'log{round_}', 6000))
    fs.mkdir('/data')
    for number in range(30):
        write(fs, f'/data/{number:02d}.bin', stream(f'd{number}', 9000))
    return fs


def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                             os.path.join(os.path.dirname(__file__), '..',
                                          '..', '..', 'test_images',
                                          'built'))
    os.makedirs(folder, exist_ok=True)
    key = {}
    for name, fs, gone in (
            ('lfs-512.img', small_blocks(),
             ['/history/deleted.bin', '/history/old-name.txt',
              '/history/moving.txt', '/gone']),
            ('lfs-4096.img', expanding_superblock(), [])):
        fs.unmount()
        image = bytes(fs.context.buffer)
        with open(os.path.join(folder, name), 'wb') as handle:
            handle.write(image)
        # The key: littlefs mounting the bytes as they are on disk.
        from littlefs.context import UserContext
        context = UserContext(len(image))
        context.buffer[:] = image
        again = LittleFS(context=context, block_size=fs.cfg.block_size,
                         block_count=fs.block_count)
        key[name] = {'block_size': fs.cfg.block_size,
                     'block_count': fs.block_count,
                     'files': answer(again), 'gone': gone}
    with open(os.path.join(folder, 'littlefs-key.json'), 'w',
              encoding='utf-8') as handle:
        import littlefs
        json.dump({'reader': f'littlefs-python {littlefs.__version__} '
                             f'(littlefs {littlefs.__LFS_VERSION__})',
                   'images': key}, handle, indent=1, sort_keys=True,
                  ensure_ascii=False)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    main()

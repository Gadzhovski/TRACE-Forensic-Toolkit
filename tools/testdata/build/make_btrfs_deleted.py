"""Build a Btrfs volume with known deleted files, by the Linux kernel itself.

core/btrfs_recover.py lists deleted files from the leaves copy-on-write
leaves behind. Its test needs a volume whose deletions are known exactly,
made by the real file system rather than by TRACE's own code: this writes
deterministic files on a loop-mounted Btrfs, deletes them in a fixed
order, and records the answer key -- each deleted file's path, size and
SHA-256 -- beside the image.

    sudo python3 tools/testdata/build/make_btrfs_deleted.py [folder]     # Linux, root

Needs mkfs.btrfs (btrfs-progs), chattr and a kernel with Btrfs. CI builds
it on Ubuntu (tests.yml); on Windows or macOS, in a privileged container:

    docker run --rm --privileged -v "$PWD:/src" -w /src debian:bookworm \\
        sh -c "apt-get update -qq && apt-get install -y -qq btrfs-progs \\
               e2fsprogs python3 >/dev/null && python3 tools/testdata/build/make_btrfs_deleted.py"

What is in it:

* live/keep.txt                 stays (a live file beside the deleted)
* docs/report.bin   300,000 B   deleted: plain extents, checksummed
* docs/note.txt         200 B   deleted: inline, in the leaf itself
* logs/app.log      ~2 MB text  deleted: zstd-compressed extents
* project/a.txt, project/b.bin  deleted with their folder
* nocow/raw.bin     100,000 B   deleted: chattr +C, no checksums kept
* victim.bin          1 MiB     deleted, then the volume filled full,
                                so its space is used again: TRACE must
                                say "overwritten" wherever the bytes no
                                longer match, never "recoverable"
* gone/ (a subvolume, secret.txt) deleted whole; whether its leaves
                                survive the kernel's cleaner is not
                                promised (optional in the key)
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

NAME = 'btrfs-deleted.raw'
SIZE = 256 * 1024 * 1024


def stream(seed, size):
    """Deterministic bytes: SHA-256 in counter mode."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def text(seed, size):
    lines = []
    total = 0
    number = 0
    while total < size:
        line = (f"2026-10-08T12:{number // 60 % 60:02d}:{number % 60:02d}Z "
                f"{seed} request {number} served in {number % 97} ms\n")
        lines.append(line)
        total += len(line)
        number += 1
    return ''.join(lines).encode()[:size]


def run(*command):
    subprocess.run(command, check=True)


def write(root, path, data):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'wb') as handle:
        handle.write(data)
    return {'path': '/' + path, 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def build(folder):
    image = os.path.join(folder, NAME)
    if os.path.exists(image):
        os.remove(image)
    with open(image, 'wb') as handle:
        handle.truncate(SIZE)
    run('mkfs.btrfs', '-q', '-L', 'deleted', image)
    mount = tempfile.mkdtemp()
    run('mount', '-o', 'loop,noatime', image, mount)
    try:
        key = {}
        write(mount, 'live/keep.txt', b'still here\n')
        key['report'] = write(mount, 'docs/report.bin',
                              stream('report', 300000))
        key['note'] = write(mount, 'docs/note.txt', text('note', 200))
        os.makedirs(os.path.join(mount, 'logs'))
        run('btrfs', 'property', 'set', os.path.join(mount, 'logs'),
            'compression', 'zstd')
        key['log'] = write(mount, 'logs/app.log', text('app', 2_000_000))
        key['a'] = write(mount, 'project/a.txt', text('a', 5000))
        key['b'] = write(mount, 'project/b.bin', stream('b', 70000))
        os.makedirs(os.path.join(mount, 'nocow'))
        run('chattr', '+C', os.path.join(mount, 'nocow'))
        key['raw'] = write(mount, 'nocow/raw.bin', stream('raw', 100000))
        key['victim'] = write(mount, 'victim.bin', stream('victim', 1 << 20))
        run('btrfs', 'subvolume', 'create', os.path.join(mount, 'gone'))
        key['secret'] = write(mount, 'gone/secret.txt', text('secret', 3000))
        run('sync')
        # The victim first, then the volume filled to the last byte: its
        # space must be used again, so it is overwritten for certain.
        os.remove(os.path.join(mount, 'victim.bin'))
        run('btrfs', 'filesystem', 'sync', mount)
        filler = os.path.join(mount, 'live', 'filler.bin')
        block = stream('filler', 1 << 20)
        with open(filler, 'wb') as handle:
            try:
                while True:
                    handle.write(block)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                pass                          # full
        # Room again for the deletions' own metadata.
        with open(filler, 'r+b') as handle:
            handle.truncate(max(0, os.path.getsize(filler) - (24 << 20)))
        run('btrfs', 'filesystem', 'sync', mount)
        for path in ('docs/report.bin', 'docs/note.txt', 'logs/app.log',
                     'project/a.txt', 'project/b.bin', 'nocow/raw.bin'):
            os.remove(os.path.join(mount, path))
        os.rmdir(os.path.join(mount, 'project'))
        run('btrfs', 'subvolume', 'delete', os.path.join(mount, 'gone'))
        run('btrfs', 'filesystem', 'sync', mount)
    finally:
        run('umount', mount)
        os.rmdir(mount)
    key['victim']['overwritten'] = True
    key['secret']['optional'] = True
    key['secret']['path'] = '/[deleted subvolume]/secret.txt'
    with open(os.path.join(folder, NAME + '.json'), 'w') as handle:
        json.dump({'image': NAME, 'deleted': list(key.values()),
                   'live': ['/live/keep.txt', '/live/filler.bin']},
                  handle, indent=1)
    return image


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    folder = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(root, 'test_images', 'built')
    os.makedirs(folder, exist_ok=True)
    if os.geteuid() != 0:
        sys.exit("Run as root: the volume is loop-mounted")
    print(build(folder))


if __name__ == '__main__':
    main()

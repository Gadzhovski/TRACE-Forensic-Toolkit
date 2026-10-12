"""Build F2FS volumes with F2FS's own tools, for core/f2fs.py.

F2FS (Android's /data, and some Linux installs) is read by no library
TRACE can install, and by not The Sleuth Kit. A reader checked only against
its own idea of the format would agree with itself, so these images are
written by f2fs-tools -- mkfs.f2fs, and sload.f2fs, which fills an image
from a folder through the same code the kernel's layout is defined by --
and, where the kernel can mount F2FS (Linux CI), by the kernel itself:

* f2fs-sload.raw   extra attributes, inode checksums: small files (inline
                    data), a 16 MiB file (direct, then indirect node
                    blocks), 300 files in one folder (several dentry
                    blocks), long and non-Latin names, links, an empty file
* f2fs-lz4.raw     the same tree, files compressed (LZ4, 4-block clusters)
* f2fs-lzo.raw     the same, LZO
* f2fs-kernel.raw  (kernel only) the tree copied in by Linux, small
                    folders as inline dentries, zstd compression on one
                    folder, and a file deleted

and f2fs-key.json: every file's path, type, size and SHA-256 (a link's
target), for each image.

    python3 tools/testdata/build/make_f2fs.py [folder]          # Linux

Distributions build f2fs-tools without LZ4 and LZO (sload then writes
an empty volume and says only "not supported"), so f2fs-tools 1.16.0 is
built here from its pinned commit, with both. Needs git, a C toolchain,
autoconf, automake, libtool, pkg-config, uuid-dev, liblz4-dev, liblzo2-dev;
the kernel image also needs root and the f2fs module. On Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && apt-get install -y -qq python3 git \\
         build-essential autoconf automake libtool pkg-config uuid-dev \\
         liblz4-dev liblzo2-dev >/dev/null && \\
         python3 tools/testdata/build/make_f2fs.py"

(Docker Desktop's kernel has no F2FS module: the kernel image is made in
Linux CI.)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

MIB = 1024 * 1024
SIZE = 96 * MIB
TOOLS_GIT = ('https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/'
             'f2fs-tools.git')
#: v1.16.0
TOOLS_COMMIT = '06c027abc6153c4a97cba5317844e8dcaaee3cf7'
MKFS = 'mkfs.f2fs'
SLOAD = 'sload.f2fs'


def run(*command, data=None):
    result = subprocess.run(command, capture_output=True, text=True,
                            input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:3])}... failed:\n{result.stdout}"
                 f"{result.stderr}")
    return result.stdout


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def text(seed, size):
    """Compressible text: lines that repeat with small changes."""
    lines = []
    total = 0
    number = 0
    while total < size:
        line = f"{seed} line {number:08d}: the quick brown fox jumps\n"
        lines.append(line)
        total += len(line)
        number += 1
    return ''.join(lines).encode()[:size]


def tree(root):
    """Write the test tree under `root`."""
    def put(path, data):
        full = os.path.join(root, *path.split('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as handle:
            handle.write(data)

    put('README.txt', b'F2FS test volume for TRACE.\n' * 10)
    put('empty.txt', b'')
    put('docs/report.bin', stream('report', 50_000))
    put('docs/notes.txt', text('notes', 3_000))
    put('big/video.bin', stream('video', 16 * MIB))
    put('big/log.txt', text('log', 2 * MIB))
    for number in range(300):
        put(f'many/file-{number:03d}.dat', stream(f'many{number}', 100 +
                                                  number * 7))
    put('names/' + 'long-name-' * 20 + '.txt', b'a long name')
    put('names/résumé – 履歴書.txt', 'non-Latin name'.encode())
    put('deep/a/b/c/d/e/file.txt', b'deep')
    os.symlink('docs/report.bin', os.path.join(root, 'link'))
    os.symlink('/etc/passwd', os.path.join(root, 'abslink'))


def answer(root):
    """{path: {'type', 'size', 'sha256' | 'target'}} of a tree."""
    out = {}
    for parent, folders, files in os.walk(root):
        for name in folders + files:
            full = os.path.join(parent, name)
            path = '/' + os.path.relpath(full, root).replace(os.sep, '/')
            if os.path.islink(full):
                target = os.readlink(full)
                out[path] = {'type': 'link', 'target': target,
                             'size': len(target.encode())}
            elif os.path.isdir(full):
                out[path] = {'type': 'dir'}
            else:
                with open(full, 'rb') as handle:
                    data = handle.read()
                out[path] = {'type': 'file', 'size': len(data),
                             'sha256': hashlib.sha256(data).hexdigest()}
    return out


def blank(path):
    with open(path, 'wb') as handle:
        handle.truncate(SIZE)


def build_tools():
    """f2fs-tools from the pinned commit, with LZ4 and LZO: sets MKFS and
    SLOAD to the binaries built."""
    global MKFS, SLOAD
    work = tempfile.mkdtemp()
    run('git', 'clone', '-q', TOOLS_GIT, work)
    run('git', '-C', work, 'checkout', '-q', TOOLS_COMMIT)
    run('sh', '-c', f'cd {work} && ./autogen.sh >/dev/null 2>&1 && '
                    f'./configure --quiet --without-selinux --disable-shared '
                    f'>/dev/null && '
                    f'make -s -j4 >/dev/null 2>&1')
    MKFS = os.path.join(work, 'mkfs', 'mkfs.f2fs')
    SLOAD = os.path.join(work, 'fsck', 'sload.f2fs')
    if not os.path.exists(SLOAD):
        # Built as fsck.f2fs; the name chooses what it does.
        os.symlink(os.path.join(work, 'fsck', 'fsck.f2fs'), SLOAD)


def sload_image(folder, name, source, compress=None):
    target = os.path.join(folder, name)
    blank(target)
    features = 'extra_attr,inode_checksum,sb_checksum'
    if compress:
        features += ',compression'
    run(MKFS, '-q', '-f', '-l', 'TRACE', '-O', features, target)
    command = [SLOAD, '-f', source, '-T', '1700000000']
    if compress:
        command += ['-c', '-a', compress, '-L', '2']
    output = run(*command, target)
    if 'Error' in output or 'not supported' in output:
        sys.exit(f"sload.f2fs: {output.strip()[-300:]}")
    return target


def kernel_image(folder, source):
    """The tree copied in by Linux; None where it cannot mount F2FS."""
    if os.geteuid() != 0 or not shutil.which('modprobe') or \
            subprocess.run(['modprobe', 'f2fs'],
                           capture_output=True).returncode != 0:
        return None
    target = os.path.join(folder, 'f2fs-kernel.raw')
    blank(target)
    run(MKFS, '-q', '-f', '-l', 'KERNEL', '-O',
        'extra_attr,inode_checksum,sb_checksum,compression', target)
    mount = tempfile.mkdtemp()
    run('mount', '-o', 'loop,compress_algorithm=zstd,compress_extension=log',
        target, mount)
    try:
        for name in os.listdir(source):
            full = os.path.join(source, name)
            if os.path.isdir(full) and not os.path.islink(full):
                shutil.copytree(full, os.path.join(mount, name),
                                symlinks=True)
            elif os.path.islink(full):
                os.symlink(os.readlink(full), os.path.join(mount, name))
            else:
                shutil.copy2(full, mount)
        with open(os.path.join(mount, 'gone.bin'), 'wb') as handle:
            handle.write(stream('gone', 200_000))
        run('sync')
        os.remove(os.path.join(mount, 'gone.bin'))
        run('sync')
    finally:
        run('umount', mount)
    return target


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    build_tools()
    source = tempfile.mkdtemp()
    tree(source)
    files = answer(source)
    key = {'tool': run(MKFS, '-V').strip(), 'tools_commit': TOOLS_COMMIT,
           'files': files, 'images': {}}
    for name, compress in (('f2fs-sload.raw', None),
                           ('f2fs-lz4.raw', 'lz4'),
                           ('f2fs-lzo.raw', 'lzo')):
        sload_image(folder, name, source, compress)
        key['images'][name] = {'writer': 'sload.f2fs',
                               'compression': compress}
    if kernel_image(folder, source):
        key['images']['f2fs-kernel.raw'] = {
            'writer': 'Linux', 'compression': 'zstd (*.log)',
            'deleted': ['/gone.bin']}
    with open(os.path.join(folder, 'f2fs-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump(key, handle, indent=2, sort_keys=True, ensure_ascii=False)
    print(f"{len(key['images'])} F2FS images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("F2FS images are built on Linux (see the docstring for "
                 "Docker).")
    main()

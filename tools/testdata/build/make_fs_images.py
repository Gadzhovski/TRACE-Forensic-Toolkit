"""Build SquashFS, EROFS, UDF, HFS and JFFS2 images with each format's own
tools, for TRACE's readers of them (core/squashfs.py, core/erofs.py,
core/udf.py, core/hfs.py, core/jffs2.py).

The Sleuth Kit reads none of these and no library with wheels for every
platform does, so TRACE reads them in Python. A reader checked only against
its own idea of a format would agree with itself; these images are written
by the tools Linux distributions ship -- and UDF also by the Linux kernel
itself, through a mount:

* sqfs-<gzip|lzo|lz4|xz|zstd|lzma>.sqfs   mksquashfs, every compressor
* sqfs-plain.sqfs        nothing compressed, no fragments (-noI -noD -noF
                         -no-fragments)
* sqfs-small-blocks.sqfs 4 KiB blocks: files of many blocks, fragments
* erofs-plain.img        uncompressed, tails inline
* erofs-noinline.img     uncompressed, no inline tails
* erofs-chunk.img        chunk-based files (--chunksize)
* erofs-lz4.img          LZ4, compact indexes
* erofs-lz4-legacy.img   LZ4, full (legacy) indexes
* erofs-lz4hc-big.img    LZ4HC, 64 KiB physical clusters, tail packing
* erofs-lzma.img         MicroLZMA, fragments
* erofs-deflate.img      Deflate, all fragments, dedupe
* udf-102.img / udf-201.img / udf-201-2k.img   mkudffs, then the tree
                         copied in by the kernel (512- and 2048-byte blocks)
* udf-bridge.iso         genisoimage -udf (ISO 9660 + UDF 1.02)
* udf-250-empty.img      mkudffs, BD-R UDF 2.50: metadata partition, VAT
* hfs.img                hformat + hcopy (classic HFS): 300 files in one
                         folder (several B-tree nodes), and a file written
                         into the holes others left, in more than three
                         extents (the extents overflow file)
* jffs2-<zlib|lzo|rtime|none>.img, jffs2-be.img   mkfs.jffs2, each
                         compressor; big-endian

and fs-images-key.json: per image, every file's path, type, size and
SHA-256 (a link's target), and its modification time.

    python3 tools/testdata/build/make_fs_images.py [folder]     # Linux, root

Needs squashfs-tools, erofs-utils, udftools, genisoimage, hfsutils and
mtd-utils (Ubuntu 24.04; Debian 13 has no hfsutils), root and the udf
module for the kernel-written UDF images. On Windows or macOS:

    docker run --rm --privileged -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && apt-get install -y -qq --no-install-recommends \\
         python3 squashfs-tools erofs-utils udftools genisoimage hfsutils \\
         mtd-utils >/dev/null && python3 tools/testdata/build/make_fs_images.py"
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

MIB = 1024 * 1024
#: Every file's modification time: a fixed, distinct second per file.
EPOCH = 1_700_000_000


def run(*command, cwd=None):
    result = subprocess.run(command, capture_output=True, text=True,
                            cwd=cwd)
    if result.returncode:
        sys.exit(f"{' '.join(command[:4])}... failed:\n{result.stdout}"
                 f"{result.stderr}")
    return result.stdout + result.stderr


def stream(seed, size):
    """Incompressible bytes."""
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


class Tree:
    """A folder of test files, with their modification times set."""

    def __init__(self, root):
        self.root = root
        self.count = 0

    def put(self, path, data):
        full = os.path.join(self.root, *path.split('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as handle:
            handle.write(data)
        self.count += 1
        os.utime(full, (EPOCH + self.count, EPOCH + self.count))

    def link(self, path, target):
        full = os.path.join(self.root, *path.split('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target, full)


def unix_tree(root):
    """The tree for the Unix file systems (SquashFS, EROFS, UDF, JFFS2)."""
    tree = Tree(root)
    tree.put('README.txt', b'File system test volume for TRACE.\n' * 10)
    tree.put('empty.txt', b'')
    tree.put('docs/report.bin', stream('report', 50_000))
    tree.put('docs/notes.txt', text('notes', 3_000))
    tree.put('docs/exact-4k.bin', stream('exact', 4096))
    tree.put('docs/exact-128k.bin', stream('exact128', 128 * 1024))
    tree.put('big/video.bin', stream('video', 3 * MIB + 123))
    tree.put('big/log.txt', text('log', 2 * MIB))
    tree.put('big/zeros.bin', bytes(1 * MIB))
    # A sparse file: a hole, data, a hole.
    full = os.path.join(root, 'big', 'sparse.bin')
    with open(full, 'wb') as handle:
        handle.seek(700_000)
        handle.write(b'after the hole' * 100)
        handle.truncate(2 * MIB)
    for number in range(300):
        tree.put(f'many/file-{number:03d}.dat',
                 stream(f'many{number}', 100 + number * 7))
    tree.put('names/' + 'long-name-' * 20 + '.txt', b'a long name')
    tree.put('names/résumé – 履歴書.txt', 'non-Latin name'.encode())
    tree.put('deep/a/b/c/d/e/file.txt', b'deep')
    tree.put('dup/one.bin', stream('dup', 200_000))
    tree.put('dup/two.bin', stream('dup', 200_000))
    tree.link('link', 'docs/report.bin')
    tree.link('abslink', '/etc/passwd')
    os.link(os.path.join(root, 'docs', 'notes.txt'),
            os.path.join(root, 'docs', 'hardlink.txt'))
    return tree


def hfs_tree(root):
    """The tree for classic HFS: names of up to 31 MacRoman characters, no
    links."""
    tree = Tree(root)
    tree.put('README.txt', b'HFS test volume for TRACE.\r' * 10)
    tree.put('empty.txt', b'')
    tree.put('docs/report.bin', stream('report', 50_000))
    tree.put('docs/notes.txt', text('notes', 3_000))
    tree.put('big/video.bin', stream('video', 1 * MIB + 77))
    for number in range(300):
        tree.put(f'many/file-{number:03d}.dat',
                 stream(f'many{number}', 100 + number * 7))
    tree.put('names/' + 'thirty-one-characters-long.txt'[:31],
             b'a long name')
    tree.put('deep/a/b/c/file.txt', b'deep')
    return tree


def answer(root, times=True):
    """{path: {'type', 'size', 'sha256' | 'target', 'mtime'}} of a tree."""
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
                if times:
                    out[path]['mtime'] = int(os.lstat(full).st_mtime)
    return out


def version(*command):
    """A tool's first line about itself (some say it on stderr, with a
    non-zero exit)."""
    result = subprocess.run(command, capture_output=True, text=True)
    lines = (result.stdout + result.stderr).strip().splitlines()
    return lines[0] if lines else ''


def blank(path, size):
    with open(path, 'wb') as handle:
        handle.truncate(size)


# -- SquashFS -----------------------------------------------------------------

def squashfs(folder, source, key):
    files = answer(source)
    for comp in ('gzip', 'lzo', 'lz4', 'xz', 'zstd', 'lzma'):
        name = f'sqfs-{comp}.sqfs'
        target = os.path.join(folder, name)
        if os.path.exists(target):
            os.remove(target)
        run('mksquashfs', source, target, '-comp', comp, '-noappend',
            '-quiet', '-no-progress')
        key[name] = {'fs': 'SquashFS', 'compression': comp, 'files': files}
    for name, options in (
            ('sqfs-plain.sqfs', ['-noI', '-noD', '-noF', '-noX',
                                 '-no-fragments']),
            ('sqfs-small-blocks.sqfs', ['-b', '4096', '-always-use-fragments'
                                        ])):
        target = os.path.join(folder, name)
        if os.path.exists(target):
            os.remove(target)
        run('mksquashfs', source, target, '-noappend', '-quiet',
            '-no-progress', *options)
        key[name] = {'fs': 'SquashFS', 'options': ' '.join(options),
                     'files': files}


# -- EROFS --------------------------------------------------------------------

def erofs(folder, source, key):
    files = answer(source)
    for name, options in (
            ('erofs-plain.img', []),
            ('erofs-noinline.img', ['-Enoinline_data']),
            ('erofs-chunk.img', ['--chunksize=8192']),
            ('erofs-lz4.img', ['-zlz4']),
            ('erofs-lz4-legacy.img', ['-zlz4', '-Elegacy-compress']),
            ('erofs-lz4hc-big.img', ['-zlz4hc,12', '-C65536',
                                     '-Eztailpacking']),
            ('erofs-lzma.img', ['-zlzma', '-C65536', '-Efragments']),
            ('erofs-deflate.img', ['-zdeflate', '-Eall-fragments,dedupe'])):
        target = os.path.join(folder, name)
        run('mkfs.erofs', '-LTRACE', *options, target, source)
        # The answer is what erofs-utils itself reads back, which is not
        # always what went in: mkfs.erofs 1.7.1 merges a sparse file's
        # chunks by keeping each group's first entry, so data after a hole
        # at a group's start is written but no longer referenced (the
        # kernel reads zeros there too). Such files are listed.
        # Ubuntu 24.04's fsck.erofs cannot decompress DEFLATE (it exits 1,
        # saying nothing): that image's answer is the source tree.
        extracted = tempfile.mkdtemp()
        result = subprocess.run(['fsck.erofs', f'--extract={extracted}',
                                 '--overwrite', '--preserve', target],
                                capture_output=True, text=True)
        if result.returncode:
            read_back, answered_by = files, 'the source tree (fsck.erofs ' \
                'could not extract this image)'
        else:
            read_back, answered_by = answer(extracted), 'fsck.erofs --extract'
        differs = sorted(path for path, entry in read_back.items()
                         if entry.get('sha256') != files.get(path, {})
                         .get('sha256'))
        key[name] = {'fs': 'EROFS', 'options': ' '.join(options),
                     'files': read_back, 'answered_by': answered_by,
                     'differs_from_source': differs}


# -- UDF ----------------------------------------------------------------------

def _copy_into(source, mount):
    for name in os.listdir(source):
        full = os.path.join(source, name)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.copytree(full, os.path.join(mount, name), symlinks=True,
                            copy_function=shutil.copy2)
        elif os.path.islink(full):
            os.symlink(os.readlink(full), os.path.join(mount, name))
        else:
            shutil.copy2(full, mount)


def udf(folder, source, key):
    can_mount = os.geteuid() == 0
    for name, revision, block in (('udf-102.img', '0x0102', 512),
                                  ('udf-201.img', '0x0201', 512),
                                  ('udf-201-2k.img', '0x0201', 2048)):
        if not can_mount:
            break
        target = os.path.join(folder, name)
        blank(target, 48 * MIB)
        run('mkudffs', '--media-type=hd', f'--udfrev={revision}',
            f'--blocksize={block}', '--label=TRACE', target)
        mount = tempfile.mkdtemp()
        result = subprocess.run(['mount', '-o', f'loop,bs={block}', '-t',
                                 'udf', target, mount], capture_output=True,
                                text=True)
        if result.returncode:
            print(f"UDF not mounted, {name} skipped: {result.stderr}")
            os.remove(target)
            continue
        deleted = {}
        try:
            _copy_into(source, mount)
            if revision == '0x0201' and block == 512:
                # A file written, then deleted: its identifier stays,
                # marked deleted, and its file entry with it.
                gone = stream('gone', 200_000)
                with open(os.path.join(mount, 'gone.bin'), 'wb') as handle:
                    handle.write(gone)
                run('sync')
                os.remove(os.path.join(mount, 'gone.bin'))
                run('sync')
                deleted['/gone.bin'] = hashlib.sha256(gone).hexdigest()
            # Hard links are not UDF's to keep (each is its own file entry
            # in a copy); the tree's answer is read from the mount itself.
            files = answer(mount)
        finally:
            run('umount', mount)
        key[name] = {'fs': 'UDF', 'revision': revision, 'block': block,
                     'writer': 'Linux', 'files': files, 'deleted': deleted}

    bridge = os.path.join(folder, 'udf-bridge.iso')
    run('genisoimage', '-quiet', '-udf', '-R', '-J', '-joliet-long',
        '-V', 'TRACE', '-o', bridge, source)
    # What genisoimage put in its UDF (it keeps links, and shortens long
    # names), as the kernel reads it.
    files = None
    if can_mount:
        mount = tempfile.mkdtemp()
        result = subprocess.run(['mount', '-o', 'loop,ro,bs=2048', '-t',
                                 'udf', bridge, mount], capture_output=True,
                                text=True)
        if not result.returncode:
            try:
                files = answer(mount)
            finally:
                run('umount', mount)
    if files is not None:
        key['udf-bridge.iso'] = {'fs': 'UDF', 'revision': '0x0102',
                                 'block': 2048, 'writer': 'genisoimage',
                                 'files': files}

    empty = os.path.join(folder, 'udf-250-empty.img')
    blank(empty, 64 * MIB)
    run('mkudffs', '--media-type=bdr', '--udfrev=0x0250',
        '--blocksize=2048', '--label=TRACE', empty)
    key['udf-250-empty.img'] = {'fs': 'UDF', 'revision': '0x0250',
                                'block': 2048, 'writer': 'mkudffs',
                                'files': {}}


# -- HFS ----------------------------------------------------------------------

#: Small files written, then every other one deleted, to leave holes.
HFS_HOLES = 40


def hfs_free_bytes():
    """The mounted HFS volume's free space: hvol says "Volume has N bytes
    free"."""
    for line in run('hvol').splitlines():
        words = line.split()
        if 'free' in words and 'bytes' in words:
            return int(words[words.index('bytes') - 1].replace(',', ''))
    sys.exit("hvol did not say how much is free")

def hfs(folder, key):
    source = tempfile.mkdtemp()
    hfs_tree(source)
    target = os.path.join(folder, 'hfs.img')
    blank(target, 16 * MIB)
    run('hformat', '-l', 'TRACE', target)
    run('hmount', target)
    try:
        for parent, folders, files in os.walk(source):
            relative = os.path.relpath(parent, source)
            here = ':' + ('' if relative == '.' else
                          relative.replace(os.sep, ':') + ':')
            for name in sorted(folders):
                run('hmkdir', here + name)
            for name in sorted(files):
                run('hcopy', '-r', os.path.join(parent, name), here + name)
        # A file written into the holes others leave: fragmented into more
        # extents than a catalog record holds, so the rest are in the
        # extents overflow file.
        # The volume is filled, then every other small file deleted: the
        # only free space left is those holes.
        run('hmkdir', ':frag')
        holes = os.path.join(source, 'hole.bin')
        with open(holes, 'wb') as handle:
            handle.write(stream('hole', 3000))
        for number in range(HFS_HOLES):
            run('hcopy', '-r', holes, f':frag:hole-{number:02d}.bin')
        free = hfs_free_bytes()
        filler = os.path.join(source, 'filler.bin')
        with open(filler, 'wb') as handle:
            handle.write(bytes(max(0, free - 2048)))
        run('hcopy', '-r', filler, ':frag:filler.bin')
        for number in range(0, HFS_HOLES, 2):
            run('hdel', f':frag:hole-{number:02d}.bin')
        fragmented = os.path.join(source, 'frag', 'fragmented.bin')
        os.makedirs(os.path.dirname(fragmented), exist_ok=True)
        with open(fragmented, 'wb') as handle:
            handle.write(stream('fragmented', 40_000))
        run('hcopy', '-r', fragmented, ':frag:fragmented.bin')
        listing = run('hls', '-l', ':frag')
        filler_size = os.path.getsize(filler)
        os.remove(filler)
    finally:
        run('humount')
    os.remove(holes)
    files = answer(source, times=False)
    for number in range(1, HFS_HOLES, 2):
        files[f'/frag/hole-{number:02d}.bin'] = {
            'type': 'file', 'size': 3000,
            'sha256': hashlib.sha256(stream('hole', 3000)).hexdigest()}
    files['/frag/filler.bin'] = {
        'type': 'file', 'size': filler_size,
        'sha256': hashlib.sha256(bytes(filler_size)).hexdigest()}
    key['hfs.img'] = {'fs': 'HFS', 'writer': 'hfsutils', 'files': files,
                      'listing': listing}


# -- JFFS2 --------------------------------------------------------------------

def jffs2(folder, source, key):
    files = answer(source)
    everything = ['-x', 'zlib', '-x', 'rtime', '-x', 'lzo']
    for name, options in (
            ('jffs2-zlib.img', ['-x', 'lzo', '-x', 'rtime']),
            ('jffs2-lzo.img', ['-X', 'lzo', '-x', 'zlib', '-x', 'rtime']),
            ('jffs2-rtime.img', ['-X', 'rtime', '-x', 'zlib', '-x', 'lzo']),
            ('jffs2-none.img', everything),
            ('jffs2-be.img', ['-b', '-x', 'lzo'])):
        target = os.path.join(folder, name)
        command = ['mkfs.jffs2', '-r', source, '-o', target, '-e', '0x10000',
                   '-p']
        if '-b' not in options:
            command.append('-l')
        run(*command, *options)
        key[name] = {'fs': 'JFFS2', 'options': ' '.join(options),
                     'files': files}


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    source = tempfile.mkdtemp()
    unix_tree(source)
    key = {}
    squashfs(folder, source, key)
    erofs(folder, source, key)
    udf(folder, source, key)
    hfs(folder, key)
    jffs2(folder, source, key)
    tools = {name: version(*command) for name, command in (
        ('mksquashfs', ('mksquashfs', '-version')),
        ('mkfs.erofs', ('mkfs.erofs', '-V')),
        ('mkudffs', ('mkudffs', '--help')),
        ('genisoimage', ('genisoimage', '--version')),
        ('mkfs.jffs2', ('mkfs.jffs2', '--version')))}
    with open(os.path.join(folder, 'fs-images-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'tools': tools, 'images': key}, handle, indent=2,
                  sort_keys=True, ensure_ascii=False)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

"""Build disk images in the containers TRACE reads in Python -- Android
sparse images, Android super (dynamic partition) images, VirtualBox VDI,
AFF v3 and compressed raw images -- each written by its own tool.

A reader checked only against its own idea of a format would agree with
itself. Here one small disk (a GPT disk holding an ext4 file system with a
known tree) is written into each container by the program that defines
it, and each tool's own reader (simg2img, lpunpack, qemu-img, affcat, the
decompressors) reads it back to say what the answer is:

* sparse-fs.simg      img2simg of the ext4 file system (raw, fill and
                      don't-care chunks)
* sparse-disk.simg    img2simg of the whole disk
* super.img           lpmake (AOSP liblp, android-14.0.0_r1, built here):
                      system_a = the ext4 file system, vendor_a = an EROFS
                      image, product_a empty, two metadata slots
* super-sparse.img    the same, written sparse (lpmake --sparse)
* disk.vdi / disk-fixed.vdi   qemu-img: dynamic and fixed VDI
* disk.aff / disk-lzma.aff / disk-plain.aff   affconvert: zlib, LZMA and
                      uncompressed 1 MiB pages
* disk.raw.gz, disk-members.raw.gz (one gzip member per 4 MiB),
  disk.raw.xz, disk-blocks.raw.xz (1 MiB xz blocks), disk.raw.zst,
  disk-frames.raw.zst (one zstd frame per 4 MiB), disk.raw.bz2,
  disk-streams.raw.bz2 (pbzip2), disk.raw.lz4, disk-linked.raw.lz4
  (-BD: blocks depend on each other)

and container-images-key.json: per image, the SHA-256 and size of what it
holds (the disk, or for super images each partition), and the tree's
answer.

    python3 tools/testdata/build/make_container_images.py [folder]   # Linux

Needs e2fsprogs, fdisk, erofs-utils, android-sdk-libsparse-utils,
qemu-utils, afflib-tools, gzip, xz-utils, zstd, bzip2, pbzip2, lz4, and
for lpmake: curl, g++ and Ubuntu 24.04's android-libbase-dev,
android-liblog-dev, android-libsparse-dev, android-libext4-utils-dev,
android-libcutils-dev, android-libboringssl-dev, zlib1g-dev. On Windows
or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && apt-get install -y -qq --no-install-recommends \\
         python3 e2fsprogs fdisk erofs-utils android-sdk-libsparse-utils \\
         qemu-utils afflib-tools xz-utils zstd bzip2 pbzip2 lz4 curl \\
         ca-certificates g++ android-libbase-dev android-liblog-dev \\
         android-libsparse-dev android-libext4-utils-dev \\
         android-libcutils-dev android-libboringssl-dev zlib1g-dev \\
         >/dev/null && python3 tools/testdata/build/make_container_images.py"
"""

import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

MIB = 1024 * 1024
EPOCH = 1_700_000_000
#: AOSP's liblp and lpmake, at this tag (Ubuntu 24.04's Android libraries
#: are android-14).
AOSP_TAG = 'android-14.0.0_r1'
AOSP = 'https://android.googlesource.com/platform/'
LIBLP = AOSP + f'system/core/+archive/refs/tags/{AOSP_TAG}/fs_mgr/liblp.tar.gz'
PARTITION_TOOLS = AOSP + (f'system/extras/+archive/refs/tags/{AOSP_TAG}/'
                          f'partition_tools.tar.gz')


def run(*command, cwd=None, data=None):
    result = subprocess.run(command, capture_output=True, cwd=cwd,
                            input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:4])}... failed:\n"
                 f"{result.stdout.decode(errors='replace')}"
                 f"{result.stderr.decode(errors='replace')}")
    return result.stdout


def shell(script, cwd=None):
    return run('sh', '-c', script, cwd=cwd)


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(MIB), b''):
            digest.update(chunk)
    return digest.hexdigest()


def tree(root):
    files = {}

    def put(path, data):
        full = os.path.join(root, *path.split('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as handle:
            handle.write(data)
        os.utime(full, (EPOCH + len(files), EPOCH + len(files)))
        files['/' + path] = hashlib.sha256(data).hexdigest()

    put('README.txt', b'Container test disk for TRACE.\n' * 20)
    put('docs/report.bin', stream('report', 300_000))
    put('docs/pattern.bin', b'\xab\xcd\xef\x01' * 65536)   # fill chunks
    put('big/video.bin', stream('video', 2 * MIB + 77))
    for number in range(40):
        put(f'many/file-{number:02d}.dat', stream(f'many{number}',
                                                  1000 + number * 37))
    return files


def build_lpmake(work):
    """lpmake and lpunpack from AOSP's sources, against Ubuntu's Android
    libraries."""
    os.makedirs(os.path.join(work, 'liblp'))
    os.makedirs(os.path.join(work, 'pt'))
    shell(f"curl -sfL '{LIBLP}' | tar -xz -C liblp", cwd=work)
    shell(f"curl -sfL '{PARTITION_TOOLS}' | tar -xz -C pt", cwd=work)
    libdir = os.path.dirname(glob.glob(
        '/usr/lib/*/android/libbase.so')[0])
    sources = ['liblp/builder.cpp', 'liblp/images.cpp',
               'liblp/partition_opener.cpp', 'liblp/property_fetcher.cpp',
               'liblp/reader.cpp', 'liblp/utility.cpp', 'liblp/writer.cpp']
    flags = ['-std=c++20', '-O1', '-Iliblp/include', '-Iliblp',
             '-I/usr/include/android', f'-L{libdir}',
             f'-Wl,-rpath,{libdir}']
    libraries = ['-lbase', '-llog', '-lsparse', '-lext4_utils', '-lcrypto',
                 '-lz']
    tools = {}
    for tool in ('lpmake', 'lpunpack'):
        run('g++', *flags, *sources, f'pt/{tool}.cc', *libraries,
            '-o', tool, cwd=work)
        tools[tool] = os.path.join(work, tool)
    return tools


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    work = tempfile.mkdtemp()
    source = os.path.join(work, 'tree')
    files = tree(source)

    # The file system, then the disk holding it at 1 MiB.
    fs = os.path.join(work, 'fs.ext4')
    run('mke2fs', '-F', '-q', '-t', 'ext4', '-L', 'TRACE', '-E',
        'root_owner=0:0', '-d', source, fs, '12M')
    disk = os.path.join(work, 'disk.raw')
    with open(disk, 'wb') as handle:
        handle.truncate(16 * MIB)
    run('sfdisk', '-q', disk, data=b'label: gpt\nstart=2048, size=24576, '
                                    b'name=data\n')
    shell(f"dd if={fs} of={disk} bs=1M seek=1 conv=notrunc status=none")
    vendor = os.path.join(work, 'vendor.erofs')
    run('mkfs.erofs', '-zlz4', vendor, source)

    key = {'tree': files,
           'disk': {'sha256': sha256_file(disk),
                    'size': os.path.getsize(disk)},
           'fs': {'sha256': sha256_file(fs), 'size': os.path.getsize(fs)},
           'vendor': {'sha256': sha256_file(vendor),
                      'size': os.path.getsize(vendor)},
           'images': {}}

    def keep(name, holds, writer, **extra):
        key['images'][name] = dict({'holds': holds, 'writer': writer},
                                   **extra)

    def check(name, read_back):
        """What the tool's own reader gives must be what went in."""
        holds = key['images'][name]['holds']
        if sha256_file(read_back) != key[holds]['sha256']:
            sys.exit(f"{name}: read back differs from the {holds}")

    # Android sparse.
    for name, holds in (('sparse-fs.simg', 'fs'), ('sparse-disk.simg',
                                                   'disk')):
        target = os.path.join(folder, name)
        run('img2simg', fs if holds == 'fs' else disk, target)
        back = os.path.join(work, name + '.raw')
        run('simg2img', target, back)
        keep(name, holds, 'img2simg')
        check(name, back)

    # Android super, from lpmake built here.
    tools = build_lpmake(os.path.join(work, 'aosp'))
    vendor_size = (os.path.getsize(vendor) + 4095) // 4096 * 4096
    for name, sparse in (('super.img', False), ('super-sparse.img', True)):
        target = os.path.join(folder, name)
        command = [tools['lpmake'], '--metadata-size', '65536',
                   '--super-name', 'super', '--metadata-slots', '2',
                   '--device', f'super:{64 * MIB}',
                   '--group', f'main:{48 * MIB}',
                   '--partition', f'system_a:readonly:{12 * MIB}:main',
                   '--image', f'system_a={fs}',
                   '--partition', f'vendor_a:readonly:{vendor_size}:main',
                   '--image', f'vendor_a={vendor}',
                   '--partition', 'product_a:readonly:0:main',
                   '--output', target]
        if sparse:
            command.append('--sparse')
        run(*command)
        unpacked = tempfile.mkdtemp()
        readable = target
        if sparse:
            # lpunpack reads only a flat super image.
            readable = os.path.join(work, name + '.raw')
            run('simg2img', target, readable)
        run(tools['lpunpack'], readable, unpacked)
        partitions = {}
        for part in sorted(os.listdir(unpacked)):
            path = os.path.join(unpacked, part)
            partitions[part[:-4] if part.endswith('.img') else part] = {
                'sha256': sha256_file(path), 'size': os.path.getsize(path)}
        keep(name, 'super', 'lpmake (AOSP liblp, ' + AOSP_TAG + ')',
             sparse=sparse, partitions=partitions,
             filesystems={'system_a': 'fs', 'vendor_a': 'vendor'})

    # VirtualBox.
    for name, options in (('disk.vdi', []), ('disk-fixed.vdi',
                                             ['-o', 'static=on'])):
        target = os.path.join(folder, name)
        run('qemu-img', 'convert', '-f', 'raw', '-O', 'vdi', *options,
            disk, target)
        back = os.path.join(work, name + '.raw')
        run('qemu-img', 'convert', '-f', 'vdi', '-O', 'raw', target, back)
        keep(name, 'disk', 'qemu-img', options=' '.join(options))
        check(name, back)

    # AFF v3.
    # 1 MiB pages (-s): the default 16 MiB would hold this disk whole.
    for name, options in (('disk.aff', ['-s1m']),
                          ('disk-lzma.aff', ['-L', '-s1m']),
                          ('disk-plain.aff', ['-x', '-s1m'])):
        target = os.path.join(folder, name)
        if os.path.exists(target):
            os.remove(target)
        run('affconvert', '-y', *options, '-o', target, disk)
        back = os.path.join(work, name + '.raw')
        shell(f"affcat '{target}' > '{back}'")
        info = run('affinfo', '-m', target).decode(errors='replace')
        keep(name, 'disk', 'affconvert', options=' '.join(options),
             affinfo=info[-400:])
        check(name, back)

    # Split AFF (-M: the largest file): an AFD folder of .aff files, and
    # AFMs -- metadata in .afm, data in split raw files. The one-file AFM
    # (no -M) is checked by its raw file: AFFLIB's affcat reads only its
    # first page (pages_per_raw_image_file 0).
    afd = os.path.join(folder, 'disk.afd')
    split = os.path.join(folder, 'aff-split')
    for path in (afd, split):
        if os.path.exists(path):
            shutil.rmtree(path)
    os.makedirs(split)
    # Uncompressed (-x), or the small test disk fits one file.
    run('affconvert', '-y', '-x', '-s1m', '-M3m', '-o', afd, disk)
    for name, options in (('disk-split.afm', ['-M3m']),
                          ('disk-one.afm', [])):
        run('affconvert', '-y', '-s1m', *options, '-o',
            os.path.join(split, name), disk)
    back = os.path.join(work, 'afd.raw')
    shell(f"affcat '{afd}' > '{back}'")
    keep('disk.afd', 'disk', 'affconvert -x -M3m',
         files=sorted(os.listdir(afd)))
    check('disk.afd', back)
    back = os.path.join(work, 'afm.raw')
    shell(f"affcat '{split}/disk-split.afm' > '{back}'")
    keep('aff-split/disk-split.afm', 'disk', 'affconvert -M3m',
         files=sorted(n for n in os.listdir(split)
                      if n.startswith('disk-split')))
    check('aff-split/disk-split.afm', back)
    keep('aff-split/disk-one.afm', 'disk', 'affconvert (one raw file)',
         affinfo=run('affinfo', '-m', os.path.join(split, 'disk-one.afm'))
         .decode(errors='replace')[-400:])
    check('aff-split/disk-one.afm', os.path.join(split, 'disk-one.000'))

    # Compressed raw images.
    pieces = os.path.join(work, 'pieces')
    os.makedirs(pieces)
    shell(f"split -b 4M -d '{disk}' '{pieces}/p'")
    compressed = (
        ('disk.raw.gz', f"gzip -c '{disk}'", 'gzip -dc'),
        ('disk-members.raw.gz', f"for p in '{pieces}'/p*; do gzip -c \"$p\"; "
                                f"done", 'gzip -dc'),
        ('disk.raw.xz', f"xz -c '{disk}'", 'xz -dc'),
        ('disk-blocks.raw.xz', f"xz -c -T2 --block-size=1MiB '{disk}'",
         'xz -dc'),
        ('disk.raw.zst', f"zstd -q -c '{disk}'", 'zstd -dc'),
        ('disk-frames.raw.zst', f"for p in '{pieces}'/p*; do zstd -q -c "
                                f"\"$p\"; done", 'zstd -dc'),
        ('disk.raw.bz2', f"bzip2 -c '{disk}'", 'bzip2 -dc'),
        ('disk-streams.raw.bz2', f"pbzip2 -c -b9 '{disk}'", 'bzip2 -dc'),
        ('disk.raw.lz4', f"lz4 -q -c '{disk}'", 'lz4 -dc'),
        ('disk-linked.raw.lz4', f"lz4 -q -BD -c '{disk}'", 'lz4 -dc'))
    for name, make, unmake in compressed:
        target = os.path.join(folder, name)
        shell(f"{make} > '{target}'")
        back = os.path.join(work, name + '.raw')
        shell(f"{unmake} '{target}' > '{back}'")
        keep(name, 'disk', make.split()[0] if not make.startswith('for')
             else make.split(';')[1].split()[0])
        check(name, back)

    key['tools'] = {tool: run('sh', '-c', f'{command} 2>&1 | head -1')
                    .decode(errors='replace').strip()
                    for tool, command in (
                        ('img2simg', 'dpkg-query -W android-sdk-libsparse-'
                                     'utils'),
                        ('qemu-img', 'qemu-img --version'),
                        ('affconvert', 'dpkg-query -W afflib-tools'),
                        ('xz', 'xz --version'), ('zstd', 'zstd --version'),
                        ('lz4', 'lz4 --version'))}
    with open(os.path.join(folder, 'container-images-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump(key, handle, indent=2, sort_keys=True)
    shutil.rmtree(work, ignore_errors=True)
    print(f"{len(key['images'])} container images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

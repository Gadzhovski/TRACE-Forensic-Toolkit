"""Embedded file systems, and the Linux kernel's own reading of them, for
TRACE's readers (core/qnx4.py, qnx6.py, cramfs.py, romfs.py).

The answer key for each image is what the kernel's read-only driver lists
when it mounts it, in a QEMU guest (qemu_guest.py, kernel_keys_init.sh):
path, type, size, SHA-256 or link target, modification time. Built:

* qnx4-tree.img   by qnx4_writer.py from the shared Unix tree (QNX's own
                  tools run only on QNX), with two deleted files -- one
                  whose blocks are free, one whose blocks another file took
* cramfs-le.cramfs / cramfs-be.cramfs   mkfs.cramfs (util-linux), both
                  byte orders; the kernel mounts only its own (little-
                  endian), so the big-endian image's key is the tree's
* romfs.img       genromfs

and, read by the kernel as they are, the pinned samples: openqnx's real
QNX4 floppy (openqnx-qnxfs.img), qnxmount's QNX6 image, unblob's
little-endian cramfs and romfs images. Written to test_images/built with
kernel-fs-key.json.

    python3 tools/testdata/build/make_kernel_keys.py [folder]   # Linux

Needs qemu-system-x86, linux-image-generic + linux-modules-extra (qnx4,
qnx6, cramfs, romfs), busybox-static, zstd, cpio, kmod, util-linux-extra
(mkfs.cramfs) and genromfs. On Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 qemu-system-x86 \\
         linux-image-generic busybox-static zstd cpio kmod \\
         util-linux-extra genromfs >/dev/null && \\
         apt-get install -y -qq linux-modules-extra-\\$(ls /lib/modules | \\
         sort -V | tail -1) >/dev/null && \\
         python3 tools/testdata/build/make_kernel_keys.py"
"""

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'make_fs_images', os.path.join(_HERE, 'make_fs_images.py'))
fs_images = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fs_images)
sys.path.insert(0, _HERE)
import qemu_guest  # noqa: E402  (beside this script)
import qnx4_writer  # noqa: E402

SAMPLES = os.path.join(_HERE, '..', '..', '..', 'test_images', 'samples')
#: Pinned samples the kernel reads as they are: name -> (fstype, label).
KERNEL_READS = {'openqnx-qnxfs.img': 'qnx4',
                'qnxmount-qnx6-test_image.bin': 'qnx6',
                'unblob-fruits.cramfs_le': 'cramfs',
                'unblob-fruits.old.cramfs_le': 'cramfs',
                'unblob-fruits.romfs': 'romfs'}
DELETED = {'deleted-free.txt': b'This file was deleted; its blocks are '
                               b'free still.\n' * 30}
REUSED = {'deleted-reused.txt': b'This file was deleted; another file took '
                                b'its blocks.\n' * 20}
LISTING = 32 * 1024 * 1024


def _disk(path, folder):
    """A copy padded to whole 512-byte sectors: QEMU's virtio disk."""
    copy = os.path.join(folder, os.path.basename(path) + '.disk')
    shutil.copy(path, copy)
    size = os.path.getsize(copy)
    if size % 512:
        with open(copy, 'ab') as handle:
            handle.write(bytes(512 - size % 512))
    return copy


def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                             os.path.join(_HERE, '..', '..', '..',
                                          'test_images', 'built'))
    os.makedirs(folder, exist_ok=True)
    source = tempfile.mkdtemp()
    fs_images.unix_tree(source)
    tree = fs_images.answer(source)
    key = {}

    qnx4 = os.path.join(folder, 'qnx4-tree.img')
    skipped = qnx4_writer.write(source, qnx4, 24 * 1024 * 1024,
                                deleted=DELETED, reused=REUSED)
    key['qnx4-tree.img'] = {
        'fs': 'qnx4', 'writer': 'qnx4_writer.py',
        'not_written': sorted('/' + os.path.relpath(p, source)
                              for p in skipped),
        'deleted': {f'/{name}': {
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}
            for name, data in DELETED.items()},
        'overwritten': sorted(f'/{name}' for name in REUSED)}

    cramfs_tree = {path: dict(entry) for path, entry in tree.items()}
    for entry in cramfs_tree.values():
        entry.pop('mtime', None)
    for name, options in (('cramfs-le.cramfs', ['-N', 'little']),
                          ('cramfs-be.cramfs', ['-N', 'big'])):
        fs_images.run('mkfs.cramfs', *options, source,
                      os.path.join(folder, name))
        key[name] = {'fs': 'cramfs', 'options': ' '.join(options),
                     'tree': cramfs_tree}
    fs_images.run('genromfs', '-f', os.path.join(folder, 'romfs.img'),
                  '-d', source, '-V', 'TRACE romfs')
    key['romfs.img'] = {'fs': 'romfs', 'tree': cramfs_tree}

    release = qemu_guest.kernel_release('qnx4', 'qnx6', 'cramfs', 'romfs')
    if release is None:
        sys.exit("No qemu-system-x86_64, or no kernel with the qnx4, qnx6, "
                 "cramfs and romfs modules")
    guest = qemu_guest.Guest(release,
                             os.path.join(_HERE, 'kernel_keys_init.sh'))
    guest.add_modules([(name, '') for name in
                       ('qnx4', 'qnx6', 'cramfs', 'romfs')])
    disks, lines = [], []
    reads = [(os.path.join(folder, name), entry['fs'], name)
             for name, entry in key.items() if name != 'cramfs-be.cramfs']
    for name, fstype in KERNEL_READS.items():
        path = os.path.join(SAMPLES, name)
        if not os.path.exists(path):
            print(f"{name} is not in test_images/samples (python -m "
                  f"tools.testdata.fetch --group samples): not read")
            continue
        reads.append((path, fstype, name))
        key.setdefault(name, {'fs': fstype, 'sample': True})
    listing = os.path.join(guest.work, 'listing')
    fs_images.blank(listing, LISTING)
    for number, (path, fstype, name) in enumerate(reads):
        disks.append(_disk(path, guest.work))
        lines.append(f"vd{chr(ord('b') + number)} {fstype} {name}")
    guest.add_file('/disks', ('\n'.join(lines) + '\n').encode())
    console = guest.boot([listing] + disks)
    with open(os.path.join(folder, 'kernel-fs-console.log'), 'w',
              encoding='utf-8') as handle:
        handle.write(console)
    text = qemu_guest.read_listing(listing)
    for _path, _fstype, name in reads:
        key[name]['kernel'] = qemu_guest.parse_listing(text, name)
        key[name]['reader'] = f'Linux {release} fs/{key[name]["fs"]}'
    with open(os.path.join(folder, 'kernel-fs-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'tools': {
            'mkfs.cramfs': fs_images.version('mkfs.cramfs', '-V'),
            'genromfs': fs_images.version('genromfs', '-h')},
            'images': key}, handle, indent=1, sort_keys=True,
            ensure_ascii=False)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

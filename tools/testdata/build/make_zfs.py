"""Build ZFS pools with OpenZFS itself, for TRACE's reader (core/zfs.py).

No library with wheels reads ZFS, and nothing but OpenZFS writes it, so
the pools are written by the kernel module and zpool/zfs of Ubuntu 24.04
(OpenZFS 2.2), in a QEMU guest (qemu_guest.py, zfs_guest_init.sh) -- no
module is loaded on the build machine. Whole disks, as zpool labels them
(GPT, the pool in partition 1 -- sgdisk partitions them here: the guest has
no udev, which zpool's own labelling of a whole disk waits for):

* zfs-solo.img           pool 'solo', one disk, ashift 12, lz4: the tree, datasets with
                         gzip-9, zstd, lzjb, zle and no compression, a
                         dataset with 512-byte records (a file of three
                         levels of indirect blocks), nested datasets, and
                         snapshot solo@before -- after which a file was
                         deleted, one rewritten and one added
* zfs-mirror-<0|1>.img   pool 'twin', a two-way mirror, ashift 9
* zfs-raidz1-<0|1|2>.img pool 'parity', a three-disk raidz1, ashift 12,
                         uncompressed
* zfs-raidz2-<0..3>.img  pool 'double', a four-disk raidz2, ashift 9, lz4
* zfs-stripe-<0|1>.img   pool 'wide', two disks as two top-level vdevs
                         (blocks spread over both), zstd

Each pool is exported at the end. zfs-key.json: per dataset (and the
snapshot) every entry as the guest listed it (path, type, size, SHA-256 or
link target, modification time), the pool's member disks, and the guest's
`zpool status` / `zfs list` for reference.

    python3 tools/testdata/build/make_zfs.py [folder]     # Linux

Needs qemu-system-x86, linux-image-generic, zfsutils-linux, gdisk,
busybox-static, zstd and cpio. On Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 qemu-system-x86 \\
         linux-image-generic zfsutils-linux gdisk busybox-static zstd cpio kmod \\
         >/dev/null && python3 tools/testdata/build/make_zfs.py"
"""

import importlib.util
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'make_fs_images', os.path.join(_HERE, 'make_fs_images.py'))
fs_images = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fs_images)
sys.path.insert(0, _HERE)
import qemu_guest  # noqa: E402  (beside this script)

DISK = 256 * 1024 * 1024
SMALL_DISK = 128 * 1024 * 1024
LISTING = 16 * 1024 * 1024
POOLS = {'solo': ['zfs-solo.img'],
         'twin': ['zfs-mirror-0.img', 'zfs-mirror-1.img'],
         'parity': ['zfs-raidz1-0.img', 'zfs-raidz1-1.img',
                    'zfs-raidz1-2.img'],
         'double': [f'zfs-raidz2-{n}.img' for n in range(4)],
         'wide': ['zfs-stripe-0.img', 'zfs-stripe-1.img']}
TOOLS = ('zpool', 'zfs', 'mount.zfs')
#: The partition type zpool gives its own (Solaris /usr & Apple ZFS).
ZFS_TYPE = '6A898CC3-1DD2-11B2-99A6-080020736631'


def sections(text):
    """The guest's listing -> ({dataset: {path: record}}, {dataset:
    compression}, the rest of the text)."""
    datasets, compression, rest = {}, {}, []
    current = None
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) != 3:
            rest.append(line)
            continue
        kind, fields, path = parts
        if kind == 'dataset':
            current = path
            datasets[current] = {}
            compression[current] = fields
            continue
        if not path.startswith(current + '/'):
            rest.append(line)
            continue
        relative = path[len(current):]
        datasets[current].update(
            qemu_guest.parse_listing(f"{kind}\t{fields}\t{relative}"))
    return datasets, compression, '\n'.join(rest)


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        _HERE, '..', '..', '..', 'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    release = qemu_guest.kernel_release('zfs', 'spl')
    if release is None:
        sys.exit("No qemu-system-x86_64, or no kernel with the ZFS module")
    guest = qemu_guest.Guest(release,
                             os.path.join(_HERE, 'zfs_guest_init.sh'))
    for tool in TOOLS:
        guest.add_binary(tool)
    guest.add_modules((('zfs', ''),))
    source = os.path.join(guest.work, 'tree')
    os.makedirs(source)
    fs_images.unix_tree(source)
    guest.add_tree(source, '/tree')
    listing = os.path.join(guest.work, 'listing')
    fs_images.blank(listing, LISTING)
    disks = []
    for names in POOLS.values():
        for name in names:
            path = os.path.join(folder, name)
            if os.path.exists(path):
                os.remove(path)
            fs_images.blank(path, DISK if name == 'zfs-solo.img'
                            else SMALL_DISK)
            qemu_guest.run('sgdisk', '-n', '1:2048:0', '-t', f'1:{ZFS_TYPE}',
                           '-c', '1:zfs', path)
            disks.append(path)
    guest.boot([listing] + disks, memory=2048)
    datasets, compression, rest = sections(qemu_guest.read_listing(listing))
    key = {'writer': f'OpenZFS (Ubuntu 24.04), Linux {release}, under QEMU',
           'pools': {pool: {'disks': names} for pool, names in
                     POOLS.items()},
           'datasets': {name: {'compression': compression[name],
                               'files': files}
                        for name, files in datasets.items()},
           'deleted_after_snapshot': ['/docs/report.bin'],
           'guest_report': rest}
    with open(os.path.join(folder, 'zfs-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump(key, handle, indent=2, sort_keys=True, ensure_ascii=False)
    print(f"{len(datasets)} datasets in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

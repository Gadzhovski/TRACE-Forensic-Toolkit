"""Build UBI and UBIFS images with mtd-utils, for TRACE's readers
(core/ubi.py, core/ubifs.py).

Neither The Sleuth Kit nor any library with wheels reads UBIFS, so TRACE
reads it in Python; these images are written by the tools embedded Linux
builds use (Buildroot, Yocto, OpenWrt), so the readers are checked against
the format as it is written, not as TRACE imagines it:

* ubifs-<lzo|zlib|zstd|none>.ubifs   mkfs.ubifs, each compressor: a bare
                         UBIFS image (logical erase blocks end to end)
* ubifs-favor-lzo.ubifs  LZO and zlib mixed, file by file
* ubifs-fanout4.ubifs    an index fanout of 4: a deep index tree
* ubi-multi.ubi          ubinize: a UBI image (128 KiB erase blocks, 2 KiB
                         pages, 512-byte sub-pages) holding two UBIFS
                         volumes ('rootfs' LZO, 'data' zlib) and a static
                         raw volume ('kernel')
* ubifs-kernel.ubi       written by the Linux kernel itself: Ubuntu's kernel
                         booted under QEMU, nandsim (128 MiB NAND, 2 KiB
                         pages), UBI attached, the tree copied into a UBIFS
                         volume and committed (unmount), then mounted again
                         and changed -- files added, deleted, renamed,
                         truncated, overwritten -- and synced but not
                         committed, so those changes are only in the
                         journal (ubifs_guest_init.sh); the flash is read
                         out while mounted

and ubifs-key.json: per image, every file's path, type, size and SHA-256 (a
link's target) and modification time -- the tree's, as written to it; for
the kernel image what that kernel listed (find, stat, sha256sum) before the
read-out -- and the raw volume's SHA-256.

    python3 tools/testdata/build/make_ubifs.py [folder]     # Linux

Needs mtd-utils (Ubuntu 24.04: 2.2.0, with zstd); for the kernel image also
qemu-system-x86, linux-image-generic and linux-modules-extra (nandsim, UBI,
UBIFS), busybox-static, zstd and cpio. On Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 mtd-utils \\
         qemu-system-x86 linux-image-generic busybox-static zstd cpio \\
         >/dev/null && apt-get install -y -qq --no-install-recommends \\
         linux-modules-extra-\\$(ls /lib/modules) >/dev/null && \\
         python3 tools/testdata/build/make_ubifs.py"
"""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'make_fs_images', os.path.join(_HERE, 'make_fs_images.py'))
fs_images = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fs_images)
sys.path.insert(0, _HERE)
import qemu_guest  # noqa: E402  (beside this script)

#: NAND geometry: 128 KiB erase blocks, 2 KiB pages, 512-byte sub-pages --
#: the EC header at 0, the VID header at 512, data from 2,048.
PEB = 128 * 1024
PAGE = 2048
SUBPAGE = 512
LEB = PEB - PAGE
MAX_LEBS = 2048


def mkfs(source, target, *options):
    fs_images.run('mkfs.ubifs', '-r', source, '-o', target, '-m', str(PAGE),
                  '-e', str(LEB), '-c', str(MAX_LEBS), *options)


# -- written by the kernel ----------------------------------------------------

#: The modules to load, with their parameters: nandsim as a 128 MiB NAND
#: of 2 KiB pages and 128 KiB blocks (ID bytes 20 f1 00 15), UBI attached
#: to it, and the compressors UBIFS asks the crypto API for (soft
#: dependencies: modprobe does not list them).
MODULES = (('nandsim', 'first_id_byte=0x20 second_id_byte=0xf1 '
                       'third_id_byte=0x00 fourth_id_byte=0x15'),
           ('ubi', 'mtd=0'),
           ('lzo', ''), ('deflate', ''), ('zstd', ''),
           ('ubifs', ''))


FLASH = 128 * 1024 * 1024
LISTING = 8 * 1024 * 1024


def kernel_image(folder, source, key):
    """ubifs-kernel.ubi, and its key from the guest's own listing."""
    release = qemu_guest.kernel_release('nandsim', 'ubifs')
    guest = qemu_guest.Guest(release,
                             os.path.join(_HERE, 'ubifs_guest_init.sh'))
    # Ubuntu's busybox has no UBI applets: mtd-utils' own.
    guest.add_binary('ubimkvol')
    guest.add_modules(MODULES)
    guest.add_tree(source, '/tree')
    flash = os.path.join(folder, 'ubifs-kernel.ubi')
    listing = os.path.join(guest.work, 'listing')
    if os.path.exists(flash):
        os.remove(flash)
    fs_images.blank(flash, FLASH)
    fs_images.blank(listing, LISTING)
    guest.boot([flash, listing])
    files = qemu_guest.parse_listing(qemu_guest.read_listing(listing))
    key['ubifs-kernel.ubi'] = {
        'fs': 'UBI', 'writer': f'Linux {release} (nandsim, under QEMU)',
        'volumes': {'rootfs': {'id': 0, 'type': 'dynamic', 'fs': 'UBIFS',
                               'files': files}},
        'gone': ['/docs/report.bin', '/docs/notes.txt',
                 '/many/file-010.dat']}


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        _HERE, '..', '..', '..', 'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    source = tempfile.mkdtemp()
    fs_images.unix_tree(source)
    files = fs_images.answer(source)
    key = {}
    for name, options in (
            ('ubifs-lzo.ubifs', ['-x', 'lzo']),
            ('ubifs-zlib.ubifs', ['-x', 'zlib']),
            ('ubifs-zstd.ubifs', ['-x', 'zstd']),
            ('ubifs-none.ubifs', ['-x', 'none']),
            ('ubifs-favor-lzo.ubifs', ['-x', 'favor_lzo', '-X', '5']),
            ('ubifs-fanout4.ubifs', ['-x', 'lzo', '-f', '4'])):
        mkfs(source, os.path.join(folder, name), *options)
        key[name] = {'fs': 'UBIFS', 'options': ' '.join(options),
                     'files': files}

    # A UBI image: two UBIFS volumes and a static raw one.
    work = tempfile.mkdtemp()
    second = tempfile.mkdtemp()
    tree = fs_images.Tree(second)
    tree.put('data.txt', b'The second UBIFS volume.\n' * 50)
    tree.put('logs/boot.log', fs_images.text('boot', 300_000))
    second_files = fs_images.answer(second)
    mkfs(source, os.path.join(work, 'rootfs.ubifs'), '-x', 'lzo')
    mkfs(second, os.path.join(work, 'data.ubifs'), '-x', 'zlib')
    kernel = fs_images.stream('kernel', 700_001)
    with open(os.path.join(work, 'kernel.bin'), 'wb') as handle:
        handle.write(kernel)
    config = os.path.join(work, 'ubinize.cfg')
    with open(config, 'w') as handle:
        handle.write(
            "[kernel]\nmode=ubi\nvol_id=0\nvol_type=static\n"
            "vol_name=kernel\nimage=kernel.bin\n\n"
            "[rootfs]\nmode=ubi\nvol_id=1\nvol_type=dynamic\n"
            "vol_name=rootfs\nimage=rootfs.ubifs\nvol_size=40MiB\n\n"
            "[data]\nmode=ubi\nvol_id=2\nvol_type=dynamic\n"
            "vol_name=data\nimage=data.ubifs\nvol_size=8MiB\n"
            "vol_flags=autoresize\n")
    fs_images.run('ubinize', '-o', os.path.join(folder, 'ubi-multi.ubi'),
                  '-p', str(PEB), '-m', str(PAGE), '-s', str(SUBPAGE),
                  config, cwd=work)
    key['ubi-multi.ubi'] = {'fs': 'UBI', 'volumes': {
        'kernel': {'id': 0, 'type': 'static', 'size': len(kernel),
                   'sha256': hashlib.sha256(kernel).hexdigest()},
        'rootfs': {'id': 1, 'type': 'dynamic', 'fs': 'UBIFS',
                   'files': files},
        'data': {'id': 2, 'type': 'dynamic', 'fs': 'UBIFS',
                 'files': second_files}}}

    if qemu_guest.kernel_release('nandsim', 'ubifs'):
        kernel_image(folder, source, key)
    else:
        print("No qemu-system-x86_64, or no kernel with nandsim and UBIFS: "
              "ubifs-kernel.ubi not built")
    tools = {'mkfs.ubifs': fs_images.version('mkfs.ubifs', '--version'),
             'ubinize': fs_images.version('ubinize', '--version')}
    with open(os.path.join(folder, 'ubifs-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'tools': tools, 'images': key}, handle, indent=2,
                  sort_keys=True, ensure_ascii=False)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

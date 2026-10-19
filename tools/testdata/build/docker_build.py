"""Build test_images/built on any machine with Docker: the Linux-only
builders of tools/testdata/build/, each in one privileged container of the
image the Dockerfile beside this script describes (Ubuntu 24.04 with what
Linux CI installs). Loop devices, the device mapper and FUSE need
--privileged; the QEMU guests (kernel keys, UBIFS, ZFS) need nothing.

    python tools/testdata/build/docker_build.py              # all
    python tools/testdata/build/docker_build.py kernel ifs   # some
    python tools/testdata/build/docker_build.py --list

Each builder's output goes to test_images/built/docker-<name>.log; a
summary says which built and which failed (a builder needing what this
machine's Docker kernel lacks -- Docker Desktop has no F2FS module --
fails alone and the others go on). Then run the tests on them:

    python tools/run_tests.py full
"""

import hashlib
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..'))
BUILT = os.path.join(REPO, 'test_images', 'built')

#: name -> (command inside the container, what it makes)
BUILDERS = {
    'kernel': ('python3 tools/testdata/build/make_kernel_keys.py',
               "QNX4 / cramfs / romfs, the kernel's reading of them and of "
               "the QNX4, QNX6, cramfs and romfs samples"),
    'ifs': ('python3 tools/testdata/build/make_ifs_images.py',
            "QNX IFS images and QNX's dumpifs reading"),
    'uboot': ('python3 tools/testdata/build/make_uboot_env.py',
              "U-Boot environments and fw_printenv's reading"),
    'littlefs': ('/opt/lfs/bin/python tools/testdata/build/make_littlefs.py',
                 "LittleFS images and littlefs's reading"),
    'fs': ('python3 tools/testdata/build/make_fs_images.py',
           'SquashFS, EROFS, UDF, classic HFS, JFFS2'),
    'ubifs': ('python3 tools/testdata/build/make_ubifs.py',
              'UBI / UBIFS (mkfs.ubifs, and the kernel under QEMU)'),
    'zfs': ('python3 tools/testdata/build/make_zfs.py',
            'ZFS pools (OpenZFS under QEMU)'),
    'btrfs': ('python3 tools/testdata/build/make_btrfs_deleted.py',
              'Btrfs with known deleted files'),
    'md': ('python3 tools/testdata/build/make_md_raid.py', 'md RAID arrays'),
    'luks': ('python3 tools/testdata/build/make_luks_lvm.py',
             'LUKS1/LUKS2 + LVM disks'),
    'veracrypt': ('python3 tools/testdata/build/make_veracrypt.py',
                  'VeraCrypt volumes (official console, pinned)'),
    'f2fs': ('python3 tools/testdata/build/make_f2fs.py',
             'F2FS (f2fs-tools built from its pinned commit)'),
    'containers': ('python3 tools/testdata/build/make_container_images.py',
                   'Android sparse/super, VDI, AFF, compressed disks'),
}


def image_tag():
    with open(os.path.join(_HERE, 'Dockerfile'), 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()[:12]
    return f'trace-testdata:{digest}'


def ensure_image(tag):
    found = subprocess.run(['docker', 'image', 'inspect', tag],
                           capture_output=True)
    if found.returncode == 0:
        return
    print(f"Building the Docker image {tag} (once; a few minutes)...")
    result = subprocess.run(['docker', 'build', '-t', tag, _HERE])
    if result.returncode:
        sys.exit("docker build failed")


def main(argv):
    if '--list' in argv:
        for name, (_command, what) in BUILDERS.items():
            print(f"{name:12} {what}")
        return 0
    chosen = [a for a in argv if not a.startswith('-')] or list(BUILDERS)
    unknown = [name for name in chosen if name not in BUILDERS]
    if unknown:
        sys.exit(f"unknown builder(s) {unknown}; --list shows them")
    if subprocess.run(['docker', 'info'], capture_output=True).returncode:
        sys.exit("Docker is not running")
    tag = image_tag()
    ensure_image(tag)
    os.makedirs(BUILT, exist_ok=True)
    results = []
    for name in chosen:
        command, what = BUILDERS[name]
        log = os.path.join(BUILT, f'docker-{name}.log')
        print(f"{name:12} {what} ...", end='', flush=True)
        started = time.time()
        env = dict(os.environ, MSYS_NO_PATHCONV='1')
        with open(log, 'w', encoding='utf-8', errors='replace') as handle:
            result = subprocess.run(
                ['docker', 'run', '--rm', '--privileged',
                 '-v', f'{REPO}:/src', '-w', '/src', tag, 'sh', '-c',
                 command], stdout=handle, stderr=subprocess.STDOUT,
                env=env)
        took = time.time() - started
        status = 'ok' if result.returncode == 0 else 'FAILED'
        print(f" {status} ({took:.0f} s)")
        results.append((name, status, log))
    failed = [r for r in results if r[1] != 'ok']
    print(f"\n{len(results) - len(failed)} of {len(results)} built "
          f"into {BUILT}")
    for name, _status, log in failed:
        print(f"  {name}: see {log}")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

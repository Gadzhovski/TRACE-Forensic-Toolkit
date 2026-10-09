"""Build Linux software RAID (md) arrays with known files, by mdadm itself.

core/mdraid.py reads md arrays from their members' images. Its tests need
arrays made by the real tools: this creates one per level and superblock
version on loop devices, puts an ext4 file system with deterministic files
on each, stops the array and keeps every member's image, with an answer
key (level, members, each file's SHA-256) beside them.

    sudo python3 tools/testdata/build/make_md_raid.py [folder]          # Linux, root

Needs mdadm, mkfs.ext4 and sfdisk. CI builds them on Ubuntu (tests.yml);
on Windows or macOS, in a privileged container:

    docker run --rm --privileged -v "$PWD:/src" -w /src debian:bookworm \\
        sh -c "apt-get update -qq && apt-get install -y -qq mdadm \\
               e2fsprogs fdisk python3 >/dev/null && python3 tools/testdata/build/make_md_raid.py"

Arrays (members are md-<name>-<n>.raw):

* raid1     2 members, superblock 1.2 (the default)
* raid1v090 2 members, superblock 0.90 (at the end of the device)
* raid1v10  2 members, superblock 1.0 (at the end, data at the start)
* raid0     2 members, 64 KiB chunks
* raid5     3 members, left-symmetric (mdadm's default)
* raid5ra   3 members, right-asymmetric
* raid6     4 members, left-symmetric
* raid10    4 members, near=2
* raid1part 2 disks, each a GPT partition of type Linux RAID holding the
            member -- as a server's disks are laid out
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

MEMBER = 24 * 1024 * 1024
PART_START = 2048
PART_SECTORS = MEMBER // 512 - PART_START - 2048
ARRAYS = (
    # name, level, members, extra mdadm options
    ('raid1', '1', 2, []),
    ('raid1v090', '1', 2, ['--metadata=0.90']),
    ('raid1v10', '1', 2, ['--metadata=1.0']),
    ('raid0', '0', 2, ['--chunk=64']),
    ('raid5', '5', 3, ['--chunk=64']),
    ('raid5ra', '5', 3, ['--chunk=64', '--layout=right-asymmetric']),
    ('raid6', '6', 4, ['--chunk=64']),
    ('raid10', '10', 4, ['--chunk=64', '--layout=n2']),
    ('raid1part', '1', 2, []),
)


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def run(*command, capture=False):
    result = subprocess.run(command, check=True, capture_output=capture,
                            text=True)
    return result.stdout.strip() if capture else None


def loop(path, offset=None, size=None):
    options = ['-f', '--show']
    if offset is not None:
        options += ['--offset', str(offset), '--sizelimit', str(size)]
    return run('losetup', *options, path, capture=True)


def build_one(folder, name, level, count, options):
    images = [os.path.join(folder, f'md-{name}-{n}.raw')
              for n in range(count)]
    loops, md, files = [], f'/dev/md/{name}', []
    started = False
    try:
        for image in images:
            with open(image, 'wb') as handle:
                handle.truncate(MEMBER)
            if name.endswith('part'):
                # A GPT disk whose one partition (type Linux RAID) is the
                # member; that byte range is loop-mounted on its own, since
                # a container has no partition device nodes.
                table = (f"label: gpt\nstart={PART_START}, "
                         f"size={PART_SECTORS}, "
                         "type=A19D880F-05FC-4D3B-A006-743F0F84911E\n")
                subprocess.run(['sfdisk', '-q', image], input=table,
                               text=True, check=True)
                loops.append(loop(image, PART_START * 512,
                                  PART_SECTORS * 512))
            else:
                loops.append(loop(image))
        run('mdadm', '--create', md, '--run', '--force', f'--level={level}',
            f'--raid-devices={count}', *options, *loops)
        started = True
        run('mkfs.ext4', '-q', '-L', name, '-b', '4096', md)
        mount = tempfile.mkdtemp()
        run('mount', md, mount)
        try:
            for index, size in enumerate((5000, 150000, 1_500_000)):
                data = stream(f'{name}:{index}', size)
                path = f'data/file{index}.bin'
                os.makedirs(os.path.join(mount, 'data'), exist_ok=True)
                with open(os.path.join(mount, path), 'wb') as handle:
                    handle.write(data)
                files.append({'path': '/' + path, 'size': size,
                              'sha256': hashlib.sha256(data).hexdigest()})
        finally:
            run('umount', mount)
            os.rmdir(mount)
        run('sync')
    finally:
        # Loop devices and arrays are the kernel's, not this process's: a
        # failed run must not leave them behind.
        if started:
            subprocess.run(['mdadm', '--stop', md], check=False)
        for device in loops:
            subprocess.run(['losetup', '-d', device], check=False)
    return {'name': name, 'level': int(level), 'members':
            [os.path.basename(i) for i in images],
            'partitioned': name.endswith('part'),
            'options': options, 'files': files}


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    folder = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(root, 'test_images', 'built')
    os.makedirs(folder, exist_ok=True)
    if os.geteuid() != 0:
        sys.exit("Run as root: the members are loop devices")
    key = [build_one(folder, *spec) for spec in ARRAYS]
    with open(os.path.join(folder, 'md-raid.json'), 'w') as handle:
        json.dump({'arrays': key}, handle, indent=1)
    print(f"{len(key)} arrays in {folder}")


if __name__ == '__main__':
    main()

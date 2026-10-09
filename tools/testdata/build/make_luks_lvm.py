"""Build encrypted Linux disks the way installers lay them out, by the
real tools: GPT -> LUKS -> LVM -> ext4.

Ubuntu's and Fedora's "encrypt the disk" installs put LVM inside LUKS, so
a reader that unlocks LUKS but looks for LVM only on the raw partition
shows nothing. TRACE's tests need such disks made by cryptsetup and lvm2
themselves: this writes one per LUKS version, each with two logical
volumes (root, home) holding known files, and in home a PNG deleted after
writing -- its bytes left in the LV's free space, for carving inside the
decrypted volume. An answer key (JSON) is written beside them.

    sudo python3 tools/testdata/build/make_luks_lvm.py [folder]          # Linux, root

Needs cryptsetup, lvm2 and mkfs.ext4. On Windows or macOS, in a
privileged container:

    docker run --rm --privileged -v "$PWD:/src" -w /src debian:bookworm \\
        sh -c "apt-get update -qq && apt-get install -y -qq cryptsetup-bin \\
               lvm2 e2fsprogs fdisk python3 >/dev/null && \\
               python3 tools/testdata/build/make_luks_lvm.py"

Disks: luks1-lvm.raw (PBKDF2, 512-byte sectors: libluksde) and
luks2-lvm.raw (argon2id, 4 KiB sectors, as installers now write them:
core/luks2.py), 48 MiB each, password PASSWORD. Argon2's memory is kept
small so a test unlocks it in a moment.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

DISK = 48 * 1024 * 1024
PART_START = 2048
PART_SECTORS = DISK // 512 - PART_START - 2048
PASSWORD = 'PASSWORD'
LVM_CONFIG = ('activation { udev_sync = 0 udev_rules = 0 } '
              'devices { obtain_device_list_from_udev = 0 }')


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def png(seed, side=96):
    """A real PNG of noise (so it does not compress away): carving proves
    it whole by its chunk CRCs."""
    pixels = stream(seed, side * side * 3)
    raw = b''.join(b'\0' + pixels[row * side * 3:(row + 1) * side * 3]
                   for row in range(side))

    def chunk(kind, data):
        return (struct.pack('>I', len(data)) + kind + data +
                struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff))
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', struct.pack('>IIBBBBB', side, side, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def run(*command, capture=False, data=None):
    result = subprocess.run(command, check=True, capture_output=capture,
                            text=True, input=data)
    return result.stdout.strip() if capture else None


def lvm(*command):
    run(command[0], '--config', LVM_CONFIG, *command[1:])


def fill(mount, prefix, sizes):
    files = []
    os.makedirs(os.path.join(mount, 'data'), exist_ok=True)
    for index, size in enumerate(sizes):
        data = stream(f'{prefix}:{index}', size)
        path = f'data/file{index}.bin'
        with open(os.path.join(mount, path), 'wb') as handle:
            handle.write(data)
        files.append({'path': '/' + path, 'size': size,
                      'sha256': hashlib.sha256(data).hexdigest()})
    return files


def build_one(folder, version):
    name = f'luks{version}-lvm'
    image = os.path.join(folder, f'{name}.raw')
    with open(image, 'wb') as handle:
        handle.truncate(DISK)
    table = (f"label: gpt\nstart={PART_START}, size={PART_SECTORS}, "
             "type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n")
    subprocess.run(['sfdisk', '-q', image], input=table, text=True,
                   check=True)
    mapper, group = f'trace{version}', f'vg{version}'
    device = run('losetup', '-f', '--show', '--offset',
                 str(PART_START * 512), '--sizelimit',
                 str(PART_SECTORS * 512), image, capture=True)
    opened = activated = False
    key = {'image': os.path.basename(image), 'password': PASSWORD,
           'luks': version, 'partition_start': PART_START, 'volumes': {}}
    try:
        options = ['--type', f'luks{version}', '--batch-mode',
                   '--key-file', '-']
        if version == 1:
            options += ['--iter-time', '50']
        if version == 2:
            options += ['--pbkdf', 'argon2id', '--pbkdf-memory', '32768',
                        '--pbkdf-parallel', '2', '--pbkdf-force-iterations',
                        '4', '--sector-size', '4096']
        run('cryptsetup', 'luksFormat', *options, device, data=PASSWORD)
        run('cryptsetup', 'open', '--key-file', '-', device, mapper,
            data=PASSWORD)
        opened = True
        plain = f'/dev/mapper/{mapper}'
        lvm('pvcreate', '-q', plain)
        lvm('vgcreate', '-q', group, plain)
        lvm('lvcreate', '-q', '-y', '-n', 'root', '-L', '16M', group)
        lvm('lvcreate', '-q', '-y', '-n', 'home', '-l', '100%FREE', group)
        activated = True
        run('dmsetup', 'mknodes')
        for volume, sizes in (('root', (4000, 200000)),
                              ('home', (7000, 900000))):
            path = f'/dev/{group}/{volume}'
            run('mkfs.ext4', '-q', '-L', volume, '-b', '4096', path)
            mount = tempfile.mkdtemp()
            run('mount', path, mount)
            try:
                record = {'files': fill(mount, f'{name}:{volume}', sizes)}
                if volume == 'home':
                    picture = png(f'{name}:deleted')
                    target = os.path.join(mount, 'deleted.png')
                    with open(target, 'wb') as handle:
                        handle.write(picture)
                    run('sync')
                    os.remove(target)
                    record['deleted_png'] = {
                        'size': len(picture),
                        'sha256': hashlib.sha256(picture).hexdigest()}
                key['volumes'][volume] = record
            finally:
                run('umount', mount)
                os.rmdir(mount)
        run('sync')
    finally:
        # Mappings and loop devices are the kernel's: never left behind.
        if activated:
            subprocess.run(['vgchange', '--config', LVM_CONFIG, '-an',
                            group], check=False)
        if opened:
            subprocess.run(['cryptsetup', 'close', mapper], check=False)
        subprocess.run(['losetup', '-d', device], check=False)
    return key


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    folder = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(root, 'test_images', 'built')
    os.makedirs(folder, exist_ok=True)
    if os.geteuid() != 0:
        sys.exit("Run as root: the disk is a loop device")
    disks = [build_one(folder, version) for version in (1, 2)]
    with open(os.path.join(folder, 'luks-lvm.json'), 'w') as handle:
        json.dump({'disks': disks}, handle, indent=1)
    print(f"{len(disks)} disks in {folder}")


if __name__ == '__main__':
    main()

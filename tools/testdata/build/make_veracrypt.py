"""Build VeraCrypt volumes with VeraCrypt itself, for core/veracrypt.py.

A VeraCrypt reader checked only against volumes written to its own reading
of the format would agree with itself whatever it got wrong. These are made
by the official VeraCrypt console (pinned below by version and SHA-256),
each holding a FAT image of known files written through VeraCrypt's own
mounted device -- so the decrypted bytes and every file have a known hash:

* vc-sha512.hc      AES, SHA-512, PIM 0 (VeraCrypt's defaults)
* vc-sha256-pim.hc  AES, SHA-256, PIM 7 (password A-PASSWORD-OF-TWENTY-PLUS)
* vc-blake2s.hc     AES, BLAKE2s-256
* vc-hidden.hc      an outer volume (OUTER) with a hidden one (HIDDEN)
* vc-serpent.hc     Serpent, SHA-512
* vc-<encryption>.hc  2 MiB, each other encryption VeraCrypt offers:
                      Twofish, Camellia, Kuznyechik and every cascade
* vc-partition.raw  a GPT disk whose partition is a VeraCrypt volume

and vc-key.json, the answer key. Password PASSWORD unless named.

    sudo python3 tools/testdata/build/make_veracrypt.py [folder]   # Linux

Needs root (VeraCrypt maps its volumes with the device mapper or FUSE),
dosfstools, mtools, fdisk. On Windows or macOS, in a privileged container:

    docker run --rm --privileged -v "$PWD:/src" -w /src ubuntu:24.04 \\
        sh -c "apt-get update -qq && apt-get install -y -qq python3 curl \\
               dosfstools mtools fdisk >/dev/null && \\
               python3 tools/testdata/build/make_veracrypt.py"

The VeraCrypt package is downloaded and checked here when `veracrypt` is
not installed.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

VERSION = '1.26.29'
PACKAGE = f'veracrypt-console-{VERSION}-Ubuntu-24.04-amd64.deb'
URL = (f'https://github.com/veracrypt/VeraCrypt/releases/download/'
       f'VeraCrypt_{VERSION}/{PACKAGE}')
PACKAGE_SHA256 = \
    '8592bbb754582cfb9ba265771b8bc0e130b81e91a23141f22cddf83496063508'

PASSWORD = 'PASSWORD'
MIB = 1024 * 1024
#: The files in each volume's FAT image: name -> size.
FILES = {'README.TXT': 700, 'PHOTO.BIN': 150_000, 'NOTES/PLAN.TXT': 4_000}


def run(*command, capture=False, data=None):
    result = subprocess.run(command, capture_output=True, text=True,
                            input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:4])}... failed:\n{result.stdout}"
                 f"{result.stderr}")
    return result.stdout.strip() if capture else None


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def install_veracrypt():
    if subprocess.run(['sh', '-c', 'command -v veracrypt'],
                      capture_output=True).returncode == 0:
        return
    work = tempfile.mkdtemp()
    package = os.path.join(work, PACKAGE)
    run('curl', '-sSLf', '-o', package, URL)
    with open(package, 'rb') as handle:
        if sha256(handle.read()) != PACKAGE_SHA256:
            sys.exit(f"{PACKAGE}: SHA-256 does not match the pinned value")
    run('sh', '-c', f'DEBIAN_FRONTEND=noninteractive apt-get install -y '
                    f'-qq {package} >/dev/null')


def fat_image(seed, size):
    """A FAT image of `size` bytes holding FILES (contents from `seed`):
    (image bytes, {path: sha256})."""
    work = tempfile.mkdtemp()
    path = os.path.join(work, 'fat.img')
    with open(path, 'wb') as handle:
        handle.truncate(size)
    run('mkfs.fat', '-n', 'TRACE', path, capture=True)
    files = {}
    env = dict(os.environ, MTOOLS_SKIP_CHECK='1')
    for name, length in FILES.items():
        data = stream(f'{seed}:{name}', length)
        local = os.path.join(work, 'file')
        with open(local, 'wb') as handle:
            handle.write(data)
        if '/' in name:
            subprocess.run(['mmd', '-i', path, '::' + name.rsplit('/', 1)[0]],
                           env=env, capture_output=True)
        subprocess.run(['mcopy', '-i', path, local, '::' + name], env=env,
                       check=True)
        files['/' + name] = sha256(data)
    with open(path, 'rb') as handle:
        return handle.read(), files


def veracrypt(*arguments):
    return run('veracrypt', '--text', '--non-interactive', *arguments,
               capture=True)


def create(target, size, password, encryption='AES', hash_name='SHA-512',
           pim=0, kind='normal', quick=False):
    arguments = ['--create', target, '--volume-type', kind,
                 '--encryption', encryption, '--hash', hash_name,
                 '--filesystem', 'none', '--password', password,
                 '--pim', str(pim), '--keyfiles', '',
                 '--random-source', '/dev/urandom']
    if size:
        arguments += ['--size', str(size)]
    if quick:
        arguments.append('--quick')
    veracrypt(*arguments)


def fill(target, password, pim, plain):
    """Mount `target`, write `plain` through VeraCrypt's own device, and
    dismount: the decrypted volume then starts with exactly these bytes
    (the rest is what creating it wrote). Returns the device's size."""
    veracrypt('--mount', target, '--filesystem', 'none', '--password',
              password, '--pim', str(pim), '--keyfiles', '',
              '--protect-hidden', 'no', '--slot', '1',
              # FUSE, not the device mapper: works wherever /dev/fuse does
              # (containers too), and leaves no kernel mapping behind.
              '--mount-options', 'nokernelcrypto')
    try:
        listing = veracrypt('--list')
        device = next(line.split()[2] for line in listing.splitlines()
                      if line.startswith('1:'))
        with open(device, 'r+b') as handle:
            handle.write(plain)
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0, 2)
            size = handle.tell()
    finally:
        veracrypt('--dismount', target)
    return size


def volume(folder, name, encryption='AES', hash_name='SHA-512', pim=0,
           size=8 * MIB, password=PASSWORD):
    target = os.path.join(folder, name)
    if os.path.exists(target):
        os.remove(target)
    create(target, size, password, encryption, hash_name, pim)
    entry = {'password': password, 'pim': pim, 'encryption': encryption,
             'hash': hash_name}
    # The usable size is the container less its two header areas.
    plain, files = fat_image(name, size - 4 * 65536)
    written = fill(target, password, pim, plain)
    entry.update(size=written, plain_length=len(plain),
                 plain_sha256=sha256(plain), files=files)
    return entry


#: Every other encryption VeraCrypt 1.26 offers, by its own names.
ENCRYPTIONS = ('Twofish', 'Camellia', 'Kuznyechik', 'AES-Twofish',
               'AES-Twofish-Serpent', 'Serpent-AES', 'Serpent-Twofish-AES',
               'Twofish-Serpent', 'Camellia-Kuznyechik', 'Camellia-Serpent',
               'Kuznyechik-AES', 'Kuznyechik-Serpent-Camellia',
               'Kuznyechik-Twofish')


def hidden_volume(folder):
    name = 'vc-hidden.hc'
    target = os.path.join(folder, name)
    if os.path.exists(target):
        os.remove(target)
    create(target, 16 * MIB, 'OUTER')
    create(target, 4 * MIB, 'HIDDEN', kind='hidden')
    outer_plain = bytes(64 * 1024)          # the outer stays empty
    outer = fill(target, 'OUTER', 0, outer_plain)
    plain, files = fat_image(name, 3 * MIB)
    written = fill(target, 'HIDDEN', 0, plain)
    return {'password': 'HIDDEN', 'outer_password': 'OUTER', 'pim': 0,
            'encryption': 'AES', 'hash': 'SHA-512', 'size': written,
            'outer_size': outer, 'plain_length': len(plain),
            'plain_sha256': sha256(plain), 'files': files}


def partition_disk(folder):
    """A 24 MiB GPT disk; its one partition (from sector 2048) is a
    VeraCrypt volume, made on a loop device as VeraCrypt makes it on a
    real disk."""
    name = 'vc-partition.raw'
    target = os.path.join(folder, name)
    with open(target, 'wb') as handle:
        handle.truncate(24 * MIB)
    run('sfdisk', '-q', target, data='label: gpt\nstart=2048, size=40960\n')
    device = run('losetup', '--find', '--show', '--offset', str(2048 * 512),
                 '--sizelimit', str(40960 * 512), target, capture=True)
    try:
        create(device, 0, PASSWORD, quick=True)
        plain, files = fat_image(name, 40960 * 512 - 4 * 65536)
        written = fill(device, PASSWORD, 0, plain)
    finally:
        run('losetup', '-d', device)
    return {'password': PASSWORD, 'pim': 0, 'encryption': 'AES',
            'hash': 'SHA-512', 'start_sector': 2048, 'size': written,
            'plain_length': len(plain), 'plain_sha256': sha256(plain),
            'files': files}


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built')
    folder = os.path.abspath(folder)
    os.makedirs(folder, exist_ok=True)
    install_veracrypt()
    version = veracrypt('--version')
    key = {'tool': version, 'package_sha256': PACKAGE_SHA256}
    key['vc-sha512.hc'] = volume(folder, 'vc-sha512.hc')
    key['vc-sha256-pim.hc'] = volume(folder, 'vc-sha256-pim.hc',
                                     hash_name='SHA-256', pim=7,
                                     # VeraCrypt takes a PIM under 485
                                     # only with 20 characters or more.
                                     password='A-PASSWORD-OF-TWENTY-PLUS')
    key['vc-blake2s.hc'] = volume(folder, 'vc-blake2s.hc',
                                  hash_name='BLAKE2s-256')
    key['vc-hidden.hc'] = hidden_volume(folder)
    key['vc-serpent.hc'] = volume(folder, 'vc-serpent.hc',
                                  encryption='Serpent')
    for encryption in ENCRYPTIONS:
        name = f'vc-{encryption.lower()}.hc'
        key[name] = volume(folder, name, encryption=encryption,
                           size=2 * MIB)
    key['vc-partition.raw'] = partition_disk(folder)
    with open(os.path.join(folder, 'vc-key.json'), 'w') as handle:
        json.dump(key, handle, indent=2, sort_keys=True)
    print(f"{version}: {len(key) - 2} volumes in {folder}")


if __name__ == '__main__':
    if not re.match(r'^linux', sys.platform):
        sys.exit("VeraCrypt volumes are built on Linux (see the docstring "
                 "for Docker).")
    main()

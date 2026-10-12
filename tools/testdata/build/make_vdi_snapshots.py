"""Build a VirtualBox snapshot chain with VirtualBox itself, for core/vdi.py.

qemu-img writes VDI but no differencing VDI; VirtualBox's own VBoxManage
does, without running a virtual machine and without its kernel driver:

* vbox-snapshots/disk.vdi             the base disk: 16 MiB of a known
                                      stream (convertfromraw)
* vbox-snapshots/Snapshots/{uuid}.vdi a differencing disk on it, then one
                                      on that (createmedium --diffparent),
                                      as VirtualBox names and places a
                                      VM's snapshots; each is written to
                                      by VirtualBox (mediumio formatfat
                                      --quick: a FAT boot sector and FATs
                                      over the parent's data)

and vbox-snapshots-key.json: for every disk of the chain, what VirtualBox
reads from it whole (mediumio cat) -- size and SHA-256 -- and its UUID and
parent's.

    python3 tools/testdata/build/make_vdi_snapshots.py [folder]

Needs VirtualBox's VBoxManage (Ubuntu 24.04: apt install virtualbox). On
Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 virtualbox \\
         >/dev/null && python3 tools/testdata/build/make_vdi_snapshots.py"
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

MIB = 1024 * 1024
SIZE = 16 * MIB


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        sys.exit(f"{' '.join(command[:4])}... failed:\n{result.stdout}"
                 f"{result.stderr}")
    return result.stdout


def stream(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def uuid_of(path):
    info = run('VBoxManage', 'showmediuminfo', 'disk', path)
    return re.search(r'^UUID:\s+(\S+)', info, re.M).group(1)


def read_whole(path, work):
    """What VirtualBox reads from the disk at `path`: (size, sha256)."""
    target = os.path.join(work, 'whole.raw')
    if os.path.exists(target):
        os.remove(target)
    run('VBoxManage', 'mediumio', f'--disk={path}', 'cat',
        f'--output={target}')
    with open(target, 'rb') as handle:
        data = handle.read()
    return len(data), hashlib.sha256(data).hexdigest()


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built')
    folder = os.path.abspath(folder)
    chain = os.path.join(folder, 'vbox-snapshots')
    if os.path.exists(chain):
        shutil.rmtree(chain)
    os.makedirs(os.path.join(chain, 'Snapshots'))
    work = tempfile.mkdtemp()
    # VBoxManage keeps a media registry in the home folder: a fresh one.
    os.environ['VBOX_USER_HOME'] = os.path.join(work, 'home')
    raw = os.path.join(work, 'base.raw')
    with open(raw, 'wb') as handle:
        handle.write(stream('vbox-base', SIZE))
    base = os.path.join(chain, 'disk.vdi')
    run('VBoxManage', 'convertfromraw', raw, base, '--format', 'VDI')
    disks = [('disk.vdi', base, None)]
    parent = base
    for level in (1, 2):
        temporary = os.path.join(chain, 'Snapshots', f'level{level}.vdi')
        run('VBoxManage', 'createmedium', 'disk', '--diffparent', parent,
            '--filename', temporary, '--format', 'VDI')
        run('VBoxManage', 'mediumio', f'--disk={temporary}', 'formatfat',
            '--quick')
        uuid = uuid_of(temporary)
        disks.append((f'Snapshots/{{{uuid}}}.vdi', temporary, parent))
        parent = temporary
    key = {'tool': run('VBoxManage', '--version').strip().splitlines()[-1],
           'disks': {}}
    for name, path, parent_path in disks:
        size, digest = read_whole(path, work)
        key['disks'][name] = {
            'uuid': uuid_of(path), 'size': size, 'sha256': digest,
            'parent_uuid': uuid_of(parent_path) if parent_path else None}
    # Named as VirtualBox names a snapshot's disk, now that VBoxManage is
    # done with them (it finds media by the path it registered).
    run('VBoxManage', 'closemedium', 'disk', parent)
    for name, path, _parent in disks[1:]:
        os.replace(path, os.path.join(chain, name))
    with open(os.path.join(folder, 'vbox-snapshots-key.json'), 'w') as out:
        json.dump(key, out, indent=2, sort_keys=True)
    shutil.rmtree(work, ignore_errors=True)
    print(f"{key['tool']}: a chain of {len(disks)} disks in {chain}")


if __name__ == '__main__':
    main()

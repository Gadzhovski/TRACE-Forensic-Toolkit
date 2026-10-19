"""Boot the build machine's own Linux kernel under QEMU, with an initramfs
TRACE puts together, to have the kernel itself write a file system -- for
the formats no userspace tool writes as the kernel does (UBIFS with an
uncommitted journal, ZFS pools).

No module is loaded on the build machine and nothing needs KVM: the guest
runs under QEMU's emulator, so this works in a plain container (Docker
Desktop's kernel has neither MTD nor ZFS). Shared by make_ubifs.py and
make_zfs.py:

* `kernel_release(*modules)`: an installed kernel whose vmlinuz is readable
  and which has the modules;
* `Guest`: the initramfs -- busybox, chosen binaries with every library
  ldd names, modules (decompressed) in load order with their parameters,
  files and trees, an /init script (`guest_listing.sh` beside it is
  installed as /listing.sh, a `list_tree` the init scripts use to write
  the answer key);
* `Guest.boot(disks)`: virtio disks in order (vda, vdb, ...), the console
  returned; an init prints 'TRACE: done' at the end and 'TRACE: <what
  failed>' on any failure, which fails the build;
* `parse_listing(text)`: list_tree's lines -> {path: {'type', 'size',
  'sha256' | 'target', 'mtime'}}.
"""

import os
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))


def run(*command, cwd=None, data=None):
    result = subprocess.run(command, capture_output=True, cwd=cwd,
                            input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:4])}... failed:\n"
                 f"{result.stdout.decode(errors='replace')}"
                 f"{result.stderr.decode(errors='replace')}")
    return result.stdout


def kernel_release(*modules):
    """An installed kernel that can be booted and has `modules`, or None."""
    if not os.path.isdir('/lib/modules') or \
            not shutil.which('qemu-system-x86_64'):
        return None
    for release in sorted(os.listdir('/lib/modules')):
        if not os.access(f'/boot/vmlinuz-{release}', os.R_OK):
            continue
        found = {name.split('.ko')[0] for _dir, _sub, files in
                 os.walk(os.path.join('/lib/modules', release, 'kernel'))
                 for name in files if '.ko' in name}
        if all(module in found for module in modules):
            return release
    return None


def module_files(release, modules):
    """[(module file, parameters)] in load order, each once: each of
    `modules` ((name, parameters)) after what it depends on."""
    out = {}
    for name, params in modules:
        listing = subprocess.run(
            ['modprobe', '--show-depends', '-S', release, name],
            capture_output=True, text=True).stdout
        for line in listing.splitlines():
            if not line.startswith('insmod '):
                continue                        # 'builtin <name>'
            path = line.split()[1]
            own = os.path.basename(path).split('.ko')[0] == \
                name.replace('-', '_')
            out.setdefault(path, params if own else '')
    return list(out.items())


class Guest:
    def __init__(self, release, init_script):
        self.release = release
        self.work = tempfile.mkdtemp()
        self.root = os.path.join(self.work, 'root')
        for name in ('bin', 'sbin', 'proc', 'sys', 'dev', 'modules', 'etc',
                     'tmp', 'mnt'):
            os.makedirs(os.path.join(self.root, name))
        shutil.copy('/bin/busybox', os.path.join(self.root, 'bin',
                                                 'busybox'))
        shutil.copy(os.path.join(_HERE, 'guest_listing.sh'),
                    os.path.join(self.root, 'listing.sh'))
        init = os.path.join(self.root, 'init')
        shutil.copy(init_script, init)
        os.chmod(init, 0o755)
        self._order = []

    def add_binary(self, name):
        """A binary by name, at its own path, with its libraries."""
        path = shutil.which(name)
        if path is None:
            sys.exit(f"{name} is not installed")
        self._copy(path)
        for line in run('ldd', path).decode().splitlines():
            library = line.split('=>')[-1].split('(')[0].strip()
            if library.startswith('/'):
                self._copy(library)

    def _copy(self, path):
        target = os.path.join(self.root, path.lstrip('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy(os.path.realpath(path), target)

    def add_modules(self, modules):
        for packed, params in module_files(self.release, modules):
            name = os.path.basename(packed).split('.ko')[0] + '.ko'
            target = os.path.join(self.root, 'modules', name)
            if packed.endswith('.zst'):
                run('zstd', '-q', '-d', packed, '-o', target)
            elif packed.endswith('.xz'):
                with open(target, 'wb') as handle:
                    handle.write(run('xz', '-d', '-c', packed))
            else:
                shutil.copy(packed, target)
            self._order.append(f"{name} {params}".strip())

    def add_tree(self, source, inside):
        shutil.copytree(source, os.path.join(self.root, inside.lstrip('/')),
                        symlinks=True)

    def add_file(self, inside, data):
        target = os.path.join(self.root, inside.lstrip('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'wb') as handle:
            handle.write(data)

    def _initrd(self):
        with open(os.path.join(self.root, 'modules', 'order'), 'w') as handle:
            handle.write(''.join(f"{line}\n" for line in self._order))
        names = run('find', '.', cwd=self.root)
        initrd = os.path.join(self.work, 'initrd.cpio')
        with open(initrd, 'wb') as handle:
            handle.write(run('cpio', '-o', '-H', 'newc', '--quiet',
                             cwd=self.root, data=names))
        return initrd

    def boot(self, disks, memory=1024):
        command = ['qemu-system-x86_64', '-m', str(memory), '-nographic',
                   '-no-reboot', '-kernel', f'/boot/vmlinuz-{self.release}',
                   '-initrd', self._initrd(),
                   '-append', 'console=ttyS0 panic=-1 quiet']
        for disk in disks:
            command += ['-drive', f'file={disk},format=raw,if=virtio']
        console = run(*command).decode('utf-8', 'replace')
        if 'TRACE: done' not in console or \
                'TRACE: ' in console.replace('TRACE: done', ''):
            sys.exit("The guest did not finish:\n" + console[-6000:])
        return console


def read_listing(disk):
    """What the guest wrote to a listing disk, up to its end mark."""
    with open(disk, 'rb') as handle:
        return handle.read().split(b'TRACE-END')[0].decode('utf-8')


def parse_listing(text, prefix=''):
    """list_tree's lines (those of section `prefix`, which is cut off) ->
    the answer key's {path: record}."""
    files = {}
    for line in text.splitlines():
        kind, fields, path = line.split('\t')
        if prefix:
            if not path.startswith(prefix + '/'):
                continue
            path = path[len(prefix):]
        if kind in ('dir', 'other'):
            files[path] = {'type': kind}
        elif kind == 'link':
            files[path] = {'type': 'link', 'target': fields,
                           'size': len(fields.encode())}
        else:
            size, digest, mtime = fields.split()
            files[path] = {'type': 'file', 'size': int(size),
                           'sha256': digest, 'mtime': int(mtime)}
    return files

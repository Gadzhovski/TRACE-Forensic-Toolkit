"""QNX IFS boot images, and QNX's dumpifs reading of them, for TRACE's
reader (core/qnx_ifs.py, core/ucl.py).

The one public IFS made by QNX's mkifs is openqnx's qnx.ifs (pinned in
samples.py): x86, a BIOS boot prefix, UCL-compressed. From it, with
dumpifs's own uncompressed copy (-u), the other ways mkifs stores an image
file system are made, so each decoder has an image QNX's tool reads:

* ifs-ucl.ifs      openqnx's image as it is
* ifs-plain.ifs    stored uncompressed (flags1 compression bits cleared)
* ifs-zlib.ifs     zlib (a gzip stream, as dumpifs's gzdopen reads it)
* ifs-lzo.ifs      LZO1X in 64 KiB blocks (lzo_blocks.c, liblzo2)
* ifs-imagefs.ifs  the image file system alone, no startup (a secondary
                   IFS, as head units keep beside the boot one)

The key (ifs-key.json) is dumpifs's: every entry's path, mode, uid, gid,
mtime, inode, symlink target from its listing (-v), each file's SHA-256 of
what it extracts (-x), and the SHA-256 of the decompressed image (-u).
dumpifs is askac/dumpifs (QNX's dumpifs.c with Linux headers), its tarball
SHA-256 pinned, built against Ubuntu's zlib, liblzo2 and libucl -- a tool
for these test images only, never part of TRACE.

    python3 tools/testdata/build/make_ifs_images.py [folder]     # Linux

Needs build-essential, zlib1g-dev, liblzo2-dev, libucl-dev, curl. On
Windows or macOS:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 build-essential \\
         zlib1g-dev liblzo2-dev libucl-dev curl ca-certificates \\
         >/dev/null && python3 tools/testdata/build/make_ifs_images.py"
"""

import gzip
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(_HERE, '..', '..', '..', 'test_images', 'samples')
DUMPIFS = ('https://codeload.github.com/askac/dumpifs/tar.gz/'
           'b7bac90e8312eca2796f2003a52791899eb8dcd9')
DUMPIFS_SHA256 = 'a07866e2d58cb88bcd4a0f0983192a29b3ed974bc58193929b3c2dc8e1700dc9'
STARTUP_SIGNATURE = b'\xeb\x7e\xff\x00'


def run(*command, cwd=None, data=None):
    result = subprocess.run(command, capture_output=True, cwd=cwd,
                            input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:3])}... failed:\n"
                 f"{result.stdout.decode(errors='replace')[-3000:]}"
                 f"{result.stderr.decode(errors='replace')[-3000:]}")
    return result.stdout


def build_tools(work, pinned):
    archive = os.path.join(work, 'dumpifs.tar.gz')
    urllib.request.urlretrieve(DUMPIFS, archive)
    with open(archive, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if pinned and digest != pinned:
        sys.exit(f"dumpifs source changed: {digest} != {pinned}")
    source = os.path.join(work, 'dumpifs-src')
    with tarfile.open(archive) as tar:
        tar.extractall(source, filter='data')
    top = os.path.join(source, os.listdir(source)[0])
    dumpifs = os.path.join(work, 'dumpifs')
    run('gcc', '-O1', '-w', '-I', top, '-o', dumpifs,
        os.path.join(top, 'dumpifs.c'), '-lz', '-llzo2', '-lucl')
    lzo = os.path.join(work, 'lzo_blocks')
    run('gcc', '-O2', '-o', lzo, os.path.join(_HERE, 'lzo_blocks.c'),
        '-llzo2')
    return dumpifs, lzo, digest


def startup(data):
    """(offset, startup_size) of the startup header."""
    at = data.find(STARTUP_SIGNATURE)
    while at >= 0:
        if struct.unpack_from('<H', data, at + 8)[0] == 0x100 and \
                not any(data[at + 50:at + 64]):
            return at, struct.unpack_from('<I', data, at + 32)[0]
        at = data.find(STARTUP_SIGNATURE, at + 1)
    sys.exit("no startup header")


def variant(head, imagefs, flag, stored):
    """A startup + image file system with flags1's compression `flag`,
    stored_size fixed."""
    out = bytearray(head)
    spos, startup_size = startup(head)
    out[spos + 6] = (out[spos + 6] & ~0x1C) | flag
    struct.pack_into('<I', out, spos + 36, startup_size + len(stored))
    return bytes(out) + stored, len(imagefs)


_ENTRY = re.compile(r'^\s+(\S+)\s+(\S+)\s+(\S.*)$')
_ATTRS = re.compile(r'(\w+)=(\S+)')


def listing(text):
    """dumpifs -v -> {path: {...}} of the image's entries."""
    out = {}
    lines = text.splitlines()
    started = False
    for number, line in enumerate(lines):
        if line.strip().startswith('Offset') and 'Name' in line:
            started = True
            continue
        if not started or line.startswith('Checksums'):
            continue
        match = _ENTRY.match(line)
        if not match or '=' in match.group(1):
            continue
        offset, size, name = match.groups()
        following = lines[number + 1] if number + 1 < len(lines) else ''
        attrs = dict(_ATTRS.findall(following)) if 'mode=' in following \
            else {}
        if name in ('*.boot', 'Startup-header', 'startup.*',
                    'Image-header', 'Image-directory') or \
                name.startswith(('Startup-header', 'Image-header')):
            continue
        if not attrs:
            continue
        record = {'mode': int(attrs['mode'], 8), 'uid': int(attrs['uid']),
                  'gid': int(attrs['gid']), 'ino': int(attrs['ino']),
                  'mtime': int(attrs['mtime'], 16)}
        if name == 'Root-dirent':
            out['/'] = dict(record, type='dir')
            continue
        if ' -> ' in name:
            path, target = name.split(' -> ', 1)
            out['/' + path] = dict(record, type='link', target=target,
                                   size=int(size, 16))
        elif ' dev=' in name:
            out['/' + name.split(' dev=')[0]] = dict(record, type='other')
        elif offset == '----' and size == '----':
            out['/' + name] = dict(record, type='dir')
        else:
            out['/' + name] = dict(record, type='file', size=int(size, 16))
    return out


def extracted(dumpifs, image, work, entries):
    """{path: sha256} of what dumpifs -x writes (into folders made first,
    from the listing: dumpifs makes none)."""
    target = tempfile.mkdtemp(dir=work)
    for path in entries:
        parent = os.path.dirname(path.lstrip('/'))
        if parent:
            os.makedirs(os.path.join(target, parent), exist_ok=True)
    run(dumpifs, '-x', os.path.abspath(image), cwd=target)
    out = {}
    for parent, _folders, files in os.walk(target):
        for name in files:
            full = os.path.join(parent, name)
            if os.path.islink(full):
                continue
            with open(full, 'rb') as handle:
                out['/' + os.path.relpath(full, target).replace(os.sep, '/')] \
                    = hashlib.sha256(handle.read()).hexdigest()
    return out


def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                             os.path.join(_HERE, '..', '..', '..',
                                          'test_images', 'built'))
    os.makedirs(folder, exist_ok=True)
    work = tempfile.mkdtemp()
    dumpifs, lzo, digest = build_tools(work, DUMPIFS_SHA256)
    original = os.path.join(SAMPLES, 'openqnx-qnx.ifs')
    if not os.path.exists(original):
        sys.exit("openqnx-qnx.ifs is not in test_images/samples: python -m "
                 "tools.testdata.fetch --group samples")
    with open(original, 'rb') as handle:
        data = handle.read()
    plain = os.path.join(work, 'plain.bin')
    run(dumpifs, '-u', plain, original)
    with open(plain, 'rb') as handle:
        expanded = handle.read()
    spos, startup_size = startup(expanded)
    head = expanded[:spos + startup_size]
    imagefs = expanded[spos + startup_size:]
    images = {'ifs-ucl.ifs': data}
    images['ifs-plain.ifs'], _ = variant(head, imagefs, 0x00, imagefs)
    images['ifs-zlib.ifs'], _ = variant(head, imagefs, 0x04,
                                        gzip.compress(imagefs, 9))
    images['ifs-lzo.ifs'], _ = variant(head, imagefs, 0x08,
                                       run(lzo, data=imagefs))
    images['ifs-imagefs.ifs'] = imagefs
    key = {}
    for name, content in images.items():
        path = os.path.join(folder, name)
        with open(path, 'wb') as handle:
            handle.write(content)
        text = run(dumpifs, '-v', path).decode('utf-8', 'replace')
        entries = listing(text)
        for entry_path, sha256 in extracted(dumpifs, path, work,
                                                entries).items():
            if entry_path in entries:
                entries[entry_path]['sha256'] = sha256
        missing = [p for p, e in entries.items()
                   if e['type'] == 'file' and 'sha256' not in e]
        if missing:
            sys.exit(f"{name}: dumpifs extracted no {missing[:3]}")
        key[name] = {'entries': entries,
                     'checksum_ok': 'not correct' not in text}
    key['ifs-ucl.ifs']['decompressed_sha256'] = \
        hashlib.sha256(imagefs).hexdigest()
    with open(os.path.join(folder, 'ifs-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'reader': f'askac/dumpifs {DUMPIFS} (sha256 {digest})',
                   'source': 'openqnx qnx.ifs (samples.py)',
                   'images': key}, handle, indent=1, sort_keys=True)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        sys.exit("These images are built on Linux (see the docstring for "
                 "Docker).")
    main()

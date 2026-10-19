"""U-Boot environments, and libubootenv's reading of them, for TRACE's
reader (core/uboot_env.py).

mkenvimage (u-boot-tools) writes each image from a list of variables;
fw_printenv (libubootenv-tool, configured to read the image file) prints
what U-Boot's own environment library reads back -- the answer key
(uboot-env-key.json). Tools for these test images only. Built:

* uboot-env.bin            8 KiB, CRC little-endian
* uboot-env-be.bin         8 KiB, CRC big-endian (mkenvimage -b)
* uboot-env-64k.bin        64 KiB environment in a 128 KiB partition
* uboot-env-redundant.bin  two 16 KiB copies (mkenvimage -r): the second
                           newer (flag 1) with changed settings, the first
                           obsolete (flag 0) -- the settings before

    python3 tools/testdata/build/make_uboot_env.py [folder]    # Linux

Needs u-boot-tools and libubootenv-tool. In Docker:

    docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh -c \\
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get \\
         install -y -qq --no-install-recommends python3 u-boot-tools \\
         libubootenv-tool >/dev/null && \\
         python3 tools/testdata/build/make_uboot_env.py"
"""

import json
import os
import subprocess
import sys
import tempfile
import zlib

VARIABLES = [
    'arch=arm', 'baudrate=115200', 'board=trace-test',
    'bootargs=console=ttyS0,115200 root=/dev/mtdblock5 rootfstype=squashfs',
    'bootcmd=run nand_boot', 'bootdelay=3', 'ethaddr=02:00:00:aa:bb:cc',
    'ipaddr=192.168.1.1', 'serverip=192.168.1.10',
    'nand_boot=nand read 0x82000000 0x200000 0x400000; bootm 0x82000000',
    'serial#=TRC1234567890', 'ver=U-Boot 2025.10 (TRACE test)',
    'unicode=résumé – 履歴書', 'empty_value=',
]
NEWER = [v for v in VARIABLES if not v.startswith('ipaddr=')] + \
    ['ipaddr=10.0.0.1', 'bootcount=7']


def run(*command, data=None):
    result = subprocess.run(command, capture_output=True, input=data)
    if result.returncode:
        sys.exit(f"{' '.join(command[:3])} failed: "
                 f"{result.stderr.decode(errors='replace')}")
    return result.stdout


def image(work, variables, size, *options):
    listing = os.path.join(work, 'vars.txt')
    with open(listing, 'w', encoding='utf-8') as handle:
        handle.write(''.join(f"{v}\n" for v in variables))
    target = os.path.join(work, 'env.bin')
    run('mkenvimage', '-s', str(size), *options, '-o', target, listing)
    with open(target, 'rb') as handle:
        return handle.read()


def printenv(work, path, lines):
    """fw_printenv over `path`: {name: value}."""
    config = os.path.join(work, 'fw_env.config')
    with open(config, 'w') as handle:
        handle.write(''.join(f"{path} {offset:#x} {size:#x}\n"
                             for offset, size in lines))
    out = run('fw_printenv', '-c', config).decode('utf-8')
    values = {}
    for line in out.splitlines():
        name, _, value = line.partition('=')
        values[name] = value
    return values


def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                             os.path.join(os.path.dirname(__file__), '..',
                                          '..', '..', 'test_images',
                                          'built'))
    os.makedirs(folder, exist_ok=True)
    work = tempfile.mkdtemp()
    built = {
        'uboot-env.bin': (image(work, VARIABLES, 0x2000),
                          [(0, 0x2000)]),
        'uboot-env-be.bin': (image(work, VARIABLES, 0x2000, '-b'),
                             [(0, 0x2000)]),
        'uboot-env-64k.bin': (image(work, VARIABLES, 0x10000) +
                              b'\xff' * 0x10000, [(0, 0x10000)]),
    }
    older = bytearray(image(work, VARIABLES, 0x4000, '-r'))
    newer = bytearray(image(work, NEWER, 0x4000, '-r'))
    older[4], newer[4] = 0, 1          # obsolete, active (fw_env.c)
    built['uboot-env-redundant.bin'] = (bytes(older + newer),
                                        [(0, 0x4000), (0x4000, 0x4000)])
    key = {}
    for name, (data, lines) in built.items():
        path = os.path.join(folder, name)
        with open(path, 'wb') as handle:
            handle.write(data)
        if name == 'uboot-env-be.bin':
            continue
        key[name] = {'variables': printenv(work, path, lines)}
    # libubootenv reads little-endian CRCs only: the big-endian image's key
    # is its twin's reading, its own CRC checked here.
    data = built['uboot-env-be.bin'][0]
    if int.from_bytes(data[:4], 'big') != zlib.crc32(data[4:]):
        sys.exit("mkenvimage -b wrote no big-endian CRC")
    key['uboot-env-be.bin'] = {
        'variables': key['uboot-env.bin']['variables'],
        'note': "fw_printenv reads little-endian CRCs only: the variables "
                "are uboot-env.bin's, written from the same list"}
    # The obsolete copy as libubootenv reads it: a copy of the pair with
    # the two flags swapped, so it picks the older one.
    swapped = bytearray(built['uboot-env-redundant.bin'][0])
    swapped[4], swapped[0x4000 + 4] = 1, 0
    other = os.path.join(work, 'swapped.bin')
    with open(other, 'wb') as handle:
        handle.write(swapped)
    key['uboot-env-redundant.bin']['other_copy'] = printenv(
        work, other, [(0, 0x4000), (0x4000, 0x4000)])
    with open(os.path.join(folder, 'uboot-env-key.json'), 'w',
              encoding='utf-8') as handle:
        json.dump({'reader': 'libubootenv fw_printenv', 'images': key},
                  handle, indent=1, sort_keys=True, ensure_ascii=False)
    print(f"{len(key)} images in {folder}")


if __name__ == '__main__':
    main()

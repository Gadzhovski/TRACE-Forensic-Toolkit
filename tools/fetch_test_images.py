"""Download the public forensic test images, and prove they are the right ones.

The tests and the carving score run against published test images -- the
Digital Forensics Tool Testing images (DFTT), the NPS corpus from Digital
Corpora, and NIST's deleted-file-recovery set. They are not kept in the
repository: they are large, and they belong to their publishers. This fetches
them from their official sources and checks each against the SHA-256 recorded
in test_images/README.md before keeping it.

A file whose checksum does not match is discarded, never kept; a file already
in test_images/ is left alone, and reported if it does not match. Nothing here
can overwrite evidence an examiner already has.

    python tools/fetch_test_images.py          # the CI set (~350 MB on disk)
    python tools/fetch_test_images.py --list   # what is in the catalog
    python tools/fetch_test_images.py daylight.dd 7-ntfs-undel.dd
"""

import argparse
import bz2
import hashlib
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE_DIR = os.path.join(ROOT, 'test_images')

_DFTT = "https://downloads.sourceforge.net/project/dftt/Test%20Images/"
_NPS = "https://downloads.digitalcorpora.org/corpora/drives/"
_NIST = "https://cfreds-archive.nist.gov/dfr-images/"

#: name -> (source URL, how it is packed, SHA-256 of the image itself).
#: Checksums are those in test_images/README.md, taken when each image was
#: first downloaded and checked against its publisher's documentation.
CATALOG = {
    'fat-img-kw.dd': (_DFTT + '2_%20FAT%20Keyword%20%231/2-kwsrch-fat.zip',
                      'zip', 'b173fd82a052e2637cfeb89cf21a603817f072799a63decffbfc948fc19a06e6'),
    'ntfs-img-kw-1.dd': (_DFTT + '3_%20NTFS%20Keyword%20%231/3-kwsrch-ntfs.zip',
                         'zip', 'cad097e8fcf4538a928c980a01bc64dcf36ca062432b0f6d5c3962e3bc0c4060'),
    'ext3-img-kw-1.dd': (_DFTT + '4_%20EXT3FS%20Keyword%20%231/4-kwsrch-ext3.zip',
                         'zip', '2065c9b3fa3f1f59fd5ee2ec0ad83a987d988e9ae898497a0b48e4986010f686'),
    'daylight.dd': (_DFTT + '5_%20FAT%20Daylight%20Savings/5-fat-daylight.zip',
                    'zip', 'a81dc8aeefb28b75e0625c1c8b54db9f46ec1c6c28e16595539d1cb00bbd45b5'),
    '6-fat-undel.dd': (_DFTT + '6_%20FAT%20File%20Recovery%20%231/6-undel-fat.zip',
                       'zip', 'e6f1f3bc53d426ae6f81b2d7b75598bc95f7447853e38b8f9ca1d1b65f7b3512'),
    '7-ntfs-undel.dd': (_DFTT + '7_%20NTFS%20File%20Recovery%20%28and%20Leap%20Year%29%20%231/7-undel-ntfs.zip',
                        'zip', '4138cc42148e3381e3c66eb50090f4a30416ae8c20247c2b9bad27cf8c764d88'),
    '8-jpeg-search.dd': (_DFTT + '8_%20JPEG%20Search%20%231/8-jpeg-search.zip',
                         'zip', '9c43d6a2dd5132cf6afc29e5c644cde0cb747c64998a68e73f2efb787887b126'),
    '9-fat-label.dd': (_DFTT + '9_%20FAT%20Volume%20Label%20%231/9-fat-label.zip',
                       'zip', 'ca312b0582c78e1b379eca318aa7a9d7fc4a809bfcfd25be093f5298e72a81ab'),
    '11-carve-fat.dd': (_DFTT + '11_%20Basic%20Data%20Carving%20%231/11-carve-fat.zip',
                        'zip', '83585232e908529286f1ff04c43b4d858604875c733183a9e3b44a07ff818d26'),
    '12-carve-ext2.dd': (_DFTT + '12_%20Basic%20Data%20Carving%20%232/12-carve-ext2.zip',
                         'zip', 'ffeb78b6cf8eed64c241212fb5cd1f3d226dcd58e16b67192f465e4a3ec46342'),
    'iso-dirtree1.iso': (_DFTT + '14_ISO9660_%231/14-iso9660-1.zip',
                         'zip', '0418d266405e1baf1334a014b9fba984962e81ec65003f34b67a7f5c7b28e6ad'),
    'iso-dirtree2.iso': (_DFTT + '14_ISO9660_%231/14-iso9660-1.zip',
                         'zip', '5f4fe2707eb4227b2d8e35482f492c888a44937abca05b67a0b63f2a2e34e074'),
    'iso-endian.iso': (_DFTT + '14_ISO9660_%231/14-iso9660-1.zip',
                       'zip', '70231746c40640efc6ea5a926ef9184910c44b43b0716d72026db41b40966b9c'),
    'ntfs1-gen2.E01': (_NPS + 'nps-2009-ntfs1/ntfs1-gen2.E01',
                       'raw', '2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea'),
    'image.gen1.dmg': (_NPS + 'nps-2009-hfsjtest1/image.gen1.dmg',
                       'raw', 'beb7795dd6d1a5319f9c20101855ffff9665fcc11c6b23de822d50c0d1e388ee'),
    'dfr-01-xfat.dd': (_NIST + 'dfr-01-xfat.dd.bz2',
                       'bz2', 'bb3755982959e189d7cfc7a4819553406e5c64e67a11d6b875ea1d4f23fa745b'),
}

_USER_AGENT = ('TRACE-test-images/1.0 '
               '(+https://github.com/Gadzhovski/TRACE-Forensic-Toolkit)')


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _download(url, target):
    request = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT})
    with urllib.request.urlopen(request, timeout=300) as response, \
            open(target, 'wb') as out:
        shutil.copyfileobj(response, out, 1 << 20)


def _extract(archive, kind, name, target):
    """Write the image `name` from a downloaded `archive` to `target`."""
    if kind == 'raw':
        shutil.move(archive, target)
    elif kind == 'bz2':
        with bz2.open(archive, 'rb') as src, open(target, 'wb') as out:
            shutil.copyfileobj(src, out, 1 << 20)
    elif kind == 'zip':
        with zipfile.ZipFile(archive) as package:
            # macOS adds __MACOSX/._name resource forks; they share the
            # image's name and are not the image.
            members = [m for m in package.namelist()
                       if m.rsplit('/', 1)[-1] == name
                       and not m.startswith('__MACOSX/')]
            if len(members) != 1:
                raise RuntimeError(f"{name} not found once in the archive "
                                   f"(found {members})")
            with package.open(members[0]) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
    else:
        raise ValueError(kind)


def fetch(name, directory=IMAGE_DIR, cache=None):
    """Make sure `name` is in `directory` and correct. Returns a status."""
    url, kind, expected = CATALOG[name]
    target = os.path.join(directory, name)
    if os.path.exists(target):
        actual = sha256_of(target)
        return 'present' if actual == expected else \
            f'PRESENT BUT CHECKSUM DIFFERS ({actual}) -- left untouched'

    os.makedirs(directory, exist_ok=True)
    cache = cache if cache is not None else {}
    with tempfile.TemporaryDirectory() as work:
        archive = cache.get(url)
        if archive is None or not os.path.exists(archive):
            archive = os.path.join(work, 'download')
            _download(url, archive)
            if kind == 'zip':
                # Several images share one archive (the three ISOs): keep it
                # for this run rather than downloading it three times.
                kept = os.path.join(tempfile.gettempdir(),
                                    'trace-fetch-' + hashlib.sha256(
                                        url.encode()).hexdigest()[:16])
                shutil.copyfile(archive, kept)
                cache[url] = kept
        staged = os.path.join(work, name)
        _extract(archive, kind, name, staged)
        actual = sha256_of(staged)
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 {actual} does not match the "
                               f"recorded {expected}; discarded")
        shutil.move(staged, target)
    return 'downloaded'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('names', nargs='*',
                        help='images to fetch (default: the whole catalog)')
    parser.add_argument('--dir', default=IMAGE_DIR)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args(argv)

    if args.list:
        for name, (url, kind, digest) in CATALOG.items():
            print(f"{name:20} {kind:4} {url}")
        return 0

    names = args.names or list(CATALOG)
    unknown = [n for n in names if n not in CATALOG]
    if unknown:
        print(f"Not in the catalog: {', '.join(unknown)}", file=sys.stderr)
        return 2

    cache, failed = {}, 0
    for name in names:
        try:
            status = fetch(name, args.dir, cache)
        except Exception as exc:
            status, failed = f"FAILED: {exc}", failed + 1
        print(f"{name:20} {status}", flush=True)
        if 'DIFFERS' in status:
            failed += 1
    for kept in cache.values():
        try:
            os.remove(kept)
        except OSError:
            pass
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

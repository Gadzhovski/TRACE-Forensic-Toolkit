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
import gzip
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE_DIR = os.path.join(ROOT, 'test_images')

_DFTT = "https://downloads.sourceforge.net/project/dftt/Test%20Images/"
_NPS = "https://downloads.digitalcorpora.org/corpora/drives/"
_NIST = "https://cfreds-archive.nist.gov/dfr-images/"
_COMMONS = "https://upload.wikimedia.org/wikipedia/commons/"
_AFF4 = ("https://raw.githubusercontent.com/aff4/ReferenceImages/"
         "84773b088bf6cce551a515d8ebb486bad69b58b8/AFF4Std/")
_BTRFS = ("https://media.githubusercontent.com/media/fox-it/dissect.btrfs/"
          "0549eb04f44df66ee51533c6356d824c1bbd4db3/tests/_data/")

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
    # Two file systems layered in each partition (NTFS under Ext2, UFS2,
    # UFS1); 10b's archive holds all four images.
    '10-ntfs-disk.dd': (_DFTT + '10_%20NTFS%20Autodetect%20%231/10b-ntfs-autodetect.zip',
                        'zip', '4d2edfe4a8ee0079720a4b9e258ecf59ffa17783465a5a013101614b4ac64049'),
    '10-ntfs-part3.dd': (_DFTT + '10_%20NTFS%20Autodetect%20%231/10b-ntfs-autodetect.zip',
                         'zip', '8e6c7b7709d52e6a41080002c0589ac3204f0e77d834f75b58d8f249d391d7bb'),
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
    # Deleted through the Recycle Bin, then the bin emptied (2.2 MB packed).
    'dfr-01-recycle-ntfs.dd': (_NIST + 'dfr-01-recycle-ntfs.dd.bz2',
                               'bz2', '6a44af0530812edf1a289c539a3c6c7d6b42e1c93e8f60e53287bddb5fdf7efa'),
    # Video for the media player's tests: small, CC0, from Wikimedia
    # Commons -- VP9 and VP8 WebM, and Theora in an .ogg (a name that says
    # audio, holding video).
    'VP9test.webm': (_COMMONS + 'e/e1/VP9test.webm', 'raw',
                     '2efbc8cbc302ce5ae498fa3f019eeb36447f15372fa92d6a62165f92449c1236'),
    'ContainerShip.webm': (_COMMONS + 'e/eb/ContainerShip.webm', 'raw',
                           'dc6f9ed8ea395c91df33f1b7aae0a50e1e4d54434514efffcb32258a1e2f4a3c'),
    'Wiki.OrientateEdges.ogg': (_COMMONS + '2/28/Wiki.OrientateEdges.ogg',
                                'raw', '4e583efb3a59d577f5f2a32cd8a6743785fe8f315a2f95c72778eb81635a1375'),
    # The AFF4 Standard v1.0 canonical reference images (Evimetry): a
    # linear image, one of allocated blocks only (UnknownData between),
    # and one with a read error (UnreadableData).
    'Base-Linear.aff4': (_AFF4 + 'Base-Linear.aff4', 'raw',
                         'bcde3297ae95cd9df214bfb79821334628dad08f21ef38374a2c091481e391c0'),
    'Base-Allocated.aff4': (_AFF4 + 'Base-Allocated.aff4', 'raw',
                            'df6c705c15339a53cf86b221858f2cd6b85c56f7078287ae99273145efe567c1'),
    'Base-Linear-ReadError.aff4': (_AFF4 + 'Base-Linear-ReadError.aff4', 'raw',
                                   '0b1c2edd6bdf37f2efe9c6fa274dd3c100de3fc5152d8a1fd82fb61f41c68e12'),
    # Btrfs, which TSK does not read (core/btrfs.py): fox-it/dissect.btrfs's
    # test volumes (128 MB each, ~1 MB packed but for compression's 5 MB),
    # whose expected contents its tests publish -- subvolumes and a
    # snapshot, nested subvolumes, zlib/LZO/zstd, sparse files, and
    # multi-disk pools (RAID0/1/5/6) read whole, degraded or one disk alone.
    'btrfs-subvolume-snapshot.raw': (_BTRFS + 'btrfs-subvolume-snapshot.bin.gz', 'gz',
                                     'ce5b3950c4b6b7200b8b76f795d09340652952bd6bec2b1803af6ecfe219f1f2'),
    'btrfs-subvolume-nested.raw': (_BTRFS + 'btrfs-subvolume-nested.bin.gz', 'gz',
                                   'bdc211d245a6bc1adec4540ae9b9041fe88f3583c9663f0aa1fa3ba8f0f1c1c7'),
    'btrfs-compression.raw': (_BTRFS + 'btrfs-compression.bin.gz', 'gz',
                              '2088190ca033e2a20c3fb93d2b5d2ca65313fbf32d193cb242d333ca5e0a538f'),
    'btrfs-sparse.raw': (_BTRFS + 'btrfs-sparse.bin.gz', 'gz',
                         '5d15ae65c1c45cdeb599294d9efacdbdb1d9133dff936200f6265521e089d258'),
    'btrfs-raid1-1.raw': (_BTRFS + 'btrfs-raid1-1.bin.gz', 'gz',
                          '63a60b87e9c17313610885db8ddd6b54146e88e910bf0bab8d7091605c20add7'),
    'btrfs-raid1-2.raw': (_BTRFS + 'btrfs-raid1-2.bin.gz', 'gz',
                          '236e3d135601e0d12d2268943a08b772ab3d0443111280e0c74634072f3da2f6'),
    'btrfs-raid0-1.raw': (_BTRFS + 'btrfs-raid0-1.bin.gz', 'gz',
                          '50df8801d6e5ba9d2eff6d5eae77f5d20289b56de1954abd418c5f648e4abb7f'),
    'btrfs-raid0-2.raw': (_BTRFS + 'btrfs-raid0-2.bin.gz', 'gz',
                          'e8e8a50e7f92c112cea0750eb857e2091dfafe207b96ee2266986176fee0ae79'),
    'btrfs-raid5-1.raw': (_BTRFS + 'btrfs-raid5-1.bin.gz', 'gz',
                          'a70fe168247374bf8fa49f61d7dba18f776a780a4f9cf5fb6c4cc8f74fa2fd4c'),
    'btrfs-raid5-2.raw': (_BTRFS + 'btrfs-raid5-2.bin.gz', 'gz',
                          '4017c940e5c6ebab590ee74f5efb9239d94a367155b91632352204b4542e97aa'),
    'btrfs-raid6-1.raw': (_BTRFS + 'btrfs-raid6-1.bin.gz', 'gz',
                          '8362b35dee600402e8bb2707609d9d6911752890339bc02550cd3bdb79cae7a6'),
    'btrfs-raid6-2.raw': (_BTRFS + 'btrfs-raid6-2.bin.gz', 'gz',
                          '2ee5262ef2e22dea37abbdce6489c1448de40e8fa3932753de88afa348739fa7'),
    'btrfs-raid6-3.raw': (_BTRFS + 'btrfs-raid6-3.bin.gz', 'gz',
                          '25f51d61b044b96c221a46850a61928a8eb351aa505001c1b1e77aaedba76461'),
}


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _download(url, target):
    """Fetch with retries and mirrors (tools/download.py): one image host
    being slow must not fail a test run."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from download import download
    finally:
        sys.path.pop(0)
    download(url, target)


def _extract(archive, kind, name, target):
    """Write the image `name` from a downloaded `archive` to `target`."""
    if kind == 'raw':
        shutil.move(archive, target)
    elif kind == 'bz2':
        with bz2.open(archive, 'rb') as src, open(target, 'wb') as out:
            shutil.copyfileobj(src, out, 1 << 20)
    elif kind == 'gz':
        with gzip.open(archive, 'rb') as src, open(target, 'wb') as out:
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

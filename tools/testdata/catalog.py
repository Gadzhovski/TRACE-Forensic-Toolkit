"""Every test image TRACE knows, with where it comes from and its group.

The group decides the folder under test_images/ (tools/testdata) and who has
it: 'ci' is what CI downloads -- small, public, and each proving something
nothing else does; 'local' is public but too big or slow for every run
(the full set runs on the maintainers' machines: python tools/run_tests.py
full); 'private' has no public source and is only ever checked, never
fetched. Artifact samples (samples.py) and NIST's sets (nist.py) have
catalogs of their own.

name -> (source URL, how it is packed, SHA-256 of the image itself).
Checksums were taken when each image was first downloaded and checked
against its publisher's documentation.
"""


_DFTT = "https://downloads.sourceforge.net/project/dftt/Test%20Images/"
_NPS = "https://downloads.digitalcorpora.org/corpora/drives/"
_NIST = "https://cfreds-archive.nist.gov/dfr-images/"
_COMMONS = "https://upload.wikimedia.org/wikipedia/commons/"
_AFF4 = ("https://raw.githubusercontent.com/aff4/ReferenceImages/"
         "84773b088bf6cce551a515d8ebb486bad69b58b8/AFF4Std/")
_BTRFS = ("https://media.githubusercontent.com/media/fox-it/dissect.btrfs/"
          "0549eb04f44df66ee51533c6356d824c1bbd4db3/tests/_data/")
_TSKDATA = ("https://raw.githubusercontent.com/sleuthkit/sleuthkit_test_data/"
            "abcb05bd7f01313115d213dcd83826989fe93535/")
_FEDORA = ("https://download.fedoraproject.org/pub/fedora/linux/releases/44/"
           "Cloud/x86_64/images/")

#: The CI set: downloaded by every CI run that needs it (cached between
#: runs, tools/testdata/fetch.py). Most of these are mostly zeros and pack
#: to a few MB -- the Btrfs volumes are 128 MB each and ~1 MB as published.
CI = {
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

#: Public, local only: python -m tools.testdata.fetch --group local
LOCAL = {
    # The DFRWS carving challenges, scored by tools/score/carve_score.py.
    'dfrws-2006-challenge.raw': (
        'https://www.dropbox.com/s/genp058scvl8hbp/dfrws-2006-challenge.zip?dl=1',
        'zip', '9d24547c9d8a17602ee5a8ecf960ff8cc2ee48575ffc127cd084b3b0a484d1dd'),
    'dfrws-2007-challenge.img': (
        'https://www.dropbox.com/s/5ze0r2o1vjxf811/dfrws-2007-challenge.zip?dl=1',
        'zip', 'ace31ac34503bf3f56acd7cfe729a1f701f17e6fc2c202de7ccbb7ea58bc3a2c'),
    # DFTT #1 (extended partitions), from The Sleuth Kit's copy of it.
    'ext-part-test-2.dd': (_TSKDATA + 'from_brian/1-extend-part.zip', 'zip',
                           'b075ed83211765dd14f24390389b77b20ef688d70aaf69385e026b5513bdd8d2'),
    # DFTT #10's single partitions (the CI set has the whole disk).
    '10-ntfs-part1.dd': (_DFTT + '10_%20NTFS%20Autodetect%20%231/10b-ntfs-autodetect.zip',
                         'zip', 'd6739c45d652c0eb67e59536e7b9c02b25ca99aaabf500fe9c374bb7f2ae8bc3'),
    '10-ntfs-part2.dd': (_DFTT + '10_%20NTFS%20Autodetect%20%231/10b-ntfs-autodetect.zip',
                         'zip', '529c607152f8ca25a6f2645e6894a80b303b4f2b352b89bdfef0fde549e3c6e2'),
    # NPS: Ubuntu's persistence file, and a multi-user Windows XP machine.
    'ubnist1.casper-rw.gen3.E01': (_NPS + 'nps-2009-casper-rw/ubnist1.casper-rw.gen3.E01',
                                   'raw', 'f2ad970ab2c8ed41e2d26d0c7e821aaee0bb6fe71063ae17bea894306a8e55ff'),
    'nps-2009-domexusers.E01': (_NPS + 'nps-2009-domexusers/nps-2009-domexusers.E01',
                                'raw', '5c52f16eddd6d1afef216d968b19e7267fbd5e3c8bb1626bfb2d8c4f36cfaa1c'),
    # A real Fedora 44 install (GPT, EFI, Btrfs subvolumes, zstd, QCOW2).
    'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2': (
        _FEDORA + 'Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2', 'raw',
        '28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f'),
}

#: No public source: checked when present, never fetched, never in CI.
#: name -> SHA-256.
PRIVATE = {
    '2020JimmyWilson.E01': '6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5',
    'BXS-1.E01': '1196221c27515e4f9a5c855da529e006bd9bebfbc5703d37bb419476ea0db55d',
    'Op Archway AXA-1.E01': 'a621e46b88a6366c90cc5bc7d412b46f3f012a08b1fd7d3fcbea2d78b761af1d',
    'evidence.E01': 'f592d381352b60d3225ca43e001ecfa4b887667db17f10634dd62cfbe9ae9f9b',
    'JHC-1-H1.e01': '1a764c556adf425c1cedcfb974cf63ca7e9764a46f551265de7eda66cb90e9d7',
    'JHC-1-H1.E02': '0f3d8f191fddd1fcf4ac0d877fef1ebfebb0129611eab3d2e4d84bd43e5861c2',
    'PZ790MP.CAP': '2a53bcaec4a5ca75b8c91f02e1deab023a387d638cabc43ddaf3a781d3a66022',
}

#: Made by the Linux kernel's tools in CI (tools/testdata/build/), never
#: downloaded: name -> the script that makes it.
BUILT = {
    'btrfs-deleted.raw': 'make_btrfs_deleted.py',
    'luks1-lvm.raw': 'make_luks_lvm.py',
    'luks2-lvm.raw': 'make_luks_lvm.py',
    'md-raid.json': 'make_md_raid.py',
}

GROUPS = {'ci': CI, 'local': LOCAL, 'private': PRIVATE, 'built': BUILT}


def group_of(name):
    """'ci' / 'local' / 'private' / 'built' / 'corpus' / 'nist', or None."""
    for group, entries in GROUPS.items():
        if name in entries:
            return group
    if name.startswith('md-') or name.startswith('luks') or \
            name.startswith('btrfs-deleted'):
        return 'built'
    if name == 'carve-corpus.dd':
        return 'corpus'
    if name.startswith('dfr-'):
        return 'nist'
    return None

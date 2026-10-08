"""Download the real Windows and browser artifacts the activity tests read.

Prefetch files from Windows XP to 11, registry hives, Jump Lists, shortcuts,
Recycle Bin records, event logs and browser history databases -- published
test data of two open-source projects, pinned to a commit and checked by
SHA-256 before it is kept:

* log2timeline/plaso (Apache 2.0) test_data/
* omerbenamram/evtx (MIT / Apache 2.0) samples/
* log2timeline/dfvfs (Apache 2.0) test_data/ -- the containers: VHD, VHDX
  (a differencing disk and its parent), VMDK, a BitLocker To Go volume
  (password "bde-TEST", from dfvfs's own tests) and an NTFS volume with two
  Volume Shadow Copies
* plaso's NTFS samples: a raw $MFT, a $UsnJrnl:$J excerpt and a QCOW2 disk
  with a change journal
* plaso's Linux, macOS, chat and cloud-sync samples: shell histories,
  utmp/wtmp, systemd journals, KnowledgeC, quarantine events, Skype,
  iMessage, Android SMS, Dropbox, Google Drive and SkyDrive logs
* python/cpython (PSF) Lib/test/test_email/data/ -- real messages
* fox-it/dissect.thumbcache (AGPL test data) -- thumbcache_*.db from Windows
  Vista to 11; and Thumbs.db files from Windows XP and Vista that were
  committed by accident to ISET/isetcam, TabularEditor (MIT) and w3c/sdw
* release binaries of PuTTY, bat and ripgrep -- executables to analyse
* mkorman90/regipy (MIT): dirty hives with their .LOG1/.LOG2
* SigmaHQ's rule release and sbousseaden/EVTX-ATTACK-SAMPLES attack logs
* Microsoft Defender artifacts (DFIRArtifactMuseum, dissect.target)
* phones: mvt-project/mvt's (Apache 2.0) iPhone backup -- its Manifest.db
  of 3,721 files and the eleven files it keeps -- into mvt-ios-backup/;
  plaso's Android contacts2.db and iOS Accounts3.sqlite and Wi-Fi plist;
  cclgroupltd/android-bits (MIT): Android binary XML files, each with the
  XML it was written from
* logical evidence: AD1 images (pyad1, dissect.evidence) and EnCase L01
  files (ggeng2/Logical_Image_DataSet)
* macOS Background Task Management files: hewigovens/BTMParser's
  BackgroundItems-v13.btm and puffyCid/macos-loginitems' (MIT) v4 and
  pre-Ventura backgrounditems.btm, one with PoisonApple's login item

Plaso's own tests record expected values for many of these files; the
activity tests check TRACE against the same values. Files land in
test_images/artifact_samples/ (gitignored, like every test image).

    python tools/fetch_artifact_samples.py
"""

import hashlib
import os
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FOLDER = os.path.join(ROOT, 'test_images', 'artifact_samples')

_PLASO = ('https://raw.githubusercontent.com/log2timeline/plaso/'
          'ac6460d7350c9160bdf69161726ee0e8d4545874/test_data/')
_EVTX = ('https://raw.githubusercontent.com/omerbenamram/evtx/'
         '47d63022caa8336ecdd0c42d335e2bb03381b00d/samples/')
_DFVFS = ('https://raw.githubusercontent.com/log2timeline/dfvfs/'
          '917cefc9426d6ded2687d2b55164ded25b44fcb7/test_data/')
_ZSTD = ('https://raw.githubusercontent.com/facebook/zstd/'
         '01b7154f1172432f8abe9b3bb9909e14a1176b7d/tests/')
_CPYTHON = ('https://raw.githubusercontent.com/python/cpython/'
            'v3.12.0/Lib/test/test_email/data/')
_DISSECT = ('https://media.githubusercontent.com/media/fox-it/'
            'dissect.thumbcache/c73ae487161720794542c13b1170186a9a64d156/'
            'tests/data/')

_PYAD1 = ('https://raw.githubusercontent.com/pcbje/pyad1/'
          '74b21889410fb40b96e3f1f1f6ab369019d6984d/test_data/')
_DISSECT_EVIDENCE = ('https://media.githubusercontent.com/media/fox-it/'
                     'dissect.evidence/'
                     'b2d1ac23288a0a77b1e6158b2dfcad0c945c5d2d/tests/_data/'
                     'ad1/')
_L01 = ('https://media.githubusercontent.com/media/ggeng2/'
        'Logical_Image_DataSet/7633f6e5442070ee6f21ecc6bcf369b8827cf52e/L01/'
        'L01_list_of_metadata/')

_DISSECT_TARGET_DATA = ('https://media.githubusercontent.com/media/fox-it/'
                        'dissect.target/'
                        'b43db371c891fa3f382c5152e16f91b0bcde418c/tests/'
                        '_data/plugins/os/windows/')

_MVT_BACKUP = ('https://raw.githubusercontent.com/mvt-project/mvt/'
               'c95eeed825405d5b46c23883ad1336f131b52e2c/tests/artifacts/'
               'ios_backup/')

_CCL_ABX = ('https://raw.githubusercontent.com/cclgroupltd/android-bits/'
            '50910571ca81ad3db87ce1dcda9033a79b37ab72/ccl_abx/TEST%20FILES/')

_REGIPY = ('https://raw.githubusercontent.com/mkorman90/regipy/'
           'ce341e7e1b3daca35496b0b21d10d293183aa176/regipy_tests/data/')

_ATTACK = ('https://raw.githubusercontent.com/sbousseaden/'
           'EVTX-ATTACK-SAMPLES/4ceed2f4706daf601c212a8f91c113dd85349a2c/')

_BTMPARSER = ('https://raw.githubusercontent.com/hewigovens/BTMParser/'
              '14d5a6ed816a11d674d965061e48df12f1d5328a/Tests/'
              'BTMParserTests/Resources/')
_LOGINITEMS = ('https://raw.githubusercontent.com/puffyCid/macos-loginitems/'
               '75658db42a9adab87e9be6ef7d0e30d91d35fa7d/tests/test_data/')

#: local name -> (URL, SHA-256)
SAMPLES = {
    'AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf': (
        _PLASO + 'winprefetch/AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf',
        '9a5ad5a3c56ec67fb2f785e1f75366a642a2ea552694f5016cc8191cf3f49861'),
    'BYTECODEGENERATOR.EXE-C1E9BCE6.pf': (
        _PLASO + 'winprefetch/BYTECODEGENERATOR.EXE-C1E9BCE6.pf',
        '7b5855fbb17fabfeba6b3b5d90c8ef23b548106edf7e24b3d67fd826a1d6d537'),
    'CMD.EXE-087B4001.pf': (
        _PLASO + 'winprefetch/CMD.EXE-087B4001.pf',
        '93ec53e941b285d1d2a11e1224ab2d5c7a1b8ac493ab8dec407f518c5655ae75'),
    'NOTEPAD.EXE-D8414F97.pf': (
        _PLASO + 'winprefetch/NOTEPAD.EXE-D8414F97.pf',
        '2eb257a375eda819c65e6b4e60dfb7b9c6691280e8cb40cec30d3e46ac96a50f'),
    'ONEDRIVE.EXE-7E152375.pf': (
        _PLASO + 'winprefetch/ONEDRIVE.EXE-7E152375.pf',
        'e9a5db11b673ba592a794a2bfeaa2aba95814d3004c32a76e4dc668789fa2424'),
    'PING.EXE-B29F6629.pf': (
        _PLASO + 'winprefetch/PING.EXE-B29F6629.pf',
        'cdb6e2de2b02808755aa2591708ebe155ee3483947e230f5fdd6870390fafd26'),
    'TASKHOST.EXE-3AE259FC.pf': (
        _PLASO + 'winprefetch/TASKHOST.EXE-3AE259FC.pf',
        '00178686d5e755e596ee164e78473eab3aba382541d0f67f93654ef84d4ed36b'),
    'WUAUCLT.EXE-830BCC14.pf': (
        _PLASO + 'winprefetch/WUAUCLT.EXE-830BCC14.pf',
        'fc20953fefb17df1e14eb7fdf4b3ea0ea597bd292cbc75712e71c6cc8af2f3ed'),
    'NTUSER-XP.DAT': (
        _PLASO + 'NTUSER.DAT',
        '4a3232850f9677de96774b4de0020ac7f5e2efeb5e4576a200bb751d9e1c9d1d'),
    'NTUSER-WIN7.DAT': (
        _PLASO + 'NTUSER-WIN7.DAT',
        '672abb15ae62fa8c002c5ee0a730cf83cd5f40706d5ffdec8f1179cf47a0bd03'),
    'NTUSER-WIN10.DAT': (
        _PLASO + 'regf/NTUSER.DAT',
        '490ba00a82808753d38e243b2aed2b9ad647e435a03f3b2e09a36bd34efd8607'),
    'UsrClass-WIN10.dat': (
        _PLASO + 'regf/UsrClass.dat',
        '6fde8416390655766f69ce3fe871c2b28e72103919083730197d0d556611abe5'),
    'SYSTEM-WIN7': (
        _PLASO + 'SYSTEM',
        '96dc1f1cc3c0b44ef9af72d1c18a8e6a4338c67988f303d05693ca4be6bf7eb9'),
    'Amcache-WIN8.hve': (
        _PLASO + 'winreg/Amcache.hve',
        'bd77d59379c4be223b41aa69dddae52269e8af78f429eabee89b56e6bcd52833'),
    'Amcache-WIN10.hve': (
        _PLASO + 'winreg/win10-Amcache.hve',
        '4e574ac939d423947701302bc35d9a0da0b669a5fb86dbf8157a46c6f38f2c6d'),
    '1b4dd67f29cb1962.automaticDestinations-ms': (
        _PLASO + 'automaticDestinations-ms/'
                 '1b4dd67f29cb1962.automaticDestinations-ms',
        '003a1b2e449f1b8bd790ca6dc3b01378b2e835836b464556d70883a6eebcf414'),
    '9d1f905ce5044aee.automaticDestinations-ms': (
        _PLASO + 'automaticDestinations-ms/'
                 '9d1f905ce5044aee.automaticDestinations-ms',
        '6c59abb4bc79f1abf51cb836fe17b95066f4dfb1b91c61f13a22316bea1d0d9f'),
    '5afe4de1b92fc382.customDestinations-ms': (
        _PLASO + 'customDestinations-ms/'
                 '5afe4de1b92fc382.customDestinations-ms',
        'c1c77214698293fcfd9fb4cae296a3faa88191092ff381e97fd947cb62bba217'),
    'NeroInfoTool.lnk': (
        _PLASO + 'NeroInfoTool.lnk',
        '186fd33109985cccb41a5fcc4fdc9d53b71d8d286e1b65b74dd9ad065a863fbb'),
    '$I103S5F.jpg': (
        _PLASO + 'recycler/$I103S5F.jpg',
        '23c233e261b9b496f547dfc7447050fbae452dffbdd135a43d1bad31bc7b0df9'),
    '$II3DF3L.zip': (
        _PLASO + 'recycler/$II3DF3L.zip',
        '016d798595fe02bc19ee53511055a3ab3343a81a5ecc1301e606c5646b8b1ce8'),
    'INFO2': (
        _PLASO + 'recycler/INFO2',
        '92b3ccd7393474754d2453338b65e0c910c3f074dccc243deae072c62f9bbb1e'),
    'System.evtx': (
        _PLASO + 'evtx/System.evtx',
        'd67fe3d1c56e0dcdd4c0d8d3512f74dd500cc2bff52686a0be52b182547e6470'),
    'new-user-security.evtx': (
        _EVTX + 'new-user-security.evtx',
        '6f9fe51d0a5dec63dc68f819e23bc14da5db0b75db4a68dfdf6b39f02868a379'),
    'RemoteConnectionManager.evtx': (
        _EVTX + '2-vss_0-Microsoft-Windows-TerminalServices-'
                'RemoteConnectionManager%4Operational.evtx',
        'f498c1c45739f2f71207b78b7cce57f483c2ddd99c74d34d284d9fe401e8c587'),
    'bad_chunk_magic.evtx': (
        _EVTX + 'sample_with_a_bad_chunk_magic.evtx',
        '456d7645be38a8f72e9c9eb6c4fe42eac9c83d6ad34a9d039616af205e3bdc6f'),
    'History-chrome': (
        _PLASO + 'chrome/History',
        'c184fd5fdf72b75c26f8bb816619f04892e776ae6e2f5512f796d9807a12fbb3'),
    'places118.sqlite': (
        _PLASO + 'firefox/places118.sqlite',
        '9c4fea060279998f12d1fdf850b7160a86636b4899fee72bcc96e2e6f7f71831'),
    'downloads.sqlite': (
        _PLASO + 'firefox/downloads.sqlite',
        '6fa1cce13bbb3b2a6acca14e75c1d94b32616f557687f5b320738748766d9667'),
    'History.db': (
        _PLASO + 'safari/History.db',
        '2e87d99d0bc7765e523ee1250828e82fb350780c0c28020db6bb0b0ce8d3f351'),
    'ntfs-dynamic.vhd': (
        _DFVFS + 'ntfs-dynamic.vhd',
        'de48673c33e024a6af635cea56c51f47769cb59ea6264d8d6b32c757dc663051'),
    'ntfs-differential.vhdx': (
        _DFVFS + 'ntfs-differential.vhdx',
        '65bd9e21c9f14d476df67b8fd104a61234ef693e70330c0e6b9878b10aff92ac'),
    'ntfs-parent.vhdx': (
        _DFVFS + 'ntfs-parent.vhdx',
        '4495375f1e92bb6ef1937f7cb4ccf56ca1c1c491c0df56280a8c1905a3d58d44'),
    'ext2.vmdk': (
        _DFVFS + 'ext2.vmdk',
        '578b5f75af790030113a92c4227c6e53dad53a17e65cb491781dc75b3cef31f8'),
    'bdetogo.raw': (
        _DFVFS + 'bdetogo.raw',
        'ed7982a1f9263e4e54889fea1fa74112d12fea0a0aa7cd8f84fc6f03198ae71b'),
    'vss.raw': (
        _DFVFS + 'vss.raw',
        'e633f0be5fb9ee9a07d44ba5223b786012ce89e9f0024f93d743568e6d052f16'),
    # NTFS internals: a raw $MFT (Windows XP), a $UsnJrnl:$J excerpt, and a
    # QCOW2 disk holding an NTFS volume with a change journal.
    'MFT': (
        _PLASO + 'MFT',
        'c78f4968345b70783fbf6573d86c4bf300295ae26ddde4033dd1037b802e13c1'),
    'UsnJrnl.raw': (
        _PLASO + 'UsnJrnl.raw',
        'a7a4d536b6a5e2008b070cfea1832f57ff3c99de04380285651e00f420853b6f'),
    'usnjrnl.qcow2': (
        _PLASO + 'usnjrnl.qcow2',
        '1746df3a672924fac8e7456e9e005afe9e55d02eb0383929430a49637584a13d'),
    # Windows evidence in ESE databases, IE caches, Windows Timeline, and
    # a Windows 7 SOFTWARE hive (networks, programs, autoruns).
    'SRUDB.dat': (
        _PLASO + 'SRUDB.dat',
        '6536ae6bb5b91f6f8f37a4af26f6cfaecc8a1f745370bfba83af7ebae6694e3e'),
    'WebCacheV01.dat': (
        _PLASO + 'WebCacheV01.dat',
        '2713e7ff413c69659442c5dcb0f23f41230fa76bf760b8aeac0ffd430d10c83e'),
    'PartitionsEx-WebCacheV01.dat': (
        _PLASO + 'PartitionsEx-WebCacheV01.dat',
        '3b2958f0283d20d38de63e110da59e03f58c927f4360e8fe5161fdb1a99c3330'),
    'msiecf-Content.IE5-index.dat': (
        _PLASO + 'msiecf/Content.IE5/index.dat',
        'd6f7d3c4cd1b05b637dca8d41fcb652cc3809a0650181e447bf609bbc81d7db9'),
    'msiecf-History.IE5-index.dat': (
        _PLASO + 'msiecf/History.IE5/index.dat',
        'd54847adc8be889cb687bd7c60af50153d310eb3fc32a79d20c93eecb655bfc1'),
    'windows-ActivitiesCache.db': (
        _PLASO + 'windows/ActivitiesCache.db',
        '95811eebd1ea3ec0244bda5c5200266861cfcf405eed687dce96af8589836888'),
    'SOFTWARE': (
        _PLASO + 'SOFTWARE',
        'c2e1a391d6be9740e79da7944e012ad9ac878902db38ec7fc225a2a68d262a1b'),
    # Volumes: APFS (plain, and encrypted with password apfs-TEST), FileVault
    # 2 (fvde-TEST), LUKS 1 (luksde-TEST) and an LVM group -- dfvfs's own.
    'apfs.raw': (
        _DFVFS + 'apfs.raw',
        'e3e3adcbbf189403d892b013d6cba155f2e58e42ff5eb541ec681c37a91a3f29'),
    'apfs_encrypted.dmg': (
        _DFVFS + 'apfs_encrypted.dmg',
        '33fe6f183aeb1a95fec68efdab17d59aedbad3d8ef1a117d411117376d9d8485'),
    'fvdetest.qcow2': (
        _DFVFS + 'fvdetest.qcow2',
        'd69ca8fccf930a0b5a5b32219184b1692d5f6331a72fd88442386dbbb20078af'),
    'luks1.raw': (
        _DFVFS + 'luks1.raw',
        '62d74398519015912e3216766912a2a4d1afc7dc4f7378f676943aaf5e0828f1'),
    # UFS1 and UFS2 (FreeBSD), each with a file, a folder and a link --
    # what TSK reads and TRACE used to label 'Unknown'.
    # XFS, which TSK does not read (core/xfs.py, libfsxfs).
    'xfs.raw': (
        _DFVFS + 'xfs.raw',
        '6f48cf411af128693436f38359177cf7018c7b54c33c730f7b8b2b83be70ac78'),
    'ufs1.raw': (
        _DFVFS + 'ufs1.raw',
        '0b809d5ef3623cca96ff1b9db67ccc8f833b4d27e1413751481c5fcad237bcc2'),
    'ufs2.raw': (
        _DFVFS + 'ufs2.raw',
        'ee5d99e5e60aa566b9e4dd0a5341c1e2b433cbbfcebffbdbf0ad2a3e2153cd67'),
    'lvm.raw': (
        _DFVFS + 'lvm.raw',
        '565f564cd35e6ee304ea810631d52223e1ee3bb61d92ff1cd035c5a25f59e43e'),
    # Linux, macOS, chat and cloud sync: plaso's, with its expected values.
    'bash_history': (
        _PLASO + 'bash_history',
        'ebba51b0ae5bc730c2623366b9de875dfc69a9c679dca00fe6b85695440a6586'),
    'bash_history_desync': (
        _PLASO + 'bash_history_desync',
        '12489b934feff3b09475bbee10739ea08ad4b69b4f11142cdad62f96a910c7bf'),
    'fish_history': (
        _PLASO + 'fish_history',
        '20be8371385152342d97033b2e9dac50e043291a3556f56902bc2ad92a394a79'),
    'zsh_extended_history.txt': (
        _PLASO + 'zsh_extended_history.txt',
        '264daefbd5c1cdfc7bb443ab4c01be24c01021c7fcb789fd8d019065b6828ebf'),
    'wtmp.1': (
        _PLASO + 'utmp/wtmp.1',
        '29e7489c71c8df699f9b34a70f7ee1e649cea2df00598f78793fcdf0fc3bb6be'),
    'utmp_x86_64': (
        _PLASO + 'utmp/utmp_x86_64',
        'f847dcb2c03f3964867ac66266024d12af04af9fa2a995ddb273a48b3f04e244'),
    'utmpx_mac': (
        _PLASO + 'utmpx_mac',
        'e70031efe246afed3c2e1d7b8a5cc57aa2574f2547e5977e63bf7b274437e780'),
    'system.journal': (
        _PLASO + 'systemd/journal/system.journal',
        '067a624d7d46c6c1786f4244a6913147ac21d0fb0d51c9be6be004fff0629b8e'),
    'system.journal.lz4': (
        _PLASO + 'systemd/journal/system.journal.lz4',
        'cac5b1a792a8bedf27aa63fb3efa5a9b00cfe729a2e85f52bc576463641c4f68'),
    'user-1000.journal': (
        _PLASO + 'systemd/journal/user-1000.journal',
        '6f075962738e7886ce0e38f2aff49ec967113cc2f2cfec6d9d7fa41340d56050'),
    'knowledgec-10.13.db': (
        _PLASO + 'macos/knowledgec-10.13.db',
        '03571fcce0b84296adc9f325cfc6eb4320e54cda2c325b9adc05e18c83389bb0'),
    'knowledgec-10.14.db': (
        _PLASO + 'macos/knowledgec-10.14.db',
        '01fc9d0ef0b10edc557c996665b74cbfe84d3d0539faad248909dd53ec022ab5'),
    'InstallHistory.plist': (
        _PLASO + 'plist/InstallHistory.plist',
        '234bd265af67660520d6083768a3ae3c92dd102a0c7214a628c8b25518b49317'),
    'quarantine.db': (
        _PLASO + 'sqlite/quarantine.db',
        '88d5f209cfef106d8e532c00e1aff96275509f4e76d77372d946489d22e93ca4'),
    'skype_main.db': (
        _PLASO + 'sqlite/skype_main.db',
        'fb52eae51d359b2ed060416dcf9725442fa0b495db32972529e9e75b34c533bb'),
    'imessage_chat.db': (
        _PLASO + 'sqlite/imessage_chat.db',
        '2931db3b556e33728867726f5bfd56464c4c2955cbe2e795660bda2ad631127d'),
    'mmssms.db': (
        _PLASO + 'android/mmssms.db',
        '0e2cadfa9d68fb1769c01ceb5d75e4dfc4872dfdde7c6db37b75e896e31e283f'),
    'dropbox_sync_history.db': (
        _PLASO + 'sqlite/dropbox_sync_history.db',
        '70a8bb01fa84e07220cc1f422af5cbbc1d147ffd5d68c24aac1feddef91aa769'),
    'gdrive_sync_log.log': (
        _PLASO + 'gdrive_synclog/sync_log.log',
        'a4cae0b93c699fdbab7f85b10cd1959bc4dd2f9bc744fca012513807691cb771'),
    'skydrive.log': (
        _PLASO + 'skydrive.log',
        '4d8bd880453c1c9d6d4b4e9de57934db8944c33df9c14d7cf4be494b64228012'),
    'skydrive_v1.log': (
        _PLASO + 'skydrive_v1.log',
        '644e15270bbeef6c05ca9790d0254e3044a1adde6dab5736194c3b7057372ef7'),
    # Mail: CPython's email test messages (PSF licence).
    'cpython-msg_02.eml': (
        _CPYTHON + 'msg_02.txt',
        '05d5e533f5e590d9ee2c7692d26dc87ccbf381f4831cca3362baf596691a55bb'),
    'cpython-msg_07.eml': (
        _CPYTHON + 'msg_07.txt',
        '8358092b45c8631df6466a2e4dc23278263b2dd2ba5765e99caba47c304dd3b5'),
    'cpython-msg_22.eml': (
        _CPYTHON + 'msg_22.txt',
        '4367f6ef8398e92de819ccd8e4938c819c2b24aa08f06cdcc0266bb0ec37eb08'),
    'cpython-msg_46.eml': (
        _CPYTHON + 'msg_46.txt',
        'd92e941be30507b7dd5976f4223f9d01998f1e73262e900e0ed002b0f53dc4b7'),
    'cpython-msg_47.eml': (
        _CPYTHON + 'msg_47.txt',
        'f43de32a9f3ec07815d8459ad8919b9a770d34122836da36401bbafbbd4acf8e'),
    # Windows thumbnail caches: fox-it dissect.thumbcache's test data
    # (Git LFS, so served from media.githubusercontent.com).
    'win7-thumbcache_256.db': (
        _DISSECT + 'windows_7/thumbcache_256.db',
        '6de5a185d522cc5a6ebc60d5717688cfbf551ead273f7ce0a1d16d7eceff097a'),
    'win7-thumbcache_idx.db': (
        _DISSECT + 'windows_7/thumbcache_idx.db',
        'dcab8d3967f8bb9bb91aa1358ba7518f427d3e60b3879a476144846c180cc01f'),
    'vista-thumbcache_32.db': (
        _DISSECT + 'windows_vista/thumbcache_32.db',
        '8b07ca4e60e4493af02375fa057158dc75436422790f703e0a9f1c4acc14f22e'),
    'win81-thumbcache_32.db': (
        _DISSECT + 'windows_81/thumbcache_32.db',
        '79b5642a25884d96a9dfbbbe50b521456103d74913d08bc802f5549fd3b5d3c0'),
    'win10-thumbcache_32.db': (
        _DISSECT + 'windows_10/thumbcache_32.db',
        'a3db73a04399dbca54f740fd1d0720154cf86b928f76985fd6bf447d9f6e297b'),
    'win11-thumbcache_32.db': (
        _DISSECT + 'windows_11/thumbcache_32.db',
        'e1f6238e5680ed3a71f66fe56b8748666ff6e31f04db3e87ef545613f42226e4'),
    # Thumbs.db as Windows XP and Vista left them in shared folders,
    # committed by accident to open-source projects (MIT, W3C).
    'xp-isetcam-Thumbs.db': (
        'https://raw.githubusercontent.com/ISET/isetcam/1199d298068facf8b18b63a416af5848dc6709a7/utility/external/fstack/books_05/Thumbs.db',
        '73020ccee39c3fb602c3f8cafe6522e36bd9041fb69b585809b758e92c9bbdb7'),
    'xp-tabulareditor-Thumbs.db': (
        'https://raw.githubusercontent.com/TabularEditor/TabularEditor/0e6b40eda539ec1edbbca32311a8691dbb5c4096/TabularEditor/Resources/Thumbs.db',
        '0a523533e683405d5f6bd5923042759d056a9d2d78d96d08c496bbb5c2d9863e'),
    'vista-w3c-Thumbs.db': (
        'https://raw.githubusercontent.com/w3c/sdw/349b5848108fe7bc9dfc1e489cecbbf5671c8559/UseCases/materials/3DGraphicsOnTheWeb/img/Thumbs.db',
        '3d75c8e9d7eb7a716758b59a0e5be76392b8450422ad2ea824ba766618ac24cf'),
    # macOS shared file lists (wader/fq, MIT) and a GTK recently-used.xbel
    # (fox-it dissect.target, Git LFS).
    'recentdocs.sfl2': (
        'https://raw.githubusercontent.com/wader/fq/0004670ad40500c350e44692dd1e84dc69d67f04/format/apple/bplist/testdata/recentdocs.sfl2',
        'd3c46380342848df768b5ee213ee3a24222424a339b040c9a2bac77fe90f9194'),
    'recentapps.sfl2': (
        'https://raw.githubusercontent.com/wader/fq/0004670ad40500c350e44692dd1e84dc69d67f04/format/apple/bplist/testdata/recentapps.sfl2',
        'fce7972989877f6f32d17bbaa883059240a1423a1bb4a64685c3bd20e118e660'),
    'recently-used.xbel': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/unix/linux/recently-used.xbel',
        'ca8ca76b9382797ec3563db71d79c9967bf6a0f4f1c8f9a751295c61058a211c'),
    # Zstandard's own decoder conformance files (facebook/zstd, BSD).
    'zstd-block-128k.zst': (
        _ZSTD + 'golden-decompression/block-128k.zst',
        '6a226ab40e6abcfc4a36baa04bf48f7ee56f166b8a26fbe2adb8fe771dceccba'),
    'zstd-empty-block.zst': (
        _ZSTD + 'golden-decompression/empty-block.zst',
        'ab5463fa31429bf81ced9f05e99b96b2fe88b1da37235a233f6bc96242332fbc'),
    'zstd-rle-first-block.zst': (
        _ZSTD + 'golden-decompression/rle-first-block.zst',
        'dd31b3fa6bb8601710cbde2c625660763bf38adc5255501e3d3a681cc0e4e1a4'),
    'zstd-zeroSeq_2B.zst': (
        _ZSTD + 'golden-decompression/zeroSeq_2B.zst',
        '8505867ac00fb49eb455da1b1e44e7cba5126f03114a72fb195170f7c95f2ca7'),
    'zstd-off0.bin.zst': (
        _ZSTD + 'golden-decompression-errors/off0.bin.zst',
        '144e2f029389c67c361bd3879ac142671592802f01f805a6c0c2b3e564d8022c'),
    'zstd-truncated_huff_state.zst': (
        _ZSTD + 'golden-decompression-errors/truncated_huff_state.zst',
        'c91a09d8824609d0643291803cbfb04b14213c02c890d5637bc3aed18e8a24f8'),
    'zstd-zeroSeq_extraneous.zst': (
        _ZSTD + 'golden-decompression-errors/zeroSeq_extraneous.zst',
        '85d7b2010abde2ff96ab8e6798b422d3cb78f8dd2108f83dbdd488da7056a6db'),
    # Windows Search indexes: a Windows 11 VM's, with its thumbnail caches
    # (AndrewRathbun/DFIRArtifactMuseum, MIT), and sidr's test indexes as
    # dissect.target tests them (Windows 10 ESE, Windows 11 SQLite).
    'rathbun-win11-Windows.edb': (
        'https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/WindowsSearchDB/Win11/RathbunVM/Windows.edb',
        '35ca37a022869e9311defe4211253948b68f55599f79258c16390ee4aa14dbf9'),
    'rathbun-win11-thumbcache_48.db': (
        'https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/Thumbcache/Win11/RathbunVM/thumbcache_48.db',
        'c0f99b5840888cf8832bf28c1f314c00b4d7b6e29020c9bc80a499ac75c6fa97'),
    'rathbun-win11-thumbcache_96.db': (
        'https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/Thumbcache/Win11/RathbunVM/thumbcache_96.db',
        '19f421db3be1944fbd32ddcdb65c0403549769259943670d7d057204715fa5c5'),
    'search-Windows.edb': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/search/Windows.edb',
        '10dd5fc05c2d19aa1fa4a705142e413fc5a4af17ae8e5e4909164262f9de7c66'),
    'search-Windows.db': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/search/Windows.db',
        'e655a1af9eb3386ffdc7e19aa8dcda06dfa2c35a1c3b657ac4a9c1c13c83f020'),
    # Executables the carving corpus does not have: a 32-bit PE (PuTTY's
    # Pageant, signed), a dynamically linked ELF (bat, Linux glibc build)
    # and an arm64 Mach-O (ripgrep, ad hoc signed) -- release archives,
    # read in memory by the tests.
    'pageant-w32.exe': (
        'https://the.earth.li/~sgtatham/putty/0.83/w32/pageant.exe',
        '48c424e22fffb39a5fd22d24ad834efee9275b7e05801397326a6d842987badf'),
    'bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz': (
        'https://github.com/sharkdp/bat/releases/download/v0.24.0/'
        'bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz',
        '0faf5d51b85bf81b92495dc93bf687d5c904adc9818b16f61ec2e7a4f925c77a'),
    'ripgrep-14.1.1-aarch64-apple-darwin.tar.gz': (
        'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/'
        'ripgrep-14.1.1-aarch64-apple-darwin.tar.gz',
        '24ad76777745fbff131c8fbc466742b011f925bfa4fffa2ded6def23b5b937be'),
    # Logical evidence. pyad1's AD1 image (Apache 2.0): four segments made
    # by FTK Imager 3.4.3.3, with FTK's log of the image's MD5/SHA-1 (from
    # dissect.evidence's copy). dissect.evidence's own AD1 test images
    # (AGPL test data, downloaded, not copied in): compressed, long names,
    # plain, and one encrypted with a passphrase. EnCase L01 files from
    # ggeng2/Logical_Image_DataSet (published research data set).
    'text-and-pictures.ad1': (
        _PYAD1 + 'text-and-pictures.ad1',
        'b48affafe6826f226bb4b3e0c97add2bc8766a6740ad992001515767d955ff8d'),
    'text-and-pictures.ad2': (
        _PYAD1 + 'text-and-pictures.ad2',
        '1bb53246dec28cf699f68656233138dc7842d789ca2aed7c712b281f19cbb062'),
    'text-and-pictures.ad3': (
        _PYAD1 + 'text-and-pictures.ad3',
        '262db84b9d479b6e7ff1e68aafb89739ea55105f03225ef1d69298c72472d05b'),
    'text-and-pictures.ad4': (
        _PYAD1 + 'text-and-pictures.ad4',
        'a50791bbb4a8bc374f386d6dbad702a153fa217df0df3b91b73bbf0a960ab8dd'),
    'text-and-pictures.ad1.txt': (
        _DISSECT_EVIDENCE + 'pcbje/text-and-pictures.ad1.txt',
        '24301f28955b835630b6ba7c026741b6bba307a1f6377ae567c9d4e230d26a93'),
    'ad1-compressed.ad1': (
        _DISSECT_EVIDENCE + 'compressed.ad1',
        'd88b6186b732dd7be752df52ed863bd9d2c273b1c8b2b3520e9032bfa1018a7c'),
    'ad1-long.ad1': (
        _DISSECT_EVIDENCE + 'long.ad1',
        '1245a140cfd79870781080d74aeec2f90c9b4530b2ac12e9a3b77c6015262b0f'),
    'ad1-test.ad1': (
        _DISSECT_EVIDENCE + 'test.ad1',
        '0c7b2a1b296a75590fd3f31d2d595cdad6c2442c2f394251c57506e9c488481a'),
    'ad1-encrypted.ad1': (
        _DISSECT_EVIDENCE + 'encrypted-passphrase/encrypted.ad1',
        '8126f55a545935a465a3b632bbced287b2843fae2a5f398c48d8a98e1bdbd26a'),
    'l01-docx.L01': (
        _L01 + 'NTFS/docx.L01',
        'c7207d70082a39acb7644c9d49a81c3dd70a841ec5e940e652114910a13da26c'),
    # Mac disk images (dfvfs test data): a zlib-compressed UDIF DMG and a
    # sparse image, each GPT + HFS+.
    'hfsplus_zlib.dmg': (
        _DFVFS + 'hfsplus_zlib.dmg',
        '5a21d44542141f93e26c3ff02057ebb6cc691c812897409f157dcaa27d629422'),
    'hfsplus.sparseimage': (
        _DFVFS + 'hfsplus.sparseimage',
        'f36c72c0571b2a9be9174ea2c12007808e1dbbee932652b1eb530f8536d01814'),
    # macOS Background Task Management (activity/btm.py).
    'BackgroundItems-v13.btm': (
        _BTMPARSER + 'BackgroundItems-v13.btm',
        'a7d58d9f15c9bb876e0f64a3b7010f7b5349fdcc5f829b869d4c4b8f19b7d022'),
    'BackgroundItems-v4.btm': (
        _LOGINITEMS + 'BackgroundItems-v4.btm',
        '5ed2ea43f0f7877a5fa568ee854379e8749a82d41e865362da2239ee15d04792'),
    'backgrounditems_sierra.btm': (
        _LOGINITEMS + 'backgrounditems_sierra.btm',
        '8056ff7c70430866c5311c86def1cc9c10d46aa3881ac3cd43e7cd52ca6d22a6'),
    'backgrounditemsPoisonApple.btm': (
        _LOGINITEMS + 'backgrounditemsPoisonApple.btm',
        '270395bc9ad1f262194da0ebd35682072f09ab4ec79ecbe0f31335c114ad8639'),
    # Dirty hives with their transaction logs (regipy's test data, MIT;
    # xz-compressed, read in memory by the tests).
    'regipy-transactions_NTUSER.DAT.xz': (
        _REGIPY + 'transactions_NTUSER.DAT.xz',
        'c1d2e899316ac133ff55b148efedb97a45ef044c3b0e367b40c15de81f4d67ad'),
    'regipy-transactions_ntuser.dat.log1.xz': (
        _REGIPY + 'transactions_ntuser.dat.log1.xz',
        '9d59a4bb625168b7483e3d4a1d7d1fd95543d0e77e1f4be791337f3d8bd402ac'),
    'regipy-transactions_ntuser.dat.log2.xz': (
        _REGIPY + 'transactions_ntuser.dat.log2.xz',
        '6e9b3099069c75dc818d6f6078edec9d57f27ec241693bca961642ddc2f0fb07'),
    'regipy-SYSTEM_B.xz': (
        _REGIPY + 'SYSTEM_B.xz',
        'd3e2898f432e8f098b1615adb34ca2da48e8bb3c4bbb663dbf5de61580352cf4'),
    'regipy-SYSTEM_B.LOG1.xz': (
        _REGIPY + 'SYSTEM_B.LOG1.xz',
        'acf3874baff41928b7c85e7521af910244fb33f87939e159e271d27429c7ec83'),
    'regipy-SYSTEM_B.LOG2.xz': (
        _REGIPY + 'SYSTEM_B.LOG2.xz',
        '4c1dcbc1de37f59c1bfaf943752f3bb83b2430dc480854da569419e9eeda58fb'),
    'regipy-UsrClass.dat.xz': (
        _REGIPY + 'UsrClass.dat.xz',
        'e8963dc88aa7dfca034d00c7c94adbaaca10739b0f767717cd82cf1196a46abe'),
    'regipy-UsrClass.dat.LOG1.xz': (
        _REGIPY + 'UsrClass.dat.LOG1.xz',
        '50857812937b02668aa6806a09453e3889887d662267570dc77bb95cbc91cbfb'),
    'regipy-UsrClass.dat.LOG2.xz': (
        _REGIPY + 'UsrClass.dat.LOG2.xz',
        '20366a8c8422c59ba890c8576746afd9629ff8b11b0a3472295a774cefaa6226'),
    # Sigma: SigmaHQ's rule release r2026-07-01 (Detection Rule License),
    # and attack logs from sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0
    # test data, downloaded, not copied in), each recording one
    # technique.
    'sigma_all_rules-r2026-07-01.zip': (
        'https://github.com/SigmaHQ/sigma/releases/download/'
        'r2026-07-01/sigma_all_rules.zip',
        '5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085'),
    'attack-CA_DCSync_4662.evtx': (
        _ATTACK + 'Credential%20Access/CA_DCSync_4662.evtx',
        '679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131'),
    'attack-DE_104_system_log_cleared.evtx': (
        _ATTACK + 'Defense%20Evasion/DE_104_system_log_cleared.evtx',
        '5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af'),
    'attack-DE_1102_security_log_cleared.evtx': (
        _ATTACK + 'Defense%20Evasion/DE_1102_security_log_cleared.evtx',
        'a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8'),
    'attack-exec_emotet_ps_4104.evtx': (
        _ATTACK + 'Other/emotet/exec_emotet_ps_4104.evtx',
        'c1639a23219f24f308e7001ffacb7e72ad6570154542adfbe5198c7c4abebd61'),
    'attack-exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx': (
        _ATTACK + 'Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx',
        '6d5b52398a67b36c160ec22db8e027efbc3e40943075d2d79c748931bc8d9982'),
    'attack-exec_sysmon_lobin_regsvr32_sct.evtx': (
        _ATTACK + 'Execution/exec_sysmon_lobin_regsvr32_sct.evtx',
        'd6978888a7dead4523c01df417aa7ea6ad2599a5bbf1acd05d89882aac956442'),
    'attack-LM_Remote_Service02_7045.evtx': (
        _ATTACK + 'Lateral%20Movement/LM_Remote_Service02_7045.evtx',
        'af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458'),
    'attack-LM_WMI_4624_4688_TargetHost.evtx': (
        _ATTACK + 'Lateral%20Movement/LM_WMI_4624_4688_TargetHost.evtx',
        '3ff3fcdb55c08ec0eaa39b25c1e02a205314f367bcedc662586bd063185ca41d'),
    'attack-LM_wmiexec_impacket_sysmon_whoami.evtx': (
        _ATTACK + 'Lateral%20Movement/LM_wmiexec_impacket_sysmon_whoami.evtx',
        '21b8852b2b386f4d3f6f0c8a7304de8e628bb43cfa23888ab317b95b784ffe59'),
    'attack-sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx': (
        _ATTACK + 'Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx',
        '9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f'),
    'attack-System_7045_namedpipe_privesc.evtx': (
        _ATTACK + 'Privilege%20Escalation/System_7045_namedpipe_privesc.evtx',
        '21a62694861beff246ea9fb357b908541b4acefaefdb7ecd6281b64df96cb187'),
    'attack-Powershell_4104_MiniDumpWriteDump_Lsass.evtx': (
        _ATTACK + 'Credential%20Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx',
        '54ff62eff26af588782e066b7b3b1b952bc83e1b75a84d81f9492e654cb5c319'),
    'attack-phish_windows_credentials_powershell_scriptblockLog_4104.evtx': (
        _ATTACK + 'Credential%20Access/'
        'phish_windows_credentials_powershell_scriptblockLog_4104.evtx',
        '177db8fa70262b4e2eba4e2902c97e82e3c6943fd111bde2ee522d5f1d57e856'),
    # Microsoft Defender: the Defender folder of an APT-simulator VM and a
    # Windows 11 Defender event log (DFIRArtifactMuseum, MIT), and
    # quarantine entries with one quarantined file (dissect.target's test
    # data, AGPL, downloaded, not copied in).
    'defender-APTSimulatorVM.zip': (
        'https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/WindowsDefender/APTSimulatorVM/Windows%20Defender/APTSimulatorVM_WindowsDefenderArtifacts.zip',
        '019d05105d005eb6cae16be94a50df3f70bd904ade9a2b7374c4ede4114eaa63'),
    'defender-Operational.evtx': (
        'https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows/EventLogs/Win11/TheTechHiveScenario/Microsoft-Windows-Windows Defender%4Operational.evtx',
        '3280513475802ee1a9d29035bbac3597cea112d6174e1392d4e822258927fb69'),
    'defender-entry-{800362A7-0000-0000-FB11-12639186E0D6}': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/defender/quarantine/Entries/{800362A7-0000-0000-FB11-12639186E0D6}',
        '4ed594d33e87bb7ed14deaf0bba10833b62f0ab681fac1f50e804044afe6169f'),
    'defender-entry-{8006A512-0000-0000-2E01-A7D5DA185F14}': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/defender/quarantine/Entries/{8006A512-0000-0000-2E01-A7D5DA185F14}',
        '039bd66f0e30b3d1d376c54e83b040b2967cff2c13bf8141735cf953f4d91c2c'),
    'defender-entry-{8006A512-0000-0000-2E11-A7D5DA185F24}': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/defender/quarantine/Entries/{8006A512-0000-0000-2E11-A7D5DA185F24}',
        '92cc0caf7cb7809f5ea75794b27fe3694f8e67761267b19127532f1f2417020c'),
    'defender-resource-A6C8322B8A19AEED96EFBD045206966DA4C9619D': (
        'https://media.githubusercontent.com/media/fox-it/dissect.target/b43db371c891fa3f382c5152e16f91b0bcde418c/tests/_data/plugins/os/windows/defender/quarantine/ResourceData/A6/A6C8322B8A19AEED96EFBD045206966DA4C9619D',
        '07e454654a394cf5b27eed2e4268322f860f9eed27bb97a7d443552b34181976'),
    # macOS FSEvents logs: plaso's version 1 and 2, dfvfs's.
    'fsevents-0000000002d89b58': (
        _PLASO + 'fsevents/fsevents-0000000002d89b58',
        '30a0d8455d4672765e30cd1f9ada5975cbc85a998877e4ac7a28d926abff48c7'),
    'fsevents-00000000001a0b79': (
        _PLASO + 'fsevents/fsevents-00000000001a0b79',
        '63fef94bc2cee7cfef64c198f4c25ed1b8c10ea701eb2ddfc5cffdc1e9f8d698'),
    'fsevents_000000000000b208': (
        _DFVFS + 'fsevents_000000000000b208',
        'a63ec661e18a196ee86137e2044feb5591b282abe92f5bf1adab0449f0ae4ebf'),
    # RDP bitmap caches: dissect.target's (Windows 7+ .bin, older .bmc).
    'rdp-Cache0000.bin': (
        _DISSECT_TARGET_DATA + 'rdpcache/Cache0000.bin',
        'de60dbe0105c25e9fb8a98ea065cb05358dc70d37c5dd54299a8bdabfa4cd0c6'),
    'rdp-bcache24.bmc': (
        _DISSECT_TARGET_DATA + 'rdpcache/bcache24.bmc',
        'e018309e635a00a6fd047953c600d619c74bcf45c6bb7dc51cf77e5ae8d7148b'),
    # Phones. MVT's iPhone backup, as a folder (Info.plist, Manifest.db
    # and the files it keeps under fileID[:2]/fileID); plaso's Android
    # contacts2.db (calls) and iOS Accounts3.sqlite and known networks.
    'mvt-ios-backup/Info.plist': (
        _MVT_BACKUP + 'Info.plist',
        '01a1b7a5176a575e13686fc0190ed881297324ad3e9345d7bc240bebf277be4a'),
    'mvt-ios-backup/Manifest.db': (
        _MVT_BACKUP + 'Manifest.db',
        '7876f1034a5082d2aaef9f6df2f90ca72168616bb724efd8bd856e0c9d7ecd96'),
    'mvt-ios-backup/0d/0d609c54856a9bb2d56729df1d68f2958a88426b': (
        _MVT_BACKUP + '0d/0d609c54856a9bb2d56729df1d68f2958a88426b',
        '37db93a97e9cafcbb7d7d02ad29c8d995b1322fecf38d23d66fc2468714834e9'),
    'mvt-ios-backup/0d/0dc926a1810f7aee4e8f38793ed788701f93bf9d': (
        _MVT_BACKUP + '0d/0dc926a1810f7aee4e8f38793ed788701f93bf9d',
        'f570f75b4693bcac962257909ae2e493c28191dc3b8089a9c85a5b1cfe7efbf1'),
    'mvt-ios-backup/1f/1f5a521220a3ad80ebfdc196978df8e7a2e49dee': (
        _MVT_BACKUP + '1f/1f5a521220a3ad80ebfdc196978df8e7a2e49dee',
        'ab0a743b74101a5b8c6dae0b2e5d65ac015a1e624b7288d400c8328647afaeca'),
    'mvt-ios-backup/20/2041457d5fe04d39d0ab481178355df6781e6858': (
        _MVT_BACKUP + '20/2041457d5fe04d39d0ab481178355df6781e6858',
        'e1dff4d8350272e24101685d5299338a531b84aed289d3e8ae6a7bef5c7d7df7'),
    'mvt-ios-backup/3a/3a47b0981ed7c10f3e2800aa66bac96a3b5db28e': (
        _MVT_BACKUP + '3a/3a47b0981ed7c10f3e2800aa66bac96a3b5db28e',
        '6e777afea087f4c2a7ea295b02935b6b52c44d8877f37d420bd466673bb68678'),
    'mvt-ios-backup/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28': (
        _MVT_BACKUP + '3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28',
        '2d7c6e9a504cd54ea8a389ebf27285d06d4a3043c35ec06e458c5a571eaf48d0'),
    'mvt-ios-backup/64/64d0019cb3d46bfc8cce545a8ba54b93e7ea9347': (
        _MVT_BACKUP + '64/64d0019cb3d46bfc8cce545a8ba54b93e7ea9347',
        '8852a5a04c3aa2793878342abeeaf0d12e31219d25f8289b3e5c7d15d35cbce9'),
    'mvt-ios-backup/6e/6e9d0cb750a70e7fa10943c134a5f021dab327e7': (
        _MVT_BACKUP + '6e/6e9d0cb750a70e7fa10943c134a5f021dab327e7',
        '39a1660b9d470a6ae2d19b581b55e026c32c2c308260d260cd92b8e01141d282'),
    'mvt-ios-backup/7c/7c7fba66680ef796b916b067077cc246adacf01d': (
        _MVT_BACKUP + '7c/7c7fba66680ef796b916b067077cc246adacf01d',
        'e30d9669074b3158b20f413735ea614da205ca11e66b8b0e366af1d2e17894f5'),
    'mvt-ios-backup/b8/b8548dc30aa1030df0ce18ef08b882cf7ab5212f': (
        _MVT_BACKUP + 'b8/b8548dc30aa1030df0ce18ef08b882cf7ab5212f',
        '4ef63cf563feedc262715967d6bf6a68d7e12ed995122d3d89086efba46890a0'),
    'mvt-ios-backup/e7/e794f6ffcc3c222535f47684a63d5178da3c4500': (
        _MVT_BACKUP + 'e7/e794f6ffcc3c222535f47684a63d5178da3c4500',
        '50ffb3b23d87ca51a060b4d85ad75381ddba37634884decf3d46dc437b64442a'),
    'android-contacts2.db': (
        _PLASO + 'android/contacts2.db',
        'b37699f86515cff66f71a1a8d9b48c7392a83fc6f9fab35c6abd8f5435221591'),
    'ios-Accounts3.sqlite': (
        _PLASO + 'ios/Accounts3.sqlite',
        'e39142fa65649f2bcea2ae8da94f1388431edfc3afb7dc30e8a296604283ed80'),
    'ios-com.apple.wifi.known-networks.plist': (
        _PLASO + 'ios/com.apple.wifi.known-networks.plist',
        '4051d11cd394bb6d58ec0ca501db387fa0e0609fa54abc62e6fa0e2f7ecaa8e0'),
    'abx-test-basic.xml': (
        _CCL_ABX + 'test-basic.xml',
        'a5289bd4859d165f40703f22c569203f9129447bedd4ed7d79ae471d1fc28d51'),
    'abx-test-basic.xml.abx': (
        _CCL_ABX + 'test-basic.xml.abx',
        'fbcc2b7da77bf3a6c27a3a64f2f625a8d9181d8159cb77ee65092afadc9c5eb4'),
    'abx-test-typed-attribute.xml': (
        _CCL_ABX + 'test-typed-attribute.xml',
        'f1cdfa43d8945c4fe304dbf7dc9fdb716b6be2539ee79e3eb9518a8a0ad32c03'),
    'abx-test-typed-attribute.xml.abx': (
        _CCL_ABX + 'test-typed-attribute.xml.abx',
        'acf2e7f5ba7695897d158a7710d53562768109982da490cbd7ce8e1cddc72a4a'),
    'abx-test_interned_strings.xml': (
        _CCL_ABX + 'test_interned_strings.xml',
        'd873ca4db055979b60701f7ec06ea6431cf736a870aa5aace6f646a550a2a244'),
    'abx-test_interned_strings.xml.abx': (
        _CCL_ABX + 'test_interned_strings.xml.abx',
        '7d6b23ec3339aa171cd6910f8194c4f5166b820add35e37195ddc74b80839d9f'),
    'l01-zip.L01': (
        _L01 + 'NTFS/zip.L01',
        '1306ead913d084f808cd9da09c428928e319cc31bfbafbd5565564d3b60ffe31'),
}


def _download(url):
    """Fetch with retries and mirrors (tools/download.py)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from download import download
    finally:
        sys.path.pop(0)
    return download(url)


def main():
    os.makedirs(FOLDER, exist_ok=True)
    fetched = kept = 0
    for name, (url, digest) in SAMPLES.items():
        path = os.path.join(FOLDER, name)
        if os.path.exists(path):
            with open(path, 'rb') as handle:
                if hashlib.sha256(handle.read()).hexdigest() == digest:
                    kept += 1
                    continue
            print(f"  {name}: checksum differs; downloading again")
        # File names hold '$' and '%': quote the last segment.
        base, last = url.rsplit('/', 1)
        data = _download(base + '/' + urllib.parse.quote(last))
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"{name}: SHA-256 does not match; not kept")
        # A name with a folder (a phone backup's layout) keeps it.
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as handle:
            handle.write(data)
        fetched += 1
    print(f"Artifact samples: {fetched} downloaded, {kept} already here "
          f"({FOLDER})")
    return 0


if __name__ == '__main__':
    sys.exit(main())

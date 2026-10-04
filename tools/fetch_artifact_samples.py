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

Plaso's own tests record expected values for many of these files; the
activity tests check TRACE against the same values. Files land in
test_images/artifact_samples/ (gitignored, like every test image).

    python tools/fetch_artifact_samples.py
"""

import hashlib
import os
import sys
import time
import urllib.parse
import urllib.request

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
}


def _download(url, attempts=4):
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                url, headers={'User-Agent': 'TRACE-tests'})
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except OSError as exc:
            if attempt == attempts - 1:
                raise SystemExit(f"Could not download {url}: {exc}")
            time.sleep(5 * (attempt + 1))


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
        with open(path, 'wb') as handle:
            handle.write(data)
        fetched += 1
    print(f"Artifact samples: {fetched} downloaded, {kept} already here "
          f"({FOLDER})")
    return 0


if __name__ == '__main__':
    sys.exit(main())

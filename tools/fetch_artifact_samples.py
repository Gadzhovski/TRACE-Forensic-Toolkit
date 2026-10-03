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

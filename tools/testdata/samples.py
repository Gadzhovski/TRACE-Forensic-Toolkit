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
* ReFS 3.2 and 1.2 volumes Windows wrote (R. Nordvik's ReFS forensic
  containers, Mendeley Data, CC BY 4.0)
* UDF discs written by CDBurnerXP, revisions 1.50 to 2.60 (7-Zip patch
  #389's test archive) -- real UDF 2.50/2.60 metadata partitions
* Cellebrite Physical Analyzer report.xml fragments (a decoded WhatsApp
  chat, an account) from sepinf-inc/IPED's test resources (GPL-3.0 test
  data, downloaded, never committed) -- what tests/test_ufdr.py wraps into
  a UFDR
* macOS Background Task Management files: hewigovens/BTMParser's
  BackgroundItems-v13.btm and puffyCid/macos-loginitems' (MIT) v4 and
  pre-Ventura backgrounditems.btm, one with PoisonApple's login item
* Chromium profile databases: plaso's Cookies (Chrome 68 and 2011) and
  Web Data, and the SQL dumps Chromium's own migration tests load for
  Login Data, Favicons and Top Sites (components/test/data), pinned
* Microsoft's documented WLAN profile samples (MicrosoftDocs/win32,
  NativeWiFi), the schema Wlansvc/Profiles files are written in
* Windows 11 Notepad tab state files (TabState/*.bin) Notepad wrote:
  ogmini's Notepad-State-Library (MIT) test files, Notepad 11.2402 to
  11.2504, with the saved text files beside them, and AbdulRhmanAlfaifi's
  notepad_parser (MIT) samples -- whose own parser's output is
  tests/expected/notepad_parser_key.json

Plaso's own tests record expected values for many of these files; the
activity tests check TRACE against the same values. Files land in
test_images/samples/ (gitignored, like every test image).

    python -m tools.testdata.fetch --group samples
"""

import hashlib
import os
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
FOLDER = os.path.join(ROOT, 'test_images', 'samples')

_PLASO = ('https://raw.githubusercontent.com/log2timeline/plaso/'
          'ac6460d7350c9160bdf69161726ee0e8d4545874/test_data/')
_EVTX = ('https://raw.githubusercontent.com/omerbenamram/evtx/'
         '47d63022caa8336ecdd0c42d335e2bb03381b00d/samples/')
_CHROMIUM = ('https://raw.githubusercontent.com/chromium/chromium/'
             '0b268b1263a4a94c8659b3609fa1d9990da1dee0/components/test/'
             'data/')
_WIN32_DOCS = ('https://raw.githubusercontent.com/MicrosoftDocs/win32/'
               'f18cd183e3c2691df8fe4d3c7ab81bc226d2ab85/desktop-src/'
               'NativeWiFi/')
_NSL = ('https://raw.githubusercontent.com/ogmini/Notepad-State-Library/'
        'ce53f9d66de4551fa78f3cb19df90d7820f08d94/')
_NOTEPAD_RS = ('https://raw.githubusercontent.com/AbdulRhmanAlfaifi/'
               'notepad_parser/f14171df0910e625dc2e6ec160de93ab7c8af9bd/')
_IPED = ('https://raw.githubusercontent.com/sepinf-inc/IPED/'
         '75bc5cafe2094e8caaa3a5c6266df50f1ae7d9eb/iped-engine/src/test/'
         'resources/')
_DFVFS = ('https://raw.githubusercontent.com/log2timeline/dfvfs/'
          '917cefc9426d6ded2687d2b55164ded25b44fcb7/test_data/')
_POI = ('https://raw.githubusercontent.com/apache/poi/'
        'ae62bb5116b9aee19ebd5834e3a82066132c9f7f/test-data/')
_MSO = ('https://raw.githubusercontent.com/nolze/msoffcrypto-tool/'
        '6d9e72c58de2cf7df1ab45ac0d74ebedac8c58e3/tests/')
_TCPDUMP = ('https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/'
            'eebca9915dc33ce4724ca55010c507c80f519c1b/tests/')
_ZEEK = ('https://raw.githubusercontent.com/zeek/zeek/'
         'b5bf5e5e42e9015d78be5105d2fd1e41eb75361f/testing/btest/Traces/')
_CPYTHON39 = ('https://raw.githubusercontent.com/python/cpython/'
              'v3.9.0/Lib/distutils/command/')
_TSKDATA = ('https://raw.githubusercontent.com/sleuthkit/sleuthkit_test_data/'
            'abcb05bd7f01313115d213dcd83826989fe93535/')
_TSKDATA_LFS = ('https://media.githubusercontent.com/media/sleuthkit/'
                'sleuthkit_test_data/'
                'abcb05bd7f01313115d213dcd83826989fe93535/')
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
    # PowerShell transcripts and a Windows Firewall log (plaso's).
    'powershell_transcript.txt': (
        _PLASO + 'powershell_transcript.txt',
        'c17fbbedb8288c6e928192130862df847b7866991380cecb37722386b8ec8036'),
    'powershell_transcript_ger.txt': (
        _PLASO + 'powershell_transcript_ger.txt',
        '775560e9b66df9a9c6f8bfbdbf903ac85a79eb2614ce823a3c1c80abaa59a3f9'),
    'windows_firewall.log': (
        _PLASO + 'windows_firewall.log',
        '186f62517ea40367d77e1c7d4a8111271939123dd5592cb576f75c9241f25600'),
    # Microsoft's WLAN profile samples (tests/test_windows_logs.py).
    'wlan-wpa2-personal-profile-sample.md': (
        _WIN32_DOCS + 'wpa2-personal-profile-sample.md',
        'df3636c4ecf58ada00ef4eb778b8ceb8ae1c76cb52ce5ef78f8d477d8d3c927e'),
    'wlan-non-broadcast-profile-sample.md': (
        _WIN32_DOCS + 'non-broadcast-profile-sample.md',
        '2ed96fb2c2a01abd2158b7a6c8abe02eadbeab92ad8263e01e1638ca4cf258ae'),
    'wlan-wpa2-enterprise-with-peap-mschapv2-profile-sample.md': (
        _WIN32_DOCS + 'wpa2-enterprise-with-peap-mschapv2-profile-sample.md',
        'a8039737d77169e23ff0311662dc414a5937a706486406cc411cf05955eedced'),
    'wlan-wpa3-personal-transition-profile-sample.md': (
        _WIN32_DOCS + 'wpa3-personal-transition-profile-sample.md',
        '0aa9a562b42e2e70dec8b624a92418fa8c347a80d79d8557c6489d9fafb4d322'),
    'wlan-bootstrap-profile-sample.md': (
        _WIN32_DOCS + 'bootstrap-profile-sample.md',
        '61052eaa87accb492e5b6b8128cb548daeb0277217d70a952f3317a58e7b6a3f'),
    # Chromium profile databases: plaso's real Cookies and Web Data, and
    # Chromium's own SQL fixtures (tests/test_chromium_extras.py).
    'chrome-Cookies-68.0.3440.106': (
        _PLASO + 'chrome/Cookies-68.0.3440.106',
        '59d1a2c835a5aba67c8e7e31ee853382fcb1b2807ffdad3b79edc53d50acc1e9'),
    'chrome-cookies.db': (
        _PLASO + 'chrome/cookies.db',
        '57c81098b475576befa9e11e30b974313ff6bba4976123297d8c4815abaa805f'),
    'chrome-Web-Data': (
        _PLASO + 'chrome/Web%20Data',
        '7779fb8b6dab0d38fd41df3dacfd9f5ca96ec1ee5ecece6b9d276a786bc23812'),
    'chromium-login_db_v43.sql': (
        _CHROMIUM + 'password_manager/login_db_v43.sql',
        'e87a53b058df2db9722c4bc742f4210b5ec807ba37edf25487bd3af5cbc3e445'),
    'chromium-login_db_v4.sql': (
        _CHROMIUM + 'password_manager/login_db_v4.sql',
        'b844e1c05dd90a77cc77a72eff8d8ab1d1e8941f3215d478913096c2f658a61f'),
    'chromium-Favicons.v9.sql': (
        _CHROMIUM + 'history/Favicons.v9.sql',
        'a9c11da9dffb92b138ca244acee1f0c1c95f005e14694d3566f3e42abac43606'),
    'chromium-TopSites.v5.sql': (
        _CHROMIUM + 'history/TopSites.v5.sql',
        '6586038a90ad2fdb052f91c1b2edae687f8c24f2c84fa3c2bc92689635a1bcf2'),
    # Windows 11 Notepad's TabState files (tests/test_notepad.py).
    'notepad-x-00bc8eb6-b8bb-459b-973a-a998b734b47c.0.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/00bc8eb6-b8bb-459b-973a-a998b734b47c.0.bin',
        'c00632272bde953b9852a39436510f216dfe2c75bd2754ca7ab1f46b49f513fe'),
    'notepad-x-00bc8eb6-b8bb-459b-973a-a998b734b47c.1.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/00bc8eb6-b8bb-459b-973a-a998b734b47c.1.bin',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    'notepad-x-00bc8eb6-b8bb-459b-973a-a998b734b47c.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/00bc8eb6-b8bb-459b-973a-a998b734b47c.bin',
        '2ccb974d017fd09cd92639d223c32e1e390ad7d29cca804311c5e5f1ca823052'),
    'notepad-x-1d971dfe-9e67-4849-a7e5-a46f4100ad0b.0.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/1d971dfe-9e67-4849-a7e5-a46f4100ad0b.0.bin',
        '7b81b5b15914e55914632e6ef0f0a6af307067dc5b9af70731f52c86b49a9901'),
    'notepad-x-1d971dfe-9e67-4849-a7e5-a46f4100ad0b.1.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/1d971dfe-9e67-4849-a7e5-a46f4100ad0b.1.bin',
        '988cb53bcbacbc8cedd480ae481edbe9bb22173cb043dcc157f11ef5e340fd7f'),
    'notepad-x-1d971dfe-9e67-4849-a7e5-a46f4100ad0b.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/1d971dfe-9e67-4849-a7e5-a46f4100ad0b.bin',
        'fbb3a67df0fcc903d838aa0f07bfb8d53f4abef33a668ade60ee4436f277c349'),
    'notepad-x-215c7345-13c2-440a-b6bb-df737db3f327.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/215c7345-13c2-440a-b6bb-df737db3f327.bin',
        'f8f2c60c761d8f860df4be4a83bcbadada85642dd7835ff7f482d73f81f78904'),
    'notepad-x-3249c0ef-a5ef-4dc6-bb00-b84a1dab317f.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/3249c0ef-a5ef-4dc6-bb00-b84a1dab317f.bin',
        '45617843a18a754b715c6574e6b289baaa17018b9afdbe4a7a7e9a0c2a5db7da'),
    'notepad-x-8508552a-b3e8-46d6-9203-9c75dd0b24a5.0.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/8508552a-b3e8-46d6-9203-9c75dd0b24a5.0.bin',
        'e25276a705defc56e9adb3deaf02332c5415ec990f6c3ad90424c29b3a0dc9fa'),
    'notepad-x-8508552a-b3e8-46d6-9203-9c75dd0b24a5.1.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/8508552a-b3e8-46d6-9203-9c75dd0b24a5.1.bin',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    'notepad-x-8508552a-b3e8-46d6-9203-9c75dd0b24a5.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/8508552a-b3e8-46d6-9203-9c75dd0b24a5.bin',
        '15a7f3a11c41f9724a59c1c45676daced87a2ff935c2e58b87ddc971ba5336da'),
    'notepad-x-abb3d672-e5d2-4994-9bc3-483a44805b16.bin': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/11.2504.62.0/TabState/abb3d672-e5d2-4994-9bc3-483a44805b16.bin',
        '06020b89c7e619caa83d7cd5febc5627413ceefcb07eab7b74baf26eb419a546'),
    'notepad-text-SavedFile-Long-UnsavedChanges.txt': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/TextFiles/SavedFile-Long-UnsavedChanges.txt',
        'f4988df6e792e119cde08ce13c987cb32ac27033cc2c3495e74db3d67449611c'),
    'notepad-text-SavedFile-Long.txt': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/TextFiles/SavedFile-Long.txt',
        'f4988df6e792e119cde08ce13c987cb32ac27033cc2c3495e74db3d67449611c'),
    'notepad-text-SavedFile-Short-UnsavedChanges.txt': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/TextFiles/SavedFile-Short-UnsavedChanges.txt',
        '580d228c3f90e24bac25a3373d720045b008347c0c1003359278272867a975be'),
    'notepad-text-SavedFile-Short.txt': (
        _NSL + 'NotepadStateLibrary/xUnitTests/TestFiles/TextFiles/SavedFile-Short.txt',
        '580d228c3f90e24bac25a3373d720045b008347c0c1003359278272867a975be'),
    'notepad-old-EncodingANSI.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/Encoding/EncodingANSI.bin',
        'bc9cc0bafb0c9d1d9c06537be6c8b74d76727aa27c3ef8f8464700885fe16885'),
    'notepad-old-EncodingUTF16BE.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/Encoding/EncodingUTF16BE.bin',
        'af23617923cfbf01d25206cc4c11f9e3faf76c877be059c6aa1395cd4c5166af'),
    'notepad-old-EncodingUTF16LE.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/Encoding/EncodingUTF16LE.bin',
        'c7d53908f6a031c88263c1b512c7bb348678fa8537d4dd87dad6273d7f3fc7e5'),
    'notepad-old-EncodingUTF8.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/Encoding/EncodingUTF8.bin',
        '714ac2c156d71abacd4b5d2cd2a894f277754d05ff2fe45e201d6bdbe218de16'),
    'notepad-old-EncodingUTF8BOM.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/Encoding/EncodingUTF8BOM.bin',
        'be0c14f68a8f87364f847695cdde4e525d7ddc2eb268440f4b6ae9aac8f736ec'),
    'notepad-old-MacintoshCR.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/CarriageReturn/MacintoshCR.bin',
        'da1bb0eb101e0cf2dbc1f56ec6435895a927aec9690966ca0dec7463108a2bab'),
    'notepad-old-UnixLF.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/CarriageReturn/UnixLF.bin',
        '09fa397c16df8e757f995621e6465de160f446850cc4d243094e2a325f665377'),
    'notepad-old-WindowsCRLF.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/CarriageReturn/WindowsCRLF.bin',
        '390927503292dbfe86f505caeda125bc321b22bde5e382ff8110f8a85aca8de2'),
    'notepad-old-SavedFile-UnsavedChanges-NotClosed.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/SavedFile/SavedFile-UnsavedChanges-NotClosed.bin',
        '479824fcc19fb15f9587a2276ce1cc129f5f726b0553b9fe0aa8a81cdf12f198'),
    'notepad-old-SavedFile-Selection.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/SavedFile/SavedFile-Selection.bin',
        '93e872e7f26cc924910846cc6ad454496e9046fc610cd8363dd08496035922b8'),
    'notepad-old-WordWrapOn.bin': (
        _NSL + 'NotepadStateLibrary/TestApp/TestFiles/WordWrapOn.bin',
        '3eaa681d093719994f37e5f620407e24b4974290a4cdd6c658c7305c311eccfa'),
    'notepad-rs-not_saved-arabic-rtl_set-bc0695dd.bin': (
        _NOTEPAD_RS + 'samples/not_saved/arabic/rtl_set/bc0695dd-4239-47fd-9ca1-5b5d5087575a.bin',
        '378d4fe001e2a89b85dab17a204b65bc1b95f861d4bd082ee876ec0150edff89'),
    'notepad-rs-not_saved-english-rtl_unset-9f7c2ef9.bin': (
        _NOTEPAD_RS + 'samples/not_saved/english/rtl_unset/9f7c2ef9-5635-4629-a936-d388ca307aac.bin',
        '83747521bce9d1fce33de6fd0050054f59c803f32e12b7fce05d18b23112b627'),
    'notepad-rs-saved-arabic-rtl_set-big_file-9cb51381.bin': (
        _NOTEPAD_RS + 'samples/saved/arabic/rtl_set/big_file/9cb51381-03ff-4d89-9cb7-08ff36f69ea8.bin',
        'c58082c7af4281a19548a3093d6c91a6e940d6465fa6e10e2a216cfcff5a2d8f'),
    'notepad-rs-saved-arabic-rtl_set-c5bf63ad.bin': (
        _NOTEPAD_RS + 'samples/saved/arabic/rtl_set/c5bf63ad-799d-4d39-a41a-fcc280410497.bin',
        'c0b00bec17eefa4bbfa377da96e7e49bcfaf70a99f7d354faff276d469deda6a'),
    'notepad-rs-saved-arabic-unsaved_mod-c5bf63ad.bin': (
        _NOTEPAD_RS + 'samples/saved/arabic/unsaved_mod/c5bf63ad-799d-4d39-a41a-fcc280410497.bin',
        '540298af9b0424593883e740bfcdb33c00ac88158118bb9e64293f07c6a0edc6'),
    'notepad-rs-saved-english-rtl_unset-22bb38a5.bin': (
        _NOTEPAD_RS + 'samples/saved/english/rtl_unset/22bb38a5-0bf4-4ff5-8aec-b821a534b3e0.bin',
        'd84f6260dc88c4a77e7a9aef2087cf3ea828e6d03a25845cc0633ce27fe428fc'),
    'notepad-rs-saved-english-rtl_unset-big_file-370b5af2.bin': (
        _NOTEPAD_RS + 'samples/saved/english/rtl_unset/big_file/370b5af2-8e7c-4e6b-998b-4aaa5d21931c.bin',
        'e8d0baddc2aa2cb02a252badb358eaf842acf9f3d72ab8498b1dcb61a7f11245'),
    'notepad-rs-saved-english-unsaved_mod-22bb38a5.bin': (
        _NOTEPAD_RS + 'samples/saved/english/unsaved_mod/22bb38a5-0bf4-4ff5-8aec-b821a534b3e0.bin',
        '492cb6109c2bd985b37e94ea477aa059ccc5415bfbf369633d1a8a7be896a87c'),
    'notepad-rs-vers-26200.6584-2adb69ab.bin': (
        _NOTEPAD_RS + 'samples/vers/26200.6584/2adb69ab-7ba0-4f17-9e09-88951912afd9.bin',
        '5cc6306868f3fbcfefbfbe6180ddb9a069b6b344c5f1e29feed5c877fb6f63cf'),
    'notepad-rs-vers-26200.6584-8f842aa4.bin': (
        _NOTEPAD_RS + 'samples/vers/26200.6584/8f842aa4-044c-4044-9944-2b5de0d53548.bin',
        '1cf4c465d631f54bc6f7e7b67f4f1db77ca6041a26674d0698bb72ba721bfd95'),
    'notepad-rs-vers-26200.6584-9bad4cfd.bin': (
        _NOTEPAD_RS + 'samples/vers/26200.6584/9bad4cfd-7ba4-4b42-b219-5bb0e82464fc.bin',
        'd06a59c220b0f9237a018ab1fa86f849c2d40a0ec6b80d0f69c87e6a3d78da30'),
    # ReFS volumes Windows wrote: R. Nordvik's "Resilient Filesystem
    # Forensic Containers" (Mendeley Data, doi:10.17632/9d7p6mbhpz.1,
    # CC BY 4.0) -- ReFS 3.2 (Windows 10 1703) holding the VeraCrypt 1.23
    # installer, and ReFS 1.2.
    'refs-v3_2.E01': (
        'https://data.mendeley.com/public-files/datasets/9d7p6mbhpz/files/'
        '7b101cfc-dc0e-4ee9-9b10-f6d9ed39f8b4/file_downloaded',
        'd9d0833b01fe8f226d2f405cee0ec3f0ca9a128e29c2e1a762b17362263ac23a'),
    'refs-v1_2-3.E01': (
        'https://data.mendeley.com/public-files/datasets/9d7p6mbhpz/files/'
        'c40de8de-4dc4-4ea0-815d-7c9664e505f7/file_downloaded',
        'c9ac080984260fb09daf8a09715cd43561b6f0565e081557d909b455b98ab28c'),
    # UDF 1.50, 2.00, 2.01, 2.50 and 2.60 discs CDBurnerXP made (2.50 and
    # 2.60 with a metadata partition), attached to 7-Zip's patch #389.
    'udf_tests.7z': (
        'https://sourceforge.net/p/sevenzip/patches/389/attachment/'
        'udf_tests.7z',
        '31630b5b1b39dac2255741f2afd93c656290aebd01e69b184f021b2ecfef3398'),
    # Physical Analyzer's report.xml, as IPED's tests keep it.
    'ufed-model-chat.xml': (
        _IPED + 'ufed-model-chat.xml',
        'fba1e816d92405e475db137d5eb4ba2874f2546dca4917665eea5c0a720e0097'),
    'ufed-model-useraccount.xml': (
        _IPED + 'ufed-model-useraccount.xml',
        '4490b72aca737faa749e093459695177d29553e6e40f07b0edd90367b8a6a24e'),
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
    # dfvfs's format corpus (tests/test_dfvfs_formats.py): a 2-segment E01
    # and a split raw numbered from .000 (both the same 4 MB ext2 disk as
    # ext2.raw), unencrypted Core Storage, LUKS2 (Argon2i, header only),
    # an Apple Partition Map, a Parallels bundle, a gzip cut short, the
    # same syslog as CPIO (four formats), LZMA-alone and raw zlib, and a
    # database holding a database in a cell.
    'ext2.raw': (
        _DFVFS + 'ext2.raw',
        'a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80'),
    'ext2.split.E01': (
        _DFVFS + 'ext2.split.E01',
        'd14f130c462b0ab8efb6bb44bbfe5680e00ffaa90538cde84579d1eb0dcac00f'),
    'ext2.split.E02': (
        _DFVFS + 'ext2.split.E02',
        'b508375954ec1d1caeed8a6e5fc503f98493816ad6a3af89f5d220244c5f2864'),
    'ext2.splitraw.000': (
        _DFVFS + 'ext2.splitraw.000',
        '2a864677a8f3c56a57ef5f02ca456205e06a274c5ba1b803c8235601d7930ee2'),
    'ext2.splitraw.001': (
        _DFVFS + 'ext2.splitraw.001',
        '5647f05ec18958947d32874eeb788fa396a05d0bab7c1b71f112ceb7e9b31eee'),
    'cs_single_volume.raw': (
        _DFVFS + 'cs_single_volume.raw',
        'b0e6e787d28816d6986f4c0489e00d99487abdb607c89ca23e0b62c9b72e4ec8'),
    'luks2.raw': (
        _DFVFS + 'luks2.raw',
        '500cc79ca8e95122acccec7a3c155f2a203fc32776bba57fb166662513f51e67'),
    # Classic HFS written by the Linux kernel (mount -t hfs) -- dfvfs's
    # utils/generate_test_data_linux.sh says what went in.
    'hfs.raw': (
        _DFVFS + 'hfs.raw',
        '88f1f131409eda86b86b31bb75f11f8bda5f87968ace2cda5c9e9ab1e4c12379'),
    'apm.dmg': (
        _DFVFS + 'apm.dmg',
        '897f487f4971e72c762e00460935e3b25176cda35620b508b490f65a7e0118ff'),
    'hfsplus.hdd/DiskDescriptor.xml': (
        _DFVFS + 'hfsplus.hdd/DiskDescriptor.xml',
        '055612a450d55d0265fd117b5cf57355376ec4c62f9a80db78a6cdfe402c8a2a'),
    'hfsplus.hdd/hfsplus.hdd.0.{5fbaabe3-6958-40ff-92a7-860e329aab41}.hds': (
        _DFVFS + 'hfsplus.hdd/'
        'hfsplus.hdd.0.{5fbaabe3-6958-40ff-92a7-860e329aab41}.hds',
        '1b5192b42705b7b959da2590d590363cda0088a4834a29c2e2984d938eb1070c'),
    'corrupt1.gz': (
        _DFVFS + 'corrupt1.gz',
        'a7524eeecdd46dbc0921aa8c5bde1a226d1cbc11d50b653573f2803e195b9014'),
    'dfvfs-syslog': (
        _DFVFS + 'syslog',
        '0420b023f8dc1b71ff25191ce4ce88d10028f99f99f7c21532611f4c273aeae9'),
    'syslog.bin.cpio': (
        _DFVFS + 'syslog.bin.cpio',
        '84bb569cf2a018db29e70d55d8b69d8463dcbd77d70f1213c2f9e7de0d21c5c7'),
    'syslog.odc.cpio': (
        _DFVFS + 'syslog.odc.cpio',
        '78f919b358a5cf7beb78c84b9cd3028cd0b343386e5442ef50736647bba4f4ad'),
    'syslog.newc.cpio': (
        _DFVFS + 'syslog.newc.cpio',
        '94e668bec666fbf9ce4d9d68fc9296ac4c3e231a6ab84f5e684bd90f49d8b53a'),
    'syslog.crc.cpio': (
        _DFVFS + 'syslog.crc.cpio',
        'ae3e4ba73c0cb9c4b796b811ce893cfbef39d2101c075c3282873dcaa302ea15'),
    'syslog.lzma': (
        _DFVFS + 'syslog.lzma',
        '434455b071dddb34481b128640ed9490c63f89b893fe9d0b673fdbd87f5d5ded'),
    'syslog.zlib': (
        _DFVFS + 'syslog.zlib',
        '871a0bd83e24721a8ca2fc00f02665d8243baa98fe4726a6487dc40661ee6abe'),
    'blob.db': (
        _DFVFS + 'blob.db',
        '0e93cfa66d0d6aebcc8c80a71a0839d75681ca82b056ef1ccb6d54ff581b5b0b'),
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
    # Apple's unified log: a Mac's /private/var/db log tree (Persist,
    # Special, Signpost, timesync, uuidtext, dsc) on APFS in a DMG --
    # plaso's, whose tests give its entry counts and messages.
    'unified_logging1.dmg': (
        _PLASO + 'unified_logging1.dmg',
        'e38da79f6eb911baf347ffc24650c7c6d22dea07139aca6a404b965e5419af08'),
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
    # Outlook .msg (Apache POI, Apache-2.0; tests/test_office_mail_pcap.py),
    # Office macros with POI's own .vba source, encrypted Office documents
    # with msoffcrypto-tool's decrypted copies (MIT; password
    # 'Password1234_', the XOR one '123456789012345'), and captures from
    # tcpdump's and Zeek's tests (BSD).
    'poi-quick.msg': (
        _POI + 'hsmf/quick.msg',
        '5cf6dd0bd15c07b8b221f070f7d69590ee6803a6b64358b9deb93a147cf4611b'),
    'poi-attachment_test_msg.msg': (
        _POI + 'hsmf/attachment_test_msg.msg',
        '4f5ab34d4e6bbb04945319dc0decdcfce785779bda618c89ca2eb0fe82e9caf0'),
    'poi-attachment_msg_pdf.msg': (
        _POI + 'hsmf/attachment_msg_pdf.msg',
        '439a1fb117edd4c84b780fcf44bf1d5167166694130ced5743a70132a83c6970'),
    'poi-chinese-traditional.msg': (
        _POI + 'hsmf/chinese-traditional.msg',
        'b84c12748155dc57b41de02c6d43aa47e82b879020df070290633e9fd5ce7fdd'),
    'poi-cyrillic_message.msg': (
        _POI + 'hsmf/cyrillic_message.msg',
        '8378273915639c4affdbe74a07105a653e3da752cd61882444deb5df771562c8'),
    'poi-HTMLBodyBinary_UTF-8.msg': (
        _POI + 'hsmf/HTMLBodyBinary_UTF-8.msg',
        '6e6a9b5ad0045dae5477608bc67827741f074f61c80d6f005466ae931894d336'),
    'poi-document-SimpleMacro.doc': (
        _POI + 'document/SimpleMacro.doc',
        '39e9608c711d38f298ed20a5bfae12fcdaed6f4be2be4d26db670475216ca393'),
    'poi-document-SimpleMacro.docm': (
        _POI + 'document/SimpleMacro.docm',
        'fd591958fcf5322f72c0a740e9606309c949254bda4c3d9bd966481ddf220563'),
    'poi-document-SimpleMacro.vba': (
        _POI + 'document/SimpleMacro.vba',
        'adfa5f1157daf9b7983aa6fc36dc4308f960b10fbfb2de26bc487b6747c5b859'),
    'poi-spreadsheet-SimpleMacro.xls': (
        _POI + 'spreadsheet/SimpleMacro.xls',
        '0e92c9bb018abd8a5f9121d65827c9e3bd280777219cb77a2efd70635143c00a'),
    'poi-spreadsheet-SimpleMacro.xlsm': (
        _POI + 'spreadsheet/SimpleMacro.xlsm',
        'f76c986f4ebc25c2cc57c088b2511a1269f4bd61d6223a2ab58db351da348ba6'),
    'poi-spreadsheet-SimpleMacro.vba': (
        _POI + 'spreadsheet/SimpleMacro.vba',
        '0d23333b21e8eba9008d5c953571e8f862aed8b9b2e5b30b6f3441a4378437b5'),
    'poi-spreadsheet-xlmmacro.xlsm': (
        _POI + 'spreadsheet/xlmmacro.xlsm',
        'e9ac8d566a43e3c3b6949e7de538705211b22af3fa1d147762d6ff1383df8092'),
    'poi-slideshow-SimpleMacro.pptm': (
        _POI + 'slideshow/SimpleMacro.pptm',
        '8a3573c82fd07a301d7f175b8bee646c0b58eb8a945bd0ff408225b6e2b89b15'),
    'poi-slideshow-SimpleMacro.vba': (
        _POI + 'slideshow/SimpleMacro.vba',
        '305a8232b1ff305bf096524d74c444197f38aeea328ad27b6cf08ce90ed289ae'),
    'mso-example_password.docx': (
        _MSO + 'inputs/example_password.docx',
        '0605624697328060fdc75ca9929ea20b9d63ebed9387ff1a97aaf9979757234a'),
    'mso-example_password.xlsx': (
        _MSO + 'inputs/example_password.xlsx',
        '3f792e3902a615bf0e91771f3f3016b80d59098b8e492efcdc0752748e15b997'),
    'mso-ecma376standard_password.docx': (
        _MSO + 'inputs/ecma376standard_password.docx',
        'd265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de'),
    'mso-rc4cryptoapi_password.doc': (
        _MSO + 'inputs/rc4cryptoapi_password.doc',
        '9c5217bea80fb1a7811ad7709dd9bb35f6c639bac7154580dd4c99d54e1fc0e0'),
    'mso-rc4cryptoapi_password.xls': (
        _MSO + 'inputs/rc4cryptoapi_password.xls',
        'b804cba40c27ea88f2ea994b6b7d75145661532f9356e7246d2499f63d58abfe'),
    'mso-xor_password_123456789012345.xls': (
        _MSO + 'inputs/xor_password_123456789012345.xls',
        'c75375186933e2413325c4e64ce76903452d51413816d0df1d5fd677ea4dd76d'),
    'mso-plain-example.docx': (
        _MSO + 'outputs/example.docx',
        '8c8212db6e624bfc69286e94d09b7e68c753ee86b6826e51427a33c841f133d1'),
    'mso-plain-example.xlsx': (
        _MSO + 'outputs/example.xlsx',
        '4dd9dd0ccbfc7fb8769f1f3307830d3cc4c5042e32d619f4b2835fada89d13c6'),
    'mso-plain-ecma376standard_password_plain.docx': (
        _MSO + 'outputs/ecma376standard_password_plain.docx',
        'ca1c0ebb465553361b9034e696d4081df0a2d41918f820060325b3ca634eb69b'),
    'mso-plain-rc4cryptoapi_password_plain.doc': (
        _MSO + 'outputs/rc4cryptoapi_password_plain.doc',
        '65eb884be862337c0e51e78bf57be6cb6601040a16055a87d1e4dd3de4c04303'),
    'mso-plain-rc4cryptoapi_password_plain.xls': (
        _MSO + 'outputs/rc4cryptoapi_password_plain.xls',
        'ccaf6545a3abe5b42ca48b6513239d3fcda5ee900d8623eb20e5d604f4702f43'),
    'mso-plain-xor_password_123456789012345_plain.xls': (
        _MSO + 'outputs/xor_password_123456789012345_plain.xls',
        '59eda76e923e7147dc584f93641f7c829180838e2642c97af1324450cdb3d527'),
    'tcpdump-dns_udp.pcap': (
        _TCPDUMP + 'dns_udp.pcap',
        'dcb83420e7512dd4085e790d40a040bc5749decb5e551fb807da5689b990fa65'),
    'tcpdump-dns_tcp.pcap': (
        _TCPDUMP + 'dns_tcp.pcap',
        '4eee693b9718b4fdaf1916ce19d825ce0cca18efb5998615c11bd86c9183acec'),
    'tcpdump-ahcp.pcapng': (
        _TCPDUMP + 'ahcp.pcapng',
        '5dd83ed8a7a97f6012b6dd1bbda4a51c789c83213bd9a422ae5487d948265375'),
    'zeek-http-get.pcap': (
        _ZEEK + 'http/get.pcap',
        '48c8c3a3560a13ffb03d4eb0ed14143fb57350ced7d6874761a963a8091b1866'),
    'zeek-tls-chrome-34-google.pcap': (
        _ZEEK + 'tls/chrome-34-google.pcap',
        '706d75a08f7db96cb0877815c9b682df3eab475012606ca074d3a5b47229ab4f'),
    # A program linked by Microsoft's linker (its Rich header), from
    # CPython 3.9's distutils (PSF licence).
    'cpython-wininst-14.0-amd64.exe': (
        _CPYTHON39 + 'wininst-14.0-amd64.exe',
        '0cf9864ae3a8679ed503f954a453452c93fa44f99ca6f39bbc5860abde7fd35e'),
    # The Sleuth Kit's own test images (sleuthkit/sleuthkit_test_data; Git
    # LFS objects) with the DFXML fiwalk wrote for some -- every file's
    # path, size and MD5 (tests/test_sleuthkit_data.py).
    'tsk-apfs-apfs_pool.E01': (
        _TSKDATA_LFS + 'apfs/apfs_pool.E01',
        'f08a7bb7565ee1778faa95a279215f3aca5fabfbffe0e34b96e0887059548400'),
    'tsk-btrfs-btrfs_testimage_50MB.E01': (
        _TSKDATA_LFS + 'btrfs/btrfs_testimage_50MB.E01',
        '42c5bda5e887002eaf6292fb0d20e022187837553bcdf4e84bf2c222b1e70b93'),
    'tsk-btrfs-btrfs_testimage_50MB.E01.xml': (
        _TSKDATA + 'btrfs/btrfs_testimage_50MB.E01.xml',
        'eb7808af05a4c93ea01f3efd467f592aad75ff527b2117fc0d6465da63547046'),
    'tsk-btrfs-btrfs_zstd.E01': (
        _TSKDATA_LFS + 'btrfs/btrfs_zstd.E01',
        'c404949c4a72760dc7e394053aec06b3776903c52b442cc686977addc0e31942'),
    'tsk-exfat-exfat1.E01': (
        _TSKDATA_LFS + 'exfat/exfat1.E01',
        '9249cbb06fef129cc411b5e1e65a6780cafad4dfa9f3566c583b5968504e5153'),
    'tsk-from_brian-6-fat-undel.E01': (
        _TSKDATA_LFS + 'from_brian/6-fat-undel.E01',
        'a45d1ab4038cfb0d9be21c86e2d224789dff8b4f62671575cb5ba50027818960'),
    'tsk-from_brian-6-fat-undel.dd.xml': (
        _TSKDATA + 'from_brian/6-fat-undel.dd.xml',
        '558750947abc3cb5ed33b0899350ccabdad07d38e788d9cff4c5cbb8a41f442d'),
    'tsk-from_brian-fat32_with_efs_file.E01': (
        _TSKDATA_LFS + 'from_brian/fat32_with_efs_file.E01',
        '705109dfc554eceec4dc588bb489a8fc0cecd877eb9cd4a7044549338caa1f71'),
    'tsk-from_brian-imageformat_mmls_1.E01': (
        _TSKDATA_LFS + 'from_brian/imageformat_mmls_1.E01',
        '5125bbc40154a6acdf96b7aded0fc28686e9c0882afb5b95ddf2dc8345ccf44e'),
    'tsk-from_brian-imageformat_mmls_1.E01.xml': (
        _TSKDATA + 'from_brian/imageformat_mmls_1.E01.xml',
        'f02fc57a59ed75267e3cd2373d78c36a179329c3b943dee07b4552f052ac9f36'),
    'tsk-from_brian-1-extend-part.zip': (
        _TSKDATA + 'from_brian/1-extend-part.zip',
        '771cc763798ed23d85f6362de4adff503bf83c33c56c5ac8dea689a3996c8ce3'),
    'tsk-fuzzing-lvm_test_issue_3235.E01': (
        _TSKDATA_LFS + 'fuzzing/lvm_test_issue_3235.E01',
        '2209ee278d79031079923647283b425e8e425af3c082a6d3dba81abb3d688f97'),
    'tsk-fuzzing-clusterfuzz-testcase-minimized-sleuthkit_fls_ntfs_fuzzer-5124116049166336': (
        _TSKDATA + 'fuzzing/clusterfuzz-testcase-minimized-sleuthkit_fls_ntfs_fuzzer-5124116049166336',
        'cde563ddb5efb41c31bd34e6fd49b56f82d33eac97e5b8fa417edf7f3ec63ee6'),
    'tsk-gpt-gpt_130_partitions.E01': (
        _TSKDATA_LFS + 'gpt/gpt_130_partitions.E01',
        'c2ca9d37af9c8f249a9667b2a319bc25861d3b80ebdbdb7f4c74863e410a490f'),
    'tsk-ufs-image.E01': (
        _TSKDATA_LFS + 'ufs/image.E01',
        'e94dfb49e8a6dc72b952127ebd32eba01396b4dfb62f359a38b89f360cbbbf30'),
    'tsk-ufs-image_dd.xml': (
        _TSKDATA + 'ufs/image_dd.xml',
        '6dfba3511ad0fe855dd3e727f9e87e2d49dc4d537353ab755f442a003f05f6bc'),
    'tsk-xfs-xfs-raw-2GB.E01': (
        _TSKDATA_LFS + 'xfs/xfs-raw-2GB.E01',
        '48397462ad7af18d4ac74534769fcbbe081712080918a0ca16e7063f62d5d772'),
}


def _download(url):
    """Fetch with retries and mirrors (tools/download.py)."""
    sys.path.insert(0, ROOT)
    from tools.testdata.download import download
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

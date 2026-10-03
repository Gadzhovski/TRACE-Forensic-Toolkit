# Test images

Disk images used to verify TRACE. **Nothing in this directory except this file
is committed** — `.gitignore` excludes every image extension at any depth. The
images are recorded here rather than stored in git so a checkout can be
reconstructed without carrying a gigabyte of evidence in history.

Verify a download before trusting a result from it: a truncated image produces
carving failures that look like tool defects.

## Carving corpora (published ground truth)

Each of these ships an answer key naming every planted file, its MD5, its size
and its sector runs. Those keys are transcribed into
`tools/carve_ground_truth.json` and scored by `tools/carve_score.py`.

| File | Size | Filesystem | Source |
|---|---|---|---|
| `11-carve-fat.dd` | 62 MB | FAT32 | [DFTT #11](https://dftt.sourceforge.net/test11/index.html) |
| `12-carve-ext2.dd` | 124 MB | Ext2 | [DFTT #12](https://dftt.sourceforge.net/test12/index.html) |
| `9-fat-label.dd` | 9.9 MB | FAT | [DFTT #9](https://dftt.sourceforge.net/test9/index.html) |
| `dfrws-2006-challenge.raw` | 48 MB | none (raw) | [DFRWS 2006](https://github.com/dfrws/dfrws2006-challenge) |
| `dfrws-2007-challenge.img` | 331 MB | none (raw) | [DFRWS 2007](https://github.com/dfrws/dfrws2007-challenge) |

### What each corpus is for

**DFTT #11 and #12** are ordinary filesystems holding ordinary files, and they
test the basics honestly. `11-carve-fat.dd` deliberately includes `haxor2.jpg`
with one byte corrupted at offset 19, which **must be rejected** — the test
exists, in the authors' words, "to show the importance of ignoring corrupted
files". `pumpkin.jpg` is an EXIF photo whose embedded thumbnail terminates with
`FFD9` before the image does, so a carver taking the first footer truncates it.
`surf.mov` begins at a `moov` atom with no `ftyp`. The boot sector is corrupted
on purpose, so the volume will not mount. `12-carve-ext2.dd` fragments almost
everything across indirect blocks; only `main_dive.jpg` is contiguous.
`lin_test.pdf` is in exactly two pieces -- its first twelve blocks, then the
rest after the indirect block -- the case reassembly rebuilds.

**DFRWS 2006 and 2007** are raw images with no filesystem, built specifically
to break carvers. 2006 lays out 32 files in 22 named scenarios, several of
which target carving heuristics directly:

- **3c** plants a lone sector beginning `0xFFD8` immediately before a real JPEG
- **3j** plants a sector beginning `0xFFD9` *inside* a JPEG
- **3g** places one complete JPEG inside another's fragmentation gap
- **3i** is a 24 MB JPEG, larger than many tools' default maximum
- **1d**, **3h** intertwine two files of the same type

2007 deepened this: of the 54 originally scored files **only 5 are
contiguous**, and its full key (114 files once MP3, MPG, EXE, ELF, AVI, FLV
and mail are counted) is what the harness scores. The fragmented ZIPs of 2006
and the in-order, two-fragment PDFs of 2007 are what reassembly is measured
against; 4.pdf is two in-order fragments too, but encrypted, so its split
cannot be proved and it is (correctly) not rebuilt.

## The rest of the DFTT suite

These test everything except carving: partition tables, keyword search,
undelete, timestamps, volume labels, filesystem detection and ISO9660. Each
page at <https://dftt.sourceforge.net/> documents what its image contains and
what a tool is expected to do with it.

| File | Size | Tests | DFTT |
|---|---|---|---|
| `ext-part-test-2.dd` | 153 MB | Extended/nested partitions -- 6 FAT16 volumes, some inside extended tables | [#1](https://dftt.sourceforge.net/test1/index.html) |
| `fat-img-kw.dd` | 15 MB | Keyword search on FAT16 | [#2](https://dftt.sourceforge.net/test2/index.html) |
| `ntfs-img-kw-1.dd` | 7.8 MB | Keyword search on NTFS | [#3](https://dftt.sourceforge.net/test3/index.html) |
| `ext3-img-kw-1.dd` | 5 MB | Keyword search on ext3 | [#4](https://dftt.sourceforge.net/test4/index.html) |
| `daylight.dd` | 1.4 MB | FAT timestamps across a daylight-saving boundary | [#5](https://dftt.sourceforge.net/test5/index.html) |
| `6-fat-undel.dd` | 5.9 MB | Recovering deleted files from FAT | [#6](https://dftt.sourceforge.net/test6/index.html) |
| `7-ntfs-undel.dd` | 5.9 MB | Recovering deleted files from NTFS, and a leap day | [#7](https://dftt.sourceforge.net/test7/index.html) |
| `8-jpeg-search.dd` | 9.8 MB | Identifying JPEGs by content, not extension | [#8](https://dftt.sourceforge.net/test8/index.html) |
| `10-ntfs-disk.dd` | 94 MB | Two file systems layered in one partition | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `10-ntfs-part1.dd` | 47 MB | Partition 1 of the above: NTFS under Ext2 | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `10-ntfs-part2.dd` | 47 MB | Partition 2 of the above: NTFS under UFS2 | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `iso-dirtree1.iso` | 366 KB | ISO9660 directory structure | [#14](https://dftt.sourceforge.net/test14/index.html) |
| `iso-dirtree2.iso` | 366 KB | ISO9660 directory structure, variant | [#14](https://dftt.sourceforge.net/test14/index.html) |
| `iso-endian.iso` | 366 KB | ISO9660 byte-order handling | [#14](https://dftt.sourceforge.net/test14/index.html) |

Three of these earn particular attention:

- **#5 (`daylight.dd`)** holds one file written in January and one in June, both
  at a round hour. FAT stores wall-clock time with no timezone, so a tool that
  converts them as though they were UTC shifts one by an hour and not the
  other. `winter.txt` must read 2:00 PM and `summer.txt` 3:00 PM.
- **#7 (`7-ntfs-undel.dd`)** deletes six files. Their directory entries survive
  but no longer link to their metadata, so a tool that reads the inode only
  from that link lists six names it cannot open. The MFT record number is still
  in the entry.
- **#10** formats each partition as NTFS and then overwrites it with Ext2 or
  UFS, leaving both signature sets intact. In the authors' words: "The test is
  whether your tool will warn you that there are two valid file systems or if
  it will show you only one and hide the other." Showing an empty partition is
  worse than either.

## Filesystems beyond FAT and NTFS

TRACE had only ever been exercised on FAT, NTFS, ext2/3 and ISO9660. These add
HFS+, exFAT and ext4, plus NTFS features -- compression, EFS encryption,
journaling -- that none of the DFTT images cover.

| File | Size | Filesystem | Tests | Source |
|---|---|---|---|---|
| `ntfs1-gen2.E01` | 34 MB | NTFS | The same files stored raw, NTFS-compressed and EFS-encrypted, plus interleaved logfile writes that fragment them | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `image.gen1.dmg` | 10 MB | HFS+ | A journaled HFS+ volume where an earlier version of a file survives only in the journal | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `ubnist1.casper-rw.gen3.E01` | 160 MB | ext3 | The persistence file from a bootable Ubuntu 8.10 USB | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `dfr-01-xfat.dd` | 63 MB | exFAT | Deleted-file recovery | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-osx.dd` | 1.0 GB | HFS+ | Deleted-file recovery across four HFS+ volumes | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-ext.dd` | 1.0 GB | ext2, ext3, ext4 | Deleted-file recovery, one volume per generation | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-ntfs.dd` | 1.0 GB | NTFS | Deleted-file recovery, non-fragmented | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-05-braid-ntfs.dd` | 1.0 GB | NTFS | Several deleted files interleaved fragment by fragment | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-05-nest-ntfs.dd` | 1.0 GB | NTFS | Several deleted files nested inside one another's gaps | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-recycle-ntfs.dd` | 1.0 GB | NTFS | Files deleted through the Recycle Bin rather than unlinked | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |

What these established, all measured rather than assumed:

- **HFS+, exFAT and ext4 list and read correctly.** exFAT recovers both its
  deleted files; ext3 recovers its one.
- **NTFS compression is transparent.** Files in the `Compressed` directory read
  back at full length with correct magic bytes, identical to `RAW`.
- **EFS-encrypted files return ciphertext**, at the right size but with no valid
  header -- which is the honest result. TRACE reports what is on the disk
  rather than implying it decrypted anything.
- **HFS+ shows no deleted entries at all**, because HFS+ removes the catalog
  record on delete rather than flagging it. That is the filesystem's behaviour,
  not a gap in the tool; those files are reachable only by carving.
- **ext2 zeroes the inode pointer on delete**, so a deleted name there has no
  metadata to follow. ext3 and ext4 keep the record but clear its size and
  block pointers. The listing now says which deleted files can actually be
  opened and which are a name and nothing more.

## Other images

| File | Size | Notes |
|---|---|---|
| `2020JimmyWilson.E01` | 296 MB | NTFS, E01. General browsing and verification. |
| `BXS-1.E01` | 152 MB | NTFS, E01. The image the I/O constants work was measured against. |
| `Op Archway AXA-1.E01` | 123 MB | NTFS, E01. |

## Checksums

The two DFRWS images were verified against the MD5s their organisers published,
and both matched on download:

```
bd09d612fc8b3f92662b98f9456f2ada  dfrws-2006-challenge.raw   (published)
8a501f3f525c85a50a3aa0bf698bffe7  dfrws-2007-challenge.img   (published)
```

SHA-256 of everything here as downloaded:

```
83585232e908529286f1ff04c43b4d858604875c733183a9e3b44a07ff818d26  11-carve-fat.dd
ffeb78b6cf8eed64c241212fb5cd1f3d226dcd58e16b67192f465e4a3ec46342  12-carve-ext2.dd
ca312b0582c78e1b379eca318aa7a9d7fc4a809bfcfd25be093f5298e72a81ab  9-fat-label.dd
9d24547c9d8a17602ee5a8ecf960ff8cc2ee48575ffc127cd084b3b0a484d1dd  dfrws-2006-challenge.raw
ace31ac34503bf3f56acd7cfe729a1f701f17e6fc2c202de7ccbb7ea58bc3a2c  dfrws-2007-challenge.img
b075ed83211765dd14f24390389b77b20ef688d70aaf69385e026b5513bdd8d2  ext-part-test-2.dd
b173fd82a052e2637cfeb89cf21a603817f072799a63decffbfc948fc19a06e6  fat-img-kw.dd
cad097e8fcf4538a928c980a01bc64dcf36ca062432b0f6d5c3962e3bc0c4060  ntfs-img-kw-1.dd
2065c9b3fa3f1f59fd5ee2ec0ad83a987d988e9ae898497a0b48e4986010f686  ext3-img-kw-1.dd
a81dc8aeefb28b75e0625c1c8b54db9f46ec1c6c28e16595539d1cb00bbd45b5  daylight.dd
e6f1f3bc53d426ae6f81b2d7b75598bc95f7447853e38b8f9ca1d1b65f7b3512  6-fat-undel.dd
4138cc42148e3381e3c66eb50090f4a30416ae8c20247c2b9bad27cf8c764d88  7-ntfs-undel.dd
9c43d6a2dd5132cf6afc29e5c644cde0cb747c64998a68e73f2efb787887b126  8-jpeg-search.dd
4d2edfe4a8ee0079720a4b9e258ecf59ffa17783465a5a013101614b4ac64049  10-ntfs-disk.dd
d6739c45d652c0eb67e59536e7b9c02b25ca99aaabf500fe9c374bb7f2ae8bc3  10-ntfs-part1.dd
529c607152f8ca25a6f2645e6894a80b303b4f2b352b89bdfef0fde549e3c6e2  10-ntfs-part2.dd
0418d266405e1baf1334a014b9fba984962e81ec65003f34b67a7f5c7b28e6ad  iso-dirtree1.iso
5f4fe2707eb4227b2d8e35482f492c888a44937abca05b67a0b63f2a2e34e074  iso-dirtree2.iso
70231746c40640efc6ea5a926ef9184910c44b43b0716d72026db41b40966b9c  iso-endian.iso
2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea  ntfs1-gen2.E01
beb7795dd6d1a5319f9c20101855ffff9665fcc11c6b23de822d50c0d1e388ee  image.gen1.dmg
f2ad970ab2c8ed41e2d26d0c7e821aaee0bb6fe71063ae17bea894306a8e55ff  ubnist1.casper-rw.gen3.E01
bb3755982959e189d7cfc7a4819553406e5c64e67a11d6b875ea1d4f23fa745b  dfr-01-xfat.dd
06e997b4a341854495ced8e201fa3b63fdfe0ba042c62fb8fa4e98283d430b6d  dfr-01-osx.dd
855e7dfdc3a807beae3dadd519243f1c047d9a7bd2c08a4e70e7a8eda8f75901  dfr-01-ext.dd
c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493  dfr-01-ntfs.dd
43f239c3b141a02c20ee2e6adc94e553215a3b35371fa291f7e3d4aa9b562cb7  dfr-05-braid-ntfs.dd
7da808c9d3da75eb437fd175567dc781f6291547fab37bb704773cb31562669c  dfr-05-nest-ntfs.dd
6a44af0530812edf1a289c539a3c6c7d6b42e1c93e8f60e53287bddb5fdf7efa  dfr-01-recycle-ntfs.dd
6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5  2020JimmyWilson.E01
1196221c27515e4f9a5c855da529e006bd9bebfbc5703d37bb419476ea0db55d  BXS-1.E01
a621e46b88a6366c90cc5bc7d412b46f3f012a08b1fd7d3fcbea2d78b761af1d  Op Archway AXA-1.E01
```

## The carving corpus

`carve-corpus.dd` is built, not downloaded:

```bash
python tools/carve_corpus.py
```

It fetches 51 real published files of the formats the DFTT/DFRWS images do
not hold (SQLite, PST, EVTX, registry hives, LNK, Office Open XML, HEIC,
Opus, Matroska, Mach-O, RAR3/RAR5, 7z, a pre-POSIX V7 tar and more) into `carve_samples/`, checks each against
its pinned SHA-256, and lays them out with a fixed seed -- so the image, and
its answer key in `tools/carve_ground_truth.json`, are the same every time.

## The artifact samples

`test_images/artifact_samples/` holds real Windows and browser artifacts for
the activity tests -- Prefetch from XP to Windows 11 (five compressed),
NTUSER / UsrClass / SYSTEM / Amcache hives, Jump Lists, a shortcut, Recycle
Bin records, event logs (including a damaged one) and Chrome, Firefox and
Safari databases:

```bash
python tools/fetch_artifact_samples.py
```

They come from log2timeline/plaso's test_data (Apache 2.0) and
omerbenamram/evtx's samples (MIT / Apache 2.0), pinned to a commit and checked
by SHA-256. The same tool fetches dfvfs's container images (Apache 2.0): a
dynamic VHD, a differencing VHDX with its parent, a VMDK, a BitLocker To Go
volume (password `bde-TEST`, as in dfvfs's own tests) and an NTFS volume with
two Volume Shadow Copies; the APFS images (plain, and encrypted with
`apfs-TEST`), a FileVault 2 disk (`fvde-TEST`), a LUKS 1 volume
(`luksde-TEST`) and an LVM volume group -- the passwords dfvfs's own tests
use; plaso's ESE databases (SRUDB.dat, WebCacheV01.dat), IE index.dat
files, a Windows Timeline database and a Windows 7 SOFTWARE hive; and
plaso's NTFS samples -- a raw Windows XP
`$MFT`, a `$UsnJrnl:$J` excerpt and `usnjrnl.qcow2`, a QCOW2 disk holding an
NTFS volume and its change journal (the NTFS, timeline and QCOW tests).
`nps-2009-domexusers.E01` (Digital Corpora, 4.4 GB, a multi-user
Windows XP machine) is used by a local end-to-end test when present.

## Re-downloading

The public images the tests use are fetched and checksum-verified by

```bash
python tools/fetch_test_images.py          # all of them
python tools/fetch_test_images.py --list   # sources
```

It never overwrites an image already here; one whose checksum differs is
reported, not replaced. The manual commands below remain for the rest.

```bash
curl -L -o dfrws-2006-challenge.zip \
  "https://www.dropbox.com/s/genp058scvl8hbp/dfrws-2006-challenge.zip?dl=1"
curl -L -o dfrws-2007-challenge.zip \
  "https://www.dropbox.com/s/5ze0r2o1vjxf811/dfrws-2007-challenge.zip?dl=1"
unzip dfrws-2006-challenge.zip && unzip dfrws-2007-challenge.zip
```

The NPS images come from Digital Corpora:

```bash
base="https://downloads.digitalcorpora.org/corpora/drives"
curl -L -O "$base/nps-2009-ntfs1/ntfs1-gen2.E01"
curl -L -O "$base/nps-2009-hfsjtest1/image.gen1.dmg"
curl -L -O "$base/nps-2009-casper-rw/ubnist1.casper-rw.gen3.E01"
```

The NIST deleted-file-recovery images are bzip2-compressed; `xfat` means exFAT
and `osx` means HFS+:

```bash
curl -L -O "https://cfreds-archive.nist.gov/dfr-images/dfr-01-xfat.dd.bz2"
bunzip2 dfr-01-xfat.dd.bz2
```

The DFTT images come from <https://dftt.sourceforge.net/>, one page per test.
Every test's archive is under the same SourceForge path:

```bash
base="https://sourceforge.net/projects/dftt/files/Test%20Images"
curl -L -o 1-extend-part.zip "$base/1_%20Extended%20Partition/1-extend-part.zip/download"
curl -L -o 7-undel-ntfs.zip  "$base/7_%20NTFS%20File%20Recovery%20%28and%20Leap%20Year%29%20%231/7-undel-ntfs.zip/download"
# ...and so on; the directory names are visible at the base URL.
```

## Scoring the carvers

```bash
python tools/carve_score.py                  # every image with a known key
python tools/carve_score.py 11-carve-fat.dd  # one image
```

Exits non-zero if a score falls below the baseline recorded in that script.
The score counts files **located**; byte-exactness is reported separately,
because a fragmented file cannot be reproduced by a contiguous carver and
counting that as a failure would measure the wrong thing.

**Expect the 2007 image to take a while.** Chunks advance 4 MB but read 36 MB,
so every byte is scanned about nine times, by each of sixteen carvers -- around
50 billion byte-scans for a 331 MB image. That overlap is what stops a file
being lost at a chunk boundary, so it is deliberate, but it makes a large image
slow to score.
